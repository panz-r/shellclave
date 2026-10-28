#include "../src/shell_builtin_internal.h"
#include "../src/shell_processor_internal.h"
#include "../src/shell_semantics_internal.h"
#include "../src/shell_source_internal.h"
#include "../src/shell_tokenizer_full_internal.h"
#include "../src/shell_word_internal.h"
#include "depgraph_test_workspace.h"
#include "malformed_source_cases.h"
#include "shell_abstract.h"
#include "shell_depgraph.h"
#include "shell_netstring.h"
#include "shell_processor.h"
#include "shell_sequence.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include "shell_transform.h"
#include "syntax_boundary_cases.h"
#include "word_byte_cases.h"
#include "word_expansion_cases.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

typedef struct {
  unsigned char bytes[64];
  size_t length;
  size_t stop_after;
} source_capture_t;

static bool capture_source_byte(unsigned char byte, void *context) {
  source_capture_t *capture = context;
  if (capture->length == sizeof(capture->bytes) ||
      (capture->stop_after != 0 && capture->length == capture->stop_after))
    return false;
  capture->bytes[capture->length++] = byte;
  return true;
}

static bool capture_decoded_byte(unsigned char byte, size_t offset,
                                 void *context) {
  source_capture_t *capture = context;
  (void)offset;
  if (capture->length == sizeof(capture->bytes))
    return false;
  capture->bytes[capture->length++] = byte;
  return capture->stop_after == 0 || capture->length < capture->stop_after;
}

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,         \
              #condition);                                                     \
      failures++;                                                              \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

static void test_source_scratch_array_reservations(void) {
  static const struct {
    size_t count, element_size, alignment;
  } cases[] = {
      {SIZE_MAX / sizeof(size_t) + 1, sizeof(size_t), _Alignof(size_t)},
      {SIZE_MAX, 1, 8},
      {512, 1, 1},
  };
  const char source[] = "x";
  unsigned char workspace[513];
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
    shell_source_operation_begin(source, 1);
    shell_source_workspace_scope_t scope = shell_source_workspace_begin(
        source, 1, workspace + 1, sizeof(workspace) - 1);
    CHECK(!shell_source_scratch_exhausted());
    CHECK(shell_source_scratch_take(1) != NULL);
    size_t *values =
        shell_source_scratch_take_array(3, sizeof(size_t), _Alignof(size_t));
    CHECK(values != NULL && (uintptr_t)values % _Alignof(size_t) == 0);
    for (size_t j = 0; j < 3; ++j)
      values[j] = j + 17;
    size_t mark = shell_source_scratch_mark();
    CHECK(shell_source_scratch_take_array(0, sizeof(size_t), 1) != NULL);
    CHECK(shell_source_scratch_mark() == mark);
    void *empty = shell_source_scratch_take_array(0, sizeof(size_t), 8);
    CHECK(empty != NULL && (uintptr_t)empty % 8 == 0);
    CHECK(shell_source_scratch_mark() == mark + 7);
    CHECK(!shell_source_scratch_exhausted());
    mark = shell_source_scratch_mark();
    CHECK(shell_source_scratch_take_array(cases[i].count, cases[i].element_size,
                                          cases[i].alignment) == NULL);
    CHECK(shell_source_scratch_mark() == mark);
    CHECK(shell_source_scratch_exhausted());
    for (size_t j = 0; j < 3; ++j)
      CHECK(values[j] == j + 17);
    shell_source_scratch_release(0);
    CHECK(shell_source_scratch_mark() == 0);
    CHECK(shell_source_scratch_exhausted());
    shell_source_workspace_end(scope);
    shell_source_operation_end();
  }
  shell_source_operation_begin(source, 1);
  shell_source_workspace_scope_t scope = shell_source_workspace_begin(
      source, 1, workspace + 1, sizeof(workspace) - 1);
  CHECK(!shell_source_scratch_exhausted());
  CHECK(shell_source_scratch_take(sizeof(workspace) - 1) != NULL);
  size_t mark = shell_source_scratch_mark();
  CHECK(shell_source_scratch_take_array(0, 1, 1) ==
        workspace + sizeof(workspace));
  CHECK(shell_source_scratch_mark() == mark);
  CHECK(shell_source_scratch_take_array(0, 1, 8) == NULL);
  CHECK(shell_source_scratch_mark() == mark);
  CHECK(shell_source_scratch_exhausted());
  shell_source_workspace_end(scope);
  shell_source_operation_end();
}

static void test_owned_conditional_workspace(void) {
  static const struct {
    const char *prefix, *opening, *tail;
    int spaces;
  } cases[] = {
      /* Eight/nine raw brackets straddle the inline index capacity. The
       * trailing command's bracket candidate prepares that persistent index. */
      {"printf '[[[['; ", "[[", "tail[[", 0},
      {"printf '[[[[['; ", "[[", "tail[[", 0},
      /* A long operand also needs value scratch without a spilled index. */
      {"printf before; ", "[[", "tail", 512},
      {"printf '[[[[['; ", "[[", "tail[[", 512},
      {"printf before; ", "[\\\n[", "tail", 512},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(*cases); ++c) {
    char source[1024];
    int n = snprintf(source, sizeof(source), "%s%s '%*s1' -eq 1 ]]; %s",
                     cases[c].prefix, cases[c].opening, cases[c].spaces, "",
                     cases[c].tail);
    CHECK(n > 0 && (size_t)n < sizeof(source));
    size_t complete = (size_t)n;
    for (unsigned malformed = 0; malformed < 2; ++malformed) {
      if (malformed)
        strcat(source, "; printf \"$(unfinished");
      size_t length = strlen(source);
      shell_process_status_t expected =
          malformed ? SHELL_PROCESS_EPARSE : SHELL_PROCESS_OK;
      shell_command_info_t *flat = NULL;
      size_t flat_count = 0;
      CHECK(shell_process_command(source, length, NULL, &flat, &flat_count) ==
            expected);
      CHECK(flat_count == (malformed ? 0u : 3u));
      CHECK(malformed ? flat == NULL : flat != NULL);
      shell_command_infos_free(flat, flat_count);
      shell_processed_commands_t processed = {0};
      CHECK(shell_process_commands(source, length, NULL, &processed) ==
            expected);
      CHECK(processed.command_count == (malformed ? 0u : 3u));
      CHECK(malformed ? processed.commands == NULL
                      : processed.commands != NULL);
      shell_processed_commands_free(&processed);
      shell_netstring_buffer_t sequence = {0};
      size_t count = 0;
      bool features = false;
      CHECK(shell_build_netargv_sequence_buffer(source, length, NULL, &sequence,
                                                &count, &features) == expected);
      CHECK(count == (malformed ? 0u : 2u));
      CHECK(malformed ? sequence.data == NULL : sequence.data != NULL);
      CHECK(features == !malformed);
      shell_netstring_buffer_free(&sequence);
      source[complete] = 0;
    }
  }
}

static void test_logical_comment_boundaries(void) {
  const shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                                 .strict_mode = true};
  for (size_t i = 0; i < sizeof(shellsplit_test_comment_words) /
                             sizeof(shellsplit_test_comment_words[0]);
       i++) {
    const char *source = shellsplit_test_comment_words[i].source;
    size_t length = strlen(source);
    shell_parse_result_t parsed = {0};
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t sequence = {0};
    size_t count = 0;
    bool features = false;
    CHECK(shell_parse_fast(source, length, &strict, &parsed) == SHELL_OK);
    CHECK(parsed.count == 1 &&
          parsed.cmds[0].features == shellsplit_test_comment_words[i].features);
    shell_process_status_t status =
        shell_process_commands(source, length, NULL, &processed);
    if (status != SHELL_PROCESS_OK || processed.command_count != 1)
      fprintf(stderr, "comment boundary processor: %s status=%d count=%zu\n",
              source, status, processed.command_count);
    CHECK(status == SHELL_PROCESS_OK && processed.command_count == 1);
    CHECK(shell_build_netargv_sequence_buffer(source, length, NULL, &sequence,
                                              &count,
                                              &features) == SHELL_PROCESS_OK &&
          count == 1);
    shell_netstring_iter_t records;
    shell_netstring_view_t record = {0};
    CHECK(shell_netstring_iter_init(&records, sequence.data, sequence.length) ==
          SHELL_NETSTRING_OK);
    CHECK(shell_netstring_iter_next(&records, &record) == SHELL_NETSTRING_OK);
    if (processed.command_count == 1) {
      shell_netstring_buffer_t argv = {0};
      CHECK(shell_render_netargv_buffer(&processed.commands[0], NULL, &argv) ==
            SHELL_PROCESS_OK);
      const char *expected = shellsplit_test_comment_words[i].netargv;
      bool matches = argv.length == strlen(expected) &&
                     memcmp(argv.data, expected, argv.length) == 0;
      if (!matches)
        fprintf(stderr, "comment boundary argv: %s actual=%.*s expected=%s\n",
                source, (int)argv.length, argv.data, expected);
      CHECK(matches);
      CHECK(argv.length == record.payload_length &&
            memcmp(argv.data, record.payload, argv.length) == 0);
      shell_netstring_buffer_free(&argv);
    }
    CHECK(shell_netstring_iter_next(&records, &record) == SHELL_NETSTRING_DONE);
    shell_netstring_buffer_free(&sequence);
    shell_processed_commands_free(&processed);
    shell_dep_graph_t graph = {0};
    CHECK(shell_dep_graph_parse(source, length, "/", NULL, &graph) ==
          SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(&graph).valid);
  }
}

static void test_quoted_literal_bytes(void) {
  shell_limits_t strict = SHELL_LIMITS_DEFAULT;
  strict.strict_mode = true;
  for (size_t i = 0; i < sizeof(shellsplit_test_word_bytes) /
                             sizeof(shellsplit_test_word_bytes[0]);
       ++i) {
    const char *word = shellsplit_test_word_bytes[i].word;
    const char *value = shellsplit_test_word_bytes[i].value;
    size_t value_length = strlen(value);
    char source[256], expected[256];
    int length = snprintf(source, sizeof(source), "printf %%s %s", word);
    int encoded = snprintf(expected, sizeof(expected), "6:printf,2:%%s,%zu:%s,",
                           value_length, value);
    CHECK(length > 0 && (size_t)length < sizeof(source) && encoded > 0 &&
          (size_t)encoded < sizeof(expected));
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, (size_t)length, &strict, &fast) == SHELL_OK);
    CHECK(fast.count == 1 && fast.cmds[0].len == (size_t)length);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, (size_t)length, NULL, &processed) ==
          SHELL_PROCESS_OK);
    CHECK(processed.command_count == 1);
    shell_netstring_buffer_t argv = {0};
    CHECK(shell_render_netargv_buffer(&processed.commands[0], NULL, &argv) ==
          SHELL_PROCESS_OK);
    CHECK(argv.length == (size_t)encoded &&
          !memcmp(argv.data, expected, (size_t)encoded));
    shell_netstring_buffer_free(&argv);
    shell_processed_commands_free(&processed);
    shell_dep_graph_t graph;
    CHECK(shell_dep_graph_parse_with_fast(source, (size_t)length, "/workspace",
                                          NULL, &fast, &graph) == SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(&graph).valid);
    unsigned commands = 0;
    for (uint32_t n = 0; n < graph.node_count; ++n) {
      const shell_dep_node_t *node = &graph.nodes[n];
      if (node->type == SHELL_NODE_CMD) {
        ++commands;
        CHECK(node->cmd.token_count == 3 &&
              node->cmd.tokens[2] == source + 10 &&
              node->cmd.token_lens[2] == strlen(word) &&
              !memcmp(node->cmd.tokens[2], word, strlen(word)));
      }
    }
    CHECK(commands == 1);
    shell_abstract_command_t *abstract = NULL;
    CHECK(shell_abstract_command_parse(source, (size_t)length, &abstract) ==
          SHELL_ABSTRACT_OK);
    shell_abstract_command_free(abstract);
    shell_transformed_command_t **transformed = NULL;
    size_t count = 0;
    CHECK(shell_transform_command_line(source, (size_t)length, NULL,
                                       &transformed,
                                       &count) == SHELL_TRANSFORM_OK);
    CHECK(count == 1);
    shell_transformed_command_list_free(transformed, count);
  }
  static const char *const locale_assignments[] = {
      "LC_ALL=C",
      "LC_ALL=C printf ok",
      "LC_ALL+=.UTF-8 printf ok",
  };
  for (size_t i = 0;
       i < sizeof(locale_assignments) / sizeof(locale_assignments[0]); ++i) {
    const char *source = locale_assignments[i];
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, strlen(source), NULL, &processed) ==
          SHELL_PROCESS_EPARSE);
    CHECK(!processed.commands && !processed.command_count);
    shell_dep_graph_t graph;
    CHECK(shell_dep_graph_parse(source, strlen(source), NULL, NULL, &graph) ==
          SHELL_DEP_EPARSE);
    CHECK(!graph.node_count && !graph.edge_count);
  }
}

static void test_comment_boundary_io(void) {
  static const struct {
    const char *source;
    bool active;
  } substitutions[] = {
      {"echo \\|#$(printf payload >out)", true},
      {"echo \\ #$(printf payload >out)", true},
      {"echo $(printf x)#$(printf payload >out)", true},
      {"echo <(printf x)#$(printf payload >out)", true},
      {"echo @(a)#$(printf payload >out)", true},
      {"{ echo \\|#$(printf payload >out); }", true},
      {"echo \\| #$(printf payload >out)", false},
      {"echo \\ # #$(printf payload >out)", false},
      {"echo $(printf x) #$(printf payload >out)", false},
  };
  for (size_t i = 0; i < sizeof(substitutions) / sizeof(substitutions[0]);
       i++) {
    const char *source = substitutions[i].source;
    shell_dep_graph_t graph = {0};
    shell_dep_error_t status =
        shell_dep_graph_parse(source, strlen(source), "/", NULL, &graph);
    CHECK(status == SHELL_DEP_OK && shell_dep_graph_validate(&graph).valid);
    unsigned writes = 0;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const shell_dep_edge_t *edge = &graph.edges[e];
      const shell_dep_node_t *target = &graph.nodes[edge->to];
      if (edge->type == SHELL_EDGE_WRITE && target->type == SHELL_NODE_DOC &&
          target->doc.kind == SHELL_DOC_FILE && target->doc.path_len == 3 &&
          memcmp(target->doc.path, "out", 3) == 0)
        writes++;
    }
    if (writes != (unsigned)substitutions[i].active)
      fprintf(stderr, "comment boundary hidden I/O: %s writes=%u\n", source,
              writes);
    CHECK(writes == (unsigned)substitutions[i].active);
  }

  static const struct {
    const char *source;
    const char *path;
  } redirects[] = {
      {"echo >\\|#", "|#"},
      {"echo >\\ #", " #"},
      {"echo >x\\\n#", "x#"},
      {"{ echo; } >\\|#", "|#"},
  };
  for (size_t i = 0; i < sizeof(redirects) / sizeof(redirects[0]); i++) {
    shell_dep_graph_t graph = {0};
    const char *source = redirects[i].source;
    CHECK(shell_dep_graph_parse(source, strlen(source), "/", NULL, &graph) ==
          SHELL_DEP_OK);
    unsigned files = 0;
    for (uint32_t n = 0; n < graph.node_count; n++) {
      const shell_dep_node_t *node = &graph.nodes[n];
      if (node->type == SHELL_NODE_DOC && node->doc.kind == SHELL_DOC_FILE) {
        source_capture_t path = {0};
        size_t path_length = 0;
        CHECK(shell_visit_static_word(node->doc.path, node->doc.path_len,
                                      capture_decoded_byte, &path,
                                      &path_length));
        if (path_length == strlen(redirects[i].path) &&
            memcmp(path.bytes, redirects[i].path, path_length) == 0)
          files++;
      }
    }
    CHECK(files == 1 && shell_dep_graph_validate(&graph).valid);
  }

  static const char *const declarations[] = {
      "cat <<A \\|# <<B\none\nA\ntwo\nB\n",
      "cat <<A $(printf x)# <<B\none\nA\ntwo\nB\n",
      "cat <<A @(x)# <<B\none\nA\ntwo\nB\n",
      "cat <<A <(printf x)# <<B\none\nA\ntwo\nB\n",
      "echo $(cat <<A \\|# <<B\none\nA\ntwo\nB\n)#",
  };
  for (size_t i = 0; i < sizeof(declarations) / sizeof(declarations[0]); i++) {
    const char *source = declarations[i];
    shell_dep_graph_t graph = {0};
    CHECK(shell_dep_graph_parse(source, strlen(source), "/", NULL, &graph) ==
          SHELL_DEP_OK);
    unsigned documents = 0;
    for (uint32_t n = 0; n < graph.node_count; n++)
      documents += graph.nodes[n].type == SHELL_NODE_DOC &&
                   graph.nodes[n].doc.kind == SHELL_DOC_HEREDOC;
    CHECK(documents == 2 && shell_dep_graph_validate(&graph).valid);
  }
}

static void test_comment_boundary_work(void) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  for (unsigned operation = 0; operation < 2; operation++) {
    size_t previous_work = 0, previous_length = 0;
    for (size_t fragments = 32; fragments <= 1024; fragments *= 2) {
      char source[4096] = "echo ";
      size_t length = 5;
      for (size_t f = 0; f < fragments; f++) {
        memcpy(source + length, "\\|#", 3);
        length += 3;
      }
      shellsplit_test_source_scan_reset();
      if (operation == 0) {
        shell_parse_result_t parsed = {0};
        CHECK(shell_parse_fast(source, length, NULL, &parsed) == SHELL_OK);
        CHECK(parsed.count == 1 && parsed.cmds[0].len == length);
      } else {
        shell_processed_commands_t processed = {0};
        CHECK(shell_process_commands(source, length, NULL, &processed) ==
              SHELL_PROCESS_OK);
        CHECK(processed.command_count == 1);
        shell_processed_commands_free(&processed);
      }
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work <= 128 * length + 1024);
      CHECK(!previous_work ||
            work <= previous_work + 128 * (length - previous_length) + 1024);
      previous_work = work;
      previous_length = length;
    }
  }
#endif
}

static void test_array_prefix_semantics(void) {
  shell_limits_t strict = SHELL_LIMITS_DEFAULT;
  strict.strict_mode = true;
  for (size_t c = 0; c < sizeof(shellsplit_test_array_prefixes) /
                             sizeof(shellsplit_test_array_prefixes[0]);
       c++) {
    const char *source = shellsplit_test_array_prefixes[c].source;
    size_t length = strlen(source);
    shell_parse_result_t parsed;
    CHECK(shell_parse_fast(source, length, &strict, &parsed) == SHELL_OK);
    uint32_t features = 0;
    for (uint32_t i = 0; i < parsed.count; i++)
      features |= parsed.cmds[i].features;
    CHECK(!!(features & SHELL_FEAT_ARRAY) ==
          shellsplit_test_array_prefixes[c].array);
    CHECK(!!(features & SHELL_FEAT_GLOBS) ==
          shellsplit_test_array_prefixes[c].glob);
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    shell_process_status_t process_status =
        shell_process_commands(source, length, NULL, &processed);
    if (process_status != (shellsplit_test_array_prefixes[c].array
                               ? SHELL_PROCESS_EPARSE
                               : SHELL_PROCESS_OK))
      fprintf(stderr, "array-prefix processor mismatch: %s status=%d\n", source,
              process_status);
    if (shellsplit_test_array_prefixes[c].array) {
      CHECK(process_status == SHELL_PROCESS_EPARSE);
      CHECK(processed.commands == NULL && processed.command_count == 0);
      CHECK(shell_dep_graph_parse(source, length, NULL, NULL, &graph) ==
            SHELL_DEP_EPARSE);
      CHECK(graph.node_count == 0 && graph.edge_count == 0);
    } else {
      CHECK(process_status == SHELL_PROCESS_OK);
      CHECK(shell_dep_graph_parse(source, length, NULL, NULL, &graph) ==
            SHELL_DEP_OK);
      CHECK(shell_dep_graph_validate(&graph).valid);
    }
    shell_processed_commands_free(&processed);
  }
}

static void test_builtin_option_semantics(void) {
  static const struct {
    const char *prefix;
    const char *suffix;
  } contexts[] = {
      {"", ""},         {"command ", ""},
      {"builtin ", ""}, {"command builtin ", ""},
      {"time -p ", ""}, {"{ ", "; }"},
      {"( ", " )"},     {"printf \"$(", ")\""},
  };
  for (size_t c = 0; c < sizeof(contexts) / sizeof(contexts[0]); c++) {
    for (size_t i = 0; i < sizeof(shellsplit_test_builtin_options) /
                               sizeof(shellsplit_test_builtin_options[0]);
         i++) {
      char source[1024];
      int length = snprintf(
          source, sizeof(source), "%s%s%s", contexts[c].prefix,
          shellsplit_test_builtin_options[i].source, contexts[c].suffix);
      CHECK(length > 0 && (size_t)length < sizeof(source));
      bool supported = shellsplit_test_builtin_options[i].supported;
      bool syntax_supported =
          supported || shellsplit_test_builtin_options[i].stateful;
      if (shell_tokenizer_has_unsupported_semantics(source, (size_t)length) !=
          !syntax_supported)
        fprintf(stderr, "builtin option classification mismatch: %s\n", source);
      CHECK(shell_tokenizer_has_unsupported_semantics(source, (size_t)length) ==
            !syntax_supported);
      shell_processed_commands_t processed = {0};
      CHECK(shell_process_commands(source, (size_t)length, NULL, &processed) ==
            (syntax_supported ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE));
      if (!syntax_supported)
        CHECK(processed.commands == NULL && processed.command_count == 0 &&
              processed.groups == NULL && processed.group_count == 0);
      shell_processed_commands_free(&processed);
      shell_dep_graph_t graph = {0};
      shell_dep_error_t graph_status =
          shell_dep_graph_parse(source, (size_t)length, NULL, NULL, &graph);
      if (graph_status != (supported ? SHELL_DEP_OK : SHELL_DEP_EPARSE))
        fprintf(stderr,
                "builtin option graph classification mismatch: %s "
                "status=%d expected=%d\n",
                source, graph_status,
                supported ? SHELL_DEP_OK : SHELL_DEP_EPARSE);
      CHECK(graph_status == (supported ? SHELL_DEP_OK : SHELL_DEP_EPARSE));
      if (supported)
        CHECK(shell_dep_graph_validate(&graph).valid);
      else
        CHECK(graph.node_count == 0 && graph.edge_count == 0);
      shell_netstring_buffer_t sequence = {0};
      size_t count = 0;
      bool features = false;
      CHECK(shell_build_netargv_sequence_buffer(source, (size_t)length, NULL,
                                                &sequence, &count, &features) ==
            (syntax_supported ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE));
      if (!syntax_supported)
        CHECK(sequence.data == NULL && sequence.length == 0 && count == 0 &&
              !features);
      shell_netstring_buffer_free(&sequence);
      shell_netstring_buffer_t raw = {0}, type = {0};
      CHECK(shell_build_anomaly_netseqs_buffer(source, (size_t)length, NULL,
                                               &raw, &type, &count) ==
            (syntax_supported ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE));
      if (!syntax_supported)
        CHECK(raw.data == NULL && type.data == NULL && count == 0);
      shell_netstring_buffer_free(&raw);
      shell_netstring_buffer_free(&type);
      shell_transformed_command_t **transformed = NULL;
      size_t transformed_count = 0;
      CHECK(shell_transform_command_line(source, (size_t)length, NULL,
                                         &transformed, &transformed_count) ==
            (syntax_supported ? SHELL_TRANSFORM_OK : SHELL_TRANSFORM_EPARSE));
      if (!syntax_supported)
        CHECK(transformed == NULL && transformed_count == 0);
      shell_transformed_command_list_free(transformed, transformed_count);
      shell_abstract_command_t *abstract = NULL;
      CHECK(shell_abstract_command_parse(source, (size_t)length, &abstract) ==
            (syntax_supported ? SHELL_ABSTRACT_OK : SHELL_ABSTRACT_EPARSE));
      if (!syntax_supported)
        CHECK(abstract == NULL);
      shell_abstract_command_free(abstract);
    }
  }
}

static void test_readonly_builtin_effect_schedule(void) {
  static const char *const readonly_names[] = {
      "UID", "EUID", "PPID", "SHELLOPTS", "BASHOPTS", "'U'\"ID\""};
  for (size_t i = 0; i < sizeof(readonly_names) / sizeof(readonly_names[0]);
       i++) {
    const char *name = readonly_names[i];
    shell_builtin_read_t read = {.writing = SHELL_READ_OPTIONS};
    CHECK(shell_builtin_read_word(&read, "other", 5) ==
          (SHELL_BUILTIN_ROLE_TARGET | SHELL_BUILTIN_ROLE_WRITE));
    CHECK(shell_builtin_read_word(&read, name, strlen(name)) ==
          SHELL_BUILTIN_ROLE_TARGET);
    CHECK(shell_builtin_read_word(&read, "fd", 2) == 0);
    CHECK(!shell_builtin_read_default_write(&read));

    shell_builtin_printf_t print = {0};
    CHECK(shell_builtin_printf_word(&print, "'%n%n'", 6) ==
          SHELL_BUILTIN_ROLE_FORMAT);
    CHECK(shell_builtin_printf_word(&print, name, strlen(name)) ==
          SHELL_BUILTIN_ROLE_TARGET);
    CHECK(shell_builtin_printf_word(&print, "fd", 2) ==
          (SHELL_BUILTIN_ROLE_TARGET | SHELL_BUILTIN_ROLE_WRITE));
    print = (shell_builtin_printf_t){0};
    CHECK(shell_builtin_printf_word(&print, "-v", 2) == 0);
    CHECK(shell_builtin_printf_word(&print, name, strlen(name)) ==
          SHELL_BUILTIN_ROLE_TARGET);
    CHECK(shell_builtin_printf_word(&print, "'%n'", 4) ==
          SHELL_BUILTIN_ROLE_FORMAT);
    CHECK(shell_builtin_printf_word(&print, "fd", 2) ==
          (SHELL_BUILTIN_ROLE_TARGET | SHELL_BUILTIN_ROLE_WRITE));
  }
}

static void test_declaration_prefix_promotion_roles(void) {
  shell_builtin_declaration_t declaration = {.kind =
                                                 SHELL_SOURCE_BUILTIN_EXPORT,
                                             .options = true,
                                             .promotes_prefix = true};
  CHECK(shell_builtin_declaration_word(&declaration, "fd", 2) ==
        (SHELL_BUILTIN_ROLE_TARGET | SHELL_BUILTIN_ROLE_PROMOTES_PREFIX));

  declaration =
      (shell_builtin_declaration_t){.kind = SHELL_SOURCE_BUILTIN_EXPORT,
                                    .options = true,
                                    .promotes_prefix = true};
  CHECK(shell_builtin_declaration_word(&declaration, "-n", 2) == 0);
  CHECK(shell_builtin_declaration_word(&declaration, "fd", 2) ==
        SHELL_BUILTIN_ROLE_TARGET);

  declaration = (shell_builtin_declaration_t){
      .kind = SHELL_SOURCE_BUILTIN_DECLARE, .options = true};
  CHECK(shell_builtin_declaration_word(&declaration, "-x", 2) == 0);
  CHECK(shell_builtin_declaration_word(&declaration, "fd", 2) ==
        (SHELL_BUILTIN_ROLE_TARGET | SHELL_BUILTIN_ROLE_PROMOTES_PREFIX));

  declaration = (shell_builtin_declaration_t){
      .kind = SHELL_SOURCE_BUILTIN_TYPESET, .options = true};
  CHECK(shell_builtin_declaration_word(&declaration, "+x", 2) == 0);
  CHECK(shell_builtin_declaration_word(&declaration, "-x", 2) == 0);
  CHECK(shell_builtin_declaration_word(&declaration, "fd", 2) ==
        (SHELL_BUILTIN_ROLE_TARGET | SHELL_BUILTIN_ROLE_PROMOTES_PREFIX));

  declaration = (shell_builtin_declaration_t){
      .kind = SHELL_SOURCE_BUILTIN_DECLARE, .options = true};
  CHECK(shell_builtin_declaration_word(&declaration, "-p", 2) == 0);
  CHECK(shell_builtin_declaration_word(&declaration, "fd", 2) == 0);

  declaration =
      (shell_builtin_declaration_t){.kind = SHELL_SOURCE_BUILTIN_EXPORT,
                                    .options = true,
                                    .promotes_prefix = true};
  CHECK(shell_builtin_declaration_word(&declaration, "fd=99", 5) ==
        (SHELL_BUILTIN_ROLE_TARGET | SHELL_BUILTIN_ROLE_WRITE |
         SHELL_BUILTIN_ROLE_PROMOTES_PREFIX));
}

static void test_printf_effect_schedule(void) {
  static const struct {
    const char *format, *data;
    bool control, stopped;
  } controls[] = {
      {"'%b%n'", "\"$V\"", true, false},  {"'%b%n'", "'\\c'", true, true},
      {"'%b%n'", "'\\\\c'", true, false}, {"'%s%n'", "\"$V\"", false, false},
      {"'%b'", "\"$V\"", false, false},   {"'%b'", "'\\c'", false, true},
  };
  for (size_t i = 0; i < sizeof(controls) / sizeof(controls[0]); i++) {
    shell_builtin_printf_t state = {0};
    CHECK(shell_builtin_printf_word(&state, controls[i].format,
                                    strlen(controls[i].format)) ==
          SHELL_BUILTIN_ROLE_FORMAT);
    CHECK(shell_builtin_printf_word(&state, controls[i].data,
                                    strlen(controls[i].data)) ==
          (controls[i].control ? SHELL_BUILTIN_ROLE_CONTROL : 0));
    CHECK((state.phase == SHELL_PRINTF_ERROR) == controls[i].stopped);
    if (state.format.has_count)
      CHECK(shell_builtin_printf_word(&state, "fd", 2) ==
            (controls[i].stopped
                 ? 0
                 : SHELL_BUILTIN_ROLE_TARGET | SHELL_BUILTIN_ROLE_WRITE));
  }
  /* A %b after %n can suppress the next iteration's write. Ownership of
   * CONTROL comes from the compiled schedule, not another format scan. */
  shell_builtin_printf_t repeated = {0};
  CHECK(shell_builtin_printf_word(&repeated, "'%n%b'", 6) ==
        SHELL_BUILTIN_ROLE_FORMAT);
  for (size_t iteration = 0; iteration < 16; iteration++) {
    CHECK(shell_builtin_printf_word(&repeated, "fd", 2) ==
          (SHELL_BUILTIN_ROLE_TARGET | SHELL_BUILTIN_ROLE_WRITE));
    CHECK(shell_builtin_printf_word(&repeated, "\"$V\"", 4) ==
          SHELL_BUILTIN_ROLE_CONTROL);
  }
  CHECK(shell_builtin_printf_word(&repeated, "fd", 2) ==
        (SHELL_BUILTIN_ROLE_TARGET | SHELL_BUILTIN_ROLE_WRITE));
  CHECK(shell_builtin_printf_word(&repeated, "'\\c'", 4) ==
        SHELL_BUILTIN_ROLE_CONTROL);
  CHECK(shell_builtin_printf_word(&repeated, "fd", 2) == 0);

  static const struct {
    const char *word;
    bool writes;
  } escapes[] = {
      {"'\\%n'", true},    {"'\\\\%n'", true},  {"'\\\\\\%n'", true},
      {"'\\x%n'", true},   {"'\\c%n'", true},   {"'\\%%n'", false},
      {"'\\x25n'", false}, {"'\\045n'", false},
  };
  for (size_t i = 0; i < sizeof(escapes) / sizeof(escapes[0]); i++) {
    shell_builtin_printf_t state = {0};
    CHECK(shell_builtin_printf_word(&state, escapes[i].word,
                                    strlen(escapes[i].word)) ==
          SHELL_BUILTIN_ROLE_FORMAT);
    unsigned role = shell_builtin_printf_word(&state, "fd", 2);
    CHECK(((role & SHELL_BUILTIN_ROLE_WRITE) != 0) == escapes[i].writes);
    CHECK(((role & SHELL_BUILTIN_ROLE_TARGET) != 0) == escapes[i].writes);
  }
  for (size_t events = SHELL_PRINTF_MAX_EVENTS - 1;
       events <= SHELL_PRINTF_MAX_EVENTS + 1; events++) {
    for (unsigned count = 0; count < 2; count++) {
      char source[128];
      size_t length = 0;
      memcpy(source, "printf '", 8);
      length = 8;
      for (size_t i = 0; i < events; i++) {
        source[length++] = '%';
        source[length++] = count ? 'n' : 'b';
      }
      source[length++] = '\'';
      source[length] = '\0';
      bool supported = !count || events <= SHELL_PRINTF_MAX_EVENTS;
      CHECK(shell_tokenizer_has_unsupported_semantics(source, length) ==
            !supported);
      shell_processed_commands_t processed = {0};
      CHECK(shell_process_commands(source, length, NULL, &processed) ==
            (supported ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE));
      shell_processed_commands_free(&processed);
      shell_dep_graph_t graph = {0};
      CHECK(shell_dep_graph_parse(source, length, NULL, NULL, &graph) ==
            (supported ? SHELL_DEP_OK : SHELL_DEP_EPARSE));
      if (supported)
        CHECK(shell_dep_graph_validate(&graph).valid);
      else
        CHECK(graph.node_count == 0 && graph.edge_count == 0);
    }
  }

  /* Long literal prefixes and many format iterations scale additively, not
   * as format-length times operand-count. No decoded buffer is allocated. */
  for (size_t prefix = 8; prefix <= 4096; prefix *= 8) {
    char format[4102];
    format[0] = '\'';
    memset(format + 1, 'x', prefix);
    memcpy(format + 1 + prefix, "%n'", 4);
    shell_builtin_printf_t state = {0};
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_source_scan_reset();
#endif
    CHECK(shell_builtin_printf_word(&state, format, prefix + 4) ==
          SHELL_BUILTIN_ROLE_FORMAT);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    size_t compile_work = shellsplit_test_source_scan_work();
    CHECK(compile_work <= 16 * (prefix + 4));
#endif
    for (unsigned argument = 0; argument < 512; argument++)
      CHECK(shell_builtin_printf_word(&state, "target", 6) ==
            (SHELL_BUILTIN_ROLE_TARGET | SHELL_BUILTIN_ROLE_WRITE));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    CHECK(shellsplit_test_source_scan_work() <= compile_work + 512 * 32);
#endif
    CHECK(state.format.count == 1 && state.format.arguments == 1);
  }

  /* The variable iterator's meaningful empty source is still accepted, while
   * required destinations are compiler-tested rather than invoked as NULL. */
  shell_source_variable_scan_t scan = {0};
  size_t start = 7, after = 9;
  CHECK(!shell_source_next_variable_expansion(NULL, 0, &scan, &start, &after));
  CHECK(start == 7 && after == 9 && scan.position == 0);
  shell_source_assignment_word_t assignment;
  CHECK(!shell_source_parse_scalar_assignment_word("", 0, &assignment));
  CHECK(assignment.name_end == 0 && assignment.equals == 0 &&
        !assignment.append);
}

static void test_raw_token_classification(void) {
  static const struct {
    const char *text;
    shell_token_type_t expected;
  } cases[] = {
      {"\"quoted\"", SHELL_TOKEN_ARGUMENT},
      {"'quoted'", SHELL_TOKEN_ARGUMENT},
      {"$((1 + 2))", SHELL_TOKEN_ARITHMETIC},
      {"$(printf value)", SHELL_TOKEN_SUBSHELL},
      {"`printf value`", SHELL_TOKEN_SUBSHELL},
      {"$1", SHELL_TOKEN_SPECIAL_VAR},
      {"${10}", SHELL_TOKEN_SPECIAL_VAR},
      {"$?", SHELL_TOKEN_SPECIAL_VAR},
      {"$-", SHELL_TOKEN_SPECIAL_VAR},
      {"$HOME", SHELL_TOKEN_VARIABLE},
      {"${HOME}", SHELL_TOKEN_VARIABLE},
      {"$(", SHELL_TOKEN_ARGUMENT},
      {"/etc/passwd", SHELL_TOKEN_ARGUMENT},
      {"./local", SHELL_TOKEN_ARGUMENT},
      {"../parent", SHELL_TOKEN_ARGUMENT},
      {".", SHELL_TOKEN_ARGUMENT},
      {"~", SHELL_TOKEN_ARGUMENT},
      {"~/child", SHELL_TOKEN_ARGUMENT},
      {"~user", SHELL_TOKEN_ARGUMENT},
      {"~1", SHELL_TOKEN_ARGUMENT},
      {"*.c", SHELL_TOKEN_GLOB},
      {"[ab].c", SHELL_TOKEN_GLOB},
      {"[", SHELL_TOKEN_ARGUMENT},
      {"--option", SHELL_TOKEN_ARGUMENT},
      {"-x", SHELL_TOKEN_ARGUMENT},
      {"-1", SHELL_TOKEN_ARGUMENT},
      {"---", SHELL_TOKEN_ARGUMENT},
      {"plain", SHELL_TOKEN_ARGUMENT},
  };

  CHECK(shell_classify_raw_token("", 0) == SHELL_TOKEN_END);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_token_type_t actual =
        shell_classify_raw_token(cases[i].text, strlen(cases[i].text));
    if (actual != cases[i].expected) {
      fprintf(stderr, "classification mismatch for %s: got %d, expected %d\n",
              cases[i].text, actual, cases[i].expected);
      failures++;
    }
  }
}

static shell_abstract_command_t *parse_abstract(const char *source) {
  shell_abstract_command_t *command = NULL;
  CHECK(shell_abstract_command_parse(source, strlen(source), &command) ==
        SHELL_ABSTRACT_OK);
  return command;
}

static bool has_type(const shell_abstract_command_t *command,
                     shell_abstract_type_t type) {
  for (size_t i = 0; command && i < command->element_count; i++) {
    if (command->elements[i]->type == type)
      return true;
  }
  return false;
}

static void test_abstraction_shapes(void) {
  shell_abstract_command_t *variables =
      parse_abstract("printf '%s' \"$HOME\" ${USER} $1 ${10} $? $-");
  CHECK(variables && variables->has_variables && variables->has_pos_vars &&
        variables->has_special_vars && variables->has_strings &&
        has_type(variables, SHELL_ABSTRACT_EV) &&
        has_type(variables, SHELL_ABSTRACT_PV) &&
        has_type(variables, SHELL_ABSTRACT_SV) &&
        has_type(variables, SHELL_ABSTRACT_STR));
  shell_abstract_command_free(variables);

  shell_abstract_command_t *paths = parse_abstract(
      "cat /etc/passwd ./local ../parent . ~ ~/child ~user '*.c' src/[ab].c");
  CHECK(paths && paths->has_paths && paths->has_abs_paths &&
        paths->has_rel_paths && paths->has_home_paths && paths->has_globs &&
        paths->has_strings && has_type(paths, SHELL_ABSTRACT_AP) &&
        has_type(paths, SHELL_ABSTRACT_RP) &&
        has_type(paths, SHELL_ABSTRACT_HP) &&
        has_type(paths, SHELL_ABSTRACT_GB));
  shell_abstract_command_free(paths);

  /* A lexer word can contain both literal path text and parameter
   * expansions.  The production target must exercise the same subspan
   * abstraction path as the allocator-instrumented tests. */
  shell_abstract_command_t *compound = parse_abstract(
      "printf /var/log/$APP.log ./$REL ~/$HOME arg-$1 status-$?");
  CHECK(compound && compound->has_variables && compound->has_pos_vars &&
        compound->has_special_vars && compound->has_paths &&
        compound->has_abs_paths && compound->has_rel_paths &&
        compound->has_home_paths && has_type(compound, SHELL_ABSTRACT_EV) &&
        has_type(compound, SHELL_ABSTRACT_PV) &&
        has_type(compound, SHELL_ABSTRACT_SV) &&
        has_type(compound, SHELL_ABSTRACT_AP) &&
        has_type(compound, SHELL_ABSTRACT_RP) &&
        has_type(compound, SHELL_ABSTRACT_HP));
  shell_abstract_command_free(compound);

  shell_abstract_command_t *multiple_fragments =
      parse_abstract("printf /a/$X/b/$Y");
  CHECK(multiple_fragments && multiple_fragments->element_count == 4 &&
        strcmp(multiple_fragments->display_text,
               "printf $AP_1$EV_1$AP_2$EV_2") == 0 &&
        multiple_fragments->elements[0]->type == SHELL_ABSTRACT_AP &&
        multiple_fragments->elements[1]->type == SHELL_ABSTRACT_EV &&
        multiple_fragments->elements[2]->type == SHELL_ABSTRACT_AP &&
        multiple_fragments->elements[3]->type == SHELL_ABSTRACT_EV);
  shell_abstract_command_free(multiple_fragments);

  /* Quoted words may emit more elements than the complete lexical token list.
   * Sizing and emission must agree for variable, path and substitution spans.
   */
  static const struct {
    const char *source;
    const char *display;
    size_t elements;
  } quoted_compounds[] = {
      {"printf '%s\\n' \"$- $@ $* $!\"\n",
       "printf $STR_1 \"$SV_1 $SV_2 $SV_3 $SV_4\"\n", 5},
      {"time printf \"$HOME $1 $?\"", "time printf \"$EV_1 $PV_1 $SV_1\"", 3},
      {"time printf \"/a/$USER/b/$HOME/c\"",
       "time printf \"$AP_1$EV_1$AP_2$EV_2$AP_3\"", 5},
      {"time printf \"$USER$HOME$USER$HOME$USER$HOME\"",
       "time printf \"$EV_1$EV_2$EV_3$EV_4$EV_5$EV_6\"", 6},
      {"time { printf \"$HOME$(printf child) $1 $?\"; }",
       "time { printf \"$EV_1$CS_1 $PV_1 $SV_1\"; }", 4},
  };
  for (size_t i = 0; i < sizeof(quoted_compounds) / sizeof(quoted_compounds[0]);
       i++) {
    shell_abstract_command_t *quoted =
        parse_abstract(quoted_compounds[i].source);
    CHECK(quoted && quoted->element_count == quoted_compounds[i].elements &&
          strcmp(quoted->display_text, quoted_compounds[i].display) == 0);
    if (quoted)
      for (size_t j = 0; j < quoted->element_count; j++) {
        const shell_abstract_element_t *element = quoted->elements[j];
        CHECK(element->start < element->end &&
              element->end <= strlen(quoted_compounds[i].source) &&
              strlen(element->original) == element->end - element->start &&
              memcmp(element->original,
                     quoted_compounds[i].source + element->start,
                     element->end - element->start) == 0);
      }
    shell_abstract_command_free(quoted);
  }

  shell_abstract_command_t *parameters = parse_abstract(
      "printf ${VALUE:-fallback} ${#VALUE} ${10} ${?} ${!prefix*} "
      "${!} ${#?} ${1} ${VALUE:-$(id)} ${VALUE:-<(id)} "
      "${VALUE:->(id)} ${VALUE:-\"$(id)\"} ${VALUE:-'$(id)'} "
      "${VALUE:-\\$(id)}");
  CHECK(parameters && parameters->element_count == 14 &&
        parameters->has_variables && parameters->has_pos_vars &&
        parameters->has_special_vars && parameters->has_cmd_subst &&
        strcmp(parameters->elements[0]->data.var.name, "VALUE") == 0 &&
        strcmp(parameters->elements[1]->data.var.name, "VALUE") == 0 &&
        parameters->elements[2]->type == SHELL_ABSTRACT_PV &&
        strcmp(parameters->elements[2]->data.var.name, "10") == 0 &&
        parameters->elements[3]->type == SHELL_ABSTRACT_SV &&
        strcmp(parameters->elements[3]->data.var.name, "?") == 0 &&
        parameters->elements[4]->data.var.name == NULL &&
        parameters->elements[5]->type == SHELL_ABSTRACT_SV &&
        strcmp(parameters->elements[5]->data.var.name, "!") == 0 &&
        parameters->elements[6]->type == SHELL_ABSTRACT_SV &&
        strcmp(parameters->elements[6]->data.var.name, "?") == 0 &&
        parameters->elements[7]->type == SHELL_ABSTRACT_PV &&
        strcmp(parameters->elements[7]->data.var.name, "1") == 0 &&
        strcmp(parameters->elements[8]->data.var.name, "VALUE") == 0 &&
        strcmp(parameters->elements[9]->data.var.name, "VALUE") == 0 &&
        strcmp(parameters->elements[10]->data.var.name, "VALUE") == 0 &&
        strcmp(parameters->elements[11]->data.var.name, "VALUE") == 0 &&
        strcmp(parameters->elements[12]->data.var.name, "VALUE") == 0 &&
        strcmp(parameters->elements[13]->data.var.name, "VALUE") == 0);
  shell_abstract_command_free(parameters);

  /* The allocator-linked abstraction suite exercises these public raw-token
   * classifications too. Keep the shipping-library contracts equally broad. */
  static const struct {
    const char *text;
    shell_token_type_t type;
  } raw_tokens[] = {
      {"", SHELL_TOKEN_END},
      {"$HOME", SHELL_TOKEN_VARIABLE},
      {"${!prefix*}", SHELL_TOKEN_VARIABLE},
      {"$1", SHELL_TOKEN_SPECIAL_VAR},
      {"${!}", SHELL_TOKEN_SPECIAL_VAR},
      {"${#?}", SHELL_TOKEN_SPECIAL_VAR},
      {"$!x", SHELL_TOKEN_ARGUMENT},
      {"$", SHELL_TOKEN_ARGUMENT},
      {"${", SHELL_TOKEN_ARGUMENT},
      {"${%word}", SHELL_TOKEN_ARGUMENT},
      {"$(printf x)", SHELL_TOKEN_SUBSHELL},
      {"`printf x`", SHELL_TOKEN_SUBSHELL},
      {"$((1 + 2))", SHELL_TOKEN_ARITHMETIC},
      {"*.log", SHELL_TOKEN_GLOB},
      /* Path-shaped words remain ARGUMENT here; the abstraction layer applies
       * their path and glob categories without changing shell-word grammar. */
      {"/tmp/*.log", SHELL_TOKEN_ARGUMENT},
      {"dir/*.log", SHELL_TOKEN_ARGUMENT},
      {"/etc/passwd", SHELL_TOKEN_ARGUMENT},
      {"./local", SHELL_TOKEN_ARGUMENT},
      {"../parent", SHELL_TOKEN_ARGUMENT},
      {".", SHELL_TOKEN_ARGUMENT},
      {"..", SHELL_TOKEN_ARGUMENT},
      {"dir/file", SHELL_TOKEN_ARGUMENT},
      {"~", SHELL_TOKEN_ARGUMENT},
      {"~user", SHELL_TOKEN_ARGUMENT},
      {"~9", SHELL_TOKEN_ARGUMENT},
      {"-x", SHELL_TOKEN_ARGUMENT},
      {"-1", SHELL_TOKEN_ARGUMENT},
      {"--long", SHELL_TOKEN_ARGUMENT},
      {"---", SHELL_TOKEN_ARGUMENT},
      {"\"quoted\"", SHELL_TOKEN_ARGUMENT},
      {"plain", SHELL_TOKEN_ARGUMENT},
  };
  for (size_t i = 0; i < sizeof(raw_tokens) / sizeof(raw_tokens[0]); i++) {
    shell_token_type_t actual = shell_classify_raw_token(
        raw_tokens[i].text, strlen(raw_tokens[i].text));
    if (actual != raw_tokens[i].type)
      fprintf(stderr, "raw token mismatch for %s: got %d, expected %d\n",
              raw_tokens[i].text, (int)actual, (int)raw_tokens[i].type);
    CHECK(actual == raw_tokens[i].type);
  }

  shell_abstract_command_t *syntax =
      parse_abstract("printf '%s' $(printf nested) `printf tick` $((1 + 2)) "
                     "> /tmp/out 2>> /tmp/err < /tmp/in <> /tmp/read-write "
                     ">| /tmp/clobber <<< word");
  CHECK(syntax && syntax->has_cmd_subst && syntax->has_arithmetic &&
        syntax->has_redirects && has_type(syntax, SHELL_ABSTRACT_CS) &&
        has_type(syntax, SHELL_ABSTRACT_AR) &&
        has_type(syntax, SHELL_ABSTRACT_REDIR));
  shell_abstract_command_free(syntax);

  shell_abstract_command_free(NULL);
}

static void test_abstraction_expansion(void) {
  static const char *const environment[] = {"HOME=/home/test", "USER=alice",
                                            "1=first", "?=status", NULL};
  const shell_runtime_context_t context = {
      .env = environment, .cwd = "/workspace", .resolve_symlinks = false};
  shell_abstract_command_t *command = parse_abstract(
      "printf \"$USER\" ~/child ~other ./relative /absolute $1 $?");
  CHECK(command && shell_abstract_command_expand(command, &context));
  bool saw_user = false;
  bool saw_home = false;
  bool saw_other_home = false;
  bool saw_relative = false;
  bool saw_absolute = false;
  bool saw_position = false;
  bool saw_special = false;
  for (size_t i = 0; command && i < command->element_count; i++) {
    shell_abstract_element_t *element = command->elements[i];
    if (element->type == SHELL_ABSTRACT_EV && element->data.var.name &&
        strcmp(element->data.var.name, "USER") == 0) {
      saw_user = element->expanded && strcmp(element->expanded, "alice") == 0;
    } else if (element->type == SHELL_ABSTRACT_HP &&
               strcmp(element->original, "~/child") == 0) {
      saw_home = element->expanded &&
                 strcmp(element->expanded, "/home/test/child") == 0;
    } else if (element->type == SHELL_ABSTRACT_HP &&
               strcmp(element->original, "~other") == 0) {
      saw_other_home =
          element->expanded && strcmp(element->expanded, "~other") == 0;
    } else if (element->type == SHELL_ABSTRACT_RP) {
      saw_relative = element->expanded &&
                     strcmp(element->expanded, "/workspace/./relative") == 0;
    } else if (element->type == SHELL_ABSTRACT_AP) {
      saw_absolute =
          element->expanded && strcmp(element->expanded, "/absolute") == 0;
    } else if (element->type == SHELL_ABSTRACT_PV) {
      saw_position =
          element->expanded && strcmp(element->expanded, "first") == 0;
    } else if (element->type == SHELL_ABSTRACT_SV) {
      saw_special =
          element->expanded && strcmp(element->expanded, "status") == 0;
    }
  }
  CHECK(saw_user && saw_home && saw_other_home && saw_relative &&
        saw_absolute && saw_position && saw_special);
  CHECK(shell_abstract_command_find_element(command, "$MISSING_1") == NULL);

  shell_abstract_command_free(command);

  const shell_runtime_context_t no_environment = {
      .env = NULL, .cwd = NULL, .resolve_symlinks = false};
  shell_abstract_element_t missing_home = {.type = SHELL_ABSTRACT_HP,
                                           .data.path.path = "~"};
  shell_abstract_element_t missing_home_path = {.type = SHELL_ABSTRACT_HP,
                                                .data.path.path = NULL};
  shell_abstract_element_t missing_path = {.type = SHELL_ABSTRACT_AP,
                                           .data.path.path = NULL};
  CHECK(shell_abstract_element_expand(&missing_home, &no_environment) == NULL);
  CHECK(shell_abstract_element_expand(&missing_home_path, &context) == NULL);
  CHECK(shell_abstract_element_expand(&missing_path, &context) == NULL);

  shell_abstract_command_t *resolvable = parse_abstract("printf /tmp");
  const shell_runtime_context_t resolve_context = {
      .env = environment, .cwd = "/workspace/", .resolve_symlinks = true};
  CHECK(resolvable &&
        shell_abstract_command_expand(resolvable, &resolve_context));
  shell_abstract_command_free(resolvable);
}

static void test_path_categories(void) {
  static const struct {
    const char *path;
    shell_path_category_t category;
  } cases[] = {{"/", SHELL_PATH_ROOT},
               {"/etc/hosts", SHELL_PATH_ETC},
               {"/var/log", SHELL_PATH_VAR},
               {"/usr/bin", SHELL_PATH_USR},
               {"/home/alice", SHELL_PATH_HOME},
               {"/root", SHELL_PATH_HOME},
               {"/tmp/file", SHELL_PATH_TMP},
               {"/proc/1", SHELL_PATH_PROC},
               {"/sys/kernel", SHELL_PATH_SYS},
               {"/dev/null", SHELL_PATH_DEV},
               {"/opt/tool", SHELL_PATH_OPT},
               {"/srv/data", SHELL_PATH_SRV},
               {"/run/user", SHELL_PATH_RUN},
               {"/sysroot/etc", SHELL_PATH_SYSROOT},
               {"/boot/vmlinuz", SHELL_PATH_BOOT},
               {"/mnt/data", SHELL_PATH_MNT},
               {"/media/disk", SHELL_PATH_MEDIA},
               {"/.snapshots/1", SHELL_PATH_SNAPSHOT},
               {"relative", SHELL_PATH_OTHER},
               {"/unclassified", SHELL_PATH_OTHER}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    CHECK(shell_path_category_from_path(cases[i].path) == cases[i].category);
    CHECK(strcmp(shell_path_category_name(cases[i].category), "UNKNOWN") != 0);
  }
  CHECK(strcmp(shell_path_category_name((shell_path_category_t)-1),
               "UNKNOWN") == 0);
}

static void test_canonical_sequences(void) {
  static const char input[] =
      "printf \"$HOME\" $1 $? /absolute ./relative ~/home *.c "
      "$(printf nested) $((1 + 2)) --option; { printf child; }";
  shell_netstring_buffer_t type_netseq = {0};
  shell_netstring_buffer_t command_netseq = {0};
  shell_netstring_buffer_t anomaly_type_netseq = {0};
  size_t count = 0;
  size_t type_count = 0;
  size_t record_count = 0;
  CHECK(shell_build_type_netseq_buffer(input, strlen(input), NULL, &type_netseq,
                                       &type_count) == SHELL_PROCESS_OK);
  /* The command substitution is an execution stage in addition to the
   * enclosing command and the brace-group child. */
  CHECK(type_netseq.data && type_count == 3 &&
        shell_netstring_validate(type_netseq.data, type_netseq.length,
                                 &record_count) == SHELL_NETSTRING_OK &&
        record_count == type_count);
  CHECK(shell_build_anomaly_netseqs_buffer(
            input, strlen(input), NULL, &command_netseq, &anomaly_type_netseq,
            &count) == SHELL_PROCESS_OK);
  CHECK(command_netseq.data && anomaly_type_netseq.data &&
        count == type_count &&
        shell_netstring_validate(command_netseq.data, command_netseq.length,
                                 NULL) == SHELL_NETSTRING_OK &&
        shell_netstring_validate(anomaly_type_netseq.data,
                                 anomaly_type_netseq.length,
                                 NULL) == SHELL_NETSTRING_OK);
  shell_netstring_buffer_free(&type_netseq);
  shell_netstring_buffer_free(&command_netseq);
  shell_netstring_buffer_free(&anomaly_type_netseq);

  const shell_process_limits_t tiny = {1, SIZE_MAX, 0};
  type_netseq = (shell_netstring_buffer_t){0};
  count = 0;
  CHECK(shell_build_type_netseq_buffer("echo value", strlen("echo value"),
                                       &tiny, &type_netseq,
                                       &count) == SHELL_PROCESS_EOUTPUT_LIMIT);
  CHECK(type_netseq.data == NULL && count == 0);
  command_netseq = (shell_netstring_buffer_t){0};
  anomaly_type_netseq = (shell_netstring_buffer_t){0};
  CHECK(shell_build_anomaly_netseqs_buffer(
            "while true; do :; done", strlen("while true; do :; done"), NULL,
            &command_netseq, &anomaly_type_netseq,
            &count) == SHELL_PROCESS_EPARSE);
  CHECK(command_netseq.data == NULL && anomaly_type_netseq.data == NULL &&
        count == 0);
}

static void test_netstring_error_boundaries(void) {
  FILE *stream = tmpfile();
  unsigned char *record = NULL;
  size_t record_length = 0;
  bool stream_rejected = false;
  CHECK(shell_netstring_validate("1", 1, NULL) == SHELL_NETSTRING_EFORMAT);
  CHECK(shell_netstring_validate("1:a", 3, NULL) == SHELL_NETSTRING_EFORMAT);
  if (stream) {
    stream_rejected = fwrite("1:aX", 1, 4, stream) == 4;
    rewind(stream);
    stream_rejected =
        stream_rejected &&
        shell_netstring_read_stream(stream, 0, &record, &record_length) ==
            SHELL_NETSTRING_EFORMAT &&
        record == NULL && record_length == 0;
  }
  CHECK(stream_rejected);
  if (stream)
    fclose(stream);
}

/* The production library must exercise the same zero-copy scanner contracts
 * as the allocator-instrumented target. Cover both accepted and rejected
 * source forms here so merged coverage cannot hide a build-specific gap. */
static void test_production_source_scanner_contract(void) {
  size_t after = 0;
  uint32_t descriptor = UINT32_MAX;
  bool valid = shell_source_parse_io_number("12>", 0, 3, &after, &descriptor) ==
                   SHELL_SOURCE_IO_NUMBER_VALID &&
               after == 2 && descriptor == 12 &&
               shell_source_parse_io_number("x", 0, 1, &after, &descriptor) ==
                   SHELL_SOURCE_IO_NUMBER_NONE &&
               shell_source_parse_io_number("999999999999>", 0, 13, &after,
                                            &descriptor) ==
                   SHELL_SOURCE_IO_NUMBER_OVERFLOW;
  valid = valid &&
          shell_source_parse_named_fd("{trace}>out", 0, strlen("{trace}>out"),
                                      &after) &&
          after == strlen("{trace}") &&
          !shell_source_parse_named_fd("{9}>out", 0, strlen("{9}>out"), &after);
  static const char continued_named[] = "{f\\\nd}\\\n>out";
  size_t marker = (size_t)(strrchr(continued_named, '>') - continued_named);
  size_t operator_position = 0;
  valid = valid &&
          shell_source_parse_named_fd(continued_named, 0,
                                      strlen(continued_named), &after) &&
          shell_source_parse_named_fd_redirect(continued_named, 0,
                                               strlen(continued_named),
                                               &operator_position) &&
          operator_position == marker;
  static const char spaced_named[] = "{fd} >out";
  valid = valid &&
          shell_source_parse_named_fd(spaced_named, 0, strlen(spaced_named),
                                      &after) &&
          !shell_source_parse_named_fd_redirect(
              spaced_named, 0, strlen(spaced_named), &operator_position);
  valid = valid && shell_source_comment_starts('#', true) &&
          !shell_source_comment_starts('#', false) &&
          !shell_source_comment_starts('x', true) &&
          shell_source_line_end("line\r\n", 6, 0) == 5 &&
          shell_source_next_line("line\nnext", 9, 0) == 5;
  static const char list_trivia[] = " \\\n# note\r\n\t\nstage";
  size_t stage_start = strlen(" \\\n# note\r\n\t\n");
  valid = valid &&
          shell_source_skip_list_trivia(list_trivia, sizeof(list_trivia) - 1,
                                        0) == stage_start &&
          shell_source_is_list_trivia(list_trivia, 0, stage_start) &&
          shell_source_skip_list_trivia("word", 4, 0) == 0 &&
          shell_source_skip_list_trivia(NULL, 0, 0) == 0;

  source_capture_t capture = {0};
  static const char ansi[] = "$'\\a\\b\\e\\E\\f\\n\\r\\t\\v\\\\\\'\\\"\\?"
                             "\\cA\\x41\\u00e9\\U0001f600\\101\\q'";
  size_t position = 0;
  valid =
      valid &&
      shell_source_decode_ansi_c_quote(ansi, sizeof(ansi) - 1, &position,
                                       capture_source_byte, &capture) &&
      position == sizeof(ansi) - 1 && capture.length > 16 &&
      shell_source_ansi_emit_codepoint(capture_source_byte, &capture, 0x800) &&
      shell_source_ansi_emit_codepoint(capture_source_byte, &capture,
                                       0x200000) &&
      shell_source_ansi_emit_codepoint(capture_source_byte, &capture,
                                       0x4000000) &&
      shell_source_ansi_emit_codepoint(capture_source_byte, &capture,
                                       UINT32_MAX);
  source_capture_t rejected = {.stop_after = 1};
  position = 0;
  valid = valid &&
          !shell_source_decode_ansi_c_quote("$'ab'", strlen("$'ab'"), &position,
                                            capture_source_byte, &rejected) &&
          rejected.length == 1;
  source_capture_t codepoint_rejected = {.stop_after = 1};

  static const char heredocs[] = "<<A <<-'B'\nbody\nA\n\tB\n";
  bool complete = false;
  after = 0;
  valid = valid &&
          shell_source_skip_heredoc_sequence(heredocs, sizeof(heredocs) - 1, 0,
                                             &after, &complete) &&
          complete && after == sizeof(heredocs) - 1;
  static const char unterminated[] = "<<EOF\nbody\n";
  complete = true;
  after = 0;
  valid = valid &&
          shell_source_skip_heredoc_sequence(
              unterminated, sizeof(unterminated) - 1, 0, &after, &complete) &&
          !complete && after == sizeof(unterminated) - 1;

  /* Keep unusual but valid delimiter spellings and the parser's malformed
   * boundaries covered in the shipping-library target too.  Coverage uses
   * the minimum result across targets, so test-only scanner coverage alone
   * cannot protect this shared implementation. */
  valid =
      valid &&
      !shell_source_ansi_emit_codepoint(capture_source_byte,
                                        &codepoint_rejected, 0x800) &&
      codepoint_rejected.length == 1 &&
      shell_source_skip_ansi_c_quote("plain", 5, 0) == 0 &&
      !shell_source_skip_complete_ansi_c_quote("$'unterminated", 14, 0, &after);
  position = 0;
  valid = valid && !shell_source_decode_ansi_c_quote(
                       NULL, 0, &position, capture_source_byte, &capture);
  position = 0;
  valid = valid && !shell_source_decode_ansi_c_quote(
                       "$'trailing\\", strlen("$'trailing\\"), &position,
                       capture_source_byte, &capture);
  static const char malformed_ansi[] = "$'\\c\\x\\u\\q'";
  position = 0;
  valid = valid && shell_source_decode_ansi_c_quote(
                       malformed_ansi, sizeof(malformed_ansi) - 1, &position,
                       capture_source_byte, &capture);
  position = 0;
  valid = valid && !shell_source_decode_ansi_c_quote(
                       "$'unterminated", strlen("$'unterminated"), &position,
                       capture_source_byte, &capture);

  static const char arithmetic[] = "$((1 + $((2)) + $(printf x)))";
  static const char balanced[] = "(echo $' ) ' $(printf ')') # )\n)";
  static const char array_subscript[] = "[$(printf ']')$((1 + 2))[nested]]";
  static const char parameter[] = "${items[$(printf key)]}";
  static const struct {
    const char *expansion;
    size_t trailing_word_bytes;
  } parameter_expansions[] = {
      {"${value:-${fallback:-one}}", 0},
      {"${value#prefix${suffix}}", 0},
      {"${value##prefix${suffix}}", 0},
      {"${value%prefix${suffix}}", 0},
      {"${value%%prefix${suffix}}", 0},
      {"${value/pattern/${replacement}}", 0},
      {"${value:-{left,right}}", 1},
      {"${value:-${fallback:-{}}", 0},
      {"${value:-{}", 0},
      {"${value#{}", 0},
      {"${value/{}", 0},
      {"${#value}", 0},
      {"${##prefix}", 0},
      {"${!prefix*}", 0},
      {"${!prefix@}", 0},
      {"${10}", 0},
      {"${?}", 0},
      {"${#?}", 0},
      {"${items[${index}]}", 0},
  };
  static const char *const malformed_parameter_expansions[] = {
      "${value${suffix}}", "${value$other}", "${value.other}",
      "${?other}",         "${10other}",     "${items[broken}",
  };
  size_t subscript_start = 0;
  valid = valid &&
          shell_source_skip_arithmetic_expansion(
              arithmetic, sizeof(arithmetic) - 1, 0, &after) &&
          after == sizeof(arithmetic) - 1 &&
          shell_source_find_balanced_parentheses(balanced, sizeof(balanced) - 1,
                                                 0, &after) &&
          after == sizeof(balanced) - 1 &&
          shell_source_skip_array_subscript(
              array_subscript, sizeof(array_subscript) - 1, 0, &after) &&
          after == sizeof(array_subscript) - 1 &&
          shell_source_find_parameter_array_subscript(
              parameter, sizeof(parameter) - 1, 0, &after, &subscript_start) &&
          subscript_start == strlen("${items") &&
          shell_source_array_assignment_is_compound("items+=(one two)",
                                                    strlen("items+=(one two)"));
  for (size_t i = 0; valid && i < sizeof(parameter_expansions) /
                                      sizeof(parameter_expansions[0]);
       i++) {
    const char *expansion = parameter_expansions[i].expansion;
    valid = shell_source_skip_parameter_expansion(expansion, strlen(expansion),
                                                  0, &after) &&
            after ==
                strlen(expansion) - parameter_expansions[i].trailing_word_bytes;
  }
  for (size_t i = 0; valid && i < sizeof(malformed_parameter_expansions) /
                                      sizeof(malformed_parameter_expansions[0]);
       i++) {
    const char *expansion = malformed_parameter_expansions[i];
    valid = !shell_source_skip_parameter_expansion(expansion, strlen(expansion),
                                                   0, &after);
  }

  /* Literal braces do not suppress the expansions they enclose. In
   * particular, a parameter's closing brace must not be consumed as though it
   * closed the outer literal pair before the dynamic-source classifier sees
   * it. Quoted, escaped, and ANSI-C literal contents remain static. */
  static const struct {
    const char *word;
    bool dynamic;
  } brace_dynamic_words[] = {
      {"{literal}", false},    {"prefix{not..a-sequence}suffix", false},
      {"{literal$}", false},   {"{literal$:}", false},
      {"{file[part}", false},  {"{file[]}", false},
      {"{a,b}", true},         {"{$value}", true},
      {"{${value}}", true},    {"{$(producer)}", true},
      {"{`producer`}", true},  {"{<(producer)}", true},
      {"{>(consumer)}", true}, {"{pattern*}", true},
      {"{file[ab]}", true},    {"{@(left|right)}", true},
      {"{\"$value\"}", true},  {"{{$(producer)}}", true},
      {"{'$value'}", false},   {"{\\$value}", false},
      {"{$'literal'}", false},
  };
  for (size_t i = 0; valid && i < sizeof(brace_dynamic_words) /
                                      sizeof(brace_dynamic_words[0]);
       i++)
    valid =
        shell_source_word_has_dynamic_syntax(
            brace_dynamic_words[i].word, strlen(brace_dynamic_words[i].word)) ==
        brace_dynamic_words[i].dynamic;

  static const struct {
    const char *word;
    bool dynamic;
  } literal_word_cases[] = {
      {"$", false},         {"$:", false},      {"path$", false},
      {"[", false},         {"[]", false},      {"path[tail", false},
      {"[ab]", true},       {"$value", true},   {"$(command)", true},
      {"$((1 + 2))", true}, {"$[1 + 2]", true}, {"$\"locale\"", true},
  };
  for (size_t i = 0;
       valid && i < sizeof(literal_word_cases) / sizeof(literal_word_cases[0]);
       i++)
    valid =
        shell_source_word_has_dynamic_syntax(
            literal_word_cases[i].word, strlen(literal_word_cases[i].word)) ==
        literal_word_cases[i].dynamic;

  static const char word[] = "prefix$' x '$(printf y)$((1 + 2))\\ z next";
  valid =
      valid &&
      shell_source_skip_shell_word(word, sizeof(word) - 1, 0, &after) &&
      after == strlen("prefix$' x '$(printf y)$((1 + 2))\\ z") &&
      shell_source_skip_redirect("{fd}>out", 0, strlen("{fd}>out")) ==
          strlen("{fd}>out") &&
      shell_source_skip_redirect("{fd} >out", 0, strlen("{fd} >out")) == 0 &&
      shell_source_skip_redirect("{fd}\\\n>out", 0, strlen("{fd}\\\n>out")) ==
          strlen("{fd}\\\n>out") &&
      shell_source_skip_redirect("> >(cat)", 0, strlen("> >(cat)")) ==
          strlen("> >(cat)") &&
      shell_source_redirect_list_before_group("2>out 3>>err", 0,
                                              strlen("2>out 3>>err"));

  static const char invalid_redirect_gap[] = "> \nout";
  static const char continued_redirect_gap[] = "> \\\nout";
  static const char comment_redirect_gap[] = "> #name";
  static const char *const attached_comment_redirects[] = {
      ">#name",  "2>#name",  "<#name",   ">|#name", "<>#name",
      "&>#name", "&>>#name", "<<<#name", "<<#name", "<<-#name",
  };
  static const char quoted_hash_redirect[] = ">\"#name\"";
  static const char escaped_hash_heredoc[] = "<<\\#name";
  static const char quoted_hash_heredoc[] = "<<-'#name'";
  valid = valid &&
          shell_source_skip_redirect(invalid_redirect_gap, 0,
                                     sizeof(invalid_redirect_gap) - 1) == 0 &&
          shell_source_skip_redirect(continued_redirect_gap, 0,
                                     sizeof(continued_redirect_gap) - 1) ==
              sizeof(continued_redirect_gap) - 1 &&
          shell_source_skip_redirect(comment_redirect_gap, 0,
                                     sizeof(comment_redirect_gap) - 1) == 0 &&
          shell_source_skip_redirect(quoted_hash_redirect, 0,
                                     sizeof(quoted_hash_redirect) - 1) ==
              sizeof(quoted_hash_redirect) - 1 &&
          shell_source_skip_redirect(escaped_hash_heredoc, 0,
                                     sizeof(escaped_hash_heredoc) - 1) ==
              sizeof(escaped_hash_heredoc) - 1 &&
          shell_source_skip_redirect(quoted_hash_heredoc, 0,
                                     sizeof(quoted_hash_heredoc) - 1) ==
              sizeof(quoted_hash_heredoc) - 1;
  for (size_t i = 0; i < sizeof(attached_comment_redirects) /
                             sizeof(attached_comment_redirects[0]);
       i++)
    valid = valid && shell_source_skip_redirect(
                         attached_comment_redirects[i], 0,
                         strlen(attached_comment_redirects[i])) == 0;

  position = 0;
  valid =
      valid &&
      !shell_source_decode_ansi_c_quote("$'unterminated",
                                        strlen("$'unterminated"), &position,
                                        capture_source_byte, &capture) &&
      !shell_source_skip_arithmetic_expansion("$((1)", 5, 0, &after) &&
      !shell_source_find_balanced_parentheses("(unterminated", 13, 0, &after) &&
      !shell_source_skip_array_subscript("['unterminated", 14, 0, &after) &&
      !shell_source_find_parameter_array_subscript("${9[x]}", 7, 0, &after,
                                                   &subscript_start) &&
      !shell_source_array_assignment_is_compound("items[=", 7) &&
      !shell_source_skip_shell_word("$'unterminated", 14, 0, &after) &&
      !shell_source_skip_shell_word("trailing\\", 9, 0, &after) &&
      shell_source_skip_redirect_word("$'unterminated", 0, 14) == 14 &&
      /* A duplication target is syntactically a shell word; semantic parsing
       * later rejects a nonnumeric, non-symbolic descriptor reference. */
      shell_source_skip_redirect("2>&x", 0, 4) == 4 &&
      shell_source_skip_redirect(">&123file", 0, strlen(">&123file")) ==
          strlen(">&123file") &&
      shell_source_skip_redirect(">&-file", 0, strlen(">&-file")) ==
          strlen(">&-") &&
      shell_source_skip_redirect(">&\"-\"file", 0, strlen(">&\"-\"file")) ==
          strlen(">&\"-\"file") &&
      shell_source_skip_redirect(">&\\-file", 0, strlen(">&\\-file")) ==
          strlen(">&\\-file") &&
      shell_source_skip_redirect(">&$'-'file", 0, strlen(">&$'-'file")) ==
          strlen(">&$'-'file") &&
      shell_source_skip_redirect("999999999999>out", 0, 16) == 0 &&
      !shell_source_redirect_list_before_group("command", 0, 7);
  CHECK(valid);
}

/* The processor, canonical sequence builder, abstract model, and transform
 * model all expose executable-substitution metadata. Keep their semantic
 * boundary aligned for ANSI-C quote escapes, where a plain quote-state scan
 * can accidentally turn literal `$(` text into code. */
static void test_substitution_metadata_agreement(void) {
  static const struct {
    const char *input;
    bool executable;
  } cases[] = {
      {"printf $'it\\'s $(id)'", false},
      {"printf '$(id)'", false},
      {"printf \"\\$(id)\"", false},
      {"printf \"<(id)\"", false},
      {"printf \"$(id)\"", true},
      {"printf ${value:-$(id)}", true},
      {"printf \"x$VALUE$(id)\"", true},
      {"printf prefix${value:-$(id)}", true},
      {"printf <(id)", true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *input = cases[i].input;
    size_t length = strlen(input);
    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_netstring_buffer_t sequence = {0};
    size_t sequence_count = 0;
    bool features = !cases[i].executable;
    shell_abstract_command_t *abstract = NULL;
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;

    CHECK(shell_process_command(input, length, NULL, &infos, &info_count) ==
              SHELL_PROCESS_OK &&
          info_count == 1 && infos != NULL &&
          shell_command_info_has_dangerous_features(&infos[0]) ==
              cases[i].executable);
    CHECK(shell_processed_commands_parse(input, length, NULL, &commands,
                                         &command_count) == SHELL_PROCESS_OK &&
          command_count == 1 && commands != NULL &&
          shell_processed_command_has_dangerous_features(&commands[0], false) ==
              cases[i].executable);
    CHECK(shell_build_netargv_sequence_buffer(input, length, NULL, &sequence,
                                              &sequence_count,
                                              &features) == SHELL_PROCESS_OK &&
          sequence_count == 1 && features == cases[i].executable);
    CHECK(shell_abstract_command_parse(input, length, &abstract) ==
              SHELL_ABSTRACT_OK &&
          abstract != NULL && abstract->has_cmd_subst == cases[i].executable);
    CHECK(shell_transform_command_line(input, length, NULL, &transformed,
                                       &transformed_count) ==
              SHELL_TRANSFORM_OK &&
          transformed_count == 1 && transformed != NULL &&
          transformed[0] != NULL &&
          transformed[0]->has_shell_syntax == cases[i].executable);

    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
    shell_netstring_buffer_free(&sequence);
    shell_commands_free(commands, command_count);
    shell_command_infos_free(infos, info_count);
  }
}

/* Exercise the lower-level record parser at its public boundary.  These
 * helpers deliberately separate lexical records from the owning higher-level
 * result, so their error and limit behavior must stay failure-atomic too. */
static void test_production_record_parser_contract(void) {
  shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
  size_t count = SIZE_MAX;
  const shell_process_limits_t short_record = {
      .max_string_bytes = 1,
      .max_total_bytes = SIZE_MAX,
  };
  const shell_process_limits_t short_total = {
      .max_string_bytes = SIZE_MAX,
      .max_total_bytes = 1,
  };
  bool valid = shell_processed_commands_parse("", 0, NULL, &commands, &count) ==
                   SHELL_PROCESS_OK &&
               commands == NULL && count == 0;

  commands = (shell_command_t *)(uintptr_t)1;
  count = SIZE_MAX;
  valid = shell_processed_commands_parse("echo value", strlen("echo value"),
                                         &short_record, &commands,
                                         &count) == SHELL_PROCESS_OK &&
          commands != NULL && count == 1 && valid;
  shell_commands_free(commands, count);
  commands = (shell_command_t *)(uintptr_t)1;
  count = SIZE_MAX;
  valid = shell_processed_commands_parse("echo value", strlen("echo value"),
                                         &short_total, &commands,
                                         &count) == SHELL_PROCESS_OK &&
          commands != NULL && count == 1 && valid;
  shell_commands_free(commands, count);

  commands = NULL;
  count = 0;
  shell_processed_word_iterator_t iterator;
  shell_token_t word;
  valid = valid &&
          shell_processed_commands_parse(
              "left |& right", strlen("left |& right"), NULL, &commands,
              &count) == SHELL_PROCESS_OK &&
          commands != NULL && count == 2 &&
          shell_processed_command_word_count(&commands[0]) == 1 &&
          (shell_processed_word_iterator_init(&iterator, &commands[0]),
           shell_processed_word_iterator_next(&iterator, &word)) &&
          !shell_processed_word_iterator_next(&iterator, &word) &&
          shell_processed_command_has_pipe_output(&commands[0]) &&
          shell_processed_command_has_dangerous_features(&commands[1], true);
  shell_commands_free(commands, count);

  valid = valid &&
          shell_process_validate_supported_source(
              "while true; do :; done", strlen("while true; do :; done"),
              NULL) == SHELL_PROCESS_EPARSE &&
          shell_process_validate_supported_source("\x01"
                                                  "echo",
                                                  5, NULL) ==
              SHELL_PROCESS_EINPUT &&
          shell_process_validate_supported_source("echo 'unterminated",
                                                  strlen("echo 'unterminated"),
                                                  NULL) == SHELL_PROCESS_EPARSE;
  CHECK(valid);
}

/* Producer-owned compound tails belong to the final body record, whereas a
 * redirect-only command after a list boundary owns a real execution stage.
 * Exercise actual records, never synthetic out-of-span marker objects. This
 * suite runs against both the test-instrumented and shipping implementations.
 */
static void test_compound_record_boundaries(void) {
  static const struct {
    const char *source;
    const char *argv[3];
    const char *anomaly;
    const char *tail;
    size_t tail_record;
  } cases[] = {
      {"{ echo ok; } >out", {"4:echo,2:ok,"}, "4:echo,", ">out", 0},
      {"(echo ok) >out", {"4:echo,2:ok,"}, "4:echo,", ">out", 0},
      {"({ echo ok; }) >out", {"4:echo,2:ok,"}, "4:echo,", ">out", 0},
      {"({(echo ok)}) >out", {"4:echo,2:ok,"}, "4:echo,", ">out", 0},
      {"time ({ echo ok; }) >out", {"4:echo,2:ok,"}, "4:echo,", ">out", 0},
      {"time ({(echo ok)})", {"4:echo,2:ok,"}, "4:echo,", NULL, 0},
      {"({ echo a; echo b; }) | cat",
       {"4:echo,1:a,", "4:echo,1:b,", "3:cat,"},
       "4:echo,4:echo,3:cat,",
       NULL,
       0},
      {"time -p { echo ok; } >out", {"4:echo,2:ok,"}, "4:echo,", ">out", 0},
      {"time -p (echo ok) >out", {"4:echo,2:ok,"}, "4:echo,", ">out", 0},
      {"{ time cat; }", {"3:cat,"}, "3:cat,", NULL, 0},
      {"(time -p cat)", {"3:cat,"}, "3:cat,", NULL, 0},
      {"(cat <<<body)", {"3:cat,"}, "3:cat,", NULL, 0},
      {"time (cat <<<body)", {"3:cat,"}, "3:cat,", NULL, 0},
      {"(time -p (cat <<<body))", {"3:cat,"}, "3:cat,", NULL, 0},
      {"(cat <<<'a)b')", {"3:cat,"}, "3:cat,", NULL, 0},
      {"(cat <<<a\\)b)", {"3:cat,"}, "3:cat,", NULL, 0},
      {"(cat <<<$'a)b')", {"3:cat,"}, "3:cat,", NULL, 0},
      {"(cat <<<body |& cat)", {"3:cat,", "3:cat,"}, "3:cat,3:cat,", NULL, 0},
      {"{ ! cat; }", {"3:cat,"}, "3:cat,", NULL, 0},
      {"{ ! time -p cat; }", {"3:cat,"}, "3:cat,", NULL, 0},
      {"{ { ! time -p cat; }; }", {"3:cat,"}, "3:cat,", NULL, 0},
      {"{ time cat | printf x; }",
       {"3:cat,", "6:printf,1:x,"},
       "3:cat,6:printf,",
       NULL,
       0},
      {"{ time cat <<'EOF'; } |& cat\nliteral $(ignored)\nEOF\n",
       {"3:cat,", "3:cat,"},
       "3:cat,3:cat,",
       NULL,
       0},
      {"{ { echo ok; } >inner; } >outer",
       {"4:echo,2:ok,"},
       "4:echo,",
       ">outer",
       0},
      {"{ echo a; echo b; } >out",
       {"4:echo,1:a,", "4:echo,1:b,"},
       "4:echo,4:echo,",
       ">out",
       1},
      {"{ echo ok; } \\\n>out", {"4:echo,2:ok,"}, "4:echo,", ">out", 0},
      {"{ echo ok; } >'two words'",
       {"4:echo,2:ok,"},
       "4:echo,",
       ">'two words'",
       0},
      {"{ echo ok; } {fd}>out", {"4:echo,2:ok,"}, "4:echo,", "{fd}>out", 0},
      {"{ echo ok; } |& cat",
       {"4:echo,2:ok,", "3:cat,"},
       "4:echo,3:cat,",
       NULL,
       0},
      {"{ echo ok; } <<'EOF'\nliteral\nEOF\n",
       {"4:echo,2:ok,"},
       "4:echo,",
       "<<'EOF'",
       0},
      {"{ cat; } <<EOF\n$(printf body)\nEOF\n",
       {"3:cat,"},
       "6:printf,3:cat,",
       "<<EOF",
       0},
      {"{ { cat; } <<'INNER'\none\nINNER\n} <<'OUTER'\ntwo\nOUTER\n",
       {"3:cat,"},
       "3:cat,",
       "<<'OUTER'",
       0},
      {"{ echo ok; } >out; >next",
       {"4:echo,2:ok,", ""},
       "4:echo,0:,",
       ">out",
       0},
      {"{ echo ok; } >out\n>next",
       {"4:echo,2:ok,", ""},
       "4:echo,0:,",
       ">out",
       0},
      {"time { echo ok; } >out && >next",
       {"4:echo,2:ok,", ""},
       "4:echo,0:,",
       ">out",
       0},
      {"{ echo ok; } >out | >next",
       {"4:echo,2:ok,", ""},
       "4:echo,0:,",
       ">out",
       0},
      {"{ echo ok; } >out & >next",
       {"4:echo,2:ok,", ""},
       "4:echo,0:,",
       ">out",
       0},
      {"{ echo ok; } <<'EOF'\nbody\nEOF\n>next",
       {"4:echo,2:ok,", ""},
       "4:echo,0:,",
       "<<'EOF'",
       0},
      {"time -p { echo ok; } <<'EOF'\nbody\nEOF\n>next",
       {"4:echo,2:ok,", ""},
       "4:echo,0:,",
       "<<'EOF'",
       0},
      {"(echo ok) <<'EOF'\nbody\nEOF\n>next",
       {"4:echo,2:ok,", ""},
       "4:echo,0:,",
       "<<'EOF'",
       0},
      {"{ { echo ok; } <<'EOF'\nbody\nEOF\n} >out\n>next",
       {"4:echo,2:ok,", ""},
       "4:echo,0:,",
       ">out",
       0},
      {"{ >inside; } >out", {""}, "0:,", ">out", 0},
      {"time { >inside; } >out", {""}, "0:,", ">out", 0},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    const char *source = cases[c].source;
    size_t length = strlen(source);
    size_t expected_count = 0;
    bool policyable = true;
    while (expected_count < 3 && cases[c].argv[expected_count]) {
      policyable = policyable && cases[c].argv[expected_count][0] != '\0';
      expected_count++;
    }
    for (unsigned producer = 0; producer < 2; producer++) {
      shell_command_t *commands = NULL;
      size_t count = 0;
      bool parsed =
          producer == 0
              ? shell_tokenize_commands(source, length, &commands, &count) ==
                    SHELL_TOKENIZE_OK
              : shell_processed_commands_parse(source, length, NULL, &commands,
                                               &count) == SHELL_PROCESS_OK;
      CHECK(parsed && count == expected_count);
      bool tail_found = cases[c].tail == NULL;
      size_t tail_position =
          cases[c].tail ? (size_t)(strstr(source, cases[c].tail) - source) : 0;
      for (size_t i = 0; i < count && i < expected_count; i++) {
        const shell_command_t *command = &commands[i];
        CHECK(command->token_count != 0 && command->tokens != NULL &&
              command->start_pos <= command->end_pos &&
              command->end_pos <= length);
        size_t words = 0;
        CHECK(shell_netstring_validate(cases[c].argv[i],
                                       strlen(cases[c].argv[i]),
                                       &words) == SHELL_NETSTRING_OK);
        CHECK(shell_processed_command_word_count(command) == words);
        for (size_t t = 0; t < command->token_count; t++) {
          const shell_token_t *token = &command->tokens[t];
          bool contained =
              token->position >= command->start_pos &&
              token->position <= command->end_pos &&
              token->length <= command->end_pos - token->position &&
              token->start == source + token->position;
          if (!contained)
            fprintf(stderr,
                    "compound record span mismatch: %s producer=%u record=%zu "
                    "span=%zu..%zu token=%zu..%zu\n",
                    source, producer, i, command->start_pos, command->end_pos,
                    token->position, token->position + token->length);
          CHECK(contained);
          if (cases[c].tail && token->position == tail_position) {
            CHECK(i == cases[c].tail_record && command->ends_group);
            tail_found = true;
          }
        }
        shell_transformed_command_t *transformed = NULL;
        CHECK(shell_transform_command(command, NULL, &transformed) ==
                  SHELL_TRANSFORM_OK &&
              transformed != NULL &&
              transformed->token_count == command->token_count &&
              strlen(transformed->original_command) ==
                  command->end_pos - command->start_pos &&
              memcmp(transformed->original_command, source + command->start_pos,
                     command->end_pos - command->start_pos) == 0);
        shell_transformed_command_free(transformed);
      }
      CHECK(tail_found);
      shell_commands_free(commands, count);
    }

    shell_command_info_t *flat = NULL;
    size_t count = 0;
    CHECK(shell_process_command(source, length, NULL, &flat, &count) ==
              SHELL_PROCESS_OK &&
          count == expected_count);
    for (size_t i = 0; i < count && i < expected_count; i++) {
      shell_netstring_buffer_t argv = {0};
      CHECK(shell_render_netargv_buffer(&flat[i], NULL, &argv) ==
                SHELL_PROCESS_OK &&
            argv.length == strlen(cases[c].argv[i]) &&
            memcmp(argv.data, cases[c].argv[i], argv.length) == 0);
      shell_netstring_buffer_free(&argv);
    }
    shell_command_infos_free(flat, count);

    shell_netstring_buffer_t policy = {0}, raw = {0}, typed = {0};
    bool features = false;
    shell_process_status_t status = shell_build_netargv_sequence_buffer(
        source, length, NULL, &policy, &count, &features);
    if (policyable) {
      if (status != SHELL_PROCESS_OK || count != expected_count || !features)
        fprintf(stderr,
                "compound policy sequence: %s status=%d count=%zu "
                "expected=%zu features=%d\n",
                source, status, count, expected_count, features);
      CHECK(status == SHELL_PROCESS_OK && count == expected_count && features);
      shell_netstring_iter_t iter;
      shell_netstring_view_t record;
      CHECK(shell_netstring_iter_init(&iter, policy.data, policy.length) ==
            SHELL_NETSTRING_OK);
      for (size_t i = 0; i < expected_count; i++)
        CHECK(shell_netstring_iter_next(&iter, &record) == SHELL_NETSTRING_OK &&
              record.payload_length == strlen(cases[c].argv[i]) &&
              memcmp(record.payload, cases[c].argv[i], record.payload_length) ==
                  0);
      CHECK(shell_netstring_iter_next(&iter, &record) == SHELL_NETSTRING_DONE);
    } else {
      CHECK(status == SHELL_PROCESS_EPARSE && policy.data == NULL &&
            policy.length == 0 && count == 0 && !features);
    }
    CHECK(shell_build_anomaly_netseqs_buffer(source, length, NULL, &raw, &typed,
                                             &count) == SHELL_PROCESS_OK &&
          raw.length == strlen(cases[c].anomaly) &&
          memcmp(raw.data, cases[c].anomaly, raw.length) == 0);
    size_t raw_count = 0, typed_count = 0;
    CHECK(shell_netstring_validate(raw.data, raw.length, &raw_count) ==
              SHELL_NETSTRING_OK &&
          shell_netstring_validate(typed.data, typed.length, &typed_count) ==
              SHELL_NETSTRING_OK &&
          raw_count == count && typed_count == count);
    shell_netstring_iter_t raw_iter, typed_iter;
    shell_netstring_view_t raw_record, typed_record;
    CHECK(shell_netstring_iter_init(&raw_iter, raw.data, raw.length) ==
              SHELL_NETSTRING_OK &&
          shell_netstring_iter_init(&typed_iter, typed.data, typed.length) ==
              SHELL_NETSTRING_OK);
    while (shell_netstring_iter_next(&raw_iter, &raw_record) ==
           SHELL_NETSTRING_OK) {
      bool has_typed = shell_netstring_iter_next(&typed_iter, &typed_record) ==
                       SHELL_NETSTRING_OK;
      CHECK(has_typed);
      if (has_typed && raw_record.payload_length == 0)
        CHECK(typed_record.payload_length == 3 &&
              memcmp(typed_record.payload, "0:,", 3) == 0);
    }
    CHECK(shell_netstring_iter_next(&typed_iter, &typed_record) ==
          SHELL_NETSTRING_DONE);
    shell_netstring_buffer_free(&policy);
    shell_netstring_buffer_free(&raw);
    shell_netstring_buffer_free(&typed);
  }
}

static void test_processed_command_conveniences(void) {
  static const char input[] = "printf 'two words' > /tmp/out";
  shell_command_info_t *infos = NULL;
  size_t info_count = 0;
  size_t netargv_length = 0;
  size_t written = 0;
  char netargv[64] = {0};
  shell_netstring_buffer_t rendered = {0};
  CHECK(shell_process_command(input, sizeof(input) - 1, NULL, &infos,
                              &info_count) == SHELL_PROCESS_OK);
  CHECK(infos && info_count == 1 && infos[0].has_redirections &&
        shell_measure_netargv(&infos[0], &netargv_length) == SHELL_PROCESS_OK &&
        netargv_length < sizeof(netargv) &&
        shell_write_netargv(&infos[0], netargv, netargv_length + 1, &written) ==
            SHELL_PROCESS_OK &&
        written == netargv_length &&
        shell_netstring_validate(netargv, written, NULL) ==
            SHELL_NETSTRING_OK &&
        shell_render_netargv_buffer(&infos[0], NULL, &rendered) ==
            SHELL_PROCESS_OK &&
        (strlen(netargv) != rendered.length ||
         memcmp(netargv, rendered.data, strlen(netargv))) == 0);
  shell_netstring_buffer_free(&rendered);

  const shell_process_limits_t tiny = {1, SIZE_MAX, 0};
  CHECK(shell_write_netargv(&infos[0], netargv, netargv_length, &written) ==
            SHELL_PROCESS_EOUTPUT_LIMIT &&
        shell_render_netargv_buffer(&infos[0], &tiny, &rendered) ==
            SHELL_PROCESS_EOUTPUT_LIMIT &&
        rendered.data == NULL);
  shell_command_infos_free(infos, info_count);

  infos = NULL;
  info_count = 0;
  CHECK(shell_process_command("echo value", strlen("echo value"), &tiny, &infos,
                              &info_count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
        infos == NULL && info_count == 0);

  infos = NULL;
  info_count = 0;
  rendered = (shell_netstring_buffer_t){0};
  netargv_length = SIZE_MAX;
  CHECK(shell_process_command("> /tmp/out", strlen("> /tmp/out"), NULL, &infos,
                              &info_count) == SHELL_PROCESS_OK &&
        infos != NULL && info_count == 1 && infos[0].command_token_count == 0 &&
        infos[0].has_redirections &&
        shell_measure_netargv(&infos[0], &netargv_length) == SHELL_PROCESS_OK &&
        netargv_length == 0 &&
        shell_render_netargv_buffer(&infos[0], NULL, &rendered) ==
            SHELL_PROCESS_OK &&
        rendered.data != NULL &&
        (rendered.length != sizeof("") - 1 ||
         memcmp(rendered.data, "", rendered.length)) == 0);
  shell_netstring_buffer_free(&rendered);
  shell_command_infos_free(infos, info_count);

  /* Source words use fragment truncation; directly supplied canonical argv
   * continues to preserve its binary payload. */
  static const char binary_source[] = "printf $'a\\0b'";
  shell_token_t binary_tokens[] = {
      {.type = SHELL_TOKEN_COMMAND, .start = "printf", .length = 6},
      {.type = SHELL_TOKEN_ARGUMENT, .start = "a\0b", .length = 3},
  };
  shell_command_info_t binary_info = {
      .command_tokens = binary_tokens,
      .command_token_count = 2,
  };
  shell_netstring_buffer_t binary_argv = {0};
  shell_netstring_buffer_t binary_sequence = {0};
  size_t records = 0;
  size_t sequence_count = 0;
  bool has_features = true;
  infos = NULL;
  info_count = 0;
  CHECK(shell_process_command(binary_source, sizeof(binary_source) - 1, NULL,
                              &infos, &info_count) == SHELL_PROCESS_OK &&
        infos != NULL && info_count == 1 &&
        shell_render_netargv_buffer(&binary_info, NULL, &binary_argv) ==
            SHELL_PROCESS_OK &&
        shell_netstring_validate(binary_argv.data, binary_argv.length,
                                 &records) == SHELL_NETSTRING_OK &&
        records == 2 && memchr(binary_argv.data, '\0', binary_argv.length) &&
        shell_build_netargv_sequence_buffer(
            binary_source, sizeof(binary_source) - 1, NULL, &binary_sequence,
            &sequence_count, &has_features) == SHELL_PROCESS_OK &&
        sequence_count == 1 && !has_features &&
        binary_sequence.length == strlen("13:6:printf,1:a,,") &&
        !memcmp(binary_sequence.data, "13:6:printf,1:a,,",
                binary_sequence.length));
  shell_command_infos_free(infos, info_count);
  shell_netstring_buffer_free(&binary_sequence);
  shell_netstring_buffer_free(&binary_argv);

  /* The measure/write and visitor forms are the allocation-free boundary for
   * callers that need decoded bytes. In particular, a visitor may stop after
   * a useful prefix without turning a valid ANSI-C or escaped word into an
   * error. */
  source_capture_t decoded = {.stop_after = 2};
  size_t decoded_length = SIZE_MAX;
  CHECK(shell_visit_decoded_word("$'a\\0b'", strlen("$'a\\0b'"),
                                 capture_decoded_byte, &decoded,
                                 &decoded_length) == SHELL_PROCESS_OK &&
        decoded_length == 2 && decoded.length == 2 && decoded.bytes[0] == 'a' &&
        decoded.bytes[1] == '\0');
  decoded = (source_capture_t){.stop_after = 2};
  decoded_length = SIZE_MAX;
  CHECK(shell_visit_decoded_word("a\\ bc", strlen("a\\ bc"),
                                 capture_decoded_byte, &decoded,
                                 &decoded_length) == SHELL_PROCESS_OK &&
        decoded_length == 2 && decoded.length == 2 && decoded.bytes[0] == 'a' &&
        decoded.bytes[1] == ' ');
  static const char *const control_words[] = {"$'\\c\\\\X'", "$'\\c\\'X'"};
  for (size_t i = 0; i < sizeof(control_words) / sizeof(control_words[0]);
       ++i) {
    decoded = (source_capture_t){.stop_after = 1};
    decoded_length = SIZE_MAX;
    CHECK(shell_visit_decoded_word(control_words[i], strlen(control_words[i]),
                                   capture_decoded_byte, &decoded,
                                   &decoded_length) == SHELL_PROCESS_OK &&
          decoded_length == 1 && decoded.length == 1 &&
          decoded.bytes[0] == 0x1c);
  }

  /* Semantic word projection leaves expansion unevaluated, but it can change
   * its spelling. Exact syntax remains in the caller's source span. */
  {
    static const char source[] = "${v:-$'a\\0b'}";
    static const char expected[] = "${v:-a}";
    source_capture_t projection = {0};
    size_t visited = SIZE_MAX, measured = SIZE_MAX, filled = SIZE_MAX;
    char bytes[sizeof(expected) - 1];
    CHECK(shell_process_visit_word_value(source, sizeof(source) - 1,
                                         capture_decoded_byte, &projection,
                                         &visited) == SHELL_PROCESS_OK &&
          visited == sizeof(expected) - 1 && projection.length == visited &&
          !memcmp(projection.bytes, expected, visited));
    CHECK(shell_process_measure_word_value(source, sizeof(source) - 1,
                                           &measured) == SHELL_PROCESS_OK &&
          measured == visited);
    CHECK(shell_process_write_word_value(source, sizeof(source) - 1, bytes,
                                         sizeof(bytes),
                                         &filled) == SHELL_PROCESS_OK &&
          filled == measured && !memcmp(bytes, expected, filled));
  }

  /* A canonical policy argv requires a program word. Redirect-only source is
   * still a real anomaly stage, but deliberately cannot become a netargv
   * command. Compound-tail redirects must likewise remain structural rather
   * than becoming a phantom second argv record. */
  shell_netstring_buffer_t no_argv = {0};
  size_t no_argv_count = SIZE_MAX;
  bool no_argv_features = true;
  shell_processed_commands_t redirect_only = {0};
  shell_netstring_buffer_t grouped_sequence = {0};
  size_t grouped_count = 0;
  bool grouped_features = false;
  CHECK(shell_build_netargv_sequence_buffer(
            ">out", strlen(">out"), NULL, &no_argv, &no_argv_count,
            &no_argv_features) == SHELL_PROCESS_EPARSE &&
        no_argv.data == NULL && no_argv_count == 0 && !no_argv_features &&
        shell_process_commands(">out", strlen(">out"), NULL, &redirect_only) ==
            SHELL_PROCESS_OK &&
        redirect_only.commands == NULL && redirect_only.command_count == 0 &&
        shell_build_netargv_sequence_buffer(
            "{ printf child; } >out", strlen("{ printf child; } >out"), NULL,
            &grouped_sequence, &grouped_count,
            &grouped_features) == SHELL_PROCESS_OK &&
        grouped_count == 1 && grouped_features &&
        shell_netstring_validate(grouped_sequence.data, grouped_sequence.length,
                                 NULL) == SHELL_NETSTRING_OK);
  shell_netstring_buffer_free(&grouped_sequence);
  shell_processed_commands_free(&redirect_only);

  /* Empty timing is a real shell operation but has no executable argv for a
   * policy to classify. Both canonical sequence forms omit that record,
   * retain the shell-feature signal, and continue with later list members.
   * A timed redirect-only stage remains unpolicyable rather than disappearing
   * with its observable I/O effect. */
  shell_netstring_buffer_t timed_sequence = {0};
  size_t timed_count = SIZE_MAX;
  bool timed_features = false;
  shell_netstring_buffer_t timed_buffer = {0};
  CHECK(shell_build_netargv_sequence_buffer(
            "time", strlen("time"), NULL, &timed_sequence, &timed_count,
            &timed_features) == SHELL_PROCESS_OK &&
        timed_sequence.data != NULL && timed_sequence.data[0] == '\0' &&
        timed_count == 0 && timed_features);
  shell_netstring_buffer_free(&timed_sequence);
  timed_sequence = (shell_netstring_buffer_t){0};
  timed_count = SIZE_MAX;
  timed_features = false;
  CHECK(shell_build_netargv_sequence_buffer(
            "time !; echo x", strlen("time !; echo x"), NULL, &timed_buffer,
            &timed_count, &timed_features) == SHELL_PROCESS_OK &&
        timed_buffer.data != NULL && timed_buffer.length == 15 &&
        memcmp(timed_buffer.data, "11:4:echo,1:x,,", 15) == 0 &&
        timed_count == 1 && timed_features);
  shell_netstring_buffer_free(&timed_buffer);
  timed_count = SIZE_MAX;
  timed_features = true;
  CHECK(shell_build_netargv_sequence_buffer(
            "time >/tmp/timing", strlen("time >/tmp/timing"), NULL,
            &timed_buffer, &timed_count,
            &timed_features) == SHELL_PROCESS_EPARSE &&
        timed_buffer.data == NULL && timed_buffer.length == 0 &&
        timed_count == 0 && !timed_features);

  /* Producer outputs are initialized empty and released before reuse. */
  shell_netstring_buffer_t rendered_buffer = {0};
  infos = NULL;
  info_count = 0;
  CHECK(shell_process_command("echo value", strlen("echo value"), NULL, &infos,
                              &info_count) == SHELL_PROCESS_OK &&
        infos != NULL && info_count == 1 &&
        shell_render_netargv_buffer(&infos[0], NULL, &rendered_buffer) ==
            SHELL_PROCESS_OK &&
        rendered_buffer.data != NULL && rendered_buffer.length != 0);
  shell_netstring_buffer_free(&rendered_buffer);
  CHECK(((&rendered_buffer)->data == NULL && (&rendered_buffer)->length == 0));
  shell_command_infos_free(infos, info_count);

  static const char unsupported_byte[] = {'e', 'c', 'h', 'o', '\0', 'x'};
  infos = (shell_command_info_t *)(uintptr_t)1;
  info_count = SIZE_MAX;
  CHECK(shell_process_command(unsupported_byte, sizeof(unsupported_byte), NULL,
                              &infos, &info_count) == SHELL_PROCESS_EINPUT &&
        infos == NULL && info_count == 0);
}

static void test_production_processor_routing_contract(void) {
  static const char *const cases[] = {
      "VAR=value command --flag \"two words\" ''",
      "command $VAR ${VAR:-default} $1 $? $((1 + 2))",
      "command $(printf one) `printf two` *.c [ab] ?",
      "command >out >>append 2>err 2>>err <>read-write >|clobber",
      "command 0<&3 1>&2 2>&- 3<<<body",
      "command &>combined &>>combined",
      "command {input}<in {output}>out {append}>>log {both}<>rw",
      "command <(producer) >(consumer) < <(input) > >(output)",
      "command <<EOF\nbody\nEOF\n",
      "! command | next",
      "! ! command |& next",
      "command |& next | final",
      "{ command; } |& { next; }",
      "command && next || fallback; final &",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    shell_processed_commands_t processed = {0};
    bool valid = shell_process_command(cases[i], strlen(cases[i]), NULL, &infos,
                                       &info_count) == SHELL_PROCESS_OK &&
                 info_count > 0 &&
                 shell_process_commands(cases[i], strlen(cases[i]), NULL,
                                        &processed) == SHELL_PROCESS_OK &&
                 processed.command_count > 0;
    for (size_t command = 0; valid && command < info_count; command++) {
      size_t netargv_length = 0;
      valid = shell_measure_netargv(&infos[command], &netargv_length) ==
                  SHELL_PROCESS_OK &&
              netargv_length > 0;
    }
    CHECK(valid);
    shell_command_infos_free(infos, info_count);
    shell_processed_commands_free(&processed);
  }

  shell_processed_commands_t negated = {0};
  CHECK(shell_process_commands("! false |& cat | sort",
                               strlen("! false |& cat | sort"), NULL,
                               &negated) == SHELL_PROCESS_OK &&
        negated.command_count == 3 && negated.commands[0].pipeline_negated &&
        negated.commands[1].pipeline_negated &&
        negated.commands[2].pipeline_negated &&
        negated.commands[0].pipeline_negation_count == 1 &&
        negated.commands[1].pipeline_negation_count == 1 &&
        negated.commands[2].pipeline_negation_count == 1 &&
        negated.commands[0].pipe_output_mode ==
            SHELL_PIPE_MODE_STDOUT_AND_STDERR &&
        negated.commands[1].pipe_output_mode == SHELL_PIPE_MODE_STDOUT &&
        !negated.commands[2].has_pipe_output &&
        negated.commands[2].pipe_output_mode == SHELL_PIPE_MODE_NONE);
  shell_processed_commands_free(&negated);
}

/* Descriptor targets are classified after Bash word decoding. Exercise the
 * shipping library's direct, group-owned, and graph-facing paths together so
 * leading zeroes, quoted values, legacy combined output, and overflow cannot
 * drift into different interpretations. */
static void test_production_fd_target_contract(void) {
  static const struct {
    const char *word;
    shell_process_fd_target_t kind;
    uint32_t descriptor;
  } target_cases[] = {
      {"0000000000000000000000000000000000000001", SHELL_PROCESS_FD_TARGET_FD,
       1},
      {"$'0000000000000000000000000000000000000001'",
       SHELL_PROCESS_FD_TARGET_FD, 1},
      {"2147483647", SHELL_PROCESS_FD_TARGET_FD, 2147483647u},
      {"-", SHELL_PROCESS_FD_TARGET_CLOSE, SHELL_PROCESS_FD_NONE},
      {"target123", SHELL_PROCESS_FD_TARGET_PATH, SHELL_PROCESS_FD_NONE},
      {"2147483648", SHELL_PROCESS_FD_TARGET_INVALID, SHELL_PROCESS_FD_NONE},
      {"00000000000000000000000000000000002147483648",
       SHELL_PROCESS_FD_TARGET_INVALID, SHELL_PROCESS_FD_NONE},
      {"$'a\\0b'", SHELL_PROCESS_FD_TARGET_PATH, SHELL_PROCESS_FD_NONE},
  };
  for (size_t i = 0; i < sizeof(target_cases) / sizeof(target_cases[0]); i++) {
    uint32_t descriptor = UINT32_MAX;
    CHECK(shell_process_classify_static_fd_target(
              target_cases[i].word, strlen(target_cases[i].word),
              &descriptor) == target_cases[i].kind &&
          descriptor == target_cases[i].descriptor);
  }

  /* `>&word` has one shared classifier for the group collector and the
   * depgraph. Exercise its three outcomes directly so ordinary pathnames,
   * descriptor syntax, and deferred command substitutions cannot drift. */
  static const struct {
    const char *word;
    shell_process_legacy_redirect_target_t kind;
  } legacy_cases[] = {
      {"file", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"$", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"$:", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"[", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"[]", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"file[part", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{literal$}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"123", SHELL_PROCESS_LEGACY_REDIRECT_DUPLICATION},
      {"-", SHELL_PROCESS_LEGACY_REDIRECT_DUPLICATION},
      {"$fd", SHELL_PROCESS_LEGACY_REDIRECT_DUPLICATION},
      {"<(producer)", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {">(consumer)", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"path-$(printf value)", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"\"path\"$(printf value)", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"literal$var", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"literal${var}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"literal$((1 + 2))", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"\"\"literal$(printf value)", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"\\\nliteral$(printf value)", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"'literal'$var", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"\\literal$var", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"$'literal'$var", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"\"$var\"literal", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"\"\\$\"$var", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"\"\\x\"$var", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"literal$:$var", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"\"$:$var\"", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"\"$((1 + 2))\"literal", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"\"$(printf value)\"literal", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"\"`printf value`\"literal", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"prefix<(producer)", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"~user/literal$var", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"literal[ab]$var", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"literal*.log", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"literal{one,two}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"literal@(one|two)", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"$(printf 2)", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"`printf 2`", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"$((1 + 2))", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"*.log", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"*", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"[12]$var", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"[[:digit:]]", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"[[=a=]]", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"[[.a.]]", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"[12$var", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"[$fd", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"[]$fd", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"file[[:digit:]]", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"\\", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"\"\\", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"\"\\\n\"$var", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"$'unterminated$var", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"prefix<(unterminated", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"{one,two}", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"@(one|two)", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"$value", SHELL_PROCESS_LEGACY_REDIRECT_DUPLICATION},
      {"2147483648", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"00000000000000000000000000000000002147483648",
       SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"\"\"", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"$'a\\0b'", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"$'a\\0b'$var", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"$'path\\0ignored'$var", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"$'123\\0path'$var", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"$'\\0ignored'path$var", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"$'\\0ignored'$var", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"$'\\0ignored'", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
  };
  for (size_t i = 0; i < sizeof(legacy_cases) / sizeof(legacy_cases[0]); i++)
    CHECK(shell_process_classify_legacy_output_target(
              legacy_cases[i].word, strlen(legacy_cases[i].word)) ==
          legacy_cases[i].kind);
  CHECK(shell_process_classify_legacy_output_target("", 0) ==
        SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED);

  /* Every accepted dynamic pathname stays a redirect operand rather than
   * leaking into argv. Exercise structured, flat, and canonical sequence
   * producers together so the shared classifier cannot diverge at an API
   * boundary. */
  static const char *const prefixed_dynamic_direct[] = {
      "printf x >&literal$var",
      "printf x >&literal${var}",
      "printf x >&literal$((1 + 2))",
      "printf x >&\"\"literal$(printf value)",
      "printf x >&\\\nliteral$(printf value)",
  };
  for (size_t i = 0;
       i < sizeof(prefixed_dynamic_direct) / sizeof(prefixed_dynamic_direct[0]);
       i++) {
    shell_processed_commands_t processed = {0};
    shell_command_info_t *flat = NULL;
    size_t flat_count = 0;
    shell_netstring_buffer_t netargv_sequence = {0};
    size_t netargv_count = 0;
    bool has_features = false;
    size_t input_length = strlen(prefixed_dynamic_direct[i]);
    CHECK(shell_process_commands(prefixed_dynamic_direct[i], input_length, NULL,
                                 &processed) == SHELL_PROCESS_OK &&
          processed.command_count == 1 &&
          processed.commands[0].command_token_count == 2 &&
          shell_process_command(prefixed_dynamic_direct[i], input_length, NULL,
                                &flat, &flat_count) == SHELL_PROCESS_OK &&
          flat_count == 1 && flat[0].command_token_count == 2 &&
          shell_build_netargv_sequence_buffer(
              prefixed_dynamic_direct[i], input_length, NULL, &netargv_sequence,
              &netargv_count, &has_features) == SHELL_PROCESS_OK &&
          netargv_sequence.data != NULL && netargv_count == 1);
    shell_netstring_buffer_free(&netargv_sequence);
    shell_command_infos_free(flat, flat_count);
    shell_processed_commands_free(&processed);
  }

  static const char *const ambiguous_direct[] = {
      "printf x >&$(printf 2)",
      "printf x >&`printf 2`",
  };
  for (size_t i = 0; i < sizeof(ambiguous_direct) / sizeof(ambiguous_direct[0]);
       i++) {
    shell_processed_commands_t processed = {
        .commands = (shell_command_info_t *)(uintptr_t)1,
        .command_count = SIZE_MAX,
    };
    shell_command_info_t *flat = (shell_command_info_t *)(uintptr_t)1;
    size_t flat_count = SIZE_MAX;
    CHECK(shell_process_commands(ambiguous_direct[i],
                                 strlen(ambiguous_direct[i]), NULL,
                                 &processed) == SHELL_PROCESS_EPARSE &&
          processed.commands == NULL && processed.command_count == 0 &&
          shell_process_command(ambiguous_direct[i],
                                strlen(ambiguous_direct[i]), NULL, &flat,
                                &flat_count) == SHELL_PROCESS_EPARSE &&
          flat == NULL && flat_count == 0);
    shell_processed_commands_free(&processed);
    shell_command_infos_free(flat, flat_count);
  }

  /* Static targets that cannot name a descriptor, close marker, or pathname
   * are rejected before every canonical producer can build a partial result.
   * The graph already rejects these forms; keep direct processor, flat, and
   * netsequence APIs on that same fail-closed contract. */
  static const char *const invalid_static_direct[] = {
      "printf x >&2147483648",
      "printf x >&00000000000000000000000000000000002147483648",
  };
  for (size_t i = 0;
       i < sizeof(invalid_static_direct) / sizeof(invalid_static_direct[0]);
       i++) {
    shell_processed_commands_t processed = {
        .commands = (shell_command_info_t *)(uintptr_t)1,
        .command_count = SIZE_MAX,
    };
    shell_command_info_t *flat = (shell_command_info_t *)(uintptr_t)1;
    size_t flat_count = SIZE_MAX;
    shell_netstring_buffer_t netargv_sequence = {0};
    size_t netargv_count = SIZE_MAX;
    bool has_features = true;
    shell_netstring_buffer_t command_netseq = {0};
    size_t command_netseq_count = SIZE_MAX;
    shell_anomaly_stages_t stages = {
        .commands = (shell_command_t *)(uintptr_t)1,
        .count = SIZE_MAX,
    };
    size_t input_length = strlen(invalid_static_direct[i]);
    CHECK(shell_process_commands(invalid_static_direct[i], input_length, NULL,
                                 &processed) == SHELL_PROCESS_EPARSE &&
          processed.commands == NULL && processed.command_count == 0 &&
          shell_process_command(invalid_static_direct[i], input_length, NULL,
                                &flat, &flat_count) == SHELL_PROCESS_EPARSE &&
          flat == NULL && flat_count == 0 &&
          shell_build_netargv_sequence_buffer(
              invalid_static_direct[i], input_length, NULL, &netargv_sequence,
              &netargv_count, &has_features) == SHELL_PROCESS_EPARSE &&
          netargv_sequence.data == NULL && netargv_count == 0 &&
          !has_features &&
          shell_build_command_netseq_buffer(
              invalid_static_direct[i], input_length, NULL, &command_netseq,
              &command_netseq_count) == SHELL_PROCESS_EPARSE &&
          command_netseq.data == NULL && command_netseq_count == 0 &&
          shell_anomaly_stages_parse(invalid_static_direct[i], input_length,
                                     NULL, &stages) == SHELL_PROCESS_EPARSE &&
          stages.commands == NULL && stages.count == 0);
  }

  /* A quoted empty legacy operand is valid syntax. Bash reaches redirect
   * setup, fails to open the empty pathname, and suppresses command execution;
   * every syntax/canonical producer must therefore preserve the command. */
  static const char empty_legacy[] = "printf x >&\"\"";
  shell_processed_commands_t empty_processed = {0};
  shell_command_info_t *empty_flat = NULL;
  size_t empty_flat_count = 0;
  shell_netstring_buffer_t empty_netargv = {0};
  size_t empty_netargv_count = 0;
  bool empty_features = false;
  shell_netstring_buffer_t empty_commands = {0};
  size_t empty_command_count = 0;
  shell_anomaly_stages_t empty_stages = {0};
  CHECK(shell_process_commands(empty_legacy, sizeof(empty_legacy) - 1, NULL,
                               &empty_processed) == SHELL_PROCESS_OK &&
        empty_processed.command_count == 1 &&
        shell_process_command(empty_legacy, sizeof(empty_legacy) - 1, NULL,
                              &empty_flat,
                              &empty_flat_count) == SHELL_PROCESS_OK &&
        empty_flat_count == 1 &&
        shell_build_netargv_sequence_buffer(
            empty_legacy, sizeof(empty_legacy) - 1, NULL, &empty_netargv,
            &empty_netargv_count, &empty_features) == SHELL_PROCESS_OK &&
        empty_netargv_count == 1 &&
        shell_build_command_netseq_buffer(
            empty_legacy, sizeof(empty_legacy) - 1, NULL, &empty_commands,
            &empty_command_count) == SHELL_PROCESS_OK &&
        empty_command_count == 1 &&
        shell_anomaly_stages_parse(empty_legacy, sizeof(empty_legacy) - 1, NULL,
                                   &empty_stages) == SHELL_PROCESS_OK &&
        empty_stages.count == 1);
  shell_anomaly_stages_free(&empty_stages);
  shell_netstring_buffer_free(&empty_commands);
  shell_netstring_buffer_free(&empty_netargv);
  shell_command_infos_free(empty_flat, empty_flat_count);
  shell_processed_commands_free(&empty_processed);

  /* The shared low-level validator must stop the redirect operand at a list
   * separator.  Otherwise the trailing semicolon becomes part of `$fd`,
   * spuriously turning a valid named-descriptor redirect into unsupported
   * dynamic syntax.  Anomaly staging exercises that full-token path. */
  static const char named_fd_sequence[] = "exec {fd}>/tmp/out; printf x >&$fd";
  shell_anomaly_stages_t named_fd_stages = {0};
  CHECK(shell_anomaly_stages_parse(named_fd_sequence,
                                   sizeof(named_fd_sequence) - 1, NULL,
                                   &named_fd_stages) == SHELL_PROCESS_OK &&
        named_fd_stages.count == 2);
  shell_anomaly_stages_free(&named_fd_stages);

  static const char *const direct_cases[] = {
      "printf x >&0000000000000000000000000000000000000001",
      "printf x >&$'0000000000000000000000000000000000000001'",
      "printf x >&123file",
      "printf x 1>&123file",
      "printf x >&-file",
      "printf x >&\"-\"file",
      "printf x >&\\-file",
      "printf x >&$'-'file",
      "printf x >&\"quoted combined\"",
      "printf x >&$'a\\0b'",
      "printf x {sink}>out >&\"${sink}\"",
      "printf x 0<&1 3>&-",
  };
  for (size_t i = 0; i < sizeof(direct_cases) / sizeof(direct_cases[0]); i++) {
    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    shell_dep_graph_t graph = {0};
    CHECK(shell_process_command(direct_cases[i], strlen(direct_cases[i]), NULL,
                                &infos, &info_count) == SHELL_PROCESS_OK &&
          info_count == 1 && infos != NULL &&
          shell_dep_graph_parse(direct_cases[i], strlen(direct_cases[i]), ".",
                                NULL, &graph) == SHELL_DEP_OK &&
          shell_dep_graph_validate(&graph).valid);
    shell_command_infos_free(infos, info_count);
  }

  shell_command_info_t *close_suffix_infos = NULL;
  size_t close_suffix_count = 0;
  shell_netstring_buffer_t close_suffix_netargv = {0};
  shell_dep_graph_t close_suffix_graph = {0};
  const char close_suffix[] = "printf x >&-file";
  CHECK(shell_process_command(close_suffix, sizeof(close_suffix) - 1, NULL,
                              &close_suffix_infos,
                              &close_suffix_count) == SHELL_PROCESS_OK &&
        close_suffix_count == 1 && close_suffix_infos != NULL &&
        shell_render_netargv_buffer(&close_suffix_infos[0], NULL,
                                    &close_suffix_netargv) ==
            SHELL_PROCESS_OK &&
        (close_suffix_netargv.length != sizeof("6:printf,1:x,4:file,") - 1 ||
         memcmp(close_suffix_netargv.data, "6:printf,1:x,4:file,",
                close_suffix_netargv.length)) == 0 &&
        shell_dep_graph_parse(close_suffix, sizeof(close_suffix) - 1, ".", NULL,
                              &close_suffix_graph) == SHELL_DEP_OK &&
        shell_dep_graph_validate(&close_suffix_graph).valid);
  shell_netstring_buffer_free(&close_suffix_netargv);
  shell_command_infos_free(close_suffix_infos, close_suffix_count);

  static const char *const group_cases[] = {
      "{ printf x; } >&0000000000000000000000000000000000000001",
      "{ printf x; } >&$'0000000000000000000000000000000000000001'",
      "{ printf x; } >&123file",
      "{ printf x; } >&$'a\\0b'",
      "{ printf x; } {sink}>out >& \"${sink}\"",
  };
  for (size_t i = 0; i < sizeof(group_cases) / sizeof(group_cases[0]); i++) {
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    shell_process_status_t process_status = shell_process_commands(
        group_cases[i], strlen(group_cases[i]), NULL, &processed);
    shell_dep_error_t graph_status = shell_dep_graph_parse(
        group_cases[i], strlen(group_cases[i]), ".", NULL, &graph);
    bool valid =
        process_status == SHELL_PROCESS_OK && processed.command_count == 1 &&
        processed.group_count == 1 && processed.group_io_op_count >= 1 &&
        graph_status == SHELL_DEP_OK && shell_dep_graph_validate(&graph).valid;
    if (!valid) {
      fprintf(stderr,
              "group descriptor case failed: %s (process=%d commands=%zu "
              "groups=%zu io=%zu graph=%d nodes=%u edges=%u)\n",
              group_cases[i], process_status, processed.command_count,
              processed.group_count, processed.group_io_op_count, graph_status,
              graph.node_count, graph.edge_count);
    }
    CHECK(valid);
    shell_processed_commands_free(&processed);
  }

  /* A literal path prefix makes this legacy combined-output target
   * unambiguously pathname-valued. The processor keeps the group-owned
   * descriptor operations explicit; the graph later adds the producer ->
   * dynamic pathname relation. */
  static const char dynamic_group[] =
      "{ printf x; } >&path-$(printf /tmp/brace-group)";
  shell_processed_commands_t dynamic_processed = {0};
  shell_dep_graph_t dynamic_graph = {0};
  shell_process_status_t dynamic_process_status = shell_process_commands(
      dynamic_group, sizeof(dynamic_group) - 1, NULL, &dynamic_processed);
  shell_dep_error_t dynamic_graph_status = shell_dep_graph_parse(
      dynamic_group, sizeof(dynamic_group) - 1, ".", NULL, &dynamic_graph);
  bool dynamic_group_ok =
      dynamic_process_status == SHELL_PROCESS_OK &&
      dynamic_processed.group_count == 1 &&
      dynamic_processed.group_io_op_count == 2 &&
      dynamic_processed.group_io_ops[0].kind == SHELL_GROUP_IO_WRITE_FILE &&
      dynamic_processed.group_io_ops[0].fd == 1 &&
      dynamic_processed.group_io_ops[1].kind == SHELL_GROUP_IO_WRITE_FILE &&
      dynamic_processed.group_io_ops[1].fd == 2 &&
      dynamic_graph_status == SHELL_DEP_OK &&
      shell_dep_graph_validate(&dynamic_graph).valid;
  if (!dynamic_group_ok) {
    fprintf(stderr,
            "dynamic group descriptor case failed (process=%d commands=%zu "
            "groups=%zu io=%zu graph=%d nodes=%u edges=%u)\n",
            dynamic_process_status, dynamic_processed.command_count,
            dynamic_processed.group_count, dynamic_processed.group_io_op_count,
            dynamic_graph_status, dynamic_graph.node_count,
            dynamic_graph.edge_count);
  }
  CHECK(dynamic_group_ok);
  shell_processed_commands_free(&dynamic_processed);

  static const char *const rejected_groups[] = {
      "{ printf x; } >&2147483648",
      "{ printf x; } >&00000000000000000000000000000000002147483648",
      "{ printf x; } >&$'2147483648'",
      "{ printf x; } >&-file",
      "{ printf x; } >&",
  };
  for (size_t i = 0; i < sizeof(rejected_groups) / sizeof(rejected_groups[0]);
       i++) {
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    CHECK(shell_process_commands(rejected_groups[i], strlen(rejected_groups[i]),
                                 NULL, &processed) == SHELL_PROCESS_EPARSE &&
          processed.commands == NULL && processed.command_count == 0 &&
          processed.groups == NULL && processed.group_count == 0 &&
          shell_dep_graph_parse(rejected_groups[i], strlen(rejected_groups[i]),
                                ".", NULL, &graph) == SHELL_DEP_EPARSE &&
          graph.node_count == 0 && graph.edge_count == 0);
  }
}

/* Keep the shipping-library contract explicit at the boundary between the
 * small Bash extensions Shellsplit models and the extensions it deliberately
 * recognizes but does not flatten into an executable command sequence. */
static void test_modern_shell_syntax_boundaries(void) {
  static const char *const modeled[] = {
      "printf x |& cat",
      "! ! printf x |& cat",
      "! \\\nprintf x |& cat",
      "! \\\nprintf x |& cat",
      "printf x 2>/tmp/err |& cat",
      "printf x 3>/tmp/trace |& cat",
      "{ printf x; } |& { cat; }",
      "printf x |& cat | sort",
  };
  for (size_t i = 0; i < sizeof(modeled) / sizeof(modeled[0]); i++) {
    const char *input = modeled[i];
    shell_parse_result_t fast = {0};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    bool valid =
        shell_parse_fast(input, strlen(input), NULL, &fast) == SHELL_OK &&
        fast.count >= 2 &&
        shell_tokenize_commands(input, strlen(input), &commands,
                                &command_count) == SHELL_TOKENIZE_OK &&
        command_count >= 2 &&
        shell_process_commands(input, strlen(input), NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count >= 2 &&
        shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    uint32_t pipe_edges = 0;
    bool has_stderr_pipe = false;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      if (graph.edges[edge].type != SHELL_EDGE_PIPE)
        continue;
      pipe_edges++;
      has_stderr_pipe = has_stderr_pipe || graph.edges[edge].source_fd == 2;
    }
    CHECK(valid && pipe_edges >= 2 && has_stderr_pipe);
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
  }

  /* Bash applies the implicit `2>&1` in `|&` after explicit redirections.
   * Check the resolved public graph rather than the provisional parser edge:
   * redirected stderr is still piped, while a redirected stdout replaces both
   * output routes. */
  static const struct {
    const char *input;
    uint32_t pipes;
    uint32_t writes;
  } resolved_pipe_routes[] = {
      {"printf x 2>/tmp/err |& cat", 2, 0},
      {"printf x >/tmp/out |& cat", 0, 2},
      {"printf x 3>/tmp/trace |& cat", 2, 1},
  };
  for (size_t i = 0;
       i < sizeof(resolved_pipe_routes) / sizeof(resolved_pipe_routes[0]);
       i++) {
    shell_dep_graph_t graph = {0};
    uint32_t pipes = 0;
    uint32_t writes = 0;
    bool stderr_pipe = false;
    CHECK(shell_dep_graph_parse(resolved_pipe_routes[i].input,
                                strlen(resolved_pipe_routes[i].input), ".",
                                NULL, &graph) == SHELL_DEP_OK &&
          shell_dep_graph_validate(&graph).valid);
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      pipes += graph.edges[edge].type == SHELL_EDGE_PIPE;
      writes += graph.edges[edge].type == SHELL_EDGE_WRITE &&
                graph.nodes[graph.edges[edge].to].type != SHELL_NODE_FD;
      stderr_pipe = stderr_pipe || (graph.edges[edge].type == SHELL_EDGE_PIPE &&
                                    graph.edges[edge].source_fd == 2 &&
                                    graph.edges[edge].target_fd == 0);
    }
    CHECK(pipes == resolved_pipe_routes[i].pipes &&
          writes == resolved_pipe_routes[i].writes &&
          (pipes == 0 || stderr_pipe));
  }

  /* These spellings retain their literal shell meaning in one-shot command
   * execution; they do not introduce control flow or an unmodelled execution
   * edge, so all canonical surfaces preserve them. */
  static const char *const literal_extensions[] = {
      "printf $'x'",
      "printf $((1 + 2))",
      "printf @(left|right)",
      "printf prefix@(left|right)suffix",
      "printf x >out@(left|right)",
      "printf x &>out",
      "printf x &>>out",
      "printf x {fd}>out",
      "printf x {fd}>out >&\"$fd\"",
      "command time echo x",
      "\"time\" echo x",
      "echo time",
      "echo '$\"localized\"'",
      "echo $'$\"localized\"'",
      "echo \\$\"localized\"",
      "echo x # $\"localized\"",
      "cat <<'EOF'\n$\"localized\"\nEOF",
  };
  for (size_t i = 0;
       i < sizeof(literal_extensions) / sizeof(literal_extensions[0]); i++) {
    const char *input = literal_extensions[i];
    shell_processed_commands_t processed = {0};
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    shell_abstract_command_t *abstract = NULL;
    shell_dep_graph_t graph = {0};
    bool preserved =
        shell_process_commands(input, strlen(input), NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == 1 &&
        shell_transform_command_line(input, strlen(input), NULL, &transformed,
                                     &transformed_count) ==
            SHELL_TRANSFORM_OK &&
        transformed_count == 1 &&
        shell_abstract_command_parse(input, strlen(input), &abstract) ==
            SHELL_ABSTRACT_OK &&
        abstract != NULL &&
        shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    CHECK(preserved);
    shell_processed_commands_free(&processed);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
  }

  /* Braces and bracket text do not quote a list operator. An extglob redirect
   * operand does. An explicit stdout redirect also correctly replaces the
   * pipeline's data route rather than adding a false PIPE edge. */
  static const char *const structural_redirects[] = {
      "printf x >out{left|right}",
      "printf x >out[left|right]",
  };
  for (size_t i = 0;
       i < sizeof(structural_redirects) / sizeof(structural_redirects[0]);
       i++) {
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    uint32_t pipes = 0;
    CHECK(shell_process_commands(structural_redirects[i],
                                 strlen(structural_redirects[i]), NULL,
                                 &processed) == SHELL_PROCESS_OK &&
          processed.command_count == 2 &&
          shell_dep_graph_parse(structural_redirects[i],
                                strlen(structural_redirects[i]), ".", NULL,
                                &graph) == SHELL_DEP_OK &&
          shell_dep_graph_validate(&graph).valid);
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      pipes += graph.edges[edge].type == SHELL_EDGE_PIPE;
    CHECK(pipes == 0);
    shell_processed_commands_free(&processed);
  }

  const shell_process_limits_t short_string = {
      .max_string_bytes = 1,
      .max_total_bytes = SIZE_MAX,
  };
  const shell_process_limits_t short_total = {
      .max_string_bytes = SIZE_MAX,
      .max_total_bytes = 1,
  };
  shell_processed_commands_t limited = {0};
  CHECK(shell_process_commands("echo value", strlen("echo value"),
                               &short_string,
                               &limited) == SHELL_PROCESS_EOUTPUT_LIMIT &&
        limited.commands == NULL && limited.command_count == 0);
  CHECK(shell_process_commands("echo one; echo two",
                               strlen("echo one; echo two"), &short_total,
                               &limited) == SHELL_PROCESS_EOUTPUT_LIMIT &&
        limited.commands == NULL && limited.command_count == 0);

  static const char long_group_redirect[] =
      "{ echo ok; } >/tmp/shellsplit-structural-redirect-operand-that-is-not-"
      "returned-output";
  const shell_process_limits_t returned_only_limit = {
      .max_string_bytes = 32,
      .max_total_bytes = 32,
  };
  CHECK(shell_process_commands(
            long_group_redirect, sizeof(long_group_redirect) - 1,
            &returned_only_limit, &limited) == SHELL_PROCESS_OK &&
        limited.command_count == 1 && limited.commands != NULL &&
        strcmp(limited.commands[0].original_command, "echo ok") == 0);
  shell_processed_commands_free(&limited);

  shell_command_info_t *flat_limited = NULL;
  size_t flat_limited_count = 0;
  CHECK(shell_process_command(long_group_redirect,
                              sizeof(long_group_redirect) - 1,
                              &returned_only_limit, &flat_limited,
                              &flat_limited_count) == SHELL_PROCESS_OK &&
        flat_limited_count == 1 && flat_limited != NULL &&
        strcmp(flat_limited[0].original_command, "echo ok") == 0);
  shell_command_infos_free(flat_limited, flat_limited_count);

  /* A trailing group redirect is structural, but a later redirect-only list
   * member is an actual flat stage. Keep its empty argv record while applying
   * limits only to the two records the caller receives. */
  static const char group_then_redirect[] =
      "{ echo ok; } >/tmp/shellsplit-structural-redirect-operand-that-is-not-"
      "returned-output; >/tmp/independent";
  flat_limited = NULL;
  flat_limited_count = 0;
  CHECK(shell_process_command(group_then_redirect,
                              sizeof(group_then_redirect) - 1,
                              &returned_only_limit, &flat_limited,
                              &flat_limited_count) == SHELL_PROCESS_OK &&
        flat_limited_count == 2 && flat_limited != NULL &&
        strcmp(flat_limited[0].original_command, "echo ok") == 0 &&
        flat_limited[1].command_token_count == 0 &&
        strcmp(flat_limited[1].original_command, ">/tmp/independent") == 0);
  shell_command_infos_free(flat_limited, flat_limited_count);

  /* A redirect-only stage after the group is returned to flat callers, unlike
   * the group-owned redirect above, and therefore must consume flat limits. */
  static const char long_independent_redirect[] =
      "{ echo ok; } >/tmp/group-owned; >/tmp/shellsplit-returned-redirect-"
      "operand-that-exceeds-the-flat-record-limit";
  flat_limited = (shell_command_info_t *)(uintptr_t)1;
  flat_limited_count = SIZE_MAX;
  CHECK(shell_process_command(
            long_independent_redirect, sizeof(long_independent_redirect) - 1,
            &returned_only_limit, &flat_limited,
            &flat_limited_count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
        flat_limited == NULL && flat_limited_count == 0);

  const shell_process_limits_t aggregate_flat_limit = {
      .max_string_bytes = SIZE_MAX,
      .max_total_bytes = strlen("echo ok") + strlen(">/tmp/independent") - 1,
  };
  flat_limited = (shell_command_info_t *)(uintptr_t)1;
  flat_limited_count = SIZE_MAX;
  CHECK(shell_process_command(
            group_then_redirect, sizeof(group_then_redirect) - 1,
            &aggregate_flat_limit, &flat_limited,
            &flat_limited_count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
        flat_limited == NULL && flat_limited_count == 0);

  /* The flat compatibility result retains independent redirect-only stages
   * beside a group, but their source must be their exact fast-parser range.
   * In particular, no group close or group-owned tail redirect may leak into
   * either a preceding list member or an inner redirect-only stage. */
  static const char leading_redirect_before_group[] = ">first; { :; } >out";
  flat_limited = NULL;
  flat_limited_count = 0;
  CHECK(shell_process_command(leading_redirect_before_group,
                              sizeof(leading_redirect_before_group) - 1, NULL,
                              &flat_limited,
                              &flat_limited_count) == SHELL_PROCESS_OK &&
        flat_limited != NULL && flat_limited_count == 2 &&
        flat_limited[0].command_token_count == 0 &&
        flat_limited[0].has_redirections &&
        strcmp(flat_limited[0].original_command, ">first") == 0 &&
        strcmp(flat_limited[1].original_command, ":") == 0 &&
        flat_limited[1].has_redirections);
  shell_command_infos_free(flat_limited, flat_limited_count);

  static const char inner_redirect_before_group_close[] = "{ :; >inner; } >out";
  flat_limited = NULL;
  flat_limited_count = 0;
  CHECK(shell_process_command(inner_redirect_before_group_close,
                              sizeof(inner_redirect_before_group_close) - 1,
                              NULL, &flat_limited,
                              &flat_limited_count) == SHELL_PROCESS_OK &&
        flat_limited != NULL && flat_limited_count == 2 &&
        strcmp(flat_limited[0].original_command, ":") == 0 &&
        flat_limited[0].has_redirections &&
        flat_limited[1].command_token_count == 0 &&
        flat_limited[1].has_redirections &&
        strcmp(flat_limited[1].original_command, ">inner") == 0);
  shell_command_infos_free(flat_limited, flat_limited_count);

  const shell_process_limits_t exact_flat_redirect_limits = {
      .max_string_bytes = strlen(">first"),
      .max_total_bytes = strlen(":") + strlen(">first"),
  };
  flat_limited = NULL;
  flat_limited_count = 0;
  CHECK(shell_process_command(leading_redirect_before_group,
                              sizeof(leading_redirect_before_group) - 1,
                              &exact_flat_redirect_limits, &flat_limited,
                              &flat_limited_count) == SHELL_PROCESS_OK &&
        flat_limited != NULL && flat_limited_count == 2);
  shell_command_infos_free(flat_limited, flat_limited_count);

  shell_process_limits_t below_flat_redirect_limits =
      exact_flat_redirect_limits;
  below_flat_redirect_limits.max_string_bytes--;
  flat_limited = (shell_command_info_t *)(uintptr_t)1;
  flat_limited_count = SIZE_MAX;
  CHECK(shell_process_command(leading_redirect_before_group,
                              sizeof(leading_redirect_before_group) - 1,
                              &below_flat_redirect_limits, &flat_limited,
                              &flat_limited_count) ==
            SHELL_PROCESS_EOUTPUT_LIMIT &&
        flat_limited == NULL && flat_limited_count == 0);
  below_flat_redirect_limits = exact_flat_redirect_limits;
  below_flat_redirect_limits.max_total_bytes--;
  flat_limited = (shell_command_info_t *)(uintptr_t)1;
  flat_limited_count = SIZE_MAX;
  CHECK(shell_process_command(leading_redirect_before_group,
                              sizeof(leading_redirect_before_group) - 1,
                              &below_flat_redirect_limits, &flat_limited,
                              &flat_limited_count) ==
            SHELL_PROCESS_EOUTPUT_LIMIT &&
        flat_limited == NULL && flat_limited_count == 0);

  const shell_process_limits_t one_group_io_op = {
      .max_string_bytes = SIZE_MAX,
      .max_total_bytes = SIZE_MAX,
      .max_group_io_ops = 1,
  };
  CHECK(shell_process_commands(
            "{ echo ok; } >one >two", strlen("{ echo ok; } >one >two"),
            &one_group_io_op, &limited) == SHELL_PROCESS_EOUTPUT_LIMIT &&
        limited.commands == NULL && limited.command_count == 0);
  flat_limited = (shell_command_info_t *)(uintptr_t)1;
  flat_limited_count = SIZE_MAX;
  CHECK(shell_process_command(
            "{ echo ok; } >one >two", strlen("{ echo ok; } >one >two"),
            &one_group_io_op, &flat_limited,
            &flat_limited_count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
        flat_limited == NULL && flat_limited_count == 0);

  static const struct {
    const char *input;
    size_t executable_count;
  } valid_list_forms[] = {
      {"! printf x |& cat", 2},
      {"time -p printf x | cat", 2},
      {"time { echo ok; } | cat", 2},
      {"{ time { echo nested; }; echo outer; }", 2},
      {"time { time { echo nested; }; echo outer; }", 2},
      {"time { echo ok; } 2>/tmp/err | cat", 2},
      {"{ echo ok; } >/tmp/out", 1},
      {"cat <<EOF\nbody\nEOF\n", 1},
      {"cat < <(printf x)", 1},
      {"printf x &> >(cat)", 1},
      {"exec {fd}>out; printf x >&\"${fd}\"", 2},
      /* Prefixes commit a simple command, not reserved control syntax. */
      {"VALUE=x [[ $VALUE == x ]]", 1},
      {">out [[ x ]]", 1},
      {"VALUE=x then", 1},
      {">out then", 1},
  };
  /* The fast parser preserves structural group and heredoc ranges beside
   * executable commands. Processed and canonical outputs deliberately expose
   * only executable simple-command records, so they have the narrower count.
   */
  for (size_t i = 0; i < sizeof(valid_list_forms) / sizeof(valid_list_forms[0]);
       i++) {
    const char *input = valid_list_forms[i].input;
    size_t input_length = strlen(input);
    shell_parse_result_t parsed = {0};
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t sequence = {0};
    size_t sequence_count = 0;
    bool has_features = false;
    CHECK(shell_tokenizer_list_syntax_valid(input, input_length));
    CHECK(shell_process_validate_supported_source(input, input_length,
                                                  &parsed) == SHELL_PROCESS_OK);
    CHECK(parsed.count >= valid_list_forms[i].executable_count);
    CHECK(shell_process_commands(input, input_length, NULL, &processed) ==
          SHELL_PROCESS_OK);
    CHECK(processed.command_count == valid_list_forms[i].executable_count);
    shell_process_status_t sequence_status =
        shell_build_netargv_sequence_buffer(input, input_length, NULL,
                                            &sequence, &sequence_count,
                                            &has_features);
    if (sequence_status != SHELL_PROCESS_OK ||
        sequence_count != valid_list_forms[i].executable_count)
      fprintf(stderr, "list-form sequence mismatch: %s status=%d count=%zu\n",
              input, (int)sequence_status, sequence_count);
    CHECK(sequence_status == SHELL_PROCESS_OK);
    CHECK(sequence_count == valid_list_forms[i].executable_count);
    CHECK(shell_netstring_validate(sequence.data, sequence.length, NULL) ==
          SHELL_NETSTRING_OK);
    shell_netstring_buffer_free(&sequence);
    shell_processed_commands_free(&processed);
  }
  static const char *const invalid_list_forms[] = {
      ";;",
      ";&",
      ";;&",
      "echo one ;; echo two",
      "echo one ;& echo two",
      "echo one ;;& echo two",
      "echo ok |",
      "echo ok >\n",
      "echo ok { cat; }",
      "{ echo; } echo",
  };
  for (size_t i = 0;
       i < sizeof(invalid_list_forms) / sizeof(invalid_list_forms[0]); i++) {
    limited.commands = (shell_command_info_t *)(uintptr_t)1;
    limited.command_count = SIZE_MAX;
    CHECK(!shell_tokenizer_list_syntax_valid(invalid_list_forms[i],
                                             strlen(invalid_list_forms[i])) &&
          shell_process_validate_supported_source(
              invalid_list_forms[i], strlen(invalid_list_forms[i]), NULL) ==
              SHELL_PROCESS_EPARSE &&
          shell_process_commands(invalid_list_forms[i],
                                 strlen(invalid_list_forms[i]), NULL,
                                 &limited) == SHELL_PROCESS_EPARSE &&
          limited.commands == NULL && limited.command_count == 0);
  }

  static const char *const rejected[] = {
      "items=(one two)",
      "echo \"$( (time;) )\"",
      "echo \"$(time (time;))\"",
      "echo \"$( (time;); : )\"",
      "echo \"$({ (time;); })\"",
      "cat <( (time;) )",
      "printf x > >( (time;) )",
      "items[0]=one",
      "select item in one; do :; done",
      "coproc worker { echo ok; }",
      "case value in x) : ;& esac",
      "case value in x) : ;;& esac",
      SHELLSPLIT_TEST_UNMODELED_BINARY_CONDITION("/tmp/x"),
      "{ " SHELLSPLIT_TEST_UNMODELED_BINARY_CONDITION("value") "; }",
      "echo $( " SHELLSPLIT_TEST_UNMODELED_BINARY_CONDITION("/tmp/x") " )",
      "(( count += 1 ))",
      "! (( count ))",
      "{ (( count )); }",
      "time eval echo hidden",
      "time coproc echo hidden",
      "time " SHELLSPLIT_TEST_UNMODELED_BINARY_CONDITION("/tmp/x"),
      "time (( count += 1 ))",
      "time shopt -s varredir_close",
      "time command declare -a values",
      "echo \"$(time eval echo hidden)\"",
      "printf '%s' $\"localized\"",
      "printf '%s' prefix$\"localized\"suffix",
      "printf '%s' ${VALUE:-$\"fallback\"}",
      "echo \"${VALUE:-$\"localized\"}\"",
      "echo one; }",
      "echo one | )",
      "echo one { literal; }",
      "echo one (cat)",
      "echo one ((1))",
      "worker () { :; }",
      "worker ( ) { :; }",
      "worker\t(\t) ( : )",
      "worker\\\n() { :; }",
      "function worker () { :; }",
      "function worker ( ) ( : )",
      "declare -a values",
      "command -p -- declare -a values",
      "\"declare\" -a values",
      "d\\eclare -a values",
      "$'declare' -a values",
      "de$'clare' -a values",
      "command \"declare\" -a values",
      "command \"-p\" \"declare\" \"-a\" values",
      "command -$'p' de$'clare' -a values",
      "builtin d\\eclare -a values",
      "declare \"-a\" values",
      "declare \\-a values",
      "declare -$'a' values",
      "declare arr[0]",
      "declare 'arr[0]'",
      "declare arr\\[0\\]",
      "declare arr$'[0]'",
      "declare \"arr[0]=value\"",
      "readonly \"map[key]+=value\"",
      "typeset map[key]",
      "command -- declare \"arr[$(printf 0)]\"",
      "printf '%s' \"${values[0]}\"",
  };
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    const char *input = rejected[i];
    shell_parse_result_t fast = {0};
    shell_processed_commands_t processed = {0};
    shell_command_info_t *flat = NULL;
    size_t flat_count = 0;
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    shell_abstract_command_t *abstract = NULL;
    shell_dep_graph_t graph = {0};
    shell_error_t fast_status =
        shell_parse_fast(input, strlen(input), NULL, &fast);
    shell_process_status_t process_status =
        shell_process_commands(input, strlen(input), NULL, &processed);
    shell_process_status_t flat_status =
        shell_process_command(input, strlen(input), NULL, &flat, &flat_count);
    shell_transform_status_t transform_status = shell_transform_command_line(
        input, strlen(input), NULL, &transformed, &transformed_count);
    shell_abstract_status_t abstract_status =
        shell_abstract_command_parse(input, strlen(input), &abstract);
    shell_dep_error_t graph_status =
        shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph);
    bool rejected_everywhere =
        process_status == SHELL_PROCESS_EPARSE && processed.commands == NULL &&
        processed.command_count == 0 && flat_status == SHELL_PROCESS_EPARSE &&
        flat == NULL && flat_count == 0 &&
        transform_status == SHELL_TRANSFORM_EPARSE && transformed == NULL &&
        transformed_count == 0 && abstract_status == SHELL_ABSTRACT_EPARSE &&
        abstract == NULL && graph_status == SHELL_DEP_EPARSE &&
        graph.node_count == 0 && graph.edge_count == 0 &&
        (fast_status == SHELL_OK || fast_status == SHELL_EPARSE);
    if (!rejected_everywhere)
      fprintf(stderr,
              "modern rejection mismatch for %s: fast=%d process=%d flat=%d "
              "transform=%d abstract=%d graph=%d\n",
              input, (int)fast_status, (int)process_status, (int)flat_status,
              (int)transform_status, (int)abstract_status, (int)graph_status);
    CHECK(rejected_everywhere);
    shell_command_infos_free(flat, flat_count);
    shell_processed_commands_free(&processed);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
  }

  static const char *const neighboring_time_forms[] = {
      "time (time;)",
      "echo \"$(time { time; })\"",
      "echo \"$(time (time; :))\"",
      "echo \"$(time (time &))\"",
      "cat <( (time; :) )",
      "printf x > >( (time &) )",
  };
  for (size_t i = 0;
       i < sizeof(neighboring_time_forms) / sizeof(neighboring_time_forms[0]);
       i++) {
    const char *input = neighboring_time_forms[i];
    shell_processed_commands_t processed = {0};
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    shell_abstract_command_t *abstract = NULL;
    shell_dep_graph_t graph = {0};
    CHECK(shell_process_commands(input, strlen(input), NULL, &processed) ==
          SHELL_PROCESS_OK);
    CHECK(shell_transform_command_line(input, strlen(input), NULL, &transformed,
                                       &transformed_count) ==
          SHELL_TRANSFORM_OK);
    CHECK(shell_abstract_command_parse(input, strlen(input), &abstract) ==
          SHELL_ABSTRACT_OK);
    CHECK(shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
              SHELL_DEP_OK &&
          shell_dep_graph_validate(&graph).valid);
    shell_processed_commands_free(&processed);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
  }
}

/* The full tokenizer is deliberately more permissive than the canonical
 * semantic adapters: it must retain complete lexical structure so callers can
 * explain why a later adapter declines a construct. Exercise each structural
 * token family against the shipping library, including adjacency and compound
 * list placement that have historically been easy to regress. */
static void test_full_tokenizer_structural_matrix(void) {
  static const char *const accepted[] = {
      "cmd one\"two\" three\\ four",
      "cmd <in >out >>append 2>err 2>>err <>readwrite >|clobber",
      "cmd &>all &>>all <<<word",
      "cmd <(producer) >(consumer)",
      "cmd $'line\\n' @(left|right)",
      "items=(one two) map[key]=value",
      SHELLSPLIT_TEST_UNMODELED_BINARY_CONDITION("/tmp/x"),
      "(( 1 + 1 ))",
      "time -p echo x",
      "echo $\"localized\"",
      "worker () { :; }",
      "worker ( ) { :; }",
      "function worker () { :; }",
      "worker ( ) ( : )",
      "9worker () { :; }",
      "foo.bar () { :; }",
      "foo-bar () { :; }",
      "\"worker\" () { :; }",
      "{ cmd; } 2>err",
      "( cmd; ) >out",
      "! ! cmd |& next | final",
      "cmd && next || fallback; trailing &",
      "cmd > \\\noutput",
      "cmd <<EOF\nbody $value\nEOF\nnext",
  };
  for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
    shell_command_t *commands = NULL;
    size_t count = 0;
    CHECK(shell_tokenize_commands(accepted[i], strlen(accepted[i]), &commands,
                                  &count) == SHELL_TOKENIZE_OK &&
          commands != NULL && count > 0);
    shell_commands_free(commands, count);
  }

  static const char *const rejected[] = {
      "cmd |",         "cmd |&",       "cmd | ! next",  "cmd && && next",
      "{ ; }",         "()",           "worker (",      "worker ( x ) { :; }",
      "cmd >\noutput", "cmd > # note", "cmd <<<\nword",
  };
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
    size_t count = SIZE_MAX;
    CHECK(shell_tokenize_commands(rejected[i], strlen(rejected[i]), &commands,
                                  &count) == SHELL_TOKENIZE_EPARSE &&
          commands == NULL && count == 0);
  }
  const char invalid_byte[] = {'c', 'm', 'd', '\x01'};
  shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
  size_t count = SIZE_MAX;
  CHECK(shell_tokenize_commands(invalid_byte, sizeof(invalid_byte), &commands,
                                &count) == SHELL_TOKENIZE_EINPUT &&
        commands == NULL && count == 0);
}

static void test_transform_api(void) {
  static const char *const inputs[] = {
      "echo $HOME",
      "time ({ printf %s ./file; })",
      "time ({(printf %s $HOME)})",
      "printf '%s' *.c",
      "echo $(printf nested)",
      "echo $((1 + 2))",
      "cat <(printf source)",
      ("cat < /tmp/in > /tmp/out 2>> /tmp/err <> /tmp/read-write >| "
       "/tmp/clobber"),
      "echo one | cat && printf two; cat &",
  };
  for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
    shell_transformed_command_t **commands = NULL;
    size_t count = 0;
    CHECK(shell_transform_command_line(inputs[i], strlen(inputs[i]), NULL,
                                       &commands,
                                       &count) == SHELL_TRANSFORM_OK);
    CHECK(commands && count > 0);
    for (size_t j = 0; commands && j < count; j++) {
      CHECK(commands[j]->original_command && commands[j]->display_text &&
            commands[j]->token_count > 0);
    }
    shell_transformed_command_list_free(commands, count);
  }

  /* Adjacent source fragments remain one shell word.  Exercise the shipping
   * implementation directly so coverage cannot be satisfied only by the
   * allocator-instrumented target. */
  static const struct {
    const char *input;
    const char *display;
  } variable_word_cases[] = {
      {"printf prefix=${NAME}suffix end", "printf prefix=VAR_VALUEsuffix end"},
      {"printf prefix${ONE}--${TWO}/${THREE}",
       "printf prefixVAR_VALUE--VAR_VALUE/VAR_VALUE"},
      {"printf prefix$NAME-suffix\\$literal",
       "printf prefixVAR_VALUE-suffix\\$literal"},
      {"printf status-$?", "printf status-VAR_VALUE"},
      {"printf prefix=${NAME}suffix escaped=\\$NAME 'literal=$NAME'",
       "printf prefix=VAR_VALUEsuffix escaped=\\$NAME 'literal=$NAME'"},
      {"printf \"prefix-${NAME}\"\\$literal-${OTHER}",
       "printf \"prefix-VAR_VALUE\"\\$literal-VAR_VALUE"},
      {"printf \"prefix-${NAME}\" \"${OTHER}suffix\" \"${ONE}-${TWO}\"",
       "printf \"prefix-VAR_VALUE\" \"VAR_VALUEsuffix\" "
       "\"VAR_VALUE-VAR_VALUE\""},
      {"printf prefix'$literal'${NAME}", "printf prefix'$literal'VAR_VALUE"},
      {"printf prefix$'don\\'t $literal'${NAME}",
       "printf prefix$'don\\'t $literal'VAR_VALUE"},
  };
  for (size_t i = 0;
       i < sizeof(variable_word_cases) / sizeof(variable_word_cases[0]); i++) {
    shell_transformed_command_t **variable_commands = NULL;
    size_t variable_count = 0;
    CHECK(shell_transform_command_line(variable_word_cases[i].input,
                                       strlen(variable_word_cases[i].input),
                                       NULL, &variable_commands,
                                       &variable_count) == SHELL_TRANSFORM_OK &&
          variable_count == 1 && variable_commands != NULL &&
          variable_commands[0] != NULL &&
          strcmp(variable_commands[0]->display_text,
                 variable_word_cases[i].display) == 0 &&
          variable_commands[0]->has_transformations);
    shell_transformed_command_list_free(variable_commands, variable_count);
  }

  shell_transformed_command_t **commands = NULL;
  size_t count = 0;
  const shell_transform_limits_t string_limit = {1, SIZE_MAX};
  CHECK(shell_transform_command_line("echo value", strlen("echo value"),
                                     &string_limit, &commands,
                                     &count) == SHELL_TRANSFORM_EOUTPUT_LIMIT);
  const shell_transform_limits_t total_limit = {SIZE_MAX, 1};
  CHECK(shell_transform_command_line("echo value", strlen("echo value"),
                                     &total_limit, &commands,
                                     &count) == SHELL_TRANSFORM_EOUTPUT_LIMIT);

  CHECK(shell_transform_command_line("echo '", strlen("echo '"), NULL,
                                     &commands,
                                     &count) == SHELL_TRANSFORM_EPARSE);

  static const char compact_timing[] = "time ({(printf %s $HOME)})";
  CHECK(shell_transform_command_line(compact_timing, strlen(compact_timing),
                                     &string_limit, &commands,
                                     &count) == SHELL_TRANSFORM_EOUTPUT_LIMIT &&
        commands == NULL && count == 0);
  CHECK(shell_transform_command_line(compact_timing, strlen(compact_timing),
                                     &total_limit, &commands,
                                     &count) == SHELL_TRANSFORM_EOUTPUT_LIMIT &&
        commands == NULL && count == 0);

  shell_transformed_command_list_free(NULL, 0);
}

static void test_processor_modifier_feature_agreement(void) {
  static const struct {
    const char *source;
    bool feature;
  } cases[] = {
      {"time true", true},      {"time -p true", true},     {"! true", true},
      {"! ! true", true},       {"! time -- ! true", true}, {"true", false},
      {"\"time\" true", false}, {"timeword true", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_command_info_t *infos = NULL;
    size_t count = 0;
    shell_processed_commands_t structured = {0};
    CHECK(shell_process_command(cases[i].source, strlen(cases[i].source), NULL,
                                &infos, &count) == SHELL_PROCESS_OK &&
          count == 1 && infos != NULL);
    CHECK(shell_process_commands(cases[i].source, strlen(cases[i].source), NULL,
                                 &structured) == SHELL_PROCESS_OK &&
          structured.command_count == 1 && structured.commands != NULL);
    CHECK(shell_command_info_has_dangerous_features(&infos[0]) ==
              cases[i].feature &&
          shell_command_info_has_dangerous_features(&structured.commands[0]) ==
              cases[i].feature);
    shell_command_infos_free(infos, count);
    shell_processed_commands_free(&structured);
  }
}

static void test_pipeline_prefix_record_boundaries(void) {
  static const struct {
    const char *source;
    size_t count;
    shell_pipeline_time_mode_t modes[3];
    uint32_t negations[3];
    size_t words[3];
    const char *command_sequence;
  } cases[] = {
      {"echo a; time echo b",
       2,
       {0, SHELL_PIPE_TIME_DEFAULT},
       {0},
       {2, 2},
       "4:echo,4:echo,"},
      {"echo a && time -p echo b",
       2,
       {0, SHELL_PIPE_TIME_POSIX},
       {0},
       {2, 2},
       "4:echo,4:echo,"},
      {"echo a || time -- echo b",
       2,
       {0, SHELL_PIPE_TIME_POSIX},
       {0},
       {2, 2},
       "4:echo,4:echo,"},
      {"echo a & time echo b",
       2,
       {0, SHELL_PIPE_TIME_DEFAULT},
       {0},
       {2, 2},
       "4:echo,4:echo,"},
      {"echo a\ntime echo b",
       2,
       {0, SHELL_PIPE_TIME_DEFAULT},
       {0},
       {2, 2},
       "4:echo,4:echo,"},
      {"time echo a; time -p echo b",
       2,
       {SHELL_PIPE_TIME_DEFAULT, SHELL_PIPE_TIME_POSIX},
       {0},
       {2, 2},
       "4:echo,4:echo,"},
      {"echo a; ! echo b", 2, {0}, {0, 1}, {2, 2}, "4:echo,4:echo,"},
      {"echo a; ! time -p ! echo b",
       2,
       {0, SHELL_PIPE_TIME_POSIX},
       {0, 2},
       {2, 2},
       "4:echo,4:echo,"},
      {"echo a; time",
       2,
       {0, SHELL_PIPE_TIME_DEFAULT},
       {0},
       {2, 0},
       "4:echo,0:,"},
      {"echo a && time",
       2,
       {0, SHELL_PIPE_TIME_DEFAULT},
       {0},
       {2, 0},
       "4:echo,0:,"},
      {"echo a; time; echo b",
       3,
       {0, SHELL_PIPE_TIME_DEFAULT, 0},
       {0},
       {2, 0, 2},
       "4:echo,0:,4:echo,"},
      {"time; echo a; time -p",
       3,
       {SHELL_PIPE_TIME_DEFAULT, 0, SHELL_PIPE_TIME_POSIX},
       {0},
       {0, 2, 0},
       "0:,4:echo,0:,"},
      {"echo a; time { echo b; }",
       2,
       {0, SHELL_PIPE_TIME_DEFAULT},
       {0},
       {2, 2},
       "4:echo,4:echo,"},
      {"echo a; time (echo b)",
       2,
       {0, SHELL_PIPE_TIME_DEFAULT},
       {0},
       {2, 2},
       "4:echo,4:echo,"},
      {"echo a | time cat", 2, {0}, {0}, {2, 2}, "4:echo,4:time,"},
      {"time true | time",
       2,
       {SHELL_PIPE_TIME_DEFAULT, SHELL_PIPE_TIME_DEFAULT},
       {0},
       {1, 1},
       "4:true,4:time,"},
      {"time true | time -p",
       2,
       {SHELL_PIPE_TIME_DEFAULT, SHELL_PIPE_TIME_DEFAULT},
       {0},
       {1, 2},
       "4:true,4:time,"},
      {"time true | time --",
       2,
       {SHELL_PIPE_TIME_DEFAULT, SHELL_PIPE_TIME_DEFAULT},
       {0},
       {1, 2},
       "4:true,4:time,"},
      {"time true | time !",
       2,
       {SHELL_PIPE_TIME_DEFAULT, SHELL_PIPE_TIME_DEFAULT},
       {0},
       {1, 2},
       "4:true,4:time,"},
      {"time -p true | time",
       2,
       {SHELL_PIPE_TIME_POSIX, SHELL_PIPE_TIME_POSIX},
       {0},
       {1, 1},
       "4:true,4:time,"},
      {"time true |& time",
       2,
       {SHELL_PIPE_TIME_DEFAULT, SHELL_PIPE_TIME_DEFAULT},
       {0},
       {1, 1},
       "4:true,4:time,"},
      {"time true | time | cat",
       3,
       {SHELL_PIPE_TIME_DEFAULT, SHELL_PIPE_TIME_DEFAULT,
        SHELL_PIPE_TIME_DEFAULT},
       {0},
       {1, 1, 1},
       "4:true,4:time,3:cat,"},
      {"time true | \"time\"",
       2,
       {SHELL_PIPE_TIME_DEFAULT, SHELL_PIPE_TIME_DEFAULT},
       {0},
       {1, 1},
       "4:true,4:time,"},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    size_t length = strlen(source);
    shell_command_t *commands = NULL;
    size_t count = 0;
    CHECK(shell_tokenize_commands(source, length, &commands, &count) ==
              SHELL_TOKENIZE_OK &&
          count == cases[i].count);
    size_t executable_count = 0;
    for (size_t record = 0; record < count; record++) {
      const shell_command_t *command = &commands[record];
      CHECK(command->token_count != 0 && command->tokens != NULL &&
            command->start_pos <= command->end_pos &&
            command->end_pos <= length);
      CHECK(command->pipeline_time_mode == cases[i].modes[record] &&
            command->pipeline_negation_count == cases[i].negations[record] &&
            shell_processed_command_word_count(command) ==
                cases[i].words[record]);
      executable_count += cases[i].words[record] != 0;
      for (size_t token = 0; token < command->token_count; token++) {
        const shell_token_t *item = &command->tokens[token];
        CHECK(item->position >= command->start_pos &&
              item->position <= command->end_pos &&
              item->length <= command->end_pos - item->position);
      }
    }
    shell_commands_free(commands, count);

    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, length, NULL, &processed) ==
              SHELL_PROCESS_OK &&
          processed.command_count == executable_count);
    shell_processed_commands_free(&processed);

    shell_transformed_command_t **transformed = NULL;
    count = 0;
    CHECK(shell_transform_command_line(source, length, NULL, &transformed,
                                       &count) == SHELL_TRANSFORM_OK &&
          count == cases[i].count);
    shell_transformed_command_list_free(transformed, count);

    shell_netstring_buffer_t raw = {0}, typed = {0}, policy = {0};
    count = 0;
    CHECK(shell_build_anomaly_netseqs_buffer(source, length, NULL, &raw, &typed,
                                             &count) == SHELL_PROCESS_OK &&
          count == cases[i].count &&
          raw.length == strlen(cases[i].command_sequence) &&
          memcmp(raw.data, cases[i].command_sequence, raw.length) == 0);
    size_t typed_count = 0;
    CHECK(shell_netstring_validate(typed.data, typed.length, &typed_count) ==
              SHELL_NETSTRING_OK &&
          typed_count == cases[i].count);
    bool features = false;
    CHECK(shell_build_netargv_sequence_buffer(source, length, NULL, &policy,
                                              &count,
                                              &features) == SHELL_PROCESS_OK &&
          count == executable_count && features);
    shell_netstring_buffer_free(&raw);
    shell_netstring_buffer_free(&typed);
    shell_netstring_buffer_free(&policy);
  }
}

static void test_document_execution_stages(void) {
  static const struct {
    const char *source;
    const char *argv;
    unsigned commands;
    unsigned timed;
    unsigned documents;
  } cases[] = {
      {"time <<<body read -r value", "4:read,2:-r,5:value,", 1, 1, 1},
      {"time 0<<<body cat", "3:cat,", 1, 1, 1},
      {"time <input <<<body cat", "3:cat,", 1, 1, 2},
      {"time <<<one 3<<<two cat argument", "3:cat,8:argument,", 1, 1, 2},
      {"time <<EOF cat\nbody\nEOF\n", "3:cat,", 1, 1, 1},
      {"time 3<<EOF cat argument\nbody\nEOF\n", "3:cat,8:argument,", 1, 1, 1},
      {"time {fd}<<<body cat <&$fd", "3:cat,", 1, 1, 1},
      {"time <<<body cat &", "3:cat,", 1, 1, 1},
      {"! <<<body cat", "3:cat,", 1, 0, 1},
      {"true | time <<<body", "4:time,", 2, 0, 1},
      {"true | time -- <<EOF\nbody\nEOF\n", "4:time,2:--,", 2, 0, 1},
      {"time true | time -p <<<body", "4:time,2:-p,", 2, 2, 1},
      {"<<<body time true", "4:time,4:true,", 1, 0, 1},
      {"<<<body ! true", "1:!,4:true,", 1, 0, 1},
      {"<<<one 3<<<two time", "4:time,", 1, 0, 2},
      {"{fd}<<<body time", "4:time,", 1, 0, 1},
      {"true | <<<body time -p", "4:time,2:-p,", 2, 0, 1},
      {"time true | <<<body time -p", "4:time,2:-p,", 2, 2, 1},
      {"<<EOF time\nbody\nEOF\n", "4:time,", 1, 0, 1},
      {"true && <<<body time", "4:time,", 2, 0, 1},
      {"true | cat <<<body", "3:cat,", 2, 0, 1},
      {"true |& 3<<<body cat", "3:cat,", 2, 0, 1},
      {"true | {fd}<<<body cat <&$fd", "3:cat,", 2, 0, 1},
      {"true | cat <<<one argument 3<<<two", "3:cat,8:argument,", 2, 0, 2},
      {"true | cat <<EOF | cat\nbody\nEOF\n", "3:cat,", 3, 0, 1},
      {"{ time <<<body cat; }", "3:cat,", 1, 1, 1},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    size_t length = strlen(source);
    shell_processed_commands_t processed = {0};
    shell_process_status_t status =
        shell_process_commands(source, length, NULL, &processed);
    if (status != SHELL_PROCESS_OK ||
        processed.command_count != cases[i].commands)
      fprintf(stderr, "document stage: %s (status %d, commands %zu)\n", source,
              status, processed.command_count);
    CHECK(status == SHELL_PROCESS_OK &&
          processed.command_count == cases[i].commands);
    if (processed.command_count == cases[i].commands) {
      size_t target = cases[i].commands == 1 ? 0 : 1;
      shell_netstring_buffer_t argv = {0};
      CHECK(shell_render_netargv_buffer(&processed.commands[target], NULL,
                                        &argv) == SHELL_PROCESS_OK &&
            argv.length == strlen(cases[i].argv) &&
            memcmp(argv.data, cases[i].argv, argv.length) == 0);
      shell_netstring_buffer_free(&argv);
      unsigned timed = 0;
      for (size_t j = 0; j < processed.command_count; j++)
        timed +=
            processed.commands[j].pipeline_time_mode != SHELL_PIPE_TIME_NONE;
      CHECK(timed == cases[i].timed);
    }
    shell_processed_commands_free(&processed);

    shell_dep_graph_t graph = {0};
    shell_dep_error_t error =
        shell_dep_graph_parse(source, length, "/", NULL, &graph);
    if (error != SHELL_DEP_OK)
      fprintf(stderr, "document graph: %s (error %d)\n", source, error);
    CHECK(error == SHELL_DEP_OK);
    unsigned commands = 0, timed = 0, documents = 0;
    unsigned target = cases[i].commands == 1 ? 0 : 1;
    for (uint32_t j = 0; j < graph.node_count; j++) {
      if (graph.nodes[j].type == SHELL_NODE_CMD) {
        if (commands == target) {
          shell_netstring_iter_t iter;
          shell_netstring_view_t view;
          CHECK(shell_netstring_iter_init(&iter, cases[i].argv,
                                          strlen(cases[i].argv)) ==
                SHELL_NETSTRING_OK);
          unsigned token = 0;
          while (shell_netstring_iter_next(&iter, &view) ==
                 SHELL_NETSTRING_OK) {
            CHECK(token < graph.nodes[j].cmd.token_count);
            if (token < graph.nodes[j].cmd.token_count)
              CHECK(graph.nodes[j].cmd.token_lens[token] ==
                        view.payload_length &&
                    memcmp(graph.nodes[j].cmd.tokens[token], view.payload,
                           view.payload_length) == 0);
            token++;
          }
          CHECK(token == graph.nodes[j].cmd.token_count);
        }
        commands++;
      }
      documents += graph.nodes[j].type == SHELL_NODE_DOC;
      if (graph.nodes[j].type == SHELL_NODE_DOC &&
          graph.nodes[j].doc.kind != SHELL_DOC_FILE) {
        const shell_dep_doc_t *doc = &graph.nodes[j].doc;
        bool final_lf = doc->kind == SHELL_DOC_HEREDOC;
        CHECK(doc->value_len > 0);
        if (final_lf)
          CHECK(doc->value[doc->value_len - 1] == '\n');
        size_t length = doc->value_len - final_lf;
        CHECK((length == 4 && memcmp(doc->value, "body", 4) == 0) ||
              (length == 3 && (memcmp(doc->value, "one", 3) == 0 ||
                               memcmp(doc->value, "two", 3) == 0)));
      }
      if (graph.nodes[j].type == SHELL_NODE_CMD)
        timed += graph.nodes[j].cmd.pipeline_time_mode != SHELL_PIPE_TIME_NONE;
    }
    CHECK(commands == cases[i].commands && timed == cases[i].timed &&
          documents == cases[i].documents);
    CHECK(shell_dep_graph_validate(&graph).valid);
  }
}

static void test_document_prefix_boundaries(void) {
  static const struct {
    const char *source;
    const char *argv[2];
    shell_pipeline_time_mode_t modes[2];
    unsigned negations[2];
    unsigned timers;
    bool split_documents;
  } cases[] = {
      {"<<<one time <<<two cat", {"4:time,3:cat,"}, {0}, {0}, 0, false},
      {"<<<one ! <<<two cat", {"1:!,3:cat,"}, {0}, {0}, 0, false},
      {"<<<one time -p 3<<<two cat <&3",
       {"4:time,2:-p,3:cat,"},
       {0},
       {0},
       0,
       false},
      {"<<EOF time <<<two cat\none\nEOF\n",
       {"4:time,3:cat,"},
       {0},
       {0},
       0,
       false},
      {"<<<one time <<EOF cat\ntwo\nEOF\n",
       {"4:time,3:cat,"},
       {0},
       {0},
       0,
       false},
      {"true | <<<one time <<<two cat",
       {"4:true,", "4:time,3:cat,"},
       {0},
       {0},
       0,
       false},
      {"time true | <<<one time <<<two cat",
       {"4:true,", "4:time,3:cat,"},
       {SHELL_PIPE_TIME_DEFAULT, SHELL_PIPE_TIME_DEFAULT},
       {0},
       1,
       false},
      {"time <<<one time <<<two cat",
       {"4:time,3:cat,"},
       {SHELL_PIPE_TIME_DEFAULT},
       {0},
       1,
       false},
      {"<<<one time \\\n<<<two cat", {"4:time,3:cat,"}, {0}, {0}, 0, false},
      {"printf one <<<one\ntime <<<two cat",
       {"6:printf,3:one,", "3:cat,"},
       {SHELL_PIPE_TIME_NONE, SHELL_PIPE_TIME_DEFAULT},
       {0},
       1,
       true},
      {"printf one <<<one\n! <<<two cat",
       {"6:printf,3:one,", "3:cat,"},
       {0},
       {0, 1},
       0,
       true},
      {"printf one <<<one\r\ntime -p <<<two cat",
       {"6:printf,3:one,", "3:cat,"},
       {SHELL_PIPE_TIME_NONE, SHELL_PIPE_TIME_POSIX},
       {0},
       1,
       true},
      {"time { <<<one time <<<two cat; }",
       {"4:time,3:cat,"},
       {0},
       {0},
       1,
       false},
      {"{ printf one <<<one\ntime <<<two cat; }",
       {"6:printf,3:one,", "3:cat,"},
       {SHELL_PIPE_TIME_NONE, SHELL_PIPE_TIME_DEFAULT},
       {0},
       1,
       true},
      {"<<<one time {fd}<<<two cat <&$fd",
       {"4:time,3:cat,"},
       {0},
       {0},
       0,
       false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    size_t count = cases[i].argv[1] ? 2 : 1;
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t sequence = {0};
    size_t sequence_count = 0;
    bool features = false;
    CHECK(shell_process_commands(source, strlen(source), NULL, &processed) ==
          SHELL_PROCESS_OK);
    CHECK(shell_build_netargv_sequence_buffer(source, strlen(source), NULL,
                                              &sequence, &sequence_count,
                                              &features) == SHELL_PROCESS_OK);
    CHECK(processed.command_count == count && sequence_count == count &&
          features);
    shell_netstring_iter_t records;
    shell_netstring_view_t record;
    CHECK(shell_netstring_iter_init(&records, sequence.data, sequence.length) ==
          SHELL_NETSTRING_OK);
    for (size_t command = 0; command < count; command++) {
      size_t expected = strlen(cases[i].argv[command]);
      CHECK(shell_netstring_iter_next(&records, &record) ==
                SHELL_NETSTRING_OK &&
            record.payload_length == expected &&
            memcmp(record.payload, cases[i].argv[command], expected) == 0);
      if (command < processed.command_count) {
        shell_netstring_buffer_t argv = {0};
        CHECK(shell_render_netargv_buffer(&processed.commands[command], NULL,
                                          &argv) == SHELL_PROCESS_OK &&
              argv.length == expected &&
              memcmp(argv.data, cases[i].argv[command], expected) == 0);
        CHECK(processed.commands[command].pipeline_time_mode ==
                  cases[i].modes[command] &&
              processed.commands[command].pipeline_negation_count ==
                  cases[i].negations[command]);
        shell_netstring_buffer_free(&argv);
      }
    }
    CHECK(shell_netstring_iter_next(&records, &record) == SHELL_NETSTRING_DONE);
    shell_netstring_buffer_free(&sequence);
    shell_processed_commands_free(&processed);

    shell_dep_graph_t graph = {0};
    shell_dep_error_t error =
        shell_dep_graph_parse(source, strlen(source), "/", NULL, &graph);
    if (error != SHELL_DEP_OK)
      fprintf(stderr, "document prefix graph: %s (error %d)\n", source, error);
    CHECK(error == SHELL_DEP_OK && shell_dep_graph_validate(&graph).valid);
    unsigned commands = 0, timers = 0, documents = 0;
    uint32_t command_nodes[2] = {UINT32_MAX, UINT32_MAX};
    for (uint32_t node = 0; node < graph.node_count; node++) {
      timers += graph.nodes[node].type == SHELL_NODE_TIME;
      if (graph.nodes[node].type != SHELL_NODE_CMD)
        continue;
      CHECK(commands < count);
      if (commands < count) {
        command_nodes[commands] = node;
        const shell_dep_cmd_t *cmd = &graph.nodes[node].cmd;
        CHECK(cmd->pipeline_time_mode == cases[i].modes[commands] &&
              cmd->pipeline_negation_count == cases[i].negations[commands]);
        shell_netstring_iter_t words;
        shell_netstring_view_t word;
        shell_netstring_iter_init(&words, cases[i].argv[commands],
                                  strlen(cases[i].argv[commands]));
        unsigned token = 0;
        while (shell_netstring_iter_next(&words, &word) == SHELL_NETSTRING_OK) {
          CHECK(token < cmd->token_count);
          if (token < cmd->token_count)
            CHECK(cmd->token_lens[token] == word.payload_length &&
                  memcmp(cmd->tokens[token], word.payload,
                         word.payload_length) == 0);
          token++;
        }
        CHECK(token == cmd->token_count);
      }
      commands++;
    }
    CHECK(commands == count && timers == cases[i].timers);
    for (uint32_t node = 0; node < graph.node_count; node++) {
      if (graph.nodes[node].type != SHELL_NODE_DOC ||
          graph.nodes[node].doc.kind == SHELL_DOC_FILE)
        continue;
      documents++;
      const shell_dep_doc_t *doc = &graph.nodes[node].doc;
      char content[16];
      size_t content_length;
      CHECK(shell_dep_doc_write_content(doc, content, sizeof(content),
                                        &content_length));
      bool first = (content_length == 3 && !memcmp(content, "one", 3)) ||
                   (content_length == 4 && !memcmp(content, "one\r", 4)) ||
                   (content_length == 4 && !memcmp(content, "one\n", 4)) ||
                   (content_length == 5 && !memcmp(content, "one\r\n", 5));
      uint32_t owner =
          command_nodes[cases[i].split_documents && first ? 0 : count - 1];
      uint32_t read_fds = 0;
      for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
        if (graph.edges[edge].from == node &&
            (graph.edges[edge].type == SHELL_EDGE_READ ||
             graph.edges[edge].type == SHELL_EDGE_FD_OPEN)) {
          CHECK(graph.edges[edge].to == owner);
          if (graph.edges[edge].type == SHELL_EDGE_READ &&
              graph.edges[edge].target_fd < 32)
            read_fds |= UINT32_C(1) << graph.edges[edge].target_fd;
        }
      }
      CHECK((read_fds & UINT32_C(1)) ==
            (first && !cases[i].split_documents ? 0 : 1));
      if (!first && strstr(source, "3<<<two"))
        CHECK(read_fds & (UINT32_C(1) << 3));
    }
    CHECK(documents == 2);
  }
}

static void check_byte_validation_work(size_t passes, size_t bytes) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  if (shellsplit_test_metadata_work(
          SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_BYTES) != bytes)
    fprintf(stderr, "byte boundary: expected %zu bytes, visited %zu\n", bytes,
            shellsplit_test_metadata_work(
                SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_BYTES));
  CHECK(shellsplit_test_metadata_work(
            SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES) == passes);
  CHECK(shellsplit_test_metadata_work(
            SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_BYTES) == bytes);
#else
  (void)passes;
  (void)bytes;
#endif
}

static void reset_byte_validation_work(void) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  shellsplit_test_source_scan_reset();
#endif
}

static void test_single_byte_validation_boundary(void) {
  static const char *const sources[] = {
      "time true",
      "time { printf '%s' \"$(printf '%s' \"$(printf nested)\")\"; } | cat",
      "cat <<EOF\n${value:-$(printf body)}\nEOF\n",
      "# comment with 'unfinished $(syntax\nprintf done",
  };
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    const char *source = sources[i];
    size_t length = strlen(source);
    for (unsigned strict = 0; strict < 2; strict++) {
      shell_limits_t limits = SHELL_LIMITS_DEFAULT;
      limits.strict_mode = strict != 0;
      /* Reusing the same address in a later operation must validate afresh. */
      reset_byte_validation_work();
      for (unsigned repeat = 1; repeat <= 2; repeat++) {
        shell_parse_result_t parsed;
        CHECK(shell_parse_fast(source, length, &limits, &parsed) == SHELL_OK);
        CHECK(parsed.status == SHELL_STATUS_OK && parsed.count != 0);
        check_byte_validation_work(repeat, repeat * length);
      }
    }
    reset_byte_validation_work();
    CHECK(shell_tokenizer_complete_syntax_valid(source, length));
    check_byte_validation_work(1, length);
    reset_byte_validation_work();
    CHECK(shell_tokenizer_list_syntax_valid(source, length));
    check_byte_validation_work(1, length);
  }

  /* The root guarantee belongs only to contained immutable source spans.
   * An unrelated iterator within that operation still validates its bytes. */
  const char root[] = "printf \"$(printf nested)\"";
  const char unrelated[] = "printf unrelated";
  const char invalid[] = {'x', '\x01'};
  reset_byte_validation_work();
  shell_source_operation_begin(root, sizeof(root) - 1);
  CHECK(shell_tokenizer_complete_syntax_valid(root, sizeof(root) - 1));
  shell_tokenizer_state_t state;
  CHECK(shell_tokenizer_init(&state, root + 10, 13, NULL));
  check_byte_validation_work(1, sizeof(root) - 1);
  CHECK(shell_tokenizer_init(&state, unrelated, sizeof(unrelated) - 1, NULL));
  check_byte_validation_work(2, sizeof(root) + sizeof(unrelated) - 2);
  CHECK(!shell_tokenizer_init(&state, invalid, sizeof(invalid), NULL));
  check_byte_validation_work(3, sizeof(root) + sizeof(unrelated));
  shell_source_operation_end();

  /* Empty byte spans remain meaningful at the lexical boundary. */
  reset_byte_validation_work();
  CHECK(shell_tokenizer_init(&state, NULL, 0, NULL));
  check_byte_validation_work(1, 0);

  char source[16384];
  size_t length = 0;
  CHECK(shellsplit_test_source_with_tail(source, sizeof(source),
                                         SHELL_MAX_SUBCOMMANDS + 1,
                                         "printf tail", &length));
  for (unsigned strict = 0; strict < 2; strict++) {
    shell_limits_t limits = {.max_subcommands = 1, .strict_mode = strict != 0};
    shell_parse_result_t parsed;
    reset_byte_validation_work();
    CHECK(shell_parse_fast(source, length, &limits, &parsed) == SHELL_ETRUNC);
    CHECK(parsed.count == 1 && parsed.status == SHELL_STATUS_TRUNCATED);
    check_byte_validation_work(1, length);
  }

  /* Prohibited bytes inside opaque syntax or past the range capacity still
   * fail admission. Word literal/comment/heredoc high bytes remain admitted
   * data; the command capacity then determines the truncation outcome. */
  static const struct {
    const char *source;
    size_t position;
    bool literal_data;
  } tails[] = {
      {"printf tail", 8, true},
      {"# comment", 4, true},
      {"printf 'quoted'", 9, true},
      {"printf $(printf nested)", 17, true},
      {"cat <<'EOF'\nbody\nEOF\n", 13, true},
      {"printf $((1))", 10, false},
      {"printf $'ansi'", 10, true},
  };
  static const unsigned char bytes[] = {0, 1, 31, 127, 128, 255};
  for (size_t i = 0; i < sizeof(tails) / sizeof(tails[0]); i++) {
    CHECK(shellsplit_test_source_with_tail(source, sizeof(source),
                                           SHELL_MAX_SUBCOMMANDS + 1,
                                           tails[i].source, &length));
    size_t invalid_position =
        length - strlen(tails[i].source) + tails[i].position;
    char saved = source[invalid_position];
    for (size_t b = 0; b < sizeof(bytes) / sizeof(bytes[0]); b++) {
      source[invalid_position] = (char)bytes[b];
      for (unsigned strict = 0; strict < 2; strict++) {
        shell_limits_t limits = {.max_subcommands = 1,
                                 .strict_mode = strict != 0};
        shell_parse_result_t parsed;
        memset(&parsed, 0xff, sizeof(parsed));
        reset_byte_validation_work();
        bool literal_data = tails[i].literal_data && bytes[b] >= 128;
        CHECK(shell_parse_fast(source, length, &limits, &parsed) ==
              (literal_data ? SHELL_ETRUNC : SHELL_EPARSE));
        if (!literal_data)
          CHECK(!parsed.count && !parsed.group_count &&
                parsed.status == SHELL_STATUS_ERROR);
        /* NUL is inadmissible representation. Other byte restrictions scan
         * the complete span so a later NUL cannot become mere unsupported
         * input; this remains one linear boundary pass. */
        check_byte_validation_work(1, bytes[b] == 0 ? invalid_position + 1
                                                    : length);
      }
    }
    source[invalid_position] = saved;
  }
}

/* Exercise real public consumers, not just their validation helpers. Every
 * operation owns fresh empty outputs and frees them on success or failure. */
static shell_process_status_t exercise_source_operation(unsigned operation,
                                                        const char *source,
                                                        size_t length) {
  shell_process_status_t status;
  size_t count = 0;
  if (operation < 2) {
    shell_command_t *commands = NULL;
    shell_tokenize_status_t tokenized =
        operation == 0
            ? shell_tokenize_commands(source, length, &commands, &count)
            : shell_tokenize_supported_commands(source, length, true, true,
                                                &commands, &count);
    shell_commands_free(commands, count);
    return tokenized == SHELL_TOKENIZE_OK       ? SHELL_PROCESS_OK
           : tokenized == SHELL_TOKENIZE_EINPUT ? SHELL_PROCESS_EINPUT
                                                : SHELL_PROCESS_EPARSE;
  }
  if (operation == 2) {
    shell_processed_commands_t processed = {0};
    status = shell_process_commands(source, length, NULL, &processed);
    shell_processed_commands_free(&processed);
    return status;
  }
  if (operation == 3) {
    shell_command_info_t *infos = NULL;
    status = shell_process_command(source, length, NULL, &infos, &count);
    shell_command_infos_free(infos, count);
    return status;
  }
  if (operation == 8) {
    shell_abstract_command_t *abstracted = NULL;
    shell_abstract_status_t abstract_status =
        shell_abstract_command_parse(source, length, &abstracted);
    shell_abstract_command_free(abstracted);
    return abstract_status == SHELL_ABSTRACT_OK       ? SHELL_PROCESS_OK
           : abstract_status == SHELL_ABSTRACT_EINPUT ? SHELL_PROCESS_EINPUT
                                                      : SHELL_PROCESS_EPARSE;
  }
  shell_netstring_buffer_t first = {0}, second = {0};
  if (operation == 4) {
    bool features = false;
    status = shell_build_netargv_sequence_buffer(source, length, NULL, &first,
                                                 &count, &features);
  } else if (operation == 5) {
    status =
        shell_build_command_netseq_buffer(source, length, NULL, &first, &count);
  } else if (operation == 6) {
    status =
        shell_build_type_netseq_buffer(source, length, NULL, &first, &count);
  } else {
    status = shell_build_anomaly_netseqs_buffer(source, length, NULL, &first,
                                                &second, &count);
  }
  if (status != SHELL_PROCESS_OK) {
    CHECK(first.data == NULL && first.length == 0 && count == 0);
    CHECK(second.data == NULL && second.length == 0);
  }
  shell_netstring_buffer_free(&first);
  shell_netstring_buffer_free(&second);
  return status;
}

static void test_public_source_validation_boundary(void) {
  static const char *const sources[] = {
      "printf ordinary",
      "time { printf '%s' \"$(printf '%s' \"$(printf nested)\")\"; } | cat",
      "cat <<EOF\n${value:-$(printf body)}\nEOF\n",
      "printf \"`printf old`\" < <(printf input)",
  };
  for (size_t s = 0; s < sizeof(sources) / sizeof(sources[0]); s++) {
    size_t length = strlen(sources[s]);
    for (unsigned operation = 0; operation < 9; operation++) {
      reset_byte_validation_work();
      for (unsigned repeat = 1; repeat <= 2; repeat++) {
        CHECK(exercise_source_operation(operation, sources[s], length) ==
              SHELL_PROCESS_OK);
        check_byte_validation_work(repeat, repeat * length);
      }
    }
  }
  /* A failed operation must close its scratch lifetime as well: mutate the
   * same storage before a later successful call and require a fresh check. */
  char source[] = "printf valid";
  for (unsigned operation = 0; operation < 9; operation++) {
    source[8] = '\1';
    reset_byte_validation_work();
    CHECK(exercise_source_operation(operation, source, sizeof(source) - 1) ==
          SHELL_PROCESS_EINPUT);
    check_byte_validation_work(1, sizeof(source) - 1);
    source[8] = 'a';
    reset_byte_validation_work();
    CHECK(exercise_source_operation(operation, source, sizeof(source) - 1) ==
          SHELL_PROCESS_OK);
    check_byte_validation_work(1, sizeof(source) - 1);
  }
  static const char *const invalid_sources[] = {
      "printf $(printf $(printf 'unterminated))",
      "printf $(printf $(while true; do :; done))",
      "printf $(printf ok) >",
      "cat <<EOF\n$(printf $(select x; do :; done))\nEOF\n",
      "printf $(printf $(printf '\\0')) ; if true; then :; fi",
  };
  for (size_t s = 0; s < sizeof(invalid_sources) / sizeof(invalid_sources[0]);
       s++) {
    size_t length = strlen(invalid_sources[s]);
    for (unsigned operation = 2; operation < 9; operation++) {
      shell_process_status_t status =
          exercise_source_operation(operation, invalid_sources[s], length);
      /* The flat diagnostic API deliberately retains unfinished substitution
       * prefixes. Complete semantic/anomaly consumers must reject them. */
      shell_process_status_t expected =
          operation == 3 && s == 0 ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE;
      if (status != expected)
        fprintf(stderr, "invalid source op=%u source=%s status=%d\n", operation,
                invalid_sources[s], status);
      CHECK(status == expected);
      reset_byte_validation_work();
      CHECK(exercise_source_operation(operation, "printf later", 12) ==
            SHELL_PROCESS_OK);
      check_byte_validation_work(1, 12);
    }
  }
}

static void test_anomaly_heredoc_collection_limits(void) {
  char source[4096];
  static const char opener[] = "cat <<EOF\n$(";
  size_t length = sizeof(opener) - 1;
  memcpy(source, opener, length);
  for (size_t i = 0; i <= SHELL_MAX_SUBCOMMANDS; i++) {
    static const char stage[] = "printf value; ";
    memcpy(source + length, stage, sizeof(stage) - 1);
    length += sizeof(stage) - 1;
  }
  static const char closer[] = ")\nEOF\n";
  memcpy(source + length, closer, sizeof(closer) - 1);
  length += sizeof(closer) - 1;
  static const char group_limit[] =
      "cat <<EOF\n$( { printf ok; } >one 2>two )\nEOF\n";
  shell_process_limits_t limits = {SIZE_MAX, SIZE_MAX, 1};
  for (unsigned fixture = 0; fixture < 2; fixture++) {
    const char *input = fixture ? group_limit : source;
    size_t input_length = fixture ? sizeof(group_limit) - 1 : length;
    const shell_process_limits_t *selected_limits = fixture ? &limits : NULL;
    for (unsigned operation = 0; operation < 3; operation++) {
      shell_netstring_buffer_t first = {0}, second = {0};
      size_t count = 0;
      shell_process_status_t status;
      if (operation == 0)
        status = shell_build_command_netseq_buffer(
            input, input_length, selected_limits, &first, &count);
      else if (operation == 1)
        status = shell_build_type_netseq_buffer(
            input, input_length, selected_limits, &first, &count);
      else
        status = shell_build_anomaly_netseqs_buffer(
            input, input_length, selected_limits, &first, &second, &count);
      CHECK(status == SHELL_PROCESS_EOUTPUT_LIMIT);
      CHECK(first.data == NULL && first.length == 0 && count == 0);
      CHECK(second.data == NULL && second.length == 0);
      shell_netstring_buffer_free(&first);
      shell_netstring_buffer_free(&second);
      reset_byte_validation_work();
      CHECK(exercise_source_operation(5, "printf later", 12) ==
            SHELL_PROCESS_OK);
      check_byte_validation_work(1, 12);
    }
  }
}

/* Exercise both transport forms through the same semantic boundary. Buffers
 * start empty; C-string results are adopted here only for test comparison. */
static shell_process_status_t
build_limited_sequences(unsigned operation, bool cstring, const char *source,
                        const shell_process_limits_t *limits,
                        shell_netstring_buffer_t *first,
                        shell_netstring_buffer_t *second, size_t *count) {
  size_t length = strlen(source);
  bool features = false;
  if (!cstring) {
    switch (operation) {
    case 0:
      return shell_build_netargv_sequence_buffer(source, length, limits, first,
                                                 count, &features);
    case 1:
      return shell_build_command_netseq_buffer(source, length, limits, first,
                                               count);
    case 2:
      return shell_build_type_netseq_buffer(source, length, limits, first,
                                            count);
    default:
      return shell_build_anomaly_netseqs_buffer(source, length, limits, first,
                                                second, count);
    }
  }
  shell_netstring_buffer_t raw = {0};
  shell_netstring_buffer_t typed = {0};
  shell_process_status_t status;
  switch (operation) {
  case 0:
    status = shell_build_netargv_sequence_buffer(source, length, limits, &raw,
                                                 count, &features);
    break;
  case 1:
    status =
        shell_build_command_netseq_buffer(source, length, limits, &raw, count);
    break;
  case 2:
    status =
        shell_build_type_netseq_buffer(source, length, limits, &raw, count);
    break;
  default:
    status = shell_build_anomaly_netseqs_buffer(source, length, limits, &raw,
                                                &typed, count);
    break;
  }
  first->data = (unsigned char *)raw.data;
  first->length = raw.data ? raw.length : 0;
  second->data = (unsigned char *)typed.data;
  second->length = typed.data ? typed.length : 0;
  return status;
}

static void test_sequence_encoded_byte_limits(void) {
  static const struct {
    const char *source;
    bool has_netargv;
  } sources[] = {
      {"printf 012345678901234567890123456789", true},
      {"p''r''i''n''t''f value", true},
      {"printf value >'a long output path that is not returned'", true},
      {"printf value <<'EOF'\na long ignored heredoc body\nEOF\n", true},
      {"printf $(printf verylongargument) $(printf otherlongargument)", true},
      {"cat <<EOF\n$(printf verylongargument)\nEOF\n", true},
      {"{ printf value; } >'a long group output path that is not returned'",
       true},
      {">'a long redirect-only path that is not returned'", false},
      {"echo ok; >'a long redirect-only path that is not returned'", false},
      {"time >'a long redirect-only path that is not returned'", false},
  };
  for (size_t s = 0; s < sizeof(sources) / sizeof(sources[0]); s++) {
    for (unsigned operation = 0; operation < 4; operation++) {
      if (operation == 0 && !sources[s].has_netargv)
        continue;
      shell_netstring_buffer_t expected = {0}, expected_second = {0};
      size_t expected_count = 0;
      shell_process_status_t status =
          build_limited_sequences(operation, false, sources[s].source, NULL,
                                  &expected, &expected_second, &expected_count);
      CHECK(status == SHELL_PROCESS_OK);
      if (status != SHELL_PROCESS_OK)
        continue;
      if (s == 0 && operation == 1) {
        CHECK(expected.length == 9 && expected_count == 1);
        CHECK(expected.length == 9 &&
              memcmp(expected.data, "6:printf,", 9) == 0);
      }
      if (s == 0 && operation == 2)
        CHECK(expected.length == 19 && expected_count == 1);
      size_t exact = expected.length > expected_second.length
                         ? expected.length
                         : expected_second.length;
      for (unsigned transport = 0; transport < 2; transport++) {
        for (unsigned cap = 0; cap < 3; cap++) {
          shell_process_limits_t limits = {
              cap == 1 ? SIZE_MAX : exact,
              cap == 0 ? SIZE_MAX : exact,
              0,
          };
          shell_netstring_buffer_t first = {0}, second = {0};
          size_t count = SIZE_MAX;
          CHECK(build_limited_sequences(operation, transport != 0,
                                        sources[s].source, &limits, &first,
                                        &second, &count) == SHELL_PROCESS_OK);
          CHECK(count == expected_count && first.length == expected.length &&
                second.length == expected_second.length);
          CHECK(first.length == expected.length &&
                memcmp(first.data, expected.data, expected.length) == 0);
          if (expected_second.length != 0)
            CHECK(second.length == expected_second.length &&
                  memcmp(second.data, expected_second.data,
                         expected_second.length) == 0);
          shell_netstring_buffer_free(&first);
          shell_netstring_buffer_free(&second);
          if (cap != 1)
            limits.max_string_bytes--;
          if (cap != 0)
            limits.max_total_bytes--;
          count = SIZE_MAX;
          CHECK(build_limited_sequences(
                    operation, transport != 0, sources[s].source, &limits,
                    &first, &second, &count) == SHELL_PROCESS_EOUTPUT_LIMIT);
          CHECK(first.data == NULL && first.length == 0 &&
                second.data == NULL && second.length == 0 && count == 0);
          shell_netstring_buffer_free(&first);
          shell_netstring_buffer_free(&second);
        }
      }
      shell_netstring_buffer_free(&expected);
      shell_netstring_buffer_free(&expected_second);
    }
  }
}

static void test_anomaly_cumulative_group_budget(void) {
  static const struct {
    const char *source;
    size_t operations;
    size_t stages;
  } cases[] = {
      {"outer $( { inner; } >one ) $( { inner; } >two )", 2, 3},
      {"outer $( { middle $( { inner; } >two ); } >one )", 2, 3},
      {"outer ` { inner; } >one ` $( { inner; } >two )", 2, 3},
      {"cat <<EOF\n$( { inner; } >one ) $( { inner; } >two )\nEOF\n", 2, 3},
      {"outer <( { inner; } >one ) >( { inner; } >two )", 2, 3},
      {"{ outer $( { inner; } >two ); } >one", 2, 2},
      {"outer $( { inner; } &>one ) $( { inner; } >two )", 3, 3},
      {"outer $( { inner; } | { other; } ) $( { child; } >two )", 3, 4},
      {"outer $( { inner; } >one ) $( { other; } )", 1, 3},
      {"cat <<'EOF'\n$( { inner; } >one )\nEOF\n", 0, 1},
  };
  for (size_t s = 0; s < sizeof(cases) / sizeof(cases[0]); s++) {
    for (unsigned operation = 1; operation < 4; operation++) {
      for (unsigned transport = 0; transport < 2; transport++) {
        /* Zero remains the documented unbounded setting. A zero-operation
         * source must also fit a finite budget without charging literal data.
         */
        size_t budgets[] = {0, cases[s].operations ? cases[s].operations : 1,
                            cases[s].operations > 1 ? cases[s].operations - 1
                                                    : 1};
        for (size_t b = 0; b < sizeof(budgets) / sizeof(budgets[0]); b++) {
          shell_process_limits_t limits = {SIZE_MAX, SIZE_MAX, budgets[b]};
          shell_netstring_buffer_t first = {0}, second = {0};
          size_t count = SIZE_MAX;
          shell_process_status_t expected =
              budgets[b] != 0 && budgets[b] < cases[s].operations
                  ? SHELL_PROCESS_EOUTPUT_LIMIT
                  : SHELL_PROCESS_OK;
          shell_process_status_t status = build_limited_sequences(
              operation, transport != 0, cases[s].source, &limits, &first,
              &second, &count);
          if (status != expected)
            fprintf(stderr,
                    "group budget source=%s budget=%zu op=%u status=%d\n",
                    cases[s].source, budgets[b], operation, status);
          CHECK(status == expected);
          if (expected == SHELL_PROCESS_OK)
            CHECK(count == cases[s].stages);
          else
            CHECK(count == 0 && first.data == NULL && first.length == 0 &&
                  second.data == NULL && second.length == 0);
          shell_netstring_buffer_free(&first);
          shell_netstring_buffer_free(&second);
        }
      }
    }
  }
  /* Immediate-list producers do not collect substitution stages or their
   * metadata; do not silently change their budget scope with the anomaly API.
   */
  shell_process_limits_t limits = {SIZE_MAX, SIZE_MAX, 1};
  shell_netstring_buffer_t first = {0}, second = {0};
  size_t count = 0;
  CHECK(build_limited_sequences(0, false, cases[0].source, &limits, &first,
                                &second, &count) == SHELL_PROCESS_OK);
  CHECK(count == 1);
  shell_netstring_buffer_free(&first);
  shell_processed_commands_t processed = {0};
  CHECK(shell_process_commands(cases[0].source, strlen(cases[0].source),
                               &limits, &processed) == SHELL_PROCESS_OK);
  CHECK(processed.command_count == 1 && processed.group_io_op_count == 0);
  shell_processed_commands_free(&processed);
}

static void test_public_anomaly_traversal_work(void) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  char source[8192];
  const size_t leaf_length = 4096;
  for (unsigned operation = 5; operation < 8; operation++) {
    for (size_t depth = 0; depth <= 16; depth = depth ? depth * 2 : 1) {
      size_t length = 7;
      memcpy(source, "printf ", length);
      for (size_t i = 0; i < depth; i++) {
        memcpy(source + length, "$(printf ", 9);
        length += 9;
      }
      size_t leaf_start = length;
      memset(source + length, 'x', leaf_length);
      length += leaf_length;
      for (size_t i = 0; i < depth; i++)
        source[length++] = ')';
      reset_byte_validation_work();
      shellsplit_test_delimiter_watch(source + leaf_start, leaf_length);
      CHECK(exercise_source_operation(operation, source, length) ==
            SHELL_PROCESS_OK);
      check_byte_validation_work(1, length);
      CHECK(shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_SYNTAX_BODIES) ==
            depth + 1);
      CHECK(shellsplit_test_metadata_work(
                SHELLSPLIT_TEST_WORK_SEMANTIC_BODIES) == depth + 1);
      CHECK(shellsplit_test_metadata_work(
                SHELLSPLIT_TEST_WORK_ANOMALY_BODIES) == depth + 1);
      size_t work = shellsplit_test_source_scan_work();
      if (work > 128 * length + 1024)
        fprintf(stderr, "anomaly work op=%u depth=%zu bytes=%zu work=%zu\n",
                operation, depth, length, work);
      CHECK(work <= 128 * length + 1024);
      CHECK(shellsplit_test_delimiter_work() <= 8 * leaf_length);
    }
  }
  /* A wide inner list followed by siblings exercises scratch retirement and
   * verifies that a collector's scope does not leak into subsequent bodies. */
  for (size_t depth = 1; depth <= 8; depth *= 2) {
    size_t length = 7;
    memcpy(source, "outer  ", length);
    for (size_t i = 0; i < depth; i++) {
      memcpy(source + length, "$(middle ", 9);
      length += 9;
    }
    size_t leaf_start = length;
    for (size_t i = 0; i < leaf_length / 2; i++)
      memcpy(source + length + i * 2, "x ", 2);
    length += leaf_length;
    for (size_t i = 0; i < depth; i++)
      source[length++] = ')';
    static const char siblings[] = " $(left) $(right $(child))";
    memcpy(source + length, siblings, sizeof(siblings) - 1);
    length += sizeof(siblings) - 1;
    reset_byte_validation_work();
    shellsplit_test_delimiter_watch(source + leaf_start, leaf_length);
    CHECK(exercise_source_operation(5, source, length) == SHELL_PROCESS_OK);
    check_byte_validation_work(1, length);
    CHECK(shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_SYNTAX_BODIES) ==
          depth + 4);
    CHECK(shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_SEMANTIC_BODIES) ==
          depth + 4);
    CHECK(shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_ANOMALY_BODIES) ==
          depth + 4);
    CHECK(shellsplit_test_source_scan_work() <= 128 * length + 1024);
    CHECK(shellsplit_test_delimiter_work() <= 8 * leaf_length);

    shell_netstring_buffer_t sequence = {0};
    size_t count = 0;
    CHECK(shell_build_command_netseq_buffer(source, length, NULL, &sequence,
                                            &count) == SHELL_PROCESS_OK);
    char expected[256];
    size_t expected_length = 0;
    for (size_t i = 0; i < depth; i++) {
      memcpy(expected + expected_length, "6:middle,", 9);
      expected_length += 9;
    }
    static const char ending[] = "4:left,5:child,5:right,5:outer,";
    memcpy(expected + expected_length, ending, sizeof(ending) - 1);
    expected_length += sizeof(ending) - 1;
    CHECK(count == depth + 4 && sequence.length == expected_length);
    CHECK(sequence.length == expected_length &&
          memcmp(sequence.data, expected, expected_length) == 0);
    shell_netstring_buffer_free(&sequence);
  }
  /* A nonzero group-I/O limit needs fast metadata, but must not cause nested
   * bodies to recursively validate syntax again while constructing it. */
  for (size_t depth = 1; depth <= 8; depth *= 2) {
    size_t length = 7;
    memcpy(source, "outer  ", length);
    for (size_t i = 0; i < depth; i++) {
      static const char opener[] = "$( { middle ";
      memcpy(source + length, opener, sizeof(opener) - 1);
      length += sizeof(opener) - 1;
    }
    size_t leaf_start = length;
    memset(source + length, 'x', leaf_length);
    length += leaf_length;
    for (size_t i = 0; i < depth; i++) {
      static const char closer[] = "; } >out )";
      memcpy(source + length, closer, sizeof(closer) - 1);
      length += sizeof(closer) - 1;
    }
    shell_process_limits_t limits = {SIZE_MAX, SIZE_MAX, depth};
    shell_netstring_buffer_t first = {0}, second = {0};
    size_t count = 0;
    reset_byte_validation_work();
    shellsplit_test_delimiter_watch(source + leaf_start, leaf_length);
    CHECK(shell_build_anomaly_netseqs_buffer(source, length, &limits, &first,
                                             &second,
                                             &count) == SHELL_PROCESS_OK);
    CHECK(count == depth + 1);
    check_byte_validation_work(1, length);
    CHECK(shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_SYNTAX_BODIES) ==
          depth + 1);
    CHECK(shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_SEMANTIC_BODIES) ==
          depth + 1);
    CHECK(shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_ANOMALY_BODIES) ==
          depth + 1);
    CHECK(shellsplit_test_source_scan_work() <= 128 * length + 1024);
    CHECK(shellsplit_test_delimiter_work() <= 8 * leaf_length);
    shell_netstring_buffer_free(&first);
    shell_netstring_buffer_free(&second);
    if (depth > 1) {
      limits.max_group_io_ops--;
      count = SIZE_MAX;
      CHECK(shell_build_anomaly_netseqs_buffer(source, length, &limits, &first,
                                               &second, &count) ==
            SHELL_PROCESS_EOUTPUT_LIMIT);
      CHECK(first.data == NULL && first.length == 0 && second.data == NULL &&
            second.length == 0 && count == 0);
    }
  }
#endif
}

static void test_complete_source_before_capacity(void) {
  const shell_limits_t strict[] = {
      {.max_subcommands = SHELL_MAX_SUBCOMMANDS, .strict_mode = true},
      {.max_subcommands = 1, .strict_mode = true},
      {.max_subcommands = 0, .strict_mode = true},
  };
  const size_t prefixes[] = {0, SHELL_MAX_SUBCOMMANDS + 1};
  for (size_t p = 0; p < sizeof(prefixes) / sizeof(prefixes[0]); p++) {
    for (size_t i = 0; i < sizeof(shellsplit_test_malformed_tails) /
                               sizeof(shellsplit_test_malformed_tails[0]);
         i++) {
      char input[4096];
      size_t length = 0;
      CHECK(shellsplit_test_source_with_tail(input, sizeof(input), prefixes[p],
                                             shellsplit_test_malformed_tails[i],
                                             &length));
      CHECK(!shell_tokenizer_complete_syntax_valid(input, length));
      for (size_t l = 0; l < sizeof(strict) / sizeof(strict[0]); l++) {
        shell_parse_result_t fast;
        memset(&fast, 0xff, sizeof(fast));
        CHECK(shell_parse_fast(input, length, &strict[l], &fast) ==
              SHELL_EPARSE);
        CHECK(fast.count == 0 && fast.group_count == 0 &&
              fast.status == SHELL_STATUS_ERROR);
      }
      shell_processed_commands_t processed = {0};
      CHECK(shell_process_commands(input, length, NULL, &processed) ==
            SHELL_PROCESS_EPARSE);
      CHECK(!processed.commands && !processed.command_count &&
            !processed.groups && !processed.group_count &&
            !processed.group_io_ops && !processed.group_io_op_count);
      shell_processed_commands_free(&processed);
      shell_netstring_buffer_t sequence = {0};
      size_t count = SIZE_MAX;
      bool features = true;
      CHECK(shell_build_netargv_sequence_buffer(input, length, NULL, &sequence,
                                                &count, &features) ==
            SHELL_PROCESS_EPARSE);
      CHECK(!sequence.data && !count && !features);
      shell_netstring_buffer_free(&sequence);
      shell_transformed_command_t **transformed = NULL;
      size_t transformed_count = 0;
      CHECK(shell_transform_command_line(input, length, NULL, &transformed,
                                         &transformed_count) ==
            SHELL_TRANSFORM_EPARSE);
      CHECK(!transformed && !transformed_count);
      shell_transformed_command_list_free(transformed, transformed_count);
      shell_abstract_command_t *abstract = NULL;
      CHECK(shell_abstract_command_parse(input, length, &abstract) ==
            SHELL_ABSTRACT_EPARSE);
      CHECK(!abstract);
      shell_abstract_command_free(abstract);
      shell_dep_graph_t graph = {0};
      CHECK(shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
            SHELL_DEP_EPARSE);
      CHECK(graph.status == SHELL_DEP_STATUS_ERROR && !graph.node_count &&
            !graph.edge_count && !graph.cwd_buf.len);
    }
  }
  /* Valid capacity exhaustion remains distinct from malformed source. */
  char valid[4096];
  size_t length = 0;
  CHECK(shellsplit_test_source_with_tail(valid, sizeof(valid),
                                         SHELL_MAX_SUBCOMMANDS + 1,
                                         "echo $(printf done)", &length));
  shell_parse_result_t fast;
  CHECK(shell_parse_fast(valid, length, &strict[0], &fast) == SHELL_ETRUNC &&
        fast.count == SHELL_MAX_SUBCOMMANDS);
  /* A supplied permissive prefix is structural metadata, not a waiver for
   * complete-source semantic inspection. Reject translated syntax after the
   * retained prefix instead of publishing a partial graph. */
  static const char translated_after_prefix[] =
      "printf first; echo \"${0:+$'$(printf ch\\x69ld >&2)'}\"";
  const shell_limits_t one = {.max_subcommands = 1};
  shell_parse_result_t prefix = {0};
  CHECK(shell_parse_fast(translated_after_prefix,
                         sizeof(translated_after_prefix) - 1, &one,
                         &prefix) == SHELL_ETRUNC);
  CHECK(prefix.count == 1 && (prefix.status & SHELL_STATUS_TRUNCATED));
  shell_dep_graph_t rejected = {0};
  CHECK(shell_dep_graph_parse_with_fast(
            translated_after_prefix, sizeof(translated_after_prefix) - 1, ".",
            NULL, &prefix, &rejected) == SHELL_DEP_EPARSE);
  CHECK(rejected.status == SHELL_DEP_STATUS_ERROR && !rejected.node_count &&
        !rejected.edge_count && !rejected.cwd_buf.len);
  static const char *const complete[] = {
      "cat <<'EOF'\n$(unfinished ' ${\nEOF\n",
      "echo ${value:-$(printf done)}",
      "cat <<EOF\n${value:-$(printf done)}\nEOF\n",
      "if true; then echo done; fi",
  };
  for (size_t i = 0; i < sizeof(complete) / sizeof(complete[0]); i++)
    CHECK(shell_tokenizer_complete_syntax_valid(complete[i],
                                                strlen(complete[i])));
}

static void test_forward_word_scanners(void) {
  static const struct {
    const char *word;
    bool dynamic;
  } cases[] = {
      {"{{a,b}", true},        {"{a,{literal}}", true}, {"{{1..3}}", true},
      {"{1..3..}", false},     {"{1..3..-2}", true},    {"{a..Z..2}", true},
      {"{1..a}", false},       {"{-..2}", false},       {"{bar..baz}", false},
      {"{1..\"2\"}", false},   {"{1..\\2}", false},     {"{1..\\\n2}", true},
      {"{1..2..3..4}", false}, {"{{\"x\"}}", false},    {"{[unmatched}", false},
      {"[[:broken[ab]", true}, {"['a']", true},         {"['']", false},
      {"[\\]]", true},         {"\\[ab]", false},       {"\"[ab]\"", false},
      {"[[.x.]]", true},       {"[[=x=]]", true},       {"[]a]", true},
      {"[!ab]", true},         {"[^^]", true},          {"[[:broken", false},
      {"{literal$}", false},   {"{${value}}", true},    {"[$'a']", true},
      {"[$'']", false},        {"[$'\\x61']", true},    {"[$'\\0']", false},
      {"[$'\\n']", true},      {"$'[a]'", false},       {"[$'ab']", true},
      {"[$']']", true},        {"[$'[]']", true},       {"{[$'a']}", true},
      {"{[$'']}", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    bool actual = shell_source_word_has_dynamic_syntax(cases[i].word,
                                                       strlen(cases[i].word));
    if (actual != cases[i].dynamic)
      fprintf(stderr, "forward word mismatch: %s\n", cases[i].word);
    CHECK(actual == cases[i].dynamic);
  }
  static const struct {
    const char *word;
    shell_process_legacy_redirect_target_t expected;
  } redirects[] = {
      {"2", SHELL_PROCESS_LEGACY_REDIRECT_DUPLICATION},
      {"-", SHELL_PROCESS_LEGACY_REDIRECT_DUPLICATION},
      {"$destination", SHELL_PROCESS_LEGACY_REDIRECT_DUPLICATION},
      {"<(printf 1)", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {">(cat)", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"'literal'", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"\"literal\"", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"\"$(printf target)\"", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"literal\"$(printf target)\"", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"`printf target`", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"literal`printf target`", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"$((1 + 2))", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"literal$((1 + 2))", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"$", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"~", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"~/file", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"@(one|two)", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"literal@(one|two)", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"[ab]", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"literal[ab]", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{$value}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{${value}}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{$(printf 1)}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{`printf 1`}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{<(printf 1)}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{>(cat)}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{$((1+2))}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{@(one|two)}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{[ab]}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{*}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{{1,2}}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{{1,2}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{1..${value}}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{1,2}", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"{1..3}", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"{1..\\\n3}", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"{1,'2'}", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"{$'a\\0b'}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{$'unterminated}", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"{$(broken}", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"{\\", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"{\"broken}", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"{prefix\\$value}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{prefix$'literal'}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{[$'a']}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{[$'']}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{[$'\\0']}", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
      {"{`broken}", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"{$((broken}", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"{<(broken}", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"{>(broken}", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"{@(broken}", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
  };
  for (size_t i = 0; i < sizeof(redirects) / sizeof(redirects[0]); i++) {
    shell_process_legacy_redirect_target_t actual =
        shell_process_classify_legacy_output_target(redirects[i].word,
                                                    strlen(redirects[i].word));
    if (actual != redirects[i].expected)
      fprintf(stderr, "forward redirect mismatch: %s\n", redirects[i].word);
    CHECK(actual == redirects[i].expected);
  }

  /* Every family scales independently of delimiter count and literal depth.
   * The work counter includes candidate probes, not just top-level progress. */
  for (unsigned family = 0; family < 7; family++) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    size_t previous_work = 0;
#endif
    for (size_t count = 64; count <= 16384; count *= 2) {
      char *word = malloc(2 * count + 16);
      CHECK(word != NULL);
      if (!word)
        return;
      size_t length = 0;
      if (family != 2 && family != 3 && family != 6)
        word[length++] = 'x';
      char opener = family == 2 || family == 3 || family == 6 ? '[' : '{';
      memset(word + length, opener, count);
      length += count;
      const char *inner = family == 3   ? ":broken"
                          : family == 4 ? "a,b}"
                          : family == 5 ? "1..3"
                          : family == 6 ? "ab]"
                                        : "literal";
      memcpy(word + length, inner, strlen(inner));
      length += strlen(inner);
      if (family == 1 || family == 5) {
        memset(word + length, '}', count);
        length += count;
      }
      word[length] = '\0';
      bool dynamic = family >= 4;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      shellsplit_test_source_scan_reset();
#endif
      CHECK(shell_source_word_has_dynamic_syntax(word, length) == dynamic);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      CHECK(shellsplit_test_source_scan_work() <= 8 * length + 32);
      shellsplit_test_source_scan_reset();
#endif
      CHECK(shell_process_classify_legacy_output_target(word, length) ==
            (family == 6 ? SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED
                         : SHELL_PROCESS_LEGACY_REDIRECT_PATH));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      CHECK(shellsplit_test_source_scan_work() <= 16 * length + 64);
#endif

      /* Static long words remain ordinary arguments across semantic APIs.
       * No group-depth limit is appropriate for literal brace characters. */
      if (!dynamic) {
        char *source = malloc(length + 8);
        CHECK(source != NULL);
        if (!source) {
          free(word);
          return;
        }
        memcpy(source, "printf ", 7);
        memcpy(source + 7, word, length + 1);
        shell_processed_commands_t processed = {0};
        shell_dep_graph_t graph;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
        shellsplit_test_source_scan_reset();
#endif
        CHECK(shell_process_commands(source, length + 7, NULL, &processed) ==
                  SHELL_PROCESS_OK &&
              processed.command_count == 1);
        CHECK(shell_dep_graph_parse(source, length + 7, ".", NULL, &graph) ==
                  SHELL_DEP_OK &&
              shell_dep_graph_validate(&graph).valid);
        shell_netstring_buffer_t sequence = {0};
        size_t records = 0;
        bool features = false;
        CHECK(shell_build_netargv_sequence_buffer(
                  source, length + 7, NULL, &sequence, &records, &features) ==
                  SHELL_PROCESS_OK &&
              records == 1);
        if (sequence.data) {
          shell_netstring_iter_t outer, argv;
          shell_netstring_view_t record, arg;
          CHECK(shell_netstring_iter_init(&outer, sequence.data,
                                          sequence.length) ==
                    SHELL_NETSTRING_OK &&
                shell_netstring_iter_next(&outer, &record) ==
                    SHELL_NETSTRING_OK &&
                shell_netstring_iter_init(&argv, record.payload,
                                          record.payload_length) ==
                    SHELL_NETSTRING_OK &&
                shell_netstring_iter_next(&argv, &arg) == SHELL_NETSTRING_OK &&
                shell_netstring_iter_next(&argv, &arg) == SHELL_NETSTRING_OK &&
                arg.payload_length == length &&
                memcmp(arg.payload, word, length) == 0 &&
                shell_netstring_iter_next(&argv, &arg) == SHELL_NETSTRING_DONE);
        }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
        /* Three independent APIs perform multiple parsing/classification
         * passes. Bound their aggregate work and its growth when input doubles;
         * the standalone scanner bounds above remain much tighter. */
        size_t work = shellsplit_test_source_scan_work();
        /* Complete lexical and graph operation passes are now charged too.
         * The measured worst-case coefficient is 262 transitions per byte;
         * keep a bounded margin without relaxing the doubling-growth check. */
        CHECK(work <= 288 * (length + 7) + 4096);
        CHECK(previous_work == 0 || work <= 2 * previous_work + 4096);
        previous_work = work;
#endif
        shell_netstring_buffer_free(&sequence);
        shell_processed_commands_free(&processed);
        free(source);
      }
      free(word);
    }
  }
}

static void test_word_expansion_recognition(void) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  for (unsigned family = 0; family < 6; family++) {
    size_t previous = 0;
    for (size_t count = 32; count <= 4096; count *= 2) {
      char word[8208];
      size_t length = 0;
      if (family == 0) {
        memset(word, 'x', count);
        length = count;
        memcpy(word + length, "+=~", 3);
        length += 3;
      } else if (family < 3) {
        memcpy(word, "x=", 2);
        length = 2;
        for (size_t i = 0; i < count; i++) {
          word[length++] = family == 1 ? ':' : '\\';
          word[length++] = family == 1 ? 'x' : ':';
        }
        word[length++] = ':';
        word[length++] = '~';
      } else {
        memcpy(word, "~/", 2);
        length = 2;
        memset(word + length, 'x', count);
        length += count;
        const char *tail = family == 3 ? "" : family == 4 ? "$value" : "\"\"";
        memcpy(word + length, tail, strlen(tail));
        length += strlen(tail);
      }
      shellsplit_test_source_scan_reset();
      shell_source_word_expansion_t expansion =
          shell_source_word_expansion(word, length, SHELL_SOURCE_WORD_ARGUMENT);
      CHECK(expansion.dynamic == (family < 3 || family == 4));
      if (!expansion.dynamic)
        CHECK(expansion.leading_tilde);
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work <= 4 * length && (!previous || work <= 2 * previous + 16));
      previous = work;
    }
  }
#endif
  for (size_t i = 0; i < sizeof(shellsplit_test_tilde_cwd) /
                             sizeof(shellsplit_test_tilde_cwd[0]);
       i++) {
    shell_source_word_expansion_t expansion = shell_source_word_expansion(
        shellsplit_test_tilde_cwd[i].word,
        strlen(shellsplit_test_tilde_cwd[i].word), SHELL_SOURCE_WORD_ARGUMENT);
    CHECK(expansion.dynamic == shellsplit_test_tilde_cwd[i].other_dynamic);
    if (!expansion.dynamic)
      CHECK(expansion.leading_tilde ==
            shellsplit_test_tilde_cwd[i].leading_tilde);
  }
  for (size_t i = 0; i < sizeof(shellsplit_test_tilde_words) /
                             sizeof(shellsplit_test_tilde_words[0]);
       i++) {
    const char *word = shellsplit_test_tilde_words[i].word;
    size_t length = strlen(word), decoded;
    CHECK(shell_source_argument_has_dynamic_syntax(word, length) ==
          shellsplit_test_tilde_words[i].argument_dynamic);
    CHECK(shell_source_word_has_dynamic_syntax(word, length) ==
          shellsplit_test_tilde_words[i].generic_dynamic);
    CHECK(shell_visit_static_word(word, length, NULL, NULL, &decoded) ==
          !shellsplit_test_tilde_words[i].generic_dynamic);
    source_capture_t capture = {0};
    CHECK(shell_source_visit_static_argument(word, length, capture_source_byte,
                                             &capture) ==
          !shellsplit_test_tilde_words[i].argument_dynamic);
  }
  for (size_t i = 0;
       i < sizeof(shellsplit_test_substitution_status_cases) /
               sizeof(shellsplit_test_substitution_status_cases[0]);
       i++) {
    for (unsigned success = 0; success < 2; success++) {
      char source[512];
      int length = snprintf(source, sizeof(source), "%s %s echo >/etc/reached",
                            shellsplit_test_substitution_status_cases[i].source,
                            success ? "&&" : "||");
      CHECK(length > 0 && (size_t)length < sizeof(source));
      shell_dep_graph_t graph = {0};
      CHECK(shell_dep_graph_parse(source, (size_t)length, ".", NULL, &graph) ==
            SHELL_DEP_OK);
      CHECK(shell_dep_graph_validate(&graph).valid);
      bool reached = false;
      for (uint32_t e = 0; e < graph.edge_count; e++) {
        const shell_dep_edge_t *edge = &graph.edges[e];
        const shell_dep_node_t *target = &graph.nodes[edge->to];
        reached |=
            edge->type == SHELL_EDGE_WRITE && target->type == SHELL_NODE_DOC &&
            target->doc.kind == SHELL_DOC_FILE && target->doc.path_len == 12 &&
            memcmp(target->doc.path, "/etc/reached", 12) == 0;
      }
      CHECK(reached ==
            (success ? shellsplit_test_substitution_status_cases[i].succeeds
                     : shellsplit_test_substitution_status_cases[i].fails));
    }
  }
  for (size_t i = 0; i < sizeof(shellsplit_test_glob_words) /
                             sizeof(shellsplit_test_glob_words[0]);
       i++) {
    const char *word = shellsplit_test_glob_words[i].word;
    bool expected = shellsplit_test_glob_words[i].glob;
    size_t length = strlen(word);
    CHECK(shell_source_word_has_glob(word, length) == expected);
    CHECK((shell_classify_raw_token(word, length) == SHELL_TOKEN_GLOB) ==
          expected);
    char source[256];
    int source_length = snprintf(source, sizeof(source), "echo %s", word);
    CHECK(source_length > 0 && (size_t)source_length < sizeof(source));
    shell_command_t *commands = NULL;
    size_t count = 0;
    CHECK(shell_tokenize_commands(source, (size_t)source_length, &commands,
                                  &count) == SHELL_TOKENIZE_OK);
    if (count) {
      if (commands[0].has_globs != expected) {
        fprintf(stderr, "glob metadata mismatch: %s\n", source);
        for (size_t j = 0; j < commands[0].token_count; j++)
          fprintf(stderr, "  token %d: %.*s\n", commands[0].tokens[j].type,
                  (int)commands[0].tokens[j].length,
                  commands[0].tokens[j].start);
      }
      CHECK(count == 1 && commands[0].has_globs == expected);
    } else
      CHECK(count == 1);
    shell_commands_free(commands, count);
    shell_abstract_command_t *abstract = NULL;
    CHECK(shell_abstract_command_parse(source, (size_t)source_length,
                                       &abstract) == SHELL_ABSTRACT_OK);
    if (abstract)
      CHECK(abstract->has_globs == expected);
    shell_abstract_command_free(abstract);
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    CHECK(shell_transform_command_line(source, (size_t)source_length, NULL,
                                       &transformed, &transformed_count) ==
          SHELL_TRANSFORM_OK);
    bool transformed_glob = false;
    for (size_t command = 0; command < transformed_count; command++)
      for (size_t token = 0; token < transformed[command]->token_count; token++)
        transformed_glob |=
            transformed[command]->tokens[token].type == SHELL_TRANSFORM_GLOB;
    CHECK(transformed_count == 1 && transformed_glob == expected);
    shell_transformed_command_list_free(transformed, transformed_count);
  }
  for (size_t i = 0; i < sizeof(shellsplit_test_parameter_words) /
                             sizeof(shellsplit_test_parameter_words[0]);
       i++) {
    const char *word = shellsplit_test_parameter_words[i].word;
    const char *expected = shellsplit_test_parameter_words[i].name;
    const char *name = NULL;
    size_t name_length = 0;
    bool matched = shell_source_word_parameter_name(word, strlen(word), &name,
                                                    &name_length);
    CHECK(matched == (expected != NULL));
    if (matched && expected)
      CHECK(name_length == strlen(expected) &&
            memcmp(name, expected, name_length) == 0 && name > word &&
            name + name_length <= word + strlen(word));
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous = 0;
  for (size_t length = 128; length <= 8192; length *= 2) {
    char *word = malloc(length);
    CHECK(word != NULL);
    if (!word)
      return;
    memset(word, '[', length);
    shellsplit_test_source_scan_reset();
    CHECK(!shell_source_word_has_glob(word, length));
    size_t work = shellsplit_test_source_scan_work();
    CHECK(work <= 4 * length && (previous == 0 || work <= 2 * previous + 8));
    previous = work;
    free(word);
  }
#endif
}

static void test_nested_expansion_features(void) {
  for (size_t i = 0; i < sizeof(shellsplit_test_expansion_features) /
                             sizeof(shellsplit_test_expansion_features[0]);
       i++) {
    const shellsplit_test_feature_case_t *fixture =
        &shellsplit_test_expansion_features[i];
    shell_abstract_command_t *abstract = parse_abstract(fixture->source);
    bool valid = abstract && abstract->has_variables == fixture->variables &&
                 abstract->has_pos_vars == fixture->positional &&
                 abstract->has_special_vars == fixture->special &&
                 abstract->has_arithmetic == fixture->arithmetic &&
                 abstract->has_cmd_subst == fixture->substitution &&
                 abstract->has_globs == fixture->glob &&
                 strcmp(abstract->display_text, fixture->display) == 0;
    if (abstract)
      for (size_t j = 0; j < abstract->element_count; j++) {
        const shell_abstract_element_t *element = abstract->elements[j];
        valid &= element->end <= strlen(fixture->source) &&
                 element->start < element->end &&
                 (j == 0 || abstract->elements[j - 1]->end <= element->start) &&
                 strlen(element->original) == element->end - element->start &&
                 memcmp(element->original, fixture->source + element->start,
                        element->end - element->start) == 0;
      }
    if (!valid)
      fprintf(stderr, "expansion feature mismatch: %s display=%s\n",
              fixture->source,
              abstract ? abstract->display_text : "parse failed");
    CHECK(valid);
    shell_abstract_command_free(abstract);
  }

  static const struct {
    const char *source, *fragment, *content;
  } arithmetic[] = {
      {"printf $((1 + 2))", "$((1 + 2))", "1 + 2"},
      {"printf \"$VALUE$((1 + 2))\"", "$((1 + 2))", "1 + 2"},
      {"printf pre$((1 + $((2))))$VALUE", "$((1 + $((2))))", "1 + $((2))"},
      {"printf $\\\n(\\\n(1 + 2)\\\n)$VALUE", "$\\\n(\\\n(1 + 2)\\\n)",
       "1 + 2"},
      {"printf \"$VALUE$((1\\\n + 2)\\\n)\"", "$((1\\\n + 2)\\\n)",
       "1\\\n + 2"},
  };
  for (size_t i = 0; i < sizeof(arithmetic) / sizeof(arithmetic[0]); i++) {
    shell_abstract_command_t *abstract = parse_abstract(arithmetic[i].source);
    size_t found = 0;
    if (abstract)
      for (size_t j = 0; j < abstract->element_count; j++) {
        const shell_abstract_element_t *element = abstract->elements[j];
        if (element->type != SHELL_ABSTRACT_AR)
          continue;
        found++;
        CHECK(element->start == (size_t)(strstr(arithmetic[i].source,
                                                arithmetic[i].fragment) -
                                         arithmetic[i].source) &&
              element->end == element->start + strlen(arithmetic[i].fragment) &&
              strcmp(element->original, arithmetic[i].fragment) == 0 &&
              strcmp(element->data.cmd_subst.content, arithmetic[i].content) ==
                  0);
      }
    CHECK(abstract && abstract->has_arithmetic && found == 1);
    shell_abstract_command_free(abstract);
  }
}

static void test_quoted_arithmetic_boundaries(void) {
  for (size_t i = 0; i < sizeof(shellsplit_test_quoted_arithmetic) /
                             sizeof(shellsplit_test_quoted_arithmetic[0]);
       i++) {
    const char *source = shellsplit_test_quoted_arithmetic[i].source;
    bool supported = shellsplit_test_quoted_arithmetic[i].supported;
    size_t length = strlen(source);
    shell_parse_result_t parsed;
    CHECK(shell_parse_fast(source, length, NULL, &parsed) == SHELL_OK);
    CHECK(((parsed.cmds[0].features & SHELL_FEAT_ARITH) != 0) ==
          shellsplit_test_quoted_arithmetic[i].arithmetic);
    CHECK(shell_tokenizer_has_unsupported_semantics(source, length) ==
          !supported);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, length, NULL, &processed) ==
          (supported ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE));
    CHECK(supported ? processed.command_count == 1
                    : processed.command_count == 0 && !processed.commands);
    shell_processed_commands_free(&processed);
    shell_netstring_buffer_t raw = {0}, type = {0};
    size_t count = SIZE_MAX;
    CHECK(shell_build_anomaly_netseqs_buffer(source, length, NULL, &raw, &type,
                                             &count) ==
          (supported ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE));
    CHECK(supported ? count == 1
                    : count == 0 && raw.length == 0 && type.length == 0);
    shell_netstring_buffer_free(&raw);
    shell_netstring_buffer_free(&type);
    shell_dep_graph_t graph;
    CHECK(shell_dep_graph_parse(source, length, ".", NULL, &graph) ==
          (supported ? SHELL_DEP_OK : SHELL_DEP_EPARSE));
    CHECK(supported ? shell_dep_graph_validate(&graph).valid
                    : graph.node_count == 0 && graph.edge_count == 0);
    shell_abstract_command_t *abstract = NULL;
    CHECK(shell_abstract_command_parse(source, length, &abstract) ==
          (supported ? SHELL_ABSTRACT_OK : SHELL_ABSTRACT_EPARSE));
    CHECK(supported
              ? abstract && abstract->has_arithmetic ==
                                shellsplit_test_quoted_arithmetic[i].arithmetic
              : !abstract);
    shell_abstract_command_free(abstract);
    shell_transformed_command_t **transformed = NULL;
    count = SIZE_MAX;
    CHECK(shell_transform_command_line(source, length, NULL, &transformed,
                                       &count) ==
          (supported ? SHELL_TRANSFORM_OK : SHELL_TRANSFORM_EPARSE));
    CHECK(supported ? count == 1 : count == 0 && !transformed);
    shell_transformed_command_list_free(transformed, count);
  }
}

static void test_forward_nested_substitutions(void) {
  /* Both nesting depth and leaf suffix length must scale linearly. Real
   * recursive balancing transitions are charged, not a nominal word length. */
  char word[2048];
  char source[sizeof(word) + 7] = "printf ";
  shell_limits_t limits = SHELL_LIMITS_DEFAULT;
  /* Deep array-reference families exceed the default private scratch. Reuse
   * a sufficient public capacity across cases in both library variants. */
  CHECK(shell_source_workspace_size(sizeof(source), &limits.workspace_size));
  limits.workspace = malloc(limits.workspace_size);
  CHECK(limits.workspace != NULL);
  for (unsigned family = 0; family < 4; family++) {
    for (size_t leaf = 64; leaf <= 1024; leaf *= 2) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      size_t previous = 0;
      size_t previous_fast = 0, previous_length = 0;
#endif
      for (size_t depth = 4; depth <= 32; depth *= 2) {
        const char *opener = family == 1   ? "$((1 + "
                             : family == 3 ? "${a["
                                           : "${x:-";
        const char *closer = family == 1 ? "))" : family == 3 ? "]}" : "}";
        size_t length = 0;
        for (size_t i = 0; i < depth; i++) {
          const char *prefix = family == 2 && i % 2 ? "$((1 + " : opener;
          memcpy(word + length, prefix, strlen(prefix));
          length += strlen(prefix);
        }
        memcpy(word + length, "$(printf x)", 11);
        size_t start = length;
        length += 11;
        memset(word + length, ' ', leaf);
        length += leaf;
        for (size_t i = depth; i > 0; i--) {
          const char *suffix = family == 2 && (i - 1) % 2 ? "))" : closer;
          memcpy(word + length, suffix, strlen(suffix));
          length += strlen(suffix);
        }
        word[length] = '\0';
        shell_source_substitution_scan_t scan = {0};
        size_t actual_start = 0, after = 0;
        shell_source_substitution_kind_t kind = SHELL_SOURCE_SUBST_COMMAND;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
        shellsplit_test_source_scan_reset();
#endif
        CHECK(shell_source_next_executable_substitution(
                  word, length, &scan, &actual_start, &after, &kind) ==
                  SHELL_SOURCE_SCAN_FOUND &&
              actual_start == start && after == start + 11 &&
              kind == SHELL_SOURCE_SUBST_COMMAND &&
              shell_source_next_executable_substitution(
                  word, length, &scan, &actual_start, &after, &kind) ==
                  SHELL_SOURCE_SCAN_DONE &&
              scan.position == length && scan.scope_count == 0 &&
              scan.has_variables == (family != 1) &&
              scan.has_arithmetic == (family == 1 || family == 2) &&
              scan.has_arrays == (family == 3));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
        size_t work = shellsplit_test_source_scan_work();
        CHECK(work <= 8 * length + 128 &&
              (previous == 0 || work <= 2 * previous + 128));
        previous = work;
#endif
        memcpy(source + 7, word, length);
        shell_parse_result_t parsed;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
        shellsplit_test_source_scan_reset();
#endif
        shell_error_t error =
            shell_parse_fast(source, length + 7, &limits, &parsed);
        if (error != SHELL_OK)
          fprintf(stderr,
                  "nested scan parse family=%u leaf=%zu depth=%zu error=%d\n",
                  family, leaf, depth, error);
        CHECK(error == SHELL_OK);
        CHECK(parsed.count == 1 &&
              !!(parsed.cmds[0].features & SHELL_FEAT_ARRAY) == (family == 3));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
        size_t fast_work = shellsplit_test_source_scan_work();
        bool linear = fast_work <= 48 * (length + 7) + 1024 &&
                      (!previous_fast ||
                       fast_work <= previous_fast +
                                        48 * (length - previous_length) + 2048);
        if (!linear)
          fprintf(stderr,
                  "nested scan budget family=%u leaf=%zu depth=%zu "
                  "bytes=%zu work=%zu previous=%zu\n",
                  family, leaf, depth, length, fast_work, previous_fast);
        CHECK(linear);
        previous_fast = fast_work;
        previous_length = length;
#endif
      }
    }
  }
  free(limits.workspace);
  static const char *const malformed[] = {
      "${x:-$(printf x)",
      "$((1 + $(printf x))",
      "${x:-$((1 + $(printf x))}",
      "${x:-'$(printf x)}",
      "${%word}",
      "${x:-prefix$'\\x24'}",
  };
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
    shell_source_substitution_scan_t scan = {0};
    size_t start, after;
    shell_source_substitution_kind_t kind;
    shell_source_scan_status_t status;
    do {
      status = shell_source_next_executable_substitution(
          malformed[i], strlen(malformed[i]), &scan, &start, &after, &kind);
    } while (status == SHELL_SOURCE_SCAN_FOUND);
    CHECK(status == SHELL_SOURCE_SCAN_MALFORMED ||
          status == SHELL_SOURCE_SCAN_INCOMPLETE);
  }
  char too_deep[512];
  size_t length = 0;
  for (size_t i = 0; i <= SHELL_MAX_SUBCOMMANDS; i++) {
    memcpy(too_deep + length, "${x:-", 5);
    length += 5;
  }
  memset(too_deep + length, '}', SHELL_MAX_SUBCOMMANDS + 1);
  length += SHELL_MAX_SUBCOMMANDS + 1;
  shell_source_substitution_scan_t scan = {0};
  size_t start, after;
  shell_source_substitution_kind_t kind;
  CHECK(shell_source_next_executable_substitution(too_deep, length, &scan,
                                                  &start, &after, &kind) ==
        SHELL_SOURCE_SCAN_MALFORMED);
}

static void test_forward_arithmetic_validation(void) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  for (size_t leaf = 64; leaf <= 1024; leaf *= 2) {
    size_t previous_work = 0, previous_length = 0;
    for (size_t depth = 4; depth <= 32; depth *= 2) {
      char source[2048] = "printf ";
      size_t length = 7;
      for (size_t i = 0; i < depth; i++) {
        memcpy(source + length, "$((1 + ", 7);
        length += 7;
      }
      memset(source + length, ' ', leaf);
      length += leaf;
      source[length++] = '1';
      for (size_t i = 0; i < depth; i++) {
        memcpy(source + length, "))", 2);
        length += 2;
      }
      shellsplit_test_source_scan_reset();
      CHECK(!shell_tokenizer_has_unsupported_semantics(source, length));
      size_t work = shellsplit_test_source_scan_work();
      bool linear =
          work <= 64 * length + 1024 &&
          (!previous_work ||
           work <= previous_work + 64 * (length - previous_length) + 2048);
      if (!linear)
        fprintf(stderr,
                "arithmetic validation budget leaf=%zu depth=%zu "
                "work=%zu previous=%zu\n",
                leaf, depth, work, previous_work);
      CHECK(linear);
      previous_work = work;
      previous_length = length;
    }
  }
#endif
}

static void test_fragment_content_boundaries(void) {
  for (size_t i = 0; i < sizeof(shellsplit_test_fragment_words) /
                             sizeof(shellsplit_test_fragment_words[0]);
       i++) {
    const char *source = shellsplit_test_fragment_words[i].source;
    const char *fragment = shellsplit_test_fragment_words[i].fragment;
    const char *content = shellsplit_test_fragment_words[i].content;
    bool string_fragment = shellsplit_test_fragment_words[i].string_fragment;
    bool variable = shellsplit_test_fragment_words[i].has_variable;
    shell_abstract_command_t *abstract = NULL;
    CHECK(shell_abstract_command_parse(source, strlen(source), &abstract) ==
          SHELL_ABSTRACT_OK);
    if (!abstract)
      continue;
    bool valid = abstract->element_count == (variable ? 2u : 1u) &&
                 abstract->has_strings == string_fragment &&
                 abstract->has_cmd_subst == !string_fragment &&
                 abstract->has_variables == variable;
    if (valid) {
      const shell_abstract_element_t *element = abstract->elements[0];
      size_t start = (size_t)(strstr(source, fragment) - source);
      valid = element->type ==
                  (string_fragment ? SHELL_ABSTRACT_STR : SHELL_ABSTRACT_CS) &&
              element->start == start &&
              element->end == start + strlen(fragment) &&
              strcmp(element->original, fragment) == 0 &&
              element->data.cmd_subst.content &&
              strcmp(element->data.cmd_subst.content, content) == 0;
      const char *suffix = source + start + strlen(fragment);
      char expected_display[256];
      int written = snprintf(
          expected_display, sizeof(expected_display), "%.*s%s%s%s", (int)start,
          source, string_fragment ? "$STR_1" : "$CS_1", variable ? "$EV_1" : "",
          variable ? suffix + strlen("$VALUE") : suffix);
      valid = valid && written > 0 &&
              (size_t)written < sizeof(expected_display) &&
              strcmp(abstract->display_text, expected_display) == 0;
      if (valid && variable)
        valid = abstract->elements[1]->type == SHELL_ABSTRACT_EV &&
                strcmp(abstract->elements[1]->original, "$VALUE") == 0 &&
                abstract->elements[1]->start ==
                    (size_t)(strstr(source, "$VALUE") - source);
    }
    if (!valid)
      fprintf(stderr, "fragment content mismatch: %s\n", source);
    CHECK(valid);
    shell_abstract_command_free(abstract);
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  /* Both standalone and compound paths must visit a growing opener prefix
   * only a constant number of times. Instrumentation includes content slicing.
   */
  for (unsigned form = 0; form < 3; form++) {
    size_t previous = 0;
    for (size_t count = 32; count <= 1024; count *= 2) {
      char source[4096];
      const char *prefix = form == 0   ? "echo $"
                           : form == 1 ? "echo pre$"
                                       : "echo \"pre$";
      const char *suffix = form == 2 ? "(id)$VALUE\"" : "'abc'";
      size_t used = strlen(prefix);
      memcpy(source, prefix, used);
      for (size_t j = 0; j < count; j++) {
        source[used++] = '\\';
        source[used++] = '\n';
      }
      memcpy(source + used, suffix, strlen(suffix) + 1);
      used += strlen(suffix);
      shellsplit_test_source_scan_reset();
      shell_abstract_command_t *abstract = NULL;
      CHECK(shell_abstract_command_parse(source, used, &abstract) ==
            SHELL_ABSTRACT_OK);
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work >= count * 2 && work <= 256 * used &&
            (!previous || work <= 2 * previous + 1024));
      if (abstract)
        CHECK(abstract->elements[0]->data.cmd_subst.content &&
              strcmp(abstract->elements[0]->data.cmd_subst.content,
                     form == 2 ? "id" : "abc") == 0);
      shell_abstract_command_free(abstract);
      previous = work;
    }
  }
#endif
}

static void test_backtick_escape_scan_contract(void) {
  static const struct {
    const char *source;
    bool quoted, complete, sensitive;
  } cases[] = {
      {"`printf child`tail", false, true, false},
      {"`printf \\$value`", false, true, true},
      {"`printf \\`child\\``", false, true, true},
      {"`printf \\\\literal`", false, true, true},
      {"`printf \\\"literal\\\"`", false, true, false},
      {"`printf \\\"literal\\\"`", true, true, true},
      {"`printf '\\q'`", true, true, false},
      {"`printf a\\ b`", false, true, false},
      {"`printf fo\\\no`", false, true, true},
      {"`printf 'a\\\nb'`", false, true, true},
      {"`printf \\$value", false, false, false},
      {"`printf \\`", false, false, false},
      {"`printf \\", false, false, false},
      {"", false, false, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    size_t length = strlen(cases[i].source);
    size_t after = SIZE_MAX, lexical_after = SIZE_MAX;
    bool sensitive = false;
    bool complete = shell_source_scan_backtick(
        cases[i].source, length, 0, cases[i].quoted, &after, &sensitive);
    CHECK(complete == cases[i].complete);
    if (complete)
      CHECK(sensitive == cases[i].sensitive && after <= length);
    CHECK(shell_source_skip_complete_backtick(cases[i].source, length, 0,
                                              &lexical_after) == complete);
    CHECK(lexical_after == after);
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous_work = 0;
  for (size_t payload = 32; payload <= 8192; payload *= 4) {
    const char head[] = "printf `printf ";
    const char tail[] = "\\$VALUE`";
    size_t length = sizeof(head) - 1 + payload + sizeof(tail) - 1;
    char *source = malloc(length + 1);
    CHECK(source != NULL);
    if (!source)
      return;
    memcpy(source, head, sizeof(head) - 1);
    memset(source + sizeof(head) - 1, 'a', payload);
    memcpy(source + sizeof(head) - 1 + payload, tail, sizeof(tail));
    shellsplit_test_source_scan_reset();
    CHECK(shell_tokenizer_has_unsupported_semantics(source, length));
    size_t work = shellsplit_test_source_scan_work();
    CHECK(work >= payload && work <= 128 * length);
    CHECK(previous_work == 0 || work <= previous_work * 5);
    previous_work = work;
    free(source);
  }
#endif
}

static void test_complete_word_semantic_work(void) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  static const struct {
    const char *head, *fragment, *tail;
    bool unsupported;
  } cases[] = {
      {"echo \"`printf '\"$\"literal\"'`\"", "''", " $\"translated\"", true},
      {"echo \"`printf '\"$\"literal\"'`\"", "''", " '$\"literal\"'", false},
      {"echo `printf x # note`", "''", " $\"translated\"", true},
      {"getopts \"a", "x", "$spec\" name \"$@\"", false},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    size_t previous_work = 0;
    for (size_t fragments = 32; fragments <= 8192; fragments *= 4) {
      size_t head = strlen(cases[c].head), fragment = strlen(cases[c].fragment);
      size_t tail = strlen(cases[c].tail);
      size_t length = head + fragments * fragment + tail;
      char *source = malloc(length + 1);
      CHECK(source != NULL);
      if (!source)
        return;
      memcpy(source, cases[c].head, head);
      for (size_t i = 0; i < fragments; i++)
        memcpy(source + head + i * fragment, cases[c].fragment, fragment);
      memcpy(source + head + fragments * fragment, cases[c].tail, tail + 1);
      shellsplit_test_source_scan_reset();
      CHECK(shell_tokenizer_has_unsupported_semantics(source, length) ==
            cases[c].unsupported);
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work >= fragments && work <= 128 * length);
      CHECK(previous_work == 0 || work <= previous_work * 5);
      previous_work = work;
      free(source);
    }
  }
#endif
}

static void test_source_helper_boundaries(void) {
  static const struct {
    const char *text;
    bool complete;
    size_t after;
  } brackets[] = {
      {"[!]]", true, 4},       {"[]a]", true, 4},    {"[[:alpha:]]", true, 11},
      {"[[.x.]]", true, 7},    {"[[=x=]]", true, 7}, {"[\\]]", true, 4},
      {"[[:broken", false, 9}, {"[a|b]", false, 2},
  };
  for (size_t i = 0; i < sizeof(brackets) / sizeof(brackets[0]); i++) {
    shell_source_glob_probe_t probe = shell_source_probe_glob_bracket(
        brackets[i].text, strlen(brackets[i].text), 0);
    CHECK(probe.complete == brackets[i].complete &&
          probe.after == brackets[i].after);
  }

  static const struct {
    const char *text;
    bool complete, expands, own_expands, dynamic, valid;
  } braces[] = {
      {"{a,b}", true, true, true, false, true},
      {"{{a,b}", false, true, false, false, true},
      {"{1..3}", true, true, true, false, true},
      {"{1...3}", true, false, false, false, true},
      {"{'a,b'}", true, false, false, false, true},
      {"{a\\,b}", true, false, false, false, true},
      {"{a\\\n,b}", true, true, true, false, true},
      {"{[ab]}", true, false, false, true, true},
      {"{$'a'}", true, false, false, false, true},
      {"{$'\\0'}", true, false, false, false, true},
      {"{${value}}", true, false, false, true, true},
      {"{`printf x`}", true, false, false, true, true},
      {"{$((1 + 2))}", true, false, false, true, true},
      {"{$(printf x)}", true, false, false, true, true},
      {"{<(printf x)}", true, false, false, true, true},
      {"{@(one|two)}", true, false, false, true, true},
      {"{\\", false, false, false, false, false},
      {"{'unfinished}", false, false, false, false, false},
      {"{${unfinished", false, false, false, true, false},
  };
  for (size_t i = 0; i < sizeof(braces) / sizeof(braces[0]); i++) {
    shell_source_brace_fragment_t fragment = shell_source_scan_brace_fragment(
        braces[i].text, strlen(braces[i].text), 0);
    CHECK(fragment.after == strlen(braces[i].text) &&
          fragment.complete == braces[i].complete &&
          fragment.expands == braces[i].expands &&
          fragment.own_expands == braces[i].own_expands &&
          fragment.dynamic == braces[i].dynamic &&
          fragment.valid == braces[i].valid);
  }

  static const char *const redirect_words[] = {
      "${value}>next",       "@(one|two)>next",    "$'quoted'>next",
      "escaped\\ word>next", "'quoted word'>next", "`printf x`>next",
      "$((1 + 2))>next",     "$(printf x)>next",   "<(printf x)>next",
      "word#literal>next",   "word #comment",      "word|next",
  };
  static const char *const redirect_stops[] = {
      ">next", ">next", ">next", ">next", ">next",     ">next",
      ">next", ">next", ">next", ">next", " #comment", "|next",
  };
  for (size_t i = 0; i < sizeof(redirect_words) / sizeof(redirect_words[0]);
       i++) {
    size_t after = shell_source_skip_redirect_word(redirect_words[i], 0,
                                                   strlen(redirect_words[i]));
    CHECK(strcmp(redirect_words[i] + after, redirect_stops[i]) == 0);
  }

  static const struct {
    const char *word;
    bool valid;
    size_t name_length;
    bool append, source_delimiter;
  } assignments[] = {
      {"name=value", true, 4, false, true},
      {"name+=value", true, 4, true, true},
      {"'na'me=value", true, 4, false, true},
      {"$'name=value'", true, 4, false, false},
      {"na\\\nme=value", true, 4, false, true},
      {"=value", false, 0, false, false},
      {"name+q=value", false, 0, false, false},
  };
  for (size_t i = 0; i < sizeof(assignments) / sizeof(assignments[0]); i++) {
    shell_source_decoded_assignment_t assignment;
    bool valid = shell_source_scan_decoded_assignment(
        assignments[i].word, strlen(assignments[i].word), NULL, NULL,
        &assignment);
    CHECK(valid == assignments[i].valid);
    if (valid)
      CHECK(assignment.name_length == assignments[i].name_length &&
            assignment.append == assignments[i].append &&
            assignment.source_delimiter == assignments[i].source_delimiter);
  }
  CHECK(shell_source_word_static_equals("'command'", 9, "command"));
  CHECK(shell_source_word_static_equals("co\\mmand", strlen("co\\mmand"),
                                        "command"));
  CHECK(!shell_source_word_static_equals("$command", 8, "command"));
  CHECK(!shell_source_word_static_equals("command", 7, "builtin"));
}

/* Diagnostic parsing retains its deliberately tolerant quote/subshell forms;
 * that must never relax the complete-source boundary used by semantic APIs.
 * All inputs here are external source, not edited internal parse objects. */
static void test_diagnostic_source_boundary(void) {
  static const struct {
    const char *source;
    shell_error_t diagnostic_status;
    unsigned diagnostic_count;
  } cases[] = {
      {"echo `unfinished", SHELL_OK, 1},
      {"echo 'unfinished", SHELL_OK, 1},
      {"echo \"unfinished", SHELL_OK, 1},
      {"(echo unfinished", SHELL_OK, 1},
      {"cat <<EOF\nunfinished\n", SHELL_OK, 3},
      {"echo $(unfinished", SHELL_EPARSE, 0},
      {"echo $((1", SHELL_EPARSE, 0},
      {"echo ${unfinished", SHELL_EPARSE, 0},
      {"echo <(unfinished", SHELL_EPARSE, 0},
      {"echo >(unfinished", SHELL_EPARSE, 0},
      {"echo &>", SHELL_EPARSE, 0},
      {"echo >", SHELL_EPARSE, 0},
      {"echo > (cmd)", SHELL_EPARSE, 0},
      {"echo > #comment", SHELL_EPARSE, 0},
      {"echo > ;", SHELL_EPARSE, 0},
      {"echo > | x", SHELL_EPARSE, 0},
      {"cmd | ! x", SHELL_EPARSE, 0},
      {"cmd |&", SHELL_EPARSE, 0},
      {"cmd ||| x", SHELL_EPARSE, 0},
      {"cmd && )", SHELL_EPARSE, 0},
      {"{ echo unfinished;", SHELL_EPARSE, 0},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    size_t length = strlen(cases[i].source);
    shell_limits_t limits = SHELL_LIMITS_DEFAULT;
    limits.strict_mode = false;
    shell_parse_result_t parsed;
    CHECK(shell_parse_fast(cases[i].source, length, &limits, &parsed) ==
              cases[i].diagnostic_status &&
          parsed.count == cases[i].diagnostic_count);
    CHECK(parsed.status == (cases[i].diagnostic_status == SHELL_OK
                                ? SHELL_STATUS_OK
                                : SHELL_STATUS_ERROR));
    for (unsigned range = 0; range < parsed.count; range++)
      CHECK(parsed.cmds[range].start <= length &&
            parsed.cmds[range].len <= length - parsed.cmds[range].start);
    limits.strict_mode = true;
    CHECK(shell_parse_fast(cases[i].source, length, &limits, &parsed) ==
              SHELL_EPARSE &&
          parsed.count == 0 && parsed.group_count == 0 &&
          parsed.status == SHELL_STATUS_ERROR);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(cases[i].source, length, NULL, &processed) ==
              SHELL_PROCESS_EPARSE &&
          processed.commands == NULL && processed.command_count == 0);
    shell_processed_commands_free(&processed);
  }
}

static void test_forward_brace_context(void) {
  static const struct {
    const char *source;
    size_t groups;
  } cases[] = {
      {"echo { { text", 0},
      {"echo } } text", 0},
      {"{ echo } ; }", 1},
      {"{ echo { { text; }", 1},
      {"time { echo } ; }", 1},
      {"! time -p { echo } ; }", 1},
      {"{ { echo } ; }; }", 2},
      {"echo >{ { text", 0},
      {"echo >foo\"bar\" { { text", 0},
      {"time\"\" { { text", 0},
      {"time -p\"\" { { text", 0},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    size_t length = strlen(source);
    shell_tokenizer_state_t state;
    shell_token_t token;
    shell_tokenizer_init(&state, source, length, NULL);
    size_t opens = 0, closes = 0;
    while (shell_tokenizer_next(&state, &token)) {
      opens += token.type == SHELL_TOKEN_GROUP_START;
      closes += token.type == SHELL_TOKEN_GROUP_END;
    }
    CHECK(opens == cases[i].groups && closes == cases[i].groups);
    shell_limits_t strict = SHELL_LIMITS_DEFAULT;
    strict.strict_mode = true;
    shell_parse_result_t parsed;
    shell_error_t status = shell_parse_fast(source, length, &strict, &parsed);
    if (status != SHELL_OK)
      fprintf(stderr, "forward brace source rejected: %s\n", source);
    CHECK(status == SHELL_OK);
    CHECK(parsed.group_count == cases[i].groups);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, length, NULL, &processed) ==
          SHELL_PROCESS_OK);
    CHECK(processed.group_count == cases[i].groups &&
          processed.command_count == 1);
    shell_processed_commands_free(&processed);
    shell_dep_graph_t graph;
    CHECK(shell_dep_graph_parse(source, length, ".", NULL, &graph) ==
          SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(&graph).valid);
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  /* Literal brace words after a long command name must not restart prefix
   * scanning at that name. Grow both dimensions to expose quadratic work. */
  size_t previous = 0;
  for (size_t count = 32; count <= 256; count *= 2) {
    size_t length = count * 10;
    char *source = malloc(length + 1);
    CHECK(source != NULL);
    if (!source)
      return;
    memset(source, 'a', count * 8);
    for (size_t word = 0; word < count; word++) {
      source[count * 8 + word * 2] = ' ';
      source[count * 8 + word * 2 + 1] = '{';
    }
    source[length] = '\0';
    shellsplit_test_source_scan_reset();
    bool valid = shell_tokenizer_complete_syntax_valid(source, length);
    size_t work = shellsplit_test_source_scan_work();
    free(source);
    CHECK(valid && work <= 128 * length &&
          (previous == 0 || work <= previous * 3));
    previous = work;
  }
#endif
}

static void test_scoped_heredoc_expansions(void) {
  for (size_t i = 0; i < sizeof(shellsplit_test_scoped_expansions) /
                             sizeof(shellsplit_test_scoped_expansions[0]);
       i++) {
    const shellsplit_test_expansion_case_t *fixture =
        &shellsplit_test_scoped_expansions[i];
    size_t length = strlen(fixture->source);
    shell_parse_result_t parsed;
    shell_limits_t limits = {.max_subcommands = 64, .strict_mode = true};
    bool valid =
        shell_parse_fast(fixture->source, length, &limits, &parsed) == SHELL_OK;
    uint32_t features = 0;
    for (uint32_t j = 0; j < parsed.count; j++)
      features |= parsed.cmds[j].features;
    if (!valid || (features & shellsplit_test_expansion_feature_mask) !=
                      fixture->features)
      fprintf(stderr, "heredoc feature mismatch: %s flags=%x expected=%x\n",
              fixture->source, features, fixture->features);
    CHECK(valid && (features & shellsplit_test_expansion_feature_mask) ==
                       fixture->features);
    CHECK(shell_tokenizer_has_unsupported_semantics(fixture->source, length) ==
          !fixture->supported);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(fixture->source, length, NULL, &processed) ==
          (fixture->supported ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE));
    shell_processed_commands_free(&processed);
    shell_netstring_buffer_t raw = {0}, type = {0};
    size_t stages = SIZE_MAX;
    shell_process_status_t status = shell_build_anomaly_netseqs_buffer(
        fixture->source, length, NULL, &raw, &type, &stages);
    if (!fixture->supported) {
      CHECK(raw.data == NULL && type.data == NULL && stages == 0);
      shell_netstring_buffer_t independent = {0};
      size_t independent_count = SIZE_MAX;
      bool features = true;
      CHECK(shell_build_command_netseq_buffer(
                fixture->source, length, NULL, &independent,
                &independent_count) == SHELL_PROCESS_EPARSE);
      CHECK(independent.data == NULL && independent.length == 0 &&
            independent_count == 0);
      CHECK(shell_build_type_netseq_buffer(fixture->source, length, NULL,
                                           &independent, &independent_count) ==
            SHELL_PROCESS_EPARSE);
      CHECK(independent.data == NULL && independent.length == 0 &&
            independent_count == 0);
      CHECK(shell_build_netargv_sequence_buffer(
                fixture->source, length, NULL, &independent, &independent_count,
                &features) == SHELL_PROCESS_EPARSE);
      CHECK(independent.data == NULL && independent.length == 0 &&
            independent_count == 0 && !features);
      shell_netstring_buffer_free(&independent);
    }
    if (status !=
            (fixture->supported ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE) ||
        stages != fixture->stages)
      fprintf(stderr, "heredoc stages mismatch: %s status=%d stages=%zu\n",
              fixture->source, status, stages);
    CHECK(status ==
              (fixture->supported ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE) &&
          stages == fixture->stages);
    size_t raw_count = 0, type_count = 0;
    CHECK(shell_netstring_validate(raw.data, raw.length, &raw_count) ==
              SHELL_NETSTRING_OK &&
          raw_count == stages);
    CHECK(shell_netstring_validate(type.data, type.length, &type_count) ==
              SHELL_NETSTRING_OK &&
          type_count == stages);
    shell_netstring_buffer_free(&raw);
    shell_netstring_buffer_free(&type);
    shell_dep_graph_t graph;
    CHECK(shell_dep_graph_parse(fixture->source, length, ".", NULL, &graph) ==
          (fixture->supported ? SHELL_DEP_OK : SHELL_DEP_EPARSE));
    size_t commands = 0;
    for (uint32_t j = 0; j < graph.node_count; j++)
      commands += graph.nodes[j].type == SHELL_NODE_CMD;
    /* File-read shortcut fixtures contain one argv-less anomaly stage;
     * their graph represents that stage directly as a FILE document. */
    CHECK(commands + fixture->file_stages == fixture->stages);
    if (fixture->supported && !shell_dep_graph_validate(&graph).valid)
      fprintf(stderr, "heredoc graph mismatch: %s\n", fixture->source);
    CHECK(fixture->supported ? shell_dep_graph_validate(&graph).valid
                             : graph.node_count == 0 && graph.edge_count == 0);
    shell_abstract_command_t *abstract = NULL;
    CHECK(shell_abstract_command_parse(fixture->source, length, &abstract) ==
          (fixture->supported ? SHELL_ABSTRACT_OK : SHELL_ABSTRACT_EPARSE));
    CHECK(fixture->supported || abstract == NULL);
    shell_abstract_command_free(abstract);
    shell_transformed_command_t **transformed = NULL;
    size_t count = 0;
    CHECK(shell_transform_command_line(fixture->source, length, NULL,
                                       &transformed, &count) ==
          (fixture->supported ? SHELL_TRANSFORM_OK : SHELL_TRANSFORM_EPARSE));
    CHECK(fixture->supported || (transformed == NULL && count == 0));
    shell_transformed_command_list_free(transformed, count);
  }
}

static void test_parameter_reevaluation_work(void) {
  static const struct {
    const char *head, *tail;
    bool unsupported;
  } cases[] = {{"${", "@P}", true},
               {"${!", "}", true},
               {"${!", "@}", false},
               {"${", "@Q}", false}};
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    for (size_t leaf = 64; leaf <= 1024; leaf *= 2) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      size_t previous_work = 0, previous_length = 0;
#endif
      for (size_t depth = 4; depth <= 32; depth *= 2) {
        char source[2048] = "printf ";
        size_t length = 7;
        for (size_t i = 0; i < depth; i++) {
          memcpy(source + length, "${outer:-", 9);
          length += 9;
        }
        size_t head = strlen(cases[c].head), tail = strlen(cases[c].tail);
        memcpy(source + length, cases[c].head, head);
        length += head;
        memset(source + length, 'v', leaf);
        length += leaf;
        memcpy(source + length, cases[c].tail, tail);
        length += tail;
        for (size_t i = 0; i < depth; i++)
          source[length++] = '}';
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
        shellsplit_test_source_scan_reset();
#endif
        CHECK(shell_tokenizer_has_unsupported_semantics(source, length) ==
              cases[c].unsupported);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
        size_t work = shellsplit_test_source_scan_work();
        CHECK(work <= 64 * length + 1024 &&
              (previous_work == 0 ||
               work <= previous_work + 64 * (length - previous_length) + 2048));
        previous_work = work;
        previous_length = length;
#endif
      }
    }
  }
}

static void test_variable_predicate_work(void) {
  /* Deep parentheses and many predicates retain only compact word roles.
   * Growing either the expression or a literal operand must not rescan it. */
  for (size_t bracket = 0; bracket < 2; bracket++) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    size_t previous_work = 0, previous_length = 0;
#endif
    for (size_t count = 16; count <= 512; count *= 2) {
      char source[8192];
      size_t length = bracket ? 2 : 5;
      memcpy(source, bracket ? "[ " : "test ", length);
      for (size_t i = 0; i < count; i++) {
        memcpy(source + length, "'(' ", 4);
        length += 4;
      }
      memcpy(source + length, "-n ", 3);
      length += 3;
      memset(source + length, 'x', count);
      length += count;
      const char predicate[] = " -a -v 'a[0]' ";
      memcpy(source + length, predicate, sizeof(predicate) - 1);
      length += sizeof(predicate) - 1;
      for (size_t i = 0; i < count; i++) {
        memcpy(source + length, "')' ", 4);
        length += 4;
      }
      if (bracket)
        source[length++] = ']';
      CHECK(shell_tokenizer_complete_syntax_valid(source, length));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      shellsplit_test_source_scan_reset();
#endif
      CHECK(shell_tokenizer_has_unsupported_semantics(source, length));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work <= 64 * length + 512 &&
            (previous_work == 0 ||
             work <= previous_work + 64 * (length - previous_length) + 512));
      previous_work = work;
      previous_length = length;
#endif
    }
  }
  /* Fixed comparisons provide one-word lookahead for dynamic left operands.
   * A late -v remains visible after any number of these supported predicates.
   */
  for (size_t bracket = 0; bracket < 2; bracket++) {
    for (size_t unsafe = 0; unsafe < 2; unsafe++) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      size_t previous_work = 0, previous_length = 0;
#endif
      for (size_t count = 16; count <= 512; count *= 2) {
        char source[16384];
        size_t length = bracket ? 2 : 5;
        memcpy(source, bracket ? "[ " : "test ", length);
        const char predicate[] = "\"$mode\" = value";
        for (size_t i = 0; i < count; i++) {
          if (i) {
            memcpy(source + length, " -a ", 4);
            length += 4;
          }
          memcpy(source + length, predicate, sizeof(predicate) - 1);
          length += sizeof(predicate) - 1;
        }
        if (unsafe) {
          const char lookup[] = " -a -v 'a[0]'";
          memcpy(source + length, lookup, sizeof(lookup) - 1);
          length += sizeof(lookup) - 1;
        }
        if (bracket) {
          source[length++] = ' ';
          source[length++] = ']';
        }
        CHECK(shell_tokenizer_complete_syntax_valid(source, length));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
        shellsplit_test_source_scan_reset();
#endif
        CHECK(shell_tokenizer_has_unsupported_semantics(source, length) ==
              (unsafe != 0));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
        size_t work = shellsplit_test_source_scan_work();
        CHECK(work <= 64 * length + 512 &&
              (previous_work == 0 ||
               work <= previous_work + 64 * (length - previous_length) + 512));
        previous_work = work;
        previous_length = length;
#endif
      }
    }
  }
  /* The ordinary-data path fails at x, but !/( interpretations reach the
   * final lookup. Keep their long tails live without rescanning prefixes or
   * multiplying the number of role states as the expression grows. */
  for (size_t bracket = 0; bracket < 2; bracket++) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    size_t previous_work = 0, previous_length = 0;
#endif
    for (size_t count = 16; count <= 512; count *= 2) {
      char source[8192];
      size_t length = bracket ? 2 : 5;
      memcpy(source, bracket ? "[ " : "test ", length);
      const char head[] = "\"$operator\" = = x";
      memcpy(source + length, head, sizeof(head) - 1);
      length += sizeof(head) - 1;
      const char predicate[] = " -a = = value";
      for (size_t i = 0; i < count; i++) {
        memcpy(source + length, predicate, sizeof(predicate) - 1);
        length += sizeof(predicate) - 1;
      }
      const char lookup[] = " -a -v 'a[0]'";
      memcpy(source + length, lookup, sizeof(lookup) - 1);
      length += sizeof(lookup) - 1;
      if (bracket) {
        source[length++] = ' ';
        source[length++] = ']';
      }
      CHECK(shell_tokenizer_complete_syntax_valid(source, length));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      shellsplit_test_source_scan_reset();
#endif
      CHECK(shell_tokenizer_has_unsupported_semantics(source, length));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work <= 64 * length + 512 &&
            (previous_work == 0 ||
             work <= previous_work + 64 * (length - previous_length) + 512));
      previous_work = work;
      previous_length = length;
#endif
    }
  }
}

static void test_forward_heredoc_expansions(void) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  for (size_t operation = 0; operation < 4; operation++) {
    size_t previous_work = 0, previous_length = 0;
    for (size_t depth = 4; depth <= 32; depth *= 2) {
      char source[2048];
      size_t length = 10;
      memcpy(source, "cat <<EOF\n", length);
      for (size_t j = 0; j < depth; j++) {
        memcpy(source + length, "${v:-", 5);
        length += 5;
      }
      memset(source + length, 'x', 1024);
      length += 1024;
      for (size_t j = 0; j < depth; j++)
        source[length++] = '}';
      memcpy(source + length, "\nEOF", 4);
      length += 4;
      shellsplit_test_source_scan_reset();
      if (operation == 0)
        CHECK(shell_tokenizer_complete_syntax_valid(source, length));
      else if (operation == 1)
        CHECK(!shell_tokenizer_has_unsupported_semantics(source, length));
      else if (operation == 2) {
        shell_parse_result_t parsed;
        shell_limits_t limits = {.max_subcommands = 64, .strict_mode = true};
        CHECK(shell_parse_fast(source, length, &limits, &parsed) == SHELL_OK);
      } else {
        shell_netstring_buffer_t raw = {0}, type = {0};
        size_t count = 0;
        CHECK(shell_build_anomaly_netseqs_buffer(source, length, NULL, &raw,
                                                 &type,
                                                 &count) == SHELL_PROCESS_OK &&
              count == 1);
        shell_netstring_buffer_free(&raw);
        shell_netstring_buffer_free(&type);
      }
      size_t work = shellsplit_test_source_scan_work();
      if (previous_work &&
          work > previous_work + 64 * (length - previous_length) + 512)
        fprintf(
            stderr,
            "heredoc non-linear work: op=%zu depth=%zu work=%zu previous=%zu\n",
            operation, depth, work, previous_work);
      CHECK(work <= 64 * length + 1024);
      CHECK(previous_work == 0 ||
            work <= previous_work + 64 * (length - previous_length) + 512);
      previous_work = work;
      previous_length = length;
    }
  }
#endif
}

static void test_malformed_heredoc_expansions(void) {
  static const char *const malformed[] = {
      "printf ${text",
      "printf ${text:}",
      "cat <<EOF\n${v:-$(printf child)} ${broken\nEOF",
      "cat <<EOF\n$(printf child) $((1 + 2)\nEOF",
      "cat <<EOF\n${v#'$(printf literal)'} $(echo &&)\nEOF",
  };
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
    size_t length = strlen(malformed[i]);
    CHECK(!shell_tokenizer_complete_syntax_valid(malformed[i], length));
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(malformed[i], length, NULL, &processed) ==
          SHELL_PROCESS_EPARSE);
    CHECK(processed.commands == NULL && processed.command_count == 0);
    shell_netstring_buffer_t raw = {0}, type = {0};
    size_t count = SIZE_MAX;
    CHECK(shell_build_anomaly_netseqs_buffer(malformed[i], length, NULL, &raw,
                                             &type,
                                             &count) == SHELL_PROCESS_EPARSE);
    CHECK(raw.data == NULL && type.data == NULL && count == 0);
    shell_dep_graph_t graph;
    CHECK(shell_dep_graph_parse(malformed[i], length, ".", NULL, &graph) ==
          SHELL_DEP_EPARSE);
    CHECK(graph.node_count == 0 && graph.edge_count == 0);
  }
}

static void test_forward_declarations_and_substrings(void) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  for (size_t operation = 0; operation < 2; operation++) {
    size_t previous_work = 0, previous_length = 0;
    for (size_t depth = 4; depth <= 32; depth *= 2) {
      char source[2048];
      size_t length = 0;
      const char *prefix = operation == 0 ? "cat <<EOF " : "printf ${text:";
      memcpy(source, prefix, strlen(prefix));
      length += strlen(prefix);
      for (size_t i = 0; i < depth; i++) {
        const char *scope = operation == 0 ? "${v:-" : "(";
        memcpy(source + length, scope, strlen(scope));
        length += strlen(scope);
      }
      const char *leaf = operation == 0 ? "<<BOGUS" : "1";
      memcpy(source + length, leaf, strlen(leaf));
      length += strlen(leaf);
      memset(source + length, operation == 0 ? 'x' : '0', 1024);
      length += 1024;
      for (size_t i = 0; i < depth; i++)
        source[length++] = operation == 0 ? '}' : ')';
      const char *suffix = operation == 0 ? "\nbody\nEOF" : "}";
      memcpy(source + length, suffix, strlen(suffix));
      length += strlen(suffix);
      shellsplit_test_source_scan_reset();
      shell_parse_result_t parsed;
      shell_limits_t limits = {.max_subcommands = 64, .strict_mode = true};
      CHECK(shell_parse_fast(source, length, &limits, &parsed) == SHELL_OK);
      CHECK(!shell_tokenizer_has_unsupported_semantics(source, length));
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work <= 128 * length + 1024);
      if (previous_work &&
          work > previous_work + 128 * (length - previous_length) + 1024)
        fprintf(stderr, "nonlinear scoped scan: op=%zu depth=%zu work=%zu\n",
                operation, depth, work);
      CHECK(previous_work == 0 ||
            work <= previous_work + 128 * (length - previous_length) + 1024);
      previous_work = work;
      previous_length = length;
    }
  }
#endif
}

static void test_executable_substitution_work(void) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  const char *wide_word = "$(printf ok) ";
  const size_t wide_count = 2304;
  size_t wide_length = wide_count * strlen(wide_word);
  char *source = malloc(wide_length + 2048);
  CHECK(source != NULL);
  if (!source)
    return;
  for (size_t wide = 0; wide < 2; wide++) {
    for (size_t operation = 0; operation < 3; operation++) {
      for (size_t depth = 1; depth <= (wide ? 8u : 16u); depth *= 2) {
        size_t length = 7;
        memcpy(source, "printf ", length);
        for (size_t i = 0; i < depth; i++) {
          memcpy(source + length, "$(printf ", 9);
          length += 9;
        }
        size_t leaf_start = length;
        if (wide) {
          for (size_t i = 0; i < wide_count; i++)
            memcpy(source + length + i * strlen(wide_word), wide_word,
                   strlen(wide_word));
          length += wide_length;
        } else {
          memset(source + length, 'x', 1024);
          length += 1024;
        }
        for (size_t i = 0; i < depth; i++)
          source[length++] = ')';
        shellsplit_test_source_scan_reset();
        shellsplit_test_delimiter_watch(source + leaf_start,
                                        wide ? wide_length : 1024);
        if (operation == 0)
          CHECK(shell_tokenizer_complete_syntax_valid(source, length));
        else if (operation == 1)
          CHECK(!shell_tokenizer_has_unsupported_semantics(source, length));
        else {
          shell_parse_result_t parsed;
          shell_limits_t limits = {.max_subcommands = 64, .strict_mode = true};
          CHECK(shell_parse_fast(source, length, &limits, &parsed) == SHELL_OK);
        }
        size_t work = shellsplit_test_source_scan_work();
        if (work > 128 * length + 1024)
          fprintf(stderr, "nested work op=%zu depth=%zu bytes=%zu work=%zu\n",
                  operation, depth, length, work);
        CHECK(work <= 128 * length + 1024);
        /* A bounded index can churn differently when ancestor keys change.
         * Count actual balancing of the unchanged leaf, not incidental work
         * from collisions elsewhere in the source. The number of source
         * phases, not nesting depth, bounds these visits. */
        size_t phases = operation == 2 ? 8 : 2;
        CHECK(shellsplit_test_delimiter_work() <=
              phases * (wide ? wide_length : 1024));
      }
    }
  }
  free(source);
#endif
}

static void test_file_substitution_provenance(void) {
  static const struct {
    const char *body;
    bool file;
  } cases[] = {
      {"<file", true},
      {"0<file", true},
      {"00<file;", true},
      {"# heading\n<file", true},
      {"<file; # tail\n", true},
      {"<file printf ok", false},
      {"1<file", false},
      {"<file <other", false},
      {"<file 2>/dev/null", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char source[256];
    int length =
        snprintf(source, sizeof(source), "printf \"$(%s)\"", cases[i].body);
    CHECK(length > 0 && (size_t)length < sizeof(source));
    shell_dep_graph_t graph;
    CHECK(shell_dep_graph_parse(source, (size_t)length, "/workspace", NULL,
                                &graph) == SHELL_DEP_OK);
    size_t direct = 0;
    for (uint32_t j = 0; j < graph.edge_count; j++) {
      shell_dep_edge_t *edge = &graph.edges[j];
      shell_dep_node_t *node = &graph.nodes[edge->from];
      if (edge->type == SHELL_EDGE_SUBST &&
          (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) &&
          node->type == SHELL_NODE_DOC && node->doc.kind == SHELL_DOC_FILE) {
        CHECK(node->doc.path_len == 4 &&
              memcmp(node->doc.path, "file", 4) == 0);
        direct++;
      }
    }
    CHECK(direct == (cases[i].file ? 1u : 0u));
    CHECK(shell_dep_graph_validate(&graph).valid);
    shell_parse_result_t parsed;
    shell_limits_t limits = {.max_subcommands = 64, .strict_mode = true};
    CHECK(shell_parse_fast(source, (size_t)length, &limits, &parsed) ==
          SHELL_OK);
    uint32_t flags = 0;
    for (uint32_t j = 0; j < parsed.count; j++)
      flags |= parsed.cmds[j].features;
    CHECK(((flags & SHELL_FEAT_SUBSHELL_FILE) != 0) == cases[i].file);
  }
}

static void test_lexical_index_lifetime(void) {
  char source[64];
  static const char *const cases[] = {
      "printf $(printf ok)",
      "printf $(echo &&)",
      "printf $(printf ${v:-)})",
      "printf $(printf ok)",
  };
  for (size_t round = 0; round < 2; round++)
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      strcpy(source, cases[i]);
      CHECK(shell_tokenizer_complete_syntax_valid(source, strlen(source)) ==
            (i != 1));
      shell_parse_result_t parsed;
      shell_limits_t limits = {.max_subcommands = 64, .strict_mode = true};
      CHECK(shell_parse_fast(source, strlen(source), &limits, &parsed) ==
            (i == 1 ? SHELL_EPARSE : SHELL_OK));
    }
  /* A wide source must not turn index capacity into a syntax restriction or
   * leave a full table disabling reuse for all subsequent nested subtrees. */
  const size_t repetitions = 2304;
  const char *word = "$(printf $(printf ok)) ";
  size_t word_length = strlen(word);
  size_t length = 7 + repetitions * word_length;
  char *wide = malloc(length);
  CHECK(wide != NULL);
  if (!wide)
    return;
  memcpy(wide, "printf ", 7);
  for (size_t i = 0; i < repetitions; i++)
    memcpy(wide + 7 + i * word_length, word, word_length);
  CHECK(shell_tokenizer_complete_syntax_valid(wide, length));
  CHECK(!shell_tokenizer_has_unsupported_semantics(wide, length));
  free(wide);
}

static bool scan_budget_family(size_t family, const char *source, size_t length,
                               size_t position, size_t *after) {
  switch (family) {
  case 0:
    return shell_source_skip_parameter_expansion(source, length, position,
                                                 after);
  case 1:
    return shell_source_skip_arithmetic_expansion(source, length, position,
                                                  after);
  case 2:
    return shell_source_skip_complete_double_quote(source, length, position,
                                                   after);
  default:
    return shell_source_find_balanced_parentheses(source, length, position + 1,
                                                  after);
  }
}

static size_t skip_with_enclosing_scanners(const char *source, size_t length,
                                           size_t enclosing) {
  if (enclosing == 0)
    return shell_source_skip_balanced_parentheses(source, length, 0);
  if (!shell_source_scan_enter())
    return length;
  size_t after = skip_with_enclosing_scanners(source, length, enclosing - 1);
  (void)shell_source_scan_leave();
  return after;
}

static void test_parenthesis_sentinel_cache_parity(void) {
  static const struct {
    const char *source;
    size_t opening, after;
  } cases[] = {
      {"(abc) tail", 0, sizeof("(abc)") - 1},
      {"prefix (abc) tail", sizeof("prefix ") - 1, sizeof("prefix (abc)") - 1},
      {"(printf \"$(echo ')')\") tail", 0,
       sizeof("(printf \"$(echo ')')\")") - 1},
      {"(cat <<'END'\n)\nEND\nprintf ok\n) tail", 0,
       sizeof("(cat <<'END'\n)\nEND\nprintf ok\n)") - 1},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    size_t length = strlen(source);
    for (size_t shift = 0; shift <= cases[i].opening; shift++) {
      for (size_t end = shift; end <= length; end++) {
        size_t span_length = end - shift;
        size_t opening = cases[i].opening - shift;
        size_t expected =
            end >= cases[i].after ? cases[i].after - shift : span_length;
        size_t cold = shell_source_skip_balanced_parentheses(
            source + shift, span_length, opening);
        shell_source_operation_begin(source, length);
        size_t complete = shell_source_skip_balanced_parentheses(
            source, length, cases[i].opening);
        size_t warm = shell_source_skip_balanced_parentheses(
            source + shift, span_length, opening);
        shell_source_operation_end();
        CHECK(complete == cases[i].after);
        CHECK(cold == expected && warm == expected);
        CHECK(warm <= span_length);
      }
    }
  }

  /* Enter real enclosing scanner frames, without modifying depth counters.
   * A cached subtree must fail with the same sentinel as a fresh traversal
   * when the remaining structural budget cannot accommodate its height. */
  static const char source[] = "(echo $(echo x)) tail";
  size_t length = sizeof(source) - 1;
  size_t complete = sizeof("(echo $(echo x))") - 1;
  for (size_t enclosing = SHELL_MAX_SUBCOMMANDS - 2;
       enclosing <= SHELL_MAX_SUBCOMMANDS; enclosing++) {
    size_t cold = skip_with_enclosing_scanners(source, length, enclosing);
    shell_source_operation_begin(source, length);
    size_t cached = shell_source_skip_balanced_parentheses(source, length, 0);
    size_t warm = skip_with_enclosing_scanners(source, length, enclosing);
    shell_source_operation_end();
    CHECK(cached == complete);
    CHECK(cold == (enclosing == SHELL_MAX_SUBCOMMANDS - 2 ? complete : length));
    CHECK(warm == cold);
  }
}

static void test_lexical_index_budget_parity(void) {
  for (size_t family = 0; family < 4; family++) {
    size_t after = 0;
    CHECK(!scan_budget_family(family, NULL, 0, 0, &after));
    CHECK(!scan_budget_family(family, "", 0, 0, &after));
  }
  /* All passes share the original immutable source. A warm index is an
   * optimization, never permission to bypass a source nesting budget. */
  for (size_t depth = 15; depth <= 20; depth++) {
    char source[512];
    size_t length = 7;
    memcpy(source, "printf ", length);
    for (size_t i = 0; i < depth; i++) {
      memcpy(source + length, "$(printf ", 9);
      length += 9;
    }
    source[length++] = '1';
    for (size_t i = 0; i < depth; i++)
      source[length++] = ')';
    bool cold_valid = shell_tokenizer_complete_syntax_valid(source, length);
    bool cold_unsupported =
        shell_tokenizer_has_unsupported_semantics(source, length);
    CHECK(cold_valid);
    CHECK(cold_unsupported == (depth > SHELL_SOURCE_MAX_EXECUTABLE_NESTING));
    for (size_t order = 0; order < 2; order++) {
      shell_source_operation_begin(source, length);
      if (order == 0)
        CHECK(shell_tokenizer_complete_syntax_valid(source, length) ==
              cold_valid);
      else
        CHECK(shell_tokenizer_has_unsupported_semantics(source, length) ==
              cold_unsupported);
      CHECK(shell_tokenizer_has_unsupported_semantics(source, length) ==
            cold_unsupported);
      CHECK(shell_tokenizer_complete_syntax_valid(source, length) ==
            cold_valid);
      shell_source_operation_end();
    }
  }
  static const struct {
    const char *prefix, *suffix;
  } families[] = {{"${v:-", "}"},
                  {"$((", "))"},
                  {"\"$(printf ", ")\""},
                  {"$(printf ", ")"}};
  for (size_t family = 0; family < sizeof(families) / sizeof(families[0]);
       family++) {
    for (size_t depth = 31; depth <= 65; depth++) {
      char source[1024];
      size_t prefix_length = strlen(families[family].prefix);
      size_t suffix_length = strlen(families[family].suffix);
      size_t length = 0;
      for (size_t i = 0; i < depth; i++) {
        memcpy(source + length, families[family].prefix, prefix_length);
        length += prefix_length;
      }
      source[length++] = '1';
      for (size_t i = 0; i < depth; i++) {
        memcpy(source + length, families[family].suffix, suffix_length);
        length += suffix_length;
      }
      size_t cold_end = 0;
      bool cold = scan_budget_family(family, source, length, 0, &cold_end);
      CHECK(cold == (depth <= (family == 2 ? SHELL_MAX_SUBCOMMANDS / 2
                                           : SHELL_MAX_SUBCOMMANDS)));
      shell_source_operation_begin(source, length);
      size_t inner_end = 0, warm_end = 0;
      (void)scan_budget_family(family, source, length, prefix_length,
                               &inner_end);
      bool warm = scan_budget_family(family, source, length, 0, &warm_end);
      CHECK(warm == cold);
      if (cold)
        CHECK(warm_end == cold_end && cold_end == length);
      shell_source_operation_end();
    }
  }
}

static void test_long_siblings_before_nested_tail(void) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  /* Longer preceding siblings used to fill the index and prevent the shorter
   * current tail from retaining its own boundaries. Increasing nesting then
   * revisited the unchanged leaf at every level. */
  const size_t siblings = 4608, payload = 512;
  const size_t capacity = 7 + siblings * (payload + 11) + 2048;
  char *source = malloc(capacity);
  CHECK(source != NULL);
  if (!source)
    return;
  size_t prefix = 7;
  memcpy(source, "printf ", prefix);
  for (size_t i = 0; i < siblings; i++) {
    memcpy(source + prefix, "$(printf ", 9);
    prefix += 9;
    memset(source + prefix, 'x', payload);
    prefix += payload;
    memcpy(source + prefix, ") ", 2);
    prefix += 2;
  }
  for (size_t operation = 0; operation < 3; operation++) {
    for (size_t depth = 1; depth <= 16; depth *= 2) {
      size_t length = prefix;
      for (size_t i = 0; i < depth; i++) {
        memcpy(source + length, "$(printf ", 9);
        length += 9;
      }
      memset(source + length, 'y', 128);
      length += 128;
      for (size_t i = 0; i < depth; i++)
        source[length++] = ')';
      shellsplit_test_source_scan_reset();
      shellsplit_test_delimiter_watch(source + prefix + depth * 9, 128);
      if (operation == 0)
        CHECK(shell_tokenizer_complete_syntax_valid(source, length));
      else if (operation == 1)
        CHECK(!shell_tokenizer_has_unsupported_semantics(source, length));
      else {
        shell_parse_result_t parsed;
        shell_limits_t limits = {.max_subcommands = 64, .strict_mode = true};
        CHECK(shell_parse_fast(source, length, &limits, &parsed) == SHELL_OK);
      }
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work <= 128 * length + 1024);
      size_t phases = operation == 2 ? 8 : 2;
      if (shellsplit_test_delimiter_work() > phases * 128)
        fprintf(stderr, "tail op=%zu depth=%zu delimiter work=%zu\n", operation,
                depth, shellsplit_test_delimiter_work());
      CHECK(shellsplit_test_delimiter_work() <= phases * 128);
    }
  }
  free(source);
#endif
}

static void test_document_lexical_boundaries(void) {
  static const struct {
    const char *source;
    const char *operand;
    bool named;
    bool heredoc;
  } cases[] = {
      {"(cat <<<body)", "body", false, false},
      {"time (cat <<<body)", "body", false, false},
      {"(time -p (cat <<<body))", "body", false, false},
      {"(cat <<<\"a)b\")", "\"a)b\"", false, false},
      {"(cat <<<a\\)b)", "a\\)b", false, false},
      {"(cat <<<$(printf body))", "$(printf body)", false, false},
      {"(cat <<<${value:-a)b})", "${value:-a)b}", false, false},
      {"(cat <<<@(a|b))", "@(a|b)", false, false},
      {"exec {fd}>/dev/null; exec {fd}>&-{out}<<<x; cat <&$out", "x", true,
       false},
      {"exec 9>/dev/null; exec 9>&-{out}<<<x; cat <&$out", "x", true, false},
      {"exec {fd}>/dev/null; exec {fd}>&-\\\n{out}<<<x; cat <&$out", "x", true,
       false},
      {"exec {fd}>/dev/null; exec {fd}>&-{out}<<EOF; cat <&$out\nx\nEOF\n", "x",
       true, true},
      {"exec 9>/dev/null; exec 9>&-{out}<<'EOF'; cat <&$out\nx\nEOF\n", "x",
       true, true},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    const char *source = cases[c].source;
    size_t length = strlen(source);
    shell_parse_result_t parsed;
    shell_limits_t limits = {.max_subcommands = 64, .strict_mode = true};
    CHECK(shell_parse_fast(source, length, &limits, &parsed) == SHELL_OK);
    CHECK(parsed.group_count == (cases[c].named ? 0 : c == 2 ? 2 : 1));
    size_t documents = 0;
    for (uint32_t i = 0; i < parsed.count; i++) {
      const shell_range_t *range = &parsed.cmds[i];
      if (range->type == SHELL_TYPE_HERESTRING) {
        const char *operand = source + range->start + 3;
        CHECK(range->len == 3 + strlen(cases[c].operand));
        CHECK(memcmp(operand, cases[c].operand, strlen(cases[c].operand)) == 0);
        documents++;
      } else if (range->type == SHELL_TYPE_HEREDOC) {
        documents++;
      }
    }
    CHECK(documents == 1);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, length, NULL, &processed) ==
          SHELL_PROCESS_OK);
    CHECK(processed.command_count == (cases[c].named ? 3 : 1));
    shell_processed_commands_free(&processed);
    shell_netstring_buffer_t sequence = {0}, raw = {0}, typed = {0};
    size_t count = 0;
    bool features = false;
    CHECK(shell_build_netargv_sequence_buffer(source, length, NULL, &sequence,
                                              &count,
                                              &features) == SHELL_PROCESS_OK);
    CHECK(count == (cases[c].named ? 3 : 1));
    CHECK(shell_build_anomaly_netseqs_buffer(source, length, NULL, &raw, &typed,
                                             &count) == SHELL_PROCESS_OK);
    shell_netstring_buffer_free(&sequence);
    shell_netstring_buffer_free(&raw);
    shell_netstring_buffer_free(&typed);
    shell_dep_graph_t graph;
    shell_dep_error_t status = shell_dep_graph_parse_with_fast(
        source, length, "/workspace", NULL, &parsed, &graph);
    CHECK(status == SHELL_DEP_OK);
    if (status != SHELL_DEP_OK)
      continue;
    CHECK(shell_dep_graph_validate(&graph).valid);
    size_t document_nodes = 0, document_reads = 0, named_opens = 0, closes = 0;
    for (uint32_t i = 0; i < graph.node_count; i++) {
      const shell_dep_node_t *node = &graph.nodes[i];
      if (node->type != SHELL_NODE_DOC ||
          node->doc.kind !=
              (cases[c].heredoc ? SHELL_DOC_HEREDOC : SHELL_DOC_HERESTRING))
        continue;
      document_nodes++;
      size_t payload_length = strlen(cases[c].operand);
      CHECK(node->doc.value_len == payload_length + cases[c].heredoc);
      CHECK(memcmp(node->doc.value, cases[c].operand, payload_length) == 0);
      if (cases[c].heredoc)
        CHECK(node->doc.value[payload_length] == '\n');
      for (uint32_t j = 0; j < graph.edge_count; j++) {
        const shell_dep_edge_t *edge = &graph.edges[j];
        if (edge->type == SHELL_EDGE_READ && edge->from == i) {
          CHECK(edge->target_fd == 0);
          CHECK(graph.nodes[edge->to].type == SHELL_NODE_CMD &&
                graph.nodes[edge->to].cmd.token_count != 0 &&
                graph.nodes[edge->to].cmd.token_lens[0] == 3 &&
                memcmp(graph.nodes[edge->to].cmd.tokens[0], "cat", 3) == 0);
          document_reads++;
        }
        if (edge->type == SHELL_EDGE_FD_OPEN && edge->from == i) {
          CHECK(edge->target_fd == SHELL_DEP_FD_NAMED &&
                edge->target_fd_name_len == 3 &&
                memcmp(edge->target_fd_name, "out", 3) == 0);
          named_opens++;
        }
      }
    }
    for (uint32_t i = 0; i < graph.edge_count; i++)
      closes += graph.edges[i].type == SHELL_EDGE_FD_CLOSE;
    CHECK(document_nodes == 1 && document_reads == 1);
    CHECK(named_opens == (cases[c].named ? 1 : 0));
    CHECK(closes == (cases[c].named ? 1 : 0));
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  /* Growing the number of document prefixes must not revisit an unchanged
   * leading word for every descriptor boundary. Count actual source work,
   * rather than depending on machine speed or timing thresholds. */
  for (size_t operation = 0; operation < 2; operation++) {
    size_t previous_work = 0, previous_length = 0;
    for (size_t documents = 4; documents <= 16; documents *= 2) {
      char source[8192];
      memcpy(source, "printf '", 8);
      size_t length = 8;
      memset(source + length, 'x', 2048);
      length += 2048;
      const char *separator = "'; exec {fd}>/dev/null; ";
      memcpy(source + length, separator, strlen(separator));
      length += strlen(separator);
      for (size_t i = 0; i < documents; i++) {
        const char *redirect =
            i == 0 ? "exec {fd}>&-{out}<<<x; " : "exec {out}<<<x; ";
        memcpy(source + length, redirect, strlen(redirect));
        length += strlen(redirect);
      }
      memcpy(source + length, "cat <&$out", 10);
      length += 10;
      shellsplit_test_source_scan_reset();
      if (operation == 0) {
        shell_parse_result_t parsed;
        shell_limits_t limits = {.max_subcommands = 64, .strict_mode = true};
        CHECK(shell_parse_fast(source, length, &limits, &parsed) == SHELL_OK);
      } else {
        shell_processed_commands_t processed = {0};
        CHECK(shell_process_commands(source, length, NULL, &processed) ==
              SHELL_PROCESS_OK);
        CHECK(processed.command_count == documents + 3);
        shell_processed_commands_free(&processed);
      }
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work <= 64 * length + 1024);
      CHECK(previous_work == 0 ||
            work <= previous_work + 128 * (length - previous_length) + 1024);
      previous_work = work;
      previous_length = length;
    }
  }
#endif
}

static void test_processor_single_pass_records(void) {
  static const struct {
    const char *source;
    size_t flat_count, structured_count, flag_index;
  } cases[] = {
      {">first; { time -p printf x |& cat; >inner; } 2>err; >last", 5, 2, 2},
      {"{ { >a; }; { printf x; >b; } 2>err; } >out", 3, 1, 1},
      {"time (cat <<'EOF'\ntime bad |& x; }\nEOF\n); >last", 2, 1, SIZE_MAX},
      {"{ >inner; } 2>err; printf x", 2, 1, SIZE_MAX},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    const char *source = cases[c].source;
    size_t length = strlen(source);
    shell_command_info_t *flat = NULL;
    size_t count = 0;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_source_scan_reset();
#endif
    shell_process_status_t status =
        shell_process_command(source, length, NULL, &flat, &count);
    CHECK(status == SHELL_PROCESS_OK && count == cases[c].flat_count);
    if (status != SHELL_PROCESS_OK)
      continue;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_PROCESS_RANGE_BUILDS) == count);
    CHECK(shellsplit_test_metadata_work(
              SHELLSPLIT_TEST_WORK_PROCESS_GROUP_BOUNDARIES) == count);
#endif
    if (cases[c].flag_index != SIZE_MAX)
      CHECK(flat[cases[c].flag_index].has_error_redirection);
    size_t argv_count = 0, total = 0, maximum = 0;
    for (size_t i = 0; i < count; i++) {
      argv_count += flat[i].command_token_count != 0;
      size_t bytes = strlen(flat[i].original_command);
      total += bytes;
      if (bytes > maximum)
        maximum = bytes;
    }
    CHECK(argv_count == cases[c].structured_count);
    shell_command_infos_free(flat, count);
    shell_process_limits_t limits = {maximum, total, 0};
    flat = NULL;
    CHECK(shell_process_command(source, length, &limits, &flat, &count) ==
              SHELL_PROCESS_OK &&
          count == cases[c].flat_count);
    shell_command_infos_free(flat, count);
    limits.max_total_bytes--;
    flat = NULL;
    count = SIZE_MAX;
    CHECK(shell_process_command(source, length, &limits, &flat, &count) ==
              SHELL_PROCESS_EOUTPUT_LIMIT &&
          flat == NULL && count == 0);
    shell_command_infos_free(flat, count);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, length, NULL, &processed) ==
              SHELL_PROCESS_OK &&
          processed.command_count == cases[c].structured_count);
    shell_processed_commands_free(&processed);
  }
}

static void test_fast_range_escaped_space_boundaries(void) {
  /* An escaped horizontal whitespace byte is word content even when a list
   * operator or the source boundary follows immediately. The fast parser's
   * zero-copy range must retain it so structured and flat canonical argv
   * cannot disagree about the final byte. */
  static const struct {
    const char *source;
    bool retains_space;
  } cases[] = {
      {"printf x\\ | cat", true},
      {"printf x\\ && cat", true},
      {"printf x\\ || cat", true},
      {"printf x\\ ; cat", true},
      {"printf x\\ & cat", true},
      {"printf x\\ \ncat", true},
      {"printf x\\ ", true},
      {"(printf '%s\\e 'non\\ | sed 's/o do' | sort)", true},
      /* An even backslash run leaves the space unescaped, so the same trim
       * must discard it while preserving both literal backslashes. */
      {"printf x\\\\ ", false},
  };
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    const char *source = cases[c].source;
    size_t length = strlen(source);
    shell_parse_result_t parsed = {0};
    shell_limits_t strict = SHELL_LIMITS_DEFAULT;
    strict.strict_mode = true;
    CHECK(shell_parse_fast(source, length, &strict, &parsed) == SHELL_OK);
    CHECK(parsed.count != 0 && parsed.cmds[0].len >= 2);
    if (parsed.count != 0 && parsed.cmds[0].len >= 2) {
      size_t end = parsed.cmds[0].start + parsed.cmds[0].len;
      if (cases[c].retains_space)
        CHECK(source[end - 2] == '\\' && source[end - 1] == ' ');
      else
        CHECK(source[end - 1] == '\\' && source[end] == ' ');
    }

    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t sequence = {0};
    size_t sequence_count = 0;
    bool features = false;
    shell_process_status_t processed_status =
        shell_process_commands(source, length, NULL, &processed);
    shell_process_status_t sequence_status =
        shell_build_netargv_sequence_buffer(source, length, NULL, &sequence,
                                            &sequence_count, &features);
    CHECK(processed_status == SHELL_PROCESS_OK);
    CHECK(sequence_status == SHELL_PROCESS_OK);
    CHECK(processed.command_count == sequence_count);
    if (processed_status == SHELL_PROCESS_OK &&
        sequence_status == SHELL_PROCESS_OK &&
        processed.command_count == sequence_count) {
      shell_netstring_iter_t records;
      shell_netstring_view_t record = {0};
      CHECK(shell_netstring_iter_init(&records, sequence.data,
                                      sequence.length) == SHELL_NETSTRING_OK);
      for (size_t i = 0; i < processed.command_count; i++) {
        shell_netstring_buffer_t argv = {0};
        CHECK(shell_netstring_iter_next(&records, &record) ==
              SHELL_NETSTRING_OK);
        CHECK(shell_render_netargv_buffer(&processed.commands[i], NULL,
                                          &argv) == SHELL_PROCESS_OK);
        CHECK(argv.length == record.payload_length &&
              memcmp(argv.data, record.payload, argv.length) == 0);
        shell_netstring_buffer_free(&argv);
      }
      CHECK(shell_netstring_iter_next(&records, &record) ==
            SHELL_NETSTRING_DONE);
    }
    shell_netstring_buffer_free(&sequence);
    shell_processed_commands_free(&processed);
  }
}

static void test_processor_heredoc_work(void) {
  /* Bodies are data, not executable ranges. Grow the number of later groups
   * without growing the body, catching a per-command revisit of that body.
   * Line work counts the bytes actually traversed by physical-line helpers. */
  const size_t body_length = 65536;
  char *source = malloc(body_length + 4096);
  CHECK(source != NULL);
  if (!source)
    return;
  for (unsigned flat_output = 0; flat_output < 2; flat_output++) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    size_t previous_work = 0, previous_length = 0, previous_lines = 0;
#endif
    for (size_t groups = 4; groups <= 32; groups *= 2) {
      const char *prefix = flat_output ? "(cat <<'EOF'\n" : "cat <<'EOF'\n";
      size_t length = strlen(prefix);
      memcpy(source, prefix, length);
      memset(source + length, 'x', body_length);
      static const char data[] =
          "time false |& cat; { echo; }; $(printf bad)\n";
      memcpy(source + length, data, sizeof(data) - 1);
      length += body_length;
      const char *end = flat_output ? "\nEOF\n); " : "\nEOF\n";
      memcpy(source + length, end, strlen(end));
      length += strlen(end);
      for (size_t i = 0; i < groups; i++) {
        static const char command[] = "{ printf x; }; ";
        memcpy(source + length, command, sizeof(command) - 1);
        length += sizeof(command) - 1;
      }
      source[length] = '\0';
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      shellsplit_test_source_scan_reset();
#endif
      if (flat_output) {
        shell_command_info_t *flat = NULL;
        size_t count = 0;
        CHECK(shell_process_command(source, length, NULL, &flat, &count) ==
                  SHELL_PROCESS_OK &&
              count == groups + 1);
        shell_command_infos_free(flat, count);
      } else {
        shell_processed_commands_t processed = {0};
        CHECK(shell_process_commands(source, length, NULL, &processed) ==
                  SHELL_PROCESS_OK &&
              processed.command_count == groups + 1 &&
              processed.group_count == groups);
        shell_processed_commands_free(&processed);
      }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      size_t work = shellsplit_test_source_scan_work();
      CHECK(shellsplit_test_line_scan_work() >= body_length);
      CHECK(work <= 128 * length + 1024);
      if (previous_work != 0 &&
          work > previous_work + 256 * (length - previous_length) + 4096)
        fprintf(stderr,
                "heredoc work flat=%u groups=%zu source=%zu total=%zu line=%zu "
                "previous=%zu\n",
                flat_output, groups, length, work,
                shellsplit_test_line_scan_work(), previous_work);
      CHECK(previous_work == 0 ||
            work <= previous_work + 256 * (length - previous_length) + 4096);
      size_t lines = shellsplit_test_line_scan_work();
      CHECK(previous_lines == 0 ||
            lines <= previous_lines + 256 * (length - previous_length) + 4096);
      CHECK(shellsplit_test_metadata_work(
                SHELLSPLIT_TEST_WORK_PROCESS_RANGE_BUILDS) == groups + 1);
      CHECK(shellsplit_test_metadata_work(
                SHELLSPLIT_TEST_WORK_PROCESS_GROUP_BOUNDARIES) == groups + 1);
      previous_work = work;
      previous_length = length;
      previous_lines = lines;
#endif
    }
  }
  free(source);
}

static void test_adjacent_named_fd_boundaries(void) {
  static const char *const commands[] = {
      "exec {fd}>/dev/null; exec {fd}>&-{out}>/dev/null; printf ok >&$out",
      "exec {fd}</dev/null; exec {fd}<&-{out}</dev/null; cat <&$out",
      "exec 9>/dev/null; exec 9>&-{out}>/dev/null; printf ok >&$out",
      "exec 9</dev/null; exec 9<&-{out}</dev/null; cat <&$out",
      "exec 9>/dev/null; exec 9>&-\\\n{out}>/dev/null; printf ok >&$out",
  };
  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    const char *source = commands[i];
    size_t length = strlen(source);
    CHECK(shell_tokenizer_complete_syntax_valid(source, length));
    CHECK(!shell_tokenizer_has_unsupported_semantics(source, length));
    shell_parse_result_t parsed;
    shell_limits_t limits = {.max_subcommands = 64, .strict_mode = true};
    CHECK(shell_parse_fast(source, length, &limits, &parsed) == SHELL_OK);
    CHECK(parsed.count == 3);
    CHECK(parsed.cmds[1].features & SHELL_FEAT_NAMED_FD);
    shell_dep_graph_t graph;
    shell_dep_error_t status = shell_dep_graph_parse_with_fast(
        source, length, "/workspace", NULL, &parsed, &graph);
    CHECK(status == SHELL_DEP_OK);
    if (status != SHELL_DEP_OK)
      continue;
    size_t closes = 0, opens = 0, uses = 0;
    for (uint32_t j = 0; j < graph.edge_count; j++) {
      const shell_dep_edge_t *edge = &graph.edges[j];
      closes += edge->type == SHELL_EDGE_FD_CLOSE;
      opens += edge->type == SHELL_EDGE_FD_OPEN;
      uses += edge->type ==
                  (i == 1 || i == 3 ? SHELL_EDGE_READ : SHELL_EDGE_WRITE) &&
              graph.nodes[edge->from].type != SHELL_NODE_FD &&
              graph.nodes[edge->to].type != SHELL_NODE_FD;
    }
    CHECK(closes == 1 && opens == 2 && uses == 1);
    CHECK(shell_dep_graph_validate(&graph).valid);
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(source, length, NULL, &processed) ==
          SHELL_PROCESS_OK);
    CHECK(processed.command_count == 3);
    shell_processed_commands_free(&processed);
  }
  static const char *const literals[] = {
      "printf word-{out}>/dev/null", "printf $(printf x){out}>/dev/null",
      "printf '{out}'>/dev/null",    "printf \\{out}>/dev/null",
      "printf \"\"{out}>/dev/null",  "printf $(printf x)9>/dev/null",
  };
  for (size_t i = 0; i < sizeof(literals) / sizeof(literals[0]); i++) {
    shell_parse_result_t parsed;
    shell_limits_t limits = {.max_subcommands = 64, .strict_mode = true};
    CHECK(shell_parse_fast(literals[i], strlen(literals[i]), &limits,
                           &parsed) == SHELL_OK);
    CHECK(!(parsed.cmds[0].features & SHELL_FEAT_NAMED_FD));
    shell_tokenizer_state_t lexer;
    CHECK(shell_tokenizer_init(&lexer, literals[i], strlen(literals[i]), NULL));
    shell_token_t token;
    while (shell_tokenizer_next(&lexer, &token)) {
      if (token.type == SHELL_TOKEN_REDIRECT_OUT ||
          token.type == SHELL_TOKEN_REDIRECT_ERR)
        CHECK(token.start[0] == '>');
    }
  }
}

int main(void) {
  test_source_scratch_array_reservations();
  test_owned_conditional_workspace();
  test_quoted_literal_bytes();
  test_logical_comment_boundaries();
  test_comment_boundary_io();
  test_comment_boundary_work();
  test_array_prefix_semantics();
  test_builtin_option_semantics();
  test_printf_effect_schedule();
  test_readonly_builtin_effect_schedule();
  test_declaration_prefix_promotion_roles();
  test_processor_single_pass_records();
  test_fast_range_escaped_space_boundaries();
  test_processor_heredoc_work();
  test_document_lexical_boundaries();
  test_sequence_encoded_byte_limits();
  test_anomaly_cumulative_group_budget();
  test_single_byte_validation_boundary();
  test_public_source_validation_boundary();
  test_anomaly_heredoc_collection_limits();
  test_public_anomaly_traversal_work();
  test_executable_substitution_work();
  test_file_substitution_provenance();
  test_lexical_index_lifetime();
  test_parenthesis_sentinel_cache_parity();
  test_lexical_index_budget_parity();
  test_adjacent_named_fd_boundaries();
  test_long_siblings_before_nested_tail();
  test_scoped_heredoc_expansions();
  test_parameter_reevaluation_work();
  test_variable_predicate_work();
  test_forward_heredoc_expansions();
  test_malformed_heredoc_expansions();
  test_forward_declarations_and_substrings();
  test_forward_nested_substitutions();
  test_forward_arithmetic_validation();
  test_quoted_arithmetic_boundaries();
  test_nested_expansion_features();
  test_word_expansion_recognition();
  test_fragment_content_boundaries();
  test_forward_brace_context();
  test_forward_word_scanners();
  test_backtick_escape_scan_contract();
  test_complete_word_semantic_work();
  test_source_helper_boundaries();
  test_diagnostic_source_boundary();
  test_complete_source_before_capacity();
  test_document_prefix_boundaries();
  test_document_execution_stages();
  test_raw_token_classification();
  test_abstraction_shapes();
  test_abstraction_expansion();
  test_path_categories();
  test_canonical_sequences();
  test_netstring_error_boundaries();
  test_production_source_scanner_contract();
  test_substitution_metadata_agreement();
  test_production_record_parser_contract();
  test_compound_record_boundaries();
  test_processed_command_conveniences();
  test_production_processor_routing_contract();
  test_production_fd_target_contract();
  test_modern_shell_syntax_boundaries();
  test_full_tokenizer_structural_matrix();
  test_transform_api();
  test_processor_modifier_feature_agreement();
  test_pipeline_prefix_record_boundaries();
  return failures == 0 ? 0 : 1;
}
