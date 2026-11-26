/* Word semantics: the processing of words and commands into their abstract
 * form, public word resolution and the semantic production of whole sources. */
#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L
#include "../src/shell_builtin_internal.h"
#include "../src/shell_processor_internal.h"
#include "../src/shell_semantics_internal.h"
#include "../src/shell_source_internal.h"
#include "../src/shell_tokenizer_full_internal.h"
#include "../src/shell_word_internal.h"
#include "depgraph_invariants.h"
#include "depgraph_test_workspace.h"
#include "graph_fixture.h"
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
#include "test_allocator.h"
#include "word_expansion_cases.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* --- semantics (from production_semantics_test.c) --- */
static int semantics_failures;

typedef struct {
  unsigned char bytes[64];
  size_t length;
  size_t stop_after;
} semantics_source_capture_t;

static bool semantics_capture_decoded_byte(unsigned char byte, size_t offset,
                                           void *context) {
  semantics_source_capture_t *capture = context;
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
      semantics_failures++;                                                    \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

static void semantics_test_source_scratch_array_reservations(void) {
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

static void semantics_test_owned_conditional_workspace(void) {
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

static void semantics_test_logical_comment_boundaries(void) {
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

static void semantics_test_builtin_option_semantics(void) {
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
      bool unmodeled = shellsplit_test_builtin_options[i].unmodeled;
      shell_dep_error_t expected = unmodeled   ? SHELL_DEP_EUNMODELED
                                   : supported ? SHELL_DEP_OK
                                               : SHELL_DEP_EPARSE;
      if (graph_status != expected)
        fprintf(stderr,
                "builtin option graph classification mismatch: %s "
                "status=%d expected=%d\n",
                source, graph_status, expected);
      CHECK(graph_status == expected);
      if (expected == SHELL_DEP_OK)
        CHECK(shell_dep_graph_validate(&graph).valid);
      else
        CHECK(graph.node_count == 0 && graph.edge_count == 0);
      shell_netstring_buffer_t sequence = {0};
      size_t count = 0;
      bool features = false;
      /* A stage of only assignments and a redirect does real I/O without
       * argv, so netargv rejects it as it does a bare redirect, unless a
       * command substitution nests it outside the immediate list. */
      bool redirect_only = strstr(source, "OPTIND='fd=2' >/dev/null") != NULL &&
                           strchr(contexts[c].prefix, '$') == NULL;
      CHECK(shell_build_netargv_sequence_buffer(source, (size_t)length, NULL,
                                                &sequence, &count, &features) ==
            (syntax_supported && !redirect_only ? SHELL_PROCESS_OK
                                                : SHELL_PROCESS_EPARSE));
      if (!syntax_supported || redirect_only)
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

static void semantics_test_raw_token_classification(void) {
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
      semantics_failures++;
    }
  }
}

static shell_abstract_command_t *semantics_parse_abstract(const char *source) {
  shell_abstract_command_t *command = NULL;
  CHECK(shell_abstract_command_parse(source, strlen(source), &command) ==
        SHELL_ABSTRACT_OK);
  return command;
}

/* Positional and special parameters are shell state, supplied by callback. */
static bool semantics_abstraction_parameter(shell_abstract_type_t type,
                                            const char *name, void *context,
                                            const char **value,
                                            size_t *value_length) {
  (void)context;
  if (type == SHELL_ABSTRACT_PV && strcmp(name, "1") == 0) {
    *value = "first";
  } else if (type == SHELL_ABSTRACT_SV && strcmp(name, "?") == 0) {
    *value = "status";
  } else {
    return false;
  }
  *value_length = strlen(*value);
  return true;
}

static void semantics_test_abstraction_expansion(void) {
  static const char *const environment[] = {"HOME=/home/test", "USER=alice",
                                            NULL};
  const shell_runtime_context_t context = {.env = environment,
                                           .cwd = "/workspace",
                                           .resolve_symlinks = false,
                                           .parameters =
                                               semantics_abstraction_parameter};
  shell_abstract_command_t *command = semantics_parse_abstract(
      "printf \"$USER\" ~/child ~other ./relative /absolute $1 $?");
  /* `~other` names another user's home, which the context cannot supply:
   * the command is incomplete, and every other element still resolves. */
  CHECK(command && !shell_abstract_command_expand(command, &context));
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
      saw_other_home = element->expanded == NULL;
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

  shell_abstract_command_t *resolvable =
      semantics_parse_abstract("printf /tmp");
  const shell_runtime_context_t resolve_context = {
      .env = environment, .cwd = "/workspace/", .resolve_symlinks = true};
  CHECK(resolvable &&
        shell_abstract_command_expand(resolvable, &resolve_context));
  shell_abstract_command_free(resolvable);
}

static void semantics_test_canonical_sequences(void) {
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

/* Leading assignments change the command's environment but are not argv:
 * argv[0] is the executable, and the assignments are reported as a shell
 * feature instead of being rendered as words. */
static void semantics_test_assignment_prefix_is_not_argv(void) {
  static const struct {
    const char *source;
    shell_process_status_t status;
    const char *netargv; /* NUL-free expected sequence, if status is OK */
    size_t count;
    bool features;
  } cases[] = {
      {"x=1 echo hi", SHELL_PROCESS_OK, "12:4:echo,2:hi,,", 1, true},
      {"FOO=1 BAR+=2 ls -l", SHELL_PROCESS_OK, "10:2:ls,2:-l,,", 1, true},
      {"x=$(echo a) echo b", SHELL_PROCESS_OK, "11:4:echo,1:b,,", 1, true},
      {"x='a b' y=\"$z\" cmd", SHELL_PROCESS_OK, "6:3:cmd,,", 1, true},
      /* Only leading words are assignments. */
      {"echo x=1", SHELL_PROCESS_OK, "13:4:echo,3:x=1,,", 1, false},
      {"env x=1 echo", SHELL_PROCESS_OK, "19:3:env,3:x=1,4:echo,,", 1, false},
      {"\"x\"=1 echo", SHELL_PROCESS_OK, "13:3:x=1,4:echo,,", 1, false},
      /* A stage of only assignments runs nothing: no record, but flagged. */
      {"x=1", SHELL_PROCESS_OK, "", 0, true},
      {"x=1 y=2", SHELL_PROCESS_OK, "", 0, true},
      {"PATH=/tmp/x; ls", SHELL_PROCESS_OK, "5:2:ls,,", 1, true},
      {"x=1 & ls", SHELL_PROCESS_OK, "5:2:ls,,", 1, true},
      /* Assignment plus a redirect or pipe is real I/O without argv. */
      {"x=1 >f", SHELL_PROCESS_EPARSE, NULL, 0, false},
      {"x=1 | cat", SHELL_PROCESS_EPARSE, NULL, 0, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_netstring_buffer_t sequence = {0};
    size_t count = 0;
    bool features = false;
    shell_process_status_t status = shell_build_netargv_sequence_buffer(
        cases[i].source, strlen(cases[i].source), NULL, &sequence, &count,
        &features);
    if (status != cases[i].status)
      fprintf(stderr, "assignment prefix: %s status=%d\n", cases[i].source,
              status);
    CHECK(status == cases[i].status);
    if (status == SHELL_PROCESS_OK) {
      size_t expected = strlen(cases[i].netargv);
      if (sequence.length != expected ||
          (expected && memcmp(sequence.data, cases[i].netargv, expected) != 0))
        fprintf(stderr, "assignment prefix: %s rendered %.*s\n",
                cases[i].source, (int)sequence.length,
                (const char *)sequence.data);
      CHECK(sequence.length == expected &&
            (expected == 0 ||
             memcmp(sequence.data, cases[i].netargv, expected) == 0));
      CHECK(count == cases[i].count && features == cases[i].features);
    }
    shell_netstring_buffer_free(&sequence);
  }

  /* The per-command record keeps every word and says how many lead. */
  shell_processed_commands_t processed = {0};
  static const char source[] = "A=1 B=2 ls -l";
  CHECK(shell_process_commands(source, strlen(source), NULL, &processed) ==
        SHELL_PROCESS_OK);
  CHECK(processed.command_count == 1);
  const shell_command_info_t *info = &processed.commands[0];
  CHECK(info->command_token_count == 4 && info->assignment_prefix_count == 2);
  CHECK(shell_command_info_has_dangerous_features(info));
  shell_netstring_buffer_t rendered = {0};
  CHECK(shell_render_netargv_buffer(info, NULL, &rendered) == SHELL_PROCESS_OK);
  CHECK(rendered.length == strlen("2:ls,2:-l,") &&
        memcmp(rendered.data, "2:ls,2:-l,", rendered.length) == 0);
  shell_netstring_buffer_free(&rendered);
  shell_processed_commands_free(&processed);
  static const char plain[] = "echo A=1";
  CHECK(shell_process_commands(plain, strlen(plain), NULL, &processed) ==
        SHELL_PROCESS_OK);
  CHECK(processed.commands[0].assignment_prefix_count == 0 &&
        !shell_command_info_has_dangerous_features(&processed.commands[0]));
  shell_processed_commands_free(&processed);

  /* Anomaly sequences name the executable too, and keep an assignment-only
   * stage as an explicit stage with the empty sentinel. */
  shell_netstring_buffer_t raw = {0}, type = {0};
  size_t count = 0;
  static const char anomaly[] = "FOO=1 ls; x=2";
  CHECK(shell_build_anomaly_netseqs_buffer(anomaly, strlen(anomaly), NULL, &raw,
                                           &type, &count) == SHELL_PROCESS_OK);
  CHECK(count == 2 && raw.length == strlen("2:ls,0:,") &&
        memcmp(raw.data, "2:ls,0:,", raw.length) == 0);
  shell_netstring_buffer_free(&raw);
  shell_netstring_buffer_free(&type);
}

static void semantics_test_netstring_error_boundaries(void) {
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

/* Producer-owned compound tails belong to the final body record, whereas a
 * redirect-only command after a list boundary owns a real execution stage.
 * Exercise actual records, never synthetic out-of-span marker objects. This
 * suite runs against both the test-instrumented and shipping implementations.
 */
static void semantics_test_compound_record_boundaries(void) {
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

static void semantics_test_processed_command_conveniences(void) {
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
  semantics_source_capture_t decoded = {.stop_after = 2};
  size_t decoded_length = SIZE_MAX;
  CHECK(shell_visit_decoded_word("$'a\\0b'", strlen("$'a\\0b'"),
                                 semantics_capture_decoded_byte, &decoded,
                                 &decoded_length) == SHELL_PROCESS_OK &&
        decoded_length == 2 && decoded.length == 2 && decoded.bytes[0] == 'a' &&
        decoded.bytes[1] == '\0');
  decoded = (semantics_source_capture_t){.stop_after = 2};
  decoded_length = SIZE_MAX;
  CHECK(shell_visit_decoded_word("a\\ bc", strlen("a\\ bc"),
                                 semantics_capture_decoded_byte, &decoded,
                                 &decoded_length) == SHELL_PROCESS_OK &&
        decoded_length == 2 && decoded.length == 2 && decoded.bytes[0] == 'a' &&
        decoded.bytes[1] == ' ');
  /* Bash treats a word ending inside a quote as a syntax error, so it has no
   * value; a final unquoted backslash is a literal byte. A visitor that
   * stops before the end never reaches the open quote. */
  static const char *const open_quote_words[] = {"'open", "\"open", "a'b\"c",
                                                 "\"open\\"};
  for (size_t i = 0; i < sizeof(open_quote_words) / sizeof(open_quote_words[0]);
       ++i) {
    size_t measured = 0;
    CHECK(shell_measure_decoded_word(open_quote_words[i],
                                     strlen(open_quote_words[i]),
                                     &measured) == SHELL_PROCESS_EPARSE);
    CHECK(shell_process_measure_word_value(open_quote_words[i],
                                           strlen(open_quote_words[i]),
                                           &measured) == SHELL_PROCESS_EPARSE);
    CHECK(shell_measure_processed_word(open_quote_words[i],
                                       strlen(open_quote_words[i]),
                                       &measured) == SHELL_PROCESS_EPARSE);
  }
  decoded = (semantics_source_capture_t){.stop_after = 1};
  decoded_length = SIZE_MAX;
  CHECK(shell_visit_decoded_word("'open", strlen("'open"),
                                 semantics_capture_decoded_byte, &decoded,
                                 &decoded_length) == SHELL_PROCESS_OK &&
        decoded_length == 1 && decoded.bytes[0] == 'o');
  decoded_length = SIZE_MAX;
  CHECK(shell_measure_decoded_word("abc\\", 4, &decoded_length) ==
            SHELL_PROCESS_OK &&
        decoded_length == 4);

  static const char *const control_words[] = {"$'\\c\\\\X'", "$'\\c\\'X'"};
  for (size_t i = 0; i < sizeof(control_words) / sizeof(control_words[0]);
       ++i) {
    decoded = (semantics_source_capture_t){.stop_after = 1};
    decoded_length = SIZE_MAX;
    CHECK(shell_visit_decoded_word(control_words[i], strlen(control_words[i]),
                                   semantics_capture_decoded_byte, &decoded,
                                   &decoded_length) == SHELL_PROCESS_OK &&
          decoded_length == 1 && decoded.length == 1 &&
          decoded.bytes[0] == 0x1c);
  }

  /* Semantic word projection leaves expansion unevaluated, but it can change
   * its spelling. Exact syntax remains in the caller's source span. */
  {
    static const char source[] = "${v:-$'a\\0b'}";
    static const char expected[] = "${v:-a}";
    semantics_source_capture_t projection = {0};
    size_t visited = SIZE_MAX, measured = SIZE_MAX, filled = SIZE_MAX;
    char bytes[sizeof(expected) - 1];
    CHECK(shell_process_visit_word_value(
              source, sizeof(source) - 1, semantics_capture_decoded_byte,
              &projection, &visited) == SHELL_PROCESS_OK &&
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

/* Descriptor targets are classified after Bash word decoding. Exercise the
 * shipping library's direct, group-owned, and graph-facing paths together so
 * leading zeroes, quoted values, legacy combined output, and overflow cannot
 * drift into different interpretations. */
static void semantics_test_production_fd_target_contract(void) {
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
static void semantics_test_modern_shell_syntax_boundaries(void) {
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

    /* A refused source stays refused wherever a command may start, including
     * after a keyword that follows a compound command directly. */
    static const char *const command_positions[] = {
        "if :; then ",
        "if { :; } then ",
        "if [[ 1 ]] then ",
        "if :; then :; elif (( 1 )) then ",
        "if :; then { :; } else ",
    };
    for (size_t position = 0;
         position < sizeof(command_positions) / sizeof(command_positions[0]);
         position++) {
      char embedded[512];
      int written = snprintf(embedded, sizeof(embedded), "%s%s\nfi",
                             command_positions[position], input);
      shell_processed_commands_t nested = {0};
      bool refused = written > 0 && (size_t)written < sizeof(embedded) &&
                     shell_process_commands(embedded, (size_t)written, NULL,
                                            &nested) == SHELL_PROCESS_EPARSE;
      if (!refused)
        fprintf(stderr, "accepted after a command position: %s\n", embedded);
      CHECK(refused);
      shell_processed_commands_free(&nested);
    }
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

static void semantics_test_processor_modifier_feature_agreement(void) {
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

static void semantics_test_pipeline_prefix_record_boundaries(void) {
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

static void semantics_test_document_prefix_boundaries(void) {
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

static void semantics_check_byte_validation_work(size_t passes, size_t bytes) {
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

static void semantics_reset_byte_validation_work(void) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  shellsplit_test_source_scan_reset();
#endif
}

static void semantics_test_single_byte_validation_boundary(void) {
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
      semantics_reset_byte_validation_work();
      for (unsigned repeat = 1; repeat <= 2; repeat++) {
        shell_parse_result_t parsed;
        CHECK(shell_parse_fast(source, length, &limits, &parsed) == SHELL_OK);
        CHECK(parsed.status == SHELL_STATUS_OK && parsed.count != 0);
        semantics_check_byte_validation_work(repeat, repeat * length);
      }
    }
    semantics_reset_byte_validation_work();
    CHECK(shell_tokenizer_complete_syntax_valid(source, length));
    semantics_check_byte_validation_work(1, length);
    semantics_reset_byte_validation_work();
    CHECK(shell_tokenizer_list_syntax_valid(source, length));
    semantics_check_byte_validation_work(1, length);
  }

  /* The root guarantee belongs only to contained immutable source spans.
   * An unrelated iterator within that operation still validates its bytes. */
  const char root[] = "printf \"$(printf nested)\"";
  const char unrelated[] = "printf unrelated";
  const char invalid[] = {'x', '\x01'};
  semantics_reset_byte_validation_work();
  shell_source_operation_begin(root, sizeof(root) - 1);
  CHECK(shell_tokenizer_complete_syntax_valid(root, sizeof(root) - 1));
  shell_tokenizer_state_t state;
  CHECK(shell_tokenizer_init(&state, root + 10, 13, NULL));
  semantics_check_byte_validation_work(1, sizeof(root) - 1);
  CHECK(shell_tokenizer_init(&state, unrelated, sizeof(unrelated) - 1, NULL));
  semantics_check_byte_validation_work(2, sizeof(root) + sizeof(unrelated) - 2);
  CHECK(!shell_tokenizer_init(&state, invalid, sizeof(invalid), NULL));
  semantics_check_byte_validation_work(3, sizeof(root) + sizeof(unrelated));
  shell_source_operation_end();

  /* Empty byte spans remain meaningful at the lexical boundary. */
  semantics_reset_byte_validation_work();
  CHECK(shell_tokenizer_init(&state, NULL, 0, NULL));
  semantics_check_byte_validation_work(1, 0);

  char source[16384];
  size_t length = 0;
  CHECK(shellsplit_test_source_with_tail(source, sizeof(source),
                                         SHELL_MAX_SUBCOMMANDS + 1,
                                         "printf tail", &length));
  for (unsigned strict = 0; strict < 2; strict++) {
    shell_limits_t limits = {.max_subcommands = 1, .strict_mode = strict != 0};
    shell_parse_result_t parsed;
    semantics_reset_byte_validation_work();
    CHECK(shell_parse_fast(source, length, &limits, &parsed) == SHELL_ETRUNC);
    CHECK(parsed.count == 1 && parsed.status == SHELL_STATUS_TRUNCATED);
    semantics_check_byte_validation_work(1, length);
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
        semantics_reset_byte_validation_work();
        bool literal_data = tails[i].literal_data && bytes[b] >= 128;
        CHECK(shell_parse_fast(source, length, &limits, &parsed) ==
              (literal_data ? SHELL_ETRUNC : SHELL_EPARSE));
        if (!literal_data)
          CHECK(!parsed.count && !parsed.group_count &&
                parsed.status == SHELL_STATUS_ERROR);
        /* NUL is inadmissible representation. Other byte restrictions scan
         * the complete span so a later NUL cannot become mere unsupported
         * input; this remains one linear boundary pass. */
        semantics_check_byte_validation_work(
            1, bytes[b] == 0 ? invalid_position + 1 : length);
      }
    }
    source[invalid_position] = saved;
  }
}

/* Exercise both transport forms through the same semantic boundary. Buffers
 * start empty; C-string results are adopted here only for test comparison. */
static shell_process_status_t semantics_build_limited_sequences(
    unsigned operation, bool cstring, const char *source,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *first,
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

static void semantics_test_sequence_encoded_byte_limits(void) {
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
      shell_process_status_t status = semantics_build_limited_sequences(
          operation, false, sources[s].source, NULL, &expected,
          &expected_second, &expected_count);
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
          CHECK(semantics_build_limited_sequences(
                    operation, transport != 0, sources[s].source, &limits,
                    &first, &second, &count) == SHELL_PROCESS_OK);
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
          CHECK(semantics_build_limited_sequences(
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

static void semantics_test_anomaly_cumulative_group_budget(void) {
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
          shell_process_status_t status = semantics_build_limited_sequences(
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
  CHECK(semantics_build_limited_sequences(0, false, cases[0].source, &limits,
                                          &first, &second,
                                          &count) == SHELL_PROCESS_OK);
  CHECK(count == 1);
  shell_netstring_buffer_free(&first);
  shell_processed_commands_t processed = {0};
  CHECK(shell_process_commands(cases[0].source, strlen(cases[0].source),
                               &limits, &processed) == SHELL_PROCESS_OK);
  CHECK(processed.command_count == 1 && processed.group_io_op_count == 0);
  shell_processed_commands_free(&processed);
}

static void semantics_test_complete_source_before_capacity(void) {
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

static void semantics_test_forward_word_scanners(void) {
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

static void semantics_test_quoted_arithmetic_boundaries(void) {
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

/* Diagnostic parsing retains its deliberately tolerant quote/subshell forms;
 * that must never relax the complete-source boundary used by semantic APIs.
 * All inputs here are external source, not edited internal parse objects. */
static void semantics_test_diagnostic_source_boundary(void) {
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

static void semantics_test_scoped_heredoc_expansions(void) {
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

static void semantics_test_forward_declarations_and_substrings(void) {
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

static void semantics_test_lexical_index_lifetime(void) {
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

static void semantics_test_fast_range_escaped_space_boundaries(void) {
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

static void semantics_test_processor_heredoc_work(void) {
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

static int run_semantics(int argc, char **argv) {
  (void)argc;
  (void)argv;
  semantics_test_source_scratch_array_reservations();
  semantics_test_owned_conditional_workspace();
  semantics_test_logical_comment_boundaries();
  semantics_test_builtin_option_semantics();
  semantics_test_assignment_prefix_is_not_argv();
  semantics_test_fast_range_escaped_space_boundaries();
  semantics_test_processor_heredoc_work();
  semantics_test_sequence_encoded_byte_limits();
  semantics_test_anomaly_cumulative_group_budget();
  semantics_test_single_byte_validation_boundary();
  semantics_test_lexical_index_lifetime();
  semantics_test_scoped_heredoc_expansions();
  semantics_test_forward_declarations_and_substrings();
  semantics_test_quoted_arithmetic_boundaries();
  semantics_test_forward_word_scanners();
  semantics_test_diagnostic_source_boundary();
  semantics_test_complete_source_before_capacity();
  semantics_test_document_prefix_boundaries();
  semantics_test_raw_token_classification();
  semantics_test_abstraction_expansion();
  semantics_test_canonical_sequences();
  semantics_test_netstring_error_boundaries();
  semantics_test_compound_record_boundaries();
  semantics_test_processed_command_conveniences();
  semantics_test_production_fd_target_contract();
  semantics_test_modern_shell_syntax_boundaries();
  semantics_test_processor_modifier_feature_agreement();
  semantics_test_pipeline_prefix_record_boundaries();
  return semantics_failures == 0 ? 0 : 1;
}
#undef CHECK

/* The abstract form's allocation-failure checks use the test library's fault
 * injection, which the production variant does not link. */
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
/* --- abstract (from abstract_test.c) --- */
static int abstract_passed;
static int abstract_failed;

static shell_abstract_command_t *abstract_parse_command(const char *input) {
  shell_abstract_command_t *command = NULL;
  return input && shell_abstract_command_parse(input, strlen(input),
                                               &command) == SHELL_ABSTRACT_OK
             ? command
             : NULL;
}

#define TEST(name, condition)                                                  \
  do {                                                                         \
    if (condition) {                                                           \
      printf("  [PASS] %s\n", name);                                           \
      abstract_passed++;                                                       \
    } else {                                                                   \
      printf("  [FAIL] %s\n", name);                                           \
      abstract_failed++;                                                       \
    }                                                                          \
  } while (0)

/* A final lone backslash is a literal word of a complete source, also as a
 * redirect operand. Its word ends at the end of input; abstraction must not
 * scan past it. The sources are copied without a terminator so that a read
 * beyond the span is caught under sanitizers. */
static void abstract_test_final_backslash_redirect_operand(void) {
  static const char *const sources[] = {"<\\", "cat <\\", "cat >\\"};
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(sources) / sizeof(sources[0]); i++) {
    size_t length = strlen(sources[i]);
    char *copy = malloc(length);
    valid = copy != NULL;
    if (!valid)
      break;
    memcpy(copy, sources[i], length);
    shell_abstract_command_t *result = NULL;
    valid = shell_abstract_command_parse(copy, length, &result) ==
                SHELL_ABSTRACT_OK &&
            result != NULL;
    shell_abstract_command_free(result);
    free(copy);
  }
  TEST("A final backslash redirect operand ends at the end of input", valid);
}

static void abstract_test_compound_variable_quote_boundaries(void) {
  static const struct {
    const char *source;
    const char *display;
    size_t element_count;
    bool has_ansi_c_string;
  } cases[] = {
      {"printf prefix'$literal'${NAME}", "printf prefix'$literal'$EV_1", 1,
       false},
      {"printf prefix$'don\\'t $literal'${NAME}", "printf prefix$STR_1$EV_1", 2,
       true},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_abstract_command_t *result = abstract_parse_command(cases[i].source);
    size_t count = 0;
    const shell_abstract_element_t *const *elements =
        result ? shell_abstract_command_get_elements(result, &count) : NULL;
    valid = result && strcmp(result->display_text, cases[i].display) == 0 &&
            count == cases[i].element_count && elements != NULL &&
            elements[count - 1] != NULL &&
            elements[count - 1]->type == SHELL_ABSTRACT_EV &&
            strcmp(elements[count - 1]->original, "${NAME}") == 0 &&
            elements[count - 1]->data.var.name != NULL &&
            strcmp(elements[count - 1]->data.var.name, "NAME") == 0 &&
            result->has_strings == cases[i].has_ansi_c_string &&
            (!cases[i].has_ansi_c_string ||
             (elements[0] && elements[0]->type == SHELL_ABSTRACT_STR &&
              strcmp(elements[0]->original, "$'don\\'t $literal'") == 0));
    shell_abstract_command_free(result);
  }
  TEST("compound variables preserve quoted and ANSI-C literal boundaries",
       valid);

  static const char *const string_words[] = {
      "prefix$'literal'",
      "prefix$'don\\'t $literal'",
      "prefix$\\\n'literal'",
  };
  valid = true;
  for (size_t i = 0;
       valid && i < sizeof(string_words) / sizeof(string_words[0]); i++) {
    char source[128];
    int length = snprintf(source, sizeof(source), "printf %s", string_words[i]);
    shell_abstract_command_t *result = abstract_parse_command(source);
    size_t count = 0;
    const shell_abstract_element_t *const *elements =
        result ? shell_abstract_command_get_elements(result, &count) : NULL;
    valid = length > 0 && (size_t)length < sizeof(source) && result &&
            strcmp(result->display_text, "printf prefix$STR_1") == 0 &&
            result->has_strings && !result->has_variables && count == 1 &&
            elements && elements[0] &&
            elements[0]->type == SHELL_ABSTRACT_STR &&
            strcmp(elements[0]->original, string_words[i] + 6) == 0 &&
            strcmp(elements[0]->data.cmd_subst.content,
                   i == 1 ? "don\\'t $literal" : "literal") == 0;
    shell_abstract_command_free(result);
  }
  TEST("composite ANSI-C strings retain source and payload metadata", valid);

  shell_abstract_command_t *continued =
      abstract_parse_command("printf ${NA\\\nME}");
  size_t count = 0;
  const shell_abstract_element_t *const *elements =
      continued ? shell_abstract_command_get_elements(continued, &count) : NULL;
  valid = continued && elements && count == 1 && elements[0] &&
          elements[0]->type == SHELL_ABSTRACT_EV &&
          strcmp(continued->display_text, "printf $EV_1") == 0 &&
          strcmp(elements[0]->original, "${NA\\\nME}") == 0 &&
          elements[0]->data.var.name &&
          strcmp(elements[0]->data.var.name, "NAME") == 0;
  shell_abstract_command_free(continued);
  TEST("continued static variable names retain canonical metadata", valid);
}

static void abstract_test_parameter_expansion_metadata(void) {
  static const struct {
    const char *source;
    shell_abstract_type_t type;
    const char *name;
  } cases[] = {
      {"printf ${VALUE:-fallback}", SHELL_ABSTRACT_EV, "VALUE"},
      {"printf ${VALUE#prefix}", SHELL_ABSTRACT_EV, "VALUE"},
      {"printf ${VALUE%%suffix}", SHELL_ABSTRACT_EV, "VALUE"},
      {"printf ${#VALUE}", SHELL_ABSTRACT_EV, "VALUE"},
      {"printf ${10}", SHELL_ABSTRACT_PV, "10"},
      {"printf ${?}", SHELL_ABSTRACT_SV, "?"},
      {"printf ${#}", SHELL_ABSTRACT_SV, "#"},
      {"printf ${!}", SHELL_ABSTRACT_SV, "!"},
      {"printf $\\\n{#}", SHELL_ABSTRACT_SV, "#"},
      {"printf $\\\n{!}", SHELL_ABSTRACT_SV, "!"},
      {"printf \"$\\\n{#}\"", SHELL_ABSTRACT_SV, "#"},
      {"printf ${#?}", SHELL_ABSTRACT_SV, "?"},
      {"printf ${!prefix*}", SHELL_ABSTRACT_EV, NULL},
      {"printf ${!prefix@}", SHELL_ABSTRACT_EV, NULL},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_abstract_command_t *result = abstract_parse_command(cases[i].source);
    size_t count = 0;
    const shell_abstract_element_t *const *elements =
        result ? shell_abstract_command_get_elements(result, &count) : NULL;
    valid = result && count == 1 && elements && elements[0] &&
            elements[0]->type == cases[i].type &&
            elements[0]->data.var.is_braced &&
            ((cases[i].name == NULL && elements[0]->data.var.name == NULL) ||
             (cases[i].name != NULL && elements[0]->data.var.name != NULL &&
              strcmp(elements[0]->data.var.name, cases[i].name) == 0));
    shell_abstract_command_free(result);
  }
  TEST("parameter expansion metadata names only static parameters", valid);
  static const char *const indirect[] = {"printf ${!name}", "printf ${!1}"};
  for (size_t i = 0; i < sizeof(indirect) / sizeof(indirect[0]); i++) {
    shell_abstract_command_t *result = NULL;
    valid &= shell_abstract_command_parse(indirect[i], strlen(indirect[i]),
                                          &result) == SHELL_ABSTRACT_EPARSE &&
             result == NULL;
    shell_abstract_command_free(result);
  }
  TEST("indirect expansions reject unmodeled value re-evaluation", valid);
}

enum {
  abstract_FLAG_VARIABLES = 1u << 0,
  abstract_FLAG_POS_VARS = 1u << 1,
  abstract_FLAG_SPECIAL_VARS = 1u << 2,
  abstract_FLAG_GLOBS = 1u << 3,
  abstract_FLAG_PATHS = 1u << 4,
  abstract_FLAG_ABS_PATHS = 1u << 5,
  abstract_FLAG_REL_PATHS = 1u << 6,
  abstract_FLAG_HOME_PATHS = 1u << 7,
  abstract_FLAG_CMD_SUBST = 1u << 8,
  abstract_FLAG_ARITHMETIC = 1u << 9,
  abstract_FLAG_STRINGS = 1u << 10,
  abstract_FLAG_REDIRECTS = 1u << 11,
};

static unsigned abstract_feature_mask(shell_abstract_command_t *command) {
  return (command->has_variables ? abstract_FLAG_VARIABLES : 0) |
         (command->has_pos_vars ? abstract_FLAG_POS_VARS : 0) |
         (command->has_special_vars ? abstract_FLAG_SPECIAL_VARS : 0) |
         (command->has_globs ? abstract_FLAG_GLOBS : 0) |
         (command->has_paths ? abstract_FLAG_PATHS : 0) |
         (command->has_abs_paths ? abstract_FLAG_ABS_PATHS : 0) |
         (command->has_rel_paths ? abstract_FLAG_REL_PATHS : 0) |
         (command->has_home_paths ? abstract_FLAG_HOME_PATHS : 0) |
         (command->has_cmd_subst ? abstract_FLAG_CMD_SUBST : 0) |
         (command->has_arithmetic ? abstract_FLAG_ARITHMETIC : 0) |
         (command->has_strings ? abstract_FLAG_STRINGS : 0) |
         (command->has_redirects ? abstract_FLAG_REDIRECTS : 0);
}

static bool abstract_validate_elements(const char *input,
                                       shell_abstract_command_t *result) {
  size_t count = 0;
  const shell_abstract_element_t *const *elements =
      shell_abstract_command_get_elements(result, &count);
  size_t mutable_count = 0;
  shell_abstract_element_t *const *mutable_elements =
      shell_abstract_command_get_mutable_elements(result, &mutable_count);
  bool valid =
      count == result->element_count &&
      elements == (const shell_abstract_element_t *const *)result->elements &&
      mutable_count == count && mutable_elements == result->elements &&
      shell_abstract_command_get_element(result, count) == NULL;
  size_t input_len = strlen(input);

  for (size_t i = 0; valid && i < count; i++) {
    const shell_abstract_element_t *element = elements[i];
    valid =
        element && element == shell_abstract_command_get_element(result, i) &&
        element ==
            shell_abstract_command_find_element(result, element->abstraction) &&
        element->start < element->end && element->end <= input_len &&
        strlen(element->original) == element->end - element->start &&
        memcmp(element->original, input + element->start,
               element->end - element->start) == 0 &&
        (i == 0 || elements[i - 1]->start <= element->start);
  }
  return valid;
}

static void abstract_test_abstraction_matrix(void) {
  printf("\n=== Exact Abstraction Matrix ===\n");

  static const struct {
    const char *name;
    const char *input;
    const char *expected;
    size_t elements;
    unsigned flags;
  } cases[] = {
      {"literal command", "ls -la", "ls -la", 0, 0},
      {"environment variable", "echo $PATH", "echo $EV_1", 1,
       abstract_FLAG_VARIABLES},
      {"absolute path", "cat /etc/passwd", "cat $AP_1", 1,
       abstract_FLAG_PATHS | abstract_FLAG_ABS_PATHS},
      {"relative path", "cat ./foo.txt", "cat $RP_1", 1,
       abstract_FLAG_PATHS | abstract_FLAG_REL_PATHS},
      {"parent-relative path", "cat ../foo.txt", "cat $RP_1", 1,
       abstract_FLAG_PATHS | abstract_FLAG_REL_PATHS},
      {"home path", "ls ~/documents", "ls $HP_1", 1,
       abstract_FLAG_PATHS | abstract_FLAG_HOME_PATHS},
      {"glob", "ls *.txt", "ls $GB_1", 1, abstract_FLAG_GLOBS},
      {"positional parameter boundaries", "echo $1 $10 ${10}",
       "echo $PV_1 $PV_20 $PV_3", 3,
       abstract_FLAG_VARIABLES | abstract_FLAG_POS_VARS},
      {"special parameter family", "echo $? $$ $# $! $@ $* $-",
       "echo $SV_1 $SV_2 $SV_3 $SV_4 $SV_5 $SV_6 $SV_7", 7,
       abstract_FLAG_VARIABLES | abstract_FLAG_SPECIAL_VARS},
      {"quoted special parameter family", "printf '%s\\n' \"$- $@ $* $!\"\n",
       "printf $STR_1 \"$SV_1 $SV_2 $SV_3 $SV_4\"\n", 5,
       abstract_FLAG_VARIABLES | abstract_FLAG_SPECIAL_VARS |
           abstract_FLAG_STRINGS},
      {"timed quoted compound variables", "time printf \"$HOME $1 $?\"",
       "time printf \"$EV_1 $PV_1 $SV_1\"", 3,
       abstract_FLAG_VARIABLES | abstract_FLAG_POS_VARS |
           abstract_FLAG_SPECIAL_VARS},
      {"quoted compound path fragments", "time printf \"/a/$USER/b/$HOME/c\"",
       "time printf \"$AP_1$EV_1$AP_2$EV_2$AP_3\"", 5,
       abstract_FLAG_VARIABLES | abstract_FLAG_PATHS | abstract_FLAG_ABS_PATHS},
      {"command substitution", "cat $(cat file.txt)", "cat $CS_1", 1,
       abstract_FLAG_CMD_SUBST},
      {"backtick substitution", "echo `date`", "echo $CS_1", 1,
       abstract_FLAG_CMD_SUBST},
      {"arithmetic expansion", "echo $((1+2))", "echo $AR_1", 1,
       abstract_FLAG_ARITHMETIC},
      {"quoted string", "echo \"hello world\"", "echo $STR_1", 1,
       abstract_FLAG_STRINGS},
      {"quoted variable", "echo \"$USER\"", "echo $EV_1", 1,
       abstract_FLAG_VARIABLES},
      {"embedded quoted variable", "echo \"prefix ${NAME} suffix\"",
       "echo \"prefix $EV_1 suffix\"", 1, abstract_FLAG_VARIABLES},
      {"multiple variables", "grep $USER $HOME/file $PATH",
       "grep $EV_1 $EV_2$AP_1 $EV_3", 4,
       abstract_FLAG_VARIABLES | abstract_FLAG_PATHS | abstract_FLAG_ABS_PATHS},
      {"mixed variables and globs", "grep -i $PATTERN /etc/*.conf ~user/*.txt",
       "grep -i $EV_1 $GB_1 $GB_2", 3,
       abstract_FLAG_VARIABLES | abstract_FLAG_GLOBS},
      {"path glob", "ls /var/log/*.log", "ls $GB_1", 1, abstract_FLAG_GLOBS},
      {"find expression", "find /var -name *.log -mtime +7",
       "find $AP_1 -name $GB_1 -mtime +7", 2,
       abstract_FLAG_PATHS | abstract_FLAG_ABS_PATHS | abstract_FLAG_GLOBS},
      {"pipeline with adjacent abstractions",
       "tail -f /var/log/$APP.log | grep -i error | head -n 100",
       "tail -f $AP_1$EV_1.log | grep -i error | head -n 100", 2,
       abstract_FLAG_VARIABLES | abstract_FLAG_PATHS | abstract_FLAG_ABS_PATHS},
      {"trailing path fragments in one variable word", "printf /a/$X/b/$Y/c",
       "printf $AP_1$EV_1$AP_2$EV_2$AP_3", 5,
       abstract_FLAG_VARIABLES | abstract_FLAG_PATHS | abstract_FLAG_ABS_PATHS},
      {"compound word abstraction families",
       "printf ./$REL/tail ~/$HOME/tail arg-$1 status-$?",
       "printf $RP_1$EV_1$AP_1 $HP_1$EV_2$AP_2 arg-$PV_1 status-$SV_1", 8,
       abstract_FLAG_VARIABLES | abstract_FLAG_PATHS | abstract_FLAG_ABS_PATHS |
           abstract_FLAG_REL_PATHS | abstract_FLAG_HOME_PATHS |
           abstract_FLAG_POS_VARS | abstract_FLAG_SPECIAL_VARS},
      {"later sequence stages are abstracted",
       "echo ok && cat /etc/$FILE || diff <(left) >(right)",
       "echo ok && cat $AP_1$EV_1 || diff $CS_1 $CS_2", 4,
       abstract_FLAG_VARIABLES | abstract_FLAG_PATHS | abstract_FLAG_ABS_PATHS |
           abstract_FLAG_CMD_SUBST},
      {"redirection targets", "cat < /tmp/in >out 2>> err 2>&1",
       "cat < $RD_1 >$RD_2 2>> $RD_3 2>&1", 3, abstract_FLAG_REDIRECTS},
      {"here-string target", "cat <<< \"$VALUE\"", "cat <<< $RD_1", 1,
       abstract_FLAG_REDIRECTS},
      {"clobber redirect target", "echo x >| /tmp/clobber", "echo x >| $RD_1",
       1, abstract_FLAG_REDIRECTS},
      {"numbered clobber redirect target", "echo x 2>| /tmp/clobber",
       "echo x 2>| $RD_1", 1, abstract_FLAG_REDIRECTS},
      /* Bare >& takes a pathname as a target for stdout and stderr; a
       * descriptor, - or an explicit descriptor prefix duplicates or closes. */
      {"output duplication pathname target", "echo ok >& /tmp/out",
       "echo ok >& $RD_1", 1, abstract_FLAG_REDIRECTS},
      {"adjacent output duplication pathname", "echo ok >&/tmp/out",
       "echo ok >&$RD_1", 1, abstract_FLAG_REDIRECTS},
      {"relative output duplication pathname", "echo ok >& out",
       "echo ok >& $RD_1", 1, abstract_FLAG_REDIRECTS},
      {"spaced numeric duplication", "echo ok 2>& 1", "echo ok 2>& 1", 0,
       abstract_FLAG_REDIRECTS},
      {"spaced numeric input duplication", "cat <& 0", "cat <& 0", 0,
       abstract_FLAG_REDIRECTS},
      {"spaced close", "echo ok >& -", "echo ok >& -", 0,
       abstract_FLAG_REDIRECTS},
      {"attached close", "echo ok >&-", "echo ok >&-", 0,
       abstract_FLAG_REDIRECTS},
      {"named descriptor duplication", "echo ok {fd}>& 1", "echo ok {fd}>& 1",
       0, abstract_FLAG_REDIRECTS},
      {"descriptor move", "echo ok >&1-", "echo ok >&1-", 0,
       abstract_FLAG_REDIRECTS},
      {"explicit descriptor keeps duplication", "echo ok 2>&out",
       "echo ok 2>&out", 0, abstract_FLAG_REDIRECTS},
      {"dynamic duplication operand", "echo ok >& $FD", "echo ok >& $EV_1", 1,
       abstract_FLAG_REDIRECTS | abstract_FLAG_VARIABLES},
      /* An active tilde prefix is a home or working-directory path. Quoting
       * or an invalid prefix body leaves a literal relative path. */
      {"tilde plus path", "cat ~+/child", "cat $HP_1", 1,
       abstract_FLAG_PATHS | abstract_FLAG_HOME_PATHS},
      {"tilde minus path", "cat ~-/child", "cat $HP_1", 1,
       abstract_FLAG_PATHS | abstract_FLAG_HOME_PATHS},
      {"user home path", "cat ~root/child", "cat $HP_1", 1,
       abstract_FLAG_PATHS | abstract_FLAG_HOME_PATHS},
      {"quote-cancelled tilde is relative", "cat ~''/child", "cat $RP_1", 1,
       abstract_FLAG_PATHS | abstract_FLAG_REL_PATHS},
      {"quote-cancelled user is relative", "cat ~root''/child", "cat $RP_1", 1,
       abstract_FLAG_PATHS | abstract_FLAG_REL_PATHS},
      {"numeric tilde body is relative", "cat ~1/x", "cat $RP_1", 1,
       abstract_FLAG_PATHS | abstract_FLAG_REL_PATHS},
      {"tilde plus suffix is relative", "cat ~+x/y", "cat $RP_1", 1,
       abstract_FLAG_PATHS | abstract_FLAG_REL_PATHS},
      {"heredoc is redirection", "cat <<EOF\npayload\nEOF",
       "cat <<EOF\npayload\nEOF", 0, abstract_FLAG_REDIRECTS},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_abstract_command_t *result = abstract_parse_command(cases[i].input);
    bool ok = result != NULL;
    bool valid = ok && result &&
                 strcmp(result->original, cases[i].input) == 0 &&
                 strcmp(result->display_text, cases[i].expected) == 0 &&
                 result->element_count == cases[i].elements &&
                 abstract_feature_mask(result) == cases[i].flags &&
                 abstract_validate_elements(cases[i].input, result);
    if (!valid && result)
      printf("    got '%s', elements=%zu, flags=0x%x\n", result->display_text,
             result->element_count, abstract_feature_mask(result));
    TEST(cases[i].name, valid);
    shell_abstract_command_free(result);
  }
}

static void abstract_test_abstraction_allocation_failures(void) {
  static const char input[] =
      "echo /var/log/$APP.log ./$REL ~/$HOME arg-$1 status-$? *.txt $(date) "
      "$((1+2)) /a/$X/b ${VALUE:-$(date)} ${!prefix*} ${?} "
      "\"$OUTER$(printf '\"$INNER')$AFTER\" "
      "\"$OUTER`printf '$INNER'`$AFTER\" "
      "\"$(printf '$INNER')\" >output";
  shellsplit_test_alloc_reset();
  shell_abstract_command_t *probe = abstract_parse_command(input);
  TEST("allocation probe succeeds", probe != NULL);
  size_t allocations = shellsplit_test_alloc_count();
  TEST("allocation probe exercises multiple allocations", allocations > 4);
  shell_abstract_command_free(probe);

  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    shellsplit_test_alloc_fail_at(fail_at);
    shell_abstract_command_t *result = (shell_abstract_command_t *)(void *)1;
    shell_abstract_status_t status =
        shell_abstract_command_parse(input, strlen(input), &result);
    shellsplit_test_alloc_reset();
    TEST("abstraction allocation failure leaves no result",
         status == SHELL_ABSTRACT_ENOMEM && result == NULL);
    shell_abstract_command_free(result);
  }

  /* Complete-command validation now accepts timing prefixes and compound
   * timing scopes. Exercise the same failure-atomic allocation boundary on
   * that path rather than only on an ordinary simple command. */
  static const char *const timed_inputs[] = {
      "time { printf %s /tmp/${VALUE}; time -p printf %s ~/nested; }",
      "time ({ printf %s /tmp/${VALUE}; })",
      "time ({(printf %s ~/nested)})",
      "time printf %s ./prefix$VALUE$(time printf child)/suffix",
      "time printf %s $VALUE`printf child`/suffix",
      "time { printf %s $VALUE<(printf child)>suffix; } >report",
      "time printf '%s\\n' \"$- $@ $* $!\"",
      "time { printf \"$HOME$(printf child) $1 $?\"; }",
      "time printf prefix$'don\\'t $literal'${NAME}",
      "time printf prefix$'literal'",
      "time printf $\\\n'abc'",
      "time printf pre$\\\n'abc'$VALUE",
      "time printf \"pre$\\\n(id)$VALUE\"",
      "time printf \"$VALUE$((1 + 2))\"",
      "time printf pre$((1))$((2))$VALUE",
      "time printf $\\\n(\\\n(1 + 2)\\\n)$VALUE",
      "time printf x${VALUE:-$((1 + 2))}*",
      "time printf >x$VALUE$((1))",
  };
  bool timed_atomic = true;
  for (size_t i = 0;
       timed_atomic && i < sizeof(timed_inputs) / sizeof(timed_inputs[0]);
       i++) {
    shellsplit_test_alloc_reset();
    probe = abstract_parse_command(timed_inputs[i]);
    allocations = shellsplit_test_alloc_count();
    timed_atomic = probe != NULL && allocations > 4;
    shell_abstract_command_free(probe);
    for (size_t fail_at = 1; timed_atomic && fail_at <= allocations;
         fail_at++) {
      shellsplit_test_alloc_fail_at(fail_at);
      shell_abstract_command_t *result = NULL;
      shell_abstract_status_t timed_status = shell_abstract_command_parse(
          timed_inputs[i], strlen(timed_inputs[i]), &result);
      shellsplit_test_alloc_reset();
      timed_atomic = timed_status == SHELL_ABSTRACT_ENOMEM && result == NULL;
      if (!timed_atomic)
        fprintf(stderr,
                "timed abstraction failure: source=%s fail_at=%zu "
                "status=%d\n",
                timed_inputs[i], fail_at, timed_status);
      shell_abstract_command_free(result);
    }
  }
  shellsplit_test_alloc_reset();
  TEST("Timed command abstraction allocation failures are atomic",
       timed_atomic);

  shell_netstring_buffer_t netseq = {0};
  size_t count = 0;
  shellsplit_test_alloc_reset();
  shell_process_status_t status = shell_build_type_netseq_buffer(
      input, strlen(input), NULL, &netseq, &count);
  allocations = shellsplit_test_alloc_count();
  /* Two date substitutions and three scoped printf substitutions precede the
   * enclosing echo. Keep the allocation probe on all six execution stages. */
  TEST("type-netsequence allocation probe succeeds",
       status == SHELL_PROCESS_OK && netseq.data && count == 6);
  shell_netstring_buffer_free(&netseq);

  bool atomic = true;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    netseq = (shell_netstring_buffer_t){0};
    count = SIZE_MAX;
    shellsplit_test_alloc_fail_at(fail_at);
    status = shell_build_type_netseq_buffer(input, strlen(input), NULL, &netseq,
                                            &count);
    shellsplit_test_alloc_reset();
    if (status != SHELL_PROCESS_ENOMEM || netseq.data != NULL || count != 0) {
      atomic = false;
      shell_netstring_buffer_free(&netseq);
      break;
    }
  }
  TEST("type-netsequence allocation failures are atomic", atomic);
}

static void abstract_test_fragment_payload_metadata(void) {
  static const struct {
    const char *name;
    const char *input;
    shell_abstract_type_t type;
    const char *original;
    const char *content;
  } cases[] = {
      {"empty backtick payload", "echo ``", SHELL_ABSTRACT_CS, "``", ""},
      {"one-character backtick payload", "echo `x`", SHELL_ABSTRACT_CS, "`x`",
       "x"},
      {"empty dollar substitution payload", "echo $()", SHELL_ABSTRACT_CS,
       "$()", ""},
      {"one-character dollar substitution payload", "echo $(x)",
       SHELL_ABSTRACT_CS, "$(x)", "x"},
      {"empty process input payload", "echo <()", SHELL_ABSTRACT_CS, "<()", ""},
      {"empty process output payload", "echo >()", SHELL_ABSTRACT_CS, ">()",
       ""},
      {"one-character process payload", "echo <(x)", SHELL_ABSTRACT_CS, "<(x)",
       "x"},
      {"adjacent short substitution payload", "echo pre`x`suffix",
       SHELL_ABSTRACT_CS, "`x`", "x"},
      {"variable-adjacent short substitution payload", "echo $VALUE`x`",
       SHELL_ABSTRACT_CS, "`x`", "x"},
      {"quoted composite short substitution payload", "echo \"$VALUE`x`\"",
       SHELL_ABSTRACT_CS, "`x`", "x"},
      {"quoted composite empty substitution payload", "echo \"$VALUE$()\"",
       SHELL_ABSTRACT_CS, "$()", ""},
      {"timed short substitution payload", "time -p echo `x`",
       SHELL_ABSTRACT_CS, "`x`", "x"},
      {"timed group empty substitution payload", "time { echo $(); }",
       SHELL_ABSTRACT_CS, "$()", ""},
      {"substitution payload preserves continuations", "echo $(x\\\ny)",
       SHELL_ABSTRACT_CS, "$(x\\\ny)", "x\\\ny"},
      {"continued opener empty payload", "echo $\\\n()", SHELL_ABSTRACT_CS,
       "$\\\n()", ""},
      {"empty single-quoted payload", "echo ''", SHELL_ABSTRACT_STR, "''", ""},
      {"empty double-quoted payload", "echo \"\"", SHELL_ABSTRACT_STR, "\"\"",
       ""},
      {"empty ANSI-C payload", "echo $''", SHELL_ABSTRACT_STR, "$''", ""},
      {"composite empty ANSI-C payload", "echo pre$''$VALUE",
       SHELL_ABSTRACT_STR, "$''", ""},
      {"single-quoted payload preserves continuations", "echo '\\\n'",
       SHELL_ABSTRACT_STR, "'\\\n'", "\\\n"},
      {"double-quoted payload preserves continuations", "echo \"\\\n\"",
       SHELL_ABSTRACT_STR, "\"\\\n\"", "\\\n"},
      {"empty arithmetic payload", "echo $(())", SHELL_ABSTRACT_AR, "$(())",
       ""},
      {"composite empty arithmetic payload", "echo pre$(())$VALUE",
       SHELL_ABSTRACT_AR, "$(())", ""},
      {"arithmetic payload", "echo $((1))", SHELL_ABSTRACT_AR, "$((1))", "1"},
      {"composite arithmetic payload", "echo pre$((1))$VALUE",
       SHELL_ABSTRACT_AR, "$((1))", "1"},
  };

  bool atomic = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shellsplit_test_alloc_reset();
    shell_abstract_command_t *result = abstract_parse_command(cases[i].input);
    size_t allocations = shellsplit_test_alloc_count();
    const char *key = cases[i].type == SHELL_ABSTRACT_CS   ? "$CS_1"
                      : cases[i].type == SHELL_ABSTRACT_AR ? "$AR_1"
                                                           : "$STR_1";
    shell_abstract_element_t *element =
        result ? shell_abstract_command_find_element(result, key) : NULL;
    size_t start =
        (size_t)(strstr(cases[i].input, cases[i].original) - cases[i].input);
    bool valid =
        result && element && element->type == cases[i].type &&
        element->data.cmd_subst.content &&
        strcmp(element->data.cmd_subst.content, cases[i].content) == 0 &&
        strcmp(element->original, cases[i].original) == 0 &&
        element->start == start &&
        element->end == start + strlen(cases[i].original) &&
        abstract_validate_elements(cases[i].input, result);
    TEST(cases[i].name, valid);
    atomic = atomic && result != NULL;
    shell_abstract_command_free(result);

    for (size_t fail_at = 1; atomic && fail_at <= allocations; fail_at++) {
      shellsplit_test_alloc_fail_at(fail_at);
      result = NULL;
      shell_abstract_status_t status = shell_abstract_command_parse(
          cases[i].input, strlen(cases[i].input), &result);
      shellsplit_test_alloc_reset();
      atomic = status == SHELL_ABSTRACT_ENOMEM && result == NULL;
      if (!atomic)
        fprintf(stderr, "fragment payload allocation failure: %s at %zu\n",
                cases[i].name, fail_at);
      shell_abstract_command_free(result);
    }
  }
  shellsplit_test_alloc_reset();
  TEST("fragment payload allocation failures leave no partial result", atomic);
}

static void abstract_test_classification_matrix(void) {
  printf("\n=== Raw Token Classification Matrix ===\n");

  static const struct {
    const char *text;
    shell_token_type_t expected;
  } cases[] = {{"", SHELL_TOKEN_END},
               {"$HOME", SHELL_TOKEN_VARIABLE},
               {"${HOME}", SHELL_TOKEN_VARIABLE},
               {"$1", SHELL_TOKEN_SPECIAL_VAR},
               {"$10", SHELL_TOKEN_SPECIAL_VAR},
               {"${10}", SHELL_TOKEN_SPECIAL_VAR},
               {"$?", SHELL_TOKEN_SPECIAL_VAR},
               {"$$", SHELL_TOKEN_SPECIAL_VAR},
               {"$#", SHELL_TOKEN_SPECIAL_VAR},
               {"$!", SHELL_TOKEN_SPECIAL_VAR},
               {"$@", SHELL_TOKEN_SPECIAL_VAR},
               {"$*", SHELL_TOKEN_SPECIAL_VAR},
               {"$-", SHELL_TOKEN_SPECIAL_VAR},
               {"$!x", SHELL_TOKEN_ARGUMENT},
               {"$@x", SHELL_TOKEN_ARGUMENT},
               {"$*x", SHELL_TOKEN_ARGUMENT},
               {"$", SHELL_TOKEN_ARGUMENT},
               {"${", SHELL_TOKEN_ARGUMENT},
               {"${%word}", SHELL_TOKEN_ARGUMENT},
               {"${!}", SHELL_TOKEN_SPECIAL_VAR},
               {"${#?}", SHELL_TOKEN_SPECIAL_VAR},
               {"${!1}", SHELL_TOKEN_SPECIAL_VAR},
               {"$()", SHELL_TOKEN_SUBSHELL},
               {"$(x)", SHELL_TOKEN_SUBSHELL},
               {"$(date)", SHELL_TOKEN_SUBSHELL},
               {"``", SHELL_TOKEN_SUBSHELL},
               {"`x`", SHELL_TOKEN_SUBSHELL},
               {"`date`", SHELL_TOKEN_SUBSHELL},
               {"`", SHELL_TOKEN_ARGUMENT},
               {"$(", SHELL_TOKEN_ARGUMENT},
               {"$((1+2))", SHELL_TOKEN_ARITHMETIC},
               {"*.txt", SHELL_TOKEN_GLOB},
               {"--foo*", SHELL_TOKEN_GLOB},
               {"-x?", SHELL_TOKEN_GLOB},
               {"--[ab]", SHELL_TOKEN_GLOB},
               {"-@(left|right)", SHELL_TOKEN_GLOB},
               {"--foo\\*", SHELL_TOKEN_ARGUMENT},
               {"\"-x?\"", SHELL_TOKEN_ARGUMENT},
               {"--dir/*.txt", SHELL_TOKEN_ARGUMENT},
               {"/tmp/*.txt", SHELL_TOKEN_ARGUMENT},
               {"dir/*.txt", SHELL_TOKEN_ARGUMENT},
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
               {"\"text\"", SHELL_TOKEN_ARGUMENT},
               {"plain", SHELL_TOKEN_ARGUMENT}};

  bool valid = shell_classify_raw_token("", 0) == SHELL_TOKEN_END;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++)
    valid = shell_classify_raw_token(cases[i].text, strlen(cases[i].text)) ==
            cases[i].expected;
  TEST("all public raw-token classifications", valid);
}

static void abstract_test_path_and_name_matrices(void) {
  printf("\n=== Path and Name Matrices ===\n");

  static const struct {
    const char *path;
    shell_path_category_t category;
  } paths[] = {{"/", SHELL_PATH_ROOT},
               {"/etc/passwd", SHELL_PATH_ETC},
               {"/var/log", SHELL_PATH_VAR},
               {"/usr/bin", SHELL_PATH_USR},
               {"/home/user", SHELL_PATH_HOME},
               {"/root", SHELL_PATH_HOME},
               {"/tmp/file", SHELL_PATH_TMP},
               {"/proc/self", SHELL_PATH_PROC},
               {"/sys/kernel", SHELL_PATH_SYS},
               {"/dev/null", SHELL_PATH_DEV},
               {"/opt/app", SHELL_PATH_OPT},
               {"/srv/data", SHELL_PATH_SRV},
               {"/run/service", SHELL_PATH_RUN},
               {"/sysroot/etc", SHELL_PATH_SYSROOT},
               {"/boot/vmlinuz", SHELL_PATH_BOOT},
               {"/mnt/disk", SHELL_PATH_MNT},
               {"/media/disk", SHELL_PATH_MEDIA},
               {"/.snapshots/1", SHELL_PATH_SNAPSHOT},
               {"/etcetera", SHELL_PATH_OTHER},
               {"/runway", SHELL_PATH_OTHER},
               {"/snapshots/1", SHELL_PATH_OTHER},
               {"/unknown", SHELL_PATH_OTHER},
               {"relative", SHELL_PATH_OTHER},
               {"", SHELL_PATH_OTHER},
               {"", SHELL_PATH_OTHER}};
  static const char *abstract_names[] = {"EV", "PV", "SV", "AP",  "RP", "HP",
                                         "GB", "CS", "AR", "STR", "RD"};
  static const char *path_names[] = {
      "ROOT",    "ETC",  "VAR", "USR",   "HOME",     "TMP",
      "PROC",    "SYS",  "DEV", "OPT",   "SRV",      "RUN",
      "SYSROOT", "BOOT", "MNT", "MEDIA", "SNAPSHOT", "OTHER"};

  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(paths) / sizeof(paths[0]); i++)
    valid = shell_path_category_from_path(paths[i].path) == paths[i].category;
  TEST("all path categories and boundary forms", valid);

  valid = true;
  for (size_t i = 0;
       valid && i < sizeof(abstract_names) / sizeof(abstract_names[0]); i++)
    valid = strcmp(shell_abstract_type_name((shell_abstract_type_t)i),
                   abstract_names[i]) == 0;
  valid = valid && strcmp(shell_abstract_type_name((shell_abstract_type_t)-1),
                          "UNKNOWN") == 0;
  TEST("all abstract type names", valid);

  valid = true;
  for (size_t i = 0; valid && i < sizeof(path_names) / sizeof(path_names[0]);
       i++)
    valid = strcmp(shell_path_category_name((shell_path_category_t)i),
                   path_names[i]) == 0;
  valid = valid && strcmp(shell_path_category_name((shell_path_category_t)-1),
                          "UNKNOWN") == 0;
  TEST("all path category names", valid);
}

static void abstract_test_runtime_expansion(void) {
  printf("\n=== Runtime Expansion Matrix ===\n");

  const char *environment[] = {"HOME=/home/testuser", "USER=testuser", NULL};
  shell_runtime_context_t context = {
      .env = environment, .cwd = "/home/testuser", .resolve_symlinks = false};
  static const struct {
    const char *input;
    const char *key;
    const char *expected;
    const char *cwd;
  } cases[] = {{"echo $USER", "$EV_1", "testuser", NULL},
               {"echo \"$USER\"", "$EV_1", "testuser", NULL},
               {"echo $HOME", "$EV_1", "/home/testuser", NULL},
               {"ls ~/documents", "$HP_1", "/home/testuser/documents", NULL},
               {"ls ~", "$HP_1", "/home/testuser", NULL},
               {"cat /etc/passwd", "$AP_1", "/etc/passwd", NULL},
               {"cat ./file", "$RP_1", "/tmp/./file", "/tmp/"},
               {"echo $MISSING", "$EV_1", NULL, NULL},
               {"echo \"prefix $USER\"", "$EV_1", "testuser", NULL},
               {"echo \"literal\"", "$STR_1", NULL, NULL},
               {"echo \"${USER}\"", "$EV_1", "testuser", NULL},
               {"echo \"${USER:-safe}\"", "$EV_1", NULL, NULL},
               {"echo \"${MISSING:-safe}\"", "$EV_1", NULL, NULL},
               {"echo \"${USER:+other}\"", "$EV_1", NULL, NULL},
               {"echo \"${#USER}\"", "$EV_1", NULL, NULL},
               {"echo \"${!USER}\"", "$EV_1", NULL, NULL},
               {"echo \"${USER:1:2}\"", "$EV_1", NULL, NULL},
               {"echo \"${USER#test}\"", "$EV_1", NULL, NULL},
               {"echo \"${USER[0]}\"", "$EV_1", NULL, NULL},
               {"echo \\/etc/passwd", "$AP_1", "/etc/passwd", NULL},
               {"echo \"\"/etc/passwd", "$AP_1", "/etc/passwd", NULL},
               {"echo /tmp/hello\\ world", "$AP_1", "/tmp/hello world", NULL},
               {"echo ./a\\ b", "$RP_1", "/tmp/./a b", "/tmp/"},
               {"echo \\~/note", "$RP_1", "/tmp/~/note", "/tmp/"},
               {"echo ~", "$HP_1", "/home/testuser", NULL},
               {"echo ~/note", "$HP_1", "/home/testuser/note", NULL},
               {"echo ~root", "$HP_1", NULL, NULL},
               {"echo ~root/note", "$HP_1", NULL, NULL},
               {"echo ~nosuchuser", "$HP_1", NULL, NULL}};

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_abstract_command_t *result = abstract_parse_command(cases[i].input);
    bool valid = result != NULL;
    shell_abstract_element_t *element =
        valid ? shell_abstract_command_find_element(result, cases[i].key)
              : NULL;
    context.cwd = cases[i].cwd ? (char *)cases[i].cwd : "/home/testuser";
    char *expanded =
        element ? shell_abstract_element_expand(element, &context) : NULL;
    valid = cases[i].expected
                ? expanded && strcmp(expanded, cases[i].expected) == 0
                : expanded == NULL;
    TEST(cases[i].input, valid);
    free(expanded);
    shell_abstract_command_free(result);
  }

  context.cwd = "/home/testuser";

  context.resolve_symlinks = true;
  shell_abstract_command_t *path_result =
      abstract_parse_command("cat /tmp/../tmp");
  bool valid = path_result != NULL;
  shell_abstract_element_t *path =
      valid ? shell_abstract_command_find_element(path_result, "$AP_1") : NULL;
  char *resolved = path ? shell_abstract_element_expand(path, &context) : NULL;
  valid = valid && resolved && strcmp(resolved, "/tmp") == 0;
  TEST("path expansion optionally resolves canonical paths", valid);
  free(resolved);
  shell_abstract_command_free(path_result);
  context.resolve_symlinks = false;

  shell_abstract_command_t *result = abstract_parse_command("echo $USER $HOME");
  valid = result && shell_abstract_command_expand(result, &context);
  shell_abstract_element_t *user =
      valid ? shell_abstract_command_find_element(result, "$EV_1") : NULL;
  shell_abstract_element_t *home =
      valid ? shell_abstract_command_find_element(result, "$EV_2") : NULL;
  valid = valid && user && user->expanded && home && home->expanded &&
          strcmp(user->expanded, "testuser") == 0 &&
          strcmp(home->expanded, "/home/testuser") == 0;
  TEST("expand all elements stores every result", valid);

  const char *empty_environment[] = {NULL};
  context.env = empty_environment;
  valid = !shell_abstract_command_expand(result, &context) && user && home &&
          user->expanded == NULL && home->expanded == NULL;
  TEST("re-expansion clears stale values and reports unresolved", valid);
  shell_abstract_command_free(result);

  /* Elements without a runtime value do not make expansion incomplete. */
  context.env = environment;
  result = abstract_parse_command("echo \"literal\" *.txt $USER $(true)");
  valid = result && shell_abstract_command_expand(result, &context);
  user = valid ? shell_abstract_command_find_element(result, "$EV_1") : NULL;
  valid = valid && user && user->expanded &&
          strcmp(user->expanded, "testuser") == 0;
  for (size_t i = 0; valid && i < result->element_count; i++)
    valid = result->elements[i] == user || !result->elements[i]->expanded;
  TEST("expansion ignores elements without runtime values", valid);
  shell_abstract_command_free(result);

  /* One unresolved element reports false but keeps the resolved ones. */
  result = abstract_parse_command("echo $USER $MISSING \"${HOME:-x}\"");
  valid = result && !shell_abstract_command_expand(result, &context);
  user = valid ? shell_abstract_command_find_element(result, "$EV_1") : NULL;
  shell_abstract_element_t *missing =
      valid ? shell_abstract_command_find_element(result, "$EV_2") : NULL;
  shell_abstract_element_t *operator =
      valid ? shell_abstract_command_find_element(result, "$EV_3") : NULL;
  valid = valid && user && user->expanded &&
          strcmp(user->expanded, "testuser") == 0 && missing &&
          !missing->expanded && operator && !operator->expanded;
  TEST("partial expansion keeps resolved values", valid);
  shell_abstract_command_free(result);

  /* Classification follows the decoded value of the word. */
  static const struct {
    const char *input;
    const char *key;
    bool absolute;
    bool relative;
  } paths[] = {{"echo \\/etc/passwd", "$AP_1", true, false},
               {"echo \"\"/etc/passwd", "$AP_1", true, false},
               {"echo /tmp/hello\\ world", "$AP_1", true, false},
               {"echo \\~/note", "$RP_1", false, true}};
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    result = abstract_parse_command(paths[i].input);
    shell_abstract_element_t *path =
        result ? shell_abstract_command_find_element(result, paths[i].key)
               : NULL;
    valid = path && result->has_abs_paths == paths[i].absolute &&
            result->has_rel_paths == paths[i].relative;
    TEST(paths[i].input, valid);
    shell_abstract_command_free(result);
  }
}

typedef struct {
  const char *name;
  const char *value;
  unsigned calls;
} abstract_parameter_fixture_t;

static bool abstract_fixture_parameter(shell_abstract_type_t type,
                                       const char *name, void *context,
                                       const char **value,
                                       size_t *value_length) {
  abstract_parameter_fixture_t *fixture = context;
  fixture->calls++;
  if ((type != SHELL_ABSTRACT_PV && type != SHELL_ABSTRACT_SV) ||
      strcmp(name, fixture->name) != 0)
    return false;
  *value = fixture->value;
  *value_length = strlen(fixture->value);
  return true;
}

/* A true result with a zero count leaves `*value` unused: the callback need
 * not set it. */
static bool abstract_unused_value_parameter(shell_abstract_type_t type,
                                            const char *name, void *context,
                                            const char **value,
                                            size_t *value_length) {
  (void)type;
  (void)name;
  (void)context;
  (void)value;
  *value_length = 0;
  return true;
}

static char *abstract_expand_first(const char *input, const char *key,
                                   const shell_runtime_context_t *context) {
  shell_abstract_command_t *result = abstract_parse_command(input);
  shell_abstract_element_t *element =
      result ? shell_abstract_command_find_element(result, key) : NULL;
  char *expanded =
      element ? shell_abstract_element_expand(element, context) : NULL;
  shell_abstract_command_free(result);
  return expanded;
}

/* Bash never reads `$1` or `$?` from the environment, so entries with those
 * names must not resolve them; only the caller's callback can. */
static void abstract_test_parameters_are_not_environment(void) {
  printf("\n=== Positional And Special Parameters ===\n");
  const char *environment[] = {"1=spoof", "?=spoof",       "10=spoof",
                               "@=spoof", "USER=testuser", NULL};
  static const struct {
    const char *input;
    const char *key;
  } cases[] = {{"echo $1", "$PV_1"},
               {"echo ${1}", "$PV_1"},
               {"echo ${10}", "$PV_1"},
               {"echo $?", "$SV_1"},
               {"echo ${?}", "$SV_1"}};
  shell_runtime_context_t no_callback = {
      .env = environment, .cwd = "/tmp", .resolve_symlinks = false};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_abstract_command_t *result = abstract_parse_command(cases[i].input);
    shell_abstract_element_t *element =
        result ? shell_abstract_command_find_element(result, cases[i].key)
               : NULL;
    char *expanded =
        element ? shell_abstract_element_expand(element, &no_callback) : NULL;
    TEST(cases[i].input, element != NULL && expanded == NULL);
    free(expanded);
    shell_abstract_command_free(result);
  }

  abstract_parameter_fixture_t fixture = {"1", "actual", 0};
  shell_runtime_context_t with_callback = {.env = environment,
                                           .cwd = "/tmp",
                                           .resolve_symlinks = false,
                                           .parameters =
                                               abstract_fixture_parameter,
                                           .parameters_context = &fixture};
  char *positional = abstract_expand_first("echo $1", "$PV_1", &with_callback);
  TEST("callback supplies a positional parameter",
       positional && strcmp(positional, "actual") == 0 && fixture.calls == 1);
  free(positional);
  positional = abstract_expand_first("echo ${1}", "$PV_1", &with_callback);
  TEST("braced positional parameter uses the callback",
       positional && strcmp(positional, "actual") == 0);
  free(positional);

  fixture = (abstract_parameter_fixture_t){"?", "0", 0};
  char *status = abstract_expand_first("echo $?", "$SV_1", &with_callback);
  TEST("callback supplies a special parameter",
       status && strcmp(status, "0") == 0);
  free(status);

  fixture = (abstract_parameter_fixture_t){"1", "", 0};
  char *empty = abstract_expand_first("echo $1", "$PV_1", &with_callback);
  TEST("an empty callback value resolves to an empty string",
       empty && empty[0] == '\0');
  free(empty);

  shell_runtime_context_t unused_value = with_callback;
  unused_value.parameters = abstract_unused_value_parameter;
  char *unset_pointer =
      abstract_expand_first("echo $1", "$PV_1", &unused_value);
  TEST("a zero count does not read the value pointer",
       unset_pointer && unset_pointer[0] == '\0');
  free(unset_pointer);

  fixture = (abstract_parameter_fixture_t){"2", "other", 0};
  char *unknown = abstract_expand_first("echo $1", "$PV_1", &with_callback);
  TEST("a callback that declines leaves the parameter unresolved",
       unknown == NULL && fixture.calls == 1);
  free(unknown);

  /* The callback is for parameters only, and operators stay unresolved. */
  fixture = (abstract_parameter_fixture_t){"1", "actual", 0};
  char *variable = abstract_expand_first("echo $USER", "$EV_1", &with_callback);
  TEST("named variables ignore the callback",
       variable && strcmp(variable, "testuser") == 0 && fixture.calls == 0);
  free(variable);
  char *operator =
      abstract_expand_first("echo ${1:-x}", "$PV_1", &with_callback);
  TEST("a parameter operator never reaches the callback",
       operator == NULL && fixture.calls == 0);
  free(operator);
}

/* Active glob syntax takes precedence over option spelling in the anomaly type
 * signature, as in shell_classify_raw_token(): a word is OPT only when it is an
 * ordinary option-shaped word. Quoted and escaped glob punctuation is literal.
 */
static void abstract_test_type_sequence_hyphen_globs(void) {
  printf("\n=== Type Sequence Hyphen Globs ===\n");
  static const struct {
    const char *command;
    const char *expected;
  } cases[] = {
      {"ls *.txt", "10:2:ls,2:GB,,"},
      {"ls -*.txt", "10:2:ls,2:GB,,"},
      {"ls -[ab].txt", "10:2:ls,2:GB,,"},
      {"ls --*", "10:2:ls,2:GB,,"},
      {"ls -?", "10:2:ls,2:GB,,"},
      {"ls -@(a|b)", "10:2:ls,2:GB,,"},
      {"ls -!(a)", "10:2:ls,2:GB,,"},
      {"ls -a*\"b\"", "10:2:ls,2:GB,,"},
      {"ls -\"a\"*", "10:2:ls,2:GB,,"},
      {"ls -- -*.c", "16:2:ls,3:OPT,2:GB,,"},
      {"ls -x", "11:2:ls,3:OPT,,"},
      {"ls --long", "11:2:ls,3:OPT,,"},
      {"ls -1", "11:2:ls,3:OPT,,"},
      {"ls -[a", "11:2:ls,3:OPT,,"},
      {"ls -\\*.txt", "11:2:ls,3:OPT,,"},
      {"ls -\\[ab].txt", "11:2:ls,3:OPT,,"},
      {"ls '-*.txt'", "11:2:ls,3:STR,,"},
      {"ls \"-*.txt\"", "11:2:ls,3:STR,,"},
      {"ls -", "11:2:ls,3:STR,,"},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    size_t length = strlen(cases[i].command);
    size_t expected = strlen(cases[i].expected);
    size_t count = 0, anomaly_count = 0;
    shell_netstring_buffer_t direct = {0}, command = {0}, type = {0};
    valid =
        shell_build_type_netseq_buffer(cases[i].command, length, NULL, &direct,
                                       &count) == SHELL_PROCESS_OK &&
        shell_build_anomaly_netseqs_buffer(cases[i].command, length, NULL,
                                           &command, &type, &anomaly_count) ==
            SHELL_PROCESS_OK &&
        direct.length == expected && type.length == expected &&
        memcmp(direct.data, cases[i].expected, expected) == 0 &&
        memcmp(type.data, cases[i].expected, expected) == 0;
    if (!valid)
      fprintf(stderr, "type signature mismatch: %s\n", cases[i].command);
    shell_netstring_buffer_free(&direct);
    shell_netstring_buffer_free(&command);
    shell_netstring_buffer_free(&type);
  }
  TEST("hyphen-prefixed active globs keep the glob type in signatures", valid);
}

static int run_abstract(int argc, char **argv) {
  (void)argc;
  (void)argv;
  printf("=== Shell Abstraction Tests ===\n");

  abstract_test_abstraction_matrix();
  abstract_test_final_backslash_redirect_operand();
  abstract_test_compound_variable_quote_boundaries();
  abstract_test_parameter_expansion_metadata();
  abstract_test_abstraction_allocation_failures();
  abstract_test_fragment_payload_metadata();
  abstract_test_classification_matrix();
  abstract_test_path_and_name_matrices();
  abstract_test_runtime_expansion();
  abstract_test_parameters_are_not_environment();
  abstract_test_type_sequence_hyphen_globs();

  printf("\n=== Summary ===\n");
  printf("Passed: %d\nFailed: %d\nTotal:  %d\n", abstract_passed,
         abstract_failed, abstract_passed + abstract_failed);
  return abstract_failed > 0 ? 1 : 0;
}
#undef TEST
#endif

/* --- expand (from expand_test.c) --- */
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "failed: %s at %d\n", #condition, __LINE__);             \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

typedef struct {
  const char *source;
  const char *payload;
  size_t payload_length;
  shell_expand_status_t status;
  size_t calls, arguments, redirects, files;
  bool seen[256];
  bool expect_absolute_cwd;
} expand_fixture_t;

static shell_expand_status_t
expand_expand_word(const shell_expand_word_request_t *request,
                   const char **netargv, size_t *length, void *context) {
  expand_fixture_t *fixture = context;
  CHECK(request->source == fixture->source);
  CHECK(request->source_length == strlen(fixture->source));
  CHECK(request->word_offset < request->source_length &&
        request->word_length <= request->source_length - request->word_offset);
  CHECK(request->owner_offset <= request->word_offset &&
        request->owner_length <=
            request->source_length - request->owner_offset);
  CHECK(request->word_offset < sizeof(fixture->seen));
  CHECK(!fixture->seen[request->word_offset]);
  fixture->seen[request->word_offset] = true;
  fixture->calls++;
  fixture->arguments += request->purpose == SHELL_EXPAND_WORD_ARGUMENT;
  fixture->redirects += request->purpose == SHELL_EXPAND_WORD_REDIRECT_PATH;
  fixture->files +=
      request->purpose == SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH;
  if (fixture->expect_absolute_cwd)
    CHECK(request->cwd_known && request->cwd_absolute &&
          strcmp(request->cwd, "/workspace") == 0);
  *netargv = fixture->payload;
  *length = fixture->payload_length;
  return fixture->status;
}

static bool expand_equal_span(const char *left, size_t left_length,
                              const char *right, size_t right_length) {
  return left_length == right_length &&
         (left_length == 0 || memcmp(left, right, left_length) == 0);
}

static void
expand_check_unresolved_equivalence(const shell_dep_graph_t *plain,
                                    const shell_dep_graph_t *resolved) {
  CHECK(plain->node_count == resolved->node_count &&
        plain->edge_count == resolved->edge_count);
  CHECK(expand_equal_span(plain->cwd_buf.data, plain->cwd_buf.len,
                          resolved->cwd_buf.data, resolved->cwd_buf.len));
  for (uint32_t i = 0; i < plain->node_count; i++) {
    const shell_dep_node_t *a = &plain->nodes[i], *b = &resolved->nodes[i];
    CHECK(a->type == b->type);
    if (a->type == SHELL_NODE_CMD) {
      CHECK(a->cmd.token_count == b->cmd.token_count &&
            a->cmd.effective_command_known == b->cmd.effective_command_known &&
            a->cmd.effective_command_token == b->cmd.effective_command_token &&
            a->cmd.effective_command_wrapper ==
                b->cmd.effective_command_wrapper &&
            a->cmd.cwd_offset == b->cmd.cwd_offset &&
            a->cmd.cwd_known == b->cmd.cwd_known &&
            a->cmd.cwd_absolute == b->cmd.cwd_absolute &&
            a->cmd.group_depth == b->cmd.group_depth &&
            a->cmd.group_kinds == b->cmd.group_kinds &&
            a->cmd.backgrounded == b->cmd.backgrounded &&
            a->cmd.pipeline_negation_count == b->cmd.pipeline_negation_count &&
            a->cmd.pipeline_negated == b->cmd.pipeline_negated &&
            a->cmd.pipeline_time_mode == b->cmd.pipeline_time_mode &&
            a->cmd.pipeline_time_id == b->cmd.pipeline_time_id &&
            a->cmd.pipe_stdin_source == b->cmd.pipe_stdin_source &&
            a->cmd.pipe_stdin_target == b->cmd.pipe_stdin_target &&
            a->cmd.pipe_stdout_source == b->cmd.pipe_stdout_source &&
            a->cmd.pipe_stdout_target == b->cmd.pipe_stdout_target);
      for (uint32_t j = 0; j < a->cmd.token_count; j++)
        CHECK(expand_equal_span(a->cmd.tokens[j], a->cmd.token_lens[j],
                                b->cmd.tokens[j], b->cmd.token_lens[j]));
    } else if (a->type == SHELL_NODE_DOC) {
      CHECK(a->doc.kind == b->doc.kind && a->doc.flags == b->doc.flags &&
            a->doc.cwd_offset == b->doc.cwd_offset &&
            a->doc.cwd_known == b->doc.cwd_known &&
            a->doc.cwd_absolute == b->doc.cwd_absolute);
      CHECK(expand_equal_span(a->doc.path, a->doc.path_len, b->doc.path,
                              b->doc.path_len));
      CHECK(expand_equal_span(a->doc.name, a->doc.name_len, b->doc.name,
                              b->doc.name_len));
      CHECK(expand_equal_span(a->doc.value, a->doc.value_len, b->doc.value,
                              b->doc.value_len));
    } else if (a->type == SHELL_NODE_GROUP) {
      CHECK(expand_equal_span(a->group.start, a->group.length, b->group.start,
                              b->group.length));
      CHECK(a->group.parent == b->group.parent &&
            a->group.kind == b->group.kind &&
            a->group.pipeline_negation_count ==
                b->group.pipeline_negation_count &&
            a->group.pipeline_negated == b->group.pipeline_negated &&
            a->group.pipeline_time_mode == b->group.pipeline_time_mode &&
            a->group.pipeline_time_id == b->group.pipeline_time_id);
    }
  }
  for (uint32_t i = 0; i < plain->edge_count; i++) {
    const shell_dep_edge_t *a = &plain->edges[i], *b = &resolved->edges[i];
    CHECK(a->from == b->from && a->to == b->to && a->type == b->type &&
          a->dir == b->dir && a->flags == b->flags &&
          a->source_fd == b->source_fd && a->target_fd == b->target_fd);
    CHECK(expand_equal_span(a->source_fd_name, a->source_fd_name_len,
                            b->source_fd_name, b->source_fd_name_len));
    CHECK(expand_equal_span(a->target_fd_name, a->target_fd_name_len,
                            b->target_fd_name, b->target_fd_name_len));
  }
}

/* graph and plain are distinct fixture-owned outputs. limits borrows writable
 * workspace shared by their sequential graph builds. */
static SHELL_NONNULL(1, 2, 3) void test_nested_and_conditional_resolution(
    shell_dep_limits_t *limits, shell_dep_graph_t *graph,
    shell_dep_graph_t *plain) {
  static const struct {
    const char *source;
    size_t arguments, redirects, files;
    size_t unresolved;
    bool substitution;
  } cases[] = {
      {"false && cat <\"$IN\"", 0, 0, 0, 0, false},
      {"true || cat <\"$IN\"", 0, 0, 0, 0, false},
      {"maybe && cat <\"$IN\"", 0, 1, 0, 1, false},
      {"echo \"$(cat <\"$IN\")\"", 1, 1, 0, 1, true},
      {"{ { cat; }; } <\"$IN\"", 0, 1, 0, 1, false},
      {"cat $(<\"$IN\") | cat", 1, 0, 1, 1, true},
      {"cat < <(cat <\"$IN\")", 0, 1, 0, 1, true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    size_t length = strlen(source);
    uint8_t unresolved[SHELL_DEP_MAX_NODES];
    for (unsigned mode = 0; mode < 3; mode++) {
      expand_fixture_t fixture = {.source = source,
                                  .payload = "9:/tmp/path,",
                                  .payload_length = 12,
                                  .status = mode == 2
                                                ? SHELL_EXPAND_RESOLVED
                                                : SHELL_EXPAND_UNRESOLVED};
      memset(unresolved, 0xff, sizeof(unresolved));
      shell_dep_error_t error = shell_dep_graph_parse_resolved(
          source, length, NULL, limits, graph, mode ? expand_expand_word : NULL,
          &fixture, unresolved);
      CHECK(error == SHELL_DEP_OK);
      CHECK(shellsplit_test_depgraph_invariants(source, length, error, graph,
                                                limits));
      CHECK(fixture.arguments == (mode ? cases[i].arguments : 0) &&
            fixture.redirects == (mode ? cases[i].redirects : 0) &&
            fixture.files == (mode ? cases[i].files : 0));
      size_t flags = 0;
      bool substitution = false, borrowed = false;
      for (uint32_t node = 0; node < SHELL_DEP_MAX_NODES; node++) {
        CHECK(unresolved[node] <= 1);
        if (node >= graph->node_count)
          CHECK(unresolved[node] == 0);
        flags += unresolved[node];
        if (node < graph->node_count &&
            graph->nodes[node].type == SHELL_NODE_DOC &&
            (graph->nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH)) {
          CHECK(graph->nodes[node].doc.value == fixture.payload + 2 &&
                graph->nodes[node].doc.value_len == 9);
          borrowed = true;
        }
      }
      CHECK(flags == (mode == 2 ? 0 : cases[i].unresolved));
      CHECK(borrowed == (mode == 2 && (cases[i].redirects || cases[i].files)));
      for (uint32_t edge = 0; edge < graph->edge_count; edge++)
        substitution |= graph->edges[edge].type == SHELL_EDGE_SUBST;
      CHECK(substitution == cases[i].substitution);
      if (mode < 2) {
        CHECK(shell_dep_graph_parse(source, length, NULL, limits, plain) ==
              SHELL_DEP_OK);
        expand_check_unresolved_equivalence(plain, graph);
      }
    }
  }
}

static int run_expand(int argc, char **argv) {
  (void)argc;
  (void)argv;
  shellsplit_graph_fixture_t graph_fixture;
  CHECK(shellsplit_graph_fixture_init(&graph_fixture,
                                      SHELLSPLIT_FIXTURE_RESOLVED, 256, 2,
                                      false, shell_dep_workspace_alignment()));
  shell_dep_limits_t limits = graph_fixture.limits;
  void *workspace = graph_fixture.workspace;
  shell_dep_graph_t *graph = graph_fixture.graph[0];
  size_t required;
  CHECK(shell_dep_resolved_workspace_size(256, NULL, &required));
  limits.workspace_size = required;
  test_nested_and_conditional_resolution(&limits, graph,
                                         graph_fixture.graph[1]);
  uint8_t unresolved[SHELL_DEP_MAX_NODES];
  static const struct {
    const char *source;
    size_t arguments, redirects, files;
    bool absolute_cwd;
  } cases[] = {
      {"echo \"$V\"", 1, 0, 0, false},
      {"cd /workspace && { echo \"$V\"; } >\"$OUT\"", 1, 1, 0, true},
      {"cat $(<\"$IN\")", 1, 0, 1, false},
      {"exec \"$V\"", 0, 0, 0, false},
      {"cd \"$V\"", 0, 0, 0, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    expand_fixture_t fixture = {.source = cases[i].source,
                                .payload = "15:/tmp/value file,",
                                .payload_length = 19,
                                .status = SHELL_EXPAND_RESOLVED,
                                .expect_absolute_cwd = cases[i].absolute_cwd};
    CHECK(shell_dep_graph_parse_resolved(
              fixture.source, strlen(fixture.source), NULL, &limits, graph,
              expand_expand_word, &fixture, unresolved) == SHELL_DEP_OK);
    CHECK(fixture.arguments == cases[i].arguments &&
          fixture.redirects == cases[i].redirects &&
          fixture.files == cases[i].files);
    CHECK(shell_dep_graph_validate(graph).valid);
    for (size_t node = 0; node < SHELL_DEP_MAX_NODES; node++)
      CHECK(unresolved[node] == 0);
    if (cases[i].redirects || cases[i].files) {
      bool borrowed_path = false;
      for (uint32_t node = 0; node < graph->node_count; node++)
        if (graph->nodes[node].type == SHELL_NODE_DOC &&
            graph->nodes[node].doc.value == fixture.payload + 3)
          borrowed_path = true;
      CHECK(borrowed_path);
    }
  }

  const char *source = "echo \"$V\"";
  static const char binary[] = {'3', ':', 'a', 0, 'b', ','};
  static const struct {
    shell_expand_status_t status;
    const char *data;
    size_t length;
    shell_dep_error_t expected;
  } values[] = {
      {SHELL_EXPAND_RESOLVED, binary, sizeof(binary), SHELL_DEP_OK},
      {SHELL_EXPAND_RESOLVED, NULL, 0, SHELL_DEP_OK},
      {SHELL_EXPAND_RESOLVED, "0:,", 3, SHELL_DEP_OK},
      {SHELL_EXPAND_UNRESOLVED, NULL, 100, SHELL_DEP_OK},
      {SHELL_EXPAND_FAILED, NULL, 0, SHELL_DEP_EEXPAND},
      {SHELL_EXPAND_RESOLVED, "01:x,", 5, SHELL_DEP_EEXPAND},
      {SHELL_EXPAND_RESOLVED, "2:x,", 4, SHELL_DEP_EEXPAND},
      {SHELL_EXPAND_RESOLVED, NULL, 1, SHELL_DEP_EEXPAND},
      {(shell_expand_status_t)7, NULL, 0, SHELL_DEP_EEXPAND},
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    expand_fixture_t fixture = {.source = source,
                                .payload = values[i].data,
                                .payload_length = values[i].length,
                                .status = values[i].status};
    memset(unresolved, 0xff, sizeof(unresolved));
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                         graph, expand_expand_word, &fixture,
                                         unresolved) == values[i].expected);
    CHECK(fixture.calls == 1);
    if (values[i].expected != SHELL_DEP_OK)
      CHECK(graph->node_count == 0 && graph->edge_count == 0);
    for (size_t node = 0; node < sizeof(unresolved); node++)
      CHECK(unresolved[node] == 0);
  }

  source = "{ echo ok; } >\"$OUT\"";
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, NULL, NULL,
                                       unresolved) == SHELL_DEP_OK);
  size_t flags = 0;
  for (size_t node = 0; node < sizeof(unresolved); node++)
    flags += unresolved[node] != 0;
  CHECK(flags == 1);
  expand_fixture_t fixture = {.source = source,
                              .payload = binary,
                              .payload_length = sizeof(binary),
                              .status = SHELL_EXPAND_RESOLVED};
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, expand_expand_word, &fixture,
                                       NULL) == SHELL_DEP_EEXPAND);
  fixture =
      (expand_fixture_t){.source = source, .status = SHELL_EXPAND_RESOLVED};
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, expand_expand_word, &fixture,
                                       NULL) ==
        SHELL_DEP_EUNMODELED); /* An empty redirect path certainly fails. */
  CHECK(graph->node_count == 0 && graph->edge_count == 0);

  source = "echo \"$V\"; while true; do echo no; done";
  fixture =
      (expand_fixture_t){.source = source, .status = SHELL_EXPAND_UNRESOLVED};
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, expand_expand_word, &fixture,
                                       unresolved) == SHELL_DEP_EPARSE);
  CHECK(fixture.calls == 0);
  source = "echo \"$V\"";
  CHECK(shell_dep_resolved_workspace_size(strlen(source), &limits, &required));
  limits.workspace_size = required;
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, NULL, NULL,
                                       unresolved) == SHELL_DEP_OK);
  CHECK(shell_dep_graph_validate(graph).valid);
  limits.max_nodes = 1;
  source = "echo \"$V\" | cat";
  CHECK(shell_dep_resolved_workspace_size(strlen(source), &limits, &required));
  limits.workspace_size = required;
  memset(unresolved, 0xff, sizeof(unresolved));
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, NULL, NULL,
                                       unresolved) == SHELL_DEP_ETRUNC);
  CHECK(graph->node_count <= 1);
  CHECK(shellsplit_test_depgraph_invariants(source, strlen(source),
                                            SHELL_DEP_ETRUNC, graph, &limits));
  for (size_t node = 0; node < sizeof(unresolved); node++) {
    CHECK(unresolved[node] <= 1);
    if (node >= graph->node_count)
      CHECK(unresolved[node] == 0);
  }
  limits.max_nodes = SHELL_DEP_LIMITS_DEFAULT.max_nodes;
  source = "cat <\"$IN\"";
  fixture = (expand_fixture_t){.source = source,
                               .payload = "1:a,1:b,",
                               .payload_length = 8,
                               .status = SHELL_EXPAND_RESOLVED};
  CHECK(shell_dep_resolved_workspace_size(strlen(source), &limits, &required));
  limits.workspace_size = required;
  /* Two resolved words make an ambiguous redirect: a certain shell error. */
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, expand_expand_word, &fixture,
                                       unresolved) == SHELL_DEP_EUNMODELED);
  CHECK(fixture.calls == 1);
  CHECK(shell_dep_graph_parse_resolved("", 0, NULL, &limits, graph, NULL, NULL,
                                       unresolved) == SHELL_DEP_EINPUT);
  CHECK(graph->node_count == 0 && graph->edge_count == 0);
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, NULL,
                                       graph, NULL, NULL,
                                       unresolved) == SHELL_DEP_EWORKSPACE);
  limits.workspace_size = required - 1;
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, NULL, NULL,
                                       NULL) == SHELL_DEP_EWORKSPACE);
  limits.workspace_size = required;
  limits.workspace = (char *)workspace + 1;
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, NULL, NULL,
                                       NULL) == SHELL_DEP_EWORKSPACE);
  limits.workspace = NULL;
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), NULL, &limits,
                                       graph, NULL, NULL,
                                       NULL) == SHELL_DEP_EWORKSPACE);
  CHECK(!shell_dep_resolved_workspace_size(SIZE_MAX, NULL, &required));
  CHECK(required == 0);
  CHECK(strcmp(shell_dep_error_string(SHELL_DEP_EEXPAND),
               "Word resolution failed") == 0);
  shellsplit_graph_fixture_destroy(&graph_fixture);
  puts("public word resolution tests passed");
  return 0;
}
#undef CHECK

int main(int argc, char **argv) {
  int status = 0;
  status |= run_semantics(argc, argv);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  status |= run_abstract(argc, argv);
#endif
  status |= run_expand(argc, argv);
  return status != 0;
}
