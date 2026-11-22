/* The shared test support the suites rely on as oracles: the comparison of two
 * parse results, the comparison of two dependency graphs, and the graph fixture
 * they build on: aligned and guarded workspaces, released cleanly, and bad
 * requests refused. */
#include "depgraph_compare.h"
#include "graph_fixture.h"
#include "source_compare.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* --- source_compare (from source_compare_test.c) --- */
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "source comparison check failed at %d: %s\n", __LINE__,  \
              #condition);                                                     \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

/* Only comparison helpers receive these fixtures. Their initialized fields
 * may differ independently; they are not fabricated inputs to parser APIs. */
#define INITIALIZE(field, initial, different) a.field = b.field = initial;
#define MUTATE(field, initial, different)                                      \
  do {                                                                         \
    b.field = different;                                                       \
    const char *changed = difference(&a, &b);                                  \
    if (!changed)                                                              \
      fprintf(stderr, "%s ignored changed field %s\n", __func__, #field);      \
    CHECK(changed != NULL);                                                    \
    b.field = a.field;                                                         \
  } while (0);
#define CHECK_FIELDS(fields)                                                   \
  fields(INITIALIZE) CHECK(difference(&a, &b) == NULL);                        \
  fields(MUTATE) CHECK(difference(&a, &b) == NULL)

/* The caller supplies a padding-only interval within both fixture objects. */
static SHELL_NONNULL(1, 2) void contrast_padding(void *a, void *b, size_t first,
                                                 size_t last) {
  for (size_t i = first; i < last; i++) {
    ((unsigned char *)a)[i] = 0x55;
    ((unsigned char *)b)[i] = 0xaa;
  }
}

static void source_compare_ranges(void) {
  shell_range_t a, b;
  memset(&a, 0x55, sizeof(a));
  memset(&b, 0xaa, sizeof(b));
  const char *(*difference)(const shell_range_t *, const shell_range_t *) =
      shellsplit_test_range_difference;
#define FIELDS(F)                                                              \
  F(start, 1, 2)                                                               \
  F(len, 4, 5)                                                                 \
  F(kind, SHELL_COMMAND_SIMPLE, SHELL_COMMAND_ARITHMETIC)                      \
  F(type, SHELL_TYPE_SIMPLE, SHELL_TYPE_PIPELINE)                              \
  F(modifiers, SHELL_CMD_MOD_PIPE_TIMED, SHELL_CMD_MOD_NONE)                   \
  F(pipeline_negation_count, 0, 1)                                             \
  F(pipeline_time_mode, SHELL_PIPE_TIME_DEFAULT, SHELL_PIPE_TIME_POSIX)        \
  F(pipeline_time_direct, true, false)                                         \
  F(pipe_input_mode, SHELL_PIPE_MODE_NONE, SHELL_PIPE_MODE_STDOUT)             \
  F(features, SHELL_FEAT_NONE, SHELL_FEAT_VARS)                                \
  F(group_depth, 0, 1)                                                         \
  F(group_kinds, SHELL_GROUP_NONE, SHELL_GROUP_BRACE)
  CHECK_FIELDS(FIELDS);
#undef FIELDS
}

static void source_compare_groups(void) {
  shell_group_t a, b;
  memset(&a, 0x55, sizeof(a));
  memset(&b, 0xaa, sizeof(b));
  const char *(*difference)(const shell_group_t *, const shell_group_t *) =
      shellsplit_test_group_difference;
#define FIELDS(F)                                                              \
  F(start, 1, 2)                                                               \
  F(end, 8, 9)                                                                 \
  F(first_command, 0, 1)                                                       \
  F(command_count, 1, 0)                                                       \
  F(parent, UINT16_MAX, 0)                                                     \
  F(kind, SHELL_GROUP_BRACE, SHELL_GROUP_SUBSHELL)                             \
  F(modifiers, SHELL_CMD_MOD_PIPE_TIMED, SHELL_CMD_MOD_NONE)                   \
  F(pipeline_negation_count, 0, 1)                                             \
  F(pipeline_time_mode, SHELL_PIPE_TIME_DEFAULT, SHELL_PIPE_TIME_POSIX)        \
  F(pipeline_time_direct, true, false)
  CHECK_FIELDS(FIELDS);
#undef FIELDS
}

static void source_compare_parses(void) {
  shell_parse_result_t a, b;
  memset(&a, 0x55, sizeof(a));
  memset(&b, 0xaa, sizeof(b));
  a.cmds[0] = b.cmds[0] = (shell_range_t){.start = 1, .len = 4};
  a.groups[0] = b.groups[0] = (shell_group_t){.start = 0, .end = 6};
  const char *(*difference)(const shell_parse_result_t *,
                            const shell_parse_result_t *) =
      shellsplit_test_parse_difference;
#define FIELDS(F)                                                              \
  F(count, 1, 0)                                                               \
  F(group_count, 1, 0)                                                         \
  F(status, SHELL_STATUS_OK, SHELL_STATUS_TRUNCATED)
  CHECK_FIELDS(FIELDS);
#undef FIELDS
  b.cmds[0].features = SHELL_FEAT_VARS;
  CHECK(difference(&a, &b) != NULL);
  b.cmds[0].features = a.cmds[0].features;
  b.groups[0].pipeline_time_direct = true;
  CHECK(difference(&a, &b) != NULL);
  b.groups[0].pipeline_time_direct = a.groups[0].pipeline_time_direct;
  CHECK(difference(&a, &b) == NULL);
}

static void source_compare_headers(void) {
  shell_source_header_t a, b;
  memset(&a, 0x55, sizeof(a));
  memset(&b, 0xaa, sizeof(b));
  const char *(*difference)(const shell_source_header_t *,
                            const shell_source_header_t *) =
      shellsplit_test_header_difference;
#define FIELDS(F)                                                              \
  F(source.start, 1, 2)                                                        \
  F(kind, SHELL_COMMAND_SIMPLE, SHELL_COMMAND_ARITHMETIC)                      \
  F(conditional_expression.start, 0, 1)                                        \
  F(conditional_expression.length, 0, 1)                                       \
  F(conditional_operands[0].start, 0, 1)                                       \
  F(conditional_operands[0].length, 0, 1)                                      \
  F(conditional_operands[1].start, 0, 1)                                       \
  F(conditional_operands[1].length, 0, 1)                                      \
  F(conditional_operand_count, 0, 2)                                           \
  F(conditional_predicate, SHELL_CONDITIONAL_PREDICATE_NONE,                   \
    SHELL_CONDITIONAL_STRING_EQUAL)                                            \
  F(conditional_negated, false, true)                                          \
  F(arithmetic_expression.start, 0, 2)                                         \
  F(arithmetic_expression.length, 0, 1)                                        \
  F(source.length, 50, 51)                                                     \
  F(word_count, 2, 1)                                                          \
  F(assignment_count, 1, 0)                                                    \
  F(first_redirect, 0, UINT32_MAX)                                             \
  F(redirect_count, 1, 0)                                                      \
  F(group_depth, 0, 1)                                                         \
  F(complete, true, false)                                                     \
  F(compound, false, true)                                                     \
  F(words[0].start, 1, 2)                                                      \
  F(words[0].length, 5, 6)                                                     \
  F(words[1].start, 7, 8)                                                      \
  F(words[1].length, 4, 5)
  CHECK_FIELDS(FIELDS);
#undef FIELDS
}

static void source_compare_io(void) {
  shell_group_io_op_t a, b;
  memset(&a, 0x55, sizeof(a));
  memset(&b, 0xaa, sizeof(b));
  const char *(*difference)(const shell_group_io_op_t *,
                            const shell_group_io_op_t *) =
      shellsplit_test_io_difference;
#define FIELDS(F)                                                              \
  F(group_index, UINT16_MAX, 0)                                                \
  F(source_start, 2, 3)                                                        \
  F(source_end, 10, 11)                                                        \
  F(operand_start, 5, 6)                                                       \
  F(operand_end, 10, 11)                                                       \
  F(fd, 2, 3)                                                                  \
  F(target_fd, SHELL_PROCESS_FD_NONE, 1)                                       \
  F(fd_name_start, 0, 1)                                                       \
  F(fd_name_end, 0, 4)                                                         \
  F(target_name_start, 0, 5)                                                   \
  F(target_name_end, 0, 7)                                                     \
  F(kind, SHELL_GROUP_IO_WRITE_FILE, SHELL_GROUP_IO_APPEND_FILE)
  CHECK_FIELDS(FIELDS);
#undef FIELDS

  /* Explicitly preserve different padding after all field stores. This
   * reproduces the false assertion independently of compiler stack layout. */
  size_t padding_start =
      offsetof(shell_group_io_op_t, group_index) + sizeof(a.group_index);
  size_t padding_end = offsetof(shell_group_io_op_t, source_start);
  contrast_padding(&a, &b, padding_start, padding_end);
  CHECK(difference(&a, &b) == NULL);
  if (padding_start < padding_end)
    CHECK(memcmp(&a, &b, sizeof(a)) != 0);
}

static void source_compare_redirects(void) {
  shell_source_redirect_t a, b;
  memset(&a, 0x55, sizeof(a));
  memset(&b, 0xaa, sizeof(b));
  a.io = b.io = (shell_group_io_op_t){.group_index = UINT16_MAX,
                                      .fd = 2,
                                      .target_fd = 1,
                                      .kind = SHELL_GROUP_IO_DUP_FD};
  const char *(*difference)(const shell_source_redirect_t *,
                            const shell_source_redirect_t *) =
      shellsplit_test_redirect_difference;
#define FIELDS(F)                                                              \
  F(header, 1, 2)                                                              \
  F(next, UINT32_MAX, 1)                                                       \
  F(heredoc, UINT32_MAX, 0)
  CHECK_FIELDS(FIELDS);
#undef FIELDS
  size_t padding_start =
      offsetof(shell_group_io_op_t, group_index) + sizeof(a.io.group_index);
  size_t padding_end = offsetof(shell_group_io_op_t, source_start);
  contrast_padding(&a.io, &b.io, padding_start, padding_end);
  CHECK(difference(&a, &b) == NULL);
  if (padding_start < padding_end)
    CHECK(memcmp(&a, &b, sizeof(a)) != 0);
  b.io.target_fd = 3;
  CHECK(difference(&a, &b) != NULL);
}

static void source_compare_documents(void) {
  static const char path[] = "input.txt", name[] = "EOF", value[] = "payload\n";
  shell_dep_doc_t a, b;
  memset(&a, 0x55, sizeof(a));
  memset(&b, 0xaa, sizeof(b));
  const char *(*difference)(const shell_dep_doc_t *, const shell_dep_doc_t *) =
      shellsplit_test_doc_difference;
#define FIELDS(F)                                                              \
  F(kind, SHELL_DOC_HEREDOC, SHELL_DOC_HERESTRING)                             \
  F(flags, SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL,                                 \
    SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS)                                     \
  F(name, name, NULL)                                                          \
  F(name_len, 3, 2)                                                            \
  F(value, value, NULL)                                                        \
  F(value_len, 8, 7)
  CHECK_FIELDS(FIELDS);
#undef FIELDS
  contrast_padding(&a, &b, offsetof(shell_dep_doc_t, kind) + sizeof(a.kind),
                   offsetof(shell_dep_doc_t, path));
  CHECK(difference(&a, &b) == NULL);
  a.kind = b.kind = SHELL_DOC_ENVVAR;
  CHECK(difference(&a, &b) == NULL);
  b.name_len--;
  CHECK(difference(&a, &b) != NULL);
  b.name_len = a.name_len;
  a.kind = b.kind = SHELL_DOC_HERESTRING;
  a.name = NULL;
  CHECK(difference(&a, &b) == NULL);

#define FIELDS(F)                                                              \
  F(kind, SHELL_DOC_FILE, SHELL_DOC_HERESTRING)                                \
  F(flags, SHELL_DEP_DOC_FLAG_NONE, SHELL_DEP_DOC_FLAG_DYNAMIC_NAME)           \
  F(path, path, NULL)                                                          \
  F(path_len, 9, 8)                                                            \
  F(cwd_offset, 0, 1)                                                          \
  F(cwd_known, true, false)                                                    \
  F(cwd_absolute, true, false)
  CHECK_FIELDS(FIELDS);
#undef FIELDS
  a.value = NULL;
  CHECK(difference(&a, &b) == NULL);
  a.flags = b.flags = SHELL_DEP_DOC_FLAG_RESOLVED_PATH;
  CHECK(difference(&a, &b) != NULL);
  a.value = b.value;
  CHECK(difference(&a, &b) == NULL);
}

static void source_compare_heredocs(void) {
  shell_source_heredoc_t a, b;
  memset(&a, 0x55, sizeof(a));
  memset(&b, 0xaa, sizeof(b));
  a.content = b.content =
      (shell_dep_doc_t){.kind = SHELL_DOC_HEREDOC,
                        .name = "EOF",
                        .name_len = 3,
                        .value = "payload\n",
                        .value_len = 8,
                        .flags = SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL};
  const char *(*difference)(const shell_source_heredoc_t *,
                            const shell_source_heredoc_t *) =
      shellsplit_test_heredoc_difference;
#define FIELDS(F)                                                              \
  F(header, 0, 1)                                                              \
  F(redirect, 0, 1)                                                            \
  F(declaration.start, 4, 5)                                                   \
  F(declaration.length, 5, 6)                                                  \
  F(delimiter_word.start, 6, 7)                                                \
  F(delimiter_word.length, 3, 4)                                               \
  F(closing_delimiter.start, 18, 19)                                           \
  F(closing_delimiter.length, 4, 3)                                            \
  F(body_start, 10, 11)                                                        \
  F(confirmed_length, 8, 7)                                                    \
  F(header_complete, true, false)                                              \
  F(body_started, true, false)                                                 \
  F(complete, true, false)                                                     \
  F(delimiter_prefix, false, true)                                             \
  F(content.value_len, 8, 7)                                                   \
  F(content.flags, SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL,                         \
    SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS)
  CHECK_FIELDS(FIELDS);
#undef FIELDS
  contrast_padding(&a.content, &b.content,
                   offsetof(shell_dep_doc_t, kind) + sizeof(a.content.kind),
                   offsetof(shell_dep_doc_t, path));
  CHECK(difference(&a, &b) == NULL);
}

static void source_compare_pending_redirector(void) {
  /* background_operator.txt begins with 99,109: the fuzz oracle selects the
   * fourth received fragment and fifth compound, not the input's shell text. */
  char source[128] = "echo before; ( : ) >existing {";
  size_t received_length = strlen(source);
  static shell_source_result_t received, completed;
  CHECK(shell_parse_draft(source, received_length, NULL, &received) ==
        SHELL_SOURCE_INCOMPLETE);
  CHECK(received.header_count == 3 && received.redirect_count == 1);
  CHECK(received.need == SHELL_SOURCE_NEEDS_REDIRECT &&
        received.prefix_length == strlen("echo before;") &&
        received.headers[2].complete && !received.headers[1].complete);
  strcpy(source + received_length, "fd}>out");
  CHECK(shell_parse_draft(source, strlen(source), NULL, &completed) ==
        SHELL_SOURCE_COMPLETE);
  CHECK(completed.header_count == 3 && completed.redirect_count == 2);
  CHECK(completed.headers[1].complete);
  CHECK(shellsplit_test_header_equal(&received.headers[2],
                                     &completed.headers[2]));
  CHECK(shellsplit_test_io_equal(&received.redirects[0].io,
                                 &completed.redirects[0].io));
  CHECK(received.redirects[0].header == completed.redirects[0].header &&
        received.redirects[0].heredoc == completed.redirects[0].heredoc);
  CHECK(received.redirects[0].next == UINT32_MAX &&
        completed.redirects[0].next == 1 &&
        completed.redirects[1].next == UINT32_MAX);
}

static int run_source_compare(int argc, char **argv) {
  (void)argc;
  (void)argv;
  source_compare_ranges();
  source_compare_groups();
  source_compare_parses();
  source_compare_headers();
  source_compare_io();
  source_compare_redirects();
  source_compare_documents();
  source_compare_heredocs();
  source_compare_pending_redirector();
  puts("semantic source comparison tests passed");
  return 0;
}
#undef CHECK
#undef INITIALIZE
#undef MUTATE
#undef CHECK_FIELDS
#undef FIELDS
#undef FIELDS
#undef FIELDS
#undef FIELDS
#undef FIELDS
#undef FIELDS
#undef FIELDS
#undef FIELDS
#undef FIELDS

/* --- depgraph_compare (from depgraph_compare_test.c) --- */
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "comparison check failed at %d: %s\n", __LINE__,         \
              #condition);                                                     \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

static void depgraph_compare_test_edges(void) {
  shell_dep_edge_t a, b;
  memset(&a, 0x55, sizeof(a));
  memset(&b, 0xaa, sizeof(b));
#define EDGE_FIELD(field, initial, different)                                  \
  a.field = initial;                                                           \
  b.field = initial;
#define EDGE_FIELDS                                                            \
  EDGE_FIELD(from, 0, 1)                                                       \
  EDGE_FIELD(to, 1, 2)                                                         \
  EDGE_FIELD(type, SHELL_EDGE_PIPE, SHELL_EDGE_READ)                           \
  EDGE_FIELD(dir, SHELL_DIR_FORWARD, SHELL_DIR_UNDIR)                          \
  EDGE_FIELD(flags, 0, SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD)                   \
  EDGE_FIELD(source_fd, 1, 2)                                                  \
  EDGE_FIELD(target_fd, 0, 3)                                                  \
  EDGE_FIELD(source_fd_name, NULL, "fd")                                       \
  EDGE_FIELD(source_fd_name_len, 0, 2)                                         \
  EDGE_FIELD(target_fd_name, NULL, "out")                                      \
  EDGE_FIELD(target_fd_name_len, 0, 3)
  EDGE_FIELDS
#undef EDGE_FIELD
  CHECK(shellsplit_test_edge_difference(&a, &b) == NULL);
#define EDGE_FIELD(field, initial, different)                                  \
  b.field = different;                                                         \
  CHECK(shellsplit_test_edge_difference(&a, &b) != NULL);                      \
  b.field = a.field;
  EDGE_FIELDS
#undef EDGE_FIELD
#undef EDGE_FIELDS
}

static void depgraph_compare_test_nodes(void) {
  shell_dep_node_t a, b;
  memset(&a, 0x55, sizeof(a));
  memset(&b, 0xaa, sizeof(b));
  a.type = b.type = SHELL_NODE_CMD;
  a.cmd.token_count = b.cmd.token_count = 1;
  a.cmd.tokens[0] = b.cmd.tokens[0] = "echo";
  a.cmd.token_lens[0] = b.cmd.token_lens[0] = 4;
#define CMD_FIELD(field, initial, different)                                   \
  a.cmd.field = initial;                                                       \
  b.cmd.field = initial;
#define CMD_FIELDS                                                             \
  CMD_FIELD(kind, SHELL_COMMAND_SIMPLE, SHELL_COMMAND_ARITHMETIC)              \
  CMD_FIELD(conditional_expression, NULL, "x")                                 \
  CMD_FIELD(conditional_expression_length, 0, 1)                               \
  CMD_FIELD(conditional_operands[0], NULL, "x")                                \
  CMD_FIELD(conditional_operand_lengths[0], 0, 1)                              \
  CMD_FIELD(conditional_operands[1], NULL, "x")                                \
  CMD_FIELD(conditional_operand_lengths[1], 0, 1)                              \
  CMD_FIELD(conditional_operand_count, 0, 2)                                   \
  CMD_FIELD(conditional_predicate, SHELL_CONDITIONAL_PREDICATE_NONE,           \
            SHELL_CONDITIONAL_STRING_EQUAL)                                    \
  CMD_FIELD(conditional_negated, false, true)                                  \
  CMD_FIELD(conditional_truth, 0, 1)                                           \
  CMD_FIELD(conditional_arithmetic_unresolved, false, true)                    \
  CMD_FIELD(conditional_unresolved, false, true)                               \
  CMD_FIELD(arithmetic_expression, NULL, "1")                                  \
  CMD_FIELD(arithmetic_expression_length, 0, 1)                                \
  CMD_FIELD(arithmetic_truth, SHELL_ARITHMETIC_UNKNOWN, SHELL_ARITHMETIC_ZERO) \
  CMD_FIELD(has_redirections, false, true)                                     \
  CMD_FIELD(effective_command_known, true, false)                              \
  CMD_FIELD(effective_command_token, 0, 1)                                     \
  CMD_FIELD(effective_command_wrapper, SHELL_DEP_COMMAND_DIRECT,               \
            SHELL_DEP_COMMAND_SEARCH)                                          \
  CMD_FIELD(cwd_offset, 0, 1)                                                  \
  CMD_FIELD(group_depth, 0, 1)                                                 \
  CMD_FIELD(group_kinds, 0, 1)                                                 \
  CMD_FIELD(backgrounded, false, true)                                         \
  CMD_FIELD(pipeline_negation_count, 0, 1)                                     \
  CMD_FIELD(pipeline_negated, false, true)                                     \
  CMD_FIELD(pipeline_time_mode, SHELL_PIPE_TIME_NONE, SHELL_PIPE_TIME_DEFAULT) \
  CMD_FIELD(pipeline_time_id, 0, 1)                                            \
  CMD_FIELD(cwd_known, true, false)                                            \
  CMD_FIELD(cwd_absolute, true, false)                                         \
  CMD_FIELD(pipe_stdin_source, UINT32_MAX, 0)                                  \
  CMD_FIELD(pipe_stdin_target, UINT32_MAX, 0)                                  \
  CMD_FIELD(pipe_stdout_source, UINT32_MAX, 0)                                 \
  CMD_FIELD(pipe_stdout_target, UINT32_MAX, 0)
  CMD_FIELDS
#undef CMD_FIELD
  CHECK(shellsplit_test_node_difference(&a, &b) == NULL);
#define CMD_FIELD(field, initial, different)                                   \
  b.cmd.field = different;                                                     \
  CHECK(shellsplit_test_node_difference(&a, &b) != NULL);                      \
  b.cmd.field = a.cmd.field;
  CMD_FIELDS
#undef CMD_FIELD
#undef CMD_FIELDS
  b.cmd.tokens[0] = "other";
  CHECK(shellsplit_test_node_difference(&a, &b) != NULL);
  b.cmd.tokens[0] = a.cmd.tokens[0];
  b.cmd.token_lens[0]++;
  CHECK(shellsplit_test_node_difference(&a, &b) != NULL);

  /* All node kinds can retain different inactive union bytes. Assignment of
   * their active subobjects must not require clearing the whole union. */
  static const shell_dep_node_type_t kinds[] = {
      SHELL_NODE_DOC,      SHELL_NODE_GROUP, SHELL_NODE_TIME,
      SHELL_NODE_ENDPOINT, SHELL_NODE_FD,    SHELL_NODE_FILE_COMPARISON};
  for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
    memset(&a, 0x55, sizeof(a));
    memset(&b, 0xaa, sizeof(b));
    a.type = b.type = kinds[i];
    switch (kinds[i]) {
    case SHELL_NODE_DOC:
      a.doc = (shell_dep_doc_t){.kind = SHELL_DOC_FILE};
      b.doc = a.doc;
      CHECK(shellsplit_test_node_difference(&a, &b) == NULL);
      b.doc.flags = SHELL_DEP_DOC_FLAG_DYNAMIC_NAME;
      break;
    case SHELL_NODE_GROUP:
      a.group = (shell_dep_group_t){.parent = UINT32_MAX};
      b.group = a.group;
      CHECK(shellsplit_test_node_difference(&a, &b) == NULL);
      b.group.pipeline_time_id = 1;
      break;
    case SHELL_NODE_TIME:
      a.time = (shell_dep_time_t){.report_external_fd_count = 1};
      b.time = a.time;
      CHECK(shellsplit_test_node_difference(&a, &b) == NULL);
      b.time.report_external_fds[0] = 2;
      break;
    case SHELL_NODE_ENDPOINT:
      CHECK(shellsplit_test_node_difference(&a, &b) == NULL);
      b.type = SHELL_NODE_DOC;
      b.doc = (shell_dep_doc_t){.kind = SHELL_DOC_FILE};
      break;
    case SHELL_NODE_FD:
      a.fd = (shell_dep_fd_t){.number = 1};
      b.fd = a.fd;
      CHECK(shellsplit_test_node_difference(&a, &b) == NULL);
      b.fd.number = 2;
      break;
    case SHELL_NODE_CMD:
      break;
    case SHELL_NODE_FILE_COMPARISON:
      a.file_comparison =
          (shell_dep_file_comparison_t){SHELL_FILE_COMPARE_SAME, 0};
      b.file_comparison = a.file_comparison;
      CHECK(shellsplit_test_node_difference(&a, &b) == NULL);
      b.file_comparison.empty_operands = 1;
      break;
    }
    CHECK(shellsplit_test_node_difference(&a, &b) != NULL);
  }
}

static int run_depgraph_compare(int argc, char **argv) {
  (void)argc;
  (void)argv;
  depgraph_compare_test_edges();
  depgraph_compare_test_nodes();
  puts("semantic graph comparison tests passed");
  return 0;
}
#undef CHECK
#undef EDGE_FIELD
#undef EDGE_FIELDS
#undef EDGE_FIELD
#undef CMD_FIELD
#undef CMD_FIELDS
#undef CMD_FIELD

/* --- fixture (from fixture_part.c) --- */
#define CHECK(x)                                                               \
  do {                                                                         \
    if (!(x)) {                                                                \
      fprintf(stderr, "fixture: %s:%d: %s\n", __FILE__, __LINE__, #x);         \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int run_fixture(int argc, char **argv) {
  (void)argc;
  (void)argv;
  shellsplit_graph_fixture_t fixture;
  size_t alignment = shell_dep_workspace_alignment();
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_SOURCE, 64,
                                      2, true, alignment));
  CHECK(fixture.graph[0] && fixture.graph[1] &&
        fixture.graph[0] != fixture.graph[1]);
  CHECK((uintptr_t)fixture.workspace % alignment == 0);
  CHECK(fixture.limits.workspace_size % alignment == 0);
  ((unsigned char *)
       fixture.workspace)[fixture.limits.workspace_size + alignment - 1] = 1;
  fixture.limits.workspace = NULL;
  fixture.limits.workspace_size = 0;
  shellsplit_graph_fixture_destroy(&fixture);
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_SOURCE, 65,
                                      0, true, 1));
  ((unsigned char *)fixture.workspace)[fixture.limits.workspace_size] = 1;
  shellsplit_graph_fixture_destroy(&fixture);
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_FIXED, 0, 0,
                                      false, 0));
  CHECK(!fixture.graph[0] && !fixture.graph[1]);
  shellsplit_graph_fixture_destroy(&fixture);
  CHECK(!shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_SOURCE,
                                       SIZE_MAX, 1, false, 0));
  shellsplit_graph_fixture_destroy(&fixture);
  CHECK(!shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_FIXED, 0, 1,
                                       false, SIZE_MAX));
  shellsplit_graph_fixture_destroy(&fixture);
  return 0;
}
#undef CHECK

int main(int argc, char **argv) {
  int status = 0;
  status |= run_source_compare(argc, argv);
  status |= run_depgraph_compare(argc, argv);
  status |= run_fixture(argc, argv);
  return status != 0;
}
