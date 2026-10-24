#include "depgraph_compare.h"
#include <stdlib.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "comparison check failed at %d: %s\n", __LINE__,         \
              #condition);                                                     \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

static void test_edges(void) {
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

static void test_nodes(void) {
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
  CMD_FIELD(conditional_operand, NULL, "x")                                    \
  CMD_FIELD(conditional_operand_length, 0, 1)                                  \
  CMD_FIELD(conditional_truth, 0, 1)                                           \
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
      SHELL_NODE_DOC, SHELL_NODE_GROUP, SHELL_NODE_TIME, SHELL_NODE_ENDPOINT,
      SHELL_NODE_FD};
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
    }
    CHECK(shellsplit_test_node_difference(&a, &b) != NULL);
  }
}

int main(void) {
  test_edges();
  test_nodes();
  puts("semantic graph comparison tests passed");
  return 0;
}
