/* Semantic equality for independently built graphs over the same borrowed
 * source. Required inputs have bounded counts and initialized active fields;
 * their source spans borrow valid storage. Metadata values may differ: this
 * comparator does not require graph-topology validity. Padding, inactive union
 * storage and unused capacity are not part of this contract.
 * This is test machinery, not a new library API or graph validation pass. */
#ifndef SHELLSPLIT_DEPGRAPH_COMPARE_H
#define SHELLSPLIT_DEPGRAPH_COMPARE_H

#include "shell_depgraph.h"
#include "shell_tokenizer.h"
#include <stdio.h>
#include <string.h>

#define SHELLSPLIT_COMPARE_FIELD(field)                                        \
  do {                                                                         \
    if (a->field != b->field)                                                  \
      return #field;                                                           \
  } while (0)

static inline SHELL_NONNULL(1, 2) const
    char *shellsplit_test_edge_difference(const shell_dep_edge_t *a,
                                          const shell_dep_edge_t *b) {
  SHELLSPLIT_COMPARE_FIELD(from);
  SHELLSPLIT_COMPARE_FIELD(to);
  SHELLSPLIT_COMPARE_FIELD(type);
  SHELLSPLIT_COMPARE_FIELD(dir);
  SHELLSPLIT_COMPARE_FIELD(flags);
  SHELLSPLIT_COMPARE_FIELD(source_fd);
  SHELLSPLIT_COMPARE_FIELD(target_fd);
  SHELLSPLIT_COMPARE_FIELD(source_fd_name);
  SHELLSPLIT_COMPARE_FIELD(source_fd_name_len);
  SHELLSPLIT_COMPARE_FIELD(target_fd_name);
  SHELLSPLIT_COMPARE_FIELD(target_fd_name_len);
  return NULL;
}

static inline SHELL_NONNULL(1, 2) const
    char *shellsplit_test_doc_difference(const shell_dep_doc_t *a,
                                         const shell_dep_doc_t *b) {
  SHELLSPLIT_COMPARE_FIELD(kind);
  SHELLSPLIT_COMPARE_FIELD(flags);
  if (a->kind == SHELL_DOC_FILE) {
    SHELLSPLIT_COMPARE_FIELD(path);
    SHELLSPLIT_COMPARE_FIELD(path_len);
    SHELLSPLIT_COMPARE_FIELD(cwd_offset);
    SHELLSPLIT_COMPARE_FIELD(cwd_known);
    SHELLSPLIT_COMPARE_FIELD(cwd_absolute);
  }
  if (a->kind == SHELL_DOC_HEREDOC || a->kind == SHELL_DOC_ENVVAR) {
    SHELLSPLIT_COMPARE_FIELD(name);
    SHELLSPLIT_COMPARE_FIELD(name_len);
  }
  if (a->kind != SHELL_DOC_FILE ||
      (a->flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH)) {
    SHELLSPLIT_COMPARE_FIELD(value);
    SHELLSPLIT_COMPARE_FIELD(value_len);
  }
  return NULL;
}

static inline SHELL_NONNULL(1, 2) const
    char *shellsplit_test_node_difference(const shell_dep_node_t *a,
                                          const shell_dep_node_t *b) {
  SHELLSPLIT_COMPARE_FIELD(type);
  switch (a->type) {
  case SHELL_NODE_CMD:
    SHELLSPLIT_COMPARE_FIELD(cmd.kind);
    SHELLSPLIT_COMPARE_FIELD(cmd.conditional_expression);
    SHELLSPLIT_COMPARE_FIELD(cmd.conditional_expression_length);
    SHELLSPLIT_COMPARE_FIELD(cmd.conditional_operands[0]);
    SHELLSPLIT_COMPARE_FIELD(cmd.conditional_operand_lengths[0]);
    SHELLSPLIT_COMPARE_FIELD(cmd.conditional_operands[1]);
    SHELLSPLIT_COMPARE_FIELD(cmd.conditional_operand_lengths[1]);
    SHELLSPLIT_COMPARE_FIELD(cmd.conditional_operand_count);
    SHELLSPLIT_COMPARE_FIELD(cmd.conditional_predicate);
    SHELLSPLIT_COMPARE_FIELD(cmd.conditional_negated);
    SHELLSPLIT_COMPARE_FIELD(cmd.conditional_truth);
    SHELLSPLIT_COMPARE_FIELD(cmd.arithmetic_expression);
    SHELLSPLIT_COMPARE_FIELD(cmd.arithmetic_expression_length);
    SHELLSPLIT_COMPARE_FIELD(cmd.arithmetic_truth);
    SHELLSPLIT_COMPARE_FIELD(cmd.has_redirections);
    SHELLSPLIT_COMPARE_FIELD(cmd.token_count);
    for (uint32_t i = 0; i < a->cmd.token_count; i++) {
      SHELLSPLIT_COMPARE_FIELD(cmd.tokens[i]);
      SHELLSPLIT_COMPARE_FIELD(cmd.token_lens[i]);
    }
    SHELLSPLIT_COMPARE_FIELD(cmd.effective_command_known);
    if (a->cmd.effective_command_known)
      SHELLSPLIT_COMPARE_FIELD(cmd.effective_command_token);
    SHELLSPLIT_COMPARE_FIELD(cmd.effective_command_wrapper);
    SHELLSPLIT_COMPARE_FIELD(cmd.cwd_offset);
    SHELLSPLIT_COMPARE_FIELD(cmd.group_depth);
    SHELLSPLIT_COMPARE_FIELD(cmd.group_kinds);
    SHELLSPLIT_COMPARE_FIELD(cmd.backgrounded);
    SHELLSPLIT_COMPARE_FIELD(cmd.pipeline_negation_count);
    SHELLSPLIT_COMPARE_FIELD(cmd.pipeline_negated);
    SHELLSPLIT_COMPARE_FIELD(cmd.pipeline_time_mode);
    SHELLSPLIT_COMPARE_FIELD(cmd.pipeline_time_id);
    SHELLSPLIT_COMPARE_FIELD(cmd.cwd_known);
    SHELLSPLIT_COMPARE_FIELD(cmd.cwd_absolute);
    SHELLSPLIT_COMPARE_FIELD(cmd.pipe_stdin_source);
    SHELLSPLIT_COMPARE_FIELD(cmd.pipe_stdin_target);
    SHELLSPLIT_COMPARE_FIELD(cmd.pipe_stdout_source);
    SHELLSPLIT_COMPARE_FIELD(cmd.pipe_stdout_target);
    break;
  case SHELL_NODE_DOC:
    return shellsplit_test_doc_difference(&a->doc, &b->doc);
  case SHELL_NODE_GROUP:
    SHELLSPLIT_COMPARE_FIELD(group.start);
    SHELLSPLIT_COMPARE_FIELD(group.length);
    SHELLSPLIT_COMPARE_FIELD(group.parent);
    SHELLSPLIT_COMPARE_FIELD(group.kind);
    SHELLSPLIT_COMPARE_FIELD(group.pipeline_negation_count);
    SHELLSPLIT_COMPARE_FIELD(group.pipeline_negated);
    SHELLSPLIT_COMPARE_FIELD(group.pipeline_time_mode);
    SHELLSPLIT_COMPARE_FIELD(group.pipeline_time_id);
    break;
  case SHELL_NODE_TIME:
    SHELLSPLIT_COMPARE_FIELD(time.start);
    SHELLSPLIT_COMPARE_FIELD(time.length);
    SHELLSPLIT_COMPARE_FIELD(time.mode);
    SHELLSPLIT_COMPARE_FIELD(time.report_fd);
    SHELLSPLIT_COMPARE_FIELD(time.report_target_fd);
    SHELLSPLIT_COMPARE_FIELD(time.report_route);
    SHELLSPLIT_COMPARE_FIELD(time.report_route_flags);
    SHELLSPLIT_COMPARE_FIELD(time.report_external_fd_count);
    for (uint32_t i = 0; i < a->time.report_external_fd_count; i++)
      SHELLSPLIT_COMPARE_FIELD(time.report_external_fds[i]);
    break;
  case SHELL_NODE_ENDPOINT:
    /* Its reserved byte is opaque construction state, not public semantics. */
    break;
  case SHELL_NODE_FD:
    SHELLSPLIT_COMPARE_FIELD(fd.number);
    break;
  }
  return NULL;
}

static inline SHELL_NONNULL(1, 2) const
    char *shellsplit_test_group_difference(const shell_group_t *a,
                                           const shell_group_t *b) {
  SHELLSPLIT_COMPARE_FIELD(start);
  SHELLSPLIT_COMPARE_FIELD(end);
  SHELLSPLIT_COMPARE_FIELD(first_command);
  SHELLSPLIT_COMPARE_FIELD(command_count);
  SHELLSPLIT_COMPARE_FIELD(parent);
  SHELLSPLIT_COMPARE_FIELD(kind);
  SHELLSPLIT_COMPARE_FIELD(modifiers);
  SHELLSPLIT_COMPARE_FIELD(pipeline_negation_count);
  SHELLSPLIT_COMPARE_FIELD(pipeline_time_mode);
  SHELLSPLIT_COMPARE_FIELD(pipeline_time_direct);
  return NULL;
}

#undef SHELLSPLIT_COMPARE_FIELD

static inline SHELL_NONNULL(1, 2) bool shellsplit_test_groups_equal(
    const shell_group_t *a, const shell_group_t *b, size_t count) {
  for (size_t i = 0; i < count; i++) {
    const char *field = shellsplit_test_group_difference(a + i, b + i);
    if (field) {
      fprintf(stderr, "compound %zu differs: %s\n", i, field);
      return false;
    }
  }
  return true;
}

static inline SHELL_NONNULL(1, 2) bool shellsplit_test_graph_equal(
    const shell_dep_graph_t *a, const shell_dep_graph_t *b) {
  if (a->node_count != b->node_count || a->edge_count != b->edge_count ||
      a->status != b->status || a->cwd_buf.len != b->cwd_buf.len) {
    fprintf(stderr, "graph counts, status or CWD length differ\n");
    return false;
  }
  for (uint32_t i = 0; i < a->node_count; i++) {
    const char *field =
        shellsplit_test_node_difference(a->nodes + i, b->nodes + i);
    if (field) {
      fprintf(stderr, "graph node %u differs: %s\n", i, field);
      return false;
    }
  }
  for (uint32_t i = 0; i < a->edge_count; i++) {
    const char *field =
        shellsplit_test_edge_difference(a->edges + i, b->edges + i);
    if (field) {
      fprintf(stderr, "graph edge %u differs: %s\n", i, field);
      return false;
    }
  }
  if (memcmp(a->cwd_buf.data, b->cwd_buf.data, a->cwd_buf.len) != 0) {
    fprintf(stderr, "graph CWD bytes differ\n");
    return false;
  }
  return true;
}

#endif
