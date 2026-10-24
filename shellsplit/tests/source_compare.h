/* Semantic comparison of source metadata over the same borrowed source.
 * Required inputs have bounded counts and initialized meaningful fields.
 * Metadata values may differ; these helpers do not require parser provenance
 * or valid topology. They never admit fabricated metadata to a library API.
 * Padding and unused capacity are unspecified, not a serialization format.
 * In particular, C struct assignment need not preserve padding bytes.
 * This header is shared by C tests and the C++ fuzz harness, not installed. */
#ifndef SHELLSPLIT_SOURCE_COMPARE_H
#define SHELLSPLIT_SOURCE_COMPARE_H

#include "depgraph_compare.h"
#include "shell_source.h"

#define SHELLSPLIT_SOURCE_FIELD(field)                                         \
  do {                                                                         \
    if (a->field != b->field)                                                  \
      return #field;                                                           \
  } while (0)

static inline SHELL_NONNULL(1, 2) const
    char *shellsplit_test_range_difference(const shell_range_t *a,
                                           const shell_range_t *b) {
  SHELLSPLIT_SOURCE_FIELD(start);
  SHELLSPLIT_SOURCE_FIELD(len);
  SHELLSPLIT_SOURCE_FIELD(type);
  SHELLSPLIT_SOURCE_FIELD(kind);
  SHELLSPLIT_SOURCE_FIELD(modifiers);
  SHELLSPLIT_SOURCE_FIELD(pipeline_negation_count);
  SHELLSPLIT_SOURCE_FIELD(pipeline_time_mode);
  SHELLSPLIT_SOURCE_FIELD(pipeline_time_direct);
  SHELLSPLIT_SOURCE_FIELD(pipe_input_mode);
  SHELLSPLIT_SOURCE_FIELD(features);
  SHELLSPLIT_SOURCE_FIELD(group_depth);
  SHELLSPLIT_SOURCE_FIELD(group_kinds);
  return NULL;
}

static inline SHELL_NONNULL(1, 2) const
    char *shellsplit_test_parse_difference(const shell_parse_result_t *a,
                                           const shell_parse_result_t *b) {
  SHELLSPLIT_SOURCE_FIELD(count);
  SHELLSPLIT_SOURCE_FIELD(group_count);
  SHELLSPLIT_SOURCE_FIELD(status);
  for (uint32_t i = 0; i < a->count; i++) {
    const char *field =
        shellsplit_test_range_difference(a->cmds + i, b->cmds + i);
    if (field)
      return field;
  }
  for (uint32_t i = 0; i < a->group_count; i++) {
    const char *field =
        shellsplit_test_group_difference(a->groups + i, b->groups + i);
    if (field)
      return field;
  }
  return NULL;
}

static inline SHELL_NONNULL(1, 2) const
    char *shellsplit_test_header_difference(const shell_source_header_t *a,
                                            const shell_source_header_t *b) {
  SHELLSPLIT_SOURCE_FIELD(source.start);
  SHELLSPLIT_SOURCE_FIELD(source.length);
  SHELLSPLIT_SOURCE_FIELD(kind);
  SHELLSPLIT_SOURCE_FIELD(arithmetic_expression.start);
  SHELLSPLIT_SOURCE_FIELD(arithmetic_expression.length);
  SHELLSPLIT_SOURCE_FIELD(word_count);
  SHELLSPLIT_SOURCE_FIELD(assignment_count);
  SHELLSPLIT_SOURCE_FIELD(first_redirect);
  SHELLSPLIT_SOURCE_FIELD(redirect_count);
  SHELLSPLIT_SOURCE_FIELD(group_depth);
  SHELLSPLIT_SOURCE_FIELD(complete);
  SHELLSPLIT_SOURCE_FIELD(compound);
  for (uint32_t i = 0; i < a->word_count; i++) {
    SHELLSPLIT_SOURCE_FIELD(words[i].start);
    SHELLSPLIT_SOURCE_FIELD(words[i].length);
  }
  return NULL;
}

static inline SHELL_NONNULL(1, 2) const
    char *shellsplit_test_io_difference(const shell_group_io_op_t *a,
                                        const shell_group_io_op_t *b) {
  SHELLSPLIT_SOURCE_FIELD(group_index);
  SHELLSPLIT_SOURCE_FIELD(source_start);
  SHELLSPLIT_SOURCE_FIELD(source_end);
  SHELLSPLIT_SOURCE_FIELD(operand_start);
  SHELLSPLIT_SOURCE_FIELD(operand_end);
  SHELLSPLIT_SOURCE_FIELD(fd);
  SHELLSPLIT_SOURCE_FIELD(target_fd);
  SHELLSPLIT_SOURCE_FIELD(fd_name_start);
  SHELLSPLIT_SOURCE_FIELD(fd_name_end);
  SHELLSPLIT_SOURCE_FIELD(target_name_start);
  SHELLSPLIT_SOURCE_FIELD(target_name_end);
  SHELLSPLIT_SOURCE_FIELD(kind);
  return NULL;
}

static inline SHELL_NONNULL(1, 2) const
    char *shellsplit_test_redirect_difference(
        const shell_source_redirect_t *a, const shell_source_redirect_t *b) {
  SHELLSPLIT_SOURCE_FIELD(header);
  SHELLSPLIT_SOURCE_FIELD(next);
  SHELLSPLIT_SOURCE_FIELD(heredoc);
  return shellsplit_test_io_difference(&a->io, &b->io);
}

static inline SHELL_NONNULL(1, 2) const
    char *shellsplit_test_heredoc_difference(const shell_source_heredoc_t *a,
                                             const shell_source_heredoc_t *b) {
  SHELLSPLIT_SOURCE_FIELD(header);
  SHELLSPLIT_SOURCE_FIELD(redirect);
  SHELLSPLIT_SOURCE_FIELD(declaration.start);
  SHELLSPLIT_SOURCE_FIELD(declaration.length);
  SHELLSPLIT_SOURCE_FIELD(delimiter_word.start);
  SHELLSPLIT_SOURCE_FIELD(delimiter_word.length);
  SHELLSPLIT_SOURCE_FIELD(closing_delimiter.start);
  SHELLSPLIT_SOURCE_FIELD(closing_delimiter.length);
  SHELLSPLIT_SOURCE_FIELD(body_start);
  SHELLSPLIT_SOURCE_FIELD(confirmed_length);
  SHELLSPLIT_SOURCE_FIELD(header_complete);
  SHELLSPLIT_SOURCE_FIELD(body_started);
  SHELLSPLIT_SOURCE_FIELD(complete);
  SHELLSPLIT_SOURCE_FIELD(delimiter_prefix);
  return shellsplit_test_doc_difference(&a->content, &b->content);
}

#undef SHELLSPLIT_SOURCE_FIELD

#define SHELLSPLIT_SOURCE_EQUAL(name, type)                                    \
  static inline SHELL_NONNULL(1, 2) bool shellsplit_test_##name##_equal(       \
      const type *a, const type *b) {                                          \
    const char *field = shellsplit_test_##name##_difference(a, b);             \
    if (field)                                                                 \
      fprintf(stderr, "source " #name " differs: %s\n", field);                \
    return field == NULL;                                                      \
  }

SHELLSPLIT_SOURCE_EQUAL(parse, shell_parse_result_t)
SHELLSPLIT_SOURCE_EQUAL(header, shell_source_header_t)
SHELLSPLIT_SOURCE_EQUAL(io, shell_group_io_op_t)
SHELLSPLIT_SOURCE_EQUAL(redirect, shell_source_redirect_t)
SHELLSPLIT_SOURCE_EQUAL(heredoc, shell_source_heredoc_t)

#undef SHELLSPLIT_SOURCE_EQUAL
#endif
