#include "source_compare.h"
#include <stddef.h>
#include <stdlib.h>

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

static void ranges(void) {
  shell_range_t a, b;
  memset(&a, 0x55, sizeof(a));
  memset(&b, 0xaa, sizeof(b));
  const char *(*difference)(const shell_range_t *, const shell_range_t *) =
      shellsplit_test_range_difference;
#define FIELDS(F)                                                              \
  F(start, 1, 2)                                                               \
  F(len, 4, 5)                                                                 \
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

static void groups(void) {
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

static void parses(void) {
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

static void headers(void) {
  shell_source_header_t a, b;
  memset(&a, 0x55, sizeof(a));
  memset(&b, 0xaa, sizeof(b));
  const char *(*difference)(const shell_source_header_t *,
                            const shell_source_header_t *) =
      shellsplit_test_header_difference;
#define FIELDS(F)                                                              \
  F(source.start, 1, 2)                                                        \
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

static void io(void) {
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

static void redirects(void) {
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

static void documents(void) {
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

static void heredocs(void) {
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

static void pending_redirector(void) {
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

int main(void) {
  ranges();
  groups();
  parses();
  headers();
  io();
  redirects();
  documents();
  heredocs();
  pending_redirector();
  puts("semantic source comparison tests passed");
  return 0;
}
