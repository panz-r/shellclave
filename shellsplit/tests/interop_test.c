#include "shell_interop.h"
#include "test_allocator.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,         \
              #condition);                                                     \
      failures++;                                                              \
    }                                                                          \
  } while (0)

static shell_error_t parse(shell_interop_handle_t *handle, const char *text,
                           size_t length, size_t *count) {
  return shell_interop_parse(handle, text, length, count);
}

static void test_parse_and_views(void) {
  static const char input[] = "echo $USER | grep *.txt && pwd";
  static const struct {
    const char *text;
    shell_cmd_type_t type;
    uint32_t features;
  } expected[] = {{"echo $USER", SHELL_TYPE_SIMPLE, SHELL_FEAT_VARS},
                  {"grep *.txt", SHELL_TYPE_PIPELINE,
                   SHELL_FEAT_GLOBS | SHELL_FEAT_PIPELINE},
                  {"pwd", SHELL_TYPE_AND, 0}};
  shell_interop_handle_t *handle = shell_interop_new();
  size_t count = 0;
  CHECK(handle && parse(handle, input, strlen(input), &count) == SHELL_OK);
  CHECK(count == 3 && shell_interop_subcommand_count(handle) == count);

  for (size_t i = 0; handle && i < count; i++) {
    shell_range_t range = {0};
    const char *view = NULL;
    size_t view_length = 0;
    const char *location = strstr(input, expected[i].text);
    CHECK(location && shell_interop_subcommand_range(handle, i, &range));
    CHECK(range.type == expected[i].type &&
          (range.features & expected[i].features) == expected[i].features);
    CHECK(range.start == (uint32_t)(location - input) &&
          range.len == strlen(expected[i].text));
    CHECK(shell_interop_subcommand_view(handle, i, &view, &view_length));
    CHECK(view_length == range.len &&
          memcmp(view, expected[i].text, view_length) == 0);
    char *copy = shell_interop_subcommand_dup(handle, i);
    CHECK(copy && strcmp(copy, expected[i].text) == 0);
    free(copy);
  }

  char *copy = shell_interop_subcommand_dup(handle, 1);
  CHECK(parse(handle, "pwd", 3, &count) == SHELL_OK && count == 1);
  CHECK(copy && strcmp(copy, "grep *.txt") == 0);
  free(copy);
  shell_interop_free(handle);
}

static void test_failures_clear_state(void) {
  shell_interop_handle_t *handle = shell_interop_new();
  size_t count = 99;
  static const char embedded_nul[] = {'p', 'w', 'd', '\0', ';', 'i', 'd'};
  CHECK(handle && parse(handle, "echo ok", 7, &count) == SHELL_OK);
  shell_range_t range = {.len = 1};
  const char *view = (const char *)(void *)1;
  size_t view_length = SIZE_MAX;
  CHECK(!shell_interop_subcommand_range(handle, 1, &range) && range.len == 0);
  CHECK(!shell_interop_subcommand_view(handle, 1, &view, &view_length) &&
        view == NULL && view_length == 0);
  CHECK(parse(handle, "pwd", 3, NULL) == SHELL_EINPUT);
  CHECK(parse(handle, NULL, 0, &count) == SHELL_EINPUT && count == 0);
  CHECK(shell_interop_subcommand_count(handle) == 0);
  CHECK(parse(handle, embedded_nul, sizeof(embedded_nul), &count) ==
        SHELL_EINPUT);
  CHECK(parse(handle, "${}", 3, &count) == SHELL_EPARSE);

  char too_long[SHELL_INTEROP_BUFFER_SIZE];
  memset(too_long, 'x', sizeof(too_long));
  CHECK(parse(handle, too_long, sizeof(too_long), &count) == SHELL_ETRUNC);
  range = (shell_range_t){.len = 1};
  CHECK(!shell_interop_subcommand_range(handle, 0, &range) && range.len == 0);
  CHECK(!shell_interop_subcommand_range(NULL, 0, &range) && range.len == 0);
  CHECK(!shell_interop_subcommand_range(handle, 0, NULL));
  CHECK(!shell_interop_subcommand_view(handle, 0, NULL, &count));
  view = (const char *)(void *)1;
  view_length = SIZE_MAX;
  CHECK(!shell_interop_subcommand_view(handle, 0, &view, NULL) && view == NULL);
  CHECK(!shell_interop_subcommand_view(NULL, 0, &view, &view_length) &&
        view == NULL && view_length == 0);
  CHECK(shell_interop_subcommand_dup(handle, 0) == NULL);
  CHECK(parse(NULL, "ls", 2, &count) == SHELL_EINPUT && count == 0);
  shell_interop_free(handle);
}

static void test_formatters(void) {
  char buffer[128];
  size_t written = 0;
  CHECK(shell_interop_format_features(SHELL_FEAT_VARS | SHELL_FEAT_GLOBS,
                                      buffer, sizeof(buffer),
                                      &written) == SHELL_OK);
  CHECK(written == strlen("VAR GLOB") && strcmp(buffer, "VAR GLOB") == 0);
  CHECK(shell_interop_format_features(0, buffer, sizeof(buffer), &written) ==
            SHELL_OK &&
        strcmp(buffer, "none") == 0);
  CHECK(shell_interop_format_features(0, buffer, sizeof("none") - 1,
                                      &written) == SHELL_ETRUNC &&
        buffer[0] == '\0' && written == 0);
  CHECK(shell_interop_format_features(SHELL_FEAT_VARS, buffer, 2, &written) ==
            SHELL_ETRUNC &&
        buffer[0] == '\0' && written == 0);
  CHECK(shell_interop_format_features(SHELL_FEAT_VARS | SHELL_FEAT_GLOBS,
                                      buffer, 5, &written) == SHELL_ETRUNC &&
        buffer[0] == '\0' && written == 0);
  CHECK(shell_interop_format_features(SHELL_FEAT_VARS, NULL, sizeof(buffer),
                                      &written) == SHELL_EINPUT &&
        written == 0);
  CHECK(shell_interop_format_features(SHELL_FEAT_VARS, buffer, 0, &written) ==
            SHELL_EINPUT &&
        written == 0);
  CHECK(shell_interop_format_features(SHELL_FEAT_VARS, buffer, sizeof(buffer),
                                      NULL) == SHELL_EINPUT);
  CHECK(strcmp(shell_interop_command_type_name(SHELL_TYPE_PIPELINE), "PIPE") ==
        0);
  CHECK(strcmp(shell_interop_command_type_name(SHELL_TYPE_SIMPLE), "SIMPLE") ==
        0);

  static const struct {
    shell_cmd_type_t type;
    const char *name;
  } types[] = {
      {SHELL_TYPE_AND, "AND"},
      {SHELL_TYPE_OR, "OR"},
      {SHELL_TYPE_SEMICOLON, "SEMICOLON"},
      {SHELL_TYPE_HEREDOC, "HEREDOC"},
      {SHELL_TYPE_HERESTRING, "HERESTRING"},
      {SHELL_TYPE_SUBSTITUTION, "SUBSTITUTION"},
      {SHELL_TYPE_BACKGROUND, "BACKGROUND"},
  };
  for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++)
    CHECK(strcmp(shell_interop_command_type_name(types[i].type),
                 types[i].name) == 0);

  const uint32_t all_features =
      SHELL_FEAT_VARS | SHELL_FEAT_GLOBS | SHELL_FEAT_SUBSHELL |
      SHELL_FEAT_ARITH | SHELL_FEAT_HEREDOC | SHELL_FEAT_HERESTRING |
      SHELL_FEAT_PROCESS_SUB | SHELL_FEAT_LOOPS | SHELL_FEAT_CONDITIONALS |
      SHELL_FEAT_CASE | SHELL_FEAT_SUBSHELL_FILE | SHELL_FEAT_PIPELINE |
      SHELL_FEAT_GROUP | SHELL_FEAT_BACKGROUND;
  CHECK(shell_interop_format_features(all_features, buffer, sizeof(buffer),
                                      &written) == SHELL_OK);
  CHECK(written == strlen(buffer) && strstr(buffer, "BACKGROUND") != NULL);
}

static void test_allocation_boundaries(void) {
  shellsplit_test_alloc_fail_at(1);
  CHECK(shell_interop_new() == NULL);
  shellsplit_test_alloc_reset();
  shell_interop_handle_t *handle = shell_interop_new();
  size_t count = 0;
  CHECK(handle && parse(handle, "echo $USER", 10, &count) == SHELL_OK);
  shellsplit_test_alloc_fail_at(1);
  CHECK(shell_interop_subcommand_dup(handle, 0) == NULL);
  shellsplit_test_alloc_reset();
  CHECK(shell_interop_format_features(SHELL_FEAT_VARS, (char[16]){0}, 16,
                                      &count) == SHELL_OK);
  shell_interop_free(handle);
}

int main(void) {
  test_parse_and_views();
  test_failures_clear_state();
  test_formatters();
  test_allocation_boundaries();
  if (failures)
    fprintf(stderr, "%d interop checks failed\n", failures);
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
