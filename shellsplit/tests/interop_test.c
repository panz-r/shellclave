#include "shell_interop.h"
#include "shell_tokenizer.h"

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

static void test_parse_matrix(void) {
  static const char input[] = "echo $USER | grep *.txt && pwd";
  static const struct {
    const char *text;
    int type;
    int required_features;
  } expected[] = {
      {"echo $USER", SHELL_TYPE_SIMPLE, SHELL_FEAT_VARS},
      {"grep *.txt", SHELL_TYPE_PIPELINE, SHELL_FEAT_GLOBS},
      {"pwd", SHELL_TYPE_AND, 0},
  };

  shell_interop_handle_t *handle = shell_interop_create();
  CHECK(handle != NULL);
  if (!handle)
    return;
  CHECK(shell_interop_parse(handle, input, (int)strlen(input)) ==
        (int)(sizeof(expected) / sizeof(expected[0])));
  CHECK(shell_interop_subcommand_count(handle) ==
        (int)(sizeof(expected) / sizeof(expected[0])));

  for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
    const char *location = strstr(input, expected[i].text);
    CHECK(location != NULL);
    CHECK(shell_interop_subcommand_type(handle, (int)i) == expected[i].type);
    CHECK((shell_interop_subcommand_features(handle, (int)i) &
           expected[i].required_features) == expected[i].required_features);
    CHECK(shell_interop_subcommand_start(handle, (int)i) == location - input);
    CHECK(shell_interop_subcommand_len(handle, (int)i) ==
          (int)strlen(expected[i].text));
    char *copy = shell_interop_subcommand_str(handle, (int)i);
    CHECK(copy != NULL && strcmp(copy, expected[i].text) == 0);
    shell_interop_free_str(copy);
  }

  char *owned = shell_interop_subcommand_str(handle, 1);
  CHECK(shell_interop_parse(handle, "pwd", 3) == 1);
  CHECK(owned != NULL && strcmp(owned, "grep *.txt") == 0);
  shell_interop_free_str(owned);
  shell_interop_destroy(handle);
}

static void test_failure_and_length_boundaries(void) {
  shell_interop_handle_t *handle = shell_interop_create();
  CHECK(handle != NULL);
  if (!handle)
    return;

  static const char embedded_nul[] = {'p', 'w', 'd', '\0', ';', 'i', 'd'};
  static const struct {
    const char *command;
    int length;
    int result;
  } invalid[] = {{NULL, 7, 0},
                 {"echo ok", 0, 0},
                 {"echo ok", -1, 0},
                 {"${}", 3, 0},
                 {embedded_nul, (int)sizeof(embedded_nul), 0}};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    CHECK(shell_interop_parse(handle, "echo ok", 7) == 1);
    CHECK(shell_interop_parse(handle, invalid[i].command, invalid[i].length) ==
          invalid[i].result);
    CHECK(shell_interop_subcommand_count(handle) == 0);
    CHECK(shell_interop_subcommand_str(handle, 0) == NULL);
  }

  char command[SHELL_INTEROP_BUFFER_SIZE];
  memset(command, 'x', sizeof(command));
  CHECK(shell_interop_parse(handle, command, (int)sizeof(command)) == -1);
  CHECK(shell_interop_subcommand_count(handle) == 0);
  command[sizeof(command) - 1] = '\0';
  CHECK(shell_interop_parse(handle, command, (int)strlen(command)) == 1);
  CHECK(shell_interop_subcommand_len(handle, 0) ==
        SHELL_INTEROP_BUFFER_SIZE - 1);
  char *copy = shell_interop_subcommand_str(handle, 0);
  CHECK(copy != NULL && memcmp(copy, command, sizeof(command)) == 0);
  shell_interop_free_str(copy);
  shell_interop_destroy(handle);
}

static void test_bounded_input_and_handle_isolation(void) {
  static const char bounded[] = {'e', 'c', 'h', 'o', ' ', '$', 'X', 'x'};
  shell_interop_handle_t *first = shell_interop_create();
  shell_interop_handle_t *second = shell_interop_create();
  CHECK(first != NULL && second != NULL);
  if (!first || !second) {
    shell_interop_destroy(first);
    shell_interop_destroy(second);
    return;
  }

  CHECK(shell_interop_parse(first, bounded, 7) == 1);
  CHECK(shell_interop_subcommand_len(first, 0) == 7);
  CHECK(shell_interop_subcommand_features(first, 0) == SHELL_FEAT_VARS);
  char *owned = shell_interop_subcommand_str(first, 0);
  CHECK(owned != NULL && strcmp(owned, "echo $X") == 0);

  CHECK(shell_interop_parse(second, "pwd; whoami", 11) == 2);
  CHECK(shell_interop_parse(first, "id", 2) == 1);
  CHECK(shell_interop_subcommand_count(second) == 2);
  char *second_copy = shell_interop_subcommand_str(second, 1);
  CHECK(second_copy != NULL && strcmp(second_copy, "whoami") == 0);
  CHECK(owned != NULL && strcmp(owned, "echo $X") == 0);

  shell_interop_free_str(second_copy);
  shell_interop_free_str(owned);
  shell_interop_destroy(second);
  shell_interop_destroy(first);
}

static void test_accessors_and_conversions(void) {
  shell_interop_handle_t *handle = shell_interop_create();
  CHECK(handle != NULL && shell_interop_parse(handle, "ls", 2) == 1);
  if (!handle)
    return;
  const int invalid_indices[] = {-1, 1, 99};
  for (size_t i = 0; i < sizeof(invalid_indices) / sizeof(invalid_indices[0]);
       i++) {
    int index = invalid_indices[i];
    CHECK(shell_interop_subcommand_type(handle, index) == 0);
    CHECK(shell_interop_subcommand_features(handle, index) == 0);
    CHECK(shell_interop_subcommand_start(handle, index) == 0);
    CHECK(shell_interop_subcommand_len(handle, index) == 0);
    CHECK(shell_interop_subcommand_str(handle, index) == NULL);
  }

  static const struct {
    int type;
    const char *name;
  } types[] = {{SHELL_TYPE_SIMPLE, "SIMPLE"},
               {SHELL_TYPE_PIPELINE, "PIPE"},
               {SHELL_TYPE_AND, "AND"},
               {SHELL_TYPE_OR, "OR"},
               {SHELL_TYPE_SEMICOLON, "SEMICOLON"},
               {SHELL_TYPE_HEREDOC, "HEREDOC"},
               {SHELL_TYPE_HERESTRING, "HERESTRING"}};
  for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
    char *name = shell_interop_type_str(types[i].type);
    CHECK(name != NULL && strcmp(name, types[i].name) == 0);
    shell_interop_free_str(name);
  }
  static const struct {
    int feature;
    const char *name;
  } feature_names[] = {
      {SHELL_FEAT_VARS, "VAR "},
      {SHELL_FEAT_GLOBS, "GLOB "},
      {SHELL_FEAT_SUBSHELL, "SUBSHELL "},
      {SHELL_FEAT_ARITH, "ARITH "},
      {SHELL_FEAT_HEREDOC, "HEREDOC "},
      {SHELL_FEAT_HERESTRING, "HERESTRING "},
      {SHELL_FEAT_PROCESS_SUB, "PROCSUB "},
      {SHELL_FEAT_LOOPS, "LOOPS "},
      {SHELL_FEAT_CONDITIONALS, "COND "},
      {SHELL_FEAT_CASE, "CASE "},
      {SHELL_FEAT_SUBSHELL_FILE, "SUBSHELL_FILE "},
  };
  int all_features = 0;
  char all_names[256] = "";
  for (size_t i = 0; i < sizeof(feature_names) / sizeof(feature_names[0]);
       i++) {
    char *name = shell_interop_features_str(feature_names[i].feature);
    CHECK(name != NULL && strcmp(name, feature_names[i].name) == 0);
    shell_interop_free_str(name);
    all_features |= feature_names[i].feature;
    strcat(all_names, feature_names[i].name);
  }
  char *features = shell_interop_features_str(all_features);
  CHECK(features != NULL && strcmp(features, all_names) == 0);
  shell_interop_free_str(features);
  features = shell_interop_features_str(1 << 30);
  CHECK(features != NULL && strcmp(features, "none") == 0);
  shell_interop_free_str(features);

  CHECK(shell_interop_parse(NULL, "ls", 2) == 0);
  CHECK(shell_interop_subcommand_count(NULL) == 0);
  CHECK(shell_interop_subcommand_type(NULL, 0) == 0);
  CHECK(shell_interop_subcommand_features(NULL, 0) == 0);
  CHECK(shell_interop_subcommand_start(NULL, 0) == 0);
  CHECK(shell_interop_subcommand_len(NULL, 0) == 0);
  CHECK(shell_interop_subcommand_str(NULL, 0) == NULL);
  shell_interop_free_str(NULL);
  shell_interop_destroy(NULL);
  shell_interop_destroy(handle);
}

int main(void) {
  test_parse_matrix();
  test_failure_and_length_boundaries();
  test_bounded_input_and_handle_isolation();
  test_accessors_and_conversions();
  if (failures)
    fprintf(stderr, "%d interop checks failed\n", failures);
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
