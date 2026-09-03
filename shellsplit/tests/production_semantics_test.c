#include "shell_abstract.h"
#include "shell_netstring.h"
#include "shell_sequence.h"
#include "shell_tokenizer_full.h"
#include "shell_transform.h"

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

  CHECK(shell_classify_raw_token(NULL, 0) == SHELL_TOKEN_END);
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

  shell_abstract_command_t *syntax =
      parse_abstract("printf '%s' $(printf nested) `printf tick` $((1 + 2)) "
                     "> /tmp/out 2>> /tmp/err < /tmp/in <> /tmp/read-write "
                     ">| /tmp/clobber <<< word");
  CHECK(syntax && syntax->has_cmd_subst && syntax->has_arithmetic &&
        syntax->has_redirects && has_type(syntax, SHELL_ABSTRACT_CS) &&
        has_type(syntax, SHELL_ABSTRACT_AR) &&
        has_type(syntax, SHELL_ABSTRACT_REDIR));
  shell_abstract_command_free(syntax);

  CHECK(shell_abstract_command_parse(NULL, 0, NULL) == SHELL_ABSTRACT_EINPUT);
  CHECK(shell_abstract_command_parse("echo '", strlen("echo '"), NULL) ==
        SHELL_ABSTRACT_EINPUT);
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
  CHECK(!shell_abstract_command_expand(NULL, &context));
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
  char *type_netseq = NULL;
  char *command_netseq = NULL;
  char *anomaly_type_netseq = NULL;
  size_t count = 0;
  size_t type_count = 0;
  size_t record_count = 0;
  CHECK(shell_build_type_netseq(input, strlen(input), NULL, &type_netseq,
                                &type_count) == SHELL_PROCESS_OK);
  CHECK(type_netseq && type_count == 2 &&
        shell_netstring_validate(type_netseq, strlen(type_netseq),
                                 &record_count) == SHELL_NETSTRING_OK &&
        record_count == type_count);
  CHECK(shell_build_anomaly_netseqs(input, strlen(input), NULL, &command_netseq,
                                    &anomaly_type_netseq,
                                    &count) == SHELL_PROCESS_OK);
  CHECK(command_netseq && anomaly_type_netseq && count == type_count &&
        shell_netstring_validate(command_netseq, strlen(command_netseq),
                                 NULL) == SHELL_NETSTRING_OK &&
        shell_netstring_validate(anomaly_type_netseq,
                                 strlen(anomaly_type_netseq),
                                 NULL) == SHELL_NETSTRING_OK);
  free(type_netseq);
  free(command_netseq);
  free(anomaly_type_netseq);

  const shell_process_limits_t tiny = {1, SIZE_MAX, 0};
  type_netseq = NULL;
  count = 0;
  CHECK(shell_build_type_netseq("echo value", strlen("echo value"), &tiny,
                                &type_netseq,
                                &count) == SHELL_PROCESS_EOUTPUT_LIMIT);
  CHECK(type_netseq == NULL && count == 0);
  command_netseq = NULL;
  anomaly_type_netseq = NULL;
  CHECK(shell_build_anomaly_netseqs("while true; do :; done",
                                    strlen("while true; do :; done"), NULL,
                                    &command_netseq, &anomaly_type_netseq,
                                    &count) == SHELL_PROCESS_EPARSE);
  CHECK(command_netseq == NULL && anomaly_type_netseq == NULL && count == 0);
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

static void test_processed_command_conveniences(void) {
  static const char input[] = "printf 'two words' > /tmp/out";
  shell_command_info_t *infos = NULL;
  size_t info_count = 0;
  size_t netargv_length = 0;
  size_t written = 0;
  char netargv[64] = {0};
  char *rendered = NULL;
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
        shell_render_netargv(&infos[0], NULL, &rendered) == SHELL_PROCESS_OK &&
        strcmp(netargv, rendered) == 0);
  free(rendered);

  const shell_process_limits_t tiny = {1, SIZE_MAX, 0};
  CHECK(shell_write_netargv(&infos[0], netargv, netargv_length, &written) ==
            SHELL_PROCESS_EOUTPUT_LIMIT &&
        shell_render_netargv(&infos[0], &tiny, &rendered) ==
            SHELL_PROCESS_EOUTPUT_LIMIT &&
        rendered == NULL);
  shell_command_infos_free(infos, info_count);

  infos = NULL;
  info_count = 0;
  CHECK(shell_process_command("echo value", strlen("echo value"), &tiny, &infos,
                              &info_count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
        infos == NULL && info_count == 0);
  CHECK(shell_measure_decoded_word(NULL, 0, &written) == SHELL_PROCESS_EINPUT &&
        shell_write_decoded_word("word", 4, netargv, 0, &written) ==
            SHELL_PROCESS_EOUTPUT_LIMIT &&
        shell_decode_word(NULL, 0, &rendered, &written) ==
            SHELL_PROCESS_EINPUT &&
        rendered == NULL && written == 0);
}

static void test_transform_api(void) {
  static const char *const inputs[] = {
      "echo $HOME",
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
            commands[j]->token_count > 0 &&
            shell_transformed_command_get_display_text(commands[j]) ==
                commands[j]->display_text);
    }
    shell_transformed_command_list_free(commands, count);
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
  CHECK(shell_transform_command_line(NULL, 0, NULL, &commands, &count) ==
        SHELL_TRANSFORM_EINPUT);
  CHECK(shell_transform_command_line("echo '", strlen("echo '"), NULL,
                                     &commands,
                                     &count) == SHELL_TRANSFORM_EPARSE);
  CHECK(shell_transform_command_line("echo", 4, NULL, NULL, &count) ==
        SHELL_TRANSFORM_EINPUT);
  CHECK(shell_transformed_command_get_display_text(NULL) == NULL);
  CHECK(!shell_transformed_command_has_transformations(NULL));
  shell_transformed_command_list_free(NULL, 0);
}

int main(void) {
  test_raw_token_classification();
  test_abstraction_shapes();
  test_abstraction_expansion();
  test_path_categories();
  test_canonical_sequences();
  test_netstring_error_boundaries();
  test_processed_command_conveniences();
  test_transform_api();
  return failures == 0 ? 0 : 1;
}
