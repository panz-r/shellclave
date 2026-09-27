#include "../src/shell_processor_internal.h"
#include "../src/shell_source_internal.h"
#include "../src/shell_tokenizer_full_internal.h"
#include "depgraph_test_workspace.h"
#include "shell_abstract.h"
#include "shell_depgraph.h"
#include "shell_netstring.h"
#include "shell_processor.h"
#include "shell_sequence.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include "shell_transform.h"

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

  /* A lexer word can contain both literal path text and parameter
   * expansions.  The production target must exercise the same subspan
   * abstraction path as the allocator-instrumented tests: coverage merges
   * source files using the lower result from each target. */
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
        strcmp(shell_abstract_command_get_display_text(multiple_fragments),
               "printf $AP_1$EV_1$AP_2$EV_2") == 0 &&
        multiple_fragments->elements[0]->type == SHELL_ABSTRACT_AP &&
        multiple_fragments->elements[1]->type == SHELL_ABSTRACT_EV &&
        multiple_fragments->elements[2]->type == SHELL_ABSTRACT_AP &&
        multiple_fragments->elements[3]->type == SHELL_ABSTRACT_EV);
  shell_abstract_command_free(multiple_fragments);

  shell_abstract_command_t *parameters = parse_abstract(
      "printf ${VALUE:-fallback} ${#VALUE} ${10} ${?} ${!prefix*} "
      "${!} ${#?} ${!1} ${VALUE:-$(id)} ${VALUE:-<(id)} "
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
   * classifications too. Keep a compact shipping-library matrix so coverage
   * merges do not discard the parser branches that callers actually use. */
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
  CHECK(shell_classify_raw_token(NULL, 0) == SHELL_TOKEN_END);

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
  /* The command substitution is an execution stage in addition to the
   * enclosing command and the brace-group child. */
  CHECK(type_netseq && type_count == 3 &&
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
  static const char continued_named[] = "{f\\\r\nd}\\\n>out";
  size_t marker = (size_t)(strrchr(continued_named, '>') - continued_named);
  size_t operator_position = 0;
  valid =
      valid &&
      shell_source_parse_named_fd(continued_named, 0, strlen(continued_named),
                                  &after) &&
      shell_source_parse_named_fd_redirect(
          continued_named, 0, strlen(continued_named), &operator_position) &&
      operator_position == marker &&
      shell_source_named_fd_start_before(continued_named,
                                         strlen(continued_named), marker) == 0;
  static const char spaced_named[] = "{fd} >out";
  marker = (size_t)(strrchr(spaced_named, '>') - spaced_named);
  valid = valid &&
          shell_source_parse_named_fd(spaced_named, 0, strlen(spaced_named),
                                      &after) &&
          !shell_source_parse_named_fd_redirect(
              spaced_named, 0, strlen(spaced_named), &operator_position) &&
          shell_source_named_fd_start_before(spaced_named, strlen(spaced_named),
                                             marker) == marker;
  valid = valid && shell_source_comment_starts("#x", 2, 0) &&
          shell_source_comment_starts("x;#x", 4, 2) &&
          !shell_source_comment_starts("x#x", 3, 1) &&
          shell_source_line_content_end("line\r\n", 6, 0) == 4 &&
          shell_source_next_line("line\nnext", 9, 0) == 5;
  static const char list_trivia[] = " \\\r\n# note\r\n\t\nstage";
  size_t stage_start = strlen(" \\\r\n# note\r\n\t\n");
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
  valid = valid &&
          !shell_source_ansi_emit_codepoint(capture_source_byte,
                                            &codepoint_rejected, 0x800) &&
          codepoint_rejected.length == 1 &&
          shell_source_skip_ansi_c_quote("plain", 5, 0) == 0 &&
          !shell_source_skip_complete_ansi_c_quote("$'unterminated", 14, 0,
                                                   &after) &&
          !shell_source_skip_complete_ansi_c_quote("$'x'", 4, 0, NULL) &&
          !shell_source_decode_ansi_c_quote(NULL, 0, &position,
                                            capture_source_byte, &capture);
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
      {"printf \\$(id)", false},
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
    char *sequence = NULL;
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
    CHECK(shell_build_netargv_sequence(input, length, NULL, &sequence,
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
    free(sequence);
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
  bool valid = shell_processed_commands_parse(NULL, 0, NULL, &commands,
                                              &count) == SHELL_PROCESS_EINPUT &&
               shell_processed_commands_parse("echo", 4, NULL, NULL, &count) ==
                   SHELL_PROCESS_EINPUT &&
               shell_processed_commands_parse("echo", 4, NULL, &commands,
                                              NULL) == SHELL_PROCESS_EINPUT;

  commands = (shell_command_t *)(uintptr_t)1;
  count = SIZE_MAX;
  valid = valid &&
          shell_processed_commands_parse("echo value", strlen("echo value"),
                                         &short_record, &commands, &count) ==
              SHELL_PROCESS_EOUTPUT_LIMIT &&
          commands == NULL && count == 0;
  commands = (shell_command_t *)(uintptr_t)1;
  count = SIZE_MAX;
  valid = valid &&
          shell_processed_commands_parse("echo value", strlen("echo value"),
                                         &short_total, &commands, &count) ==
              SHELL_PROCESS_EOUTPUT_LIMIT &&
          commands == NULL && count == 0;

  commands = NULL;
  count = 0;
  shell_processed_word_iterator_t iterator;
  shell_token_t word;
  valid =
      valid &&
      shell_processed_commands_parse("left |& right", strlen("left |& right"),
                                     NULL, &commands,
                                     &count) == SHELL_PROCESS_OK &&
      commands != NULL && count == 2 &&
      shell_processed_command_word_count(&commands[0]) == 1 &&
      (shell_processed_word_iterator_init(&iterator, &commands[0]),
       shell_processed_word_iterator_next(&iterator, &word)) &&
      !shell_processed_word_iterator_next(&iterator, &word) &&
      shell_processed_command_has_pipe_output(&commands[0]) &&
      shell_processed_command_has_dangerous_features(&commands[1], true) &&
      !shell_processed_command_is_group_structure(
          commands, count, 0, "left |& right", sizeof("left |& right") - 1) &&
      !shell_processed_command_is_group_structure(NULL, 0, 0, NULL, 0);
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

  infos = NULL;
  info_count = 0;
  rendered = NULL;
  netargv_length = SIZE_MAX;
  CHECK(shell_process_command("> /tmp/out", strlen("> /tmp/out"), NULL, &infos,
                              &info_count) == SHELL_PROCESS_OK &&
        infos != NULL && info_count == 1 && infos[0].command_token_count == 0 &&
        infos[0].has_redirections &&
        shell_measure_netargv(&infos[0], &netargv_length) == SHELL_PROCESS_OK &&
        netargv_length == 0 &&
        shell_render_netargv(&infos[0], NULL, &rendered) == SHELL_PROCESS_OK &&
        rendered != NULL && strcmp(rendered, "") == 0);
  free(rendered);
  shell_command_infos_free(infos, info_count);

  CHECK(shell_measure_decoded_word(NULL, 0, &written) == SHELL_PROCESS_EINPUT &&
        shell_write_decoded_word("word", 4, netargv, 0, &written) ==
            SHELL_PROCESS_EOUTPUT_LIMIT &&
        shell_decode_word(NULL, 0, &rendered, &written) ==
            SHELL_PROCESS_EINPUT &&
        rendered == NULL && written == 0);

  /* The shipping library retains binary canonical argv supplied directly,
   * while complete source with an ANSI-C NUL is rejected by default. */
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
  char *legacy_argv = (char *)(uintptr_t)1;
  char *legacy_sequence = (char *)(uintptr_t)1;
  size_t records = 0;
  size_t sequence_count = 0;
  bool has_features = true;
  infos = NULL;
  info_count = 0;
  CHECK(shell_process_command(binary_source, sizeof(binary_source) - 1, NULL,
                              &infos, &info_count) == SHELL_PROCESS_EPARSE &&
        infos == NULL && info_count == 0 &&
        shell_render_netargv_buffer(&binary_info, NULL, &binary_argv) ==
            SHELL_PROCESS_OK &&
        shell_netstring_validate(binary_argv.data, binary_argv.length,
                                 &records) == SHELL_NETSTRING_OK &&
        records == 2 && memchr(binary_argv.data, '\0', binary_argv.length) &&
        shell_render_netargv(&binary_info, NULL, &legacy_argv) ==
            SHELL_PROCESS_EOUTPUT_LIMIT &&
        legacy_argv == NULL &&
        shell_build_netargv_sequence_buffer(
            binary_source, sizeof(binary_source) - 1, NULL, &binary_sequence,
            &sequence_count, &has_features) == SHELL_PROCESS_EPARSE &&
        sequence_count == 0 && !has_features && binary_sequence.data == NULL &&
        binary_sequence.length == 0 &&
        shell_build_netargv_sequence(binary_source, sizeof(binary_source) - 1,
                                     NULL, &legacy_sequence, &sequence_count,
                                     &has_features) == SHELL_PROCESS_EPARSE &&
        legacy_sequence == NULL && sequence_count == 0 && !has_features);
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

  /* A canonical policy argv requires a program word. Redirect-only source is
   * still a real anomaly stage, but deliberately cannot become a netargv
   * command. Compound-tail redirects must likewise remain structural rather
   * than becoming a phantom second argv record. */
  char *no_argv = (char *)(uintptr_t)1;
  size_t no_argv_count = SIZE_MAX;
  bool no_argv_features = true;
  shell_processed_commands_t redirect_only = {0};
  shell_netstring_buffer_t grouped_sequence = {0};
  size_t grouped_count = 0;
  bool grouped_features = false;
  CHECK(shell_build_netargv_sequence(">out", strlen(">out"), NULL, &no_argv,
                                     &no_argv_count, &no_argv_features) ==
            SHELL_PROCESS_EPARSE &&
        no_argv == NULL && no_argv_count == 0 && !no_argv_features &&
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

  /* Byte-buffer outputs are single-use ownership objects. Rejecting an
   * occupied destination prevents a failed render from overwriting caller
   * storage or leaking an earlier canonical record. */
  unsigned char marker = 0xa5;
  shell_netstring_buffer_t occupied = {.data = &marker, .length = 1};
  infos = NULL;
  info_count = 0;
  CHECK(shell_process_command("echo value", strlen("echo value"), NULL, &infos,
                              &info_count) == SHELL_PROCESS_OK &&
        infos != NULL && info_count == 1 &&
        shell_render_netargv_buffer(&infos[0], NULL, &occupied) ==
            SHELL_PROCESS_EINPUT &&
        occupied.data == &marker && occupied.length == 1);
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
      {"$'a\\0b'", SHELL_PROCESS_FD_TARGET_INVALID, SHELL_PROCESS_FD_NONE},
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
      {"\"\\\r\n\"$var", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"$'unterminated$var", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"prefix<(unterminated", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"{one,two}", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"@(one|two)", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"$value", SHELL_PROCESS_LEGACY_REDIRECT_DUPLICATION},
      {"2147483648", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"00000000000000000000000000000000002147483648",
       SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"\"\"", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"$'a\\0b'", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"$'a\\0b'$var", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
  };
  for (size_t i = 0; i < sizeof(legacy_cases) / sizeof(legacy_cases[0]); i++)
    CHECK(shell_process_classify_legacy_output_target(
              legacy_cases[i].word, strlen(legacy_cases[i].word)) ==
          legacy_cases[i].kind);
  CHECK(shell_process_classify_legacy_output_target(NULL, 0) ==
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
    char *netargv_sequence = NULL;
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
          shell_build_netargv_sequence(prefixed_dynamic_direct[i], input_length,
                                       NULL, &netargv_sequence, &netargv_count,
                                       &has_features) == SHELL_PROCESS_OK &&
          netargv_sequence != NULL && netargv_count == 1);
    free(netargv_sequence);
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
      "printf x >&\"\"",
      "printf x >&$'a\\0b'",
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
    char *netargv_sequence = (char *)(uintptr_t)1;
    size_t netargv_count = SIZE_MAX;
    bool has_features = true;
    char *command_netseq = (char *)(uintptr_t)1;
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
          shell_build_netargv_sequence(invalid_static_direct[i], input_length,
                                       NULL, &netargv_sequence, &netargv_count,
                                       &has_features) == SHELL_PROCESS_EPARSE &&
          netargv_sequence == NULL && netargv_count == 0 && !has_features &&
          shell_build_command_netseq(
              invalid_static_direct[i], input_length, NULL, &command_netseq,
              &command_netseq_count) == SHELL_PROCESS_EPARSE &&
          command_netseq == NULL && command_netseq_count == 0 &&
          shell_anomaly_stages_parse(invalid_static_direct[i], input_length,
                                     NULL, &stages) == SHELL_PROCESS_EPARSE &&
          stages.commands == NULL && stages.count == 0);
  }

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
  char *close_suffix_netargv = NULL;
  shell_dep_graph_t close_suffix_graph = {0};
  const char close_suffix[] = "printf x >&-file";
  CHECK(shell_process_command(close_suffix, sizeof(close_suffix) - 1, NULL,
                              &close_suffix_infos,
                              &close_suffix_count) == SHELL_PROCESS_OK &&
        close_suffix_count == 1 && close_suffix_infos != NULL &&
        shell_render_netargv(&close_suffix_infos[0], NULL,
                             &close_suffix_netargv) == SHELL_PROCESS_OK &&
        strcmp(close_suffix_netargv, "6:printf,1:x,4:file,") == 0 &&
        shell_dep_graph_parse(close_suffix, sizeof(close_suffix) - 1, ".", NULL,
                              &close_suffix_graph) == SHELL_DEP_OK &&
        shell_dep_graph_validate(&close_suffix_graph).valid);
  free(close_suffix_netargv);
  shell_command_infos_free(close_suffix_infos, close_suffix_count);

  static const char *const group_cases[] = {
      "{ printf x; } >&0000000000000000000000000000000000000001",
      "{ printf x; } >&$'0000000000000000000000000000000000000001'",
      "{ printf x; } >&123file",
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
      "{ printf x; } >&$'a\\0b'",
      "{ printf x; } >&-file",
      "{ printf x; } >&",
      "{ printf x; } 2>&combined",
      "{ printf x; } {sink}>&combined",
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
      "! \\\r\nprintf x |& cat",
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
      writes += graph.edges[edge].type == SHELL_EDGE_WRITE;
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
      {"! printf x |& cat", 2},      {"{ echo ok; } >/tmp/out", 1},
      {"cat <<EOF\nbody\nEOF\n", 1}, {"cat < <(printf x)", 1},
      {"printf x &> >(cat)", 1},     {"exec {fd}>out; printf x >&\"${fd}\"", 2},
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
    CHECK(shell_build_netargv_sequence_buffer(
              input, input_length, NULL, &sequence, &sequence_count,
              &has_features) == SHELL_PROCESS_OK);
    CHECK(sequence_count == valid_list_forms[i].executable_count);
    CHECK(shell_netstring_validate(sequence.data, sequence.length, NULL) ==
          SHELL_NETSTRING_OK);
    shell_netstring_buffer_free(&sequence);
    shell_processed_commands_free(&processed);
  }
  static const char *const invalid_list_forms[] = {
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
      "items[0]=one",
      "select item in one; do :; done",
      "coproc worker { echo ok; }",
      "case value in x) : ;& esac",
      "case value in x) : ;;& esac",
      "[[ -f /tmp/x ]]",
      "VALUE=x [[ $VALUE == x ]]",
      "{ [[ -n value ]]; }",
      "echo $( [[ -f /tmp/x ]] )",
      "(( count += 1 ))",
      "! (( 1 ))",
      "{ (( 1 )); }",
      "time echo x",
      "time -p echo x",
      "VALUE=x time echo x",
      "! time false",
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
      "[[ -f /tmp/x ]]",
      "(( 1 + 1 ))",
      "time -p echo x",
      "echo $\"localized\"",
      "worker () { :; }",
      "worker ( ) { :; }",
      "function worker () { :; }",
      "worker ( ) ( : )",
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
      "cmd |",
      "cmd |&",
      "cmd | ! next",
      "cmd && && next",
      "{ ; }",
      "()",
      "worker (",
      "worker ( x ) { :; }",
      "9worker () { :; }",
      "cmd >\noutput",
      "cmd > # note",
      "cmd <<<\nword",
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
  test_production_source_scanner_contract();
  test_substitution_metadata_agreement();
  test_production_record_parser_contract();
  test_processed_command_conveniences();
  test_production_processor_routing_contract();
  test_production_fd_target_contract();
  test_modern_shell_syntax_boundaries();
  test_full_tokenizer_structural_matrix();
  test_transform_api();
  return failures == 0 ? 0 : 1;
}
