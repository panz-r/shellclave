#define _POSIX_C_SOURCE 200809L
#include "shell_abstract.h"
#include "shell_sequence.h"
#include "test_allocator.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed;
static int failed;

static shell_abstract_command_t *parse_command(const char *input) {
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
      passed++;                                                                \
    } else {                                                                   \
      printf("  [FAIL] %s\n", name);                                           \
      failed++;                                                                \
    }                                                                          \
  } while (0)

static void test_bounded_span_and_statuses(void) {
  printf("\n=== Bounded Span and Status Matrix ===\n");

  static const char literal_with_suffix[] = {'e', 'c', 'h', 'o', 'X', '\0'};
  static const char abstract_with_suffix[] = {'c', 'a', 't', ' ', '/',
                                              't', 'm', 'p', 'X', '\0'};
  shell_abstract_command_t *result = NULL;
  bool valid =
      shell_abstract_command_parse(literal_with_suffix, 4, &result) ==
          SHELL_ABSTRACT_OK &&
      result &&
      strcmp(shell_abstract_command_get_source(result), "echo") == 0 &&
      strcmp(shell_abstract_command_get_display_text(result), "echo") == 0;
  shell_abstract_command_free(result);

  result = NULL;
  valid =
      valid &&
      shell_abstract_command_parse(abstract_with_suffix, 8, &result) ==
          SHELL_ABSTRACT_OK &&
      result &&
      strcmp(shell_abstract_command_get_source(result), "cat /tmp") == 0 &&
      strcmp(shell_abstract_command_get_display_text(result), "cat $AP_1") == 0;
  shell_abstract_command_free(result);
  TEST("abstraction honors exact non-terminated spans", valid);

  static const char embedded_nul[] = {'e', 'c', 'h', 'o', '\0', 'x'};
  result = (shell_abstract_command_t *)(void *)1;
  valid = shell_abstract_command_parse(embedded_nul, sizeof(embedded_nul),
                                       &result) == SHELL_ABSTRACT_EINPUT &&
          result == NULL;
  result = (shell_abstract_command_t *)(void *)1;
  valid = valid &&
          shell_abstract_command_parse("echo '", strlen("echo '"), &result) ==
              SHELL_ABSTRACT_EPARSE &&
          result == NULL;
  valid = valid && shell_abstract_command_parse("echo", strlen("echo"), NULL) ==
                       SHELL_ABSTRACT_EINPUT;
  TEST("abstraction reports input and parse failures precisely", valid);
}

static void test_ansi_c_arithmetic_span(void) {
  const char *source = "echo $(( $(printf $'foo\\'bar)') + 1 ))";
  shell_abstract_command_t *result = parse_command(source);
  bool valid = result &&
               strcmp(shell_abstract_command_get_source(result), source) == 0 &&
               strcmp(shell_abstract_command_get_display_text(result),
                      "echo $AR_1") == 0;
  shell_abstract_command_free(result);
  TEST("ANSI-C quote preserves the complete arithmetic abstraction", valid);
}

enum {
  FLAG_VARIABLES = 1u << 0,
  FLAG_POS_VARS = 1u << 1,
  FLAG_SPECIAL_VARS = 1u << 2,
  FLAG_GLOBS = 1u << 3,
  FLAG_PATHS = 1u << 4,
  FLAG_ABS_PATHS = 1u << 5,
  FLAG_REL_PATHS = 1u << 6,
  FLAG_HOME_PATHS = 1u << 7,
  FLAG_CMD_SUBST = 1u << 8,
  FLAG_ARITHMETIC = 1u << 9,
  FLAG_STRINGS = 1u << 10,
  FLAG_REDIRECTS = 1u << 11,
};

static unsigned feature_mask(shell_abstract_command_t *command) {
  return (shell_abstract_command_has_variables(command) ? FLAG_VARIABLES : 0) |
         (shell_abstract_command_has_pos_vars(command) ? FLAG_POS_VARS : 0) |
         (shell_abstract_command_has_special_vars(command) ? FLAG_SPECIAL_VARS
                                                           : 0) |
         (shell_abstract_command_has_globs(command) ? FLAG_GLOBS : 0) |
         (shell_abstract_command_has_paths(command) ? FLAG_PATHS : 0) |
         (shell_abstract_command_has_abs_paths(command) ? FLAG_ABS_PATHS : 0) |
         (shell_abstract_command_has_rel_paths(command) ? FLAG_REL_PATHS : 0) |
         (shell_abstract_command_has_home_paths(command) ? FLAG_HOME_PATHS
                                                         : 0) |
         (shell_abstract_command_has_cmd_subst(command) ? FLAG_CMD_SUBST : 0) |
         (shell_abstract_command_has_arithmetic(command) ? FLAG_ARITHMETIC
                                                         : 0) |
         (shell_abstract_command_has_strings(command) ? FLAG_STRINGS : 0) |
         (shell_abstract_command_has_redirects(command) ? FLAG_REDIRECTS : 0);
}

static bool validate_elements(const char *input,
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

static void test_abstraction_matrix(void) {
  printf("\n=== Exact Abstraction Matrix ===\n");

  static const struct {
    const char *name;
    const char *input;
    const char *expected;
    size_t elements;
    unsigned flags;
  } cases[] = {
      {"literal command", "ls -la", "ls -la", 0, 0},
      {"environment variable", "echo $PATH", "echo $EV_1", 1, FLAG_VARIABLES},
      {"absolute path", "cat /etc/passwd", "cat $AP_1", 1,
       FLAG_PATHS | FLAG_ABS_PATHS},
      {"relative path", "cat ./foo.txt", "cat $RP_1", 1,
       FLAG_PATHS | FLAG_REL_PATHS},
      {"parent-relative path", "cat ../foo.txt", "cat $RP_1", 1,
       FLAG_PATHS | FLAG_REL_PATHS},
      {"home path", "ls ~/documents", "ls $HP_1", 1,
       FLAG_PATHS | FLAG_HOME_PATHS},
      {"glob", "ls *.txt", "ls $GB_1", 1, FLAG_GLOBS},
      {"positional parameter boundaries", "echo $1 $10 ${10}",
       "echo $PV_1 $PV_20 $PV_3", 3, FLAG_VARIABLES | FLAG_POS_VARS},
      {"special parameter family", "echo $? $$ $# $! $@ $* $-",
       "echo $SV_1 $SV_2 $SV_3 $SV_4 $SV_5 $SV_6 $SV_7", 7,
       FLAG_VARIABLES | FLAG_SPECIAL_VARS},
      {"command substitution", "cat $(cat file.txt)", "cat $CS_1", 1,
       FLAG_CMD_SUBST},
      {"backtick substitution", "echo `date`", "echo $CS_1", 1, FLAG_CMD_SUBST},
      {"arithmetic expansion", "echo $((x+1))", "echo $AR_1", 1,
       FLAG_ARITHMETIC},
      {"quoted string", "echo \"hello world\"", "echo $STR_1", 1, FLAG_STRINGS},
      {"quoted variable", "echo \"$USER\"", "echo $EV_1", 1, FLAG_VARIABLES},
      {"embedded quoted variable", "echo \"prefix ${NAME} suffix\"",
       "echo $EV_1", 1, FLAG_VARIABLES},
      {"multiple variables", "grep $USER $HOME/file $PATH",
       "grep $EV_1 $EV_2$AP_1 $EV_3", 4,
       FLAG_VARIABLES | FLAG_PATHS | FLAG_ABS_PATHS},
      {"mixed variables and globs", "grep -i $PATTERN /etc/*.conf ~user/*.txt",
       "grep -i $EV_1 $GB_1 $GB_2", 3, FLAG_VARIABLES | FLAG_GLOBS},
      {"path glob", "ls /var/log/*.log", "ls $GB_1", 1, FLAG_GLOBS},
      {"find expression", "find /var -name *.log -mtime +7",
       "find $AP_1 -name $GB_1 -mtime +7", 2,
       FLAG_PATHS | FLAG_ABS_PATHS | FLAG_GLOBS},
      {"pipeline with adjacent abstractions",
       "tail -f /var/log/$APP.log | grep -i error | head -n 100",
       "tail -f $AP_1$EV_1.log | grep -i error | head -n 100", 2,
       FLAG_VARIABLES | FLAG_PATHS | FLAG_ABS_PATHS},
      {"later sequence stages are abstracted",
       "echo ok && cat /etc/$FILE || diff <(left) >(right)",
       "echo ok && cat $AP_1$EV_1 || diff $CS_1 $CS_2", 4,
       FLAG_VARIABLES | FLAG_PATHS | FLAG_ABS_PATHS | FLAG_CMD_SUBST},
      {"redirection targets", "cat < /tmp/in >out 2>> err 2>&1",
       "cat < $RD_1 >$RD_2 2>> $RD_3 2>&1", 3, FLAG_REDIRECTS},
      {"here-string target", "cat <<< \"$VALUE\"", "cat <<< $RD_1", 1,
       FLAG_REDIRECTS},
      {"clobber redirect target", "echo x >| /tmp/clobber", "echo x >| $RD_1",
       1, FLAG_REDIRECTS},
      {"numbered clobber redirect target", "echo x 2>| /tmp/clobber",
       "echo x 2>| $RD_1", 1, FLAG_REDIRECTS},
      {"heredoc is redirection", "cat <<EOF\npayload\nEOF",
       "cat <<EOF\npayload\nEOF", 0, FLAG_REDIRECTS},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_abstract_command_t *result = parse_command(cases[i].input);
    bool ok = result != NULL;
    bool valid = ok && result &&
                 strcmp(shell_abstract_command_get_source(result),
                        cases[i].input) == 0 &&
                 strcmp(shell_abstract_command_get_display_text(result),
                        cases[i].expected) == 0 &&
                 result->element_count == cases[i].elements &&
                 feature_mask(result) == cases[i].flags &&
                 validate_elements(cases[i].input, result);
    if (!valid && result)
      printf("    got '%s', elements=%zu, flags=0x%x\n", result->display_text,
             result->element_count, feature_mask(result));
    TEST(cases[i].name, valid);
    shell_abstract_command_free(result);
  }
}

static void test_abstraction_allocation_failures(void) {
  static const char input[] =
      "echo $USER /etc/passwd *.txt $(date) $((x+1)) >output";
  shellsplit_test_alloc_reset();
  shell_abstract_command_t *probe = parse_command(input);
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

  char *netseq = NULL;
  size_t count = 0;
  shellsplit_test_alloc_reset();
  shell_process_status_t status =
      shell_build_type_netseq(input, strlen(input), NULL, &netseq, &count);
  allocations = shellsplit_test_alloc_count();
  TEST("type-netsequence allocation probe succeeds",
       status == SHELL_PROCESS_OK && netseq && count == 1);
  free(netseq);

  bool atomic = true;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    netseq = (char *)(void *)1;
    count = SIZE_MAX;
    shellsplit_test_alloc_fail_at(fail_at);
    status =
        shell_build_type_netseq(input, strlen(input), NULL, &netseq, &count);
    shellsplit_test_alloc_reset();
    if (status != SHELL_PROCESS_ENOMEM || netseq != NULL || count != 0) {
      atomic = false;
      free(netseq);
      break;
    }
  }
  TEST("type-netsequence allocation failures are atomic", atomic);
}

static void test_element_metadata(void) {
  printf("\n=== Element Metadata Matrix ===\n");

  enum detail_kind { VARIABLE, PATH, GLOB, SUBSTITUTION };
  static const struct {
    const char *name;
    const char *input;
    const char *key;
    shell_abstract_type_t type;
    const char *original;
    enum detail_kind detail_kind;
    const char *detail;
    bool property;
    bool secondary_property;
  } cases[] = {
      {"braced variable metadata", "echo ${USER}", "$EV_1", SHELL_ABSTRACT_EV,
       "${USER}", VARIABLE, "USER", true, false},
      {"quoted variable metadata", "echo \"$USER\"", "$EV_1", SHELL_ABSTRACT_EV,
       "\"$USER\"", VARIABLE, "USER", false, true},
      {"trailing-slash path metadata", "ls /etc/", "$AP_1", SHELL_ABSTRACT_AP,
       "/etc/", PATH, "/etc/", true, false},
      {"path glob metadata", "ls /var/log/*.log", "$GB_1", SHELL_ABSTRACT_GB,
       "/var/log/*.log", GLOB, "/var/log/*.log", true, false},
      {"command substitution metadata", "cat $(printf hi)", "$CS_1",
       SHELL_ABSTRACT_CS, "$(printf hi)", SUBSTITUTION, "printf hi", false,
       false},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_abstract_command_t *result = parse_command(cases[i].input);
    bool valid = result != NULL;
    shell_abstract_element_t *element =
        valid ? shell_abstract_command_find_element(result, cases[i].key)
              : NULL;
    valid = valid && element && element->type == cases[i].type &&
            strcmp(element->original, cases[i].original) == 0;
    if (valid) {
      switch (cases[i].detail_kind) {
      case VARIABLE:
        valid = element->data.var.name &&
                strcmp(element->data.var.name, cases[i].detail) == 0 &&
                element->data.var.is_braced == cases[i].property &&
                element->data.var.is_quoted == cases[i].secondary_property;
        break;
      case PATH:
        valid = element->data.path.path &&
                strcmp(element->data.path.path, cases[i].detail) == 0 &&
                element->data.path.ends_with_slash == cases[i].property;
        break;
      case GLOB:
        valid = element->data.glob.pattern &&
                strcmp(element->data.glob.pattern, cases[i].detail) == 0 &&
                element->data.glob.has_slash == cases[i].property;
        break;
      case SUBSTITUTION:
        valid = element->data.cmd_subst.content &&
                strcmp(element->data.cmd_subst.content, cases[i].detail) == 0;
        break;
      }
    }
    TEST(cases[i].name, valid);
    shell_abstract_command_free(result);
  }
}

static void test_classification_matrix(void) {
  printf("\n=== Raw Token Classification Matrix ===\n");

  static const struct {
    const char *text;
    shell_token_type_t expected;
  } cases[] = {
      {"$HOME", SHELL_TOKEN_VARIABLE},    {"${HOME}", SHELL_TOKEN_VARIABLE},
      {"$1", SHELL_TOKEN_SPECIAL_VAR},    {"$10", SHELL_TOKEN_SPECIAL_VAR},
      {"${10}", SHELL_TOKEN_SPECIAL_VAR}, {"$?", SHELL_TOKEN_SPECIAL_VAR},
      {"$$", SHELL_TOKEN_SPECIAL_VAR},    {"$#", SHELL_TOKEN_SPECIAL_VAR},
      {"$!", SHELL_TOKEN_SPECIAL_VAR},    {"$@", SHELL_TOKEN_SPECIAL_VAR},
      {"$*", SHELL_TOKEN_SPECIAL_VAR},    {"$-", SHELL_TOKEN_SPECIAL_VAR},
      {"$!x", SHELL_TOKEN_ARGUMENT},      {"$@x", SHELL_TOKEN_ARGUMENT},
      {"$*x", SHELL_TOKEN_ARGUMENT},      {"$(date)", SHELL_TOKEN_SUBSHELL},
      {"`date`", SHELL_TOKEN_SUBSHELL},   {"$((1+2))", SHELL_TOKEN_ARITHMETIC},
      {"*.txt", SHELL_TOKEN_GLOB},        {"/etc/passwd", SHELL_TOKEN_ARGUMENT},
      {"\"text\"", SHELL_TOKEN_ARGUMENT}, {"plain", SHELL_TOKEN_ARGUMENT}};

  bool valid = shell_classify_raw_token(NULL, 0) == SHELL_TOKEN_END;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++)
    valid = shell_classify_raw_token(cases[i].text, strlen(cases[i].text)) ==
            cases[i].expected;
  TEST("all public raw-token classifications", valid);
}

static void test_path_and_name_matrices(void) {
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
               {NULL, SHELL_PATH_OTHER}};
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

static void test_runtime_expansion(void) {
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
               {"echo \"prefix $USER\"", "$EV_1", NULL, NULL},
               {"echo \"literal\"", "$STR_1", NULL, NULL}};

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_abstract_command_t *result = parse_command(cases[i].input);
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
  shell_abstract_command_t *path_result = parse_command("cat /tmp/../tmp");
  bool valid = path_result != NULL;
  shell_abstract_element_t *path =
      valid ? shell_abstract_command_find_element(path_result, "$AP_1") : NULL;
  char *resolved = path ? shell_abstract_element_expand(path, &context) : NULL;
  valid = valid && resolved && strcmp(resolved, "/tmp") == 0;
  TEST("path expansion optionally resolves canonical paths", valid);
  free(resolved);
  shell_abstract_command_free(path_result);
  context.resolve_symlinks = false;

  shell_abstract_command_t *result = parse_command("echo $USER $HOME");
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
  valid = shell_abstract_command_expand(result, &context) && user && home &&
          user->expanded == NULL && home->expanded == NULL;
  TEST("re-expansion clears stale values", valid);
  shell_abstract_command_free(result);
}

static void test_invalid_and_null_inputs(void) {
  printf("\n=== Invalid and Null Inputs ===\n");

  shell_abstract_command_t *result = parse_command("");
  bool valid = result == NULL;
  result = parse_command(NULL);
  valid = valid && result == NULL;
  TEST("abstraction rejects invalid inputs", valid);

  size_t count = 7;
  valid =
      shell_abstract_command_get_display_text(NULL) == NULL &&
      shell_abstract_command_get_source(NULL) == NULL &&
      shell_abstract_command_get_elements(NULL, &count) == NULL && count == 0 &&
      shell_abstract_command_get_elements(NULL, NULL) == NULL &&
      shell_abstract_command_get_mutable_elements(NULL, &count) == NULL &&
      count == 0 && shell_abstract_command_get_element(NULL, 0) == NULL &&
      shell_abstract_command_find_element(NULL, "$EV_1") == NULL &&
      shell_abstract_element_expand(NULL, NULL) == NULL &&
      !shell_abstract_command_expand(NULL, NULL) &&
      !shell_abstract_command_has_redirects(NULL) && feature_mask(NULL) == 0;
  TEST("query and expansion APIs are null-safe", valid);
  shell_abstract_command_free(NULL);
}

static void test_type_sequence_matrix(void) {
  printf("\n=== Type Sequence Matrix ===\n");
  char *netseq = NULL;
  size_t command_count = 0;
  bool valid =
      shell_build_type_netseq("printf 'two words'; cd /tmp",
                              strlen("printf 'two words'; cd /tmp"), NULL,
                              &netseq, &command_count) == SHELL_PROCESS_OK &&
      command_count == 2 && netseq &&
      strcmp(netseq, "15:6:printf,3:STR,,10:2:cd,2:AP,,") == 0;
  TEST("nested type sequence uses one record per command", valid);
  free(netseq);

  netseq = NULL;
  command_count = 0;
  valid = shell_build_type_netseq(
              "'my tool' 'two words'", strlen("'my tool' 'two words'"), NULL,
              &netseq, &command_count) == SHELL_PROCESS_OK &&
          command_count == 1 && netseq &&
          strcmp(netseq, "16:7:my tool,3:STR,,") == 0;
  TEST("nested type sequence preserves spaced executable names", valid);
  free(netseq);

  netseq = NULL;
  command_count = 0;
  valid = shell_build_type_netseq(
              "foo\"bar\" 'two words'", strlen("foo\"bar\" 'two words'"), NULL,
              &netseq, &command_count) == SHELL_PROCESS_OK &&
          command_count == 1 && netseq &&
          strcmp(netseq, "15:6:foobar,3:STR,,") == 0;
  TEST("nested type sequence shares quote-fragment decoding", valid);
  free(netseq);

  netseq = NULL;
  command_count = 0;
  valid = shell_build_type_netseq("my\\\ncommand value",
                                  strlen("my\\\ncommand value"), NULL, &netseq,
                                  &command_count) == SHELL_PROCESS_OK &&
          command_count == 1 && netseq &&
          strcmp(netseq, "18:9:mycommand,3:STR,,") == 0;
  TEST("nested type sequence shares escaped-newline decoding", valid);
  free(netseq);

  netseq = (char *)(void *)1;
  command_count = SIZE_MAX;
  valid = shell_build_type_netseq("'' value", strlen("'' value"), NULL, &netseq,
                                  &command_count) == SHELL_PROCESS_EPARSE &&
          netseq == NULL && command_count == 0;
  TEST("nested type sequence rejects an empty decoded executable", valid);

  valid = shell_build_type_netseq(NULL, 0, NULL, &netseq, &command_count) ==
              SHELL_PROCESS_EINPUT &&
          netseq == NULL && command_count == 0;
  valid = valid &&
          shell_build_type_netseq("echo x", strlen("echo x"), NULL, NULL,
                                  &command_count) == SHELL_PROCESS_EINPUT &&
          command_count == 0;
  valid = valid &&
          shell_build_type_netseq("echo x", strlen("echo x"), NULL, &netseq,
                                  NULL) == SHELL_PROCESS_EINPUT &&
          netseq == NULL;
  TEST("nested type sequence validates every argument atomically", valid);

  shell_process_limits_t limits = {SIZE_MAX, SIZE_MAX, 0};
  limits.max_string_bytes = 1;
  valid =
      shell_build_type_netseq("echo x", strlen("echo x"), &limits, &netseq,
                              &command_count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
      netseq == NULL && command_count == 0;
  TEST("nested type sequence enforces its outer output limit", valid);
}

int main(void) {
  printf("=== Shell Abstraction Tests ===\n");

  test_abstraction_matrix();
  test_bounded_span_and_statuses();
  test_ansi_c_arithmetic_span();
  test_abstraction_allocation_failures();
  test_element_metadata();
  test_classification_matrix();
  test_path_and_name_matrices();
  test_runtime_expansion();
  test_invalid_and_null_inputs();
  test_type_sequence_matrix();

  printf("\n=== Summary ===\n");
  printf("Passed: %d\nFailed: %d\nTotal:  %d\n", passed, failed,
         passed + failed);
  return failed > 0 ? 1 : 0;
}
