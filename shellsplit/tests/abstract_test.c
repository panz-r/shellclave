#define _POSIX_C_SOURCE 200809L
#include "shell_abstract.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed;
static int failed;

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

static unsigned feature_mask(abstracted_command_t *command) {
  return (shell_has_variables(command) ? FLAG_VARIABLES : 0) |
         (shell_has_pos_vars(command) ? FLAG_POS_VARS : 0) |
         (shell_has_special_vars(command) ? FLAG_SPECIAL_VARS : 0) |
         (shell_has_globs(command) ? FLAG_GLOBS : 0) |
         (shell_has_paths(command) ? FLAG_PATHS : 0) |
         (shell_has_abs_paths(command) ? FLAG_ABS_PATHS : 0) |
         (shell_has_rel_paths(command) ? FLAG_REL_PATHS : 0) |
         (shell_has_home_paths(command) ? FLAG_HOME_PATHS : 0) |
         (shell_has_cmd_subst(command) ? FLAG_CMD_SUBST : 0) |
         (shell_has_arithmetic(command) ? FLAG_ARITHMETIC : 0) |
         (shell_has_strings(command) ? FLAG_STRINGS : 0) |
         (shell_has_redirects(command) ? FLAG_REDIRECTS : 0);
}

static bool validate_elements(const char *input, abstracted_command_t *result) {
  size_t count = 0;
  abstract_element_t **elements = shell_get_elements(result, &count);
  bool valid = count == result->element_count && elements == result->elements &&
               shell_get_element_at(result, count) == NULL;
  size_t input_len = strlen(input);

  for (size_t i = 0; valid && i < count; i++) {
    abstract_element_t *element = elements[i];
    valid = element && element == shell_get_element_at(result, i) &&
            element ==
                shell_get_element_by_abstract(result, element->abstraction) &&
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
      {"heredoc is redirection", "cat <<EOF\npayload\nEOF",
       "cat <<EOF\npayload\nEOF", 0, FLAG_REDIRECTS},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    abstracted_command_t *result = NULL;
    bool ok = shell_abstract_command(cases[i].input, &result);
    bool valid = ok && result &&
                 strcmp(shell_get_original(result), cases[i].input) == 0 &&
                 strcmp(shell_get_abstracted(result), cases[i].expected) == 0 &&
                 result->element_count == cases[i].elements &&
                 feature_mask(result) == cases[i].flags &&
                 validate_elements(cases[i].input, result);
    if (!valid && result)
      printf("    got '%s', elements=%zu, flags=0x%x\n", result->abstracted,
             result->element_count, feature_mask(result));
    TEST(cases[i].name, valid);
    shell_abstracted_destroy(result);
  }
}

static void test_element_metadata(void) {
  printf("\n=== Element Metadata Matrix ===\n");

  enum detail_kind { VARIABLE, PATH, GLOB, SUBSTITUTION };
  static const struct {
    const char *name;
    const char *input;
    const char *key;
    abstract_type_t type;
    const char *original;
    enum detail_kind detail_kind;
    const char *detail;
    bool property;
    bool secondary_property;
  } cases[] = {
      {"braced variable metadata", "echo ${USER}", "$EV_1", ABSTRACT_EV,
       "${USER}", VARIABLE, "USER", true, false},
      {"quoted variable metadata", "echo \"$USER\"", "$EV_1", ABSTRACT_EV,
       "\"$USER\"", VARIABLE, "USER", false, true},
      {"trailing-slash path metadata", "ls /etc/", "$AP_1", ABSTRACT_AP,
       "/etc/", PATH, "/etc/", true, false},
      {"path glob metadata", "ls /var/log/*.log", "$GB_1", ABSTRACT_GB,
       "/var/log/*.log", GLOB, "/var/log/*.log", true, false},
      {"command substitution metadata", "cat $(printf hi)", "$CS_1",
       ABSTRACT_CS, "$(printf hi)", SUBSTITUTION, "printf hi", false, false},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    abstracted_command_t *result = NULL;
    bool valid = shell_abstract_command(cases[i].input, &result) && result;
    abstract_element_t *element =
        valid ? shell_get_element_by_abstract(result, cases[i].key) : NULL;
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
    shell_abstracted_destroy(result);
  }
}

static void test_classification_matrix(void) {
  printf("\n=== Raw Token Classification Matrix ===\n");

  static const struct {
    const char *text;
    token_type_t expected;
  } cases[] = {{"$HOME", TOKEN_VARIABLE},    {"${HOME}", TOKEN_VARIABLE},
               {"$1", TOKEN_SPECIAL_VAR},    {"$10", TOKEN_SPECIAL_VAR},
               {"${10}", TOKEN_SPECIAL_VAR}, {"$?", TOKEN_SPECIAL_VAR},
               {"$$", TOKEN_SPECIAL_VAR},    {"$#", TOKEN_SPECIAL_VAR},
               {"$!", TOKEN_SPECIAL_VAR},    {"$@", TOKEN_SPECIAL_VAR},
               {"$*", TOKEN_SPECIAL_VAR},    {"$-", TOKEN_SPECIAL_VAR},
               {"$!x", TOKEN_ARGUMENT},      {"$@x", TOKEN_ARGUMENT},
               {"$*x", TOKEN_ARGUMENT},      {"$(date)", TOKEN_SUBSHELL},
               {"`date`", TOKEN_SUBSHELL},   {"$((1+2))", TOKEN_ARITHMETIC},
               {"*.txt", TOKEN_GLOB},        {"/etc/passwd", TOKEN_ARGUMENT},
               {"\"text\"", TOKEN_ARGUMENT}, {"plain", TOKEN_ARGUMENT}};

  bool valid = shell_classify_raw_token(NULL, 0) == TOKEN_END;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++)
    valid = shell_classify_raw_token(cases[i].text, strlen(cases[i].text)) ==
            cases[i].expected;
  TEST("all public raw-token classifications", valid);
}

static void test_path_and_name_matrices(void) {
  printf("\n=== Path and Name Matrices ===\n");

  static const struct {
    const char *path;
    path_category_t category;
  } paths[] = {{"/", PATH_ROOT},
               {"/etc/passwd", PATH_ETC},
               {"/var/log", PATH_VAR},
               {"/usr/bin", PATH_USR},
               {"/home/user", PATH_HOME},
               {"/root", PATH_HOME},
               {"/tmp/file", PATH_TMP},
               {"/proc/self", PATH_PROC},
               {"/sys/kernel", PATH_SYS},
               {"/dev/null", PATH_DEV},
               {"/opt/app", PATH_OPT},
               {"/srv/data", PATH_SRV},
               {"/run/service", PATH_RUN},
               {"/sysroot/etc", PATH_SYSROOT},
               {"/boot/vmlinuz", PATH_BOOT},
               {"/mnt/disk", PATH_MNT},
               {"/media/disk", PATH_MEDIA},
               {"/.snapshots/1", PATH_SNAPSHOT},
               {"/etcetera", PATH_OTHER},
               {"/runway", PATH_OTHER},
               {"/snapshots/1", PATH_OTHER},
               {"/unknown", PATH_OTHER},
               {"relative", PATH_OTHER},
               {"", PATH_OTHER},
               {NULL, PATH_OTHER}};
  static const char *abstract_names[] = {"EV", "PV", "SV", "AP",  "RP", "HP",
                                         "GB", "CS", "AR", "STR", "RD"};
  static const char *path_names[] = {
      "ROOT",    "ETC",  "VAR", "USR",   "HOME",     "TMP",
      "PROC",    "SYS",  "DEV", "OPT",   "SRV",      "RUN",
      "SYSROOT", "BOOT", "MNT", "MEDIA", "SNAPSHOT", "OTHER"};

  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(paths) / sizeof(paths[0]); i++)
    valid = shell_get_path_category(paths[i].path) == paths[i].category;
  TEST("all path categories and boundary forms", valid);

  valid = true;
  for (size_t i = 0;
       valid && i < sizeof(abstract_names) / sizeof(abstract_names[0]); i++)
    valid = strcmp(shell_abstract_type_name((abstract_type_t)i),
                   abstract_names[i]) == 0;
  valid = valid &&
          strcmp(shell_abstract_type_name((abstract_type_t)-1), "UNKNOWN") == 0;
  TEST("all abstract type names", valid);

  valid = true;
  for (size_t i = 0; valid && i < sizeof(path_names) / sizeof(path_names[0]);
       i++)
    valid = strcmp(shell_path_category_name((path_category_t)i),
                   path_names[i]) == 0;
  valid = valid &&
          strcmp(shell_path_category_name((path_category_t)-1), "UNKNOWN") == 0;
  TEST("all path category names", valid);
}

static void test_runtime_expansion(void) {
  printf("\n=== Runtime Expansion Matrix ===\n");

  char *environment[] = {"HOME=/home/testuser", "USER=testuser", NULL};
  runtime_context_t context = {
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
    abstracted_command_t *result = NULL;
    bool valid = shell_abstract_command(cases[i].input, &result) && result;
    abstract_element_t *element =
        valid ? shell_get_element_by_abstract(result, cases[i].key) : NULL;
    context.cwd = cases[i].cwd ? (char *)cases[i].cwd : "/home/testuser";
    char *expanded = element ? shell_expand_element(element, &context) : NULL;
    valid = cases[i].expected
                ? expanded && strcmp(expanded, cases[i].expected) == 0
                : expanded == NULL;
    TEST(cases[i].input, valid);
    free(expanded);
    shell_abstracted_destroy(result);
  }

  context.cwd = "/home/testuser";

  abstracted_command_t *path_result = NULL;
  context.resolve_symlinks = true;
  bool valid =
      shell_abstract_command("cat /tmp/../tmp", &path_result) && path_result;
  abstract_element_t *path =
      valid ? shell_get_element_by_abstract(path_result, "$AP_1") : NULL;
  char *resolved = path ? shell_expand_element(path, &context) : NULL;
  valid = valid && resolved && strcmp(resolved, "/tmp") == 0;
  TEST("path expansion optionally resolves canonical paths", valid);
  free(resolved);
  shell_abstracted_destroy(path_result);
  context.resolve_symlinks = false;

  abstracted_command_t *result = NULL;
  valid = shell_abstract_command("echo $USER $HOME", &result) && result &&
          shell_expand_all_elements(result, &context);
  abstract_element_t *user =
      valid ? shell_get_element_by_abstract(result, "$EV_1") : NULL;
  abstract_element_t *home =
      valid ? shell_get_element_by_abstract(result, "$EV_2") : NULL;
  valid = valid && user && user->expanded && home && home->expanded &&
          strcmp(user->expanded, "testuser") == 0 &&
          strcmp(home->expanded, "/home/testuser") == 0;
  TEST("expand all elements stores every result", valid);

  char *empty_environment[] = {NULL};
  context.env = empty_environment;
  valid = shell_expand_all_elements(result, &context) && user && home &&
          user->expanded == NULL && home->expanded == NULL;
  TEST("re-expansion clears stale values", valid);
  shell_abstracted_destroy(result);
}

static void test_invalid_and_null_inputs(void) {
  printf("\n=== Invalid and Null Inputs ===\n");

  abstracted_command_t *result = (abstracted_command_t *)1;
  bool valid = !shell_abstract_command("", &result) && result == NULL;
  result = (abstracted_command_t *)1;
  valid = valid && !shell_abstract_command(NULL, &result) && result == NULL &&
          !shell_abstract_command("echo", NULL);
  TEST("abstraction rejects invalid inputs", valid);

  size_t count = 7;
  valid = shell_get_abstracted(NULL) == NULL &&
          shell_get_original(NULL) == NULL &&
          shell_get_elements(NULL, &count) == NULL && count == 7 &&
          shell_get_elements(NULL, NULL) == NULL &&
          shell_get_element_at(NULL, 0) == NULL &&
          shell_get_element_by_abstract(NULL, "$EV_1") == NULL &&
          shell_expand_element(NULL, NULL) == NULL &&
          !shell_expand_all_elements(NULL, NULL) &&
          !shell_has_redirects(NULL) && feature_mask(NULL) == 0;
  TEST("query and expansion APIs are null-safe", valid);
  shell_abstracted_destroy(NULL);
}

static void test_type_sequence_matrix(void) {
  printf("\n=== Type Sequence Matrix ===\n");

  static const struct {
    const char *command;
    const char *expected;
  } cases[] = {
      {"cat /etc/passwd", "cat AP"},
      {"grep -i root /etc/shadow", "grep OPT STR AP"},
      {"cat /etc/passwd | grep root", "cat AP | grep STR"},
      {"ls ; cd /tmp && pwd || echo done", "ls | cd AP | pwd | echo STR"},
      {"echo $HOME", "echo EV"},
      {"$COMMAND argument", "EV STR"},
      {"echo $1 $? *.c $((1+2))", "echo PV SV GB AR"},
      {"cat ./file.txt ~/file.txt", "cat RP HP"},
      {"echo hi > out", "echo STR"},
      {"> out echo hi", "echo STR"},
      {"cat <<EOF\npayload\nEOF", "cat"},
      {"diff <(left) >(right)", "diff CS CS"},
  };

  bool valid = shell_build_type_sequence(NULL) == NULL &&
               shell_build_type_sequence("") == NULL;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    char *sequence = shell_build_type_sequence(cases[i].command);
    valid = sequence && strcmp(sequence, cases[i].expected) == 0;
    if (!valid && sequence)
      printf("    command '%s': got '%s', expected '%s'\n", cases[i].command,
             sequence, cases[i].expected);
    free(sequence);
  }
  TEST("canonical sequences preserve clean command semantics", valid);

  char long_command[700] = "echo";
  char long_expected[1400] = "echo";
  for (size_t i = 0; i < 300; i++) {
    strcat(long_command, " x");
    strcat(long_expected, " STR");
  }
  char *sequence = shell_build_type_sequence(long_command);
  valid = sequence && strcmp(sequence, long_expected) == 0;
  TEST("type sequence grows for 300 arguments", valid);
  free(sequence);
}

int main(void) {
  printf("=== Shell Abstraction Tests ===\n");

  test_abstraction_matrix();
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
