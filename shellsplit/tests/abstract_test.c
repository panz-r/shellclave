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
  bool valid = shell_abstract_command_parse(literal_with_suffix, 4, &result) ==
                   SHELL_ABSTRACT_OK &&
               result && strcmp(result->original, "echo") == 0 &&
               strcmp(result->display_text, "echo") == 0;
  shell_abstract_command_free(result);

  result = NULL;
  valid = valid &&
          shell_abstract_command_parse(abstract_with_suffix, 8, &result) ==
              SHELL_ABSTRACT_OK &&
          result && strcmp(result->original, "cat /tmp") == 0 &&
          strcmp(result->display_text, "cat $AP_1") == 0;
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
  TEST("abstraction reports input and parse failures precisely", valid);

  static const char *const malformed_complete_commands[] = {
      "time{ true; }",
      "( git",
      "time { true;",
      "echo one |",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(malformed_complete_commands) /
                             sizeof(malformed_complete_commands[0]);
       i++) {
    result = (shell_abstract_command_t *)(void *)1;
    valid = valid &&
            shell_abstract_command_parse(malformed_complete_commands[i],
                                         strlen(malformed_complete_commands[i]),
                                         &result) == SHELL_ABSTRACT_EPARSE &&
            result == NULL;
  }
  TEST("abstraction rejects malformed complete command syntax", valid);

  char excessive_commands[(SHELL_MAX_SUBCOMMANDS + 1u) * 2u + 1u];
  size_t excessive_length = 0;
  for (size_t i = 0; i <= SHELL_MAX_SUBCOMMANDS; i++) {
    excessive_commands[excessive_length++] = ':';
    excessive_commands[excessive_length++] = ';';
  }
  excessive_commands[excessive_length] = '\0';
  result = (shell_abstract_command_t *)(void *)1;
  valid = shell_abstract_command_parse(excessive_commands, excessive_length,
                                       &result) == SHELL_ABSTRACT_EOVERFLOW &&
          result == NULL;
  TEST("abstraction maps semantic command capacity to overflow", valid);
}

static void test_dynamic_arithmetic_is_rejected(void) {
  const char *source = "echo $(( $(printf $'foo\\'bar)') + 1 ))";
  shell_abstract_command_t *result = (shell_abstract_command_t *)(void *)1;
  bool valid = shell_abstract_command_parse(source, strlen(source), &result) ==
                   SHELL_ABSTRACT_EPARSE &&
               result == NULL;
  shell_abstract_command_free(result);
  TEST("Dynamic arithmetic is rejected before abstraction", valid);
}

static void test_timed_complete_command_abstraction(void) {
  printf("\n=== Timed Complete Command Abstraction ===\n");

  static const struct {
    const char *source;
    const char *display;
    size_t element_count;
    shell_abstract_type_t first_type;
    const char *first_original;
    size_t first_start;
    const char *second_original;
    size_t second_start;
  } cases[] = {
      {"time -p -- printf %s /workspace/${NAME}",
       "time -p -- printf %s $AP_1$EV_1", 2, SHELL_ABSTRACT_AP, "/workspace/",
       21, "${NAME}", 32},
      {"time { printf %s ./file; }", "time { printf %s $RP_1; }", 1,
       SHELL_ABSTRACT_RP, "./file", 17, NULL, 0},
      {"time ({ printf %s ./file; })", "time ({ printf %s $RP_1; })", 1,
       SHELL_ABSTRACT_RP, "./file", 18, NULL, 0},
      {"time ({(printf %s ./file)})", "time ({(printf %s $RP_1)})", 1,
       SHELL_ABSTRACT_RP, "./file", 18, NULL, 0},
      {"time { time -p printf %s ~/file; }",
       "time { time -p printf %s $HP_1; }", 1, SHELL_ABSTRACT_HP, "~/file", 25,
       NULL, 0},
  };

  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_abstract_command_t *result = NULL;
    shell_abstract_status_t status = shell_abstract_command_parse(
        cases[i].source, strlen(cases[i].source), &result);
    size_t count = 0;
    const shell_abstract_element_t *const *elements =
        shell_abstract_command_get_elements(result, &count);
    bool item = status == SHELL_ABSTRACT_OK && result != NULL &&
                strcmp(result->original, cases[i].source) == 0 &&
                strcmp(result->display_text, cases[i].display) == 0 &&
                elements != NULL && count == cases[i].element_count &&
                elements[0] != NULL &&
                elements[0]->type == cases[i].first_type &&
                strcmp(elements[0]->original, cases[i].first_original) == 0 &&
                elements[0]->start == cases[i].first_start &&
                elements[0]->end ==
                    cases[i].first_start + strlen(cases[i].first_original) &&
                result->has_paths;
    if (cases[i].second_original) {
      item = item && elements[1] != NULL &&
             strcmp(elements[1]->original, cases[i].second_original) == 0 &&
             elements[1]->start == cases[i].second_start &&
             elements[1]->end ==
                 cases[i].second_start + strlen(cases[i].second_original) &&
             result->has_variables;
    }
    valid = valid && item;
    shell_abstract_command_free(result);
  }
  TEST("Timed complete commands retain syntax and abstraction offsets", valid);
}

static void test_compound_variable_quote_boundaries(void) {
  static const struct {
    const char *source;
    const char *display;
    size_t element_count;
    bool has_ansi_c_string;
  } cases[] = {
      {"printf prefix'$literal'${NAME}", "printf prefix'$literal'$EV_1", 1,
       false},
      {"printf prefix$'don\\'t $literal'${NAME}", "printf prefix$STR_1$EV_1", 2,
       true},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_abstract_command_t *result = parse_command(cases[i].source);
    size_t count = 0;
    const shell_abstract_element_t *const *elements =
        result ? shell_abstract_command_get_elements(result, &count) : NULL;
    valid = result && strcmp(result->display_text, cases[i].display) == 0 &&
            count == cases[i].element_count && elements != NULL &&
            elements[count - 1] != NULL &&
            elements[count - 1]->type == SHELL_ABSTRACT_EV &&
            strcmp(elements[count - 1]->original, "${NAME}") == 0 &&
            elements[count - 1]->data.var.name != NULL &&
            strcmp(elements[count - 1]->data.var.name, "NAME") == 0 &&
            result->has_strings == cases[i].has_ansi_c_string &&
            (!cases[i].has_ansi_c_string ||
             (elements[0] && elements[0]->type == SHELL_ABSTRACT_STR &&
              strcmp(elements[0]->original, "$'don\\'t $literal'") == 0));
    shell_abstract_command_free(result);
  }
  TEST("compound variables preserve quoted and ANSI-C literal boundaries",
       valid);

  static const char *const string_words[] = {
      "prefix$'literal'",
      "prefix$'don\\'t $literal'",
      "prefix$\\\n'literal'",
  };
  valid = true;
  for (size_t i = 0;
       valid && i < sizeof(string_words) / sizeof(string_words[0]); i++) {
    char source[128];
    int length = snprintf(source, sizeof(source), "printf %s", string_words[i]);
    shell_abstract_command_t *result = parse_command(source);
    size_t count = 0;
    const shell_abstract_element_t *const *elements =
        result ? shell_abstract_command_get_elements(result, &count) : NULL;
    valid = length > 0 && (size_t)length < sizeof(source) && result &&
            strcmp(result->display_text, "printf prefix$STR_1") == 0 &&
            result->has_strings && !result->has_variables && count == 1 &&
            elements && elements[0] &&
            elements[0]->type == SHELL_ABSTRACT_STR &&
            strcmp(elements[0]->original, string_words[i] + 6) == 0 &&
            strcmp(elements[0]->data.cmd_subst.content,
                   i == 1 ? "don\\'t $literal" : "literal") == 0;
    shell_abstract_command_free(result);
  }
  TEST("composite ANSI-C strings retain source and payload metadata", valid);

  shell_abstract_command_t *continued = parse_command("printf ${NA\\\nME}");
  size_t count = 0;
  const shell_abstract_element_t *const *elements =
      continued ? shell_abstract_command_get_elements(continued, &count) : NULL;
  valid = continued && elements && count == 1 && elements[0] &&
          elements[0]->type == SHELL_ABSTRACT_EV &&
          strcmp(continued->display_text, "printf $EV_1") == 0 &&
          strcmp(elements[0]->original, "${NA\\\nME}") == 0 &&
          elements[0]->data.var.name &&
          strcmp(elements[0]->data.var.name, "NAME") == 0;
  shell_abstract_command_free(continued);
  TEST("continued static variable names retain canonical metadata", valid);
}

static void test_compound_substitution_boundaries(void) {
  shell_abstract_command_t *result = parse_command("printf \"x$VAR$(id)\"");
  size_t count = 0;
  const shell_abstract_element_t *const *elements =
      result ? shell_abstract_command_get_elements(result, &count) : NULL;
  bool valid = result && elements && count == 2 && result->has_cmd_subst &&
               strcmp(result->display_text, "printf \"x$EV_1$CS_1\"") == 0 &&
               elements[0]->type == SHELL_ABSTRACT_EV &&
               strcmp(elements[0]->original, "$VAR") == 0 &&
               elements[1]->type == SHELL_ABSTRACT_CS &&
               strcmp(elements[1]->original, "$(id)") == 0 &&
               elements[1]->data.cmd_subst.content &&
               strcmp(elements[1]->data.cmd_subst.content, "id") == 0;
  shell_abstract_command_free(result);

  result = parse_command("printf prefix${VAR:-$(id)}");
  count = 0;
  elements =
      result ? shell_abstract_command_get_elements(result, &count) : NULL;
  valid = valid && result && elements && count == 1 && result->has_cmd_subst &&
          elements[0]->type == SHELL_ABSTRACT_EV &&
          strcmp(elements[0]->original, "${VAR:-$(id)}") == 0 &&
          strcmp(result->display_text, "printf prefix$EV_1") == 0;
  shell_abstract_command_free(result);

  result = parse_command("printf x$VAR`id` <(producer)");
  count = 0;
  elements =
      result ? shell_abstract_command_get_elements(result, &count) : NULL;
  valid = valid && result && elements && count == 3 && result->has_cmd_subst &&
          elements[0]->type == SHELL_ABSTRACT_EV &&
          elements[1]->type == SHELL_ABSTRACT_CS &&
          strcmp(elements[1]->original, "`id`") == 0 &&
          elements[2]->type == SHELL_ABSTRACT_CS &&
          strcmp(elements[2]->original, "<(producer)") == 0;
  shell_abstract_command_free(result);

  static const char *const literal_cases[] = {
      "printf \"x$VAR<(producer)\"",
      "printf x$VAR\\$(id)",
      "printf x$VAR$'$(id)'",
      "printf x$VAR'$(id)'",
  };
  for (size_t i = 0;
       valid && i < sizeof(literal_cases) / sizeof(literal_cases[0]); i++) {
    result = parse_command(literal_cases[i]);
    valid = result && !result->has_cmd_subst;
    shell_abstract_command_free(result);
  }
  TEST("compound abstractions retain active substitution boundaries", valid);

  static const struct {
    const char *source;
    const char *substitution;
    const char *content;
  } scoped[] = {
      {"echo \"$OUTER$(printf '$INNER')$AFTER\"", "$(printf '$INNER')",
       "printf '$INNER'"},
      {"echo \"$OUTER$(printf '\"$INNER')$AFTER\"", "$(printf '\"$INNER')",
       "printf '\"$INNER'"},
      {"echo \"$OUTER$(printf \"$INNER\")$AFTER\"", "$(printf \"$INNER\")",
       "printf \"$INNER\""},
      {"echo \"$OUTER`printf '$INNER'`$AFTER\"", "`printf '$INNER'`",
       "printf '$INNER'"},
  };
  valid = true;
  for (size_t i = 0; i < sizeof(scoped) / sizeof(scoped[0]); i++) {
    result = parse_command(scoped[i].source);
    count = 0;
    elements =
        result ? shell_abstract_command_get_elements(result, &count) : NULL;
    bool matches =
        result && elements && count == 3 && result->has_variables &&
        result->has_cmd_subst &&
        strcmp(result->display_text, "echo \"$EV_1$CS_1$EV_2\"") == 0;
    static const char *const variables[] = {"$OUTER", "$AFTER"};
    for (size_t j = 0; matches && j < 2; j++) {
      const shell_abstract_element_t *element = elements[2 * j];
      const char *expected = strstr(scoped[i].source, variables[j]);
      matches = element->type == SHELL_ABSTRACT_EV &&
                strcmp(element->original, variables[j]) == 0 &&
                strcmp(element->data.var.name, variables[j] + 1) == 0 &&
                element->data.var.is_quoted &&
                element->start == (size_t)(expected - scoped[i].source) &&
                element->end - element->start == strlen(variables[j]);
    }
    if (matches) {
      const shell_abstract_element_t *element = elements[1];
      matches =
          element->type == SHELL_ABSTRACT_CS &&
          strcmp(element->original, scoped[i].substitution) == 0 &&
          strcmp(element->data.cmd_subst.content, scoped[i].content) == 0 &&
          element->start ==
              (size_t)(strstr(scoped[i].source, scoped[i].substitution) -
                       scoped[i].source) &&
          element->end - element->start == strlen(scoped[i].substitution);
    }
    valid = valid && matches;
    shell_abstract_command_free(result);
  }
  TEST("child substitution quoting cannot alter outer variable metadata",
       valid);
}

static void test_parameter_expansion_metadata(void) {
  static const struct {
    const char *source;
    shell_abstract_type_t type;
    const char *name;
  } cases[] = {
      {"printf ${VALUE:-fallback}", SHELL_ABSTRACT_EV, "VALUE"},
      {"printf ${VALUE#prefix}", SHELL_ABSTRACT_EV, "VALUE"},
      {"printf ${VALUE%%suffix}", SHELL_ABSTRACT_EV, "VALUE"},
      {"printf ${#VALUE}", SHELL_ABSTRACT_EV, "VALUE"},
      {"printf ${10}", SHELL_ABSTRACT_PV, "10"},
      {"printf ${?}", SHELL_ABSTRACT_SV, "?"},
      {"printf ${#}", SHELL_ABSTRACT_SV, "#"},
      {"printf ${!}", SHELL_ABSTRACT_SV, "!"},
      {"printf $\\\n{#}", SHELL_ABSTRACT_SV, "#"},
      {"printf $\\\n{!}", SHELL_ABSTRACT_SV, "!"},
      {"printf \"$\\\n{#}\"", SHELL_ABSTRACT_SV, "#"},
      {"printf ${#?}", SHELL_ABSTRACT_SV, "?"},
      {"printf ${!prefix*}", SHELL_ABSTRACT_EV, NULL},
      {"printf ${!prefix@}", SHELL_ABSTRACT_EV, NULL},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_abstract_command_t *result = parse_command(cases[i].source);
    size_t count = 0;
    const shell_abstract_element_t *const *elements =
        result ? shell_abstract_command_get_elements(result, &count) : NULL;
    valid = result && count == 1 && elements && elements[0] &&
            elements[0]->type == cases[i].type &&
            elements[0]->data.var.is_braced &&
            ((cases[i].name == NULL && elements[0]->data.var.name == NULL) ||
             (cases[i].name != NULL && elements[0]->data.var.name != NULL &&
              strcmp(elements[0]->data.var.name, cases[i].name) == 0));
    shell_abstract_command_free(result);
  }
  TEST("parameter expansion metadata names only static parameters", valid);
  static const char *const indirect[] = {"printf ${!name}", "printf ${!1}"};
  for (size_t i = 0; i < sizeof(indirect) / sizeof(indirect[0]); i++) {
    shell_abstract_command_t *result = NULL;
    valid &= shell_abstract_command_parse(indirect[i], strlen(indirect[i]),
                                          &result) == SHELL_ABSTRACT_EPARSE &&
             result == NULL;
    shell_abstract_command_free(result);
  }
  TEST("indirect expansions reject unmodeled value re-evaluation", valid);
}

static void test_nested_parameter_substitution_metadata(void) {
  static const struct {
    const char *source;
    bool has_substitution;
  } cases[] = {
      {"printf ${VALUE:-$(id)}", true},
      {"printf ${VALUE:-`id`}", true},
      {"printf ${VALUE:-<(id)}", true},
      {"printf ${VALUE:->(id)}", true},
      {"printf ${VALUE:-${FALLBACK:-$(id)}}", true},
      {"printf ${VALUE#prefix${SUFFIX:-$(id)}}", true},
      {"printf ${VALUE:-\"$(id)\"}", true},
      {"printf ${VALUE:-'$(id)'}", false},
      {"printf ${VALUE:-$'`id`'}", false},
      {"printf ${VALUE:-\\$(id)}", false},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_abstract_command_t *result = parse_command(cases[i].source);
    size_t count = 0;
    const shell_abstract_element_t *const *elements =
        result ? shell_abstract_command_get_elements(result, &count) : NULL;
    valid = result && count == 1 && elements && elements[0] &&
            elements[0]->type == SHELL_ABSTRACT_EV &&
            strcmp(elements[0]->original,
                   cases[i].source + strlen("printf ")) == 0 &&
            result->has_cmd_subst == cases[i].has_substitution;
    shell_abstract_command_free(result);
  }
  TEST("nested parameter substitutions remain visible in metadata", valid);
}

static void test_invalid_parameter_selectors(void) {
  static const char *const cases[] = {
      "printf ${VALUE${SUFFIX}}", "printf ${VALUE$SUFFIX}",
      "printf ${VALUE.suffix}",   "printf ${?suffix}",
      "printf ${10suffix}",
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_abstract_command_t *result = (shell_abstract_command_t *)(void *)1;
    valid = shell_abstract_command_parse(cases[i], strlen(cases[i]), &result) ==
                SHELL_ABSTRACT_EPARSE &&
            result == NULL;
  }
  TEST("invalid parameter selectors cannot produce abstractions", valid);
}

static void test_quote_aware_substitution_metadata(void) {
  static const struct {
    const char *source;
    bool has_substitution;
  } cases[] = {
      {"printf \"$(id)\"", true},         {"printf \"`id`\"", true},
      {"printf prefix$(id)suffix", true}, {"printf x >\"$(id)\"", true},
      {"printf '<(id)'", false},          {"printf $'$(id)'", false},
      {"printf \\$(id)", false},          {"printf \"<(id)\"", false},
      {"printf \">(id)\"", false},        {"printf ${VALUE:-\"<(id)\"}", false},
      {"printf ${VALUE:-<(id)}", true},   {"printf ${VALUE:->(id)}", true},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_abstract_command_t *result = parse_command(cases[i].source);
    valid = result && result->has_cmd_subst == cases[i].has_substitution;
    shell_abstract_command_free(result);
  }
  TEST("substitution metadata honors quote execution semantics", valid);
}

static void test_modern_word_abstractions(void) {
  shell_abstract_command_t *result =
      parse_command("printf $'a\\n' @(left|right)");
  size_t count = 0;
  const shell_abstract_element_t *const *elements =
      result ? shell_abstract_command_get_elements(result, &count) : NULL;
  bool valid = result && elements && count == 2 &&
               strcmp(result->display_text, "printf $STR_1 $GB_1") == 0 &&
               result->has_strings && result->has_globs && elements[0] &&
               elements[1] && elements[0]->type == SHELL_ABSTRACT_STR &&
               strcmp(elements[0]->original, "$'a\\n'") == 0 &&
               elements[0]->data.cmd_subst.content &&
               strcmp(elements[0]->data.cmd_subst.content, "a\\n") == 0 &&
               elements[1]->type == SHELL_ABSTRACT_GB &&
               elements[1]->data.glob.pattern &&
               strcmp(elements[1]->data.glob.pattern, "@(left|right)") == 0;
  shell_abstract_command_free(result);
  TEST("ANSI-C strings and extglobs retain abstract metadata", valid);
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
  return (command->has_variables ? FLAG_VARIABLES : 0) |
         (command->has_pos_vars ? FLAG_POS_VARS : 0) |
         (command->has_special_vars ? FLAG_SPECIAL_VARS : 0) |
         (command->has_globs ? FLAG_GLOBS : 0) |
         (command->has_paths ? FLAG_PATHS : 0) |
         (command->has_abs_paths ? FLAG_ABS_PATHS : 0) |
         (command->has_rel_paths ? FLAG_REL_PATHS : 0) |
         (command->has_home_paths ? FLAG_HOME_PATHS : 0) |
         (command->has_cmd_subst ? FLAG_CMD_SUBST : 0) |
         (command->has_arithmetic ? FLAG_ARITHMETIC : 0) |
         (command->has_strings ? FLAG_STRINGS : 0) |
         (command->has_redirects ? FLAG_REDIRECTS : 0);
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
      {"quoted special parameter family", "printf '%s\\n' \"$- $@ $* $!\"\n",
       "printf $STR_1 \"$SV_1 $SV_2 $SV_3 $SV_4\"\n", 5,
       FLAG_VARIABLES | FLAG_SPECIAL_VARS | FLAG_STRINGS},
      {"timed quoted compound variables", "time printf \"$HOME $1 $?\"",
       "time printf \"$EV_1 $PV_1 $SV_1\"", 3,
       FLAG_VARIABLES | FLAG_POS_VARS | FLAG_SPECIAL_VARS},
      {"quoted compound path fragments", "time printf \"/a/$USER/b/$HOME/c\"",
       "time printf \"$AP_1$EV_1$AP_2$EV_2$AP_3\"", 5,
       FLAG_VARIABLES | FLAG_PATHS | FLAG_ABS_PATHS},
      {"command substitution", "cat $(cat file.txt)", "cat $CS_1", 1,
       FLAG_CMD_SUBST},
      {"backtick substitution", "echo `date`", "echo $CS_1", 1, FLAG_CMD_SUBST},
      {"arithmetic expansion", "echo $((1+2))", "echo $AR_1", 1,
       FLAG_ARITHMETIC},
      {"quoted string", "echo \"hello world\"", "echo $STR_1", 1, FLAG_STRINGS},
      {"quoted variable", "echo \"$USER\"", "echo $EV_1", 1, FLAG_VARIABLES},
      {"embedded quoted variable", "echo \"prefix ${NAME} suffix\"",
       "echo \"prefix $EV_1 suffix\"", 1, FLAG_VARIABLES},
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
      {"trailing path fragments in one variable word", "printf /a/$X/b/$Y/c",
       "printf $AP_1$EV_1$AP_2$EV_2$AP_3", 5,
       FLAG_VARIABLES | FLAG_PATHS | FLAG_ABS_PATHS},
      {"compound word abstraction families",
       "printf ./$REL/tail ~/$HOME/tail arg-$1 status-$?",
       "printf $RP_1$EV_1$AP_1 $HP_1$EV_2$AP_2 arg-$PV_1 status-$SV_1", 8,
       FLAG_VARIABLES | FLAG_PATHS | FLAG_ABS_PATHS | FLAG_REL_PATHS |
           FLAG_HOME_PATHS | FLAG_POS_VARS | FLAG_SPECIAL_VARS},
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
                 strcmp(result->original, cases[i].input) == 0 &&
                 strcmp(result->display_text, cases[i].expected) == 0 &&
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
      "echo /var/log/$APP.log ./$REL ~/$HOME arg-$1 status-$? *.txt $(date) "
      "$((1+2)) /a/$X/b ${VALUE:-$(date)} ${!prefix*} ${?} "
      "\"$OUTER$(printf '\"$INNER')$AFTER\" "
      "\"$OUTER`printf '$INNER'`$AFTER\" "
      "\"$(printf '$INNER')\" >output";
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

  /* Complete-command validation now accepts timing prefixes and compound
   * timing scopes. Exercise the same failure-atomic allocation boundary on
   * that path rather than only on an ordinary simple command. */
  static const char *const timed_inputs[] = {
      "time { printf %s /tmp/${VALUE}; time -p printf %s ~/nested; }",
      "time ({ printf %s /tmp/${VALUE}; })",
      "time ({(printf %s ~/nested)})",
      "time printf %s ./prefix$VALUE$(time printf child)/suffix",
      "time printf %s $VALUE`printf child`/suffix",
      "time { printf %s $VALUE<(printf child)>suffix; } >report",
      "time printf '%s\\n' \"$- $@ $* $!\"",
      "time { printf \"$HOME$(printf child) $1 $?\"; }",
      "time printf prefix$'don\\'t $literal'${NAME}",
      "time printf prefix$'literal'",
      "time printf $\\\n'abc'",
      "time printf pre$\\\n'abc'$VALUE",
      "time printf \"pre$\\\n(id)$VALUE\"",
      "time printf \"$VALUE$((1 + 2))\"",
      "time printf pre$((1))$((2))$VALUE",
      "time printf $\\\n(\\\n(1 + 2)\\\n)$VALUE",
      "time printf x${VALUE:-$((1 + 2))}*",
      "time printf >x$VALUE$((1))",
  };
  bool timed_atomic = true;
  for (size_t i = 0;
       timed_atomic && i < sizeof(timed_inputs) / sizeof(timed_inputs[0]);
       i++) {
    shellsplit_test_alloc_reset();
    probe = parse_command(timed_inputs[i]);
    allocations = shellsplit_test_alloc_count();
    timed_atomic = probe != NULL && allocations > 4;
    shell_abstract_command_free(probe);
    for (size_t fail_at = 1; timed_atomic && fail_at <= allocations;
         fail_at++) {
      shellsplit_test_alloc_fail_at(fail_at);
      shell_abstract_command_t *result = NULL;
      shell_abstract_status_t timed_status = shell_abstract_command_parse(
          timed_inputs[i], strlen(timed_inputs[i]), &result);
      shellsplit_test_alloc_reset();
      timed_atomic = timed_status == SHELL_ABSTRACT_ENOMEM && result == NULL;
      if (!timed_atomic)
        fprintf(stderr,
                "timed abstraction failure: source=%s fail_at=%zu "
                "status=%d\n",
                timed_inputs[i], fail_at, timed_status);
      shell_abstract_command_free(result);
    }
  }
  shellsplit_test_alloc_reset();
  TEST("Timed command abstraction allocation failures are atomic",
       timed_atomic);

  shell_netstring_buffer_t netseq = {0};
  size_t count = 0;
  shellsplit_test_alloc_reset();
  shell_process_status_t status = shell_build_type_netseq_buffer(
      input, strlen(input), NULL, &netseq, &count);
  allocations = shellsplit_test_alloc_count();
  /* Two date substitutions and three scoped printf substitutions precede the
   * enclosing echo. Keep the allocation probe on all six execution stages. */
  TEST("type-netsequence allocation probe succeeds",
       status == SHELL_PROCESS_OK && netseq.data && count == 6);
  shell_netstring_buffer_free(&netseq);

  bool atomic = true;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    netseq = (shell_netstring_buffer_t){0};
    count = SIZE_MAX;
    shellsplit_test_alloc_fail_at(fail_at);
    status = shell_build_type_netseq_buffer(input, strlen(input), NULL, &netseq,
                                            &count);
    shellsplit_test_alloc_reset();
    if (status != SHELL_PROCESS_ENOMEM || netseq.data != NULL || count != 0) {
      atomic = false;
      shell_netstring_buffer_free(&netseq);
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

static void test_fragment_payload_metadata(void) {
  static const struct {
    const char *name;
    const char *input;
    shell_abstract_type_t type;
    const char *original;
    const char *content;
  } cases[] = {
      {"empty backtick payload", "echo ``", SHELL_ABSTRACT_CS, "``", ""},
      {"one-character backtick payload", "echo `x`", SHELL_ABSTRACT_CS, "`x`",
       "x"},
      {"empty dollar substitution payload", "echo $()", SHELL_ABSTRACT_CS,
       "$()", ""},
      {"one-character dollar substitution payload", "echo $(x)",
       SHELL_ABSTRACT_CS, "$(x)", "x"},
      {"empty process input payload", "echo <()", SHELL_ABSTRACT_CS, "<()", ""},
      {"empty process output payload", "echo >()", SHELL_ABSTRACT_CS, ">()",
       ""},
      {"one-character process payload", "echo <(x)", SHELL_ABSTRACT_CS, "<(x)",
       "x"},
      {"adjacent short substitution payload", "echo pre`x`suffix",
       SHELL_ABSTRACT_CS, "`x`", "x"},
      {"variable-adjacent short substitution payload", "echo $VALUE`x`",
       SHELL_ABSTRACT_CS, "`x`", "x"},
      {"quoted composite short substitution payload", "echo \"$VALUE`x`\"",
       SHELL_ABSTRACT_CS, "`x`", "x"},
      {"quoted composite empty substitution payload", "echo \"$VALUE$()\"",
       SHELL_ABSTRACT_CS, "$()", ""},
      {"timed short substitution payload", "time -p echo `x`",
       SHELL_ABSTRACT_CS, "`x`", "x"},
      {"timed group empty substitution payload", "time { echo $(); }",
       SHELL_ABSTRACT_CS, "$()", ""},
      {"substitution payload preserves continuations", "echo $(x\\\ny)",
       SHELL_ABSTRACT_CS, "$(x\\\ny)", "x\\\ny"},
      {"continued opener empty payload", "echo $\\\n()", SHELL_ABSTRACT_CS,
       "$\\\n()", ""},
      {"empty single-quoted payload", "echo ''", SHELL_ABSTRACT_STR, "''", ""},
      {"empty double-quoted payload", "echo \"\"", SHELL_ABSTRACT_STR, "\"\"",
       ""},
      {"empty ANSI-C payload", "echo $''", SHELL_ABSTRACT_STR, "$''", ""},
      {"composite empty ANSI-C payload", "echo pre$''$VALUE",
       SHELL_ABSTRACT_STR, "$''", ""},
      {"single-quoted payload preserves continuations", "echo '\\\n'",
       SHELL_ABSTRACT_STR, "'\\\n'", "\\\n"},
      {"double-quoted payload preserves continuations", "echo \"\\\n\"",
       SHELL_ABSTRACT_STR, "\"\\\n\"", "\\\n"},
      {"empty arithmetic payload", "echo $(())", SHELL_ABSTRACT_AR, "$(())",
       ""},
      {"composite empty arithmetic payload", "echo pre$(())$VALUE",
       SHELL_ABSTRACT_AR, "$(())", ""},
      {"arithmetic payload", "echo $((1))", SHELL_ABSTRACT_AR, "$((1))", "1"},
      {"composite arithmetic payload", "echo pre$((1))$VALUE",
       SHELL_ABSTRACT_AR, "$((1))", "1"},
  };

  bool atomic = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shellsplit_test_alloc_reset();
    shell_abstract_command_t *result = parse_command(cases[i].input);
    size_t allocations = shellsplit_test_alloc_count();
    const char *key = cases[i].type == SHELL_ABSTRACT_CS   ? "$CS_1"
                      : cases[i].type == SHELL_ABSTRACT_AR ? "$AR_1"
                                                           : "$STR_1";
    shell_abstract_element_t *element =
        result ? shell_abstract_command_find_element(result, key) : NULL;
    size_t start =
        (size_t)(strstr(cases[i].input, cases[i].original) - cases[i].input);
    bool valid =
        result && element && element->type == cases[i].type &&
        element->data.cmd_subst.content &&
        strcmp(element->data.cmd_subst.content, cases[i].content) == 0 &&
        strcmp(element->original, cases[i].original) == 0 &&
        element->start == start &&
        element->end == start + strlen(cases[i].original) &&
        validate_elements(cases[i].input, result);
    TEST(cases[i].name, valid);
    atomic = atomic && result != NULL;
    shell_abstract_command_free(result);

    for (size_t fail_at = 1; atomic && fail_at <= allocations; fail_at++) {
      shellsplit_test_alloc_fail_at(fail_at);
      result = NULL;
      shell_abstract_status_t status = shell_abstract_command_parse(
          cases[i].input, strlen(cases[i].input), &result);
      shellsplit_test_alloc_reset();
      atomic = status == SHELL_ABSTRACT_ENOMEM && result == NULL;
      if (!atomic)
        fprintf(stderr, "fragment payload allocation failure: %s at %zu\n",
                cases[i].name, fail_at);
      shell_abstract_command_free(result);
    }
  }
  shellsplit_test_alloc_reset();
  TEST("fragment payload allocation failures leave no partial result", atomic);
}

static void test_classification_matrix(void) {
  printf("\n=== Raw Token Classification Matrix ===\n");

  static const struct {
    const char *text;
    shell_token_type_t expected;
  } cases[] = {{"", SHELL_TOKEN_END},
               {"$HOME", SHELL_TOKEN_VARIABLE},
               {"${HOME}", SHELL_TOKEN_VARIABLE},
               {"$1", SHELL_TOKEN_SPECIAL_VAR},
               {"$10", SHELL_TOKEN_SPECIAL_VAR},
               {"${10}", SHELL_TOKEN_SPECIAL_VAR},
               {"$?", SHELL_TOKEN_SPECIAL_VAR},
               {"$$", SHELL_TOKEN_SPECIAL_VAR},
               {"$#", SHELL_TOKEN_SPECIAL_VAR},
               {"$!", SHELL_TOKEN_SPECIAL_VAR},
               {"$@", SHELL_TOKEN_SPECIAL_VAR},
               {"$*", SHELL_TOKEN_SPECIAL_VAR},
               {"$-", SHELL_TOKEN_SPECIAL_VAR},
               {"$!x", SHELL_TOKEN_ARGUMENT},
               {"$@x", SHELL_TOKEN_ARGUMENT},
               {"$*x", SHELL_TOKEN_ARGUMENT},
               {"$", SHELL_TOKEN_ARGUMENT},
               {"${", SHELL_TOKEN_ARGUMENT},
               {"${%word}", SHELL_TOKEN_ARGUMENT},
               {"${!}", SHELL_TOKEN_SPECIAL_VAR},
               {"${#?}", SHELL_TOKEN_SPECIAL_VAR},
               {"${!1}", SHELL_TOKEN_SPECIAL_VAR},
               {"$()", SHELL_TOKEN_SUBSHELL},
               {"$(x)", SHELL_TOKEN_SUBSHELL},
               {"$(date)", SHELL_TOKEN_SUBSHELL},
               {"``", SHELL_TOKEN_SUBSHELL},
               {"`x`", SHELL_TOKEN_SUBSHELL},
               {"`date`", SHELL_TOKEN_SUBSHELL},
               {"`", SHELL_TOKEN_ARGUMENT},
               {"$(", SHELL_TOKEN_ARGUMENT},
               {"$((1+2))", SHELL_TOKEN_ARITHMETIC},
               {"*.txt", SHELL_TOKEN_GLOB},
               {"--foo*", SHELL_TOKEN_GLOB},
               {"-x?", SHELL_TOKEN_GLOB},
               {"--[ab]", SHELL_TOKEN_GLOB},
               {"-@(left|right)", SHELL_TOKEN_GLOB},
               {"--foo\\*", SHELL_TOKEN_ARGUMENT},
               {"\"-x?\"", SHELL_TOKEN_ARGUMENT},
               {"--dir/*.txt", SHELL_TOKEN_ARGUMENT},
               {"/tmp/*.txt", SHELL_TOKEN_ARGUMENT},
               {"dir/*.txt", SHELL_TOKEN_ARGUMENT},
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
               {"\"text\"", SHELL_TOKEN_ARGUMENT},
               {"plain", SHELL_TOKEN_ARGUMENT}};

  bool valid = shell_classify_raw_token("", 0) == SHELL_TOKEN_END;
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
               {"", SHELL_PATH_OTHER}};
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
               {"echo \"prefix $USER\"", "$EV_1", "testuser", NULL},
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
  TEST("abstraction rejects invalid inputs", valid);

  shell_abstract_command_free(NULL);
}

static void test_type_sequence_matrix(void) {
  printf("\n=== Type Sequence Matrix ===\n");
  shell_netstring_buffer_t netseq = {0};
  size_t command_count = 0;
  bool valid =
      shell_build_type_netseq_buffer(
          "printf 'two words'; cd /tmp", strlen("printf 'two words'; cd /tmp"),
          NULL, &netseq, &command_count) == SHELL_PROCESS_OK &&
      command_count == 2 && netseq.data &&
      (netseq.length != sizeof("15:6:printf,3:STR,,10:2:cd,2:AP,,") - 1 ||
       memcmp(netseq.data, "15:6:printf,3:STR,,10:2:cd,2:AP,,",
              netseq.length)) == 0;
  TEST("nested type sequence uses one record per command", valid);
  shell_netstring_buffer_free(&netseq);

  netseq = (shell_netstring_buffer_t){0};
  command_count = 0;
  valid = shell_build_type_netseq_buffer(
              "'my tool' 'two words'", strlen("'my tool' 'two words'"), NULL,
              &netseq, &command_count) == SHELL_PROCESS_OK &&
          command_count == 1 && netseq.data &&
          (netseq.length != sizeof("16:7:my tool,3:STR,,") - 1 ||
           memcmp(netseq.data, "16:7:my tool,3:STR,,", netseq.length)) == 0;
  TEST("nested type sequence preserves spaced executable names", valid);
  shell_netstring_buffer_free(&netseq);

  netseq = (shell_netstring_buffer_t){0};
  command_count = 0;
  valid = shell_build_type_netseq_buffer(
              "foo\"bar\" 'two words'", strlen("foo\"bar\" 'two words'"), NULL,
              &netseq, &command_count) == SHELL_PROCESS_OK &&
          command_count == 1 && netseq.data &&
          (netseq.length != sizeof("15:6:foobar,3:STR,,") - 1 ||
           memcmp(netseq.data, "15:6:foobar,3:STR,,", netseq.length)) == 0;
  TEST("nested type sequence shares quote-fragment decoding", valid);
  shell_netstring_buffer_free(&netseq);

  netseq = (shell_netstring_buffer_t){0};
  command_count = 0;
  valid = shell_build_type_netseq_buffer(
              "my\\\ncommand value", strlen("my\\\ncommand value"), NULL,
              &netseq, &command_count) == SHELL_PROCESS_OK &&
          command_count == 1 && netseq.data &&
          (netseq.length != sizeof("18:9:mycommand,3:STR,,") - 1 ||
           memcmp(netseq.data, "18:9:mycommand,3:STR,,", netseq.length)) == 0;
  TEST("nested type sequence shares escaped-newline decoding", valid);
  shell_netstring_buffer_free(&netseq);

  netseq = (shell_netstring_buffer_t){0};
  command_count = SIZE_MAX;
  valid = shell_build_type_netseq_buffer("'' value", strlen("'' value"), NULL,
                                         &netseq, &command_count) ==
              SHELL_PROCESS_EPARSE &&
          netseq.data == NULL && command_count == 0;
  TEST("nested type sequence rejects an empty decoded executable", valid);

  valid = shell_build_type_netseq_buffer(
              "", 0, NULL, &netseq, &command_count) == SHELL_PROCESS_EINPUT &&
          netseq.data == NULL && command_count == 0;
  TEST("nested type sequence validates every argument atomically", valid);

  shell_process_limits_t limits = {SIZE_MAX, SIZE_MAX, 0};
  limits.max_string_bytes = 1;
  valid = shell_build_type_netseq_buffer("echo x", strlen("echo x"), &limits,
                                         &netseq, &command_count) ==
              SHELL_PROCESS_EOUTPUT_LIMIT &&
          netseq.data == NULL && command_count == 0;
  TEST("nested type sequence enforces its outer output limit", valid);

  /* Input fits the bound, but its framed type sequence does not. This must
   * fail at the output measurement boundary, not in source parsing. */
  limits.max_string_bytes = 10;
  netseq = (shell_netstring_buffer_t){0};
  command_count = SIZE_MAX;
  valid = shell_build_type_netseq_buffer("echo x", strlen("echo x"), &limits,
                                         &netseq, &command_count) ==
              SHELL_PROCESS_EOUTPUT_LIMIT &&
          netseq.data == NULL && command_count == 0;
  TEST("nested type sequence checks framed output after parsing", valid);
}

int main(void) {
  printf("=== Shell Abstraction Tests ===\n");

  test_abstraction_matrix();
  test_bounded_span_and_statuses();
  test_dynamic_arithmetic_is_rejected();
  test_timed_complete_command_abstraction();
  test_compound_variable_quote_boundaries();
  test_compound_substitution_boundaries();
  test_parameter_expansion_metadata();
  test_nested_parameter_substitution_metadata();
  test_invalid_parameter_selectors();
  test_quote_aware_substitution_metadata();
  test_modern_word_abstractions();
  test_abstraction_allocation_failures();
  test_element_metadata();
  test_fragment_payload_metadata();
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
