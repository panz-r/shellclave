/* Grammar: how sources are tokenized and parsed, the fast parser's ranges and
 * groups, the inherited boundaries between commands, and the corpus of sources
 * the parsers must agree on. */
#include "../src/shell_pipeline_internal.h"
#include "../src/shell_processor_internal.h"
#include "../src/shell_semantics_internal.h"
#include "../src/shell_source_internal.h"
#include "../src/shell_tokenizer_full_internal.h"
#include "control_word_cases.h"
#include "depgraph_test_workspace.h"
#include "shell_abstract.h"
#include "shell_depgraph.h"
#include "shell_processor.h"
#include "shell_sequence.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include "shell_transform.h"
#include "syntax_boundary_cases.h"
#include "test_allocator.h"
#include "test_source_scans.h"
#include "word_expansion_cases.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#include "test_source_scans.h"
#endif
#include "../src/shell_builtin_internal.h"
#include "../src/shell_depgraph_internal.h"
#include "depgraph_compare.h"
#include "depgraph_invariants.h"
#include "graph_fixture.h"
#include "shell_netstring.h"
#include "shellclave_command_corpus_fixtures.h"

/* The tokenizer's allocation-failure checks use the test library's fault
 * injection, which the production variant does not link. */
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
/* --- tokenizer (from tokenizer_test.c) --- */
static int tokenizer_test_count = 0;
static int tokenizer_pass_count = 0;

/* Anomaly command sequences walk executable substitutions in source order,
 * including the special expansion grammar of an unquoted here-document body.
 * Keep that contract explicit: quote bytes in the body are data, but command
 * substitutions and parameter-expansion fallbacks execute before `cat`. */
static bool tokenizer_command_netseq_matches(const char *input,
                                             const char *expected,
                                             size_t expected_count) {
  shell_netstring_buffer_t sequence = {0};
  size_t count = 0;
  shell_process_status_t status = shell_build_command_netseq_buffer(
      input, strlen(input), NULL, &sequence, &count);
  bool matches = status == SHELL_PROCESS_OK && sequence.data != NULL &&
                 count == expected_count &&
                 (sequence.length != strlen(expected) ||
                  memcmp(sequence.data, expected, sequence.length)) == 0;
  shell_netstring_buffer_free(&sequence);
  return matches;
}

/* The grouped-redirection collector appends several independently owned
 * records. Exercise every allocation boundary through the public processor so
 * an error cannot expose a partial command or group-I/O list. */
static bool
tokenizer_process_commands_allocation_failure_atomic(const char *input) {
  if (!input)
    return false;
  shell_processed_commands_t processed = {0};
  shellsplit_test_alloc_reset();
  if (shell_process_commands(input, strlen(input), NULL, &processed) !=
      SHELL_PROCESS_OK)
    return false;
  size_t allocation_count = shellsplit_test_alloc_count();
  shell_processed_commands_free(&processed);
  if (allocation_count == 0)
    return false;

  bool valid = true;
  for (size_t fail_at = 1; fail_at <= allocation_count; fail_at++) {
    processed = (shell_processed_commands_t){
        .commands = (shell_command_info_t *)(uintptr_t)1,
        .command_count = SIZE_MAX,
    };
    shellsplit_test_alloc_fail_at(fail_at);
    shell_process_status_t status =
        shell_process_commands(input, strlen(input), NULL, &processed);
    valid = valid && status == SHELL_PROCESS_ENOMEM &&
            processed.commands == NULL && processed.command_count == 0;
    shell_processed_commands_free(&processed);
  }
  shellsplit_test_alloc_reset();
  return valid;
}

/* The legacy flat processor still owns several per-command buffers.  Its
 * callers must receive no partial command list if one of those allocations
 * fails, just like users of the structured result. */
static bool
tokenizer_process_command_allocation_failure_atomic(const char *input) {
  if (!input)
    return false;
  shell_command_info_t *infos = NULL;
  size_t count = 0;
  shellsplit_test_alloc_reset();
  if (shell_process_command(input, strlen(input), NULL, &infos, &count) !=
      SHELL_PROCESS_OK)
    return false;
  size_t allocation_count = shellsplit_test_alloc_count();
  shell_command_infos_free(infos, count);
  if (allocation_count == 0)
    return false;

  bool valid = true;
  for (size_t fail_at = 1; fail_at <= allocation_count; fail_at++) {
    infos = (shell_command_info_t *)(uintptr_t)1;
    count = SIZE_MAX;
    shellsplit_test_alloc_fail_at(fail_at);
    shell_process_status_t status =
        shell_process_command(input, strlen(input), NULL, &infos, &count);
    valid =
        valid && status == SHELL_PROCESS_ENOMEM && infos == NULL && count == 0;
    shell_command_infos_free(infos, count);
  }
  shellsplit_test_alloc_reset();
  return valid;
}

typedef struct {
  unsigned char *bytes;
  size_t capacity;
  size_t stop_after;
} tokenizer_decoded_word_capture_t;

typedef struct {
  unsigned char bytes[64];
  size_t length;
  size_t stop_after;
} tokenizer_source_byte_capture_t;

typedef struct {
  size_t count;
  size_t starts[2];
  size_t lengths[2];
  bool quoted[2];
} tokenizer_heredoc_body_capture_t;

static bool tokenizer_capture_source_byte(unsigned char byte, void *context) {
  tokenizer_source_byte_capture_t *capture = context;
  if (capture->length == sizeof(capture->bytes) ||
      (capture->stop_after != 0 && capture->length == capture->stop_after))
    return false;
  capture->bytes[capture->length++] = byte;
  return true;
}

static bool tokenizer_reject_source_byte(unsigned char byte, void *context) {
  (void)byte;
  (void)context;
  return false;
}

static bool tokenizer_capture_decoded_word_byte(unsigned char byte,
                                                size_t offset, void *context) {
  tokenizer_decoded_word_capture_t *capture = context;
  if (offset >= capture->capacity)
    return false;
  capture->bytes[offset] = byte;
  return capture->stop_after == 0 || offset + 1 < capture->stop_after;
}

void test(const char *name, int result) {
  tokenizer_test_count++;
  if (result) {
    tokenizer_pass_count++;
    printf("  [PASS] %s\n", name);
  } else {
    printf("  [FAIL] %s\n", name);
    exit(EXIT_FAILURE);
  }
}

static bool tokenizer_tokens_are_consistent(const char *input,
                                            shell_command_t *cmds,
                                            size_t count) {
  size_t input_len = strlen(input);
  for (size_t i = 0; i < count; i++) {
    if (cmds[i].start_pos > cmds[i].end_pos || cmds[i].end_pos > input_len)
      return false;
    for (size_t j = 0; j < cmds[i].token_count; j++) {
      shell_token_t *token = &cmds[i].tokens[j];
      if (token->position < cmds[i].start_pos ||
          token->position > cmds[i].end_pos ||
          token->length > cmds[i].end_pos - token->position ||
          token->position > input_len ||
          token->length > input_len - token->position ||
          token->start != input + token->position)
        return false;
    }
  }
  return true;
}

static bool tokenizer_processed_group_descriptors_match_source(
    const shell_parse_result_t *fast,
    const shell_processed_commands_t *result) {
  if (fast->group_count != result->group_count)
    return false;
  for (uint32_t i = 0; i < fast->group_count; i++) {
    const shell_group_t *source = &fast->groups[i];
    const shell_group_t *processed = &result->groups[i];
    if (source->start != processed->start || source->end != processed->end ||
        source->parent != processed->parent ||
        source->kind != processed->kind ||
        source->modifiers != processed->modifiers ||
        processed->first_command > result->command_count ||
        processed->command_count >
            result->command_count - processed->first_command)
      return false;
  }
  return true;
}

static void tokenizer_test_token_type_names(void) {
  static const char *names[] = {
      "COMMAND",
      "ARGUMENT",
      "PIPE",
      "REDIRECT_IN",
      "REDIRECT_OUT",
      "REDIRECT_ERR",
      "REDIRECT_APPEND",
      "SEMICOLON",
      "AND",
      "BACKGROUND",
      "OR",
      "SUBSHELL_START",
      "SUBSHELL_END",
      "GROUP_START",
      "GROUP_END",
      "END",
      "VARIABLE",
      "VARIABLE_QUOTED",
      "SPECIAL_VAR",
      "GLOB",
      "SUBSHELL",
      "ARITHMETIC",
      "PROCESS_SUB",
      "HEREDOC",
      "HERESTRING",
      "REDIRECT_READ_WRITE",
      "REDIRECT_CLOBBER",
      "PIPE_NEGATE",
      "REDIRECT_BOTH",
      "REDIRECT_BOTH_APPEND",
      "ANSI_C_QUOTED",
      "EXTGLOB",
      "ARRAY_ASSIGNMENT",
      "CASE_TERMINATE",
      "CASE_FALLTHROUGH",
      "CASE_TEST_NEXT",
      "PIPE_BOTH",
      "PIPE_TIME",
      "PIPE_TIME_OPTION",
      "ARITHMETIC_COMMAND",
      "CONDITIONAL_COMMAND",
  };
  bool valid = sizeof(names) / sizeof(names[0]) == SHELL_TOKEN_TYPE_COUNT;
  for (size_t i = 0; valid && i < sizeof(names) / sizeof(names[0]); i++)
    valid = strcmp(shell_token_type_name((shell_token_type_t)i), names[i]) == 0;
  valid =
      valid &&
      strcmp(shell_token_type_name((shell_token_type_t)SHELL_TOKEN_TYPE_COUNT),
             "UNKNOWN") == 0;
  test("Token type names cover every enum value", valid);
}

static void tokenizer_test_list_syntax_contract(void) {
  static const char *const valid[] = {
      "",
      "echo \\| \\& \\!",
      "echo '|' \"&&\"",
      "echo ';;' ';;&' ';&' \\;\\;",
      "case value in value) : ;; esac",
      "echo one;\n",
      "echo one &\n",
      "echo one |\n cat",
      "echo one |&\n cat",
      "echo one &&\n cat",
      "echo one ||\r\n cat",
      "echo one\n\n",
      "echo one # trailing comment\n",
      "# comment only",
      "for item in one; do :; done",
      "{ echo one; }",
      "\\;}",
      "((1)) 2>out",
      "((1))2>out",
      "((1))2>&1",
      "((1))2>>out",
      "((1))12>out",
      "((1))2<&0",
      "((1)){fd}>out",
      "((1)){fd}<f",
      "((1))#comment",
      "((1))>out",
      "((1))2>out#c",
      "echo 2>(:)",
      "echo 12<(:)",
      "echo a2>(:)",
      "echo >&2>(printf x)",
      "echo >2>(:)",
      "echo >&2<(:)",
      "echo >&2 >(:)",
      "echo 2>&1",
      "echo 2>out",
      "cat 3<f",
      "{<f echo one; }",
      "{>f echo one; }",
      "{ echo one; }<f",
      "{ echo one; }>f",
      "{\\\n echo one; }",
      "{\\\n\\\n echo one; }",
      "echo \"$({\\\n echo one; })\"",
      "( echo one; )",
      "{ echo one; } >/tmp/group.out 2>&1",
      "{ echo one; } >$(printf path)",
      "{ echo one; } > >(cat)",
      "{ echo one; } <<<$(printf body)",
      "( echo one; ) < <(printf input) | cat",
      "{ { echo one; } >/tmp/inner; echo two; } >/tmp/outer",
      "{ echo one; }; echo two",
      "( echo one; ) && echo two",
      "! ! command",
      "! \\\nprintf command",
      "! ! { printf command; } | cat",
      "echo !",
      "name()",
      "function sample { :; }",
      "function _sample { :; }",
      "sample() { :; }",
      "_sample() { :; }",
      "if true; then { :; }; else { :; }; fi",
      "while false; do { :; }; done",
  };
  static const char *const invalid[] = {
      ";;",
      ";&",
      ";;&",
      "echo one ;; echo two",
      "echo one ;& echo two",
      "echo one ;;& echo two",
      ")",
      "echo one; }",
      "echo one | )",
      "echo one { literal; }",
      "echo one (cat)",
      "echo one ((1))",
      "function { :; }",
      "echo one | ! cat",
      "echo one |& | cat",
      "echo one && && cat",
      "echo one || || cat",
      "echo one & & cat",
      "echo one |& ; cat",
      "echo one |& ! cat",
      "!",
      "! # continuation without a command\n",
      "! # note\nprintf command",
      "! \nprintf command",
      "! !",
      "echo one |\n",
      "echo one && # continuation without a command\n",
      "echo one\n| cat",
      "{ ; }",
      "()",
      "{ echo one; } echo two",
      "{\\\necho one; }",
      "{echo one; }",
      /* Only `))` ends its command; a word may not follow either closer. */
      "((1))abc",
      "((1))x>out",
      "((1))2>",
      "((1))(",
      "((1))\"x\"",
      "((1))$x",
      "[[ a ]]x",
      "[[ a ]]2>out",
      "[[ a ]]#c",
      "[[ a ]]{fd}>out",
      "}",
      "echo one; }",
      "( echo one; })",
      "}&",
      "{ echo one; }2>out",
      "{ echo one; }2>&1",
      "{ echo one; }x",
      "{;",
      "{<(echo one) cat; }",
      "{",
      "echo one; {",
      "{ echo one; } 'echo two'",
      "( echo one; ) ! echo two",
      "{ echo one; } >",
      "{ echo one; } > && echo two",
      "{ echo one; } > { echo two; }",
      "echo ! { x; }",
      "echo then { x; }",
      "echo do { x; }",
      "echo else { x; }",
      "echo elif { x; }",
  };
  bool valid_syntax = !shell_tokenizer_list_syntax_valid(NULL, 0);
  for (size_t i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
    if (!shell_tokenizer_list_syntax_valid(valid[i], strlen(valid[i]))) {
      printf("    valid list syntax rejected: %s\n", valid[i]);
      valid_syntax = false;
    }
  }
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    if (shell_tokenizer_list_syntax_valid(invalid[i], strlen(invalid[i]))) {
      printf("    invalid list syntax accepted: %s\n", invalid[i]);
      valid_syntax = false;
    }
  }

  char nesting[(SHELL_MAX_GROUPS + 1u) * 3u + 2u];
  size_t position = 0;
  for (size_t i = 0; i <= SHELL_MAX_GROUPS; i++) {
    nesting[position++] = '(';
    nesting[position++] = ' ';
  }
  nesting[position++] = ':';
  for (size_t i = 0; i <= SHELL_MAX_GROUPS; i++)
    nesting[position++] = ')';
  nesting[position] = '\0';
  valid_syntax =
      valid_syntax && !shell_tokenizer_list_syntax_valid(nesting, position);
  test("List syntax accepts continuations and rejects impossible operators",
       valid_syntax);

  static const char *const modeled[] = {
      "echo one;\n",
      "echo one |\n cat",
      "echo one |&\n cat",
      "echo one &&\n cat",
      "echo one ||\r\n cat",
      "{ echo one; } |& { cat; }",
      "{\\\n echo one; }",
      "! ! printf command |& cat",
      "((1))2>out",
      "((1)){fd}>out",
      /* Digits after an operator are a file name unless they touch another
       * redirect operator. */
      "echo >2",
      "echo x >2",
      "echo >22",
      "echo 2>2",
      "echo <2",
      "{ echo; } >2",
      ": >12",
      "echo >2;",
      "echo >2&",
      "echo >2>(:)",
  };
  bool public_contract = true;
  for (size_t i = 0; i < sizeof(modeled) / sizeof(modeled[0]); i++) {
    const char *input = modeled[i];
    shell_parse_result_t fast = {0};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    bool accepted =
        shell_parse_fast(input, strlen(input), NULL, &fast) == SHELL_OK &&
        fast.count > 0 &&
        shell_tokenize_commands(input, strlen(input), &commands,
                                &command_count) == SHELL_TOKENIZE_OK &&
        command_count > 0 &&
        shell_process_commands(input, strlen(input), NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count > 0 &&
        shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    if (!accepted) {
      printf("    valid public list rejected: %s\n", input);
      public_contract = false;
    }
  }
  test("List grammar agrees across public parsing surfaces", public_contract);

  /* Digits touching a second operator are its IO number, leaving the first
   * operator without a target: Bash rejects each of these. */
  static const char *const no_target[] = {"echo >2>x", "echo >2<x",
                                          "echo >2>>x", "echo >2>&1"};
  bool targets_required = true;
  for (size_t i = 0; i < sizeof(no_target) / sizeof(no_target[0]); i++) {
    shell_limits_t strict = SHELL_LIMITS_DEFAULT;
    strict.strict_mode = true;
    shell_parse_result_t parsed = {0};
    if (shell_parse_fast(no_target[i], strlen(no_target[i]), &strict,
                         &parsed) != SHELL_EPARSE) {
      printf("    redirect without a target accepted: %s\n", no_target[i]);
      targets_required = false;
    }
  }
  test("A redirect touching another operator has no target", targets_required);
}

static void tokenizer_test_source_scanner_boundaries(void) {
  static const struct {
    const char *prefix;
    bool descriptor;
  } boundaries[] = {
      {"", true},
      {"cat ", true},
      {"cat\t", true},
      {"cat\r\n", true},
      {"cat \\\n", true},
      {"cat \\\n", true},
      {"cat x\\ ", false},
      {"cat $'x'", false},
      {"cat ''", false},
      {"cat \"\"", false},
      {"cat $'x'\\\n", false},
      {"cat $'x'\\\n", false},
      {"cat $(echo)", false},
      {"cat ${value}", false},
      {"cat $((1))", false},
      {"cat <(echo)", false},
      {"cat >(echo)", false},
      {"cat @(one|two)", false},
      {"cat foo}", false},
      {"cat \\;", false},
      {"(cat)", true},
      {"{ cat; }", true},
      {"cat;", true},
      {"cat&&", true},
      {"cat|", true},
      {"cat <<EOF\n' ) ${\nEOF\n(cat)", true},
      {"# '(\n(cat)", true},
  };
  bool boundary_valid = !shell_source_word_boundary(NULL, 0, 0) &&
                        !shell_source_word_boundary("", 0, 1);
  for (size_t i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); i++) {
    char source[128];
    int length =
        snprintf(source, sizeof(source), "%s1\\\n2>", boundaries[i].prefix);
    size_t start = strlen(boundaries[i].prefix);
    bool matched = length > 0 &&
                   shell_source_word_boundary(source, (size_t)length, start) ==
                       boundaries[i].descriptor;
    if (!matched)
      fprintf(stderr, "Descriptor boundary mismatch: %s\n", source);
    boundary_valid = boundary_valid && matched;
  }
  test("Descriptor prefixes require whole words across source continuations",
       boundary_valid);
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

  shell_pipeline_prefix_state_t prefix_state =
      shell_pipeline_prefix_state_initial(true);
  shell_source_pipeline_prefix_t prefix = shell_source_parse_pipeline_prefix(
      "time -p -- ! printf x", 0, strlen("time -p -- ! printf x"));
  valid =
      valid && prefix.valid && prefix.has_modifier &&
      prefix.stage_start == strlen("time -p -- ! ") &&
      prefix.time_mode == SHELL_PIPE_TIME_POSIX && prefix.negation_count == 1 &&
      prefix.ends_with_negator &&
      shell_pipeline_prefix_step(&prefix_state, SHELL_PIPE_PREFIX_WORD_TIME) ==
          SHELL_PIPE_PREFIX_ACCEPTED_TIME &&
      shell_pipeline_prefix_step(&prefix_state, SHELL_PIPE_PREFIX_WORD_POSIX) ==
          SHELL_PIPE_PREFIX_ACCEPTED_OPTION &&
      shell_pipeline_prefix_step(&prefix_state,
                                 SHELL_PIPE_PREFIX_WORD_END_OPTIONS) ==
          SHELL_PIPE_PREFIX_ACCEPTED_OPTION;
  prefix_state.negation_count = UINT32_MAX;
  valid =
      valid &&
      shell_pipeline_prefix_step(&prefix_state,
                                 SHELL_PIPE_PREFIX_WORD_NEGATE) ==
          SHELL_PIPE_PREFIX_OVERFLOW &&
      !prefix_state.valid &&
      shell_pipeline_prefix_step(&prefix_state, SHELL_PIPE_PREFIX_WORD_TIME) ==
          SHELL_PIPE_PREFIX_NOT_ACCEPTED;
  prefix = shell_source_parse_pipeline_prefix("", 0, 0);
  valid =
      valid && prefix.valid && !prefix.has_modifier && prefix.stage_start == 0;

  size_t compound_prefix_end = 0;
  valid = valid &&
          shell_tokenizer_compound_prefix_span("! time -p { echo x; }",
                                               strlen("! time -p { echo x; }"),
                                               0, &compound_prefix_end) &&
          compound_prefix_end == strlen("! time -p ") &&
          !shell_tokenizer_compound_prefix_span(
              "time echo x", strlen("time echo x"), 0, &compound_prefix_end) &&
          !shell_tokenizer_compound_prefix_span("echo time { x; }",
                                                strlen("echo time { x; }"), 0,
                                                &compound_prefix_end);

  valid = valid &&
          shell_source_parse_named_fd("{trace}>out", 0, strlen("{trace}>out"),
                                      &after) &&
          after == strlen("{trace}") &&
          !shell_source_parse_named_fd("{9}>out", 0, strlen("{9}>out"), &after);

  static const struct {
    const char *source;
    bool descriptor;
    bool redirect;
  } named_boundaries[] = {
      {"{fd}>out", true, true},         {"{f\\\nd}>out", true, true},
      {"{f\\\nd}\\\n>out", true, true}, {"{f\\\rd}>out", false, false},
      {"{f\\\r\nd}>out", false, false}, {"{fd} >out", true, false},
      {"{fd}\t>out", true, false},      {"{f d}>out", false, false},
      {"x{fd}>out", false, false},      {"''{fd}>out", false, false},
      {"$'x'{fd}>out", false, false},   {"${x}{fd}>out", false, false},
      {"$(x){fd}>out", false, false},   {"{9}>out", false, false},
      {"{}>out", false, false},
  };
  for (size_t i = 0; i < sizeof(named_boundaries) / sizeof(named_boundaries[0]);
       i++) {
    const char *source = named_boundaries[i].source;
    size_t length = strlen(source);
    const char *brace = strchr(source, '{');
    size_t start = brace ? (size_t)(brace - source) : length;
    const char *operator = strrchr(source, '>');
    size_t marker = operator ? (size_t)(operator - source) : length;
    size_t named_after = 0;
    size_t redirect_after = 0;
    bool parsed =
        shell_source_parse_named_fd(source, start, length, &named_after);
    bool redirect = shell_source_parse_named_fd_redirect(source, start, length,
                                                         &redirect_after);
    valid = valid && parsed == named_boundaries[i].descriptor &&
            redirect == named_boundaries[i].redirect &&
            (!redirect || redirect_after == marker);
  }

  size_t parameter_start = 0;
  size_t parameter_end = 0;
  size_t expansion_end = 0;
  static const char continued_parameter[] = "\"${f\\\nd}\"";
  static const char continued_after_dollar_lf[] = "$\\\n{fd}";
  static const char continued_after_dollar_crlf[] = "$\\\r\n{fd}";
  static const char continued_after_dollar_cr[] = "$\\\r{fd}";
  static const char quoted_after_dollar_lf[] = "\"$\\\n{fd}\"";
  valid =
      valid &&
      shell_source_parse_named_fd_parameter("$fd", 0, strlen("$fd"),
                                            &parameter_start, &parameter_end) &&
      parameter_start == 1 && parameter_end == 3 &&
      shell_source_parse_named_fd_parameter(
          continued_after_dollar_lf, 0, sizeof(continued_after_dollar_lf) - 1,
          &parameter_start, &parameter_end) &&
      parameter_start == 4 && parameter_end == 6 &&
      !shell_source_parse_named_fd_parameter(
          continued_after_dollar_crlf, 0,
          sizeof(continued_after_dollar_crlf) - 1, &parameter_start,
          &parameter_end) &&
      !shell_source_parse_named_fd_parameter(
          continued_after_dollar_cr, 0, sizeof(continued_after_dollar_cr) - 1,
          &parameter_start, &parameter_end) &&
      shell_source_parse_named_fd_parameter(quoted_after_dollar_lf, 0,
                                            sizeof(quoted_after_dollar_lf) - 1,
                                            &parameter_start, &parameter_end) &&
      parameter_start == 5 && parameter_end == 7 &&
      shell_source_skip_variable_expansion(
          continued_after_dollar_lf, sizeof(continued_after_dollar_lf) - 1, 0,
          &expansion_end) &&
      expansion_end == sizeof(continued_after_dollar_lf) - 1 &&
      shell_source_parse_named_fd_parameter(continued_parameter, 0,
                                            sizeof(continued_parameter) - 1,
                                            &parameter_start, &parameter_end) &&
      parameter_start == 3 && parameter_end == 7 &&
      !shell_source_parse_named_fd_parameter("${fd:-1}", 0, 8, &parameter_start,
                                             &parameter_end) &&
      !shell_source_parse_named_fd_parameter(
          "$fd-suffix", 0, 10, &parameter_start, &parameter_end) &&
      !shell_source_parse_named_fd_parameter("\"$fd", 0, 4, &parameter_start,
                                             &parameter_end) &&
      shell_source_redirection_consumes_word(">&", 2) &&
      shell_source_redirection_consumes_word(">|", 2) &&
      !shell_source_redirection_consumes_word("2>&1", 4);

  valid = valid && shell_source_comment_starts('#', true) &&
          !shell_source_comment_starts('#', false) &&
          !shell_source_comment_starts('x', true) &&
          shell_source_line_end("line\r\n", 6, 0) == 5 &&
          shell_source_next_line("line\nnext", 9, 0) == 5;

  /* Redirect topology uses the same expansion predicate as argument words:
   * preserve quoted and escaped literals, but mark expansion forms that
   * could select a different endpoint at execution time as dynamic. */
  static const struct {
    const char *word;
    bool dynamic;
  } redirect_words[] = {
      {"plain", false},
      {"'quoted'", false},
      {"\"quoted\"", false},
      {"\\$literal", false},
      {"$'literal'", false},
      {"$'unterminated", true},
      {"$name", true},
      {"`command`", true},
      {">(consumer)", true},
      {"*.log", true},
      {"?", true},
      {"[a]", true},
      {"{a,b}", true},
      {"{a..c}", true},
      {"{1..3}", true},
      {"{a..c..2}", true},
      {"{{a,b}}", true},
      {"foo{bar}", false},
      {"foo{bar..baz}", false},
      {"foo\\{a,b\\}", false},
      {"foo\"{a,b}\"", false},
      {"{1..2..3..4}", false},
      {"{a..}", false},
      {"{..b}", false},
      {"{a..b..}", false},
      {"{-..2}", false},
      {"{1..x}", false},
      {"{ab..cd}", false},
      {"{'a,b'}", false},
      {"{\"a,b\"}", false},
      {"{a\\,b}", false},
      {"{$'a,b'}", false},
      {"{a\\\nb}", false},
      {"?(one|two)", true},
      {"*(one|two)", true},
      {"+(one|two)", true},
      {"@(one|two)", true},
      {"!(one|two)", true},
      {"~", true},
      {"\\\n~", true},
      {"prefix\\\n~", false},
      {"\\", true},
      {"'~'", false},
      {"\"*.log\"", false},
      {"'unterminated", true},
      {"\"unterminated", true},
  };
  for (size_t i = 0;
       valid && i < sizeof(redirect_words) / sizeof(redirect_words[0]); i++) {
    bool dynamic = shell_source_argument_has_dynamic_syntax(
        redirect_words[i].word, strlen(redirect_words[i].word));
    if (dynamic != redirect_words[i].dynamic) {
      fprintf(stderr, "redirect dynamic-syntax mismatch: %s\n",
              redirect_words[i].word);
      valid = false;
    }
  }

  /* Descriptor duplication evaluates a complete static word before deciding
   * whether it names an fd. Quoting therefore does not turn `>&"7"` into a
   * filename redirect. ANSI-C NUL truncation can leave a valid fd, close
   * marker or pathname; malformed words remain unusable as any of them. */
  static const struct {
    const char *word;
    shell_process_fd_target_t target;
    uint32_t fd;
  } fd_targets[] = {
      {"7", SHELL_PROCESS_FD_TARGET_FD, 7},
      {"\"7\"", SHELL_PROCESS_FD_TARGET_FD, 7},
      {"$'7'", SHELL_PROCESS_FD_TARGET_FD, 7},
      {"0000000000000000000000000000000000000001", SHELL_PROCESS_FD_TARGET_FD,
       1},
      {"$'0000000000000000000000000000000000000001'",
       SHELL_PROCESS_FD_TARGET_FD, 1},
      {"2147483647", SHELL_PROCESS_FD_TARGET_FD, 2147483647u},
      {"2147483648", SHELL_PROCESS_FD_TARGET_INVALID, SHELL_PROCESS_FD_NONE},
      {"00000000000000000000000000000000002147483648",
       SHELL_PROCESS_FD_TARGET_INVALID, SHELL_PROCESS_FD_NONE},
      {"-", SHELL_PROCESS_FD_TARGET_CLOSE, SHELL_PROCESS_FD_NONE},
      {"\"-\"", SHELL_PROCESS_FD_TARGET_CLOSE, SHELL_PROCESS_FD_NONE},
      {"path", SHELL_PROCESS_FD_TARGET_PATH, SHELL_PROCESS_FD_NONE},
      {"$name", SHELL_PROCESS_FD_TARGET_PATH, SHELL_PROCESS_FD_NONE},
      {"$'a\\0b'", SHELL_PROCESS_FD_TARGET_PATH, SHELL_PROCESS_FD_NONE},
      {"$'7\\0ignored'", SHELL_PROCESS_FD_TARGET_FD, 7},
      {"$'-\\0ignored'", SHELL_PROCESS_FD_TARGET_CLOSE, SHELL_PROCESS_FD_NONE},
      {"abcdefghijklmnopqrstuvwxyzabcdefghi", SHELL_PROCESS_FD_TARGET_PATH,
       SHELL_PROCESS_FD_NONE},
      {"$'\\0'abcdefghijklmnopqrstuvwxyzabcdefghi",
       SHELL_PROCESS_FD_TARGET_PATH, SHELL_PROCESS_FD_NONE},
      {"", SHELL_PROCESS_FD_TARGET_INVALID, SHELL_PROCESS_FD_NONE},
  };
  for (size_t i = 0; valid && i < sizeof(fd_targets) / sizeof(fd_targets[0]);
       i++) {
    uint32_t fd = 0;
    valid = shell_process_classify_static_fd_target(
                fd_targets[i].word, strlen(fd_targets[i].word), &fd) ==
                fd_targets[i].target &&
            fd == fd_targets[i].fd;
  }

  static const char list_trivia[] = " \\\n# note\r\n\t\nstage";
  size_t stage = strlen(" \\\n# note\r\n\t\n");
  valid = valid &&
          shell_source_skip_list_trivia(list_trivia, sizeof(list_trivia) - 1,
                                        0) == stage &&
          shell_source_is_list_trivia(list_trivia, 0, stage) &&
          shell_source_skip_list_trivia("word", 4, 0) == 0 &&
          shell_source_skip_list_trivia(NULL, 0, 0) == 0;

  /* Only backslash-LF is erased by the shell grammar. CR and CRLF remain
   * ordinary word bytes followed, in the latter case, by a separator LF. */
  static const char lf_continuation[] = "\\\n";
  static const char crlf_word[] = "\\\r\n";
  valid =
      valid && !shell_source_is_escaped_line_ending(NULL, 0, 0) &&
      !shell_source_is_escaped_line_ending("x", 0, 1) &&
      !shell_source_is_escaped_line_ending("\\", 0, 1) &&
      shell_source_is_escaped_line_ending(lf_continuation, 0,
                                          sizeof(lf_continuation) - 1) &&
      !shell_source_is_escaped_line_ending(crlf_word, 0,
                                           sizeof(crlf_word) - 1) &&
      !shell_source_is_escaped_line_ending(crlf_word, 0, 2) &&
      shell_source_skip_inline_continuations(" \t\\\n\\\nword", 10, 0) == 6 &&
      shell_source_skip_inline_continuations("word", 4, 0) == 0 &&
      shell_source_skip_inline_continuations(NULL, 0, 0) == 0 &&
      shell_source_skip_redirect("> >(cmd", 0, strlen("> >(cmd")) == 0 &&
      shell_source_skip_redirect(">& >(cmd", 0, strlen(">& >(cmd")) == 0;

  tokenizer_source_byte_capture_t capture = {0};
  static const char ansi[] = "$'\\a\\b\\e\\E\\f\\n\\r\\t\\v\\\\\\'\\\"\\?"
                             "\\cA\\x41\\u00e9\\U0001f600\\101\\q'";
  size_t position = 0;
  valid = valid &&
          shell_source_decode_ansi_c_quote(ansi, sizeof(ansi) - 1, &position,
                                           tokenizer_capture_source_byte,
                                           &capture) &&
          position == sizeof(ansi) - 1 && capture.length > 16;
  tokenizer_source_byte_capture_t rejected = {.stop_after = 1};
  position = 0;
  valid = valid &&
          !shell_source_decode_ansi_c_quote("$'ab'", strlen("$'ab'"), &position,
                                            tokenizer_capture_source_byte,
                                            &rejected) &&
          rejected.length == 1;
  static const char *const control_backslashes[] = {"$'\\c\\\\X'",
                                                    "$'\\c\\'X'"};
  for (size_t i = 0;
       i < sizeof(control_backslashes) / sizeof(control_backslashes[0]); ++i) {
    position = 0;
    valid = valid &&
            !shell_source_decode_ansi_c_quote(
                control_backslashes[i], strlen(control_backslashes[i]),
                &position, tokenizer_reject_source_byte, NULL) &&
            position == 6;
  }
  tokenizer_source_byte_capture_t protected_quote = {.stop_after = 1};
  position = 0;
  valid = valid &&
          !shell_source_decode_ansi_c_quote(
              "$'\\c\\'X'", strlen("$'\\c\\'X'"), &position,
              tokenizer_capture_source_byte, &protected_quote) &&
          position == 6 && protected_quote.length == 1 &&
          protected_quote.bytes[0] == 0x1c;
  /* Incomplete ANSI-C escapes remain literal bytes. This matters to the
   * canonical netargv builder because dropping the backslash changes argv. */
  tokenizer_source_byte_capture_t incomplete_control = {0};
  tokenizer_source_byte_capture_t incomplete_hex = {0};
  tokenizer_source_byte_capture_t incomplete_unicode = {0};
  position = 0;
  valid = valid &&
          shell_source_decode_ansi_c_quote(
              "$'\\c'", strlen("$'\\c'"), &position,
              tokenizer_capture_source_byte, &incomplete_control) &&
          incomplete_control.length == 2 &&
          memcmp(incomplete_control.bytes, "\\c", 2) == 0;
  position = 0;
  valid =
      valid &&
      shell_source_decode_ansi_c_quote("$'\\x'", strlen("$'\\x'"), &position,
                                       tokenizer_capture_source_byte,
                                       &incomplete_hex) &&
      incomplete_hex.length == 2 && memcmp(incomplete_hex.bytes, "\\x", 2) == 0;
  position = 0;
  valid = valid &&
          shell_source_decode_ansi_c_quote(
              "$'\\u'", strlen("$'\\u'"), &position,
              tokenizer_capture_source_byte, &incomplete_unicode) &&
          incomplete_unicode.length == 2 &&
          memcmp(incomplete_unicode.bytes, "\\u", 2) == 0;
  valid = valid &&
          shell_source_ansi_emit_codepoint(tokenizer_capture_source_byte,
                                           &capture, 0x800) &&
          shell_source_ansi_emit_codepoint(tokenizer_capture_source_byte,
                                           &capture, 0x200000) &&
          shell_source_ansi_emit_codepoint(tokenizer_capture_source_byte,
                                           &capture, 0x4000000) &&
          shell_source_ansi_emit_codepoint(tokenizer_capture_source_byte,
                                           &capture, UINT32_MAX);

  static const char heredocs[] = "<<A <<-'B'\nbody\nA\n\tB\n";
  bool complete = false;
  after = 0;
  valid = valid &&
          shell_source_skip_heredoc_sequence(heredocs, sizeof(heredocs) - 1, 0,
                                             &after, &complete) &&
          complete && after == sizeof(heredocs) - 1;
  static const char unterminated[] = "<<EOF\nbody\n";
  after = 0;
  complete = true;
  valid = valid &&
          shell_source_skip_heredoc_sequence(
              unterminated, sizeof(unterminated) - 1, 0, &after, &complete) &&
          !complete && after == sizeof(unterminated) - 1;
  /* Declaration-line shell syntax must not create a false delimiter or
   * expose a document body before the pending heredoc is recognized. */
  static const char *const declaration_forms[] = {
      "<<EOF $'quoted <</>'\nbody\nEOF\n",   "<<EOF 'quoted <</>'\nbody\nEOF\n",
      "<<EOF $(printf '<</>')\nbody\nEOF\n", "<<EOF $((1 + 2))\nbody\nEOF\n",
      "<<EOF <(printf '<</>')\nbody\nEOF\n", "<<EOF # comment\nbody\nEOF\n",
  };
  for (size_t i = 0;
       valid && i < sizeof(declaration_forms) / sizeof(declaration_forms[0]);
       i++) {
    size_t length = strlen(declaration_forms[i]);
    complete = false;
    valid = shell_source_skip_heredoc_sequence(declaration_forms[i], length, 0,
                                               &after, &complete) &&
            complete && after == length;
  }
  static const char *const malformed_declarations[] = {
      "<<EOF $'unterminated\nbody\nEOF\n",
      "<<EOF $(unterminated\nbody\nEOF\n",
  };
  for (size_t i = 0; valid && i < sizeof(malformed_declarations) /
                                      sizeof(malformed_declarations[0]);
       i++) {
    complete = false;
    valid = !shell_source_skip_heredoc_sequence(
        malformed_declarations[i], strlen(malformed_declarations[i]), 0, &after,
        &complete);
  }

  static const char arithmetic[] = "$((1 + $((2)) + $(printf x)))";
  after = 0;
  valid = valid &&
          shell_source_skip_arithmetic_expansion(
              arithmetic, sizeof(arithmetic) - 1, 0, &after) &&
          after == sizeof(arithmetic) - 1;
  static const char balanced[] = "(echo $' ) ' $(printf ')') # )\n)";
  after = 0;
  valid = valid &&
          shell_source_find_balanced_parentheses(balanced, sizeof(balanced) - 1,
                                                 0, &after) &&
          after == sizeof(balanced) - 1 &&
          shell_source_skip_balanced_parentheses("(unterminated", 13, 0) == 13;

  static const char array_subscript[] = "[$(printf ']')$((1 + 2))[nested]]";
  after = 0;
  valid = valid &&
          shell_source_skip_array_subscript(
              array_subscript, sizeof(array_subscript) - 1, 0, &after) &&
          after == sizeof(array_subscript) - 1;
  /* Subscripts may nest quoted delimiters and physical continuations. A
   * malformed inner expansion must not make a later `]` look like a valid
   * outer terminator. */
  static const char *const valid_subscripts[] = {
      "[a\\\nb]",
      "[a\\\nb]",
      "[$'hidden ]' + 1]",
      "['hidden ]' + 1]",
      "[\"hidden ]\" + 1]",
      "[`printf ']'` + 1]",
      "[$((1 + 2)) + 1]",
      "[$(printf ']') + 1]",
      "[${v:-]} + (2)]",
      "[${v:-[} + (2)]",
      "[${v:-${w:-]}}]",
      "[${v:-$(printf ])}]",
      "[<(printf ]) + 1]",
      "[>(printf [) + 1]",
      "[${indices[0]:-]}]",
      "[$\\\n{v:-]} + 1]",
      "[<\\\n(printf ]) + 1]",
      "[${v:-\"] [\"}]",
      "[${v:-<(printf ])}]",
      "[[nested]]",
  };
  for (size_t i = 0;
       valid && i < sizeof(valid_subscripts) / sizeof(valid_subscripts[0]);
       i++) {
    size_t length = strlen(valid_subscripts[i]);
    valid = shell_source_skip_array_subscript(valid_subscripts[i], length, 0,
                                              &after) &&
            after == length;
  }
  static const char *const invalid_subscripts[] = {
      "[$'unterminated]", "['unterminated]", "[$((1 + 2]",
      "[$(printf x]",     "[${v:-]",         "[${v:-[}",
      "[<(printf ]",      "[>(printf [",     "[${}]",
      "[${v!}]",
  };
  for (size_t i = 0;
       valid && i < sizeof(invalid_subscripts) / sizeof(invalid_subscripts[0]);
       i++) {
    size_t length = strlen(invalid_subscripts[i]);
    valid = !shell_source_skip_array_subscript(invalid_subscripts[i], length, 0,
                                               &after);
  }
  valid = valid &&
          shell_source_skip_array_subscript(
              "[nested] tail", strlen("[nested] tail"), 0, &after) &&
          after == strlen("[nested]");
  size_t subscript_start = 0;
  static const char parameter[] = "${items[$(printf key)]}";
  valid = valid &&
          shell_source_find_parameter_array_subscript(
              parameter, sizeof(parameter) - 1, 0, &after, &subscript_start) &&
          subscript_start == strlen("${items") &&
          shell_source_array_assignment_is_compound(
              "items+=(one two)", strlen("items+=(one two)")) &&
          !shell_source_array_assignment_is_compound("items[0]=one",
                                                     strlen("items[0]=one"));
  static const char *const parameter_forms[] = {
      "${#}",
      "${#name}",
      "${!name}",
      "${!prefix*}",
      "${!prefix@}",
      "${items[0]}",
      "${name\\\n:-fallback}",
      "${9:-fallback}",
  };
  for (size_t i = 0;
       valid && i < sizeof(parameter_forms) / sizeof(parameter_forms[0]); i++) {
    size_t length = strlen(parameter_forms[i]);
    valid = shell_source_skip_parameter_expansion(parameter_forms[i], length, 0,
                                                  &after) &&
            after == length;
  }
  static const char *const invalid_parameter_forms[] = {
      "${#",
      "${!",
      "${!name[unterminated}",
      "${name$other}",
  };
  for (size_t i = 0; valid && i < sizeof(invalid_parameter_forms) /
                                      sizeof(invalid_parameter_forms[0]);
       i++) {
    valid = !shell_source_skip_parameter_expansion(
        invalid_parameter_forms[i], strlen(invalid_parameter_forms[i]), 0,
        &after);
  }

  static const char word[] = "prefix$' x '$(printf y)$((1 + 2))\\ z next";
  valid = valid &&
          shell_source_skip_shell_word(word, sizeof(word) - 1, 0, &after) &&
          after == strlen("prefix$' x '$(printf y)$((1 + 2))\\ z");
  static const char *const redirects[] = {
      "2>>out",  "<&0",      "&>>out",   "{fd}>out",
      "3<>file", "> >(cat)", "< <(cat)", "<<<word",
  };
  for (size_t i = 0; valid && i < sizeof(redirects) / sizeof(redirects[0]); i++)
    valid = shell_source_skip_redirect(redirects[i], 0, strlen(redirects[i])) ==
            strlen(redirects[i]);
  static const char fd_line_continuation[] = "3\\\n>out";
  static const char *const combined_prefix_words[] = {
      "2&>out",
      "3&>>out",
      "{fd}&>out",
  };
  valid = valid &&
          shell_source_skip_redirect("3 >out", 0, strlen("3 >out")) == 0 &&
          shell_source_skip_redirect(fd_line_continuation, 0,
                                     sizeof(fd_line_continuation) - 1) ==
              sizeof(fd_line_continuation) - 1;
  for (size_t i = 0; valid && i < sizeof(combined_prefix_words) /
                                      sizeof(combined_prefix_words[0]);
       i++) {
    size_t length = strlen(combined_prefix_words[i]);
    valid =
        shell_source_skip_redirect(combined_prefix_words[i], 0, length) == 0 &&
        !shell_source_redirect_list_before_group(combined_prefix_words[i], 0,
                                                 length);
  }
  valid = valid &&
          shell_source_redirect_list_before_group("2>out 3>>err", 0,
                                                  strlen("2>out 3>>err")) &&
          !shell_source_redirect_list_before_group("2>out command", 0,
                                                   strlen("2>out command"));

  valid =
      valid &&
      !shell_source_skip_complete_ansi_c_quote("$'x\\'", 5, 0, &after) &&
      shell_source_skip_complete_ansi_c_quote("$'x\\\\'", 6, 0, &after) &&
      after == 6 &&
      !shell_source_skip_complete_ansi_c_quote("$'unterminated", 14, 0, &after);
  position = 0;
  valid =
      valid && !shell_source_decode_ansi_c_quote(
                   NULL, 0, &position, tokenizer_capture_source_byte, &capture);
  position = 0;
  valid = valid && !shell_source_decode_ansi_c_quote(
                       "$'trailing\\", strlen("$'trailing\\"), &position,
                       tokenizer_capture_source_byte, &capture);
  static const char ansi_literal_variable[] = "$'don\\'t $literal'";
  static const char ansi_then_variable[] = "$'don\\'t $literal'${NAME}";
  shell_token_t ansi_literal_token = {
      .start = ansi_literal_variable,
      .length = sizeof(ansi_literal_variable) - 1,
  };
  shell_token_t ansi_then_variable_token = {
      .start = ansi_then_variable,
      .length = sizeof(ansi_then_variable) - 1,
  };
  valid = valid && !shell_tokenizer_token_has_variable(&ansi_literal_token) &&
          shell_tokenizer_token_has_variable(&ansi_then_variable_token);

  size_t reserved_after = SIZE_MAX;
  shell_source_compound_tail_t empty_tail =
      shell_source_parse_compound_tail("", 0, 0);
  shell_source_compound_tail_t logical_or_tail =
      shell_source_parse_compound_tail("||", 2, 0);
  valid =
      valid &&
      !shell_source_match_plain_word("", 0, 0, "time", 4, &reserved_after) &&
      reserved_after == 0 && !empty_tail.has_pipeline &&
      empty_tail.redirect_end == 0 && !logical_or_tail.has_pipeline &&
      logical_or_tail.redirect_end == 0;
  /* Every caller that scans a borrowed word must fail closed on malformed
   * quote fragments. These direct helper checks keep the same contract across
   * substitutions, array subscripts, and redirect operands. */
  shell_source_variable_scan_t variable_scan = {0};
  static const char malformed_ansi_fragment[] = "$'unterminated";
  valid =
      valid &&
      !shell_source_next_variable_expansion(NULL, 0, &variable_scan, &position,
                                            &after) &&
      !shell_tokenizer_token_has_variable(&(shell_token_t){0}) &&
      !shell_source_find_balanced_parentheses(
          "($'unterminated", strlen("($'unterminated"), 0, &after) &&
      !shell_source_skip_array_subscript(
          "[$'unterminated", strlen("[$'unterminated"), 0, &after) &&
      !shell_source_skip_parameter_expansion(
          "${name$'unterminated", strlen("${name$'unterminated"), 0, &after) &&
      !shell_source_skip_array_subscript(NULL, 0, 0, &after) &&
      !shell_source_find_parameter_array_subscript(NULL, 0, 0, &after,
                                                   &subscript_start) &&
      shell_source_skip_redirect_word(malformed_ansi_fragment, 0,
                                      sizeof(malformed_ansi_fragment) - 1) ==
          sizeof(malformed_ansi_fragment) - 1;
  static const char malformed_ansi[] = "$'\\c\\x\\u\\q'";
  position = 0;
  valid = valid && shell_source_decode_ansi_c_quote(
                       malformed_ansi, sizeof(malformed_ansi) - 1, &position,
                       tokenizer_capture_source_byte, &capture);
  position = 0;
  valid = valid && !shell_source_decode_ansi_c_quote(
                       "$'unterminated", strlen("$'unterminated"), &position,
                       tokenizer_capture_source_byte, &capture);

  complete = true;
  after = 0;
  valid =
      valid &&
      !shell_source_skip_heredoc_sequence("<<<word", 7, 0, &after, &complete) &&
      !shell_source_skip_heredoc_sequence("<<", 2, 0, &after, &complete);
  after = 0;
  valid =
      valid && !shell_source_skip_arithmetic_expansion("$((1)", 5, 0, &after) &&
      !shell_source_find_balanced_parentheses("(unterminated", 13, 0, &after) &&
      !shell_source_skip_array_subscript("['unterminated", 14, 0, &after) &&
      !shell_source_find_parameter_array_subscript("${9[x]}", 7, 0, &after,
                                                   &subscript_start) &&
      !shell_source_array_assignment_is_compound("items[=", 7);
  valid =
      valid && !shell_source_skip_shell_word("$'unterminated", 14, 0, &after) &&
      !shell_source_skip_shell_word("trailing\\", 9, 0, &after) &&
      shell_source_skip_redirect_word("$'unterminated", 0, 14) == 14 &&
      /* A duplication target is syntactically a shell word; semantic parsing
       * later limits it to an fd number or exact named-fd parameter. */
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
      shell_source_skip_redirect("{fd} >out", 0, strlen("{fd} >out")) == 0 &&
      shell_source_skip_redirect("{fd}\\\n>out", 0, strlen("{fd}\\\n>out")) ==
          strlen("{fd}\\\n>out") &&
      !shell_source_redirect_list_before_group("command", 0, 7);
  test("Shared source scanners cover quoting, documents, and redirects", valid);
}

/* Redirect operands and ordinary words use the same borrowed-span iterator.
 * It must keep quoted delimiters opaque and refuse incomplete substitutions
 * rather than exposing a misleading executable span. */
static void tokenizer_test_executable_substitution_scanner_contract(void) {
  static const struct {
    const char *word;
    const char *span;
    shell_source_substitution_kind_t kind;
  } cases[] = {
      {"pre$(printf ')')post", "$(printf ')')", SHELL_SOURCE_SUBST_COMMAND},
      {"`printf hi`", "`printf hi`", SHELL_SOURCE_SUBST_BACKTICK},
      {"<(printf hi)", "<(printf hi)", SHELL_SOURCE_SUBST_PROCESS_INPUT},
      {">(printf hi)", ">(printf hi)", SHELL_SOURCE_SUBST_PROCESS_OUTPUT},
      {"$'ignored $(word)'$(printf real)", "$(printf real)",
       SHELL_SOURCE_SUBST_COMMAND},
      {"'ignored $(word)'$(printf real)", "$(printf real)",
       SHELL_SOURCE_SUBST_COMMAND},
      {"$((1 + 2))$(printf real)", "$(printf real)",
       SHELL_SOURCE_SUBST_COMMAND},
      {"\\\n$(printf real)", "$(printf real)", SHELL_SOURCE_SUBST_COMMAND},
      {"${x:-$(printf real)}", "$(printf real)", SHELL_SOURCE_SUBST_COMMAND},
      {"${x:-<(printf real)}", "<(printf real)",
       SHELL_SOURCE_SUBST_PROCESS_INPUT},
      {"${x:-\"ignored <(printf hi)\"$(printf real)}", "$(printf real)",
       SHELL_SOURCE_SUBST_COMMAND},
      {"\"${x:-\"$(printf real)\"}\"", "$(printf real)",
       SHELL_SOURCE_SUBST_COMMAND},
      {"$((1 + $(printf real)))", "$(printf real)", SHELL_SOURCE_SUBST_COMMAND},
      {"\"${x/a/<(printf real)}\"", "<(printf real)",
       SHELL_SOURCE_SUBST_PROCESS_INPUT},
      {"\"${x^$(printf real)}\"", "$(printf real)", SHELL_SOURCE_SUBST_COMMAND},
      {"\"${x:-$'\\\\\\$(printf real)'}\"", "$(printf real)",
       SHELL_SOURCE_SUBST_COMMAND},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_source_substitution_scan_t scan = {0};
    shell_source_substitution_kind_t kind = SHELL_SOURCE_SUBST_COMMAND;
    size_t start = 0;
    size_t after = 0;
    valid = shell_source_next_executable_substitution(
                cases[i].word, strlen(cases[i].word), &scan, &start, &after,
                &kind) == SHELL_SOURCE_SCAN_FOUND &&
            kind == cases[i].kind && after - start == strlen(cases[i].span) &&
            memcmp(cases[i].word + start, cases[i].span, after - start) == 0 &&
            shell_source_next_executable_substitution(
                cases[i].word, strlen(cases[i].word), &scan, &start, &after,
                &kind) == SHELL_SOURCE_SCAN_DONE;
  }
  static const char *const incomplete[] = {
      "$'unterminated", "`unterminated",  "$((1 + 2)",
      "$(unterminated", "<(unterminated", ">(unterminated",
  };
  for (size_t i = 0; valid && i < sizeof(incomplete) / sizeof(incomplete[0]);
       i++) {
    shell_source_substitution_scan_t scan = {0};
    size_t start = 0;
    size_t after = 0;
    shell_source_substitution_kind_t kind = SHELL_SOURCE_SUBST_COMMAND;
    valid = shell_source_next_executable_substitution(
                incomplete[i], strlen(incomplete[i]), &scan, &start, &after,
                &kind) == SHELL_SOURCE_SCAN_INCOMPLETE;
  }
  static const char *const literal[] = {
      "\"${x:-\"<(printf hi)\"}\"",
      "'${x:-$(printf hi)}'",
      "$'$(printf hi)'",
      "${x:-\\<(printf hi)}",
      "$((1 < (2)))",
      "\"${x/a/'$(printf hi)'}\"",
      "\"${x#'$(printf hi)'}\"",
      "\"${x:-$'\\\\$(printf hi)'}\"",
  };
  for (size_t i = 0; valid && i < sizeof(literal) / sizeof(literal[0]); i++)
    valid = !shell_source_word_has_executable_substitution(literal[i],
                                                           strlen(literal[i]));
  const char *sequential = "${x:-$(printf first)}$(printf second)";
  shell_source_substitution_scan_t sequential_scan = {0};
  shell_source_substitution_kind_t sequential_kind;
  size_t sequential_start = 0, sequential_after = 0;
  valid =
      valid &&
      shell_source_next_executable_substitution(
          sequential, strlen(sequential), &sequential_scan, &sequential_start,
          &sequential_after, &sequential_kind) == SHELL_SOURCE_SCAN_FOUND &&
      sequential_kind == SHELL_SOURCE_SUBST_COMMAND &&
      sequential_start == strlen("${x:-") &&
      shell_source_next_executable_substitution(
          sequential, strlen(sequential), &sequential_scan, &sequential_start,
          &sequential_after, &sequential_kind) == SHELL_SOURCE_SCAN_FOUND &&
      sequential_kind == SHELL_SOURCE_SUBST_COMMAND &&
      sequential_start == strlen("${x:-$(printf first)}") &&
      shell_source_next_executable_substitution(
          sequential, strlen(sequential), &sequential_scan, &sequential_start,
          &sequential_after, &sequential_kind) == SHELL_SOURCE_SCAN_DONE;
  test("Executable substitution scanner preserves spans and rejects incomplete "
       "words",
       valid);
}

/* A closing brace is a complete word when the next logical byte ends it. An
 * escaped line ending is removed before parsing, so it may separate `}` from
 * what follows: the group must close in the same place, with the same command
 * spans, as without it. */
static void tokenizer_test_brace_close_across_line_continuation(void) {
  static const struct {
    const char *source;
    uint32_t group_end;
    uint32_t second_start;
    uint32_t second_length;
  } accepted[] = {
      {"{ printf ok; } ; printf done", 14, 17, 11},
      {"{ printf ok; }\\\n ; printf done", 14, 19, 11},
      {"{ printf ok; }\\\n; printf done", 14, 18, 11},
      {"{ printf ok; }\\\n&& printf done", 14, 19, 11},
      {"{ printf ok; }\\\n\\\n ; printf done", 14, 21, 11},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(accepted) / sizeof(accepted[0]); i++) {
    shell_parse_result_t parsed = {0};
    valid = shell_parse_fast(accepted[i].source, strlen(accepted[i].source),
                             NULL, &parsed) == SHELL_OK &&
            parsed.count == 2 && parsed.group_count == 1 &&
            parsed.groups[0].kind == SHELL_GROUP_BRACE &&
            parsed.groups[0].start == 0 &&
            parsed.groups[0].end == accepted[i].group_end &&
            parsed.groups[0].first_command == 0 &&
            parsed.groups[0].command_count == 1 &&
            parsed.groups[0].parent == UINT16_MAX &&
            parsed.cmds[0].start == 2 && parsed.cmds[0].len == 9 &&
            parsed.cmds[1].start == accepted[i].second_start &&
            parsed.cmds[1].len == accepted[i].second_length;
  }
  test("Brace group closes across an escaped line ending", valid);

  static const char nested[] = "{ { printf a; }\\\n ; printf b; }";
  shell_parse_result_t parsed = {0};
  valid =
      shell_parse_fast(nested, sizeof(nested) - 1, NULL, &parsed) == SHELL_OK &&
      parsed.count == 2 && parsed.group_count == 2 &&
      parsed.groups[0].start == 0 && parsed.groups[0].end == 31 &&
      parsed.groups[0].parent == UINT16_MAX && parsed.groups[1].start == 2 &&
      parsed.groups[1].end == 15 && parsed.groups[1].parent == 0;
  test("Nested brace groups close across an escaped line ending", valid);

  /* Trailing, redirect and pipe forms parse; a continued word does not close
   * the group, and a brace that is only a word stays one. */
  static const char *const parsed_ok[] = {
      "{ printf ok; }\\\n",       "{ printf ok; }\\\n > /dev/null",
      "{ printf ok; }\\\n | cat", "( { printf a; }\\\n )",
      "{ echo }\\\n; }",          "printf ok; }x",
      "printf ok; }\\\nx",
  };
  valid = true;
  for (size_t i = 0; valid && i < sizeof(parsed_ok) / sizeof(parsed_ok[0]);
       i++) {
    parsed = (shell_parse_result_t){0};
    valid = shell_parse_fast(parsed_ok[i], strlen(parsed_ok[i]), NULL,
                             &parsed) == SHELL_OK;
  }
  test("Continued and literal braces match Bash acceptance", valid);

  static const char *const rejected[] = {
      "{ printf ok; }\\\nfoo",
      "printf ok; }\\\n ; printf x",
      "printf ok; } ; printf x",
  };
  valid = true;
  for (size_t i = 0; valid && i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    parsed = (shell_parse_result_t){0};
    valid = shell_parse_fast(rejected[i], strlen(rejected[i]), NULL, &parsed) ==
            SHELL_EPARSE;
  }
  test("Continued braces that Bash rejects stay rejected", valid);
}

/* A `!` is a pipeline negator only where a shell word starts. An escaped line
 * ending is removed before words are recognized, so it joins `!` to a
 * preceding expansion instead of starting a new word: Bash reads
 * `echo $x\\<newline>! tail` as the arguments `abc!` and `tail`. */
static size_t tokenizer_test_negator_positions(const char *source,
                                               size_t *positions,
                                               size_t capacity) {
  shell_tokenizer_state_t state;
  shell_token_t token;
  size_t count = 0;
  if (!shell_tokenizer_init(&state, source, strlen(source), NULL))
    return SIZE_MAX;
  while (shell_tokenizer_next(&state, &token))
    if (token.type == SHELL_TOKEN_PIPE_NEGATE && count < capacity)
      positions[count++] = token.position;
  return count;
}

static void tokenizer_test_negator_requires_a_word_start(void) {
  static const char *const joined[] = {
      "printf '<%s>\\n' $value\\\n! tail",
      "printf '<%s>\\n' $(printf abc)\\\n! tail",
      "printf '<%s>\\n' \"$value\"\\\n! tail",
      "echo $x\\\n! tail",
      "echo ${x}\\\n! tail",
      "echo `date`\\\n! tail",
      "echo \"$(printf x)\"\\\n! tail",
      "echo $x$y\\\n! tail",
      "echo <(true)\\\n! tail",
      "echo $((1 + 2))\\\n! tail",
      "echo ${x}! tail",
      "echo $x\\\n\\\n! tail",
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(joined) / sizeof(joined[0]); i++) {
    size_t positions[4];
    valid = tokenizer_test_negator_positions(joined[i], positions, 4) == 0;
    if (!valid)
      fprintf(stderr, "unexpected negator: %s\n", joined[i]);
  }
  test("A line continuation after an expansion does not start a negator",
       valid);

  static const struct {
    const char *source;
    size_t first;
    size_t count;
  } negated[] = {
      {"! true", 0, 1},
      {"echo a; ! false", 8, 1},
      {"echo a;\\\n! false", 9, 1},
      {"echo a &&\\\n! false", 11, 1},
      {"echo a ||\\\n! false", 11, 1},
      {"echo a\n! false", 7, 1},
      {"echo $x ;\\\n! false", 11, 1},
      {"if ! true; then :; fi", 3, 1},
      {"case x in a) ! false ;; esac", 13, 1},
      {"( ! true )", 2, 1},
      {"{ ! true; }", 2, 1},
      {"! \\\n! true", 0, 2},
  };
  valid = true;
  for (size_t i = 0; valid && i < sizeof(negated) / sizeof(negated[0]); i++) {
    size_t positions[4];
    size_t count =
        tokenizer_test_negator_positions(negated[i].source, positions, 4);
    valid = count == negated[i].count && positions[0] == negated[i].first;
    if (!valid)
      fprintf(stderr, "negator lost or moved: %s\n", negated[i].source);
  }
  test("Pipeline negators at a word start are still recognized", valid);
}

/* `>&` and `<&` duplicate or close a descriptor: their `&` belongs to the
 * operator, also when an escaped line ending separates the two bytes, and is
 * never background execution. Conversely an `&` after an escaped `>` is a real
 * background operator. */
static void tokenizer_test_descriptor_duplication_is_not_background(void) {
  static const struct {
    const char *source;
    bool background;
  } cases[] = {
      {"echo 2>&1", false},
      {"echo 2>\\\n&1", false},
      {"echo >\\\n&2", false},
      {"echo <\\\n&0", false},
      {"echo >\\\n&-", false},
      {"echo 2<\\\n&-", false},
      {"echo {fd}>\\\n&1", false},
      {"echo {fd}<\\\n&0", false},
      {"echo a >\\\n\\\n&1", false},
      {"echo $(echo 2>&1)", false},
      {"echo $(echo 2>\\\n&1)", false},
      {"echo $(echo >\\\n&2)", false},
      {"echo $(echo <\\\n&0)", false},
      {"echo $(echo {fd}>\\\n&1)", false},
      {"echo <(echo 2>\\\n&1)", false},
      {"echo `echo 2>\\\n&1`", false},
      {"echo \"$(echo 2>\\\n&1)\"", false},
      {"echo $(echo a |& cat)", false},
      {"echo $(echo a &> f)", false},
      {"echo $(echo a &\\\n& b)", false},
      /* A real background operator, including after a duplication. */
      {"echo >&2 &", true},
      {"echo >\\\n&2 &", true},
      {"echo $(echo a &)", true},
      {"echo $(echo a >&2 &)", true},
      {"echo $(echo a >\\\n&2 &)", true},
      {"echo $(echo a >&2&)", true},
      {"echo $(echo \\>& )", true},
      {"echo $(echo \\<& )", true},
      {"echo $(echo '>'& )", true},
      {"echo <(echo a &)", true},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t parsed = {0};
    uint32_t features = 0;
    valid = shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                             &parsed) == SHELL_OK;
    for (uint32_t cmd = 0; valid && cmd < parsed.count; cmd++)
      features |= parsed.cmds[cmd].features;
    valid = valid &&
            ((features & SHELL_FEAT_BACKGROUND) != 0) == cases[i].background;
    if (!valid)
      fprintf(stderr, "wrong background feature (0x%05x): %s\n", features,
              cases[i].source);
  }
  test("Descriptor duplication is not background execution", valid);
}

/* An escaped line ending is removed before pattern syntax is read, so it may
 * sit anywhere in a bracket expression, including between the delimiter and
 * the `]` that closes a POSIX class: `[[:alpha:\<newline>]]` is `[[:alpha:]]`.
 * An unterminated bracket stays a literal word. */
static void tokenizer_test_glob_class_continuation_keeps_the_feature(void) {
  static const struct {
    const char *source;
    bool globs;
  } cases[] = {
      {"echo [[:alpha:]]", true},
      {"echo [[:alpha:\\\n]]", true},
      {"echo [[:alp\\\nha:]]", true},
      {"echo [[\\\n:alpha:]]", true},
      {"echo [[:alpha\\\n:]]", true},
      {"echo [\\\n[:alpha:]]", true},
      {"echo [[:alpha:]\\\n]", true},
      {"echo [[:digit:\\\n]]", true},
      {"echo [[:upper:\\\n]]", true},
      {"echo [[:lower:\\\n]]", true},
      {"echo [[:alnum:\\\n]]", true},
      {"echo [[.a.\\\n]]", true},
      {"echo [[=a=\\\n]]", true},
      {"echo [[:alpha:\\\n\\\n]]", true},
      {"echo [[:alpha:\\\n]\\\n]", true},
      {"echo [!\\\n[:alpha:]]", true},
      {"echo [^[:alpha:\\\n]]", true},
      {"echo [a[:digit:\\\n]b]", true},
      {"echo $(echo [[:alpha:\\\n]])", true},
      {"echo `echo [[:alpha:\\\n]]`", true},
      /* Unterminated or quoted: not a pattern. */
      {"echo [[:alpha:]", false},
      {"echo [[:alpha:]x", false},
      {"echo [[:alpha:", false},
      {"echo [[:alpha:\\\n", false},
      {"echo [[:alpha:\\\n]", false},
      {"echo [[:alpha\\\n:]", false},
      {"echo [[:alpha:\\\n]x", false},
      {"echo [[.a.]", false},
      {"echo [[=a=\\\n]", false},
      {"echo [[:alpha:\\\nx", false},
      {"echo [[:alpha:\\\n\\\n", false},
      {"echo \"[[:alpha:\\\n]]\"", false},
      {"echo '[[:alpha:\\\n]]'", false},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t parsed = {0};
    uint32_t features = 0;
    valid = shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                             &parsed) == SHELL_OK;
    for (uint32_t cmd = 0; valid && cmd < parsed.count; cmd++)
      features |= parsed.cmds[cmd].features;
    valid = valid && ((features & SHELL_FEAT_GLOBS) != 0) == cases[i].globs;
    if (!valid)
      fprintf(stderr, "wrong glob feature (0x%04x): %s\n", features,
              cases[i].source);
  }
  test("A continuation inside a glob class keeps the glob feature", valid);
}

/* A quoted prefix and an adjacent extglob are one shell word. The extglob
 * opener must not restart the token and drop the prefix: the token spans have
 * to cover every byte of the word, and the redirect-operand forms are valid. */
static void tokenizer_test_quoted_prefix_extglob_is_one_word(void) {
  static const struct {
    const char *source;
    /* Source text of each token, space-separated; a token never contains
     * a space in these cases. */
    const char *words;
  } cases[] = {
      {": >\"a\"@(b)", ": > \"a\"@(b)"},
      {": > \"a\"@(b)", ": > \"a\"@(b)"},
      {"cat <\"a\"@(b)", "cat < \"a\"@(b)"},
      {"echo \"a\"@(b)", "echo \"a\"@(b)"},
      {"echo 'a'@(b)", "echo 'a'@(b)"},
      {"echo \"a\"?(b)", "echo \"a\"?(b)"},
      {"echo \"a\"*(b)", "echo \"a\"*(b)"},
      {"echo \"a\"+(b)", "echo \"a\"+(b)"},
      {"echo \"a\"!(b)", "echo \"a\"!(b)"},
      {"echo \"a\"@(b)\"c\"", "echo \"a\"@(b)\"c\""},
      {"echo \"a\"@(b)c@(d)", "echo \"a\"@(b)c@(d)"},
      {"echo \"a\"\"b\"@(c)", "echo \"a\"\"b\"@(c)"},
      {"echo \"a\"@(b) c", "echo \"a\"@(b) c"},
      {"\"a\"@(b)", "\"a\"@(b)"},
      /* Neighbors that already kept the whole word. */
      {"echo a\"b\"@(c)", "echo a\"b\"@(c)"},
      {"echo a@(b)", "echo a@(b)"},
      {"echo @(b)", "echo @(b)"},
      {"echo \"a\"*", "echo \"a\"*"},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    size_t length = strlen(source);
    shell_tokenizer_state_t state;
    shell_token_t token;
    char words[128] = "";
    valid = shell_tokenizer_init(&state, source, length, NULL);
    while (valid && shell_tokenizer_next(&state, &token)) {
      size_t used = strlen(words);
      valid = used + token.length + 2 < sizeof(words);
      if (!valid)
        break;
      snprintf(words + used, sizeof(words) - used, "%s%.*s", used ? " " : "",
               (int)token.length, token.start);
    }
    valid = valid && strcmp(words, cases[i].words) == 0;
    if (!valid)
      fprintf(stderr, "tokens [%s], expected [%s]: %s\n", words, cases[i].words,
              source);
    static shell_source_result_t draft;
    shell_parse_result_t parsed = {0};
    shell_dep_graph_t graph = {0};
    valid = valid &&
            shell_parse_draft(source, length, NULL, &draft) ==
                SHELL_SOURCE_COMPLETE &&
            shell_parse_fast(source, length, NULL, &parsed) == SHELL_OK &&
            shell_dep_graph_parse(source, length, ".", NULL, &graph) ==
                SHELL_DEP_OK;
    if (!valid)
      fprintf(stderr, "not admitted: %s\n", source);
  }
  test("A quoted prefix and an extglob stay one word", valid);
}

/* Quoted and ANSI-C spans inside a bracket expression are literal members: a
 * quoted space or operator does not end the word, and a quoted `]` does not
 * close the expression. Bash expands `[a" "b]` but leaves `[a"]"` alone. */
static void tokenizer_test_glob_bracket_quoted_members_keep_the_feature(void) {
  static const struct {
    const char *source;
    bool globs;
  } cases[] = {
      {"echo [a\" \"b]", true},
      {"echo [a' 'b]", true},
      {"echo [a\";\"b]", true},
      {"echo [a\"|\"b]", true},
      {"echo [a\"&\"b]", true},
      {"echo [a\"<\"b]", true},
      {"echo [a\">\"b]", true},
      {"echo [a\"(\"b]", true},
      {"echo [a\")\"b]", true},
      {"echo [!\" \"]", true},
      {"echo [^\" \"]", true},
      {"echo [a$' 'b]", true},
      {"echo [a$']']", true},
      {"echo [\"a b\"]", true},
      {"echo [a\"b c\"d]", true},
      {"echo [\"]\"]", true},
      {"echo [\"]\"b]", true},
      {"echo [a']'b]", true},
      {"echo [a\"]\"b]", true},
      {"echo $(echo [a\" \"b])", true},
      {"echo `echo [a' 'b]`", true},
      {"echo x [a\" \"b] y", true},
      /* Unquoted space or operator still ends the word. */
      {"echo [a b]", false},
      {"echo [a;b]", false},
      {"echo [a|b]", false},
      /* A quoted `]` is not a closer, and the word is quoted or unfinished. */
      {"echo [a\"]\"", false},
      {"echo [a']'", false},
      {"echo [\"]\"", false},
      {"echo [!\"]\"", false},
      {"echo \"[a b]\"", false},
      {"echo '[a\" \"b]'", false},
      {"echo [a\"b\"", false},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t parsed = {0};
    uint32_t features = 0;
    valid = shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                             &parsed) == SHELL_OK;
    for (uint32_t cmd = 0; valid && cmd < parsed.count; cmd++)
      features |= parsed.cmds[cmd].features;
    valid = valid && ((features & SHELL_FEAT_GLOBS) != 0) == cases[i].globs;
    if (!valid)
      fprintf(stderr, "wrong glob feature (0x%04x): %s\n", features,
              cases[i].source);
  }
  test("Quoted bracket members keep the glob feature", valid);

  /* A `>&word` target that is a bracket glob may expand to a descriptor
   * number, so quoting a member cannot make it a provable pathname. */
  static const struct {
    const char *word;
    shell_process_legacy_redirect_target_t target;
  } targets[] = {
      {"[ab]", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"[a\" \"b]", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"[a' 'b]", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"[1\" \"]", SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED},
      {"[a\"]\"", SHELL_PROCESS_LEGACY_REDIRECT_PATH},
  };
  valid = true;
  for (size_t i = 0; valid && i < sizeof(targets) / sizeof(targets[0]); i++) {
    valid = shell_process_classify_legacy_output_target(
                targets[i].word, strlen(targets[i].word)) == targets[i].target;
    if (!valid)
      fprintf(stderr, "wrong legacy target class: %s\n", targets[i].word);
  }
  test("Quoted bracket members do not prove a pathname target", valid);
}

/* The wrapper state machine is shared by the semantic gate and the dependency
 * graph. Exercise its transition contract directly as well as through those
 * higher-level APIs, including quote removal and every terminating outcome. */
static void tokenizer_test_current_shell_wrapper_chain_contract(void) {
  shell_source_wrapper_state_t state = {0};
  bool valid =
      shell_source_wrapper_start(&state, "", 0) ==
          SHELL_SOURCE_WRAPPER_NONEXECUTING &&
      shell_source_wrapper_start(&state, "com'mand'", strlen("com'mand'")) ==
          SHELL_SOURCE_WRAPPER_MORE &&
      shell_source_wrapper_consume(&state, "-pp", strlen("-pp")) ==
          SHELL_SOURCE_WRAPPER_MORE &&
      shell_source_wrapper_consume(&state, "$'command'",
                                   strlen("$'command'")) ==
          SHELL_SOURCE_WRAPPER_MORE &&
      shell_source_wrapper_consume(&state, "e\\xec", strlen("e\\xec")) ==
          SHELL_SOURCE_WRAPPER_STATIC_TARGET &&
      state.exec_persistent &&
      shell_source_wrapper_start(&state, "command", strlen("command")) ==
          SHELL_SOURCE_WRAPPER_MORE &&
      shell_source_wrapper_consume(&state, "-pV", strlen("-pV")) ==
          SHELL_SOURCE_WRAPPER_NONEXECUTING &&
      shell_source_wrapper_start(&state, "builtin", strlen("builtin")) ==
          SHELL_SOURCE_WRAPPER_MORE &&
      shell_source_wrapper_consume(&state, "-p", strlen("-p")) ==
          SHELL_SOURCE_WRAPPER_NONEXECUTING &&
      shell_source_wrapper_start(&state, "command", strlen("command")) ==
          SHELL_SOURCE_WRAPPER_MORE &&
      shell_source_wrapper_consume(&state, "$target", strlen("$target")) ==
          SHELL_SOURCE_WRAPPER_DYNAMIC_TARGET &&
      shell_source_wrapper_start(&state, "command", strlen("command")) ==
          SHELL_SOURCE_WRAPPER_MORE &&
      shell_source_wrapper_consume(&state, "--", strlen("--")) ==
          SHELL_SOURCE_WRAPPER_MORE &&
      shell_source_wrapper_consume(&state, "builtin", strlen("builtin")) ==
          SHELL_SOURCE_WRAPPER_MORE &&
      shell_source_wrapper_consume(&state, "--", strlen("--")) ==
          SHELL_SOURCE_WRAPPER_MORE &&
      shell_source_wrapper_consume(&state, "exec", strlen("exec")) ==
          SHELL_SOURCE_WRAPPER_STATIC_TARGET &&
      !state.exec_persistent &&
      shell_source_classify_command_option("-pp", strlen("-pp")) ==
          SHELL_SOURCE_COMMAND_OPTION_EXECUTES &&
      shell_source_classify_command_option("-v", strlen("-v")) ==
          SHELL_SOURCE_COMMAND_OPTION_INSPECTS &&
      shell_source_classify_command_option("-q", strlen("-q")) ==
          SHELL_SOURCE_COMMAND_OPTION_INVALID &&
      !shell_source_word_static_starts_dash("", 0) &&
      shell_source_word_static_equals("'builtin'", strlen("'builtin'"),
                                      "builtin");

  tokenizer_source_byte_capture_t stopped = {.length = 1, .stop_after = 1};
  valid = valid &&
          !shell_source_visit_static_word("$'x'", strlen("$'x'"),
                                          tokenizer_capture_source_byte,
                                          &stopped) &&
          !shell_source_visit_static_word(
              "\\x", strlen("\\x"), tokenizer_capture_source_byte, &stopped) &&
          !shell_source_visit_static_word(
              "x", strlen("x"), tokenizer_capture_source_byte, &stopped) &&
          shell_source_skip_redirect("<>out", 0, strlen("<>out")) ==
              strlen("<>out");
  test("Current-shell wrapper chains share static semantics", valid);
}

/* An escaped physical line ending is removed before shell grammar recognizes
 * the following byte.  These cases deliberately put the removal point inside
 * every expansion opener so the low-level scanners, canonical processor, and
 * dependency graph cannot silently disagree on the resulting command. */
static void tokenizer_test_expansion_line_continuation_contract(void) {
  static const char *const accepted[] = {
      "printf %s ${f\\\nd}",
      "printf %s $\\\n(printf child)",
      "printf %s $\\\n((1 + 2))",
      "printf %s $((1)\\\n)",
      "cat <\\\n(printf input) > \\\n>(cat)",
      "printf %s $\\\n'ansi'",
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
    const char *input = accepted[i];
    shell_parse_result_t parsed = {0};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    shell_netstring_buffer_t sequence = {0};
    size_t sequence_count = 0;
    bool features = false;

    shell_error_t fast_status =
        shell_parse_fast(input, strlen(input), NULL, &parsed);
    shell_tokenize_status_t tokenize_status = shell_tokenize_commands(
        input, strlen(input), &commands, &command_count);
    shell_process_status_t process_status =
        shell_process_commands(input, strlen(input), NULL, &processed);
    shell_process_status_t sequence_status =
        shell_build_netargv_sequence_buffer(
            input, strlen(input), NULL, &sequence, &sequence_count, &features);
    shell_dep_error_t graph_status =
        shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph);
    bool accepted =
        fast_status == SHELL_OK && parsed.count != 0 &&
        tokenize_status == SHELL_TOKENIZE_OK && command_count != 0 &&
        process_status == SHELL_PROCESS_OK && processed.command_count != 0 &&
        sequence_status == SHELL_PROCESS_OK && sequence.data != NULL &&
        sequence_count != 0 && graph_status == SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    if (!accepted) {
      fprintf(stderr,
              "continued expansion rejected: %s (fast=%d tokenize=%d "
              "process=%d sequence=%d graph=%d)\n",
              input, fast_status, tokenize_status, process_status,
              sequence_status, graph_status);
    }
    valid = valid && accepted;
    shell_netstring_buffer_free(&sequence);
    shell_processed_commands_free(&processed);
    shell_commands_free(commands, command_count);
  }
  test("Expansion openers preserve escaped physical continuations", valid);

  static const char command_substitution[] = "printf %s $\\\n(printf child)";
  shell_tokenizer_state_t state;
  shell_token_t token;
  bool saw_subshell = false;
  bool saw_variable = false;
  valid = shell_tokenizer_init(&state, command_substitution,
                               sizeof(command_substitution) - 1, NULL);
  while (valid && shell_tokenizer_next(&state, &token)) {
    saw_subshell = saw_subshell || token.type == SHELL_TOKEN_SUBSHELL;
    saw_variable = saw_variable || token.type == SHELL_TOKEN_VARIABLE ||
                   token.type == SHELL_TOKEN_VARIABLE_QUOTED;
  }
  test("Continued command substitutions do not become variables",
       valid && saw_subshell && !saw_variable);

  static const struct {
    const char *reference;
    const char *continued;
    uint32_t feature;
  } feature_pairs[] = {
      {"printf %s ${value}", "printf %s $\\\n{value}", SHELL_FEAT_VARS},
      {"printf %s $(printf child)", "printf %s $\\\n(printf child)",
       SHELL_FEAT_SUBSHELL},
      {"printf %s $((1 + 2))", "printf %s $\\\n((1 + 2))", SHELL_FEAT_ARITH},
      {"printf %s $(<file)", "printf %s $\\\n(<file)",
       SHELL_FEAT_SUBSHELL_FILE},
      {"cat <(printf input)", "cat <\\\n(printf input)",
       SHELL_FEAT_PROCESS_SUB},
      {"printf %s $'literal'", "printf %s $\\\n'literal'",
       SHELL_FEAT_ANSI_C_QUOTE},
      {"printf %s @(one|two)", "printf %s @\\\n(one|two)", SHELL_FEAT_EXTGLOB},
      {"printf %s {fd}>out", "printf %s {f\\\nd}>out", SHELL_FEAT_NAMED_FD},
      {"printf x &>out", "printf x &\\\n>out", SHELL_FEAT_COMBINED_REDIRECT},
  };
  valid = true;
  for (size_t i = 0; i < sizeof(feature_pairs) / sizeof(feature_pairs[0]);
       i++) {
    shell_parse_result_t reference = {0};
    shell_parse_result_t continued = {0};
    valid = valid &&
            shell_parse_fast(feature_pairs[i].reference,
                             strlen(feature_pairs[i].reference), NULL,
                             &reference) == SHELL_OK &&
            shell_parse_fast(feature_pairs[i].continued,
                             strlen(feature_pairs[i].continued), NULL,
                             &continued) == SHELL_OK &&
            reference.count == 1 && continued.count == 1 &&
            reference.cmds[0].type == continued.cmds[0].type &&
            reference.cmds[0].features == continued.cmds[0].features &&
            (continued.cmds[0].features & feature_pairs[i].feature) != 0;
  }
  test("Fast feature metadata matches continued expansion spellings", valid);

  static const char locale_quote[] = "printf %s $\\\n\"localized\"";
  shell_processed_commands_t processed = {0};
  shell_process_status_t status = shell_process_commands(
      locale_quote, sizeof(locale_quote) - 1, NULL, &processed);
  valid = shell_tokenizer_has_unsupported_semantics(locale_quote,
                                                    sizeof(locale_quote) - 1) &&
          status == SHELL_PROCESS_EPARSE && processed.commands == NULL &&
          processed.command_count == 0;
  shell_processed_commands_free(&processed);
  test("Continued locale quotes retain their unsupported classification",
       valid);

  /* A shift is arithmetic syntax, not a heredoc declaration. Its `<<` must
   * not terminate the locale-quote scan before it reaches later executable
   * source. */
  static const char shifted_locale_quote[] =
      ": $((1 << 2))\nprintf %s $\"localized\"";
  processed = (shell_processed_commands_t){0};
  status = shell_process_commands(
      shifted_locale_quote, sizeof(shifted_locale_quote) - 1, NULL, &processed);
  valid = shell_tokenizer_has_unsupported_semantics(
              shifted_locale_quote, sizeof(shifted_locale_quote) - 1) &&
          status == SHELL_PROCESS_EPARSE && processed.commands == NULL &&
          processed.command_count == 0;
  shell_processed_commands_free(&processed);
  test("Arithmetic shifts do not hide later locale quotes", valid);

  /* The two `<` bytes can be separated by a removed physical continuation.
   * Locale-looking body bytes remain literal heredoc data in that spelling. */
  static const char continued_heredoc_body[] =
      "cat <\\\n<EOF\n$\"literal body\"\nEOF\n";
  processed = (shell_processed_commands_t){0};
  status = shell_process_commands(continued_heredoc_body,
                                  sizeof(continued_heredoc_body) - 1, NULL,
                                  &processed);
  valid = !shell_tokenizer_has_unsupported_semantics(
              continued_heredoc_body, sizeof(continued_heredoc_body) - 1) &&
          status == SHELL_PROCESS_OK && processed.commands != NULL &&
          processed.command_count == 1;
  shell_processed_commands_free(&processed);
  test("Continued heredoc bodies retain literal locale-like bytes", valid);

  /* Only the deferred body is opaque. A locale quote after the delimiter on
   * the declaration line remains an active command argument and must still
   * fail closed. */
  static const char heredoc_header_locale_quote[] =
      "cat <<EOF $\"localized\"\nbody\nEOF\n";
  processed = (shell_processed_commands_t){0};
  status = shell_process_commands(heredoc_header_locale_quote,
                                  sizeof(heredoc_header_locale_quote) - 1, NULL,
                                  &processed);
  valid = shell_tokenizer_has_unsupported_semantics(
              heredoc_header_locale_quote,
              sizeof(heredoc_header_locale_quote) - 1) &&
          status == SHELL_PROCESS_EPARSE && processed.commands == NULL &&
          processed.command_count == 0;
  shell_processed_commands_free(&processed);
  test("Heredoc declarations retain active locale-quote arguments", valid);

  static const char *const ansi_words[] = {
      "$\\\n'\\x41\\0B'",
      "$\\\n'\\x41\\0B'",
  };
  static const unsigned char ansi_expected[] = {'A', '\0', 'B'};
  valid = true;
  for (size_t i = 0; i < sizeof(ansi_words) / sizeof(ansi_words[0]); i++) {
    const char *word = ansi_words[i];
    unsigned char decoded[sizeof(ansi_expected)] = {0};
    size_t measured = 0, written = 0;
    char command[64];
    int command_length =
        snprintf(command, sizeof(command), "printf %%s %s", word);
    valid = valid && command_length > 0 &&
            (size_t)command_length < sizeof(command) &&
            shell_measure_decoded_word(word, strlen(word), &measured) ==
                SHELL_PROCESS_OK &&
            measured == sizeof(ansi_expected) &&
            shell_write_decoded_word(word, strlen(word), (char *)decoded,
                                     sizeof(decoded),
                                     &written) == SHELL_PROCESS_OK &&
            written == sizeof(ansi_expected) &&
            memcmp(decoded, ansi_expected, sizeof(ansi_expected)) == 0 &&
            shell_process_validate_supported_source(
                command, (size_t)command_length, NULL) == SHELL_PROCESS_OK;
  }
  test("Continued ANSI-C NUL distinguishes binary decoding from shell values",
       valid);

  static const char continued_fd[] = "{ printf x; } >&$\\\n'7'";
  memset(&processed, 0, sizeof(processed));
  status = shell_process_commands(continued_fd, sizeof(continued_fd) - 1, NULL,
                                  &processed);
  valid = status == SHELL_PROCESS_OK && processed.group_io_op_count == 1 &&
          processed.group_io_ops[0].kind == SHELL_GROUP_IO_DUP_FD &&
          processed.group_io_ops[0].fd == 1 &&
          processed.group_io_ops[0].target_fd == 7;
  shell_processed_commands_free(&processed);
  test("Continued ANSI-C descriptor words retain FD classification", valid);
}

/* These helpers deliberately make conservative decisions before the parser
 * builds an endpoint or descriptor route. Exercise their rejecting paths
 * directly: a malformed spelling must never become a command word, a file
 * endpoint, or a descriptor alias merely because another scanner accepted a
 * surrounding command. */
static void tokenizer_test_redirect_operand_safety_contract(void) {
  size_t name_start = SIZE_MAX;
  size_t name_end = SIZE_MAX;
  uint32_t fd = UINT32_MAX;
  static const char long_nul_target[] =
      "$'\\0'abcdefghijklmnopqrstuvwxyzabcdefghi";

  bool valid =
      !shell_source_redirection_consumes_word(NULL, 0) &&
      !shell_source_redirection_consumes_word("", 0) &&
      shell_source_redirection_consumes_word(">&", 2) &&
      shell_source_redirection_consumes_word(">|", 2) &&
      !shell_source_parse_named_fd_parameter("${fd", 0, 4, &name_start,
                                             &name_end) &&
      name_start == 0 && name_end == 0 &&
      !shell_source_parse_named_fd_parameter("$", 0, 1, &name_start,
                                             &name_end) &&
      name_start == 0 && name_end == 0 &&
      shell_source_parse_named_fd_parameter("\"$fd\"", 0, 5, &name_start,
                                            &name_end) &&
      name_start == 2 && name_end == 4 &&
      shell_source_argument_has_dynamic_syntax("$'unterminated",
                                               strlen("$'unterminated")) &&
      shell_source_argument_has_dynamic_syntax("<(producer)",
                                               strlen("<(producer)")) &&
      shell_source_argument_has_dynamic_syntax(">(consumer)",
                                               strlen(">(consumer)")) &&
      shell_source_skip_redirect(">& >(consumer", 0, strlen(">& >(consumer")) ==
          0 &&
      shell_process_classify_static_fd_target(
          long_nul_target, sizeof(long_nul_target) - 1, &fd) ==
          SHELL_PROCESS_FD_TARGET_PATH &&
      fd == SHELL_PROCESS_FD_NONE;
  test("Redirect operands classify effective values after rejecting malformed "
       "syntax",
       valid);
}

static void tokenizer_test_record_parser_boundaries(void) {
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
  bool valid = shell_processed_commands_parse("", 0, NULL, &commands, &count) ==
                   SHELL_PROCESS_OK &&
               commands == NULL && count == 0;

  commands = (shell_command_t *)(uintptr_t)1;
  count = SIZE_MAX;
  valid = shell_processed_commands_parse("echo value", strlen("echo value"),
                                         &short_record, &commands,
                                         &count) == SHELL_PROCESS_OK &&
          commands != NULL && count == 1 && valid;
  shell_commands_free(commands, count);
  commands = (shell_command_t *)(uintptr_t)1;
  count = SIZE_MAX;
  valid = shell_processed_commands_parse("echo value", strlen("echo value"),
                                         &short_total, &commands,
                                         &count) == SHELL_PROCESS_OK &&
          commands != NULL && count == 1 && valid;
  shell_commands_free(commands, count);

  commands = NULL;
  count = 0;
  shell_processed_word_iterator_t pipe_iterator;
  shell_token_t pipe_word;
  valid = valid &&
          shell_processed_commands_parse(
              "left |& right", strlen("left |& right"), NULL, &commands,
              &count) == SHELL_PROCESS_OK &&
          commands != NULL && count == 2 &&
          shell_processed_command_word_count(&commands[0]) == 1 &&
          (shell_processed_word_iterator_init(&pipe_iterator, &commands[0]),
           shell_processed_word_iterator_next(&pipe_iterator, &pipe_word)) &&
          !shell_processed_word_iterator_next(&pipe_iterator, &pipe_word) &&
          shell_processed_command_has_pipe_output(&commands[0]) &&
          shell_processed_command_has_dangerous_features(&commands[1], true);
  shell_commands_free(commands, count);

  /* A redirection operand may span adjacent lexical fragments, but the next
   * whitespace-separated word is an argument again. Exercise the borrowed
   * command convenience accessors without allocating an artificial argv. */
  static const char redirect_boundary_source[] = ">out next";
  static shell_token_t redirect_boundary_tokens[] = {
      {.type = SHELL_TOKEN_REDIRECT_OUT,
       .start = redirect_boundary_source,
       .length = 1,
       .position = 0},
      {.type = SHELL_TOKEN_ARGUMENT,
       .start = redirect_boundary_source + 1,
       .length = 3,
       .position = 1},
      {.type = SHELL_TOKEN_ARGUMENT,
       .start = redirect_boundary_source + 5,
       .length = 4,
       .position = 5},
  };
  const shell_command_t redirect_boundary = {
      .tokens = redirect_boundary_tokens,
      .token_count = sizeof(redirect_boundary_tokens) /
                     sizeof(redirect_boundary_tokens[0]),
  };
  shell_processed_word_iterator_t redirect_iterator;
  shell_token_t redirect_word;
  shell_processed_word_iterator_init(&redirect_iterator, &redirect_boundary);
  valid =
      valid && shell_processed_command_word_count(&redirect_boundary) == 1 &&
      shell_processed_word_iterator_next(&redirect_iterator, &redirect_word) &&
      redirect_word.start == redirect_boundary_tokens[2].start &&
      redirect_word.length == redirect_boundary_tokens[2].length &&
      !shell_processed_word_iterator_next(&redirect_iterator, &redirect_word);

  valid = valid &&
          shell_process_validate_supported_source("", 0, NULL) ==
              SHELL_PROCESS_EINPUT &&
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
  test("Record parser validates limits and supported-source contracts", valid);
}

static void tokenizer_test_modern_bash_syntax_contract(void) {
  bool enum_values_stable =
      SHELL_GROUP_IO_READ_FILE == 0 && SHELL_GROUP_IO_WRITE_FILE == 1 &&
      SHELL_GROUP_IO_APPEND_FILE == 2 && SHELL_GROUP_IO_HEREDOC == 3 &&
      SHELL_GROUP_IO_HERESTRING == 4 && SHELL_GROUP_IO_DUP_FD == 5 &&
      SHELL_GROUP_IO_CLOSE_FD == 6 && SHELL_GROUP_IO_PIPE_INPUT == 7 &&
      SHELL_GROUP_IO_PIPE_OUTPUT == 8 && SHELL_GROUP_IO_BACKGROUND == 9 &&
      SHELL_GROUP_IO_READ_WRITE_FILE == 10 &&
      SHELL_GROUP_IO_PROCESS_SUB_IN == 11 &&
      SHELL_GROUP_IO_PROCESS_SUB_OUT == 12 &&
      SHELL_GROUP_IO_PROCESS_SUB_RW_IN == 13 &&
      SHELL_GROUP_IO_PROCESS_SUB_RW_OUT == 14 &&
      SHELL_GROUP_IO_PROCESS_SUB_UNROUTED == 15 &&
      SHELL_GROUP_IO_PIPE_OUTPUT_STDERR == 16 && SHELL_GROUP_IO_MOVE_FD == 17 &&
      SHELL_GROUP_IO_FAILED_REDIRECT == 18;
  test("Group I/O enum appends modern redirect operations", enum_values_stable);

  const char *source = "! items=(one two) printf $'a\\0b' @(left|right) &>out";
  shell_tokenizer_state_t state;
  shell_token_t token;
  shell_parse_result_t parsed = {0};
  shell_command_info_t *infos = NULL;
  size_t count = 0;
  shell_token_type_t expected[] = {
      SHELL_TOKEN_PIPE_NEGATE, SHELL_TOKEN_ARRAY_ASSIGNMENT,
      SHELL_TOKEN_COMMAND,     SHELL_TOKEN_ANSI_C_QUOTED,
      SHELL_TOKEN_EXTGLOB,     SHELL_TOKEN_REDIRECT_BOTH,
      SHELL_TOKEN_COMMAND,
  };
  bool valid = shell_tokenizer_init(&state, source, strlen(source), NULL);
  for (size_t i = 0; valid && i < sizeof(expected) / sizeof(expected[0]); i++)
    valid = shell_tokenizer_next(&state, &token) && token.type == expected[i];
  valid = valid && !shell_tokenizer_next(&state, &token);
  test("Modern Bash syntax has dedicated lexical tokens", valid);

  const char *timed_source = "! time -p -- echo x | cat";
  shell_command_t *timed_commands = NULL;
  size_t timed_count = 0;
  valid = shell_tokenize_commands(timed_source, strlen(timed_source),
                                  &timed_commands,
                                  &timed_count) == SHELL_TOKENIZE_OK &&
          timed_count == 2 &&
          timed_commands[0].pipeline_time_mode == SHELL_PIPE_TIME_POSIX &&
          timed_commands[1].pipeline_time_mode == SHELL_PIPE_TIME_POSIX &&
          timed_commands[0].pipeline_negation_count == 1 &&
          timed_commands[1].pipeline_negation_count == 1 &&
          timed_commands[0].token_count >= 3 &&
          timed_commands[0].tokens[0].type == SHELL_TOKEN_PIPE_NEGATE &&
          timed_commands[0].tokens[1].type == SHELL_TOKEN_PIPE_TIME &&
          timed_commands[0].tokens[2].type == SHELL_TOKEN_PIPE_TIME_OPTION;
  shell_commands_free(timed_commands, timed_count);
  infos = NULL;
  count = 0;
  valid = valid &&
          shell_process_command(timed_source, strlen(timed_source), NULL,
                                &infos, &count) == SHELL_PROCESS_OK &&
          count == 2 && infos[0].pipeline_time_mode == SHELL_PIPE_TIME_POSIX &&
          infos[1].pipeline_time_mode == SHELL_PIPE_TIME_POSIX &&
          infos[0].command_token_count == 2 &&
          infos[0].command_tokens[0].length == 4 &&
          memcmp(infos[0].command_tokens[0].start, "echo", 4) == 0 &&
          infos[1].command_token_count == 1 &&
          infos[1].command_tokens[0].length == 3 &&
          memcmp(infos[1].command_tokens[0].start, "cat", 3) == 0;
  shell_command_infos_free(infos, count);
  test("Bash time syntax is metadata rather than executable argv", valid);

  static const char *const document_pipelines[] = {
      "time -p ! cat <<<body | cat",
      "time -p ! cat <<EOF | cat\nbody\nEOF\n",
      "time -p ! cat <<<body argument | cat",
      "time -p ! cat | <<<body",
      "time -p ! cat | <<EOF\nbody\nEOF\n",
  };
  valid = true;
  for (size_t i = 0;
       i < sizeof(document_pipelines) / sizeof(document_pipelines[0]); i++) {
    timed_commands = NULL;
    timed_count = 0;
    bool item = shell_tokenize_commands(
                    document_pipelines[i], strlen(document_pipelines[i]),
                    &timed_commands, &timed_count) == SHELL_TOKENIZE_OK &&
                timed_count == 2;
    for (size_t command = 0; item && command < timed_count; command++)
      item =
          timed_commands[command].pipeline_time_mode == SHELL_PIPE_TIME_POSIX &&
          timed_commands[command].pipeline_negation_count == 1;
    shell_commands_free(timed_commands, timed_count);
    infos = NULL;
    count = 0;
    shell_process_status_t status = shell_process_command(
        document_pipelines[i], strlen(document_pipelines[i]), NULL, &infos,
        &count);
    item = item && status == SHELL_PROCESS_OK && count == 2;
    for (size_t command = 0; item && command < count; command++)
      item = infos[command].pipeline_time_mode == SHELL_PIPE_TIME_POSIX &&
             infos[command].pipeline_negation_count == 1;
    shell_command_infos_free(infos, count);
    if (!item)
      fprintf(stderr, "Document pipeline consumer: %s\n",
              document_pipelines[i]);
    valid = valid && item;
  }
  test("Document pipeline modifiers reach full tokenizer and processor", valid);

  /* Repeated timing prefixes retain the innermost formatting option. They are
   * syntax on every public parsing surface, never an executable argv word or
   * an anomaly execution-stage record. */
  static const char repeated_time_source[] = "time time -p true";
  shell_netstring_buffer_t repeated_netargv = {0};
  shell_netstring_buffer_t repeated_command_netseq = {0};
  shell_transformed_command_t **repeated_transformed = NULL;
  size_t repeated_transformed_count = 0;
  shell_abstract_command_t *repeated_abstract = NULL;
  timed_commands = NULL;
  timed_count = 0;
  infos = NULL;
  count = 0;
  bool repeated_features = false;
  valid =
      shell_tokenize_commands(repeated_time_source,
                              sizeof(repeated_time_source) - 1, &timed_commands,
                              &timed_count) == SHELL_TOKENIZE_OK &&
      timed_count == 1 &&
      timed_commands[0].pipeline_time_mode == SHELL_PIPE_TIME_POSIX &&
      timed_commands[0].token_count == 4 &&
      timed_commands[0].tokens[0].type == SHELL_TOKEN_PIPE_TIME &&
      timed_commands[0].tokens[1].type == SHELL_TOKEN_PIPE_TIME &&
      timed_commands[0].tokens[2].type == SHELL_TOKEN_PIPE_TIME_OPTION &&
      timed_commands[0].tokens[3].type == SHELL_TOKEN_COMMAND &&
      shell_process_command(repeated_time_source,
                            sizeof(repeated_time_source) - 1, NULL, &infos,
                            &count) == SHELL_PROCESS_OK &&
      count == 1 && infos[0].pipeline_time_mode == SHELL_PIPE_TIME_POSIX &&
      infos[0].command_token_count == 1 &&
      infos[0].command_tokens[0].length == strlen("true") &&
      memcmp(infos[0].command_tokens[0].start, "true", strlen("true")) == 0 &&
      shell_build_netargv_sequence_buffer(
          repeated_time_source, sizeof(repeated_time_source) - 1, NULL,
          &repeated_netargv, &count, &repeated_features) == SHELL_PROCESS_OK &&
      repeated_netargv.data != NULL &&
      (repeated_netargv.length != sizeof("7:4:true,,") - 1 ||
       memcmp(repeated_netargv.data, "7:4:true,,", repeated_netargv.length)) ==
          0 &&
      count == 1 && repeated_features &&
      shell_build_command_netseq_buffer(
          repeated_time_source, sizeof(repeated_time_source) - 1, NULL,
          &repeated_command_netseq, &count) == SHELL_PROCESS_OK &&
      repeated_command_netseq.data != NULL &&
      (repeated_command_netseq.length != sizeof("4:true,") - 1 ||
       memcmp(repeated_command_netseq.data, "4:true,",
              repeated_command_netseq.length)) == 0 &&
      count == 1 &&
      shell_transform_command_line(
          repeated_time_source, sizeof(repeated_time_source) - 1, NULL,
          &repeated_transformed,
          &repeated_transformed_count) == SHELL_TRANSFORM_OK &&
      repeated_transformed_count == 1 && repeated_transformed != NULL &&
      repeated_transformed[0]->has_shell_syntax &&
      shell_abstract_command_parse(repeated_time_source,
                                   sizeof(repeated_time_source) - 1,
                                   &repeated_abstract) == SHELL_ABSTRACT_OK &&
      repeated_abstract != NULL;
  shell_abstract_command_free(repeated_abstract);
  shell_transformed_command_list_free(repeated_transformed,
                                      repeated_transformed_count);
  shell_netstring_buffer_free(&repeated_command_netseq);
  shell_netstring_buffer_free(&repeated_netargv);
  shell_command_infos_free(infos, count);
  shell_commands_free(timed_commands, timed_count);
  test("Repeated Bash time prefixes stay structural across APIs", valid);

  static const struct {
    const char *source;
    shell_pipeline_time_mode_t mode;
  } timed_boundaries[] = {
      {"time>/tmp/timing echo x", SHELL_PIPE_TIME_DEFAULT},
      {"time</dev/null cat", SHELL_PIPE_TIME_DEFAULT},
      {"time -p>/tmp/timing true", SHELL_PIPE_TIME_POSIX},
      {"time -->/tmp/timing true", SHELL_PIPE_TIME_POSIX},
      {"ti\\\nme true", SHELL_PIPE_TIME_DEFAULT},
      {"\\\ntime true", SHELL_PIPE_TIME_DEFAULT},
      {"time\\\n>/tmp/timing true", SHELL_PIPE_TIME_DEFAULT},
  };
  valid = true;
  for (size_t i = 0; i < sizeof(timed_boundaries) / sizeof(timed_boundaries[0]);
       i++) {
    timed_commands = NULL;
    timed_count = 0;
    bool item =
        shell_tokenize_commands(
            timed_boundaries[i].source, strlen(timed_boundaries[i].source),
            &timed_commands, &timed_count) == SHELL_TOKENIZE_OK &&
        timed_count == 1 &&
        timed_commands[0].pipeline_time_mode == timed_boundaries[i].mode;
    valid = valid && item;
    shell_commands_free(timed_commands, timed_count);
  }
  test("Bash time recognizes logical word and redirect boundaries", valid);

  static const char *const attached_negator_redirects[] = {
      "!>/tmp/out true",     "!<in cat", "!<<<body cat", "!&>/tmp/out true",
      "!\\\n>/tmp/out true",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(attached_negator_redirects) /
                             sizeof(attached_negator_redirects[0]);
       i++) {
    shell_parse_result_t fast = {0};
    timed_commands = NULL;
    timed_count = 0;
    bool item = shell_parse_fast(attached_negator_redirects[i],
                                 strlen(attached_negator_redirects[i]), NULL,
                                 &fast) == SHELL_OK &&
                fast.count != 0 && fast.cmds[0].pipeline_negation_count == 1 &&
                shell_tokenize_commands(attached_negator_redirects[i],
                                        strlen(attached_negator_redirects[i]),
                                        &timed_commands,
                                        &timed_count) == SHELL_TOKENIZE_OK &&
                timed_count != 0 &&
                timed_commands[0].pipeline_negation_count == 1 &&
                timed_commands[0].token_count != 0 &&
                timed_commands[0].tokens[0].type == SHELL_TOKEN_PIPE_NEGATE &&
                tokenizer_tokens_are_consistent(attached_negator_redirects[i],
                                                timed_commands, timed_count);
    valid = valid && item;
    shell_commands_free(timed_commands, timed_count);
  }
  static const char *const word_forming_bang[] = {
      "!2>/tmp/out true", "!{fd}>/tmp/out true", "!<(printf x)",
      "!>(cat)",          "!(pattern)",
  };
  for (size_t i = 0;
       i < sizeof(word_forming_bang) / sizeof(word_forming_bang[0]); i++) {
    shell_parse_result_t fast = {0};
    timed_commands = NULL;
    timed_count = 0;
    bool item =
        shell_parse_fast(word_forming_bang[i], strlen(word_forming_bang[i]),
                         NULL, &fast) == SHELL_OK &&
        fast.count != 0 && fast.cmds[0].pipeline_negation_count == 0 &&
        shell_tokenize_commands(word_forming_bang[i],
                                strlen(word_forming_bang[i]), &timed_commands,
                                &timed_count) == SHELL_TOKENIZE_OK &&
        timed_count != 0 && timed_commands[0].pipeline_negation_count == 0 &&
        timed_commands[0].token_count != 0 &&
        timed_commands[0].tokens[0].type != SHELL_TOKEN_PIPE_NEGATE;
    valid = valid && item;
    shell_commands_free(timed_commands, timed_count);
  }
  test("Pipeline negation recognizes operator but not word-forming boundaries",
       valid);

  static const char *const invalid_timed_closes[] = {
      "(time)",
      "(time !)",
      "echo \"$(time)\"",
      "cat <(time)",
      "cat >(time !)",
      "echo \"${value:-$(time)}\"",
      "cat <<EOF\n$(time)\nEOF\n",
      "cat <<EOF\n'$(time)'\nEOF\n",
      "cat <<EOF\n${value:-$(time)}\nEOF\n",
      "cat <<EOF\n$(( $(time) ))\nEOF\n",
      "cat <<EOF\n`(time)`\nEOF\n",
  };
  valid = true;
  for (size_t i = 0;
       i < sizeof(invalid_timed_closes) / sizeof(invalid_timed_closes[0]);
       i++) {
    shell_parse_result_t fast = {0};
    shell_processed_commands_t processed = {0};
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    timed_commands = NULL;
    timed_count = 0;
    bool item =
        !shell_tokenizer_list_syntax_valid(invalid_timed_closes[i],
                                           strlen(invalid_timed_closes[i])) &&
        shell_parse_fast(invalid_timed_closes[i],
                         strlen(invalid_timed_closes[i]), NULL,
                         &fast) == SHELL_EPARSE &&
        shell_tokenize_commands(
            invalid_timed_closes[i], strlen(invalid_timed_closes[i]),
            &timed_commands, &timed_count) == SHELL_TOKENIZE_EPARSE &&
        shell_process_commands(invalid_timed_closes[i],
                               strlen(invalid_timed_closes[i]), NULL,
                               &processed) == SHELL_PROCESS_EPARSE &&
        shell_transform_command_line(
            invalid_timed_closes[i], strlen(invalid_timed_closes[i]), NULL,
            &transformed, &transformed_count) == SHELL_TRANSFORM_EPARSE;
    valid = valid && item && timed_commands == NULL && timed_count == 0 &&
            processed.commands == NULL && processed.command_count == 0 &&
            transformed == NULL && transformed_count == 0;
    shell_commands_free(timed_commands, timed_count);
    shell_processed_commands_free(&processed);
    shell_transformed_command_list_free(transformed, transformed_count);
  }
  static const char *const valid_timed_terminators[] = {
      "time",
      "time !",
      "(time;)",
      "(time !\n)",
      "echo \"$(time;)\"",
      "cat <(time;)",
      "echo \"`time`\"",
      "cat <<'EOF'\n$(time)\nEOF\n",
      "cat <<EOF\n$(time;)\nEOF\n",
      "cat <<EOF\n\\$(time)\nEOF\n",
      "cat <<EOF\n${value:-$(time;)}\nEOF\n",
      "cat <<EOF\n$(( $(time;) ))\nEOF\n",
      "cat <<EOF\n`time`\nEOF\n",
      "cat <<EOF\n<(time)\nEOF\n",
  };
  for (size_t i = 0;
       i < sizeof(valid_timed_terminators) / sizeof(valid_timed_terminators[0]);
       i++)
    valid = valid &&
            shell_tokenizer_list_syntax_valid(
                valid_timed_terminators[i], strlen(valid_timed_terminators[i]));

  /* Bash's outer `-n` pass accepts these complete lexical forms, then its
   * recursive parenthesized-substitution parser rejects the terminal empty
   * timed pipeline when the source is executed. Canonical semantic APIs must
   * reject them atomically even though the diagnostic list scanner remains
   * intentionally lexical. */
  static const char *const runtime_invalid_parenthesized_time[] = {
      "echo \"$(time)\"",
      "echo \"$(time;)\"",
      "echo \"$(exec 2>&1; time;)\"",
      "cat <(time;)",
      "printf x > >(time;)",
      "cat <<EOF\n$(time;)\nEOF\n",
      "cat <<EOF\n${value:-$(time;)}\nEOF\n",
  };
  for (size_t i = 0; i < sizeof(runtime_invalid_parenthesized_time) /
                             sizeof(runtime_invalid_parenthesized_time[0]);
       i++) {
    shell_processed_commands_t processed = {0};
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    const char *source = runtime_invalid_parenthesized_time[i];
    bool item =
        shell_process_validate_supported_source(source, strlen(source), NULL) ==
            SHELL_PROCESS_EPARSE &&
        shell_process_commands(source, strlen(source), NULL, &processed) ==
            SHELL_PROCESS_EPARSE &&
        shell_transform_command_line(source, strlen(source), NULL, &transformed,
                                     &transformed_count) ==
            SHELL_TRANSFORM_EPARSE &&
        processed.commands == NULL && processed.command_count == 0 &&
        transformed == NULL && transformed_count == 0;
    valid = valid && item;
    shell_processed_commands_free(&processed);
    shell_transformed_command_list_free(transformed, transformed_count);
  }
  static const char *const runtime_valid_parenthesized_time[] = {
      "echo \"$(time &)\"", "echo \"$(time >/dev/null)\"",
      ": < <(time; :)",     "printf x > >(time; :)",
      "echo `time;`",
  };
  for (size_t i = 0; i < sizeof(runtime_valid_parenthesized_time) /
                             sizeof(runtime_valid_parenthesized_time[0]);
       i++) {
    shell_processed_commands_t processed = {0};
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    const char *source = runtime_valid_parenthesized_time[i];
    bool item =
        shell_process_validate_supported_source(source, strlen(source), NULL) ==
            SHELL_PROCESS_OK &&
        shell_process_commands(source, strlen(source), NULL, &processed) ==
            SHELL_PROCESS_OK &&
        shell_transform_command_line(source, strlen(source), NULL, &transformed,
                                     &transformed_count) == SHELL_TRANSFORM_OK;
    valid = valid && item;
    shell_processed_commands_free(&processed);
    shell_transformed_command_list_free(transformed, transformed_count);
  }
  test("Empty timed pipelines require the correct terminating context", valid);

  static const char *const prefixed_groups[] = {
      "time { echo x; }",
      "! { echo x; }",
      "! time (echo x)",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(prefixed_groups) / sizeof(prefixed_groups[0]);
       i++) {
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    timed_commands = NULL;
    timed_count = 0;
    bool item = shell_tokenize_commands(
                    prefixed_groups[i], strlen(prefixed_groups[i]),
                    &timed_commands, &timed_count) == SHELL_TOKENIZE_OK &&
                timed_count == 1 &&
                tokenizer_tokens_are_consistent(prefixed_groups[i],
                                                timed_commands, timed_count) &&
                shell_transform_command_line(
                    prefixed_groups[i], strlen(prefixed_groups[i]), NULL,
                    &transformed, &transformed_count) == SHELL_TRANSFORM_OK &&
                transformed_count == 1 && transformed[0]->has_shell_syntax;
    valid = valid && item;
    shell_commands_free(timed_commands, timed_count);
    shell_transformed_command_list_free(transformed, transformed_count);
  }
  test("Compound pipeline prefixes preserve command token-span invariants",
       valid);

  static const char timed_transform_source[] = "time -p -- printf $VALUE";
  shell_transformed_command_t **timed_transformed = NULL;
  size_t timed_transformed_count = 0;
  shell_transform_limits_t timed_transform_limit = {
      .max_string_bytes = 8,
      .max_total_bytes = SIZE_MAX,
  };
  valid =
      shell_transform_command_line(
          timed_transform_source, sizeof(timed_transform_source) - 1, NULL,
          &timed_transformed, &timed_transformed_count) == SHELL_TRANSFORM_OK &&
      timed_transformed_count == 1 && timed_transformed != NULL &&
      timed_transformed[0]->has_shell_syntax &&
      timed_transformed[0]->has_transformations &&
      strcmp(timed_transformed[0]->display_text,
             "time -p -- printf VAR_VALUE") == 0;
  shell_transformed_command_list_free(timed_transformed,
                                      timed_transformed_count);
  timed_transformed = (shell_transformed_command_t **)(void *)1;
  timed_transformed_count = SIZE_MAX;
  valid = valid &&
          shell_transform_command_line(
              timed_transform_source, sizeof(timed_transform_source) - 1,
              &timed_transform_limit, &timed_transformed,
              &timed_transformed_count) == SHELL_TRANSFORM_EOUTPUT_LIMIT &&
          timed_transformed == NULL && timed_transformed_count == 0;
  test("Timed transformations preserve syntax and fail atomically at limits",
       valid);

  static const char *const composed_time_words[] = {
      "time$(echo x)", "time`echo x`", "time$((1))",   "time$'x'",
      "time>(true)",   "time<(true)",  "time{fd}>out",
  };
  valid = true;
  for (size_t i = 0;
       i < sizeof(composed_time_words) / sizeof(composed_time_words[0]); i++) {
    timed_commands = NULL;
    timed_count = 0;
    bool item = shell_tokenize_commands(
                    composed_time_words[i], strlen(composed_time_words[i]),
                    &timed_commands, &timed_count) == SHELL_TOKENIZE_OK &&
                timed_count != 0;
    for (size_t command = 0; item && command < timed_count; command++) {
      item = timed_commands[command].pipeline_time_mode == SHELL_PIPE_TIME_NONE;
      for (size_t index = 0;
           item && index < timed_commands[command].token_count; index++)
        item = timed_commands[command].tokens[index].type !=
                   SHELL_TOKEN_PIPE_TIME &&
               timed_commands[command].tokens[index].type !=
                   SHELL_TOKEN_PIPE_TIME_OPTION;
    }
    valid = valid && item;
    shell_commands_free(timed_commands, timed_count);
  }
  test("Composed time spellings remain ordinary shell words", valid);

  const char *compound_timed =
      "time printf x | { time -p cat; printf tail; } | sort";
  timed_commands = NULL;
  timed_count = 0;
  valid = shell_tokenize_commands(compound_timed, strlen(compound_timed),
                                  &timed_commands,
                                  &timed_count) == SHELL_TOKENIZE_OK &&
          timed_count == 4 &&
          timed_commands[0].pipeline_time_mode == SHELL_PIPE_TIME_DEFAULT &&
          timed_commands[1].pipeline_time_mode == SHELL_PIPE_TIME_POSIX &&
          timed_commands[2].pipeline_time_mode == SHELL_PIPE_TIME_DEFAULT &&
          timed_commands[3].pipeline_time_mode == SHELL_PIPE_TIME_DEFAULT;
  if (!valid) {
    fprintf(stderr, "compound time modes: count=%zu", timed_count);
    for (size_t i = 0; i < timed_count; i++)
      fprintf(stderr, " %u", (unsigned)timed_commands[i].pipeline_time_mode);
    fputc('\n', stderr);
  }
  shell_commands_free(timed_commands, timed_count);
  test("Full tokenizer preserves nested compound timing scopes", valid);

  static const struct {
    const char *source;
    shell_pipeline_time_mode_t modes[3];
    uint32_t negations[3];
  } nested_modifier_scopes[] = {
      {"time -p { time a | b; } | c",
       {SHELL_PIPE_TIME_DEFAULT, SHELL_PIPE_TIME_DEFAULT,
        SHELL_PIPE_TIME_POSIX},
       {0, 0, 0}},
      {"time { time -p a | b; } | c",
       {SHELL_PIPE_TIME_POSIX, SHELL_PIPE_TIME_POSIX, SHELL_PIPE_TIME_DEFAULT},
       {0, 0, 0}},
      {"! { ! ! a | b; } | c",
       {SHELL_PIPE_TIME_NONE, SHELL_PIPE_TIME_NONE, SHELL_PIPE_TIME_NONE},
       {2, 2, 1}},
      {"! { a; b; }",
       {SHELL_PIPE_TIME_NONE, SHELL_PIPE_TIME_NONE, SHELL_PIPE_TIME_NONE},
       {0, 0, 0}},
  };
  valid = true;
  for (size_t i = 0;
       i < sizeof(nested_modifier_scopes) / sizeof(nested_modifier_scopes[0]);
       i++) {
    const char *input = nested_modifier_scopes[i].source;
    timed_commands = NULL;
    timed_count = 0;
    bool item = shell_tokenize_commands(input, strlen(input), &timed_commands,
                                        &timed_count) == SHELL_TOKENIZE_OK &&
                timed_count == (i == 3 ? 2 : 3);
    for (size_t command = 0; item && command < timed_count; command++)
      item = timed_commands[command].pipeline_time_mode ==
                 nested_modifier_scopes[i].modes[command] &&
             timed_commands[command].pipeline_negation_count ==
                 nested_modifier_scopes[i].negations[command] &&
             timed_commands[command].pipeline_negated ==
                 ((nested_modifier_scopes[i].negations[command] & 1u) != 0);
    if (!item)
      fprintf(stderr, "nested modifier scope mismatch: %s\n", input);
    shell_commands_free(timed_commands, timed_count);

    shell_command_info_t *processed = NULL;
    size_t processed_count = 0;
    bool processed_item =
        shell_process_command(input, strlen(input), NULL, &processed,
                              &processed_count) == SHELL_PROCESS_OK &&
        processed_count == (i == 3 ? 2 : 3);
    for (size_t command = 0; processed_item && command < processed_count;
         command++)
      processed_item =
          processed[command].pipeline_time_mode ==
              nested_modifier_scopes[i].modes[command] &&
          processed[command].pipeline_negation_count ==
              nested_modifier_scopes[i].negations[command] &&
          processed[command].pipeline_negated ==
              ((nested_modifier_scopes[i].negations[command] & 1u) != 0);
    if (!processed_item)
      fprintf(stderr, "processed modifier scope mismatch: %s\n", input);
    shell_command_infos_free(processed, processed_count);
    valid = valid && item && processed_item;
  }
  test("Tokenizer and processor bound nested pipeline modifier scopes", valid);

  static const char *const empty_timed[] = {
      "time", "time !", "! time", "time -p", "time --",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(empty_timed) / sizeof(empty_timed[0]); i++) {
    infos = NULL;
    count = 0;
    shell_process_status_t status = shell_process_command(
        empty_timed[i], strlen(empty_timed[i]), NULL, &infos, &count);
    bool item =
        status == SHELL_PROCESS_OK && count == 1 &&
        infos[0].command_token_count == 0 &&
        infos[0].pipeline_time_mode ==
            (strstr(empty_timed[i], "-p") || strstr(empty_timed[i], "--")
                 ? SHELL_PIPE_TIME_POSIX
                 : SHELL_PIPE_TIME_DEFAULT);
    if (!item)
      fprintf(stderr, "empty timed pipeline mismatch: %s status=%d count=%zu\n",
              empty_timed[i], (int)status, count);
    valid = valid && item;
    shell_command_infos_free(infos, count);
  }
  test("Empty timed pipelines retain one argv-less semantic stage", valid);

  static const struct {
    const char *source;
    size_t count;
  } timed_list_boundaries[] = {
      {"time; echo next", 2},
      {"time & echo next", 2},
      {"time !; echo next", 2},
      {"time # timing an empty pipeline\necho next", 2},
      {"time\necho next", 2},
  };
  valid = true;
  for (size_t i = 0;
       i < sizeof(timed_list_boundaries) / sizeof(timed_list_boundaries[0]);
       i++) {
    shell_processed_commands_t processed = {0};
    shell_process_status_t status = shell_process_commands(
        timed_list_boundaries[i].source,
        strlen(timed_list_boundaries[i].source), NULL, &processed);
    bool item =
        status == SHELL_PROCESS_OK && processed.command_count == 1 &&
        processed.commands[0].pipeline_time_mode == SHELL_PIPE_TIME_NONE;
    if (!item)
      fprintf(stderr,
              "timed list structured mismatch: %s status=%d count=%zu\n",
              timed_list_boundaries[i].source, (int)status,
              processed.command_count);
    valid = valid && item;
    shell_processed_commands_free(&processed);

    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_tokenize_status_t tokenize_status = shell_tokenize_commands(
        timed_list_boundaries[i].source,
        strlen(timed_list_boundaries[i].source), &commands, &command_count);
    item = tokenize_status == SHELL_TOKENIZE_OK &&
           command_count == timed_list_boundaries[i].count &&
           commands[0].pipeline_time_mode != SHELL_PIPE_TIME_NONE;
    if (!item)
      fprintf(stderr, "timed list lexical mismatch: %s status=%d count=%zu\n",
              timed_list_boundaries[i].source, (int)tokenize_status,
              command_count);
    valid = valid && item;
    shell_commands_free(commands, command_count);
  }
  static const char *const invalid_empty_timed_joins[] = {
      "time | cat",
      "time |& cat",
      "time && echo next",
      "time || echo next",
      "echo \"$( (time;) )\"",
      "echo \"$(time (time;))\"",
      "echo \"$( (time;); : )\"",
      "cat <( (time;) )",
      "printf x > >( (time;) )",
  };
  for (size_t i = 0; i < sizeof(invalid_empty_timed_joins) /
                             sizeof(invalid_empty_timed_joins[0]);
       i++) {
    shell_processed_commands_t processed = {0};
    valid = valid &&
            shell_process_commands(invalid_empty_timed_joins[i],
                                   strlen(invalid_empty_timed_joins[i]), NULL,
                                   &processed) == SHELL_PROCESS_EPARSE &&
            processed.commands == NULL && processed.command_count == 0;
  }
  test("Empty timed pipelines obey Bash list boundaries", valid);

  const char *pipe_both_source = "left|&right";
  shell_token_type_t pipe_both_tokens[] = {
      SHELL_TOKEN_COMMAND, SHELL_TOKEN_PIPE_BOTH, SHELL_TOKEN_COMMAND};
  valid = shell_tokenizer_init(&state, pipe_both_source,
                               strlen(pipe_both_source), NULL);
  for (size_t i = 0;
       valid && i < sizeof(pipe_both_tokens) / sizeof(pipe_both_tokens[0]); i++)
    valid = shell_tokenizer_next(&state, &token) &&
            token.type == pipe_both_tokens[i] &&
            (token.type != SHELL_TOKEN_PIPE_BOTH || token.length == 2);
  valid = valid && !shell_tokenizer_next(&state, &token);
  parsed = (shell_parse_result_t){0};
  valid = valid &&
          shell_parse_fast(pipe_both_source, strlen(pipe_both_source), NULL,
                           &parsed) == SHELL_OK &&
          parsed.count == 2 && parsed.cmds[1].type == SHELL_TYPE_PIPELINE &&
          parsed.cmds[1].pipe_input_mode == SHELL_PIPE_MODE_STDOUT_AND_STDERR &&
          (parsed.cmds[0].features & SHELL_FEAT_BACKGROUND) == 0;
  test("Bash pipe-both has one lexical and fast-parser relation", valid);

  const char *mixed_pipe_source = "! left |& middle | right";
  parsed = (shell_parse_result_t){0};
  valid = shell_parse_fast(mixed_pipe_source, strlen(mixed_pipe_source), NULL,
                           &parsed) == SHELL_OK &&
          parsed.count == 3 &&
          (parsed.cmds[0].modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0 &&
          parsed.cmds[1].type == SHELL_TYPE_PIPELINE &&
          parsed.cmds[1].pipe_input_mode == SHELL_PIPE_MODE_STDOUT_AND_STDERR &&
          parsed.cmds[2].type == SHELL_TYPE_PIPELINE &&
          parsed.cmds[2].pipe_input_mode == SHELL_PIPE_MODE_STDOUT;
  test("Mixed Bash pipelines preserve each input mode", valid);

  infos = NULL;
  count = 0;
  valid = shell_process_command(pipe_both_source, strlen(pipe_both_source),
                                NULL, &infos, &count) == SHELL_PROCESS_OK &&
          count == 2 && infos[0].has_pipe_output &&
          infos[0].pipe_output_mode == SHELL_PIPE_MODE_STDOUT_AND_STDERR &&
          infos[1].has_pipe_input &&
          infos[1].pipe_output_mode == SHELL_PIPE_MODE_NONE;
  shell_command_infos_free(infos, count);
  static const char group_pipe_both_source[] = "{ left; } |& { right; }";
  shell_processed_commands_t pipe_both_groups = {0};
  valid = valid &&
          shell_process_commands(group_pipe_both_source,
                                 sizeof(group_pipe_both_source) - 1, NULL,
                                 &pipe_both_groups) == SHELL_PROCESS_OK &&
          pipe_both_groups.group_count == 2 &&
          pipe_both_groups.group_io_op_count == 2;
  const shell_group_io_op_t *pipe_both_output = NULL;
  const shell_group_io_op_t *pipe_both_input = NULL;
  for (size_t i = 0; i < pipe_both_groups.group_io_op_count; i++) {
    const shell_group_io_op_t *op = &pipe_both_groups.group_io_ops[i];
    if (op->kind == SHELL_GROUP_IO_PIPE_OUTPUT_STDERR)
      pipe_both_output = op;
    if (op->kind == SHELL_GROUP_IO_PIPE_INPUT)
      pipe_both_input = op;
  }
  valid = valid && pipe_both_output != NULL && pipe_both_input != NULL &&
          pipe_both_output->group_index != pipe_both_input->group_index &&
          pipe_both_output->source_start == pipe_both_input->source_start &&
          pipe_both_output->source_end == pipe_both_input->source_end &&
          pipe_both_output->source_end - pipe_both_output->source_start == 2 &&
          memcmp(group_pipe_both_source + pipe_both_output->source_start, "|&",
                 2) == 0;
  shell_processed_commands_free(&pipe_both_groups);
  test("Bash pipe-both preserves canonical command and group metadata", valid);

  static const struct {
    const char *input;
    shell_pipe_mode_t mode;
    shell_group_io_kind_t output_kind;
  } continued_group_pipelines[] = {
      {"{ left; } | # note\n{ right; }", SHELL_PIPE_MODE_STDOUT,
       SHELL_GROUP_IO_PIPE_OUTPUT},
      {"{ left; } |& \\\n{ right; }", SHELL_PIPE_MODE_STDOUT_AND_STDERR,
       SHELL_GROUP_IO_PIPE_OUTPUT_STDERR},
  };
  valid = true;
  for (size_t i = 0; i < sizeof(continued_group_pipelines) /
                             sizeof(continued_group_pipelines[0]);
       i++) {
    const char *input = continued_group_pipelines[i].input;
    shell_processed_commands_t continued = {0};
    valid = valid &&
            shell_process_commands(input, strlen(input), NULL, &continued) ==
                SHELL_PROCESS_OK &&
            continued.command_count == 2 && continued.group_count == 2 &&
            continued.group_io_op_count == 2;
    const shell_group_io_op_t *output = NULL;
    const shell_group_io_op_t *input_op = NULL;
    for (size_t op = 0; op < continued.group_io_op_count; op++) {
      if (continued.group_io_ops[op].kind ==
          continued_group_pipelines[i].output_kind)
        output = &continued.group_io_ops[op];
      if (continued.group_io_ops[op].kind == SHELL_GROUP_IO_PIPE_INPUT)
        input_op = &continued.group_io_ops[op];
    }
    valid =
        valid && output != NULL && input_op != NULL &&
        output->group_index != input_op->group_index &&
        output->source_start == input_op->source_start &&
        output->source_end == input_op->source_end &&
        (continued_group_pipelines[i].mode == SHELL_PIPE_MODE_STDOUT_AND_STDERR
             ? output->source_end - output->source_start == 2
             : output->source_end - output->source_start == 1);
    shell_processed_commands_free(&continued);
  }
  test("Continued group pipelines retain shared I/O relations", valid);

  shell_processed_commands_t repeated_negation = {0};
  infos = NULL;
  count = 0;
  valid = shell_process_command("! ! true", strlen("! ! true"), NULL, &infos,
                                &count) == SHELL_PROCESS_OK &&
          count == 1 && infos[0].pipeline_negation_count == 2 &&
          !infos[0].pipeline_negated && infos[0].command_token_count == 1 &&
          infos[0].command_tokens[0].length == 4 &&
          memcmp(infos[0].command_tokens[0].start, "true", 4) == 0 &&
          shell_process_commands("! ! true", strlen("! ! true"), NULL,
                                 &repeated_negation) == SHELL_PROCESS_OK &&
          repeated_negation.command_count == 1 &&
          repeated_negation.commands[0].pipeline_negation_count == 2 &&
          !repeated_negation.commands[0].pipeline_negated &&
          repeated_negation.commands[0].command_token_count == 1 &&
          repeated_negation.commands[0].command_tokens[0].length == 4 &&
          memcmp(repeated_negation.commands[0].command_tokens[0].start, "true",
                 4) == 0;
  shell_command_infos_free(infos, count);
  shell_processed_commands_free(&repeated_negation);
  test("Repeated pipeline negation preserves count and command identity",
       valid);

  typedef struct {
    const char *input;
    size_t count;
    uint32_t negation_count[3];
    bool negated[3];
    shell_pipe_mode_t output_modes[3];
  } structured_negation_case_t;
  static const structured_negation_case_t structured_negation_cases[] = {
      {"! false | cat",
       2,
       {1, 1, 0},
       {true, true, false},
       {SHELL_PIPE_MODE_STDOUT, SHELL_PIPE_MODE_NONE, SHELL_PIPE_MODE_NONE}},
      {"! false |& cat | sort",
       3,
       {1, 1, 1},
       {true, true, true},
       {SHELL_PIPE_MODE_STDOUT_AND_STDERR, SHELL_PIPE_MODE_STDOUT,
        SHELL_PIPE_MODE_NONE}},
      {"! ! false |& cat | sort",
       3,
       {2, 2, 2},
       {false, false, false},
       {SHELL_PIPE_MODE_STDOUT_AND_STDERR, SHELL_PIPE_MODE_STDOUT,
        SHELL_PIPE_MODE_NONE}},
      {"! \\\nfalse | cat",
       2,
       {1, 1, 0},
       {true, true, false},
       {SHELL_PIPE_MODE_STDOUT, SHELL_PIPE_MODE_NONE, SHELL_PIPE_MODE_NONE}},
      {"left && ! false",
       2,
       {0, 1, 0},
       {false, true, false},
       {SHELL_PIPE_MODE_NONE, SHELL_PIPE_MODE_NONE, SHELL_PIPE_MODE_NONE}},
  };
  valid = true;
  for (size_t i = 0; i < sizeof(structured_negation_cases) /
                             sizeof(structured_negation_cases[0]);
       i++) {
    const structured_negation_case_t *item = &structured_negation_cases[i];
    shell_processed_commands_t processed = {0};
    bool case_valid =
        shell_process_commands(item->input, strlen(item->input), NULL,
                               &processed) == SHELL_PROCESS_OK &&
        processed.command_count == item->count;
    for (size_t command = 0; case_valid && command < item->count; command++)
      case_valid = processed.commands[command].pipeline_negated ==
                       item->negated[command] &&
                   processed.commands[command].pipeline_negation_count ==
                       item->negation_count[command] &&
                   processed.commands[command].pipe_output_mode ==
                       item->output_modes[command];
    if (!case_valid)
      printf("    structured negation case failed: %s\n", item->input);
    valid = valid && case_valid;
    shell_processed_commands_free(&processed);
  }
  test("Structured processing preserves POSIX pipeline negation", valid);

  static const char *const broken_negated_pipelines[] = {
      "! # note\nprintf x |& cat",
      "! \nprintf x |& cat",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(broken_negated_pipelines) /
                             sizeof(broken_negated_pipelines[0]);
       i++) {
    const char *input = broken_negated_pipelines[i];
    shell_command_t *tokens = (shell_command_t *)(uintptr_t)1;
    size_t token_count = SIZE_MAX;
    infos = (shell_command_info_t *)(uintptr_t)1;
    count = SIZE_MAX;
    shell_processed_commands_t broken = {
        .commands = (shell_command_info_t *)(uintptr_t)1,
        .command_count = SIZE_MAX,
    };
    valid = valid &&
            shell_tokenize_commands(input, strlen(input), &tokens,
                                    &token_count) == SHELL_TOKENIZE_EPARSE &&
            tokens == NULL && token_count == 0 &&
            shell_process_command(input, strlen(input), NULL, &infos, &count) ==
                SHELL_PROCESS_EPARSE &&
            infos == NULL && count == 0 &&
            shell_process_commands(input, strlen(input), NULL, &broken) ==
                SHELL_PROCESS_EPARSE &&
            broken.commands == NULL && broken.command_count == 0;
  }
  test("Pipeline negation cannot cross comments or raw newlines", valid);

  /* A continuation immediately after `!` supplies no reserved-word
   * delimiter: Bash removes it before tokenization, yielding the ordinary
   * command word `!echo`, not a pipeline modifier. */
  static const char joined_bang_word[] = "!\\\necho true";
  infos = NULL;
  count = 0;
  valid = shell_process_command(joined_bang_word, sizeof(joined_bang_word) - 1,
                                NULL, &infos, &count) == SHELL_PROCESS_OK &&
          count == 1 && infos[0].pipeline_negation_count == 0 &&
          !infos[0].pipeline_negated && infos[0].command_token_count == 2 &&
          infos[0].command_tokens[0].length == strlen("!\\\necho") &&
          memcmp(infos[0].command_tokens[0].start, "!\\\necho",
                 strlen("!\\\necho")) == 0;
  shell_command_infos_free(infos, count);
  test("Immediate continued bang remains one ordinary command word", valid);

  shell_processed_commands_t negated_group = {0};
  shell_process_status_t group_status = shell_process_commands(
      "! { false; } | cat", strlen("! { false; } | cat"), NULL, &negated_group);
  bool group_valid =
      group_status == SHELL_PROCESS_OK && negated_group.command_count == 2 &&
      negated_group.group_count == 1 &&
      !negated_group.commands[0].pipeline_negated &&
      negated_group.commands[1].pipeline_negated &&
      negated_group.commands[1].pipeline_negation_count == 1 &&
      (negated_group.groups[0].modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0 &&
      negated_group.groups[0].pipeline_negation_count == 1;
  shell_processed_commands_free(&negated_group);
  if (!group_valid)
    printf("    single negated group failed (status %d)\n", group_status);
  valid = group_valid;
  group_status = shell_process_commands("! ! { false; } | cat",
                                        strlen("! ! { false; } | cat"), NULL,
                                        &negated_group);
  group_valid =
      group_status == SHELL_PROCESS_OK && negated_group.command_count == 2 &&
      negated_group.group_count == 1 &&
      !negated_group.commands[0].pipeline_negated &&
      !negated_group.commands[1].pipeline_negated &&
      negated_group.commands[1].pipeline_negation_count == 2 &&
      (negated_group.groups[0].modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0 &&
      negated_group.groups[0].pipeline_negation_count == 2;
  shell_processed_commands_free(&negated_group);
  if (!group_valid)
    printf("    repeated negated group failed (status %d)\n", group_status);
  valid = valid && group_valid;
  test("Structured negation remains owned by compound pipeline stages", valid);

  static const char *const invalid_structured_lists[] = {
      "left |",     "left |&",     "left &&",      "left ||",
      "left | ! x", "left |& ! x", "left && && x", "left || || x",
      "left & & x", "left |& | x", "left |& ; x",  "{ ; }",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(invalid_structured_lists) /
                             sizeof(invalid_structured_lists[0]);
       i++) {
    const char *input = invalid_structured_lists[i];
    shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
    size_t command_count = SIZE_MAX;
    shell_processed_commands_t processed = {
        .commands = (shell_command_info_t *)(uintptr_t)1,
        .command_count = SIZE_MAX,
        .groups = (shell_group_t *)(uintptr_t)1,
        .group_count = SIZE_MAX,
        .group_io_ops = (shell_group_io_op_t *)(uintptr_t)1,
        .group_io_op_count = SIZE_MAX,
    };
    shell_transformed_command_t **transformed =
        (shell_transformed_command_t **)(uintptr_t)1;
    size_t transformed_count = SIZE_MAX;
    valid = valid &&
            shell_tokenize_commands(input, strlen(input), &commands,
                                    &command_count) == SHELL_TOKENIZE_EPARSE &&
            commands == NULL && command_count == 0 &&
            shell_process_commands(input, strlen(input), NULL, &processed) ==
                SHELL_PROCESS_EPARSE &&
            processed.commands == NULL && processed.command_count == 0 &&
            processed.groups == NULL && processed.group_count == 0 &&
            processed.group_io_ops == NULL &&
            processed.group_io_op_count == 0 &&
            shell_transform_command_line(input, strlen(input), NULL,
                                         &transformed, &transformed_count) ==
                SHELL_TRANSFORM_EPARSE &&
            transformed == NULL && transformed_count == 0;
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    shell_transformed_command_list_free(transformed, transformed_count);
  }
  test("Malformed shell lists fail atomically across semantic adapters", valid);

  test("Fast parser rejects misplaced compound-array syntax",
       shell_parse_fast("printf items=(one two)",
                        strlen("printf items=(one two)"), NULL,
                        &parsed) == SHELL_EPARSE);
  static const char feature_source[] =
      "! items=(one two) printf $'a\\0b' @(left|right) &>out";
  valid = shell_parse_fast(feature_source, sizeof(feature_source) - 1, NULL,
                           &parsed) == SHELL_OK &&
          parsed.count == 1 &&
          (parsed.cmds[0].modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0 &&
          (parsed.cmds[0].features & SHELL_FEAT_ANSI_C_QUOTE) != 0 &&
          (parsed.cmds[0].features & SHELL_FEAT_EXTGLOB) != 0 &&
          (parsed.cmds[0].features & SHELL_FEAT_ARRAY) != 0 &&
          (parsed.cmds[0].features & SHELL_FEAT_COMBINED_REDIRECT) != 0;
  test("Fast parser preserves modern Bash feature metadata", valid);

  /* Shellsplit models one fixed Bash option state. Any set/shopt mutation can
   * alter later parsing or execution, so reject direct and wrapped mutation
   * spellings while retaining inspection-only forms. */
  static const char *const named_fd_scope_mutations[] = {
      "shopt -s varredir_close",
      "shopt -u varredir_close",
      "shopt -s lastpipe",
      "shopt -u lastpipe",
      "shopt -s extglob",
      "shopt -u execfail",
      "command shopt -s varredir_close",
      "command shopt -u lastpipe",
      "builtin -- shopt -u varredir_close",
      "command builtin shopt -s varredir_close",
      "builtin command shopt -u lastpipe",
      "command command builtin shopt -s lastpipe",
      "sh'opt' '-s' varredir_close",
      "sh'opt' '-u' lastpipe",
      "shopt $mode varredir_close",
      "x+=value shopt -s varredir_close",
      "x+\\\n=value shopt -u varredir_close",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(named_fd_scope_mutations) /
                             sizeof(named_fd_scope_mutations[0]);
       i++) {
    shell_command_info_t *rejected_infos = (shell_command_info_t *)(uintptr_t)1;
    size_t rejected_count = SIZE_MAX;
    valid =
        valid &&
        shell_process_validate_supported_source(
            named_fd_scope_mutations[i], strlen(named_fd_scope_mutations[i]),
            NULL) == SHELL_PROCESS_EPARSE &&
        shell_process_command(
            named_fd_scope_mutations[i], strlen(named_fd_scope_mutations[i]),
            NULL, &rejected_infos, &rejected_count) == SHELL_PROCESS_EPARSE &&
        rejected_infos == NULL && rejected_count == 0;
  }
  valid = valid &&
          shell_process_validate_supported_source(
              "shopt -q varredir_close", strlen("shopt -q varredir_close"),
              NULL) == SHELL_PROCESS_OK &&
          shell_process_validate_supported_source("shopt -q lastpipe",
                                                  strlen("shopt -q lastpipe"),
                                                  NULL) == SHELL_PROCESS_OK &&
          shell_process_validate_supported_source(
              "command -v shopt -s varredir_close",
              strlen("command -v shopt -s varredir_close"),
              NULL) == SHELL_PROCESS_OK &&
          shell_process_validate_supported_source("shopt -q extglob",
                                                  strlen("shopt -q extglob"),
                                                  NULL) == SHELL_PROCESS_OK;
  test("Named-FD scope option mutations are unsupported", valid);

  parsed = (shell_parse_result_t){0};
  valid =
      shell_parse_fast(">out items=(one two)", strlen(">out items=(one two)"),
                       NULL, &parsed) == SHELL_OK &&
      parsed.count == 1 && (parsed.cmds[0].features & SHELL_FEAT_ARRAY) != 0;
  test("Fast array context retains leading redirection state", valid);

  infos = NULL;
  count = 0;
  shell_netstring_buffer_t netargv = {0};
  shell_token_t binary_tokens[] = {
      {.type = SHELL_TOKEN_COMMAND, .start = "printf", .length = 6},
      {.type = SHELL_TOKEN_ARGUMENT, .start = "a\0b", .length = 3},
  };
  shell_command_info_t binary_info = {
      .command_tokens = binary_tokens,
      .command_token_count = 2,
  };
  valid = shell_process_command("printf $'a\\0b'", strlen("printf $'a\\0b'"),
                                NULL, &infos, &count) == SHELL_PROCESS_OK &&
          infos != NULL && count == 1 &&
          shell_render_netargv_buffer(&binary_info, NULL, &netargv) ==
              SHELL_PROCESS_OK;
  shell_netstring_iter_t iter;
  shell_netstring_view_t first, second;
  valid = valid &&
          shell_netstring_iter_init(&iter, netargv.data, netargv.length) ==
              SHELL_NETSTRING_OK &&
          shell_netstring_iter_next(&iter, &first) == SHELL_NETSTRING_OK &&
          shell_netstring_iter_next(&iter, &second) == SHELL_NETSTRING_OK &&
          second.payload_length == 3 && second.payload[0] == 'a' &&
          second.payload[1] == '\0' && second.payload[2] == 'b' &&
          shell_netstring_iter_next(&iter, &second) == SHELL_NETSTRING_DONE;
  shell_netstring_buffer_free(&netargv);
  shell_command_infos_free(infos, count);
  test("Complete source truncates ANSI-C fragments; direct netargv remains "
       "binary",
       valid);

  char ansi_bytes[3] = {0};
  size_t ansi_length = 0;
  size_t ansi_written = 0;
  valid = shell_measure_decoded_word("$'\\x4142'", strlen("$'\\x4142'"),
                                     &ansi_length) == SHELL_PROCESS_OK &&
          ansi_length == sizeof(ansi_bytes) &&
          shell_write_decoded_word("$'\\x4142'", strlen("$'\\x4142'"),
                                   ansi_bytes, sizeof(ansi_bytes),
                                   &ansi_written) == SHELL_PROCESS_OK &&
          ansi_written == sizeof(ansi_bytes) &&
          memcmp(ansi_bytes, "A42", sizeof(ansi_bytes)) == 0;
  test("ANSI-C hex escapes consume at most two digits", valid);

  char ansi_escapes[5] = {0};
  ansi_length = 0;
  ansi_written = 0;
  valid = shell_measure_decoded_word("$'\\q\\x\\u12'", strlen("$'\\q\\x\\u12'"),
                                     &ansi_length) == SHELL_PROCESS_OK &&
          ansi_length == sizeof(ansi_escapes) &&
          shell_write_decoded_word("$'\\q\\x\\u12'", strlen("$'\\q\\x\\u12'"),
                                   ansi_escapes, sizeof(ansi_escapes),
                                   &ansi_written) == SHELL_PROCESS_OK &&
          ansi_written == sizeof(ansi_escapes) &&
          memcmp(ansi_escapes, "\\q\\x\x12", sizeof(ansi_escapes)) == 0;
  test("ANSI-C preserves unknown escapes and accepts short Unicode", valid);

  char ansi_incomplete[2] = {0};
  ansi_written = 0;
  valid = shell_write_decoded_word("$'\\c'", strlen("$'\\c'"), ansi_incomplete,
                                   sizeof(ansi_incomplete),
                                   &ansi_written) == SHELL_PROCESS_OK &&
          ansi_written == sizeof(ansi_incomplete) &&
          memcmp(ansi_incomplete, "\\c", sizeof(ansi_incomplete)) == 0;
  test("ANSI-C preserves an incomplete control escape", valid);

  unsigned char ansi_del = 0;
  ansi_length = 0;
  ansi_written = 0;
  valid = shell_measure_decoded_word("$'\\c?'", strlen("$'\\c?'"),
                                     &ansi_length) == SHELL_PROCESS_OK &&
          ansi_length == 1 &&
          shell_write_decoded_word("$'\\c?'", strlen("$'\\c?'"),
                                   (char *)&ansi_del, sizeof(ansi_del),
                                   &ansi_written) == SHELL_PROCESS_OK &&
          ansi_written == 1 && ansi_del == 0x7f;
  test("ANSI-C control-question escape emits DEL", valid);

  static const char extended_ansi_source[] = "$'\\uD800\\U00110000'";
  unsigned char extended_ansi[8] = {0};
  ansi_length = 0;
  ansi_written = 0;
  valid = shell_measure_decoded_word(extended_ansi_source,
                                     sizeof(extended_ansi_source) - 1,
                                     &ansi_length) == SHELL_PROCESS_EPARSE &&
          shell_write_decoded_word(extended_ansi_source,
                                   sizeof(extended_ansi_source) - 1,
                                   (char *)extended_ansi, sizeof(extended_ansi),
                                   &ansi_written) == SHELL_PROCESS_EPARSE &&
          ansi_written == 0;
  test("ANSI-C non-ASCII Unicode requires an execution locale contract", valid);

  static const char *const locale_words[] = {
      "$'\\u0080'",
      "$'\\u00e9'",
      "$'\\U0001f600'",
      "$'\\U80000000'",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(locale_words) / sizeof(locale_words[0]); i++) {
    char output[16];
    size_t written = SIZE_MAX;
    char *decoded = NULL;
    size_t decoded_length = 0;
    valid &= shell_write_processed_word(
                 locale_words[i], strlen(locale_words[i]), output,
                 sizeof(output), &written) == SHELL_PROCESS_EPARSE &&
             written == 0;
    valid &=
        shell_decode_word(locale_words[i], strlen(locale_words[i]), &decoded,
                          &decoded_length) == SHELL_PROCESS_EPARSE &&
        decoded == NULL;
    free(decoded);
  }
  static const char bytes_source[] = "$'\\u007f\\xE9\\351'";
  static const unsigned char bytes_expected[] = {0x7f, 0xe9, 0xe9};
  unsigned char byte_output[3];
  size_t byte_count = 0;
  valid &= shell_write_processed_word(bytes_source, sizeof(bytes_source) - 1,
                                      (char *)byte_output, sizeof(byte_output),
                                      &byte_count) == SHELL_PROCESS_OK &&
           byte_count == sizeof(byte_output) &&
           memcmp(byte_output, bytes_expected, sizeof(byte_output)) == 0;
  test("Canonical word decoding rejects locale-dependent escapes, not bytes",
       valid);

  shell_netstring_buffer_t argv_sequence = {0};
  shell_netstring_buffer_t command_sequence = {0};
  shell_netstring_buffer_t type_sequence = {0};
  shell_netstring_buffer_t anomaly_commands = {0};
  shell_netstring_buffer_t anomaly_types = {0};
  size_t sequence_count = 0;
  bool features = false;
  const char *binary_source = "$'a\\0b'c arg";
  valid =
      shell_build_netargv_sequence_buffer(binary_source, strlen(binary_source),
                                          NULL, &argv_sequence, &sequence_count,
                                          &features) == SHELL_PROCESS_OK &&
      argv_sequence.length == strlen("11:2:ac,3:arg,,") &&
      sequence_count == 1 &&
      !memcmp(argv_sequence.data, "11:2:ac,3:arg,,", argv_sequence.length) &&
      shell_build_command_netseq_buffer(binary_source, strlen(binary_source),
                                        NULL, &command_sequence,
                                        &sequence_count) == SHELL_PROCESS_OK &&
      sequence_count == 1 && command_sequence.length == 5 &&
      !memcmp(command_sequence.data, "2:ac,", 5) &&
      shell_build_type_netseq_buffer(binary_source, strlen(binary_source), NULL,
                                     &type_sequence,
                                     &sequence_count) == SHELL_PROCESS_OK &&
      type_sequence.data != NULL && sequence_count == 1 &&
      shell_build_anomaly_netseqs_buffer(
          binary_source, strlen(binary_source), NULL, &anomaly_commands,
          &anomaly_types, &sequence_count) == SHELL_PROCESS_OK &&
      sequence_count == 1 &&
      anomaly_commands.length == command_sequence.length &&
      !memcmp(anomaly_commands.data, command_sequence.data,
              command_sequence.length) &&
      anomaly_types.length == type_sequence.length &&
      !memcmp(anomaly_types.data, type_sequence.data, type_sequence.length);
  shell_netstring_buffer_free(&argv_sequence);
  shell_netstring_buffer_free(&command_sequence);
  shell_netstring_buffer_free(&type_sequence);
  shell_netstring_buffer_free(&anomaly_commands);
  shell_netstring_buffer_free(&anomaly_types);
  test("Canonical sequence builders share effective ANSI-C word values", valid);

  infos = NULL;
  count = 0;
  valid = shell_process_command("! false | cat", strlen("! false | cat"), NULL,
                                &infos, &count) == SHELL_PROCESS_OK &&
          count == 2 && infos[0].pipeline_negated &&
          infos[1].pipeline_negated && infos[0].has_pipe_output &&
          infos[1].has_pipe_input;
  shell_command_infos_free(infos, count);
  shell_processed_commands_t incomplete_negation = {0};
  valid = valid &&
          shell_process_commands("!", strlen("!"), NULL,
                                 &incomplete_negation) == SHELL_PROCESS_EPARSE;
  shell_processed_commands_free(&incomplete_negation);
  infos = NULL;
  count = 0;
  valid = valid &&
          shell_process_command("echo !", strlen("echo !"), NULL, &infos,
                                &count) == SHELL_PROCESS_OK &&
          count == 1 && !infos[0].pipeline_negated &&
          infos[0].command_token_count == 2 &&
          infos[0].command_tokens[1].length == 1 &&
          infos[0].command_tokens[1].start[0] == '!';
  shell_command_infos_free(infos, count);
  const struct {
    const char *source;
    shell_process_status_t expected;
  } syntax_cases[] = {
      {"cmd | ! other", SHELL_PROCESS_EPARSE},
      {"items=(one two)", SHELL_PROCESS_EPARSE},
      {"items[0]=one", SHELL_PROCESS_EPARSE},
      {"map[key]+=one", SHELL_PROCESS_EPARSE},
      {"printf '%s' \"${items[0]}\"", SHELL_PROCESS_EPARSE},
      {"declare -a items", SHELL_PROCESS_EPARSE},
      {"FOO=bar declare -a items", SHELL_PROCESS_EPARSE},
      {"FOO+=bar declare -a items", SHELL_PROCESS_EPARSE},
      {"command typeset -A items", SHELL_PROCESS_EPARSE},
      {"command -p -- declare -a items", SHELL_PROCESS_EPARSE},
      {"builtin -- typeset -A items", SHELL_PROCESS_EPARSE},
      {"echo item[0]=one", SHELL_PROCESS_OK},
      {"echo one ;& echo two", SHELL_PROCESS_EPARSE},
      {"echo one ;;& echo two", SHELL_PROCESS_EPARSE},
      {"echo $(echo one ;& echo two)", SHELL_PROCESS_EPARSE},
      {"cmd {fd}>&1", SHELL_PROCESS_OK},
      {"cmd {fd}>out", SHELL_PROCESS_OK},
  };
  for (size_t i = 0; i < sizeof(syntax_cases) / sizeof(syntax_cases[0]); i++) {
    shell_processed_commands_t processed = {0};
    shell_process_status_t status = shell_process_commands(
        syntax_cases[i].source, strlen(syntax_cases[i].source), NULL,
        &processed);
    if (status != syntax_cases[i].expected) {
      fprintf(stderr, "Unexpected status %d for modern syntax: %s\n",
              (int)status, syntax_cases[i].source);
      valid = false;
    }
    shell_processed_commands_free(&processed);
  }
  test("Pipeline negation and arrays preserve semantic boundaries", valid);

  shell_processed_commands_t deferred = {0};
  valid = shell_process_commands("select x in a; do :; done",
                                 strlen("select x in a; do :; done"), NULL,
                                 &deferred) == SHELL_PROCESS_EPARSE &&
          shell_process_commands("coproc worker { echo ok; }",
                                 strlen("coproc worker { echo ok; }"), NULL,
                                 &deferred) == SHELL_PROCESS_EPARSE;
  shell_processed_commands_free(&deferred);
  test("Deferred control-flow constructs reject semantically", valid);
}

static void tokenizer_test_processor_routing_cross_product(void) {
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
      "command <<-'EOF'\n\tbody\n\tEOF\n",
      "! command | next",
      "command |& next | final",
      "{ command; } |& { next; }",
      "( command; ) >out",
      "command && next || fallback; final &",
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    shell_processed_commands_t processed = {0};
    valid = shell_process_command(cases[i], strlen(cases[i]), NULL, &infos,
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
    shell_command_infos_free(infos, info_count);
    shell_processed_commands_free(&processed);
  }
  test("Processor preserves routing syntax across canonical adapters", valid);
}

static void tokenizer_test_escaped_word_prefix_boundaries(void) {
  static const struct {
    const char *source;
    const char *word;
    const char *second;
    size_t commands;
  } cases[] = {
      {"echo \\V&", "V", NULL, 1},
      {"echo \\V;", "V", NULL, 1},
      {"echo \\V| cat", "V", "cat", 2},
      {"echo \\V|& cat", "V", "cat", 2},
      {"echo \\V&& cat", "V", "cat", 2},
      {"echo \\V|| cat", "V", "cat", 2},
      {"echo \\V& cat", "V", "cat", 2},
      {"echo \\V\ncat", "V", "cat", 2},
      {"echo \\V>out", "V", NULL, 1},
      {"echo \\V<in", "V", NULL, 1},
      {"echo \\V$VALUE", "V$VALUE", NULL, 1},
      {"echo \\V${VALUE}", "V${VALUE}", NULL, 1},
      {"echo \\V$((1 + 2))", "V$((1 + 2))", NULL, 1},
      {"echo \\V$'x'", "Vx", NULL, 1},
      {"echo \\V$(printf x)", "V$(printf x)", NULL, 1},
      {"echo \\V`printf x`", "V`printf x`", NULL, 1},
      {"echo \\V<(printf x)", "V<(printf x)", NULL, 1},
      {"echo \\V>(cat)", "V>(cat)", NULL, 1},
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_netstring_buffer_t sequence = {0};
    shell_processed_commands_t processed = {0};
    size_t count = 0;
    bool features = false;
    bool item_valid =
        shell_build_netargv_sequence_buffer(
            cases[i].source, strlen(cases[i].source), NULL, &sequence, &count,
            &features) == SHELL_PROCESS_OK &&
        count == cases[i].commands &&
        shell_process_commands(cases[i].source, strlen(cases[i].source), NULL,
                               &processed) == SHELL_PROCESS_OK &&
        processed.command_count == count;
    shell_netstring_iter_t records;
    if (item_valid)
      item_valid =
          shell_netstring_iter_init(&records, sequence.data, sequence.length) ==
          SHELL_NETSTRING_OK;
    for (size_t command = 0; item_valid && command < count; command++) {
      shell_netstring_view_t record;
      shell_netstring_buffer_t argv = {0};
      item_valid =
          shell_netstring_iter_next(&records, &record) == SHELL_NETSTRING_OK &&
          shell_render_netargv_buffer(&processed.commands[command], NULL,
                                      &argv) == SHELL_PROCESS_OK;
      if (item_valid)
        item_valid = record.payload_length == argv.length &&
                     memcmp(record.payload, argv.data, argv.length) == 0;
      if (item_valid) {
        shell_netstring_iter_t words;
        shell_netstring_view_t word;
        const char *first = command == 0 ? "echo" : cases[i].second;
        item_valid =
            first != NULL &&
            shell_netstring_iter_init(&words, record.payload,
                                      record.payload_length) ==
                SHELL_NETSTRING_OK &&
            shell_netstring_iter_next(&words, &word) == SHELL_NETSTRING_OK &&
            word.payload_length == strlen(first) &&
            memcmp(word.payload, first, word.payload_length) == 0;
        if (item_valid && command == 0)
          item_valid =
              shell_netstring_iter_next(&words, &word) == SHELL_NETSTRING_OK &&
              word.payload_length == strlen(cases[i].word) &&
              memcmp(word.payload, cases[i].word, word.payload_length) == 0;
        if (item_valid)
          item_valid =
              shell_netstring_iter_next(&words, &word) == SHELL_NETSTRING_DONE;
      }
      shell_netstring_buffer_free(&argv);
    }
    shell_netstring_view_t extra;
    if (item_valid)
      item_valid =
          shell_netstring_iter_next(&records, &extra) == SHELL_NETSTRING_DONE;
    if (!item_valid)
      fprintf(stderr, "escaped-prefix boundary failed: %s\n", cases[i].source);
    valid = valid && item_valid;
    shell_netstring_buffer_free(&sequence);
    shell_processed_commands_free(&processed);
  }
  test("Escaped word prefixes survive operators and adjacent expansions",
       valid);
}

static void tokenizer_test_array_semantic_boundaries(void) {
  static const char *const supported[] = {
      "echo ${x:-[abc]}",   "echo ${x#[abc]}",     "echo ${x%[abc]}",
      "echo ${x//[abc]/q}", "echo ${x:-foo[bar]}", "echo \\${items[0]}",
      "echo '${items[0]}'",
  };
  static const char *const rejected[] = {
      "echo ${items[0]}",
      "echo ${items[${index}]}",
      "echo \"${#items[0]}\"",
      "echo pre\"${items[0]}\"post",
      "echo >\"${items[0]}\"",
      "echo ${!items[$(printf key)]}",
      "echo $((items[0]))",
      "echo \"$((items[0]))\"",
      "echo >\"$((items[0]))\"",
      "echo pre$((items[0]))post",
      "echo $(( \"items[0]\" ))",
      "echo $(( ${x:-[abc]} + 1 ))",
      "echo $(( ${x:-${items[0]}} ))",
      "echo $((items[$(printf 0)] + 1))",
      "echo $(printf $((items[0])))",
      "echo \"$(for x in y; do :; done)\"",
      "printf items=(one two)",
      "declare arr[0]",
      "declare 'arr[0]'",
      "declare arr\\[0\\]",
      "declare arr$'[0]'",
      "typeset map[key]",
      "command -- declare \"arr[$(printf 0)]\"",
      "echo \"${value:-$\"localized\"}\"",
      "echo \"${outer:-${inner:-$\"localized\"}}\"",
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(supported) / sizeof(supported[0]); i++) {
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    valid = valid &&
            shell_process_commands(supported[i], strlen(supported[i]), NULL,
                                   &processed) == SHELL_PROCESS_OK &&
            processed.command_count == 1 &&
            shell_dep_graph_parse(supported[i], strlen(supported[i]), ".", NULL,
                                  &graph) == SHELL_DEP_OK &&
            shell_dep_graph_validate(&graph).valid;
    shell_processed_commands_free(&processed);
  }
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    valid = valid &&
            shell_process_commands(rejected[i], strlen(rejected[i]), NULL,
                                   &processed) == SHELL_PROCESS_EPARSE &&
            processed.command_count == 0 &&
            shell_dep_graph_parse(rejected[i], strlen(rejected[i]), ".", NULL,
                                  &graph) == SHELL_DEP_EPARSE &&
            graph.node_count == 0 && graph.edge_count == 0 &&
            graph.status == SHELL_DEP_STATUS_ERROR;
    shell_processed_commands_free(&processed);
  }
  test("Array semantic boundary accepts patterns and rejects real arrays",
       valid);
}

static void tokenizer_test_ansi_c_structural_scanner_contract(void) {
  static const char *const cases[] = {
      "echo $(printf $'foo\\'bar)')",
      "cat <(printf $'foo\\'bar)')",
      "echo ${value:-$(printf $'foo\\'bar)')}",
      "{ echo $(printf $'foo\\'bar)'); }",
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    size_t length = strlen(cases[i]);
    shell_process_status_t process_status =
        shell_process_commands(cases[i], length, NULL, &processed);
    shell_dep_error_t graph_status =
        shell_dep_graph_parse(cases[i], length, ".", NULL, &graph);
    bool case_valid = process_status == SHELL_PROCESS_OK &&
                      graph_status == SHELL_DEP_OK &&
                      shell_dep_graph_validate(&graph).valid;
    valid = valid && case_valid;
    shell_processed_commands_free(&processed);
  }
  test("ANSI-C quotes remain opaque to structural scanners", valid);

  const char *arithmetic = "echo $(( $(printf $'foo\\'bar)') + 1 ))";
  shell_tokenizer_state_t state;
  shell_token_t token;
  valid = shell_tokenizer_init(&state, arithmetic, strlen(arithmetic), NULL) &&
          shell_tokenizer_next(&state, &token) &&
          token.type == SHELL_TOKEN_COMMAND &&
          shell_tokenizer_next(&state, &token) &&
          token.type == SHELL_TOKEN_ARITHMETIC && token.position == 5 &&
          token.length == strlen(arithmetic) - token.position &&
          !shell_tokenizer_next(&state, &token);
  test("ANSI-C quote cannot truncate arithmetic token span", valid);

  static const char *const array_subscripts[] = {
      "echo ${array[$'close] bracket']}",
      "echo ${array['close] bracket']}",
      "echo ${array[\"close] bracket\"]}",
      "echo ${array[$(printf \"]\")]}",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(array_subscripts) / sizeof(array_subscripts[0]);
       i++) {
    const char *input = array_subscripts[i];
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    valid = valid && shell_tokenizer_init(&state, input, strlen(input), NULL) &&
            shell_tokenizer_next(&state, &token) &&
            token.type == SHELL_TOKEN_COMMAND &&
            shell_tokenizer_next(&state, &token) &&
            token.type == SHELL_TOKEN_VARIABLE &&
            token.position == strlen("echo ") &&
            token.length == strlen(input) - token.position &&
            !shell_tokenizer_next(&state, &token) &&
            shell_process_commands(input, strlen(input), NULL, &processed) ==
                SHELL_PROCESS_EPARSE &&
            processed.commands == NULL && processed.command_count == 0 &&
            shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
                SHELL_DEP_EPARSE &&
            graph.node_count == 0 && graph.edge_count == 0;
    shell_processed_commands_free(&processed);
  }
  test("Quoted array subscripts tokenize once and reject consistently", valid);
}

static void tokenizer_test_nested_quote_and_ansi_completion(void) {
  static const char *const nested[] = {
      "echo \"${value:-\"x;y\"}\"",
      "echo \"$(printf \"x;y\")\"",
      "echo \"`printf \"x;y\"`\"",
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(nested) / sizeof(nested[0]); i++) {
    const char *source = nested[i];
    shell_command_t *commands = NULL;
    size_t count = 0;
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    size_t word_after = 0;
    const char *word = strchr(source, '"');
    bool word_ok =
        word &&
        shell_source_skip_shell_word(word, strlen(word), 0, &word_after) &&
        word_after == strlen(word);
    shell_tokenize_status_t token_status =
        shell_tokenize_commands(source, strlen(source), &commands, &count);
    shell_process_status_t process_status =
        shell_process_commands(source, strlen(source), NULL, &processed);
    shell_dep_error_t graph_status =
        shell_dep_graph_parse(source, strlen(source), ".", NULL, &graph);
    bool case_valid =
        word_ok && token_status == SHELL_TOKENIZE_OK && count == 1 &&
        process_status == SHELL_PROCESS_OK && processed.command_count == 1 &&
        graph_status == SHELL_DEP_OK && shell_dep_graph_validate(&graph).valid;
    if (!case_valid)
      fprintf(stderr,
              "nested quote case %zu: word=%d after=%zu token=%d count=%zu "
              "process=%d commands=%zu graph=%d\n",
              i, word_ok, word_after, token_status, count, process_status,
              processed.command_count, graph_status);
    valid = valid && case_valid;
    shell_commands_free(commands, count);
    shell_processed_commands_free(&processed);
  }
  test("Nested double-quote scopes agree across scanners and processor", valid);

  const char *unclosed_outer = "\"$(printf \"x;y\")";
  size_t quote_after = 0;
  test("Nested quotes do not supply the outer closing delimiter",
       !shell_source_skip_complete_quoted_text(
           unclosed_outer, strlen(unclosed_outer), 0, '"', &quote_after) &&
           !shell_source_skip_shell_word(unclosed_outer, strlen(unclosed_outer),
                                         0, &quote_after));
  bool recognized = false;
  bool helper_contract =
      !shell_source_skip_complete_backtick(NULL, 0, 0, &quote_after) &&
      !shell_source_skip_double_quote_expansion(NULL, 0, 0, &recognized,
                                                &quote_after) &&
      !shell_source_skip_complete_quoted_text(NULL, 0, 0, '\'', &quote_after) &&
      !shell_source_skip_parameter_selector(NULL, 0, 0, &quote_after) &&
      !shell_source_skip_variable_expansion(NULL, 0, 0, &quote_after) &&
      !shell_source_skip_complete_quoted_text("\"x\"", 3, 0, 'x',
                                              &quote_after) &&
      !shell_source_skip_complete_quoted_text("x", 1, 0, 'x', &quote_after) &&
      shell_source_skip_complete_quoted_text("'x'", 3, 0, '\'', &quote_after) &&
      quote_after == 3;
  test("Shared quote scanner validates boundaries and literal scopes",
       helper_contract);

  const char *incomplete = "echo $'foo\\'";
  shell_tokenizer_state_t state;
  shell_token_t token;
  shell_processed_commands_t processed = {0};
  bool lexical =
      shell_tokenizer_init(&state, incomplete, strlen(incomplete), NULL);
  bool saw_ansi = false;
  while (lexical && shell_tokenizer_next(&state, &token))
    saw_ansi = saw_ansi || token.type == SHELL_TOKEN_ANSI_C_QUOTED;
  lexical = lexical && !saw_ansi &&
            shell_process_commands(incomplete, strlen(incomplete), NULL,
                                   &processed) == SHELL_PROCESS_EPARSE;
  shell_processed_commands_free(&processed);
  test("Escaped final apostrophe is not a complete ANSI-C token", lexical);

  static const char *const escaped_final_quote[] = {
      "echo \"value\\\"",
      "echo `printf value\\`",
      "echo ${value:-\"word\\\"}",
  };
  bool completion_valid = true;
  for (size_t i = 0;
       i < sizeof(escaped_final_quote) / sizeof(escaped_final_quote[0]); i++) {
    shell_command_t *commands = NULL;
    size_t count = 0;
    shell_processed_commands_t rejected = {0};
    shell_tokenize_status_t tokenize_status = shell_tokenize_commands(
        escaped_final_quote[i], strlen(escaped_final_quote[i]), &commands,
        &count);
    shell_process_status_t process_status =
        shell_process_commands(escaped_final_quote[i],
                               strlen(escaped_final_quote[i]), NULL, &rejected);
    /* The low-level full lexer may retain an incomplete backtick token for
     * diagnostics; the strict processor and quote scanner must reject it. */
    size_t quote_after = 0;
    bool complete_backtick = false;
    if (i == 1) {
      const char *open = strchr(escaped_final_quote[i], '`');
      complete_backtick = open && shell_source_skip_complete_backtick(
                                      open, strlen(open), 0, &quote_after);
    }
    completion_valid &=
        process_status == SHELL_PROCESS_EPARSE &&
        (i == 1 ? !complete_backtick : tokenize_status != SHELL_TOKENIZE_OK);
    shell_commands_free(commands, count);
    shell_processed_commands_free(&rejected);
  }
  test("Escaped final quote bytes cannot complete strict shell syntax",
       completion_valid);

  char nested_parameters[6 * (SHELL_MAX_SUBCOMMANDS + 1) + 2];
  size_t parameter_length = 0;
  for (size_t i = 0; i <= SHELL_MAX_SUBCOMMANDS; i++) {
    memcpy(nested_parameters + parameter_length, "${x:-", 5);
    parameter_length += 5;
  }
  nested_parameters[parameter_length++] = 'x';
  for (size_t i = 0; i <= SHELL_MAX_SUBCOMMANDS; i++)
    nested_parameters[parameter_length++] = '}';
  nested_parameters[parameter_length] = '\0';
  size_t parameter_after = 0;
  test("Nested parameter scanner rejects excessive recursion",
       !shell_source_skip_parameter_expansion(
           nested_parameters, parameter_length, 0, &parameter_after));

  char mixed_nesting[8 * (SHELL_MAX_SUBCOMMANDS / 2 + 2) + 2];
  bool mixed_valid = true;
  for (size_t levels = SHELL_MAX_SUBCOMMANDS / 2 - 1;
       levels <= SHELL_MAX_SUBCOMMANDS / 2 + 1; levels += 2) {
    size_t used = 0;
    for (size_t i = 0; i < levels; i++) {
      memcpy(mixed_nesting + used, "${x:-\"", 6);
      used += 6;
    }
    mixed_nesting[used++] = 'x';
    for (size_t i = 0; i < levels; i++) {
      memcpy(mixed_nesting + used, "\"}", 2);
      used += 2;
    }
    mixed_nesting[used] = '\0';
    size_t mixed_after = 0;
    bool accepted = shell_source_skip_parameter_expansion(mixed_nesting, used,
                                                          0, &mixed_after);
    mixed_valid &= levels < SHELL_MAX_SUBCOMMANDS / 2
                       ? accepted && mixed_after == used
                       : !accepted;
  }
  test("Mixed quote and parameter nesting shares one recursion budget",
       mixed_valid);

  static const char *const malformed_parameter_operands[] = {
      "${}",
      "${value",
      "${value:-$'bad}",
      "${value:-\"bad}",
      "${value:-`bad}",
      "${value:-${other:-bad}",
      "${value:-$((1+2)}",
      "${value:-$(printf}",
      "${value:-<(printf}",
  };
  bool malformed_operands_rejected = true;
  for (size_t i = 0; i < sizeof(malformed_parameter_operands) /
                             sizeof(malformed_parameter_operands[0]);
       i++) {
    const char *source = malformed_parameter_operands[i];
    size_t after = 0;
    malformed_operands_rejected &= !shell_source_skip_parameter_expansion(
        source, strlen(source), 0, &after);
  }
  test("Malformed parameter operands fail before exposing nested syntax",
       malformed_operands_rejected);

  static const char *const rejected_decode_paths[] = {
      "$'a'",   "$'\\c'",   "$'\\x'",     "$'\\u'",
      "$'\\q'", "$'\\x41'", "$'\\u00e9'", "$'\\101'",
  };
  bool decoder_failure_atomic = true;
  for (size_t i = 0;
       i < sizeof(rejected_decode_paths) / sizeof(rejected_decode_paths[0]);
       i++) {
    size_t cursor = 0;
    const char *source = rejected_decode_paths[i];
    decoder_failure_atomic &= !shell_source_decode_ansi_c_quote(
        source, strlen(source), &cursor, tokenizer_reject_source_byte, NULL);
  }
  test("ANSI-C decoding stops on caller rejection in every escape family",
       decoder_failure_atomic);

  size_t guard_after = 0, content_start = 0, content_length = 0;
  shell_source_substitution_scan_t guard_scan = {0};
  shell_source_substitution_kind_t guard_kind;
  bool guard_inputs =
      shell_source_skip_pipeline_negator_gap(NULL, 0, 0) == 0 &&
      shell_source_skip_escaped_line_endings(NULL, 0, 0) == 0 &&
      shell_source_skip_escaped_line_endings_backward(NULL, 0, 0) == 0 &&
      shell_source_logical_following(NULL, 0, 0) == 0 &&
      !shell_source_parse_named_fd_redirect(NULL, 0, 0, &guard_after) &&
      !shell_source_arithmetic_content(NULL, 0, 0, &content_start,
                                       &content_length, &guard_after) &&
      shell_source_next_executable_substitution(
          NULL, 0, &guard_scan, &content_start, &guard_after, &guard_kind) ==
          SHELL_SOURCE_SCAN_DONE;
  test("Shared scanners handle empty spans without reading source bytes",
       guard_inputs);

  char deeply_nested[5 * (SHELL_MAX_SUBCOMMANDS + 1) + 2];
  size_t position = 0;
  for (size_t i = 0; i <= SHELL_MAX_SUBCOMMANDS; i++) {
    deeply_nested[position++] = '"';
    deeply_nested[position++] = '$';
    deeply_nested[position++] = '(';
  }
  deeply_nested[position++] = 'x';
  for (size_t i = 0; i <= SHELL_MAX_SUBCOMMANDS; i++) {
    deeply_nested[position++] = ')';
    deeply_nested[position++] = '"';
  }
  deeply_nested[position] = '\0';
  size_t after = 0;
  test("Nested quote/substitution scanner bounds recursion",
       !shell_source_skip_shell_word(deeply_nested, position, 0, &after));
}

static void tokenizer_test_double_quoted_parameter_substitution_scope(void) {
  static const struct {
    const char *source;
    bool executes;
  } cases[] = {
      {"echo \"${x:-'$(printf hi)'}\"", true},
      {"echo \"${x:-$'$(printf hi)'}\"", true},
      {"echo \"${x:-'`printf hi`'}\"", true},
      {"echo \"${x:-'${y:-$(printf hi)}'}\"", true},
      {"echo ${x:-'$(printf hi)'}", false},
      {"echo ${x:-$'$(printf hi)'}", false},
      {"echo \"${x:-'\\$(printf hi)'}\"", false},
      {"echo \"${x:-'<(printf hi)'}\"", false},
      {"echo \"${x/a/'$(printf hi)'}\"", false},
      {"echo \"${x#'$(printf hi)'}\"", false},
      {"echo \"${x:-$'\\\\$(printf hi)'}\"", false},
      {"echo \"${x:-$'\\\\\\$(printf hi)'}\"", true},
      {"echo \"${x:-$'\\`printf hi\\`'}\"", false},
      {"echo \"${x:-$'\\x24'}\"", false},
      {"echo \"${x:-$'\\x3c'}\"", false},
      {"echo \"${x:-$'\\x28'}\"", false},
      {"echo \"${x:-$'\"$(printf hi)\"'}\"", true},
      {"echo \"${x^$(printf hi)}\"", true},
      {"echo \"${x/a/<(printf hi)}\"", true},
      {"echo \"${x:-'a\"b'}\"", false},
      {"echo \"${x:-'\"$(printf hi)'}\"", true},
      {"echo \"${x:-'a}$(printf hi)'}\"", true},
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    size_t length = strlen(source);
    shell_parse_result_t fast = {0};
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t commands = {0};
    shell_netstring_buffer_t types = {0};
    size_t stage_count = 0;
    bool executes = shell_source_word_has_executable_substitution(
        source + strlen("echo "), length - strlen("echo "));
    bool process_substitution =
        strstr(source, "<(printf hi)") != NULL && cases[i].executes;
    bool case_valid =
        executes == cases[i].executes &&
        shell_parse_fast(source, length, NULL, &fast) == SHELL_OK &&
        fast.count == 1 &&
        ((fast.cmds[0].features & SHELL_FEAT_SUBSHELL) != 0) ==
            (cases[i].executes && !process_substitution) &&
        ((fast.cmds[0].features & SHELL_FEAT_PROCESS_SUB) != 0) ==
            process_substitution &&
        shell_process_commands(source, length, NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == 1 &&
        shell_build_anomaly_netseqs_buffer(source, length, NULL, &commands,
                                           &types,
                                           &stage_count) == SHELL_PROCESS_OK &&
        stage_count == (cases[i].executes ? 2u : 1u) &&
        tokenizer_command_netseq_matches(
            source, cases[i].executes ? "6:printf,4:echo," : "4:echo,",
            cases[i].executes ? 2 : 1);
    if (!case_valid)
      fprintf(stderr, "quoted parameter substitution case %zu failed\n", i);
    valid &= case_valid;
    shell_netstring_buffer_free(&commands);
    shell_netstring_buffer_free(&types);
    shell_processed_commands_free(&processed);
  }
  test("Quoted parameter operands preserve executable substitution scope",
       valid);

  const char *malformed = "echo \"${x:-'$(printf hi)}\"";
  shell_processed_commands_t rejected = {0};
  test("Incomplete parameter quote still fails structurally",
       shell_process_commands(malformed, strlen(malformed), NULL, &rejected) ==
               SHELL_PROCESS_EPARSE &&
           rejected.commands == NULL && rejected.command_count == 0);
  shell_processed_commands_free(&rejected);

  static const struct {
    const char *source;
    bool raw_complete;
  } unsupported_ansi[] = {
      {"echo \"${x:-$'\\x24(printf hi)'}\"", false},
      {"echo \"${x:-$'\\044(printf hi)'}\"", false},
      {"echo \"${x:-$'\\u0024(printf hi)'}\"", false},
      {"echo \"${x:-$'\\U00000024(printf hi)'}\"", false},
      {"echo \"${x:-$'\\x5c$(printf hi)'}\"", false},
      {"echo \"${x:-$'\\x60printf hi\\x60'}\"", false},
      {"echo \"${x:-$'$\\x28printf hi)'}\"", false},
      {"echo \"${x:-$'\\x27$(printf hi)'}\"", false},
      {"echo \"${x:-$'\\\\`printf hi`'}\"", false},
      {"echo \"${x:-$'\\\\\\`printf hi`'}\"", false},
      /* These raw children frame completely. Only the semantic boundary
       * rejects the different source produced by decoding their bodies. */
      {"echo \"${x:-$'$(printf\\x20X)'}\"", true},
      {"echo \"${x:-$'$(pr\\x69ntf X)'}\"", true},
      {"echo \"${x:-$'$(printf\\040X)'}\"", true},
      {"echo \"${x:-$'\\\\'$(printf hi)}\"", false},
      {"echo \"${x:-$'\\\"$(printf hi)'}\"", false},
      {"echo \"${x:-$'\\'$(printf hi)'}\"", false},
      {"echo \"${x:-$'\"$(printf hi)'}\"", false},
  };
  bool encoded_rejected = true;
  for (size_t i = 0; i < sizeof(unsupported_ansi) / sizeof(unsupported_ansi[0]);
       i++) {
    shell_processed_commands_t decoded = {0};
    shell_parse_result_t fast = {0};
    shell_command_t *full = NULL;
    size_t full_count = 0;
    shell_netstring_buffer_t raw = {0};
    shell_netstring_buffer_t typed = {0};
    size_t stages = 0;
    const char *source = unsupported_ansi[i].source;
    size_t length = strlen(source);
    shell_error_t fast_status = shell_parse_fast(source, length, NULL, &fast);
    shell_tokenize_status_t full_status =
        shell_tokenize_commands(source, length, &full, &full_count);
    shell_process_status_t process_status =
        shell_process_commands(source, length, NULL, &decoded);
    shell_process_status_t anomaly_status = shell_build_anomaly_netseqs_buffer(
        source, length, NULL, &raw, &typed, &stages);
    /* The full tokenizer is lexical and may preserve an unsupported word or
     * reject its incomplete quote; semantic APIs must reject either way. */
    bool lexical_consistent =
        (full_status == SHELL_TOKENIZE_OK && full != NULL && full_count == 1) ||
        (!unsupported_ansi[i].raw_complete &&
         full_status == SHELL_TOKENIZE_EPARSE && full == NULL &&
         full_count == 0);
    bool case_valid =
        fast_status ==
            (unsupported_ansi[i].raw_complete ? SHELL_OK : SHELL_EPARSE) &&
        fast.count == (unsupported_ansi[i].raw_complete ? 1u : 0u) &&
        lexical_consistent && process_status == SHELL_PROCESS_EPARSE &&
        decoded.commands == NULL && decoded.command_count == 0 &&
        anomaly_status == SHELL_PROCESS_EPARSE && raw.data == NULL &&
        typed.data == NULL && stages == 0;
    if (!case_valid)
      fprintf(stderr,
              "ANSI parameter case %zu: fast=%d full=%d process=%d "
              "anomaly=%d\n",
              i, fast_status, full_status, process_status, anomaly_status);
    encoded_rejected &= case_valid;
    shell_netstring_buffer_free(&raw);
    shell_netstring_buffer_free(&typed);
    shell_commands_free(full, full_count);
    shell_processed_commands_free(&decoded);
  }
  test("ANSI-C encoded syntax and translated child bodies fail closed",
       encoded_rejected);
}

static void tokenizer_test_error_strings(void) {
  static const struct {
    shell_error_t error;
    const char *text;
  } cases[] = {{SHELL_OK, "OK"},
               {SHELL_EINPUT, "Invalid input"},
               {SHELL_ETRUNC, "Truncated (limits exceeded)"},
               {SHELL_EPARSE, "Parse error"},
               {(shell_error_t)1, "Unknown error"}};
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    valid =
        valid && strcmp(shell_error_string(cases[i].error), cases[i].text) == 0;
  test("Fast-parser error strings cover known and unknown values", valid);
}

static void tokenizer_test_composition_metadata(void) {
  shell_command_t *commands = NULL;
  size_t count = 0;
  bool ok = (shell_tokenize_commands("echo ok # | ignored\npwd",
                                     strlen("echo ok # | ignored\npwd"),
                                     &commands, &count) == SHELL_TOKENIZE_OK) &&
            count == 2 && commands[0].token_count >= 2 &&
            commands[0].tokens[0].start[0] == 'e' &&
            commands[0].tokens[1].start[0] == 'o' &&
            commands[1].tokens[0].start[0] == 'p';
  shell_commands_free(commands, count);
  test("Comments hide operators and preserve following command", ok);

  commands = NULL;
  count = 0;
  ok = (shell_tokenize_commands("first & second", strlen("first & second"),
                                &commands, &count) == SHELL_TOKENIZE_OK) &&
       count == 2 && commands[0].has_background &&
       commands[1].tokens[0].type == SHELL_TOKEN_COMMAND;
  shell_commands_free(commands, count);
  test("Background separator is represented without losing commands", ok);

  commands = NULL;
  count = 0;
  ok = (shell_tokenize_commands("(one; two)", strlen("(one; two)"), &commands,
                                &count) == SHELL_TOKENIZE_OK) &&
       count == 2 && commands[0].has_groups && commands[1].has_groups &&
       commands[0].group_depth == 1 && commands[1].group_depth == 1 &&
       commands[0].start_pos == 1 && commands[1].start_pos == 6 &&
       commands[1].end_pos == 9;
  shell_commands_free(commands, count);
  test("Parenthesized groups retain command spans and depth", ok);

  /* A process substitution or arithmetic expansion can be the command word
   * itself. Its terminating newline is therefore the record's separator, not
   * ignorable leading whitespace for a nonexistent following command. */
  static const struct {
    const char *input;
    shell_token_type_t word_type;
  } expansion_commands[] = {
      {"<(id)\n", SHELL_TOKEN_PROCESS_SUB},
      {"$((1))\n", SHELL_TOKEN_ARITHMETIC},
  };
  ok = true;
  for (size_t i = 0;
       i < sizeof(expansion_commands) / sizeof(expansion_commands[0]); i++) {
    commands = NULL;
    count = 0;
    ok = ok &&
         shell_tokenize_commands(expansion_commands[i].input,
                                 strlen(expansion_commands[i].input), &commands,
                                 &count) == SHELL_TOKENIZE_OK &&
         count == 1 && commands[0].token_count == 2 &&
         commands[0].tokens[0].type == expansion_commands[i].word_type &&
         commands[0].tokens[1].type == SHELL_TOKEN_SEMICOLON &&
         commands[0].tokens[1].length == 1 &&
         commands[0].tokens[1].start[0] == '\n';
    shell_commands_free(commands, count);
  }
  test("Expansion-only commands retain their terminating separator", ok);
}

static bool tokenizer_is_cleared_end_token(const shell_token_t *token) {
  return token->type == SHELL_TOKEN_END && token->start == NULL &&
         token->length == 0 && token->position == 0 && !token->is_quoted &&
         !token->is_escaped;
}

typedef struct {
  const char *name;
  const char *input;
  size_t token_count;
  shell_token_type_t types[8];
  const char *texts[8];
  int if_depth;
  int loop_depth;
  int case_depth;
} tokenizer_iterator_case_t;

static void tokenizer_run_iterator_cases(const tokenizer_iterator_case_t *cases,
                                         size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_tokenizer_state_t state;
    shell_tokenizer_init(&state, cases[i].input, strlen(cases[i].input), NULL);
    bool valid = state.input == cases[i].input && state.position == 0 &&
                 state.length == strlen(cases[i].input);
    for (size_t j = 0; j < cases[i].token_count; j++) {
      shell_token_t token;
      bool advanced = shell_tokenizer_next(&state, &token);
      valid = advanced && token.type == cases[i].types[j] &&
              token.start == cases[i].input + token.position &&
              token.length == strlen(cases[i].texts[j]) &&
              strncmp(token.start, cases[i].texts[j], token.length) == 0 &&
              valid;
    }

    shell_token_t end_token;
    memset(&end_token, 0xA5, sizeof(end_token));
    bool exhausted = !shell_tokenizer_next(&state, &end_token);
    size_t final_position = state.position;
    memset(&end_token, 0xA5, sizeof(end_token));
    exhausted = !shell_tokenizer_next(&state, &end_token) && exhausted;
    valid = exhausted && state.position == final_position &&
            state.if_depth == cases[i].if_depth &&
            state.loop_depth == cases[i].loop_depth &&
            state.case_depth == cases[i].case_depth &&
            tokenizer_is_cleared_end_token(&end_token) && valid;
    test(cases[i].name, valid);
  }
}

static void tokenizer_test_iterator_argument_contracts(void) {
  shell_tokenizer_state_t state;
  memset(&state, 0xA5, sizeof(state));
  shell_tokenizer_init(&state, NULL, 0, NULL);
  shell_token_t token;
  memset(&token, 0xA5, sizeof(token));
  bool null_input =
      state.input && state.input[0] == '\0' && state.position == 0 &&
      state.length == 0 && !state.in_quotes && !state.in_subshell &&
      state.quote_char == '\0' && state.paren_depth == 0 &&
      state.brace_depth == 0 && !state.in_arithmetic &&
      state.arith_depth == 0 && state.if_depth == 0 && state.loop_depth == 0 &&
      state.case_depth == 0 && !shell_tokenizer_next(&state, &token) &&
      tokenizer_is_cleared_end_token(&token);

  shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
  size_t command_count = SIZE_MAX;
  shell_tokenize_status_t parse_status = shell_tokenize_commands(
      "'unterminated", strlen("'unterminated"), &commands, &command_count);
  static const char bounded_input[] = {'e', 'c', 'h', 'o'};
  bool bounded_input_ok =
      shell_tokenize_commands(bounded_input, sizeof(bounded_input), &commands,
                              &command_count) == SHELL_TOKENIZE_OK &&
      command_count == 1;
  shell_commands_free(commands, command_count);
  commands = (shell_command_t *)(uintptr_t)1;
  command_count = SIZE_MAX;
  static const char nul_input[] = {'e', 'c', 'h', 'o', '\0', ';', 'i', 'd'};
  bool embedded_nul_rejected =
      shell_tokenize_commands(nul_input, sizeof(nul_input), &commands,
                              &command_count) == SHELL_TOKENIZE_EINPUT &&
      commands == NULL && command_count == 0;
  test("Tokenizer iterator: empty spans, bounded input and parse failures",
       null_input && bounded_input_ok && embedded_nul_rejected &&
           parse_status == SHELL_TOKENIZE_EPARSE && commands == NULL &&
           command_count == 0);
}

typedef struct {
  const char *name;
  const char *input;
  size_t command_count;
} tokenizer_tokenizer_case_t;

static void
tokenizer_run_tokenizer_cases(const tokenizer_tokenizer_case_t *cases,
                              size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    bool parsed =
        (shell_tokenize_commands(cases[i].input, strlen(cases[i].input),
                                 &commands, &command_count) ==
         (cases[i].command_count ? SHELL_TOKENIZE_OK : SHELL_TOKENIZE_BLANK));
    test(cases[i].name, parsed && command_count == cases[i].command_count &&
                            tokenizer_tokens_are_consistent(
                                cases[i].input, commands, command_count));
    shell_commands_free(commands, command_count);
  }
}

static void tokenizer_check_tokenizer_case(const char *name, const char *input,
                                           size_t expected_count) {
  shell_command_t *commands = NULL;
  size_t command_count = 0;
  bool parsed = (shell_tokenize_commands(input, strlen(input), &commands,
                                         &command_count) == SHELL_TOKENIZE_OK);
  bool valid = parsed && command_count == expected_count &&
               tokenizer_tokens_are_consistent(input, commands, command_count);
  if (!valid)
    printf("    commands: got %zu, expected %zu\n", command_count,
           expected_count);
  test(name, valid);
  shell_commands_free(commands, command_count);
}

static void
tokenizer_run_rejected_cases(const tokenizer_tokenizer_case_t *cases,
                             size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_command_t *sentinel = (shell_command_t *)(uintptr_t)1;
    shell_command_t *commands = sentinel;
    size_t command_count = SIZE_MAX;
    bool parsed = (shell_tokenize_commands(
                       cases[i].input, strlen(cases[i].input), &commands,
                       &command_count) == SHELL_TOKENIZE_OK);
    test(cases[i].name, !parsed && commands == NULL &&
                            command_count == cases[i].command_count);
    if (commands && commands != sentinel && command_count < 1024)
      shell_commands_free(commands, command_count);
  }
}

enum {
  tokenizer_EXPECT_VARIABLE = 1u << 0,
  tokenizer_EXPECT_GLOB = 1u << 1,
  tokenizer_EXPECT_SUBSHELL = 1u << 2,
  tokenizer_EXPECT_ARITHMETIC = 1u << 3,
  tokenizer_EXPECT_LOOP = 1u << 4,
  tokenizer_EXPECT_CONDITIONAL = 1u << 5,
  tokenizer_EXPECT_CASE = 1u << 6,
  tokenizer_EXPECT_IF = 1u << 7,
  tokenizer_EXPECT_SHELL_FEATURE =
      tokenizer_EXPECT_VARIABLE | tokenizer_EXPECT_GLOB |
      tokenizer_EXPECT_SUBSHELL | tokenizer_EXPECT_ARITHMETIC,
};

typedef struct {
  tokenizer_tokenizer_case_t tokenizer;
  unsigned features;
} tokenizer_feature_case_t;

static void tokenizer_run_feature_cases(const tokenizer_feature_case_t *cases,
                                        size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    bool parsed = (shell_tokenize_commands(cases[i].tokenizer.input,
                                           strlen(cases[i].tokenizer.input),
                                           &commands, &command_count) ==
                   (cases[i].tokenizer.command_count ? SHELL_TOKENIZE_OK
                                                     : SHELL_TOKENIZE_BLANK));
    unsigned features = 0;
    for (size_t j = 0; j < command_count; j++) {
      unsigned command_features =
          (commands[j].has_variables ? tokenizer_EXPECT_VARIABLE : 0) |
          (commands[j].has_globs ? tokenizer_EXPECT_GLOB : 0) |
          (commands[j].has_subshells ? tokenizer_EXPECT_SUBSHELL : 0) |
          (commands[j].has_arithmetic ? tokenizer_EXPECT_ARITHMETIC : 0) |
          (commands[j].has_loops ? tokenizer_EXPECT_LOOP : 0) |
          (commands[j].has_conditionals ? tokenizer_EXPECT_CONDITIONAL : 0) |
          (commands[j].has_if ? tokenizer_EXPECT_IF : 0) |
          (commands[j].has_case ? tokenizer_EXPECT_CASE : 0);
      features |= command_features;
    }
    bool valid = parsed && command_count == cases[i].tokenizer.command_count &&
                 features == cases[i].features &&
                 tokenizer_tokens_are_consistent(cases[i].tokenizer.input,
                                                 commands, command_count);
    if (!valid)
      printf("    features: count=%zu expected=%zu got=%#x expected=%#x\n",
             command_count, cases[i].tokenizer.command_count, features,
             cases[i].features);
    test(cases[i].tokenizer.name, valid);
    shell_commands_free(commands, command_count);
  }
}

typedef struct {
  tokenizer_tokenizer_case_t tokenizer;
  uint64_t variable_stages;
  uint64_t glob_stages;
  uint64_t subshell_stages;
  uint64_t arithmetic_stages;
} tokenizer_stage_case_t;

static void tokenizer_run_stage_cases(const tokenizer_stage_case_t *cases,
                                      size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    bool parsed =
        (shell_tokenize_commands(cases[i].tokenizer.input,
                                 strlen(cases[i].tokenizer.input), &commands,
                                 &command_count) == SHELL_TOKENIZE_OK);
    uint64_t variables = 0;
    uint64_t globs = 0;
    uint64_t subshells = 0;
    uint64_t arithmetic = 0;
    for (size_t j = 0; j < command_count && j < 64; j++) {
      uint64_t stage = UINT64_C(1) << j;
      variables |= commands[j].has_variables ? stage : 0;
      globs |= commands[j].has_globs ? stage : 0;
      subshells |= commands[j].has_subshells ? stage : 0;
      arithmetic |= commands[j].has_arithmetic ? stage : 0;
    }
    bool valid = parsed && command_count == cases[i].tokenizer.command_count &&
                 command_count <= 64 && variables == cases[i].variable_stages &&
                 globs == cases[i].glob_stages &&
                 subshells == cases[i].subshell_stages &&
                 arithmetic == cases[i].arithmetic_stages &&
                 tokenizer_tokens_are_consistent(cases[i].tokenizer.input,
                                                 commands, command_count);
    if (!valid)
      printf("    stages: count=%zu vars=%#llx globs=%#llx subs=%#llx "
             "arith=%#llx\n",
             command_count, (unsigned long long)variables,
             (unsigned long long)globs, (unsigned long long)subshells,
             (unsigned long long)arithmetic);
    test(cases[i].tokenizer.name, valid);
    shell_commands_free(commands, command_count);
  }
}

enum {
  tokenizer_PROCESS_PIPE_INPUT = 1u << 0,
  tokenizer_PROCESS_PIPE_OUTPUT = 1u << 1,
  tokenizer_PROCESS_REDIRECTION = 1u << 2,
  tokenizer_PROCESS_ERROR_REDIRECTION = 1u << 3,
};

typedef struct {
  const char *name;
  const char *input;
  size_t command_count;
  const char *original_commands[4];
  const char *legacy_renderings[4];
  unsigned flags[4];
  unsigned feature_stages;
} tokenizer_processor_case_t;

static bool
tokenizer_tokens_refer_to_owned_command(const shell_token_t *tokens,
                                        size_t token_count,
                                        const char *original_command) {
  if ((!tokens && token_count != 0) || !original_command)
    return false;
  size_t length = strlen(original_command);
  for (size_t i = 0; i < token_count; i++) {
    if (tokens[i].position > length ||
        tokens[i].length > length - tokens[i].position ||
        tokens[i].start != original_command + tokens[i].position)
      return false;
  }
  return true;
}

static void
tokenizer_run_processor_cases(const tokenizer_processor_case_t *cases,
                              size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_command_info_t *infos = NULL;
    size_t command_count = 0;
    shell_process_status_t process_status = shell_process_command(
        cases[i].input, strlen(cases[i].input), NULL, &infos, &command_count);
    bool has_shell_features = false;
    bool processed =
        process_status ==
        (cases[i].command_count ? SHELL_PROCESS_OK : SHELL_PROCESS_BLANK);
    bool valid = processed && command_count == cases[i].command_count &&
                 (command_count == 0 || infos);
    for (size_t j = 0; infos && j < cases[i].command_count && j < command_count;
         j++) {
      unsigned flags =
          (infos[j].has_pipe_input ? tokenizer_PROCESS_PIPE_INPUT : 0) |
          (infos[j].has_pipe_output ? tokenizer_PROCESS_PIPE_OUTPUT : 0) |
          (infos[j].has_redirections ? tokenizer_PROCESS_REDIRECTION : 0) |
          (infos[j].has_error_redirection ? tokenizer_PROCESS_ERROR_REDIRECTION
                                          : 0);
      bool expected_feature = (cases[i].feature_stages & (1u << j)) != 0;
      shell_netstring_buffer_t netargv = {0};
      bool rendered = shell_render_netargv_buffer(&infos[j], NULL, &netargv) ==
                      SHELL_PROCESS_OK;
      bool stage_valid =
          infos[j].original_command && rendered && netargv.data &&
          strcmp(infos[j].original_command, cases[i].original_commands[j]) ==
              0 &&
          flags == cases[i].flags[j] &&
          tokenizer_tokens_refer_to_owned_command(infos[j].shell_tokens,
                                                  infos[j].shell_token_count,
                                                  infos[j].original_command) &&
          tokenizer_tokens_refer_to_owned_command(infos[j].command_tokens,
                                                  infos[j].command_token_count,
                                                  infos[j].original_command) &&
          shell_command_info_has_dangerous_features(&infos[j]) ==
              expected_feature;
      if (!stage_valid)
        printf("    stage %zu: original='%s' netargv='%.*s' flags=%#x "
               "feature=%d\n",
               j, infos[j].original_command ? infos[j].original_command : "",
               (int)netargv.length,
               netargv.data ? (const char *)netargv.data : "", flags,
               shell_command_info_has_dangerous_features(&infos[j]));
      shell_netstring_buffer_free(&netargv);
      valid = stage_valid && valid;
      has_shell_features |= expected_feature;
    }
    if (!valid)
      printf("    processor: count=%zu expected=%zu features=%d\n",
             command_count, cases[i].command_count, has_shell_features);
    test(cases[i].name, valid);
    shell_command_infos_free(infos, command_count);
  }
}

typedef struct {
  const char *name;
  const char *input;
  size_t command_count;
  const char *transformed_commands[5];
  unsigned transformed_stages;
  const char *original_commands[5];
} tokenizer_transform_line_case_t;

static void
tokenizer_run_transform_line_cases(const tokenizer_transform_line_case_t *cases,
                                   size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_transformed_command_t **commands = NULL;
    size_t command_count = 0;
    bool transformed =
        shell_transform_command_line(cases[i].input, strlen(cases[i].input),
                                     NULL, &commands, &command_count) ==
        (cases[i].command_count ? SHELL_TRANSFORM_OK : SHELL_TRANSFORM_BLANK);
    bool valid = transformed && command_count == cases[i].command_count &&
                 (command_count == 0 || commands != NULL);
    for (size_t j = 0; valid && j < command_count; j++) {
      unsigned transform_mask = cases[i].transformed_stages & UINT16_MAX;
      unsigned shell_only_mask = cases[i].transformed_stages >> 16;
      bool expected_transform = (transform_mask & (1u << j)) != 0;
      bool expected_shell =
          ((transform_mask | shell_only_mask) & (1u << j)) != 0;
      const char *expected_original = cases[i].original_commands[j];
      if (!expected_original && command_count == 1)
        expected_original = cases[i].input;
      valid = commands[j] && commands[j]->original_command &&
              commands[j]->display_text && expected_original &&
              strcmp(commands[j]->original_command, expected_original) == 0 &&
              strcmp(commands[j]->display_text,
                     cases[i].transformed_commands[j]) == 0 &&
              commands[j]->has_transformations == expected_transform &&
              commands[j]->has_shell_syntax == expected_shell;
      if (!valid && commands[j])
        fprintf(stderr,
                "    stage %zu: original=[%s] display=[%s] "
                "transformed=%d syntax=%d\n",
                j, commands[j]->original_command, commands[j]->display_text,
                commands[j]->has_transformations,
                commands[j]->has_shell_syntax);
    }
    if (!valid)
      printf("    transform line: count=%zu expected=%zu\n", command_count,
             cases[i].command_count);
    test(cases[i].name, valid);
    shell_transformed_command_list_free(commands, command_count);
  }
}

static void tokenizer_test_transform_allocation_failures(void) {
  static const char input[] =
      "echo prefix$USER-suffix \"literal\"${NAME}\\\n-tail a b c d e f g h "
      "i j k l m n o p \"$OUTER$(printf '\"$INNER')$AFTER\" "
      "\"$OUTER`printf '$INNER'`$AFTER\" "
      "$OUTER<(printf '$INNER')$AFTER | grep '*.txt'";
  shell_transformed_command_t **commands = NULL;
  size_t count = 0;
  shellsplit_test_alloc_reset();
  shell_transform_status_t status = shell_transform_command_line(
      input, strlen(input), NULL, &commands, &count);
  size_t allocations = shellsplit_test_alloc_count();
  test("Transform allocation probe succeeds",
       status == SHELL_TRANSFORM_OK && count == 2 && allocations > 5);
  shell_transformed_command_list_free(commands, count);

  bool atomic = true;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    commands = (shell_transformed_command_t **)(void *)1;
    count = SIZE_MAX;
    shellsplit_test_alloc_fail_at(fail_at);
    status = shell_transform_command_line(input, strlen(input), NULL, &commands,
                                          &count);
    shellsplit_test_alloc_reset();
    if (status != SHELL_TRANSFORM_ENOMEM || commands != NULL || count != 0) {
      atomic = false;
      shell_transformed_command_list_free(commands, count);
      break;
    }
  }
  test("Transform allocation failures report ENOMEM and clear outputs", atomic);
}

static void tokenizer_test_output_limit_boundaries(void) {
  static const char input[] = "echo one日本 ; printf two\x80\xff";
  shell_command_info_t *infos = NULL;
  size_t count = 0;
  shell_process_status_t process_status =
      shell_process_command(input, strlen(input), NULL, &infos, &count);
  size_t process_max = 0;
  size_t process_total = 0;
  for (size_t i = 0; process_status == SHELL_PROCESS_OK && i < count; i++) {
    size_t original = strlen(infos[i].original_command);
    if (original > process_max)
      process_max = original;
    process_total += original;
  }
  shell_command_infos_free(infos, count);

  shell_process_limits_t process_limits = {process_max, process_total, 0};
  infos = NULL;
  count = 0;
  bool process_valid =
      process_status == SHELL_PROCESS_OK &&
      shell_process_command(input, strlen(input), &process_limits, &infos,
                            &count) == SHELL_PROCESS_OK;
  shell_command_infos_free(infos, count);
  process_limits.max_string_bytes--;
  infos = (shell_command_info_t *)(uintptr_t)1;
  count = SIZE_MAX;
  process_valid =
      process_valid &&
      shell_process_command(input, strlen(input), &process_limits, &infos,
                            &count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
      infos == NULL && count == 0;
  process_limits.max_string_bytes = process_max;
  process_limits.max_total_bytes--;
  infos = (shell_command_info_t *)(uintptr_t)1;
  count = SIZE_MAX;
  process_valid =
      process_valid &&
      shell_process_command(input, strlen(input), &process_limits, &infos,
                            &count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
      infos == NULL && count == 0;
  test("Processor output limits accept exact bounds and reject overflow",
       process_valid);

  static const char structural_group_redirect[] =
      "{ echo ok; } >/tmp/shellsplit-group-owned-redirect-that-is-not-a-"
      "returned-flat-record";
  const shell_process_limits_t returned_only_limit = {
      .max_string_bytes = 32,
      .max_total_bytes = 32,
  };
  infos = NULL;
  count = 0;
  bool group_flat_limit_valid =
      shell_process_command(
          structural_group_redirect, sizeof(structural_group_redirect) - 1,
          &returned_only_limit, &infos, &count) == SHELL_PROCESS_OK &&
      infos != NULL && count == 1 &&
      strcmp(infos[0].original_command, "echo ok") == 0;
  shell_command_infos_free(infos, count);

  static const char long_independent_redirect[] =
      "{ echo ok; } >/tmp/group-owned; >/tmp/shellsplit-returned-redirect-"
      "operand-that-exceeds-the-flat-record-limit";
  infos = (shell_command_info_t *)(uintptr_t)1;
  count = SIZE_MAX;
  group_flat_limit_valid =
      group_flat_limit_valid &&
      shell_process_command(long_independent_redirect,
                            sizeof(long_independent_redirect) - 1,
                            &returned_only_limit, &infos,
                            &count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
      infos == NULL && count == 0;

  static const char group_then_redirect[] =
      "{ echo ok; } >/tmp/group-owned; >/tmp/independent";
  const shell_process_limits_t aggregate_flat_limit = {
      .max_string_bytes = SIZE_MAX,
      .max_total_bytes = strlen("echo ok") + strlen(">/tmp/independent") - 1,
  };
  infos = (shell_command_info_t *)(uintptr_t)1;
  count = SIZE_MAX;
  group_flat_limit_valid =
      group_flat_limit_valid &&
      shell_process_command(group_then_redirect,
                            sizeof(group_then_redirect) - 1,
                            &aggregate_flat_limit, &infos,
                            &count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
      infos == NULL && count == 0;
  test("Processor flat limits cover merged group records",
       group_flat_limit_valid);

  shell_transformed_command_t **commands = NULL;
  size_t transformed_count = 0;
  shell_transform_status_t transform_status = shell_transform_command_line(
      input, strlen(input), NULL, &commands, &transformed_count);
  size_t transform_max = 0;
  size_t transform_total = 0;
  for (size_t i = 0;
       transform_status == SHELL_TRANSFORM_OK && i < transformed_count; i++) {
    size_t lengths[2] = {strlen(commands[i]->original_command),
                         strlen(commands[i]->display_text)};
    for (size_t j = 0; j < 2; j++) {
      if (lengths[j] > transform_max)
        transform_max = lengths[j];
      transform_total += lengths[j];
    }
    for (size_t j = 0; j < commands[i]->token_count; j++) {
      size_t original = strlen(commands[i]->tokens[j].original);
      size_t transformed = strlen(commands[i]->tokens[j].transformed);
      if (original > transform_max)
        transform_max = original;
      if (transformed > transform_max)
        transform_max = transformed;
      transform_total += original + transformed;
    }
  }
  shell_transformed_command_list_free(commands, transformed_count);

  shell_transform_limits_t transform_limits = {transform_max, transform_total};
  commands = NULL;
  transformed_count = 0;
  bool transform_valid = transform_status == SHELL_TRANSFORM_OK &&
                         shell_transform_command_line(
                             input, strlen(input), &transform_limits, &commands,
                             &transformed_count) == SHELL_TRANSFORM_OK;
  shell_transformed_command_list_free(commands, transformed_count);
  transform_limits.max_string_bytes--;
  commands = (shell_transformed_command_t **)(uintptr_t)1;
  transformed_count = SIZE_MAX;
  transform_valid = transform_valid &&
                    shell_transform_command_line(
                        input, strlen(input), &transform_limits, &commands,
                        &transformed_count) == SHELL_TRANSFORM_EOUTPUT_LIMIT &&
                    commands == NULL && transformed_count == 0;
  transform_limits.max_string_bytes = transform_max;
  transform_limits.max_total_bytes--;
  commands = (shell_transformed_command_t **)(uintptr_t)1;
  transformed_count = SIZE_MAX;
  transform_valid = transform_valid &&
                    shell_transform_command_line(
                        input, strlen(input), &transform_limits, &commands,
                        &transformed_count) == SHELL_TRANSFORM_EOUTPUT_LIMIT &&
                    commands == NULL && transformed_count == 0;
  shell_transform_limits_t token_limit = {
      .max_string_bytes = 12,
      .max_total_bytes = SIZE_MAX,
  };
  commands = (shell_transformed_command_t **)(uintptr_t)1;
  transformed_count = SIZE_MAX;
  transform_valid =
      transform_valid &&
      shell_transform_command_line(
          "echo $VERY_LONG_VARIABLE_NAME",
          strlen("echo $VERY_LONG_VARIABLE_NAME"), &token_limit, &commands,
          &transformed_count) == SHELL_TRANSFORM_EOUTPUT_LIMIT &&
      commands == NULL && transformed_count == 0;
  test("Transform output limits enforce exact call-wide aggregate bounds",
       transform_valid);
}

/* Canonical buffers are length-delimited, but every legacy C-string adapter
 * needs one additional byte. Keep this arithmetic in a shared helper and
 * exercise its exact boundary without constructing an impossible input-sized
 * shell command. */
static void tokenizer_test_cstring_allocation_size_boundaries(void) {
  size_t allocation_size = SIZE_MAX;
  bool valid =
      shell_process_cstring_allocation_size(0, &allocation_size) ==
          SHELL_PROCESS_OK &&
      allocation_size == 1 &&
      shell_process_cstring_allocation_size(SIZE_MAX - 1, &allocation_size) ==
          SHELL_PROCESS_OK &&
      allocation_size == SIZE_MAX &&
      shell_process_cstring_allocation_size(SIZE_MAX, &allocation_size) ==
          SHELL_PROCESS_EOVERFLOW &&
      allocation_size == 0;
  test("Legacy canonical outputs reject a wrapping terminator allocation",
       valid);
}

static void tokenizer_test_canonical_control_compounds_rejected(void) {
  static const char *const diagnostic_cases[] = {
      "for ((i=0; i<3; i++)); do echo \"$i\"; done\n",
      "echo before; for ((i=0; i<3; i++)); do echo inside; done; echo after | "
      "cat",
  };
  bool diagnostic_valid = true;
  for (size_t i = 0; i < sizeof(diagnostic_cases) / sizeof(diagnostic_cases[0]);
       i++) {
    const char *source = diagnostic_cases[i];
    shell_command_t *commands = NULL;
    size_t count = 0;
    if (shell_tokenize_commands(source, strlen(source), &commands, &count) !=
        SHELL_TOKENIZE_OK) {
      diagnostic_valid = false;
      continue;
    }
    const char *for_word = strstr(source, "for ((");
    bool retained_for = false;
    for (size_t command = 0; command < count; command++) {
      for (size_t index = 0; index < commands[command].token_count; index++) {
        const shell_token_t *token = &commands[command].tokens[index];
        retained_for =
            retained_for || (token->start == for_word && token->length == 3);
        diagnostic_valid =
            diagnostic_valid &&
            token->position >= commands[command].start_pos &&
            token->position <= commands[command].end_pos &&
            token->length <= commands[command].end_pos - token->position;
      }
    }
    diagnostic_valid = diagnostic_valid && retained_for;
    shell_commands_free(commands, count);
  }
  test("Unsupported nested parentheses cannot discard an ordinary prefix word",
       diagnostic_valid);
  static const char *const cases[] = {
      "for ((i = 0; i < 2; i++)); do echo \"$i\"; done",
      "for value in one two; do echo \"$value\"; done",
      "while read line; do echo \"$line\"; done",
      "until test -f file; do sleep 1; done",
      "case value in value) echo yes;; esac",
      "function example { echo yes; }",
      "example() { echo yes; }",
      "example() ( echo yes )",
      "example () { echo yes; }",
      "example ( ) { echo yes; }",
      "example\t(\t) ( echo yes )",
      "example\\\n() { echo yes; }",
      "function example () { echo yes; }",
      "function example ( ) ( echo yes )",
      "cat <(while read line; do echo $line; done)",
      "echo prefix; do echo invalid; done",
      "whi\\\nle true; d\\\no :; do\\\nne",
      "unti\\\nl false; d\\\no :; do\\\nne",
      "f\\\nor item in one; d\\\no :; do\\\nne",
      "sele\\\nct item in one; d\\\no :; do\\\nne",
      "ca\\\nse item i\\\nn item) :;; esa\\\nc",
      "cop\\\nroc :",
      "fun\\\nction example { :; }",
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_command_info_t *infos = (shell_command_info_t *)(uintptr_t)1;
    size_t info_count = SIZE_MAX;
    shell_processed_commands_t processed = {
        .commands = (shell_command_info_t *)(uintptr_t)1,
        .command_count = SIZE_MAX,
        .groups = (shell_group_t *)(uintptr_t)1,
        .group_count = SIZE_MAX,
        .group_io_ops = (shell_group_io_op_t *)(uintptr_t)1,
        .group_io_op_count = SIZE_MAX,
    };
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t command_netseq = {0};
    shell_netstring_buffer_t type_netseq = {0};
    shell_netstring_buffer_t paired_command = {0};
    shell_netstring_buffer_t paired_type = {0};
    size_t count = SIZE_MAX;
    bool features = true;
    size_t length = strlen(cases[i]);
    valid =
        valid &&
        shell_process_command(cases[i], length, NULL, &infos, &info_count) ==
            SHELL_PROCESS_EPARSE &&
        infos == NULL && info_count == 0 &&
        shell_process_commands(cases[i], length, NULL, &processed) ==
            SHELL_PROCESS_EPARSE &&
        processed.commands == NULL && processed.command_count == 0 &&
        processed.groups == NULL && processed.group_count == 0 &&
        processed.group_io_ops == NULL && processed.group_io_op_count == 0 &&
        shell_build_netargv_sequence_buffer(cases[i], length, NULL, &netargv,
                                            &count, &features) ==
            SHELL_PROCESS_EPARSE &&
        netargv.data == NULL && count == 0 && !features &&
        shell_build_command_netseq_buffer(cases[i], length, NULL,
                                          &command_netseq,
                                          &count) == SHELL_PROCESS_EPARSE &&
        command_netseq.data == NULL && count == 0 &&
        shell_build_type_netseq_buffer(cases[i], length, NULL, &type_netseq,
                                       &count) == SHELL_PROCESS_EPARSE &&
        type_netseq.data == NULL && count == 0 &&
        shell_build_anomaly_netseqs_buffer(cases[i], length, NULL,
                                           &paired_command, &paired_type,
                                           &count) == SHELL_PROCESS_EPARSE &&
        paired_command.data == NULL && paired_type.data == NULL && count == 0;
  }
  test("Canonical APIs reject unsupported control compounds", valid);

  /* A well-formed `if` is supported: the canonical APIs return its commands,
   * without the keywords, and its group. */
  static const char *const if_sources[] = {
      "if test -f file; then echo yes; else echo no; fi",
      "{ if test -f file; then echo yes; fi; }",
      "echo $(if test -f file; then echo yes; fi)",
      "i\\\nf true; th\\\nen :; el\\\nse :; f\\\ni",
  };
  bool if_valid = true;
  for (size_t i = 0; i < sizeof(if_sources) / sizeof(if_sources[0]); i++) {
    shell_processed_commands_t processed = {0};
    shell_process_status_t error = shell_process_commands(
        if_sources[i], strlen(if_sources[i]), NULL, &processed);
    bool has_group = false;
    for (size_t g = 0; g < processed.group_count; g++)
      has_group = has_group || processed.groups[g].kind == SHELL_GROUP_IF;
    bool accepted = error == SHELL_PROCESS_OK && processed.command_count >= 1 &&
                    (has_group || i == 2);
    for (size_t c = 0; accepted && c < processed.command_count; c++) {
      const shell_command_info_t *info = &processed.commands[c];
      if (info->command_token_count == 0)
        continue;
      const shell_token_t *first = &info->command_tokens[0];
      accepted = !(first->length == 2 && !strncmp(first->start, "if", 2)) &&
                 !(first->length == 4 && !strncmp(first->start, "then", 4)) &&
                 !(first->length == 2 && !strncmp(first->start, "fi", 2));
    }
    if_valid = if_valid && accepted;
    shell_processed_commands_free(&processed);
  }
  test("Canonical APIs accept a well-formed if without its keywords", if_valid);
}

static void tokenizer_test_control_word_literals_are_accepted(void) {
  static const char *const cases[] = {
      "echo if then elif else fi while until for do done case in esac function",
      "echo 'if' \"while\" \\for",
      "# if true; then\nprintf case",
      "command if then",
      "NAME=value printf until",
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t netargv = {0};
    size_t count = 0;
    bool features = false;
    size_t length = strlen(cases[i]);
    valid = valid &&
            shell_process_commands(cases[i], length, NULL, &processed) ==
                SHELL_PROCESS_OK &&
            processed.command_count == 1 &&
            shell_build_netargv_sequence_buffer(cases[i], length, NULL,
                                                &netargv, &count, &features) ==
                SHELL_PROCESS_OK &&
            count == 1 && netargv.data != NULL;
    shell_netstring_buffer_free(&netargv);
    shell_processed_commands_free(&processed);
  }
  test("Canonical APIs keep non-structural control words as literals", valid);
}

static void tokenizer_test_structured_processor_requires_complete_syntax(void) {
  const char *input = "echo `unterminated";
  shell_command_info_t *flat = NULL;
  size_t flat_count = 0;
  shell_netstring_buffer_t netargv = {0};
  shell_processed_commands_t structured = {
      .commands = (shell_command_info_t *)(uintptr_t)1,
      .command_count = SIZE_MAX,
      .groups = (shell_group_t *)(uintptr_t)1,
      .group_count = SIZE_MAX,
      .group_io_ops = (shell_group_io_op_t *)(uintptr_t)1,
      .group_io_op_count = SIZE_MAX,
  };
  bool valid =
      shell_process_command(input, strlen(input), NULL, &flat, &flat_count) ==
          SHELL_PROCESS_OK &&
      flat != NULL && flat_count == 1 &&
      shell_render_netargv_buffer(&flat[0], NULL, &netargv) ==
          SHELL_PROCESS_OK &&
      netargv.data != NULL &&
      (netargv.length != sizeof("4:echo,13:`unterminated,") - 1 ||
       memcmp(netargv.data, "4:echo,13:`unterminated,", netargv.length)) == 0 &&
      shell_process_commands(input, strlen(input), NULL, &structured) ==
          SHELL_PROCESS_EPARSE &&
      structured.commands == NULL && structured.command_count == 0 &&
      structured.groups == NULL && structured.group_count == 0 &&
      structured.group_io_ops == NULL && structured.group_io_op_count == 0;
  shell_command_infos_free(flat, flat_count);
  shell_netstring_buffer_free(&netargv);
  test("Structured processing rejects incomplete lexical records", valid);
}

static void tokenizer_test_tolerant_unfinished_group_omits_empty_command(void) {
  const char *input = "one && (";
  shell_command_t *commands = NULL;
  size_t command_count = 0;
  shell_tokenize_status_t status =
      shell_tokenize_commands(input, strlen(input), &commands, &command_count);
  bool valid =
      status == SHELL_TOKENIZE_OK && commands != NULL && command_count == 1;
  for (size_t i = 0; valid && i < command_count; i++)
    valid = commands[i].tokens != NULL && commands[i].token_count != 0 &&
            commands[i].start_pos < commands[i].end_pos;
  shell_commands_free(commands, command_count);
  test("Tolerant unfinished groups do not produce empty commands", valid);
}

/* Blank source is valid but has no command: every command-line API reports
 * BLANK rather than success with nothing, or a parse error. Zero-length
 * input stays invalid input where the strict parser defines it so. */
static void tokenizer_test_blank_source_convention(void) {
  static const char *const blank[] = {
      " \t\n",
      "# comment",
      "# <(printf data)\n",
      "\\\n",
      "\\\n # continued empty source\n \\\n",
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(blank) / sizeof(blank[0]); i++) {
    const char *source = blank[i];
    size_t length = strlen(source);

    shell_transformed_command_t **transformed =
        (shell_transformed_command_t **)(uintptr_t)1;
    size_t transformed_count = SIZE_MAX;
    valid = shell_transform_command_line(source, length, NULL, &transformed,
                                         &transformed_count) ==
                SHELL_TRANSFORM_BLANK &&
            transformed == NULL && transformed_count == 0;

    shell_abstract_command_t *abstract =
        (shell_abstract_command_t *)(uintptr_t)1;
    valid = valid &&
            shell_abstract_command_parse(source, length, &abstract) ==
                SHELL_ABSTRACT_BLANK &&
            abstract == NULL;

    shell_netstring_buffer_t argv = {0}, command = {0}, type = {0},
                             anomaly_command = {0}, anomaly_type = {0};
    size_t count = SIZE_MAX;
    bool features = true;
    valid =
        valid &&
        shell_build_netargv_sequence_buffer(source, length, NULL, &argv, &count,
                                            &features) == SHELL_PROCESS_BLANK &&
        argv.data == NULL && argv.length == 0 && count == 0 && !features &&
        shell_build_command_netseq_buffer(source, length, NULL, &command,
                                          &count) == SHELL_PROCESS_BLANK &&
        command.data == NULL && command.length == 0 && count == 0 &&
        shell_build_type_netseq_buffer(source, length, NULL, &type, &count) ==
            SHELL_PROCESS_BLANK &&
        type.data == NULL && type.length == 0 && count == 0 &&
        shell_build_anomaly_netseqs_buffer(source, length, NULL,
                                           &anomaly_command, &anomaly_type,
                                           &count) == SHELL_PROCESS_BLANK &&
        anomaly_command.data == NULL && anomaly_type.data == NULL && count == 0;
  }
  test("Blank source is reported as BLANK by every command-line API", valid);
}

/* An unmatched `(` leaves no lexical command record, yet it is incomplete
 * syntax, not blank source. The tokenizer, the flat processor and the
 * canonical sequence builder all reject it. */
static void tokenizer_test_record_less_syntax_is_not_blank(void) {
  static const char *const cases[] = {"(", "( ", "((", ")", "(!", "( !"};
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    size_t length = strlen(cases[i]);
    shell_command_info_t *infos = (shell_command_info_t *)(uintptr_t)1;
    size_t count = SIZE_MAX;
    shell_netstring_buffer_t argv = {0};
    size_t argv_count = SIZE_MAX;
    bool features = true;
    shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
    size_t command_count = SIZE_MAX;
    /* The diagnostic tokenizer reads `((` as an arithmetic command and
     * keeps it as a record. */
    valid =
        (strcmp(cases[i], "((") == 0 ||
         (shell_tokenize_commands(cases[i], length, &commands,
                                  &command_count) == SHELL_TOKENIZE_EPARSE &&
          commands == NULL && command_count == 0)) &&
        shell_process_command(cases[i], length, NULL, &infos, &count) ==
            SHELL_PROCESS_EPARSE &&
        infos == NULL && count == 0 &&
        shell_build_netargv_sequence_buffer(cases[i], length, NULL, &argv,
                                            &argv_count, &features) ==
            SHELL_PROCESS_EPARSE &&
        argv.data == NULL;
  }
  test("Record-less incomplete syntax is a parse error, not blank", valid);
}

static void tokenizer_test_posix_brace_group_forms(void) {
  static const struct {
    const char *input;
    size_t command_count;
    uint8_t group_kinds;
  } valid_cases[] = {
      {"{ echo;}", 1, SHELL_GROUP_BRACE},
      {"{( echo )}", 1, SHELL_GROUP_BRACE | SHELL_GROUP_SUBSHELL},
      {"{ printf '%s\\n' \"$(date)\" \"${value}\" \"$((1 + 2))\" `date`; }", 1,
       SHELL_GROUP_BRACE},
      {"{ echo first; # } is a comment\n echo second; }", 2, SHELL_GROUP_BRACE},
      {"{ cat <<EOF\n}\nEOF\necho done; }", 2, SHELL_GROUP_BRACE},
      {"{ cat <<\"A B\"; printf after; }\nbody\nA B\n", 2, SHELL_GROUP_BRACE},
      {"{ cat <<<value; printf after; }", 2, SHELL_GROUP_BRACE},
      {"echo { literal }", 1, SHELL_GROUP_NONE},
      {"echo }", 1, SHELL_GROUP_NONE},
      {"( echo '}' )", 1, SHELL_GROUP_SUBSHELL},
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(valid_cases) / sizeof(valid_cases[0]); i++) {
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    valid = valid &&
            shell_tokenize_commands(valid_cases[i].input,
                                    strlen(valid_cases[i].input), &commands,
                                    &command_count) == SHELL_TOKENIZE_OK &&
            command_count == valid_cases[i].command_count &&
            commands[0].group_kinds == valid_cases[i].group_kinds;
    shell_commands_free(commands, command_count);
  }
  test("POSIX brace groups accept compact, nested, and literal forms", valid);

  static const char *const invalid_cases[] = {
      "{ echo }",
      "{ echo;",
      "{ ( echo; } )",
      "{ echo; } echo next",
      "( echo; ) 'next'",
      "{ echo; } >",
      "{ echo; } > && echo next",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(invalid_cases) / sizeof(invalid_cases[0]);
       i++) {
    shell_netstring_buffer_t sequence = {0};
    size_t count = 0;
    bool features = false;
    shell_parse_result_t parsed = {0};
    shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
    size_t command_count = SIZE_MAX;
    valid = valid &&
            shell_tokenize_commands(invalid_cases[i], strlen(invalid_cases[i]),
                                    &commands,
                                    &command_count) == SHELL_TOKENIZE_EPARSE &&
            commands == NULL && command_count == 0 &&
            shell_build_netargv_sequence_buffer(
                invalid_cases[i], strlen(invalid_cases[i]), NULL, &sequence,
                &count, &features) == SHELL_PROCESS_EPARSE &&
            sequence.data == NULL && count == 0 && !features &&
            shell_parse_fast(invalid_cases[i], strlen(invalid_cases[i]), NULL,
                             &parsed) == SHELL_EPARSE;
  }
  test("Canonical processing rejects invalid brace-group terminators", valid);

  static const char *const mismatched_closers[] = {
      "( echo; } )",
      "{ echo; ) }",
  };
  valid = true;
  for (size_t i = 0;
       i < sizeof(mismatched_closers) / sizeof(mismatched_closers[0]); i++) {
    shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
    size_t command_count = SIZE_MAX;
    valid = valid &&
            shell_tokenize_commands(mismatched_closers[i],
                                    strlen(mismatched_closers[i]), &commands,
                                    &command_count) == SHELL_TOKENIZE_EPARSE &&
            commands == NULL && command_count == 0;
  }
  test("Full tokenizer rejects mismatched reserved group closers", valid);

  const char *redirected = "{ echo; } > /tmp/group.out";
  shell_netstring_buffer_t sequence = {0};
  size_t count = 0;
  bool features = false;
  shell_process_status_t status = shell_build_netargv_sequence_buffer(
      redirected, strlen(redirected), NULL, &sequence, &count, &features);
  test("Group trailing redirects do not create empty netargv commands",
       status == SHELL_PROCESS_OK && count == 1 && sequence.data != NULL &&
           (sequence.length != sizeof("7:4:echo,,") - 1 ||
            memcmp(sequence.data, "7:4:echo,,", sequence.length)) == 0);
  shell_netstring_buffer_free(&sequence);

  shell_command_info_t *infos = NULL;
  count = 0;
  status = shell_process_command(redirected, strlen(redirected), NULL, &infos,
                                 &count);
  test("Processed command metadata omits group redirect operands",
       status == SHELL_PROCESS_OK && count == 1 && infos != NULL &&
           infos[0].command_token_count == 1 && infos[0].has_redirections);
  shell_command_infos_free(infos, count);

  shell_processed_commands_t processed = {0};
  status = shell_process_commands("{( echo )}", strlen("{( echo )}"), NULL,
                                  &processed);
  test("Canonical processed output retains group descriptors",
       status == SHELL_PROCESS_OK && processed.command_count == 1 &&
           processed.group_count == 2 &&
           processed.groups[0].kind == SHELL_GROUP_BRACE &&
           processed.groups[1].kind == SHELL_GROUP_SUBSHELL &&
           processed.groups[1].parent == 0);
  shell_processed_commands_free(&processed);
}

static void tokenizer_test_brace_group_process_substitution_contract(void) {
  static const struct {
    const char *input;
    size_t command_count;
    size_t first_word_count;
    bool has_redirection;
    bool process_is_word;
  } cases[] = {
      {"{ cat <(printf config); } | sort", 2, 2, false, true},
      {"{ cat < <(printf config); } | sort", 2, 1, true, false},
      {"{ printf value 3> >(cat); }", 1, 2, true, false},
      {"{ printf value; } > >(cat)", 1, 2, true, false},
      {"{ printf value >&3; } 3> >(cat)", 1, 2, true, false},
      {"{ printf value >&3; } 3> >(printf one; cat)", 1, 2, true, false},
      {"{ cat; } < <(printf config)", 1, 1, true, false},
  };

  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t netargv = {0};
    size_t netargv_count = 0;
    bool features = false;
    shell_process_status_t info_status = shell_process_command(
        cases[i].input, strlen(cases[i].input), NULL, &infos, &info_count);
    shell_process_status_t processed_status = shell_process_commands(
        cases[i].input, strlen(cases[i].input), NULL, &processed);
    shell_process_status_t netargv_status = shell_build_netargv_sequence_buffer(
        cases[i].input, strlen(cases[i].input), NULL, &netargv, &netargv_count,
        &features);
    bool saw_process_word = false;
    for (size_t token = 0;
         infos && token < infos[0].command_token_count && !saw_process_word;
         token++)
      saw_process_word =
          infos[0].command_tokens[token].type == SHELL_TOKEN_PROCESS_SUB;
    valid = valid && info_status == SHELL_PROCESS_OK &&
            processed_status == SHELL_PROCESS_OK &&
            netargv_status == SHELL_PROCESS_OK && infos != NULL &&
            info_count == cases[i].command_count &&
            processed.command_count == cases[i].command_count &&
            processed.group_count == 1 && netargv.data != NULL &&
            netargv_count == cases[i].command_count && features &&
            infos[0].command_token_count == cases[i].first_word_count &&
            infos[0].has_redirections == cases[i].has_redirection &&
            saw_process_word == cases[i].process_is_word &&
            shell_command_info_has_dangerous_features(&infos[0]);
    shell_netstring_buffer_free(&netargv);
    shell_processed_commands_free(&processed);
    shell_command_infos_free(infos, info_count);
  }
  test("Brace process substitutions retain their canonical role", valid);
}

static void tokenizer_test_brace_group_heredoc_sequence_contract(void) {
  static const struct {
    const char *input;
    size_t command_count;
  } cases[] = {
      {"{ cat; cat; } <<EOF | sort\nbody\nEOF", 3},
      {"{ cat; cat; } <<A <<-'B'\none\nA\n\ttwo\n\tB\n", 2},
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {0};
    valid = valid &&
            shell_tokenize_commands(cases[i].input, strlen(cases[i].input),
                                    &commands,
                                    &command_count) == SHELL_TOKENIZE_OK &&
            command_count == cases[i].command_count &&
            shell_process_commands(cases[i].input, strlen(cases[i].input), NULL,
                                   &processed) == SHELL_PROCESS_OK &&
            processed.command_count == cases[i].command_count;
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
  }

  static const char *const body_data_cases[] = {
      "{ cat <<EOF\n}\nEOF\necho done; }",
      "{ cat <<\"A B\"; printf done; }\nbody\nA B\n",
      "{ cat <<A <<-'B'; printf done; }\none\nA\n\ttwo\n\tB\n",
      "{ cat <<'EOF'\n$( { id; } )\nEOF\necho done; }",
      ("{ cat <<E'OF' <<-\\D'ONE'\n}\nEOF\n\t$( { id; } )\n\tDONE\n"
       "echo done; }"),
  };
  for (size_t i = 0;
       valid && i < sizeof(body_data_cases) / sizeof(body_data_cases[0]); i++) {
    const char *input = body_data_cases[i];
    size_t length = strlen(input);
    shell_parse_result_t fast = {0};
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
    shell_dep_error_t error =
        shell_dep_graph_parse(input, length, ".", &limits, &graph);
    valid = shell_parse_fast(input, length, NULL, &fast) == SHELL_OK &&
            fast.group_count == 1 && fast.groups[0].start == 0 &&
            fast.groups[0].end > fast.groups[0].start &&
            fast.groups[0].end <= length &&
            shell_process_commands(input, length, NULL, &processed) ==
                SHELL_PROCESS_OK &&
            processed.command_count == 2 && error == SHELL_DEP_OK &&
            shell_dep_graph_validate(&graph).valid && graph.node_count > 0 &&
            graph.nodes[0].type == SHELL_NODE_GROUP &&
            graph.nodes[0].group.start == input &&
            graph.nodes[0].group.length ==
                fast.groups[0].end - fast.groups[0].start;
    shell_processed_commands_free(&processed);
  }
  test("Brace heredoc bodies never become processed commands", valid);
}

static void tokenizer_test_brace_group_grammar_matrix(void) {
  static const struct {
    const char *input;
    size_t command_count;
    uint32_t group_count;
  } valid_cases[] = {
      {"! ! true", 1, 0},
      {"! ! ! true", 1, 0},
      {"! { false; }", 1, 1},
      {"a && ! b", 2, 0},
      {"a & ! b", 2, 0},
      {"{\n echo one\n}", 1, 1},
      {"{ \r\n  echo one\r\n}", 2, 1},
      {"{ echo one; } && { cat; }", 2, 2},
      {"cat /tmp/in | { printf '%s\\n' \"$value\"; } > /tmp/out", 2, 1},
      {"{ echo \"}\"; # } remains text\n printf two; }", 2, 1},
      {"{ cat <<'EOF'\n}\nEOF\nprintf done; }", 2, 1},
      {"( { cat <<EOF\n$(id)\nEOF\n})", 1, 2},
      {"{ ( echo one; ); } 3> /tmp/trace 2>> /tmp/err", 1, 2},
      {"{ echo one; } & { cat; }", 2, 2},
      {"{ printf left; } 3>/tmp/left | { cat; } 2>>/tmp/right && "
       "{ printf tail; }",
       3, 3},
      {"{ printf source; } <<'EOF' | { cat; } > /tmp/right && "
       "{ printf tail; }\n"
       "payload\n"
       "EOF\n",
       3, 3},
      {"{ cat <(printf config); } | sort", 2, 1},
      {"{ cat < <(printf config); } | sort", 2, 1},
      {"{ printf value 3> >(cat); }", 1, 1},
      {"printf value 2>> >(cat)", 1, 0},
      {"{ { cat <(printf config); }; }", 1, 2},
      {"cat /tmp/in | ( sort one; echo two; sort three; ) "
       "3>/tmp/trace 4<&0 5>&- </tmp/in 6>&1 8<&0 9>&- | sort",
       5, 1},
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(valid_cases) / sizeof(valid_cases[0]); i++) {
    const char *input = valid_cases[i].input;
    size_t length = strlen(input);
    shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    shell_parse_result_t fast = {0};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t command_netseq = {0};
    shell_netstring_buffer_t type_netseq = {0};
    shell_netstring_buffer_t paired_command = {0};
    shell_netstring_buffer_t paired_type = {0};
    bool features = false;

    shell_error_t fast_status = shell_parse_fast(input, length, &strict, &fast);
    shell_tokenize_status_t tokenizer_status =
        shell_tokenize_commands(input, length, &commands, &command_count);
    shell_process_status_t process_status =
        shell_process_commands(input, length, NULL, &processed);
    size_t netargv_count = 0;
    size_t command_count_out = 0;
    size_t type_count = 0;
    size_t anomaly_count = 0;
    shell_process_status_t netargv_status = shell_build_netargv_sequence_buffer(
        input, length, NULL, &netargv, &netargv_count, &features);
    shell_process_status_t command_status = shell_build_command_netseq_buffer(
        input, length, NULL, &command_netseq, &command_count_out);
    shell_process_status_t type_status = shell_build_type_netseq_buffer(
        input, length, NULL, &type_netseq, &type_count);
    shell_process_status_t anomaly_status = shell_build_anomaly_netseqs_buffer(
        input, length, NULL, &paired_command, &paired_type, &anomaly_count);
    shell_dep_error_t graph_status =
        shell_dep_graph_parse(input, length, ".", NULL, &graph);
    bool case_valid =
        fast_status == SHELL_OK && fast.count >= valid_cases[i].command_count &&
        fast.group_count == valid_cases[i].group_count &&
        tokenizer_status == SHELL_TOKENIZE_OK &&
        command_count >= valid_cases[i].command_count &&
        process_status == SHELL_PROCESS_OK &&
        processed.command_count == valid_cases[i].command_count &&
        processed.group_count == valid_cases[i].group_count &&
        tokenizer_processed_group_descriptors_match_source(&fast, &processed) &&
        netargv_status == SHELL_PROCESS_OK && netargv.data != NULL &&
        netargv_count == valid_cases[i].command_count &&
        command_status == SHELL_PROCESS_OK && command_netseq.data != NULL &&
        command_count_out >= valid_cases[i].command_count &&
        type_status == SHELL_PROCESS_OK && type_netseq.data != NULL &&
        type_count == command_count_out && anomaly_status == SHELL_PROCESS_OK &&
        paired_command.data != NULL && paired_type.data != NULL &&
        anomaly_count == command_count_out &&
        (command_netseq.length != paired_command.length ||
         memcmp(command_netseq.data, paired_command.data,
                command_netseq.length)) == 0 &&
        (type_netseq.length != paired_type.length ||
         memcmp(type_netseq.data, paired_type.data, type_netseq.length)) == 0 &&
        graph_status == SHELL_DEP_OK && shell_dep_graph_validate(&graph).valid;
    if (!case_valid)
      printf(
          "    valid brace case rejected: %s (fast=%d tokenizer=%d process=%d "
          "netargv=%d command=%d type=%d anomaly=%d graph=%d)\n",
          input, fast_status, tokenizer_status, process_status, netargv_status,
          command_status, type_status, anomaly_status, graph_status);
    valid = valid && case_valid;
    shell_netstring_buffer_free(&netargv);
    shell_netstring_buffer_free(&command_netseq);
    shell_netstring_buffer_free(&type_netseq);
    shell_netstring_buffer_free(&paired_command);
    shell_netstring_buffer_free(&paired_type);
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
  }
  test("Brace grammar agrees across canonical processing surfaces", valid);

  static const char *const invalid_cases[] = {
      "{ echo one }",
      "{ echo one;",
      "{ ( echo one; } )",
      "{ cat <(printf; }",
      "{ printf value 3> >(cat; }",
      "echo > (printf value)",
      "echo < (printf value)",
      "echo >> (printf value)",
      "cat << (EOF",
      "diff <(",
      "{ echo; } > (cat)",
      "3>/tmp/trace </tmp/in { echo one; }",
      "4<&0 ( echo one; )",
      "<<EOF { cat; }\npayload\nEOF\n",
      "<> /tmp/read-write { echo one; }",
      ">| /tmp/forced { echo one; }",
      "7<> /tmp/read-write 2>&1 { echo one; }",
      "a |",
      "a &&",
      "a ||",
      "a || || b",
      "a && && b",
      "a & & b",
      "a | ! b",
      "a |&",
      "a |& & b",
      "a |&& b",
      "a |& || b",
      "a |& ; b",
      "a |& | b",
      "a |& ! b",
      "a | & b",
      "echo one; }",
      "echo one | )",
      "echo one { literal; }",
      "echo one (cat)",
      "echo one ((1))",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(invalid_cases) / sizeof(invalid_cases[0]);
       i++) {
    const char *input = invalid_cases[i];
    size_t length = strlen(input);
    shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    shell_parse_result_t fast = {0};
    shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
    size_t command_count = SIZE_MAX;
    shell_command_info_t *infos = (shell_command_info_t *)(uintptr_t)1;
    size_t info_count = SIZE_MAX;
    shell_processed_commands_t processed = {
        .commands = (shell_command_info_t *)(uintptr_t)1,
        .command_count = SIZE_MAX,
        .groups = (shell_group_t *)(uintptr_t)1,
        .group_count = SIZE_MAX,
        .group_io_ops = (shell_group_io_op_t *)(uintptr_t)1,
        .group_io_op_count = SIZE_MAX,
    };
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t command_netseq = {0};
    shell_netstring_buffer_t type_netseq = {0};
    shell_netstring_buffer_t paired_command = {0};
    shell_netstring_buffer_t paired_type = {0};
    size_t count = SIZE_MAX;
    bool features = true;
    shell_dep_graph_t graph = {0};

    shell_error_t fast_status = shell_parse_fast(input, length, &strict, &fast);
    shell_tokenize_status_t tokenizer_status =
        shell_tokenize_commands(input, length, &commands, &command_count);
    shell_process_status_t one_status =
        shell_process_command(input, length, NULL, &infos, &info_count);
    shell_process_status_t process_status =
        shell_process_commands(input, length, NULL, &processed);
    shell_process_status_t netargv_status = shell_build_netargv_sequence_buffer(
        input, length, NULL, &netargv, &count, &features);
    shell_process_status_t command_status = shell_build_command_netseq_buffer(
        input, length, NULL, &command_netseq, &count);
    shell_process_status_t type_status = shell_build_type_netseq_buffer(
        input, length, NULL, &type_netseq, &count);
    shell_process_status_t anomaly_status = shell_build_anomaly_netseqs_buffer(
        input, length, NULL, &paired_command, &paired_type, &count);
    shell_dep_error_t graph_status =
        shell_dep_graph_parse(input, length, ".", NULL, &graph);
    bool case_valid =
        fast_status == SHELL_EPARSE &&
        tokenizer_status == SHELL_TOKENIZE_EPARSE && commands == NULL &&
        command_count == 0 && one_status == SHELL_PROCESS_EPARSE &&
        infos == NULL && info_count == 0 &&
        process_status == SHELL_PROCESS_EPARSE && processed.commands == NULL &&
        processed.command_count == 0 && processed.groups == NULL &&
        processed.group_count == 0 && processed.group_io_ops == NULL &&
        processed.group_io_op_count == 0 &&
        netargv_status == SHELL_PROCESS_EPARSE && netargv.data == NULL &&
        count == 0 && !features && command_status == SHELL_PROCESS_EPARSE &&
        command_netseq.data == NULL && count == 0 &&
        type_status == SHELL_PROCESS_EPARSE && type_netseq.data == NULL &&
        count == 0 && anomaly_status == SHELL_PROCESS_EPARSE &&
        paired_command.data == NULL && paired_type.data == NULL && count == 0 &&
        graph_status == SHELL_DEP_EPARSE;
    valid = valid && case_valid;
  }
  test("Invalid brace and redirect syntax clears every canonical boundary",
       valid);
}

static void tokenizer_test_brace_group_operation_limits_are_atomic(void) {
  static const char input[] =
      "{ ( cat; ); printf two; } 3>/tmp/trace 2>>/tmp/err";
  shell_process_limits_t exact = {SIZE_MAX, SIZE_MAX, 2};
  shell_processed_commands_t processed = {0};
  bool valid = shell_process_commands(input, sizeof(input) - 1, &exact,
                                      &processed) == SHELL_PROCESS_OK &&
               processed.command_count == 2 && processed.group_count == 2 &&
               processed.group_io_op_count == 2;
  shell_processed_commands_free(&processed);

  exact.max_group_io_ops = 1;
  processed.commands = (shell_command_info_t *)(uintptr_t)1;
  processed.command_count = SIZE_MAX;
  processed.groups = (shell_group_t *)(uintptr_t)1;
  processed.group_count = SIZE_MAX;
  processed.group_io_ops = (shell_group_io_op_t *)(uintptr_t)1;
  processed.group_io_op_count = SIZE_MAX;
  valid = valid &&
          shell_process_commands(input, sizeof(input) - 1, &exact,
                                 &processed) == SHELL_PROCESS_EOUTPUT_LIMIT &&
          processed.commands == NULL && processed.command_count == 0 &&
          processed.groups == NULL && processed.group_count == 0 &&
          processed.group_io_ops == NULL && processed.group_io_op_count == 0;

  shell_netstring_buffer_t netargv = {0};
  shell_netstring_buffer_t command_netseq = {0};
  shell_netstring_buffer_t type_netseq = {0};
  shell_netstring_buffer_t paired_command = {0};
  shell_netstring_buffer_t paired_type = {0};
  size_t count = SIZE_MAX;
  bool features = true;
  valid = valid &&
          shell_build_netargv_sequence_buffer(input, sizeof(input) - 1, &exact,
                                              &netargv, &count, &features) ==
              SHELL_PROCESS_EOUTPUT_LIMIT &&
          netargv.data == NULL && count == 0 && !features;
  count = SIZE_MAX;
  valid = valid &&
          shell_build_command_netseq_buffer(input, sizeof(input) - 1, &exact,
                                            &command_netseq, &count) ==
              SHELL_PROCESS_EOUTPUT_LIMIT &&
          command_netseq.data == NULL && count == 0;
  count = SIZE_MAX;
  valid = valid &&
          shell_build_type_netseq_buffer(input, sizeof(input) - 1, &exact,
                                         &type_netseq, &count) ==
              SHELL_PROCESS_EOUTPUT_LIMIT &&
          type_netseq.data == NULL && count == 0;
  count = SIZE_MAX;
  valid = valid &&
          shell_build_anomaly_netseqs_buffer(
              input, sizeof(input) - 1, &exact, &paired_command, &paired_type,
              &count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
          paired_command.data == NULL && paired_type.data == NULL && count == 0;
  test("Brace-group operation limits clear every canonical result", valid);
}

/* Anomaly sequences are structural execution inputs, not policy netargv.
 * Nested substitutions execute before the enclosing simple command, while the
 * ordinary netargv sequence remains deliberately top-level and
 * authorization-oriented. */
static void
tokenizer_test_anomaly_sequences_include_nested_execution_stages(void) {
  static const struct {
    const char *input;
    const char *raw;
    size_t count;
  } cases[] = {
      {"outer $(inner) < <(producer); cat <<EOF\n$(here)\nEOF\n",
       "5:inner,8:producer,5:outer,4:here,3:cat,", 5},
      {"outer $(>nested)", "0:,5:outer,", 2},
      {"outer $(middle $(inner))", "5:inner,6:middle,5:outer,", 3},
      {"outer `middle $(inner)`", "5:inner,6:middle,5:outer,", 3},
      {"outer $(middle <(producer))", "8:producer,6:middle,5:outer,", 3},
      {"cat <<EOF\n`backtick`\n${value:-$(parameter)}\nEOF\n",
       "8:backtick,9:parameter,3:cat,", 3},
      {"cat <<EOF\n\\$(literal)\\`also\\`\nEOF\n", "3:cat,", 1},
      {"cat <<A <<'B'\n$(first)\nA\n$(literal)\nB\n", "5:first,3:cat,", 2},
      {"cat <<'EOF'\n$(literal)\nEOF\n", "3:cat,", 1},
      {"{ outer $(inner); } | tail", "5:inner,5:outer,4:tail,", 3},
      {"{ group; } >out; tail", "5:group,4:tail,", 2},
  };

  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_netstring_buffer_t raw = {0};
    shell_netstring_buffer_t typed = {0};
    shell_netstring_buffer_t paired_raw = {0};
    shell_netstring_buffer_t paired_typed = {0};
    shell_netstring_buffer_t raw_buffer = {0};
    shell_netstring_buffer_t typed_buffer = {0};
    size_t raw_count = 0;
    size_t typed_count = 0;
    size_t paired_count = 0;
    valid = valid &&
            shell_build_command_netseq_buffer(
                cases[i].input, strlen(cases[i].input), NULL, &raw,
                &raw_count) == SHELL_PROCESS_OK &&
            raw.data != NULL && raw_count == cases[i].count &&
            (raw.length != strlen(cases[i].raw) ||
             memcmp(raw.data, cases[i].raw, raw.length)) == 0 &&
            shell_build_type_netseq_buffer(cases[i].input,
                                           strlen(cases[i].input), NULL, &typed,
                                           &typed_count) == SHELL_PROCESS_OK &&
            typed.data != NULL && typed_count == cases[i].count &&
            shell_netstring_validate(typed.data, typed.length, NULL) ==
                SHELL_NETSTRING_OK &&
            shell_build_anomaly_netseqs_buffer(
                cases[i].input, strlen(cases[i].input), NULL, &paired_raw,
                &paired_typed, &paired_count) == SHELL_PROCESS_OK &&
            paired_raw.data != NULL && paired_typed.data != NULL &&
            paired_count == cases[i].count &&
            (paired_raw.length != raw.length ||
             memcmp(paired_raw.data, raw.data, paired_raw.length)) == 0 &&
            (paired_typed.length != typed.length ||
             memcmp(paired_typed.data, typed.data, paired_typed.length)) == 0 &&
            shell_build_anomaly_netseqs_buffer(
                cases[i].input, strlen(cases[i].input), NULL, &raw_buffer,
                &typed_buffer, &paired_count) == SHELL_PROCESS_OK &&
            paired_count == cases[i].count && raw_buffer.length == raw.length &&
            typed_buffer.length == typed.length &&
            memcmp(raw_buffer.data, raw.data, raw_buffer.length) == 0 &&
            memcmp(typed_buffer.data, typed.data, typed_buffer.length) == 0;
    shell_netstring_buffer_free(&typed_buffer);
    shell_netstring_buffer_free(&raw_buffer);
    shell_netstring_buffer_free(&paired_typed);
    shell_netstring_buffer_free(&paired_raw);
    shell_netstring_buffer_free(&typed);
    shell_netstring_buffer_free(&raw);
  }

  shell_netstring_buffer_t netargv = {0};
  size_t netargv_count = 0;
  bool features = false;
  valid = valid &&
          shell_build_netargv_sequence_buffer(
              "outer $(inner)", strlen("outer $(inner)"), NULL, &netargv,
              &netargv_count, &features) == SHELL_PROCESS_OK &&
          netargv.data != NULL && netargv_count == 1 && features;
  shell_netstring_buffer_free(&netargv);

  shell_netstring_buffer_t raw = {0};
  shell_netstring_buffer_t typed = {0};
  size_t count = SIZE_MAX;
  valid = valid &&
          shell_build_anomaly_netseqs_buffer(
              "outer $(while true; do :; done)",
              strlen("outer $(while true; do :; done)"), NULL, &raw, &typed,
              &count) == SHELL_PROCESS_EPARSE &&
          raw.data == NULL && typed.data == NULL && count == 0;

  static const char *const dynamic_arithmetic[] = {
      "outer $((1 + $(inside)))",
      "outer $((1 + $\\\n(inside)))",
      "cat <<EOF\n$((1 + $(arith)))\nEOF\n",
  };
  for (size_t i = 0;
       i < sizeof(dynamic_arithmetic) / sizeof(dynamic_arithmetic[0]); i++) {
    raw = (shell_netstring_buffer_t){0};
    typed = (shell_netstring_buffer_t){0};
    count = SIZE_MAX;
    valid = valid &&
            shell_build_anomaly_netseqs_buffer(
                dynamic_arithmetic[i], strlen(dynamic_arithmetic[i]), NULL,
                &raw, &typed, &count) == SHELL_PROCESS_EPARSE &&
            raw.data == NULL && typed.data == NULL && count == 0;
  }

  char too_many[4 * SHELL_MAX_SUBCOMMANDS + 16] = "outer $(";
  size_t position = strlen(too_many);
  for (size_t i = 0; i < SHELL_MAX_SUBCOMMANDS; i++) {
    too_many[position++] = 'x';
    if (i + 1 < SHELL_MAX_SUBCOMMANDS)
      too_many[position++] = ';';
  }
  too_many[position++] = ')';
  too_many[position] = '\0';
  raw = (shell_netstring_buffer_t){0};
  count = SIZE_MAX;
  valid = valid &&
          shell_build_command_netseq_buffer(too_many, position, NULL, &raw,
                                            &count) ==
              SHELL_PROCESS_EOUTPUT_LIMIT &&
          raw.data == NULL && count == 0;

  test("Anomaly sequences include nested shell execution stages", valid);
}

static void tokenizer_test_static_arithmetic_depth_is_bounded(void) {
  /* The static arithmetic recognizer must reject adversarial nesting before
   * its recursive grammar can exhaust the process stack. Exercise both the
   * source-facing canonical APIs and the depgraph consumer. */
  size_t accepted_depth = SHELL_MAX_SUBCOMMANDS - 1;
  size_t rejected_depth = SHELL_MAX_SUBCOMMANDS;
  size_t capacity = 32 + 5 * (rejected_depth + 2);
  char *input = calloc(capacity, 1);
  bool valid = input != NULL;
  if (!valid) {
    test("Static arithmetic nesting is bounded", false);
    return;
  }

  size_t used = (size_t)snprintf(input, capacity, "echo $((");
  for (size_t i = 0; valid && i < accepted_depth; i++) {
    if (used + 1 >= capacity)
      valid = false;
    else
      input[used++] = '(';
  }
  if (valid)
    input[used++] = '1';
  for (size_t i = 0; valid && i < accepted_depth; i++) {
    if (used + 1 >= capacity)
      valid = false;
    else
      input[used++] = ')';
  }
  if (valid && used + 2 < capacity) {
    input[used++] = ')';
    input[used++] = ')';
    input[used] = '\0';
  } else {
    valid = false;
  }
  shell_netstring_buffer_t raw = {0};
  size_t count = 0;
  bool accepted = shell_build_command_netseq_buffer(
                      input, used, NULL, &raw, &count) == SHELL_PROCESS_OK &&
                  raw.data != NULL;
  valid = valid && accepted;
  shell_netstring_buffer_free(&raw);

  used = (size_t)snprintf(input, capacity, "echo $((");
  for (size_t i = 0; i < rejected_depth; i++)
    input[used++] = '(';
  input[used++] = '1';
  for (size_t i = 0; i < rejected_depth; i++)
    input[used++] = ')';
  input[used++] = ')';
  input[used++] = ')';
  input[used] = '\0';
  raw = (shell_netstring_buffer_t){0};
  count = SIZE_MAX;
  shell_dep_graph_t graph = {0};
  bool rejected =
      shell_process_validate_supported_source(input, used, NULL) ==
          SHELL_PROCESS_EPARSE &&
      shell_build_command_netseq_buffer(input, used, NULL, &raw, &count) ==
          SHELL_PROCESS_EPARSE &&
      raw.data == NULL && count == 0 &&
      shell_dep_graph_parse(input, used, ".", NULL, &graph) == SHELL_DEP_EPARSE;
  valid = valid && rejected;

  /* Right-associative exponentiation and chained conditionals have their own
   * recursive grammar paths. They share the same structural cap as grouped
   * expressions instead of relying on a shallow ordinary test corpus. */
  for (size_t family = 0; family < 2; family++) {
    for (size_t boundary = 0; boundary < 2; boundary++) {
      size_t operators = boundary == 0 ? accepted_depth : rejected_depth;
      used = (size_t)snprintf(input, capacity, "echo $((");
      for (size_t i = 0; i < operators; i++) {
        size_t width = family == 0 ? 3 : 4;
        if (used + width + 3 >= capacity) {
          valid = false;
          break;
        }
        memcpy(input + used, family == 0 ? "1**" : "1?1:", width);
        used += width;
      }
      if (!valid)
        continue;
      input[used++] = '1';
      input[used++] = ')';
      input[used++] = ')';
      input[used] = '\0';
      raw = (shell_netstring_buffer_t){0};
      count = SIZE_MAX;
      shell_process_status_t status =
          shell_build_command_netseq_buffer(input, used, NULL, &raw, &count);
      bool expected = boundary == 0 ? status == SHELL_PROCESS_OK &&
                                          raw.data != NULL && count == 1
                                    : status == SHELL_PROCESS_EPARSE &&
                                          raw.data == NULL && count == 0;
      valid = valid && expected;
      shell_netstring_buffer_free(&raw);
    }
  }

  /* Linear prefix syntax is no longer recursively parsed. */
  used = (size_t)snprintf(input, capacity, "echo $((");
  while (used + 5 < capacity) {
    input[used++] = '-';
    input[used++] = ' ';
  }
  input[used++] = '1';
  input[used++] = ')';
  input[used++] = ')';
  input[used] = '\0';
  raw = (shell_netstring_buffer_t){0};
  bool unary = shell_build_command_netseq_buffer(input, used, NULL, &raw,
                                                 &count) == SHELL_PROCESS_OK &&
               raw.data != NULL;
  valid = valid && unary;
  shell_netstring_buffer_free(&raw);
  /* The lower-level source scanner has its own recursive nested-arithmetic
   * route. Its boundary must agree with the semantic grammar's safe cap. */
  used = (size_t)snprintf(input, capacity, "echo ");
  for (size_t i = 0; i < SHELL_MAX_SUBCOMMANDS; i++) {
    input[used++] = '$';
    input[used++] = '(';
    input[used++] = '(';
  }
  input[used++] = '1';
  for (size_t i = 0; i < SHELL_MAX_SUBCOMMANDS; i++) {
    input[used++] = ')';
    input[used++] = ')';
  }
  input[used] = '\0';
  size_t after = 0;
  bool scanner_accepted = shell_source_skip_arithmetic_expansion(
                              input, used, strlen("echo "), &after) &&
                          after == used;
  used = (size_t)snprintf(input, capacity, "echo ");
  for (size_t i = 0; i <= SHELL_MAX_SUBCOMMANDS; i++) {
    input[used++] = '$';
    input[used++] = '(';
    input[used++] = '(';
  }
  input[used++] = '1';
  for (size_t i = 0; i <= SHELL_MAX_SUBCOMMANDS; i++) {
    input[used++] = ')';
    input[used++] = ')';
  }
  input[used] = '\0';
  bool scanner_rejected = !shell_source_skip_arithmetic_expansion(
      input, used, strlen("echo "), &after);
  valid = valid && scanner_accepted && scanner_rejected;
  free(input);
  test("Static arithmetic nesting is bounded", valid);
}

static void
tokenizer_test_anomaly_sequences_represent_redirect_only_record(void) {
  const char *input = ">/tmp/no-executable";
  shell_netstring_buffer_t netargv = {0};
  shell_netstring_buffer_t command_netseq = {0};
  shell_netstring_buffer_t type_netseq = {0};
  shell_netstring_buffer_t paired_command = {0};
  shell_netstring_buffer_t paired_type = {0};
  size_t count = SIZE_MAX;
  bool features = true;
  shell_processed_commands_t processed = {0};
  bool valid = shell_process_commands(input, strlen(input), NULL, &processed) ==
                   SHELL_PROCESS_OK &&
               processed.command_count == 0 &&
               shell_build_netargv_sequence_buffer(
                   input, strlen(input), NULL, &netargv, &count, &features) ==
                   SHELL_PROCESS_EPARSE &&
               netargv.data == NULL && count == 0 && !features;
  shell_processed_commands_free(&processed);
  count = SIZE_MAX;
  valid = valid &&
          shell_build_command_netseq_buffer(input, strlen(input), NULL,
                                            &command_netseq,
                                            &count) == SHELL_PROCESS_OK &&
          command_netseq.data != NULL && count == 1 &&
          (command_netseq.length != sizeof("0:,") - 1 ||
           memcmp(command_netseq.data, "0:,", command_netseq.length)) == 0;
  count = SIZE_MAX;
  valid =
      valid &&
      shell_build_type_netseq_buffer(input, strlen(input), NULL, &type_netseq,
                                     &count) == SHELL_PROCESS_OK &&
      type_netseq.data != NULL && count == 1 &&
      (type_netseq.length != sizeof("3:0:,,") - 1 ||
       memcmp(type_netseq.data, "3:0:,,", type_netseq.length)) == 0;
  count = SIZE_MAX;
  valid = valid &&
          shell_build_anomaly_netseqs_buffer(input, strlen(input), NULL,
                                             &paired_command, &paired_type,
                                             &count) == SHELL_PROCESS_OK &&
          paired_command.data != NULL && paired_type.data != NULL &&
          count == 1 &&
          (paired_command.length != command_netseq.length ||
           memcmp(paired_command.data, command_netseq.data,
                  paired_command.length)) == 0 &&
          (paired_type.length != type_netseq.length ||
           memcmp(paired_type.data, type_netseq.data, paired_type.length)) == 0;
  shell_netstring_buffer_free(&paired_type);
  shell_netstring_buffer_free(&paired_command);
  shell_netstring_buffer_free(&type_netseq);
  shell_netstring_buffer_free(&command_netseq);

  /* The anomaly-only sentinel is still subject to each builder's ordinary
   * output and source contracts, including empty-executable rejection. */
  shell_process_limits_t raw_limit = {2, SIZE_MAX, 0};
  shell_process_limits_t type_limit = {3, SIZE_MAX, 0};
  shell_netstring_buffer_t command_buffer = {0};
  shell_netstring_buffer_t type_buffer = {0};
  count = SIZE_MAX;
  valid = valid &&
          shell_build_command_netseq_buffer(input, strlen(input), &raw_limit,
                                            &command_netseq, &count) ==
              SHELL_PROCESS_EOUTPUT_LIMIT &&
          command_netseq.data == NULL && count == 0;
  count = SIZE_MAX;
  valid = valid &&
          shell_build_type_netseq_buffer(input, strlen(input), &type_limit,
                                         &type_buffer, &count) ==
              SHELL_PROCESS_EOUTPUT_LIMIT &&
          type_buffer.data == NULL && type_buffer.length == 0 && count == 0;
  count = SIZE_MAX;
  valid = valid &&
          shell_build_anomaly_netseqs_buffer(
              input, strlen(input), &type_limit, &command_buffer, &type_buffer,
              &count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
          command_buffer.data == NULL && command_buffer.length == 0 &&
          type_buffer.data == NULL && type_buffer.length == 0 && count == 0;
  const char *binary_input = "$'\\0binary'";
  count = SIZE_MAX;
  valid = valid &&
          shell_build_anomaly_netseqs_buffer(
              binary_input, strlen(binary_input), NULL, &paired_command,
              &paired_type, &count) == SHELL_PROCESS_EPARSE &&
          paired_command.data == NULL && paired_type.data == NULL && count == 0;

  /* The sentinel is reserved for a missing executable, not for an explicitly
   * empty executable word. Every sequence form must keep rejecting the latter
   * rather than silently assigning it the redirect-only meaning. */
  count = SIZE_MAX;
  valid = valid &&
          shell_build_command_netseq_buffer("'' x", strlen("'' x"), NULL,
                                            &command_netseq,
                                            &count) == SHELL_PROCESS_EPARSE &&
          command_netseq.data == NULL && count == 0;
  count = SIZE_MAX;
  valid =
      valid &&
      shell_build_type_netseq_buffer("'' x", strlen("'' x"), NULL, &type_netseq,
                                     &count) == SHELL_PROCESS_EPARSE &&
      type_netseq.data == NULL && count == 0;
  shell_netstring_buffer_free(&command_buffer);
  shell_netstring_buffer_free(&type_buffer);

  command_netseq = (shell_netstring_buffer_t){0};
  type_netseq = (shell_netstring_buffer_t){0};
  paired_command = (shell_netstring_buffer_t){0};
  paired_type = (shell_netstring_buffer_t){0};
  count = 0;
  valid =
      valid &&
      shell_build_anomaly_netseqs_buffer("echo ok; >/tmp/no-executable",
                                         strlen("echo ok; >/tmp/no-executable"),
                                         NULL, &paired_command, &paired_type,
                                         &count) == SHELL_PROCESS_OK &&
      count == 2 &&
      (paired_command.length != sizeof("4:echo,0:,") - 1 ||
       memcmp(paired_command.data, "4:echo,0:,", paired_command.length)) == 0 &&
      (paired_type.length != sizeof("13:4:echo,3:STR,,3:0:,,") - 1 ||
       memcmp(paired_type.data, "13:4:echo,3:STR,,3:0:,,",
              paired_type.length)) == 0;
  shell_netstring_buffer_free(&paired_type);
  shell_netstring_buffer_free(&paired_command);
  paired_command = (shell_netstring_buffer_t){0};
  paired_type = (shell_netstring_buffer_t){0};
  count = 0;
  valid = valid &&
          shell_build_anomaly_netseqs_buffer("time !", strlen("time !"), NULL,
                                             &paired_command, &paired_type,
                                             &count) == SHELL_PROCESS_OK &&
          count == 1 &&
          (paired_command.length != sizeof("0:,") - 1 ||
           memcmp(paired_command.data, "0:,", paired_command.length)) == 0 &&
          (paired_type.length != sizeof("3:0:,,") - 1 ||
           memcmp(paired_type.data, "3:0:,,", paired_type.length)) == 0;
  shell_netstring_buffer_free(&paired_type);
  shell_netstring_buffer_free(&paired_command);
  test("Anomaly sequences retain argv-less structural stages", valid);
}

/* A redirect operand is one shell word. A physical line ending or comment
 * cannot quietly supply a later command word as that operand, whereas an
 * escaped physical line ending remains part of the same command. */
static void tokenizer_test_redirect_operand_boundary_contract(void) {
  static const char *const invalid[] = {
      "echo >\nout",         "echo > # comment",
      "echo >\n# note\nout", "echo <\nin",
      "echo 2>\nerr",        "echo &>\nout",
      "echo >|\nout",        "echo <>\nout",
      "echo <<<\nword",      "echo <<\nEOF\nbody\nEOF",
      "echo >#comment",      "echo 2>#comment",
      "echo <#comment",      "echo >|#comment",
      "echo <>#comment",     "echo &>#comment",
      "echo &>>#comment",    "echo <<<#comment",
      "echo <<#comment",     "echo <<-#comment",
      "echo << #comment",    "echo <<- #comment",
  };
  const shell_limits_t strict = {
      .max_subcommands = SHELL_MAX_SUBCOMMANDS,
      .strict_mode = true,
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    const char *input = invalid[i];
    shell_parse_result_t fast = {0};
    shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
    size_t command_count = SIZE_MAX;
    shell_command_info_t *infos = (shell_command_info_t *)(uintptr_t)1;
    size_t info_count = SIZE_MAX;
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t netargv = {0};
    size_t netargv_count = SIZE_MAX;
    bool features = true;
    shell_netstring_buffer_t command_netseq = {0};
    size_t command_netseq_count = SIZE_MAX;
    shell_netstring_buffer_t type_netseq = {0};
    size_t type_netseq_count = SIZE_MAX;
    shell_netstring_buffer_t anomaly_commands = {0};
    shell_netstring_buffer_t anomaly_types = {0};
    size_t anomaly_count = SIZE_MAX;
    shell_dep_graph_t graph = {0};
    valid = valid &&
            shell_parse_fast(input, strlen(input), &strict, &fast) ==
                SHELL_EPARSE &&
            shell_tokenize_commands(input, strlen(input), &commands,
                                    &command_count) == SHELL_TOKENIZE_EPARSE &&
            commands == NULL && command_count == 0 &&
            shell_process_command(input, strlen(input), NULL, &infos,
                                  &info_count) == SHELL_PROCESS_EPARSE &&
            infos == NULL && info_count == 0 &&
            shell_process_commands(input, strlen(input), NULL, &processed) ==
                SHELL_PROCESS_EPARSE &&
            processed.commands == NULL && processed.command_count == 0 &&
            shell_build_netargv_sequence_buffer(
                input, strlen(input), NULL, &netargv, &netargv_count,
                &features) == SHELL_PROCESS_EPARSE &&
            netargv.data == NULL && netargv_count == 0 && !features &&
            shell_build_command_netseq_buffer(
                input, strlen(input), NULL, &command_netseq,
                &command_netseq_count) == SHELL_PROCESS_EPARSE &&
            command_netseq.data == NULL && command_netseq_count == 0 &&
            shell_build_type_netseq_buffer(input, strlen(input), NULL,
                                           &type_netseq, &type_netseq_count) ==
                SHELL_PROCESS_EPARSE &&
            type_netseq.data == NULL && type_netseq_count == 0 &&
            shell_build_anomaly_netseqs_buffer(
                input, strlen(input), NULL, &anomaly_commands, &anomaly_types,
                &anomaly_count) == SHELL_PROCESS_EPARSE &&
            anomaly_commands.data == NULL && anomaly_types.data == NULL &&
            anomaly_count == 0 &&
            shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
                SHELL_DEP_EPARSE &&
            graph.node_count == 0 && graph.edge_count == 0;
    if (commands != (shell_command_t *)(uintptr_t)1)
      shell_commands_free(commands, command_count);
    if (infos != (shell_command_info_t *)(uintptr_t)1)
      shell_command_infos_free(infos, info_count);
    shell_processed_commands_free(&processed);
    shell_netstring_buffer_free(&netargv);
    shell_netstring_buffer_free(&command_netseq);
    shell_netstring_buffer_free(&type_netseq);
    shell_netstring_buffer_free(&anomaly_commands);
    shell_netstring_buffer_free(&anomaly_types);
  }

  /* The full tokenizer keeps an I/O-only simple command as one structural
   * record. Canonical argv builders reject its lack of an executable later;
   * retaining the redirect tokens here is required for graph analysis. */
  static const char *const io_only[] = {">out", "<<EOF\nbody\nEOF\n"};
  for (size_t i = 0; i < sizeof(io_only) / sizeof(io_only[0]); i++) {
    shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
    size_t command_count = SIZE_MAX;
    valid = valid &&
            shell_tokenize_commands(io_only[i], strlen(io_only[i]), &commands,
                                    &command_count) == SHELL_TOKENIZE_OK &&
            commands != NULL && command_count == 1 &&
            commands[0].token_count > 0;
    shell_commands_free(commands, command_count);
  }

  static const char *const accepted[] = {
      "echo > \\\nout",
      "echo 2> \\\nerr",
      "echo >\"#name\"",
      "echo >\\#name",
      "echo <<<\"#value\"",
      "echo <<<\\#value",
      "echo <<'#marker'\nbody\n#marker\n",
      "echo <<\\#marker\nbody\n#marker\n",
      "echo <<-'#marker'\n\tbody\n\t#marker\n",
  };
  for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); i++) {
    const char *input = accepted[i];
    shell_parse_result_t fast = {0};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_netstring_buffer_t netargv = {0};
    size_t netargv_count = 0;
    bool features = false;
    shell_dep_graph_t graph = {0};
    valid =
        valid &&
        shell_parse_fast(input, strlen(input), &strict, &fast) == SHELL_OK &&
        shell_tokenize_commands(input, strlen(input), &commands,
                                &command_count) == SHELL_TOKENIZE_OK &&
        command_count == 1 &&
        shell_build_netargv_sequence_buffer(input, strlen(input), NULL,
                                            &netargv, &netargv_count,
                                            &features) == SHELL_PROCESS_OK &&
        netargv_count == 1 &&
        (netargv.length != sizeof("7:4:echo,,") - 1 ||
         memcmp(netargv.data, "7:4:echo,,", netargv.length)) == 0 &&
        shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        /* A possible failure opening stderr retains inherited stderr for the
         * shell's diagnostic in addition to the successful file route. */
        graph.node_count == (i == 1 ? 5u : 4u) &&
        graph.edge_count == (i == 1 ? 4u : 3u) &&
        shell_dep_graph_validate(&graph).valid;
    shell_commands_free(commands, command_count);
    shell_netstring_buffer_free(&netargv);
  }

  /* Fast ranges may stop at the backslash while the physical line ending and
   * a following io_number are outside that range. Reprocessing must restore
   * the continuation and leave only the executable in canonical argv. */
  static const char *const continued_io_numbers[] = {
      "cmd >out \\\n3<<<data",
      "cmd >out \\\n3<<<data",
  };
  for (size_t i = 0;
       i < sizeof(continued_io_numbers) / sizeof(continued_io_numbers[0]);
       i++) {
    shell_processed_commands_t processed = {0};
    const char *input = continued_io_numbers[i];
    valid = valid &&
            shell_process_commands(input, strlen(input), NULL, &processed) ==
                SHELL_PROCESS_OK &&
            processed.command_count == 1 &&
            processed.commands[0].command_token_count == 1;
    const shell_token_t *word = processed.command_count == 1
                                    ? &processed.commands[0].command_tokens[0]
                                    : NULL;
    valid = valid && word != NULL && word->length == 3 &&
            memcmp(word->start, "cmd", 3) == 0;
    shell_processed_commands_free(&processed);
  }
  test("Redirect operands preserve inline boundaries across APIs", valid);
}

static void tokenizer_test_processed_group_io_contract(void) {
  static const char composed[] =
      "cat /tmp/in | { cat; cat; } <<< \"two words\" | sort && printf tail";
  static const char documents[] = "{ cat; cat; } <<A <<-'B'\n"
                                  "one\n"
                                  "A\n"
                                  "\ttwo\n"
                                  "\tB\n";
  shell_processed_commands_t result = {0};
  shell_process_status_t status =
      shell_process_commands(composed, sizeof(composed) - 1, NULL, &result);
  bool valid =
      status == SHELL_PROCESS_OK && result.command_count == 5 &&
      result.group_count == 1 && result.group_io_op_count == 3 &&
      result.group_io_ops[0].kind == SHELL_GROUP_IO_PIPE_INPUT &&
      result.group_io_ops[1].kind == SHELL_GROUP_IO_HERESTRING &&
      result.group_io_ops[2].kind == SHELL_GROUP_IO_PIPE_OUTPUT &&
      result.group_io_ops[1].group_index == 0 &&
      !result.commands[1].has_pipe_input &&
      !result.commands[2].has_pipe_output &&
      result.group_io_ops[1].source_end > result.group_io_ops[1].source_start &&
      memcmp(composed + result.group_io_ops[1].source_start,
             "<<< \"two words\"", sizeof("<<< \"two words\"") - 1) == 0;
  shell_processed_commands_free(&result);

  memset(&result, 0, sizeof(result));
  status =
      shell_process_commands(documents, sizeof(documents) - 1, NULL, &result);
  valid =
      valid && status == SHELL_PROCESS_OK && result.command_count == 2 &&
      result.group_count == 1 && result.group_io_op_count == 2 &&
      result.group_io_ops[0].kind == SHELL_GROUP_IO_HEREDOC &&
      result.group_io_ops[1].kind == SHELL_GROUP_IO_HEREDOC &&
      result.group_io_ops[0].source_end > result.group_io_ops[0].source_start &&
      memcmp(documents + result.group_io_ops[0].source_start, "<<A",
             sizeof("<<A") - 1) == 0 &&
      memcmp(documents + result.group_io_ops[1].source_start, "<<-'B'",
             sizeof("<<-'B'") - 1) == 0;
  shell_processed_commands_free(&result);

  static const struct {
    const char *input;
    shell_group_io_kind_t kind;
    uint32_t fd;
    uint32_t target_fd;
    const char *redirect;
  } redirects[] = {
      {"{ echo; }</tmp/in", SHELL_GROUP_IO_READ_FILE, 0, UINT32_MAX,
       "</tmp/in"},
      {"{ echo; }> /tmp/out", SHELL_GROUP_IO_WRITE_FILE, 1, UINT32_MAX,
       "> /tmp/out"},
      {"{ echo; }>>/tmp/out", SHELL_GROUP_IO_APPEND_FILE, 1, UINT32_MAX,
       ">>/tmp/out"},
      {"{ echo; } 2>/tmp/err", SHELL_GROUP_IO_WRITE_FILE, 2, UINT32_MAX,
       "2>/tmp/err"},
      {"{ echo; } 2>>/tmp/err", SHELL_GROUP_IO_APPEND_FILE, 2, UINT32_MAX,
       "2>>/tmp/err"},
      {"{ echo; } 2>&1", SHELL_GROUP_IO_DUP_FD, 2, 1, "2>&1"},
      {"{ echo; } 4>& 3", SHELL_GROUP_IO_DUP_FD, 4, 3, "4>& 3"},
      {"{ echo; } 5>&\t4", SHELL_GROUP_IO_DUP_FD, 5, 4, "5>&\t4"},
      {"{ echo; } 6>& \\\n5", SHELL_GROUP_IO_DUP_FD, 6, 5, "6>& \\\n5"},
      {"{ echo; }>&\"7\"", SHELL_GROUP_IO_DUP_FD, 1, 7, ">&\"7\""},
      {"{ echo; }>& \"7\"", SHELL_GROUP_IO_DUP_FD, 1, 7, ">& \"7\""},
      {"{ echo; }>&$'7'", SHELL_GROUP_IO_DUP_FD, 1, 7, ">&$'7'"},
      {"{ echo; }>&0000000000000000000000000000000000000001",
       SHELL_GROUP_IO_DUP_FD, 1, 1,
       ">&0000000000000000000000000000000000000001"},
      {"{ echo; }>&$'0000000000000000000000000000000000000001'",
       SHELL_GROUP_IO_DUP_FD, 1, 1,
       ">&$'0000000000000000000000000000000000000001'"},
      {"{ echo; } 0<&-", SHELL_GROUP_IO_CLOSE_FD, 0, UINT32_MAX, "0<&-"},
      {"{ echo; } 7>& -", SHELL_GROUP_IO_CLOSE_FD, 7, UINT32_MAX, "7>& -"},
      {"{ echo; }>&\"-\"", SHELL_GROUP_IO_CLOSE_FD, 1, UINT32_MAX, ">&\"-\""},
      {"{ echo; } <>/tmp/read-write", SHELL_GROUP_IO_READ_WRITE_FILE, 0,
       UINT32_MAX, "<>/tmp/read-write"},
      {"{ echo; } >|/tmp/forced", SHELL_GROUP_IO_WRITE_FILE, 1, UINT32_MAX,
       ">|/tmp/forced"},
  };
  for (size_t i = 0; i < sizeof(redirects) / sizeof(redirects[0]); i++) {
    memset(&result, 0, sizeof(result));
    status = shell_process_commands(redirects[i].input,
                                    strlen(redirects[i].input), NULL, &result);
    bool case_valid =
        status == SHELL_PROCESS_OK && result.group_count == 1 &&
        result.group_io_op_count == 1 &&
        result.group_io_ops[0].kind == redirects[i].kind &&
        result.group_io_ops[0].fd == redirects[i].fd &&
        result.group_io_ops[0].target_fd == redirects[i].target_fd &&
        result.group_io_ops[0].source_end >
            result.group_io_ops[0].source_start &&
        memcmp(redirects[i].input + result.group_io_ops[0].source_start,
               redirects[i].redirect, strlen(redirects[i].redirect)) == 0;
    valid = valid && case_valid;
    shell_processed_commands_free(&result);
  }

  /* A group-owned symbolic target remains a descriptor reference even when
   * blank trivia separates it from `&`. The group metadata keeps the whole
   * redirect spelling while exposing only the identifier span to callers. */
  static const char whitespace_named[] =
      "{ printf x; } {sink}>out >& \"${sink}\"";
  const char *whitespace_named_reference = strstr(whitespace_named, "${sink}");
  memset(&result, 0, sizeof(result));
  status = shell_process_commands(whitespace_named,
                                  sizeof(whitespace_named) - 1, NULL, &result);
  valid = valid && whitespace_named_reference != NULL &&
          status == SHELL_PROCESS_OK && result.group_count == 1 &&
          result.group_io_op_count == 2 &&
          result.group_io_ops[1].kind == SHELL_GROUP_IO_DUP_FD &&
          result.group_io_ops[1].fd == 1 &&
          result.group_io_ops[1].target_fd == SHELL_PROCESS_FD_NONE &&
          result.group_io_ops[1].target_name_start ==
              (uint32_t)(whitespace_named_reference - whitespace_named + 2) &&
          result.group_io_ops[1].target_name_end ==
              (uint32_t)(whitespace_named_reference - whitespace_named +
                         strlen("${sink}") - 1);
  shell_processed_commands_free(&result);

  /* Canonical command and anomaly sequences must use the same accepted group
   * redirect grammar as structured processing. This reaches both netstring
   * builders, which are Shellgate's anomaly-facing input surfaces. */
  shell_netstring_buffer_t command_netseq = {0};
  shell_netstring_buffer_t anomaly_commands = {0};
  shell_netstring_buffer_t anomaly_types = {0};
  size_t command_count = 0;
  size_t anomaly_count = 0;
  valid = valid &&
          shell_build_command_netseq_buffer(
              whitespace_named, sizeof(whitespace_named) - 1, NULL,
              &command_netseq, &command_count) == SHELL_PROCESS_OK &&
          command_count == 1 && command_netseq.data != NULL &&
          command_netseq.length != 0 &&
          shell_build_anomaly_netseqs_buffer(
              whitespace_named, sizeof(whitespace_named) - 1, NULL,
              &anomaly_commands, &anomaly_types,
              &anomaly_count) == SHELL_PROCESS_OK &&
          anomaly_count == 1 && anomaly_commands.data != NULL &&
          anomaly_commands.length != 0 && anomaly_types.data != NULL &&
          anomaly_types.length != 0;
  shell_netstring_buffer_free(&command_netseq);
  shell_netstring_buffer_free(&anomaly_commands);
  shell_netstring_buffer_free(&anomaly_types);

  /* Redirect operands terminate at an adjacent, unquoted redirection. The
   * compact spelling is common in generated shell and must not fabricate a
   * file called \`first>second\`. */
  static const char compact[] = "{ echo; }>first>second";
  memset(&result, 0, sizeof(result));
  status = shell_process_commands(compact, sizeof(compact) - 1, NULL, &result);
  valid =
      valid && status == SHELL_PROCESS_OK && result.group_count == 1 &&
      result.group_io_op_count == 2 &&
      result.group_io_ops[0].kind == SHELL_GROUP_IO_WRITE_FILE &&
      result.group_io_ops[1].kind == SHELL_GROUP_IO_WRITE_FILE &&
      result.group_io_ops[0].fd == 1 && result.group_io_ops[1].fd == 1 &&
      result.group_io_ops[0].source_end - result.group_io_ops[0].source_start ==
          sizeof(">first") - 1 &&
      result.group_io_ops[1].source_end - result.group_io_ops[1].source_start ==
          sizeof(">second") - 1 &&
      memcmp(compact + result.group_io_ops[0].source_start, ">first",
             sizeof(">first") - 1) == 0 &&
      memcmp(compact + result.group_io_ops[1].source_start, ">second",
             sizeof(">second") - 1) == 0;
  shell_processed_commands_free(&result);

  static const struct {
    const char *input;
    shell_group_io_kind_t kind;
    uint32_t fd;
    const char *operand;
  } process_redirects[] = {
      {"{ cat; } 3< <(printf input)", SHELL_GROUP_IO_PROCESS_SUB_IN, 3,
       "<(printf input)"},
      {"( printf value; ) 4> >(cat)", SHELL_GROUP_IO_PROCESS_SUB_OUT, 4,
       ">(cat)"},
      {"{ printf value; } 5>> >(cat)", SHELL_GROUP_IO_PROCESS_SUB_OUT, 5,
       ">(cat)"},
      {"{ cat; } < >(sh)", SHELL_GROUP_IO_PROCESS_SUB_UNROUTED, 0, ">(sh)"},
      {"{ cat; } > <(printf input)", SHELL_GROUP_IO_PROCESS_SUB_UNROUTED, 1,
       "<(printf input)"},
      {"{ cat; } <> <(printf input)", SHELL_GROUP_IO_PROCESS_SUB_RW_IN, 0,
       "<(printf input)"},
      {"{ cat; } <> >(sh)", SHELL_GROUP_IO_PROCESS_SUB_RW_OUT, 0, ">(sh)"},
      {"{ cat; } 3<> >(sh)", SHELL_GROUP_IO_PROCESS_SUB_RW_OUT, 3, ">(sh)"},
      {"{ printf value; } 3> >(printf '%s' 'a)')",
       SHELL_GROUP_IO_PROCESS_SUB_OUT, 3, ">(printf '%s' 'a)')"},
  };
  for (size_t i = 0;
       i < sizeof(process_redirects) / sizeof(process_redirects[0]); i++) {
    memset(&result, 0, sizeof(result));
    status = shell_process_commands(process_redirects[i].input,
                                    strlen(process_redirects[i].input), NULL,
                                    &result);
    bool case_valid =
        status == SHELL_PROCESS_OK && result.group_count == 1 &&
        result.group_io_op_count == 1 &&
        result.group_io_ops[0].kind == process_redirects[i].kind &&
        result.group_io_ops[0].fd == process_redirects[i].fd &&
        result.group_io_ops[0].target_fd == UINT32_MAX &&
        result.group_io_ops[0].operand_end -
                result.group_io_ops[0].operand_start ==
            strlen(process_redirects[i].operand) &&
        memcmp(process_redirects[i].input +
                   result.group_io_ops[0].operand_start,
               process_redirects[i].operand,
               strlen(process_redirects[i].operand)) == 0;
    valid = valid && case_valid;
    shell_processed_commands_free(&result);
  }

  /* `>& <(...)` is Bash's legacy combined-output spelling with a pathname
   * operand. The process substitution is cross-directional, so both output
   * descriptors retain unrouted process-substitution metadata. */
  static const char legacy_cross_direction[] =
      "{ printf value; } >& <(printf input)";
  memset(&result, 0, sizeof(result));
  status =
      shell_process_commands(legacy_cross_direction,
                             sizeof(legacy_cross_direction) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.group_count == 1 &&
          result.group_io_op_count == 2 &&
          result.group_io_ops[0].kind == SHELL_GROUP_IO_PROCESS_SUB_UNROUTED &&
          result.group_io_ops[1].kind == SHELL_GROUP_IO_PROCESS_SUB_UNROUTED &&
          result.group_io_ops[0].fd == 1 && result.group_io_ops[1].fd == 2 &&
          result.group_io_ops[0].operand_end -
                  result.group_io_ops[0].operand_start ==
              sizeof("<(printf input)") - 1 &&
          memcmp(legacy_cross_direction + result.group_io_ops[0].operand_start,
                 "<(printf input)", sizeof("<(printf input)") - 1) == 0;
  shell_processed_commands_free(&result);

  /* A command substitution can resolve to an fd or close marker, so a group
   * cannot label it as combined output without making a false claim. */
  static const char *const ambiguous_legacy_targets[] = {
      "{ printf value; } >&$(printf 2)",
      "{ printf value; } >&`printf 2`",
  };
  for (size_t i = 0; i < sizeof(ambiguous_legacy_targets) /
                             sizeof(ambiguous_legacy_targets[0]);
       i++) {
    memset(&result, 0, sizeof(result));
    status = shell_process_commands(ambiguous_legacy_targets[i],
                                    strlen(ambiguous_legacy_targets[i]), NULL,
                                    &result);
    valid = valid && status == SHELL_PROCESS_EPARSE &&
            result.commands == NULL && result.command_count == 0 &&
            result.group_io_ops == NULL && result.group_io_op_count == 0;
    shell_processed_commands_free(&result);
  }

  /* A valid redirect list can end at a list operator. This is the normal
   * completion boundary, not a malformed redirect following the group. */
  static const char control_suffix[] = "{ echo; } >/tmp/out && printf next";
  memset(&result, 0, sizeof(result));
  status = shell_process_commands(control_suffix, sizeof(control_suffix) - 1,
                                  NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 2 &&
          result.group_count == 1 && result.group_io_op_count == 1 &&
          result.group_io_ops[0].kind == SHELL_GROUP_IO_WRITE_FILE &&
          result.group_io_ops[0].fd == 1;
  shell_processed_commands_free(&result);

  static const char nested[] =
      "{ { echo inner; } >/tmp/inner; echo outer; } >/tmp/outer";
  memset(&result, 0, sizeof(result));
  status = shell_process_commands(nested, sizeof(nested) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.group_count == 2 &&
          result.group_io_op_count == 2 &&
          result.group_io_ops[0].group_index !=
              result.group_io_ops[1].group_index &&
          result.group_io_ops[0].kind == SHELL_GROUP_IO_WRITE_FILE &&
          result.group_io_ops[1].kind == SHELL_GROUP_IO_WRITE_FILE;
  shell_processed_commands_free(&result);

  static const char leading[] =
      "{ echo one; } 3>/tmp/trace </tmp/in 2>>/tmp/err";
  memset(&result, 0, sizeof(result));
  status = shell_process_commands(leading, sizeof(leading) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 1 &&
          result.group_count == 1 && result.group_io_op_count == 3 &&
          result.group_io_ops[0].kind == SHELL_GROUP_IO_WRITE_FILE &&
          result.group_io_ops[0].fd == 3 &&
          result.group_io_ops[1].kind == SHELL_GROUP_IO_READ_FILE &&
          result.group_io_ops[1].fd == 0 &&
          result.group_io_ops[2].kind == SHELL_GROUP_IO_APPEND_FILE &&
          result.group_io_ops[2].fd == 2;
  shell_processed_commands_free(&result);

  static const char leading_heredoc[] = "{ cat; } <<EOF\npayload\nEOF\n";
  memset(&result, 0, sizeof(result));
  status = shell_process_commands(leading_heredoc, sizeof(leading_heredoc) - 1,
                                  NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 1 &&
          result.group_count == 1 && result.group_io_op_count == 1 &&
          result.group_io_ops[0].kind == SHELL_GROUP_IO_HEREDOC &&
          result.group_io_ops[0].fd == 0;
  shell_processed_commands_free(&result);

  /* Paired relations share one operator span but must still be returned
   * deterministically as source output followed by target input for both
   * ordinary and stderr-inclusive pipelines. */
  static const struct {
    const char *source;
    shell_group_io_kind_t output_kind;
  } sibling_pipelines[] = {
      {"{ echo one; } | { cat; }", SHELL_GROUP_IO_PIPE_OUTPUT},
      {"{ echo one; } |& { cat; }", SHELL_GROUP_IO_PIPE_OUTPUT_STDERR},
  };
  for (size_t pipeline = 0;
       valid &&
       pipeline < sizeof(sibling_pipelines) / sizeof(sibling_pipelines[0]);
       pipeline++) {
    for (size_t attempt = 0; valid && attempt < 8; attempt++) {
      memset(&result, 0, sizeof(result));
      status = shell_process_commands(
          sibling_pipelines[pipeline].source,
          strlen(sibling_pipelines[pipeline].source), NULL, &result);
      valid = status == SHELL_PROCESS_OK && result.command_count == 2 &&
              result.group_count == 2 && result.group_io_op_count == 2 &&
              result.group_io_ops[0].kind ==
                  sibling_pipelines[pipeline].output_kind &&
              result.group_io_ops[1].kind == SHELL_GROUP_IO_PIPE_INPUT &&
              result.group_io_ops[0].group_index !=
                  result.group_io_ops[1].group_index &&
              result.group_io_ops[0].source_start ==
                  result.group_io_ops[1].source_start &&
              result.group_io_ops[0].source_end ==
                  result.group_io_ops[1].source_end;
      shell_processed_commands_free(&result);
    }
  }

  /* A backslash-newline is removed before group-owned redirects and list
   * operators bind. Keep the structured metadata aligned with the fast parser
   * and graph when that continuation appears after the source group. */
  static const struct {
    const char *source;
    shell_group_io_kind_t output_kind;
    size_t operator_length;
  } continued_sibling_pipelines[] = {
      {"{ echo one; } \\\n| { cat; }", SHELL_GROUP_IO_PIPE_OUTPUT, 1},
      {"{ echo one; } \\\n|& { cat; }", SHELL_GROUP_IO_PIPE_OUTPUT_STDERR, 2},
  };
  for (size_t pipeline = 0;
       valid && pipeline < sizeof(continued_sibling_pipelines) /
                               sizeof(continued_sibling_pipelines[0]);
       pipeline++) {
    memset(&result, 0, sizeof(result));
    status = shell_process_commands(
        continued_sibling_pipelines[pipeline].source,
        strlen(continued_sibling_pipelines[pipeline].source), NULL, &result);
    valid = status == SHELL_PROCESS_OK && result.command_count == 2 &&
            result.group_count == 2 && result.group_io_op_count == 2 &&
            result.group_io_ops[0].kind ==
                continued_sibling_pipelines[pipeline].output_kind &&
            result.group_io_ops[1].kind == SHELL_GROUP_IO_PIPE_INPUT &&
            result.group_io_ops[0].group_index !=
                result.group_io_ops[1].group_index &&
            result.group_io_ops[0].source_start ==
                result.group_io_ops[1].source_start &&
            result.group_io_ops[0].source_end ==
                result.group_io_ops[1].source_end &&
            result.group_io_ops[0].source_end -
                    result.group_io_ops[0].source_start ==
                continued_sibling_pipelines[pipeline].operator_length;
    shell_processed_commands_free(&result);
  }

  /* Continuations may occur before the redirect list, between the operator
   * and its operand, or between adjacent redirects. None creates a new
   * command boundary. Exercise LF continuations at every boundary. */
  static const char continued_redirects[] =
      "{ echo one; } \\\n> \\\nout \\\n2> \\\nerr \\\n| cat";
  memset(&result, 0, sizeof(result));
  status = shell_process_commands(
      continued_redirects, sizeof(continued_redirects) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 2 &&
          result.group_count == 1 && result.group_io_op_count == 3 &&
          result.group_io_ops[0].kind == SHELL_GROUP_IO_WRITE_FILE &&
          result.group_io_ops[0].fd == 1 &&
          result.group_io_ops[1].kind == SHELL_GROUP_IO_WRITE_FILE &&
          result.group_io_ops[1].fd == 2 &&
          result.group_io_ops[2].kind == SHELL_GROUP_IO_PIPE_OUTPUT;
  shell_processed_commands_free(&result);

  static const char continued_background[] = "{ echo one; } \\\n&";
  memset(&result, 0, sizeof(result));
  status = shell_process_commands(
      continued_background, sizeof(continued_background) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 1 &&
          result.group_count == 1 && result.group_io_op_count == 1 &&
          result.group_io_ops[0].kind == SHELL_GROUP_IO_BACKGROUND;
  shell_processed_commands_free(&result);

  static const char ordinary_newline[] = "{ echo one; }\nprintf next";
  memset(&result, 0, sizeof(result));
  status = shell_process_commands(ordinary_newline,
                                  sizeof(ordinary_newline) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 2 &&
          result.group_count == 1 && result.group_io_op_count == 0;
  shell_processed_commands_free(&result);
  test("Processed groups retain their own redirect and pipeline metadata",
       valid);
}

static void tokenizer_test_processed_group_io_boundaries(void) {
  static const char mixed[] = "{ echo one; } 3>\"/tmp/trace file\" "
                              "0<prefix<(cat) 2>>>(cat)suffix 6>&1 4<&0 5>&-";
  static const shell_group_io_kind_t kinds[] = {
      SHELL_GROUP_IO_WRITE_FILE,  SHELL_GROUP_IO_READ_FILE,
      SHELL_GROUP_IO_APPEND_FILE, SHELL_GROUP_IO_DUP_FD,
      SHELL_GROUP_IO_DUP_FD,      SHELL_GROUP_IO_CLOSE_FD,
  };
  static const uint32_t fds[] = {3, 0, 2, 6, 4, 5};
  static const uint32_t targets[] = {UINT32_MAX, UINT32_MAX, UINT32_MAX,
                                     1,          0,          UINT32_MAX};
  shell_processed_commands_t result = {0};
  shell_process_status_t status =
      shell_process_commands(mixed, sizeof(mixed) - 1, NULL, &result);
  bool valid = status == SHELL_PROCESS_OK && result.group_count == 1 &&
               result.group_io_op_count == sizeof(kinds) / sizeof(kinds[0]);
  for (size_t i = 0; valid && i < result.group_io_op_count; i++) {
    const shell_group_io_op_t *op = &result.group_io_ops[i];
    valid =
        op->group_index == 0 && op->kind == kinds[i] && op->fd == fds[i] &&
        op->target_fd == targets[i] && op->source_start < op->source_end &&
        op->operand_start < op->operand_end &&
        (i == 0 || result.group_io_ops[i - 1].source_end <= op->source_start);
  }
  shell_processed_commands_free(&result);

  static const char named_continued[] =
      "{ printf value; } {f\\\nd}>/tmp/out >&\"$f\\\nd\"";
  memset(&result, 0, sizeof(result));
  status = shell_process_commands(named_continued, sizeof(named_continued) - 1,
                                  NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.group_count == 1 &&
          result.group_io_op_count == 2 &&
          result.group_io_ops[0].fd == SHELL_PROCESS_FD_NAMED &&
          result.group_io_ops[0].fd_name_start <
              result.group_io_ops[0].fd_name_end &&
          result.group_io_ops[1].kind == SHELL_GROUP_IO_DUP_FD &&
          result.group_io_ops[1].fd == 1 &&
          result.group_io_ops[1].target_fd == SHELL_PROCESS_FD_NONE &&
          result.group_io_ops[1].target_name_start <
              result.group_io_ops[1].target_name_end;
  shell_processed_commands_free(&result);

  /* A continuation immediately after `$` remains part of the same named-FD
   * parameter. Do not degrade it into Bash's legacy combined-output
   * redirect: the group owns a stdout-only descriptor duplication. */
  static const char named_braced_after_dollar[] =
      "{ printf value; } {sink}>/tmp/out >&$\\\n{sink}";
  const char *named_braced_after_dollar_reference =
      strstr(named_braced_after_dollar, "$\\\n{sink}");
  memset(&result, 0, sizeof(result));
  status = shell_process_commands(named_braced_after_dollar,
                                  sizeof(named_braced_after_dollar) - 1, NULL,
                                  &result);
  valid = valid && named_braced_after_dollar_reference != NULL &&
          status == SHELL_PROCESS_OK && result.group_count == 1 &&
          result.group_io_op_count == 2 &&
          result.group_io_ops[1].kind == SHELL_GROUP_IO_DUP_FD &&
          result.group_io_ops[1].fd == 1 &&
          result.group_io_ops[1].target_fd == SHELL_PROCESS_FD_NONE &&
          result.group_io_ops[1].target_name_start ==
              (uint32_t)(named_braced_after_dollar_reference -
                         named_braced_after_dollar + 4) &&
          result.group_io_ops[1].target_name_end ==
              (uint32_t)(named_braced_after_dollar_reference -
                         named_braced_after_dollar + 8);
  shell_processed_commands_free(&result);

  static const char maximum_descriptor[] =
      "{ cat; } 2147483647</tmp/maximum-input";
  memset(&result, 0, sizeof(result));
  status = shell_process_commands(
      maximum_descriptor, sizeof(maximum_descriptor) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 1 &&
          result.group_count == 1 && result.group_io_op_count == 1 &&
          result.group_io_ops[0].kind == SHELL_GROUP_IO_READ_FILE &&
          result.group_io_ops[0].fd == SHELL_DEP_FD_MAX;
  shell_processed_commands_free(&result);

  static const char nested[] =
      "{ :; { echo inner; } 3>/tmp/inner 4<&0; echo outer; } "
      "7>/tmp/outer 2>>/tmp/outer.err";
  status = shell_process_commands(nested, sizeof(nested) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.group_count == 2 &&
          result.group_io_op_count == 4 &&
          result.group_io_ops[0].group_index == 1 &&
          result.group_io_ops[0].kind == SHELL_GROUP_IO_WRITE_FILE &&
          result.group_io_ops[1].group_index == 1 &&
          result.group_io_ops[1].kind == SHELL_GROUP_IO_DUP_FD &&
          result.group_io_ops[1].fd == 4 &&
          result.group_io_ops[1].target_fd == 0 &&
          result.group_io_ops[2].group_index == 0 &&
          result.group_io_ops[2].kind == SHELL_GROUP_IO_WRITE_FILE &&
          result.group_io_ops[3].group_index == 0 &&
          result.group_io_ops[3].kind == SHELL_GROUP_IO_APPEND_FILE;
  shell_processed_commands_free(&result);

  shell_process_limits_t limits = {SIZE_MAX, SIZE_MAX, 6};
  status = shell_process_commands(mixed, sizeof(mixed) - 1, &limits, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.group_io_op_count == 6;
  shell_processed_commands_free(&result);
  limits.max_group_io_ops = 0;
  status = shell_process_commands(mixed, sizeof(mixed) - 1, &limits, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.group_io_op_count == 6;
  shell_processed_commands_free(&result);
  limits.max_group_io_ops = 5;
  result.commands = (shell_command_info_t *)(uintptr_t)1;
  result.command_count = SIZE_MAX;
  result.groups = (shell_group_t *)(uintptr_t)1;
  result.group_count = SIZE_MAX;
  result.group_io_ops = (shell_group_io_op_t *)(uintptr_t)1;
  result.group_io_op_count = SIZE_MAX;
  status = shell_process_commands(mixed, sizeof(mixed) - 1, &limits, &result);
  valid = valid && status == SHELL_PROCESS_EOUTPUT_LIMIT &&
          result.commands == NULL && result.command_count == 0 &&
          result.groups == NULL && result.group_count == 0 &&
          result.group_io_ops == NULL && result.group_io_op_count == 0;

  /* A group-owned `|&` contributes an ordered output/input pair, so its
   * second relation must observe the same output-limit and clearing contract
   * as ordinary redirects. */
  static const char pipe_both_limit[] = "{ printf left; } |& { cat; }";
  limits.max_group_io_ops = 2;
  status = shell_process_commands(pipe_both_limit, sizeof(pipe_both_limit) - 1,
                                  &limits, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.group_io_op_count == 2;
  shell_processed_commands_free(&result);
  limits.max_group_io_ops = 1;
  result.commands = (shell_command_info_t *)(uintptr_t)1;
  result.command_count = SIZE_MAX;
  result.groups = (shell_group_t *)(uintptr_t)1;
  result.group_count = SIZE_MAX;
  result.group_io_ops = (shell_group_io_op_t *)(uintptr_t)1;
  result.group_io_op_count = SIZE_MAX;
  status = shell_process_commands(pipe_both_limit, sizeof(pipe_both_limit) - 1,
                                  &limits, &result);
  valid = valid && status == SHELL_PROCESS_EOUTPUT_LIMIT &&
          result.commands == NULL && result.command_count == 0 &&
          result.groups == NULL && result.group_count == 0 &&
          result.group_io_ops == NULL && result.group_io_op_count == 0;

  static const char compact_limit[] = "{ echo; }>first>second";
  limits.max_group_io_ops = 2;
  status = shell_process_commands(compact_limit, sizeof(compact_limit) - 1,
                                  &limits, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.group_io_op_count == 2;
  shell_processed_commands_free(&result);
  limits.max_group_io_ops = 1;
  result.commands = (shell_command_info_t *)(uintptr_t)1;
  result.command_count = SIZE_MAX;
  result.groups = (shell_group_t *)(uintptr_t)1;
  result.group_count = SIZE_MAX;
  result.group_io_ops = (shell_group_io_op_t *)(uintptr_t)1;
  result.group_io_op_count = SIZE_MAX;
  status = shell_process_commands(compact_limit, sizeof(compact_limit) - 1,
                                  &limits, &result);
  valid = valid && status == SHELL_PROCESS_EOUTPUT_LIMIT &&
          result.commands == NULL && result.command_count == 0 &&
          result.groups == NULL && result.group_count == 0 &&
          result.group_io_ops == NULL && result.group_io_op_count == 0;

  /* The fifth operation is the first one in the outer group's trailing
   * redirect segment. Its capacity failure must not be mistaken for the
   * ordinary end-of-redirect-list parse boundary. */
  static const char nested_limit[] =
      "{ :; { :; { cat one; cat two; cat three; } 40>/tmp/nested-out-0; "
      "cat nested; } 21>/tmp/nested-in-1 20>/tmp/nested-in-0; cat nested; } "
      "41>/tmp/nested-out-1 <<< \"two words\" && printf tail";
  limits.max_group_io_ops = 5;
  status = shell_process_commands(nested_limit, sizeof(nested_limit) - 1,
                                  &limits, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.group_io_op_count == 5;
  shell_processed_commands_free(&result);
  limits.max_group_io_ops = 4;
  result.commands = (shell_command_info_t *)(uintptr_t)1;
  result.command_count = SIZE_MAX;
  result.groups = (shell_group_t *)(uintptr_t)1;
  result.group_count = SIZE_MAX;
  result.group_io_ops = (shell_group_io_op_t *)(uintptr_t)1;
  result.group_io_op_count = SIZE_MAX;
  status = shell_process_commands(nested_limit, sizeof(nested_limit) - 1,
                                  &limits, &result);
  valid = valid && status == SHELL_PROCESS_EOUTPUT_LIMIT &&
          result.commands == NULL && result.command_count == 0 &&
          result.groups == NULL && result.group_count == 0 &&
          result.group_io_ops == NULL && result.group_io_op_count == 0;

  shellsplit_test_alloc_reset();
  status = shell_process_commands(mixed, sizeof(mixed) - 1, NULL, &result);
  size_t allocations = shellsplit_test_alloc_count();
  shell_processed_commands_free(&result);
  valid = valid && status == SHELL_PROCESS_OK && allocations > 0;
  bool allocation_failures_atomic = true;
  for (size_t fail_at = 1; valid && fail_at <= allocations; fail_at++) {
    result.commands = (shell_command_info_t *)(uintptr_t)1;
    result.command_count = SIZE_MAX;
    result.groups = (shell_group_t *)(uintptr_t)1;
    result.group_count = SIZE_MAX;
    result.group_io_ops = (shell_group_io_op_t *)(uintptr_t)1;
    result.group_io_op_count = SIZE_MAX;
    shellsplit_test_alloc_fail_at(fail_at);
    status = shell_process_commands(mixed, sizeof(mixed) - 1, NULL, &result);
    shellsplit_test_alloc_reset();
    if (status == SHELL_PROCESS_OK) {
      allocation_failures_atomic = false;
      shell_processed_commands_free(&result);
      break;
    }
    allocation_failures_atomic =
        allocation_failures_atomic && status == SHELL_PROCESS_ENOMEM &&
        result.commands == NULL && result.command_count == 0 &&
        result.groups == NULL && result.group_count == 0 &&
        result.group_io_ops == NULL && result.group_io_op_count == 0;
  }
  shellsplit_test_alloc_reset();
  test("Processed group operations enforce limits and fail atomically",
       valid && allocation_failures_atomic);
}

static void
tokenizer_test_group_combined_named_redirect_and_document_contract(void) {
  shell_processed_commands_t result = {0};
  shell_process_status_t status;
  bool valid = true;

  static const struct {
    const char *source;
    shell_group_io_kind_t kind;
  } combined[] = {
      {"{ printf x; } &>combined", SHELL_GROUP_IO_WRITE_FILE},
      {"( printf x ) &>>combined", SHELL_GROUP_IO_APPEND_FILE},
      {"{ printf x; } &> >(cat)", SHELL_GROUP_IO_PROCESS_SUB_OUT},
      {"{ printf x; } >&combined", SHELL_GROUP_IO_WRITE_FILE},
      {"{ printf x; } >&123file", SHELL_GROUP_IO_WRITE_FILE},
      {"{ printf x; } >&literal$destination", SHELL_GROUP_IO_WRITE_FILE},
      {"{ printf x; } >&\"\"literal$(printf target)",
       SHELL_GROUP_IO_WRITE_FILE},
      {"( printf x ) 1>&combined", SHELL_GROUP_IO_WRITE_FILE},
      {"{ printf x; } >& >(cat)", SHELL_GROUP_IO_PROCESS_SUB_OUT},
  };
  for (size_t i = 0; valid && i < sizeof(combined) / sizeof(combined[0]); i++) {
    status = shell_process_commands(combined[i].source,
                                    strlen(combined[i].source), NULL, &result);
    valid = status == SHELL_PROCESS_OK && result.group_count == 1 &&
            result.group_io_op_count == 2 &&
            result.group_io_ops[0].kind == combined[i].kind &&
            result.group_io_ops[1].kind == combined[i].kind &&
            result.group_io_ops[0].fd == 1 && result.group_io_ops[1].fd == 2 &&
            result.group_io_ops[0].source_start ==
                result.group_io_ops[1].source_start &&
            result.group_io_ops[0].source_end ==
                result.group_io_ops[1].source_end &&
            result.group_io_ops[0].operand_start ==
                result.group_io_ops[1].operand_start &&
            result.group_io_ops[0].operand_end ==
                result.group_io_ops[1].operand_end;
    shell_processed_commands_free(&result);
  }

  /* An unquoted close marker ends the redirect even when text follows it.
   * That text cannot form a redirect-only group tail, so the complete source
   * is invalid rather than a combined-output redirect to `-file`. */
  status = shell_process_commands(
      "{ printf x; } >&-file", strlen("{ printf x; } >&-file"), NULL, &result);
  valid = valid && status == SHELL_PROCESS_EPARSE && result.commands == NULL &&
          result.command_count == 0 && result.groups == NULL &&
          result.group_count == 0 && result.group_io_ops == NULL &&
          result.group_io_op_count == 0;
  shell_processed_commands_free(&result);

  static const char combined_pipeline[] = "{ printf x; } &>combined | cat";
  status = shell_process_commands(combined_pipeline,
                                  sizeof(combined_pipeline) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 2 &&
          result.group_count == 1 && result.group_io_op_count == 3 &&
          result.group_io_ops[0].fd == 1 && result.group_io_ops[1].fd == 2 &&
          result.group_io_ops[2].kind == SHELL_GROUP_IO_PIPE_OUTPUT;
  shell_processed_commands_free(&result);

  static const char named[] =
      "{ printf x; } {input}<in {output}>out {both}<>state";
  status = shell_process_commands(named, sizeof(named) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.group_count == 1 &&
          result.group_io_op_count == 3 &&
          result.group_io_ops[0].kind == SHELL_GROUP_IO_READ_FILE &&
          result.group_io_ops[1].kind == SHELL_GROUP_IO_WRITE_FILE &&
          result.group_io_ops[2].kind == SHELL_GROUP_IO_READ_WRITE_FILE;
  for (size_t i = 0; valid && i < result.group_io_op_count; i++)
    valid = result.group_io_ops[i].fd == SHELL_PROCESS_FD_NAMED &&
            result.group_io_ops[i].target_fd == SHELL_PROCESS_FD_NONE;
  shell_processed_commands_free(&result);

  /* A named descriptor is consumed through an exact parameter word, rather
   * than treating `$sink` as a raw filename.  Retain the source spans for the
   * allocator and the deferred lookup independently. */
  static const char named_parameter[] =
      "{ printf x; } {sink}>out >&\"${sink}\"";
  const char *sink_declaration = strstr(named_parameter, "{sink}");
  const char *sink_reference = strstr(named_parameter, "${sink}");
  status = shell_process_commands(named_parameter, sizeof(named_parameter) - 1,
                                  NULL, &result);
  bool named_parameter_valid =
      sink_declaration != NULL && sink_reference != NULL &&
      status == SHELL_PROCESS_OK && result.group_count == 1 &&
      result.group_io_op_count == 2 &&
      result.group_io_ops[0].fd == SHELL_PROCESS_FD_NAMED &&
      result.group_io_ops[0].kind == SHELL_GROUP_IO_WRITE_FILE &&
      result.group_io_ops[1].fd == 1 &&
      result.group_io_ops[1].kind == SHELL_GROUP_IO_DUP_FD &&
      result.group_io_ops[1].target_fd == SHELL_PROCESS_FD_NONE &&
      result.group_io_ops[0].fd_name_start ==
          (uint32_t)(sink_declaration - named_parameter) &&
      result.group_io_ops[0].fd_name_end ==
          (uint32_t)(sink_declaration - named_parameter + strlen("{sink}")) &&
      result.group_io_ops[1].target_name_start ==
          (uint32_t)(sink_reference - named_parameter + 2) &&
      result.group_io_ops[1].target_name_end ==
          (uint32_t)(sink_reference - named_parameter + strlen("${sink}") - 1);
  valid = valid && named_parameter_valid;
  shell_processed_commands_free(&result);

  static const char named_lifecycle[] =
      "{ printf x; } {input}<&0 {output}>&1 {closed}>&- {sink}> >(cat)";
  status = shell_process_commands(named_lifecycle, sizeof(named_lifecycle) - 1,
                                  NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.group_count == 1 &&
          result.group_io_op_count == 4 &&
          result.group_io_ops[0].kind == SHELL_GROUP_IO_DUP_FD &&
          result.group_io_ops[0].fd == SHELL_PROCESS_FD_NAMED &&
          result.group_io_ops[0].target_fd == 0 &&
          result.group_io_ops[1].kind == SHELL_GROUP_IO_DUP_FD &&
          result.group_io_ops[1].fd == SHELL_PROCESS_FD_NAMED &&
          result.group_io_ops[1].target_fd == 1 &&
          result.group_io_ops[2].kind == SHELL_GROUP_IO_CLOSE_FD &&
          result.group_io_ops[2].fd == SHELL_PROCESS_FD_NAMED &&
          result.group_io_ops[3].kind == SHELL_GROUP_IO_PROCESS_SUB_OUT &&
          result.group_io_ops[3].fd == SHELL_PROCESS_FD_NAMED;
  shell_processed_commands_free(&result);

  /* Named descriptor documents have the same dynamic descriptor identity as
   * named file redirects, but their operand span is the declaration word,
   * never the deferred heredoc body. */
  static const struct {
    const char *source;
    shell_group_io_kind_t kind;
    const char *operand;
  } named_documents[] = {
      {"{ cat; } {fd}<<<payload", SHELL_GROUP_IO_HERESTRING, "payload"},
      {"{ cat; } {fd}<<EOF\nbody\nEOF\n", SHELL_GROUP_IO_HEREDOC, "EOF"},
  };
  for (size_t i = 0;
       valid && i < sizeof(named_documents) / sizeof(named_documents[0]); i++) {
    const char *source = named_documents[i].source;
    const char *redirect = strstr(source, "{fd}");
    const char *operand = strstr(redirect, named_documents[i].operand);
    status = shell_process_commands(source, strlen(source), NULL, &result);
    valid =
        redirect != NULL && operand != NULL && status == SHELL_PROCESS_OK &&
        result.command_count == 1 && result.group_count == 1 &&
        result.group_io_op_count == 1 &&
        result.group_io_ops[0].kind == named_documents[i].kind &&
        result.group_io_ops[0].fd == SHELL_PROCESS_FD_NAMED &&
        result.group_io_ops[0].target_fd == SHELL_PROCESS_FD_NONE &&
        result.group_io_ops[0].source_start == (uint32_t)(redirect - source) &&
        result.group_io_ops[0].source_end ==
            (uint32_t)(operand - source + strlen(named_documents[i].operand)) &&
        result.group_io_ops[0].operand_start == (uint32_t)(operand - source) &&
        result.group_io_ops[0].operand_end ==
            (uint32_t)(operand - source + strlen(named_documents[i].operand));
    shell_processed_commands_free(&result);
  }

  static const char named_document_pipeline[] =
      "{ cat; } {fd}<<<payload |& sed x";
  status = shell_process_commands(named_document_pipeline,
                                  sizeof(named_document_pipeline) - 1, NULL,
                                  &result);
  valid =
      valid && status == SHELL_PROCESS_OK && result.command_count == 2 &&
      result.group_count == 1 && result.group_io_op_count == 2 &&
      result.group_io_ops[0].kind == SHELL_GROUP_IO_HERESTRING &&
      result.group_io_ops[0].fd == SHELL_PROCESS_FD_NAMED &&
      result.group_io_ops[1].kind == SHELL_GROUP_IO_PIPE_OUTPUT_STDERR &&
      result.group_io_ops[0].source_start < result.group_io_ops[1].source_start;
  shell_processed_commands_free(&result);

  static const char *const unsupported[] = {
      "{ cat; } {fd}<<<",
      "{ cat; } {fd}<<EOF\nbody\n",
      "{ printf x; } 2&>combined",
      "{ printf x; } 3&>>combined",
      "{ printf x; } {fd}&>combined",
  };
  for (size_t i = 0; valid && i < sizeof(unsupported) / sizeof(unsupported[0]);
       i++) {
    result.commands = (shell_command_info_t *)(uintptr_t)1;
    result.command_count = SIZE_MAX;
    result.groups = (shell_group_t *)(uintptr_t)1;
    result.group_count = SIZE_MAX;
    result.group_io_ops = (shell_group_io_op_t *)(uintptr_t)1;
    result.group_io_op_count = SIZE_MAX;
    status = shell_process_commands(unsupported[i], strlen(unsupported[i]),
                                    NULL, &result);
    valid = status == SHELL_PROCESS_EPARSE && result.commands == NULL &&
            result.command_count == 0 && result.groups == NULL &&
            result.group_count == 0 && result.group_io_ops == NULL &&
            result.group_io_op_count == 0;
  }

  shell_process_limits_t document_limit = {SIZE_MAX, SIZE_MAX, 1};
  status = shell_process_commands(named_document_pipeline,
                                  sizeof(named_document_pipeline) - 1,
                                  &document_limit, &result);
  valid = valid && status == SHELL_PROCESS_EOUTPUT_LIMIT &&
          result.commands == NULL && result.command_count == 0 &&
          result.groups == NULL && result.group_count == 0 &&
          result.group_io_ops == NULL && result.group_io_op_count == 0;

  shell_process_limits_t limits = {SIZE_MAX, SIZE_MAX, 2};
  static const char combined_limit[] = "{ printf x; } &>combined";
  status = shell_process_commands(combined_limit, sizeof(combined_limit) - 1,
                                  &limits, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.group_io_op_count == 2;
  shell_processed_commands_free(&result);
  limits.max_group_io_ops = 1;
  status = shell_process_commands(combined_limit, sizeof(combined_limit) - 1,
                                  &limits, &result);
  valid = valid && status == SHELL_PROCESS_EOUTPUT_LIMIT &&
          result.commands == NULL && result.command_count == 0 &&
          result.groups == NULL && result.group_count == 0 &&
          result.group_io_ops == NULL && result.group_io_op_count == 0;
  test("Combined, named, and document group I/O preserves exact metadata",
       valid);
}

static void tokenizer_test_combined_redirect_prefix_word_contract(void) {
  static const struct {
    const char *source;
    const char *netargv;
  } direct[] = {
      {"printf x 2&>combined", "6:printf,1:x,1:2,"},
      {"printf x 3&>>combined", "6:printf,1:x,1:3,"},
      {"printf x {fd}&>combined", "6:printf,1:x,4:{fd},"},
      {"printf x >&combined", "6:printf,1:x,"},
      {"printf x 1>&combined", "6:printf,1:x,"},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(direct) / sizeof(direct[0]); i++) {
    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    shell_netstring_buffer_t netargv = {0};
    shell_process_status_t status = shell_process_command(
        direct[i].source, strlen(direct[i].source), NULL, &infos, &info_count);
    valid = status == SHELL_PROCESS_OK && infos != NULL && info_count == 1 &&
            infos[0].has_redirections && infos[0].has_error_redirection &&
            shell_render_netargv_buffer(&infos[0], NULL, &netargv) ==
                SHELL_PROCESS_OK &&
            netargv.data != NULL &&
            (netargv.length != strlen(direct[i].netargv) ||
             memcmp(netargv.data, direct[i].netargv, netargv.length)) == 0;
    shell_netstring_buffer_free(&netargv);
    shell_command_infos_free(infos, info_count);
  }

  /* A compound group accepts only a redirect list after its delimiter. The
   * same prefix words that remain argv data in a simple command consequently
   * make the group form invalid, and every structured output is cleared. */
  static const char *const invalid_groups[] = {
      "{ printf x; } 2&>combined",
      "{ printf x; } 3&>>combined",
      "{ printf x; } {fd}&>combined",
      "{ printf x; } >&",
      "{ printf x; } <>&1",
      "{ printf x; } 999999999999>out",
      "{ printf x; } >&2147483648",
      "{ printf x; } >&00000000000000000000000000000000002147483648",
      "{ printf x; } >&$'2147483648'",
      "{ printf x; } >& >(cat",
  };
  for (size_t i = 0;
       valid && i < sizeof(invalid_groups) / sizeof(invalid_groups[0]); i++) {
    shell_processed_commands_t processed = {
        .commands = (shell_command_info_t *)(uintptr_t)1,
        .command_count = SIZE_MAX,
        .groups = (shell_group_t *)(uintptr_t)1,
        .group_count = SIZE_MAX,
        .group_io_ops = (shell_group_io_op_t *)(uintptr_t)1,
        .group_io_op_count = SIZE_MAX,
    };
    shell_process_status_t status = shell_process_commands(
        invalid_groups[i], strlen(invalid_groups[i]), NULL, &processed);
    valid = status == SHELL_PROCESS_EPARSE && processed.commands == NULL &&
            processed.command_count == 0 && processed.groups == NULL &&
            processed.group_count == 0 && processed.group_io_ops == NULL &&
            processed.group_io_op_count == 0;
  }
  test("Combined redirects never consume descriptor-looking prefix words",
       valid);
}

/* Wider conditional predicates and mutating arithmetic are unsupported
 * compounds. Their punctuation may be separated only by physical continuations,
 * which shell removes before recognizing the command. Every public semantic
 * adapter must reject that source atomically. */
static void tokenizer_test_continued_bash_compound_syntax_contract(void) {
  static const char *const unsupported[] = {
      "(\\\n( count += 1 ))",
      "(\\\n( count += 1 ))",
      "(\\\n( count += 1 ))",
      "[\\\n[ file " SHELLSPLIT_TEST_UNMODELED_BINARY_WORD " other ]]",
      "[\\\n[ file " SHELLSPLIT_TEST_UNMODELED_BINARY_WORD " other ]]",
      "[[\\\n file " SHELLSPLIT_TEST_UNMODELED_BINARY_WORD " other ]]",
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
    shell_command_info_t *infos = (shell_command_info_t *)(uintptr_t)1;
    size_t info_count = SIZE_MAX;
    shell_processed_commands_t processed = {
        .commands = (shell_command_info_t *)(uintptr_t)1,
        .command_count = SIZE_MAX,
    };
    shell_transformed_command_t **transformed =
        (shell_transformed_command_t **)(uintptr_t)1;
    size_t transformed_count = SIZE_MAX;
    valid =
        valid &&
        shell_tokenizer_has_unsupported_semantics(unsupported[i],
                                                  strlen(unsupported[i])) &&
        shell_process_validate_supported_source(unsupported[i],
                                                strlen(unsupported[i]),
                                                NULL) == SHELL_PROCESS_EPARSE &&
        shell_process_command(unsupported[i], strlen(unsupported[i]), NULL,
                              &infos, &info_count) == SHELL_PROCESS_EPARSE &&
        infos == NULL && info_count == 0 &&
        shell_process_commands(unsupported[i], strlen(unsupported[i]), NULL,
                               &processed) == SHELL_PROCESS_EPARSE &&
        processed.commands == NULL && processed.command_count == 0 &&
        shell_transform_command_line(unsupported[i], strlen(unsupported[i]),
                                     NULL, &transformed, &transformed_count) ==
            SHELL_TRANSFORM_EPARSE &&
        transformed == NULL && transformed_count == 0;
    shell_command_infos_free(infos, info_count);
    shell_processed_commands_free(&processed);
    shell_transformed_command_list_free(transformed, transformed_count);
  }

  static const char external_word[] = "[[\\\nliteral";
  valid =
      valid &&
      !shell_tokenizer_has_unsupported_semantics(external_word,
                                                 sizeof(external_word) - 1) &&
      shell_process_validate_supported_source(
          external_word, sizeof(external_word) - 1, NULL) == SHELL_PROCESS_OK;
  test("Continued Bash compound commands remain unsupported", valid);
}

static void
tokenizer_test_current_shell_metaprogramming_semantic_contract(void) {
  /* The strict model must never accept a known builtin that can run a second
   * current-shell program, defer one to a handler, replay one, or alter later
   * command lookup. Quote removal, prefixes, and wrappers do not hide that
   * role. */
  static const char *const unsupported[] = {
      "eval 'shopt -s lastpipe'",
      "let result=1",
      "let 'values[$(printf 0)]=1'",
      ". /tmp/shell-state",
      "source /tmp/shell-state",
      "trap 'shopt -s lastpipe' DEBUG",
      "alias change_scope='shopt -s lastpipe'",
      "unalias change_scope",
      "history -s 'shopt -s lastpipe'; fc -s -1",
      "enable -f /tmp/shell-state change_scope",
      "shopt -s expand_aliases",
      "shopt -u expand_aliases",
      "shopt -s extglob",
      "shopt -u execfail",
      "state=1 eval 'shopt -u varredir_close'",
      "command eval 'shopt -s lastpipe'",
      "builtin source /tmp/shell-state",
      "command command eval 'shopt -s lastpipe'",
      "command builtin source /tmp/shell-state",
      "builtin command trap - DEBUG",
      "command trap - DEBUG",
      "builtin alias scope='printf x'",
      "command fc -s -1",
      "builtin enable -n printf",
      "e'val' 'shopt -s lastpipe'",
      "s'ource' /tmp/shell-state",
      "tr'ap' 'shopt -s lastpipe' DEBUG",
      "set -o posix",
      "set -e",
      "set +e",
      "set -o nounset",
      "set +o pipefail",
      "command -p set -o posix",
      "builtin set '-o' po'six'",
      "s'et' -o po\\\nsix",
      "shopt -s -o posix",
      "shopt -so posix",
      "shopt -os posix",
      "command shopt -s -o posix",
      "builtin command shopt '-so' po'six'",
      "shopt -s -o po\\\nsix",
      "shopt -s -o \"$option\"",
      /* A dynamic option name may expand to `posix`, so the conservative
       * source gate must reject it before the current shell can change mode. */
      "set -o \"$option\"",
      "set \"$option\"",
      "POSIXLY_CORRECT=1",
      "POSIXLY_CORRECT=1 true",
      "POSIXLY_CORRECT=\"1\" true",
      "export POSIXLY_CORRECT=1",
      "BASH_COMPAT=42",
      "BASH_XTRACEFD=9",
      "export BASH_COMPAT=42",
      "printf -v BASH_XTRACEFD 9",
      "export POSIXLY_CORRECT=\"1\"",
      "export \"POSIXLY_CORRECT=1\"",
      "export PO\"SIXLY_CORRECT\"=1",
      "export \"POSIXLY_CORRECT+=1\"",
      "export $'POSIXLY_CORRECT'=1",
      "e$'val\\0x' 'printf bypass'",
      "command e$'val\\x00x' 'printf bypass'",
      "export $'POSIXLY_CORRECT\\0X'=1",
      "printf $'\\u00e9'",
      "printf \"${value:-$'a\\0b'}\"",
      "declare POSIXLY_CORRECT=1",
      "declare 'POSIXLY_CORRECT=1'",
      "export $'NAME\\x3dvalue'",
      "target='POSIXLY_CORRECT=1'; declare \"$target\"",
      "target='POSIXLY_CORRECT=1'; typeset \"$target\"",
      "target='POSIXLY_CORRECT=1'; local \"$target\"",
      "target='POSIXLY_CORRECT=1'; export \"$target\"",
      "target='POSIXLY_CORRECT=1'; command -p declare \"$target\"",
      "target='POSIXLY_CORRECT=1'; builtin export \"$target\"",
      "target='POSIXLY_CORRECT=1'; command builtin export \"$target\"",
      "printf -v POSIXLY_CORRECT enabled",
      "printf -vPOSIXLY_CORRECT enabled",
      "printf -v \"$target\" enabled",
      "printf -v\"$target\" enabled",
      "printf -v${target} enabled",
      "printf '-v'\"$target\" enabled",
      /* Array-producing builtin forms and array targets are intentionally
       * outside the scalar current-shell model. `mapfile -C` additionally
       * evaluates callback source in the current shell. */
      "mapfile values </tmp/input",
      "readarray values </tmp/input",
      "mapfile -c 1 -C 'printf callback' values </tmp/input",
      "read -a values",
      "printf -v 'fd[0]' 9",
      "printf -vfd[0] 9",
      "printf -v $'fd[0]' 9",
      /* `wait -p` writes the completed job identifier into its variable. */
      "wait -p fd",
      "wait -n -p fd",
      "wait \"$wait_options\"",
      /* Arithmetic expansion executes in the current shell. Only a static
       * numeric expression is modeled: Bash may recursively evaluate a
       * variable or command-substitution result as arithmetic source. */
      ": $((fd=9))",
      ": $((fd+=1))",
      ": $((++fd))",
      ": $((fd--))",
      ": $((fd1++))",
      ": $((fd\\\n++))",
      ": $((++\\\nfd))",
      ": $((array[0]++))",
      ": $(( $((fd=9)) + 1 ))",
      ": $((fd\\\n=9))",
      ": $((fd))",
      ": $(( ${fd} ))",
      ": $(( $(printf 'fd=12') ))",
      ": $((`printf fd=12`))",
      ": $((08))",
      ": $((2#2))",
      ": $((1 2))",
      ": $((1 + ))",
      ": $((1++))",
      ": $((1 @ 2))",
      "cat <<EOF\n$((fd=9))\nEOF\n",
      "pushd /tmp",
      "popd",
      "command pushd /tmp",
      "builtin popd",
      "declare -n ref=fd",
      "typeset +n ref=fd",
      "command -p readonly -n ref=fd",
      "builtin command readonly -n ref=fd",
      /* Declaration operands retain array meaning after quote removal and
       * across nested or dynamic subscript syntax. These are unsupported even
       * though each outer declaration is otherwise a simple command. */
      "declare values[index[nested]]=value",
      "declare $'values'[slot]=value",
      "declare values[${slot}]=value",
      "declare values[$((slot))]=value",
      "declare values[$(printf slot)]=value",
      "printf \"$(set -o posix)\"",
      "cat <(declare -n ref=fd)",
      "cat <<EOF\n$(printf -v POSIXLY_CORRECT enabled)\nEOF\n",
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    shell_processed_commands_t processed = {0};
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    valid =
        valid &&
        shell_tokenizer_has_unsupported_semantics(unsupported[i],
                                                  strlen(unsupported[i])) &&
        shell_process_validate_supported_source(unsupported[i],
                                                strlen(unsupported[i]),
                                                NULL) == SHELL_PROCESS_EPARSE &&
        shell_process_command(unsupported[i], strlen(unsupported[i]), NULL,
                              &infos, &info_count) == SHELL_PROCESS_EPARSE &&
        infos == NULL && info_count == 0 &&
        shell_process_commands(unsupported[i], strlen(unsupported[i]), NULL,
                               &processed) == SHELL_PROCESS_EPARSE &&
        processed.commands == NULL && processed.command_count == 0 &&
        shell_transform_command_line(unsupported[i], strlen(unsupported[i]),
                                     NULL, &transformed, &transformed_count) ==
            SHELL_TRANSFORM_EPARSE &&
        transformed == NULL && transformed_count == 0;
    shell_command_infos_free(infos, info_count);
    shell_processed_commands_free(&processed);
    shell_transformed_command_list_free(transformed, transformed_count);
  }

  static const char *const supported[] = {
      "printf eval . source",
      "printf 'eval' '.' source",
      "printf '$\\0b'",
      "printf \"$'a\\0b'\"",
      "cat <<EOF\n$'a\\0b'\nEOF\n",
      "shopt -q lastpipe",
      "shopt -q expand_aliases",
      "printf $runner",
      "runner=eval; $runner 'shopt -s lastpipe'",
      "shopt -q -o posix",
      "command -v set -o posix",
      /* `--` ends option parsing. It must not make a later positional word
       * select an option, and bare `declare --` remains a query. */
      "set -- positional",
      "declare --",
      "printf '%s' -v POSIXLY_CORRECT",
      "printf -- -v POSIXLY_CORRECT",
      "printf -v ordinary value",
      "printf -vordinary value",
      "printf -v 3 ignored",
      "read -r value",
      "wait -n",
      "getopts ab choice",
      ": $((1 + 2))",
      ": $((1--2))",
      ": $((1 == 1))",
      ": $((1 <= 2))",
      ": $((0x10 + 2))",
      ": $((0x))",
      ": $((2#1010 + 8#17 + 16#ff + 36#Z + 37#A + 64#_@))",
      ": $((1 ? 2, 3 : 4))",
      ": $((2**3 + (4 << 1)))",
      ": $((1 + $((2))))",
      ": $((1 + \\\n2))",
      ": $((1 \\\n))",
      "declare ordinary=value",
      "typeset ordinary=value",
      "export ordinary=value",
      "declare ordinary=$(printf value)",
      "typeset ordinary=$(printf value)",
      "local ordinary=$(printf value)",
      "export ordinary=$(printf value)",
      "export ordinary=\"$(printf value)\"",
      "export \"ordinary=$(printf value)\"",
      "declare or'dinary'=\"$(printf value)\"",
      "export $'ordinary'=\"$(printf value)\"",
  };
  for (size_t i = 0; valid && i < sizeof(supported) / sizeof(supported[0]); i++)
    valid = !shell_tokenizer_has_unsupported_semantics(supported[i],
                                                       strlen(supported[i])) &&
            shell_process_validate_supported_source(
                supported[i], strlen(supported[i]), NULL) == SHELL_PROCESS_OK;
  test("Current-shell metaprogramming is unsupported", valid);
}

/* The resolver models descriptor values, not shell-variable attributes. A
 * readonly declaration can make a later named-FD allocation fail while keeping
 * the old descriptor binding alive, so every state-changing spelling must be
 * rejected before any public producer can expose a partial result. */
static void tokenizer_test_readonly_named_fd_semantic_contract(void) {
  static const char *const unsupported[] = {
      "readonly fd; exec {fd}>/tmp/second; printf bytes >&$fd",
      "readonly fd=locked; exec {fd}>/tmp/second; printf bytes >&$fd",
      "readonly \"$target\"; exec {fd}>/tmp/second; printf bytes >&$fd",
      "read\\\nonly fd; exec {fd}>/tmp/second; printf bytes >&$fd",
      "declare -r fd; exec {fd}>/tmp/second; printf bytes >&$fd",
      "typeset -r fd; exec {fd}>/tmp/second; printf bytes >&$fd",
      "declare -r fd=locked; exec {fd}>/tmp/second; printf bytes >&$fd",
      "command -p readonly fd; exec {fd}>/tmp/second; printf bytes >&$fd",
      "builtin readonly fd; exec {fd}>/tmp/second; printf bytes >&$fd",
      "command -p declare -r fd; exec {fd}>/tmp/second; printf bytes >&$fd",
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
    /* A failed expectation must leave cleanup safe even if a later producer
     * call is skipped by short-circuit evaluation. */
    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    bool case_valid =
        shell_tokenizer_has_unsupported_semantics(unsupported[i],
                                                  strlen(unsupported[i])) &&
        shell_process_validate_supported_source(unsupported[i],
                                                strlen(unsupported[i]),
                                                NULL) == SHELL_PROCESS_EPARSE &&
        shell_process_command(unsupported[i], strlen(unsupported[i]), NULL,
                              &infos, &info_count) == SHELL_PROCESS_EPARSE &&
        infos == NULL && info_count == 0 &&
        shell_transform_command_line(unsupported[i], strlen(unsupported[i]),
                                     NULL, &transformed, &transformed_count) ==
            SHELL_TRANSFORM_EPARSE &&
        transformed == NULL && transformed_count == 0;
    if (!case_valid)
      fprintf(stderr, "readonly mutation case failed: %s\n", unsupported[i]);
    valid = case_valid && valid;
    shell_command_infos_free(infos, info_count);
    shell_transformed_command_list_free(transformed, transformed_count);
  }

  static const char *const supported[] = {
      "readonly", "readonly -p", "readonly --", "declare -r", "typeset -r",
  };
  for (size_t i = 0; valid && i < sizeof(supported) / sizeof(supported[0]); i++)
    valid = !shell_tokenizer_has_unsupported_semantics(supported[i],
                                                       strlen(supported[i])) &&
            shell_process_validate_supported_source(
                supported[i], strlen(supported[i]), NULL) == SHELL_PROCESS_OK;
  test("Readonly descriptor mutations are unsupported atomically", valid);
}

static size_t tokenizer_render_nested_brace_heredoc(char *output,
                                                    uint32_t depth) {
  size_t length = 0;
  for (uint32_t i = 0; i < depth; i++) {
    memcpy(output + length, "{ ", 2);
    length += 2;
  }
  memcpy(output + length, "cat", 3);
  length += 3;
  for (uint32_t i = 0; i < depth; i++) {
    memcpy(output + length, "; }", 3);
    length += 3;
  }
  memcpy(output + length, " <<EOF\nbody\nEOF", sizeof(" <<EOF\nbody\nEOF"));
  return length + sizeof(" <<EOF\nbody\nEOF") - 1;
}

static void tokenizer_test_brace_group_maximum_contract(void) {
  char input[(SHELL_MAX_GROUPS + 1) * 5 + 32];
  size_t length =
      tokenizer_render_nested_brace_heredoc(input, SHELL_MAX_GROUPS);
  shell_parse_result_t fast = {0};
  shell_command_t *commands = NULL;
  size_t command_count = 0;
  shell_processed_commands_t processed = {0};
  shell_dep_graph_t graph = {0};
  shell_error_t fast_error = shell_parse_fast(input, length, NULL, &fast);
  shell_tokenize_status_t tokenize_error =
      shell_tokenize_commands(input, length, &commands, &command_count);
  shell_process_status_t process_error =
      shell_process_commands(input, length, NULL, &processed);
  shell_dep_error_t dep_error =
      shell_dep_graph_parse(input, length, ".", NULL, &graph);
  shell_dep_graph_validation_t graph_validation =
      shell_dep_graph_validate(&graph);
  bool valid = fast_error == SHELL_OK && fast.group_count == SHELL_MAX_GROUPS &&
               tokenize_error == SHELL_TOKENIZE_OK && command_count != 0 &&
               command_count <= SHELL_MAX_SUBCOMMANDS &&
               process_error == SHELL_PROCESS_OK &&
               processed.command_count != 0 &&
               processed.command_count <= SHELL_MAX_SUBCOMMANDS &&
               processed.group_count == SHELL_MAX_GROUPS &&
               dep_error == SHELL_DEP_OK && graph_validation.valid;
  shell_commands_free(commands, command_count);
  shell_processed_commands_free(&processed);

  length = tokenizer_render_nested_brace_heredoc(input, SHELL_MAX_GROUPS + 1);
  commands = (shell_command_t *)(uintptr_t)1;
  command_count = SIZE_MAX;
  processed.commands = (shell_command_info_t *)(uintptr_t)1;
  processed.command_count = 1;
  processed.groups = (shell_group_t *)(uintptr_t)1;
  processed.group_count = 1;
  processed.group_io_ops = (shell_group_io_op_t *)(uintptr_t)1;
  processed.group_io_op_count = 1;
  memset(&fast, 0, sizeof(fast));
  fast_error = shell_parse_fast(input, length, NULL, &fast);
  tokenize_error =
      shell_tokenize_commands(input, length, &commands, &command_count);
  process_error = shell_process_commands(input, length, NULL, &processed);
  dep_error = shell_dep_graph_parse(input, length, ".", NULL, &graph);
  bool rejected =
      fast_error == SHELL_ETRUNC && fast.status == SHELL_STATUS_TRUNCATED &&
      !fast.count && !fast.group_count &&
      tokenize_error == SHELL_TOKENIZE_EOVERFLOW && commands == NULL &&
      command_count == 0 && process_error == SHELL_PROCESS_EOUTPUT_LIMIT &&
      processed.commands == NULL && processed.command_count == 0 &&
      processed.groups == NULL && processed.group_count == 0 &&
      processed.group_io_ops == NULL && processed.group_io_op_count == 0 &&
      dep_error == SHELL_DEP_ETRUNC &&
      graph.status == SHELL_DEP_STATUS_TRUNCATED && !graph.node_count &&
      !graph.edge_count;
  valid = valid && rejected;
  test("Brace-group maximum depth is consistent across high-level APIs", valid);
}

static void tokenizer_test_empty_process_argv(void) {
  static const char source[] = "<() printf a<()b <()>() ''<() \"<()\"";
  static const char expected[] = "6:printf,2:ab,0:,3:<(),";
  shell_command_info_t *infos = NULL;
  size_t count = 0;
  shell_netstring_buffer_t argv = {0}, sequence = {0}, raw = {0}, typed = {0};
  bool valid = shell_process_command(source, sizeof(source) - 1, NULL, &infos,
                                     &count) == SHELL_PROCESS_OK &&
               count == 1;
  if (valid)
    valid = shell_render_netargv_buffer(&infos[0], NULL, &argv) ==
                SHELL_PROCESS_OK &&
            argv.length == sizeof(expected) - 1 &&
            !memcmp(argv.data, expected, argv.length);
  shell_command_infos_free(infos, count);
  shell_netstring_buffer_free(&argv);
  bool features = false;
  valid = valid &&
          shell_build_netargv_sequence_buffer(source, sizeof(source) - 1, NULL,
                                              &sequence, &count,
                                              &features) == SHELL_PROCESS_OK &&
          count == 1;
  shell_netstring_iter_t iterator;
  shell_netstring_view_t record;
  valid = valid &&
          shell_netstring_iter_init(&iterator, sequence.data,
                                    sequence.length) == SHELL_NETSTRING_OK &&
          shell_netstring_iter_next(&iterator, &record) == SHELL_NETSTRING_OK &&
          record.payload_length == sizeof(expected) - 1 &&
          !memcmp(record.payload, expected, record.payload_length);
  valid =
      valid &&
      shell_build_anomaly_netseqs_buffer(source, sizeof(source) - 1, NULL, &raw,
                                         &typed, &count) == SHELL_PROCESS_OK &&
      count == 1;
  valid = valid &&
          tokenizer_command_netseq_matches("<() printf ok", "6:printf,", 1);
  shell_netstring_buffer_free(&raw);
  shell_netstring_buffer_free(&typed);
  shell_netstring_buffer_free(&sequence);
  test("Canonical argv elides empty process words, not quoted empty arguments",
       valid);
  test("Empty process words preserve allocation failure atomicity",
       tokenizer_process_commands_allocation_failure_atomic(source));
}

static void tokenizer_test_elided_group_records(void) {
  static const struct {
    const char *source;
    size_t flat_count, structured_count, groups;
    size_t flagged;
    bool stderr_redirect;
  } cases[] = {
      {"{ printf ok; <(); } 2>errors", 2, 1, 1, 0, true},
      {"{ printf ok; <()>() ; } >out", 2, 1, 1, 0, false},
      {"{ { printf ok; <(); } 2>inner; >(); } >outer", 3, 1, 2, 0, true},
      {"{ <(); >(); } 2>errors", 2, 0, 1, SIZE_MAX, true},
      {"{ printf ok; ''<(); } 2>errors", 2, 2, 1, 1, true},
      {"{ printf ok; $value; } 2>errors", 2, 2, 1, 1, true},
      {"<(); { >(); }; printf ok", 3, 1, 1, SIZE_MAX, false}};
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_command_info_t *flat = NULL;
    size_t count = 0;
    shell_processed_commands_t structured = {0};
    valid = shell_process_command(cases[i].source, strlen(cases[i].source),
                                  NULL, &flat, &count) == SHELL_PROCESS_OK &&
            count == cases[i].flat_count &&
            shell_process_commands(cases[i].source, strlen(cases[i].source),
                                   NULL, &structured) == SHELL_PROCESS_OK &&
            structured.command_count == cases[i].structured_count &&
            structured.group_count == cases[i].groups;
    for (size_t c = 0; valid && c < count; c++)
      valid = flat[c].has_redirections == (c == cases[i].flagged) &&
              flat[c].has_error_redirection ==
                  (c == cases[i].flagged && cases[i].stderr_redirect);
    for (size_t g = 0; valid && g < structured.group_count; g++) {
      const shell_group_t *group = &structured.groups[g];
      valid = group->first_command == 0 &&
              group->command_count == (i == 6 ? 0 : cases[i].structured_count);
    }
    valid = valid &&
            (structured.commands == NULL) == (cases[i].structured_count == 0);
    shell_command_infos_free(flat, count);
    shell_processed_commands_free(&structured);
  }
  test("Elided stages preserve flat flags and structured group indexes", valid);
  test("Elided group records remain allocation-failure atomic",
       tokenizer_process_commands_allocation_failure_atomic(cases[2].source) &&
           tokenizer_process_commands_allocation_failure_atomic(
               cases[3].source));

  /* Anomaly sequences retain both structural stages, including the empty
   * sentinel; structured omission must not remove that observation. */
  shell_netstring_buffer_t raw = {0}, typed = {0};
  size_t count = 0;
  const char *source = "{ printf ok; <(); } 2>errors";
  valid =
      shell_build_anomaly_netseqs_buffer(source, strlen(source), NULL, &raw,
                                         &typed, &count) == SHELL_PROCESS_OK &&
      count == 2;
  if (valid) {
    shell_netstring_iter_t raw_iter, typed_iter;
    shell_netstring_view_t raw_record, typed_record;
    valid = shell_netstring_iter_init(&raw_iter, raw.data, raw.length) ==
                SHELL_NETSTRING_OK &&
            shell_netstring_iter_init(&typed_iter, typed.data, typed.length) ==
                SHELL_NETSTRING_OK;
    for (size_t i = 0; valid && i < count; i++) {
      valid = shell_netstring_iter_next(&raw_iter, &raw_record) ==
                  SHELL_NETSTRING_OK &&
              shell_netstring_iter_next(&typed_iter, &typed_record) ==
                  SHELL_NETSTRING_OK;
      if (valid && i == 1)
        valid = raw_record.payload_length == 0 &&
                typed_record.payload_length == 3 &&
                !memcmp(typed_record.payload, "0:,", 3);
    }
  }
  shell_netstring_buffer_free(&raw);
  shell_netstring_buffer_free(&typed);
  test("Elided stages remain explicit anomaly records", valid);

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous = 0;
  valid = true;
  for (unsigned groups = 4; valid && groups <= 16; groups *= 2) {
    char source[2048] = "";
    for (unsigned g = 0; g < groups; g++)
      strcat(source, "{ printf ok; <()>()<(); } 2>errors; ");
    shell_command_info_t *flat = NULL;
    size_t count = 0;
    shellsplit_test_source_scan_reset();
    valid = shell_process_command(source, strlen(source), NULL, &flat,
                                  &count) == SHELL_PROCESS_OK &&
            count == 2 * groups;
    size_t work = shellsplit_test_source_scan_work();
    valid = valid && work && (!previous || work <= 3 * previous);
    previous = work;
    for (size_t i = 0; valid && i < count; i++)
      valid = flat[i].has_error_redirection == (i % 2 == 0);
    shell_command_infos_free(flat, count);
  }
  test("Elided group flag projection retains linear source work", valid);
#endif
}

static void tokenizer_test_processed_word_iterator_boundary_contract(void) {
  static const char continuation_source[] = ">x\\\ny next";
  shell_token_t redirect_tokens[] = {
      {.type = SHELL_TOKEN_REDIRECT_OUT,
       .start = continuation_source,
       .length = 1,
       .position = 0},
      {.type = SHELL_TOKEN_ARGUMENT,
       .start = continuation_source + 1,
       .length = 1,
       .position = 1},
      {.type = SHELL_TOKEN_ARGUMENT,
       .start = continuation_source + 4,
       .length = 1,
       .position = 4},
      {.type = SHELL_TOKEN_ARGUMENT,
       .start = continuation_source + 6,
       .length = 4,
       .position = 6},
  };
  shell_command_t redirect_command = {
      .tokens = redirect_tokens,
      .token_count = sizeof(redirect_tokens) / sizeof(redirect_tokens[0]),
  };
  shell_processed_word_iterator_t iterator;
  shell_token_t word = {0};
  shell_processed_word_iterator_init(&iterator, &redirect_command);
  bool redirect_valid = shell_processed_word_iterator_next(&iterator, &word) &&
                        word.start == continuation_source + 6 &&
                        word.length == 4 &&
                        !shell_processed_word_iterator_next(&iterator, &word);
  bool valid = redirect_valid;

  static const char fragment_source[] = "a\\\nb";
  shell_token_t fragments[] = {
      {.type = SHELL_TOKEN_ARGUMENT,
       .start = fragment_source,
       .length = 1,
       .position = 0},
      {.type = SHELL_TOKEN_ARGUMENT,
       .start = fragment_source + 3,
       .length = 1,
       .position = 3,
       .is_quoted = true,
       .is_escaped = true},
  };
  shell_command_t fragment_command = {
      .tokens = fragments,
      .token_count = sizeof(fragments) / sizeof(fragments[0]),
  };
  shell_processed_word_iterator_init(&iterator, &fragment_command);
  bool fragment_valid = shell_processed_word_iterator_next(&iterator, &word) &&
                        word.start == fragment_source && word.length == 4 &&
                        word.is_quoted && word.is_escaped &&
                        !shell_processed_word_iterator_next(&iterator, &word);
  valid = valid && fragment_valid;

  static const char lf_source[] = "a\\\nb";
  shell_token_t lf = {.type = SHELL_TOKEN_ARGUMENT,
                      .start = lf_source + 3,
                      .length = 1,
                      .position = 3};
  static const char invalid_gap_source[] = "a b";
  shell_token_t invalid_gap = {.type = SHELL_TOKEN_ARGUMENT,
                               .start = invalid_gap_source + 2,
                               .length = 1,
                               .position = 2};
  static const char crlf_source[] = "a\\\r\nb";
  shell_token_t crlf = {.type = SHELL_TOKEN_ARGUMENT,
                        .start = crlf_source + 4,
                        .length = 1,
                        .position = 4};
  bool continuation_valid =
      shell_tokenizer_token_continues_word(&lf, 1) &&
      !shell_tokenizer_token_continues_word(&crlf, 1) &&
      !shell_tokenizer_token_continues_word(&invalid_gap, 1) &&
      !shell_tokenizer_token_continues_word(&invalid_gap, 3);
  valid = valid && continuation_valid;
  test("Processed-word iterator preserves continuation and word boundaries",
       valid);
}

/* Substitutions own their quoting and scalar parameters. A word-level scalar
 * iterator must not visit child command source or leak its quote state into
 * the enclosing word. Child commands are analyzed separately by netseq APIs. */
static void tokenizer_test_scalar_variable_substitution_scopes(void) {
  static const struct {
    const char *word;
    const char *variables[3];
    size_t count;
  } cases[] = {
      {"\"$OUTER$(printf '$INNER')$AFTER\"", {"$OUTER", "$AFTER"}, 2},
      {"\"$OUTER$(printf '\"$INNER')$AFTER\"", {"$OUTER", "$AFTER"}, 2},
      {"\"$OUTER$(printf \"$INNER\")$AFTER\"", {"$OUTER", "$AFTER"}, 2},
      {"\"$OUTER`printf '$INNER'`$AFTER\"", {"$OUTER", "$AFTER"}, 2},
      {"$OUTER<(printf '$INNER')$AFTER", {"$OUTER", "$AFTER"}, 2},
      {"$OUTER<(printf \"$INNER\")$AFTER", {"$OUTER", "$AFTER"}, 2},
      {"$OUTER>(printf '\"$INNER')$AFTER", {"$OUTER", "$AFTER"}, 2},
      {"\"$OUTER<(literal $INNER)$AFTER\"", {"$OUTER", "$INNER", "$AFTER"}, 3},
      {"\"$OUTER$((1 + ${INNER:-2}))$AFTER\"", {"$OUTER", "$AFTER"}, 2},
      {"\"$OUTER$\\\n(printf '$INNER')$AFTER\"", {"$OUTER", "$AFTER"}, 2},
      {"\"$OUTER<\\\n(printf '$INNER')$AFTER\"",
       {"$OUTER", "$INNER", "$AFTER"},
       3},
      {"$OUTER<\\\n(printf '$INNER')$AFTER", {"$OUTER", "$AFTER"}, 2},
      {"\"${OUTER:-$(printf '$INNER')}$AFTER\"",
       {"${OUTER:-$(printf '$INNER')}", "$AFTER"},
       2},
      {"'$INNER'${AFTER}", {"${AFTER}"}, 1},
      {"$'don\\'t $INNER'$AFTER", {"$AFTER"}, 1},
      {"\"$(printf '$INNER')\"", {NULL}, 0},
      {"\"`printf '$INNER'`\"", {NULL}, 0},
      {"<(printf '$INNER')", {NULL}, 0},
      {">(printf '$INNER')", {NULL}, 0},
      {"$((1 + $INNER))", {NULL}, 0},
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_source_variable_scan_t scan = {0};
    size_t start = SIZE_MAX, after = SIZE_MAX;
    bool matches = true;
    for (size_t j = 0; j < cases[i].count; j++) {
      const char *expected = strstr(cases[i].word, cases[i].variables[j]);
      bool found = shell_source_next_variable_expansion(
          cases[i].word, strlen(cases[i].word), &scan, &start, &after);
      matches = matches && found && expected &&
                start == (size_t)(expected - cases[i].word) &&
                after - start == strlen(cases[i].variables[j]);
    }
    size_t previous_start = start, previous_after = after;
    matches = matches &&
              !shell_source_next_variable_expansion(cases[i].word,
                                                    strlen(cases[i].word),
                                                    &scan, &start, &after) &&
              start == previous_start && after == previous_after;
    if (!matches)
      fprintf(stderr, "scalar substitution scope: %s\n", cases[i].word);
    valid = valid && matches;
  }
  test("Scalar variable spans respect substitution and enclosing quote scopes",
       valid);

  static const struct {
    const char *source;
    const char *display;
    const char *types;
    bool variables;
    bool arithmetic;
    bool substitution;
    bool replacements;
  } consumers[] = {
      {"echo \"$OUTER$(printf '$INNER')$AFTER\"",
       "echo \"VAR_VALUE$(printf '$INNER')VAR_VALUE\"",
       "15:6:printf,3:STR,,12:4:echo,2:EV,,", true, false, true, true},
      {"echo \"$OUTER$(printf '\"$INNER')$AFTER\"",
       "echo \"VAR_VALUE$(printf '\"$INNER')VAR_VALUE\"",
       "15:6:printf,3:STR,,12:4:echo,2:EV,,", true, false, true, true},
      {"echo \"$OUTER`printf '$INNER'`$AFTER\"",
       "echo \"VAR_VALUE`printf '$INNER'`VAR_VALUE\"",
       "15:6:printf,3:STR,,12:4:echo,2:EV,,", true, false, true, true},
      {"echo $OUTER<(printf '$INNER')$AFTER",
       "echo VAR_VALUETEMP_FILEVAR_VALUE",
       "15:6:printf,3:STR,,12:4:echo,2:EV,,", true, false, true, true},
      {"echo $OUTER>(printf '$INNER')$AFTER",
       "echo VAR_VALUETEMP_FILEVAR_VALUE",
       "15:6:printf,3:STR,,12:4:echo,2:EV,,", true, false, true, true},
      {"echo \"$(printf '$INNER')\"", "echo \"$(printf '$INNER')\"",
       "15:6:printf,3:STR,,13:4:echo,3:STR,,", false, false, true, false},
      {"echo \"$(printf 'INNER')\"", "echo \"$(printf 'INNER')\"",
       "15:6:printf,3:STR,,13:4:echo,3:STR,,", false, false, true, false},
      {"echo \"$(printf \"$INNER\")\"", "echo \"$(printf \"$INNER\")\"",
       "14:6:printf,2:EV,,13:4:echo,3:STR,,", false, false, true, false},
      {"echo \"$OUTER$((1 + 2))$AFTER\"",
       "echo \"VAR_VALUE$((1 + 2))VAR_VALUE\"", "12:4:echo,2:EV,,", true, true,
       false, true},
      {"printf fo\\\no", "printf foo", "15:6:printf,3:STR,,", false, false,
       false, false},
  };
  valid = true;
  for (size_t i = 0; i < sizeof(consumers) / sizeof(consumers[0]); i++) {
    const char *source = consumers[i].source;
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    shell_abstract_command_t *abstract = NULL;
    shell_netstring_buffer_t raw = {0};
    shell_netstring_buffer_t typed = {0};
    size_t stages = 0;
    size_t expected_stages = consumers[i].substitution ? 2 : 1;
    bool matches =
        shell_transform_command_line(source, strlen(source), NULL, &transformed,
                                     &transformed_count) ==
            SHELL_TRANSFORM_OK &&
        transformed_count == 1 &&
        strcmp(transformed[0]->display_text, consumers[i].display) == 0 &&
        transformed[0]->has_transformations == consumers[i].replacements &&
        shell_abstract_command_parse(source, strlen(source), &abstract) ==
            SHELL_ABSTRACT_OK &&
        abstract->has_variables == consumers[i].variables &&
        abstract->has_cmd_subst == consumers[i].substitution &&
        abstract->has_arithmetic == consumers[i].arithmetic &&
        shell_build_anomaly_netseqs_buffer(source, strlen(source), NULL, &raw,
                                           &typed,
                                           &stages) == SHELL_PROCESS_OK &&
        stages == expected_stages &&
        (typed.length != strlen(consumers[i].types) ||
         memcmp(typed.data, consumers[i].types, typed.length)) == 0 &&
        (raw.length != strlen(consumers[i].substitution ? "6:printf,4:echo,"
                              : consumers[i].arithmetic ? "4:echo,"
                                                        : "6:printf,") ||
         memcmp(raw.data,
                consumers[i].substitution ? "6:printf,4:echo,"
                : consumers[i].arithmetic ? "4:echo,"
                                          : "6:printf,",
                raw.length)) == 0;
    if (!matches)
      fprintf(stderr, "scalar substitution consumer: %s\n", source);
    valid = valid && matches;
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
    shell_netstring_buffer_free(&typed);
    shell_netstring_buffer_free(&raw);
  }
  test("Transformation, abstraction and anomaly signatures agree on variable "
       "scopes",
       valid);
}

static void tokenizer_test_prevalidated_anomaly_stages(void) {
  static const struct {
    const char *source;
    const char *raw;
    bool contextual;
  } cases[] = {
      {"echo ok; >out; echo \"$(printf x)\" <(printf y); time",
       "4:echo,0:,6:printf,6:printf,4:echo,0:,", false},
      {"exec {fd}<<<payload && read -p\"$fd\" -u \"$fd\" value",
       "4:exec,4:read,", true},
      {"exec {fd}<<<payload && echo \"$(read -p\"$fd\" -u \"$fd\" value)\"",
       "4:exec,4:read,4:echo,", true},
  };
  shell_dep_graph_t *graph = malloc(sizeof(*graph));
  bool valid = graph != NULL;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    size_t length = strlen(source);
    valid =
        shell_dep_graph_parse(source, length, "/", NULL, graph) == SHELL_DEP_OK;
    if (!valid)
      break;
    shell_anomaly_stages_t stages = {0};
    shellsplit_test_source_scan_reset();
    valid = shell_anomaly_stages_collect_prevalidated(
                source, length, NULL, NULL, &stages) == SHELL_PROCESS_OK &&
            shellsplit_test_metadata_work(
                SHELLSPLIT_TEST_WORK_SEMANTIC_BODIES) == 0 &&
            shellsplit_test_metadata_work(
                SHELLSPLIT_TEST_WORK_PROCESS_STRICT_PARSE) == 0 &&
            shellsplit_test_metadata_work(
                SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES) == 0;
    shell_netstring_buffer_t raw = {0}, typed = {0}, raw_only = {0};
    size_t count = SIZE_MAX, raw_count = SIZE_MAX;
    valid = valid &&
            shell_build_anomaly_netseqs_from_stages(
                &stages, NULL, &raw, &typed, &count) == SHELL_PROCESS_OK &&
            shell_build_command_netseq_from_stages(
                &stages, NULL, &raw_only, &raw_count) == SHELL_PROCESS_OK &&
            count == stages.count && raw_count == count &&
            raw.length == strlen(cases[i].raw) &&
            memcmp(raw.data, cases[i].raw, raw.length) == 0 &&
            raw_only.length == raw.length &&
            memcmp(raw.data, raw_only.data, raw.length) == 0;
    shell_netstring_buffer_t public_raw = {0}, public_typed = {0};
    size_t public_count = SIZE_MAX;
    shell_process_status_t status = shell_build_anomaly_netseqs_buffer(
        source, length, NULL, &public_raw, &public_typed, &public_count);
    if (cases[i].contextual) {
      valid = valid && status == SHELL_PROCESS_EPARSE && !public_raw.data &&
              !public_typed.data && public_count == 0;
      public_count = SIZE_MAX;
      valid = valid &&
              shell_build_command_netseq_buffer(source, length, NULL,
                                                &public_raw, &public_count) ==
                  SHELL_PROCESS_EPARSE &&
              !public_raw.data && public_count == 0;
      public_count = SIZE_MAX;
      valid = valid &&
              shell_build_type_netseq_buffer(source, length, NULL,
                                             &public_typed, &public_count) ==
                  SHELL_PROCESS_EPARSE &&
              !public_typed.data && public_count == 0;
    } else {
      valid = valid && status == SHELL_PROCESS_OK && public_count == count &&
              public_raw.length == raw.length &&
              public_typed.length == typed.length &&
              memcmp(public_raw.data, raw.data, raw.length) == 0 &&
              memcmp(public_typed.data, typed.data, typed.length) == 0;
    }
    shell_netstring_buffer_free(&public_raw);
    shell_netstring_buffer_free(&public_typed);
    shell_netstring_buffer_free(&raw);
    shell_netstring_buffer_free(&typed);
    shell_netstring_buffer_free(&raw_only);

    /* Every render allocation is still an operational failure boundary; the
     * already validated borrowed stage view remains reusable after failure. */
    for (unsigned paired = 0; valid && paired < 2; paired++) {
      shellsplit_test_alloc_reset();
      status = paired ? shell_build_anomaly_netseqs_from_stages(
                            &stages, NULL, &raw, &typed, &count)
                      : shell_build_command_netseq_from_stages(&stages, NULL,
                                                               &raw, &count);
      size_t allocations = shellsplit_test_alloc_count();
      shellsplit_test_alloc_reset();
      valid = status == SHELL_PROCESS_OK && allocations != 0;
      shell_netstring_buffer_free(&raw);
      shell_netstring_buffer_free(&typed);
      for (size_t fail = 1; valid && fail <= allocations; fail++) {
        shellsplit_test_alloc_fail_at(fail);
        status = paired ? shell_build_anomaly_netseqs_from_stages(
                              &stages, NULL, &raw, &typed, &count)
                        : shell_build_command_netseq_from_stages(&stages, NULL,
                                                                 &raw, &count);
        shellsplit_test_alloc_reset();
        valid = status == SHELL_PROCESS_ENOMEM && count == 0 && !raw.data &&
                !raw.length && !typed.data && !typed.length;
      }
      shell_process_limits_t short_limit = {1, 1, 0};
      status = paired ? shell_build_anomaly_netseqs_from_stages(
                            &stages, &short_limit, &raw, &typed, &count)
                      : shell_build_command_netseq_from_stages(
                            &stages, &short_limit, &raw, &count);
      valid = valid && status == SHELL_PROCESS_EOUTPUT_LIMIT && count == 0 &&
              !raw.data && !typed.data;
    }
    shell_anomaly_stages_free(&stages);
    shellsplit_test_alloc_reset();
    status = shell_anomaly_stages_collect_prevalidated(source, length, NULL,
                                                       NULL, &stages);
    size_t allocations = shellsplit_test_alloc_count();
    shellsplit_test_alloc_reset();
    valid = valid && status == SHELL_PROCESS_OK && allocations != 0;
    shell_anomaly_stages_free(&stages);
    for (size_t fail = 1; valid && fail <= allocations; fail++) {
      shellsplit_test_alloc_fail_at(fail);
      status = shell_anomaly_stages_collect_prevalidated(source, length, NULL,
                                                         NULL, &stages);
      shellsplit_test_alloc_reset();
      valid = status == SHELL_PROCESS_ENOMEM && !stages.commands &&
              stages.count == 0;
      shell_anomaly_stages_free(&stages);
    }
  }
  free(graph);
  test("Graph-validated anomaly stages share renderers and atomic failures",
       valid);

  static const char grouped[] = "{ echo a; } >one; { echo b; } >two";
  graph = malloc(sizeof(*graph));
  valid = graph && shell_dep_graph_parse(grouped, sizeof(grouped) - 1, "/",
                                         NULL, graph) == SHELL_DEP_OK;
  shell_anomaly_stages_t stages = {0};
  shell_process_limits_t group_limit = {SIZE_MAX, SIZE_MAX, 1};
  valid = valid &&
          shell_anomaly_stages_collect_prevalidated(
              grouped, sizeof(grouped) - 1, &group_limit, NULL, &stages) ==
              SHELL_PROCESS_EOUTPUT_LIMIT &&
          !stages.commands && stages.count == 0;
  shell_anomaly_stages_free(&stages);
  free(graph);
  test("Prevalidated anomaly collection retains the group-I/O budget", valid);
}

static void tokenizer_test_control_syntax_scope_contract(void) {
  static const struct {
    const char *source;
    shell_control_syntax_t expected;
  } cases[] = {
      {NULL, SHELL_CONTROL_SYNTAX_NONE},
      {"", SHELL_CONTROL_SYNTAX_NONE},
      {"if true; then echo ok; fi", SHELL_CONTROL_SYNTAX_NONE},
      {"if true; then echo ok", SHELL_CONTROL_SYNTAX_NONE},
      {"if true; then while true; do :; done; fi",
       SHELL_CONTROL_SYNTAX_COMPLETE},
      {"whi\\\nle true; do echo ok; done", SHELL_CONTROL_SYNTAX_COMPLETE},
      {"echo if while; printf '%s' done", SHELL_CONTROL_SYNTAX_NONE},
      {"'while' true; wh\\ile true", SHELL_CONTROL_SYNTAX_NONE},
      {"echo ok >while # if true", SHELL_CONTROL_SYNTAX_NONE},
      {"echo $(if true; then echo ok; fi)", SHELL_CONTROL_SYNTAX_NONE},
      {"fi $(printf x)", SHELL_CONTROL_SYNTAX_NONE},
      {"if $(printf x)then; then :; fi", SHELL_CONTROL_SYNTAX_NONE},
      {"case $(printf x)in in x) :;; esac", SHELL_CONTROL_SYNTAX_COMPLETE},
  };
  static const char enclosing[] = "enclosing lexical context";
  shell_source_operation_begin(enclosing, sizeof(enclosing) - 1);
  shell_source_scope_frontier(enclosing, 3);
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    size_t length = cases[i].source ? strlen(cases[i].source) : 0;
    shell_control_syntax_t syntax =
        shell_tokenizer_control_syntax(cases[i].source, length);
    /* Entering another scope exposes the previous one without adding a
     * test-only accessor; restore it before the next classification. */
    shell_source_scope_t previous =
        shell_source_scope_begin(enclosing, sizeof(enclosing) - 1);
    bool restored =
        previous.begin == (uintptr_t)enclosing &&
        previous.end == (uintptr_t)enclosing + sizeof(enclosing) - 1 &&
        previous.frontier == (uintptr_t)enclosing + 3;
    shell_source_scope_end(previous);
    if (syntax != cases[i].expected || !restored) {
      fprintf(stderr, "control syntax/scope mismatch: %s\n",
              cases[i].source ? cases[i].source : "(no source)");
      valid = false;
    }
  }
  shell_source_operation_end();
  test("Control syntax preserves lexical classification and enclosing scope",
       valid);
}

static int run_tokenizer(int argc, char **argv) {
  (void)argc;
  (void)argv;
  tokenizer_test_prevalidated_anomaly_stages();
  tokenizer_test_control_syntax_scope_contract();
  tokenizer_test_scalar_variable_substitution_scopes();
  tokenizer_test_transform_allocation_failures();
  test("Quoted byte processing is allocation-failure atomic",
       tokenizer_process_commands_allocation_failure_atomic(
           "{ printf '%s' '日本'; } >'résumé.txt'") &&
           tokenizer_process_command_allocation_failure_atomic(
               "printf '%s' '\x80\xff' >'réport.txt'"));
  test("Unquoted byte processing is allocation-failure atomic",
       tokenizer_process_commands_allocation_failure_atomic(
           "{ printf '%s' 日本; } >résumé.txt") &&
           tokenizer_process_command_allocation_failure_atomic(
               "printf '%s' \x80\xff >résumé.txt"));
  test("ANSI-C byte processing is allocation-failure atomic",
       tokenizer_process_commands_allocation_failure_atomic(
           "{ printf '%s' $'日本\\t語'; } >$'résumé.txt'") &&
           tokenizer_process_command_allocation_failure_atomic(
               "printf '%s' $'\x80\xff' >$'résumé.txt'"));
  test("ANSI-C NUL processing is allocation-failure atomic",
       tokenizer_process_commands_allocation_failure_atomic(
           "{ printf '%s' $'a\\0b'; } >$'out\\0ignored'") &&
           tokenizer_process_command_allocation_failure_atomic(
               "printf '%s' pre$'a\\0b'post $'\\0'"));
  test("Later timing prefixes are allocation-failure atomic",
       tokenizer_process_command_allocation_failure_atomic(
           "echo a; time -p echo b; time; ! echo c") &&
           tokenizer_process_command_allocation_failure_atomic(
               "echo a; time { echo b; time; }"));
  test("Document execution stages are allocation-failure atomic",
       tokenizer_process_commands_allocation_failure_atomic(
           "{ time 3<<<body cat <&3; } | time <<<next") &&
           tokenizer_process_commands_allocation_failure_atomic(
               "time <<EOF cat argument\nbody\nEOF\n") &&
           tokenizer_process_command_allocation_failure_atomic(
               "{ time <<<body cat; } | cat <<<next"));
  tokenizer_test_output_limit_boundaries();
  tokenizer_test_cstring_allocation_size_boundaries();
  tokenizer_test_canonical_control_compounds_rejected();
  tokenizer_test_control_word_literals_are_accepted();
  tokenizer_test_structured_processor_requires_complete_syntax();
  tokenizer_test_tolerant_unfinished_group_omits_empty_command();
  tokenizer_test_blank_source_convention();
  tokenizer_test_record_less_syntax_is_not_blank();
  tokenizer_test_posix_brace_group_forms();
  tokenizer_test_brace_group_process_substitution_contract();
  tokenizer_test_brace_group_heredoc_sequence_contract();
  tokenizer_test_brace_group_grammar_matrix();
  tokenizer_test_brace_group_operation_limits_are_atomic();
  tokenizer_test_anomaly_sequences_include_nested_execution_stages();
  tokenizer_test_static_arithmetic_depth_is_bounded();
  tokenizer_test_anomaly_sequences_represent_redirect_only_record();
  tokenizer_test_redirect_operand_boundary_contract();
  tokenizer_test_processed_group_io_contract();
  tokenizer_test_processed_group_io_boundaries();
  tokenizer_test_group_combined_named_redirect_and_document_contract();
  tokenizer_test_combined_redirect_prefix_word_contract();
  tokenizer_test_continued_bash_compound_syntax_contract();
  tokenizer_test_current_shell_metaprogramming_semantic_contract();
  tokenizer_test_readonly_named_fd_semantic_contract();
  tokenizer_test_brace_group_maximum_contract();
  tokenizer_test_processed_word_iterator_boundary_contract();
  tokenizer_test_empty_process_argv();
  tokenizer_test_elided_group_records();
  tokenizer_test_token_type_names();
  tokenizer_test_list_syntax_contract();
  tokenizer_test_source_scanner_boundaries();
  tokenizer_test_executable_substitution_scanner_contract();
  tokenizer_test_brace_close_across_line_continuation();
  tokenizer_test_negator_requires_a_word_start();
  tokenizer_test_descriptor_duplication_is_not_background();
  tokenizer_test_glob_class_continuation_keeps_the_feature();
  tokenizer_test_quoted_prefix_extglob_is_one_word();
  tokenizer_test_glob_bracket_quoted_members_keep_the_feature();
  tokenizer_test_current_shell_wrapper_chain_contract();
  tokenizer_test_expansion_line_continuation_contract();
  tokenizer_test_redirect_operand_safety_contract();
  tokenizer_test_record_parser_boundaries();
  tokenizer_test_modern_bash_syntax_contract();
  tokenizer_test_processor_routing_cross_product();
  tokenizer_test_escaped_word_prefix_boundaries();
  tokenizer_test_array_semantic_boundaries();
  tokenizer_test_ansi_c_structural_scanner_contract();
  tokenizer_test_nested_quote_and_ansi_completion();
  tokenizer_test_double_quoted_parameter_substitution_scope();
  tokenizer_test_error_strings();
  tokenizer_test_composition_metadata();
  static const tokenizer_iterator_case_t iterator_cases[] = {
      {"Tokenizer iterator: empty input", "", 0, {0}, {NULL}, 0, 0, 0},
      {"Tokenizer iterator: leading whitespace preserves newline separator",
       " \t\n",
       1,
       {SHELL_TOKEN_SEMICOLON},
       {"\n"},
       0,
       0,
       0},
      {"Tokenizer iterator: token sequence",
       "echo \"$VAR\" | cat 2>&1",
       5,
       {SHELL_TOKEN_COMMAND, SHELL_TOKEN_VARIABLE_QUOTED, SHELL_TOKEN_PIPE,
        SHELL_TOKEN_COMMAND, SHELL_TOKEN_REDIRECT_ERR},
       {"echo", "\"$VAR\"", "|", "cat", "2>&1"},
       0,
       0,
       0},
      {"Tokenizer iterator: keyword depth transitions",
       "if for case",
       3,
       {SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND},
       {"if", "for", "case"},
       1,
       1,
       1},
      {"Tokenizer iterator: conditional markers do not open nesting",
       "if then elif else fi",
       5,
       {SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND,
        SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND},
       {"if", "then", "elif", "else", "fi"},
       0,
       0,
       0},
      {"Tokenizer iterator: all loop openers share depth accounting",
       "for while until select done",
       5,
       {SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND,
        SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND},
       {"for", "while", "until", "select", "done"},
       0,
       3,
       0},
      {"Tokenizer iterator: unmatched closers leave depths at zero",
       "fi for do done done case esac esac",
       8,
       {SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND,
        SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND,
        SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND},
       {"fi", "for", "do", "done", "done", "case", "esac", "esac"},
       0,
       0,
       0},
      {"Tokenizer iterator: process substitutions",
       "diff <(left \"(x)\") >(right)",
       3,
       {SHELL_TOKEN_COMMAND, SHELL_TOKEN_PROCESS_SUB, SHELL_TOKEN_PROCESS_SUB},
       {"diff", "<(left \"(x)\")", ">(right)"},
       0,
       0,
       0},
      {"Tokenizer iterator: special parameter family",
       "echo $? $$ $# $! $@ $* $-",
       8,
       {SHELL_TOKEN_COMMAND, SHELL_TOKEN_SPECIAL_VAR, SHELL_TOKEN_SPECIAL_VAR,
        SHELL_TOKEN_SPECIAL_VAR, SHELL_TOKEN_SPECIAL_VAR,
        SHELL_TOKEN_SPECIAL_VAR, SHELL_TOKEN_SPECIAL_VAR,
        SHELL_TOKEN_SPECIAL_VAR},
       {"echo", "$?", "$$", "$#", "$!", "$@", "$*", "$-"},
       0,
       0,
       0},
      {"Tokenizer iterator: positional parameter boundary",
       "echo $10 ${10}",
       4,
       {SHELL_TOKEN_COMMAND, SHELL_TOKEN_SPECIAL_VAR, SHELL_TOKEN_COMMAND,
        SHELL_TOKEN_VARIABLE},
       {"echo", "$1", "0", "${10}"},
       0,
       0,
       0},
      {"Tokenizer iterator: descriptor redirection family",
       ">>log>&10 <&0 3>&- 4<&- 12>>log",
       8,
       {SHELL_TOKEN_REDIRECT_APPEND, SHELL_TOKEN_COMMAND,
        SHELL_TOKEN_REDIRECT_ERR, SHELL_TOKEN_REDIRECT_IN,
        SHELL_TOKEN_REDIRECT_ERR, SHELL_TOKEN_REDIRECT_IN,
        SHELL_TOKEN_REDIRECT_APPEND, SHELL_TOKEN_COMMAND},
       {">>", "log", ">&10", "<&0", "3>&-", "4<&-", "12>>", "log"},
       0,
       0,
       0},
      {"Tokenizer iterator: raw close marker leaves adjacent argv",
       "printf x >&-file",
       4,
       {SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND, SHELL_TOKEN_REDIRECT_ERR,
        SHELL_TOKEN_COMMAND},
       {"printf", "x", ">&-", "file"},
       0,
       0,
       0},
      {"Tokenizer iterator: maximum io_number remains a descriptor",
       "2147483647>out",
       2,
       {SHELL_TOKEN_REDIRECT_ERR, SHELL_TOKEN_COMMAND},
       {"2147483647>", "out"},
       0,
       0,
       0},
      {"Tokenizer iterator: overflowing io_number remains a word",
       "2147483648>out",
       3,
       {SHELL_TOKEN_COMMAND, SHELL_TOKEN_REDIRECT_OUT, SHELL_TOKEN_COMMAND},
       {"2147483648", ">", "out"},
       0,
       0,
       0},
  };
  tokenizer_run_iterator_cases(iterator_cases, sizeof(iterator_cases) /
                                                   sizeof(iterator_cases[0]));
  tokenizer_test_iterator_argument_contracts();
  printf("Running unified tokenizer tests...\n\n");
  printf("=== BASIC TOKENIZER TESTS ===\n\n");

  static const tokenizer_tokenizer_case_t basic_cases[] = {
      {"pipe and redirect", "cat xx | less -G > rsr", 2},
      {"multi-stage pipeline", "cat file.txt | grep pattern | sort | uniq", 4},
      {"variable and glob", "grep \\$PATTERN *.log", 1},
      {"mixed logical operators", "cmd1 && cmd2 || cmd3", 3},
      {"semicolon separator", "cmd1 ; cmd2", 2},
      {"quoted operator and redirects",
       "grep -E \"pattern|another\" file.txt > output.txt 2>&1", 1},
      {"redirected pipeline", "cat < input.txt | wc -l > count.txt", 2},
      {"quoted pipeline", "echo 'hello world' | tr 'a-z' 'A-Z'", 2},
      {"three-stage command chain",
       "find . -name '*.c' | xargs grep -l main | head -5", 3},
      {"eight-stage pipeline", "a | b | c | d | e | f | g | h", 8},
      {"simple command", "echo hello", 1},
      {"command arguments", "echo hello world", 1},
      {"output redirect", "cmd > file.txt", 1},
      {"append redirect", "cmd >>file.txt", 1},
      {"mixed pipe and logical operators", "a | b && c | d", 4},
      {"logical fallback after pipeline",
       "cat file.txt | grep pattern || echo done", 3},
      {"git pipeline", "git log --oneline | head -10", 2},
      {"system administration pipeline", "cat /etc/passwd | cut -d: -f1 | sort",
       3},
      {"empty input", "", 0},
  };
  tokenizer_run_tokenizer_cases(basic_cases,
                                sizeof(basic_cases) / sizeof(basic_cases[0]));

  printf("\n=== EXTENDED TOKENIZER TESTS ===\n\n");

  static const tokenizer_feature_case_t feature_cases[] = {
      {{"plain command", "echo hello", 1}, 0},
      {{"simple variable", "echo $VAR", 1}, tokenizer_EXPECT_VARIABLE},
      {{"braced variable", "echo ${VAR}", 1}, tokenizer_EXPECT_VARIABLE},
      {{"special variables", "echo $1 $# $? $$", 1}, tokenizer_EXPECT_VARIABLE},
      {{"multiple variables", "echo $A $B $C", 1}, tokenizer_EXPECT_VARIABLE},
      {{"asterisk glob", "ls *.txt", 1}, tokenizer_EXPECT_GLOB},
      {{"question-mark glob", "cat file?.txt", 1}, tokenizer_EXPECT_GLOB},
      {{"bracket glob", "ls file[123].txt", 1}, tokenizer_EXPECT_GLOB},
      {{"command substitution", "cat $(file)", 1}, tokenizer_EXPECT_SUBSHELL},
      {{"backtick substitution", "cat `file`", 1}, tokenizer_EXPECT_SUBSHELL},
      {{"arithmetic expansion", "echo $((x+1))", 1},
       tokenizer_EXPECT_ARITHMETIC},
      {{"features across pipeline", "cat $FILE | grep *.log", 2},
       tokenizer_EXPECT_VARIABLE | tokenizer_EXPECT_GLOB},
      {{"combined features", "ls ${DIR}/*.txt | sort", 2},
       tokenizer_EXPECT_VARIABLE | tokenizer_EXPECT_GLOB},
      {{"empty input", "", 0}, 0},
      {{"whitespace input", "   ", 0}, 0},
      {{"single-character command", "x", 1}, 0},
      {{"variable with underscore and numbers", "echo $VAR_NAME_123", 1},
       tokenizer_EXPECT_VARIABLE},
      {{"empty command substitution", "echo $()", 1},
       tokenizer_EXPECT_SUBSHELL},
      {{"nested command substitutions", "echo $(echo $(echo hi))", 1},
       tokenizer_EXPECT_SUBSHELL},
      {{"glob argument", "cmd *.c", 1}, tokenizer_EXPECT_GLOB},
      {{"combined glob forms", "ls file???[0-9]*.{c,h}", 1},
       tokenizer_EXPECT_GLOB},
      {{"negated bracket glob", "ls file[!123].txt", 1}, tokenizer_EXPECT_GLOB},
  };
  tokenizer_run_feature_cases(feature_cases,
                              sizeof(feature_cases) / sizeof(feature_cases[0]));

  static const tokenizer_tokenizer_case_t rejected_cases[] = {
      {"reject nested variable braces", "echo ${VAR${SUFFIX}}", 0},
      {"reject unclosed variable brace", "echo ${VAR", 0},
  };
  tokenizer_run_rejected_cases(rejected_cases, sizeof(rejected_cases) /
                                                   sizeof(rejected_cases[0]));

  static const tokenizer_stage_case_t stage_cases[] = {
      {{"features remain attached to pipeline stages",
        "cmd1 $VAR1 | cmd2 *.txt | cmd3 $(sub) | cmd4 `back`", 4},
       UINT64_C(0x1),
       UINT64_C(0x2),
       UINT64_C(0xc),
       0},
      {{"features remain attached across semicolons",
        "cmd1 $VAR; cmd2 *.txt; cmd3", 3},
       UINT64_C(0x1),
       UINT64_C(0x2),
       0,
       0},
      {{"features remain attached across logical operators",
        "cmd1 $VAR && cmd2 *.txt || cmd3 $((x))", 3},
       UINT64_C(0x1),
       UINT64_C(0x2),
       0,
       UINT64_C(0x4)},
      {{"quoted variable does not activate quoted glob",
        "echo \"$VAR\" '*.txt'", 1},
       UINT64_C(0x1),
       0,
       0,
       0},
  };
  tokenizer_run_stage_cases(stage_cases,
                            sizeof(stage_cases) / sizeof(stage_cases[0]));

  // Test 75: Large pipeline with all features
  {
    const char *input =
        "find ${START_DIR} -name \"*.${EXT}\" -type f 2>/dev/null | "
        "grep -v \"^\\.\" | sort -u | head -${MAX_COUNT} | "
        "while read file; do wc -l \"$file\"; done | "
        "awk '{sum+=$1} END {print sum}' > ${OUTPUT_FILE}";
    tokenizer_check_tokenizer_case(
        "Extended tokenizer: large mixed-feature pipeline", input, 8);
  }

  // Test 76: Complex data processing pipeline
  {
    const char *input =
        "cat ${LOG_DIR}/*.log.$(date +%Y%m%d) 2>/dev/null | "
        "grep -E '${PATTERN}|${ALT_PATTERN}' | "
        "sed 's/${OLD}/${NEW}/g' | "
        "sort | uniq -c | sort -rn | "
        "head -n ${LIMIT} | "
        "awk '{print $2 \" \" $1}' > ${OUTPUT_DIR}/results.txt && "
        "echo \"Processed $(wc -l < ${OUTPUT_DIR}/results.txt) entries\"";
    tokenizer_check_tokenizer_case(
        "Extended tokenizer: data processing pipeline", input, 9);
  }

  // Test 77: System monitoring pipeline
  {
    const char *input =
        "ps aux --sort=-%${MEM_FIELD} | "
        "head -n ${TOP_N} | "
        "awk '{print $2, $${MEM_FIELD}, $${CPU_FIELD}}' | "
        "while read pid mem cpu; do "
        "  proc_name=$(cat /proc/$pid/comm 2>/dev/null); "
        "  echo \"$proc_name: mem=${mem}% cpu=${cpu}%\"; "
        "done | sort -t= -k2 -rn | "
        "tee ${OUTPUT_DIR}/top_procs.txt | "
        "mail -s \"Top processes on ${HOSTNAME}\" ${ADMIN_EMAIL}";
    tokenizer_check_tokenizer_case(
        "Extended tokenizer: system monitoring pipeline", input, 10);
  }

  // Test 78: Build and test pipeline with a PIPESTATUS array reference
  {
    const char *input =
        "make clean && "
        "make -j${JOBS} 2>&1 | tee ${BUILD_LOG} && "
        "if [ $? -eq 0 ]; then "
        "  ctest --output-on-failure -j${TEST_JOBS} | tee ${TEST_LOG}; "
        "  if [ ${PIPESTATUS[0]} -eq 0 ]; then "
        "    echo \"All tests passed\" | mail -s \"${PROJECT} build: SUCCESS\" "
        "${TEAM_EMAIL}; "
        "  else "
        "    echo \"Tests failed\" | mail -s \"${PROJECT} build: FAILED\" "
        "${TEAM_EMAIL}; "
        "  fi; "
        "else "
        "  echo \"Build failed\" | mail -s \"${PROJECT} build: FAILED\" "
        "${TEAM_EMAIL}; "
        "fi";
    tokenizer_check_tokenizer_case(
        "Extended tokenizer: preserve PIPESTATUS pipeline structure", input,
        13);
  }

  // Test 79: Database operations pipeline
  {
    const char *input =
        "mysql -u${DB_USER} -p${DB_PASS} -h ${DB_HOST} ${DB_NAME} -e \""
        "SELECT ${COLUMNS} FROM ${TABLE} "
        "WHERE ${WHERE_CLAUSE} "
        "ORDER BY ${ORDER_BY} "
        "LIMIT ${LIMIT}\" 2>/dev/null | "
        "sed '1d' | "
        "while read -r ${FIELDS}; do "
        "  echo \"Processing: ${RECORD}\"; "
        "  ./process_${TYPE}.sh ${RECORD} ${PARAMS}; "
        "done | "
        "mysql -u${DB_USER} -p${DB_PASS} -h ${DB_HOST} ${DB_NAME} -e "
        "\"INSERT INTO ${RESULT_TABLE} ${SELECT_CLAUSE}\"";
    tokenizer_check_tokenizer_case(
        "Extended tokenizer: database operations pipeline", input, 7);
  }

  // Test 80: Container orchestration pipeline
  {
    const char *input =
        "kubectl get pods -n ${NAMESPACE} -o jsonpath='{range .items[*]}"
        "{.metadata.name}{\"\\n\"}{.status.phase}{\"\\n\"}"
        "{end}' | grep \"${STATUS}\" | "
        "while read pod status; do "
        "  echo \"Scaling down: $pod\"; "
        "  kubectl scale deployment ${DEPLOYMENT} --replicas=0 -n "
        "${NAMESPACE}; "
        "done | "
        "kubectl apply -f ${MANIFEST_DIR}/*.yaml && "
        "sleep ${DELAY} && "
        "kubectl rollout status deployment/${DEPLOYMENT} -n ${NAMESPACE} && "
        "kubectl get pods -n ${NAMESPACE} | grep Running | wc -l";
    tokenizer_check_tokenizer_case(
        "Extended tokenizer: container orchestration pipeline", input, 12);
  }

  // Test 81: Log aggregation and analysis
  {
    const char *input =
        "for log_file in ${LOG_DIR}/${APP_NAME}*.${DATE}.log; do "
        "  if [ -f \"$log_file\" ]; then "
        "    echo \"Processing: $log_file\"; "
        "    grep -i '${ERROR_PATTERN}' \"$log_file\" | "
        "    awk '{print $${FIELD_NUM}}' | sort | uniq -c | "
        "    while read count error; do "
        "      echo \"$count: $error\"; "
        "      if [ $count -gt ${THRESHOLD} ]; then "
        "        alert.sh \"$error occurred $count times\" ${SEVERITY}; "
        "      fi; "
        "    done >> ${REPORT_DIR}/errors_${DATE}.txt; "
        "  fi; "
        "done && "
        "cat ${REPORT_DIR}/errors_${DATE}.txt | mail -s \"Error Report "
        "${DATE}\" ${ALERT_EMAIL}";
    tokenizer_check_tokenizer_case(
        "Extended tokenizer: log aggregation and analysis", input, 15);
  }

  // Test 82: File processing with subshells and globs
  {
    const char *input =
        "find . -name \"*.${EXT}\" -type f -newer ${REFERENCE_FILE} | "
        "xargs -I {} sh -c '"
        "  filename=$(basename {}); "
        "  dir=$(dirname {}); "
        "  newname=$(echo $filename | sed \"s/${OLD_EXT}/${NEW_EXT}/g\"); "
        "  cp {} \"$dir/$newname\"; "
        "  echo \"Converted: $filename -> $newname\";"
        "' | "
        "tee -a ${LOG_FILE}";
    tokenizer_check_tokenizer_case(
        "Extended tokenizer: file processing with subshells and globs", input,
        3);
  }

  // Test 83: API data processing pipeline
  {
    const char *input =
        "curl -s ${API_URL}/${ENDPOINT}?api_key=${API_KEY} | "
        "jq -r '.${DATA_FIELD}[] | select(.${FILTER_KEY} == "
        "\"${FILTER_VALUE}\")' | "
        "while read item; do "
        "  id=$(echo $item | jq -r '.id'); "
        "  name=$(echo $item | jq -r '.name'); "
        "  echo \"Processing: $name (ID: $id)\"; "
        "  curl -X POST ${WEBHOOK_URL} -H \"Content-Type: application/json\" "
        "    -d \"{\\\"id\\\": \\\"$id\\\", \\\"name\\\": \\\"$name\\\", "
        "\\\"processed\\\": true}\" || true; "
        "done | "
        "jq -s '.' > ${OUTPUT_DIR}/processed_${TIMESTAMP}.json";
    tokenizer_check_tokenizer_case(
        "Extended tokenizer: API data processing pipeline", input, 10);
  }

  // Test 84: Complete CI/CD pipeline with a PIPESTATUS array reference
  {
    const char *input =
        "git clone ${REPO_URL} ${WORK_DIR} && "
        "cd ${WORK_DIR} && "
        "git checkout ${BRANCH} && "
        "docker build -t ${IMAGE_NAME}:${VERSION} . && "
        "docker run --rm ${IMAGE_NAME}:${VERSION} ${TEST_CMD} | tee "
        "${TEST_OUTPUT} && "
        "if [ ${PIPESTATUS[0]} -eq 0 ]; then "
        "  docker tag ${IMAGE_NAME}:${VERSION} "
        "${REGISTRY}/${IMAGE_NAME}:latest && "
        "  docker tag ${IMAGE_NAME}:${VERSION} "
        "${REGISTRY}/${IMAGE_NAME}:${VERSION} && "
        "  docker push ${REGISTRY}/${IMAGE_NAME}:latest && "
        "  docker push ${REGISTRY}/${IMAGE_NAME}:${VERSION} && "
        "  echo \"Deployment successful\" | slack -c ${SLACK_CHANNEL}; "
        "else "
        "  echo \"Tests failed, not deploying\" | slack -c ${SLACK_CHANNEL}; "
        "  exit 1; "
        "fi";
    tokenizer_check_tokenizer_case(
        "Extended tokenizer: preserve CI/CD structure", input, 16);
  }

  printf("\n=== TRANSFORM TESTS ===\n\n");

  {
    char input[] = "echo $NAME *.txt $(id) $((1+2)) <(left)";
    static const char *originals[] = {"echo",  "$NAME",    "*.txt",
                                      "$(id)", "$((1+2))", "<(left)"};
    static const char *transformed[] = {"echo",         "VAR_VALUE",
                                        "FILE_PATTERN", "TEMP_FILE",
                                        "VAR_VALUE",    "TEMP_FILE"};
    static const shell_transform_type_t types[] = {
        SHELL_TRANSFORM_NONE,     SHELL_TRANSFORM_VARIABLE,
        SHELL_TRANSFORM_GLOB,     SHELL_TRANSFORM_SUBSHELL,
        SHELL_TRANSFORM_VARIABLE, SHELL_TRANSFORM_SUBSHELL};
    shell_transformed_command_t **commands = NULL;
    size_t count = 0;
    bool valid =
        shell_transform_command_line(input, strlen(input), NULL, &commands,
                                     &count) == SHELL_TRANSFORM_OK &&
        count == 1 && commands && commands[0] &&
        commands[0]->token_count == sizeof(types) / sizeof(types[0]);
    memset(input, 'X', strlen(input));
    if (valid &&
        (strcmp(commands[0]->original_command,
                "echo $NAME *.txt $(id) $((1+2)) <(left)") != 0 ||
         strcmp(commands[0]->display_text,
                "echo VAR_VALUE FILE_PATTERN TEMP_FILE VAR_VALUE TEMP_FILE") !=
             0 ||
         !commands[0]->has_transformations || !commands[0]->has_shell_syntax))
      valid = false;
    for (size_t i = 0; valid && i < sizeof(types) / sizeof(types[0]); i++) {
      shell_transformed_token_t *token = &commands[0]->tokens[i];
      valid = token->original && token->transformed &&
              strcmp(token->original, originals[i]) == 0 &&
              strcmp(token->transformed, transformed[i]) == 0 &&
              token->type == types[i] &&
              token->is_shell_construct == (types[i] != SHELL_TRANSFORM_NONE);
    }
    test("Transform: token metadata owns exact strings", valid);
    shell_transformed_command_list_free(commands, count);
  }

  {
    static const char input[] = "echo >out";
    shell_transformed_command_t **commands = NULL;
    size_t count = 0;
    bool valid =
        shell_transform_command_line(input, strlen(input), NULL, &commands,
                                     &count) == SHELL_TRANSFORM_OK &&
        count == 1 && commands && commands[0] &&
        !commands[0]->has_transformations && commands[0]->has_shell_syntax;
    bool saw_redirect = false;
    for (size_t i = 0; valid && i < commands[0]->token_count; i++) {
      const shell_transformed_token_t *token = &commands[0]->tokens[i];
      if (strcmp(token->original, ">") != 0)
        continue;
      saw_redirect =
          token->type == SHELL_TRANSFORM_NONE && token->is_shell_construct;
    }
    test("Transform: shell syntax need not normalize display",
         valid && saw_redirect);
    shell_transformed_command_list_free(commands, count);
  }

  {
    static const char input[] = "left |& right";
    shell_transformed_command_t **commands = NULL;
    size_t count = 0;
    bool valid =
        shell_transform_command_line(input, strlen(input), NULL, &commands,
                                     &count) == SHELL_TRANSFORM_OK &&
        count == 2;
    bool saw_pipe = false;
    for (size_t command = 0; valid && command < count; command++) {
      for (size_t token = 0; token < commands[command]->token_count; token++) {
        const shell_transformed_token_t *item =
            &commands[command]->tokens[token];
        valid = item->type >= SHELL_TRANSFORM_NONE &&
                item->type <= SHELL_TRANSFORM_SUBSHELL;
        if (strcmp(item->original, "|&") == 0)
          saw_pipe =
              item->type == SHELL_TRANSFORM_NONE && item->is_shell_construct;
      }
    }
    test("Transform: operators use shell marker without legacy categories",
         valid && saw_pipe);
    shell_transformed_command_list_free(commands, count);
  }

  static const tokenizer_transform_line_case_t transform_line_cases[] = {
      {"Transform: variable",
       "echo $NAME",
       1,
       {"echo VAR_VALUE"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform: quoted variable",
       "echo \"$NAME\"",
       1,
       {"echo VAR_VALUE"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform: embedded quoted variable",
       "echo \"prefix ${NAME} suffix\"",
       1,
       {"echo \"prefix VAR_VALUE suffix\""},
       UINT32_C(0x1),
       {NULL}},
      {"Transform: literal quoted dollars",
       "echo 'Cost: $100' \"Cost: \\$100\"",
       1,
       {"echo 'Cost: $100' \"Cost: \\$100\""},
       0,
       {NULL}},
      {"Transform: glob",
       "ls *.txt",
       1,
       {"ls FILE_PATTERN"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform: multiple variables",
       "echo $A $B $C",
       1,
       {"echo VAR_VALUE VAR_VALUE VAR_VALUE"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform: braced variable",
       "echo ${VAR}",
       1,
       {"echo VAR_VALUE"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform: command substitution",
       "cat $(file)",
       1,
       {"cat TEMP_FILE"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform: backtick substitution",
       "cat `file`",
       1,
       {"cat TEMP_FILE"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform: special variables",
       "echo $1 $# $? $$",
       1,
       {"echo VAR_VALUE VAR_VALUE VAR_VALUE VAR_VALUE"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: mixed features",
       "ls ${DIR}/*.txt | grep $PATTERN",
       2,
       {"ls VAR_VALUEFILE_PATTERN |", "grep VAR_VALUE"},
       UINT32_C(0x3),
       {"ls ${DIR}/*.txt |", "grep $PATTERN"}},
      {"Transform line: complex pipeline",
       "find ${DIR} -name \"*.log\" | head -${N} | sort",
       3,
       {"find VAR_VALUE -name \"*.log\" |", "head -VAR_VALUE |", "sort"},
       UINT32_C(0x3),
       {"find ${DIR} -name \"*.log\" |", "head -${N} |", "sort"}},
      {"Transform line: preserves variable word affixes",
       "printf prefix=${NAME}suffix end",
       1,
       {"printf prefix=VAR_VALUEsuffix end"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: preserves multiple variable word fragments",
       "printf prefix${ONE}--${TWO}/${THREE}",
       1,
       {"printf prefixVAR_VALUE--VAR_VALUE/VAR_VALUE"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: preserves unbraced and escaped word fragments",
       "printf prefix$NAME-suffix\\$literal",
       1,
       {"printf prefixVAR_VALUE-suffix\\$literal"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: preserves special-variable word fragments",
       "printf status-$?",
       1,
       {"printf status-VAR_VALUE"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: retains literal dollar fragments",
       "printf prefix=${NAME}suffix escaped=\\$NAME 'literal=$NAME'",
       1,
       {"printf prefix=VAR_VALUEsuffix escaped=\\$NAME 'literal=$NAME'"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: preserves quoted variable affixes",
       "printf \"prefix-${NAME}\" \"${OTHER}suffix\" \"${ONE}-${TWO}\"",
       1,
       {"printf \"prefix-VAR_VALUE\" \"VAR_VALUEsuffix\" "
        "\"VAR_VALUE-VAR_VALUE\""},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: joins quoted and variable fragments",
       "echo \"x\"${y}z",
       1,
       {"echo \"x\"VAR_VALUEz"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: joins ANSI-C and literal fragments",
       "echo $'x'3",
       1,
       {"echo $'x'3"},
       0,
       {NULL}},
      {"Transform line: quoted command substitution has shell syntax",
       "echo \"$(id)\"",
       1,
       {"echo \"$(id)\""},
       UINT32_C(0x10000),
       {NULL}},
      {"Transform line: quoted backticks have shell syntax",
       "echo \"`id`\"",
       1,
       {"echo \"`id`\""},
       UINT32_C(0x10000),
       {NULL}},
      {"Transform line: quoted process substitution is literal",
       "echo \"<(id)\"",
       1,
       {"echo \"<(id)\""},
       0,
       {NULL}},
      {"Transform line: ANSI-C substitution spelling is literal",
       "echo $'$(id)'",
       1,
       {"echo $'$(id)'"},
       0,
       {NULL}},
      {"Transform line: ANSI-C escaped quote keeps substitution literal",
       "echo $'it\\'s $(id)'",
       1,
       {"echo $'it\\'s $(id)'"},
       0,
       {NULL}},
      {"Transform line: extglob becomes a file pattern",
       "echo @(left|right)",
       1,
       {"echo FILE_PATTERN"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: removes LF word continuations",
       "echo \"x\"\\\n${y}z",
       1,
       {"echo \"x\"VAR_VALUEz"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: preserves escaped CR before a newline",
       "echo \"x\"\\\r\n# comment",
       1,
       {"echo \"x\"\\\r \n"},
       UINT32_C(0x10000),
       {NULL}},
      {"Transform line: preserves escaped CR next to a variable",
       "echo \"x\"\\\r${y}z",
       1,
       {"echo \"x\"\\\rVAR_VALUEz"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: preserves VT and FF word bytes",
       "echo a\vb a\fb",
       1,
       {"echo a\vb a\fb"},
       0,
       {NULL}},
      {"Transform line: joins substitution suffixes",
       "echo $(id)suffix",
       1,
       {"echo TEMP_FILEsuffix"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: joins process-substitution affixes",
       "echo pre<(id)post",
       1,
       {"echo preTEMP_FILEpost"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: separate process substitution stays separate",
       "echo pre <(id) post",
       1,
       {"echo pre TEMP_FILE post"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: Bash pipe-both",
       "printf $VALUE |& cat",
       2,
       {"printf VAR_VALUE |&", "cat"},
       UINT32_C(0x1),
       {"printf $VALUE |&", "cat"}},
      {"Transform line: variables and redirection",
       "echo $VAR | grep $PATTERN > output.txt",
       2,
       {"echo VAR_VALUE |", "grep VAR_VALUE > output.txt"},
       UINT32_C(0x3),
       {"echo $VAR |", "grep $PATTERN > output.txt"}},
      {"Transform line: redirection only",
       "cmd > file.txt 2>&1",
       1,
       {"cmd > file.txt 2>&1"},
       UINT32_C(0x10000),
       {NULL}},
      {
          "Transform line: syntax without replacements",
          "a | b && c || d ; e",
          5,
          {"a |", "b &&", "c ||", "d ;", "e"},
          UINT32_C(0xf0000),
          {"a |", "b &&", "c ||", "d ;", "e"},
      },
      {"Transform line: preserves stage source spans",
       "  echo $A | printf %s $B  ",
       2,
       {"echo VAR_VALUE |", "printf %s VAR_VALUE"},
       UINT32_C(0x3),
       {"  echo $A |", "printf %s $B  "}},
      {"Transform line: empty input", "", 0, {NULL}, 0, {NULL}},
  };
  tokenizer_run_transform_line_cases(transform_line_cases,
                                     sizeof(transform_line_cases) /
                                         sizeof(transform_line_cases[0]));

  {
    static const struct {
      const char *source;
      shell_transform_status_t status;
    } cases[] = {
        {"", SHELL_TRANSFORM_BLANK},
        {" \t", SHELL_TRANSFORM_BLANK},
        {"\x01"
         "cmd",
         SHELL_TRANSFORM_EINPUT},
        {"echo '", SHELL_TRANSFORM_EPARSE},
    };
    bool valid = true;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      shell_transformed_command_t **commands =
          (shell_transformed_command_t **)(uintptr_t)1;
      size_t count = SIZE_MAX;
      shell_transform_status_t status = shell_transform_command_line(
          cases[i].source, strlen(cases[i].source), NULL, &commands, &count);
      valid =
          valid && status == cases[i].status && commands == NULL && count == 0;
      shell_transformed_command_list_free(commands, count);
    }
    shell_transformed_command_free(NULL);
    test("Transform: external-input failures clear writable outputs", valid);
  }

  {
    static const char *const sources[] = {
        "echo a | cat",    "cat <input",
        "echo a >output",  "echo a 2>error",
        "echo a >>output", "cat <>data",
        "echo a >|output", "echo a; echo b",
        "true && echo a",  "echo a &",
        "false || echo a", "{ echo a; }",
        "(echo a)",        "cat <<EOF\nbody\nEOF\n",
        "cat <<<word",     "cat <(echo a)",
    };
    bool valid = true;
    for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
      shell_transformed_command_t **commands = NULL;
      size_t count = 0;
      shell_transform_status_t status = shell_transform_command_line(
          sources[i], strlen(sources[i]), NULL, &commands, &count);
      bool has_syntax = false;
      for (size_t j = 0; j < count; j++)
        has_syntax |= commands[j]->has_shell_syntax;
      valid = valid && status == SHELL_TRANSFORM_OK && has_syntax;
      shell_transformed_command_list_free(commands, count);
    }
    test("Transform: real shell constructs retain diagnostic syntax", valid);
  }

  {
    shell_transformed_command_t **commands =
        (shell_transformed_command_t **)(uintptr_t)1;
    size_t count = SIZE_MAX;
    const shell_transform_limits_t tiny = {3, 3};
    shell_transform_status_t status = shell_transform_command_line(
        "echo $NAME", strlen("echo $NAME"), &tiny, &commands, &count);
    bool valid = status == SHELL_TRANSFORM_EOUTPUT_LIMIT && commands == NULL &&
                 count == 0;
    test("Transform: explicit output limits report rejection", valid);
    shell_transformed_command_list_free(commands, count);
  }

  printf("\n=== STRESS/CRASH TEST CASES ===\n\n");

  static const tokenizer_feature_case_t stress_edge_cases[] = {
      {{"Edge: unclosed command substitution", "echo $(cmd", 1}, 0},
      {{"Edge: unclosed arithmetic expansion", "echo $((x+1)", 1}, 0},
      {{"Edge: empty quotes", "echo \"\" ''", 1}, 0},
      {{"Edge: mixed quote characters", "echo \"hello'world\"", 1}, 0},
      {{"Edge: trailing backslash", "echo hello\\", 1}, 0},
      {{"Edge: adjacent special variables", "echo $$$$$$", 1},
       tokenizer_EXPECT_VARIABLE},
      {{"Edge: unclosed bracket glob", "ls file[", 1}, 0},
      {{"Edge: lone bracket glob", "ls [", 1}, 0},
      {{"Edge: unclosed negated bracket glob", "ls file[!", 1}, 0},
      {{"Edge: command substitution containing pipe",
        "echo $(cat file.txt | grep pattern)", 1},
       tokenizer_EXPECT_SUBSHELL},
      {{"Stress: sixteen pipeline stages", "a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p",
        16},
       0},
      {{"Stress: eight semicolon-separated commands",
        "cmd1; cmd2; cmd3; cmd4; cmd5; cmd6; cmd7; cmd8", 8},
       0},
      {{"Edge: mixed sequencing operators",
        "cmd1 | cmd2 && cmd3 ; cmd4 || cmd5", 5},
       0},
      {{"Edge: variable names containing digits", "echo $VAR123 $ABC_456_DEF",
        1},
       tokenizer_EXPECT_VARIABLE},
      {{"Edge: lone dollar", "echo $", 1}, 0},
      {{"Edge: unclosed backtick", "echo `", 1}, 0},
      {{"Edge: repeated redirections",
        "cmd < in.txt > out1.txt 2> err.txt >> log1.txt >> log2.txt", 1},
       0},
      {{"Edge: redirections around pipeline",
        "cat < file.txt | grep pattern > output.txt 2>&1", 2},
       0},
      {{"Edge: special parameter family",
        "echo $1 $2 $3 $4 $5 $6 $7 $8 $9 $10 $$ $? $# $-", 1},
       tokenizer_EXPECT_VARIABLE},
      {{"Edge: adjacent quoted variables", "echo \"$VAR$VAR2${VAR3}\"", 1},
       tokenizer_EXPECT_VARIABLE},
      {{"Edge: variable followed by glob", "ls $DIR/*.txt", 1},
       tokenizer_EXPECT_VARIABLE | tokenizer_EXPECT_GLOB},
      {{"Edge: multiple glob forms", "ls *.txt *.log *.dat ??.* [abc]*.{cpp,h}",
        1},
       tokenizer_EXPECT_GLOB},
      {{"Edge: arithmetic operator family",
        "echo $((a+b)) $((c-d)) $((e*f)) $((g/h)) $((i%j)) $((k**l))", 1},
       tokenizer_EXPECT_ARITHMETIC},
      {{"Edge: arithmetic command framing", "(((echo hello)))", 1},
       tokenizer_EXPECT_ARITHMETIC},
      {{"Edge: alternating quote forms", "echo 'a\"b\"c' \"d'e'e\"", 1}, 0},
      {{"Edge: variable followed by bracket glob", "ls $FILE[0-9]", 1},
       tokenizer_EXPECT_VARIABLE | tokenizer_EXPECT_GLOB},
      {{"Edge: all sequencing operators", "cmd1 && cmd2 || cmd3 | cmd4 ; cmd5",
        5},
       0},
      {{"Edge: redirect-only command", "< in.txt > out.txt", 1}, 0},
      {{"Stress: mixed-feature sequence",
        "cat ${FILE1} | grep -E '$PATTERN|${ALT}' | sort -u > ${OUTPUT}.txt && "
        "echo \"Done: $(wc -l < ${OUTPUT}.txt)\"",
        4},
       tokenizer_EXPECT_VARIABLE | tokenizer_EXPECT_SUBSHELL},
      {{"Stress: nested substitution containing features",
        "echo $(echo $(echo $VAR *.txt $((x+1))))", 1},
       tokenizer_EXPECT_SUBSHELL},
      {{"Edge: ordered descriptor duplication", "cmd > file.txt 2>&1 1>&2", 1},
       0},
      {{"Edge: heredoc-shaped multiline input", "cmd <<EOF\nhello\nEOF", 1}, 0},
      {{"Edge: substitution pipe followed by outer pipe",
        "cmd $(echo a | cat) | cmd2", 2},
       tokenizer_EXPECT_SUBSHELL},
      {{"Stress: all token feature classes",
        "cmd $VAR ${VAR} *.txt $((1+2)) $(cmd) `cmd` $1 | cmd2 < file.txt > "
        "out.txt 2>&1 && cmd3 || cmd4 ; cmd5",
        5},
       tokenizer_EXPECT_VARIABLE | tokenizer_EXPECT_GLOB |
           tokenizer_EXPECT_SUBSHELL | tokenizer_EXPECT_ARITHMETIC},
      {{"Edge: dash-leading command", "-n echo hello", 1}, 0},
      {{"Edge: escaped space", "echo hello\\ world", 1}, 0},
      {{"Edge: trailing semicolon", "echo hello ;", 1}, 0},
      {{"Edge: backslashes in double quotes", "echo \"path\\to\\file\"", 1}, 0},
      {{"Edge: newline in double quotes", "echo \"hello\nworld\"", 1}, 0},
      {{"Edge: unusual arithmetic parentheses", "echo $((x)) $((())) $(((x)))",
        1},
       tokenizer_EXPECT_ARITHMETIC},
      {{"Edge: command substitution containing semicolons",
        "echo $(cmd1; cmd2; cmd3)", 1},
       tokenizer_EXPECT_SUBSHELL},
  };
  tokenizer_run_feature_cases(stress_edge_cases,
                              sizeof(stress_edge_cases) /
                                  sizeof(stress_edge_cases[0]));

  // Test 97: Long command (~4x larger than typical)
  {
    const char *input = "cmd1 $VAR1 $VAR2 $VAR3 $VAR4 $VAR5 $VAR6 $VAR7 $VAR8 "
                        "$VAR9 $VAR10 *.txt *.log *.dat | "
                        "cmd2 $VAR1 $VAR2 $VAR3 $VAR4 $VAR5 | "
                        "cmd3 $(sub1) $(sub2) $(sub3) | "
                        "cmd4 `back1` `back2` `back3` | "
                        "cmd5 $((x+1)) $((y*2)) $((z-3)) | "
                        "cmd6 ${VAR1} ${VAR2} ${VAR3} | "
                        "cmd7 *.???[0-9]*.{a,b,c} | "
                        "cmd8 | cmd9 | cmd10 | cmd11 | cmd12";
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = (shell_tokenize_commands(input, strlen(input), &cmds,
                                          &count) == SHELL_TOKENIZE_OK);
    test("Stress: long command (~4x)",
         result && count == 12 &&
             tokenizer_tokens_are_consistent(input, cmds, count));
    shell_commands_free(cmds, count);
  }

  // Test 118: Very long single token
  {
    char input[2048];
    memset(input, 'a', 2047);
    input[2047] = '\0';
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = (shell_tokenize_commands(input, strlen(input), &cmds,
                                          &count) == SHELL_TOKENIZE_OK);
    test("Stress: very long token (2KB)",
         result && count == 1 && cmds[0].token_count == 1 &&
             cmds[0].tokens[0].length == sizeof(input) - 1 &&
             tokenizer_tokens_are_consistent(input, cmds, count));
    shell_commands_free(cmds, count);
  }

  // Test 144: Very long command (~8x typical)
  {
    char input[8192];
    strcpy(input, "cmd1 $V1 $V2 $V3 *.txt *.log | ");
    for (int i = 0; i < 50; i++) {
      strcat(input, "cmd$((i)) $(echo i) | ");
    }
    strcat(input, "tail");
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = (shell_tokenize_commands(input, strlen(input), &cmds,
                                          &count) == SHELL_TOKENIZE_OK);
    test("Stress: very long command (~8x)",
         result && count == 52 &&
             tokenizer_tokens_are_consistent(input, cmds, count));
    shell_commands_free(cmds, count);
  }

  static const tokenizer_processor_case_t processor_cases[] = {
      {"Processor: plain command",
       "echo hello",
       1,
       {"echo hello"},
       {"echo hello"},
       {0},
       0},
      {"Processor: pipeline",
       "echo hello | grep world",
       2,
       {"echo hello |", "grep world"},
       {"echo hello", "grep world"},
       {tokenizer_PROCESS_PIPE_OUTPUT, tokenizer_PROCESS_PIPE_INPUT},
       0x3},
      {"Processor: redirections",
       "cmd > output.txt 2>&1",
       1,
       {"cmd > output.txt 2>&1"},
       {"cmd"},
       {tokenizer_PROCESS_REDIRECTION | tokenizer_PROCESS_ERROR_REDIRECTION},
       0x1},
      {"Processor: combined redirect marks stderr",
       "cmd &> output.txt",
       1,
       {"cmd &> output.txt"},
       {"cmd"},
       {tokenizer_PROCESS_REDIRECTION | tokenizer_PROCESS_ERROR_REDIRECTION},
       0x1},
      {"Processor: combined append redirect marks stderr",
       "cmd &>> output.txt",
       1,
       {"cmd &>> output.txt"},
       {"cmd"},
       {tokenizer_PROCESS_REDIRECTION | tokenizer_PROCESS_ERROR_REDIRECTION},
       0x1},
      {"Processor: sequencing operators",
       "a && b || c ; d",
       4,
       {"a &&", "b ||", "c ;", "d"},
       {"a", "b", "c", "d"},
       {0, 0, 0, 0},
       0x7},
      {"Processor: redirected pipeline",
       "cat < in | grep x > out",
       2,
       {"cat < in |", "grep x > out"},
       {"cat", "grep x"},
       {tokenizer_PROCESS_PIPE_OUTPUT | tokenizer_PROCESS_REDIRECTION,
        tokenizer_PROCESS_PIPE_INPUT | tokenizer_PROCESS_REDIRECTION},
       0x3},
      {"Processor: descriptor duplication keeps following argument",
       "cmd 2>&1 arg",
       1,
       {"cmd 2>&1 arg"},
       {"cmd arg"},
       {tokenizer_PROCESS_REDIRECTION | tokenizer_PROCESS_ERROR_REDIRECTION},
       0x1},
      {"Processor: raw close marker keeps adjacent argv",
       "printf x >&-file",
       1,
       {"printf x >&-file"},
       {"printf x file"},
       {tokenizer_PROCESS_REDIRECTION | tokenizer_PROCESS_ERROR_REDIRECTION},
       0x1},
      {"Processor: here-string operand is shell syntax",
       "cat <<< data",
       1,
       {"cat <<< data"},
       {"cat"},
       {tokenizer_PROCESS_REDIRECTION},
       0x1},
      {"Processor: heredoc body is shell syntax",
       "cat <<-'EOF'\n\t$LITERAL\n\tEOF",
       1,
       {"cat <<-'EOF'\n\t$LITERAL\n\tEOF"},
       {"cat"},
       {tokenizer_PROCESS_REDIRECTION},
       0x1},
      {"Processor: redirect-only stage has empty DFA input",
       "> output",
       1,
       {"> output"},
       {""},
       {tokenizer_PROCESS_REDIRECTION},
       0x1},
      {"Processor: variables remain in DFA input",
       "echo $VAR $NAME",
       1,
       {"echo $VAR $NAME"},
       {"echo $VAR $NAME"},
       {0},
       0},
      {"Processor: assembles quote fragments and escaped spaces",
       "echo foo\"bar\" a\\ b pre' mid 'post",
       1,
       {"echo foo\"bar\" a\\ b pre' mid 'post"},
       {"echo foobar \"a b\" \"pre mid post\""},
       {0},
       0},
      {"Processor: preserves empty and quoted operator arguments",
       "printf '' \"\" '>'",
       1,
       {"printf '' \"\" '>'"},
       {"printf \"\" \"\" \">\""},
       {0},
       0},
      {"Processor: canonicalizes literal quote and backslash arguments",
       "printf 'a\"b' \"c'd\" 'x\\y'",
       1,
       {"printf 'a\"b' \"c'd\" 'x\\y'"},
       {"printf \"a\\\"b\" \"c'd\" \"x\\\\y\""},
       {0},
       0},
      {"Processor: assembles adjacent empty quote fragments",
       "printf foo''bar ''foo foo''",
       1,
       {"printf foo''bar ''foo foo''"},
       {"printf foobar foo foo"},
       {0},
       0},
      {"Processor: removes escaped newlines while assembling words",
       "printf a\\\nb \"c\\\nd\"",
       1,
       {"printf a\\\nb \"c\\\nd\""},
       {"printf ab cd"},
       {0},
       0},
      {"Processor: command substitution is shell execution",
       "echo $(id) `whoami`",
       1,
       {"echo $(id) `whoami`"},
       {"echo $(id) `whoami`"},
       {0},
       0x1},
      {"Processor: process substitution is shell execution",
       "diff <(left) >(right)",
       1,
       {"diff <(left) >(right)"},
       {"diff <(left) >(right)"},
       {0},
       0x1},
      {"Processor: empty input", "", 0, {NULL}, {NULL}, {0}, 0},
  };
  tokenizer_run_processor_cases(
      processor_cases, sizeof(processor_cases) / sizeof(processor_cases[0]));

  {
    char input[] = "cat < in | grep x > out";
    shell_command_info_t *infos = NULL;
    size_t count = 0;
    bool processed = shell_process_command(input, strlen(input), NULL, &infos,
                                           &count) == SHELL_PROCESS_OK;
    memset(input, 'X', sizeof(input) - 1);
    bool valid =
        processed && count == 2 && infos &&
        strcmp(infos[0].original_command, "cat < in |") == 0 &&
        strcmp(infos[1].original_command, "grep x > out") == 0 &&
        infos[0].command_token_count == 1 && infos[0].shell_token_count == 2 &&
        infos[1].command_token_count == 2 && infos[1].shell_token_count == 1 &&
        strncmp(infos[0].command_tokens[0].start, "cat", 3) == 0 &&
        infos[0].shell_tokens[0].start[0] == '<' &&
        infos[0].shell_tokens[1].start[0] == '|' &&
        strncmp(infos[1].command_tokens[0].start, "grep", 4) == 0 &&
        infos[1].shell_tokens[0].start[0] == '>';
    test("Processor: returned metadata owns its source text", valid);
    shell_command_infos_free(infos, count);
  }

  // Test: NULL handling
  {
    shell_command_info_t *infos = (shell_command_info_t *)(uintptr_t)1;
    size_t count = SIZE_MAX;
    shell_process_status_t process_result =
        shell_process_command("", 0, NULL, &infos, &count);
    bool process_valid =
        process_result == SHELL_PROCESS_BLANK && infos == NULL && count == 0;
    test("Processor: empty input is blank and produces no lexical records",
         process_valid);

    static const char *const blank[] = {" \t\n", "# comment", "\\\n"};
    bool blank_valid = true;
    for (size_t i = 0; i < sizeof(blank) / sizeof(blank[0]); i++) {
      infos = (shell_command_info_t *)(uintptr_t)1;
      count = SIZE_MAX;
      blank_valid =
          blank_valid &&
          shell_process_command(blank[i], strlen(blank[i]), NULL, &infos,
                                &count) == SHELL_PROCESS_BLANK &&
          infos == NULL && count == 0;
    }
    test("Processor: trivia-only source is blank in the flat API", blank_valid);

    infos = (shell_command_info_t *)(uintptr_t)1;
    count = SIZE_MAX;
    process_result = shell_process_command("\x01"
                                           "cmd",
                                           strlen("\x01"
                                                  "cmd"),
                                           NULL, &infos, &count);
    process_valid =
        process_result != SHELL_PROCESS_OK && infos == NULL && count == 0;
    test("Processor: rejected input clears every writable output",
         process_valid);
  }

  {
    const char *word = "foo\"bar\"\\\n' two words'\\$";
    const char expected[] = "foobar two words$";
    char decoded[sizeof(expected)] = {0};
    size_t measured = 0, written = 0;
    bool valid = shell_measure_decoded_word(word, strlen(word), &measured) ==
                     SHELL_PROCESS_OK &&
                 measured == strlen(expected) &&
                 shell_write_decoded_word(word, strlen(word), decoded, measured,
                                          &written) == SHELL_PROCESS_OK &&
                 written == measured &&
                 memcmp(decoded, expected, measured) == 0;
    const size_t expected_length = measured;
    valid = valid &&
            shell_write_decoded_word(word, strlen(word), decoded, measured - 1,
                                     &written) == SHELL_PROCESS_EOUTPUT_LIMIT &&
            written == 0;
    char *owned = NULL;
    size_t owned_length = 0;
    valid = valid &&
            shell_decode_word(word, strlen(word), &owned, &owned_length) ==
                SHELL_PROCESS_OK &&
            owned_length == expected_length && strcmp(owned, expected) == 0;
    free(owned);
    test("Decoded-word measure/write matches owned decoding", valid);
  }

  {
    static const char word[] = "$'\\x2fhome\\0'$(id)";
    static const unsigned char expected[] = {'/', 'h', 'o', 'm', 'e', '\0',
                                             '$', '(', 'i', 'd', ')'};
    unsigned char visited[sizeof(expected)] = {0};
    unsigned char written_bytes[sizeof(expected)] = {0};
    tokenizer_decoded_word_capture_t capture = {
        .bytes = visited,
        .capacity = sizeof(visited),
    };
    size_t visited_length = 0;
    size_t measured = 0;
    size_t written = 0;
    bool valid =
        shell_visit_decoded_word(word, sizeof(word) - 1,
                                 tokenizer_capture_decoded_word_byte, &capture,
                                 &visited_length) == SHELL_PROCESS_OK &&
        shell_measure_decoded_word(word, sizeof(word) - 1, &measured) ==
            SHELL_PROCESS_OK &&
        shell_write_decoded_word(word, sizeof(word) - 1, (char *)written_bytes,
                                 sizeof(written_bytes),
                                 &written) == SHELL_PROCESS_OK &&
        visited_length == sizeof(expected) && measured == sizeof(expected) &&
        written == sizeof(expected) &&
        memcmp(visited, expected, sizeof(expected)) == 0 &&
        memcmp(written_bytes, expected, sizeof(expected)) == 0;
    capture.stop_after = 3;
    memset(visited, 0, sizeof(visited));
    visited_length = 0;
    valid = valid &&
            shell_visit_decoded_word(
                word, sizeof(word) - 1, tokenizer_capture_decoded_word_byte,
                &capture, &visited_length) == SHELL_PROCESS_OK &&
            visited_length == 3 && memcmp(visited, expected, 3) == 0;
    test("Decoded-word visitor shares binary-safe syntax decoding", valid);
  }

  {
    static const char static_word[] = "c'ur'\\l$'\\x00'";
    static const unsigned char expected[] = {'c', 'u', 'r', 'l'};
    unsigned char bytes[sizeof(expected)] = {0};
    tokenizer_decoded_word_capture_t capture = {
        .bytes = bytes,
        .capacity = sizeof(bytes),
    };
    size_t length = SIZE_MAX;
    bool valid = shell_visit_static_word(static_word, sizeof(static_word) - 1,
                                         tokenizer_capture_decoded_word_byte,
                                         &capture, &length) &&
                 length == sizeof(expected) &&
                 memcmp(bytes, expected, sizeof(expected)) == 0;
    capture.stop_after = 1;
    length = SIZE_MAX;
    valid = valid &&
            shell_visit_static_word(
                "$'a\\0discarded'c", strlen("$'a\\0discarded'c"),
                tokenizer_capture_decoded_word_byte, &capture, &length) &&
            length == 1 && bytes[0] == 'a';
    length = SIZE_MAX;
    valid = valid &&
            !shell_visit_static_word("\"$command\"", strlen("\"$command\""),
                                     tokenizer_capture_decoded_word_byte,
                                     &capture, &length) &&
            length == 0;
    length = SIZE_MAX;
    valid = valid &&
            !shell_visit_static_word("'unfinished", strlen("'unfinished"),
                                     tokenizer_capture_decoded_word_byte,
                                     &capture, &length) &&
            length == 0;
    test("Static-word visitor rejects runtime and malformed words", valid);
  }

  {
    static const struct {
      const char *word;
      const char *payload;
      bool is_static;
    } cases[] = {{"a<()b", "ab", true},
                 {"<()", "", true},
                 {"''<()", "", true},
                 {"a>( \t\n)b", "ab", true},
                 {"a<(printf x)b", "a<(printf x)b", false}};
    bool valid = true;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      const char *word = cases[i].word;
      size_t length = strlen(word), measured = SIZE_MAX, written = SIZE_MAX;
      size_t visited = SIZE_MAX, owned_length = SIZE_MAX;
      char bytes[64] = {0};
      char *owned = NULL;
      size_t expected = strlen(cases[i].payload);
      valid = valid &&
              shell_measure_decoded_word(word, length, &measured) ==
                  SHELL_PROCESS_OK &&
              measured == expected &&
              shell_write_decoded_word(word, length, bytes, sizeof(bytes),
                                       &written) == SHELL_PROCESS_OK &&
              written == expected &&
              memcmp(bytes, cases[i].payload, expected) == 0 &&
              shell_visit_decoded_word(word, length, NULL, NULL, &visited) ==
                  SHELL_PROCESS_OK &&
              visited == expected &&
              shell_decode_word(word, length, &owned, &owned_length) ==
                  SHELL_PROCESS_OK &&
              owned_length == expected &&
              memcmp(owned, cases[i].payload, expected) == 0 &&
              shell_measure_processed_word(word, length, &measured) ==
                  SHELL_PROCESS_OK &&
              measured == expected &&
              shell_write_processed_word(word, length, bytes, sizeof(bytes),
                                         &written) == SHELL_PROCESS_OK &&
              written == expected &&
              memcmp(bytes, cases[i].payload, expected) == 0 &&
              shell_visit_static_word(word, length, NULL, NULL, &visited) ==
                  cases[i].is_static;
      free(owned);
    }
    test("Word helpers elide empty process payloads, retaining nonempty source",
         valid);
  }

  {
    const char *word = "quoted";
    char *owned = (char *)(uintptr_t)1;
    size_t length = SIZE_MAX;
    bool valid = true;
    shellsplit_test_alloc_reset();
    shellsplit_test_alloc_fail_at(1);
    valid = valid &&
            shell_decode_word(word, strlen(word), &owned, &length) ==
                SHELL_PROCESS_ENOMEM &&
            owned == NULL && length == 0;
    shellsplit_test_alloc_reset();
    test("Decoded-word allocation failure clears owned output", valid);
  }

  {
    static const char word[] = "word";
    static const char redirect[] = ">";
    shell_token_t tokens[] = {
        {.type = SHELL_TOKEN_COMMAND, .start = word, .length = 4},
        {.type = SHELL_TOKEN_REDIRECT_OUT, .start = redirect, .length = 1},
        {.type = SHELL_TOKEN_ARGUMENT, .start = word, .length = 4},
        {.type = SHELL_TOKEN_PIPE, .start = "|", .length = 1},
        {.type = SHELL_TOKEN_SUBSHELL, .start = "$(x)", .length = 4},
        {.type = SHELL_TOKEN_PROCESS_SUB, .start = "<(x)", .length = 4},
    };
    shell_command_t command = {
        .tokens = tokens, .token_count = sizeof(tokens) / sizeof(tokens[0])};
    shell_command_t plain = {.tokens = tokens, .token_count = 1};
    shell_token_t redirections[] = {
        {.type = SHELL_TOKEN_COMMAND, .start = word, .length = 4},
        {.type = SHELL_TOKEN_REDIRECT_IN, .start = "<", .length = 1},
        {.type = SHELL_TOKEN_ARGUMENT, .start = word, .length = 4},
        {.type = SHELL_TOKEN_REDIRECT_APPEND, .start = ">>", .length = 2},
        {.type = SHELL_TOKEN_ARGUMENT, .start = word, .length = 4},
        {.type = SHELL_TOKEN_HEREDOC, .start = "<<", .length = 2},
        {.type = SHELL_TOKEN_ARGUMENT, .start = word, .length = 4},
        {.type = SHELL_TOKEN_HERESTRING, .start = "<<<", .length = 3},
        {.type = SHELL_TOKEN_ARGUMENT, .start = word, .length = 4},
        {.type = SHELL_TOKEN_REDIRECT_ERR, .start = "", .length = 0},
        {.type = SHELL_TOKEN_ARGUMENT, .start = word, .length = 4},
    };
    shell_token_t plain_words[] = {
        {.type = SHELL_TOKEN_COMMAND, .start = word, .length = 4},
        {.type = SHELL_TOKEN_ARGUMENT, .start = word, .length = 4},
    };
    shell_command_t only_words = {.tokens = plain_words, .token_count = 2};
    shell_command_t nested_word = {.tokens = &tokens[4], .token_count = 2};
    shell_command_t redirects = {
        .tokens = redirections,
        .token_count = sizeof(redirections) / sizeof(redirections[0]),
    };
    shell_processed_word_iterator_t iterator;
    shell_token_t command_word[4] = {0};
    shell_token_t redirect_word[3] = {0};
    shell_processed_word_iterator_init(&iterator, &command);
    bool command_words =
        shell_processed_word_iterator_next(&iterator, &command_word[0]) &&
        shell_processed_word_iterator_next(&iterator, &command_word[1]) &&
        shell_processed_word_iterator_next(&iterator, &command_word[2]) &&
        !shell_processed_word_iterator_next(&iterator, &command_word[3]);
    shell_processed_word_iterator_init(&iterator, &redirects);
    bool redirect_words =
        shell_processed_word_iterator_next(&iterator, &redirect_word[0]) &&
        shell_processed_word_iterator_next(&iterator, &redirect_word[1]) &&
        !shell_processed_word_iterator_next(&iterator, &redirect_word[2]);
    bool valid =
        shell_processed_command_word_count(&command) == 3 &&
        !shell_processed_word_iterator_next(&iterator, &command_word[3]) &&
        command_words && command_word[0].start == tokens[0].start &&
        command_word[1].start == tokens[4].start &&
        command_word[2].start == tokens[5].start &&
        shell_processed_command_word_count(&redirects) == 2 && redirect_words &&
        redirect_word[0].start == redirections[0].start &&
        redirect_word[1].start == redirections[10].start &&
        shell_processed_command_has_dangerous_features(&plain, true) &&
        shell_processed_command_has_dangerous_features(&command, false) &&
        shell_processed_command_has_dangerous_features(&nested_word, false) &&
        !shell_processed_command_has_dangerous_features(&only_words, false) &&
        shell_processed_command_has_pipe_output(&command) &&
        !shell_processed_command_has_pipe_output(&plain);
    test("Processed-command word iterator respects redirection operands",
         valid);
  }

  {
    shell_command_info_t *infos = (shell_command_info_t *)(uintptr_t)1;
    size_t count = SIZE_MAX;
    const shell_process_limits_t tiny = {3, 3, 0};
    shell_process_status_t status = shell_process_command(
        "echo value", strlen("echo value"), &tiny, &infos, &count);
    test("Processor: explicit output limits report rejection",
         status == SHELL_PROCESS_EOUTPUT_LIMIT && infos == NULL && count == 0);
    shell_command_infos_free(infos, count);
  }

  {
    shell_command_info_t *infos = NULL;
    size_t count = 0;
    shell_netstring_buffer_t netargv = {0};
    shell_process_limits_t limits = {1, 1, 0};
    bool valid = shell_process_command("echo x", strlen("echo x"), NULL, &infos,
                                       &count) == SHELL_PROCESS_OK &&
                 count == 1 &&
                 shell_render_netargv_buffer(&infos[0], &limits, &netargv) ==
                     SHELL_PROCESS_EOUTPUT_LIMIT &&
                 netargv.data == NULL;
    limits.max_string_bytes = SIZE_MAX;
    valid = valid &&
            shell_render_netargv_buffer(&infos[0], &limits, &netargv) ==
                SHELL_PROCESS_EOUTPUT_LIMIT &&
            netargv.data == NULL;
    shellsplit_test_alloc_reset();
    shellsplit_test_alloc_fail_at(1);
    valid = valid &&
            shell_render_netargv_buffer(&infos[0], NULL, &netargv) ==
                SHELL_PROCESS_ENOMEM &&
            netargv.data == NULL;
    shellsplit_test_alloc_reset();
    shell_command_infos_free(infos, count);
    test("Netargv rendering validates limits and allocation failures", valid);
  }

  {
    shell_command_info_t *infos = NULL;
    size_t count = 0;
    bool valid = shell_process_command("printf '' 'two words'",
                                       strlen("printf '' 'two words'"), NULL,
                                       &infos, &count) == SHELL_PROCESS_OK &&
                 count == 1;
    size_t length = 0, written = SIZE_MAX;
    char exact[32] = {0};
    char short_buffer[31];
    memset(short_buffer, 0xA5, sizeof(short_buffer));
    shell_netstring_buffer_t allocated = {0};
    valid = valid &&
            shell_measure_netargv(&infos[0], &length) == SHELL_PROCESS_OK &&
            length == strlen("6:printf,0:,9:two words,") &&
            length + 1 <= sizeof(exact) &&
            shell_write_netargv(&infos[0], exact, length + 1, &written) ==
                SHELL_PROCESS_OK &&
            written == length &&
            strcmp(exact, "6:printf,0:,9:two words,") == 0 &&
            shell_write_netargv(&infos[0], short_buffer, length, &written) ==
                SHELL_PROCESS_EOUTPUT_LIMIT &&
            written == 0 && short_buffer[0] == (char)0xA5 &&
            shell_render_netargv_buffer(&infos[0], NULL, &allocated) ==
                SHELL_PROCESS_OK &&
            (allocated.length != strlen(exact) ||
             memcmp(allocated.data, exact, allocated.length)) == 0;
    shell_netstring_buffer_free(&allocated);
    shell_command_infos_free(infos, count);
    test("Netargv measure/write matches allocating renderer", valid);
  }

  printf("\n=== PIPELINE/SUBCOMMAND EXTRACTION TESTS ===\n\n");
#define STAGES(name, input, count, vars, globs, subs, arith)                   \
  {                                                                            \
    {name, input, count}, vars, globs, subs, arith                             \
  }
  static const tokenizer_stage_case_t pipeline_cases[] = {
      STAGES("Pipeline: basic 3-stage", "cat file.txt | grep pattern | sort", 3,
             0, 0, 0, 0),
      STAGES("Pipeline: 4-stage", "a | b | c | d", 4, 0, 0, 0, 0),
      STAGES("Pipeline: semicolon separated", "cmd1 ; cmd2 ; cmd3 ; cmd4", 4, 0,
             0, 0, 0),
      STAGES("Pipeline: AND separated", "cmd1 && cmd2 && cmd3", 3, 0, 0, 0, 0),
      STAGES("Pipeline: OR separated", "cmd1 || cmd2 || cmd3", 3, 0, 0, 0, 0),
      STAGES("Pipeline: mixed operators", "cmd1 | cmd2 && cmd3 ; cmd4 || cmd5",
             5, 0, 0, 0, 0),
      STAGES("Pipeline: with redirections",
             "cat < in.txt | grep pattern > out.txt", 2, 0, 0, 0, 0),
      STAGES("Pipeline: stderr redirect", "cmd1 2>&1 | cmd2", 2, 0, 0, 0, 0),
      STAGES("Pipeline: numeric argument before redirect", "cmd1 2 >&1 | cmd2",
             2, 0, 0, 0, 0),
      STAGES("Pipeline: multiple redirects", "cmd > out.txt 2>&1", 1, 0, 0, 0,
             0),
      STAGES("Pipeline: long (10 stages)",
             "a1 | a2 | a3 | a4 | a5 | a6 | a7 | a8 | a9 | a10", 10, 0, 0, 0,
             0),
      STAGES("Pipeline: quoted args", "echo 'hello world' | tr 'a-z' 'A-Z'", 2,
             0, 0, 0, 0),
      STAGES("Pipeline: with variables", "cat $FILE | grep $PATTERN | sort", 3,
             UINT64_C(0x3), 0, 0, 0),
      STAGES("Pipeline: with globs", "ls *.txt | grep pattern | sort", 3, 0,
             UINT64_C(0x1), 0, 0),
      STAGES("Pipeline: with subshell", "cat $(file) | grep pattern", 2, 0, 0,
             UINT64_C(0x1), 0),
      STAGES("Pipeline: subshells in both stages",
             "echo $(echo cmd1) | $(echo cmd2)", 2, 0, 0, UINT64_C(0x3), 0),
      STAGES("Pipeline: with arithmetic", "echo $((x+1)) | cat", 2, 0, 0, 0,
             UINT64_C(0x1)),
      STAGES("Pipeline: nested arithmetic then command substitution",
             "echo $((1 + $((2 * 3)))) | echo $(done)", 2, 0, 0, UINT64_C(0x2),
             UINT64_C(0x1)),
      STAGES("Pipeline: real-world (passwd)",
             "cat /etc/passwd | cut -d: -f1 | sort | uniq | head -10", 5, 0, 0,
             0, 0),
      STAGES("Pipeline: git", "git log --oneline | head -10 | grep fix", 3, 0,
             0, 0, 0),
      STAGES("Pipeline: find", "find . -name '*.c' | xargs grep main | head -5",
             3, 0, 0, 0, 0),
      STAGES("Pipeline: single command", "echo hello world", 1, 0, 0, 0, 0),
      STAGES("Pipeline: only redirects", "< in.txt > out.txt", 1, 0, 0, 0, 0),
      STAGES("Pipeline: all features combined",
             "cat ${FILE}*.txt | grep -E '$PATTERN' | sort -u > ${OUTPUT}.txt "
             "&& echo done",
             4, UINT64_C(0x5), UINT64_C(0x1), 0, 0),
  };
#undef STAGES
  tokenizer_run_stage_cases(pipeline_cases,
                            sizeof(pipeline_cases) / sizeof(pipeline_cases[0]));

  printf("\n=== STRESS/CRASH TEST CASES - PART 2 ===\n\n");

  // Test 174: Maximum depth subshell
  {
    char input[512];
    strcpy(input, "echo ");
    for (int i = 0; i < 20; i++) {
      strcat(input, "$(echo ");
    }
    strcat(input, "x");
    for (int i = 0; i < 20; i++) {
      strcat(input, ")");
    }
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = (shell_tokenize_commands(input, strlen(input), &cmds,
                                          &count) == SHELL_TOKENIZE_OK);
    test("Stress: max depth nesting (20 levels)",
         result && count == 1 && cmds[0].has_subshells &&
             tokenizer_tokens_are_consistent(input, cmds, count));
    shell_commands_free(cmds, count);
  }

  static const tokenizer_feature_case_t compound_syntax_cases[] = {
      {{"Stress: nested command substitution (8 levels)",
        "echo $(echo $(echo $(echo $(echo $(echo $(echo $(echo hello)))))))",
        1},
       tokenizer_EXPECT_SUBSHELL},
      {{"Edge: process substitution", "diff <(cmd1) <(cmd2)", 1}, 0},
      {{"Edge: heredoc-shaped input", "cat <<EOF\nline1\nline2\nEOF", 1}, 0},
      {{"Edge: heredoc-shaped input with variable", "cat <<EOF\n$VAR\nEOF", 1},
       0},
      {{"Edge: double brackets", "[[ $var == \"test\" ]]", 1},
       tokenizer_EXPECT_VARIABLE | tokenizer_EXPECT_CONDITIONAL},
      {{"Edge: for loop", "for f in *.txt; do echo $f; done", 3},
       tokenizer_EXPECT_VARIABLE | tokenizer_EXPECT_GLOB |
           tokenizer_EXPECT_LOOP},
      {{"Edge: while loop", "while read line; do echo $line; done < file.txt",
        3},
       tokenizer_EXPECT_VARIABLE | tokenizer_EXPECT_LOOP},
      {{"Edge: case statement", "case $var in a) echo a;; esac", 1},
       tokenizer_EXPECT_VARIABLE | tokenizer_EXPECT_CASE},
      {{"Edge: conditional", "if [ -f file.txt ]; then echo exists; fi", 2},
       tokenizer_EXPECT_IF},
  };
  tokenizer_run_feature_cases(compound_syntax_cases,
                              sizeof(compound_syntax_cases) /
                                  sizeof(compound_syntax_cases[0]));

  static const tokenizer_feature_case_t parameter_expansion_cases[] = {
      {{"Edge: array variable", "echo ${array[@]}", 1},
       tokenizer_EXPECT_VARIABLE},
      {{"Edge: default parameter expansion", "echo ${VAR:-default}", 1},
       tokenizer_EXPECT_VARIABLE},
      {{"Edge: assignment parameter expansion", "echo ${VAR:=default}", 1},
       tokenizer_EXPECT_VARIABLE},
      {{"Edge: parameter length", "echo ${#VAR}", 1},
       tokenizer_EXPECT_VARIABLE},
      {{"Edge: substring expansion", "echo ${VAR:0:5}", 1},
       tokenizer_EXPECT_VARIABLE},
      {{"Edge: pattern removal", "echo ${VAR##*/}", 1},
       tokenizer_EXPECT_VARIABLE},
      {{"Edge: pattern substitution", "echo ${VAR/pattern/replace}", 1},
       tokenizer_EXPECT_VARIABLE},
  };
  tokenizer_run_feature_cases(parameter_expansion_cases,
                              sizeof(parameter_expansion_cases) /
                                  sizeof(parameter_expansion_cases[0]));

  static const tokenizer_tokenizer_case_t syntax_edge_cases[] = {
      {"Edge: numbered file descriptors", "cmd 0<in 1>out 2>err 3>&1", 1},
      {"Edge: nested quote forms", "echo \"hello 'world' \\\"inner\\\"\"", 1},
      {"Edge: escape sequences", "echo \\n\\t\\r\\\\", 1},
      {"Edge: separators without spaces", "cmd1;cmd2;cmd3", 3},
      {"Edge: shebang-shaped input", "#!/bin/bash\necho hello", 1},
      {"Edge: comment-shaped text after pipe", "cmd1 | # comment\ncmd2", 2},
      {"Edge: trailing background operator", "cmd1 | cmd2 &", 2},
      {"Edge: pipe-and operator", "cmd1 |& cmd2", 2},
      {"Edge: parenthesized pipeline stages", "(cmd1) | (cmd2)", 2},
      {"Edge: brace expansion", "echo {a,b,c}.txt", 1},
      {"Edge: function definition", "function foo { echo hello; }", 2},
  };
  tokenizer_run_tokenizer_cases(syntax_edge_cases,
                                sizeof(syntax_edge_cases) /
                                    sizeof(syntax_edge_cases[0]));

  static const tokenizer_feature_case_t syntax_feature_cases[] = {
      {{"Edge: backticks containing pipe", "echo `cat file.txt | grep pattern`",
        1},
       tokenizer_EXPECT_SUBSHELL},
      {{"Edge: backticks containing list separator",
        "echo `printf x; printf y`", 1},
       tokenizer_EXPECT_SUBSHELL},
      {{"Edge: escaped backtick inside substitution",
        "echo `printf \\`literal\\` | cat`", 1},
       tokenizer_EXPECT_SUBSHELL},
      {{"Edge: variable followed by path suffix", "echo $PATH:/new/path", 1},
       tokenizer_EXPECT_VARIABLE},
      {{"Edge: variable embedded in double quotes", "echo \"Cost: $$100\"", 1},
       tokenizer_EXPECT_VARIABLE},
      {{"Edge: braced variable embedded in double quotes",
        "echo \"prefix ${VAR} suffix\"", 1},
       tokenizer_EXPECT_VARIABLE},
      {{"Edge: escaped dollar in double quotes", "echo \"Cost: \\$100\"", 1},
       0},
      {{"Edge: dollar in single quotes", "echo 'Cost: $100'", 1}, 0},
      {{"Edge: complex command substitution",
        "echo $(cat $FILE *.txt | grep $PATTERN | sort $((N+1)) )", 1},
       tokenizer_EXPECT_SUBSHELL},
      {{"Edge: local assignment sequence", "local x=5; echo $x", 2},
       tokenizer_EXPECT_VARIABLE},
      {{"Quoted command substitution", "echo \"$(id)\"", 1},
       tokenizer_EXPECT_SUBSHELL},
      {{"Quoted command substitution with affixes",
        "echo \"prefix$(id)suffix\"", 1},
       tokenizer_EXPECT_SUBSHELL},
      {{"Quoted backtick substitution", "echo \"prefix`id`suffix\"", 1},
       tokenizer_EXPECT_SUBSHELL},
      {{"Quoted arithmetic expansion", "echo \"$((1 + 2))\"", 1},
       tokenizer_EXPECT_ARITHMETIC},
      {{"Single-quoted substitution is literal", "echo '$(id)'", 1}, 0},
      {{"Variable inside glob word", "echo prefix${HOME}/*.txt", 1},
       tokenizer_EXPECT_VARIABLE | tokenizer_EXPECT_GLOB},
      {{"Quoted variable inside glob word", "echo \"${HOME}\"/file*.txt", 1},
       tokenizer_EXPECT_VARIABLE | tokenizer_EXPECT_GLOB},
      {{"Variable inside extglob word", "echo @($HOME|x)", 1},
       tokenizer_EXPECT_VARIABLE | tokenizer_EXPECT_GLOB},
      {{"Substitution inside glob word", "echo $(id)*.txt", 1},
       tokenizer_EXPECT_SUBSHELL | tokenizer_EXPECT_GLOB},
      {{"Heredoc delimiter is not expanded", "cat <<$ENDMARK\nx\n$ENDMARK\n",
        1},
       0},
  };
  tokenizer_run_feature_cases(syntax_feature_cases,
                              sizeof(syntax_feature_cases) /
                                  sizeof(syntax_feature_cases[0]));

  // Test 190: Very long command with many tokens
  {
    char input[8192];
    strcpy(input, "cmd1");
    for (int i = 0; i < 200; i++) {
      strcat(input, " arg");
    }
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = (shell_tokenize_commands(input, strlen(input), &cmds,
                                          &count) == SHELL_TOKENIZE_OK);
    test("Stress: long command (200 args)",
         result && count == 1 && cmds[0].token_count == 201 &&
             tokenizer_tokens_are_consistent(input, cmds, count));
    shell_commands_free(cmds, count);
  }

  // Test 191: Very long pipeline with many args
  {
    char input[16384];
    input[0] = '\0';
    for (int i = 0; i < 50; i++) {
      if (i > 0)
        strcat(input, " | ");
      sprintf(input + strlen(input), "cmd%d arg1 arg2 arg3", i + 1);
    }
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = (shell_tokenize_commands(input, strlen(input), &cmds,
                                          &count) == SHELL_TOKENIZE_OK);
    bool token_counts_match = result && count == 50;
    for (size_t i = 0; token_counts_match && i < count; i++)
      token_counts_match = cmds[i].token_count == (i + 1 < count ? 5 : 4);
    test("Stress: long pipeline (50 stages)",
         token_counts_match &&
             tokenizer_tokens_are_consistent(input, cmds, count));
    shell_commands_free(cmds, count);
  }

  // Test 206: Very long variable name
  {
    char input[2007] = "echo $";
    memset(input + 6, 'V', 2000);
    input[2006] = '\0';
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = (shell_tokenize_commands(input, strlen(input), &cmds,
                                          &count) == SHELL_TOKENIZE_OK);
    test("Stress: very long variable name (2000 characters)",
         result && count == 1 && cmds[0].has_variables &&
             tokenizer_tokens_are_consistent(input, cmds, count));
    shell_commands_free(cmds, count);
  }

  /* --- PARSER REGRESSION TESTS --- */

  printf("\n=== PARSER REGRESSION TESTS ===\n\n");

  static const tokenizer_tokenizer_case_t invalid_input_cases[] = {
      {"Control character at start is rejected",
       "\x01"
       "cmd",
       0},
      {"Multiple leading control characters are rejected", "\x07\x1btext", 0},
      {"ANSI-C quotes do not admit high bytes in arithmetic",
       "echo $(( $'\x80\xff' ))", 0},
      {"Embedded control character is rejected", "cmd\x01suffix", 0},
      {"High bytes in arithmetic are rejected", "echo $((\x80))", 0},
      {"Bare separator is rejected", "|", 0},
  };
  tokenizer_run_rejected_cases(invalid_input_cases,
                               sizeof(invalid_input_cases) /
                                   sizeof(invalid_input_cases[0]));

  // Test 217: Quotes spanning tokens - actually VALID shell syntax!
  // "text "text" is parsed as "text" (quoted) followed by text (unquoted) - NOT
  // a bug
  {
    const char *input = "\"text \"text";
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = (shell_tokenize_commands(input, strlen(input), &cmds,
                                          &count) == SHELL_TOKENIZE_OK);
    // This is CORRECT behavior - shell parses it as two words
    test("Adjacent quoted and unquoted text is one command",
         result && count == 1 &&
             tokenizer_tokens_are_consistent(input, cmds, count));
    if (cmds)
      shell_commands_free(cmds, count);
  }

  // Test 218: Double keyword 'if if' - actually VALID shell syntax!
  // Bash accepts "if if cmd" - runs "if" as command, uses exit status as
  // condition
  {
    const char *input = "if if cmd";
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = (shell_tokenize_commands(input, strlen(input), &cmds,
                                          &count) == SHELL_TOKENIZE_OK);
    test("Tokenizer accepts keyword-shaped command fragments",
         result && count == 1 &&
             tokenizer_tokens_are_consistent(input, cmds, count));
    if (cmds)
      shell_commands_free(cmds, count);
  }

  // Test 219: Double `do` keyword - complex case requires full grammar
  // parsing. For the fast tokenizer, we only detect at command start, nested
  // is flagged
  {
    const char *input = "while true; do do cmd; done";
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = (shell_tokenize_commands(input, strlen(input), &cmds,
                                          &count) == SHELL_TOKENIZE_OK);
    // This is a complex case - fast tokenizer may not catch nested "do do"
    test("Non-strict tokenizer accepts unsupported compound grammar",
         result == 1);
    if (cmds)
      shell_commands_free(cmds, count);
  }

  // Regression: an unmatched glob bracket must not create a token beyond the
  // terminating NUL.
  {
    const char *input = "pw[d";
    shell_tokenizer_state_t state;
    shell_token_t token;
    bool in_bounds = true;
    size_t input_len = strlen(input);

    shell_tokenizer_init(&state, input, strlen(input), NULL);
    while (shell_tokenizer_next(&state, &token)) {
      if (token.position > input_len ||
          token.length > input_len - token.position ||
          token.start != input + token.position) {
        in_bounds = false;
        break;
      }
    }
    test("Unmatched glob bracket keeps tokens within input", in_bounds);
  }

  {
    shell_command_info_t *infos = NULL;
    size_t count = 0;
    shell_netstring_buffer_t netargv = {0};
    shell_process_status_t status = shell_process_command(
        "printf '' foo\"bar\" 'two words' '>'",
        strlen("printf '' foo\"bar\" 'two words' '>'"), NULL, &infos, &count);
    if (status == SHELL_PROCESS_OK && count == 1)
      status = shell_render_netargv_buffer(&infos[0], NULL, &netargv);
    bool valid = status == SHELL_PROCESS_OK && count == 1 && netargv.data &&
                 (netargv.length !=
                      sizeof("6:printf,0:,6:foobar,9:two words,1:>,") - 1 ||
                  memcmp(netargv.data, "6:printf,0:,6:foobar,9:two words,1:>,",
                         netargv.length)) == 0;
    test("Netargv rendering preserves exact argument boundaries", valid);
    shell_netstring_buffer_free(&netargv);
    shell_command_infos_free(infos, count);
  }

  {
    static const struct {
      const char *command;
      const char *netargv;
      const char *sequence;
      bool has_executable_substitution;
    } cases[] = {
        {"echo foo$(cat)bar", "4:echo,12:foo$(cat)bar,",
         "23:4:echo,12:foo$(cat)bar,,", true},
        {"echo <(cat)foo", "4:echo,9:<(cat)foo,", "19:4:echo,9:<(cat)foo,,",
         true},
        {"echo \"<(cat)foo\"", "4:echo,9:<(cat)foo,", "19:4:echo,9:<(cat)foo,,",
         false},
        {"echo \"$(cat)\"foo", "4:echo,9:$(cat)foo,", "19:4:echo,9:$(cat)foo,,",
         true},
        {"echo foo`cat`bar", "4:echo,11:foo`cat`bar,",
         "22:4:echo,11:foo`cat`bar,,", true},
        {"echo pre${value}post", "4:echo,15:pre${value}post,",
         "26:4:echo,15:pre${value}post,,", false},
    };
    bool valid = true;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      shell_command_info_t *infos = NULL;
      size_t info_count = 0;
      shell_netstring_buffer_t netargv = {0};
      shell_netstring_buffer_t sequence = {0};
      size_t sequence_count = 0;
      bool features = false;
      shell_process_status_t status =
          shell_process_command(cases[i].command, strlen(cases[i].command),
                                NULL, &infos, &info_count);
      if (status == SHELL_PROCESS_OK && info_count == 1)
        status = shell_render_netargv_buffer(&infos[0], NULL, &netargv);
      shell_process_status_t sequence_status =
          shell_build_netargv_sequence_buffer(
              cases[i].command, strlen(cases[i].command), NULL, &sequence,
              &sequence_count, &features);
      valid =
          valid && status == SHELL_PROCESS_OK && info_count == 1 &&
          netargv.data &&
          (netargv.length != strlen(cases[i].netargv) ||
           memcmp(netargv.data, cases[i].netargv, netargv.length)) == 0 &&
          sequence_status == SHELL_PROCESS_OK && sequence_count == 1 &&
          sequence.data &&
          (sequence.length != strlen(cases[i].sequence) ||
           memcmp(sequence.data, cases[i].sequence, sequence.length)) == 0 &&
          features == cases[i].has_executable_substitution;
      shell_netstring_buffer_free(&sequence);
      shell_netstring_buffer_free(&netargv);
      shell_command_infos_free(infos, info_count);
    }
    test("Canonical netargv preserves complete dynamic source words", valid);
  }

  {
    static const char word[] = "<(printf \\))";
    char output[sizeof(word)] = {0};
    size_t measured = 0;
    size_t written = 0;
    bool valid =
        shell_measure_processed_word(word, strlen(word), &measured) ==
            SHELL_PROCESS_OK &&
        measured == strlen(word) &&
        shell_write_processed_word(word, strlen(word), output, measured,
                                   &written) == SHELL_PROCESS_OK &&
        written == measured && memcmp(output, word, measured) == 0;
    test("Processed-word writer preserves escaped substitution syntax", valid);
  }

  {
    static const struct {
      const char *source;
      const char *rendered;
    } cases[] = {
        {"plain", "plain"},
        {"'two words'", "two words"},
        {"a\\ b", "a b"},
        {"a\\\nb", "ab"},
        {"\"a\\\"b\"", "a\"b"},
        {"$(printf x)", "$(printf x)"},
        {"<(printf x)", "<(printf x)"},
        {"`printf x`", "`printf x`"},
        {"$'a\\x42'", "aB"},
    };
    bool valid = true;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      size_t measured = 0;
      size_t written = SIZE_MAX;
      char output[64] = {0};
      size_t expected = strlen(cases[i].rendered);
      shell_process_status_t measured_status = shell_measure_processed_word(
          cases[i].source, strlen(cases[i].source), &measured);
      shell_process_status_t write_status = shell_write_processed_word(
          cases[i].source, strlen(cases[i].source), output, expected, &written);
      valid = valid && measured_status == SHELL_PROCESS_OK &&
              measured == expected && write_status == SHELL_PROCESS_OK &&
              written == expected &&
              memcmp(output, cases[i].rendered, expected) == 0;
      written = SIZE_MAX;
      valid = valid &&
              shell_write_processed_word(
                  cases[i].source, strlen(cases[i].source), output,
                  expected - 1, &written) == SHELL_PROCESS_EOUTPUT_LIMIT &&
              written == 0;
    }
    test("Processed-word writer measures and bounds every word form", valid);
  }

  {
    shell_netstring_buffer_t sequence = {0};
    size_t count = 0;
    bool features = false;
    shell_process_status_t status = shell_build_netargv_sequence_buffer(
        "printf '' 'two words'; cd '/tmp path'",
        strlen("printf '' 'two words'; cd '/tmp path'"), NULL, &sequence,
        &count, &features);
    bool valid =
        status == SHELL_PROCESS_OK && count == 2 && features && sequence.data &&
        (sequence.length !=
             sizeof("24:6:printf,0:,9:two words,,17:2:cd,9:/tmp path,,") - 1 ||
         memcmp(sequence.data,
                "24:6:printf,0:,9:two words,,17:2:cd,9:/tmp path,,",
                sequence.length)) == 0;
    test("Nested netargv sequence preserves subcommand boundaries", valid);
    shell_netstring_buffer_free(&sequence);

    shell_netstring_buffer_t command_netseq = {0};
    shell_netstring_buffer_t type_netseq = {0};
    shell_netstring_buffer_t expected_command_netseq = {0};
    shell_netstring_buffer_t expected_type_netseq = {0};
    size_t paired_count = 0;
    valid =
        shell_build_anomaly_netseqs_buffer(
            "printf '' 'two words'; cd '/tmp path'",
            strlen("printf '' 'two words'; cd '/tmp path'"), NULL,
            &command_netseq, &type_netseq, &paired_count) == SHELL_PROCESS_OK &&
        shell_build_command_netseq_buffer(
            "printf '' 'two words'; cd '/tmp path'",
            strlen("printf '' 'two words'; cd '/tmp path'"), NULL,
            &expected_command_netseq, &count) == SHELL_PROCESS_OK &&
        shell_build_type_netseq_buffer(
            "printf '' 'two words'; cd '/tmp path'",
            strlen("printf '' 'two words'; cd '/tmp path'"), NULL,
            &expected_type_netseq, &count) == SHELL_PROCESS_OK &&
        paired_count == 2 && command_netseq.data && type_netseq.data &&
        (command_netseq.length != expected_command_netseq.length ||
         memcmp(command_netseq.data, expected_command_netseq.data,
                command_netseq.length)) == 0 &&
        (type_netseq.length != expected_type_netseq.length ||
         memcmp(type_netseq.data, expected_type_netseq.data,
                type_netseq.length)) == 0;
    test("Paired anomaly netsequences share canonical command boundaries",
         valid);
    shell_netstring_buffer_free(&expected_type_netseq);
    shell_netstring_buffer_free(&expected_command_netseq);
    shell_netstring_buffer_free(&type_netseq);
    shell_netstring_buffer_free(&command_netseq);

    command_netseq = (shell_netstring_buffer_t){0};
    type_netseq = (shell_netstring_buffer_t){0};
    paired_count = SIZE_MAX;
    valid = shell_build_anomaly_netseqs_buffer("", 0, NULL, &command_netseq,
                                               &type_netseq, &paired_count) ==
                SHELL_PROCESS_EINPUT &&
            command_netseq.data == NULL && type_netseq.data == NULL &&
            paired_count == 0;
    shell_process_limits_t pair_limits = {SIZE_MAX, 8, 0};
    valid = valid &&
            shell_build_anomaly_netseqs_buffer(
                "echo x", strlen("echo x"), &pair_limits, &command_netseq,
                &type_netseq, &paired_count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
            command_netseq.data == NULL && type_netseq.data == NULL &&
            paired_count == 0;
    test("Paired anomaly netsequences clear every output on failure", valid);

    static const char *const paired_inputs[] = {
        "'my tool' 'two words' 2>&1; printf '' | sed 's/x/y/'",
        "printf \\\"quoted\\\"; echo one\\ two >output",
        "echo x && cd '/tmp path'; :",
    };
    valid = true;
    for (size_t i = 0; i < sizeof(paired_inputs) / sizeof(paired_inputs[0]);
         i++) {
      const char *input = paired_inputs[i];
      command_netseq = (shell_netstring_buffer_t){0};
      type_netseq = (shell_netstring_buffer_t){0};
      expected_command_netseq = (shell_netstring_buffer_t){0};
      expected_type_netseq = (shell_netstring_buffer_t){0};
      paired_count = 0;
      size_t command_count = 0;
      size_t type_count = 0;
      valid = valid &&
              shell_build_anomaly_netseqs_buffer(
                  input, strlen(input), NULL, &command_netseq, &type_netseq,
                  &paired_count) == SHELL_PROCESS_OK &&
              shell_build_command_netseq_buffer(
                  input, strlen(input), NULL, &expected_command_netseq,
                  &command_count) == SHELL_PROCESS_OK &&
              shell_build_type_netseq_buffer(input, strlen(input), NULL,
                                             &expected_type_netseq,
                                             &type_count) == SHELL_PROCESS_OK &&
              paired_count == command_count && paired_count == type_count &&
              (command_netseq.length != expected_command_netseq.length ||
               memcmp(command_netseq.data, expected_command_netseq.data,
                      command_netseq.length)) == 0 &&
              (type_netseq.length != expected_type_netseq.length ||
               memcmp(type_netseq.data, expected_type_netseq.data,
                      type_netseq.length)) == 0;
      shell_netstring_buffer_free(&expected_type_netseq);
      shell_netstring_buffer_free(&expected_command_netseq);
      shell_netstring_buffer_free(&type_netseq);
      shell_netstring_buffer_free(&command_netseq);
    }
    test("Paired anomaly netsequences match independent builders", valid);

    static const struct {
      const char *input;
      const char *raw;
      const char *typed;
      size_t stage_count;
    } compound_signatures[] = {
        {"$'c'3>out", "2:c3,", "5:2:c3,,", 1},
        {"${x}3>out", "5:${x}3,", "8:5:${x}3,,", 1},
        {"$(printf c)3>out", "6:printf,12:$(printf c)3,",
         "15:6:printf,3:STR,,16:12:$(printf c)3,,", 2},
        {"cat $'x'3>out", "3:cat,", "12:3:cat,3:STR,,", 1},
        {"cat \"x\"${y}z>out", "3:cat,", "12:3:cat,3:STR,,", 1},
        {"cat ${x}3>out", "3:cat,", "11:3:cat,2:EV,,", 1},
        {"cat @(one|two)suffix>out", "3:cat,", "11:3:cat,2:GB,,", 1},
        {"my\\\ncommand value", "9:mycommand,", "18:9:mycommand,3:STR,,", 1},
        {"my\\\ncommand value", "9:mycommand,", "18:9:mycommand,3:STR,,", 1},
    };
    valid = true;
    for (size_t i = 0;
         i < sizeof(compound_signatures) / sizeof(compound_signatures[0]);
         i++) {
      command_netseq = (shell_netstring_buffer_t){0};
      type_netseq = (shell_netstring_buffer_t){0};
      paired_count = 0;
      const char *input = compound_signatures[i].input;
      valid = valid &&
              shell_build_anomaly_netseqs_buffer(
                  input, strlen(input), NULL, &command_netseq, &type_netseq,
                  &paired_count) == SHELL_PROCESS_OK &&
              paired_count == compound_signatures[i].stage_count &&
              command_netseq.data && type_netseq.data &&
              (command_netseq.length != strlen(compound_signatures[i].raw) ||
               memcmp(command_netseq.data, compound_signatures[i].raw,
                      command_netseq.length)) == 0 &&
              (type_netseq.length != strlen(compound_signatures[i].typed) ||
               memcmp(type_netseq.data, compound_signatures[i].typed,
                      type_netseq.length)) == 0;
      shell_netstring_buffer_free(&type_netseq);
      shell_netstring_buffer_free(&command_netseq);
    }
    test("Compound argv words retain aligned anomaly signatures", valid);

    command_netseq = (shell_netstring_buffer_t){0};
    type_netseq = (shell_netstring_buffer_t){0};
    paired_count = SIZE_MAX;
    valid = shell_build_anomaly_netseqs_buffer(
                "'' x", strlen("'' x"), NULL, &command_netseq, &type_netseq,
                &paired_count) == SHELL_PROCESS_EPARSE &&
            command_netseq.data == NULL && type_netseq.data == NULL &&
            paired_count == 0;
    command_netseq = (shell_netstring_buffer_t){0};
    type_netseq = (shell_netstring_buffer_t){0};
    paired_count = SIZE_MAX;
    valid = valid &&
            shell_build_anomaly_netseqs_buffer("\x01"
                                               "bad",
                                               strlen("\x01"
                                                      "bad"),
                                               NULL, &command_netseq,
                                               &type_netseq, &paired_count) ==
                SHELL_PROCESS_EINPUT &&
            command_netseq.data == NULL && type_netseq.data == NULL &&
            paired_count == 0;
    test("Paired anomaly netsequences reject empty executables atomically",
         valid);

    valid = true;
    bool pair_completed = false;
    static const char *const allocation_inputs[] = {
        "echo x; printf y",
        "{ cat; } >out; >a; >b",
        "cat 0<<EOF\nwhile true; do :; done\nEOF\n",
        "{ cat; } 1\\\n2<<EOF\nbody\nEOF\n>out",
        "cat $'x'\\\n3>out",
        /* Timing must not bypass expansion/quote handling or failure cleanup
         * in legacy combined-output redirects and nested execution stages. */
        "time printf x >&$VAR$'suffix'",
        "time printf x >&\"$VAR\"literal$(printf suffix)",
        "time printf x >&${VAR}/report",
        "time printf x >&~user/file",
        "time { printf '%s' \"$(time printf value)\" |& cat; } 2>report",
        "time {fd}<<<payload cat <&$fd; time --",
        "outer $(middle $(inner)) $(sibling <(producer))",
        "outer `middle $(inner)`; cat <<EOF\n${value:-$(body)}\nEOF\n",
        "echo \"$OUTER$(printf '\"$INNER')$AFTER\"",
        "echo \"$OUTER`printf '$INNER'`$AFTER\"",
        "echo \"$(printf '$INNER')\"; echo \"$(printf \"$INNER\")\"",
        /* These final fixtures exercise a shared finite group-I/O budget and
         * every allocation while charging sibling and nested bodies. */
        "outer $( { inner; } >one ) $( { inner; } >two )",
        "cat <<EOF\n$( { middle $( { inner; } >two ); } >one )\nEOF\n",
    };
    const shell_process_limits_t group_budget = {SIZE_MAX, SIZE_MAX, 2};
    for (size_t input_index = 0;
         valid &&
         input_index < sizeof(allocation_inputs) / sizeof(allocation_inputs[0]);
         input_index++) {
      pair_completed = false;
      for (size_t fail_at = 1; fail_at < 128; fail_at++) {
        shellsplit_test_alloc_reset();
        shellsplit_test_alloc_fail_at(fail_at);
        command_netseq = (shell_netstring_buffer_t){0};
        type_netseq = (shell_netstring_buffer_t){0};
        paired_count = SIZE_MAX;
        status = shell_build_anomaly_netseqs_buffer(
            allocation_inputs[input_index],
            strlen(allocation_inputs[input_index]),
            input_index >=
                    sizeof(allocation_inputs) / sizeof(allocation_inputs[0]) - 2
                ? &group_budget
                : NULL,
            &command_netseq, &type_netseq, &paired_count);
        if (status == SHELL_PROCESS_OK) {
          pair_completed = true;
          shell_netstring_buffer_free(&type_netseq);
          shell_netstring_buffer_free(&command_netseq);
          break;
        }
        valid = valid && status == SHELL_PROCESS_ENOMEM &&
                command_netseq.data == NULL && type_netseq.data == NULL &&
                paired_count == 0;
        if (!valid) {
          fprintf(stderr,
                  "paired allocation failure: source=%s fail_at=%zu "
                  "status=%d count=%zu\n",
                  allocation_inputs[input_index], fail_at, status,
                  paired_count);
          break;
        }
      }
      if (valid && !pair_completed)
        fprintf(stderr, "paired allocation budget exhausted: %s\n",
                allocation_inputs[input_index]);
      valid = valid && pair_completed;
    }
    shellsplit_test_alloc_reset();
    test("Paired anomaly netsequences are allocation-failure atomic",
         valid && pair_completed);

    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    status = shell_process_command(
        "cmd 2>>errors <>input &>output >|forced\n",
        strlen("cmd 2>>errors <>input &>output >|forced\n"), NULL, &infos,
        &info_count);
    valid = status == SHELL_PROCESS_OK && infos && info_count == 1;
    shell_command_infos_free(infos, info_count);
    test("Processor owns compound-redirection token boundaries", valid);

    sequence = (shell_netstring_buffer_t){0};
    count = 99;
    features = true;
    valid = shell_build_netargv_sequence_buffer("", 0, NULL, &sequence, &count,
                                                &features) ==
                SHELL_PROCESS_EINPUT &&
            sequence.data == NULL && count == 0 && !features;
    test("Nested netargv sequence rejects invalid input atomically", valid);

    sequence = (shell_netstring_buffer_t){0};
    count = SIZE_MAX;
    features = true;
    valid = shell_build_netargv_sequence_buffer(
                "\x01"
                "bad",
                strlen("\x01"
                       "bad"),
                NULL, &sequence, &count, &features) == SHELL_PROCESS_EINPUT &&
            sequence.data == NULL && count == 0 && !features;
    test("Nested netargv sequence propagates parser failures atomically",
         valid);

    shell_process_limits_t limits = {SIZE_MAX, SIZE_MAX, 0};
    limits.max_string_bytes = 1;
    features = true;
    valid = shell_build_netargv_sequence_buffer(
                "echo x", strlen("echo x"), &limits, &sequence, &count,
                &features) == SHELL_PROCESS_EOUTPUT_LIMIT &&
            sequence.data == NULL && count == 0 && !features;
    test("Nested netargv sequence enforces its outer output limit", valid);

    limits = (shell_process_limits_t){SIZE_MAX, 10, 0};
    valid = shell_build_netargv_sequence_buffer(
                "echo x", strlen("echo x"), &limits, &sequence, &count,
                &features) == SHELL_PROCESS_EOUTPUT_LIMIT &&
            sequence.data == NULL && count == 0 && !features;
    test("Nested netargv sequence checks its post-processing size", valid);

    valid = true;
    bool completed = false;
    for (size_t fail_at = 1; fail_at < 32; fail_at++) {
      shellsplit_test_alloc_reset();
      shellsplit_test_alloc_fail_at(fail_at);
      sequence = (shell_netstring_buffer_t){0};
      count = SIZE_MAX;
      features = true;
      status = shell_build_netargv_sequence_buffer(
          "echo x", strlen("echo x"), NULL, &sequence, &count, &features);
      if (status == SHELL_PROCESS_OK) {
        completed = true;
        shell_netstring_buffer_free(&sequence);
        break;
      }
      valid = valid && status == SHELL_PROCESS_ENOMEM &&
              sequence.data == NULL && count == 0 && !features;
    }
    shellsplit_test_alloc_reset();
    test("Nested netargv sequence is failure-atomic at every allocation",
         valid && completed);

    sequence = (shell_netstring_buffer_t){0};
    count = 0;
    valid =
        shell_build_command_netseq_buffer("'my tool' one two; printf x",
                                          strlen("'my tool' one two; printf x"),
                                          NULL, &sequence,
                                          &count) == SHELL_PROCESS_OK &&
        count == 2 && sequence.data &&
        (sequence.length != sizeof("7:my tool,6:printf,") - 1 ||
         memcmp(sequence.data, "7:my tool,6:printf,", sequence.length)) == 0;
    test("Command netsequence records executables rather than arguments",
         valid);
    shell_netstring_buffer_free(&sequence);

    valid = true;
    limits = (shell_process_limits_t){SIZE_MAX, SIZE_MAX, 0};
    limits.max_total_bytes = 1;
    valid = valid &&
            shell_build_command_netseq_buffer("echo x", strlen("echo x"),
                                              &limits, &sequence, &count) ==
                SHELL_PROCESS_EOUTPUT_LIMIT &&
            sequence.data == NULL && count == 0;
    test("Command netsequence validates outputs and limits", valid);

    limits = (shell_process_limits_t){SIZE_MAX, 6, 0};
    valid = shell_build_command_netseq_buffer("echo x", strlen("echo x"),
                                              &limits, &sequence, &count) ==
                SHELL_PROCESS_EOUTPUT_LIMIT &&
            sequence.data == NULL && count == 0;
    test("Command netsequence checks its encoded size", valid);

    sequence = (shell_netstring_buffer_t){0};
    count = SIZE_MAX;
    valid = shell_build_command_netseq_buffer("\x01"
                                              "bad",
                                              strlen("\x01"
                                                     "bad"),
                                              NULL, &sequence,
                                              &count) == SHELL_PROCESS_EINPUT &&
            sequence.data == NULL && count == 0;
    test("Command netsequence propagates parser failures atomically", valid);

    valid = true;
    completed = false;
    for (size_t fail_at = 1; fail_at < 32; fail_at++) {
      shellsplit_test_alloc_reset();
      shellsplit_test_alloc_fail_at(fail_at);
      sequence = (shell_netstring_buffer_t){0};
      count = SIZE_MAX;
      status = shell_build_command_netseq_buffer("echo x", strlen("echo x"),
                                                 NULL, &sequence, &count);
      if (status == SHELL_PROCESS_OK) {
        completed = true;
        shell_netstring_buffer_free(&sequence);
        break;
      }
      valid = valid && status == SHELL_PROCESS_ENOMEM &&
              sequence.data == NULL && count == 0;
    }
    shellsplit_test_alloc_reset();
    test("Command netsequence is failure-atomic at every allocation",
         valid && completed);
  }

  test("Grouped redirection processing is allocation-failure atomic",
       tokenizer_process_commands_allocation_failure_atomic(
           "{ printf x; } {out}>out {input}<in {both}<>read-write 2>&1"));

  test("Flat command processing is allocation-failure atomic",
       tokenizer_process_command_allocation_failure_atomic(
           ">/tmp/leading; { printf 'two words'; >/tmp/inner; } "
           ">/tmp/group-out; >/tmp/independent"));

  test("Command netsequence follows executable heredoc expansions",
       tokenizer_command_netseq_matches("cat <<EOF\n$(printf child)\nEOF\n",
                                        "6:printf,3:cat,", 2) &&
           tokenizer_command_netseq_matches("cat <<EOF\n`printf child`\nEOF\n",
                                            "6:printf,3:cat,", 2) &&
           tokenizer_command_netseq_matches(
               "cat <<EOF\n${value:-$(printf child)}\nEOF\n", "6:printf,3:cat,",
               2) &&
           tokenizer_command_netseq_matches(
               "cat <<'EOF'\n$(printf child)\nEOF\n", "3:cat,", 1) &&
           tokenizer_command_netseq_matches("cat <(printf child)",
                                            "6:printf,3:cat,", 2));

  /* Direct canonical builders retain binary payloads, while complete source
   * uses Bash's fragment-local truncation. */
  {
    static const char source[] = "printf $'a\\0b'";
    shell_token_t tokens[] = {
        {.type = SHELL_TOKEN_COMMAND, .start = "printf", .length = 6},
        {.type = SHELL_TOKEN_ARGUMENT, .start = "a\0b", .length = 3},
    };
    shell_command_info_t binary_info = {
        .command_tokens = tokens,
        .command_token_count = 2,
    };
    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    shell_netstring_buffer_t argv = {0};
    shell_netstring_buffer_t sequence = {0};
    size_t record_count = 0;
    size_t sequence_count = 0;
    bool features = true;
    shell_process_status_t status = shell_process_command(
        source, sizeof(source) - 1, NULL, &infos, &info_count);
    bool buffer_valid =
        status == SHELL_PROCESS_OK && infos != NULL && info_count == 1 &&
        shell_render_netargv_buffer(&binary_info, NULL, &argv) ==
            SHELL_PROCESS_OK &&
        shell_netstring_validate(argv.data, argv.length, &record_count) ==
            SHELL_NETSTRING_OK &&
        record_count == 2 && memchr(argv.data, '\0', argv.length) != NULL &&
        shell_build_netargv_sequence_buffer(source, sizeof(source) - 1, NULL,
                                            &sequence, &sequence_count,
                                            &features) == SHELL_PROCESS_OK &&
        sequence_count == 1 && !features &&
        sequence.length == strlen("13:6:printf,1:a,,") &&
        !memcmp(sequence.data, "13:6:printf,1:a,,", sequence.length);
    shell_netstring_buffer_free(&sequence);
    shell_netstring_buffer_free(&argv);
    shell_command_infos_free(infos, info_count);
    test("Canonical netargv buffers preserve embedded NUL payloads",
         buffer_valid);
  }

  printf("\n=== SUMMARY ===\n");
  printf("Results: %d/%d passed\n", tokenizer_pass_count, tokenizer_test_count);
  return (tokenizer_pass_count == tokenizer_test_count) ? 0 : 1;
}
#undef STAGES
#endif

/* --- parser (from fast_parser_test.c) --- */
static int parser_test_count = 0;
static int parser_pass_count = 0;

static void parser_test(const char *name, int result) {
  parser_test_count++;
  if (result) {
    parser_pass_count++;
    printf("  [PASS] %s\n", name);
  } else {
    printf("  [FAIL] %s\n", name);
    exit(EXIT_FAILURE);
  }
}

static void parser_test_has_feature(const char *name,
                                    const shell_parse_result_t *result,
                                    uint32_t idx, uint32_t feature) {
  parser_test_count++;
  if (idx < result->count &&
      (result->cmds[idx].features & feature) == feature) {
    parser_pass_count++;
    printf("  [PASS] %s\n", name);
  } else {
    printf("  [FAIL] %s\n", name);
  }
}

static void parser_test_array_assignment_prefix_features(void) {
  bool valid = true;
  shell_limits_t strict = SHELL_LIMITS_DEFAULT;
  strict.strict_mode = true;
  for (size_t c = 0; c < sizeof(shellsplit_test_array_prefixes) /
                             sizeof(shellsplit_test_array_prefixes[0]);
       c++) {
    const char *source = shellsplit_test_array_prefixes[c].source;
    shell_parse_result_t parsed;
    bool item =
        shell_parse_fast(source, strlen(source), &strict, &parsed) == SHELL_OK;
    uint32_t features = 0;
    for (uint32_t i = 0; i < parsed.count; i++)
      features |= parsed.cmds[i].features;
    item = item &&
           !!(features & SHELL_FEAT_ARRAY) ==
               shellsplit_test_array_prefixes[c].array &&
           !!(features & SHELL_FEAT_GLOBS) ==
               shellsplit_test_array_prefixes[c].glob;
    if (!item)
      fprintf(stderr, "array prefix mismatch: %s features=%x\n", source,
              features);
    valid = item && valid;
  }
  parser_test(
      "Array assignment position follows complete timing and scalar prefixes",
      valid);
  valid = true;

  /* Repeated words, fragments within one value, and a long scalar name all
   * require linear forward work. Counting real source visits catches suffix
   * probes that a nominal per-input charge would miss. */
  for (unsigned family = 0; family < 4; family++) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    size_t previous_work = 0;
#endif
    for (size_t units = 64; units <= 2048; units *= 2) {
      static const char prefix[] = "time ";
      static const char suffix[] = " a[0]=b";
      char source[16384];
      size_t used = sizeof(prefix) - 1;
      memcpy(source, prefix, used);
      if (family == 1 || family == 3) {
        const char *assignment = family == 1 ? "A=" : "A[1 + 2]=";
        size_t prefix_length = strlen(assignment);
        memcpy(source + used, assignment, prefix_length);
        used += prefix_length;
      }
      for (size_t i = 0; i < units; i++) {
        const char *part = family == 0 ? "A=\"\" " : family == 2 ? "A" : "'x'";
        size_t length = strlen(part);
        memcpy(source + used, part, length);
        used += length;
      }
      if (family == 2) {
        memcpy(source + used, "=''", 3);
        used += 3;
      }
      memcpy(source + used, suffix, sizeof(suffix));
      used += sizeof(suffix) - 1;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      shellsplit_test_source_scan_reset();
#endif
      shell_parse_result_t parsed;
      bool item =
          shell_parse_fast(source, used, &strict, &parsed) == SHELL_OK &&
          parsed.count == 1 && (parsed.cmds[0].features & SHELL_FEAT_ARRAY) &&
          !(parsed.cmds[0].features & SHELL_FEAT_GLOBS);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      size_t work = shellsplit_test_source_scan_work();
      item = item && work <= 128 * used + 1024 &&
             (previous_work == 0 || work <= 2 * previous_work + 2048);
      previous_work = work;
#endif
      if (!item)
        fprintf(stderr,
                "assignment prefix scaling mismatch: family=%u size=%zu\n",
                family, units);
      valid = item && valid;
    }
  }
  parser_test("Assignment-prefix classification has linear source work", valid);
}

static void parser_test_control_word_boundaries(void) {
  static const char *const keywords[] = {
      "while", "until", "for", "select", "if", "then",
      "elif",  "else",  "fi",  "case",   "in", "esac",
  };
  static const char *const forms[] = {
      "x.%s", "日本.%s",  "日本''%s", "%s.txt",   "'%s'", "\\%s",
      "%s''", "%s$EMPTY", "name=%s",  "${v:-%s}", ">%s",  "<<<%s",
  };
  const uint32_t controls = SHELL_FEAT_LOOPS | SHELL_FEAT_CONDITIONALS |
                            SHELL_FEAT_IF | SHELL_FEAT_CASE;
  bool valid = true;
  for (size_t k = 0; k < sizeof(keywords) / sizeof(keywords[0]); ++k) {
    for (size_t f = 0; f < sizeof(forms) / sizeof(forms[0]); ++f) {
      char word[128], source[192];
      int word_length = snprintf(word, sizeof(word), forms[f], keywords[k]);
      int length =
          snprintf(source, sizeof(source), "printf %%s %s; echo tail", word);
      bool fits = word_length > 0 && (size_t)word_length < sizeof(word) &&
                  length > 0 && (size_t)length < sizeof(source);
      for (unsigned mode = 0; fits && mode < 3; ++mode) {
        shell_limits_t limits = SHELL_LIMITS_DEFAULT;
        limits.strict_mode = mode != 0;
        if (mode == 2)
          limits.max_subcommands = 1;
        shell_parse_result_t parsed;
        shell_error_t error =
            shell_parse_fast(source, (size_t)length, &limits, &parsed);
        bool item =
            error == (mode == 2 ? SHELL_ETRUNC : SHELL_OK) && parsed.count >= 1;
        for (uint32_t i = 0; i < parsed.count; ++i)
          item &= (parsed.cmds[i].features & controls) == 0;
        if (!item)
          fprintf(stderr, "control word boundary: mode=%u source=%s\n", mode,
                  source);
        valid &= item;
      }
      valid &= fits;
      shell_command_t *commands = NULL;
      size_t count = 0;
      bool full =
          fits && shell_tokenize_commands(source, (size_t)length, &commands,
                                          &count) == SHELL_TOKENIZE_OK;
      for (size_t i = 0; i < count; ++i)
        full &= !commands[i].has_loops && !commands[i].has_conditionals &&
                !commands[i].has_case;
      if (!full)
        fprintf(stderr, "tokenizer control word boundary: source=%s\n", source);
      shell_commands_free(commands, count);
      valid &= full;
    }
  }
  parser_test("Control spellings use complete words in all range modes", valid);

  valid = true;
  for (size_t i = 0; i < sizeof(shellsplit_test_control_word_fragments) /
                             sizeof(shellsplit_test_control_word_fragments[0]);
       i++) {
    const char *source = shellsplit_test_control_word_fragments[i].source;
    for (unsigned strict = 0; strict < 2; strict++) {
      shell_limits_t limits = SHELL_LIMITS_DEFAULT;
      limits.strict_mode = strict != 0;
      shell_parse_result_t parsed;
      bool item = shell_parse_fast(source, strlen(source), &limits, &parsed) ==
                  SHELL_OK;
      uint32_t features = 0;
      for (uint32_t c = 0; c < parsed.count; c++)
        features |= parsed.cmds[c].features;
      item &= (features & controls) ==
              shellsplit_test_control_word_fragments[i].range_control_features;
      if (!item)
        fprintf(stderr, "control fragment range: strict=%u source=%s\n", strict,
                source);
      valid = item && valid;
    }
    shell_command_t *commands = NULL;
    size_t count = 0;
    bool item = shell_tokenize_commands(source, strlen(source), &commands,
                                        &count) == SHELL_TOKENIZE_OK;
    for (size_t c = 0; c < count; c++)
      item &= !commands[c].has_conditionals && !commands[c].has_loops &&
              !commands[c].has_case;
    shell_commands_free(commands, count);
    if (!item)
      fprintf(stderr, "control fragment tokens: source=%s\n", source);
    valid = item && valid;
  }
  parser_test("Keyword-shaped command fragments remain ordinary words", valid);

  static const struct {
    const char *source;
    uint32_t expected;
  } contexts[] = {
      {"if true; then :; fi", SHELL_FEAT_IF},
      {"while false; do :; done", SHELL_FEAT_LOOPS},
      {"case x in x) :;; esac", SHELL_FEAT_CASE},
      {"printf %s if", SHELL_FEAT_IF},
      {"printf %s then elif else", SHELL_FEAT_IF},
      {"printf %s do done", 0},
      {"printf %s coproc function", 0},
      {"printf %s 'select' select\"\"", 0},
      {"printf %s whi\\\nle", SHELL_FEAT_LOOPS},
      {"echo \"$(if true; then :; fi)\"", SHELL_FEAT_IF},
      {"echo ${v:-$(while false; do :; done)}", SHELL_FEAT_LOOPS},
      {"cat <(if true; then :; fi)", SHELL_FEAT_IF},
      {"echo `if true; then :; fi`", SHELL_FEAT_IF},
      {"cat <<EOF\n$(if true; then :; fi)\nEOF\n", SHELL_FEAT_IF},
      {"cat <<<$(if true; then :; fi)", SHELL_FEAT_IF},
      {"echo ok # if while case\n", 0},
      {"echo \"$(printf ok # if while case\n)\"", 0},
      {"cat <<'EOF'\nif while case\nEOF\n", 0},
      {"cat <<EOF\nif while case\nEOF\n", 0},
      {"cat <<if\nwhile case\nif\n", 0},
      {"echo ${v:-if} ${v/case/while} $if", 0},
      {"printf %s while<()", 0},
      {"printf %s <()while", 0},
      {"echo ok >while", 0},
      {"echo while<()", 0},
      {"echo <()while", 0},
  };
  valid = true;
  for (size_t c = 0; c < sizeof(contexts) / sizeof(contexts[0]); ++c) {
    shell_parse_result_t parsed;
    shell_limits_t limits = SHELL_LIMITS_DEFAULT;
    limits.strict_mode = true;
    bool item = shell_parse_fast(contexts[c].source, strlen(contexts[c].source),
                                 &limits, &parsed) == SHELL_OK;
    uint32_t features = 0;
    for (uint32_t i = 0; i < parsed.count; ++i)
      features |= parsed.cmds[i].features;
    item &= (features & controls) == contexts[c].expected;
    if (!item)
      fprintf(stderr, "control context: source=%s features=%x expected=%x\n",
              contexts[c].source, features & controls, contexts[c].expected);
    if (!contexts[c].expected) {
      shell_command_t *commands = NULL;
      size_t count = 0;
      item &= shell_tokenize_commands(contexts[c].source,
                                      strlen(contexts[c].source), &commands,
                                      &count) == SHELL_TOKENIZE_OK;
      for (size_t i = 0; i < count; ++i)
        item &= !commands[i].has_loops && !commands[i].has_conditionals &&
                !commands[i].has_case;
      shell_commands_free(commands, count);
    }
    valid &= item;
  }
  parser_test("Control features distinguish executable children from word data",
              valid);

  valid = true;
  for (unsigned family = 0; family < 3; ++family) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    size_t previous = 0;
#endif
    for (size_t units = 64; units <= 2048; units *= 2) {
      char source[16384] = "printf %s ";
      size_t length = strlen(source);
      if (family == 2)
        source[length++] = 'i';
      const char *fragment = family == 0   ? "x''"
                             : family == 1 ? "x.if "
                                           : "\\\n";
      size_t size = strlen(fragment);
      for (size_t i = 0; i < units; ++i) {
        memcpy(source + length, fragment, size);
        length += size;
      }
      const char *tail = family == 2 ? "f" : family == 0 ? "if" : "tail";
      size_t tail_length = strlen(tail);
      memcpy(source + length, tail, tail_length + 1);
      length += tail_length;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      shellsplit_test_source_scan_reset();
#endif
      shell_parse_result_t parsed;
      shell_limits_t limits = SHELL_LIMITS_DEFAULT;
      limits.strict_mode = true;
      bool item =
          shell_parse_fast(source, length, &limits, &parsed) == SHELL_OK &&
          parsed.count == 1 &&
          (parsed.cmds[0].features & controls) ==
              (family == 2 ? SHELL_FEAT_IF : 0);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      size_t work = shellsplit_test_source_scan_work();
      item &= work <= 128 * length + 1024 &&
              (!previous || work <= 2 * previous + 2048);
      previous = work;
#endif
      if (!item)
        fprintf(stderr, "control feature scaling: family=%u units=%zu\n",
                family, units);
      valid &= item;
    }
  }
  parser_test("Control-word classification has linear source work", valid);

  valid = true;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous = 0;
#endif
  for (size_t depth = 2; depth <= 16; depth *= 2) {
    char source[1024];
    size_t length = 0;
    static const char opener[] = "echo ${v:-$(";
    for (size_t i = 0; i < depth; ++i) {
      memcpy(source + length, opener, sizeof(opener) - 1);
      length += sizeof(opener) - 1;
    }
    static const char body[] = "echo 日本''if";
    memcpy(source + length, body, sizeof(body) - 1);
    length += sizeof(body) - 1;
    for (size_t i = 0; i < depth; ++i) {
      memcpy(source + length, ")}", 2);
      length += 2;
    }
    source[length] = '\0';
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_source_scan_reset();
#endif
    shell_parse_result_t parsed;
    shell_limits_t limits = SHELL_LIMITS_DEFAULT;
    limits.strict_mode = true;
    bool item =
        shell_parse_fast(source, length, &limits, &parsed) == SHELL_OK &&
        parsed.count == 1 && !(parsed.cmds[0].features & controls);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    size_t work = shellsplit_test_source_scan_work();
    item &= work <= 256 * length + 1024 &&
            (!previous || work <= 3 * previous + 1024);
    previous = work;
#endif
    if (!item)
      fprintf(stderr, "nested control feature scaling: depth=%zu\n", depth);
    valid &= item;
  }
  parser_test("Nested control-feature walks visit each executable body once",
              valid);
}

typedef struct {
  const char *name;
  const char *input;
  uint32_t expected_count;
  uint32_t type_index;
  uint16_t expected_type;
  uint32_t feature_index;
  uint32_t required_features;
  uint32_t forbidden_features;
} parser_parse_case_t;

#define NO_CHECK UINT32_MAX

static bool parser_valid_command_type(uint16_t type) {
  switch (type) {
  case SHELL_TYPE_SIMPLE:
  case SHELL_TYPE_PIPELINE:
  case SHELL_TYPE_AND:
  case SHELL_TYPE_OR:
  case SHELL_TYPE_SEMICOLON:
  case SHELL_TYPE_HEREDOC:
  case SHELL_TYPE_HERESTRING:
  case SHELL_TYPE_SUBSTITUTION:
  case SHELL_TYPE_BACKGROUND:
    return true;
  default:
    return false;
  }
}

static bool parser_result_invariants(const char *input, size_t input_len,
                                     shell_error_t error,
                                     const shell_parse_result_t *result) {
  const uint32_t all_features =
      SHELL_FEAT_VARS | SHELL_FEAT_GLOBS | SHELL_FEAT_SUBSHELL |
      SHELL_FEAT_ARITH | SHELL_FEAT_HEREDOC | SHELL_FEAT_HERESTRING |
      SHELL_FEAT_PROCESS_SUB | SHELL_FEAT_LOOPS | SHELL_FEAT_CONDITIONALS |
      SHELL_FEAT_IF | SHELL_FEAT_CASE | SHELL_FEAT_SUBSHELL_FILE |
      SHELL_FEAT_PIPELINE | SHELL_FEAT_GROUP | SHELL_FEAT_BACKGROUND |
      SHELL_FEAT_EXTGLOB | SHELL_FEAT_ANSI_C_QUOTE | SHELL_FEAT_ARRAY |
      SHELL_FEAT_NAMED_FD | SHELL_FEAT_COMBINED_REDIRECT;
  if (!input || !result || result->count > SHELL_MAX_SUBCOMMANDS ||
      result->group_count > SHELL_MAX_GROUPS)
    return false;
  if ((error == SHELL_OK) != (result->status == SHELL_STATUS_OK) ||
      (error == SHELL_ETRUNC) != (result->status == SHELL_STATUS_TRUNCATED))
    return false;

  uint32_t previous_end = 0;
  for (uint32_t i = 0; i < result->count; i++) {
    const shell_range_t *range = &result->cmds[i];
    size_t length = 0;
    const char *view = shell_subcommand_view(input, range, &length);
    char copy[64];
    size_t expected_copy =
        range->len < sizeof(copy) ? range->len : sizeof(copy) - 1;
    size_t copied = shell_subcommand_copy(input, range, copy, sizeof(copy));
    if (range->len == 0 || range->start > input_len ||
        range->len > input_len - range->start || range->start < previous_end ||
        !parser_valid_command_type(range->type) ||
        (range->features & ~all_features) != 0 ||
        (range->modifiers &
         ~(SHELL_CMD_MOD_PIPE_NEGATED | SHELL_CMD_MOD_PIPE_TIMED)) != 0 ||
        range->pipeline_time_mode > SHELL_PIPE_TIME_POSIX ||
        ((range->pipeline_time_mode != SHELL_PIPE_TIME_NONE) !=
         ((range->modifiers & SHELL_CMD_MOD_PIPE_TIMED) != 0)) ||
        (range->pipeline_time_direct &&
         range->pipeline_time_mode == SHELL_PIPE_TIME_NONE) ||
        view != input + range->start || length != range->len ||
        copied != expected_copy || memcmp(copy, view, expected_copy) != 0 ||
        copy[copied] != '\0' ||
        shell_source_space((unsigned char)input[range->start]) ||
        shell_source_space(
            (unsigned char)input[range->start + range->len - 1]) ||
        range->role > SHELL_RANGE_ROLE_ELSE)
      return false;
    previous_end = range->start + range->len;
  }
  if (error != SHELL_OK)
    return true;
  for (uint32_t i = 0; i < result->group_count; i++) {
    const shell_group_t *group = &result->groups[i];
    if (group->start >= group->end || group->end > input_len ||
        group->first_command > result->count ||
        group->command_count > result->count - group->first_command ||
        (group->kind != SHELL_GROUP_BRACE &&
         group->kind != SHELL_GROUP_SUBSHELL &&
         group->kind != SHELL_GROUP_IF) ||
        group->role > SHELL_RANGE_ROLE_ELSE ||
        (group->role != SHELL_RANGE_ROLE_NONE &&
         (group->parent == UINT16_MAX ||
          result->groups[group->parent].kind != SHELL_GROUP_IF)) ||
        (group->modifiers &
         ~(SHELL_CMD_MOD_PIPE_NEGATED | SHELL_CMD_MOD_PIPE_TIMED)) != 0 ||
        group->pipeline_time_mode > SHELL_PIPE_TIME_POSIX ||
        ((group->pipeline_time_mode != SHELL_PIPE_TIME_NONE) !=
         ((group->modifiers & SHELL_CMD_MOD_PIPE_TIMED) != 0)) ||
        (group->pipeline_time_direct &&
         group->pipeline_time_mode == SHELL_PIPE_TIME_NONE) ||
        (group->parent != UINT16_MAX && group->parent >= i))
      return false;
    if (group->parent != UINT16_MAX) {
      const shell_group_t *parent = &result->groups[group->parent];
      if (group->start < parent->start || group->end > parent->end ||
          group->first_command < parent->first_command ||
          group->first_command + group->command_count >
              parent->first_command + parent->command_count)
        return false;
    }
  }
  /* A range with a role lies in an `if` group. */
  for (uint32_t i = 0; i < result->count; i++) {
    if (result->cmds[i].role == SHELL_RANGE_ROLE_NONE)
      continue;
    bool in_if = false;
    for (uint32_t g = 0; g < result->group_count; g++)
      in_if |=
          result->groups[g].kind == SHELL_GROUP_IF &&
          result->groups[g].first_command <= i &&
          i - result->groups[g].first_command < result->groups[g].command_count;
    if (!in_if)
      return false;
  }
  return true;
}

static shell_error_t parser_parse_checked(const char *input, size_t input_len,
                                          const shell_limits_t *limits,
                                          shell_parse_result_t *result) {
  shell_error_t error = shell_parse_fast(input, input_len, limits, result);
  if (input && result && (error == SHELL_OK || error == SHELL_ETRUNC) &&
      !parser_result_invariants(input, input_len, error, result)) {
    printf("  [FAIL] parser result invariant for %zu-byte input\n", input_len);
    parser_test_count++;
  }
  return error;
}

#define shell_parse_fast parser_parse_checked

static void parser_extract(const char *input, shell_parse_result_t *result) {
  shell_parse_fast(input, strlen(input), NULL, result);
}

/* --- unit tests: one feature at a time --- */

static void parser_test_feature_matrix(void) {
  printf("\n--- Feature Detection Matrix ---\n");

  static const parser_parse_case_t cases[] = {
      {"single-quoted command", "'ls'", 1, 0, SHELL_TYPE_SIMPLE, 0, 0, 0},
      {"double-quoted command", "\"ls\"", 1, 0, SHELL_TYPE_SIMPLE, 0, 0, 0},
      {"quoted command with arguments", "'ls' -la", 1, 0, SHELL_TYPE_SIMPLE, 0,
       0, 0},
      {"semicolon in single quotes", "'echo hello; world'", 1, 0,
       SHELL_TYPE_SIMPLE, 0, 0, 0},
      {"semicolon in double quotes", "\"echo hello; world\"", 1, 0,
       SHELL_TYPE_SIMPLE, 0, 0, 0},
      {"simple variable", "echo $VAR", 1, NO_CHECK, 0, 0, SHELL_FEAT_VARS, 0},
      {"braced variable", "echo ${VAR}", 1, NO_CHECK, 0, 0, SHELL_FEAT_VARS, 0},
      {"positional variable", "echo $1", 1, NO_CHECK, 0, 0, SHELL_FEAT_VARS, 0},
      {"special variables", "echo $? $$ $#", 1, NO_CHECK, 0, 0, SHELL_FEAT_VARS,
       0},
      {"plain command", "echo hello", 1, NO_CHECK, 0, 0, 0,
       SHELL_FEAT_VARS | SHELL_FEAT_SUBSHELL | SHELL_FEAT_ARITH},
      {"star glob", "ls *.txt", 1, NO_CHECK, 0, 0, SHELL_FEAT_GLOBS, 0},
      {"question glob", "ls file?.txt", 1, NO_CHECK, 0, 0, SHELL_FEAT_GLOBS, 0},
      {"bracket glob", "ls [abc].txt", 1, NO_CHECK, 0, 0, SHELL_FEAT_GLOBS, 0},
      {"plain filename", "ls file.txt", 1, NO_CHECK, 0, 0, 0, SHELL_FEAT_GLOBS},
      {"heredoc bracket content", "cat << EOF\n[content]\nEOF", 2, NO_CHECK, 0,
       NO_CHECK, 0, 0},
      {"dollar subshell", "echo $(date)", 1, 0, SHELL_TYPE_SUBSTITUTION, 0,
       SHELL_FEAT_SUBSHELL, 0},
      {"backtick subshell", "echo `date`", 1, 0, SHELL_TYPE_SUBSTITUTION, 0,
       SHELL_FEAT_SUBSHELL, 0},
      {"arithmetic", "echo $((1+2))", 1, NO_CHECK, 0, 0, SHELL_FEAT_ARITH, 0},
      {"arithmetic variables", "echo $((x + y))", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_ARITH | SHELL_FEAT_VARS, 0},
      {"arithmetic command variables and substitution",
       "(( $x + $(printf 1) ))", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_ARITH | SHELL_FEAT_VARS | SHELL_FEAT_SUBSHELL,
       SHELL_FEAT_GROUP | SHELL_FEAT_PROCESS_SUB | SHELL_FEAT_GLOBS},
      {"arithmetic command array", "(( items[0] ))", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_ARITH | SHELL_FEAT_ARRAY, SHELL_FEAT_GLOBS},
      {"arithmetic command child pipeline", "(( $(printf 1 | cat) ))", 1,
       NO_CHECK, 0, 0,
       SHELL_FEAT_ARITH | SHELL_FEAT_SUBSHELL | SHELL_FEAT_PIPELINE,
       SHELL_FEAT_GROUP},
      {"arithmetic command child loop", "(( $(while false; do :; done) ))", 1,
       NO_CHECK, 0, 0,
       SHELL_FEAT_ARITH | SHELL_FEAT_SUBSHELL | SHELL_FEAT_LOOPS, 0},
      {"arithmetic command child ANSI-C quote", "(( $(printf $'1') ))", 1,
       NO_CHECK, 0, 0,
       SHELL_FEAT_ARITH | SHELL_FEAT_SUBSHELL | SHELL_FEAT_ANSI_C_QUOTE, 0},
      {"arithmetic command adjacent shifts", "((1<<(2) && 8>>(1)))", 1,
       NO_CHECK, 0, 0, SHELL_FEAT_ARITH,
       SHELL_FEAT_PROCESS_SUB | SHELL_FEAT_HEREDOC | SHELL_FEAT_GROUP |
           SHELL_FEAT_GLOBS | SHELL_FEAT_PIPELINE | SHELL_FEAT_BACKGROUND},
      {"plain expression", "echo 1+2", 1, NO_CHECK, 0, 0, 0, SHELL_FEAT_ARITH},
      {"variable pipeline", "echo $VAR | grep pattern", 2, 1,
       SHELL_TYPE_PIPELINE, 0, SHELL_FEAT_VARS, 0},
      {"glob pipeline", "ls *.txt | sort", 2, 1, SHELL_TYPE_PIPELINE, 0,
       SHELL_FEAT_GLOBS, 0},
      {"subshell pipeline", "$(cmd) | cat", 2, 1, SHELL_TYPE_PIPELINE, 0,
       SHELL_FEAT_SUBSHELL, 0},
      {"variable and-chain", "test -n $VAR && echo found", 2, 1, SHELL_TYPE_AND,
       0, SHELL_FEAT_VARS, 0},
      {"arithmetic or-chain", "x=$((1+2)) || y=0", 2, 1, SHELL_TYPE_OR, 0,
       SHELL_FEAT_ARITH, 0},
      {"double-quoted variable", "echo \"$VAR\"", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_VARS, 0},
      {"double-quoted command substitution", "echo \"$(id)\"", 1, 0,
       SHELL_TYPE_SUBSTITUTION, 0, SHELL_FEAT_SUBSHELL, 0},
      {"double-quoted combined redirect", "echo \"&>out\"", 1, NO_CHECK, 0, 0,
       0, SHELL_FEAT_COMBINED_REDIRECT},
      {"double-quoted extglob", "echo \"@(left|right)\"", 1, NO_CHECK, 0, 0, 0,
       SHELL_FEAT_EXTGLOB | SHELL_FEAT_GROUP},
      {"double-quoted array syntax", "echo \"items=(one)\"", 1, NO_CHECK, 0, 0,
       0, SHELL_FEAT_ARRAY | SHELL_FEAT_GROUP},
      {"double-quoted named descriptor", "echo \"{fd}>out\"", 1, NO_CHECK, 0, 0,
       0, SHELL_FEAT_NAMED_FD},
      {"double-quoted process substitution", "echo \"<(producer)\"", 1,
       NO_CHECK, 0, 0, 0, SHELL_FEAT_PROCESS_SUB | SHELL_FEAT_GROUP},
      {"single quote inside double substitution", "echo \"'$(id)\"", 1, 0,
       SHELL_TYPE_SUBSTITUTION, 0, SHELL_FEAT_SUBSHELL, 0},
      {"adjacent substitutions", "echo $(id)$(pwd)", 1, 0,
       SHELL_TYPE_SUBSTITUTION, 0, SHELL_FEAT_SUBSHELL, 0},
      {"embedded adjacent substitutions", "echo pre$(id)suf$(pwd)", 1, 0,
       SHELL_TYPE_SUBSTITUTION, 0, SHELL_FEAT_SUBSHELL, 0},
      {"mixed substitutions", "echo $(id)`pwd`", 1, 0, SHELL_TYPE_SUBSTITUTION,
       0, SHELL_FEAT_SUBSHELL, 0},
      {"arithmetic with executable substitution", "echo $(( $(id) + 1 ))", 1,
       NO_CHECK, 0, 0, SHELL_FEAT_ARITH | SHELL_FEAT_SUBSHELL, 0},
      {"arithmetic expansion variants",
       "echo $(( $(id) + ${value} + $1 + $number ))", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_ARITH | SHELL_FEAT_SUBSHELL | SHELL_FEAT_VARS, 0},
      {"ANSI-C quote inside arithmetic substitution",
       "echo $(( $(printf $'x)') + 1 ))", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_ARITH | SHELL_FEAT_SUBSHELL | SHELL_FEAT_ANSI_C_QUOTE, 0},
      {"indexed array assignment", "items[0]=one", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_ARRAY, SHELL_FEAT_GLOBS},
      {"associative array assignment with ANSI-C index", "items[$'key]']=one",
       1, NO_CHECK, 0, 0, SHELL_FEAT_ARRAY | SHELL_FEAT_ANSI_C_QUOTE,
       SHELL_FEAT_GLOBS},
      {"parameter array reference", "echo ${items[$'key]']}", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_VARS | SHELL_FEAT_ARRAY | SHELL_FEAT_ANSI_C_QUOTE,
       SHELL_FEAT_GLOBS},
      {"parameter default bracket pattern is not an array",
       "echo ${value:-[x]}", 1, NO_CHECK, 0, 0, SHELL_FEAT_VARS,
       SHELL_FEAT_ARRAY},
      {"ordinary array-shaped argument is not an array assignment",
       "echo item[0]=one", 1, NO_CHECK, 0, 0, SHELL_FEAT_GLOBS,
       SHELL_FEAT_ARRAY},
      {"array assignment after scalar prefix", "MODE=x items[0]=one command", 1,
       NO_CHECK, 0, 0, SHELL_FEAT_ARRAY, SHELL_FEAT_GLOBS},
      {"arithmetic array reference", "echo $((items[0] + 1))", 1, NO_CHECK, 0,
       0, SHELL_FEAT_ARITH | SHELL_FEAT_ARRAY, SHELL_FEAT_GLOBS},
      {"quoted arithmetic array reference", "echo \"$((items[0]))\"", 1,
       NO_CHECK, 0, 0, SHELL_FEAT_ARITH | SHELL_FEAT_ARRAY, SHELL_FEAT_GLOBS},
      {"mixed parameter array reference", "echo pre\"${items[0]}\"post", 1,
       NO_CHECK, 0, 0, SHELL_FEAT_VARS | SHELL_FEAT_ARRAY, SHELL_FEAT_GLOBS},
      {"quoted literal array syntax", "echo '${items[0]}'", 1, NO_CHECK, 0, 0,
       0, SHELL_FEAT_ARRAY},
      {"quoted escaped substitution", "echo \"\\$(id)\"", 1, NO_CHECK, 0, 0, 0,
       SHELL_FEAT_SUBSHELL},
      {"even escaped substitution", "echo \\\\$(id)", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_SUBSHELL, 0},
      {"first-command process substitution", "cat <(id)", 1, 0,
       SHELL_TYPE_SUBSTITUTION, 0, SHELL_FEAT_PROCESS_SUB, 0},
      /* A process substitution belongs to the command that contains it, not
       * to the range before the connector. */
      {"process substitution after AND", "echo ok && cat <(id)", 2, 1,
       SHELL_TYPE_AND, 1, SHELL_FEAT_PROCESS_SUB, 0},
      {"no process substitution before AND", "echo ok && cat <(id)", 2,
       NO_CHECK, 0, 0, 0, SHELL_FEAT_PROCESS_SUB},
      {"no process substitution before semicolon", "echo ok; cat <(id)", 2,
       NO_CHECK, 0, 0, 0, SHELL_FEAT_PROCESS_SUB},
      {"process substitution after semicolon", "echo ok; cat <(id)", 2,
       NO_CHECK, 0, 1, SHELL_FEAT_PROCESS_SUB, 0},
      {"no process substitution before newline", "echo ok\ncat <(id)", 2,
       NO_CHECK, 0, 0, 0, SHELL_FEAT_PROCESS_SUB},
      {"process substitution after newline", "echo ok\ncat <(id)", 2, NO_CHECK,
       0, 1, SHELL_FEAT_PROCESS_SUB, 0},
      {"no process substitution before pipe", "echo ok | cat <(id)", 2,
       NO_CHECK, 0, 0, 0, SHELL_FEAT_PROCESS_SUB},
      {"process substitution after pipe", "echo ok | cat <(id)", 2, NO_CHECK, 0,
       1, SHELL_FEAT_PROCESS_SUB, 0},
      {"no process substitution before OR", "echo ok || cat >(id)", 2, NO_CHECK,
       0, 0, 0, SHELL_FEAT_PROCESS_SUB},
      {"output process substitution after OR", "echo ok || cat >(id)", 2,
       NO_CHECK, 0, 1, SHELL_FEAT_PROCESS_SUB, 0},
      {"redirect target output process substitution", "printf value 2> >(cat)",
       1, 0, SHELL_TYPE_SUBSTITUTION, 0, SHELL_FEAT_PROCESS_SUB, 0},
      {"special option variable", "echo $-", 1, NO_CHECK, 0, 0, SHELL_FEAT_VARS,
       0},
      /* A special parameter owns its name byte, so ? and * are not patterns.
       * Pattern syntax around it still is. */
      {"status parameter is not a glob", "printf '%s\\n' $?", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_VARS, SHELL_FEAT_GLOBS},
      {"star parameter is not a glob", "echo $*", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_VARS, SHELL_FEAT_GLOBS},
      {"at parameter is not a glob", "echo $@", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_VARS, SHELL_FEAT_GLOBS},
      {"braced status parameter is not a glob", "echo ${?}", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_VARS, SHELL_FEAT_GLOBS},
      {"adjacent status parameters are not globs", "echo $?$?", 1, NO_CHECK, 0,
       0, SHELL_FEAT_VARS, SHELL_FEAT_GLOBS},
      {"glob after status parameter", "echo $?*.log", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_VARS | SHELL_FEAT_GLOBS, 0},
      {"glob after star parameter", "echo $*?", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_VARS | SHELL_FEAT_GLOBS, 0},
      {"glob after named parameter", "echo $x?", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_VARS | SHELL_FEAT_GLOBS, 0},
      /* A bracket is a pattern only when its word closes it. */
      {"lone bracket is not a glob", "echo [", 1, NO_CHECK, 0, 0, 0,
       SHELL_FEAT_GLOBS},
      {"test command bracket is not a glob", "[ -e /tmp/example ]", 1, NO_CHECK,
       0, 0, 0, SHELL_FEAT_GLOBS},
      {"unclosed bracket word is not a glob", "echo [ab", 1, NO_CHECK, 0, 0, 0,
       SHELL_FEAT_GLOBS},
      {"later bracket word does not close it", "echo [ a ]", 1, NO_CHECK, 0, 0,
       0, SHELL_FEAT_GLOBS},
      {"empty bracket is not a glob", "echo []", 1, NO_CHECK, 0, 0, 0,
       SHELL_FEAT_GLOBS},
      {"bracket pattern is a glob", "echo [ab]", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_GLOBS, 0},
      {"negated bracket pattern is a glob", "echo [!a]*", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_GLOBS, 0},
      {"character class pattern is a glob", "echo [[:alpha:]]", 1, NO_CHECK, 0,
       0, SHELL_FEAT_GLOBS, 0},
      {"embedded bracket pattern is a glob", "ls a[b-c]d", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_GLOBS, 0},
      {"quoted bracket pattern is not a glob", "echo '[ab]'", 1, NO_CHECK, 0, 0,
       0, SHELL_FEAT_GLOBS},
      {"escaped bracket pattern is not a glob", "echo \\[ab\\]", 1, NO_CHECK, 0,
       0, 0, SHELL_FEAT_GLOBS},
      {"loop feature", "while true", 1, NO_CHECK, 0, 0, SHELL_FEAT_LOOPS, 0},
      {"conditional feature", "[[ true ]]", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_CONDITIONALS, 0},
      {"if feature", "if true; then :; fi", 2, NO_CHECK, 0, 0, SHELL_FEAT_IF,
       0},
      {"case feature", "case value", 1, NO_CHECK, 0, 0, SHELL_FEAT_CASE, 0},
      {"file command substitution", "echo $(<file)", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_SUBSHELL | SHELL_FEAT_SUBSHELL_FILE, 0},
      {"here-string", "cmd <<< string", 2, 1, SHELL_TYPE_HERESTRING, 1,
       SHELL_FEAT_HERESTRING, 0},
      {"here-string quoted escape", "cmd <<< \"two\\\" words\"", 2, 1,
       SHELL_TYPE_HERESTRING, 1, SHELL_FEAT_HERESTRING, 0},
      {"here-string escaped space", "cmd <<< two\\ words", 2, 1,
       SHELL_TYPE_HERESTRING, 1, SHELL_FEAT_HERESTRING, 0},
      {"here-string command substitution", "cmd <<< $(printf one)", 2, 1,
       SHELL_TYPE_HERESTRING, 1, SHELL_FEAT_HERESTRING | SHELL_FEAT_SUBSHELL,
       0},
      {"here-string file command substitution", "cmd <<< $(</tmp/input)", 2, 1,
       SHELL_TYPE_HERESTRING, 1,
       SHELL_FEAT_HERESTRING | SHELL_FEAT_SUBSHELL | SHELL_FEAT_SUBSHELL_FILE,
       0},
      {"here-string backtick substitution", "cmd <<< `printf one`", 2, 1,
       SHELL_TYPE_HERESTRING, 1, SHELL_FEAT_HERESTRING | SHELL_FEAT_SUBSHELL,
       0},
      {"here-string scalar expansion", "cmd <<< \"$value\"", 2, 1,
       SHELL_TYPE_HERESTRING, 1, SHELL_FEAT_HERESTRING | SHELL_FEAT_VARS, 0},
      {"here-string process substitution", "cmd <<< <(printf one)", 2, 1,
       SHELL_TYPE_HERESTRING, 1, SHELL_FEAT_HERESTRING | SHELL_FEAT_PROCESS_SUB,
       SHELL_FEAT_SUBSHELL},
      {"here-string literal punctuation", "cmd <<< if*", 2, 1,
       SHELL_TYPE_HERESTRING, 1, SHELL_FEAT_HERESTRING,
       SHELL_FEAT_GLOBS | SHELL_FEAT_CONDITIONALS},
      {"here-string literal substitution", "cmd <<< '$(false)'", 2, 1,
       SHELL_TYPE_HERESTRING, 1, SHELL_FEAT_HERESTRING, SHELL_FEAT_SUBSHELL},
      {"single-quoted variable", "echo '$VAR'", 1, NO_CHECK, 0, 0, 0,
       SHELL_FEAT_VARS},
      {"double-quoted glob", "echo \"*.txt\"", 1, NO_CHECK, 0, 0, 0,
       SHELL_FEAT_GLOBS},
      {"escaped space", "echo hello\\ world", 1, NO_CHECK, 0, NO_CHECK, 0, 0},
      {"escaped variable", "echo \\$VAR", 1, NO_CHECK, 0, 0, 0,
       SHELL_FEAT_VARS},
      {"escaped quoted variable", "echo \"\\$VAR\"", 1, NO_CHECK, 0, 0, 0,
       SHELL_FEAT_VARS},
      {"array subscript", "echo ${arr[0]}", 1, NO_CHECK, 0, 0, SHELL_FEAT_VARS,
       0},
      {"parameter expansion", "echo ${var:-default}", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_VARS, 0},
      {"subshell assignment", "var=$(echo hi)", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_SUBSHELL, 0},
      {"arithmetic assignment", "var=$((1+2))", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_ARITH, 0},
      {"multiple variables", "echo $a $b $c", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_VARS, 0},
      {"single-quoted glob", "ls '*.txt'", 1, NO_CHECK, 0, 0, 0,
       SHELL_FEAT_GLOBS},
      {"nested subshell", "echo $(echo $(date))", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_SUBSHELL, 0},
      {"triple subshell", "echo $(a $(b $(c)))", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_SUBSHELL, 0},
      {"subshell variable", "x=$(echo $y)", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_SUBSHELL | SHELL_FEAT_VARS, 0},
      {"nested backticks", "`echo \\`date\\` `", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_SUBSHELL, 0},
      {"string conditional", "if [ \"$a\" = \"b\" ]; then echo yes; fi", 2,
       NO_CHECK, 0, 0, SHELL_FEAT_VARS, 0},
      {"numeric conditional", "if [ $x -gt 0 ]; then echo positive; fi", 2,
       NO_CHECK, 0, 0, SHELL_FEAT_VARS, 0},
      {"regex conditional", "if [[ $x =~ pattern ]]; then match; fi", 2,
       NO_CHECK, 0, 0, SHELL_FEAT_VARS, 0},
      {"glob conditional", "if [[ $str == *.* ]]; then echo ext; fi", 2,
       NO_CHECK, 0, 0, SHELL_FEAT_VARS | SHELL_FEAT_GLOBS, 0},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t result;
    shell_error_t error =
        shell_parse_fast(cases[i].input, strlen(cases[i].input), NULL, &result);
    bool valid = parser_result_invariants(
                     cases[i].input, strlen(cases[i].input), error, &result) &&
                 error == SHELL_OK && result.status == SHELL_STATUS_OK;
    if (cases[i].expected_count != NO_CHECK)
      valid = valid && result.count == cases[i].expected_count;
    if (cases[i].type_index != NO_CHECK)
      valid = valid && cases[i].type_index < result.count &&
              result.cmds[cases[i].type_index].type == cases[i].expected_type;
    if (cases[i].feature_index != NO_CHECK) {
      valid = valid && cases[i].feature_index < result.count;
      if (valid) {
        uint32_t features = result.cmds[cases[i].feature_index].features;
        valid = (features & cases[i].required_features) ==
                    cases[i].required_features &&
                (features & cases[i].forbidden_features) == 0;
      }
    }
    if (!valid) {
      printf("    error=%d status=%u count=%u", error, result.status,
             result.count);
      if (cases[i].feature_index < result.count)
        printf(" features[%u]=0x%x", cases[i].feature_index,
               result.cmds[cases[i].feature_index].features);
      printf("\n");
    }
    parser_test(cases[i].name, valid);
  }

  shell_parse_result_t metadata;
  parser_extract("cmd1 & cmd2", &metadata);
  parser_test_has_feature("Background marks preceding command", &metadata, 0,
                          SHELL_FEAT_BACKGROUND);
  parser_extract("(cmd1; cmd2)", &metadata);
  parser_test("Group metadata and feature are retained",
              metadata.count == 2 && metadata.cmds[0].group_depth == 1 &&
                  metadata.cmds[1].group_depth == 1 &&
                  (metadata.cmds[0].features & SHELL_FEAT_GROUP) != 0);

  parser_extract(
      "cd /workspace && { sleep 2; printf 'q'; } | ./clock > /tmp/clock.out",
      &metadata);
  parser_test("POSIX brace group retains four simple commands",
              metadata.count == 4 && metadata.group_count == 1 &&
                  metadata.groups[0].kind == SHELL_GROUP_BRACE &&
                  metadata.groups[0].parent == UINT16_MAX &&
                  metadata.groups[0].first_command == 1 &&
                  metadata.groups[0].command_count == 2 &&
                  metadata.cmds[0].group_kinds == SHELL_GROUP_NONE &&
                  metadata.cmds[1].group_depth == 1 &&
                  metadata.cmds[2].group_depth == 1 &&
                  metadata.cmds[1].group_kinds == SHELL_GROUP_BRACE &&
                  metadata.cmds[2].group_kinds == SHELL_GROUP_BRACE &&
                  metadata.cmds[3].type == SHELL_TYPE_PIPELINE &&
                  (metadata.cmds[1].features & SHELL_FEAT_GROUP) != 0);

  parser_extract("{( echo )}", &metadata);
  parser_test("Nested brace descriptors preserve parent and command spans",
              metadata.count == 1 && metadata.group_count == 2 &&
                  metadata.groups[0].kind == SHELL_GROUP_BRACE &&
                  metadata.groups[0].parent == UINT16_MAX &&
                  metadata.groups[0].first_command == 0 &&
                  metadata.groups[0].command_count == 1 &&
                  metadata.groups[1].kind == SHELL_GROUP_SUBSHELL &&
                  metadata.groups[1].parent == 0 &&
                  metadata.groups[1].first_command == 0 &&
                  metadata.groups[1].command_count == 1);

  static const char *const compact_groups[] = {
      "({ echo ok; })", "({(echo ok)})", "time ({ echo ok; })",
      "time ({(echo ok)})", "({ echo a; echo b; }) | cat"};
  for (size_t i = 0; i < sizeof(compact_groups) / sizeof(compact_groups[0]);
       i++) {
    shell_limits_t limits = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    shell_error_t error = shell_parse_fast(
        compact_groups[i], strlen(compact_groups[i]), &limits, &metadata);
    parser_test("Compact nested delimiters retain lexical group membership",
                error == SHELL_OK &&
                    parser_result_invariants(compact_groups[i],
                                             strlen(compact_groups[i]), error,
                                             &metadata) &&
                    metadata.group_count == (i == 1 || i == 3 ? 3 : 2) &&
                    metadata.groups[0].kind == SHELL_GROUP_SUBSHELL &&
                    metadata.groups[1].kind == SHELL_GROUP_BRACE &&
                    metadata.groups[1].parent == 0 &&
                    metadata.cmds[0].group_depth == (i == 1 || i == 3 ? 3 : 2));
  }

  parser_extract("exit <<< <(printf '%s' \"$(true)\")", &metadata);
  parser_test(
      "Lexical document features still include child-shell substitutions",
      metadata.count == 2 &&
          (metadata.cmds[1].features &
           (SHELL_FEAT_PROCESS_SUB | SHELL_FEAT_SUBSHELL)) ==
              (SHELL_FEAT_PROCESS_SUB | SHELL_FEAT_SUBSHELL));

  parser_extract("{ cat; cat; } <<< value", &metadata);
  parser_test("Group here-strings do not create synthetic fast-parser stages",
              metadata.count == 2 && metadata.group_count == 1 &&
                  metadata.groups[0].kind == SHELL_GROUP_BRACE &&
                  metadata.cmds[0].type == SHELL_TYPE_SIMPLE &&
                  metadata.cmds[1].type == SHELL_TYPE_SEMICOLON);
}

void test_layer1_utility_functions(void) {
  printf("\n--- Layer 1: Utility Functions ---\n");

  const shell_range_t range = {.start = 2, .len = 6};
  const char input[] = "  ls -la";
  char buf[64];

  size_t copied = shell_subcommand_copy(input, &range, buf, sizeof(buf));
  parser_test("copy returns exact subcommand",
              copied == 6 && strcmp(buf, "ls -la") == 0);

  copied = shell_subcommand_copy(input, &range, buf, 3);
  parser_test("copy truncates and terminates a small buffer",
              copied == 2 && strcmp(buf, "ls") == 0);

  size_t len = 0;
  const char *ptr = shell_subcommand_view(input, &range, &len);
  parser_test("get returns the ranged view", ptr == input + 2 && len == 6);

  const shell_range_t empty = {.start = 0, .len = 0};
  buf[0] = 'x';
  copied = shell_subcommand_copy(input, &empty, buf, sizeof(buf));
  parser_test("Copy preserves an empty subcommand",
              copied == 0 && buf[0] == '\0');

  ptr = shell_subcommand_view(input, &empty, NULL);
  parser_test("Ranged view may omit its length output", ptr == input);
}

void test_layer1_error_handling(void) {
  printf("\n--- Layer 1: Error Handling ---\n");

  shell_parse_result_t result;
  const shell_limits_t limits = {.max_subcommands = 1, .strict_mode = false};
  static const struct {
    const char *name;
    const char *input;
    uint16_t type;
    uint32_t features;
  } truncation_cases[] = {
      {"pipeline truncation", "cmd1 | cmd2", SHELL_TYPE_SIMPLE,
       SHELL_FEAT_PIPELINE},
      {"heredoc truncation", "cat <<EOF\nbody\nEOF ; pwd", SHELL_TYPE_SIMPLE,
       0},
      {"substitution truncation", "echo $(id); pwd", SHELL_TYPE_SUBSTITUTION,
       SHELL_FEAT_SUBSHELL},
      {"process substitution truncation", "diff <(a) <(b); pwd",
       SHELL_TYPE_SUBSTITUTION, SHELL_FEAT_PROCESS_SUB},
      {"loop truncation", "for x in a; do echo $x; done ; pwd",
       SHELL_TYPE_SIMPLE, SHELL_FEAT_LOOPS},
      {"conditional truncation", "if true; then echo yes; fi ; pwd",
       SHELL_TYPE_SIMPLE, SHELL_FEAT_IF},
      {"mixed composition truncation", "a && b || c | d ; e", SHELL_TYPE_SIMPLE,
       0},
  };
  for (size_t i = 0; i < sizeof(truncation_cases) / sizeof(truncation_cases[0]);
       i++) {
    shell_error_t error =
        shell_parse_fast(truncation_cases[i].input,
                         strlen(truncation_cases[i].input), &limits, &result);
    parser_test(truncation_cases[i].name,
                error == SHELL_ETRUNC &&
                    result.status == SHELL_STATUS_TRUNCATED &&
                    result.count == 1 &&
                    result.cmds[0].type == truncation_cases[i].type &&
                    (result.cmds[0].features & truncation_cases[i].features) ==
                        truncation_cases[i].features);
  }

  shell_error_t err;

#if SIZE_MAX > UINT32_MAX
  memset(&result, 0xa5, sizeof(result));
  err = shell_parse_fast("x", (size_t)UINT32_MAX + 1, NULL, &result);
  parser_test("Rejects input too large for range offsets",
              err == SHELL_EINPUT && result.count == 0 &&
                  result.status == SHELL_STATUS_ERROR);
#endif
}

void test_dialect_oracle(void) {
  static const struct {
    const char *input;
    uint32_t count;
    uint32_t graph_count;
    uint16_t first_type;
    uint16_t second_type;
  } cases[] = {
      {"ls", 1, 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE},
      {"ls | wc", 2, 2, SHELL_TYPE_SIMPLE, SHELL_TYPE_PIPELINE},
      {"ls && pwd", 2, 2, SHELL_TYPE_SIMPLE, SHELL_TYPE_AND},
      {"ls || pwd", 2, 2, SHELL_TYPE_SIMPLE, SHELL_TYPE_OR},
      {"echo 'a|b'", 1, 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE},
      {"echo \"a; b\"", 1, 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE},
      {"echo $(id)", 1, 2, SHELL_TYPE_SUBSTITUTION, SHELL_TYPE_SIMPLE},
      {"echo $(id)$(pwd)", 1, 3, SHELL_TYPE_SUBSTITUTION, SHELL_TYPE_SIMPLE},
      {"echo pre$(id)suf$(pwd)", 1, 3, SHELL_TYPE_SUBSTITUTION,
       SHELL_TYPE_SIMPLE},
      {"echo $(id)`pwd`", 1, 3, SHELL_TYPE_SUBSTITUTION, SHELL_TYPE_SIMPLE},
      {"echo \"$(id)$(pwd)\"", 1, 3, SHELL_TYPE_SUBSTITUTION,
       SHELL_TYPE_SIMPLE},
      {"echo \"\\$(id)\"", 1, 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE},
      {"echo $(cat /tmp/a | sort)", 1, 3, SHELL_TYPE_SUBSTITUTION,
       SHELL_TYPE_SIMPLE},
      {"cat <(sort <(cat /tmp/a))", 1, 3, SHELL_TYPE_SUBSTITUTION,
       SHELL_TYPE_SIMPLE},
      {"echo $(id) && pwd", 2, 3, SHELL_TYPE_SUBSTITUTION, SHELL_TYPE_AND},
      {"cat <(printf x) | sort", 2, 3, SHELL_TYPE_SUBSTITUTION,
       SHELL_TYPE_PIPELINE},
      {"echo $((1+2))", 1, 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE},
      {"cmd ;", 1, 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t fast = {0};
    shell_error_t error =
        shell_parse_fast(cases[i].input, strlen(cases[i].input), NULL, &fast);
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    bool full_ok = (shell_tokenize_commands(
                        cases[i].input, strlen(cases[i].input), &commands,
                        &command_count) == SHELL_TOKENIZE_OK);
    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    shell_process_status_t process_error = shell_process_command(
        cases[i].input, strlen(cases[i].input), NULL, &infos, &info_count);
    shell_dep_graph_t graph;
    memset(&graph, 0xa5, sizeof(graph));
    shell_dep_error_t graph_error = shell_dep_graph_parse(
        cases[i].input, strlen(cases[i].input), ".", NULL, &graph);
    parser_test("Dialect oracle constructs a complete bounded graph",
                graph_error == SHELL_DEP_OK &&
                    graph.node_count <= SHELL_DEP_MAX_NODES);
    uint32_t graph_commands = 0;
    for (uint32_t node = 0; node < graph.node_count; node++)
      if (graph.nodes[node].type == SHELL_NODE_CMD)
        graph_commands++;
    bool ranges_agree = full_ok && command_count == cases[i].count &&
                        process_error == SHELL_PROCESS_OK &&
                        info_count == cases[i].count;
    for (uint32_t command = 0; ranges_agree && command < fast.count;
         command++) {
      const shell_range_t *range = &fast.cmds[command];
      size_t fast_end = (size_t)range->start + range->len;
      size_t full_end = commands[command].end_pos;
      /* The allocating tokenizer omits a closing parenthesis from the
       * command span when it was consumed as a group delimiter.  The fast
       * zero-copy range keeps the delimiter in its source slice.  Treat that
       * one-byte representation difference as equivalent while still
       * requiring both APIs to agree on command count and start boundaries. */
      bool full_span_covers_fast =
          full_end >= fast_end ||
          (full_end < strlen(cases[i].input) && full_end + 1 >= fast_end &&
           cases[i].input[full_end] == ')');
      ranges_agree =
          commands[command].start_pos <= range->start && full_span_covers_fast;
      for (size_t token = 0;
           ranges_agree && token < infos[command].command_token_count;
           token++) {
        const shell_token_t *value = &infos[command].command_tokens[token];
        ranges_agree = value->position <= range->len &&
                       value->length <= range->len - value->position;
      }
    }
    if (!ranges_agree)
      printf("    differential mismatch for '%s': fast=%u full=%zu info=%zu\n",
             cases[i].input, fast.count, command_count, info_count);
    if (!ranges_agree)
      for (uint32_t command = 0;
           command < fast.count && command < command_count &&
           command < info_count;
           command++)
        printf("      %u fast='%.*s' full=[%zu,%zu) info='%s'\n", command,
               fast.cmds[command].len,
               cases[i].input + fast.cmds[command].start,
               commands[command].start_pos, commands[command].end_pos,
               infos[command].original_command);
    char name[96];
    snprintf(name, sizeof(name), "dialect oracle: %s", cases[i].input);
    bool valid =
        error == SHELL_OK && fast.count == cases[i].count &&
        fast.cmds[0].type == cases[i].first_type &&
        (cases[i].count < 2 || fast.cmds[1].type == cases[i].second_type) &&
        ranges_agree && graph_error == SHELL_DEP_OK &&
        graph_commands == cases[i].graph_count;
    if (!valid)
      printf("    oracle details: error=%d fast=%u graph_error=%d graph=%u\n",
             error, fast.count, graph_error, graph_commands);
    parser_test(name, valid);
    shell_command_infos_free(infos, info_count);
    shell_commands_free(commands, command_count);
  }

  static const char *strict_errors[] = {"echo 'x", "echo \"x", "$(("};
  for (size_t i = 0; i < sizeof(strict_errors) / sizeof(strict_errors[0]);
       i++) {
    shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    shell_parse_result_t result = {0};
    shell_error_t error = shell_parse_fast(
        strict_errors[i], strlen(strict_errors[i]), &strict, &result);
    parser_test("strict dialect rejects incomplete syntax",
                error == SHELL_EPARSE && result.status == SHELL_STATUS_ERROR);
  }

  const char non_ascii[] = "echo \xC3\xA9";
  shell_parse_result_t result = {0};
  shell_error_t error =
      shell_parse_fast(non_ascii, sizeof(non_ascii) - 1, NULL, &result);
  parser_test("fast parser preserves non-ASCII word text",
              error == SHELL_OK && result.count == 1);
  shell_command_t *commands = NULL;
  size_t command_count = 0;
  parser_test("full tokenizer preserves non-ASCII word text",
              shell_tokenize_commands(non_ascii, strlen(non_ascii), &commands,
                                      &command_count) == SHELL_TOKENIZE_OK &&
                  commands != NULL && command_count == 1);
  shell_commands_free(commands, command_count);
}

/* --- large and complex tests --- */

typedef struct {
  const char *name;
  const char *input;
  uint32_t count;
  uint32_t feature_index;
  uint32_t features;
} parser_complex_case_t;

static void parser_test_complex_case_matrix(void) {
  printf("\n--- Layer 3: Complex Inputs ---\n");
  static const parser_complex_case_t cases[] = {
      {"find pipeline",
       "find . -name '*.txt' -type f | grep -v test | sort | "
       "uniq -c | head -20",
       5, 0, 0},
      {"conditional sequence",
       "if [ -f config ]; then source config && echo loaded; else echo "
       "missing; fi",
       4, 0, 0},
      {"substitution and boolean operators",
       "count=$(ls *.log 2>/dev/null | wc -l) && [ $count -gt 0 ] || echo "
       "'no files'",
       3, 0, SHELL_FEAT_SUBSHELL | SHELL_FEAT_GLOBS},
      {"nested substitution and arithmetic", "echo $(( $(date +%s) + 3600 ))",
       1, 0, SHELL_FEAT_SUBSHELL | SHELL_FEAT_ARITH},
      {"parameter expansion forms", "echo ${var:-default} ${var:=assigned}", 1,
       0, SHELL_FEAT_VARS},
      {"long feature interaction",
       "echo \"Processing ${files[@]} at $(date +%T)...\" && for f in *.log; "
       "do grep ERROR $f >> errors.txt; done",
       4, 0, SHELL_FEAT_VARS | SHELL_FEAT_SUBSHELL},
      {"mixed control flow and pipeline",
       "if [ -f ~/.bashrc ]; then source ~/.bashrc; fi && export "
       "PATH=\"$HOME/bin:$PATH\" && find . -name '*.c' -exec gcc -o {} {} "
       "\\; | grep -v 'Permission denied' || echo 'Build failed'",
       6, 0, 0},
      {"array loop and substitutions",
       "arr=($(ls *.txt | sort)) && for f in \"${arr[@]}\"; do count=$(wc -l "
       "< \"$f\"); echo \"$f: $count lines\"; done | tee report.txt",
       6, 0, SHELL_FEAT_SUBSHELL},
      {"newline separators", "cmd1\ncmd2\ncmd3", 3, 0, 0},
      {"mixed whitespace and operators",
       "  cmd1  \t  |  \n  cmd2  \t  ;  \n  cmd3  ", 3, 0, 0},
      {"function definition", "function foo { echo hello; }", 2, 0, 0},
      {"function definition shorthand", "foo() { cat $1; }", 2, 0, 0},
      {"C-style loop", "for ((i=0; i<10; i++)); do echo $i; done", 3, 1,
       SHELL_FEAT_VARS},
      {"for loop expansion", "for f in *.txt; do wc -l $f; done", 3, 1,
       SHELL_FEAT_VARS},
      {"while loop redirection",
       "while IFS= read -r line; do echo $line; done < file", 3, 1,
       SHELL_FEAT_VARS},
      {"mixed composition operators", "a && b || c | d ; e && f || g | h", 8, 0,
       0},
      {"command group", "{ a; b; c; }", 3, 0, 0},
      {"build loop", "for f in *.c; do gcc -o ${f%.c} $f; done", 3, 1,
       SHELL_FEAT_VARS},
      {"substitution followed by cleanup",
       "tar czf backup.tar.gz $(find . -name '*.log') && rm *.log", 2, 0,
       SHELL_FEAT_SUBSHELL},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t result;
    shell_error_t error =
        shell_parse_fast(cases[i].input, strlen(cases[i].input), NULL, &result);
    bool valid = error == SHELL_OK && result.status == SHELL_STATUS_OK &&
                 result.count == cases[i].count;
    if (valid && cases[i].features != 0)
      valid = cases[i].feature_index < result.count &&
              (result.cmds[cases[i].feature_index].features &
               cases[i].features) == cases[i].features;
    if (!valid)
      printf("    %s: input='%s', error=%d status=%u count=%u expected=%u\n",
             cases[i].name, cases[i].input, error, result.status, result.count,
             cases[i].count);
    parser_test(cases[i].name, valid);
  }
}

static void parser_test_strict_mode(void) {
  printf("\n--- Strict Mode ---\n");

  static const struct {
    const char *name;
    const char *input;
    bool strict;
    shell_error_t expected_error;
  } cases[] = {
      {"strict rejects unterminated single quote", "echo 'unclosed", true,
       SHELL_EPARSE},
      {"strict rejects unterminated double quote", "echo \"unclosed", true,
       SHELL_EPARSE},
      {"strict rejects unterminated backtick", "echo `unclosed", true,
       SHELL_EPARSE},
      {"strict rejects empty unterminated arithmetic", "$((", true,
       SHELL_EPARSE},
      {"strict rejects unterminated arithmetic expression", "$((i++", true,
       SHELL_EPARSE},
      {"strict rejects unterminated arithmetic command", "((i++", true,
       SHELL_EPARSE},
      {"strict accepts closed arithmetic expression", "$((i++))", true,
       SHELL_OK},
      {"strict accepts closed arithmetic command", "((i++))", true, SHELL_OK},
      {"strict rejects bare opening brace command", "foo; {", true,
       SHELL_EPARSE},
      {"strict rejects bare closing brace command", "foo; }", true,
       SHELL_EPARSE},
      {"strict rejects unmatched pipeline closer", "foo | )", true,
       SHELL_EPARSE},
      {"strict rejects brace argument as group", "echo { foo; }", true,
       SHELL_EPARSE},
      {"strict rejects subshell argument", "echo (foo)", true, SHELL_EPARSE},
      {"strict rejects arithmetic argument", "echo ((1))", true, SHELL_EPARSE},
      {"strict preserves literal braces", "echo { foo", true, SHELL_OK},
      {"strict preserves literal closer", "echo }", true, SHELL_OK},
      {"strict accepts nested group extension", "{( echo )}", true, SHELL_OK},
      {"permissive accepts unterminated single quote", "echo 'unclosed", false,
       SHELL_OK},
      {"permissive accepts unterminated double quote", "echo \"unclosed", false,
       SHELL_OK},
      {"permissive accepts unterminated backtick", "echo `unclosed", false,
       SHELL_OK},
      {"strict accepts closed single quote", "echo 'valid'", true, SHELL_OK},
      {"strict accepts closed double quote", "echo \"valid\"", true, SHELL_OK},
      {"strict accepts spaces in single quotes", "echo 'hello world'", true,
       SHELL_OK},
      {"strict accepts escaped double quotes",
       "echo \"a \\\"quoted\\\" string\"", true, SHELL_OK},
      {"strict accepts closed backtick in double quotes", "echo \"`date`\"",
       true, SHELL_OK},
      {"strict ignores backtick in single quotes", "echo '`'", true, SHELL_OK},
  };
  shell_limits_t limits = {.max_subcommands = 64, .strict_mode = false};

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t result;
    limits.strict_mode = cases[i].strict;
    shell_error_t error = shell_parse_fast(
        cases[i].input, strlen(cases[i].input), &limits, &result);
    bool valid = error == cases[i].expected_error;
    if (cases[i].expected_error == SHELL_OK)
      valid = valid && result.status == SHELL_STATUS_OK && result.count == 1;
    parser_test(cases[i].name, valid);
  }

  shell_parse_result_t arithmetic_after_separator = {0};
  limits.strict_mode = true;
  parser_test("strict accepts arithmetic command after separator",
              shell_parse_fast("foo; ((1))", strlen("foo; ((1))"), &limits,
                               &arithmetic_after_separator) == SHELL_OK &&
                  arithmetic_after_separator.status == SHELL_STATUS_OK &&
                  arithmetic_after_separator.count == 2);
}

static void parser_test_strict_heredoc_completion(void) {
  printf("\n--- Strict Heredoc Completion ---\n");
  static const char *const incomplete[] = {
      "cat <<EOF\nbody\n",
      "cat <<-'EOF'\r\n\tbody\r\n",
      "cat <<A <<B\none\nA\n",
  };
  shell_limits_t limits = {.max_subcommands = 64, .strict_mode = true};
  bool valid = true;
  for (size_t i = 0; i < sizeof(incomplete) / sizeof(incomplete[0]); i++) {
    shell_parse_result_t result = {0};
    valid = valid &&
            shell_parse_fast(incomplete[i], strlen(incomplete[i]), &limits,
                             &result) == SHELL_EPARSE &&
            result.status == SHELL_STATUS_ERROR;
    limits.strict_mode = false;
    memset(&result, 0, sizeof(result));
    valid = valid && shell_parse_fast(incomplete[i], strlen(incomplete[i]),
                                      &limits, &result) == SHELL_OK;
    limits.strict_mode = true;
  }
  shell_parse_result_t malformed = {0};
  valid = valid &&
          shell_parse_fast("cat <<\n", strlen("cat <<\n"), &limits,
                           &malformed) == SHELL_EPARSE &&
          malformed.status == SHELL_STATUS_ERROR;

  char capacity[SHELL_MAX_SUBCOMMANDS * 16 + 1] = {0};
  size_t used = 0;
  for (uint32_t i = 0; i <= SHELL_MAX_SUBCOMMANDS; i++)
    used += (size_t)snprintf(capacity + used, sizeof(capacity) - used,
                             "cat <<E\nx\nE\n");
  shell_limits_t permissive = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                               .strict_mode = false};
  memset(&malformed, 0, sizeof(malformed));
  valid = valid &&
          shell_parse_fast(capacity, used, &permissive, &malformed) ==
              SHELL_ETRUNC &&
          malformed.status == SHELL_STATUS_TRUNCATED;

  static const char complete[] = "cat <<A <<-'B'\r\n"
                                 "one\r\n"
                                 "A\n"
                                 "\ttwo\r\n"
                                 "\tB\r\n";
  shell_parse_result_t result = {0};
  valid = valid &&
          shell_parse_fast(complete, sizeof(complete) - 1, &limits, &result) ==
              SHELL_OK &&
          result.status == SHELL_STATUS_OK;
  static const char ansi_complete[] = "cat <<$'EO\\x46' <<-$'B'\r\n"
                                      "one\r\n"
                                      "EOF\n"
                                      "\ttwo\r\n"
                                      "\tB\r\n";
  memset(&result, 0, sizeof(result));
  valid = valid &&
          shell_parse_fast(ansi_complete, sizeof(ansi_complete) - 1, &limits,
                           &result) == SHELL_OK &&
          result.status == SHELL_STATUS_OK;
  parser_test("Strict mode validates quoted, tab-stripped heredoc terminators",
              valid);
}

static void parser_test_nested_heredoc_rejection(void) {
  printf("\n--- Nested Heredoc Dialect Boundary ---\n");
  static const char *cases[] = {
      "echo $(cat <<EOF\nbody\nEOF)",
      "echo $(cat <<'EOF'\n$(id)\nEOF) && pwd",
      "cat <(cat <<EOF\nbody\nEOF)",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    for (int strict = 0; strict <= 1; strict++) {
      shell_limits_t limits = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                               .strict_mode = strict != 0};
      shell_parse_result_t result = {0};
      shell_error_t error =
          shell_parse_fast(cases[i], strlen(cases[i]), &limits, &result);
      char name[96];
      snprintf(name, sizeof(name), "%s nested heredoc rejected (%s)",
               strict ? "strict" : "permissive", cases[i]);
      parser_test(name, error == SHELL_EPARSE &&
                            result.status == SHELL_STATUS_ERROR &&
                            result.count == 0);
    }
  }

  static const char *const valid_cases[] = {
      "echo $(cat <<EOF\n)\nEOF\n)",
      "echo $(cat <<E'OF'\n)\nEOF\n)",
      "cat <(cat <<EOF\n)\nEOF\n)",
  };
  for (size_t i = 0; i < sizeof(valid_cases) / sizeof(valid_cases[0]); i++) {
    shell_limits_t limits = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    shell_parse_result_t result = {0};
    shell_error_t error = shell_parse_fast(
        valid_cases[i], strlen(valid_cases[i]), &limits, &result);
    char name[96];
    snprintf(name, sizeof(name), "nested heredoc accepted (%s)",
             valid_cases[i]);
    parser_test(name, error == SHELL_OK && result.status == SHELL_STATUS_OK &&
                          result.count == 1);
  }
}

static bool parser_make_nested_heredoc_substitution(char *command,
                                                    size_t capacity,
                                                    bool process_substitution) {
  int written = snprintf(command, capacity,
                         process_substitution ? "cat <(cat" : "echo $(cat");
  if (written < 0 || (size_t)written >= capacity)
    return false;
  size_t used = (size_t)written;
  for (uint32_t i = 0; i < 9; i++) {
    written = snprintf(command + used, capacity - used, " <<H%u", i);
    if (written < 0 || (size_t)written >= capacity - used)
      return false;
    used += (size_t)written;
  }
  written = snprintf(command + used, capacity - used, "\n");
  if (written < 0 || (size_t)written >= capacity - used)
    return false;
  used += (size_t)written;
  for (uint32_t i = 0; i < 9; i++) {
    written = snprintf(command + used, capacity - used, "body%u\nH%u\n", i, i);
    if (written < 0 || (size_t)written >= capacity - used)
      return false;
    used += (size_t)written;
  }
  written = snprintf(command + used, capacity - used, ")");
  return written >= 0 && (size_t)written < capacity - used;
}

static void parser_test_substitution_comment_and_heredoc_capacity(void) {
  printf("\n--- Substitution Comment and Heredoc Capacity ---\n");
  shell_limits_t limits = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                           .strict_mode = true};
  static const struct {
    const char *name;
    const char *input;
    shell_error_t expected;
  } comment_cases[] = {
      {"commented command-substitution closer is not syntax",
       "echo $(printf value # )", SHELL_EPARSE},
      {"commented process-substitution closer is not syntax",
       "cat <(printf value # )", SHELL_EPARSE},
      {"command substitution resumes after a comment",
       "echo $(printf value # )\nprintf done)", SHELL_OK},
      {"quoted comment text remains part of a substitution",
       "echo $(printf '# )')", SHELL_OK},
      {"escaped comment and parenthesis remain literal",
       "echo $(printf \\#\\) )", SHELL_OK},
  };
  for (size_t i = 0; i < sizeof(comment_cases) / sizeof(comment_cases[0]);
       i++) {
    shell_parse_result_t result = {0};
    shell_error_t error =
        shell_parse_fast(comment_cases[i].input, strlen(comment_cases[i].input),
                         &limits, &result);
    parser_test(comment_cases[i].name,
                error == comment_cases[i].expected &&
                    (error != SHELL_OK ||
                     (result.status == SHELL_STATUS_OK && result.count == 1)));
  }

  for (int process_substitution = 0; process_substitution <= 1;
       process_substitution++) {
    char command[512];
    shell_parse_result_t result = {0};
    bool built = parser_make_nested_heredoc_substitution(
        command, sizeof(command), process_substitution != 0);
    shell_error_t error =
        built ? shell_parse_fast(command, strlen(command), &limits, &result)
              : SHELL_EPARSE;
    parser_test(process_substitution
                    ? "nested process substitution accepts nine heredocs"
                    : "nested command substitution accepts nine heredocs",
                built && error == SHELL_OK &&
                    result.status == SHELL_STATUS_OK && result.count == 1);
  }
}

static void parser_test_source_scanner_contract(void) {
  printf("\n--- Shared Source Scanner Contract ---\n");
  static const char lines[] = "one\r\ntwo\nlast";
  parser_test(
      "source scanner retains CR before LF and recognizes final physical lines",
      shell_source_line_end(lines, sizeof(lines) - 1, 0) == 4 &&
          shell_source_next_line(lines, sizeof(lines) - 1, 0) == 5 &&
          shell_source_line_end(lines, sizeof(lines) - 1, 5) == 8 &&
          shell_source_next_line(lines, sizeof(lines) - 1, 9) ==
              sizeof(lines) - 1);

  parser_test("source scanner uses logical shell-word comment boundaries",
              shell_source_comment_starts('#', true) &&
                  !shell_source_comment_starts('#', false) &&
                  !shell_source_comment_starts('x', true));

  static const char quoted[] = "\"one \\\"two\\\"\"";
  parser_test(
      "source scanner skips quoted text and quoted escapes",
      shell_source_skip_quoted_text(quoted, sizeof(quoted) - 1, 0, '"') ==
              sizeof(quoted) - 1 &&
          shell_source_skip_quoted_text("'unfinished", 11, 0, '\'') == 11);

  shell_source_pending_heredoc_t pending = {0};
  size_t position = 0;
  static const char delimiter[] = "- \t\"E\"'O'\\F rest";
  bool parsed = shell_source_parse_heredoc_delimiter(
      delimiter, sizeof(delimiter) - 1, &position, &pending);
  parser_test(
      "source scanner decodes quoted and tab-stripped heredoc delimiters",
      parsed && pending.strip_tabs && position < sizeof(delimiter) - 1 &&
          shell_source_line_is_heredoc_delimiter("\tEOF\n", 5, 0, &pending) &&
          !shell_source_line_is_heredoc_delimiter("\tEOF\r\n", 6, 0,
                                                  &pending) &&
          !shell_source_line_is_heredoc_delimiter("\tEOG\n", 5, 0, &pending));
  position = 0;
  static const char escaped_delimiter[] = "\"E\\\"F\"";
  static const char retained_backslash_delimiter[] = "\"E\\qF\"";
  static const char empty_delimiter[] = "''";
  shell_source_pending_heredoc_t escaped_pending = {0};
  shell_source_pending_heredoc_t retained_backslash_pending = {0};
  shell_source_pending_heredoc_t empty_pending = {0};
  bool escaped_parsed = shell_source_parse_heredoc_delimiter(
      escaped_delimiter, sizeof(escaped_delimiter) - 1, &position,
      &escaped_pending);
  position = 0;
  bool retained_backslash_parsed = shell_source_parse_heredoc_delimiter(
      retained_backslash_delimiter, sizeof(retained_backslash_delimiter) - 1,
      &position, &retained_backslash_pending);
  position = 0;
  bool empty_parsed = shell_source_parse_heredoc_delimiter(
      empty_delimiter, sizeof(empty_delimiter) - 1, &position, &empty_pending);
  parser_test(
      "source scanner handles escaped and empty delimiter bytes",
      escaped_parsed &&
          shell_source_line_is_heredoc_delimiter("E\"F\n", 4, 0,
                                                 &escaped_pending) &&
          retained_backslash_parsed &&
          shell_source_line_is_heredoc_delimiter("E\\qF\n", 5, 0,
                                                 &retained_backslash_pending) &&
          empty_parsed &&
          shell_source_line_is_heredoc_delimiter("\n", 1, 0, &empty_pending));
  position = 0;
  parser_test(
      "declaration boundary retains dangling escapes as incomplete",
      shell_source_probe_heredoc_delimiter("\\", 1, &position, &pending) ==
          SHELL_HEREDOC_WORD_INCOMPLETE);
  static const char ansi_delimiter[] = "$'EO\\x46'";
  static const char ansi_nul_delimiter[] = "$'E\\0F'";
  static const char ansi_nul_suffix[] = "$'E\\0F'X$'Y\\0Z'W";
  shell_source_pending_heredoc_t ansi_pending = {0};
  shell_source_pending_heredoc_t ansi_nul_pending = {0};
  shell_source_pending_heredoc_t ansi_suffix_pending = {0};
  position = 0;
  bool ansi_parsed = shell_source_parse_heredoc_delimiter(
      ansi_delimiter, sizeof(ansi_delimiter) - 1, &position, &ansi_pending);
  position = 0;
  bool ansi_nul_parsed = shell_source_parse_heredoc_delimiter(
      ansi_nul_delimiter, sizeof(ansi_nul_delimiter) - 1, &position,
      &ansi_nul_pending);
  position = 0;
  bool ansi_suffix_parsed = shell_source_parse_heredoc_delimiter(
      ansi_nul_suffix, sizeof(ansi_nul_suffix) - 1, &position,
      &ansi_suffix_pending);
  parser_test("source scanner decodes ANSI-C heredoc delimiters",
              ansi_parsed &&
                  shell_source_heredoc_delimiter_is_quoted(&ansi_pending) &&
                  shell_source_line_is_heredoc_delimiter("EOF\n", 4, 0,
                                                         &ansi_pending) &&
                  ansi_nul_parsed &&
                  shell_source_line_is_heredoc_delimiter("E\n", 2, 0,
                                                         &ansi_nul_pending) &&
                  !shell_source_line_is_heredoc_delimiter("EF\n", 3, 0,
                                                          &ansi_nul_pending));
  parser_test("ANSI-C NUL truncates only its heredoc quote segment",
              ansi_suffix_parsed &&
                  shell_source_line_is_heredoc_delimiter(
                      "EXYW\n", 5, 0, &ansi_suffix_pending) &&
                  !shell_source_line_is_heredoc_delimiter(
                      "E\n", 2, 0, &ansi_suffix_pending));
  bool decoded_nul = false;
  bool locale_dependent = false;
  position = 0;
  parser_test(
      "ANSI-C NUL probe distinguishes malformed and inactive quotes",
      shell_source_ansi_c_quote_facts("$'a\\0b'", 7, &position, &decoded_nul,
                                      &locale_dependent) &&
          decoded_nul && !locale_dependent && position == 7 &&
          !shell_source_heredoc_word_has_unsupported_ansi_c(NULL, 0) &&
          !shell_source_heredoc_word_has_unsupported_ansi_c("\\$'a\\0b'", 8) &&
          !shell_source_heredoc_word_has_unsupported_ansi_c("\"$'a\\0b'\"",
                                                            9) &&
          !shell_source_heredoc_word_has_unsupported_ansi_c("'$'a\\0b''", 9) &&
          !shell_source_heredoc_word_has_unsupported_ansi_c("\\\n$'a\\0b'",
                                                            10));
  position = 0;
  parser_test("ANSI-C syntax boundary rejects an unfinished quote",
              !shell_source_ansi_c_quote_facts("$'unterminated", 14, &position,
                                               &decoded_nul,
                                               &locale_dependent));
  position = 0;
  parser_test(
      "ANSI-C Unicode facts do not conflate byte escapes with code points",
      shell_source_ansi_c_quote_facts("$'\\u00e9'", 9, &position, &decoded_nul,
                                      &locale_dependent) &&
          !decoded_nul && locale_dependent && position == 9 &&
          shell_source_heredoc_word_has_unsupported_ansi_c("$'\\u00e9'", 9) &&
          !shell_source_heredoc_word_has_unsupported_ansi_c("$'\\xE9'", 7));
  static const char suffix_source[] =
      "cat <<$'E\\0F'X\npayload\nE\nEX\nprintf done\n";
  shell_parse_result_t suffix_result = {0};
  parser_test(
      "Fast parser keeps heredoc body until concatenated delimiter",
      shell_parse_fast(suffix_source, sizeof(suffix_source) - 1, NULL,
                       &suffix_result) == SHELL_OK &&
          suffix_result.count == 3 &&
          suffix_result.cmds[2].start ==
              (uint32_t)(strstr(suffix_source, "printf done") - suffix_source));
  position = 0;
  parser_test(
      "source scanner rejects malformed heredoc delimiters",
      !shell_source_parse_heredoc_delimiter("-", 1, &position, &pending) &&
          !shell_source_parse_heredoc_delimiter("\\", 1, &position, &pending) &&
          !shell_source_parse_heredoc_delimiter("'EOF", 4, &position,
                                                &pending));

  static const char sequence[] =
      "cat <<<'not a document' <<E'OF' <<-\\D'ONE'\r\n"
      "one\r\n"
      "EOF\n"
      "\ttwo\r\n"
      "\tDONE\r\n"
      "printf retained";
  const char *first_document = strstr(sequence, "<<E'OF'");
  const char *trailing = strstr(sequence, "printf retained");
  size_t sequence_after = 0;
  bool complete = false;
  bool skipped =
      first_document != NULL && trailing != NULL &&
      shell_source_skip_heredoc_sequence(sequence, sizeof(sequence) - 1,
                                         (size_t)(first_document - sequence),
                                         &sequence_after, &complete);
  parser_test("source scanner skips FIFO mixed-quote heredoc bodies",
              skipped && complete &&
                  sequence_after == (size_t)(trailing - sequence));

  static const char *const opaque_header_cases[] = {
      "cat <<EOF \\x\nbody\nEOF\n",
      "cat <<EOF 'ignored'\nbody\nEOF\n",
      "cat <<EOF # ignored\nbody\nEOF\n",
      "cat <<EOF $((1 << 2))\nbody\nEOF\n",
      "cat <<EOF $(printf value)\nbody\nEOF\n",
      "cat <<EOF <<<word\nbody\nEOF\n",
  };
  const shell_source_pending_heredoc_t plain_pending = {.word = "EOF",
                                                        .word_length = 3};
  bool opaque_headers =
      !shell_source_heredoc_delimiter_is_quoted(&plain_pending);
  for (size_t i = 0; opaque_headers && i < sizeof(opaque_header_cases) /
                                               sizeof(opaque_header_cases[0]);
       i++) {
    size_t opaque_after = 0;
    bool opaque_complete = false;
    const char *opaque = opaque_header_cases[i];
    opaque_headers = shell_source_skip_heredoc_sequence(
        opaque, strlen(opaque), (size_t)(strstr(opaque, "<<EOF") - opaque),
        &opaque_after, &opaque_complete);
    opaque_headers =
        opaque_headers && opaque_complete && opaque_after == strlen(opaque);
  }
  parser_test(
      "source scanner keeps opaque header syntax out of heredoc matching",
      opaque_headers);

  static const char unterminated_sequence[] = "cat <<E'OF'\nbody\n";
  first_document = strstr(unterminated_sequence, "<<E'OF'");
  sequence_after = 0;
  complete = true;
  skipped = first_document != NULL &&
            shell_source_skip_heredoc_sequence(
                unterminated_sequence, sizeof(unterminated_sequence) - 1,
                (size_t)(first_document - unterminated_sequence),
                &sequence_after, &complete);
  parser_test("source scanner distinguishes incomplete heredoc bodies",
              skipped && !complete &&
                  sequence_after == sizeof(unterminated_sequence) - 1);

  static const struct {
    const char *input;
    bool balanced;
  } parentheses[] = {
      {"(plain)", true},
      {"(')')", true},
      {"(\\))", true},
      {"(# )\nprintf done)", true},
      {"(cat <<EOF\n)\nEOF\n)", true},
      {"($((1 << 2)))", true},
      {"(unterminated", false},
  };
  bool balanced_contract = true;
  for (size_t i = 0; i < sizeof(parentheses) / sizeof(parentheses[0]); i++) {
    size_t after = 0;
    bool balanced = shell_source_find_balanced_parentheses(
        parentheses[i].input, strlen(parentheses[i].input), 0, &after);
    balanced_contract = balanced_contract &&
                        balanced == parentheses[i].balanced &&
                        (!balanced || after == strlen(parentheses[i].input));
  }
  parser_test(
      "source scanner keeps nested data opaque while balancing parentheses",
      balanced_contract);

  size_t after = 0;
  parser_test(
      "source scanner balances arithmetic expansions and rejects bad starts",
      shell_source_skip_arithmetic_expansion("$((1 + $(printf 2)))", 20, 0,
                                             &after) &&
          after == 20 &&
          shell_source_skip_arithmetic_expansion(
              "$(( 'x' + 2))", strlen("$(( 'x' + 2))"), 0, &after) &&
          !shell_source_skip_arithmetic_expansion("$((1 + 2)", 10, 0, &after) &&
          !shell_source_skip_arithmetic_expansion("(1 + 2)", 7, 0, &after));
  static const char ansi_arithmetic[] = "$(( $'()' + 1 ))";
  static const char malformed_ansi_arithmetic[] = "$(( $'unterminated ))";
  parser_test("source scanner balances ANSI-C quotes in arithmetic expansions",
              shell_source_skip_arithmetic_expansion(
                  ansi_arithmetic, sizeof(ansi_arithmetic) - 1, 0, &after) &&
                  after == sizeof(ansi_arithmetic) - 1 &&
                  !shell_source_skip_arithmetic_expansion(
                      malformed_ansi_arithmetic,
                      sizeof(malformed_ansi_arithmetic) - 1, 0, &after));
  static const char continued_assignment[] = "N\\\nAME=value";
  shell_source_decoded_assignment_t assignment = {0};
  parser_test(
      "source scanner preserves assignment positions after LF continuation",
      shell_source_scan_decoded_assignment(continued_assignment,
                                           sizeof(continued_assignment) - 1,
                                           NULL, NULL, &assignment) &&
          assignment.name_length == 4 && assignment.source_delimiter &&
          assignment.equals == 6 && assignment.name_end == 6 &&
          !assignment.append);
  parser_test(
      "source scanner rejects malformed nested and direct scanner inputs",
      !shell_source_find_balanced_parentheses(NULL, 0, 0, &after) &&
          shell_source_find_balanced_parentheses("(`quoted`)", 10, 0, &after) &&
          !shell_source_find_balanced_parentheses("($((broken)", 11, 0,
                                                  &after) &&
          !shell_source_skip_arithmetic_expansion(
              "$(( $((1) ))", strlen("$(( $((1) ))"), 0, &after) &&
          !shell_source_skip_arithmetic_expansion(
              "$(( $(echo ", strlen("$(( $(echo "), 0, &after) &&
          !shell_source_find_balanced_parentheses("(cat <<\n)", 9, 0, &after) &&
          shell_source_skip_redirect_word("$((broken", 0, 9) == 9);

  static const char substitution_word[] =
      "prefix$(printf 'one; two'; printf three)suffix next";
  static const char arithmetic_word[] = "$((1 << 2)) next";
  size_t substitution_after = 0;
  size_t arithmetic_after = 0;
  size_t word_after = 0;
  bool skips_substitution = shell_source_skip_shell_word(
      substitution_word, sizeof(substitution_word) - 1, 0, &substitution_after);
  bool skips_arithmetic = shell_source_skip_shell_word(
      arithmetic_word, sizeof(arithmetic_word) - 1, 0, &arithmetic_after);
  bool rejects_null_input =
      !shell_source_skip_shell_word(NULL, 0, 0, &word_after);
  bool rejects_null_result = !shell_source_skip_shell_word(
      substitution_word, sizeof(substitution_word) - 1, 0, NULL);
  bool rejects_past_end = !shell_source_skip_shell_word(
      substitution_word, sizeof(substitution_word) - 1,
      sizeof(substitution_word), &word_after);
  bool rejects_dangling_escape =
      !shell_source_skip_shell_word("word\\", 5, 0, &word_after);
  bool rejects_unclosed_quote =
      !shell_source_skip_shell_word("'unterminated", 13, 0, &word_after);
  bool rejects_unclosed_substitution =
      !shell_source_skip_shell_word("$(printf", 8, 0, &word_after);
  bool rejects_unclosed_arithmetic =
      !shell_source_skip_shell_word("$((1 + 2)", 9, 0, &word_after);
  parser_test(
      "source scanner keeps shell words intact and rejects incomplete ones",
      skips_substitution &&
          substitution_after == sizeof(substitution_word) - sizeof(" next") &&
          skips_arithmetic &&
          arithmetic_after == sizeof(arithmetic_word) - sizeof(" next") &&
          rejects_null_input && rejects_null_result && rejects_past_end &&
          rejects_dangling_escape && rejects_unclosed_quote &&
          rejects_unclosed_substitution && rejects_unclosed_arithmetic);

  static const struct {
    const char *expansion;
    size_t trailing_word_bytes;
  } parameter_expansions[] = {
      {"${value:-left|&right}", 0},
      {"${value:-left>file}", 0},
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
      {"${array[${index}]}", 0},
      {"${#value}", 0},
      {"${##prefix}", 0},
      {"${!prefix*}", 0},
      {"${!prefix@}", 0},
      {"${10}", 0},
      {"${?}", 0},
      {"${#?}", 0},
      {"${value:-$'a|b'}", 0},
      {"${value:-$((1 | 2))}", 0},
      {"${value:-$(printf '|')}", 0},
      {"${value:-<(printf '|')}", 0},
  };
  bool parameter_contract = true;
  for (size_t i = 0;
       parameter_contract &&
       i < sizeof(parameter_expansions) / sizeof(parameter_expansions[0]);
       i++) {
    const char *expansion = parameter_expansions[i].expansion;
    size_t parameter_after = 0;
    parameter_contract =
        shell_source_skip_parameter_expansion(expansion, strlen(expansion), 0,
                                              &parameter_after) &&
        parameter_after ==
            strlen(expansion) - parameter_expansions[i].trailing_word_bytes;
  }
  parser_test(
      "source scanner keeps nested parameter words opaque",
      parameter_contract &&
          !shell_source_skip_parameter_expansion("${}", 3, 0, &after) &&
          !shell_source_skip_parameter_expansion("${VAR${SUFFIX}}", 15, 0,
                                                 &after) &&
          !shell_source_skip_parameter_expansion("${${suffix}}", 12, 0,
                                                 &after) &&
          !shell_source_skip_parameter_expansion("${VAR$SUFFIX}", 13, 0,
                                                 &after) &&
          !shell_source_skip_parameter_expansion("${VAR.suffix}", 13, 0,
                                                 &after) &&
          !shell_source_skip_parameter_expansion("${?suffix}", 10, 0, &after) &&
          !shell_source_skip_parameter_expansion("${10suffix}", 11, 0,
                                                 &after) &&
          !shell_source_skip_parameter_expansion("${array[broken}", 15, 0,
                                                 &after) &&
          !shell_source_skip_parameter_expansion("${value:-$'unterminated}", 24,
                                                 0, &after) &&
          !shell_source_skip_parameter_expansion("${value:-$(broken}", 18, 0,
                                                 &after));

  static const char *const bracket_patterns[] = {
      "[[:alpha:]]", "[[.x.]]", "[[=x=]]",   "[]a]",
      "[!ab]",       "[a\\|b]", "[[:\\|:]]",
  };
  bool bracket_contract = true;
  for (size_t i = 0; bracket_contract &&
                     i < sizeof(bracket_patterns) / sizeof(bracket_patterns[0]);
       i++) {
    const char *pattern = bracket_patterns[i];
    size_t bracket_after = 0;
    bracket_contract = shell_source_skip_glob_bracket(pattern, strlen(pattern),
                                                      0, &bracket_after) &&
                       bracket_after == strlen(pattern);
  }
  parser_test(
      "source scanner recognizes non-structural glob bracket candidates",
      bracket_contract && !shell_source_skip_glob_bracket(NULL, 0, 0, &after) &&
          !shell_source_skip_extglob(NULL, 0, 0, &after) &&
          !shell_source_skip_glob_bracket("[a b]", 5, 0, &after) &&
          !shell_source_skip_glob_bracket("[[:alpha:]", 10, 0, &after) &&
          !shell_source_skip_glob_bracket("[[:alpha", 8, 0, &after) &&
          !shell_source_skip_glob_bracket("[a|b]", 5, 0, &after) &&
          !shell_source_skip_glob_bracket("[[:|:]]", 7, 0, &after) &&
          !shell_source_skip_glob_bracket("[a&&b]", 6, 0, &after) &&
          !shell_source_skip_glob_bracket("[", 1, 0, &after));

  parser_test("source scanner keeps extglob alternatives inside one word",
              shell_source_skip_extglob("@(left|right)", 13, 0, &after) &&
                  after == 13 &&
                  shell_source_skip_extglob("prefix@(left|right)suffix", 25, 6,
                                            &after) &&
                  after == 19 &&
                  !shell_source_skip_extglob(NULL, 0, 0, &after) &&
                  !shell_source_skip_extglob("@(", 2, 0, &after) &&
                  !shell_source_skip_extglob("@(left|right", 12, 0, &after));

  static const char *const opaque_word_fragments[] = {
      "prefix${value:-left|&right}suffix next",
      "prefix@(left|right)suffix next",
      "prefix\\{left\\|right\\}suffix next",
      "prefix'[left|right]'suffix next",
  };
  bool opaque_word_contract = true;
  for (size_t i = 0;
       opaque_word_contract &&
       i < sizeof(opaque_word_fragments) / sizeof(opaque_word_fragments[0]);
       i++) {
    const char *word = opaque_word_fragments[i];
    size_t word_end = strcspn(word, " ");
    size_t word_after = 0;
    opaque_word_contract =
        shell_source_skip_shell_word(word, strlen(word), 0, &word_after) &&
        word_after == word_end &&
        shell_source_skip_redirect_word(word, 0, strlen(word)) == word_end;
  }
  parser_test(
      "source scanner preserves real shell-word fragments in word scanners",
      opaque_word_contract);

  static const char *const structural_word_fragments[] = {
      "prefix{left|right}suffix next",
      "prefix[left|right]suffix next",
  };
  bool structural_word_contract = true;
  for (size_t i = 0;
       structural_word_contract && i < sizeof(structural_word_fragments) /
                                           sizeof(structural_word_fragments[0]);
       i++) {
    const char *word = structural_word_fragments[i];
    size_t operator_at = strcspn(word, "|&;<>");
    size_t word_after = 0;
    structural_word_contract =
        shell_source_skip_shell_word(word, strlen(word), 0, &word_after) &&
        word_after == operator_at &&
        shell_source_skip_redirect_word(word, 0, strlen(word)) == operator_at;
  }
  parser_test("source scanner leaves brace and bracket operators structural",
              structural_word_contract);

  parser_test("source scanner rejects incomplete parameter words consistently",
              !shell_source_skip_shell_word("${", 2, 0, &after) &&
                  shell_source_skip_redirect_word("${", 0, 2) == 2);

  static const char escaped_arithmetic_word[] = "$((1\\+2))";
  size_t escaped_arithmetic_after = 0;
  bool skips_escaped_arithmetic = shell_source_skip_shell_word(
      escaped_arithmetic_word, sizeof(escaped_arithmetic_word) - 1, 0,
      &escaped_arithmetic_after);
  bool rejects_unclosed_process_redirect =
      shell_source_skip_redirect(">(broken", 0, sizeof(">(broken") - 1) == 0;
  bool rejects_invalid_redirect_list =
      !shell_source_redirect_list_before_group("not-a-redirect", 0, 14);
  shell_source_pending_heredoc_t missing_document;
  size_t delimiter_after = 0;
  bool parsed_delimiter = shell_source_parse_heredoc_delimiter(
      "EOF", 3, &delimiter_after, &missing_document);
  bool rejects_missing_pending_document =
      parsed_delimiter &&
      !shell_source_skip_pending_heredoc_bodies(
          "body\n", 5, 0, &missing_document, 1, &word_after) &&
      word_after == 5;
  parser_test(
      "source scanner rejects invalid redirect and document boundaries",
      skips_escaped_arithmetic &&
          escaped_arithmetic_after == sizeof(escaped_arithmetic_word) - 1 &&
          rejects_unclosed_process_redirect && rejects_invalid_redirect_list &&
          rejects_missing_pending_document);

  static const struct {
    const char *input;
    size_t expected;
  } redirect_words[] = {
      {"plain next", 5},
      {"\"two words\" > out", sizeof("\"two words\"") - 1},
      {"'two words'|next", sizeof("'two words'") - 1},
      {"`printf x`;next", sizeof("`printf x`") - 1},
      {"prefix$(printf 'a b')suffix>next",
       sizeof("prefix$(printf 'a b')suffix") - 1},
      {"$((1 << 2)) next", sizeof("$((1 << 2))") - 1},
      {"<(printf input) next", sizeof("<(printf input)") - 1},
      {"word\\ value;next", sizeof("word\\ value") - 1},
      {"# comment", 0},
      {"word#literal next", sizeof("word#literal") - 1},
  };
  bool redirect_contract = true;
  for (size_t i = 0; i < sizeof(redirect_words) / sizeof(redirect_words[0]);
       i++)
    redirect_contract =
        redirect_contract &&
        shell_source_skip_redirect_word(redirect_words[i].input, 0,
                                        strlen(redirect_words[i].input)) ==
            redirect_words[i].expected;
  parser_test("source scanner keeps complete redirect operands intact",
              redirect_contract);
}

static void parser_test_extglob_expansion_features(void) {
  for (unsigned conditional = 0; conditional < 2; ++conditional) {
    for (size_t i = 0; i < sizeof(shellsplit_test_extglob_features) /
                               sizeof(shellsplit_test_extglob_features[0]);
         ++i) {
      char source[256];
      snprintf(source, sizeof(source),
               conditional ? "[[ -n %s ]]" : "printf %s",
               shellsplit_test_extglob_features[i].word);
      shell_parse_result_t parsed = {0};
      shell_limits_t limits = SHELL_LIMITS_DEFAULT;
      limits.strict_mode = true;
      bool valid = shell_parse_fast(source, strlen(source), &limits, &parsed) ==
                   SHELL_OK;
      uint32_t features = 0;
      for (uint32_t c = 0; c < parsed.count; ++c)
        features |= parsed.cmds[c].features;
      uint32_t expected = shellsplit_test_extglob_features[i].features |
                          (conditional ? SHELL_FEAT_CONDITIONALS : 0);
      parser_test(source,
                  valid && parsed.count == 1 &&
                      (features & shellsplit_test_extglob_feature_mask) ==
                          expected);
    }
  }
}

static void parser_test_incomplete_control_delimiters(void) {
  /* Shellsplit does not model control-flow execution, but the range parser
   * must still reject unfinished compounds. Reserved terminators in a simple
   * command's argument position do not close those compounds. */
  static const char *const cases[] = {
      "if true; then printf fi",
      "while true; do printf done",
      "case item in item) printf esac",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t result = {0};
    shell_error_t error =
        shell_parse_fast(cases[i], strlen(cases[i]), NULL, &result);
    char name[96];
    snprintf(name, sizeof(name), "reject incomplete control: %s", cases[i]);
    parser_test(name,
                error == SHELL_EPARSE && result.status == SHELL_STATUS_ERROR);
  }
}

static void parser_test_fast_parser_limitations(void) {
  printf("\n--- Fast Parser Regression Tests ---\n");

  static const char high_bytes[] = {(char)0x80, (char)0x81, 'c', 'm', 'd'};
  static const char embedded_high_byte[] = {'c', 'm', 'd', (char)0x80, 'x'};
  static const char quoted_high_byte[] = {'e', 'c',  'h',       'o',
                                          ' ', '\'', (char)0xff};
  static const char arithmetic_high_byte[] = {'$',        '(', '(', 'x',
                                              (char)0xfe, ')', ')'};
  static const struct {
    const char *name;
    const char *input;
    size_t len;
    shell_status_t expected_status;
    uint32_t expected_count;
  } cases[] = {
      {"reject control character",
       "\x01"
       "cmd",
       sizeof("\x01"
              "cmd") -
           1,
       SHELL_STATUS_ERROR, 0},
      {"reject multiple control characters", "\x07\x1btext",
       sizeof("\x07\x1btext") - 1, SHELL_STATUS_ERROR, 0},
      {"retain high bytes", high_bytes, sizeof(high_bytes), SHELL_STATUS_OK, 1},
      {"reject embedded control character", "cmd\x01suffix",
       sizeof("cmd\x01suffix") - 1, SHELL_STATUS_ERROR, 0},
      {"retain embedded high byte", embedded_high_byte,
       sizeof(embedded_high_byte), SHELL_STATUS_OK, 1},
      {"permissive parse retains unfinished quoted byte", quoted_high_byte,
       sizeof(quoted_high_byte), SHELL_STATUS_OK, 1},
      {"reject high byte in arithmetic", arithmetic_high_byte,
       sizeof(arithmetic_high_byte), SHELL_STATUS_ERROR, 0},
      {"accept adjacent quoted and unquoted text", "\"text \"text",
       sizeof("\"text \"text") - 1, SHELL_STATUS_OK, 1},
      {"accept keyword-shaped command fragments", "echo if if cmd",
       sizeof("echo if if cmd") - 1, SHELL_STATUS_OK, 1},
      {"reject bare separator", "|", 1, SHELL_STATUS_ERROR, 0},
      {"accept trailing backslash", "cmd\\", sizeof("cmd\\") - 1,
       SHELL_STATUS_OK, 1},
      {"reject empty parameter braces", "${}", sizeof("${}") - 1,
       SHELL_STATUS_ERROR, 0},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t result;
    shell_error_t error =
        shell_parse_fast(cases[i].input, cases[i].len, NULL, &result);
    bool valid = result.status == cases[i].expected_status &&
                 result.count == cases[i].expected_count;
    valid = valid && (cases[i].expected_status == SHELL_STATUS_OK
                          ? error == SHELL_OK
                          : error == SHELL_EPARSE);
    parser_test(cases[i].name, valid);
  }
}

/* --- FEATURE FLAGS API TESTS --- */

static uint32_t parser_feature_flags_mask(const shell_feature_flags_t *flags) {
  return (flags->has_vars ? SHELL_FEAT_VARS : 0) |
         (flags->has_globs ? SHELL_FEAT_GLOBS : 0) |
         (flags->has_subshell ? SHELL_FEAT_SUBSHELL : 0) |
         (flags->has_arith ? SHELL_FEAT_ARITH : 0) |
         (flags->has_heredoc ? SHELL_FEAT_HEREDOC : 0) |
         (flags->has_herestring ? SHELL_FEAT_HERESTRING : 0) |
         (flags->has_process_sub ? SHELL_FEAT_PROCESS_SUB : 0) |
         (flags->has_loops ? SHELL_FEAT_LOOPS : 0) |
         (flags->has_conditionals ? SHELL_FEAT_CONDITIONALS : 0) |
         (flags->has_case ? SHELL_FEAT_CASE : 0) |
         (flags->has_subshell_file ? SHELL_FEAT_SUBSHELL_FILE : 0) |
         (flags->has_pipeline ? SHELL_FEAT_PIPELINE : 0) |
         (flags->has_group ? SHELL_FEAT_GROUP : 0) |
         (flags->has_background ? SHELL_FEAT_BACKGROUND : 0);
}

static void parser_test_feature_flags(void) {
  printf("\n--- Feature Flags API ---\n");

  /* NULL is an explicit no-op convenience contract. */
  shell_feature_flags_from_bits(UINT32_MAX, NULL);

  uint32_t masks[] = {
      SHELL_FEAT_NONE,
      SHELL_FEAT_VARS,
      SHELL_FEAT_GLOBS,
      SHELL_FEAT_SUBSHELL,
      SHELL_FEAT_ARITH,
      SHELL_FEAT_HEREDOC,
      SHELL_FEAT_HERESTRING,
      SHELL_FEAT_PROCESS_SUB,
      SHELL_FEAT_LOOPS,
      SHELL_FEAT_CONDITIONALS,
      SHELL_FEAT_CASE,
      SHELL_FEAT_SUBSHELL_FILE,
      SHELL_FEAT_PIPELINE,
      SHELL_FEAT_GROUP,
      SHELL_FEAT_BACKGROUND,
      SHELL_FEAT_VARS | SHELL_FEAT_GLOBS,
      (uint32_t)((SHELL_FEAT_SUBSHELL_FILE << 1) - 1),
  };
  for (size_t i = 0; i < sizeof(masks) / sizeof(masks[0]); i++) {
    shell_feature_flags_t flags;
    shell_feature_flags_from_bits(masks[i], &flags);
    char name[80];
    snprintf(name, sizeof(name), "feature mask 0x%03x round-trips", masks[i]);
    parser_test(name, parser_feature_flags_mask(&flags) == masks[i]);
  }
}

static void parser_test_source_io_number_contract(void) {
  static const char maximum[] = "2147483647";
  static const char overflow[] = "214748364800";
  static const char maximum_redirect[] = "2147483647>out";
  static const char overflow_redirect[] = "2147483648>out";
  static const char spaced_process_output[] = "> >(cat)";
  static const char spaced_process_input[] = "< <(printf data)";
  size_t after = SIZE_MAX;
  uint32_t descriptor = UINT32_MAX;
  bool valid = shell_source_parse_io_number(NULL, 0, 0, &after, &descriptor) ==
                   SHELL_SOURCE_IO_NUMBER_NONE &&
               after == 0 && descriptor == 0;

  after = SIZE_MAX;
  descriptor = UINT32_MAX;
  valid = valid &&
          shell_source_parse_io_number("word", 0, strlen("word"), &after,
                                       &descriptor) ==
              SHELL_SOURCE_IO_NUMBER_NONE &&
          after == 0 && descriptor == 0;

  after = SIZE_MAX;
  descriptor = 0;
  valid = valid &&
          shell_source_parse_io_number(maximum, 0, sizeof(maximum) - 1, &after,
                                       &descriptor) ==
              SHELL_SOURCE_IO_NUMBER_VALID &&
          after == sizeof(maximum) - 1 && descriptor == SHELL_DEP_FD_MAX;

  after = 0;
  descriptor = 0;
  valid = valid &&
          shell_source_parse_io_number(overflow, 0, sizeof(overflow) - 1,
                                       &after, &descriptor) ==
              SHELL_SOURCE_IO_NUMBER_OVERFLOW &&
          after == sizeof(overflow) - 1 && descriptor == 0 &&
          shell_source_skip_redirect(NULL, 0, 0) == 0 &&
          shell_source_skip_redirect(overflow_redirect, 0,
                                     sizeof(overflow_redirect) - 1) == 0 &&
          shell_source_skip_redirect(maximum_redirect, 0,
                                     sizeof(maximum_redirect) - 1) ==
              sizeof(maximum_redirect) - 1 &&
          shell_source_skip_redirect(spaced_process_output, 0,
                                     sizeof(spaced_process_output) - 1) ==
              sizeof(spaced_process_output) - 1 &&
          shell_source_skip_redirect(spaced_process_input, 0,
                                     sizeof(spaced_process_input) - 1) ==
              sizeof(spaced_process_input) - 1;
  parser_test("Shared io_number parser preserves fd bounds and redirect syntax",
              valid);
}

/* Only shell syntax that actually quotes its contents may hide a list
 * operator. Exercise those boundaries, and the complementary ordinary brace
 * and bracket cases, through every public parsing surface. */
static void parser_test_word_fragment_operator_boundaries(void) {
  static const char *const opaque_word_cases[] = {
      "echo ${value:-left|&right}",          "echo ${value:-left>file}",
      "echo ${value:-left\\|right}",         "echo ${value:-'left|right'}",
      "echo ${value:-$'left|right'}",        "echo ${value:-$((1 | 2))}",
      "echo ${value:-{left|right}}",         "echo prefix@(left|right)suffix",
      "echo prefix\\{left\\|right\\}suffix", "echo prefix'[left|right]'suffix",
  };
  static const char *const escaped_cases[] = {
      "echo \\|",
      "echo \\&",
      "echo \\;",
      "echo \\|\\&",
  };
  shell_limits_t strict = {
      .max_subcommands = SHELL_MAX_SUBCOMMANDS,
      .strict_mode = true,
  };
  bool valid = true;
  for (size_t set = 0; set < 2; set++) {
    const char *const *cases = set == 0 ? opaque_word_cases : escaped_cases;
    size_t count =
        set == 0 ? sizeof(opaque_word_cases) / sizeof(opaque_word_cases[0])
                 : sizeof(escaped_cases) / sizeof(escaped_cases[0]);
    for (size_t i = 0; valid && i < count; i++) {
      const char *input = cases[i];
      shell_parse_result_t fast = {0};
      shell_command_t *commands = NULL;
      size_t command_count = 0;
      shell_processed_commands_t processed = {0};
      shell_dep_graph_t graph = {0};
      valid =
          shell_source_skip_shell_word(input, strlen(input), 5, &(size_t){0}) &&
          shell_parse_fast(input, strlen(input), &strict, &fast) == SHELL_OK &&
          fast.count == 1 && fast.cmds[0].type == SHELL_TYPE_SIMPLE &&
          fast.cmds[0].pipe_input_mode == SHELL_PIPE_MODE_NONE &&
          shell_tokenize_commands(input, strlen(input), &commands,
                                  &command_count) == SHELL_TOKENIZE_OK &&
          command_count == 1 &&
          shell_process_commands(input, strlen(input), NULL, &processed) ==
              SHELL_PROCESS_OK &&
          processed.command_count == 1 &&
          !processed.commands[0].has_pipe_input &&
          !processed.commands[0].has_pipe_output &&
          shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
              SHELL_DEP_OK &&
          graph.edge_count == 3 && shell_dep_graph_validate(&graph).valid;
      shell_commands_free(commands, command_count);
      shell_processed_commands_free(&processed);
    }
  }
  parser_test(
      "Quoted and expansion word fragments keep operators out of list parsing",
      valid);

  static const char *const structural_word_cases[] = {
      "echo prefix{left|right}suffix",
      "echo [left|right]",
      "echo [[:alpha:]|]",
      "echo []|]",
      "echo [!left|right]",
  };
  bool structural = true;
  for (size_t i = 0; structural && i < sizeof(structural_word_cases) /
                                           sizeof(structural_word_cases[0]);
       i++) {
    const char *input = structural_word_cases[i];
    shell_parse_result_t fast = {0};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    uint32_t pipe_count = 0;
    structural =
        shell_parse_fast(input, strlen(input), &strict, &fast) == SHELL_OK &&
        fast.count == 2 && fast.cmds[1].type == SHELL_TYPE_PIPELINE &&
        fast.cmds[1].pipe_input_mode == SHELL_PIPE_MODE_STDOUT &&
        shell_tokenize_commands(input, strlen(input), &commands,
                                &command_count) == SHELL_TOKENIZE_OK &&
        command_count == 2 &&
        shell_process_commands(input, strlen(input), NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == 2 && processed.commands[0].has_pipe_output &&
        processed.commands[1].has_pipe_input &&
        shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    for (uint32_t edge = 0; structural && edge < graph.edge_count; edge++)
      pipe_count += graph.edges[edge].type == SHELL_EDGE_PIPE;
    structural = structural && pipe_count == 1;
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
  }
  parser_test("Brace and bracket text leave list operators structural",
              structural);

  static const struct {
    const char *input;
    uint32_t commands;
    uint32_t pipes;
  } redirect_fragment_cases[] = {
      {"printf x >out@(left|right)", 1, 0},
      /* An explicit stdout redirect wins over the syntactic pipeline's data
       * route, so the graph correctly has no PIPE relation. */
      {"printf x >out{left|right}", 2, 0},
      {"printf x >out[left|right]", 2, 0},
  };
  bool redirect_fragments = true;
  for (size_t i = 0;
       redirect_fragments &&
       i < sizeof(redirect_fragment_cases) / sizeof(redirect_fragment_cases[0]);
       i++) {
    const char *input = redirect_fragment_cases[i].input;
    shell_parse_result_t fast = {0};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    uint32_t pipe_count = 0;
    redirect_fragments =
        shell_parse_fast(input, strlen(input), &strict, &fast) == SHELL_OK &&
        fast.count == redirect_fragment_cases[i].commands &&
        shell_tokenize_commands(input, strlen(input), &commands,
                                &command_count) == SHELL_TOKENIZE_OK &&
        command_count == redirect_fragment_cases[i].commands &&
        shell_process_commands(input, strlen(input), NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == redirect_fragment_cases[i].commands &&
        shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    for (uint32_t edge = 0; redirect_fragments && edge < graph.edge_count;
         edge++)
      pipe_count += graph.edges[edge].type == SHELL_EDGE_PIPE;
    redirect_fragments =
        redirect_fragments && pipe_count == redirect_fragment_cases[i].pipes;
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
  }
  parser_test("Redirect operands preserve only true shell-word syntax",
              redirect_fragments);

  const shell_process_limits_t short_string = {
      .max_string_bytes = 1,
      .max_total_bytes = SIZE_MAX,
  };
  const shell_process_limits_t short_total = {
      .max_string_bytes = SIZE_MAX,
      .max_total_bytes = 1,
  };
  shell_processed_commands_t limited = {0};
  bool limits_are_atomic =
      shell_process_commands("echo value", strlen("echo value"), &short_string,
                             &limited) == SHELL_PROCESS_EOUTPUT_LIMIT &&
      limited.commands == NULL && limited.command_count == 0 &&
      shell_process_commands("echo one; echo two", strlen("echo one; echo two"),
                             &short_total,
                             &limited) == SHELL_PROCESS_EOUTPUT_LIMIT &&
      limited.commands == NULL && limited.command_count == 0;
  parser_test("Processed command limits clear partial output",
              limits_are_atomic);

  static const char *const malformed_word_cases[] = {
      "echo ${}",
      "echo ${VAR${SUFFIX}}",
      "echo ${${suffix}}",
      "echo ${value:-$'unterminated}",
      "echo ${value:-$(broken}",
  };
  bool rejects_malformed = true;
  for (size_t i = 0;
       rejects_malformed &&
       i < sizeof(malformed_word_cases) / sizeof(malformed_word_cases[0]);
       i++) {
    shell_parse_result_t parsed = {0};
    shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
    size_t command_count = SIZE_MAX;
    rejects_malformed =
        shell_parse_fast(malformed_word_cases[i],
                         strlen(malformed_word_cases[i]), &strict,
                         &parsed) == SHELL_EPARSE &&
        parsed.status == SHELL_STATUS_ERROR &&
        shell_tokenize_commands(malformed_word_cases[i],
                                strlen(malformed_word_cases[i]), &commands,
                                &command_count) == SHELL_TOKENIZE_EPARSE &&
        commands == NULL && command_count == 0;
  }
  parser_test("Word fragments reject incomplete structural subsyntax",
              rejects_malformed);
}

/* A pipe after a `>` is a pipeline operator only when the `>` is a word byte:
 * an unescaped `>|` is the clobber redirection and consumes the pipe. */
static void parser_test_pipe_after_escaped_redirect_byte(void) {
  static const struct {
    const char *source;
    uint32_t commands;
  } cases[] = {
      {"x \\>| y", 2},   {"x \\>|y", 2}, {"x \\>|\\>| y", 3},
      {"x \\\\>| y", 1}, {"x >| y", 1},  {"x 2>| y", 1},
  };
  bool valid = true;
  for (size_t strict = 0; strict < 2; strict++)
    for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
      const char *source = cases[i].source;
      shell_limits_t limits = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                               .strict_mode = strict != 0};
      shell_parse_result_t fast = {0};
      shell_processed_commands_t processed = {0};
      valid = shell_parse_fast(source, strlen(source), &limits, &fast) ==
                  SHELL_OK &&
              fast.count == cases[i].commands &&
              (cases[i].commands == 1 ||
               fast.cmds[1].type == SHELL_TYPE_PIPELINE) &&
              shell_process_commands(source, strlen(source), NULL,
                                     &processed) == SHELL_PROCESS_OK &&
              processed.command_count == cases[i].commands &&
              processed.commands[0].has_pipe_output == (cases[i].commands > 1);
      shell_processed_commands_free(&processed);
    }
  parser_test(
      "An escaped redirection byte leaves the following pipe an operator",
      valid);
}

/* A backslash before a newline continues the line only when it is not itself
 * escaped: in `a\\<LF>}` the pair is a backslash word byte and the brace closes
 * the group, while in `a\<LF>}` and `a\\\<LF>}` the brace joins the word. */
static void parser_test_escaped_backslash_before_newline(void) {
  static const struct {
    const char *source;
    bool complete;
  } cases[] = {
      {"{ echo a\\\\\n}", true},    {"{ echo a\\\\\\\\\n}", true},
      {"{ echo a;\\\n}", true},     {"{ echo a\\\n}", false},
      {"{ echo a\\\\\\\n}", false},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    static shell_source_result_t draft;
    shell_parse_result_t fast = {0};
    valid = (shell_parse_draft(source, strlen(source), NULL, &draft) ==
             SHELL_SOURCE_COMPLETE) == cases[i].complete &&
            (shell_parse_fast(source, strlen(source), NULL, &fast) ==
             SHELL_OK) == cases[i].complete;
  }
  parser_test("A newline after an escaped backslash does not continue the line",
              valid);
}

/* `\x{` in an ANSI-C string takes every hex digit up to an optional closing
 * brace and keeps the low byte, as Bash does; a plain `\x` takes at most two
 * digits and stays literal when none follow. */
static void parser_test_ansi_c_braced_hex_escape(void) {
  static const struct {
    const char *word;
    const char *expected;
    size_t length;
  } cases[] = {
      {"$'\\x{41}'", "A", 1},     {"$'\\x{414243}'", "C", 1},
      {"$'\\x{000041}'", "A", 1}, {"$'\\x{100}'", "\0", 1},
      {"$'\\x{4}1'", "\0041", 2}, {"$'\\x{4g}'", "\004g}", 3},
      {"$'\\x{41'", "A", 1},      {"$'\\x{41}}'", "A}", 2},
      {"$'\\x{}'", "\0", 1},      {"$'\\x{ 41}'", "\0 41}", 5},
      {"$'\\x41'", "A", 1},       {"$'\\x414'", "A4", 2},
      {"$'\\xg'", "\\xg", 3},     {"$'\\x'", "\\x", 2},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    char *decoded = NULL;
    size_t length = 0;
    valid = shell_decode_word(cases[i].word, strlen(cases[i].word), &decoded,
                              &length) == SHELL_PROCESS_OK &&
            length == cases[i].length &&
            memcmp(decoded, cases[i].expected, length) == 0;
    free(decoded);
  }
  parser_test("ANSI-C braced hex escapes take every digit up to the brace",
              valid);
}

/* Zero-length input is invalid input for the structured processor, while
 * whitespace, comments and escaped line endings are valid blank source. */
static void parser_test_structured_blank_and_empty_source(void) {
  static const struct {
    const char *source;
    shell_process_status_t status;
  } cases[] = {
      {"", SHELL_PROCESS_EINPUT},
      {" \t\n", SHELL_PROCESS_BLANK},
      {"# comment", SHELL_PROCESS_BLANK},
      {"\\\n", SHELL_PROCESS_BLANK},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_processed_commands_t processed = {0};
    valid = shell_process_commands(cases[i].source, strlen(cases[i].source),
                                   NULL, &processed) == cases[i].status &&
            processed.commands == NULL && processed.command_count == 0;
    shell_processed_commands_free(&processed);
  }
  parser_test(
      "The structured processor reports empty input as invalid, not blank",
      valid);
}

/* `then`, `elif`, `else` and `fi` end the list of an `if` right after a
 * compound command, as after a simple one: `if { :; } then :; fi`. A redirect
 * on the compound makes Bash read them as words, and outside an `if` they are
 * a syntax error. */
static void parser_test_if_keyword_after_compound(void) {
  static const struct {
    const char *source;
    bool valid;
  } cases[] = {
      {"if { :; } then :; fi", true},
      {"if true; then { :; } fi", true},
      {"if true; then ( :; ) fi", true},
      {"if false; then :; elif { :; } then :; fi", true},
      {"if true; then :; else { :; } fi", true},
      {"if [[ 1 ]] then echo hi; fi", true},
      {"if (( 1 )) then echo hi; fi", true},
      {"if [[ 1 ]]; then [[ 1 ]] fi", true},
      {"if [[ 1 ]] then [[ 2 ]] elif (( 3 )) then :; else [[ 4 ]] fi", true},
      {"if [[ 1 ]] then { :; } fi", true},
      {"if true; then if true; then :; fi fi", true},
      {"{ :; } fi", false},
      {"{ :; } then", false},
      {"[[ 1 ]] then", false},
      {"if true; then ( :; ) | cat fi", false},
      {"if { :; } > f then :; fi", false},
      {"if true; then { :; } > f fi", false},
      {"if [[ 1 ]] > f then :; fi", false},
      {"if true; then { :; } if true; then :; fi; fi", false},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    static shell_source_result_t draft;
    shell_processed_commands_t processed = {0};
    bool accepted = shell_parse_draft(source, strlen(source), NULL, &draft) ==
                        SHELL_SOURCE_COMPLETE &&
                    shell_process_commands(source, strlen(source), NULL,
                                           &processed) == SHELL_PROCESS_OK;
    shell_processed_commands_free(&processed);
    valid = accepted == cases[i].valid;
    if (!valid)
      fprintf(stderr, "%s: expected %s\n", source,
              cases[i].valid ? "accepted" : "rejected");
  }
  parser_test("An if keyword after a compound command ends the list", valid);
}

/* A `then`, `elif` or `else` right after a compound command opens command
 * position as it does after a simple command, so the unsupported syntax that
 * follows is refused there too: `if { :; } then declare -a x; fi`. */
static void parser_test_unsupported_syntax_after_compound_keyword(void) {
  static const struct {
    const char *source;
    bool accepted;
  } cases[] = {
      {"if { :; } then echo ok; fi", true},
      {"if [[ 1 ]] then x=1; elif (( 1 )) then y=2; fi", true},
      {"if { :; } then declare -a x; fi", false},
      {"if ( : ) then coproc cat; fi", false},
      {"if [[ 1 ]] then while true; do :; done; fi", false},
      {"if (( 1 )) then for i in a; do :; done; fi", false},
      {"if { :; } then f() { :; }; fi", false},
      {"if { :; } then case x in x) :;; esac; fi", false},
      {"if { :; } then :; elif { :; } then declare -a y; fi", false},
      {"if { :; } then :; else [[ 1 ]] fi", true},
      {"if { :; } then :; elif { :; } then :; else coproc c; fi", false},
      {"if true; then if { :; } then :; fi declare -a x; fi", false},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    shell_processed_commands_t processed = {0};
    bool accepted = shell_process_commands(source, strlen(source), NULL,
                                           &processed) == SHELL_PROCESS_OK;
    shell_processed_commands_free(&processed);
    valid = accepted == cases[i].accepted;
    if (!valid)
      fprintf(stderr, "%s: expected %s\n", source,
              cases[i].accepted ? "accepted" : "rejected");
  }
  parser_test("Unsupported syntax after a then following a compound is refused",
              valid);
}

/* A closing brace follows a conditional or arithmetic command directly, as it
 * follows a group; a redirect on the command makes it an ordinary word. */
static void parser_test_brace_after_conditional_command(void) {
  static const struct {
    const char *source;
    bool accepted;
  } cases[] = {
      {"{ [[ 1 ]] }", true},
      {"{ (( 1 )) }", true},
      {"{ :; [[ 1 ]] }", true},
      {"if { [[ 1 ]] } then :; fi", true},
      {"{ [[ 1 ]] } > f", true},
      {"{ time [[ 1 ]] }", true},
      {"{ ! [[ 1 ]] }", true},
      {"{ { [[ 1 ]] } }", true},
      {"if true; then { (( 1 )) } fi", true},
      {"{ [[ 1 ]] > f }", false},
      {"{ [[ 1 ]]} ", false},
      {"[[ 1 ]] }", false},
      {"{ [[ 1 ]] }}", false},
      {"{ [[ 1 ]] } fi", false},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    static shell_source_result_t draft;
    shell_processed_commands_t processed = {0};
    bool accepted = shell_parse_draft(source, strlen(source), NULL, &draft) ==
                        SHELL_SOURCE_COMPLETE &&
                    shell_process_commands(source, strlen(source), NULL,
                                           &processed) == SHELL_PROCESS_OK;
    shell_processed_commands_free(&processed);
    valid = accepted == cases[i].accepted;
    if (!valid)
      fprintf(stderr, "%s: expected %s\n", source,
              cases[i].accepted ? "accepted" : "rejected");
  }
  parser_test("A closing brace follows a conditional or arithmetic command",
              valid);
}

static void parser_test_pipeline_time_metadata(void) {
  static const struct {
    const char *source;
    uint32_t count;
    shell_pipeline_time_mode_t mode;
    uint32_t negations;
  } reserved[] = {
      {"time echo x", 1, SHELL_PIPE_TIME_DEFAULT, 0},
      {"time -p echo x | cat", 2, SHELL_PIPE_TIME_POSIX, 0},
      {"time -- echo x", 1, SHELL_PIPE_TIME_POSIX, 0},
      {"time time echo x", 1, SHELL_PIPE_TIME_DEFAULT, 0},
      {"time -p time echo x", 1, SHELL_PIPE_TIME_POSIX, 0},
      {"time time -p true", 1, SHELL_PIPE_TIME_POSIX, 0},
      {"! time ! echo x | cat", 2, SHELL_PIPE_TIME_DEFAULT, 2},
      {"time>/tmp/timing echo x", 1, SHELL_PIPE_TIME_DEFAULT, 0},
      {"time</dev/null cat", 1, SHELL_PIPE_TIME_DEFAULT, 0},
      {"time -p>/tmp/timing true", 1, SHELL_PIPE_TIME_POSIX, 0},
      {"time -->/tmp/timing true", 1, SHELL_PIPE_TIME_POSIX, 0},
      {"ti\\\nme true", 1, SHELL_PIPE_TIME_DEFAULT, 0},
      {"\\\ntime true", 1, SHELL_PIPE_TIME_DEFAULT, 0},
      {"time\\\n>/tmp/timing true", 1, SHELL_PIPE_TIME_DEFAULT, 0},
      {"time", 1, SHELL_PIPE_TIME_DEFAULT, 0},
      {"time !", 1, SHELL_PIPE_TIME_DEFAULT, 1},
      {"! time", 1, SHELL_PIPE_TIME_DEFAULT, 1},
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(reserved) / sizeof(reserved[0]); i++) {
    shell_parse_result_t parsed = {0};
    shell_error_t status = shell_parse_fast(
        reserved[i].source, strlen(reserved[i].source), NULL, &parsed);
    bool item = status == SHELL_OK && parsed.count == reserved[i].count;
    for (uint32_t command = 0; item && command < parsed.count; command++) {
      item =
          (parsed.cmds[command].modifiers & SHELL_CMD_MOD_PIPE_TIMED) != 0 &&
          parsed.cmds[command].pipeline_time_mode == reserved[i].mode &&
          parsed.cmds[command].pipeline_negation_count == reserved[i].negations;
    }
    if (!item)
      fprintf(stderr,
              "time metadata mismatch: %s status=%d count=%u modifiers=%u "
              "mode=%u negations=%u\n",
              reserved[i].source, (int)status, parsed.count,
              parsed.count ? parsed.cmds[0].modifiers : 0,
              parsed.count ? parsed.cmds[0].pipeline_time_mode : 0,
              parsed.count ? parsed.cmds[0].pipeline_negation_count : 0);
    valid = valid && item;
  }
  parser_test("Fast parser retains Bash time pipeline metadata", valid);

  static const struct {
    const char *source;
    uint8_t kind;
  } timed_groups[] = {
      {"time { printf x; } | cat", SHELL_GROUP_BRACE},
      {"time -p (printf x; cat) | sort", SHELL_GROUP_SUBSHELL},
  };
  valid = true;
  for (size_t i = 0; i < sizeof(timed_groups) / sizeof(timed_groups[0]); i++) {
    shell_parse_result_t parsed = {0};
    bool item =
        shell_parse_fast(timed_groups[i].source, strlen(timed_groups[i].source),
                         NULL, &parsed) == SHELL_OK &&
        parsed.group_count == 1 && parsed.count >= 2 &&
        parsed.groups[0].kind == timed_groups[i].kind &&
        (parsed.groups[0].modifiers & SHELL_CMD_MOD_PIPE_TIMED) != 0 &&
        parsed.groups[0].pipeline_time_direct &&
        parsed.groups[0].pipeline_time_mode ==
            (i == 0 ? SHELL_PIPE_TIME_DEFAULT : SHELL_PIPE_TIME_POSIX) &&
        parsed.cmds[parsed.count - 1].type == SHELL_TYPE_PIPELINE &&
        parsed.cmds[parsed.count - 1].pipeline_time_mode ==
            parsed.groups[0].pipeline_time_mode;
    if (!item) {
      fprintf(stderr,
              "timed group mismatch: %s count=%u groups=%u group_mod=%u "
              "group_mode=%u last_type=%u last_mod=%u last_mode=%u\n",
              timed_groups[i].source, parsed.count, parsed.group_count,
              parsed.group_count ? parsed.groups[0].modifiers : 0,
              parsed.group_count ? parsed.groups[0].pipeline_time_mode : 0,
              parsed.count ? parsed.cmds[parsed.count - 1].type : 0,
              parsed.count ? parsed.cmds[parsed.count - 1].modifiers : 0,
              parsed.count ? parsed.cmds[parsed.count - 1].pipeline_time_mode
                           : 0);
    }
    valid = valid && item;
  }
  parser_test("Fast parser attaches time to compound pipeline roots", valid);

  const char *compound_member =
      "time printf x | { time -p cat; printf tail; } | sort";
  shell_parse_result_t compound = {0};
  valid = shell_parse_fast(compound_member, strlen(compound_member), NULL,
                           &compound) == SHELL_OK &&
          compound.count == 4 && compound.group_count == 1 &&
          compound.cmds[0].pipeline_time_mode == SHELL_PIPE_TIME_DEFAULT &&
          compound.cmds[0].pipeline_time_direct &&
          compound.groups[0].pipeline_time_mode == SHELL_PIPE_TIME_DEFAULT &&
          !compound.groups[0].pipeline_time_direct &&
          compound.cmds[1].pipeline_time_mode == SHELL_PIPE_TIME_POSIX &&
          compound.cmds[1].pipeline_time_direct &&
          compound.cmds[2].pipeline_time_mode == SHELL_PIPE_TIME_NONE &&
          compound.cmds[3].pipeline_time_mode == SHELL_PIPE_TIME_DEFAULT &&
          !compound.cmds[3].pipeline_time_direct;
  parser_test("Compound pipeline members separate outer and nested timing",
              valid);

  static const struct {
    const char *source;
    uint16_t modifier;
  } nested_groups[] = {
      {"{ time { echo nested; }; echo outer; }", SHELL_CMD_MOD_PIPE_TIMED},
      {"{ ! { echo nested; }; echo outer; }", SHELL_CMD_MOD_PIPE_NEGATED},
      {"time { time -p { echo nested; }; echo outer; }",
       SHELL_CMD_MOD_PIPE_TIMED},
      {"! { ! { echo nested; }; echo outer; }", SHELL_CMD_MOD_PIPE_NEGATED},
  };
  valid = true;
  for (size_t i = 0; i < sizeof(nested_groups) / sizeof(nested_groups[0]);
       i++) {
    shell_parse_result_t parsed = {0};
    bool item = shell_parse_fast(nested_groups[i].source,
                                 strlen(nested_groups[i].source), NULL,
                                 &parsed) == SHELL_OK &&
                parsed.group_count == 2 && parsed.count == 2;
    uint32_t direct = 0;
    for (uint32_t group = 0; item && group < parsed.group_count; group++)
      direct +=
          (parsed.groups[group].modifiers & nested_groups[i].modifier) != 0;
    item = item && direct >= 1;
    if (!item)
      fprintf(stderr,
              "nested pipeline modifier mismatch: %s count=%u "
              "groups=%u direct=%u\n",
              nested_groups[i].source, parsed.count, parsed.group_count,
              direct);
    valid = valid && item;
  }
  parser_test("Nested brace groups retain reserved pipeline modifiers", valid);

  static const struct {
    const char *source;
    uint32_t negations;
    shell_pipeline_time_mode_t mode;
  } redirected_groups[] = {
      {"time { echo x; } 2>err | cat", 0, SHELL_PIPE_TIME_DEFAULT},
      {"time -p (echo x) {fd}>out |& cat", 0, SHELL_PIPE_TIME_POSIX},
      {"time { echo x; } &>all | cat", 0, SHELL_PIPE_TIME_DEFAULT},
      {"time { cat; } <<<body | cat", 0, SHELL_PIPE_TIME_DEFAULT},
      {"time { cat; } <<EOF | cat\nbody\nEOF\n", 0, SHELL_PIPE_TIME_DEFAULT},
      {"! { echo x; } >out | cat", 1, SHELL_PIPE_TIME_NONE},
      {"! ! (echo x) <in |& cat", 2, SHELL_PIPE_TIME_NONE},
      {"time echo x | { cat; } 2>err | sort", 0, SHELL_PIPE_TIME_DEFAULT},
  };
  valid = true;
  for (size_t i = 0;
       i < sizeof(redirected_groups) / sizeof(redirected_groups[0]); i++) {
    shell_parse_result_t parsed = {0};
    bool item = shell_parse_fast(redirected_groups[i].source,
                                 strlen(redirected_groups[i].source), NULL,
                                 &parsed) == SHELL_OK &&
                parsed.count >= 2;
    const shell_range_t *last = item ? &parsed.cmds[parsed.count - 1] : NULL;
    item = item && last->type == SHELL_TYPE_PIPELINE &&
           last->pipeline_negation_count == redirected_groups[i].negations &&
           last->pipeline_time_mode == redirected_groups[i].mode;
    if (!item)
      fprintf(stderr,
              "redirected group modifier mismatch: %s count=%u "
              "last-type=%u negations=%u mode=%u\n",
              redirected_groups[i].source, parsed.count, last ? last->type : 0,
              last ? last->pipeline_negation_count : 0,
              last ? last->pipeline_time_mode : 0);
    valid = valid && item;
  }
  parser_test("Group redirect tails preserve outer pipeline modifiers", valid);

  static const char *const ordinary[] = {
      "VALUE=x time echo x",
      ">out time echo x",
      "command time echo x",
      "\\time echo x",
      "'time' echo x",
      "echo | time cat",
      "<<<body time echo x",
      "echo | <<<body time",
      "<<<one 3<<<two time",
      "<<<one time <<<two cat",
      "<<<one time -p 3<<<two cat <&3",
      "<<<one time \\\n<<<two cat",
      "<<EOF time <<<two cat\none\nEOF\n",
      "<<<one time <<EOF cat\ntwo\nEOF\n",
      "true | time <<<one <<<two cat",
      "{fd}<<<body time",
      "<<EOF time\nbody\nEOF\n",
      "time$(echo x)",
      "time`echo x`",
      "time$((1))",
      "time$'x'",
      "time>(true)",
      "time<(true)",
      "time{fd}>out",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(ordinary) / sizeof(ordinary[0]); i++) {
    shell_parse_result_t parsed = {0};
    valid = valid && shell_parse_fast(ordinary[i], strlen(ordinary[i]), NULL,
                                      &parsed) == SHELL_OK;
    for (uint32_t command = 0; valid && command < parsed.count; command++)
      valid =
          (parsed.cmds[command].modifiers & SHELL_CMD_MOD_PIPE_TIMED) == 0 &&
          parsed.cmds[command].pipeline_time_mode == SHELL_PIPE_TIME_NONE;
  }
  parser_test(
      "Time remains an ordinary word outside reserved pipeline position",
      valid);

  shell_parse_result_t document_negator = {0};
  valid = shell_parse_fast("<<<body ! true", strlen("<<<body ! true"), NULL,
                           &document_negator) == SHELL_OK &&
          document_negator.count == 2;
  for (uint32_t command = 0; valid && command < document_negator.count;
       command++)
    valid = document_negator.cmds[command].pipeline_negation_count == 0 &&
            (document_negator.cmds[command].modifiers &
             SHELL_CMD_MOD_PIPE_NEGATED) == 0;
  parser_test("Negator after a leading document remains an ordinary word",
              valid);

  static const char *const continued_negator[] = {
      "<<<one ! <<<two cat", "<<<one ! 3<<<two cat",
      "<<EOF ! <<<two cat\none\nEOF\n"};
  valid = true;
  for (size_t i = 0;
       i < sizeof(continued_negator) / sizeof(continued_negator[0]); i++) {
    shell_parse_result_t parsed = {0};
    valid = valid &&
            shell_parse_fast(continued_negator[i], strlen(continued_negator[i]),
                             NULL, &parsed) == SHELL_OK;
    for (uint32_t range = 0; valid && range < parsed.count; range++)
      valid = parsed.cmds[range].pipeline_negation_count == 0;
  }
  parser_test("Document fragments do not restart reserved negator recognition",
              valid);

  static const struct {
    const char *source;
    shell_pipeline_time_mode_t mode;
    uint32_t negations;
  } document_lines[] = {
      {"printf one <<<one\ntime <<<two cat", SHELL_PIPE_TIME_DEFAULT, 0},
      {"printf one <<<one\r\ntime -p <<<two cat", SHELL_PIPE_TIME_POSIX, 0},
      {"printf one <<<one\n! <<<two cat", SHELL_PIPE_TIME_NONE, 1},
      {"printf one <<<one\n#comment\n! time <<<two cat",
       SHELL_PIPE_TIME_DEFAULT, 1},
  };
  valid = true;
  for (size_t i = 0; i < sizeof(document_lines) / sizeof(document_lines[0]);
       i++) {
    shell_parse_result_t parsed = {0};
    bool item = shell_parse_fast(document_lines[i].source,
                                 strlen(document_lines[i].source), NULL,
                                 &parsed) == SHELL_OK &&
                parsed.count == 4;
    if (item)
      item = parsed.cmds[2].type == SHELL_TYPE_HERESTRING &&
             parsed.cmds[2].pipeline_time_mode == document_lines[i].mode &&
             parsed.cmds[2].pipeline_negation_count ==
                 document_lines[i].negations &&
             parsed.cmds[0].pipeline_time_mode == SHELL_PIPE_TIME_NONE;
    valid = valid && item;
  }
  parser_test("Real document line endings restore pipeline-prefix context",
              valid);

  static const char *const option_fragments[] = {
      "time -p$(echo x)", "time -p`echo x`",  "time -p$'x'",
      "time -p>(true)",   "time --$(echo x)",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(option_fragments) / sizeof(option_fragments[0]);
       i++) {
    shell_parse_result_t parsed = {0};
    valid = valid &&
            shell_parse_fast(option_fragments[i], strlen(option_fragments[i]),
                             NULL, &parsed) == SHELL_OK &&
            parsed.count != 0 &&
            parsed.cmds[0].pipeline_time_mode == SHELL_PIPE_TIME_DEFAULT;
  }
  parser_test("Time options require complete logical words", valid);

  static const char *const invalid_post_pipe_compounds[] = {
      "echo | time { cat; }",
      "echo | time (cat)",
      "echo | ! { cat; }",
      "echo | ! (cat)",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(invalid_post_pipe_compounds) /
                             sizeof(invalid_post_pipe_compounds[0]);
       i++) {
    shell_parse_result_t parsed = {0};
    valid = valid && shell_parse_fast(invalid_post_pipe_compounds[i],
                                      strlen(invalid_post_pipe_compounds[i]),
                                      NULL, &parsed) == SHELL_EPARSE;
  }
  parser_test("Post-pipe modifiers cannot introduce compound stages", valid);
}

/* Document redirects may carry Bash's named descriptor allocator. They are
 * redirect syntax, never an argv fragment, and a bare document redirect can
 * be the pipeline stage modified by one or more leading `!` reserved words. */
static void parser_test_named_document_and_negation_metadata(void) {
  static const struct {
    const char *input;
    uint16_t document_type;
    uint32_t negation_count;
    shell_pipeline_time_mode_t time_mode;
  } cases[] = {
      {"printf x {fd}<<<body", SHELL_TYPE_HERESTRING, 0, SHELL_PIPE_TIME_NONE},
      {"printf x {fd}<<EOF\nbody\nEOF\n", SHELL_TYPE_HEREDOC, 0,
       SHELL_PIPE_TIME_NONE},
      {"! <<<body", SHELL_TYPE_HERESTRING, 1, SHELL_PIPE_TIME_NONE},
      {"! ! <<EOF\nbody\nEOF\n", SHELL_TYPE_HEREDOC, 2, SHELL_PIPE_TIME_NONE},
      {"! <<<body | cat", SHELL_TYPE_HERESTRING, 1, SHELL_PIPE_TIME_NONE},
      {"{ cat; } {fd}<<<body", SHELL_TYPE_HERESTRING, 0, SHELL_PIPE_TIME_NONE},
      {"{ cat; } {fd}<<EOF\nbody\nEOF\n", SHELL_TYPE_HEREDOC, 0,
       SHELL_PIPE_TIME_NONE},
      {"time <<<body", SHELL_TYPE_HERESTRING, 0, SHELL_PIPE_TIME_DEFAULT},
      {"time -p ! 3<<EOF\nbody\nEOF\n", SHELL_TYPE_HEREDOC, 1,
       SHELL_PIPE_TIME_POSIX},
  };
  const shell_limits_t strict = {
      .max_subcommands = SHELL_MAX_SUBCOMMANDS,
      .strict_mode = true,
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t parsed = {0};
    valid = valid && shell_parse_fast(cases[i].input, strlen(cases[i].input),
                                      &strict, &parsed) == SHELL_OK;
    uint32_t document = UINT32_MAX;
    for (uint32_t range = 0; range < parsed.count; range++)
      if (parsed.cmds[range].type & cases[i].document_type)
        document = range;
    if (i == 5) {
      /* A trailing group here-string is recorded in group I/O metadata rather
       * than as a synthetic command range. */
      valid = valid && parsed.count == 1 && document == UINT32_MAX;
    } else {
      valid =
          valid && document != UINT32_MAX &&
          parsed.cmds[document].pipeline_negation_count ==
              cases[i].negation_count &&
          (!!(parsed.cmds[document].modifiers & SHELL_CMD_MOD_PIPE_NEGATED) ==
           (cases[i].negation_count != 0)) &&
          parsed.cmds[document].pipeline_time_mode == cases[i].time_mode &&
          (!!(parsed.cmds[document].modifiers & SHELL_CMD_MOD_PIPE_TIMED) ==
           (cases[i].time_mode != SHELL_PIPE_TIME_NONE));
    }
    if (i < 2)
      valid = valid && parsed.count == 2 &&
              parsed.cmds[0].len == strlen("printf x");
    if (i == 4)
      valid = valid && parsed.count == 2 &&
              parsed.cmds[1].type == SHELL_TYPE_PIPELINE &&
              parsed.cmds[1].pipeline_negation_count == 1;
    if (i == 6)
      valid = valid && parsed.count == 2;
  }
  parser_test(
      "Fast parser classifies named and modified document redirect stages",
      valid);
}

static void parser_test_document_pipeline_modifiers(void) {
  static const char *const cases[] = {
      "time -p ! cat <<<body | cat",
      "time -p ! cat <<EOF | cat\nbody\nEOF\n",
      "time -p ! cat <<<body argument | cat",
      "time -p ! cat <<<one 3<<<two |& cat",
      "time -p ! cat | <<<body",
      "time -p ! cat | <<EOF\nbody\nEOF\n",
      "time -p ! { cat; } | <<<body",
      "time -p ! <<<body | cat",
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t parsed = {0};
    bool item =
        shell_parse_fast(cases[i], strlen(cases[i]), NULL, &parsed) == SHELL_OK;
    uint32_t stages = 0;
    for (uint32_t range = 0; item && range < parsed.count; range++) {
      const shell_range_t *member = &parsed.cmds[range];
      if (member->pipe_input_mode == SHELL_PIPE_MODE_NONE)
        continue;
      stages++;
      item = member->pipeline_time_mode == SHELL_PIPE_TIME_POSIX &&
             member->pipeline_negation_count == 1 &&
             (member->features & SHELL_FEAT_PIPELINE) != 0;
    }
    item = item && stages == 1 && parsed.count != 0 &&
           (parsed.cmds[0].features & SHELL_FEAT_PIPELINE) != 0;
    if (!item)
      fprintf(stderr, "Document pipeline metadata: %s\n", cases[i]);
    valid = valid && item;
  }
  parser_test("Document fragments preserve timed and negated pipeline stages",
              valid);
}

/* These semantic classifiers sit below the public processor adapters. Exercise
 * their quote, expansion, and unsupported-control boundaries directly so the
 * adapters cannot accidentally narrow the lexical contract. */
static void parser_test_semantic_classifier_boundaries(void) {
  static const struct {
    const char *input;
    bool unsupported;
  } source_cases[] = {
      {"", false},
      {"printf '%s' while", false},
      {"while true; do :; done", true},
      {"echo items[0]", false},
      {"echo ${items[0]}", true},
      {"echo $(while true; do :; done)", true},
      {"echo <(while true; do :; done)", true},
      {"echo `while true; do :; done`", true},
      {"echo ${value:-$(while true; do :; done)}", true},
      {"echo $((items[0]))", true},
      {"echo \"\\$(while true; do :; done)\"", false},
      {"echo \"$(printf x)\"", false},
      {"echo $'while'", false},
      {"echo $'$\"localized\"'", false},
      {"echo \\$\"localized\"", false},
      {"echo x # $\"localized\"", false},
      {"cat <<'EOF'\n$\"localized\"\nEOF", false},
      {"echo $\"localized\"", true},
      {"echo prefix$\"localized\"suffix", true},
      {"echo ${value:-$\"fallback\"}", true},
      {"echo \"${value:-$\"localized\"}\"", true},
      {"echo \"${outer:-${inner:-$\"localized\"}}\"", true},
      {"echo \"${value:-\\$\"literal\"}\"", false},
      {"echo \"${value:-'$\"literal\"'}\"", false},
      {"declare arr[0]", true},
      {"declare 'arr[0]'", true},
      {"declare arr\\[0\\]", true},
      {"declare arr$'[0]'", true},
      {"declare ar\"r\"[0]", true},
      {"declare arr[$((0))]", true},
      {"declare arr[${index}]", true},
      {"declare arr[`printf 0`]", true},
      {"declare ar\\\nr[0]", true},
      {"f\\\nd=shadow declare -a values", true},
      {"de$'clare' -a values", true},
      {"command -$'p' de$'clare' -a values", true},
      {"declare -$'a' values", true},
      {"echo de$'clare' -a values", false},
      {"$tool -a values", false},
      {"typeset map[key]", true},
      {"command -- declare \"arr[$(printf 0)]\"", true},
      {"declare scalar='[literal]'", false},
      {SHELLSPLIT_TEST_UNMODELED_BINARY_CONDITION("/tmp/x"), true},
      {"VALUE=x [[ $VALUE == x ]]", false},
      {">out [[ x ]]", false},
      {"VALUE=x then", false},
      {">out then", false},
      {"{ [[ -n value ]]; }", false},
      {"echo $( " SHELLSPLIT_TEST_UNMODELED_BINARY_CONDITION("/tmp/x") " )",
       true},
      {"(( count += 1 ))", true},
      {"! (( 1 ))", false},
      {"{ (( 1 )); }", false},
      {"time echo x", false},
      {"time eval echo hidden", true},
      {"time coproc echo hidden", true},
      {"time " SHELLSPLIT_TEST_UNMODELED_BINARY_CONDITION("/tmp/x"), true},
      {"time (( count += 1 ))", true},
      {"time shopt -s varredir_close", true},
      {"time command declare -a values", true},
      {"echo \"$(time eval echo hidden)\"", true},
      {"VALUE=x time -p echo x", false},
      {"! time false", false},
      {"command time echo x", false},
      {"\"time\" echo x", false},
      {"echo $'unterminated", false},
  };
  static const struct {
    const char *input;
    bool array_semantics;
  } arithmetic_cases[] = {
      {"1 + value", false},
      {"\\items[0]", true},
      {"items[0] + 1", true},
      {"'items[0]'", false},
      {"\"items[0]\"", true},
      {"$'literal' items[0]", true},
      {"${items[0]}", true},
      {"${value:-$(while true; do :; done)}", true},
      {"`while true; do :; done`", true},
      {"$(while true; do :; done)", true},
      {"$((items[0]))", true},
      {"$'unterminated", false},
  };
  bool valid = !shell_tokenizer_arithmetic_has_array_semantics(NULL, 0) &&
               shell_tokenizer_has_unsupported_semantics(NULL, 0);
  shell_tokenizer_state_t escaped_glob_state;
  shell_token_t escaped_glob = {0};
  valid = valid &&
          shell_tokenizer_init(&escaped_glob_state, "[a\\]]", strlen("[a\\]]"),
                               NULL) &&
          shell_tokenizer_next(&escaped_glob_state, &escaped_glob) &&
          escaped_glob.type == SHELL_TOKEN_GLOB;
  for (size_t i = 0; i < sizeof(source_cases) / sizeof(source_cases[0]); i++) {
    bool got = shell_tokenizer_has_unsupported_semantics(
        source_cases[i].input, strlen(source_cases[i].input));
    if (got != source_cases[i].unsupported)
      fprintf(stderr,
              "semantic classification mismatch: %s got=%d expected=%d\n",
              source_cases[i].input, got, source_cases[i].unsupported);
    valid = got == source_cases[i].unsupported && valid;
  }
  for (size_t i = 0; i < sizeof(arithmetic_cases) / sizeof(arithmetic_cases[0]);
       i++) {
    bool got = shell_tokenizer_arithmetic_has_array_semantics(
        arithmetic_cases[i].input, strlen(arithmetic_cases[i].input));
    valid = got == arithmetic_cases[i].array_semantics && valid;
  }
  char too_many_commands[2 * (SHELL_MAX_SUBCOMMANDS + 1)] = {0};
  for (size_t i = 0; i < SHELL_MAX_SUBCOMMANDS + 1; i++) {
    too_many_commands[2 * i] = 'x';
    if (i + 1 < SHELL_MAX_SUBCOMMANDS + 1)
      too_many_commands[2 * i + 1] = ';';
  }
  shell_processed_commands_t too_many = {
      .commands = (shell_command_info_t *)(uintptr_t)1,
      .command_count = SIZE_MAX,
  };
  valid = valid && shell_process_commands(
                       too_many_commands, strlen(too_many_commands), NULL,
                       &too_many) == SHELL_PROCESS_EOUTPUT_LIMIT;
  valid = valid && too_many.commands == NULL && too_many.command_count == 0;

  char unsupported_after_capacity[2 * (SHELL_MAX_SUBCOMMANDS + 1) +
                                  sizeof("time eval echo hidden")] = {0};
  size_t capacity_used = 0;
  for (size_t i = 0; i < SHELL_MAX_SUBCOMMANDS + 1; i++)
    capacity_used += (size_t)snprintf(
        unsupported_after_capacity + capacity_used,
        sizeof(unsupported_after_capacity) - capacity_used, "x;");
  capacity_used +=
      (size_t)snprintf(unsupported_after_capacity + capacity_used,
                       sizeof(unsupported_after_capacity) - capacity_used,
                       "time eval echo hidden");
  too_many = (shell_processed_commands_t){
      .commands = (shell_command_info_t *)(uintptr_t)1,
      .command_count = SIZE_MAX,
  };
  valid = valid && capacity_used < sizeof(unsupported_after_capacity) &&
          shell_process_commands(unsupported_after_capacity, capacity_used,
                                 NULL, &too_many) == SHELL_PROCESS_EPARSE &&
          too_many.commands == NULL && too_many.command_count == 0;
  parser_test("Semantic classifiers retain quote and expansion boundaries",
              valid);
}

/* Exercise transformation after tokenization has established source spans.
 * In particular, a short variable spelling expands to a longer display token,
 * so both string and aggregate output limits need independent coverage. */
static void parser_test_transform_contract_boundaries(void) {
  shell_transformed_command_t *transformed =
      (shell_transformed_command_t *)(uintptr_t)1;
  shell_command_t *tokenized = NULL;
  size_t tokenized_count = 0;
  const shell_transform_limits_t display_limit = {
      .max_string_bytes = 2,
      .max_total_bytes = SIZE_MAX,
  };
  const shell_transform_limits_t total_limit = {
      .max_string_bytes = SIZE_MAX,
      .max_total_bytes = 20,
  };
  bool valid =
      shell_tokenize_commands("$X", 2, &tokenized, &tokenized_count) ==
          SHELL_TOKENIZE_OK &&
      tokenized_count == 1 &&
      shell_transform_command(&tokenized[0], &display_limit, &transformed) ==
          SHELL_TRANSFORM_EOUTPUT_LIMIT &&
      transformed == NULL &&
      shell_transform_command(&tokenized[0], &total_limit, &transformed) ==
          SHELL_TRANSFORM_EOUTPUT_LIMIT &&
      transformed == NULL;
  shell_commands_free(tokenized, tokenized_count);
  shell_transformed_command_t **commands =
      (shell_transformed_command_t **)(uintptr_t)1;
  size_t count = SIZE_MAX;
  valid = valid &&
          shell_transform_command_line("", 0, NULL, &commands, &count) ==
              SHELL_TRANSFORM_BLANK &&
          commands == NULL && count == 0;
  parser_test("Transform contracts retain expansion and output boundaries",
              valid);
}

/* Abstraction is a diagnostic adapter, but it still consumes the same lexical
 * spans as canonical processing. Exercise it from both library variants so
 * path, expansion, redirect, and accessor contracts cannot drift. */
static void parser_test_abstract_adapter_contract(void) {
  shell_abstract_command_t *abstracted =
      (shell_abstract_command_t *)(uintptr_t)1;
  const char source[] =
      "printf $HOME /etc/passwd ./relative ~/home *.c $(id) $((1 + 2)) >out";
  shell_abstract_status_t null_status =
      shell_abstract_command_parse("", 0, &abstracted);
  bool null_cleared = abstracted == NULL;
  shell_abstract_status_t malformed_status =
      shell_abstract_command_parse("echo '", strlen("echo '"), &abstracted);
  bool malformed_cleared = abstracted == NULL;
  shell_abstract_status_t parse_status =
      shell_abstract_command_parse(source, sizeof(source) - 1, &abstracted);
  bool valid = null_status == SHELL_ABSTRACT_EINPUT && null_cleared &&
               malformed_status == SHELL_ABSTRACT_EPARSE && malformed_cleared &&
               parse_status == SHELL_ABSTRACT_OK && abstracted != NULL &&
               abstracted->original != NULL &&
               abstracted->display_text != NULL && abstracted->has_variables &&
               abstracted->has_paths && abstracted->has_abs_paths &&
               abstracted->has_rel_paths && abstracted->has_home_paths &&
               abstracted->has_globs && abstracted->has_cmd_subst &&
               abstracted->has_arithmetic && abstracted->has_redirects;
  parser_test("Abstract adapter establishes every required output", valid);
  size_t element_count = 0;
  const shell_abstract_element_t *const *elements =
      shell_abstract_command_get_elements(abstracted, &element_count);
  valid =
      valid && elements != NULL && element_count > 0 &&
      shell_abstract_command_get_element(abstracted, element_count) == NULL &&
      shell_abstract_command_find_element(abstracted, "$missing") == NULL &&
      shell_classify_raw_token("/tmp/file", strlen("/tmp/file")) ==
          SHELL_TOKEN_ARGUMENT &&
      shell_path_category_from_path("/tmp/file") == SHELL_PATH_TMP &&
      strcmp(shell_abstract_type_name((shell_abstract_type_t)99), "UNKNOWN") ==
          0 &&
      strcmp(shell_path_category_name((shell_path_category_t)99), "UNKNOWN") ==
          0;
  /* Raw classification accepts a token span rather than a command line. Keep
   * malformed and boundary spellings distinct from the richer parsed input
   * above. */
  valid = valid && shell_classify_raw_token("", 0) == SHELL_TOKEN_END &&
          shell_classify_raw_token("$", 1) == SHELL_TOKEN_ARGUMENT &&
          shell_classify_raw_token("${x}", 4) == SHELL_TOKEN_VARIABLE &&
          shell_classify_raw_token("${12}", 5) == SHELL_TOKEN_SPECIAL_VAR &&
          shell_classify_raw_token("$?", 2) == SHELL_TOKEN_SPECIAL_VAR &&
          shell_classify_raw_token("$(x)", 4) == SHELL_TOKEN_SUBSHELL &&
          shell_classify_raw_token("$((1))", 6) == SHELL_TOKEN_ARITHMETIC &&
          shell_classify_raw_token("~other", 6) == SHELL_TOKEN_ARGUMENT &&
          shell_classify_raw_token("relative/path", strlen("relative/path")) ==
              SHELL_TOKEN_ARGUMENT &&
          shell_classify_raw_token("--option", strlen("--option")) ==
              SHELL_TOKEN_ARGUMENT;
  const char *const environment[] = {"HOME=/home/example", "HOMEVAR=value",
                                     NULL};
  shell_runtime_context_t runtime = {
      .env = environment,
      .cwd = "/work/base",
      .resolve_symlinks = false,
  };
  valid = valid && shell_abstract_command_expand(abstracted, &runtime);
  shell_abstract_command_free(abstracted);
  parser_test("Abstract adapter preserves lexical and accessor contracts",
              valid);
}

/* These are distinct malformed source boundaries, not merely different
 * spellings of a trailing operator.  Exercise them through both the shipping
 * and allocator-instrumented fast-parser targets: redirects must have a word
 * operand, group prefixes cannot masquerade as command arguments, and a
 * redirect-only syntax is kept distinct from an executable command range. */
static void parser_test_strict_redirect_and_group_rejection(void) {
  static const char *const cases[] = {
      "command >",
      "command > (consumer)",
      "command > | next",
      "command << (delimiter)",
      ">output { command; }",
      ">output (printf x)",
      "2>>output (printf x)",
      "{ command }",
      "command |",
      "command &&",
  };
  const shell_limits_t strict = {
      .max_subcommands = SHELL_MAX_SUBCOMMANDS,
      .strict_mode = true,
  };
  bool rejected = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t result = {0};
    shell_error_t status =
        shell_parse_fast(cases[i], strlen(cases[i]), &strict, &result);
    bool case_rejected =
        status == SHELL_EPARSE && result.status == SHELL_STATUS_ERROR;
    if (!case_rejected)
      fprintf(stderr,
              "strict redirect/group case accepted: %s (status=%d, "
              "parser-status=%d)\n",
              cases[i], status, result.status);
    rejected = rejected && case_rejected;
  }
  parser_test(
      "Strict fast parser rejects malformed redirect and group boundaries",
      rejected);

  shell_parse_result_t redirect_only = {0};
  parser_test("Fast parser retains redirect-only structural syntax",
              shell_parse_fast(">output", strlen(">output"), &strict,
                               &redirect_only) == SHELL_OK &&
                  redirect_only.count == 1 &&
                  redirect_only.cmds[0].type == SHELL_TYPE_SIMPLE);
}

/* --- MAIN --- */

static void parser_test_nested_double_quote_boundaries(void) {
  static const char *const valid_sources[] = {
      "echo \"${value:-\"x;y\"}\"",
      "echo \"$(printf \"x;y\")\"",
      "echo \"`printf \"x;y\"`\"",
      "echo \"${value:-\"x;y\"}\"; next",
  };
  shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                           .strict_mode = true};
  bool valid = true;
  for (size_t i = 0; i < sizeof(valid_sources) / sizeof(valid_sources[0]);
       i++) {
    shell_parse_result_t result = {0};
    const char *source = valid_sources[i];
    valid = valid &&
            shell_parse_fast(source, strlen(source), &strict, &result) ==
                SHELL_OK &&
            result.count == (i == 3 ? 2u : 1u);
  }
  parser_test("Nested quote scopes preserve outer command boundaries", valid);

  const char *quoted_operator = "echo \"${value:-\"x&y\"}\"";
  shell_parse_result_t feature_result = {0};
  bool feature_ok = shell_parse_fast(quoted_operator, strlen(quoted_operator),
                                     &strict, &feature_result) == SHELL_OK &&
                    feature_result.count == 1 &&
                    !(feature_result.cmds[0].features & SHELL_FEAT_BACKGROUND);
  parser_test("Nested quoted ampersand is not a background feature",
              feature_ok);

  static const char *const parameter_punctuation[] = {
      "echo ${value:-x&y}",
      "echo \"${value:-x&y}\"",
      "echo \"${value:-\"x&y\"}\"",
  };
  bool parameter_features_ok = true;
  for (size_t i = 0;
       i < sizeof(parameter_punctuation) / sizeof(parameter_punctuation[0]);
       i++) {
    shell_parse_result_t parsed = {0};
    parameter_features_ok &=
        shell_parse_fast(parameter_punctuation[i],
                         strlen(parameter_punctuation[i]), &strict,
                         &parsed) == SHELL_OK &&
        parsed.count == 1 && (parsed.cmds[0].features & SHELL_FEAT_VARS) != 0 &&
        (parsed.cmds[0].features & SHELL_FEAT_BACKGROUND) == 0;
  }
  parser_test(
      "Parameter-word ampersands do not mark outer background execution",
      parameter_features_ok);

  const char *nested_background = "echo ${value:-$(sleep 1 & wait)}";
  shell_parse_result_t nested_features = {0};
  parser_test(
      "Executable commands inside parameter words retain background metadata",
      shell_parse_fast(nested_background, strlen(nested_background), &strict,
                       &nested_features) == SHELL_OK &&
          nested_features.count == 1 &&
          (nested_features.cmds[0].features & SHELL_FEAT_SUBSHELL) != 0 &&
          (nested_features.cmds[0].features & SHELL_FEAT_BACKGROUND) != 0);

  static const struct {
    const char *source;
    uint32_t required;
    uint32_t forbidden;
  } operand_features[] = {
      {"echo ${value:-`printf hi`}", SHELL_FEAT_VARS | SHELL_FEAT_SUBSHELL,
       SHELL_FEAT_BACKGROUND},
      {"echo ${value:-<(printf hi)}", SHELL_FEAT_VARS | SHELL_FEAT_PROCESS_SUB,
       SHELL_FEAT_BACKGROUND},
      {"echo \"${value:-\"<(printf hi)\"}\"", SHELL_FEAT_VARS,
       SHELL_FEAT_PROCESS_SUB | SHELL_FEAT_BACKGROUND},
      {"echo ${value:-$(printf one)$(printf two)}",
       SHELL_FEAT_VARS | SHELL_FEAT_SUBSHELL, SHELL_FEAT_BACKGROUND},
  };
  bool operand_features_ok = true;
  for (size_t i = 0; i < sizeof(operand_features) / sizeof(operand_features[0]);
       i++) {
    shell_parse_result_t parsed = {0};
    operand_features_ok &=
        shell_parse_fast(operand_features[i].source,
                         strlen(operand_features[i].source), &strict,
                         &parsed) == SHELL_OK &&
        parsed.count == 1 &&
        (parsed.cmds[0].features & operand_features[i].required) ==
            operand_features[i].required &&
        (parsed.cmds[0].features & operand_features[i].forbidden) == 0;
  }
  parser_test(
      "Parameter operands retain executable features without leaking syntax",
      operand_features_ok);

  static const char *const incomplete_nested[] = {
      "echo \"${value:-\"x;y\"\"",
      "echo \"$(printf \"x;y\"\"",
      "echo \"`printf x\"",
  };
  bool invalid = true;
  for (size_t i = 0;
       i < sizeof(incomplete_nested) / sizeof(incomplete_nested[0]); i++) {
    shell_parse_result_t rejected = {0};
    invalid = invalid && shell_parse_fast(incomplete_nested[i],
                                          strlen(incomplete_nested[i]), &strict,
                                          &rejected) == SHELL_EPARSE;
  }
  parser_test("Incomplete expansions cannot borrow the outer quote delimiter",
              invalid);

  const char *incomplete = "echo $'foo\\'";
  shell_parse_result_t result = {0};
  parser_test("Escaped final ANSI-C apostrophe is not a closing delimiter",
              shell_parse_fast(incomplete, strlen(incomplete), &strict,
                               &result) == SHELL_EPARSE);
  const char *complete = "echo $'foo\\\\'";
  parser_test("Paired ANSI-C backslashes permit a closing apostrophe",
              shell_parse_fast(complete, strlen(complete), &strict, &result) ==
                      SHELL_OK &&
                  result.count == 1);
}

static void parser_test_prefix_scan_scaling(void) {
  static const struct {
    const char *prefix;
    const char *suffix;
    size_t document_anchor;
  } cases[] = {
      {"printf x | ", "<<<word cat", SIZE_MAX},
      {"! printf x | ", "<<<word cat", SIZE_MAX},
      {"time printf x | ", "<<<word cat", SIZE_MAX},
      {"! time printf x |& ", "<<<word cat", SIZE_MAX},
      {"true; # ignored time !\n ! ", "<<<word cat", 24},
      {"true && time ! ", "<<<word cat", 8},
      {"true; time ", "{fd}<<<word cat", 6},
      {"printf x | { time ! ", "<<<word cat; }", 13},
      {"time ", "{ printf x; }", SIZE_MAX},
      {"! time ", "(printf x)", SIZE_MAX},
  };
  bool valid = true;
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    for (size_t padding = 256; padding <= 8192; padding *= 2) {
      size_t prefix = strlen(cases[c].prefix);
      size_t suffix = strlen(cases[c].suffix);
      size_t length = prefix + padding + suffix;
      char *source = malloc(length + 1);
      if (!source) {
        valid = false;
        break;
      }
      memcpy(source, cases[c].prefix, prefix);
      memset(source + prefix, ' ', padding);
      memcpy(source + prefix + padding, cases[c].suffix, suffix + 1);
      shell_parse_result_t parsed;
      shell_limits_t strict = SHELL_LIMITS_DEFAULT;
      strict.strict_mode = true;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      shellsplit_test_source_scan_reset();
#endif
      bool item =
          shell_parse_fast(source, length, &strict, &parsed) == SHELL_OK;
      shell_execution_map_t execution;
      if (item) {
        shell_execution_map_build(source, length, &parsed, &execution);
        if (cases[c].document_anchor != SIZE_MAX) {
          bool found = false;
          for (uint32_t i = 0; i < parsed.count; i++)
            if (shell_execution_document(&parsed.cmds[i])) {
              found = true;
              item = item && execution.anchor[i] == cases[c].document_anchor;
              break;
            }
          item = item && found;
        }
      }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
      item = item && shellsplit_test_source_scan_work() <= 32 * length;
#endif
      if (!item)
        fprintf(stderr, "prefix scaling mismatch: case=%zu padding=%zu\n", c,
                padding);
      valid = valid && item;
      free(source);
    }
  }
  parser_test("Pipeline and document prefix scans have a linear work budget",
              valid);

  /* Nested compounds make both the group count and flattened range count grow.
   * Index construction must visit those tables in one sweep; a per-range group
   * search or per-group range scan would make this family quadratic. */
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous_work = 0;
#endif
  for (size_t depth = 4; depth <= 32; depth *= 2) {
    char source[4096];
    size_t used = 0;
    for (size_t group = 0; group < depth; group++) {
      static const char prefix[] = "{ printf x; ";
      memcpy(source + used, prefix, sizeof(prefix) - 1);
      used += sizeof(prefix) - 1;
    }
    source[used++] = ':';
    for (size_t group = 0; group < depth; group++) {
      static const char suffix[] = "; }";
      memcpy(source + used, suffix, sizeof(suffix) - 1);
      used += sizeof(suffix) - 1;
    }
    source[used] = '\0';

    shell_parse_result_t parsed = {0};
    shell_limits_t strict = SHELL_LIMITS_DEFAULT;
    strict.strict_mode = true;
    bool item = shell_parse_fast(source, used, &strict, &parsed) == SHELL_OK &&
                parsed.group_count == depth && parsed.count == depth + 1;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_source_scan_reset();
#endif
    shell_execution_map_t execution;
    if (item)
      shell_execution_map_build(source, used, &parsed, &execution);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    size_t work = shellsplit_test_source_scan_work();
    item = item && work <= 64 * (parsed.count + parsed.group_count) + 256 &&
           (previous_work == 0 || work <= 3 * previous_work + 128);
    previous_work = work;
#endif
    if (!item)
      fprintf(stderr, "pipeline index scaling mismatch: depth=%zu\n", depth);
    valid = valid && item;
  }
  parser_test("Pipeline indexing scales with groups and ranges", valid);
}

/* `if` is a group from its `if` word through its `fi` word. The keywords belong
 * to no range, and each range says which list of the `if` it is in. */
static void parser_test_if_structure(void) {
  printf("\n--- If groups ---\n");
  typedef struct {
    const char *text;
    uint8_t role, arm;
  } expected_range_t;
  static const struct {
    const char *name;
    const char *input;
    uint32_t ranges, groups;
    expected_range_t first[7];
  } cases[] = {
      {"if then fi",
       "if a; then b; fi",
       2,
       1,
       {{"a", SHELL_RANGE_ROLE_CONDITION, 0}, {"b", SHELL_RANGE_ROLE_THEN, 0}}},
      {"if else",
       "if a; then b; else c; fi",
       3,
       1,
       {{"a", SHELL_RANGE_ROLE_CONDITION, 0},
        {"b", SHELL_RANGE_ROLE_THEN, 0},
        {"c", SHELL_RANGE_ROLE_ELSE, 1}}},
      {"elif chain",
       "if a; then b; elif c; then d; elif e; then f; else g; fi",
       7,
       1,
       {{"a", SHELL_RANGE_ROLE_CONDITION, 0},
        {"b", SHELL_RANGE_ROLE_THEN, 0},
        {"c", SHELL_RANGE_ROLE_CONDITION, 1},
        {"d", SHELL_RANGE_ROLE_THEN, 1},
        {"e", SHELL_RANGE_ROLE_CONDITION, 2},
        {"f", SHELL_RANGE_ROLE_THEN, 2},
        {"g", SHELL_RANGE_ROLE_ELSE, 3}}},
      {"newlines separate sections",
       "if a\nthen\n  b\nelse\n  c\nfi",
       3,
       1,
       {{"a", SHELL_RANGE_ROLE_CONDITION, 0},
        {"b", SHELL_RANGE_ROLE_THEN, 0},
        {"c", SHELL_RANGE_ROLE_ELSE, 1}}},
      {"a condition may be a list",
       "if a && b; then c; fi",
       3,
       1,
       {{"a", SHELL_RANGE_ROLE_CONDITION, 0},
        {"b", SHELL_RANGE_ROLE_CONDITION, 0},
        {"c", SHELL_RANGE_ROLE_THEN, 0}}},
      {"a nested group takes the role of its section",
       "if a; then { b; }; else ( c ); fi",
       3,
       3,
       {{"a", SHELL_RANGE_ROLE_CONDITION, 0},
        {"b", SHELL_RANGE_ROLE_NONE, 0},
        {"c", SHELL_RANGE_ROLE_NONE, 0}}},
      {"a nested if has its own sections",
       "if a; then if b; then c; fi; fi",
       3,
       2,
       {{"a", SHELL_RANGE_ROLE_CONDITION, 0},
        {"b", SHELL_RANGE_ROLE_CONDITION, 0},
        {"c", SHELL_RANGE_ROLE_THEN, 0}}},
      {"keyword words as arguments are ordinary",
       "echo if then elif else fi",
       1,
       0,
       {{"echo if then elif else fi", SHELL_RANGE_ROLE_NONE, 0}}},
      {"a keyword after an assignment is not reserved",
       "x=1 if",
       1,
       0,
       {{"x=1 if", SHELL_RANGE_ROLE_NONE, 0}}},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_limits_t limits = SHELL_LIMITS_DEFAULT;
    limits.strict_mode = true;
    shell_parse_result_t result;
    bool ok = shell_parse_fast(cases[i].input, strlen(cases[i].input), &limits,
                               &result) == SHELL_OK &&
              result.count == cases[i].ranges &&
              result.group_count == cases[i].groups;
    for (uint32_t r = 0; ok && r < result.count && r < 7; r++) {
      const shell_range_t *range = &result.cmds[r];
      const expected_range_t *want = &cases[i].first[r];
      ok = range->len == strlen(want->text) &&
           memcmp(cases[i].input + range->start, want->text, range->len) == 0 &&
           range->role == want->role && range->arm == want->arm;
    }
    parser_test(cases[i].name, ok);
  }

  /* The group spans from `if` to the end of `fi`, and a nested group knows the
   * section of the `if` it sits in. */
  static const char nested[] = "if a; then { b; }; else ( c ); fi";
  shell_limits_t limits = SHELL_LIMITS_DEFAULT;
  limits.strict_mode = true;
  shell_parse_result_t result;
  bool ok = shell_parse_fast(nested, sizeof(nested) - 1, &limits, &result) ==
                SHELL_OK &&
            result.group_count == 3 &&
            result.groups[0].kind == SHELL_GROUP_IF &&
            result.groups[0].start == 0 &&
            result.groups[0].end == sizeof(nested) - 1 &&
            result.groups[0].parent == UINT16_MAX &&
            result.groups[1].kind == SHELL_GROUP_BRACE &&
            result.groups[1].parent == 0 &&
            result.groups[1].role == SHELL_RANGE_ROLE_THEN &&
            result.groups[1].arm == 0 &&
            result.groups[2].kind == SHELL_GROUP_SUBSHELL &&
            result.groups[2].role == SHELL_RANGE_ROLE_ELSE &&
            result.groups[2].arm == 1;
  parser_test("a nested group records its section", ok);

  /* The keywords are structure only in order; anything else is rejected. */
  static const char *const invalid[] = {
      "if a; fi",
      "if a; then b; else c; else d; fi",
      "if a; then b; else c; elif d; then e; fi",
      "if a; then b; fi; fi",
      "if a; then b",
      "{ if a; then b; }; fi",
      "if a; then b; ) fi",
  };
  bool rejected = true;
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    shell_parse_result_t unused;
    rejected = rejected && shell_parse_fast(invalid[i], strlen(invalid[i]),
                                            &limits, &unused) != SHELL_OK;
  }
  parser_test("out-of-order and unterminated if sources are rejected",
              rejected);
}

static int run_parser(int argc, char **argv) {
  (void)argc;
  (void)argv;
  printf("=== FAST PARSER API TESTS ===\n");
  printf("Testing shell_parse_fast() and related functions\n\n");

  printf("=== UNIT TESTS ===\n");
  parser_test_feature_matrix();
  parser_test_extglob_expansion_features();
  parser_test_control_word_boundaries();
  parser_test_array_assignment_prefix_features();
  test_layer1_utility_functions();
  test_layer1_error_handling();
  test_dialect_oracle();
  parser_test_if_structure();

  printf("\n=== LARGE AND COMPLEX TESTS ===\n");
  parser_test_complex_case_matrix();

  printf("\n=== FEATURE FLAGS API TESTS ===\n");
  parser_test_feature_flags();
  parser_test_source_io_number_contract();
  parser_test_word_fragment_operator_boundaries();
  parser_test_pipe_after_escaped_redirect_byte();
  parser_test_escaped_backslash_before_newline();
  parser_test_ansi_c_braced_hex_escape();
  parser_test_structured_blank_and_empty_source();
  parser_test_if_keyword_after_compound();
  parser_test_unsupported_syntax_after_compound_keyword();
  parser_test_brace_after_conditional_command();
  parser_test_pipeline_time_metadata();
  parser_test_prefix_scan_scaling();
  parser_test_named_document_and_negation_metadata();
  parser_test_document_pipeline_modifiers();
  parser_test_semantic_classifier_boundaries();
  parser_test_nested_double_quote_boundaries();
  parser_test_transform_contract_boundaries();
  parser_test_abstract_adapter_contract();
  parser_test_strict_redirect_and_group_rejection();

  parser_test_fast_parser_limitations();

  parser_test_strict_mode();
  parser_test_strict_heredoc_completion();
  parser_test_nested_heredoc_rejection();
  parser_test_substitution_comment_and_heredoc_capacity();
  parser_test_source_scanner_contract();
  parser_test_incomplete_control_delimiters();

  printf("\n=== SUMMARY ===\n");
  printf("Results: %d/%d passed\n", parser_pass_count, parser_test_count);
  if (parser_pass_count == parser_test_count) {
    printf("  [PASS] All tests\n");
    return 0;
  } else {
    printf("  [FAIL] %d tests failed\n", parser_test_count - parser_pass_count);
    return 1;
  }
}
#undef NO_CHECK
#undef shell_parse_fast

/* --- boundary (from boundary_test.c) --- */
#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);          \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

static uint32_t boundary_command(const shell_dep_graph_t *graph,
                                 const char *name) {
  size_t length = strlen(name);
  for (uint32_t i = 0; i < graph->node_count; i++) {
    const shell_dep_node_t *node = &graph->nodes[i];
    if (node->type == SHELL_NODE_CMD && node->cmd.token_count &&
        node->cmd.token_lens[0] == length &&
        !memcmp(node->cmd.tokens[0], name, length))
      return i;
  }
  return UINT32_MAX;
}

static bool boundary_route(const shell_dep_graph_t *graph, uint32_t owner,
                           uint32_t fd, bool input, uint32_t inherited) {
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    uint32_t endpoint = input ? edge->from : edge->to;
    if (edge->type == (input ? SHELL_EDGE_READ : SHELL_EDGE_WRITE) &&
        (input ? edge->to : edge->from) == owner &&
        (input ? edge->target_fd : edge->source_fd) == fd &&
        graph->nodes[endpoint].type == SHELL_NODE_FD &&
        graph->nodes[endpoint].fd.number == inherited)
      return true;
  }
  return false;
}

static void boundary_parse(const char *source, shell_dep_limits_t *limits,
                           shell_dep_graph_t *graph) {
  shell_dep_error_t status =
      shell_dep_graph_parse(source, strlen(source), "/", limits, graph);
  if (status != SHELL_DEP_OK)
    fprintf(stderr, "source: %s\nstatus: %d\n", source, status);
  CHECK(status == SHELL_DEP_OK);
  /* The invariant helper validates successful graphs before inspecting them. */
  CHECK(shellsplit_test_depgraph_invariants(source, strlen(source), status,
                                            graph, limits));
  for (uint32_t i = 0; i < graph->node_count; i++)
    if (graph->nodes[i].type == SHELL_NODE_FD)
      for (uint32_t j = 0; j < i; j++)
        CHECK(graph->nodes[j].type != SHELL_NODE_FD ||
              graph->nodes[j].fd.number != graph->nodes[i].fd.number);
}

static uint32_t boundary_implicit_input(const shell_dep_graph_t *graph) {
  uint32_t result = UINT32_MAX;
  for (uint32_t node = 0; node < graph->node_count; node++)
    if (graph->nodes[node].type == SHELL_NODE_DOC &&
        (graph->nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT)) {
      CHECK(result == UINT32_MAX);
      result = node;
      CHECK(graph->nodes[node].doc.kind == SHELL_DOC_FILE);
      CHECK(graph->nodes[node].doc.flags == SHELL_DEP_DOC_FLAG_IMPLICIT);
      CHECK(graph->nodes[node].doc.path_len == 9);
      CHECK(!memcmp(graph->nodes[node].doc.path, "/dev/null", 9));
      CHECK(graph->nodes[node].doc.value == NULL &&
            graph->nodes[node].doc.name == NULL);
      bool used = false;
      for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
        CHECK(graph->edges[edge].to != node);
        if (graph->edges[edge].from == node) {
          CHECK(graph->edges[edge].type == SHELL_EDGE_READ);
          used = true;
        }
      }
      CHECK(used);
    }
  return result;
}

static bool boundary_reads_implicit(const shell_dep_graph_t *graph,
                                    uint32_t owner, uint32_t fd) {
  uint32_t input = boundary_implicit_input(graph);
  for (;;) {
    uint32_t parent = UINT32_MAX;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      if (item->type == SHELL_EDGE_READ && item->from == input &&
          item->to == owner && item->target_fd == fd)
        return true;
      if (item->type == SHELL_EDGE_GROUP && item->to == owner)
        parent = item->from;
    }
    if (parent == UINT32_MAX)
      return false;
    owner = parent;
  }
}

static void boundary_background_newlines(shell_dep_limits_t *limits,
                                         shell_dep_graph_t *graph,
                                         shell_dep_graph_t *other) {
  static const char *const separators[] = {" ", "\n", " # note\n", "\n\n"};
  static const struct {
    const char *source;
    bool implicit;
  } stages[] = {{"wc -c", true},          {"true | wc -c", false},
                {"true |& wc -c", false}, {"time wc -c", true},
                {"true && wc -c", true},  {"false || wc -c", true},
                {"{ wc -c; }", true},     {"(wc -c)", true}};
  for (size_t stage = 0; stage < sizeof(stages) / sizeof(stages[0]); stage++)
    for (size_t separator = 0;
         separator < sizeof(separators) / sizeof(separators[0]); separator++) {
      char source[256];
      snprintf(source, sizeof(source), "%s &%swait", stages[stage].source,
               separators[separator]);
      boundary_parse(source, limits, graph);
      uint32_t wc = boundary_command(graph, "wc"),
               wait = boundary_command(graph, "wait");
      CHECK(wc != UINT32_MAX && wait != UINT32_MAX);
      CHECK(graph->nodes[wc].cmd.backgrounded &&
            !graph->nodes[wait].cmd.backgrounded);
      CHECK(boundary_implicit_input(graph) != UINT32_MAX);
      if (boundary_reads_implicit(graph, wc, 0) != stages[stage].implicit)
        fprintf(stderr, "background stdin case: %s\n", source);
      CHECK(boundary_reads_implicit(graph, wc, 0) == stages[stage].implicit);
      CHECK(!boundary_reads_implicit(graph, wait, 0) &&
            boundary_route(graph, wait, 0, true, 0));
      unsigned backgrounds = 0;
      for (uint32_t edge = 0; edge < graph->edge_count; edge++)
        if (graph->edges[edge].type == SHELL_EDGE_BACKGROUND) {
          CHECK(graph->edges[edge].to == wait);
          backgrounds++;
        }
      CHECK(backgrounds == 1);
      shell_parse_result_t fast;
      CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
      CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", limits,
                                            &fast, other) == SHELL_DEP_OK);
      CHECK(shellsplit_test_graph_equal(graph, other));
    }

  static const char *const recursive[] = {
      "printf '%%s' \"$(wc -c &%swait)\"", "cat <(wc -c &%swait)",
      "{ wc -c &%swait; }", "(wc -c &%swait)"};
  for (size_t item = 0; item < sizeof(recursive) / sizeof(recursive[0]); item++)
    for (size_t separator = 0;
         separator < sizeof(separators) / sizeof(separators[0]); separator++) {
      char source[256];
      snprintf(source, sizeof(source), recursive[item], separators[separator]);
      boundary_parse(source, limits, graph);
      CHECK(boundary_reads_implicit(graph, boundary_command(graph, "wc"), 0));
      uint32_t wait = boundary_command(graph, "wait");
      unsigned backgrounds = 0;
      for (uint32_t edge = 0; edge < graph->edge_count; edge++)
        backgrounds += graph->edges[edge].type == SHELL_EDGE_BACKGROUND &&
                       graph->edges[edge].to == wait;
      CHECK(backgrounds == 1);
      shell_parse_result_t fast;
      CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
      CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", limits,
                                            &fast, other) == SHELL_DEP_OK);
      CHECK(shellsplit_test_graph_equal(graph, other));
    }

  static const char *const tails[] = {"\n", " # end\n", "\n\n# end\n"};
  for (size_t tail = 0; tail < sizeof(tails) / sizeof(tails[0]); tail++) {
    char source[128];
    snprintf(source, sizeof(source), "wc -c &%s", tails[tail]);
    boundary_parse(source, limits, graph);
    CHECK(graph->nodes[boundary_command(graph, "wc")].cmd.backgrounded);
    CHECK(boundary_reads_implicit(graph, boundary_command(graph, "wc"), 0));
  }

  static const char *const documents[] = {"wc -c 3<<EOF &\nbody\nEOF\nwait",
                                          "wc -c 3<<<body & # note\n\nwait"};
  for (size_t item = 0; item < sizeof(documents) / sizeof(documents[0]);
       item++) {
    boundary_parse(documents[item], limits, graph);
    CHECK(!boundary_reads_implicit(graph, boundary_command(graph, "wc"), 0));
    uint32_t wait = boundary_command(graph, "wait");
    unsigned backgrounds = 0;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++)
      backgrounds += graph->edges[edge].type == SHELL_EDGE_BACKGROUND &&
                     graph->edges[edge].to == wait;
    CHECK(backgrounds == 1 && boundary_route(graph, wait, 0, true, 0));
  }

  static const char *const isolated[] = {
      "exec 0<&- && true &%scat", "false || exec 0<&- &%scat",
      "cd /tmp && true &%scat", "cd /tmp && exec 0<&- &%scat",
      "exec 0<&- && true &%scd /tmp && true &\ncat"};
  for (size_t item = 0; item < sizeof(isolated) / sizeof(isolated[0]); item++)
    for (size_t separator = 0;
         separator < sizeof(separators) / sizeof(separators[0]); separator++) {
      char source[256];
      snprintf(source, sizeof(source), isolated[item], separators[separator]);
      boundary_parse(source, limits, graph);
      uint32_t cat = boundary_command(graph, "cat");
      CHECK(cat != UINT32_MAX && boundary_route(graph, cat, 0, true, 0));
      CHECK(!boundary_reads_implicit(graph, cat, 0));
      CHECK(
          graph->nodes[cat].cmd.cwd_known &&
          !strcmp(graph->cwd_buf.data + graph->nodes[cat].cmd.cwd_offset, "/"));
    }

  /* A newline after `&` retains its source span but advances Bash's input
   * unit. Newlines after binary connectors remain in the current unit. */
  static const struct {
    const char *source;
    uint16_t connector;
    uint32_t input_unit;
  } connectors[] = {{"wc &\nwait", SHELL_TYPE_BACKGROUND, 1},
                    {"wc & # note\n\nwait", SHELL_TYPE_BACKGROUND, 2},
                    {"true |\nwc", SHELL_TYPE_PIPELINE, 0},
                    {"true |&\nwc", SHELL_TYPE_PIPELINE, 0},
                    {"true &&\nwc", SHELL_TYPE_AND, 0},
                    {"false ||\nwc", SHELL_TYPE_OR, 0}};
  for (size_t item = 0; item < sizeof(connectors) / sizeof(connectors[0]);
       item++) {
    shell_parse_result_t fast;
    shell_pipeline_index_t index;
    const char *source = connectors[item].source;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    CHECK(fast.count == 2);
    shell_pipeline_index_connectors(source, strlen(source), &fast, &index);
    CHECK(index.range_successor[0] == connectors[item].connector);
    CHECK(index.range_connector[1] == connectors[item].connector);
    CHECK(index.range_input_unit[0] == 0 &&
          index.range_input_unit[1] == connectors[item].input_unit);
  }
  /* A separator after a closed group must not reassign the pipeline head's
   * successor. Newline-separated lists match their one-line spelling. */
  static const struct {
    const char *lines;
    const char *inline_source;
  } after_group[] = {
      {"cd /tmp | (:);\ncat", "cd /tmp | (:); cat"},
      {"cd /tmp | { :; };\ncat", "cd /tmp | { :; }; cat"},
      {"cd /tmp | (:);\n\ncat", "cd /tmp | (:); cat"},
      {"cd /tmp | (:)\n\ncat", "cd /tmp | (:); cat"},
  };
  for (size_t item = 0; item < sizeof(after_group) / sizeof(after_group[0]);
       item++) {
    shell_parse_result_t fast;
    shell_pipeline_index_t index;
    const char *source = after_group[item].lines;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    shell_pipeline_index_connectors(source, strlen(source), &fast, &index);
    CHECK(index.range_successor[0] == SHELL_TYPE_PIPELINE &&
          index.group_connector[0] == SHELL_TYPE_PIPELINE);
    boundary_parse(source, limits, graph);
    uint32_t cat = boundary_command(graph, "cat");
    CHECK(cat != UINT32_MAX && graph->nodes[cat].cmd.cwd_known &&
          !strcmp(graph->cwd_buf.data + graph->nodes[cat].cmd.cwd_offset, "/"));
    boundary_parse(after_group[item].inline_source, limits, other);
    CHECK(graph->node_count == other->node_count &&
          graph->edge_count == other->edge_count);
  }
  static const char group_source[] = "wc & # note\n\n{ wait; }";
  shell_parse_result_t fast;
  shell_pipeline_index_t index;
  CHECK(shell_parse_fast(group_source, sizeof(group_source) - 1, NULL, &fast) ==
        SHELL_OK);
  CHECK(fast.group_count == 1);
  shell_pipeline_index_connectors(group_source, sizeof(group_source) - 1, &fast,
                                  &index);
  CHECK(index.group_connector[0] == SHELL_TYPE_BACKGROUND &&
        index.group_connector_start[0] == 3 &&
        index.group_connector_end[0] == 4 && index.group_input_unit[0] == 2);
}

static void boundary_async_completion(shell_dep_limits_t *limits,
                                      shell_dep_graph_t *graph,
                                      shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    bool reached;
  } cases[] = {
      {"{ false & } || printf bad >out", false},
      {"{ true & } || printf bad >out", false},
      {"{ exit 1 & } || printf bad >out", false},
      {"{ false & } && printf good >out", true},
      {"{ false & } && true || printf bad >out", false},
      {"{ false && true & } || printf bad >out", false},
      {"{ false || true & } || printf bad >out", false},
      {"{ { false; } & } || printf bad >out", false},
      {"{ (false) & } || printf bad >out", false},
      {"{ false | true & } || printf bad >out", false},
      {"{ time false & } || printf bad >out", false},
      {"{ ! true & } || printf bad >out", false},
      {"(false &) || printf bad >out", false},
      {"(false &) && printf good >out", true},
      {"{ { false & }; } || printf bad >out", false},
      {"{ (false &); } || printf bad >out", false},
      {"! { false & } && printf bad >out", false},
      {"! { false & } || printf good >out", true},
      {"time { false & } || printf bad >out", false},
      {"{ false &\n} || printf bad >out", false},
      {"{ false & # note\n\n} || printf bad >out", false},
      {"{ false & } || { printf bad >out; }", false},
      {"echo \"$( { false & } || printf bad >out )\"", false},
      {"echo \"$( { false & } && printf good >out )\"", true},
      {"cat <({ false & } || printf bad >out)", false},
      {"{ false; } || printf good >out", true},
      {"{ true; } || printf bad >out", false},
      {"{ false & true; } || printf bad >out", false},
      {"{ true & false; } || printf good >out", true},
      {"exit 0; { false & } && printf bad >out", false},
      {"UID=1; { false & } && printf bad >out", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    boundary_parse(cases[i].source, limits, graph);
    uint32_t marker = boundary_command(graph, "printf");
    CHECK(marker != UINT32_MAX);
    bool effects = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      if ((item->type == SHELL_EDGE_READ && item->to == marker) ||
          (item->type == SHELL_EDGE_WRITE && item->from == marker))
        effects = true;
    }
    if (effects != cases[i].reached) {
      fprintf(stderr, "asynchronous completion: %s\n", cases[i].source);
      shell_dep_graph_dump(graph, stderr);
    }
    CHECK(effects == cases[i].reached);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                           &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(cases[i].source,
                                          strlen(cases[i].source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
  }
  boundary_parse("{ false & } || exec 0<&-; cat", limits, graph);
  CHECK(boundary_route(graph, boundary_command(graph, "cat"), 0, true, 0));
  for (uint32_t edge = 0; edge < graph->edge_count; edge++)
    CHECK(graph->edges[edge].type != SHELL_EDGE_FD_CLOSE);
  boundary_parse("{ false & } || cd /tmp; cat", limits, graph);
  uint32_t cat = boundary_command(graph, "cat");
  CHECK(cat != UINT32_MAX && graph->nodes[cat].cmd.cwd_known &&
        !strcmp(graph->cwd_buf.data + graph->nodes[cat].cmd.cwd_offset, "/"));
  boundary_parse("{ false & } || export MARK=value; cat", limits, graph);
  for (uint32_t edge = 0; edge < graph->edge_count; edge++)
    CHECK(graph->edges[edge].type != SHELL_EDGE_ENV);
}

static void boundary_standard_directions(shell_dep_limits_t *limits,
                                         shell_dep_graph_t *graph,
                                         shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    uint32_t local_fd, inherited;
    bool input, group;
  } cases[] = {
      {"wc 0>&1", 0, 1, false, false},
      {"wc 1<&0", 1, 0, true, false},
      {"wc 2<&0", 2, 0, true, false},
      {"wc 0>&1 1>&-", 0, 1, false, false},
      {"wc 1<&0 0<&-", 1, 0, true, false},
      {"wc 0>&1 0>&-", 0, SHELL_DEP_FD_NONE, false, false},
      {"wc 1<&0 1<&-", 1, SHELL_DEP_FD_NONE, true, false},
      {"wc 0>&1 0>&2", 0, 2, false, false},
      {"wc 1<&0 1<&2", 1, 2, true, false},
      {"exec 0>&1; wc", 0, 1, false, false},
      {"exec 1<&0; wc", 1, 0, true, false},
      {"exec 3>&1; wc 0>&3-", 0, 1, false, false},
      /* A self move leaves the descriptor unchanged and needs no sparse use. */
      {"wc 0>&0-", 0, SHELL_DEP_FD_NONE, false, false},
      {"{ wc; } 0>&1", 0, 1, false, true},
      {"{ wc; } 1<&0", 1, 0, true, true},
      {"echo \"$(wc 1<&0)\"", 1, 0, true, false},
      {"cat <(wc 1<&0)", 1, 0, true, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    boundary_parse(cases[i].source, limits, graph);
    uint32_t owner = boundary_command(graph, "wc");
    CHECK(owner != UINT32_MAX);
    if (cases[i].group)
      for (uint32_t edge = 0; edge < graph->edge_count; edge++)
        if (graph->edges[edge].type == SHELL_EDGE_GROUP &&
            graph->edges[edge].to == owner) {
          owner = graph->edges[edge].from;
          break;
        }
    unsigned count = 0;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      if (item->type != (cases[i].input ? SHELL_EDGE_READ : SHELL_EDGE_WRITE) ||
          (cases[i].input ? item->to : item->from) != owner ||
          (cases[i].input ? item->target_fd : item->source_fd) !=
              cases[i].local_fd)
        continue;
      const shell_dep_node_t *resource =
          &graph->nodes[cases[i].input ? item->from : item->to];
      CHECK(resource->type == SHELL_NODE_FD &&
            resource->fd.number == cases[i].inherited);
      count++;
    }
    if (count != (cases[i].inherited != SHELL_DEP_FD_NONE ? 1u : 0u)) {
      fprintf(stderr, "standard direction case: %s\n", cases[i].source);
      shell_dep_graph_dump(graph, stderr);
    }
    CHECK(count == (cases[i].inherited != SHELL_DEP_FD_NONE ? 1u : 0u));
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                           &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(cases[i].source,
                                          strlen(cases[i].source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
  }

  static const struct {
    const char *source;
    bool input;
    uint32_t fd;
  } files[] = {{"wc 0>out", false, 0},
               {"wc 1<input", true, 1},
               {"wc 2<input", true, 2},
               {"wc 0<input 1>&0", true, 1},
               {"wc 0<input 1<&0-", true, 1}};
  for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
    boundary_parse(files[i].source, limits, graph);
    uint32_t owner = boundary_command(graph, "wc");
    unsigned count = 0;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      /* Opening read-only stderr can itself fail before installing that
       * route. Its shell diagnostic still uses the inherited writable fd 2. */
      bool setup_diagnostic = files[i].fd == 2 &&
                              item->type == SHELL_EDGE_WRITE &&
                              item->from == owner && item->source_fd == 2 &&
                              graph->nodes[item->to].type == SHELL_NODE_FD;
      CHECK(setup_diagnostic ||
            !(item->type ==
                  (files[i].input ? SHELL_EDGE_WRITE : SHELL_EDGE_READ) &&
              (files[i].input ? item->from : item->to) == owner &&
              (files[i].input ? item->source_fd : item->target_fd) ==
                  files[i].fd));
      if (item->type == (files[i].input ? SHELL_EDGE_READ : SHELL_EDGE_WRITE) &&
          (files[i].input ? item->to : item->from) == owner &&
          (files[i].input ? item->target_fd : item->source_fd) == files[i].fd) {
        CHECK(graph->nodes[files[i].input ? item->from : item->to].type ==
              SHELL_NODE_DOC);
        count++;
      }
    }
    CHECK(count == 1);
  }
  boundary_parse("wc 0>&1 | cat", limits, graph);
  uint32_t writer = boundary_command(graph, "wc"),
           reader = boundary_command(graph, "cat");
  unsigned copies = 0;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->type == SHELL_EDGE_PIPE && item->from == writer &&
        item->to == reader && item->source_fd == 0 && item->target_fd == 0)
      copies++;
  }
  CHECK(copies == 1);
  boundary_parse("echo \"$(wc 0>&1)\"", limits, graph);
  writer = boundary_command(graph, "wc");
  copies = 0;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->from == writer && item->source_fd == 0 &&
        (item->type == SHELL_EDGE_WRITE || item->type == SHELL_EDGE_SUBST))
      copies++;
  }
  CHECK(copies == 1);
}

static void boundary_async_inputs(shell_dep_limits_t *limits,
                                  shell_dep_graph_t *graph,
                                  shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    bool implicit;
  } cases[] = {
      {"wc -c &", true},
      {"wc -c <&0 &", false},
      {"wc -c 3<&0 &", true},
      {"wc -c 3</dev/null &", false},
      {": 3<<<\"$(wc -c)\" &", false},
      {"{ wc -c; } 3<<<value &", false},
      {"wc -c 0>&0 &", true},
      {"wc -c 0>&- &", false},
      {"wc -c 3<&0 0<&3- &", true},
      {"wc -c 3<&0 0<&\"3\"- &", true},
      {"wc -c 3<&0 0<&3\\- &", true},
      {"{ wc -c <&0; } &", true},
      {"{ wc -c & } &", true},
      {"{ { wc -c; } & } &", true},
      {"{ wc -c; } <&0 &", false},
      {"{ wc -c & wait; } <&0", false},
      {"{ :; } <&0; wc -c &", false},
      {"{ :; } <&0\nwc -c &", false},
      {"{ :; } <&0; (true); wc -c &", false},
      {"{ :; } <&0; (wc -c & wait)", true},
      {"{ :; } <&0; { :; } 2>&1; wc -c &", true},
      {"cat | { wc -c & wait; }", false},
      {"{ :; } <&0; true | (true); wc -c &", false},
      {"cat <(wc -c)", false},
      {"printf '%s' \"$(wc -c)\" &", false},
      {"value=$(wc -c) &", false},
      {"! printf '%s' \"$(wc -c)\" &", false},
      {"printf '%s' \"$(wc -c)\" | cat &", false},
      {"time printf '%s' \"$(wc -c)\" &", true},
      {"true && printf '%s' \"$(wc -c)\" &", true},
      {"false || printf '%s' \"$(wc -c)\" &", true},
      {": 3>\"$(wc -c >&2; printf /dev/null)\" &", true},
      {"{ { printf '%s' \"$(wc -c)\"; }; } &", true},
      {"exec {fd}<&0; wc -c <&$fd &", false},
      {"UID=1\nwc -c & wait", true},
      {"UID=1\ntime wc -c & wait", true},
      {"UID=1\n{ wc -c; } & wait", true},
      {"UID=1\ntrue && wc -c & wait", true},
      {"UID=1\nfalse || wc -c & wait", true},
      {"UID=1\ntrue && printf '%s' \"$(wc -c)\" & wait", true},
      {"UID=1\nvalue=$(wc -c) & wait", false},
      {"UID=1\n: 3>\"$(wc -c >&2; printf /dev/null)\" & wait", true},
      {"UID=1; time wc -c & wait", false},
      {"UID=1; : &\nwc -c &\nwait", true},
      {"UID=1; : & # note\n\nwc -c &\nwait", true},
      {"UID=1; { :; } &\nwc -c &\nwait", true},
      {"UID=1; time : &\nwc -c &\nwait", true},
      {"UID=1; : &\ntrue && wc -c &\nwait", true},
      {"UID=1; : & wc -c &\nwait", false},
      {"exit 0; : &\nwc -c &\nwait", false},
      {"exit 0\ntime wc -c & wait", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    boundary_parse(cases[i].source, limits, graph);
    uint32_t wc = boundary_command(graph, "wc");
    CHECK(wc != UINT32_MAX);
    if (boundary_reads_implicit(graph, wc, 0) != cases[i].implicit)
      fprintf(stderr, "async case: %s\n", cases[i].source);
    CHECK(boundary_reads_implicit(graph, wc, 0) == cases[i].implicit);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                           &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(cases[i].source,
                                          strlen(cases[i].source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
  }
  boundary_parse("wc -c &", limits, graph);
  uint32_t wc = boundary_command(graph, "wc");
  CHECK(boundary_route(graph, wc, 0, true,
                       0)); /* Nonfatal implicit-open failure. */
  CHECK(boundary_reads_implicit(graph, wc, 0));
  uint32_t implicit = boundary_implicit_input(graph);
  *other = *graph;
  other->nodes[implicit].doc.path = NULL;
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->nodes[implicit].doc.flags |= SHELL_DEP_DOC_FLAG_TRANSIENT;
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->nodes[other->node_count++] = graph->nodes[implicit];
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->edges[other->edge_count - 1].type = SHELL_EDGE_WRITE;
  CHECK(!shell_dep_graph_validate(other).valid);
  boundary_parse("wc -c 3<&0 &", limits, graph);
  CHECK(boundary_reads_implicit(graph, boundary_command(graph, "wc"), 3));
  boundary_parse("wc -c & cat", limits, graph);
  CHECK(!boundary_reads_implicit(graph, boundary_command(graph, "cat"), 0));
  CHECK(boundary_route(graph, boundary_command(graph, "cat"), 0, true, 0));
  boundary_parse("true && exec 0<&- & cat", limits, graph);
  CHECK(boundary_route(graph, boundary_command(graph, "cat"), 0, true, 0));
  CHECK(!boundary_reads_implicit(graph, boundary_command(graph, "cat"), 0));
  boundary_parse("cd /tmp && true & cat", limits, graph);
  uint32_t cat = boundary_command(graph, "cat");
  CHECK(graph->nodes[cat].cmd.cwd_known &&
        !strcmp(graph->cwd_buf.data + graph->nodes[cat].cmd.cwd_offset, "/"));
  boundary_parse("exec 0<before || exit; UID=1\n"
                 "cd /tmp && true & cat",
                 limits, graph);
  cat = boundary_command(graph, "cat");
  CHECK(graph->nodes[cat].cmd.cwd_known &&
        !strcmp(graph->cwd_buf.data + graph->nodes[cat].cmd.cwd_offset, "/"));
  unsigned parent_reads = 0;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->type == SHELL_EDGE_READ && item->to == cat &&
        item->target_fd == 0) {
      const shell_dep_node_t *resource = &graph->nodes[item->from];
      CHECK(resource->type == SHELL_NODE_DOC && resource->doc.path_len == 6 &&
            !memcmp(resource->doc.path, "before", 6));
      parent_reads++;
    }
  }
  CHECK(parent_reads == 1 && !boundary_reads_implicit(graph, cat, 0));
  boundary_parse("true || wc -c &", limits, graph);
  CHECK(boundary_implicit_input(graph) !=
        UINT32_MAX); /* true executes in the wrapper. */
  boundary_parse("false && { wc; } &", limits, graph);
  CHECK(!boundary_reads_implicit(graph, boundary_command(graph, "wc"), 0));
  boundary_parse("exec 0<&-; wc -c &", limits, graph);
  CHECK(boundary_reads_implicit(graph, boundary_command(graph, "wc"), 0));
  boundary_parse(">out &", limits, graph);
  CHECK(boundary_implicit_input(graph) == UINT32_MAX);
  boundary_parse("exec 2>&1 &", limits, graph);
  CHECK(boundary_implicit_input(graph) == UINT32_MAX);
  boundary_parse("time { exec 2<&0; wc; } &", limits, graph);
  CHECK(boundary_reads_implicit(graph, boundary_command(graph, "wc"), 0));
  bool unavailable = false;
  for (uint32_t node = 0; node < graph->node_count; node++)
    if (graph->nodes[node].type == SHELL_NODE_TIME)
      unavailable |= (graph->nodes[node].time.report_route_flags &
                      SHELL_TIME_REPORT_ROUTE_UNAVAILABLE) != 0;
  CHECK(unavailable);
  boundary_parse("{ : >& }; wc; }", limits, graph);
  bool literal_closer = false;
  for (uint32_t node = 0; node < graph->node_count; node++)
    literal_closer |= graph->nodes[node].type == SHELL_NODE_DOC &&
                      graph->nodes[node].doc.kind == SHELL_DOC_FILE &&
                      graph->nodes[node].doc.path_len == 1 &&
                      graph->nodes[node].doc.path[0] == '}';
  CHECK(literal_closer);
  static const char malformed[] = "{ wc && }";
  CHECK(shell_dep_graph_parse(malformed, sizeof(malformed) - 1, "/", limits,
                              graph) == SHELL_DEP_EPARSE);
  CHECK(graph->node_count == 0 && graph->edge_count == 0);
}

static void boundary_timing_destinations(shell_dep_limits_t *limits,
                                         shell_dep_graph_t *graph,
                                         shell_dep_graph_t *other) {
  static const char source[] = "probe && exec 2>&1; time wc";
  boundary_parse(source, limits, graph);
  uint32_t timer = UINT32_MAX, first = UINT32_MAX, second = UINT32_MAX;
  uint32_t unused_destination = UINT32_MAX;
  for (uint32_t node = 0; node < graph->node_count; node++) {
    if (graph->nodes[node].type == SHELL_NODE_TIME)
      timer = node;
    if (graph->nodes[node].type == SHELL_NODE_FD &&
        graph->nodes[node].fd.number == 0)
      unused_destination = node;
  }
  CHECK(timer != UINT32_MAX && unused_destination != UINT32_MAX);
  CHECK(graph->nodes[timer].time.report_external_fd_count == 2);
  for (uint32_t edge = 0; edge < graph->edge_count; edge++)
    if (graph->edges[edge].from == timer &&
        graph->edges[edge].type == SHELL_EDGE_WRITE &&
        graph->nodes[graph->edges[edge].to].type == SHELL_NODE_FD) {
      if (first == UINT32_MAX)
        first = edge;
      else {
        CHECK(second == UINT32_MAX);
        second = edge;
      }
    }
  CHECK(first != UINT32_MAX && second != UINT32_MAX);
  *other = *graph;
  other->edges[second].to = other->edges[first].to;
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->edges[second] = other->edges[--other->edge_count];
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->edges[second].to = unused_destination;
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  shell_dep_time_t *time = &other->nodes[timer].time;
  uint32_t swap = time->report_external_fds[0];
  time->report_external_fds[0] = time->report_external_fds[1];
  time->report_external_fds[1] = swap;
  CHECK(shell_dep_graph_validate(other).valid);
  CHECK(shellsplit_test_depgraph_invariants(source, sizeof(source) - 1,
                                            SHELL_DEP_OK, other, limits));
  *other = *graph;
  other->edges[second] = other->edges[--other->edge_count];
  time = &other->nodes[timer].time;
  time->report_external_fd_count = 1;
  time->report_external_fds[0] = other->nodes[other->edges[first].to].fd.number;
  time->report_route_flags |= SHELL_TIME_REPORT_ROUTE_UNKNOWN;
  other->status = SHELL_DEP_STATUS_TRUNCATED;
  CHECK(shell_dep_graph_validate(other).valid);
  CHECK(shellsplit_test_depgraph_invariants(source, sizeof(source) - 1,
                                            SHELL_DEP_ETRUNC, other, limits));
}

typedef struct {
  const char *word;
  unsigned calls;
} boundary_recovery_resolution_t;

static shell_expand_status_t
boundary_recovery_resolve(const shell_expand_word_request_t *request,
                          const char **netargv, size_t *length, void *context) {
  boundary_recovery_resolution_t *fixture = context;
  CHECK(request->purpose == SHELL_EXPAND_WORD_REDIRECT_PATH);
  CHECK(request->source + request->word_offset == fixture->word &&
        request->word_length == strlen("\"$(wc -c)\""));
  CHECK(request->cwd_known && request->cwd_absolute &&
        !strcmp(request->cwd, "/"));
  fixture->calls++;
  *netargv = "3:out,";
  *length = sizeof("3:out,") - 1;
  return SHELL_EXPAND_RESOLVED;
}

static void boundary_recovery_resolution(shell_dep_limits_t *limits,
                                         shell_dep_graph_t *graph,
                                         shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    unsigned calls;
    bool implicit;
  } cases[] = {
      {"UID=1\ntime : >\"$(wc -c)\" & cat", 1, true},
      {"UID=1\ntrue && : >\"$(wc -c)\" & cat", 1, true},
      {"{ false & } || : >\"$(wc -c)\"; cat", 0, false},
      {"(false &) || : >\"$(wc -c)\"; cat", 0, false},
      {"{ { false & }; } || : >\"$(wc -c)\"; cat", 0, false},
      {"{ false & } && : >\"$(wc -c)\"; cat", 1, false},
      {"! { false & } || : >\"$(wc -c)\"; cat", 1, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    boundary_recovery_resolution_t fixture = {strstr(source, "\"$(wc -c)\""),
                                              0};
    uint8_t unresolved[SHELL_DEP_MAX_NODES];
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                         graph, boundary_recovery_resolve,
                                         &fixture, unresolved) == SHELL_DEP_OK);
    CHECK(fixture.calls == cases[i].calls &&
          shell_dep_graph_validate(graph).valid);
    CHECK(boundary_reads_implicit(graph, boundary_command(graph, "wc"), 0) ==
          cases[i].implicit);
    CHECK(!boundary_reads_implicit(graph, boundary_command(graph, "cat"), 0));
    if (!cases[i].calls)
      for (uint32_t edge = 0; edge < graph->edge_count; edge++)
        CHECK(graph->edges[edge].type != SHELL_EDGE_SUBST);
    for (uint32_t node = 0; node < SHELL_DEP_MAX_NODES; node++)
      CHECK(unresolved[node] == 0);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    fixture.calls = 0;
    shell_expand_cache_t cache;
    shell_dep_limits_t graph_limits = *limits;
    CHECK(shell_expand_cache_init(
        boundary_recovery_resolve, &fixture, source, strlen(source), false,
        limits->workspace, limits->workspace_size, &cache,
        &graph_limits.workspace, &graph_limits.workspace_size));
    shell_dep_word_resolver_t resolver = {shell_expand_resolve, &cache};
    CHECK(shell_dep_graph_parse_with_fast_resolver(
              source, strlen(source), "/", &graph_limits, &fast, other,
              &resolver, unresolved) == SHELL_DEP_OK);
    CHECK(cache.error == SHELL_DEP_OK && fixture.calls == cases[i].calls &&
          shellsplit_test_graph_equal(graph, other));
  }
}

typedef struct {
  const char *netargv;
  shell_expand_status_t status;
  unsigned paths, later;
} boundary_diagnostic_resolution_t;

static shell_expand_status_t
boundary_diagnostic_resolve(const shell_expand_word_request_t *request,
                            const char **netargv, size_t *length,
                            void *context) {
  boundary_diagnostic_resolution_t *fixture = context;
  if (request->purpose != SHELL_EXPAND_WORD_REDIRECT_PATH)
    return SHELL_EXPAND_UNRESOLVED;
  const char *word = request->source + request->word_offset;
  if (request->word_length == 7 && !memcmp(word, "\"$path\"", 7)) {
    fixture->paths++;
    if (fixture->status == SHELL_EXPAND_RESOLVED) {
      *netargv = fixture->netargv;
      *length = strlen(*netargv);
    }
    return fixture->status;
  }
  CHECK(request->word_length == 8 && !memcmp(word, "\"$later\"", 8));
  fixture->later++;
  *netargv = "4:next,";
  *length = 7;
  return SHELL_EXPAND_RESOLVED;
}

static void boundary_diagnostic_resolution(shell_dep_limits_t *limits,
                                           shell_dep_graph_t *graph,
                                           shell_dep_graph_t *other) {
  static const struct {
    const char *value;
    shell_expand_status_t status;
    bool stopped;
  } cases[] = {{"", SHELL_EXPAND_RESOLVED, true},
               {"0:,", SHELL_EXPAND_RESOLVED, true},
               {"1:a,1:b,", SHELL_EXPAND_RESOLVED, true},
               {"3:out,", SHELL_EXPAND_RESOLVED, false},
               {NULL, SHELL_EXPAND_UNRESOLVED, false}};
  const char *source = "sh -c \"$(echo 2>&1 >\"$path\" >\"$later\")\"";
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    boundary_diagnostic_resolution_t fixture = {cases[i].value, cases[i].status,
                                                0, 0};
    uint8_t unresolved[SHELL_DEP_MAX_NODES];
    /* An empty or ambiguous resolved path certainly fails setup: a
     * shell-level error which no dependency graph models. */
    if (cases[i].stopped) {
      CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                           graph, boundary_diagnostic_resolve,
                                           &fixture,
                                           unresolved) == SHELL_DEP_EUNMODELED);
      CHECK(fixture.paths == 1 && fixture.later == 0);
      continue;
    }
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                         graph, boundary_diagnostic_resolve,
                                         &fixture, unresolved) == SHELL_DEP_OK);
    CHECK(fixture.paths == 1 && fixture.later == !cases[i].stopped);
    bool diagnostic = false, body = false;
    uint32_t echo = boundary_command(graph, "echo");
    for (uint32_t e = 0; e < graph->edge_count; e++) {
      const shell_dep_edge_t *edge = &graph->edges[e];
      diagnostic |= edge->type == SHELL_EDGE_SUBST && edge->from == echo &&
                    edge->source_fd == 2;
      body |= edge->type == SHELL_EDGE_READ && edge->to == echo;
    }
    CHECK(diagnostic && body == !cases[i].stopped);
    CHECK(shell_dep_graph_validate(graph).valid);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    fixture.paths = fixture.later = 0;
    shell_expand_cache_t cache;
    shell_dep_limits_t graph_limits = *limits;
    CHECK(shell_expand_cache_init(
        boundary_diagnostic_resolve, &fixture, source, strlen(source), false,
        limits->workspace, limits->workspace_size, &cache,
        &graph_limits.workspace, &graph_limits.workspace_size));
    shell_dep_word_resolver_t resolver = {shell_expand_resolve, &cache};
    CHECK(shell_dep_graph_parse_with_fast_resolver(
              source, strlen(source), "/", &graph_limits, &fast, other,
              &resolver, unresolved) == SHELL_DEP_OK);
    CHECK(fixture.paths == 1 && fixture.later == !cases[i].stopped);
    CHECK(shellsplit_test_graph_equal(graph, other));
  }
  boundary_diagnostic_resolution_t failure = {NULL, SHELL_EXPAND_FAILED, 0, 0};
  uint8_t unresolved[SHELL_DEP_MAX_NODES];
  CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                       graph, boundary_diagnostic_resolve,
                                       &failure,
                                       unresolved) == SHELL_DEP_EEXPAND);
  CHECK(failure.paths == 1 && failure.later == 0);
}

static void boundary_cd_commands(shell_dep_limits_t *limits,
                                 shell_dep_graph_t *graph,
                                 shell_dep_graph_t *other) {
  static const struct {
    const char *source, *spelling, *cwd;
  } cases[] = {
      {"cd /tmp; pwd", "cd", NULL},
      {"c'd' /tmp; pwd", "c'd'", NULL},
      {"command cd /tmp; pwd", "command", NULL},
      {"builtin cd /tmp; pwd", "builtin", NULL},
      {"cd one two; pwd", "cd", "/"},
      {"false && cd /tmp; pwd", "cd", "/"},
      {"(cd /tmp); pwd", "cd", "/"},
      {"cd /tmp | true; pwd", "cd", "/"},
      {"cd /tmp & pwd", "cd", "/"},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    boundary_parse(cases[i].source, limits, graph);
    uint32_t cd = boundary_command(graph, cases[i].spelling);
    uint32_t pwd = boundary_command(graph, "pwd");
    CHECK(cd != UINT32_MAX && pwd != UINT32_MAX);
    CHECK(graph->nodes[cd].cmd.cwd_known &&
          !strcmp(graph->cwd_buf.data + graph->nodes[cd].cmd.cwd_offset, "/"));
    CHECK(graph->nodes[pwd].cmd.cwd_known == (cases[i].cwd != NULL));
    if (cases[i].cwd)
      CHECK(!strcmp(graph->cwd_buf.data + graph->nodes[pwd].cmd.cwd_offset,
                    cases[i].cwd));
    bool cwd_edge = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++)
      cwd_edge |= graph->edges[edge].type == SHELL_EDGE_CWD &&
                  graph->edges[edge].from == cd && graph->edges[edge].to == cd;
    CHECK(cwd_edge == (i != 5));
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                           &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(cases[i].source,
                                          strlen(cases[i].source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
  }

  static const struct {
    const char *source;
    bool capture;
  } captures[] = {
      {"sh -c \"$(exec 2>&1; cd one two)\"", true},
      {"sh -c \"$(cd /; cd -)\"", true},
      {"sh -c \"$({ exec 2>&1; cd one two; })\"", true},
      {"sh -c \"$(exec 2>&1; command cd one two)\"", true},
      {"sh -c \"$(exec 2>&1; builtin cd one two)\"", true},
      {"sh -c \"$(exec 1>&- 2>&-; cd one two)\"", false},
      {"sh -c \"$(false >&- 2>&- && cd one two)\"", false},
  };
  for (size_t i = 0; i < sizeof(captures) / sizeof(captures[0]); i++) {
    const char *source = captures[i].source;
    boundary_parse(source, limits, graph);
    bool capture = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++)
      capture |= graph->edges[edge].type == SHELL_EDGE_SUBST;
    if (capture != captures[i].capture)
      fprintf(stderr, "cd capture: %s\n", source);
    CHECK(capture == captures[i].capture);
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                         other, NULL, NULL,
                                         NULL) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    for (uint32_t nodes = 0; nodes <= graph->node_count; nodes++)
      for (uint32_t edges = 0; edges <= graph->edge_count; edges++) {
        shell_dep_limits_t bounded = *limits;
        bounded.max_nodes = nodes;
        bounded.max_edges = edges;
        shell_dep_error_t status =
            shell_dep_graph_parse(source, strlen(source), "/", &bounded, other);
        CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        CHECK(other->node_count <= nodes && other->edge_count <= edges &&
              shell_dep_graph_validate(other).valid);
        if (status == SHELL_DEP_OK)
          CHECK(shellsplit_test_graph_equal(graph, other));
      }
  }

  boundary_parse("exec 2>error; cd one two", limits, graph);
  uint32_t cd = boundary_command(graph, "cd");
  bool stderr_file = false;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    const shell_dep_node_t *to = &graph->nodes[item->to];
    stderr_file |= item->type == SHELL_EDGE_WRITE && item->from == cd &&
                   item->source_fd == 2 && to->type == SHELL_NODE_DOC &&
                   to->doc.path_len == 5 && !memcmp(to->doc.path, "error", 5);
  }
  CHECK(stderr_file);
}

static void boundary_owner_stream_inventory(shell_dep_limits_t *limits,
                                            shell_dep_graph_t *graph,
                                            shell_dep_graph_t *other) {
  static const char *const cases[] = {
      "exec 30>&1; printf data 31>&30 31>&- 31>&30",
      "exec 30>&1; printf data 31>&30 | cat",
      "exec 30>out; printf data 31>&30",
      "exec 30>&1; { printf data 31>&30; } 2>&1",
      "sh -c \"$(exec 30>&1; printf data 31>&30 31>&- 31>&30)\"",
      "exec {fd}>&1; printf data >&$fd",
      "exec 30>&1; printf data 0>&30 1<&0 2>&-",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    boundary_parse(cases[i], limits, graph);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(cases[i], strlen(cases[i]), NULL, &fast) ==
          SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(cases[i], strlen(cases[i]), "/",
                                          limits, &fast,
                                          other) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    CHECK(shell_dep_graph_parse_resolved(cases[i], strlen(cases[i]), "/",
                                         limits, other, NULL, NULL,
                                         NULL) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    uint32_t owner = boundary_command(graph, "printf");
    CHECK(owner != UINT32_MAX);
    if (i < 2 || i == 3)
      CHECK(boundary_route(graph, owner, 31, false, 1));
    if (i == 6)
      CHECK(boundary_route(graph, owner, 0, false, 1) &&
            boundary_route(graph, owner, 1, false, 1) &&
            !boundary_route(graph, owner, 2, false, 2));
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  for (unsigned family = 0; family < 2; family++) {
    size_t previous = 0;
    for (unsigned count = 4; count <= 32; count *= 2) {
      char source[2048] = "";
      size_t length = 0;
      for (unsigned i = 0; i < count; i++)
        length += (size_t)snprintf(source + length, sizeof(source) - length,
                                   "exec %u>&1; %s", 30 + i,
                                   family == 0 ? ":; " : "");
      if (family == 1)
        for (unsigned i = 0; i < count; i++)
          strcat(source, ":; ");
      shellsplit_test_source_scan_reset();
      boundary_parse(source, limits, graph);
      size_t work =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_OWNER_STREAMS);
      CHECK(work > 0 && work <= 96 * count &&
            (!previous || work <= 3 * previous));
      previous = work;
    }
  }
#endif
}

static void boundary_assignment_effects(shell_dep_limits_t *limits,
                                        shell_dep_graph_t *graph,
                                        shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    uint32_t environments, substitutions;
  } cases[] = {
      {"UID=1 true", 0, 0},
      {"UID+=1 true", 0, 0},
      {"U\\\nID=1 true", 0, 0},
      {"UID=1 command true", 0, 0},
      {"UID=1 builtin true", 0, 0},
      {"first=ok UID=1 last=ok true", 2, 0},
      {"first=ok UID=1 last=ok", 1, 0},
      {"UID=1 EUID=2 true", 0, 0},
      {"x=$(printf data) UID=$(printf ignored) last=ok true", 2, 1},
      {"UID=$(printf skipped) true", 0, 0},
      {"UID=$(printf data) $missing", 0, 1},
      {"UID=$(printf data) $(true)", 0, 2},
      {"UID=$(printf marker >&2; printf data) $(true)", 0, 2},
      {"UID=$(printf data) $first $second", 0, 1},
      {"UID=$(printf data) \"$@\"", 0, 1},
      {"UID=$(printf data) \"${!prefix@}\"", 0, 1},
      {"UID=$(printf data) ${!prefix*}", 0, 1},
      {"UID=$(printf data) ${@:-}", 0, 1},
      {"UID=$(printf data) \"${@:+data}\"", 0, 1},
      {"UID=$(printf data) \"${@:99}\"", 0, 1},
      {"UID=$(printf skipped) \"${!prefix*}\"", 0, 0},
      {"UID=$(printf skipped) \"${!pre\\\nfix\\\n*}\"", 0, 0},
      {"UID=$(printf skipped) \"${@-data}\"", 0, 0},
      {"UID=$(printf skipped) \"${@:-data}\"", 0, 0},
      {"UID=$(printf skipped) \"${@-}\"", 0, 0},
      {"UID=$(printf skipped) \"${@:-}\"", 0, 0},
      {"UID=$(printf skipped) \"${@:-\"$@\"}\"", 0, 0},
      {"UID=$(printf skipped) \"${@?error}\"", 0, 0},
      {"UID=$(printf skipped) \"${@:?error}\"", 0, 0},
      {"UID=$(printf skipped) \"${\\\n@:\\\n-data}\"", 0, 0},
      {"UID=$(printf skipped) \"${!prefix@}\"suffix", 0, 0},
      {"UID=$(printf data) {,}", 0, 1},
      {"UID=$(printf skipped) \"$missing\"", 0, 0},
      {"UID=$(printf skipped) \"${missing:-}\"", 0, 0},
      {"UID=$(printf skipped) \"$(true)\"", 0, 1},
      {"UID=$(printf skipped) $missing true", 0, 0},
      {"UID=$(printf skipped) $missing \"\"", 0, 0},
      {"UID=$(printf skipped) \"$@\"\"\"", 0, 0},
      {"UID=$(printf skipped) literal$missing", 0, 0},
      {"UID=$(printf skipped) $missing-suffix", 0, 0},
      {"UID=$(printf skipped) *", 0, 0},
      {"UID=$(printf skipped) {,}suffix", 0, 0},
      {"UID=$(printf skipped) {a,b}", 0, 0},
      {"UID=$(printf skipped) {a,$missing}", 0, 0},
      {"UID=$(printf skipped) {\"\",}", 0, 0},
      {"x=$(printf first) UID=$(printf data) last=$(printf last) $maybe", 2, 3},
      {"UID=$(printf data) EUID=$(printf skipped) $maybe", 0, 1},
      {"UID=$(printf data) $maybe 3>$(printf /dev/null)", 0, 1},
      {"false && UID=$(printf skipped) $maybe", 0, 0},
      {"(UID=$(printf data) $maybe)", 0, 1},
      {"{ UID=$(printf data) $maybe; }", 0, 1},
      {"UID=$(printf data) $maybe | true", 0, 1},
      {"UID=$(printf data) $maybe & true", 0, 1},
      {"UID=${missing:?skipped} true; x=kept", 1, 0},
      {"UID=$(printf data) later=$(printf skipped)", 0, 1},
      {"export UID=$(printf data)", 0, 1},
      {"export -Z x=$(printf data)", 0, 1},
      {"export UID=1", 0, 0},
      {"export -p UID=1 x=2", 1, 0},
      {"export -- UID=1 EUID+=2 x=3", 1, 0},
      {"export 'U''ID=1' x=2", 1, 0},
      {"command export UID=1 x=2", 1, 0},
      {"builtin export UID=1 x=2", 1, 0},
      {"export -Z x=1", 0, 0},
      {"export -f UID=1 x=2", 0, 0},
      {"false && UID=1 true", 0, 0},
      {"false && export x=1", 0, 0},
      {"sh -c \"$(exec 2>&1; UID=$(printf skipped) true 1>&- 2>&-)\"", 0, 1},
  };
  /* A statically empty command name certainly fails its lookup, a
   * shell-level error which no dependency graph models. */
  static const char *const empty_names[] = {"UID=$(printf skipped) ''",
                                            "UID=$(printf skipped) $''"};
  for (size_t i = 0; i < sizeof(empty_names) / sizeof(empty_names[0]); i++)
    CHECK(shell_dep_graph_parse(empty_names[i], strlen(empty_names[i]), "/",
                                limits, graph) == SHELL_DEP_EUNMODELED);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    boundary_parse(source, limits, graph);
    uint32_t environments = 0, substitutions = 0;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      environments += graph->edges[edge].type == SHELL_EDGE_ENV;
      substitutions +=
          graph->edges[edge].type == SHELL_EDGE_SUBST &&
          (graph->edges[edge].flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD);
    }
    if (environments != cases[i].environments ||
        substitutions != cases[i].substitutions)
      fprintf(stderr, "assignment effects: %s (%u ENV, %u SUBST)\n", source,
              environments, substitutions);
    CHECK(environments == cases[i].environments &&
          substitutions == cases[i].substitutions);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                         other, NULL, NULL,
                                         NULL) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    for (uint32_t nodes = 0; nodes <= graph->node_count; nodes++)
      for (uint32_t edges = 0; edges <= graph->edge_count; edges++) {
        shell_dep_limits_t bounded = *limits;
        bounded.max_nodes = nodes;
        bounded.max_edges = edges;
        shell_dep_error_t status =
            shell_dep_graph_parse(source, strlen(source), "/", &bounded, other);
        CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        CHECK(other->node_count <= nodes && other->edge_count <= edges &&
              shell_dep_graph_validate(other).valid);
        if (status == SHELL_DEP_OK)
          CHECK(shellsplit_test_graph_equal(graph, other));
      }
  }
}

static void boundary_assignment_streams(shell_dep_limits_t *limits,
                                        shell_dep_graph_t *graph,
                                        shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    bool captured, diagnostic;
  } cases[] = {
      {"sh -c \"$(x=1)\"", false, false},
      {"sh -c \"$(exec 2>&1; x=1)\"", false, false},
      {"sh -c \"$(x=$(printf data))\"", false, false},
      {"sh -c \"$(<<<\"$(printf data)\")\"", false, true},
      {"sh -c \"$(UID=1)\"", false, true},
      {"sh -c \"$(UID=1 2>&1)\"", false, true},
      {"sh -c \"$(exec 2>&1; UID=1)\"", true, true},
      {"sh -c \"$(exec 2>&1; UID+=1)\"", true, true},
      {"sh -c \"$(exec 2>&1; U\\\nID=1)\"", true, true},
      {"sh -c \"$(exec 2>&1; UID=1 1>&- 2>&-)\"", true, true},
      {"sh -c \"$(exec 1>&- 2>&-; UID=1)\"", false, false},
      {"sh -c \"$(false >&- 2>&- && UID=1)\"", false, false},
      {"sh -c \"$(exec 2>&1; UID=1 true 1>&- 2>&-)\"", true, true},
      {"sh -c \"$(exec 2>&1; UID=1 command true 1>&- 2>&-)\"", true, true},
      {"sh -c \"$(exec 2>&1; UID=1 builtin true 1>&- 2>&-)\"", true, true},
      {"sh -c \"$(exec 1>&- 2>&-; UID=1 true 1>&- 2>&-)\"", false, false},
      {"sh -c \"$({ UID=1 true 1>&- 2>&-; } 2>&1)\"", true, true},
      {"sh -c \"$(>out 2>&1)\"", false, true},
      {"sh -c \"$(2>&1 >out)\"", true, true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    boundary_parse(source, limits, graph);
    uint32_t shell = boundary_command(graph, "sh");
    bool captured = false, diagnostic = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      captured |= item->type == SHELL_EDGE_SUBST && item->to == shell &&
                  (item->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD);
      const shell_dep_node_t *owner = &graph->nodes[item->from];
      bool assignment_owner = owner->type == SHELL_NODE_GROUP;
      if (owner->type == SHELL_NODE_CMD) {
        const shell_dep_cmd_t *stage = &owner->cmd;
        assignment_owner = stage->token_count == 0 ||
                           (stage->token_lens[0] == 4 &&
                            !memcmp(stage->tokens[0], "true", 4)) ||
                           (stage->token_lens[0] == 7 &&
                            (!memcmp(stage->tokens[0], "command", 7) ||
                             !memcmp(stage->tokens[0], "builtin", 7)));
      }
      diagnostic |=
          item->source_fd == 2 &&
          (item->type == SHELL_EDGE_SUBST || item->type == SHELL_EDGE_WRITE) &&
          item->from != shell && assignment_owner;
    }
    if (captured != cases[i].captured || diagnostic != cases[i].diagnostic) {
      fprintf(stderr, "assignment stream: %s\n", source);
      shell_dep_graph_dump(graph, stderr);
    }
    CHECK(captured == cases[i].captured && diagnostic == cases[i].diagnostic);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                         other, NULL, NULL,
                                         NULL) == SHELL_DEP_OK &&
          shellsplit_test_graph_equal(graph, other));
    for (uint32_t nodes = 0; nodes <= graph->node_count; nodes++)
      for (uint32_t edges = 0; edges <= graph->edge_count; edges++) {
        shell_dep_limits_t bounded = *limits;
        bounded.max_nodes = nodes;
        bounded.max_edges = edges;
        shell_dep_error_t status =
            shell_dep_graph_parse(source, strlen(source), "/", &bounded, other);
        CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        CHECK(other->node_count <= nodes && other->edge_count <= edges &&
              shell_dep_graph_validate(other).valid);
        if (status == SHELL_DEP_OK)
          CHECK(shellsplit_test_graph_equal(graph, other));
      }
  }
  boundary_parse("UID=1", limits, graph);
  CHECK(boundary_route(graph, 0, 2, false, 2));
  CHECK(!boundary_route(graph, 0, 1, false, 1) &&
        !boundary_route(graph, 0, 0, true, 0));
  boundary_parse("x=1", limits, graph);
  CHECK(graph->node_count == 2 && graph->edge_count == 1 &&
        graph->edges[0].type == SHELL_EDGE_ENV);
  boundary_parse("exec 2>error; UID=1", limits, graph);
  bool file_diagnostic = false;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    const shell_dep_node_t *target = &graph->nodes[item->to];
    file_diagnostic |= item->type == SHELL_EDGE_WRITE && item->source_fd == 2 &&
                       graph->nodes[item->from].type == SHELL_NODE_CMD &&
                       graph->nodes[item->from].cmd.token_count == 0 &&
                       target->type == SHELL_NODE_DOC &&
                       target->doc.path_len == 5 &&
                       !memcmp(target->doc.path, "error", 5);
  }
  CHECK(file_diagnostic);
  static const struct {
    const char *source;
    bool capture;
  } process_setup[] = {
      {"< <(true)", false},
      {"> >(true)", false},
      /* Bash's file-command shortcut actually reads the process descriptor. */
      {"sh -c \"$(< <(true))\"", true},
      /* The consumer's own stdout still inherits the enclosing capture. */
      {"sh -c \"$(> >(true))\"", true}};
  for (size_t i = 0; i < sizeof(process_setup) / sizeof(process_setup[0]);
       i++) {
    boundary_parse(process_setup[i].source, limits, graph);
    bool setup = false, capture = false;
    uint32_t shell = boundary_command(graph, "sh");
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      setup |= item->type == SHELL_EDGE_FD_OPEN;
      capture |= item->type == SHELL_EDGE_SUBST && item->to == shell &&
                 (item->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD);
    }
    CHECK((setup || i == 2) && capture == process_setup[i].capture);
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    char source[1024] = "";
    for (unsigned i = 0; i < count; i++)
      strcat(source, "UID=1 true;");
    shellsplit_test_source_scan_reset();
    boundary_parse(source, limits, graph);
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_DIAGNOSTIC_ROUTES);
    unsigned height = 0;
    for (unsigned n = count; n; n >>= 1)
      height++;
    CHECK(work > 0 && work <= 64 * count * height &&
          (!previous || work <= 3 * previous));
    previous = work;
  }
#endif
}

typedef struct {
  unsigned arguments, paths;
  bool fail;
} boundary_nullable_resolution_t;

static shell_expand_status_t
boundary_nullable_resolve(const shell_expand_word_request_t *request,
                          const char **netargv, size_t *length, void *context) {
  boundary_nullable_resolution_t *fixture = context;
  const char *word = request->source + request->word_offset;
  if (request->purpose == SHELL_EXPAND_WORD_ARGUMENT) {
    CHECK(request->word_length == sizeof("\"$payload\"") - 1 &&
          !memcmp(word, "\"$payload\"", request->word_length));
    fixture->arguments++;
  } else {
    CHECK(request->purpose == SHELL_EXPAND_WORD_REDIRECT_PATH &&
          request->word_length == sizeof("\"$path\"") - 1 &&
          !memcmp(word, "\"$path\"", request->word_length));
    fixture->paths++;
  }
  *netargv = NULL;
  *length = 0;
  return fixture->fail ? SHELL_EXPAND_FAILED : SHELL_EXPAND_UNRESOLVED;
}

static void boundary_nullable_assignments(shell_dep_limits_t *limits,
                                          shell_dep_graph_t *graph,
                                          shell_dep_graph_t *other) {
  static const struct {
    const char *word;
    bool survives;
  } words[] = {
      {"$missing", false},
      {"${missing:-}", false},
      {"$(true)", false},
      {"`true`", false},
      {"$((1+2))", false},
      {"\"$@\"", false},
      {"\"${@}\"", false},
      {"\"${!prefix@}\"", false},
      {"${!prefix*}", false},
      {"${@:-}", false},
      {"\"${@+data}\"", false},
      {"\"${@:+data}\"", false},
      {"\"${@#prefix}\"", false},
      {"\"${@:99}\"", false},
      {"{,}", false},
      {"\\\n$missing\\\n", false},
      {"''", true},
      {"\"\"", true},
      {"$''", true},
      {"$'\\0'", true},
      {"\"$missing\"", true},
      {"\"${missing:-$@}\"", true},
      {"\"$(true)\"", true},
      {"\"`true`\"", true},
      {"\"$((1+2))\"", true},
      {"\"$*\"", true},
      {"\"${#@}\"", true},
      {"\"${!prefix*}\"", true},
      {"\"${!pre\\\nfix\\\n*}\"", true},
      {"\"${@-data}\"", true},
      {"\"${@:-data}\"", true},
      {"\"${@-}\"", true},
      {"\"${@:-}\"", true},
      {"\"${@:-\"$@\"}\"", true},
      {"\"${@?error}\"", true},
      {"\"${@:?error}\"", true},
      {"\"${\\\n@:\\\n-data}\"", true},
      {"\"${!prefix@}\"suffix", true},
      {"\"$@\"''", true},
      {"literal$missing", true},
      {"$missing-suffix", true},
      {"$missing\\ ", true},
      {"{,}suffix", true},
      {"{{literal}}", true},
      {"{{,},}", false},
      {"{a,b}", true},
      {"{a,$missing}", true},
      {"{\"\",}", true},
      {"{\"$@\",}", false},
      {"{{},}", true},
      {"*", true},
      {"[a]", true},
      {"~", true},
      {"<(true)", true},
      {"\\$missing", true},
      {"$", true},
  };
  for (unsigned i = 0; i < sizeof(words) / sizeof(words[0]); i++)
    CHECK(shell_builtin_word_guarantees_argument(
              words[i].word, strlen(words[i].word)) == words[i].survives);
  /* Nonempty lists need not be scalar: getopts still cannot prove which
   * expanded word supplies its destination. Keep its exact-word boundary. */
  const char *multiple = "getopts \"${@:-ab}\" option";
  CHECK(!shell_builtin_parameter_is_scalar("${@:-ab}", sizeof("${@:-ab}") - 1));
  CHECK(shell_dep_graph_parse(multiple, strlen(multiple), "/", limits, graph) ==
        SHELL_DEP_EPARSE);
  CHECK(graph->node_count == 0 && graph->edge_count == 0);
  static const struct {
    const char *source;
    bool cwd_known;
  } continuation[] = {
      {"UID=${missing:?rhs} $maybe; printf after", false},
      {"UID=${missing:?rhs} $maybe && printf after", false},
      {"! UID=${missing:?rhs} $maybe || printf after", false},
      {"{ UID=${missing:?rhs} $maybe; } && printf after", false},
      {"(UID=${missing:?rhs} $maybe); printf after", true},
      {"UID=${missing:?rhs} $maybe & printf after", true},
      {"UID=$(printf data) $maybe 1>&- 2>&-; printf after", false},
      {"exec 3>&1; UID=${missing:?rhs} $maybe 3>&-; printf after >&3", false},
      /* The setup may succeed, so `$maybe` may run and change directory. */
      {"IFS=0123456789 UID=1 $maybe 4>fail\n"
       "exec {fd}>&1; printf after >&\"$fd\"",
       false},
  };
  for (unsigned i = 0; i < sizeof(continuation) / sizeof(continuation[0]);
       i++) {
    boundary_parse(continuation[i].source, limits, graph);
    uint32_t after = UINT32_MAX;
    for (uint32_t node = 0; node < graph->node_count; node++)
      if (graph->nodes[node].type == SHELL_NODE_CMD &&
          graph->nodes[node].cmd.token_count == 2 &&
          graph->nodes[node].cmd.token_lens[1] == 5 &&
          !memcmp(graph->nodes[node].cmd.tokens[1], "after", 5))
        after = node;
    CHECK(after != UINT32_MAX && boundary_route(graph, after, 1, false, 1));
    CHECK(graph->nodes[after].cmd.cwd_known == continuation[i].cwd_known);
  }

  /* A rejected RHS runs only on the null path, where preceding IFS commits
   * are visible. Its printf then meets an ambiguous redirect: a certain
   * shell-level error, so no dependency graph models the input. */
  {
    static const char source[] =
        "IFS=0123456789 UID=$(exec {fd}>&1; printf rhs >&$fd) $maybe";
    CHECK(shell_dep_graph_parse(source, sizeof(source) - 1, "/", limits,
                                graph) == SHELL_DEP_EUNMODELED);
  }

  /* A prefix committed before the readonly error invalidates its old named
   * descriptor proof. Mixed IFS/descriptor facts must not select the valid
   * executable alternative and silently discard the null one. */
  static const char *const unresolved[] = {
      "exec {fd}>out; fd=changed UID=$(printf rhs >&\"$fd\") $maybe",
      "IFS=0123456789 x=$(exec {fd}>&1; printf rhs >&$fd) UID=1 $maybe",
      ("IFS=0123456789 UID=1 $maybe 4>fail\n"
       "exec {fd}>&1; printf after >&$fd"),
  };
  for (unsigned i = 0; i < sizeof(unresolved) / sizeof(unresolved[0]); i++) {
    CHECK(shell_dep_graph_parse(unresolved[i], strlen(unresolved[i]), "/",
                                limits, graph) == SHELL_DEP_EPARSE);
    CHECK(graph->node_count == 0 && graph->edge_count == 0);
  }
  /* A certainly failing setup is a shell-level error: no model. */
  {
    static const char source[] =
        "exec {fd}>out; fd=changed UID=1 $maybe 4>\"\" || "
        "printf after >&\"$fd\"";
    CHECK(shell_dep_graph_parse(source, sizeof(source) - 1, "/", limits,
                                graph) == SHELL_DEP_EUNMODELED);
  }

  static const char *const resolved[] = {
      "UID=$(printf '%s' \"$payload\") $maybe >\"$path\"",
      "UID=$(printf '%s' \"$payload\") \"$maybe\" >\"$path\"",
      "UID=$(printf '%s' \"$payload\") \"${!prefix*}\" >\"$path\"",
      "UID=$(printf '%s' \"$payload\") \"${!prefix@}\" >\"$path\"",
      "UID=$(printf '%s' \"$payload\") \"${@:-data}\" >\"$path\"",
  };
  for (unsigned i = 0; i < sizeof(resolved) / sizeof(resolved[0]); i++) {
    boundary_nullable_resolution_t fixture = {0};
    boundary_parse(resolved[i], limits, graph);
    CHECK(shell_dep_graph_parse_resolved(
              resolved[i], strlen(resolved[i]), "/", limits, other,
              boundary_nullable_resolve, &fixture, NULL) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
    CHECK(fixture.arguments == (i == 0 || i == 3 ? 1u : 0u) &&
          fixture.paths == 1);
  }
  boundary_nullable_resolution_t failure = {.fail = true};
  CHECK(shell_dep_graph_parse_resolved(resolved[0], strlen(resolved[0]), "/",
                                       limits, other, boundary_nullable_resolve,
                                       &failure, NULL) == SHELL_DEP_EEXPAND);
  CHECK(other->node_count == 0 && other->edge_count == 0);

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous = 0;
  for (unsigned count = 32; count <= 256; count *= 2) {
    char source[4096] = "UID=$(printf data) ";
    for (unsigned word = 0; word < count; word++)
      strcat(source, "$missing\\\n");
    strcat(source, "$missing");
    shellsplit_test_source_scan_reset();
    boundary_parse(source, limits, graph);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(work > 0 && work <= 256 * strlen(source) &&
          (!previous || work <= 3 * previous));
    CHECK(boundary_command(graph, "printf") != UINT32_MAX);
    previous = work;
  }
  previous = 0;
  for (unsigned count = 32; count <= 256; count *= 2) {
    char source[4096] = "UID=$(printf skipped) \"${!";
    for (unsigned byte = 0; byte < count; byte++)
      strcat(source, "p\\\n");
    strcat(source, "*}\"");
    shellsplit_test_source_scan_reset();
    boundary_parse(source, limits, graph);
    size_t work = shellsplit_test_source_scan_work();
    CHECK(work > 0 && work <= 256 * strlen(source) &&
          (!previous || work <= 3 * previous));
    CHECK(boundary_command(graph, "printf") == UINT32_MAX);
    previous = work;
  }
#endif
}

static void boundary_diagnostic_flows(shell_dep_limits_t *limits,
                                      shell_dep_graph_t *graph,
                                      shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    bool capture;
  } cases[] = {
      {"sh -c \"$(echo 2>&1 >/missing/x)\"", true},
      {"sh -c \"$(echo >/missing/x 2>&1)\"", false},
      {"sh -c \"$(echo >/missing/x)\"", false},
      {"sh -c \"$(echo 2>&- >/missing/x)\"", false},
      {"sh -c \"$(2>&1 >/missing/x)\"", true},
      {"sh -c \"$({ echo body; } 2>&1 >/missing/x)\"", true},
      {"sh -c \"$( (echo body) 2>&1 >/missing/x)\"", true},
      {"sh -c \"$(time echo 2>&1 >/missing/x)\"", true},
      {"sh -c \"$(false && echo 2>&1 >/missing/x)\"", false},
      {"sh -c \"$(true || echo 2>&1 >/missing/x)\"", false},
      {"sh -c \"$(echo 2>&1 >/missing/x)\"", true},
      {"sh -c \"$(echo >/missing/x 2>&1)\"", false},
      {"cat <(echo 2>&1 >/missing/x)", true},
      {"cat <(echo >/missing/x 2>&1)", false},
      {"sh -c \"$(echo 2>&1 1>/missing/x)\"", true},
      {"sh -c \"$(echo 2>&1 {fd}>/missing/x)\"", true},
      {"sh -c \"$(exec 2>&1; echo ok &)\"", true},
      {"exec 10>&-; sh -c \"$(: 2>&1 10>&- 4>/missing/x)\"", true},
      {"exec 63<<<seed; sh -c \"$(read -u63 -n0 probe; "
       "{ true 2>&1 5>left 6>right 7>/missing/x; })\"",
       true},
      {"exec 63<<<seed; sh -c \"$(read -u63 -n0 probe; "
       "{ true 5>left 6>right 2>&- 7>/missing/x; })\"",
       false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    boundary_parse(cases[i].source, limits, graph);
    bool capture = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      capture |= item->type == SHELL_EDGE_SUBST && item->source_fd == 2;
      if (item->type == SHELL_EDGE_WRITE && item->source_fd == 2 &&
          graph->nodes[item->to].type == SHELL_NODE_ENDPOINT)
        for (uint32_t out = 0; out < graph->edge_count; out++)
          capture |= graph->edges[out].type == SHELL_EDGE_SUBST &&
                     graph->edges[out].from == item->to;
    }
    if (capture != cases[i].capture)
      fprintf(stderr, "diagnostic capture: %s\n", cases[i].source);
    CHECK(capture == cases[i].capture);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                           &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(cases[i].source,
                                          strlen(cases[i].source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_failure_cleanup_reference(true);
    boundary_parse(cases[i].source, limits, other);
    shellsplit_test_failure_cleanup_reference(false);
    CHECK(shellsplit_test_graph_equal(graph, other));
#endif
  }
  /* The group saves fd 2 at fd 10, and the persistent close destroys that
   * save: Bash cannot restore fd 2 (reference Bash captures "10: Bad file
   * descriptor"). No dependency model. */
  static const char destroyed[] =
      "exec 10>&-; sh -c \"$({ exec 10>&-; } 2>&1)\"";
  CHECK(shell_dep_graph_parse(destroyed, sizeof(destroyed) - 1, "/", limits,
                              graph) == SHELL_DEP_EUNMODELED);
  boundary_parse("echo 2>&1 >/missing/x | cat", limits, graph);
  uint32_t echo = boundary_command(graph, "echo"),
           cat = boundary_command(graph, "cat");
  bool piped = false;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    piped |= item->type == SHELL_EDGE_PIPE && item->from == echo &&
             item->to == cat && item->source_fd == 2 && item->target_fd == 0;
  }
  CHECK(piped);
  /* More than 16 distinct prefix sinks fit the graph. Split into three
   * owners to stay within the independent per-command lexical token bound. */
  char source[1024] = ":;";
  for (unsigned owner = 0; owner < 3; owner++) {
    strcat(source, " echo");
    for (unsigned i = 0; i < 8; i++) {
      char redirect[32];
      snprintf(redirect, sizeof(redirect), " 2>error%u", owner * 8 + i);
      strcat(source, redirect);
    }
    strcat(source, " >/missing/x;");
  }
  boundary_parse(source, limits, graph);
  unsigned destinations = 0;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->type == SHELL_EDGE_WRITE &&
        graph->nodes[item->from].type == SHELL_NODE_CMD &&
        item->source_fd == 2 && graph->nodes[item->to].type == SHELL_NODE_DOC)
      destinations++;
  }
  CHECK(destinations == 24);
  for (unsigned nodes = 0; nodes <= 8; nodes++)
    for (unsigned edges = 0; edges <= 12; edges++) {
      shell_dep_limits_t bounded = *limits;
      bounded.max_nodes = nodes;
      bounded.max_edges = edges;
      const char *limited_source = cases[0].source;
      shell_dep_error_t status = shell_dep_graph_parse(
          limited_source, strlen(limited_source), "/", &bounded, other);
      CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
      CHECK(other->node_count <= nodes && other->edge_count <= edges &&
            shell_dep_graph_validate(other).valid);
      if (status == SHELL_DEP_OK) {
        bool captured = false;
        for (uint32_t edge = 0; edge < other->edge_count; edge++)
          captured |= other->edges[edge].type == SHELL_EDGE_SUBST &&
                      other->edges[edge].source_fd == 2;
        CHECK(captured);
      }
    }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  shellsplit_test_failure_cleanup_reference(true);
  boundary_parse(source, limits, other);
  shellsplit_test_failure_cleanup_reference(false);
  CHECK(shellsplit_test_graph_equal(graph, other));
  size_t previous = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    strcpy(source, ":;");
    for (unsigned i = 0; i < count; i++) {
      char stage[40];
      snprintf(stage, sizeof(stage), " echo 2>error%u >/missing/x;", i);
      strcat(source, stage);
    }
    shellsplit_test_source_scan_reset();
    boundary_parse(source, limits, graph);
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_DIAGNOSTIC_ROUTES);
    unsigned height = 0;
    for (unsigned size = count; size; size >>= 1)
      height++;
    CHECK(work > 0 && work <= 64 * count * height &&
          (!previous || work <= 3 * previous));
    previous = work;
  }
#endif
}

/* UINT32_MAX selects any consumer. Index collectors once so exact-consumer
 * assertions do not rescan the edge stream for every diagnostic producer. */
static bool boundary_captured_stderr(const shell_dep_graph_t *graph,
                                     uint32_t consumer) {
  bool collectors[SHELL_DEP_MAX_NODES] = {false};
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->type != SHELL_EDGE_SUBST ||
        (consumer != UINT32_MAX && item->to != consumer))
      continue;
    if (item->source_fd == 2)
      return true;
    collectors[item->from] = true;
  }
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->type == SHELL_EDGE_WRITE && item->source_fd == 2 &&
        graph->nodes[item->to].type == SHELL_NODE_ENDPOINT &&
        collectors[item->to])
      return true;
  }
  return false;
}

static void boundary_expansion_diagnostics(shell_dep_limits_t *limits,
                                           shell_dep_graph_t *graph,
                                           shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    bool capture;
  } cases[] = {
      {"sh -c \"$(exec 2>&1; x=${missing:?expansion-marker})\"", true},
      {"sh -c \"$(exec 2>&1; x=$((1/0)))\"", true},
      {"sh -c \"$(exec 2>&1; x=${value:1/0})\"", true},
      {"sh -c \"$(exec 2>&1; x=${missing:?expansion-marker} 1>&- 2>&-)\"",
       true},
      {"sh -c \"$(exec 2>&1; : ${missing:?expansion-marker} 1>&- 2>&-)\"",
       true},
      {"sh -c \"$(exec 2>&1; x=$((1/0)) true 1>&- 2>&-)\"", true},
      {"sh -c \"$(exec 2>&1; export x=${missing:?expansion-marker} 1>&- "
       "2>&-)\"",
       true},
      {"sh -c \"$(x=${missing:?expansion-marker} 2>&1)\"", false},
      {"sh -c \"$(exec 2>&-; x=${missing:?expansion-marker})\"", false},
      {"sh -c \"$(exec 2>&1; false 1>&- 2>&- && "
       "x=${missing:?expansion-marker})\"",
       false},
      {"sh -c \"$(exec 2>&1; true 1>&- 2>&- || x=$((1/0)))\"", false},
      {"sh -c \"$(exec 2>&1; UID=${missing:?expansion-marker} true 1>&- "
       "2>&-)\"",
       true},
      {"sh -c \"$(x=1)\"", false},
      {"sh -c \"$(exec 2>&1; x='${missing:?literal}')\"", false},
      {"sh -c \"$(: 2>&1 >${missing:?expansion-marker} 2>&-)\"", true},
      {"sh -c \"$(: >${missing:?expansion-marker} 2>&1)\"", false},
      {"sh -c \"$(: 2>&- >${missing:?expansion-marker} 2>&1)\"", false},
      {"sh -c \"$(: 2>&1 >/missing/x >${missing:?expansion-marker})\"", true},
      {"sh -c \"$(: 2>&1 <<<$((1/0)) 2>&-)\"", true},
      {"sh -c \"$(: <<<$((1/0)) 2>&1 1>&- 2>&-)\"", false},
      {"sh -c \"$(: 2>&1 <<EOF 2>&-\n${missing:?expansion-marker}\nEOF\n)\"",
       true},
      {"sh -c \"$(: <<EOF 2>&1 1>&- "
       "2>&-\n${missing:?expansion-marker}\nEOF\n)\"",
       false},
      {"sh -c \"$(: <<'EOF' 1>&- 2>&-\n${missing:?literal}\nEOF\n)\"", false},
      {"sh -c \"$(exec 2<input; x=${missing:?expansion-marker})\"", false},
      {"sh -c \"$({ :; } 2>&1 >${missing:?expansion-marker})\"", true},
      {"sh -c \"$({ :; } >${missing:?expansion-marker} 2>&1)\"", false},
      {"sh -c \"$( (x=${missing:?expansion-marker}) 2>&1)\"", true},
      {"cat <(exec 2>&1; x=$((1/0)))", true},
      {"sh -c \"$(exec 2>&1; x=$(exec 2>&1; y=$((1/0))))\"", true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    boundary_parse(source, limits, graph);
    if (boundary_captured_stderr(graph, UINT32_MAX) != cases[i].capture)
      fprintf(stderr, "expansion diagnostic: %s\n", source);
    CHECK(boundary_captured_stderr(graph, UINT32_MAX) == cases[i].capture);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
  }

  /* A failed RHS is shell stderr, even when there is no executable argv.
   * Its incoming binding must survive the command's later close operations. */
  boundary_parse("exec 2>&1; x=$((1/0)) 1>&- 2>&-", limits, graph);
  uint32_t assignment = UINT32_MAX;
  for (uint32_t node = 0; node < graph->node_count; node++)
    if (graph->nodes[node].type == SHELL_NODE_CMD &&
        !graph->nodes[node].cmd.token_count)
      assignment = node;
  CHECK(assignment != UINT32_MAX &&
        boundary_route(graph, assignment, 2, false, 1));
  CHECK(!boundary_route(graph, assignment, 0, true, 0) &&
        !boundary_route(graph, assignment, 1, false, 1));

  boundary_parse("exec 2>errors; x=$((1/0)) 2>&-", limits, graph);
  bool written = false;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    if (item->type == SHELL_EDGE_WRITE && item->source_fd == 2 &&
        graph->nodes[item->to].type == SHELL_NODE_DOC &&
        graph->nodes[item->to].doc.path_len == 6 &&
        !memcmp(graph->nodes[item->to].doc.path, "errors", 6))
      written = true;
  }
  CHECK(written);
  boundary_parse("{ x=$((1/0)); } 2>&1 | cat", limits, graph);
  bool piped = false;
  for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
    const shell_dep_edge_t *item = &graph->edges[edge];
    piped |= item->type == SHELL_EDGE_PIPE && item->source_fd == 2 &&
             item->to == boundary_command(graph, "cat") && item->target_fd == 0;
  }
  CHECK(piped);

  static const char *const limited_sources[] = {
      "sh -c \"$(exec 2>&1; x=${missing:?expansion-marker})\"",
      "sh -c \"$(exec 2>&1; x=$((1/0)))\"",
      "sh -c \"$(: 2>&1 >${missing:?expansion-marker} 2>&-)\"",
      "sh -c \"$(: 2>&1 <<<$((1/0)) 2>&-)\"",
      "sh -c \"$(: 2>&1 <<EOF 2>&-\n${missing:?expansion-marker}\nEOF\n)\"",
  };
  for (size_t i = 0; i < sizeof(limited_sources) / sizeof(limited_sources[0]);
       i++) {
    const char *source = limited_sources[i];
    for (unsigned nodes = 0; nodes <= 12; nodes++)
      for (unsigned edges = 0; edges <= 18; edges++) {
        shell_dep_limits_t bounded = *limits;
        bounded.max_nodes = nodes;
        bounded.max_edges = edges;
        shell_dep_error_t status =
            shell_dep_graph_parse(source, strlen(source), "/", &bounded, other);
        CHECK(status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC);
        CHECK(other->node_count <= nodes && other->edge_count <= edges &&
              shell_dep_graph_validate(other).valid);
        CHECK(status != SHELL_DEP_OK ||
              boundary_captured_stderr(other, UINT32_MAX));
      }
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    char source[4096] = "";
    for (unsigned i = 0; i < count; i++) {
      strcat(source, ": <<<$((1/0));");
    }
    shellsplit_test_source_scan_reset();
    boundary_parse(source, limits, graph);
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_DIAGNOSTIC_ROUTES);
    unsigned height = 0;
    for (unsigned size = count; size; size >>= 1)
      height++;
    CHECK(work > 0 && work <= 128 * count * height &&
          (!previous || work <= 3 * previous));
    previous = work;
  }
#endif
}

typedef struct {
  const char *value;
  shell_expand_status_t status;
  unsigned calls;
} boundary_file_diagnostic_resolution_t;

static shell_expand_status_t
boundary_file_diagnostic_resolve(const shell_expand_word_request_t *request,
                                 const char **netargv, size_t *length,
                                 void *context) {
  boundary_file_diagnostic_resolution_t *fixture = context;
  if (request->purpose != SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH)
    return SHELL_EXPAND_UNRESOLVED;
  fixture->calls++;
  *netargv = fixture->value;
  *length = fixture->value ? strlen(fixture->value) : 0;
  return fixture->status;
}

static void boundary_file_diagnostics(shell_dep_limits_t *limits,
                                      shell_dep_graph_t *graph,
                                      shell_dep_graph_t *other) {
  static const struct {
    const char *source;
    bool captured;
  } cases[] = {
      {"sh -c \"$(exec 2>&1; x=$(<input))\"", true},
      {"sh -c \"$(x=$(<input))\"", false},
      {"sh -c \"$(exec 2>&-; x=$(<input))\"", false},
      {"sh -c \"$(exec 2<input; x=$(<input))\"", false},
      {"sh -c \"$(exec 2>&1; x=$(<input) 1>&- 2>&-)\"", true},
      {"sh -c \"$(x=$(<input) 2>&1)\"", false},
      {"sh -c \"$(exec 2>&1; false 1>&- 2>&- && x=$(<input))\"", false},
      {"sh -c \"$(exec 2>&1; x=$(< <(true 1>&- 2>&-)))\"", true},
      {"sh -c \"$(exec 2>&1; x=$(<$(printf input)))\"", true},
      {"sh -c \"$(: 2>&1 >$(<input) 1>&- 2>&-)\"", true},
      {"sh -c \"$(: >$(<input) 2>&1 1>&- 2>&-)\"", false},
      {"sh -c \"$(: 2>&1 <<<\"$(<input)\" 1>&- 2>&-)\"", true},
      {"sh -c \"$({ :; } 2>&1 >$(<input))\"", true},
      {"sh -c \"$(exec 2>&1; x=$(y=$(<input)))\"", true},
      {"sh -c \"$(x=$(exec 2>&1; y=$(<input)))\"", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    boundary_parse(source, limits, graph);
    uint32_t shell = boundary_command(graph, "sh");
    CHECK(shell != UINT32_MAX);
    if (boundary_captured_stderr(graph, shell) != cases[i].captured)
      fprintf(stderr, "file diagnostic receiver: %s\n", source);
    CHECK(boundary_captured_stderr(graph, shell) == cases[i].captured);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(source, strlen(source), "/", limits,
                                          &fast, other) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                         other, NULL, NULL,
                                         NULL) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
  }

  static const struct {
    const char *word, *value;
    shell_expand_status_t status;
    bool failed;
  } values[] = {
      {"\"$FILE\"", "0:,", SHELL_EXPAND_RESOLVED, true},
      {"\"$@\"", NULL, SHELL_EXPAND_RESOLVED, true},
      {"\"$@\"", "1:a,1:b,", SHELL_EXPAND_RESOLVED, true},
      {"\"$FILE\"", "10:/tmp/input,", SHELL_EXPAND_RESOLVED, false},
      {"\"$FILE\"", NULL, SHELL_EXPAND_UNRESOLVED, false},
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    char source[128];
    snprintf(source, sizeof(source), "sh -c \"$(exec 2>&1; x=$(<%s))\"",
             values[i].word);
    boundary_file_diagnostic_resolution_t fixture = {values[i].value,
                                                     values[i].status, 0};
    /* A resolved pathname which is empty or several words certainly fails:
     * a shell-level error which no dependency graph models. */
    if (values[i].failed) {
      CHECK(shell_dep_graph_parse_resolved(
                source, strlen(source), "/", limits, graph,
                boundary_file_diagnostic_resolve, &fixture,
                NULL) == SHELL_DEP_EUNMODELED);
      CHECK(fixture.calls == 1);
      continue;
    }
    CHECK(shell_dep_graph_parse_resolved(source, strlen(source), "/", limits,
                                         graph,
                                         boundary_file_diagnostic_resolve,
                                         &fixture, NULL) == SHELL_DEP_OK);
    CHECK(fixture.calls == 1 && shell_dep_graph_validate(graph).valid);
    uint32_t shell = boundary_command(graph, "sh");
    CHECK(shell != UINT32_MAX && boundary_captured_stderr(graph, shell));
    unsigned content = 0;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      content += item->type == SHELL_EDGE_SUBST &&
                 graph->nodes[item->from].type == SHELL_NODE_DOC;
    }
    CHECK(content == !values[i].failed);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
    shell_expand_cache_t cache;
    shell_dep_limits_t resolved = *limits;
    fixture.calls = 0;
    CHECK(shell_expand_cache_init(
        boundary_file_diagnostic_resolve, &fixture, source, strlen(source),
        false, limits->workspace, limits->workspace_size, &cache,
        &resolved.workspace, &resolved.workspace_size));
    shell_dep_word_resolver_t resolver = {shell_expand_resolve, &cache};
    uint8_t unresolved[SHELL_DEP_MAX_NODES];
    CHECK(shell_dep_graph_parse_with_fast_resolver(
              source, strlen(source), "/", &resolved, &fast, other, &resolver,
              unresolved) == SHELL_DEP_OK);
    CHECK(fixture.calls == 1 && shellsplit_test_graph_equal(graph, other));
    for (unsigned nodes = 0; nodes <= 10; nodes++)
      for (unsigned edges = 0; edges <= 14; edges++) {
        shell_dep_limits_t bounded = *limits;
        bounded.max_nodes = nodes;
        bounded.max_edges = edges;
        fixture.calls = 0;
        shell_dep_error_t error = shell_dep_graph_parse_resolved(
            source, strlen(source), "/", &bounded, other,
            boundary_file_diagnostic_resolve, &fixture, NULL);
        CHECK(error == SHELL_DEP_OK || error == SHELL_DEP_ETRUNC);
        CHECK(fixture.calls <= 1 && other->node_count <= nodes &&
              other->edge_count <= edges &&
              shell_dep_graph_validate(other).valid);
        CHECK(error != SHELL_DEP_OK ||
              shellsplit_test_graph_equal(graph, other));
      }
  }
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  size_t previous = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    char source[4096] = "";
    for (unsigned i = 0; i < count; i++)
      strcat(source, "x=$(<input);");
    shellsplit_test_source_scan_reset();
    boundary_parse(source, limits, graph);
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_DIAGNOSTIC_ROUTES);
    unsigned height = 0;
    for (unsigned size = count; size; size >>= 1)
      height++;
    CHECK(work > 0 && work <= 128 * count * height &&
          (!previous || work <= 3 * previous));
    previous = work;
  }
#endif
}

static void boundary_terminal_pipe_capacity(shell_dep_limits_t *limits,
                                            shell_dep_graph_t *graph,
                                            shell_dep_graph_t *other) {
  const char *regression = "echo 2>&1 >/missing/x | cat <input";
  shell_dep_limits_t bounded = *limits;
  bounded.max_nodes = 5;
  bounded.max_edges = 3;
  CHECK(shell_dep_graph_parse(regression, strlen(regression), "/", &bounded,
                              other) == SHELL_DEP_ETRUNC);
  CHECK(other->node_count <= 5 && other->edge_count <= 3 &&
        shell_dep_graph_validate(other).valid);

  static const struct {
    const char *source;
    uint32_t producers;
    bool diagnostic, timer_pipe;
  } cases[] = {
      {"echo 2>&1 >/missing/x | cat <input", 1, true, false},
      {"echo 2>&1 >/missing/x | cat <&-", 1, true, false},
      {"{ echo 2>&1 >/missing/x; } | cat <input", 2, true, false},
      {"(echo 2>&1 >/missing/x) | cat <input", 2, true, false},
      {"time echo 2>&1 >/missing/x | cat <input", 1, true, false},
      {"echo | : <&-", 1, false, false},
      {"echo | cat <input", 1, false, false},
      {"{ echo one; echo two; } 2>&1 | cat <input", 2, false, false},
      {"{ time echo; } 2>&1 | cat <input", 3, false, true},
      {"printf '%s' \"$(echo 2>&1 >/missing/x | cat <input)\"", 1, true, false},
      {"cat <(echo 2>&1 >/missing/x | cat <input)", 1, true, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *source = cases[i].source;
    size_t length = strlen(source);
    boundary_parse(source, limits, graph);
    uint32_t terminal = UINT32_MAX;
    for (uint32_t node = 0; node < graph->node_count; node++)
      if (graph->nodes[node].type == SHELL_NODE_ENDPOINT) {
        CHECK(terminal == UINT32_MAX);
        terminal = node;
      }
    CHECK(terminal != UINT32_MAX);
    uint32_t producers = 0;
    uint32_t echo = boundary_command(graph, "echo");
    bool diagnostic_pipe = false, timer_pipe = false;
    for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
      const shell_dep_edge_t *item = &graph->edges[edge];
      if (item->type == SHELL_EDGE_PIPE && item->to == terminal) {
        CHECK(item->target_fd == 0 && item->flags == 0);
        producers++;
        diagnostic_pipe |= item->from == echo && item->source_fd == 2;
        if (graph->nodes[item->from].type == SHELL_NODE_TIME) {
          const shell_dep_time_t *time = &graph->nodes[item->from].time;
          CHECK(item->source_fd == 2 &&
                time->report_route == SHELL_TIME_REPORT_GRAPH &&
                time->report_external_fd_count == 0);
          timer_pipe = true;
        }
      }
    }
    CHECK(producers == cases[i].producers &&
          timer_pipe == cases[i].timer_pipe &&
          (!cases[i].diagnostic || diagnostic_pipe));

    shell_parse_result_t fast;
    CHECK(shell_parse_fast(source, length, NULL, &fast) == SHELL_OK);
    for (uint32_t nodes = 0; nodes <= graph->node_count + 1; nodes++)
      for (uint32_t edges = 0; edges <= graph->edge_count + 1; edges++) {
        bounded = *limits;
        bounded.max_nodes = nodes;
        bounded.max_edges = edges;
        for (unsigned api = 0; api < 3; api++) {
          shell_dep_error_t status =
              api == 0
                  ? shell_dep_graph_parse(source, length, "/", &bounded, other)
              : api == 1
                  ? shell_dep_graph_parse_with_fast(source, length, "/",
                                                    &bounded, &fast, other)
                  : shell_dep_graph_parse_resolved(
                        source, length, "/", &bounded, other, NULL, NULL, NULL);
          bool valid =
              (status == SHELL_DEP_OK || status == SHELL_DEP_ETRUNC) &&
              other->node_count <= nodes && other->edge_count <= edges &&
              shellsplit_test_depgraph_invariants(source, length, status, other,
                                                  &bounded);
          if (!valid)
            fprintf(stderr,
                    "terminal capacity: %s (api=%u nodes=%u edges=%u "
                    "status=%d)\n",
                    source, api, nodes, edges, status);
          CHECK(valid);
          if (status == SHELL_DEP_OK)
            CHECK(shellsplit_test_graph_equal(graph, other));
        }
      }
  }
}

static int run_boundary(int argc, char **argv) {
  (void)argc;
  (void)argv;
  shellsplit_graph_fixture_t fixture;
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_RESOLVED,
                                      4096, 2, false, 0));
  shell_dep_limits_t limits = fixture.limits;
  shell_dep_graph_t *graph = fixture.graph[0];
  shell_dep_graph_t *other = fixture.graph[1];
  boundary_background_newlines(&limits, graph, other);
  boundary_async_completion(&limits, graph, other);
  boundary_async_inputs(&limits, graph, other);
  boundary_standard_directions(&limits, graph, other);
  boundary_timing_destinations(&limits, graph, other);
  boundary_recovery_resolution(&limits, graph, other);
  boundary_cd_commands(&limits, graph, other);
  boundary_owner_stream_inventory(&limits, graph, other);
  boundary_assignment_effects(&limits, graph, other);
  boundary_assignment_streams(&limits, graph, other);
  boundary_nullable_assignments(&limits, graph, other);
  boundary_diagnostic_flows(&limits, graph, other);
  boundary_expansion_diagnostics(&limits, graph, other);
  boundary_file_diagnostics(&limits, graph, other);
  boundary_terminal_pipe_capacity(&limits, graph, other);
  boundary_diagnostic_resolution(&limits, graph, other);
  char exact[512] = "";
  for (unsigned i = 0; i < 64; i++)
    strcat(exact, i == 0 ? "wc" : ";wc");
  static const char *const trivia[] = {"", ";", " \n", "; \n# end\n"};
  size_t exact_length = strlen(exact);
  for (unsigned i = 0; i < sizeof(trivia) / sizeof(trivia[0]); i++) {
    strcpy(exact + exact_length, trivia[i]);
    boundary_parse(exact, &limits, graph);
    CHECK(graph->node_count == 67 && graph->edge_count == 255);
  }
  strcpy(exact + exact_length, ";wc");
  CHECK(shell_dep_graph_parse(exact, strlen(exact), "/", &limits, graph) ==
        SHELL_DEP_ETRUNC);
  CHECK(graph->node_count == 67 && graph->edge_count == 255 &&
        shell_dep_graph_validate(graph).valid);

  static const char *const async_capacity[] = {
      "wc &",
      "wc &\nwait",
      "exec 0<&- && true &\ncat",
      "{ wc; } &",
      "time wc &",
      "true && wc &",
      "printf '%s' \"$(wc)\" &",
      "wc 0>&1",
      "wc 1<&0",
      "UID=1\ntrue && wc & wait",
      "probe && exec 2>&1; time wc",
  };
  for (unsigned source = 0;
       source < sizeof(async_capacity) / sizeof(async_capacity[0]); source++)
    for (unsigned nodes = 0; nodes <= 8; nodes++)
      for (unsigned edges = 0; edges <= 15; edges++) {
        shell_dep_limits_t bounded = limits;
        bounded.max_nodes = nodes;
        bounded.max_edges = edges;
        shell_dep_error_t error = shell_dep_graph_parse(
            async_capacity[source], strlen(async_capacity[source]), "/",
            &bounded, graph);
        CHECK(error == SHELL_DEP_OK || error == SHELL_DEP_ETRUNC);
        CHECK(graph->node_count <= nodes && graph->edge_count <= edges &&
              shell_dep_graph_validate(graph).valid);
        (void)boundary_implicit_input(graph);
      }

  static const struct {
    const char *source;
    uint32_t stdout_fd, stderr_fd;
    const char *stdout_file, *stderr_file;
  } cases[] = {
      {"wc -l file.txt", 1, 2, NULL, NULL},
      {"wc -l file.txt 2>&1", 1, 1, NULL, NULL},
      {"wc -l file.txt 1>&2", 2, 2, NULL, NULL},
      {"wc -l file.txt 2>&1 >out", SHELL_DEP_FD_NONE, 1, "out", NULL},
      {"wc -l file.txt >out 2>&1", SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE, "out",
       "out"},
      {"wc -l file.txt 2>&-", 1, SHELL_DEP_FD_NONE, NULL, NULL},
      {"wc -l file.txt 2>&2-", 1, 2, NULL, NULL},
      {"exec 3>&1; wc -l file.txt 1>&3-", 1, 2, NULL, NULL},
      {"exec {fd}>&1; wc -l file.txt 2>&$fd", 1, 1, NULL, NULL},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    boundary_parse(cases[i].source, &limits, graph);
    uint32_t owner = boundary_command(graph, "wc");
    CHECK(owner != UINT32_MAX && boundary_route(graph, owner, 0, true, 0));
    for (uint32_t fd = 1; fd <= 2; fd++) {
      uint32_t inherited = fd == 1 ? cases[i].stdout_fd : cases[i].stderr_fd;
      const char *file = fd == 1 ? cases[i].stdout_file : cases[i].stderr_file;
      unsigned destinations = 0;
      for (uint32_t edge = 0; edge < graph->edge_count; edge++) {
        const shell_dep_edge_t *item = &graph->edges[edge];
        if (item->type != SHELL_EDGE_WRITE || item->from != owner ||
            item->source_fd != fd)
          continue;
        const shell_dep_node_t *target = &graph->nodes[item->to];
        bool failed_open = i == 4 && fd == 2 && target->type == SHELL_NODE_FD &&
                           target->fd.number == 2;
        if (file && !failed_open)
          CHECK(target->type == SHELL_NODE_DOC &&
                target->doc.kind == SHELL_DOC_FILE &&
                target->doc.path_len == strlen(file) &&
                !memcmp(target->doc.path, file, strlen(file)));
        else if (!failed_open)
          CHECK(target->type == SHELL_NODE_FD &&
                target->fd.number == inherited);
        destinations++;
      }
      CHECK(destinations == (file || inherited != SHELL_DEP_FD_NONE ? 1u : 0u) +
                                (i == 4 && fd == 2 ? 1u : 0u));
    }
  }

  boundary_parse("wc -l file.txt", &limits, graph);
  CHECK(graph->node_count == 5 && graph->edge_count == 4);
  boundary_parse("wc -l file.txt 2>&1", &limits, graph);
  /* Both sparse stdout/stderr slots retain their available read/write halves.
   */
  CHECK(graph->node_count == 4 && graph->edge_count == 6);
  uint32_t external = UINT32_MAX;
  for (uint32_t i = 0; i < graph->node_count; i++)
    if (graph->nodes[i].type == SHELL_NODE_FD)
      external = i;
  CHECK(external != UINT32_MAX);
  *other = *graph;
  other->nodes[external].fd.number = SHELL_DEP_FD_NONE;
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->nodes[other->node_count++] = graph->nodes[external];
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->nodes[other->node_count++] =
      (shell_dep_node_t){.type = SHELL_NODE_FD, .fd = {.number = 3}};
  CHECK(!shell_dep_graph_validate(other).valid);
  *other = *graph;
  other->edges[other->edge_count - 1].type = SHELL_EDGE_PIPE;
  CHECK(!shell_dep_graph_validate(other).valid);
  boundary_parse("time wc", &limits, graph);
  *other = *graph;
  for (uint32_t i = 0; i < other->node_count; i++)
    if (other->nodes[i].type == SHELL_NODE_TIME)
      other->nodes[i].time.report_external_fds[0] = 1;
  CHECK(!shell_dep_graph_validate(other).valid);

  static const char *const scopes[] = {
      "{ wc -l file.txt; echo ok; } 2>&1",
      "( wc -l file.txt; echo ok ) 2>&1",
      "{ { wc -l file.txt; }; } 2>&1",
      "{ wc -l file.txt 2>&1; echo ok; }",
      "echo \"$(wc -l file.txt)\"",
      "echo \"$(wc -l file.txt 2>&1)\"",
      "echo `wc -l file.txt`",
      "cat <(wc -l file.txt)",
      "cat > >(wc -l file.txt)",
      "wc -l file.txt | cat",
      "wc -l file.txt |& cat",
      "probe && exec 2>&1; wc -l file.txt",
      "time wc -l file.txt",
      "echo \"$(exec 3>&2; time wc 2>&3)\"",
      "time { wc; } 2>&1",
      "echo \"$( { wc; } )\"",
      "true || wc -l file.txt",
      ">out",
      "exec 2>&1",
      "time",
  };
  for (size_t i = 0; i < sizeof(scopes) / sizeof(scopes[0]); i++) {
    boundary_parse(scopes[i], &limits, graph);
    shell_parse_result_t fast;
    CHECK(shell_parse_fast(scopes[i], strlen(scopes[i]), NULL, &fast) ==
          SHELL_OK);
    CHECK(shell_dep_graph_parse_with_fast(scopes[i], strlen(scopes[i]), "/",
                                          &limits, &fast,
                                          other) == SHELL_DEP_OK);
    CHECK(shellsplit_test_graph_equal(graph, other));
  }
  boundary_parse(" ", &limits, graph);
  CHECK(graph->node_count == 0 && graph->edge_count == 0);
  boundary_parse("echo \"$(wc -l file.txt 2>&1)\"", &limits, graph);
  uint32_t owner = boundary_command(graph, "wc");
  CHECK(boundary_route(graph, owner, 0, true, 0));
  CHECK(!boundary_route(graph, owner, 1, false, 1) &&
        !boundary_route(graph, owner, 2, false, 1));
  boundary_parse("probe && exec 2>&1; wc -l file.txt", &limits, graph);
  owner = boundary_command(graph, "wc");
  CHECK(boundary_route(graph, owner, 2, false, 1) &&
        boundary_route(graph, owner, 2, false, 2));
  boundary_parse("true || wc -l file.txt", &limits, graph);
  owner = boundary_command(graph, "wc");
  CHECK(!boundary_route(graph, owner, 0, true, 0) &&
        !boundary_route(graph, owner, 1, false, 1));
  boundary_parse("echo \"$( { wc; } )\"", &limits, graph);
  uint32_t child_group = UINT32_MAX;
  for (uint32_t i = 0; i < graph->node_count; i++)
    if (graph->nodes[i].type == SHELL_NODE_GROUP)
      child_group = i;
  owner = boundary_command(graph, "wc");
  CHECK(child_group != UINT32_MAX &&
        boundary_route(graph, child_group, 0, true, 0) &&
        boundary_route(graph, child_group, 2, false, 2));
  CHECK(!boundary_route(graph, owner, 0, true, 0) &&
        !boundary_route(graph, owner, 2, false, 2));
  boundary_parse("{ >out; }", &limits, graph);
  for (uint32_t i = 0; i < graph->node_count; i++)
    if (graph->nodes[i].type == SHELL_NODE_FD)
      CHECK(graph->nodes[i].fd.number == 2);
  /* No body needs stdin/stdout. Only the possible open-error diagnostic has
   * an inherited stream relation. */
  unsigned diagnostic_boundaries = 0;
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (graph->nodes[edge->to].type == SHELL_NODE_FD) {
      CHECK(edge->type == SHELL_EDGE_WRITE && edge->source_fd == 2);
      diagnostic_boundaries++;
    }
    CHECK(graph->nodes[edge->from].type != SHELL_NODE_FD);
  }
  CHECK(diagnostic_boundaries == 1);

  /* Repeated nested exposures are coalesced before retained-edge budgeting. */
  char nested[512] = "";
  for (unsigned i = 0; i < 16; i++)
    strcat(nested, "{ ");
  strcat(nested, "wc;");
  for (unsigned i = 0; i < 16; i++)
    strcat(nested, " }; ");
  boundary_parse(nested, &limits, graph);
  uint32_t boundaries = 0;
  for (uint32_t i = 0; i < graph->edge_count; i++)
    boundaries += graph->nodes[graph->edges[i].from].type == SHELL_NODE_FD ||
                  graph->nodes[graph->edges[i].to].type == SHELL_NODE_FD;
  CHECK(boundaries == 3);

  /* Many conditional routes shared by deeply nested groups must not consume
   * the public edge budget once per redundant intermediate exposure. The
   * executor contract opens only 0, 1 and 2 as external descriptors. */
  char alternatives[2048] = "probe && exec 2>&1; probe && exec 2>&0; ";
  for (unsigned i = 0; i < 60; i++)
    strcat(alternatives, "{ ");
  strcat(alternatives, "wc;");
  for (unsigned i = 0; i < 60; i++)
    strcat(alternatives, " }; ");
  boundary_parse(alternatives, &limits, graph);
  uint32_t outer = UINT32_MAX;
  for (uint32_t i = 0; i < graph->node_count; i++)
    if (graph->nodes[i].type == SHELL_NODE_GROUP &&
        graph->nodes[i].group.parent == UINT32_MAX) {
      CHECK(outer == UINT32_MAX);
      outer = i;
    }
  CHECK(outer != UINT32_MAX);
  CHECK(boundary_route(graph, outer, 0, true, 0) &&
        boundary_route(graph, outer, 1, false, 1));
  for (unsigned fd = 0; fd <= 2; fd++)
    CHECK(boundary_route(graph, outer, 2, false, fd));

  for (uint32_t max_nodes = 1; max_nodes <= 4; max_nodes++)
    for (uint32_t max_edges = 0; max_edges <= 3; max_edges++) {
      shell_dep_limits_t bounded = limits;
      bounded.max_nodes = max_nodes;
      bounded.max_edges = max_edges;
      shell_dep_error_t status =
          shell_dep_graph_parse("wc", 2, "/", &bounded, graph);
      CHECK(status == ((max_nodes == 4 && max_edges == 3) ? SHELL_DEP_OK
                                                          : SHELL_DEP_ETRUNC));
      CHECK(graph->node_count <= max_nodes && graph->edge_count <= max_edges);
      CHECK(shell_dep_graph_validate(graph).valid);
    }
  static const char stopped_join[] =
      "exec 3>/tmp/move-a 4>/tmp/move-b || exit; "
      "exec 10>&3 11>&- 12>&- 13>&-; exec 3>&10- 11>&4 10>&-; "
      ": \"$(echo next >&11)\"";
  shell_dep_limits_t limited = limits;
  limited.max_edges = 1;
  CHECK(shell_dep_graph_parse(stopped_join, sizeof(stopped_join) - 1, "/",
                              &limited, graph) == SHELL_DEP_ETRUNC);
  CHECK(graph->node_count == 0 && graph->edge_count == 0 &&
        shell_dep_graph_validate(graph).valid);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  /* Completing nested compounds ending in background units projects each
   * final outcome once, rather than searching their prefixes or ancestors. */
  for (unsigned family = 0; family < 2; family++) {
    size_t previous_work = 0;
    for (unsigned count = 4; count <= 32; count *= 2) {
      char source[1024] = "";
      for (unsigned i = 0; i < count; i++)
        strcat(source, "{ ");
      strcat(source, "false &");
      for (unsigned i = 1; i < count; i++)
        strcat(source, family == 0 ? " };" : " } &");
      strcat(source, " } || printf bad >out");
      shellsplit_test_source_scan_reset();
      boundary_parse(source, &limits, graph);
      uint32_t marker = boundary_command(graph, "printf");
      CHECK(marker != UINT32_MAX);
      for (uint32_t edge = 0; edge < graph->edge_count; edge++)
        CHECK(!((graph->edges[edge].type == SHELL_EDGE_READ &&
                 graph->edges[edge].to == marker) ||
                (graph->edges[edge].type == SHELL_EDGE_WRITE &&
                 graph->edges[edge].from == marker)));
      size_t work =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_CONTROL_ENDPOINTS);
      CHECK(work > 0 && work <= 256 * count &&
            (!previous_work || work <= 3 * previous_work));
      previous_work = work;
    }
  }
  /* Exercise the connector walk directly so route publication cannot mask a
   * repeated source scan. Both stage and trivia growth must remain linear. */
  for (unsigned family = 0; family < 2; family++) {
    size_t previous_work = 0;
    for (unsigned count = 4; count <= 32; count *= 2) {
      char source[1024] = "wc &\n";
      for (unsigned i = 1; i < count; i++)
        strcat(source, family == 0 ? "wc &\n\n# note\n" : "\n# note\n");
      strcat(source, "wait");
      shell_parse_result_t fast;
      shell_pipeline_index_t index;
      CHECK(shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK);
      shellsplit_test_source_scan_reset();
      shell_pipeline_index_connectors(source, strlen(source), &fast, &index);
      size_t work = shellsplit_test_source_scan_work();
      CHECK(work > 0 && work <= 64 * strlen(source) &&
            (!previous_work || work <= 3 * previous_work));
      CHECK(index.range_successor[0] == SHELL_TYPE_BACKGROUND &&
            index.range_connector[fast.count - 1] == SHELL_TYPE_BACKGROUND);
      previous_work = work;
    }
  }
  size_t previous = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    char source[1024] = "";
    for (unsigned i = 0; i < count; i++)
      strcat(source, "wc; ");
    shellsplit_test_source_scan_reset();
    boundary_parse(source, &limits, graph);
    size_t work = shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_BOUNDARY);
    unsigned height = 0;
    for (unsigned size = count; size; size >>= 1)
      height++;
    CHECK(work > 0 && work <= 96 * count * height &&
          (!previous || work <= 3 * previous));
    previous = work;
  }
  previous = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    char source[1024] = "";
    for (unsigned group = 0; group < count; group++)
      strcat(source, "{ ");
    strcat(source, "wc;");
    for (unsigned group = 0; group < count; group++)
      strcat(source, " } &");
    shellsplit_test_source_scan_reset();
    boundary_parse(source, &limits, graph);
    CHECK(boundary_reads_implicit(graph, boundary_command(graph, "wc"), 0));
    size_t work = shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_BOUNDARY);
    unsigned height = 0;
    for (unsigned size = count; size; size >>= 1)
      height++;
    CHECK(work > 0 && work <= 120 * count * height &&
          (!previous || work <= 3 * previous));
    previous = work;
  }
#endif
  shellsplit_graph_fixture_destroy(&fixture);
  puts("inherited boundary graph tests passed");
  return 0;
}
#undef CHECK

/* --- corpus (from corpus_test.c) --- */
/* Cross-surface regression coverage for the anonymous coding-agent corpus.
 * Fixtures are data only: this test only parses and models them. */

static unsigned corpus_passed;
static unsigned corpus_failed;

#define ARRAY_COUNT(values) (sizeof(values) / sizeof((values)[0]))

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      printf("    FAIL: %s at %s:%d\n", #condition, __FILE__, __LINE__);       \
      return false;                                                            \
    }                                                                          \
  } while (0)

#define TEST(name) static bool test_##name(void)
#define RUN(name)                                                              \
  do {                                                                         \
    printf("  %-42s ", #name);                                                 \
    if (test_##name()) {                                                       \
      puts("PASS");                                                            \
      corpus_passed++;                                                         \
    } else {                                                                   \
      corpus_failed++;                                                         \
    }                                                                          \
  } while (0)

static bool corpus_valid_netsequence(const shell_netstring_buffer_t *sequence,
                                     size_t expected_records) {
  size_t records = 0;
  return sequence->data != NULL && sequence->length != 0 &&
         shell_netstring_validate(sequence->data, sequence->length, &records) ==
             SHELL_NETSTRING_OK &&
         records == expected_records;
}

/* Anomaly netsequences are the sole canonical transport that retains an
 * argv-less stage. Its raw record is empty and its corresponding typed record
 * contains exactly one empty argv[0]. Check both forms together so a later
 * refactor cannot silently turn that structural stage into an executable. */
static bool
corpus_anomaly_empty_stage_count(const shell_netstring_buffer_t *raw,
                                 const shell_netstring_buffer_t *typed,
                                 size_t *out_count) {
  if (!raw || !typed || !out_count)
    return false;
  *out_count = 0;
  shell_netstring_iter_t raw_records;
  shell_netstring_iter_t typed_records;
  if (shell_netstring_iter_init(&raw_records, raw->data, raw->length) !=
          SHELL_NETSTRING_OK ||
      shell_netstring_iter_init(&typed_records, typed->data, typed->length) !=
          SHELL_NETSTRING_OK)
    return false;
  for (;;) {
    shell_netstring_view_t raw_record;
    shell_netstring_view_t typed_record;
    shell_netstring_status_t raw_status =
        shell_netstring_iter_next(&raw_records, &raw_record);
    shell_netstring_status_t typed_status =
        shell_netstring_iter_next(&typed_records, &typed_record);
    if (raw_status == SHELL_NETSTRING_DONE ||
        typed_status == SHELL_NETSTRING_DONE)
      return raw_status == SHELL_NETSTRING_DONE &&
             typed_status == SHELL_NETSTRING_DONE;
    if (raw_status != SHELL_NETSTRING_OK || typed_status != SHELL_NETSTRING_OK)
      return false;
    if (raw_record.payload_length != 0)
      continue;
    shell_netstring_iter_t argv;
    shell_netstring_view_t argv0;
    if (shell_netstring_iter_init(&argv, typed_record.payload,
                                  typed_record.payload_length) !=
            SHELL_NETSTRING_OK ||
        shell_netstring_iter_next(&argv, &argv0) != SHELL_NETSTRING_OK ||
        argv0.payload_length != 0 ||
        shell_netstring_iter_next(&argv, &argv0) != SHELL_NETSTRING_DONE)
      return false;
    (*out_count)++;
  }
}

TEST(canonical_processing_surfaces_agree) {
  for (size_t i = 0; i < SHELLCLAVE_COMMAND_CORPUS_COUNT; i++) {
    const char *input = shellclave_command_corpus_commands[i];
    size_t length = strlen(input);
    shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    shell_parse_result_t fast = {0};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t command_netseq = {0};
    shell_netstring_buffer_t type_netseq = {0};
    shell_netstring_buffer_t anomaly_commands = {0};
    shell_netstring_buffer_t anomaly_types = {0};
    shell_dep_graph_t graph = {0};
    size_t netargv_count = 0;
    size_t command_count_out = 0;
    size_t type_count = 0;
    size_t anomaly_count = 0;
    bool features = false;

    bool valid =
        shell_parse_fast(input, length, &strict, &fast) == SHELL_OK &&
        fast.count > 0 &&
        shell_tokenize_commands(input, length, &commands, &command_count) ==
            SHELL_TOKENIZE_OK &&
        command_count >= fast.count &&
        shell_process_commands(input, length, NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count > 0 &&
        shell_build_netargv_sequence_buffer(input, length, NULL, &netargv,
                                            &netargv_count,
                                            &features) == SHELL_PROCESS_OK &&
        netargv_count == processed.command_count &&
        corpus_valid_netsequence(&netargv, netargv_count) &&
        shell_build_command_netseq_buffer(input, length, NULL, &command_netseq,
                                          &command_count_out) ==
            SHELL_PROCESS_OK &&
        command_count_out >= processed.command_count &&
        corpus_valid_netsequence(&command_netseq, command_count_out) &&
        shell_build_type_netseq_buffer(input, length, NULL, &type_netseq,
                                       &type_count) == SHELL_PROCESS_OK &&
        type_count == command_count_out &&
        corpus_valid_netsequence(&type_netseq, type_count) &&
        shell_build_anomaly_netseqs_buffer(
            input, length, NULL, &anomaly_commands, &anomaly_types,
            &anomaly_count) == SHELL_PROCESS_OK &&
        anomaly_count == command_count_out &&
        corpus_valid_netsequence(&anomaly_commands, anomaly_count) &&
        corpus_valid_netsequence(&anomaly_types, anomaly_count) &&
        shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;

    if (!valid) {
      printf("    fixture %zu failed: %s\n", i, input);
      shell_netstring_buffer_free(&netargv);
      shell_netstring_buffer_free(&command_netseq);
      shell_netstring_buffer_free(&type_netseq);
      shell_netstring_buffer_free(&anomaly_commands);
      shell_netstring_buffer_free(&anomaly_types);
      shell_processed_commands_free(&processed);
      shell_commands_free(commands, command_count);
      return false;
    }
    shell_netstring_iter_t records;
    valid = shell_netstring_iter_init(&records, netargv.data, netargv.length) ==
            SHELL_NETSTRING_OK;
    for (size_t c = 0; valid && c < processed.command_count; c++) {
      shell_netstring_view_t record;
      shell_netstring_buffer_t rendered = {0};
      valid =
          shell_netstring_iter_next(&records, &record) == SHELL_NETSTRING_OK &&
          shell_render_netargv_buffer(&processed.commands[c], NULL,
                                      &rendered) == SHELL_PROCESS_OK &&
          record.payload_length == rendered.length &&
          memcmp(record.payload, rendered.data, rendered.length) == 0;
      shell_netstring_buffer_free(&rendered);
    }
    valid =
        valid && command_netseq.length == anomaly_commands.length &&
        type_netseq.length == anomaly_types.length &&
        memcmp(command_netseq.data, anomaly_commands.data,
               command_netseq.length) == 0 &&
        memcmp(type_netseq.data, anomaly_types.data, type_netseq.length) == 0;
    shell_netstring_buffer_free(&netargv);
    shell_netstring_buffer_free(&command_netseq);
    shell_netstring_buffer_free(&type_netseq);
    shell_netstring_buffer_free(&anomaly_commands);
    shell_netstring_buffer_free(&anomaly_types);
    shell_processed_commands_free(&processed);
    shell_commands_free(commands, command_count);
    CHECK(valid);
  }
  return true;
}

TEST(supported_syntax_model_matrix) {
  /* These are compact representatives for paths that are uncommon in the
   * anonymized corpus. Keep them as parser inputs only; none is executed.
   * Descriptors above 2 start closed (SHELL_DEP_EUNMODELED), so a copied
   * descriptor is opened first. */
  static const char *const cases[] = {
      "printf x >out",
      "printf x >>out",
      "cat <in",
      "cat <>read-write",
      "printf x >|forced",
      "printf x 2>err 3>>trace 4>&1 5<&0 6>&-",
      "printf x &>all",
      "printf x &>>all",
      "printf x >&combined",
      "printf x 1>&\"combined name\"",
      "printf x >&\\$literal",
      "exec 7>seven; printf x >&\"7\"",
      "exec 7>seven; printf x >&$'7'",
      "printf x >&\"-\"",
      "printf x {trace}>out {input}<in {both}<>read-write",
      "cat <<EOF\nbody\nEOF\n",
      "cat <<-'EOF'\n\tbody\n\tEOF\n",
      "cat <<<\"body\"",
      "printf x > >(cat)",
      "cat < <(printf x)",
      "cat <(printf x)",
      "printf x | cat",
      "printf x |& cat",
      "! printf x |& cat | sort",
      "printf x && cat",
      "printf x || cat",
      "printf x & cat",
      "printf x; cat",
      "{ printf x; } | { cat; }",
      "{ printf x; } |& { cat; }",
      "{ printf x; } >out 2>&1",
      "{ printf x; } &>all",
      "{ printf x; } &>>all",
      "{ printf x; } &> >(cat)",
      "{ printf x; } >&combined",
      "exec 7>seven; { printf x; } >&\"7\"",
      "exec 7>seven; { printf x; } >&$'7'",
      "{ printf x; } >&\"-\"",
      "{ printf x; } {trace}>out {input}<in {both}<>read-write",
      "{ cat; } <<EOF\nbody\nEOF\n",
      "(printf x) | cat",
      "echo $(printf x)",
      "echo $(<input)",
      "echo `printf x`",
      "echo \"$(( 1 + 2 ))\"",
      "echo ${value:-$(printf x)}",
      "echo $'a\\tb'",
      "echo @(foo|bar)",
      "echo prefix@(foo|bar)suffix",
      "echo !(foo)",
      "echo \\! \"!\" '!'",
      "VAR=value command",
      "export VAR=$(printf x)",
      "exec {out}>out; exec {copy}<&$out; printf x >&$copy",
      "exec {in}<in; exec {copy}>&$in; cat <&$copy",
      "cd /tmp && pwd",
      "cd ./relative; pwd",
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i];
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    bool valid = shell_process_commands(input, strlen(input), NULL,
                                        &processed) == SHELL_PROCESS_OK &&
                 shell_dep_graph_parse(input, strlen(input), "/work/base", NULL,
                                       &graph) == SHELL_DEP_OK &&
                 shell_dep_graph_validate(&graph).valid;
    if (!valid) {
      printf("    syntax case %zu failed: %s\n", i, input);
      shell_processed_commands_free(&processed);
      return false;
    }
    shell_processed_commands_free(&processed);
  }
  return true;
}

/* Run the less common, but fully supported, spellings through every exported
 * representation.  The fixture corpus deliberately favours short everyday
 * commands; this compact matrix makes the shipping and allocator-linked test
 * libraries exercise the same substitution, word-shape, and redirection
 * paths without treating any diagnostic display as shell input. */
TEST(cross_surface_edge_syntax) {
  static const char *const cases[] = {
      "printf /a/${VALUE:-$(producer)}/$1",
      "printf x >&literal{path}",
      "cat < <(producer) |& sed x > >(consumer)",
      "cat < prefix<(producer)",
      "cat > >(consumer)suffix",
      "{ cat; } <> <(producer)suffix",
      "cat < <(producer)<(consumer)",
      "echo $(<prefix<(producer))",
      "cat < prefix<(producer)$(printf path)",
      "printf x 2>&1 3>&- {out}>out {in}<in {both}<>read-write",
      "printf x {out\\\nfd}>out {in\\\nfd}<in",
      "cat >out\\\nsuffix next",
      "$'c'3>out;cat \"x\"${y}z;my\\\ncommand value",
      "printf prefix$'literal'${NAME} \"$ONE$TWO\"",
      "cat <<EOF\n$(producer)\nEOF\n",
      "cat <<EOF\nwhile true; do :; done\n$\"locale\"\n\\$(literal)\n"
      "\\${items[0]}\n$(printf value)\n$((1 + 2))\nEOF\n",
      "cat <<'EOF'\n$(while true; do :; done)\n${items[0]}\n"
      "$((items[0]))\n$\"locale\"\nEOF\n",
      "cat <<${items[0]}\nbody\n${items[0]}\n",
      "cat <<EOF <<-'LITERAL'\r\n$(printf value)\r\nEOF\n"
      "\t$(while true; do :; done)\r\n\tLITERAL\r\n",
      "printf $'a\\tb' @(left|right)",
      "printf ${VALUE#prefix${SUFFIX:-$(producer)}}",
      "printf ${VALUE##prefix${SUFFIX}} ${VALUE%tail${SUFFIX}}",
      "printf ${VALUE%%tail${SUFFIX}} ${VALUE/pattern/${REPLACEMENT}}",
      "printf ${VALUE:-{left,right}}",
      "printf ${VALUE:-{}",
      "printf ${VALUE#{}",
      "printf ${VALUE/{}",
      "printf ${VALUE:-${FALLBACK:-{}}",
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i];
    size_t length = strlen(input);
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t command_netseq = {0};
    shell_netstring_buffer_t type_netseq = {0};
    shell_netstring_buffer_t anomaly_commands = {0};
    shell_netstring_buffer_t anomaly_types = {0};
    shell_transformed_command_t **transformed = NULL;
    shell_abstract_command_t *abstract = NULL;
    shell_dep_graph_t graph = {0};
    size_t netargv_count = 0;
    size_t command_count = 0;
    size_t type_count = 0;
    size_t anomaly_count = 0;
    size_t transformed_count = 0;
    bool features = false;

    bool valid =
        shell_process_commands(input, length, NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count > 0 &&
        shell_build_netargv_sequence_buffer(input, length, NULL, &netargv,
                                            &netargv_count,
                                            &features) == SHELL_PROCESS_OK &&
        netargv_count == processed.command_count &&
        corpus_valid_netsequence(&netargv, netargv_count) &&
        shell_build_command_netseq_buffer(input, length, NULL, &command_netseq,
                                          &command_count) == SHELL_PROCESS_OK &&
        command_count >= processed.command_count &&
        corpus_valid_netsequence(&command_netseq, command_count) &&
        shell_build_type_netseq_buffer(input, length, NULL, &type_netseq,
                                       &type_count) == SHELL_PROCESS_OK &&
        type_count == command_count &&
        corpus_valid_netsequence(&type_netseq, type_count) &&
        shell_build_anomaly_netseqs_buffer(
            input, length, NULL, &anomaly_commands, &anomaly_types,
            &anomaly_count) == SHELL_PROCESS_OK &&
        anomaly_count == command_count &&
        corpus_valid_netsequence(&anomaly_commands, anomaly_count) &&
        corpus_valid_netsequence(&anomaly_types, anomaly_count) &&
        shell_transform_command_line(input, length, NULL, &transformed,
                                     &transformed_count) ==
            SHELL_TRANSFORM_OK &&
        transformed_count == processed.command_count &&
        shell_abstract_command_parse(input, length, &abstract) ==
            SHELL_ABSTRACT_OK &&
        abstract != NULL &&
        shell_dep_graph_parse(input, length, "/work/base", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    shell_netstring_buffer_free(&netargv);
    shell_netstring_buffer_free(&command_netseq);
    shell_netstring_buffer_free(&type_netseq);
    shell_netstring_buffer_free(&anomaly_commands);
    shell_netstring_buffer_free(&anomaly_types);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
    shell_processed_commands_free(&processed);
    if (!valid) {
      printf("    cross-surface case %zu failed: %s\n", i, input);
      return false;
    }
  }
  return true;
}

/* Redirect-only shell operations are meaningful graph nodes even though they
 * have no executable argv. Keep that distinction visible at every public
 * boundary: executable argv output rejects any composition containing such a
 * stage, while the anomaly sequences preserve it with their empty argv[0]
 * sentinel and the graph retains its I/O operation. */
TEST(redirect_only_stages_remain_graph_visible) {
  static const struct {
    const char *input;
    size_t processed_count;
    size_t anomaly_stage_count;
    uint32_t minimum_reads;
    uint32_t minimum_writes;
  } cases[] = {
      {">output", 0, 1, 0, 1},
      {"<input >output", 0, 1, 1, 1},
      {"printf x; >output", 1, 2, 0, 1},
      {"{ cat; } >out; >a; >b", 1, 3, 0, 3},
      {"{ cat; } >out\n>a", 1, 2, 0, 2},
      {"{ cat; }\n>a", 1, 2, 0, 1},
      {"{ cat; }; >a", 1, 2, 0, 1},
      {"{ cat; } # comment\n>a", 1, 2, 0, 1},
      {"{ cat; } >out && >a", 1, 2, 0, 2},
      {"{ cat; } >out || >a", 1, 2, 0, 2},
      {"{ cat; } >out & >a", 1, 2, 0, 2},
      {"{ cat; } >out | >a", 1, 2, 0, 2},
      {"{ cat; } >out |& >a", 1, 2, 0, 2},
      {"{ { cat; } >out; >a; }", 1, 2, 0, 2},
      {"echo 3\n>out", 1, 2, 0, 1},
      {"{ cat; } <<EOF\nbody\nEOF\n>out", 1, 2, 1, 1},
      {"{ cat; } 0<<EOF\nbody\nEOF\n>out", 1, 2, 1, 1},
      {"{ cat; } 1\\\n2<<EOF\nbody\nEOF\n>out", 1, 2, 1, 1},
      {"{ cat; } <<-'EOF'\n\tbody\n\tEOF\n# separate stage\n>out", 1, 2, 1, 1},
  };

  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i].input;
    size_t length = strlen(input);
    shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    shell_parse_result_t fast = {0};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t anomaly_commands = {0};
    shell_netstring_buffer_t anomaly_types = {0};
    shell_dep_graph_t graph = {0};
    size_t netargv_count = SIZE_MAX;
    bool features = true;
    uint32_t empty_commands = 0;
    uint32_t reads = 0;
    uint32_t writes = 0;
    size_t empty_anomaly_stages = SIZE_MAX;

    bool valid = shell_parse_fast(input, length, &strict, &fast) == SHELL_OK &&
                 fast.count > 0 &&
                 shell_tokenize_commands(input, length, &commands,
                                         &command_count) == SHELL_TOKENIZE_OK &&
                 command_count > 0 &&
                 shell_process_commands(input, length, NULL, &processed) ==
                     SHELL_PROCESS_OK &&
                 processed.command_count == cases[i].processed_count &&
                 (processed.command_count == 0 ? processed.commands == NULL
                                               : processed.commands != NULL) &&
                 shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
                     SHELL_DEP_OK &&
                 shell_dep_graph_validate(&graph).valid;
    shell_process_status_t netargv_status = shell_build_netargv_sequence_buffer(
        input, length, NULL, &netargv, &netargv_count, &features);
    size_t anomaly_count = SIZE_MAX;
    valid = valid && netargv_status == SHELL_PROCESS_EPARSE &&
            netargv.data == NULL && netargv.length == 0 && netargv_count == 0 &&
            !features &&
            shell_build_anomaly_netseqs_buffer(
                input, length, NULL, &anomaly_commands, &anomaly_types,
                &anomaly_count) == SHELL_PROCESS_OK &&
            anomaly_count == cases[i].anomaly_stage_count &&
            corpus_valid_netsequence(&anomaly_commands, anomaly_count) &&
            corpus_valid_netsequence(&anomaly_types, anomaly_count) &&
            corpus_anomaly_empty_stage_count(&anomaly_commands, &anomaly_types,
                                             &empty_anomaly_stages);
    for (uint32_t node = 0; valid && node < graph.node_count; node++)
      empty_commands += graph.nodes[node].type == SHELL_NODE_CMD &&
                        graph.nodes[node].cmd.token_count == 0;
    for (uint32_t edge = 0; valid && edge < graph.edge_count; edge++) {
      reads += graph.edges[edge].type == SHELL_EDGE_READ;
      writes += graph.edges[edge].type == SHELL_EDGE_WRITE;
    }
    valid = valid &&
            empty_commands ==
                cases[i].anomaly_stage_count - cases[i].processed_count &&
            empty_anomaly_stages ==
                cases[i].anomaly_stage_count - cases[i].processed_count &&
            reads >= cases[i].minimum_reads &&
            writes >= cases[i].minimum_writes;
    shell_netstring_buffer_free(&netargv);
    shell_netstring_buffer_free(&anomaly_commands);
    shell_netstring_buffer_free(&anomaly_types);
    shell_processed_commands_free(&processed);
    shell_commands_free(commands, command_count);
    if (!valid) {
      printf("    redirect-only case %zu failed: %s\n", i, input);
      return false;
    }
  }
  return true;
}

/* A syntax rejection must agree at every canonical boundary. In particular,
 * a malformed modern operator cannot be retained by the processor or graph
 * after the fast parser rejects it. */
TEST(malformed_syntax_is_rejected_atomically) {
  static const char *const cases[] = {
      "printf x |&",
      "printf x |& | cat",
      "printf x | # note",
      "printf x |& \\\n",
      "printf x && # note",
      "printf x ||\n",
      "! # note\nprintf x",
      "! \nprintf x",
      "! !",
      "echo then { x; }",
      "echo one; }",
      "echo one | )",
      "echo one { literal; }",
      "echo one (cat)",
      "echo one ((1))",
      "printf x > (consumer)",
      "printf x && && cat",
      "printf $'unterminated",
      "printf $(unterminated",
      "cat < prefix<(unterminated",
      "cat >",
      "cat >;echo hi",
      "cat 0<<<",
      "cat 0<<<&1 echo hi",
      "cat 0<<",
      "cat 3<<-",
      "cat 0<<EOF\nunterminated\n",
      "{ cat; } 0<<<",
      "{ cat; } 0<<<;echo hi",
      "{ cat; } >;echo hi",
      "printf ${VALUE${SUFFIX}}",
      "printf ${VALUE$SUFFIX}",
      "printf ${VALUE.suffix}",
      "printf ${?suffix}",
      "printf ${10suffix}",
      "while true; do :; done",
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i];
    shell_processed_commands_t processed = {
        .commands = (shell_command_info_t *)(uintptr_t)1,
        .command_count = SIZE_MAX,
    };
    shell_netstring_buffer_t netargv = {0};
    shell_dep_graph_t graph = {0};
    shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    shell_parse_result_t fast = {0};
    shell_error_t fast_status =
        shell_parse_fast(input, strlen(input), &strict, &fast);
    CHECK(strcmp(input, "while true; do :; done") == 0
              ? fast_status == SHELL_OK
              : fast_status == SHELL_EPARSE);
    CHECK(shell_process_commands(input, strlen(input), NULL, &processed) ==
          SHELL_PROCESS_EPARSE);
    CHECK(processed.commands == NULL && processed.command_count == 0);
    size_t subcommands = SIZE_MAX;
    bool features = true;
    CHECK(shell_build_netargv_sequence_buffer(
              input, strlen(input), NULL, &netargv, &subcommands, &features) ==
          SHELL_PROCESS_EPARSE);
    CHECK(netargv.data == NULL && netargv.length == 0 && subcommands == 0 &&
          !features);
    CHECK(shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
          SHELL_DEP_EPARSE);
    CHECK(graph.node_count == 0 && graph.edge_count == 0 &&
          graph.cwd_buf.len == 0 &&
          (graph.status & SHELL_DEP_STATUS_ERROR) != 0);
  }
  return true;
}

/* These sources are valid shell syntax and must remain lexically available for
 * diagnostics. The semantic adapters deliberately reject them together: they
 * must never flatten definition, control, or array semantics into executable
 * argv records. This test runs against both Shellsplit library variants. */
TEST(unsupported_semantics_are_rejected_atomically) {
  static const char *const cases[] = {
      "worker () { :; }",
      "worker ( ) { :; }",
      "worker\t(\t) ( : )",
      "worker\\\n() { :; }",
      "function worker () { :; }",
      "function worker ( ) ( : )",
      "select item in one; do :; done",
      "coproc worker { :; }",
      "items=(one two)",
      "declare -a items",
      "declare arr[0]",
      "declare 'arr[0]'",
      "declare arr\\[0\\]",
      "declare arr$'[0]'",
      "typeset map[key]",
      "command -- declare \"arr[$(printf 0)]\"",
      "printf '%s' \"${items[0]}\"",
      "echo \"${value:-$\"localized\"}\"",
      "echo \"${outer:-${inner:-$\"localized\"}}\"",
      "cat <<EOF\n$(while true; do :; done)\nEOF\n",
      "cat <<EOF\n`select item in one; do :; done`\nEOF\n",
      "cat <<EOF\n${items[0]}\nEOF\n",
      "cat <<EOF\n$((items[0]))\nEOF\n",
      "cat <<EOF\n\"${items[0]}\"\nEOF\n",
      "echo $(cat <<EOF\n$(while true; do :; done)\nEOF\n)",
      "case value in x) : ;& esac",
      "case value in x) : ;;& esac",
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i];
    size_t length = strlen(input);
    shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    shell_parse_result_t fast = {0};
    shell_command_t *lexical = NULL;
    size_t lexical_count = 0;
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t command_netseq = {0};
    shell_netstring_buffer_t type_netseq = {0};
    shell_netstring_buffer_t anomaly_commands = {0};
    shell_netstring_buffer_t anomaly_types = {0};
    shell_transformed_command_t **transformed = NULL;
    shell_abstract_command_t *abstract = NULL;
    shell_dep_graph_t graph = {0};
    size_t count = SIZE_MAX;
    size_t transformed_count = SIZE_MAX;
    bool features = true;

    /* The fast parser intentionally remains a bounded structural scanner:
     * accepted lexical extensions may report either its retained range or an
     * unsupported grammar result. The complete tokenizer is the contract that
     * must preserve these valid spellings for later semantic rejection. */
    shell_error_t fast_status = shell_parse_fast(input, length, &strict, &fast);
    CHECK(fast_status == SHELL_OK || fast_status == SHELL_EPARSE);
    shell_tokenize_status_t lexical_status =
        shell_tokenize_commands(input, length, &lexical, &lexical_count);
    if (lexical_status != SHELL_TOKENIZE_OK) {
      printf("    lexical unsupported case %zu: status=%d for %s\n", i,
             (int)lexical_status, input);
      return false;
    }
    CHECK(lexical != NULL && lexical_count != 0);
    shell_commands_free(lexical, lexical_count);

    CHECK(shell_process_commands(input, length, NULL, &processed) ==
          SHELL_PROCESS_EPARSE);
    CHECK(processed.commands == NULL && processed.command_count == 0 &&
          processed.groups == NULL && processed.group_count == 0 &&
          processed.group_io_ops == NULL && processed.group_io_op_count == 0);
    CHECK(shell_build_netargv_sequence_buffer(input, length, NULL, &netargv,
                                              &count, &features) ==
          SHELL_PROCESS_EPARSE);
    CHECK(netargv.data == NULL && netargv.length == 0 && count == 0 &&
          !features);
    count = SIZE_MAX;
    CHECK(shell_build_command_netseq_buffer(input, length, NULL,
                                            &command_netseq,
                                            &count) == SHELL_PROCESS_EPARSE);
    CHECK(command_netseq.data == NULL && command_netseq.length == 0 &&
          count == 0);
    count = SIZE_MAX;
    CHECK(shell_build_type_netseq_buffer(input, length, NULL, &type_netseq,
                                         &count) == SHELL_PROCESS_EPARSE);
    CHECK(type_netseq.data == NULL && type_netseq.length == 0 && count == 0);
    count = SIZE_MAX;
    CHECK(shell_build_anomaly_netseqs_buffer(input, length, NULL,
                                             &anomaly_commands, &anomaly_types,
                                             &count) == SHELL_PROCESS_EPARSE);
    CHECK(anomaly_commands.data == NULL && anomaly_commands.length == 0 &&
          anomaly_types.data == NULL && anomaly_types.length == 0 &&
          count == 0);
    CHECK(shell_transform_command_line(input, length, NULL, &transformed,
                                       &transformed_count) ==
          SHELL_TRANSFORM_EPARSE);
    CHECK(transformed == NULL && transformed_count == 0);
    CHECK(shell_abstract_command_parse(input, length, &abstract) ==
          SHELL_ABSTRACT_EPARSE);
    CHECK(abstract == NULL);
    CHECK(shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
          SHELL_DEP_EPARSE);
    CHECK(graph.node_count == 0 && graph.edge_count == 0 &&
          graph.cwd_buf.len == 0 &&
          (graph.status & SHELL_DEP_STATUS_ERROR) != 0);
  }
  return true;
}

/* Named descriptors retain process-substitution structure through every
 * canonical surface. Direct forms create symbolic descriptor routes; composite
 * operands remain dynamic filename expressions, just as their numeric-FD
 * counterparts do. */
TEST(named_fd_process_substitutions_are_canonical) {
  static const char *const cases[] = {
      "cmd {fd}< <(producer)",  "cmd {fd}< prefix<(producer)",
      "cmd {fd}> >(consumer)",  "cmd {fd}> prefix>(consumer)",
      "cmd {fd}>> >(consumer)", "cmd {fd}>> prefix>(consumer)",
      "cmd {fd}<> <(producer)", "cmd {fd}<> prefix<(producer)",
      "cmd {fd}<> >(consumer)",
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i];
    size_t length = strlen(input);
    shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    shell_parse_result_t fast = {0};
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t command_netseq = {0};
    shell_netstring_buffer_t type_netseq = {0};
    shell_netstring_buffer_t anomaly_commands = {0};
    shell_netstring_buffer_t anomaly_types = {0};
    shell_transformed_command_t **transformed = NULL;
    shell_abstract_command_t *abstract = NULL;
    shell_dep_graph_t graph = {0};
    size_t count = SIZE_MAX;
    size_t transformed_count = SIZE_MAX;
    bool features = true;

    CHECK(shell_parse_fast(input, length, &strict, &fast) == SHELL_OK);
    CHECK(shell_process_commands(input, length, NULL, &processed) ==
          SHELL_PROCESS_OK);
    CHECK(processed.commands != NULL && processed.command_count >= 1);
    CHECK(shell_build_netargv_sequence_buffer(input, length, NULL, &netargv,
                                              &count,
                                              &features) == SHELL_PROCESS_OK);
    CHECK(count >= 1 && features && corpus_valid_netsequence(&netargv, count));
    count = SIZE_MAX;
    CHECK(shell_build_command_netseq_buffer(input, length, NULL,
                                            &command_netseq,
                                            &count) == SHELL_PROCESS_OK);
    CHECK(count >= 1 && corpus_valid_netsequence(&command_netseq, count));
    count = SIZE_MAX;
    CHECK(shell_build_type_netseq_buffer(input, length, NULL, &type_netseq,
                                         &count) == SHELL_PROCESS_OK);
    CHECK(count >= 1 && corpus_valid_netsequence(&type_netseq, count));
    count = SIZE_MAX;
    CHECK(shell_build_anomaly_netseqs_buffer(input, length, NULL,
                                             &anomaly_commands, &anomaly_types,
                                             &count) == SHELL_PROCESS_OK);
    CHECK(count >= 1 && corpus_valid_netsequence(&anomaly_commands, count) &&
          corpus_valid_netsequence(&anomaly_types, count));
    CHECK(shell_transform_command_line(input, length, NULL, &transformed,
                                       &transformed_count) ==
          SHELL_TRANSFORM_OK);
    CHECK(transformed != NULL && transformed_count >= 1);
    CHECK(shell_abstract_command_parse(input, length, &abstract) ==
          SHELL_ABSTRACT_OK);
    CHECK(abstract != NULL);
    CHECK(shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
          SHELL_DEP_OK);
    CHECK(graph.node_count >= 1 && shell_dep_graph_validate(&graph).valid);
    shell_processed_commands_free(&processed);
    shell_netstring_buffer_free(&netargv);
    shell_netstring_buffer_free(&command_netseq);
    shell_netstring_buffer_free(&type_netseq);
    shell_netstring_buffer_free(&anomaly_commands);
    shell_netstring_buffer_free(&anomaly_types);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
  }
  return true;
}

static bool corpus_check_redirect_command_boundary(const char *input) {
  shell_netstring_buffer_t sequence = {0};
  size_t count = 0;
  bool features = false;
  CHECK(shell_build_netargv_sequence_buffer(input, strlen(input), NULL,
                                            &sequence, &count,
                                            &features) == SHELL_PROCESS_OK);
  static const char expected[] = "6:3:cat,,12:4:echo,2:hi,,";
  bool valid = count == 2 && sequence.length == sizeof(expected) - 1 &&
               memcmp(sequence.data, expected, sizeof(expected) - 1) == 0;
  shell_netstring_buffer_free(&sequence);
  CHECK(valid);

  shell_netstring_buffer_t anomaly = {0};
  count = 0;
  CHECK(shell_build_command_netseq_buffer(input, strlen(input), NULL, &anomaly,
                                          &count) == SHELL_PROCESS_OK);
  /* Process substitutions and expandable here-strings add child execution
   * stages ahead of the two top-level commands. The redirect-boundary matrix
   * is intentionally shared by both forms, so preserve the top-level netargv
   * assertion above and check the full anomaly sequence separately. */
  valid = count >= 2 && corpus_valid_netsequence(&anomaly, count);
  CHECK(valid);

  shell_netstring_buffer_t raw = {0}, typed = {0};
  size_t paired_count = 0;
  CHECK(shell_build_anomaly_netseqs_buffer(input, strlen(input), NULL, &raw,
                                           &typed,
                                           &paired_count) == SHELL_PROCESS_OK);
  valid = valid && paired_count == count && raw.length == anomaly.length &&
          memcmp(raw.data, anomaly.data, raw.length) == 0 &&
          corpus_valid_netsequence(&typed, paired_count);
  shell_netstring_buffer_free(&anomaly);
  shell_netstring_buffer_free(&raw);
  shell_netstring_buffer_free(&typed);
  CHECK(valid);
  return true;
}

TEST(redirect_separator_boundaries) {
  static const char *separators[] = {";", "|", "|&", "&&", "||", "&", "\n"};
  static const char *prefixes[] = {"cat >out", "{ cat; } >out"};
  static const char *spacing[] = {"", " "};
  for (size_t prefix = 0; prefix < ARRAY_COUNT(prefixes); prefix++)
    for (size_t i = 0; i < ARRAY_COUNT(separators); i++) {
      for (size_t space = 0; space < ARRAY_COUNT(spacing); space++) {
        char input[128];
        snprintf(input, sizeof(input), "%s%s%secho hi", prefixes[prefix],
                 separators[i], spacing[space]);
        CHECK(corpus_check_redirect_command_boundary(input));
      }
    }
  return true;
}

TEST(descriptor_graph_routes_and_identities) {
  static const struct {
    const char *input;
    const char *argument;
    uint32_t fd;
    bool write;
  } cases[] = {
      {"cat $'x'3>out", "x3", 1, true},
      {"cat ''3>out", "3", 1, true},
      {"cat \"\"0<<<body", "0", 0, false},
      {"cat $'x'0<<EOF\nbody\nEOF\n", "x0", 0, false},
      {"cat 1\\\n2>out", NULL, 12, true},
      {"cat 1\\\n2<<<body", NULL, 12, false},
      {"cat 1\\\n2<<EOF\nbody\nEOF\n", NULL, 12, false},
      {"cat 1\\\n2<<-'EOF'\n\tbody\n\tEOF\n", NULL, 12, false},
      {"{ cat; } 1\\\n2<<<body", NULL, 12, false},
      {"{ cat; } 1\\\n2<<EOF\nbody\nEOF\n", NULL, 12, false},
      {"(cat)3>out", NULL, 3, true},
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    shell_dep_graph_t graph = {0};
    CHECK(shell_dep_graph_parse(cases[i].input, strlen(cases[i].input), ".",
                                NULL, &graph) == SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(&graph).valid);
    uint32_t commands = 0, routes = 0;
    for (uint32_t n = 0; n < graph.node_count; n++) {
      if (graph.nodes[n].type != SHELL_NODE_CMD)
        continue;
      const shell_dep_cmd_t *cmd = &graph.nodes[n].cmd;
      commands++;
      CHECK(cmd->token_count == (cases[i].argument ? 2u : 1u));
      CHECK(cmd->token_lens[0] == 3 && memcmp(cmd->tokens[0], "cat", 3) == 0);
      if (cases[i].argument) {
        char decoded[16];
        size_t written = 0;
        CHECK(shell_write_decoded_word(cmd->tokens[1], cmd->token_lens[1],
                                       decoded, sizeof(decoded),
                                       &written) == SHELL_PROCESS_OK);
        CHECK(written == strlen(cases[i].argument) &&
              memcmp(decoded, cases[i].argument, written) == 0);
      }
    }
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const shell_dep_edge_t *edge = &graph.edges[e];
      if (graph.nodes[edge->from].type == SHELL_NODE_FD ||
          graph.nodes[edge->to].type == SHELL_NODE_FD)
        continue;
      if (cases[i].write && edge->type == SHELL_EDGE_WRITE) {
        CHECK(edge->source_fd == cases[i].fd);
        CHECK(graph.nodes[edge->from].type ==
              (cases[i].input[0] == '(' ? SHELL_NODE_GROUP : SHELL_NODE_CMD));
        routes++;
      } else if (!cases[i].write && edge->type == SHELL_EDGE_READ) {
        CHECK(edge->target_fd == cases[i].fd);
        CHECK(graph.nodes[edge->to].type ==
              (cases[i].input[0] == '{' ? SHELL_NODE_GROUP : SHELL_NODE_CMD));
        routes++;
      }
    }
    if (commands != 1 || routes != 1) {
      fprintf(stderr, "Descriptor graph case: %s (commands=%u routes=%u)\n",
              cases[i].input, commands, routes);
      return false;
    }
  }
  return true;
}

static int run_corpus(int argc, char **argv) {
  (void)argc;
  (void)argv;
  puts("shellsplit corpus tests");
  RUN(canonical_processing_surfaces_agree);
  RUN(supported_syntax_model_matrix);
  RUN(cross_surface_edge_syntax);
  RUN(redirect_only_stages_remain_graph_visible);
  RUN(malformed_syntax_is_rejected_atomically);
  RUN(unsupported_semantics_are_rejected_atomically);
  RUN(named_fd_process_substitutions_are_canonical);
  RUN(redirect_separator_boundaries);
  RUN(descriptor_graph_routes_and_identities);
  printf("\n%u passed, %u failed\n", corpus_passed, corpus_failed);
  return corpus_failed == 0 ? 0 : 1;
}
#undef ARRAY_COUNT
#undef CHECK
#undef TEST
#undef RUN

int main(int argc, char **argv) {
  int status = 0;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  status |= run_tokenizer(argc, argv);
#endif
  status |= run_parser(argc, argv);
  status |= run_boundary(argc, argv);
  status |= run_corpus(argc, argv);
  return status != 0;
}
