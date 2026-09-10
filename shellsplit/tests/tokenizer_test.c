#include "../src/shell_processor_internal.h"
#include "../src/shell_source_internal.h"
#include "../src/shell_tokenizer_full_internal.h"
#include "shell_depgraph.h"
#include "shell_processor.h"
#include "shell_sequence.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include "shell_transform.h"
#include "test_allocator.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;

typedef struct {
  unsigned char *bytes;
  size_t capacity;
  size_t stop_after;
} decoded_word_capture_t;

typedef struct {
  unsigned char bytes[64];
  size_t length;
  size_t stop_after;
} source_byte_capture_t;

typedef struct {
  size_t count;
  size_t starts[2];
  size_t lengths[2];
  bool quoted[2];
} heredoc_body_capture_t;

static bool capture_heredoc_body(const char *input, size_t body_start,
                                 size_t body_length, bool delimiter_quoted,
                                 void *context) {
  (void)input;
  heredoc_body_capture_t *capture = context;
  if (!capture ||
      capture->count == sizeof(capture->starts) / sizeof(capture->starts[0]))
    return false;
  size_t index = capture->count++;
  capture->starts[index] = body_start;
  capture->lengths[index] = body_length;
  capture->quoted[index] = delimiter_quoted;
  return true;
}

static bool capture_source_byte(unsigned char byte, void *context) {
  source_byte_capture_t *capture = context;
  if (capture->length == sizeof(capture->bytes) ||
      (capture->stop_after != 0 && capture->length == capture->stop_after))
    return false;
  capture->bytes[capture->length++] = byte;
  return true;
}

static bool capture_decoded_word_byte(unsigned char byte, size_t offset,
                                      void *context) {
  decoded_word_capture_t *capture = context;
  if (offset >= capture->capacity)
    return false;
  capture->bytes[offset] = byte;
  return capture->stop_after == 0 || offset + 1 < capture->stop_after;
}

void test(const char *name, int result) {
  test_count++;
  if (result) {
    pass_count++;
    printf("  [PASS] %s\n", name);
  } else {
    printf("  [FAIL] %s\n", name);
  }
}

static bool tokens_are_consistent(const char *input, shell_command_t *cmds,
                                  size_t count) {
  size_t input_len = strlen(input);
  for (size_t i = 0; i < count; i++) {
    if (cmds[i].start_pos > cmds[i].end_pos || cmds[i].end_pos > input_len)
      return false;
    for (size_t j = 0; j < cmds[i].token_count; j++) {
      shell_token_t *token = &cmds[i].tokens[j];
      if (token->position > input_len ||
          token->length > input_len - token->position ||
          token->start != input + token->position)
        return false;
    }
  }
  return true;
}

static bool processed_group_descriptors_match_source(
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

static void test_token_type_names(void) {
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

static void test_list_syntax_contract(void) {
  static const char *const valid[] = {
      "",
      "echo \\| \\& \\!",
      "echo '|' \"&&\"",
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
      "( echo one; )",
      "{ echo one; } >/tmp/group.out 2>&1",
      "( echo one; ) < <(printf input) | cat",
      "{ { echo one; } >/tmp/inner; echo two; } >/tmp/outer",
      "{ echo one; }; echo two",
      "( echo one; ) && echo two",
      "! ! command",
      "! \\\r\nprintf command",
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

  char nesting[(SHELL_MAX_GROUPS + 1u) * 2u + 2u];
  size_t position = 0;
  for (size_t i = 0; i <= SHELL_MAX_GROUPS; i++)
    nesting[position++] = '(';
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
      "! ! printf command |& cat",
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
}

static void test_source_scanner_boundaries(void) {
  static const struct {
    const char *prefix;
    bool descriptor;
  } boundaries[] = {
      {"", true},
      {"cat ", true},
      {"cat\t", true},
      {"cat\r\n", true},
      {"cat \\\n", true},
      {"cat \\\r\n", true},
      {"cat x\\ ", false},
      {"cat $'x'", false},
      {"cat ''", false},
      {"cat \"\"", false},
      {"cat $'x'\\\n", false},
      {"cat $'x'\\\r\n", false},
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
                        !shell_source_word_boundary("", 0, 1) &&
                        shell_source_io_number_start_before(NULL, 0, 0) == 0 &&
                        shell_source_io_number_start_before("", 0, 1) == 1;
  for (size_t i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); i++) {
    char source[128];
    int length =
        snprintf(source, sizeof(source), "%s1\\\n2>", boundaries[i].prefix);
    size_t start = strlen(boundaries[i].prefix);
    size_t marker = (size_t)length - 1;
    bool matched =
        length > 0 &&
        shell_source_word_boundary(source, (size_t)length, start) ==
            boundaries[i].descriptor &&
        shell_source_io_number_start_before(source, (size_t)length, marker) ==
            (boundaries[i].descriptor ? start : marker);
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
      {"{fd}>out", true, true},
      {"{f\\\nd}>out", true, true},
      {"{f\\\r\nd}\\\r\n>out", true, true},
      {"{fd} >out", true, false},
      {"{fd}\t>out", true, false},
      {"{f d}>out", false, false},
      {"x{fd}>out", false, false},
      {"''{fd}>out", false, false},
      {"$'x'{fd}>out", false, false},
      {"${x}{fd}>out", false, false},
      {"$(x){fd}>out", false, false},
      {"{9}>out", false, false},
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
    bool recovered =
        shell_source_named_fd_start_before(source, length, marker) == 0;
    valid = valid && parsed == named_boundaries[i].descriptor &&
            redirect == named_boundaries[i].redirect &&
            (!redirect || redirect_after == marker) &&
            recovered == named_boundaries[i].redirect;
  }

  valid = valid && shell_source_comment_starts("#x", 2, 0) &&
          shell_source_comment_starts("x;#x", 4, 2) &&
          !shell_source_comment_starts("x#x", 3, 1) &&
          shell_source_line_content_end("line\r\n", 6, 0) == 4 &&
          shell_source_next_line("line\nnext", 9, 0) == 5;
  static const char list_trivia[] = " \\\r\n# note\r\n\t\nstage";
  size_t stage = strlen(" \\\r\n# note\r\n\t\n");
  valid = valid &&
          shell_source_skip_list_trivia(list_trivia, sizeof(list_trivia) - 1,
                                        0) == stage &&
          shell_source_is_list_trivia(list_trivia, 0, stage) &&
          shell_source_skip_list_trivia("word", 4, 0) == 0 &&
          shell_source_skip_list_trivia(NULL, 0, 0) == 0;

  /* Escaped physical endings are list/redirect grammar, not word text. Cover
   * both lexer representations of CRLF (one token or `\\\r` plus LF) so
   * the source helper cannot regress one platform's token stream. */
  static const char lf_continuation[] = "\\\n";
  static const char crlf_continuation[] = "\\\r\n";
  valid =
      valid && !shell_source_is_escaped_line_ending(NULL, 0, 0) &&
      !shell_source_is_escaped_line_ending("x", 0, 1) &&
      !shell_source_is_escaped_line_ending("\\", 0, 1) &&
      shell_source_is_escaped_line_ending(lf_continuation, 0,
                                          sizeof(lf_continuation) - 1) &&
      shell_source_is_escaped_line_ending(crlf_continuation, 0,
                                          sizeof(crlf_continuation) - 1) &&
      shell_source_is_escaped_line_ending(crlf_continuation, 2,
                                          sizeof(crlf_continuation) - 1) &&
      shell_source_is_escaped_line_ending(crlf_continuation, 0, 2) &&
      shell_source_skip_inline_continuations(" \t\\\n\\\r\nword", 11, 0) == 7 &&
      shell_source_skip_inline_continuations("word", 4, 0) == 0 &&
      shell_source_skip_inline_continuations(NULL, 0, 0) == 0 &&
      shell_source_skip_list_trivia_backward(NULL, 0, 0) == 0 &&
      shell_source_skip_list_trivia_backward("cmd # note\r\n\t", 12, 12) == 3 &&
      shell_source_skip_list_trivia_backward("cmd \\\r", 6, 6) == 3 &&
      shell_source_skip_redirect("> >(cmd", 0, strlen("> >(cmd")) == 0;

  source_byte_capture_t capture = {0};
  static const char ansi[] = "$'\\a\\b\\e\\E\\f\\n\\r\\t\\v\\\\\\'\\\"\\?"
                             "\\cA\\x41\\u00e9\\U0001f600\\101\\q'";
  size_t position = 0;
  valid = valid &&
          shell_source_decode_ansi_c_quote(ansi, sizeof(ansi) - 1, &position,
                                           capture_source_byte, &capture) &&
          position == sizeof(ansi) - 1 && capture.length > 16;
  source_byte_capture_t rejected = {.stop_after = 1};
  position = 0;
  valid = valid &&
          !shell_source_decode_ansi_c_quote("$'ab'", strlen("$'ab'"), &position,
                                            capture_source_byte, &rejected) &&
          rejected.length == 1;
  /* Incomplete ANSI-C escapes remain literal bytes. This matters to the
   * canonical netargv builder because dropping the backslash changes argv. */
  source_byte_capture_t incomplete_control = {0};
  source_byte_capture_t incomplete_hex = {0};
  source_byte_capture_t incomplete_unicode = {0};
  position = 0;
  valid = valid &&
          shell_source_decode_ansi_c_quote("$'\\c'", strlen("$'\\c'"),
                                           &position, capture_source_byte,
                                           &incomplete_control) &&
          incomplete_control.length == 2 &&
          memcmp(incomplete_control.bytes, "\\c", 2) == 0;
  position = 0;
  valid =
      valid &&
      shell_source_decode_ansi_c_quote("$'\\x'", strlen("$'\\x'"), &position,
                                       capture_source_byte, &incomplete_hex) &&
      incomplete_hex.length == 2 && memcmp(incomplete_hex.bytes, "\\x", 2) == 0;
  position = 0;
  valid = valid &&
          shell_source_decode_ansi_c_quote("$'\\u'", strlen("$'\\u'"),
                                           &position, capture_source_byte,
                                           &incomplete_unicode) &&
          incomplete_unicode.length == 2 &&
          memcmp(incomplete_unicode.bytes, "\\u", 2) == 0;
  valid =
      valid &&
      shell_source_ansi_emit_codepoint(capture_source_byte, &capture, 0x800) &&
      shell_source_ansi_emit_codepoint(capture_source_byte, &capture,
                                       0x200000) &&
      shell_source_ansi_emit_codepoint(capture_source_byte, &capture,
                                       0x4000000) &&
      shell_source_ansi_emit_codepoint(capture_source_byte, &capture,
                                       UINT32_MAX);

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

  valid = valid && shell_source_skip_ansi_c_quote("plain", 5, 0) == 0 &&
          !shell_source_skip_complete_ansi_c_quote("$'unterminated", 14, 0,
                                                   &after) &&
          !shell_source_skip_complete_ansi_c_quote("$'x'", 4, 0, NULL) &&
          !shell_source_decode_ansi_c_quote(NULL, 0, &position,
                                            capture_source_byte, &capture);
  position = 0;
  valid = valid && !shell_source_decode_ansi_c_quote(
                       "$'trailing\\", strlen("$'trailing\\"), &position,
                       capture_source_byte, &capture);
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
                       capture_source_byte, &capture);
  position = 0;
  valid = valid && !shell_source_decode_ansi_c_quote(
                       "$'unterminated", strlen("$'unterminated"), &position,
                       capture_source_byte, &capture);

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
      shell_source_skip_redirect("2>&x", 0, 4) == 0 &&
      shell_source_skip_redirect("999999999999>out", 0, 16) == 0 &&
      shell_source_skip_redirect("{fd} >out", 0, strlen("{fd} >out")) == 0 &&
      shell_source_skip_redirect("{fd}\\\n>out", 0, strlen("{fd}\\\n>out")) ==
          strlen("{fd}\\\n>out") &&
      !shell_source_redirect_list_before_group("command", 0, 7);
  test("Shared source scanners cover quoting, documents, and redirects", valid);
}

static void test_named_fd_word_boundaries(void) {
  static const struct {
    const char *input;
    const char *netseq;
    size_t words;
  } cases[] = {
      {"cat $'x'{fd}>out", "14:3:cat,5:x{fd},,", 2},
      {"cat ''{fd}>out", "13:3:cat,4:{fd},,", 2},
      {"cat ${x}{fd}>out", "17:3:cat,8:${x}{fd},,", 2},
      {"cat $(x){fd}>out", "17:3:cat,8:$(x){fd},,", 2},
      {"cat {f\\\nd}>out", "6:3:cat,,", 1},
      {"cat {f\\\r\nd}\\\n>out", "6:3:cat,,", 1},
      {"cat {fd} >out", "13:3:cat,4:{fd},,", 2},
      {"cat {fd}\t>out", "13:3:cat,4:{fd},,", 2},
      {"cat {f d}>out", "16:3:cat,2:{f,2:d},,", 3},
      {"cat $'x'{fd}<<<body", "14:3:cat,5:x{fd},,", 2},
      {"cat {f\\\nd}<<<body", "6:3:cat,,", 1},
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char *sequence = NULL;
    size_t count = 0;
    bool features = false;
    shell_processed_commands_t processed = {0};
    valid = valid &&
            shell_build_netargv_sequence(cases[i].input, strlen(cases[i].input),
                                         NULL, &sequence, &count,
                                         &features) == SHELL_PROCESS_OK &&
            sequence && strcmp(sequence, cases[i].netseq) == 0 && count == 1 &&
            features &&
            shell_process_commands(cases[i].input, strlen(cases[i].input), NULL,
                                   &processed) == SHELL_PROCESS_OK &&
            processed.command_count == 1 &&
            processed.commands[0].command_token_count == cases[i].words;
    shell_processed_commands_free(&processed);
    free(sequence);
  }
  test("Named descriptors require whole words across canonical APIs", valid);
}

static void test_record_parser_boundaries(void) {
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
  shell_processed_word_iterator_t pipe_iterator;
  shell_token_t pipe_word;
  valid =
      valid &&
      shell_processed_commands_parse("left |& right", strlen("left |& right"),
                                     NULL, &commands,
                                     &count) == SHELL_PROCESS_OK &&
      commands != NULL && count == 2 &&
      shell_processed_command_word_count(&commands[0]) == 1 &&
      (shell_processed_word_iterator_init(&pipe_iterator, &commands[0]),
       shell_processed_word_iterator_next(&pipe_iterator, &pipe_word)) &&
      !shell_processed_word_iterator_next(&pipe_iterator, &pipe_word) &&
      shell_processed_command_has_pipe_output(&commands[0]) &&
      shell_processed_command_has_dangerous_features(&commands[1], true) &&
      !shell_processed_command_is_group_structure(
          commands, count, 0, "left |& right", sizeof("left |& right") - 1) &&
      !shell_processed_command_is_group_structure(NULL, 0, 0, NULL, 0);
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
  const shell_command_t structural_empty = {0};
  shell_processed_word_iterator_t redirect_iterator;
  shell_token_t redirect_word;
  shell_processed_word_iterator_init(&redirect_iterator, &redirect_boundary);
  valid =
      valid && shell_processed_command_word_count(&redirect_boundary) == 1 &&
      shell_processed_word_iterator_next(&redirect_iterator, &redirect_word) &&
      redirect_word.start == redirect_boundary_tokens[2].start &&
      redirect_word.length == redirect_boundary_tokens[2].length &&
      !shell_processed_word_iterator_next(&redirect_iterator, &redirect_word) &&
      shell_processed_command_is_group_structure(&structural_empty, 1, 0, NULL,
                                                 0);

  valid = valid &&
          shell_process_validate_supported_source(NULL, 0, NULL) ==
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

static void test_modern_bash_syntax_contract(void) {
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
      SHELL_GROUP_IO_PIPE_OUTPUT_STDERR == 16;
  test("Group I/O enum appends pipe-both output", enum_values_stable);

  const char *source = "! printf $'a\\0b' @(left|right) items=(one two) &>out";
  shell_tokenizer_state_t state;
  shell_token_t token;
  shell_parse_result_t parsed = {0};
  shell_command_info_t *infos = NULL;
  size_t count = 0;
  shell_token_type_t expected[] = {
      SHELL_TOKEN_PIPE_NEGATE,      SHELL_TOKEN_COMMAND,
      SHELL_TOKEN_ANSI_C_QUOTED,    SHELL_TOKEN_EXTGLOB,
      SHELL_TOKEN_ARRAY_ASSIGNMENT, SHELL_TOKEN_REDIRECT_BOTH,
      SHELL_TOKEN_COMMAND,
  };
  bool valid = shell_tokenizer_init(&state, source, strlen(source));
  for (size_t i = 0; valid && i < sizeof(expected) / sizeof(expected[0]); i++)
    valid = shell_tokenizer_next(&state, &token) && token.type == expected[i];
  valid = valid && !shell_tokenizer_next(&state, &token);
  test("Modern Bash syntax has dedicated lexical tokens", valid);

  const char *pipe_both_source = "left|&right";
  shell_token_type_t pipe_both_tokens[] = {
      SHELL_TOKEN_COMMAND, SHELL_TOKEN_PIPE_BOTH, SHELL_TOKEN_COMMAND};
  valid =
      shell_tokenizer_init(&state, pipe_both_source, strlen(pipe_both_source));
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
      {"{ left; } |& \\\r\n{ right; }", SHELL_PIPE_MODE_STDOUT_AND_STDERR,
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

  valid = shell_parse_fast(source, strlen(source), NULL, &parsed) == SHELL_OK &&
          parsed.count == 1 &&
          (parsed.cmds[0].modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0 &&
          (parsed.cmds[0].features & SHELL_FEAT_ANSI_C_QUOTE) != 0 &&
          (parsed.cmds[0].features & SHELL_FEAT_EXTGLOB) != 0 &&
          (parsed.cmds[0].features & SHELL_FEAT_ARRAY) != 0 &&
          (parsed.cmds[0].features & SHELL_FEAT_COMBINED_REDIRECT) != 0;
  test("Fast parser preserves modern Bash feature metadata", valid);

  parsed = (shell_parse_result_t){0};
  valid =
      shell_parse_fast(">out items=(one two)", strlen(">out items=(one two)"),
                       NULL, &parsed) == SHELL_OK &&
      parsed.count == 1 && (parsed.cmds[0].features & SHELL_FEAT_ARRAY) != 0;
  test("Fast array context retains leading redirection state", valid);

  infos = NULL;
  count = 0;
  shell_netstring_buffer_t netargv = {0};
  valid = shell_process_command("printf $'a\\0b'", strlen("printf $'a\\0b'"),
                                NULL, &infos, &count) == SHELL_PROCESS_OK &&
          count == 1 &&
          shell_render_netargv_buffer(&infos[0], NULL, &netargv) ==
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
  test("ANSI-C NUL escape survives canonical netargv", valid);

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
  static const unsigned char extended_ansi_expected[] = {
      0xed, 0xa0, 0x80, 0xf4, 0x90, 0x80, 0x80,
  };
  unsigned char extended_ansi[sizeof(extended_ansi_expected)] = {0};
  ansi_length = 0;
  ansi_written = 0;
  valid = shell_measure_decoded_word(extended_ansi_source,
                                     sizeof(extended_ansi_source) - 1,
                                     &ansi_length) == SHELL_PROCESS_OK &&
          ansi_length == sizeof(extended_ansi_expected) &&
          shell_write_decoded_word(extended_ansi_source,
                                   sizeof(extended_ansi_source) - 1,
                                   (char *)extended_ansi, sizeof(extended_ansi),
                                   &ansi_written) == SHELL_PROCESS_OK &&
          ansi_written == sizeof(extended_ansi_expected) &&
          memcmp(extended_ansi, extended_ansi_expected,
                 sizeof(extended_ansi_expected)) == 0;
  test("ANSI-C retains Bash extended Unicode byte forms", valid);

  char *legacy = NULL;
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
      sequence_count == 1 &&
      shell_build_command_netseq_buffer(binary_source, strlen(binary_source),
                                        NULL, &command_sequence,
                                        &sequence_count) == SHELL_PROCESS_OK &&
      sequence_count == 1 &&
      shell_build_type_netseq_buffer(binary_source, strlen(binary_source), NULL,
                                     &type_sequence,
                                     &sequence_count) == SHELL_PROCESS_OK &&
      sequence_count == 1 &&
      shell_build_anomaly_netseqs_buffer(
          binary_source, strlen(binary_source), NULL, &anomaly_commands,
          &anomaly_types, &sequence_count) == SHELL_PROCESS_OK &&
      sequence_count == 1 &&
      shell_build_netargv_sequence(binary_source, strlen(binary_source), NULL,
                                   &legacy, &sequence_count,
                                   &features) == SHELL_PROCESS_EOUTPUT_LIMIT &&
      legacy == NULL &&
      shell_build_command_netseq(binary_source, strlen(binary_source), NULL,
                                 &legacy, &sequence_count) ==
          SHELL_PROCESS_EOUTPUT_LIMIT &&
      legacy == NULL &&
      shell_build_type_netseq(binary_source, strlen(binary_source), NULL,
                              &legacy,
                              &sequence_count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
      legacy == NULL;
  shell_netstring_buffer_free(&argv_sequence);
  shell_netstring_buffer_free(&command_sequence);
  shell_netstring_buffer_free(&type_sequence);
  shell_netstring_buffer_free(&anomaly_commands);
  shell_netstring_buffer_free(&anomaly_types);
  test("Canonical sequence buffers retain binary payloads", valid);

  char *aliased_netseq = NULL;
  shell_netstring_buffer_t aliased_buffer = {0};
  valid = shell_build_anomaly_netseqs(
              "echo value", strlen("echo value"), NULL, &aliased_netseq,
              &aliased_netseq, &sequence_count) == SHELL_PROCESS_EINPUT &&
          aliased_netseq == NULL &&
          shell_build_anomaly_netseqs_buffer(
              "echo value", strlen("echo value"), NULL, &aliased_buffer,
              &aliased_buffer, &sequence_count) == SHELL_PROCESS_EINPUT &&
          aliased_buffer.data == NULL && aliased_buffer.length == 0;
  test("Aligned anomaly sequence outputs reject aliasing", valid);

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
      {"command typeset -A items", SHELL_PROCESS_EPARSE},
      {"command -p -- declare -a items", SHELL_PROCESS_EPARSE},
      {"builtin -- typeset -A items", SHELL_PROCESS_EPARSE},
      {"echo item[0]=one", SHELL_PROCESS_OK},
      {"echo one ;& echo two", SHELL_PROCESS_EPARSE},
      {"echo one ;;& echo two", SHELL_PROCESS_EPARSE},
      {"echo $(echo one ;& echo two)", SHELL_PROCESS_EPARSE},
      {"cmd {fd}>&1", SHELL_PROCESS_EPARSE},
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

static void test_processor_routing_cross_product(void) {
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

static void test_canonical_buffer_output_contract(void) {
  const char *source = "printf value";
  shell_command_info_t *infos = NULL;
  size_t info_count = 0;
  shell_netstring_buffer_t rendered = {0};
  shell_netstring_buffer_t argv_sequence = {0};
  shell_netstring_buffer_t command_sequence = {0};
  shell_netstring_buffer_t type_sequence = {0};
  shell_netstring_buffer_t anomaly_commands = {0};
  shell_netstring_buffer_t anomaly_types = {0};
  size_t count = 0;
  bool features = false;

  bool valid = shell_process_command(source, strlen(source), NULL, &infos,
                                     &info_count) == SHELL_PROCESS_OK &&
               info_count == 1 &&
               shell_render_netargv_buffer(&infos[0], NULL, &rendered) ==
                   SHELL_PROCESS_OK &&
               rendered.data != NULL && rendered.length != 0;
  shell_netstring_buffer_free(&rendered);
  valid = valid &&
          shell_render_netargv_buffer(&infos[0], NULL, &rendered) ==
              SHELL_PROCESS_OK &&
          rendered.data != NULL && rendered.length != 0;
  unsigned char *rendered_data = rendered.data;
  size_t rendered_length = rendered.length;
  valid = valid &&
          shell_render_netargv_buffer(&infos[0], NULL, &rendered) ==
              SHELL_PROCESS_EINPUT &&
          rendered.data == rendered_data && rendered.length == rendered_length;
  shell_netstring_buffer_free(&rendered);
  valid = valid &&
          shell_render_netargv_buffer(NULL, NULL, &rendered) ==
              SHELL_PROCESS_EINPUT &&
          rendered.data == NULL && rendered.length == 0;
  shell_netstring_buffer_t inconsistent = {.length = 1};
  valid = valid && !shell_netstring_buffer_is_empty(&inconsistent) &&
          shell_render_netargv_buffer(&infos[0], NULL, &inconsistent) ==
              SHELL_PROCESS_EINPUT &&
          inconsistent.data == NULL && inconsistent.length == 1;
  shell_command_infos_free(infos, info_count);

  valid = valid &&
          shell_build_netargv_sequence_buffer(source, strlen(source), NULL,
                                              &argv_sequence, &count,
                                              &features) == SHELL_PROCESS_OK &&
          argv_sequence.data != NULL && argv_sequence.length != 0;
  unsigned char *argv_data = argv_sequence.data;
  size_t argv_length = argv_sequence.length;
  valid =
      valid &&
      shell_build_netargv_sequence_buffer(source, strlen(source), NULL,
                                          &argv_sequence, &count,
                                          &features) == SHELL_PROCESS_EINPUT &&
      argv_sequence.data == argv_data && argv_sequence.length == argv_length;
  shell_netstring_buffer_free(&argv_sequence);
  valid = valid &&
          shell_build_netargv_sequence_buffer(source, strlen(source), NULL,
                                              &argv_sequence, &count,
                                              &features) == SHELL_PROCESS_OK &&
          argv_sequence.data != NULL && argv_sequence.length != 0;
  shell_netstring_buffer_free(&argv_sequence);
  count = SIZE_MAX;
  features = true;
  valid = valid &&
          shell_build_netargv_sequence_buffer(
              "while true; do :; done", strlen("while true; do :; done"), NULL,
              &argv_sequence, &count, &features) == SHELL_PROCESS_EPARSE &&
          argv_sequence.data == NULL && argv_sequence.length == 0 &&
          count == 0 && !features;

  valid = valid &&
          shell_build_command_netseq_buffer(source, strlen(source), NULL,
                                            &command_sequence,
                                            &count) == SHELL_PROCESS_OK &&
          command_sequence.data != NULL && command_sequence.length != 0;
  unsigned char *command_data = command_sequence.data;
  size_t command_length = command_sequence.length;
  valid = valid &&
          shell_build_command_netseq_buffer(source, strlen(source), NULL,
                                            &command_sequence,
                                            &count) == SHELL_PROCESS_EINPUT &&
          command_sequence.data == command_data &&
          command_sequence.length == command_length;
  shell_netstring_buffer_free(&command_sequence);
  valid = valid &&
          shell_build_command_netseq_buffer(source, strlen(source), NULL,
                                            &command_sequence,
                                            &count) == SHELL_PROCESS_OK &&
          command_sequence.data != NULL && command_sequence.length != 0;
  shell_netstring_buffer_free(&command_sequence);
  count = SIZE_MAX;
  valid = valid &&
          shell_build_command_netseq_buffer(
              "while true; do :; done", strlen("while true; do :; done"), NULL,
              &command_sequence, &count) == SHELL_PROCESS_EPARSE &&
          command_sequence.data == NULL && command_sequence.length == 0 &&
          count == 0;

  valid = valid &&
          shell_build_type_netseq_buffer(source, strlen(source), NULL,
                                         &type_sequence,
                                         &count) == SHELL_PROCESS_OK &&
          type_sequence.data != NULL && type_sequence.length != 0;
  unsigned char *type_data = type_sequence.data;
  size_t type_length = type_sequence.length;
  valid = valid &&
          shell_build_type_netseq_buffer(source, strlen(source), NULL,
                                         &type_sequence,
                                         &count) == SHELL_PROCESS_EINPUT &&
          type_sequence.data == type_data &&
          type_sequence.length == type_length;
  shell_netstring_buffer_free(&type_sequence);
  valid = valid &&
          shell_build_type_netseq_buffer(source, strlen(source), NULL,
                                         &type_sequence,
                                         &count) == SHELL_PROCESS_OK &&
          type_sequence.data != NULL && type_sequence.length != 0;
  shell_netstring_buffer_free(&type_sequence);
  count = SIZE_MAX;
  valid = valid &&
          shell_build_type_netseq_buffer(
              "while true; do :; done", strlen("while true; do :; done"), NULL,
              &type_sequence, &count) == SHELL_PROCESS_EPARSE &&
          type_sequence.data == NULL && type_sequence.length == 0 && count == 0;

  valid = valid &&
          shell_build_anomaly_netseqs_buffer(source, strlen(source), NULL,
                                             &anomaly_commands, &anomaly_types,
                                             &count) == SHELL_PROCESS_OK &&
          anomaly_commands.data != NULL && anomaly_commands.length != 0 &&
          anomaly_types.data != NULL && anomaly_types.length != 0;
  unsigned char *anomaly_command_data = anomaly_commands.data;
  size_t anomaly_command_length = anomaly_commands.length;
  unsigned char *anomaly_type_data = anomaly_types.data;
  size_t anomaly_type_length = anomaly_types.length;
  valid = valid &&
          shell_build_anomaly_netseqs_buffer(source, strlen(source), NULL,
                                             &anomaly_commands, &anomaly_types,
                                             &count) == SHELL_PROCESS_EINPUT &&
          anomaly_commands.data == anomaly_command_data &&
          anomaly_commands.length == anomaly_command_length &&
          anomaly_types.data == anomaly_type_data &&
          anomaly_types.length == anomaly_type_length;
  shell_netstring_buffer_free(&anomaly_commands);
  shell_netstring_buffer_free(&anomaly_types);
  valid = valid &&
          shell_build_anomaly_netseqs_buffer(source, strlen(source), NULL,
                                             &anomaly_commands, &anomaly_types,
                                             &count) == SHELL_PROCESS_OK &&
          anomaly_commands.data != NULL && anomaly_commands.length != 0 &&
          anomaly_types.data != NULL && anomaly_types.length != 0;
  shell_netstring_buffer_free(&anomaly_commands);
  shell_netstring_buffer_free(&anomaly_types);
  count = SIZE_MAX;
  valid =
      valid &&
      shell_build_anomaly_netseqs_buffer(
          "while true; do :; done", strlen("while true; do :; done"), NULL,
          &anomaly_commands, &anomaly_types, &count) == SHELL_PROCESS_EPARSE &&
      anomaly_commands.data == NULL && anomaly_commands.length == 0 &&
      anomaly_types.data == NULL && anomaly_types.length == 0 && count == 0;

  test("Canonical buffer outputs require release before reuse", valid);
}

static void test_array_semantic_boundaries(void) {
  static const char *const supported[] = {
      "echo ${x:-[abc]}",    "echo ${x#[abc]}",
      "echo ${x%[abc]}",     "echo ${x//[abc]/q}",
      "echo ${x:-foo[bar]}", "echo \\${items[0]}",
      "echo '${items[0]}'",  "echo $(( ${x:-[abc]} + 1 ))",
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

static void test_ansi_c_structural_scanner_contract(void) {
  static const char *const cases[] = {
      "echo $(printf $'foo\\'bar)')",
      "cat <(printf $'foo\\'bar)')",
      "echo $(( $(printf $'foo\\'bar)') + 1 ))",
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
  valid = shell_tokenizer_init(&state, arithmetic, strlen(arithmetic)) &&
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
    valid = valid && shell_tokenizer_init(&state, input, strlen(input)) &&
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

static void test_error_strings(void) {
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

static void test_composition_metadata(void) {
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

static bool is_cleared_end_token(const shell_token_t *token) {
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
} iterator_case_t;

static void run_iterator_cases(const iterator_case_t *cases, size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_tokenizer_state_t state;
    shell_tokenizer_init(&state, cases[i].input, strlen(cases[i].input));
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
            is_cleared_end_token(&end_token) && valid;
    test(cases[i].name, valid);
  }
}

static void test_iterator_argument_contracts(void) {
  shell_tokenizer_state_t state;
  memset(&state, 0xA5, sizeof(state));
  shell_tokenizer_init(&state, NULL, 0);
  shell_token_t token;
  memset(&token, 0xA5, sizeof(token));
  bool null_input =
      state.input && state.input[0] == '\0' && state.position == 0 &&
      state.length == 0 && !state.in_quotes && !state.in_subshell &&
      state.quote_char == '\0' && state.paren_depth == 0 &&
      state.brace_depth == 0 && !state.in_arithmetic &&
      state.arith_depth == 0 && state.if_depth == 0 && state.loop_depth == 0 &&
      state.case_depth == 0 && !shell_tokenizer_next(&state, &token) &&
      is_cleared_end_token(&token);

  shell_tokenizer_init(&state, "echo", strlen("echo"));
  size_t initial_position = state.position;
  bool null_output =
      !shell_tokenizer_next(&state, NULL) && state.position == initial_position;

  memset(&token, 0xA5, sizeof(token));
  bool null_state =
      !shell_tokenizer_next(NULL, &token) && is_cleared_end_token(&token);
  memset(&state, 0, sizeof(state));
  memset(&token, 0xA5, sizeof(token));
  bool zero_state =
      !shell_tokenizer_next(&state, &token) && is_cleared_end_token(&token);
  shell_tokenizer_init(&state, "cmd\x01suffix", strlen("cmd\x01suffix"));
  memset(&token, 0xA5, sizeof(token));
  bool invalid_input =
      !shell_tokenizer_next(&state, &token) && is_cleared_end_token(&token);
  shell_tokenizer_init(NULL, "ignored", strlen("ignored"));

  shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
  size_t command_count = SIZE_MAX;
  bool aggregate_null_input =
      shell_tokenize_commands(NULL, 0, &commands, &command_count) ==
          SHELL_TOKENIZE_EINPUT &&
      commands == NULL && command_count == 0;
  bool missing_outputs =
      shell_tokenize_commands("echo", strlen("echo"), NULL, &command_count) ==
          SHELL_TOKENIZE_EINPUT &&
      shell_tokenize_commands("echo", strlen("echo"), &commands, NULL) ==
          SHELL_TOKENIZE_EINPUT;
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
  test("Tokenizer iterator: NULL and exhausted argument contracts",
       null_input && null_output && null_state && zero_state && invalid_input &&
           aggregate_null_input && missing_outputs && bounded_input_ok &&
           embedded_nul_rejected && parse_status == SHELL_TOKENIZE_EPARSE &&
           commands == NULL && command_count == 0);
}

typedef struct {
  const char *name;
  const char *input;
  size_t command_count;
} tokenizer_case_t;

static void run_tokenizer_cases(const tokenizer_case_t *cases, size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    bool parsed = (shell_tokenize_commands(
                       cases[i].input, strlen(cases[i].input), &commands,
                       &command_count) == SHELL_TOKENIZE_OK);
    test(cases[i].name,
         parsed && command_count == cases[i].command_count &&
             tokens_are_consistent(cases[i].input, commands, command_count));
    shell_commands_free(commands, command_count);
  }
}

static void check_tokenizer_case(const char *name, const char *input,
                                 size_t expected_count) {
  shell_command_t *commands = NULL;
  size_t command_count = 0;
  bool parsed = (shell_tokenize_commands(input, strlen(input), &commands,
                                         &command_count) == SHELL_TOKENIZE_OK);
  bool valid = parsed && command_count == expected_count &&
               tokens_are_consistent(input, commands, command_count);
  if (!valid)
    printf("    commands: got %zu, expected %zu\n", command_count,
           expected_count);
  test(name, valid);
  shell_commands_free(commands, command_count);
}

static void run_rejected_cases(const tokenizer_case_t *cases, size_t count) {
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
  EXPECT_VARIABLE = 1u << 0,
  EXPECT_GLOB = 1u << 1,
  EXPECT_SUBSHELL = 1u << 2,
  EXPECT_ARITHMETIC = 1u << 3,
  EXPECT_LOOP = 1u << 4,
  EXPECT_CONDITIONAL = 1u << 5,
  EXPECT_CASE = 1u << 6,
  EXPECT_SHELL_FEATURE =
      EXPECT_VARIABLE | EXPECT_GLOB | EXPECT_SUBSHELL | EXPECT_ARITHMETIC,
};

typedef struct {
  tokenizer_case_t tokenizer;
  unsigned features;
} feature_case_t;

static void run_feature_cases(const feature_case_t *cases, size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    bool parsed =
        (shell_tokenize_commands(cases[i].tokenizer.input,
                                 strlen(cases[i].tokenizer.input), &commands,
                                 &command_count) == SHELL_TOKENIZE_OK);
    unsigned features = 0;
    bool feature_api_consistent = true;
    for (size_t j = 0; j < command_count; j++) {
      unsigned command_features =
          (commands[j].has_variables ? EXPECT_VARIABLE : 0) |
          (commands[j].has_globs ? EXPECT_GLOB : 0) |
          (commands[j].has_subshells ? EXPECT_SUBSHELL : 0) |
          (commands[j].has_arithmetic ? EXPECT_ARITHMETIC : 0) |
          (commands[j].has_loops ? EXPECT_LOOP : 0) |
          (commands[j].has_conditionals ? EXPECT_CONDITIONAL : 0) |
          (commands[j].has_case ? EXPECT_CASE : 0);
      features |= command_features;
      if (shell_command_has_shell_features(&commands[j]) !=
          ((command_features & EXPECT_SHELL_FEATURE) != 0))
        feature_api_consistent = false;
    }
    bool valid = parsed && command_count == cases[i].tokenizer.command_count &&
                 features == cases[i].features && feature_api_consistent &&
                 tokens_are_consistent(cases[i].tokenizer.input, commands,
                                       command_count);
    if (!valid)
      printf("    features: count=%zu expected=%zu got=%#x expected=%#x\n",
             command_count, cases[i].tokenizer.command_count, features,
             cases[i].features);
    test(cases[i].tokenizer.name, valid);
    shell_commands_free(commands, command_count);
  }
}

typedef struct {
  tokenizer_case_t tokenizer;
  uint64_t variable_stages;
  uint64_t glob_stages;
  uint64_t subshell_stages;
  uint64_t arithmetic_stages;
} stage_case_t;

static void run_stage_cases(const stage_case_t *cases, size_t count) {
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
    bool feature_api_consistent = true;
    for (size_t j = 0; j < command_count && j < 64; j++) {
      uint64_t stage = UINT64_C(1) << j;
      variables |= commands[j].has_variables ? stage : 0;
      globs |= commands[j].has_globs ? stage : 0;
      subshells |= commands[j].has_subshells ? stage : 0;
      arithmetic |= commands[j].has_arithmetic ? stage : 0;
      bool has_feature = commands[j].has_variables || commands[j].has_globs ||
                         commands[j].has_subshells ||
                         commands[j].has_arithmetic;
      if (shell_command_has_shell_features(&commands[j]) != has_feature)
        feature_api_consistent = false;
    }
    bool valid = parsed && command_count == cases[i].tokenizer.command_count &&
                 command_count <= 64 && variables == cases[i].variable_stages &&
                 globs == cases[i].glob_stages &&
                 subshells == cases[i].subshell_stages &&
                 arithmetic == cases[i].arithmetic_stages &&
                 feature_api_consistent &&
                 tokens_are_consistent(cases[i].tokenizer.input, commands,
                                       command_count);
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
  PROCESS_PIPE_INPUT = 1u << 0,
  PROCESS_PIPE_OUTPUT = 1u << 1,
  PROCESS_REDIRECTION = 1u << 2,
  PROCESS_ERROR_REDIRECTION = 1u << 3,
};

typedef struct {
  const char *name;
  const char *input;
  size_t command_count;
  const char *original_commands[4];
  const char *legacy_renderings[4];
  unsigned flags[4];
  unsigned feature_stages;
} processor_case_t;

static bool tokens_refer_to_owned_command(const shell_token_t *tokens,
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

static void run_processor_cases(const processor_case_t *cases, size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_command_info_t *infos = NULL;
    size_t command_count = 0;
    shell_process_status_t process_status = shell_process_command(
        cases[i].input, strlen(cases[i].input), NULL, &infos, &command_count);
    bool has_shell_features = false;
    bool processed = process_status == SHELL_PROCESS_OK;
    bool valid = processed && command_count == cases[i].command_count &&
                 (command_count == 0 || infos);
    for (size_t j = 0; infos && j < cases[i].command_count && j < command_count;
         j++) {
      unsigned flags =
          (infos[j].has_pipe_input ? PROCESS_PIPE_INPUT : 0) |
          (infos[j].has_pipe_output ? PROCESS_PIPE_OUTPUT : 0) |
          (infos[j].has_redirections ? PROCESS_REDIRECTION : 0) |
          (infos[j].has_error_redirection ? PROCESS_ERROR_REDIRECTION : 0);
      bool expected_feature = (cases[i].feature_stages & (1u << j)) != 0;
      char *netargv = NULL;
      bool rendered =
          shell_render_netargv(&infos[j], NULL, &netargv) == SHELL_PROCESS_OK;
      bool stage_valid =
          infos[j].original_command && rendered && netargv &&
          strcmp(infos[j].original_command, cases[i].original_commands[j]) ==
              0 &&
          flags == cases[i].flags[j] &&
          tokens_refer_to_owned_command(infos[j].shell_tokens,
                                        infos[j].shell_token_count,
                                        infos[j].original_command) &&
          tokens_refer_to_owned_command(infos[j].command_tokens,
                                        infos[j].command_token_count,
                                        infos[j].original_command) &&
          shell_command_info_has_dangerous_features(&infos[j]) ==
              expected_feature;
      if (!stage_valid)
        printf("    stage %zu: original='%s' netargv='%s' flags=%#x "
               "feature=%d\n",
               j, infos[j].original_command ? infos[j].original_command : "",
               netargv ? netargv : "", flags,
               shell_command_info_has_dangerous_features(&infos[j]));
      free(netargv);
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
} transform_line_case_t;

static void run_transform_line_cases(const transform_line_case_t *cases,
                                     size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_transformed_command_t **commands = NULL;
    size_t command_count = 0;
    bool transformed = shell_transform_command_line(
                           cases[i].input, strlen(cases[i].input), NULL,
                           &commands, &command_count) == SHELL_TRANSFORM_OK;
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
              commands[j]->has_shell_syntax == expected_shell &&
              shell_transformed_command_has_transformations(commands[j]) ==
                  expected_transform &&
              shell_transformed_command_get_display_text(commands[j]) ==
                  commands[j]->display_text;
    }
    if (!valid)
      printf("    transform line: count=%zu expected=%zu\n", command_count,
             cases[i].command_count);
    test(cases[i].name, valid);
    shell_transformed_command_list_free(commands, command_count);
  }
}

static void test_tokenize_allocation_failures(void) {
  static const char input[] =
      "echo a b c d e f g h i j k l m n o p q r ; printf x ; sort";
  shell_command_t *commands = NULL;
  size_t count = 0;
  shellsplit_test_alloc_reset();
  bool success = (shell_tokenize_commands(input, strlen(input), &commands,
                                          &count) == SHELL_TOKENIZE_OK);
  size_t allocations = shellsplit_test_alloc_count();
  test("Allocation probe tokenizes multiple grown commands",
       success && count == 3 && allocations >= 5);
  shell_commands_free(commands, count);

  bool atomic = true;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    commands = (shell_command_t *)(void *)1;
    count = SIZE_MAX;
    shellsplit_test_alloc_fail_at(fail_at);
    success = (shell_tokenize_commands(input, strlen(input), &commands,
                                       &count) == SHELL_TOKENIZE_OK);
    shellsplit_test_alloc_reset();
    if (success || commands != NULL || count != 0) {
      atomic = false;
      shell_commands_free(commands, count);
      break;
    }
  }
  test("Tokenizer allocation failures clear outputs", atomic);

  static const char compound_input[] =
      "{ printf left; } 3>/tmp/left | { cat; } 2>>/tmp/right && "
      "{ printf tail; }";
  commands = NULL;
  count = 0;
  shellsplit_test_alloc_reset();
  success = shell_tokenize_commands(compound_input, strlen(compound_input),
                                    &commands, &count) == SHELL_TOKENIZE_OK;
  allocations = shellsplit_test_alloc_count();
  bool compound_success = success && commands != NULL && count == 3;
  shell_commands_free(commands, count);

  atomic = true;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    commands = (shell_command_t *)(void *)1;
    count = SIZE_MAX;
    shellsplit_test_alloc_fail_at(fail_at);
    success = shell_tokenize_commands(compound_input, strlen(compound_input),
                                      &commands, &count) == SHELL_TOKENIZE_OK;
    shellsplit_test_alloc_reset();
    if (success || commands != NULL || count != 0) {
      atomic = false;
      shell_commands_free(commands, count);
      break;
    }
  }
  test("Compound brace growth is allocation-failure atomic",
       compound_success && atomic);
}

static void test_processor_allocation_failures(void) {
  static const char input[] =
      "echo prefix$USER-suffix a b c d e f g h i j k l m n o p | grep "
      "'*.txt'";
  shell_command_info_t *infos = NULL;
  size_t count = 0;
  shellsplit_test_alloc_reset();
  shell_process_status_t status =
      shell_process_command(input, strlen(input), NULL, &infos, &count);
  size_t allocations = shellsplit_test_alloc_count();
  test("Processor allocation probe succeeds",
       status == SHELL_PROCESS_OK && count == 2 && allocations > 5);
  shell_command_infos_free(infos, count);

  bool atomic = true;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    infos = (shell_command_info_t *)(void *)1;
    count = SIZE_MAX;
    shellsplit_test_alloc_fail_at(fail_at);
    status = shell_process_command(input, strlen(input), NULL, &infos, &count);
    shellsplit_test_alloc_reset();
    if (status != SHELL_PROCESS_ENOMEM || infos != NULL || count != 0) {
      atomic = false;
      shell_command_infos_free(infos, count);
      break;
    }
  }
  test("Processor allocation failures report ENOMEM and clear outputs", atomic);

  static const char repeated_negation[] = "! ! true";
  shell_processed_commands_t repeated = {0};
  shellsplit_test_alloc_reset();
  status = shell_process_commands(
      repeated_negation, sizeof(repeated_negation) - 1, NULL, &repeated);
  allocations = shellsplit_test_alloc_count();
  bool repeated_success = status == SHELL_PROCESS_OK &&
                          repeated.command_count == 1 &&
                          repeated.commands[0].pipeline_negation_count == 2 &&
                          !repeated.commands[0].pipeline_negated &&
                          repeated.commands[0].command_token_count == 1;
  shell_processed_commands_free(&repeated);

  atomic = true;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    repeated.commands = (shell_command_info_t *)(uintptr_t)1;
    repeated.command_count = SIZE_MAX;
    repeated.groups = (shell_group_t *)(uintptr_t)1;
    repeated.group_count = SIZE_MAX;
    repeated.group_io_ops = (shell_group_io_op_t *)(uintptr_t)1;
    repeated.group_io_op_count = SIZE_MAX;
    shellsplit_test_alloc_fail_at(fail_at);
    status = shell_process_commands(
        repeated_negation, sizeof(repeated_negation) - 1, NULL, &repeated);
    shellsplit_test_alloc_reset();
    if (status != SHELL_PROCESS_ENOMEM || repeated.commands != NULL ||
        repeated.command_count != 0 || repeated.groups != NULL ||
        repeated.group_count != 0 || repeated.group_io_ops != NULL ||
        repeated.group_io_op_count != 0) {
      atomic = false;
      shell_processed_commands_free(&repeated);
      break;
    }
  }
  test("Repeated negation processing is allocation-failure atomic",
       repeated_success && atomic);

  bool has_features = false;
  char *sequence = NULL;
  shellsplit_test_alloc_reset();
  status = shell_build_netargv_sequence(input, strlen(input), NULL, &sequence,
                                        &count, &has_features);
  allocations = shellsplit_test_alloc_count();
  test("Netargv-sequence allocation probe succeeds",
       status == SHELL_PROCESS_OK && sequence && count == 2 && has_features);
  free(sequence);

  atomic = true;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    sequence = (char *)(void *)1;
    count = SIZE_MAX;
    has_features = true;
    shellsplit_test_alloc_fail_at(fail_at);
    status = shell_build_netargv_sequence(input, strlen(input), NULL, &sequence,
                                          &count, &has_features);
    shellsplit_test_alloc_reset();
    if (status != SHELL_PROCESS_ENOMEM || sequence != NULL || count != 0 ||
        has_features) {
      atomic = false;
      free(sequence);
      break;
    }
  }
  test("Netargv-sequence allocation failures are atomic", atomic);

  shellsplit_test_alloc_reset();
  status =
      shell_build_command_netseq(input, strlen(input), NULL, &sequence, &count);
  allocations = shellsplit_test_alloc_count();
  test("Command-netsequence allocation probe succeeds",
       status == SHELL_PROCESS_OK && sequence && count == 2);
  free(sequence);

  atomic = true;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    sequence = (char *)(void *)1;
    count = SIZE_MAX;
    shellsplit_test_alloc_fail_at(fail_at);
    status = shell_build_command_netseq(input, strlen(input), NULL, &sequence,
                                        &count);
    shellsplit_test_alloc_reset();
    if (status != SHELL_PROCESS_ENOMEM || sequence != NULL || count != 0) {
      atomic = false;
      free(sequence);
      break;
    }
  }
  test("Command-netsequence allocation failures are atomic", atomic);
}

static void test_transform_allocation_failures(void) {
  static const char input[] =
      "echo prefix$USER-suffix \"literal\"${NAME}\\\r\n-tail a b c d e f g h "
      "i j k l m n o p | grep '*.txt'";
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

static void test_output_limit_boundaries(void) {
  static const char input[] = "echo one ; printf two";
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
static void test_cstring_allocation_size_boundaries(void) {
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
      allocation_size == 0 &&
      shell_process_cstring_allocation_size(0, NULL) == SHELL_PROCESS_EINPUT;
  test("Legacy canonical outputs reject a wrapping terminator allocation",
       valid);
}

static void test_posix_brace_group_sequence(void) {
  const char *input =
      "cd /workspace && { sleep 2; printf 'q'; } | ./clock > /tmp/clock.out";
  char *sequence = NULL;
  size_t count = 0;
  bool features = false;
  shell_process_status_t status = shell_build_netargv_sequence(
      input, strlen(input), NULL, &sequence, &count, &features);
  test("POSIX brace group renders four canonical netargv records",
       status == SHELL_PROCESS_OK && count == 4 && features &&
           sequence != NULL &&
           strcmp(sequence,
                  "19:2:cd,10:/workspace,,12:5:sleep,1:2,,13:6:printf,1:q,,"
                  "10:7:./clock,,") == 0);
  free(sequence);
}

static void test_canonical_control_compounds_rejected(void) {
  static const char *const cases[] = {
      "for ((i = 0; i < 2; i++)); do echo \"$i\"; done",
      "for value in one two; do echo \"$value\"; done",
      "while read line; do echo \"$line\"; done",
      "until test -f file; do sleep 1; done",
      "if test -f file; then echo yes; else echo no; fi",
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
      "{ if test -f file; then echo yes; fi; }",
      "echo $(if test -f file; then echo yes; fi)",
      "cat <(while read line; do echo $line; done)",
      "echo prefix; do echo invalid; done",
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
    char *netargv = (char *)(uintptr_t)1;
    char *command_netseq = (char *)(uintptr_t)1;
    char *type_netseq = (char *)(uintptr_t)1;
    char *paired_command = (char *)(uintptr_t)1;
    char *paired_type = (char *)(uintptr_t)1;
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
        shell_build_netargv_sequence(cases[i], length, NULL, &netargv, &count,
                                     &features) == SHELL_PROCESS_EPARSE &&
        netargv == NULL && count == 0 && !features &&
        shell_build_command_netseq(cases[i], length, NULL, &command_netseq,
                                   &count) == SHELL_PROCESS_EPARSE &&
        command_netseq == NULL && count == 0 &&
        shell_build_type_netseq(cases[i], length, NULL, &type_netseq, &count) ==
            SHELL_PROCESS_EPARSE &&
        type_netseq == NULL && count == 0 &&
        shell_build_anomaly_netseqs(cases[i], length, NULL, &paired_command,
                                    &paired_type,
                                    &count) == SHELL_PROCESS_EPARSE &&
        paired_command == NULL && paired_type == NULL && count == 0;
  }
  test("Canonical APIs reject unsupported control compounds", valid);
}

static void test_unsupported_control_precedes_capacity(void) {
  char input[2048];
  size_t used = 0;
  for (size_t i = 0; i <= SHELL_MAX_SUBCOMMANDS; i++) {
    int written = snprintf(input + used, sizeof(input) - used, "x%zu | ", i);
    if (written < 0 || (size_t)written >= sizeof(input) - used) {
      test("Unsupported controls take precedence over command capacity", false);
      return;
    }
    used += (size_t)written;
  }
  int written = snprintf(input + used, sizeof(input) - used,
                         "select choice in one two; do :; done");
  if (written < 0 || (size_t)written >= sizeof(input) - used) {
    test("Unsupported controls take precedence over command capacity", false);
    return;
  }
  used += (size_t)written;

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
  char *netargv = (char *)(uintptr_t)1;
  size_t count = SIZE_MAX;
  bool features = true;
  bool valid =
      shell_process_validate_supported_source(input, used, NULL) ==
          SHELL_PROCESS_EPARSE &&
      shell_process_command(input, used, NULL, &infos, &info_count) ==
          SHELL_PROCESS_EPARSE &&
      infos == NULL && info_count == 0 &&
      shell_process_commands(input, used, NULL, &processed) ==
          SHELL_PROCESS_EPARSE &&
      processed.commands == NULL && processed.command_count == 0 &&
      processed.groups == NULL && processed.group_count == 0 &&
      processed.group_io_ops == NULL && processed.group_io_op_count == 0 &&
      shell_build_netargv_sequence(input, used, NULL, &netargv, &count,
                                   &features) == SHELL_PROCESS_EPARSE &&
      netargv == NULL && count == 0 && !features;
  test("Unsupported controls take precedence over command capacity", valid);
}

static void test_control_word_literals_are_accepted(void) {
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
    char *netargv = NULL;
    size_t count = 0;
    bool features = false;
    size_t length = strlen(cases[i]);
    valid =
        valid &&
        shell_process_commands(cases[i], length, NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == 1 &&
        shell_build_netargv_sequence(cases[i], length, NULL, &netargv, &count,
                                     &features) == SHELL_PROCESS_OK &&
        count == 1 && netargv != NULL;
    free(netargv);
    shell_processed_commands_free(&processed);
  }
  test("Canonical APIs keep non-structural control words as literals", valid);
}

static void test_structured_processor_requires_complete_syntax(void) {
  const char *input = "echo `unterminated";
  shell_command_info_t *flat = NULL;
  size_t flat_count = 0;
  char *netargv = NULL;
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
      shell_render_netargv(&flat[0], NULL, &netargv) == SHELL_PROCESS_OK &&
      netargv != NULL && strcmp(netargv, "4:echo,13:`unterminated,") == 0 &&
      shell_process_commands(input, strlen(input), NULL, &structured) ==
          SHELL_PROCESS_EPARSE &&
      structured.commands == NULL && structured.command_count == 0 &&
      structured.groups == NULL && structured.group_count == 0 &&
      structured.group_io_ops == NULL && structured.group_io_op_count == 0;
  shell_command_infos_free(flat, flat_count);
  free(netargv);
  test("Structured processing rejects incomplete lexical records", valid);
}

static void test_tolerant_unfinished_group_omits_empty_command(void) {
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

static void test_processed_commands_preserve_comment_free_ranges(void) {
  static const struct {
    const char *input;
    const char *fast_range;
    const char *command;
  } cases[] = {{"#\nJ", "J", "J"},
               {"# ignored by the full tokenizer\nprintf visible\n",
                "printf visible", "printf"}};
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t fast = {0};
    shell_processed_commands_t processed = {0};
    size_t fast_range_length = strlen(cases[i].fast_range);
    size_t command_length = strlen(cases[i].command);
    valid = valid &&
            shell_parse_fast(cases[i].input, strlen(cases[i].input), NULL,
                             &fast) == SHELL_OK &&
            fast.count == 1 && fast.cmds[0].len == fast_range_length &&
            memcmp(cases[i].input + fast.cmds[0].start, cases[i].fast_range,
                   fast_range_length) == 0 &&
            shell_process_commands(cases[i].input, strlen(cases[i].input), NULL,
                                   &processed) == SHELL_PROCESS_OK &&
            processed.command_count == 1 && processed.commands != NULL &&
            processed.commands[0].command_token_count != 0 &&
            processed.commands[0].command_tokens[0].length == command_length &&
            memcmp(processed.commands[0].command_tokens[0].start,
                   cases[i].command, command_length) == 0;
    shell_processed_commands_free(&processed);
  }
  test("Processed commands preserve comment-free fast ranges", valid);
}

static void test_processed_comment_only_source_is_empty(void) {
  static const char *const cases[] = {
      "# comment-only source",
      "# <(printf data)",
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t fast = {0};
    shell_processed_commands_t processed = {0};
    valid =
        shell_parse_fast(cases[i], strlen(cases[i]), NULL, &fast) == SHELL_OK &&
        fast.count == 0 && fast.status == SHELL_STATUS_OK &&
        shell_process_commands(cases[i], strlen(cases[i]), NULL, &processed) ==
            SHELL_PROCESS_EPARSE &&
        processed.commands == NULL && processed.command_count == 0 &&
        processed.groups == NULL && processed.group_count == 0 &&
        processed.group_io_ops == NULL && processed.group_io_op_count == 0;
    shell_processed_commands_free(&processed);
  }
  test("Structured processing rejects comment-only source without records",
       valid);
}

static void test_posix_brace_group_forms(void) {
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
    char *sequence = NULL;
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
            shell_build_netargv_sequence(
                invalid_cases[i], strlen(invalid_cases[i]), NULL, &sequence,
                &count, &features) == SHELL_PROCESS_EPARSE &&
            sequence == NULL && count == 0 && !features &&
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
  char *sequence = NULL;
  size_t count = 0;
  bool features = false;
  shell_process_status_t status = shell_build_netargv_sequence(
      redirected, strlen(redirected), NULL, &sequence, &count, &features);
  test("Group trailing redirects do not create empty netargv commands",
       status == SHELL_PROCESS_OK && count == 1 && sequence != NULL &&
           strcmp(sequence, "7:4:echo,,") == 0);
  free(sequence);

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

static void test_command_position_group_syntax_rejected(void) {
  static const char *const invalid_cases[] = {
      "foo; {",  "foo; }",  "foo && {",      "foo && }",   "foo | {",
      "foo | }", "foo | )", "echo { foo; }", "echo (foo)", "echo ((1))",
  };
  shell_limits_t strict_limits = {
      .max_subcommands = SHELL_MAX_SUBCOMMANDS,
      .strict_mode = true,
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(invalid_cases) / sizeof(invalid_cases[0]);
       i++) {
    const char *input = invalid_cases[i];
    size_t length = strlen(input);
    shell_parse_result_t parsed = {0};
    shell_processed_commands_t processed = {0};
    char *netargv = (char *)(uintptr_t)1;
    char *commands = (char *)(uintptr_t)1;
    char *types = (char *)(uintptr_t)1;
    char *anomaly_commands = (char *)(uintptr_t)1;
    char *anomaly_types = (char *)(uintptr_t)1;
    size_t count = SIZE_MAX;
    size_t anomaly_count = SIZE_MAX;
    bool features = true;
    shell_dep_graph_t graph;

    valid = valid &&
            shell_parse_fast(input, length, &strict_limits, &parsed) ==
                SHELL_EPARSE &&
            shell_process_commands(input, length, NULL, &processed) ==
                SHELL_PROCESS_EPARSE &&
            processed.commands == NULL && processed.command_count == 0 &&
            shell_build_netargv_sequence(input, length, NULL, &netargv, &count,
                                         &features) == SHELL_PROCESS_EPARSE &&
            netargv == NULL && count == 0 && !features &&
            shell_build_command_netseq(input, length, NULL, &commands,
                                       &count) == SHELL_PROCESS_EPARSE &&
            commands == NULL && count == 0 &&
            shell_build_type_netseq(input, length, NULL, &types, &count) ==
                SHELL_PROCESS_EPARSE &&
            types == NULL && count == 0 &&
            shell_build_anomaly_netseqs(input, length, NULL, &anomaly_commands,
                                        &anomaly_types, &anomaly_count) ==
                SHELL_PROCESS_EPARSE &&
            anomaly_commands == NULL && anomaly_types == NULL &&
            anomaly_count == 0 &&
            shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
                SHELL_DEP_EPARSE;
    if (netargv != (char *)(uintptr_t)1)
      free(netargv);
    if (commands != (char *)(uintptr_t)1)
      free(commands);
    if (types != (char *)(uintptr_t)1)
      free(types);
    if (anomaly_commands != (char *)(uintptr_t)1)
      free(anomaly_commands);
    if (anomaly_types != (char *)(uintptr_t)1)
      free(anomaly_types);
    shell_processed_commands_free(&processed);
  }
  test("Semantic APIs reject command-position group syntax", valid);

  static const char *const literal_cases[] = {
      "echo {", "echo }", "echo {foo}", "echo foo}", "{( echo )}",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(literal_cases) / sizeof(literal_cases[0]);
       i++) {
    const char *input = literal_cases[i];
    shell_parse_result_t parsed = {0};
    char *netargv = NULL;
    size_t count = 0;
    bool features = false;
    valid =
        valid &&
        shell_parse_fast(input, strlen(input), &strict_limits, &parsed) ==
            SHELL_OK &&
        shell_build_netargv_sequence(input, strlen(input), NULL, &netargv,
                                     &count, &features) == SHELL_PROCESS_OK &&
        count > 0;
    free(netargv);
  }
  test("Strict group syntax preserves literal brace words", valid);
}

static void test_full_tokenizer_group_context(void) {
  const char *input =
      "{ printf \"$value\" $(id) <(producer) >out <<EOF\nbody\nEOF\n; }";
  shell_tokenizer_state_t state;
  shell_token_t token;
  bool valid = shell_tokenizer_init(&state, input, strlen(input));
  bool saw_quoted_variable = false;
  bool saw_substitution = false;
  bool saw_process_substitution = false;
  bool saw_redirect = false;
  bool saw_heredoc = false;
  bool saw_separator = false;
  size_t token_count = 0;
  while (valid && shell_tokenizer_next(&state, &token)) {
    valid = token.group_depth == 1 && token.group_kinds == SHELL_GROUP_BRACE;
    switch (token.type) {
    case SHELL_TOKEN_VARIABLE_QUOTED:
      saw_quoted_variable = true;
      break;
    case SHELL_TOKEN_SUBSHELL:
      saw_substitution = true;
      break;
    case SHELL_TOKEN_PROCESS_SUB:
      saw_process_substitution = true;
      break;
    case SHELL_TOKEN_REDIRECT_OUT:
      saw_redirect = true;
      break;
    case SHELL_TOKEN_HEREDOC:
      saw_heredoc = true;
      break;
    case SHELL_TOKEN_SEMICOLON:
      saw_separator = true;
      break;
    default:
      break;
    }
    token_count++;
  }
  valid = valid && token_count != 0 && saw_quoted_variable &&
          saw_substitution && saw_process_substitution && saw_redirect &&
          saw_heredoc && saw_separator;
  test("Full tokenizer stamps group context on every token path", valid);

  static const struct {
    shell_token_type_t type;
    size_t group_depth;
    uint8_t group_kinds;
  } nested_expected[] = {
      {SHELL_TOKEN_GROUP_START, 1, SHELL_GROUP_BRACE},
      {SHELL_TOKEN_GROUP_START, 2, SHELL_GROUP_BRACE | SHELL_GROUP_SUBSHELL},
      {SHELL_TOKEN_COMMAND, 2, SHELL_GROUP_BRACE | SHELL_GROUP_SUBSHELL},
      {SHELL_TOKEN_GROUP_END, 2, SHELL_GROUP_BRACE | SHELL_GROUP_SUBSHELL},
      {SHELL_TOKEN_SEMICOLON, 1, SHELL_GROUP_BRACE},
      {SHELL_TOKEN_GROUP_END, 1, SHELL_GROUP_BRACE},
  };
  const char *nested_input = "{ ( echo ); }";
  valid = shell_tokenizer_init(&state, nested_input, strlen(nested_input));
  for (size_t i = 0;
       valid && i < sizeof(nested_expected) / sizeof(nested_expected[0]); i++) {
    valid = shell_tokenizer_next(&state, &token) &&
            token.type == nested_expected[i].type &&
            token.group_depth == nested_expected[i].group_depth &&
            token.group_kinds == nested_expected[i].group_kinds;
  }
  valid = valid && !shell_tokenizer_next(&state, &token);
  test("Nested group delimiters retain their complete context", valid);

  shell_command_t *commands = NULL;
  size_t command_count = 0;
  const char *multiple_commands = "{ echo one; echo two; }";
  valid =
      shell_tokenize_commands(multiple_commands, strlen(multiple_commands),
                              &commands, &command_count) == SHELL_TOKENIZE_OK &&
      command_count == 2;
  for (size_t i = 0; valid && i < command_count; i++)
    valid = commands[i].group_depth == 1 &&
            commands[i].group_kinds == SHELL_GROUP_BRACE;
  shell_commands_free(commands, command_count);
  test("Brace-contained commands retain depth after list separators", valid);
}

static void test_brace_group_process_substitution_contract(void) {
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
    char *netargv = NULL;
    size_t netargv_count = 0;
    bool features = false;
    shell_process_status_t info_status = shell_process_command(
        cases[i].input, strlen(cases[i].input), NULL, &infos, &info_count);
    shell_process_status_t processed_status = shell_process_commands(
        cases[i].input, strlen(cases[i].input), NULL, &processed);
    shell_process_status_t netargv_status =
        shell_build_netargv_sequence(cases[i].input, strlen(cases[i].input),
                                     NULL, &netargv, &netargv_count, &features);
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
            processed.group_count == 1 && netargv != NULL &&
            netargv_count == cases[i].command_count && features &&
            infos[0].command_token_count == cases[i].first_word_count &&
            infos[0].has_redirections == cases[i].has_redirection &&
            saw_process_word == cases[i].process_is_word &&
            shell_command_info_has_dangerous_features(&infos[0]);
    free(netargv);
    shell_processed_commands_free(&processed);
    shell_command_infos_free(infos, info_count);
  }
  test("Brace process substitutions retain their canonical role", valid);
}

static void test_clobber_redirection_operand_contract(void) {
  static const struct {
    const char *input;
    const char *netargv;
  } valid_cases[] = {
      {"echo hi >| /tmp/out", "12:4:echo,2:hi,,"},
      {"echo hi 2>|/tmp/err", "12:4:echo,2:hi,,"},
  };

  bool valid = true;
  for (size_t i = 0; i < sizeof(valid_cases) / sizeof(valid_cases[0]); i++) {
    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    char *netargv = NULL;
    size_t netargv_count = 0;
    bool has_features = false;
    valid =
        valid &&
        shell_process_command(valid_cases[i].input,
                              strlen(valid_cases[i].input), NULL, &infos,
                              &info_count) == SHELL_PROCESS_OK &&
        infos != NULL && info_count == 1 && infos[0].command_token_count == 2 &&
        infos[0].has_redirections &&
        infos[0].command_tokens[0].length == strlen("echo") &&
        memcmp(infos[0].command_tokens[0].start, "echo", strlen("echo")) == 0 &&
        infos[0].command_tokens[1].length == strlen("hi") &&
        memcmp(infos[0].command_tokens[1].start, "hi", strlen("hi")) == 0 &&
        shell_build_netargv_sequence(
            valid_cases[i].input, strlen(valid_cases[i].input), NULL, &netargv,
            &netargv_count, &has_features) == SHELL_PROCESS_OK &&
        netargv != NULL && netargv_count == 1 && has_features &&
        strcmp(netargv, valid_cases[i].netargv) == 0;
    free(netargv);
    shell_command_infos_free(infos, info_count);
  }

  const char *invalid = "{ echo; } >| (echo)";
  shell_parse_result_t fast = {0};
  shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
  size_t command_count = SIZE_MAX;
  valid =
      valid &&
      shell_parse_fast(invalid, strlen(invalid), NULL, &fast) == SHELL_EPARSE &&
      shell_tokenize_commands(invalid, strlen(invalid), &commands,
                              &command_count) == SHELL_TOKENIZE_EPARSE &&
      commands == NULL && command_count == 0;
  shell_commands_free(commands, command_count);
  test("Clobber redirects consume operands across canonical processing", valid);
}

static void test_brace_group_processed_contract(void) {
  static const char *const valid_cases[] = {
      "{ echo \"$(printf '}')\"; }",
      "{ echo \"${value}\"; }",
      "{ echo \"$((1 + 2))\"; `printf '}'`; }",
      "{ echo one; # } remains a comment\n echo two; }",
      "{ { echo inner; } && ( echo outer ); } > /tmp/group.out",
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(valid_cases) / sizeof(valid_cases[0]); i++) {
    shell_parse_result_t fast = {0};
    shell_processed_commands_t processed = {0};
    shell_process_status_t status = shell_process_commands(
        valid_cases[i], strlen(valid_cases[i]), NULL, &processed);
    valid = valid &&
            shell_parse_fast(valid_cases[i], strlen(valid_cases[i]), NULL,
                             &fast) == SHELL_OK &&
            status == SHELL_PROCESS_OK &&
            /* The rich result omits structural redirect-only ranges that the
             * fast parser intentionally retains for lexical callers. */
            processed.command_count <= fast.count &&
            processed.group_count == fast.group_count &&
            processed_group_descriptors_match_source(&fast, &processed);
    shell_processed_commands_free(&processed);
  }
  test("Processed brace descriptors agree across opaque syntax contexts",
       valid);

  static const char *const invalid_cases[] = {
      "{ echo",
      "{ echo;",
      "{ ( echo; } )",
      "{ echo $(printf; }",
      "{ echo `printf; }",
      "{ cat <<EOF\nbody\n; }",
  };
  valid = true;
  for (size_t i = 0; i < sizeof(invalid_cases) / sizeof(invalid_cases[0]);
       i++) {
    shell_processed_commands_t processed = {
        .commands = (shell_command_info_t *)(uintptr_t)1,
        .command_count = 1,
        .groups = (shell_group_t *)(uintptr_t)1,
        .group_count = 1,
    };
    shell_process_status_t status = shell_process_commands(
        invalid_cases[i], strlen(invalid_cases[i]), NULL, &processed);
    valid = valid && status == SHELL_PROCESS_EPARSE &&
            processed.commands == NULL && processed.command_count == 0 &&
            processed.groups == NULL && processed.group_count == 0;
  }
  test("Processed brace failures clear owned results", valid);
}

static void test_processed_group_command_intervals(void) {
  static const char input[] = "cat <<<value; { printf one; { printf two; }; }";
  shell_parse_result_t fast = {0};
  shell_processed_commands_t processed = {0};
  shell_process_status_t status =
      shell_process_commands(input, sizeof(input) - 1, NULL, &processed);
  bool valid =
      shell_parse_fast(input, sizeof(input) - 1, NULL, &fast) == SHELL_OK &&
      status == SHELL_PROCESS_OK && processed.command_count == 3 &&
      processed.group_count == 2 && processed.groups[0].first_command == 1 &&
      processed.groups[0].command_count == 2 &&
      processed.groups[1].first_command == 2 &&
      processed.groups[1].command_count == 1 &&
      processed_group_descriptors_match_source(&fast, &processed);
  shell_processed_commands_free(&processed);
  test("Processed group intervals index retained commands", valid);
}

static void test_brace_group_boundaries_and_redirections(void) {
  static const struct {
    const char *input;
    size_t command_count;
    uint32_t group_count;
  } boundary_cases[] = {
      {"{\n echo one\n}", 1, 1},      {"{ echo one; } | { cat; }", 2, 2},
      {"{\r\n  echo one\r\n}", 1, 1}, {"echo \\{ \\}", 1, 0},
      {"echo {foo}", 1, 0},           {"echo foo}", 1, 0},
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(boundary_cases) / sizeof(boundary_cases[0]);
       i++) {
    shell_parse_result_t fast = {0};
    shell_processed_commands_t processed = {0};
    bool case_valid =
        shell_parse_fast(boundary_cases[i].input,
                         strlen(boundary_cases[i].input), NULL,
                         &fast) == SHELL_OK &&
        shell_process_commands(boundary_cases[i].input,
                               strlen(boundary_cases[i].input), NULL,
                               &processed) == SHELL_PROCESS_OK &&
        fast.count == boundary_cases[i].command_count &&
        processed.command_count == boundary_cases[i].command_count &&
        fast.group_count == boundary_cases[i].group_count &&
        processed.group_count == boundary_cases[i].group_count &&
        processed_group_descriptors_match_source(&fast, &processed);
    valid = valid && case_valid;
    shell_processed_commands_free(&processed);
  }
  test("Brace delimiters respect POSIX word and newline boundaries", valid);

  static const struct {
    const char *input;
    size_t token_count;
  } redirect_cases[] = {
      {"{ echo one; echo two; } > /tmp/group.out", 2},
      {"{ echo one; echo two; } >> /tmp/group.out", 2},
      {"{ cat; cat; } < /tmp/group.in", 1},
      {"{ echo one; echo two; } 2>&1", 2},
      {"{ cat; cat; } <<< value", 1},
      {"{ cat; cat; } <<< \"two words\"", 1},
      {"{ cat; cat; } <<'EOF'\n}\nEOF", 1},
      {"{ echo one; echo two; } </tmp/group.in >/tmp/group.out "
       "2>>/tmp/group.err",
       2},
  };
  valid = true;
  for (size_t i = 0; i < sizeof(redirect_cases) / sizeof(redirect_cases[0]);
       i++) {
    shell_command_info_t *infos = NULL;
    size_t count = 0;
    shell_process_status_t status = shell_process_command(
        redirect_cases[i].input, strlen(redirect_cases[i].input), NULL, &infos,
        &count);
    bool case_valid = status == SHELL_PROCESS_OK && count == 2 && infos != NULL;
    for (size_t j = 0; case_valid && j < count; j++)
      case_valid =
          infos[j].command_token_count == redirect_cases[i].token_count &&
          infos[j].has_redirections == (j + 1 == count);
    valid = valid && case_valid;
    shell_command_infos_free(infos, count);
  }
  test("Brace-group redirects stay attached without synthetic commands", valid);
}

static void test_brace_group_heredoc_sequence_contract(void) {
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

static void test_brace_group_grammar_matrix(void) {
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
      {"{\r\n  echo one\r\n}", 1, 1},
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
    shell_limits_t strict = {SHELL_MAX_SUBCOMMANDS, true};
    shell_parse_result_t fast = {0};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    char *netargv = NULL;
    char *command_netseq = NULL;
    char *type_netseq = NULL;
    char *paired_command = NULL;
    char *paired_type = NULL;
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
    shell_process_status_t netargv_status = shell_build_netargv_sequence(
        input, length, NULL, &netargv, &netargv_count, &features);
    shell_process_status_t command_status = shell_build_command_netseq(
        input, length, NULL, &command_netseq, &command_count_out);
    shell_process_status_t type_status =
        shell_build_type_netseq(input, length, NULL, &type_netseq, &type_count);
    shell_process_status_t anomaly_status = shell_build_anomaly_netseqs(
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
        processed_group_descriptors_match_source(&fast, &processed) &&
        netargv_status == SHELL_PROCESS_OK && netargv != NULL &&
        netargv_count == valid_cases[i].command_count &&
        command_status == SHELL_PROCESS_OK && command_netseq != NULL &&
        command_count_out >= valid_cases[i].command_count &&
        type_status == SHELL_PROCESS_OK && type_netseq != NULL &&
        type_count == command_count_out && anomaly_status == SHELL_PROCESS_OK &&
        paired_command != NULL && paired_type != NULL &&
        anomaly_count == command_count_out &&
        strcmp(command_netseq, paired_command) == 0 &&
        strcmp(type_netseq, paired_type) == 0 && graph_status == SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    if (!case_valid)
      printf(
          "    valid brace case rejected: %s (fast=%d tokenizer=%d process=%d "
          "netargv=%d command=%d type=%d anomaly=%d graph=%d)\n",
          input, fast_status, tokenizer_status, process_status, netargv_status,
          command_status, type_status, anomaly_status, graph_status);
    valid = valid && case_valid;
    free(netargv);
    free(command_netseq);
    free(type_netseq);
    free(paired_command);
    free(paired_type);
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
    shell_limits_t strict = {SHELL_MAX_SUBCOMMANDS, true};
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
    char *netargv = (char *)(uintptr_t)1;
    char *command_netseq = (char *)(uintptr_t)1;
    char *type_netseq = (char *)(uintptr_t)1;
    char *paired_command = (char *)(uintptr_t)1;
    char *paired_type = (char *)(uintptr_t)1;
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
    shell_process_status_t netargv_status = shell_build_netargv_sequence(
        input, length, NULL, &netargv, &count, &features);
    shell_process_status_t command_status = shell_build_command_netseq(
        input, length, NULL, &command_netseq, &count);
    shell_process_status_t type_status =
        shell_build_type_netseq(input, length, NULL, &type_netseq, &count);
    shell_process_status_t anomaly_status = shell_build_anomaly_netseqs(
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
        netargv_status == SHELL_PROCESS_EPARSE && netargv == NULL &&
        count == 0 && !features && command_status == SHELL_PROCESS_EPARSE &&
        command_netseq == NULL && count == 0 &&
        type_status == SHELL_PROCESS_EPARSE && type_netseq == NULL &&
        count == 0 && anomaly_status == SHELL_PROCESS_EPARSE &&
        paired_command == NULL && paired_type == NULL && count == 0 &&
        graph_status == SHELL_DEP_EPARSE;
    valid = valid && case_valid;
  }
  test("Invalid brace and redirect syntax clears every canonical boundary",
       valid);
}

static void test_brace_group_operation_limits_are_atomic(void) {
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

  char *netargv = (char *)(uintptr_t)1;
  char *command_netseq = (char *)(uintptr_t)1;
  char *type_netseq = (char *)(uintptr_t)1;
  char *paired_command = (char *)(uintptr_t)1;
  char *paired_type = (char *)(uintptr_t)1;
  size_t count = SIZE_MAX;
  bool features = true;
  valid = valid &&
          shell_build_netargv_sequence(input, sizeof(input) - 1, &exact,
                                       &netargv, &count, &features) ==
              SHELL_PROCESS_EOUTPUT_LIMIT &&
          netargv == NULL && count == 0 && !features;
  count = SIZE_MAX;
  valid = valid &&
          shell_build_command_netseq(input, sizeof(input) - 1, &exact,
                                     &command_netseq,
                                     &count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
          command_netseq == NULL && count == 0;
  count = SIZE_MAX;
  valid =
      valid &&
      shell_build_type_netseq(input, sizeof(input) - 1, &exact, &type_netseq,
                              &count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
      type_netseq == NULL && count == 0;
  count = SIZE_MAX;
  valid = valid &&
          shell_build_anomaly_netseqs(input, sizeof(input) - 1, &exact,
                                      &paired_command, &paired_type,
                                      &count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
          paired_command == NULL && paired_type == NULL && count == 0;
  test("Brace-group operation limits clear every canonical result", valid);
}

static void test_extraneous_brace_closer_rejected(void) {
  const char *input = "{ echo one; } }";
  shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
  size_t command_count = SIZE_MAX;
  shell_command_info_t *infos = (shell_command_info_t *)(uintptr_t)1;
  size_t info_count = SIZE_MAX;
  bool valid =
      shell_tokenize_commands(input, strlen(input), &commands,
                              &command_count) == SHELL_TOKENIZE_EPARSE &&
      commands == NULL && command_count == 0 &&
      shell_process_command(input, strlen(input), NULL, &infos, &info_count) ==
          SHELL_PROCESS_EPARSE &&
      infos == NULL && info_count == 0;
  test("Full tokenizer rejects an extraneous brace-group closer", valid);
}

/* Anomaly sequences are structural execution inputs, not policy netargv.
 * Nested substitutions execute before the enclosing simple command, while the
 * ordinary netargv sequence remains deliberately top-level and
 * authorization-oriented. */
static void test_anomaly_sequences_include_nested_execution_stages(void) {
  static const struct {
    const char *input;
    const char *raw;
    size_t count;
  } cases[] = {
      {"outer $(inner) < <(producer); cat <<EOF\n$(here)\nEOF\n",
       "5:inner,8:producer,5:outer,4:here,3:cat,", 5},
      {"outer $(>nested)", "0:,5:outer,", 2},
      {"outer $((1 + $(inside)))", "6:inside,5:outer,", 2},
      {"outer $(middle $(inner))", "5:inner,6:middle,5:outer,", 3},
      {"outer `middle $(inner)`", "5:inner,6:middle,5:outer,", 3},
      {"outer $(middle <(producer))", "8:producer,6:middle,5:outer,", 3},
      {"cat <<EOF\n`backtick`\n${value:-$(parameter)}\n$((1 + "
       "$(arith)))\nEOF\n",
       "8:backtick,9:parameter,5:arith,3:cat,", 4},
      {"cat <<EOF\n\\$(literal)\\`also\\`\nEOF\n", "3:cat,", 1},
      {"cat <<A <<'B'\n$(first)\nA\n$(literal)\nB\n", "5:first,3:cat,", 2},
      {"cat <<'EOF'\n$(literal)\nEOF\n", "3:cat,", 1},
      {"{ outer $(inner); } | tail", "5:inner,5:outer,4:tail,", 3},
      {"{ group; } >out; tail", "5:group,4:tail,", 2},
  };

  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char *raw = NULL;
    char *typed = NULL;
    char *paired_raw = NULL;
    char *paired_typed = NULL;
    shell_netstring_buffer_t raw_buffer = {0};
    shell_netstring_buffer_t typed_buffer = {0};
    size_t raw_count = 0;
    size_t typed_count = 0;
    size_t paired_count = 0;
    valid =
        valid &&
        shell_build_command_netseq(cases[i].input, strlen(cases[i].input), NULL,
                                   &raw, &raw_count) == SHELL_PROCESS_OK &&
        raw != NULL && raw_count == cases[i].count &&
        strcmp(raw, cases[i].raw) == 0 &&
        shell_build_type_netseq(cases[i].input, strlen(cases[i].input), NULL,
                                &typed, &typed_count) == SHELL_PROCESS_OK &&
        typed != NULL && typed_count == cases[i].count &&
        shell_netstring_validate(typed, strlen(typed), NULL) ==
            SHELL_NETSTRING_OK &&
        shell_build_anomaly_netseqs(cases[i].input, strlen(cases[i].input),
                                    NULL, &paired_raw, &paired_typed,
                                    &paired_count) == SHELL_PROCESS_OK &&
        paired_raw != NULL && paired_typed != NULL &&
        paired_count == cases[i].count && strcmp(paired_raw, raw) == 0 &&
        strcmp(paired_typed, typed) == 0 &&
        shell_build_anomaly_netseqs_buffer(
            cases[i].input, strlen(cases[i].input), NULL, &raw_buffer,
            &typed_buffer, &paired_count) == SHELL_PROCESS_OK &&
        paired_count == cases[i].count && raw_buffer.length == strlen(raw) &&
        typed_buffer.length == strlen(typed) &&
        memcmp(raw_buffer.data, raw, raw_buffer.length) == 0 &&
        memcmp(typed_buffer.data, typed, typed_buffer.length) == 0;
    shell_netstring_buffer_free(&typed_buffer);
    shell_netstring_buffer_free(&raw_buffer);
    free(paired_typed);
    free(paired_raw);
    free(typed);
    free(raw);
  }

  char *netargv = NULL;
  size_t netargv_count = 0;
  bool features = false;
  valid = valid &&
          shell_build_netargv_sequence(
              "outer $(inner)", strlen("outer $(inner)"), NULL, &netargv,
              &netargv_count, &features) == SHELL_PROCESS_OK &&
          netargv != NULL && netargv_count == 1 && features;
  free(netargv);

  char *raw = (char *)(uintptr_t)1;
  char *typed = (char *)(uintptr_t)1;
  size_t count = SIZE_MAX;
  valid = valid &&
          shell_build_anomaly_netseqs("outer $(while true; do :; done)",
                                      strlen("outer $(while true; do :; done)"),
                                      NULL, &raw, &typed,
                                      &count) == SHELL_PROCESS_EPARSE &&
          raw == NULL && typed == NULL && count == 0;

  char too_many[4 * SHELL_MAX_SUBCOMMANDS + 16] = "outer $(";
  size_t position = strlen(too_many);
  for (size_t i = 0; i < SHELL_MAX_SUBCOMMANDS; i++) {
    too_many[position++] = 'x';
    if (i + 1 < SHELL_MAX_SUBCOMMANDS)
      too_many[position++] = ';';
  }
  too_many[position++] = ')';
  too_many[position] = '\0';
  raw = (char *)(uintptr_t)1;
  count = SIZE_MAX;
  valid = valid &&
          shell_build_command_netseq(too_many, position, NULL, &raw, &count) ==
              SHELL_PROCESS_EOUTPUT_LIMIT &&
          raw == NULL && count == 0;

  test("Anomaly sequences include nested shell execution stages", valid);
}

static void test_anomaly_sequences_represent_redirect_only_record(void) {
  const char *input = ">/tmp/no-executable";
  char *netargv = NULL;
  char *command_netseq = NULL;
  char *type_netseq = NULL;
  char *paired_command = NULL;
  char *paired_type = NULL;
  size_t count = SIZE_MAX;
  bool features = true;
  shell_processed_commands_t processed = {0};
  bool valid =
      shell_process_commands(input, strlen(input), NULL, &processed) ==
          SHELL_PROCESS_OK &&
      processed.command_count == 0 &&
      shell_build_netargv_sequence(input, strlen(input), NULL, &netargv, &count,
                                   &features) == SHELL_PROCESS_EPARSE &&
      netargv == NULL && count == 0 && !features;
  shell_processed_commands_free(&processed);
  count = SIZE_MAX;
  valid =
      valid &&
      shell_build_command_netseq(input, strlen(input), NULL, &command_netseq,
                                 &count) == SHELL_PROCESS_OK &&
      command_netseq != NULL && count == 1 &&
      strcmp(command_netseq, "0:,") == 0;
  count = SIZE_MAX;
  valid = valid &&
          shell_build_type_netseq(input, strlen(input), NULL, &type_netseq,
                                  &count) == SHELL_PROCESS_OK &&
          type_netseq != NULL && count == 1 &&
          strcmp(type_netseq, "3:0:,,") == 0;
  count = SIZE_MAX;
  valid =
      valid &&
      shell_build_anomaly_netseqs(input, strlen(input), NULL, &paired_command,
                                  &paired_type, &count) == SHELL_PROCESS_OK &&
      paired_command != NULL && paired_type != NULL && count == 1 &&
      strcmp(paired_command, command_netseq) == 0 &&
      strcmp(paired_type, type_netseq) == 0;
  free(paired_type);
  free(paired_command);
  free(type_netseq);
  free(command_netseq);

  /* The anomaly-only sentinel is still subject to each builder's ordinary
   * output and binary-transport contracts. It is not a loophole that makes
   * a tiny output limit succeed, and the legacy C-string adapter must reject
   * a distinct binary executable without exposing partial paired output. */
  shell_process_limits_t raw_limit = {2, SIZE_MAX, 0};
  shell_process_limits_t type_limit = {3, SIZE_MAX, 0};
  shell_netstring_buffer_t command_buffer = {0};
  shell_netstring_buffer_t type_buffer = {0};
  count = SIZE_MAX;
  valid = valid &&
          shell_build_command_netseq(input, strlen(input), &raw_limit,
                                     &command_netseq,
                                     &count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
          command_netseq == NULL && count == 0;
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
  const char *binary_input = "$'sentinel\\0binary'";
  count = SIZE_MAX;
  valid = valid &&
          shell_build_anomaly_netseqs(binary_input, strlen(binary_input), NULL,
                                      &paired_command, &paired_type,
                                      &count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
          paired_command == NULL && paired_type == NULL && count == 0;

  /* The sentinel is reserved for a missing executable, not for an explicitly
   * empty executable word. Every sequence form must keep rejecting the latter
   * rather than silently assigning it the redirect-only meaning. */
  count = SIZE_MAX;
  valid =
      valid &&
      shell_build_command_netseq("'' x", strlen("'' x"), NULL, &command_netseq,
                                 &count) == SHELL_PROCESS_EPARSE &&
      command_netseq == NULL && count == 0;
  count = SIZE_MAX;
  valid = valid &&
          shell_build_type_netseq("'' x", strlen("'' x"), NULL, &type_netseq,
                                  &count) == SHELL_PROCESS_EPARSE &&
          type_netseq == NULL && count == 0;
  shell_netstring_buffer_free(&command_buffer);
  shell_netstring_buffer_free(&type_buffer);

  command_netseq = NULL;
  type_netseq = NULL;
  paired_command = NULL;
  paired_type = NULL;
  count = 0;
  valid = valid &&
          shell_build_anomaly_netseqs("echo ok; >/tmp/no-executable",
                                      strlen("echo ok; >/tmp/no-executable"),
                                      NULL, &paired_command, &paired_type,
                                      &count) == SHELL_PROCESS_OK &&
          count == 2 && strcmp(paired_command, "4:echo,0:,") == 0 &&
          strcmp(paired_type, "13:4:echo,3:STR,,3:0:,,") == 0;
  free(paired_type);
  free(paired_command);
  test("Anomaly sequences retain redirect-only command stages", valid);
}

/* A redirect operand is one shell word. A physical line ending or comment
 * cannot quietly supply a later command word as that operand, whereas an
 * escaped physical line ending remains part of the same command. */
static void test_redirect_operand_boundary_contract(void) {
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
    char *netargv = (char *)(uintptr_t)1;
    size_t netargv_count = SIZE_MAX;
    bool features = true;
    char *command_netseq = (char *)(uintptr_t)1;
    size_t command_netseq_count = SIZE_MAX;
    char *type_netseq = (char *)(uintptr_t)1;
    size_t type_netseq_count = SIZE_MAX;
    char *anomaly_commands = (char *)(uintptr_t)1;
    char *anomaly_types = (char *)(uintptr_t)1;
    size_t anomaly_count = SIZE_MAX;
    shell_dep_graph_t graph = {0};
    valid =
        valid &&
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
        shell_build_netargv_sequence(input, strlen(input), NULL, &netargv,
                                     &netargv_count,
                                     &features) == SHELL_PROCESS_EPARSE &&
        netargv == NULL && netargv_count == 0 && !features &&
        shell_build_command_netseq(input, strlen(input), NULL, &command_netseq,
                                   &command_netseq_count) ==
            SHELL_PROCESS_EPARSE &&
        command_netseq == NULL && command_netseq_count == 0 &&
        shell_build_type_netseq(input, strlen(input), NULL, &type_netseq,
                                &type_netseq_count) == SHELL_PROCESS_EPARSE &&
        type_netseq == NULL && type_netseq_count == 0 &&
        shell_build_anomaly_netseqs(input, strlen(input), NULL,
                                    &anomaly_commands, &anomaly_types,
                                    &anomaly_count) == SHELL_PROCESS_EPARSE &&
        anomaly_commands == NULL && anomaly_types == NULL &&
        anomaly_count == 0 &&
        shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
            SHELL_DEP_EPARSE &&
        graph.node_count == 0 && graph.edge_count == 0;
    if (commands != (shell_command_t *)(uintptr_t)1)
      shell_commands_free(commands, command_count);
    if (infos != (shell_command_info_t *)(uintptr_t)1)
      shell_command_infos_free(infos, info_count);
    shell_processed_commands_free(&processed);
    if (netargv != (char *)(uintptr_t)1)
      free(netargv);
    if (command_netseq != (char *)(uintptr_t)1)
      free(command_netseq);
    if (type_netseq != (char *)(uintptr_t)1)
      free(type_netseq);
    if (anomaly_commands != (char *)(uintptr_t)1)
      free(anomaly_commands);
    if (anomaly_types != (char *)(uintptr_t)1)
      free(anomaly_types);
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
      "echo 2> \\\r\nerr",
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
    char *netargv = NULL;
    size_t netargv_count = 0;
    bool features = false;
    shell_dep_graph_t graph = {0};
    valid =
        valid &&
        shell_parse_fast(input, strlen(input), &strict, &fast) == SHELL_OK &&
        shell_tokenize_commands(input, strlen(input), &commands,
                                &command_count) == SHELL_TOKENIZE_OK &&
        command_count == 1 &&
        shell_build_netargv_sequence(input, strlen(input), NULL, &netargv,
                                     &netargv_count,
                                     &features) == SHELL_PROCESS_OK &&
        netargv_count == 1 && strcmp(netargv, "7:4:echo,,") == 0 &&
        shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        graph.node_count == 2 && graph.edge_count == 1;
    shell_commands_free(commands, command_count);
    free(netargv);
  }

  /* Fast ranges may stop at the backslash while the physical line ending and
   * a following io_number are outside that range. Reprocessing must restore
   * the continuation and leave only the executable in canonical argv. */
  static const char *const continued_io_numbers[] = {
      "cmd >out \\\n3<<<data",
      "cmd >out \\\r\n3<<<data",
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

static void test_processed_group_io_contract(void) {
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
      {"{ echo; }2>/tmp/err", SHELL_GROUP_IO_WRITE_FILE, 2, UINT32_MAX,
       "2>/tmp/err"},
      {"{ echo; }2>>/tmp/err", SHELL_GROUP_IO_APPEND_FILE, 2, UINT32_MAX,
       "2>>/tmp/err"},
      {"{ echo; }2>&1", SHELL_GROUP_IO_DUP_FD, 2, 1, "2>&1"},
      {"{ echo; }0<&-", SHELL_GROUP_IO_CLOSE_FD, 0, UINT32_MAX, "0<&-"},
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
      {"{ echo one; } \\\r\n|& { cat; }", SHELL_GROUP_IO_PIPE_OUTPUT_STDERR, 2},
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
   * command boundary. Exercise LF and CRLF physical lines in one fixture. */
  static const char continued_redirects[] =
      "{ echo one; } \\\n> \\\nout \\\n2> \\\r\nerr \\\n| cat";
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

static void test_processed_group_io_boundaries(void) {
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

/* Redirect-only stages remain graph and anomaly structure, but the structured
 * argv result must not retain an empty command slot or its backing allocation.
 * Exercise lazy growth as well: five executable stages grow the owned array
 * before the final redirect-only stage is omitted. */
static void test_redirect_only_processed_result_ownership(void) {
  static const struct {
    const char *source;
    size_t command_count;
  } cases[] = {
      {">output", 0},
      {"<input >output", 0},
      {"printf x; >output", 1},
      {"{ cat; } >out; >a", 1},
      {"printf one; printf two; printf three; >output", 3},
      {"printf one; printf two; printf three; printf four; printf five; "
       ">output",
       5},
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_processed_commands_t result = {0};
    shell_process_status_t status = shell_process_commands(
        cases[i].source, strlen(cases[i].source), NULL, &result);
    valid = valid && status == SHELL_PROCESS_OK &&
            result.command_count == cases[i].command_count &&
            (result.command_count == 0 ? result.commands == NULL
                                       : result.commands != NULL);
    shell_processed_commands_free(&result);
  }

  static const char *const allocation_cases[] = {
      ">output",
      "printf x; >output",
      "printf one; printf two; printf three; >output",
      "printf one; printf two; printf three; printf four; printf five; >output",
  };
  for (size_t i = 0;
       valid && i < sizeof(allocation_cases) / sizeof(allocation_cases[0]);
       i++) {
    shell_processed_commands_t result = {0};
    shellsplit_test_alloc_reset();
    shell_process_status_t status = shell_process_commands(
        allocation_cases[i], strlen(allocation_cases[i]), NULL, &result);
    size_t allocation_count = shellsplit_test_alloc_count();
    valid = valid && status == SHELL_PROCESS_OK && allocation_count > 0 &&
            (result.command_count == 0 ? result.commands == NULL
                                       : result.commands != NULL);
    shell_processed_commands_free(&result);

    for (size_t fail_at = 1; valid && fail_at <= allocation_count; fail_at++) {
      result = (shell_processed_commands_t){
          .commands = (shell_command_info_t *)(uintptr_t)1,
          .command_count = SIZE_MAX,
          .groups = (shell_group_t *)(uintptr_t)1,
          .group_count = SIZE_MAX,
          .group_io_ops = (shell_group_io_op_t *)(uintptr_t)1,
          .group_io_op_count = SIZE_MAX,
      };
      shellsplit_test_alloc_fail_at(fail_at);
      status = shell_process_commands(
          allocation_cases[i], strlen(allocation_cases[i]), NULL, &result);
      shellsplit_test_alloc_reset();
      valid = valid && status == SHELL_PROCESS_ENOMEM &&
              result.commands == NULL && result.command_count == 0 &&
              result.groups == NULL && result.group_count == 0 &&
              result.group_io_ops == NULL && result.group_io_op_count == 0;
    }
  }
  shellsplit_test_alloc_reset();
  test("Redirect-only processed results are compact and allocation-atomic",
       valid);
}

static void test_group_combined_named_redirect_and_document_contract(void) {
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
      "{ printf x; } {fd}>&1",      "{ printf x; } {fd}>&-",
      "{ printf x; } {fd}> >(cat)", "{ cat; } {fd}<<<",
      "{ cat; } {fd}<<EOF\nbody\n", "{ printf x; } 2&>combined",
      "{ printf x; } 3&>>combined", "{ printf x; } {fd}&>combined",
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

static void test_combined_redirect_prefix_word_contract(void) {
  static const struct {
    const char *source;
    const char *netargv;
  } direct[] = {
      {"printf x 2&>combined", "6:printf,1:x,1:2,"},
      {"printf x 3&>>combined", "6:printf,1:x,1:3,"},
      {"printf x {fd}&>combined", "6:printf,1:x,4:{fd},"},
  };
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(direct) / sizeof(direct[0]); i++) {
    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    char *netargv = NULL;
    shell_process_status_t status = shell_process_command(
        direct[i].source, strlen(direct[i].source), NULL, &infos, &info_count);
    valid =
        status == SHELL_PROCESS_OK && infos != NULL && info_count == 1 &&
        infos[0].has_redirections && infos[0].has_error_redirection &&
        shell_render_netargv(&infos[0], NULL, &netargv) == SHELL_PROCESS_OK &&
        netargv != NULL && strcmp(netargv, direct[i].netargv) == 0;
    free(netargv);
    shell_command_infos_free(infos, info_count);
  }

  /* A compound group accepts only a redirect list after its delimiter. The
   * same prefix words that remain argv data in a simple command consequently
   * make the group form invalid, and every structured output is cleared. */
  static const char *const invalid_groups[] = {
      "{ printf x; } 2&>combined",
      "{ printf x; } 3&>>combined",
      "{ printf x; } {fd}&>combined",
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

static void test_substitution_scanner_contract(void) {
  /* A group redirect operand is one shell word, not a whitespace split. Its
   * embedded command substitutions and backticks can contain spaces while the
   * source span still covers the complete operand. */
  static const char redirects[] =
      "{ echo; } >prefix$(printf '/tmp/out')suffix 2>`printf /tmp/err`";
  shell_processed_commands_t result = {0};
  shell_process_status_t status =
      shell_process_commands(redirects, sizeof(redirects) - 1, NULL, &result);
  bool valid = status == SHELL_PROCESS_OK && result.group_count == 1 &&
               result.group_io_op_count == 2 &&
               result.group_io_ops[0].kind == SHELL_GROUP_IO_WRITE_FILE &&
               result.group_io_ops[1].kind == SHELL_GROUP_IO_WRITE_FILE &&
               result.group_io_ops[0].operand_end -
                       result.group_io_ops[0].operand_start ==
                   strlen("prefix$(printf '/tmp/out')suffix") &&
               result.group_io_ops[1].operand_end -
                       result.group_io_ops[1].operand_start ==
                   strlen("`printf /tmp/err`");
  shell_processed_commands_free(&result);

  shell_process_limits_t limits = {SIZE_MAX, SIZE_MAX, 1};
  status = shell_process_commands(redirects, sizeof(redirects) - 1, &limits,
                                  &result);
  valid = valid && status == SHELL_PROCESS_EOUTPUT_LIMIT &&
          result.commands == NULL && result.group_io_ops == NULL;
  shell_processed_commands_free(&result);

  /* A closing parenthesis in a nested heredoc is data, not the process
   * substitution delimiter. Unterminated bodies remain a parse error for the
   * complete structured API. */
  static const char nested_heredoc[] = "cat <(cat <<EOF\n)\nEOF\n)";
  status = shell_process_commands(nested_heredoc, sizeof(nested_heredoc) - 1,
                                  NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 1;
  shell_processed_commands_free(&result);

  /* The same structural rule applies to a command substitution. Its heredoc
   * body remains deferred data until the closing delimiter, then the outer
   * command-substitution delimiter closes normally. */
  static const char nested_command_heredoc[] = "echo $(cat <<EOF\n)\nEOF\n)";
  status =
      shell_process_commands(nested_command_heredoc,
                             sizeof(nested_command_heredoc) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 1;
  shell_processed_commands_free(&result);

  static const char mixed_quote_delimiter[] = "echo $(cat <<E'OF'\n)\nEOF\n)";
  status = shell_process_commands(
      mixed_quote_delimiter, sizeof(mixed_quote_delimiter) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 1;
  shell_processed_commands_free(&result);

  /* `<<` is an arithmetic shift inside `$((...))`, not a heredoc operator.
   * This must stay true through command and process substitutions. */
  static const char arithmetic_command[] = "echo $(printf '%s' $((1 << 2)))";
  status = shell_process_commands(
      arithmetic_command, sizeof(arithmetic_command) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 1;
  shell_processed_commands_free(&result);

  static const char arithmetic_process[] = "cat <(printf '%s' $((1 << 2)))";
  status = shell_process_commands(
      arithmetic_process, sizeof(arithmetic_process) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 1;
  shell_processed_commands_free(&result);

  static const char arithmetic_brace[] = "{ echo $((1 << 2)); }";
  status = shell_process_commands(arithmetic_brace,
                                  sizeof(arithmetic_brace) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 1 &&
          result.group_count == 1;
  shell_processed_commands_free(&result);

  /* A dynamic redirect operand can itself be arithmetic. Its shift operator
   * remains part of that word rather than beginning a heredoc declaration. */
  static const char arithmetic_redirect[] = "{ echo; } >$((1 << 2))";
  status = shell_process_commands(
      arithmetic_redirect, sizeof(arithmetic_redirect) - 1, NULL, &result);
  valid = valid && status == SHELL_PROCESS_OK && result.command_count == 1 &&
          result.group_count == 1 && result.group_io_op_count == 1 &&
          result.group_io_ops[0].kind == SHELL_GROUP_IO_WRITE_FILE &&
          result.group_io_ops[0].operand_end -
                  result.group_io_ops[0].operand_start ==
              strlen("$((1 << 2))");
  shell_processed_commands_free(&result);

  static const char unterminated[] = "cat <(cat <<EOF\n)\n";
  status = shell_process_commands(unterminated, sizeof(unterminated) - 1, NULL,
                                  &result);
  valid = valid && status == SHELL_PROCESS_EPARSE && result.commands == NULL &&
          result.group_io_ops == NULL;
  shell_processed_commands_free(&result);

  test("Substitution scanning preserves redirects, heredocs, and arithmetic",
       valid);
}

static void test_processed_group_descriptor_contract(void) {
  static const struct {
    const char *input;
    shell_group_kind_t group_kind;
    size_t operation_count;
    shell_group_io_kind_t kinds[4];
    uint32_t fds[4];
    uint32_t targets[4];
  } cases[] = {
      {"{ echo one; } 4<&0",
       SHELL_GROUP_BRACE,
       1,
       {SHELL_GROUP_IO_DUP_FD},
       {4},
       {0}},
      {"( echo one; ) 5>&-",
       SHELL_GROUP_SUBSHELL,
       1,
       {SHELL_GROUP_IO_CLOSE_FD},
       {5},
       {UINT32_MAX}},
      {"{ echo one; } 3>/tmp/trace 4<&0 5>&- 2>&1",
       SHELL_GROUP_BRACE,
       4,
       {SHELL_GROUP_IO_WRITE_FILE, SHELL_GROUP_IO_DUP_FD,
        SHELL_GROUP_IO_CLOSE_FD, SHELL_GROUP_IO_DUP_FD},
       {3, 4, 5, 2},
       {UINT32_MAX, 0, UINT32_MAX, 1}},
      {"{ sh; } > >(cat) <<< \"$(printf payload)\"",
       SHELL_GROUP_BRACE,
       2,
       {SHELL_GROUP_IO_PROCESS_SUB_OUT, SHELL_GROUP_IO_HERESTRING},
       {1, 0},
       {UINT32_MAX, UINT32_MAX}},
  };
  bool valid = true;
  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    shell_parse_result_t fast = {0};
    shell_processed_commands_t result = {0};
    valid = valid &&
            shell_parse_fast(cases[c].input, strlen(cases[c].input), NULL,
                             &fast) == SHELL_OK &&
            fast.group_count == 1 &&
            shell_process_commands(cases[c].input, strlen(cases[c].input), NULL,
                                   &result) == SHELL_PROCESS_OK &&
            result.command_count == 1 && result.group_count == 1 &&
            result.groups[0].kind == cases[c].group_kind &&
            result.group_io_op_count == cases[c].operation_count;
    for (size_t i = 0; valid && i < result.group_io_op_count; i++) {
      const shell_group_io_op_t *op = &result.group_io_ops[i];
      valid =
          op->group_index == 0 && op->kind == cases[c].kinds[i] &&
          op->fd == cases[c].fds[i] && op->target_fd == cases[c].targets[i] &&
          op->source_start < op->source_end &&
          (i == 0 || result.group_io_ops[i - 1].source_end <= op->source_start);
    }
    shell_processed_commands_free(&result);
  }

  static const char heredoc_descriptors[] =
      "{ cat; cat; } 4<&0 5>&- <<-'EOF' 3>\"/tmp/trace file\" 6>&1\n"
      "\tpayload\n"
      "\tEOF\n";
  static const shell_group_io_kind_t heredoc_kinds[] = {
      SHELL_GROUP_IO_DUP_FD,  SHELL_GROUP_IO_CLOSE_FD,
      SHELL_GROUP_IO_HEREDOC, SHELL_GROUP_IO_WRITE_FILE,
      SHELL_GROUP_IO_DUP_FD,
  };
  static const uint32_t heredoc_fds[] = {4, 5, 0, 3, 6};
  static const uint32_t heredoc_targets[] = {0, UINT32_MAX, UINT32_MAX,
                                             UINT32_MAX, 1};
  shell_processed_commands_t heredoc_result = {0};
  shell_process_status_t heredoc_status = shell_process_commands(
      heredoc_descriptors, sizeof(heredoc_descriptors) - 1, NULL,
      &heredoc_result);
  valid = valid && heredoc_status == SHELL_PROCESS_OK &&
          heredoc_result.command_count == 2 &&
          heredoc_result.group_count == 1 &&
          heredoc_result.group_io_op_count ==
              sizeof(heredoc_kinds) / sizeof(heredoc_kinds[0]);
  for (size_t i = 0; valid && i < heredoc_result.group_io_op_count; i++) {
    const shell_group_io_op_t *op = &heredoc_result.group_io_ops[i];
    valid = op->group_index == 0 && op->kind == heredoc_kinds[i] &&
            op->fd == heredoc_fds[i] && op->target_fd == heredoc_targets[i] &&
            op->source_start < op->source_end &&
            op->operand_start < op->operand_end &&
            (i == 0 ||
             heredoc_result.group_io_ops[i - 1].source_end <= op->source_start);
  }
  if (valid) {
    const shell_group_io_op_t *write = &heredoc_result.group_io_ops[3];
    size_t write_length = write->source_end - write->source_start;
    valid = write_length == strlen("3>\"/tmp/trace file\"") &&
            memcmp(heredoc_descriptors + write->source_start,
                   "3>\"/tmp/trace file\"", write_length) == 0;
  }
  shell_processed_commands_free(&heredoc_result);

  /* Apply the returned source-order operations to a tiny test-only descriptor
   * table.  This verifies the metadata preserves POSIX's order-sensitive
   * duplication semantics without turning the dependency graph into an FD
   * routing model. */
  static const struct {
    const char *input;
    int expected_fd1;
    int expected_fd2;
  } order_cases[] = {
      {"{ echo one; } 2>&1 >/tmp/out", 3, 1},
      {"{ echo one; } >/tmp/out 2>&1", 3, 3},
      {"{ echo one; } 3>&1 1>&- 4>&3", -1, 2},
  };
  for (size_t c = 0; c < sizeof(order_cases) / sizeof(order_cases[0]); c++) {
    shell_processed_commands_t result = {0};
    int descriptor[5] = {0, 1, 2, -1, -1};
    shell_process_status_t status = shell_process_commands(
        order_cases[c].input, strlen(order_cases[c].input), NULL, &result);
    valid = valid && status == SHELL_PROCESS_OK;
    for (size_t i = 0; valid && i < result.group_io_op_count; i++) {
      const shell_group_io_op_t *op = &result.group_io_ops[i];
      if (op->fd >= sizeof(descriptor) / sizeof(descriptor[0])) {
        valid = false;
      } else if (op->kind == SHELL_GROUP_IO_DUP_FD) {
        valid = op->target_fd < sizeof(descriptor) / sizeof(descriptor[0]);
        if (valid)
          descriptor[op->fd] = descriptor[op->target_fd];
      } else if (op->kind == SHELL_GROUP_IO_CLOSE_FD) {
        descriptor[op->fd] = -1;
      } else if (op->kind == SHELL_GROUP_IO_WRITE_FILE ||
                 op->kind == SHELL_GROUP_IO_APPEND_FILE) {
        descriptor[op->fd] = 3;
      }
    }
    valid = valid && descriptor[1] == order_cases[c].expected_fd1 &&
            descriptor[2] == order_cases[c].expected_fd2;
    if (c == 2)
      valid = valid && descriptor[4] == 1;
    shell_processed_commands_free(&result);
  }
  test("Processed groups preserve leading descriptor and routing order", valid);
}

static void test_heredoc_iterator_contract(void) {
  static const char input[] = "cat <<E'OF' <<-\\D'ONE'\n"
                              "one\n"
                              "EOF\n"
                              "\ttwo\n"
                              "\tDONE\n"
                              "printf done";
  static const shell_token_type_t types[] = {
      SHELL_TOKEN_COMMAND,   SHELL_TOKEN_HEREDOC, SHELL_TOKEN_HEREDOC,
      SHELL_TOKEN_SEMICOLON, SHELL_TOKEN_COMMAND, SHELL_TOKEN_COMMAND,
  };
  static const char *const texts[] = {"cat", "<<E'OF'", "<<-\\D'ONE'",
                                      "\n",  "printf",  "done"};
  shell_tokenizer_state_t state;
  shell_tokenizer_init(&state, input, sizeof(input) - 1);
  bool valid = true;
  for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
    shell_token_t token;
    bool advanced = shell_tokenizer_next(&state, &token);
    bool token_valid = advanced && token.type == types[i] &&
                       token.length == strlen(texts[i]) &&
                       memcmp(token.start, texts[i], token.length) == 0;
    if (i == 1 || i == 2)
      token_valid = token_valid && token.is_quoted;
    valid = valid && token_valid;
  }
  shell_token_t token;
  valid = valid && !shell_tokenizer_next(&state, &token) &&
          !state.heredoc_error && state.pending_heredoc_count == 0;

  /* A named descriptor is part of an inline-document redirect, not a word
   * followed by a bare redirect. The full lexer must retain that boundary for
   * both document forms. The lexical iterator preserves the terminating
   * newline as a list separator; the structured command tokenizer below
   * consumes it as the document-only stage boundary. */
  static const char named_heredoc[] = "cat& {fd}<<EOF\nbody\nEOF\n";
  shell_tokenizer_init(&state, named_heredoc, sizeof(named_heredoc) - 1);
  static const shell_token_type_t named_types[] = {
      SHELL_TOKEN_COMMAND,
      SHELL_TOKEN_BACKGROUND,
      SHELL_TOKEN_HEREDOC,
      SHELL_TOKEN_SEMICOLON,
  };
  static const char *const named_texts[] = {"cat", "&", "{fd}<<EOF", "\n"};
  for (size_t i = 0; i < sizeof(named_types) / sizeof(named_types[0]); i++) {
    bool advanced = shell_tokenizer_next(&state, &token);
    valid = valid && advanced && token.type == named_types[i] &&
            token.length == strlen(named_texts[i]) &&
            memcmp(token.start, named_texts[i], token.length) == 0;
  }
  valid = valid && !shell_tokenizer_next(&state, &token) &&
          !state.heredoc_error && state.pending_heredoc_count == 0;

  static const char named_herestring[] = "{fd}<<<payload";
  shell_tokenizer_init(&state, named_herestring, sizeof(named_herestring) - 1);
  bool named_herestring_advanced = shell_tokenizer_next(&state, &token);
  bool named_herestring_valid =
      named_herestring_advanced && token.type == SHELL_TOKEN_HERESTRING &&
      token.length == sizeof("{fd}<<<") - 1 &&
      memcmp(token.start, "{fd}<<<", token.length) == 0;
  bool named_herestring_operand =
      shell_tokenizer_next(&state, &token) &&
      token.type == SHELL_TOKEN_COMMAND &&
      token.length == sizeof("payload") - 1 &&
      memcmp(token.start, "payload", token.length) == 0;
  bool named_herestring_exhausted = !shell_tokenizer_next(&state, &token);
  valid = valid && named_herestring_valid && named_herestring_operand &&
          named_herestring_exhausted;

  shell_command_t *named_commands = NULL;
  size_t named_command_count = 0;
  bool named_commands_valid =
      shell_tokenize_commands(named_heredoc, sizeof(named_heredoc) - 1,
                              &named_commands,
                              &named_command_count) == SHELL_TOKENIZE_OK &&
      named_command_count == 2 && named_commands != NULL &&
      named_commands[1].token_count == 1 &&
      named_commands[1].tokens[0].type == SHELL_TOKEN_HEREDOC &&
      named_commands[1].tokens[0].length == sizeof("{fd}<<EOF") - 1;
  valid = valid && named_commands_valid;
  shell_commands_free(named_commands, named_command_count);

  shell_command_t *commands = NULL;
  size_t command_count = 0;
  static const char unterminated[] = "cat <<EOF\nbody\n";
  bool unterminated_valid =
      shell_tokenize_commands(unterminated, sizeof(unterminated) - 1, &commands,
                              &command_count) == SHELL_TOKENIZE_OK &&
      commands != NULL && command_count == 1;
  valid = valid && unterminated_valid;
  shell_commands_free(commands, command_count);
  test("Heredoc iterator emits declarations and skips ordered bodies", valid);
}

static void test_canonical_heredoc_api_contract(void) {
  static const struct {
    const char *name;
    const char *input;
    size_t document_count;
    size_t literal_count;
    const char *first_delimiter;
  } cases[] = {
      {"space-separated delimiter", "cat << EOF\nbody\nEOF\nprintf after\n", 1,
       0, "EOF"},
      {"double-quoted retained backslash",
       "cat <<\"E\\qF\"\nbody\nE\\qF\nprintf after\n", 1, 1, "E\\qF"},
      {"double-quoted whitespace delimiter",
       "cat <<\"A B\"\nbody\nA B\nprintf after\n", 1, 1, "A B"},
      {"escaped whitespace delimiter", "cat <<A\\ B\nbody\nA B\nprintf after\n",
       1, 1, "A\\ B"},
      {"empty single-quoted delimiter", "cat <<''\n\nprintf after\n", 1, 1, ""},
      {"mixed FIFO CRLF delimiters",
       "cat << EOF <<-\"F\"\r\none\r\nEOF\r\n\ttwo\r\n\tF\r\n"
       "printf after\r\n",
       2, 1, "EOF"},
  };

  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *input = cases[i].input;
    size_t length = strlen(input);
    shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    shell_parse_result_t fast = {0};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {0};
    char *netargv = NULL;
    char *command_netseq = NULL;
    char *anomaly_commands = NULL;
    char *anomaly_types = NULL;
    size_t netargv_count = 0;
    size_t command_netseq_count = 0;
    size_t anomaly_count = 0;
    bool features = false;
    shell_dep_graph_t graph = {0};

    valid =
        valid && shell_parse_fast(input, length, &strict, &fast) == SHELL_OK &&
        fast.status == SHELL_STATUS_OK &&
        shell_tokenize_commands(input, length, &commands, &command_count) ==
            SHELL_TOKENIZE_OK &&
        command_count == 2 &&
        shell_process_commands(input, length, NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == 2 &&
        shell_build_netargv_sequence(input, length, NULL, &netargv,
                                     &netargv_count,
                                     &features) == SHELL_PROCESS_OK &&
        netargv != NULL && netargv_count == 2 && features &&
        shell_build_command_netseq(input, length, NULL, &command_netseq,
                                   &command_netseq_count) == SHELL_PROCESS_OK &&
        command_netseq != NULL && command_netseq_count == 2 &&
        shell_build_anomaly_netseqs(input, length, NULL, &anomaly_commands,
                                    &anomaly_types,
                                    &anomaly_count) == SHELL_PROCESS_OK &&
        anomaly_commands != NULL && anomaly_types != NULL &&
        anomaly_count == 2 &&
        shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;

    size_t documents = 0;
    size_t literals = 0;
    size_t reads = 0;
    const shell_dep_doc_t *first_document = NULL;
    for (uint32_t node = 0; node < graph.node_count; node++) {
      const shell_dep_node_t *current = &graph.nodes[node];
      if (current->type != SHELL_NODE_DOC ||
          current->doc.kind != SHELL_DOC_HEREDOC)
        continue;
      if (!first_document)
        first_document = &current->doc;
      documents++;
      literals +=
          (current->doc.flags & SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL) != 0;
    }
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      reads += graph.edges[edge].type == SHELL_EDGE_READ;
    valid = valid && documents == cases[i].document_count &&
            literals == cases[i].literal_count && reads > 0 &&
            first_document != NULL && first_document->name != NULL &&
            first_document->name_len == strlen(cases[i].first_delimiter) &&
            memcmp(first_document->name, cases[i].first_delimiter,
                   first_document->name_len) == 0;

    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    free(netargv);
    free(command_netseq);
    free(anomaly_commands);
    free(anomaly_types);
  }
  test("Canonical APIs agree on POSIX heredoc delimiters", valid);
}

static void test_heredoc_expansion_semantic_contract(void) {
  static const char *const unsupported[] = {
      "cat <<EOF\n$(while true; do :; done)\nEOF\n",
      "cat <<EOF\n`select item in one; do :; done`\nEOF\n",
      "cat <<EOF\n${items[0]}\nEOF\n",
      "cat <<EOF\n$((items[0]))\nEOF\n",
      "cat <<EOF\n\"${items[0]}\"\nEOF\n",
      "echo $(cat <<EOF\n$(coproc worker { :; })\nEOF\n)",
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++)
    valid = valid && shell_tokenizer_has_unsupported_semantics(
                         unsupported[i], strlen(unsupported[i]));

  static const char *const supported[] = {
      ("cat <<EOF\nwhile true; do :; done\n$\"locale\"\n"
       "\\$(while true; do :; done)\n\\${items[0]}\n$(printf x)\n"
       "$((1 + 2))\nEOF\n"),
      ("cat <<'EOF'\n$(while true; do :; done)\n${items[0]}\n"
       "$((items[0]))\n$\"locale\"\nEOF\n"),
      "cat <<${items[0]}\nbody\n${items[0]}\n",
  };
  for (size_t i = 0; valid && i < sizeof(supported) / sizeof(supported[0]); i++)
    valid = !shell_tokenizer_has_unsupported_semantics(supported[i],
                                                       strlen(supported[i]));

  static const char visited[] = "cat <<EOF <<-'LITERAL'\r\n"
                                "$(printf active)\r\n"
                                "EOF\r\n"
                                "\t$(while true; do :; done)\r\n"
                                "\tLITERAL\r\n";
  heredoc_body_capture_t capture = {0};
  size_t after = 0;
  bool complete = false;
  size_t first_operator = strlen("cat ");
  valid = valid &&
          shell_source_visit_heredoc_sequence(
              visited, sizeof(visited) - 1, first_operator,
              capture_heredoc_body, &capture, &after, &complete) &&
          complete && after == sizeof(visited) - 1 && capture.count == 2 &&
          !capture.quoted[0] && capture.quoted[1] &&
          capture.lengths[0] == strlen("$(printf active)\r\n") &&
          capture.lengths[1] == strlen("\t$(while true; do :; done)\r\n") &&
          memcmp(visited + capture.starts[0], "$(printf active)\r\n",
                 capture.lengths[0]) == 0 &&
          memcmp(visited + capture.starts[1], "\t$(while true; do :; done)\r\n",
                 capture.lengths[1]) == 0;
  test("Heredoc validation distinguishes active expansions from literal data",
       valid);
}

static size_t render_nested_brace_heredoc(char *output, uint32_t depth) {
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

static void test_brace_group_maximum_contract(void) {
  char input[(SHELL_MAX_GROUPS + 1) * 5 + 32];
  size_t length = render_nested_brace_heredoc(input, SHELL_MAX_GROUPS);
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

  length = render_nested_brace_heredoc(input, SHELL_MAX_GROUPS + 1);
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
      fast_error == SHELL_EPARSE && tokenize_error == SHELL_TOKENIZE_EPARSE &&
      commands == NULL && command_count == 0 &&
      process_error == SHELL_PROCESS_EPARSE && processed.commands == NULL &&
      processed.command_count == 0 && processed.groups == NULL &&
      processed.group_count == 0 && processed.group_io_ops == NULL &&
      processed.group_io_op_count == 0 && dep_error == SHELL_DEP_EPARSE;
  valid = valid && rejected;
  test("Brace-group maximum depth is consistent across high-level APIs", valid);
}

static void test_canonical_sequence_model_capacity_contract(void) {
  char input[(SHELL_MAX_SUBCOMMANDS + 1) * 2];
  size_t length = 0;
  for (size_t i = 0; i < SHELL_MAX_SUBCOMMANDS + 1; i++) {
    input[length++] = 'x';
    if (i + 1 < SHELL_MAX_SUBCOMMANDS + 1)
      input[length++] = '|';
  }

  shell_command_info_t *flat = NULL;
  size_t flat_count = 0;
  shell_processed_commands_t processed = {0};
  char *netargv = (char *)(uintptr_t)1;
  size_t netargv_count = SIZE_MAX;
  bool features = true;
  bool valid = shell_process_command(input, length, NULL, &flat, &flat_count) ==
                   SHELL_PROCESS_OK &&
               flat != NULL && flat_count == SHELL_MAX_SUBCOMMANDS + 1 &&
               shell_process_commands(input, length, NULL, &processed) ==
                   SHELL_PROCESS_EOUTPUT_LIMIT &&
               processed.commands == NULL && processed.command_count == 0 &&
               processed.groups == NULL && processed.group_count == 0 &&
               processed.group_io_ops == NULL &&
               processed.group_io_op_count == 0 &&
               shell_build_netargv_sequence(input, length, NULL, &netargv,
                                            &netargv_count, &features) ==
                   SHELL_PROCESS_EOUTPUT_LIMIT &&
               netargv == NULL && netargv_count == 0 && !features;
  shell_command_infos_free(flat, flat_count);
  shell_processed_commands_free(&processed);
  test("Canonical sequence honors semantic-model capacity", valid);
}

static void test_group_structure_redirect_marker_contract(void) {
  /* Exercise the compound-boundary metadata contract directly so downstream
   * sequence builders cannot turn a redirect-only structural record into an
   * executable empty command. */
  static const char input[] = "{ echo; } >/tmp/out";
  shell_token_t redirect = {
      .type = SHELL_TOKEN_REDIRECT_OUT,
      .start = input + 10,
      .length = 1,
      .position = 10,
  };
  shell_command_t commands[2] = {0};
  commands[0].tokens = &redirect;
  commands[0].token_count = 1;
  commands[0].end_pos = 9;
  commands[0].ends_group = true;
  commands[1].tokens = &redirect;
  commands[1].token_count = 1;

  bool valid = shell_processed_command_is_group_structure(commands, 2, 1, input,
                                                          strlen(input));
  valid = valid &&
          !shell_processed_command_is_group_structure(commands, 2, 1, NULL, 0);
  redirect.position = SIZE_MAX;
  valid = valid && !shell_processed_command_is_group_structure(
                       commands, 2, 1, input, strlen(input));
  redirect.position = 10;
  shell_token_t distant = {
      .type = SHELL_TOKEN_REDIRECT_OUT,
      .start = input + 15,
      .length = 1,
      .position = 15,
  };
  commands[1].tokens = &distant;
  valid = valid && !shell_processed_command_is_group_structure(
                       commands, 2, 1, input, strlen(input));
  distant.position = SIZE_MAX;
  valid = valid && !shell_processed_command_is_group_structure(
                       commands, 2, 1, input, strlen(input));
  commands[1].tokens = &redirect;
  commands[0].end_pos = 11;
  valid = valid && !shell_processed_command_is_group_structure(
                       commands, 2, 1, input, strlen(input));
  commands[0].end_pos = 9;
  commands[0].ends_group = false;
  valid = valid && !shell_processed_command_is_group_structure(
                       commands, 2, 1, input, strlen(input));
  test("Group redirect markers remain structural", valid);
}

static void test_processed_word_iterator_boundary_contract(void) {
  static const char continuation_source[] = ">x\\\r\ny next";
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
       .start = continuation_source + 5,
       .length = 1,
       .position = 5},
      {.type = SHELL_TOKEN_ARGUMENT,
       .start = continuation_source + 7,
       .length = 4,
       .position = 7},
  };
  shell_command_t redirect_command = {
      .tokens = redirect_tokens,
      .token_count = sizeof(redirect_tokens) / sizeof(redirect_tokens[0]),
  };
  shell_processed_word_iterator_t iterator;
  shell_token_t word = {0};
  shell_processed_word_iterator_init(&iterator, &redirect_command);
  bool redirect_valid = shell_processed_word_iterator_next(&iterator, &word) &&
                        word.start == continuation_source + 7 &&
                        word.length == 4 &&
                        !shell_processed_word_iterator_next(&iterator, &word);
  bool valid = redirect_valid;

  static const char fragment_source[] = "a\\\r\nb";
  shell_token_t fragments[] = {
      {.type = SHELL_TOKEN_ARGUMENT,
       .start = fragment_source,
       .length = 1,
       .position = 0},
      {.type = SHELL_TOKEN_ARGUMENT,
       .start = fragment_source + 4,
       .length = 1,
       .position = 4,
       .is_quoted = true,
       .is_escaped = true},
  };
  shell_command_t fragment_command = {
      .tokens = fragments,
      .token_count = sizeof(fragments) / sizeof(fragments[0]),
  };
  shell_processed_word_iterator_init(&iterator, &fragment_command);
  bool fragment_valid = shell_processed_word_iterator_next(&iterator, &word) &&
                        word.start == fragment_source && word.length == 5 &&
                        word.is_quoted && word.is_escaped &&
                        !shell_processed_word_iterator_next(&iterator, &word);
  valid = valid && fragment_valid;

  shell_token_t overflow_tokens[] = {
      {.type = SHELL_TOKEN_ARGUMENT,
       .start = fragment_source,
       .length = 1,
       .position = 0},
      {.type = SHELL_TOKEN_ARGUMENT,
       .start = fragment_source,
       .length = 1,
       .position = SIZE_MAX},
  };
  shell_command_t overflow_command = {
      .tokens = overflow_tokens,
      .token_count = sizeof(overflow_tokens) / sizeof(overflow_tokens[0]),
  };
  shell_processed_word_iterator_init(&iterator, &overflow_command);
  bool overflow_valid = shell_processed_word_iterator_next(&iterator, &word) &&
                        word.position == 0 &&
                        shell_processed_word_iterator_next(&iterator, &word) &&
                        word.position == SIZE_MAX &&
                        !shell_processed_word_iterator_next(&iterator, &word);
  valid = valid && overflow_valid;

  shell_token_t overflow_operand_tokens[] = {
      {.type = SHELL_TOKEN_REDIRECT_OUT,
       .start = continuation_source,
       .length = 1,
       .position = 0},
      {.type = SHELL_TOKEN_ARGUMENT,
       .start = fragment_source,
       .length = 1,
       .position = SIZE_MAX},
      {.type = SHELL_TOKEN_ARGUMENT,
       .start = fragment_source,
       .length = 1,
       .position = 2},
  };
  shell_command_t overflow_operand_command = {
      .tokens = overflow_operand_tokens,
      .token_count =
          sizeof(overflow_operand_tokens) / sizeof(overflow_operand_tokens[0]),
  };
  shell_processed_word_iterator_init(&iterator, &overflow_operand_command);
  bool overflow_operand_valid =
      shell_processed_word_iterator_next(&iterator, &word) &&
      word.position == 2 &&
      !shell_processed_word_iterator_next(&iterator, &word);
  valid = valid && overflow_operand_valid;

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
  bool continuation_valid =
      shell_tokenizer_token_continues_word(&lf, 1) &&
      !shell_tokenizer_token_continues_word(NULL, 0) &&
      !shell_tokenizer_token_continues_word(&invalid_gap, 1) &&
      !shell_tokenizer_token_continues_word(&invalid_gap, 3);
  valid = valid && continuation_valid;
  test("Processed-word iterator preserves continuation and overflow boundaries",
       valid);
}

int main(void) {
  test_tokenize_allocation_failures();
  test_processor_allocation_failures();
  test_transform_allocation_failures();
  test_output_limit_boundaries();
  test_cstring_allocation_size_boundaries();
  test_canonical_control_compounds_rejected();
  test_unsupported_control_precedes_capacity();
  test_control_word_literals_are_accepted();
  test_structured_processor_requires_complete_syntax();
  test_tolerant_unfinished_group_omits_empty_command();
  test_processed_commands_preserve_comment_free_ranges();
  test_processed_comment_only_source_is_empty();
  test_posix_brace_group_sequence();
  test_posix_brace_group_forms();
  test_command_position_group_syntax_rejected();
  test_full_tokenizer_group_context();
  test_brace_group_process_substitution_contract();
  test_clobber_redirection_operand_contract();
  test_brace_group_processed_contract();
  test_processed_group_command_intervals();
  test_brace_group_boundaries_and_redirections();
  test_brace_group_heredoc_sequence_contract();
  test_brace_group_grammar_matrix();
  test_brace_group_operation_limits_are_atomic();
  test_extraneous_brace_closer_rejected();
  test_anomaly_sequences_include_nested_execution_stages();
  test_anomaly_sequences_represent_redirect_only_record();
  test_redirect_operand_boundary_contract();
  test_processed_group_io_contract();
  test_processed_group_io_boundaries();
  test_redirect_only_processed_result_ownership();
  test_group_combined_named_redirect_and_document_contract();
  test_combined_redirect_prefix_word_contract();
  test_substitution_scanner_contract();
  test_processed_group_descriptor_contract();
  test_heredoc_iterator_contract();
  test_canonical_heredoc_api_contract();
  test_heredoc_expansion_semantic_contract();
  test_brace_group_maximum_contract();
  test_canonical_sequence_model_capacity_contract();
  test_group_structure_redirect_marker_contract();
  test_processed_word_iterator_boundary_contract();
  test_token_type_names();
  test_list_syntax_contract();
  test_source_scanner_boundaries();
  test_named_fd_word_boundaries();
  test_record_parser_boundaries();
  test_modern_bash_syntax_contract();
  test_processor_routing_cross_product();
  test_canonical_buffer_output_contract();
  test_array_semantic_boundaries();
  test_ansi_c_structural_scanner_contract();
  test_error_strings();
  test_composition_metadata();
  static const iterator_case_t iterator_cases[] = {
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
       "cmd >>&9 >&10 <&0 3>&- 4<&- 12>>log",
       8,
       {SHELL_TOKEN_COMMAND, SHELL_TOKEN_REDIRECT_APPEND,
        SHELL_TOKEN_REDIRECT_ERR, SHELL_TOKEN_REDIRECT_IN,
        SHELL_TOKEN_REDIRECT_ERR, SHELL_TOKEN_REDIRECT_IN,
        SHELL_TOKEN_REDIRECT_APPEND, SHELL_TOKEN_COMMAND},
       {"cmd", ">>&9", ">&10", "<&0", "3>&-", "4<&-", "12>>", "log"},
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
  run_iterator_cases(iterator_cases,
                     sizeof(iterator_cases) / sizeof(iterator_cases[0]));
  test_iterator_argument_contracts();
  printf("Running unified tokenizer tests...\n\n");
  printf("=== BASIC TOKENIZER TESTS ===\n\n");

  static const tokenizer_case_t basic_cases[] = {
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
  run_tokenizer_cases(basic_cases,
                      sizeof(basic_cases) / sizeof(basic_cases[0]));

  printf("\n=== EXTENDED TOKENIZER TESTS ===\n\n");

  static const feature_case_t feature_cases[] = {
      {{"plain command", "echo hello", 1}, 0},
      {{"simple variable", "echo $VAR", 1}, EXPECT_VARIABLE},
      {{"braced variable", "echo ${VAR}", 1}, EXPECT_VARIABLE},
      {{"special variables", "echo $1 $# $? $$", 1}, EXPECT_VARIABLE},
      {{"multiple variables", "echo $A $B $C", 1}, EXPECT_VARIABLE},
      {{"asterisk glob", "ls *.txt", 1}, EXPECT_GLOB},
      {{"question-mark glob", "cat file?.txt", 1}, EXPECT_GLOB},
      {{"bracket glob", "ls file[123].txt", 1}, EXPECT_GLOB},
      {{"command substitution", "cat $(file)", 1}, EXPECT_SUBSHELL},
      {{"backtick substitution", "cat `file`", 1}, EXPECT_SUBSHELL},
      {{"arithmetic expansion", "echo $((x+1))", 1}, EXPECT_ARITHMETIC},
      {{"features across pipeline", "cat $FILE | grep *.log", 2},
       EXPECT_VARIABLE | EXPECT_GLOB},
      {{"combined features", "ls ${DIR}/*.txt | sort", 2},
       EXPECT_VARIABLE | EXPECT_GLOB},
      {{"empty input", "", 0}, 0},
      {{"whitespace input", "   ", 0}, 0},
      {{"single-character command", "x", 1}, 0},
      {{"variable with underscore and numbers", "echo $VAR_NAME_123", 1},
       EXPECT_VARIABLE},
      {{"empty command substitution", "echo $()", 1}, EXPECT_SUBSHELL},
      {{"nested command substitutions", "echo $(echo $(echo hi))", 1},
       EXPECT_SUBSHELL},
      {{"glob argument", "cmd *.c", 1}, EXPECT_GLOB},
      {{"combined glob forms", "ls file???[0-9]*.{c,h}", 1}, EXPECT_GLOB},
      {{"negated bracket glob", "ls file[!123].txt", 1}, EXPECT_GLOB},
  };
  run_feature_cases(feature_cases,
                    sizeof(feature_cases) / sizeof(feature_cases[0]));

  static const tokenizer_case_t rejected_cases[] = {
      {"reject nested variable braces", "echo ${VAR${SUFFIX}}", 0},
      {"reject unclosed variable brace", "echo ${VAR", 0},
  };
  run_rejected_cases(rejected_cases,
                     sizeof(rejected_cases) / sizeof(rejected_cases[0]));

  static const stage_case_t stage_cases[] = {
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
  run_stage_cases(stage_cases, sizeof(stage_cases) / sizeof(stage_cases[0]));

  // Test 75: Large pipeline with all features
  {
    const char *input =
        "find ${START_DIR} -name \"*.${EXT}\" -type f 2>/dev/null | "
        "grep -v \"^\\.\" | sort -u | head -${MAX_COUNT} | "
        "while read file; do wc -l \"$file\"; done | "
        "awk '{sum+=$1} END {print sum}' > ${OUTPUT_FILE}";
    check_tokenizer_case("Extended tokenizer: large mixed-feature pipeline",
                         input, 8);
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
    check_tokenizer_case("Extended tokenizer: data processing pipeline", input,
                         9);
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
    check_tokenizer_case("Extended tokenizer: system monitoring pipeline",
                         input, 10);
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
    check_tokenizer_case(
        "Extended tokenizer: preserve PIPESTATUS pipeline structure", input,
        15);
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
    check_tokenizer_case("Extended tokenizer: database operations pipeline",
                         input, 7);
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
    check_tokenizer_case("Extended tokenizer: container orchestration pipeline",
                         input, 12);
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
    check_tokenizer_case("Extended tokenizer: log aggregation and analysis",
                         input, 17);
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
    check_tokenizer_case(
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
    check_tokenizer_case("Extended tokenizer: API data processing pipeline",
                         input, 10);
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
    check_tokenizer_case("Extended tokenizer: preserve CI/CD structure", input,
                         17);
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

  static const transform_line_case_t transform_line_cases[] = {
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
      {"Transform line: removes CRLF word continuations",
       "echo \"x\"\\\r\n${y}z",
       1,
       {"echo \"x\"VAR_VALUEz"},
       UINT32_C(0x1),
       {NULL}},
      {"Transform line: joins substitution suffixes",
       "echo $(id)suffix",
       1,
       {"echo TEMP_FILEsuffix"},
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
  run_transform_line_cases(transform_line_cases,
                           sizeof(transform_line_cases) /
                               sizeof(transform_line_cases[0]));

  {
    shell_transformed_command_t **sentinel =
        (shell_transformed_command_t **)(uintptr_t)1;
    shell_transformed_command_t **commands = sentinel;
    shell_transformed_command_t *command =
        (shell_transformed_command_t *)(uintptr_t)1;
    shell_command_t empty = {0};
    shell_token_t malformed_tokens[] = {
        {.type = SHELL_TOKEN_COMMAND,
         .start = "echo",
         .length = 4,
         .position = 0},
        {.type = SHELL_TOKEN_ARGUMENT,
         .start = NULL,
         .length = 5,
         .position = 5},
        {.type = SHELL_TOKEN_ARGUMENT,
         .start = "x",
         .length = 2,
         .position = 4},
    };
    shell_command_t malformed[] = {
        {.tokens = &malformed_tokens[0],
         .token_count = 1,
         .start_pos = 2,
         .end_pos = 1},
        {.tokens = malformed_tokens,
         .token_count = 2,
         .start_pos = 0,
         .end_pos = 10},
        {.tokens = &malformed_tokens[2],
         .token_count = 1,
         .start_pos = 0,
         .end_pos = 5},
    };
    size_t count = SIZE_MAX;
    bool valid = true;

    if (shell_transform_command_line(NULL, 0, NULL, &commands, &count) !=
            SHELL_TRANSFORM_EINPUT ||
        commands != NULL || count != 0)
      valid = false;
    commands = sentinel;
    count = SIZE_MAX;
    if (shell_transform_command_line("\x01"
                                     "cmd",
                                     strlen("\x01"
                                            "cmd"),
                                     NULL, &commands,
                                     &count) != SHELL_TRANSFORM_EINPUT ||
        commands != NULL || count != 0)
      valid = false;
    if (shell_transform_command_line("echo", strlen("echo"), NULL, NULL,
                                     &count) != SHELL_TRANSFORM_EINPUT)
      valid = false;
    if (shell_transform_command_line("echo", strlen("echo"), NULL, &commands,
                                     NULL) != SHELL_TRANSFORM_EINPUT)
      valid = false;
    commands = sentinel;
    count = SIZE_MAX;
    if (shell_transform_command_line(" \t", 2, NULL, &commands, &count) !=
            SHELL_TRANSFORM_OK ||
        commands != NULL || count != 0)
      valid = false;
    commands = sentinel;
    count = SIZE_MAX;
    if (shell_transform_command_line("echo '", strlen("echo '"), NULL,
                                     &commands,
                                     &count) != SHELL_TRANSFORM_EPARSE ||
        commands != NULL || count != 0)
      valid = false;
    if (shell_transform_command(NULL, NULL, &command) !=
            SHELL_TRANSFORM_EINPUT ||
        command != NULL)
      valid = false;
    command = (shell_transformed_command_t *)(uintptr_t)1;
    if (shell_transform_command(&empty, NULL, &command) !=
            SHELL_TRANSFORM_EINPUT ||
        command != NULL)
      valid = false;
    if (shell_transform_command(&empty, NULL, NULL) != SHELL_TRANSFORM_EINPUT)
      valid = false;
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
      command = (shell_transformed_command_t *)(uintptr_t)1;
      if (shell_transform_command(&malformed[i], NULL, &command) ==
              SHELL_TRANSFORM_OK ||
          command != NULL)
        valid = false;
    }
    shell_token_t first = {.type = SHELL_TOKEN_COMMAND,
                           .start = "echo x",
                           .length = 4,
                           .position = 0};
    const shell_command_t first_invalid[] = {
        {.tokens = &(shell_token_t){.type = SHELL_TOKEN_COMMAND,
                                    .start = NULL,
                                    .length = 4,
                                    .position = 0},
         .token_count = 1,
         .start_pos = 0,
         .end_pos = 4},
        {.tokens = &(shell_token_t){.type = SHELL_TOKEN_COMMAND,
                                    .start = "echo",
                                    .length = 4,
                                    .position = 0},
         .token_count = 1,
         .start_pos = 1,
         .end_pos = 4},
        {.tokens = &(shell_token_t){.type = SHELL_TOKEN_COMMAND,
                                    .start = "echo",
                                    .length = 4,
                                    .position = 5},
         .token_count = 1,
         .start_pos = 0,
         .end_pos = 4},
        {.tokens = &(shell_token_t){.type = SHELL_TOKEN_COMMAND,
                                    .start = "echo",
                                    .length = 5,
                                    .position = 0},
         .token_count = 1,
         .start_pos = 0,
         .end_pos = 4},
    };
    for (size_t i = 0; i < sizeof(first_invalid) / sizeof(first_invalid[0]);
         i++) {
      command = (shell_transformed_command_t *)(uintptr_t)1;
      if (shell_transform_command(&first_invalid[i], NULL, &command) !=
              SHELL_TRANSFORM_EINPUT ||
          command != NULL)
        valid = false;
    }
    shell_token_t later_tokens[] = {
        first,
        {.type = SHELL_TOKEN_ARGUMENT,
         .start = NULL,
         .length = 1,
         .position = 4},
    };
    command = (shell_transformed_command_t *)(uintptr_t)1;
    if (shell_transform_command(&(shell_command_t){.tokens = later_tokens,
                                                   .token_count = 2,
                                                   .start_pos = 0,
                                                   .end_pos = 5},
                                NULL, &command) != SHELL_TRANSFORM_EINPUT ||
        command != NULL)
      valid = false;
    command = (shell_transformed_command_t *)(uintptr_t)1;
    if (shell_transform_command(&(shell_command_t){.tokens = &first,
                                                   .token_count = SIZE_MAX,
                                                   .start_pos = 0,
                                                   .end_pos = 4},
                                NULL, &command) != SHELL_TRANSFORM_EOVERFLOW ||
        command != NULL)
      valid = false;
    shell_transform_limits_t transformed_limit = {.max_string_bytes = 5,
                                                  .max_total_bytes = SIZE_MAX};
    command = (shell_transformed_command_t *)(uintptr_t)1;
    if (shell_transform_command(&(shell_command_t){.tokens = &first,
                                                   .token_count = 1,
                                                   .start_pos = 0,
                                                   .end_pos = 4},
                                &transformed_limit,
                                &command) != SHELL_TRANSFORM_OK ||
        command == NULL)
      valid = false;
    shell_transformed_command_free(command);
    transformed_limit.max_string_bytes = 3;
    command = (shell_transformed_command_t *)(uintptr_t)1;
    if (shell_transform_command(&(shell_command_t){.tokens = &first,
                                                   .token_count = 1,
                                                   .start_pos = 0,
                                                   .end_pos = 4},
                                &transformed_limit,
                                &command) != SHELL_TRANSFORM_EOUTPUT_LIMIT ||
        command != NULL)
      valid = false;
    const shell_token_type_t syntax_types[] = {
        SHELL_TOKEN_PIPE,
        SHELL_TOKEN_REDIRECT_IN,
        SHELL_TOKEN_REDIRECT_OUT,
        SHELL_TOKEN_REDIRECT_ERR,
        SHELL_TOKEN_REDIRECT_APPEND,
        SHELL_TOKEN_REDIRECT_READ_WRITE,
        SHELL_TOKEN_REDIRECT_CLOBBER,
        SHELL_TOKEN_SEMICOLON,
        SHELL_TOKEN_AND,
        SHELL_TOKEN_BACKGROUND,
        SHELL_TOKEN_OR,
        SHELL_TOKEN_GROUP_START,
        SHELL_TOKEN_GROUP_END,
        SHELL_TOKEN_SUBSHELL_START,
        SHELL_TOKEN_SUBSHELL_END,
        SHELL_TOKEN_HEREDOC,
        SHELL_TOKEN_HERESTRING,
        SHELL_TOKEN_PROCESS_SUB,
    };
    for (size_t i = 0; i < sizeof(syntax_types) / sizeof(syntax_types[0]);
         i++) {
      shell_token_t syntax = {
          .type = syntax_types[i], .start = "x", .length = 1, .position = 0};
      command = NULL;
      if (shell_transform_command(&(shell_command_t){.tokens = &syntax,
                                                     .token_count = 1,
                                                     .start_pos = 0,
                                                     .end_pos = 1},
                                  NULL, &command) != SHELL_TRANSFORM_OK ||
          !command || !command->has_shell_syntax)
        valid = false;
      shell_transformed_command_free(command);
    }
    transformed_limit.max_string_bytes = SIZE_MAX;
    transformed_limit.max_total_bytes = 1;
    command = (shell_transformed_command_t *)(uintptr_t)1;
    if (shell_transform_command(&(shell_command_t){.tokens = &first,
                                                   .token_count = 1,
                                                   .start_pos = 0,
                                                   .end_pos = 4},
                                &transformed_limit,
                                &command) != SHELL_TRANSFORM_EOUTPUT_LIMIT ||
        command != NULL)
      valid = false;
    if (shell_transformed_command_get_display_text(NULL) != NULL ||
        shell_transformed_command_has_transformations(NULL))
      valid = false;
    shell_transformed_command_free(NULL);
    test("Transform: failure contracts clear writable outputs", valid);
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

  static const feature_case_t stress_edge_cases[] = {
      {{"Edge: unclosed command substitution", "echo $(cmd", 1}, 0},
      {{"Edge: unclosed arithmetic expansion", "echo $((x+1)", 1}, 0},
      {{"Edge: empty quotes", "echo \"\" ''", 1}, 0},
      {{"Edge: mixed quote characters", "echo \"hello'world\"", 1}, 0},
      {{"Edge: trailing backslash", "echo hello\\", 1}, 0},
      {{"Edge: adjacent special variables", "echo $$$$$$", 1}, EXPECT_VARIABLE},
      {{"Edge: unclosed bracket glob", "ls file[", 1}, 0},
      {{"Edge: lone bracket glob", "ls [", 1}, 0},
      {{"Edge: unclosed negated bracket glob", "ls file[!", 1}, 0},
      {{"Edge: command substitution containing pipe",
        "echo $(cat file.txt | grep pattern)", 1},
       EXPECT_SUBSHELL},
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
       EXPECT_VARIABLE},
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
       EXPECT_VARIABLE},
      {{"Edge: adjacent quoted variables", "echo \"$VAR$VAR2${VAR3}\"", 1},
       EXPECT_VARIABLE},
      {{"Edge: variable followed by glob", "ls $DIR/*.txt", 1},
       EXPECT_VARIABLE | EXPECT_GLOB},
      {{"Edge: multiple glob forms", "ls *.txt *.log *.dat ??.* [abc]*.{cpp,h}",
        1},
       EXPECT_GLOB},
      {{"Edge: arithmetic operator family",
        "echo $((a+b)) $((c-d)) $((e*f)) $((g/h)) $((i%j)) $((k**l))", 1},
       EXPECT_ARITHMETIC},
      {{"Edge: nested bare parentheses", "(((echo hello)))", 1}, 0},
      {{"Edge: alternating quote forms", "echo 'a\"b\"c' \"d'e'e\"", 1}, 0},
      {{"Edge: variable followed by bracket glob", "ls $FILE[0-9]", 1},
       EXPECT_VARIABLE | EXPECT_GLOB},
      {{"Edge: all sequencing operators", "cmd1 && cmd2 || cmd3 | cmd4 ; cmd5",
        5},
       0},
      {{"Edge: redirect-only command", "< in.txt > out.txt", 1}, 0},
      {{"Stress: mixed-feature sequence",
        "cat ${FILE1} | grep -E '$PATTERN|${ALT}' | sort -u > ${OUTPUT}.txt && "
        "echo \"Done: $(wc -l < ${OUTPUT}.txt)\"",
        4},
       EXPECT_VARIABLE},
      {{"Stress: nested substitution containing features",
        "echo $(echo $(echo $VAR *.txt $((x+1))))", 1},
       EXPECT_SUBSHELL},
      {{"Edge: ordered descriptor duplication", "cmd > file.txt 2>&1 1>&2", 1},
       0},
      {{"Edge: heredoc-shaped multiline input", "cmd <<EOF\nhello\nEOF", 1}, 0},
      {{"Edge: substitution pipe followed by outer pipe",
        "cmd $(echo a | cat) | cmd2", 2},
       EXPECT_SUBSHELL},
      {{"Stress: all token feature classes",
        "cmd $VAR ${VAR} *.txt $((1+2)) $(cmd) `cmd` $1 | cmd2 < file.txt > "
        "out.txt 2>&1 && cmd3 || cmd4 ; cmd5",
        5},
       EXPECT_VARIABLE | EXPECT_GLOB | EXPECT_SUBSHELL | EXPECT_ARITHMETIC},
      {{"Edge: dash-leading command", "-n echo hello", 1}, 0},
      {{"Edge: escaped space", "echo hello\\ world", 1}, 0},
      {{"Edge: trailing semicolon", "echo hello ;", 1}, 0},
      {{"Edge: backslashes in double quotes", "echo \"path\\to\\file\"", 1}, 0},
      {{"Edge: newline in double quotes", "echo \"hello\nworld\"", 1}, 0},
      {{"Edge: unusual arithmetic parentheses", "echo $((x)) $((())) $(((x)))",
        1},
       EXPECT_ARITHMETIC},
      {{"Edge: command substitution containing semicolons",
        "echo $(cmd1; cmd2; cmd3)", 1},
       EXPECT_SUBSHELL},
  };
  run_feature_cases(stress_edge_cases,
                    sizeof(stress_edge_cases) / sizeof(stress_edge_cases[0]));

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
         result && count == 12 && tokens_are_consistent(input, cmds, count));
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
             tokens_are_consistent(input, cmds, count));
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
         result && count == 52 && tokens_are_consistent(input, cmds, count));
    shell_commands_free(cmds, count);
  }

  static const processor_case_t processor_cases[] = {
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
       {PROCESS_PIPE_OUTPUT, PROCESS_PIPE_INPUT},
       0x3},
      {"Processor: redirections",
       "cmd > output.txt 2>&1",
       1,
       {"cmd > output.txt 2>&1"},
       {"cmd"},
       {PROCESS_REDIRECTION | PROCESS_ERROR_REDIRECTION},
       0x1},
      {"Processor: combined redirect marks stderr",
       "cmd &> output.txt",
       1,
       {"cmd &> output.txt"},
       {"cmd"},
       {PROCESS_REDIRECTION | PROCESS_ERROR_REDIRECTION},
       0x1},
      {"Processor: combined append redirect marks stderr",
       "cmd &>> output.txt",
       1,
       {"cmd &>> output.txt"},
       {"cmd"},
       {PROCESS_REDIRECTION | PROCESS_ERROR_REDIRECTION},
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
       {PROCESS_PIPE_OUTPUT | PROCESS_REDIRECTION,
        PROCESS_PIPE_INPUT | PROCESS_REDIRECTION},
       0x3},
      {"Processor: descriptor duplication keeps following argument",
       "cmd 2>&1 arg",
       1,
       {"cmd 2>&1 arg"},
       {"cmd arg"},
       {PROCESS_REDIRECTION | PROCESS_ERROR_REDIRECTION},
       0x1},
      {"Processor: here-string operand is shell syntax",
       "cat <<< data",
       1,
       {"cat <<< data"},
       {"cat"},
       {PROCESS_REDIRECTION},
       0x1},
      {"Processor: heredoc body is shell syntax",
       "cat <<-'EOF'\n\t$LITERAL\n\tEOF",
       1,
       {"cat <<-'EOF'\n\t$LITERAL\n\tEOF"},
       {"cat"},
       {PROCESS_REDIRECTION},
       0x1},
      {"Processor: redirect-only stage has empty DFA input",
       "> output",
       1,
       {"> output"},
       {""},
       {PROCESS_REDIRECTION},
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
  run_processor_cases(processor_cases,
                      sizeof(processor_cases) / sizeof(processor_cases[0]));

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
        shell_process_command(NULL, 0, NULL, &infos, &count);
    bool process_valid =
        process_result != SHELL_PROCESS_OK && infos == NULL && count == 0;
    test("Processor: NULL input clears every writable output", process_valid);

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
    valid = valid &&
            shell_measure_decoded_word(NULL, 0, &measured) ==
                SHELL_PROCESS_EINPUT &&
            measured == 0 &&
            shell_write_decoded_word(word, strlen(word), NULL, 0, &written) ==
                SHELL_PROCESS_EINPUT &&
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
    decoded_word_capture_t capture = {
        .bytes = visited,
        .capacity = sizeof(visited),
    };
    size_t visited_length = 0;
    size_t measured = 0;
    size_t written = 0;
    bool valid =
        shell_visit_decoded_word(word, sizeof(word) - 1,
                                 capture_decoded_word_byte, &capture,
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
            shell_visit_decoded_word(word, sizeof(word) - 1,
                                     capture_decoded_word_byte, &capture,
                                     &visited_length) == SHELL_PROCESS_OK &&
            visited_length == 3 && memcmp(visited, expected, 3) == 0;
    test("Decoded-word visitor shares binary-safe syntax decoding", valid);
  }

  {
    const char *word = "quoted";
    char destination[sizeof("quoted")] = {0};
    char *owned = (char *)(uintptr_t)1;
    size_t length = SIZE_MAX;
    size_t written = SIZE_MAX;
    bool valid =
        shell_measure_decoded_word(word, strlen(word), NULL) ==
            SHELL_PROCESS_EINPUT &&
        shell_write_decoded_word(NULL, 0, destination, sizeof(destination),
                                 &written) == SHELL_PROCESS_EINPUT &&
        written == 0 &&
        shell_write_decoded_word(word, strlen(word), destination,
                                 sizeof(destination),
                                 NULL) == SHELL_PROCESS_EINPUT &&
        shell_decode_word(NULL, 0, &owned, &length) == SHELL_PROCESS_EINPUT &&
        owned == NULL && length == 0 &&
        shell_decode_word(word, strlen(word), NULL, &length) ==
            SHELL_PROCESS_EINPUT &&
        length == 0 &&
        shell_decode_word(word, strlen(word), &owned, NULL) ==
            SHELL_PROCESS_EINPUT &&
        owned == NULL;
    shellsplit_test_alloc_reset();
    shellsplit_test_alloc_fail_at(1);
    valid = valid &&
            shell_decode_word(word, strlen(word), &owned, &length) ==
                SHELL_PROCESS_ENOMEM &&
            owned == NULL && length == 0;
    shellsplit_test_alloc_reset();
    test("Decoded-word helpers reject invalid and exhausted storage", valid);
  }

  {
    shell_command_info_t *infos = NULL;
    size_t count = 0;
    shell_process_status_t rejected[] = {
        shell_process_command("echo", strlen("echo"), NULL, NULL, &count),
        shell_process_command("echo", strlen("echo"), NULL, &infos, NULL),
    };
    bool valid = !shell_command_info_has_dangerous_features(NULL);
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++)
      valid = valid && rejected[i] != SHELL_PROCESS_OK;
    test("Processor: NULL output and accessor contracts", valid);
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
    shell_processed_word_iterator_init(&iterator, NULL);
    bool valid =
        shell_processed_command_word_count(NULL) == 0 &&
        shell_processed_command_word_count(&command) == 3 &&
        !shell_processed_word_iterator_next(NULL, &command_word[3]) &&
        !shell_processed_word_iterator_next(&iterator, NULL) &&
        !shell_processed_word_iterator_next(&iterator, &command_word[3]) &&
        command_words && command_word[0].start == tokens[0].start &&
        command_word[1].start == tokens[4].start &&
        command_word[2].start == tokens[5].start &&
        shell_processed_command_word_count(&redirects) == 2 && redirect_words &&
        redirect_word[0].start == redirections[0].start &&
        redirect_word[1].start == redirections[10].start &&
        !shell_processed_command_has_dangerous_features(NULL, false) &&
        shell_processed_command_has_dangerous_features(&plain, true) &&
        shell_processed_command_has_dangerous_features(&command, false) &&
        shell_processed_command_has_dangerous_features(&nested_word, false) &&
        !shell_processed_command_has_dangerous_features(&only_words, false) &&
        !shell_processed_command_has_pipe_output(NULL) &&
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
    size_t measured = SIZE_MAX;
    char *netargv = (char *)(uintptr_t)1;
    shell_process_limits_t limits = {1, 1, 0};
    bool valid =
        shell_render_netargv(NULL, NULL, &netargv) == SHELL_PROCESS_EINPUT &&
        netargv == NULL &&
        shell_process_command("echo x", strlen("echo x"), NULL, &infos,
                              &count) == SHELL_PROCESS_OK &&
        count == 1 &&
        shell_measure_netargv(NULL, &measured) == SHELL_PROCESS_EINPUT &&
        measured == 0 &&
        shell_measure_netargv(&infos[0], NULL) == SHELL_PROCESS_EINPUT &&
        shell_render_netargv(&infos[0], NULL, NULL) == SHELL_PROCESS_EINPUT &&
        shell_render_netargv(&infos[0], &limits, &netargv) ==
            SHELL_PROCESS_EOUTPUT_LIMIT &&
        netargv == NULL;
    limits.max_string_bytes = SIZE_MAX;
    valid = valid &&
            shell_render_netargv(&infos[0], &limits, &netargv) ==
                SHELL_PROCESS_EOUTPUT_LIMIT &&
            netargv == NULL;
    shellsplit_test_alloc_reset();
    shellsplit_test_alloc_fail_at(1);
    valid = valid &&
            shell_render_netargv(&infos[0], NULL, &netargv) ==
                SHELL_PROCESS_ENOMEM &&
            netargv == NULL;
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
    char *allocated = NULL;
    valid =
        valid &&
        shell_measure_netargv(&infos[0], &length) == SHELL_PROCESS_OK &&
        length == strlen("6:printf,0:,9:two words,") &&
        length + 1 <= sizeof(exact) &&
        shell_write_netargv(&infos[0], exact, length + 1, &written) ==
            SHELL_PROCESS_OK &&
        written == length && strcmp(exact, "6:printf,0:,9:two words,") == 0 &&
        shell_write_netargv(&infos[0], short_buffer, length, &written) ==
            SHELL_PROCESS_EOUTPUT_LIMIT &&
        written == 0 && short_buffer[0] == (char)0xA5 &&
        shell_render_netargv(&infos[0], NULL, &allocated) == SHELL_PROCESS_OK &&
        strcmp(allocated, exact) == 0;
    free(allocated);
    shell_command_infos_free(infos, count);
    test("Netargv measure/write matches allocating renderer", valid);
  }

  printf("\n=== PIPELINE/SUBCOMMAND EXTRACTION TESTS ===\n\n");
#define STAGES(name, input, count, vars, globs, subs, arith)                   \
  {                                                                            \
    {name, input, count}, vars, globs, subs, arith                             \
  }
  static const stage_case_t pipeline_cases[] = {
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
  run_stage_cases(pipeline_cases,
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
             tokens_are_consistent(input, cmds, count));
    shell_commands_free(cmds, count);
  }

  static const feature_case_t compound_syntax_cases[] = {
      {{"Stress: nested command substitution (8 levels)",
        "echo $(echo $(echo $(echo $(echo $(echo $(echo $(echo hello)))))))",
        1},
       EXPECT_SUBSHELL},
      {{"Edge: process substitution", "diff <(cmd1) <(cmd2)", 1}, 0},
      {{"Edge: heredoc-shaped input", "cat <<EOF\nline1\nline2\nEOF", 1}, 0},
      {{"Edge: heredoc-shaped input with variable", "cat <<EOF\n$VAR\nEOF", 1},
       0},
      {{"Edge: double brackets", "[[ $var == \"test\" ]]", 1}, EXPECT_VARIABLE},
      {{"Edge: for loop", "for f in *.txt; do echo $f; done", 3},
       EXPECT_VARIABLE | EXPECT_GLOB | EXPECT_LOOP},
      {{"Edge: while loop", "while read line; do echo $line; done < file.txt",
        3},
       EXPECT_VARIABLE | EXPECT_LOOP},
      {{"Edge: case statement", "case $var in a) echo a;; esac", 1},
       EXPECT_VARIABLE | EXPECT_CASE},
      {{"Edge: conditional", "if [ -f file.txt ]; then echo exists; fi", 3},
       EXPECT_CONDITIONAL},
  };
  run_feature_cases(compound_syntax_cases,
                    sizeof(compound_syntax_cases) /
                        sizeof(compound_syntax_cases[0]));

  static const feature_case_t parameter_expansion_cases[] = {
      {{"Edge: array variable", "echo ${array[@]}", 1}, EXPECT_VARIABLE},
      {{"Edge: default parameter expansion", "echo ${VAR:-default}", 1},
       EXPECT_VARIABLE},
      {{"Edge: assignment parameter expansion", "echo ${VAR:=default}", 1},
       EXPECT_VARIABLE},
      {{"Edge: parameter length", "echo ${#VAR}", 1}, EXPECT_VARIABLE},
      {{"Edge: substring expansion", "echo ${VAR:0:5}", 1}, EXPECT_VARIABLE},
      {{"Edge: pattern removal", "echo ${VAR##*/}", 1}, EXPECT_VARIABLE},
      {{"Edge: pattern substitution", "echo ${VAR/pattern/replace}", 1},
       EXPECT_VARIABLE},
  };
  run_feature_cases(parameter_expansion_cases,
                    sizeof(parameter_expansion_cases) /
                        sizeof(parameter_expansion_cases[0]));

  static const tokenizer_case_t syntax_edge_cases[] = {
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
  run_tokenizer_cases(syntax_edge_cases,
                      sizeof(syntax_edge_cases) / sizeof(syntax_edge_cases[0]));

  static const feature_case_t syntax_feature_cases[] = {
      {{"Edge: backticks containing pipe", "echo `cat file.txt | grep pattern`",
        1},
       EXPECT_SUBSHELL},
      {{"Edge: variable followed by path suffix", "echo $PATH:/new/path", 1},
       EXPECT_VARIABLE},
      {{"Edge: variable embedded in double quotes", "echo \"Cost: $$100\"", 1},
       EXPECT_VARIABLE},
      {{"Edge: braced variable embedded in double quotes",
        "echo \"prefix ${VAR} suffix\"", 1},
       EXPECT_VARIABLE},
      {{"Edge: escaped dollar in double quotes", "echo \"Cost: \\$100\"", 1},
       0},
      {{"Edge: dollar in single quotes", "echo 'Cost: $100'", 1}, 0},
      {{"Edge: complex command substitution",
        "echo $(cat $FILE *.txt | grep $PATTERN | sort $((N+1)) )", 1},
       EXPECT_SUBSHELL},
      {{"Edge: local assignment sequence", "local x=5; echo $x", 2},
       EXPECT_VARIABLE},
  };
  run_feature_cases(syntax_feature_cases, sizeof(syntax_feature_cases) /
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
             tokens_are_consistent(input, cmds, count));
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
         token_counts_match && tokens_are_consistent(input, cmds, count));
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
             tokens_are_consistent(input, cmds, count));
    shell_commands_free(cmds, count);
  }

  /* --- PARSER REGRESSION TESTS --- */

  printf("\n=== PARSER REGRESSION TESTS ===\n\n");

  static const tokenizer_case_t invalid_input_cases[] = {
      {"Control character at start is rejected",
       "\x01"
       "cmd",
       0},
      {"Multiple leading control characters are rejected", "\x07\x1btext", 0},
      {"Raw high bytes are rejected",
       "\x80\x81"
       "cmd",
       0},
      {"Embedded control character is rejected", "cmd\x01suffix", 0},
      {"Embedded high byte is rejected", "cmd\x80suffix", 0},
      {"Quoted high byte is rejected", "echo '\x80'", 0},
      {"Bare separator is rejected", "|", 0},
  };
  run_rejected_cases(invalid_input_cases, sizeof(invalid_input_cases) /
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
         result && count == 1 && tokens_are_consistent(input, cmds, count));
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
         result && count == 1 && tokens_are_consistent(input, cmds, count));
    if (cmds)
      shell_commands_free(cmds, count);
  }

  // Test 219: Double 'then' keyword - complex case requires full grammar
  // parsing For fast tokenizer, we only detect at command start, nested is
  // flagged
  {
    const char *input = "if true; then then cmd; fi";
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = (shell_tokenize_commands(input, strlen(input), &cmds,
                                          &count) == SHELL_TOKENIZE_OK);
    // This is a complex case - fast tokenizer may not catch nested "then then"
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

    shell_tokenizer_init(&state, input, strlen(input));
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
    char *netargv = NULL;
    shell_process_status_t status = shell_process_command(
        "printf '' foo\"bar\" 'two words' '>'",
        strlen("printf '' foo\"bar\" 'two words' '>'"), NULL, &infos, &count);
    if (status == SHELL_PROCESS_OK && count == 1)
      status = shell_render_netargv(&infos[0], NULL, &netargv);
    bool valid = status == SHELL_PROCESS_OK && count == 1 && netargv &&
                 strcmp(netargv, "6:printf,0:,6:foobar,9:two words,1:>,") == 0;
    test("Netargv rendering preserves exact argument boundaries", valid);
    free(netargv);
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
      char *netargv = NULL;
      char *sequence = NULL;
      size_t sequence_count = 0;
      bool features = false;
      shell_process_status_t status =
          shell_process_command(cases[i].command, strlen(cases[i].command),
                                NULL, &infos, &info_count);
      if (status == SHELL_PROCESS_OK && info_count == 1)
        status = shell_render_netargv(&infos[0], NULL, &netargv);
      shell_process_status_t sequence_status = shell_build_netargv_sequence(
          cases[i].command, strlen(cases[i].command), NULL, &sequence,
          &sequence_count, &features);
      valid = valid && status == SHELL_PROCESS_OK && info_count == 1 &&
              netargv && strcmp(netargv, cases[i].netargv) == 0 &&
              sequence_status == SHELL_PROCESS_OK && sequence_count == 1 &&
              sequence && strcmp(sequence, cases[i].sequence) == 0 &&
              features == cases[i].has_executable_substitution;
      free(sequence);
      free(netargv);
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
    char *sequence = NULL;
    size_t count = 0;
    bool features = false;
    shell_process_status_t status = shell_build_netargv_sequence(
        "printf '' 'two words'; cd '/tmp path'",
        strlen("printf '' 'two words'; cd '/tmp path'"), NULL, &sequence,
        &count, &features);
    bool valid =
        status == SHELL_PROCESS_OK && count == 2 && features && sequence &&
        strcmp(sequence, "24:6:printf,0:,9:two words,,17:2:cd,9:/tmp path,,") ==
            0;
    test("Nested netargv sequence preserves subcommand boundaries", valid);
    free(sequence);

    char *command_netseq = NULL;
    char *type_netseq = NULL;
    char *expected_command_netseq = NULL;
    char *expected_type_netseq = NULL;
    size_t paired_count = 0;
    valid =
        shell_build_anomaly_netseqs(
            "printf '' 'two words'; cd '/tmp path'",
            strlen("printf '' 'two words'; cd '/tmp path'"), NULL,
            &command_netseq, &type_netseq, &paired_count) == SHELL_PROCESS_OK &&
        shell_build_command_netseq(
            "printf '' 'two words'; cd '/tmp path'",
            strlen("printf '' 'two words'; cd '/tmp path'"), NULL,
            &expected_command_netseq, &count) == SHELL_PROCESS_OK &&
        shell_build_type_netseq("printf '' 'two words'; cd '/tmp path'",
                                strlen("printf '' 'two words'; cd '/tmp path'"),
                                NULL, &expected_type_netseq,
                                &count) == SHELL_PROCESS_OK &&
        paired_count == 2 && command_netseq && type_netseq &&
        strcmp(command_netseq, expected_command_netseq) == 0 &&
        strcmp(type_netseq, expected_type_netseq) == 0;
    test("Paired anomaly netsequences share canonical command boundaries",
         valid);
    free(expected_type_netseq);
    free(expected_command_netseq);
    free(type_netseq);
    free(command_netseq);

    command_netseq = (char *)(uintptr_t)1;
    type_netseq = (char *)(uintptr_t)1;
    paired_count = SIZE_MAX;
    valid = shell_build_anomaly_netseqs(NULL, 0, NULL, &command_netseq,
                                        &type_netseq, &paired_count) ==
                SHELL_PROCESS_EINPUT &&
            command_netseq == NULL && type_netseq == NULL && paired_count == 0;
    shell_process_limits_t pair_limits = {SIZE_MAX, 8, 0};
    valid = valid &&
            shell_build_anomaly_netseqs(
                "echo x", strlen("echo x"), &pair_limits, &command_netseq,
                &type_netseq, &paired_count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
            command_netseq == NULL && type_netseq == NULL && paired_count == 0;
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
      command_netseq = NULL;
      type_netseq = NULL;
      expected_command_netseq = NULL;
      expected_type_netseq = NULL;
      paired_count = 0;
      size_t command_count = 0;
      size_t type_count = 0;
      valid = valid &&
              shell_build_anomaly_netseqs(input, strlen(input), NULL,
                                          &command_netseq, &type_netseq,
                                          &paired_count) == SHELL_PROCESS_OK &&
              shell_build_command_netseq(input, strlen(input), NULL,
                                         &expected_command_netseq,
                                         &command_count) == SHELL_PROCESS_OK &&
              shell_build_type_netseq(input, strlen(input), NULL,
                                      &expected_type_netseq,
                                      &type_count) == SHELL_PROCESS_OK &&
              paired_count == command_count && paired_count == type_count &&
              strcmp(command_netseq, expected_command_netseq) == 0 &&
              strcmp(type_netseq, expected_type_netseq) == 0;
      free(expected_type_netseq);
      free(expected_command_netseq);
      free(type_netseq);
      free(command_netseq);
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
        {"my\\\r\ncommand value", "9:mycommand,", "18:9:mycommand,3:STR,,", 1},
    };
    valid = true;
    for (size_t i = 0;
         i < sizeof(compound_signatures) / sizeof(compound_signatures[0]);
         i++) {
      command_netseq = NULL;
      type_netseq = NULL;
      paired_count = 0;
      const char *input = compound_signatures[i].input;
      valid = valid &&
              shell_build_anomaly_netseqs(input, strlen(input), NULL,
                                          &command_netseq, &type_netseq,
                                          &paired_count) == SHELL_PROCESS_OK &&
              paired_count == compound_signatures[i].stage_count &&
              command_netseq && type_netseq &&
              strcmp(command_netseq, compound_signatures[i].raw) == 0 &&
              strcmp(type_netseq, compound_signatures[i].typed) == 0;
      free(type_netseq);
      free(command_netseq);
    }
    test("Compound argv words retain aligned anomaly signatures", valid);

    command_netseq = (char *)(uintptr_t)1;
    type_netseq = (char *)(uintptr_t)1;
    paired_count = SIZE_MAX;
    valid = shell_build_anomaly_netseqs(
                "'' x", strlen("'' x"), NULL, &command_netseq, &type_netseq,
                &paired_count) == SHELL_PROCESS_EPARSE &&
            command_netseq == NULL && type_netseq == NULL && paired_count == 0;
    command_netseq = (char *)(uintptr_t)1;
    type_netseq = (char *)(uintptr_t)1;
    paired_count = SIZE_MAX;
    valid =
        valid &&
        shell_build_anomaly_netseqs("\x01"
                                    "bad",
                                    strlen("\x01"
                                           "bad"),
                                    NULL, &command_netseq, &type_netseq,
                                    &paired_count) == SHELL_PROCESS_EINPUT &&
        command_netseq == NULL && type_netseq == NULL && paired_count == 0;
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
    };
    for (size_t input_index = 0;
         valid &&
         input_index < sizeof(allocation_inputs) / sizeof(allocation_inputs[0]);
         input_index++) {
      pair_completed = false;
      for (size_t fail_at = 1; fail_at < 128; fail_at++) {
        shellsplit_test_alloc_reset();
        shellsplit_test_alloc_fail_at(fail_at);
        command_netseq = (char *)(uintptr_t)1;
        type_netseq = (char *)(uintptr_t)1;
        paired_count = SIZE_MAX;
        status = shell_build_anomaly_netseqs(
            allocation_inputs[input_index],
            strlen(allocation_inputs[input_index]), NULL, &command_netseq,
            &type_netseq, &paired_count);
        if (status == SHELL_PROCESS_OK) {
          pair_completed = true;
          free(type_netseq);
          free(command_netseq);
          break;
        }
        valid = valid && status == SHELL_PROCESS_ENOMEM &&
                command_netseq == NULL && type_netseq == NULL &&
                paired_count == 0;
      }
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

    sequence = (char *)1;
    count = 99;
    features = true;
    valid = shell_build_netargv_sequence(NULL, 0, NULL, &sequence, &count,
                                         &features) == SHELL_PROCESS_EINPUT &&
            sequence == NULL && count == 0 && !features;
    test("Nested netargv sequence rejects invalid input atomically", valid);

    valid = shell_build_netargv_sequence("echo x", strlen("echo x"), NULL, NULL,
                                         &count,
                                         &features) == SHELL_PROCESS_EINPUT &&
            count == 0 && !features;
    valid = valid &&
            shell_build_netargv_sequence("echo x", strlen("echo x"), NULL,
                                         &sequence, NULL,
                                         &features) == SHELL_PROCESS_EINPUT &&
            sequence == NULL && !features;
    valid = valid &&
            shell_build_netargv_sequence("echo x", strlen("echo x"), NULL,
                                         &sequence, &count,
                                         NULL) == SHELL_PROCESS_EINPUT &&
            sequence == NULL && count == 0;
    test("Nested netargv sequence validates every output", valid);

    sequence = (char *)(uintptr_t)1;
    count = SIZE_MAX;
    features = true;
    valid = shell_build_netargv_sequence("\x01"
                                         "bad",
                                         strlen("\x01"
                                                "bad"),
                                         NULL, &sequence, &count,
                                         &features) == SHELL_PROCESS_EINPUT &&
            sequence == NULL && count == 0 && !features;
    test("Nested netargv sequence propagates parser failures atomically",
         valid);

    shell_process_limits_t limits = {SIZE_MAX, SIZE_MAX, 0};
    limits.max_string_bytes = 1;
    features = true;
    valid = shell_build_netargv_sequence("echo x", strlen("echo x"), &limits,
                                         &sequence, &count, &features) ==
                SHELL_PROCESS_EOUTPUT_LIMIT &&
            sequence == NULL && count == 0 && !features;
    test("Nested netargv sequence enforces its outer output limit", valid);

    limits = (shell_process_limits_t){SIZE_MAX, 10, 0};
    valid = shell_build_netargv_sequence("echo x", strlen("echo x"), &limits,
                                         &sequence, &count, &features) ==
                SHELL_PROCESS_EOUTPUT_LIMIT &&
            sequence == NULL && count == 0 && !features;
    test("Nested netargv sequence checks its post-processing size", valid);

    valid = true;
    bool completed = false;
    for (size_t fail_at = 1; fail_at < 32; fail_at++) {
      shellsplit_test_alloc_reset();
      shellsplit_test_alloc_fail_at(fail_at);
      sequence = (char *)(uintptr_t)1;
      count = SIZE_MAX;
      features = true;
      status = shell_build_netargv_sequence("echo x", strlen("echo x"), NULL,
                                            &sequence, &count, &features);
      if (status == SHELL_PROCESS_OK) {
        completed = true;
        free(sequence);
        break;
      }
      valid = valid && status == SHELL_PROCESS_ENOMEM && sequence == NULL &&
              count == 0 && !features;
    }
    shellsplit_test_alloc_reset();
    test("Nested netargv sequence is failure-atomic at every allocation",
         valid && completed);

    sequence = NULL;
    count = 0;
    valid =
        shell_build_command_netseq("'my tool' one two; printf x",
                                   strlen("'my tool' one two; printf x"), NULL,
                                   &sequence, &count) == SHELL_PROCESS_OK &&
        count == 2 && sequence && strcmp(sequence, "7:my tool,6:printf,") == 0;
    test("Command netsequence records executables rather than arguments",
         valid);
    free(sequence);

    valid = shell_build_command_netseq("echo x", strlen("echo x"), NULL, NULL,
                                       &count) == SHELL_PROCESS_EINPUT &&
            count == 0;
    valid =
        valid &&
        shell_build_command_netseq("echo x", strlen("echo x"), NULL, &sequence,
                                   NULL) == SHELL_PROCESS_EINPUT &&
        sequence == NULL;
    limits = (shell_process_limits_t){SIZE_MAX, SIZE_MAX, 0};
    limits.max_total_bytes = 1;
    valid = valid &&
            shell_build_command_netseq("echo x", strlen("echo x"), &limits,
                                       &sequence,
                                       &count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
            sequence == NULL && count == 0;
    test("Command netsequence validates outputs and limits", valid);

    limits = (shell_process_limits_t){SIZE_MAX, 6, 0};
    valid = shell_build_command_netseq("echo x", strlen("echo x"), &limits,
                                       &sequence,
                                       &count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
            sequence == NULL && count == 0;
    test("Command netsequence checks its encoded size", valid);

    sequence = (char *)(uintptr_t)1;
    count = SIZE_MAX;
    valid = shell_build_command_netseq("\x01"
                                       "bad",
                                       strlen("\x01"
                                              "bad"),
                                       NULL, &sequence,
                                       &count) == SHELL_PROCESS_EINPUT &&
            sequence == NULL && count == 0;
    test("Command netsequence propagates parser failures atomically", valid);

    valid = true;
    completed = false;
    for (size_t fail_at = 1; fail_at < 32; fail_at++) {
      shellsplit_test_alloc_reset();
      shellsplit_test_alloc_fail_at(fail_at);
      sequence = (char *)(uintptr_t)1;
      count = SIZE_MAX;
      status = shell_build_command_netseq("echo x", strlen("echo x"), NULL,
                                          &sequence, &count);
      if (status == SHELL_PROCESS_OK) {
        completed = true;
        free(sequence);
        break;
      }
      valid = valid && status == SHELL_PROCESS_ENOMEM && sequence == NULL &&
              count == 0;
    }
    shellsplit_test_alloc_reset();
    test("Command netsequence is failure-atomic at every allocation",
         valid && completed);
  }

  printf("\n=== SUMMARY ===\n");
  printf("Results: %d/%d passed\n", pass_count, test_count);
  return (pass_count == test_count) ? 0 : 1;
}
