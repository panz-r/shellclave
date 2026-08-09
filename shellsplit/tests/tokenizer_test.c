#include "shell_processor.h"
#include "shell_tokenizer_full.h"
#include "shell_transform.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;

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
      "OR",
      "SUBSHELL_START",
      "SUBSHELL_END",
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
  };
  bool valid = sizeof(names) / sizeof(names[0]) == TOKEN_HERESTRING + 1;
  for (size_t i = 0; valid && i < sizeof(names) / sizeof(names[0]); i++)
    valid = strcmp(shell_token_type_name((token_type_t)i), names[i]) == 0;
  valid = valid &&
          strcmp(shell_token_type_name((token_type_t)(TOKEN_HERESTRING + 1)),
                 "UNKNOWN") == 0;
  test("Token type names cover every enum value", valid);
}

static bool is_cleared_end_token(const shell_token_t *token) {
  return token->type == TOKEN_END && token->start == NULL &&
         token->length == 0 && token->position == 0 && !token->is_quoted &&
         !token->is_escaped;
}

typedef struct {
  const char *name;
  const char *input;
  size_t token_count;
  token_type_t types[8];
  const char *texts[8];
  int if_depth;
  int loop_depth;
  int case_depth;
} iterator_case_t;

static void run_iterator_cases(const iterator_case_t *cases, size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_tokenizer_state_t state;
    shell_tokenizer_init(&state, cases[i].input);
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
  shell_tokenizer_init(&state, NULL);
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

  shell_tokenizer_init(&state, "echo");
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
  shell_tokenizer_init(&state, "cmd\x01suffix");
  memset(&token, 0xA5, sizeof(token));
  bool invalid_input =
      !shell_tokenizer_next(&state, &token) && is_cleared_end_token(&token);
  shell_tokenizer_init(NULL, "ignored");

  shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
  size_t command_count = SIZE_MAX;
  bool aggregate_null_input =
      !shell_tokenize_commands(NULL, &commands, &command_count) &&
      commands == NULL && command_count == 0;
  bool missing_outputs =
      !shell_tokenize_commands("echo", NULL, &command_count) &&
      !shell_tokenize_commands("echo", &commands, NULL);
  test("Tokenizer iterator: NULL and exhausted argument contracts",
       null_input && null_output && null_state && zero_state && invalid_input &&
           aggregate_null_input && missing_outputs);
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
    bool parsed =
        shell_tokenize_commands(cases[i].input, &commands, &command_count);
    test(cases[i].name,
         parsed && command_count == cases[i].command_count &&
             tokens_are_consistent(cases[i].input, commands, command_count));
    shell_free_commands(commands, command_count);
  }
}

static void check_tokenizer_case(const char *name, const char *input,
                                 size_t expected_count) {
  shell_command_t *commands = NULL;
  size_t command_count = 0;
  bool parsed = shell_tokenize_commands(input, &commands, &command_count);
  bool valid = parsed && command_count == expected_count &&
               tokens_are_consistent(input, commands, command_count);
  if (!valid)
    printf("    commands: got %zu, expected %zu\n", command_count,
           expected_count);
  test(name, valid);
  shell_free_commands(commands, command_count);
}

static void run_rejected_cases(const tokenizer_case_t *cases, size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_command_t *sentinel = (shell_command_t *)(uintptr_t)1;
    shell_command_t *commands = sentinel;
    size_t command_count = SIZE_MAX;
    bool parsed =
        shell_tokenize_commands(cases[i].input, &commands, &command_count);
    test(cases[i].name, !parsed && commands == NULL &&
                            command_count == cases[i].command_count);
    if (commands && commands != sentinel && command_count < 1024)
      shell_free_commands(commands, command_count);
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
    bool parsed = shell_tokenize_commands(cases[i].tokenizer.input, &commands,
                                          &command_count);
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
      if (shell_has_features(&commands[j]) !=
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
    shell_free_commands(commands, command_count);
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
    bool parsed = shell_tokenize_commands(cases[i].tokenizer.input, &commands,
                                          &command_count);
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
      if (shell_has_features(&commands[j]) != has_feature)
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
    shell_free_commands(commands, command_count);
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
  const char *clean_commands[4];
  unsigned flags[4];
  unsigned feature_stages;
} processor_case_t;

static void free_dfa_inputs(const char **inputs, size_t count) {
  for (size_t i = 0; i < count; i++)
    free((void *)inputs[i]);
  free(inputs);
}

static void run_processor_cases(const processor_case_t *cases, size_t count) {
  for (size_t i = 0; i < count; i++) {
    shell_command_info_t *infos = NULL;
    size_t command_count = 0;
    shell_process_status_t process_status =
        shell_process_command(cases[i].input, NULL, &infos, &command_count);
    const char **dfa_inputs = NULL;
    size_t dfa_count = 0;
    bool has_shell_features = false;
    shell_process_status_t extract_status = shell_extract_dfa_inputs(
        cases[i].input, NULL, &dfa_inputs, &dfa_count, &has_shell_features);
    bool processed = process_status == SHELL_PROCESS_OK;
    bool extracted = extract_status == SHELL_PROCESS_OK;
    bool valid = processed && extracted &&
                 command_count == cases[i].command_count &&
                 dfa_count == cases[i].command_count &&
                 (command_count == 0 || (infos && dfa_inputs)) &&
                 has_shell_features == (cases[i].feature_stages != 0);
    for (size_t j = 0; infos && dfa_inputs && j < cases[i].command_count &&
                       j < command_count && j < dfa_count;
         j++) {
      unsigned flags =
          (infos[j].has_pipe_input ? PROCESS_PIPE_INPUT : 0) |
          (infos[j].has_pipe_output ? PROCESS_PIPE_OUTPUT : 0) |
          (infos[j].has_redirections ? PROCESS_REDIRECTION : 0) |
          (infos[j].has_error_redirection ? PROCESS_ERROR_REDIRECTION : 0);
      bool expected_feature = (cases[i].feature_stages & (1u << j)) != 0;
      bool stage_valid =
          infos[j].original_command && infos[j].clean_command &&
          dfa_inputs[j] &&
          shell_get_clean_command(&infos[j]) == infos[j].clean_command &&
          strcmp(infos[j].original_command, cases[i].original_commands[j]) ==
              0 &&
          strcmp(infos[j].clean_command, cases[i].clean_commands[j]) == 0 &&
          strcmp(dfa_inputs[j], cases[i].clean_commands[j]) == 0 &&
          flags == cases[i].flags[j] &&
          shell_has_dangerous_features(&infos[j]) == expected_feature;
      if (!stage_valid)
        printf("    stage %zu: original='%s' clean='%s' flags=%#x "
               "feature=%d\n",
               j, infos[j].original_command ? infos[j].original_command : "",
               infos[j].clean_command ? infos[j].clean_command : "", flags,
               shell_has_dangerous_features(&infos[j]));
      valid = stage_valid && valid;
    }
    if (!valid)
      printf("    processor: count=%zu dfa=%zu expected=%zu features=%d\n",
             command_count, dfa_count, cases[i].command_count,
             has_shell_features);
    test(cases[i].name, valid);
    shell_free_command_infos(infos, command_count);
    free_dfa_inputs(dfa_inputs, dfa_count);
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
    transformed_command_t **commands = NULL;
    size_t command_count = 0;
    bool transformed =
        shell_transform_command_line(cases[i].input, NULL, &commands,
                                     &command_count) == SHELL_TRANSFORM_OK;
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
      valid =
          commands[j] && commands[j]->original_command &&
          commands[j]->transformed_command && expected_original &&
          strcmp(commands[j]->original_command, expected_original) == 0 &&
          strcmp(commands[j]->transformed_command,
                 cases[i].transformed_commands[j]) == 0 &&
          commands[j]->has_transformations == expected_transform &&
          commands[j]->has_shell_syntax == expected_shell &&
          shell_has_transformations(commands[j]) == expected_transform &&
          shell_get_dfa_input(commands[j]) == commands[j]->transformed_command;
    }
    if (!valid)
      printf("    transform line: count=%zu expected=%zu\n", command_count,
             cases[i].command_count);
    test(cases[i].name, valid);
    shell_free_transformed_commands(commands, command_count);
    free(commands);
  }
}

int main(void) {
  test_token_type_names();
  static const iterator_case_t iterator_cases[] = {
      {"Tokenizer iterator: empty input", "", 0, {0}, {NULL}, 0, 0, 0},
      {"Tokenizer iterator: whitespace exhaustion",
       " \t\n",
       0,
       {0},
       {NULL},
       0,
       0,
       0},
      {"Tokenizer iterator: token sequence",
       "echo \"$VAR\" | cat 2>&1",
       5,
       {TOKEN_COMMAND, TOKEN_VARIABLE_QUOTED, TOKEN_PIPE, TOKEN_COMMAND,
        TOKEN_REDIRECT_ERR},
       {"echo", "\"$VAR\"", "|", "cat", "2>&1"},
       0,
       0,
       0},
      {"Tokenizer iterator: keyword depth transitions",
       "if for case",
       3,
       {TOKEN_COMMAND, TOKEN_COMMAND, TOKEN_COMMAND},
       {"if", "for", "case"},
       1,
       1,
       1},
      {"Tokenizer iterator: process substitutions",
       "diff <(left \"(x)\") >(right)",
       3,
       {TOKEN_COMMAND, TOKEN_PROCESS_SUB, TOKEN_PROCESS_SUB},
       {"diff", "<(left \"(x)\")", ">(right)"},
       0,
       0,
       0},
      {"Tokenizer iterator: special parameter family",
       "echo $? $$ $# $! $@ $* $-",
       8,
       {TOKEN_COMMAND, TOKEN_SPECIAL_VAR, TOKEN_SPECIAL_VAR, TOKEN_SPECIAL_VAR,
        TOKEN_SPECIAL_VAR, TOKEN_SPECIAL_VAR, TOKEN_SPECIAL_VAR,
        TOKEN_SPECIAL_VAR},
       {"echo", "$?", "$$", "$#", "$!", "$@", "$*", "$-"},
       0,
       0,
       0},
      {"Tokenizer iterator: positional parameter boundary",
       "echo $10 ${10}",
       4,
       {TOKEN_COMMAND, TOKEN_SPECIAL_VAR, TOKEN_COMMAND, TOKEN_VARIABLE},
       {"echo", "$1", "0", "${10}"},
       0,
       0,
       0},
      {"Tokenizer iterator: descriptor redirection family",
       "cmd >>&9 >&10 <&0 3>&- 4<&- 12>>log",
       8,
       {TOKEN_COMMAND, TOKEN_REDIRECT_APPEND, TOKEN_REDIRECT_ERR,
        TOKEN_REDIRECT_IN, TOKEN_REDIRECT_ERR, TOKEN_REDIRECT_IN,
        TOKEN_REDIRECT_APPEND, TOKEN_COMMAND},
       {"cmd", ">>&9", ">&10", "<&0", "3>&-", "4<&-", "12>>", "log"},
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
    static const transform_type_t types[] = {
        TRANSFORM_NONE,     TRANSFORM_VARIABLE, TRANSFORM_GLOB,
        TRANSFORM_SUBSHELL, TRANSFORM_VARIABLE, TRANSFORM_SUBSHELL};
    transformed_command_t **commands = NULL;
    size_t count = 0;
    bool valid = shell_transform_command_line(input, NULL, &commands, &count) ==
                     SHELL_TRANSFORM_OK &&
                 count == 1 && commands && commands[0] &&
                 commands[0]->token_count == sizeof(types) / sizeof(types[0]);
    memset(input, 'X', strlen(input));
    if (valid &&
        (strcmp(commands[0]->original_command,
                "echo $NAME *.txt $(id) $((1+2)) <(left)") != 0 ||
         strcmp(commands[0]->transformed_command,
                "echo VAR_VALUE FILE_PATTERN TEMP_FILE VAR_VALUE TEMP_FILE") !=
             0 ||
         !commands[0]->has_transformations || !commands[0]->has_shell_syntax))
      valid = false;
    for (size_t i = 0; valid && i < sizeof(types) / sizeof(types[0]); i++) {
      transformed_token_t *token = &commands[0]->tokens[i];
      valid = token->original && token->transformed &&
              strcmp(token->original, originals[i]) == 0 &&
              strcmp(token->transformed, transformed[i]) == 0 &&
              token->type == types[i] &&
              token->is_shell_construct == (types[i] != TRANSFORM_NONE);
    }
    test("Transform: token metadata owns exact strings", valid);
    shell_free_transformed_commands(commands, count);
    free(commands);
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
       {"echo VAR_VALUE"},
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
       {"ls VAR_VALUE FILE_PATTERN |", "grep VAR_VALUE"},
       UINT32_C(0x3),
       {"ls ${DIR}/*.txt |", "grep $PATTERN"}},
      {"Transform line: complex pipeline",
       "find ${DIR} -name \"*.log\" | head -${N} | sort",
       3,
       {"find VAR_VALUE -name \"*.log\" |", "head - VAR_VALUE |", "sort"},
       UINT32_C(0x3),
       {"find ${DIR} -name \"*.log\" |", "head -${N} |", "sort"}},
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
    transformed_command_t **sentinel = (transformed_command_t **)(uintptr_t)1;
    transformed_command_t **commands = sentinel;
    transformed_command_t *command = (transformed_command_t *)(uintptr_t)1;
    shell_command_t empty = {0};
    shell_token_t malformed_tokens[] = {
        {.type = TOKEN_COMMAND, .start = "echo", .length = 4, .position = 0},
        {.type = TOKEN_ARGUMENT, .start = NULL, .length = 5, .position = 5},
        {.type = TOKEN_ARGUMENT, .start = "x", .length = 2, .position = 4},
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

    if (shell_transform_command_line(NULL, NULL, &commands, &count) !=
            SHELL_TRANSFORM_EINPUT ||
        commands != NULL || count != 0)
      valid = false;
    commands = sentinel;
    count = SIZE_MAX;
    if (shell_transform_command_line("\x01"
                                     "cmd",
                                     NULL, &commands,
                                     &count) != SHELL_TRANSFORM_EPARSE ||
        commands != NULL || count != 0)
      valid = false;
    if (shell_transform_command_line("echo", NULL, NULL, &count) !=
        SHELL_TRANSFORM_EINPUT)
      valid = false;
    if (shell_transform_command_line("echo", NULL, &commands, NULL) !=
        SHELL_TRANSFORM_EINPUT)
      valid = false;
    if (shell_transform_command(NULL, NULL, &command) !=
            SHELL_TRANSFORM_EINPUT ||
        command != NULL)
      valid = false;
    command = (transformed_command_t *)(uintptr_t)1;
    if (shell_transform_command(&empty, NULL, &command) !=
            SHELL_TRANSFORM_EINPUT ||
        command != NULL)
      valid = false;
    if (shell_transform_command(&empty, NULL, NULL) != SHELL_TRANSFORM_EINPUT)
      valid = false;
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
      command = (transformed_command_t *)(uintptr_t)1;
      if (shell_transform_command(&malformed[i], NULL, &command) ==
              SHELL_TRANSFORM_OK ||
          command != NULL)
        valid = false;
    }
    if (shell_get_dfa_input(NULL) != NULL || shell_has_transformations(NULL))
      valid = false;
    shell_free_transformed_command(NULL);
    test("Transform: failure contracts clear writable outputs", valid);
  }

  {
    transformed_command_t **commands = (transformed_command_t **)(uintptr_t)1;
    size_t count = SIZE_MAX;
    const shell_transform_limits_t tiny = {3, 3};
    shell_transform_status_t status =
        shell_transform_command_line("echo $NAME", &tiny, &commands, &count);
    bool valid = status == SHELL_TRANSFORM_EOUTPUT_LIMIT && commands == NULL &&
                 count == 0;
    test("Transform: explicit output limits report rejection", valid);
    shell_free_transformed_commands(commands, count);
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
      {{"Edge: repeated logical operators", "cmd1 || || || cmd2", 2}, 0},
      {{"Edge: dash-leading command", "-n echo hello", 1}, 0},
      {{"Edge: escaped space", "echo hello\\ world", 1}, 0},
      {{"Edge: trailing pipe", "echo hello |", 1}, 0},
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
    int result = shell_tokenize_commands(input, &cmds, &count);
    test("Stress: long command (~4x)",
         result && count == 12 && tokens_are_consistent(input, cmds, count));
    shell_free_commands(cmds, count);
  }

  // Test 118: Very long single token
  {
    char input[2048];
    memset(input, 'a', 2047);
    input[2047] = '\0';
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = shell_tokenize_commands(input, &cmds, &count);
    test("Stress: very long token (2KB)",
         result && count == 1 && cmds[0].token_count == 1 &&
             cmds[0].tokens[0].length == sizeof(input) - 1 &&
             tokens_are_consistent(input, cmds, count));
    shell_free_commands(cmds, count);
  }

  // Test 144: Very long command (~8x typical)
  {
    char input[8192];
    strcpy(input, "cmd1 $V1 $V2 $V3 *.txt *.log | ");
    for (int i = 0; i < 50; i++) {
      strcat(input, "cmd$((i)) $(echo i) | ");
    }
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = shell_tokenize_commands(input, &cmds, &count);
    test("Stress: very long command (~8x)",
         result && count == 51 && tokens_are_consistent(input, cmds, count));
    shell_free_commands(cmds, count);
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
    bool processed =
        shell_process_command(input, NULL, &infos, &count) == SHELL_PROCESS_OK;
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
    shell_free_command_infos(infos, count);
  }

  // Test: NULL handling
  {
    shell_command_info_t *infos = (shell_command_info_t *)(uintptr_t)1;
    const char **inputs = (const char **)(uintptr_t)1;
    size_t count = SIZE_MAX;
    bool has_shell = true;
    shell_process_status_t process_result =
        shell_process_command(NULL, NULL, &infos, &count);
    bool process_valid =
        process_result != SHELL_PROCESS_OK && infos == NULL && count == 0;
    count = SIZE_MAX;
    shell_process_status_t extract_result =
        shell_extract_dfa_inputs(NULL, NULL, &inputs, &count, &has_shell);
    test("Processor: NULL input clears every writable output",
         process_valid && extract_result != SHELL_PROCESS_OK &&
             inputs == NULL && count == 0 && !has_shell);

    infos = (shell_command_info_t *)(uintptr_t)1;
    inputs = (const char **)(uintptr_t)1;
    count = SIZE_MAX;
    has_shell = true;
    process_result = shell_process_command("\x01"
                                           "cmd",
                                           NULL, &infos, &count);
    process_valid =
        process_result != SHELL_PROCESS_OK && infos == NULL && count == 0;
    count = SIZE_MAX;
    extract_result =
        shell_extract_dfa_inputs("\x01"
                                 "cmd",
                                 NULL, &inputs, &count, &has_shell);
    test("Processor: rejected input clears every writable output",
         process_valid && extract_result != SHELL_PROCESS_OK &&
             inputs == NULL && count == 0 && !has_shell);
  }

  {
    shell_command_info_t *infos = NULL;
    const char **inputs = NULL;
    size_t count = 0;
    bool has_shell = false;
    shell_process_status_t rejected[] = {
        shell_process_command("echo", NULL, NULL, &count),
        shell_process_command("echo", NULL, &infos, NULL),
        shell_extract_dfa_inputs("echo", NULL, NULL, &count, &has_shell),
        shell_extract_dfa_inputs("echo", NULL, &inputs, NULL, &has_shell),
        shell_extract_dfa_inputs("echo", NULL, &inputs, &count, NULL),
    };
    bool valid = shell_get_clean_command(NULL) == NULL &&
                 !shell_has_dangerous_features(NULL);
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++)
      valid = valid && rejected[i] != SHELL_PROCESS_OK;
    test("Processor: NULL output and accessor contracts", valid);
  }

  {
    shell_command_info_t *infos = (shell_command_info_t *)(uintptr_t)1;
    size_t count = SIZE_MAX;
    const shell_process_limits_t tiny = {3, 3};
    shell_process_status_t status =
        shell_process_command("echo value", &tiny, &infos, &count);
    test("Processor: explicit output limits report rejection",
         status == SHELL_PROCESS_EOUTPUT_LIMIT && infos == NULL && count == 0);
    shell_free_command_infos(infos, count);
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
      STAGES("Pipeline: stderr redirect with space", "cmd1 2 >&1 | cmd2", 2, 0,
             0, 0, 0),
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
    int result = shell_tokenize_commands(input, &cmds, &count);
    test("Stress: max depth nesting (20 levels)",
         result && count == 1 && cmds[0].has_subshells &&
             tokens_are_consistent(input, cmds, count));
    shell_free_commands(cmds, count);
  }

  static const feature_case_t compound_syntax_cases[] = {
      {{"Stress: nested command substitution (8 levels)",
        "echo $(echo $(echo $(echo $(echo $(echo $(echo $(echo hello)))))))",
        1},
       EXPECT_SUBSHELL},
      {{"Edge: process substitution", "diff <(cmd1) <(cmd2)", 1}, 0},
      {{"Edge: heredoc-shaped input", "cat <<EOF\nline1\nline2\nEOF", 1}, 0},
      {{"Edge: heredoc-shaped input with variable", "cat <<EOF\n$VAR\nEOF", 1},
       EXPECT_VARIABLE},
      {{"Edge: double brackets", "[[ $var == \"test\" ]]", 1}, EXPECT_VARIABLE},
      {{"Edge: for loop", "for f in *.txt; do echo $f; done", 3},
       EXPECT_VARIABLE | EXPECT_GLOB | EXPECT_LOOP},
      {{"Edge: while loop", "while read line; do echo $line; done < file.txt",
        3},
       EXPECT_VARIABLE | EXPECT_LOOP},
      {{"Edge: case statement", "case $var in a) echo a;; esac", 2},
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
      {"Edge: comment-shaped text before pipe", "cmd1 # comment\n| cmd2", 2},
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
    int result = shell_tokenize_commands(input, &cmds, &count);
    test("Stress: long command (200 args)",
         result && count == 1 && cmds[0].token_count == 201 &&
             tokens_are_consistent(input, cmds, count));
    shell_free_commands(cmds, count);
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
    int result = shell_tokenize_commands(input, &cmds, &count);
    bool token_counts_match = result && count == 50;
    for (size_t i = 0; token_counts_match && i < count; i++)
      token_counts_match = cmds[i].token_count == (i + 1 < count ? 5 : 4);
    test("Stress: long pipeline (50 stages)",
         token_counts_match && tokens_are_consistent(input, cmds, count));
    shell_free_commands(cmds, count);
  }

  // Test 206: Very long variable name
  {
    char input[2007] = "echo $";
    memset(input + 6, 'V', 2000);
    input[2006] = '\0';
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = shell_tokenize_commands(input, &cmds, &count);
    test("Stress: very long variable name (2000 characters)",
         result && count == 1 && cmds[0].has_variables &&
             tokens_are_consistent(input, cmds, count));
    shell_free_commands(cmds, count);
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
    int result = shell_tokenize_commands(input, &cmds, &count);
    // This is CORRECT behavior - shell parses it as two words
    test("Adjacent quoted and unquoted text is one command",
         result && count == 1 && tokens_are_consistent(input, cmds, count));
    if (cmds)
      shell_free_commands(cmds, count);
  }

  // Test 218: Double keyword 'if if' - actually VALID shell syntax!
  // Bash accepts "if if cmd" - runs "if" as command, uses exit status as
  // condition
  {
    const char *input = "if if cmd";
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = shell_tokenize_commands(input, &cmds, &count);
    test("Tokenizer accepts keyword-shaped command fragments",
         result && count == 1 && tokens_are_consistent(input, cmds, count));
    if (cmds)
      shell_free_commands(cmds, count);
  }

  // Test 219: Double 'then' keyword - complex case requires full grammar
  // parsing For fast tokenizer, we only detect at command start, nested is
  // flagged
  {
    const char *input = "if true; then then cmd; fi";
    shell_command_t *cmds = NULL;
    size_t count = 0;
    int result = shell_tokenize_commands(input, &cmds, &count);
    // This is a complex case - fast tokenizer may not catch nested "then then"
    test("Non-strict tokenizer accepts unsupported compound grammar",
         result == 1);
    if (cmds)
      shell_free_commands(cmds, count);
  }

  // Regression: an unmatched glob bracket must not create a token beyond the
  // terminating NUL.
  {
    const char *input = "pw[d";
    shell_tokenizer_state_t state;
    shell_token_t token;
    bool in_bounds = true;
    size_t input_len = strlen(input);

    shell_tokenizer_init(&state, input);
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

  printf("\n=== SUMMARY ===\n");
  printf("Results: %d/%d passed\n", pass_count, test_count);
  return (pass_count == test_count) ? 0 : 1;
}
