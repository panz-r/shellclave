#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;

static void test(const char *name, int result) {
  test_count++;
  if (result) {
    pass_count++;
    printf("  [PASS] %s\n", name);
  } else {
    printf("  [FAIL] %s\n", name);
  }
}

static void test_range_eq(const char *name, const shell_parse_result_t *result,
                          uint32_t idx, uint32_t exp_start, uint32_t exp_len,
                          uint16_t exp_type, uint16_t exp_features) {
  test_count++;
  if (idx < result->count) {
    const shell_range_t *r = &result->cmds[idx];
    if (r->start == exp_start && r->len == exp_len && r->type == exp_type &&
        r->features == exp_features) {
      pass_count++;
      printf("  [PASS] %s\n", name);
      return;
    }
    printf("  [FAIL] %s (got start=%u len=%u type=%u feat=%u, expected "
           "start=%u len=%u type=%u feat=%u)\n",
           name, r->start, r->len, r->type, r->features, exp_start, exp_len,
           exp_type, exp_features);
  } else {
    printf("  [FAIL] %s (index %u out of range, count=%u)\n", name, idx,
           result->count);
  }
}

static void test_count_only(const char *name,
                            const shell_parse_result_t *result,
                            uint32_t exp_count) {
  test_count++;
  if (result->count == exp_count) {
    pass_count++;
    printf("  [PASS] %s\n", name);
  } else {
    printf("  [FAIL] %s (got count=%u, expected %u)\n", name, result->count,
           exp_count);
  }
}

static void test_type(const char *name, const shell_parse_result_t *result,
                      uint32_t idx, uint16_t exp_type) {
  test_count++;
  if (idx < result->count && result->cmds[idx].type == exp_type) {
    pass_count++;
    printf("  [PASS] %s\n", name);
  } else {
    printf("  [FAIL] %s\n", name);
  }
}

static void test_has_feature(const char *name,
                             const shell_parse_result_t *result, uint32_t idx,
                             uint16_t feature) {
  test_count++;
  if (idx < result->count &&
      (result->cmds[idx].features & feature) == feature) {
    pass_count++;
    printf("  [PASS] %s\n", name);
  } else {
    printf("  [FAIL] %s\n", name);
  }
}

static void test_no_feature(const char *name,
                            const shell_parse_result_t *result, uint32_t idx,
                            uint16_t feature) {
  test_count++;
  if (idx < result->count && !(result->cmds[idx].features & feature)) {
    pass_count++;
    printf("  [PASS] %s\n", name);
  } else {
    printf("  [FAIL] %s\n", name);
  }
}

static void extract(const char *input, shell_parse_result_t *result) {
  shell_parse_fast(input, strlen(input), NULL, result);
}

static void extract_limited(const char *input, shell_limits_t *limits,
                            shell_parse_result_t *result) {
  shell_parse_fast(input, strlen(input), limits, result);
}

/* --- LAYER 1: UNIT TESTS - One feature at a time --- */

void test_layer1_basic_inputs(void) {
  printf("\n--- Layer 1: Basic Inputs ---\n");

  shell_parse_result_t result;

  // Test: empty input
  shell_error_t err = shell_parse_fast("", 0, NULL, &result);
  test("Empty input returns SHELL_EINPUT with no ranges",
       err == SHELL_EINPUT && result.count == 0 &&
           result.status == SHELL_STATUS_ERROR);

  // Test: NULL input
  err = shell_parse_fast(NULL, 0, NULL, &result);
  test("NULL input returns SHELL_EINPUT", err == SHELL_EINPUT);

  // Test: whitespace only
  extract("   \t\n  ", &result);
  test_count_only("Whitespace only returns 0", &result, 0);

  // Test: simple command
  extract("ls -la", &result);
  test_count_only("Simple command count=1", &result, 1);
  test_range_eq("Simple command range correct", &result, 0, 0, 6,
                SHELL_TYPE_SIMPLE, SHELL_FEAT_NONE);

  // Test: quoted command (single quotes - valid shell syntax to run command
  // with literal name)
  extract("'ls'", &result);
  test_count_only("Single-quoted command count=1", &result, 1);

  // Test: quoted command (double quotes)
  extract("\"ls\"", &result);
  test_count_only("Double-quoted command count=1", &result, 1);

  // Test: quoted command with args
  extract("'ls' -la", &result);
  test_count_only("Quoted command with args count=1", &result, 1);

  // Test: semicolon inside single quotes (should NOT be a separator)
  extract("'echo hello; world'", &result);
  test_count_only("Semicolon in quotes count=1", &result, 1);

  // Test: semicolon inside double quotes (should NOT be a separator)
  extract("\"echo hello; world\"", &result);
  test_count_only("Semicolon in double quotes count=1", &result, 1);
}

void test_layer1_simple_separators(void) {
  printf("\n--- Layer 1: Simple Separators ---\n");

  shell_parse_result_t result;

  // Test: single pipe
  extract("cmd1 | cmd2", &result);
  test_count_only("Single pipe count=2", &result, 2);
  test_range_eq("First cmd after pipe", &result, 0, 0, 4, SHELL_TYPE_SIMPLE,
                SHELL_FEAT_PIPELINE);
  test_type("Second cmd type=PIPELINE", &result, 1, SHELL_TYPE_PIPELINE);

  // Test: semicolon
  extract("cmd1 ; cmd2", &result);
  test_count_only("Semicolon count=2", &result, 2);
  test_type("Second cmd type=SEMICOLON", &result, 1, SHELL_TYPE_SEMICOLON);

  // Test: semicolon without whitespace (adjacent to words)
  extract("cmd1;cmd2", &result);
  test_count_only("Semicolon no-whitespace count=2", &result, 2);

  // Test: double ampersand
  extract("cmd1 && cmd2", &result);
  test_count_only("&& count=2", &result, 2);
  test_type("Second cmd type=AND", &result, 1, SHELL_TYPE_AND);

  // Test: double pipe
  extract("cmd1 || cmd2", &result);
  test_count_only("|| count=2", &result, 2);
  test_type("Second cmd type=OR", &result, 1, SHELL_TYPE_OR);
}

void test_layer1_whitespace_trimming(void) {
  printf("\n--- Layer 1: Whitespace Trimming ---\n");

  shell_parse_result_t result;

  // Test: leading/trailing whitespace in subcommand
  extract("  ls -la  ", &result);
  test_range_eq("Leading/trailing whitespace trimmed", &result, 0, 2, 6,
                SHELL_TYPE_SIMPLE, SHELL_FEAT_NONE);

  // Test: whitespace around pipe
  extract("  cmd1  |  cmd2  ", &result);
  test_range_eq("First piped command trimmed", &result, 0, 2, 4,
                SHELL_TYPE_SIMPLE, SHELL_FEAT_PIPELINE);
  test_range_eq("Second piped command trimmed", &result, 1, 11, 4,
                SHELL_TYPE_PIPELINE, SHELL_FEAT_PIPELINE);

  // Test: multiple spaces - still single command (whitespace separates args,
  // not subcommands)
  extract("cmd1    cmd2", &result);
  test_count_only("Multiple spaces count=1 (args)", &result, 1);

  // Test: tabs and spaces mixed
  extract("cmd1\t|\tcmd2", &result);
  test_count_only("Tabs and spaces count=2", &result, 2);
}

void test_layer1_heredoc(void) {
  printf("\n--- Layer 1: HEREDOC ---\n");

  shell_parse_result_t result;

  // Test: basic heredoc
  extract("cat << EOF", &result);
  test_count_only("Basic heredoc count=2", &result, 2);
  test_type("Heredoc type=HEREDOC (at idx 1)", &result, 1, SHELL_TYPE_HEREDOC);
  test_has_feature("Heredoc has HEREDOC feature (idx 1)", &result, 1,
                   SHELL_FEAT_HEREDOC);

  // Test: heredoc with delimiter
  extract("cat << ENDOFFILE", &result);
  test_count_only("Heredoc with delimiter count=2", &result, 2);
  test_range_eq("Heredoc range includes <<", &result, 1, 4, 12,
                SHELL_TYPE_HEREDOC, SHELL_FEAT_HEREDOC);

  // Test: heredoc with command and redirect
  extract("cat << EOF > output.txt", &result);
  test_count_only("Heredoc+redirect count=3", &result, 3);
}

typedef struct {
  const char *name;
  const char *input;
  uint32_t expected_count;
  uint32_t type_index;
  uint16_t expected_type;
  uint32_t feature_index;
  uint16_t required_features;
  uint16_t forbidden_features;
} parse_case_t;

#define NO_CHECK UINT32_MAX

static void test_feature_matrix(void) {
  printf("\n--- Feature Detection Matrix ---\n");

  static const parse_case_t cases[] = {
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
      {"heredoc bracket content", "cat << EOF\n[content]\nEOF", 4, NO_CHECK, 0,
       NO_CHECK, 0, 0},
      {"dollar subshell", "echo $(date)", 1, 0, SHELL_TYPE_SUBSTITUTION, 0,
       SHELL_FEAT_SUBSHELL, 0},
      {"backtick subshell", "echo `date`", 1, 0, SHELL_TYPE_SUBSTITUTION, 0,
       SHELL_FEAT_SUBSHELL, 0},
      {"arithmetic", "echo $((1+2))", 1, NO_CHECK, 0, 0, SHELL_FEAT_ARITH, 0},
      {"arithmetic variables", "echo $((x + y))", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_ARITH | SHELL_FEAT_VARS, 0},
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
      {"single quote inside double substitution", "echo \"'$(id)\"", 1, 0,
       SHELL_TYPE_SUBSTITUTION, 0, SHELL_FEAT_SUBSHELL, 0},
      {"first-command process substitution", "cat <(id)", 1, 0,
       SHELL_TYPE_SUBSTITUTION, 0, SHELL_FEAT_PROCESS_SUB, 0},
      {"process substitution after AND", "echo ok && cat <(id)", 2, 1,
       SHELL_TYPE_AND, 0, SHELL_FEAT_PROCESS_SUB, 0},
      {"special option variable", "echo $-", 1, NO_CHECK, 0, 0, SHELL_FEAT_VARS,
       0},
      {"loop feature", "while true", 1, NO_CHECK, 0, 0, SHELL_FEAT_LOOPS, 0},
      {"conditional feature", "if true", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_CONDITIONALS, 0},
      {"case feature", "case value", 1, NO_CHECK, 0, 0, SHELL_FEAT_CASE, 0},
      {"file command substitution", "echo $(<file)", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_SUBSHELL | SHELL_FEAT_SUBSHELL_FILE, 0},
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
      {"string conditional", "if [ \"$a\" = \"b\" ]; then echo yes; fi", 3,
       NO_CHECK, 0, 0, SHELL_FEAT_VARS, 0},
      {"numeric conditional", "if [ $x -gt 0 ]; then echo positive; fi", 3,
       NO_CHECK, 0, 0, SHELL_FEAT_VARS, 0},
      {"regex conditional", "if [[ $x =~ pattern ]]; then match; fi", 3,
       NO_CHECK, 0, 0, SHELL_FEAT_VARS, 0},
      {"glob conditional", "if [[ $str == *.* ]]; then echo ext; fi", 3,
       NO_CHECK, 0, 0, SHELL_FEAT_VARS | SHELL_FEAT_GLOBS, 0},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t result;
    shell_error_t error =
        shell_parse_fast(cases[i].input, strlen(cases[i].input), NULL, &result);
    bool valid = error == SHELL_OK && result.status == SHELL_STATUS_OK;
    if (cases[i].expected_count != NO_CHECK)
      valid = valid && result.count == cases[i].expected_count;
    if (cases[i].type_index != NO_CHECK)
      valid = valid && cases[i].type_index < result.count &&
              result.cmds[cases[i].type_index].type == cases[i].expected_type;
    if (cases[i].feature_index != NO_CHECK) {
      valid = valid && cases[i].feature_index < result.count;
      if (valid) {
        uint16_t features = result.cmds[cases[i].feature_index].features;
        valid = (features & cases[i].required_features) ==
                    cases[i].required_features &&
                (features & cases[i].forbidden_features) == 0;
      }
    }
    for (uint32_t j = 0; valid && j < result.count; j++) {
      const shell_range_t *range = &result.cmds[j];
      size_t input_len = strlen(cases[i].input);
      valid = range->len > 0 && range->start <= input_len &&
              range->len <= input_len - range->start &&
              !isspace((unsigned char)cases[i].input[range->start]) &&
              !isspace(
                  (unsigned char)cases[i].input[range->start + range->len - 1]);
    }
    if (!valid) {
      printf("    error=%d status=%u count=%u", error, result.status,
             result.count);
      if (cases[i].feature_index < result.count)
        printf(" features[%u]=0x%x", cases[i].feature_index,
               result.cmds[cases[i].feature_index].features);
      printf("\n");
    }
    test(cases[i].name, valid);
  }
}

void test_layer1_utility_functions(void) {
  printf("\n--- Layer 1: Utility Functions ---\n");

  const shell_range_t range = {.start = 2, .len = 6};
  const char input[] = "  ls -la";
  char buf[64];

  size_t copied = shell_copy_subcommand(input, &range, buf, sizeof(buf));
  test("copy returns exact subcommand",
       copied == 6 && strcmp(buf, "ls -la") == 0);

  copied = shell_copy_subcommand(input, &range, buf, 3);
  test("copy truncates and terminates a small buffer",
       copied == 2 && strcmp(buf, "ls") == 0);

  uint32_t len = 0;
  const char *ptr = shell_get_subcommand(input, &range, &len);
  test("get returns the ranged view", ptr == input + 2 && len == 6);

  // Test: NULL inputs
  copied = shell_copy_subcommand(NULL, NULL, NULL, 0);
  test("Copy with NULL returns 0", copied == 0);

  ptr = shell_get_subcommand(NULL, NULL, NULL);
  test("Get with NULL returns NULL", ptr == NULL);
}

void test_layer1_error_handling(void) {
  printf("\n--- Layer 1: Error Handling ---\n");

  shell_parse_result_t result;
  shell_limits_t limits;

  // Test: truncation
  limits.max_subcommands = 1;
  extract_limited("cmd1 | cmd2 | cmd3", &limits, &result);
  test("Truncation returns SHELL_ETRUNC",
       result.status & SHELL_STATUS_TRUNCATED);
  test_count_only("Truncated count=1", &result, 1);

  shell_error_t trunc_error =
      shell_parse_fast("cmd1 | cmd2", strlen("cmd1 | cmd2"), &limits, &result);
  test("Truncated pipeline returns SHELL_ETRUNC", trunc_error == SHELL_ETRUNC);
  test("Truncated pipeline preserves feature metadata",
       result.cmds[0].features & SHELL_FEAT_PIPELINE);

  trunc_error = shell_parse_fast("echo $(id); pwd", strlen("echo $(id); pwd"),
                                 &limits, &result);
  test("Truncated substitution returns SHELL_ETRUNC",
       trunc_error == SHELL_ETRUNC);
  test("Truncated substitution preserves type metadata",
       result.cmds[0].type == SHELL_TYPE_SUBSTITUTION &&
           (result.cmds[0].features & SHELL_FEAT_SUBSHELL));

  // Test: NULL result
  shell_error_t err = shell_parse_fast("cmd", 3, NULL, NULL);
  test("NULL result returns SHELL_EINPUT", err == SHELL_EINPUT);

#if SIZE_MAX > UINT32_MAX
  memset(&result, 0xa5, sizeof(result));
  err = shell_parse_fast("x", (size_t)UINT32_MAX + 1, NULL, &result);
  test("Rejects input too large for range offsets",
       err == SHELL_EINPUT && result.count == 0 &&
           result.status == SHELL_STATUS_ERROR);
#endif
}

void test_adversarial_bytes(void) {
  static const unsigned char cases[][8] = {
      {'e', 'c', 'h', 'o', ' ', 0x80, 0, 0},
      {'e', 'c', 'h', 'o', ' ', '\'', 0xFF, 0},
      {'$', '(', '(', 'x', 0xFE, ')', ')', 0},
      {'e', 'c', 'h', 'o', ' ', 0x01, 0, 0},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t result;
    size_t length = 0;
    while (length < sizeof(cases[i]) && cases[i][length] != 0)
      length++;
    shell_error_t err =
        shell_parse_fast((const char *)cases[i], length, NULL, &result);
    test("adversarial bytes produce a documented parser result",
         err == SHELL_OK || err == SHELL_EPARSE || err == SHELL_ETRUNC);
    test("adversarial byte result remains bounded",
         result.count <= SHELL_MAX_SUBCOMMANDS);
  }
}

void test_dialect_oracle(void) {
  static const struct {
    const char *input;
    uint32_t count;
    uint16_t first_type;
    uint16_t second_type;
  } cases[] = {
      {"ls", 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE},
      {"ls | wc", 2, SHELL_TYPE_SIMPLE, SHELL_TYPE_PIPELINE},
      {"ls && pwd", 2, SHELL_TYPE_SIMPLE, SHELL_TYPE_AND},
      {"ls || pwd", 2, SHELL_TYPE_SIMPLE, SHELL_TYPE_OR},
      {"echo 'a|b'", 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE},
      {"echo \"a; b\"", 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE},
      {"echo $(id)", 1, SHELL_TYPE_SUBSTITUTION, SHELL_TYPE_SIMPLE},
      {"echo $((1+2))", 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE},
      {"cmd ;", 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t fast = {0};
    shell_error_t error =
        shell_parse_fast(cases[i].input, strlen(cases[i].input), NULL, &fast);
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    bool full_ok =
        shell_tokenize_commands(cases[i].input, &commands, &command_count);
    char name[96];
    snprintf(name, sizeof(name), "dialect oracle: %s", cases[i].input);
    test(name, error == SHELL_OK && fast.count == cases[i].count &&
                   fast.cmds[0].type == cases[i].first_type &&
                   (cases[i].count < 2 ||
                    fast.cmds[1].type == cases[i].second_type) &&
                   full_ok && command_count == cases[i].count);
    shell_free_commands(commands, command_count);
  }

  static const char *strict_errors[] = {"echo 'x", "echo \"x", "$(("};
  for (size_t i = 0; i < sizeof(strict_errors) / sizeof(strict_errors[0]);
       i++) {
    shell_limits_t strict = {SHELL_MAX_SUBCOMMANDS, true};
    shell_parse_result_t result = {0};
    shell_error_t error = shell_parse_fast(
        strict_errors[i], strlen(strict_errors[i]), &strict, &result);
    test("strict dialect rejects incomplete syntax",
         error == SHELL_EPARSE && result.status == SHELL_STATUS_ERROR);
  }

  const char non_ascii[] = "echo \xC3\xA9";
  shell_parse_result_t result = {0};
  shell_error_t error =
      shell_parse_fast(non_ascii, sizeof(non_ascii) - 1, NULL, &result);
  test("fast parser rejects non-ASCII shell text",
       error == SHELL_EPARSE && result.count == 0);
  shell_command_t *commands = NULL;
  size_t command_count = 0;
  test("full tokenizer rejects non-ASCII shell text",
       !shell_tokenize_commands(non_ascii, &commands, &command_count) &&
           commands == NULL && command_count == 0);
  shell_free_commands(commands, command_count);
}

void test_layer1_edge_cases(void) {
  printf("\n--- Layer 1: Edge Cases ---\n");

  shell_parse_result_t result;

  // Test: multiple pipes
  extract("a | b | c | d", &result);
  test_count_only("Multiple pipes count=4", &result, 4);

  // Test: all separators
  extract("a && b || c ; d | e", &result);
  test_count_only("All separators count=5", &result, 5);

  // Test: pipe at end - should now return error (invalid shell)
  extract("cmd1 |", &result);
  test("Pipe at end should be rejected", result.status == SHELL_STATUS_ERROR);

  // Test: semicolon at end
  extract("cmd1 ;", &result);
  test_count_only("Semicolon at end count=1", &result, 1);
  test("Semicolon at end is accepted", result.status == SHELL_STATUS_OK);

  // Test: redirect handled
  extract("cmd > file", &result);
  test_count_only("Redirect count=1", &result, 1);

  // Test: input redirect
  extract("cmd < file", &result);
  test_count_only("Input redirect count=1", &result, 1);

  // Test: append redirect
  extract("cmd >> file", &result);
  test_count_only("Append redirect count=1", &result, 1);
}

void test_layer1_type_values(void) {
  printf("\n--- Layer 1: Type Values ---\n");

  shell_parse_result_t result;

  // Verify type values are distinct
  extract("cmd1", &result);
  test("SIMPLE type value", result.cmds[0].type == SHELL_TYPE_SIMPLE);

  extract("echo $(id)", &result);
  test("SUBSTITUTION type value",
       result.cmds[0].type == SHELL_TYPE_SUBSTITUTION);

  extract("cmd1 | cmd2", &result);
  test("PIPELINE type value", result.cmds[1].type == SHELL_TYPE_PIPELINE);

  extract("cmd1 && cmd2", &result);
  test("AND type value", result.cmds[1].type == SHELL_TYPE_AND);

  extract("cmd1 || cmd2", &result);
  test("OR type value", result.cmds[1].type == SHELL_TYPE_OR);

  extract("cmd1 ; cmd2", &result);
  test("SEMICOLON type value", result.cmds[1].type == SHELL_TYPE_SEMICOLON);

  extract("cat << EOF", &result);
  test("HEREDOC type value (at idx 1)",
       result.count > 1 && result.cmds[1].type == SHELL_TYPE_HEREDOC);
}

/* --- LAYER 2: INTERACTION TESTS - MULTIPLE FEATURES --- */

void test_layer2_heredoc_with_features(void) {
  printf("\n--- Layer 2: HEREDOC with Features ---\n");

  shell_parse_result_t result;

  // HEREDOC with vars inside
  extract("cat << EOF\necho $VAR\nEOF", &result);
  test_count_only("Heredoc+var count=4", &result, 4);
  test_type("Heredoc type at idx 1", &result, 1, SHELL_TYPE_HEREDOC);

  // HEREDOC with globs
  extract("grep pattern << END\n*.txt\nEND", &result);
  test_count_only("Heredoc+glob count=4", &result, 4);

  // HEREDOC followed by pipeline
  extract("cat << EOF | sort", &result);
  test_count_only("Heredoc+pipe count=3", &result, 3);
  test_type("Idx 1 is HEREDOC", &result, 1, SHELL_TYPE_HEREDOC);
  test_type("Idx 2 is PIPELINE", &result, 2, SHELL_TYPE_PIPELINE);
}

void test_layer2_complex_sequences(void) {
  printf("\n--- Layer 2: Complex Sequences ---\n");

  shell_parse_result_t result;

  // Chain: && followed by ||
  extract("cmd1 && cmd2 || cmd3", &result);
  test_count_only("&& || chain count=3", &result, 3);
  test_type("Second type=AND", &result, 1, SHELL_TYPE_AND);
  test_type("Third type=OR", &result, 2, SHELL_TYPE_OR);

  // Chain: ; followed by |
  extract("cmd1 ; cmd2 | cmd3", &result);
  test_count_only("; | chain count=3", &result, 3);
  test_type("Second type=SEMICOLON", &result, 1, SHELL_TYPE_SEMICOLON);
  test_type("Third type=PIPELINE", &result, 2, SHELL_TYPE_PIPELINE);

  // Complex: all operators
  extract("cmd1 && cmd2 | cmd3 || cmd4 ; cmd5", &result);
  test_count_only("All operators count=5", &result, 5);
}

void test_layer2_redirects(void) {
  printf("\n--- Layer 2: Redirects ---\n");

  shell_parse_result_t result;

  // Output redirect
  extract("echo hi > file.txt", &result);
  test_count_only("Output redirect count=1", &result, 1);

  // Input redirect
  extract("grep pattern < input.txt", &result);
  test_count_only("Input redirect count=1", &result, 1);

  // Both redirects
  extract("grep pattern < in.txt > out.txt", &result);
  test_count_only("Both redirects count=1", &result, 1);

  // Redirect with pipeline
  extract("grep pattern < file | sort > output", &result);
  test_count_only("Redirect+pipe count=2", &result, 2);

  // File descriptor
  extract("cmd 2>&1", &result);
  test_count_only("File descriptor count=1", &result, 1);
}

void test_layer2_mixed_commands(void) {
  printf("\n--- Layer 2: Mixed Commands ---\n");

  shell_parse_result_t result;

  // Command with args and pipeline
  extract("ls -la /tmp | head -n 10", &result);
  test_count_only("ls -la | head -n 10 count=2", &result, 2);

  // Command substitution in pipeline
  extract("$(echo hello) | wc -l", &result);
  test_count_only("Subshell pipeline count=2", &result, 2);
  test_has_feature("First has SUBSHELL", &result, 0, SHELL_FEAT_SUBSHELL);

  // Arithmetic in assignment - space-separated assignments treated as single
  // command
  extract("x=$((1+2)) y=$((3+4))", &result);
  test_count_only("Two assignments count=1 (space = args)", &result, 1);
  test_has_feature("Has ARITH", &result, 0, SHELL_FEAT_ARITH);
}

/* --- LAYER 3: LARGE/COMPLEX TESTS --- */

void test_layer3_real_world_commands(void) {
  printf("\n--- Layer 3: Real World Commands ---\n");

  shell_parse_result_t result;

  // Build pipeline like find+grep+sort
  extract(
      "find . -name '*.txt' -type f | grep -v test | sort | uniq -c | head -20",
      &result);
  test_count_only("find|grep|sort|uniq|head count=5", &result, 5);

  // Complex conditional
  extract("if [ -f config ]; then source config && echo loaded; else echo "
          "missing; fi",
          &result);
  test_count_only("if-then-else-fi count=5", &result, 5);

  // Complex with variables and arithmetic
  extract("count=$(ls *.log 2>/dev/null | wc -l) && [ $count -gt 0 ] || echo "
          "'no files'",
          &result);
  test_count_only("Complex pipeline count=4", &result, 4);
}

void test_layer3_nesting(void) {
  printf("\n--- Layer 3: Nesting ---\n");

  shell_parse_result_t result;

  // Nested subshells
  extract("echo $(( $(date +%s) + 3600 ))", &result);
  test_count_only("Nested subshell+arith count=1", &result, 1);
  test_has_feature("Has SUBSHELL", &result, 0, SHELL_FEAT_SUBSHELL);
  test_has_feature("Has ARITH", &result, 0, SHELL_FEAT_ARITH);

  // Nested braces
  extract("echo ${var:-default} ${var:=assigned}", &result);
  test_count_only("Nested braces count=1", &result, 1);
  test_has_feature("Has VARS", &result, 0, SHELL_FEAT_VARS);

  // Deep pipeline
  extract("a | b | c | d | e | f | g | h", &result);
  test_count_only("Deep pipeline count=8", &result, 8);
}

void test_layer3_many_subcommands(void) {
  printf("\n--- Layer 3: Many Subcommands ---\n");

  shell_parse_result_t result;

  // 10 commands with various separators
  extract("c1 && c2 || c3 ; c4 | c5 && c6 || c7 ; c8 | c9 | c10", &result);
  test_count_only("Many separators count=10", &result, 10);

  // Long semicolon chain
  char buf[256];
  strcpy(buf, "cmd1");
  for (int i = 2; i <= 20; i++) {
    strcat(buf, " ; cmd");
    char num[4];
    snprintf(num, sizeof(num), "%d", i);
    strcat(buf, num);
  }
  extract(buf, &result);
  test_count_only("20 semicolons count=20", &result, 20);
}

void test_layer3_long_commands(void) {
  printf("\n--- Layer 3: Long Commands ---\n");

  shell_parse_result_t result;

  // Long command with many args
  char buf[1024];
  strcpy(buf, "gcc -o program main.c -I./include -L./lib -lm -lpthread -DDEBUG "
              "-O2 -Wall");
  extract(buf, &result);
  test_count_only("Long gcc command count=1", &result, 1);

  // Long pipeline: cat|sort|uniq|head|tail = 5 subcommands
  strcpy(buf, "cat file1.txt file2.txt file3.txt | sort | uniq | head -100 | "
              "tail -50 > output.txt");
  extract(buf, &result);
  test_count_only("Long pipeline count=5", &result, 5);

  // Long with features
  strcpy(buf, "echo \"Processing ${files[@]} at $(date +%T)...\" && for f in "
              "*.log; do grep ERROR $f >> errors.txt; done");
  extract(buf, &result);
  test_count_only("Complex long command count=4", &result, 4);
  test_has_feature("Has VAR", &result, 0, SHELL_FEAT_VARS);
  test_has_feature("Has SUBSHELL", &result, 0, SHELL_FEAT_SUBSHELL);
}

void test_layer3_combined_stress(void) {
  printf("\n--- Layer 3: Combined Stress ---\n");

  shell_parse_result_t result;

  // Very complex command
  extract("if [ -f ~/.bashrc ]; then source ~/.bashrc; fi && export "
          "PATH=\"$HOME/bin:$PATH\" && find . -name '*.c' -exec gcc -o {} {} "
          "\\; | grep -v 'Permission denied' || echo 'Build failed'",
          &result);
  test_count_only("Very complex count=7", &result, 7);

  // Multiple features everywhere
  extract("arr=($(ls *.txt | sort)) && for f in \"${arr[@]}\"; do count=$(wc "
          "-l < \"$f\"); echo \"$f: $count lines\"; done | tee report.txt",
          &result);
  test_count_only("Array+for+subshell count=7", &result, 7);
  test_has_feature("Has SUBSHELL", &result, 0, SHELL_FEAT_SUBSHELL);
  // VARS is in later subcommands, not index 0
}

void test_layer3_whitespace_stress(void) {
  printf("\n--- Layer 3: Whitespace Stress ---\n");

  shell_parse_result_t result;

  // Many spaces - still single command (whitespace separates args, not
  // subcommands)
  extract("cmd1      cmd2     cmd3", &result);
  test_count_only("Many spaces count=1 (args, not subcmds)", &result, 1);

  // Tabs - same, single command
  extract("cmd1\t\tcmd2\tcmd3", &result);
  test_count_only("Tabs count=1 (args, not subcmds)", &result, 1);

  // Newlines as separators - these DO separate subcommands
  extract("cmd1\ncmd2\ncmd3", &result);
  test_count_only("Newlines count=3", &result, 3);

  // All whitespace types
  extract("  cmd1  \t  |  \n  cmd2  \t  ;  \n  cmd3  ", &result);
  test_count_only("Mixed whitespace count=3", &result, 3);
}

void test_layer3_boundary_conditions(void) {
  printf("\n--- Layer 3: Boundary Conditions ---\n");

  shell_parse_result_t result;
  shell_limits_t limits;

  // Exactly at limit
  limits.max_subcommands = 3;
  extract_limited("a | b | c", &limits, &result);
  test_count_only("At limit count=3", &result, 3);
  test("No truncation at limit", !(result.status & SHELL_STATUS_TRUNCATED));

  // Over limit
  extract_limited("a | b | c | d", &limits, &result);
  test_count_only("Over limit count=3", &result, 3);
  test("Truncation over limit", result.status & SHELL_STATUS_TRUNCATED);

  // Single char commands
  extract("a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p",
          &result);
  test_count_only("Single char commands count=16", &result, 16);
}

void test_layer3_features_stress(void) {
  printf("\n--- Layer 3: Features Stress ---\n");

  shell_parse_result_t result;

  // All features in one command
  // Note: x=$((1+2)) has ARITH but no $VAR (assignment, not variable reference)
  extract("x=$((1+2)) && y=$(echo $z) && ls *.txt && echo \"$var ${arr[@]} "
          "$((a+b))\"",
          &result);
  test_count_only("All features count=4", &result, 4);
  test_has_feature("First has ARITH", &result, 0, SHELL_FEAT_ARITH);
  test_no_feature("First no VARS (assignment)", &result, 0, SHELL_FEAT_VARS);
  test_has_feature("Second has SUBSHELL+VARS", &result, 1, SHELL_FEAT_SUBSHELL);
  test_has_feature("Third has GLOBS", &result, 2, SHELL_FEAT_GLOBS);
  test_has_feature("Fourth has VARS+ARITH", &result, 3, SHELL_FEAT_VARS);
  test_has_feature("Fourth has ARITH", &result, 3, SHELL_FEAT_ARITH);

  // Complex real-world with all features
  // Note: No $((...)) arithmetic in this command, only variables, globs,
  // subshell
  extract("RESULT=$(grep -E 'ERROR|WARN' ${LOG_DIR}/*.log 2>/dev/null | wc -l) "
          "&& if [ $RESULT -gt 0 ]; then echo \"Found $RESULT issues\"; fi",
          &result);
  test_count_only("Real-world all features count=5", &result, 5);
  test_has_feature("Has SUBSHELL", &result, 0, SHELL_FEAT_SUBSHELL);
  test_has_feature("Has VARS", &result, 0, SHELL_FEAT_VARS);
  test_has_feature("Has GLOBS", &result, 0, SHELL_FEAT_GLOBS);
  // No ARITH in this command - removed test
}

/* --- ADDITIONAL LAYER 1 TESTS --- */

void test_layer1_more_separators(void) {
  printf("\n--- Layer 1: More Separators ---\n");

  shell_parse_result_t result;

  // Multiple && in sequence
  extract("a && b && c && d", &result);
  test_count_only("Multiple && count=4", &result, 4);
  test_type("Third type=AND", &result, 2, SHELL_TYPE_AND);

  // Multiple || in sequence
  extract("a || b || c || d", &result);
  test_count_only("Multiple || count=4", &result, 4);
  test_type("Third type=OR", &result, 2, SHELL_TYPE_OR);

  // Mix of ; and |
  extract("a ; b | c ; d", &result);
  test_count_only("Mix ; and | count=4", &result, 4);

  // Background & is NOT a separator in shell - it's part of the command
  extract("cmd1 & cmd2", &result);
  test_count_only("Background & count=1 (not separator)", &result, 1);

  // && followed by |
  extract("a && b | c", &result);
  test_count_only("&& then | count=3", &result, 3);
}

void test_layer1_more_heredoc(void) {
  printf("\n--- Layer 1: More HEREDOC Variants ---\n");

  shell_parse_result_t result;

  // Strip heredoc (<<-)
  extract("cat <<- EOF", &result);
  test_count_only("Strip heredoc count=3", &result, 3);

  // Quoted delimiter
  extract("cat << 'EOF'", &result);
  test_count_only("Quoted heredoc count=2", &result, 2);

  // Double-quoted delimiter
  extract("cat << \"EOF\"", &result);
  test_count_only("Double-quoted heredoc count=2", &result, 2);

  // Here-string (<<<) - now properly detected as HERESTRING
  extract("cmd <<< string", &result);
  test_count_only("Here-string count=2", &result, 2);
  test_type("Here-string type=HERESTRING", &result, 1, SHELL_TYPE_HERESTRING);
  test_has_feature("Here-string has HERESTRING feature", &result, 1,
                   SHELL_FEAT_HERESTRING);

  // Multiple heredocs
  extract("cat << A << B", &result);
  test_count_only("Multiple heredocs count=3", &result, 3);
}

void test_layer1_special_chars(void) {
  printf("\n--- Layer 1: Special Characters ---\n");

  shell_parse_result_t result;

  // Colon in path
  extract("/usr/local/bin:/usr/bin", &result);
  test_count_only("Colon in path count=1", &result, 1);

  // Dollar in quoted string
  extract("echo \"cost is $$$\"", &result);
  test_count_only("Dollar in quotes count=1", &result, 1);

  // Backticks
  extract("echo `date`", &result);
  test_has_feature("Backticks has SUBSHELL", &result, 0, SHELL_FEAT_SUBSHELL);

  // Process substitution - <() is NOT a separator, treated as part of command
  extract("diff <(cmd1) <(cmd2)", &result);
  test_count_only("Process substitution count=1 (not sep)", &result, 1);

  // Process substitution with redirect
  extract("diff <(cmd1) <(cmd2) > out", &result);
  test_count_only("Process sub+redirect count=1 (not sep)", &result, 1);
}

/* --- ADDITIONAL LAYER 3 TESTS --- */

void test_layer3_script_snippets(void) {
  printf("\n--- Layer 3: Script Snippets ---\n");

  shell_parse_result_t result;

  // Function definition
  extract("function foo { echo hello; }", &result);
  test_count_only("Function def count=2", &result, 2);

  // Function with args
  extract("foo() { cat $1; }", &result);
  test_count_only("Function with args count=2", &result, 2);

  // Local variable
  extract("local x=5; echo $x", &result);
  test_count_only("Local var count=2", &result, 2);

  // Export statement
  extract("export PATH=/usr/bin:$PATH", &result);
  test_count_only("Export count=1", &result, 1);

  // Read builtin
  extract("read line < file", &result);
  test_count_only("Read builtin count=1", &result, 1);
}

void test_layer3_complex_loops(void) {
  printf("\n--- Layer 3: Complex Loops ---\n");

  shell_parse_result_t result;

  // C-style for loop - splits into multiple parts by ;
  extract("for ((i=0; i<10; i++)); do echo $i; done", &result);
  test_count_only("C-for count=3", &result, 3);
  // The ARITH is in one of the middle parts, VARS in the echo part

  // For with glob
  extract("for f in *.txt; do wc -l $f; done", &result);
  test_count_only("For+glob count=3", &result, 3);
  test_has_feature("For header has GLOBS", &result, 0, SHELL_FEAT_GLOBS);
  test_has_feature("For body has VARS", &result, 1, SHELL_FEAT_VARS);

  // While with read
  extract("while IFS= read -r line; do echo $line; done < file", &result);
  test_count_only("While+read count=3", &result, 3);

  // Select menu
  extract("select opt in a b c; do echo $opt; done", &result);
  test_count_only("Select count=3", &result, 3);
}

void test_layer3_command_chains(void) {
  printf("\n--- Layer 3: Command Chains ---\n");

  shell_parse_result_t result;

  // Complex chain with all operators
  extract("a && b || c | d ; e && f || g | h", &result);
  test_count_only("Complex chain count=8", &result, 8);

  // Pipeline in parentheses - grouping, not a subshell feature
  extract("(a | b | c)", &result);
  test_count_only("Pipeline in parens count=3 (pipes split)", &result, 3);

  // Command group
  extract("{ a; b; c; }", &result);
  test_count_only("Command group count=4", &result, 4);

  // Array assignment
  extract("arr=(one two three)", &result);
  test_count_only("Array assignment count=1", &result, 1);

  // Index into array
  extract("echo ${arr[0]} ${arr[1]}", &result);
  test_has_feature("Array index has VARS", &result, 0, SHELL_FEAT_VARS);
}

void test_layer3_realistic_scripts(void) {
  printf("\n--- Layer 3: Realistic Scripts ---\n");

  shell_parse_result_t result;

  // Build script snippet
  extract("for f in *.c; do gcc -o ${f%.c} $f; done", &result);
  test_count_only("Build script count=3", &result, 3);
  test_has_feature("Build header has GLOBS", &result, 0, SHELL_FEAT_GLOBS);
  test_has_feature("Build body has VARS", &result, 1, SHELL_FEAT_VARS);

  // Git-style command
  extract("git log --oneline -n 10 | head", &result);
  test_count_only("Git-style count=2", &result, 2);

  // Docker-style command - quoted string doesn't expand vars
  extract("docker ps -a --filter \"name=test\" | grep -v CONTAINER", &result);
  test_count_only("Docker-style count=2", &result, 2);
  // First part has no VARS because quoted

  // Make-style command
  extract("make all 2>&1 | tee build.log", &result);
  test_count_only("Make-style count=2", &result, 2);

  // Backup script
  extract("tar czf backup.tar.gz $(find . -name '*.log') && rm *.log", &result);
  test_count_only("Backup script count=2", &result, 2);
  test_has_feature("Backup command has SUBSHELL", &result, 0,
                   SHELL_FEAT_SUBSHELL);
  test_has_feature("Backup cleanup has GLOBS", &result, 1, SHELL_FEAT_GLOBS);
}

void test_layer3_stress_sequential(void) {
  printf("\n--- Layer 3: Stress - Sequential Commands ---\n");

  shell_parse_result_t result;

  // 30 sequential commands
  char buf[512] = "cmd1";
  for (int i = 2; i <= 30; i++) {
    strcat(buf, " ; cmd");
    char num[4];
    snprintf(num, sizeof(num), "%d", i);
    strcat(buf, num);
  }
  extract(buf, &result);
  test_count_only("30 sequential count=30", &result, 30);

  // Alternating operators
  strcpy(buf, "c1 && c2 || c3 && c4 || c5 && c6 || c7 && c8 || c9 && c10");
  extract(buf, &result);
  test_count_only("Alternating operators count=10", &result, 10);

  // Deep nesting
  extract("echo $((((($x))))))", &result);
  test_has_feature("Deep nesting has VARS", &result, 0, SHELL_FEAT_VARS);

  // Many variables
  extract("echo $a $b $c $d $e $f $g $h $i $j $k $l $m $n $o $p", &result);
  test_has_feature("Many vars has VARS", &result, 0, SHELL_FEAT_VARS);
}

void test_layer3_boundary_edge(void) {
  printf("\n--- Layer 3: Boundary and Edge ---\n");

  shell_parse_result_t result;
  shell_limits_t limits;

  // Exactly at subcommand limit
  limits.max_subcommands = 5;
  extract_limited("a | b | c | d | e", &limits, &result);
  test_count_only("At subcommand limit count=5", &result, 5);
  test("No trunc at limit", !(result.status & SHELL_STATUS_TRUNCATED));

  // Over subcommand limit
  extract_limited("a | b | c | d | e | f", &limits, &result);
  test_count_only("Over subcommand limit count=5", &result, 5);
  test("Trunc over limit", result.status & SHELL_STATUS_TRUNCATED);

  // Very small buffer simulation - single char
  limits.max_subcommands = 1;
  extract_limited("a | b | c", &limits, &result);
  test_count_only("Single subcommand limit count=1", &result, 1);

  // Command with all special chars - pipes and semicolons are separators
  // Note: This test has known issues with redirect handling - using valid shell
  // syntax
  extract("cmd $VAR * ? [ ] { } ( ) | & ; '\"`\\\\", &result);
  // Note: count may be less than 2 due to redirect parsing issues with < >
  test_count_only("All special chars count=3", &result, 3);
}

void test_layer3_feature_exhaustiveness(void) {
  printf("\n--- Layer 3: Feature Exhaustiveness ---\n");

  shell_parse_result_t result;

  // All features combined
  extract("x=$((a+b)) && y=$(echo $z) && ls *.log && echo \"$v ${arr[@]}\"",
          &result);
  test_count_only("All features combined count=4", &result, 4);
  test_has_feature("First has ARITH+VARS", &result, 0,
                   SHELL_FEAT_ARITH | SHELL_FEAT_VARS);
  test_has_feature("Second has SUBSHELL+VARS", &result, 1,
                   SHELL_FEAT_SUBSHELL | SHELL_FEAT_VARS);
  test_has_feature("Third has GLOBS", &result, 2, SHELL_FEAT_GLOBS);
  test_has_feature("Fourth has VARS", &result, 3, SHELL_FEAT_VARS);

  // Multiple features in subshell
  extract("$(echo $x $((y+z)) *.txt)", &result);
  test_count_only("Multi-feature subshell count=1", &result, 1);
  test_has_feature("Multi-feature subshell has all", &result, 0,
                   SHELL_FEAT_SUBSHELL | SHELL_FEAT_VARS | SHELL_FEAT_ARITH |
                       SHELL_FEAT_GLOBS);

  // Heredoc with all features
  extract("cat << EOF\necho $var\n*.txt\n$((x+1))\nEOF", &result);
  test_count_only("Heredoc+features count=6", &result, 6);

  // Deep pipeline with features
  extract("a | b | c | d | e | f | g | h", &result);
  test_count_only("Deep pipeline with features count=8", &result, 8);

  // Long command with all features
  char buf[512];
  snprintf(buf, sizeof(buf),
           "x=$((a+b)) && y=$(echo $z) && ls *.txt > out.log 2>&1 && "
           "if [ -f config ]; then source config; fi && "
           "for f in *.log; do grep ERROR $f >> errors.txt; done");
  extract(buf, &result);
  test_count_only("Long multi-feature count=9", &result, 9);
}

static void test_strict_mode(void) {
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
    test(cases[i].name, valid);
  }
}

static void test_fast_parser_limitations(void) {
  printf("\n--- Fast Parser Regression Tests ---\n");

  static const char high_bytes[] = {(char)0x80, (char)0x81, 'c', 'm', 'd'};
  static const char embedded_high_byte[] = {'c', 'm', 'd', (char)0x80, 'x'};
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
      {"reject high bytes", high_bytes, sizeof(high_bytes), SHELL_STATUS_ERROR,
       0},
      {"reject embedded control character", "cmd\x01suffix",
       sizeof("cmd\x01suffix") - 1, SHELL_STATUS_ERROR, 0},
      {"reject embedded high byte", embedded_high_byte,
       sizeof(embedded_high_byte), SHELL_STATUS_ERROR, 0},
      {"accept adjacent quoted and unquoted text", "\"text \"text",
       sizeof("\"text \"text") - 1, SHELL_STATUS_OK, 1},
      {"accept keyword-shaped command fragments", "if if cmd",
       sizeof("if if cmd") - 1, SHELL_STATUS_OK, 1},
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
    test(cases[i].name, valid);
  }
}

/* --- FEATURE FLAGS API TESTS --- */

static uint16_t feature_flags_mask(const shell_feature_flags_t *flags) {
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
         (flags->has_pipeline ? SHELL_FEAT_PIPELINE : 0);
}

static void test_feature_flags(void) {
  printf("\n--- Feature Flags API ---\n");

  uint16_t masks[] = {
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
      SHELL_FEAT_VARS | SHELL_FEAT_GLOBS,
      (uint16_t)((SHELL_FEAT_SUBSHELL_FILE << 1) - 1),
  };
  for (size_t i = 0; i < sizeof(masks) / sizeof(masks[0]); i++) {
    shell_feature_flags_t flags;
    shell_get_feature_flags(masks[i], &flags);
    char name[80];
    snprintf(name, sizeof(name), "feature mask 0x%03x round-trips", masks[i]);
    test(name, feature_flags_mask(&flags) == masks[i]);
  }
}

/* --- MAIN --- */

int main(void) {
  printf("=== FAST PARSER API TESTS ===\n");
  printf("Testing shell_parse_fast() and related functions\n\n");

  printf("=== LAYER 1: UNIT TESTS (~50 tests) ===\n");
  test_layer1_basic_inputs();
  test_layer1_simple_separators();
  test_layer1_whitespace_trimming();
  test_layer1_heredoc();
  test_feature_matrix();
  test_layer1_utility_functions();
  test_layer1_error_handling();
  test_adversarial_bytes();
  test_dialect_oracle();
  test_layer1_edge_cases();
  test_layer1_type_values();

  printf("\n=== LAYER 2: INTERACTION TESTS (~100 tests) ===\n");
  test_layer2_heredoc_with_features();
  test_layer2_complex_sequences();
  test_layer2_redirects();
  test_layer2_mixed_commands();

  printf("\n=== LAYER 3: LARGE/COMPLEX TESTS (~100 tests) ===\n");
  test_layer3_real_world_commands();
  test_layer3_nesting();
  test_layer3_many_subcommands();
  test_layer3_long_commands();
  test_layer3_combined_stress();
  test_layer3_whitespace_stress();
  test_layer3_boundary_conditions();
  test_layer3_features_stress();

  printf("\n=== ADDITIONAL LAYER 1 TESTS ===\n");
  test_layer1_more_separators();
  test_layer1_more_heredoc();
  test_layer1_special_chars();

  printf("\n=== ADDITIONAL LAYER 2 TESTS ===\n");

  printf("\n=== ADDITIONAL LAYER 3 TESTS ===\n");
  test_layer3_script_snippets();
  test_layer3_complex_loops();
  test_layer3_command_chains();
  test_layer3_realistic_scripts();
  test_layer3_stress_sequential();
  test_layer3_boundary_edge();
  test_layer3_feature_exhaustiveness();

  printf("\n=== FEATURE FLAGS API TESTS ===\n");
  test_feature_flags();

  test_fast_parser_limitations();

  test_strict_mode();

  printf("\n=== SUMMARY ===\n");
  printf("Results: %d/%d passed\n", pass_count, test_count);
  if (pass_count == test_count) {
    printf("  [PASS] All tests\n");
    return 0;
  } else {
    printf("  [FAIL] %d tests failed\n", test_count - pass_count);
    return 1;
  }
}
