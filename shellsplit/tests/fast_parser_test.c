#include "shell_depgraph.h"
#include "shell_processor.h"
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

static bool valid_command_type(uint16_t type) {
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

static bool result_invariants(const char *input, size_t input_len,
                              shell_error_t error,
                              const shell_parse_result_t *result) {
  const uint32_t all_features =
      SHELL_FEAT_VARS | SHELL_FEAT_GLOBS | SHELL_FEAT_SUBSHELL |
      SHELL_FEAT_ARITH | SHELL_FEAT_HEREDOC | SHELL_FEAT_HERESTRING |
      SHELL_FEAT_PROCESS_SUB | SHELL_FEAT_LOOPS | SHELL_FEAT_CONDITIONALS |
      SHELL_FEAT_CASE | SHELL_FEAT_SUBSHELL_FILE | SHELL_FEAT_PIPELINE |
      SHELL_FEAT_GROUP | SHELL_FEAT_BACKGROUND;
  if (!input || !result || result->count > SHELL_MAX_SUBCOMMANDS)
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
        !valid_command_type(range->type) ||
        (range->features & ~all_features) != 0 ||
        view != input + range->start || length != range->len ||
        copied != expected_copy || memcmp(copy, view, expected_copy) != 0 ||
        copy[copied] != '\0' || isspace((unsigned char)input[range->start]) ||
        isspace((unsigned char)input[range->start + range->len - 1]))
      return false;
    previous_end = range->start + range->len;
  }
  return true;
}

static shell_error_t parse_checked(const char *input, size_t input_len,
                                   const shell_limits_t *limits,
                                   shell_parse_result_t *result) {
  shell_error_t error = shell_parse_fast(input, input_len, limits, result);
  if (input && result && (error == SHELL_OK || error == SHELL_ETRUNC) &&
      !result_invariants(input, input_len, error, result)) {
    printf("  [FAIL] parser result invariant for %zu-byte input\n", input_len);
    test_count++;
  }
  return error;
}

#define shell_parse_fast parse_checked

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

  err = shell_parse_fast("   \t\n  ", strlen("   \t\n  "), NULL, &result);
  test("Whitespace-only input has no command",
       err == SHELL_EPARSE && result.status == SHELL_STATUS_ERROR &&
           result.count == 0);

  // Test: simple command
  extract("ls -la", &result);
  test_count_only("Simple command count=1", &result, 1);
  test_range_eq("Simple command range correct", &result, 0, 0, 6,
                SHELL_TYPE_SIMPLE, SHELL_FEAT_NONE);
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
  printf("\n--- HEREDOC Matrix ---\n");
  static const struct {
    const char *name;
    const char *input;
    uint32_t count;
    uint32_t range_start;
    uint32_t range_length;
    uint32_t secondary_index;
    uint16_t secondary_type;
  } cases[] = {
      {"plain delimiter", "cat << EOF", 2, 4, 6, NO_CHECK, 0},
      {"long delimiter", "cat << ENDOFFILE", 2, 4, 12, NO_CHECK, 0},
      {"redirect after heredoc", "cat << EOF > output.txt", 3, NO_CHECK,
       NO_CHECK, NO_CHECK, 0},
      {"tab-stripping delimiter", "cat <<- EOF", 3, NO_CHECK, NO_CHECK,
       NO_CHECK, 0},
      {"single-quoted delimiter", "cat << 'EOF'", 2, NO_CHECK, NO_CHECK,
       NO_CHECK, 0},
      {"double-quoted delimiter", "cat << \"EOF\"", 2, NO_CHECK, NO_CHECK,
       NO_CHECK, 0},
      {"multiple heredocs", "cat << A << B", 3, NO_CHECK, NO_CHECK, NO_CHECK,
       0},
      {"variable content", "cat << EOF\necho $VAR\nEOF", 4, NO_CHECK, NO_CHECK,
       NO_CHECK, 0},
      {"glob content", "grep pattern << END\n*.txt\nEND", 4, NO_CHECK, NO_CHECK,
       NO_CHECK, 0},
      {"pipeline interaction", "cat << EOF | sort", 3, NO_CHECK, NO_CHECK, 2,
       SHELL_TYPE_PIPELINE},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t result;
    shell_error_t error =
        shell_parse_fast(cases[i].input, strlen(cases[i].input), NULL, &result);
    bool valid = result_invariants(cases[i].input, strlen(cases[i].input),
                                   error, &result) &&
                 error == SHELL_OK && result.status == SHELL_STATUS_OK &&
                 result.count == cases[i].count && result.count > 1 &&
                 result.cmds[1].type == SHELL_TYPE_HEREDOC &&
                 (result.cmds[1].features & SHELL_FEAT_HEREDOC) != 0;
    if (valid && cases[i].range_start != NO_CHECK)
      valid = result.cmds[1].start == cases[i].range_start &&
              result.cmds[1].len == cases[i].range_length;
    if (valid && cases[i].secondary_index != NO_CHECK)
      valid =
          cases[i].secondary_index < result.count &&
          result.cmds[cases[i].secondary_index].type == cases[i].secondary_type;
    if (!valid)
      printf("    %s: error=%d status=%u count=%u\n", cases[i].name, error,
             result.status, result.count);
    test(cases[i].name, valid);
  }
}

static void test_feature_matrix(void) {
  printf("\n--- Feature Detection Matrix ---\n");

  static const parse_case_t cases[] = {
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
      {"adjacent substitutions", "echo $(id)$(pwd)", 1, 0,
       SHELL_TYPE_SUBSTITUTION, 0, SHELL_FEAT_SUBSHELL, 0},
      {"embedded adjacent substitutions", "echo pre$(id)suf$(pwd)", 1, 0,
       SHELL_TYPE_SUBSTITUTION, 0, SHELL_FEAT_SUBSHELL, 0},
      {"mixed substitutions", "echo $(id)`pwd`", 1, 0, SHELL_TYPE_SUBSTITUTION,
       0, SHELL_FEAT_SUBSHELL, 0},
      {"arithmetic with executable substitution", "echo $(( $(id) + 1 ))", 1,
       NO_CHECK, 0, 0, SHELL_FEAT_ARITH | SHELL_FEAT_SUBSHELL, 0},
      {"odd escaped substitution", "echo \\$(id)", 1, NO_CHECK, 0, 0, 0,
       SHELL_FEAT_SUBSHELL},
      {"even escaped substitution", "echo \\\\$(id)", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_SUBSHELL, 0},
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
      {"here-string", "cmd <<< string", 2, 1, SHELL_TYPE_HERESTRING, 1,
       SHELL_FEAT_HERESTRING, 0},
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
    bool valid = result_invariants(cases[i].input, strlen(cases[i].input),
                                   error, &result) &&
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
    test(cases[i].name, valid);
  }

  shell_parse_result_t metadata;
  extract("cmd1 & cmd2", &metadata);
  test_has_feature("Background marks preceding command", &metadata, 0,
                   SHELL_FEAT_BACKGROUND);
  extract("(cmd1; cmd2)", &metadata);
  test("Group metadata and feature are retained",
       metadata.count == 2 && metadata.cmds[0].group_depth == 1 &&
           metadata.cmds[1].group_depth == 1 &&
           (metadata.cmds[0].features & SHELL_FEAT_GROUP) != 0);
}

void test_layer1_utility_functions(void) {
  printf("\n--- Layer 1: Utility Functions ---\n");

  const shell_range_t range = {.start = 2, .len = 6};
  const char input[] = "  ls -la";
  char buf[64];

  size_t copied = shell_subcommand_copy(input, &range, buf, sizeof(buf));
  test("copy returns exact subcommand",
       copied == 6 && strcmp(buf, "ls -la") == 0);

  copied = shell_subcommand_copy(input, &range, buf, 3);
  test("copy truncates and terminates a small buffer",
       copied == 2 && strcmp(buf, "ls") == 0);

  size_t len = 0;
  const char *ptr = shell_subcommand_view(input, &range, &len);
  test("get returns the ranged view", ptr == input + 2 && len == 6);

  // Test: NULL inputs
  copied = shell_subcommand_copy(NULL, NULL, NULL, 0);
  test("Copy with NULL returns 0", copied == 0);

  ptr = shell_subcommand_view(NULL, NULL, NULL);
  test("Get with NULL returns NULL", ptr == NULL);
}

void test_layer1_error_handling(void) {
  printf("\n--- Layer 1: Error Handling ---\n");

  shell_parse_result_t result;
  const shell_limits_t limits = {.max_subcommands = 1, .strict_mode = false};
  static const struct {
    const char *name;
    const char *input;
    uint16_t type;
    uint16_t features;
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
       SHELL_TYPE_SIMPLE, SHELL_FEAT_CONDITIONALS},
      {"mixed composition truncation", "a && b || c | d ; e", SHELL_TYPE_SIMPLE,
       0},
  };
  for (size_t i = 0; i < sizeof(truncation_cases) / sizeof(truncation_cases[0]);
       i++) {
    shell_error_t error =
        shell_parse_fast(truncation_cases[i].input,
                         strlen(truncation_cases[i].input), &limits, &result);
    test(truncation_cases[i].name,
         error == SHELL_ETRUNC && result.status == SHELL_STATUS_TRUNCATED &&
             result.count == 1 &&
             result.cmds[0].type == truncation_cases[i].type &&
             (result.cmds[0].features & truncation_cases[i].features) ==
                 truncation_cases[i].features);
  }

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
      {"echo \\$(id)", 1, 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE},
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
    shell_dep_error_t graph_error = shell_dep_graph_parse(
        cases[i].input, strlen(cases[i].input), ".", NULL, &graph);
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
    test(name, valid);
    shell_command_infos_free(infos, info_count);
    shell_commands_free(commands, command_count);
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
       !(shell_tokenize_commands(non_ascii, strlen(non_ascii), &commands,
                                 &command_count) == SHELL_TOKENIZE_OK) &&
           commands == NULL && command_count == 0);
  shell_commands_free(commands, command_count);
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

void test_layer2_complex_sequences(void) {
  printf("\n--- Layer 2: Complex Sequences ---\n");
  static const struct {
    const char *name;
    const char *input;
    uint32_t count;
    uint16_t types[5];
  } cases[] = {
      {"AND then OR",
       "cmd1 && cmd2 || cmd3",
       3,
       {SHELL_TYPE_SIMPLE, SHELL_TYPE_AND, SHELL_TYPE_OR}},
      {"semicolon then pipeline",
       "cmd1 ; cmd2 | cmd3",
       3,
       {SHELL_TYPE_SIMPLE, SHELL_TYPE_SEMICOLON, SHELL_TYPE_PIPELINE}},
      {"all composition operators",
       "cmd1 && cmd2 | cmd3 || cmd4 ; cmd5",
       5,
       {SHELL_TYPE_SIMPLE, SHELL_TYPE_AND, SHELL_TYPE_PIPELINE, SHELL_TYPE_OR,
        SHELL_TYPE_SEMICOLON}},
      {"repeated AND",
       "a && b && c && d",
       4,
       {SHELL_TYPE_SIMPLE, SHELL_TYPE_AND, SHELL_TYPE_AND, SHELL_TYPE_AND}},
      {"repeated OR",
       "a || b || c || d",
       4,
       {SHELL_TYPE_SIMPLE, SHELL_TYPE_OR, SHELL_TYPE_OR, SHELL_TYPE_OR}},
      {"background ampersand separates commands",
       "cmd1 & cmd2",
       2,
       {SHELL_TYPE_SIMPLE, SHELL_TYPE_BACKGROUND}},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t result;
    shell_error_t error =
        shell_parse_fast(cases[i].input, strlen(cases[i].input), NULL, &result);
    bool valid = result_invariants(cases[i].input, strlen(cases[i].input),
                                   error, &result) &&
                 error == SHELL_OK && result.status == SHELL_STATUS_OK &&
                 result.count == cases[i].count;
    for (uint32_t j = 0; valid && j < result.count; j++)
      valid = result.cmds[j].type == cases[i].types[j];
    if (!valid)
      printf("    %s: input='%s', error=%d status=%u count=%u expected=%u\n",
             cases[i].name, cases[i].input, error, result.status, result.count,
             cases[i].count);
    test(cases[i].name, valid);
  }
}

void test_layer2_redirects(void) {
  printf("\n--- Layer 2: Redirects ---\n");

  shell_parse_result_t result;

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

typedef struct {
  const char *name;
  const char *input;
  uint32_t count;
  uint32_t feature_index;
  uint16_t features;
} complex_case_t;

static void test_complex_case_matrix(void) {
  printf("\n--- Layer 3: Complex Inputs ---\n");
  static const complex_case_t cases[] = {
      {"find pipeline",
       "find . -name '*.txt' -type f | grep -v test | sort | "
       "uniq -c | head -20",
       5, 0, 0},
      {"conditional sequence",
       "if [ -f config ]; then source config && echo loaded; else echo "
       "missing; fi",
       5, 0, 0},
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
       7, 0, 0},
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
      {"command group", "{ a; b; c; }", 4, 0, 0},
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
    test(cases[i].name, valid);
  }
}

void test_layer1_special_chars(void) {
  printf("\n--- Process Substitution with Redirection ---\n");

  shell_parse_result_t result;
  extract("diff <(cmd1) <(cmd2) > out", &result);
  test_range_eq("Process substitution retains composed-command metadata",
                &result, 0, 0, 26, SHELL_TYPE_SUBSTITUTION,
                SHELL_FEAT_PROCESS_SUB);
}

/* --- ADDITIONAL LAYER 3 TESTS --- */

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
  test("Single subcommand limit truncates",
       result.status & SHELL_STATUS_TRUNCATED);

  char default_limit[512] = "c";
  for (int i = 1; i < 65; i++)
    strcat(default_limit, " | c");
  extract(default_limit, &result);
  test_count_only("Default limit retains 64 commands", &result, 64);
  test("Default limit reports truncation",
       result.status & SHELL_STATUS_TRUNCATED);
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

static void test_nested_heredoc_rejection(void) {
  printf("\n--- Nested Heredoc Dialect Boundary ---\n");
  static const char *cases[] = {
      "echo $(cat <<EOF\nbody\nEOF)",
      "echo $(cat <<'EOF'\n$(id)\nEOF) && pwd",
      "cat <(cat <<EOF\nbody\nEOF)",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    for (int strict = 0; strict <= 1; strict++) {
      shell_limits_t limits = {SHELL_MAX_SUBCOMMANDS, strict != 0};
      shell_parse_result_t result = {0};
      shell_error_t error =
          shell_parse_fast(cases[i], strlen(cases[i]), &limits, &result);
      char name[96];
      snprintf(name, sizeof(name), "%s nested heredoc rejected (%s)",
               strict ? "strict" : "permissive", cases[i]);
      test(name, error == SHELL_EPARSE && result.status == SHELL_STATUS_ERROR &&
                     result.count == 0);
    }
  }
}

static void test_dialect_boundary_matrix(void) {
  printf("\n--- Unsupported Redirect Boundary ---\n");
  static const char *cases[] = {"cmd &>file", "cmd &>>file"};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t result = {0};
    shell_error_t error =
        shell_parse_fast(cases[i], strlen(cases[i]), NULL, &result);
    char name[96];
    snprintf(name, sizeof(name), "reject unsupported redirect: %s", cases[i]);
    test(name, error == SHELL_EPARSE && result.status == SHELL_STATUS_ERROR &&
                   result.count == 0);
  }
}

static void test_fast_parser_limitations(void) {
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
      {"reject high bytes", high_bytes, sizeof(high_bytes), SHELL_STATUS_ERROR,
       0},
      {"reject embedded control character", "cmd\x01suffix",
       sizeof("cmd\x01suffix") - 1, SHELL_STATUS_ERROR, 0},
      {"reject embedded high byte", embedded_high_byte,
       sizeof(embedded_high_byte), SHELL_STATUS_ERROR, 0},
      {"reject high byte after quote", quoted_high_byte,
       sizeof(quoted_high_byte), SHELL_STATUS_ERROR, 0},
      {"reject high byte in arithmetic", arithmetic_high_byte,
       sizeof(arithmetic_high_byte), SHELL_STATUS_ERROR, 0},
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

static uint32_t feature_flags_mask(const shell_feature_flags_t *flags) {
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

static void test_feature_flags(void) {
  printf("\n--- Feature Flags API ---\n");

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
  test_dialect_oracle();
  test_layer1_edge_cases();
  test_layer1_type_values();

  printf("\n=== LAYER 2: INTERACTION TESTS (~100 tests) ===\n");
  test_layer2_complex_sequences();
  test_layer2_redirects();
  test_layer2_mixed_commands();

  printf("\n=== LAYER 3: LARGE/COMPLEX TESTS (~100 tests) ===\n");
  test_complex_case_matrix();

  printf("\n=== ADDITIONAL LAYER 1 TESTS ===\n");
  test_layer1_special_chars();

  printf("\n=== ADDITIONAL LAYER 3 TESTS ===\n");
  test_layer3_stress_sequential();
  test_layer3_boundary_edge();
  test_layer3_feature_exhaustiveness();

  printf("\n=== FEATURE FLAGS API TESTS ===\n");
  test_feature_flags();

  test_fast_parser_limitations();

  test_strict_mode();
  test_nested_heredoc_rejection();
  test_dialect_boundary_matrix();

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
