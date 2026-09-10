#include "../src/shell_source_internal.h"
#include "../src/shell_tokenizer_full_internal.h"
#include "shell_abstract.h"
#include "shell_depgraph.h"
#include "shell_processor.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include "shell_transform.h"
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
                             uint32_t feature) {
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
  uint32_t required_features;
  uint32_t forbidden_features;
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
      SHELL_FEAT_GROUP | SHELL_FEAT_BACKGROUND | SHELL_FEAT_EXTGLOB |
      SHELL_FEAT_ANSI_C_QUOTE | SHELL_FEAT_ARRAY | SHELL_FEAT_NAMED_FD |
      SHELL_FEAT_COMBINED_REDIRECT;
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
        !valid_command_type(range->type) ||
        (range->features & ~all_features) != 0 ||
        view != input + range->start || length != range->len ||
        copied != expected_copy || memcmp(copy, view, expected_copy) != 0 ||
        copy[copied] != '\0' || isspace((unsigned char)input[range->start]) ||
        isspace((unsigned char)input[range->start + range->len - 1]))
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
         group->kind != SHELL_GROUP_SUBSHELL) ||
        (group->modifiers & ~SHELL_CMD_MOD_PIPE_NEGATED) != 0 ||
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

void test_comment_boundaries(void) {
  printf("\n--- Comment Boundaries ---\n");

  static const struct {
    const char *input;
    uint32_t count;
    uint32_t starts[2];
    uint32_t lengths[2];
    uint16_t types[2];
  } cases[] = {
      {"# <(printf data)", 0, {0, 0}, {0, 0}, {0, 0}},
      {"# unmatched ' and $(not parsed)", 0, {0, 0}, {0, 0}, {0, 0}},
      {"# ignored\nprintf visible",
       1,
       {sizeof("# ignored\n") - 1, 0},
       {sizeof("printf visible") - 1, 0},
       {SHELL_TYPE_SEMICOLON, 0}},
      {"printf one; # <(producer)",
       1,
       {0, 0},
       {sizeof("printf one") - 1, 0},
       {SHELL_TYPE_SIMPLE, 0}},
      {"printf one\n# ignored\nprintf two",
       2,
       {0, sizeof("printf one\n# ignored\n") - 1},
       {sizeof("printf one") - 1, sizeof("printf two") - 1},
       {SHELL_TYPE_SIMPLE, SHELL_TYPE_SEMICOLON}},
  };

  for (unsigned strict = 0; strict <= 1; strict++) {
    shell_limits_t limits = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = strict != 0};
    bool valid = true;
    for (size_t i = 0; valid && i < sizeof(cases) / sizeof(cases[0]); i++) {
      shell_parse_result_t result = {0};
      shell_error_t error = shell_parse_fast(
          cases[i].input, strlen(cases[i].input), &limits, &result);
      valid = error == SHELL_OK && result.status == SHELL_STATUS_OK &&
              result.count == cases[i].count &&
              result_invariants(cases[i].input, strlen(cases[i].input), error,
                                &result);
      for (uint32_t command = 0; valid && command < result.count; command++)
        valid = result.cmds[command].start == cases[i].starts[command] &&
                result.cmds[command].len == cases[i].lengths[command] &&
                result.cmds[command].type == cases[i].types[command] &&
                result.cmds[command].features == SHELL_FEAT_NONE;
    }
    test(strict ? "Comment boundaries in strict mode"
                : "Comment boundaries in permissive mode",
         valid);
  }
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
      {"tab-stripping delimiter", "cat <<- EOF", 2, NO_CHECK, NO_CHECK,
       NO_CHECK, 0},
      {"single-quoted delimiter", "cat << 'EOF'", 2, NO_CHECK, NO_CHECK,
       NO_CHECK, 0},
      {"double-quoted delimiter", "cat << \"EOF\"", 2, NO_CHECK, NO_CHECK,
       NO_CHECK, 0},
      {"multiple heredocs", "cat << A << B", 3, NO_CHECK, NO_CHECK, NO_CHECK,
       0},
      {"variable content", "cat << EOF\necho $VAR\nEOF", 2, NO_CHECK, NO_CHECK,
       NO_CHECK, 0},
      {"glob content", "grep pattern << END\n*.txt\nEND", 2, NO_CHECK, NO_CHECK,
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
      {"heredoc bracket content", "cat << EOF\n[content]\nEOF", 2, NO_CHECK, 0,
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
      {"odd escaped substitution", "echo \\$(id)", 1, NO_CHECK, 0, 0, 0,
       SHELL_FEAT_SUBSHELL},
      {"even escaped substitution", "echo \\\\$(id)", 1, NO_CHECK, 0, 0,
       SHELL_FEAT_SUBSHELL, 0},
      {"first-command process substitution", "cat <(id)", 1, 0,
       SHELL_TYPE_SUBSTITUTION, 0, SHELL_FEAT_PROCESS_SUB, 0},
      {"process substitution after AND", "echo ok && cat <(id)", 2, 1,
       SHELL_TYPE_AND, 0, SHELL_FEAT_PROCESS_SUB, 0},
      {"redirect target output process substitution", "printf value 2> >(cat)",
       1, 0, SHELL_TYPE_SUBSTITUTION, 0, SHELL_FEAT_PROCESS_SUB, 0},
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
      {"here-string quoted escape", "cmd <<< \"two\\\" words\"", 2, 1,
       SHELL_TYPE_HERESTRING, 1, SHELL_FEAT_HERESTRING, 0},
      {"here-string escaped space", "cmd <<< two\\ words", 2, 1,
       SHELL_TYPE_HERESTRING, 1, SHELL_FEAT_HERESTRING, 0},
      {"here-string command substitution", "cmd <<< $(printf one)", 2, 1,
       SHELL_TYPE_HERESTRING, 1, SHELL_FEAT_HERESTRING, 0},
      {"here-string file command substitution", "cmd <<< $(</tmp/input)", 2, 1,
       SHELL_TYPE_HERESTRING, 1, SHELL_FEAT_HERESTRING, 0},
      {"here-string backtick substitution", "cmd <<< `printf one`", 2, 1,
       SHELL_TYPE_HERESTRING, 1, SHELL_FEAT_HERESTRING, 0},
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

  extract(
      "cd /workspace && { sleep 2; printf 'q'; } | ./clock > /tmp/clock.out",
      &metadata);
  test("POSIX brace group retains four simple commands",
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

  extract("{( echo )}", &metadata);
  test("Nested brace descriptors preserve parent and command spans",
       metadata.count == 1 && metadata.group_count == 2 &&
           metadata.groups[0].kind == SHELL_GROUP_BRACE &&
           metadata.groups[0].parent == UINT16_MAX &&
           metadata.groups[0].first_command == 0 &&
           metadata.groups[0].command_count == 1 &&
           metadata.groups[1].kind == SHELL_GROUP_SUBSHELL &&
           metadata.groups[1].parent == 0 &&
           metadata.groups[1].first_command == 0 &&
           metadata.groups[1].command_count == 1);

  extract("{ cat; cat; } <<< value", &metadata);
  test("Group here-strings do not create synthetic fast-parser stages",
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
  shell_limits_t limits = {.strict_mode = true};

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
    test(cases[i].name, valid);
  }

  shell_parse_result_t arithmetic_after_separator = {0};
  limits.strict_mode = true;
  test("strict accepts arithmetic command after separator",
       shell_parse_fast("foo; ((1))", strlen("foo; ((1))"), &limits,
                        &arithmetic_after_separator) == SHELL_OK &&
           arithmetic_after_separator.status == SHELL_STATUS_OK &&
           arithmetic_after_separator.count == 2);
}

static void test_strict_heredoc_completion(void) {
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
                                 "A\r\n"
                                 "\ttwo\r\n"
                                 "\tB\r\n";
  shell_parse_result_t result = {0};
  valid = valid &&
          shell_parse_fast(complete, sizeof(complete) - 1, &limits, &result) ==
              SHELL_OK &&
          result.status == SHELL_STATUS_OK;
  static const char ansi_complete[] = "cat <<$'EO\\x46' <<-$'B'\r\n"
                                      "one\r\n"
                                      "EOF\r\n"
                                      "\ttwo\r\n"
                                      "\tB\r\n";
  memset(&result, 0, sizeof(result));
  valid = valid &&
          shell_parse_fast(ansi_complete, sizeof(ansi_complete) - 1, &limits,
                           &result) == SHELL_OK &&
          result.status == SHELL_STATUS_OK;
  test("Strict mode validates quoted, tab-stripped heredoc terminators", valid);
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

  static const char *const valid_cases[] = {
      "echo $(cat <<EOF\n)\nEOF\n)",
      "echo $(cat <<E'OF'\n)\nEOF\n)",
      "cat <(cat <<EOF\n)\nEOF\n)",
  };
  for (size_t i = 0; i < sizeof(valid_cases) / sizeof(valid_cases[0]); i++) {
    shell_limits_t limits = {SHELL_MAX_SUBCOMMANDS, true};
    shell_parse_result_t result = {0};
    shell_error_t error = shell_parse_fast(
        valid_cases[i], strlen(valid_cases[i]), &limits, &result);
    char name[96];
    snprintf(name, sizeof(name), "nested heredoc accepted (%s)",
             valid_cases[i]);
    test(name, error == SHELL_OK && result.status == SHELL_STATUS_OK &&
                   result.count == 1);
  }
}

static bool make_nested_heredoc_substitution(char *command, size_t capacity,
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

static void test_substitution_comment_and_heredoc_capacity(void) {
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
    test(comment_cases[i].name,
         error == comment_cases[i].expected &&
             (error != SHELL_OK ||
              (result.status == SHELL_STATUS_OK && result.count == 1)));
  }

  for (int process_substitution = 0; process_substitution <= 1;
       process_substitution++) {
    char command[512];
    shell_parse_result_t result = {0};
    bool built = make_nested_heredoc_substitution(command, sizeof(command),
                                                  process_substitution != 0);
    shell_error_t error =
        built ? shell_parse_fast(command, strlen(command), &limits, &result)
              : SHELL_EPARSE;
    test(process_substitution
             ? "nested process substitution accepts nine heredocs"
             : "nested command substitution accepts nine heredocs",
         built && error == SHELL_OK && result.status == SHELL_STATUS_OK &&
             result.count == 1);
  }
}

static void test_source_scanner_contract(void) {
  printf("\n--- Shared Source Scanner Contract ---\n");
  static const char lines[] = "one\r\ntwo\nlast";
  test("source scanner recognizes CRLF and final physical lines",
       shell_source_line_end(lines, sizeof(lines) - 1, 0) == 4 &&
           shell_source_line_content_end(lines, sizeof(lines) - 1, 0) == 3 &&
           shell_source_next_line(lines, sizeof(lines) - 1, 0) == 5 &&
           shell_source_line_end(lines, sizeof(lines) - 1, 5) == 8 &&
           shell_source_next_line(lines, sizeof(lines) - 1, 9) ==
               sizeof(lines) - 1);

  static const char comment[] = "x # comment";
  test("source scanner recognizes only shell-word comment boundaries",
       shell_source_comment_starts("#comment", 8, 0) &&
           shell_source_comment_starts(comment, sizeof(comment) - 1, 2) &&
           shell_source_comment_starts("x;#comment", 10, 2) &&
           shell_source_comment_starts("x|#comment", 10, 2) &&
           !shell_source_comment_starts("word#literal", 12, 4) &&
           !shell_source_comment_starts(NULL, 0, 0));

  static const char quoted[] = "\"one \\\"two\\\"\"";
  test("source scanner skips quoted text and quoted escapes",
       shell_source_skip_quoted_text(quoted, sizeof(quoted) - 1, 0, '"') ==
               sizeof(quoted) - 1 &&
           shell_source_skip_quoted_text("'unfinished", 11, 0, '\'') == 11);

  shell_source_pending_heredoc_t pending = {0};
  size_t position = 0;
  static const char delimiter[] = "- \t\"E\"'O'\\F rest";
  bool parsed = shell_source_parse_heredoc_delimiter(
      delimiter, sizeof(delimiter) - 1, &position, &pending);
  test(
      "source scanner decodes quoted and tab-stripped heredoc delimiters",
      parsed && pending.strip_tabs && position < sizeof(delimiter) - 1 &&
          shell_source_line_is_heredoc_delimiter("\tEOF\r\n", 6, 0, &pending) &&
          !shell_source_line_is_heredoc_delimiter("\tEOG\n", 5, 0, &pending));
  position = 0;
  static const char escaped_delimiter[] = "\"E\\\"F\"";
  static const char retained_backslash_delimiter[] = "\"E\\qF\"";
  static const char empty_delimiter[] = "''";
  shell_source_pending_heredoc_t escaped_pending = {0};
  shell_source_pending_heredoc_t retained_backslash_pending = {0};
  shell_source_pending_heredoc_t empty_pending = {0};
  shell_source_pending_heredoc_t dangling_pending = {
      .word = "\\", .word_length = 1, .strip_tabs = false};
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
  test("source scanner handles escaped delimiter bytes and rejects dangling "
       "ones",
       escaped_parsed &&
           shell_source_line_is_heredoc_delimiter("E\"F\n", 4, 0,
                                                  &escaped_pending) &&
           retained_backslash_parsed &&
           shell_source_line_is_heredoc_delimiter(
               "E\\qF\n", 5, 0, &retained_backslash_pending) &&
           empty_parsed &&
           shell_source_line_is_heredoc_delimiter("\n", 1, 0, &empty_pending) &&
           !shell_source_line_is_heredoc_delimiter("\\\n", 2, 0,
                                                   &dangling_pending));
  static const char ansi_delimiter[] = "$'EO\\x46'";
  static const char ansi_nul_delimiter[] = "$'E\\0F'";
  shell_source_pending_heredoc_t ansi_pending = {0};
  shell_source_pending_heredoc_t ansi_nul_pending = {0};
  position = 0;
  bool ansi_parsed = shell_source_parse_heredoc_delimiter(
      ansi_delimiter, sizeof(ansi_delimiter) - 1, &position, &ansi_pending);
  position = 0;
  bool ansi_nul_parsed = shell_source_parse_heredoc_delimiter(
      ansi_nul_delimiter, sizeof(ansi_nul_delimiter) - 1, &position,
      &ansi_nul_pending);
  test("source scanner decodes ANSI-C heredoc delimiters",
       ansi_parsed && shell_source_heredoc_delimiter_is_quoted(&ansi_pending) &&
           shell_source_line_is_heredoc_delimiter("EOF\n", 4, 0,
                                                  &ansi_pending) &&
           ansi_nul_parsed &&
           shell_source_line_is_heredoc_delimiter("E\n", 2, 0,
                                                  &ansi_nul_pending) &&
           !shell_source_line_is_heredoc_delimiter("EF\n", 3, 0,
                                                   &ansi_nul_pending));
  position = 0;
  test(
      "source scanner rejects malformed heredoc delimiters",
      !shell_source_parse_heredoc_delimiter("-", 1, &position, &pending) &&
          !shell_source_parse_heredoc_delimiter("\\", 1, &position, &pending) &&
          !shell_source_parse_heredoc_delimiter("'EOF", 4, &position,
                                                &pending));

  static const char sequence[] =
      "cat <<<'not a document' <<E'OF' <<-\\D'ONE'\r\n"
      "one\r\n"
      "EOF\r\n"
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
  test("source scanner skips FIFO mixed-quote heredoc bodies",
       skipped && complete && sequence_after == (size_t)(trailing - sequence));

  static const char *const opaque_header_cases[] = {
      "cat <<EOF \\x\nbody\nEOF\n",
      "cat <<EOF 'ignored'\nbody\nEOF\n",
      "cat <<EOF # ignored\nbody\nEOF\n",
      "cat <<EOF $((1 << 2))\nbody\nEOF\n",
      "cat <<EOF $(printf value)\nbody\nEOF\n",
      "cat <<EOF <<<word\nbody\nEOF\n",
  };
  bool opaque_headers = !shell_source_heredoc_delimiter_is_quoted(NULL);
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
  test("source scanner keeps opaque header syntax out of heredoc matching",
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
  test("source scanner distinguishes incomplete heredoc bodies",
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
  test("source scanner keeps nested data opaque while balancing parentheses",
       balanced_contract);

  size_t after = 0;
  test(
      "source scanner balances arithmetic expansions and rejects bad starts",
      shell_source_skip_arithmetic_expansion("$((1 + $(printf 2)))", 20, 0,
                                             &after) &&
          after == 20 &&
          shell_source_skip_arithmetic_expansion(
              "$(( 'x' + 2))", strlen("$(( 'x' + 2))"), 0, &after) &&
          !shell_source_skip_arithmetic_expansion("$((1 + 2)", 10, 0, &after) &&
          !shell_source_skip_arithmetic_expansion("(1 + 2)", 7, 0, &after));
  test(
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
  test("source scanner keeps shell words intact and rejects incomplete ones",
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
  test(
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
  test("source scanner recognizes non-structural glob bracket candidates",
       bracket_contract &&
           !shell_source_skip_glob_bracket(NULL, 0, 0, &after) &&
           !shell_source_skip_glob_bracket("[a b]", 5, 0, &after) &&
           !shell_source_skip_glob_bracket("[[:alpha:]", 10, 0, &after) &&
           !shell_source_skip_glob_bracket("[[:alpha", 8, 0, &after) &&
           !shell_source_skip_glob_bracket("[a|b]", 5, 0, &after) &&
           !shell_source_skip_glob_bracket("[[:|:]]", 7, 0, &after) &&
           !shell_source_skip_glob_bracket("[a&&b]", 6, 0, &after) &&
           !shell_source_skip_glob_bracket("[", 1, 0, &after));

  test("source scanner keeps extglob alternatives inside one word",
       shell_source_skip_extglob("@(left|right)", 13, 0, &after) &&
           after == 13 &&
           shell_source_skip_extglob("prefix@(left|right)suffix", 25, 6,
                                     &after) &&
           after == 19 && !shell_source_skip_extglob(NULL, 0, 0, &after) &&
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
  test("source scanner preserves real shell-word fragments in word scanners",
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
  test("source scanner leaves brace and bracket operators structural",
       structural_word_contract);

  test("source scanner rejects incomplete parameter words consistently",
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
      !shell_source_redirect_list_before_group(NULL, 0, 0);
  bool rejects_missing_pending_document =
      !shell_source_skip_pending_heredoc_bodies(NULL, 0, 0, NULL, 0,
                                                &word_after);
  test("source scanner rejects invalid redirect and document boundaries",
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
  test("source scanner keeps complete redirect operands intact",
       redirect_contract);
}

static void test_arithmetic_shift_heredoc_boundary(void) {
  printf("\n--- Arithmetic Shift Heredoc Boundary ---\n");
  static const struct {
    const char *input;
    uint32_t command_count;
    uint32_t required_features;
  } cases[] = {
      {"echo $((1 << 2))", 1, SHELL_FEAT_ARITH},
      {"{ echo $((1 << 2)); }", 1, SHELL_FEAT_ARITH},
      {"echo $(printf '%s' $((1 << 2)))", 1,
       SHELL_FEAT_ARITH | SHELL_FEAT_SUBSHELL},
      {"cat <(printf '%s' $((1 << 2)))", 1,
       SHELL_FEAT_ARITH | SHELL_FEAT_PROCESS_SUB},
      {"echo $(( (1 << 2) + $((3 << 1)) ))", 1, SHELL_FEAT_ARITH},
      {"echo $(printf '%s' $(( $(printf 1) + (1 << 2) )))", 1,
       SHELL_FEAT_ARITH | SHELL_FEAT_SUBSHELL},
      {"echo >$((1 << 2))", 1, SHELL_FEAT_ARITH},
  };
  shell_limits_t limits = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                           .strict_mode = true};
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t result = {0};
    shell_error_t error = shell_parse_fast(
        cases[i].input, strlen(cases[i].input), &limits, &result);
    valid = valid && error == SHELL_OK && result.status == SHELL_STATUS_OK &&
            result.count == cases[i].command_count &&
            (result.cmds[0].features & cases[i].required_features) ==
                cases[i].required_features;
  }

  /* The arithmetic shift must not suppress genuine heredoc completion
   * checks that follow it. */
  static const char completed_heredoc[] = "echo $((1 << 2)) <<EOF\nbody\nEOF\n";
  shell_parse_result_t result = {0};
  valid = valid &&
          shell_parse_fast(completed_heredoc, sizeof(completed_heredoc) - 1,
                           &limits, &result) == SHELL_OK &&
          result.status == SHELL_STATUS_OK;

  static const char incomplete_heredoc[] = "echo $((1 << 2)) <<EOF\nbody\n";
  memset(&result, 0, sizeof(result));
  valid = valid &&
          shell_parse_fast(incomplete_heredoc, sizeof(incomplete_heredoc) - 1,
                           &limits, &result) == SHELL_EPARSE &&
          result.status == SHELL_STATUS_ERROR;
  test("Arithmetic shifts remain opaque to heredoc scanning", valid);
}

static void test_dialect_boundary_matrix(void) {
  printf("\n--- Combined Redirect Boundary ---\n");
  static const char *cases[] = {"cmd &>file", "cmd &>>file"};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t result = {0};
    shell_error_t error =
        shell_parse_fast(cases[i], strlen(cases[i]), NULL, &result);
    char name[96];
    snprintf(name, sizeof(name), "accept combined redirect: %s", cases[i]);
    test(name, error == SHELL_OK && result.status == SHELL_STATUS_OK &&
                   result.count == 1 &&
                   (result.cmds[0].features & SHELL_FEAT_COMBINED_REDIRECT));
  }
}

static void test_incomplete_control_delimiters(void) {
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
    test(name, error == SHELL_EPARSE && result.status == SHELL_STATUS_ERROR);
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

static void test_group_descriptor_limits(void) {
  char command[(SHELL_MAX_GROUPS + 1) * 5 + 4];
  size_t length = 0;
  for (uint32_t i = 0; i < SHELL_MAX_GROUPS; i++) {
    memcpy(command + length, "{ ", 2);
    length += 2;
  }
  command[length++] = ':';
  for (uint32_t i = 0; i < SHELL_MAX_GROUPS; i++) {
    memcpy(command + length, "; }", 3);
    length += 3;
  }
  command[length] = '\0';

  shell_parse_result_t result = {0};
  shell_error_t error = shell_parse_fast(command, length, NULL, &result);
  test("Exactly SHELL_MAX_GROUPS nested brace descriptors succeed",
       error == SHELL_OK && result.group_count == SHELL_MAX_GROUPS &&
           result.count == 1);

  memmove(command + 2, command, length + 1);
  memcpy(command, "{ ", 2);
  length += 2;
  memcpy(command + length, "; }", 3);
  length += 3;
  command[length] = '\0';
  memset(&result, 0, sizeof(result));
  error = shell_parse_fast(command, length, NULL, &result);
  test("One more nested brace group is rejected without overflowing",
       error == SHELL_EPARSE && result.group_count <= SHELL_MAX_GROUPS &&
           result.status == SHELL_STATUS_ERROR);
}

static void test_io_number_bounds(void) {
  static const char maximum[] = "cat 2147483647<<<value";
  static const char overflow[] = "cat 2147483648<<<value";
  static const char attached_word[] = "cat2147483647<<<value";
  shell_parse_result_t parsed = {0};
  bool valid = shell_parse_fast(maximum, sizeof(maximum) - 1, NULL, &parsed) ==
                   SHELL_OK &&
               parsed.count == 2 && parsed.cmds[0].start == 0 &&
               parsed.cmds[0].len == strlen("cat") &&
               parsed.cmds[0].type == SHELL_TYPE_SIMPLE;

  memset(&parsed, 0, sizeof(parsed));
  valid = valid &&
          shell_parse_fast(overflow, sizeof(overflow) - 1, NULL, &parsed) ==
              SHELL_OK &&
          parsed.count == 2 && parsed.cmds[0].start == 0 &&
          parsed.cmds[0].len == strlen("cat 2147483648") &&
          parsed.cmds[0].type == SHELL_TYPE_SIMPLE;
  memset(&parsed, 0, sizeof(parsed));
  valid = valid &&
          shell_parse_fast(attached_word, sizeof(attached_word) - 1, NULL,
                           &parsed) == SHELL_OK &&
          parsed.count == 2 && parsed.cmds[0].start == 0 &&
          parsed.cmds[0].len == strlen("cat2147483647") &&
          parsed.cmds[0].type == SHELL_TYPE_SIMPLE;
  test("Fast parser keeps overflowing io_numbers as ordinary words", valid);
}

static void test_source_io_number_contract(void) {
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
  test("Shared io_number parser preserves fd bounds and redirect syntax",
       valid);
}

static void test_quoted_heredoc_delimiter_fast_ranges(void) {
  static const struct {
    const char *name;
    const char *input;
    const char *marker;
  } cases[] = {
      {"quoted whitespace delimiter",
       "cat <<\"A B\"\nbody\nA B\nprintf after\n", "<<\"A B\""},
      {"escaped whitespace delimiter", "cat <<A\\ B\nbody\nA B\nprintf after\n",
       "<<A\\ B"},
  };
  shell_limits_t strict = {
      .max_subcommands = SHELL_MAX_SUBCOMMANDS,
      .strict_mode = true,
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t parsed = {0};
    bool marker_found = false;
    bool command_after_found = false;
    bool body_became_command = false;
    valid = valid && shell_parse_fast(cases[i].input, strlen(cases[i].input),
                                      &strict, &parsed) == SHELL_OK;
    for (uint32_t range = 0; range < parsed.count; range++) {
      const shell_range_t *current = &parsed.cmds[range];
      const char *start = cases[i].input + current->start;
      marker_found =
          marker_found || (current->type == SHELL_TYPE_HEREDOC &&
                           current->len == strlen(cases[i].marker) &&
                           memcmp(start, cases[i].marker, current->len) == 0);
      command_after_found = command_after_found ||
                            (current->len == strlen("printf after") &&
                             memcmp(start, "printf after", current->len) == 0);
      body_became_command =
          body_became_command ||
          (current->len == strlen("body") && memcmp(start, "body", 4) == 0) ||
          (current->len == strlen("B") && memcmp(start, "B", 1) == 0);
    }
    valid =
        valid && marker_found && command_after_found && !body_became_command;
  }
  test("Fast parser keeps complete quoted heredoc delimiter ranges", valid);
}

static void test_group_context_on_redirect_and_operator_ranges(void) {
  static const struct {
    const char *input;
    uint32_t count;
  } cases[] = {
      {"{ cat <<<value; printf after; }", 3},
      {"{ cat <<EOF; printf after; }\npayload\nEOF\n", 3},
      {"{ cat || printf after; }", 2},
      {"{ cat | printf after; }", 2},
  };
  shell_limits_t strict = {
      .max_subcommands = SHELL_MAX_SUBCOMMANDS,
      .strict_mode = true,
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t parsed = {0};
    valid = valid &&
            shell_parse_fast(cases[i].input, strlen(cases[i].input), &strict,
                             &parsed) == SHELL_OK &&
            parsed.count == cases[i].count;
    for (uint32_t range = 0; valid && range < parsed.count; range++)
      valid = parsed.cmds[range].group_depth == 1 &&
              parsed.cmds[range].group_kinds == SHELL_GROUP_BRACE;
  }
  test("Fast parser preserves group context across redirect ranges and "
       "operators",
       valid);
}

/* A physical linebreak after a list connector belongs to the pending stage,
 * rather than becoming an intervening semicolon. Exercise comments, CRLF, and
 * escaped line endings because each reaches the same source-span boundary by
 * a different scanner path. */
static void test_list_connector_continuation_metadata(void) {
  static const struct {
    const char *name;
    const char *input;
    uint16_t type;
    shell_pipe_mode_t pipe_mode;
  } cases[] = {
      {"newline pipeline", "left |\nright", SHELL_TYPE_PIPELINE,
       SHELL_PIPE_MODE_STDOUT},
      {"CRLF pipe-both", "left |&\r\nright", SHELL_TYPE_PIPELINE,
       SHELL_PIPE_MODE_STDOUT_AND_STDERR},
      {"commented pipeline", "left | # note\nright", SHELL_TYPE_PIPELINE,
       SHELL_PIPE_MODE_STDOUT},
      {"commented pipe-both", "left |& # note\r\nright", SHELL_TYPE_PIPELINE,
       SHELL_PIPE_MODE_STDOUT_AND_STDERR},
      {"blank commented pipeline", "left |\n\n # note\n right",
       SHELL_TYPE_PIPELINE, SHELL_PIPE_MODE_STDOUT},
      {"escaped newline pipeline", "left | \\\nright", SHELL_TYPE_PIPELINE,
       SHELL_PIPE_MODE_STDOUT},
      {"escaped CRLF pipe-both", "left |& \\\r\nright", SHELL_TYPE_PIPELINE,
       SHELL_PIPE_MODE_STDOUT_AND_STDERR},
      {"newline AND", "left &&\nright", SHELL_TYPE_AND, SHELL_PIPE_MODE_NONE},
      {"commented OR", "left || # note\nright", SHELL_TYPE_OR,
       SHELL_PIPE_MODE_NONE},
      {"ordinary newline remains sequential", "left\nright",
       SHELL_TYPE_SEMICOLON, SHELL_PIPE_MODE_NONE},
  };
  static const char *const malformed[] = {
      "left | # note",
      "left |& \\\n",
      "left && # note",
      "left ||\r\n",
  };
  shell_limits_t strict = {
      .max_subcommands = SHELL_MAX_SUBCOMMANDS,
      .strict_mode = true,
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t parsed = {0};
    valid = valid &&
            shell_parse_fast(cases[i].input, strlen(cases[i].input), &strict,
                             &parsed) == SHELL_OK &&
            parsed.count == 2 && parsed.cmds[1].type == cases[i].type &&
            parsed.cmds[1].pipe_input_mode == cases[i].pipe_mode;
  }
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
    shell_parse_result_t parsed = {0};
    valid = valid &&
            shell_parse_fast(malformed[i], strlen(malformed[i]), &strict,
                             &parsed) == SHELL_EPARSE &&
            parsed.status == SHELL_STATUS_ERROR;
  }
  test("Fast parser preserves continued list connector metadata", valid);
}

/* Only shell syntax that actually quotes its contents may hide a list
 * operator. Exercise those boundaries, and the complementary ordinary brace
 * and bracket cases, through every public parsing surface. */
static void test_word_fragment_operator_boundaries(void) {
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
          graph.edge_count == 0;
      shell_commands_free(commands, command_count);
      shell_processed_commands_free(&processed);
    }
  }
  test("Quoted and expansion word fragments keep operators out of list parsing",
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
  test("Brace and bracket text leave list operators structural", structural);

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
  test("Redirect operands preserve only true shell-word syntax",
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
  test("Processed command limits clear partial output", limits_are_atomic);

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
  test("Word fragments reject incomplete structural subsyntax",
       rejects_malformed);
}

/* `!` is a counted pipeline modifier. It may cross horizontal whitespace and
 * escaped physical continuations, but never a raw newline or comment. */
static void test_pipeline_negation_trivia_metadata(void) {
  static const struct {
    const char *input;
    uint32_t count;
    uint32_t negation_count;
    shell_pipe_mode_t pipe_mode;
  } cases[] = {
      {"! \\\nprintf x", 1, 1, SHELL_PIPE_MODE_NONE},
      {"! ! printf x |& cat", 2, 2, SHELL_PIPE_MODE_STDOUT_AND_STDERR},
      {"! ! ! \\\r\nprintf x | cat", 2, 3, SHELL_PIPE_MODE_STDOUT},
  };
  shell_limits_t strict = {
      .max_subcommands = SHELL_MAX_SUBCOMMANDS,
      .strict_mode = true,
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t parsed = {0};
    valid = valid &&
            shell_parse_fast(cases[i].input, strlen(cases[i].input), &strict,
                             &parsed) == SHELL_OK &&
            parsed.count == cases[i].count;
    for (uint32_t range = 0; valid && range < parsed.count; range++)
      valid =
          (parsed.cmds[range].modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0 &&
          parsed.cmds[range].pipeline_negation_count == cases[i].negation_count;
    if (valid && parsed.count > 1)
      valid = parsed.cmds[1].type == SHELL_TYPE_PIPELINE &&
              parsed.cmds[1].pipe_input_mode == cases[i].pipe_mode;
  }

  static const char negated_group[] = "! ! { printf x; } | cat";
  shell_parse_result_t grouped = {0};
  valid = valid &&
          shell_parse_fast(negated_group, sizeof(negated_group) - 1, &strict,
                           &grouped) == SHELL_OK &&
          grouped.count == 2 && grouped.group_count == 1 &&
          (grouped.groups[0].modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0 &&
          grouped.groups[0].pipeline_negation_count == 2 &&
          (grouped.cmds[1].modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0 &&
          grouped.cmds[1].pipeline_negation_count == 2;

  static const char *const incomplete[] = {
      "!", "! # note\n", "! \\\n", "!\nprintf x", "! !",
  };
  for (size_t i = 0; i < sizeof(incomplete) / sizeof(incomplete[0]); i++) {
    shell_parse_result_t parsed = {0};
    valid = valid &&
            shell_parse_fast(incomplete[i], strlen(incomplete[i]), &strict,
                             &parsed) == SHELL_EPARSE &&
            parsed.status == SHELL_STATUS_ERROR;
  }
  test("Fast parser preserves counted pipeline negation boundaries", valid);
}

/* Document redirects may carry Bash's named descriptor allocator. They are
 * redirect syntax, never an argv fragment, and a bare document redirect can
 * be the pipeline stage modified by one or more leading `!` reserved words. */
static void test_named_document_and_negation_metadata(void) {
  static const struct {
    const char *input;
    uint16_t document_type;
    uint32_t negation_count;
  } cases[] = {
      {"printf x {fd}<<<body", SHELL_TYPE_HERESTRING, 0},
      {"printf x {fd}<<EOF\nbody\nEOF\n", SHELL_TYPE_HEREDOC, 0},
      {"! <<<body", SHELL_TYPE_HERESTRING, 1},
      {"! ! <<EOF\nbody\nEOF\n", SHELL_TYPE_HEREDOC, 2},
      {"! <<<body | cat", SHELL_TYPE_HERESTRING, 1},
      {"{ cat; } {fd}<<<body", SHELL_TYPE_HERESTRING, 0},
      {"{ cat; } {fd}<<EOF\nbody\nEOF\n", SHELL_TYPE_HEREDOC, 0},
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
           (cases[i].negation_count != 0));
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
  test("Fast parser classifies named document redirects and negated document "
       "stages",
       valid);
}

/* The strict fast parser is the shared admission check for every canonical
 * surface. Keep uncommon malformed operator forms here rather than relying on
 * a later tokenizer to reject a partially structured list. */
static void test_strict_operator_boundary_matrix(void) {
  static const char *const malformed[] = {
      "echo @(unterminated",
      "echo value=(unterminated",
      "echo &>",
      "echo &>>",
      "echo > (group)",
      "echo < (group)",
      "echo >|",
      "echo > >out",
      "echo < <in",
      "echo |&",
      "echo | ! next",
      "echo && && next",
      "echo || || next",
      "echo ; ;",
      "echo & &",
      "echo $'unterminated",
      "echo $(unterminated",
      "echo <(unterminated",
      "echo >(unterminated",
      "echo ${unterminated",
      "echo $((unterminated",
      "echo )",
      "echo; }",
      "echo | )",
      "echo { literal; }",
      "echo (cat)",
      "echo ((1))",
  };
  shell_limits_t strict = {
      .max_subcommands = SHELL_MAX_SUBCOMMANDS,
      .strict_mode = true,
  };
  bool valid = true;
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
    shell_parse_result_t result = {0};
    shell_error_t status =
        shell_parse_fast(malformed[i], strlen(malformed[i]), &strict, &result);
    valid = (status == SHELL_EPARSE && result.status == SHELL_STATUS_ERROR) &&
            valid;
  }

  char nested[8 * (SHELL_MAX_SUBCOMMANDS + 1) + sizeof(" echo ")] = {0};
  size_t used = 0;
  for (size_t i = 0; i < SHELL_MAX_SUBCOMMANDS + 1; i++)
    used += (size_t)snprintf(nested + used, sizeof(nested) - used, "{ (");
  used += (size_t)snprintf(nested + used, sizeof(nested) - used, " echo ");
  for (size_t i = 0; i < SHELL_MAX_SUBCOMMANDS + 1; i++)
    used += (size_t)snprintf(nested + used, sizeof(nested) - used, ") ; }");
  shell_parse_result_t result = {0};
  shell_error_t nested_status =
      shell_parse_fast(nested, used, &strict, &result);
  valid = valid && used < sizeof(nested) && nested_status == SHELL_EPARSE &&
          result.status == SHELL_STATUS_ERROR;
  test("Strict parser rejects malformed and over-nested operators", valid);
}

/* These semantic classifiers sit below the public processor adapters. Exercise
 * their quote, expansion, and unsupported-control boundaries directly so the
 * adapters cannot accidentally narrow the lexical contract. */
static void test_semantic_classifier_boundaries(void) {
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
      {"echo \\$(while true; do :; done)", false},
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
      {"de$'clare' -a values", true},
      {"command -$'p' de$'clare' -a values", true},
      {"declare -$'a' values", true},
      {"echo de$'clare' -a values", false},
      {"$tool -a values", false},
      {"typeset map[key]", true},
      {"command -- declare \"arr[$(printf 0)]\"", true},
      {"declare scalar='[literal]'", false},
      {"[[ -f /tmp/x ]]", true},
      {"VALUE=x [[ $VALUE == x ]]", true},
      {"{ [[ -n value ]]; }", true},
      {"echo $( [[ -f /tmp/x ]] )", true},
      {"(( count += 1 ))", true},
      {"! (( 1 ))", true},
      {"{ (( 1 )); }", true},
      {"time echo x", true},
      {"VALUE=x time -p echo x", true},
      {"! time false", true},
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
  valid =
      valid &&
      shell_tokenizer_init(&escaped_glob_state, "[a\\]]", strlen("[a\\]]")) &&
      shell_tokenizer_next(&escaped_glob_state, &escaped_glob) &&
      escaped_glob.type == SHELL_TOKEN_GLOB;
  for (size_t i = 0; i < sizeof(source_cases) / sizeof(source_cases[0]); i++) {
    bool got = shell_tokenizer_has_unsupported_semantics(
        source_cases[i].input, strlen(source_cases[i].input));
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
  test("Semantic classifiers retain quote and expansion boundaries", valid);
}

/* Exercise transformation after tokenization has established source spans.
 * In particular, a short variable spelling expands to a longer display token,
 * so both string and aggregate output limits need independent coverage. */
static void test_transform_contract_boundaries(void) {
  shell_transformed_command_t *transformed =
      (shell_transformed_command_t *)(uintptr_t)1;
  shell_command_t empty = {0};
  shell_token_t invalid = {
      .type = SHELL_TOKEN_COMMAND, .start = NULL, .length = 1, .position = 0};
  shell_command_t malformed = {
      .tokens = &invalid, .token_count = 1, .start_pos = 0, .end_pos = 1};
  shell_token_t variable = {
      .type = SHELL_TOKEN_VARIABLE, .start = "$X", .length = 2, .position = 0};
  shell_command_t command = {
      .tokens = &variable, .token_count = 1, .start_pos = 0, .end_pos = 2};
  const shell_transform_limits_t display_limit = {
      .max_string_bytes = 2,
      .max_total_bytes = SIZE_MAX,
  };
  const shell_transform_limits_t total_limit = {
      .max_string_bytes = SIZE_MAX,
      .max_total_bytes = 20,
  };
  bool valid =
      shell_transform_command(NULL, NULL, &transformed) ==
          SHELL_TRANSFORM_EINPUT &&
      transformed == NULL &&
      shell_transform_command(&empty, NULL, &transformed) ==
          SHELL_TRANSFORM_EINPUT &&
      transformed == NULL &&
      shell_transform_command(&malformed, NULL, &transformed) ==
          SHELL_TRANSFORM_EINPUT &&
      transformed == NULL &&
      shell_transform_command(&command, &display_limit, &transformed) ==
          SHELL_TRANSFORM_EOUTPUT_LIMIT &&
      transformed == NULL &&
      shell_transform_command(&command, &total_limit, &transformed) ==
          SHELL_TRANSFORM_EOUTPUT_LIMIT &&
      transformed == NULL;
  shell_transformed_command_t **commands =
      (shell_transformed_command_t **)(uintptr_t)1;
  size_t count = SIZE_MAX;
  valid = valid &&
          shell_transform_command_line(NULL, 0, NULL, &commands, &count) ==
              SHELL_TRANSFORM_EINPUT &&
          commands == NULL && count == 0 &&
          shell_transform_command_line("echo $X", strlen("echo $X"), NULL, NULL,
                                       &count) == SHELL_TRANSFORM_EINPUT;
  test("Transform contracts retain expansion and output boundaries", valid);
}

static bool stop_after_first_decoded_byte(unsigned char byte,
                                          size_t decoded_offset,
                                          void *context) {
  (void)byte;
  (void)decoded_offset;
  size_t *seen = context;
  (*seen)++;
  return false;
}

/* The word helpers are deliberately byte-oriented: callers supply exact
 * capacity, including when substitutions preserve their source spelling.
 * Check short destinations and early visitors without allocating a temporary
 * decoded string. */
static void test_word_writer_contract_boundaries(void) {
  char destination[16] = {0};
  size_t written = SIZE_MAX;
  size_t seen = 0;
  shell_command_info_t *infos = NULL;
  size_t info_count = 0;
  bool valid =
      shell_visit_decoded_word("word", 4, stop_after_first_decoded_byte, &seen,
                               &written) == SHELL_PROCESS_OK &&
      seen == 1 && written == 1 &&
      shell_write_decoded_word("word", 4, destination, 3, &written) ==
          SHELL_PROCESS_EOUTPUT_LIMIT &&
      written == 0 &&
      shell_measure_processed_word(NULL, 0, &written) == SHELL_PROCESS_EINPUT &&
      written == 0 &&
      shell_write_processed_word(NULL, 0, destination, sizeof(destination),
                                 &written) == SHELL_PROCESS_EINPUT &&
      written == 0 &&
      shell_write_processed_word("$(printf x)", strlen("$(printf x)"),
                                 destination, 1,
                                 &written) == SHELL_PROCESS_EOUTPUT_LIMIT &&
      written == 0 &&
      shell_write_processed_word("x", 1, destination, 0, &written) ==
          SHELL_PROCESS_EOUTPUT_LIMIT &&
      written == 0 &&
      shell_process_command("echo x", strlen("echo x"), NULL, &infos,
                            &info_count) == SHELL_PROCESS_OK &&
      info_count == 1;
  shell_netstring_buffer_t occupied = {
      .data = (unsigned char *)destination,
      .length = 1,
  };
  const shell_process_limits_t tiny = {
      .max_string_bytes = 1,
      .max_total_bytes = 1,
  };
  valid = valid &&
          shell_render_netargv_buffer(&infos[0], NULL, &occupied) ==
              SHELL_PROCESS_EINPUT &&
          shell_render_netargv_buffer(&infos[0], &tiny, &occupied) ==
              SHELL_PROCESS_EINPUT;
  shell_command_infos_free(infos, info_count);
  infos = (shell_command_info_t *)(uintptr_t)1;
  info_count = SIZE_MAX;
  valid = valid &&
          shell_process_command("echo x", strlen("echo x"), &tiny, &infos,
                                &info_count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
          infos == NULL && info_count == 0;
  test("Word writers preserve byte-capacity and visitor contracts", valid);
}

/* Abstraction is a diagnostic adapter, but it still consumes the same lexical
 * spans as canonical processing. Exercise it from both library variants so
 * path, expansion, redirect, and accessor contracts cannot drift. */
static void test_abstract_adapter_contract(void) {
  shell_abstract_command_t *abstracted =
      (shell_abstract_command_t *)(uintptr_t)1;
  const char source[] =
      "printf $HOME /etc/passwd ./relative ~/home *.c $(id) $((1 + 2)) >out";
  shell_abstract_status_t null_status =
      shell_abstract_command_parse(NULL, 0, &abstracted);
  bool null_cleared = abstracted == NULL;
  shell_abstract_status_t malformed_status =
      shell_abstract_command_parse("echo '", strlen("echo '"), &abstracted);
  bool malformed_cleared = abstracted == NULL;
  shell_abstract_status_t parse_status =
      shell_abstract_command_parse(source, sizeof(source) - 1, &abstracted);
  bool valid = null_status == SHELL_ABSTRACT_EINPUT && null_cleared &&
               malformed_status == SHELL_ABSTRACT_EPARSE && malformed_cleared &&
               parse_status == SHELL_ABSTRACT_OK && abstracted != NULL &&
               shell_abstract_command_get_source(abstracted) != NULL &&
               shell_abstract_command_get_display_text(abstracted) != NULL &&
               shell_abstract_command_has_variables(abstracted) &&
               shell_abstract_command_has_paths(abstracted) &&
               shell_abstract_command_has_abs_paths(abstracted) &&
               shell_abstract_command_has_rel_paths(abstracted) &&
               shell_abstract_command_has_home_paths(abstracted) &&
               shell_abstract_command_has_globs(abstracted) &&
               shell_abstract_command_has_cmd_subst(abstracted) &&
               shell_abstract_command_has_arithmetic(abstracted) &&
               shell_abstract_command_has_redirects(abstracted);
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
  valid = valid && shell_classify_raw_token(NULL, 0) == SHELL_TOKEN_END &&
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
  test("Abstract adapter preserves lexical and accessor contracts", valid);
}

/* A redirect or list operator alone is not an executable fast-parser range.
 * Exercise every compact spelling here so the no-command rejection stays
 * separate from valid redirection operands such as `cat <input`. */
static void test_operator_only_rejection(void) {
  static const char *const cases[] = {
      "<", ">", "<<", ">>", "<<<", ";", "&&", "||", "|", "|&", "&", "&>", "&>>",
  };
  bool rejected = true;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_parse_result_t result = {0};
    rejected = rejected &&
               shell_parse_fast(cases[i], strlen(cases[i]), NULL, &result) ==
                   SHELL_EPARSE &&
               result.count == 0;
  }
  test("Fast parser rejects operator-only input", rejected);
}

/* These inputs reach the fast structural scanner after lexical validation but
 * cannot form a strict canonical command. Keep their rejection contracts
 * explicit: they prevent incomplete expansions or malformed group placement
 * from being recovered as ordinary words. */
static void test_strict_structural_rejection(void) {
  static const char *const cases[] = {
      "${broken",
      "\\$(broken",
      ">output { :; }",
      "{ echo",
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
              "strict structural case accepted: %s (status=%d, "
              "parser-status=%d)\n",
              cases[i], status, result.status);
    rejected = rejected && case_rejected;
  }
  test("Strict fast parser rejects malformed structural forms", rejected);
}

/* --- MAIN --- */

int main(void) {
  printf("=== FAST PARSER API TESTS ===\n");
  printf("Testing shell_parse_fast() and related functions\n\n");

  printf("=== LAYER 1: UNIT TESTS (~50 tests) ===\n");
  test_layer1_basic_inputs();
  test_layer1_simple_separators();
  test_comment_boundaries();
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
  test_group_descriptor_limits();
  test_io_number_bounds();
  test_source_io_number_contract();
  test_quoted_heredoc_delimiter_fast_ranges();
  test_group_context_on_redirect_and_operator_ranges();
  test_list_connector_continuation_metadata();
  test_word_fragment_operator_boundaries();
  test_pipeline_negation_trivia_metadata();
  test_named_document_and_negation_metadata();
  test_strict_operator_boundary_matrix();
  test_semantic_classifier_boundaries();
  test_transform_contract_boundaries();
  test_word_writer_contract_boundaries();
  test_abstract_adapter_contract();
  test_operator_only_rejection();
  test_strict_structural_rejection();

  test_fast_parser_limitations();

  test_strict_mode();
  test_strict_heredoc_completion();
  test_nested_heredoc_rejection();
  test_substitution_comment_and_heredoc_capacity();
  test_source_scanner_contract();
  test_arithmetic_shift_heredoc_boundary();
  test_dialect_boundary_matrix();
  test_incomplete_control_delimiters();

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
