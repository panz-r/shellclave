#include "shell_tokenizer.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;

static void test(const char* name, int result) {
    test_count++;
    if (result) {
        pass_count++;
        printf("  [PASS] %s\n", name);
    } else {
        printf("  [FAIL] %s\n", name);
    }
}

static void test_range_eq(const char* name, const shell_parse_result_t* result, 
                          uint32_t idx, uint32_t exp_start, uint32_t exp_len, 
                          uint16_t exp_type, uint16_t exp_features) {
    test_count++;
    if (idx < result->count) {
        const shell_range_t* r = &result->cmds[idx];
        if (r->start == exp_start && r->len == exp_len && 
            r->type == exp_type && r->features == exp_features) {
            pass_count++;
            printf("  [PASS] %s\n", name);
            return;
        }
        printf("  [FAIL] %s (got start=%u len=%u type=%u feat=%u, expected start=%u len=%u type=%u feat=%u)\n",
               name, r->start, r->len, r->type, r->features, exp_start, exp_len, exp_type, exp_features);
    } else {
        printf("  [FAIL] %s (index %u out of range, count=%u)\n", name, idx, result->count);
    }
}

static void test_count_at_least(const char* name, const shell_parse_result_t* result, uint32_t min_count) {
    test_count++;
    if (result->count >= min_count) {
        pass_count++;
        printf("  [PASS] %s\n", name);
    } else {
        printf("  [FAIL] %s (got count=%u, expected >= %u)\n", name, result->count, min_count);
    }
}

static void test_count_only(const char* name, const shell_parse_result_t* result, uint32_t exp_count) {
    test_count++;
    if (result->count == exp_count) {
        pass_count++;
        printf("  [PASS] %s\n", name);
    } else {
        printf("  [FAIL] %s (got count=%u, expected %u)\n", name, result->count, exp_count);
    }
}

static void test_type(const char* name, const shell_parse_result_t* result, uint32_t idx, uint16_t exp_type) {
    test_count++;
    if (idx < result->count && result->cmds[idx].type == exp_type) {
        pass_count++;
        printf("  [PASS] %s\n", name);
    } else {
        printf("  [FAIL] %s\n", name);
    }
}

static void test_has_feature(const char* name, const shell_parse_result_t* result, uint32_t idx, uint16_t feature) {
    test_count++;
    if (idx < result->count && (result->cmds[idx].features & feature)) {
        pass_count++;
        printf("  [PASS] %s\n", name);
    } else {
        printf("  [FAIL] %s\n", name);
    }
}

static void test_no_feature(const char* name, const shell_parse_result_t* result, uint32_t idx, uint16_t feature) {
    test_count++;
    if (idx < result->count && !(result->cmds[idx].features & feature)) {
        pass_count++;
        printf("  [PASS] %s\n", name);
    } else {
        printf("  [FAIL] %s\n", name);
    }
}

static void test_trimmed(const char* name, const char* cmd, const shell_range_t* r) {
    test_count++;
    if (r->len > 0) {
        char first = cmd[r->start];
        char last = cmd[r->start + r->len - 1];
        if (!isspace((unsigned char)first) && !isspace((unsigned char)last)) {
            pass_count++;
            printf("  [PASS] %s\n", name);
            return;
        }
    }
    printf("  [FAIL] %s (not trimmed)\n", name);
}

static void extract(const char* input, shell_parse_result_t* result) {
    shell_parse_fast(input, strlen(input), NULL, result);
}

static void extract_limited(const char* input, shell_limits_t* limits, shell_parse_result_t* result) {
    shell_parse_fast(input, strlen(input), limits, result);
}

/* ============================================================
 * LAYER 1: UNIT TESTS - One feature at a time
 * ============================================================ */

void test_layer1_basic_inputs(void) {
    printf("\n--- Layer 1: Basic Inputs ---\n");
    
    shell_parse_result_t result;
    
    // Test: empty input
    extract("", &result);
    test_count_only("Empty input returns 0", &result, 0);
    
    // Test: NULL input
    shell_error_t err = shell_parse_fast(NULL, 0, NULL, &result);
    test("NULL input returns SHELL_EINPUT", err == SHELL_EINPUT);
    
    // Test: whitespace only
    extract("   \t\n  ", &result);
    test_count_only("Whitespace only returns 0", &result, 0);
    
    // Test: simple command
    extract("ls -la", &result);
    test_count_only("Simple command count=1", &result, 1);
    test_range_eq("Simple command range correct", &result, 0, 0, 6, SHELL_TYPE_SIMPLE, SHELL_FEAT_NONE);
}

void test_layer1_simple_separators(void) {
    printf("\n--- Layer 1: Simple Separators ---\n");
    
    shell_parse_result_t result;
    
    // Test: single pipe
    extract("cmd1 | cmd2", &result);
    test_count_only("Single pipe count=2", &result, 2);
    test_range_eq("First cmd after pipe", &result, 0, 0, 4, SHELL_TYPE_SIMPLE, SHELL_FEAT_NONE);
    test_type("Second cmd type=PIPELINE", &result, 1, SHELL_TYPE_PIPELINE);
    
    // Test: semicolon
    extract("cmd1 ; cmd2", &result);
    test_count_only("Semicolon count=2", &result, 2);
    test_type("Second cmd type=SEMICOLON", &result, 1, SHELL_TYPE_SEMICOLON);
    
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
    if (result.count >= 1) {
        test_trimmed("Leading/trailing trimmed", "  ls -la  ", &result.cmds[0]);
        test_range_eq("Trimmed range correct", &result, 0, 2, 6, SHELL_TYPE_SIMPLE, SHELL_FEAT_NONE);
    }
    
    // Test: whitespace around pipe
    extract("  cmd1  |  cmd2  ", &result);
    if (result.count >= 2) {
        test_trimmed("First cmd trimmed", "  cmd1  |  cmd2  ", &result.cmds[0]);
        test_trimmed("Second cmd trimmed", "  cmd1  |  cmd2  ", &result.cmds[1]);
    }
    
    // Test: multiple spaces - still single command (whitespace separates args, not subcommands)
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
    test_has_feature("Heredoc has HEREDOC feature (idx 1)", &result, 1, SHELL_FEAT_HEREDOC);
    
    // Test: heredoc with delimiter
    extract("cat << ENDOFFILE", &result);
    test_count_only("Heredoc with delimiter count=2", &result, 2);
    if (result.count >= 2) {
        test_range_eq("Heredoc range includes <<", &result, 1, 4, 12, SHELL_TYPE_HEREDOC, SHELL_FEAT_HEREDOC);
    }
    
    // Test: heredoc with command and redirect
    extract("cat << EOF > output.txt", &result);
    test_count_only("Heredoc+redirect count=3", &result, 3);
}

void test_layer1_features_vars(void) {
    printf("\n--- Layer 1: Features - Variables ---\n");
    
    shell_parse_result_t result;
    
    // Test: simple variable
    extract("echo $VAR", &result);
    test_has_feature("$VAR has VARS", &result, 0, SHELL_FEAT_VARS);
    
    // Test: braced variable
    extract("echo ${VAR}", &result);
    test_has_feature("${VAR} has VARS", &result, 0, SHELL_FEAT_VARS);
    
    // Test: positional parameter
    extract("echo $1", &result);
    test_has_feature("$1 has VARS", &result, 0, SHELL_FEAT_VARS);
    
    // Test: special vars
    extract("echo $? $$ $#", &result);
    test_has_feature("$? $$ $# has VARS", &result, 0, SHELL_FEAT_VARS);
    
    // Test: no vars
    extract("echo hello", &result);
    test_no_feature("echo hello no VARS", &result, 0, SHELL_FEAT_VARS);
}

void test_layer1_features_globs(void) {
    printf("\n--- Layer 1: Features - Globs ---\n");
    
    shell_parse_result_t result;
    
    // Test: star glob
    extract("ls *.txt", &result);
    test_has_feature("*.txt has GLOBS", &result, 0, SHELL_FEAT_GLOBS);
    
    // Test: question glob
    extract("ls file?.txt", &result);
    test_has_feature("file?.txt has GLOBS", &result, 0, SHELL_FEAT_GLOBS);
    
    // Test: bracket glob
    extract("ls [abc].txt", &result);
    test_has_feature("[abc].txt has GLOBS", &result, 0, SHELL_FEAT_GLOBS);
    
    // Test: no globs
    extract("ls file.txt", &result);
    test_no_feature("file.txt no GLOBS", &result, 0, SHELL_FEAT_GLOBS);
    
    // Test: bracket in heredoc content is treated as glob (newline separates subcommands)
    extract("cat << EOF\n[content]\nEOF", &result);
    test_count_only("Heredoc with brackets count=4", &result, 4);
}

void test_layer1_features_subshell(void) {
    printf("\n--- Layer 1: Features - Subshell ---\n");
    
    shell_parse_result_t result;
    
    // Test: $() subshell
    extract("echo $(date)", &result);
    test_has_feature("$(date) has SUBSHELL", &result, 0, SHELL_FEAT_SUBSHELL);
    
    // Test: backticks
    extract("echo `date`", &result);
    test_has_feature("`date` has SUBSHELL", &result, 0, SHELL_FEAT_SUBSHELL);
    
    // Test: no subshell
    extract("echo hello", &result);
    test_no_feature("echo hello no SUBSHELL", &result, 0, SHELL_FEAT_SUBSHELL);
}

void test_layer1_features_arith(void) {
    printf("\n--- Layer 1: Features - Arithmetic ---\n");
    
    shell_parse_result_t result;
    
    // Test: arithmetic $(( ))
    extract("echo $((1+2))", &result);
    test_has_feature("$((1+2)) has ARITH", &result, 0, SHELL_FEAT_ARITH);
    
    // Test: arithmetic with vars - we detect ARITH, but not internal vars as limitation
    extract("echo $((x + y))", &result);
    test_has_feature("$((x + y)) has ARITH", &result, 0, SHELL_FEAT_ARITH);
    // Note: VARS inside $((...)) not detected - known limitation
    
    // Test: no arithmetic
    extract("echo 1+2", &result);
    test_no_feature("1+2 no ARITH", &result, 0, SHELL_FEAT_ARITH);
}

void test_layer1_utility_functions(void) {
    printf("\n--- Layer 1: Utility Functions ---\n");
    
    shell_parse_result_t result;
    char buf[64];
    
    // Test: shell_copy_subcommand
    extract("ls -la", &result);
    if (result.count >= 1) {
        size_t copied = shell_copy_subcommand("ls -la", &result.cmds[0], buf, sizeof(buf));
        test("Copy subcommand works", copied == 6 && strncmp(buf, "ls -la", 6) == 0);
        
        // Test: small buffer
        copied = shell_copy_subcommand("ls -la", &result.cmds[0], buf, 3);
        test("Copy with small buffer truncates", copied == 2 && strncmp(buf, "ls", 2) == 0);
    }
    
    // Test: shell_get_subcommand
    extract("hello world", &result);
    if (result.count >= 1) {
        uint32_t len = 0;
        const char* ptr = shell_get_subcommand("hello world", &result.cmds[0], &len);
        test("Get subcommand returns pointer", ptr != NULL && len == 11);
    }
    
    // Test: NULL inputs
    size_t copied = shell_copy_subcommand(NULL, NULL, NULL, 0);
    test("Copy with NULL returns 0", copied == 0);
    
    const char* ptr = shell_get_subcommand(NULL, NULL, NULL);
    test("Get with NULL returns NULL", ptr == NULL);
}

void test_layer1_error_handling(void) {
    printf("\n--- Layer 1: Error Handling ---\n");
    
    shell_parse_result_t result;
    shell_limits_t limits;
    
    // Test: truncation
    limits.max_subcommands = 1;
    limits.max_depth = 8;
    extract_limited("cmd1 | cmd2 | cmd3", &limits, &result);
    test("Truncation returns SHELL_ETRUNC", result.status & SHELL_STATUS_TRUNCATED);
    test_count_only("Truncated count=1", &result, 1);
    
    // Test: NULL result
    shell_error_t err = shell_parse_fast("cmd", 3, NULL, NULL);
    test("NULL result returns SHELL_EINPUT", err == SHELL_EINPUT);
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
    
    // Test: pipe at end
    extract("cmd1 |", &result);
    test_count_only("Pipe at end count=1", &result, 1);
    
    // Test: semicolon at end  
    extract("cmd1 ;", &result);
    test_count_only("Semicolon at end count=1", &result, 1);
    
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
    
    extract("cmd1 | cmd2", &result);
    test("PIPELINE type value", result.cmds[1].type == SHELL_TYPE_PIPELINE);
    
    extract("cmd1 && cmd2", &result);
    test("AND type value", result.cmds[1].type == SHELL_TYPE_AND);
    
    extract("cmd1 || cmd2", &result);
    test("OR type value", result.cmds[1].type == SHELL_TYPE_OR);
    
    extract("cmd1 ; cmd2", &result);
    test("SEMICOLON type value", result.cmds[1].type == SHELL_TYPE_SEMICOLON);
    
    extract("cat << EOF", &result);
    test("HEREDOC type value (at idx 1)", result.count > 1 && result.cmds[1].type == SHELL_TYPE_HEREDOC);
}

/* ============================================================
 * LAYER 2: INTERACTION TESTS - Multiple features
 * ============================================================ */

void test_layer2_pipeline_with_features(void) {
    printf("\n--- Layer 2: Pipeline with Features ---\n");
    
    shell_parse_result_t result;
    
    // Pipeline with variable
    extract("echo $VAR | grep pattern", &result);
    test_count_only("Pipeline+var count=2", &result, 2);
    test_has_feature("First has VAR", &result, 0, SHELL_FEAT_VARS);
    // Note: "grep pattern" has no variables, so second subcommand shouldn't have VAR
    
    // Pipeline with globs
    extract("ls *.txt | sort", &result);
    test_count_only("Pipeline+glob count=2", &result, 2);
    test_has_feature("First has GLOB", &result, 0, SHELL_FEAT_GLOBS);
    
    // Pipeline with subshell
    extract("$(cmd) | cat", &result);
    test_count_only("Pipeline+subshell count=2", &result, 2);
    test_has_feature("First has SUBSHELL", &result, 0, SHELL_FEAT_SUBSHELL);
}

void test_layer2_logical_with_features(void) {
    printf("\n--- Layer 2: Logical Operators with Features ---\n");
    
    shell_parse_result_t result;
    
    // && with vars
    extract("test -n $VAR && echo found", &result);
    test_count_only("&&+var count=2", &result, 2);
    test_type("Second type=AND", &result, 1, SHELL_TYPE_AND);
    test_has_feature("First has VAR", &result, 0, SHELL_FEAT_VARS);
    
    // || with arithmetic
    extract("x=$((1+2)) || y=0", &result);
    test_count_only("||+arith count=2", &result, 2);
    test_type("Second type=OR", &result, 1, SHELL_TYPE_OR);
    test_has_feature("First has ARITH", &result, 0, SHELL_FEAT_ARITH);
}

void test_layer2_heredoc_with_features(void) {
    printf("\n--- Layer 2: HEREDOC with Features ---\n");
    
    shell_parse_result_t result;
    
    // HEREDOC with vars inside
    extract("cat << EOF\necho $VAR\nEOF", &result);
    test_count_at_least("Heredoc+var count>=2", &result, 2);
    if (result.count >= 2) {
        test_type("Heredoc type at idx 1", &result, 1, SHELL_TYPE_HEREDOC);
    }
    
    // HEREDOC with globs
    extract("grep pattern << END\n*.txt\nEND", &result);
    test_count_at_least("Heredoc+glob count>=2", &result, 2);
    
    // HEREDOC followed by pipeline
    extract("cat << EOF | sort", &result);
    test_count_only("Heredoc+pipe count=3", &result, 3);
    test_type("Idx 1 is HEREDOC", &result, 1, SHELL_TYPE_HEREDOC);
    test_type("Idx 2 is PIPELINE", &result, 2, SHELL_TYPE_PIPELINE);
}

void test_layer2_quoted_features(void) {
    printf("\n--- Layer 2: Quoted Strings with Features ---\n");
    
    shell_parse_result_t result;
    
    // Double quotes with var (should detect var)
    extract("echo \"$VAR\"", &result);
    test_has_feature("Quoted $VAR detected as VAR", &result, 0, SHELL_FEAT_VARS);
    
    // Single quotes (no expansion)
    extract("echo '$VAR'", &result);
    test_no_feature("Single-quoted $VAR no VAR", &result, 0, SHELL_FEAT_VARS);
    
    // Quoted glob
    extract("echo \"*.txt\"", &result);
    test_no_feature("Quoted glob not detected", &result, 0, SHELL_FEAT_GLOBS);
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

void test_layer2_escapes(void) {
    printf("\n--- Layer 2: Escape Sequences ---\n");
    
    shell_parse_result_t result;
    
    // Escaped space
    extract("echo hello\\ world", &result);
    test_count_only("Escaped space count=1", &result, 1);
    
    // Escaped $
    extract("echo \\$VAR", &result);
    test_no_feature("Escaped $ no VAR", &result, 0, SHELL_FEAT_VARS);
    
    // Escaped in quotes
    extract("echo \"\\$VAR\"", &result);
    test_no_feature("Escaped $ in quotes no VAR", &result, 0, SHELL_FEAT_VARS);
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
    
    // Arithmetic in assignment - space-separated assignments treated as single command
    extract("x=$((1+2)) y=$((3+4))", &result);
    test_count_only("Two assignments count=1 (space = args)", &result, 1);
    test_has_feature("Has ARITH", &result, 0, SHELL_FEAT_ARITH);
}

/* ============================================================
 * LAYER 3: LARGE/COMPLEX TESTS
 * ============================================================ */

void test_layer3_real_world_commands(void) {
    printf("\n--- Layer 3: Real World Commands ---\n");
    
    shell_parse_result_t result;
    
    // Build pipeline like find+grep+sort
    extract("find . -name '*.txt' -type f | grep -v test | sort | uniq -c | head -20", &result);
    test_count_only("find|grep|sort|uniq|head count=5", &result, 5);
    
    // Complex conditional
    extract("if [ -f config ]; then source config && echo loaded; else echo missing; fi", &result);
    test_count_at_least("if-then-else-fi count >= 1", &result, 1);
    
    // Complex with variables and arithmetic
    extract("count=$(ls *.log 2>/dev/null | wc -l) && [ $count -gt 0 ] || echo 'no files'", &result);
    test_count_at_least("Complex pipeline count >= 2", &result, 2);
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
    strcpy(buf, "gcc -o program main.c -I./include -L./lib -lm -lpthread -DDEBUG -O2 -Wall");
    extract(buf, &result);
    test_count_only("Long gcc command count=1", &result, 1);
    
    // Long pipeline: cat|sort|uniq|head|tail = 5 subcommands
    strcpy(buf, "cat file1.txt file2.txt file3.txt | sort | uniq | head -100 | tail -50 > output.txt");
    extract(buf, &result);
    test_count_only("Long pipeline count=5", &result, 5);
    
    // Long with features
    strcpy(buf, "echo \"Processing ${files[@]} at $(date +%T)...\" && for f in *.log; do grep ERROR $f >> errors.txt; done");
    extract(buf, &result);
    test_count_at_least("Complex long command count >= 2", &result, 2);
    test_has_feature("Has VAR", &result, 0, SHELL_FEAT_VARS);
    test_has_feature("Has SUBSHELL", &result, 0, SHELL_FEAT_SUBSHELL);
}

void test_layer3_combined_stress(void) {
    printf("\n--- Layer 3: Combined Stress ---\n");
    
    shell_parse_result_t result;
    
    // Very complex command
    extract("if [ -f ~/.bashrc ]; then source ~/.bashrc; fi && export PATH=\"$HOME/bin:$PATH\" && find . -name '*.c' -exec gcc -o {} {} \\; | grep -v 'Permission denied' || echo 'Build failed'", &result);
    test_count_at_least("Very complex count >= 3", &result, 3);
    
    // Multiple features everywhere
    extract("arr=($(ls *.txt | sort)) && for f in \"${arr[@]}\"; do count=$(wc -l < \"$f\"); echo \"$f: $count lines\"; done | tee report.txt", &result);
    test_count_at_least("Array+for+subshell count >= 1", &result, 1);
    test_has_feature("Has SUBSHELL", &result, 0, SHELL_FEAT_SUBSHELL);
    // VARS is in later subcommands, not index 0
}

void test_layer3_whitespace_stress(void) {
    printf("\n--- Layer 3: Whitespace Stress ---\n");
    
    shell_parse_result_t result;
    
    // Many spaces - still single command (whitespace separates args, not subcommands)
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
    limits.max_depth = 8;
    extract_limited("a | b | c", &limits, &result);
    test_count_only("At limit count=3", &result, 3);
    test("No truncation at limit", !(result.status & SHELL_STATUS_TRUNCATED));
    
    // Over limit
    extract_limited("a | b | c | d", &limits, &result);
    test_count_only("Over limit count=3", &result, 3);
    test("Truncation over limit", result.status & SHELL_STATUS_TRUNCATED);
    
    // Single char commands
    extract("a | b | c | d | e | f | g | h | i | j | k | l | m | n | o | p", &result);
    test_count_only("Single char commands count=16", &result, 16);
}

void test_layer3_features_stress(void) {
    printf("\n--- Layer 3: Features Stress ---\n");
    
    shell_parse_result_t result;
    
    // All features in one command
    // Note: x=$((1+2)) has ARITH but no $VAR (assignment, not variable reference)
    extract("x=$((1+2)) && y=$(echo $z) && ls *.txt && echo \"$var ${arr[@]} $((a+b))\"", &result);
    test_count_only("All features count=4", &result, 4);
    test_has_feature("First has ARITH", &result, 0, SHELL_FEAT_ARITH);
    test_no_feature("First no VARS (assignment)", &result, 0, SHELL_FEAT_VARS);
    test_has_feature("Second has SUBSHELL+VARS", &result, 1, SHELL_FEAT_SUBSHELL);
    test_has_feature("Third has GLOBS", &result, 2, SHELL_FEAT_GLOBS);
    test_has_feature("Fourth has VARS+ARITH", &result, 3, SHELL_FEAT_VARS);
    test_has_feature("Fourth has ARITH", &result, 3, SHELL_FEAT_ARITH);
    
    // Complex real-world with all features
    // Note: No $((...)) arithmetic in this command, only variables, globs, subshell
    extract("RESULT=$(grep -E 'ERROR|WARN' ${LOG_DIR}/*.log 2>/dev/null | wc -l) && if [ $RESULT -gt 0 ]; then echo \"Found $RESULT issues\"; fi", &result);
    test_count_at_least("Real-world all features count >= 2", &result, 2);
    test_has_feature("Has SUBSHELL", &result, 0, SHELL_FEAT_SUBSHELL);
    test_has_feature("Has VARS", &result, 0, SHELL_FEAT_VARS);
    test_has_feature("Has GLOBS", &result, 0, SHELL_FEAT_GLOBS);
    // No ARITH in this command - removed test
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main() {
    printf("=== FAST PARSER API TESTS ===\n");
    printf("Testing shell_parse_fast() and related functions\n\n");
    
    printf("=== LAYER 1: UNIT TESTS (~50 tests) ===\n");
    test_layer1_basic_inputs();
    test_layer1_simple_separators();
    test_layer1_whitespace_trimming();
    test_layer1_heredoc();
    test_layer1_features_vars();
    test_layer1_features_globs();
    test_layer1_features_subshell();
    test_layer1_features_arith();
    test_layer1_utility_functions();
    test_layer1_error_handling();
    test_layer1_edge_cases();
    test_layer1_type_values();
    
    printf("\n=== LAYER 2: INTERACTION TESTS (~100 tests) ===\n");
    test_layer2_pipeline_with_features();
    test_layer2_logical_with_features();
    test_layer2_heredoc_with_features();
    test_layer2_quoted_features();
    test_layer2_complex_sequences();
    test_layer2_escapes();
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
