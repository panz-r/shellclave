#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>

#include "shell_ast_generator.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include "shell_processor.h"

static FILE* crash_log = NULL;

static int verify_metadata(const char* cmd, size_t cmd_len, bool expects_parse_success) {
    // Parse with fast parser
    shell_parse_result_t result;
    shell_error_t err = shell_parse_fast(cmd, tc->cmd_len, NULL, &result);
    
    // Test passes if:
    // 1. Valid command parses successfully (err == SHELL_OK)
    // 2. Invalid command is correctly rejected (err != SHELL_OK)
    // Test fails if:
    // 1. Valid command is incorrectly rejected (expects_parse_success=true but err != SHELL_OK)
    // 2. Invalid command is incorrectly accepted (expects_parse_success=false but err == SHELL_OK)
    
    if (tc->expects_parse_success) {
        // Expecting success - should parse without error
        if (err != SHELL_OK) {
            printf("FAIL: expected parse success but got error %d for: %s\n", err, cmd);
            return 1;
        }
    } else {
        // Expecting failure - should be rejected with error
        if (err == SHELL_OK) {
            printf("FAIL: invalid syntax not detected: %s\n", cmd);
            return 1;
        }
    }
    
    // Additional check: subcommand count should be reasonable
    if (tc->expected_subcommands > 1 && result.count < 1) {
        printf("FAIL: expected %u subcommands but parser returned %u for: %s\n", 
               tc->expected_subcommands, result.count, cmd);
        return 1;
    }
    
    // Invariant: Count should be reasonable
    if (result.count > 100) {
        printf("FAIL: suspiciously high subcommand count %u for: %s\n", result.count, cmd);
        return 1;
    }
    
    // Invariant: All ranges should be within bounds
    for (uint32_t i = 0; i < result.count; i++) {
        shell_range_t* r = &result.cmds[i];
        if (r->start > tc->cmd_len || r->len > tc->cmd_len || r->start + r->len > tc->cmd_len) {
            printf("FAIL: range out of bounds for: %s\n", cmd);
            return 1;
        }
    }
    
    // Expectation 7: Check with full parser - should not crash
    shell_command_t* commands = NULL;
    size_t command_count = 0;
    bool full_ok = shell_tokenize_commands(cmd, &commands, &command_count);
    
    if (tc->expects_parse_success && !full_ok) {
        printf("FAIL: full parser failed but expected success for: %s\n", cmd);
        if (commands) shell_free_commands(commands, command_count);
        return 1;
    }
    
    if (commands) shell_free_commands(commands, command_count);
    
    // Expectation 8: Check with processor - should not crash
    shell_command_info_t* infos = NULL;
    size_t info_count = 0;
    bool proc_ok = shell_process_command(cmd, &infos, &info_count);
    
    if (tc->expects_parse_success && !proc_ok) {
        printf("FAIL: processor failed but expected success for: %s\n", cmd);
        if (infos) shell_free_command_infos(infos, info_count);
        return 1;
    }
    
    if (infos) shell_free_command_infos(infos, info_count);
    
    return 0;
}

static int test_with_metadata(shell_test_case_t* tc) {
    const char* cmd = tc->command;
    
    // Test fast parser
    shell_parse_result_t result;
    shell_error_t err = shell_parse_fast(cmd, tc->cmd_len, NULL, &result);
    
    // Error codes should be valid
    if (err < 0 && err != SHELL_ETRUNC && err != SHELL_EPARSE && err != SHELL_EINPUT) {
        printf("FAIL: invalid error code %d for: %s\n", err, cmd);
        return 1;
    }
    
    // Check output bounds
    for (uint32_t i = 0; i < result.count; i++) {
        shell_range_t* r = &result.cmds[i];
        if (r->start > tc->cmd_len || r->len > tc->cmd_len || r->start + r->len > tc->cmd_len) {
            printf("FAIL: invalid range for: %s\n", cmd);
            return 1;
        }
    }
    
    // Test full parser - should not crash
    shell_command_t* commands = NULL;
    size_t command_count = 0;
    shell_tokenize_commands(cmd, &commands, &command_count);
    if (commands) {
        shell_free_commands(commands, command_count);
    }
    
    // Test processor - should not crash
    shell_command_info_t* infos = NULL;
    size_t info_count = 0;
    shell_process_command(cmd, &infos, &info_count);
    if (infos) {
        shell_free_command_infos(infos, info_count);
    }
    
    return verify_metadata(tc, cmd);
}

static void save_crash(const char* cmd, const char* test_name) {
    if (!crash_log) {
        crash_log = fopen("tests/generator_crashes.log", "a");
        if (!crash_log) return;
    }
    fprintf(crash_log, "=== %s ===\n", test_name);
    fprintf(crash_log, "%s\n\n", cmd);
    fflush(crash_log);
}

static void save_metadata(shell_test_case_t* tc) {
    if (!crash_log) {
        crash_log = fopen("tests/generator_crashes.log", "a");
        if (!crash_log) return;
    }
    fprintf(crash_log, "=== METADATA ===\n");
    fprintf(crash_log, "command: %s\n", tc->command);
    fprintf(crash_log, "cmd_len: %zu\n", tc->cmd_len);
    fprintf(crash_log, "expects_parse_success: %d\n", tc->expects_parse_success);
    fprintf(crash_log, "is_malformed: %d\n", tc->is_malformed);
    fprintf(crash_log, "has_unclosed_quote: %d\n", tc->has_unclosed_quote);
    fprintf(crash_log, "has_unclosed_paren: %d\n", tc->has_unclosed_paren);
    fprintf(crash_log, "has_unclosed_brace: %d\n", tc->has_unclosed_brace);
    fprintf(crash_log, "expected_subcommands: %u\n", tc->expected_subcommands);
    fprintf(crash_log, "expected_pipeline_stages: %u\n", tc->expected_pipeline_stages);
    fprintf(crash_log, "expected_variables: %u\n", tc->expected_variables);
    fprintf(crash_log, "expected_subshells: %u\n", tc->expected_subshells);
    fprintf(crash_log, "expected_redirects: %u\n", tc->expected_redirects);
    fprintf(crash_log, "expects_heredoc: %d\n", tc->expects_heredoc);
    fprintf(crash_log, "expects_arithmetic: %d\n", tc->expects_arithmetic);
    fprintf(crash_log, "expects_case: %d\n", tc->expects_case);
    fprintf(crash_log, "expects_loops: %d\n", tc->expects_loops);
    fprintf(crash_log, "expects_conditionals: %d\n", tc->expects_conditionals);
    fprintf(crash_log, "expects_process_sub: %d\n", tc->expects_process_sub);
    fprintf(crash_log, "expects_glob: %d\n", tc->expects_glob);
    fprintf(crash_log, "\n");
    fflush(crash_log);
}

int main(int argc, char* argv[]) {
    int num_tests = 100;
    int seed_arg = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            seed_arg = atoi(argv[i + 1]);
            i++;
        } else {
            num_tests = atoi(argv[i]);
            if (num_tests == 0) num_tests = 100;
        }
    }
    
    printf("Running %d generated shell command tests with metadata validation...\n", num_tests);
    
    shell_generator_t gen;
    
    uint64_t seed;
    if (seed_arg) {
        seed = seed_arg;
    } else {
        seed = ((uint64_t)time(NULL) << 32) | (getpid() & 0xFFFFFFFF);
    }
    printf("Using seed: %lu\n", (unsigned long)seed);
    
    shell_generator_init_heap(&gen, 8192, seed);
    
    int passed = 0;
    int failed = 0;
    int correctly_rejected = 0;
    
    for (int i = 0; i < num_tests; i++) {
        shell_test_case_t* tc = shell_generator_generate_with_metadata(&gen, 4096);
        
        if (tc && tc->command && tc->cmd_len > 0) {
            int result = test_with_metadata(tc);
            if (result == 0) {
                if (tc->expects_parse_success) {
                    passed++;
                } else {
                    correctly_rejected++;
                }
            } else {
                failed++;
                printf("FAIL: %s\n", tc->command);
                save_crash(tc->command, "generator_test");
                save_metadata(tc);
            }
        }
        
        if (tc) shell_test_case_free(tc);
        
        if ((i + 1) % 100 == 0 || failed > 0) {
            printf("Progress: %d/%d (passed: %d, rejected: %d, failed: %d)\n", 
                   i + 1, num_tests, passed, correctly_rejected, failed);
        }
    }
    
    shell_generator_free(&gen);
    
    if (crash_log) {
        fclose(crash_log);
    }
    
    printf("\n=== RESULTS ===\n");
    printf("Total: %d\n", num_tests);
    printf("Passed (valid commands parsed): %d\n", passed);
    printf("Correctly rejected (invalid detected): %d\n", correctly_rejected);
    printf("Failed: %d\n", failed);
    printf("Success rate: %.2f%%\n", (double)(passed + correctly_rejected) / num_tests * 100.0);
    
    if (failed > 0) {
        printf("\nFailing commands saved to: tests/generator_crashes.log\n");
    }
    
    return failed > 0 ? 1 : 0;
}
