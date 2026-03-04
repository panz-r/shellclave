#define _POSIX_C_SOURCE 200809L
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

static void save_crash(const char* cmd, const char* filename) {
    if (!crash_log) {
        crash_log = fopen("tests/generator_crashes.log", "w");
    }
    if (crash_log) {
        fprintf(crash_log, "FAIL: %s\n", cmd);
    }
}

static int verify_command(const char* cmd, size_t cmd_len, bool expects_parse_success) {
    shell_parse_result_t result;
    shell_error_t err = shell_parse_fast(cmd, cmd_len, NULL, &result);
    
    if (expects_parse_success) {
        if (err != SHELL_OK) {
            printf("FAIL: expected parse success but got error %d for: %s\n", err, cmd);
            return 1;
        }
    } else {
        if (err == SHELL_OK) {
            printf("FAIL: invalid syntax not detected: %s\n", cmd);
            return 1;
        }
    }
    
    if (result.count > 100) {
        printf("FAIL: suspiciously high subcommand count %u for: %s\n", result.count, cmd);
        return 1;
    }
    
    shell_command_t* commands = NULL;
    size_t command_count = 0;
    bool full_ok = shell_tokenize_commands(cmd, &commands, &command_count);
    
    if (expects_parse_success && !full_ok) {
        printf("FAIL: full parser failed but expected success for: %s\n", cmd);
        if (commands) shell_free_commands(commands, command_count);
        return 1;
    }
    
    if (commands) shell_free_commands(commands, command_count);
    
    shell_command_info_t* infos = NULL;
    size_t info_count = 0;
    bool proc_ok = shell_process_command(cmd, &infos, &info_count);
    
    if (expects_parse_success && !proc_ok) {
        printf("FAIL: processor failed but expected success for: %s\n", cmd);
        if (infos) shell_free_command_infos(infos, info_count);
        return 1;
    }
    
    if (infos) shell_free_command_infos(infos, info_count);
    
    return 0;
}

int main(int argc, char** argv) {
    int num_tests = 100;
    uint64_t seed_arg = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            num_tests = atoi(argv[++i]);
            if (num_tests == 0) num_tests = 100;
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            seed_arg = (uint64_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-n count] [-s seed]\n", argv[0]);
            return 0;
        }
    }
    
    printf("Running %d AST-based generated shell command tests...\n", num_tests);
    
    uint64_t seed;
    if (seed_arg) {
        seed = seed_arg;
    } else {
        seed = ((uint64_t)time(NULL) << 32) | (getpid() & 0xFFFFFFFF);
    }
    printf("Using seed: %lu\n", (unsigned long)seed);
    
    shell_ast_generator_t* gen = shell_ast_generator_create(seed);
    
    char buffer[4096];
    int passed = 0;
    int correctly_rejected = 0;
    int failed = 0;
    
    for (int i = 0; i < num_tests; i++) {
        shell_ast_t* ast = shell_ast_generator_generate(gen, 4096);
        
        if (!ast) {
            failed++;
            continue;
        }
        
        buffer[0] = '\0';
        shell_ast_serialize(ast, buffer, sizeof(buffer));
        size_t cmd_len = strlen(buffer);
        
        if (cmd_len == 0) {
            shell_ast_destroy(ast);
            continue;
        }
        
        bool expects_success = shell_ast_expects_parse_success(ast);
        
        int result = verify_command(buffer, cmd_len, expects_success);
        
        if (result == 0) {
            if (expects_success) {
                passed++;
            } else {
                correctly_rejected++;
            }
        } else {
            failed++;
            save_crash(buffer, "generator_test");
        }
        
        shell_ast_destroy(ast);
        
        if ((i + 1) % 100 == 0 || failed > 0) {
            printf("Progress: %d/%d (passed: %d, rejected: %d, failed: %d)\n", 
                   i + 1, num_tests, passed, correctly_rejected, failed);
        }
    }
    
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
