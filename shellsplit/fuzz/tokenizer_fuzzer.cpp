// LibFuzzer harness for shellsplit - fuzzes all parsers
// Fuzzes: fast parser, full parser, transformer, processor

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include "shell_transform.h"
#include "shell_processor.h"

extern "C" {

static const size_t MAX_INPUT_SIZE = 8192;
static int g_verbose = 0;

extern "C" void LLVMFuzzerInitialize(int* argc, char*** argv) {
    const char* verbose = getenv("SHELLSPLIT_FUZZ_VERBOSE");
    if (verbose && (*verbose == '1' || *verbose == 'y' || *verbose == 'Y')) {
        g_verbose = 1;
    }
    if (g_verbose) {
        fprintf(stderr, "DEBUG: ShellSplit fuzzer initialized\n");
    }
}

// Test fast parser
static int test_fast_parser(const char* input, size_t length) {
    shell_parse_result_t result;
    shell_error_t err = shell_parse_fast(input, length, NULL, &result);
    
    if (err < 0 && err != SHELL_ETRUNC) {
        if (g_verbose) fprintf(stderr, "\n=== FAST PARSER ERROR: Invalid return code %d ===\n", err);
        return 1;
    }
    
    if (result.count > SHELL_MAX_SUBCOMMANDS) {
        if (g_verbose) fprintf(stderr, "\n=== FAST PARSER ERROR: Invalid count %u ===\n", result.count);
        return 1;
    }
    
    for (uint32_t i = 0; i < result.count; i++) {
        shell_range_t* r = &result.cmds[i];
        if (r->start > length || r->len > length || r->start + r->len > length) {
            if (g_verbose) fprintf(stderr, "\n=== FAST PARSER ERROR: Invalid range at idx %u ===\n", i);
            return 1;
        }
        
        char buf[256];
        size_t copied = shell_copy_subcommand(input, r, buf, sizeof(buf));
        if (copied > r->len) {
            if (g_verbose) fprintf(stderr, "\n=== FAST PARSER ERROR: Copy overflow ===\n");
            return 1;
        }
        
        uint32_t out_len = 0;
        const char* ptr = shell_get_subcommand(input, r, &out_len);
        if (ptr && out_len != r->len) {
            if (g_verbose) fprintf(stderr, "\n=== FAST PARSER ERROR: Length mismatch ===\n");
            return 1;
        }
    }
    
    // Test with limited subcommands
    if (length > 10) {
        shell_limits_t limits = {1, 8};
        shell_parse_result_t result_limited;
        err = shell_parse_fast(input, length, &limits, &result_limited);
        if (err < 0 && err != SHELL_ETRUNC) {
            if (g_verbose) fprintf(stderr, "\n=== FAST PARSER ERROR: Limited parse failed ===\n");
            return 1;
        }
        if (result_limited.count > 1) {
            if (g_verbose) fprintf(stderr, "\n=== FAST PARSER ERROR: Limited count exceeded ===\n");
            return 1;
        }
    }
    
    return 0;
}

// Test full parser
static int test_full_parser(const char* input, size_t length) {
    if (length == 0) return 0;
    
    char* null_term = (char*)malloc(length + 1);
    if (!null_term) return 0;
    memcpy(null_term, input, length);
    null_term[length] = '\0';
    
    shell_command_t* commands = NULL;
    size_t command_count = 0;
    
    bool success = shell_tokenize_commands(null_term, &commands, &command_count);
    
    // Clean up on failure
    if (!success) {
        shell_free_commands(commands, command_count);
        free(null_term);
        return 0;
    }
    
    if (success && commands) {
        for (size_t i = 0; i < command_count; i++) {
            shell_command_t* cmd = &commands[i];
            
            if (cmd->tokens) {
                for (size_t j = 0; j < cmd->token_count; j++) {
                    shell_token_t* tok = &cmd->tokens[j];
                    if (tok->start) {
                        size_t pos = tok->start - null_term;
                        if (pos > length) {
                            if (g_verbose) fprintf(stderr, "\n=== FULL PARSER ERROR: Token position overflow ===\n");
                            free(null_term);
                            shell_free_commands(commands, command_count);
                            return 1;
                        }
                    }
                }
            }
        }
        shell_free_commands(commands, command_count);
    }
    
    free(null_term);
    return 0;
}

// Test transformer
static int test_transformer(const char* input, size_t length) {
    if (length == 0) return 0;
    
    char* null_term = (char*)malloc(length + 1);
    if (!null_term) return 0;
    memcpy(null_term, input, length);
    null_term[length] = '\0';
    
    transformed_command_t** transformed_cmds = NULL;
    size_t transformed_count = 0;
    
    bool success = shell_transform_command_line(null_term, &transformed_cmds, &transformed_count);
    
    // Clean up on failure
    if (!success) {
        shell_free_transformed_commands(transformed_cmds, transformed_count);
        free(null_term);
        return 0;
    }
    
    if (success && transformed_cmds) {
        for (size_t i = 0; i < transformed_count; i++) {
            transformed_command_t* tcmd = transformed_cmds[i];
            if (!tcmd) continue;
            
            if (tcmd->tokens) {
                for (size_t j = 0; j < tcmd->token_count; j++) {
                    transformed_token_t* tok = &tcmd->tokens[j];
                    if (tok->original && tok->original != null_term) {
                        size_t offset = tok->original - null_term;
                        if (offset > length) {
                            if (g_verbose) fprintf(stderr, "\n=== TRANSFORMER ERROR: Token offset overflow ===\n");
                            free(null_term);
                            shell_free_transformed_commands(transformed_cmds, transformed_count);
                            return 1;
                        }
                    }
                }
            }
        }
        shell_free_transformed_commands(transformed_cmds, transformed_count);
    }
    
    free(null_term);
    return 0;
}

// Test processor
static int test_processor(const char* input, size_t length) {
    if (length == 0) return 0;
    
    char* null_term = (char*)malloc(length + 1);
    if (!null_term) return 0;
    memcpy(null_term, input, length);
    null_term[length] = '\0';
    
    shell_command_info_t* infos = NULL;
    size_t command_count = 0;
    
    bool success = shell_process_command(null_term, &infos, &command_count);
    
    // Clean up on failure
    if (!success) {
        shell_free_command_infos(infos, command_count);
        free(null_term);
        return 0;
    }
    
    if (success && infos) {
        for (size_t i = 0; i < command_count; i++) {
            shell_command_info_t* info = &infos[i];
            (void)info; // Just check allocation
            
            // Check clean command is within bounds if set
            if (info->clean_command && info->clean_command != null_term) {
                size_t offset = info->clean_command - null_term;
                if (offset > length) {
                    if (g_verbose) fprintf(stderr, "\n=== PROCESSOR ERROR: Clean command offset overflow ===\n");
                    free(null_term);
                    shell_free_command_infos(infos, command_count);
                    return 1;
                }
            }
        }
        shell_free_command_infos(infos, command_count);
    }
    
    free(null_term);
    return 0;
}

// Test DFA input extraction
static int test_dfa_extraction(const char* input, size_t length) {
    if (length == 0) return 0;
    
    char* null_term = (char*)malloc(length + 1);
    if (!null_term) return 0;
    memcpy(null_term, input, length);
    null_term[length] = '\0';
    
    const char** dfa_inputs = NULL;
    size_t dfa_input_count = 0;
    bool has_shell_features = false;
    
    bool success = shell_extract_dfa_inputs(null_term, &dfa_inputs, &dfa_input_count, &has_shell_features);
    
    // Clean up on failure
    if (!success) {
        // dfa_inputs might be allocated, need to free if success was false after allocation
        // But shell_extract_dfa_inputs handles this internally via shell_free_command_infos
        free(null_term);
        return 0;
    }
    
    if (success && dfa_inputs) {
        for (size_t i = 0; i < dfa_input_count; i++) {
            if (dfa_inputs[i]) {
                size_t offset = dfa_inputs[i] - null_term;
                if (offset > length) {
                    if (g_verbose) fprintf(stderr, "\n=== DFA EXTRACT ERROR: Input offset overflow ===\n");
                    // Free the strings before returning error
                    for (size_t j = 0; j < dfa_input_count; j++) {
                        free((void*)dfa_inputs[j]);
                    }
                    free(null_term);
                    free(dfa_inputs);
                    return 1;
                }
            }
        }
        // dfa_inputs contains pointers to clean_command strings that we need to free
        for (size_t i = 0; i < dfa_input_count; i++) {
            free((void*)dfa_inputs[i]);
        }
        free(dfa_inputs);
    }
    
    free(null_term);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > MAX_INPUT_SIZE) {
        size = MAX_INPUT_SIZE;
    }
    
    if (size == 0) {
        return 0;
    }
    
    const char* input = (const char*)data;
    
    // Test all parsers - continue on error, don't abort
    // This allows fuzzing to continue even when bugs are found
    
    test_fast_parser(input, size);
    test_full_parser(input, size);
    test_transformer(input, size);
    test_processor(input, size);
    test_dfa_extraction(input, size);
    
    return 0;
}

} // extern "C"
