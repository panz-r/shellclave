#ifndef SHELL_GENERATOR_H
#define SHELL_GENERATOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    char* buffer;
    size_t buffer_size;
    size_t buffer_pos;
    uint64_t rng_state;
    bool buffer_managed;
    
    // Probability of generating invalid syntax (0-100, default 20)
    uint8_t invalid_syntax_probability;
    
    // Metadata tracking - built as command is generated
    uint32_t subcommand_count;
    uint32_t pipeline_count;
    uint32_t command_count;
    uint32_t variable_count;
    uint32_t subshell_count;
    uint32_t redirect_count;
    bool has_heredoc;
    bool has_arithmetic;
    bool has_case;
    bool has_loops;
    bool has_conditionals;
    bool has_process_sub;
    bool has_glob;
    bool is_malformed;
    bool has_unclosed_quote;
    bool has_unclosed_paren;
    bool has_unclosed_brace;
} shell_generator_t;

typedef struct {
    char* command;
    size_t cmd_len;
    
    // Generator's knowledge about what was created
    uint32_t expected_subcommands;
    uint32_t expected_pipeline_stages;
    uint32_t expected_variables;
    uint32_t expected_subshells;
    uint32_t expected_redirects;
    bool expects_heredoc;
    bool expects_arithmetic;
    bool expects_case;
    bool expects_loops;
    bool expects_conditionals;
    bool expects_process_sub;
    bool expects_glob;
    bool is_malformed;
    bool has_unclosed_quote;
    bool has_unclosed_paren;
    bool has_unclosed_brace;
    
    // Whether we expect parser success
    bool expects_parse_success;
    
    // Additional invariants
    size_t min_expected_len;
    size_t max_expected_len;
} shell_test_case_t;

void shell_generator_init(shell_generator_t* gen, char* buffer, size_t buffer_size, uint64_t seed);

void shell_generator_init_heap(shell_generator_t* gen, size_t initial_size, uint64_t seed);

void shell_generator_free(shell_generator_t* gen);

char* shell_generator_generate(shell_generator_t* gen, size_t max_len);

shell_test_case_t* shell_generator_generate_with_metadata(shell_generator_t* gen, size_t max_len);

void shell_test_case_free(shell_test_case_t* tc);

void shell_generator_set_invalid_probability(shell_generator_t* gen, uint8_t probability);

uint8_t shell_generator_get_invalid_probability(shell_generator_t* gen);

#endif
