#define _GNU_SOURCE
#include "shell_generator.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

// Forward declarations for API functions
bool shell_generator_add_command(shell_generator_t* gen);
bool shell_generator_add_pipeline(shell_generator_t* gen);
bool shell_generator_add_subcommand(shell_generator_t* gen);
bool shell_generator_add_redirect(shell_generator_t* gen);
bool shell_generator_add_variable(shell_generator_t* gen);
bool shell_generator_add_glob(shell_generator_t* gen);
bool shell_generator_add_arithmetic(shell_generator_t* gen);
bool shell_generator_add_subshell(shell_generator_t* gen);
bool shell_generator_add_heredoc(shell_generator_t* gen);

static uint64_t xorshift64(uint64_t* state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static uint64_t random_range(uint64_t* state, uint64_t max) {
    return xorshift64(state) % max;
}

static void ensure_capacity(shell_generator_t* gen, size_t needed) {
    if (gen->buffer_pos + needed >= gen->buffer_size) {
        if (gen->buffer_managed) {
            size_t new_size = gen->buffer_size * 2;
            if (new_size < gen->buffer_pos + needed + 1) {
                new_size = gen->buffer_pos + needed + 1;
            }
            char* new_buffer = realloc(gen->buffer, new_size);
            if (new_buffer) {
                gen->buffer = new_buffer;
                gen->buffer_size = new_size;
            }
        } else {
            // User-managed buffer - just truncate
            gen->buffer[gen->buffer_size - 1] = '\0';
        }
    }
}

static void append_str(shell_generator_t* gen, const char* str) {
    size_t len = strlen(str);
    ensure_capacity(gen, len + 1);
    memcpy(gen->buffer + gen->buffer_pos, str, len);
    gen->buffer_pos += len;
}

static void append_char(shell_generator_t* gen, char c) {
    ensure_capacity(gen, 2);
    gen->buffer[gen->buffer_pos++] = c;
}

static void reset_metadata(shell_generator_t* gen) {
    gen->subcommand_count = 0;
    gen->pipeline_count = 0;
    gen->command_count = 0;
    gen->variable_count = 0;
    gen->subshell_count = 0;
    gen->redirect_count = 0;
    gen->has_heredoc = false;
    gen->has_arithmetic = false;
    gen->has_case = false;
    gen->has_loops = false;
    gen->has_conditionals = false;
    gen->has_process_sub = false;
    gen->has_glob = false;
    gen->is_malformed = false;
    gen->has_unclosed_quote = false;
    gen->has_unclosed_paren = false;
    gen->has_unclosed_brace = false;
}

void shell_generator_init(shell_generator_t* gen, char* buffer, size_t buffer_size, uint64_t seed) {
    gen->buffer = buffer;
    gen->buffer_size = buffer_size;
    gen->buffer_pos = 0;
    gen->rng_state = seed;
    gen->buffer_managed = false;
    gen->invalid_syntax_probability = 20;  // Default 20%
    reset_metadata(gen);
    if (buffer_size > 0) {
        buffer[0] = '\0';
    }
}

void shell_generator_init_heap(shell_generator_t* gen, size_t initial_size, uint64_t seed) {
    gen->buffer = malloc(initial_size);
    gen->buffer_size = initial_size;
    gen->buffer_pos = 0;
    gen->rng_state = seed;
    gen->buffer_managed = true;
    gen->invalid_syntax_probability = 20;  // Default 20%
    reset_metadata(gen);
    if (gen->buffer) {
        gen->buffer[0] = '\0';
    }
}

void shell_generator_free(shell_generator_t* gen) {
    if (gen->buffer_managed && gen->buffer) {
        free(gen->buffer);
        gen->buffer = NULL;
        gen->buffer_size = 0;
    }
    gen->buffer_managed = false;
}

static bool has_pattern(const char* str, size_t len, const char* pattern) {
    size_t plen = strlen(pattern);
    if (len < plen) return false;
    for (size_t i = 0; i <= len - plen; i++) {
        if (memcmp(str + i, pattern, plen) == 0) {
            return true;
        }
    }
    return false;
}

shell_test_case_t* shell_generator_generate_with_metadata(shell_generator_t* gen, size_t max_len) {
    char* cmd = shell_generator_generate(gen, max_len);
    if (!cmd) return NULL;
    
    shell_test_case_t* tc = calloc(1, sizeof(shell_test_case_t));
    if (!tc) return NULL;
    
    size_t len = strlen(cmd);
    tc->command = strndup(cmd, len);
    tc->cmd_len = len;
    
    // Use the metadata tracked during generation (more accurate than re-analyzing)
    tc->expected_subcommands = gen->subcommand_count > 0 ? gen->subcommand_count : 1;
    tc->expected_pipeline_stages = gen->pipeline_count > 0 ? gen->pipeline_count : 1;
    tc->expected_variables = gen->variable_count;
    tc->expected_subshells = gen->subshell_count;
    tc->expected_redirects = gen->redirect_count;
    tc->expects_heredoc = gen->has_heredoc;
    tc->expects_arithmetic = gen->has_arithmetic;
    tc->expects_case = gen->has_case;
    tc->expects_loops = gen->has_loops;
    tc->expects_conditionals = gen->has_conditionals;
    tc->expects_process_sub = gen->has_process_sub;
    tc->expects_glob = gen->has_glob;
    tc->is_malformed = gen->is_malformed;
    tc->has_unclosed_quote = gen->has_unclosed_quote;
    tc->has_unclosed_paren = gen->has_unclosed_paren;
    tc->has_unclosed_brace = gen->has_unclosed_brace;
    
    // Valid shell if it has commands and no unclosed syntax
    tc->expects_parse_success = !gen->is_malformed && !gen->has_unclosed_quote && 
                                 !gen->has_unclosed_paren && !gen->has_unclosed_brace;
    
    // Track min/max expected length
    tc->min_expected_len = 2;  // minimum valid command
    tc->max_expected_len = max_len;
    
    return tc;
}

void shell_test_case_free(shell_test_case_t* tc) {
    if (tc) {
        free(tc->command);
        free(tc);
    }
}

void shell_generator_set_invalid_probability(shell_generator_t* gen, uint8_t probability) {
    if (probability > 100) probability = 100;
    gen->invalid_syntax_probability = probability;
}

uint8_t shell_generator_get_invalid_probability(shell_generator_t* gen) {
    return gen->invalid_syntax_probability;
}

static bool append_command(shell_generator_t* gen);
static bool append_simple_command(shell_generator_t* gen);
static bool append_argument(shell_generator_t* gen);
static bool append_deep_subshell(shell_generator_t* gen, uint64_t depth);

static const char* commands[] = {
    "ls", "cat", "grep", "find", "echo", "printf", "head", "tail",
    "sort", "uniq", "wc", "awk", "sed", "cut", "tr", "date",
    "pwd", "cd", "mkdir", "rm", "cp", "mv", "chmod", "chown",
    "git", "docker", "make", "gcc", "clang", "python", "perl",
    "ps", "top", "df", "du", "free", "whoami", "id", "env",
    "curl", "wget", "ssh", "scp", "rsync", "tar", "zip", "unzip"
};

static const size_t num_commands = sizeof(commands) / sizeof(commands[0]);

static const char* variables[] = {
    "HOME", "USER", "PATH", "PWD", "SHELL", "TERM", "HOSTNAME",
    "LANG", "LC_ALL", "EDITOR", "VISUAL", "PAGER", "MAKEFLAGS"
};

static const size_t num_variables = sizeof(variables) / sizeof(variables[0]);

static const char* glob_patterns[] = {
    "*.txt", "*.log", "*.conf", "*.sh", "*.c", "*.h",
    "file?.dat", "test[0-9].*", "data*", "*.{c,h,o}",
    ".[!.]*", "??*", "*.{1,2,3}"
};

static const size_t num_globs = sizeof(glob_patterns) / sizeof(glob_patterns[0]);

static const char* special_vars[] = {
    "$@", "$$", "$#", "$?", "$!", "$*"
};

static const size_t num_special_vars = sizeof(special_vars) / sizeof(special_vars[0]);

static const char* operators[] = {
    "+", "-", "*", "/", "%", "<<", ">>", "<", ">", "&", "|", "^", "~"
};

static const size_t num_operators = sizeof(operators) / sizeof(operators[0]);

static bool append_command(shell_generator_t* gen) {
    const char* cmd = commands[random_range(&gen->rng_state, num_commands)];
    append_str(gen, cmd);
    return true;
}

static bool append_argument(shell_generator_t* gen) {
    // Check if we should generate invalid syntax
    bool generate_invalid = random_range(&gen->rng_state, 100) < gen->invalid_syntax_probability;
    
    if (generate_invalid) {
        uint64_t error_type = random_range(&gen->rng_state, 6);
        switch (error_type) {
            case 0: {
                // Unclosed double quote - missing closing "
                append_char(gen, '"');
                append_str(gen, "text");
                // No closing quote - unclosed
                gen->has_unclosed_quote = true;
                break;
            }
            case 1: {
                // Unclosed single quote - missing closing '
                append_char(gen, '\'');
                append_str(gen, "text");
                // No closing quote - unclosed
                gen->has_unclosed_quote = true;
                break;
            }
            case 2: {
                // Trailing \ before space - incomplete escape
                append_str(gen, "text\\ ");
                break;
            }
            case 3: {
                // Unclosed ${ without variable
                append_str(gen, "${");
                gen->has_unclosed_brace = true;
                break;
            }
            case 4: {
                // Unclosed subshell
                append_str(gen, "$(cmd1 | cmd2");
                gen->has_unclosed_paren = true;
                break;
            }
            default: {
                // Trailing \ without escape
                append_str(gen, "text\\");
                break;
            }
        }
        return true;
    }
    
    uint64_t r = random_range(&gen->rng_state, 100);
    
    if (r < 40) {
        append_str(gen, "-");
        if (random_range(&gen->rng_state, 2)) {
            append_char(gen, '-');
        }
        append_char(gen, 'a' + random_range(&gen->rng_state, 26));
        if (random_range(&gen->rng_state, 2)) {
            char val[32];
            snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 1000));
            append_char(gen, ' ');
            append_str(gen, val);
        }
    } else if (r < 70) {
        append_str(gen, "/tmp/test");
        append_char(gen, '0' + random_range(&gen->rng_state, 10));
        append_str(gen, ".txt");
    } else if (r < 85) {
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
    } else if (r < 95) {
        append_str(gen, "${");
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
        append_char(gen, '}');
    } else {
        append_str(gen, glob_patterns[random_range(&gen->rng_state, num_globs)]);
    }
    
    return true;
}

static bool append_simple_command(shell_generator_t* gen) {
    append_command(gen);
    
    uint64_t num_args = random_range(&gen->rng_state, 6);
    for (uint64_t i = 0; i < num_args; i++) {
        append_char(gen, ' ');
        append_argument(gen);
    }
    
    return true;
}

bool shell_generator_add_command(shell_generator_t* gen) {
    append_simple_command(gen);
    return true;
}

bool shell_generator_add_extreme_pipeline(shell_generator_t* gen) {
    uint64_t num_pipes = random_range(&gen->rng_state, 8) + 3;
    for (uint64_t i = 0; i < num_pipes; i++) {
        if (i > 0) {
            append_str(gen, " | ");
        }
        if (random_range(&gen->rng_state, 5) == 0) {
            append_deep_subshell(gen, random_range(&gen->rng_state, 2) + 1);
        } else {
            append_simple_command(gen);
        }
    }
    return true;
}

bool shell_generator_add_many_args(shell_generator_t* gen) {
    append_command(gen);
    
    uint64_t num_args = random_range(&gen->rng_state, 20) + 5;
    for (uint64_t i = 0; i < num_args; i++) {
        append_char(gen, ' ');
        uint64_t arg_type = random_range(&gen->rng_state, 10);
        if (arg_type < 3) {
            append_str(gen, "-");
            append_char(gen, 'a' + random_range(&gen->rng_state, 26));
        } else if (arg_type < 5) {
            append_str(gen, "--long-option=");
            append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
        } else if (arg_type < 7) {
            shell_generator_add_variable(gen);
        } else if (arg_type < 9) {
            append_str(gen, glob_patterns[random_range(&gen->rng_state, num_globs)]);
        } else {
            shell_generator_add_arithmetic(gen);
        }
    }
    return true;
}

bool shell_generator_add_redirect(shell_generator_t* gen) {
    append_char(gen, ' ');
    
    uint64_t r = random_range(&gen->rng_state, 10);
    if (r < 4) {
        append_str(gen, ">");
    } else if (r < 7) {
        append_str(gen, ">>");
    } else if (r < 9) {
        append_str(gen, "<");
    } else {
        append_str(gen, "2>");
    }
    
    append_char(gen, ' ');
    append_str(gen, "/tmp/out");
    append_char(gen, '0' + random_range(&gen->rng_state, 10));
    append_str(gen, ".txt");
    
    gen->redirect_count++;
    return true;
}

bool shell_generator_add_variable(shell_generator_t* gen) {
    // Check if we should generate invalid variable syntax
    bool generate_invalid = random_range(&gen->rng_state, 100) < gen->invalid_syntax_probability;
    
    if (generate_invalid) {
        uint64_t error_type = random_range(&gen->rng_state, 5);
        switch (error_type) {
            case 0: {
                // Bare $ at end (unclosed)
                append_char(gen, '$');
                gen->has_unclosed_brace = true;
                break;
            }
            case 1: {
                // ${VAR without closing brace
                append_str(gen, "${");
                append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
                gen->has_unclosed_brace = true;
                break;
            }
            case 2: {
                // $ without valid identifier
                append_char(gen, '$');
                append_char(gen, '$');
                // Random character that's not valid
                append_char(gen, '@');
                break;
            }
            case 3: {
                // Trailing $ 
                append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
                append_char(gen, '$');
                break;
            }
            default: {
                // Empty ${}
                append_str(gen, "${}");
                gen->has_unclosed_brace = true;
                break;
            }
        }
        gen->variable_count++;
        return true;
    }
    
    uint64_t r = random_range(&gen->rng_state, 10);
    
    if (r < 5) {
        append_str(gen, "$");
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
    } else if (r < 8) {
        append_str(gen, "${");
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
        append_char(gen, '}');
    } else if (r < 9) {
        append_str(gen, "$");
        append_char(gen, '0' + random_range(&gen->rng_state, 10));
    } else {
        append_str(gen, special_vars[random_range(&gen->rng_state, num_special_vars)]);
    }
    
    gen->variable_count++;
    return true;
}

bool shell_generator_add_glob(shell_generator_t* gen) {
    append_str(gen, glob_patterns[random_range(&gen->rng_state, num_globs)]);
    gen->has_glob = true;
    return true;
}

bool shell_generator_add_arithmetic(shell_generator_t* gen) {
    append_str(gen, "$(( ");
    
    uint64_t r = random_range(&gen->rng_state, 10);
    if (r < 3) {
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
    } else if (r < 6) {
        char val[16];
        snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 100));
        append_str(gen, val);
    } else {
        append_str(gen, "$");
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
    }
    
    append_char(gen, ' ');
    const char* ops[] = {"+", "-", "*", "/", "%"};
    append_str(gen, ops[random_range(&gen->rng_state, 5)]);
    append_char(gen, ' ');
    
    r = random_range(&gen->rng_state, 10);
    if (r < 3) {
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
    } else {
        char val[16];
        snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 100));
        append_str(gen, val);
    }
    
    append_str(gen, " ))");
    gen->has_arithmetic = true;
    return true;
}

bool shell_generator_add_subshell(shell_generator_t* gen) {
    append_str(gen, "$(");
    gen->subshell_count++;
    append_simple_command(gen);
    append_char(gen, ')');
    return true;
}

bool shell_generator_add_heredoc(shell_generator_t* gen) {
    uint64_t r = random_range(&gen->rng_state, 10);
    
    if (r < 6) {
        append_str(gen, "<<EOF");
    } else if (r < 8) {
        append_str(gen, "<<-EOF");
    } else if (r < 9) {
        append_str(gen, "<<'EOF'");
    } else {
        append_str(gen, "<<\"EOF\"");
    }
    
    append_char(gen, '\n');
    append_str(gen, "content here\n");
    append_str(gen, "EOF");
    
    gen->has_heredoc = true;
    return true;
}

bool shell_generator_add_pipeline(shell_generator_t* gen) {
    gen->command_count++;
    append_simple_command(gen);
    
    uint64_t num_pipes = random_range(&gen->rng_state, 3) + 1;
    for (uint64_t i = 0; i < num_pipes; i++) {
        append_char(gen, ' ');
        append_char(gen, '|');
        append_char(gen, ' ');
        gen->pipeline_count++;
        append_simple_command(gen);
    }
    gen->subcommand_count += num_pipes;
    
    return true;
}

bool shell_generator_add_subcommand(shell_generator_t* gen) {
    uint64_t separator = random_range(&gen->rng_state, 10);
    
    if (separator < 4) {
        append_str(gen, " && ");
    } else if (separator < 7) {
        append_str(gen, " || ");
    } else if (separator < 9) {
        append_char(gen, ';');
    } else {
        append_char(gen, '\n');
    }
    
    return true;
}

static bool append_process_sub(shell_generator_t* gen) {
    if (random_range(&gen->rng_state, 2) == 0) {
        append_str(gen, "<(");
    } else {
        append_str(gen, ">(");
    }
    append_simple_command(gen);
    append_char(gen, ')');
    gen->has_process_sub = true;
    return true;
}

static bool append_quoted_string(shell_generator_t* gen) {
    if (random_range(&gen->rng_state, 2) == 0) {
        append_char(gen, '"');
        for (int i = 0; i < random_range(&gen->rng_state, 5) + 1; i++) {
            uint64_t r = random_range(&gen->rng_state, 10);
            if (r < 3) {
                append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
            } else if (r < 5) {
                append_str(gen, "${");
                append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
                append_char(gen, '}');
            } else if (r < 7) {
                shell_generator_add_arithmetic(gen);
            } else {
                append_str(gen, "text");
            }
        }
        append_char(gen, '"');
    } else {
        append_char(gen, '\'');
        for (int i = 0; i < random_range(&gen->rng_state, 8) + 1; i++) {
            append_char(gen, 'a' + random_range(&gen->rng_state, 26));
        }
        append_char(gen, '\'');
    }
    return true;
}

static bool append_case_pattern(shell_generator_t* gen) {
    uint64_t r = random_range(&gen->rng_state, 10);
    if (r < 3) {
        append_str(gen, "*");
    } else if (r < 5) {
        append_str(gen, "?");
    } else if (r < 7) {
        append_str(gen, "[");
        append_char(gen, 'a' + random_range(&gen->rng_state, 26));
        append_char(gen, '-');
        append_char(gen, 'z');
        append_char(gen, ']');
    } else {
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
    }
    return true;
}

static bool append_case_item(shell_generator_t* gen) {
    append_case_pattern(gen);
    for (uint64_t i = 0; i < random_range(&gen->rng_state, 3); i++) {
        append_char(gen, '|');
        append_case_pattern(gen);
    }
    append_str(gen, ")\n");
    append_simple_command(gen);
    append_str(gen, " ;;\n");
    return true;
}

static bool append_deep_arithmetic(shell_generator_t* gen, uint64_t max_depth) {
    if (max_depth == 0) {
        char val[32];
        snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 100));
        append_str(gen, val);
        return true;
    }
    
    // Check if we should generate invalid arithmetic syntax
    bool generate_invalid = random_range(&gen->rng_state, 100) < gen->invalid_syntax_probability;
    
    if (generate_invalid) {
        uint64_t error_type = random_range(&gen->rng_state, 6);
        switch (error_type) {
            case 0: {
                // Missing operator: "123 456" instead of "123 + 456"
                append_str(gen, "$(( ");
                char val[32];
                snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 1000));
                append_str(gen, val);
                append_char(gen, ' ');
                snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 1000));
                append_str(gen, val);
                append_str(gen, " ))");
                gen->has_unclosed_paren = false;  // Balanced but invalid syntax
                return true;
            }
            case 1: {
                // Trailing operator: "123 + " without second operand
                append_str(gen, "$(( ");
                char val[32];
                snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 1000));
                append_str(gen, val);
                append_char(gen, ' ');
                append_str(gen, operators[random_range(&gen->rng_state, num_operators)]);
                append_str(gen, " ))");
                return true;
            }
            case 2: {
                // Unbalanced parens around expression
                append_str(gen, "$(( ");
                append_char(gen, '(');
                char val[32];
                snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 1000));
                append_str(gen, val);
                append_char(gen, ' ');
                append_str(gen, operators[random_range(&gen->rng_state, num_operators)]);
                append_char(gen, ' ');
                snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 1000));
                append_str(gen, val);
                // Missing closing paren
                append_str(gen, " ))");
                gen->has_unclosed_paren = true;
                return true;
            }
            case 3: {
                // ~ operator after number (should be before): "123 ~" invalid
                append_str(gen, "$(( ");
                char val[32];
                snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 1000));
                append_str(gen, val);
                append_char(gen, ' ');
                append_str(gen, "~ ");
                snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 1000));
                append_str(gen, val);
                append_str(gen, " ))");
                return true;
            }
            case 4: {
                // Unclosed $(( 
                append_str(gen, "$(( ");
                char val[32];
                snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 1000));
                append_str(gen, val);
                gen->has_unclosed_paren = true;
                return true;
            }
            default: {
                // Parenthesis without operator: "(123 + 456)" inside expression
                append_str(gen, "$(( ");
                append_char(gen, '(');
                char val[32];
                snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 1000));
                append_str(gen, val);
                append_char(gen, ' ');
                append_str(gen, operators[random_range(&gen->rng_state, num_operators)]);
                append_char(gen, ' ');
                snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 1000));
                append_str(gen, val);
                append_char(gen, ')');
                append_char(gen, ' ');
                snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 1000));
                append_str(gen, val);
                append_str(gen, " ))");
                return true;
            }
        }
    }
    
    append_str(gen, "$(( ");
    
    uint64_t depth = random_range(&gen->rng_state, 3) + 1;
    for (uint64_t d = 0; d < depth; d++) {
        if (d > 0) append_char(gen, '(');
        
        if (random_range(&gen->rng_state, 4) < 2 && max_depth > 1) {
            append_str(gen, "$(( ");
            append_deep_arithmetic(gen, max_depth - 1);
            append_str(gen, " ))");
        } else {
            char val[32];
            snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 1000));
            append_str(gen, val);
            append_char(gen, ' ');
            append_str(gen, operators[random_range(&gen->rng_state, num_operators)]);
            append_char(gen, ' ');
            snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 1000));
            append_str(gen, val);
        }
        
        if (d > 0) append_char(gen, ')');
        if (d < depth - 1) append_char(gen, ' ');
    }
    
    append_str(gen, " ))");
    return true;
}

static bool append_deep_subshell(shell_generator_t* gen, uint64_t depth) {
    if (depth == 0) {
        append_simple_command(gen);
        return true;
    }
    
    uint64_t type = random_range(&gen->rng_state, 5);
    
    if (type < 2) {
        append_str(gen, "$(");
        append_deep_subshell(gen, depth - 1);
        append_char(gen, ')');
    } else if (type < 4) {
        append_char(gen, '(');
        append_deep_subshell(gen, depth - 1);
        append_char(gen, ')');
    } else {
        append_str(gen, "`");
        append_simple_command(gen);
        append_char(gen, '`');
    }
    
    return true;
}

static bool append_nested_conditionals(shell_generator_t* gen, uint64_t depth) {
    if (depth == 0) {
        append_simple_command(gen);
        return true;
    }
    
    append_str(gen, "if ");
    append_deep_subshell(gen, depth > 2 ? 1 : 0);
    append_str(gen, "; then ");
    
    if (random_range(&gen->rng_state, 3) == 0) {
        append_nested_conditionals(gen, depth - 1);
    } else {
        append_simple_command(gen);
    }
    
    if (random_range(&gen->rng_state, 2) == 0) {
        append_str(gen, "; else ");
        append_simple_command(gen);
    }
    
    append_str(gen, "; fi");
    gen->has_conditionals = true;
    return true;
}

static bool append_case_statement(shell_generator_t* gen) {
    append_str(gen, "case ");
    shell_generator_add_variable(gen);
    append_str(gen, " in\n");
    
    uint64_t num_cases = random_range(&gen->rng_state, 4) + 2;
    for (uint64_t i = 0; i < num_cases; i++) {
        append_case_item(gen);
    }
    
    append_str(gen, "esac");
    gen->has_case = true;
    return true;
}

static bool append_complex_redirect(shell_generator_t* gen) {
    uint64_t r = random_range(&gen->rng_state, 15);
    
    if (r < 4) {
        append_str(gen, ">");
    } else if (r < 7) {
        append_str(gen, ">>");
    } else if (r < 9) {
        append_str(gen, "<");
    } else if (r < 11) {
        append_str(gen, "2>");
    } else if (r < 13) {
        append_str(gen, "2>&1");
    } else {
        append_str(gen, "&>");
    }
    
    append_char(gen, ' ');
    
    if (random_range(&gen->rng_state, 3) == 0) {
        append_process_sub(gen);
    } else {
        append_str(gen, "/tmp/out");
        append_char(gen, '0' + random_range(&gen->rng_state, 10));
        append_str(gen, ".txt");
    }
    
    return true;
}

static bool append_for_loop(shell_generator_t* gen) {
    append_str(gen, "for ");
    append_char(gen, 'i');
    append_str(gen, " in ");
    
    uint64_t num_items = random_range(&gen->rng_state, 5) + 1;
    for (uint64_t i = 0; i < num_items; i++) {
        if (i > 0) append_char(gen, ' ');
        append_str(gen, "item");
        append_char(gen, '0' + i);
    }
    
    append_str(gen, "; do\n");
    append_simple_command(gen);
    append_str(gen, "\ndone");
    gen->has_loops = true;
    return true;
}

static bool append_while_loop(shell_generator_t* gen) {
    append_str(gen, "while ");
    append_deep_subshell(gen, 1);
    append_str(gen, "; do\n");
    append_simple_command(gen);
    append_str(gen, "\ndone");
    gen->has_loops = true;
    return true;
}

static bool append_array_access(shell_generator_t* gen) {
    append_str(gen, "${");
    append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
    append_char(gen, '[');
    
    if (random_range(&gen->rng_state, 2) == 0) {
        char val[16];
        snprintf(val, sizeof(val), "%lu", (unsigned long)random_range(&gen->rng_state, 10));
        append_str(gen, val);
    } else {
        append_str(gen, "@");
    }
    
    append_char(gen, ']');
    append_char(gen, '}');
    return true;
}

static bool append_param_expansion(shell_generator_t* gen) {
    append_str(gen, "${");
    
    uint64_t type = random_range(&gen->rng_state, 8);
    if (type == 0) {
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
        append_str(gen, ":-default}");
    } else if (type == 1) {
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
        append_str(gen, ":=");
        append_str(gen, "value}");
    } else if (type == 2) {
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
        append_str(gen, ":+alternate}");
    } else if (type == 3) {
        append_str(gen, "#");
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
        append_char(gen, '}');
    } else if (type == 4) {
        append_str(gen, "!");
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
        append_char(gen, '}');
    } else if (type == 5) {
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
        append_str(gen, "%suffix}");
    } else if (type == 6) {
        append_str(gen, variables[random_range(&gen->rng_state, num_variables)]);
        append_str(gen, "%%prefix}");
    } else {
        append_str(gen, ":?error}");
    }
    
    return true;
}

static char* shell_generator_generate_malformed(shell_generator_t* gen, size_t max_len) {
    gen->is_malformed = true;
    uint64_t mal_type = random_range(&gen->rng_state, 12);
    
    switch (mal_type) {
        case 0: {
            // Binary: null bytes embedded
            for (uint64_t i = 0; i < random_range(&gen->rng_state, 8) + 1; i++) {
                append_str(gen, "cmd");
                append_char(gen, '\0');
                append_str(gen, "arg");
            }
            break;
        }
        case 1: {
            // Control characters
            for (uint64_t i = 0; i < random_range(&gen->rng_state, 10) + 1; i++) {
                append_char(gen, 0x01 + random_range(&gen->rng_state, 0x1F));
            }
            append_str(gen, "cmd");
            break;
        }
        case 2: {
            // High bytes (binary data)
            for (uint64_t i = 0; i < random_range(&gen->rng_state, 16) + 1; i++) {
                append_char(gen, 0x80 + random_range(&gen->rng_state, 0x80));
            }
            break;
        }
        case 3: {
            // Unbalanced quotes
            append_char(gen, '"');
            append_str(gen, "text");
            // Randomly close or don't close quote
            if (random_range(&gen->rng_state, 2) == 0) {
                // Closed quote - this is actually VALID shell!
                append_char(gen, '"');
                // Not malformed - it's just a quoted command
                gen->is_malformed = false;
            } else {
                // Unclosed quote - truly malformed
                gen->has_unclosed_quote = true;
            }
            break;
        }
        case 4: {
            // Unclosed subshell
            append_str(gen, "$(cmd1 | cmd2");
            gen->has_unclosed_paren = true;
            break;
        }
        case 5: {
            // Unclosed arithmetic
            append_str(gen, "$((1+2");
            gen->has_unclosed_paren = true;
            break;
        }
        case 6: {
            // Truncated/redirection only - but sometimes add a command before
            // to make valid shell like "cmd >" or "cmd > file"
            if (random_range(&gen->rng_state, 3) == 0) {
                // Add a command first - makes it potentially valid
                append_str(gen, "cmd");
                append_char(gen, ' ');
            }
            for (uint64_t i = 0; i < random_range(&gen->rng_state, 5) + 1; i++) {
                if (random_range(&gen->rng_state, 2) == 0) {
                    append_char(gen, '>');
                } else {
                    append_char(gen, '<');
                }
                if (random_range(&gen->rng_state, 2) == 0) {
                    append_char(gen, '>');
                }
                append_char(gen, ' ');
            }
            break;
        }
        case 7: {
            // Just separators - but sometimes add a command before
            if (random_range(&gen->rng_state, 3) == 0) {
                append_str(gen, "cmd");
                append_char(gen, ' ');
            }
            for (uint64_t i = 0; i < random_range(&gen->rng_state, 8) + 1; i++) {
                if (random_range(&gen->rng_state, 4) == 0) append_str(gen, "&&");
                else if (random_range(&gen->rng_state, 3) == 0) append_str(gen, "||");
                else if (random_range(&gen->rng_state, 2) == 0) append_str(gen, ";");
                else append_char(gen, '|');
            }
            break;
        }
        case 8: {
            // Variable without name
            append_char(gen, '$');
            if (random_range(&gen->rng_state, 2) == 0) {
                // ${VAR} - valid if has variable name, invalid if empty
                append_char(gen, '{');
                if (random_range(&gen->rng_state, 3) == 0) {
                    // Empty ${} - invalid
                    append_char(gen, '}');
                    gen->has_unclosed_brace = false;  // It's actually balanced, just empty
                } else {
                    // ${VAR} - valid variable
                    append_str(gen, "VAR");
                    append_char(gen, '}');
                    gen->has_unclosed_brace = false;
                    gen->is_malformed = false;  // Actually valid!
                }
            } else {
                // $VAR - valid variable reference
                append_str(gen, "VAR");
                gen->has_unclosed_brace = false;
                gen->is_malformed = false;  // Actually valid!
            }
            break;
        }
        case 9: {
            // Incomplete glob
            append_str(gen, "*[");
            break;
        }
        case 10: {
            // Binary fuzzer patterns
            if (random_range(&gen->rng_state, 2) == 0) {
                append_char(gen, 0x01);
                append_char(gen, '7');
            } else {
                for (uint64_t i = 0; i < 8; i++) {
                    append_char(gen, 0xFF);
                }
                append_char(gen, 'Y');
            }
            break;
        }
        default: {
            // Random bytes up to max_len
            for (uint64_t i = 0; i < random_range(&gen->rng_state, 20) + 1; i++) {
                append_char(gen, random_range(&gen->rng_state, 256));
            }
            break;
        }
    }
    
    append_char(gen, '\0');
    gen->buffer[gen->buffer_pos - 1] = '\0'; // ensure null terminator
    
    return gen->buffer;
}

char* shell_generator_generate(shell_generator_t* gen, size_t max_len) {
    if (!gen->buffer || gen->buffer_size == 0) {
        return NULL;
    }
    
    gen->buffer_pos = 0;
    gen->buffer[0] = '\0';
    reset_metadata(gen);
    
    // 15% chance: generate malformed/binary edge case instead of valid shell
    if (random_range(&gen->rng_state, 100) < 15) {
        return shell_generator_generate_malformed(gen, max_len);
    }
    
    gen->command_count = 1;  // At least one command
    uint64_t num_subcommands = (random_range(&gen->rng_state, 4)) + 1;
    
    for (uint64_t s = 0; s < num_subcommands; s++) {
        if (s > 0) {
            if (random_range(&gen->rng_state, 10) < 4) {
                append_str(gen, " && ");
            } else if (random_range(&gen->rng_state, 10) < 7) {
                append_str(gen, " || ");
            } else if (random_range(&gen->rng_state, 10) < 9) {
                append_str(gen, " ; ");
            } else {
                append_str(gen, " | ");
            }
        }
        
        uint64_t cmd_type = random_range(&gen->rng_state, 100);
        
        if (cmd_type < 30) {
            append_simple_command(gen);
            
            if (random_range(&gen->rng_state, 10) < 4) {
                for (int i = 0; i < random_range(&gen->rng_state, 3) + 1; i++) {
                    append_char(gen, ' ');
                    append_complex_redirect(gen);
                }
            }
        } else if (cmd_type < 45) {
            shell_generator_add_pipeline(gen);
        } else if (cmd_type < 52) {
            append_str(gen, "if ");
            append_deep_subshell(gen, random_range(&gen->rng_state, 2) + 1);
            append_str(gen, "; then ");
            append_simple_command(gen);
            append_str(gen, "; fi");
            gen->has_conditionals = true;
        } else if (cmd_type < 58) {
            append_str(gen, "if ");
            append_nested_conditionals(gen, 2);
            append_str(gen, "; then ");
            append_simple_command(gen);
            append_str(gen, "; fi");
        } else if (cmd_type < 65) {
            append_simple_command(gen);
            append_str(gen, " | ");
            append_simple_command(gen);
            append_str(gen, " > /dev/null 2>&1");
        } else if (cmd_type < 70) {
            append_simple_command(gen);
            append_char(gen, ' ');
            shell_generator_add_variable(gen);
        } else if (cmd_type < 75) {
            append_simple_command(gen);
            append_char(gen, ' ');
            shell_generator_add_arithmetic(gen);
        } else if (cmd_type < 78) {
            append_deep_arithmetic(gen, 3);
        } else if (cmd_type < 82) {
            shell_generator_add_heredoc(gen);
        } else if (cmd_type < 85) {
            append_simple_command(gen);
            append_char(gen, ' ');
            shell_generator_add_subshell(gen);
        } else if (cmd_type < 88) {
            append_deep_subshell(gen, random_range(&gen->rng_state, 3) + 1);
        } else if (cmd_type < 91) {
            append_case_statement(gen);
        } else if (cmd_type < 94) {
            append_for_loop(gen);
        } else if (cmd_type < 97) {
            append_while_loop(gen);
        } else if (cmd_type < 98) {
            append_simple_command(gen);
            append_char(gen, ' ');
            append_array_access(gen);
        } else {
            append_simple_command(gen);
            append_char(gen, ' ');
            append_param_expansion(gen);
        }
        
        if (gen->buffer_pos > max_len) {
            break;
        }
    }
    
    // Post-generation validation: scan the actual output to verify metadata
    // This fixes false positives where we marked something as invalid but it actually parsed fine
    if (gen->buffer_pos > 0) {
        // Scan for quote balance
        int quote_count = 0;
        for (size_t i = 0; i < gen->buffer_pos; i++) {
            if (gen->buffer[i] == '"' || gen->buffer[i] == '\'') {
                quote_count++;
            }
        }
        // If we marked has_unclosed_quote but quotes are balanced, clear the flag
        if (gen->has_unclosed_quote && quote_count % 2 == 0) {
            gen->has_unclosed_quote = false;
        }
        
        // Scan for ${} empty expansion
        for (size_t i = 0; i + 1 < gen->buffer_pos; i++) {
            if (gen->buffer[i] == '$' && gen->buffer[i+1] == '{') {
                // Check if it's ${
                if (i + 2 < gen->buffer_pos && gen->buffer[i+2] == '}') {
                    // This is ${} - empty expansion, mark as having unclosed brace
                    gen->has_unclosed_brace = true;
                }
            }
        }
        
        // Check for bare $ at end
        char last = gen->buffer[gen->buffer_pos - 1];
        char second_last = gen->buffer_pos > 1 ? gen->buffer[gen->buffer_pos - 2] : '\0';
        if (last == '$' && second_last != '$' && second_last != '{' && 
            second_last != '(' && !isalpha(second_last) && second_last != '_') {
            gen->has_unclosed_brace = true;
        }
    }
    
    // Check for unbalanced arithmetic: count $(( and ))
    int arith_opens = 0;
    for (size_t i = 0; i + 2 < gen->buffer_pos; i++) {
        if (gen->buffer[i] == '$' && gen->buffer[i+1] == '(' && gen->buffer[i+2] == '(') {
            arith_opens++;
        }
    }
    // Count )) - each )) closes one $(( 
    int arith_closes = 0;
    for (size_t i = 0; i + 1 < gen->buffer_pos; i++) {
        if (gen->buffer[i] == ')' && gen->buffer[i+1] == ')') {
            arith_closes++;
        }
    }
    if (arith_opens > arith_closes) {
        gen->has_unclosed_paren = true;
    }
    
    // Post-validation: If the output has actual command content (not just invalid patterns),
    // it might be valid shell. Clear is_malformed if we detect valid patterns.
    if (gen->is_malformed && gen->buffer_pos > 0) {
        bool has_valid_content = false;
        
        // Check for alphanumeric content (potential command names)
        for (size_t i = 0; i < gen->buffer_pos; i++) {
            if (isalpha((unsigned char)gen->buffer[i])) {
                has_valid_content = true;
                break;
            }
        }
        
        // If has valid content and no other malformed indicators, it's probably valid
        if (has_valid_content && !gen->has_unclosed_quote && 
            !gen->has_unclosed_paren && !gen->has_unclosed_brace) {
            gen->is_malformed = false;
        }
    }
    
    append_char(gen, '\0');
    return gen->buffer;
}
