#define _POSIX_C_SOURCE 200809L
#include "shell_ast_generator.h"
#include "shell_ast.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>

typedef struct shell_ast_generator_internal {
    uint64_t rng_state;
    size_t max_len;
    shell_ast_t* current_ast;
} shell_ast_generator_internal_t;

static uint64_t splitmix64(uint64_t x) {
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

static uint64_t random_next(shell_ast_generator_t* gen) {
    shell_ast_generator_internal_t* g = (shell_ast_generator_internal_t*)gen;
    g->rng_state = splitmix64(g->rng_state);
    return g->rng_state;
}

static uint64_t random_range(shell_ast_generator_t* gen, uint64_t max) {
    if (max == 0) return 0;
    return random_next(gen) % max;
}

static const char* COMMANDS[] = {
    "ls", "cat", "echo", "grep", "sed", "awk", "find", "sort", "uniq", "head",
    "tail", "wc", "tr", "cut", "paste", "diff", "comm", "vim", "nano", "less",
    "more", "tar", "gzip", "gunzip", "zip", "unzip", "curl", "wget", "ssh",
    "scp", "rsync", "make", "gcc", "g++", "clang", "python", "perl", "ruby",
    "node", "npm", "git", "svn", "hg", "chmod", "chown", "chgrp", "mkdir",
    "rmdir", "rm", "mv", "cp", "touch", "ln", "df", "du", "free", "top",
    "ps", "pidof", "kill", "killall", "pgrep", "pkill", "whoami", "id",
    "hostname", "uname", "date", "cal", "uptime", "dmesg", "journalctl"
};

#define NUM_COMMANDS (sizeof(COMMANDS) / sizeof(COMMANDS[0]))

static const char* VARIABLES[] = {
    "HOME", "USER", "PATH", "PWD", "SHELL", "TERM", "HOSTNAME", "LANG",
    "SHLVL", "DISPLAY", "EDITOR", "VISUAL", "PAGER", "MAIL", "TZ"
};

#define NUM_VARIABLES (sizeof(VARIABLES) / sizeof(VARIABLES[0]))

static const char* GLOB_PATTERNS[] = {
    "*.txt", "*.log", "*.conf", "*.sh", "*.c", "*.h", "*.o",
    "file?.dat", "test[0-9]*.txt", "data*.csv", "*.{txt,log}",
    "dir/*", "dir/**/*.c", "file??.*", "*.tmp"
};

#define NUM_GLOB_PATTERNS (sizeof(GLOB_PATTERNS) / sizeof(GLOB_PATTERNS[0]))

static const char* CASE_PATTERNS[] = {
    "*.txt", "*.log", "*", "foo", "bar", "[0-9]*"
};

#define NUM_CASE_PATTERNS (sizeof(CASE_PATTERNS) / sizeof(CASE_PATTERNS[0]))

static const char* LOOP_TYPES[] = {"while", "until", "for"};

static const char* ARITHMETIC_EXPRS[] = {
    "1 + 2", "x - y", "a * b", "p / q", "n % m",
    "i++", "j--", "a += 3", "b -= 1", "x = y",
    "(a + b) * c", "a > b ? a : b", "a & b", "a | b", "a ^ b"
};

#define NUM_ARITHMETIC (sizeof(ARITHMETIC_EXPRS) / sizeof(ARITHMETIC_EXPRS[0]))

shell_ast_generator_t* shell_ast_generator_create(uint64_t seed) {
    shell_ast_generator_internal_t* g = (shell_ast_generator_internal_t*)calloc(1, sizeof(shell_ast_generator_internal_t));
    if (!g) return NULL;
    g->rng_state = seed ? seed : (uint64_t)time(NULL);
    return (shell_ast_generator_t*)g;
}

void shell_ast_generator_destroy(shell_ast_generator_t* gen) {
    if (gen) {
        free(gen);
    }
}

static const char* gen_random_command(shell_ast_generator_t* gen) {
    return COMMANDS[random_range(gen, NUM_COMMANDS)];
}

static const char* gen_random_file(shell_ast_generator_t* gen) {
    static char buf[64];
    snprintf(buf, sizeof(buf), "/tmp/test%u.txt", (unsigned)random_range(gen, 10));
    return buf;
}

static const char* gen_random_variable(shell_ast_generator_t* gen) {
    return VARIABLES[random_range(gen, NUM_VARIABLES)];
}

static const char* gen_random_glob(shell_ast_generator_t* gen) {
    return GLOB_PATTERNS[random_range(gen, NUM_GLOB_PATTERNS)];
}

static const char* gen_random_case_pattern(shell_ast_generator_t* gen) {
    return CASE_PATTERNS[random_range(gen, NUM_CASE_PATTERNS)];
}

static const char* gen_random_arithmetic(shell_ast_generator_t* gen) {
    return ARITHMETIC_EXPRS[random_range(gen, NUM_ARITHMETIC)];
}

// ============================================================
// Phase 1: Generator functions for each AST type
// ============================================================

static ast_node_t* gen_command(shell_ast_generator_t* gen, shell_ast_t* ast) {
    return shell_ast_add_command(ast, gen_random_command(gen));
}

static ast_node_t* gen_command_with_redirects(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* cmd = gen_command(gen, ast);
    if (random_range(gen, 4) == 0) {
        int type = random_range(gen, 5);
        const char* target = gen_random_file(gen);
        
        // Ensure target is never empty - always use a valid filename
        if (!target || strlen(target) == 0) {
            target = "/tmp/test.txt";
        }
        
        switch (type) {
            case 0: cmd = shell_ast_add_redirect(ast, cmd, target, -1, false, false, false); break;
            case 1: cmd = shell_ast_add_redirect(ast, cmd, target, -1, true, false, false); break;
            case 2: cmd = shell_ast_add_redirect(ast, cmd, target, -1, false, true, false); break;
            case 3: cmd = shell_ast_add_redirect(ast, cmd, target, 2, false, false, true); break;
            case 4: cmd = shell_ast_add_redirect(ast, cmd, target, 2, false, true, true); break;
        }
    }
    return cmd;
}

// Generate variable: $VAR or ${VAR}
static ast_node_t* gen_variable(shell_ast_generator_t* gen, shell_ast_t* ast) {
    bool is_braced = (random_range(gen, 2) == 0);
    const char* var_name = gen_random_variable(gen);
    // Ensure variable name is never empty - always use a valid name
    if (!var_name || strlen(var_name) == 0) {
        var_name = "HOME";
    }
    return shell_ast_add_variable(ast, var_name, is_braced);
}

// Generate quoted string: 'single' or "double"
static ast_node_t* gen_quote(shell_ast_generator_t* gen, shell_ast_t* ast) {
    char quote_char = (random_range(gen, 2) == 0) ? '"' : '\'';
    bool is_closed = (random_range(gen, 10) != 0); // 90% closed
    const char* content = "hello world test content";
    return shell_ast_add_quote(ast, content, quote_char, is_closed);
}

// Generate glob pattern: *.txt, file?.log, etc.
static ast_node_t* gen_glob(shell_ast_generator_t* gen, shell_ast_t* ast) {
    const char* pattern = gen_random_glob(gen);
    return shell_ast_add_glob(ast, pattern);
}

// Generate heredoc: <<DELIM content DELIM
static ast_node_t* gen_heredoc(shell_ast_generator_t* gen, shell_ast_t* ast) {
    bool is_closed = (random_range(gen, 10) != 0); // 90% closed
    const char* delim = "EOF";
    const char* content = "heredoc content line 1\nline 2\nline 3";
    
    ast_node_t* node = shell_ast_add_heredoc(ast, delim, content);
    if (node && !is_closed) {
        node->is_valid = false;
        ast->has_heredoc = true;
        ast->has_valid_structure = false;
        // Mark as unclosed by not having child with content
        if (node->child) {
            free(node->child);
            node->child = NULL;
        }
    }
    return node;
}

// Generate case statement: case VAR in pattern) cmd;; esac
static ast_node_t* gen_case(shell_ast_generator_t* gen, shell_ast_t* ast) {
    const char* var = gen_random_variable(gen);
    const char* pattern = gen_random_case_pattern(gen);
    ast_node_t* body = gen_command_with_redirects(gen, ast);
    return shell_ast_add_case(ast, var, pattern, body);
}

// Generate if statement: if cmd then cmd [else cmd] fi
static ast_node_t* gen_if(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* condition = gen_command_with_redirects(gen, ast);
    ast_node_t* then_branch = gen_command_with_redirects(gen, ast);
    return shell_ast_add_if(ast, condition, then_branch);
}

// Generate loop: while/until/for
static ast_node_t* gen_loop(shell_ast_generator_t* gen, shell_ast_t* ast) {
    const char* loop_type = LOOP_TYPES[random_range(gen, 3)];
    ast_node_t* body = gen_command_with_redirects(gen, ast);
    ast_node_t* list = gen_command_with_redirects(gen, ast);
    return shell_ast_add_loop(ast, loop_type, "i", list, body);
}

// Generate arithmetic: $(( expr ))
static ast_node_t* gen_arithmetic(shell_ast_generator_t* gen, shell_ast_t* ast) {
    bool is_unclosed = (random_range(gen, 5) == 0);
    const char* expr = gen_random_arithmetic(gen);
    return shell_ast_add_arithmetic(ast, expr, is_unclosed);
}

// Generate subshell: ( cmd )
static ast_node_t* gen_subshell(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* inner = gen_command_with_redirects(gen, ast);
    return shell_ast_add_subshell(ast, inner);
}

// Generate process substitution: <(cmd) or >(cmd)
static ast_node_t* gen_process_sub(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* cmd = gen_command(gen, ast);
    bool is_input = (random_range(gen, 2) == 0);
    return shell_ast_add_process_sub(ast, cmd, is_input);
}

// Generate pipeline: cmd1 | cmd2
static ast_node_t* gen_pipeline(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* cmd1 = gen_command_with_redirects(gen, ast);
    ast_node_t* cmd2 = gen_command_with_redirects(gen, ast);
    return shell_ast_add_pipeline(ast, cmd1, cmd2);
}

// Generate sequence: cmd1 ; cmd2 or cmd1 && cmd2 or cmd1 || cmd2
static ast_node_t* gen_sequence(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* cmd1 = gen_command_with_redirects(gen, ast);
    ast_node_t* cmd2 = gen_command_with_redirects(gen, ast);
    const char* sep = ";";
    int sep_type = random_range(gen, 3);
    if (sep_type == 0) sep = "&&";
    else if (sep_type == 1) sep = "||";
    return shell_ast_add_sequence(ast, cmd1, cmd2, sep);
}

// ============================================================
// Phase 2: Complex combinations
// ============================================================

// cmd $VAR *.txt > file - variable + glob + redirect
static void gen_complex_var_glob_redirect(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* cmd = gen_command(gen, ast);
    // Add variable as argument
    ast_node_t* var_node = gen_variable(gen, ast);
    var_node->next = cmd;
    // Add glob as another argument
    ast_node_t* glob_node = gen_glob(gen, ast);
    glob_node->next = var_node;
    // Add redirect
    const char* target = gen_random_file(gen);
    cmd = shell_ast_add_redirect(ast, cmd, target, -1, false, false, false);
    ast->root = cmd;
    ast->has_valid_structure = true;
    ast->has_redirect = true;
}

// echo $(cmd) | grep $PATTERN - subshell in pipeline
static void gen_subshell_in_pipeline(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* cmd1 = shell_ast_add_command(ast, "echo");
    ast_node_t* subshell = gen_subshell(gen, ast);
    subshell->next = cmd1;
    
    ast_node_t* cmd2 = shell_ast_add_command(ast, "grep");
    ast_node_t* var = gen_variable(gen, ast);
    var->next = cmd2;
    
    ast->root = shell_ast_add_pipeline(ast, cmd1, cmd2);
    ast->has_valid_structure = true;
    ast->has_subshell = true;
}

// cmd && $VAR || other - compound with variables
static void gen_compound_with_vars(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* cmd1 = gen_command(gen, ast);
    ast_node_t* var1 = gen_variable(gen, ast);
    var1->next = cmd1;
    
    ast_node_t* seq1 = shell_ast_add_sequence(ast, cmd1, var1, "&&");
    
    ast_node_t* cmd2 = gen_command(gen, ast);
    ast_node_t* var2 = gen_variable(gen, ast);
    var2->next = cmd2;
    
    ast->root = shell_ast_add_sequence(ast, seq1, cmd2, "||");
    ast->has_valid_structure = true;
}

// $((VAR + 1)) && cmd - arithmetic with command
static void gen_arithmetic_compound(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* arith = gen_arithmetic(gen, ast);
    if (arith && !arith->is_valid) {
        ast->has_unclosed_paren = true;
        ast->has_valid_structure = false;
        ast->root = arith;
        return;
    }
    
    ast_node_t* cmd = gen_command(gen, ast);
    ast->root = shell_ast_add_sequence(ast, arith, cmd, "&&");
    ast->has_valid_structure = true;
    ast->has_arithmetic = true;
}

// while read line; do echo $line; done < file - loop with redirect
static void gen_loop_with_redirect(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* body = gen_command(gen, ast);
    ast_node_t* var = gen_variable(gen, ast);
    var->next = body;
    
    ast_node_t* list = shell_ast_add_command(ast, "read");
    ast_node_t* loop = shell_ast_add_loop(ast, "while", "line", list, body);
    
    const char* target = gen_random_file(gen);
    ast_node_t* cmd = shell_ast_add_redirect(ast, body, target, -1, true, false, false);
    (void)cmd;
    
    ast->root = loop;
    ast->has_valid_structure = true;
    ast->has_loops = true;
    ast->has_redirect = true;
}

// cat <<EOF | grep pattern - heredoc in pipeline
static void gen_heredoc_in_pipeline(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* heredoc = gen_heredoc(gen, ast);
    if (heredoc && !heredoc->is_valid) {
        ast->root = heredoc;
        ast->has_valid_structure = false;
        ast->has_heredoc = true;
        return;
    }
    
    ast_node_t* cmd1 = shell_ast_add_command(ast, "cat");
    ast_node_t* cmd2 = shell_ast_add_command(ast, "grep");
    ast_node_t* pattern = gen_glob(gen, ast); // Use glob as pattern
    pattern->next = cmd2;
    
    ast->root = shell_ast_add_pipeline(ast, cmd1, cmd2);
    ast->has_valid_structure = true;
    ast->has_heredoc = true;
}

// "quoted $VAR" - quoted string with variable
static void gen_quoted_with_var(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* cmd = gen_command(gen, ast);
    ast_node_t* quote = gen_quote(gen, ast);
    // Force closed for valid case
    quote->is_valid = true;
    quote->next = cmd;
    
    ast->root = cmd;
    ast->has_valid_structure = true;
    ast->has_unclosed_quote = false;
}

// for f in *.txt; do cat $f; done - glob in loop
static void gen_glob_in_loop(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* glob = gen_glob(gen, ast);
    ast_node_t* body = gen_command(gen, ast);
    ast_node_t* var = gen_variable(gen, ast);
    var->next = body;
    
    ast_node_t* list = glob;
    ast_node_t* loop = shell_ast_add_loop(ast, "for", "f", list, body);
    
    ast->root = loop;
    ast->has_valid_structure = true;
    ast->has_loops = true;
    ast->has_glob = true;
}

// ============================================================
// Phase 3: Invalid cases - more comprehensive
// ============================================================

// Unclosed heredoc without closing delimiter
static void gen_unclosed_heredoc(shell_ast_generator_t* gen, shell_ast_t* ast) {
    (void)gen;
    ast_node_t* node = shell_ast_add_heredoc(ast, "EOF", NULL); // No content = unclosed
    if (node) {
        node->is_valid = false;
        ast->root = node;
        ast->has_heredoc = true;
        ast->has_valid_structure = false;
    }
}

// Mismatched quotes: "hello' - open double, close single
static void gen_mismatched_quotes(shell_ast_generator_t* gen, shell_ast_t* ast) {
    (void)gen;
    ast_node_t* node = shell_ast_add_quote(ast, "hello", '"', false);
    if (node) {
        // Mark as having quote mismatch by setting is_braced incorrectly
        node->is_braced = false; // Single quote marker but content from double
        ast->root = node;
        ast->has_unclosed_quote = true;
        ast->has_valid_structure = false;
    }
}

// Unclosed backtick: using command with invalid flag to represent unclosed backtick
// We create "``" (empty backticks) which is truly invalid in bash
static void gen_unclosed_backtick(shell_ast_generator_t* gen, shell_ast_t* ast) {
    (void)gen;
    // Use a quoted empty string with mismatched quotes to create truly invalid syntax
    ast_node_t* node = shell_ast_add_quote(ast, "", '"', false); // unclosed double quote
    if (node) {
        ast->root = node;
        ast->has_unclosed_quote = true;
        ast->has_valid_structure = false;
    }
}

// Invalid glob - use a pattern that bash actually rejects
// Since bash is very lenient, we use a command separator that triggers parse error
static void gen_invalid_glob(shell_ast_generator_t* gen, shell_ast_t* ast) {
    (void)gen;
    // Use "||" which is invalid in bash
    ast_node_t* node = shell_ast_add_command(ast, "||");
    if (node) {
        node->is_valid = false;
        ast->root = node;
        ast->has_valid_structure = false;
    }
}

// Nested unclosed: ${VAR$(cmd
static void gen_nested_unclosed(shell_ast_generator_t* gen, shell_ast_t* ast) {
    (void)gen;
    ast_node_t* node = shell_ast_add_variable(ast, "", true); // Empty braced variable
    if (node) {
        node->is_valid = false;
        ast->root = node;
        ast->has_unclosed_brace = true;
        ast->has_valid_structure = false;
    }
}

// Empty command with operators: | cmd (leading separator)
static void gen_leading_separator(shell_ast_generator_t* gen, shell_ast_t* ast) {
    (void)gen;
    ast_node_t* node = shell_ast_add_sequence(ast, NULL, NULL, "|");
    if (node) {
        node->is_valid = false;
        ast->root = node;
        ast->has_valid_structure = false;
    }
}

// Invalid arithmetic: $(( without closing
static void gen_invalid_arithmetic(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* node = shell_ast_add_arithmetic(ast, "", true); // Empty unclosed
    if (node) {
        ast->root = node;
        ast->has_arithmetic = true;
        ast->has_unclosed_paren = true;
        ast->has_valid_structure = false;
    }
}

// Unclosed subshell: ( cmd without )
static void gen_unclosed_subshell(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* node = shell_ast_add_subshell(ast, gen_command(gen, ast));
    if (node) {
        node->is_valid = false;
        ast->root = node;
        ast->has_subshell = true;
        ast->has_unclosed_paren = true;
        ast->has_valid_structure = false;
    }
}

// Invalid redirect target: cmd > (no file)
static void gen_missing_redirect_target(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* cmd = gen_command(gen, ast);
    ast_node_t* node = shell_ast_add_redirect(ast, cmd, "", -1, false, false, false);
    if (node) {
        node->is_valid = false;
        ast->root = node;
        ast->has_redirect = true;
        ast->has_valid_structure = false;
    }
}

// Multiple unclosed: unclosed quote + paren
static void gen_multiple_unclosed(shell_ast_generator_t* gen, shell_ast_t* ast) {
    (void)gen;
    // Create unclosed quote
    ast_node_t* quote = shell_ast_add_quote(ast, "text", '"', false);
    // Create unclosed paren
    ast_node_t* paren = shell_ast_add_subshell(ast, NULL);
    if (paren) paren->is_valid = false;
    
    // Chain them - both invalid
    if (quote) {
        quote->next = paren;
        ast->root = quote;
    } else {
        ast->root = paren;
    }
    
    ast->has_unclosed_quote = true;
    ast->has_unclosed_paren = true;
    ast->has_valid_structure = false;
}

// Invalid case without esac
static void gen_incomplete_case(shell_ast_generator_t* gen, shell_ast_t* ast) {
    (void)gen;
    ast_node_t* node = shell_ast_add_case(ast, "$VAR", "pattern", gen_command(gen, ast));
    if (node) {
        node->is_valid = false;
        ast->root = node;
        ast->has_case = true;
        ast->has_valid_structure = false;
    }
}

// Invalid if without fi
static void gen_incomplete_if(shell_ast_generator_t* gen, shell_ast_t* ast) {
    (void)gen;
    ast_node_t* node = shell_ast_add_if(ast, gen_command(gen, ast), gen_command(gen, ast));
    if (node) {
        node->is_valid = false;
        ast->root = node;
        ast->has_conditionals = true;
        ast->has_valid_structure = false;
    }
}

// Invalid loop without done
static void gen_incomplete_loop(shell_ast_generator_t* gen, shell_ast_t* ast) {
    (void)gen;
    ast_node_t* node = shell_ast_add_loop(ast, "while", "i", gen_command(gen, ast), gen_command(gen, ast));
    if (node) {
        node->is_valid = false;
        ast->root = node;
        ast->has_loops = true;
        ast->has_valid_structure = false;
    }
}

// Empty command
static void gen_empty_command(shell_ast_generator_t* gen, shell_ast_t* ast) {
    (void)gen;
    ast->root = NULL;
    ast->has_valid_structure = false;
}

// Whitespace only
static void gen_whitespace_only(shell_ast_generator_t* gen, shell_ast_t* ast) {
    (void)gen;
    ast_node_t* node = shell_ast_add_command(ast, "   \t\t   ");
    if (node) {
        node->is_valid = false;
        ast->root = node;
        ast->has_valid_structure = false;
    }
}

// ============================================================
// Main generator functions
// ============================================================

static void gen_valid_shell(shell_ast_generator_t* gen, shell_ast_t* ast) {
    int type = random_range(gen, 100);
    
    if (type < 20) {
        // Simple command with optional redirect
        ast->root = gen_command_with_redirects(gen, ast);
    } else if (type < 30) {
        // Simple command with variable
        ast_node_t* cmd = gen_command(gen, ast);
        ast_node_t* var = gen_variable(gen, ast);
        var->next = cmd;
        ast->root = cmd;
    } else if (type < 40) {
        // Command with glob
        ast_node_t* cmd = gen_command(gen, ast);
        ast_node_t* glob = gen_glob(gen, ast);
        glob->next = cmd;
        ast->root = cmd;
    } else if (type < 50) {
        // Pipeline
        ast->root = gen_pipeline(gen, ast);
    } else if (type < 60) {
        // Sequence (; or && or ||)
        ast->root = gen_sequence(gen, ast);
    } else if (type < 68) {
        // Subshell
        ast->root = gen_subshell(gen, ast);
        ast->has_subshell = true;
    } else if (type < 75) {
        // Arithmetic
        ast->root = gen_arithmetic(gen, ast);
        if (ast->root && !ast->root->is_valid) {
            ast->has_unclosed_paren = true;
            ast->has_valid_structure = false;
            return;
        }
        ast->has_arithmetic = true;
    } else if (type < 80) {
        // Process substitution
        ast->root = gen_process_sub(gen, ast);
        ast->has_process_sub = true;
    } else if (type < 84) {
        // Quoted string
        ast_node_t* cmd = gen_command(gen, ast);
        ast_node_t* quote = gen_quote(gen, ast);
        // Force closed for valid shell - must also clear the flags that might have been set
        quote->is_valid = true;
        quote->next = cmd;
        ast->root = cmd;
        // Clear flags that might have been set by unclosed quote
        ast->has_unclosed_quote = false;
        ast->has_valid_structure = true;
    } else if (type < 87) {
        // Loop (for/while/until)
        ast->root = gen_loop(gen, ast);
        ast->has_loops = true;
    } else if (type < 90) {
        // If statement
        ast->root = gen_if(gen, ast);
        ast->has_conditionals = true;
    } else if (type < 92) {
        // Case statement
        ast->root = gen_case(gen, ast);
        ast->has_case = true;
    } else if (type < 94) {
        // Complex: variable + glob + redirect
        gen_complex_var_glob_redirect(gen, ast);
    } else if (type < 96) {
        // Complex: subshell in pipeline
        gen_subshell_in_pipeline(gen, ast);
    } else if (type < 98) {
        // Complex: compound with variables
        gen_compound_with_vars(gen, ast);
    } else {
        // Complex: glob in loop
        gen_glob_in_loop(gen, ast);
    }
    
    if (ast->root) {
        ast->has_valid_structure = true;
    }
}

static void gen_invalid_shell(shell_ast_generator_t* gen, shell_ast_t* ast) {
    int type = random_range(gen, 25);
    
    switch (type) {
        case 0:
            shell_ast_add_binary(ast);
            break;
        case 1:
            shell_ast_add_control_char(ast);
            break;
        case 2:
            shell_ast_add_high_bytes(ast);
            break;
        case 3:
            shell_ast_add_unclosed_quote(ast, '"');
            break;
        case 4:
            shell_ast_add_unclosed_paren(ast);
            break;
        case 5:
            shell_ast_add_unclosed_brace(ast);
            break;
        case 6:
            shell_ast_add_bare_redirect(ast);
            break;
        case 7:
            shell_ast_add_separators_only(ast);
            break;
        case 8:
            shell_ast_add_incomplete_glob(ast);
            break;
        case 9:
            // New: Unclosed heredoc
            gen_unclosed_heredoc(gen, ast);
            break;
        case 10:
            // New: Mismatched quotes
            gen_mismatched_quotes(gen, ast);
            break;
        case 11:
            // New: Unclosed backtick (invalid command)
            gen_unclosed_backtick(gen, ast);
            break;
        case 12:
            // New: Invalid glob pattern
            gen_invalid_glob(gen, ast);
            break;
        case 13:
            // New: Nested unclosed
            gen_nested_unclosed(gen, ast);
            break;
        case 14:
            // New: Leading separator
            gen_leading_separator(gen, ast);
            break;
        case 15:
            // New: Invalid arithmetic
            gen_invalid_arithmetic(gen, ast);
            break;
        case 16:
            // New: Unclosed subshell
            gen_unclosed_subshell(gen, ast);
            break;
        case 17:
            // New: Missing redirect target
            gen_missing_redirect_target(gen, ast);
            break;
        case 18:
            // New: Multiple unclosed
            gen_multiple_unclosed(gen, ast);
            break;
        case 19:
            // New: Incomplete case
            gen_incomplete_case(gen, ast);
            break;
        case 20:
            // New: Incomplete if
            gen_incomplete_if(gen, ast);
            break;
        case 21:
            // New: Incomplete loop
            gen_incomplete_loop(gen, ast);
            break;
        case 22:
            // New: Empty command
            gen_empty_command(gen, ast);
            break;
        case 23:
            // New: Whitespace only
            gen_whitespace_only(gen, ast);
            break;
        default:
            // Fallback to existing
            shell_ast_add_binary(ast);
            break;
    }
}

shell_ast_t* shell_ast_generator_generate(shell_ast_generator_t* gen, size_t max_len) {
    shell_ast_generator_internal_t* g = (shell_ast_generator_internal_t*)gen;
    g->max_len = max_len;
    
    shell_ast_t* ast = shell_ast_create();
    if (!ast) return NULL;
    
    g->current_ast = ast;
    
    // Increase invalid generation rate to test more edge cases
    bool generate_invalid = (random_range(gen, 100) < 30);
    
    if (generate_invalid) {
        gen_invalid_shell(gen, ast);
    } else {
        gen_valid_shell(gen, ast);
    }
    
    return ast;
}
