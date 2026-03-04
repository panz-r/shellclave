#define _POSIX_C_SOURCE 200809L
#include "shell_ast_generator.h"
#include "shell_ast.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
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
    "LC_ALL", "EDITOR", "VISUAL", "PAGER", "MAKEFLAGS", "CC", "CXX",
    "CFLAGS", "CXXFLAGS", "LDFLAGS", "LD_LIBRARY_PATH", "PYTHONPATH"
};

#define NUM_VARIABLES (sizeof(VARIABLES) / sizeof(VARIABLES[0]))

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

static const char* gen_random_variable(shell_ast_generator_t* gen) {
    return VARIABLES[random_range(gen, NUM_VARIABLES)];
}

static const char* gen_random_file(shell_ast_generator_t* gen) {
    static char buf[64];
    snprintf(buf, sizeof(buf), "/tmp/test%u.txt", (unsigned)random_range(gen, 10));
    return buf;
}

static ast_node_t* gen_command(shell_ast_generator_t* gen, shell_ast_t* ast) {
    return shell_ast_add_command(ast, gen_random_command(gen));
}

static ast_node_t* gen_variable(shell_ast_generator_t* gen, shell_ast_t* ast, bool braced) {
    return shell_ast_add_variable(ast, gen_random_variable(gen), braced);
}

static ast_node_t* gen_redirect(shell_ast_generator_t* gen, shell_ast_t* ast, ast_node_t* cmd) {
    int type = random_range(gen, 5);
    const char* target = gen_random_file(gen);
    
    switch (type) {
        case 0: return shell_ast_add_redirect(ast, cmd, target, -1, false, false, false);
        case 1: return shell_ast_add_redirect(ast, cmd, target, -1, false, true, false);
        case 2: return shell_ast_add_redirect(ast, cmd, target, -1, true, false, false);
        case 3: return shell_ast_add_redirect(ast, cmd, target, 2, false, false, true);
        case 4: return shell_ast_add_redirect(ast, cmd, target, 2, false, true, true);
        default: return cmd;
    }
}

static ast_node_t* gen_command_with_redirects(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* cmd = gen_command(gen, ast);
    if (random_range(gen, 4) == 0) {
        cmd = gen_redirect(gen, ast, cmd);
    }
    return cmd;
}

static ast_node_t* gen_pipeline(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* cmd1 = gen_command_with_redirects(gen, ast);
    ast_node_t* cmd2 = gen_command_with_redirects(gen, ast);
    return shell_ast_add_pipeline(ast, cmd1, cmd2);
}

static ast_node_t* gen_sequence(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* cmd1 = gen_command_with_redirects(gen, ast);
    ast_node_t* cmd2 = gen_command_with_redirects(gen, ast);
    const char* sep = ";";
    int sep_type = random_range(gen, 3);
    if (sep_type == 0) sep = "&&";
    else if (sep_type == 1) sep = "||";
    return shell_ast_add_sequence(ast, cmd1, cmd2, sep);
}

static ast_node_t* gen_subshell(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* inner = gen_command_with_redirects(gen, ast);
    return shell_ast_add_subshell(ast, inner);
}

static ast_node_t* gen_process_sub(shell_ast_generator_t* gen, shell_ast_t* ast) {
    ast_node_t* cmd = gen_command(gen, ast);
    bool is_input = (random_range(gen, 2) == 0);
    return shell_ast_add_process_sub(ast, cmd, is_input);
}

static ast_node_t* gen_variable_ref(shell_ast_generator_t* gen, shell_ast_t* ast) {
    bool braced = (random_range(gen, 2) == 0);
    return gen_variable(gen, ast, braced);
}

static ast_node_t* gen_arithmetic(shell_ast_generator_t* gen, shell_ast_t* ast) {
    bool unclosed = (random_range(gen, 5) == 0);
    return shell_ast_add_arithmetic(ast, "1 + 2", unclosed);
}

static void gen_valid_shell(shell_ast_generator_t* gen, shell_ast_t* ast) {
    int type = random_range(gen, 100);
    
    if (type < 30) {
        ast->root = gen_command_with_redirects(gen, ast);
    } else if (type < 50) {
        ast->root = gen_pipeline(gen, ast);
    } else if (type < 65) {
        ast->root = gen_sequence(gen, ast);
    } else if (type < 75) {
        ast->root = gen_subshell(gen, ast);
    } else if (type < 85) {
        ast->root = gen_command_with_redirects(gen, ast);
    } else if (type < 90) {
        ast->root = gen_arithmetic(gen, ast);
        if (ast->root && !ast->root->is_valid) {
            ast->has_unclosed_paren = true;
            ast->has_valid_structure = false;
        }
    } else {
        ast->root = gen_process_sub(gen, ast);
        ast->has_process_sub = true;
    }
    
    if (ast->root) {
        ast->has_valid_structure = true;
    }
}

static void gen_invalid_shell(shell_ast_generator_t* gen, shell_ast_t* ast) {
    int type = random_range(gen, 10);
    
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
        default:
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
    
    bool generate_invalid = (random_range(gen, 100) < 20);
    
    if (generate_invalid) {
        gen_invalid_shell(gen, ast);
    } else {
        gen_valid_shell(gen, ast);
    }
    
    return ast;
}
