#define _POSIX_C_SOURCE 200809L
#include "shell_abstract.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [OPTIONS] [command]\n", prog);
    fprintf(stderr, "   or: %s [OPTIONS] -f <file>\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -f <file>   Read command from file (one per line)\n");
    fprintf(stderr, "  -e <env>    Add environment variable (VAR=value)\n");
    fprintf(stderr, "  -c <cwd>    Set current working directory\n");
    fprintf(stderr, "  -x          Expand variables using environment\n");
    fprintf(stderr, "  -h          Show this help\n");
}

void print_element(abstract_element_t* elem) {
    printf("    Type: %s\n", shell_abstract_type_name(elem->type));
    printf("    Original: %s\n", elem->original);
    printf("    Abstracted: %s\n", elem->abstraction);
    printf("    Position: %zu-%zu\n", elem->start, elem->end);
    
    switch (elem->type) {
        case ABSTRACT_EV:
        case ABSTRACT_PV:
        case ABSTRACT_SV:
            printf("    Var name: %s\n", elem->data.var.name ? elem->data.var.name : "(null)");
            printf("    Braced: %s\n", elem->data.var.is_braced ? "yes" : "no");
            if (elem->expanded) {
                printf("    Expanded: %s\n", elem->expanded);
            }
            break;
            
        case ABSTRACT_AP:
        case ABSTRACT_RP:
        case ABSTRACT_HP:
            printf("    Path: %s\n", elem->data.path.path ? elem->data.path.path : "(null)");
            printf("    Absolute: %s\n", elem->data.path.is_absolute ? "yes" : "no");
            printf("    Ends with /: %s\n", elem->data.path.ends_with_slash ? "yes" : "no");
            if (elem->expanded) {
                printf("    Expanded: %s\n", elem->expanded);
            }
            break;
            
        case ABSTRACT_GB:
            printf("    Glob pattern: %s\n", elem->data.glob.pattern ? elem->data.glob.pattern : "(null)");
            printf("    Has slash: %s\n", elem->data.glob.has_slash ? "yes" : "no");
            break;
            
        case ABSTRACT_CS:
            printf("    Command: %s\n", elem->data.cmd_subst.content ? elem->data.cmd_subst.content : "(null)");
            break;
            
        default:
            break;
    }
}

void process_command(const char* cmd, runtime_context_t* ctx, bool expand) {
    printf("========================================\n");
    printf("Command: %s\n", cmd);
    printf("========================================\n");
    
    abstracted_command_t* result = NULL;
    
    if (!shell_abstract_command(cmd, &result)) {
        printf("ERROR: Failed to abstract command\n\n");
        return;
    }
    
    printf("\n--- Results ---\n");
    printf("Original:    %s\n", result->original);
    printf("Abstracted:  %s\n", result->abstracted);
    printf("Elements:    %zu\n", result->element_count);
    
    printf("\n--- Flags ---\n");
    printf("Has variables:     %d\n", shell_has_variables(result));
    printf("Has pos_vars:      %d\n", shell_has_pos_vars(result));
    printf("Has special_vars:  %d\n", shell_has_special_vars(result));
    printf("Has globs:         %d\n", shell_has_globs(result));
    printf("Has paths:         %d\n", shell_has_paths(result));
    printf("Has abs_paths:     %d\n", shell_has_abs_paths(result));
    printf("Has rel_paths:     %d\n", shell_has_rel_paths(result));
    printf("Has home_paths:    %d\n", shell_has_home_paths(result));
    printf("Has cmd_subst:     %d\n", shell_has_cmd_subst(result));
    printf("Has arithmetic:    %d\n", shell_has_arithmetic(result));
    printf("Has strings:       %d\n", shell_has_strings(result));
    
    printf("\n--- Elements ---\n");
    for (size_t i = 0; i < result->element_count; i++) {
        printf("\n[%zu] %s\n", i, result->elements[i]->abstraction);
        print_element(result->elements[i]);
    }
    
    // Expand if requested
    if (expand && ctx) {
        printf("\n--- Expansion ---\n");
        if (shell_expand_all_elements(result, ctx)) {
            for (size_t i = 0; i < result->element_count; i++) {
                if (result->elements[i]->expanded) {
                    printf("%s -> %s\n", 
                           result->elements[i]->abstraction,
                           result->elements[i]->expanded);
                }
            }
        }
    }
    
    printf("\n");
    shell_abstracted_destroy(result);
}

int main(int argc, char** argv) {
    const char* filename = NULL;
    bool expand = false;
    char* cwd = NULL;
    char** env_add = NULL;
    int env_count = 0;
    int env_capacity = 10;
    
    env_add = calloc(env_capacity, sizeof(char*));
    if (!env_add) {
        fprintf(stderr, "Memory error\n");
        return 1;
    }
    
    // Parse arguments
    int opt;
    while ((opt = getopt(argc, argv, "f:e:c:xh")) != -1) {
        switch (opt) {
            case 'f':
                filename = optarg;
                break;
            case 'e':
                if (env_count < env_capacity) {
                    env_add[env_count++] = optarg;
                }
                break;
            case 'c':
                cwd = optarg;
                break;
            case 'x':
                expand = true;
                break;
            case 'h':
            default:
                print_usage(argv[0]);
                free(env_add);
                return opt == 'h' ? 0 : 1;
        }
    }
    
    // Build runtime context
    runtime_context_t ctx = {0};
    
    if (cwd) {
        ctx.cwd = cwd;
    } else {
        char buf[4096];
        if (getcwd(buf, sizeof(buf))) {
            ctx.cwd = strdup(buf);
        }
    }
    
    // Build environment (additions first so they take precedence)
    extern char** environ;
    int env_size = 0;
    for (char** e = environ; *e; e++) env_size++;
    
    ctx.env = calloc(env_size + env_count + 1, sizeof(char*));
    if (!ctx.env) {
        fprintf(stderr, "Memory error\n");
        free(env_add);
        free((void*)ctx.cwd);
        return 1;
    }
    
    // Add user-specified env vars first (so they override system vars)
    int idx = 0;
    for (int i = 0; i < env_count; i++) {
        ctx.env[idx++] = env_add[i];
    }
    // Then add system environment, skipping any we've already added
    for (char** e = environ; *e; e++) {
        // Skip if this variable was already added
        bool skip = false;
        for (int i = 0; i < env_count; i++) {
            const char* eq = strchr(env_add[i], '=');
            if (eq) {
                size_t var_len = eq - env_add[i];
                if (strncmp(*e, env_add[i], var_len) == 0 && (*e)[var_len] == '=') {
                    skip = true;
                    break;
                }
            }
        }
        if (!skip) {
            ctx.env[idx++] = *e;
        }
    }
    ctx.env[idx] = NULL;
    
    if (filename) {
        // Read from file
        FILE* f = fopen(filename, "r");
        if (!f) {
            fprintf(stderr, "Error: Cannot open file '%s'\n", filename);
            free(env_add);
            free((void*)ctx.cwd);
            free(ctx.env);
            return 1;
        }
        
        char line[8192];
        while (fgets(line, sizeof(line), f)) {
            // Remove trailing newline
            size_t len = strlen(line);
            if (len > 0 && line[len-1] == '\n') {
                line[len-1] = '\0';
            }
            // Skip empty lines and comments
            if (line[0] == '\0' || line[0] == '#') {
                continue;
            }
            process_command(line, &ctx, expand);
        }
        
        fclose(f);
    } else if (optind < argc) {
        // Command from arguments - join all remaining args
        size_t total_len = 0;
        for (int i = optind; i < argc; i++) {
            total_len += strlen(argv[i]) + 1;
        }
        
        char* cmd = malloc(total_len);
        if (!cmd) {
            fprintf(stderr, "Memory error\n");
            free(env_add);
            free((void*)ctx.cwd);
            free(ctx.env);
            return 1;
        }
        
        cmd[0] = '\0';
        for (int i = optind; i < argc; i++) {
            if (i > optind) strcat(cmd, " ");
            strcat(cmd, argv[i]);
        }
        
        process_command(cmd, &ctx, expand);
        free(cmd);
    } else {
        // Read from stdin
        char line[8192];
        printf("Enter shell commands (Ctrl-D to end):\n");
        while (fgets(line, sizeof(line), stdin)) {
            // Remove trailing newline
            size_t len = strlen(line);
            if (len > 0 && line[len-1] == '\n') {
                line[len-1] = '\0';
            }
            if (line[0] == '\0') continue;
            process_command(line, &ctx, expand);
        }
    }
    
    free(env_add);
    if (cwd != ctx.cwd) free((void*)ctx.cwd);
    free(ctx.env);
    
    return 0;
}
