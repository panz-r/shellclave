#define _POSIX_C_SOURCE 200809L
#include "shell_ast.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

static ast_node_t* ast_node_create(ast_node_type_t type) {
    ast_node_t* node = (ast_node_t*)calloc(1, sizeof(ast_node_t));
    if (node) {
        node->type = type;
        node->redirect_fd = -1;
        node->is_valid = true;
    }
    return node;
}

shell_ast_t* shell_ast_create(void) {
    shell_ast_t* ast = (shell_ast_t*)calloc(1, sizeof(shell_ast_t));
    return ast;
}

static void free_ast_node(ast_node_t* node) {
    if (!node) return;
    free_ast_node(node->child);
    free_ast_node(node->next);
    free(node->value);
    free(node->redirect_target);
    free(node);
}

void shell_ast_destroy(shell_ast_t* ast) {
    if (!ast) return;
    free_ast_node(ast->root);
    free(ast);
}

ast_node_t* shell_ast_add_command(shell_ast_t* ast, const char* command) {
    if (!ast || !command) return NULL;
    
    ast_node_t* node = ast_node_create(AST_COMMAND);
    if (node) {
        node->value = strdup(command);
        ast->node_count++;
    }
    return node;
}

ast_node_t* shell_ast_add_pipeline(shell_ast_t* ast, ast_node_t* cmd1, ast_node_t* cmd2) {
    if (!ast || !cmd1 || !cmd2) return NULL;
    
    ast_node_t* node = ast_node_create(AST_PIPELINE);
    if (node) {
        node->child = cmd1;
        node->next = cmd2;
        ast->node_count++;
    }
    return node;
}

ast_node_t* shell_ast_add_sequence(shell_ast_t* ast, ast_node_t* cmd1, ast_node_t* cmd2, const char* separator) {
    if (!ast || !cmd1 || !cmd2) return NULL;
    
    ast_node_t* node = ast_node_create(AST_SEQUENCE);
    if (node) {
        node->child = cmd1;
        node->next = cmd2;
        node->value = separator ? strdup(separator) : strdup(";");
        ast->node_count++;
    }
    return node;
}

ast_node_t* shell_ast_add_subshell(shell_ast_t* ast, ast_node_t* content) {
    if (!ast) return NULL;
    
    ast_node_t* node = ast_node_create(AST_SUBSHELL);
    if (node) {
        node->child = content;
        ast->node_count++;
        ast->has_subshell = true;
    }
    return node;
}

ast_node_t* shell_ast_add_redirect(shell_ast_t* ast, ast_node_t* cmd, const char* target, 
                                   int fd, bool is_input, bool is_append, bool is_stderr) {
    if (!ast || !cmd) return NULL;
    
    ast_node_t* node = ast_node_create(AST_REDIRECT);
    if (node) {
        node->child = cmd;
        node->redirect_target = target ? strdup(target) : NULL;
        node->redirect_fd = fd;
        node->is_input_redirect = is_input;
        node->is_append = is_append;
        node->is_stderr_redirect = is_stderr;
        ast->node_count++;
        ast->has_redirect = true;
    }
    return node;
}

ast_node_t* shell_ast_add_variable(shell_ast_t* ast, const char* name, bool is_braced) {
    if (!ast || !name) return NULL;

    ast_node_t* node = ast_node_create(AST_VARIABLE);
    if (node) {
        node->value = strdup(name);
        node->is_braced = is_braced;
        ast->node_count++;
    }
    return node;
}

ast_node_t* shell_ast_add_arithmetic(shell_ast_t* ast, const char* expr, bool is_unclosed) {
    if (!ast || !expr) return NULL;
    
    ast_node_t* node = ast_node_create(AST_ARITHMETIC);
    if (node) {
        node->value = strdup(expr);
        node->is_valid = !is_unclosed;
        ast->node_count++;
        ast->has_arithmetic = true;
        if (is_unclosed) {
            ast->has_unclosed_paren = true;
            ast->has_valid_structure = false;
        }
    }
    return node;
}

ast_node_t* shell_ast_add_heredoc(shell_ast_t* ast, const char* delimiter, const char* content) {
    if (!ast || !delimiter) return NULL;
    
    ast_node_t* node = ast_node_create(AST_HEREDOC);
    if (node) {
        node->value = strdup(delimiter);
        node->child = content ? ast_node_create(AST_COMMAND) : NULL;
        if (node->child) {
            node->child->value = strdup(content);
        }
        ast->node_count++;
        ast->has_heredoc = true;
    }
    return node;
}

ast_node_t* shell_ast_add_process_sub(shell_ast_t* ast, ast_node_t* cmd, bool is_input) {
    if (!ast || !cmd) return NULL;
    
    ast_node_t* node = ast_node_create(AST_PROCESS_SUB);
    if (node) {
        node->child = cmd;
        node->is_input_redirect = is_input;
        ast->node_count++;
        ast->has_process_sub = true;
    }
    return node;
}

void shell_ast_mark_invalid(shell_ast_t* ast) {
    if (ast) {
        ast->has_valid_structure = false;
    }
}

void shell_ast_mark_unclosed_quote(shell_ast_t* ast) {
    if (ast) {
        ast->has_unclosed_quote = true;
        ast->has_valid_structure = false;
    }
}

void shell_ast_mark_unclosed_paren(shell_ast_t* ast) {
    if (ast) {
        ast->has_unclosed_paren = true;
        ast->has_valid_structure = false;
    }
}

void shell_ast_mark_unclosed_brace(shell_ast_t* ast) {
    if (ast) {
        ast->has_unclosed_brace = true;
        ast->has_valid_structure = false;
    }
}

// Forward declaration for recursive serialization
static size_t serialize_node(const ast_node_t* node, char* buffer, size_t buffer_size, size_t pos);

static size_t append_str(char* buffer, size_t buffer_size, size_t pos, const char* str) {
    if (!buffer || !str) return pos;
    while (*str && pos < buffer_size - 1) {
        buffer[pos++] = *str++;
    }
    if (pos < buffer_size) buffer[pos] = '\0';
    return pos;
}

static size_t serialize_node(const ast_node_t* node, char* buffer, size_t buffer_size, size_t pos) {
    if (!node || !buffer || pos >= buffer_size) return pos;

    switch (node->type) {
        case AST_COMMAND:
            if (node->value) {
                pos = append_str(buffer, buffer_size, pos, node->value);
            }
            /* Recursively serialize child nodes (args, vars, globs attached as children) */
            if (node->child) {
                pos = serialize_node(node->child, buffer, buffer_size, pos);
            }
            /* Handle redirects attached via child */
            if (node->has_redirect && node->child && node->child->type == AST_REDIRECT) {
                /* Redirect already serialized as part of child */
            }
            break;
            
        case AST_PIPELINE:
            if (node->child) {
                pos = serialize_node(node->child, buffer, buffer_size, pos);
            }
            pos = append_str(buffer, buffer_size, pos, " | ");
            if (node->next) {
                pos = serialize_node(node->next, buffer, buffer_size, pos);
            }
            break;
            
        case AST_SEQUENCE:
            if (node->child) {
                pos = serialize_node(node->child, buffer, buffer_size, pos);
            }
            if (node->value) {
                pos = append_str(buffer, buffer_size, pos, " ");
                pos = append_str(buffer, buffer_size, pos, node->value);
                pos = append_str(buffer, buffer_size, pos, " ");
            } else {
                pos = append_str(buffer, buffer_size, pos, " ; ");
            }
            if (node->next) {
                pos = serialize_node(node->next, buffer, buffer_size, pos);
            }
            break;
            
        case AST_SUBSHELL:
            pos = append_str(buffer, buffer_size, pos, "( ");
            if (node->child) {
                pos = serialize_node(node->child, buffer, buffer_size, pos);
            }
            if (node->is_valid) {
                pos = append_str(buffer, buffer_size, pos, " )");
            }
            break;
            
        case AST_REDIRECT:
            if (node->child) {
                pos = serialize_node(node->child, buffer, buffer_size, pos);
            }
            // Add redirect
            if (node->redirect_fd >= 0) {
                char fd_str[16];
                snprintf(fd_str, sizeof(fd_str), "%d", node->redirect_fd);
                pos = append_str(buffer, buffer_size, pos, fd_str);
            }
            if (node->is_stderr_redirect) {
                pos = append_str(buffer, buffer_size, pos, ">");
            } else if (node->is_input_redirect) {
                pos = append_str(buffer, buffer_size, pos, "<");
            } else {
                pos = append_str(buffer, buffer_size, pos, ">");
            }
            if (node->is_append) {
                pos = append_str(buffer, buffer_size, pos, ">");
            }
            // Only add space and target if target is non-empty
            if (node->redirect_target && node->redirect_target[0] != '\0') {
                pos = append_str(buffer, buffer_size, pos, " ");
                pos = append_str(buffer, buffer_size, pos, node->redirect_target);
            }
            break;
            
        case AST_VARIABLE:
            if (node->is_braced) {
                pos = append_str(buffer, buffer_size, pos, "${");
                if (node->value) pos = append_str(buffer, buffer_size, pos, node->value);
                pos = append_str(buffer, buffer_size, pos, "}");
            } else {
                pos = append_str(buffer, buffer_size, pos, "$");
                if (node->value) pos = append_str(buffer, buffer_size, pos, node->value);
            }
            break;
            
        case AST_ARITHMETIC:
            pos = append_str(buffer, buffer_size, pos, "$((");
            if (node->value) pos = append_str(buffer, buffer_size, pos, node->value);
            if (node->is_valid) {
                pos = append_str(buffer, buffer_size, pos, "))");
            }
            break;
            
        case AST_HEREDOC:
            pos = append_str(buffer, buffer_size, pos, "<<");
            if (node->value) pos = append_str(buffer, buffer_size, pos, node->value);
            pos = append_str(buffer, buffer_size, pos, "\n");
            if (node->child && node->child->value) {
                pos = append_str(buffer, buffer_size, pos, node->child->value);
            }
            // Only output closing delimiter if heredoc is valid/closed
            if (node->is_valid) {
                pos = append_str(buffer, buffer_size, pos, "\n");
                if (node->value) pos = append_str(buffer, buffer_size, pos, node->value);
            }
            break;
            
        case AST_PROCESS_SUB:
            if (node->is_input_redirect) {
                pos = append_str(buffer, buffer_size, pos, "<(");
            } else {
                pos = append_str(buffer, buffer_size, pos, ">(");
            }
            if (node->child) {
                pos = serialize_node(node->child, buffer, buffer_size, pos);
            }
            pos = append_str(buffer, buffer_size, pos, ")");
            break;
            
        case AST_CASE:
            pos = append_str(buffer, buffer_size, pos, "case ");
            if (node->value) pos = append_str(buffer, buffer_size, pos, node->value);
            pos = append_str(buffer, buffer_size, pos, " in ");
            if (node->child) {
                pos = serialize_node(node->child, buffer, buffer_size, pos);
            }
            pos = append_str(buffer, buffer_size, pos, " ;;");
            if (node->is_valid) {
                pos = append_str(buffer, buffer_size, pos, " esac");
            }
            break;
            
        case AST_IF:
            pos = append_str(buffer, buffer_size, pos, "if ");
            if (node->child) {
                pos = serialize_node(node->child, buffer, buffer_size, pos);
            }
            pos = append_str(buffer, buffer_size, pos, " then ");
            if (node->next) {
                pos = serialize_node(node->next, buffer, buffer_size, pos);
            }
            if (node->is_valid) {
                pos = append_str(buffer, buffer_size, pos, " fi");
            }
            break;
            
        case AST_LOOP:
            if (node->value) pos = append_str(buffer, buffer_size, pos, node->value);
            pos = append_str(buffer, buffer_size, pos, " ");
            if (node->next) {
                pos = serialize_node(node->next, buffer, buffer_size, pos);
            }
            pos = append_str(buffer, buffer_size, pos, " do ");
            if (node->child) {
                pos = serialize_node(node->child, buffer, buffer_size, pos);
            }
            if (node->is_valid) {
                pos = append_str(buffer, buffer_size, pos, " done");
            }
            break;
            
        case AST_GLOB:
            if (node->value) pos = append_str(buffer, buffer_size, pos, node->value);
            break;
            
        case AST_QUOTE:
            if (node->is_braced) { // Using is_braced to store quote char
                pos = append_str(buffer, buffer_size, pos, "\"");
            } else {
                pos = append_str(buffer, buffer_size, pos, "'");
            }
            if (node->value) pos = append_str(buffer, buffer_size, pos, node->value);
            if (node->is_valid) {
                if (node->is_braced) {
                    pos = append_str(buffer, buffer_size, pos, "\"");
                } else {
                    pos = append_str(buffer, buffer_size, pos, "'");
                }
            }
            break;
            
        case AST_BACKTICK:
            pos = append_str(buffer, buffer_size, pos, "`");
            if (node->value) pos = append_str(buffer, buffer_size, pos, node->value);
            if (node->is_valid) {
                pos = append_str(buffer, buffer_size, pos, "`");
            }
            break;
            
        default:
            // Unhandled AST types - skip silently
            break;
    }
    
    return pos;
}

char* shell_ast_serialize(const shell_ast_t* ast, char* buffer, size_t buffer_size) {
    if (!ast || !buffer || buffer_size == 0) return NULL;
    
    buffer[0] = '\0';
    size_t pos = serialize_node(ast->root, buffer, buffer_size, 0);
    
    if (pos >= buffer_size) {
        buffer[buffer_size - 1] = '\0';
    }
    
    return buffer;
}

// ==== Additional builder functions =====

ast_node_t* shell_ast_add_command_with_args(shell_ast_t* ast, const char* command, const char** args, size_t num_args) {
    if (!ast || !command) return NULL;

    ast_node_t* node = ast_node_create(AST_COMMAND);
    if (node) {
        /* Build command with args */
        size_t len = strlen(command) + 1;
        for (size_t i = 0; i < num_args; i++) {
            if (args[i]) len += 1 + strlen(args[i]); /* space + arg */
        }
        node->value = (char*)calloc(1, len);  /* Zero-initialize for safety */
        if (node->value) {
            strcpy(node->value, command);
            for (size_t i = 0; i < num_args; i++) {
                if (args[i]) {
                    strcat(node->value, " ");
                    strcat(node->value, args[i]);
                }
            }
        }
        ast->node_count++;
    }
    return node;
}

ast_node_t* shell_ast_add_if(shell_ast_t* ast, ast_node_t* condition, ast_node_t* then_branch) {
    if (!ast) return NULL;
    
    ast_node_t* node = ast_node_create(AST_IF);
    if (node) {
        node->child = condition;  // condition
        node->next = then_branch; // then branch
        ast->node_count++;
        ast->has_conditionals = true;
    }
    return node;
}

ast_node_t* shell_ast_add_loop(shell_ast_t* ast, const char* type, const char* var, ast_node_t* list, ast_node_t* body) {
    if (!ast) return NULL;
    (void)var;  // Reserved for future use
    
    ast_node_t* node = ast_node_create(AST_LOOP);
    if (node) {
        node->value = strdup(type ? type : "while");
        node->child = body;
        node->next = list;
        ast->node_count++;
        ast->has_loops = true;
    }
    return node;
}

ast_node_t* shell_ast_add_case(shell_ast_t* ast, const char* var, const char* pattern, ast_node_t* body) {
    if (!ast) return NULL;
    (void)pattern;  // Reserved for future use
    
    ast_node_t* node = ast_node_create(AST_CASE);
    if (node) {
        node->value = strdup(var ? var : "$VAR");
        node->child = body; // pattern list
        ast->node_count++;
        ast->has_case = true;
    }
    return node;
}

ast_node_t* shell_ast_add_quote(shell_ast_t* ast, const char* content, char quote_char, bool is_closed) {
    if (!ast) return NULL;
    
    ast_node_t* node = ast_node_create(AST_QUOTE);
    if (node) {
        node->value = strdup(content ? content : "");
        node->is_valid = is_closed;
        node->is_braced = (quote_char == '"'); // Use is_braced to store quote char
        ast->node_count++;
        if (!is_closed) {
            ast->has_unclosed_quote = true;
            ast->has_valid_structure = false;
        }
    }
    return node;
}

ast_node_t* shell_ast_add_glob(shell_ast_t* ast, const char* pattern) {
    if (!ast) return NULL;
    
    ast_node_t* node = ast_node_create(AST_GLOB);
    if (node) {
        node->value = strdup(pattern ? pattern : "*");
        ast->node_count++;
        ast->has_glob = true;
    }
    return node;
}

// ==== Invalid pattern generators =====

void shell_ast_add_binary(shell_ast_t* ast) {
    if (!ast) return;
    
    ast_node_t* node = ast_node_create(AST_COMMAND);
    if (node) {
        node->value = strdup("\xFF\xFE");
        node->is_valid = false;
        
        ast->root = node;
        ast->node_count++;
        ast->has_binary = true;
        ast->has_valid_structure = false;
    }
}

void shell_ast_add_control_char(shell_ast_t* ast) {
    if (!ast) return;
    
    ast_node_t* node = ast_node_create(AST_COMMAND);
    if (node) {
        node->value = strdup("\x01\x02");
        node->is_valid = false;
        ast->root = node;
        ast->node_count++;
        ast->has_control_char = true;
        ast->has_valid_structure = false;
    }
}

void shell_ast_add_high_bytes(shell_ast_t* ast) {
    if (!ast) return;
    
    ast_node_t* node = ast_node_create(AST_COMMAND);
    if (node) {
        node->value = strdup("\x80\xFF");
        node->is_valid = false;
        ast->root = node;
        ast->node_count++;
        ast->has_high_bytes = true;
        ast->has_valid_structure = false;
    }
}

void shell_ast_add_unclosed_quote(shell_ast_t* ast, char quote_char) {
    if (!ast) return;
    
    ast_node_t* node = ast_node_create(AST_QUOTE);
    if (node) {
        node->value = strdup("text");
        node->is_valid = false;
        node->is_braced = (quote_char == '"');
        ast->root = node;
        ast->node_count++;
        ast->has_unclosed_quote = true;
        ast->has_valid_structure = false;
    }
}

void shell_ast_add_unclosed_paren(shell_ast_t* ast) {
    if (!ast) return;
    
    ast_node_t* node = ast_node_create(AST_SUBSHELL);
    if (node) {
        node->is_valid = false;
        ast->root = node;
        ast->node_count++;
        ast->has_unclosed_paren = true;
        ast->has_valid_structure = false;
    }
}

void shell_ast_add_unclosed_brace(shell_ast_t* ast) {
    if (!ast) return;
    
    ast_node_t* node = ast_node_create(AST_VARIABLE);
    if (node) {
        node->value = strdup("");
        node->is_valid = false;
        node->is_braced = true;
        ast->root = node;
        ast->node_count++;
        ast->has_unclosed_brace = true;
        ast->has_valid_structure = false;
    }
}

void shell_ast_add_bare_redirect(shell_ast_t* ast) {
    if (!ast) return;
    
    // Create a redirect node without a command - this is invalid
    ast_node_t* node = ast_node_create(AST_REDIRECT);
    if (node) {
        node->is_valid = false;
        node->redirect_target = strdup("");
        ast->root = node;
        ast->node_count++;
        ast->has_valid_structure = false;
    }
}

void shell_ast_add_separators_only(shell_ast_t* ast) {
    if (!ast) return;
    
    // Just separators, no commands - invalid
    ast_node_t* node = ast_node_create(AST_SEQUENCE);
    if (node) {
        node->is_valid = false;
        node->value = strdup(";");
        ast->root = node;
        ast->node_count++;
        ast->has_valid_structure = false;
    }
}

void shell_ast_add_incomplete_glob(shell_ast_t* ast) {
    if (!ast) return;
    
    ast_node_t* node = ast_node_create(AST_GLOB);
    if (node) {
        // Use "||" which is actually invalid in bash
        node->value = strdup("||");
        node->is_valid = false;
        ast->root = node;
        ast->node_count++;
        ast->has_glob = true;
        ast->has_valid_structure = false;
    }
}

// ==== Metadata getters =====

bool shell_ast_is_valid(const shell_ast_t* ast) {
    if (!ast) return false;
    return ast->has_valid_structure;
}

bool shell_ast_expects_parse_success(const shell_ast_t* ast) {
    if (!ast) return false;
    // Valid if: has valid structure AND no unclosed syntax
    // Exception: Heredocs - bash is lenient and accepts unclosed heredocs with warning
    // So we don't fail on has_valid_structure if the only issue is heredoc
    if (ast->has_heredoc && !ast->has_valid_structure) {
        // Only fail if there are OTHER issues besides heredoc
        return !ast->has_unclosed_quote && 
               !ast->has_unclosed_paren && 
               !ast->has_unclosed_brace;
    }
    return ast->has_valid_structure && 
           !ast->has_unclosed_quote && 
           !ast->has_unclosed_paren && 
           !ast->has_unclosed_brace;
}

bool shell_ast_has_unclosed_quote(const shell_ast_t* ast) {
    return ast ? ast->has_unclosed_quote : false;
}

bool shell_ast_has_unclosed_paren(const shell_ast_t* ast) {
    return ast ? ast->has_unclosed_paren : false;
}

bool shell_ast_has_unclosed_brace(const shell_ast_t* ast) {
    return ast ? ast->has_unclosed_brace : false;
}
