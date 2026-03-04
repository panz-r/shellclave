#ifndef SHELL_AST_H
#define SHELL_AST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef enum {
    AST_COMMAND,
    AST_PIPELINE,
    AST_SEQUENCE,
    AST_SUBSHELL,
    AST_REDIRECT,
    AST_VARIABLE,
    AST_ARITHMETIC,
    AST_HEREDOC,
    AST_PROCESS_SUB,
    AST_CASE,
    AST_IF,
    AST_LOOP,
    AST_GLOB,
    AST_QUOTE,
    AST_BACKTICK,
} ast_node_type_t;

typedef struct ast_node {
    ast_node_type_t type;
    struct ast_node* next;       // For chaining (pipeline, sequence)
    struct ast_node* child;     // For subshell contents, redirects
    char* value;                // Command name, variable name, etc.
    char* redirect_target;      // File for redirect
    int redirect_fd;            // File descriptor for redirect (-1 for none)
    bool is_input_redirect;     // true for <, false for >
    bool is_append;             // true for >>
    bool is_stderr_redirect;    // true for 2>
    bool is_valid;             // false if this node makes the AST invalid
    bool is_braced;            // true for ${VAR}, false for $VAR
    bool has_redirect;          // has redirect attached
    bool is_closing;            // for if/fi, case/esac, etc.
} ast_node_t;

typedef struct {
    ast_node_t* root;
    uint32_t node_count;
    bool has_valid_structure;   // Overall AST is valid shell
    bool has_unclosed_quote;
    bool has_unclosed_paren;
    bool has_unclosed_brace;
    bool has_case;
    bool has_loops;
    bool has_conditionals;
    bool has_process_sub;
    bool has_heredoc;
    bool has_arithmetic;
    bool has_glob;
    bool has_redirect;
    bool has_subshell;
    bool has_binary;            // Contains binary/control chars
    bool has_control_char;      // Contains control characters
    bool has_high_bytes;        // Contains high bytes (0x80+)
} shell_ast_t;

// AST creation
shell_ast_t* shell_ast_create(void);
void shell_ast_destroy(shell_ast_t* ast);

// Simple command node
ast_node_t* shell_ast_add_command(shell_ast_t* ast, const char* command);

// Command with arguments
ast_node_t* shell_ast_add_command_with_args(shell_ast_t* ast, const char* command, const char** args, size_t num_args);

// Pipeline: cmd1 | cmd2
ast_node_t* shell_ast_add_pipeline(shell_ast_t* ast, ast_node_t* cmd1, ast_node_t* cmd2);

// Sequence: cmd1 ; cmd2 or cmd1 && cmd2 or cmd1 || cmd2
ast_node_t* shell_ast_add_sequence(shell_ast_t* ast, ast_node_t* cmd1, ast_node_t* cmd2, const char* separator);

// Subshell: ( cmd )
ast_node_t* shell_ast_add_subshell(shell_ast_t* ast, ast_node_t* content);

// Redirect: cmd > file or cmd < file or cmd 2>&1
ast_node_t* shell_ast_add_redirect(shell_ast_t* ast, ast_node_t* cmd, const char* target, 
                                   int fd, bool is_input, bool is_append, bool is_stderr);

// Variable: $VAR or ${VAR}
ast_node_t* shell_ast_add_variable(shell_ast_t* ast, const char* name, bool is_braced);

// Arithmetic: $(( expr ))
ast_node_t* shell_ast_add_arithmetic(shell_ast_t* ast, const char* expr, bool is_unclosed);

// Heredoc: <<EOF ... EOF
ast_node_t* shell_ast_add_heredoc(shell_ast_t* ast, const char* delimiter, const char* content);

// Process substitution: <(cmd) or >(cmd)
ast_node_t* shell_ast_add_process_sub(shell_ast_t* ast, ast_node_t* cmd, bool is_input);

// Case statement: case VAR in pattern) cmd;; esac
ast_node_t* shell_ast_add_case(shell_ast_t* ast, const char* var, const char* pattern, ast_node_t* body);

// If statement: if cmd then cmd fi
ast_node_t* shell_ast_add_if(shell_ast_t* ast, ast_node_t* condition, ast_node_t* then_branch);

// Loop: while cmd do cmd done or for VAR in list do cmd done
ast_node_t* shell_ast_add_loop(shell_ast_t* ast, const char* type, const char* var, ast_node_t* list, ast_node_t* body);

// Quoted string
ast_node_t* shell_ast_add_quote(shell_ast_t* ast, const char* content, char quote_char, bool is_closed);

// Glob pattern
ast_node_t* shell_ast_add_glob(shell_ast_t* ast, const char* pattern);

// ==== Generator-specific invalid patterns ====

// Binary/control chars embedded
void shell_ast_add_binary(shell_ast_t* ast);

// Control character at start
void shell_ast_add_control_char(shell_ast_t* ast);

// High bytes (binary data)
void shell_ast_add_high_bytes(shell_ast_t* ast);

// Unclosed quote
void shell_ast_add_unclosed_quote(shell_ast_t* ast, char quote_char);

// Unclosed paren/subshell
void shell_ast_add_unclosed_paren(shell_ast_t* ast);

// Unclosed brace/variable
void shell_ast_add_unclosed_brace(shell_ast_t* ast);

// Bare redirect (no command before)
void shell_ast_add_bare_redirect(shell_ast_t* ast);

// Just separators
void shell_ast_add_separators_only(shell_ast_t* ast);

// Incomplete glob
void shell_ast_add_incomplete_glob(shell_ast_t* ast);

// ==== Metadata getters =====

// Check if the AST represents valid shell
bool shell_ast_is_valid(const shell_ast_t* ast);

// Get expected metadata from AST
bool shell_ast_expects_parse_success(const shell_ast_t* ast);
bool shell_ast_has_unclosed_quote(const shell_ast_t* ast);
bool shell_ast_has_unclosed_paren(const shell_ast_t* ast);
bool shell_ast_has_unclosed_brace(const shell_ast_t* ast);

// Serialization to string
char* shell_ast_serialize(const shell_ast_t* ast, char* buffer, size_t buffer_size);

#endif
