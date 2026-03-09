#ifndef SHELL_ABSTRACT_H
#define SHELL_ABSTRACT_H

#include "shell_tokenizer_full.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Shell Command Abstraction Engine
 *
 * Transforms shell commands into abstracted forms for DFA matching,
 * while extracting elements for separate validation.
 *
 * Pipeline:
 *   Raw Command → Tokenize → Classify → Abstract → DFA Match
 *                                                     ↓
 *                                         Extract Elements for Validation
 */

/* ============================================================
 * PHASE 1: Extended Token Classification (extends tokenizer types)
 * ============================================================ */

/**
 * Abstract type for DFA matching - maps to internal abstract indices
 */
typedef enum {
    ABSTRACT_EV,    // Environment variable: $FOO → $EV_1
    ABSTRACT_PV,    // Positional: $1 → $PV_1
    ABSTRACT_SV,    // Special: $? → $SV_1
    ABSTRACT_AP,    // Absolute path: /etc → $AP_1
    ABSTRACT_RP,    // Relative path: ./foo → $RP_1
    ABSTRACT_HP,    // Home path: ~/file → $HP_1
    ABSTRACT_GB,    // Glob: *.txt → $GB_1
    ABSTRACT_CS,    // Command subst: $(cmd) → $CS_1
    ABSTRACT_AR,    // Arithmetic: $((x+1)) → $AR_1
    ABSTRACT_STR,   // String: "foo" → $STR_1
    ABSTRACT_REDIR  // Redirect target: > file → $RD_1
} abstract_type_t;

/**
 * Path category for validation rules
 */
typedef enum {
    PATH_ROOT,         // /
    PATH_ETC,          // /etc/
    PATH_VAR,          // /var/
    PATH_USR,          // /usr/
    PATH_HOME,         // /home/*, /root
    PATH_TMP,          // /tmp/
    PATH_PROC,         // /proc/
    PATH_SYS,          // /sys/
    PATH_DEV,          // /dev/
    PATH_OPT,          // /opt/
    PATH_SRV,          // /srv/
    PATH_RUN,          // /run/
    PATH_SYSROOT,      // /sysroot/
    PATH_BOOT,         // /boot/
    PATH_MNT,          // /mnt/
    PATH_MEDIA,        // /media/
    PATH_SNAPSHOT,     // /.snapshots/
    PATH_OTHER         // anything else
} path_category_t;

/**
 * Single abstracted element
 */
typedef struct {
    abstract_type_t type;
    const char* original;      // Original text from input
    char* abstraction;         // "$AP_1" (owned)
    size_t start;
    size_t end;
    
    // Classification details (owned copies)
    union {
        struct {
            char* name;         // For variables: "PATH", "1", etc.
            bool is_braced;     // ${VAR} vs $VAR
            bool is_quoted;
        } var;
        
        struct {
            char* path;         // "/etc", "./foo"
            bool is_absolute;
            bool ends_with_slash;
        } path;
        
        struct {
            char* pattern;     // "*.txt"
            bool has_slash;
        } glob;
        
        struct {
            char* content;      // Command substitution content
        } cmd_subst;
    } data;
    
    // Runtime-expandable data (set during validation phase)
    char* expanded;
} abstract_element_t;

/**
 * Full abstracted command
 */
typedef struct {
    const char* original;               // "grep $USER /etc/*.conf"
    char* abstracted;                   // "grep $EV_1 $AP_1$GB_1" (owned)
    
    abstract_element_t** elements;       // Array of pointers (owned)
    size_t element_count;

    // Metadata flags
    bool has_variables;
    bool has_pos_vars;
    bool has_special_vars;
    bool has_globs;
    bool has_cmd_subst;
    bool has_abs_paths;
    bool has_rel_paths;
    bool has_home_paths;
    bool has_paths;         // Any path type
    bool has_redirects;
    bool has_strings;
    bool has_arithmetic;
} abstracted_command_t;

/* ============================================================
 * PHASE 2: Abstraction Functions
 * ============================================================ */

/**
 * Classify a raw token string (no tokenization needed)
 * Uses tokenizer types for basic classification
 */
token_type_t shell_classify_raw_token(const char* text, size_t len);

/**
 * Create abstracted command from original
 * 
 * This is the main entry point - tokenizes, classifies, and abstracts
 * in one flow.
 */
bool shell_abstract_command(
    const char* command,
    abstracted_command_t** result
);

/**
 * Get the abstracted form for DFA matching
 */
const char* shell_get_abstracted(abstracted_command_t* cmd);

/**
 * Get all extracted elements for validation
 */
abstract_element_t** shell_get_elements(abstracted_command_t* cmd, size_t* count);

/**
 * Get original command
 */
const char* shell_get_original(abstracted_command_t* cmd);

/**
 * Check if command has specific feature
 */
bool shell_has_variables(abstracted_command_t* cmd);
bool shell_has_pos_vars(abstracted_command_t* cmd);
bool shell_has_special_vars(abstracted_command_t* cmd);
bool shell_has_globs(abstracted_command_t* cmd);
bool shell_has_paths(abstracted_command_t* cmd);
bool shell_has_abs_paths(abstracted_command_t* cmd);
bool shell_has_rel_paths(abstracted_command_t* cmd);
bool shell_has_home_paths(abstracted_command_t* cmd);
bool shell_has_cmd_subst(abstracted_command_t* cmd);
bool shell_has_arithmetic(abstracted_command_t* cmd);
bool shell_has_strings(abstracted_command_t* cmd);

/**
 * Get element by abstraction string (e.g., "$AP_1")
 */
abstract_element_t* shell_get_element_by_abstract(
    abstracted_command_t* cmd,
    const char* abstraction
);

/**
 * Get element by index
 */
abstract_element_t* shell_get_element_at(abstracted_command_t* cmd, size_t index);

/* ============================================================
 * PHASE 3: Runtime Expansion (Optional)
 * ============================================================ */

/**
 * Runtime context for expansion
 */
typedef struct {
    char** env;              // Environment variables (NULL-terminated)
    char* cwd;               // Current working directory
    bool resolve_symlinks;
} runtime_context_t;

/**
 * Expand a single element using runtime context
 * Returns expanded string (caller must free) or NULL on failure
 */
char* shell_expand_element(
    abstract_element_t* elem,
    runtime_context_t* ctx
);

/**
 * Expand all elements in an abstracted command
 */
bool shell_expand_all_elements(
    abstracted_command_t* cmd,
    runtime_context_t* ctx
);

/* ============================================================
 * Utility Functions
 * ============================================================ */

/**
 * Get path category from resolved path
 */
path_category_t shell_get_path_category(const char* resolved_path);

/**
 * Get human-readable name for abstract type
 */
const char* shell_abstract_type_name(abstract_type_t type);

/**
 * Get human-readable name for path category
 */
const char* shell_path_category_name(path_category_t cat);

/* ============================================================
 * Cleanup
 * ============================================================ */

/**
 * Free abstracted command and all elements
 */
void shell_abstracted_destroy(abstracted_command_t* cmd);

#ifdef __cplusplus
}
#endif

#endif // SHELL_ABSTRACT_H
