#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shell_interop.h"
#include "shell_tokenizer.h"

/* Static result buffer - caller allocates */
static shell_parse_result_t g_result;
static char g_cmd_buffer[4096];

/**
 * Parse a shell command - stores result internally for Go to query
 */
int shell_interop_parse(const char* cmd, int cmd_len) {
    if (cmd == NULL || cmd_len <= 0) {
        return 0;
    }
    
    /* Copy command to our buffer (null-terminate) */
    int len = cmd_len;
    if (len >= (int)sizeof(g_cmd_buffer)) {
        len = sizeof(g_cmd_buffer) - 1;
    }
    memcpy(g_cmd_buffer, cmd, len);
    g_cmd_buffer[len] = '\0';
    
    /* Use default limits */
    shell_limits_t limits = SHELL_LIMITS_DEFAULT;
    
    /* Parse the command */
    shell_error_t err = shell_parse_fast(g_cmd_buffer, len, &limits, &g_result);
    
    if (err != SHELL_OK) {
        return 0;
    }
    
    return (int)g_result.count;
}

/* Get subcommand count */
int shell_interop_subcommand_count(void) {
    return (int)g_result.count;
}

/* Get type of subcommand i */
int shell_interop_subcommand_type(int i) {
    if (i < 0 || i >= (int)g_result.count) {
        return 0;
    }
    return (int)g_result.cmds[i].type;
}

/* Get features of subcommand i */
int shell_interop_subcommand_features(int i) {
    if (i < 0 || i >= (int)g_result.count) {
        return 0;
    }
    return (int)g_result.cmds[i].features;
}

/* Get start position */
int shell_interop_subcommand_start(int i) {
    if (i < 0 || i >= (int)g_result.count) {
        return 0;
    }
    return (int)g_result.cmds[i].start;
}

/* Get length */
int shell_interop_subcommand_len(int i) {
    if (i < 0 || i >= (int)g_result.count) {
        return 0;
    }
    return (int)g_result.cmds[i].len;
}

/* Get subcommand string - caller must free */
char* shell_interop_subcommand_str(int i) {
    if (i < 0 || i >= (int)g_result.count) {
        return NULL;
    }
    
    char* buf = malloc(g_result.cmds[i].len + 1);
    if (buf == NULL) {
        return NULL;
    }
    
    shell_copy_subcommand(g_cmd_buffer, &g_result.cmds[i], buf, g_result.cmds[i].len + 1);
    return buf;
}

/* Free a string */
void shell_interop_free_str(char* s) {
    if (s != NULL) {
        free(s);
    }
}

/* Get features as string */
char* shell_interop_features_str(int features) {
    char* buf = malloc(256);
    if (buf == NULL) return NULL;
    
    buf[0] = '\0';
    
    if (features & SHELL_FEAT_VARS) strcat(buf, "VAR ");
    if (features & SHELL_FEAT_GLOBS) strcat(buf, "GLOB ");
    if (features & SHELL_FEAT_SUBSHELL) strcat(buf, "SUBSHELL ");
    if (features & SHELL_FEAT_ARITH) strcat(buf, "ARITH ");
    if (features & SHELL_FEAT_HEREDOC) strcat(buf, "HEREDOC ");
    if (features & SHELL_FEAT_HERESTRING) strcat(buf, "HERESTRING ");
    if (features & SHELL_FEAT_PROCESS_SUB) strcat(buf, "PROCSUB ");
    if (features & SHELL_FEAT_LOOPS) strcat(buf, "LOOPS ");
    if (features & SHELL_FEAT_CONDITIONALS) strcat(buf, "COND ");
    if (features & SHELL_FEAT_CASE) strcat(buf, "CASE ");
    
    if (buf[0] == '\0') {
        strcpy(buf, "none");
    }
    
    return buf;
}

/* Get type as string */
char* shell_interop_type_str(int type) {
    char* buf = malloc(64);
    if (buf == NULL) return NULL;
    
    /* Check type bits */
    if (type & SHELL_TYPE_PIPELINE) {
        strcpy(buf, "PIPE");
    } else if (type & SHELL_TYPE_AND) {
        strcpy(buf, "AND");
    } else if (type & SHELL_TYPE_OR) {
        strcpy(buf, "OR");
    } else if (type & SHELL_TYPE_SEMICOLON) {
        strcpy(buf, "SEMICOLON");
    } else {
        strcpy(buf, "SIMPLE");
    }
    
    return buf;
}
