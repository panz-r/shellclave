#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shell_interop.h"
#include "shell_tokenizer.h"

#define SHELL_INTEROP_BUFFER_SIZE 4096

struct shell_interop_handle {
    shell_parse_result_t result;
    char cmd_buffer[SHELL_INTEROP_BUFFER_SIZE];
};

/* Create a new interop handle */
shell_interop_handle_t* shell_interop_create(void) {
    shell_interop_handle_t* handle = calloc(1, sizeof(shell_interop_handle_t));
    return handle;
}

/* Destroy an interop handle */
void shell_interop_destroy(shell_interop_handle_t* handle) {
    if (handle) {
        free(handle);
    }
}

/* Parse a shell command */
int shell_interop_parse(shell_interop_handle_t* handle, const char* cmd, int cmd_len) {
    if (handle == NULL || cmd == NULL || cmd_len <= 0) {
        return 0;
    }

    /* Reject commands that exceed buffer capacity */
    if (cmd_len >= (int)sizeof(handle->cmd_buffer)) {
        return -1;  /* Error: command too long */
    }

    /* Copy command to buffer (null-terminate) */
    memcpy(handle->cmd_buffer, cmd, cmd_len);
    handle->cmd_buffer[cmd_len] = '\0';

    /* Use default limits */
    shell_limits_t limits = SHELL_LIMITS_DEFAULT;

    /* Parse the command */
    shell_error_t err = shell_parse_fast(handle->cmd_buffer, cmd_len, &limits, &handle->result);

    if (err != SHELL_OK) {
        return 0;
    }

    return (int)handle->result.count;
}

/* Get subcommand count */
int shell_interop_subcommand_count(shell_interop_handle_t* handle) {
    if (handle == NULL) {
        return 0;
    }
    return (int)handle->result.count;
}

/* Get type of subcommand i */
int shell_interop_subcommand_type(shell_interop_handle_t* handle, int i) {
    if (handle == NULL || i < 0 || i >= (int)handle->result.count) {
        return 0;
    }
    return (int)handle->result.cmds[i].type;
}

/* Get features of subcommand i */
int shell_interop_subcommand_features(shell_interop_handle_t* handle, int i) {
    if (handle == NULL || i < 0 || i >= (int)handle->result.count) {
        return 0;
    }
    return (int)handle->result.cmds[i].features;
}

/* Get start position */
int shell_interop_subcommand_start(shell_interop_handle_t* handle, int i) {
    if (handle == NULL || i < 0 || i >= (int)handle->result.count) {
        return 0;
    }
    return (int)handle->result.cmds[i].start;
}

/* Get length */
int shell_interop_subcommand_len(shell_interop_handle_t* handle, int i) {
    if (handle == NULL || i < 0 || i >= (int)handle->result.count) {
        return 0;
    }
    return (int)handle->result.cmds[i].len;
}

/* Get subcommand string - caller must free */
char* shell_interop_subcommand_str(shell_interop_handle_t* handle, int i) {
    if (handle == NULL || i < 0 || i >= (int)handle->result.count) {
        return NULL;
    }

    char* buf = malloc(handle->result.cmds[i].len + 1);
    if (buf == NULL) {
        return NULL;
    }

    shell_copy_subcommand(handle->cmd_buffer, &handle->result.cmds[i], buf, handle->result.cmds[i].len + 1);
    return buf;
}

/* Free a string */
void shell_interop_free_str(char* s) {
    if (s != NULL) {
        free(s);
    }
}

/* Get features as string - caller must free */
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

/* Get type as string - caller must free */
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