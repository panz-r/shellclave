#define _POSIX_C_SOURCE 200809L
#include "shell_transform.h"
#include "shell_tokenizer_full.h"
#include <stdlib.h>
#include <string.h>

static const char* VAR_PLACEHOLDER = "VAR_VALUE";
static const char* GLOB_PLACEHOLDER = "FILE_PATTERN";
static const char* SUBSHELL_PLACEHOLDER = "TEMP_FILE";

static transformed_token_t create_transformed_token(
    const char* original,
    const char* transformed,
    transform_type_t type,
    bool is_shell_construct
) {
    transformed_token_t token;
    token.original = original;
    token.transformed = transformed;
    token.type = type;
    token.is_shell_construct = is_shell_construct;
    return token;
}

static transformed_token_t transform_variable_token(shell_token_t* token) {
    char* transformed = malloc(strlen(VAR_PLACEHOLDER) + 1);
    if (!transformed) {
        return create_transformed_token(token->start, token->start, TRANSFORM_NONE, false);
    }
    strcpy(transformed, VAR_PLACEHOLDER);
    return create_transformed_token(token->start, transformed, TRANSFORM_VARIABLE, true);
}

static transformed_token_t transform_glob_token(shell_token_t* token) {
    char* transformed = malloc(strlen(GLOB_PLACEHOLDER) + 1);
    if (!transformed) {
        return create_transformed_token(token->start, token->start, TRANSFORM_NONE, false);
    }
    strcpy(transformed, GLOB_PLACEHOLDER);
    return create_transformed_token(token->start, transformed, TRANSFORM_GLOB, true);
}

static transformed_token_t transform_subshell_token(shell_token_t* token) {
    char* transformed = malloc(strlen(SUBSHELL_PLACEHOLDER) + 1);
    if (!transformed) {
        return create_transformed_token(token->start, token->start, TRANSFORM_NONE, false);
    }
    strcpy(transformed, SUBSHELL_PLACEHOLDER);
    return create_transformed_token(token->start, transformed, TRANSFORM_SUBSHELL, true);
}

static char* build_transformed_command(transformed_token_t* tokens, size_t token_count) {
    if (token_count == 0) return strdup("");
    
    size_t total_length = 0;
    for (size_t i = 0; i < token_count; i++) {
        total_length += strlen(tokens[i].transformed);
        if (i > 0) total_length++;
    }

    char* buffer = malloc(total_length + 1);
    if (!buffer) return NULL;

    char* pos = buffer;
    for (size_t i = 0; i < token_count; i++) {
        if (i > 0) *pos++ = ' ';
        strcpy(pos, tokens[i].transformed);
        pos += strlen(tokens[i].transformed);
    }
    *pos = '\0';
    return buffer;
}

bool shell_transform_command(shell_command_t* cmd, transformed_command_t** transformed_cmd) {
    if (!cmd || !transformed_cmd) return false;

    transformed_command_t* tcmd = malloc(sizeof(transformed_command_t));
    if (!tcmd) return false;

    tcmd->original_command = NULL;
    tcmd->transformed_command = NULL;
    tcmd->tokens = NULL;
    tcmd->token_count = 0;
    tcmd->has_transformations = false;
    tcmd->has_shell_syntax = false;

    // Check if command has tokens - if not, we can't transform it
    if (cmd->token_count == 0 || cmd->tokens == NULL) {
        free(tcmd);
        return false;
    }
    
    size_t orig_length = cmd->end_pos - cmd->start_pos;
    tcmd->original_command = strndup(cmd->tokens[0].start, orig_length);
    if (!tcmd->original_command) {
        free(tcmd);
        return false;
    }

    transformed_token_t* tokens = malloc(cmd->token_count * sizeof(transformed_token_t));
    if (!tokens) {
        free((void*)tcmd->original_command);
        free(tcmd);
        return false;
    }

    for (size_t i = 0; i < cmd->token_count; i++) {
        shell_token_t* tok = &cmd->tokens[i];
        switch (tok->type) {
            case TOKEN_VARIABLE:
            case TOKEN_VARIABLE_QUOTED:
            case TOKEN_SPECIAL_VAR:
                tokens[i] = transform_variable_token(tok);
                tcmd->has_transformations = true;
                tcmd->has_shell_syntax = true;
                break;
            case TOKEN_GLOB:
                tokens[i] = transform_glob_token(tok);
                tcmd->has_transformations = true;
                tcmd->has_shell_syntax = true;
                break;
            case TOKEN_SUBSHELL:
                tokens[i] = transform_subshell_token(tok);
                tcmd->has_transformations = true;
                tcmd->has_shell_syntax = true;
                break;
            default:
                tokens[i] = create_transformed_token(tok->start, tok->start, TRANSFORM_NONE, false);
                break;
        }
    }

    tcmd->tokens = tokens;
    tcmd->token_count = cmd->token_count;
    tcmd->transformed_command = build_transformed_command(tokens, tcmd->token_count);

    if (!tcmd->transformed_command) {
        for (size_t i = 0; i < tcmd->token_count; i++) {
            if (tokens[i].type != TRANSFORM_NONE) free((void*)tokens[i].transformed);
        }
        free(tokens);
        free((void*)tcmd->original_command);
        free(tcmd);
        return false;
    }

    *transformed_cmd = tcmd;
    return true;
}

bool shell_transform_command_line(
    const char* command_line,
    transformed_command_t*** transformed_cmds,
    size_t* transformed_count
) {
    if (!command_line || !transformed_cmds || !transformed_count) return false;

    shell_command_t* cmds = NULL;
    size_t cmd_count = 0;

    if (!shell_tokenize_commands(command_line, &cmds, &cmd_count)) return false;

    if (cmd_count == 0) {
        *transformed_cmds = NULL;
        *transformed_count = 0;
        return true;
    }

    transformed_command_t** tcmds = malloc(cmd_count * sizeof(transformed_command_t*));
    if (!tcmds) {
        shell_free_commands(cmds, cmd_count);
        *transformed_count = 0;
        return false;
    }

    size_t success_count = 0;
    for (size_t i = 0; i < cmd_count; i++) {
        if (shell_transform_command(&cmds[i], &tcmds[i])) {
            success_count++;
        } else {
            // On failure, free successfully transformed commands
            for (size_t j = 0; j < success_count; j++) {
                shell_free_transformed_commands(&tcmds[j], 1);
            }
            free(tcmds);
            shell_free_commands(cmds, cmd_count);
            *transformed_count = success_count;
            return false;
        }
    }

    *transformed_cmds = tcmds;
    *transformed_count = success_count;
    shell_free_commands(cmds, cmd_count);
    return true;
}

void shell_free_transformed_commands(transformed_command_t** commands, size_t count) {
    if (!commands) return;
    for (size_t i = 0; i < count; i++) {
        if (commands[i]) {
            free((void*)commands[i]->original_command);
            free((void*)commands[i]->transformed_command);
            if (commands[i]->tokens) {
                for (size_t j = 0; j < commands[i]->token_count; j++) {
                    if (commands[i]->tokens[j].type != TRANSFORM_NONE)
                        free((void*)commands[i]->tokens[j].transformed);
                }
                free(commands[i]->tokens);
            }
            free(commands[i]);
        }
    }
    // Note: don't free(commands) here - caller manages the array memory
}

const char* shell_get_dfa_input(transformed_command_t* cmd) {
    return cmd ? cmd->transformed_command : NULL;
}

bool shell_has_transformations(transformed_command_t* cmd) {
    return cmd ? cmd->has_transformations : false;
}
