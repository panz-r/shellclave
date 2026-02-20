#define _POSIX_C_SOURCE 200809L
#include "shell_transform.h"
#include <stdlib.h>
#include <string.h>

// Variable placeholder
static const char* VAR_PLACEHOLDER = "VAR_VALUE";

// Glob placeholder
static const char* GLOB_PLACEHOLDER = "FILE_PATTERN";

// Subshell placeholder
static const char* SUBSHELL_PLACEHOLDER = "TEMP_FILE";

// Helper: Create transformed token
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

// Transform variable token
static transformed_token_t transform_variable_token(
    extended_shell_token_t* token
) {
    // Extract variable name (skip $ or ${})
    const char* name_start = token->start + 1;
    size_t name_length = token->length - 1;

    if (token->length > 2 && token->start[1] == '{') {
        // ${VAR} format - skip {} braces
        name_start += 1;
        name_length -= 2;
    }

    // Create transformation
    char* transformed = malloc(strlen(VAR_PLACEHOLDER) + 1);
    if (!transformed) {
        return create_transformed_token(token->start, token->start, TRANSFORM_NONE, false);
    }
    strcpy(transformed, VAR_PLACEHOLDER);

    return create_transformed_token(token->start, transformed, TRANSFORM_VARIABLE, true);
}

// Transform glob token
static transformed_token_t transform_glob_token(
    extended_shell_token_t* token
) {
    // Create transformation
    char* transformed = malloc(strlen(GLOB_PLACEHOLDER) + 1);
    if (!transformed) {
        return create_transformed_token(token->start, token->start, TRANSFORM_NONE, false);
    }
    strcpy(transformed, GLOB_PLACEHOLDER);

    return create_transformed_token(token->start, transformed, TRANSFORM_GLOB, true);
}

// Transform subshell token
static transformed_token_t transform_subshell_token(
    extended_shell_token_t* token
) {
    // Create transformation
    char* transformed = malloc(strlen(SUBSHELL_PLACEHOLDER) + 1);
    if (!transformed) {
        return create_transformed_token(token->start, token->start, TRANSFORM_NONE, false);
    }
    strcpy(transformed, SUBSHELL_PLACEHOLDER);

    return create_transformed_token(token->start, transformed, TRANSFORM_SUBSHELL, true);
}

// Build transformed command string
static char* build_transformed_command(
    transformed_token_t* tokens,
    size_t token_count
) {
    if (token_count == 0) {
        return strdup("");
    }

    // Calculate total length needed
    size_t total_length = 0;
    for (size_t i = 0; i < token_count; i++) {
        total_length += strlen(tokens[i].transformed);
        if (i > 0) total_length++; // Space between tokens
    }

    // Allocate buffer
    char* buffer = malloc(total_length + 1);
    if (!buffer) return NULL;

    // Build command string
    char* pos = buffer;
    for (size_t i = 0; i < token_count; i++) {
        if (i > 0) {
            *pos++ = ' ';
        }
        strcpy(pos, tokens[i].transformed);
        pos += strlen(tokens[i].transformed);
    }
    *pos = '\0';

    return buffer;
}

// Basic transformation fallback (no shell syntax handling)
static bool basic_transformation(
    shell_command_t* basic_cmd,
    const char* original_line,
    transformed_command_t** transformed_cmd
) {
    if (!basic_cmd || !transformed_cmd) {
        return false;
    }

    // Allocate transformed command
    transformed_command_t* cmd = malloc(sizeof(transformed_command_t));
    if (!cmd) return false;

    // Initialize
    cmd->original_command = NULL;
    cmd->transformed_command = NULL;
    cmd->tokens = NULL;
    cmd->token_count = 0;
    cmd->has_transformations = false;
    cmd->has_shell_syntax = false;
    // NOTE: subshell_commands/subshell_count not in header - disabled
    // cmd->subshell_commands = NULL;
    // cmd->subshell_count = 0;

    // Extract original command text
    size_t orig_length = basic_cmd->end_pos - basic_cmd->start_pos;
    cmd->original_command = strndup(original_line + basic_cmd->start_pos, orig_length);
    if (!cmd->original_command) {
        free(cmd);
        return false;
    }

    // For basic transformation, no shell syntax handling
    // Just copy the original as transformed
    cmd->transformed_command = strdup(cmd->original_command);
    if (!cmd->transformed_command) {
        free((void*)cmd->original_command);
        free(cmd);
        return false;
    }

    *transformed_cmd = cmd;
    return true;
}

// Transform single command
bool shell_transform_command(
    extended_shell_command_t* extended_cmd,
    transformed_command_t** transformed_cmd
) {
    if (!extended_cmd || !transformed_cmd) {
        return false;
    }

    // Allocate transformed command
    transformed_command_t* cmd = malloc(sizeof(transformed_command_t));
    if (!cmd) return false;

    // Initialize
    cmd->original_command = NULL;
    cmd->transformed_command = NULL;
    cmd->tokens = NULL;
    cmd->token_count = 0;
    cmd->has_transformations = false;
    cmd->has_shell_syntax = false;

    // Extract original command text
    size_t orig_length = extended_cmd->end_pos - extended_cmd->start_pos;
    cmd->original_command = strndup(
        extended_cmd->tokens[0].start - (extended_cmd->start_pos - extended_cmd->tokens[0].position),
        orig_length
    );
    // Simplified - in real implementation, properly extract original command

    // Allocate token array (start with same size as extended command)
    transformed_token_t* tokens = malloc(extended_cmd->token_count * sizeof(transformed_token_t));
    if (!tokens) {
        free(cmd);
        return false;
    }

    // Transform each token
    for (size_t i = 0; i < extended_cmd->token_count; i++) {
        extended_shell_token_t* ext_token = &extended_cmd->tokens[i];

        switch (ext_token->type) {
            case TOKEN_VARIABLE:
            case TOKEN_VARIABLE_QUOTED:
            case TOKEN_SPECIAL_VAR:
                tokens[i] = transform_variable_token(ext_token);
                cmd->has_transformations = true;
                cmd->has_shell_syntax = true;
                break;

            case TOKEN_GLOB:
                tokens[i] = transform_glob_token(ext_token);
                cmd->has_transformations = true;
                cmd->has_shell_syntax = true;
                break;

            case TOKEN_SUBSHELL:
                tokens[i] = transform_subshell_token(ext_token);
                cmd->has_transformations = true;
                cmd->has_shell_syntax = true;
                break;

            default:
                // No transformation needed
                tokens[i] = create_transformed_token(
                    ext_token->start,
                    ext_token->start,
                    TRANSFORM_NONE,
                    false
                );
                break;
        }
    }

    cmd->tokens = tokens;
    cmd->token_count = extended_cmd->token_count;

    // Build transformed command string
    cmd->transformed_command = build_transformed_command(tokens, cmd->token_count);
    if (!cmd->transformed_command) {
        // Cleanup on failure
        for (size_t i = 0; i < cmd->token_count; i++) {
            if (tokens[i].type != TRANSFORM_NONE) {
                free((void*)tokens[i].transformed);
            }
        }
        free(tokens);
        free((void*)cmd->original_command);
        free(cmd);
        return false;
    }

    *transformed_cmd = cmd;
    return true;
}

// Transform entire command line with fallback
bool shell_transform_command_line(
    const char* command_line,
    transformed_command_t*** transformed_cmds,
    size_t* transformed_count
) {
    if (!command_line || !transformed_cmds || !transformed_count) {
        return false;
    }

    // Try extended tokenization first
    extended_shell_command_t* extended_cmds = NULL;
    size_t extended_count = 0;

    if (!extended_shell_tokenize_commands(command_line, &extended_cmds, &extended_count)) {
        // Extended tokenization failed - try basic tokenization
        shell_command_t* basic_cmds = NULL;
        size_t basic_count = 0;

        if (!shell_tokenize_commands(command_line, &basic_cmds, &basic_count)) {
            // Complete tokenization failure
            return false;
        }

        // Basic transformation (no shell syntax handling)
        if (basic_count == 0) {
            *transformed_cmds = NULL;
            *transformed_count = 0;
            shell_free_commands(basic_cmds, basic_count);
            return true;
        }

        // Allocate transformed commands array
        transformed_command_t** cmds = malloc(basic_count * sizeof(transformed_command_t*));
        if (!cmds) {
            shell_free_commands(basic_cmds, basic_count);
            return false;
        }

        // Basic transformation
        size_t success_count = 0;
        for (size_t i = 0; i < basic_count; i++) {
            if (basic_transformation(&basic_cmds[i], command_line, &cmds[i])) {
                success_count++;
            } else {
                // Free any successfully transformed commands
                for (size_t j = 0; j < i; j++) {
                    shell_free_transformed_commands(&cmds[j], 1);
                }
                free(cmds);
                shell_free_commands(basic_cmds, basic_count);
                return false;
            }
        }

        *transformed_cmds = cmds;
        *transformed_count = success_count;
        shell_free_commands(basic_cmds, basic_count);
        return true;
    }

    // Extended tokenization succeeded
    if (extended_count == 0) {
        *transformed_cmds = NULL;
        *transformed_count = 0;
        extended_shell_free_commands(extended_cmds, extended_count);
        return true;
    }

    // Allocate transformed commands array
    transformed_command_t** cmds = malloc(extended_count * sizeof(transformed_command_t*));
    if (!cmds) {
        extended_shell_free_commands(extended_cmds, extended_count);
        return false;
    }

    // Transform each command
    size_t success_count = 0;
    for (size_t i = 0; i < extended_count; i++) {
        if (shell_transform_command(&extended_cmds[i], &cmds[i])) {
            success_count++;
        } else {
            // Free any successfully transformed commands
            for (size_t j = 0; j < i; j++) {
                shell_free_transformed_commands(&cmds[j], 1);
            }
            free(cmds);
            extended_shell_free_commands(extended_cmds, extended_count);
            return false;
        }
    }

    *transformed_cmds = cmds;
    *transformed_count = success_count;
    extended_shell_free_commands(extended_cmds, extended_count);
    return true;
}

// Free transformed commands
void shell_free_transformed_commands(
    transformed_command_t** commands,
    size_t count
) {
    if (!commands) return;

    for (size_t i = 0; i < count; i++) {
        if (commands[i]) {
            free((void*)commands[i]->original_command);
            free((void*)commands[i]->transformed_command);

            if (commands[i]->tokens) {
                for (size_t j = 0; j < commands[i]->token_count; j++) {
                    if (commands[i]->tokens[j].type != TRANSFORM_NONE) {
                        free((void*)commands[i]->tokens[j].transformed);
                    }
                }
                free(commands[i]->tokens);
            }
            free(commands[i]);
        }
    }
    free(commands);
}

// Get DFA input from transformed command
const char* shell_get_dfa_input(
    transformed_command_t* cmd
) {
    return cmd ? cmd->transformed_command : NULL;
}

// Check if command has shell transformations
bool shell_has_transformations(
    transformed_command_t* cmd
) {
    return cmd ? cmd->has_transformations : false;
}