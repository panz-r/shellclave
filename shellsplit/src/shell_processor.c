#define _POSIX_C_SOURCE 200809L
#include "shell_processor.h"
#include "shell_tokenizer_full.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Forward declarations
static bool split_pipeline_into_commands(shell_command_info_t* info, const char** inputs, size_t* dfa_input_count);

// Helper: Check if token is shell operator
static bool is_shell_operator_token(shell_token_t* token) {
    return token->type == TOKEN_PIPE ||
           token->type == TOKEN_REDIRECT_IN ||
           token->type == TOKEN_REDIRECT_OUT ||
           token->type == TOKEN_REDIRECT_ERR ||
           token->type == TOKEN_REDIRECT_APPEND ||
           token->type == TOKEN_SEMICOLON ||
           token->type == TOKEN_AND ||
           token->type == TOKEN_OR ||
           token->type == TOKEN_SUBSHELL_START ||
           token->type == TOKEN_SUBSHELL_END;
}

// Helper: Build clean command string from tokens
static char* build_clean_command(shell_token_t* tokens, size_t count);

// Forward declarations
static bool process_single_command_internal(
    shell_command_t* basic_cmd,
    const char* original_line,
    shell_command_info_t* info
);

static bool split_pipeline_command(
    shell_command_t* pipeline_cmd,
    const char* original_line,
    shell_command_info_t* info
);

// Helper: Build clean command string from tokens
static char* build_clean_command(shell_token_t* tokens, size_t count) {
    if (count == 0) {
        return strdup("");
    }

    // Calculate total length needed
    size_t total_length = 0;
    for (size_t i = 0; i < count; i++) {
        total_length += tokens[i].length;
        if (i > 0) total_length++; // Space between arguments
    }

    // Allocate buffer
    char* buffer = malloc(total_length + 1);
    if (!buffer) return NULL;

    // Build command string
    char* pos = buffer;
    for (size_t i = 0; i < count; i++) {
        if (i > 0) {
            *pos++ = ' ';
        }
        memcpy(pos, tokens[i].start, tokens[i].length);
        pos += tokens[i].length;
    }
    *pos = '\0';

    return buffer;
}

// Process single command with shell/command separation
static bool process_single_command(
    shell_command_t* basic_cmd,
    const char* original_line,
    shell_command_info_t* info
) {
    if (!basic_cmd || !info) return false;

    // Initialize info
    memset(info, 0, sizeof(shell_command_info_t));

    // Store original command
    size_t orig_length = basic_cmd->end_pos - basic_cmd->start_pos;
    info->original_command = strndup(original_line + basic_cmd->start_pos, orig_length);
    if (!info->original_command) return false;

    // Check if this command contains pipes (pipeline)
    bool has_pipes = false;
    for (size_t i = 0; i < basic_cmd->token_count; i++) {
        if (basic_cmd->tokens[i].type == TOKEN_PIPE) {
            has_pipes = true;
            break;
        }
    }

    if (has_pipes) {
        // This is a pipeline - split into individual commands
        bool success = split_pipeline_command(basic_cmd, original_line, info);
        if (!success) {
            free((void*)info->original_command);
            memset(info, 0, sizeof(shell_command_info_t));
        }
        return success;
    }

    // Not a pipeline - process as single command
    bool success = process_single_command_internal(basic_cmd, original_line, info);
    if (!success) {
        free((void*)info->original_command);
        memset(info, 0, sizeof(shell_command_info_t));
    }
    return success;
}

// Process single command (not a pipeline)
static bool process_single_command_internal(
    shell_command_t* basic_cmd,
    const char* original_line,
    shell_command_info_t* info
) {
    (void)original_line;  // Unused
    
    // Separate shell tokens from command tokens
    shell_token_t* shell_tokens = NULL;
    shell_token_t* command_tokens = NULL;
    size_t shell_count = 0;
    size_t command_count = 0;

    // Allocate temporary arrays
    shell_tokens = malloc(basic_cmd->token_count * sizeof(shell_token_t));
    command_tokens = malloc(basic_cmd->token_count * sizeof(shell_token_t));
    if (!shell_tokens || !command_tokens) {
        free(shell_tokens);
        free(command_tokens);
        return false;
    }

    // Classify tokens
    for (size_t i = 0; i < basic_cmd->token_count; i++) {
        shell_token_t* token = &basic_cmd->tokens[i];

        if (is_shell_operator_token(token)) {
            // Shell operator
            shell_tokens[shell_count++] = *token;

            // Track shell features
            switch (token->type) {
                case TOKEN_PIPE:
                    if (i > 0) info->has_pipe_input = true;
                    if (i < basic_cmd->token_count - 1) info->has_pipe_output = true;
                    break;
                case TOKEN_REDIRECT_IN:
                case TOKEN_REDIRECT_OUT:
                case TOKEN_REDIRECT_APPEND:
                    info->has_redirections = true;
                    break;
                case TOKEN_REDIRECT_ERR:
                    info->has_redirections = true;
                    info->has_error_redirection = true;
                    break;
                default:
                    break;
            }
        } else {
            // Command token
            command_tokens[command_count++] = *token;
        }
    }

    // Build clean command string
    info->clean_command = build_clean_command(command_tokens, command_count);
    if (!info->clean_command) {
        free(shell_tokens);
        free(command_tokens);
        return false;
    }

    // Copy tokens to info structure
    if (shell_count > 0) {
        info->shell_tokens = malloc(shell_count * sizeof(shell_token_t));
        if (!info->shell_tokens) {
            free(shell_tokens);
            free(command_tokens);
            return false;
        }
        memcpy(info->shell_tokens, shell_tokens, shell_count * sizeof(shell_token_t));
        info->shell_token_count = shell_count;
    }

    if (command_count > 0) {
        info->command_tokens = malloc(command_count * sizeof(shell_token_t));
        if (!info->command_tokens) {
            free(shell_tokens);
            free(command_tokens);
            free(info->shell_tokens);
            return false;
        }
        memcpy(info->command_tokens, command_tokens, command_count * sizeof(shell_token_t));
        info->command_token_count = command_count;
    }

    free(shell_tokens);
    free(command_tokens);
    return true;
}

// Split pipeline command into individual commands
static bool split_pipeline_command(
    shell_command_t* pipeline_cmd,
    const char* original_line,
    shell_command_info_t* info
) {
    (void)original_line;  // Unused
    
    // Count pipe operators to determine number of commands
    size_t pipe_count = 0;
    for (size_t i = 0; i < pipeline_cmd->token_count; i++) {
        if (pipeline_cmd->tokens[i].type == TOKEN_PIPE) {
            pipe_count++;
        }
    }

    // For pipeline, we'll create a single info with multiple commands
    // This is a simplified approach - real implementation would be more robust

    // Build clean command by removing pipe operators
    shell_token_t* command_tokens = malloc(pipeline_cmd->token_count * sizeof(shell_token_t));
    if (!command_tokens) return false;

    size_t command_token_count = 0;
    for (size_t i = 0; i < pipeline_cmd->token_count; i++) {
        if (pipeline_cmd->tokens[i].type != TOKEN_PIPE) {
            command_tokens[command_token_count++] = pipeline_cmd->tokens[i];
        }
    }

    info->clean_command = build_clean_command(command_tokens, command_token_count);
    free(command_tokens);

    if (!info->clean_command) return false;

    // Mark as having pipes
    info->has_pipe_input = true;
    info->has_pipe_output = true;

    return true;
}

// Main processing function
bool shell_process_command(
    const char* command_line,
    shell_command_info_t** command_infos,
    size_t* command_count
) {
    if (!command_line || !command_infos || !command_count) {
        return false;
    }

    // First, tokenize normally
    shell_command_t* basic_commands;
    size_t basic_count;

    if (!shell_tokenize_commands(command_line, &basic_commands, &basic_count)) {
        return false;
    }

    if (basic_count == 0) {
        *command_infos = NULL;
        *command_count = 0;
        return true;
    }

    // Allocate command info array
    shell_command_info_t* infos = malloc(basic_count * sizeof(shell_command_info_t));
    if (!infos) {
        shell_free_commands(basic_commands, basic_count);
        *command_count = 0;
        return false;
    }

    // Process each command
    for (size_t i = 0; i < basic_count; i++) {
        if (!process_single_command(&basic_commands[i], command_line, &infos[i])) {
            shell_free_command_infos(infos, i);
            shell_free_commands(basic_commands, basic_count);
            *command_count = i;
            return false;
        }
    }

    shell_free_commands(basic_commands, basic_count);
    *command_infos = infos;
    *command_count = basic_count;
    return true;
}

// Free command info structures
void shell_free_command_infos(
    shell_command_info_t* infos,
    size_t count
) {
    if (!infos) return;

    for (size_t i = 0; i < count; i++) {
        free((void*)infos[i].original_command);
        free((void*)infos[i].clean_command);
        free(infos[i].shell_tokens);
        free(infos[i].command_tokens);
    }
    free(infos);
}

// Get clean command for DFA validation
const char* shell_get_clean_command(
    shell_command_info_t* info
) {
    return info ? info->clean_command : NULL;
}

// Check if command has dangerous shell features
bool shell_has_dangerous_features(
    shell_command_info_t* info
) {
    if (!info) return false;

    // For now, all shell features are considered "features" but not necessarily dangerous
    // The DFA will determine if the clean command is dangerous
    return info->has_pipe_input || info->has_pipe_output ||
           info->has_redirections || info->has_error_redirection;
}

// Process command line and extract DFA inputs
bool shell_extract_dfa_inputs(
    const char* command_line,
    const char*** dfa_inputs,
    size_t* dfa_input_count,
    bool* has_shell_features
) {
    if (!command_line || !dfa_inputs || !dfa_input_count || !has_shell_features) {
        return false;
    }

    shell_command_info_t* infos;
    size_t count;

    if (!shell_process_command(command_line, &infos, &count)) {
        *dfa_inputs = NULL;
        *dfa_input_count = 0;
        *has_shell_features = false;
        return false;
    }

    if (count == 0) {
        *dfa_inputs = NULL;
        *dfa_input_count = 0;
        *has_shell_features = false;
        return true;
    }

    // Allocate array for DFA inputs
    const char** inputs = malloc(count * sizeof(const char*));
    if (!inputs) {
        shell_free_command_infos(infos, count);
        *dfa_input_count = 0;
        return false;
    }

    // Extract clean commands and check for shell features
    bool shell_features = false;
    for (size_t i = 0; i < count; i++) {
        inputs[i] = shell_get_clean_command(&infos[i]);
        if (shell_has_dangerous_features(&infos[i])) {
            shell_features = true;
        }
    }

    *dfa_inputs = inputs;
    *dfa_input_count = count;
    *has_shell_features = shell_features;

    // Note: We're transferring ownership of the clean_command strings to the caller
    // The caller gets pointers to the strings in infos[i].clean_command
    // After this function returns, the caller must free these strings
    // We must NOT call shell_free_command_infos because it would free clean_command
    // Instead, we manually free only the parts we still own
    
    // Free original_command and shell/command tokens but NOT clean_command
    for (size_t i = 0; i < count; i++) {
        free((void*)infos[i].original_command);
        free(infos[i].shell_tokens);
        free(infos[i].command_tokens);
        // Do NOT free infos[i].clean_command - caller owns it now
    }
    free(infos);

    return true;
}

// Split pipeline into individual commands
// NOTE: This function is not currently used but may be needed for full pipeline support
// Suppress unused warning - this is a planned feature
static bool __attribute__((unused)) split_pipeline_into_commands(
    shell_command_info_t* pipeline_info,
    const char** command_array,
    size_t* command_count
) {
    (void)pipeline_info;
    (void)command_array;
    (void)command_count;
    
    // Disabled for now - needs integration with extract_pipeline_commands
    return false;
}