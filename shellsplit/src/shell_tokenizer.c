#include "shell_tokenizer.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

// Initialize tokenizer state
void shell_tokenizer_init(shell_tokenizer_state_t* state, const char* input) {
    if (state == NULL || input == NULL) return;

    state->input = input;
    state->position = 0;
    state->length = strlen(input);
    state->in_quotes = false;
    state->in_subshell = false;
    state->quote_char = '\0';
    state->paren_depth = 0;
}

// Check if character is a shell operator
static bool is_shell_operator(char c) {
    return c == '|' || c == '>' || c == '<' || c == '&' || c == ';' || c == '(' || c == ')';
}

// Skip whitespace
static void skip_whitespace(shell_tokenizer_state_t* state) {
    while (state->position < state->length && isspace(state->input[state->position])) {
        state->position++;
    }
}

// Handle quotes and escaping
static bool handle_quotes(shell_tokenizer_state_t* state) {
    char c = state->input[state->position];

    if (c == '"' || c == '\'' || c == '`') {
        if (!state->in_quotes) {
            // Start of quotes
            state->in_quotes = true;
            state->quote_char = c;
            state->position++;
            return true;
        } else if (c == state->quote_char) {
            // End of quotes
            state->in_quotes = false;
            state->quote_char = '\0';
            state->position++;
            return true;
        }
    }

    // Handle backslash escaping
    if (c == '\\' && state->position + 1 < state->length) {
        state->position += 2; // Skip both backslash and next char
        return true;
    }

    return false;
}

// Get next token
bool shell_tokenizer_next(shell_tokenizer_state_t* state, shell_token_t* token) {
    if (state == NULL || token == NULL || state->position >= state->length) {
        token->type = TOKEN_END;
        return false;
    }

    skip_whitespace(state);

    if (state->position >= state->length) {
        token->type = TOKEN_END;
        return false;
    }

    size_t start_pos = state->position;
    char current_char = state->input[start_pos];

    // Handle quotes first
    if (handle_quotes(state)) {
        if (state->in_quotes) {
            // We're inside quotes, treat everything as part of the token until closing quote
            while (state->position < state->length) {
                if (handle_quotes(state)) {
                    if (!state->in_quotes) break; // Found closing quote
                } else {
                    state->position++;
                }
            }

            token->type = TOKEN_ARGUMENT;
            token->start = state->input + start_pos;
            token->length = state->position - start_pos;
            token->position = start_pos;
            return true;
        }
        // If we handled quotes but not in quotes anymore, continue to check for operators
        current_char = state->input[state->position];
    }

    // Check for shell operators (only if not in quotes)
    if (!state->in_quotes && is_shell_operator(current_char)) {
        // Handle multi-character operators first
        if (state->position + 1 < state->length) {
            char next_char = state->input[state->position + 1];

            if (current_char == '|' && next_char == '|') {
                token->type = TOKEN_OR;
                token->start = state->input + state->position;
                token->length = 2;
                token->position = state->position;
                state->position += 2;
                return true;
            } else if (current_char == '&' && next_char == '&') {
                token->type = TOKEN_AND;
                token->start = state->input + state->position;
                token->length = 2;
                token->position = state->position;
                state->position += 2;
                return true;
            } else if (current_char == '>' && next_char == '>') {
                token->type = TOKEN_REDIRECT_APPEND;
                token->start = state->input + state->position;
                token->length = 2;
                token->position = state->position;
                state->position += 2;
                return true;
            } else if (current_char == '2' && next_char == '>') {
                token->type = TOKEN_REDIRECT_ERR;
                token->start = state->input + state->position;
                token->length = 2;
                token->position = state->position;
                state->position += 2;
                return true;
            }
        }

        // Single character operators
        switch (current_char) {
            case '|':
                token->type = TOKEN_PIPE;
                break;
            case '>':
                token->type = TOKEN_REDIRECT_OUT;
                break;
            case '<':
                token->type = TOKEN_REDIRECT_IN;
                break;
            case '&':
                token->type = TOKEN_AND; // Could also be background process
                break;
            case ';':
                token->type = TOKEN_SEMICOLON;
                break;
            case '(':
                token->type = TOKEN_SUBSHELL_START;
                state->paren_depth++;
                state->in_subshell = true;
                break;
            case ')':
                token->type = TOKEN_SUBSHELL_END;
                state->paren_depth--;
                if (state->paren_depth == 0) {
                    state->in_subshell = false;
                }
                break;
            default:
                // Should not happen
                token->type = TOKEN_ARGUMENT;
                break;
        }

        token->start = state->input + state->position;
        token->length = 1;
        token->position = state->position;
        state->position++;
        return true;
    }

    // Handle regular tokens (commands and arguments)
    while (state->position < state->length) {
        char c = state->input[state->position];

        if (state->in_quotes) {
            if (handle_quotes(state)) {
                if (!state->in_quotes) break; // End of quoted section
            } else {
                state->position++;
            }
        } else {
            if (isspace(c) || is_shell_operator(c)) {
                break;
            }
            state->position++;
        }
    }

    // Determine token type (first token is command, rest are arguments)
    token->type = TOKEN_COMMAND; // We'll let the caller determine this based on context
    token->start = state->input + start_pos;
    token->length = state->position - start_pos;
    token->position = start_pos;

    return true;
}

// Tokenize entire command line into commands
bool shell_tokenize_commands(const char* input, shell_command_t** commands, size_t* command_count) {
    if (input == NULL || commands == NULL || command_count == NULL) {
        return false;
    }

    shell_tokenizer_state_t state;
    shell_tokenizer_init(&state, input);

    // First pass: count commands
    size_t count = 0;
    bool expect_command = true;

    shell_tokenizer_state_t temp_state = state;
    shell_token_t token;

    while (shell_tokenizer_next(&temp_state, &token)) {
        if (expect_command && (token.type == TOKEN_COMMAND || token.type == TOKEN_ARGUMENT)) {
            count++;
            expect_command = false;
        }

        if (token.type == TOKEN_PIPE || token.type == TOKEN_SEMICOLON ||
            token.type == TOKEN_AND || token.type == TOKEN_OR) {
            expect_command = true;
        }
    }

    if (count == 0) {
        *command_count = 0;
        return true;
    }

    // Allocate command array
    *commands = malloc(count * sizeof(shell_command_t));
    if (*commands == NULL) {
        return false;
    }

    // Second pass: tokenize and group into commands
    shell_tokenizer_init(&state, input);
    size_t current_command = 0;
    shell_command_t* current_cmd = &(*commands)[current_command];

    // Allocate initial token array for first command
    shell_token_t* tokens = malloc(16 * sizeof(shell_token_t)); // Start with 16 tokens
    if (tokens == NULL) {
        free(*commands);
        return false;
    }
    size_t token_capacity = 16;

    current_cmd->tokens = tokens;
    current_cmd->token_count = 0;
    current_cmd->start_pos = state.position;

    expect_command = true;

    while (shell_tokenizer_next(&state, &token)) {
        // Check if this token starts a new command
        if (expect_command && (token.type == TOKEN_COMMAND || token.type == TOKEN_ARGUMENT)) {
            if (current_cmd->token_count > 0) {
                // Start new command
                current_command++;
                current_cmd = &(*commands)[current_command];
                current_cmd->start_pos = token.position;

                // Allocate token array for new command
                tokens = malloc(16 * sizeof(shell_token_t));
                if (tokens == NULL) {
                    shell_free_commands(*commands, current_command);
                    return false;
                }
                token_capacity = 16;
                current_cmd->tokens = tokens;
                current_cmd->token_count = 0;
            }
            expect_command = false;
        }

        // Add token to current command
        if (current_cmd->token_count >= token_capacity) {
            // Resize token array
            size_t new_capacity = token_capacity * 2;
            shell_token_t* new_tokens = realloc(tokens, new_capacity * sizeof(shell_token_t));
            if (new_tokens == NULL) {
                shell_free_commands(*commands, current_command + 1);
                return false;
            }
            tokens = new_tokens;
            token_capacity = new_capacity;
            current_cmd->tokens = tokens;
        }

        current_cmd->tokens[current_cmd->token_count++] = token;

        // Check if next token should be a command
        if (token.type == TOKEN_PIPE || token.type == TOKEN_SEMICOLON ||
            token.type == TOKEN_AND || token.type == TOKEN_OR) {
            expect_command = true;
            current_cmd->end_pos = token.position + token.length;
        }
    }

    // Set end position for last command
    if (current_command < count) {
        (*commands)[current_command].end_pos = state.position;
    }

    *command_count = count;
    return true;
}

// Free tokenized commands
void shell_free_commands(shell_command_t* commands, size_t command_count) {
    if (commands == NULL) return;

    for (size_t i = 0; i < command_count; i++) {
        if (commands[i].tokens != NULL) {
            free(commands[i].tokens);
        }
    }
    free(commands);
}

// Get human-readable token type name
const char* shell_token_type_name(token_type_t type) {
    switch (type) {
        case TOKEN_COMMAND: return "COMMAND";
        case TOKEN_ARGUMENT: return "ARGUMENT";
        case TOKEN_PIPE: return "PIPE";
        case TOKEN_REDIRECT_IN: return "REDIRECT_IN";
        case TOKEN_REDIRECT_OUT: return "REDIRECT_OUT";
        case TOKEN_REDIRECT_ERR: return "REDIRECT_ERR";
        case TOKEN_REDIRECT_APPEND: return "REDIRECT_APPEND";
        case TOKEN_SEMICOLON: return "SEMICOLON";
        case TOKEN_AND: return "AND";
        case TOKEN_OR: return "OR";
        case TOKEN_SUBSHELL_START: return "SUBSHELL_START";
        case TOKEN_SUBSHELL_END: return "SUBSHELL_END";
        case TOKEN_END: return "END";
        default: return "UNKNOWN";
    }
}