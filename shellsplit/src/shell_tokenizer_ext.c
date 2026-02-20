#include "shell_tokenizer_ext.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

// Initialize extended tokenizer state
void extended_shell_tokenizer_init(
    extended_shell_tokenizer_state_t* state,
    const char* input
) {
    if (state == NULL || input == NULL) return;

    state->input = input;
    state->position = 0;
    state->length = strlen(input);
    state->in_quotes = false;
    state->in_subshell = false;
    state->quote_char = '\0';
    state->paren_depth = 0;
    state->brace_depth = 0;
    state->in_arithmetic = false;
}

// Check if character is shell operator (extended)
static bool is_shell_operator_ext(char c) {
    return c == '|' || c == '>' || c == '<' || c == '&' ||
           c == ';' || c == '(' || c == ')' || c == '$' || c == '`' || c == '[';
}

// Skip whitespace
static void skip_whitespace_ext(extended_shell_tokenizer_state_t* state) {
    while (state->position < state->length && isspace(state->input[state->position])) {
        state->position++;
    }
}

// Handle quotes and escaping (extended)
static bool handle_quotes_ext(extended_shell_tokenizer_state_t* state) {
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

// Parse variable token
static bool parse_variable(extended_shell_tokenizer_state_t* state, extended_shell_token_t* token) {
    if (state->position >= state->length) return false;

    size_t start = state->position;
    bool is_quoted = state->in_quotes;

    // Check for $ character
    if (state->input[state->position] != '$') {
        return false;
    }
    state->position++; // Skip '$'

    // Check for ${VAR} format
    if (state->position < state->length && state->input[state->position] == '{') {
        state->position++; // Skip '{'
        state->brace_depth++;

        while (state->position < state->length) {
            char c = state->input[state->position];
            if (c == '}') {
                state->position++;
                state->brace_depth--;
                token->type = is_quoted ? TOKEN_VARIABLE_QUOTED : TOKEN_VARIABLE;
                token->start = state->input + start;
                token->length = state->position - start;
                token->position = start;
                token->is_quoted = is_quoted;
                token->is_escaped = false;
                return true;
            }
            if (!isalnum(c) && c != '_') {
                // Invalid variable name - treat as regular text
                return false;
            }
            state->position++;
        }
        // Unclosed brace - treat as regular text
        return false;
    }

    // Check for special variables ($1, $#, $?, $$)
    if (state->position < state->length) {
        char next = state->input[state->position];
        if (isdigit(next) || next == '#' || next == '?' || next == '$') {
            state->position++;
            token->type = is_quoted ? TOKEN_VARIABLE_QUOTED : TOKEN_SPECIAL_VAR;
            token->start = state->input + start;
            token->length = state->position - start;
            token->position = start;
            token->is_quoted = is_quoted;
            token->is_escaped = false;
            return true;
        }
    }

    // Simple $VAR format
    while (state->position < state->length) {
        char c = state->input[state->position];
        if (!isalnum(c) && c != '_') {
            break;
        }
        state->position++;
    }

    if (state->position > start + 1) { // At least $ + one char
        token->type = is_quoted ? TOKEN_VARIABLE_QUOTED : TOKEN_VARIABLE;
        token->start = state->input + start;
        token->length = state->position - start;
        token->position = start;
        token->is_quoted = is_quoted;
        token->is_escaped = false;
        return true;
    }

    // Just a lone $ - not a variable
    return false;
}

// Parse subshell token
static bool parse_subshell(extended_shell_tokenizer_state_t* state, extended_shell_token_t* token) {
    if (state->position >= state->length) return false;

    size_t start = state->position;
    bool is_quoted = state->in_quotes;

    // Check for $(command) format
    if (state->input[state->position] == '$' &&
        state->position + 1 < state->length &&
        state->input[state->position + 1] == '(') {

        state->position += 2; // Skip '$('
        state->paren_depth++;
        state->in_subshell = true;

        int depth = 1;
        while (state->position < state->length && depth > 0) {
            char c = state->input[state->position];
            if (c == '(') depth++;
            if (c == ')') depth--;
            if (depth > 0) state->position++;
        }

        if (depth == 0) {
            // Found closing parenthesis
            token->type = TOKEN_SUBSHELL;
            token->start = state->input + start;
            token->length = state->position - start + 1; // Include closing )
            token->position = start;
            token->is_quoted = is_quoted;
            token->is_escaped = false;
            state->in_subshell = false;
            state->position++; // Skip closing )
            return true;
        }
        // Unclosed subshell - treat as regular text
        return false;
    }

    // Check for `command` format (legacy)
    if (state->input[state->position] == '`') {
        state->position++; // Skip '`'
        state->in_subshell = true;

        while (state->position < state->length) {
            char c = state->input[state->position];
            if (c == '`') {
                state->position++;
                token->type = TOKEN_SUBSHELL;
                token->start = state->input + start;
                token->length = state->position - start;
                token->position = start;
                token->is_quoted = is_quoted;
                token->is_escaped = false;
                state->in_subshell = false;
                return true;
            }
            state->position++;
        }
        // Unclosed backtick - treat as regular text
        return false;
    }

    return false;
}

// Check if token contains glob patterns
static bool is_glob_pattern(const char* str, size_t length) {
    for (size_t i = 0; i < length; i++) {
        char c = str[i];
        if (c == '*' || c == '?' || c == '[') {
            return true;
        }
    }
    return false;
}

// Get next extended token
bool extended_shell_tokenizer_next(
    extended_shell_tokenizer_state_t* state,
    extended_shell_token_t* token
) {
    if (state == NULL || token == NULL || state->position >= state->length) {
        token->type = TOKEN_END;
        return false;
    }

    skip_whitespace_ext(state);

    if (state->position >= state->length) {
        token->type = TOKEN_END;
        return false;
    }

    size_t start_pos = state->position;
    char current_char = state->input[start_pos];

    // Handle quotes first
    if (handle_quotes_ext(state)) {
        if (state->in_quotes) {
            // We're inside quotes, treat everything as part of the token until closing quote
            while (state->position < state->length) {
                if (handle_quotes_ext(state)) {
                    if (!state->in_quotes) break; // Found closing quote
                } else {
                    state->position++;
                }
            }

            // Check if this is a variable inside quotes
            const char* token_start = state->input + start_pos + 1; // Skip opening quote
            size_t token_length = (state->position - start_pos) - 2; // Skip both quotes

            if (token_length > 0 && token_start[0] == '$') {
                // Potential variable inside quotes
                extended_shell_tokenizer_state_t temp_state = *state;
                temp_state.position = start_pos + 1;
                temp_state.in_quotes = true;

                extended_shell_token_t temp_token;
                if (parse_variable(&temp_state, &temp_token)) {
                    // It's a variable
                    token->type = TOKEN_VARIABLE_QUOTED;
                    token->start = state->input + start_pos;
                    token->length = state->position - start_pos;
                    token->position = start_pos;
                    token->is_quoted = true;
                    token->is_escaped = false;
                    return true;
                }
            }

            // Regular quoted text
            token->type = TOKEN_ARGUMENT;
            token->start = state->input + start_pos;
            token->length = state->position - start_pos;
            token->position = start_pos;
            token->is_quoted = true;
            token->is_escaped = false;
            return true;
        }
        // If we handled quotes but not in quotes anymore, continue to check for operators
        current_char = state->input[state->position];
    }

    // Check for variables first (before operators)
    if (current_char == '$' && !state->in_quotes) {
        if (parse_variable(state, token)) {
            return true;
        }
        // If variable parsing failed, continue with normal processing
        current_char = state->input[state->position];
    }

    // Check for subshells
    if ((current_char == '$' || current_char == '`') && !state->in_quotes) {
        if (parse_subshell(state, token)) {
            return true;
        }
        // If subshell parsing failed, continue with normal processing
        current_char = state->input[state->position];
    }

    // Check for shell operators (only if not in quotes)
    if (!state->in_quotes && is_shell_operator_ext(current_char)) {
        // Handle multi-character operators first
        if (state->position + 1 < state->length) {
            char next_char = state->input[state->position + 1];

            if (current_char == '|' && next_char == '|') {
                token->type = TOKEN_OR;
                token->start = state->input + state->position;
                token->length = 2;
                token->position = state->position;
                token->is_quoted = false;
                token->is_escaped = false;
                state->position += 2;
                return true;
            } else if (current_char == '&' && next_char == '&') {
                token->type = TOKEN_AND;
                token->start = state->input + state->position;
                token->length = 2;
                token->position = state->position;
                token->is_quoted = false;
                token->is_escaped = false;
                state->position += 2;
                return true;
            } else if (current_char == '>' && next_char == '>') {
                token->type = TOKEN_REDIRECT_APPEND;
                token->start = state->input + state->position;
                token->length = 2;
                token->position = state->position;
                token->is_quoted = false;
                token->is_escaped = false;
                state->position += 2;
                return true;
            } else if (current_char == '2' && next_char == '>') {
                token->type = TOKEN_REDIRECT_ERR;
                token->start = state->input + state->position;
                token->length = 2;
                token->position = state->position;
                token->is_quoted = false;
                token->is_escaped = false;
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
                token->type = TOKEN_AND;
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
            case '[':
                // Could be glob pattern or test command
                token->type = TOKEN_ARGUMENT; // Let glob detection handle it
                break;
            default:
                token->type = TOKEN_ARGUMENT;
                break;
        }

        token->start = state->input + state->position;
        token->length = 1;
        token->position = state->position;
        token->is_quoted = false;
        token->is_escaped = false;
        state->position++;
        return true;
    }

    // Handle regular tokens (commands and arguments)
    while (state->position < state->length) {
        char c = state->input[state->position];

        if (state->in_quotes) {
            if (handle_quotes_ext(state)) {
                if (!state->in_quotes) break; // End of quoted section
            } else {
                state->position++;
            }
        } else {
            if (isspace(c) || is_shell_operator_ext(c)) {
                break;
            }
            state->position++;
        }
    }

    // Determine token type
    size_t token_length = state->position - start_pos;
    const char* token_text = state->input + start_pos;

    // Check for glob patterns
    if (is_glob_pattern(token_text, token_length)) {
        token->type = TOKEN_GLOB;
    } else {
        // First token is command, rest are arguments
        token->type = TOKEN_COMMAND;
        for (size_t i = 0; i < start_pos; i++) {
            if (state->input[i] == '|' || state->input[i] == ';' ||
                state->input[i] == '&') {
                token->type = TOKEN_COMMAND;
                break;
            }
        }
    }

    token->start = state->input + start_pos;
    token->length = token_length;
    token->position = start_pos;
    token->is_quoted = state->in_quotes;
    token->is_escaped = false;

    return true;
}

// Tokenize with extended syntax support
bool extended_shell_tokenize_commands(
    const char* input,
    extended_shell_command_t** commands,
    size_t* command_count
) {
    if (input == NULL || commands == NULL || command_count == NULL) {
        return false;
    }

    extended_shell_tokenizer_state_t state;
    extended_shell_tokenizer_init(&state, input);

    // First pass: count commands
    size_t count = 0;
    bool expect_command = true;

    extended_shell_tokenizer_state_t temp_state = state;
    extended_shell_token_t token;

    while (extended_shell_tokenizer_next(&temp_state, &token)) {
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
    *commands = malloc(count * sizeof(extended_shell_command_t));
    if (*commands == NULL) {
        return false;
    }

    // Second pass: tokenize and group into commands
    extended_shell_tokenizer_init(&state, input);
    size_t current_command = 0;
    extended_shell_command_t* current_cmd = &(*commands)[current_command];

    // Allocate initial token array for first command
    extended_shell_token_t* tokens = malloc(16 * sizeof(extended_shell_token_t));
    if (tokens == NULL) {
        free(*commands);
        return false;
    }
    size_t token_capacity = 16;

    current_cmd->tokens = tokens;
    current_cmd->token_count = 0;
    current_cmd->start_pos = state.position;
    current_cmd->has_variables = false;
    current_cmd->has_globs = false;
    current_cmd->has_subshells = false;
    current_cmd->has_arithmetic = false;

    expect_command = true;

    while (extended_shell_tokenizer_next(&state, &token)) {
        // Check if this token starts a new command
        if (expect_command && (token.type == TOKEN_COMMAND || token.type == TOKEN_ARGUMENT)) {
            if (current_cmd->token_count > 0) {
                // Start new command
                current_command++;
                current_cmd = &(*commands)[current_command];
                current_cmd->start_pos = token.position;

                // Allocate token array for new command
                tokens = malloc(16 * sizeof(extended_shell_token_t));
                if (tokens == NULL) {
                    // Free existing commands
                    for (size_t i = 0; i <= current_command; i++) {
                        free((*commands)[i].tokens);
                    }
                    free(*commands);
                    return false;
                }
                token_capacity = 16;
                current_cmd->tokens = tokens;
                current_cmd->token_count = 0;
                current_cmd->has_variables = false;
                current_cmd->has_globs = false;
                current_cmd->has_subshells = false;
                current_cmd->has_arithmetic = false;
            }
            expect_command = false;
        }

        // Add token to current command
        if (current_cmd->token_count >= token_capacity) {
            // Resize token array
            size_t new_capacity = token_capacity * 2;
            extended_shell_token_t* new_tokens = realloc(tokens, new_capacity * sizeof(extended_shell_token_t));
            if (new_tokens == NULL) {
                // Free existing commands
                for (size_t i = 0; i <= current_command; i++) {
                    free((*commands)[i].tokens);
                }
                free(*commands);
                return false;
            }
            tokens = new_tokens;
            token_capacity = new_capacity;
            current_cmd->tokens = tokens;
        }

        current_cmd->tokens[current_cmd->token_count++] = token;

        // Track shell features
        switch (token.type) {
            case TOKEN_VARIABLE:
            case TOKEN_VARIABLE_QUOTED:
            case TOKEN_SPECIAL_VAR:
                current_cmd->has_variables = true;
                break;
            case TOKEN_GLOB:
                current_cmd->has_globs = true;
                break;
            case TOKEN_SUBSHELL:
                current_cmd->has_subshells = true;
                break;
            case TOKEN_ARITHMETIC:
                current_cmd->has_arithmetic = true;
                break;
            default:
                break;
        }

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

// Free extended commands
void extended_shell_free_commands(
    extended_shell_command_t* commands,
    size_t command_count
) {
    if (commands == NULL) return;

    for (size_t i = 0; i < command_count; i++) {
        free(commands[i].tokens);
    }
    free(commands);
}

// Get human-readable extended token type name
const char* extended_shell_token_type_name(
    token_type_t type
) {
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
        case TOKEN_VARIABLE: return "VARIABLE";
        case TOKEN_VARIABLE_QUOTED: return "VARIABLE_QUOTED";
        case TOKEN_SPECIAL_VAR: return "SPECIAL_VAR";
        case TOKEN_GLOB: return "GLOB";
        case TOKEN_SUBSHELL: return "SUBSHELL";
        case TOKEN_ARITHMETIC: return "ARITHMETIC";
        case TOKEN_PROCESS_SUB: return "PROCESS_SUB";
        case TOKEN_END: return "END";
        default: return "UNKNOWN";
    }
}

// Check if command has shell scripting features
bool extended_shell_has_features(
    extended_shell_command_t* command
) {
    if (command == NULL) return false;
    return command->has_variables || command->has_globs ||
           command->has_subshells || command->has_arithmetic;
}