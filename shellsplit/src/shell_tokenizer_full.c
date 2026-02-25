#include "shell_tokenizer_full.h"
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
    state->brace_depth = 0;
    state->in_arithmetic = false;
}

// Check if character is a shell operator
static bool is_shell_operator(char c) {
    return c == '|' || c == '>' || c == '<' || c == '&' ||
           c == ';' || c == '(' || c == ')' || c == '$' || c == '`' || c == '[';
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

    if (c == '"' || c == '\'') {
        if (!state->in_quotes) {
            state->in_quotes = true;
            state->quote_char = c;
            state->position++;
            return true;
        } else if (c == state->quote_char) {
            state->in_quotes = false;
            state->quote_char = '\0';
            state->position++;
            return true;
        }
    }

    // Handle backslash escaping
    if (c == '\\' && state->position + 1 < state->length) {
        state->position += 2;
        return true;
    }

    return false;
}

// Parse variable token
static bool parse_variable(shell_tokenizer_state_t* state, shell_token_t* token) {
    if (state->position >= state->length) return false;

    size_t start = state->position;
    bool is_quoted = state->in_quotes;

    if (state->input[state->position] != '$') {
        return false;
    }
    state->position++;

    // Check for ${VAR} format
    if (state->position < state->length && state->input[state->position] == '{') {
        state->position++;
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
            // Allow:
            // - alphanumeric and _ for variable names
            // - %, # for parameter expansion patterns (${var%%pattern}, ${var%pattern}, ${var#pattern})
            // - :, -, =, ?, + for parameter expansion operators (${var:-default}, ${var:=default}, etc.)
            // - ! for indirection (${!var})
            // - [ for array subscript (${arr[index]})
            // - @, * for special parameters
            // - / for pattern substitution (${var/pattern/replace})
            if (!isalnum(c) && c != '_' && c != '%' && c != '#' && 
                c != ':' && c != '-' && c != '=' && c != '?' && c != '+' &&
                c != '!' && c != '[' && c != '@' && c != '*' && c != '/') {
                return false;
            }
            state->position++;
        }
        return false;
    }

    // Check for special variables ($1, $#, $?, $$, $!, $@, $*)
    if (state->position < state->length) {
        char next = state->input[state->position];
        // Handle: $0-$9, $#, $?, $$, $!, $@, $*
        if (isdigit(next) || next == '#' || next == '?' || next == '$' || 
            next == '!' || next == '@' || next == '*') {
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

    if (state->position > start + 1) {
        token->type = is_quoted ? TOKEN_VARIABLE_QUOTED : TOKEN_VARIABLE;
        token->start = state->input + start;
        token->length = state->position - start;
        token->position = start;
        token->is_quoted = is_quoted;
        token->is_escaped = false;
        return true;
    }

    return false;
}

// Parse subshell token
static bool parse_subshell(shell_tokenizer_state_t* state, shell_token_t* token) {
    if (state->position >= state->length) return false;

    size_t start = state->position;
    bool is_quoted = state->in_quotes;

    // Check for $(command) format
    if (state->input[state->position] == '$' &&
        state->position + 1 < state->length &&
        state->input[state->position + 1] == '(') {

        state->position += 2;
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
            token->type = TOKEN_SUBSHELL;
            token->start = state->input + start;
            token->length = state->position - start + 1;
            token->position = start;
            token->is_quoted = is_quoted;
            token->is_escaped = false;
            state->paren_depth--;
            state->in_subshell = false;
            state->position++;
            return true;
        }
        return false;
    }

    // Check for `command` format (legacy)
    if (state->input[state->position] == '`') {
        state->position++;
        state->paren_depth++;
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
                state->paren_depth--;
                state->in_subshell = false;
                return true;
            }
            state->position++;
        }
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

// Recursively detect features inside a subshell or other complex token
// Returns true if any features were found
static bool detect_features_recursive(const char* content, size_t length,
                                      bool* has_variables, bool* has_globs,
                                      bool* has_subshells, bool* has_arithmetic) {
    if (!content || length == 0) return false;
    
    shell_tokenizer_state_t state;
    shell_tokenizer_init(&state, content);
    
    bool found_features = false;
    shell_token_t token;
    
    while (shell_tokenizer_next(&state, &token)) {
        switch (token.type) {
            case TOKEN_VARIABLE:
            case TOKEN_VARIABLE_QUOTED:
            case TOKEN_SPECIAL_VAR:
                if (has_variables) *has_variables = true;
                found_features = true;
                break;
            case TOKEN_GLOB:
                if (has_globs) *has_globs = true;
                found_features = true;
                break;
            case TOKEN_SUBSHELL:
                if (has_subshells) *has_subshells = true;
                found_features = true;
                // Recursively check inside the subshell
                if (token.length > 2) {
                    const char* inner = token.start + 2;  // Skip $(
                    size_t inner_len = token.length - 3;   // Exclude $( and )
                    bool inner_has_vars = false, inner_has_globs = false;
                    bool inner_has_subs = false, inner_has_arith = false;
                    detect_features_recursive(inner, inner_len,
                                            &inner_has_vars, &inner_has_globs,
                                            &inner_has_subs, &inner_has_arith);
                    if (has_variables && inner_has_vars) *has_variables = true;
                    if (has_globs && inner_has_globs) *has_globs = true;
                    if (has_subshells && inner_has_subs) *has_subshells = true;
                    if (has_arithmetic && inner_has_arith) *has_arithmetic = true;
                }
                break;
            case TOKEN_ARITHMETIC:
                if (has_arithmetic) *has_arithmetic = true;
                found_features = true;
                break;
            default:
                break;
        }
    }
    
    return found_features;
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
            while (state->position < state->length) {
                if (handle_quotes(state)) {
                    if (!state->in_quotes) break;
                } else {
                    state->position++;
                }
            }

            // Check if this is a variable inside quotes
            const char* token_start = state->input + start_pos + 1;
            size_t token_length = (state->position - start_pos) - 2;

            if (token_length > 0 && token_start[0] == '$') {
                shell_tokenizer_state_t temp_state = *state;
                temp_state.position = start_pos + 1;
                temp_state.in_quotes = true;

                shell_token_t temp_token;
                if (parse_variable(&temp_state, &temp_token)) {
                    token->type = TOKEN_VARIABLE_QUOTED;
                    token->start = state->input + start_pos;
                    token->length = state->position - start_pos;
                    token->position = start_pos;
                    token->is_quoted = true;
                    token->is_escaped = false;
                    return true;
                }
            }

            token->type = TOKEN_ARGUMENT;
            token->start = state->input + start_pos;
            token->length = state->position - start_pos;
            token->position = start_pos;
            token->is_quoted = true;
            token->is_escaped = false;
            return true;
        }
        current_char = state->input[state->position];
    }

    // Check for $(( arithmetic expansion first
    if (current_char == '$' && !state->in_quotes) {
        if (state->position + 2 < state->length &&
            state->input[state->position + 1] == '(' && 
            state->input[state->position + 2] == '(') {
            size_t start = state->position;
            state->position += 3;
            int depth = 2;
            while (state->position < state->length && depth > 0) {
                char c = state->input[state->position];
                if (c == '(') depth++;
                if (c == ')') depth--;
                state->position++;
            }
            if (depth == 0) {
                token->type = TOKEN_ARITHMETIC;
                token->start = state->input + start;
                token->length = state->position - start;
                token->position = start;
                token->is_quoted = false;
                token->is_escaped = false;
                return true;
            }
            state->position = start;
        }
        
        if (parse_variable(state, token)) {
            return true;
        }
        state->position = start_pos;
    }

    // Check for subshells
    if ((current_char == '$' || current_char == '`') && !state->in_quotes) {
        if (parse_subshell(state, token)) {
            return true;
        }
        current_char = state->input[state->position];
    }

    // Check for shell operators
    if (!state->in_quotes && is_shell_operator(current_char)) {
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
                
                // Check for >>&N (append and redirect)
                if (state->position < state->length && state->input[state->position] == '&') {
                    token->length = 3;
                    state->position++;
                    if (state->position < state->length &&
                        (state->input[state->position] == '1' ||
                         state->input[state->position] == '2')) {
                        token->length = 4;
                        state->position++;
                    }
                }
                return true;
            } else if (current_char == '2' && next_char == '>') {
                token->type = TOKEN_REDIRECT_ERR;
                token->start = state->input + state->position;
                token->length = 2;
                token->position = state->position;
                token->is_quoted = false;
                token->is_escaped = false;
                state->position += 2;
                
                if (state->position < state->length && state->input[state->position] == '&') {
                    token->length = 3;
                    state->position++;
                    if (state->position < state->length &&
                        (state->input[state->position] == '1' ||
                         state->input[state->position] == '2')) {
                        token->length = 4;
                        state->position++;
                    }
                }
                return true;
            } else if (current_char == '>' && next_char == '&') {
                token->type = TOKEN_REDIRECT_ERR;
                token->start = state->input + state->position;
                token->length = 2;
                token->position = state->position;
                token->is_quoted = false;
                token->is_escaped = false;
                state->position += 2;
                if (state->position < state->length &&
                    (state->input[state->position] == '1' ||
                     state->input[state->position] == '2')) {
                    token->length = 3;
                    state->position++;
                }
                return true;
            }
        }

        switch (current_char) {
            case '|':
                token->type = TOKEN_PIPE;
                break;
            case '>':
                token->type = TOKEN_REDIRECT_OUT;
                break;
            case '<':
                token->type = TOKEN_REDIRECT_IN;
                // Check for <&N (input duplication)
                if (state->position + 1 < state->length && state->input[state->position + 1] == '&') {
                    state->position++;
                    if (state->position + 1 < state->length &&
                        (state->input[state->position + 1] == '1' ||
                         state->input[state->position + 1] == '2')) {
                        token->length = 3;
                        state->position++;
                    } else {
                        token->length = 2;
                    }
                }
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
                if (state->paren_depth > 0) state->paren_depth--;
                if (state->paren_depth == 0) state->in_subshell = false;
                break;
            case '[':
                if (state->position + 1 < state->length) {
                    size_t bracket_start = state->position;
                    state->position++;
                    if (state->position < state->length && 
                        (state->input[state->position] == '!' || 
                         state->input[state->position] == '^')) {
                        state->position++;
                    }
                    while (state->position < state->length) {
                        char c = state->input[state->position];
                        if (c == ']') {
                            state->position++;
                            token->type = TOKEN_GLOB;
                            token->start = state->input + bracket_start;
                            token->length = state->position - bracket_start;
                            token->position = bracket_start;
                            token->is_quoted = false;
                            token->is_escaped = false;
                            return true;
                        }
                        if (c == '\\' && state->position + 1 < state->length) {
                            state->position += 2;
                            continue;
                        }
                        if (isspace(c) || is_shell_operator(c)) {
                            break;
                        }
                        state->position++;
                    }
                }
                token->type = TOKEN_ARGUMENT;
                break;
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                if (state->position + 1 < state->length) {
                    size_t check_pos = state->position + 1;
                    while (check_pos < state->length && 
                           isspace(state->input[check_pos])) {
                        check_pos++;
                    }
                    if (check_pos < state->length) {
                        char after_num = state->input[check_pos];
                        if (after_num == '>' || after_num == '<') {
                            if (after_num == '>') {
                                token->type = TOKEN_REDIRECT_ERR;
                            } else {
                                token->type = TOKEN_REDIRECT_IN;
                            }
                            token->start = state->input + state->position;
                            token->length = check_pos - state->position + 1;
                            token->position = state->position;
                            token->is_quoted = false;
                            token->is_escaped = false;
                            state->position = check_pos + 1;
                            return true;
                        }
                    }
                }
                token->type = TOKEN_ARGUMENT;
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

    // Check for digit followed by redirect (e.g., "2>&1" or "2 >&1" with space)
    if (!state->in_quotes && isdigit(current_char)) {
        size_t check_pos = state->position + 1;
        while (check_pos < state->length && isspace(state->input[check_pos])) {
            check_pos++;
        }
        if (check_pos < state->length) {
            char after_digit = state->input[check_pos];
            if (after_digit == '>') {
                token->type = TOKEN_REDIRECT_ERR;
                token->start = state->input + state->position;
                token->position = state->position;
                token->is_quoted = false;
                token->is_escaped = false;
                
                // Check for >&N or >>&N patterns
                if (check_pos + 1 < state->length && state->input[check_pos + 1] == '&') {
                    size_t fd_pos = check_pos + 2;
                    if (fd_pos < state->length && (state->input[fd_pos] == '1' || state->input[fd_pos] == '2')) {
                        token->length = fd_pos + 1 - state->position;
                        state->position = fd_pos + 1;
                    } else {
                        token->length = check_pos + 1 - state->position;
                        state->position = check_pos + 1;
                    }
                } else {
                    token->length = check_pos + 1 - state->position;
                    state->position = check_pos + 1;
                }
                return true;
            } else if (after_digit == '<') {
                token->type = TOKEN_REDIRECT_IN;
                token->start = state->input + state->position;
                token->length = check_pos + 1 - state->position;
                token->position = state->position;
                token->is_quoted = false;
                token->is_escaped = false;
                state->position = check_pos + 1;
                return true;
            }
        }
    }

    // Handle regular tokens
    while (state->position < state->length) {
        char c = state->input[state->position];

        if (state->in_quotes) {
            if (handle_quotes(state)) {
                if (!state->in_quotes) break;
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

    size_t token_length = state->position - start_pos;
    const char* token_text = state->input + start_pos;

    if (is_glob_pattern(token_text, token_length)) {
        token->type = TOKEN_GLOB;
    } else {
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
        if (expect_command && (token.type == TOKEN_COMMAND || token.type == TOKEN_ARGUMENT || 
                              token.type == TOKEN_SUBSHELL || token.type == TOKEN_VARIABLE ||
                              token.type == TOKEN_VARIABLE_QUOTED || token.type == TOKEN_SPECIAL_VAR)) {
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

    *commands = malloc(count * sizeof(shell_command_t));
    if (*commands == NULL) {
        *command_count = 0;
        return false;
    }

    // Second pass: tokenize and group into commands
    shell_tokenizer_init(&state, input);
    size_t current_command = 0;
    shell_command_t* current_cmd = &(*commands)[current_command];

    shell_token_t* tokens = malloc(16 * sizeof(shell_token_t));
    if (tokens == NULL) {
        free(*commands);
        *command_count = 0;
        return false;
    }
    size_t token_capacity = 16;

    current_cmd->tokens = tokens;
    current_cmd->token_count = 0;
    current_cmd->start_pos = state.position;
    current_cmd->end_pos = state.position;
    current_cmd->has_variables = false;
    current_cmd->has_globs = false;
    current_cmd->has_subshells = false;
    current_cmd->has_arithmetic = false;

    expect_command = true;

    while (shell_tokenizer_next(&state, &token)) {
        if (expect_command && (token.type == TOKEN_COMMAND || token.type == TOKEN_ARGUMENT ||
                              token.type == TOKEN_SUBSHELL || token.type == TOKEN_VARIABLE ||
                              token.type == TOKEN_VARIABLE_QUOTED || token.type == TOKEN_SPECIAL_VAR)) {
            if (current_cmd->token_count > 0) {
                if (current_command + 1 < count) {
                    current_command++;
                    current_cmd = &(*commands)[current_command];
                    current_cmd->start_pos = token.position;
                    current_cmd->end_pos = token.position;

                    tokens = malloc(16 * sizeof(shell_token_t));
                    if (tokens == NULL) {
                        shell_free_commands(*commands, current_command);
                        *command_count = current_command;
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
            }
            expect_command = false;
        }

        if (current_cmd->token_count >= token_capacity) {
            size_t new_capacity = token_capacity * 2;
            shell_token_t* new_tokens = realloc(tokens, new_capacity * sizeof(shell_token_t));
            if (new_tokens == NULL) {
                shell_free_commands(*commands, current_command + 1);
                *command_count = current_command + 1;
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

        if (token.type == TOKEN_PIPE || token.type == TOKEN_SEMICOLON ||
            token.type == TOKEN_AND || token.type == TOKEN_OR) {
            expect_command = true;
            current_cmd->end_pos = token.position + token.length;
        }
    }

    if (current_command < count) {
        (*commands)[current_command].end_pos = state.position;
    }

    // Check for unclosed quotes, parentheses, or braces - indicates malformed input
    if (state.in_quotes || state.paren_depth > 0 || state.brace_depth > 0) {
        // Clean up allocated commands before returning error
        for (size_t i = 0; i < count; i++) {
            if ((*commands)[i].tokens != NULL) {
                free((*commands)[i].tokens);
            }
        }
        free(*commands);
        *commands = NULL;
        *command_count = 0;
        return false;
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
bool shell_has_features(shell_command_t* command) {
    if (command == NULL) return false;
    return command->has_variables || command->has_globs ||
           command->has_subshells || command->has_arithmetic;
}
