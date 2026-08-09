#include "shell_tokenizer_full.h"
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* The tokenizer consumes textual shell input, not arbitrary binary.  Keep C
 * whitespace as valid separators, but reject all other control bytes, DEL,
 * and raw high bytes before a partial token stream can be exposed. */
static bool contains_invalid_shell_byte(const char *input) {
  for (const unsigned char *cursor = (const unsigned char *)input; *cursor;
       cursor++) {
    if ((*cursor < 0x20 && !isspace(*cursor)) || *cursor == 0x7F ||
        *cursor >= 0x80)
      return true;
  }
  return false;
}

void shell_tokenizer_init(shell_tokenizer_state_t *state, const char *input) {
  if (state == NULL)
    return;

  memset(state, 0, sizeof(*state));
  state->input = input ? input : "";
  state->length =
      contains_invalid_shell_byte(state->input) ? 0 : strlen(state->input);
}

static void check_keyword(shell_tokenizer_state_t *state,
                          const char *token_text, size_t token_len) {
  if (token_text == NULL || token_len == 0)
    return;

  // Track control-flow keywords for depth validation.
  // then/else/elif are recognized as flow keywords but do not directly adjust
  // depth here.
  if (token_len == 2 && strncmp(token_text, "if", 2) == 0) {
    state->if_depth++;
  } else if (token_len == 4) {
    if (strncmp(token_text, "then", 4) == 0 ||
        strncmp(token_text, "else", 4) == 0 ||
        strncmp(token_text, "elif", 4) == 0) {
      /* no depth change */
    }
  } else if (token_len == 2 && strncmp(token_text, "fi", 2) == 0) {
    if (state->if_depth > 0)
      state->if_depth--;
  }

  if (token_len == 5) {
    if (strncmp(token_text, "while", 5) == 0 ||
        strncmp(token_text, "until", 5) == 0) {
      state->loop_depth++;
    }
  } else if (token_len == 3 && strncmp(token_text, "for", 3) == 0) {
    state->loop_depth++;
  } else if (token_len == 4 && strncmp(token_text, "done", 4) == 0) {
    if (state->loop_depth > 0)
      state->loop_depth--;
  }

  if (token_len == 4 && strncmp(token_text, "case", 4) == 0) {
    state->case_depth++;
  } else if (token_len == 4 && strncmp(token_text, "esac", 4) == 0) {
    if (state->case_depth > 0)
      state->case_depth--;
  }
}

static bool is_shell_operator(char c) {
  return c == '|' || c == '>' || c == '<' || c == '&' || c == ';' || c == '(' ||
         c == ')' || c == '$' || c == '`' || c == '[';
}

static void skip_whitespace(shell_tokenizer_state_t *state) {
  while (state->position < state->length &&
         isspace((unsigned char)state->input[state->position])) {
    state->position++;
  }
}

static bool handle_quotes(shell_tokenizer_state_t *state) {
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

  if (c == '\\' && state->position + 1 < state->length) {
    state->position += 2;
    return true;
  }

  return false;
}

static bool parse_variable(shell_tokenizer_state_t *state,
                           shell_token_t *token) {
  if (state->position >= state->length)
    return false;

  size_t start = state->position;
  bool is_quoted = state->in_quotes;

  if (state->input[state->position] != '$') {
    return false;
  }
  state->position++;

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

      // Subscript may contain: simple index, $VAR, $((expr)), etc.
      if (c == '[') {
        int bracket_depth = 1;
        state->position++;

        while (state->position < state->length && bracket_depth > 0) {
          char bc = state->input[state->position];

          // Handle nested brackets
          if (bc == '[') {
            bracket_depth++;
            state->position++;
            continue;
          }
          if (bc == ']') {
            bracket_depth--;
            if (bracket_depth > 0) {
              state->position++;
              continue;
            }
            state->position++;
            break;
          }

          state->position++;
        }
        continue;
      }

      // Allow:
      // - alphanumeric and _ for variable names
      // - %, # for parameter expansion patterns (${var%%pattern},
      // ${var%pattern}, ${var#pattern})
      // - :, -, =, ?, + for parameter expansion operators (${var:-default},
      // ${var:=default}, etc.)
      // - ! for indirection (${!var})
      // - @, * for special parameters
      // - / for pattern substitution (${var/pattern/replace})
      if (!isalnum((unsigned char)c) && c != '_' && c != '%' && c != '#' &&
          c != ':' && c != '-' && c != '=' && c != '?' && c != '+' &&
          c != '!' && c != '@' && c != '*' && c != '/') {
        return false;
      }
      state->position++;
    }
    return false;
  }

  if (state->position < state->length) {
    char next = state->input[state->position];
    // Handle: $0-$9, $#, $?, $$, $!, $@, $*, $-
    if (isdigit((unsigned char)next) || next == '#' || next == '?' ||
        next == '$' || next == '!' || next == '@' || next == '*' ||
        next == '-') {
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

  while (state->position < state->length) {
    char c = state->input[state->position];
    if (!isalnum((unsigned char)c) && c != '_') {
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

static bool quoted_token_has_variable(const shell_token_t *token) {
  if (!token || !token->is_quoted || token->length < 2 ||
      token->start[0] != '"')
    return false;

  shell_tokenizer_state_t state = {0};
  state.input = token->start;
  state.length = token->length;
  if (token->start[token->length - 1] == '"')
    state.length--;
  state.position = 1;
  state.in_quotes = true;
  state.quote_char = '"';

  while (state.position < state.length) {
    if (state.input[state.position] == '\\' &&
        state.position + 1 < state.length) {
      state.position += 2;
      continue;
    }
    if (state.input[state.position] == '$') {
      shell_token_t variable;
      size_t position = state.position;
      if (parse_variable(&state, &variable))
        return true;
      state.position = position;
    }
    state.position++;
  }
  return false;
}

static bool parse_process_substitution(shell_tokenizer_state_t *state,
                                       shell_token_t *token, size_t start_pos,
                                       bool is_quoted) {
  if (start_pos + 1 >= state->length || state->input[start_pos + 1] != '(')
    return false;

  size_t position = start_pos + 2;
  int depth = 1;
  char quote = 0;
  while (position < state->length && depth > 0) {
    char c = state->input[position];
    if (c == '\\' && quote != '\'' && position + 1 < state->length) {
      position += 2;
      continue;
    }
    if (quote) {
      if (c == quote)
        quote = 0;
    } else if (c == '\'' || c == '"' || c == '`') {
      quote = c;
    } else if (c == '(') {
      depth++;
    } else if (c == ')') {
      depth--;
    }
    position++;
  }
  if (depth != 0)
    return false;

  token->type = TOKEN_PROCESS_SUB;
  token->start = state->input + start_pos;
  token->length = position - start_pos;
  token->position = start_pos;
  token->is_quoted = is_quoted;
  token->is_escaped = false;
  state->position = position;
  return true;
}

static bool parse_heredoc(shell_tokenizer_state_t *state, shell_token_t *token,
                          size_t start_pos, bool is_quoted) {
  if (start_pos + 1 >= state->length || state->input[start_pos + 1] != '<' ||
      (start_pos + 2 < state->length && state->input[start_pos + 2] == '<'))
    return false;

  size_t position = start_pos + 2;
  bool strip_tabs = position < state->length && state->input[position] == '-';
  if (strip_tabs)
    position++;
  while (position < state->length &&
         (state->input[position] == ' ' || state->input[position] == '\t'))
    position++;

  char delimiter_quote = 0;
  if (position < state->length &&
      (state->input[position] == '\'' || state->input[position] == '"'))
    delimiter_quote = state->input[position++];
  size_t delimiter_start = position;
  while (position < state->length) {
    char c = state->input[position];
    if ((delimiter_quote && c == delimiter_quote) ||
        (!delimiter_quote && (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
                              c == ';' || c == '&' || c == '|')))
      break;
    position++;
  }
  size_t delimiter_length = position - delimiter_start;
  if (delimiter_quote && position < state->length &&
      state->input[position] == delimiter_quote)
    position++;
  size_t token_end = position;

  size_t line_end = position;
  while (line_end < state->length &&
         (state->input[line_end] == ' ' || state->input[line_end] == '\t'))
    line_end++;
  if (delimiter_length > 0 && line_end < state->length &&
      (state->input[line_end] == '\n' || state->input[line_end] == '\r')) {
    if (state->input[line_end] == '\r' && line_end + 1 < state->length &&
        state->input[line_end + 1] == '\n')
      line_end++;
    size_t line_start = line_end + 1;
    while (line_start <= state->length) {
      size_t candidate = line_start;
      if (strip_tabs)
        while (candidate < state->length && state->input[candidate] == '\t')
          candidate++;
      if (candidate + delimiter_length <= state->length &&
          memcmp(state->input + candidate, state->input + delimiter_start,
                 delimiter_length) == 0) {
        size_t after = candidate + delimiter_length;
        if (after == state->length || state->input[after] == '\n' ||
            state->input[after] == '\r') {
          token_end = after;
          break;
        }
      }
      const char *newline =
          memchr(state->input + line_start, '\n', state->length - line_start);
      if (!newline)
        break;
      line_start = (size_t)(newline - state->input) + 1;
    }
  }

  token->type = TOKEN_HEREDOC;
  token->start = state->input + start_pos;
  token->length = token_end - start_pos;
  token->position = start_pos;
  token->is_quoted = is_quoted || delimiter_quote != 0;
  token->is_escaped = false;
  state->position = token_end;
  return true;
}

static bool token_has_unescaped_dollar(const shell_token_t *token) {
  for (size_t i = 0; i < token->length; i++) {
    if (token->start[i] == '\\' && i + 1 < token->length) {
      i++;
    } else if (token->start[i] == '$') {
      return true;
    }
  }
  return false;
}

static bool parse_subshell(shell_tokenizer_state_t *state,
                           shell_token_t *token) {
  if (state->position >= state->length)
    return false;

  size_t start = state->position;
  bool is_quoted = state->in_quotes;

  // Parse command substitution: `$(...)`.
  if (state->input[state->position] == '$' &&
      state->position + 1 < state->length &&
      state->input[state->position + 1] == '(') {

    state->position += 2;
    state->paren_depth++;
    state->in_subshell = true;

    int depth = 1;
    while (state->position < state->length && depth > 0) {
      char c = state->input[state->position];
      if (c == '(')
        depth++;
      if (c == ')')
        depth--;
      if (depth > 0)
        state->position++;
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

  // Parse legacy backtick command substitution (`...`).
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

// Check whether token text contains shell glob wildcards (`*`, `?`, `[`).
static bool is_glob_pattern(const char *str, size_t length) {
  for (size_t i = 0; i < length; i++) {
    char c = str[i];
    if (c == '*' || c == '?' || c == '[') {
      return true;
    }
  }
  return false;
}

static size_t scan_descriptor_target(const char *input, size_t position,
                                     size_t length) {
  if (position < length && input[position] == '-')
    return position + 1;
  while (position < length && isdigit((unsigned char)input[position]))
    position++;
  return position;
}

bool shell_tokenizer_next(shell_tokenizer_state_t *state,
                          shell_token_t *token) {
  if (token == NULL)
    return false;

  memset(token, 0, sizeof(*token));
  token->type = TOKEN_END;
  if (state == NULL || state->input == NULL ||
      state->position >= state->length) {
    return false;
  }

  skip_whitespace(state);

  if (state->position >= state->length) {
    return false;
  }

  size_t start_pos = state->position;
  char current_char = state->input[start_pos];
  bool is_quoted = state->in_quotes;

  // Invalid bytes are rejected before tokenization, so this tokenizer never
  // yields a partial stream for malformed byte sequences.

  // Handle quotes first
  char opening_quote = current_char;
  if (handle_quotes(state)) {
    if (state->in_quotes) {
      while (state->position < state->length) {
        if (handle_quotes(state)) {
          if (!state->in_quotes)
            break;
        } else {
          state->position++;
        }
      }

      token->type = TOKEN_ARGUMENT;
      token->start = state->input + start_pos;
      token->length = state->position - start_pos;
      token->position = start_pos;
      token->is_quoted = true;
      token->is_escaped = false;
      /* Variables expand anywhere inside double quotes. Classifying the whole
       * shell word as variable-bearing lets downstream transformation remain
       * conservative without splitting one argument into several. */
      if (opening_quote == '"' && quoted_token_has_variable(token))
        token->type = TOKEN_VARIABLE_QUOTED;
      return true;
    }
    current_char = state->input[state->position];
  }

  // Parse arithmetic expansion: `$((...))` first.
  if (current_char == '$' && !state->in_quotes) {
    if (state->position + 1 < state->length &&
        state->input[state->position + 1] == '{') {
      // This is a ${...} variable - try to parse it
      // Note: parse_variable increments brace_depth when entering ${...}
      // If it fails, we should NOT restore brace_depth - let final check catch
      // unclosed braces
      if (parse_variable(state, token)) {
        return true;
      }
      // On failure, reset position but NOT brace_depth - the unclosed brace
      // will be caught by the final check in shell_tokenize_commands
      state->position = start_pos;
    }
    if (state->position + 2 < state->length &&
        state->input[state->position + 1] == '(' &&
        state->input[state->position + 2] == '(') {
      size_t start = state->position;
      int saved_arith_depth = state->arith_depth;
      bool saved_in_arithmetic = state->in_arithmetic;
      state->position += 3;
      state->arith_depth = saved_arith_depth + 1;
      state->in_arithmetic = true;

      // The arithmetic opener contributes two parentheses. A local balance
      // handles both ordinary and nested parentheses without corrupting the
      // tokenizer's surrounding arithmetic state.
      int depth = 2;
      bool found_matching_paren = false;
      while (state->position < state->length && depth > 0) {
        char c = state->input[state->position];
        if (c == '(')
          depth++;
        else if (c == ')') {
          depth--;
          if (depth == 0)
            found_matching_paren = true;
        }
        state->position++;
      }

      // Only accept if we actually found matching )) - not just reached end of
      // input
      if (found_matching_paren) {
        // depth == 0 means we found matching ))
        // position > start + 3 ensures we consumed at least "$((" and one )
        // beyond the opening pair. This prevents accepting unclosed $((x+1)
        // which has one )
        token->type = TOKEN_ARITHMETIC;
        token->start = state->input + start;
        token->length = state->position - start;
        token->position = start;
        token->is_quoted = false;
        token->is_escaped = false;
        state->arith_depth = saved_arith_depth;
        state->in_arithmetic = saved_in_arithmetic;
        return true;
      }
      // Restore state on failure
      state->arith_depth = saved_arith_depth;
      state->in_arithmetic = saved_in_arithmetic;
      state->position = start;
    }

    // Only parse variable if not in arithmetic
    if (!state->in_arithmetic) {
      // Save brace_depth in case parse_variable modifies it and returns false
      int saved_brace_depth = state->brace_depth;
      if (parse_variable(state, token)) {
        return true;
      }
      // Restore brace_depth on failure - parse_variable may have modified it
      state->brace_depth = saved_brace_depth;
      state->position = start_pos;
    }
  }

  // Check for subshells (but not if inside arithmetic - they're handled there)
  if ((current_char == '$' || current_char == '`') && !state->in_quotes &&
      !state->in_arithmetic) {
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
        if (state->position < state->length &&
            state->input[state->position] == '&') {
          state->position++;
          state->position = scan_descriptor_target(
              state->input, state->position, state->length);
          token->length = state->position - token->position;
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
        state->position = scan_descriptor_target(state->input, state->position,
                                                 state->length);
        token->length = state->position - token->position;
        return true;
      }
    }

    switch (current_char) {
    case '|':
      token->type = TOKEN_PIPE;
      break;
    case '>':
      if (parse_process_substitution(state, token, start_pos, is_quoted))
        return true;
      token->type = TOKEN_REDIRECT_OUT;
      break;
    case '<':
      // Check for heredoc: <<, process substitution: <(cmd), here-string: <<<
      if (state->position + 1 < state->length) {
        // Check for <<< (here-string)
        if (state->input[state->position + 1] == '<' &&
            state->position + 2 < state->length &&
            state->input[state->position + 2] == '<') {
          // Here-string: <<<
          state->position += 2; // skip <<
          token->type = TOKEN_HERESTRING;
          token->start = state->input + start_pos;
          token->length = 3;
          token->position = start_pos;
          token->is_quoted = is_quoted;
          token->is_escaped = false;
          state->position++;
          return true;
        }

        if (parse_heredoc(state, token, start_pos, is_quoted))
          return true;

        if (parse_process_substitution(state, token, start_pos, is_quoted))
          return true;
      }
      token->type = TOKEN_REDIRECT_IN;
      // Check for <&N (input duplication)
      if (state->position + 1 < state->length &&
          state->input[state->position + 1] == '&') {
        token->start = state->input + start_pos;
        token->position = start_pos;
        token->is_quoted = is_quoted;
        token->is_escaped = false;
        state->position = scan_descriptor_target(
            state->input, state->position + 2, state->length);
        token->length = state->position - start_pos;
        return true;
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
      if (state->paren_depth > 0)
        state->paren_depth--;
      if (state->paren_depth == 0)
        state->in_subshell = false;
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
          if (isspace((unsigned char)c) || is_shell_operator(c)) {
            break;
          }
          state->position++;
        }

        /* An unmatched '[' is literal shell text. Return the consumed text
         * instead of manufacturing a token at the end of the input. */
        token->type = TOKEN_ARGUMENT;
        token->start = state->input + bracket_start;
        token->length = state->position - bracket_start;
        token->position = bracket_start;
        token->is_quoted = false;
        token->is_escaped = false;
        return true;
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

  // Check for a descriptor followed by a redirect. Whitespace is accepted for
  // compatibility with the historical tokenizer convention (for example,
  // "2 >&1"), even though a POSIX IO number is normally adjacent to the
  // operator.
  if (!state->in_quotes && isdigit((unsigned char)current_char)) {
    size_t check_pos = state->position;
    while (check_pos < state->length &&
           isdigit((unsigned char)state->input[check_pos]))
      check_pos++;
    while (check_pos < state->length &&
           isspace((unsigned char)state->input[check_pos])) {
      check_pos++;
    }
    if (check_pos < state->length) {
      char after_digit = state->input[check_pos];
      if (after_digit == '>' || after_digit == '<') {
        token->type =
            after_digit == '<' ? TOKEN_REDIRECT_IN : TOKEN_REDIRECT_ERR;
        token->start = state->input + state->position;
        token->position = state->position;
        token->is_quoted = false;
        token->is_escaped = false;

        size_t end = check_pos + 1;
        if (after_digit == '>' && end < state->length &&
            state->input[end] == '>') {
          token->type = TOKEN_REDIRECT_APPEND;
          end++;
        }
        if (end < state->length && state->input[end] == '&') {
          end = scan_descriptor_target(state->input, end + 1, state->length);
        }
        token->length = end - state->position;
        state->position = end;
        return true;
      }
    }
  }

  while (state->position < state->length) {
    char c = state->input[state->position];

    if (state->in_quotes) {
      if (handle_quotes(state)) {
        if (!state->in_quotes)
          break;
      } else {
        state->position++;
      }
    } else {
      if (isspace((unsigned char)c) || is_shell_operator(c)) {
        break;
      }
      state->position++;
    }
  }

  size_t token_length = state->position - start_pos;
  const char *token_text = state->input + start_pos;

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

  check_keyword(state, token_text, token_length);

  return true;
}

bool shell_tokenize_commands(const char *input, shell_command_t **commands,
                             size_t *command_count) {
  if (commands == NULL || command_count == NULL)
    return false;
  *commands = NULL;
  *command_count = 0;
  if (input == NULL)
    return false;

  shell_tokenizer_state_t state;
  shell_tokenizer_init(&state, input);

  size_t count = 0;
  bool expect_command = true;

  shell_tokenizer_state_t temp_state = state;
  shell_token_t token;

  while (shell_tokenizer_next(&temp_state, &token)) {
    if (expect_command &&
        (token.type == TOKEN_COMMAND || token.type == TOKEN_ARGUMENT ||
         token.type == TOKEN_SUBSHELL || token.type == TOKEN_VARIABLE ||
         token.type == TOKEN_VARIABLE_QUOTED ||
         token.type == TOKEN_SPECIAL_VAR || token.type == TOKEN_ARITHMETIC ||
         token.type == TOKEN_GLOB || token.type == TOKEN_HEREDOC ||
         token.type == TOKEN_HERESTRING || token.type == TOKEN_REDIRECT_IN ||
         token.type == TOKEN_REDIRECT_OUT || token.type == TOKEN_REDIRECT_ERR ||
         token.type == TOKEN_REDIRECT_APPEND ||
         token.type == TOKEN_PROCESS_SUB)) {
      count++;
      expect_command = false;
    }

    if (token.type == TOKEN_PIPE || token.type == TOKEN_SEMICOLON ||
        token.type == TOKEN_AND || token.type == TOKEN_OR) {
      expect_command = true;
    }
  }

  if (count == 0 && input != NULL && input[0] != '\0') {
    bool has_non_whitespace = false;
    size_t input_len = strlen(input);
    for (size_t i = 0; i < input_len; i++) {
      char c = input[i];
      if (isspace((unsigned char)c))
        continue;

      if (c == '&' && i + 1 < input_len &&
          (input[i + 1] == '>' || input[i + 1] == '<')) {
        i++; // skip the next char
        continue;
      }
      if (c == '<' || c == '>') {
        if (i + 1 < input_len && (input[i + 1] == '<' || input[i + 1] == '>')) {
          i++; // skip the next char
        }
        continue;
      }

      has_non_whitespace = true;
      break;
    }
    if (has_non_whitespace) {
      return false;
    }
  }

  if (count == 0) {
    return true;
  }

  if (count > SIZE_MAX / sizeof(shell_command_t))
    return false;
  *commands = malloc(count * sizeof(shell_command_t));
  if (*commands == NULL) {
    return false;
  }

  memset(*commands, 0, count * sizeof(shell_command_t));

  shell_tokenizer_init(&state, input);
  size_t current_command = 0;
  shell_command_t *current_cmd = &(*commands)[current_command];

  shell_token_t *tokens = malloc(16 * sizeof(shell_token_t));
  if (tokens == NULL) {
    free(*commands);
    *commands = NULL;
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
  current_cmd->has_loops = false;
  current_cmd->has_conditionals = false;
  current_cmd->has_case = false;

  expect_command = true;
  bool saw_loop = false;
  bool saw_conditional = false;
  bool saw_case = false;

  while (shell_tokenizer_next(&state, &token)) {
    saw_loop = saw_loop || state.loop_depth > 0;
    saw_conditional = saw_conditional || state.if_depth > 0;
    saw_case = saw_case || state.case_depth > 0;
    if (expect_command &&
        (token.type == TOKEN_COMMAND || token.type == TOKEN_ARGUMENT ||
         token.type == TOKEN_SUBSHELL || token.type == TOKEN_VARIABLE ||
         token.type == TOKEN_VARIABLE_QUOTED ||
         token.type == TOKEN_SPECIAL_VAR || token.type == TOKEN_GLOB)) {
      if (current_cmd->token_count > 0) {
        if (current_command + 1 < count) {
          current_cmd->tokens = tokens;

          current_command++;
          current_cmd = &(*commands)[current_command];
          current_cmd->start_pos = token.position;
          current_cmd->end_pos = token.position;

          tokens = malloc(16 * sizeof(shell_token_t));
          if (tokens == NULL) {
            shell_free_commands(*commands, current_command);
            *commands = NULL;
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
      if (token_capacity > SIZE_MAX / 2 ||
          token_capacity * 2 > SIZE_MAX / sizeof(shell_token_t)) {
        shell_free_commands(*commands, current_command + 1);
        *commands = NULL;
        return false;
      }
      size_t new_capacity = token_capacity * 2;
      shell_token_t *new_tokens =
          realloc(tokens, new_capacity * sizeof(shell_token_t));
      if (new_tokens == NULL) {
        shell_free_commands(*commands, current_command + 1);
        *commands = NULL;
        return false;
      }
      tokens = new_tokens;
      token_capacity = new_capacity;
      current_cmd->tokens = tokens;
    }

    current_cmd->tokens[current_cmd->token_count++] = token;

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
    case TOKEN_HEREDOC:
      if (!token.is_quoted && token_has_unescaped_dollar(&token))
        current_cmd->has_variables = true;
      break;
    default:
      break;
    }
    if (token.type == TOKEN_ARGUMENT && quoted_token_has_variable(&token))
      current_cmd->has_variables = true;

    if (token.type == TOKEN_PIPE || token.type == TOKEN_SEMICOLON ||
        token.type == TOKEN_AND || token.type == TOKEN_OR) {
      expect_command = true;
      current_cmd->end_pos = token.position + token.length;
    }
  }

  if (current_command < count) {
    (*commands)[current_command].end_pos = state.position;
    current_cmd->tokens = tokens;
  }

  // Check for unclosed quotes or braces - indicates malformed input
  // Note: We allow unclosed parentheses (paren_depth > 0) because inputs like
  // "( git" are valid shell - the unclosed paren is just shell syntax for
  // subshell start
  if (state.in_quotes || state.brace_depth > 0) {
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

  // Compound constructs normally close before tokenization finishes, so their
  // final nesting depth is zero. Preserve whether each construct occurred
  // while scanning and expose it on every command in the compound sequence.
  if (count > 0) {
    for (size_t i = 0; i < count; i++) {
      (*commands)[i].has_loops = saw_loop;
      (*commands)[i].has_conditionals = saw_conditional;
      (*commands)[i].has_case = saw_case;
    }
  }

  *command_count = count;
  return true;
}

// Free tokenized commands
void shell_free_commands(shell_command_t *commands, size_t command_count) {
  if (commands == NULL)
    return;

  for (size_t i = 0; i < command_count; i++) {
    if (commands[i].tokens != NULL) {
      free(commands[i].tokens);
    }
  }
  free(commands);
}

// Get human-readable token type name
const char *shell_token_type_name(token_type_t type) {
  switch (type) {
  case TOKEN_COMMAND:
    return "COMMAND";
  case TOKEN_ARGUMENT:
    return "ARGUMENT";
  case TOKEN_PIPE:
    return "PIPE";
  case TOKEN_REDIRECT_IN:
    return "REDIRECT_IN";
  case TOKEN_REDIRECT_OUT:
    return "REDIRECT_OUT";
  case TOKEN_REDIRECT_ERR:
    return "REDIRECT_ERR";
  case TOKEN_REDIRECT_APPEND:
    return "REDIRECT_APPEND";
  case TOKEN_SEMICOLON:
    return "SEMICOLON";
  case TOKEN_AND:
    return "AND";
  case TOKEN_OR:
    return "OR";
  case TOKEN_SUBSHELL_START:
    return "SUBSHELL_START";
  case TOKEN_SUBSHELL_END:
    return "SUBSHELL_END";
  case TOKEN_VARIABLE:
    return "VARIABLE";
  case TOKEN_VARIABLE_QUOTED:
    return "VARIABLE_QUOTED";
  case TOKEN_SPECIAL_VAR:
    return "SPECIAL_VAR";
  case TOKEN_GLOB:
    return "GLOB";
  case TOKEN_SUBSHELL:
    return "SUBSHELL";
  case TOKEN_ARITHMETIC:
    return "ARITHMETIC";
  case TOKEN_PROCESS_SUB:
    return "PROCESS_SUB";
  case TOKEN_HEREDOC:
    return "HEREDOC";
  case TOKEN_HERESTRING:
    return "HERESTRING";
  case TOKEN_END:
    return "END";
  default:
    return "UNKNOWN";
  }
}

// Check if command has shell scripting features
bool shell_has_features(shell_command_t *command) {
  if (command == NULL)
    return false;
  return command->has_variables || command->has_globs ||
         command->has_subshells || command->has_arithmetic;
}
