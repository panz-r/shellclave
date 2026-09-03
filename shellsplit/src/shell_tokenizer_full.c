#include "shell_tokenizer_full.h"
#include "alloc.h"
#include "shell_source_internal.h"
#include "shell_tokenizer_full_internal.h"
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* The tokenizer consumes textual shell input, not arbitrary binary.  Keep C
 * whitespace as valid separators, but reject all other control bytes, DEL,
 * and raw high bytes before a partial token stream can be exposed. */
static bool contains_invalid_shell_byte(const char *input, size_t length) {
  for (size_t i = 0; i < length; i++) {
    unsigned char byte = (unsigned char)input[i];
    if (byte == '\0' || (byte < 0x20 && !isspace(byte)) || byte == 0x7F ||
        byte >= 0x80)
      return true;
  }
  return false;
}

static size_t skip_parameter_expansion(const char *input, size_t length,
                                       size_t position) {
  size_t depth = 1;
  for (position += 2; position < length && depth > 0; position++) {
    char c = input[position];
    if (c == '\\' && position + 1 < length) {
      position++;
    } else if (c == '\'' || c == '"') {
      position = shell_source_skip_quoted_text(input, length, position, c) - 1;
    } else if (c == '{') {
      depth++;
    } else if (c == '}') {
      depth--;
    }
  }
  return position;
}

static size_t compound_list_segment_start(const char *input, size_t end) {
  size_t start = 0;
  char quote = 0;
  for (size_t position = 0; position < end; position++) {
    char c = input[position];
    if (quote != 0) {
      if (c == '\\' && quote == '"' && position + 1 < end) {
        position++;
      } else if (c == quote) {
        quote = 0;
      }
      continue;
    }
    if (c == '\\' && position + 1 < end) {
      position++;
      continue;
    }
    /* A process-substitution operand belongs to the preceding redirect. Its
     * parentheses are not compound-list separators while locating a later
     * brace-group prefix. */
    if ((c == '<' || c == '>') && position + 1 < end &&
        input[position + 1] == '(') {
      position =
          shell_source_skip_balanced_parentheses(input, end, position + 1) - 1;
      continue;
    }
    size_t redirect = shell_source_skip_redirect(input, position, end);
    if (redirect > position) {
      position = redirect - 1;
      continue;
    }
    if (c == '\'' || c == '"') {
      quote = c;
      continue;
    }
    if (c == ';' || c == '|' || c == '&' || c == '(' || c == '\n' || c == '\r')
      start = position + 1;
  }
  return start;
}

static bool brace_follows_redirect_list(const char *input, size_t end) {
  return shell_source_redirect_list_before_group(
      input, compound_list_segment_start(input, end), end);
}

/* A closing brace is a reserved word only when it is separated from adjacent
 * shell words. Keep word-shaped text such as `}suffix` opaque to the group
 * stack, while recognizing group trailing redirections (`}2>out`). */
static bool brace_group_close_delimiter(const char *input, size_t length,
                                        size_t position, char before,
                                        bool newline_separator) {
  if (before != ';' && before != ')' && !newline_separator)
    return false;
  if (position + 1 == length)
    return true;
  char after = input[position + 1];
  if (isspace((unsigned char)after) || after == ';' || after == '|' ||
      after == '&' || after == ')' || after == '<' || after == '>')
    return true;
  if (!isdigit((unsigned char)after))
    return false;
  size_t cursor = position + 1;
  while (cursor < length && isdigit((unsigned char)input[cursor]))
    cursor++;
  return cursor < length && (input[cursor] == '<' || input[cursor] == '>');
}

/* Validate POSIX brace-group delimiters before allocating token arrays. Shell
 * expansions, substitutions, comments, and heredoc bodies are opaque here:
 * their delimiters must not affect the surrounding compound-list stack. */
static bool brace_groups_valid(const char *input, size_t length) {
  uint8_t stack[SHELL_MAX_SUBCOMMANDS];
  size_t depth = 0;
  bool saw_brace = false;
  shell_source_pending_heredoc_t pending[SHELL_SOURCE_MAX_PENDING_HEREDOCS];
  size_t pending_count = 0;
  for (size_t i = 0; i < length; i++) {
    char c = input[i];
    if (c == '\n' && pending_count > 0) {
      size_t after = length;
      /* This remains a lexical validator: an incomplete document leaves its
       * body opaque through EOF, while strict higher-level APIs reject the
       * same input through their fast-parser pass. */
      (void)shell_source_skip_pending_heredoc_bodies(
          input, length, i + 1, pending, pending_count, &after);
      pending_count = 0;
      if (after == 0)
        return false;
      i = after - 1;
      continue;
    }
    if (c == '\'' || c == '"') {
      i = shell_source_skip_quoted_text(input, length, i, c) - 1;
      continue;
    }
    if (c == '\\' && i + 1 < length) {
      i++;
      continue;
    }
    if (c == '#' && shell_source_comment_starts(input, length, i)) {
      size_t line_end = shell_source_line_end(input, length, i);
      if (line_end == length)
        break;
      /* Leave the physical newline visible so pending heredocs declared
       * before the comment begin at the right body line. */
      i = line_end - 1;
      continue;
    }
    if (c == '`') {
      i = shell_source_skip_quoted_text(input, length, i, '`') - 1;
      continue;
    }
    if (c == '$' && i + 1 < length && input[i + 1] == '{') {
      i = skip_parameter_expansion(input, length, i) - 1;
      continue;
    }
    if (c == '$' && i + 1 < length && input[i + 1] == '(') {
      i = shell_source_skip_balanced_parentheses(input, length, i + 1) - 1;
      continue;
    }
    /* Process substitutions are shell words whose parentheses are opaque to
     * the surrounding compound-list stack, just like command substitutions.
     * Skipping both delimiters together avoids treating their closing ')'
     * as an unmatched subshell group inside a brace group. */
    if ((c == '<' || c == '>') && i + 1 < length && input[i + 1] == '(') {
      i = shell_source_skip_balanced_parentheses(input, length, i + 1) - 1;
      continue;
    }
    if (c == '<' && i + 2 < length && input[i + 1] == '<' &&
        input[i + 2] == '<') {
      /* Here-strings have a shell word operand but no deferred body. Treat
       * the complete operator atomically so its latter `<<` is never queued
       * as a heredoc declaration. */
      i += 2;
      continue;
    }
    if (c == '<' && i + 1 < length && input[i + 1] == '<') {
      if (pending_count == sizeof(pending) / sizeof(pending[0]))
        return false;
      size_t delimiter = i + 2;
      size_t line_end = shell_source_line_end(input, length, i);
      if (!shell_source_parse_heredoc_delimiter(input, line_end, &delimiter,
                                                &pending[pending_count]))
        return false;
      pending_count++;
      i = delimiter - 1;
      continue;
    }
    size_t previous = i;
    bool newline_separator = false;
    while (previous > 0 && isspace((unsigned char)input[previous - 1])) {
      newline_separator = newline_separator || input[previous - 1] == '\n' ||
                          input[previous - 1] == '\r';
      previous--;
    }
    char before = previous ? input[previous - 1] : '\0';
    bool command_boundary = previous == 0 || before == ';' || before == '|' ||
                            before == '&' || before == '(' || before == '{' ||
                            brace_follows_redirect_list(input, previous);
    bool closing_brace =
        c == '}' && brace_group_close_delimiter(input, length, i, before,
                                                newline_separator);
    bool duplicate_brace_close =
        c == '}' && saw_brace && depth == 0 && before == '}';
    if (c == '{' && command_boundary && i + 1 < length &&
        (isspace((unsigned char)input[i + 1]) || input[i + 1] == '(')) {
      if (depth == SHELL_MAX_SUBCOMMANDS)
        return false;
      stack[depth++] = SHELL_GROUP_BRACE;
      saw_brace = true;
    } else if (c == '(' &&
               !(i > 0 && (input[i - 1] == '$' || input[i - 1] == '<' ||
                           input[i - 1] == '>'))) {
      if (depth < SHELL_MAX_SUBCOMMANDS)
        stack[depth++] = SHELL_GROUP_SUBSHELL;
    } else if (closing_brace || duplicate_brace_close) {
      if (depth == 0) {
        /* A second reserved closing delimiter immediately after a completed
         * brace group is not an ordinary word. Keep the full tokenizer in
         * step with strict parsing rather than accepting a partial group. */
        if (duplicate_brace_close)
          return false;
        continue;
      }
      /* A reserved brace cannot close an ordinary parenthesized group. This
       * is distinct from a literal `}` embedded in an argument. */
      if (stack[depth - 1] != SHELL_GROUP_BRACE)
        return false;
      depth--;
    } else if (c == ')' && depth > 0) {
      if (stack[depth - 1] != SHELL_GROUP_SUBSHELL)
        return false;
      depth--;
    }
  }
  return !saw_brace || depth == 0;
}

bool shell_tokenizer_init(shell_tokenizer_state_t *state, const char *input,
                          size_t input_length) {
  if (state == NULL)
    return false;

  memset(state, 0, sizeof(*state));
  state->input = input ? input : "";
  if ((!input && input_length != 0) ||
      contains_invalid_shell_byte(state->input, input_length))
    return false;
  state->length = input_length;
  return true;
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
         c == ')' || c == '{' || c == '}' || c == '$' || c == '`' || c == '[';
}

static bool is_brace_group_delimiter(const shell_tokenizer_state_t *state,
                                     bool opening) {
  size_t p = state->position;
  if (p >= state->length)
    return false;
  if (opening) {
    if (p + 1 >= state->length ||
        (!isspace((unsigned char)state->input[p + 1]) &&
         state->input[p + 1] != '('))
      return false;
    size_t previous = p;
    while (previous > 0 && isspace((unsigned char)state->input[previous - 1]))
      previous--;
    if (previous > 0) {
      char before = state->input[previous - 1];
      if (before != ';' && before != '|' && before != '&' && before != '(' &&
          before != '{' && !brace_follows_redirect_list(state->input, previous))
        return false;
    }
  } else if (state->brace_group_depth == 0) {
    return false;
  }
  if (!opening && p > 0) {
    char before = state->input[p - 1];
    if (!isspace((unsigned char)before) && before != ';' && before != '\n' &&
        before != '\r' && before != '|' && before != '&' && before != '(' &&
        before != ')')
      return false;
  }
  if (p + 1 == state->length)
    return true;
  char after = state->input[p + 1];
  if (isspace((unsigned char)after) || (opening && after == '(') ||
      after == ';' || after == '|' || after == '&' || after == ')')
    return true;
  if (!opening && (after == '<' || after == '>'))
    return true;
  if (!opening && isdigit((unsigned char)after)) {
    size_t cursor = 0;
    uint32_t descriptor = 0;
    return shell_source_parse_io_number(state->input, p + 1, state->length,
                                        &cursor, &descriptor) ==
               SHELL_SOURCE_IO_NUMBER_VALID &&
           cursor < state->length &&
           (state->input[cursor] == '<' || state->input[cursor] == '>');
  }
  return false;
}

static size_t
shell_tokenizer_group_depth(const shell_tokenizer_state_t *state) {
  return (size_t)state->paren_depth + (size_t)state->brace_group_depth;
}

static void shell_token_set_group_context(shell_token_t *token,
                                          size_t group_depth,
                                          uint8_t group_kinds) {
  token->group_depth = group_depth;
  token->group_kinds = group_kinds;
}

static bool
shell_token_return_current_group_context(const shell_tokenizer_state_t *state,
                                         shell_token_t *token) {
  shell_token_set_group_context(token, shell_tokenizer_group_depth(state),
                                state->group_kinds);
  return true;
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
        token->type =
            is_quoted ? SHELL_TOKEN_VARIABLE_QUOTED : SHELL_TOKEN_VARIABLE;
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
      token->type =
          is_quoted ? SHELL_TOKEN_VARIABLE_QUOTED : SHELL_TOKEN_SPECIAL_VAR;
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
    token->type =
        is_quoted ? SHELL_TOKEN_VARIABLE_QUOTED : SHELL_TOKEN_VARIABLE;
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

  size_t position = 0;
  if (!shell_source_find_balanced_parentheses(state->input, state->length,
                                              start_pos + 1, &position))
    return false;

  token->type = SHELL_TOKEN_PROCESS_SUB;
  token->start = state->input + start_pos;
  token->length = position - start_pos;
  token->position = start_pos;
  token->is_quoted = is_quoted;
  token->is_escaped = false;
  state->position = position;
  return true;
}

static bool skip_pending_heredocs(shell_tokenizer_state_t *state) {
  shell_source_pending_heredoc_t pending[SHELL_MAX_SUBCOMMANDS];
  for (size_t h = 0; h < state->pending_heredoc_count; h++) {
    const shell_pending_heredoc_t *raw = &state->pending_heredocs[h];
    pending[h] = (shell_source_pending_heredoc_t){
        .word = state->input + raw->delimiter_position,
        .word_length = raw->delimiter_length,
        .strip_tabs = raw->strip_tabs,
    };
  }
  size_t after = state->length;
  if (!shell_source_skip_pending_heredoc_bodies(
          state->input, state->length, state->position, pending,
          state->pending_heredoc_count, &after)) {
    /* Keep the non-strict EOF behavior shared by the existing fast parser:
     * an unterminated heredoc consumes the remaining source as data. */
    state->position = state->length;
    state->pending_heredoc_count = 0;
    return true;
  }
  state->position = after;
  state->pending_heredoc_count = 0;
  return true;
}

static bool parse_heredoc(shell_tokenizer_state_t *state, shell_token_t *token,
                          size_t start_pos, bool is_quoted) {
  if (start_pos + 1 >= state->length || state->input[start_pos + 1] != '<' ||
      (start_pos + 2 < state->length && state->input[start_pos + 2] == '<'))
    return false;

  size_t position = start_pos + 2;
  shell_source_pending_heredoc_t parsed = {0};
  bool delimiter_valid = shell_source_parse_heredoc_delimiter(
      state->input, state->length, &position, &parsed);
  token->type = SHELL_TOKEN_HEREDOC;
  token->start = state->input + start_pos;
  token->length = position - start_pos;
  token->position = start_pos;
  token->is_quoted =
      is_quoted ||
      (delimiter_valid && shell_source_heredoc_delimiter_is_quoted(&parsed));
  token->is_escaped = false;
  if (!delimiter_valid ||
      state->pending_heredoc_count >= SHELL_MAX_SUBCOMMANDS) {
    state->heredoc_error = true;
  } else {
    shell_pending_heredoc_t *pending =
        &state->pending_heredocs[state->pending_heredoc_count++];
    pending->delimiter_position = (size_t)(parsed.word - state->input);
    pending->delimiter_length = parsed.word_length;
    pending->strip_tabs = parsed.strip_tabs;
  }
  state->position = position;
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
    size_t after = 0;
    if (!shell_source_find_balanced_parentheses(state->input, state->length,
                                                state->position + 1, &after)) {
      /* The allocating lexer retains incomplete words for diagnostics. Keep
       * the whole unfinished substitution as one ordinary token; strict
       * processor and graph APIs reject it before producing canonical data. */
      token->type = SHELL_TOKEN_ARGUMENT;
      token->start = state->input + start;
      token->length = state->length - start;
      token->position = start;
      token->is_quoted = is_quoted;
      token->is_escaped = false;
      state->position = state->length;
      return true;
    }
    token->type = SHELL_TOKEN_SUBSHELL;
    token->start = state->input + start;
    token->length = after - start;
    token->position = start;
    token->is_quoted = is_quoted;
    token->is_escaped = false;
    state->position = after;
    return true;
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
        token->type = SHELL_TOKEN_SUBSHELL;
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
  size_t after = 0;
  uint32_t descriptor = 0;
  return shell_source_parse_io_number(input, position, length, &after,
                                      &descriptor) ==
                 SHELL_SOURCE_IO_NUMBER_VALID
             ? after
             : position;
}

bool shell_tokenizer_next(shell_tokenizer_state_t *state,
                          shell_token_t *token) {
  if (token == NULL)
    return false;

  memset(token, 0, sizeof(*token));
  token->type = SHELL_TOKEN_END;
  if (state == NULL || state->input == NULL ||
      state->position >= state->length) {
    return false;
  }

  for (;;) {
    if (state->position >= state->length)
      return false;
    if (!state->in_quotes && (state->input[state->position] == '\n' ||
                              state->input[state->position] == '\r')) {
      size_t newline = state->position++;
      if (state->input[newline] == '\r' && state->position < state->length &&
          state->input[state->position] == '\n')
        state->position++;
      size_t newline_length = state->position - newline;
      if (state->pending_heredoc_count != 0)
        (void)skip_pending_heredocs(state);
      token->type = SHELL_TOKEN_SEMICOLON;
      token->start = state->input + newline;
      token->length = newline_length;
      token->position = newline;
      return shell_token_return_current_group_context(state, token);
    }
    skip_whitespace(state);
    if (state->position >= state->length)
      return false;
    if (!state->in_quotes &&
        shell_source_comment_starts(state->input, state->length,
                                    state->position)) {
      while (state->position < state->length &&
             state->input[state->position] != '\n' &&
             state->input[state->position] != '\r')
        state->position++;
      continue;
    }
    break;
  }

  size_t start_pos = state->position;
  char current_char = state->input[start_pos];
  bool is_quoted = state->in_quotes;
  bool word_had_quotes = false;

  // Invalid bytes are rejected before tokenization, so this tokenizer never
  // yields a partial stream for malformed byte sequences.

  // Handle quotes first
  char opening_quote = current_char;
  bool escaped_substitution = !state->in_quotes && current_char == '\\' &&
                              state->position + 2 < state->length &&
                              state->input[state->position + 1] == '$' &&
                              state->input[state->position + 2] == '(';
  if (!escaped_substitution && handle_quotes(state)) {
    word_had_quotes = true;
    if (state->in_quotes) {
      while (state->position < state->length) {
        if (handle_quotes(state)) {
          if (!state->in_quotes)
            break;
        } else {
          state->position++;
        }
      }

      if (state->position == state->length ||
          isspace((unsigned char)state->input[state->position]) ||
          is_shell_operator(state->input[state->position])) {
        token->type = SHELL_TOKEN_ARGUMENT;
        token->start = state->input + start_pos;
        token->length = state->position - start_pos;
        token->position = start_pos;
        token->is_quoted = true;
        token->is_escaped = false;
        /* Variables expand anywhere inside double quotes. Classifying the
         * whole shell word as variable-bearing lets downstream transformation
         * remain conservative without splitting one argument into several. */
        if (opening_quote == '"' && quoted_token_has_variable(token))
          token->type = SHELL_TOKEN_VARIABLE_QUOTED;
        return shell_token_return_current_group_context(state, token);
      }
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
        return shell_token_return_current_group_context(state, token);
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
        token->type = SHELL_TOKEN_ARITHMETIC;
        token->start = state->input + start;
        token->length = state->position - start;
        token->position = start;
        token->is_quoted = false;
        token->is_escaped = false;
        state->arith_depth = saved_arith_depth;
        state->in_arithmetic = saved_in_arithmetic;
        return shell_token_return_current_group_context(state, token);
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
        return shell_token_return_current_group_context(state, token);
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
      return shell_token_return_current_group_context(state, token);
    }
    current_char = state->input[state->position];
  }

  // Check for shell operators
  if (!state->in_quotes && (current_char == '{' || current_char == '}') &&
      !is_brace_group_delimiter(state, current_char == '{')) {
    /* Braces outside reserved-word positions are ordinary word bytes. */
  } else if (!state->in_quotes && is_shell_operator(current_char)) {
    if (state->position + 1 < state->length) {
      char next_char = state->input[state->position + 1];

      if (current_char == '|' && next_char == '|') {
        token->type = SHELL_TOKEN_OR;
        token->start = state->input + state->position;
        token->length = 2;
        token->position = state->position;
        token->is_quoted = false;
        token->is_escaped = false;
        state->position += 2;
        return shell_token_return_current_group_context(state, token);
      } else if (current_char == '&' && next_char == '&') {
        token->type = SHELL_TOKEN_AND;
        token->start = state->input + state->position;
        token->length = 2;
        token->position = state->position;
        token->is_quoted = false;
        token->is_escaped = false;
        state->position += 2;
        return shell_token_return_current_group_context(state, token);
      } else if (current_char == '>' && next_char == '>') {
        token->type = SHELL_TOKEN_REDIRECT_APPEND;
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
        return shell_token_return_current_group_context(state, token);
      } else if (current_char == '>' && next_char == '&') {
        token->type = SHELL_TOKEN_REDIRECT_ERR;
        token->start = state->input + state->position;
        token->length = 2;
        token->position = state->position;
        token->is_quoted = false;
        token->is_escaped = false;
        state->position += 2;
        state->position = scan_descriptor_target(state->input, state->position,
                                                 state->length);
        token->length = state->position - token->position;
        return shell_token_return_current_group_context(state, token);
      } else if (current_char == '>' && next_char == '|') {
        token->type = SHELL_TOKEN_REDIRECT_CLOBBER;
        token->start = state->input + state->position;
        token->length = 2;
        token->position = state->position;
        token->is_quoted = false;
        token->is_escaped = false;
        state->position += 2;
        return shell_token_return_current_group_context(state, token);
      } else if (current_char == '<' && next_char == '>') {
        token->type = SHELL_TOKEN_REDIRECT_READ_WRITE;
        token->start = state->input + state->position;
        token->length = 2;
        token->position = state->position;
        token->is_quoted = false;
        token->is_escaped = false;
        state->position += 2;
        return shell_token_return_current_group_context(state, token);
      }
    }

    size_t token_group_depth = shell_tokenizer_group_depth(state);
    uint8_t token_group_kinds = state->group_kinds;
    switch (current_char) {
    case '|':
      token->type = SHELL_TOKEN_PIPE;
      break;
    case '>':
      if (parse_process_substitution(state, token, start_pos, is_quoted))
        return shell_token_return_current_group_context(state, token);
      token->type = SHELL_TOKEN_REDIRECT_OUT;
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
          token->type = SHELL_TOKEN_HERESTRING;
          token->start = state->input + start_pos;
          token->length = 3;
          token->position = start_pos;
          token->is_quoted = is_quoted;
          token->is_escaped = false;
          state->position++;
          return shell_token_return_current_group_context(state, token);
        }

        if (parse_heredoc(state, token, start_pos, is_quoted))
          return shell_token_return_current_group_context(state, token);

        if (parse_process_substitution(state, token, start_pos, is_quoted))
          return shell_token_return_current_group_context(state, token);
      }
      token->type = SHELL_TOKEN_REDIRECT_IN;
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
        return shell_token_return_current_group_context(state, token);
      }
      break;
    case '&':
      token->type = SHELL_TOKEN_BACKGROUND;
      break;
    case ';':
      token->type = SHELL_TOKEN_SEMICOLON;
      break;
    case '(':
      token->type = SHELL_TOKEN_GROUP_START;
      state->paren_depth++;
      state->in_subshell = true;
      state->group_kinds |= SHELL_GROUP_SUBSHELL;
      token_group_depth = shell_tokenizer_group_depth(state);
      token_group_kinds = state->group_kinds;
      break;
    case '{':
      token->type = SHELL_TOKEN_GROUP_START;
      state->brace_group_depth++;
      state->group_kinds |= SHELL_GROUP_BRACE;
      token_group_depth = shell_tokenizer_group_depth(state);
      token_group_kinds = state->group_kinds;
      break;
    case '}':
      token->type = SHELL_TOKEN_GROUP_END;
      token_group_depth = shell_tokenizer_group_depth(state);
      token_group_kinds = state->group_kinds;
      state->brace_group_depth--;
      if (state->brace_group_depth == 0)
        state->group_kinds &= (uint8_t)~SHELL_GROUP_BRACE;
      break;
    case ')':
      token->type = SHELL_TOKEN_GROUP_END;
      token_group_depth = shell_tokenizer_group_depth(state);
      token_group_kinds = state->group_kinds;
      if (state->paren_depth > 0)
        state->paren_depth--;
      if (state->paren_depth == 0)
        state->in_subshell = false;
      if (state->paren_depth == 0)
        state->group_kinds &= (uint8_t)~SHELL_GROUP_SUBSHELL;
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
            token->type = SHELL_TOKEN_GLOB;
            token->start = state->input + bracket_start;
            token->length = state->position - bracket_start;
            token->position = bracket_start;
            token->is_quoted = false;
            token->is_escaped = false;
            return shell_token_return_current_group_context(state, token);
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
        token->type = SHELL_TOKEN_ARGUMENT;
        token->start = state->input + bracket_start;
        token->length = state->position - bracket_start;
        token->position = bracket_start;
        token->is_quoted = false;
        token->is_escaped = false;
        return shell_token_return_current_group_context(state, token);
      }
      token->type = SHELL_TOKEN_ARGUMENT;
      break;
    default:
      token->type = SHELL_TOKEN_ARGUMENT;
      break;
    }

    token->start = state->input + state->position;
    token->length = 1;
    token->position = state->position;
    token->is_quoted = false;
    token->is_escaped = false;
    state->position++;
    shell_token_set_group_context(token, token_group_depth, token_group_kinds);
    return true;
  }

  // Check for a descriptor followed by a redirect. Whitespace is accepted for
  // compatibility with the historical tokenizer convention (for example,
  // "2 >&1"), even though a POSIX IO number is normally adjacent to the
  // operator.
  if (!state->in_quotes && isdigit((unsigned char)current_char)) {
    size_t check_pos = 0;
    uint32_t descriptor = 0;
    shell_source_io_number_t io_number = shell_source_parse_io_number(
        state->input, state->position, state->length, &check_pos, &descriptor);
    if (io_number == SHELL_SOURCE_IO_NUMBER_OVERFLOW)
      goto ordinary_word;
    while (check_pos < state->length &&
           isspace((unsigned char)state->input[check_pos])) {
      check_pos++;
    }
    if (check_pos < state->length) {
      char after_digit = state->input[check_pos];
      if (after_digit == '>' || after_digit == '<') {
        token->type = after_digit == '<' ? SHELL_TOKEN_REDIRECT_IN
                                         : SHELL_TOKEN_REDIRECT_ERR;
        token->start = state->input + state->position;
        token->position = state->position;
        token->is_quoted = false;
        token->is_escaped = false;

        size_t end = check_pos + 1;
        if (after_digit == '>' && end < state->length &&
            state->input[end] == '>') {
          token->type = SHELL_TOKEN_REDIRECT_APPEND;
          end++;
        } else if (after_digit == '>' && end < state->length &&
                   state->input[end] == '|') {
          token->type = SHELL_TOKEN_REDIRECT_CLOBBER;
          end++;
        } else if (after_digit == '<' && end < state->length &&
                   state->input[end] == '>') {
          token->type = SHELL_TOKEN_REDIRECT_READ_WRITE;
          end++;
        }
        if (end < state->length && state->input[end] == '&') {
          end = scan_descriptor_target(state->input, end + 1, state->length);
        }
        token->length = end - state->position;
        state->position = end;
        return shell_token_return_current_group_context(state, token);
      }
    }
  }

ordinary_word:
  while (state->position < state->length) {
    char c = state->input[state->position];

    if (state->in_quotes) {
      if (handle_quotes(state)) {
        continue;
      } else {
        state->position++;
      }
    } else {
      if (c == '\\' && state->position + 1 < state->length) {
        /* An escaped '$' disarms command substitution as a whole.  Continue
         * across its balanced parentheses so a literal `\\$(name)` remains
         * one shell word instead of exposing a spurious subshell group. */
        if (state->input[state->position + 1] == '$' &&
            state->position + 2 < state->length &&
            state->input[state->position + 2] == '(') {
          state->position = shell_source_skip_balanced_parentheses(
              state->input, state->length, state->position + 2);
          continue;
        }
        state->position += 2;
        continue;
      }
      if (c == '\'' || c == '"') {
        word_had_quotes = true;
        (void)handle_quotes(state);
        continue;
      }
      if (isspace((unsigned char)c) ||
          (is_shell_operator(c) && c != '{' && c != '}')) {
        break;
      }
      state->position++;
    }
  }

  size_t token_length = state->position - start_pos;
  const char *token_text = state->input + start_pos;

  if (is_glob_pattern(token_text, token_length)) {
    token->type = SHELL_TOKEN_GLOB;
  } else {
    token->type = SHELL_TOKEN_COMMAND;
    for (size_t i = 0; i < start_pos; i++) {
      if (state->input[i] == '|' || state->input[i] == ';' ||
          state->input[i] == '&') {
        token->type = SHELL_TOKEN_COMMAND;
        break;
      }
    }
  }

  token->start = state->input + start_pos;
  token->length = token_length;
  token->position = start_pos;
  token->is_quoted = word_had_quotes;
  token->is_escaped = memchr(token_text, '\\', token_length) != NULL;
  shell_token_set_group_context(token, shell_tokenizer_group_depth(state),
                                state->group_kinds);

  check_keyword(state, token_text, token_length);

  return true;
}

static bool full_token_is_redirection(const shell_token_t *token) {
  return token->type == SHELL_TOKEN_REDIRECT_IN ||
         token->type == SHELL_TOKEN_REDIRECT_OUT ||
         token->type == SHELL_TOKEN_REDIRECT_ERR ||
         token->type == SHELL_TOKEN_REDIRECT_APPEND ||
         token->type == SHELL_TOKEN_REDIRECT_READ_WRITE ||
         token->type == SHELL_TOKEN_REDIRECT_CLOBBER ||
         token->type == SHELL_TOKEN_HEREDOC ||
         token->type == SHELL_TOKEN_HERESTRING;
}

static bool full_redirection_consumes_next(const shell_token_t *token) {
  /* `>|` has no trailing '<' or '>' byte, but it still requires a pathname.
   * Keep this semantic exception explicit rather than treating the final
   * spelling byte as the complete redirect grammar. */
  if (token->type == SHELL_TOKEN_HERESTRING ||
      token->type == SHELL_TOKEN_REDIRECT_CLOBBER)
    return true;
  if (token->length == 0)
    return false;
  char last = token->start[token->length - 1];
  return last == '<' || last == '>';
}

static bool control_token_is_word(const shell_token_t *token) {
  return token->type == SHELL_TOKEN_COMMAND ||
         token->type == SHELL_TOKEN_ARGUMENT;
}

static bool control_token_is_assignment_prefix(const shell_token_t *token) {
  if (!control_token_is_word(token) || token->is_quoted || token->is_escaped ||
      token->length < 3 ||
      !(isalpha((unsigned char)token->start[0]) || token->start[0] == '_'))
    return false;

  size_t i = 1;
  while (i < token->length &&
         (isalnum((unsigned char)token->start[i]) || token->start[i] == '_'))
    i++;
  return i < token->length && token->start[i] == '=';
}

static bool control_token_starts_function_definition(const shell_token_t *token,
                                                     const char *input,
                                                     size_t input_length) {
  if (!control_token_is_word(token) || token->is_quoted || token->is_escaped ||
      token->position > input_length ||
      token->length > input_length - token->position)
    return false;

  size_t position = token->position + token->length;
  if (position + 1 >= input_length || input[position] != '(' ||
      input[position + 1] != ')')
    return false;
  /* A bare, unquoted NAME() can only introduce a function definition in
   * shell grammar.  Leave validation of the following compound command to
   * the ordinary parser; Shellsplit rejects the construct as unsupported. */
  return true;
}

static bool control_token_nested_content(const shell_token_t *token,
                                         const char **content,
                                         size_t *content_length) {
  if (!token || !content || !content_length)
    return false;
  if ((token->type == SHELL_TOKEN_SUBSHELL ||
       token->type == SHELL_TOKEN_PROCESS_SUB) &&
      token->length >= 3 &&
      ((token->start[0] == '$' || token->start[0] == '<' ||
        token->start[0] == '>') &&
       token->start[1] == '(' && token->start[token->length - 1] == ')')) {
    *content = token->start + 2;
    *content_length = token->length - 3;
    return true;
  }
  if (token->type == SHELL_TOKEN_SUBSHELL && token->length >= 2 &&
      token->start[0] == '`' && token->start[token->length - 1] == '`') {
    *content = token->start + 1;
    *content_length = token->length - 2;
    return true;
  }
  return false;
}

static shell_control_syntax_t
control_syntax_scan(const char *input, size_t input_length, uint32_t depth);

typedef enum {
  CONTROL_FRAME_IF,
  CONTROL_FRAME_LOOP,
  CONTROL_FRAME_CASE,
} control_frame_t;

typedef struct {
  control_frame_t type;
  bool body_started;
  bool case_selector_seen;
  bool misplaced_marker;
} control_frame_state_t;

static bool control_token_is(const shell_token_t *token, const char *word) {
  return control_token_is_word(token) && !token->is_quoted &&
         !token->is_escaped && token->length == strlen(word) &&
         memcmp(token->start, word, token->length) == 0;
}

/* Shellsplit does not model control-flow execution. Use the full lexical
 * tokenizer instead of raw source scans so words in comments, quoted text,
 * escapes, redirect operands, and ordinary argument positions are not
 * mistaken for reserved control words. */
shell_control_syntax_t shell_tokenizer_control_syntax(const char *input,
                                                      size_t input_length) {
  return control_syntax_scan(input, input_length, 0);
}

static shell_control_syntax_t
control_syntax_scan(const char *input, size_t input_length, uint32_t depth) {
  if (depth > 16)
    return SHELL_CONTROL_SYNTAX_INCOMPLETE;
  shell_tokenizer_state_t state;
  if (!shell_tokenizer_init(&state, input, input_length))
    return SHELL_CONTROL_SYNTAX_NONE;

  bool command_start = true;
  bool redirect_operand = false;
  bool saw_control = false;
  control_frame_state_t frames[SHELL_MAX_SUBCOMMANDS];
  size_t frame_count = 0;
  shell_token_t token;
  while (shell_tokenizer_next(&state, &token)) {
    const char *nested_content = NULL;
    size_t nested_length = 0;
    if (control_token_nested_content(&token, &nested_content, &nested_length)) {
      shell_control_syntax_t nested =
          control_syntax_scan(nested_content, nested_length, depth + 1);
      if (nested != SHELL_CONTROL_SYNTAX_NONE)
        return nested;
    }
    if (token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_SEMICOLON ||
        token.type == SHELL_TOKEN_AND || token.type == SHELL_TOKEN_OR ||
        token.type == SHELL_TOKEN_BACKGROUND) {
      command_start = true;
      redirect_operand = false;
      continue;
    }
    if (token.type == SHELL_TOKEN_GROUP_START ||
        token.type == SHELL_TOKEN_SUBSHELL_START) {
      command_start = true;
      redirect_operand = false;
      continue;
    }
    if (token.type == SHELL_TOKEN_GROUP_END ||
        token.type == SHELL_TOKEN_SUBSHELL_END) {
      command_start = false;
      redirect_operand = false;
      continue;
    }
    if (full_token_is_redirection(&token)) {
      redirect_operand = full_redirection_consumes_next(&token);
      continue;
    }
    if (redirect_operand) {
      redirect_operand = false;
      continue;
    }

    if (frame_count != 0) {
      control_frame_state_t *frame = &frames[frame_count - 1];
      if (frame->type == CONTROL_FRAME_CASE && !frame->body_started &&
          !frame->case_selector_seen) {
        /* `case WORD in` reserves its first `in` only after the selector.
         * In particular, `case in in` has `in` as both selector and marker.
         * A selector may be an expansion token rather than a plain word. */
        frame->case_selector_seen = true;
        command_start = false;
        continue;
      }
      if (frame->type == CONTROL_FRAME_CASE && !frame->body_started &&
          frame->case_selector_seen && control_token_is(&token, "in")) {
        frame->body_started = true;
        saw_control = true;
        continue;
      }
      if (!command_start) {
        if (!frame->body_started && ((frame->type == CONTROL_FRAME_IF &&
                                      (control_token_is(&token, "then") ||
                                       control_token_is(&token, "elif") ||
                                       control_token_is(&token, "else"))) ||
                                     (frame->type == CONTROL_FRAME_LOOP &&
                                      control_token_is(&token, "do"))))
          frame->misplaced_marker = true;
        continue;
      }
      if (frame->type == CONTROL_FRAME_IF &&
          (control_token_is(&token, "then") ||
           control_token_is(&token, "elif") ||
           control_token_is(&token, "else"))) {
        frame->body_started = true;
        frame->misplaced_marker = false;
        saw_control = true;
        continue;
      }
      if (frame->type == CONTROL_FRAME_LOOP && control_token_is(&token, "do")) {
        frame->body_started = true;
        frame->misplaced_marker = false;
        saw_control = true;
        continue;
      }
      if ((frame->type == CONTROL_FRAME_IF && control_token_is(&token, "fi")) ||
          (frame->type == CONTROL_FRAME_LOOP &&
           control_token_is(&token, "done")) ||
          (frame->type == CONTROL_FRAME_CASE &&
           control_token_is(&token, "esac"))) {
        frame_count--;
        saw_control = true;
        continue;
      }
    }
    if (!command_start)
      continue;

    if (control_token_starts_function_definition(&token, input, input_length) ||
        control_token_is(&token, "function"))
      return SHELL_CONTROL_SYNTAX_COMPLETE;

    control_frame_t frame;
    bool push_frame = false;
    if (control_token_is(&token, "if")) {
      frame = CONTROL_FRAME_IF;
      push_frame = true;
    } else if (control_token_is(&token, "while") ||
               control_token_is(&token, "until") ||
               control_token_is(&token, "for")) {
      frame = CONTROL_FRAME_LOOP;
      push_frame = true;
    } else if (control_token_is(&token, "case")) {
      frame = CONTROL_FRAME_CASE;
      push_frame = true;
    } else if (control_token_is(&token, "then") ||
               control_token_is(&token, "elif") ||
               control_token_is(&token, "else") ||
               control_token_is(&token, "fi") ||
               control_token_is(&token, "do") ||
               control_token_is(&token, "done") ||
               control_token_is(&token, "in") ||
               control_token_is(&token, "esac")) {
      saw_control = true;
      return SHELL_CONTROL_SYNTAX_INCOMPLETE;
    }

    if (push_frame) {
      if (frame_count == sizeof(frames) / sizeof(frames[0]))
        return SHELL_CONTROL_SYNTAX_INCOMPLETE;
      frames[frame_count++] = (control_frame_state_t){
          .type = frame,
          .body_started = false,
          .case_selector_seen = false,
          .misplaced_marker = false,
      };
      saw_control = true;
      continue;
    }
    if (!control_token_is_assignment_prefix(&token))
      command_start = false;
  }
  for (size_t i = 0; i < frame_count; i++)
    if (frames[i].body_started || frames[i].misplaced_marker)
      return SHELL_CONTROL_SYNTAX_INCOMPLETE;
  return saw_control ? SHELL_CONTROL_SYNTAX_COMPLETE
                     : SHELL_CONTROL_SYNTAX_NONE;
}

static bool full_tokens_are_redirect_prefix(const shell_token_t *tokens,
                                            size_t count) {
  bool consume_operand = false;
  bool found = false;
  for (size_t i = 0; i < count; i++) {
    if (full_token_is_redirection(&tokens[i])) {
      if (consume_operand)
        return false;
      consume_operand = full_redirection_consumes_next(&tokens[i]);
      found = true;
    } else if (consume_operand) {
      consume_operand = false;
    } else {
      return false;
    }
  }
  return found && !consume_operand;
}

static bool full_has_redirect_prefix_group(const char *input,
                                           size_t input_length) {
  shell_tokenizer_state_t state;
  if (!shell_tokenizer_init(&state, input, input_length))
    return false;

  shell_token_t prefix[16];
  size_t prefix_count = 0;
  shell_token_t token;
  while (shell_tokenizer_next(&state, &token)) {
    if (token.type == SHELL_TOKEN_GROUP_START &&
        full_tokens_are_redirect_prefix(prefix, prefix_count))
      return true;
    if (token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_SEMICOLON ||
        token.type == SHELL_TOKEN_AND || token.type == SHELL_TOKEN_OR ||
        token.type == SHELL_TOKEN_BACKGROUND) {
      prefix_count = 0;
      continue;
    }
    if (prefix_count == sizeof(prefix) / sizeof(prefix[0]))
      return false;
    prefix[prefix_count++] = token;
  }
  return false;
}

static bool full_tokens_need_redirect_operand(const shell_token_t *tokens,
                                              size_t count) {
  bool consume_operand = false;
  for (size_t i = 0; i < count; i++) {
    if (full_token_is_redirection(&tokens[i])) {
      if (consume_operand)
        return false;
      consume_operand = full_redirection_consumes_next(&tokens[i]);
    } else if (consume_operand) {
      consume_operand = false;
    }
  }
  return consume_operand;
}

/* Process substitution is a single word beginning with `<(` or `>(`.
 * A parenthesized group cannot instead be used as the whitespace-separated
 * operand of a redirection (`> (command)`): Bash rejects that spelling.
 * Detect the token boundary here so the allocating tokenizer agrees with the
 * strict fast parser rather than accepting an invalid group as a redirect
 * target. */
static bool full_has_bare_redirect_group_operand(const char *input,
                                                 size_t input_length) {
  shell_tokenizer_state_t state;
  if (!shell_tokenizer_init(&state, input, input_length))
    return false;

  shell_token_t previous = {0};
  bool have_previous = false;
  shell_token_t token;
  while (shell_tokenizer_next(&state, &token)) {
    if (token.type == SHELL_TOKEN_GROUP_START && have_previous &&
        full_token_is_redirection(&previous) &&
        full_redirection_consumes_next(&previous))
      return true;
    previous = token;
    have_previous = true;
  }
  return false;
}

static bool full_commands_append_slot(shell_command_t **commands,
                                      size_t *count) {
  if (!commands || !*commands || !count ||
      *count == SIZE_MAX / sizeof(**commands))
    return false;
  shell_command_t *grown =
      realloc(*commands, (*count + 1) * sizeof(**commands));
  if (!grown)
    return false;
  memset(&grown[*count], 0, sizeof(*grown));
  *commands = grown;
  (*count)++;
  return true;
}

shell_tokenize_status_t shell_tokenize_commands(const char *input,
                                                size_t input_length,
                                                shell_command_t **commands,
                                                size_t *command_count) {
  if (commands == NULL || command_count == NULL)
    return SHELL_TOKENIZE_EINPUT;
  *commands = NULL;
  *command_count = 0;
  if (input == NULL || contains_invalid_shell_byte(input, input_length))
    return SHELL_TOKENIZE_EINPUT;
  if (!brace_groups_valid(input, input_length))
    return SHELL_TOKENIZE_EPARSE;
  if (full_has_bare_redirect_group_operand(input, input_length))
    return SHELL_TOKENIZE_EPARSE;
  if (full_has_redirect_prefix_group(input, input_length))
    return SHELL_TOKENIZE_EPARSE;

  shell_tokenizer_state_t state;
  if (!shell_tokenizer_init(&state, input, input_length))
    return SHELL_TOKENIZE_EINPUT;

  size_t count = 0;
  bool expect_command = true;

  shell_tokenizer_state_t temp_state = state;
  shell_token_t token;

  while (shell_tokenizer_next(&temp_state, &token)) {
    /* A closing group completes the compound command even when the preceding
     * list ended in a separator. Its following redirects bind to that group;
     * they must not be counted as a new redirect-only command. */
    if (token.type == SHELL_TOKEN_GROUP_END) {
      expect_command = false;
      continue;
    }
    if (token.type == SHELL_TOKEN_GROUP_START) {
      /* A leading redirection list is structural syntax, not the first
       * simple command in its group. The following word starts the command
       * that is enclosed by this group. */
      expect_command = true;
      continue;
    }
    if (expect_command &&
        (token.type == SHELL_TOKEN_COMMAND ||
         token.type == SHELL_TOKEN_ARGUMENT ||
         token.type == SHELL_TOKEN_SUBSHELL ||
         token.type == SHELL_TOKEN_VARIABLE ||
         token.type == SHELL_TOKEN_VARIABLE_QUOTED ||
         token.type == SHELL_TOKEN_SPECIAL_VAR ||
         token.type == SHELL_TOKEN_ARITHMETIC ||
         token.type == SHELL_TOKEN_GLOB || token.type == SHELL_TOKEN_HEREDOC ||
         token.type == SHELL_TOKEN_HERESTRING ||
         token.type == SHELL_TOKEN_REDIRECT_IN ||
         token.type == SHELL_TOKEN_REDIRECT_OUT ||
         token.type == SHELL_TOKEN_REDIRECT_ERR ||
         token.type == SHELL_TOKEN_REDIRECT_APPEND ||
         token.type == SHELL_TOKEN_REDIRECT_READ_WRITE ||
         token.type == SHELL_TOKEN_REDIRECT_CLOBBER ||
         token.type == SHELL_TOKEN_PROCESS_SUB)) {
      count++;
      expect_command = false;
    }

    if (token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_SEMICOLON ||
        token.type == SHELL_TOKEN_AND || token.type == SHELL_TOKEN_BACKGROUND ||
        token.type == SHELL_TOKEN_OR) {
      expect_command = true;
    }
  }

  if (count == 0 && input_length != 0) {
    bool has_non_whitespace = false;
    size_t input_len = input_length;
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
      return SHELL_TOKENIZE_EPARSE;
    }
  }

  if (count == 0) {
    return SHELL_TOKENIZE_OK;
  }

  if (count > SIZE_MAX / sizeof(shell_command_t))
    return SHELL_TOKENIZE_EOVERFLOW;
  *commands = malloc(count * sizeof(shell_command_t));
  if (*commands == NULL) {
    return SHELL_TOKENIZE_ENOMEM;
  }

  memset(*commands, 0, count * sizeof(shell_command_t));

  if (!shell_tokenizer_init(&state, input, input_length))
    return SHELL_TOKENIZE_EINPUT;
  size_t current_command = 0;
  shell_command_t *current_cmd = &(*commands)[current_command];

  shell_token_t *tokens = malloc(16 * sizeof(shell_token_t));
  if (tokens == NULL) {
    free(*commands);
    *commands = NULL;
    return SHELL_TOKENIZE_ENOMEM;
  }
  size_t token_capacity = 16;

  current_cmd->tokens = tokens;
  current_cmd->token_count = 0;
  current_cmd->start_pos = state.position;
  current_cmd->end_pos = state.position;
  current_cmd->group_depth = 0;
  current_cmd->group_kinds = SHELL_GROUP_NONE;
  current_cmd->has_variables = false;
  current_cmd->has_globs = false;
  current_cmd->has_subshells = false;
  current_cmd->has_arithmetic = false;
  current_cmd->has_loops = false;
  current_cmd->has_conditionals = false;
  current_cmd->has_case = false;
  current_cmd->has_groups = false;
  current_cmd->ends_group = false;
  current_cmd->has_background = false;

  expect_command = true;
  bool saw_loop = false;
  bool saw_conditional = false;
  bool saw_case = false;
  bool closed_group_at_end = false;

  while (shell_tokenizer_next(&state, &token)) {
    closed_group_at_end = token.type == SHELL_TOKEN_GROUP_END;
    saw_loop = saw_loop || state.loop_depth > 0;
    saw_conditional = saw_conditional || state.if_depth > 0;
    saw_case = saw_case || state.case_depth > 0;
    if (token.type == SHELL_TOKEN_GROUP_START ||
        token.type == SHELL_TOKEN_GROUP_END) {
      bool group_starts_command = token.type == SHELL_TOKEN_GROUP_START &&
                                  expect_command &&
                                  current_cmd->token_count != 0;
      if (group_starts_command) {
        if (current_command + 1 >= count) {
          if (!full_commands_append_slot(commands, &count)) {
            shell_commands_free(*commands, current_command + 1);
            *commands = NULL;
            *command_count = 0;
            return SHELL_TOKENIZE_ENOMEM;
          }
          current_cmd = &(*commands)[current_command];
        }
        current_cmd->end_pos = token.position;
        current_cmd->tokens = tokens;
        current_command++;
        current_cmd = &(*commands)[current_command];
        current_cmd->start_pos = token.position + 1;
        current_cmd->end_pos = token.position + 1;
        tokens = malloc(16 * sizeof(shell_token_t));
        if (tokens == NULL) {
          shell_commands_free(*commands, current_command);
          *commands = NULL;
          *command_count = 0;
          return SHELL_TOKENIZE_ENOMEM;
        }
        token_capacity = 16;
        current_cmd->tokens = tokens;
        current_cmd->token_count = 0;
        current_cmd->group_depth = shell_tokenizer_group_depth(&state);
        current_cmd->group_kinds = state.group_kinds;
        current_cmd->has_groups = false;
        current_cmd->ends_group = false;
        current_cmd->has_background = false;
        expect_command = true;
      }
      current_cmd->has_groups = true;
      if (token.group_depth > current_cmd->group_depth)
        current_cmd->group_depth = token.group_depth;
      current_cmd->group_kinds |= token.group_kinds;
      if (token.type == SHELL_TOKEN_GROUP_START &&
          current_cmd->token_count == 0) {
        current_cmd->start_pos = token.position + 1;
      } else if (token.type == SHELL_TOKEN_GROUP_END) {
        current_cmd->end_pos = token.position;
        current_cmd->ends_group = true;
      }
      continue;
    }
    bool redirect_operand = full_tokens_need_redirect_operand(
        current_cmd->tokens, current_cmd->token_count);
    if (expect_command && (token.type == SHELL_TOKEN_COMMAND ||
                           token.type == SHELL_TOKEN_ARGUMENT ||
                           token.type == SHELL_TOKEN_SUBSHELL ||
                           token.type == SHELL_TOKEN_VARIABLE ||
                           token.type == SHELL_TOKEN_VARIABLE_QUOTED ||
                           token.type == SHELL_TOKEN_SPECIAL_VAR ||
                           token.type == SHELL_TOKEN_GLOB)) {
      if (current_cmd->token_count > 0 && !redirect_operand) {
        bool can_split = current_command + 1 < count;
        if (!can_split && current_cmd->ends_group) {
          if (full_commands_append_slot(commands, &count)) {
            current_cmd = &(*commands)[current_command];
            can_split = true;
          } else {
            shell_commands_free(*commands, current_command + 1);
            *commands = NULL;
            *command_count = 0;
            return SHELL_TOKENIZE_ENOMEM;
          }
        }
        if (can_split) {
          current_cmd->tokens = tokens;

          current_command++;
          current_cmd = &(*commands)[current_command];
          current_cmd->start_pos = token.position;
          current_cmd->end_pos = token.position;

          tokens = malloc(16 * sizeof(shell_token_t));
          if (tokens == NULL) {
            shell_commands_free(*commands, current_command);
            *commands = NULL;
            *command_count = 0;
            return SHELL_TOKENIZE_ENOMEM;
          }
          token_capacity = 16;
          current_cmd->tokens = tokens;
          current_cmd->token_count = 0;
          current_cmd->has_variables = false;
          current_cmd->has_globs = false;
          current_cmd->has_subshells = false;
          current_cmd->has_arithmetic = false;
          current_cmd->group_depth = shell_tokenizer_group_depth(&state);
          current_cmd->group_kinds = state.group_kinds;
          current_cmd->has_groups = false;
          current_cmd->ends_group = false;
          current_cmd->has_background = false;
        }
      } else if (current_cmd->has_groups && !redirect_operand) {
        current_cmd->start_pos = token.position;
      }
      expect_command = false;
    }

    if (current_cmd->token_count >= token_capacity) {
      if (token_capacity > SIZE_MAX / 2 ||
          token_capacity * 2 > SIZE_MAX / sizeof(shell_token_t)) {
        shell_commands_free(*commands, current_command + 1);
        *commands = NULL;
        *command_count = 0;
        return SHELL_TOKENIZE_EOVERFLOW;
      }
      size_t new_capacity = token_capacity * 2;
      shell_token_t *new_tokens =
          realloc(tokens, new_capacity * sizeof(shell_token_t));
      if (new_tokens == NULL) {
        shell_commands_free(*commands, current_command + 1);
        *commands = NULL;
        *command_count = 0;
        return SHELL_TOKENIZE_ENOMEM;
      }
      tokens = new_tokens;
      token_capacity = new_capacity;
      current_cmd->tokens = tokens;
    }

    current_cmd->tokens[current_cmd->token_count++] = token;
    if (token.type == SHELL_TOKEN_COMMAND ||
        token.type == SHELL_TOKEN_ARGUMENT ||
        token.type == SHELL_TOKEN_SUBSHELL ||
        token.type == SHELL_TOKEN_VARIABLE ||
        token.type == SHELL_TOKEN_VARIABLE_QUOTED ||
        token.type == SHELL_TOKEN_SPECIAL_VAR ||
        token.type == SHELL_TOKEN_GLOB ||
        token.type == SHELL_TOKEN_ARITHMETIC ||
        token.type == SHELL_TOKEN_PROCESS_SUB)
      if (!redirect_operand)
        current_cmd->ends_group = false;

    switch (token.type) {
    case SHELL_TOKEN_VARIABLE:
    case SHELL_TOKEN_VARIABLE_QUOTED:
    case SHELL_TOKEN_SPECIAL_VAR:
      current_cmd->has_variables = true;
      break;
    case SHELL_TOKEN_GLOB:
      current_cmd->has_globs = true;
      break;
    case SHELL_TOKEN_SUBSHELL:
      current_cmd->has_subshells = true;
      break;
    case SHELL_TOKEN_GROUP_START:
    case SHELL_TOKEN_GROUP_END:
      current_cmd->has_groups = true;
      break;
    case SHELL_TOKEN_BACKGROUND:
      current_cmd->has_background = true;
      break;
    case SHELL_TOKEN_ARITHMETIC:
      current_cmd->has_arithmetic = true;
      break;
    case SHELL_TOKEN_HEREDOC:
      if (!token.is_quoted && token_has_unescaped_dollar(&token))
        current_cmd->has_variables = true;
      break;
    default:
      break;
    }
    if (token.type == SHELL_TOKEN_ARGUMENT && quoted_token_has_variable(&token))
      current_cmd->has_variables = true;

    if (token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_SEMICOLON ||
        token.type == SHELL_TOKEN_AND || token.type == SHELL_TOKEN_BACKGROUND ||
        token.type == SHELL_TOKEN_OR) {
      expect_command = true;
      current_cmd->end_pos = token.position + token.length;
    }
  }

  if (current_command < count) {
    if (!closed_group_at_end)
      (*commands)[current_command].end_pos = state.position;
    current_cmd->tokens = tokens;
  }

  /* A permissively accepted unfinished group may have allocated a new command
   * slot after a list operator (for example, `one && (`) without producing a
   * lexical token for that slot.  Do not expose that allocation as an empty
   * command record.  Earlier completed commands remain useful to diagnostic
   * callers under the tokenizer's tolerant-parenthesis contract. */
  if (current_command < count && current_cmd->token_count == 0) {
    free(current_cmd->tokens);
    current_cmd->tokens = NULL;
    count = current_command;
  }

  // Check for unclosed quotes or braces - indicates malformed input
  // Note: We allow unclosed parentheses (paren_depth > 0) because inputs like
  // "( git" are valid shell - the unclosed paren is just shell syntax for
  // subshell start
  if (state.in_quotes || state.brace_depth > 0 || state.brace_group_depth > 0 ||
      state.heredoc_error) {
    // Clean up allocated commands before returning error
    for (size_t i = 0; i < count; i++) {
      if ((*commands)[i].tokens != NULL) {
        free((*commands)[i].tokens);
      }
    }
    free(*commands);
    *commands = NULL;
    *command_count = 0;
    return SHELL_TOKENIZE_EPARSE;
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
  return SHELL_TOKENIZE_OK;
}

// Free tokenized commands
void shell_commands_free(shell_command_t *commands, size_t command_count) {
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
const char *shell_token_type_name(shell_token_type_t type) {
  switch (type) {
  case SHELL_TOKEN_COMMAND:
    return "COMMAND";
  case SHELL_TOKEN_ARGUMENT:
    return "ARGUMENT";
  case SHELL_TOKEN_PIPE:
    return "PIPE";
  case SHELL_TOKEN_REDIRECT_IN:
    return "REDIRECT_IN";
  case SHELL_TOKEN_REDIRECT_OUT:
    return "REDIRECT_OUT";
  case SHELL_TOKEN_REDIRECT_ERR:
    return "REDIRECT_ERR";
  case SHELL_TOKEN_REDIRECT_APPEND:
    return "REDIRECT_APPEND";
  case SHELL_TOKEN_REDIRECT_READ_WRITE:
    return "REDIRECT_READ_WRITE";
  case SHELL_TOKEN_REDIRECT_CLOBBER:
    return "REDIRECT_CLOBBER";
  case SHELL_TOKEN_SEMICOLON:
    return "SEMICOLON";
  case SHELL_TOKEN_AND:
    return "AND";
  case SHELL_TOKEN_BACKGROUND:
    return "BACKGROUND";
  case SHELL_TOKEN_OR:
    return "OR";
  case SHELL_TOKEN_SUBSHELL_START:
    return "SUBSHELL_START";
  case SHELL_TOKEN_SUBSHELL_END:
    return "SUBSHELL_END";
  case SHELL_TOKEN_GROUP_START:
    return "GROUP_START";
  case SHELL_TOKEN_GROUP_END:
    return "GROUP_END";
  case SHELL_TOKEN_VARIABLE:
    return "VARIABLE";
  case SHELL_TOKEN_VARIABLE_QUOTED:
    return "VARIABLE_QUOTED";
  case SHELL_TOKEN_SPECIAL_VAR:
    return "SPECIAL_VAR";
  case SHELL_TOKEN_GLOB:
    return "GLOB";
  case SHELL_TOKEN_SUBSHELL:
    return "SUBSHELL";
  case SHELL_TOKEN_ARITHMETIC:
    return "ARITHMETIC";
  case SHELL_TOKEN_PROCESS_SUB:
    return "PROCESS_SUB";
  case SHELL_TOKEN_HEREDOC:
    return "HEREDOC";
  case SHELL_TOKEN_HERESTRING:
    return "HERESTRING";
  case SHELL_TOKEN_END:
    return "END";
  default:
    return "UNKNOWN";
  }
}

// Check if command has shell scripting features
bool shell_command_has_shell_features(const shell_command_t *command) {
  if (command == NULL)
    return false;
  return command->has_variables || command->has_globs ||
         command->has_subshells || command->has_arithmetic;
}
