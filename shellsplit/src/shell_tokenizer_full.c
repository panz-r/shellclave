#include "shell_tokenizer_full.h"
#include "alloc.h"
#include "shell_arithmetic_internal.h"
#include "shell_ascii.h"
#include "shell_builtin_internal.h"
#include "shell_conditional_internal.h"
#include "shell_keywords_internal.h"
#include "shell_source_admission_internal.h"
#include "shell_source_draft_internal.h"
#include "shell_source_internal.h"
#include "shell_tokenizer_full_internal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static SHELL_NONNULL(1) bool arithmetic_has_unsupported_semantics(
    const char *input, size_t length);
static _Thread_local shell_semantic_token_observer_t semantic_token_observer;
static _Thread_local shell_semantic_read_fd_observer_t
    semantic_read_fd_observer;
static _Thread_local shell_semantic_process_observer_t
    semantic_process_observer;
static _Thread_local void *semantic_token_context;

static bool unsupported_semantics_scan(const char *input, size_t input_length,
                                       bool parenthesized_substitution);
static SHELL_NONNULL(1) bool unsupported_semantics_scan_impl(
    const char *input, size_t input_length, bool parenthesized_substitution);

void shell_tokenizer_arithmetic_content(const shell_token_t *token,
                                        bool complete, const char **content,
                                        size_t *content_length) {
  size_t open = shell_source_logical_following(token->start, token->length, 0);
  if (token->type == SHELL_TOKEN_ARITHMETIC)
    open = shell_source_logical_following(token->start, token->length, open);
  size_t end = token->length;
  if (complete)
    end = token->type == SHELL_TOKEN_ARITHMETIC_COMMAND
              ? end - 2
              : shell_source_skip_inline_continuations_backward(token->start,
                                                                end - 1) -
                    1;
  *content = token->start + open + 1;
  *content_length = end - open - 1;
}

/* Bash arithmetic accepts indexed and associative array references.  They do
 * not become ordinary scalar words merely because the outer lexer represents
 * the whole expression as one ARITHMETIC token, so inspect the expression
 * before canonical callers accept it. */
bool shell_tokenizer_arithmetic_has_array_semantics(const char *input,
                                                    size_t length) {
  if (!input)
    return false;
  shell_source_substitution_scan_t scan = {0};
  scan.scope.arithmetic_scope = true;
  scan.scope.suppress_process = true;
  size_t start = 0, after = 0;
  shell_source_substitution_kind_t kind = SHELL_SOURCE_SUBST_COMMAND;
  while (shell_source_next_executable_substitution(input, length, &scan, &start,
                                                   &after, &kind) ==
         SHELL_SOURCE_SCAN_FOUND) {
    size_t content_start = start + 1;
    if (kind != SHELL_SOURCE_SUBST_BACKTICK)
      content_start = shell_source_logical_following(input, length, start) + 1;
    if (unsupported_semantics_scan(input + content_start,
                                   after - content_start - 1,
                                   kind != SHELL_SOURCE_SUBST_BACKTICK))
      return true;
  }
  return scan.has_arrays;
}

/* Arithmetic grammar and proof belong to the shared private analyzer. */
static SHELL_NONNULL(1) bool arithmetic_has_unsupported_semantics(
    const char *input, size_t length) {
  return !shell_arithmetic_analyze(input, length).supported;
}

static SHELL_NONNULL(1) bool substring_has_unsupported_semantics(
    const char *input, size_t length) {
  return !shell_arithmetic_substring_supported(input, length);
}

/* A closing brace is a reserved word only when it is separated from adjacent
 * shell words. Keep word-shaped text such as `}suffix` opaque to the group
 * stack, while recognizing group trailing redirections (`}2>out`). */
static bool brace_group_close_delimiter(const char *input, size_t length,
                                        size_t position, char before,
                                        bool newline_separator) {
  if (before != ';' && before != '&' && before != ')' && !newline_separator)
    return false;
  size_t after = shell_source_logical_following(input, length, position);
  if (after == length)
    return true;
  char following = input[after];
  if (shell_source_space((unsigned char)following) || following == ';' ||
      following == '|' || following == '&' || following == ')' ||
      following == '<' || following == '>')
    return true;
  if (!shell_ascii_digit((unsigned char)following))
    return false;
  size_t cursor = after;
  while (cursor < length && shell_ascii_digit((unsigned char)input[cursor]))
    cursor++;
  cursor = shell_source_skip_escaped_line_endings(input, length, cursor);
  return cursor < length && (input[cursor] == '<' || input[cursor] == '>');
}

/* Validate POSIX brace-group delimiters before allocating token arrays.
 * Control/function syntax has already taken its separate diagnostic path.
 * Expansions, substitutions, comments, and heredoc bodies are opaque here:
 * their delimiters must not affect the surrounding compound-list stack. */
static bool brace_groups_valid(const char *input, size_t length) {
  uint8_t stack[SHELL_MAX_SUBCOMMANDS];
  size_t depth = 0;
  bool saw_brace = false;
  bool context_possible = true;
  shell_tokenizer_state_t lexical;
  shell_tokenizer_init_prechecked(&lexical, input, length);
  shell_token_t lexical_token = {0};
  bool have_lexical_token = false;
  shell_source_pending_heredoc_t pending[SHELL_SOURCE_MAX_PENDING_HEREDOCS];
  size_t pending_count = 0;
  bool word_boundary = true;
  for (size_t i = 0; i < length; i++) {
    char c = input[i];
    bool starts_word = word_boundary;
    word_boundary = shell_source_word_separator(c);
    if (c == ';' || c == '|' || c == '&' || c == '\n') {
      context_possible = true;
    }
    if ((c == '\n') && pending_count > 0) {
      size_t after = length;
      /* This remains a lexical validator: an incomplete document leaves its
       * body opaque through EOF, while strict higher-level APIs reject the
       * same input through their fast-parser pass. */
      (void)shell_source_skip_pending_heredoc_bodies(
          input, length, shell_source_next_line(input, length, i), pending,
          pending_count, &after);
      pending_count = 0;
      if (after == 0)
        return false;
      i = after - 1;
      continue;
    }
    if (c == '[') {
      while (!have_lexical_token ||
             lexical_token.position + lexical_token.length <= i) {
        if (!shell_tokenizer_next(&lexical, &lexical_token))
          break;
        have_lexical_token = true;
      }
      if (have_lexical_token && lexical_token.position == i &&
          lexical_token.type == SHELL_TOKEN_CONDITIONAL_COMMAND) {
        i += lexical_token.length - 1;
        context_possible = false;
        word_boundary = false;
        continue;
      }
    }
    if (c == '(') {
      size_t content, end, after;
      if (shell_source_arithmetic_command(input, length, i, &content, &end,
                                          &after) ==
          SHELL_ARITHMETIC_FRAME_COMPLETE) {
        i = after - 1;
        context_possible = false;
        word_boundary = false;
        continue;
      }
    }
    if (c == '$' &&
        shell_source_logical_next_is(input, length, i, '\'', NULL)) {
      size_t quoted = 0;
      if (shell_source_skip_complete_ansi_c_quote(input, length, i, &quoted)) {
        i = quoted - 1;
        continue;
      }
    }
    if (c == '\'' || c == '"') {
      i = shell_source_skip_quoted_text(input, length, i, c) - 1;
      continue;
    }
    if (c == '\\' && i + 1 < length) {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, i);
      if (continued != i)
        word_boundary = starts_word;
      i = continued != i ? continued - 1 : i + 1;
      continue;
    }
    if (shell_source_comment_starts(c, starts_word)) {
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
    if (c == '$' && shell_source_logical_next_is(input, length, i, '{', NULL)) {
      size_t after = 0;
      if (!shell_source_skip_parameter_expansion(input, length, i, &after))
        return false;
      i = after - 1;
      continue;
    }
    size_t substitution_open = 0;
    if (c == '$' && shell_source_dollar_parentheses_open(input, length, i,
                                                         &substitution_open)) {
      i = shell_source_skip_balanced_parentheses(input, length,
                                                 substitution_open) -
          1;
      continue;
    }
    /* Process substitutions are shell words whose parentheses are opaque to
     * the surrounding compound-list stack, just like command substitutions.
     * Skipping both delimiters together avoids treating their closing ')'
     * as an unmatched subshell group inside a brace group. */
    if ((c == '<' || c == '>') && shell_source_process_substitution_open(
                                      input, length, i, &substitution_open)) {
      i = shell_source_skip_balanced_parentheses(input, length,
                                                 substitution_open) -
          1;
      word_boundary = false;
      continue;
    }
    size_t operator_after = 0;
    if (c == '<' && shell_source_match_logical_punctuation(
                        input, length, i, "<<<", &operator_after)) {
      /* Here-strings have a shell word operand but no deferred body. Treat
       * the complete operator atomically so its latter `<<` is never queued
       * as a heredoc declaration. */
      i = operator_after - 1;
      continue;
    }
    if (c == '<' && shell_source_match_logical_punctuation(
                        input, length, i, "<<", &operator_after)) {
      if (pending_count == sizeof(pending) / sizeof(pending[0]))
        return false;
      size_t delimiter = operator_after;
      if (!shell_source_parse_heredoc_delimiter(input, length, &delimiter,
                                                &pending[pending_count]))
        return false;
      pending_count++;
      i = delimiter - 1;
      word_boundary = false;
      continue;
    }
    /* Consume ordinary words as spans. Their literal braces are not compound
     * delimiters, and must not trigger repeated source-prefix reconstruction.
     */
    bool possible_brace_open =
        c == '{' && i + 1 < length &&
        (shell_source_space((unsigned char)input[i + 1]) ||
         input[i + 1] == '(');
    if ((c != '{' && c != '}' && c != '(' && c != ')' &&
         !shell_source_space((unsigned char)c) && !strchr("<>;|&", c)) ||
        (c == '{' && !possible_brace_open)) {
      size_t after = 0;
      if (shell_source_skip_shell_word_impl(input, length, i, &after, true) &&
          after > i)
        i = after - 1;
      continue;
    }
    if (c != '{' && c != '}' && c != '(' && c != ')')
      continue;
    size_t previous = i;
    bool newline_separator = false;
    bool continued_line = false;
    do {
      continued_line = false;
      while (previous > 0 &&
             shell_source_space((unsigned char)input[previous - 1])) {
        newline_separator = newline_separator || input[previous - 1] == '\n';
        previous--;
      }
      if (previous > 0 && input[previous - 1] == '\\' &&
          (previous < length && input[previous] == '\n')) {
        previous--;
        newline_separator = false;
        continued_line = true;
      }
    } while (continued_line);
    char before = previous ? input[previous - 1] : '\0';
    bool closing_brace =
        c == '}' && brace_group_close_delimiter(input, length, i, before,
                                                newline_separator);
    bool duplicate_brace_close =
        c == '}' && saw_brace && depth == 0 && before == '}';
    bool command_boundary =
        (possible_brace_open || closing_brace || duplicate_brace_close) &&
        context_possible &&
        (previous == 0 || newline_separator || before == ';' || before == '|' ||
         before == '&' || before == '(' || before == '{');
    if (possible_brace_open || (closing_brace && before == '&')) {
      /* Reuse forward lexical command position rather than reconstructing
       * the prefix for every literal brace after a potentially long word.
       * The iterator advances monotonically and keeps whole word spans. */
      while (!have_lexical_token ||
             lexical_token.position + lexical_token.length <= i) {
        if (!shell_tokenizer_next(&lexical, &lexical_token))
          break;
        have_lexical_token = true;
      }
      if (possible_brace_open)
        command_boundary = have_lexical_token && lexical_token.position == i &&
                           lexical_token.type == SHELL_TOKEN_GROUP_START;
      else
        /* `&` terminates a brace list, but also occurs in redirect operators.
         * Reuse the forward lexical context: a redirect pathname `}` is not
         * a reserved group closer. Binary && still fails stage validation. */
        closing_brace = have_lexical_token && lexical_token.position == i &&
                        lexical_token.type == SHELL_TOKEN_GROUP_END;
    }
    if (possible_brace_open && command_boundary && i + 1 < length &&
        (shell_source_space((unsigned char)input[i + 1]) ||
         input[i + 1] == '(')) {
      if (depth == SHELL_MAX_SUBCOMMANDS)
        return false;
      stack[depth++] = SHELL_GROUP_BRACE;
      saw_brace = true;
      context_possible = true;
    } else if (c == '(' &&
               !(i > 0 && (input[i - 1] == '$' || input[i - 1] == '<' ||
                           input[i - 1] == '>'))) {
      if (depth < SHELL_MAX_SUBCOMMANDS)
        stack[depth++] = SHELL_GROUP_SUBSHELL;
      context_possible = true;
    } else if (closing_brace || duplicate_brace_close) {
      if (depth == 0) {
        /* A reserved closing delimiter cannot start a command after a list
         * operator: `echo; }` is not an argument-bearing simple command.
         * A `}` elsewhere (for example, `echo }`) remains an ordinary word.
         * Keep lexical and strict parsing aligned for a repeated closer too.
         */
        if (command_boundary || duplicate_brace_close)
          return false;
        continue;
      }
      /* A reserved brace cannot close an ordinary parenthesized group. This
       * is distinct from a literal `}` embedded in an argument. */
      if (stack[depth - 1] != SHELL_GROUP_BRACE)
        return false;
      depth--;
      context_possible = false;
    } else if (c == ')' && depth > 0) {
      if (stack[depth - 1] != SHELL_GROUP_SUBSHELL)
        return false;
      depth--;
      context_possible = false;
    } else if (possible_brace_open) {
      /* Once a would-be opener is an ordinary word, later words cannot turn
       * this same simple-command prefix back into compound syntax. */
      context_possible = false;
    }
  }
  return !saw_brace || depth == 0;
}

/* Input is a required, domain-checked span. No grammar validation is needed
 * merely to initialize or rewind an iterator over that immutable span. */
void shell_tokenizer_init_prechecked(shell_tokenizer_state_t *state,
                                     const char *input, size_t input_length) {
  memset(state, 0, sizeof(*state));
  state->input = input;
  state->length = input_length;
  state->lexical_command_position = true;
  state->lexical_prefix = LEXICAL_TIME_ALLOWED | LEXICAL_ASSIGNMENT_ALLOWED;
}

bool shell_tokenizer_init(shell_tokenizer_state_t *state, const char *input,
                          size_t input_length, const shell_limits_t *limits) {
  shell_tokenizer_init_prechecked(state, input ? input : "", 0);
  if (limits) {
    state->workspace = limits->workspace;
    state->workspace_size = limits->workspace_size;
  }
  if (!input && input_length != 0)
    return false;
  shell_source_iterator_scope_t previous =
      shell_source_iterator_begin(state->input, input_length, &state->workspace,
                                  &state->workspace_size, true);
  bool valid = shell_source_bytes_valid(state->input, input_length) &&
               !shell_source_scratch_exhausted();
  shell_source_iterator_end(previous, state->workspace, state->workspace_size);
  if (valid)
    state->length = input_length;
  return valid;
}

/* The iterator supplies a whole-word start and its redirect role. Keyword
 * identity and counter effects belong to the shared lexical classifier. */
static SHELL_NONNULL(1, 2) void check_keyword(shell_tokenizer_state_t *state,
                                              const shell_token_t *token) {
  const shell_keyword_t *keyword =
      shell_source_keyword(state->input, state->length, token->position, NULL);
  if (!keyword)
    return;
  int *depth;
  switch (keyword->depth) {
  case SHELL_KEYWORD_DEPTH_CONDITIONAL:
    depth = &state->if_depth;
    break;
  case SHELL_KEYWORD_DEPTH_LOOP:
    depth = &state->loop_depth;
    break;
  case SHELL_KEYWORD_DEPTH_CASE:
    depth = &state->case_depth;
    break;
  default:
    return;
  }
  if (keyword->delta > 0 || *depth > 0)
    *depth += keyword->delta;
}

static bool is_shell_operator(char c) {
  return c == '|' || c == '>' || c == '<' || c == '&' || c == ';' || c == '(' ||
         c == ')' || c == '{' || c == '}' || c == '$' || c == '`' || c == '[';
}

static bool token_at_word_boundary(const shell_tokenizer_state_t *state) {
  if (!state || state->position == 0)
    return true;
  char previous = state->input[state->position - 1];
  return shell_source_space((unsigned char)previous) || previous == ';' ||
         previous == '|' || previous == '&' || previous == '(' ||
         previous == '{' || previous == '}';
}

/* next() retains the end of the preceding logical word fragment. Operators
 * clear it, including compact close redirects, so adjacency after `>&-` is
 * different from adjacency after an ordinary dash in a word. */
static SHELL_NONNULL(1) bool token_starts_word(
    const shell_tokenizer_state_t *state) {
  return state->lexical_operand_end == 0 ||
         shell_source_skip_escaped_line_endings(state->input, state->length,
                                                state->lexical_operand_end) !=
             state->position;
}

typedef enum {
  ARRAY_WORD_NONE,
  ARRAY_WORD_INDEXED,
  ARRAY_WORD_COMPOUND,
  ARRAY_WORD_UNCLASSIFIED,
} array_word_t;

/* Only a leading indexed assignment can absorb unquoted subscript blanks.
 * Declaration operands retain ordinary word boundaries; their special syntax
 * is the compound-array opener, not arbitrary assignment-looking operands.
 * end owns the assignment prefix through '=' or the compound body's '('. */
static SHELL_NONNULL(1, 5) array_word_t
    array_assignment_probe(const char *input, size_t length, size_t start,
                           bool leading, size_t *end) {
  if (!(shell_ascii_alpha((unsigned char)input[start]) || input[start] == '_'))
    return ARRAY_WORD_NONE;
  size_t limit = length;
  if (!leading && !shell_source_skip_shell_word(input, length, start, &limit))
    return ARRAY_WORD_NONE;
  size_t position = shell_source_logical_following(input, length, start);
  bool indexed = false;
  while (position < length &&
         (shell_ascii_alnum((unsigned char)input[position]) ||
          input[position] == '_'))
    position = shell_source_logical_following(input, length, position);
  if (position < length && input[position] == '[') {
    indexed = true;
    size_t close = 0;
    /* A declaration's ordinary word cannot acquire its closing bracket from
     * a later operand. Avoid preparing array facts for this negative shape. */
    if (!leading && !memchr(input + position, ']', limit - position))
      return ARRAY_WORD_NONE;
    if (!shell_source_skip_array_subscript(input, limit, position, &close))
      return leading ? ARRAY_WORD_UNCLASSIFIED : ARRAY_WORD_NONE;
    position = shell_source_skip_escaped_line_endings(input, length, close);
  }
  if (position < length && input[position] == '+')
    position = shell_source_logical_following(input, length, position);
  if (position >= limit || input[position] != '=') {
    /* A final backslash can still become a removed LF before '=' or '+='.
     * Do not expose subscript parentheses as list syntax at that prefix. */
    bool pending = position == length ||
                   (position + 1 == length && input[position] == '\\');
    return leading && indexed && pending ? ARRAY_WORD_UNCLASSIFIED
                                         : ARRAY_WORD_NONE;
  }
  size_t rhs = shell_source_logical_following(input, length, position);
  if (rhs == length || input[rhs] != '(') {
    /* a[0]=value and map[key]+=value are still array syntax even though the
     * RHS is not a compound assignment. The semantic layer rejects them. */
    if (!indexed || !leading)
      return ARRAY_WORD_NONE;
    *end = position + 1;
    return ARRAY_WORD_INDEXED;
  }
  *end = rhs;
  return ARRAY_WORD_COMPOUND;
}

bool shell_tokenizer_word_end(const char *source, size_t length,
                              const shell_token_t *token, size_t *end) {
  size_t start = token->position;
  if (token->type == SHELL_TOKEN_ARRAY_ASSIGNMENT) {
    start += token->length;
    if (source[start - 1] == ')') {
      *end = start;
      return true;
    }
  }
  return shell_source_skip_shell_word(source, length, start, end);
}

static bool is_brace_group_delimiter(const shell_tokenizer_state_t *state,
                                     bool opening) {
  size_t p = state->position;
  if (p >= state->length)
    return false;
  bool operand = state->lexical_redirect_operand &&
                 (state->lexical_operand_end == 0 ||
                  shell_source_skip_escaped_line_endings(
                      state->input, p, state->lexical_operand_end) == p);
  if (!state->lexical_command_position || operand)
    return false;
  size_t following =
      shell_source_logical_following(state->input, state->length, p);
  if (opening) {
    if (following < state->length &&
        (!shell_source_space((unsigned char)state->input[following]) &&
         state->input[following] != '('))
      return false;
  } else if (state->brace_group_depth == 0) {
    return false;
  }
  if (!opening && p > 0) {
    size_t before = shell_source_skip_escaped_line_endings_backward(
        state->input, state->length, p);
    if (before == 0)
      return false;
    char preceding = state->input[before - 1];
    if (!shell_source_space((unsigned char)preceding) && preceding != ';' &&
        preceding != '|' && preceding != '&' && preceding != '(' &&
        preceding != ')')
      return false;
  }
  if (following == state->length)
    return true;
  char after = state->input[following];
  if (shell_source_space((unsigned char)after) || (opening && after == '(') ||
      after == ';' || after == '|' || after == '&' || after == ')')
    return true;
  if (!opening && (after == '<' || after == '>'))
    return true;
  if (!opening && shell_ascii_digit((unsigned char)after)) {
    size_t cursor = 0;
    uint32_t descriptor = 0;
    return shell_source_parse_io_number(state->input, following, state->length,
                                        &cursor, &descriptor) ==
               SHELL_SOURCE_IO_NUMBER_VALID &&
           (cursor = shell_source_skip_escaped_line_endings(
                state->input, state->length, cursor)) < state->length &&
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
         shell_source_blank((unsigned char)state->input[state->position])) {
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

  /* Backslashes are literal in ordinary single quotes. In double quotes,
   * only the shell's five escapable bytes suppress the next byte's syntax.
   * ANSI-C quotes are consumed by their dedicated scanner. */
  if (c == '\\' && state->position + 1 < state->length &&
      (!state->in_quotes ||
       (state->quote_char == '"' &&
        strchr("$`\"\\\n", state->input[state->position + 1])))) {
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
  state->position = shell_source_skip_escaped_line_endings(
      state->input, state->length, state->position);
  size_t parameter_start = state->position;

  if (state->position < state->length && state->input[state->position] == '{') {
    size_t after = 0;
    if (!shell_source_skip_parameter_expansion(state->input, state->length,
                                               start, &after)) {
      /* Preserve the existing final malformed-expansion check after callers
       * restore the token position. */
      state->brace_depth++;
      return false;
    }
    state->position = after;
    token->type =
        is_quoted ? SHELL_TOKEN_VARIABLE_QUOTED : SHELL_TOKEN_VARIABLE;
    token->start = state->input + start;
    token->length = state->position - start;
    token->position = start;
    token->is_quoted = is_quoted;
    token->is_escaped = false;
    return true;
  }

  if (state->position < state->length) {
    char next = state->input[state->position];
    // Handle: $0-$9, $#, $?, $$, $!, $@, $*, $-
    if (shell_ascii_digit((unsigned char)next) || next == '#' || next == '?' ||
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
    size_t continued = shell_source_skip_escaped_line_endings(
        state->input, state->length, state->position);
    if (continued != state->position) {
      state->position = continued;
      continue;
    }
    char c = state->input[state->position];
    if (!shell_ascii_alnum((unsigned char)c) && c != '_') {
      break;
    }
    state->position++;
  }

  if (state->position > parameter_start) {
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

bool shell_tokenizer_token_has_variable(const shell_token_t *token) {
  if (!token || !token->start || token->length == 0)
    return false;
  shell_source_variable_scan_t scan = {0};
  size_t start = 0, after = 0;
  return shell_source_next_variable_expansion(token->start, token->length,
                                              &scan, &start, &after);
}

static bool quoted_token_has_variable(const shell_token_t *token) {
  return token && token->is_quoted && token->length >= 2 &&
         token->start[0] == '"' && shell_tokenizer_token_has_variable(token);
}

static bool parse_process_substitution(shell_tokenizer_state_t *state,
                                       shell_token_t *token, size_t start_pos,
                                       bool is_quoted) {
  size_t open = 0;
  if (!shell_source_process_substitution_open(state->input, state->length,
                                              start_pos, &open))
    return false;

  size_t position = 0;
  if (!shell_source_find_balanced_parentheses(state->input, state->length, open,
                                              &position))
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
                          size_t start_pos, size_t operator_pos,
                          bool is_quoted) {
  size_t operator_after = 0;
  size_t here_string_after = 0;
  if (!shell_source_match_logical_punctuation(
          state->input, state->length, operator_pos, "<<", &operator_after) ||
      shell_source_match_logical_punctuation(
          state->input, state->length, operator_pos, "<<<", &here_string_after))
    return false;

  size_t position = operator_after;
  shell_source_pending_heredoc_t parsed = {0};
  shell_source_heredoc_word_status_t delimiter_status =
      shell_source_probe_heredoc_delimiter(state->input, state->length,
                                           &position, &parsed);
  bool delimiter_valid = delimiter_status == SHELL_HEREDOC_WORD_COMPLETE;
  /* An unfinished declaration is one received lexical token. Its remaining
   * quotes, parentheses and operators are delimiter data, not later command
   * grammar. In particular an open $[...] must not expose '(' as a group. */
  if (delimiter_status == SHELL_HEREDOC_WORD_INCOMPLETE)
    position = state->length;
  token->type = SHELL_TOKEN_HEREDOC;
  token->start = state->input + start_pos;
  token->length = position - start_pos;
  token->position = start_pos;
  token->is_quoted =
      is_quoted ||
      (delimiter_valid && shell_source_heredoc_delimiter_is_quoted(&parsed));
  token->is_escaped = memchr(token->start, '\\', token->length) != NULL;
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
  size_t open = 0;
  if (shell_source_dollar_parentheses_open(state->input, state->length,
                                           state->position, &open)) {
    size_t after = 0;
    if (!shell_source_find_balanced_parentheses(state->input, state->length,
                                                open, &after)) {
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
    size_t after = 0;
    if (!shell_source_skip_complete_backtick(state->input, state->length,
                                             state->position, &after))
      return false;
    token->type = SHELL_TOKEN_SUBSHELL;
    token->start = state->input + start;
    token->length = after - start;
    token->position = start;
    token->is_quoted = is_quoted;
    token->is_escaped = false;
    state->position = after;
    return true;
  }

  return false;
}

static size_t scan_descriptor_target(const char *input, size_t position,
                                     size_t length) {
  if (!input || position >= length)
    return position;
  /* A physical continuation is removed before Bash interprets a duplicate
   * target. Keep it inside the redirect token's raw span even when the target
   * is an ordinary word that remains available to the word tokenizer. */
  size_t target_start =
      shell_source_skip_escaped_line_endings(input, length, position);
  if (target_start == length)
    return position;
  /* An immediate raw dash is the lexical close marker, even when a following
   * word is adjacent: `>&-file` is `>&-` followed by argv `file`. Quoted or
   * escaped dashes still use complete-word classification below. */
  size_t close_end =
      shell_source_redirect_close_end(input, target_start, length);
  if (close_end != target_start)
    return close_end;
  /* Preserve the established compact token spelling for an exact numeric
   * target, but only after finding the complete shell word. A numeric prefix
   * in `>&123file` is a legacy combined-output pathname, so leave its operand
   * for normal word tokenization rather than splitting it into a descriptor
   * duplicate followed by argv. */
  size_t target_end =
      shell_source_skip_redirect_word(input, target_start, length);
  if (target_end == target_start)
    return position;
  size_t parsed_end = 0;
  uint32_t descriptor = 0;
  return shell_source_parse_io_number(input, target_start, target_end,
                                      &parsed_end, &descriptor) ==
                     SHELL_SOURCE_IO_NUMBER_VALID &&
                 parsed_end == target_end
             ? target_end
             : target_start;
}

/* start..operator_position is an already-recognized optional descriptor.
 * Bare, numeric and named spellings use the same operator boundary. */
static SHELL_NONNULL(1, 2) bool full_redirect_token(
    shell_tokenizer_state_t *state, shell_token_t *token, size_t start,
    size_t operator_position, bool numeric) {
  size_t after;
  bool duplicate;
  shell_token_type_t type = shell_source_redirect_operator(
      state->input, state->length, operator_position, &after, &duplicate);
  if (type == SHELL_TOKEN_HEREDOC) {
    parse_heredoc(state, token, start, operator_position, false);
    return shell_token_return_current_group_context(state, token);
  }
  if (duplicate)
    after = scan_descriptor_target(state->input, after, state->length);
  if (numeric && type == SHELL_TOKEN_REDIRECT_OUT)
    type = SHELL_TOKEN_REDIRECT_ERR;
  *token = (shell_token_t){
      .type = type,
      .start = state->input + start,
      .position = start,
      .length = after - start,
      .is_escaped = memchr(state->input + start, '\\', after - start) != NULL};
  state->position = after;
  return shell_token_return_current_group_context(state, token);
}

static SHELL_NONNULL(1, 2) bool shell_tokenizer_next_raw(
    shell_tokenizer_state_t *state, shell_token_t *token) {
  memset(token, 0, sizeof(*token));
  token->type = SHELL_TOKEN_END;
  if ((state->input == NULL) || (state->position >= state->length)) {
    return false;
  }

  for (;;) {
    if (state->position >= state->length)
      return false;
    if (!state->in_quotes && state->input[state->position] == '\n') {
      size_t newline = state->position++;
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
    /* `skip_whitespace()` also consumes horizontal space before a physical
     * line ending. Loop back so that ending is emitted as a list separator
     * rather than falling through into the word scanner. Apart from fixing
     * ordinary `word \n next` boundaries, this keeps a pending `!` from
     * silently crossing a raw newline. */
    if (!state->in_quotes && state->input[state->position] == '\n')
      continue;
    if (!state->in_quotes &&
        shell_source_comment_starts(state->input[state->position],
                                    token_starts_word(state))) {
      while (state->position < state->length &&
             state->input[state->position] != '\n') {
        SHELL_SOURCE_WORD_SCAN(1);
        state->position++;
      }
      continue;
    }
    break;
  }

  size_t start_pos = state->position;
  char current_char = state->input[start_pos];
  bool is_quoted = state->in_quotes;
  bool word_had_quotes = false;

  /* A physical line continuation at a token boundary is grammar, not the
   * prefix of the next lexical operator.  In particular, retaining its old
   * start position while recognizing a following `<<<` made one malformed
   * HERESTRING token span `\\\n<<`.  Emit the continuation by itself so the
   * list and source validators can discard it while the next call starts at
   * the real operator. Continuations embedded in an ordinary word are still
   * consumed by the word scanner below. */
  if (!state->in_quotes && current_char == '\\' &&
      start_pos + 1 < state->length && state->input[start_pos + 1] == '\n') {
    state->position = start_pos + 2;
    token->type = SHELL_TOKEN_ARGUMENT;
    token->start = state->input + start_pos;
    token->length = state->position - start_pos;
    token->position = start_pos;
    token->is_quoted = false;
    token->is_escaped = true;
    return shell_token_return_current_group_context(state, token);
  }

  // Invalid bytes are rejected before tokenization, so this tokenizer never
  // yields a partial stream for malformed byte sequences.

  // Handle quotes first
  char opening_quote = current_char;
  if (handle_quotes(state)) {
    word_had_quotes = true;
    if (state->in_quotes) {
      while (state->position < state->length) {
        SHELL_SOURCE_WORD_SCAN(1);
        if (state->quote_char == '"' &&
            (state->input[state->position] == '$' ||
             state->input[state->position] == '`')) {
          size_t after = 0;
          bool recognized = false;
          if (shell_source_skip_double_quote_expansion(
                  state->input, state->length, state->position, &recognized,
                  &after) &&
              recognized) {
            state->position = after;
            continue;
          }
        }
        if (handle_quotes(state)) {
          if (!state->in_quotes)
            break;
        } else {
          state->position++;
        }
      }

      if (state->position == state->length ||
          shell_source_space((unsigned char)state->input[state->position]) ||
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
    if (state->position >= state->length) {
      /* A final escaped byte is a complete literal word. In particular,
       * bounded recursive parses may end at `\\)`, whose closing parenthesis
       * belongs to the enclosing substitution and is outside this slice. */
      token->type = SHELL_TOKEN_ARGUMENT;
      token->start = state->input + start_pos;
      token->length = state->position - start_pos;
      token->position = start_pos;
      token->is_quoted = is_quoted;
      token->is_escaped = current_char == '\\';
      return shell_token_return_current_group_context(state, token);
    }
    /* An escaped byte already started an ordinary word. Finish that word
     * before recognizing a following operator or expansion; otherwise `\\V&`
     * emits only '&' and silently loses the argument. */
    if (current_char == '\\') {
      word_had_quotes = false;
      char following = state->input[state->position];
      size_t substitution_open = 0;
      if (following == '$' || following == '`' ||
          ((following == '<' || following == '>') &&
           shell_source_process_substitution_open(state->input, state->length,
                                                  state->position,
                                                  &substitution_open))) {
        /* Preserve the prefix as a word fragment. The next call recognizes
         * the expansion without overwriting the already consumed bytes. */
        token->type = SHELL_TOKEN_ARGUMENT;
        token->start = state->input + start_pos;
        token->length = state->position - start_pos;
        token->position = start_pos;
        token->is_quoted = false;
        token->is_escaped = true;
        return shell_token_return_current_group_context(state, token);
      }
      goto ordinary_word;
    }
    current_char = state->input[state->position];
  }

  // Parse arithmetic expansion: `$((...))` first.
  if (current_char == '$' && !state->in_quotes) {
    size_t dollar_next = shell_source_logical_following(
        state->input, state->length, state->position);
    if (dollar_next < state->length && state->input[dollar_next] == '{') {
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
    if (shell_source_dollar_arithmetic_open(state->input, state->length,
                                            state->position, NULL)) {
      size_t start = state->position;
      int saved_arith_depth = state->arith_depth;
      bool saved_in_arithmetic = state->in_arithmetic;
      state->arith_depth = saved_arith_depth + 1;
      state->in_arithmetic = true;
      size_t after = 0;
      if (shell_source_skip_arithmetic_expansion(state->input, state->length,
                                                 start, &after)) {
        token->type = SHELL_TOKEN_ARITHMETIC;
        token->start = state->input + start;
        token->length = after - start;
        token->position = start;
        token->is_quoted = false;
        token->is_escaped = false;
        state->position = after;
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

  if (!state->in_quotes && state->lexical_command_position &&
      current_char == '[') {
    shell_conditional_t condition =
        shell_conditional_parse(state->input, state->length, state->position);
    if (condition.frame != SHELL_CONDITIONAL_NONE &&
        condition.frame != SHELL_CONDITIONAL_UNSUPPORTED) {
      *token = (shell_token_t){.type = SHELL_TOKEN_CONDITIONAL_COMMAND,
                               .start = state->input + state->position,
                               .position = state->position,
                               .length = condition.after - state->position};
      state->position = condition.after;
      state->in_conditional = condition.frame == SHELL_CONDITIONAL_INCOMPLETE;
      state->conditional_invalid = condition.frame == SHELL_CONDITIONAL_INVALID;
      return shell_token_return_current_group_context(state, token);
    }
  }

  if (!state->in_quotes && state->lexical_command_position &&
      current_char == '(') {
    size_t content, end, after;
    shell_arithmetic_frame_t frame = shell_source_arithmetic_command(
        state->input, state->length, state->position, &content, &end, &after);
    if (frame != SHELL_ARITHMETIC_FRAME_NONE) {
      token->type = SHELL_TOKEN_ARITHMETIC_COMMAND;
      token->start = state->input + state->position;
      token->position = state->position;
      token->length = after - state->position;
      token->is_quoted = token->is_escaped = false;
      state->position = after;
      state->in_arithmetic = frame == SHELL_ARITHMETIC_FRAME_INCOMPLETE;
      return shell_token_return_current_group_context(state, token);
    }
  }

  if (!state->in_quotes && current_char == '!' &&
      token_at_word_boundary(state) &&
      shell_source_match_pipeline_negator(state->input, state->length,
                                          state->position, NULL)) {
    token->type = SHELL_TOKEN_PIPE_NEGATE;
    token->start = state->input + state->position;
    token->length = 1;
    token->position = state->position;
    token->is_quoted = false;
    token->is_escaped = false;
    state->position++;
    return shell_token_return_current_group_context(state, token);
  }

  if (!state->in_quotes && current_char == '$' &&
      shell_source_logical_next_is(state->input, state->length, state->position,
                                   '\'', NULL)) {
    size_t after = 0;
    if (shell_source_skip_complete_ansi_c_quote(state->input, state->length,
                                                state->position, &after)) {
      token->type = SHELL_TOKEN_ANSI_C_QUOTED;
      token->start = state->input + state->position;
      token->length = after - state->position;
      token->position = state->position;
      token->is_quoted = true;
      token->is_escaped = true;
      state->position = after;
      return shell_token_return_current_group_context(state, token);
    }
  }

  if (!state->in_quotes) {
    size_t after = 0;
    if (shell_source_skip_extglob(state->input, state->length, state->position,
                                  &after)) {
      token->type = SHELL_TOKEN_EXTGLOB;
      token->start = state->input + state->position;
      token->length = after - state->position;
      token->position = state->position;
      token->is_quoted = false;
      token->is_escaped = false;
      state->position = after;
      return shell_token_return_current_group_context(state, token);
    }
  }

  bool pending_redirect_word =
      state->lexical_redirect_operand &&
      (state->lexical_operand_end == 0 ||
       shell_source_skip_escaped_line_endings(state->input, state->length,
                                              state->lexical_operand_end) ==
           state->position);
  if (!state->in_quotes && !pending_redirect_word && token_starts_word(state) &&
      (state->lexical_prefix &
       (LEXICAL_ASSIGNMENT_ALLOWED | LEXICAL_DECLARATION_OPERANDS))) {
    size_t after = 0;
    array_word_t array = array_assignment_probe(
        state->input, state->length, state->position,
        (state->lexical_prefix & LEXICAL_ASSIGNMENT_ALLOWED) != 0, &after);
    if (array == ARRAY_WORD_COMPOUND &&
        !shell_source_find_balanced_parentheses(state->input, state->length,
                                                after, &after))
      array = ARRAY_WORD_UNCLASSIFIED;
    if (array == ARRAY_WORD_INDEXED || array == ARRAY_WORD_COMPOUND) {
      token->type = SHELL_TOKEN_ARRAY_ASSIGNMENT;
      token->start = state->input + state->position;
      token->length = after - state->position;
      token->position = state->position;
      token->is_quoted = false;
      token->is_escaped = memchr(token->start, '\\', token->length) != NULL;
      state->position = after;
      return shell_token_return_current_group_context(state, token);
    }
  }

  if (!state->in_quotes && !word_had_quotes && current_char == '{' &&
      token_starts_word(state)) {
    size_t redirect = 0;
    if (shell_source_parse_named_fd_redirect_at_word_start(
            state->input, state->position, state->length, &redirect)) {
      return full_redirect_token(state, token, state->position, redirect,
                                 false);
    }
  }

  // Check for shell operators
  if (!state->in_quotes && (current_char == '{' || current_char == '}') &&
      !is_brace_group_delimiter(state, current_char == '{')) {
    /* Braces outside reserved-word positions are ordinary word bytes. */
  } else if (!state->in_quotes && is_shell_operator(current_char)) {
    size_t logical_next = shell_source_logical_following(
        state->input, state->length, state->position);
    if (current_char == '<' || current_char == '>') {
      if (parse_process_substitution(state, token, start_pos, is_quoted))
        return shell_token_return_current_group_context(state, token);
      return full_redirect_token(state, token, start_pos, start_pos, false);
    }
    if (current_char == '&' && logical_next < state->length &&
        state->input[logical_next] == '>')
      return full_redirect_token(state, token, start_pos, start_pos, false);
    if (logical_next < state->length) {
      char next_char = state->input[logical_next];

      if (current_char == '|' && next_char == '|') {
        token->type = SHELL_TOKEN_OR;
        token->start = state->input + state->position;
        token->position = state->position;
        token->is_quoted = false;
        state->position = logical_next + 1;
        token->length = state->position - token->position;
        token->is_escaped = token->length != 2;
        return shell_token_return_current_group_context(state, token);
      } else if (current_char == '&' && next_char == '&') {
        token->type = SHELL_TOKEN_AND;
        token->start = state->input + state->position;
        token->position = state->position;
        token->is_quoted = false;
        state->position = logical_next + 1;
        token->length = state->position - token->position;
        token->is_escaped = token->length != 2;
        return shell_token_return_current_group_context(state, token);
      }
    }

    size_t token_group_depth = shell_tokenizer_group_depth(state);
    uint8_t token_group_kinds = state->group_kinds;
    size_t operator_length = 1;
    switch (current_char) {
    case '|':
      if (shell_source_match_logical_punctuation(state->input, state->length,
                                                 state->position, "|&",
                                                 &logical_next)) {
        token->type = SHELL_TOKEN_PIPE_BOTH;
        operator_length = logical_next - state->position;
      } else {
        token->type = SHELL_TOKEN_PIPE;
      }
      break;
    case '&':
      token->type = SHELL_TOKEN_BACKGROUND;
      break;
    case ';':
      if (shell_source_match_logical_punctuation(state->input, state->length,
                                                 state->position, ";;&",
                                                 &logical_next)) {
        token->type = SHELL_TOKEN_CASE_TEST_NEXT;
        operator_length = logical_next - state->position;
      } else if (shell_source_match_logical_punctuation(
                     state->input, state->length, state->position, ";&",
                     &logical_next)) {
        token->type = SHELL_TOKEN_CASE_FALLTHROUGH;
        operator_length = logical_next - state->position;
      } else if (shell_source_match_logical_punctuation(
                     state->input, state->length, state->position, ";;",
                     &logical_next)) {
        token->type = SHELL_TOKEN_CASE_TERMINATE;
        operator_length = logical_next - state->position;
      } else {
        token->type = SHELL_TOKEN_SEMICOLON;
      }
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
      /* Quotes/expansions can supply bracket members. Classify the complete
       * word once instead of probing each unfinished bracket suffix. */
      goto ordinary_word;
    default:
      token->type = SHELL_TOKEN_ARGUMENT;
      break;
    }

    token->start = state->input + state->position;
    token->length = operator_length;
    token->position = state->position;
    token->is_quoted = false;
    token->is_escaped = memchr(token->start, '\\', token->length) != NULL;
    state->position += token->length;
    shell_token_set_group_context(token, token_group_depth, token_group_kinds);
    return true;
  }

  // An IO number must touch its operator. Whitespace leaves a numeric argv
  // word, and a physical newline starts a separate command.
  if (!state->in_quotes && !word_had_quotes &&
      shell_ascii_digit((unsigned char)current_char) &&
      token_starts_word(state)) {
    size_t check_pos = 0;
    uint32_t descriptor = 0;
    shell_source_io_number_t io_number = shell_source_parse_io_number(
        state->input, state->position, state->length, &check_pos, &descriptor);
    if (io_number == SHELL_SOURCE_IO_NUMBER_OVERFLOW)
      goto ordinary_word;
    if (check_pos < state->length) {
      char after_digit = state->input[check_pos];
      if (after_digit == '>' || after_digit == '<') {
        return full_redirect_token(state, token, state->position, check_pos,
                                   true);
      }
    }
  }

ordinary_word:
  while (state->position < state->length) {
    SHELL_SOURCE_WORD_SCAN(1);
    char c = state->input[state->position];

    if (state->in_quotes) {
      if (state->quote_char == '"' && (c == '$' || c == '`')) {
        size_t after = 0;
        bool recognized = false;
        if (shell_source_skip_double_quote_expansion(
                state->input, state->length, state->position, &recognized,
                &after) &&
            recognized) {
          state->position = after;
          continue;
        }
      }
      if (handle_quotes(state)) {
        continue;
      } else {
        state->position++;
      }
    } else {
      if (c == '\\' && state->position + 1 < state->length) {
        /* An escape protects its next byte only. In unquoted \$(name),
         * the dollar is literal but the parentheses remain shell syntax. */
        state->position += 2;
        continue;
      }
      if (c == '\'' || c == '"') {
        word_had_quotes = true;
        (void)handle_quotes(state);
        continue;
      }
      if (c == '$') {
        size_t after = 0;
        if (shell_source_skip_complete_ansi_c_quote(state->input, state->length,
                                                    state->position, &after)) {
          word_had_quotes = true;
          state->position = after;
          continue;
        }
        if (shell_source_skip_variable_expansion(state->input, state->length,
                                                 state->position, &after)) {
          state->position = after;
          continue;
        }
      }
      size_t extglob_after = 0;
      if (shell_source_skip_extglob(state->input, state->length,
                                    state->position, &extglob_after)) {
        state->position = extglob_after;
        continue;
      }
      if (shell_source_space((unsigned char)c) ||
          (is_shell_operator(c) && c != '{' && c != '}' && c != '[')) {
        break;
      }
      state->position++;
    }
  }

  size_t token_length = state->position - start_pos;
  const char *token_text = state->input + start_pos;

  if (shell_source_word_has_glob(token_text, token_length)) {
    token->type = SHELL_TOKEN_GLOB;
  } else {
    token->type = SHELL_TOKEN_COMMAND;
  }

  token->start = state->input + start_pos;
  token->length = token_length;
  token->position = start_pos;
  token->is_quoted = word_had_quotes;
  token->is_escaped = memchr(token_text, '\\', token_length) != NULL;
  shell_token_set_group_context(token, shell_tokenizer_group_depth(state),
                                state->group_kinds);

  return true;
}

/* Source spans include every lexical fragment of a redirect operand. */
static size_t full_redirect_end(const char *input, size_t input_length,
                                const shell_token_t *token) {
  size_t end = shell_source_skip_redirect(input, token->position, input_length);
  return end > token->position ? end : 0;
}

static bool full_redirection_consumes_next(const shell_token_t *token) {
  return token &&
         shell_source_redirection_consumes_word(token->start, token->length);
}

/* The raw scanner preserves diagnostic lexical tokens. This small forward
 * state machine preserves reserved-word, assignment and declaration roles,
 * so literal braces never trigger a scan of preceding source. Prefix words
 * are complete logical words, not fragments such as time"". */
static bool shell_tokenizer_next_body(shell_tokenizer_state_t *state,
                                      shell_token_t *token) {
  shell_source_scope_frontier(state->input, state->position);
  if (!shell_tokenizer_next_raw(state, token))
    return false;
  SHELL_SOURCE_WORD_SCAN(1);
  if (shell_source_is_escaped_line_ending(state->input, token->position,
                                          token->position + token->length))
    return true;
  switch (token->type) {
  case SHELL_TOKEN_PIPE:
  case SHELL_TOKEN_PIPE_BOTH:
  case SHELL_TOKEN_SEMICOLON:
  case SHELL_TOKEN_AND:
  case SHELL_TOKEN_OR:
  case SHELL_TOKEN_BACKGROUND:
  case SHELL_TOKEN_GROUP_START:
  case SHELL_TOKEN_GROUP_END:
    state->lexical_command_position = true;
    state->lexical_redirect_operand = false;
    state->lexical_operand_end = 0;
    /* Bash's time_command_acceptable() excludes a plain pipe immediately
     * before LF, but not |&. A second LF changes that two-token history.
     * Comments leave their LF visible; removed continuations do not update
     * this state. Keep lexical recognition separate from stage grammar. */
    if (token->type == SHELL_TOKEN_PIPE)
      state->lexical_prefix =
          LEXICAL_PREVIOUS_PIPE | LEXICAL_ASSIGNMENT_ALLOWED;
    else if (token->type == SHELL_TOKEN_PIPE_BOTH ||
             (token->type == SHELL_TOKEN_SEMICOLON &&
              (state->lexical_prefix & LEXICAL_PREVIOUS_PIPE)))
      state->lexical_prefix = LEXICAL_ASSIGNMENT_ALLOWED;
    else
      state->lexical_prefix = LEXICAL_TIME_ALLOWED | LEXICAL_ASSIGNMENT_ALLOWED;
    return true;
  default:
    break;
  }
  if (token->type == SHELL_TOKEN_ARITHMETIC_COMMAND ||
      token->type == SHELL_TOKEN_CONDITIONAL_COMMAND) {
    state->lexical_command_position = false;
    state->lexical_redirect_operand = false;
    state->lexical_operand_end = token->position + token->length;
    state->lexical_prefix = 0;
    return true;
  }
  if (full_token_is_redirection(token)) {
    /* A redirect commits simple-command syntax even while argv[0] is still
     * pending. Later braces are ordinary words, not reserved group openers. */
    state->lexical_command_position = false;
    state->lexical_redirect_operand = full_redirection_consumes_next(token);
    state->lexical_operand_end = 0;
    state->lexical_prefix &= LEXICAL_ASSIGNMENT_ALLOWED;
    return true;
  }
  if (state->lexical_redirect_operand) {
    if (state->lexical_operand_end == 0 ||
        shell_tokenizer_token_continues_word(token,
                                             state->lexical_operand_end)) {
      state->lexical_operand_end = token->position + token->length;
      /* Reserved-looking bytes are word data in a redirect operand. Publish
       * that role once, before any consumer interprets pipeline modifiers. */
      if (token->type == SHELL_TOKEN_PIPE_NEGATE)
        token->type = SHELL_TOKEN_ARGUMENT;
      return true;
    }
    state->lexical_redirect_operand = false;
  }
  bool continues =
      state->lexical_operand_end != 0 &&
      shell_tokenizer_token_continues_word(token, state->lexical_operand_end);
  state->lexical_operand_end = token->position + token->length;
  if (continues)
    return true;
  check_keyword(state, token);
  if (state->lexical_command_position) {
    size_t after = 0;
    if (token->type == SHELL_TOKEN_PIPE_NEGATE) {
      state->lexical_prefix &=
          LEXICAL_TIME_ALLOWED | LEXICAL_ASSIGNMENT_ALLOWED;
      return true;
    }
    if ((state->lexical_prefix & LEXICAL_TIME_ALLOWED) &&
        shell_source_match_plain_word(state->input, state->length,
                                      token->position, "time", 4, &after)) {
      state->lexical_prefix = LEXICAL_TIME_ALLOWED | LEXICAL_TIME_P_ALLOWED |
                              LEXICAL_TIME_DASH_ALLOWED |
                              LEXICAL_ASSIGNMENT_ALLOWED;
      return true;
    }
    if ((state->lexical_prefix & LEXICAL_TIME_P_ALLOWED) &&
        shell_source_match_plain_word(state->input, state->length,
                                      token->position, "-p", 2, &after)) {
      state->lexical_prefix &= (uint8_t)~LEXICAL_TIME_P_ALLOWED;
      return true;
    }
    if ((state->lexical_prefix & LEXICAL_TIME_DASH_ALLOWED) &&
        shell_source_match_plain_word(state->input, state->length,
                                      token->position, "--", 2, &after)) {
      state->lexical_prefix &=
          LEXICAL_TIME_ALLOWED | LEXICAL_ASSIGNMENT_ALLOWED;
      return true;
    }
  }
  bool assignment_open = state->lexical_prefix & LEXICAL_ASSIGNMENT_ALLOWED;
  shell_source_assignment_word_t assignment;
  bool assignment_word =
      assignment_open &&
      (token->type == SHELL_TOKEN_ARRAY_ASSIGNMENT ||
       shell_source_parse_scalar_assignment_word(
           token->start, state->length - token->position, &assignment));
  bool declaration =
      assignment_open && !assignment_word &&
      (shell_source_match_plain_word(state->input, state->length,
                                     token->position, "declare", 7, NULL) ||
       shell_source_match_plain_word(state->input, state->length,
                                     token->position, "typeset", 7, NULL) ||
       shell_source_match_plain_word(state->input, state->length,
                                     token->position, "local", 5, NULL) ||
       shell_source_match_plain_word(state->input, state->length,
                                     token->position, "export", 6, NULL) ||
       shell_source_match_plain_word(state->input, state->length,
                                     token->position, "readonly", 8, NULL));
  state->lexical_command_position = false;
  state->lexical_prefix =
      assignment_word ? LEXICAL_ASSIGNMENT_ALLOWED
      : declaration   ? LEXICAL_DECLARATION_OPERANDS
                      : state->lexical_prefix & LEXICAL_DECLARATION_OPERANDS;
  return true;
}

bool shell_tokenizer_next(shell_tokenizer_state_t *state,
                          shell_token_t *token) {
  shell_source_iterator_scope_t previous = shell_source_iterator_begin(
      state->input, state->length, &state->workspace, &state->workspace_size,
      false);
  bool found = shell_tokenizer_next_body(state, token);
  if (shell_source_scratch_exhausted()) {
    state->heredoc_error = true;
    state->position = state->length;
    memset(token, 0, sizeof(*token));
    token->type = SHELL_TOKEN_END;
    found = false;
  }
  shell_source_iterator_end(previous, state->workspace, state->workspace_size);
  return found;
}

static bool control_token_is_word(const shell_token_t *token) {
  return token->type == SHELL_TOKEN_COMMAND ||
         token->type == SHELL_TOKEN_ARGUMENT ||
         token->type == SHELL_TOKEN_ANSI_C_QUOTED ||
         token->type == SHELL_TOKEN_EXTGLOB ||
         token->type == SHELL_TOKEN_GLOB ||
         token->type == SHELL_TOKEN_ARRAY_ASSIGNMENT;
}

static bool control_token_starts_function_definition(const shell_token_t *token,
                                                     const char *input,
                                                     size_t input_length) {
  if (!control_token_is_word(token) || token->position > input_length ||
      token->length > input_length - token->position)
    return false;

  size_t word_end;
  if (!shell_source_skip_shell_word(input, input_length, token->position,
                                    &word_end))
    return false;
  return shell_source_function_declarator_after(input, input_length, word_end);
}

/* The Bash `function` spelling needs a name before a compound body. Keep the
 * unsupported-function classifier from accepting `function { ...; }` merely
 * because it saw the keyword: that form is malformed shell syntax, while a
 * real declaration remains lexically representable for the semantic boundary
 * to reject as unsupported. */
static bool control_function_keyword_has_name(const shell_token_t *token,
                                              const char *input,
                                              size_t input_length) {
  if (token && token->type == SHELL_TOKEN_CONDITIONAL_COMMAND)
    return false;
  if (!token || !input || token->position > input_length ||
      token->length > input_length - token->position)
    return false;
  size_t position = token->position + token->length;
  while (position < input_length &&
         (input[position] == ' ' || input[position] == '\t'))
    position++;
  if (position >= input_length)
    return false;
  return shell_ascii_alpha((unsigned char)input[position]) ||
         input[position] == '_';
}

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

static bool token_is_plain_word(const char *input, size_t input_length,
                                const shell_token_t *token, const char *word) {
  if (!input || !token || !word ||
      (token->type != SHELL_TOKEN_COMMAND &&
       token->type != SHELL_TOKEN_ARGUMENT))
    return false;
  size_t after = token->position;
  return shell_source_match_plain_word(input, input_length, token->position,
                                       word, strlen(word), &after) &&
         after == token->position + token->length;
}

/* The lexer deliberately exposes quote and expansion fragments separately,
 * while declaration builtins resolve their name and options after quote
 * removal across the complete shell word.  Start at the first fragment and
 * recover that full raw word before decoding static spelling.  This keeps
 * `de$'clare'` and `-$'a'` from bypassing the semantic boundary without ever
 * treating a dynamic expansion as a declaration name or option. Decode only
 * static shell spelling here: parameter, command, and arithmetic expansions
 * remain source bytes, so no runtime value can turn an ordinary word into a
 * declaration builtin. */
/* Required source/token/visitor; context follows the visitor's contract. */
static SHELL_NONNULL(1, 3, 4) bool token_visit_static_word(
    const char *input, size_t input_length, const shell_token_t *token,
    shell_source_byte_visitor_t visitor, void *context) {
  if ((!control_token_is_word(token) &&
       token->type != SHELL_TOKEN_PROCESS_SUB) ||
      token->position > input_length)
    return false;
  size_t word_end = 0;
  if (!shell_source_skip_shell_word(input, input_length, token->position,
                                    &word_end) ||
      word_end <= token->position || word_end > input_length)
    return false;
  const char *word = input + token->position;
  size_t word_length = word_end - token->position;
  return shell_source_visit_decoded_word(word, word_length, visitor, context);
}

typedef struct {
  const char *word;
  size_t length;
  size_t position;
  bool matches;
} static_word_match_t;

static SHELL_NONNULL(2) bool static_word_match_emit(unsigned char byte,
                                                    void *context) {
  static_word_match_t *match = context;
  if (match->position >= match->length ||
      byte != (unsigned char)match->word[match->position])
    match->matches = false;
  match->position++;
  return true;
}

static SHELL_NONNULL(1, 3,
                     4) bool token_is_static_word(const char *input,
                                                  size_t input_length,
                                                  const shell_token_t *token,
                                                  const char *word) {
  static_word_match_t match = {
      .word = word,
      .length = strlen(word),
      .matches = true,
  };
  return token_visit_static_word(input, input_length, token,
                                 static_word_match_emit, &match) &&
         match.matches && match.position == match.length;
}

static SHELL_NONNULL(1, 3) shell_source_builtin_kind_t
    token_static_builtin_kind(const char *input, size_t input_length,
                              const shell_token_t *token) {
  if ((!control_token_is_word(token) &&
       token->type != SHELL_TOKEN_PROCESS_SUB) ||
      token->position > input_length)
    return SHELL_SOURCE_BUILTIN_NONE;
  size_t word_end = 0;
  if (!shell_source_skip_shell_word(input, input_length, token->position,
                                    &word_end) ||
      word_end <= token->position || word_end > input_length)
    return SHELL_SOURCE_BUILTIN_NONE;
  return shell_source_static_builtin_kind(input + token->position,
                                          word_end - token->position);
}

typedef struct {
  const char *prefix;
  size_t length;
  size_t position;
  bool matches;
} word_prefix_match_t;

static SHELL_NONNULL(2) bool word_prefix_match_emit(unsigned char byte,
                                                    void *context) {
  word_prefix_match_t *match = context;
  if (match->position < match->length &&
      byte != (unsigned char)match->prefix[match->position])
    match->matches = false;
  match->position++;
  return true;
}

/* Quote removal can make several lexical tokens one option word.  Inspect its
 * leading decoded spelling without allocating so `-v\"$name\"` and
 * `'-v'\"$name\"` cannot bypass the semantic gate. Dynamic material after
 * the prefix is deliberately not interpreted here. */
static SHELL_NONNULL(1, 3,
                     4) bool token_has_word_prefix(const char *input,
                                                   size_t input_length,
                                                   const shell_token_t *token,
                                                   const char *prefix) {
  word_prefix_match_t match = {
      .prefix = prefix,
      .length = strlen(prefix),
      .matches = true,
  };
  return token_visit_static_word(input, input_length, token,
                                 word_prefix_match_emit, &match) &&
         match.matches && match.position >= match.length;
}

/* Semantic roles are assigned to the full logical shell word, while lexical
 * iteration may expose quote or expansion fragments separately.  A missing
 * whole-word span is dynamic in a role where Bash would resolve a target. */
static SHELL_NONNULL(1, 3) bool semantic_word_has_dynamic_syntax(
    const char *input, size_t input_length, const shell_token_t *token,
    size_t semantic_word_end) {
  return semantic_word_end <= token->position ||
         semantic_word_end > input_length ||
         shell_source_word_has_dynamic_syntax(
             input + token->position, semantic_word_end - token->position);
}

/* These builtins either execute source in the current interpreter or mutate
 * its later command interpretation. Shellsplit models the submitted source,
 * not a second program assembled at runtime, so accepting one could let it
 * change descriptor or pipeline lifetime after validation. Reject the whole
 * static builtin form instead of attempting to parse trap handlers, aliases,
 * history replay, completion expansion/callbacks, Readline key bindings, or
 * dynamically loaded builtin grammars. */
static SHELL_NONNULL(1, 3) bool token_is_unmodeled_current_shell_builtin(
    const char *input, size_t input_length, const shell_token_t *token) {
  switch (token_static_builtin_kind(input, input_length, token)) {
  case SHELL_SOURCE_BUILTIN_ALIAS:
  case SHELL_SOURCE_BUILTIN_BIND:
  case SHELL_SOURCE_BUILTIN_COMPGEN:
  case SHELL_SOURCE_BUILTIN_COMPLETE:
  case SHELL_SOURCE_BUILTIN_COMPOPT:
  case SHELL_SOURCE_BUILTIN_DOT:
  case SHELL_SOURCE_BUILTIN_ENABLE:
  case SHELL_SOURCE_BUILTIN_EVAL:
  case SHELL_SOURCE_BUILTIN_FC:
  case SHELL_SOURCE_BUILTIN_LET:
  case SHELL_SOURCE_BUILTIN_MAPFILE:
  case SHELL_SOURCE_BUILTIN_POPD:
  case SHELL_SOURCE_BUILTIN_PUSHD:
  case SHELL_SOURCE_BUILTIN_READARRAY:
  case SHELL_SOURCE_BUILTIN_SOURCE:
  case SHELL_SOURCE_BUILTIN_TRAP:
  case SHELL_SOURCE_BUILTIN_UNALIAS:
    return true;
  default:
    return false;
  }
}

typedef struct {
  bool option;
  size_t position;
} static_option_scan_t;

static SHELL_NONNULL(2) bool static_option_emit(unsigned char byte,
                                                void *context) {
  static_option_scan_t *scan = context;
  if (scan->position == 0)
    scan->option = byte == '-' || byte == '+';
  scan->position++;
  return true;
}

static SHELL_NONNULL(1, 3, 4) bool token_scan_static_option(
    const char *input, size_t input_length, const shell_token_t *token,
    static_option_scan_t *scan) {
  *scan = (static_option_scan_t){0};
  return token_visit_static_word(input, input_length, token, static_option_emit,
                                 scan) &&
         scan->position > 0;
}

typedef struct {
  size_t position;
  size_t selectors;
  uint32_t names;
  unsigned char sign;
  bool valid, changes;
} static_set_option_t;

/* Bits distinguish complete valid names from prefixes/invalid names that stop
 * set processing. Every complete selector operand mutates option state. */
static const struct {
  /* NULL means that this flag has no named -o/+o spelling. */
  const char *name;
  unsigned char short_option;
} set_options[] = {
    {"posix", 0},       {"allexport", 'a'}, {"braceexpand", 'B'},
    {"emacs", 0},       {"errexit", 'e'},   {"errtrace", 'E'},
    {"functrace", 'T'}, {"hashall", 'h'},   {"histexpand", 'H'},
    {"history", 0},     {"ignoreeof", 0},   {"interactive-comments", 0},
    {"keyword", 'k'},   {"monitor", 'm'},   {"noclobber", 'C'},
    {"noexec", 'n'},    {"noglob", 'f'},    {"nolog", 0},
    {"notify", 'b'},    {"nounset", 'u'},   {"onecmd", 't'},
    {"physical", 'P'},  {"pipefail", 0},    {"privileged", 'p'},
    {"verbose", 'v'},   {"vi", 0},          {"xtrace", 'x'},
    {NULL, 'r'},
};

_Static_assert(sizeof(set_options) / sizeof(set_options[0]) < 32,
               "set option names must fit their selector mask");

static SHELL_NONNULL(2) bool static_set_option_emit(unsigned char byte,
                                                    void *context) {
  static_set_option_t *scan = context;
  bool changes = false;
  for (size_t i = 0; i < sizeof(set_options) / sizeof(set_options[0]); i++) {
    uint32_t bit = UINT32_C(1) << i;
    changes |=
        set_options[i].short_option != 0 && byte == set_options[i].short_option;
    /* Match payload bytes, never the name's terminator. An exhausted name
     * drops out before the next byte advances its candidate offset. */
    if ((scan->names & bit) != 0 &&
        (!set_options[i].name || set_options[i].name[scan->position] == '\0' ||
         byte != (unsigned char)set_options[i].name[scan->position]))
      scan->names &= ~bit;
  }
  if (scan->position++ == 0) {
    scan->sign = byte == '-' || byte == '+' ? byte : 0;
    return true;
  }
  if (!scan->sign || !scan->valid)
    return true;
  if (byte == 'o')
    scan->selectors++;
  else if (changes)
    scan->changes = true;
  else
    scan->valid = false;
  return true;
}

static SHELL_NONNULL(1) uint32_t
    static_set_selector_names(const static_set_option_t *scan) {
  uint32_t names = 0;
  for (size_t i = 0; i < sizeof(set_options) / sizeof(set_options[0]); i++) {
    uint32_t bit = UINT32_C(1) << i;
    if ((scan->names & bit) != 0 && set_options[i].name &&
        set_options[i].name[scan->position] == '\0')
      names |= bit;
  }
  return names;
}

typedef struct {
  unsigned char letter;
  size_t position;
  bool option;
  bool found;
} static_option_letter_scan_t;

static SHELL_NONNULL(2) bool static_option_letter_emit(unsigned char byte,
                                                       void *context) {
  static_option_letter_scan_t *scan = context;
  if (scan->position == 0)
    scan->option = byte == '-';
  else if (scan->option && byte == scan->letter)
    scan->found = true;
  scan->position++;
  return true;
}

static SHELL_NONNULL(1, 3) bool token_static_option_has_letter(
    const char *input, size_t input_length, const shell_token_t *token,
    unsigned char letter) {
  static_option_letter_scan_t scan = {.letter = letter};
  return token_visit_static_word(input, input_length, token,
                                 static_option_letter_emit, &scan) &&
         scan.option && scan.found;
}

typedef struct {
  bool option;
  bool enables;
  bool disables;
  size_t position;
} static_shopt_option_scan_t;

static SHELL_NONNULL(2) bool static_shopt_option_emit(unsigned char byte,
                                                      void *context) {
  static_shopt_option_scan_t *scan = context;
  if (scan->position == 0)
    scan->option = byte == '-';
  else if (scan->option && byte == 's')
    scan->enables = true;
  else if (scan->option && byte == 'u')
    scan->disables = true;
  scan->position++;
  return true;
}

static SHELL_NONNULL(1, 3, 4) bool token_scan_shopt_option(
    const char *input, size_t input_length, const shell_token_t *token,
    static_shopt_option_scan_t *scan) {
  *scan = (static_shopt_option_scan_t){0};
  return token_visit_static_word(input, input_length, token,
                                 static_shopt_option_emit, scan) &&
         scan->position > 0;
}

typedef enum {
  DECLARATION_ARRAY_NAME,
  DECLARATION_ARRAY_SUBSCRIPT,
  DECLARATION_ARRAY_COMPLETE,
  DECLARATION_ARRAY_PLUS,
  DECLARATION_ARRAY_VALUE,
  DECLARATION_ARRAY_OTHER,
} declaration_array_state_t;

typedef struct {
  declaration_array_state_t state;
  size_t subscript_depth;
  size_t skip;
  bool have_name;
} declaration_array_scan_t;

/* Declaration builtins interpret their operands after quote removal. This
 * scanner recognizes a complete static NAME[subscript] operand without
 * evaluating an expansion or allocating a temporary decoded word. */
static SHELL_NONNULL(2) bool declaration_array_emit(unsigned char byte,
                                                    void *context) {
  declaration_array_scan_t *scan = context;
  if (scan->state == DECLARATION_ARRAY_OTHER)
    return true;
  if (scan->skip != 0) {
    scan->skip--;
    return true;
  }

  switch (scan->state) {
  case DECLARATION_ARRAY_NAME:
    if (!scan->have_name) {
      if (!(shell_ascii_alpha(byte) || byte == '_')) {
        scan->state = DECLARATION_ARRAY_OTHER;
        return true;
      }
      scan->have_name = true;
      return true;
    }
    if (shell_ascii_alnum(byte) || byte == '_')
      return true;
    if (byte == '=') {
      scan->state = DECLARATION_ARRAY_OTHER;
      return true;
    }
    if (byte != '[') {
      scan->state = DECLARATION_ARRAY_OTHER;
      return true;
    }
    scan->state = DECLARATION_ARRAY_SUBSCRIPT;
    scan->subscript_depth = 1;
    return true;
  case DECLARATION_ARRAY_SUBSCRIPT:
    if (byte == '[') {
      scan->subscript_depth++;
    } else if (byte == ']' && --scan->subscript_depth == 0) {
      scan->state = DECLARATION_ARRAY_COMPLETE;
    }
    return true;
  case DECLARATION_ARRAY_COMPLETE:
    if (byte == '=') {
      scan->state = DECLARATION_ARRAY_VALUE;
      return true;
    }
    if (byte == '+') {
      scan->state = DECLARATION_ARRAY_PLUS;
      return true;
    }
    scan->state = DECLARATION_ARRAY_OTHER;
    return true;
  case DECLARATION_ARRAY_PLUS:
    if (byte == '=') {
      scan->state = DECLARATION_ARRAY_VALUE;
      return true;
    }
    scan->state = DECLARATION_ARRAY_OTHER;
    return true;
  case DECLARATION_ARRAY_VALUE:
    /* The declaration builtin has already recognized the array designator.
     * Its assigned value need not be parsed to reject the unsupported array
     * semantic without evaluating any runtime expansion. */
    return true;
  case DECLARATION_ARRAY_OTHER:
    return true;
  }
  return true;
}

static SHELL_NONNULL(1) bool word_has_array_designator_after(const char *input,
                                                             size_t length,
                                                             size_t skip) {
  declaration_array_scan_t scan = {
      .state = DECLARATION_ARRAY_NAME,
      .skip = skip,
  };
  bool in_single = false;
  bool in_double = false;
  for (size_t position = 0; position < length; position++) {
    char c = input[position];
    if (!in_single && !in_double && c == '$' &&
        shell_source_logical_next_is(input, length, position, '\'', NULL)) {
      size_t after = position;
      if (!shell_source_decode_ansi_c_word(input, length, &after,
                                           declaration_array_emit, &scan))
        return false;
      position = after - 1;
      continue;
    }
    if (c == '\\' && !in_single && position + 1 < length) {
      char next = input[++position];
      if (next == '\n')
        continue;
      if (in_double && next != '$' && next != '`' && next != '"' &&
          next != '\\')
        (void)declaration_array_emit('\\', &scan);
      (void)declaration_array_emit((unsigned char)next, &scan);
      continue;
    }
    if (c == '\'' && !in_double) {
      in_single = !in_single;
      continue;
    }
    if (c == '"' && !in_single) {
      in_double = !in_double;
      continue;
    }
    if (!in_single && c == '`') {
      size_t after = 0;
      if (!shell_source_skip_complete_quoted_text(input, length, position, c,
                                                  &after))
        return false;
      position = after - 1;
      continue;
    }
    if (!in_single && c == '$' &&
        shell_source_logical_next_is(input, length, position, '{', NULL)) {
      size_t after = 0;
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 &after))
        return false;
      position = after - 1;
      continue;
    }
    size_t open = 0;
    if (!in_single && c == '$' &&
        shell_source_dollar_arithmetic_open(input, length, position, &open)) {
      size_t after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &after))
        return false;
      position = after - 1;
      continue;
    }
    if (!in_single && c == '$' &&
        shell_source_dollar_parentheses_open(input, length, position, &open)) {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, open, &after))
        return false;
      position = after - 1;
      continue;
    }
    if (!in_single && !in_double && (c == '<' || c == '>') &&
        shell_source_process_substitution_open(input, length, position,
                                               &open)) {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, open, &after))
        return false;
      position = after - 1;
      continue;
    }
    (void)declaration_array_emit((unsigned char)c, &scan);
  }
  return scan.state == DECLARATION_ARRAY_COMPLETE ||
         scan.state == DECLARATION_ARRAY_VALUE;
}

/* `[[` and `((` are Bash compound commands only at a command-word position.
 * The full lexer keeps their bytes available as ordinary lexical tokens so it
 * can still diagnose incomplete source, but the canonical command model must
 * not turn either construct into an argv program.  Match the source spelling
 * rather than one particular token shape: `[[` may be exposed as two bracket
 * tokens, while `((` is exposed as nested group openers. */
static bool token_starts_bash_compound_command(const shell_token_t *token,
                                               const char *input,
                                               size_t input_length) {
  if (token && token->type == SHELL_TOKEN_CONDITIONAL_COMMAND)
    return false;
  if (!token || !input || token->position > input_length ||
      token->length == 0 || token->length > input_length - token->position)
    return false;
  if (shell_token_is_literal(token))
    return false;

  size_t position = token->position;
  size_t after = 0;
  /* Bash recognizes `[[` as a conditional command only when the delimiter
   * after it begins the condition. Keep a word such as `[[literal` lexical
   * data instead of rejecting a possible external command name. */
  if (!shell_source_match_logical_punctuation(input, input_length, position,
                                              "[[", &after))
    return false;
  after = shell_source_skip_escaped_line_endings(input, input_length, after);
  return after == input_length ||
         shell_source_space((unsigned char)input[after]);
}

/* Inspect every active expansion regardless of the outer token's diagnostic
 * classification. The semantic boundary's lexical pass owns malformed-source
 * rejection; this predicate classifies unsupported operations using the same
 * inherited quote contexts as graph and feature consumers. */
static SHELL_NONNULL(1) bool expansion_has_unsupported_semantics(
    const char *input, size_t length, bool heredoc) {
  shell_source_substitution_scan_t scan = {
      .scope = {.heredoc = heredoc, .suppress_process = heredoc}};
  size_t start, after;
  shell_source_substitution_kind_t kind;
  shell_source_scan_status_t status;
  while ((status = shell_source_next_word_expansion(input, length, &scan,
                                                    &start, &after, &kind)) ==
         SHELL_SOURCE_SCAN_FOUND) {
    /* A legacy body's escape layer is removed before its nested parse. Raw
     * borrowed spans cannot describe that logical source, so do not classify
     * or validate the raw body as though it were an ordinary command list. */
    if (scan.has_backtick_escapes)
      return true;
    if (semantic_process_observer &&
        (kind == SHELL_SOURCE_SUBST_PROCESS_INPUT ||
         kind == SHELL_SOURCE_SUBST_PROCESS_OUTPUT))
      semantic_process_observer(input + start, after - start,
                                semantic_token_context);
    if (kind == SHELL_SOURCE_EXPANSION_SUBSTRING) {
      if (substring_has_unsupported_semantics(input + start, after - start))
        return true;
      continue;
    }
    size_t content_start = start + 1;
    if (kind == SHELL_SOURCE_EXPANSION_ARITHMETIC) {
      size_t open = 0;
      (void)shell_source_dollar_arithmetic_open(input, length, start, &open);
      content_start = open + 1;
      /* The outer arithmetic scope owns nested math. The literal grammar
       * parses nested expansions once on its own forward cursor. */
      size_t close = after - 2;
      while (close > content_start && input[close] != ')')
        close--;
      if (arithmetic_has_unsupported_semantics(input + content_start,
                                               close - content_start))
        return true;
      continue;
    }
    if (kind != SHELL_SOURCE_SUBST_BACKTICK)
      content_start = shell_source_logical_following(input, length, start) + 1;
    if (unsupported_semantics_scan(input + content_start,
                                   after - content_start - 1,
                                   kind != SHELL_SOURCE_SUBST_BACKTICK))
      return true;
  }
  /* Complete raw framing can still require decoded or reconstructed source
   * which retained semantic products cannot represent. Preserve that
   * terminal as unsupported. Malformed and incomplete source remain owned by
   * their syntax-validation boundaries rather than being relabelled here. */
  return status == SHELL_SOURCE_SCAN_UNSUPPORTED || scan.has_arrays ||
         scan.has_locale_quote || scan.has_ansi_nul || scan.has_ansi_locale ||
         scan.has_parameter_write || scan.has_parameter_reevaluation;
}

static SHELL_NONNULL(1) bool word_has_unsupported_semantics(const char *input,
                                                            size_t length) {
  return expansion_has_unsupported_semantics(input, length, false);
}

/* Quote bytes at a heredoc root are data. The shared forward stream still
 * applies parameter-pattern quoting and visits only active expansions. */
static SHELL_NONNULL(1) bool heredoc_body_has_unsupported_semantics(
    const char *input, size_t length) {
  return expansion_has_unsupported_semantics(input, length, true);
}

typedef struct {
  bool unsupported;
} heredoc_semantic_scan_t;

static bool scan_heredoc_body_unsupported_semantics(const char *input,
                                                    size_t body_start,
                                                    size_t body_length,
                                                    bool delimiter_quoted,
                                                    void *context) {
  heredoc_semantic_scan_t *scan = context;
  if (!scan || delimiter_quoted)
    return true;
  if (!heredoc_body_has_unsupported_semantics(input + body_start, body_length))
    return true;
  scan->unsupported = true;
  return false;
}

/* A HEREDOC lexical token includes any descriptor prefix and delimiter word.
 * Locate its already-recognized `<<` operator so the shared source helper can
 * traverse the entire FIFO declaration line without treating unrelated `<<`
 * syntax, such as an arithmetic shift, as a document. */
static bool heredoc_token_operator_position(const shell_token_t *token,
                                            size_t *operator_position) {
  if (!token || !token->start || !operator_position ||
      token->type != SHELL_TOKEN_HEREDOC)
    return false;
  for (size_t i = 0; i < token->length; i++) {
    size_t after = 0;
    if (token->start[i] == '<' &&
        shell_source_match_logical_punctuation(token->start, token->length, i,
                                               "<<", &after) &&
        !shell_source_match_logical_punctuation(token->start, token->length, i,
                                                "<<<", NULL)) {
      *operator_position = token->position + i;
      return true;
    }
  }
  return false;
}

static bool
heredoc_sequence_has_unsupported_semantics(const char *input, size_t length,
                                           const shell_token_t *token,
                                           size_t *sequence_after) {
  size_t operator_position = 0;
  if (!heredoc_token_operator_position(token, &operator_position))
    return false;
  heredoc_semantic_scan_t scan = {0};
  bool complete = false;
  size_t after = length;
  if (!shell_source_visit_heredoc_sequence(
          input, length, operator_position,
          scan_heredoc_body_unsupported_semantics, &scan, &after, &complete))
    return false;
  if (sequence_after)
    *sequence_after = after;
  return scan.unsupported;
}

/* token is a recognized heredoc in input's immutable span. Syntax completeness
 * belongs to the declaration probe; classify only its supported semantics. */
static SHELL_NONNULL(1, 3) bool heredoc_delimiter_has_unsupported_semantics(
    const char *input, size_t length, const shell_token_t *token,
    bool parenthesized_substitution) {
  size_t operator_position = 0;
  if (!heredoc_token_operator_position(token, &operator_position))
    return false;
  size_t delimiter = 0;
  if (!shell_source_match_logical_punctuation(input, length, operator_position,
                                              "<<", &delimiter))
    return false;
  shell_source_pending_heredoc_t pending = {0};
  if (!shell_source_parse_heredoc_delimiter(input, length, &delimiter,
                                            &pending))
    return false;
  if (shell_source_heredoc_word_has_unsupported_ansi_c(pending.word,
                                                       pending.word_length))
    return true;
  /* Bash print_comsub omits the separator before an unquoted delimiter. A
   * leading dash then becomes the <<- operator on the execution-time parse,
   * changing both the terminator and tab stripping. The resulting commands
   * cannot borrow the original body spans faithfully. Real quoting and an
   * already-strip-tabs operator preserve their original framing instead. */
  return parenthesized_substitution && !pending.strip_tabs &&
         pending.word[0] == '-' &&
         !shell_source_heredoc_delimiter_is_quoted(&pending);
}

/* Keep all current-shell builtin roles together.  A target reached through a
 * wrapper chain must receive exactly the same classification as a direct
 * command word; otherwise `command builtin shopt ...` could evade the
 * source-level semantic boundary. */
typedef struct {
  bool declaration;
  shell_builtin_declaration_t declaration_state;
  bool shopt;
  bool shopt_mutates;
  bool set_builtin;
  size_t set_selectors;
  bool set_invalid_after_selectors;
  bool printf_builtin;
  shell_builtin_printf_t printf_state;
  bool read_builtin;
  shell_builtin_read_t read;
  bool getopts_builtin;
  shell_builtin_getopts_t getopts;
  bool unset_builtin;
  shell_builtin_unset_t unset;
  bool wait_builtin;
  bool wait_options;
  bool test_builtin;
  shell_builtin_test_t test;
  shell_source_wrapper_state_t wrapper;
} semantic_builtin_state_t;

typedef struct {
  size_t end;
  bool eligible;
  bool scanned;
  bool has_time;
  bool has_stage;
} semantic_pipeline_prefix_t;

static semantic_pipeline_prefix_t semantic_pipeline_prefix_initial(void) {
  return (semantic_pipeline_prefix_t){.eligible = true};
}

/* Both semantic scanners operate on lexical tokens, whereas reserved `time`
 * and `!` belong to the surrounding pipeline grammar. Recover that grammar
 * from the shared source parser and leave the command-word position open
 * until the first actual stage token. Required token/state storage is owned by
 * the calling scanner; the token borrows its unchanged input source span. */
static SHELL_NONNULL(1, 3, 4) bool semantic_token_is_pipeline_prefix(
    const char *input, size_t input_length, const shell_token_t *token,
    semantic_pipeline_prefix_t *state) {
  if (!state->eligible)
    return false;
  if (!state->scanned) {
    shell_source_pipeline_prefix_t prefix = shell_source_parse_pipeline_prefix(
        input, token->position, input_length);
    state->end = prefix.valid && prefix.has_modifier ? prefix.stage_start
                                                     : token->position;
    state->has_time = prefix.valid && prefix.has_modifier &&
                      prefix.time_mode != SHELL_PIPE_TIME_NONE;
    state->scanned = true;
  }
  if (token->position < state->end)
    return true;
  state->eligible = false;
  return false;
}

/* token borrows the required immutable input span; state is required writable
 * scanner-local storage, replaced by this command's builtin classification. */
static SHELL_NONNULL(1, 3, 4) bool semantic_set_builtin_target(
    const char *input, size_t input_length, const shell_token_t *token,
    semantic_builtin_state_t *state) {
  *state = (semantic_builtin_state_t){0};
  if (token_is_unmodeled_current_shell_builtin(input, input_length, token))
    return true;
  shell_source_builtin_kind_t kind =
      token_static_builtin_kind(input, input_length, token);
  state->declaration = kind == SHELL_SOURCE_BUILTIN_DECLARE ||
                       kind == SHELL_SOURCE_BUILTIN_TYPESET ||
                       kind == SHELL_SOURCE_BUILTIN_LOCAL ||
                       kind == SHELL_SOURCE_BUILTIN_READONLY ||
                       kind == SHELL_SOURCE_BUILTIN_EXPORT;
  state->declaration_state = (shell_builtin_declaration_t){
      .kind = kind,
      .options = true,
      .promotes_prefix = kind == SHELL_SOURCE_BUILTIN_EXPORT};
  state->shopt = kind == SHELL_SOURCE_BUILTIN_SHOPT;
  state->set_builtin = kind == SHELL_SOURCE_BUILTIN_SET;
  state->printf_builtin = kind == SHELL_SOURCE_BUILTIN_PRINTF;
  state->read_builtin = kind == SHELL_SOURCE_BUILTIN_READ;
  state->read.writing = SHELL_READ_OPTIONS;
  if (state->read_builtin && semantic_read_fd_observer)
    semantic_read_fd_observer(input + token->position, 0, 3, NULL, 0, false,
                              semantic_token_context);
  state->getopts_builtin = kind == SHELL_SOURCE_BUILTIN_GETOPTS;
  state->getopts.phases = SHELL_GETOPTS_OPTIONS;
  state->unset_builtin = kind == SHELL_SOURCE_BUILTIN_UNSET;
  state->unset.options = true;
  state->wait_builtin = kind == SHELL_SOURCE_BUILTIN_WAIT;
  state->wait_options = state->wait_builtin;
  state->test_builtin =
      kind == SHELL_SOURCE_BUILTIN_TEST || kind == SHELL_SOURCE_BUILTIN_BRACKET;
  state->test.bracket = kind == SHELL_SOURCE_BUILTIN_BRACKET;
  return false;
}

static bool unsupported_semantics_scan(const char *input, size_t input_length,
                                       bool parenthesized_substitution) {
  /* Expansion traversal owns nested command bodies. Do not recursively scan
   * every body's descendants again just to classify its control words. */
  static _Thread_local size_t depth;
  if (!input)
    return true;
  if (depth > SHELL_SOURCE_MAX_EXECUTABLE_NESTING)
    return true;
  depth++;
  shell_source_scope_t previous = shell_source_scope_begin(input, input_length);
  bool unsupported = unsupported_semantics_scan_impl(
      input, input_length, parenthesized_substitution);
  shell_source_scope_end(previous);
  depth--;
  return unsupported;
}

static SHELL_NONNULL(1) bool unsupported_semantics_scan_impl(
    const char *input, size_t input_length, bool parenthesized_substitution) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_SEMANTIC_BODIES);
#endif
  shell_tokenizer_state_t state;
  /* This helper classifies valid shell source.  Let each public adapter keep
   * its established EINPUT result for raw control bytes or other invalid
   * source rather than relabelling them as unsupported semantics. */
  if (!shell_tokenizer_init(&state, input, input_length, NULL))
    return false;
  /* Readonly variables can make a later `{name}>...` allocation fail while
   * preserving the previous descriptor binding. Route resolution intentionally
   * has no shell-variable attribute table, so reject every state-changing
   * readonly declaration before it can reach that model. */
  semantic_builtin_state_t builtin = {0};
  bool command_start = true;
  bool awaiting_command = false;
  /* A plain leading integer assignment is temporary once an executable word
   * follows. Without one it performs arithmetic in the current shell. += can
   * perform that arithmetic even for temporary command-prefix assignments. */
  bool integer_assignment = false;
  semantic_pipeline_prefix_t pipeline_prefix =
      semantic_pipeline_prefix_initial();
  size_t redirect_operand_end = 0;
  /* Semantic roles apply to logical shell words, not their lexical quote and
   * escape fragments. Once the first fragment has been classified, skip the
   * remaining fragments until the recovered source-word boundary. */
  size_t semantic_word_end = 0;
  size_t expansion_word_end = 0;
  size_t heredoc_sequence_after = 0;
  bool terminal_empty_time = false;
  /* Prefix state belongs to a compound's command list. Closing an inner
   * subshell must validate its terminal state before restoring the outer
   * pipeline; a brace close, unlike a subshell close, permits empty `time`. */
  semantic_pipeline_prefix_t compound_prefixes[SHELL_MAX_GROUPS];
  uint32_t compound_depth = 0;
  shell_token_t token;
  while (shell_tokenizer_next(&state, &token)) {
    if (semantic_token_observer)
      semantic_token_observer(&token, semantic_token_context);
    if (shell_source_is_escaped_line_ending(input, token.position,
                                            token.position + token.length))
      continue;
    if (token.type == SHELL_TOKEN_CONDITIONAL_COMMAND) {
      shell_conditional_t condition =
          shell_conditional_parse(input, input_length, token.position);
      if (condition.frame != SHELL_CONDITIONAL_COMPLETE)
        return true;
      for (unsigned operand = 0; operand < condition.operand_count; ++operand)
        if (word_has_unsupported_semantics(input + condition.operands[operand],
                                           condition.operand_lengths[operand]))
          return true;
      command_start = false;
      pipeline_prefix.scanned = pipeline_prefix.has_stage = true;
      continue;
    }
    if (token.type == SHELL_TOKEN_ARITHMETIC_COMMAND) {
      if (state.in_arithmetic)
        return true;
      const char *content;
      size_t content_length;
      shell_tokenizer_arithmetic_content(&token, true, &content,
                                         &content_length);
      if (!shell_arithmetic_analyze(content, content_length).supported)
        return true;
      command_start = false;
      pipeline_prefix.scanned = true;
      pipeline_prefix.has_stage = true;
      continue;
    }
    /* Shellsplit deliberately does not execute or model case clauses.  The
     * clause terminators are meaningful only there, and Bash rejects them in
     * an ordinary command list.  Never reinterpret one as a plain separator.
     */
    if (token.type == SHELL_TOKEN_CASE_TERMINATE ||
        token.type == SHELL_TOKEN_CASE_FALLTHROUGH ||
        token.type == SHELL_TOKEN_CASE_TEST_NEXT)
      return true;
    /* Continuation LF does not begin a new pipeline stage. The lexical
     * iterator independently retains Bash's time-keyword history; the list
     * boundary rejects a reserved time where only a stage is permitted. */
    if (command_start && !pipeline_prefix.scanned &&
        !pipeline_prefix.has_stage && token.type == SHELL_TOKEN_SEMICOLON &&
        (token.start[0] == '\n'))
      continue;
    bool list_operator =
        token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_PIPE_BOTH ||
        token.type == SHELL_TOKEN_SEMICOLON || token.type == SHELL_TOKEN_AND ||
        token.type == SHELL_TOKEN_OR || token.type == SHELL_TOKEN_BACKGROUND;
    if (parenthesized_substitution &&
        (token.type == SHELL_TOKEN_SUBSHELL_END ||
         (token.type == SHELL_TOKEN_GROUP_END && token.start[0] == ')')) &&
        (terminal_empty_time || (command_start && pipeline_prefix.has_time &&
                                 !pipeline_prefix.has_stage)))
      return true;
    if (parenthesized_substitution && command_start && list_operator &&
        pipeline_prefix.has_time && !pipeline_prefix.has_stage)
      terminal_empty_time = token.type != SHELL_TOKEN_BACKGROUND;
    else if (!list_operator)
      terminal_empty_time = false;
    if (command_start && semantic_token_is_pipeline_prefix(
                             input, input_length, &token, &pipeline_prefix))
      continue;
    /* An assignment or redirect leaves argv[0] pending, but commits a simple
     * command: a later `if`, `then`, or `[[` is an executable word, not
     * reserved syntax. Reuse the first-stage fact instead of conflating the two
     * roles. */
    bool reserved_word_position = command_start && !pipeline_prefix.has_stage;
    if (command_start && !list_operator)
      pipeline_prefix.has_stage = true;
    /* A heredoc delimiter undergoes quote removal only. Its parameter-like
     * spelling is literal and must not be mistaken for an executable word
     * expansion; its body is inspected below with heredoc-specific rules. */
    bool word_token = control_token_is_word(&token) ||
                      token.type == SHELL_TOKEN_VARIABLE ||
                      token.type == SHELL_TOKEN_VARIABLE_QUOTED ||
                      token.type == SHELL_TOKEN_SPECIAL_VAR ||
                      token.type == SHELL_TOKEN_SUBSHELL ||
                      token.type == SHELL_TOKEN_ARITHMETIC ||
                      token.type == SHELL_TOKEN_PROCESS_SUB ||
                      token.type == SHELL_TOKEN_PIPE_NEGATE ||
                      token.type == SHELL_TOKEN_PIPE_TIME ||
                      token.type == SHELL_TOKEN_PIPE_TIME_OPTION;
    if (word_token && token.position >= expansion_word_end) {
      /* Classify the complete word, not separate $/quote fragments. Nested
       * executable bodies own their quote/comment state in the shared scoped
       * expansion stream. Keep visiting every lexical fragment for observers,
       * but never rescan a suffix with a fabricated fresh quote context. */
      if (!shell_source_skip_shell_word(input, input_length, token.position,
                                        &expansion_word_end))
        return false; /* Syntax validation owns incomplete words. */
      if (word_has_unsupported_semantics(input + token.position,
                                         expansion_word_end - token.position))
        return true;
    } else if (full_token_is_redirection(&token) &&
               token.type != SHELL_TOKEN_HEREDOC &&
               word_has_unsupported_semantics(token.start, token.length)) {
      /* Descriptor duplication tokens can own their complete operand. */
      return true;
    }
    if (token.type == SHELL_TOKEN_HEREDOC &&
        heredoc_delimiter_has_unsupported_semantics(input, input_length, &token,
                                                    parenthesized_substitution))
      return true;
    if (token.type == SHELL_TOKEN_HEREDOC &&
        token.position >= heredoc_sequence_after) {
      if (heredoc_sequence_has_unsupported_semantics(
              input, input_length, &token, &heredoc_sequence_after))
        return true;
    }
    if (redirect_operand_end != 0 && token.position < redirect_operand_end)
      continue;
    redirect_operand_end = 0;
    if (list_operator) {
      if (builtin.test_builtin && shell_builtin_test_unsupported(&builtin.test))
        return true;
      if (integer_assignment)
        return true;
      command_start = true;
      awaiting_command = false;
      pipeline_prefix = semantic_pipeline_prefix_initial();
      if (token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_PIPE_BOTH)
        pipeline_prefix.eligible = false;
      builtin = (semantic_builtin_state_t){0};
      semantic_word_end = 0;
      continue;
    }
    if (reserved_word_position &&
        token_starts_bash_compound_command(&token, input, input_length))
      return true;
    if (token.type == SHELL_TOKEN_GROUP_START ||
        token.type == SHELL_TOKEN_SUBSHELL_START) {
      if (integer_assignment)
        return true;
      /* Defer an over-capacity source to the parser's resource-limit boundary.
       * This classifier does not turn exhaustion into unsupported syntax. */
      if (compound_depth == SHELL_MAX_GROUPS)
        return false;
      compound_prefixes[compound_depth++] = pipeline_prefix;
      command_start = true;
      awaiting_command = false;
      pipeline_prefix = semantic_pipeline_prefix_initial();
      builtin = (semantic_builtin_state_t){0};
      semantic_word_end = 0;
      continue;
    }
    if (token.type == SHELL_TOKEN_GROUP_END ||
        token.type == SHELL_TOKEN_SUBSHELL_END) {
      if (builtin.test_builtin && shell_builtin_test_unsupported(&builtin.test))
        return true;
      if (integer_assignment)
        return true;
      command_start = false;
      awaiting_command = false;
      pipeline_prefix = compound_depth != 0
                            ? compound_prefixes[--compound_depth]
                            : (semantic_pipeline_prefix_t){0};
      builtin = (semantic_builtin_state_t){0};
      semantic_word_end = 0;
      continue;
    }
    if (full_token_is_redirection(&token)) {
      /* Resettable predefined names require graph-side path state. Names whose
       * prohibited capability can never be removed remain source-semantically
       * unsupported and need no deferred graph verdict. */
      size_t name_after;
      if (shell_source_parse_named_fd_at_word_start(
              token.start, 0, token.length, &name_after)) {
        unsigned properties =
            shell_builtin_name_properties(token.start + 1, name_after - 2);
        if ((properties & (SHELL_VARIABLE_UNSTABLE | SHELL_VARIABLE_READONLY |
                           SHELL_VARIABLE_ARRAY | SHELL_VARIABLE_FROZEN)) &&
            !(properties & SHELL_VARIABLE_DESPECIALIZES_ON_UNSET))
          return true;
      }
      redirect_operand_end = full_redirect_end(input, input_length, &token);
      continue;
    }

    if (semantic_word_end != 0 && token.position < semantic_word_end)
      continue;
    semantic_word_end = 0;
    if (word_token)
      semantic_word_end = expansion_word_end;

    /* A lexer can recognize the spelling NAME[index]=value without knowing
     * whether it occupies an assignment-prefix position.  Outside that
     * position Bash passes it as an ordinary argument (for example,
     * `echo a[0]=b`), so reject it only when it has array-assignment
     * semantics.  Declaration builtins also give their operands that meaning.
     */
    if (token.type == SHELL_TOKEN_ARRAY_ASSIGNMENT &&
        (command_start ||
         shell_source_array_assignment_is_compound(token.start, token.length)))
      return true;

    if (word_token &&
        shell_source_word_is_elided(input + token.position,
                                    semantic_word_end - token.position)) {
      /* Expansion can remove a command word, but cannot reopen the lexical
       * assignment/reserved-word prefix. Keep looking only for argv[0]. */
      awaiting_command |= command_start;
      command_start = false;
      continue;
    }
    if (command_start || awaiting_command) {
      if (command_start && token.type == SHELL_TOKEN_PIPE_NEGATE)
        continue;
      /* Control syntax is unsupported whether complete or incomplete. The
       * list validator retains its diagnostic control grammar separately;
       * this forward semantic pass only needs the command-position keyword
       * or function introducer, not another descendant walk. */
      if (reserved_word_position &&
          (shell_source_keyword(input, input_length, token.position, NULL) ||
           control_token_starts_function_definition(&token, input,
                                                    input_length)))
        return true;
      /* Scalar assignment prefixes do not consume the command-word position.
       * Keep looking so `VAR=x declare -a values` cannot evade the semantic
       * rejection. */
      shell_source_assignment_word_t assignment;
      if (command_start && control_token_is_word(&token) &&
          shell_source_parse_scalar_assignment_word(token.start, token.length,
                                                    &assignment)) {
        /* POSIXLY_CORRECT changes Bash's current-shell assignment lifetime.
         * A leading assignment is normally temporary, but rejecting this
         * spelling keeps the supported-source contract independent of which
         * command follows it. The executor separately makes the variable
         * readonly before source evaluation to contain dynamic writers. */
        unsigned properties =
            shell_builtin_name_properties(token.start, assignment.name_end);
        if (properties & SHELL_VARIABLE_FROZEN)
          return true;
        if ((properties & SHELL_VARIABLE_INTEGER) &&
            !(properties & SHELL_VARIABLE_DESPECIALIZES_ON_UNSET)) {
          if (assignment.append)
            return true;
          integer_assignment = true;
        }
        continue;
      }
      integer_assignment = false;
      size_t word_length = semantic_word_end > token.position
                               ? semantic_word_end - token.position
                               : 0;
      shell_source_wrapper_step_t wrapper_step = shell_source_wrapper_start(
          &builtin.wrapper, input + token.position, word_length);
      if (wrapper_step == SHELL_SOURCE_WRAPPER_STATIC_TARGET) {
        if (semantic_set_builtin_target(input, input_length, &token, &builtin))
          return true;
      } else if (wrapper_step != SHELL_SOURCE_WRAPPER_MORE) {
        builtin = (semantic_builtin_state_t){0};
      }
      command_start = false;
      awaiting_command = false;
      continue;
    }
    if (builtin.wrapper.kind != SHELL_SOURCE_WRAPPER_NONE) {
      size_t word_length = semantic_word_end > token.position
                               ? semantic_word_end - token.position
                               : 0;
      shell_source_wrapper_step_t wrapper_step = shell_source_wrapper_consume(
          &builtin.wrapper, input + token.position, word_length);
      if (wrapper_step == SHELL_SOURCE_WRAPPER_STATIC_TARGET) {
        if (semantic_set_builtin_target(input, input_length, &token, &builtin))
          return true;
      } else if (wrapper_step != SHELL_SOURCE_WRAPPER_MORE) {
        builtin = (semantic_builtin_state_t){0};
      }
      continue;
    }
    if (builtin.test_builtin) {
      /* The syntax boundary owns incomplete words. Retain compact role facts
       * until the command boundary supplies Bash's expression arity. */
      if (semantic_word_end <= token.position)
        return false;
      shell_builtin_test_word(&builtin.test, input + token.position,
                              semantic_word_end - token.position);
      continue;
    }
    if (builtin.set_builtin) {
      if (semantic_word_has_dynamic_syntax(input, input_length, &token,
                                           semantic_word_end))
        /* A runtime word can become either a short option or the operand of
         * a pending -o/+o selector. Option state is deliberately fixed for a
         * supported source, so this ambiguity is rejected at this boundary. */
        return true;
      static_set_option_t option = {
          .names =
              (UINT32_C(1) << (sizeof(set_options) / sizeof(set_options[0]))) -
              1,
          .valid = true};
      (void)token_visit_static_word(input, input_length, &token,
                                    static_set_option_emit, &option);
      if (builtin.set_selectors != 0 && option.sign == 0) {
        uint32_t names = static_set_selector_names(&option);
        if (names != 0)
          return true;
        builtin.set_selectors--;
        /* An invalid option name stops Bash before any later selectors. */
        if (names == 0 ||
            (builtin.set_selectors == 0 && builtin.set_invalid_after_selectors))
          builtin.set_builtin = false;
        continue;
      }
      /* A selector before an invalid flag is still applied. If that selector
       * has no operand because the next word is an option, it is only a query;
       * the invalid flag then stops processing before that next option. */
      if (builtin.set_invalid_after_selectors) {
        builtin.set_builtin = false;
        continue;
      }
      /* Bash applies valid short-option letters before diagnosing a later
       * invalid one in the same word. Any proved option mutation therefore
       * leaves the graph's fixed execution model, even on an error path. */
      if (option.changes)
        return true;
      /* A following option leaves pending `o` selectors as harmless queries.
       * Bare `+` continues; bare `-`, `--`, invalid flags, or a positional
       * argument end option processing. */
      if (option.sign == 0 || (!option.valid && option.selectors == 0) ||
          (option.sign == '-' && option.position == 1))
        builtin.set_builtin = false;
      builtin.set_selectors = option.selectors;
      builtin.set_invalid_after_selectors = !option.valid;
      continue;
    }
    if (builtin.getopts_builtin) {
      if (shell_builtin_getopts_word(&builtin.getopts, input + token.position,
                                     semantic_word_end - token.position) &
          SHELL_BUILTIN_ROLE_UNSUPPORTED)
        return true;
      continue;
    }
    if (builtin.read_builtin) {
      unsigned roles =
          shell_builtin_read_word(&builtin.read, input + token.position,
                                  semantic_word_end - token.position);
      if ((roles & SHELL_BUILTIN_ROLE_UNSUPPORTED) ||
          ((roles & SHELL_BUILTIN_ROLE_READ_CONTEXT) &&
           !semantic_read_fd_observer) ||
          ((roles & SHELL_BUILTIN_ROLE_TARGET) &&
           word_has_array_designator_after(
               input + token.position, semantic_word_end - token.position, 0)))
        return true;
      if (semantic_read_fd_observer &&
          (builtin.read.fd_kind || builtin.read.parameter))
        semantic_read_fd_observer(
            input + token.position, builtin.read.fd_number,
            builtin.read.fd_kind, builtin.read.parameter,
            builtin.read.parameter_length, builtin.read.parameter_identity,
            semantic_token_context);
      continue;
    }
    if (builtin.unset_builtin) {
      unsigned roles =
          shell_builtin_unset_word(&builtin.unset, input + token.position,
                                   semantic_word_end - token.position);
      if ((roles & SHELL_BUILTIN_ROLE_TARGET) &&
          word_has_array_designator_after(
              input + token.position, semantic_word_end - token.position, 0))
        return true;
      continue;
    }
    if (builtin.wait_builtin) {
      if (builtin.wait_options) {
        if (semantic_word_has_dynamic_syntax(input, input_length, &token,
                                             semantic_word_end))
          return true;
        if (token_is_static_word(input, input_length, &token, "--")) {
          builtin.wait_options = false;
          continue;
        }
        if (token_static_option_has_letter(input, input_length, &token, 'p'))
          return true;
        static_option_scan_t option;
        if (token_scan_static_option(input, input_length, &token, &option) &&
            option.option)
          continue;
        builtin.wait_options = false;
      }
      builtin.wait_builtin = false;
      continue;
    }
    if (builtin.printf_builtin) {
      /* An incomplete word belongs to the syntax-validation boundary, not
       * the supported-semantics classifier. */
      if (semantic_word_end <= token.position)
        return false;
      /* An unresolved attached target is rejected at the source boundary.
       * Fully dynamic option selection retains its unknown-writer role. */
      if (builtin.printf_state.phase == SHELL_PRINTF_OPTIONS &&
          token_has_word_prefix(input, input_length, &token, "-v") &&
          semantic_word_has_dynamic_syntax(input, input_length, &token,
                                           semantic_word_end))
        return true;
      size_t length = semantic_word_end - token.position;
      unsigned roles = shell_builtin_printf_word(
          &builtin.printf_state, input + token.position, length);
      if ((roles & SHELL_BUILTIN_ROLE_UNSUPPORTED) ||
          ((roles & SHELL_BUILTIN_ROLE_TARGET) &&
           ((roles & SHELL_BUILTIN_ROLE_DYNAMIC) ||
            word_has_array_designator_after(
                input + token.position, length,
                roles & SHELL_BUILTIN_ROLE_ATTACHED ? 2 : 0))))
        return true;
      continue;
    }
    if (builtin.shopt) {
      static_shopt_option_scan_t option;
      if (token_scan_shopt_option(input, input_length, &token, &option) &&
          option.option) {
        builtin.shopt_mutates =
            builtin.shopt_mutates || option.enables || option.disables;
        continue;
      }
      size_t word_end = semantic_word_end;
      bool dynamic = word_end <= token.position ||
                     shell_source_argument_has_dynamic_syntax(
                         input + token.position, word_end - token.position);
      /* A dynamic selector could be `-s` or `-u`, so it may alter the
       * lifetime contract even if the following source bytes look harmless. */
      if (dynamic)
        return true;
      /* All option state is part of the launch contract. Even options which
       * do not currently affect graph construction can change the meaning of
       * later syntax as support grows, so accept inspection-only shopt forms
       * and reject every static mutation attempt uniformly. */
      if (builtin.shopt_mutates)
        return true;
    }
    if (builtin.declaration) {
      if (semantic_word_end <= token.position)
        return false;
      size_t length = semantic_word_end - token.position;
      unsigned roles = shell_builtin_declaration_word(
          &builtin.declaration_state, input + token.position, length);
      if ((roles & SHELL_BUILTIN_ROLE_UNSUPPORTED) ||
          ((roles & SHELL_BUILTIN_ROLE_TARGET) &&
           word_has_array_designator_after(input + token.position, length, 0)))
        return true;
    }
  }
  return (builtin.test_builtin &&
          shell_builtin_test_unsupported(&builtin.test)) ||
         integer_assignment || terminal_empty_time ||
         (parenthesized_substitution && command_start &&
          pipeline_prefix.has_time && !pipeline_prefix.has_stage);
}

bool shell_tokenizer_has_unsupported_semantics(const char *input,
                                               size_t input_length) {
  shell_source_operation_begin(input ? input : "", input_length);
  bool unsupported = unsupported_semantics_scan(input, input_length, false);
  shell_source_operation_end();
  return unsupported;
}

bool shell_tokenizer_inspect_semantics(
    const char *input, size_t input_length,
    shell_semantic_token_observer_t observer,
    shell_semantic_read_fd_observer_t read_fd,
    shell_semantic_process_observer_t process, void *context) {
  shell_semantic_token_observer_t previous = semantic_token_observer;
  shell_semantic_read_fd_observer_t previous_read = semantic_read_fd_observer;
  shell_semantic_process_observer_t previous_process =
      semantic_process_observer;
  void *previous_context = semantic_token_context;
  semantic_token_observer = observer;
  semantic_read_fd_observer = read_fd;
  semantic_process_observer = process;
  semantic_token_context = context;
  bool unsupported =
      shell_tokenizer_has_unsupported_semantics(input, input_length);
  semantic_token_observer = previous;
  semantic_read_fd_observer = previous_read;
  semantic_process_observer = previous_process;
  semantic_token_context = previous_context;
  return unsupported;
}

static SHELL_NONNULL(1) shell_control_syntax_t
    control_syntax_scan_impl(const char *input, size_t input_length) {
  shell_tokenizer_state_t state;
  if (!shell_tokenizer_init(&state, input, input_length, NULL))
    return SHELL_CONTROL_SYNTAX_NONE;

  /* Reserved-word eligibility only; this walk does not locate argv[0] after
   * assignments and redirects as the semantic builtin classifier does. */
  bool command_start = true;
  semantic_pipeline_prefix_t pipeline_prefix =
      semantic_pipeline_prefix_initial();
  size_t redirect_operand_end = 0;
  bool saw_control = false;
  control_frame_state_t frames[SHELL_MAX_SUBCOMMANDS];
  size_t frame_count = 0;
  shell_token_t token;
  for (;;) {
    /* Capture the iterator's forward adjacency history before it publishes
     * this token's end. A token can be just one fragment of a shell word. */
    size_t preceding_word_end = state.lexical_operand_end;
    if (!shell_tokenizer_next(&state, &token))
      break;
    /* A continued physical line belongs to the surrounding lexical source
     * word. It cannot consume the command-start position between a function
     * name and its declarator. */
    if (shell_source_is_escaped_line_ending(input, token.position,
                                            token.position + token.length))
      continue;
    bool continues =
        preceding_word_end != 0 &&
        shell_tokenizer_token_continues_word(&token, preceding_word_end);
    /* Neither a suffix fragment nor a keyword-shaped prefix followed by an
     * expansion is a reserved word. Use the original source boundary; token
     * EOF is not word EOF. Keyword lookahead leaves nested bodies opaque. */
    const shell_keyword_t *facts =
        !continues && control_token_is_word(&token)
            ? shell_source_keyword(input, input_length, token.position, NULL)
            : NULL;
    shell_keyword_kind_t keyword = facts ? facts->kind : SHELL_KEYWORD_NONE;
    /* Retain the connector's prefix eligibility across physical newlines,
     * exactly as in the unsupported-semantics stream above. */
    if (command_start && !pipeline_prefix.scanned &&
        !pipeline_prefix.has_stage && token.type == SHELL_TOKEN_SEMICOLON &&
        (token.start[0] == '\n'))
      continue;
    if (command_start && semantic_token_is_pipeline_prefix(
                             input, input_length, &token, &pipeline_prefix))
      continue;
    if (command_start)
      pipeline_prefix.has_stage = true;
    if (redirect_operand_end != 0 && token.position < redirect_operand_end)
      continue;
    redirect_operand_end = 0;
    if (token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_PIPE_BOTH ||
        token.type == SHELL_TOKEN_SEMICOLON ||
        token.type == SHELL_TOKEN_CASE_TERMINATE ||
        token.type == SHELL_TOKEN_CASE_FALLTHROUGH ||
        token.type == SHELL_TOKEN_CASE_TEST_NEXT ||
        token.type == SHELL_TOKEN_AND || token.type == SHELL_TOKEN_OR ||
        token.type == SHELL_TOKEN_BACKGROUND) {
      command_start = true;
      pipeline_prefix = semantic_pipeline_prefix_initial();
      if (token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_PIPE_BOTH)
        pipeline_prefix.eligible = false;
      continue;
    }
    if (token.type == SHELL_TOKEN_GROUP_START ||
        token.type == SHELL_TOKEN_SUBSHELL_START) {
      command_start = true;
      pipeline_prefix = semantic_pipeline_prefix_initial();
      continue;
    }
    if (token.type == SHELL_TOKEN_GROUP_END ||
        token.type == SHELL_TOKEN_SUBSHELL_END) {
      command_start = false;
      pipeline_prefix = (semantic_pipeline_prefix_t){0};
      continue;
    }
    if (full_token_is_redirection(&token)) {
      redirect_operand_end = full_redirect_end(input, input_length, &token);
      command_start = false;
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
          frame->case_selector_seen && keyword == SHELL_KEYWORD_IN) {
        frame->body_started = true;
        saw_control = true;
        continue;
      }
      if (!command_start) {
        if (!frame->body_started &&
            ((frame->type == CONTROL_FRAME_IF &&
              (keyword == SHELL_KEYWORD_THEN || keyword == SHELL_KEYWORD_ELIF ||
               keyword == SHELL_KEYWORD_ELSE)) ||
             (frame->type == CONTROL_FRAME_LOOP &&
              keyword == SHELL_KEYWORD_DO)))
          frame->misplaced_marker = true;
        continue;
      }
      if (frame->type == CONTROL_FRAME_IF &&
          (keyword == SHELL_KEYWORD_THEN || keyword == SHELL_KEYWORD_ELIF ||
           keyword == SHELL_KEYWORD_ELSE)) {
        frame->body_started = true;
        frame->misplaced_marker = false;
        saw_control = true;
        continue;
      }
      if (frame->type == CONTROL_FRAME_LOOP && keyword == SHELL_KEYWORD_DO) {
        frame->body_started = true;
        frame->misplaced_marker = false;
        saw_control = true;
        continue;
      }
      if ((frame->type == CONTROL_FRAME_IF && keyword == SHELL_KEYWORD_FI) ||
          (frame->type == CONTROL_FRAME_LOOP &&
           keyword == SHELL_KEYWORD_DONE) ||
          (frame->type == CONTROL_FRAME_CASE &&
           keyword == SHELL_KEYWORD_ESAC)) {
        frame_count--;
        saw_control = true;
        continue;
      }
    }
    if (!command_start)
      continue;

    if (control_token_starts_function_definition(&token, input, input_length) ||
        (keyword == SHELL_KEYWORD_FUNCTION &&
         control_function_keyword_has_name(&token, input, input_length)))
      return SHELL_CONTROL_SYNTAX_COMPLETE;

    control_frame_t frame;
    bool push_frame = false;
    if (keyword == SHELL_KEYWORD_IF) {
      frame = CONTROL_FRAME_IF;
      push_frame = true;
    } else if (keyword == SHELL_KEYWORD_WHILE ||
               keyword == SHELL_KEYWORD_UNTIL || keyword == SHELL_KEYWORD_FOR ||
               keyword == SHELL_KEYWORD_SELECT) {
      frame = CONTROL_FRAME_LOOP;
      push_frame = true;
    } else if (keyword == SHELL_KEYWORD_COPROC) {
      /* Bash coprocesses introduce a concurrently executing command and a
       * pair of implicit descriptors.  The semantic command model does not
       * represent either yet, so reject them explicitly rather than treating
       * `coproc` as an ordinary executable name. */
      return SHELL_CONTROL_SYNTAX_COMPLETE;
    } else if (keyword == SHELL_KEYWORD_CASE) {
      frame = CONTROL_FRAME_CASE;
      push_frame = true;
    } else if (keyword == SHELL_KEYWORD_THEN || keyword == SHELL_KEYWORD_ELIF ||
               keyword == SHELL_KEYWORD_ELSE || keyword == SHELL_KEYWORD_FI ||
               keyword == SHELL_KEYWORD_DO || keyword == SHELL_KEYWORD_DONE ||
               keyword == SHELL_KEYWORD_IN || keyword == SHELL_KEYWORD_ESAC) {
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
    /* Any first simple-command word, including an assignment prefix, consumes
     * reserved-word eligibility. This diagnostic walk has no argv[0] duties. */
    command_start = false;
  }
  for (size_t i = 0; i < frame_count; i++)
    if (frames[i].body_started || frames[i].misplaced_marker)
      return SHELL_CONTROL_SYNTAX_INCOMPLETE;
  return saw_control ? SHELL_CONTROL_SYNTAX_COMPLETE
                     : SHELL_CONTROL_SYNTAX_NONE;
}

/* Shellsplit does not model control-flow execution. Use the full lexical
 * tokenizer instead of raw source scans so words in comments, quoted text,
 * escapes, redirect operands, adjacent word fragments, and ordinary argument
 * positions are not mistaken for reserved control words. */
shell_control_syntax_t shell_tokenizer_control_syntax(const char *input,
                                                      size_t input_length) {
  if (!input)
    return SHELL_CONTROL_SYNTAX_NONE;
  shell_source_scope_t previous = shell_source_scope_begin(input, input_length);
  shell_control_syntax_t result = control_syntax_scan_impl(input, input_length);
  shell_source_scope_end(previous);
  return result;
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
  if (!shell_tokenizer_init(&state, input, input_length, NULL))
    return false;

  shell_token_t prefix[16];
  size_t prefix_count = 0;
  shell_token_t token;
  while (shell_tokenizer_next(&state, &token)) {
    if (token.type == SHELL_TOKEN_GROUP_START &&
        full_tokens_are_redirect_prefix(prefix, prefix_count))
      return true;
    if (token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_PIPE_BOTH ||
        token.type == SHELL_TOKEN_SEMICOLON || token.type == SHELL_TOKEN_AND ||
        token.type == SHELL_TOKEN_OR || token.type == SHELL_TOKEN_BACKGROUND) {
      prefix_count = 0;
      continue;
    }
    if (prefix_count == sizeof(prefix) / sizeof(prefix[0]))
      return false;
    prefix[prefix_count++] = token;
  }
  return false;
}

static bool full_tokens_need_redirect_operand(const char *input,
                                              size_t input_length,
                                              const shell_token_t *tokens,
                                              size_t count,
                                              const shell_token_t *next) {
  /* The lexer can emit several adjacent tokens for one operand, notably a
   * process substitution followed by literal text. None starts a new command.
   */
  for (size_t i = count; i > 0; i--) {
    if (!full_token_is_redirection(&tokens[i - 1]))
      continue;
    size_t redirect_end =
        full_redirect_end(input, input_length, &tokens[i - 1]);
    return redirect_end != 0 && next->position < redirect_end;
  }
  return false;
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
  if (!shell_tokenizer_init(&state, input, input_length, NULL))
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

typedef struct {
  bool needs_stage;
  bool pipeline_start;
  shell_pipeline_prefix_state_t prefix;
  /* Lexical assignment eligibility differs from reserved-word eligibility:
   * leading assignments/redirects still leave the command name pending.
   * Declaration syntax requires a literal unquoted command spelling, not a
   * runtime or quote-removed builtin identity. Each word is classified once. */
  bool assignment_prefix_open, declaration_operands;
  size_t word_end;
  /* True only after a real list terminator completed the preceding stage.
   * An otherwise empty `time` prefix may end at top-level EOF, but it may not
   * use a containing `)` as an implicit terminator. */
  bool may_end;
  /* A redirect's operand is one shell word. Only inline whitespace and an
   * escaped physical line ending may intervene; an ordinary newline or
   * comment starts a new list context instead of supplying that word. */
  bool redirect_operand;
  size_t redirect_operator_end;
  /* A compound command is a complete pipeline stage, but POSIX permits a
   * trailing redirect list before the next list operator.  Keep that narrow
   * grammar state separate from an ordinary completed command: an unquoted
   * word after `}` or `)` is not a new command without a separator. */
  bool after_group;
  bool group_redirect_operand;
  bool group_redirect_word_open;
  size_t group_redirect_word_end;
  size_t group_redirect_operator_end;
} shell_list_state_t;

typedef struct {
  shell_list_state_t parent;
  shell_token_type_t opening_type;
  size_t opening_position;
} shell_list_group_state_t;

static shell_list_state_t shell_list_state_initial(void) {
  return (shell_list_state_t){
      .needs_stage = true,
      .pipeline_start = true,
      .assignment_prefix_open = true,
      .prefix = shell_pipeline_prefix_state_initial(true),
      .may_end = false,
      .redirect_operand = false,
      .redirect_operator_end = 0,
      .after_group = false,
      .group_redirect_operand = false,
      .group_redirect_word_open = false,
      .group_redirect_word_end = 0,
      .group_redirect_operator_end = 0,
  };
}

static bool shell_list_token_is_newline(const shell_token_t *token) {
  return token->type == SHELL_TOKEN_SEMICOLON && token->length != 0 &&
         (token->start[0] == '\n');
}

static shell_pipeline_prefix_word_t
full_pipeline_prefix_word(const char *input, size_t input_length,
                          const shell_token_t *token) {
  if (token->type == SHELL_TOKEN_PIPE_NEGATE)
    return SHELL_PIPE_PREFIX_WORD_NEGATE;
  if (token_is_plain_word(input, input_length, token, "time"))
    return SHELL_PIPE_PREFIX_WORD_TIME;
  if (token_is_plain_word(input, input_length, token, "-p"))
    return SHELL_PIPE_PREFIX_WORD_POSIX;
  if (token_is_plain_word(input, input_length, token, "--"))
    return SHELL_PIPE_PREFIX_WORD_END_OPTIONS;
  return SHELL_PIPE_PREFIX_WORD_OTHER;
}

bool shell_tokenizer_compound_prefix_span(const char *input,
                                          size_t input_length, size_t start,
                                          size_t *prefix_end) {
  if (prefix_end)
    *prefix_end = 0;
  if (!input || !prefix_end || start > input_length)
    return false;
  shell_source_pipeline_prefix_t prefix =
      shell_source_parse_pipeline_prefix(input, start, input_length);
  if (!prefix.valid || !prefix.has_modifier || prefix.prefix_start != start ||
      prefix.stage_start >= input_length ||
      (input[prefix.stage_start] != '{' && input[prefix.stage_start] != '('))
    return false;
  *prefix_end = prefix.stage_start;
  return true;
}

/* Escapes belong to the token which consumed them. In particular, a raw LF
 * emitted after a skipped comment is structural even if the comment ends in
 * backslash. Continuation-only escapes do not quote an operator. */
static SHELL_NONNULL(1) bool shell_list_token_has_noncontinuation_escape(
    const shell_token_t *token) {
  for (size_t position = 0; position < token->length;) {
    if (token->start[position] != '\\') {
      position++;
      continue;
    }
    size_t continued = shell_source_skip_escaped_line_endings(
        token->start, token->length, position);
    if (continued == position)
      return true;
    position = continued;
  }
  return false;
}

bool shell_token_is_literal(const shell_token_t *token) {
  return token->is_quoted ||
         (token->is_escaped &&
          shell_list_token_has_noncontinuation_escape(token));
}

/* Control-compound detection deliberately tolerates incomplete syntax so a
 * semantic caller can report it as unsupported. It must not bypass the shell
 * grammar rule for redirect operands: only horizontal whitespace and escaped
 * physical line endings can separate an operator from its shell word. */
static bool full_redirect_operands_have_inline_boundaries(const char *input,
                                                          size_t input_length) {
  shell_tokenizer_state_t tokenizer;
  if (!shell_tokenizer_init(&tokenizer, input, input_length, NULL))
    return false;

  bool operand_pending = false;
  size_t operator_end = 0;
  shell_token_t token;
  while (shell_tokenizer_next(&tokenizer, &token)) {
    bool literal_token = shell_token_is_literal(&token);
    if (shell_source_is_escaped_line_ending(input, token.position,
                                            token.position + token.length))
      continue;

    if (operand_pending) {
      if (shell_list_token_is_newline(&token) ||
          (token.position != operator_end &&
           shell_source_skip_inline_continuations(
               input, token.position, operator_end) != token.position))
        return false;
      if (!literal_token &&
          (full_token_is_redirection(&token) ||
           token.type == SHELL_TOKEN_GROUP_END ||
           token.type == SHELL_TOKEN_SUBSHELL_END ||
           token.type == SHELL_TOKEN_PIPE ||
           token.type == SHELL_TOKEN_PIPE_BOTH ||
           token.type == SHELL_TOKEN_AND || token.type == SHELL_TOKEN_OR ||
           token.type == SHELL_TOKEN_SEMICOLON ||
           token.type == SHELL_TOKEN_BACKGROUND ||
           token.type == SHELL_TOKEN_GROUP_START ||
           token.type == SHELL_TOKEN_SUBSHELL_START))
        return false;
      operand_pending = false;
    }

    if (!literal_token && full_token_is_redirection(&token)) {
      operand_pending = full_redirection_consumes_next(&token);
      operator_end = token.position + token.length;
    }
  }
  /* The lexer retains a malformed heredoc token for diagnostics, but the
   * shared syntax boundary must not let its following bytes impersonate a
   * separate shell word. This is observable for `<<-#comment`: the optional
   * dash is part of the operator, so the raw hash still starts a comment. */
  return !operand_pending && !tokenizer.heredoc_error;
}

/* This validates only the token-level list grammar shared by Shellsplit's
 * public parsers. Redirections count as a complete simple-command stage,
 * because a redirect-only command is valid shell syntax. */
typedef enum {
  SHELL_LIST_END_TOP_LEVEL,
  SHELL_LIST_END_PARENTHESIZED,
  SHELL_LIST_END_RECEIVED,
  SHELL_LIST_END_RECEIVED_CHILD,
} shell_list_end_context_t;

static bool
shell_tokenizer_list_syntax_valid_impl(const char *input, size_t input_length,
                                       shell_list_end_context_t end_context,
                                       size_t recursion_depth,
                                       bool require_complete);

static bool shell_list_validate_substitution_content(
    const char *input, size_t input_length, size_t start, size_t after,
    shell_source_substitution_kind_t kind, size_t recursion_depth,
    bool require_complete) {
  if (!input || start >= after || after > input_length)
    return false;
  size_t content_start = start + 1;
  if (kind != SHELL_SOURCE_SUBST_BACKTICK) {
    size_t open = 0;
    bool valid = (kind == SHELL_SOURCE_SUBST_COMMAND &&
                  shell_source_dollar_parentheses_open(input, input_length,
                                                       start, &open)) ||
                 ((kind == SHELL_SOURCE_SUBST_PROCESS_INPUT ||
                   kind == SHELL_SOURCE_SUBST_PROCESS_OUTPUT) &&
                  shell_source_process_substitution_open(input, input_length,
                                                         start, &open));
    if (!valid)
      return false;
    content_start = open + 1;
  }
  if (content_start >= after)
    return false;
  size_t content_length = after - content_start - 1;
  shell_list_end_context_t nested_context = kind == SHELL_SOURCE_SUBST_BACKTICK
                                                ? SHELL_LIST_END_TOP_LEVEL
                                                : SHELL_LIST_END_PARENTHESIZED;
  return shell_tokenizer_list_syntax_valid_impl(
      input + content_start, content_length, nested_context,
      recursion_depth + 1, require_complete);
}

static SHELL_NONNULL(1) bool shell_list_validate_expansion_span(
    const char *input, size_t input_length, size_t recursion_depth,
    bool require_complete, bool heredoc, bool arithmetic) {
  if (recursion_depth >= SHELL_MAX_SUBCOMMANDS)
    return false;
  shell_source_substitution_scan_t scan = {
      .scope = {.heredoc = heredoc,
                .suppress_process = heredoc || arithmetic,
                .arithmetic_scope = arithmetic}};
  size_t start = 0;
  size_t after = 0;
  shell_source_substitution_kind_t kind;
  shell_source_scan_status_t scan_status;
  while ((scan_status = shell_source_next_executable_substitution(
              input, input_length, &scan, &start, &after, &kind)) ==
         SHELL_SOURCE_SCAN_FOUND) {
    if (!shell_list_validate_substitution_content(input, input_length, start,
                                                  after, kind, recursion_depth,
                                                  require_complete))
      return false;
  }
  /* Diagnostic iteration deliberately tolerates unfinished source words. */
  return !require_complete || scan_status == SHELL_SOURCE_SCAN_DONE;
}

static SHELL_NONNULL(1) bool shell_list_validate_substitution_span(
    const char *input, size_t input_length, size_t recursion_depth,
    bool require_complete) {
  return shell_list_validate_expansion_span(
      input, input_length, recursion_depth, require_complete, false, false);
}

/* Only the root quoting policy differs; nested operands retain scoped syntax.
 * No complete parameter suffix is balanced and then recursively revisited. */
static SHELL_NONNULL(1) bool shell_list_validate_heredoc_body_substitutions(
    const char *input, size_t input_length, size_t recursion_depth,
    bool require_complete) {
  return shell_list_validate_expansion_span(
      input, input_length, recursion_depth, require_complete, true, false);
}

typedef struct {
  size_t recursion_depth;
  bool require_complete;
  bool valid;
} shell_list_heredoc_validation_t;

static bool shell_list_validate_heredoc_body(const char *input,
                                             size_t body_start,
                                             size_t body_length,
                                             bool delimiter_quoted,
                                             void *context) {
  shell_list_heredoc_validation_t *validation = context;
  if (!input || !validation)
    return false;
  if (delimiter_quoted)
    return true;
  validation->valid = shell_list_validate_heredoc_body_substitutions(
      input + body_start, body_length, validation->recursion_depth,
      validation->require_complete);
  return validation->valid;
}

static bool shell_list_validate_substitutions(const char *input,
                                              size_t input_length,
                                              size_t recursion_depth,
                                              bool require_complete) {
  if (!input || recursion_depth >= SHELL_MAX_SUBCOMMANDS)
    return false;
  shell_tokenizer_state_t tokenizer;
  if (!shell_tokenizer_init(&tokenizer, input, input_length, NULL))
    return false;
  size_t heredoc_sequence_after = 0;
  shell_token_t token;
  while (shell_tokenizer_next(&tokenizer, &token)) {
    if (token.position > input_length ||
        token.length > input_length - token.position)
      return false;
    if (token.type == SHELL_TOKEN_CONDITIONAL_COMMAND) {
      /* The compound token includes grammar and comments. Only its operands
       * are word-expansion spans; conditional parsing owns the trivia. */
      shell_conditional_t condition =
          shell_conditional_parse(input, input_length, token.position);
      for (unsigned operand = 0; operand < condition.operand_count; ++operand)
        if (condition.operand_lengths[operand] &&
            !shell_list_validate_substitution_span(
                input + condition.operands[operand],
                condition.operand_lengths[operand], recursion_depth,
                require_complete))
          return false;
      continue;
    }
    if (token.type != SHELL_TOKEN_HEREDOC) {
      if (!shell_list_validate_substitution_span(
              token.start, token.length, recursion_depth, require_complete))
        return false;
      continue;
    }
    if (token.position < heredoc_sequence_after)
      continue;
    size_t operator_position = 0;
    size_t after = input_length;
    bool complete = false;
    shell_list_heredoc_validation_t validation = {
        .recursion_depth = recursion_depth,
        .require_complete = require_complete,
        .valid = true,
    };
    if (!heredoc_token_operator_position(&token, &operator_position) ||
        !shell_source_visit_heredoc_sequence(
            input, input_length, operator_position,
            shell_list_validate_heredoc_body, &validation, &after, &complete) ||
        !validation.valid || (require_complete && !complete))
      return false;
    /* Only diagnostic iteration may retain an unfinished document at EOF. */
    heredoc_sequence_after = after;
  }
  return !require_complete ||
         !(tokenizer.in_quotes || tokenizer.in_subshell ||
           tokenizer.paren_depth || tokenizer.brace_depth ||
           tokenizer.brace_group_depth || tokenizer.in_arithmetic ||
           tokenizer.in_conditional || tokenizer.conditional_invalid ||
           tokenizer.arith_depth || tokenizer.heredoc_error);
}

/* Both ordinary terminators and an empty timed newline complete a list unit.
 * Never qualify a partial binary list, enclosing group, or pending document. */
static void shell_list_draft_checkpoint(shell_source_draft_state_t *draft,
                                        size_t group_count, bool may_end,
                                        size_t pending_documents,
                                        size_t position) {
  if (draft && group_count == 0 && may_end && pending_documents == 0 &&
      (draft->need == SHELL_SOURCE_NEEDS_NONE ||
       position <= draft->incomplete_at))
    draft->prefix_length = (uint32_t)position;
}

static SHELL_NONNULL(1) bool shell_tokenizer_list_syntax_valid_body(
    const char *input, size_t input_length,
    shell_list_end_context_t end_context, size_t recursion_depth,
    bool require_complete, shell_source_draft_state_t *draft) {
  bool can_append = end_context == SHELL_LIST_END_RECEIVED ||
                    end_context == SHELL_LIST_END_RECEIVED_CHILD;
  if (!draft && !shell_list_validate_substitutions(
                    input, input_length, recursion_depth, require_complete))
    return false;

  if (!draft &&
      !full_redirect_operands_have_inline_boundaries(input, input_length))
    return false;
  /* Control compounds have their own list grammar (notably `case` uses `;;`).
   * They remain lexically representable so canonical APIs can reject them as
   * unsupported. Classify them before brace validation: a text-only `then` or
   * `do` must never be mistaken for structural syntax in an ordinary command.
   */
  /* Drafts classify reserved words in the walk below: received EOF can still
   * extend `if` to `ifx`, whereas a closed child has a committed final word. */
  shell_control_syntax_t control =
      draft ? SHELL_CONTROL_SYNTAX_NONE
            : shell_tokenizer_control_syntax(input, input_length);
  if (control != SHELL_CONTROL_SYNTAX_NONE)
    return !require_complete || control == SHELL_CONTROL_SYNTAX_COMPLETE;
  if (!draft && !brace_groups_valid(input, input_length))
    return false;
  if (!draft && (full_has_bare_redirect_group_operand(input, input_length) ||
                 full_has_redirect_prefix_group(input, input_length)))
    return false;

  shell_tokenizer_state_t tokenizer;
  if (!shell_tokenizer_init(&tokenizer, input, input_length, NULL))
    return false;

  shell_list_state_t state = shell_list_state_initial();
  shell_list_group_state_t groups[SHELL_MAX_GROUPS];
  size_t group_count = 0;
  bool saw_token = false;
  size_t last_position = 0;
  shell_token_t token;
  while (shell_tokenizer_next(&tokenizer, &token)) {
    /* An unfinished word suspends grammar only where a word is permitted.
     * A fresh compound tail must first prove a redirector role; a quote or
     * substitution cannot hide an otherwise impossible ordinary argument. */
    if (draft && token.position >= draft->incomplete_at &&
        (draft->need == SHELL_SOURCE_NEEDS_QUOTE ||
         draft->need == SHELL_SOURCE_NEEDS_ESCAPE ||
         draft->need == SHELL_SOURCE_NEEDS_SUBSTITUTION) &&
        (!state.after_group || state.group_redirect_operand ||
         (state.group_redirect_word_open &&
          token.position == state.group_redirect_word_end)))
      break;
    bool literal_token = shell_token_is_literal(&token);

    /* Reuse subscript boundaries only where this lexical role can own an
     * assignment. Ordinary words must not trigger whole-suffix lookahead. */
    bool array_candidate =
        !state.after_group && !state.redirect_operand &&
        token.position >= state.word_end && control_token_is_word(&token) &&
        (state.assignment_prefix_open || state.declaration_operands);
    size_t array_end = 0;
    /* Escapes inside a subscript/body do not quote its outer assignment
     * spelling. Recognize that spelling rather than using a whole-token flag.
     */
    array_word_t array =
        array_candidate
            ? array_assignment_probe(input, input_length, token.position,
                                     state.assignment_prefix_open, &array_end)
            : ARRAY_WORD_NONE;
    if (array == ARRAY_WORD_COMPOUND ||
        (draft && array == ARRAY_WORD_UNCLASSIFIED)) {
      /* Array recovery is not modeled. An unresolved subscript cannot prove
       * an outer group/list error, and cannot qualify a recovery prefix. */
      if (draft)
        draft->failure = SHELL_SOURCE_UNSUPPORTED;
      if (draft)
        return false;
    }
    bool redirect_word = state.redirect_operand;

    /* Diagnostic lexing keeps an unmatched '}' as a word, including in
     * unsupported function syntax. In modeled list grammar its reserved
     * command-position role nevertheless proves an unmatched close. */
    if (draft && !literal_token && state.needs_stage &&
        token_is_plain_word(input, input_length, &token, "}"))
      return false;

    /* Case terminators are not separators in an ordinary command list.
     * Actual control constructs took their diagnostic path above. Reject a
     * bare clause operator here even if there is no command to allocate. */
    if (draft && !literal_token && state.needs_stage &&
        token_starts_bash_compound_command(&token, input, input_length)) {
      size_t word_end;
      bool pending_keyword = can_append &&
                             shell_source_keyword(input, input_length,
                                                  token.position, &word_end) &&
                             word_end == input_length;
      if (!pending_keyword) {
        draft->failure = SHELL_SOURCE_UNSUPPORTED;
        return false;
      }
    }
    if (!literal_token && (token.type == SHELL_TOKEN_CASE_TERMINATE ||
                           token.type == SHELL_TOKEN_CASE_FALLTHROUGH ||
                           token.type == SHELL_TOKEN_CASE_TEST_NEXT))
      return false;

    /* The iterator retains source spans, so a bare escaped line ending can
     * appear as an argument token. It is grammar rather than a command word
     * in every list state. */
    if (shell_source_is_escaped_line_ending(input, token.position,
                                            token.position + token.length))
      continue;
    /* Removed continuations cannot replace the pending operator's diagnostic
     * location when EOF arrives before its operand. */
    last_position = token.position;
    /* Leading/newline-only trivia is not a pending stage. In particular an
     * empty substitution body may contain line endings without making its
     * closing parenthesis satisfy a missing command after &&, |, or !. */
    saw_token |= !shell_list_token_is_newline(&token);

    /* Simple and compound-tail redirects share this received-word boundary:
     * a final logical < or > can still become <(...) or >(...) by appending
     * `(`. Removed continuations preserve that possibility; a final backslash
     * can still acquire LF. Blanks after the punctuation rule it out. */
    if (draft && (state.redirect_operand || state.group_redirect_operand) &&
        !literal_token && (token.start[0] == '<' || token.start[0] == '>')) {
      size_t following =
          shell_source_logical_following(input, input_length, token.position);
      if (following == input_length) {
        draft->need = SHELL_SOURCE_NEEDS_SUBSTITUTION;
        draft->incomplete_at = (uint32_t)token.position;
        break;
      }
      if (following == input_length - 1 && input[following] == '\\') {
        draft->need = SHELL_SOURCE_NEEDS_ESCAPE;
        draft->incomplete_at = (uint32_t)following;
        break;
      }
    }
    if (state.redirect_operand) {
      /* The next lexer token begins exactly at the operator end for a raw
       * line break, so a gap-only check cannot distinguish it from an
       * adjacent operand.  A physical line ending terminates the command; it
       * never supplies a redirect word. Escaped line endings were consumed
       * above and therefore remain valid continuations. */
      if (shell_list_token_is_newline(&token))
        return false;
      if (token.position != state.redirect_operator_end &&
          shell_source_skip_inline_continuations(input, token.position,
                                                 state.redirect_operator_end) !=
              token.position)
        return false;
      /* Operators are complete longest-match tokens. An adjacent operator
       * cannot replace this operator's missing shell-word operand. */
      if (!literal_token &&
          (full_token_is_redirection(&token) ||
           token.type == SHELL_TOKEN_GROUP_END ||
           token.type == SHELL_TOKEN_SUBSHELL_END ||
           token.type == SHELL_TOKEN_PIPE ||
           token.type == SHELL_TOKEN_PIPE_BOTH ||
           token.type == SHELL_TOKEN_AND || token.type == SHELL_TOKEN_OR ||
           token.type == SHELL_TOKEN_SEMICOLON ||
           token.type == SHELL_TOKEN_BACKGROUND ||
           token.type == SHELL_TOKEN_GROUP_START ||
           token.type == SHELL_TOKEN_SUBSHELL_START))
        return false;
      state.redirect_operand = false;
      state.redirect_operator_end = 0;
    }

    /* After a brace group or subshell, accept only its redirect list, a list
     * separator, or a containing-group close.  In particular, reject the
     * otherwise tempting but invalid `{ echo; } echo` spelling. */
    if (state.after_group) {
      if (state.group_redirect_word_open &&
          token.position != state.group_redirect_word_end)
        state.group_redirect_word_open = false;
      if (state.group_redirect_word_open &&
          !full_token_is_redirection(&token) &&
          token.type != SHELL_TOKEN_GROUP_START &&
          token.type != SHELL_TOKEN_SUBSHELL_START &&
          token.type != SHELL_TOKEN_GROUP_END &&
          token.type != SHELL_TOKEN_SUBSHELL_END &&
          token.type != SHELL_TOKEN_PIPE &&
          token.type != SHELL_TOKEN_PIPE_BOTH &&
          token.type != SHELL_TOKEN_AND && token.type != SHELL_TOKEN_OR &&
          token.type != SHELL_TOKEN_SEMICOLON &&
          token.type != SHELL_TOKEN_BACKGROUND) {
        state.group_redirect_word_end = token.position + token.length;
        continue;
      }
      if (state.group_redirect_operand) {
        if (!literal_token &&
            (full_token_is_redirection(&token) ||
             token.type == SHELL_TOKEN_GROUP_START ||
             token.type == SHELL_TOKEN_SUBSHELL_START ||
             token.type == SHELL_TOKEN_GROUP_END ||
             token.type == SHELL_TOKEN_SUBSHELL_END ||
             token.type == SHELL_TOKEN_PIPE ||
             token.type == SHELL_TOKEN_PIPE_BOTH ||
             token.type == SHELL_TOKEN_AND || token.type == SHELL_TOKEN_OR ||
             token.type == SHELL_TOKEN_SEMICOLON ||
             token.type == SHELL_TOKEN_BACKGROUND))
          return false;
        state.group_redirect_operand = false;
        state.group_redirect_word_open = true;
        state.group_redirect_word_end = token.position + token.length;
        continue;
      }
      if (full_token_is_redirection(&token)) {
        state.group_redirect_operand = full_redirection_consumes_next(&token);
        state.group_redirect_word_open = false;
        state.group_redirect_operator_end = token.position + token.length;
        continue;
      }
      /* Received EOF has not committed a new redirector's lexical role.
       * Closed children cannot gain an operator outside their delimiter. */
      if (draft && can_append) {
        size_t at;
        shell_source_fd_prefix_t prefix = shell_source_pending_fd_prefix(
            input, token.position, input_length, &at);
        if (prefix != SHELL_SOURCE_FD_PREFIX_NONE) {
          draft->need = prefix == SHELL_SOURCE_FD_PREFIX_ESCAPE
                            ? SHELL_SOURCE_NEEDS_ESCAPE
                            : SHELL_SOURCE_NEEDS_REDIRECT;
          draft->incomplete_at = (uint32_t)at;
          break;
        }
      }
      if (literal_token ||
          (token.type != SHELL_TOKEN_GROUP_END &&
           token.type != SHELL_TOKEN_SUBSHELL_END &&
           token.type != SHELL_TOKEN_PIPE &&
           token.type != SHELL_TOKEN_PIPE_BOTH &&
           token.type != SHELL_TOKEN_AND && token.type != SHELL_TOKEN_OR &&
           token.type != SHELL_TOKEN_SEMICOLON &&
           token.type != SHELL_TOKEN_BACKGROUND))
        return false;
      /* A containing-group closer is handled below.  Separators clear this
       * state through their ordinary transition. */
    }
    if (token.type == SHELL_TOKEN_CONDITIONAL_COMMAND) {
      if (!state.needs_stage || state.redirect_operand)
        return false;
      shell_conditional_t condition =
          shell_conditional_parse(input, input_length, token.position);
      if (condition.frame == SHELL_CONDITIONAL_UNSUPPORTED) {
        if (draft)
          draft->failure = SHELL_SOURCE_UNSUPPORTED;
        return false;
      }
      if (condition.frame == SHELL_CONDITIONAL_INVALID)
        return false;
      if (condition.frame == SHELL_CONDITIONAL_INCOMPLETE) {
        if (!draft)
          return !require_complete;
        draft->need = SHELL_SOURCE_NEEDS_CONDITIONAL;
        draft->incomplete_at = (uint32_t)token.position;
        break;
      }
      for (unsigned operand = 0; operand < condition.operand_count; ++operand)
        if (!shell_list_validate_expansion_span(
                input + condition.operands[operand],
                condition.operand_lengths[operand], recursion_depth,
                require_complete, false, false))
          return false;
      state.needs_stage = false;
      state.pipeline_start = false;
      state.assignment_prefix_open = false;
      state.after_group = true;
      continue;
    }
    if (token.type == SHELL_TOKEN_ARITHMETIC_COMMAND) {
      if (!state.needs_stage || state.redirect_operand)
        return false;
      if (tokenizer.in_arithmetic) {
        if (!draft)
          return !require_complete;
        draft->need = SHELL_SOURCE_NEEDS_ARITHMETIC;
        draft->incomplete_at = (uint32_t)token.position;
        break;
      }
      const char *content;
      size_t content_length;
      shell_tokenizer_arithmetic_content(&token, true, &content,
                                         &content_length);
      if (!shell_list_validate_expansion_span(content, content_length,
                                              recursion_depth, require_complete,
                                              false, true))
        return false;
      state.needs_stage = false;
      state.pipeline_start = false;
      state.assignment_prefix_open = false;
      state.after_group = true;
      continue;
    }
    if (!literal_token && (token.type == SHELL_TOKEN_GROUP_START ||
                           token.type == SHELL_TOKEN_SUBSHELL_START)) {
      /* A compound command begins a pipeline stage; it cannot be appended to
       * an already complete simple command (`echo (cmd)`). Command
       * substitutions are opaque word tokens. A raw preceding '$' does not
       * prove substitution: it may have been escaped. */
      if (!state.needs_stage)
        return false;
      if (group_count == SHELL_MAX_GROUPS) {
        if (draft)
          draft->failure = SHELL_SOURCE_TRUNCATED;
        return false;
      }
      groups[group_count++] = (shell_list_group_state_t){
          .parent = state,
          .opening_type = token.type,
          .opening_position = token.position,
      };
      state = shell_list_state_initial();
      continue;
    }

    if (!literal_token && (token.type == SHELL_TOKEN_GROUP_END ||
                           token.type == SHELL_TOKEN_SUBSHELL_END)) {
      if (group_count == 0)
        return false;
      shell_list_group_state_t group = groups[--group_count];
      if ((input[group.opening_position] == '(' && token.start[0] != ')') ||
          (input[group.opening_position] == '{' && token.start[0] != '}'))
        return false;
      /* `name()` is a function declaration marker, not an empty subshell.
       * Preserve its lexical classification while control-flow/function
       * semantics remain outside the canonical model. */
      bool empty_function_marker =
          group.opening_type == SHELL_TOKEN_GROUP_START &&
          group.opening_position + 1 == token.position &&
          !group.parent.needs_stage;
      if (state.needs_stage && !state.may_end && !empty_function_marker)
        return false;
      state = group.parent;
      state.needs_stage = false;
      state.pipeline_start = false;
      state.prefix = shell_pipeline_prefix_state_initial(false);
      state.may_end = false;
      state.redirect_operand = false;
      state.redirect_operator_end = 0;
      state.after_group = true;
      state.group_redirect_operand = false;
      state.group_redirect_word_open = false;
      state.group_redirect_word_end = 0;
      state.group_redirect_operator_end = 0;
      state.assignment_prefix_open = false;
      state.declaration_operands = false;
      state.word_end = 0;
      continue;
    }

    /* Outside a pending stage, ! follows the ordinary-word role transition
     * below. In particular a redirect/assignment prefix can leave argv[0]
     * pending while already excluding reserved pipeline syntax. */
    if (!literal_token && token.type == SHELL_TOKEN_PIPE_NEGATE &&
        state.needs_stage) {
      if (!state.pipeline_start)
        return false;
      if (shell_pipeline_prefix_step(&state.prefix,
                                     SHELL_PIPE_PREFIX_WORD_NEGATE) ==
          SHELL_PIPE_PREFIX_OVERFLOW)
        return false;
      /* Consuming a prefix starts a new pipeline. A preceding list separator
       * no longer permits EOF; empty timing has its own completion rule. */
      state.may_end = false;
      continue;
    }

    /* Lexical time recognition can return after continuation LF even while
     * the grammar still needs a post-pipe stage. That reserved word is not
     * an executable command named time, and Bash rejects it here. */
    if (!literal_token && state.needs_stage && !state.pipeline_start &&
        tokenizer.lexical_command_position &&
        token_is_plain_word(input, input_length, &token, "time"))
      return false;

    if (!literal_token && state.needs_stage && state.pipeline_start) {
      shell_pipeline_prefix_step_t step = shell_pipeline_prefix_step(
          &state.prefix,
          full_pipeline_prefix_word(input, input_length, &token));
      if (step == SHELL_PIPE_PREFIX_OVERFLOW)
        return false;
      if (step != SHELL_PIPE_PREFIX_NOT_ACCEPTED) {
        state.may_end = false;
        continue;
      }
    }

    if (!literal_token && token.type == SHELL_TOKEN_SEMICOLON &&
        shell_list_token_is_newline(&token) && state.needs_stage) {
      /* A binary connector continues across LF. Bash also admits a standalone
       * negation terminated by LF; that empty pipeline is not modeled. */
      if (state.prefix.negation_count != 0 &&
          state.prefix.time_mode == SHELL_PIPE_TIME_NONE) {
        if (draft)
          draft->failure = SHELL_SOURCE_UNSUPPORTED;
        return false;
      }
      if (state.prefix.time_mode != SHELL_PIPE_TIME_NONE) {
        state = shell_list_state_initial();
        state.may_end = true;
      }
      shell_list_draft_checkpoint(draft, group_count, state.may_end,
                                  tokenizer.pending_heredoc_count,
                                  tokenizer.position);
      continue;
    }

    if (!literal_token &&
        (token.type == SHELL_TOKEN_PIPE ||
         token.type == SHELL_TOKEN_PIPE_BOTH || token.type == SHELL_TOKEN_AND ||
         token.type == SHELL_TOKEN_OR || token.type == SHELL_TOKEN_SEMICOLON ||
         token.type == SHELL_TOKEN_BACKGROUND)) {
      bool ends_empty_timed_pipeline =
          state.needs_stage && state.prefix.time_mode != SHELL_PIPE_TIME_NONE &&
          (token.type == SHELL_TOKEN_SEMICOLON ||
           token.type == SHELL_TOKEN_BACKGROUND);
      if (state.needs_stage && !ends_empty_timed_pipeline) {
        if (draft && state.prefix.negation_count != 0 &&
            (token.type == SHELL_TOKEN_SEMICOLON ||
             token.type == SHELL_TOKEN_BACKGROUND))
          draft->failure = SHELL_SOURCE_UNSUPPORTED;
        return false;
      }
      state.needs_stage = true;
      state.pipeline_start =
          token.type != SHELL_TOKEN_PIPE && token.type != SHELL_TOKEN_PIPE_BOTH;
      state.prefix = shell_pipeline_prefix_state_initial(state.pipeline_start);
      state.may_end = token.type == SHELL_TOKEN_SEMICOLON ||
                      token.type == SHELL_TOKEN_BACKGROUND;
      shell_list_draft_checkpoint(draft, group_count, state.may_end,
                                  tokenizer.pending_heredoc_count,
                                  tokenizer.position);
      state.redirect_operand = false;
      state.redirect_operator_end = 0;
      state.after_group = false;
      state.group_redirect_operand = false;
      state.group_redirect_word_open = false;
      state.group_redirect_word_end = 0;
      state.group_redirect_operator_end = 0;
      state.assignment_prefix_open = true;
      state.declaration_operands = false;
      state.word_end = 0;
      continue;
    }

    if (draft && !literal_token && state.needs_stage &&
        !full_token_is_redirection(&token)) {
      size_t word_end;
      if (shell_source_keyword(input, input_length, token.position,
                               &word_end)) {
        if (word_end != input_length || !can_append) {
          draft->failure = SHELL_SOURCE_UNSUPPORTED;
          return false;
        }
        draft->need = SHELL_SOURCE_NEEDS_COMMAND;
        draft->incomplete_at = (uint32_t)token.position;
        return true;
      }
      if (control_token_starts_function_definition(&token, input,
                                                   input_length)) {
        draft->failure = SHELL_SOURCE_UNSUPPORTED;
        return false;
      }
    }
    if (!full_token_is_redirection(&token) &&
        token.position >= state.word_end) {
      size_t word_end;
      /* Scalar indexed-assignment tokens end at '='. Their value fragments
       * retain the same assignment role through the complete shell word. */
      if (!shell_tokenizer_word_end(input, input_length, &token, &word_end))
        /* Diagnostic tokenization may retain an unfinished word. Its
         * remaining fragments still consume one lexical role; completeness
         * belongs to the existing strict/draft validation boundaries. */
        word_end = input_length;
      state.word_end = word_end;
      if (!redirect_word && state.assignment_prefix_open) {
        shell_source_assignment_word_t assignment;
        bool assignment_word =
            token.type == SHELL_TOKEN_ARRAY_ASSIGNMENT ||
            shell_source_parse_scalar_assignment_word(
                input + token.position, word_end - token.position, &assignment);
        if (!assignment_word) {
          state.declaration_operands =
              token_is_plain_word(input, input_length, &token, "declare") ||
              token_is_plain_word(input, input_length, &token, "typeset") ||
              token_is_plain_word(input, input_length, &token, "local") ||
              token_is_plain_word(input, input_length, &token, "export") ||
              token_is_plain_word(input, input_length, &token, "readonly");
          state.assignment_prefix_open = false;
        }
      }
    }
    /* Bash's lexical declaration-operand eligibility ends at a redirection.
     * A leading redirect still leaves the first command word pending. */
    if (full_token_is_redirection(&token))
      state.declaration_operands = false;
    state.needs_stage = false;
    state.pipeline_start = false;
    state.prefix = shell_pipeline_prefix_state_initial(false);
    state.may_end = false;
    if (!literal_token && full_token_is_redirection(&token)) {
      state.redirect_operand = full_redirection_consumes_next(&token);
      state.redirect_operator_end = token.position + token.length;
    }
    state.after_group = false;
    state.group_redirect_operand = false;
    state.group_redirect_word_open = false;
    state.group_redirect_word_end = 0;
    state.group_redirect_operator_end = 0;
  }

  if (draft) {
    /* A pending document must not hide a separately proven grammar error in
     * a closed child. EOF may terminate its body, not a group or connector. */
    if (draft->heredoc_eof && !can_append &&
        (group_count || tokenizer.in_quotes || state.redirect_operand ||
         state.group_redirect_operand ||
         (saw_token && state.needs_stage && !state.may_end &&
          state.prefix.time_mode == SHELL_PIPE_TIME_NONE &&
          (state.prefix.negation_count == 0 ||
           end_context != SHELL_LIST_END_TOP_LEVEL))))
      return false;
    if (draft->need == SHELL_SOURCE_NEEDS_NONE) {
      if (tokenizer.heredoc_error) {
        draft->need = SHELL_SOURCE_NEEDS_HEREDOC_HEADER;
        draft->incomplete_at = (uint32_t)last_position;
      } else if (tokenizer.in_quotes) {
        draft->need = SHELL_SOURCE_NEEDS_QUOTE;
        draft->incomplete_at = (uint32_t)last_position;
      } else if (state.redirect_operand || state.group_redirect_operand) {
        size_t operator_end = state.redirect_operand
                                  ? state.redirect_operator_end
                                  : state.group_redirect_operator_end;
        size_t operand = shell_source_skip_inline_continuations(
            input, input_length, operator_end);
        /* A comment cannot acquire a redirect operand by appending another
         * line: that newline already terminates the missing-operand header. */
        if (operand < input_length && input[operand] == '#')
          return false;
        draft->need = SHELL_SOURCE_NEEDS_REDIRECT;
        draft->incomplete_at = (uint32_t)last_position;
      } else if (group_count) {
        draft->need = SHELL_SOURCE_NEEDS_GROUP;
        draft->incomplete_at = (uint32_t)groups[0].opening_position;
      } else if (saw_token && state.needs_stage && !state.may_end &&
                 state.prefix.time_mode == SHELL_PIPE_TIME_NONE) {
        if (state.prefix.negation_count != 0 &&
            (end_context == SHELL_LIST_END_RECEIVED ||
             end_context == SHELL_LIST_END_TOP_LEVEL)) {
          draft->failure = SHELL_SOURCE_UNSUPPORTED;
          return false;
        }
        draft->need = SHELL_SOURCE_NEEDS_COMMAND;
        draft->incomplete_at = (uint32_t)last_position;
      }
    }
    return true;
  }
  if (require_complete &&
      (group_count != 0 || tokenizer.in_quotes || tokenizer.in_subshell ||
       tokenizer.paren_depth != 0 || tokenizer.brace_depth != 0 ||
       tokenizer.brace_group_depth != 0 || tokenizer.in_arithmetic ||
       tokenizer.in_conditional || tokenizer.conditional_invalid ||
       tokenizer.arith_depth != 0 || tokenizer.heredoc_error))
    return false;
  /* The lexical API intentionally retains incomplete parenthesized prefixes
   * for diagnostics. Strict semantic callers reject them at this boundary. */
  if (!saw_token || group_count != 0)
    return true;
  if (state.redirect_operand || state.group_redirect_operand)
    return false;
  if (!state.needs_stage || state.may_end)
    return true;
  return end_context == SHELL_LIST_END_TOP_LEVEL &&
         state.prefix.time_mode != SHELL_PIPE_TIME_NONE;
}

static bool
shell_tokenizer_list_syntax_valid_impl(const char *input, size_t input_length,
                                       shell_list_end_context_t end_context,
                                       size_t recursion_depth,
                                       bool require_complete) {
  if (!input)
    return false;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_SYNTAX_BODIES);
#endif
  shell_source_scope_t previous = shell_source_scope_begin(input, input_length);
  bool valid = shell_tokenizer_list_syntax_valid_body(
      input, input_length, end_context, recursion_depth, require_complete,
      NULL);
  shell_source_scope_end(previous);
  return valid;
}

shell_source_status_t
shell_source_draft_grammar(const char *source, size_t length,
                           shell_source_draft_end_t end_context,
                           shell_source_draft_state_t *result) {
  shell_source_scope_t previous = shell_source_scope_begin(source, length);
  bool valid = shell_tokenizer_list_syntax_valid_body(
      source, length,
      end_context == SHELL_SOURCE_END_RECEIVED ? SHELL_LIST_END_RECEIVED
      : end_context == SHELL_SOURCE_END_OPEN_CHILD
          ? SHELL_LIST_END_RECEIVED_CHILD
      : end_context == SHELL_SOURCE_END_BACKTICK ? SHELL_LIST_END_TOP_LEVEL
                                                 : SHELL_LIST_END_PARENTHESIZED,
      0, false, result);
  shell_source_scope_end(previous);
  if (!valid)
    return result->failure == SHELL_SOURCE_COMPLETE ? SHELL_SOURCE_INVALID
                                                    : result->failure;
  return result->need == SHELL_SOURCE_NEEDS_NONE ? SHELL_SOURCE_COMPLETE
                                                 : SHELL_SOURCE_INCOMPLETE;
}

bool shell_tokenizer_list_syntax_valid(const char *input, size_t input_length) {
  shell_source_operation_begin(input ? input : "", input_length);
  bool valid = shell_tokenizer_list_syntax_valid_impl(
      input, input_length, SHELL_LIST_END_TOP_LEVEL, 0, false);
  shell_source_operation_end();
  return valid;
}

bool shell_tokenizer_complete_syntax_valid(const char *input,
                                           size_t input_length) {
  shell_source_operation_begin(input ? input : "", input_length);
  bool valid = shell_tokenizer_list_syntax_valid_impl(
      input, input_length, SHELL_LIST_END_TOP_LEVEL, 0, true);
  shell_source_operation_end();
  return valid;
}

/* commands owns count initialized slots. Growth is called only after the
 * initial allocation succeeds; the outer and inner pointers are required. */
static SHELL_NONNULL(1, 2) bool full_commands_append_slot(
    shell_command_t **commands, size_t *count) {
  if (*count == SIZE_MAX / sizeof(**commands))
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

/* Start a successor before retaining any of its syntax or words. The counting
 * pass is only a reservation hint: diagnostic group records can require an
 * additional slot. Allocate before advancing so failure leaves every owned
 * token buffer reachable through the existing records. */
static SHELL_NONNULL(1, 2, 3, 4) bool full_commands_start_record(
    shell_command_t **commands, size_t *capacity, size_t *index,
    const shell_tokenizer_state_t *state, size_t start, uint32_t negation_count,
    shell_pipeline_time_mode_t time_mode) {
  shell_token_t *tokens = malloc(16 * sizeof(*tokens));
  if (!tokens)
    return false;
  if (*index + 1 >= *capacity &&
      !full_commands_append_slot(commands, capacity)) {
    free(tokens);
    return false;
  }
  shell_command_t *command = &(*commands)[++*index];
  *command = (shell_command_t){
      .tokens = tokens,
      .start_pos = start,
      .end_pos = start,
      .group_depth = shell_tokenizer_group_depth(state),
      .group_kinds = state->group_kinds,
      .pipeline_negation_count = negation_count,
      .pipeline_negated = (negation_count & UINT32_C(1)) != 0,
      .pipeline_time_mode = time_mode,
  };
  return true;
}

/* Required output storage and a borrowed input span are caller preconditions.
 * This boundary still validates the external byte domain and list grammar. */
static SHELL_NONNULL(1, 3, 4) shell_tokenize_status_t
    shell_tokenize_commands_impl(const char *input, size_t input_length,
                                 shell_command_t **commands,
                                 size_t *command_count, bool allow_initial_time,
                                 bool require_complete,
                                 bool reject_unsupported) {
  *commands = NULL;
  *command_count = 0;
  if (!shell_source_bytes_valid(input, input_length))
    return SHELL_TOKENIZE_EINPUT;
  if (!(require_complete
            ? shell_tokenizer_complete_syntax_valid(input, input_length)
            : shell_tokenizer_list_syntax_valid(input, input_length)))
    return SHELL_TOKENIZE_EPARSE;
  if (reject_unsupported &&
      shell_tokenizer_has_unsupported_semantics(input, input_length))
    return SHELL_TOKENIZE_EPARSE;

  return shell_tokenize_prevalidated_commands(
      input, input_length, allow_initial_time, commands, command_count);
}

shell_tokenize_status_t shell_tokenize_prevalidated_commands(
    const char *input, size_t input_length, bool allow_initial_time,
    shell_command_t **commands, size_t *command_count) {
  *commands = NULL;
  *command_count = 0;

  shell_tokenizer_state_t state;
  shell_tokenizer_init_prechecked(&state, input, input_length);
  /* Sliced post-pipe stages retain their root parse's ordinary-word role.
   * Prefix metadata alone is insufficient: lexical brace recognition must
   * see that an initial executable named time already commits the command. */
  if (!allow_initial_time)
    state.lexical_prefix &= (uint8_t)~LEXICAL_TIME_MASK;

  size_t count = 0;
  bool expect_command = true;
  bool pipeline_start = true;
  shell_pipeline_prefix_state_t pipeline_prefix =
      shell_pipeline_prefix_state_initial(allow_initial_time);

  shell_tokenizer_state_t temp_state = state;
  shell_token_t token;

  while (shell_tokenizer_next(&temp_state, &token)) {
    /* The zero-copy iterator keeps escaped physical line endings in the
     * source stream. A standalone continuation never contributes a command
     * token or list separator. */
    if (shell_source_is_escaped_line_ending(input, token.position,
                                            token.position + token.length))
      continue;
    /* The supported-list boundary has already declined empty negation at LF.
     * Here a newline only continues a validated binary list operator. */
    if (expect_command && shell_list_token_is_newline(&token)) {
      if (pipeline_prefix.time_mode == SHELL_PIPE_TIME_NONE)
        continue;
    }
    if (pipeline_start) {
      shell_pipeline_prefix_step_t prefix_step = shell_pipeline_prefix_step(
          &pipeline_prefix,
          full_pipeline_prefix_word(input, input_length, &token));
      if (prefix_step == SHELL_PIPE_PREFIX_OVERFLOW)
        return SHELL_TOKENIZE_EOVERFLOW;
      if (prefix_step != SHELL_PIPE_PREFIX_NOT_ACCEPTED)
        continue;
    }
    if (token.type == SHELL_TOKEN_PIPE_NEGATE)
      continue;
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
    if (expect_command && (full_token_is_redirection(&token) ||
                           token.type == SHELL_TOKEN_COMMAND ||
                           token.type == SHELL_TOKEN_ARGUMENT ||
                           token.type == SHELL_TOKEN_SUBSHELL ||
                           token.type == SHELL_TOKEN_VARIABLE ||
                           token.type == SHELL_TOKEN_VARIABLE_QUOTED ||
                           token.type == SHELL_TOKEN_SPECIAL_VAR ||
                           token.type == SHELL_TOKEN_ARITHMETIC ||
                           token.type == SHELL_TOKEN_ARITHMETIC_COMMAND ||
                           token.type == SHELL_TOKEN_CONDITIONAL_COMMAND ||
                           token.type == SHELL_TOKEN_GLOB ||
                           token.type == SHELL_TOKEN_ANSI_C_QUOTED ||
                           token.type == SHELL_TOKEN_EXTGLOB ||
                           token.type == SHELL_TOKEN_ARRAY_ASSIGNMENT ||
                           token.type == SHELL_TOKEN_HEREDOC ||
                           token.type == SHELL_TOKEN_HERESTRING ||
                           token.type == SHELL_TOKEN_REDIRECT_IN ||
                           token.type == SHELL_TOKEN_REDIRECT_OUT ||
                           token.type == SHELL_TOKEN_REDIRECT_ERR ||
                           token.type == SHELL_TOKEN_REDIRECT_APPEND ||
                           token.type == SHELL_TOKEN_REDIRECT_READ_WRITE ||
                           token.type == SHELL_TOKEN_REDIRECT_CLOBBER ||
                           token.type == SHELL_TOKEN_REDIRECT_BOTH ||
                           token.type == SHELL_TOKEN_REDIRECT_BOTH_APPEND ||
                           token.type == SHELL_TOKEN_PROCESS_SUB)) {
      count++;
      expect_command = false;
      pipeline_start = false;
      pipeline_prefix = shell_pipeline_prefix_state_initial(false);
    }

    if (token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_PIPE_BOTH ||
        token.type == SHELL_TOKEN_SEMICOLON || token.type == SHELL_TOKEN_AND ||
        token.type == SHELL_TOKEN_BACKGROUND || token.type == SHELL_TOKEN_OR) {
      if (expect_command && pipeline_prefix.time_mode != SHELL_PIPE_TIME_NONE &&
          (token.type == SHELL_TOKEN_SEMICOLON ||
           token.type == SHELL_TOKEN_BACKGROUND))
        count++;
      expect_command = true;
      pipeline_start =
          token.type != SHELL_TOKEN_PIPE && token.type != SHELL_TOKEN_PIPE_BOTH;
      pipeline_prefix = shell_pipeline_prefix_state_initial(pipeline_start);
    }
  }

  if (expect_command && pipeline_prefix.time_mode != SHELL_PIPE_TIME_NONE)
    count++;

  if (count == 0 && input_length != 0) {
    bool has_non_whitespace = false;
    size_t input_len = input_length;
    for (size_t i = 0; i < input_len; i++) {
      char c = input[i];
      if (shell_source_space((unsigned char)c))
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

  shell_tokenizer_init_prechecked(&state, input, input_length);
  if (!allow_initial_time)
    state.lexical_prefix &= (uint8_t)~LEXICAL_TIME_MASK;
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
  current_cmd->pipeline_negation_count = 0;
  current_cmd->pipeline_negated = false;
  current_cmd->pipeline_time_mode = SHELL_PIPE_TIME_NONE;

  expect_command = true;
  pipeline_start = true;
  pipeline_prefix = shell_pipeline_prefix_state_initial(allow_initial_time);
  size_t pipeline_modifier_token_count = 0;
  shell_pipeline_time_mode_t pipeline_scope_time_mode = SHELL_PIPE_TIME_NONE;
  uint32_t pipeline_scope_negation_count = 0;
  shell_pipeline_time_mode_t inherited_time_mode = SHELL_PIPE_TIME_NONE;
  typedef struct {
    shell_pipeline_time_mode_t pipeline_scope_time_mode;
    uint32_t pipeline_scope_negation_count;
    shell_pipeline_time_mode_t inherited_time_mode;
  } shell_modifier_group_state_t;
  shell_modifier_group_state_t modifier_group_stack[SHELL_MAX_GROUPS];
  size_t modifier_group_depth = 0;
  bool saw_loop = false;
  bool saw_conditional = false;
  bool saw_case = false;
  bool closed_group_at_end = false;
  bool group_tail_active = false;

  while (shell_tokenizer_next(&state, &token)) {
    if (shell_source_is_escaped_line_ending(input, token.position,
                                            token.position + token.length))
      continue;
    if (expect_command && shell_list_token_is_newline(&token)) {
      group_tail_active = false;
      if (pipeline_prefix.time_mode == SHELL_PIPE_TIME_NONE)
        continue;
    }
    closed_group_at_end = token.type == SHELL_TOKEN_GROUP_END;
    saw_loop = saw_loop || state.loop_depth > 0;
    saw_conditional = saw_conditional || state.if_depth > 0 ||
                      token.type == SHELL_TOKEN_CONDITIONAL_COMMAND;
    saw_case = saw_case || state.case_depth > 0;
    if (token.type == SHELL_TOKEN_GROUP_START ||
        token.type == SHELL_TOKEN_GROUP_END) {
      group_tail_active = token.type == SHELL_TOKEN_GROUP_END;
      bool group_starts_command =
          token.type == SHELL_TOKEN_GROUP_START && expect_command &&
          current_cmd->token_count != 0 &&
          current_cmd->token_count != pipeline_modifier_token_count;
      if (group_starts_command) {
        current_cmd->end_pos = token.position;
        if (!full_commands_start_record(
                commands, &count, &current_command, &state, token.position + 1,
                pipeline_scope_negation_count,
                pipeline_scope_time_mode != SHELL_PIPE_TIME_NONE
                    ? pipeline_scope_time_mode
                    : inherited_time_mode)) {
          shell_commands_free(*commands, current_command + 1);
          *commands = NULL;
          return SHELL_TOKENIZE_ENOMEM;
        }
        current_cmd = &(*commands)[current_command];
        tokens = current_cmd->tokens;
        token_capacity = 16;
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
      if (token.type == SHELL_TOKEN_GROUP_START) {
        /* The syntax validator rejects one-more-than-capacity nesting first;
         * retain this independent guard beside the fixed-size state stack. */
        if (modifier_group_depth == SHELL_MAX_GROUPS) {
          shell_commands_free(*commands, current_command + 1);
          *commands = NULL;
          *command_count = 0;
          return SHELL_TOKENIZE_EOVERFLOW;
        }
        modifier_group_stack[modifier_group_depth++] =
            (shell_modifier_group_state_t){
                .pipeline_scope_time_mode = pipeline_scope_time_mode,
                .pipeline_scope_negation_count = pipeline_scope_negation_count,
                .inherited_time_mode = inherited_time_mode,
            };
        if (pipeline_scope_time_mode != SHELL_PIPE_TIME_NONE)
          inherited_time_mode = pipeline_scope_time_mode;
        if (current_cmd->pipeline_time_mode == SHELL_PIPE_TIME_NONE)
          current_cmd->pipeline_time_mode = inherited_time_mode;
        /* Prefix syntax belongs to this compound pipeline, not to its first
         * flattened inner simple command. Metadata above retains its meaning;
         * discard the lexical prefix tokens so every exposed token remains
         * inside the command record's declared source span. */
        if (pipeline_modifier_token_count != 0 &&
            current_cmd->token_count == pipeline_modifier_token_count) {
          current_cmd->token_count = 0;
          current_cmd->start_pos = token.position + 1;
          /* Negation belongs to the compound pipeline result, not to the first
           * simple command executed inside the compound. */
          current_cmd->pipeline_negation_count = 0;
          current_cmd->pipeline_negated = false;
        }
        pipeline_scope_time_mode = SHELL_PIPE_TIME_NONE;
        pipeline_scope_negation_count = 0;
        pipeline_start = true;
        pipeline_prefix = shell_pipeline_prefix_state_initial(true);
        /* Entering a group starts a new pipeline-prefix context. Ordinary
         * words retained by diagnostic parsing (such as `for` before `((`)
         * are not modifier tokens and must never be discarded by a nested
         * opening delimiter's modifier-only check. */
        pipeline_modifier_token_count = 0;
      } else if (modifier_group_depth != 0) {
        pipeline_scope_time_mode =
            modifier_group_stack[modifier_group_depth - 1]
                .pipeline_scope_time_mode;
        pipeline_scope_negation_count =
            modifier_group_stack[modifier_group_depth - 1]
                .pipeline_scope_negation_count;
        inherited_time_mode =
            modifier_group_stack[modifier_group_depth - 1].inherited_time_mode;
        modifier_group_depth--;
        pipeline_start = false;
        pipeline_prefix = shell_pipeline_prefix_state_initial(false);
        pipeline_modifier_token_count = 0;
      }
      continue;
    }
    /* The newline that starts pending-heredoc body consumption is a list
     * separator, not part of an argv-less document operation.  Retaining it
     * in the structured record made the allocating tokenizer disagree with
     * the lexical iterator, whose heredoc token already owns the complete
     * declaration and body. */
    if (shell_list_token_is_newline(&token) && current_cmd->token_count != 0) {
      bool document_only = false;
      for (size_t index = 0; index < current_cmd->token_count; index++) {
        const shell_token_t *prior = &current_cmd->tokens[index];
        if (prior->type == SHELL_TOKEN_HEREDOC)
          document_only = true;
        else if (!full_token_is_redirection(prior)) {
          document_only = false;
          break;
        }
      }
      if (document_only) {
        expect_command = true;
        pipeline_start = true;
        current_cmd->end_pos = token.position + token.length;
        pipeline_prefix = shell_pipeline_prefix_state_initial(true);
        continue;
      }
    }
    bool redirect_operand = full_tokens_need_redirect_operand(
        input, input_length, current_cmd->tokens, current_cmd->token_count,
        &token);
    shell_pipeline_prefix_step_t prefix_step = SHELL_PIPE_PREFIX_NOT_ACCEPTED;
    if (pipeline_start)
      prefix_step = shell_pipeline_prefix_step(
          &pipeline_prefix,
          full_pipeline_prefix_word(input, input_length, &token));
    if (prefix_step == SHELL_PIPE_PREFIX_OVERFLOW) {
      shell_commands_free(*commands, count);
      *commands = NULL;
      *command_count = 0;
      return SHELL_TOKENIZE_EOVERFLOW;
    }
    if (prefix_step != SHELL_PIPE_PREFIX_NOT_ACCEPTED &&
        pipeline_modifier_token_count == 0 && current_cmd->token_count != 0) {
      /* A completed record still owns its list separator. The new prefix
       * belongs to the successor, including an argv-less timing operation. */
      if (!full_commands_start_record(
              commands, &count, &current_command, &state, token.position,
              pipeline_scope_negation_count,
              pipeline_scope_time_mode != SHELL_PIPE_TIME_NONE
                  ? pipeline_scope_time_mode
                  : inherited_time_mode)) {
        shell_commands_free(*commands, current_command + 1);
        *commands = NULL;
        return SHELL_TOKENIZE_ENOMEM;
      }
      current_cmd = &(*commands)[current_command];
      tokens = current_cmd->tokens;
      token_capacity = 16;
    }
    if (prefix_step == SHELL_PIPE_PREFIX_ACCEPTED_TIME) {
      token.type = SHELL_TOKEN_PIPE_TIME;
      if (pipeline_scope_time_mode == SHELL_PIPE_TIME_NONE)
        pipeline_scope_time_mode = SHELL_PIPE_TIME_DEFAULT;
      current_cmd->pipeline_time_mode = pipeline_prefix.time_mode;
      pipeline_modifier_token_count++;
    } else if (prefix_step == SHELL_PIPE_PREFIX_ACCEPTED_OPTION) {
      token.type = SHELL_TOKEN_PIPE_TIME_OPTION;
      pipeline_scope_time_mode = SHELL_PIPE_TIME_POSIX;
      current_cmd->pipeline_time_mode = pipeline_prefix.time_mode;
      pipeline_modifier_token_count++;
    }
    if (token.type == SHELL_TOKEN_PIPE_NEGATE && !pipeline_start) {
      /* `!` is ordinary word data after a command. It cannot begin a later
       * pipeline stage either; reject that form rather than dropping it. */
      if (current_cmd->token_count > 0 &&
          (current_cmd->tokens[current_cmd->token_count - 1].type ==
               SHELL_TOKEN_PIPE ||
           current_cmd->tokens[current_cmd->token_count - 1].type ==
               SHELL_TOKEN_PIPE_BOTH)) {
        shell_commands_free(*commands, count);
        *commands = NULL;
        *command_count = 0;
        return SHELL_TOKENIZE_EPARSE;
      }
      token.type = SHELL_TOKEN_ARGUMENT;
    }
    if (token.type == SHELL_TOKEN_PIPE_NEGATE) {
      /* This is a modifier of the following pipeline, never an argv word.
       * Bash accepts repeated modifiers; retain their exact count and expose
       * the effective inversion through its parity. */
      pipeline_modifier_token_count++;
      pipeline_scope_negation_count = pipeline_prefix.negation_count;
      current_cmd->pipeline_negation_count = pipeline_prefix.negation_count;
      current_cmd->pipeline_negated =
          (pipeline_prefix.negation_count & UINT32_C(1)) != 0;
    }
    if (expect_command &&
        ((full_token_is_redirection(&token) && !group_tail_active) ||
         token.type == SHELL_TOKEN_COMMAND ||
         token.type == SHELL_TOKEN_ARGUMENT ||
         token.type == SHELL_TOKEN_SUBSHELL ||
         token.type == SHELL_TOKEN_VARIABLE ||
         token.type == SHELL_TOKEN_VARIABLE_QUOTED ||
         token.type == SHELL_TOKEN_SPECIAL_VAR ||
         token.type == SHELL_TOKEN_GLOB ||
         token.type == SHELL_TOKEN_ANSI_C_QUOTED ||
         token.type == SHELL_TOKEN_EXTGLOB ||
         token.type == SHELL_TOKEN_ARRAY_ASSIGNMENT ||
         token.type == SHELL_TOKEN_ARITHMETIC ||
         token.type == SHELL_TOKEN_ARITHMETIC_COMMAND ||
         token.type == SHELL_TOKEN_CONDITIONAL_COMMAND ||
         token.type == SHELL_TOKEN_PROCESS_SUB)) {
      /* The leading `!` is retained as the pipeline's syntax token, but it
       * does not occupy a simple-command slot. The first following word must
       * join that same record rather than create a phantom `!` command. */
      bool has_only_pipeline_modifiers =
          pipeline_modifier_token_count != 0 &&
          current_cmd->token_count == pipeline_modifier_token_count;
      if (current_cmd->token_count > 0 && !redirect_operand &&
          !has_only_pipeline_modifiers) {
        if (!full_commands_start_record(
                commands, &count, &current_command, &state, token.position,
                pipeline_scope_negation_count,
                pipeline_scope_time_mode != SHELL_PIPE_TIME_NONE
                    ? pipeline_scope_time_mode
                    : inherited_time_mode)) {
          shell_commands_free(*commands, current_command + 1);
          *commands = NULL;
          return SHELL_TOKENIZE_ENOMEM;
        }
        current_cmd = &(*commands)[current_command];
        tokens = current_cmd->tokens;
        token_capacity = 16;
      }
      expect_command = false;
      pipeline_start = false;
      pipeline_prefix.time_keyword_allowed = false;
      if (current_cmd->pipeline_time_mode == SHELL_PIPE_TIME_NONE)
        current_cmd->pipeline_time_mode =
            pipeline_scope_time_mode != SHELL_PIPE_TIME_NONE
                ? pipeline_scope_time_mode
                : inherited_time_mode;
      if (current_cmd->pipeline_negation_count == 0) {
        current_cmd->pipeline_negation_count = pipeline_scope_negation_count;
        current_cmd->pipeline_negated =
            (pipeline_scope_negation_count & UINT32_C(1)) != 0;
      }
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

    /* Group delimiters are structural and are not retained in flattened
     * simple-command records. Pin a new group-body record to its first
     * retained token, whether that token is a pipeline modifier, redirect, or
     * argv word. Once a token is retained the record start must never advance:
     * every consumer relies on all token spans lying within the record span. */
    if (current_cmd->has_groups && current_cmd->token_count == 0)
      current_cmd->start_pos = token.position;
    current_cmd->tokens[current_cmd->token_count++] = token;
    /* Compound tails may append redirects after the closing delimiter. A
     * heredoc's declaration newline can be consumed without a separator token,
     * so a later record must not be required to finalize this record's span.
     * Establish token containment here, once as each token is appended. */
    size_t token_end = token.position + token.length;
    if (token_end > current_cmd->end_pos)
      current_cmd->end_pos = token_end;
    if (token.type == SHELL_TOKEN_COMMAND ||
        token.type == SHELL_TOKEN_ARGUMENT ||
        token.type == SHELL_TOKEN_SUBSHELL ||
        token.type == SHELL_TOKEN_VARIABLE ||
        token.type == SHELL_TOKEN_VARIABLE_QUOTED ||
        token.type == SHELL_TOKEN_SPECIAL_VAR ||
        token.type == SHELL_TOKEN_GLOB ||
        token.type == SHELL_TOKEN_ANSI_C_QUOTED ||
        token.type == SHELL_TOKEN_EXTGLOB ||
        token.type == SHELL_TOKEN_ARRAY_ASSIGNMENT ||
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
    case SHELL_TOKEN_EXTGLOB:
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
    case SHELL_TOKEN_PIPE:
      current_cmd->pipe_output_mode = SHELL_PIPE_MODE_STDOUT;
      break;
    case SHELL_TOKEN_PIPE_BOTH:
      current_cmd->pipe_output_mode = SHELL_PIPE_MODE_STDOUT_AND_STDERR;
      break;
    case SHELL_TOKEN_CONDITIONAL_COMMAND: {
      current_cmd->kind = SHELL_COMMAND_CONDITIONAL;
      current_cmd->ends_group = true;
      shell_conditional_t condition =
          shell_conditional_parse(token.start, token.length, 0);
      current_cmd->has_globs |= shell_conditional_pattern(condition.predicate);
      for (unsigned operand = 0; operand < condition.operand_count; ++operand) {
        shell_source_substitution_scan_t scan = {0};
        size_t start, after;
        shell_source_substitution_kind_t kind;
        while (shell_source_next_executable_substitution(
                   token.start + condition.operands[operand],
                   condition.operand_lengths[operand], &scan, &start, &after,
                   &kind) == SHELL_SOURCE_SCAN_FOUND)
          current_cmd->has_subshells |= kind == SHELL_SOURCE_SUBST_COMMAND ||
                                        kind == SHELL_SOURCE_SUBST_BACKTICK;
        current_cmd->has_variables |=
            scan.has_variables || scan.has_arithmetic_variables;
        current_cmd->has_arithmetic |= scan.has_arithmetic;
      }
      break;
    }
    case SHELL_TOKEN_ARITHMETIC_COMMAND:
      current_cmd->kind = SHELL_COMMAND_ARITHMETIC;
      current_cmd->ends_group = true;
      /* fall through */
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
    if ((token.type == SHELL_TOKEN_COMMAND ||
         token.type == SHELL_TOKEN_ARGUMENT) &&
        shell_tokenizer_token_has_variable(&token))
      current_cmd->has_variables = true;

    if (token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_PIPE_BOTH ||
        token.type == SHELL_TOKEN_SEMICOLON || token.type == SHELL_TOKEN_AND ||
        token.type == SHELL_TOKEN_BACKGROUND || token.type == SHELL_TOKEN_OR) {
      expect_command = true;
      pipeline_start =
          token.type != SHELL_TOKEN_PIPE && token.type != SHELL_TOKEN_PIPE_BOTH;
      current_cmd->end_pos = token.position + token.length;
      pipeline_prefix = shell_pipeline_prefix_state_initial(pipeline_start);
      if (token.type != SHELL_TOKEN_PIPE &&
          token.type != SHELL_TOKEN_PIPE_BOTH) {
        pipeline_scope_time_mode = SHELL_PIPE_TIME_NONE;
        pipeline_scope_negation_count = 0;
      }
      pipeline_modifier_token_count = 0;
      group_tail_active = false;
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
  } else
    count = current_command + 1;

  /* Unclosed quotes and braces are unusable even for lexical diagnostics. The
   * allocating tokenizer deliberately retains incomplete parenthesized input
   * such as `( git`; complete-command consumers apply the strict shared source
   * validator before relying on this tolerant representation. */
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
      (*commands)[i].pipeline_negated =
          ((*commands)[i].pipeline_negation_count & UINT32_C(1)) != 0;
    }
  }

  *command_count = count;
  return SHELL_TOKENIZE_OK;
}

shell_tokenize_status_t shell_tokenize_commands(const char *input,
                                                size_t input_length,
                                                shell_command_t **commands,
                                                size_t *command_count) {
  if (!shell_source_operation_begin_owned(input, input_length)) {
    *commands = NULL;
    *command_count = 0;
    return SHELL_TOKENIZE_ENOMEM;
  }
  shell_tokenize_status_t status = shell_tokenize_commands_impl(
      input, input_length, commands, command_count, true, false, false);
  if (shell_source_scratch_exhausted()) {
    shell_commands_free(*commands, *command_count);
    *commands = NULL;
    *command_count = 0;
    status = SHELL_TOKENIZE_EOVERFLOW;
  }
  shell_source_operation_end();
  return status;
}

shell_tokenize_status_t shell_tokenize_supported_commands(
    const char *input, size_t input_length, bool allow_initial_time,
    bool require_complete, shell_command_t **commands, size_t *command_count) {
  if (!shell_source_operation_begin_owned(input, input_length)) {
    *commands = NULL;
    *command_count = 0;
    return SHELL_TOKENIZE_ENOMEM;
  }
  shell_tokenize_status_t status =
      shell_tokenize_commands_impl(input, input_length, commands, command_count,
                                   allow_initial_time, require_complete, true);
  if (shell_source_scratch_exhausted()) {
    shell_commands_free(*commands, *command_count);
    *commands = NULL;
    *command_count = 0;
    status = SHELL_TOKENIZE_EOVERFLOW;
  }
  shell_source_operation_end();
  return status;
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
  case SHELL_TOKEN_PIPE_BOTH:
    return "PIPE_BOTH";
  case SHELL_TOKEN_PIPE_TIME:
    return "PIPE_TIME";
  case SHELL_TOKEN_PIPE_TIME_OPTION:
    return "PIPE_TIME_OPTION";
  case SHELL_TOKEN_ARITHMETIC_COMMAND:
    return "ARITHMETIC_COMMAND";
  case SHELL_TOKEN_CONDITIONAL_COMMAND:
    return "CONDITIONAL_COMMAND";
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
  case SHELL_TOKEN_PIPE_NEGATE:
    return "PIPE_NEGATE";
  case SHELL_TOKEN_REDIRECT_BOTH:
    return "REDIRECT_BOTH";
  case SHELL_TOKEN_REDIRECT_BOTH_APPEND:
    return "REDIRECT_BOTH_APPEND";
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
  case SHELL_TOKEN_ANSI_C_QUOTED:
    return "ANSI_C_QUOTED";
  case SHELL_TOKEN_EXTGLOB:
    return "EXTGLOB";
  case SHELL_TOKEN_ARRAY_ASSIGNMENT:
    return "ARRAY_ASSIGNMENT";
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
  case SHELL_TOKEN_CASE_TERMINATE:
    return "CASE_TERMINATE";
  case SHELL_TOKEN_CASE_FALLTHROUGH:
    return "CASE_FALLTHROUGH";
  case SHELL_TOKEN_CASE_TEST_NEXT:
    return "CASE_TEST_NEXT";
  case SHELL_TOKEN_END:
    return "END";
  default:
    return "UNKNOWN";
  }
}
