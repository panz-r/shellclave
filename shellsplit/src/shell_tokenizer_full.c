#include "shell_tokenizer_full.h"
#include "alloc.h"
#include "shell_source_internal.h"
#include "shell_tokenizer_full_internal.h"
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static bool declaration_word_has_array_designator(const char *input,
                                                  size_t length);

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

/* Bash arithmetic accepts indexed and associative array references.  They do
 * not become ordinary scalar words merely because the outer lexer represents
 * the whole expression as one ARITHMETIC token, so inspect the expression
 * before canonical callers accept it. */
bool shell_tokenizer_arithmetic_has_array_semantics(const char *input,
                                                    size_t length) {
  if (!input)
    return false;

  for (size_t position = 0; position < length; position++) {
    char c = input[position];
    if (c == '\\' && position + 1 < length) {
      position++;
      continue;
    }
    if (c == '$' && position + 1 < length && input[position + 1] == '\'') {
      size_t after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &after))
        return false;
      position = after - 1;
      continue;
    }
    if (c == '\'') {
      size_t after = shell_source_skip_quoted_text(input, length, position, c);
      if (after <= position + 1 || after > length || input[after - 1] != c)
        return false;
      position = after - 1;
      continue;
    }
    if (c == '"') {
      size_t after = shell_source_skip_quoted_text(input, length, position, c);
      if (after <= position + 1 || after > length || input[after - 1] != c)
        return false;
      if (shell_tokenizer_arithmetic_has_array_semantics(input + position + 1,
                                                         after - position - 2))
        return true;
      position = after - 1;
      continue;
    }
    if (c == '`') {
      size_t after = shell_source_skip_quoted_text(input, length, position, c);
      if (after <= position + 1 || after > length || input[after - 1] != c)
        return false;
      if (shell_tokenizer_has_unsupported_semantics(input + position + 1,
                                                    after - position - 2))
        return true;
      position = after - 1;
      continue;
    }
    if (c == '$' && position + 1 < length && input[position + 1] == '{') {
      size_t after = 0, subscript_start = 0;
      if (shell_source_find_parameter_array_subscript(input, length, position,
                                                      &after, &subscript_start))
        return true;
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 &after))
        return false;
      if (after > position + 3 && after <= length && input[after - 1] == '}' &&
          shell_tokenizer_has_unsupported_semantics(input + position + 2,
                                                    after - position - 3))
        return true;
      position = after - 1;
      continue;
    }
    if (c == '$' && position + 1 < length && input[position + 1] == '(') {
      size_t after = 0;
      if (position + 2 < length && input[position + 2] == '(') {
        if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                    &after))
          return false;
        if (after > position + 5 &&
            shell_tokenizer_arithmetic_has_array_semantics(
                input + position + 3, after - position - 5))
          return true;
      } else {
        if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                                    &after))
          return false;
        if (shell_tokenizer_has_unsupported_semantics(input + position + 2,
                                                      after - position - 3))
          return true;
      }
      position = after - 1;
      continue;
    }
    if (!(isalpha((unsigned char)c) || c == '_'))
      continue;
    size_t after_name = position + 1;
    while (after_name < length && (isalnum((unsigned char)input[after_name]) ||
                                   input[after_name] == '_'))
      after_name++;
    if (after_name < length && input[after_name] == '[') {
      size_t after_subscript = 0;
      if (shell_source_skip_array_subscript(input, length, after_name,
                                            &after_subscript))
        return true;
    }
    position = after_name - 1;
  }
  return false;
}

static bool function_parentheses_open_body(const char *input, size_t length,
                                           size_t position,
                                           size_t segment_start);

static size_t compound_list_segment_start(const char *input, size_t length,
                                          size_t end) {
  if (!input || end > length)
    return 0;
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
    if (c == '$' && position + 1 < end && input[position + 1] == '\'') {
      size_t quoted = 0;
      if (shell_source_skip_complete_ansi_c_quote(input, end, position,
                                                  &quoted)) {
        position = quoted - 1;
        continue;
      }
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
    if (c == ';' || c == '|' || c == '&' || c == '\n' || c == '\r')
      start = position + 1;
    else if (c == '(' &&
             !function_parentheses_open_body(input, length, position, start))
      start = position + 1;
  }
  return start;
}

static bool brace_follows_redirect_list(const char *input, size_t length,
                                        size_t end) {
  return shell_source_redirect_list_before_group(
      input, compound_list_segment_start(input, length, end), end);
}

/* Shell function names are NAME tokens, not arbitrary shell words. Keep this
 * separate from the surrounding tokenizer so every consumer agrees that
 * `name ( )` is a function declarator while `9name ( )` is malformed. */
static bool function_name_end(const char *input, size_t end, size_t position,
                              size_t *after) {
  if (!input || !after || position >= end ||
      !(isalpha((unsigned char)input[position]) || input[position] == '_'))
    return false;
  position++;
  while (position < end &&
         (isalnum((unsigned char)input[position]) || input[position] == '_'))
    position++;
  *after = position;
  return true;
}

/* Parse the optional parenthesized part of a function declarator. Shell
 * lexical processing removes escaped physical line endings, so accept those
 * alongside horizontal space, but never cross a raw line break or comment. */
static bool function_parentheses_after_name(const char *input, size_t length,
                                            size_t position, size_t *after) {
  if (!input || !after)
    return false;
  position = shell_source_skip_inline_continuations(input, length, position);
  if (position == length || input[position] != '(')
    return false;
  position =
      shell_source_skip_inline_continuations(input, length, position + 1);
  if (position == length || input[position] != ')')
    return false;
  *after = shell_source_skip_inline_continuations(input, length, position + 1);
  return true;
}

static bool function_body_starts_at(const char *input, size_t length,
                                    size_t position) {
  return position < length &&
         (input[position] == '{' || input[position] == '(');
}

/* Validate the complete declaration prefix before an opening `(`. This is
 * also used while balancing groups, where treating the declarator as a
 * subshell would make a valid function body look structurally unrelated. */
static bool function_name_before_parentheses(const char *input, size_t end,
                                             size_t segment_start) {
  if (!input)
    return false;
  size_t position = segment_start;
  position = shell_source_skip_inline_continuations(input, end, position);
  if (position == end)
    return false;

  static const char keyword[] = "function";
  if (end - position >= sizeof(keyword) - 1 &&
      memcmp(input + position, keyword, sizeof(keyword) - 1) == 0) {
    size_t keyword_end = position + sizeof(keyword) - 1;
    size_t name_start =
        shell_source_skip_inline_continuations(input, end, keyword_end);
    if (name_start != keyword_end)
      position = name_start;
  }

  size_t name_end = 0;
  return function_name_end(input, end, position, &name_end) &&
         shell_source_skip_inline_continuations(input, end, name_end) == end;
}

/* Return whether the complete source prefix ending immediately before a
 * function body is a POSIX NAME ( ) declarator or Bash `function NAME` form.
 * The latter may optionally contain the same parenthesized spelling. */
static bool function_declarator_before_body(const char *input, size_t length,
                                            size_t end) {
  if (!input)
    return false;
  size_t position = compound_list_segment_start(input, length, end);
  position = shell_source_skip_inline_continuations(input, end, position);
  if (position == end)
    return false;

  static const char keyword[] = "function";
  bool bash_keyword =
      end - position >= sizeof(keyword) - 1 &&
      memcmp(input + position, keyword, sizeof(keyword) - 1) == 0;
  if (bash_keyword) {
    size_t keyword_end = position + sizeof(keyword) - 1;
    size_t name_start =
        shell_source_skip_inline_continuations(input, end, keyword_end);
    /* `functionality` is an ordinary name, and Bash's `function` keyword
     * needs a distinct following name. */
    if (name_start == keyword_end)
      bash_keyword = false;
    else
      position = name_start;
  }

  size_t name_end = 0;
  if (!function_name_end(input, end, position, &name_end))
    return false;
  size_t after = shell_source_skip_inline_continuations(input, end, name_end);
  if (after == end)
    return bash_keyword;

  size_t declarator_end = 0;
  if (!function_parentheses_after_name(input, end, name_end, &declarator_end))
    return false;
  return declarator_end == end;
}

/* A function body is a compound command even though Shellsplit deliberately
 * classifies functions as unsupported later.  Retain its brace nesting here
 * so lexical validation does not turn otherwise valid Bash/POSIX syntax into
 * an unrelated unmatched-closing-brace error. */
static bool brace_follows_function_declaration(const char *input, size_t length,
                                               size_t end) {
  return function_declarator_before_body(input, length, end);
}

/* True only when the complete prefix of this compound-list segment consists
 * of one or more reserved `!` pipeline modifiers. A comment or raw physical
 * line ending terminates a bang rather than joining it to a later group. */
static bool brace_follows_pipeline_negation(const char *input, size_t length,
                                            size_t end) {
  size_t position = compound_list_segment_start(input, length, end);
  while (position < end && isspace((unsigned char)input[position]))
    position++;
  bool found = false;
  while (position < end && input[position] == '!') {
    size_t after = position + 1;
    if (after == end || !isspace((unsigned char)input[after]))
      return false;
    after = shell_source_skip_pipeline_negator_gap(input, end, after);
    if (after == end)
      return true;
    if (input[after] == '\n' || input[after] == '\r' ||
        (input[after] == '#' && shell_source_comment_starts(input, end, after)))
      return false;
    found = true;
    if (input[after] != '!' || after + 1 == end ||
        !isspace((unsigned char)input[after + 1]))
      return false;
    position = after;
  }
  return found && position == end;
}

static bool function_parentheses_open_body(const char *input, size_t length,
                                           size_t position,
                                           size_t segment_start) {
  if (!input || position == 0 || position >= length)
    return false;
  if (!function_name_before_parentheses(input, position, segment_start))
    return false;
  size_t name_start =
      shell_source_skip_inline_continuations(input, position, segment_start);
  static const char keyword[] = "function";
  if (position - name_start >= sizeof(keyword) - 1 &&
      memcmp(input + name_start, keyword, sizeof(keyword) - 1) == 0) {
    size_t keyword_end = name_start + sizeof(keyword) - 1;
    size_t function_name_start =
        shell_source_skip_inline_continuations(input, position, keyword_end);
    if (function_name_start != keyword_end)
      name_start = function_name_start;
  }
  size_t name_end = 0;
  if (!function_name_end(input, position, name_start, &name_end))
    return false;
  size_t body = 0;
  return function_parentheses_after_name(input, length, name_end, &body) &&
         function_body_starts_at(input, length, body);
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
    if (c == '$' && i + 1 < length && input[i + 1] == '\'') {
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
      size_t after = 0;
      if (!shell_source_skip_parameter_expansion(input, length, i, &after))
        return false;
      i = after - 1;
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
    bool continued_line = false;
    do {
      continued_line = false;
      while (previous > 0 && isspace((unsigned char)input[previous - 1])) {
        newline_separator = newline_separator || input[previous - 1] == '\n' ||
                            input[previous - 1] == '\r';
        previous--;
      }
      if (previous > 0 && input[previous - 1] == '\\' &&
          ((previous < length && input[previous] == '\n') ||
           (previous + 1 < length && input[previous] == '\r' &&
            input[previous + 1] == '\n'))) {
        previous--;
        newline_separator = false;
        continued_line = true;
      }
    } while (continued_line);
    char before = previous ? input[previous - 1] : '\0';
    bool command_boundary =
        previous == 0 || newline_separator || before == ';' || before == '|' ||
        before == '&' || before == '(' || before == '{' ||
        brace_follows_redirect_list(input, length, previous) ||
        brace_follows_pipeline_negation(input, length, i);
    bool closing_brace =
        c == '}' && brace_group_close_delimiter(input, length, i, before,
                                                newline_separator);
    bool duplicate_brace_close =
        c == '}' && saw_brace && depth == 0 && before == '}';
    if (c == '{' &&
        (command_boundary ||
         brace_follows_function_declaration(input, length, i)) &&
        i + 1 < length &&
        (isspace((unsigned char)input[i + 1]) || input[i + 1] == '(')) {
      if (depth == SHELL_MAX_SUBCOMMANDS)
        return false;
      stack[depth++] = SHELL_GROUP_BRACE;
      saw_brace = true;
    } else if (c == '(' &&
               !(i > 0 && (input[i - 1] == '$' || input[i - 1] == '<' ||
                           input[i - 1] == '>')) &&
               !function_parentheses_open_body(
                   input, length, i,
                   compound_list_segment_start(input, length, i))) {
      if (depth < SHELL_MAX_SUBCOMMANDS)
        stack[depth++] = SHELL_GROUP_SUBSHELL;
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

static bool token_at_word_boundary(const shell_tokenizer_state_t *state) {
  if (!state || state->position == 0)
    return true;
  char previous = state->input[state->position - 1];
  return isspace((unsigned char)previous) || previous == ';' ||
         previous == '|' || previous == '&' || previous == '(' ||
         previous == '{' || previous == '}';
}

static bool parse_array_assignment_end(const char *input, size_t length,
                                       size_t start, size_t *end) {
  if (!input || !end || start >= length ||
      !(isalpha((unsigned char)input[start]) || input[start] == '_'))
    return false;
  size_t position = start + 1;
  bool indexed = false;
  while (position < length &&
         (isalnum((unsigned char)input[position]) || input[position] == '_'))
    position++;
  if (position < length && input[position] == '[') {
    indexed = true;
    size_t close = 0;
    if (!shell_source_skip_array_subscript(input, length, position, &close))
      return false;
    position = close;
  }
  if (position < length && input[position] == '+')
    position++;
  if (position >= length || input[position] != '=')
    return false;
  if (position + 1 >= length || input[position + 1] != '(') {
    /* a[0]=value and map[key]+=value are still array syntax even though the
     * RHS is not a compound assignment. The semantic layer rejects them. */
    if (!indexed)
      return false;
    *end = position + 1;
    return true;
  }
  size_t after = 0;
  if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                              &after))
    return false;
  *end = after;
  return true;
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
          before != '{' &&
          !brace_follows_redirect_list(state->input, state->length, previous) &&
          !brace_follows_pipeline_negation(state->input, state->length, p))
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
         state->input[state->position] != '\n' &&
         state->input[state->position] != '\r' &&
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
    bool cr = state->input[state->position + 1] == '\r';
    state->position += 2;
    if (cr && state->position < state->length &&
        state->input[state->position] == '\n')
      state->position++;
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
                          size_t start_pos, size_t operator_pos,
                          bool is_quoted) {
  if (operator_pos + 1 >= state->length ||
      state->input[operator_pos + 1] != '<' ||
      (operator_pos + 2 < state->length &&
       state->input[operator_pos + 2] == '<'))
    return false;

  size_t position = operator_pos + 2;
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
    /* `$?` is the shell status parameter, not a literal-prefix glob. The
     * caller may be classifying a compound word such as `status-$?`, where
     * the expansion is deliberately retained inside one argv item. */
    if (c == '?' && i > 0 && str[i - 1] == '$')
      continue;
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
    /* `skip_whitespace()` also consumes horizontal space before a physical
     * line ending. Loop back so that ending is emitted as a list separator
     * rather than falling through into the word scanner. Apart from fixing
     * ordinary `word \n next` boundaries, this keeps a pending `!` from
     * silently crossing a raw newline. */
    if (!state->in_quotes && (state->input[state->position] == '\n' ||
                              state->input[state->position] == '\r'))
      continue;
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

  /* A physical line continuation at a token boundary is grammar, not the
   * prefix of the next lexical operator.  In particular, retaining its old
   * start position while recognizing a following `<<<` made one malformed
   * HERESTRING token span `\\\n<<`.  Emit the continuation by itself so the
   * list and source validators can discard it while the next call starts at
   * the real operator. Continuations embedded in an ordinary word are still
   * consumed by the word scanner below. */
  if (!state->in_quotes && current_char == '\\' &&
      start_pos + 1 < state->length &&
      (state->input[start_pos + 1] == '\n' ||
       state->input[start_pos + 1] == '\r')) {
    state->position = start_pos + 2;
    if (state->input[start_pos + 1] == '\r' &&
        state->position < state->length &&
        state->input[state->position] == '\n')
      state->position++;
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

  if (!state->in_quotes && current_char == '!' &&
      token_at_word_boundary(state) &&
      (state->position + 1 == state->length ||
       isspace((unsigned char)state->input[state->position + 1]))) {
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
      state->position + 1 < state->length &&
      state->input[state->position + 1] == '\'') {
    size_t after = shell_source_skip_ansi_c_quote(state->input, state->length,
                                                  state->position);
    if (after > state->position + 2 && after <= state->length &&
        state->input[after - 1] == '\'') {
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

  if (!state->in_quotes &&
      (current_char == '?' || current_char == '*' || current_char == '+' ||
       current_char == '@' || current_char == '!') &&
      state->position + 1 < state->length &&
      state->input[state->position + 1] == '(') {
    size_t after = 0;
    if (shell_source_find_balanced_parentheses(state->input, state->length,
                                               state->position + 1, &after)) {
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

  if (!state->in_quotes) {
    size_t after = 0;
    if (parse_array_assignment_end(state->input, state->length, state->position,
                                   &after)) {
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

  if (!state->in_quotes && current_char == '{') {
    size_t redirect = 0;
    if (shell_source_parse_named_fd_redirect(state->input, state->position,
                                             state->length, &redirect)) {
      size_t operator_start = redirect;
      char direction = state->input[redirect++];
      if (direction == '<' && redirect + 1 < state->length &&
          state->input[redirect] == '<' && state->input[redirect + 1] == '<') {
        token->type = SHELL_TOKEN_HERESTRING;
        token->start = state->input + state->position;
        token->length = redirect + 2 - state->position;
        token->position = state->position;
        token->is_quoted = false;
        token->is_escaped = false;
        state->position = redirect + 2;
        return shell_token_return_current_group_context(state, token);
      }
      if (direction == '<' && redirect < state->length &&
          state->input[redirect] == '<') {
        parse_heredoc(state, token, state->position, operator_start, false);
        return shell_token_return_current_group_context(state, token);
      }
      token->type =
          direction == '<' ? SHELL_TOKEN_REDIRECT_IN : SHELL_TOKEN_REDIRECT_OUT;
      if (direction == '>' && redirect < state->length &&
          state->input[redirect] == '>') {
        token->type = SHELL_TOKEN_REDIRECT_APPEND;
        redirect++;
      } else if (direction == '<' && redirect < state->length &&
                 state->input[redirect] == '>') {
        token->type = SHELL_TOKEN_REDIRECT_READ_WRITE;
        redirect++;
      }
      if (redirect < state->length && state->input[redirect] == '&') {
        token->type = SHELL_TOKEN_REDIRECT_ERR;
        redirect =
            scan_descriptor_target(state->input, redirect + 1, state->length);
      }
      token->start = state->input + state->position;
      token->length = redirect - state->position;
      token->position = state->position;
      token->is_quoted = false;
      token->is_escaped = memchr(token->start, '\\', token->length) != NULL;
      state->position = redirect;
      return shell_token_return_current_group_context(state, token);
    }
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
      } else if (current_char == '&' && next_char == '>') {
        token->type = SHELL_TOKEN_REDIRECT_BOTH;
        token->start = state->input + state->position;
        token->position = state->position;
        token->is_quoted = false;
        token->is_escaped = false;
        state->position += 2;
        if (state->position < state->length &&
            state->input[state->position] == '>') {
          token->type = SHELL_TOKEN_REDIRECT_BOTH_APPEND;
          state->position++;
        }
        token->length = state->position - token->position;
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
    size_t operator_length = 1;
    switch (current_char) {
    case '|':
      if (state->position + 1 < state->length &&
          state->input[state->position + 1] == '&') {
        token->type = SHELL_TOKEN_PIPE_BOTH;
        operator_length = 2;
      } else {
        token->type = SHELL_TOKEN_PIPE;
      }
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

        if (parse_heredoc(state, token, start_pos, start_pos, is_quoted))
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
      if (state->position + 2 < state->length &&
          state->input[state->position + 1] == ';' &&
          state->input[state->position + 2] == '&') {
        token->type = SHELL_TOKEN_CASE_TEST_NEXT;
        operator_length = 3;
      } else if (state->position + 1 < state->length &&
                 state->input[state->position + 1] == '&') {
        token->type = SHELL_TOKEN_CASE_FALLTHROUGH;
        operator_length = 2;
      } else if (state->position + 1 < state->length &&
                 state->input[state->position + 1] == ';') {
        token->type = SHELL_TOKEN_CASE_TERMINATE;
        operator_length = 2;
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
    case '[': {
      size_t after = 0;
      if (shell_source_skip_glob_bracket(state->input, state->length,
                                         state->position, &after)) {
        token->type = SHELL_TOKEN_GLOB;
        token->start = state->input + state->position;
        token->length = after - state->position;
        token->position = state->position;
        token->is_quoted = false;
        token->is_escaped = false;
        state->position = after;
        return shell_token_return_current_group_context(state, token);
      }
      token->type = SHELL_TOKEN_ARGUMENT;
    } break;
    default:
      token->type = SHELL_TOKEN_ARGUMENT;
      break;
    }

    token->start = state->input + state->position;
    token->length = operator_length;
    token->position = state->position;
    token->is_quoted = false;
    token->is_escaped = false;
    state->position += token->length;
    shell_token_set_group_context(token, token_group_depth, token_group_kinds);
    return true;
  }

  // An IO number must touch its operator. Whitespace leaves a numeric argv
  // word, and a physical newline starts a separate command.
  if (!state->in_quotes && isdigit((unsigned char)current_char) &&
      shell_source_word_boundary(state->input, state->length,
                                 state->position)) {
    size_t check_pos = 0;
    uint32_t descriptor = 0;
    shell_source_io_number_t io_number = shell_source_parse_io_number(
        state->input, state->position, state->length, &check_pos, &descriptor);
    if (io_number == SHELL_SOURCE_IO_NUMBER_OVERFLOW)
      goto ordinary_word;
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
        if (after_digit == '<' && end + 1 < state->length &&
            state->input[end] == '<' && state->input[end + 1] == '<') {
          /* Keep numeric-FD here-strings as one operator, just like bare
           * and named-FD here-strings. Splitting off the first '<' makes
           * the remaining bytes look like a heredoc delimiter. */
          token->type = SHELL_TOKEN_HERESTRING;
          end += 2;
        } else if (after_digit == '<' && end < state->length &&
                   state->input[end] == '<') {
          parse_heredoc(state, token, state->position, check_pos, false);
          return shell_token_return_current_group_context(state, token);
        } else if (after_digit == '>' && end < state->length &&
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
        if (token->type != SHELL_TOKEN_HERESTRING && end < state->length &&
            state->input[end] == '&') {
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
        bool cr = state->input[state->position + 1] == '\r';
        state->position += 2;
        if (cr && state->position < state->length &&
            state->input[state->position] == '\n')
          state->position++;
        continue;
      }
      if (c == '\'' || c == '"') {
        word_had_quotes = true;
        (void)handle_quotes(state);
        continue;
      }
      if (c == '$') {
        size_t after = 0;
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
         token->type == SHELL_TOKEN_REDIRECT_BOTH ||
         token->type == SHELL_TOKEN_REDIRECT_BOTH_APPEND ||
         token->type == SHELL_TOKEN_HEREDOC ||
         token->type == SHELL_TOKEN_HERESTRING;
}

/* Source spans include every lexical fragment of a redirect operand. */
static size_t full_redirect_end(const char *input, size_t input_length,
                                const shell_token_t *token) {
  size_t end = shell_source_skip_redirect(input, token->position, input_length);
  return end > token->position ? end : 0;
}

static bool full_redirection_consumes_next(const shell_token_t *token) {
  /* `>|` has no trailing '<' or '>' byte, but it still requires a pathname.
   * Keep this semantic exception explicit rather than treating the final
   * spelling byte as the complete redirect grammar. */
  if (token->type == SHELL_TOKEN_HERESTRING ||
      token->type == SHELL_TOKEN_REDIRECT_CLOBBER ||
      token->type == SHELL_TOKEN_REDIRECT_BOTH ||
      token->type == SHELL_TOKEN_REDIRECT_BOTH_APPEND)
    return true;
  if (token->length == 0)
    return false;
  char last = token->start[token->length - 1];
  return last == '<' || last == '>';
}

static bool full_redirection_uses_named_fd(const shell_token_t *token) {
  if (!token || !token->start)
    return false;
  size_t operator_position = 0;
  return shell_source_parse_named_fd_redirect(token->start, 0, token->length,
                                              &operator_position);
}

/* Named-FD inline documents have first-class FD_OPEN modeling. Only pathname
 * redirects need this unsupported-form guard: their operand can contain an
 * unrepresentable process-substitution stream even when it is concatenated
 * with literal pathname text. */
static bool full_named_fd_path_operand_has_process_substitution(
    const shell_tokenizer_state_t *state, const shell_token_t *token) {
  if (!state || !token || !full_redirection_uses_named_fd(token) ||
      token->type == SHELL_TOKEN_HEREDOC ||
      token->type == SHELL_TOKEN_HERESTRING)
    return false;
  size_t operand = shell_source_skip_inline_continuations(
      state->input, state->length, state->position);
  size_t after = 0;
  return operand < state->length &&
         shell_source_skip_shell_word(state->input, state->length, operand,
                                      &after) &&
         after > operand &&
         shell_source_word_has_process_substitution(state->input + operand,
                                                    after - operand);
}

static bool control_token_is_word(const shell_token_t *token) {
  return token->type == SHELL_TOKEN_COMMAND ||
         token->type == SHELL_TOKEN_ARGUMENT ||
         token->type == SHELL_TOKEN_ANSI_C_QUOTED ||
         token->type == SHELL_TOKEN_EXTGLOB ||
         token->type == SHELL_TOKEN_GLOB ||
         token->type == SHELL_TOKEN_ARRAY_ASSIGNMENT;
}

/* A full-tokenizer word may be exposed as several lexical fragments (`name`
 * followed by a GLOB `[index]`, for example). Recover its complete raw span
 * before testing declaration semantics so quote removal cannot hide an array
 * designator from the semantic boundary. */
static bool
declaration_operand_has_array_designator(const char *input, size_t input_length,
                                         const shell_token_t *token) {
  if (!input || !token || !control_token_is_word(token) ||
      token->position > input_length)
    return false;
  size_t after = 0;
  if (!shell_source_skip_shell_word(input, input_length, token->position,
                                    &after) ||
      after <= token->position || after > input_length)
    return false;
  return declaration_word_has_array_designator(input + token->position,
                                               after - token->position);
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
  if (!control_token_is_word(token) || token->is_quoted ||
      token->position > input_length ||
      token->length > input_length - token->position)
    return false;

  size_t name_end = 0;
  if (!function_name_end(token->start, token->length, 0, &name_end) ||
      shell_source_skip_escaped_line_endings(token->start, token->length,
                                             name_end) != token->length)
    return false;
  size_t after = 0;
  return function_parentheses_after_name(
      input, input_length, token->position + token->length, &after);
}

/* The Bash `function` spelling needs a name before a compound body. Keep the
 * unsupported-function classifier from accepting `function { ...; }` merely
 * because it saw the keyword: that form is malformed shell syntax, while a
 * real declaration remains lexically representable for the semantic boundary
 * to reject as unsupported. */
static bool control_function_keyword_has_name(const shell_token_t *token,
                                              const char *input,
                                              size_t input_length) {
  if (!token || !input || token->position > input_length ||
      token->length > input_length - token->position)
    return false;
  size_t position = token->position + token->length;
  while (position < input_length &&
         (input[position] == ' ' || input[position] == '\t'))
    position++;
  if (position >= input_length)
    return false;
  return isalpha((unsigned char)input[position]) || input[position] == '_';
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

static bool token_is_plain_word(const shell_token_t *token, const char *word) {
  return token &&
         (token->type == SHELL_TOKEN_COMMAND ||
          token->type == SHELL_TOKEN_ARGUMENT) &&
         !token->is_quoted && !token->is_escaped &&
         token->length == strlen(word) &&
         memcmp(token->start, word, token->length) == 0;
}

/* Declaration builtins resolve their command name and options after quote
 * removal. Decode only static shell spelling here: parameter, command, and
 * arithmetic expansions are retained as source bytes, so no runtime value can
 * turn an otherwise ordinary word into a declaration builtin. */
/* The lexer deliberately exposes quote and expansion fragments separately,
 * while declaration builtins resolve their name and options after quote
 * removal across the complete shell word.  Start at the first fragment and
 * recover that full raw word before decoding static spelling.  This keeps
 * `de$'clare'` and `-$'a'` from bypassing the semantic boundary without ever
 * treating a dynamic expansion as a declaration name or option. */
static bool token_visit_static_word(const char *input, size_t input_length,
                                    const shell_token_t *token,
                                    shell_source_byte_visitor_t visitor,
                                    void *context) {
  if (!input || !token || !visitor || !control_token_is_word(token) ||
      token->position > input_length)
    return false;
  size_t word_end = 0;
  if (!shell_source_skip_shell_word(input, input_length, token->position,
                                    &word_end) ||
      word_end <= token->position || word_end > input_length)
    return false;
  const char *word = input + token->position;
  size_t word_length = word_end - token->position;
  char quote = '\0';
  for (size_t position = 0; position < word_length; position++) {
    char c = word[position];
    if (quote == '\0' && c == '$' && position + 1 < word_length &&
        word[position + 1] == '\'') {
      size_t after = position;
      if (!shell_source_decode_ansi_c_quote(word, word_length, &after, visitor,
                                            context))
        return false;
      position = after - 1;
      continue;
    }
    if (quote == '\0' && (c == '\'' || c == '"')) {
      quote = c;
      continue;
    }
    if (quote != '\0' && c == quote) {
      quote = '\0';
      continue;
    }
    if (c == '\\' && quote != '\'' && position + 1 < word_length) {
      char next = word[position + 1];
      if (quote == '\0' || next == '$' || next == '`' || next == '"' ||
          next == '\\' || next == '\n' || next == '\r') {
        if (next != '\n' && next != '\r' &&
            !visitor((unsigned char)next, context))
          return false;
        position++;
        if (next == '\r' && position + 1 < token->length &&
            token->start[position + 1] == '\n')
          position++;
        continue;
      }
    }
    if (!visitor((unsigned char)c, context))
      return false;
  }
  return quote == '\0';
}

typedef struct {
  const char *word;
  size_t length;
  size_t position;
  bool matches;
} static_word_match_t;

static bool static_word_match_emit(unsigned char byte, void *context) {
  static_word_match_t *match = context;
  if (!match)
    return false;
  if (match->position >= match->length ||
      byte != (unsigned char)match->word[match->position])
    match->matches = false;
  match->position++;
  return true;
}

static bool token_is_static_word(const char *input, size_t input_length,
                                 const shell_token_t *token, const char *word) {
  if (!word)
    return false;
  static_word_match_t match = {
      .word = word,
      .length = strlen(word),
      .matches = true,
  };
  return token_visit_static_word(input, input_length, token,
                                 static_word_match_emit, &match) &&
         match.matches && match.position == match.length;
}

typedef struct {
  bool option;
  bool array;
  size_t position;
} static_option_scan_t;

static bool static_option_emit(unsigned char byte, void *context) {
  static_option_scan_t *scan = context;
  if (!scan)
    return false;
  if (scan->position == 0)
    scan->option = byte == '-' || byte == '+';
  else if (scan->option && (byte == 'a' || byte == 'A'))
    scan->array = true;
  scan->position++;
  return true;
}

static bool token_scan_static_option(const char *input, size_t input_length,
                                     const shell_token_t *token,
                                     static_option_scan_t *scan) {
  if (!scan)
    return false;
  *scan = (static_option_scan_t){0};
  return token_visit_static_word(input, input_length, token, static_option_emit,
                                 scan) &&
         scan->position > 0;
}

/* Find active Bash locale quotes before the full lexer can split the leading
 * '$' from its quoted fragment. Unlike ANSI-C quotes, locale quotes cannot be
 * rendered into canonical argv without the executor's locale and catalog.
 * Comments, escaped dollars, ordinary quotes, and ANSI-C literal text remain
 * outside this check. */
static bool source_has_locale_quote(const char *input, size_t length) {
  if (!input)
    return false;
  bool in_single = false;
  bool in_double = false;
  shell_source_pending_heredoc_t pending[SHELL_SOURCE_MAX_PENDING_HEREDOCS];
  size_t pending_count = 0;
  for (size_t position = 0; position < length; position++) {
    char c = input[position];
    /* Here-document bodies are deferred data, not command-list source. This
     * scanner must mirror the lexer by skipping them wholesale: a locale-like
     * spelling in a quoted body is literal data and must not reject the outer
     * command. */
    if (c == '\n' && pending_count != 0) {
      size_t after = 0;
      if (!shell_source_skip_pending_heredoc_bodies(
              input, length, position + 1, pending, pending_count, &after))
        return false;
      pending_count = 0;
      position = after - 1;
      continue;
    }
    if (c == '\\' && !in_single && position + 1 < length) {
      position++;
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
    if (in_single || in_double)
      continue;
    if (c == '#' && shell_source_comment_starts(input, length, position)) {
      position = shell_source_line_end(input, length, position);
      continue;
    }
    if (c == '<' && position + 2 < length && input[position + 1] == '<' &&
        input[position + 2] != '<') {
      if (pending_count == sizeof(pending) / sizeof(pending[0]))
        return false;
      size_t delimiter = position + 2;
      size_t line_end = shell_source_line_end(input, length, position);
      if (!shell_source_parse_heredoc_delimiter(input, line_end, &delimiter,
                                                &pending[pending_count]))
        return false;
      pending_count++;
      position = delimiter - 1;
      continue;
    }
    if (c == '$' && position + 1 < length && input[position + 1] == '\'') {
      size_t after = 0;
      if (shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                  &after)) {
        position = after - 1;
        continue;
      }
    }
    if (c == '$' && position + 1 < length && input[position + 1] == '"')
      return true;
  }
  return false;
}

/* `${parameter-word}` starts a fresh shell-word context even when the
 * expansion itself is enclosed in double quotes.  Keep this smaller scanner
 * separate from source_has_locale_quote(): parameter words do not have
 * top-level comments or heredoc declarations, but their active `$"..."`
 * fragments still depend on the executor's locale and message catalog. */
static bool word_has_active_locale_quote(const char *input, size_t length) {
  if (!input)
    return false;

  bool in_single = false;
  bool in_double = false;
  for (size_t position = 0; position < length; position++) {
    char c = input[position];
    if (!in_single && !in_double && c == '$' && position + 1 < length &&
        input[position + 1] == '\'') {
      size_t after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &after))
        return false;
      position = after - 1;
      continue;
    }
    if (c == '\\' && !in_single && position + 1 < length) {
      position++;
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
    if (in_single)
      continue;
    if (!in_double && c == '$' && position + 1 < length &&
        input[position + 1] == '"')
      return true;

    /* Re-enter nested parameter and arithmetic words with a fresh quote
     * context. A quote in a nested parameter word is not paired with the
     * quote that encloses its containing expansion. */
    if (c == '$' && position + 1 < length && input[position + 1] == '{') {
      size_t after = 0;
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 &after))
        return false;
      if (word_has_active_locale_quote(input + position + 2,
                                       after - position - 3))
        return true;
      position = after - 1;
      continue;
    }
    if (c == '$' && position + 2 < length && input[position + 1] == '(' &&
        input[position + 2] == '(') {
      size_t after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &after))
        return false;
      if (word_has_active_locale_quote(input + position + 3,
                                       after - position - 5))
        return true;
      position = after - 1;
      continue;
    }
    if (c == '`') {
      size_t after = shell_source_skip_quoted_text(input, length, position, c);
      if (after <= position + 1 || after > length || input[after - 1] != c)
        return false;
      position = after - 1;
      continue;
    }
    if (c == '$' && position + 1 < length && input[position + 1] == '(') {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                                  &after))
        return false;
      position = after - 1;
      continue;
    }
    if (!in_double && (c == '<' || c == '>') && position + 1 < length &&
        input[position + 1] == '(') {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                                  &after))
        return false;
      position = after - 1;
    }
  }
  return false;
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
  bool have_name;
} declaration_array_scan_t;

/* Declaration builtins interpret their operands after quote removal. This
 * scanner recognizes a complete static NAME[subscript] operand without
 * evaluating an expansion or allocating a temporary decoded word. */
static bool declaration_array_emit(unsigned char byte, void *context) {
  declaration_array_scan_t *scan = context;
  if (!scan || scan->state == DECLARATION_ARRAY_OTHER)
    return true;

  switch (scan->state) {
  case DECLARATION_ARRAY_NAME:
    if (!scan->have_name) {
      if (!(isalpha(byte) || byte == '_')) {
        scan->state = DECLARATION_ARRAY_OTHER;
        return true;
      }
      scan->have_name = true;
      return true;
    }
    if (isalnum(byte) || byte == '_')
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

static bool declaration_word_has_array_designator(const char *input,
                                                  size_t length) {
  if (!input)
    return false;
  declaration_array_scan_t scan = {.state = DECLARATION_ARRAY_NAME};
  bool in_single = false;
  bool in_double = false;
  for (size_t position = 0; position < length; position++) {
    char c = input[position];
    if (!in_single && !in_double && c == '$' && position + 1 < length &&
        input[position + 1] == '\'') {
      size_t after = position;
      if (!shell_source_decode_ansi_c_quote(input, length, &after,
                                            declaration_array_emit, &scan))
        return false;
      position = after - 1;
      continue;
    }
    if (c == '\\' && !in_single && position + 1 < length) {
      char next = input[++position];
      if (next == '\r' && position + 1 < length && input[position + 1] == '\n')
        position++;
      if (next == '\n' || next == '\r')
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
      size_t after = shell_source_skip_quoted_text(input, length, position, c);
      if (after <= position + 1 || after > length || input[after - 1] != c)
        return false;
      position = after - 1;
      continue;
    }
    if (!in_single && c == '$' && position + 1 < length &&
        input[position + 1] == '{') {
      size_t after = 0;
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 &after))
        return false;
      position = after - 1;
      continue;
    }
    if (!in_single && c == '$' && position + 2 < length &&
        input[position + 1] == '(' && input[position + 2] == '(') {
      size_t after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &after))
        return false;
      position = after - 1;
      continue;
    }
    if (!in_single && c == '$' && position + 1 < length &&
        input[position + 1] == '(') {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                                  &after))
        return false;
      position = after - 1;
      continue;
    }
    if (!in_single && !in_double && (c == '<' || c == '>') &&
        position + 1 < length && input[position + 1] == '(') {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                                  &after))
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
  if (!token || !input || token->is_quoted || token->is_escaped ||
      token->position > input_length || token->length == 0 ||
      token->length > input_length - token->position)
    return false;

  size_t position = token->position;
  if (position + 1 >= input_length)
    return false;
  if (input[position] == '(' && input[position + 1] == '(')
    return true;
  /* Bash recognizes `[[` as a conditional command only when the delimiter
   * after it begins the condition. Keep a word such as `[[literal` lexical
   * data instead of rejecting a possible external command name. */
  return input[position] == '[' && input[position + 1] == '[' &&
         (position + 2 == input_length ||
          isspace((unsigned char)input[position + 2]));
}

/* Inspect every active expansion in one lexical word.  The full tokenizer may
 * classify a mixed or quoted word as ARGUMENT/GLOB even when it contains an
 * arithmetic expression, parameter array reference, or nested command.  The
 * semantic boundary must therefore follow shell quoting rules rather than the
 * outer token spelling. */
static bool word_has_unsupported_semantics(const char *input, size_t length) {
  if (!input)
    return true;
  if (word_has_active_locale_quote(input, length))
    return true;
  bool in_single = false;
  bool in_double = false;
  for (size_t position = 0; position < length; position++) {
    char c = input[position];
    if (c == '\\' && !in_single && position + 1 < length) {
      position++;
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
    if (in_single)
      continue;
    if (c == '$' && position + 1 < length && input[position + 1] == '\'' &&
        !in_double) {
      size_t after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &after))
        return false;
      position = after - 1;
      continue;
    }
    if (c == '`') {
      size_t after = shell_source_skip_quoted_text(input, length, position, c);
      if (after <= position + 1 || after > length || input[after - 1] != c)
        return false;
      if (shell_tokenizer_has_unsupported_semantics(input + position + 1,
                                                    after - position - 2))
        return true;
      position = after - 1;
      continue;
    }
    if (c == '$' && position + 1 < length && input[position + 1] == '{') {
      size_t after = 0, subscript_start = 0;
      if (shell_source_find_parameter_array_subscript(input, length, position,
                                                      &after, &subscript_start))
        return true;
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 &after))
        return false;
      if (after <= position + 3 || after > length || input[after - 1] != '}')
        return false;
      if (word_has_unsupported_semantics(input + position + 2,
                                         after - position - 3))
        return true;
      position = after - 1;
      continue;
    }
    if (c == '$' && position + 1 < length && input[position + 1] == '(') {
      size_t after = 0;
      if (position + 2 < length && input[position + 2] == '(') {
        if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                    &after))
          return false;
        if (after <= position + 5 ||
            shell_tokenizer_arithmetic_has_array_semantics(
                input + position + 3, after - position - 5))
          return true;
      } else {
        if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                                    &after))
          return false;
        if (after <= position + 3 ||
            shell_tokenizer_has_unsupported_semantics(input + position + 2,
                                                      after - position - 3))
          return true;
      }
      position = after - 1;
      continue;
    }
    if (!in_double && (c == '<' || c == '>') && position + 1 < length &&
        input[position + 1] == '(') {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                                  &after))
        return false;
      if (after <= position + 3 ||
          shell_tokenizer_has_unsupported_semantics(input + position + 2,
                                                    after - position - 3))
        return true;
      position = after - 1;
    }
  }
  return false;
}

/* An unquoted heredoc expands parameter, command, and arithmetic syntax, but
 * does not apply ordinary shell-word quote grouping: quote bytes in its body
 * are data. In particular, `$"..."`, process-substitution spellings, and a
 * bare control word remain literal body bytes. Only the expansions handled
 * below can introduce unsupported shell semantics. */
static bool heredoc_body_has_unsupported_semantics(const char *input,
                                                   size_t length) {
  if (!input)
    return true;
  for (size_t position = 0; position < length; position++) {
    char c = input[position];
    if (c == '\\' && position + 1 < length) {
      char next = input[position + 1];
      if (next == '$' || next == '`' || next == '\\' || next == '\n' ||
          next == '\r') {
        position++;
        continue;
      }
    }
    if (c == '`') {
      size_t after = shell_source_skip_quoted_text(input, length, position, c);
      if (after <= position + 1 || after > length || input[after - 1] != c)
        return false;
      if (shell_tokenizer_has_unsupported_semantics(input + position + 1,
                                                    after - position - 2))
        return true;
      position = after - 1;
      continue;
    }
    if (c != '$' || position + 1 >= length)
      continue;
    if (input[position + 1] == '{') {
      size_t after = 0, subscript_start = 0;
      if (shell_source_find_parameter_array_subscript(input, length, position,
                                                      &after, &subscript_start))
        return true;
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 &after) ||
          after <= position + 3 || after > length || input[after - 1] != '}')
        return false;
      if (heredoc_body_has_unsupported_semantics(input + position + 2,
                                                 after - position - 3))
        return true;
      position = after - 1;
      continue;
    }
    if (input[position + 1] != '(')
      continue;
    size_t after = 0;
    if (position + 2 < length && input[position + 2] == '(') {
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &after))
        return false;
      if (after <= position + 5 ||
          shell_tokenizer_arithmetic_has_array_semantics(input + position + 3,
                                                         after - position - 5))
        return true;
    } else {
      if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                                  &after) ||
          after <= position + 3)
        return false;
      if (shell_tokenizer_has_unsupported_semantics(input + position + 2,
                                                    after - position - 3))
        return true;
    }
    position = after - 1;
  }
  return false;
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
  for (size_t i = 0; i + 1 < token->length; i++) {
    if (token->start[i] == '<' && token->start[i + 1] == '<') {
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

bool shell_tokenizer_has_unsupported_semantics(const char *input,
                                               size_t input_length) {
  if (!input)
    return true;
  shell_tokenizer_state_t state;
  /* This helper classifies valid shell source.  Let each public adapter keep
   * its established EINPUT result for raw control bytes or other invalid
   * source rather than relabelling them as unsupported semantics. */
  if (!shell_tokenizer_init(&state, input, input_length))
    return false;
  if (source_has_locale_quote(input, input_length))
    return true;
  if (shell_tokenizer_has_unsupported_control(input, input_length))
    return true;
  bool declaration = false;
  bool declaration_wrapper = false;
  bool command_start = true;
  size_t redirect_operand_end = 0;
  /* Semantic roles apply to logical shell words, not their lexical quote and
   * escape fragments. Once the first fragment has been classified, skip the
   * remaining fragments until the recovered source-word boundary. */
  size_t semantic_word_end = 0;
  size_t heredoc_sequence_after = 0;
  shell_token_t token;
  while (shell_tokenizer_next(&state, &token)) {
    /* Shellsplit deliberately does not execute or model case clauses.  The
     * clause terminators are meaningful only there, and Bash rejects them in
     * an ordinary command list.  Never reinterpret one as a plain separator.
     */
    if (token.type == SHELL_TOKEN_CASE_TERMINATE ||
        token.type == SHELL_TOKEN_CASE_FALLTHROUGH ||
        token.type == SHELL_TOKEN_CASE_TEST_NEXT)
      return true;
    if (token.type == SHELL_TOKEN_REDIRECT_ERR && token.length >= 4 &&
        token.start[0] == '{')
      return true;
    /* A heredoc delimiter undergoes quote removal only. Its parameter-like
     * spelling is literal and must not be mistaken for an executable word
     * expansion; its body is inspected below with heredoc-specific rules. */
    if (token.type != SHELL_TOKEN_HEREDOC &&
        word_has_unsupported_semantics(token.start, token.length))
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
    if (token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_PIPE_BOTH ||
        token.type == SHELL_TOKEN_SEMICOLON || token.type == SHELL_TOKEN_AND ||
        token.type == SHELL_TOKEN_OR || token.type == SHELL_TOKEN_BACKGROUND) {
      command_start = true;
      declaration = false;
      declaration_wrapper = false;
      semantic_word_end = 0;
      continue;
    }
    if (command_start &&
        token_starts_bash_compound_command(&token, input, input_length))
      return true;
    if (token.type == SHELL_TOKEN_GROUP_START ||
        token.type == SHELL_TOKEN_SUBSHELL_START) {
      command_start = true;
      semantic_word_end = 0;
      continue;
    }
    if (token.type == SHELL_TOKEN_GROUP_END ||
        token.type == SHELL_TOKEN_SUBSHELL_END) {
      command_start = false;
      semantic_word_end = 0;
      continue;
    }
    if (full_token_is_redirection(&token)) {
      redirect_operand_end = full_redirect_end(input, input_length, &token);
      if (full_redirection_consumes_next(&token) &&
          full_named_fd_path_operand_has_process_substitution(&state, &token))
        return true;
      continue;
    }

    if (semantic_word_end != 0 && token.position < semantic_word_end)
      continue;
    semantic_word_end = 0;
    if (control_token_is_word(&token)) {
      size_t word_end = 0;
      if (shell_source_skip_shell_word(input, input_length, token.position,
                                       &word_end) &&
          word_end > token.position && word_end <= input_length)
        semantic_word_end = word_end;
    }

    /* A lexer can recognize the spelling NAME[index]=value without knowing
     * whether it occupies an assignment-prefix position.  Outside that
     * position Bash passes it as an ordinary argument (for example,
     * `echo a[0]=b`), so reject it only when it has array-assignment
     * semantics.  Declaration builtins also give their operands that meaning.
     */
    if (token.type == SHELL_TOKEN_ARRAY_ASSIGNMENT &&
        (command_start || declaration ||
         shell_source_array_assignment_is_compound(token.start, token.length)))
      return true;
    if (declaration &&
        declaration_operand_has_array_designator(input, input_length, &token))
      return true;

    if (command_start) {
      if (token.type == SHELL_TOKEN_PIPE_NEGATE)
        continue;
      /* Scalar assignment prefixes do not consume the command-word position.
       * Keep looking so `VAR=x declare -a values` cannot evade the semantic
       * rejection. */
      if (control_token_is_assignment_prefix(&token))
        continue;
      if (token_is_plain_word(&token, "time"))
        return true;
      declaration_wrapper =
          token_is_static_word(input, input_length, &token, "command") ||
          token_is_static_word(input, input_length, &token, "builtin");
      declaration =
          token_is_static_word(input, input_length, &token, "declare") ||
          token_is_static_word(input, input_length, &token, "typeset") ||
          token_is_static_word(input, input_length, &token, "local") ||
          token_is_static_word(input, input_length, &token, "readonly");
      command_start = false;
      continue;
    }
    if (declaration_wrapper) {
      /* `command` and `builtin` can carry options before the command they
       * invoke. Their operands retain the invoked command's semantics, so do
       * not let `command -p declare -a names` bypass array-declaration
       * rejection. Treat every static quote-removed dash word as a wrapper
       * option; this is deliberately conservative and only affects unsupported
       * semantic classification. */
      static_option_scan_t option;
      if (token_scan_static_option(input, input_length, &token, &option) &&
          option.option)
        continue;
      declaration_wrapper = false;
      declaration =
          token_is_static_word(input, input_length, &token, "declare") ||
          token_is_static_word(input, input_length, &token, "typeset") ||
          token_is_static_word(input, input_length, &token, "local") ||
          token_is_static_word(input, input_length, &token, "readonly");
      continue;
    }
    if (declaration) {
      static_option_scan_t option;
      if (token_scan_static_option(input, input_length, &token, &option) &&
          option.option && option.array)
        return true;
    }
  }
  return false;
}

static shell_control_syntax_t
control_syntax_scan(const char *input, size_t input_length, uint32_t depth) {
  if (depth > 16)
    return SHELL_CONTROL_SYNTAX_INCOMPLETE;
  shell_tokenizer_state_t state;
  if (!shell_tokenizer_init(&state, input, input_length))
    return SHELL_CONTROL_SYNTAX_NONE;

  bool command_start = true;
  size_t redirect_operand_end = 0;
  bool saw_control = false;
  control_frame_state_t frames[SHELL_MAX_SUBCOMMANDS];
  size_t frame_count = 0;
  shell_token_t token;
  while (shell_tokenizer_next(&state, &token)) {
    /* A continued physical line belongs to the surrounding lexical source
     * word. It cannot consume the command-start position between a function
     * name and its declarator. */
    if (shell_source_is_escaped_line_ending(input, token.position,
                                            token.position + token.length))
      continue;
    const char *nested_content = NULL;
    size_t nested_length = 0;
    if (control_token_nested_content(&token, &nested_content, &nested_length)) {
      shell_control_syntax_t nested =
          control_syntax_scan(nested_content, nested_length, depth + 1);
      if (nested != SHELL_CONTROL_SYNTAX_NONE)
        return nested;
    }
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
      continue;
    }
    if (token.type == SHELL_TOKEN_GROUP_START ||
        token.type == SHELL_TOKEN_SUBSHELL_START) {
      command_start = true;
      continue;
    }
    if (token.type == SHELL_TOKEN_GROUP_END ||
        token.type == SHELL_TOKEN_SUBSHELL_END) {
      command_start = false;
      continue;
    }
    if (full_token_is_redirection(&token)) {
      redirect_operand_end = full_redirect_end(input, input_length, &token);
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
        (control_token_is(&token, "function") &&
         control_function_keyword_has_name(&token, input, input_length)))
      return SHELL_CONTROL_SYNTAX_COMPLETE;

    control_frame_t frame;
    bool push_frame = false;
    if (control_token_is(&token, "if")) {
      frame = CONTROL_FRAME_IF;
      push_frame = true;
    } else if (control_token_is(&token, "while") ||
               control_token_is(&token, "until") ||
               control_token_is(&token, "for") ||
               control_token_is(&token, "select")) {
      frame = CONTROL_FRAME_LOOP;
      push_frame = true;
    } else if (control_token_is(&token, "coproc")) {
      /* Bash coprocesses introduce a concurrently executing command and a
       * pair of implicit descriptors.  The semantic command model does not
       * represent either yet, so reject them explicitly rather than treating
       * `coproc` as an ordinary executable name. */
      return SHELL_CONTROL_SYNTAX_COMPLETE;
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

typedef struct {
  bool needs_stage;
  bool pipeline_start;
  bool has_negation;
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
      .has_negation = false,
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
         (token->start[0] == '\n' || token->start[0] == '\r');
}

/* Structural punctuation can be returned as a standalone token immediately
 * after a preceding escape. The token itself then has no escape byte to mark,
 * so inspect the source run that ends at its position. */
static bool shell_list_token_is_literal(const char *input,
                                        const shell_token_t *token) {
  if (token->is_quoted || token->is_escaped)
    return true;
  size_t backslashes = 0;
  for (size_t pos = (size_t)(token->start - input);
       pos > 0 && input[pos - 1] == '\\'; pos--)
    backslashes++;
  return (backslashes % 2) != 0;
}

/* Control-compound detection deliberately tolerates incomplete syntax so a
 * semantic caller can report it as unsupported. It must not bypass the shell
 * grammar rule for redirect operands: only horizontal whitespace and escaped
 * physical line endings can separate an operator from its shell word. */
static bool full_redirect_operands_have_inline_boundaries(const char *input,
                                                          size_t input_length) {
  shell_tokenizer_state_t tokenizer;
  if (!shell_tokenizer_init(&tokenizer, input, input_length))
    return false;

  bool operand_pending = false;
  size_t operator_end = 0;
  shell_token_t token;
  while (shell_tokenizer_next(&tokenizer, &token)) {
    bool literal_token = shell_list_token_is_literal(input, &token);
    if (shell_source_is_escaped_line_ending(input, token.position,
                                            token.position + token.length))
      continue;

    if (operand_pending) {
      if (shell_list_token_is_newline(&token) ||
          (token.position != operator_end &&
           shell_source_skip_inline_continuations(
               input, token.position, operator_end) != token.position))
        return false;
      if (!literal_token && full_token_is_redirection(&token) &&
          token.position == operator_end) {
        operand_pending = full_redirection_consumes_next(&token);
        operator_end = token.position + token.length;
        continue;
      }
      if (!literal_token &&
          (full_token_is_redirection(&token) ||
           token.type == SHELL_TOKEN_GROUP_END ||
           token.type == SHELL_TOKEN_SUBSHELL_END ||
           token.type == SHELL_TOKEN_PIPE_NEGATE ||
           token.type == SHELL_TOKEN_PIPE ||
           token.type == SHELL_TOKEN_PIPE_BOTH ||
           token.type == SHELL_TOKEN_AND || token.type == SHELL_TOKEN_OR ||
           token.type == SHELL_TOKEN_SEMICOLON ||
           token.type == SHELL_TOKEN_BACKGROUND ||
           ((token.type == SHELL_TOKEN_GROUP_START ||
             token.type == SHELL_TOKEN_SUBSHELL_START) &&
            (token.position == 0 || input[token.position - 1] != '$'))))
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
bool shell_tokenizer_list_syntax_valid(const char *input, size_t input_length) {
  if (!input)
    return false;

  if (!full_redirect_operands_have_inline_boundaries(input, input_length))
    return false;
  /* Control compounds have their own list grammar (notably `case` uses `;;`).
   * They remain lexically representable so canonical APIs can reject them as
   * unsupported. Classify them before brace validation: a text-only `then` or
   * `do` must never be mistaken for structural syntax in an ordinary command.
   */
  if (shell_tokenizer_control_syntax(input, input_length) !=
      SHELL_CONTROL_SYNTAX_NONE)
    return true;
  if (!brace_groups_valid(input, input_length))
    return false;
  if (full_has_bare_redirect_group_operand(input, input_length) ||
      full_has_redirect_prefix_group(input, input_length))
    return false;

  shell_tokenizer_state_t tokenizer;
  if (!shell_tokenizer_init(&tokenizer, input, input_length))
    return false;

  shell_list_state_t state = shell_list_state_initial();
  shell_list_group_state_t groups[SHELL_MAX_GROUPS];
  size_t group_count = 0;
  bool saw_token = false;
  shell_token_t token;
  while (shell_tokenizer_next(&tokenizer, &token)) {
    bool literal_token = shell_list_token_is_literal(input, &token);

    /* The iterator retains source spans, so a bare escaped line ending can
     * appear as an argument token. It is grammar rather than a command word
     * in every list state. */
    if (shell_source_is_escaped_line_ending(input, token.position,
                                            token.position + token.length))
      continue;
    saw_token = true;

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
      /* Adjacent redirect fragments can belong to one operator. Keep
       * extending it until its actual shell-word operand begins. */
      if (!literal_token && full_token_is_redirection(&token) &&
          token.position == state.redirect_operator_end) {
        state.redirect_operand = full_redirection_consumes_next(&token);
        state.redirect_operator_end = token.position + token.length;
        continue;
      }
      if (!literal_token &&
          (full_token_is_redirection(&token) ||
           token.type == SHELL_TOKEN_GROUP_END ||
           token.type == SHELL_TOKEN_SUBSHELL_END ||
           token.type == SHELL_TOKEN_PIPE_NEGATE ||
           token.type == SHELL_TOKEN_PIPE ||
           token.type == SHELL_TOKEN_PIPE_BOTH ||
           token.type == SHELL_TOKEN_AND || token.type == SHELL_TOKEN_OR ||
           token.type == SHELL_TOKEN_SEMICOLON ||
           token.type == SHELL_TOKEN_BACKGROUND ||
           ((token.type == SHELL_TOKEN_GROUP_START ||
             token.type == SHELL_TOKEN_SUBSHELL_START) &&
            (token.position == 0 || input[token.position - 1] != '$'))))
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
          token.type != SHELL_TOKEN_PIPE_NEGATE &&
          token.type != SHELL_TOKEN_PIPE &&
          token.type != SHELL_TOKEN_PIPE_BOTH &&
          token.type != SHELL_TOKEN_AND && token.type != SHELL_TOKEN_OR &&
          token.type != SHELL_TOKEN_SEMICOLON &&
          token.type != SHELL_TOKEN_BACKGROUND) {
        state.group_redirect_word_end = token.position + token.length;
        continue;
      }
      if (state.group_redirect_operand) {
        /* Adjacent redirect fragments extend one operator rather than
         * introducing a second redirect with a missing first operand. */
        if (!literal_token && full_token_is_redirection(&token) &&
            token.position == state.group_redirect_operator_end) {
          state.group_redirect_operator_end = token.position + token.length;
          continue;
        }
        /* The iterator exposes the `(` in `$(command)` as a group token.
         * It is nevertheless one redirect operand, not a bare group after a
         * completed compound command. Let the existing balanced-group path
         * consume it, then re-establish the post-group boundary at its close.
         */
        if (!literal_token &&
            (token.type == SHELL_TOKEN_GROUP_START ||
             token.type == SHELL_TOKEN_SUBSHELL_START) &&
            token.position != 0 && input[token.position - 1] == '$') {
          state.group_redirect_operand = false;
          state.after_group = false;
          if (group_count == SHELL_MAX_GROUPS)
            return false;
          groups[group_count++] = (shell_list_group_state_t){
              .parent = state,
              .opening_type = token.type,
              .opening_position = token.position,
          };
          state = shell_list_state_initial();
          continue;
        } else {
          if (!literal_token &&
              (full_token_is_redirection(&token) ||
               token.type == SHELL_TOKEN_GROUP_START ||
               token.type == SHELL_TOKEN_SUBSHELL_START ||
               token.type == SHELL_TOKEN_GROUP_END ||
               token.type == SHELL_TOKEN_SUBSHELL_END ||
               token.type == SHELL_TOKEN_PIPE_NEGATE ||
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
      }
      if (full_token_is_redirection(&token)) {
        state.group_redirect_operand = full_redirection_consumes_next(&token);
        state.group_redirect_word_open = false;
        state.group_redirect_operator_end = token.position + token.length;
        continue;
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
    if (!literal_token && (token.type == SHELL_TOKEN_GROUP_START ||
                           token.type == SHELL_TOKEN_SUBSHELL_START)) {
      /* A compound command begins a pipeline stage; it cannot be appended to
       * an already complete simple command (`echo (cmd)`). Command
       * substitutions retain their leading dollar and are one shell word,
       * not this grammar production. */
      if (!state.needs_stage &&
          (token.position == 0 || input[token.position - 1] != '$'))
        return false;
      if (group_count == SHELL_MAX_GROUPS)
        return false;
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
      state.has_negation = false;
      state.may_end = false;
      state.redirect_operand = false;
      state.redirect_operator_end = 0;
      state.after_group = true;
      state.group_redirect_operand = false;
      state.group_redirect_word_open = false;
      state.group_redirect_word_end = 0;
      state.group_redirect_operator_end = 0;
      continue;
    }

    if (!literal_token && token.type == SHELL_TOKEN_PIPE_NEGATE) {
      if (!state.needs_stage) {
        /* `!` is only a pipeline modifier at a pipeline start. Elsewhere the
         * full tokenizer intentionally preserves it as a simple-command word
         * (for example, `echo !`). */
        continue;
      }
      if (!state.pipeline_start)
        return false;
      if (!state.has_negation) {
        state.has_negation = true;
        state.may_end = false;
        continue;
      }
      /* Bash permits repeated leading negators. They all modify the same
       * pipeline; the processor retains their exact count and parity. */
      continue;
    }

    if (!literal_token && token.type == SHELL_TOKEN_SEMICOLON &&
        shell_list_token_is_newline(&token) && state.needs_stage) {
      /* A binary list connector continues across physical lines. A pending
       * `!` does not: its next stage must stay on the same logical line (or
       * use an escaped physical continuation). */
      if (state.has_negation)
        return false;
      continue;
    }

    if (!literal_token &&
        (token.type == SHELL_TOKEN_PIPE ||
         token.type == SHELL_TOKEN_PIPE_BOTH || token.type == SHELL_TOKEN_AND ||
         token.type == SHELL_TOKEN_OR || token.type == SHELL_TOKEN_SEMICOLON ||
         token.type == SHELL_TOKEN_BACKGROUND)) {
      if (state.needs_stage)
        return false;
      state.needs_stage = true;
      state.pipeline_start =
          token.type != SHELL_TOKEN_PIPE && token.type != SHELL_TOKEN_PIPE_BOTH;
      state.has_negation = false;
      state.may_end = token.type == SHELL_TOKEN_SEMICOLON ||
                      token.type == SHELL_TOKEN_BACKGROUND;
      state.redirect_operand = false;
      state.redirect_operator_end = 0;
      state.after_group = false;
      state.group_redirect_operand = false;
      state.group_redirect_word_open = false;
      state.group_redirect_word_end = 0;
      state.group_redirect_operator_end = 0;
      continue;
    }

    state.needs_stage = false;
    state.pipeline_start = false;
    state.has_negation = false;
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

  /* The lexical API intentionally retains incomplete parenthesized prefixes
   * for diagnostics. Strict semantic callers reject them later. */
  return !saw_token || group_count != 0 ||
         (!state.redirect_operand && !state.group_redirect_operand &&
          (!state.needs_stage || state.may_end));
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
  if (!shell_tokenizer_list_syntax_valid(input, input_length))
    return SHELL_TOKENIZE_EPARSE;

  shell_tokenizer_state_t state;
  if (!shell_tokenizer_init(&state, input, input_length))
    return SHELL_TOKENIZE_EINPUT;

  size_t count = 0;
  bool expect_command = true;
  bool pipeline_start = true;
  uint32_t pipeline_negation_count = 0;

  shell_tokenizer_state_t temp_state = state;
  shell_token_t token;

  while (shell_tokenizer_next(&temp_state, &token)) {
    /* The zero-copy iterator keeps escaped physical line endings in the
     * source stream. A standalone continuation never contributes a command
     * token or list separator. */
    if (shell_source_is_escaped_line_ending(input, token.position,
                                            token.position + token.length))
      continue;
    /* The list-syntax validator has already rejected a raw physical newline
     * after a pending `!`. Here a newline only continues a validated binary
     * list operator. */
    if (expect_command && shell_list_token_is_newline(&token))
      continue;
    if (token.type == SHELL_TOKEN_PIPE_NEGATE) {
      if (pipeline_start) {
        if (pipeline_negation_count == UINT32_MAX)
          return SHELL_TOKENIZE_EOVERFLOW;
        pipeline_negation_count++;
        continue;
      }
      continue;
    }
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
      pipeline_negation_count = 0;
    }

    if (token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_PIPE_BOTH ||
        token.type == SHELL_TOKEN_SEMICOLON || token.type == SHELL_TOKEN_AND ||
        token.type == SHELL_TOKEN_BACKGROUND || token.type == SHELL_TOKEN_OR) {
      expect_command = true;
      pipeline_start =
          token.type != SHELL_TOKEN_PIPE && token.type != SHELL_TOKEN_PIPE_BOTH;
      pipeline_negation_count = 0;
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
  current_cmd->pipeline_negation_count = 0;
  current_cmd->pipeline_negated = false;

  expect_command = true;
  pipeline_start = true;
  pipeline_negation_count = 0;
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
      continue;
    }
    closed_group_at_end = token.type == SHELL_TOKEN_GROUP_END;
    saw_loop = saw_loop || state.loop_depth > 0;
    saw_conditional = saw_conditional || state.if_depth > 0;
    saw_case = saw_case || state.case_depth > 0;
    if (token.type == SHELL_TOKEN_GROUP_START ||
        token.type == SHELL_TOKEN_GROUP_END) {
      group_tail_active = token.type == SHELL_TOKEN_GROUP_END;
      bool group_starts_command =
          token.type == SHELL_TOKEN_GROUP_START && expect_command &&
          current_cmd->token_count != 0 &&
          current_cmd->token_count != pipeline_negation_count;
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
        current_cmd->pipeline_negation_count = 0;
        current_cmd->pipeline_negated = false;
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
        pipeline_negation_count = 0;
        continue;
      }
    }
    bool redirect_operand = full_tokens_need_redirect_operand(
        input, input_length, current_cmd->tokens, current_cmd->token_count,
        &token);
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
      if (pipeline_negation_count == UINT32_MAX) {
        shell_commands_free(*commands, count);
        *commands = NULL;
        *command_count = 0;
        return SHELL_TOKENIZE_EOVERFLOW;
      }
      pipeline_negation_count++;
      current_cmd->pipeline_negation_count = pipeline_negation_count;
      current_cmd->pipeline_negated =
          (pipeline_negation_count & UINT32_C(1)) != 0;
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
         token.type == SHELL_TOKEN_PROCESS_SUB)) {
      /* The leading `!` is retained as the pipeline's syntax token, but it
       * does not occupy a simple-command slot. The first following word must
       * join that same record rather than create a phantom `!` command. */
      bool has_only_pipeline_negation =
          pipeline_negation_count != 0 &&
          current_cmd->token_count == pipeline_negation_count;
      if (current_cmd->token_count > 0 && !redirect_operand &&
          !has_only_pipeline_negation) {
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
          current_cmd->pipeline_negation_count = 0;
          current_cmd->pipeline_negated = false;
        }
      } else if (current_cmd->has_groups && !redirect_operand) {
        current_cmd->start_pos = token.position;
      }
      expect_command = false;
      pipeline_start = false;
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
      pipeline_negation_count = 0;
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
    uint32_t active_negation_count = 0;
    for (size_t i = 0; i < count; i++) {
      (*commands)[i].has_loops = saw_loop;
      (*commands)[i].has_conditionals = saw_conditional;
      (*commands)[i].has_case = saw_case;
      if ((*commands)[i].pipeline_negation_count != 0) {
        active_negation_count = (*commands)[i].pipeline_negation_count;
      } else if (i > 0 &&
                 (*commands)[i - 1].pipe_output_mode != SHELL_PIPE_MODE_NONE) {
        (*commands)[i].pipeline_negation_count = active_negation_count;
      } else {
        active_negation_count = 0;
      }
      (*commands)[i].pipeline_negated =
          ((*commands)[i].pipeline_negation_count & UINT32_C(1)) != 0;
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
  case SHELL_TOKEN_PIPE_BOTH:
    return "PIPE_BOTH";
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

// Check if command has shell scripting features
bool shell_command_has_shell_features(const shell_command_t *command) {
  if (command == NULL)
    return false;
  return command->has_variables || command->has_globs ||
         command->has_subshells || command->has_arithmetic;
}
