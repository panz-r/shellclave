#include "shell_tokenizer.h"
#include "shell_source_internal.h"
#include "shell_tokenizer_full.h"
#include "shell_tokenizer_full_internal.h"
#include <ctype.h>
#include <string.h>

/* --- FAST PARSER IMPLEMENTATION --- */

/**
 * Check if character is a shell separator
 */
static inline bool is_separator(char c) {
  return c == '|' || c == ';' || c == '&' || c == '<' || c == '>' ||
         c == '\n' || c == '\r';
}

static bool source_range_is_whitespace(const char *cmd, uint32_t start,
                                       uint32_t end) {
  for (uint32_t pos = start; pos < end; pos++)
    if (!isspace((unsigned char)cmd[pos]))
      return false;
  return true;
}

/* A pending list connector may be followed by blank space, comments, and
 * escaped physical line endings before its stage begins. Keep this narrower
 * than general word scanning: any other byte starts a real stage. */
static bool source_range_is_list_continuation_trivia(const char *cmd,
                                                     uint32_t start,
                                                     uint32_t end) {
  return shell_source_is_list_trivia(cmd, start, end);
}

/* An io_number is contiguous with its redirect and starts at a shell-word
 * boundary. Values above INT_MAX remain ordinary argument text. */
static uint32_t source_io_number_start_before(const char *cmd, uint32_t marker,
                                              uint32_t length) {
  return (uint32_t)shell_source_io_number_start_before(cmd, length, marker);
}

/* A named descriptor is a redirect prefix in exactly the same way as an
 * io_number.  Keep the prefix out of the preceding command range: `{fd}` in
 * `cmd {fd}<<<word` is syntax, not argv.  The source helper remains the
 * authority for the spelling; this small reverse scan only finds its start. */
static uint32_t source_redirect_prefix_start_before(const char *cmd,
                                                    uint32_t marker,
                                                    uint32_t length) {
  uint32_t numeric = source_io_number_start_before(cmd, marker, length);
  if (numeric != marker)
    return numeric;
  return (uint32_t)shell_source_named_fd_start_before(cmd, length, marker);
}

/* `{` and `}` are reserved words only when they form a complete word. Keep
 * this separate from parameter-expansion handling: an unquoted `}` in
 * `echo foo}` is ordinary argument text, whereas `foo; }` is an invalid
 * command-position closer. */
static bool group_word_ends_here(const char *cmd, uint32_t pos,
                                 uint32_t cmd_len) {
  if (pos + 1 == cmd_len)
    return true;
  char next = cmd[pos + 1];
  return isspace((unsigned char)next) || is_separator(next) || next == ')';
}

/* Advance across one shell word without splitting a quoted here-string
 * operand at embedded whitespace.  Full word decoding remains the processor's
 * responsibility; this only preserves the parser's source range. */
static uint32_t skip_shell_word(const char *cmd, uint32_t pos,
                                uint32_t cmd_len) {
  size_t after = pos;
  if (!shell_source_skip_shell_word(cmd, cmd_len, pos, &after) ||
      after > UINT32_MAX)
    return pos;
  return (uint32_t)after;
}

/* POSIX permits redirects following a compound command, but not before its
 * opening delimiter.  Recognize a complete prefix here solely to reject that
 * otherwise easy-to-misparse extension. */
static bool redirect_list_precedes_group(const char *cmd, uint32_t start,
                                         uint32_t end) {
  return shell_source_redirect_list_before_group(cmd, start, end);
}

typedef struct {
  uint32_t start;
  uint32_t end;
} heredoc_body_span_t;

/* Find complete heredoc body blocks. Their contents are data for the fast
 * structural parser, even though later layers may inspect unquoted bodies for
 * expansions. An incomplete declaration deliberately leaves no span: the
 * normal fast-parser contract remains permissive, while strict callers reject
 * it through the same scanner. */
static bool collect_heredoc_body_spans(const char *cmd, uint32_t length,
                                       heredoc_body_span_t *spans,
                                       uint32_t capacity,
                                       uint32_t *span_count) {
  shell_source_pending_heredoc_t pending[SHELL_MAX_SUBCOMMANDS];
  uint32_t pending_count = 0;
  *span_count = 0;
  char quote = '\0';
  for (uint32_t position = 0; position < length;) {
    char c = cmd[position];
    if (quote) {
      if (c == '\\' && quote == '"' && position + 1 < length) {
        position += 2;
        continue;
      }
      if (c == quote)
        quote = '\0';
      position++;
      continue;
    }
    if (c == '\\' && position + 1 < length) {
      size_t continued =
          shell_source_skip_escaped_line_endings(cmd, length, position);
      position = (uint32_t)(continued != position ? continued : position + 2);
      continue;
    }
    if (c == '$' &&
        shell_source_logical_next_is(cmd, length, position, '\'', NULL)) {
      size_t after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(cmd, length, position,
                                                   &after) ||
          after > UINT32_MAX)
        return false;
      position = (uint32_t)after;
      continue;
    }
    if (c == '\'' || c == '"') {
      quote = c;
      position++;
      continue;
    }
    if (c == '$' &&
        shell_source_dollar_arithmetic_open(cmd, length, position, NULL)) {
      size_t after = 0;
      if (!shell_source_skip_arithmetic_expansion(cmd, length, position,
                                                  &after) ||
          after > UINT32_MAX)
        return false;
      position = (uint32_t)after;
      continue;
    }
    if (c == '#' && shell_source_comment_starts(cmd, length, position)) {
      while (position < length && cmd[position] != '\n')
        position++;
      continue;
    }
    size_t operator_after = 0;
    if (c == '<' && shell_source_match_logical_punctuation(
                        cmd, length, position, "<<<", &operator_after)) {
      position = (uint32_t)operator_after;
      continue;
    }
    if (c == '<' && shell_source_match_logical_punctuation(
                        cmd, length, position, "<<", &operator_after)) {
      if (pending_count == SHELL_MAX_SUBCOMMANDS)
        return false;
      size_t delimiter = operator_after;
      if (!shell_source_parse_heredoc_delimiter(cmd, length, &delimiter,
                                                &pending[pending_count]) ||
          delimiter > UINT32_MAX)
        return false;
      position = (uint32_t)delimiter;
      pending_count++;
      continue;
    }
    if ((c != '\n' && c != '\r') || pending_count == 0) {
      position++;
      continue;
    }
    position = (uint32_t)shell_source_next_line(cmd, length, position);
    uint32_t body_start = position;
    for (uint32_t h = 0; h < pending_count; h++) {
      bool found = false;
      while (position <= length) {
        uint32_t line_start = position;
        if (shell_source_line_is_heredoc_delimiter(cmd, length, line_start,
                                                   &pending[h])) {
          position = (uint32_t)shell_source_next_line(cmd, length, line_start);
          found = true;
          break;
        }
        if (position == length)
          break;
        position = (uint32_t)shell_source_next_line(cmd, length, line_start);
        if (position <= line_start)
          break;
      }
      if (!found)
        return false;
    }
    if (*span_count == capacity)
      return false;
    spans[(*span_count)++] = (heredoc_body_span_t){body_start, position};
    pending_count = 0;
  }
  return quote == '\0' && pending_count == 0;
}

/* Strict callers require every top-level heredoc declaration to have a
 * matching terminator. */
static bool strict_heredocs_complete(const char *cmd, uint32_t length) {
  heredoc_body_span_t spans[SHELL_MAX_SUBCOMMANDS];
  uint32_t span_count = 0;
  return collect_heredoc_body_spans(cmd, length, spans, SHELL_MAX_SUBCOMMANDS,
                                    &span_count);
}

static bool shell_identifier_start(char c) {
  return isalpha((unsigned char)c) || c == '_';
}

static bool shell_identifier_continue(char c) {
  return isalnum((unsigned char)c) || c == '_';
}

/* Recognize assignment syntax that establishes an array without treating the
 * index as a glob or the compound value as a command group. */
static bool skip_array_assignment(const char *input, uint32_t length,
                                  uint32_t position, size_t *after,
                                  size_t *subscript_start,
                                  size_t *subscript_after, size_t *value_start,
                                  size_t *value_after) {
  if (!input || !after || !subscript_start || !subscript_after ||
      !value_start || !value_after || position >= length ||
      !shell_identifier_start(input[position]))
    return false;

  *subscript_start = 0;
  *subscript_after = 0;
  *value_start = 0;
  *value_after = 0;

  size_t cursor = position + 1;
  while (cursor < length && shell_identifier_continue(input[cursor]))
    cursor++;
  bool indexed = false;
  if (cursor < length && input[cursor] == '[') {
    *subscript_start = cursor;
    if (!shell_source_skip_array_subscript(input, length, cursor, &cursor))
      return false;
    *subscript_after = cursor;
    indexed = true;
  }
  if (cursor < length && input[cursor] == '+')
    cursor++;
  if (cursor >= length || input[cursor] != '=')
    return false;
  if (!indexed && (cursor + 1 >= length || input[cursor + 1] != '('))
    return false;

  cursor++;
  if (cursor < length && input[cursor] == '(') {
    size_t group_start = cursor;
    if (!shell_source_find_balanced_parentheses(input, length, cursor, &cursor))
      return false;
    *value_start = group_start + 1;
    *value_after = cursor - 1;
  }
  *after = cursor;
  return true;
}

/* The fast scanner is lexical, but an array-shaped assignment is an array
 * assignment only before a command word. Keep this tiny no-allocation view of
 * the full token stream so `echo a[0]=b` remains an ordinary glob-capable
 * argument while `a[0]=b command` is tagged as Bash array syntax. */
typedef struct {
  shell_tokenizer_state_t state;
  shell_token_t token;
  bool ready;
  bool command_start;
  bool redirect_operand;
  bool token_array_assignment;
} fast_array_context_t;

static bool fast_token_is_redirection(const shell_token_t *token) {
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

static bool fast_redirection_consumes_next(const shell_token_t *token) {
  return token &&
         shell_source_redirection_consumes_word(token->start, token->length);
}

static bool fast_token_is_scalar_assignment(const shell_token_t *token) {
  if (!token || token->is_quoted || token->is_escaped || token->length < 3 ||
      (token->type != SHELL_TOKEN_COMMAND &&
       token->type != SHELL_TOKEN_ARGUMENT) ||
      !shell_identifier_start(token->start[0]))
    return false;
  size_t position = 1;
  while (position < token->length &&
         shell_identifier_continue(token->start[position]))
    position++;
  return position < token->length && token->start[position] == '=';
}

static bool fast_array_context_init(fast_array_context_t *context,
                                    const char *input, uint32_t length) {
  if (!context || !shell_tokenizer_init(&context->state, input, length))
    return false;
  context->ready = false;
  context->command_start = true;
  context->redirect_operand = false;
  context->token_array_assignment = false;
  return true;
}

static bool fast_array_context_next(fast_array_context_t *context) {
  if (!shell_tokenizer_next(&context->state, &context->token))
    return false;
  context->ready = true;
  context->token_array_assignment =
      context->token.type == SHELL_TOKEN_ARRAY_ASSIGNMENT &&
      (context->command_start ||
       shell_source_array_assignment_is_compound(context->token.start,
                                                 context->token.length));

  if (context->token.type == SHELL_TOKEN_PIPE_NEGATE)
    return true;
  if (context->token.type == SHELL_TOKEN_PIPE ||
      context->token.type == SHELL_TOKEN_PIPE_BOTH ||
      context->token.type == SHELL_TOKEN_SEMICOLON ||
      context->token.type == SHELL_TOKEN_AND ||
      context->token.type == SHELL_TOKEN_OR ||
      context->token.type == SHELL_TOKEN_BACKGROUND) {
    context->command_start = true;
    context->redirect_operand = false;
    return true;
  }
  if (context->token.type == SHELL_TOKEN_GROUP_START ||
      context->token.type == SHELL_TOKEN_SUBSHELL_START) {
    context->command_start = true;
    context->redirect_operand = false;
    return true;
  }
  if (context->token.type == SHELL_TOKEN_GROUP_END ||
      context->token.type == SHELL_TOKEN_SUBSHELL_END) {
    context->command_start = false;
    context->redirect_operand = false;
    return true;
  }
  if (fast_token_is_redirection(&context->token)) {
    context->redirect_operand = fast_redirection_consumes_next(&context->token);
    return true;
  }
  if (context->redirect_operand) {
    context->redirect_operand = false;
    return true;
  }
  if (context->command_start &&
      (context->token.type == SHELL_TOKEN_ARRAY_ASSIGNMENT ||
       fast_token_is_scalar_assignment(&context->token)))
    return true;
  context->command_start = false;
  return true;
}

static bool fast_array_assignment_at(fast_array_context_t *context,
                                     uint32_t position) {
  if (!context)
    return false;
  while ((!context->ready || context->token.position < position) &&
         fast_array_context_next(context))
    ;
  return context->ready && context->token.position == position &&
         context->token_array_assignment;
}

static void detect_features(const char *cmd, uint32_t start, uint32_t len,
                            uint32_t *features);

/* Parameter operands have their own lexical scope. Scan expansion features
 * there, but do not promote their punctuation to the containing command's
 * list/pipeline/redirect flags. Executable substitutions are then inspected
 * in their own command scope. */
static void detect_parameter_features(const char *input, size_t position,
                                      size_t after, bool outer_double_quote,
                                      uint32_t *features) {
  uint32_t inner = 0;
  size_t brace = shell_source_logical_following(input, after, position);
  if (brace + 1 < after - 1)
    detect_features(input, (uint32_t)brace + 1, (uint32_t)(after - brace - 2),
                    &inner);
  const uint32_t syntax = SHELL_FEAT_BACKGROUND | SHELL_FEAT_GLOBS |
                          SHELL_FEAT_PIPELINE | SHELL_FEAT_GROUP |
                          SHELL_FEAT_HEREDOC | SHELL_FEAT_HERESTRING |
                          SHELL_FEAT_NAMED_FD | SHELL_FEAT_COMBINED_REDIRECT |
                          SHELL_FEAT_SUBSHELL | SHELL_FEAT_PROCESS_SUB;
  *features |= SHELL_FEAT_VARS | (inner & ~syntax);

  shell_source_substitution_scan_t scan = {0};
  scan.in_double_quote = outer_double_quote;
  size_t start = 0, end = 0;
  shell_source_substitution_kind_t kind;
  while (shell_source_next_executable_substitution(
      input + position, after - position, &scan, &start, &end, &kind)) {
    size_t body_start = start + 1;
    if (kind == SHELL_SOURCE_SUBST_COMMAND) {
      *features |= SHELL_FEAT_SUBSHELL;
      body_start = shell_source_logical_following(input + position,
                                                  after - position, start) +
                   1;
    } else if (kind == SHELL_SOURCE_SUBST_BACKTICK) {
      *features |= SHELL_FEAT_SUBSHELL;
    } else {
      *features |= SHELL_FEAT_PROCESS_SUB;
      body_start = shell_source_logical_following(input + position,
                                                  after - position, start) +
                   1;
    }
    if (end > body_start + 1)
      detect_features(input + position, (uint32_t)body_start,
                      (uint32_t)(end - body_start - 1), features);
  }
}

/* Arithmetic content has its own grammar: `items[0]` is an array reference,
 * not a pathname glob. Scan only expansion features here and recurse into
 * command substitutions, rather than feeding the expression through the
 * ordinary shell-word feature walker. */
static void detect_arithmetic_features(const char *cmd, size_t start,
                                       size_t end, uint32_t *features) {
  if (!cmd || !features || start > end)
    return;
  for (size_t position = start; position < end;) {
    char c = cmd[position];
    if (c == '\\' && position + 1 < end) {
      size_t continued =
          shell_source_skip_escaped_line_endings(cmd, end, position);
      position = continued != position ? continued : position + 2;
      continue;
    }
    if (c == '$' &&
        shell_source_logical_next_is(cmd, end, position, '\'', NULL)) {
      size_t after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(cmd, end, position, &after))
        return;
      *features |= SHELL_FEAT_ANSI_C_QUOTE;
      position = after;
      continue;
    }
    if (c == '\'' || c == '"') {
      size_t after = 0;
      if (!shell_source_skip_complete_quoted_text(cmd, end, position, c,
                                                  &after))
        return;
      position = after;
      continue;
    }
    if (c == '`') {
      size_t after = 0;
      if (!shell_source_skip_complete_backtick(cmd, end, position, &after))
        return;
      *features |= SHELL_FEAT_SUBSHELL;
      if (after > position + 1)
        detect_features(cmd, (uint32_t)position + 1,
                        (uint32_t)(after - position - 2), features);
      position = after;
      continue;
    }
    if (isdigit((unsigned char)c)) {
      size_t after = 0;
      if (shell_source_skip_arithmetic_number(cmd, end, position, &after)) {
        position = after;
        continue;
      }
    }
    if (c == '$') {
      size_t command_open = 0;
      if (shell_source_dollar_arithmetic_open(cmd, end, position, NULL)) {
        size_t content_start = 0, content_length = 0, after = 0;
        if (!shell_source_arithmetic_content(cmd, end, position, &content_start,
                                             &content_length, &after))
          return;
        *features |= SHELL_FEAT_ARITH;
        detect_arithmetic_features(cmd, content_start,
                                   content_start + content_length, features);
        position = after;
        continue;
      }
      if (shell_source_dollar_parentheses_open(cmd, end, position,
                                               &command_open)) {
        size_t after = 0;
        if (!shell_source_find_balanced_parentheses(cmd, end, command_open,
                                                    &after))
          return;
        *features |= SHELL_FEAT_SUBSHELL;
        if (after > command_open + 1)
          detect_features(cmd, (uint32_t)command_open + 1,
                          (uint32_t)(after - command_open - 2), features);
        position = after;
        continue;
      }
      size_t next = shell_source_logical_following(cmd, end, position);
      if (next < end &&
          (isalpha((unsigned char)cmd[next]) || cmd[next] == '_' ||
           isdigit((unsigned char)cmd[next]) || strchr("#?$!@*-{", cmd[next])))
        *features |= SHELL_FEAT_VARS;
    }
    if (isalpha((unsigned char)c) || c == '_')
      *features |= SHELL_FEAT_VARS;
    position++;
  }
}

/**
 * Detect features in a subcommand range
 */
static void detect_features(const char *cmd, uint32_t start, uint32_t len,
                            uint32_t *features) {
  static _Thread_local unsigned nesting;
  if (nesting >= SHELL_MAX_SUBCOMMANDS)
    return;
  nesting++;
  const char *p = cmd + start;
  uint32_t i = 0;
  bool in_single_quotes = false;
  bool in_double_quotes = false;
  fast_array_context_t array_context;
  bool have_array_context = fast_array_context_init(&array_context, p, len);

  while (i < len) {
    char c = p[i];

    // Handle single quotes - no expansion inside
    if (c == '\'' && !in_double_quotes) {
      in_single_quotes = !in_single_quotes;
      i++;
      continue;
    }

    if (in_single_quotes) {
      i++;
      continue;
    }

    // Handle double quotes - variables expand, globs don't
    if (c == '"' && !in_single_quotes) {
      in_double_quotes = !in_double_quotes;
      i++;
      continue;
    }

    // Skip escapes. Escaped physical line endings are lexically removed, so
    // consume a complete LF or CRLF continuation rather than exposing its
    // trailing LF as source syntax on the next iteration.
    if (c == '\\' && i + 1 < len) {
      size_t continued = shell_source_skip_escaped_line_endings(p, len, i);
      i = (uint32_t)(continued != i ? continued : i + 2);
      continue;
    }

    if (c == '$' && shell_source_logical_next_is(p, len, i, '{', NULL)) {
      size_t after = 0;
      if (shell_source_skip_parameter_expansion(p, len, i, &after)) {
        detect_parameter_features(p, i, after, in_double_quotes, features);
        size_t subscript_start = 0, subscript_after = 0;
        if (shell_source_find_parameter_array_subscript(
                p, len, i, &subscript_after, &subscript_start))
          *features |= SHELL_FEAT_ARRAY;
        i = (uint32_t)after;
        continue;
      }
    }

    // Arithmetic expansions are opaque source units. Recurse into their
    // physical content range so a continuation inside either opener cannot
    // turn the following `(` into an ordinary command group.
    if (c == '$' && shell_source_dollar_arithmetic_open(p, len, i, NULL)) {
      *features |= SHELL_FEAT_ARITH;
      size_t content_start = 0, content_length = 0, arithmetic_after = 0;
      if (shell_source_arithmetic_content(p, len, i, &content_start,
                                          &content_length, &arithmetic_after)) {
        bool has_array = shell_tokenizer_arithmetic_has_array_semantics(
            p + content_start, content_length);
        if (has_array)
          *features |= SHELL_FEAT_ARRAY;
        size_t first = content_start;
        size_t content_end = content_start + content_length;
        while (first < content_end) {
          size_t continued =
              shell_source_skip_escaped_line_endings(p, content_end, first);
          if (continued != first) {
            first = continued;
            continue;
          }
          if (!isspace((unsigned char)p[first]))
            break;
          first++;
        }
        if (!has_array && first < content_end &&
            (isalpha((unsigned char)p[first]) || p[first] == '_'))
          *features |= SHELL_FEAT_VARS;
        if (content_length != 0)
          detect_arithmetic_features(p, content_start,
                                     content_start + content_length, features);
        i = (uint32_t)arithmetic_after;
        continue;
      }
      /* Leave malformed arithmetic to the structural parser. */
      i++;
      continue;
    }
    if (in_double_quotes && (c == '$' || c == '`')) {
      bool recognized = false;
      size_t after = 0;
      if (shell_source_skip_double_quote_expansion(p, len, i, &recognized,
                                                   &after) &&
          recognized) {
        size_t content_start = i + 1;
        if (c == '`') {
          *features |= SHELL_FEAT_SUBSHELL;
        } else if (shell_source_logical_next_is(p, len, i, '{', NULL)) {
          *features |= SHELL_FEAT_VARS;
          /* Revisit the parameter as its own unquoted syntactic scope. This
           * preserves array-subscript detection as well as nested features,
           * without letting its quotes alter the enclosing quote state. */
          detect_features(p, i, (uint32_t)(after - i), features);
          i = (uint32_t)after;
          continue;
        } else {
          *features |= SHELL_FEAT_SUBSHELL;
          content_start = shell_source_logical_following(p, len, i) + 1;
        }
        if (after > content_start + 1)
          detect_features(p, (uint32_t)content_start,
                          (uint32_t)(after - content_start - 1), features);
        i = (uint32_t)after;
        continue;
      }
    }
    // Grammar-only syntax is literal inside double quotes. Parameter, command,
    // and arithmetic expansions below intentionally remain visible there.
    if (!in_double_quotes && shell_identifier_start(c)) {
      size_t after = 0, subscript_start = 0, subscript_after = 0;
      size_t value_start = 0, value_after = 0;
      if (skip_array_assignment(p, len, i, &after, &subscript_start,
                                &subscript_after, &value_start, &value_after) &&
          have_array_context && fast_array_assignment_at(&array_context, i)) {
        *features |= SHELL_FEAT_ARRAY;
        if (subscript_after > subscript_start + 1)
          detect_features(p, (uint32_t)subscript_start + 1,
                          (uint32_t)(subscript_after - subscript_start - 2),
                          features);
        if (value_after > value_start)
          detect_features(p, (uint32_t)value_start,
                          (uint32_t)(value_after - value_start), features);
        i = (uint32_t)after;
        continue;
      }
    }
    size_t combined_redirect = 0;
    if (!in_double_quotes && c == '&' &&
        shell_source_logical_next_is(p, len, i, '>', &combined_redirect)) {
      *features |= SHELL_FEAT_COMBINED_REDIRECT;
      size_t after = combined_redirect + 1;
      size_t append = 0;
      if (shell_source_logical_next_is(p, len, combined_redirect, '>', &append))
        after = append + 1;
      i = (uint32_t)after;
      continue;
    }
    if (!in_double_quotes && c == '$' &&
        shell_source_logical_next_is(p, len, i, '\'', NULL)) {
      *features |= SHELL_FEAT_ANSI_C_QUOTE;
      size_t after = 0;
      if (shell_source_skip_complete_ansi_c_quote(p, len, i, &after)) {
        i = (uint32_t)after;
        continue;
      }
    }
    if (!in_double_quotes &&
        (c == '?' || c == '*' || c == '+' || c == '@' || c == '!')) {
      size_t extglob_after = 0;
      if (shell_source_skip_extglob(p, len, i, &extglob_after)) {
        *features |= SHELL_FEAT_EXTGLOB;
        i = (uint32_t)extglob_after;
        continue;
      }
    }
    if (!in_double_quotes && c == '{') {
      size_t operator_position = 0;
      if (shell_source_parse_named_fd_redirect(p, i, len, &operator_position))
        *features |= SHELL_FEAT_NAMED_FD;
    }
    size_t process_open = 0;
    if (!in_double_quotes && (c == '<' || c == '>') &&
        shell_source_process_substitution_open(p, len, i, &process_open)) {
      *features |= SHELL_FEAT_PROCESS_SUB;
      size_t after = 0;
      if (shell_source_find_balanced_parentheses(p, len, process_open,
                                                 &after)) {
        if (after > process_open + 1)
          detect_features(p, (uint32_t)process_open + 1,
                          (uint32_t)(after - process_open - 2), features);
        i = (uint32_t)after;
        continue;
      }
      continue;
    }
    bool arithmetic_paren =
        i > 1 && p[i - 1] == '(' && (p[i - 2] == '$' || p[i - 2] == '(');
    if (!in_double_quotes && c == '(' && !arithmetic_paren &&
        !(i > 0 && (p[i - 1] == '$' || p[i - 1] == '<' || p[i - 1] == '>')))
      *features |= SHELL_FEAT_GROUP;
    switch (c) {
    case '$':
      // Variables expand in double quotes
      {
        size_t next_position = shell_source_logical_following(p, len, i);
        if (next_position < len) {
          char next = p[next_position];
          if (next == '(') {
            if (shell_source_dollar_arithmetic_open(p, len, i, NULL)) {
              // This is handled by the arithmetic-expansion branch above.
              continue;
            }
            *features |= SHELL_FEAT_SUBSHELL;
            size_t after = 0;
            if (shell_source_find_balanced_parentheses(p, len, next_position,
                                                       &after)) {
              if (after > next_position + 1)
                detect_features(p, (uint32_t)next_position + 1,
                                (uint32_t)(after - next_position - 2),
                                features);
              i = (uint32_t)after;
              continue;
            }
          } else if (next == '`') {
            *features |= SHELL_FEAT_SUBSHELL;
          } else if (next == '{') {
            *features |= SHELL_FEAT_VARS;
            size_t after = 0, subscript_start = 0;
            if (shell_source_find_parameter_array_subscript(p, len, i, &after,
                                                            &subscript_start)) {
              *features |= SHELL_FEAT_ARRAY;
              if (after > subscript_start + 1)
                detect_features(p, (uint32_t)subscript_start + 1,
                                (uint32_t)(after - subscript_start - 2),
                                features);
              i = (uint32_t)after;
              continue;
            }
          } else if (isdigit((unsigned char)next) || next == '#' ||
                     next == '?' || next == '$' || next == '!' || next == '@' ||
                     next == '*' || next == '-') {
            *features |= SHELL_FEAT_VARS;
          } else if (isalpha((unsigned char)next) || next == '_') {
            *features |= SHELL_FEAT_VARS;
          }
        }
      }
      break;
    case '`':
      *features |= SHELL_FEAT_SUBSHELL;
      break;
    case '&':
      if (!in_double_quotes && !(i + 1 < len && p[i + 1] == '&') &&
          !(i > 0 && (p[i - 1] == '<' || p[i - 1] == '>')))
        *features |= SHELL_FEAT_BACKGROUND;
      break;
    case '*':
    case '?':
      // Globs do NOT expand in double quotes
      if (!in_double_quotes) {
        *features |= SHELL_FEAT_GLOBS;
      }
      break;
    case '[':
      // Globs do NOT expand in double quotes, and not in heredoc context
      if (!in_double_quotes && !(i > 0 && p[i - 1] == '<')) {
        *features |= SHELL_FEAT_GLOBS;
      }
      break;
    default:
      break;
    }

    i++;
  }
  nesting--;
}

/* Match an unquoted reserved spelling after lexical line-continuation removal.
 * Ordinary backslash escapes and quotes deliberately fail: `wh\\ile` is a
 * command word, while `whi\\\nle` is the reserved `while` word. */
static bool detect_logical_unquoted_word_is(const char *text, size_t start,
                                            size_t end, const char *word) {
  if (!text || !word || start > end)
    return false;
  size_t matched = 0;
  size_t word_length = strlen(word);
  for (size_t position = start; position < end;) {
    size_t continued =
        shell_source_skip_escaped_line_endings(text, end, position);
    if (continued != position) {
      position = continued;
      continue;
    }
    char c = text[position++];
    if (c == '\\' || c == '\'' || c == '"' || c == '`' ||
        matched == word_length || c != word[matched])
      return false;
    matched++;
  }
  return matched == word_length;
}

/* Detect control-flow and file-substitution features in one subcommand.
 * This is intentionally lexical: the fast parser reports feature presence,
 * while the full parser remains responsible for detailed shell structure. */
static void detect_control_features(const char *cmd, uint32_t start,
                                    uint32_t len, uint32_t *features) {
  const char *p = cmd + start;
  uint32_t word_start = UINT32_MAX;
  bool in_single = false;
  bool in_double = false;

  for (uint32_t i = 0; i <= len; i++) {
    char c = i < len ? p[i] : ' ';
    if (in_single) {
      if (c == '\'')
        in_single = false;
      continue;
    }
    if (in_double) {
      if (c == '"')
        in_double = false;
      else if (c == '\\' && i + 1 < len)
        i++;
      continue;
    }
    if (c == '\'') {
      in_single = true;
      if (word_start != UINT32_MAX) {
        word_start = UINT32_MAX;
      }
      continue;
    }
    if (c == '"') {
      in_double = true;
      if (word_start != UINT32_MAX)
        word_start = UINT32_MAX;
      continue;
    }
    if (c == '\\' && i + 1 < len) {
      if (word_start == UINT32_MAX)
        word_start = i;
      size_t continued = shell_source_skip_escaped_line_endings(p, len, i);
      i = (uint32_t)(continued != i ? continued - 1 : i + 1);
      continue;
    }

    if (isalnum((unsigned char)c) || c == '_') {
      if (word_start == UINT32_MAX)
        word_start = i;
      continue;
    }

    if (word_start != UINT32_MAX) {
      if (detect_logical_unquoted_word_is(p, word_start, i, "while") ||
          detect_logical_unquoted_word_is(p, word_start, i, "until") ||
          detect_logical_unquoted_word_is(p, word_start, i, "for") ||
          detect_logical_unquoted_word_is(p, word_start, i, "select"))
        *features |= SHELL_FEAT_LOOPS;
      if (detect_logical_unquoted_word_is(p, word_start, i, "if") ||
          detect_logical_unquoted_word_is(p, word_start, i, "then") ||
          detect_logical_unquoted_word_is(p, word_start, i, "elif") ||
          detect_logical_unquoted_word_is(p, word_start, i, "else") ||
          detect_logical_unquoted_word_is(p, word_start, i, "fi"))
        *features |= SHELL_FEAT_CONDITIONALS;
      if (detect_logical_unquoted_word_is(p, word_start, i, "case") ||
          detect_logical_unquoted_word_is(p, word_start, i, "in") ||
          detect_logical_unquoted_word_is(p, word_start, i, "esac"))
        *features |= SHELL_FEAT_CASE;
      word_start = UINT32_MAX;
    }

    size_t command_open = 0;
    if (c == '$' &&
        shell_source_dollar_parentheses_open(p, len, i, &command_open) &&
        !shell_source_dollar_arithmetic_open(p, len, i, NULL)) {
      uint32_t j = (uint32_t)shell_source_skip_escaped_line_endings(
          p, len, command_open + 1);
      while (j < len && isspace((unsigned char)p[j]))
        j++;
      if (j < len && p[j] == '<')
        *features |= SHELL_FEAT_SUBSHELL_FILE;
    }
  }
}

static void detect_all_features(const char *cmd, uint32_t start, uint32_t len,
                                uint32_t *features) {
  detect_features(cmd, start, len, features);
  detect_control_features(cmd, start, len, features);
}

/* Complete metadata that depends on the full set of recorded ranges. This is
 * also used on truncation so retained ranges have the same metadata as they
 * would in an otherwise identical complete parse. */
static void normalize_result_metadata(shell_parse_result_t *result) {
  for (uint32_t i = 0; i < result->count; i++) {
    if (result->cmds[i].type == SHELL_TYPE_SIMPLE &&
        (result->cmds[i].features & SHELL_FEAT_SUBSHELL)) {
      result->cmds[i].type = SHELL_TYPE_SUBSTITUTION;
    }
  }

  for (uint32_t i = 0; i < result->count; i++) {
    if (result->cmds[i].group_depth > 0)
      result->cmds[i].features |= SHELL_FEAT_GROUP;
    if (result->cmds[i].type == SHELL_TYPE_PIPELINE) {
      if (result->cmds[i].pipe_input_mode == SHELL_PIPE_MODE_NONE)
        result->cmds[i].pipe_input_mode = SHELL_PIPE_MODE_STDOUT;
      result->cmds[i].features |= SHELL_FEAT_PIPELINE;
      if (i > 0)
        result->cmds[i - 1].features |= SHELL_FEAT_PIPELINE;
    }
    if (result->cmds[i].type == SHELL_TYPE_BACKGROUND && i > 0)
      result->cmds[i - 1].features |= SHELL_FEAT_BACKGROUND;
  }
}

/* Scan the leading negators for one pipeline stage. A bare `!` must be
 * followed on the same logical line by the next modifier or stage: unlike a
 * binary list connector, an unescaped newline or comment cannot bridge it.
 * Return zero for non-negated ranges and malformed/incomplete prefixes. */
static uint32_t range_pipeline_negation_prefix(const char *cmd, uint32_t start,
                                               uint32_t end,
                                               uint32_t *stage_start) {
  if (stage_start)
    *stage_start = start;
  while (start < end && isspace((unsigned char)cmd[start]))
    start++;
  uint32_t count = 0;
  for (;;) {
    if (start == end || cmd[start] != '!')
      break;
    uint32_t after = start + 1;
    if (after == end || !isspace((unsigned char)cmd[after]))
      break;
    after = (uint32_t)shell_source_skip_pipeline_negator_gap(cmd, end, after);
    if (after < end &&
        (cmd[after] == '\n' || cmd[after] == '\r' ||
         (cmd[after] == '#' && shell_source_comment_starts(cmd, end, after))))
      return 0;
    if (count == UINT32_MAX)
      return 0;
    count++;
    /* A group opener is outside this bounded prefix while the range parser is
     * deciding whether `{` or `(` starts a compound pipeline stage. Preserve
     * the completed modifier sequence for that caller; normalization below
     * rejects the same empty stage when it is an actual complete range. */
    if (after == end) {
      if (stage_start)
        *stage_start = after;
      return count;
    }
    /* A following `!` is another modifier only when it too is delimited.
     * `! !literal` therefore executes the command named `!literal` under one
     * negation, as Bash does. */
    if (cmd[after] != '!' || after + 1 == end ||
        !isspace((unsigned char)cmd[after + 1])) {
      if (stage_start)
        *stage_start = after;
      return count;
    }
    start = after;
  }
  return 0;
}

/* A reserved `!` before a compound group belongs to the surrounding pipeline,
 * not to the group's first inner command. */
static bool range_is_pipeline_negator_prefix(const char *cmd, uint32_t start,
                                             uint32_t end) {
  uint32_t stage = start;
  return range_pipeline_negation_prefix(cmd, start, end, &stage) != 0 &&
         stage == end;
}

/* `!` is a reserved pipeline modifier, not an executable command word. The
 * range tokenizer keeps it inside the first range so it never becomes a
 * generic separator; remove that prefix here and attach one explicit modifier
 * to every range in the syntactic pipeline. */
static bool normalize_pipeline_negation(const char *cmd,
                                        shell_parse_result_t *result) {
  /* Redirect-only stages have no word range from which to strip `!`.  The
   * marker records the modifier directly; propagate it through its pipeline
   * just as a word-bearing first stage would. */
  for (uint32_t i = 0; i < result->count; i++) {
    shell_range_t *first = &result->cmds[i];
    if ((first->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) == 0)
      continue;
    if (first->pipeline_negation_count == 0)
      return false;
    if (i != 0 && first->type == SHELL_TYPE_PIPELINE)
      continue;
    for (uint32_t member = i + 1; member < result->count; member++) {
      if (result->cmds[member].type != SHELL_TYPE_PIPELINE)
        break;
      result->cmds[member].modifiers |= SHELL_CMD_MOD_PIPE_NEGATED;
      result->cmds[member].pipeline_negation_count =
          first->pipeline_negation_count;
    }
  }
  for (uint32_t i = 0; i < result->count; i++) {
    shell_range_t *first = &result->cmds[i];
    uint32_t offset = 0;
    while (offset < first->len &&
           isspace((unsigned char)cmd[first->start + offset]))
      offset++;
    if (offset >= first->len || cmd[first->start + offset] != '!')
      continue;
    /* A pipeline negator begins a pipeline, not a later stage. `cmd | ! x`
     * is invalid shell syntax; after &&/||/;/& the new range begins a new
     * pipeline and is valid. */
    if (i != 0 && first->type == SHELL_TYPE_PIPELINE)
      return false;
    uint32_t range_end = first->start + first->len;
    uint32_t stage_start = first->start + offset;
    uint32_t negation_count = range_pipeline_negation_prefix(
        cmd, first->start + offset, range_end, &stage_start);
    if (negation_count == 0) {
      /* `!literal` is an ordinary command word, while a delimited but
       * incomplete negator is malformed source. */
      if (first->start + offset + 1 == range_end ||
          isspace((unsigned char)cmd[first->start + offset + 1]))
        return false;
      continue;
    }
    if (stage_start == range_end)
      return false;
    first->len = range_end - stage_start;
    first->start = stage_start;
    first->modifiers |= SHELL_CMD_MOD_PIPE_NEGATED;
    first->pipeline_negation_count = negation_count;
    for (uint32_t member = i + 1; member < result->count; member++) {
      if (result->cmds[member].type != SHELL_TYPE_PIPELINE)
        break;
      result->cmds[member].modifiers |= SHELL_CMD_MOD_PIPE_NEGATED;
      result->cmds[member].pipeline_negation_count = negation_count;
    }
  }

  /* A group opener removes its delimiter and prefix from the inner command
   * range, so `! { list; } | cmd` has no range beginning with `!`. Retain the
   * modifier on the GROUP descriptor and apply it to later pipe stages. */
  for (uint32_t group_index = 0; group_index < result->group_count;
       group_index++) {
    shell_group_t *group = &result->groups[group_index];
    if ((group->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) == 0)
      continue;
    if (group->pipeline_negation_count == 0)
      group->pipeline_negation_count = 1;
    for (uint32_t member = 0; member < result->count; member++) {
      shell_range_t *range = &result->cmds[member];
      if (range->start < group->end)
        continue;
      if (range->type != SHELL_TYPE_PIPELINE)
        break;
      range->modifiers |= SHELL_CMD_MOD_PIPE_NEGATED;
      range->pipeline_negation_count = group->pipeline_negation_count;
    }
  }
  return true;
}

static bool input_bytes_are_supported(const char *cmd, size_t cmd_len) {
  for (size_t i = 0; i < cmd_len; i++) {
    unsigned char byte = (unsigned char)cmd[i];
    if ((byte < 0x20 && !isspace(byte)) || byte == 0x7f || byte >= 0x80)
      return false;
  }
  return true;
}

/* Comment scanning records the first comment that belongs to the current
 * candidate subcommand. A comment may begin at that range's first byte (for
 * example after a newline or semicolon), in which case it contributes no
 * executable range. Keep every emission path on the same boundary rule so
 * feature detection never sees comment text as shell syntax. */
static uint32_t range_end_before_comment(uint32_t start, uint32_t end,
                                         uint32_t comment_start) {
  return comment_start != UINT32_MAX && comment_start >= start &&
                 comment_start < end
             ? comment_start
             : end;
}

/* A comment-only source is syntactically valid yet has no executable range.
 * This predicate is deliberately lexical: it accepts only whitespace and
 * comments that begin at a shell word boundary. */
static bool source_is_comment_only(const char *cmd, size_t cmd_len) {
  bool saw_comment = false;
  for (size_t pos = 0; pos < cmd_len;) {
    if (isspace((unsigned char)cmd[pos])) {
      pos++;
      continue;
    }
    if (cmd[pos] != '#' || !shell_source_comment_starts(cmd, cmd_len, pos))
      return false;
    saw_comment = true;
    while (pos < cmd_len && cmd[pos] != '\n' && cmd[pos] != '\r')
      pos++;
  }
  return saw_comment;
}

/**
 * Fast shell command parser - zero-copy, bounded
 */
shell_error_t shell_parse_fast(const char *cmd, size_t cmd_len,
                               const shell_limits_t *limits,
                               shell_parse_result_t *result) {
  // Validate inputs
  if (!cmd || !result) {
    return SHELL_EINPUT;
  }

  /* Ranges store byte offsets in uint32_t, so larger inputs are not
   * representable by this API.  Reject before any traversal can narrow a
   * position or range length. */
  if (cmd_len > UINT32_MAX) {
    result->count = 0;
    result->status = SHELL_STATUS_ERROR;
    return SHELL_EINPUT;
  }

  if (cmd_len == 0) {
    result->count = 0;
    result->status = SHELL_STATUS_ERROR;
    return SHELL_EINPUT;
  }

  // Use default limits if not provided
  shell_limits_t local_limits;
  if (!limits) {
    local_limits = SHELL_LIMITS_DEFAULT;
    limits = &local_limits;
  }

  // Initialize result
  memset(result, 0, sizeof(shell_parse_result_t));

  /* Reject bytes outside the supported shell-text domain before any syntax
   * path can skip or reinterpret them. */
  if (!input_bytes_are_supported(cmd, cmd_len)) {
    result->status = SHELL_STATUS_ERROR;
    return SHELL_EPARSE;
  }
  if (!shell_tokenizer_list_syntax_valid(cmd, cmd_len)) {
    result->status = SHELL_STATUS_ERROR;
    return SHELL_EPARSE;
  }

  /* The fast parser preserves lexical ranges for control compounds so the
   * higher-level semantic boundary can report them as unsupported syntax.
   * In particular, a `case` pattern closes with `)`, which is not a subshell
   * delimiter. Do not mistake that token for an unmatched parenthesized
   * group while scanning a source that the control classifier already owns. */
  bool has_unsupported_control =
      shell_tokenizer_has_unsupported_control(cmd, cmd_len);

  uint32_t max_cmds = limits->max_subcommands;
  if (max_cmds > SHELL_MAX_SUBCOMMANDS) {
    max_cmds = SHELL_MAX_SUBCOMMANDS;
  }

  heredoc_body_span_t heredoc_bodies[SHELL_MAX_SUBCOMMANDS];
  uint32_t heredoc_body_count = 0;
  if (!collect_heredoc_body_spans(cmd, (uint32_t)cmd_len, heredoc_bodies,
                                  SHELL_MAX_SUBCOMMANDS, &heredoc_body_count))
    heredoc_body_count = 0;
  uint32_t next_heredoc_body = 0;

  // Helper to trim outer whitespace and emit one parsed subcommand record.
#define RECORD_SUBCMD(s, e, type_val)                                          \
  do {                                                                         \
    uint32_t _s = (s);                                                         \
    uint32_t _e = range_end_before_comment(_s, (e), comment_start);            \
    while (_s < _e && isspace((unsigned char)cmd[_s]))                         \
      _s++;                                                                    \
    while (_e > _s && isspace((unsigned char)cmd[_e - 1]))                     \
      _e--;                                                                    \
    if (_s < _e && subcmd_idx < max_cmds) {                                    \
      result->cmds[subcmd_idx].start = _s;                                     \
      result->cmds[subcmd_idx].len = _e - _s;                                  \
      result->cmds[subcmd_idx].type = (type_val);                              \
      result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;      \
      result->cmds[subcmd_idx].features = 0;                                   \
      result->cmds[subcmd_idx].group_depth = group_depth;                      \
      result->cmds[subcmd_idx].group_kinds = group_kinds;                      \
      detect_all_features(cmd, _s, _e - _s,                                    \
                          &result->cmds[subcmd_idx].features);                 \
      subcmd_idx++;                                                            \
    } else if (subcmd_idx >= max_cmds) {                                       \
      result->status = SHELL_STATUS_TRUNCATED;                                 \
      result->count = subcmd_idx;                                              \
      goto truncated;                                                          \
    }                                                                          \
  } while (0)

#define OPEN_GROUP(kind_val, start_val, modifiers_val, negation_count_val)     \
  do {                                                                         \
    if (result->group_count >= SHELL_MAX_GROUPS ||                             \
        group_descriptor_depth >= SHELL_MAX_GROUPS) {                          \
      result->status = SHELL_STATUS_TRUNCATED;                                 \
      result->count = subcmd_idx;                                              \
      goto truncated;                                                          \
    }                                                                          \
    shell_group_t *_group = &result->groups[result->group_count];              \
    _group->start = (start_val);                                               \
    _group->end = 0;                                                           \
    _group->first_command = (uint16_t)subcmd_idx;                              \
    _group->command_count = 0;                                                 \
    _group->parent = group_descriptor_depth                                    \
                         ? group_descriptor_stack[group_descriptor_depth - 1]  \
                         : UINT16_MAX;                                         \
    _group->kind = (kind_val);                                                 \
    _group->modifiers = (modifiers_val);                                       \
    _group->pipeline_negation_count = (negation_count_val);                    \
    group_descriptor_stack[group_descriptor_depth++] =                         \
        (uint16_t)result->group_count++;                                       \
  } while (0)

#define CLOSE_GROUP(kind_val, end_val)                                         \
  do {                                                                         \
    if (group_descriptor_depth == 0 ||                                         \
        result->groups[group_descriptor_stack[group_descriptor_depth - 1]]     \
                .kind != (kind_val)) {                                         \
      result->status = SHELL_STATUS_ERROR;                                     \
      result->count = subcmd_idx;                                              \
      return SHELL_EPARSE;                                                     \
    }                                                                          \
    shell_group_t *_group =                                                    \
        &result->groups[group_descriptor_stack[--group_descriptor_depth]];     \
    _group->end = (end_val);                                                   \
    _group->command_count = (uint16_t)(subcmd_idx - _group->first_command);    \
  } while (0)

  uint32_t pos = 0;
  uint32_t subcmd_start = 0;
  uint32_t subcmd_idx = 0;
  uint16_t current_type = SHELL_TYPE_SIMPLE;
  uint8_t current_pipe_input_mode = SHELL_PIPE_MODE_NONE;
  uint16_t group_depth = 0;
  uint8_t group_kinds = SHELL_GROUP_NONE;
  uint16_t brace_group_depth = 0;
  uint8_t brace_group_stack[SHELL_MAX_SUBCOMMANDS];
  uint16_t brace_group_stack_depth = 0;
  uint16_t group_descriptor_stack[SHELL_MAX_GROUPS];
  uint16_t group_descriptor_depth = 0;
  uint32_t comment_start = UINT32_MAX;
  bool in_quotes = false;
  char quote_char = 0;
  int brace_depth = 0;
  int brace_start_pos = -1;
  uint32_t last_closed_group_end = UINT32_MAX;
  uint32_t function_paren_close = UINT32_MAX;
  uint32_t heredoc_prefix_start = UINT32_MAX;
  int paren_depth = 0;              // Track all non-arithmetic parentheses
  int group_paren_depth = 0;        // Track ordinary parenthesized groups
  int substitution_paren_depth = 0; // $(), <(), and >() delimiters
  int arith_depth = 0;              // Track when inside $((...))

  // Scan the command one byte at a time, maintaining quote and feature state.
  while (pos < cmd_len) {
    while (next_heredoc_body < heredoc_body_count &&
           pos >= heredoc_bodies[next_heredoc_body].end)
      next_heredoc_body++;
    if (next_heredoc_body < heredoc_body_count &&
        pos >= heredoc_bodies[next_heredoc_body].start) {
      pos = heredoc_bodies[next_heredoc_body].end;
      subcmd_start = pos;
      comment_start = UINT32_MAX;
      continue;
    }
    char c = cmd[pos];
    /* A nested expansion owns its quotes even inside an outer double-quoted
     * word. Consume its whole span before the outer quote state sees any
     * delimiter or command-list operator from its body. */
    if (in_quotes && quote_char == '"' && (c == '$' || c == '`')) {
      size_t after = 0;
      bool recognized = false;
      bool complete = shell_source_skip_double_quote_expansion(
          cmd, cmd_len, pos, &recognized, &after);
      if (recognized) {
        if ((!complete && (c != '`' || limits->strict_mode)) ||
            (complete && after > UINT32_MAX)) {
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        pos = complete ? (uint32_t)after : cmd_len;
        continue;
      }
    }
    /* ANSI-C quoting is one shell-word fragment, even when its body contains
     * escaped quotes or delimiter-looking bytes. Consume it before generic
     * quote and delimiter handling so it remains opaque to this structural
     * parser. */
    if (!in_quotes && c == '$' &&
        shell_source_logical_next_is(cmd, cmd_len, pos, '\'', NULL)) {
      size_t after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(cmd, cmd_len, pos, &after) ||
          after > UINT32_MAX) {
        if (limits->strict_mode) {
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
      } else {
        pos = (uint32_t)after;
        continue;
      }
    }
    /* A balanced parameter expansion is one shell-word fragment. Its default,
     * pattern, or replacement word may contain bytes that are operators at
     * the enclosing command-list level. */
    if (!in_quotes && c == '$') {
      size_t next =
          shell_source_skip_escaped_line_endings(cmd, cmd_len, pos + 1);
      if (next < cmd_len && cmd[next] == '{') {
        size_t after = 0;
        if (!shell_source_skip_parameter_expansion(cmd, cmd_len, pos, &after) ||
            after > UINT32_MAX) {
          /* A braced parameter expansion is syntactically complete or it is
           * invalid source; permissive range recovery must not turn `${}` or an
           * unterminated expansion into an unrelated ordinary brace word. */
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        pos = (uint32_t)after;
        continue;
      }
    }
    /* Command substitutions are one shell-word component at this layer. The
     * shared scanner owns their matching parentheses and deferred heredoc
     * bodies, so syntax in the nested command cannot split the outer range.
     * Arithmetic expansion remains on its dedicated depth-tracking path. */
    size_t substitution_open = 0;
    if (!in_quotes && c == '$' &&
        shell_source_dollar_parentheses_open(cmd, cmd_len, pos,
                                             &substitution_open) &&
        !shell_source_dollar_arithmetic_open(cmd, cmd_len, pos, NULL)) {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(cmd, cmd_len,
                                                  substitution_open, &after) ||
          after > UINT32_MAX) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      pos = (uint32_t)after;
      continue;
    }
    /* Process substitutions have the same balanced command-list body as
     * `$()`, but their leading redirection byte can be separated from `(` by
     * an escaped physical line ending. Consume the whole source fragment here
     * rather than relying on the immediately preceding physical byte when the
     * opening parenthesis is reached. */
    if (!in_quotes && (c == '<' || c == '>') &&
        shell_source_process_substitution_open(cmd, cmd_len, pos,
                                               &substitution_open)) {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(cmd, cmd_len,
                                                  substitution_open, &after) ||
          after > UINT32_MAX) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      /* Retain the fast parser's historical eager attribution: once a list
       * connector has closed a preceding range, its following process
       * substitution is recorded on that emitted range. The final range is
       * still classified as a substitution below when it starts a command. */
      if (subcmd_idx > 0 && subcmd_idx < max_cmds)
        result->cmds[subcmd_idx - 1].features |= SHELL_FEAT_PROCESS_SUB;
      if (current_type == SHELL_TYPE_SIMPLE)
        current_type = SHELL_TYPE_SUBSTITUTION;
      pos = (uint32_t)after;
      continue;
    }
    /* This parser's established lexical dialect treats `\$(...)` as an
     * escaped literal word component. Keep the complete parenthesized suffix
     * opaque so strict group validation cannot reinterpret it as a subshell
     * command. */
    if (!in_quotes && c == '\\' && pos + 2 < cmd_len && cmd[pos + 1] == '$' &&
        cmd[pos + 2] == '(') {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(cmd, cmd_len, pos + 2,
                                                  &after) ||
          after > UINT32_MAX) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      pos = (uint32_t)after;
      continue;
    }
    if (!in_quotes && arith_depth == 0 && substitution_paren_depth == 0) {
      size_t after = 0;
      if (shell_source_skip_extglob(cmd, cmd_len, pos, &after) &&
          after <= UINT32_MAX) {
        pos = (uint32_t)after;
        continue;
      }
    }
    bool function_paren = c == '(' && pos + 1 < cmd_len &&
                          cmd[pos + 1] == ')' && pos > subcmd_start &&
                          pos > 0 && !isspace((unsigned char)cmd[pos - 1]) &&
                          !is_separator(cmd[pos - 1]);
    bool closes_group = c == ')' && arith_depth == 0 &&
                        substitution_paren_depth == 0 && group_paren_depth > 0;
    bool closes_arithmetic = c == ')' && arith_depth > 0;
    bool closes_function_paren = c == ')' && pos == function_paren_close;
    bool inside_parameter_expansion = brace_depth > 0;

    /* POSIX brace groups use reserved words, not ordinary argv words. The
     * delimiters must be separated from their list by shell whitespace or an
     * operator. Parameter expansion braces remain handled below. */
    bool brace_open =
        c == '{' &&
        (pos == 0 || isspace((unsigned char)cmd[pos - 1]) ||
         is_separator(cmd[pos - 1])) &&
        pos + 1 < cmd_len &&
        (isspace((unsigned char)cmd[pos + 1]) || cmd[pos + 1] == '(');
    bool brace_close_redirect = false;
    if (c == '}' && pos + 1 < cmd_len && isdigit((unsigned char)cmd[pos + 1])) {
      size_t redirect = 0;
      uint32_t descriptor = 0;
      shell_source_io_number_t io_number = shell_source_parse_io_number(
          cmd, pos + 1, cmd_len, &redirect, &descriptor);
      brace_close_redirect = io_number == SHELL_SOURCE_IO_NUMBER_VALID &&
                             redirect < cmd_len &&
                             (cmd[redirect] == '<' || cmd[redirect] == '>');
    }
    bool brace_close =
        c == '}' && brace_depth == 0 && brace_group_depth > 0 &&
        (pos == 0 || isspace((unsigned char)cmd[pos - 1]) ||
         cmd[pos - 1] == ';' || cmd[pos - 1] == '\n' || cmd[pos - 1] == '\r' ||
         cmd[pos - 1] == ')') &&
        (pos + 1 == cmd_len || isspace((unsigned char)cmd[pos + 1]) ||
         is_separator(cmd[pos + 1]) || cmd[pos + 1] == ')' ||
         brace_close_redirect);
    bool only_whitespace_before_delimiter =
        source_range_is_whitespace(cmd, subcmd_start, pos);
    bool directly_after_closed_group =
        last_closed_group_end != UINT32_MAX &&
        source_range_is_whitespace(cmd, last_closed_group_end, pos);
    bool command_boundary =
        (only_whitespace_before_delimiter ||
         range_is_pipeline_negator_prefix(cmd, subcmd_start, pos)) &&
        !directly_after_closed_group;

    bool redirect_prefix =
        redirect_list_precedes_group(cmd, subcmd_start, pos) ||
        (heredoc_prefix_start != UINT32_MAX &&
         redirect_list_precedes_group(cmd, heredoc_prefix_start, pos));
    if (!in_quotes && arith_depth == 0 && substitution_paren_depth == 0 &&
        brace_open && redirect_prefix) {
      result->status = SHELL_STATUS_ERROR;
      result->count = subcmd_idx;
      return SHELL_EPARSE;
    }
    if (!in_quotes && arith_depth == 0 && substitution_paren_depth == 0 &&
        !inside_parameter_expansion && brace_open &&
        (limits->strict_mode ? command_boundary
                             : only_whitespace_before_delimiter)) {
      if (brace_group_stack_depth == SHELL_MAX_SUBCOMMANDS) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      brace_group_stack[brace_group_stack_depth++] = SHELL_GROUP_BRACE;
      uint32_t group_stage = subcmd_start;
      uint32_t group_negation_count =
          range_pipeline_negation_prefix(cmd, subcmd_start, pos, &group_stage);
      OPEN_GROUP(SHELL_GROUP_BRACE, pos,
                 group_negation_count ? SHELL_CMD_MOD_PIPE_NEGATED : 0,
                 group_negation_count);
      brace_group_depth++;
      group_depth++;
      group_kinds |= SHELL_GROUP_BRACE;
      subcmd_start = pos + 1;
      pos++;
      continue;
    }
    if (!in_quotes && limits->strict_mode && arith_depth == 0 &&
        substitution_paren_depth == 0 && !inside_parameter_expansion &&
        command_boundary && c == '{' &&
        group_word_ends_here(cmd, pos, cmd_len)) {
      /* A standalone opening brace needs an argument-list separator after it.
       * Otherwise it is neither a group delimiter nor an ordinary word. */
      result->status = SHELL_STATUS_ERROR;
      result->count = subcmd_idx;
      return SHELL_EPARSE;
    }
    if (!in_quotes && arith_depth == 0 && substitution_paren_depth == 0 &&
        brace_close) {
      if (brace_group_stack_depth == 0 ||
          brace_group_stack[brace_group_stack_depth - 1] != SHELL_GROUP_BRACE) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      uint32_t probe = subcmd_start;
      while (probe < pos && isspace((unsigned char)cmd[probe]))
        probe++;
      if (probe != pos) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      brace_group_depth--;
      brace_group_stack_depth--;
      group_depth--;
      CLOSE_GROUP(SHELL_GROUP_BRACE, pos + 1);
      last_closed_group_end = pos + 1;
      if (brace_group_depth == 0)
        group_kinds &= (uint8_t)~SHELL_GROUP_BRACE;
      pos++;
      subcmd_start = pos;
      continue;
    }
    if (!in_quotes && limits->strict_mode && arith_depth == 0 &&
        substitution_paren_depth == 0 && !inside_parameter_expansion &&
        command_boundary && c == '}' &&
        (group_word_ends_here(cmd, pos, cmd_len) || brace_close_redirect)) {
      result->status = SHELL_STATUS_ERROR;
      result->count = subcmd_idx;
      return SHELL_EPARSE;
    }

    /* A comment starts at a word boundary and extends to the next line. It
     * is data-free shell syntax, so operators in the comment must not split
     * the command range. */
    if (!in_quotes && c == '#' &&
        shell_source_comment_starts(cmd, cmd_len, pos)) {
      if (comment_start == UINT32_MAX)
        comment_start = pos;
      while (pos < cmd_len && cmd[pos] != '\n' && cmd[pos] != '\r')
        pos++;
      continue;
    }

    /* An unquoted escaped physical line ending is removed before list
     * grammar is evaluated. In particular, it cannot become the missing
     * right-hand stage of a pipeline or AND/OR list. */
    if (!in_quotes && c == '\\' && pos + 1 < cmd_len &&
        (cmd[pos + 1] == '\n' || cmd[pos + 1] == '\r')) {
      uint32_t after = pos + 2;
      if (after < cmd_len && cmd[pos + 1] == '\r' && cmd[after] == '\n')
        after++;
      /* A group closer, a pending list operator, or a redirect list may have
       * left `subcmd_start` at source trivia. Do not emit a phantom command
       * for a continuation that shell removes before parsing the next token. */
      if (source_range_is_list_continuation_trivia(cmd, subcmd_start, after)) {
        subcmd_start = after;
        comment_start = UINT32_MAX;
      } else if (range_is_pipeline_negator_prefix(cmd, subcmd_start, after)) {
        /* Keep a pending `!` with its following stage. Normalization strips
         * the modifier after the complete range has been emitted. */
        comment_start = UINT32_MAX;
      }
      pos = after;
      continue;
    }

    // Handle quotes
    if (!in_quotes && (c == '"' || c == '\'')) {
      in_quotes = true;
      quote_char = c;
      pos++;
      continue;
    }

    // Skip content inside quotes
    if (in_quotes) {
      if (quote_char == '\'') {
        // Single quotes: no escapes, everything is literal until closing '
        if (c == '\'') {
          in_quotes = false;
          quote_char = 0;
        }
        pos++;
      } else {
        // Double quotes: handle escapes for ", \, $, `
        if (c == '\\' && pos + 1 < cmd_len) {
          pos += 2; // Skip escaped char
        } else if (c == '"') {
          in_quotes = false;
          quote_char = 0;
          pos++;
        } else {
          pos++;
        }
      }
      continue;
    }

    // Track brace depth only for ${var...}. Literal braces are ordinary word
    // bytes unless they were already recognized above as brace-group syntax;
    // treating every `{` as a parameter expansion makes strict callers reject
    // valid arguments such as `echo {`.
    if (c == '{') {
      if (brace_depth == 0 && pos > 0 && cmd[pos - 1] == '$') {
        // This is ${ - start of variable expansion, remember position
        // Content starts AFTER this brace
        brace_start_pos = pos + 1;
        brace_depth = 1;
      } else if (brace_depth > 0) {
        brace_depth++;
      }
    } else if (c == '}' && brace_depth > 0) {
      // Check for empty ${} - no variable name between braces
      if (brace_start_pos > 0 && brace_depth == 1) {
        // We're closing the ${...} - check if there's any content
        // Content starts at brace_start_pos (after ${) and ends at pos (before
        // })
        bool has_content = false;
        for (uint32_t i = (uint32_t)brace_start_pos; i < pos; i++) {
          if (!isspace((unsigned char)cmd[i])) {
            has_content = true;
            break;
          }
        }
        if (!has_content) {
          // Empty ${} - malformed
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        brace_start_pos = -1; // Reset
      }
      brace_depth--;
    }

    // Track arithmetic expansion $(( ... )) and (( ... ))
    // Note: $(( opens TWO parens - handle specially to avoid double counting
    if (c == '$' &&
        shell_source_dollar_arithmetic_open(cmd, cmd_len, pos, NULL)) {
      size_t after = 0;
      if (!shell_source_skip_arithmetic_expansion(cmd, cmd_len, pos, &after) ||
          after > UINT32_MAX) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      pos = (uint32_t)after;
      continue;
    }
    // Also handle plain (( )) - arithmetic in bash. Physical continuations
    // are removed before syntax recognition, so use the same logical
    // punctuation matcher as the full lexer.
    size_t arithmetic_command_after = 0;
    if (c == '(' && shell_source_match_logical_punctuation(
                        cmd, cmd_len, pos, "((", &arithmetic_command_after)) {
      /* `(( ... ))` is a shell arithmetic command only at a command
       * boundary. In argument position it is invalid shell syntax, not a
       * simple command containing literal parentheses. */
      if (limits->strict_mode && arith_depth == 0 &&
          !inside_parameter_expansion && !command_boundary) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      // This is ((...)) - arithmetic
      arith_depth += 2;
      pos = (uint32_t)arithmetic_command_after; // Skip logical ((
      continue;
    }
    /* Arithmetic parentheses can nest ordinary grouping parentheses as well
     * as nested `$((...))` forms. Track those opens so their matching close
     * cannot be mistaken for the end of the surrounding expansion. */
    if (c == '(' && arith_depth > 0) {
      arith_depth++;
      pos++;
      continue;
    }
    if (c == ')' && arith_depth > 0) {
      arith_depth--;
    }

    // Track regular parentheses () for subshell detection
    // But not inside arithmetic $(( )) or process substitution <( )
    // Only track when NOT inside arithmetic expansion
    if (arith_depth == 0) {
      if (c == '(' && !function_paren) {
        /* Extglob alternatives and array values are words, not command
         * groups. Their interior may contain spaces, pipes, or parentheses,
         * all of which are opaque to the command-list parser. */
        if (pos > 0 && (cmd[pos - 1] == '=' || cmd[pos - 1] == '?' ||
                        cmd[pos - 1] == '*' || cmd[pos - 1] == '+' ||
                        cmd[pos - 1] == '@' || cmd[pos - 1] == '!')) {
          size_t after = 0;
          if (!shell_source_find_balanced_parentheses(cmd, cmd_len, pos,
                                                      &after) ||
              after > UINT32_MAX) {
            if (limits->strict_mode) {
              result->status = SHELL_STATUS_ERROR;
              result->count = subcmd_idx;
              return SHELL_EPARSE;
            }
          } else {
            pos = (uint32_t)after;
            continue;
          }
        }
        /* A parenthesized group is a command, not a word expansion. `$(` and
         * `<(`/`>(` were consumed above by their dedicated scanners. */
        if (limits->strict_mode && !inside_parameter_expansion &&
            !command_boundary) {
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        paren_depth++;
        if (pos > 0 && (cmd[pos - 1] == '$' || cmd[pos - 1] == '<' ||
                        cmd[pos - 1] == '>')) {
          substitution_paren_depth++;
        } else {
          if (brace_group_depth > 0) {
            if (brace_group_stack_depth == SHELL_MAX_SUBCOMMANDS) {
              result->status = SHELL_STATUS_ERROR;
              result->count = subcmd_idx;
              return SHELL_EPARSE;
            }
            brace_group_stack[brace_group_stack_depth++] = SHELL_GROUP_SUBSHELL;
          }
          uint32_t group_stage = subcmd_start;
          uint32_t group_negation_count = range_pipeline_negation_prefix(
              cmd, subcmd_start, pos, &group_stage);
          OPEN_GROUP(SHELL_GROUP_SUBSHELL, pos,
                     group_negation_count ? SHELL_CMD_MOD_PIPE_NEGATED : 0,
                     group_negation_count);
          group_depth++, group_paren_depth++;
          group_kinds |= SHELL_GROUP_SUBSHELL;
          /* A group delimiter is syntax, not part of its first command. */
          uint32_t group_prefix = subcmd_start;
          while (group_prefix < pos &&
                 isspace((unsigned char)cmd[group_prefix]))
            group_prefix++;
          if (redirect_list_precedes_group(cmd, subcmd_start, pos) ||
              (heredoc_prefix_start != UINT32_MAX &&
               redirect_list_precedes_group(cmd, heredoc_prefix_start, pos))) {
            result->status = SHELL_STATUS_ERROR;
            result->count = subcmd_idx;
            return SHELL_EPARSE;
          }
          if (group_prefix == pos ||
              range_is_pipeline_negator_prefix(cmd, subcmd_start, pos))
            subcmd_start = pos + 1;
        }
      } else if (function_paren) {
        function_paren_close = pos + 1;
      } else if (c == ')' && paren_depth > 0) {
        paren_depth--;
        if (substitution_paren_depth > 0) {
          substitution_paren_depth--;
        } else if (group_paren_depth > 0 && !closes_group) {
          if (brace_group_depth > 0) {
            if (brace_group_stack_depth == 0 ||
                brace_group_stack[brace_group_stack_depth - 1] !=
                    SHELL_GROUP_SUBSHELL) {
              result->status = SHELL_STATUS_ERROR;
              result->count = subcmd_idx;
              return SHELL_EPARSE;
            }
            brace_group_stack_depth--;
          }
          group_paren_depth--;
          group_depth--;
          if (group_paren_depth == 0)
            group_kinds &= (uint8_t)~SHELL_GROUP_SUBSHELL;
        }
      }
    }

    if (limits->strict_mode && !inside_parameter_expansion && c == ')' &&
        !closes_arithmetic && arith_depth == 0 &&
        substitution_paren_depth == 0 && !closes_group &&
        !closes_function_paren && !has_unsupported_control) {
      result->status = SHELL_STATUS_ERROR;
      result->count = subcmd_idx;
      return SHELL_EPARSE;
    }
    if (closes_function_paren)
      function_paren_close = UINT32_MAX;

    /* A dollar not starting one of the complete expansion forms handled
     * above is a literal shell-word byte. In particular, Bash accepts `$`,
     * `$:`, and `path$` as pathnames. Do not overload brace_depth as a
     * pseudo-error channel here: `${...}`, `$'...'`, and `$(...)` already
     * have structural validation at their respective scanners. */

    /* Bash combines stdout and stderr with &>word / &>>word. It is one
     * redirect, not a background separator followed by an ordinary word. */
    size_t combined_redirect = 0;
    if (!in_quotes && c == '&' &&
        shell_source_logical_next_is(cmd, cmd_len, pos, '>',
                                     &combined_redirect)) {
      size_t operator_end = combined_redirect + 1;
      size_t append = 0;
      if (shell_source_logical_next_is(cmd, cmd_len, combined_redirect, '>',
                                       &append))
        operator_end = append + 1;
      uint32_t operand = (uint32_t)operator_end;
      while (operand < cmd_len && isspace((unsigned char)cmd[operand]))
        operand++;
      size_t after = operand;
      if (!shell_source_skip_shell_word(cmd, cmd_len, operand, &after) ||
          after == operand || after > UINT32_MAX) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      pos = (uint32_t)after;
      continue;
    }

    /* Command and backtick substitutions compose multiple processes. Keep
     * their concrete syntax in the feature mask and classify a standalone
     * subcommand with the substitution operator type. */
    if (current_type == SHELL_TYPE_SIMPLE &&
        ((c == '$' &&
          shell_source_dollar_parentheses_open(cmd, cmd_len, pos, NULL) &&
          !shell_source_dollar_arithmetic_open(cmd, cmd_len, pos, NULL)) ||
         (c == '`' && !(in_quotes && quote_char == '\'')))) {
      current_type = SHELL_TYPE_SUBSTITUTION;
    }

    /* A legacy substitution is one shell-word fragment. Operators inside it
     * belong to its nested command, never to this command list. */
    if (!in_quotes && c == '`') {
      size_t after = 0;
      if (!shell_source_skip_complete_backtick(cmd, cmd_len, pos, &after) ||
          after > UINT32_MAX) {
        if (limits->strict_mode) {
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        pos = cmd_len;
      } else {
        pos = (uint32_t)after;
      }
      continue;
    }

    // Handle escapes outside quotes
    if (c == '\\' && pos + 1 < cmd_len) {
      pos += 2;
      continue;
    }

    // Check for HERESTRING <<< (here-string) - must check before << and NOT
    // inside arithmetic
    size_t here_string_after = 0;
    if (arith_depth == 0 && c == '<' &&
        shell_source_match_logical_punctuation(cmd, cmd_len, pos, "<<<",
                                               &here_string_after)) {
      uint32_t redirect_prefix_start =
          source_redirect_prefix_start_before(cmd, pos, cmd_len);
      uint32_t negation_stage = subcmd_start;
      uint32_t negation_count = range_pipeline_negation_prefix(
          cmd, subcmd_start, pos, &negation_stage);
      bool negated_document_stage =
          negation_count != 0 && negation_stage == pos;
      bool trailing_group_redirect =
          last_closed_group_end != UINT32_MAX &&
          shell_source_skip_inline_continuations(cmd, pos,
                                                 last_closed_group_end) == pos;
      if (!trailing_group_redirect && last_closed_group_end != UINT32_MAX &&
          redirect_prefix_start > last_closed_group_end)
        trailing_group_redirect =
            shell_source_skip_inline_continuations(cmd, redirect_prefix_start,
                                                   last_closed_group_end) ==
            redirect_prefix_start;
      // End current subcommand if it has content (trim whitespace)
      if (!negated_document_stage && subcmd_idx < max_cmds &&
          subcmd_start < pos) {
        uint32_t s = subcmd_start;
        uint32_t e =
            redirect_prefix_start >= subcmd_start ? redirect_prefix_start : pos;
        while (s < e && isspace((unsigned char)cmd[s]))
          s++;
        while (e > s && isspace((unsigned char)cmd[e - 1]))
          e--;
        if (s < e) {
          result->cmds[subcmd_idx].start = s;
          result->cmds[subcmd_idx].len = e - s;
          result->cmds[subcmd_idx].type = current_type;
          result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
          result->cmds[subcmd_idx].features = 0;
          result->cmds[subcmd_idx].group_depth = group_depth;
          result->cmds[subcmd_idx].group_kinds = group_kinds;
          detect_all_features(cmd, s, e - s,
                              &result->cmds[subcmd_idx].features);
          subcmd_idx++;
        }
      }

      // Start herestring as new subcommand
      if (subcmd_idx >= max_cmds) {
        result->status = SHELL_STATUS_TRUNCATED;
        result->count = subcmd_idx;
        goto truncated;
      }

      // Record herestring subcommand: include <<< and the string
      uint32_t herestring_start = pos;
      pos = (uint32_t)here_string_after;

      pos = (uint32_t)shell_source_skip_inline_continuations(cmd, cmd_len, pos);

      // Find the complete shell word, including any quoted whitespace.
      uint32_t string_start = pos;
      pos = skip_shell_word(cmd, pos, cmd_len);
      uint32_t string_len = pos - string_start;

      if (string_len == 0) {
        // No string found - treat as less-than
        pos = herestring_start + 1;
      } else {
        if (trailing_group_redirect) {
          /* A here-string after a compound group is a redirection on that
           * group, not a synthetic executable stage. */
          subcmd_start = pos;
          current_type = SHELL_TYPE_SIMPLE;
          continue;
        }
        // Record herestring subcommand: <<< + string
        result->cmds[subcmd_idx].start = herestring_start;
        result->cmds[subcmd_idx].len = (pos - herestring_start);
        result->cmds[subcmd_idx].type = SHELL_TYPE_HERESTRING;
        result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
        result->cmds[subcmd_idx].features = SHELL_FEAT_HERESTRING;
        result->cmds[subcmd_idx].group_depth = group_depth;
        result->cmds[subcmd_idx].group_kinds = group_kinds;
        result->cmds[subcmd_idx].modifiers =
            negated_document_stage ? SHELL_CMD_MOD_PIPE_NEGATED : 0;
        result->cmds[subcmd_idx].pipeline_negation_count =
            negated_document_stage ? negation_count : 0;
        subcmd_idx++;

        // Start next subcommand
        subcmd_start = pos;
        current_type = SHELL_TYPE_SIMPLE;
        current_pipe_input_mode = SHELL_PIPE_MODE_NONE;

        // Skip whitespace to next token
        while (pos < cmd_len && isspace((unsigned char)cmd[pos]))
          pos++;
        continue;
      }
    }

    // Check for HEREDOC << (heredoc) - only if not <<< and NOT inside
    // arithmetic
    size_t heredoc_operator_after = 0;
    if (arith_depth == 0 && c == '<' &&
        shell_source_match_logical_punctuation(cmd, cmd_len, pos, "<<",
                                               &heredoc_operator_after)) {
      uint32_t redirect_prefix_start =
          source_redirect_prefix_start_before(cmd, pos, cmd_len);
      uint32_t negation_stage = subcmd_start;
      uint32_t negation_count = range_pipeline_negation_prefix(
          cmd, subcmd_start, pos, &negation_stage);
      bool negated_document_stage =
          negation_count != 0 && negation_stage == pos;
      /* A trailing group redirection may carry an io_number immediately
       * before `<<`.  It is still a redirect on the completed group, not a
       * synthetic command containing that number. */
      bool trailing_group_redirect =
          last_closed_group_end != UINT32_MAX &&
          shell_source_skip_inline_continuations(cmd, pos,
                                                 last_closed_group_end) == pos;
      if (!trailing_group_redirect) {
        size_t descriptor_after = 0;
        uint32_t descriptor = 0;
        bool numeric_prefix =
            shell_source_parse_io_number(cmd, redirect_prefix_start, pos,
                                         &descriptor_after, &descriptor) ==
                SHELL_SOURCE_IO_NUMBER_VALID &&
            descriptor_after == pos;
        trailing_group_redirect =
            last_closed_group_end != UINT32_MAX &&
            redirect_prefix_start > last_closed_group_end &&
            shell_source_skip_inline_continuations(cmd, redirect_prefix_start,
                                                   last_closed_group_end) ==
                redirect_prefix_start &&
            (numeric_prefix || redirect_prefix_start != pos);
      }
      // End current subcommand if it has content (trim whitespace)
      if (!trailing_group_redirect && !negated_document_stage &&
          subcmd_idx < max_cmds && subcmd_start < pos) {
        uint32_t s = subcmd_start;
        uint32_t e =
            redirect_prefix_start >= subcmd_start ? redirect_prefix_start : pos;
        while (s < e && isspace((unsigned char)cmd[s]))
          s++;
        while (e > s && isspace((unsigned char)cmd[e - 1]))
          e--;
        if (s < e) {
          result->cmds[subcmd_idx].start = s;
          result->cmds[subcmd_idx].len = e - s;
          result->cmds[subcmd_idx].type = current_type;
          result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
          result->cmds[subcmd_idx].features = 0;
          result->cmds[subcmd_idx].group_depth = group_depth;
          result->cmds[subcmd_idx].group_kinds = group_kinds;
          detect_all_features(cmd, s, e - s,
                              &result->cmds[subcmd_idx].features);
          subcmd_idx++;
        }
      }

      // Start heredoc as new subcommand
      if (subcmd_idx >= max_cmds) {
        result->status = SHELL_STATUS_TRUNCATED;
        result->count = subcmd_idx;
        goto truncated;
      }

      // Find heredoc delimiter (word after <<).  This is a shell word rather
      // than a whitespace-delimited string: quotes and backslash escapes may
      // be part of its spelling.  Keep this in lockstep with the body scanner
      // so the marker range ends after the complete raw delimiter word.
      uint32_t heredoc_start = pos;
      if (!trailing_group_redirect)
        heredoc_prefix_start = redirect_prefix_start;
      size_t delimiter_position = heredoc_operator_after;
      shell_source_pending_heredoc_t pending;
      bool delimiter_valid = shell_source_parse_heredoc_delimiter(
          cmd, cmd_len, &delimiter_position, &pending);

      if (!delimiter_valid) {
        size_t delimiter_start = heredoc_operator_after;
        if (delimiter_start < cmd_len && cmd[delimiter_start] == '-')
          delimiter_start++;
        while (delimiter_start < cmd_len &&
               (cmd[delimiter_start] == ' ' || cmd[delimiter_start] == '\t'))
          delimiter_start++;
        if (delimiter_start < cmd_len &&
            (cmd[delimiter_start] == '(' || cmd[delimiter_start] == ')')) {
          /* An unquoted parenthesis is shell syntax, not a heredoc delimiter.
           * In particular, `<< (word)` cannot become a redirect followed by
           * a command group. */
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        // No delimiter found - treat as less-than
        pos = heredoc_start + 1;
      } else {
        pos = (uint32_t)delimiter_position;
        // Record heredoc subcommand: include << and delimiter
        result->cmds[subcmd_idx].start = heredoc_start;
        result->cmds[subcmd_idx].len = (pos - heredoc_start); // << + delimiter
        result->cmds[subcmd_idx].type = SHELL_TYPE_HEREDOC;
        result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
        result->cmds[subcmd_idx].features = SHELL_FEAT_HEREDOC;
        result->cmds[subcmd_idx].group_depth = group_depth;
        result->cmds[subcmd_idx].group_kinds = group_kinds;
        result->cmds[subcmd_idx].modifiers =
            negated_document_stage ? SHELL_CMD_MOD_PIPE_NEGATED : 0;
        result->cmds[subcmd_idx].pipeline_negation_count =
            negated_document_stage ? negation_count : 0;
        subcmd_idx++;

        // Start next subcommand after delimiter
        subcmd_start = pos;
        current_type = SHELL_TYPE_SIMPLE;
        current_pipe_input_mode = SHELL_PIPE_MODE_NONE;

        // Skip whitespace to next token
        while (pos < cmd_len && isspace((unsigned char)cmd[pos]))
          pos++;
        continue;
      }
    }

    /* Close an ordinary parenthesized group after recording its final
     * command.  The group itself is represented by group_depth metadata. */
    if (closes_group) {
      if (brace_group_depth > 0) {
        if (brace_group_stack_depth == 0 ||
            brace_group_stack[brace_group_stack_depth - 1] !=
                SHELL_GROUP_SUBSHELL) {
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        brace_group_stack_depth--;
      }
      if (subcmd_start < pos)
        RECORD_SUBCMD(subcmd_start, pos, current_type);
      CLOSE_GROUP(SHELL_GROUP_SUBSHELL, pos + 1);
      last_closed_group_end = pos + 1;
      group_paren_depth--;
      group_depth--;
      if (group_paren_depth == 0)
        group_kinds &= (uint8_t)~SHELL_GROUP_SUBSHELL;
      pos++;
      subcmd_start = pos;
      current_type = SHELL_TYPE_SIMPLE;
      comment_start = UINT32_MAX;
      continue;
    }

    // Check for separators (but not if inside arithmetic - there < > are
    // operators)
    if (arith_depth == 0 && substitution_paren_depth == 0 && is_separator(c)) {
      /* A lone '&' backgrounds the preceding command and starts a new
       * execution unit. It is distinct from logical AND (&&). */
      size_t operator_after = pos;
      bool logical_and =
          c == '&' && shell_source_match_logical_punctuation(
                          cmd, cmd_len, pos, "&&", &operator_after);
      bool logical_or =
          c == '|' && shell_source_match_logical_punctuation(
                          cmd, cmd_len, pos, "||", &operator_after);
      if (c == '&' && !logical_and) {
        if (subcmd_start < pos)
          RECORD_SUBCMD(subcmd_start, pos, current_type);
        if (subcmd_idx > 0)
          result->cmds[subcmd_idx - 1].features |= SHELL_FEAT_BACKGROUND;
        pos++;
        subcmd_start = pos;
        current_type = SHELL_TYPE_BACKGROUND;
        current_pipe_input_mode = SHELL_PIPE_MODE_NONE;
        comment_start = UINT32_MAX;
        last_closed_group_end = UINT32_MAX;
        continue;
      }

      // Handle &&
      if (logical_and) {
        // End current subcommand (trim whitespace)
        if (subcmd_start < pos) {
          if (subcmd_idx >= max_cmds) {
            result->status = SHELL_STATUS_TRUNCATED;
            result->count = subcmd_idx;
            goto truncated;
          }
          uint32_t s = subcmd_start;
          uint32_t e = range_end_before_comment(s, pos, comment_start);
          while (s < e && isspace((unsigned char)cmd[s]))
            s++;
          while (e > s && isspace((unsigned char)cmd[e - 1]))
            e--;
          if (s < e) {
            result->cmds[subcmd_idx].start = s;
            result->cmds[subcmd_idx].len = e - s;
            result->cmds[subcmd_idx].type = current_type;
            result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
            result->cmds[subcmd_idx].features = 0;
            result->cmds[subcmd_idx].group_depth = group_depth;
            result->cmds[subcmd_idx].group_kinds = group_kinds;
            detect_all_features(cmd, s, e - s,
                                &result->cmds[subcmd_idx].features);
            subcmd_idx++;
          }
        }

        // Start new subcommand with AND type
        pos = (uint32_t)operator_after;
        subcmd_start = pos;
        current_type = SHELL_TYPE_AND;
        current_pipe_input_mode = SHELL_PIPE_MODE_NONE;
        last_closed_group_end = UINT32_MAX;
        continue;
      }

      // Handle ||
      if (logical_or) {
        // End current subcommand (trim whitespace)
        if (subcmd_start < pos) {
          if (subcmd_idx >= max_cmds) {
            result->status = SHELL_STATUS_TRUNCATED;
            result->count = subcmd_idx;
            goto truncated;
          }
          uint32_t s = subcmd_start;
          uint32_t e = pos;
          while (s < e && isspace((unsigned char)cmd[s]))
            s++;
          while (e > s && isspace((unsigned char)cmd[e - 1]))
            e--;
          if (s < e) {
            result->cmds[subcmd_idx].start = s;
            result->cmds[subcmd_idx].len = e - s;
            result->cmds[subcmd_idx].type = current_type;
            result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
            result->cmds[subcmd_idx].features = 0;
            result->cmds[subcmd_idx].group_depth = group_depth;
            result->cmds[subcmd_idx].group_kinds = group_kinds;
            detect_all_features(cmd, s, e - s,
                                &result->cmds[subcmd_idx].features);
            subcmd_idx++;
          }
        }

        // Start new subcommand with OR type
        pos = (uint32_t)operator_after;
        subcmd_start = pos;
        current_type = SHELL_TYPE_OR;
        current_pipe_input_mode = SHELL_PIPE_MODE_NONE;
        last_closed_group_end = UINT32_MAX;
        continue;
      }

      // Handle |
      if (c == '|' && !(pos > 0 && cmd[pos - 1] == '>')) {
        // End current subcommand (trim whitespace)
        if (subcmd_start < pos) {
          if (subcmd_idx >= max_cmds) {
            result->status = SHELL_STATUS_TRUNCATED;
            result->count = subcmd_idx;
            goto truncated;
          }
          uint32_t s = subcmd_start;
          uint32_t e = pos;
          while (s < e && isspace((unsigned char)cmd[s]))
            s++;
          while (e > s && isspace((unsigned char)cmd[e - 1]))
            e--;
          if (s < e) {
            result->cmds[subcmd_idx].start = s;
            result->cmds[subcmd_idx].len = e - s;
            result->cmds[subcmd_idx].type = current_type;
            result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
            result->cmds[subcmd_idx].features = 0;
            result->cmds[subcmd_idx].group_depth = group_depth;
            result->cmds[subcmd_idx].group_kinds = group_kinds;
            detect_all_features(cmd, s, e - s,
                                &result->cmds[subcmd_idx].features);
            subcmd_idx++;
          }
        }

        // Start new subcommand with PIPELINE type
        if (subcmd_idx > 0)
          result->cmds[subcmd_idx - 1].features |= SHELL_FEAT_PIPELINE;
        size_t pipe_after = pos + 1;
        bool pipe_stderr = shell_source_match_logical_punctuation(
            cmd, cmd_len, pos, "|&", &pipe_after);
        /* A failed multi-byte match deliberately leaves `pipe_after` at the
         * first byte.  Ordinary `|` must still consume itself; otherwise the
         * fast parser revisits the same source offset forever. */
        pos = (uint32_t)(pipe_stderr ? pipe_after : (size_t)pos + 1);
        subcmd_start = pos;
        current_type = SHELL_TYPE_PIPELINE;
        current_pipe_input_mode = pipe_stderr
                                      ? SHELL_PIPE_MODE_STDOUT_AND_STDERR
                                      : SHELL_PIPE_MODE_STDOUT;
        last_closed_group_end = UINT32_MAX;
        continue;
      }

      // Handle ; and newlines as command separators
      if (c == ';' || c == '\n' || c == '\r') {
        // End current subcommand (trim whitespace)
        bool pending_list_continuation =
            (current_type == SHELL_TYPE_PIPELINE ||
             current_type == SHELL_TYPE_AND || current_type == SHELL_TYPE_OR) &&
            source_range_is_list_continuation_trivia(cmd, subcmd_start,
                                                     pos + 1);
        /* Unlike a binary list connector, a leading `!` cannot cross a raw
         * comment or physical line ending. Recognize only a same-logical-line
         * modifier prefix so strict validation rejects an incomplete pipeline
         * rather than treating the reserved word as an executable command. */
        bool pending_pipeline_negation =
            range_is_pipeline_negator_prefix(cmd, subcmd_start, pos + 1);
        if (subcmd_start < pos) {
          if (subcmd_idx >= max_cmds) {
            result->status = SHELL_STATUS_TRUNCATED;
            result->count = subcmd_idx;
            goto truncated;
          }
          uint32_t s = subcmd_start;
          uint32_t e = range_end_before_comment(s, pos, comment_start);
          while (s < e && isspace((unsigned char)cmd[s]))
            s++;
          while (e > s && isspace((unsigned char)cmd[e - 1]))
            e--;
          /* POSIX linebreaks after a pending pipeline or AND/OR connector
           * continue the next stage. The full tokenizer already recognizes
           * this grammar; retain the fast parser's connector metadata rather
           * than silently turning it into a semicolon relation. */
          if (s < e && !pending_list_continuation &&
              !pending_pipeline_negation) {
            result->cmds[subcmd_idx].start = s;
            result->cmds[subcmd_idx].len = e - s;
            result->cmds[subcmd_idx].type = current_type;
            result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
            result->cmds[subcmd_idx].features = 0;
            result->cmds[subcmd_idx].group_depth = group_depth;
            result->cmds[subcmd_idx].group_kinds = group_kinds;
            detect_all_features(cmd, s, e - s,
                                &result->cmds[subcmd_idx].features);
            subcmd_idx++;
          }
        }

        if (pending_list_continuation) {
          pos++;
          subcmd_start = pos;
          comment_start = UINT32_MAX;
          continue;
        }
        if (pending_pipeline_negation) {
          pos++;
          comment_start = UINT32_MAX;
          continue;
        }

        // Start new subcommand with SEMICOLON type
        pos++;
        subcmd_start = pos;
        current_type = SHELL_TYPE_SEMICOLON;
        current_pipe_input_mode = SHELL_PIPE_MODE_NONE;
        comment_start = UINT32_MAX;
        last_closed_group_end = UINT32_MAX;
        continue;
      }

      // Handle < and > (redirects) - skip but don't break subcommand
      // But NOT if inside arithmetic - there they're operators, not redirects
      if ((c == '<' || c == '>') && arith_depth == 0) {
        // Check for process substitution: >(cmd) or <(cmd)
        size_t process_open = 0;
        if (shell_source_process_substitution_open(cmd, cmd_len, pos,
                                                   &process_open)) {
          size_t after = 0;
          if (!shell_source_find_balanced_parentheses(cmd, cmd_len,
                                                      process_open, &after) ||
              after > UINT32_MAX) {
            result->status = SHELL_STATUS_ERROR;
            result->count = subcmd_idx;
            return SHELL_EPARSE;
          }
          pos = (uint32_t)after;
          // Mark that we have process substitution (if we have at least one
          // subcommand)
          if (subcmd_idx > 0 && subcmd_idx < max_cmds) {
            result->cmds[subcmd_idx - 1].features |= SHELL_FEAT_PROCESS_SUB;
          }
          if (current_type == SHELL_TYPE_SIMPLE) {
            current_type = SHELL_TYPE_SUBSTITUTION;
          }
          continue;
        }
        // Check for multi-char redirects: >>, <<, >&, &>, <&, &<, etc.
        bool is_double_redirect = false;
        bool is_extended_redirect = false;
        bool is_fd_redirect = false; // >& or <& (file descriptor redirect)
        size_t redirect_after = (size_t)pos + 1;
        size_t redirect_next =
            shell_source_logical_following(cmd, cmd_len, pos);
        if (redirect_next < cmd_len) {
          if (cmd[redirect_next] == c) {
            // >>, <<
            is_double_redirect = true;
            redirect_after = redirect_next + 1;
          } else if ((c == '>' && cmd[redirect_next] == '|') ||
                     (c == '<' && cmd[redirect_next] == '>')) {
            is_extended_redirect = true;
            redirect_after = redirect_next + 1;
          } else if (cmd[redirect_next] == '&') {
            // >& or <& (fd redirect)
            is_fd_redirect = true;
            redirect_after = redirect_next + 1;
          }
        }
        pos = (uint32_t)redirect_after;
        // Skip file descriptor number if present (but not after >>, and not for
        // fd redirects) For 2>file, skip the 2. For 2>&1, don't skip the 1
        // (it's the target).
        if (!is_double_redirect && !is_fd_redirect && !is_extended_redirect) {
          size_t target_after = 0;
          uint32_t descriptor = 0;
          if (shell_source_parse_io_number(cmd, pos, cmd_len, &target_after,
                                           &descriptor) ==
              SHELL_SOURCE_IO_NUMBER_VALID)
            pos = (uint32_t)target_after;
        }
        pos =
            (uint32_t)shell_source_skip_inline_continuations(cmd, cmd_len, pos);
        // Validate: redirect must be followed by a valid target
        // Check for end of input or invalid next character
        if (pos >= cmd_len) {
          // No target after redirect - invalid
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }

        // Check for valid redirect operators: &>, &>>, <&, &<, etc.
        // These are valid bash redirects (e.g., >&1, 2>&1, &>file)
        char next_ch = cmd[pos];
        /* A process substitution may be the target of an ordinary redirect:
         * `2> >(consumer)` and `0< <(producer)`. Leave its opener for the
         * normal process-substitution scanner on the next iteration. */
        bool process_sub_target =
            (next_ch == '<' || next_ch == '>') &&
            shell_source_process_substitution_open(cmd, cmd_len, pos, NULL);
        /* Process substitution is one shell word. The opener must be
         * contiguous with `<` or `>`: `> (command)` is a syntax error, not a
         * redirect to a parenthesized command group. The same spelling is not
         * a valid unquoted heredoc delimiter either. */
        bool bare_group_operand = next_ch == '(';
        if (bare_group_operand) {
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        // Redirect target can't be an operator or an unquoted comment,
        // except process substitution.  Inline continuations have already
        // been removed; an ordinary physical line break remains an error.
        if (!process_sub_target &&
            (next_ch == '<' || next_ch == '>' || next_ch == '|' ||
             next_ch == ';' || next_ch == '&' || next_ch == '#' ||
             next_ch == '\n' || next_ch == '\r')) {
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        continue;
      }
    }

    pos++;
  }

  if (brace_group_depth != 0 || brace_group_stack_depth != 0) {
    result->status = SHELL_STATUS_ERROR;
    result->count = subcmd_idx;
    return SHELL_EPARSE;
  }
  /* The historical non-strict fast-parser contract accepts an unfinished
   * parenthesized prefix. Do not expose an incomplete descriptor for it. */
  if (group_descriptor_depth != 0) {
    if (limits->strict_mode) {
      result->status = SHELL_STATUS_ERROR;
      result->count = subcmd_idx;
      return SHELL_EPARSE;
    }
    result->group_count = group_descriptor_stack[0];
  }

  // End final subcommand
  if (subcmd_start < pos && subcmd_idx < max_cmds) {
    // Trim trailing whitespace
    uint32_t end_pos = pos;
    while (end_pos > subcmd_start && isspace((unsigned char)cmd[end_pos - 1])) {
      end_pos--;
    }

    // Trim leading whitespace
    uint32_t start_pos = subcmd_start;
    end_pos = range_end_before_comment(start_pos, end_pos, comment_start);
    while (start_pos < end_pos && isspace((unsigned char)cmd[start_pos])) {
      start_pos++;
    }

    if (start_pos < end_pos) {
      result->cmds[subcmd_idx].start = start_pos;
      result->cmds[subcmd_idx].len = end_pos - start_pos;
      result->cmds[subcmd_idx].type = current_type;
      result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
      result->cmds[subcmd_idx].features = 0;
      result->cmds[subcmd_idx].group_depth = group_depth;
      result->cmds[subcmd_idx].group_kinds = group_kinds;
      detect_all_features(cmd, start_pos, end_pos - start_pos,
                          &result->cmds[subcmd_idx].features);
      subcmd_idx++;
    }
  } else if (subcmd_idx >= max_cmds) {
    result->status = SHELL_STATUS_TRUNCATED;
    result->count = subcmd_idx;
    goto truncated;
  }

  if (limits && limits->strict_mode) {
    bool in_single = false, in_double = false, in_backtick = false;
    for (size_t i = 0; i < cmd_len; i++) {
      char c = cmd[i];
      if (!in_single && !in_double && !in_backtick && c == '#' &&
          shell_source_comment_starts(cmd, cmd_len, i)) {
        while (i < cmd_len && cmd[i] != '\n' && cmd[i] != '\r')
          i++;
        continue;
      }
      if (!in_single && !in_double && !in_backtick && c == '$' &&
          i + 1 < cmd_len && cmd[i + 1] == '\'') {
        size_t after = 0;
        if (shell_source_skip_complete_ansi_c_quote(cmd, cmd_len, i, &after)) {
          i = after - 1;
          continue;
        }
      }
      if (c == '\\' && !in_single && i + 1 < cmd_len) {
        i++;
        continue;
      }
      if (c == '\'' && !in_double && !in_backtick) {
        in_single = !in_single;
      } else if (c == '"' && !in_single && !in_backtick) {
        in_double = !in_double;
      } else if (c == '`' && !in_single) {
        in_backtick = !in_backtick;
      }
    }
    if (in_single || in_double || in_backtick) {
      result->status |= SHELL_STATUS_ERROR;
      result->count = subcmd_idx;
      return SHELL_EPARSE;
    }
  }

  // Check for unclosed quotes, parameter braces, or arithmetic expansion.
  // Only in strict mode; permissive mode allows unterminated quotes
  if ((limits && limits->strict_mode) &&
      (in_quotes || brace_depth > 0 || arith_depth > 0)) {
    result->status = SHELL_STATUS_ERROR;
    result->count = subcmd_idx;
    return SHELL_EPARSE;
  }

  // Check for unclosed parentheses - indicates invalid input like "( git"
  // But allow subshell syntax - only reject if paren_depth > 0 AND the content
  // doesn't look like a valid subshell (e.g., "( ls )" has matching parens)
  if ((limits && limits->strict_mode) && paren_depth > 0) {
    result->status = SHELL_STATUS_ERROR;
    result->count = subcmd_idx;
    return SHELL_EPARSE;
  }

  /* Control compounds are deliberately outside this range tokenizer's grammar.
   * The lexer-aware scan rejects incomplete forms while allowing complete
   * forms through to higher-level APIs, which reject unsupported execution
   * semantics before producing canonical records or dependency graphs. */
  if (shell_tokenizer_control_syntax(cmd, cmd_len) ==
      SHELL_CONTROL_SYNTAX_INCOMPLETE) {
    result->status = SHELL_STATUS_ERROR;
    result->count = subcmd_idx;
    return SHELL_EPARSE;
  }

  /* A comment-only source is valid but has no executable range. Redirects
   * without an operand and incomplete list operators have already returned
   * from the structural scan above, so no second raw-byte operator pass is
   * needed here. */
  if (subcmd_idx == 0) {
    if (source_is_comment_only(cmd, cmd_len)) {
      result->count = 0;
      normalize_result_metadata(result);
      result->status = SHELL_STATUS_OK;
      return SHELL_OK;
    }
    result->status = SHELL_STATUS_ERROR;
    result->count = 0;
    return SHELL_EPARSE;
  }

  // Ensure each parsed subcommand has real content beyond redirect/separator
  // syntax.
  bool has_command_content = false;
  for (uint32_t i = 0; i < subcmd_idx; i++) {
    uint32_t start = result->cmds[i].start;
    uint32_t len = result->cmds[i].len;

    // Check if this subcommand has actual content (not just redirect chars)
    for (uint32_t j = 0; j < len; j++) {
      char ch = cmd[start + j];
      // Skip redirect operators and separators
      if (ch == '<' || ch == '>' || ch == ';' || ch == '|' || ch == '&') {
        continue;
      }
      // Skip whitespace
      if (isspace((unsigned char)ch)) {
        continue;
      }
      // This subcommand has actual command content
      has_command_content = true;
      break;
    }
    if (has_command_content)
      break;
  }

  if (!has_command_content) {
    result->status = SHELL_STATUS_ERROR;
    result->count = 0;
    return SHELL_EPARSE;
  }

  /* A literal final '|', ';', or '&' may be quoted or escaped. The scanner's
   * pending list state, rather than a raw source-byte check, is authoritative
   * for an actual trailing operator. */
  if (subcmd_start >= cmd_len && subcmd_idx > 0) {
    // The last thing we saw was a separator - check what type
    // If current_type is PIPELINE/SEMICOLON/AND/OR, we have a trailing
    // separator
    if (current_type == SHELL_TYPE_PIPELINE || current_type == SHELL_TYPE_AND ||
        current_type == SHELL_TYPE_OR) {
      result->status = SHELL_STATUS_ERROR;
      result->count = subcmd_idx;
      return SHELL_EPARSE;
    }
  }

  if (limits->strict_mode &&
      !strict_heredocs_complete(cmd, (uint32_t)cmd_len)) {
    result->status = SHELL_STATUS_ERROR;
    result->count = subcmd_idx;
    return SHELL_EPARSE;
  }

  result->count = subcmd_idx;
  if (!normalize_pipeline_negation(cmd, result)) {
    result->status = SHELL_STATUS_ERROR;
    return SHELL_EPARSE;
  }
  normalize_result_metadata(result);
  result->status = SHELL_STATUS_OK;
  return SHELL_OK;

truncated:
  result->count = subcmd_idx;
  if (!normalize_pipeline_negation(cmd, result)) {
    result->status = SHELL_STATUS_ERROR;
    return SHELL_EPARSE;
  }
  normalize_result_metadata(result);
  result->status = SHELL_STATUS_TRUNCATED;
  return SHELL_ETRUNC;
}

/**
 * Copy subcommand to buffer (null-terminated)
 */
size_t shell_subcommand_copy(const char *cmd, const shell_range_t *range,
                             char *buf, size_t buf_len) {
  if (!cmd || !range || !buf || buf_len == 0) {
    return 0;
  }

  if (range->len == 0) {
    buf[0] = '\0';
    return 0;
  }

  size_t copy_len = range->len;
  if (copy_len >= buf_len) {
    copy_len = buf_len - 1;
  }

  memcpy(buf, cmd + range->start, copy_len);
  buf[copy_len] = '\0';
  return copy_len;
}

/**
 * Get subcommand pointer (not null-terminated)
 */
const char *shell_subcommand_view(const char *cmd, const shell_range_t *range,
                                  size_t *out_len) {
  if (!cmd || !range) {
    if (out_len)
      *out_len = 0;
    return NULL;
  }

  if (out_len)
    *out_len = range->len;
  return cmd + range->start;
}

const char *shell_error_string(shell_error_t err) {
  switch (err) {
  case SHELL_OK:
    return "OK";
  case SHELL_EINPUT:
    return "Invalid input";
  case SHELL_ETRUNC:
    return "Truncated (limits exceeded)";
  case SHELL_EPARSE:
    return "Parse error";
  default:
    return "Unknown error";
  }
}

void shell_feature_flags_from_bits(uint32_t features,
                                   shell_feature_flags_t *flags) {
  if (!flags)
    return;
  flags->has_vars = (features & SHELL_FEAT_VARS) != 0;
  flags->has_globs = (features & SHELL_FEAT_GLOBS) != 0;
  flags->has_subshell = (features & SHELL_FEAT_SUBSHELL) != 0;
  flags->has_arith = (features & SHELL_FEAT_ARITH) != 0;
  flags->has_heredoc = (features & SHELL_FEAT_HEREDOC) != 0;
  flags->has_herestring = (features & SHELL_FEAT_HERESTRING) != 0;
  flags->has_process_sub = (features & SHELL_FEAT_PROCESS_SUB) != 0;
  flags->has_loops = (features & SHELL_FEAT_LOOPS) != 0;
  flags->has_conditionals = (features & SHELL_FEAT_CONDITIONALS) != 0;
  flags->has_case = (features & SHELL_FEAT_CASE) != 0;
  flags->has_subshell_file = (features & SHELL_FEAT_SUBSHELL_FILE) != 0;
  flags->has_pipeline = (features & SHELL_FEAT_PIPELINE) != 0;
  flags->has_group = (features & SHELL_FEAT_GROUP) != 0;
  flags->has_background = (features & SHELL_FEAT_BACKGROUND) != 0;
  flags->has_extglob = (features & SHELL_FEAT_EXTGLOB) != 0;
  flags->has_ansi_c_quote = (features & SHELL_FEAT_ANSI_C_QUOTE) != 0;
  flags->has_array = (features & SHELL_FEAT_ARRAY) != 0;
  flags->has_named_fd = (features & SHELL_FEAT_NAMED_FD) != 0;
  flags->has_combined_redirect = (features & SHELL_FEAT_COMBINED_REDIRECT) != 0;
}
