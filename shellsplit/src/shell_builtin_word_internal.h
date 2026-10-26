#ifndef SHELL_BUILTIN_WORD_INTERNAL_H
#define SHELL_BUILTIN_WORD_INTERNAL_H

#include "shell_source_internal.h"

/* Visit literal and opaque scalar/substitution fragments of a complete word.
 * With allow_unquoted=false, success proves one argv entry, including empty.
 * With it true, unquoted scalar cardinality remains the caller's concern.
 * List selectors are not projected; callbacks may have seen a prefix before
 * failure. The source boundary separately checks nested expansion semantics.
 * Visitors consume every fragment; context may be NULL if they allow it. */
typedef void (*shell_builtin_word_dynamic_fn)(const char *word, size_t length,
                                              bool quoted, void *context);
/* NULL rejects nonempty process fragments. A visitor receives their guaranteed
 * pathname contribution, not an evaluated pathname or the child source. */
typedef void (*shell_builtin_word_process_fn)(void *context);

/* The source scanner has isolated a complete parameter expansion. Prove
 * scalar cardinality without resolving its value or copying its identifier.
 * Complex operators and list selectors remain unknown; length selectors are
 * scalar even for @. Logical continuations do not change that proof. */
static inline SHELL_NONNULL(1) bool shell_builtin_parameter_is_scalar(
    const char *word, size_t length) {
  size_t position = shell_source_skip_escaped_line_endings(word, length, 1);
  size_t end = length;
  if (word[position] == '{') {
    position++;
    end--;
  }
  position = shell_source_skip_escaped_line_endings(word, end, position);
  if (position == end)
    return false;
  unsigned char first = (unsigned char)word[position];
  size_t next = shell_source_skip_escaped_line_endings(word, end, position + 1);
  bool length_selector = first == '#' && next < end;
  if (length_selector) {
    position = next;
    first = (unsigned char)word[position];
    next = shell_source_skip_escaped_line_endings(word, end, position + 1);
  }
  if (strchr("#?$!-*@", first))
    return next == end && (first != '@' || length_selector);
  bool positional = shell_ascii_digit(first) != 0;
  if (!positional && !(shell_ascii_alpha(first) || first == '_'))
    return false;
  for (position = next; position < end;) {
    unsigned char byte = (unsigned char)word[position];
    if (positional ? !shell_ascii_digit(byte)
                   : !(shell_ascii_alnum(byte) || byte == '_'))
      return false;
    position = shell_source_skip_escaped_line_endings(word, end, position + 1);
  }
  return true;
}

static inline SHELL_NONNULL(1, 3, 4) bool shell_builtin_visit_word_impl(
    const char *word, size_t length, shell_source_byte_visitor_t literal,
    shell_builtin_word_dynamic_fn dynamic, void *context, bool allow_unquoted,
    shell_builtin_word_process_fn process) {
  char quote = 0;
  bool start = true;
  shell_source_brace_scan_t braces = {0};
  shell_source_glob_scan_t glob = {0};
  for (size_t position = 0; position < length;) {
    unsigned char byte = (unsigned char)word[position];
    size_t empty_after;
    if (!quote && (byte == '<' || byte == '>') &&
        shell_source_empty_process_fragment(word, length, position,
                                            &empty_after)) {
      position = empty_after;
      start = false;
      continue;
    }
    if (byte == '\\' && quote != '\'' && position + 1 < length) {
      unsigned char next = (unsigned char)word[position + 1];
      if (!quote || next == '$' || next == '`' || next == '"' || next == '\\' ||
          next == '\n') {
        position += 2;
        if (next != '\n') {
          shell_source_brace_scan_literal(&braces);
          shell_source_glob_scan_step(&glob, next, true);
          literal(next, context);
          start = false;
        }
        continue;
      }
    }
    if (!quote && byte == '$' &&
        shell_source_logical_next_is(word, length, position, '\'', NULL)) {
      shell_source_brace_scan_literal(&braces);
      if (!shell_source_decode_ansi_c_word(word, length, &position, literal,
                                           context))
        return false;
      start = false;
      continue;
    }
    if (!quote && (byte == '\'' || byte == '"')) {
      shell_source_brace_scan_literal(&braces);
      quote = (char)byte;
      start = false;
      position++;
      continue;
    }
    if (quote && byte == (unsigned char)quote) {
      quote = 0;
      position++;
      continue;
    }
    if (quote != '\'' && (byte == '`' || shell_source_dollar_has_dynamic_syntax(
                                             word, length, position))) {
      if (quote != '"' && !allow_unquoted)
        return false;
      size_t after = 0, open = 0;
      if (byte == '`') {
        if (!shell_source_skip_complete_backtick(word, length, position,
                                                 &after))
          return false;
      } else if (shell_source_dollar_arithmetic_open(word, length, position,
                                                     &open)) {
        if (!shell_source_skip_arithmetic_expansion(word, length, position,
                                                    &after))
          return false;
      } else if (shell_source_dollar_parentheses_open(word, length, position,
                                                      &open)) {
        if (!shell_source_find_balanced_parentheses(word, length, open, &after))
          return false;
      } else {
        if (!shell_source_skip_variable_expansion(word, length, position,
                                                  &after) ||
            !shell_builtin_parameter_is_scalar(word + position,
                                               after - position))
          return false;
      }
      dynamic(word + position, after - position, quote == '"', context);
      position = after;
      start = false;
      continue;
    }
    if (!quote) {
      size_t open, after;
      if ((byte == '<' || byte == '>') &&
          shell_source_process_substitution_open(word, length, position,
                                                 &open)) {
        if (!process ||
            !shell_source_find_balanced_parentheses(word, length, open, &after))
          return false;
        process(context);
        shell_source_brace_scan_literal(&braces);
        shell_source_glob_scan_step(&glob, '/', true);
        position = after;
        start = false;
        continue;
      }
      if (((byte == '?' || byte == '*' || byte == '+' || byte == '@' ||
            byte == '!') &&
           shell_source_logical_next_is(word, length, position, '(', NULL)) ||
          byte == '*' || byte == '?' || (byte == '~' && start) ||
          shell_source_glob_scan_step(&glob, byte, false) ||
          shell_source_brace_scan_step(&braces, byte))
        return false;
    } else
      shell_source_glob_scan_step(&glob, byte, true);
    literal(byte, context);
    start = false;
    position++;
  }
  return quote == 0;
}

static inline SHELL_NONNULL(1, 3, 4) bool shell_builtin_visit_single_word(
    const char *word, size_t length, shell_source_byte_visitor_t literal,
    shell_builtin_word_dynamic_fn dynamic, void *context) {
  return shell_builtin_visit_word_impl(word, length, literal, dynamic, context,
                                       false, NULL);
}

#endif
