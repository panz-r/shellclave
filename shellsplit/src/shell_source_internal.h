#ifndef SHELL_SOURCE_INTERNAL_H
#define SHELL_SOURCE_INTERNAL_H

#include "shell_tokenizer.h"
#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Parameter, quote, arithmetic, and command-substitution scanners recurse
 * into one another. A shared per-thread budget bounds mixed nesting too. */
#ifdef __cplusplus
static thread_local unsigned shell_source_scan_depth;
#else
static _Thread_local unsigned shell_source_scan_depth;
#endif

static inline bool shell_source_scan_enter(void) {
  if (shell_source_scan_depth >= SHELL_MAX_SUBCOMMANDS)
    return false;
  shell_source_scan_depth++;
  return true;
}

static inline void shell_source_scan_leave(void) { shell_source_scan_depth--; }

typedef enum {
  SHELL_SOURCE_IO_NUMBER_NONE,
  SHELL_SOURCE_IO_NUMBER_VALID,
  SHELL_SOURCE_IO_NUMBER_OVERFLOW,
} shell_source_io_number_t;

/* An io_number is adjacent decimal syntax before a redirection operator. Bash
 * accepts descriptors through INT_MAX; larger digit sequences are ordinary
 * word text, not an fd and never the UINT32_MAX no-descriptor sentinel. */
static inline shell_source_io_number_t
shell_source_parse_io_number(const char *input, size_t start, size_t end,
                             size_t *after, uint32_t *descriptor) {
  if (after)
    *after = start;
  if (descriptor)
    *descriptor = 0;
  if (!input || start > end || !after || !descriptor)
    return SHELL_SOURCE_IO_NUMBER_NONE;

  size_t position = start;
  uint64_t value = 0;
  bool overflow = false;
  while (position < end) {
    /* Escaped physical line endings disappear before IO-number recognition.
     * Horizontal space and ordinary line endings must remain boundaries. */
    if (position > start && input[position] == '\\' && position + 1 < end &&
        (input[position + 1] == '\n' || input[position + 1] == '\r')) {
      bool cr = input[position + 1] == '\r';
      position += 2;
      if (cr && position < end && input[position] == '\n')
        position++;
      continue;
    }
    if (!isdigit((unsigned char)input[position]))
      break;
    uint32_t digit = (uint32_t)(input[position] - '0');
    if (value > ((uint64_t)INT_MAX - digit) / 10u)
      overflow = true;
    if (!overflow)
      value = value * 10u + digit;
    position++;
  }
  *after = position;
  if (position == start)
    return SHELL_SOURCE_IO_NUMBER_NONE;
  if (overflow)
    return SHELL_SOURCE_IO_NUMBER_OVERFLOW;
  *descriptor = (uint32_t)value;
  return SHELL_SOURCE_IO_NUMBER_VALID;
}

/* The lexical source scanner must accept every pending heredoc that the fast
 * tokenizer can represent. Dependency-graph document limits remain separate
 * and are enforced only when a graph is built. */
#define SHELL_SOURCE_MAX_PENDING_HEREDOCS SHELL_MAX_SUBCOMMANDS

/* Source scanning is deliberately non-evaluating, but nested arithmetic
 * expansions still recurse through the scanner. Keep that recursion bounded
 * by the same structural limit used for parsed shell constructs so malformed
 * input cannot consume the process stack before a caller can reject it. */
#define SHELL_SOURCE_MAX_ARITHMETIC_NESTING SHELL_MAX_SUBCOMMANDS

/* Source text remains zero-copy throughout Shellsplit.  These helpers only
 * recognize physical line boundaries: callers retain the original bytes,
 * including carriage returns in CRLF document bodies. */
static inline size_t shell_source_line_end(const char *input, size_t length,
                                           size_t start) {
  size_t end = start;
  while (end < length && input[end] != '\n')
    end++;
  return end;
}

static inline size_t
shell_source_line_content_end(const char *input, size_t length, size_t start) {
  size_t end = shell_source_line_end(input, length, start);
  if (end > start && input[end - 1] == '\r')
    end--;
  return end;
}

static inline size_t shell_source_next_line(const char *input, size_t length,
                                            size_t start) {
  size_t end = shell_source_line_end(input, length, start);
  return end < length ? end + 1 : end;
}

/* A comment begins only at an unquoted shell-word boundary. Shell operators,
 * including redirections, end a word, so `>#comment` has no redirect operand.
 * Keep this shared with the balanced scanners so a parenthesis in comment text
 * cannot terminate a command or process substitution. */
static inline bool shell_source_comment_starts(const char *input, size_t length,
                                               size_t position) {
  if (!input || position >= length || input[position] != '#')
    return false;
  if (position == 0)
    return true;
  char previous = input[position - 1];
  return isspace((unsigned char)previous) || previous == ';' ||
         previous == '|' || previous == '&' || previous == '<' ||
         previous == '>' || previous == '(' || previous == ')';
}

/* Advance across shell grammar that may separate a pending list connector or
 * `!` pipeline modifier from its next stage: whitespace, comments, and
 * escaped physical line endings. This is intentionally not general word
 * scanning; callers must already be at a list-grammar boundary. */
static inline size_t shell_source_skip_list_trivia(const char *input,
                                                   size_t length,
                                                   size_t position) {
  if (!input || position > length)
    return 0;
  while (position < length) {
    if (isspace((unsigned char)input[position])) {
      position++;
      continue;
    }
    if (input[position] == '\\' && position + 1 < length &&
        (input[position + 1] == '\n' || input[position + 1] == '\r')) {
      position += 2;
      if (position < length && input[position - 1] == '\r' &&
          input[position] == '\n')
        position++;
      continue;
    }
    if (input[position] == '#' &&
        shell_source_comment_starts(input, length, position)) {
      while (position < length && input[position] != '\n' &&
             input[position] != '\r')
        position++;
      continue;
    }
    break;
  }
  return position;
}

/* True when an interval contains only the shell grammar that may separate a
 * list connector from its next stage. */
static inline bool shell_source_is_list_trivia(const char *input, size_t start,
                                               size_t end) {
  return input && start <= end &&
         shell_source_skip_list_trivia(input, end, start) == end;
}

/* A pipeline negator is deliberately narrower than a pending binary list
 * operator. `!` first needs a horizontal-word separator: a continuation
 * immediately after it is removed and joins the following bytes into a word
 * such as `!echo`. Once that separator exists, only horizontal whitespace and
 * escaped physical line endings may extend the gap to its pipeline stage; a
 * raw physical line ending or comment terminates the modifier. */
static inline size_t shell_source_skip_pipeline_negator_gap(const char *input,
                                                            size_t length,
                                                            size_t position) {
  if (!input || position > length)
    return 0;
  while (position < length) {
    unsigned char current = (unsigned char)input[position];
    if (isspace(current) && current != '\n' && current != '\r') {
      position++;
      continue;
    }
    if (input[position] == '\\' && position + 1 < length) {
      if (input[position + 1] == '\n') {
        position += 2;
        continue;
      }
      if (input[position + 1] == '\r') {
        position += 2;
        if (position < length && input[position] == '\n')
          position++;
        continue;
      }
    }
    break;
  }
  return position;
}

/* A standalone escaped physical line ending is a lexical continuation, not
 * a shell word. It is intentionally narrower than shell_source_is_list_trivia:
 * ordinary newlines remain visible list separators. */
static inline bool shell_source_is_escaped_line_ending(const char *input,
                                                       size_t start,
                                                       size_t end) {
  if (!input || start >= end)
    return false;
  /* The iterator may split CRLF into a `\\\r` token followed by an LF
   * separator. Both pieces belong to the same escaped physical line ending
   * and must be invisible to list grammar. */
  if (input[start] == '\n')
    return start >= 2 && input[start - 2] == '\\' && input[start - 1] == '\r' &&
           start + 1 == end;
  if (input[start] != '\\')
    return false;
  start++;
  if (start >= end)
    return false;
  if (input[start] == '\n')
    return start + 1 == end;
  if (input[start] != '\r')
    return false;
  /* The lexer may expose CRLF as either a `\\\r` token followed by LF or
   * one complete continuation token. Accept both representations. */
  return start + 1 == end ||
         (start + 1 < end && input[start + 1] == '\n' && start + 2 == end);
}

/* Advance across horizontal space and escaped physical line endings. Unlike
 * list trivia this deliberately does not cross an ordinary line break or a
 * comment: a caller using it is still examining syntax attached to the same
 * shell grammar token, such as a redirect list following a compound group. */
static inline size_t shell_source_skip_inline_continuations(const char *input,
                                                            size_t length,
                                                            size_t position) {
  if (!input || position > length)
    return 0;
  while (position < length) {
    if (input[position] == ' ' || input[position] == '\t') {
      position++;
      continue;
    }
    if (input[position] != '\\' || position + 1 >= length)
      break;
    if (input[position + 1] == '\n') {
      position += 2;
      continue;
    }
    if (input[position + 1] == '\r') {
      position += 2;
      if (position < length && input[position] == '\n')
        position++;
      continue;
    }
    break;
  }
  return position;
}

/* Escaped physical line endings are removed by shell lexical processing, but
 * horizontal whitespace remains significant for syntax that requires lexical
 * adjacency. In particular, Bash accepts `{fd}\\\n>out` as a named-FD
 * redirect and rejects `{fd} >out`. Keep this deliberately narrower than
 * shell_source_skip_inline_continuations(). */
static inline size_t shell_source_skip_escaped_line_endings(const char *input,
                                                            size_t length,
                                                            size_t position) {
  if (!input || position > length)
    return 0;
  while (position + 1 < length && input[position] == '\\') {
    if (input[position + 1] == '\n') {
      position += 2;
      continue;
    }
    if (input[position + 1] == '\r') {
      position += 2;
      if (position < length && input[position] == '\n')
        position++;
      continue;
    }
    break;
  }
  return position;
}

/* Reverse counterpart for source ranges that end immediately after logical
 * punctuation.  It strips only physical continuations, never horizontal
 * whitespace or ordinary line breaks. */
static inline size_t shell_source_skip_escaped_line_endings_backward(
    const char *input, size_t length, size_t position) {
  if (!input || position > length)
    return 0;
  while (position >= 2) {
    if (input[position - 1] == '\n' && input[position - 2] == '\\') {
      position -= 2;
      continue;
    }
    if (position >= 3 && input[position - 1] == '\n' &&
        input[position - 2] == '\r' && input[position - 3] == '\\') {
      position -= 3;
      continue;
    }
    if (input[position - 1] == '\r' && input[position - 2] == '\\') {
      position -= 2;
      continue;
    }
    break;
  }
  return position;
}

/* Shell lexical processing removes an unquoted backslash-newline before it
 * recognizes the token which follows.  Keep that logical lookahead separate
 * from span handling: every caller still reports and stores offsets in the
 * original, zero-copy source buffer. */
static inline size_t shell_source_logical_following(const char *input,
                                                    size_t length,
                                                    size_t position) {
  if (!input || position >= length)
    return length;
  return shell_source_skip_escaped_line_endings(input, length, position + 1);
}

static inline bool shell_source_logical_next_is(const char *input,
                                                size_t length, size_t position,
                                                char expected, size_t *next) {
  size_t logical = shell_source_logical_following(input, length, position);
  if (next)
    *next = logical;
  return logical < length && input[logical] == expected;
}

/* Match punctuation after the shell has removed unquoted escaped physical line
 * endings.  `spelling` is an operator spelling (rather than a shell word), so
 * no horizontal whitespace or comment may intervene.  On success `after`
 * names the first raw byte after the final punctuation byte; the returned
 * span therefore still includes every removed continuation for zero-copy
 * tokens, diagnostics, and graph source ranges.  Keep operator recognition
 * here rather than open-coding `position + 1` throughout the parser: Bash
 * recognizes `|\\\n&`, `&\\\n>`, and `>\\\n&` as `|&`, `&>`, and `>&`.
 */
static inline bool shell_source_match_logical_punctuation(const char *input,
                                                          size_t length,
                                                          size_t position,
                                                          const char *spelling,
                                                          size_t *after) {
  if (after)
    *after = position;
  if (!input || !spelling || spelling[0] == '\0' || position >= length)
    return false;
  size_t cursor = position;
  for (size_t index = 0; spelling[index] != '\0'; index++) {
    if (cursor >= length || input[cursor] != spelling[index])
      return false;
    if (spelling[index + 1] == '\0') {
      cursor++;
      break;
    }
    cursor = shell_source_logical_following(input, length, cursor);
  }
  if (after)
    *after = cursor;
  return true;
}

/* These predicates describe source-level openers, not complete constructs.
 * The matching scanners below remain responsible for balanced validation. */
static inline bool shell_source_dollar_parentheses_open(const char *input,
                                                        size_t length,
                                                        size_t position,
                                                        size_t *open) {
  if (!input || position >= length || input[position] != '$')
    return false;
  return shell_source_logical_next_is(input, length, position, '(', open);
}

static inline bool shell_source_dollar_arithmetic_open(const char *input,
                                                       size_t length,
                                                       size_t position,
                                                       size_t *open) {
  size_t first = 0;
  if (!shell_source_dollar_parentheses_open(input, length, position, &first))
    return false;
  return shell_source_logical_next_is(input, length, first, '(', open);
}

static inline bool shell_source_process_substitution_open(const char *input,
                                                          size_t length,
                                                          size_t position,
                                                          size_t *open) {
  if (!input || position >= length ||
      (input[position] != '<' && input[position] != '>'))
    return false;
  return shell_source_logical_next_is(input, length, position, '(', open);
}

/* Parse the scalar assignment-word prefix after shell lexical removal of
 * escaped physical line endings. This deliberately recognizes only the
 * identifier forms that can prefix an ordinary assignment: `name=value` and
 * `name+=value`. The returned positions retain the original source spelling
 * so callers can keep zero-copy views without reconstructing the word. */
typedef struct {
  size_t name_end;
  size_t equals;
  bool append;
} shell_source_assignment_word_t;

static inline bool
shell_source_parse_scalar_assignment_word(const char *input, size_t length,
                                          shell_source_assignment_word_t *out) {
  if (out)
    *out = (shell_source_assignment_word_t){0};
  if (!input || !out || length < 2)
    return false;

  size_t position = 0;
  size_t identifier_length = 0;
  while (position < length) {
    size_t next =
        shell_source_skip_escaped_line_endings(input, length, position);
    if (next != position) {
      position = next;
      continue;
    }

    unsigned char byte = (unsigned char)input[position];
    if (byte == '=') {
      if (identifier_length == 0)
        return false;
      out->name_end = position;
      out->equals = position;
      return true;
    }
    if (byte == '+' && identifier_length != 0) {
      size_t equals =
          shell_source_skip_escaped_line_endings(input, length, position + 1);
      if (equals < length && input[equals] == '=') {
        out->name_end = position;
        out->equals = equals;
        out->append = true;
        return true;
      }
      return false;
    }
    if (identifier_length == 0 ? !(isalpha(byte) || byte == '_')
                               : !(isalnum(byte) || byte == '_'))
      return false;
    identifier_length++;
    position++;
  }
  return false;
}

/* Move backward across list-connector trivia while locating the preceding
 * connector. Callers never use this to skip arbitrary command text. */
static inline size_t shell_source_skip_list_trivia_backward(const char *input,
                                                            size_t length,
                                                            size_t position) {
  if (!input || position > length)
    return 0;

  for (;;) {
    /* Remove horizontal space and physical line endings. A backslash directly
     * before an LF or CRLF is a shell line continuation, so remove that pair
     * together. Do not consume a backslash separated from the line ending by
     * whitespace: it is part of a shell word. */
    while (position > 0) {
      char previous = input[position - 1];
      if (previous == '\n') {
        position--;
        if (position > 0 && input[position - 1] == '\r')
          position--;
        if (position > 0 && input[position - 1] == '\\')
          position--;
        continue;
      }
      if (previous == '\r') {
        position--;
        if (position > 0 && input[position - 1] == '\\')
          position--;
        continue;
      }
      if (!isspace((unsigned char)previous))
        break;
      position--;
    }

    /* If the preceding physical line contains a shell comment, discard the
     * comment suffix and repeat so runs of comments and blank lines are
     * handled together. Track quotes while finding `#`: the boundary helper
     * alone intentionally cannot distinguish a hash in quoted word text. */
    size_t line_start = position;
    while (line_start > 0 && input[line_start - 1] != '\n' &&
           input[line_start - 1] != '\r')
      line_start--;
    bool in_single = false;
    bool in_double = false;
    bool found_comment = false;
    for (size_t cursor = line_start; cursor < position; cursor++) {
      char current = input[cursor];
      if (current == '\\' && !in_single && cursor + 1 < position) {
        cursor++;
        continue;
      }
      if (current == '\'' && !in_double) {
        in_single = !in_single;
        continue;
      }
      if (current == '"' && !in_single) {
        in_double = !in_double;
        continue;
      }
      if (!in_single && !in_double && current == '#' &&
          shell_source_comment_starts(input, length, cursor)) {
        position = cursor;
        found_comment = true;
        break;
      }
    }
    if (found_comment)
      continue;
    return position;
  }
}

/* Skip one quoted shell fragment, including its opening delimiter. The
 * lexical helpers below deliberately tolerate an unterminated quote: callers
 * that require a complete command validate that separately. */
static inline bool shell_source_skip_complete_double_quote(const char *input,
                                                           size_t length,
                                                           size_t position,
                                                           size_t *after);
static inline bool shell_source_skip_complete_quoted_text(const char *input,
                                                          size_t length,
                                                          size_t position,
                                                          char quote,
                                                          size_t *after);

static inline size_t shell_source_skip_quoted_text(const char *input,
                                                   size_t length,
                                                   size_t position,
                                                   char quote) {
  size_t after = 0;
  return shell_source_skip_complete_quoted_text(input, length, position, quote,
                                                &after)
             ? after
             : length;
}

/* Locate the closing delimiter of one legacy command substitution. A
 * backslash-escaped backtick is content, not the closing delimiter. */
static inline bool shell_source_skip_complete_backtick(const char *input,
                                                       size_t length,
                                                       size_t position,
                                                       size_t *after) {
  if (!input || !after || position >= length || input[position] != '`')
    return false;
  for (size_t cursor = position + 1; cursor < length; cursor++) {
    if (input[cursor] == '\\' && cursor + 1 < length) {
      cursor++;
      continue;
    }
    if (input[cursor] == '`') {
      *after = cursor + 1;
      return true;
    }
  }
  return false;
}

/* Bash ANSI-C quotes are one word fragment. Completion is determined by an
 * unescaped delimiter, never by inspecting the last source byte: `$'x\'`
 * ends in an apostrophe but has no closing quote. */
static inline bool shell_source_skip_complete_ansi_c_quote(const char *input,
                                                           size_t length,
                                                           size_t position,
                                                           size_t *after) {
  size_t quote = 0;
  if (!input || !after || position >= length || input[position] != '$' ||
      !shell_source_logical_next_is(input, length, position, '\'', &quote))
    return false;
  position = quote + 1;
  while (position < length) {
    if (input[position] == '\\' && position + 1 < length) {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (continued != position) {
        position = continued;
        continue;
      }
      position += 2;
    } else if (input[position++] == '\'') {
      *after = position;
      return true;
    }
  }
  return false;
}

/* Permissive lexical callers retain an incomplete fragment through EOF. */
static inline size_t shell_source_skip_ansi_c_quote(const char *input,
                                                    size_t length,
                                                    size_t position) {
  size_t after = 0;
  if (shell_source_skip_complete_ansi_c_quote(input, length, position, &after))
    return after;
  return input && position < length && input[position] == '$' &&
                 shell_source_logical_next_is(input, length, position, '\'',
                                              NULL)
             ? length
             : position;
}

/* Decode one complete Bash ANSI-C quote through a byte visitor. This is shared
 * by canonical argv rendering and heredoc delimiter matching so both paths
 * retain identical escape semantics. A false visitor result aborts decoding;
 * callers that need to distinguish output failure from malformed source keep
 * that detail in their visitor context. */
typedef bool (*shell_source_byte_visitor_t)(unsigned char byte, void *context);

static inline int shell_source_ansi_hex_value(char value) {
  if (value >= '0' && value <= '9')
    return value - '0';
  if (value >= 'a' && value <= 'f')
    return value - 'a' + 10;
  if (value >= 'A' && value <= 'F')
    return value - 'A' + 10;
  return -1;
}

static inline bool shell_source_ansi_emit(shell_source_byte_visitor_t visitor,
                                          void *context, unsigned char byte) {
  return !visitor || visitor(byte, context);
}

static inline bool
shell_source_ansi_emit_codepoint(shell_source_byte_visitor_t visitor,
                                 void *context, uint32_t value) {
  /* Bash retains its historical UTF-8 byte forms for ANSI-C code points.
   * Values above INT32_MAX expand to no bytes. */
  if (value > INT32_MAX)
    return true;
  if (value <= 0x7f)
    return shell_source_ansi_emit(visitor, context, (unsigned char)value);
  unsigned char encoded[6];
  size_t count = value <= 0x7ff       ? 2
                 : value <= 0xffff    ? 3
                 : value <= 0x1fffff  ? 4
                 : value <= 0x3ffffff ? 5
                                      : 6;
  for (size_t i = count; i-- > 1;) {
    encoded[i] = (unsigned char)(0x80 | (value & 0x3f));
    value >>= 6;
  }
  encoded[0] = (unsigned char)((count == 2   ? 0xc0
                                : count == 3 ? 0xe0
                                : count == 4 ? 0xf0
                                : count == 5 ? 0xf8
                                             : 0xfc) |
                               value);
  for (size_t i = 0; i < count; i++)
    if (!shell_source_ansi_emit(visitor, context, encoded[i]))
      return false;
  return true;
}

/* `position` starts at '$' and is advanced past the closing quote. */
static inline bool shell_source_decode_ansi_c_quote(
    const char *text, size_t length, size_t *position,
    shell_source_byte_visitor_t visitor, void *context) {
  if (!text || !position || *position >= length || text[*position] != '$')
    return false;
  size_t quote = shell_source_logical_following(text, length, *position);
  if (quote >= length || text[quote] != '\'')
    return false;
  *position = quote + 1;
  while (*position < length) {
    unsigned char value = (unsigned char)text[(*position)++];
    if (value == '\'')
      return true;
    if (value != '\\') {
      if (!shell_source_ansi_emit(visitor, context, value))
        return false;
      continue;
    }
    if (*position == length)
      return false;
    char escape = text[(*position)++];
    unsigned char decoded = 0;
    switch (escape) {
    case 'a':
      decoded = '\a';
      break;
    case 'b':
      decoded = '\b';
      break;
    case 'e':
    case 'E':
      decoded = 0x1b;
      break;
    case 'f':
      decoded = '\f';
      break;
    case 'n':
      decoded = '\n';
      break;
    case 'r':
      decoded = '\r';
      break;
    case 't':
      decoded = '\t';
      break;
    case 'v':
      decoded = '\v';
      break;
    case '\\':
    case '\'':
    case '"':
    case '?':
      decoded = (unsigned char)escape;
      break;
    case 'c':
      if (*position == length || text[*position] == '\'') {
        if (!shell_source_ansi_emit(visitor, context, (unsigned char)'\\'))
          return false;
        decoded = 'c';
      } else {
        decoded = (unsigned char)text[(*position)++];
        decoded = decoded == '?' ? 0x7f : (unsigned char)(decoded & 0x1f);
      }
      break;
    case 'x': {
      int digit = *position < length
                      ? shell_source_ansi_hex_value(text[*position])
                      : -1;
      if (digit < 0) {
        if (!shell_source_ansi_emit(visitor, context, (unsigned char)'\\'))
          return false;
        decoded = 'x';
        break;
      }
      unsigned value = 0;
      for (size_t digits = 0; digits < 2 && digit >= 0; digits++) {
        value = (value << 4) | (unsigned)digit;
        (*position)++;
        digit = *position < length
                    ? shell_source_ansi_hex_value(text[*position])
                    : -1;
      }
      decoded = (unsigned char)value;
      break;
    }
    case 'u':
    case 'U': {
      size_t digits = escape == 'u' ? 4 : 8;
      uint32_t codepoint = 0;
      size_t consumed = 0;
      while (consumed < digits && *position + consumed < length) {
        int digit = shell_source_ansi_hex_value(text[*position + consumed]);
        if (digit < 0)
          break;
        codepoint = (codepoint << 4) | (uint32_t)digit;
        consumed++;
      }
      if (consumed == 0) {
        if (!shell_source_ansi_emit(visitor, context, (unsigned char)'\\'))
          return false;
        decoded = (unsigned char)escape;
      } else {
        *position += consumed;
        if (!shell_source_ansi_emit_codepoint(visitor, context, codepoint))
          return false;
        continue;
      }
      break;
    }
    default:
      if (escape >= '0' && escape <= '7') {
        unsigned value = (unsigned)(escape - '0');
        for (size_t i = 0; i < 2 && *position < length &&
                           text[*position] >= '0' && text[*position] <= '7';
             i++)
          value = (value << 3) | (unsigned)(text[(*position)++] - '0');
        decoded = (unsigned char)value;
      } else {
        if (!shell_source_ansi_emit(visitor, context, (unsigned char)'\\'))
          return false;
        decoded = (unsigned char)escape;
      }
      break;
    }
    if (!shell_source_ansi_emit(visitor, context, decoded))
      return false;
  }
  return false;
}

static inline bool shell_source_find_ansi_c_nul(unsigned char byte,
                                                void *context) {
  if (byte == '\0')
    *(bool *)context = true;
  return true;
}

/* Complete-command semantics cannot treat an ANSI-C NUL as ordinary argv:
 * Bash discards the rest of that quoted segment before executing the word.
 * Keep the byte-faithful decoder available to standalone and binary callers;
 * this probe lets semantic consumers reject the ambiguous source spelling. */
static inline bool shell_source_ansi_c_quote_has_nul(const char *text,
                                                     size_t length,
                                                     size_t *position,
                                                     bool *has_nul) {
  if (!has_nul)
    return false;
  *has_nul = false;
  return shell_source_decode_ansi_c_quote(
      text, length, position, shell_source_find_ansi_c_nul, has_nul);
}

/* Heredoc delimiters do quote removal but do not expand parameter-like text.
 * Inspect only active ANSI-C quotes, not literal dollars in other quotes. */
static inline bool shell_source_heredoc_word_has_ansi_c_nul(const char *word,
                                                            size_t length) {
  if (!word)
    return false;
  char quote = '\0';
  for (size_t position = 0; position < length; position++) {
    char c = word[position];
    if (quote == '\0' && c == '$' &&
        shell_source_logical_next_is(word, length, position, '\'', NULL)) {
      bool has_nul = false;
      size_t after = position;
      if (!shell_source_ansi_c_quote_has_nul(word, length, &after, &has_nul))
        return false;
      if (has_nul)
        return true;
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
    if (c == '\\' && quote != '\'' && position + 1 < length) {
      char next = word[position + 1];
      if (quote == '\0' || next == '$' || next == '`' || next == '"' ||
          next == '\\' || next == '\n' || next == '\r') {
        position++;
        if (next == '\r' && position + 1 < length && word[position + 1] == '\n')
          position++;
      }
    }
  }
  return false;
}

/* Only raw, contiguous source bytes may become executable graph nodes. Bash
 * decodes ANSI-C escapes before expanding a double-quoted parameter word, so
 * an escape in a substitution body changes the command that actually runs.
 * The graph deliberately borrows the original source: reject such words
 * rather than giving a decoded command a misleading raw-source span. */
static inline bool shell_source_ansi_expansion_metabyte(unsigned value) {
  return value == '$' || value == '\\' || value == '`' || value == '<' ||
         value == '>' || value == '(' || value == ')' || value == '{' ||
         value == '}' || value == '\'' || value == '"';
}

static inline bool shell_source_ansi_quote_has_encoded_syntax(const char *text,
                                                              size_t start,
                                                              size_t after,
                                                              bool isolated) {
  if (!text || after < start + 3)
    return false;
  bool has_raw_substitution = false;
  size_t raw_double_quotes = 0;
  for (size_t i = start + 2; i + 1 < after; i++)
    if (text[i] == '"') {
      raw_double_quotes++;
    } else {
      has_raw_substitution |=
          text[i] == '`' ||
          (text[i] == '$' &&
           shell_source_logical_next_is(text, after - 1, i, '(', NULL));
    }
  if (raw_double_quotes % 2 != 0)
    return true;
  for (size_t position = start + 2; position + 1 < after;) {
    if (text[position] != '\\') {
      position++;
      continue;
    }
    size_t escape_start = position;
    size_t slashes = position;
    while (slashes + 1 < after && text[slashes] == '\\')
      slashes++;
    /* Bash pairs backticks while parsing the ANSI-C word. Two or more
     * backslashes before a raw backtick can make that pairing ambiguous
     * across the later parameter-word expansion. */
    if (slashes - position >= 2 && slashes + 1 < after && text[slashes] == '`')
      return true;
    bool before_raw_opener =
        slashes + 1 < after &&
        (text[slashes] == '`' ||
         (text[slashes] == '$' &&
          shell_source_logical_next_is(text, after - 1, slashes, '(', NULL)));
    if (has_raw_substitution && !before_raw_opener)
      return true;
    position++;
    if (position + 1 >= after)
      break;
    unsigned value = 0;
    char escape = text[position++];
    if (escape == '\'' || escape == '"' ||
        (escape == '\\' && !before_raw_opener))
      return true;
    if (escape == 'x' || escape == 'u' || escape == 'U') {
      size_t limit = escape == 'x' ? 2 : escape == 'u' ? 4 : 8;
      size_t digits = 0;
      while (digits < limit && position + 1 < after) {
        int digit = shell_source_ansi_hex_value(text[position]);
        if (digit < 0)
          break;
        value = (value << 4) | (unsigned)digit;
        position++;
        digits++;
      }
      bool literal_byte = value == '$' || value == '<' || value == '>' ||
                          value == '(' || value == ')';
      if (digits && shell_source_ansi_expansion_metabyte(value) &&
          !(isolated && escape_start == start + 2 && position == after - 1 &&
            literal_byte))
        return true;
    } else if (escape >= '0' && escape <= '7') {
      value = (unsigned)(escape - '0');
      for (size_t digits = 0; digits < 2 && position + 1 < after &&
                              text[position] >= '0' && text[position] <= '7';
           digits++)
        value = (value << 3) | (unsigned)(text[position++] - '0');
      bool literal_byte = value == '$' || value == '<' || value == '>' ||
                          value == '(' || value == ')';
      if (shell_source_ansi_expansion_metabyte(value) &&
          !(isolated && escape_start == start + 2 && position == after - 1 &&
            literal_byte))
        return true;
    }
  }
  return false;
}

typedef struct {
  const char *word;
  size_t word_length;
  bool strip_tabs;
} shell_source_pending_heredoc_t;

/* Read the delimiter word after a `<<` or `<<-` operator. Here-document
 * delimiter processing applies quote removal only: parameter-like bytes stay
 * literal. Retain the original word and decode it while comparing physical
 * lines, so mixed quotes and backslash-quoted delimiters remain zero-copy. */
static inline bool
shell_source_parse_heredoc_delimiter(const char *input, size_t length,
                                     size_t *position,
                                     shell_source_pending_heredoc_t *pending) {
  size_t cursor =
      shell_source_skip_escaped_line_endings(input, length, *position);
  pending->strip_tabs = false;
  if (cursor < length && input[cursor] == '-') {
    pending->strip_tabs = true;
    cursor++;
  }
  while (cursor < length && (input[cursor] == ' ' || input[cursor] == '\t'))
    cursor++;
  if (cursor == length)
    return false;
  /* The delimiter is a shell word. A raw hash at its start therefore begins a
   * comment, including the `<<-#comment` spelling where the immediately
   * preceding byte is the heredoc operator's optional dash. Quoted and
   * backslash-escaped hashes remain ordinary delimiter bytes below. */
  if (input[cursor] == '#')
    return false;

  size_t start = cursor;
  char quote = '\0';
  while (cursor < length) {
    char c = input[cursor];
    if (quote != '\0') {
      if (c == quote) {
        quote = '\0';
        cursor++;
        continue;
      }
      if (c == '\\' && quote == '"' && cursor + 1 < length &&
          (input[cursor + 1] == '$' || input[cursor + 1] == '`' ||
           input[cursor + 1] == '"' || input[cursor + 1] == '\\' ||
           input[cursor + 1] == '\n' || input[cursor + 1] == '\r')) {
        size_t continued =
            shell_source_skip_escaped_line_endings(input, length, cursor);
        cursor = continued != cursor ? continued : cursor + 2;
      } else {
        cursor++;
      }
      continue;
    }
    if (c == '\\') {
      if (cursor + 1 >= length)
        return false;
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, cursor);
      cursor = continued != cursor ? continued : cursor + 2;
      continue;
    }
    if (c == '$' &&
        shell_source_logical_next_is(input, length, cursor, '\'', NULL)) {
      size_t after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, cursor,
                                                   &after))
        return false;
      cursor = after;
      continue;
    }
    if (c == '\'' || c == '"') {
      quote = c;
      cursor++;
      continue;
    }
    if (isspace((unsigned char)c) || c == ';' || c == '&' || c == '|' ||
        c == '<' || c == '>' || c == '(' || c == ')')
      break;
    cursor++;
  }
  /* A shell word is required, but quote removal may legitimately produce an
   * empty delimiter: `<<''` and `<<""` terminate on a blank physical line. */
  if (cursor == start || quote != '\0')
    return false;
  pending->word = input + start;
  pending->word_length = cursor - start;
  *position = cursor;
  return true;
}

typedef struct {
  const char *input;
  size_t text;
  size_t end;
  bool mismatch;
  bool terminated;
} shell_source_heredoc_match_t;

static inline bool shell_source_match_heredoc_byte(unsigned char byte,
                                                   void *context) {
  shell_source_heredoc_match_t *match = context;
  /* Bash truncates one ANSI-C quoted segment at its first decoded NUL. The
   * matcher resets this flag before resuming with later word fragments. */
  if (match->terminated || match->mismatch)
    return true;
  if (byte == '\0') {
    match->terminated = true;
    return true;
  }
  if (match->text == match->end || match->input[match->text] != (char)byte) {
    match->mismatch = true;
    return true;
  }
  match->text++;
  return true;
}

static inline bool shell_source_line_is_heredoc_delimiter(
    const char *input, size_t length, size_t line,
    const shell_source_pending_heredoc_t *pending) {
  if (!input || !pending || !pending->word)
    return false;
  size_t text = line;
  if (pending->strip_tabs)
    while (text < length && input[text] == '\t')
      text++;
  shell_source_heredoc_match_t match = {
      .input = input,
      .text = text,
      .end = shell_source_line_content_end(input, length, text),
  };
  char quote = '\0';
  for (size_t word = 0; word < pending->word_length;) {
    char c = pending->word[word++];
    if (quote == '\0' && c == '$' &&
        shell_source_logical_next_is(pending->word, pending->word_length,
                                     word - 1, '\'', NULL)) {
      size_t position = word - 1;
      if (!shell_source_decode_ansi_c_quote(
              pending->word, pending->word_length, &position,
              shell_source_match_heredoc_byte, &match))
        return false;
      match.terminated = false;
      word = position;
      continue;
    }
    if (quote != '\0') {
      if (c == quote) {
        quote = '\0';
        continue;
      }
      if (c == '\\' && quote == '"' && word < pending->word_length) {
        size_t continued = shell_source_skip_escaped_line_endings(
            pending->word, pending->word_length, word - 1);
        if (continued != word - 1) {
          word = continued;
          continue;
        }
        if (pending->word[word] == '$' || pending->word[word] == '`' ||
            pending->word[word] == '"' || pending->word[word] == '\\')
          c = pending->word[word++];
      }
    } else if (c == '\'' || c == '"') {
      quote = c;
      continue;
    } else if (c == '\\') {
      size_t continued = shell_source_skip_escaped_line_endings(
          pending->word, pending->word_length, word - 1);
      if (continued != word - 1) {
        word = continued;
        continue;
      }
      if (word == pending->word_length)
        return false;
      c = pending->word[word++];
    }
    if (!shell_source_match_heredoc_byte((unsigned char)c, &match))
      return false;
  }
  return quote == '\0' && !match.mismatch && match.text == match.end;
}

/* A quoted delimiter disables expansion of its document body. The parser
 * retains the raw word span for zero-copy matching, so derive that flag from
 * the syntax that quote removal will process. */
static inline bool shell_source_heredoc_delimiter_is_quoted(
    const shell_source_pending_heredoc_t *pending) {
  if (!pending)
    return false;
  for (size_t i = 0; i < pending->word_length; i++) {
    char c = pending->word[i];
    if (c == '\\' || c == '\'' || c == '"')
      return true;
  }
  return false;
}

static inline bool shell_source_find_balanced_parentheses(const char *input,
                                                          size_t length,
                                                          size_t position,
                                                          size_t *after);
static inline bool shell_source_skip_arithmetic_expansion(const char *input,
                                                          size_t length,
                                                          size_t position,
                                                          size_t *after);
static inline bool
shell_source_skip_arithmetic_expansion_depth(const char *input, size_t length,
                                             size_t position, size_t *after,
                                             size_t nesting);

/* Visit one physical body for every FIFO declaration on a shared heredoc
 * line. `body_start` and `body_length` preserve source bytes exactly: a
 * <<- body still includes its leading tabs, because callers may need to apply
 * their own shell-semantic processing before rendering its logical content.
 * The delimiter line itself is excluded. A quoted delimiter makes that body
 * literal. Returning false from the visitor stops pending-body traversal;
 * callers that need to distinguish that from a missing terminator retain the
 * distinction in their visitor context. */
typedef bool (*shell_source_heredoc_body_visitor_t)(const char *input,
                                                    size_t body_start,
                                                    size_t body_length,
                                                    bool delimiter_quoted,
                                                    void *context);

/* Consume the bodies for a FIFO sequence of declarations after their shared
 * declaration line. A missing terminator is reported separately from the
 * sentinel end position so tolerant lexical callers can still treat the
 * remainder as document data, while strict parsers reject it. */
static inline bool shell_source_visit_pending_heredoc_bodies(
    const char *input, size_t length, size_t line,
    const shell_source_pending_heredoc_t *pending, size_t pending_count,
    shell_source_heredoc_body_visitor_t visitor, void *context, size_t *after) {
  if (!input || !pending || !after)
    return false;
  for (size_t h = 0; h < pending_count; h++) {
    size_t body_start = line;
    bool found = false;
    while (line < length) {
      if (shell_source_line_is_heredoc_delimiter(input, length, line,
                                                 &pending[h])) {
        size_t body_length = line - body_start;
        if (visitor &&
            !visitor(input, body_start, body_length,
                     shell_source_heredoc_delimiter_is_quoted(&pending[h]),
                     context))
          return false;
        line = shell_source_next_line(input, length, line);
        found = true;
        break;
      }
      size_t next = shell_source_next_line(input, length, line);
      if (next <= line)
        break;
      line = next;
    }
    if (!found) {
      *after = length;
      return false;
    }
  }
  *after = line;
  return true;
}

static inline bool shell_source_skip_pending_heredoc_bodies(
    const char *input, size_t length, size_t line,
    const shell_source_pending_heredoc_t *pending, size_t pending_count,
    size_t *after) {
  return shell_source_visit_pending_heredoc_bodies(
      input, length, line, pending, pending_count, NULL, NULL, after);
}

/* Skip every pending document declared on one physical line beginning at a
 * here-document operator. The declaration scanner keeps quoted and nested
 * substitutions opaque, then hands the FIFO body matching to the shared
 * routine above. It is deliberately a lexical helper: callers choose whether
 * an unterminated document is tolerated or rejected. */
static inline bool shell_source_visit_heredoc_sequence(
    const char *input, size_t length, size_t position,
    shell_source_heredoc_body_visitor_t visitor, void *context, size_t *after,
    bool *complete) {
  if (!input || !after || !complete ||
      !shell_source_match_logical_punctuation(input, length, position, "<<",
                                              NULL) ||
      shell_source_match_logical_punctuation(input, length, position, "<<<",
                                             NULL))
    return false;

  shell_source_pending_heredoc_t pending[SHELL_SOURCE_MAX_PENDING_HEREDOCS];
  size_t pending_count = 0;
  /* The declaration line may contain physical continuations. Scan until the
   * first newline that survives lexical continuation removal instead of the
   * first raw line ending, otherwise `<<\\\nEOF` never reaches its delimiter.
   */
  size_t line_end = length;
  size_t cursor = position;
  while (cursor < length) {
    char c = input[cursor];
    if (c == '\\' && cursor + 1 < length) {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, cursor);
      if (continued != cursor) {
        cursor = continued;
        continue;
      }
      cursor += 2;
      continue;
    }
    if (c == '$' &&
        shell_source_logical_next_is(input, length, cursor, '\'', NULL)) {
      size_t quoted = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, cursor,
                                                   &quoted))
        return false;
      cursor = quoted;
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      size_t quoted = shell_source_skip_quoted_text(input, length, cursor, c);
      if (quoted > length)
        return false;
      cursor = quoted;
      continue;
    }
    if (c == '#' && shell_source_comment_starts(input, length, cursor)) {
      line_end = shell_source_line_end(input, length, cursor);
      break;
    }
    if (c == '$' &&
        shell_source_dollar_arithmetic_open(input, length, cursor, NULL)) {
      size_t after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, cursor,
                                                  &after))
        return false;
      cursor = after;
      continue;
    }
    size_t substitution_open = 0;
    if ((c == '$' && shell_source_dollar_parentheses_open(
                         input, length, cursor, &substitution_open)) ||
        ((c == '<' || c == '>') &&
         shell_source_process_substitution_open(input, length, cursor,
                                                &substitution_open))) {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(input, length,
                                                  substitution_open, &after))
        return false;
      cursor = after;
      continue;
    }
    size_t operator_after = 0;
    if (c == '<' && shell_source_match_logical_punctuation(
                        input, length, cursor, "<<<", &operator_after)) {
      cursor = operator_after;
      continue;
    }
    if (c == '<' && shell_source_match_logical_punctuation(
                        input, length, cursor, "<<", &operator_after)) {
      if (pending_count == sizeof(pending) / sizeof(pending[0]))
        return false;
      size_t delimiter = operator_after;
      if (!shell_source_parse_heredoc_delimiter(input, length, &delimiter,
                                                &pending[pending_count]))
        return false;
      pending_count++;
      cursor = delimiter;
      continue;
    }
    if (c == '\n' || c == '\r') {
      line_end = cursor;
      break;
    }
    cursor++;
  }

  if (pending_count == 0)
    return false;
  size_t bodies = shell_source_next_line(input, length, line_end);
  *complete = shell_source_visit_pending_heredoc_bodies(
      input, length, bodies, pending, pending_count, visitor, context, after);
  return true;
}

static inline bool shell_source_skip_heredoc_sequence(const char *input,
                                                      size_t length,
                                                      size_t position,
                                                      size_t *after,
                                                      bool *complete) {
  return shell_source_visit_heredoc_sequence(input, length, position, NULL,
                                             NULL, after, complete);
}

/* Skip one arithmetic expansion at its leading `$`.  Arithmetic syntax uses
 * `<<` as an ordinary shift operator, so callers that are looking for shell
 * redirections must keep the complete `$((...))` opaque. Nested command and
 * arithmetic substitutions remain independently balanced. */
static inline bool shell_source_skip_arithmetic_expansion(const char *input,
                                                          size_t length,
                                                          size_t position,
                                                          size_t *after) {
  return shell_source_skip_arithmetic_expansion_depth(input, length, position,
                                                      after, 1);
}

static inline bool shell_source_skip_arithmetic_expansion_depth_impl(
    const char *input, size_t length, size_t position, size_t *after,
    size_t nesting) {
  size_t open = 0;
  if (!input || !after || nesting > SHELL_SOURCE_MAX_ARITHMETIC_NESTING ||
      !shell_source_dollar_arithmetic_open(input, length, position, &open))
    return false;

  size_t depth = 1;
  for (position = open + 1; position < length; position++) {
    char c = input[position];
    if (c == '\\' && position + 1 < length) {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (continued != position) {
        position = continued - 1;
        continue;
      }
      position++;
    } else if (c == '$' && shell_source_logical_next_is(input, length, position,
                                                        '\'', NULL)) {
      size_t quoted = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &quoted))
        return false;
      position = quoted - 1;
    } else if (c == '\'' || c == '"' || c == '`') {
      size_t quoted = 0;
      if (!shell_source_skip_complete_quoted_text(input, length, position, c,
                                                  &quoted))
        return false;
      position = quoted - 1;
    } else if (c == '$' && shell_source_dollar_arithmetic_open(
                               input, length, position, NULL)) {
      size_t nested_after = 0;
      if (!shell_source_skip_arithmetic_expansion_depth(
              input, length, position, &nested_after, nesting + 1))
        return false;
      position = nested_after - 1;
    } else if (c == '$') {
      size_t nested_open = 0;
      if (!shell_source_dollar_parentheses_open(input, length, position,
                                                &nested_open))
        continue;
      size_t nested_after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, nested_open,
                                                  &nested_after))
        return false;
      position = nested_after - 1;
    } else if (c == '(') {
      depth++;
    } else if (c == ')') {
      if (depth > 1) {
        depth--;
      } else {
        size_t close = shell_source_logical_following(input, length, position);
        if (close >= length || input[close] != ')')
          return false;
        *after = close + 1;
        return true;
      }
    }
  }
  return false;
}

static inline bool
shell_source_skip_arithmetic_expansion_depth(const char *input, size_t length,
                                             size_t position, size_t *after,
                                             size_t nesting) {
  if (!shell_source_scan_enter())
    return false;
  bool complete = shell_source_skip_arithmetic_expansion_depth_impl(
      input, length, position, after, nesting);
  shell_source_scan_leave();
  return complete;
}

/* Skip one statically numeric Bash arithmetic literal after lexical
 * continuation removal. This is deliberately shared by semantic validation and
 * fast feature classification: a base literal must not turn its digit letters
 * into identifiers in only one of those paths.
 *
 * Bash accepts decimal, legacy-octal, hexadecimal, and `base#digits` integer
 * constants. The latter has bases 2 through 64; for bases up to 36 upper and
 * lower case letters are equivalent, while bases above 36 use lower case,
 * upper case, `@`, and `_` as distinct digits. Invalid spellings are not
 * partially accepted as a shorter number, because their caller must reject
 * rather than reinterpret them as dynamic arithmetic source. */
static inline bool shell_source_skip_arithmetic_number(const char *input,
                                                       size_t length,
                                                       size_t position,
                                                       size_t *after) {
  if (!input || !after)
    return false;

  position = shell_source_skip_escaped_line_endings(input, length, position);
  if (position >= length || !isdigit((unsigned char)input[position]))
    return false;

  unsigned char first = (unsigned char)input[position++];

  /* Hexadecimal has priority over the leading-zero legacy-octal spelling. */
  if (first == '0') {
    size_t prefix =
        shell_source_skip_escaped_line_endings(input, length, position);
    if (prefix < length && (input[prefix] == 'x' || input[prefix] == 'X')) {
      position = prefix + 1;
      size_t digits = 0;
      for (;;) {
        size_t next =
            shell_source_skip_escaped_line_endings(input, length, position);
        if (next >= length || !isxdigit((unsigned char)input[next]))
          break;
        position = next + 1;
        digits++;
      }
      if (digits == 0)
        return false;
      *after = position;
      return true;
    }
  }

  /* Scan the decimal prefix once. It may be a decimal/octal constant or the
   * base part of `base#digits`. Keep the base bounded while scanning, rather
   * than allowing a large source literal to overflow a host integer. */
  unsigned int base = first - (unsigned char)'0';
  bool base_too_large = false;
  bool legacy_octal = first == '0';
  for (;;) {
    size_t next =
        shell_source_skip_escaped_line_endings(input, length, position);
    if (next >= length || !isdigit((unsigned char)input[next]))
      break;
    unsigned char digit = (unsigned char)input[next] - (unsigned char)'0';
    if (legacy_octal && digit > 7)
      return false;
    if (base > 64 / 10 || (base == 64 / 10 && digit > 64 % 10))
      base_too_large = true;
    else if (!base_too_large)
      base = base * 10 + digit;
    position = next + 1;
  }

  size_t hash = shell_source_skip_escaped_line_endings(input, length, position);
  if (hash >= length || input[hash] != '#') {
    *after = position;
    return true;
  }
  if (base_too_large || base < 2 || base > 64)
    return false;

  position = hash + 1;
  size_t digits = 0;
  for (;;) {
    size_t next =
        shell_source_skip_escaped_line_endings(input, length, position);
    if (next >= length)
      break;
    unsigned char byte = (unsigned char)input[next];
    unsigned int value = 0;
    bool valid_digit = true;
    if (isdigit(byte))
      value = byte - (unsigned char)'0';
    else if (byte >= 'a' && byte <= 'z')
      value = 10u + byte - (unsigned char)'a';
    else if (byte >= 'A' && byte <= 'Z')
      value = base <= 36 ? 10u + byte - (unsigned char)'A'
                         : 36u + byte - (unsigned char)'A';
    else if (byte == '@')
      value = 62;
    else if (byte == '_')
      value = 63;
    else
      valid_digit = false;
    if (!valid_digit)
      break;
    if (value >= base)
      return false;
    position = next + 1;
    digits++;
  }
  if (digits == 0)
    return false;
  *after = position;
  return true;
}

/* Find the byte after a balanced shell fragment at an opening `(`. Quoting,
 * escapes, comments, nested substitutions, and deferred heredoc bodies remain
 * opaque while matching parentheses. Returns false for an unterminated or
 * malformed fragment; shell_source_skip_balanced_parentheses() maps that
 * failure to `length` for callers that need a sentinel position. */
static inline bool
shell_source_find_balanced_parentheses_impl(const char *input, size_t length,
                                            size_t position, size_t *after) {
  if (!input || !after || position >= length || input[position] != '(')
    return false;
  size_t depth = 1;
  shell_source_pending_heredoc_t pending[SHELL_SOURCE_MAX_PENDING_HEREDOCS];
  size_t pending_count = 0;
  for (position++; position < length && depth > 0; position++) {
    char c = input[position];
    if (c == '\\' && position + 1 < length) {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (continued != position) {
        position = continued - 1;
        continue;
      }
      position++;
    } else if (c == '$' && shell_source_logical_next_is(input, length, position,
                                                        '\'', NULL)) {
      size_t quoted = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &quoted))
        return false;
      position = quoted - 1;
    } else if (c == '\'' || c == '"') {
      size_t quoted = 0;
      if (!shell_source_skip_complete_quoted_text(input, length, position, c,
                                                  &quoted))
        return false;
      position = quoted - 1;
    } else if (c == '`') {
      size_t quoted = 0;
      if (!shell_source_skip_complete_backtick(input, length, position,
                                               &quoted))
        return false;
      position = quoted - 1;
    } else if (c == '#' &&
               shell_source_comment_starts(input, length, position)) {
      /* Leave a newline visible for deferred heredoc-body processing. */
      size_t line_end = shell_source_line_end(input, length, position);
      position = line_end == length ? length - 1 : line_end - 1;
    } else if (c == '$' && shell_source_dollar_arithmetic_open(
                               input, length, position, NULL)) {
      size_t arithmetic_after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &arithmetic_after))
        return false;
      position = arithmetic_after - 1;
    } else if (c == '<') {
      size_t operator_after = 0;
      if (shell_source_match_logical_punctuation(input, length, position, "<<<",
                                                 &operator_after)) {
        position = operator_after - 1;
      } else if (shell_source_match_logical_punctuation(
                     input, length, position, "<<", &operator_after)) {
        size_t delimiter_position = operator_after;
        if (pending_count == sizeof(pending) / sizeof(pending[0]) ||
            !shell_source_parse_heredoc_delimiter(
                input, length, &delimiter_position, &pending[pending_count]))
          return false;
        pending_count++;
        position = delimiter_position - 1;
      }
    } else if (c == '\n' && pending_count > 0) {
      size_t line = 0;
      if (!shell_source_skip_pending_heredoc_bodies(
              input, length, position + 1, pending, pending_count, &line))
        return false;
      pending_count = 0;
      position = line - 1;
    } else if (c == '(') {
      depth++;
    } else if (c == ')') {
      depth--;
    }
  }
  if (depth != 0)
    return false;
  *after = position;
  return true;
}

static inline bool shell_source_find_balanced_parentheses(const char *input,
                                                          size_t length,
                                                          size_t position,
                                                          size_t *after) {
  if (!shell_source_scan_enter())
    return false;
  bool complete = shell_source_find_balanced_parentheses_impl(input, length,
                                                              position, after);
  shell_source_scan_leave();
  return complete;
}

static inline size_t shell_source_skip_balanced_parentheses(const char *input,
                                                            size_t length,
                                                            size_t position) {
  size_t after = length;
  (void)shell_source_find_balanced_parentheses(input, length, position, &after);
  return after;
}

/* Skip an array subscript beginning at an opening `[`. Array expressions are
 * not evaluated by Shellsplit, but their structural delimiters must still be
 * recognized accurately so quoted or substituted `]` bytes cannot terminate
 * the surrounding parameter or assignment early. */
static inline bool shell_source_skip_array_subscript(const char *input,
                                                     size_t length,
                                                     size_t position,
                                                     size_t *after) {
  if (!input || !after || position >= length || input[position] != '[')
    return false;

  size_t depth = 1;
  for (position++; position < length; position++) {
    char c = input[position];
    if (c == '\\' && position + 1 < length) {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (continued != position) {
        position = continued - 1;
        continue;
      }
      position++;
    } else if (c == '$' && shell_source_logical_next_is(input, length, position,
                                                        '\'', NULL)) {
      size_t quoted = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &quoted))
        return false;
      position = quoted - 1;
    } else if (c == '\'' || c == '"' || c == '`') {
      size_t quoted = 0;
      if (!shell_source_skip_complete_quoted_text(input, length, position, c,
                                                  &quoted))
        return false;
      position = quoted - 1;
    } else if (c == '$' && shell_source_dollar_arithmetic_open(
                               input, length, position, NULL)) {
      size_t arithmetic_after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &arithmetic_after))
        return false;
      position = arithmetic_after - 1;
    } else if (c == '$') {
      size_t substitution_open = 0;
      if (!shell_source_dollar_parentheses_open(input, length, position,
                                                &substitution_open))
        continue;
      size_t substitution_after = 0;
      if (!shell_source_find_balanced_parentheses(
              input, length, substitution_open, &substitution_after))
        return false;
      position = substitution_after - 1;
    } else if (c == '[') {
      depth++;
    } else if (c == ']') {
      depth--;
      if (depth == 0) {
        *after = position + 1;
        return true;
      }
    }
  }
  return false;
}

/* Identify the array-only form of a braced parameter expansion.  A bracket
 * elsewhere in `${parameter-word}` is normally a pattern, not an array
 * subscript, so callers must not use a raw `[` search for this distinction. */
static inline bool
shell_source_find_parameter_array_subscript(const char *input, size_t length,
                                            size_t position, size_t *after,
                                            size_t *subscript_start) {
  if (!input || !after || !subscript_start || position >= length ||
      input[position] != '$')
    return false;

  *subscript_start = 0;
  size_t cursor = shell_source_logical_following(input, length, position);
  if (cursor >= length || input[cursor] != '{')
    return false;
  cursor = shell_source_logical_following(input, length, cursor);
  if (cursor < length && (input[cursor] == '#' || input[cursor] == '!'))
    cursor = shell_source_logical_following(input, length, cursor);
  if (cursor >= length ||
      !(isalpha((unsigned char)input[cursor]) || input[cursor] == '_'))
    return false;
  while (cursor < length) {
    cursor = shell_source_skip_escaped_line_endings(input, length, cursor);
    if (cursor >= length ||
        !(isalnum((unsigned char)input[cursor]) || input[cursor] == '_'))
      break;
    cursor++;
  }
  if (cursor >= length || input[cursor] != '[')
    return false;

  *subscript_start = cursor;
  return shell_source_skip_array_subscript(input, length, cursor, after);
}

/* A braced parameter starts with one parameter selector, not an arbitrary
 * shell word. Parse that selector before scanning an optional parameter word:
 * `${name:-${fallback}}` and `${name#x${suffix}}` are valid, whereas
 * `${name${suffix}}`, `${name$other}`, and `${name.other}` are not. This is
 * structural validation only; callers retain responsibility for rejecting
 * syntactically valid but unsupported array semantics. */
static inline bool shell_source_parameter_is_special(unsigned char c) {
  return c == '#' || c == '?' || c == '$' || c == '!' || c == '@' || c == '*' ||
         c == '-';
}

static inline bool shell_source_skip_parameter_base(const char *input,
                                                    size_t length,
                                                    size_t *position) {
  if (!input || !position || *position >= length)
    return false;

  size_t cursor =
      shell_source_skip_escaped_line_endings(input, length, *position);
  if (cursor >= length)
    return false;
  unsigned char c = (unsigned char)input[cursor];
  if (isalpha(c) || c == '_') {
    cursor++;
    while (cursor < length) {
      cursor = shell_source_skip_escaped_line_endings(input, length, cursor);
      if (cursor >= length)
        break;
      c = (unsigned char)input[cursor];
      if (!(isalnum(c) || c == '_'))
        break;
      cursor++;
    }
  } else if (isdigit(c)) {
    do {
      cursor++;
      cursor = shell_source_skip_escaped_line_endings(input, length, cursor);
    } while (cursor < length && isdigit((unsigned char)input[cursor]));
  } else if (shell_source_parameter_is_special(c)) {
    cursor++;
  } else {
    return false;
  }

  *position = cursor;
  return true;
}

/* Skip the parameter selector immediately after `${`.  `#` prefixes the
 * length form except where it is the special `$#` selector; `!` prefixes
 * indirection unless it is `${!}`. An array subscript is retained structurally
 * so the full tokenizer can subsequently reject unsupported array semantics
 * without misclassifying the enclosing expansion. */
static inline bool shell_source_skip_parameter_selector(const char *input,
                                                        size_t length,
                                                        size_t position,
                                                        size_t *after) {
  if (!input || !after || position >= length)
    return false;

  position = shell_source_skip_escaped_line_endings(input, length, position);
  if (position >= length)
    return false;
  bool indirect = false;
  if (input[position] == '#') {
    size_t next = shell_source_logical_following(input, length, position);
    if (next >= length)
      return false;
    if (input[next] == '}') {
      *after = next;
      return true;
    }
    /* `${##word}` means pattern removal from the special `$#`, not the
     * length of a parameter named `#word`. Leave the first `#` for the base
     * selector so the second one is recognized as its operator. */
    if (input[next] != '#')
      position = next;
  } else if (input[position] == '!') {
    position = shell_source_logical_following(input, length, position);
    if (position >= length)
      return false;
    if (input[position] == '}') {
      *after = position;
      return true;
    }
    indirect = true;
  }

  if (!shell_source_skip_parameter_base(input, length, &position))
    return false;

  position = shell_source_skip_escaped_line_endings(input, length, position);
  if (position < length && input[position] == '[') {
    size_t subscript_after = 0;
    if (!shell_source_skip_array_subscript(input, length, position,
                                           &subscript_after))
      return false;
    position = subscript_after;
  }

  position = shell_source_skip_escaped_line_endings(input, length, position);

  /* `${!prefix*}` and `${!prefix@}` enumerate matching parameter names.
   * They are selector syntax, rather than a parameter-word operator. */
  if (indirect && position < length &&
      (input[position] == '*' || input[position] == '@'))
    position++;

  *after = position;
  return true;
}

/* Recognize the structural operators that introduce a parameter word. The
 * scanner does not evaluate those operators; its only job is to know when
 * nested shell syntax belongs to the operand rather than the selector. */
static inline bool shell_source_parameter_word_operator(const char *input,
                                                        size_t length,
                                                        size_t position,
                                                        size_t *word_start) {
  if (!input || !word_start || position >= length)
    return false;

  position = shell_source_skip_escaped_line_endings(input, length, position);
  if (position >= length)
    return false;
  char op = input[position++];
  position = shell_source_skip_escaped_line_endings(input, length, position);
  switch (op) {
  case ':':
    if (position < length &&
        (input[position] == '-' || input[position] == '=' ||
         input[position] == '+' || input[position] == '?')) {
      position++;
      position =
          shell_source_skip_escaped_line_endings(input, length, position);
    }
    break;
  case '#':
  case '%':
  case '^':
  case ',':
    if (position < length && input[position] == op) {
      position++;
      position =
          shell_source_skip_escaped_line_endings(input, length, position);
    }
    break;
  case '/':
    if (position < length &&
        (input[position] == '/' || input[position] == '#' ||
         input[position] == '%')) {
      position++;
      position =
          shell_source_skip_escaped_line_endings(input, length, position);
    }
    break;
  case '-':
  case '=':
  case '+':
  case '?':
  case '@':
    break;
  default:
    return false;
  }

  *word_start = position;
  return true;
}

/* Skip one complete `${...}` expansion. Escaped physical line endings are
 * removed before recognizing the dollar/brace boundary. The parameter word
 * can contain shell syntax of its own, so list punctuation, redirects, and
 * nested substitutions do not become outer command-list syntax. A raw `{` is
 * an ordinary parameter word byte: only a nested `${...}` changes the
 * closing-brace depth. Keep this scanner shared by the fast source parser and
 * full tokenizer so a valid expansion cannot be accepted by one surface and
 * split by another. */
static inline bool shell_source_skip_parameter_expansion(const char *input,
                                                         size_t length,
                                                         size_t position,
                                                         size_t *after);

static inline bool shell_source_skip_parameter_expansion_impl(const char *input,
                                                              size_t length,
                                                              size_t position,
                                                              size_t *after) {
  if (!input || !after || position >= length || input[position] != '$')
    return false;

  size_t brace =
      shell_source_skip_escaped_line_endings(input, length, position + 1);
  if (brace >= length || input[brace] != '{')
    return false;
  size_t selector =
      shell_source_skip_escaped_line_endings(input, length, brace + 1);
  if (selector >= length || input[selector] == '}')
    return false;

  if (!shell_source_skip_parameter_selector(input, length, selector, &position))
    return false;
  position = shell_source_skip_escaped_line_endings(input, length, position);
  if (position < length && input[position] == '}') {
    *after = position + 1;
    return true;
  }
  if (!shell_source_parameter_word_operator(input, length, position, &position))
    return false;
  size_t word_start = position;

  while (position < length) {
    char c = input[position];
    if (c == '\\' && position + 1 < length) {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (continued != position) {
        position = continued;
        continue;
      }
      position += 2;
      continue;
    }
    size_t next = shell_source_logical_following(input, length, position);
    if (c == '$' && next < length && input[next] == '\'') {
      size_t quoted = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &quoted))
        return false;
      bool isolated =
          position == word_start && quoted < length && input[quoted] == '}';
      if (shell_source_ansi_quote_has_encoded_syntax(input, position, quoted,
                                                     isolated))
        return false;
      position = quoted;
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      size_t quoted = 0;
      if (!shell_source_skip_complete_quoted_text(input, length, position, c,
                                                  &quoted))
        return false;
      position = quoted;
      continue;
    }
    if (c == '$' && next < length && input[next] == '{') {
      size_t parameter_after = 0;
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 &parameter_after))
        return false;
      position = parameter_after;
      continue;
    }
    size_t arithmetic_open = 0;
    if (shell_source_dollar_arithmetic_open(input, length, position,
                                            &arithmetic_open)) {
      size_t arithmetic_after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &arithmetic_after))
        return false;
      position = arithmetic_after;
      continue;
    }
    size_t substitution_open = 0;
    if ((c == '$' && shell_source_dollar_parentheses_open(
                         input, length, position, &substitution_open)) ||
        ((c == '<' || c == '>') &&
         shell_source_process_substitution_open(input, length, position,
                                                &substitution_open))) {
      size_t substitution_after = 0;
      if (!shell_source_find_balanced_parentheses(
              input, length, substitution_open, &substitution_after))
        return false;
      position = substitution_after;
      continue;
    }
    if (c == '}') {
      *after = position + 1;
      return true;
    }
    position++;
  }
  return false;
}

static inline bool shell_source_skip_parameter_expansion(const char *input,
                                                         size_t length,
                                                         size_t position,
                                                         size_t *after) {
  if (!shell_source_scan_enter())
    return false;
  bool complete = shell_source_skip_parameter_expansion_impl(input, length,
                                                             position, after);
  shell_source_scan_leave();
  return complete;
}

/* Report whether one byte starts shell expansion inside double quotes and,
 * when it does, return the complete span. `$'...'` and process substitution
 * are not special in that context. */
static inline bool shell_source_skip_double_quote_expansion(const char *input,
                                                            size_t length,
                                                            size_t position,
                                                            bool *recognized,
                                                            size_t *after) {
  if (!input || !recognized || !after || position >= length)
    return false;
  *recognized = false;
  char c = input[position];
  if (c == '`') {
    *recognized = true;
    return shell_source_skip_complete_backtick(input, length, position, after);
  }
  if (c != '$')
    return true;
  if (shell_source_dollar_arithmetic_open(input, length, position, NULL)) {
    *recognized = true;
    return shell_source_skip_arithmetic_expansion(input, length, position,
                                                  after);
  }
  if (shell_source_logical_next_is(input, length, position, '{', NULL)) {
    *recognized = true;
    return shell_source_skip_parameter_expansion(input, length, position,
                                                 after);
  }
  size_t open = 0;
  if (shell_source_dollar_parentheses_open(input, length, position, &open)) {
    *recognized = true;
    return shell_source_find_balanced_parentheses(input, length, open, after);
  }
  return true;
}

/* An expansion inside double quotes has its own quote scope. Consume it
 * before looking for the enclosing `"`; otherwise a quote in `${word}` or
 * `$(command)` can terminate the outer word and expose nested operators. */
static inline bool
shell_source_skip_complete_double_quote_impl(const char *input, size_t length,
                                             size_t position, size_t *after) {
  if (!input || !after || position >= length || input[position] != '"')
    return false;
  for (size_t cursor = position + 1; cursor < length;) {
    char c = input[cursor];
    if (c == '\\' && cursor + 1 < length) {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, cursor);
      cursor = continued != cursor ? continued : cursor + 2;
      continue;
    }
    if (c == '"') {
      *after = cursor + 1;
      return true;
    }
    bool recognized = false;
    size_t nested_after = 0;
    if ((c == '$' || c == '`') &&
        !shell_source_skip_double_quote_expansion(input, length, cursor,
                                                  &recognized, &nested_after))
      return false;
    if (recognized) {
      cursor = nested_after;
      continue;
    }
    cursor++;
  }
  return false;
}

/* Quote and substitution scanners call one another. Bound the newly shared
 * double-quote recursion independently of source length, including when the
 * caller invokes a scanner directly rather than through the command parser. */
static inline bool shell_source_skip_complete_double_quote(const char *input,
                                                           size_t length,
                                                           size_t position,
                                                           size_t *after) {
  if (!shell_source_scan_enter())
    return false;
  bool complete = shell_source_skip_complete_double_quote_impl(input, length,
                                                               position, after);
  shell_source_scan_leave();
  return complete;
}

static inline bool shell_source_skip_complete_quoted_text(const char *input,
                                                          size_t length,
                                                          size_t position,
                                                          char quote,
                                                          size_t *after) {
  if (!input || !after || position >= length || input[position] != quote)
    return false;
  if (quote == '"')
    return shell_source_skip_complete_double_quote(input, length, position,
                                                   after);
  if (quote == '`')
    return shell_source_skip_complete_backtick(input, length, position, after);
  if (quote != '\'')
    return false;
  for (size_t cursor = position + 1; cursor < length; cursor++) {
    if (input[cursor] == '\'') {
      *after = cursor + 1;
      return true;
    }
  }
  return false;
}

/* Skip one parameter expansion that may occur within a larger shell word.
 * This is deliberately narrower than general dollar syntax: command,
 * arithmetic, and ANSI-C substitutions have their own structural scanners.
 * Keeping ordinary and special parameters together prevents `prefix$NAME` or
 * `status-$?` from being split into fictitious argv words. */
static inline bool shell_source_skip_variable_expansion(const char *input,
                                                        size_t length,
                                                        size_t position,
                                                        size_t *after) {
  if (!input || !after || position >= length || input[position] != '$')
    return false;
  size_t next =
      shell_source_skip_escaped_line_endings(input, length, position + 1);
  if (next >= length)
    return false;
  if (input[next] == '{')
    return shell_source_skip_parameter_expansion(input, length, position,
                                                 after);

  char character = input[next];
  if (isdigit((unsigned char)character) || character == '#' ||
      character == '?' || character == '$' || character == '!' ||
      character == '@' || character == '*' || character == '-') {
    *after = next + 1;
    return true;
  }
  if (!(isalpha((unsigned char)character) || character == '_'))
    return false;

  position = next + 1;
  while (position < length) {
    size_t continued =
        shell_source_skip_escaped_line_endings(input, length, position);
    if (continued != position) {
      position = continued;
      continue;
    }
    if (!(isalnum((unsigned char)input[position]) || input[position] == '_'))
      break;
    position++;
  }
  *after = position;
  return true;
}

/* Stateful iterator for ordinary and special parameter expansions in one
 * complete shell word. It deliberately excludes command/arithmetic
 * substitutions, which have separate structural handling. Unlike a raw '$'
 * search it respects ordinary quoting, escaped bytes, and complete Bash ANSI-C
 * `$'...'` fragments (whose escaped apostrophes are not shell quote ends). */
typedef struct {
  size_t position;
  bool in_single_quote;
  bool in_double_quote;
} shell_source_variable_scan_t;

static inline bool
shell_source_next_variable_expansion(const char *input, size_t length,
                                     shell_source_variable_scan_t *scan,
                                     size_t *start, size_t *after) {
  if (!input || !scan || !start || !after)
    return false;
  while (scan->position < length) {
    size_t position = scan->position;
    char c = input[position];
    if (!scan->in_single_quote && !scan->in_double_quote && c == '$' &&
        shell_source_logical_next_is(input, length, position, '\'', NULL)) {
      size_t ansi_after = 0;
      if (shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                  &ansi_after)) {
        scan->position = ansi_after;
        continue;
      }
    }
    if (c == '\\' && !scan->in_single_quote && position + 1 < length) {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (continued != position) {
        scan->position = continued;
        continue;
      }
      scan->position += 2;
      continue;
    }
    if (c == '\'' && !scan->in_double_quote) {
      scan->in_single_quote = !scan->in_single_quote;
      scan->position++;
      continue;
    }
    if (c == '"' && !scan->in_single_quote) {
      scan->in_double_quote = !scan->in_double_quote;
      scan->position++;
      continue;
    }
    if (!scan->in_single_quote && c == '$' &&
        shell_source_skip_variable_expansion(input, length, position, after)) {
      *start = position;
      scan->position = *after;
      return true;
    }
    scan->position++;
  }
  return false;
}

/* Recognize a complete glob bracket expression.  This is a lexical candidate
 * helper, not a shell-list delimiter suppressor: unquoted shell operators in
 * bracket text still delimit the surrounding command.  POSIX character,
 * equivalence, and collating subexpressions have their own closing delimiter
 * before the outer ']'. */
static inline bool shell_source_skip_glob_bracket(const char *input,
                                                  size_t length,
                                                  size_t position,
                                                  size_t *after) {
  if (!input || !after || position >= length || input[position] != '[')
    return false;
  size_t cursor = position + 1;
  if (cursor < length && (input[cursor] == '!' || input[cursor] == '^'))
    cursor++;
  if (cursor < length && input[cursor] == ']')
    cursor++;

  while (cursor < length) {
    char c = input[cursor];
    if (c == '\\' && cursor + 1 < length) {
      cursor += 2;
      continue;
    }
    if (isspace((unsigned char)c))
      return false;
    if (c == '|' || c == '&' || c == ';' || c == '<' || c == '>' || c == '(' ||
        c == ')')
      return false;
    if (c == '[' && cursor + 1 < length &&
        (input[cursor + 1] == ':' || input[cursor + 1] == '.' ||
         input[cursor + 1] == '=')) {
      char delimiter = input[cursor + 1];
      cursor += 2;
      while (cursor + 1 < length &&
             !(input[cursor] == delimiter && input[cursor + 1] == ']')) {
        if (input[cursor] == '\\' && cursor + 1 < length) {
          cursor++;
        } else if (input[cursor] == '|' || input[cursor] == '&' ||
                   input[cursor] == ';' || input[cursor] == '<' ||
                   input[cursor] == '>' || input[cursor] == '(' ||
                   input[cursor] == ')') {
          return false;
        }
        cursor++;
      }
      if (cursor + 1 >= length)
        return false;
      cursor += 2;
      continue;
    }
    if (c == ']') {
      *after = cursor + 1;
      return true;
    }
    cursor++;
  }
  return false;
}

/* Extglob alternatives are shell-word grammar in the supported Bash dialect.
 * Keep their balanced parentheses and internal `|` bytes opaque to the outer
 * command-list scanner, including when the extglob follows a literal prefix. */
static inline bool shell_source_skip_extglob(const char *input, size_t length,
                                             size_t position, size_t *after) {
  size_t open = 0;
  if (!input || !after || position >= length ||
      (input[position] != '?' && input[position] != '*' &&
       input[position] != '+' && input[position] != '@' &&
       input[position] != '!') ||
      !shell_source_logical_next_is(input, length, position, '(', &open))
    return false;
  return shell_source_find_balanced_parentheses(input, length, open, after);
}

/* A dollar byte is literal unless it begins syntax whose result depends on
 * execution.  Keep the legacy `$[...]` arithmetic spelling conservative: it
 * is deprecated Bash syntax, but accepting it as a static pathname would be
 * less safe than declining to resolve it.  ANSI-C quotes are handled by the
 * callers because a complete quote is static while an incomplete one is not.
 * A bare `$`, `$:`, and similar non-parameter spellings remain literal. */
static inline bool shell_source_dollar_has_dynamic_syntax(const char *input,
                                                          size_t length,
                                                          size_t position) {
  if (!input || position >= length || input[position] != '$')
    return false;

  size_t next_position =
      shell_source_logical_following(input, length, position);
  if (next_position >= length)
    return false;
  char next = input[next_position];
  if (next == '(' || next == '[' || next == '"')
    return true;

  size_t after = 0;
  return shell_source_skip_variable_expansion(input, length, position, &after);
}

/* Recognize a direct process-substitution operand, not a concatenated word.
 * The matching close must consume the whole bounded source span. */
static inline bool shell_source_word_is_process_substitution(const char *input,
                                                             size_t length) {
  size_t after = 0;
  size_t open = 0;
  return input &&
         shell_source_process_substitution_open(input, length, 0, &open) &&
         shell_source_find_balanced_parentheses(input, length, open, &after) &&
         after == length;
}

/* Detect an unquoted process substitution in one raw shell word. A redirect
 * pathname may concatenate a process-substitution expansion with literal text
 * (for example, `prefix<(producer)`), so checking only a whole-word `<(...)`
 * spelling would leave an unsupported descriptor route partially modeled.
 * Quoted and escaped spellings do not trigger this predicate. This broader
 * unsupported-syntax check must not be used to infer a direct stream route. */
static inline bool shell_source_word_has_process_substitution(const char *input,
                                                              size_t length) {
  if (!input)
    return false;
  size_t position = 0;
  while (position < length) {
    char c = input[position];
    if (c == '\\') {
      if (position + 1 >= length)
        return false;
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (continued != position) {
        position = continued;
        continue;
      }
      position += 2;
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      size_t after = 0;
      if (!shell_source_skip_complete_quoted_text(input, length, position, c,
                                                  &after))
        return false;
      position = after;
      continue;
    }
    if (c == '$' &&
        shell_source_logical_next_is(input, length, position, '{', NULL)) {
      size_t after = 0;
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 &after))
        return false;
      position = after;
      continue;
    }
    size_t extglob_after = 0;
    if (shell_source_skip_extglob(input, length, position, &extglob_after)) {
      position = extglob_after;
      continue;
    }
    if (c == '$' &&
        shell_source_dollar_arithmetic_open(input, length, position, NULL)) {
      size_t after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &after))
        return false;
      position = after;
      continue;
    }
    size_t open = 0;
    if ((c == '<' || c == '>') && shell_source_process_substitution_open(
                                      input, length, position, &open)) {
      size_t after = 0;
      return shell_source_find_balanced_parentheses(input, length, open,
                                                    &after);
    }
    if (c == '$' &&
        shell_source_dollar_parentheses_open(input, length, position, &open)) {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, open, &after))
        return false;
      position = after;
      continue;
    }
    position++;
  }
  return false;
}

/* Detect an executable substitution anywhere in one complete source word.
 * Command substitutions and backticks remain active inside double quotes;
 * process substitutions do not, except in parameter pattern operands, whose
 * quote rules are independent of the outer quotes. Single and ANSI-C quotes
 * are literal in ordinary words. Inside a double-quoted
 * default word, Bash re-expands decoded ANSI-C text; numeric escapes that
 * create unrepresentable source openers are rejected by the structural
 * parameter scanner above. Callers have already established balanced source
 * structure, so this is a feature iterator rather than another parser. */
/* Stateful iterator for executable substitution spans in one complete shell
 * word. Scoped parameter operands and arithmetic expressions are traversed
 * without exposing their punctuation as outer shell syntax. */
typedef enum {
  SHELL_SOURCE_SUBST_COMMAND = 0,
  SHELL_SOURCE_SUBST_BACKTICK,
  SHELL_SOURCE_SUBST_PROCESS_INPUT,
  SHELL_SOURCE_SUBST_PROCESS_OUTPUT,
} shell_source_substitution_kind_t;

static inline bool
shell_source_arithmetic_content(const char *input, size_t length,
                                size_t position, size_t *content_start,
                                size_t *content_length, size_t *after);

typedef struct {
  size_t position;
  bool in_single_quote;
  bool in_double_quote;
  /* A parameter word inside double quotes retains expansion semantics even
   * where apostrophes pair structurally to protect its closing brace. */
  bool inherited_double_quote;
  size_t scope_end;
  unsigned scope_count;
  bool suppress_process;
  bool arithmetic_scope;
  /* In a double-quoted parameter default word, Bash expands the decoded
   * contents of $'...' a second time. Keep its source boundary while walking
   * the executable substitutions in that decoded word. */
  size_t ansi_end;
  struct {
    size_t resume;
    size_t end;
    bool single_quote;
    bool double_quote;
    bool inherited_double_quote;
    bool suppress_process;
    bool arithmetic_scope;
    size_t ansi_end;
  } scopes[SHELL_MAX_SUBCOMMANDS];
} shell_source_substitution_scan_t;

static inline bool shell_source_next_executable_substitution(
    const char *input, size_t length, shell_source_substitution_scan_t *scan,
    size_t *start, size_t *after, shell_source_substitution_kind_t *kind) {
  if (!input || !scan || !start || !after || !kind)
    return false;

  if (scan->scope_end == 0 && scan->scope_count == 0)
    scan->scope_end = length;

  while (scan->position < length) {
    if (scan->position >= scan->scope_end) {
      if (scan->scope_count == 0)
        return false;
      scan->scope_count--;
      scan->position = scan->scopes[scan->scope_count].resume;
      scan->scope_end = scan->scopes[scan->scope_count].end;
      scan->in_single_quote = scan->scopes[scan->scope_count].single_quote;
      scan->in_double_quote = scan->scopes[scan->scope_count].double_quote;
      scan->inherited_double_quote =
          scan->scopes[scan->scope_count].inherited_double_quote;
      scan->suppress_process = scan->scopes[scan->scope_count].suppress_process;
      scan->arithmetic_scope = scan->scopes[scan->scope_count].arithmetic_scope;
      scan->ansi_end = scan->scopes[scan->scope_count].ansi_end;
      continue;
    }
    size_t position = scan->position;
    if (scan->ansi_end && position >= scan->ansi_end) {
      scan->position = scan->ansi_end + 1;
      scan->ansi_end = 0;
      continue;
    }
    char c = input[position];
    if (scan->ansi_end && c == '\\') {
      size_t escaped = position;
      while (escaped < scan->ansi_end && input[escaped] == '\\')
        escaped++;
      /* Every pair decodes to one backslash; an unpaired backslash
       * preceding an expansion opener survives ANSI decoding as another
       * backslash. Bash's second expansion sees an unescaped opener for
       * residues 0 and 3. */
      if (escaped < scan->ansi_end &&
          (input[escaped] == '$' || input[escaped] == '`')) {
        size_t slashes = escaped - position;
        scan->position =
            slashes % 4 == 0 || slashes % 4 == 3 ? escaped : escaped + 1;
      } else {
        scan->position = escaped;
      }
      continue;
    }
    if (!scan->in_single_quote && !scan->in_double_quote &&
        !scan->inherited_double_quote && c == '$' &&
        shell_source_logical_next_is(input, length, position, '\'', NULL)) {
      size_t ansi_after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &ansi_after))
        return false;
      scan->position = ansi_after;
      continue;
    }
    if (!scan->in_single_quote && !scan->in_double_quote &&
        scan->inherited_double_quote && !scan->ansi_end && c == '$' &&
        shell_source_logical_next_is(input, length, position, '\'', NULL)) {
      size_t ansi_after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &ansi_after))
        return false;
      scan->ansi_end = ansi_after - 1;
      scan->position =
          shell_source_logical_following(input, length, position) + 1;
      continue;
    }
    if (c == '\\' && !scan->in_single_quote && position + 1 < length) {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, position);
      scan->position = continued != position ? continued : position + 2;
      continue;
    }
    if (c == '\'' && !scan->ansi_end && !scan->in_double_quote &&
        !scan->inherited_double_quote) {
      scan->in_single_quote = !scan->in_single_quote;
      scan->position++;
      continue;
    }
    if (c == '"' && !scan->ansi_end && !scan->in_single_quote) {
      scan->in_double_quote = !scan->in_double_quote;
      scan->position++;
      continue;
    }
    if (scan->in_single_quote) {
      scan->position++;
      continue;
    }
    if (c == '`') {
      size_t substitution_after = 0;
      if (!shell_source_skip_complete_backtick(input, length, position,
                                               &substitution_after))
        return false;
      *start = position;
      *after = substitution_after;
      *kind = SHELL_SOURCE_SUBST_BACKTICK;
      scan->position = substitution_after;
      return true;
    }
    if (c == '$' &&
        shell_source_logical_next_is(input, length, position, '{', NULL)) {
      size_t parameter_after = 0;
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 &parameter_after))
        return false;
      size_t brace = shell_source_logical_following(input, length, position);
      size_t selector =
          shell_source_skip_escaped_line_endings(input, length, brace + 1);
      size_t operator_position = 0;
      size_t word_start = 0;
      if (!shell_source_skip_parameter_selector(input, length, selector,
                                                &operator_position))
        return false;
      operator_position = shell_source_skip_escaped_line_endings(
          input, length, operator_position);
      if (operator_position < parameter_after - 1 &&
          !shell_source_parameter_word_operator(input, length,
                                                operator_position, &word_start))
        return false;
      bool pattern_word =
          operator_position < parameter_after - 1 &&
          (input[operator_position] == '#' || input[operator_position] == '%' ||
           input[operator_position] == '/' || input[operator_position] == '^' ||
           input[operator_position] == ',');
      if (scan->scope_count >= SHELL_MAX_SUBCOMMANDS)
        return false;
      unsigned depth = scan->scope_count++;
      scan->scopes[depth].resume = parameter_after;
      scan->scopes[depth].end = scan->scope_end;
      scan->scopes[depth].single_quote = scan->in_single_quote;
      scan->scopes[depth].double_quote = scan->in_double_quote;
      scan->scopes[depth].inherited_double_quote = scan->inherited_double_quote;
      scan->scopes[depth].suppress_process = scan->suppress_process;
      scan->scopes[depth].arithmetic_scope = scan->arithmetic_scope;
      scan->scopes[depth].ansi_end = scan->ansi_end;
      /* Selectors can contain executable array subscripts too; walk them
       * before the operand instead of jumping straight to word_start. */
      scan->position = brace + 1;
      scan->scope_end = parameter_after - 1;
      scan->suppress_process = pattern_word ? false
                                            : scan->suppress_process ||
                                                  scan->in_double_quote ||
                                                  scan->inherited_double_quote;
      scan->inherited_double_quote =
          !pattern_word &&
          (scan->inherited_double_quote || scan->in_double_quote);
      scan->in_single_quote = false;
      scan->in_double_quote = false;
      scan->arithmetic_scope = false;
      scan->ansi_end = 0;
      continue;
    }
    if (c == '$' &&
        shell_source_dollar_arithmetic_open(input, length, position, NULL)) {
      size_t content_start = 0, content_length = 0, arithmetic_after = 0;
      if (!shell_source_arithmetic_content(input, length, position,
                                           &content_start, &content_length,
                                           &arithmetic_after))
        return false;
      if (scan->scope_count >= SHELL_MAX_SUBCOMMANDS)
        return false;
      unsigned depth = scan->scope_count++;
      scan->scopes[depth].resume = arithmetic_after;
      scan->scopes[depth].end = scan->scope_end;
      scan->scopes[depth].single_quote = scan->in_single_quote;
      scan->scopes[depth].double_quote = scan->in_double_quote;
      scan->scopes[depth].inherited_double_quote = scan->inherited_double_quote;
      scan->scopes[depth].suppress_process = scan->suppress_process;
      scan->scopes[depth].arithmetic_scope = scan->arithmetic_scope;
      scan->scopes[depth].ansi_end = scan->ansi_end;
      scan->position = content_start;
      scan->scope_end = content_start + content_length;
      scan->in_single_quote = false;
      scan->in_double_quote = false;
      scan->inherited_double_quote = false;
      scan->suppress_process = true;
      scan->arithmetic_scope = true;
      scan->ansi_end = 0;
      continue;
    }
    size_t open = 0;
    if (c == '$' &&
        shell_source_dollar_parentheses_open(input, length, position, &open)) {
      size_t substitution_after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, open,
                                                  &substitution_after))
        return false;
      *start = position;
      *after = substitution_after;
      *kind = SHELL_SOURCE_SUBST_COMMAND;
      scan->position = substitution_after;
      return true;
    }
    if (!scan->in_double_quote && !scan->inherited_double_quote &&
        !scan->suppress_process && !scan->arithmetic_scope &&
        (c == '<' || c == '>') &&
        shell_source_process_substitution_open(input, length, position,
                                               &open)) {
      size_t substitution_after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, open,
                                                  &substitution_after))
        return false;
      *start = position;
      *after = substitution_after;
      *kind = c == '<' ? SHELL_SOURCE_SUBST_PROCESS_INPUT
                       : SHELL_SOURCE_SUBST_PROCESS_OUTPUT;
      scan->position = substitution_after;
      return true;
    }
    scan->position++;
  }
  return false;
}

static inline bool
shell_source_word_has_executable_substitution(const char *input,
                                              size_t length) {
  shell_source_substitution_scan_t scan = {0};
  size_t start = 0, after = 0;
  shell_source_substitution_kind_t kind;
  return shell_source_next_executable_substitution(input, length, &scan, &start,
                                                   &after, &kind);
}

/* A compound array assignment remains array grammar wherever it appears:
 * unlike `a[0]=word`, Bash cannot reinterpret `a=(one two)` as one ordinary
 * command argument after a command word. */
static inline bool shell_source_array_assignment_is_compound(const char *input,
                                                             size_t length) {
  if (!input || length < 4 ||
      !(isalpha((unsigned char)input[0]) || input[0] == '_'))
    return false;
  size_t position = 1;
  while (position < length &&
         (isalnum((unsigned char)input[position]) || input[position] == '_'))
    position++;
  if (position < length && input[position] == '[') {
    if (!shell_source_skip_array_subscript(input, length, position, &position))
      return false;
  }
  if (position < length && input[position] == '+')
    position++;
  return position + 1 < length && input[position] == '=' &&
         input[position + 1] == '(';
}

/* Skip one complete shell word while retaining its raw source span. Unlike a
 * redirect operand, this reports an incomplete substitution or quote so
 * callers that need complete syntax can reject it rather than flattening the
 * remainder into ordinary text. */
static inline bool shell_source_skip_shell_word_impl(const char *input,
                                                     size_t length,
                                                     size_t position,
                                                     size_t *after,
                                                     bool stop_groups) {
  if (!input || !after || position > length)
    return false;
  while (position < length) {
    char c = input[position];
    if (c == '$' &&
        shell_source_logical_next_is(input, length, position, '{', NULL)) {
      size_t parameter_after = 0;
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 &parameter_after))
        return false;
      position = parameter_after;
      continue;
    }
    size_t extglob_after = 0;
    if (shell_source_skip_extglob(input, length, position, &extglob_after)) {
      position = extglob_after;
      continue;
    }
    if (c == '$' &&
        shell_source_logical_next_is(input, length, position, '\'', NULL)) {
      size_t quoted = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &quoted))
        return false;
      position = quoted;
      continue;
    }
    if (c == '\\') {
      if (position + 1 >= length)
        return false;
      position += 2;
      if (input[position - 1] == '\r' && position < length &&
          input[position] == '\n')
        position++;
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      size_t quoted = 0;
      if (!shell_source_skip_complete_quoted_text(input, length, position, c,
                                                  &quoted))
        return false;
      position = quoted;
      continue;
    }
    if (c == '$' &&
        shell_source_dollar_arithmetic_open(input, length, position, NULL)) {
      size_t arithmetic_after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &arithmetic_after))
        return false;
      position = arithmetic_after;
      continue;
    }
    size_t open = 0;
    if ((c == '$' && shell_source_dollar_parentheses_open(input, length,
                                                          position, &open)) ||
        ((c == '<' || c == '>') && shell_source_process_substitution_open(
                                       input, length, position, &open))) {
      size_t substitution_after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, open,
                                                  &substitution_after))
        return false;
      position = substitution_after;
      continue;
    }
    if ((stop_groups && (c == '(' || c == ')')) || isspace((unsigned char)c) ||
        c == '|' || c == ';' || c == '&' || c == '<' || c == '>' || c == '\n' ||
        c == '\r')
      break;
    position++;
  }
  *after = position;
  return true;
}

static inline bool shell_source_skip_shell_word(const char *input,
                                                size_t length, size_t position,
                                                size_t *after) {
  return shell_source_skip_shell_word_impl(input, length, position, after,
                                           false);
}

/* Determine whether a descriptor starts a whole shell word. Scan opaque word
 * fragments together: the ')' of $(producer) must not behave like a group
 * closer. Ordinary whitespace takes the constant-time path. */
static inline bool shell_source_word_boundary(const char *input, size_t length,
                                              size_t target) {
  if (!input || target > length)
    return false;
  if (target == 0)
    return true;
  unsigned char previous = (unsigned char)input[target - 1];
  if (isspace(previous)) {
    size_t before = target - 1;
    if (previous == '\n' && before && input[before - 1] == '\r')
      before--;
    size_t slashes = 0;
    while (before && input[before - 1] == '\\') {
      before--;
      slashes++;
    }
    if (!(slashes & 1))
      return true;
  } else if (!strchr(";|&<>()}", previous)) {
    return false;
  }
  size_t position = 0;
  size_t braces = 0;
  while (position < target) {
    size_t next =
        shell_source_skip_inline_continuations(input, target, position);
    if (next != position) {
      position = next;
      continue;
    }
    char c = input[position];
    if (c == '#' && shell_source_comment_starts(input, length, position)) {
      position = shell_source_next_line(input, length, position);
      continue;
    }
    if (c == '<' &&
        shell_source_match_logical_punctuation(input, target, position, "<<",
                                               NULL) &&
        !shell_source_match_logical_punctuation(input, target, position, "<<<",
                                                NULL)) {
      bool complete = false;
      if (shell_source_skip_heredoc_sequence(input, length, position, &next,
                                             &complete) &&
          complete && next <= target) {
        position = next;
        continue;
      }
    }
    size_t brace_next = shell_source_logical_following(input, length, position);
    if (c == '{' && brace_next < length &&
        (isspace((unsigned char)input[brace_next]) ||
         input[brace_next] == '(')) {
      braces++;
      position++;
      continue;
    }
    if (c == '}' && braces) {
      braces--;
      position++;
      continue;
    }
    /* Process substitutions are word fragments, not redirect operators. */
    if (isspace((unsigned char)c) || strchr(";|&()", c) ||
        ((c == '<' || c == '>') && !shell_source_process_substitution_open(
                                       input, length, position, NULL))) {
      position++;
      continue;
    }
    if (!shell_source_skip_shell_word_impl(input, length, position, &next,
                                           true) ||
        next <= position || next >= target)
      return false;
    position = next;
  }
  return position == target;
}

/* Bash's {name}>word descriptor allocator. Recognition happens after escaped
 * physical line endings are removed, but the returned offset remains in the
 * original source. The opening brace must begin a complete shell word. */
static inline bool shell_source_parse_named_fd(const char *input, size_t start,
                                               size_t end, size_t *after) {
  if (after)
    *after = start;
  if (!input || !after || start >= end || input[start] != '{' ||
      !shell_source_word_boundary(input, end, start))
    return false;

  size_t position = start + 1;
  bool first = true;
  while (position < end) {
    position = shell_source_skip_escaped_line_endings(input, end, position);
    if (position >= end)
      return false;
    unsigned char c = (unsigned char)input[position];
    if (c == '}') {
      if (first)
        return false;
      *after = position + 1;
      return true;
    }
    if (first ? !(isalpha(c) || c == '_') : !(isalnum(c) || c == '_'))
      return false;
    first = false;
    position++;
  }
  return false;
}

/* Recover a complete Bash `{name}` descriptor prefix that is immediately
 * followed by a redirect operator after lexical line-continuation removal.
 * This is the one named-FD recognition boundary used by tokenization and I/O
 * modeling; literal blanks never cross it. */
static inline bool
shell_source_parse_named_fd_redirect(const char *input, size_t start,
                                     size_t end, size_t *operator_position) {
  if (operator_position)
    *operator_position = start;
  if (!input || !operator_position)
    return false;
  size_t after = 0;
  if (!shell_source_parse_named_fd(input, start, end, &after))
    return false;
  after = shell_source_skip_escaped_line_endings(input, end, after);
  if (after >= end || (input[after] != '<' && input[after] != '>'))
    return false;
  *operator_position = after;
  return true;
}

/* A redirection token consumes one following shell word unless its target is
 * already part of the token (for example, `2>&1` or `2>&-`).  Keep this
 * spelling-level rule shared by canonical command construction and dependency
 * analysis: `>&$fd` is normally tokenized as `>&` plus `$fd`, but `$fd` is a
 * descriptor operand, never argv. */
static inline bool shell_source_redirection_consumes_word(const char *input,
                                                          size_t length) {
  if (!input || length == 0)
    return false;
  /* The lexer keeps a terminal physical continuation in the redirect token's
   * raw span. It disappears before shell grammar assigns the following word
   * to the operator, so all spelling checks below must stop at that logical
   * end rather than the source-buffer end. */
  size_t logical_end =
      shell_source_skip_escaped_line_endings_backward(input, length, length);
  if (logical_end == 0)
    return false;
  /* `>|` is the one ordinary output spelling whose last byte is not the
   * operator that introduced the pathname. Match it after lexical removal of
   * physical continuations too: `>\\\n|path` is still a clobber redirect,
   * never a pipe followed by argv. */
  size_t after = 0;
  uint32_t descriptor = 0;
  if (shell_source_parse_named_fd_redirect(input, 0, logical_end, &after)) {
    /* `after` already names the direction byte. */
  } else {
    shell_source_io_number_t io_number = shell_source_parse_io_number(
        input, 0, logical_end, &after, &descriptor);
    if (io_number == SHELL_SOURCE_IO_NUMBER_OVERFLOW)
      return false;
  }
  size_t operator_after = 0;
  if (shell_source_match_logical_punctuation(input, logical_end, after, ">|",
                                             &operator_after) &&
      operator_after == logical_end)
    return true;
  char last = input[logical_end - 1];
  return last == '<' || last == '>' || last == '&';
}

/* Parse the deliberately narrow parameter form used as a Bash named-FD
 * duplication target. Escaped physical line endings disappear during shell
 * lexical processing, so they are permitted after the dollar marker, after
 * an opening brace, or between identifier bytes. The returned zero-copy span
 * retains the original spelling. This accepts
 * exactly `$name` and `${name}`, optionally wrapped by one complete pair of
 * double quotes; general parameter expansion and concatenated words remain
 * outside descriptor analysis. */
static inline bool shell_source_parse_named_fd_parameter(const char *input,
                                                         size_t start,
                                                         size_t end,
                                                         size_t *name_start,
                                                         size_t *name_end) {
  if (name_start)
    *name_start = start;
  if (name_end)
    *name_end = start;
  if (!input || !name_start || !name_end || start >= end)
    return false;

  if (input[start] == '"') {
    if (end - start < 4 || input[end - 1] != '"')
      return false;
    start++;
    end--;
  }
  if (start >= end || input[start++] != '$')
    return false;
  start = shell_source_skip_escaped_line_endings(input, end, start);

  bool braced = start < end && input[start] == '{';
  if (braced) {
    start++;
    start = shell_source_skip_escaped_line_endings(input, end, start);
    if (start >= end || input[end - 1] != '}')
      return false;
    end--;
  }
  if (start >= end)
    return false;

  size_t position = start;
  bool first = true;
  while (position < end) {
    size_t next = shell_source_skip_escaped_line_endings(input, end, position);
    if (next != position) {
      position = next;
      continue;
    }
    unsigned char c = (unsigned char)input[position];
    if (first ? !(isalpha(c) || c == '_') : !(isalnum(c) || c == '_'))
      return false;
    first = false;
    position++;
  }
  if (first)
    return false;
  *name_start = start;
  *name_end = end;
  return true;
}

/* Walk backward over any escaped physical line endings immediately before a
 * logical source byte. */
static inline size_t
shell_source_skip_inline_continuations_backward(const char *input,
                                                size_t position) {
  while (position) {
    size_t ending = position;
    if (input[ending - 1] == '\n') {
      ending--;
      if (ending && input[ending - 1] == '\r')
        ending--;
    } else if (input[ending - 1] == '\r') {
      ending--;
    } else {
      break;
    }
    if (!ending || input[ending - 1] != '\\')
      break;
    position = ending - 1;
  }
  return position;
}

/* Return the physical span of an arithmetic expansion's expression. The two
 * closing parentheses may be separated by removed physical line endings, so
 * `after - 2` is not reliably the first closing delimiter. Keep the returned
 * span in the original buffer; consumers retain zero-copy source views and
 * use their ordinary continuation-aware scanners within it. */
static inline bool
shell_source_arithmetic_content(const char *input, size_t length,
                                size_t position, size_t *content_start,
                                size_t *content_length, size_t *after) {
  if (content_start)
    *content_start = 0;
  if (content_length)
    *content_length = 0;
  if (after)
    *after = 0;
  if (!input || !content_start || !content_length || !after)
    return false;

  size_t open = 0;
  if (!shell_source_dollar_arithmetic_open(input, length, position, &open) ||
      !shell_source_skip_arithmetic_expansion(input, length, position, after))
    return false;
  if (*after == 0 || *after > length)
    return false;

  /* The final byte is the second logical `)`. Walk back over any removed
   * continuations to locate the physical first logical `)`. */
  size_t before_second =
      shell_source_skip_inline_continuations_backward(input, *after - 1);
  if (before_second == 0)
    return false;
  size_t first_close = before_second - 1;
  if (first_close < open + 1)
    return false;
  *content_start = open + 1;
  *content_length = first_close - *content_start;
  return true;
}

/* Recover an adjacent descriptor without allocating a normalized spelling.
 * Escaped physical newlines can occur between digits or before the operator. */
static inline size_t shell_source_io_number_start_before(const char *input,
                                                         size_t length,
                                                         size_t marker) {
  if (!input || marker > length)
    return marker;
  size_t start = marker;
  while (start) {
    size_t before =
        shell_source_skip_inline_continuations_backward(input, start);
    if (before != start) {
      start = before;
      continue;
    }
    if (isdigit((unsigned char)input[start - 1])) {
      start--;
      continue;
    }
    break;
  }
  while (start < marker && !isdigit((unsigned char)input[start]))
    start++;
  size_t after = start;
  uint32_t descriptor = 0;
  return start < marker && shell_source_word_boundary(input, length, start) &&
                 shell_source_parse_io_number(input, start, marker, &after,
                                              &descriptor) ==
                     SHELL_SOURCE_IO_NUMBER_VALID &&
                 after == marker
             ? start
             : marker;
}

/* Recover a named descriptor immediately before a redirect operator without
 * allocating its continuation-normalized identifier. */
static inline size_t shell_source_named_fd_start_before(const char *input,
                                                        size_t length,
                                                        size_t marker) {
  if (!input || marker > length)
    return marker;
  size_t position =
      shell_source_skip_inline_continuations_backward(input, marker);
  if (!position || input[position - 1] != '}')
    return marker;
  position--;
  while (position) {
    size_t before =
        shell_source_skip_inline_continuations_backward(input, position);
    if (before != position) {
      position = before;
      continue;
    }
    unsigned char c = (unsigned char)input[position - 1];
    if (isalnum(c) || c == '_') {
      position--;
      continue;
    }
    if (c != '{')
      return marker;
    position--;
    size_t after = position;
    return shell_source_parse_named_fd(input, position, marker, &after) &&
                   shell_source_skip_escaped_line_endings(input, marker,
                                                          after) == marker
               ? position
               : marker;
  }
  return marker;
}

/* Skip one redirect operand. Adjacent redirects delimit each other, so this
 * recognizes `>first>second` as two operations rather than one filename.
 * Quotes and all substitution forms are opaque, keeping the result an exact
 * source span even when a substituted value contains separators or spaces. */
static inline size_t shell_source_skip_redirect_word(const char *input,
                                                     size_t position,
                                                     size_t end) {
  while (position < end) {
    char c = input[position];
    if (c == '$' &&
        shell_source_logical_next_is(input, end, position, '{', NULL)) {
      size_t parameter_after = 0;
      if (!shell_source_skip_parameter_expansion(input, end, position,
                                                 &parameter_after))
        return end;
      position = parameter_after;
      continue;
    }
    size_t extglob_after = 0;
    if (shell_source_skip_extglob(input, end, position, &extglob_after)) {
      position = extglob_after;
      continue;
    }
    if (c == '$' &&
        shell_source_logical_next_is(input, end, position, '\'', NULL)) {
      size_t quoted = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, end, position,
                                                   &quoted))
        return end;
      position = quoted;
      continue;
    }
    if (c == '\\' && position + 1 < end) {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, end, position);
      if (continued != position) {
        position = continued;
        continue;
      }
      position += 2;
      continue;
    }
    if (c == '\'' || c == '"') {
      position = shell_source_skip_quoted_text(input, end, position, c);
      continue;
    }
    if (c == '`') {
      position = shell_source_skip_quoted_text(input, end, position, c);
      continue;
    }
    if (c == '$' &&
        shell_source_dollar_arithmetic_open(input, end, position, NULL)) {
      size_t after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, end, position, &after))
        return end;
      position = after;
      continue;
    }
    size_t substitution_open = 0;
    if ((c == '$' && shell_source_dollar_parentheses_open(
                         input, end, position, &substitution_open)) ||
        ((c == '<' || c == '>') &&
         shell_source_process_substitution_open(input, end, position,
                                                &substitution_open))) {
      position =
          shell_source_skip_balanced_parentheses(input, end, substitution_open);
      continue;
    }
    if (c == '#' && shell_source_comment_starts(input, end, position))
      break;
    if (isspace((unsigned char)c) || c == '|' || c == ';' || c == '&' ||
        c == '<' || c == '>')
      break;
    position++;
  }
  return position;
}

/* A brace sequence has either numeric endpoints or one-byte letter endpoints,
 * optionally followed by a numeric increment. This is deliberately narrower
 * than a generic `..` spelling: `foo{bar..baz}` and `foo{-..2}` are literal
 * pathnames, whereas `foo{a..c}` and `foo{1..3}` expand into several paths. */
static inline bool shell_source_brace_sequence_integer(const char *input,
                                                       size_t start,
                                                       size_t end) {
  if (!input || start >= end)
    return false;
  if (input[start] == '+' || input[start] == '-')
    start++;
  if (start >= end)
    return false;
  for (size_t position = start; position < end; position++)
    if (!isdigit((unsigned char)input[position]))
      return false;
  return true;
}

static inline bool shell_source_brace_sequence_letter(unsigned char byte) {
  return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z');
}

static inline bool shell_source_brace_sequence_expands(const char *input,
                                                       size_t start,
                                                       size_t end) {
  if (!input || start >= end)
    return false;
  size_t separators[2] = {0, 0};
  size_t separator_count = 0;
  for (size_t position = start; position < end; position++) {
    if (input[position] == '.' && position + 1 < end &&
        input[position + 1] == '.') {
      if (separator_count == 2)
        return false;
      separators[separator_count++] = position;
      position++;
      continue;
    }
    if (input[position] == '\\' || input[position] == '\'' ||
        input[position] == '"' || input[position] == '{' ||
        input[position] == '}' || input[position] == ',')
      return false;
  }
  if (separator_count == 0)
    return false;

  size_t first_start = start;
  size_t first_end = separators[0];
  size_t second_start = separators[0] + 2;
  size_t second_end = separator_count == 2 ? separators[1] : end;
  size_t increment_start = separator_count == 2 ? separators[1] + 2 : end;
  if (first_start >= first_end || second_start >= second_end ||
      (separator_count == 2 && increment_start >= end))
    return false;

  bool numeric =
      shell_source_brace_sequence_integer(input, first_start, first_end) &&
      shell_source_brace_sequence_integer(input, second_start, second_end);
  bool characters =
      first_end - first_start == 1 && second_end - second_start == 1 &&
      shell_source_brace_sequence_letter((unsigned char)input[first_start]) &&
      shell_source_brace_sequence_letter((unsigned char)input[second_start]);
  return (numeric || characters) &&
         (separator_count != 2 ||
          shell_source_brace_sequence_integer(input, increment_start, end));
}

/* Identify one unquoted brace pair and whether it expands or contains syntax
 * whose spelling is only known at execution time. Nested pairs are checked
 * independently, so a literal outer pair cannot hide `foo{{a,b}}` or
 * `foo{$(producer)}`. Quoted and escaped delimiters are ordinary bytes. A
 * dynamic inner spelling is enough for the caller to reject static treatment,
 * even before the outer pair's closing brace needs to be located. */
static inline bool shell_source_brace_expansion_pair(const char *input,
                                                     size_t length, size_t open,
                                                     size_t *after,
                                                     bool *expands,
                                                     bool *has_dynamic_syntax) {
  if (after)
    *after = open;
  if (expands)
    *expands = false;
  if (has_dynamic_syntax)
    *has_dynamic_syntax = false;
  if (!input || !after || !expands || !has_dynamic_syntax || open >= length ||
      input[open] != '{')
    return false;

  bool in_single_quote = false;
  bool in_double_quote = false;
  bool has_alternative = false;
  bool nested_expands = false;
  for (size_t position = open + 1; position < length;) {
    char c = input[position];
    if (in_single_quote) {
      if (c == '\'')
        in_single_quote = false;
      position++;
      continue;
    }
    if (c == '\\') {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (continued != position) {
        position = continued;
        continue;
      }
      if (++position < length)
        position++;
      continue;
    }
    if (!in_double_quote && c == '\'') {
      in_single_quote = true;
      position++;
      continue;
    }
    if (c == '"') {
      in_double_quote = !in_double_quote;
      position++;
      continue;
    }
    if (!in_double_quote && c == '$' &&
        shell_source_logical_next_is(input, length, position, '\'', NULL)) {
      size_t ansi_after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &ansi_after))
        return false;
      position = ansi_after;
      continue;
    }
    /* Parameter and command substitution remain active inside literal
     * braces. Do not let the parameter's closing `}` masquerade as the outer
     * brace or skip the command substitution before the caller sees it. A
     * bare `$` stays literal, however. */
    if (c == '`' ||
        shell_source_dollar_has_dynamic_syntax(input, length, position)) {
      *has_dynamic_syntax = true;
      return true;
    }
    if (in_double_quote) {
      position++;
      continue;
    }
    if (((c == '<' || c == '>') && shell_source_process_substitution_open(
                                       input, length, position, NULL)) ||
        ((c == '?' || c == '*' || c == '+' || c == '@' || c == '!') &&
         shell_source_logical_next_is(input, length, position, '(', NULL)) ||
        c == '*' || c == '?') {
      *has_dynamic_syntax = true;
      return true;
    }
    if (c == '[') {
      size_t bracket_after = 0;
      if (shell_source_skip_glob_bracket(input, length, position,
                                         &bracket_after)) {
        *has_dynamic_syntax = true;
        return true;
      }
    }
    if (c == '{') {
      size_t nested_after = 0;
      bool nested = false;
      bool nested_dynamic = false;
      if (shell_source_brace_expansion_pair(input, length, position,
                                            &nested_after, &nested,
                                            &nested_dynamic)) {
        if (nested_dynamic) {
          *has_dynamic_syntax = true;
          return true;
        }
        nested_expands = nested_expands || nested;
        position = nested_after;
        continue;
      }
    }
    if (c == '}') {
      *after = position + 1;
      *expands = nested_expands || has_alternative ||
                 shell_source_brace_sequence_expands(input, open + 1, position);
      return true;
    }
    if (c == ',')
      has_alternative = true;
    position++;
  }
  return false;
}

/* Whether a complete shell word needs runtime expansion before it has one
 * static byte spelling. Quoted and escaped bytes are literal; ANSI-C quotes
 * are decoded statically. This rejects parameter and command substitutions,
 * glob syntax, actual brace expansion, and unquoted tilde expansion. Semantic
 * consumers use it before quote removal so they cannot promote a
 * runtime-computed word into a builtin, descriptor name, or concrete path. */
static inline bool shell_source_word_has_dynamic_syntax_with_tilde_policy(
    const char *input, size_t length, bool tilde_is_dynamic) {
  if (!input || length == 0)
    return true;
  bool in_single_quote = false;
  bool in_double_quote = false;
  bool logical_word_start = true;
  for (size_t position = 0; position < length;) {
    char c = input[position];
    if (in_single_quote) {
      if (c == '\'')
        in_single_quote = false;
      position++;
      continue;
    }
    if (c == '\\') {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (continued != position) {
        position = continued;
        continue;
      }
      if (position + 1 >= length)
        return true;
      position += 2;
      logical_word_start = false;
      continue;
    }
    if (!in_double_quote && c == '\'') {
      in_single_quote = true;
      logical_word_start = false;
      position++;
      continue;
    }
    if (c == '"') {
      in_double_quote = !in_double_quote;
      logical_word_start = false;
      position++;
      continue;
    }
    if (!in_double_quote && c == '$' &&
        shell_source_logical_next_is(input, length, position, '\'', NULL)) {
      size_t after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &after))
        return true;
      position = after;
      logical_word_start = false;
      continue;
    }
    if (c == '`' ||
        shell_source_dollar_has_dynamic_syntax(input, length, position))
      return true;
    if (!in_double_quote) {
      if ((c == '<' || c == '>') &&
          shell_source_process_substitution_open(input, length, position, NULL))
        return true;
      if ((c == '?' || c == '*' || c == '+' || c == '@' || c == '!') &&
          shell_source_logical_next_is(input, length, position, '(', NULL))
        return true;
      if (c == '*' || c == '?')
        return true;
      if (c == '[') {
        size_t bracket_after = 0;
        if (shell_source_skip_glob_bracket(input, length, position,
                                           &bracket_after))
          return true;
      }
      if (c == '~' && logical_word_start && tilde_is_dynamic)
        return true;
      if (c == '{') {
        size_t after = 0;
        bool expands = false;
        bool has_dynamic_syntax = false;
        if (shell_source_brace_expansion_pair(input, length, position, &after,
                                              &expands, &has_dynamic_syntax)) {
          if (expands || has_dynamic_syntax)
            return true;
          position = after;
          logical_word_start = false;
          continue;
        }
      }
    }
    logical_word_start = false;
    position++;
  }
  return in_single_quote || in_double_quote;
}

static inline bool shell_source_word_has_dynamic_syntax(const char *input,
                                                        size_t length) {
  return shell_source_word_has_dynamic_syntax_with_tilde_policy(input, length,
                                                                true);
}

/* Decode a complete static shell word without allocating.  This is the
 * source-level counterpart of Shellsplit's processed-word rendering: quote
 * removal and ANSI-C quotes are resolved, while any syntax whose value needs
 * expansion keeps the word out of the static-command path.  Keep wrapper
 * recognition here so semantic validation and dependency analysis cannot
 * grow subtly different interpretations of `command` and `builtin`. */
static inline bool
shell_source_visit_static_word(const char *word, size_t word_length,
                               shell_source_byte_visitor_t visitor,
                               void *context) {
  if (!word || word_length == 0 || !visitor ||
      shell_source_word_has_dynamic_syntax(word, word_length))
    return false;

  char quote = '\0';
  for (size_t position = 0; position < word_length; position++) {
    char c = word[position];
    if (quote == '\0' && c == '$' &&
        shell_source_logical_next_is(word, word_length, position, '\'', NULL)) {
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
        if (next == '\r' && position + 1 < word_length &&
            word[position + 1] == '\n')
          position++;
        continue;
      }
    }
    if (!visitor((unsigned char)c, context))
      return false;
  }
  return quote == '\0';
}

/* Declaration builtins recognize assignment operands after quote removal,
 * unlike an assignment in the shell's command-prefix position. Inspect only
 * the name: expansion in the value does not make a literal write target
 * dynamic. `source_delimiter` is false when ANSI-C decoding produced the
 * equals sign, because that word cannot be split into borrowed name/value
 * source spans. Callers that need those spans must reject that form. */
typedef struct {
  size_t name_end;
  size_t equals;
  size_t name_length;
  bool append;
  bool source_delimiter;
} shell_source_decoded_assignment_t;

typedef struct {
  shell_source_decoded_assignment_t result;
  shell_source_byte_visitor_t visitor;
  void *context;
  size_t source_position;
  size_t plus_position;
  bool pending_plus;
  bool found;
  bool valid;
} shell_source_assignment_scan_t;

static inline bool shell_source_assignment_emit(unsigned char byte,
                                                void *context) {
  shell_source_assignment_scan_t *scan = context;
  if (!scan || !scan->valid)
    return false;
  if (scan->found)
    return true;
  if (byte == '=') {
    if (scan->result.name_length == 0)
      return scan->valid = false;
    scan->result.append = scan->pending_plus;
    scan->result.name_end =
        scan->pending_plus ? scan->plus_position : scan->source_position;
    scan->result.equals = scan->source_position;
    scan->result.source_delimiter =
        scan->source_position != SIZE_MAX &&
        (!scan->pending_plus || scan->plus_position != SIZE_MAX);
    scan->found = true;
    return true;
  }
  if (byte == '+' && scan->result.name_length != 0 && !scan->pending_plus) {
    scan->pending_plus = true;
    scan->plus_position = scan->source_position;
    return true;
  }
  if (scan->pending_plus ||
      (scan->result.name_length == 0 ? !(isalpha(byte) || byte == '_')
                                     : !(isalnum(byte) || byte == '_')))
    return scan->valid = false;
  if (scan->visitor && !scan->visitor(byte, scan->context))
    return scan->valid = false;
  scan->result.name_length++;
  return true;
}

static inline bool shell_source_scan_decoded_assignment(
    const char *word, size_t word_length, shell_source_byte_visitor_t visitor,
    void *context, shell_source_decoded_assignment_t *out) {
  if (out)
    *out = (shell_source_decoded_assignment_t){0};
  if (!word || !out || word_length == 0)
    return false;
  shell_source_assignment_scan_t scan = {
      .visitor = visitor,
      .context = context,
      .valid = true,
  };
  char quote = '\0';
  for (size_t position = 0; position < word_length; position++) {
    char c = word[position];
    if (quote == '\0' && c == '$' &&
        shell_source_logical_next_is(word, word_length, position, '\'', NULL)) {
      size_t after = position;
      scan.source_position = SIZE_MAX;
      if (!shell_source_decode_ansi_c_quote(
              word, word_length, &after, shell_source_assignment_emit, &scan))
        return false;
      if (scan.found) {
        *out = scan.result;
        return true;
      }
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
        position++;
        if (next == '\r' && position + 1 < word_length &&
            word[position + 1] == '\n')
          position++;
        if (next == '\n' || next == '\r')
          continue;
        c = next;
      }
    }
    scan.source_position = position;
    if (!shell_source_assignment_emit((unsigned char)c, &scan))
      return false;
    if (scan.found) {
      *out = scan.result;
      return true;
    }
  }
  return false;
}

typedef struct {
  const char *expected;
  size_t expected_length;
  size_t position;
  bool matches;
} shell_source_static_word_match_t;

static inline bool shell_source_static_word_match_byte(unsigned char byte,
                                                       void *context) {
  shell_source_static_word_match_t *match = context;
  if (!match)
    return false;
  if (match->position >= match->expected_length ||
      byte != (unsigned char)match->expected[match->position])
    match->matches = false;
  match->position++;
  return true;
}

static inline bool shell_source_word_static_equals(const char *word,
                                                   size_t word_length,
                                                   const char *expected) {
  if (!expected)
    return false;
  shell_source_static_word_match_t match = {
      .expected = expected,
      .expected_length = strlen(expected),
      .matches = true,
  };
  return shell_source_visit_static_word(
             word, word_length, shell_source_static_word_match_byte, &match) &&
         match.matches && match.position == match.expected_length;
}

/* Current-shell builtins have effects that matter to Shellsplit's strict
 * semantic boundary and named-descriptor model. Keep their identity in this
 * shared source helper: callers may differ in how they walk command words,
 * but must not grow independent spellings for the same builtin. */
typedef enum {
  SHELL_SOURCE_BUILTIN_NONE,
  SHELL_SOURCE_BUILTIN_ALIAS,
  SHELL_SOURCE_BUILTIN_DECLARE,
  SHELL_SOURCE_BUILTIN_DOT,
  SHELL_SOURCE_BUILTIN_ENABLE,
  SHELL_SOURCE_BUILTIN_EVAL,
  SHELL_SOURCE_BUILTIN_EXEC,
  SHELL_SOURCE_BUILTIN_EXPORT,
  SHELL_SOURCE_BUILTIN_FC,
  SHELL_SOURCE_BUILTIN_GETOPTS,
  SHELL_SOURCE_BUILTIN_LET,
  SHELL_SOURCE_BUILTIN_LOCAL,
  SHELL_SOURCE_BUILTIN_MAPFILE,
  SHELL_SOURCE_BUILTIN_PRINTF,
  SHELL_SOURCE_BUILTIN_POPD,
  SHELL_SOURCE_BUILTIN_PUSHD,
  SHELL_SOURCE_BUILTIN_READ,
  SHELL_SOURCE_BUILTIN_READARRAY,
  SHELL_SOURCE_BUILTIN_READONLY,
  SHELL_SOURCE_BUILTIN_SET,
  SHELL_SOURCE_BUILTIN_SHOPT,
  SHELL_SOURCE_BUILTIN_SOURCE,
  SHELL_SOURCE_BUILTIN_TRAP,
  SHELL_SOURCE_BUILTIN_TYPESET,
  SHELL_SOURCE_BUILTIN_UNALIAS,
  SHELL_SOURCE_BUILTIN_UNSET,
  SHELL_SOURCE_BUILTIN_WAIT,
} shell_source_builtin_kind_t;

static inline shell_source_builtin_kind_t
shell_source_static_builtin_kind(const char *word, size_t word_length) {
  if (shell_source_word_static_equals(word, word_length, "alias"))
    return SHELL_SOURCE_BUILTIN_ALIAS;
  if (shell_source_word_static_equals(word, word_length, "declare"))
    return SHELL_SOURCE_BUILTIN_DECLARE;
  if (shell_source_word_static_equals(word, word_length, "."))
    return SHELL_SOURCE_BUILTIN_DOT;
  if (shell_source_word_static_equals(word, word_length, "enable"))
    return SHELL_SOURCE_BUILTIN_ENABLE;
  if (shell_source_word_static_equals(word, word_length, "eval"))
    return SHELL_SOURCE_BUILTIN_EVAL;
  if (shell_source_word_static_equals(word, word_length, "exec"))
    return SHELL_SOURCE_BUILTIN_EXEC;
  if (shell_source_word_static_equals(word, word_length, "export"))
    return SHELL_SOURCE_BUILTIN_EXPORT;
  if (shell_source_word_static_equals(word, word_length, "fc"))
    return SHELL_SOURCE_BUILTIN_FC;
  if (shell_source_word_static_equals(word, word_length, "getopts"))
    return SHELL_SOURCE_BUILTIN_GETOPTS;
  if (shell_source_word_static_equals(word, word_length, "let"))
    return SHELL_SOURCE_BUILTIN_LET;
  if (shell_source_word_static_equals(word, word_length, "local"))
    return SHELL_SOURCE_BUILTIN_LOCAL;
  if (shell_source_word_static_equals(word, word_length, "mapfile"))
    return SHELL_SOURCE_BUILTIN_MAPFILE;
  if (shell_source_word_static_equals(word, word_length, "printf"))
    return SHELL_SOURCE_BUILTIN_PRINTF;
  if (shell_source_word_static_equals(word, word_length, "popd"))
    return SHELL_SOURCE_BUILTIN_POPD;
  if (shell_source_word_static_equals(word, word_length, "pushd"))
    return SHELL_SOURCE_BUILTIN_PUSHD;
  if (shell_source_word_static_equals(word, word_length, "read"))
    return SHELL_SOURCE_BUILTIN_READ;
  if (shell_source_word_static_equals(word, word_length, "readarray"))
    return SHELL_SOURCE_BUILTIN_READARRAY;
  if (shell_source_word_static_equals(word, word_length, "readonly"))
    return SHELL_SOURCE_BUILTIN_READONLY;
  if (shell_source_word_static_equals(word, word_length, "set"))
    return SHELL_SOURCE_BUILTIN_SET;
  if (shell_source_word_static_equals(word, word_length, "shopt"))
    return SHELL_SOURCE_BUILTIN_SHOPT;
  if (shell_source_word_static_equals(word, word_length, "source"))
    return SHELL_SOURCE_BUILTIN_SOURCE;
  if (shell_source_word_static_equals(word, word_length, "trap"))
    return SHELL_SOURCE_BUILTIN_TRAP;
  if (shell_source_word_static_equals(word, word_length, "typeset"))
    return SHELL_SOURCE_BUILTIN_TYPESET;
  if (shell_source_word_static_equals(word, word_length, "unalias"))
    return SHELL_SOURCE_BUILTIN_UNALIAS;
  if (shell_source_word_static_equals(word, word_length, "unset"))
    return SHELL_SOURCE_BUILTIN_UNSET;
  if (shell_source_word_static_equals(word, word_length, "wait"))
    return SHELL_SOURCE_BUILTIN_WAIT;
  return SHELL_SOURCE_BUILTIN_NONE;
}

typedef struct {
  size_t position;
  bool starts_dash;
} shell_source_static_dash_t;

static inline bool shell_source_static_dash_byte(unsigned char byte,
                                                 void *context) {
  shell_source_static_dash_t *dash = context;
  if (!dash)
    return false;
  if (dash->position == 0)
    dash->starts_dash = byte == '-';
  dash->position++;
  return true;
}

static inline bool shell_source_word_static_starts_dash(const char *word,
                                                        size_t word_length) {
  shell_source_static_dash_t dash = {0};
  return shell_source_visit_static_word(word, word_length,
                                        shell_source_static_dash_byte, &dash) &&
         dash.starts_dash;
}

typedef enum {
  SHELL_SOURCE_COMMAND_OPTION_EXECUTES,
  SHELL_SOURCE_COMMAND_OPTION_INSPECTS,
  SHELL_SOURCE_COMMAND_OPTION_INVALID,
} shell_source_command_option_t;

typedef struct {
  size_t position;
  bool valid;
  bool inspection;
} shell_source_command_option_scan_t;

static inline bool shell_source_command_option_byte(unsigned char byte,
                                                    void *context) {
  shell_source_command_option_scan_t *scan = context;
  if (!scan)
    return false;
  if (scan->position == 0) {
    scan->valid = byte == '-';
  } else if (byte == 'p') {
    /* `command -p` may be repeated or combined. */
  } else if (byte == 'v' || byte == 'V') {
    scan->inspection = true;
  } else {
    scan->valid = false;
  }
  scan->position++;
  return true;
}

/* The `command` builtin's `-v` and `-V` forms inspect rather than execute
 * their operands.  Retaining that distinction prevents an inspection from
 * being misclassified as a current-shell state mutation. */
static inline shell_source_command_option_t
shell_source_classify_command_option(const char *word, size_t word_length) {
  shell_source_command_option_scan_t scan = {0};
  if (!shell_source_visit_static_word(
          word, word_length, shell_source_command_option_byte, &scan) ||
      !scan.valid || scan.position <= 1)
    return SHELL_SOURCE_COMMAND_OPTION_INVALID;
  return scan.inspection ? SHELL_SOURCE_COMMAND_OPTION_INSPECTS
                         : SHELL_SOURCE_COMMAND_OPTION_EXECUTES;
}

typedef enum {
  SHELL_SOURCE_WRAPPER_MORE,
  SHELL_SOURCE_WRAPPER_STATIC_TARGET,
  SHELL_SOURCE_WRAPPER_DYNAMIC_TARGET,
  SHELL_SOURCE_WRAPPER_NONEXECUTING,
} shell_source_wrapper_step_t;

typedef enum {
  SHELL_SOURCE_WRAPPER_NONE,
  SHELL_SOURCE_WRAPPER_COMMAND,
  SHELL_SOURCE_WRAPPER_BUILTIN,
} shell_source_wrapper_kind_t;

typedef struct {
  shell_source_wrapper_kind_t kind;
  bool options;
  /* A redirection attached to `exec` remains in the current shell only when
   * every wrapper in its chain is `command`. `builtin exec` scopes it to the
   * wrapper invocation instead. */
  bool exec_persistent;
} shell_source_wrapper_state_t;

static inline shell_source_wrapper_kind_t
shell_source_wrapper_kind(const char *word, size_t word_length) {
  if (shell_source_word_static_equals(word, word_length, "command"))
    return SHELL_SOURCE_WRAPPER_COMMAND;
  if (shell_source_word_static_equals(word, word_length, "builtin"))
    return SHELL_SOURCE_WRAPPER_BUILTIN;
  return SHELL_SOURCE_WRAPPER_NONE;
}

static inline shell_source_wrapper_step_t
shell_source_wrapper_start(shell_source_wrapper_state_t *state,
                           const char *word, size_t word_length) {
  if (!state || !word || word_length == 0)
    return SHELL_SOURCE_WRAPPER_NONEXECUTING;
  *state = (shell_source_wrapper_state_t){.exec_persistent = true};
  if (shell_source_word_has_dynamic_syntax(word, word_length))
    return SHELL_SOURCE_WRAPPER_DYNAMIC_TARGET;
  state->kind = shell_source_wrapper_kind(word, word_length);
  if (state->kind == SHELL_SOURCE_WRAPPER_NONE)
    return SHELL_SOURCE_WRAPPER_STATIC_TARGET;
  state->options = true;
  state->exec_persistent = state->kind == SHELL_SOURCE_WRAPPER_COMMAND;
  return SHELL_SOURCE_WRAPPER_MORE;
}

static inline shell_source_wrapper_step_t
shell_source_wrapper_consume(shell_source_wrapper_state_t *state,
                             const char *word, size_t word_length) {
  if (!state || state->kind == SHELL_SOURCE_WRAPPER_NONE || !word ||
      word_length == 0)
    return SHELL_SOURCE_WRAPPER_NONEXECUTING;
  if (shell_source_word_has_dynamic_syntax(word, word_length)) {
    state->kind = SHELL_SOURCE_WRAPPER_NONE;
    return SHELL_SOURCE_WRAPPER_DYNAMIC_TARGET;
  }
  if (state->options &&
      shell_source_word_static_equals(word, word_length, "--")) {
    state->options = false;
    return SHELL_SOURCE_WRAPPER_MORE;
  }
  if (state->options &&
      shell_source_word_static_starts_dash(word, word_length)) {
    if (state->kind != SHELL_SOURCE_WRAPPER_COMMAND) {
      state->kind = SHELL_SOURCE_WRAPPER_NONE;
      return SHELL_SOURCE_WRAPPER_NONEXECUTING;
    }
    shell_source_command_option_t option =
        shell_source_classify_command_option(word, word_length);
    if (option == SHELL_SOURCE_COMMAND_OPTION_EXECUTES)
      return SHELL_SOURCE_WRAPPER_MORE;
    state->kind = SHELL_SOURCE_WRAPPER_NONE;
    return SHELL_SOURCE_WRAPPER_NONEXECUTING;
  }

  shell_source_wrapper_kind_t nested =
      shell_source_wrapper_kind(word, word_length);
  if (nested != SHELL_SOURCE_WRAPPER_NONE) {
    state->kind = nested;
    state->options = true;
    state->exec_persistent =
        state->exec_persistent && nested == SHELL_SOURCE_WRAPPER_COMMAND;
    return SHELL_SOURCE_WRAPPER_MORE;
  }
  state->kind = SHELL_SOURCE_WRAPPER_NONE;
  return SHELL_SOURCE_WRAPPER_STATIC_TARGET;
}

/* CWD resolution models the supported leading-tilde forms separately. It
 * still needs the exact same conservative classification for every other
 * expansion, rather than a duplicate scanner that can drift from redirects. */
static inline bool
shell_source_word_has_dynamic_syntax_allow_tilde(const char *input,
                                                 size_t length) {
  return shell_source_word_has_dynamic_syntax_with_tilde_policy(input, length,
                                                                false);
}

/* Redirect topology needs the same static-word rule. The explicit name keeps
 * call sites clear when they must distinguish a concrete FILE DOC from a
 * runtime pathname or a descriptor-ambiguous operand. */
static inline bool
shell_source_redirect_word_has_dynamic_path_syntax(const char *input,
                                                   size_t length) {
  return shell_source_word_has_dynamic_syntax(input, length);
}

/* Skip one complete redirection and its operand. Return the original position
 * when it is not a valid redirect at that offset. This is shared by compound
 * boundary detection and prefix validation so descriptor punctuation never
 * becomes a spurious command separator. */
static inline size_t shell_source_skip_redirect(const char *input,
                                                size_t position, size_t end) {
  if (!input || position >= end)
    return position;
  /* Bash's combined-output operators have no io-number or named-descriptor
   * form.  In `2&>file`, `2` is consequently a shell word followed by an
   * unprefixed `&>` redirect, not a descriptor for that redirect.  Detect
   * these operators before considering descriptor prefixes so compound-tail
   * validation cannot consume that word as part of the redirect. */
  size_t combined_after = position;
  bool combined_output = shell_source_match_logical_punctuation(
                             input, end, position, "&>>", &combined_after) ||
                         shell_source_match_logical_punctuation(
                             input, end, position, "&>", &combined_after);
  size_t cursor = position;
  uint32_t descriptor = 0;
  bool named_fd = false;
  shell_source_io_number_t numeric_fd = SHELL_SOURCE_IO_NUMBER_NONE;
  if (!combined_output) {
    named_fd = shell_source_parse_named_fd(input, position, end, &cursor);
    if (named_fd)
      cursor = shell_source_skip_escaped_line_endings(input, end, cursor);
  }
  if (!combined_output && !named_fd)
    numeric_fd = shell_source_parse_io_number(input, position, end, &cursor,
                                              &descriptor);
  if (numeric_fd == SHELL_SOURCE_IO_NUMBER_OVERFLOW)
    return position;
  /* Bash requires `{name}` immediately before its redirect operator. Numeric
   * io_number syntax also permits no physical whitespace. Escaped physical
   * line endings have already been removed by shell lexical processing, so
   * they may still bridge the descriptor and its operator. */
  if ((named_fd || numeric_fd == SHELL_SOURCE_IO_NUMBER_VALID) &&
      cursor < end && isspace((unsigned char)input[cursor]))
    return position;
  if (combined_output) {
    cursor = combined_after;
  } else {
    cursor = shell_source_skip_inline_continuations(input, end, cursor);
    if (cursor == end || (input[cursor] != '<' && input[cursor] != '>'))
      return position;
  }

  char direction = combined_output ? '>' : input[cursor++];
  bool heredoc = false;
  if (!combined_output && direction == '<') {
    cursor = shell_source_skip_escaped_line_endings(input, end, cursor);
    if (cursor < end && input[cursor] == '<') {
      cursor++;
      cursor = shell_source_skip_escaped_line_endings(input, end, cursor);
      if (cursor < end && input[cursor] == '<') {
        cursor++;
      } else {
        heredoc = true;
        if (cursor < end && input[cursor] == '-')
          cursor++;
      }
    } else if (cursor < end && input[cursor] == '>') {
      /* `< >` is the read/write redirect. It shares the `<` prefix with a
       * here-document, but is not part of that branch. */
      cursor++;
    }
  } else if (!combined_output) {
    cursor = shell_source_skip_escaped_line_endings(input, end, cursor);
    if (direction == '>' && cursor < end &&
        (input[cursor] == '>' || input[cursor] == '|')) {
      cursor++;
    }
  }

  cursor = shell_source_skip_escaped_line_endings(input, end, cursor);
  size_t operator_end = cursor;
  cursor = shell_source_skip_inline_continuations(input, end, cursor);
  size_t operand = cursor;
  if (!heredoc && cursor < end && input[cursor] == '&') {
    cursor++;
    cursor = shell_source_skip_inline_continuations(input, end, cursor);
    /* A duplication target is usually one complete shell word. The raw close
     * marker is the exception: Bash recognizes the immediate `-` in
     * `>&-file` as `>&-`, then parses `file` as the following command word.
     * Preserve that lexical boundary here. Quoted and escaped spellings still
     * take the normal whole-word path and are classified after decoding. */
    if (cursor < end && input[cursor] == '-') {
      cursor++;
    } else if (cursor < end && (input[cursor] == '<' || input[cursor] == '>')) {
      /* `>& >(consumer)` uses Bash's legacy combined-output spelling. Its
       * operand is still one process-substitution word, not a second redirect
       * that ends the surrounding redirect list. */
      size_t open = 0;
      if (!shell_source_process_substitution_open(input, end, cursor, &open))
        return position;
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(input, end, open, &after))
        return position;
      cursor = shell_source_skip_redirect_word(input, after, end);
    } else {
      cursor = shell_source_skip_redirect_word(input, cursor, end);
    }
  } else if (cursor < end && (input[cursor] == '<' || input[cursor] == '>')) {
    /* A process-substitution operand remains one redirect operand even when
     * whitespace separates it from its redirection operator: `> >(cmd)` and
     * `< <(cmd)`. */
    size_t open = 0;
    if (!shell_source_process_substitution_open(input, end, cursor, &open))
      return position;
    size_t after = 0;
    if (!shell_source_find_balanced_parentheses(input, end, open, &after))
      return position;
    cursor = shell_source_skip_redirect_word(input, after, end);
  } else if (cursor < end && cursor == operator_end && input[cursor] == '(') {
    size_t after = 0;
    if (!shell_source_find_balanced_parentheses(input, end, cursor, &after))
      return position;
    cursor = shell_source_skip_redirect_word(input, after, end);
  } else if (heredoc) {
    /* A heredoc delimiter follows shell-word rules, including its special
     * comment boundary. Do not route it through the generic redirect-word
     * scanner: after `<<-`, a raw hash is still a comment even though its
     * immediately preceding source byte is the operator's dash. */
    shell_source_pending_heredoc_t pending = {0};
    if (!shell_source_parse_heredoc_delimiter(input, end, &cursor, &pending))
      return position;
  } else {
    cursor = shell_source_skip_redirect_word(input, cursor, end);
  }
  return operand == cursor ? position : cursor;
}

/* Shellclave rejects a complete redirection list immediately before a
 * compound-group delimiter. Keep that policy identical in both tokenizers;
 * this scanner recognizes every redirect spelling accepted by the fast path,
 * including read/write, clobber, and descriptor forms. */
static inline bool shell_source_redirect_list_before_group(const char *input,
                                                           size_t start,
                                                           size_t end) {
  if (!input || start > end)
    return false;
  size_t position = start;
  bool found = false;
  while (position < end) {
    position = shell_source_skip_inline_continuations(input, end, position);
    if (position == end)
      return found;
    size_t next = shell_source_skip_redirect(input, position, end);
    if (next == position)
      return false;
    position = next;
    found = true;
  }
  return found;
}

#endif
