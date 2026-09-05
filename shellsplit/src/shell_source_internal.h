#ifndef SHELL_SOURCE_INTERNAL_H
#define SHELL_SOURCE_INTERNAL_H

#include "shell_tokenizer.h"
#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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
  while (position < end && isdigit((unsigned char)input[position])) {
    uint32_t digit = (uint32_t)(input[position] - '0');
    if (value > ((uint64_t)INT_MAX - digit) / 10u) {
      while (++position < end && isdigit((unsigned char)input[position]))
        ;
      *after = position;
      return SHELL_SOURCE_IO_NUMBER_OVERFLOW;
    }
    value = value * 10u + digit;
    position++;
  }
  *after = position;
  if (position == start)
    return SHELL_SOURCE_IO_NUMBER_NONE;
  *descriptor = (uint32_t)value;
  return SHELL_SOURCE_IO_NUMBER_VALID;
}

/* Bash's {name}>word descriptor allocator. The braces and the redirect must
 * be adjacent; whitespace or an invalid shell identifier leaves the text an
 * ordinary shell word/group delimiter. */
static inline bool shell_source_parse_named_fd(const char *input, size_t start,
                                               size_t end, size_t *after,
                                               size_t *name_start,
                                               size_t *name_length) {
  if (after)
    *after = start;
  if (name_start)
    *name_start = 0;
  if (name_length)
    *name_length = 0;
  if (!input || !after || !name_start || !name_length || start + 3 > end ||
      input[start] != '{' ||
      !(isalpha((unsigned char)input[start + 1]) || input[start + 1] == '_'))
    return false;
  size_t position = start + 2;
  while (position < end &&
         (isalnum((unsigned char)input[position]) || input[position] == '_'))
    position++;
  if (position >= end || input[position] != '}')
    return false;
  *name_start = start + 1;
  *name_length = position - *name_start;
  *after = position + 1;
  return true;
}

/* The lexical source scanner must accept every pending heredoc that the fast
 * tokenizer can represent. Dependency-graph document limits remain separate
 * and are enforced only when a graph is built. */
#define SHELL_SOURCE_MAX_PENDING_HEREDOCS SHELL_MAX_SUBCOMMANDS

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

/* A comment begins only at an unquoted shell-word boundary. Keep this shared
 * with the balanced scanners so a parenthesis in comment text cannot terminate
 * a command or process substitution. */
static inline bool shell_source_comment_starts(const char *input, size_t length,
                                               size_t position) {
  if (!input || position >= length || input[position] != '#')
    return false;
  if (position == 0)
    return true;
  char previous = input[position - 1];
  return isspace((unsigned char)previous) || previous == ';' ||
         previous == '|' || previous == '&' || previous == '(' ||
         previous == ')';
}

/* Skip one quoted shell fragment, including its opening delimiter. The
 * lexical helpers below deliberately tolerate an unterminated quote: callers
 * that require a complete command validate that separately. */
static inline size_t shell_source_skip_quoted_text(const char *input,
                                                   size_t length,
                                                   size_t position,
                                                   char quote) {
  position++;
  while (position < length) {
    if (input[position] == '\\' && quote != '\'' && position + 1 < length) {
      position += 2;
    } else if (input[position++] == quote) {
      break;
    }
  }
  return position;
}

/* Bash ANSI-C quotes are a single shell-word fragment. */
static inline size_t shell_source_skip_ansi_c_quote(const char *input,
                                                    size_t length,
                                                    size_t position) {
  if (!input || position + 1 >= length || input[position] != '$' ||
      input[position + 1] != '\'')
    return position;
  position += 2;
  while (position < length) {
    if (input[position] == '\\' && position + 1 < length) {
      position += 2;
    } else if (input[position++] == '\'') {
      break;
    }
  }
  return position;
}

/* Return the byte after one complete ANSI-C quote. Keeping completion checking
 * beside the lexical skipper prevents structural scanners from accidentally
 * treating an escaped apostrophe in $'...' as the end of a plain single quote.
 */
static inline bool shell_source_skip_complete_ansi_c_quote(const char *input,
                                                           size_t length,
                                                           size_t position,
                                                           size_t *after) {
  if (!after)
    return false;
  size_t quoted = shell_source_skip_ansi_c_quote(input, length, position);
  if (quoted <= position + 2 || quoted > length || input[quoted - 1] != '\'')
    return false;
  *after = quoted;
  return true;
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
  if (!text || !position || *position + 1 >= length || text[*position] != '$' ||
      text[*position + 1] != '\'')
    return false;
  *position += 2;
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
  size_t cursor = *position;
  pending->strip_tabs = false;
  if (cursor < length && input[cursor] == '-') {
    pending->strip_tabs = true;
    cursor++;
  }
  while (cursor < length && (input[cursor] == ' ' || input[cursor] == '\t'))
    cursor++;
  if (cursor == length)
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
           input[cursor + 1] == '\n')) {
        cursor += 2;
      } else {
        cursor++;
      }
      continue;
    }
    if (c == '\\') {
      if (cursor + 1 >= length)
        return false;
      cursor += 2;
      continue;
    }
    if (c == '$' && cursor + 1 < length && input[cursor + 1] == '\'') {
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
  /* Bash stores a heredoc delimiter as a C string: the first ANSI-C NUL
   * terminates its spelling and any remaining quote bytes are irrelevant. */
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
    if (quote == '\0' && c == '$' && word < pending->word_length &&
        pending->word[word] == '\'') {
      size_t position = word - 1;
      if (!shell_source_decode_ansi_c_quote(
              pending->word, pending->word_length, &position,
              shell_source_match_heredoc_byte, &match))
        return false;
      word = position;
      continue;
    }
    if (quote != '\0') {
      if (c == quote) {
        quote = '\0';
        continue;
      }
      if (c == '\\' && quote == '"' && word < pending->word_length &&
          (pending->word[word] == '$' || pending->word[word] == '`' ||
           pending->word[word] == '"' || pending->word[word] == '\\' ||
           pending->word[word] == '\n'))
        c = pending->word[word++];
    } else if (c == '\'' || c == '"') {
      quote = c;
      continue;
    } else if (c == '\\') {
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

/* Consume the bodies for a FIFO sequence of declarations after their shared
 * declaration line. A missing terminator is reported separately from the
 * sentinel end position so tolerant lexical callers can still treat the
 * remainder as document data, while strict parsers reject it. */
static inline bool shell_source_skip_pending_heredoc_bodies(
    const char *input, size_t length, size_t line,
    const shell_source_pending_heredoc_t *pending, size_t pending_count,
    size_t *after) {
  if (!input || !pending || !after)
    return false;
  for (size_t h = 0; h < pending_count; h++) {
    bool found = false;
    while (line < length) {
      if (shell_source_line_is_heredoc_delimiter(input, length, line,
                                                 &pending[h])) {
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

/* Skip every pending document declared on one physical line beginning at a
 * here-document operator. The declaration scanner keeps quoted and nested
 * substitutions opaque, then hands the FIFO body matching to the shared
 * routine above. It is deliberately a lexical helper: callers choose whether
 * an unterminated document is tolerated or rejected. */
static inline bool shell_source_skip_heredoc_sequence(const char *input,
                                                      size_t length,
                                                      size_t position,
                                                      size_t *after,
                                                      bool *complete) {
  if (!input || !after || !complete || position + 1 >= length ||
      input[position] != '<' || input[position + 1] != '<' ||
      (position + 2 < length && input[position + 2] == '<'))
    return false;

  shell_source_pending_heredoc_t pending[SHELL_SOURCE_MAX_PENDING_HEREDOCS];
  size_t pending_count = 0;
  size_t line_end = shell_source_line_end(input, length, position);
  size_t cursor = position;
  while (cursor < line_end) {
    char c = input[cursor];
    if (c == '\\' && cursor + 1 < line_end) {
      cursor += 2;
      continue;
    }
    if (c == '$' && cursor + 1 < line_end && input[cursor + 1] == '\'') {
      size_t quoted = shell_source_skip_ansi_c_quote(input, line_end, cursor);
      if (quoted <= cursor + 2 || quoted > line_end ||
          input[quoted - 1] != '\'')
        return false;
      cursor = quoted;
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      size_t quoted = shell_source_skip_quoted_text(input, line_end, cursor, c);
      if (quoted > line_end)
        return false;
      cursor = quoted;
      continue;
    }
    if (c == '#' && shell_source_comment_starts(input, length, cursor))
      break;
    if (c == '$' && cursor + 2 < line_end && input[cursor + 1] == '(' &&
        input[cursor + 2] == '(') {
      size_t after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, line_end, cursor,
                                                  &after))
        return false;
      cursor = after;
      continue;
    }
    if ((c == '$' || c == '<' || c == '>') && cursor + 1 < line_end &&
        input[cursor + 1] == '(') {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(input, line_end, cursor + 1,
                                                  &after))
        return false;
      cursor = after;
      continue;
    }
    if (c == '<' && cursor + 2 < line_end && input[cursor + 1] == '<' &&
        input[cursor + 2] == '<') {
      cursor += 3;
      continue;
    }
    if (c == '<' && cursor + 1 < line_end && input[cursor + 1] == '<') {
      if (pending_count == sizeof(pending) / sizeof(pending[0]))
        return false;
      size_t delimiter = cursor + 2;
      if (!shell_source_parse_heredoc_delimiter(input, line_end, &delimiter,
                                                &pending[pending_count]))
        return false;
      pending_count++;
      cursor = delimiter;
      continue;
    }
    cursor++;
  }

  if (pending_count == 0)
    return false;
  size_t bodies = shell_source_next_line(input, length, line_end);
  *complete = shell_source_skip_pending_heredoc_bodies(
      input, length, bodies, pending, pending_count, after);
  return true;
}

/* Skip one arithmetic expansion at its leading `$`.  Arithmetic syntax uses
 * `<<` as an ordinary shift operator, so callers that are looking for shell
 * redirections must keep the complete `$((...))` opaque. Nested command and
 * arithmetic substitutions remain independently balanced. */
static inline bool shell_source_skip_arithmetic_expansion(const char *input,
                                                          size_t length,
                                                          size_t position,
                                                          size_t *after) {
  if (!input || !after || position + 2 >= length || input[position] != '$' ||
      input[position + 1] != '(' || input[position + 2] != '(')
    return false;

  size_t depth = 1;
  for (position += 3; position < length; position++) {
    char c = input[position];
    if (c == '\\' && position + 1 < length) {
      position++;
    } else if (c == '$' && position + 1 < length &&
               input[position + 1] == '\'') {
      size_t quoted = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &quoted))
        return false;
      position = quoted - 1;
    } else if (c == '\'' || c == '"' || c == '`') {
      position = shell_source_skip_quoted_text(input, length, position, c) - 1;
    } else if (c == '$' && position + 2 < length &&
               input[position + 1] == '(' && input[position + 2] == '(') {
      size_t nested_after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &nested_after))
        return false;
      position = nested_after - 1;
    } else if (c == '$' && position + 1 < length &&
               input[position + 1] == '(') {
      size_t nested_after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                                  &nested_after))
        return false;
      position = nested_after - 1;
    } else if (c == '(') {
      depth++;
    } else if (c == ')') {
      if (depth > 1) {
        depth--;
      } else if (position + 1 < length && input[position + 1] == ')') {
        *after = position + 2;
        return true;
      } else {
        return false;
      }
    }
  }
  return false;
}

/* Find the byte after a balanced shell fragment at an opening `(`. Quoting,
 * escapes, comments, nested substitutions, and deferred heredoc bodies remain
 * opaque while matching parentheses. Returns false for an unterminated or
 * malformed fragment; shell_source_skip_balanced_parentheses() maps that
 * failure to `length` for callers that need a sentinel position. */
static inline bool shell_source_find_balanced_parentheses(const char *input,
                                                          size_t length,
                                                          size_t position,
                                                          size_t *after) {
  if (!input || !after || position >= length || input[position] != '(')
    return false;
  size_t depth = 1;
  shell_source_pending_heredoc_t pending[SHELL_SOURCE_MAX_PENDING_HEREDOCS];
  size_t pending_count = 0;
  for (position++; position < length && depth > 0; position++) {
    char c = input[position];
    if (c == '\\' && position + 1 < length) {
      position++;
    } else if (c == '$' && position + 1 < length &&
               input[position + 1] == '\'') {
      size_t quoted = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &quoted))
        return false;
      position = quoted - 1;
    } else if (c == '\'' || c == '"') {
      position = shell_source_skip_quoted_text(input, length, position, c) - 1;
    } else if (c == '`') {
      position = shell_source_skip_quoted_text(input, length, position, c) - 1;
    } else if (c == '#' &&
               shell_source_comment_starts(input, length, position)) {
      /* Leave a newline visible for deferred heredoc-body processing. */
      size_t line_end = shell_source_line_end(input, length, position);
      position = line_end == length ? length - 1 : line_end - 1;
    } else if (c == '$' && position + 2 < length &&
               input[position + 1] == '(' && input[position + 2] == '(') {
      size_t arithmetic_after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &arithmetic_after))
        return false;
      position = arithmetic_after - 1;
    } else if (c == '<' && position + 2 < length &&
               input[position + 1] == '<' && input[position + 2] == '<') {
      position += 2;
    } else if (c == '<' && position + 1 < length &&
               input[position + 1] == '<') {
      size_t delimiter_position = position + 2;
      if (pending_count == sizeof(pending) / sizeof(pending[0]) ||
          !shell_source_parse_heredoc_delimiter(
              input, length, &delimiter_position, &pending[pending_count]))
        return false;
      pending_count++;
      position = delimiter_position - 1;
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
      position++;
    } else if (c == '$' && position + 1 < length &&
               input[position + 1] == '\'') {
      size_t quoted = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &quoted))
        return false;
      position = quoted - 1;
    } else if (c == '\'' || c == '"' || c == '`') {
      size_t quoted = shell_source_skip_quoted_text(input, length, position, c);
      if (quoted <= position + 1 || quoted > length || input[quoted - 1] != c)
        return false;
      position = quoted - 1;
    } else if (c == '$' && position + 2 < length &&
               input[position + 1] == '(' && input[position + 2] == '(') {
      size_t arithmetic_after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &arithmetic_after))
        return false;
      position = arithmetic_after - 1;
    } else if (c == '$' && position + 1 < length &&
               input[position + 1] == '(') {
      size_t substitution_after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                                  &substitution_after))
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
  if (!input || !after || !subscript_start || position + 2 >= length ||
      input[position] != '$' || input[position + 1] != '{')
    return false;

  *subscript_start = 0;
  size_t cursor = position + 2;
  if (cursor < length && (input[cursor] == '#' || input[cursor] == '!'))
    cursor++;
  if (cursor >= length ||
      !(isalpha((unsigned char)input[cursor]) || input[cursor] == '_'))
    return false;
  while (cursor < length &&
         (isalnum((unsigned char)input[cursor]) || input[cursor] == '_'))
    cursor++;
  if (cursor >= length || input[cursor] != '[')
    return false;

  *subscript_start = cursor;
  return shell_source_skip_array_subscript(input, length, cursor, after);
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
static inline bool shell_source_skip_shell_word(const char *input,
                                                size_t length, size_t position,
                                                size_t *after) {
  if (!input || !after || position > length)
    return false;
  while (position < length) {
    char c = input[position];
    if (c == '$' && position + 1 < length && input[position + 1] == '\'') {
      size_t quoted = shell_source_skip_ansi_c_quote(input, length, position);
      if (quoted <= position + 2 || quoted > length ||
          input[quoted - 1] != '\'')
        return false;
      position = quoted;
      continue;
    }
    if (c == '\\') {
      if (position + 1 >= length)
        return false;
      position += 2;
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      size_t quoted = shell_source_skip_quoted_text(input, length, position, c);
      if (quoted <= position + 1 || quoted > length || input[quoted - 1] != c)
        return false;
      position = quoted;
      continue;
    }
    if (c == '$' && position + 2 < length && input[position + 1] == '(' &&
        input[position + 2] == '(') {
      size_t arithmetic_after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &arithmetic_after))
        return false;
      position = arithmetic_after;
      continue;
    }
    if ((c == '$' || c == '<' || c == '>') && position + 1 < length &&
        input[position + 1] == '(') {
      size_t substitution_after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                                  &substitution_after))
        return false;
      position = substitution_after;
      continue;
    }
    if (isspace((unsigned char)c) || c == '|' || c == ';' || c == '&' ||
        c == '<' || c == '>' || c == '\n' || c == '\r')
      break;
    position++;
  }
  *after = position;
  return true;
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
    if (c == '$' && position + 1 < end && input[position + 1] == '\'') {
      size_t quoted = shell_source_skip_ansi_c_quote(input, end, position);
      if (quoted <= position + 2 || quoted > end || input[quoted - 1] != '\'')
        return end;
      position = quoted;
      continue;
    }
    if (c == '\\' && position + 1 < end) {
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
    if (c == '$' && position + 2 < end && input[position + 1] == '(' &&
        input[position + 2] == '(') {
      size_t after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, end, position, &after))
        return end;
      position = after;
      continue;
    }
    if ((c == '$' || c == '<' || c == '>') && position + 1 < end &&
        input[position + 1] == '(') {
      position =
          shell_source_skip_balanced_parentheses(input, end, position + 1);
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

/* Skip one complete redirection and its operand. Return the original position
 * when it is not a valid redirect at that offset. This is shared by compound
 * boundary detection and prefix validation so descriptor punctuation never
 * becomes a spurious command separator. */
static inline size_t shell_source_skip_redirect(const char *input,
                                                size_t position, size_t end) {
  if (!input || position >= end)
    return position;
  size_t cursor = position;
  uint32_t descriptor = 0;
  size_t name_start = 0, name_length = 0;
  bool named_fd = shell_source_parse_named_fd(input, position, end, &cursor,
                                              &name_start, &name_length);
  if (!named_fd && shell_source_parse_io_number(input, position, end, &cursor,
                                                &descriptor) ==
                       SHELL_SOURCE_IO_NUMBER_OVERFLOW)
    return position;
  /* Bash requires `{name}` immediately before its redirect operator. Numeric
   * io_number syntax permits no whitespace either, but only named FDs need
   * this explicit check because their closing brace is otherwise a word. */
  if (named_fd && cursor < end && isspace((unsigned char)input[cursor]))
    return position;
  while (cursor < end && isspace((unsigned char)input[cursor]))
    cursor++;
  bool combined_output =
      cursor + 1 < end && input[cursor] == '&' && input[cursor + 1] == '>';
  if (combined_output)
    cursor++;
  if (cursor == end || (input[cursor] != '<' && input[cursor] != '>'))
    return position;

  char direction = input[cursor++];
  bool heredoc = false;
  if (direction == '<' && cursor < end && input[cursor] == '<') {
    cursor++;
    if (cursor < end && input[cursor] == '<') {
      cursor++;
    } else {
      heredoc = true;
      if (cursor < end && input[cursor] == '-')
        cursor++;
    }
  } else if (cursor < end && ((direction == '>' && (input[cursor] == '>' ||
                                                    input[cursor] == '|')) ||
                              (direction == '<' && input[cursor] == '>'))) {
    cursor++;
  }

  size_t operator_end = cursor;
  while (cursor < end && isspace((unsigned char)input[cursor]))
    cursor++;
  size_t operand = cursor;
  if (!heredoc && cursor < end && input[cursor] == '&') {
    cursor++;
    if (cursor < end && input[cursor] == '-') {
      cursor++;
    } else {
      size_t target = cursor;
      while (cursor < end && isdigit((unsigned char)input[cursor]))
        cursor++;
      if (target == cursor)
        return position;
    }
  } else if (cursor + 1 < end &&
             (input[cursor] == '<' || input[cursor] == '>') &&
             input[cursor + 1] == '(') {
    /* A process-substitution operand remains one redirect operand even when
     * whitespace separates it from its redirection operator: `> >(cmd)` and
     * `< <(cmd)`. */
    size_t after = 0;
    if (!shell_source_find_balanced_parentheses(input, end, cursor + 1, &after))
      return position;
    cursor = after;
  } else if (cursor < end && cursor == operator_end && input[cursor] == '(') {
    size_t after = 0;
    if (!shell_source_find_balanced_parentheses(input, end, cursor, &after))
      return position;
    cursor = after;
  } else {
    cursor = shell_source_skip_redirect_word(input, cursor, end);
  }
  (void)combined_output;
  (void)named_fd;
  (void)name_start;
  (void)name_length;
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
    while (position < end && isspace((unsigned char)input[position]))
      position++;
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
