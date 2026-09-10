#ifndef SHELL_SOURCE_INTERNAL_H
#define SHELL_SOURCE_INTERNAL_H

#include "shell_tokenizer.h"
#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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
 * operator. A raw physical line ending or comment terminates `!` rather than
 * supplying its pipeline stage; only horizontal whitespace and an escaped
 * physical line ending may separate it from the following command. */
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

  size_t cursor = *position;
  unsigned char c = (unsigned char)input[cursor];
  if (isalpha(c) || c == '_') {
    cursor++;
    while (cursor < length) {
      c = (unsigned char)input[cursor];
      if (!(isalnum(c) || c == '_'))
        break;
      cursor++;
    }
  } else if (isdigit(c)) {
    do {
      cursor++;
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

  bool indirect = false;
  if (input[position] == '#') {
    if (position + 1 >= length)
      return false;
    if (input[position + 1] == '}') {
      *after = position + 1;
      return true;
    }
    /* `${##word}` means pattern removal from the special `$#`, not the
     * length of a parameter named `#word`. Leave the first `#` for the base
     * selector so the second one is recognized as its operator. */
    if (input[position + 1] != '#')
      position++;
  } else if (input[position] == '!') {
    position++;
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

  if (position < length && input[position] == '[') {
    size_t subscript_after = 0;
    if (!shell_source_skip_array_subscript(input, length, position,
                                           &subscript_after))
      return false;
    position = subscript_after;
  }

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

  char op = input[position++];
  switch (op) {
  case ':':
    if (position < length &&
        (input[position] == '-' || input[position] == '=' ||
         input[position] == '+' || input[position] == '?'))
      position++;
    break;
  case '#':
  case '%':
  case '^':
  case ',':
    if (position < length && input[position] == op)
      position++;
    break;
  case '/':
    if (position < length && (input[position] == '/' ||
                              input[position] == '#' || input[position] == '%'))
      position++;
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

/* Skip one complete `${...}` expansion. The parameter word can contain shell
 * syntax of its own, so list punctuation, redirects, and nested substitutions
 * do not become outer command-list syntax. A raw `{` is an ordinary parameter
 * word byte: only a nested `${...}` changes the closing-brace depth. Keep this
 * scanner shared by the fast source parser and the full tokenizer so a valid
 * expansion cannot be accepted by one surface and split by another. */
static inline bool shell_source_skip_parameter_expansion(const char *input,
                                                         size_t length,
                                                         size_t position,
                                                         size_t *after) {
  if (!input || !after || position + 2 >= length || input[position] != '$' ||
      input[position + 1] != '{' || input[position + 2] == '}')
    return false;

  if (!shell_source_skip_parameter_selector(input, length, position + 2,
                                            &position))
    return false;
  if (position < length && input[position] == '}') {
    *after = position + 1;
    return true;
  }
  if (!shell_source_parameter_word_operator(input, length, position, &position))
    return false;

  for (; position < length; position++) {
    char c = input[position];
    if (c == '\\' && position + 1 < length) {
      position++;
      continue;
    }
    if (c == '$' && position + 1 < length && input[position + 1] == '\'') {
      size_t quoted = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &quoted))
        return false;
      position = quoted - 1;
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      size_t quoted = shell_source_skip_quoted_text(input, length, position, c);
      if (quoted <= position + 1 || quoted > length || input[quoted - 1] != c)
        return false;
      position = quoted - 1;
      continue;
    }
    if (c == '$' && position + 1 < length && input[position + 1] == '{') {
      size_t parameter_after = 0;
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 &parameter_after))
        return false;
      position = parameter_after - 1;
      continue;
    }
    if (c == '$' && position + 2 < length && input[position + 1] == '(' &&
        input[position + 2] == '(') {
      size_t arithmetic_after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &arithmetic_after))
        return false;
      position = arithmetic_after - 1;
      continue;
    }
    if ((c == '$' || c == '<' || c == '>') && position + 1 < length &&
        input[position + 1] == '(') {
      size_t substitution_after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                                  &substitution_after))
        return false;
      position = substitution_after - 1;
      continue;
    }
    if (c == '}') {
      *after = position + 1;
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
  if (!input || !after || position + 1 >= length || input[position] != '$')
    return false;
  if (input[position + 1] == '{')
    return shell_source_skip_parameter_expansion(input, length, position,
                                                 after);

  char next = input[position + 1];
  if (isdigit((unsigned char)next) || next == '#' || next == '?' ||
      next == '$' || next == '!' || next == '@' || next == '*' || next == '-') {
    *after = position + 2;
    return true;
  }
  if (!(isalpha((unsigned char)next) || next == '_'))
    return false;

  position += 2;
  while (position < length &&
         (isalnum((unsigned char)input[position]) || input[position] == '_'))
    position++;
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
        position + 1 < length && input[position + 1] == '\'') {
      size_t ansi_after = 0;
      if (shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                  &ansi_after)) {
        scan->position = ansi_after;
        continue;
      }
    }
    if (c == '\\' && !scan->in_single_quote && position + 1 < length) {
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
  if (!input || !after || position + 1 >= length ||
      (input[position] != '?' && input[position] != '*' &&
       input[position] != '+' && input[position] != '@' &&
       input[position] != '!') ||
      input[position + 1] != '(')
    return false;
  return shell_source_find_balanced_parentheses(input, length, position + 1,
                                                after);
}

/* Recognize a direct process-substitution operand, not a concatenated word.
 * The matching close must consume the whole bounded source span. */
static inline bool shell_source_word_is_process_substitution(const char *input,
                                                             size_t length) {
  size_t after = 0;
  return input && length >= 3 && (input[0] == '<' || input[0] == '>') &&
         input[1] == '(' &&
         shell_source_find_balanced_parentheses(input, length, 1, &after) &&
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
      position += 2;
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      size_t after = shell_source_skip_quoted_text(input, length, position, c);
      if (after <= position + 1 || after > length || input[after - 1] != c)
        return false;
      position = after;
      continue;
    }
    if (c == '$' && position + 1 < length && input[position + 1] == '{') {
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
    if (c == '$' && position + 2 < length && input[position + 1] == '(' &&
        input[position + 2] == '(') {
      size_t after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &after))
        return false;
      position = after;
      continue;
    }
    if ((c == '<' || c == '>') && position + 1 < length &&
        input[position + 1] == '(') {
      size_t after = 0;
      return shell_source_find_balanced_parentheses(input, length, position + 1,
                                                    &after);
    }
    if (c == '$' && position + 1 < length && input[position + 1] == '(') {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                                  &after))
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
 * process substitutions do not.  Single quotes, ANSI-C quotes, and escaped
 * spellings are literal.  The tokenizer has already established balanced
 * source structure for callers of this helper, so this is intentionally a
 * feature predicate rather than another parser. */
static inline bool
shell_source_word_has_executable_substitution(const char *input,
                                              size_t length) {
  if (!input)
    return false;

  bool in_single_quote = false;
  bool in_double_quote = false;
  for (size_t position = 0; position < length; position++) {
    char c = input[position];
    if (!in_single_quote && !in_double_quote && c == '$' &&
        position + 1 < length && input[position + 1] == '\'') {
      size_t after = 0;
      if (shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                  &after)) {
        position = after - 1;
        continue;
      }
    }
    if (c == '\\' && !in_single_quote && position + 1 < length) {
      position++;
      continue;
    }
    if (c == '\'' && !in_double_quote) {
      in_single_quote = !in_single_quote;
      continue;
    }
    if (c == '"' && !in_single_quote) {
      in_double_quote = !in_double_quote;
      continue;
    }
    if (in_single_quote)
      continue;
    if (c == '`')
      return true;
    if (c == '$' && position + 1 < length && input[position + 1] == '(' &&
        !(position + 2 < length && input[position + 2] == '('))
      return true;
    if (!in_double_quote && (c == '<' || c == '>') && position + 1 < length &&
        input[position + 1] == '(')
      return true;
  }
  return false;
}

/* Stateful iterator for executable substitution spans in one complete shell
 * word.  Unlike shell_source_word_has_executable_substitution(), this exposes
 * source spans so diagnostic consumers can replace direct substitutions
 * without splitting the surrounding argv word.  Arithmetic expansions stay
 * opaque here: callers still use the feature predicate above to report a
 * command substitution nested in arithmetic, while this iterator avoids
 * mistaking arithmetic comparison syntax for a process substitution. */
typedef enum {
  SHELL_SOURCE_SUBST_COMMAND = 0,
  SHELL_SOURCE_SUBST_BACKTICK,
  SHELL_SOURCE_SUBST_PROCESS_INPUT,
  SHELL_SOURCE_SUBST_PROCESS_OUTPUT,
} shell_source_substitution_kind_t;

typedef struct {
  size_t position;
  bool in_single_quote;
  bool in_double_quote;
} shell_source_substitution_scan_t;

static inline bool shell_source_next_executable_substitution(
    const char *input, size_t length, shell_source_substitution_scan_t *scan,
    size_t *start, size_t *after, shell_source_substitution_kind_t *kind) {
  if (!input || !scan || !start || !after || !kind)
    return false;

  while (scan->position < length) {
    size_t position = scan->position;
    char c = input[position];
    if (!scan->in_single_quote && !scan->in_double_quote && c == '$' &&
        position + 1 < length && input[position + 1] == '\'') {
      size_t ansi_after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &ansi_after))
        return false;
      scan->position = ansi_after;
      continue;
    }
    if (c == '\\' && !scan->in_single_quote && position + 1 < length) {
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
    if (scan->in_single_quote) {
      scan->position++;
      continue;
    }
    if (c == '`') {
      size_t substitution_after =
          shell_source_skip_quoted_text(input, length, position, '`');
      if (substitution_after <= position + 1 || substitution_after > length ||
          input[substitution_after - 1] != '`')
        return false;
      *start = position;
      *after = substitution_after;
      *kind = SHELL_SOURCE_SUBST_BACKTICK;
      scan->position = substitution_after;
      return true;
    }
    if (c == '$' && position + 2 < length && input[position + 1] == '(' &&
        input[position + 2] == '(') {
      size_t arithmetic_after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &arithmetic_after))
        return false;
      scan->position = arithmetic_after;
      continue;
    }
    if (c == '$' && position + 1 < length && input[position + 1] == '(') {
      size_t substitution_after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, position + 1,
                                                  &substitution_after))
        return false;
      *start = position;
      *after = substitution_after;
      *kind = SHELL_SOURCE_SUBST_COMMAND;
      scan->position = substitution_after;
      return true;
    }
    if (!scan->in_double_quote && (c == '<' || c == '>') &&
        position + 1 < length && input[position + 1] == '(') {
      size_t substitution_after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, position + 1,
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
    if (c == '$' && position + 1 < length && input[position + 1] == '{') {
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
      if (input[position - 1] == '\r' && position < length &&
          input[position] == '\n')
        position++;
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
    if (c == '<' && position + 1 < target && input[position + 1] == '<') {
      bool complete = false;
      if (shell_source_skip_heredoc_sequence(input, length, position, &next,
                                             &complete) &&
          complete && next <= target) {
        position = next;
        continue;
      }
    }
    if (c == '{' && position + 1 < length &&
        (isspace((unsigned char)input[position + 1]) ||
         input[position + 1] == '(')) {
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
        ((c == '<' || c == '>') &&
         !(position + 1 < length && input[position + 1] == '('))) {
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
    if (c == '$' && position + 1 < end && input[position + 1] == '{') {
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
  /* Bash's combined-output operators have no io-number or named-descriptor
   * form.  In `2&>file`, `2` is consequently a shell word followed by an
   * unprefixed `&>` redirect, not a descriptor for that redirect.  Detect
   * these operators before considering descriptor prefixes so compound-tail
   * validation cannot consume that word as part of the redirect. */
  bool combined_output = position + 1 < end && input[position] == '&' &&
                         input[position + 1] == '>';
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
  cursor = shell_source_skip_inline_continuations(input, end, cursor);
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
  cursor = shell_source_skip_inline_continuations(input, end, cursor);
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
