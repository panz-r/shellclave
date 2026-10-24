#ifndef SHELL_SOURCE_LEXICAL_INTERNAL_H
#define SHELL_SOURCE_LEXICAL_INTERNAL_H

#include "shell_ascii.h"
#include "shell_source_scan_work_internal.h"
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Bash grammar blanks are space/tab; only LF ends a source line. CR, VT and
 * FF remain word bytes. Arithmetic whitespace uses the same space/tab/LF set;
 * builtin numeric operands have their own parsing rules. */
static inline bool shell_source_blank(unsigned char byte) {
  return byte == ' ' || byte == '\t';
}

static inline bool shell_source_space(unsigned char byte) {
  return shell_source_blank(byte) || byte == '\n';
}

typedef enum {
  SHELL_SOURCE_IO_NUMBER_NONE,
  SHELL_SOURCE_IO_NUMBER_VALID,
  SHELL_SOURCE_IO_NUMBER_OVERFLOW,
} shell_source_io_number_t;

/* An io_number is adjacent decimal syntax before a redirection operator. Bash
 * accepts descriptors through INT_MAX; larger digit sequences are ordinary
 * word text, not an fd and never the UINT32_MAX no-descriptor sentinel.
 * start <= end, and input provides immutable storage through end. NULL input
 * means an empty span (start == end). Both output destinations are required. */
static inline SHELL_NONNULL(4, 5) shell_source_io_number_t
    shell_source_parse_io_number(const char *input, size_t start, size_t end,
                                 size_t *after, uint32_t *descriptor) {
  *after = start;
  *descriptor = 0;

  size_t position = start;
  uint64_t value = 0;
  bool overflow = false;
  while (position < end) {
    /* Escaped physical line endings disappear before IO-number recognition.
     * Horizontal space and ordinary line endings must remain boundaries. */
    if (position > start && input[position] == '\\' && position + 1 < end &&
        input[position + 1] == '\n') {
      position += 2;
      continue;
    }
    if (!shell_ascii_digit((unsigned char)input[position]))
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

/* Source text remains zero-copy throughout Shellsplit.  These helpers only
 * recognize physical line boundaries: callers retain the original bytes,
 * including carriage returns in CRLF document bodies. */
static inline size_t shell_source_line_end(const char *input, size_t length,
                                           size_t start) {
  size_t end = start;
  while (end < length && input[end] != '\n')
    end++;
  SHELL_SOURCE_LINE_SCAN(end - start + (end < length));
  return end;
}

static inline size_t shell_source_next_line(const char *input, size_t length,
                                            size_t start) {
  size_t end = shell_source_line_end(input, length, start);
  return end < length ? end + 1 : end;
}

/* Callers establish an unquoted logical word boundary in their forward walk.
 * The preceding physical byte cannot establish it: escaped operators and the
 * closing ')' of an expansion are word content, and continuations disappear.
 * Grammar-only walkers already start at a boundary; byte walkers retain it
 * across continuations and keep quotes/expansions opaque. */
static inline bool shell_source_comment_starts(char byte, bool word_boundary) {
  return byte == '#' && word_boundary;
}

/* Only unquoted, unescaped shell syntax separates words. An opaque word
 * fragment (including a substitution) must leave the boundary false. */
static inline bool shell_source_word_separator(char byte) {
  return shell_source_space((unsigned char)byte) || byte == ';' ||
         byte == '|' || byte == '&' || byte == '<' || byte == '>' ||
         byte == '(' || byte == ')';
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
    if (shell_source_space((unsigned char)input[position])) {
      position++;
      continue;
    }
    if (input[position] == '\\' && position + 1 < length &&
        input[position + 1] == '\n') {
      position += 2;
      continue;
    }
    if (shell_source_comment_starts(input[position], true)) {
      while (position < length && input[position] != '\n')
        position++;
      continue;
    }
    break;
  }
  return position;
}

/* Semantic blank bytes, shared with the source grammar.
 * Callers supply a position within the source span. Only Bash's space, tab,
 * LF and erased backslash-LF may disappear here: CR (even before LF), VT and
 * FF are word content, not evidence that a substitution is empty. */
static inline SHELL_NONNULL(1) size_t
    shell_source_skip_blank_continuations(const char *input, size_t length,
                                          size_t position) {
  while (position < length) {
    char byte = input[position];
    if (byte == ' ' || byte == '\t' || byte == '\n') {
      position++;
    } else if (byte == '\\' && position + 1 < length &&
               input[position + 1] == '\n') {
      position += 2;
    } else {
      break;
    }
  }
  return position;
}

/* Complete-source lexical emptiness. The source is a valid byte span; this
 * boundary classifies trivia, not malformed shell grammar. Comments remain
 * distinguishable because Bash gives comment-only backticks a completion
 * status, unlike blank backticks and empty $(). Comments end only at LF; a
 * CR inside a comment remains comment text. */
typedef enum {
  SHELL_SOURCE_NONEMPTY,
  SHELL_SOURCE_BLANK,
  SHELL_SOURCE_COMMENT,
} shell_source_empty_kind_t;

static inline SHELL_NONNULL(1) shell_source_empty_kind_t
    shell_source_empty_kind(const char *input, size_t length) {
  bool comment = false;
  for (size_t position = 0; position < length;) {
    position = shell_source_skip_blank_continuations(input, length, position);
    if (position == length)
      break;
    if (!shell_source_comment_starts(input[position], true))
      return SHELL_SOURCE_NONEMPTY;
    comment = true;
    while (position < length && input[position] != '\n')
      position++;
  }
  return comment ? SHELL_SOURCE_COMMENT : SHELL_SOURCE_BLANK;
}

/* True when an interval contains only the shell grammar that may separate a
 * list connector from its next stage. */
static inline bool shell_source_is_list_trivia(const char *input, size_t start,
                                               size_t end) {
  return input && start <= end &&
         shell_source_skip_list_trivia(input, end, start) == end;
}

/* After a recognized pipeline negator, horizontal whitespace and escaped
 * physical line endings may extend the gap to its stage. A raw physical line
 * ending or comment terminates the modifier. Recognition itself also permits
 * an adjacent redirection (`!>out command`); word-forming adjacency such as
 * `!echo`, `!2>out`, or `!<(producer)` is rejected by the matcher below. */
static inline size_t shell_source_skip_pipeline_negator_gap(const char *input,
                                                            size_t length,
                                                            size_t position) {
  if (!input || position > length)
    return 0;
  while (position < length) {
    SHELL_SOURCE_PREFIX_SCAN(1);
    unsigned char current = (unsigned char)input[position];
    if (shell_source_blank(current)) {
      position++;
      continue;
    }
    if (input[position] == '\\' && position + 1 < length) {
      if (input[position + 1] == '\n') {
        position += 2;
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
  return input[start] == '\\' && start + 1 < end && input[start + 1] == '\n' &&
         start + 2 == end;
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

/* Match one complete, unquoted shell word after removing escaped physical
 * line endings.  Reserved words must use this boundary rather than matching a
 * single lexer fragment: expansion, quote, and process-substitution fragments
 * adjacent to the spelling all form one ordinary shell word.  Redirections
 * and shell operators delimit a reserved word; `<(` and `>(` do not because
 * they are word-forming process substitutions. The caller supplies immutable
 * input[0..end) with position <= end and word[0..word_length). `after` is an
 * optional output, set to position on a mismatch. */
static SHELL_NONNULL(1, 4) inline bool shell_source_match_plain_word(
    const char *input, size_t end, size_t position, const char *word,
    size_t word_length, size_t *after) {
  if (after)
    *after = position;
  size_t cursor = position;
  for (size_t matched = 0; matched < word_length; matched++) {
    cursor = shell_source_skip_escaped_line_endings(input, end, cursor);
    if (cursor >= end || input[cursor] != word[matched])
      return false;
    cursor++;
  }
  cursor = shell_source_skip_escaped_line_endings(input, end, cursor);
  if (cursor < end) {
    unsigned char next = (unsigned char)input[cursor];
    bool redirect_boundary =
        (next == '<' || next == '>') &&
        !shell_source_process_substitution_open(input, end, cursor, NULL);
    bool operator_boundary =
        next == ';' || next == '|' || next == '&' || next == '(' || next == ')';
    if (!shell_source_space(next) && !redirect_boundary && !operator_boundary)
      return false;
  }
  if (after)
    *after = cursor;
  return true;
}

/* input supplies length immutable bytes and position < length. Recognition
 * does not establish balanced or supported syntax; the declaration boundary
 * probes that separately. */
static inline SHELL_NONNULL(1) bool shell_source_heredoc_fragment_open(
    const char *input, size_t length, size_t position) {
  if (input[position] != '$')
    return shell_source_process_substitution_open(input, length, position,
                                                  NULL);
  size_t next = shell_source_logical_following(input, length, position);
  return next < length &&
         (input[next] == '{' || input[next] == '(' || input[next] == '[');
}

#endif
