#ifndef SHELL_WORD_FRAGMENT_INTERNAL_H
#define SHELL_WORD_FRAGMENT_INTERNAL_H

#include "shell_ascii.h"
#include "shell_source_lexical_internal.h"
#include "shell_source_scan_work_internal.h"
#include <limits.h>
#include <stdint.h>
#include <string.h>

/* Nonrecursive word-fragment rules, shared by lexical framing, semantic
 * projection, binary decoders and diagnostic rendering. */
/* Bash ANSI-C quotes are one word fragment. Completion is determined by an
 * unescaped delimiter, never by inspecting the last source byte: `$'x\'`
 * ends in an apostrophe but has no closing quote.
 * input supplies length immutable bytes (NULL only for length zero),
 * position <= length, and after is a required writable offset. */
static inline SHELL_NONNULL(4) bool shell_source_skip_complete_ansi_c_quote(
    const char *input, size_t length, size_t position, size_t *after) {
  size_t quote = 0;
  if (position >= length || input[position] != '$' ||
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

/* Decode one escape after its backslash. Required immutable text supplies
 * length readable bytes; *position < length names the escape character and
 * advances past its payload, including a doubled control-backslash operand
 * or the literal apostrophe protected by that operand. The quote decoder
 * owns framing validation.
 * A NULL visitor suppresses output; context is passed through unchanged.
 * Optional locale_dependent accumulates into caller-initialized storage.
 * Sharing this operation keeps byte truncation and Unicode handling identical
 * in word decoding, delimiter matching, and executable-syntax classification.
 */
static inline SHELL_NONNULL(1, 3) bool shell_source_decode_ansi_escape(
    const char *text, size_t length, size_t *position,
    shell_source_byte_visitor_t visitor, void *context,
    bool *locale_dependent) {
  SHELL_SOURCE_WORD_SCAN(1);
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
      SHELL_SOURCE_WORD_SCAN(1);
      unsigned char operand = (unsigned char)text[(*position)++];
      decoded = operand == '?' ? 0x7f : (unsigned char)(operand & 0x1f);
      /* Bash consumes a doubled backslash as one control operand. A quote
       * protected by the consumed backslash stays literal: emit it here so
       * the enclosing decoder cannot mistake it for the closing delimiter.
       * Consume the complete unit before invoking a cancellable visitor. */
      if (operand == '\\' && *position < length &&
          (text[*position] == '\\' || text[*position] == '\'')) {
        SHELL_SOURCE_WORD_SCAN(1);
        unsigned char protected_byte = (unsigned char)text[(*position)++];
        if (protected_byte == '\'') {
          if (!shell_source_ansi_emit(visitor, context, decoded))
            return false;
          decoded = protected_byte;
        }
      }
    }
    break;
  case 'x': {
    unsigned value = 0;
    size_t consumed = 0;
    while (consumed < 2 && *position < length) {
      SHELL_SOURCE_WORD_SCAN(1);
      int digit = shell_source_ansi_hex_value(text[*position]);
      if (digit < 0)
        break;
      value = (value << 4) | (unsigned)digit;
      (*position)++;
      consumed++;
    }
    if (consumed == 0) {
      if (!shell_source_ansi_emit(visitor, context, (unsigned char)'\\'))
        return false;
      decoded = 'x';
      break;
    }
    decoded = (unsigned char)value;
    break;
  }
  case 'u':
  case 'U': {
    size_t digits = escape == 'u' ? 4 : 8;
    uint32_t codepoint = 0;
    size_t consumed = 0;
    while (consumed < digits && *position < length) {
      SHELL_SOURCE_WORD_SCAN(1);
      int digit = shell_source_ansi_hex_value(text[*position]);
      if (digit < 0)
        break;
      codepoint = (codepoint << 4) | (uint32_t)digit;
      (*position)++;
      consumed++;
    }
    if (consumed == 0) {
      if (!shell_source_ansi_emit(visitor, context, (unsigned char)'\\'))
        return false;
      decoded = (unsigned char)escape;
    } else {
      if (locale_dependent && codepoint > 0x7f)
        *locale_dependent = true;
      return shell_source_ansi_emit_codepoint(visitor, context, codepoint);
    }
    break;
  }
  default:
    if (escape >= '0' && escape <= '7') {
      unsigned value = (unsigned)(escape - '0');
      for (size_t i = 0; i < 2 && *position < length; i++) {
        SHELL_SOURCE_WORD_SCAN(1);
        if (text[*position] < '0' || text[*position] > '7')
          break;
        value = (value << 3) | (unsigned)(text[(*position)++] - '0');
      }
      decoded = (unsigned char)value;
    } else {
      if (!shell_source_ansi_emit(visitor, context, (unsigned char)'\\'))
        return false;
      decoded = (unsigned char)escape;
    }
    break;
  }
  return shell_source_ansi_emit(visitor, context, decoded);
}

typedef enum {
  SHELL_SOURCE_ANSI_BYTES,
  SHELL_SOURCE_ANSI_WORD,
} shell_source_ansi_mode_t;

typedef struct {
  /* First NUL escape's source offset, or the closing quote. */
  size_t value_end;
  unsigned char first_byte;
  bool has_nul;
  bool locale_dependent;
  bool has_value;
} shell_source_ansi_facts_t;

typedef struct {
  shell_source_byte_visitor_t visitor;
  void *context;
  shell_source_ansi_facts_t *facts;
  size_t source_position;
  shell_source_ansi_mode_t mode;
} shell_source_ansi_sink_t;

static inline SHELL_NONNULL(2) bool shell_source_ansi_value_byte(
    unsigned char byte, void *context) {
  shell_source_ansi_sink_t *sink = (shell_source_ansi_sink_t *)context;
  if (!byte && !sink->facts->has_nul) {
    sink->facts->has_nul = true;
    sink->facts->value_end = sink->source_position;
  }
  if (sink->mode == SHELL_SOURCE_ANSI_WORD && sink->facts->has_nul)
    return true;
  if (!sink->facts->has_value) {
    sink->facts->first_byte = byte;
    sink->facts->has_value = true;
  }
  return shell_source_ansi_emit(sink->visitor, sink->context, byte);
}

/* Required writable position <= length, advanced past the closing quote on
 * success. text supplies length immutable bytes (NULL only for length zero).
 * A NULL visitor requests validation without emitting bytes.
 * Optional facts receives fragment-local facts, including on incomplete input.
 * WORD suppresses the first decoded NUL and the rest of that fragment's value,
 * but still consumes its complete lexical spelling. BYTES preserves every byte.
 * Non-ASCII Unicode escapes need Bash's execution locale; the internal byte
 * decoder retains UTF-8 for lexical delimiter recognition only. In WORD mode,
 * escapes in the discarded tail do not contribute locale requirements. */
static inline SHELL_NONNULL(3) bool shell_source_decode_ansi_c_quote_impl(
    const char *text, size_t length, size_t *position,
    shell_source_byte_visitor_t visitor, void *context,
    shell_source_ansi_mode_t mode, shell_source_ansi_facts_t *facts) {
  shell_source_ansi_facts_t local = {.value_end = length};
  shell_source_ansi_sink_t sink = {visitor, context, &local, 0, mode};
  bool complete = false;
  size_t quote = 0;
  if (*position >= length || text[*position] != '$')
    goto done;
  quote = shell_source_logical_following(text, length, *position);
  if (quote >= length || text[quote] != '\'')
    goto done;
  *position = quote + 1;
  while (*position < length) {
    SHELL_SOURCE_WORD_SCAN(1);
    sink.source_position = *position;
    unsigned char value = (unsigned char)text[(*position)++];
    if (value == '\'') {
      if (!local.has_nul)
        local.value_end = *position - 1;
      complete = true;
      break;
    }
    if (value != '\\') {
      if (!shell_source_ansi_value_byte(value, &sink))
        break;
    } else if (*position == length ||
               !shell_source_decode_ansi_escape(
                   text, length, position, shell_source_ansi_value_byte, &sink,
                   mode == SHELL_SOURCE_ANSI_BYTES || !local.has_nul
                       ? &local.locale_dependent
                       : NULL))
      break;
  }
done:
  if (facts)
    *facts = local;
  return complete;
}

static inline SHELL_NONNULL(3) bool shell_source_decode_ansi_c_quote(
    const char *text, size_t length, size_t *position,
    shell_source_byte_visitor_t visitor, void *context) {
  return shell_source_decode_ansi_c_quote_impl(
      text, length, position, visitor, context, SHELL_SOURCE_ANSI_BYTES, NULL);
}

/* Effective ANSI-C fragment value for semantic consumers. Source extent and
 * quote framing are retained even when a decoded NUL truncates the value. */
static inline SHELL_NONNULL(3) bool shell_source_decode_ansi_c_word(
    const char *text, size_t length, size_t *position,
    shell_source_byte_visitor_t visitor, void *context) {
  return shell_source_decode_ansi_c_quote_impl(
      text, length, position, visitor, context, SHELL_SOURCE_ANSI_WORD, NULL);
}

/* Facts describe the effective fragment value. A NUL is supported in ordinary
 * word contexts; double-quoted parameter defaults retain their separate
 * unsupported semantics. Raw byte decoding remains available independently. */
static inline SHELL_NONNULL(3, 4, 5) bool shell_source_ansi_c_quote_facts(
    const char *text, size_t length, size_t *position, bool *has_nul,
    bool *locale_dependent) {
  shell_source_ansi_facts_t facts;
  bool complete = shell_source_decode_ansi_c_quote_impl(
      text, length, position, NULL, NULL, SHELL_SOURCE_ANSI_WORD, &facts);
  *has_nul = facts.has_nul;
  *locale_dependent = facts.locale_dependent;
  return complete;
}

/* Empty process substitutions produce no pathname in the reference Bash.
 * Classify a fragment at a known word position without balancing its suffix:
 * a nonempty body stops at its first nontrivia byte. Syntax validation owns
 * completeness. This keeps adjacent-fragment decoding linear. */
static inline SHELL_NONNULL(1, 4) bool shell_source_empty_process_fragment(
    const char *word, size_t length, size_t start, size_t *after) {
  size_t open;
  if (!shell_source_process_substitution_open(word, length, start, &open))
    return false;
  size_t position = open + 1;
  while (position < length) {
    position = shell_source_skip_blank_continuations(word, length, position);
    if (position == length)
      break;
    unsigned char byte = (unsigned char)word[position++];
    if (byte == ')') {
      *after = position;
      return true;
    }
    if (byte == '#') {
      while (position < length && word[position] != '\n')
        position++;
    } else
      return false;
  }
  return false;
}

/* One complete process fragment; expansion traversal uses this to distinguish
 * a real endpoint from a substitution that produces no pathname. */
static inline SHELL_NONNULL(1) bool shell_source_empty_process_word(
    const char *word, size_t length) {
  size_t after;
  return shell_source_empty_process_fragment(word, length, 0, &after) &&
         after == length;
}

/* A whole unquoted word consisting only of empty process fragments and line
 * continuations vanishes from argv. Quotes, even empty ones, preserve a word.
 * This is expansion semantics, never lexical assignment/reserved-word
 * recognition. Callers retain the original lexical command-prefix boundary. */
static inline SHELL_NONNULL(1) bool shell_source_word_is_elided(
    const char *word, size_t length) {
  size_t position = 0;
  while (position < length) {
    position = shell_source_skip_escaped_line_endings(word, length, position);
    if (position == length)
      break;
    size_t after;
    if (!shell_source_empty_process_fragment(word, length, position, &after))
      return false;
    position = after;
  }
  return true;
}

/* Consume one ordinary quote/escape/literal step of a preframed word.
 * position < length; all state/output pointers are distinct writable storage.
 * False removes syntax without emitting a byte. No expansion is performed. */
static inline SHELL_NONNULL(1, 3, 4, 5, 6) bool shell_word_literal_step(
    const char *word, size_t length, size_t *position, char *quote,
    unsigned char *byte, bool *protected_byte) {
  char c = word[(*position)++];
  if (*quote == 0 && (c == '\'' || c == '"')) {
    *quote = c;
    return false;
  }
  if (*quote != 0 && c == *quote) {
    *quote = 0;
    return false;
  }
  if (c == '\\' && *quote != '\'' && *position < length) {
    char next = word[*position];
    if (*quote == 0 || next == '$' || next == '`' || next == '"' ||
        next == '\\' || next == '\n') {
      ++*position;
      if (next == '\n')
        return false;
      *byte = (unsigned char)next;
      *protected_byte = true;
      return true;
    }
  }
  *byte = (unsigned char)c;
  *protected_byte = *quote != 0;
  return true;
}

typedef bool (*shell_source_quoted_byte_visitor_t)(unsigned char byte,
                                                   bool quoted, void *context);

typedef struct {
  shell_source_quoted_byte_visitor_t visitor;
  void *context;
} shell_source_quoted_visitor_t;

static inline SHELL_NONNULL(2) bool shell_source_visit_ansi_quoted_byte(
    unsigned char byte, void *context) {
  shell_source_quoted_visitor_t *visit =
      (shell_source_quoted_visitor_t *)context;
  return visit->visitor(byte, true, visit->context);
}

/* Visit a complete word's literal projection without allocating: remove quotes,
 * decode effective ANSI-C values, and erase empty process fragments. Dynamic
 * spelling is not evaluated. The static-word adapters in
 * shell_source_internal.h combine context-sensitive expansion classification
 * with this projection. Shared projection keeps option-prefix recognition and
 * graph static command/wrapper recognition aligned without confusing spelling
 * with a value. word is a required readable span (including length zero);
 * visitor is required. context is passed through and may be NULL if the visitor
 * allows it. The visitor must not modify the word. quoted reports protection by
 * a quote or escape, including every effective ANSI-C byte. Removed syntax and
 * empty fragments emit no bytes. This projection does not evaluate expansions.
 */
static inline SHELL_NONNULL(1, 3) bool shell_source_visit_quoted_word(
    const char *word, size_t word_length,
    shell_source_quoted_byte_visitor_t visitor, void *context) {
  if (word_length == 0)
    return false;

  char quote = '\0';
  for (size_t position = 0; position < word_length;) {
    char c = word[position];
    size_t after;
    if (!quote && (c == '<' || c == '>') &&
        shell_source_empty_process_fragment(word, word_length, position,
                                            &after)) {
      position = after;
      continue;
    }
    if (quote == '\0' && c == '$' &&
        shell_source_logical_next_is(word, word_length, position, '\'', NULL)) {
      size_t after = position;
      shell_source_quoted_visitor_t visit = {visitor, context};
      if (!shell_source_decode_ansi_c_word(word, word_length, &after,
                                           shell_source_visit_ansi_quoted_byte,
                                           &visit))
        return false;
      position = after;
      continue;
    }
    unsigned char byte;
    bool protected_byte;
    if (shell_word_literal_step(word, word_length, &position, &quote, &byte,
                                &protected_byte) &&
        !visitor(byte, protected_byte, context))
      return false;
  }
  return quote == '\0';
}

typedef struct {
  shell_source_byte_visitor_t visitor;
  void *context;
} shell_source_unquoted_visitor_t;

static inline SHELL_NONNULL(3) bool shell_source_visit_without_quote(
    unsigned char byte, bool quoted, void *context) {
  (void)quoted;
  shell_source_unquoted_visitor_t *visit =
      (shell_source_unquoted_visitor_t *)context;
  return visit->visitor(byte, visit->context);
}

/* Same projection and span contract, discarding quote provenance. */
static inline SHELL_NONNULL(1, 3) bool shell_source_visit_decoded_word(
    const char *word, size_t word_length, shell_source_byte_visitor_t visitor,
    void *context) {
  shell_source_unquoted_visitor_t visit = {visitor, context};
  return shell_source_visit_quoted_word(
      word, word_length, shell_source_visit_without_quote, &visit);
}

#endif
