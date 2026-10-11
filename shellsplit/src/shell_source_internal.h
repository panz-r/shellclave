#ifndef SHELL_SOURCE_INTERNAL_H
#define SHELL_SOURCE_INTERNAL_H

#include "shell_tokenizer.h"
#include <ctype.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#include "test_source_scans.h"
#define SHELL_SOURCE_PREFIX_SCAN(length)                                       \
  shellsplit_test_source_scan_charge(length)
#define SHELL_SOURCE_DELIMITER_SCAN(input, position)                           \
  shellsplit_test_delimiter_charge((input) + (position), 1)
#define SHELL_SOURCE_LINE_SCAN(length) shellsplit_test_line_scan_charge(length)
#else
#define SHELL_SOURCE_PREFIX_SCAN(length) ((void)0)
#define SHELL_SOURCE_DELIMITER_SCAN(input, position) ((void)0)
#define SHELL_SOURCE_LINE_SCAN(length) ((void)0)
#endif

/* Count actual word-scanner transitions, including failed delimiter probes.
 * This compiles away in shipping builds. */
#define SHELL_SOURCE_WORD_SCAN(length) SHELL_SOURCE_PREFIX_SCAN(length)

/* Operation-local lexical index. Delimiter consumers reuse source boundaries
 * found during the forward nested walk instead of balancing each ancestor's
 * suffix again. Entries refer only to the immutable root span and expire at
 * the end of the outer operation; this is not caller-consistency validation.
 * No public result owns this index or grows to carry it. */
enum {
  SHELL_SOURCE_INDEX_PARENS = 1,
  SHELL_SOURCE_INDEX_PARAMETER,
  SHELL_SOURCE_INDEX_DOUBLE_QUOTE,
  SHELL_SOURCE_INDEX_ARITHMETIC = 5,
};
typedef struct {
  uintptr_t begin, end, frontier;
} shell_source_scope_t;
#ifdef __cplusplus
extern "C" {
#endif
void shell_source_operation_begin(const char *input, size_t length)
    SHELL_NONNULL(1);
void shell_source_operation_end(void);
/* External source-byte boundary, shared by tokenizer and processor adapters.
 * Reject NUL, non-whitespace control bytes, DEL and high bytes. Successful
 * checks of the operation's immutable root cover its contained spans. */
bool shell_source_bytes_valid(const char *input, size_t length)
    SHELL_NONNULL(1);
/* Enter one borrowed lexical body, restoring its enclosing body on exit.
 * Index capacity belongs to this active scope and its ancestors, not to facts
 * from arbitrary siblings inspected earlier in the operation. */
shell_source_scope_t shell_source_scope_begin(const char *input, size_t length)
    SHELL_NONNULL(1);
void shell_source_scope_end(shell_source_scope_t previous);
/* A lexical iterator consumes its current scope in source order. Matching a
 * delimiter does not advance this frontier: its children have not been
 * consumed yet. NULL denotes an inactive/empty diagnostic iterator. */
void shell_source_scope_frontier(const char *input, size_t position);
bool shell_source_index_get(const char *input, size_t length, size_t position,
                            unsigned kind, size_t *value, size_t *height)
    SHELL_NONNULL(1, 5, 6);
void shell_source_index_put(const char *input, size_t length, size_t position,
                            unsigned kind, size_t value, size_t height)
    SHELL_NONNULL(1);
#ifdef __cplusplus
}
#endif

/* Parameter, quote, arithmetic, and command-substitution scanners recurse
 * into one another. A shared per-thread budget bounds mixed nesting too. */
/* The cached scanner boundaries below accept an empty source span (including
 * NULL with length zero) as no match. Nonempty spans require valid immutable
 * storage; their required `after` destination is distinct writable storage.
 * Reject an absent source position before calling the non-null index leaves. */
#ifdef __cplusplus
static thread_local unsigned shell_source_scan_depth;
static thread_local size_t shell_source_scan_heights[SHELL_MAX_SUBCOMMANDS];
#else
static _Thread_local unsigned shell_source_scan_depth;
static _Thread_local size_t shell_source_scan_heights[SHELL_MAX_SUBCOMMANDS];
#endif

static inline bool shell_source_scan_enter(void) {
  if (shell_source_scan_depth >= SHELL_MAX_SUBCOMMANDS)
    return false;
  shell_source_scan_heights[shell_source_scan_depth] = 1;
  shell_source_scan_depth++;
  return true;
}

/* Heights describe source structure, not the C stack used to discover it.
 * Reusing a subtree must consume the same structural budget as walking it. */
static inline void shell_source_scan_child(size_t height) {
  if (shell_source_scan_depth &&
      shell_source_scan_heights[shell_source_scan_depth - 1] < height + 1)
    shell_source_scan_heights[shell_source_scan_depth - 1] = height + 1;
}

static inline size_t shell_source_scan_leave(void) {
  size_t height = shell_source_scan_heights[--shell_source_scan_depth];
  shell_source_scan_child(height);
  return height;
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

/* Executable substitution inspection and dependency graph imports share this
 * semantic nesting budget. Lexical word scopes have their separate budget
 * above; cached lexical facts do not change either limit. */
#define SHELL_SOURCE_MAX_EXECUTABLE_NESTING 16u

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
  return isspace((unsigned char)byte) || byte == ';' || byte == '|' ||
         byte == '&' || byte == '<' || byte == '>' || byte == '(' ||
         byte == ')';
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
    if (shell_source_comment_starts(input[position], true)) {
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
    if (!isspace(next) && !redirect_boundary && !operator_boundary)
      return false;
  }
  if (after)
    *after = cursor;
  return true;
}

/* Recognize the reserved pipeline-negation word at one shell word boundary.
 * Shell operators delimit reserved words without requiring whitespace, and
 * escaped physical line endings disappear before that decision.  Keep the
 * word-forming exceptions explicit: `!<(` / `!>(` are ordinary words with a
 * process-substitution suffix, `!(...)` is Bash extglob syntax, and numeric or
 * named descriptor prefixes remain part of their containing word. The caller
 * supplies immutable input[0..end) with position <= end. `after` is optional.
 */
static SHELL_NONNULL(1) inline bool shell_source_match_pipeline_negator(
    const char *input, size_t end, size_t position, size_t *after) {
  if (after)
    *after = position;
  if (position == end || input[position] != '!')
    return false;

  size_t cursor =
      shell_source_skip_escaped_line_endings(input, end, position + 1);
  if (cursor < end) {
    unsigned char next = (unsigned char)input[cursor];
    if (isspace(next)) {
      /* Whitespace always delimits the reserved word. */
    } else if ((next == '<' || next == '>') &&
               !shell_source_process_substitution_open(input, end, cursor,
                                                       NULL)) {
      /* A redirection begins the following (possibly argv-less) command. */
    } else if (next == ';' || next == '|' || next == '&' || next == ')') {
      /* List operators and a containing close are lexical boundaries. Syntax
       * validation decides whether the resulting empty pipeline is legal. */
    } else {
      return false;
    }
  }
  if (after)
    *after = position + 1;
  return true;
}

typedef struct {
  size_t prefix_start;
  size_t stage_start;
  uint32_t negation_count;
  shell_pipeline_time_mode_t time_mode;
  bool has_modifier;
  bool ends_with_negator;
  bool valid;
} shell_source_pipeline_prefix_t;

/* Semantic state for Bash's reserved pipeline modifiers.  Source scanners and
 * token-oriented parsers deliberately share these transitions: only their
 * boundary recognition differs. */
typedef struct {
  uint32_t negation_count;
  shell_pipeline_time_mode_t time_mode;
  bool time_keyword_allowed;
  bool time_p_allowed;
  bool time_dashdash_allowed;
  bool has_modifier;
  bool ends_with_negator;
  bool valid;
} shell_pipeline_prefix_state_t;

typedef enum {
  SHELL_PIPE_PREFIX_WORD_OTHER = 0,
  SHELL_PIPE_PREFIX_WORD_TIME,
  SHELL_PIPE_PREFIX_WORD_POSIX,
  SHELL_PIPE_PREFIX_WORD_END_OPTIONS,
  SHELL_PIPE_PREFIX_WORD_NEGATE,
} shell_pipeline_prefix_word_t;

typedef enum {
  SHELL_PIPE_PREFIX_NOT_ACCEPTED = 0,
  SHELL_PIPE_PREFIX_ACCEPTED_TIME,
  SHELL_PIPE_PREFIX_ACCEPTED_OPTION,
  SHELL_PIPE_PREFIX_ACCEPTED_NEGATE,
  SHELL_PIPE_PREFIX_OVERFLOW,
} shell_pipeline_prefix_step_t;

static inline shell_pipeline_prefix_state_t
shell_pipeline_prefix_state_initial(bool allow_time_keyword) {
  return (shell_pipeline_prefix_state_t){
      .time_mode = SHELL_PIPE_TIME_NONE,
      .time_keyword_allowed = allow_time_keyword,
      .valid = true,
  };
}

/* state is an initialized prefix state. An invalid state is a sticky syntax
 * failure; NULL has no state-machine meaning. */
static SHELL_NONNULL(1) inline shell_pipeline_prefix_step_t
    shell_pipeline_prefix_step(shell_pipeline_prefix_state_t *state,
                               shell_pipeline_prefix_word_t word) {
  if (!state->valid)
    return SHELL_PIPE_PREFIX_NOT_ACCEPTED;

  if (word == SHELL_PIPE_PREFIX_WORD_NEGATE) {
    if (state->negation_count == UINT32_MAX) {
      state->valid = false;
      return SHELL_PIPE_PREFIX_OVERFLOW;
    }
    state->negation_count++;
    state->time_p_allowed = false;
    state->time_dashdash_allowed = false;
    state->has_modifier = true;
    state->ends_with_negator = true;
    return SHELL_PIPE_PREFIX_ACCEPTED_NEGATE;
  }
  if (word == SHELL_PIPE_PREFIX_WORD_TIME && state->time_keyword_allowed) {
    if (state->time_mode == SHELL_PIPE_TIME_NONE)
      state->time_mode = SHELL_PIPE_TIME_DEFAULT;
    state->time_p_allowed = true;
    state->time_dashdash_allowed = true;
    state->has_modifier = true;
    state->ends_with_negator = false;
    return SHELL_PIPE_PREFIX_ACCEPTED_TIME;
  }
  if (word == SHELL_PIPE_PREFIX_WORD_POSIX &&
      state->time_mode != SHELL_PIPE_TIME_NONE && state->time_p_allowed) {
    state->time_mode = SHELL_PIPE_TIME_POSIX;
    state->time_p_allowed = false;
    state->ends_with_negator = false;
    return SHELL_PIPE_PREFIX_ACCEPTED_OPTION;
  }
  if (word == SHELL_PIPE_PREFIX_WORD_END_OPTIONS &&
      state->time_mode != SHELL_PIPE_TIME_NONE &&
      state->time_dashdash_allowed) {
    state->time_mode = SHELL_PIPE_TIME_POSIX;
    state->time_p_allowed = false;
    state->time_dashdash_allowed = false;
    state->ends_with_negator = false;
    return SHELL_PIPE_PREFIX_ACCEPTED_OPTION;
  }
  return SHELL_PIPE_PREFIX_NOT_ACCEPTED;
}

/* Parse Bash's pipeline-prefix grammar shared by the fast and allocating
 * parsers. Each reserved `time` consumes at most `-p` and then `--`; another
 * `time` starts another (semantically idempotent) prefix. Raw newlines and
 * comments terminate the current pipeline, while escaped line endings do not.
 * The caller decides whether a prefix without a stage is complete. Bash
 * accepts an empty timed pipeline at top-level EOF (including `time !`) and
 * before a real list terminator, but not merely because a parenthesized
 * substitution or subshell closes. A prefix before a compound-command opener
 * instead modifies that compound stage. */
/* input addresses at least end immutable bytes; start <= end. The caller
 * supplies a list-grammar boundary, even for an empty span. */
static SHELL_NONNULL(1) inline shell_source_pipeline_prefix_t
    shell_source_parse_pipeline_prefix(const char *input, size_t start,
                                       size_t end) {
  shell_source_pipeline_prefix_t result = {
      .prefix_start = start,
      .stage_start = start,
      .time_mode = SHELL_PIPE_TIME_NONE,
      .valid = true,
  };
  for (;;) {
    while (start < end && isspace((unsigned char)input[start]) &&
           input[start] != '\n' && input[start] != '\r') {
      SHELL_SOURCE_PREFIX_SCAN(1);
      start++;
    }
    size_t continued =
        shell_source_skip_escaped_line_endings(input, end, start);
    if (continued == start)
      break;
    start = continued;
  }
  result.prefix_start = start;
  size_t position = start;
  shell_pipeline_prefix_state_t state =
      shell_pipeline_prefix_state_initial(true);
  for (;;) {
    SHELL_SOURCE_PREFIX_SCAN(1);
    size_t after = position;
    shell_pipeline_prefix_word_t word = SHELL_PIPE_PREFIX_WORD_OTHER;
    if (shell_source_match_pipeline_negator(input, end, position, &after)) {
      word = SHELL_PIPE_PREFIX_WORD_NEGATE;
    } else if (shell_source_match_plain_word(input, end, position, "time", 4,
                                             &after)) {
      word = SHELL_PIPE_PREFIX_WORD_TIME;
    } else if (shell_source_match_plain_word(input, end, position, "-p", 2,
                                             &after)) {
      word = SHELL_PIPE_PREFIX_WORD_POSIX;
    } else if (shell_source_match_plain_word(input, end, position, "--", 2,
                                             &after)) {
      word = SHELL_PIPE_PREFIX_WORD_END_OPTIONS;
    }

    shell_pipeline_prefix_step_t step =
        shell_pipeline_prefix_step(&state, word);
    if (step == SHELL_PIPE_PREFIX_OVERFLOW) {
      result.valid = false;
      return result;
    }
    if (step == SHELL_PIPE_PREFIX_NOT_ACCEPTED)
      break;
    position = shell_source_skip_pipeline_negator_gap(input, end, after);

    if (position >= end || input[position] == '\n' || input[position] == '\r' ||
        shell_source_comment_starts(input[position], true))
      break;
  }
  result.stage_start = position;
  result.negation_count = state.negation_count;
  result.time_mode = state.time_mode;
  result.has_modifier = state.has_modifier;
  result.ends_with_negator = state.ends_with_negator;
  result.valid = state.valid;
  return result;
}

/* Parse the scalar assignment-word prefix after shell lexical removal of
 * escaped physical line endings. This deliberately recognizes only the
 * identifier forms that can prefix an ordinary assignment: `name=value` and
 * `name+=value`. The returned positions retain the original source spelling
 * so callers can keep zero-copy views without reconstructing the word.
 * input is an immutable readable span, including an empty span; out is
 * required distinct writable storage and is cleared before scanning. */
typedef struct {
  size_t name_end;
  size_t equals;
  bool append;
} shell_source_assignment_word_t;

static inline SHELL_NONNULL(1, 3) bool shell_source_parse_scalar_assignment_word(
    const char *input, size_t length, shell_source_assignment_word_t *out) {
  *out = (shell_source_assignment_word_t){0};
  if (length < 2)
    return false;

  size_t position = 0;
  size_t identifier_length = 0;
  while (position < length) {
    SHELL_SOURCE_WORD_SCAN(1);
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

/* Skip one quoted shell fragment, including its opening delimiter. The
 * lexical helpers below deliberately tolerate an unterminated quote: callers
 * that require a complete command validate that separately. */
static inline SHELL_NONNULL(4) bool shell_source_skip_complete_double_quote(
    const char *input, size_t length, size_t position, size_t *after);
static inline SHELL_NONNULL(5) bool shell_source_skip_complete_quoted_text(
    const char *input, size_t length, size_t position, char quote,
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

/* Locate a legacy command substitution's end on one forward cursor. Bash
 * removes backslashes before $, `, \\, and newline before parsing its body;
 * an enclosing double quote also enables removal before ". Inner body quotes
 * do not protect against this outer removal. Optional escape_sensitive receives
 * that semantic fact on completion; NULL requests delimiter location only.
 * The borrowed raw body cannot represent the removed layer faithfully, so the
 * supported-source boundary rejects active escape-sensitive forms.
 * input supplies length immutable bytes (NULL only for length zero),
 * position <= length, and after is a required writable offset. */
static inline SHELL_NONNULL(5) bool shell_source_scan_backtick(
    const char *input, size_t length, size_t position, bool double_quoted,
    size_t *after, bool *escape_sensitive) {
  if (position >= length || input[position] != '`')
    return false;
  bool sensitive = false;
  for (size_t cursor = position + 1; cursor < length; cursor++) {
    SHELL_SOURCE_WORD_SCAN(1);
    if (input[cursor] == '\\' && cursor + 1 < length) {
      char next = input[cursor + 1];
      sensitive |= next == '$' || next == '`' || next == '\\' || next == '\n' ||
                   (double_quoted && next == '"');
      SHELL_SOURCE_WORD_SCAN(1);
      cursor++;
      continue;
    }
    if (input[cursor] == '`') {
      *after = cursor + 1;
      if (escape_sensitive)
        *escape_sensitive = sensitive;
      return true;
    }
  }
  return false;
}

/* Lexical delimiter consumers do not interpret the nested escape layer. */
static inline SHELL_NONNULL(4) bool shell_source_skip_complete_backtick(
    const char *input, size_t length, size_t position, size_t *after) {
  return shell_source_scan_backtick(input, length, position, false, after,
                                    NULL);
}

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

/* Required writable position <= length, advanced past the closing quote on
 * success. text supplies length immutable bytes (NULL only for length zero).
 * A NULL visitor requests validation without emitting bytes. */
/* locale_dependent is an optional fact output, initialized by the caller.
 * Non-ASCII Unicode escapes need Bash's execution locale; the internal byte
 * decoder retains UTF-8 for lexical delimiter recognition only. */
static inline SHELL_NONNULL(3) bool shell_source_decode_ansi_c_quote_impl(
    const char *text, size_t length, size_t *position,
    shell_source_byte_visitor_t visitor, void *context,
    bool *locale_dependent) {
  if (*position >= length || text[*position] != '$')
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
        if (locale_dependent && codepoint > 0x7f)
          *locale_dependent = true;
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

static inline SHELL_NONNULL(3) bool shell_source_decode_ansi_c_quote(
    const char *text, size_t length, size_t *position,
    shell_source_byte_visitor_t visitor, void *context) {
  return shell_source_decode_ansi_c_quote_impl(text, length, position, visitor,
                                               context, NULL);
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
static inline SHELL_NONNULL(3, 4, 5) bool shell_source_ansi_c_quote_facts(
    const char *text, size_t length, size_t *position, bool *has_nul,
    bool *locale_dependent) {
  *has_nul = false;
  *locale_dependent = false;
  return shell_source_decode_ansi_c_quote_impl(text, length, position,
                                               shell_source_find_ansi_c_nul,
                                               has_nul, locale_dependent);
}

/* Heredoc delimiters do quote removal but do not expand parameter-like text.
 * Inspect only active ANSI-C quotes, not literal dollars in other quotes. */
static inline bool
shell_source_heredoc_word_has_unsupported_ansi_c(const char *word,
                                                 size_t length) {
  if (!word)
    return false;
  char quote = '\0';
  for (size_t position = 0; position < length; position++) {
    char c = word[position];
    if (quote == '\0' && c == '$' &&
        shell_source_logical_next_is(word, length, position, '\'', NULL)) {
      bool has_nul = false;
      bool locale_dependent = false;
      size_t after = position;
      if (!shell_source_ansi_c_quote_facts(word, length, &after, &has_nul,
                                           &locale_dependent))
        return false;
      if (has_nul || locale_dependent)
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

/* Match quote-removed delimiter bytes against one physical line. The caller
 * supplies immutable input[0..length), line <= length, and an initialized
 * descriptor borrowing valid immutable word[0..word_length) storage. */
static SHELL_NONNULL(1, 4) inline bool shell_source_line_is_heredoc_delimiter(
    const char *input, size_t length, size_t line,
    const shell_source_pending_heredoc_t *pending) {
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
 * the syntax that quote removal will process. The required descriptor borrows
 * valid immutable word[0..word_length) storage. */
static SHELL_NONNULL(1) inline bool shell_source_heredoc_delimiter_is_quoted(
    const shell_source_pending_heredoc_t *pending) {
  for (size_t i = 0; i < pending->word_length; i++) {
    char c = pending->word[i];
    if (c == '\\' || c == '\'' || c == '"')
      return true;
  }
  return false;
}

static inline SHELL_NONNULL(4) bool shell_source_find_balanced_parentheses(
    const char *input, size_t length, size_t position, size_t *after);
static inline SHELL_NONNULL(4) bool shell_source_skip_arithmetic_expansion(
    const char *input, size_t length, size_t position, size_t *after);
static inline SHELL_NONNULL(
    4) bool shell_source_skip_arithmetic_expansion_depth(const char *input,
                                                         size_t length,
                                                         size_t position,
                                                         size_t *after,
                                                         size_t nesting);

static inline SHELL_NONNULL(4) bool shell_source_skip_parameter_expansion(
    const char *input, size_t length, size_t position, size_t *after);
static inline SHELL_NONNULL(4) bool shell_source_skip_extglob(const char *input,
                                                              size_t length,
                                                              size_t position,
                                                              size_t *after);

typedef enum {
  SHELL_SOURCE_DECL_LINE_END = 0,
  SHELL_SOURCE_DECL_FOUND,
  SHELL_SOURCE_DECL_MALFORMED,
} shell_source_declaration_status_t;

/* Walk a declaration line once. cursor initially names a source position and
 * advances past each real << delimiter; LINE_END leaves it at the surviving
 * newline (or length). Quoted text and expansion operands are opaque, so
 * punctuation inside them cannot declare another document. All destinations
 * are distinct writable storage. word_boundary describes the logical word
 * context at cursor and is retained between declarations on the same line.
 * This is a lexical syntax boundary. */
static SHELL_NONNULL(1, 3, 4, 5, 6) inline shell_source_declaration_status_t
    shell_source_next_heredoc_declaration_impl(
        const char *input, size_t length, size_t *cursor,
        shell_source_pending_heredoc_t *pending, size_t *operator_position,
        bool *word_boundary) {
  while (*cursor < length) {
    shell_source_scope_frontier(input, *cursor);
    SHELL_SOURCE_WORD_SCAN(1);
    size_t position = *cursor;
    char c = input[position];
    if (c == '\n' || c == '\r')
      return SHELL_SOURCE_DECL_LINE_END;
    if (shell_source_comment_starts(c, *word_boundary)) {
      *cursor = shell_source_line_end(input, length, position);
      return SHELL_SOURCE_DECL_LINE_END;
    }
    if (c == '\\' && position + 1 < length) {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, position);
      *cursor = continued != position ? continued : position + 2;
      if (continued == position)
        *word_boundary = false;
      continue;
    }
    *word_boundary = shell_source_word_separator(c);
    if (shell_source_skip_extglob(input, length, position, cursor))
      continue;
    if (c == '$' &&
        shell_source_logical_next_is(input, length, position, '\'', NULL)) {
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   cursor))
        return SHELL_SOURCE_DECL_MALFORMED;
      continue;
    }
    if (c == '\'' || c == '"' || c == '`') {
      if (!shell_source_skip_complete_quoted_text(input, length, position, c,
                                                  cursor))
        return SHELL_SOURCE_DECL_MALFORMED;
      continue;
    }
    if (c == '$' &&
        shell_source_logical_next_is(input, length, position, '{', NULL)) {
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 cursor))
        return SHELL_SOURCE_DECL_MALFORMED;
      continue;
    }
    if (c == '$' &&
        shell_source_dollar_arithmetic_open(input, length, position, NULL)) {
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  cursor))
        return SHELL_SOURCE_DECL_MALFORMED;
      continue;
    }
    size_t open = 0;
    if ((c == '$' && shell_source_dollar_parentheses_open(input, length,
                                                          position, &open)) ||
        ((c == '<' || c == '>') && shell_source_process_substitution_open(
                                       input, length, position, &open))) {
      if (!shell_source_find_balanced_parentheses(input, length, open, cursor))
        return SHELL_SOURCE_DECL_MALFORMED;
      *word_boundary = false;
      continue;
    }
    size_t after = 0;
    if (c == '<' && shell_source_match_logical_punctuation(
                        input, length, position, "<<<", &after)) {
      *cursor = after;
      continue;
    }
    if (c == '<' && shell_source_match_logical_punctuation(
                        input, length, position, "<<", &after)) {
      if (!shell_source_parse_heredoc_delimiter(input, length, &after, pending))
        return SHELL_SOURCE_DECL_MALFORMED;
      *operator_position = position;
      *cursor = after;
      *word_boundary = false;
      return SHELL_SOURCE_DECL_FOUND;
    }
    (*cursor)++;
  }
  return SHELL_SOURCE_DECL_LINE_END;
}

static SHELL_NONNULL(1, 3, 4, 5, 6) inline shell_source_declaration_status_t
    shell_source_next_heredoc_declaration(
        const char *input, size_t length, size_t *cursor,
        shell_source_pending_heredoc_t *pending, size_t *operator_position,
        bool *word_boundary) {
  /* Declaration lookahead owns a forward cursor independently of its caller.
   * Retire completed sibling facts without advancing a containing word's
   * semantic cursor, which may still need to inspect those bodies. */
  shell_source_scope_t previous = shell_source_scope_begin(input, length);
  shell_source_declaration_status_t status =
      shell_source_next_heredoc_declaration_impl(
          input, length, cursor, pending, operator_position, word_boundary);
  shell_source_scope_end(previous);
  return status;
}

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
 * remainder as document data, while strict parsers reject it. The caller
 * supplies immutable input[0..length), line <= length, a pending array of
 * pending_count valid declarations, and writable after storage. visitor is
 * optional; context is passed through unchanged and may be NULL. */
static SHELL_NONNULL(1, 4, 8) inline bool shell_source_visit_pending_heredoc_bodies(
    const char *input, size_t length, size_t line,
    const shell_source_pending_heredoc_t *pending, size_t pending_count,
    shell_source_heredoc_body_visitor_t visitor, void *context, size_t *after) {
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

static SHELL_NONNULL(1, 4, 6) inline bool shell_source_skip_pending_heredoc_bodies(
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
 * an unterminated document is tolerated or rejected. The caller supplies an
 * immutable input span, position <= length, and required output storage.
 * The source need not begin with a valid heredoc; this function checks its
 * declarations and delimiters. visitor/context follow the pending-body
 * visitor contract above. */
static SHELL_NONNULL(1, 6, 7) inline bool shell_source_visit_heredoc_sequence(
    const char *input, size_t length, size_t position,
    shell_source_heredoc_body_visitor_t visitor, void *context, size_t *after,
    bool *complete) {
  if (!shell_source_match_logical_punctuation(input, length, position, "<<",
                                              NULL) ||
      shell_source_match_logical_punctuation(input, length, position, "<<<",
                                             NULL))
    return false;

  shell_source_pending_heredoc_t pending[SHELL_SOURCE_MAX_PENDING_HEREDOCS];
  size_t pending_count = 0, operator_position = 0;
  shell_source_pending_heredoc_t declaration;
  shell_source_declaration_status_t status;
  bool word_boundary = true;
  while ((status = shell_source_next_heredoc_declaration(
              input, length, &position, &declaration, &operator_position,
              &word_boundary)) == SHELL_SOURCE_DECL_FOUND) {
    if (pending_count == SHELL_SOURCE_MAX_PENDING_HEREDOCS)
      return false;
    pending[pending_count++] = declaration;
  }
  if (status == SHELL_SOURCE_DECL_MALFORMED || pending_count == 0)
    return false;
  size_t bodies = shell_source_next_line(input, length, position);
  *complete = shell_source_visit_pending_heredoc_bodies(
      input, length, bodies, pending, pending_count, visitor, context, after);
  return true;
}

static SHELL_NONNULL(1, 4, 5) inline bool shell_source_skip_heredoc_sequence(
    const char *input, size_t length, size_t position, size_t *after,
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

static inline SHELL_NONNULL(
    1,
    4) bool shell_source_skip_arithmetic_expansion_depth_impl(const char *input,
                                                              size_t length,
                                                              size_t position,
                                                              size_t *after,
                                                              size_t nesting) {
  size_t open = 0;
  /* The wrapper has already admitted this nesting budget before either a
   * cache hit or a fresh scan. This implementation owns spelling validation. */
  if (!shell_source_dollar_arithmetic_open(input, length, position, &open))
    return false;

  size_t depth = 1;
  for (position = open + 1; position < length; position++) {
    SHELL_SOURCE_DELIMITER_SCAN(input, position);
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
  if (nesting > SHELL_SOURCE_MAX_ARITHMETIC_NESTING)
    return false;
  if (position >= length)
    return false;
  size_t height;
  if (shell_source_index_get(input, length, position,
                             SHELL_SOURCE_INDEX_ARITHMETIC, after, &height)) {
    if (height > SHELL_MAX_SUBCOMMANDS - shell_source_scan_depth ||
        height > SHELL_SOURCE_MAX_ARITHMETIC_NESTING - nesting + 1)
      return false;
    shell_source_scan_child(height);
    return *after <= length;
  }
  if (!shell_source_scan_enter())
    return false;
  bool complete = shell_source_skip_arithmetic_expansion_depth_impl(
      input, length, position, after, nesting);
  height = shell_source_scan_leave();
  if (complete)
    shell_source_index_put(input, length, position,
                           SHELL_SOURCE_INDEX_ARITHMETIC, *after, height);
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
static inline SHELL_NONNULL(
    1, 4) bool shell_source_find_balanced_parentheses_impl(const char *input,
                                                           size_t length,
                                                           size_t position,
                                                           size_t *after) {
  if (input[position] != '(')
    return false;
  size_t depth = 1;
  shell_source_pending_heredoc_t pending[SHELL_SOURCE_MAX_PENDING_HEREDOCS];
  size_t pending_count = 0;
  bool word_boundary = true;
  for (position++; position < length && depth > 0; position++) {
    SHELL_SOURCE_DELIMITER_SCAN(input, position);
    char c = input[position];
    bool starts_word = word_boundary;
    word_boundary = shell_source_word_separator(c);
    size_t extglob_after = 0;
    if (c == '\\' && position + 1 < length) {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (continued != position) {
        word_boundary = starts_word;
        position = continued - 1;
        continue;
      }
      position++;
    } else if (shell_source_skip_extglob(input, length, position,
                                         &extglob_after)) {
      position = extglob_after - 1;
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
    } else if (shell_source_comment_starts(c, starts_word)) {
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
    } else if (c == '$' && shell_source_logical_next_is(input, length, position,
                                                        '{', NULL)) {
      size_t parameter_after = 0;
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 &parameter_after))
        return false;
      position = parameter_after - 1;
    } else if ((c == '$' || c == '<' || c == '>')) {
      size_t open = 0;
      bool substitution = c == '$' ? shell_source_dollar_parentheses_open(
                                         input, length, position, &open)
                                   : shell_source_process_substitution_open(
                                         input, length, position, &open);
      if (substitution) {
        size_t substitution_after = 0;
        if (!shell_source_find_balanced_parentheses(input, length, open,
                                                    &substitution_after))
          return false;
        position = substitution_after - 1;
        word_boundary = false;
        continue;
      }
      if (c != '<')
        continue;
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
        word_boundary = false;
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
  if (position >= length)
    return false;
  size_t height;
  if (shell_source_index_get(input, length, position, SHELL_SOURCE_INDEX_PARENS,
                             after, &height)) {
    if (height > SHELL_MAX_SUBCOMMANDS - shell_source_scan_depth)
      return false;
    shell_source_scan_child(height);
    return *after <= length;
  }
  if (!shell_source_scan_enter())
    return false;
  bool complete = shell_source_find_balanced_parentheses_impl(input, length,
                                                              position, after);
  height = shell_source_scan_leave();
  if (complete)
    shell_source_index_put(input, length, position, SHELL_SOURCE_INDEX_PARENS,
                           *after, height);
  return complete;
}

static inline size_t shell_source_skip_balanced_parentheses(const char *input,
                                                            size_t length,
                                                            size_t position) {
  size_t after = 0;
  return shell_source_find_balanced_parentheses(input, length, position, &after)
             ? after
             : length;
}

/* Skip an array subscript beginning at an opening `[`. Array expressions are
 * not evaluated by Shellsplit, but their structural delimiters must still be
 * recognized accurately so quoted or substituted `]` bytes cannot terminate
 * the surrounding parameter or assignment early.
 * input supplies length immutable bytes (NULL only for length zero),
 * position <= length, and after is a required writable offset. */
static inline SHELL_NONNULL(4) bool shell_source_skip_array_subscript(
    const char *input, size_t length, size_t position, size_t *after) {
  if (position >= length || input[position] != '[')
    return false;

  size_t depth = 1;
  for (position++; position < length; position++) {
    SHELL_SOURCE_WORD_SCAN(1);
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
/* Same source-span contract as the subscript skipper. Both output offsets
 * are required, distinct writable destinations. */
static inline SHELL_NONNULL(
    4,
    5) bool shell_source_find_parameter_array_subscript(const char *input,
                                                        size_t length,
                                                        size_t position,
                                                        size_t *after,
                                                        size_t
                                                            *subscript_start) {
  if (position >= length || input[position] != '$')
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
/* Recognize only the selector's scalar head. The word walker consumes a
 * following subscript in its forward scope stream; it never balances that
 * suffix merely to revisit it. Outputs and source span are required storage. */
static SHELL_NONNULL(1, 4, 5) inline bool shell_source_skip_parameter_head(
    const char *input, size_t length, size_t position, size_t *after,
    bool *indirect) {
  *indirect = false;
  if (position >= length)
    return false;

  position = shell_source_skip_escaped_line_endings(input, length, position);
  if (position >= length)
    return false;
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
    *indirect = true;
  }

  if (!shell_source_skip_parameter_base(input, length, &position))
    return false;

  *after = position;
  return true;
}

/* input supplies length immutable bytes (NULL only for length zero),
 * position <= length, and after is required distinct writable storage.
 * No match leaves after unchanged. */
static inline SHELL_NONNULL(4) bool shell_source_skip_parameter_selector(
    const char *input, size_t length, size_t position, size_t *after) {
  if (position >= length)
    return false;
  bool indirect;
  if (!shell_source_skip_parameter_head(input, length, position, &position,
                                        &indirect))
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

typedef enum {
  SHELL_SOURCE_PARAMETER_WORD,
  SHELL_SOURCE_PARAMETER_PATTERN,
  SHELL_SOURCE_PARAMETER_SUBSTRING,
} shell_source_parameter_operand_t;

/* position names a recognized parameter operator. Its immediate logical
 * successor distinguishes :- from : -1; whitespace is significant here. */
static SHELL_NONNULL(1) inline shell_source_parameter_operand_t
    shell_source_parameter_operand(const char *input, size_t length,
                                   size_t position) {
  if (strchr("#%/^,", input[position]))
    return SHELL_SOURCE_PARAMETER_PATTERN;
  if (input[position] == ':') {
    size_t next = shell_source_logical_following(input, length, position);
    if (next == length || !strchr("-=+?", input[next]))
      return SHELL_SOURCE_PARAMETER_SUBSTRING;
  }
  return SHELL_SOURCE_PARAMETER_WORD;
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

static inline SHELL_NONNULL(
    1, 4) bool shell_source_skip_parameter_expansion_impl(const char *input,
                                                          size_t length,
                                                          size_t position,
                                                          size_t *after) {
  if (input[position] != '$')
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
  if (position == length)
    return false;
  shell_source_parameter_operand_t operand =
      shell_source_parameter_operand(input, length, position);
  if (!shell_source_parameter_word_operator(input, length, position, &position))
    return false;
  size_t word_start = position;
  if (operand == SHELL_SOURCE_PARAMETER_SUBSTRING && position < length &&
      input[position] == '}')
    return false;

  while (position < length) {
    SHELL_SOURCE_WORD_SCAN(1);
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
  if (position >= length)
    return false;
  size_t height;
  if (shell_source_index_get(input, length, position,
                             SHELL_SOURCE_INDEX_PARAMETER, after, &height)) {
    if (height > SHELL_MAX_SUBCOMMANDS - shell_source_scan_depth)
      return false;
    shell_source_scan_child(height);
    return *after <= length;
  }
  if (!shell_source_scan_enter())
    return false;
  bool complete = shell_source_skip_parameter_expansion_impl(input, length,
                                                             position, after);
  height = shell_source_scan_leave();
  if (complete)
    shell_source_index_put(input, length, position,
                           SHELL_SOURCE_INDEX_PARAMETER, *after, height);
  return complete;
}

/* Report whether one byte starts shell expansion inside double quotes and,
 * when it does, return the complete span. `$'...'` and process substitution
 * are not special in that context. input supplies length immutable bytes
 * (NULL only for length zero), position <= length, and both outputs are
 * required distinct writable storage. An empty span leaves outputs unchanged;
 * after is defined only for a complete recognized expansion. */
static inline SHELL_NONNULL(4, 5) bool shell_source_skip_double_quote_expansion(
    const char *input, size_t length, size_t position, bool *recognized,
    size_t *after) {
  if (position >= length)
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
static inline SHELL_NONNULL(
    1, 4) bool shell_source_skip_complete_double_quote_impl(const char *input,
                                                            size_t length,
                                                            size_t position,
                                                            size_t *after) {
  if (input[position] != '"')
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
  if (position >= length)
    return false;
  size_t height;
  if (shell_source_index_get(input, length, position,
                             SHELL_SOURCE_INDEX_DOUBLE_QUOTE, after, &height)) {
    if (height > SHELL_MAX_SUBCOMMANDS - shell_source_scan_depth)
      return false;
    shell_source_scan_child(height);
    return *after <= length;
  }
  if (!shell_source_scan_enter())
    return false;
  bool complete = shell_source_skip_complete_double_quote_impl(input, length,
                                                               position, after);
  height = shell_source_scan_leave();
  if (complete)
    shell_source_index_put(input, length, position,
                           SHELL_SOURCE_INDEX_DOUBLE_QUOTE, *after, height);
  return complete;
}

/* Same immutable/empty-span contract as the quote skippers. position <= length;
 * after is required distinct writable storage, defined for a complete match. */
static inline SHELL_NONNULL(5) bool shell_source_skip_complete_quoted_text(
    const char *input, size_t length, size_t position, char quote,
    size_t *after) {
  if (position >= length || input[position] != quote)
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
 * `status-$?` from being split into fictitious argv words. The immutable source
 * may be NULL only for length zero; position <= length. Required distinct
 * after storage is defined for a complete match. */
static inline SHELL_NONNULL(4) bool shell_source_skip_variable_expansion(
    const char *input, size_t length, size_t position, size_t *after) {
  if (position >= length || input[position] != '$')
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
 * complete shell word. Command, backtick, process and arithmetic substitutions
 * are opaque spans: their bodies and quoting belong to separate structural
 * analysis, not to the enclosing word's scalar parameters. A complete braced
 * parameter expansion is emitted as one span, including its operand. Unlike a
 * raw '$' search it respects ordinary quoting, escaped bytes, and Bash ANSI-C
 * `$'...'` fragments (whose escaped apostrophes are not shell quote ends).
 * Input is an immutable span; NULL denotes an empty span only (length == 0).
 * Initialize scan to zero before the first call. Required, distinct writable
 * outputs and scan remain valid across calls; no match leaves outputs intact.
 */
typedef struct {
  size_t position;
  bool in_single_quote;
  bool in_double_quote;
} shell_source_variable_scan_t;

static inline SHELL_NONNULL(3, 4, 5) bool shell_source_next_variable_expansion(
    const char *input, size_t length, shell_source_variable_scan_t *scan,
    size_t *start, size_t *after) {
  while (scan->position < length) {
    SHELL_SOURCE_WORD_SCAN(1);
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
    if (!scan->in_single_quote) {
      bool recognized = false;
      size_t substitution_after = 0;
      if ((c == '$' || c == '`') &&
          !shell_source_skip_double_quote_expansion(
              input, length, position, &recognized, &substitution_after))
        return false;
      if (recognized) {
        scan->position = substitution_after;
        continue;
      }
      size_t open = 0;
      if (!scan->in_double_quote && (c == '<' || c == '>') &&
          shell_source_process_substitution_open(input, length, position,
                                                 &open)) {
        if (!shell_source_find_balanced_parentheses(input, length, open,
                                                    &substitution_after))
          return false;
        scan->position = substitution_after;
        continue;
      }
    }
    scan->position++;
  }
  return false;
}

/* A bounded-state recognizer for any bracket candidate in a forward word
 * stream. Several candidates can overlap (notably inside an unfinished POSIX
 * class), but equivalent states merge instead of retrying their suffixes.
 * Quoted/escaped bytes are fed as literals and cannot open or close syntax. */
typedef struct {
  unsigned states;
} shell_source_glob_scan_t;

static SHELL_NONNULL(1) inline bool shell_source_glob_scan_step(
    shell_source_glob_scan_t *scan, unsigned char byte, bool literal) {
  enum {
    HEAD = 1u << 0,
    NEGATED = 1u << 1,
    BODY = 1u << 2,
    OPEN = 1u << 3,
    CLASS_COLON = 1u << 4,
    CLASS_DOT = 1u << 5,
    CLASS_EQUAL = 1u << 6,
    CLOSE_COLON = 1u << 7,
    CLOSE_DOT = 1u << 8,
    CLOSE_EQUAL = 1u << 9
  };
  SHELL_SOURCE_WORD_SCAN(1);
  if (!literal && (isspace(byte) || strchr("|&;<>()", byte))) {
    scan->states = 0;
    return false;
  }
  unsigned states = scan->states, next = 0;
  bool body = (states & BODY) != 0;
  if (states & (HEAD | NEGATED)) {
    if (!literal && byte == ']')
      next |= BODY; /* A leading ']' is a member, not the terminator. */
    else if (!literal && (byte == '!' || byte == '^') && (states & HEAD)) {
      next |= NEGATED;
      body = body || (states & NEGATED) != 0;
    } else
      body = true;
  }
  if (states & OPEN) {
    if (!literal && byte == ':')
      next |= CLASS_COLON;
    else if (!literal && byte == '.')
      next |= CLASS_DOT;
    else if (!literal && byte == '=')
      next |= CLASS_EQUAL;
    else
      body = true;
  }
  bool complete = body && !literal && byte == ']';
  if (body && !complete)
    next |= !literal && byte == '[' ? OPEN : BODY;
  const unsigned classes[] = {CLASS_COLON, CLASS_DOT, CLASS_EQUAL};
  const unsigned closes[] = {CLOSE_COLON, CLOSE_DOT, CLOSE_EQUAL};
  const unsigned char delimiters[] = {':', '.', '='};
  for (unsigned i = 0; i < 3; i++) {
    if (states & classes[i])
      next |= !literal && byte == delimiters[i] ? closes[i] : classes[i];
    if (states & closes[i])
      next |= !literal && byte == ']'             ? BODY
              : !literal && byte == delimiters[i] ? closes[i]
                                                  : classes[i];
  }
  if (!literal && byte == '[')
    next |= HEAD;
  scan->states = next;
  return complete;
}

typedef struct {
  size_t after; /* Examined endpoint on failure; closing endpoint on success. */
  bool complete;
} shell_source_glob_probe_t;

/* Required source at an opening '['. The probe is linear, but a failed probe
 * must not be repeated at another opener before its examined endpoint. Word
 * classifiers use the streaming recognizer above instead. */
static SHELL_NONNULL(1) inline shell_source_glob_probe_t
    shell_source_probe_glob_bracket(const char *input, size_t length,
                                    size_t position) {
  size_t cursor = position + 1;
  if (cursor < length && (input[cursor] == '!' || input[cursor] == '^')) {
    SHELL_SOURCE_WORD_SCAN(1);
    cursor++;
  }
  if (cursor < length && input[cursor] == ']') {
    SHELL_SOURCE_WORD_SCAN(1);
    cursor++;
  }
  while (cursor < length) {
    SHELL_SOURCE_WORD_SCAN(1);
    char c = input[cursor];
    if (c == '\\' && cursor + 1 < length) {
      cursor += 2;
      continue;
    }
    if (isspace((unsigned char)c) || strchr("|&;<>()", c))
      break;
    if (c == '[' && cursor + 1 < length &&
        (input[cursor + 1] == ':' || input[cursor + 1] == '.' ||
         input[cursor + 1] == '=')) {
      char delimiter = input[cursor + 1];
      cursor += 2;
      while (cursor + 1 < length &&
             !(input[cursor] == delimiter && input[cursor + 1] == ']')) {
        SHELL_SOURCE_WORD_SCAN(1);
        if (input[cursor] == '\\' && cursor + 1 < length)
          cursor++;
        else if (strchr("|&;<>()", input[cursor]))
          return (shell_source_glob_probe_t){cursor, false};
        cursor++;
      }
      if (cursor + 1 >= length)
        return (shell_source_glob_probe_t){length, false};
      cursor += 2;
      continue;
    }
    if (c == ']')
      return (shell_source_glob_probe_t){cursor + 1, true};
    cursor++;
  }
  return (shell_source_glob_probe_t){cursor, false};
}

/* Recognize a complete glob bracket expression.  This is a lexical candidate
 * helper, not a shell-list delimiter suppressor: unquoted shell operators in
 * bracket text still delimit the surrounding command.  POSIX character,
 * equivalence, and collating subexpressions have their own closing delimiter
 * before the outer ']'. input supplies length immutable bytes (NULL only for
 * length zero), position <= length, and after is required distinct writable
 * storage. No match leaves after unchanged. */
static inline SHELL_NONNULL(4) bool shell_source_skip_glob_bracket(
    const char *input, size_t length, size_t position, size_t *after) {
  if (position >= length || input[position] != '[')
    return false;
  shell_source_glob_probe_t probe =
      shell_source_probe_glob_bracket(input, length, position);
  if (probe.complete)
    *after = probe.after;
  return probe.complete;
}

/* Extglob alternatives are shell-word grammar in the supported Bash dialect.
 * Keep their balanced parentheses and internal `|` bytes opaque to the outer
 * command-list scanner, including when the extglob follows a literal prefix.
 * Same immutable/empty-span contract as the bracket skipper: position <=
 * length, and required distinct after storage is defined for a complete match.
 */
static inline SHELL_NONNULL(4) bool shell_source_skip_extglob(const char *input,
                                                              size_t length,
                                                              size_t position,
                                                              size_t *after) {
  size_t open = 0;
  if (position >= length ||
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
 * parameter scanner above. Structural failures are distinct from exhaustion:
 * complete-source consumers must not mistake malformed input for no features.
 */
/* Stateful iterator for executable substitution spans in one complete shell
 * word. Scoped parameter operands and arithmetic expressions are traversed
 * without exposing their punctuation as outer shell syntax. */
typedef enum {
  SHELL_SOURCE_SUBST_COMMAND = 0,
  SHELL_SOURCE_SUBST_BACKTICK,
  SHELL_SOURCE_SUBST_PROCESS_INPUT,
  SHELL_SOURCE_SUBST_PROCESS_OUTPUT,
  /* Only the general word iterator emits this kind. The executable-only
   * adapter below consumes it without exposing it to graph consumers. */
  SHELL_SOURCE_EXPANSION_ARITHMETIC,
  /* A completed substring operand, excluding the selector/operator/brace.
   * The span contains offset and optional length, not a $((...)) wrapper. */
  SHELL_SOURCE_EXPANSION_SUBSTRING,
} shell_source_substitution_kind_t;

typedef enum {
  SHELL_SOURCE_SCAN_DONE = 0,
  SHELL_SOURCE_SCAN_FOUND,
  SHELL_SOURCE_SCAN_MALFORMED,
} shell_source_scan_status_t;

static inline bool
shell_source_arithmetic_content(const char *input, size_t length,
                                size_t position, size_t *content_start,
                                size_t *content_length, size_t *after);

typedef struct {
  bool in_single_quote;
  bool in_double_quote;
  /* A parameter word inside double quotes retains expansion semantics even
   * where apostrophes pair structurally to protect its closing brace. */
  bool inherited_double_quote;
  /* Heredoc roots have literal quote bytes and limited backslash escapes.
   * Their parameter defaults inherit expansion semantics, but not ANSI-C or
   * locale quoting. Pattern operands establish ordinary word quoting. */
  bool heredoc;
  /* Inherited double quoting ignores apostrophes for expansion, but the
   * parameter grammar still pairs them when finding its closing brace. */
  char delimiter_quote;
  bool suppress_process;
  bool arithmetic_scope;
  bool substring_scope;
  bool selector_pending;
  bool selector_indirect;
  bool selector_subscript;
  /* Inherited conditional parameter operand: its substitutions may not run.
   * Stored in the scope stack so querying a yielded substitution is O(1). */
  bool conditional;
  /* In a double-quoted parameter default word, Bash expands the decoded
   * contents of $'...' a second time. Keep its source boundary while walking
   * the executable substitutions in that decoded word. */
  size_t ansi_end;
  char closer; /* Zero at root, '}' for parameters, ')' for math, ']' for
                  arrays. */
  size_t parentheses;
  size_t selector_end;
  size_t word_start;
  size_t expansion_start;
} shell_source_expansion_scope_t;

typedef struct {
  size_t position;
  shell_source_expansion_scope_t scope;
  unsigned scope_count;
  shell_source_expansion_scope_t scopes[SHELL_MAX_SUBCOMMANDS];
  /* Semantic features are independent of which non-overlapping diagnostic
   * element owns the word. Command/process substitution interiors stay opaque.
   */
  bool has_variables;
  bool has_positional;
  bool has_special;
  bool has_arithmetic;
  /* Active expansion failures either abort the current input unit or terminate
   * the noninteractive shell. Nested executable bodies have their own scope.
   * Command/process substitution bodies have their own scope and stay opaque.
   * This is possibility metadata, not evaluation of a runtime value. */
  bool has_expansion_abort;
  bool has_expansion_termination;
  /* Conditional scalar writes cannot be modeled without parameter set/null
   * state and value/attribute semantics. Semantic consumers reject active
   * =/:= operators; lexical consumers still retain their structure. */
  bool has_parameter_write;
  /* Prompt transformations and actual indirect dereferences can evaluate
   * shell syntax stored in a value. Name enumeration is not dereferencing.
   * Semantic consumers reject re-evaluation until its runtime source is
   * modeled; ordinary parameter expansion remains deferred value data. */
  bool has_parameter_reevaluation;
  /* An active legacy backtick body requires escape removal before its nested
   * parse. Reject at the supported-source boundary, not in semantic leaves. */
  bool has_backtick_escapes;
  bool has_arithmetic_variables;
  bool has_arrays;
  bool has_ansi_c;
  bool has_ansi_nul;
  bool has_ansi_locale;
  bool has_locale_quote;
  unsigned arithmetic_depth;
} shell_source_substitution_scan_t;

/* The selector has already been structurally recognized. Record its parameter
 * category without copying a name or rescanning its operand. */
static SHELL_NONNULL(1, 4) inline void shell_source_note_parameter(
    const char *input, size_t length, size_t selector,
    shell_source_substitution_scan_t *scan) {
  if (input[selector] == '#' || input[selector] == '!') {
    size_t next = shell_source_logical_following(input, length, selector);
    if (next < length && input[next] != '}')
      selector = next;
  }
  scan->has_variables = true;
  scan->has_positional |= isdigit((unsigned char)input[selector]) != 0;
  scan->has_special |= shell_source_parameter_is_special(input[selector]);
}

/* Iterate one immutable lexical word. Initialize scan to zero once and reuse
 * it for that same span through DONE. Input may be NULL only for length zero;
 * scan and all output pointers are required distinct writable storage, not
 * aliasing input. FOUND guarantees a complete nonempty expansion span within
 * input: an executable substitution, an outermost arithmetic expansion, or
 * the operand of a completed substring expansion.
 * Executable substitutions inside math precede its completion event; nested
 * arithmetic is owned by the outer math event and never emitted repeatedly.
 * MALFORMED reports source
 * syntax or nesting-limit failure, never invalid pointer arguments. Consume
 * through DONE before publishing results: a later malformed enclosing scope
 * can follow a complete substitution. Parameter and arithmetic scopes close
 * during forward traversal, never by balancing and revisiting their suffixes.
 * Whole-word lexical quote validation belongs to the caller; a classifier may
 * initialize scope.in_double_quote for an already-open containing quote.
 * For an unquoted heredoc body initialize scope.heredoc and
 * scope.suppress_process to true. Its outer quote bytes are data, but nested
 * parameter patterns still establish their own quote contexts.
 */
static inline SHELL_NONNULL(3, 4, 5, 6) shell_source_scan_status_t
    shell_source_next_word_expansion(const char *input, size_t length,
                                     shell_source_substitution_scan_t *scan,
                                     size_t *start, size_t *after,
                                     shell_source_substitution_kind_t *kind) {
  while (scan->position < length) {
    SHELL_SOURCE_WORD_SCAN(1);
    shell_source_expansion_scope_t *scope = &scan->scope;
    size_t position = scan->position;
    if (scope->selector_pending) {
      position =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (position == length)
        return SHELL_SOURCE_SCAN_MALFORMED;
      if (!scope->selector_subscript && input[position] == '[') {
        if (scan->scope_count == SHELL_MAX_SUBCOMMANDS)
          return SHELL_SOURCE_SCAN_MALFORMED;
        scope->selector_subscript = true;
        scan->has_arrays = true;
        scan->scopes[scan->scope_count++] = *scope;
        *scope =
            (shell_source_expansion_scope_t){.suppress_process = true,
                                             .closer = ']',
                                             .parentheses = 1,
                                             .conditional = scope->conditional};
        scan->position = position + 1;
        continue;
      }
      bool name_enumeration =
          scope->selector_indirect && !scope->selector_subscript &&
          (input[position] == '*' || input[position] == '@') &&
          shell_source_logical_next_is(input, length, position, '}', NULL);
      if (name_enumeration)
        position++;
      position =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (position == length)
        return SHELL_SOURCE_SCAN_MALFORMED;
      size_t word_start = position;
      bool has_word = input[position] != '}';
      if (has_word && !shell_source_parameter_word_operator(
                          input, length, position, &word_start))
        return SHELL_SOURCE_SCAN_MALFORMED;
      shell_source_parameter_operand_t operand =
          has_word ? shell_source_parameter_operand(input, length, position)
                   : SHELL_SOURCE_PARAMETER_WORD;
      size_t operator_position = position;
      if (input[operator_position] == ':')
        operator_position =
            shell_source_logical_following(input, length, operator_position);
      scope->conditional |=
          has_word &&
          (operand == SHELL_SOURCE_PARAMETER_PATTERN ||
           input[operator_position] == '-' || input[operator_position] == '+' ||
           input[operator_position] == '=' || input[operator_position] == '?');
      scan->has_parameter_write |= has_word && input[operator_position] == '=';
      bool indirect_lookup = scope->selector_indirect && !name_enumeration;
      scan->has_parameter_reevaluation |=
          indirect_lookup || (has_word && input[operator_position] == '@' &&
                              shell_source_logical_next_is(
                                  input, length, operator_position, 'P', NULL));
      scan->has_expansion_abort |=
          indirect_lookup || (has_word && input[operator_position] == '=');
      scan->has_expansion_termination |=
          has_word && input[operator_position] == '?';
      if (operand == SHELL_SOURCE_PARAMETER_PATTERN) {
        scope->inherited_double_quote = false;
        scope->suppress_process = false;
        scope->heredoc = false;
      }
      if (operand == SHELL_SOURCE_PARAMETER_SUBSTRING) {
        if (word_start < length && input[word_start] == '}')
          return SHELL_SOURCE_SCAN_MALFORMED;
        scope->substring_scope = true;
        scope->arithmetic_scope = true;
        scope->suppress_process = true;
        scan->has_arithmetic = true;
        scan->has_expansion_abort = true;
      }
      scope->selector_pending = false;
      scope->selector_end = position;
      scope->word_start = word_start;
      scan->position = word_start;
      continue;
    }
    if (scope->ansi_end && position >= scope->ansi_end) {
      scan->position = scope->ansi_end + 1;
      scope->ansi_end = 0;
      continue;
    }
    char c = input[position];
    bool heredoc_root = scope->heredoc && scope->closer == 0;
    if (heredoc_root && c == '\\' && position + 1 < length) {
      char next = input[position + 1];
      scan->position += (next == '$' || next == '`' || next == '\\' ||
                         next == '\n' || next == '\r')
                            ? 2
                            : 1;
      continue;
    }
    if (scope->ansi_end && c == '\\') {
      size_t escaped = position;
      while (escaped < scope->ansi_end && input[escaped] == '\\')
        escaped++;
      /* Every pair decodes to one backslash; an unpaired backslash
       * preceding an expansion opener survives ANSI decoding as another
       * backslash. Bash's second expansion sees an unescaped opener for
       * residues 0 and 3. */
      if (escaped < scope->ansi_end &&
          (input[escaped] == '$' || input[escaped] == '`')) {
        size_t slashes = escaped - position;
        scan->position =
            slashes % 4 == 0 || slashes % 4 == 3 ? escaped : escaped + 1;
      } else {
        scan->position = escaped;
      }
      continue;
    }
    if (!scope->heredoc && !scope->in_single_quote && !scope->in_double_quote &&
        !scope->inherited_double_quote && c == '$' &&
        shell_source_logical_next_is(input, length, position, '\'', NULL)) {
      size_t ansi_after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &ansi_after))
        return SHELL_SOURCE_SCAN_MALFORMED;
      scan->has_ansi_c = true;
      size_t nul_after = position;
      bool has_nul = false;
      bool locale_dependent = false;
      (void)shell_source_ansi_c_quote_facts(input, length, &nul_after, &has_nul,
                                            &locale_dependent);
      scan->has_ansi_nul |= has_nul;
      scan->has_ansi_locale |= locale_dependent;
      if (scope->closer == '}' &&
          shell_source_ansi_quote_has_encoded_syntax(
              input, position, ansi_after,
              position == scope->word_start && ansi_after < length &&
                  input[ansi_after] == '}'))
        return SHELL_SOURCE_SCAN_MALFORMED;
      scan->position = ansi_after;
      continue;
    }
    if (!scope->heredoc && !scope->in_single_quote && !scope->in_double_quote &&
        scope->inherited_double_quote && !scope->ansi_end && c == '$' &&
        shell_source_logical_next_is(input, length, position, '\'', NULL)) {
      size_t ansi_after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(input, length, position,
                                                   &ansi_after))
        return SHELL_SOURCE_SCAN_MALFORMED;
      scan->has_ansi_c = true;
      size_t nul_after = position;
      bool has_nul = false;
      bool locale_dependent = false;
      (void)shell_source_ansi_c_quote_facts(input, length, &nul_after, &has_nul,
                                            &locale_dependent);
      scan->has_ansi_nul |= has_nul;
      scan->has_ansi_locale |= locale_dependent;
      if (scope->closer == '}' &&
          shell_source_ansi_quote_has_encoded_syntax(
              input, position, ansi_after,
              position == scope->word_start && ansi_after < length &&
                  input[ansi_after] == '}'))
        return SHELL_SOURCE_SCAN_MALFORMED;
      scope->ansi_end = ansi_after - 1;
      scan->position =
          shell_source_logical_following(input, length, position) + 1;
      continue;
    }
    if (c == '\\' && !scope->in_single_quote && position + 1 < length) {
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, position);
      scan->position =
          continued != position ? continued
          : scope->delimiter_quote == '\'' && input[position + 1] == '\''
              ? position + 1
              : position + 2;
      continue;
    }
    if (scope->inherited_double_quote && !scope->ansi_end &&
        (c == '\'' || c == '"')) {
      if (!scope->delimiter_quote)
        scope->delimiter_quote = c;
      else if (scope->delimiter_quote == c)
        scope->delimiter_quote = 0;
    }
    if (!heredoc_root && c == '\'' && !scope->ansi_end &&
        !scope->in_double_quote && !scope->inherited_double_quote) {
      scope->in_single_quote = !scope->in_single_quote;
      scan->position++;
      continue;
    }
    if (!heredoc_root && c == '"' && !scope->ansi_end &&
        !scope->in_single_quote) {
      scope->in_double_quote = !scope->in_double_quote;
      scan->position++;
      continue;
    }
    if (scope->in_single_quote) {
      scan->position++;
      continue;
    }
    if (scope->arithmetic_scope && c == '[')
      scan->has_arrays = true;
    if (!scope->heredoc && c == '$' && !scope->in_double_quote &&
        scope->delimiter_quote != '\'' &&
        shell_source_logical_next_is(input, length, position, '"', NULL))
      scan->has_locale_quote = true;
    if (c == '`') {
      size_t substitution_after = 0;
      bool escape_sensitive = false;
      if (!shell_source_scan_backtick(input, length, position,
                                      scope->in_double_quote ||
                                          scope->inherited_double_quote,
                                      &substitution_after, &escape_sensitive))
        return SHELL_SOURCE_SCAN_MALFORMED;
      scan->has_backtick_escapes |= escape_sensitive;
      *start = position;
      *after = substitution_after;
      *kind = SHELL_SOURCE_SUBST_BACKTICK;
      scan->position = substitution_after;
      return SHELL_SOURCE_SCAN_FOUND;
    }
    if (c == '$' &&
        shell_source_logical_next_is(input, length, position, '{', NULL)) {
      size_t brace = shell_source_logical_following(input, length, position);
      size_t selector =
          shell_source_skip_escaped_line_endings(input, length, brace + 1);
      size_t head_after = 0;
      bool indirect;
      if (!shell_source_skip_parameter_head(input, length, selector,
                                            &head_after, &indirect))
        return SHELL_SOURCE_SCAN_MALFORMED;
      if (scan->scope_count >= SHELL_MAX_SUBCOMMANDS)
        return SHELL_SOURCE_SCAN_MALFORMED;
      shell_source_note_parameter(input, length, selector, scan);
      scan->scopes[scan->scope_count++] = *scope;
      scan->position = head_after;
      scope->suppress_process = scope->suppress_process ||
                                scope->in_double_quote ||
                                scope->inherited_double_quote;
      scope->inherited_double_quote = (scope->inherited_double_quote ||
                                       scope->in_double_quote || heredoc_root);
      scope->in_single_quote = false;
      scope->in_double_quote = false;
      scope->delimiter_quote = 0;
      scope->arithmetic_scope = false;
      scope->substring_scope = false;
      scope->selector_pending = true;
      scope->selector_indirect = indirect;
      scope->selector_subscript = false;
      scope->ansi_end = 0;
      scope->closer = '}';
      continue;
    }
    size_t open = 0;
    if (c == '$' &&
        shell_source_dollar_arithmetic_open(input, length, position, &open)) {
      if (scan->scope_count >= SHELL_MAX_SUBCOMMANDS)
        return SHELL_SOURCE_SCAN_MALFORMED;
      scan->has_arithmetic = true;
      scan->has_expansion_abort = true;
      scan->arithmetic_depth++;
      scan->scopes[scan->scope_count++] = *scope;
      scan->position = open + 1;
      *scope =
          (shell_source_expansion_scope_t){.suppress_process = true,
                                           .conditional = scope->conditional,
                                           .arithmetic_scope = true,
                                           .closer = ')',
                                           .expansion_start = position,
                                           .parentheses = 1};
      continue;
    }
    if (c == '$' &&
        shell_source_dollar_parentheses_open(input, length, position, &open)) {
      size_t substitution_after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, open,
                                                  &substitution_after))
        return SHELL_SOURCE_SCAN_MALFORMED;
      *start = position;
      *after = substitution_after;
      *kind = SHELL_SOURCE_SUBST_COMMAND;
      scan->position = substitution_after;
      return SHELL_SOURCE_SCAN_FOUND;
    }
    if (!scope->in_double_quote && !scope->inherited_double_quote &&
        !scope->suppress_process && !scope->arithmetic_scope &&
        (c == '<' || c == '>') &&
        shell_source_process_substitution_open(input, length, position,
                                               &open)) {
      size_t substitution_after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, open,
                                                  &substitution_after))
        return SHELL_SOURCE_SCAN_MALFORMED;
      *start = position;
      *after = substitution_after;
      *kind = c == '<' ? SHELL_SOURCE_SUBST_PROCESS_INPUT
                       : SHELL_SOURCE_SUBST_PROCESS_OUTPUT;
      scan->position = substitution_after;
      return SHELL_SOURCE_SCAN_FOUND;
    }
    if (c == '$') {
      size_t variable_after;
      if (shell_source_skip_variable_expansion(input, length, position,
                                               &variable_after)) {
        size_t selector =
            shell_source_logical_following(input, length, position);
        shell_source_note_parameter(input, variable_after, selector, scan);
        scan->position = variable_after;
        continue;
      }
    }
    if (!scope->ansi_end) {
      bool parameter_unquoted =
          scope->inherited_double_quote
              ? scope->delimiter_quote == 0
              : !scope->in_single_quote && !scope->in_double_quote;
      if (scope->closer == '}' && c == '}' && position >= scope->selector_end &&
          parameter_unquoted) {
        bool substring = scope->substring_scope;
        size_t operand_start = scope->word_start;
        scan->position++;
        *scope = scan->scopes[--scan->scope_count];
        if (substring) {
          *start = operand_start;
          *after = position;
          *kind = SHELL_SOURCE_EXPANSION_SUBSTRING;
          return SHELL_SOURCE_SCAN_FOUND;
        }
        continue;
      }
      if (scope->closer == ')' && !scope->in_single_quote &&
          !scope->in_double_quote) {
        if (c == '(')
          scope->parentheses++;
        if (c == ')') {
          if (--scope->parentheses == 0) {
            size_t close =
                shell_source_logical_following(input, length, position);
            if (close >= length || input[close] != ')')
              return SHELL_SOURCE_SCAN_MALFORMED;
            size_t arithmetic_start = scope->expansion_start;
            scan->position = close + 1;
            *scope = scan->scopes[--scan->scope_count];
            if (--scan->arithmetic_depth == 0) {
              *start = arithmetic_start;
              *after = scan->position;
              *kind = SHELL_SOURCE_EXPANSION_ARITHMETIC;
              return SHELL_SOURCE_SCAN_FOUND;
            }
            continue;
          }
        }
      }
      if (scope->closer == ']' && !scope->in_single_quote &&
          !scope->in_double_quote) {
        if (c == '[')
          scope->parentheses++;
        if (c == ']' && --scope->parentheses == 0) {
          scan->position++;
          *scope = scan->scopes[--scan->scope_count];
          continue;
        }
      }
      if (scope->arithmetic_scope && !scope->in_single_quote &&
          !scope->in_double_quote) {
        if (isdigit((unsigned char)c)) {
          size_t number_after;
          if (shell_source_skip_arithmetic_number(input, length, position,
                                                  &number_after)) {
            scan->position = number_after;
            continue;
          }
        }
        if (isalpha((unsigned char)c) || c == '_')
          scan->has_arithmetic_variables = true;
      }
    }
    scan->position++;
  }
  return scan->scope_count ? SHELL_SOURCE_SCAN_MALFORMED
                           : SHELL_SOURCE_SCAN_DONE;
}

/* Compatibility adapter for consumers that need only executable command or
 * process substitutions. The same stream still gathers semantic features and
 * validates expansion scope boundaries through DONE. */
static inline SHELL_NONNULL(3, 4, 5, 6) shell_source_scan_status_t
    shell_source_next_executable_substitution(
        const char *input, size_t length,
        shell_source_substitution_scan_t *scan, size_t *start, size_t *after,
        shell_source_substitution_kind_t *kind) {
  shell_source_scan_status_t status;
  do {
    status = shell_source_next_word_expansion(input, length, scan, start, after,
                                              kind);
  } while (status == SHELL_SOURCE_SCAN_FOUND &&
           (*kind == SHELL_SOURCE_EXPANSION_ARITHMETIC ||
            *kind == SHELL_SOURCE_EXPANSION_SUBSTRING));
  return status;
}

/* Classification of a lexically validated word, not a syntax boundary. The
 * first executable span suffices; callers needing rejection of untrusted raw
 * syntax consume the iterator through DONE instead. */
static inline bool
shell_source_word_has_executable_substitution(const char *input,
                                              size_t length) {
  shell_source_substitution_scan_t scan = {0};
  size_t start = 0, after = 0;
  shell_source_substitution_kind_t kind;
  return shell_source_next_executable_substitution(input, length, &scan, &start,
                                                   &after, &kind) ==
         SHELL_SOURCE_SCAN_FOUND;
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

/* Skip one complete shell word while retaining its raw source span. Unquoted
 * parentheses delimit the outer word; quotes and expansion bodies above keep
 * their parentheses opaque. Unlike a
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
                                           true);
}

/* Recognize Bash's file-content substitution from its complete body, not its
 * first byte. A single fd-0 input redirect may have list trivia and one final
 * semicolon. Other commands, descriptors, or redirects are ordinary shell
 * execution. The caller supplies a syntactically validated immutable body;
 * outputs borrow the original operand, with no decoding or allocation. */
static SHELL_NONNULL(1, 3, 4) inline bool shell_source_file_substitution(
    const char *input, size_t length, size_t *operand_start,
    size_t *operand_end) {
  size_t position = shell_source_skip_list_trivia(input, length, 0);
  size_t operator_position = position;
  uint32_t descriptor = 0;
  shell_source_io_number_t number = shell_source_parse_io_number(
      input, position, length, &operator_position, &descriptor);
  if (number == SHELL_SOURCE_IO_NUMBER_OVERFLOW ||
      (number == SHELL_SOURCE_IO_NUMBER_VALID && descriptor != 0))
    return false;
  operator_position =
      shell_source_skip_escaped_line_endings(input, length, operator_position);
  if (operator_position == length || input[operator_position] != '<')
    return false;
  position = shell_source_logical_following(input, length, operator_position);
  if (position < length && (input[position] == '<' || input[position] == '>' ||
                            input[position] == '&' || input[position] == '('))
    return false;
  position = shell_source_skip_inline_continuations(input, length, position);
  size_t after = position;
  if (!shell_source_skip_shell_word(input, length, position, &after) ||
      after == position)
    return false;
  size_t tail = shell_source_skip_list_trivia(input, length, after);
  if (tail < length && input[tail] == ';')
    tail = shell_source_skip_list_trivia(input, length, tail + 1);
  if (tail != length)
    return false;
  *operand_start = position;
  *operand_end = after;
  return true;
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
    if (shell_source_comment_starts(c, true)) {
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

/* Bash's {name}>word descriptor allocator. The caller's forward lexical
 * cursor has established a word start and 0 <= start <= end in input.
 * Recognition removes physical continuations without copying; after is an
 * absolute source offset. Required pointers refer to valid storage. */
static SHELL_NONNULL(
    1,
    4) inline bool shell_source_parse_named_fd_at_word_start(const char *input,
                                                             size_t start,
                                                             size_t end,
                                                             size_t *after) {
  *after = start;
  if (start == end || input[start] != '{')
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

/* Arbitrary-position recognition boundary for consumers which have not yet
 * established lexical word context. Forward token cursors use the prechecked
 * helper above instead; NULL input/output has the existing no-match meaning. */
static inline bool shell_source_parse_named_fd(const char *input, size_t start,
                                               size_t end, size_t *after) {
  if (after)
    *after = start;
  return input && after && start <= end &&
         shell_source_word_boundary(input, end, start) &&
         shell_source_parse_named_fd_at_word_start(input, start, end, after);
}

static SHELL_NONNULL(1, 4) inline bool shell_source_parse_named_fd_redirect_at_word_start(
    const char *input, size_t start, size_t end, size_t *operator_position) {
  size_t after;
  if (!shell_source_parse_named_fd_at_word_start(input, start, end, &after))
    return false;
  after = shell_source_skip_escaped_line_endings(input, end, after);
  if (after == end || (input[after] != '<' && input[after] != '>'))
    return false;
  *operator_position = after;
  return true;
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

/* Skip one redirect operand. Adjacent redirects delimit each other, so this
 * recognizes `>first>second` as two operations rather than one filename.
 * Quotes and all substitution forms are opaque, keeping the result an exact
 * source span even when a substituted value contains separators or spaces. */
static inline size_t shell_source_skip_redirect_word(const char *input,
                                                     size_t position,
                                                     size_t end) {
  bool word_boundary = true;
  while (position < end) {
    char c = input[position];
    if (shell_source_comment_starts(c, word_boundary))
      break;
    size_t continued =
        shell_source_skip_escaped_line_endings(input, end, position);
    if (continued != position) {
      position = continued;
      continue;
    }
    word_boundary = false;
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
    if (isspace((unsigned char)c) || c == '|' || c == ';' || c == '&' ||
        c == '<' || c == '>' || c == '(' || c == ')')
      break;
    position++;
  }
  return position;
}

/* Brace classification needs no stack: a nested '{' permanently disqualifies
 * its parent's sequence spelling. Only the current innermost sequence and
 * the depth of an outstanding comma need to survive. Once any pair expands,
 * that fact persists even if its outer pair is unmatched. */
typedef struct {
  size_t depth, comma_depth, sequence_depth;
  size_t lengths[3];
  unsigned part;
  bool numeric[3], digits[3], letters[3];
  bool sequence_valid, pending_dot, root_comma, expands, root_expands;
} shell_source_brace_scan_t;

static SHELL_NONNULL(1) inline void shell_source_brace_scan_literal(
    shell_source_brace_scan_t *scan) {
  scan->sequence_valid = false;
}

static SHELL_NONNULL(1) inline bool shell_source_brace_scan_step(
    shell_source_brace_scan_t *scan, unsigned char byte) {
  SHELL_SOURCE_WORD_SCAN(1);
  if (byte == '{') {
    scan->depth++;
    scan->sequence_depth = scan->depth;
    scan->part = 0;
    scan->pending_dot = false;
    scan->sequence_valid = true;
    for (unsigned i = 0; i < 3; i++) {
      scan->lengths[i] = 0;
      scan->numeric[i] = scan->letters[i] = true;
      scan->digits[i] = false;
    }
    return false;
  }
  if (!scan->depth)
    return false;
  if (byte == ',') {
    scan->comma_depth = scan->depth;
    scan->root_comma = scan->root_comma || scan->depth == 1;
    scan->sequence_valid = false;
  }
  if (byte == '}') {
    bool sequence = scan->sequence_depth == scan->depth &&
                    scan->sequence_valid && !scan->pending_dot &&
                    scan->part >= 1 &&
                    ((scan->numeric[0] && scan->digits[0] && scan->numeric[1] &&
                      scan->digits[1]) ||
                     (scan->letters[0] && scan->lengths[0] == 1 &&
                      scan->letters[1] && scan->lengths[1] == 1)) &&
                    (scan->part == 1 || (scan->numeric[2] && scan->digits[2]));
    bool expands = scan->comma_depth == scan->depth || sequence;
    if (scan->depth == 1)
      scan->root_expands = scan->root_comma || sequence;
    scan->expands = scan->expands || expands;
    scan->depth--;
    scan->sequence_valid = false; /* Never restore or rescan a parent's text. */
    return expands;
  }
  if (scan->sequence_depth != scan->depth || !scan->sequence_valid)
    return false;
  if (byte == '.') {
    if (scan->pending_dot) {
      scan->pending_dot = false;
      if (++scan->part > 2)
        scan->sequence_valid = false;
    } else
      scan->pending_dot = true;
    return false;
  }
  if (scan->pending_dot) {
    scan->sequence_valid = false;
    return false;
  }
  unsigned part = scan->part;
  bool digit = byte >= '0' && byte <= '9';
  scan->numeric[part] =
      scan->numeric[part] &&
      (digit || (scan->lengths[part] == 0 && (byte == '+' || byte == '-')));
  scan->digits[part] = scan->digits[part] || digit;
  scan->letters[part] =
      scan->letters[part] && scan->lengths[part] == 0 &&
      ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z'));
  scan->lengths[part]++;
  return false;
}

typedef struct {
  size_t after;
  bool complete, expands, own_expands, dynamic, valid, has_nul;
} shell_source_brace_fragment_t;

typedef struct {
  shell_source_brace_fragment_t *fragment;
  shell_source_glob_scan_t *glob;
} shell_source_brace_ansi_context_t;

static SHELL_NONNULL(2) inline bool shell_source_brace_ansi_byte(
    unsigned char byte, void *context) {
  shell_source_brace_ansi_context_t *ansi = context;
  ansi->fragment->has_nul = ansi->fragment->has_nul || byte == 0;
  shell_source_glob_scan_step(ansi->glob, byte, true);
  return true;
}

static SHELL_NONNULL(2) inline bool shell_source_glob_ansi_byte(
    unsigned char byte, void *context) {
  shell_source_glob_scan_step(context, byte, true);
  return true;
}

/* Recognize active glob syntax in one borrowed shell-word span. This is
 * classification, not another source-validation boundary: diagnostic callers
 * may supply an unfinished word. Quotes and expansion interiors are opaque
 * to outer pattern syntax. Bracket candidates share a bounded forward state,
 * including literal members supplied by quoted/escaped fragments. */
static SHELL_NONNULL(1) inline bool shell_source_word_has_glob(
    const char *input, size_t length) {
  shell_source_glob_scan_t brackets = {0};
  char quote = 0;
  for (size_t position = 0; position < length;) {
    SHELL_SOURCE_WORD_SCAN(1);
    unsigned char byte = (unsigned char)input[position];
    if (quote == '\'') {
      if (byte == '\'')
        quote = 0;
      else
        shell_source_glob_scan_step(&brackets, byte, true);
      position++;
      continue;
    }
    if (byte == '\\') {
      size_t after =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (after != position) {
        position = after;
        continue;
      }
      if (position + 1 == length)
        return false;
      if (quote == '"' && !strchr("$`\"\\", input[position + 1])) {
        shell_source_glob_scan_step(&brackets, byte, true);
        position++;
      } else {
        shell_source_glob_scan_step(&brackets,
                                    (unsigned char)input[position + 1], true);
        position += 2;
      }
      continue;
    }
    if ((!quote && byte == '\'') || byte == '"') {
      quote = quote ? 0 : (char)byte;
      position++;
      continue;
    }
    if (!quote && byte == '$' &&
        shell_source_logical_next_is(input, length, position, '\'', NULL)) {
      if (!shell_source_decode_ansi_c_quote(
              input, length, &position, shell_source_glob_ansi_byte, &brackets))
        return false;
      continue;
    }
    bool expansion = false;
    size_t after = 0;
    if (!shell_source_skip_double_quote_expansion(input, length, position,
                                                  &expansion, &after))
      return false;
    if (!expansion && byte == '$')
      expansion =
          shell_source_skip_variable_expansion(input, length, position, &after);
    size_t open = 0;
    if (!quote && (byte == '<' || byte == '>') &&
        shell_source_process_substitution_open(input, length, position,
                                               &open)) {
      expansion = true;
      if (!shell_source_find_balanced_parentheses(input, length, open, &after))
        return false;
    }
    if (expansion) {
      /* The fragment can supply bracket members, but its source punctuation
       * cannot close a bracket or open a pattern in the containing word. */
      shell_source_glob_scan_step(&brackets, 'x', true);
      position = after;
      continue;
    }
    if (!quote &&
        (byte == '*' || byte == '?' ||
         (strchr("+@!", byte) &&
          shell_source_logical_next_is(input, length, position, '(', NULL))))
      return true;
    if (shell_source_glob_scan_step(&brackets, byte, quote != 0))
      return true;
    position++;
  }
  return false;
}

/* Match a whole, unquoted scalar parameter word for a name-only callback.
 * Outputs borrow a contiguous name from input. Compound words, operators,
 * special parameters, and names requiring continuation removal do not match;
 * resolving those requires a different expansion contract, not a copy here. */
static SHELL_NONNULL(1, 3, 4) inline bool shell_source_word_parameter_name(
    const char *input, size_t length, const char **name, size_t *name_length) {
  if (length < 2 || input[0] != '$')
    return false;
  size_t after = 0;
  if (!shell_source_skip_variable_expansion(input, length, 0, &after) ||
      after != length)
    return false;
  bool braced = input[1] == '{';
  size_t start = braced ? 2 : 1;
  size_t end = braced ? length - 1 : length;
  if (start == end)
    return false;
  bool positional = isdigit((unsigned char)input[start]) != 0;
  if (!positional &&
      !(isalpha((unsigned char)input[start]) || input[start] == '_'))
    return false;
  for (size_t position = start; position < end; position++) {
    unsigned char byte = (unsigned char)input[position];
    if (positional ? !isdigit(byte) : !(isalnum(byte) || byte == '_'))
      return false;
  }
  *name = input + start;
  *name_length = end - start;
  return true;
}

/* Consume a brace fragment once, through its outer close or the word's end.
 * Required source points at an opening '{'. Unmatched literal braces are not
 * malformed. Dynamic fragments are consumed too, never reported with an
 * unchanged cursor. own_expands distinguishes removed outer braces from
 * literal outer braces surrounding a nested expansion. */
static SHELL_NONNULL(1) inline shell_source_brace_fragment_t
    shell_source_scan_brace_fragment(const char *input, size_t length,
                                     size_t open) {
  shell_source_brace_fragment_t result = {.after = length, .valid = true};
  shell_source_brace_scan_t braces = {0};
  shell_source_glob_scan_t glob = {0};
  char quote = 0;
  for (size_t position = open; position < length;) {
    SHELL_SOURCE_WORD_SCAN(1);
    unsigned char c = (unsigned char)input[position];
    if (quote == '\'') {
      if (c == '\'')
        quote = 0;
      else
        shell_source_glob_scan_step(&glob, c, true);
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
      if (position + 1 == length) {
        result.valid = false;
        return result;
      }
      shell_source_brace_scan_literal(&braces);
      shell_source_glob_scan_step(&glob, (unsigned char)input[position + 1],
                                  true);
      position += 2;
      continue;
    }
    if ((!quote && c == '\'') || c == '"') {
      shell_source_brace_scan_literal(&braces);
      quote = quote ? 0 : (char)c;
      position++;
      continue;
    }
    if (!quote && c == '$' &&
        shell_source_logical_next_is(input, length, position, '\'', NULL)) {
      shell_source_brace_scan_literal(&braces);
      shell_source_brace_ansi_context_t ansi = {&result, &glob};
      if (!shell_source_decode_ansi_c_quote(
              input, length, &position, shell_source_brace_ansi_byte, &ansi)) {
        result.valid = false;
        return result;
      }
      continue;
    }
    size_t after = 0, substitution_open = 0;
    bool dynamic = false, complete = true;
    if (c == '`') {
      dynamic = true;
      complete =
          shell_source_skip_complete_backtick(input, length, position, &after);
    } else if (c == '$' && shell_source_dollar_arithmetic_open(
                               input, length, position, NULL)) {
      dynamic = true;
      complete = shell_source_skip_arithmetic_expansion(input, length, position,
                                                        &after);
    } else if ((c == '$' && shell_source_dollar_parentheses_open(
                                input, length, position, &substitution_open)) ||
               (!quote && (c == '<' || c == '>') &&
                shell_source_process_substitution_open(input, length, position,
                                                       &substitution_open))) {
      dynamic = true;
      complete = shell_source_find_balanced_parentheses(
          input, length, substitution_open, &after);
    } else if (c == '$' && shell_source_logical_next_is(input, length, position,
                                                        '{', NULL)) {
      dynamic = true;
      complete = shell_source_skip_parameter_expansion(input, length, position,
                                                       &after);
    } else if (c == '$' && shell_source_skip_variable_expansion(
                               input, length, position, &after)) {
      dynamic = true;
    } else if (!quote && strchr("?*+@!", c) &&
               shell_source_logical_next_is(input, length, position, '(',
                                            &substitution_open)) {
      dynamic = true;
      complete = shell_source_find_balanced_parentheses(
          input, length, substitution_open, &after);
    }
    if (dynamic) {
      result.dynamic = true;
      shell_source_brace_scan_literal(&braces);
      if (!complete) {
        result.valid = false;
        return result;
      }
      position = after;
      continue;
    }
    if (quote) {
      shell_source_glob_scan_step(&glob, c, true);
      position++;
      continue;
    }
    if (c == '*' || c == '?' ||
        shell_source_dollar_has_dynamic_syntax(input, length, position))
      result.dynamic = true;
    result.dynamic =
        shell_source_glob_scan_step(&glob, c, false) || result.dynamic;
    shell_source_brace_scan_step(&braces, c);
    position++;
    if (!braces.depth) {
      result.after = position;
      result.complete = true;
      break;
    }
  }
  result.valid = result.valid && quote == 0;
  result.expands = braces.expands;
  result.own_expands = braces.root_expands;
  return result;
}

/* Whether a complete shell word needs runtime expansion before it has one
 * static byte spelling. Quoted and escaped bytes are literal; ANSI-C quotes
 * are decoded statically. This rejects parameter and command substitutions,
 * glob syntax, actual brace expansion, and unquoted tilde expansion. Semantic
 * consumers use it before quote removal so they cannot promote a
 * runtime-computed word into a builtin, descriptor name, or concrete path. */
typedef enum {
  SHELL_SOURCE_WORD_GENERIC,
  SHELL_SOURCE_WORD_ARGUMENT,
} shell_source_word_context_t;

typedef struct {
  bool dynamic;       /* Runtime expansion other than a leading tilde. */
  bool leading_tilde; /* An unquoted, uncancelled leading tilde prefix. */
} shell_source_word_expansion_t;

/* Argument words (and FILE redirect operands) undergo Bash's assignment-shaped
 * tilde expansion. Recognize the unquoted name[+]= prefix alongside the word
 * walk, not by searching every suffix. A tilde prefix must remain unquoted
 * through its slash/assignment-colon delimiter or the end of the word.
 * CWD resolution models leading tilde expansion separately, but must still
 * reject any later runtime expansion. Keep scanning after its delimiter.
 * NULL or an empty span denotes an unavailable word and is dynamic; otherwise
 * input is an immutable readable span. leading_tilde is meaningful only when
 * dynamic is false. */
static inline shell_source_word_expansion_t
shell_source_word_expansion(const char *input, size_t length,
                            shell_source_word_context_t context) {
  shell_source_word_expansion_t expansion = {0};
  if (!input || length == 0)
    return (shell_source_word_expansion_t){.dynamic = true};
  bool in_single_quote = false;
  bool in_double_quote = false;
  bool tilde_start = true, tilde_prefix = false;
  bool leading_prefix = false;
  enum {
    PREFIX_NONE,
    PREFIX_START,
    PREFIX_NAME,
    PREFIX_PLUS,
    PREFIX_VALUE
  } prefix = context == SHELL_SOURCE_WORD_ARGUMENT ? PREFIX_START : PREFIX_NONE;
  shell_source_brace_scan_t braces = {0};
  shell_source_glob_scan_t glob = {0};
  for (size_t position = 0; position < length;) {
    SHELL_SOURCE_WORD_SCAN(1);
    char c = input[position];
    if (in_single_quote) {
      if (c == '\'')
        in_single_quote = false;
      else
        shell_source_glob_scan_step(&glob, (unsigned char)c, true);
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
        return (shell_source_word_expansion_t){.dynamic = true};
      if (prefix != PREFIX_VALUE)
        prefix = PREFIX_NONE;
      tilde_prefix = false;
      shell_source_brace_scan_literal(&braces);
      shell_source_glob_scan_step(&glob, (unsigned char)input[position + 1],
                                  true);
      position += 2;
      tilde_start = false;
      continue;
    }
    if (!in_double_quote && c == '\'') {
      shell_source_brace_scan_literal(&braces);
      in_single_quote = true;
      if (prefix != PREFIX_VALUE)
        prefix = PREFIX_NONE;
      tilde_start = tilde_prefix = false;
      position++;
      continue;
    }
    if (c == '"') {
      shell_source_brace_scan_literal(&braces);
      in_double_quote = !in_double_quote;
      if (prefix != PREFIX_VALUE)
        prefix = PREFIX_NONE;
      tilde_start = tilde_prefix = false;
      position++;
      continue;
    }
    if (!in_double_quote && c == '$' &&
        shell_source_logical_next_is(input, length, position, '\'', NULL)) {
      shell_source_brace_scan_literal(&braces);
      size_t after = position;
      if (!shell_source_decode_ansi_c_quote(input, length, &after,
                                            shell_source_glob_ansi_byte, &glob))
        return (shell_source_word_expansion_t){.dynamic = true};
      position = after;
      if (prefix != PREFIX_VALUE)
        prefix = PREFIX_NONE;
      tilde_start = tilde_prefix = false;
      continue;
    }
    if (c == '`' ||
        shell_source_dollar_has_dynamic_syntax(input, length, position))
      return (shell_source_word_expansion_t){.dynamic = true};
    if (!in_double_quote) {
      bool value_start = false;
      if (prefix == PREFIX_START)
        prefix =
            isalpha((unsigned char)c) || c == '_' ? PREFIX_NAME : PREFIX_NONE;
      else if (prefix == PREFIX_NAME) {
        if (c == '=') {
          prefix = PREFIX_VALUE;
          value_start = true;
        } else if (c == '+')
          prefix = PREFIX_PLUS;
        else if (!isalnum((unsigned char)c) && c != '_')
          prefix = PREFIX_NONE;
      } else if (prefix == PREFIX_PLUS) {
        value_start = c == '=';
        prefix = value_start ? PREFIX_VALUE : PREFIX_NONE;
      }
      if (tilde_prefix && (c == '/' || (prefix == PREFIX_VALUE && c == ':'))) {
        if (!leading_prefix)
          return (shell_source_word_expansion_t){.dynamic = true};
        expansion.leading_tilde = true;
        tilde_prefix = false;
      }
      if ((c == '<' || c == '>') &&
          shell_source_process_substitution_open(input, length, position, NULL))
        return (shell_source_word_expansion_t){.dynamic = true};
      if ((c == '?' || c == '*' || c == '+' || c == '@' || c == '!') &&
          shell_source_logical_next_is(input, length, position, '(', NULL))
        return (shell_source_word_expansion_t){.dynamic = true};
      if (c == '*' || c == '?')
        return (shell_source_word_expansion_t){.dynamic = true};
      if (shell_source_glob_scan_step(&glob, (unsigned char)c, false))
        return (shell_source_word_expansion_t){.dynamic = true};
      if (c == '~' && tilde_start) {
        tilde_prefix = true;
        leading_prefix = prefix != PREFIX_VALUE;
      }
      if (shell_source_brace_scan_step(&braces, (unsigned char)c))
        return (shell_source_word_expansion_t){.dynamic = true};
      tilde_start = value_start || (prefix == PREFIX_VALUE && c == ':');
    } else
      shell_source_glob_scan_step(&glob, (unsigned char)c, true);
    position++;
  }
  expansion.dynamic =
      in_single_quote || in_double_quote || (tilde_prefix && !leading_prefix);
  expansion.leading_tilde |= tilde_prefix && leading_prefix;
  return expansion;
}

static inline bool shell_source_word_has_dynamic_syntax_in_context(
    const char *input, size_t length, shell_source_word_context_t context) {
  shell_source_word_expansion_t expansion =
      shell_source_word_expansion(input, length, context);
  return expansion.dynamic || expansion.leading_tilde;
}

static inline bool shell_source_word_has_dynamic_syntax(const char *input,
                                                        size_t length) {
  return shell_source_word_has_dynamic_syntax_in_context(
      input, length, SHELL_SOURCE_WORD_GENERIC);
}

static inline SHELL_NONNULL(1) bool shell_source_argument_has_dynamic_syntax(
    const char *input, size_t length) {
  return shell_source_word_has_dynamic_syntax_in_context(
      input, length, SHELL_SOURCE_WORD_ARGUMENT);
}

/* Decode a complete static shell word without allocating.  This is the
 * source-level counterpart of Shellsplit's processed-word rendering: quote
 * removal and ANSI-C quotes are resolved, while any syntax whose value needs
 * expansion keeps the word out of the static-command path.  Keep wrapper
 * recognition here so semantic validation and dependency analysis cannot
 * grow subtly different interpretations of `command` and `builtin`.
 * word is a required readable span (including length zero); visitor is
 * required. context is passed through and may be NULL if the visitor allows
 * it. The visitor must not modify the word. */
static inline SHELL_NONNULL(1, 3) bool shell_source_visit_static_word_in_context(
    const char *word, size_t word_length, shell_source_byte_visitor_t visitor,
    void *context, shell_source_word_context_t word_context) {
  if (word_length == 0 || shell_source_word_has_dynamic_syntax_in_context(
                              word, word_length, word_context))
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

static inline SHELL_NONNULL(1, 3) bool shell_source_visit_static_word(
    const char *word, size_t word_length, shell_source_byte_visitor_t visitor,
    void *context) {
  return shell_source_visit_static_word_in_context(
      word, word_length, visitor, context, SHELL_SOURCE_WORD_GENERIC);
}

static inline SHELL_NONNULL(1, 3) bool shell_source_visit_static_argument(
    const char *word, size_t word_length, shell_source_byte_visitor_t visitor,
    void *context) {
  return shell_source_visit_static_word_in_context(
      word, word_length, visitor, context, SHELL_SOURCE_WORD_ARGUMENT);
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

/* Required live assignment accumulator; failure describes operand syntax or
 * visitor rejection, not missing caller storage. */
static inline SHELL_NONNULL(2) bool shell_source_assignment_emit(
    unsigned char byte, void *context) {
  shell_source_assignment_scan_t *scan = context;
  if (!scan->valid)
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

/* word is a required immutable readable span, even when empty. out is
 * required distinct writable storage, cleared before scanning. visitor may
 * be NULL for classification only; context has the visitor's own contract. */
static inline SHELL_NONNULL(1, 5) bool shell_source_scan_decoded_assignment(
    const char *word, size_t word_length, shell_source_byte_visitor_t visitor,
    void *context, shell_source_decoded_assignment_t *out) {
  *out = (shell_source_decoded_assignment_t){0};
  if (word_length == 0)
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

/* Required live match accumulator, supplied by word_static_equals. */
static inline SHELL_NONNULL(2) bool shell_source_static_word_match_byte(
    unsigned char byte, void *context) {
  shell_source_static_word_match_t *match = context;
  if (match->position >= match->expected_length ||
      byte != (unsigned char)match->expected[match->position])
    match->matches = false;
  match->position++;
  return true;
}

/* Required immutable source span and NUL-terminated expected spelling. */
static inline SHELL_NONNULL(1, 3) bool shell_source_word_static_equals(
    const char *word, size_t word_length, const char *expected) {
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
  SHELL_SOURCE_BUILTIN_BIND,
  SHELL_SOURCE_BUILTIN_BRACKET,
  SHELL_SOURCE_BUILTIN_COMPGEN,
  SHELL_SOURCE_BUILTIN_COMPLETE,
  SHELL_SOURCE_BUILTIN_COMPOPT,
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
  SHELL_SOURCE_BUILTIN_TEST,
  SHELL_SOURCE_BUILTIN_TYPESET,
  SHELL_SOURCE_BUILTIN_UNALIAS,
  SHELL_SOURCE_BUILTIN_UNSET,
  SHELL_SOURCE_BUILTIN_WAIT,
} shell_source_builtin_kind_t;

static inline SHELL_NONNULL(1) shell_source_builtin_kind_t
    shell_source_static_builtin_kind(const char *word, size_t word_length) {
  if (shell_source_word_static_equals(word, word_length, "alias"))
    return SHELL_SOURCE_BUILTIN_ALIAS;
  if (shell_source_word_static_equals(word, word_length, "bind"))
    return SHELL_SOURCE_BUILTIN_BIND;
  if (shell_source_word_static_equals(word, word_length, "["))
    return SHELL_SOURCE_BUILTIN_BRACKET;
  if (shell_source_word_static_equals(word, word_length, "compgen"))
    return SHELL_SOURCE_BUILTIN_COMPGEN;
  if (shell_source_word_static_equals(word, word_length, "complete"))
    return SHELL_SOURCE_BUILTIN_COMPLETE;
  if (shell_source_word_static_equals(word, word_length, "compopt"))
    return SHELL_SOURCE_BUILTIN_COMPOPT;
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
  if (shell_source_word_static_equals(word, word_length, "test"))
    return SHELL_SOURCE_BUILTIN_TEST;
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

/* Required live dash accumulator; context is not optional here. */
static inline SHELL_NONNULL(2) bool shell_source_static_dash_byte(
    unsigned char byte, void *context) {
  shell_source_static_dash_t *dash = context;
  if (dash->position == 0)
    dash->starts_dash = byte == '-';
  dash->position++;
  return true;
}

/* Required immutable source span, including an empty span. */
static inline SHELL_NONNULL(1) bool shell_source_word_static_starts_dash(
    const char *word, size_t word_length) {
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

/* Required live option accumulator; context is not optional here. */
static inline SHELL_NONNULL(2) bool shell_source_command_option_byte(
    unsigned char byte, void *context) {
  shell_source_command_option_scan_t *scan = context;
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
static inline SHELL_NONNULL(1) shell_source_command_option_t
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

static inline SHELL_NONNULL(1) shell_source_wrapper_kind_t
    shell_source_wrapper_kind(const char *word, size_t word_length) {
  if (shell_source_word_static_equals(word, word_length, "command"))
    return SHELL_SOURCE_WRAPPER_COMMAND;
  if (shell_source_word_static_equals(word, word_length, "builtin"))
    return SHELL_SOURCE_WRAPPER_BUILTIN;
  return SHELL_SOURCE_WRAPPER_NONE;
}

/* Required distinct writable state and immutable source span. Empty words
 * are nonexecuting and leave state unchanged; nonempty words initialize it. */
static inline SHELL_NONNULL(1, 2) shell_source_wrapper_step_t
    shell_source_wrapper_start(shell_source_wrapper_state_t *state,
                               const char *word, size_t word_length) {
  if (word_length == 0)
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

/* Required initialized live state and immutable source span. Empty words or
 * an inactive wrapper are nonexecuting and leave state unchanged. */
static inline SHELL_NONNULL(1, 2) shell_source_wrapper_step_t
    shell_source_wrapper_consume(shell_source_wrapper_state_t *state,
                                 const char *word, size_t word_length) {
  if (state->kind == SHELL_SOURCE_WRAPPER_NONE || word_length == 0)
    return SHELL_SOURCE_WRAPPER_NONEXECUTING;
  if (shell_source_argument_has_dynamic_syntax(word, word_length)) {
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

/* Redirect topology needs the same static-word rule. The explicit name keeps
 * call sites clear when they must distinguish a concrete FILE DOC from a
 * runtime pathname or a descriptor-ambiguous operand. */
static inline bool
shell_source_redirect_word_has_dynamic_path_syntax(const char *input,
                                                   size_t length) {
  return shell_source_word_has_dynamic_syntax_in_context(
      input, length, SHELL_SOURCE_WORD_ARGUMENT);
}

/* At a lexical word boundary, skip one complete redirection and its operand.
 * The calling redirect-list walk supplies the boundary. Return the original
 * position when it is not a valid redirect at that offset. This is shared by
 * compound boundary detection and prefix validation so descriptor punctuation
 * never becomes a spurious command separator. */
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
    named_fd = shell_source_parse_named_fd_at_word_start(input, position, end,
                                                         &cursor);
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

typedef struct {
  size_t redirect_end;
  size_t next_stage;
  shell_pipe_mode_t pipe_mode;
  bool has_pipeline;
} shell_source_compound_tail_t;

/* Inspect the grammar immediately following a completed compound command.
 * Redirects in this position belong to the compound itself, even though the
 * fast parser may retain them as separate structural ranges. If a pipeline
 * connector follows that redirect list, next_stage names the first
 * non-trivia byte of its following member. Ordinary line endings and list
 * operators stop the scan; only the trivia after an already recognized pipe
 * may cross physical lines. The caller supplies immutable input[0..length)
 * and compound_end <= length from its unchanged parse result. */
static SHELL_NONNULL(1) inline shell_source_compound_tail_t
    shell_source_parse_compound_tail(const char *input, size_t length,
                                     size_t compound_end) {
  shell_source_compound_tail_t result = {
      .redirect_end = compound_end,
      .next_stage = compound_end,
      .pipe_mode = SHELL_PIPE_MODE_NONE,
      .has_pipeline = false,
  };
  size_t position = compound_end;
  for (;;) {
    position = shell_source_skip_inline_continuations(input, length, position);
    size_t after = shell_source_skip_redirect(input, position, length);
    if (after == position)
      break;
    result.redirect_end = after;
    position = after;
  }

  position = shell_source_skip_inline_continuations(input, length, position);
  size_t after = position;
  if (shell_source_match_logical_punctuation(input, length, position, "|&",
                                             &after)) {
    result.pipe_mode = SHELL_PIPE_MODE_STDOUT_AND_STDERR;
  } else if (shell_source_match_logical_punctuation(input, length, position,
                                                    "|", &after)) {
    size_t logical_next =
        shell_source_skip_escaped_line_endings(input, length, after);
    if (logical_next < length && input[logical_next] == '|')
      return result;
    result.pipe_mode = SHELL_PIPE_MODE_STDOUT;
  } else {
    return result;
  }

  result.has_pipeline = true;
  result.next_stage = shell_source_skip_list_trivia(input, length, after);
  return result;
}

/* Shellclave rejects a complete redirection list immediately before a
 * compound-group delimiter. Keep that policy identical in both tokenizers;
 * this scanner recognizes every redirect spelling accepted by the fast path,
 * including read/write, clobber, and descriptor forms. The caller supplies
 * immutable input[0..end) with start <= end. */
static SHELL_NONNULL(1) inline bool shell_source_redirect_list_before_group(
    const char *input, size_t start, size_t end) {
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
