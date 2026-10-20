#ifndef SHELL_SOURCE_INTERNAL_H
#define SHELL_SOURCE_INTERNAL_H

#include "shell_ascii.h"
#include "shell_source.h"
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

/* Bash grammar blanks are space/tab; only LF ends a source line. CR, VT and
 * FF remain word bytes. Numeric operands and arithmetic use separate rules. */
static inline bool shell_source_blank(unsigned char byte) {
  return byte == ' ' || byte == '\t';
}

static inline bool shell_source_space(unsigned char byte) {
  return shell_source_blank(byte) || byte == '\n';
}

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
  SHELL_SOURCE_INDEX_HEREDOC_BODY,
  SHELL_SOURCE_INDEX_UNCLOSED_PARENS,
  SHELL_SOURCE_INDEX_BACKTICK,
  SHELL_SOURCE_INDEX_UNCLOSED_BACKTICK,
  SHELL_SOURCE_INDEX_LITERAL_FRAGMENT,
};
typedef struct {
  uintptr_t begin, end, frontier;
} shell_source_scope_t;
/* Private backing, owned by one operation. Graphs reserve it in their existing
 * workspace; allocation-free defaults lease the bounded TLS instance. */
#define SHELL_SOURCE_INDEX_CAPACITY 4096u
typedef struct {
  uintptr_t key;
  size_t value, height;
  unsigned kind, generation;
} shell_source_index_entry_t;
typedef struct {
  shell_source_index_entry_t entries[SHELL_SOURCE_INDEX_CAPACITY];
} shell_source_index_t;
/* Non-evicting subscript facts. Entries are ordered by source offset, so an
 * unsuccessful outer candidate cannot make nested candidates rescan it.
 * parent is temporary linkage for the iterative matching walk. */
typedef struct shell_source_array_boundary {
  uintptr_t key, after, failed_end;
  struct shell_source_array_boundary *parent;
} shell_source_array_boundary_t;
#define SHELL_SOURCE_INLINE_ARRAYS 8u
typedef struct {
  shell_source_array_boundary_t *entries;
  size_t count;
  bool prepared;
} shell_source_array_index_t;
typedef struct {
  uintptr_t begin, end;
  shell_source_scope_t scope;
  unsigned depth, generation;
  bool bytes_prechecked, owns_default_index;
  shell_source_index_t *index;
  unsigned char scratch[256];
  void *workspace;
  uintptr_t workspace_begin, workspace_end;
  size_t workspace_size, scratch_used;
  bool scratch_exhausted;
  void *owned_workspace;
  shell_source_array_index_t arrays;
  shell_source_array_boundary_t inline_arrays[SHELL_SOURCE_INLINE_ARRAYS];
} shell_source_operation_t;
#ifdef __cplusplus
extern "C" {
#endif
void shell_source_operation_begin(const char *input, size_t length)
    SHELL_NONNULL(1);
/* The root graph adapter already has a successful strict parse or qualified
 * draft prefix for exactly this operation's immutable root. Transfer its
 * byte-admission guarantee without traversing the source. Error/truncated
 * results establish no such guarantee. Independent callbacks do not inherit
 * it; recursive implementation views share their root's proof. */
void shell_source_operation_prechecked(void);
void shell_source_operation_end(void);
/* Allocating adapters reserve one operation-owned arena, reused by internal
 * views and released by operation_end. False means allocation failure and
 * leaves no active operation. Allocation-free boundaries never call this. */
bool shell_source_operation_begin_owned(const char *input, size_t length)
    SHELL_NONNULL(1);
/* Internal consumers explicitly share this operation. Application callbacks
 * suspend it instead: their public calls are independent validation domains,
 * even when their input overlaps the enclosing source. No cache is copied. */
shell_source_operation_t shell_source_operation_suspend(void);
void shell_source_operation_restore(shell_source_operation_t previous);
/* Bind initialized operation-local backing before any source traversal. The
 * required index is writable, aligned, and lives through the operation. */
void shell_source_operation_index(shell_source_index_t *index) SHELL_NONNULL(1);
/* Borrow optional additional scratch for this operation. NULL/zero keeps the
 * bounded private default. Contained consumers inherit their owner's buffer;
 * application callbacks have independent operations regardless of overlap. */
typedef struct {
  void *buffer;
  size_t size, used;
  bool exhausted, inherit;
  uintptr_t begin, end;
  shell_source_array_index_t arrays;
  bool share_arrays;
  shell_source_array_boundary_t inline_arrays[SHELL_SOURCE_INLINE_ARRAYS];
} shell_source_workspace_scope_t;
shell_source_workspace_scope_t
shell_source_workspace_begin(const char *source, size_t length, void *buffer,
                             size_t size) SHELL_NONNULL(1);
void shell_source_workspace_end(shell_source_workspace_scope_t previous);
size_t shell_source_scratch_mark(void);
void *shell_source_scratch_take(size_t size);
void shell_source_scratch_release(size_t mark);
bool shell_source_scratch_exhausted(void);
/* External source-byte boundary, shared by tokenizer and processor adapters.
 * Reject NUL, non-whitespace control bytes and DEL. High bytes are literal
 * data in ordinary quotes and heredoc islands; nested executable source
 * establishes its own word contexts. Successful
 * checks of the operation's immutable root cover its contained spans. */
bool shell_source_bytes_valid(const char *input, size_t length)
    SHELL_NONNULL(1);
/* Typed admission for source consumers. A successful operation-wide check is
 * shared with contained spans. Non-NUL byte restrictions describe the model,
 * not Bash syntax; representational rejection and resource stops stay distinct.
 */
shell_source_status_t shell_source_bytes_status(const char *input,
                                                size_t length) SHELL_NONNULL(1);

/* High-byte admission after control/NUL rejection. Ordinary quoted literals
 * and heredoc data preserve bytes; arithmetic/selectors remain code. */
shell_source_status_t shell_source_scoped_bytes_status(const char *input,
                                                       size_t length)
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
/* opening identifies a known opening bracket in this workspace's immutable
 * source view. NULL reports unavailable bookkeeping scratch, not a syntax
 * error. Returned storage lasts through the operation and is not evicted. */
shell_source_array_boundary_t *shell_source_array_boundary(const char *opening)
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
/* Use the array index width for balanced scanner unwinds. Narrow unsigned
 * wrap can become an oversized TLS relocation when GCC folds those paths. */
#ifdef __cplusplus
static thread_local size_t shell_source_scan_depth;
static thread_local size_t shell_source_scan_heights[SHELL_MAX_SUBCOMMANDS];
#else
static _Thread_local size_t shell_source_scan_depth;
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

/* Classify unsupported reserved syntax only after the caller establishes a
 * grammar-reserved-word position. Quotes, ordinary escapes and adjoining word
 * fragments prevent a match; physical continuations do not. `after` optionally
 * receives the logical word's physical end, so a draft can distinguish an
 * appendable word at received EOF from a committed unsupported construct.
 * Supported groups and pipeline prefixes are handled by their own grammar. */
static SHELL_NONNULL(1) inline bool shell_source_unsupported_keyword(
    const char *input, size_t end, size_t position, size_t *after) {
  static const char *const words[] = {
      "if",     "then",   "else",     "elif", "fi",   "for",
      "while",  "until",  "do",       "done", "case", "esac",
      "select", "coproc", "function", "[[",   "in",   "]]"};
  /* Consume a shared physical prefix only once. Most command words cannot
   * start a keyword at all; do not enter the logical-word matcher for every
   * keyword on every ordinary command in semantic sweeps. */
  position = shell_source_skip_escaped_line_endings(input, end, position);
  if (position == end)
    return false;
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++)
    if (input[position] == words[i][0] &&
        shell_source_match_plain_word(input, end, position, words[i],
                                      strlen(words[i]), after))
      return true;
  return false;
}

/* A complete shell word followed by an empty parenthesized declarator is
 * unsupported function syntax. Bash accepts names beyond C identifiers,
 * including quoted words; name restrictions cannot prove a grammar error.
 * position is the known word end. Blanks/continuations are allowed, not LF. */
static inline SHELL_NONNULL(1) bool shell_source_function_declarator_after(
    const char *input, size_t length, size_t position) {
  position = shell_source_skip_inline_continuations(input, length, position);
  if (position == length || input[position] != '(')
    return false;
  position =
      shell_source_skip_inline_continuations(input, length, position + 1);
  return position < length && input[position] == ')';
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
    if (shell_source_space(next)) {
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
 * comments end this prefix scan, while escaped line endings do not. The
 * caller supplies a pipeline-head context; post-connector keyword recognition
 * belongs to the forward lexer and list-grammar boundary, not this span scan.
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
    while (start < end && shell_source_blank((unsigned char)input[start])) {
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

    if (position >= end || input[position] == '\n' ||
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
    if (identifier_length == 0 ? !(shell_ascii_alpha(byte) || byte == '_')
                               : !(shell_ascii_alnum(byte) || byte == '_'))
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
 * that semantic fact on completion or received EOF; NULL requests delimiter
 * location only.
 * The borrowed raw body cannot represent the removed layer faithfully, so the
 * supported-source boundary rejects active escape-sensitive forms.
 * input supplies length immutable bytes (NULL only for length zero),
 * position <= length, and after is a required writable offset. */
static inline SHELL_NONNULL(5) bool shell_source_scan_backtick(
    const char *input, size_t length, size_t position, bool double_quoted,
    size_t *after, bool *escape_sensitive) {
  if (position >= length || input[position] != '`')
    return false;
  size_t cached_after, escapes;
  bool complete = shell_source_index_get(input, length, position,
                                         SHELL_SOURCE_INDEX_BACKTICK,
                                         &cached_after, &escapes) &&
                  cached_after <= length;
  if (complete || (shell_source_index_get(input, length, position,
                                          SHELL_SOURCE_INDEX_UNCLOSED_BACKTICK,
                                          &cached_after, &escapes) &&
                   cached_after == length)) {
    if (escape_sensitive)
      *escape_sensitive = (escapes & (double_quoted ? 3u : 1u)) != 0;
    if (complete)
      *after = cached_after;
    return complete;
  }
  /* Cache quote-independent facts, not the caller's quote-dependent answer.
   * The same raw child may first be located by a delimiter-only consumer. */
  escapes = 0;
  for (size_t cursor = position + 1; cursor < length; cursor++) {
    SHELL_SOURCE_WORD_SCAN(1);
    SHELL_SOURCE_DELIMITER_SCAN(input, cursor);
    if (input[cursor] == '\\' && cursor + 1 < length) {
      char next = input[cursor + 1];
      if (next == '$' || next == '`' || next == '\\' || next == '\n')
        escapes |= 1u;
      if (next == '"')
        escapes |= 2u;
      SHELL_SOURCE_WORD_SCAN(1);
      SHELL_SOURCE_DELIMITER_SCAN(input, cursor + 1);
      cursor++;
      continue;
    }
    if (input[cursor] == '`') {
      *after = cursor + 1;
      shell_source_index_put(input, length, position,
                             SHELL_SOURCE_INDEX_BACKTICK, *after, escapes);
      if (escape_sensitive)
        *escape_sensitive = (escapes & (double_quoted ? 3u : 1u)) != 0;
      return true;
    }
  }
  shell_source_index_put(input, length, position,
                         SHELL_SOURCE_INDEX_UNCLOSED_BACKTICK, length, escapes);
  if (escape_sensitive)
    *escape_sensitive = (escapes & (double_quoted ? 3u : 1u)) != 0;
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

typedef enum {
  /* Unclassified delimiter grammar/normalization, not a Bash error proof. */
  SHELL_HEREDOC_WORD_INVALID,
  SHELL_HEREDOC_WORD_COMPLETE,
  SHELL_HEREDOC_WORD_INCOMPLETE,
  /* A received operator/comment/separator commits an absent word. */
  SHELL_HEREDOC_WORD_MISSING,
} shell_source_heredoc_word_status_t;

/* Delimiter-only fragments are balanced and normalized lexically, never
 * evaluated as expansions. position points to a recognized opener. */
shell_source_heredoc_word_status_t
shell_source_heredoc_fragment(const char *input, size_t length,
                              size_t *position) SHELL_NONNULL(1, 3);

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

/* Forward lexical facts for an already complete delimiter word. Balanced
 * dollar/process and backtick fragments are delimiter spelling, not quoting
 * of the heredoc body. Quotes inside them do not set its quoted flag.
 * position starts at a fragment boundary and receives the next active ANSI-C
 * opener, or length. quoted accumulates actual outer quoting. No syntax is
 * revalidated here; the declaration probe established complete fragments. */
static inline SHELL_NONNULL(1, 3, 4) size_t
    shell_source_next_heredoc_ansi(const char *word, size_t length,
                                   size_t *position, bool *quoted) {
  char quote = '\0';
  while (*position < length) {
    SHELL_SOURCE_WORD_SCAN(1);
    size_t cursor = *position;
    char c = word[cursor];
    if (quote != '\'' && (!quote || c == '$') &&
        shell_source_heredoc_fragment_open(word, length, cursor)) {
      (void)shell_source_heredoc_fragment(word, length, position);
      continue;
    }
    if (quote != '\'' && c == '`') {
      size_t after = length;
      (void)shell_source_skip_complete_backtick(word, length, cursor, &after);
      *position = after;
      continue;
    }
    if (!quote && c == '$' &&
        shell_source_logical_next_is(word, length, cursor, '\'', NULL)) {
      *quoted = true;
      return cursor;
    }
    if (!quote && (c == '\'' || c == '"')) {
      *quoted = true;
      quote = c;
    } else if (quote && c == quote) {
      quote = '\0';
    } else if (c == '\\' && quote != '\'') {
      size_t continued =
          shell_source_skip_escaped_line_endings(word, length, cursor);
      if (continued != cursor) {
        *position = continued;
        continue;
      }
      if (!quote || word[cursor + 1] == '$' || word[cursor + 1] == '`' ||
          word[cursor + 1] == '"' || word[cursor + 1] == '\\') {
        *quoted = true;
        (*position)++;
      }
    }
    (*position)++;
  }
  return length;
}

/* The word is lexically complete (it may have unsupported semantics).
 * NULL/zero represents no word. Heredoc delimiters do quote removal but do not
 * expand parameter-like text. Inspect only active ANSI-C quotes, not literal
 * dollars in other quotes or raw backtick fragments. */
static inline bool
shell_source_heredoc_word_has_unsupported_ansi_c(const char *word,
                                                 size_t length) {
  if (!word)
    return false;
  size_t position = 0;
  bool quoted = false;
  while (shell_source_next_heredoc_ansi(word, length, &position, &quoted) <
         length) {
    bool has_nul = false;
    bool locale_dependent = false;
    if (!shell_source_ansi_c_quote_facts(word, length, &position, &has_nul,
                                         &locale_dependent))
      return false;
    if (has_nul || locale_dependent)
      return true;
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

/* Read the delimiter word after a `<<` or `<<-` operator. Grouped fragments
 * undergo lexical normalization, never runtime expansion. Retain the original
 * word, then prepare its normalized delimiter once
 * before comparing body lines. Unchanged flat unquoted spellings remain
 * zero-copy. */
static inline shell_source_heredoc_word_status_t
shell_source_probe_heredoc_delimiter(const char *input, size_t length,
                                     size_t *position,
                                     shell_source_pending_heredoc_t *pending) {
  size_t cursor =
      shell_source_skip_escaped_line_endings(input, length, *position);
  pending->strip_tabs = false;
  if (cursor < length && input[cursor] == '-') {
    pending->strip_tabs = true;
    cursor++;
  }
  cursor = shell_source_skip_inline_continuations(input, length, cursor);
  pending->word = input + cursor;
  pending->word_length = length - cursor;
  if (cursor == length)
    return SHELL_HEREDOC_WORD_INCOMPLETE;
  /* The delimiter is a shell word. A raw hash at its start therefore begins a
   * comment, including the `<<-#comment` spelling where the immediately
   * preceding byte is the heredoc operator's optional dash. Quoted and
   * backslash-escaped hashes remain ordinary delimiter bytes below. */
  if (input[cursor] == '#')
    return SHELL_HEREDOC_WORD_MISSING;

  size_t start = cursor;
  char quote = '\0';
  while (cursor < length) {
    char c = input[cursor];
    if (quote == '"' && c == '`') {
      size_t after;
      if (!shell_source_skip_complete_backtick(input, length, cursor, &after))
        return SHELL_HEREDOC_WORD_INCOMPLETE;
      cursor = after;
      continue;
    }
    if (quote != '\'' && (!quote || c == '$') &&
        shell_source_heredoc_fragment_open(input, length, cursor)) {
      shell_source_heredoc_word_status_t status =
          shell_source_heredoc_fragment(input, length, &cursor);
      if (status != SHELL_HEREDOC_WORD_COMPLETE)
        return status;
      continue;
    }
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
        return SHELL_HEREDOC_WORD_INCOMPLETE;
      size_t continued =
          shell_source_skip_escaped_line_endings(input, length, cursor);
      cursor = continued != cursor ? continued : cursor + 2;
      continue;
    }
    if (c == '$' &&
        shell_source_logical_next_is(input, length, cursor, '"', NULL))
      return SHELL_HEREDOC_WORD_INVALID; /* Locale-dependent delimiter. */
    if (c == '$' &&
        shell_source_logical_next_is(input, length, cursor, '\'', NULL)) {
      size_t after = 0;
      bool has_nul, locale_dependent;
      after = cursor;
      if (!shell_source_ansi_c_quote_facts(input, length, &after, &has_nul,
                                           &locale_dependent))
        return SHELL_HEREDOC_WORD_INCOMPLETE;
      if (locale_dependent)
        return SHELL_HEREDOC_WORD_INVALID;
      cursor = after;
      continue;
    }
    if (c == '`') {
      /* Backticks are retained literal delimiter spelling, but still group
       * lexical spaces and operators. Do not parse the enclosed text as a
       * command or let its punctuation split the declaration. */
      size_t after;
      if (!shell_source_skip_complete_backtick(input, length, cursor, &after))
        return SHELL_HEREDOC_WORD_INCOMPLETE;
      cursor = after;
      continue;
    }
    if (c == '\'' || c == '"') {
      quote = c;
      cursor++;
      continue;
    }
    if ((c == '<' || c == '>') &&
        shell_source_logical_following(input, length, cursor) == length)
      return SHELL_HEREDOC_WORD_INCOMPLETE; /* A following '(' can form a word.
                                             */
    if (shell_source_space((unsigned char)c) || c == ';' || c == '&' ||
        c == '|' || c == '<' || c == '>' || c == '(' || c == ')')
      break;
    cursor++;
  }
  /* A shell word is required, but quote removal may legitimately produce an
   * empty delimiter: `<<''` and `<<""` terminate on a blank physical line. */
  if (quote != '\0')
    return SHELL_HEREDOC_WORD_INCOMPLETE;
  if (cursor == start)
    return SHELL_HEREDOC_WORD_MISSING;
  pending->word = input + start;
  pending->word_length = cursor - start;
  *position = cursor;
  return SHELL_HEREDOC_WORD_COMPLETE;
}

static inline bool
shell_source_parse_heredoc_delimiter(const char *input, size_t length,
                                     size_t *position,
                                     shell_source_pending_heredoc_t *pending) {
  return shell_source_probe_heredoc_delimiter(
             input, length, position, pending) == SHELL_HEREDOC_WORD_COMPLETE;
}

typedef struct {
  unsigned char *bytes; /* NULL measures the decoded representation. */
  size_t length;
} shell_source_heredoc_decode_t;

static inline SHELL_NONNULL(2) void shell_source_heredoc_decode_byte(
    unsigned char byte, shell_source_heredoc_decode_t *decoded) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_HEREDOC_PREPARATION);
#endif
  if (decoded->bytes)
    decoded->bytes[decoded->length] = byte;
  decoded->length++;
}

typedef struct {
  shell_source_heredoc_decode_t *decoded;
  bool quoted, escape;
  char quote;
} shell_source_heredoc_remove_t;

/* Consume the virtual lexical spelling, not the raw source. Quotes in a
 * literal backtick may affect this pass but never its lexical quoted flag. */
static inline SHELL_NONNULL(2) void shell_source_heredoc_remove_byte(
    unsigned char byte, shell_source_heredoc_remove_t *remove) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_HEREDOC_PREPARATION);
#endif
  if (!remove->quoted) {
    shell_source_heredoc_decode_byte(byte, remove->decoded);
    return;
  }
  if (remove->escape) {
    remove->escape = false;
    if (remove->quote == '"' && byte != '$' && byte != '`' && byte != '"' &&
        byte != '\\' && byte != '\n')
      shell_source_heredoc_decode_byte('\\', remove->decoded);
  } else if (remove->quote == '\'') {
    if (byte == '\'') {
      remove->quote = '\0';
      return;
    }
  } else if (byte == '\\') {
    remove->escape = true;
    return;
  } else if (byte == '"') {
    remove->quote = remove->quote ? '\0' : '"';
    return;
  } else if (byte == '\'' && !remove->quote) {
    remove->quote = '\'';
    return;
  }
  shell_source_heredoc_decode_byte(byte, remove->decoded);
}

typedef struct {
  shell_source_heredoc_remove_t *remove;
  unsigned char first;
  bool have_first, started, terminated;
} shell_source_heredoc_ansi_t;

static inline SHELL_NONNULL(2) void shell_source_heredoc_protect_byte(
    unsigned char byte, shell_source_heredoc_remove_t *remove) {
  shell_source_heredoc_remove_byte(byte, remove);
  if (byte == '\'') {
    shell_source_heredoc_remove_byte('\\', remove);
    shell_source_heredoc_remove_byte('\'', remove);
    shell_source_heredoc_remove_byte('\'', remove);
  }
}

/* Bash lexically replaces $'...' with sh_single_quote(decoded). Delay the
 * first byte to implement its singleton-apostrophe spelling (\\') without
 * another scan or an intermediate allocation. NUL ends only this segment. */
static inline SHELL_NONNULL(2) bool shell_source_heredoc_ansi_byte(
    unsigned char byte, void *context) {
  shell_source_heredoc_ansi_t *ansi = (shell_source_heredoc_ansi_t *)context;
  if (ansi->terminated)
    return true;
  if (!byte) {
    ansi->terminated = true;
    return true;
  }
  if (!ansi->have_first) {
    ansi->first = byte;
    ansi->have_first = true;
    return true;
  }
  if (!ansi->started) {
    shell_source_heredoc_remove_byte('\'', ansi->remove);
    shell_source_heredoc_protect_byte(ansi->first, ansi->remove);
    ansi->started = true;
  }
  shell_source_heredoc_protect_byte(byte, ansi->remove);
  return true;
}

/* Measure/fill the same forward stream: lexical continuation removal and
 * protected ANSI-C translation first, then whole-word quote removal. Actual
 * lexical quotes control body expansion independently of the second phase. */
static inline SHELL_NONNULL(1, 2, 3) void shell_source_decode_heredoc(
    const shell_source_pending_heredoc_t *pending,
    shell_source_heredoc_decode_t *decoded, bool *quoted) {
  char lexical_quote = '\0';
  *quoted = false;
  size_t lexical = 0;
  size_t ansi = shell_source_next_heredoc_ansi(
      pending->word, pending->word_length, &lexical, quoted);
  shell_source_heredoc_remove_t remove = {decoded, *quoted, false, '\0'};
  size_t backtick_end = 0;
  for (size_t word = 0; word < pending->word_length;) {
    SHELL_SOURCE_WORD_SCAN(1);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_HEREDOC_PREPARATION);
#endif
    char c = pending->word[word++];
    if (word - 1 == ansi) {
      size_t position = word - 1;
      shell_source_heredoc_ansi_t fragment = {&remove, 0, false, false, false};
      /* The declaration probe admitted this complete fragment; our visitor
       * cannot fail. Do not revalidate syntax in either measure or fill. */
      (void)shell_source_decode_ansi_c_quote(
          pending->word, pending->word_length, &position,
          shell_source_heredoc_ansi_byte, &fragment);
      if (!fragment.started) {
        if (fragment.have_first && fragment.first == '\'') {
          shell_source_heredoc_remove_byte('\\', &remove);
          shell_source_heredoc_remove_byte('\'', &remove);
        } else {
          shell_source_heredoc_remove_byte('\'', &remove);
          if (fragment.have_first)
            shell_source_heredoc_remove_byte(fragment.first, &remove);
          shell_source_heredoc_remove_byte('\'', &remove);
        }
      } else {
        shell_source_heredoc_remove_byte('\'', &remove);
      }
      word = position;
      lexical = position;
      ansi = shell_source_next_heredoc_ansi(pending->word, pending->word_length,
                                            &lexical, quoted);
      continue;
    }
    if (word > backtick_end && lexical_quote != '\'' && c == '`')
      (void)shell_source_skip_complete_backtick(
          pending->word, pending->word_length, word - 1, &backtick_end);
    bool in_backtick = word <= backtick_end;
    if (c == '\\' && lexical_quote != '\'') {
      size_t continued = shell_source_skip_escaped_line_endings(
          pending->word, pending->word_length, word - 1);
      if (continued != word - 1) {
        word = continued;
        continue;
      }
      shell_source_heredoc_remove_byte((unsigned char)c, &remove);
      /* A complete word has a following byte for every lexical escape. */
      if (in_backtick || !lexical_quote || pending->word[word] == '$' ||
          pending->word[word] == '`' || pending->word[word] == '"' ||
          pending->word[word] == '\\')
        shell_source_heredoc_remove_byte((unsigned char)pending->word[word++],
                                         &remove);
      continue;
    }
    if (!in_backtick) {
      if (c == lexical_quote)
        lexical_quote = '\0';
      else if (!lexical_quote && (c == '\'' || c == '"'))
        lexical_quote = c;
    }
    shell_source_heredoc_remove_byte((unsigned char)c, &remove);
  }
}

typedef struct {
  const unsigned char *bytes;
  size_t length;
  bool quoted;
} shell_source_heredoc_delimiter_t;

/* Construct normalized spelling from a complete admitted delimiter word.
 * Pieces and bytes use the current operation's borrowed arena and expire
 * when its caller releases the delimiter-preparation scratch mark. */
bool shell_source_prepare_literal_heredoc(
    const shell_source_pending_heredoc_t *pending,
    shell_source_heredoc_delimiter_t *delimiter) SHELL_NONNULL(1, 2);

/* pending borrows a complete immutable delimiter word admitted by the
 * declaration probe, not an unfinished raw spelling. The operation's scratch
 * remains live through all comparisons using the returned delimiter. */
static inline SHELL_NONNULL(1, 2) bool shell_source_prepare_heredoc(
    const shell_source_pending_heredoc_t *pending,
    shell_source_heredoc_delimiter_t *delimiter) {
  /* A dollar fragment needs lexical grouping and Bash command printing. The
   * common flat spelling retains its allocation-free streaming fast path. */
  for (size_t i = 0; i < pending->word_length; i++)
    if (shell_source_heredoc_fragment_open(pending->word, pending->word_length,
                                           i))
      return shell_source_prepare_literal_heredoc(pending, delimiter);
  shell_source_heredoc_decode_t measure = {NULL, 0};
  shell_source_decode_heredoc(pending, &measure, &delimiter->quoted);
  delimiter->length = measure.length;
  /* Grouped fragments took the printer path above. An unquoted flat word
   * can only lose continuations, so equal length proves byte identity here;
   * it would not prove identity for a printed command fragment. */
  if (!delimiter->quoted && measure.length == pending->word_length) {
    delimiter->bytes = (const unsigned char *)pending->word;
    return true;
  }
  unsigned char *bytes =
      (unsigned char *)shell_source_scratch_take(measure.length);
  if (!bytes)
    return false;
  shell_source_heredoc_decode_t fill = {bytes, 0};
  bool quoted;
  /* The same immutable spelling and emitter fill exactly the measured bytes. */
  shell_source_decode_heredoc(pending, &fill, &quoted);
  delimiter->bytes = bytes;
  return true;
}

/* Match one logical body line against an already prepared delimiter.
 * A final unpaired backslash in an unquoted line may acquire LF on append;
 * it cannot yet be committed as a mismatching content byte. */
static inline SHELL_NONNULL(1, 4, 5, 6) bool shell_source_match_prepared_heredoc(
    const char *input, size_t length, size_t line,
    const shell_source_heredoc_delimiter_t *delimiter, size_t *after,
    bool *prefix, bool strip_tabs) {
  size_t position = line, matched = 0;
  bool mismatch = false, escaped = false, line_start = true;
  *prefix = false;
  while (position < length) {
    SHELL_SOURCE_LINE_SCAN(1);
    unsigned char byte = (unsigned char)input[position];
    if (byte == '\n')
      break;
    if (!delimiter->quoted && !escaped && byte == '\\') {
      if (position + 1 == length) {
        *after = length;
        *prefix = !mismatch;
        return false;
      }
      if (input[position + 1] == '\n') {
        SHELL_SOURCE_LINE_SCAN(1);
        position += 2;
        continue;
      }
    }
    if (strip_tabs && line_start && byte == '\t') {
      position++;
      continue;
    }
    line_start = false;
    escaped = !delimiter->quoted && !escaped && byte == '\\';
    if (matched == delimiter->length || byte != delimiter->bytes[matched])
      mismatch = true;
    else if (!mismatch)
      matched++;
    position++;
  }
  *after = position < length ? position + 1 : position;
  *prefix = !mismatch && matched < delimiter->length && position == length;
  return !mismatch && matched == delimiter->length;
}

/* Single-line projection used by isolated framing tests. Streaming consumers
 * prepare once for the whole document, not once for each candidate line. */
static inline SHELL_NONNULL(1, 4, 5, 6) bool shell_source_match_heredoc_line(
    const char *input, size_t length, size_t line,
    const shell_source_pending_heredoc_t *pending, size_t *after,
    bool *prefix) {
  size_t mark = shell_source_scratch_mark();
  shell_source_heredoc_delimiter_t delimiter;
  *after = length;
  *prefix = false;
  bool result =
      shell_source_prepare_heredoc(pending, &delimiter) &&
      shell_source_match_prepared_heredoc(input, length, line, &delimiter,
                                          after, prefix, pending->strip_tabs);
  shell_source_scratch_release(mark);
  return result;
}
typedef struct {
  size_t body_start, body_end, confirmed_end;
  size_t delimiter_start, delimiter_end, after;
  bool complete, delimiter_prefix;
} shell_source_heredoc_frame_t;

/* Boolean projection for consumers which do not retain draft framing. */
static inline SHELL_NONNULL(1, 4) bool shell_source_line_is_heredoc_delimiter(
    const char *input, size_t length, size_t line,
    const shell_source_pending_heredoc_t *pending) {
  size_t after;
  bool prefix;
  return shell_source_match_heredoc_line(input, length, line, pending, &after,
                                         &prefix);
}

/* One shared framing walk, retaining raw source spans and the received versus
 * confirmed body prefix. No delimiter is synthesized for unfinished input. */
static inline SHELL_NONNULL(1, 4) shell_source_heredoc_frame_t
    shell_source_frame_heredoc(const char *input, size_t length,
                               size_t body_start,
                               const shell_source_pending_heredoc_t *pending) {
  shell_source_heredoc_frame_t frame = {.body_start = body_start,
                                        .body_end = length,
                                        .confirmed_end = length,
                                        .delimiter_start = length,
                                        .delimiter_end = length,
                                        .after = length};
  size_t body_end, delimiter_length;
  if (shell_source_index_get(input, length, body_start,
                             SHELL_SOURCE_INDEX_HEREDOC_BODY, &body_end,
                             &delimiter_length)) {
    frame.body_end = frame.confirmed_end = frame.delimiter_start = body_end;
    frame.delimiter_end = frame.after = body_end + delimiter_length;
    frame.complete = true;
    return frame;
  }
  size_t mark = shell_source_scratch_mark();
  shell_source_heredoc_delimiter_t delimiter;
  if (!shell_source_prepare_heredoc(pending, &delimiter))
    return frame;
  for (size_t line = body_start; line < length;) {
    size_t after;
    bool prefix;
    if (shell_source_match_prepared_heredoc(input, length, line, &delimiter,
                                            &after, &prefix,
                                            pending->strip_tabs)) {
      frame.body_end = frame.confirmed_end = frame.delimiter_start = line;
      frame.delimiter_end = frame.after = after;
      frame.complete = true;
      shell_source_index_put(input, length, body_start,
                             SHELL_SOURCE_INDEX_HEREDOC_BODY, line,
                             after - line);
      break;
    }
    if (prefix) {
      frame.confirmed_end = line;
      frame.delimiter_prefix = true;
    }
    line = after;
  }
  shell_source_scratch_release(mark);
  return frame;
}

/* A quoted delimiter disables expansion of its document body. Derive the
 * lexical flag, not the mere presence of quote-looking text inside literal
 * backticks. The required descriptor borrows a complete immutable delimiter
 * word[0..word_length). */
static SHELL_NONNULL(1) inline bool shell_source_heredoc_delimiter_is_quoted(
    const shell_source_pending_heredoc_t *pending) {
  size_t position = 0;
  bool quoted = false;
  (void)shell_source_next_heredoc_ansi(pending->word, pending->word_length,
                                       &position, &quoted);
  return quoted;
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
    if (c == '\n')
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
    shell_source_heredoc_frame_t frame =
        shell_source_frame_heredoc(input, length, line, &pending[h]);
    if (!frame.complete) {
      *after = length;
      return false;
    }
    if (visitor &&
        !visitor(input, frame.body_start, frame.body_end - frame.body_start,
                 shell_source_heredoc_delimiter_is_quoted(&pending[h]),
                 context))
      return false;
    line = frame.after;
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
  if (position >= length || !shell_ascii_digit((unsigned char)input[position]))
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
        if (next >= length || !shell_ascii_xdigit((unsigned char)input[next]))
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
    if (next >= length || !shell_ascii_digit((unsigned char)input[next]))
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
    if (shell_ascii_digit(byte))
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
  size_t failed_end;
  if (shell_source_index_get(input, length, position,
                             SHELL_SOURCE_INDEX_UNCLOSED_PARENS, &failed_end,
                             &height) &&
      failed_end == length)
    return false;
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
  else
    /* Immutable received EOF is part of this negative fact. Do not reuse it
     * for a different span end (for example a separately qualified prefix).
     * Nested draft consumers reuse the failed forward walk, not its suffix. */
    shell_source_index_put(input, length, position,
                           SHELL_SOURCE_INDEX_UNCLOSED_PARENS, length, height);
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
 * recognized accurately. Quotes and complete parameter, arithmetic, command,
 * and process substitutions own their delimiters; their `[` and `]` bytes
 * cannot affect the enclosing subscript. Unfinished scopes fail this candidate
 * without exposing their interior as outer list syntax. Successful boundaries
 * are reusable within their span; unfinished facts belong to the received EOF.
 * input supplies length immutable bytes; position identifies a known opening
 * `[` in the active workspace's source view, and after is a required writable
 * offset. The span helper below also accepts an empty span as no match. */
static inline SHELL_NONNULL(1, 4) bool shell_source_skip_array_subscript_impl(
    const char *input, size_t length, size_t position, size_t *after) {
  shell_source_array_boundary_t *root =
      shell_source_array_boundary(input + position);
  if (!root)
    return false;
  uintptr_t end = (uintptr_t)(input + length);
  if (root->after) {
    if (root->after > end)
      return false;
    *after = root->after - (uintptr_t)input;
    return true;
  }
  if (root->failed_end == end)
    return false;
  root->parent = NULL;
  shell_source_array_boundary_t *top = root;
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
        goto unfinished;
      position = quoted - 1;
    } else if (c == '\'' || c == '"' || c == '`') {
      size_t quoted = 0;
      if (!shell_source_skip_complete_quoted_text(input, length, position, c,
                                                  &quoted))
        goto unfinished;
      position = quoted - 1;
    } else if (c == '$' && shell_source_logical_next_is(input, length, position,
                                                        '{', NULL)) {
      size_t parameter_after = 0;
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 &parameter_after))
        goto unfinished;
      position = parameter_after - 1;
    } else if (c == '$' && shell_source_dollar_arithmetic_open(
                               input, length, position, NULL)) {
      size_t arithmetic_after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &arithmetic_after))
        goto unfinished;
      position = arithmetic_after - 1;
    } else if (c == '$' || c == '<' || c == '>') {
      size_t substitution_open = 0;
      bool substitution =
          c == '$'
              ? shell_source_dollar_parentheses_open(input, length, position,
                                                     &substitution_open)
              : shell_source_process_substitution_open(input, length, position,
                                                       &substitution_open);
      if (!substitution)
        continue;
      size_t substitution_after = 0;
      if (!shell_source_find_balanced_parentheses(
              input, length, substitution_open, &substitution_after))
        goto unfinished;
      position = substitution_after - 1;
    } else if (c == '[') {
      shell_source_array_boundary_t *child =
          shell_source_array_boundary(input + position);
      if (!child)
        goto unfinished;
      if (child->after) {
        if (child->after > end)
          goto unfinished;
        position = child->after - (uintptr_t)input - 1;
      } else if (child->failed_end == end) {
        goto unfinished;
      } else {
        child->parent = top;
        top = child;
      }
    } else if (c == ']') {
      top->after = (uintptr_t)(input + position + 1);
      top = top->parent;
      if (!top) {
        *after = position + 1;
        return true;
      }
    }
  }
unfinished:
  while (top) {
    top->failed_end = end;
    top = top->parent;
  }
  return false;
}

static inline SHELL_NONNULL(4) bool shell_source_skip_array_subscript(
    const char *input, size_t length, size_t position, size_t *after) {
  if (position >= length || input[position] != '[')
    return false;
  shell_source_operation_begin(input, length);
  bool complete =
      shell_source_skip_array_subscript_impl(input, length, position, after);
  shell_source_operation_end();
  return complete;
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
  if (cursor >= length || !(shell_ascii_alpha((unsigned char)input[cursor]) ||
                            input[cursor] == '_'))
    return false;
  while (cursor < length) {
    cursor = shell_source_skip_escaped_line_endings(input, length, cursor);
    if (cursor >= length || !(shell_ascii_alnum((unsigned char)input[cursor]) ||
                              input[cursor] == '_'))
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

typedef enum {
  SHELL_SOURCE_PARAMETER_COMPLETE,
  SHELL_SOURCE_PARAMETER_INCOMPLETE,
  SHELL_SOURCE_PARAMETER_MALFORMED,
} shell_source_parameter_status_t;

/* At a selector boundary, a final backslash can still acquire a continuation
 * LF. Other invalid bytes cannot be repaired by appending. position <= length;
 * input supplies that immutable span, including at zero length. */
static inline SHELL_NONNULL(1) bool shell_source_parameter_at_eof(
    const char *input, size_t length, size_t position) {
  return position == length ||
         (input[position] == '\\' && position + 1 == length);
}

/* Consume a scalar base on a forward cursor. Required position is in
 * [0,length] and receives the consumed/terminal offset for every status.
 * COMPLETE means one base, not a complete enclosing ${...} expansion. */
static inline SHELL_NONNULL(1, 3) shell_source_parameter_status_t
    shell_source_skip_parameter_base(const char *input, size_t length,
                                     size_t *position) {
  size_t cursor =
      shell_source_skip_escaped_line_endings(input, length, *position);
  *position = cursor;
  if (shell_source_parameter_at_eof(input, length, cursor))
    return SHELL_SOURCE_PARAMETER_INCOMPLETE;
  SHELL_SOURCE_WORD_SCAN(1);
  unsigned char c = (unsigned char)input[cursor];
  if (shell_ascii_alpha(c) || c == '_') {
    cursor++;
    while (cursor < length) {
      cursor = shell_source_skip_escaped_line_endings(input, length, cursor);
      if (cursor >= length)
        break;
      SHELL_SOURCE_WORD_SCAN(1);
      c = (unsigned char)input[cursor];
      if (!(shell_ascii_alnum(c) || c == '_'))
        break;
      cursor++;
    }
  } else if (shell_ascii_digit(c)) {
    do {
      cursor++;
      cursor = shell_source_skip_escaped_line_endings(input, length, cursor);
      if (cursor < length)
        SHELL_SOURCE_WORD_SCAN(1);
    } while (cursor < length &&
             shell_ascii_digit((unsigned char)input[cursor]));
  } else if (shell_source_parameter_is_special(c)) {
    cursor++;
  } else {
    return SHELL_SOURCE_PARAMETER_MALFORMED;
  }

  *position = cursor;
  return cursor < length && shell_source_parameter_at_eof(input, length, cursor)
             ? SHELL_SOURCE_PARAMETER_INCOMPLETE
             : SHELL_SOURCE_PARAMETER_COMPLETE;
}

/* Skip the parameter selector immediately after `${`.  `#` prefixes the
 * length form except where it is the special `$#` selector; `!` prefixes
 * indirection unless it is `${!}`. An array subscript is retained structurally
 * so the full tokenizer can subsequently reject unsupported array semantics
 * without misclassifying the enclosing expansion. */
/* Recognize only the selector's scalar head. The word walker consumes a
 * following subscript in its forward scope stream; it never balances that
 * suffix merely to revisit it. Required source span and outputs are distinct;
 * position <= length. after retains forward progress on every status, rather
 * than making EOF consumers infer it from the original selector start. */
static SHELL_NONNULL(1, 4, 5) inline shell_source_parameter_status_t
    shell_source_skip_parameter_head(const char *input, size_t length,
                                     size_t position, size_t *after,
                                     bool *indirect) {
  *indirect = false;
  position = shell_source_skip_escaped_line_endings(input, length, position);
  *after = position;
  if (shell_source_parameter_at_eof(input, length, position))
    return SHELL_SOURCE_PARAMETER_INCOMPLETE;
  if (input[position] == '#') {
    size_t next = shell_source_logical_following(input, length, position);
    *after = next;
    if (shell_source_parameter_at_eof(input, length, next))
      return SHELL_SOURCE_PARAMETER_INCOMPLETE;
    if (input[next] == '}') {
      *after = next;
      return SHELL_SOURCE_PARAMETER_COMPLETE;
    }
    /* `${##word}` means pattern removal from the special `$#`, not the
     * length of a parameter named `#word`. Leave the first `#` for the base
     * selector so the second one is recognized as its operator. */
    if (input[next] != '#')
      position = next;
  } else if (input[position] == '!') {
    position = shell_source_logical_following(input, length, position);
    *after = position;
    if (shell_source_parameter_at_eof(input, length, position))
      return SHELL_SOURCE_PARAMETER_INCOMPLETE;
    if (input[position] == '}') {
      *after = position;
      return SHELL_SOURCE_PARAMETER_COMPLETE;
    }
    *indirect = true;
  }

  shell_source_parameter_status_t status =
      shell_source_skip_parameter_base(input, length, &position);
  *after = position;
  return status;
}

/* input supplies length immutable bytes (NULL only for length zero),
 * position <= length, and after is required distinct writable storage.
 * No match leaves after unchanged. */
static inline SHELL_NONNULL(4) bool shell_source_skip_parameter_selector(
    const char *input, size_t length, size_t position, size_t *after) {
  if (position >= length)
    return false;
  bool indirect;
  if (shell_source_skip_parameter_head(input, length, position, &position,
                                       &indirect) !=
      SHELL_SOURCE_PARAMETER_COMPLETE)
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
  if (shell_ascii_digit((unsigned char)character) || character == '#' ||
      character == '?' || character == '$' || character == '!' ||
      character == '@' || character == '*' || character == '-') {
    *after = next + 1;
    return true;
  }
  if (!(shell_ascii_alpha((unsigned char)character) || character == '_'))
    return false;

  position = next + 1;
  while (position < length) {
    size_t continued =
        shell_source_skip_escaped_line_endings(input, length, position);
    if (continued != position) {
      position = continued;
      continue;
    }
    if (!(shell_ascii_alnum((unsigned char)input[position]) ||
          input[position] == '_'))
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
  if (!literal && (shell_source_space(byte) || strchr("|&;<>()", byte))) {
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
    if (shell_source_space((unsigned char)c) || strchr("|&;<>()", c))
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
  SHELL_SOURCE_SCAN_INCOMPLETE,
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
  /* Byte admission is independent of quoting: heredoc literal text and its
   * parameter words remain data, even where pattern quoting changes. Math,
   * substring offsets and array subscripts establish code domains. */
  bool data_domain;
  /* Ordinary word roots permit literal quote data. Parameter operands inherit
   * that permission; math, substring arithmetic and subscripts clear it so
   * quoting cannot hide their code from byte admission. */
  bool quoted_data;
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
  /* One-based operand offsets identify conditional execution without a
   * source-prefix rescan. Nonconditional nested scopes inherit this pair. */
  size_t guard_start, guard_parent;
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

typedef struct {
  size_t position;
  shell_source_expansion_scope_t scope;
  unsigned scope_count;
  bool exhausted; /* Bounded expansion-scope storage, not malformed syntax. */
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
  /* Optional boundary observer. NULL disables it. Regions are nonempty,
   * ordered, disjoint code spans, excluding executable child bodies (which
   * the boundary visits separately). Completion events never repeat a span.
   * context is borrowed for the iteration and interpreted only by visitor. */
  void (*code_visitor)(const char *source, size_t start, size_t end,
                       void *context);
  void *code_context;
  size_t code_start;
  /* Valid only at INCOMPLETE: body_start != 0 identifies an unfinished
   * executable child and its entire received body, without a closing byte.
   * Arithmetic/quote-only EOF has body_start == 0. No rescan is required to
   * distinguish backticks, command substitutions and process substitutions. */
  struct {
    shell_source_substitution_kind_t kind;
    size_t body_start, body_length;
  } unfinished;
} shell_source_substitution_scan_t;

static inline SHELL_NONNULL(2) void shell_source_report_word_code(
    const char *input, shell_source_substitution_scan_t *scan, size_t end) {
  const shell_source_expansion_scope_t *scope = &scan->scope;
  bool quoted = scope->quoted_data && !scope->selector_pending &&
                !scope->ansi_end &&
                (scope->in_single_quote || scope->in_double_quote ||
                 scope->inherited_double_quote);
  if (scan->code_visitor && !scope->data_domain && !quoted &&
      scan->code_start < end)
    scan->code_visitor(input, scan->code_start, end, scan->code_context);
  scan->code_start = end;
}

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
  scan->has_positional |=
      shell_ascii_digit((unsigned char)input[selector]) != 0;
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
 * MALFORMED reports invalid source syntax or nesting-limit failure;
 * INCOMPLETE reports an unfinished expansion at received EOF. Both reject
 * strict consumers; draft consumers distinguish them. Neither reports invalid
 * pointer arguments. Consume
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
    shell_source_next_word_expansion_body(
        const char *input, size_t length,
        shell_source_substitution_scan_t *scan, size_t *start, size_t *after,
        shell_source_substitution_kind_t *kind) {
  while (scan->position < length) {
    SHELL_SOURCE_WORD_SCAN(1);
    shell_source_expansion_scope_t *scope = &scan->scope;
    size_t position = scan->position;
    if (scope->selector_pending) {
      position =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (shell_source_parameter_at_eof(input, length, position))
        return SHELL_SOURCE_SCAN_INCOMPLETE;
      if (!scope->selector_subscript && input[position] == '[') {
        if (scan->scope_count == SHELL_MAX_SUBCOMMANDS) {
          scan->exhausted = true;
          return SHELL_SOURCE_SCAN_MALFORMED;
        }
        scope->selector_subscript = true;
        scan->has_arrays = true;
        shell_source_report_word_code(input, scan, position + 1);
        scan->scopes[scan->scope_count++] = *scope;
        *scope = (shell_source_expansion_scope_t){
            .suppress_process = true,
            .closer = ']',
            .parentheses = 1,
            .conditional = scope->conditional,
            .guard_start = scope->guard_start,
            .guard_parent = scope->guard_parent};
        scan->position = position + 1;
        continue;
      }
      bool name_enumeration = false;
      if (scope->selector_indirect && !scope->selector_subscript &&
          (input[position] == '*' || input[position] == '@')) {
        size_t next = shell_source_logical_following(input, length, position);
        if (shell_source_parameter_at_eof(input, length, next))
          return SHELL_SOURCE_SCAN_INCOMPLETE;
        name_enumeration = input[next] == '}';
        if (name_enumeration)
          position = next;
      }
      position =
          shell_source_skip_escaped_line_endings(input, length, position);
      if (position == length)
        return SHELL_SOURCE_SCAN_INCOMPLETE;
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
      bool conditional =
          has_word &&
          (operand == SHELL_SOURCE_PARAMETER_PATTERN ||
           input[operator_position] == '-' || input[operator_position] == '+' ||
           input[operator_position] == '=' || input[operator_position] == '?');
      if (conditional) {
        scope->guard_parent = scope->guard_start;
        scope->guard_start = word_start + 1;
      }
      scope->conditional |= conditional;
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
      shell_source_report_word_code(input, scan, word_start);
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
        scope->data_domain = false;
        scope->quoted_data = false;
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
      shell_source_report_word_code(input, scan, scan->position);
      scope->ansi_end = 0;
      continue;
    }
    char c = input[position];
    bool heredoc_root = scope->heredoc && scope->closer == 0;
    if (heredoc_root && c == '\\' && position + 1 < length) {
      char next = input[position + 1];
      scan->position +=
          (next == '$' || next == '`' || next == '\\' || next == '\n') ? 2 : 1;
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
        return SHELL_SOURCE_SCAN_INCOMPLETE;
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
        return SHELL_SOURCE_SCAN_INCOMPLETE;
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
      shell_source_report_word_code(input, scan, position);
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
      shell_source_report_word_code(input, scan, position);
      scope->in_single_quote = !scope->in_single_quote;
      scan->position++;
      continue;
    }
    if (!heredoc_root && c == '"' && !scope->ansi_end &&
        !scope->in_single_quote) {
      shell_source_report_word_code(input, scan, position);
      scope->in_double_quote = !scope->in_double_quote;
      scan->position++;
      continue;
    }
    if (scope->in_single_quote) {
      scan->position++;
      continue;
    }
    /* Legacy arithmetic has its own bracket grammar. Do not let its spaces
     * and parentheses become outer list syntax or manufacture a syntax-error
     * judgment. Semantic consumers already decline unsupported arithmetic. */
    if (c == '$' &&
        shell_source_logical_next_is(input, length, position, '[', NULL))
      return SHELL_SOURCE_SCAN_MALFORMED;
    if (scope->arithmetic_scope && c == '[')
      scan->has_arrays = true;
    if (!scope->heredoc && c == '$' && !scope->in_double_quote &&
        scope->delimiter_quote != '\'' &&
        shell_source_logical_next_is(input, length, position, '"', NULL))
      scan->has_locale_quote = true;
    if (c == '`') {
      size_t substitution_after = 0;
      bool escape_sensitive = false;
      bool complete = shell_source_scan_backtick(
          input, length, position,
          scope->in_double_quote || scope->inherited_double_quote,
          &substitution_after, &escape_sensitive);
      scan->has_backtick_escapes |= escape_sensitive;
      shell_source_report_word_code(input, scan, position);
      if (!complete) {
        scan->unfinished.kind = SHELL_SOURCE_SUBST_BACKTICK;
        scan->unfinished.body_start = position + 1;
        scan->unfinished.body_length = length - position - 1;
        scan->code_start = length;
        return SHELL_SOURCE_SCAN_INCOMPLETE;
      }
      scan->code_start = substitution_after;
      *start = position;
      *after = substitution_after;
      *kind = SHELL_SOURCE_SUBST_BACKTICK;
      scan->position = substitution_after;
      return SHELL_SOURCE_SCAN_FOUND;
    }
    if (c == '$' &&
        shell_source_logical_next_is(input, length, position, '{', NULL)) {
      shell_source_report_word_code(input, scan, position);
      size_t brace = shell_source_logical_following(input, length, position);
      size_t selector =
          shell_source_skip_escaped_line_endings(input, length, brace + 1);
      size_t head_after = 0;
      bool indirect;
      shell_source_parameter_status_t head = shell_source_skip_parameter_head(
          input, length, selector, &head_after, &indirect);
      if (head != SHELL_SOURCE_PARAMETER_COMPLETE) {
        scan->position = head_after;
        return head == SHELL_SOURCE_PARAMETER_INCOMPLETE
                   ? SHELL_SOURCE_SCAN_INCOMPLETE
                   : SHELL_SOURCE_SCAN_MALFORMED;
      }
      if (scan->scope_count >= SHELL_MAX_SUBCOMMANDS) {
        scan->exhausted = true;
        return SHELL_SOURCE_SCAN_MALFORMED;
      }
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
      if (scan->scope_count >= SHELL_MAX_SUBCOMMANDS) {
        scan->exhausted = true;
        return SHELL_SOURCE_SCAN_MALFORMED;
      }
      scan->has_arithmetic = true;
      scan->has_expansion_abort = true;
      scan->arithmetic_depth++;
      shell_source_report_word_code(input, scan, open + 1);
      scan->scopes[scan->scope_count++] = *scope;
      scan->position = open + 1;
      *scope =
          (shell_source_expansion_scope_t){.suppress_process = true,
                                           .conditional = scope->conditional,
                                           .guard_start = scope->guard_start,
                                           .guard_parent = scope->guard_parent,
                                           .arithmetic_scope = true,
                                           .closer = ')',
                                           .expansion_start = position,
                                           .parentheses = 1};
      continue;
    }
    if (c == '$' &&
        shell_source_dollar_parentheses_open(input, length, position, &open)) {
      size_t substitution_after = 0;
      shell_source_report_word_code(input, scan, position);
      if (!shell_source_find_balanced_parentheses(input, length, open,
                                                  &substitution_after)) {
        scan->unfinished.kind = SHELL_SOURCE_SUBST_COMMAND;
        scan->unfinished.body_start = open + 1;
        scan->unfinished.body_length = length - open - 1;
        scan->code_start = length;
        return SHELL_SOURCE_SCAN_INCOMPLETE;
      }
      scan->code_start = substitution_after;
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
      shell_source_report_word_code(input, scan, position);
      if (!shell_source_find_balanced_parentheses(input, length, open,
                                                  &substitution_after)) {
        scan->unfinished.kind = c == '<' ? SHELL_SOURCE_SUBST_PROCESS_INPUT
                                         : SHELL_SOURCE_SUBST_PROCESS_OUTPUT;
        scan->unfinished.body_start = open + 1;
        scan->unfinished.body_length = length - open - 1;
        scan->code_start = length;
        return SHELL_SOURCE_SCAN_INCOMPLETE;
      }
      scan->code_start = substitution_after;
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
        shell_source_report_word_code(input, scan, scan->position);
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
            if (close >= length)
              return SHELL_SOURCE_SCAN_INCOMPLETE;
            if (input[close] != ')')
              return SHELL_SOURCE_SCAN_MALFORMED;
            size_t arithmetic_start = scope->expansion_start;
            scan->position = close + 1;
            shell_source_report_word_code(input, scan, scan->position);
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
          shell_source_report_word_code(input, scan, scan->position);
          *scope = scan->scopes[--scan->scope_count];
          continue;
        }
      }
      if (scope->arithmetic_scope && !scope->in_single_quote &&
          !scope->in_double_quote) {
        if (shell_ascii_digit((unsigned char)c)) {
          size_t number_after;
          if (shell_source_skip_arithmetic_number(input, length, position,
                                                  &number_after)) {
            scan->position = number_after;
            continue;
          }
        }
        if (shell_ascii_alpha((unsigned char)c) || c == '_')
          scan->has_arithmetic_variables = true;
      }
    }
    scan->position++;
  }
  return scan->scope_count ? SHELL_SOURCE_SCAN_INCOMPLETE
                           : SHELL_SOURCE_SCAN_DONE;
}

/* The observer also sees received code at unfinished arithmetic/quote EOF.
 * An unfinished executable child is opaque to the parent just like a closed
 * child. Its descriptor supplies the boundary's separate recursive domain.
 * Initialize scope.data_domain for a literal heredoc root, independently of
 * scope.heredoc's quote rules. Observer-free semantic consumers use the same
 * expansion events and need no byte-domain traversal of their own. */
static inline SHELL_NONNULL(3, 4, 5, 6) shell_source_scan_status_t
    shell_source_next_word_expansion(const char *input, size_t length,
                                     shell_source_substitution_scan_t *scan,
                                     size_t *start, size_t *after,
                                     shell_source_substitution_kind_t *kind) {
  shell_source_scan_status_t status = shell_source_next_word_expansion_body(
      input, length, scan, start, after, kind);
  size_t end = status == SHELL_SOURCE_SCAN_INCOMPLETE ? length : scan->position;
  shell_source_report_word_code(input, scan, end);
  return status;
}

/* Compatibility adapter for consumers that need only executable command or
 * process substitutions. The same stream still gathers semantic features and
 * validates expansion scope boundaries through DONE. */
static inline SHELL_NONNULL(3, 4, 5, 6) shell_source_scan_status_t
    shell_source_next_executable_substitution(
        const char *input, size_t length,
        shell_source_substitution_scan_t *scan, size_t *start, size_t *after,
        shell_source_substitution_kind_t *kind) {
  for (;;) {
    shell_source_scan_status_t status = shell_source_next_word_expansion(
        input, length, scan, start, after, kind);
    if (status != SHELL_SOURCE_SCAN_FOUND)
      return status;
    if (*kind != SHELL_SOURCE_EXPANSION_ARITHMETIC &&
        *kind != SHELL_SOURCE_EXPANSION_SUBSTRING)
      return SHELL_SOURCE_SCAN_FOUND;
  }
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

/* Recognize a compound-array opener, including a received unfinished body.
 * This shape does not establish lexical assignment eligibility: unlike
 * a[0]=word, a=(one two) cannot be an ordinary command or redirect argument. */
static inline SHELL_NONNULL(1) bool shell_source_array_assignment_is_compound(
    const char *input, size_t length) {
  if (length < 3 ||
      !(shell_ascii_alpha((unsigned char)input[0]) || input[0] == '_'))
    return false;
  size_t position = shell_source_logical_following(input, length, 0);
  while (position < length &&
         (shell_ascii_alnum((unsigned char)input[position]) ||
          input[position] == '_'))
    position = shell_source_logical_following(input, length, position);
  if (position < length && input[position] == '[') {
    if (!shell_source_skip_array_subscript(input, length, position, &position))
      return false;
    position = shell_source_skip_escaped_line_endings(input, length, position);
  }
  if (position < length && input[position] == '+')
    position = shell_source_logical_following(input, length, position);
  if (position == length || input[position] != '=')
    return false;
  position = shell_source_logical_following(input, length, position);
  return position < length && input[position] == '(';
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
    if ((stop_groups && (c == '(' || c == ')')) ||
        shell_source_space((unsigned char)c) || c == '|' || c == ';' ||
        c == '&' || c == '<' || c == '>' || c == '\n')
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
  if (shell_source_space(previous)) {
    size_t before = target - 1;
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
        (shell_source_space((unsigned char)input[brace_next]) ||
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
    if (shell_source_space((unsigned char)c) || strchr(";|&()", c) ||
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

typedef enum {
  SHELL_SOURCE_FD_PREFIX_NONE,
  SHELL_SOURCE_FD_PREFIX_CLOSED,
  SHELL_SOURCE_FD_PREFIX_PENDING,
  SHELL_SOURCE_FD_PREFIX_ESCAPE,
} shell_source_fd_prefix_t;

/* One forward recognition of Bash's {name} redirector. A known word start
 * and start <= end are required. CLOSED supplies the offset after '}',
 * PENDING reaches received EOF in an appendable name, and ESCAPE locates
 * its final backslash which can still acquire LF. NONE is not a name prefix.
 * Continuations are removed without copying; quotes/ordinary escapes are
 * not identifier bytes. Complete consumers accept CLOSED only. */
static SHELL_NONNULL(1, 4) inline shell_source_fd_prefix_t
    shell_source_probe_named_fd_at_word_start(const char *input, size_t start,
                                              size_t end, size_t *after) {
  *after = start;
  if (start == end || input[start] != '{')
    return SHELL_SOURCE_FD_PREFIX_NONE;

  size_t position = start + 1;
  bool first = true;
  for (;;) {
    size_t next = shell_source_skip_escaped_line_endings(input, end, position);
    SHELL_SOURCE_WORD_SCAN(next - position);
    position = next;
    if (position == end) {
      *after = end;
      return SHELL_SOURCE_FD_PREFIX_PENDING;
    }
    SHELL_SOURCE_WORD_SCAN(1);
    unsigned char c = (unsigned char)input[position];
    if (c == '\\' && position + 1 == end) {
      *after = position;
      return SHELL_SOURCE_FD_PREFIX_ESCAPE;
    }
    if (c == '}') {
      if (first)
        return SHELL_SOURCE_FD_PREFIX_NONE;
      *after = position + 1;
      return SHELL_SOURCE_FD_PREFIX_CLOSED;
    }
    if (first ? !(shell_ascii_alpha(c) || c == '_')
              : !(shell_ascii_alnum(c) || c == '_'))
      return SHELL_SOURCE_FD_PREFIX_NONE;
    first = false;
    position++;
  }
}

/* Complete {name} recognition, with the original no-match offset contract.
 * Known word start, start <= end, and distinct required output storage. */
static SHELL_NONNULL(
    1,
    4) inline bool shell_source_parse_named_fd_at_word_start(const char *input,
                                                             size_t start,
                                                             size_t end,
                                                             size_t *after) {
  size_t parsed;
  bool complete =
      shell_source_probe_named_fd_at_word_start(input, start, end, &parsed) ==
      SHELL_SOURCE_FD_PREFIX_CLOSED;
  *after = complete ? parsed : start;
  return complete;
}

/* Received-tail projection at a nonempty known word start. Only PENDING or
 * ESCAPE can be returned besides NONE; diagnostic receives the redirector's
 * start or its final backslash respectively. Numeric bounds and identifier
 * spelling are the same as complete redirect recognition. This is local
 * lexical work, not a rescan of preceding source or a new public parse mode.
 */
static SHELL_NONNULL(1, 4) inline shell_source_fd_prefix_t
    shell_source_pending_fd_prefix(const char *input, size_t start, size_t end,
                                   size_t *diagnostic) {
  size_t after;
  if (input[start] == '{') {
    shell_source_fd_prefix_t status =
        shell_source_probe_named_fd_at_word_start(input, start, end, &after);
    if (status == SHELL_SOURCE_FD_PREFIX_NONE)
      return status;
    if (status != SHELL_SOURCE_FD_PREFIX_CLOSED) {
      *diagnostic = status == SHELL_SOURCE_FD_PREFIX_ESCAPE ? after : start;
      return status;
    }
  } else {
    if (!shell_ascii_digit((unsigned char)input[start]))
      return SHELL_SOURCE_FD_PREFIX_NONE;
    uint32_t descriptor;
    shell_source_io_number_t number =
        shell_source_parse_io_number(input, start, end, &after, &descriptor);
    SHELL_SOURCE_WORD_SCAN(after - start);
    if (number != SHELL_SOURCE_IO_NUMBER_VALID)
      return SHELL_SOURCE_FD_PREFIX_NONE;
  }
  size_t next = shell_source_skip_escaped_line_endings(input, end, after);
  SHELL_SOURCE_WORD_SCAN(next - after);
  after = next;
  if (after == end) {
    *diagnostic = start;
    return SHELL_SOURCE_FD_PREFIX_PENDING;
  }
  if (after + 1 == end && input[after] == '\\') {
    *diagnostic = after;
    return SHELL_SOURCE_FD_PREFIX_ESCAPE;
  }
  return SHELL_SOURCE_FD_PREFIX_NONE;
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

/* A move suffix is the last source dash outside a completed quoted fragment.
 * The caller supplies one complete shell word; escaped dashes count too,
 * whereas a dash inside a final quoted fragment does not. Strip only lexical
 * continuations and the suffix escape, retaining the exact operand prefix. */
static inline SHELL_NONNULL(1, 3) bool shell_source_fd_move_prefix(
    const char *input, size_t length, size_t *prefix_length) {
  while (length >= 2 && input[length - 1] == '\n') {
    size_t slash = length - 2;
    if (input[slash] != '\\')
      break;
    size_t escapes = 0;
    for (size_t i = slash + 1; i != 0 && input[i - 1] == '\\'; i--)
      escapes++;
    if ((escapes & 1u) == 0)
      break;
    length = slash;
  }
  if (length < 2 || input[length - 1] != '-')
    return false;
  size_t prefix = length - 1, escapes = 0;
  for (size_t i = prefix; i != 0 && input[i - 1] == '\\'; i--)
    escapes++;
  if (escapes & 1u)
    prefix--;
  if (prefix == 0)
    return false;
  *prefix_length = prefix;
  return true;
}

/* Parse an exact $name or ${name}, optionally double quoted, for a tracked
 * named-FD operand. Escaped physical line endings are removed logically;
 * returned name offsets still borrow the original source spelling. General
 * parameter evaluation and concatenated words are outside this helper. */
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
    if (first ? !(shell_ascii_alpha(c) || c == '_')
              : !(shell_ascii_alnum(c) || c == '_'))
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
    if (shell_source_space((unsigned char)c) || c == '|' || c == ';' ||
        c == '&' || c == '<' || c == '>' || c == '(' || c == ')')
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
  shell_source_brace_ansi_context_t *ansi =
      (shell_source_brace_ansi_context_t *)context;
  ansi->fragment->has_nul = ansi->fragment->has_nul || byte == 0;
  shell_source_glob_scan_step(ansi->glob, byte, true);
  return true;
}

static SHELL_NONNULL(2) inline bool shell_source_glob_ansi_byte(
    unsigned char byte, void *context) {
  shell_source_glob_scan_step((shell_source_glob_scan_t *)context, byte, true);
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
  bool positional = shell_ascii_digit((unsigned char)input[start]) != 0;
  if (!positional &&
      !(shell_ascii_alpha((unsigned char)input[start]) || input[start] == '_'))
    return false;
  for (size_t position = start; position < end; position++) {
    unsigned char byte = (unsigned char)input[position];
    if (positional ? !shell_ascii_digit(byte)
                   : !(shell_ascii_alnum(byte) || byte == '_'))
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
        prefix = shell_ascii_alpha((unsigned char)c) || c == '_' ? PREFIX_NAME
                                                                 : PREFIX_NONE;
      else if (prefix == PREFIX_NAME) {
        if (c == '=') {
          prefix = PREFIX_VALUE;
          value_start = true;
        } else if (c == '+')
          prefix = PREFIX_PLUS;
        else if (!shell_ascii_alnum((unsigned char)c) && c != '_')
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
      if ((c == '<' || c == '>') && shell_source_process_substitution_open(
                                        input, length, position, NULL)) {
        size_t after;
        if (!shell_source_empty_process_fragment(input, length, position,
                                                 &after))
          return (shell_source_word_expansion_t){.dynamic = true};
        position = after;
        tilde_start = tilde_prefix = false;
        if (prefix != PREFIX_VALUE)
          prefix = PREFIX_NONE;
        continue;
      }
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

/* Visit a complete word's literal projection without allocating: remove quotes,
 * decode ANSI-C fragments, and erase empty process fragments. Dynamic spelling
 * is not evaluated; callers requiring a static value use the wrapper below.
 * Shared projection keeps semantic option-prefix recognition and graph static
 * command/wrapper recognition aligned without confusing spelling with a value.
 * word is a required readable span (including length zero); visitor is
 * required. context is passed through and may be NULL if the visitor allows
 * it. The visitor must not modify the word. */
static inline SHELL_NONNULL(1, 3) bool shell_source_visit_decoded_word(
    const char *word, size_t word_length, shell_source_byte_visitor_t visitor,
    void *context) {
  if (word_length == 0)
    return false;

  char quote = '\0';
  for (size_t position = 0; position < word_length; position++) {
    char c = word[position];
    size_t after;
    if (!quote && (c == '<' || c == '>') &&
        shell_source_empty_process_fragment(word, word_length, position,
                                            &after)) {
      position = after - 1;
      continue;
    }
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
          next == '\\' || next == '\n') {
        if (next != '\n' && !visitor((unsigned char)next, context))
          return false;
        position++;
        continue;
      }
    }
    if (!visitor((unsigned char)c, context))
      return false;
  }
  return quote == '\0';
}

/* A decoded spelling is not a runtime value. Static consumers first exclude
 * dynamic syntax; option-prefix recognizers may instead inspect the literal
 * projection while retaining their separate unresolved-value state. */
static inline SHELL_NONNULL(1, 3) bool shell_source_visit_static_word_in_context(
    const char *word, size_t word_length, shell_source_byte_visitor_t visitor,
    void *context, shell_source_word_context_t word_context) {
  return !shell_source_word_has_dynamic_syntax_in_context(word, word_length,
                                                          word_context) &&
         shell_source_visit_decoded_word(word, word_length, visitor, context);
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

/* Declaration builtins recognize assignment operands after quote removal and
 * empty process-fragment elision, unlike lexical command-prefix assignments.
 * Inspect only the name: expansion in the value does not make a literal write
 * target dynamic. `source_delimiter` is false when ANSI-C decoding produced the
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
  shell_source_assignment_scan_t *scan =
      (shell_source_assignment_scan_t *)context;
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
  if (scan->pending_plus || (scan->result.name_length == 0
                                 ? !(shell_ascii_alpha(byte) || byte == '_')
                                 : !(shell_ascii_alnum(byte) || byte == '_')))
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
    SHELL_SOURCE_WORD_SCAN(1);
    char c = word[position];
    size_t empty_after;
    if (!quote && (c == '<' || c == '>') &&
        shell_source_empty_process_fragment(word, word_length, position,
                                            &empty_after)) {
      SHELL_SOURCE_WORD_SCAN(empty_after - position - 1);
      position = empty_after - 1;
      continue;
    }
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
          next == '\\' || next == '\n') {
        position++;
        if (next == '\n')
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
  shell_source_static_word_match_t *match =
      (shell_source_static_word_match_t *)context;
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

typedef struct {
  const char *name;
  size_t length;
  shell_source_builtin_kind_t kind;
} shell_source_builtin_entry_t;

/* One catalog for default Bash dispatch and semantic identity. NONE entries
 * are still builtins; their arguments retain the previous ordinary-word
 * classification. Runtime builtin loading/disabling is unsupported syntax. */
#define SHELL_BUILTIN_ENTRY(name, kind) {name, sizeof(name) - 1, kind}
static const shell_source_builtin_entry_t shell_source_builtins[] = {
    SHELL_BUILTIN_ENTRY("alias", SHELL_SOURCE_BUILTIN_ALIAS),
    SHELL_BUILTIN_ENTRY("bind", SHELL_SOURCE_BUILTIN_BIND),
    SHELL_BUILTIN_ENTRY("[", SHELL_SOURCE_BUILTIN_BRACKET),
    SHELL_BUILTIN_ENTRY("compgen", SHELL_SOURCE_BUILTIN_COMPGEN),
    SHELL_BUILTIN_ENTRY("complete", SHELL_SOURCE_BUILTIN_COMPLETE),
    SHELL_BUILTIN_ENTRY("compopt", SHELL_SOURCE_BUILTIN_COMPOPT),
    SHELL_BUILTIN_ENTRY("declare", SHELL_SOURCE_BUILTIN_DECLARE),
    SHELL_BUILTIN_ENTRY(".", SHELL_SOURCE_BUILTIN_DOT),
    SHELL_BUILTIN_ENTRY("enable", SHELL_SOURCE_BUILTIN_ENABLE),
    SHELL_BUILTIN_ENTRY("eval", SHELL_SOURCE_BUILTIN_EVAL),
    SHELL_BUILTIN_ENTRY("exec", SHELL_SOURCE_BUILTIN_EXEC),
    SHELL_BUILTIN_ENTRY("export", SHELL_SOURCE_BUILTIN_EXPORT),
    SHELL_BUILTIN_ENTRY("fc", SHELL_SOURCE_BUILTIN_FC),
    SHELL_BUILTIN_ENTRY("getopts", SHELL_SOURCE_BUILTIN_GETOPTS),
    SHELL_BUILTIN_ENTRY("let", SHELL_SOURCE_BUILTIN_LET),
    SHELL_BUILTIN_ENTRY("local", SHELL_SOURCE_BUILTIN_LOCAL),
    SHELL_BUILTIN_ENTRY("mapfile", SHELL_SOURCE_BUILTIN_MAPFILE),
    SHELL_BUILTIN_ENTRY("printf", SHELL_SOURCE_BUILTIN_PRINTF),
    SHELL_BUILTIN_ENTRY("popd", SHELL_SOURCE_BUILTIN_POPD),
    SHELL_BUILTIN_ENTRY("pushd", SHELL_SOURCE_BUILTIN_PUSHD),
    SHELL_BUILTIN_ENTRY("read", SHELL_SOURCE_BUILTIN_READ),
    SHELL_BUILTIN_ENTRY("readarray", SHELL_SOURCE_BUILTIN_READARRAY),
    SHELL_BUILTIN_ENTRY("readonly", SHELL_SOURCE_BUILTIN_READONLY),
    SHELL_BUILTIN_ENTRY("set", SHELL_SOURCE_BUILTIN_SET),
    SHELL_BUILTIN_ENTRY("shopt", SHELL_SOURCE_BUILTIN_SHOPT),
    SHELL_BUILTIN_ENTRY("source", SHELL_SOURCE_BUILTIN_SOURCE),
    SHELL_BUILTIN_ENTRY("trap", SHELL_SOURCE_BUILTIN_TRAP),
    SHELL_BUILTIN_ENTRY("test", SHELL_SOURCE_BUILTIN_TEST),
    SHELL_BUILTIN_ENTRY("typeset", SHELL_SOURCE_BUILTIN_TYPESET),
    SHELL_BUILTIN_ENTRY("unalias", SHELL_SOURCE_BUILTIN_UNALIAS),
    SHELL_BUILTIN_ENTRY("unset", SHELL_SOURCE_BUILTIN_UNSET),
    SHELL_BUILTIN_ENTRY("wait", SHELL_SOURCE_BUILTIN_WAIT),
    SHELL_BUILTIN_ENTRY(":", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("bg", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("break", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("builtin", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("caller", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("cd", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("command", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("continue", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("dirs", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("disown", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("echo", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("exit", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("false", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("fg", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("hash", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("help", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("history", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("jobs", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("kill", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("logout", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("pwd", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("return", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("shift", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("suspend", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("times", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("true", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("type", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("ulimit", SHELL_SOURCE_BUILTIN_NONE),
    SHELL_BUILTIN_ENTRY("umask", SHELL_SOURCE_BUILTIN_NONE),
};
#undef SHELL_BUILTIN_ENTRY
enum {
  SHELL_SOURCE_BUILTIN_COUNT =
      sizeof(shell_source_builtins) / sizeof(shell_source_builtins[0])
};
#ifdef __cplusplus
static_assert(SHELL_SOURCE_BUILTIN_COUNT <= 64, "builtin bitmap capacity");
#else
_Static_assert(SHELL_SOURCE_BUILTIN_COUNT <= 64, "builtin bitmap capacity");
#endif

typedef struct {
  uint64_t matches;
  size_t position;
} shell_source_builtin_scan_t;

static inline SHELL_NONNULL(2) bool shell_source_builtin_byte(
    unsigned char byte, void *context) {
  shell_source_builtin_scan_t *scan = (shell_source_builtin_scan_t *)context;
  for (size_t i = 0; i < SHELL_SOURCE_BUILTIN_COUNT; i++)
    if ((scan->matches & (UINT64_C(1) << i)) &&
        (scan->position >= shell_source_builtins[i].length ||
         byte != (unsigned char)shell_source_builtins[i].name[scan->position]))
      scan->matches &= ~(UINT64_C(1) << i);
  scan->position++;
  return true;
}

/* Required immutable word. NULL result means nonstatic or non-builtin.
 * Decode once against the bounded catalog, rather than walking the source
 * separately for every candidate spelling. */
static inline SHELL_NONNULL(1) const
    shell_source_builtin_entry_t *shell_source_builtin_lookup(const char *word,
                                                              size_t length) {
  shell_source_builtin_scan_t scan = {
      UINT64_MAX >> (64 - SHELL_SOURCE_BUILTIN_COUNT), 0};
  if (!shell_source_visit_static_word(word, length, shell_source_builtin_byte,
                                      &scan))
    return NULL;
  for (size_t i = 0; i < SHELL_SOURCE_BUILTIN_COUNT; i++)
    if ((scan.matches & (UINT64_C(1) << i)) &&
        scan.position == shell_source_builtins[i].length)
      return &shell_source_builtins[i];
  return NULL;
}

static inline SHELL_NONNULL(1) shell_source_builtin_kind_t
    shell_source_static_builtin_kind(const char *word, size_t word_length) {
  const shell_source_builtin_entry_t *entry =
      shell_source_builtin_lookup(word, word_length);
  return entry ? entry->kind : SHELL_SOURCE_BUILTIN_NONE;
}

static inline SHELL_NONNULL(1) bool shell_source_word_is_builtin(
    const char *word, size_t word_length) {
  return shell_source_builtin_lookup(word, word_length) != NULL;
}

typedef struct {
  size_t position;
  bool starts_dash;
} shell_source_static_dash_t;

/* Required live dash accumulator; context is not optional here. */
static inline SHELL_NONNULL(2) bool shell_source_static_dash_byte(
    unsigned char byte, void *context) {
  shell_source_static_dash_t *dash = (shell_source_static_dash_t *)context;
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
  shell_source_command_option_scan_t *scan =
      (shell_source_command_option_scan_t *)context;
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

/* At a preframed duplication-operand start, recognize Bash's raw close token.
 * Inline trivia/continuations have already been skipped. Quotes and escapes
 * are word spelling, whereas the immediate '-' consumes just one byte even
 * when another word follows without whitespace. position <= end. */
static inline SHELL_NONNULL(1) size_t
    shell_source_redirect_close_end(const char *input, size_t position,
                                    size_t end) {
  return position < end && input[position] == '-' ? position + 1 : position;
}

/* Recognize one complete longest-match redirect operator. position is its
 * first < or >, or the & of an established &> spelling, not an io-number/name
 * prefix. Input is readable through length, with position < length. Removed
 * physical continuations can join punctuation; unrelated operators never join
 * it. Duplication targets and heredoc delimiters have their own lexical
 * scanners.
 */
static SHELL_NONNULL(1, 4, 5) inline shell_token_type_t
    shell_source_redirect_operator(const char *input, size_t length,
                                   size_t position, size_t *after,
                                   bool *duplicate) {
  char first = input[position];
  size_t second = shell_source_logical_following(input, length, position);
  char next = second < length ? input[second] : '\0';
  *after = position + 1;
  *duplicate = false;
  if (first == '&') {
    *after = second + 1; /* Caller established &>. */
    size_t third = shell_source_logical_following(input, length, second);
    if (third < length && input[third] == '>') {
      *after = third + 1;
      return SHELL_TOKEN_REDIRECT_BOTH_APPEND;
    }
    return SHELL_TOKEN_REDIRECT_BOTH;
  }
  if (next == '&') {
    *after = second + 1;
    *duplicate = true;
    return first == '<' ? SHELL_TOKEN_REDIRECT_IN : SHELL_TOKEN_REDIRECT_ERR;
  }
  if (first == '>') {
    if (next == '>' || next == '|') {
      *after = second + 1;
      return next == '>' ? SHELL_TOKEN_REDIRECT_APPEND
                         : SHELL_TOKEN_REDIRECT_CLOBBER;
    }
    return SHELL_TOKEN_REDIRECT_OUT;
  }
  if (next == '>') {
    *after = second + 1;
    return SHELL_TOKEN_REDIRECT_READ_WRITE;
  }
  if (next == '<') {
    *after = second + 1;
    size_t third = shell_source_logical_following(input, length, second);
    if (third < length && input[third] == '<') {
      *after = third + 1;
      return SHELL_TOKEN_HERESTRING;
    }
    return SHELL_TOKEN_HEREDOC;
  }
  return SHELL_TOKEN_REDIRECT_IN;
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
      cursor < end && shell_source_space((unsigned char)input[cursor]))
    return position;
  if (combined_output) {
    cursor = combined_after;
  } else {
    cursor = shell_source_skip_inline_continuations(input, end, cursor);
    if (cursor == end || (input[cursor] != '<' && input[cursor] != '>'))
      return position;
  }

  size_t operator_end;
  bool duplicate;
  shell_token_type_t operator_type = shell_source_redirect_operator(
      input, end, combined_output ? position : cursor, &operator_end,
      &duplicate);
  bool heredoc = operator_type == SHELL_TOKEN_HEREDOC;
  if (heredoc) {
    /* Start at the operator's exact end: only an immediately adjacent dash
     * is <<- syntax. Delimiter fragments have their own word grammar. */
    shell_source_pending_heredoc_t pending;
    cursor = operator_end;
    return shell_source_parse_heredoc_delimiter(input, end, &cursor, &pending)
               ? cursor
               : position;
  }
  cursor = operator_end;
  cursor = shell_source_skip_inline_continuations(input, end, cursor);
  size_t operand = cursor;
  if (duplicate) {
    /* A duplication target is usually one complete shell word. The raw close
     * marker is the exception: Bash recognizes the immediate `-` in
     * `>&-file` as `>&-`, then parses `file` as the following command word.
     * Preserve that lexical boundary here. Quoted and escaped spellings still
     * take the normal whole-word path and are classified after decoding. */
    size_t close_end = shell_source_redirect_close_end(input, cursor, end);
    if (close_end != cursor) {
      cursor = close_end;
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
