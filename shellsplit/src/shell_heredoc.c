/* Lexical spelling of delimiter-only dollar fragments. These fragments are
 * parsed, but not expanded or executed. In particular Bash prints a parsed
 * $(...) back into the delimiter word before applying quote removal. */
#include "shell_keywords_internal.h"
#include "shell_source_internal.h"
#include <stdio.h>

typedef enum {
  LIT_BYTES,
  LIT_SINGLE_BYTES,
  LIT_ANSI,
  LIT_ANSI_RAW,
  LIT_CHILD,
  LIT_WORD,
  LIT_DOCUMENT,
  LIT_QUOTED_CHILD,
} literal_kind_t;

typedef struct literal_piece literal_piece_t;
struct literal_piece {
  literal_piece_t *next, *child;
  const char *text;
  size_t length;
  literal_kind_t kind;
  bool strip_tabs, join_lines;
};

typedef struct {
  unsigned char previous, last;
  bool nul;
} literal_tail_t;

typedef struct {
  literal_piece_t *first, *last;
  bool any;
  literal_tail_t tail;
} literal_rope_t;

typedef struct {
  shell_source_pending_heredoc_t word;
  shell_source_heredoc_delimiter_t delimiter;
  literal_piece_t *body;
} literal_document_t;

typedef struct {
  const char *input;
  size_t length, position;
  unsigned depth;
  bool build;
  shell_source_heredoc_word_status_t status;
  literal_document_t pending[SHELL_MAX_SUBCOMMANDS];
  size_t pending_count;
} literal_parser_t;

typedef struct {
  literal_rope_t spelling;
  size_t start, end;
  bool quoted;
} literal_word_t;

typedef void (*literal_byte_t)(unsigned char byte, void *context);
typedef struct {
  literal_byte_t byte;
  void *context;
} literal_output_t;

/* Two pieces per source byte cover words, operators, and wrappers. Each
 * allocation permits arbitrary caller alignment. The remaining 16 bytes per
 * source byte cover printed spelling, live decoded nested delimiters and
 * conditional matching. A pattern uses at most two bytes per projected unit,
 * sizeof(size_t) per byte of its longest literal run, one decoded subject,
 * and size_t alignment padding; together these fit the 16-byte source factor.
 * These temporary spans share operation scratch.
 * Subscript facts and the public iterator's private continuation record use
 * an additional boundary entry plus 64 bytes per source byte. This covers
 * arbitrary alignment and keeps persistent facts outside delimiter marks.
 * This intentionally bounds storage, not semantic/parser capacities. */
bool shell_source_workspace_size(size_t length, size_t *size) {
  const size_t factor =
      2 * (sizeof(literal_piece_t) + _Alignof(literal_piece_t) - 1) + 16 +
      sizeof(shell_source_array_boundary_t) + 64;
  *size = 0;
  if (length > SIZE_MAX / factor)
    return false;
  *size = length * factor;
  return true;
}

static void literal_emit(literal_piece_t *piece, literal_output_t output);
static void literal_emit_word(literal_piece_t *piece, literal_output_t output);
static SHELL_NONNULL(1) literal_word_t
    literal_word(literal_parser_t *parser, char closing, bool inherited_double,
                 bool arithmetic);
static SHELL_NONNULL(1) literal_rope_t
    literal_list(literal_parser_t *parser, char closing);

static SHELL_NONNULL(1) literal_piece_t *literal_piece(literal_parser_t *parser,
                                                       literal_kind_t kind,
                                                       const char *text,
                                                       size_t length) {
  if (!parser->build)
    return NULL;
  void *storage = shell_source_scratch_take(sizeof(literal_piece_t) +
                                            _Alignof(literal_piece_t) - 1);
  if (!storage) {
    parser->status = SHELL_HEREDOC_WORD_INVALID;
    return NULL;
  }
  uintptr_t address = (uintptr_t)storage;
  address += (_Alignof(literal_piece_t) - address % _Alignof(literal_piece_t)) %
             _Alignof(literal_piece_t);
  literal_piece_t *piece = (literal_piece_t *)address;
  *piece = (literal_piece_t){.kind = kind, .text = text, .length = length};
  return piece;
}

/* Composable lexical facts, not a second traversal of nested word trees.
 * Raw NUL freezes the enclosing word's tail; a LIT_WORD contains that effect.
 */
static SHELL_NONNULL(1) void literal_tail_join(literal_tail_t *tail,
                                               literal_tail_t suffix) {
  if (!tail->nul) {
    if (suffix.last) {
      tail->previous = suffix.previous ? suffix.previous : tail->last;
      tail->last = suffix.last;
    }
    tail->nul = suffix.nul;
  }
}

static SHELL_NONNULL(2) void literal_tail_byte(unsigned char byte,
                                               void *context) {
  literal_tail_t *tail = context;
  if (!tail->nul) {
    if (!byte)
      tail->nul = true;
    else {
      tail->previous = tail->last;
      tail->last = byte;
    }
  }
}

static SHELL_NONNULL(1) void literal_append(literal_rope_t *rope,
                                            literal_piece_t *piece) {
  rope->any = true;
  if (!piece)
    return;
  if (rope->last)
    rope->last->next = piece;
  else
    rope->first = piece;
  rope->last = piece;
  literal_tail_t tail = {0};
  /* Leaves are visited once here; composites merge the facts below. The
   * quoted child is one already-decoded delimiter, never a command subtree.
   * Pending document bodies acquire text later and are followed by their
   * delimiter/newline, so they cannot determine a command's final bytes. */
  if (piece->kind != LIT_CHILD && piece->kind != LIT_WORD &&
      piece->kind != LIT_DOCUMENT)
    literal_emit(piece, (literal_output_t){literal_tail_byte, &tail});
  literal_tail_join(&rope->tail, tail);
}

static SHELL_NONNULL(1) void literal_join(literal_rope_t *rope,
                                          literal_rope_t suffix) {
  if (!suffix.any)
    return;
  rope->any = true;
  literal_tail_join(&rope->tail, suffix.tail);
  if (!suffix.first)
    return;
  if (rope->last)
    rope->last->next = suffix.first;
  else
    rope->first = suffix.first;
  rope->last = suffix.last;
}

static SHELL_NONNULL(1, 2, 3) void literal_text(literal_parser_t *parser,
                                                literal_rope_t *rope,
                                                const char *text) {
  literal_append(rope, literal_piece(parser, LIT_BYTES, text, strlen(text)));
}

static SHELL_NONNULL(1, 2) void literal_raw(literal_parser_t *parser,
                                            literal_rope_t *rope, size_t start,
                                            size_t end, bool single) {
  if (start != end)
    literal_append(rope,
                   literal_piece(parser, single ? LIT_SINGLE_BYTES : LIT_BYTES,
                                 parser->input + start, end - start));
}

static SHELL_NONNULL(1, 2) void literal_child(literal_parser_t *parser,
                                              literal_rope_t *rope,
                                              literal_rope_t child) {
  literal_piece_t *piece = literal_piece(parser, LIT_CHILD, NULL, 0);
  if (piece)
    piece->child = child.first;
  literal_append(rope, piece);
  literal_tail_join(&rope->tail, child.tail);
}

/* Unlike a matched-pair child, a parsed shell word is a C-string boundary in
 * Bash. A raw translated NUL ends this word, not following command structure.
 * Keep that boundary in the private rope rather than copying its spelling. */
static SHELL_NONNULL(1, 2) void literal_word_child(literal_parser_t *parser,
                                                   literal_rope_t *rope,
                                                   literal_rope_t word) {
  literal_piece_t *piece = literal_piece(parser, LIT_WORD, NULL, 0);
  if (piece)
    piece->child = word.first;
  literal_append(rope, piece);
  word.tail.nul = false;
  literal_tail_join(&rope->tail, word.tail);
}

static SHELL_NONNULL(1) bool literal_enter(literal_parser_t *parser) {
  if (++parser->depth >= SHELL_MAX_SUBCOMMANDS) {
    parser->status = SHELL_HEREDOC_WORD_INVALID;
    return false;
  }
  return true;
}

/* Literal word grouping deliberately does not validate a parameter selector
 * or evaluate an arithmetic expression. Bash does neither for delimiters. */
static SHELL_NONNULL(1) literal_rope_t
    literal_balanced(literal_parser_t *parser, char close,
                     bool inherited_double, bool arithmetic) {
  literal_rope_t result = {0};
  if (!literal_enter(parser))
    return result;
  literal_word_t body =
      literal_word(parser, close, inherited_double, arithmetic);
  literal_join(&result, body.spelling);
  if (parser->status == SHELL_HEREDOC_WORD_COMPLETE) {
    if (parser->position == parser->length)
      parser->status = SHELL_HEREDOC_WORD_INCOMPLETE;
    else {
      literal_raw(parser, &result, parser->position, parser->position + 1,
                  false);
      parser->position++;
    }
  }
  parser->depth--;
  return result;
}

/* A recursive substitution has its own pending heredoc queue. Parentheses
 * used only for grouping a list keep the enclosing queue instead. */
static SHELL_NONNULL(1) literal_rope_t
    literal_substitution(literal_parser_t *parser) {
  literal_rope_t result = {0};
  if (!literal_enter(parser))
    return result;
  literal_parser_t child = {.input = parser->input,
                            .length = parser->length,
                            .position = parser->position,
                            .depth = parser->depth,
                            .build = parser->build,
                            .status = SHELL_HEREDOC_WORD_COMPLETE};
  result = literal_list(&child, ')');
  parser->position = child.position;
  parser->status = child.status;
  parser->depth--;
  return result;
}

static SHELL_NONNULL(1) literal_rope_t
    literal_fragment_spelling(literal_parser_t *parser, bool inherited_double) {
  literal_rope_t result = {0};
  size_t start = parser->position;
  size_t after, height;
  if (!parser->build &&
      shell_source_index_get(parser->input, parser->length, start,
                             SHELL_SOURCE_INDEX_LITERAL_FRAGMENT, &after,
                             &height)) {
    parser->position = after;
    result.any = true;
    return result;
  }
  size_t open =
      shell_source_logical_following(parser->input, parser->length, start);
  char kind = parser->input[open];
  parser->position = open + 1;
  size_t first = shell_source_skip_escaped_line_endings(
      parser->input, parser->length, parser->position);
  if (kind == '{' && first < parser->length &&
      (shell_source_space((unsigned char)parser->input[first]) ||
       parser->input[first] == '|')) {
    /* Bash 5.3 current-shell substitutions require their own command
     * semantics and printer. They are not ordinary literal parameters. */
    parser->status = SHELL_HEREDOC_WORD_INVALID;
    return result;
  }
  literal_raw(parser, &result, start, parser->position, false);
  if (kind == '{' || kind == '[') {
    literal_join(&result, literal_balanced(parser, kind == '{' ? '}' : ']',
                                           inherited_double, kind == '['));
  } else if (shell_source_logical_next_is(parser->input, parser->length, open,
                                          '(', NULL)) {
    /* parse_comsub delegates an immediate second '(' to matched-pair
     * lexing, even if execution would later select a subshell fallback.
     * Preserve that balanced spelling; do not speculate about execution
     * grammar or print it as a parsed command tree. */
    literal_join(&result, literal_balanced(parser, ')', false, true));
  } else {
    literal_rope_t body = literal_substitution(parser);
    /* parse_comsub separates a leading subshell from the dollar opener so
     * its printed spelling cannot turn into arithmetic on the next parse. */
    if (body.first && body.first->text && body.first->length &&
        body.first->text[0] == '(')
      literal_text(parser, &result, " ");
    literal_join(&result, body);
    literal_text(parser, &result, ")");
  }
  if (parser->status == SHELL_HEREDOC_WORD_COMPLETE)
    shell_source_index_put(parser->input, parser->length, start,
                           SHELL_SOURCE_INDEX_LITERAL_FRAGMENT,
                           parser->position, 0);
  return result;
}

static literal_word_t literal_word(literal_parser_t *parser, char closing,
                                   bool inherited_double, bool arithmetic) {
  literal_word_t result = {.start = parser->position};
  size_t raw = parser->position;
  char quote = '\0';
  /* Bash's matched-pair lexer changes ANSI-C protection in double-quoted
   * parameter patterns. Record that state during this walk, not by rescanning
   * a selector (which may itself contain a large nested fragment). */
  enum { PARAMETER, OPERATOR, WORD, PATTERN } parameter = PARAMETER;
  bool parameter_byte = false;
  while (parser->position < parser->length &&
         parser->status == SHELL_HEREDOC_WORD_COMPLETE) {
    size_t position = parser->position;
    SHELL_SOURCE_WORD_SCAN(1);
    SHELL_SOURCE_DELIMITER_SCAN(parser->input, position);
    char c = parser->input[position];
    /* Removed physical continuations are not parameter bytes. In particular,
     * a leading continuation must not turn ${#name...} into a pattern and
     * change ANSI-C protection (and the terminating line) inside quotes. */
    if (c == '\\' && quote != '\'' && position + 1 < parser->length &&
        parser->input[position + 1] == '\n') {
      parser->position += 2;
      continue;
    }
    if (closing == '}' && !quote) {
      if (parameter == PARAMETER && parameter_byte && strchr("#%/^,", c))
        parameter = PATTERN;
      else if (parameter == PARAMETER && strchr("#%^,~:-=?+/", c))
        parameter = OPERATOR;
      else if (parameter == OPERATOR && !strchr("#%^,~:-=?+/", c))
        parameter = WORD;
      parameter_byte = true;
    }
    if (c == '\\' && quote != '\'') {
      if (position + 1 == parser->length) {
        parser->status = SHELL_HEREDOC_WORD_INCOMPLETE;
        break;
      }
      if (!quote && !closing && parser->input[position + 1] != '\n')
        result.quoted = true;
      parser->position += 2;
      continue;
    }
    if (quote == '\'') {
      parser->position++;
      if (c == '\'') {
        literal_raw(parser, &result.spelling, raw, parser->position, true);
        raw = parser->position;
        quote = '\0';
      }
      continue;
    }
    if ((!quote || c == '$') && (!arithmetic || c == '$') &&
        shell_source_heredoc_fragment_open(parser->input, parser->length,
                                           position)) {
      literal_raw(parser, &result.spelling, raw, position, false);
      literal_join(
          &result.spelling,
          literal_fragment_spelling(parser, inherited_double || quote == '"'));
      raw = parser->position;
      continue;
    }
    if (!quote && c == '$' &&
        shell_source_logical_next_is(parser->input, parser->length, position,
                                     '"', NULL)) {
      parser->status = SHELL_HEREDOC_WORD_INVALID;
      break;
    }
    if (!quote && c == '$' &&
        shell_source_logical_next_is(parser->input, parser->length, position,
                                     '\'', NULL)) {
      size_t after = position;
      if (parser->build) {
        /* The declaration admitted this complete quote already. Construction
         * needs its extent, not another unsupported-feature validation. */
        (void)shell_source_skip_complete_ansi_c_quote(
            parser->input, parser->length, position, &after);
      } else {
        bool has_nul, locale_dependent;
        if (!shell_source_ansi_c_quote_facts(parser->input, parser->length,
                                             &after, &has_nul,
                                             &locale_dependent)) {
          parser->status = SHELL_HEREDOC_WORD_INCOMPLETE;
          break;
        }
        if (locale_dependent) {
          parser->status = SHELL_HEREDOC_WORD_INVALID;
          break;
        }
      }
      literal_raw(parser, &result.spelling, raw, position, false);
      literal_append(&result.spelling,
                     literal_piece(parser,
                                   inherited_double && parameter != PATTERN
                                       ? LIT_ANSI_RAW
                                       : LIT_ANSI,
                                   parser->input + position, after - position));
      if (!closing)
        result.quoted = true;
      parser->position = raw = after;
      continue;
    }
    if (c == '`') {
      size_t after = position;
      if (!shell_source_skip_complete_backtick(parser->input, parser->length,
                                               position, &after)) {
        parser->status = SHELL_HEREDOC_WORD_INCOMPLETE;
        break;
      }
      parser->position = after;
      continue;
    }
    size_t extglob_open;
    if (!quote && strchr("@?+!*", c) &&
        shell_source_logical_next_is(parser->input, parser->length, position,
                                     '(', &extglob_open)) {
      literal_raw(parser, &result.spelling, raw, extglob_open + 1, false);
      parser->position = extglob_open + 1;
      literal_join(&result.spelling,
                   literal_balanced(parser, ')', inherited_double, arithmetic));
      raw = parser->position;
      continue;
    }
    if (c == '\'' && !quote) {
      literal_raw(parser, &result.spelling, raw, position, false);
      if (!closing)
        result.quoted = true;
      quote = c;
      raw = position;
    } else if (c == '"') {
      if (!closing)
        result.quoted = true;
      quote = quote ? '\0' : '"';
    } else if (!quote && closing && c == closing) {
      break;
    } else if (!quote &&
               ((closing == ')' && c == '(') || (closing == ']' && c == '['))) {
      literal_raw(parser, &result.spelling, raw, position + 1, false);
      parser->position++;
      literal_join(
          &result.spelling,
          literal_balanced(parser, closing, inherited_double, arithmetic));
      raw = parser->position;
      continue;
    } else if (!quote && !closing &&
               (shell_source_space((unsigned char)c) || strchr(";&|<>()", c))) {
      if ((c == '<' || c == '>') &&
          shell_source_logical_following(parser->input, parser->length,
                                         position) == parser->length) {
        parser->position = parser->length;
        parser->status = SHELL_HEREDOC_WORD_INCOMPLETE;
      }
      break;
    }
    parser->position++;
  }
  literal_raw(parser, &result.spelling, raw, parser->position, quote == '\'');
  if (quote && parser->status == SHELL_HEREDOC_WORD_COMPLETE)
    parser->status = SHELL_HEREDOC_WORD_INCOMPLETE;
  result.end = parser->position;
  return result;
}

static SHELL_NONNULL(2) void literal_remove_byte(unsigned char byte,
                                                 void *context) {
  shell_source_heredoc_remove_byte(byte, context);
}

static shell_source_heredoc_delimiter_t
literal_prepare_word(literal_word_t word) {
  shell_source_heredoc_decode_t measure = {0};
  shell_source_heredoc_remove_t remove = {&measure, word.quoted, false, '\0'};
  literal_emit_word(word.spelling.first,
                    (literal_output_t){literal_remove_byte, &remove});
  unsigned char *bytes = shell_source_scratch_take(measure.length);
  if (bytes) {
    shell_source_heredoc_decode_t fill = {bytes, 0};
    remove = (shell_source_heredoc_remove_t){&fill, word.quoted, false, '\0'};
    literal_emit_word(word.spelling.first,
                      (literal_output_t){literal_remove_byte, &remove});
  }
  return (shell_source_heredoc_delimiter_t){bytes, measure.length, word.quoted};
}

static SHELL_NONNULL(1) void literal_gap(literal_parser_t *parser) {
  parser->position = shell_source_skip_inline_continuations(
      parser->input, parser->length, parser->position);
  if (parser->position < parser->length &&
      parser->input[parser->position] == '#')
    parser->position =
        shell_source_line_end(parser->input, parser->length, parser->position);
}

static SHELL_NONNULL(1) void literal_bodies(literal_parser_t *parser) {
  for (size_t d = 0; d < parser->pending_count; d++) {
    literal_document_t *doc = &parser->pending[d];
    size_t start = parser->position, line = start, after = start;
    bool prefix = false, complete = false;
    while (line < parser->length) {
      if (shell_source_match_prepared_heredoc(parser->input, parser->length,
                                              line, &doc->delimiter, &after,
                                              &prefix, doc->word.strip_tabs)) {
        complete = true;
        break;
      }
      line = after;
    }
    if (!complete) {
      parser->position = parser->length;
      parser->status = SHELL_HEREDOC_WORD_INCOMPLETE;
      return;
    }
    if (doc->body) {
      doc->body->text = parser->input + start;
      doc->body->length = line - start;
      doc->body->strip_tabs = doc->word.strip_tabs;
      doc->body->join_lines = !doc->delimiter.quoted;
    }
    parser->position = after;
  }
  parser->pending_count = 0;
}

static SHELL_NONNULL(1, 2) bool literal_punctuation(literal_parser_t *parser,
                                                    const char *text) {
  size_t after;
  if (!shell_source_match_logical_punctuation(parser->input, parser->length,
                                              parser->position, text, &after))
    return false;
  parser->position = after;
  return true;
}

static SHELL_NONNULL(1, 2, 3) bool literal_redirect(literal_parser_t *parser,
                                                    literal_rope_t *redirects,
                                                    literal_rope_t *documents) {
  size_t start = parser->position, op = start;
  uint32_t fd = 0;
  size_t fd_name_end = 0;
  bool named = shell_source_parse_named_fd_at_word_start(
      parser->input, start, parser->length, &fd_name_end);
  shell_source_io_number_t number = SHELL_SOURCE_IO_NUMBER_NONE;
  if (named)
    op = fd_name_end;
  else
    number = shell_source_parse_io_number(parser->input, start, parser->length,
                                          &op, &fd);
  op =
      shell_source_skip_escaped_line_endings(parser->input, parser->length, op);
  if (op == parser->length ||
      (parser->input[op] != '<' && parser->input[op] != '>' &&
       !(parser->input[op] == '&' &&
         shell_source_logical_next_is(parser->input, parser->length, op, '>',
                                      NULL))) ||
      shell_source_process_substitution_open(parser->input, parser->length, op,
                                             NULL))
    return false;
  if (number == SHELL_SOURCE_IO_NUMBER_OVERFLOW) {
    return false; /* The number is an ordinary preceding word, as in Bash. */
  }
  if (op != start && parser->input[op] == '&')
    return false; /* Combined output has no numeric/named redirector form. */
  parser->position = op;
  const char *operator = NULL;
  bool combined = false, document = false, strip_tabs = false,
       duplicate = false;
  bool input = parser->input[op] == '<';
  if (literal_punctuation(parser, "&>>"))
    operator = "&>> ", combined = true;
  else if (literal_punctuation(parser, "&>"))
    operator = "&> ", combined = true;
  else if (literal_punctuation(parser, "<<<"))
    operator = "<<< ";
  else if (literal_punctuation(parser, "<<-"))
    operator = "<<-", document = strip_tabs = true;
  else if (literal_punctuation(parser, "<<"))
    operator = "<<", document = true;
  else if (literal_punctuation(parser, ">>"))
    operator = ">> ";
  else if (literal_punctuation(parser, ">|"))
    operator = ">| ";
  else if (literal_punctuation(parser, "<>"))
    operator = "<> ";
  else if (literal_punctuation(parser, "<&"))
    operator = "<&", duplicate = true;
  else if (literal_punctuation(parser, ">&"))
    operator = ">&", duplicate = true;
  else {
    parser->position++;
    operator = input ? "< " : "> ";
  }
  parser->position = shell_source_skip_inline_continuations(
      parser->input, parser->length, parser->position);
  size_t word_start = parser->position;
  size_t close_end = duplicate ? shell_source_redirect_close_end(
                                     parser->input, word_start, parser->length)
                               : word_start;
  bool close_target = close_end != word_start;
  literal_word_t word;
  if (close_target) {
    word = (literal_word_t){.start = word_start, .end = close_end};
    literal_raw(parser, &word.spelling, word_start, close_end, false);
    parser->position = close_end;
  } else
    word = literal_word(parser, '\0', false, false);
  if (word.end == word.start || parser->status != SHELL_HEREDOC_WORD_COMPLETE) {
    if (word.end == parser->length)
      parser->status = SHELL_HEREDOC_WORD_INCOMPLETE;
    else if (parser->status == SHELL_HEREDOC_WORD_COMPLETE)
      parser->status = SHELL_HEREDOC_WORD_INVALID;
    return true;
  }
  if (redirects->any)
    literal_text(parser, redirects, " ");
  uint32_t target_fd = 0;
  size_t target_after = word.start;
  bool digits =
      duplicate && shell_source_parse_io_number(
                       parser->input, word.start, word.end, &target_after,
                       &target_fd) == SHELL_SOURCE_IO_NUMBER_VALID;
  bool numeric_target = digits && target_after == word.end;
  /* Bash selects word-form moves from lexical spelling, even for quoted,
   * escaped or overflowing fd prefixes. The cached tail already accounts for
   * continuation removal and raw translated NUL at this word boundary. */
  bool move = duplicate && !close_target && word.spelling.tail.last == '-';
  bool numeric_move =
      move && digits && target_after < word.end &&
      parser->input[target_after] == '-' &&
      shell_source_skip_escaped_line_endings(parser->input, word.end,
                                             target_after + 1) == word.end;
  if (named)
    literal_raw(parser, redirects, start, fd_name_end, false);
  else if (!combined && ((number == SHELL_SOURCE_IO_NUMBER_VALID &&
                          fd != (input ? 0u : 1u)) ||
                         numeric_target || move || close_target)) {
    if (number == SHELL_SOURCE_IO_NUMBER_VALID) {
      /* Decimal IO_NUMBER spelling is normalized by Bash's parser. */
      char digits[16];
      int count = snprintf(digits, sizeof(digits), "%u", fd);
      char *bytes =
          parser->build ? shell_source_scratch_take((size_t)count) : NULL;
      if (bytes)
        memcpy(bytes, digits, (size_t)count);
      literal_append(redirects, literal_piece(parser, LIT_SINGLE_BYTES, bytes,
                                              (size_t)count));
    } else
      literal_text(parser, redirects, input ? "0" : "1");
  }
  literal_text(parser, redirects, close_target ? ">&" : operator);
  if (!document) {
    if (numeric_target || numeric_move) {
      char digits[16];
      int count = snprintf(digits, sizeof(digits), "%u", target_fd);
      char *bytes =
          parser->build ? shell_source_scratch_take((size_t)count) : NULL;
      if (bytes)
        memcpy(bytes, digits, (size_t)count);
      literal_append(redirects, literal_piece(parser, LIT_SINGLE_BYTES, bytes,
                                              (size_t)count));
      if (numeric_move)
        literal_text(parser, redirects, "-");
    } else
      literal_word_child(parser, redirects, word.spelling);
    return true;
  }
  if (parser->pending_count == SHELL_MAX_SUBCOMMANDS) {
    parser->status = SHELL_HEREDOC_WORD_INVALID;
    return true;
  }
  literal_document_t *doc = &parser->pending[parser->pending_count++];
  doc->word = (shell_source_pending_heredoc_t){
      parser->input + word.start, word.end - word.start, strip_tabs};
  if (parser->build)
    doc->delimiter = literal_prepare_word(word);
  else if (!shell_source_prepare_heredoc(&doc->word, &doc->delimiter))
    parser->status = SHELL_HEREDOC_WORD_INVALID;
  if (!doc->delimiter.bytes) {
    parser->status = SHELL_HEREDOC_WORD_INVALID;
    return true;
  }
  literal_piece_t *delimiter =
      literal_piece(parser, LIT_SINGLE_BYTES,
                    (const char *)doc->delimiter.bytes, doc->delimiter.length);
  literal_rope_t delimiter_rope = {0};
  literal_append(&delimiter_rope, delimiter);
  if (doc->delimiter.quoted) {
    literal_piece_t *quoted = literal_piece(parser, LIT_QUOTED_CHILD, NULL, 0);
    if (quoted)
      quoted->child = delimiter;
    literal_append(redirects, quoted);
  } else
    literal_child(parser, redirects, delimiter_rope);
  doc->body = literal_piece(parser, LIT_DOCUMENT, NULL, 0);
  literal_append(documents, doc->body);
  literal_child(parser, documents, delimiter_rope);
  literal_text(parser, documents, "\n");
  return true;
}

static SHELL_NONNULL(1) bool literal_reserved(const literal_parser_t *parser,
                                              size_t start, size_t end) {
  return shell_source_keyword(parser->input, end, start, NULL) ||
         shell_source_match_plain_word(parser->input, end, start, "!", 1, NULL);
}

static SHELL_NONNULL(1, 2) literal_rope_t
    literal_stage(literal_parser_t *parser, literal_rope_t *documents) {
  literal_rope_t result = {0}, words = {0}, redirects = {0};
  literal_gap(parser);
  if (parser->position == parser->length)
    return result;
  bool compound = false;
  size_t start = parser->position;
  bool brace = shell_source_match_plain_word(parser->input, parser->length,
                                             start, "{", 1, NULL);
  if (parser->input[start] == '(' &&
      shell_source_logical_next_is(parser->input, parser->length, start, '(',
                                   NULL)) {
    /* Command-position ((...)) is outside the supported grammar. Do not
     * silently print it as nested subshells and choose a different delimiter.
     */
    parser->status = SHELL_HEREDOC_WORD_INVALID;
    return result;
  }
  if (parser->input[start] == '(' || brace) {
    if (!literal_enter(parser))
      return result;
    compound = true;
    parser->position++;
    literal_text(parser, &words, brace ? "{ " : "( ");
    literal_rope_t body = literal_list(parser, brace ? '}' : ')');
    if (!body.any && parser->status == SHELL_HEREDOC_WORD_COMPLETE)
      parser->status = SHELL_HEREDOC_WORD_INVALID;
    bool terminated = body.tail.last == '\n' ||
                      (body.tail.previous == ' ' && body.tail.last == '&');
    literal_join(&words, body);
    literal_text(parser, &words, brace ? (terminated ? " }" : "; }") : " )");
    parser->depth--;
  }
  while (parser->status == SHELL_HEREDOC_WORD_COMPLETE) {
    literal_gap(parser);
    if (literal_redirect(parser, &redirects, documents))
      continue;
    start = parser->position;
    if (start == parser->length || strchr(";&|()", parser->input[start]) ||
        (parser->input[start] == '}' &&
         shell_source_match_plain_word(parser->input, parser->length, start,
                                       "}", 1, NULL)) ||
        parser->input[start] == '\n')
      break;
    if (compound) {
      parser->status = SHELL_HEREDOC_WORD_INVALID;
      break;
    }
    literal_word_t word = literal_word(parser, '\0', false, false);
    /* At received EOF this word can still gain a suffix, so an apparent
     * reserved word is not yet an unsupported construct. The substitution
     * itself also still needs its closing delimiter. */
    if (parser->status == SHELL_HEREDOC_WORD_COMPLETE &&
        word.end == parser->length) {
      parser->status = SHELL_HEREDOC_WORD_INCOMPLETE;
      break;
    }
    if (word.end == start || (!words.any && !redirects.any &&
                              literal_reserved(parser, start, word.end))) {
      parser->status = SHELL_HEREDOC_WORD_INVALID;
      break;
    }
    if (words.any)
      literal_text(parser, &words, " ");
    literal_word_child(parser, &words, word.spelling);
  }
  if (!words.any && !redirects.any)
    return result;
  literal_join(&result, words);
  if (words.any && redirects.any)
    literal_text(parser, &result, " ");
  literal_join(&result, redirects);
  return result;
}

static SHELL_NONNULL(1, 2, 3) void literal_flush(literal_parser_t *parser,
                                                 literal_rope_t *result,
                                                 literal_rope_t *documents) {
  if (!documents->any)
    return;
  literal_text(parser, result, "\n");
  literal_join(result, *documents);
  *documents = (literal_rope_t){0};
}

static literal_rope_t literal_list(literal_parser_t *parser, char closing) {
  literal_rope_t result = {0}, documents = {0};
  bool need_command = false, pipeline_start = true, ended = false;
  while (parser->status == SHELL_HEREDOC_WORD_COMPLETE) {
    literal_gap(parser);
    while (parser->position < parser->length &&
           parser->input[parser->position] == '\n') {
      parser->position++;
      literal_bodies(parser);
      literal_gap(parser);
    }
    if (parser->status != SHELL_HEREDOC_WORD_COMPLETE)
      break;
    if (parser->position == parser->length) {
      parser->status = SHELL_HEREDOC_WORD_INCOMPLETE;
      break;
    }
    if (parser->input[parser->position] == closing) {
      if (need_command || (closing == '}' && !ended))
        parser->status = SHELL_HEREDOC_WORD_INVALID;
      else
        parser->position++;
      break;
    }
    shell_source_pipeline_prefix_t prefix = {0};
    if (pipeline_start) {
      prefix = shell_source_parse_pipeline_prefix(
          parser->input, parser->position, parser->length);
      if (!prefix.valid) {
        parser->status = SHELL_HEREDOC_WORD_INVALID;
        break;
      }
      parser->position = prefix.stage_start;
      if (prefix.time_mode != SHELL_PIPE_TIME_NONE)
        literal_text(parser, &result,
                     prefix.time_mode == SHELL_PIPE_TIME_POSIX ? "time -p "
                                                               : "time ");
      if (prefix.negation_count & 1)
        literal_text(parser, &result, "! ");
    }
    literal_rope_t stage = literal_stage(parser, &documents);
    if (parser->status != SHELL_HEREDOC_WORD_COMPLETE)
      break;
    if (!stage.any && prefix.time_mode != SHELL_PIPE_TIME_NONE &&
        parser->position < parser->length &&
        (parser->input[parser->position] == ';' ||
         parser->input[parser->position] == '\n'))
      stage.any = true;
    if (!stage.any) {
      if (parser->status == SHELL_HEREDOC_WORD_COMPLETE)
        parser->status = parser->position == parser->length
                             ? SHELL_HEREDOC_WORD_INCOMPLETE
                             : SHELL_HEREDOC_WORD_INVALID;
      break;
    }
    literal_join(&result, stage);
    need_command = false;
    ended = false;
    literal_gap(parser);
    if (parser->position == parser->length) {
      parser->status = SHELL_HEREDOC_WORD_INCOMPLETE;
      break;
    }
    if (parser->input[parser->position] == closing)
      continue;
    const char *connector;
    bool pipe = false;
    if (literal_punctuation(parser, "|&")) {
      literal_text(parser, &result, " 2>&1");
      connector = " |";
      pipe = true;
    } else if (literal_punctuation(parser, "&&"))
      connector = " &&";
    else if (literal_punctuation(parser, "||"))
      connector = " ||";
    else if (literal_punctuation(parser, "|")) {
      connector = " |";
      pipe = true;
    } else if (literal_punctuation(parser, ";")) {
      connector = ";";
      ended = true;
    } else if (literal_punctuation(parser, "&")) {
      connector = " &";
      ended = true;
    } else if (parser->input[parser->position] == '\n') {
      parser->position++;
      literal_bodies(parser);
      connector = "\n";
      ended = true;
    } else {
      parser->status = SHELL_HEREDOC_WORD_INVALID;
      break;
    }
    /* Consume physical header newlines and their FIFO bodies exactly once
     * before deciding whether this connector has a following command. Raw
     * trivia lookahead would mistake a pending body for that command. */
    literal_gap(parser);
    while (parser->position < parser->length &&
           parser->input[parser->position] == '\n' &&
           parser->status == SHELL_HEREDOC_WORD_COMPLETE) {
      parser->position++;
      literal_bodies(parser);
      literal_gap(parser);
    }
    bool terminal = parser->position < parser->length &&
                    parser->input[parser->position] == closing;
    if (terminal && ended && connector[0] != '&' && connector[1] != '&') {
      /* A trailing semicolon/newline belongs to grammar, not a connection. */
      literal_flush(parser, &result, &documents);
      continue;
    }
    bool had_documents = documents.any;
    if (!(had_documents && (connector[0] == ';' || connector[0] == '\n')))
      literal_text(parser, &result, connector);
    if (had_documents && !pipe && !ended)
      literal_text(parser, &result, " ");
    literal_flush(parser, &result, &documents);
    if (had_documents && connector[0] == '\n')
      literal_text(parser, &result, "\n");
    if (connector[0] != '\n' && !terminal)
      literal_text(parser, &result, had_documents && pipe ? "  " : " ");
    need_command = !ended;
    pipeline_start = !pipe;
  }
  literal_flush(parser, &result, &documents);
  if (parser->pending_count && parser->status == SHELL_HEREDOC_WORD_COMPLETE)
    parser->status = SHELL_HEREDOC_WORD_INVALID;
  return result;
}

/* bytes may be NULL only for an empty span. A NULL piece is an empty rope;
 * allocated pieces and the output visitor remain live through emission. */
static void literal_output_bytes(literal_output_t output, const char *bytes,
                                 size_t length) {
  for (size_t i = 0; i < length; i++)
    output.byte((unsigned char)bytes[i], output.context);
}

typedef struct {
  literal_output_t output;
  unsigned char first;
  bool have_first, started, terminated, raw;
} literal_ansi_t;

static void literal_protect(literal_output_t output, unsigned char byte) {
  output.byte(byte, output.context);
  if (byte == '\'')
    literal_output_bytes(output, "\\''", 3);
}

static SHELL_NONNULL(2) bool literal_ansi_byte(unsigned char byte,
                                               void *context) {
  literal_ansi_t *ansi = context;
  if (ansi->terminated)
    return true;
  if (!byte) {
    ansi->terminated = true;
    /* Protected translation is sh_single_quote(C-string), which truncates
     * only its segment. Raw matched-pair translation preserves the NUL until
     * its owning lexical word is consumed by Bash's C-string machinery. */
    if (ansi->raw)
      ansi->output.byte(0, ansi->output.context);
    return true;
  }
  if (ansi->raw) {
    ansi->output.byte(byte, ansi->output.context);
    return true;
  }
  if (!ansi->have_first) {
    ansi->first = byte;
    ansi->have_first = true;
    return true;
  }
  if (!ansi->started) {
    ansi->output.byte('\'', ansi->output.context);
    literal_protect(ansi->output, ansi->first);
    ansi->started = true;
  }
  literal_protect(ansi->output, byte);
  return true;
}

typedef struct {
  literal_output_t output;
  unsigned char first;
  bool have_first, started;
} literal_quote_t;

static SHELL_NONNULL(2) void literal_quote_byte(unsigned char byte,
                                                void *context) {
  literal_quote_t *quote = context;
  if (!quote->have_first) {
    quote->first = byte;
    quote->have_first = true;
    return;
  }
  if (!quote->started) {
    quote->output.byte('\'', quote->output.context);
    literal_protect(quote->output, quote->first);
    quote->started = true;
  }
  literal_protect(quote->output, byte);
}

static void literal_finish_quote(literal_quote_t quote) {
  if (quote.started)
    quote.output.byte('\'', quote.output.context);
  else if (quote.have_first && quote.first == '\'')
    literal_output_bytes(quote.output, "\\'", 2);
  else {
    quote.output.byte('\'', quote.output.context);
    if (quote.have_first)
      quote.output.byte(quote.first, quote.output.context);
    quote.output.byte('\'', quote.output.context);
  }
}

typedef struct {
  literal_output_t output;
  bool terminated;
} literal_word_output_t;

static SHELL_NONNULL(2) void literal_word_byte(unsigned char byte,
                                               void *context) {
  literal_word_output_t *word = context;
  if (word->terminated)
    return;
  if (!byte)
    word->terminated = true;
  else
    word->output.byte(byte, word->output.context);
}

static void literal_emit_word(literal_piece_t *piece, literal_output_t output) {
  literal_word_output_t word = {.output = output};
  literal_emit(piece, (literal_output_t){literal_word_byte, &word});
}

static void literal_emit(literal_piece_t *piece, literal_output_t output) {
  for (; piece; piece = piece->next) {
    if (piece->kind == LIT_CHILD) {
      literal_emit(piece->child, output);
    } else if (piece->kind == LIT_WORD) {
      literal_emit_word(piece->child, output);
    } else if (piece->kind == LIT_QUOTED_CHILD) {
      literal_quote_t quote = {.output = output};
      literal_emit(piece->child,
                   (literal_output_t){literal_quote_byte, &quote});
      literal_finish_quote(quote);
    } else if (piece->kind == LIT_ANSI || piece->kind == LIT_ANSI_RAW) {
      size_t position = 0;
      literal_ansi_t ansi = {.output = output,
                             .raw = piece->kind == LIT_ANSI_RAW};
      (void)shell_source_decode_ansi_c_quote(
          piece->text, piece->length, &position, literal_ansi_byte, &ansi);
      if (!ansi.raw)
        literal_finish_quote((literal_quote_t){output, ansi.first,
                                               ansi.have_first, ansi.started});
    } else {
      bool line_start = true;
      for (size_t i = 0; i < piece->length; i++) {
        SHELL_SOURCE_WORD_SCAN(1);
        SHELL_SOURCE_DELIMITER_SCAN(piece->text, i);
        unsigned char byte = (unsigned char)piece->text[i];
        if ((piece->kind == LIT_BYTES ||
             (piece->kind == LIT_DOCUMENT && piece->join_lines)) &&
            byte == '\\' && i + 1 < piece->length) {
          if (piece->text[i + 1] == '\n') {
            i++;
            continue;
          }
          output.byte(byte, output.context);
          output.byte((unsigned char)piece->text[++i], output.context);
          continue;
        }
        if (piece->kind == LIT_DOCUMENT && piece->strip_tabs && line_start &&
            byte == '\t')
          continue;
        line_start = byte == '\n';
        output.byte(byte, output.context);
      }
    }
  }
}

shell_source_heredoc_word_status_t
shell_source_heredoc_fragment(const char *input, size_t length,
                              size_t *position) {
  size_t start = *position, mark = shell_source_scratch_mark();
  literal_parser_t parser = {.input = input,
                             .length = length,
                             .position = start,
                             .status = SHELL_HEREDOC_WORD_COMPLETE};
  (void)literal_fragment_spelling(&parser, false);
  *position = parser.position;
  shell_source_scratch_release(mark);
  return parser.status;
}

bool shell_source_prepare_literal_heredoc(
    const shell_source_pending_heredoc_t *pending,
    shell_source_heredoc_delimiter_t *delimiter) {
  literal_parser_t parser = {.input = pending->word,
                             .length = pending->word_length,
                             .build = true,
                             .status = SHELL_HEREDOC_WORD_COMPLETE};
  literal_word_t word = literal_word(&parser, '\0', false, false);
  if (parser.status != SHELL_HEREDOC_WORD_COMPLETE)
    return false;
  *delimiter = literal_prepare_word(word);
  return parser.status == SHELL_HEREDOC_WORD_COMPLETE && delimiter->bytes;
}
