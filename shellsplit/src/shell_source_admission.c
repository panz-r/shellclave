#include "shell_source_admission_internal.h"
#include "shell_source_internal.h"
#include "shell_tokenizer_full_internal.h"

static SHELL_NONNULL(1) bool ascii_span(const char *source, size_t start,
                                        size_t end) {
  for (size_t i = start; i < end; i++) {
    SHELL_SOURCE_WORD_SCAN(1);
    if ((unsigned char)source[i] >= 0x80)
      return false;
  }
  return true;
}

static SHELL_NONNULL(1) shell_source_status_t
    source_byte_islands(const char *source, size_t length, size_t depth);

static SHELL_NONNULL(1, 4) void code_bytes(const char *source, size_t start,
                                           size_t end, void *context) {
  bool *valid = context;
  *valid = ascii_span(source, start, end) && *valid;
}

/* The containing construct establishes the root byte and expansion rules.
 * Executable substitutions establish independent source contexts, including
 * inside arithmetic, quotes or an expandable document. Indexed assignment
 * prefixes keep their subscript code domain; their separately tokenized values
 * use ordinary word data. */
static SHELL_NONNULL(1) shell_source_status_t
    word_byte_islands(const char *word, size_t length, size_t depth,
                      bool heredoc, bool word_data, bool arithmetic) {
  shell_source_substitution_scan_t scan = {
      .scope = {.heredoc = heredoc,
                .suppress_process = heredoc || arithmetic,
                .arithmetic_scope = arithmetic,
                .data_domain = heredoc,
                .word_data = word_data},
      .code_visitor = code_bytes};
  bool valid = true;
  scan.code_context = &valid;
  size_t start, after;
  shell_source_substitution_kind_t kind;
  shell_source_scan_status_t status;
  while ((status = shell_source_next_word_expansion(word, length, &scan, &start,
                                                    &after, &kind)) ==
         SHELL_SOURCE_SCAN_FOUND) {
    if (!valid || scan.has_backtick_escapes)
      return SHELL_SOURCE_UNSUPPORTED;
    if (kind == SHELL_SOURCE_EXPANSION_ARITHMETIC ||
        kind == SHELL_SOURCE_EXPANSION_SUBSTRING)
      continue;
    size_t body = start + 1, open = 0;
    if (kind != SHELL_SOURCE_SUBST_BACKTICK) {
      if (kind == SHELL_SOURCE_SUBST_COMMAND)
        shell_source_dollar_parentheses_open(word, length, start, &open);
      else
        shell_source_process_substitution_open(word, length, start, &open);
      body = open + 1;
    }
    shell_source_status_t child =
        source_byte_islands(word + body, after - body - 1, depth + 1);
    if (child != SHELL_SOURCE_COMPLETE)
      return child;
  }
  if (scan.exhausted)
    return SHELL_SOURCE_TRUNCATED;
  if (!valid || scan.has_backtick_escapes ||
      status == SHELL_SOURCE_SCAN_MALFORMED ||
      status == SHELL_SOURCE_SCAN_UNSUPPORTED)
    return SHELL_SOURCE_UNSUPPORTED;
  if (scan.unfinished.body_start)
    return source_byte_islands(word + scan.unfinished.body_start,
                               scan.unfinished.body_length, depth + 1);
  return SHELL_SOURCE_COMPLETE;
}

static SHELL_NONNULL(1) shell_source_status_t
    source_byte_islands_body(const char *source, size_t length, size_t depth) {
  if (depth >= SHELL_MAX_SUBCOMMANDS)
    return SHELL_SOURCE_TRUNCATED;
  shell_tokenizer_state_t lexer;
  shell_tokenizer_init_prechecked(&lexer, source, length);
  shell_source_pending_heredoc_t pending[SHELL_MAX_SUBCOMMANDS];
  size_t count = 0;
  shell_token_t token;
  /* The lexer owns comment/trivia classification, including trailing comments
   * at EOF. Those skipped spans admit literal high bytes; emitted words keep
   * their scoped code checks. Deferred bodies are qualified separately below.
   * The root boundary already checked NUL and prohibited control/DEL bytes
   * everywhere, including skipped data. */
  while (shell_tokenizer_next(&lexer, &token)) {
    size_t end = token.position + token.length;
    if (token.type == SHELL_TOKEN_HEREDOC) {
      if (lexer.heredoc_error) {
        size_t op = token.position, after_operator;
        while (op < length && source[op] != '<')
          op++;
        shell_source_match_logical_punctuation(source, length, op, "<<",
                                               &after_operator);
        shell_source_pending_heredoc_t partial;
        shell_source_heredoc_word_status_t status =
            shell_source_probe_heredoc_delimiter(source, length,
                                                 &after_operator, &partial);
        if (status == SHELL_HEREDOC_WORD_INCOMPLETE)
          return SHELL_SOURCE_COMPLETE;
        if (status == SHELL_HEREDOC_WORD_INVALID)
          return SHELL_SOURCE_UNSUPPORTED;
        if (status == SHELL_HEREDOC_WORD_MISSING) {
          /* Byte admission does not diagnose this grammar error or invent a
           * body. Keep checking later code/data islands; the collector will
           * report INVALID once the whole byte domain has been admitted. */
          continue;
        }
        /* A complete word which could not join a full pending queue is a
         * resource stop. A previous missing word can leave heredoc_error
         * sticky, so a successfully appended declaration still proceeds. */
        if (lexer.pending_heredoc_count == count &&
            count == SHELL_MAX_SUBCOMMANDS)
          return SHELL_SOURCE_TRUNCATED;
      }
      if (lexer.pending_heredoc_count > count) {
        const shell_pending_heredoc_t *raw =
            &lexer.pending_heredocs[lexer.pending_heredoc_count - 1];
        pending[count++] = (shell_source_pending_heredoc_t){
            .word = source + raw->delimiter_position,
            .word_length = raw->delimiter_length,
            .strip_tabs = raw->strip_tabs};
      }
      /* An unfinished quoted delimiter is still a data island. Syntax
       * validation, not byte admission, decides whether it is complete. */
    } else if (token.type == SHELL_TOKEN_ARITHMETIC_COMMAND) {
      const char *content;
      size_t content_length;
      shell_tokenizer_arithmetic_content(&token, !lexer.in_arithmetic, &content,
                                         &content_length);
      shell_source_status_t status =
          word_byte_islands(content, content_length, depth, false, false, true);
      if (status != SHELL_SOURCE_COMPLETE)
        return status;
    } else {
      shell_source_status_t status =
          word_byte_islands(token.start, token.length, depth, false,
                            token.type != SHELL_TOKEN_ARRAY_ASSIGNMENT, false);
      if (status != SHELL_SOURCE_COMPLETE)
        return status;
    }
    if (token.type == SHELL_TOKEN_SEMICOLON && token.length == 1 &&
        token.start[0] == '\n' && count) {
      size_t body_start = end;
      for (size_t h = 0; h < count; h++) {
        shell_source_heredoc_frame_t frame =
            shell_source_frame_heredoc(source, length, body_start, &pending[h]);
        /* A tentative closing line is not executable body data. Its raw
         * bytes remain available in framing, without assuming an expansion. */
        if (!shell_source_heredoc_delimiter_is_quoted(&pending[h])) {
          shell_source_status_t status = word_byte_islands(
              source + body_start, frame.confirmed_end - body_start, depth,
              true, true, false);
          if (status != SHELL_SOURCE_COMPLETE)
            return status;
        }
        body_start = frame.after;
        if (!frame.complete)
          break;
      }
      count = 0;
    }
  }
  return shell_source_scratch_exhausted() ? SHELL_SOURCE_TRUNCATED
                                          : SHELL_SOURCE_COMPLETE;
}

static SHELL_NONNULL(1) shell_source_status_t
    source_byte_islands(const char *source, size_t length, size_t depth) {
  shell_source_scope_t previous = shell_source_scope_begin(source, length);
  shell_source_status_t status =
      source_byte_islands_body(source, length, depth);
  shell_source_scope_end(previous);
  return status;
}

/* Source-byte admission is not word separation: CR, VT and FF are readable
 * text, but only space/tab/LF separate Bash words. Reject other control bytes,
 * DEL before exposing a partial stream. High bytes belong to ordinary word
 * literals, comments and scoped heredoc data, with byte offsets and no
 * decoding.
 */
shell_source_status_t shell_source_bytes_status(const char *input,
                                                size_t length) {
  if (shell_source_operation_bytes_admitted(input, length))
    return SHELL_SOURCE_COMPLETE;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_PASSES);
#endif
  bool high_bytes = false;
  bool unsupported = false;
  for (size_t i = 0; i < length; i++) {
    SHELL_SOURCE_WORD_SCAN(1);
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
    shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_BYTE_VALIDATION_BYTES);
#endif
    unsigned char byte = (unsigned char)input[i];
    if (byte == '\0')
      return SHELL_SOURCE_INVALID_INPUT;
    unsupported |= (byte < 0x20 && !shell_ascii_space(byte)) || byte == 0x7F;
    high_bytes |= byte >= 0x80;
  }
  if (unsupported)
    return SHELL_SOURCE_UNSUPPORTED;
  if (high_bytes) {
    shell_source_status_t status = source_byte_islands(input, length, 0);
    if (status != SHELL_SOURCE_COMPLETE)
      return status;
  }
  shell_source_operation_note_admitted(input, length);
  return SHELL_SOURCE_COMPLETE;
}

bool shell_source_bytes_valid(const char *input, size_t length) {
  return shell_source_bytes_status(input, length) == SHELL_SOURCE_COMPLETE;
}
