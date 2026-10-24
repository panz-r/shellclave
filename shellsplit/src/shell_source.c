#include "shell_source.h"
#include "shell_keywords_internal.h"
#include "shell_processor_internal.h"
#include "shell_source_admission_internal.h"
#include "shell_source_draft_internal.h"
#include "shell_source_internal.h"
#include "shell_tokenizer_full_internal.h"
#include <string.h>

typedef struct {
  const char *source;
  shell_source_result_t *result;
  uint32_t header;
  uint32_t last_redirect[SHELL_SOURCE_MAX_HEADERS];
  shell_redirect_word_t redirect_word;
  shell_source_status_t failure;
} source_collector_t;

/* One lexical body's recovery facts. Record spans remain root-relative;
 * grammar diagnostics are relative to this body, never inherited from a
 * parent's unfinished word. Only the root frame is published to callers. */
typedef struct {
  size_t base;
  shell_source_draft_state_t grammar;
} source_body_t;

/* at is a root-relative position inside this body's source span. Collection
 * and projection preserve its first unfinished construct independently of
 * any child body's more local recovery needs. */
static SHELL_NONNULL(1) void need(source_body_t *body, shell_source_need_t kind,
                                  size_t at) {
  if (body->grammar.need == SHELL_SOURCE_NEEDS_NONE) {
    body->grammar.need = kind;
    body->grammar.incomplete_at = (uint32_t)(at - body->base);
  }
}

static SHELL_NONNULL(1) uint32_t
    header_new(source_collector_t *collector, size_t start, size_t depth,
               bool compound) {
  shell_source_result_t *out = collector->result;
  if (out->header_count == SHELL_SOURCE_MAX_HEADERS) {
    collector->failure = SHELL_SOURCE_TRUNCATED;
    return UINT32_MAX;
  }
  uint32_t id = out->header_count++;
  out->headers[id] = (shell_source_header_t){
      .source = {(uint32_t)start, 0},
      .first_redirect = UINT32_MAX,
      .group_depth = (uint16_t)depth,
      .complete = true,
      .compound = compound,
      .kind = compound ? SHELL_COMMAND_GROUP : SHELL_COMMAND_SIMPLE};
  collector->last_redirect[id] = UINT32_MAX;
  return id;
}

static SHELL_NONNULL(1, 2, 3) shell_process_status_t
    redirect_append(void *context, const shell_group_io_op_t *op,
                    const shell_redirect_word_t *word) {
  source_collector_t *collector = context;
  shell_source_result_t *out = collector->result;
  collector->redirect_word = *word;
  if (out->redirect_count == SHELL_SOURCE_MAX_REDIRECTS) {
    collector->failure = SHELL_SOURCE_TRUNCATED;
    return SHELL_PROCESS_EOUTPUT_LIMIT;
  }
  uint32_t id = out->redirect_count++;
  out->redirects[id] = (shell_source_redirect_t){.io = *op,
                                                 .header = collector->header,
                                                 .next = UINT32_MAX,
                                                 .heredoc = UINT32_MAX};
  shell_source_header_t *header = &out->headers[collector->header];
  if (header->redirect_count++)
    out->redirects[collector->last_redirect[collector->header]].next = id;
  else
    header->first_redirect = id;
  collector->last_redirect[collector->header] = id;
  if (op->kind == SHELL_GROUP_IO_HEREDOC) {
    if (out->heredoc_count == SHELL_SOURCE_MAX_HEREDOCS) {
      collector->failure = SHELL_SOURCE_TRUNCATED;
      return SHELL_PROCESS_EOUTPUT_LIMIT;
    }
    uint32_t doc = out->heredoc_count++;
    out->redirects[id].heredoc = doc;
    out->heredocs[doc] = (shell_source_heredoc_t){
        .header = collector->header,
        .redirect = id,
        .declaration = {op->source_start, op->source_end - op->source_start},
        .delimiter_word = {op->operand_start,
                           op->operand_end - op->operand_start},
        .content = {.kind = SHELL_DOC_HEREDOC}};
  }
  return SHELL_PROCESS_OK;
}

static SHELL_NONNULL(1, 2) shell_source_status_t
    collect(source_collector_t *collector, source_body_t *body, size_t length,
            size_t depth, shell_source_draft_end_t end_context);

/* Keep one ordered iterator for complete and unfinished words alike. Closed
 * children retain their records and must have classified grammar even when a
 * later quote or substitution has not arrived. The executable-only adapter
 * consumes arithmetic completion events without collecting their children
 * twice. Heredoc roots use their own quoting and EOF diagnostics. */
static SHELL_NONNULL(1, 2) bool collect_expansions(
    source_collector_t *collector, source_body_t *owner, size_t base,
    size_t length, size_t depth, bool heredoc, bool unfinished,
    bool arithmetic) {
  const char *word = collector->source + base;
  shell_source_substitution_scan_t scan = {
      .scope = {.heredoc = heredoc,
                .suppress_process = heredoc || arithmetic,
                .arithmetic_scope = arithmetic}};
  size_t start, after;
  shell_source_substitution_kind_t kind;
  shell_source_scan_status_t terminal;
  while ((terminal = shell_source_next_executable_substitution(
              word, length, &scan, &start, &after, &kind)) ==
         SHELL_SOURCE_SCAN_FOUND) {
    if (scan.has_backtick_escapes)
      return false;
    size_t body = start + 1, open = 0;
    if (kind != SHELL_SOURCE_SUBST_BACKTICK) {
      if (kind == SHELL_SOURCE_SUBST_COMMAND)
        shell_source_dollar_parentheses_open(word, length, start, &open);
      else
        shell_source_process_substitution_open(word, length, start, &open);
      body = open + 1;
    }
    source_body_t child = {.base = base + body};
    shell_source_status_t status = collect(
        collector, &child, after - body - 1, depth + 1,
        kind == SHELL_SOURCE_SUBST_BACKTICK ? SHELL_SOURCE_END_BACKTICK
                                            : SHELL_SOURCE_END_PARENTHESIZED);
    if (status != SHELL_SOURCE_COMPLETE) {
      collector->failure = status;
      return false;
    }
  }
  if (scan.exhausted) {
    collector->failure = SHELL_SOURCE_TRUNCATED;
    return false;
  }
  if (terminal == SHELL_SOURCE_SCAN_MALFORMED ||
      terminal == SHELL_SOURCE_SCAN_UNSUPPORTED || scan.has_backtick_escapes)
    return false;
  if (unfinished) {
    bool quoted =
        scan.scope.in_single_quote || scan.scope.in_double_quote ||
        (scan.position < length && word[scan.position] == '$' &&
         shell_source_logical_next_is(word, length, scan.position, '\'', NULL));
    need(owner,
         quoted                               ? SHELL_SOURCE_NEEDS_QUOTE
         : length && word[length - 1] == '\\' ? SHELL_SOURCE_NEEDS_ESCAPE
                                              : SHELL_SOURCE_NEEDS_SUBSTITUTION,
         base);
  } else if (!heredoc) {
    return terminal == SHELL_SOURCE_SCAN_DONE;
  }
  if (scan.unfinished.body_start) {
    size_t body = scan.unfinished.body_start;
    size_t received = scan.unfinished.body_length;
    source_body_t child = {.base = base + body};
    shell_source_status_t status = collect(
        collector, &child, received, depth + 1, SHELL_SOURCE_END_OPEN_CHILD);
    if (status != SHELL_SOURCE_COMPLETE && status != SHELL_SOURCE_INCOMPLETE) {
      collector->failure = status;
      return false;
    }
  }
  return true;
}

static SHELL_NONNULL(1) void header_finish(source_collector_t *collector,
                                           uint32_t id, size_t end) {
  if (id == UINT32_MAX)
    return;
  shell_source_header_t *header = &collector->result->headers[id];
  header->source.length = (uint32_t)end - header->source.start;
}

static SHELL_NONNULL(1, 2) bool collect_body(source_collector_t *collector,
                                             source_body_t *body, size_t length,
                                             size_t depth) {
  if (depth >= SHELL_MAX_GROUPS) {
    collector->failure = SHELL_SOURCE_TRUNCATED;
    return false;
  }
  size_t base = body->base;
  const char *source = collector->source + base;
  shell_source_result_t *out = collector->result;
  shell_tokenizer_state_t lexer;
  shell_tokenizer_init_prechecked(&lexer, source, length);
  uint32_t current = UINT32_MAX, groups[SHELL_MAX_GROUPS];
  uint32_t documents[SHELL_SOURCE_MAX_HEREDOCS];
  size_t group_count = 0, document_count = 0, covered = 0;
  bool allow_prefix = true, continuation = false;
  shell_token_t token;
  while (shell_tokenizer_next(&lexer, &token)) {
    size_t start = token.position, end = start + token.length;
    if (start < covered)
      continue;
    /* A closed compound owns a still-appendable redirector, not an ordinary
     * word or another '{' group. Leave its existing redirects and children
     * untouched until an operator actually arrives. Closed child grammar
     * separately commits this local EOF and rejects an unfinished redirector.
     */
    if (current != UINT32_MAX && out->headers[current].compound) {
      size_t at;
      shell_source_fd_prefix_t prefix =
          shell_source_pending_fd_prefix(source, start, length, &at);
      if (prefix != SHELL_SOURCE_FD_PREFIX_NONE) {
        out->headers[current].complete = false;
        need(body,
             prefix == SHELL_SOURCE_FD_PREFIX_ESCAPE
                 ? SHELL_SOURCE_NEEDS_ESCAPE
                 : SHELL_SOURCE_NEEDS_REDIRECT,
             base + at);
        break;
      }
    }
    bool structural = !shell_token_is_literal(&token);
    bool newline = token.type == SHELL_TOKEN_SEMICOLON && token.length == 1 &&
                   token.start[0] == '\n';
    if (structural && (token.type == SHELL_TOKEN_GROUP_START ||
                       token.type == SHELL_TOKEN_SUBSHELL_START)) {
      if (group_count == SHELL_MAX_GROUPS) {
        collector->failure = SHELL_SOURCE_TRUNCATED;
        return false;
      }
      current = header_new(collector, base + start, depth + group_count, true);
      if (current == UINT32_MAX)
        return false;
      groups[group_count++] = current;
      current = UINT32_MAX;
      allow_prefix = true;
      continuation = false;
      continue;
    }
    if (structural && (token.type == SHELL_TOKEN_GROUP_END ||
                       token.type == SHELL_TOKEN_SUBSHELL_END)) {
      header_finish(collector, current, base + start);
      if (!group_count) {
        collector->failure = SHELL_SOURCE_INVALID;
        return false;
      }
      current = groups[--group_count];
      header_finish(collector, current, base + end);
      continue;
    }
    if (structural &&
        (token.type == SHELL_TOKEN_SEMICOLON ||
         token.type == SHELL_TOKEN_BACKGROUND ||
         token.type == SHELL_TOKEN_PIPE ||
         token.type == SHELL_TOKEN_PIPE_BOTH || token.type == SHELL_TOKEN_AND ||
         token.type == SHELL_TOKEN_OR)) {
      header_finish(collector, current, base + start);
      if (!newline || current != UINT32_MAX || !continuation) {
        allow_prefix = token.type != SHELL_TOKEN_PIPE &&
                       token.type != SHELL_TOKEN_PIPE_BOTH;
        continuation = token.type == SHELL_TOKEN_PIPE ||
                       token.type == SHELL_TOKEN_PIPE_BOTH ||
                       token.type == SHELL_TOKEN_AND ||
                       token.type == SHELL_TOKEN_OR;
      }
      current = UINT32_MAX;
      if (newline && document_count) {
        size_t body_start = end;
        for (size_t h = 0; h < document_count; h++)
          out->heredocs[documents[h]].header_complete = true;
        for (size_t h = 0; h < document_count; h++) {
          shell_source_heredoc_t *doc = &out->heredocs[documents[h]];
          shell_source_pending_heredoc_t pending = {
              .word = collector->source + doc->delimiter_word.start,
              .word_length = doc->delimiter_word.length,
              .strip_tabs = (doc->content.flags &
                             SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS) != 0};
          doc->header_complete = true;
          doc->body_started = true;
          shell_source_heredoc_frame_t frame =
              shell_source_frame_heredoc(source, length, body_start, &pending);
          doc->body_start = (uint32_t)(base + body_start);
          doc->content.value = source + body_start;
          doc->content.value_len = (uint32_t)(frame.body_end - body_start);
          doc->confirmed_length = (uint32_t)(frame.confirmed_end - body_start);
          doc->complete = frame.complete;
          doc->delimiter_prefix = frame.delimiter_prefix;
          if (frame.complete)
            doc->closing_delimiter = (shell_source_span_t){
                (uint32_t)(base + frame.delimiter_start),
                (uint32_t)(frame.delimiter_end - frame.delimiter_start)};
          else {
            body->grammar.heredoc_eof = true;
            need(body, SHELL_SOURCE_NEEDS_HEREDOC_BODY, doc->declaration.start);
          }
          /* Keep raw received content above, but publish children only from
           * confirmed data. Appending may finish the candidate delimiter. */
          if (!(doc->content.flags & SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL) &&
              !collect_expansions(collector, body, base + body_start,
                                  frame.confirmed_end - body_start,
                                  depth + group_count, true, false, false))
            return false;
          body_start = frame.after;
          if (!frame.complete)
            break;
        }
        document_count = 0;
      }
      continue;
    }
    if (shell_source_is_escaped_line_ending(source, start, end)) {
      continue;
    }
    if (current == UINT32_MAX) {
      if (allow_prefix) {
        shell_source_pipeline_prefix_t prefix =
            shell_source_parse_pipeline_prefix(source, start, length);
        allow_prefix = false;
        if (prefix.has_modifier && prefix.stage_start > start) {
          covered = prefix.stage_start;
          continue;
        }
      }
      current = header_new(collector, base + start, depth + group_count, false);
      if (current == UINT32_MAX)
        return false;
      continuation = false;
    }
    collector->header = current;
    if (token.type == SHELL_TOKEN_ARITHMETIC_COMMAND) {
      const char *expression;
      size_t expression_length;
      shell_tokenizer_arithmetic_content(&token, !lexer.in_arithmetic,
                                         &expression, &expression_length);
      size_t content = (size_t)(expression - source);
      size_t after = start + token.length;
      out->headers[current].kind = SHELL_COMMAND_ARITHMETIC;
      out->headers[current].compound = true;
      out->headers[current].arithmetic_expression = (shell_source_span_t){
          (uint32_t)(base + content), (uint32_t)expression_length};
      if (lexer.in_arithmetic) {
        out->headers[current].complete = false;
        need(body, SHELL_SOURCE_NEEDS_ARITHMETIC, base + start);
      }
      if (!collect_expansions(collector, body, base + content,
                              expression_length, depth + group_count, false,
                              lexer.in_arithmetic, true))
        return false;
      covered = after;
      continue;
    }
    /* A leading process substitution is a word fragment, not a redirect.
     * Its following quote/expansion belongs to that same word. */
    bool process_word =
        shell_source_process_substitution_open(source, length, start, NULL);
    size_t redirect_end =
        process_word ? start
                     : shell_source_skip_redirect(source, start, length);
    /* The complete operator still has a redirect role without its word.
     * Preserve that role for numeric/named prefixes as well as bare forms;
     * later grammar, not an invented argv word, diagnoses the missing word. */
    if (!process_word && redirect_end == start &&
        token.type != SHELL_TOKEN_HEREDOC &&
        full_token_is_redirection(&token)) {
      out->headers[current].complete = false;
      covered = end;
      continue;
    }
    if (redirect_end != start) {
      uint32_t old_docs = out->heredoc_count;
      bool found;
      shell_process_status_t status = shell_process_visit_redirects(
          collector->source, (uint32_t)(base + start),
          (uint32_t)(base + redirect_end), UINT16_MAX, true, redirect_append,
          collector, &found);
      if (status != SHELL_PROCESS_OK) {
        if (status == SHELL_PROCESS_EOUTPUT_LIMIT)
          collector->failure = SHELL_SOURCE_TRUNCATED;
        return false;
      }
      for (uint32_t id = old_docs; id < out->heredoc_count; id++) {
        shell_source_heredoc_t *doc = &out->heredocs[id];
        size_t position = start;
        while (position < redirect_end && source[position] != '<')
          position++;
        size_t operator_after = 0;
        shell_source_match_logical_punctuation(source, length, position, "<<",
                                               &operator_after);
        shell_source_pending_heredoc_t pending;
        shell_source_parse_heredoc_delimiter(source, length, &operator_after,
                                             &pending);
        doc->delimiter_word = (shell_source_span_t){
            (uint32_t)(base + (size_t)(pending.word - source)),
            (uint32_t)pending.word_length};
        if (pending.strip_tabs)
          doc->content.flags |= SHELL_DEP_DOC_FLAG_HEREDOC_STRIP_TABS;
        if (shell_source_heredoc_delimiter_is_quoted(&pending))
          doc->content.flags |= SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL;
        documents[document_count++] = id;
      }
      if (old_docs == out->heredoc_count) {
        shell_redirect_word_t word = collector->redirect_word;
        if (!word.complete) {
          out->headers[current].complete = false;
          /* An empty operand is grammar, not an open expansion. Keep walking
           * so a separator/comment cannot hide behind a fabricated unfinished
           * substitution; EOF alone can still acquire its redirect word. */
          if (word.start != word.end) {
            if (!collect_expansions(collector, body, word.start,
                                    word.end - word.start, depth + group_count,
                                    false, true, false))
              return false;
            break;
          }
        } else if (!collect_expansions(
                       collector, body, word.start, word.end - word.start,
                       depth + group_count, false, false, false))
          return false;
      }
      covered = redirect_end;
      continue;
    }
    if (token.type == SHELL_TOKEN_HEREDOC) {
      size_t op = start, after_operator;
      while (op < length && source[op] != '<')
        op++;
      shell_source_match_logical_punctuation(source, length, op, "<<",
                                             &after_operator);
      shell_source_pending_heredoc_t partial;
      shell_source_heredoc_word_status_t delimiter_status =
          shell_source_probe_heredoc_delimiter(source, length, &after_operator,
                                               &partial);
      if (delimiter_status != SHELL_HEREDOC_WORD_INCOMPLETE) {
        if (delimiter_status == SHELL_HEREDOC_WORD_MISSING)
          collector->failure = SHELL_SOURCE_INVALID;
        else if (delimiter_status == SHELL_HEREDOC_WORD_COMPLETE &&
                 lexer.heredoc_error &&
                 lexer.pending_heredoc_count == SHELL_MAX_SUBCOMMANDS)
          collector->failure = SHELL_SOURCE_TRUNCATED;
        return false;
      }
      if (out->heredoc_count == SHELL_SOURCE_MAX_HEREDOCS) {
        collector->failure = SHELL_SOURCE_TRUNCATED;
        return false;
      }
      out->heredocs[out->heredoc_count++] = (shell_source_heredoc_t){
          .header = current,
          .redirect = UINT32_MAX,
          .declaration = {(uint32_t)(base + start), (uint32_t)(length - start)},
          .delimiter_word = {(uint32_t)(base + (size_t)(partial.word - source)),
                             (uint32_t)partial.word_length},
          .content = {.kind = SHELL_DOC_HEREDOC}};
      need(body, SHELL_SOURCE_NEEDS_HEREDOC_HEADER, base + start);
      out->headers[current].complete = false;
      break;
    }
    size_t word_end = start;
    if (!shell_tokenizer_word_end(source, length, &token, &word_end)) {
      out->headers[current].complete = false;
      if (!collect_expansions(collector, body, base + start, length - start,
                              depth + group_count, false, true, false))
        return false;
      break;
    }
    if (word_end == start) { /* Missing redirect operand: grammar owns need. */
      out->headers[current].complete = false;
      continue;
    }
    shell_source_header_t *header = &out->headers[current];
    if (header->word_count == 0 && header->redirect_count == 0 &&
        shell_source_function_declarator_after(source, length, word_end))
      return false;
    /* The grammar diagnoses this appendable tail. Project that same word
     * fact here while its owning header is available; closed child sources
     * will be declined by their grammar instead of claiming completeness. */
    if (header->word_count == 0 && header->redirect_count == 0 &&
        shell_source_keyword(source, length, start, NULL)) {
      if (word_end != length)
        return false;
      header->complete = false;
    }
    if (header->word_count == SHELL_DEP_MAX_TOKENS) {
      collector->failure = SHELL_SOURCE_TRUNCATED;
      return false;
    }
    shell_source_assignment_word_t assignment;
    if (header->assignment_count == header->word_count &&
        (token.type == SHELL_TOKEN_ARRAY_ASSIGNMENT ||
         shell_source_parse_scalar_assignment_word(
             source + start, word_end - start, &assignment)))
      header->assignment_count++;
    header->words[header->word_count++] = (shell_source_span_t){
        (uint32_t)(base + start), (uint32_t)(word_end - start)};
    if (!collect_expansions(collector, body, base + start, word_end - start,
                            depth + group_count, false, false, false))
      return false;
    covered = word_end;
  }
  for (size_t h = 0; h < document_count; h++) {
    body->grammar.heredoc_eof = true;
    need(body, SHELL_SOURCE_NEEDS_HEREDOC_HEADER,
         out->heredocs[documents[h]].declaration.start);
  }
  header_finish(collector, current, base + length);
  /* Received extents remain useful even when the enclosing delimiter has not
   * arrived. Completeness belongs to that header, not its closed descendants.
   */
  while (group_count) {
    uint32_t group = groups[--group_count];
    header_finish(collector, group, base + length);
    out->headers[group].complete = false;
  }
  return true;
}

/* Every body follows the same collection/projection path exactly once.
 * Closed children commit their final word: local recovery information still
 * explains the grammar boundary, but cannot authorize appending outside it.
 * body has its source base and zero-initialized grammar on entry; it is
 * distinct from the enclosing body's frame throughout this invocation. */
static SHELL_NONNULL(1, 2) shell_source_status_t
    collect(source_collector_t *collector, source_body_t *body, size_t length,
            size_t depth, shell_source_draft_end_t end_context) {
  const char *source = collector->source + body->base;
  shell_source_scope_t previous = shell_source_scope_begin(source, length);
  shell_source_status_t status;
  if (collect_body(collector, body, length, depth))
    status =
        shell_source_draft_grammar(source, length, end_context, &body->grammar);
  else
    status = collector->failure;
  if (end_context != SHELL_SOURCE_END_RECEIVED &&
      end_context != SHELL_SOURCE_END_OPEN_CHILD &&
      status == SHELL_SOURCE_INCOMPLETE)
    /* Bash accepts implicit document termination at child EOF with warnings.
     * Its framing is not modeled; inability to append is not a syntax proof. */
    status = body->grammar.heredoc_eof ? SHELL_SOURCE_UNSUPPORTED
                                       : SHELL_SOURCE_INVALID;
  shell_source_scope_end(previous);
  return status;
}

shell_source_status_t shell_parse_draft(const char *source, size_t length,
                                        const shell_limits_t *limits,
                                        shell_source_result_t *out) {
  memset(out, 0, sizeof(*out));
  if (length > UINT32_MAX)
    return SHELL_SOURCE_TRUNCATED;
  shell_source_operation_begin(source, length);
  shell_source_workspace_scope_t previous = shell_source_workspace_begin(
      source, length, limits ? limits->workspace : NULL,
      limits ? limits->workspace_size : 0);
  shell_source_status_t status = shell_source_bytes_status(source, length);
  if (status != SHELL_SOURCE_COMPLETE)
    goto done;
  source_collector_t collector = {
      .source = source, .result = out, .failure = SHELL_SOURCE_UNSUPPORTED};
  source_body_t root = {0};
  status = collect(&collector, &root, length, 0, SHELL_SOURCE_END_RECEIVED);
  out->prefix_length = root.grammar.prefix_length;
  out->incomplete_at = root.grammar.incomplete_at;
  out->need = root.grammar.need;
  if (status == SHELL_SOURCE_COMPLETE)
    out->prefix_length = (uint32_t)length;
  if (status != SHELL_SOURCE_COMPLETE && status != SHELL_SOURCE_INCOMPLETE)
    goto done;
  if (out->prefix_length) {
    if (!shell_tokenizer_complete_syntax_valid(source, out->prefix_length)) {
      /* The diagnostic grammar already classified every modeled context.
       * Failure of this coarser strict boundary is not a new syntax proof. */
      status = SHELL_SOURCE_UNSUPPORTED;
      goto done;
    }
    shell_limits_t strict = limits ? *limits : SHELL_LIMITS_DEFAULT;
    strict.strict_mode = true;
    shell_error_t error = shell_parse_prevalidated(source, out->prefix_length,
                                                   &strict, &out->prefix);
    if (error != SHELL_OK) {
      status = error == SHELL_ETRUNC ? SHELL_SOURCE_TRUNCATED
                                     : SHELL_SOURCE_UNSUPPORTED;
      goto done;
    }
  }
  out->tail_start = out->prefix_length;
done:
  if (shell_source_scratch_exhausted())
    status = SHELL_SOURCE_TRUNCATED;
  if (status != SHELL_SOURCE_COMPLETE && status != SHELL_SOURCE_INCOMPLETE) {
    memset(&out->prefix, 0, sizeof(out->prefix));
    out->prefix_length = out->tail_start = 0;
    for (uint32_t h = 0; h < out->header_count; h++)
      out->headers[h].complete = false;
  }
  shell_source_workspace_end(previous);
  shell_source_operation_end();
  return status;
}
