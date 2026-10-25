#include "shell_tokenizer.h"
#include "shell_ascii.h"
#include "shell_conditional_internal.h"
#include "shell_keywords_internal.h"
#include "shell_pipeline_internal.h"
#include "shell_semantics_internal.h"
#include "shell_source_internal.h"
#include "shell_token_regions_internal.h"
#include "shell_token_traits_internal.h"
#include "shell_tokenizer_full.h"
#include "shell_tokenizer_full_internal.h"
#include <string.h>

/* --- FAST PARSER IMPLEMENTATION --- */

/**
 * Check if character is a shell separator
 */
static inline bool is_separator(char c) {
  return c == '|' || c == ';' || c == '&' || c == '<' || c == '>' || c == '\n';
}

/* Trim only lexical separator whitespace from a fast-parser range. An
 * unquoted backslash makes horizontal whitespace part of the preceding word,
 * while a backslash plus a physical line ending disappears before token
 * recognition and may be removed with the surrounding separator trivia.
 * Each call walks only the discarded suffix (and at most one retained
 * backslash run), so the parser remains linear across disjoint ranges. */
static SHELL_NONNULL(1) uint32_t
    fast_range_trim_end(const char *cmd, uint32_t start, uint32_t end) {
  while (end > start && shell_source_space((unsigned char)cmd[end - 1])) {
    unsigned char byte = (unsigned char)cmd[end - 1];
    if (byte == '\n') {
      size_t continued =
          shell_source_skip_inline_continuations_backward(cmd, end);
      if (continued < end) {
        end = (uint32_t)continued;
        continue;
      }
    }

    uint32_t slash = end - 1;
    while (slash > start && cmd[slash - 1] == '\\')
      slash--;
    if (((end - 1 - slash) & 1u) != 0)
      break;
    end--;
  }
  return end;
}

static SHELL_NONNULL(1) uint32_t
    fast_range_trim_start(const char *cmd, uint32_t start, uint32_t end) {
  while (start < end && shell_source_space((unsigned char)cmd[start]))
    start++;
  return start;
}

/* An io_number is contiguous with its redirect and starts at a shell-word
 * boundary. Values above INT_MAX remain ordinary argument text. */
/* `{` and `}` are reserved words only when they form a complete word. Keep
 * this separate from parameter-expansion handling: an unquoted `}` in
 * `echo foo}` is ordinary argument text, whereas `foo; }` is an invalid
 * command-position closer. */
static bool group_word_ends_here(const char *cmd, uint32_t pos,
                                 uint32_t cmd_len) {
  if (pos + 1 == cmd_len)
    return true;
  char next = cmd[pos + 1];
  return shell_source_space((unsigned char)next) || is_separator(next) ||
         next == ')';
}

/* Advance across one shell word without splitting a quoted here-string
 * operand at embedded whitespace. This preserves source ranges; shell_word.c
 * and its private fragment/decoder headers own value decoding. */
static uint32_t skip_shell_word(const char *cmd, uint32_t pos,
                                uint32_t cmd_len) {
  size_t after = pos;
  if (!shell_source_skip_shell_word(cmd, cmd_len, pos, &after) ||
      after > UINT32_MAX)
    return pos;
  return (uint32_t)after;
}

typedef struct {
  uint32_t start;
  uint32_t end;
  uint32_t operator_position;
  uint32_t features;
} heredoc_body_span_t;

static SHELL_NONNULL(1, 5) void detect_expansion_features(
    const char *input, size_t length, bool outer_double_quote,
    bool arithmetic_body, uint32_t *features, bool heredoc);

/* Retain complete document body/delimiter spans for structural skipping, with
 * expansion features attached to each declaration's source position. Root
 * body bytes are never interpreted as list syntax. An incomplete declaration
 * is tolerated only by the diagnostic parser; strict validation rejects it. */
static SHELL_NONNULL(1, 3, 5) bool collect_heredoc_body_spans(
    const char *cmd, uint32_t length, heredoc_body_span_t *spans,
    uint32_t capacity, uint32_t *span_count) {
  shell_source_pending_heredoc_t pending[SHELL_MAX_SUBCOMMANDS];
  size_t pending_positions[SHELL_MAX_SUBCOMMANDS];
  *span_count = 0;
  size_t position = 0;
  while (position < length) {
    uint32_t pending_count = 0;
    bool word_boundary = true;
    shell_source_pending_heredoc_t declaration;
    size_t operator_position = 0;
    shell_source_declaration_status_t status;
    while ((status = shell_source_next_heredoc_declaration(
                cmd, length, &position, &declaration, &operator_position,
                &word_boundary)) == SHELL_SOURCE_DECL_FOUND) {
      if (pending_count == SHELL_MAX_SUBCOMMANDS)
        return false;
      pending_positions[pending_count] = operator_position;
      pending[pending_count++] = declaration;
    }
    if (status == SHELL_SOURCE_DECL_MALFORMED)
      return false;
    position = shell_source_next_line(cmd, length, position);
    for (uint32_t h = 0; h < pending_count; h++) {
      size_t body_start = position;
      shell_source_heredoc_frame_t frame =
          shell_source_frame_heredoc(cmd, length, body_start, &pending[h]);
      if (!frame.complete || *span_count == capacity)
        return false;
      position = frame.after;
      heredoc_body_span_t *span = &spans[(*span_count)++];
      *span = (heredoc_body_span_t){(uint32_t)body_start, (uint32_t)position,
                                    (uint32_t)pending_positions[h], 0};
      if (!shell_source_heredoc_delimiter_is_quoted(&pending[h]))
        detect_expansion_features(cmd + body_start, frame.body_end - body_start,
                                  false, false, &span->features, true);
    }
  }
  return true;
}

static bool shell_identifier_start(char c) {
  return shell_ascii_alpha((unsigned char)c) || c == '_';
}

static bool shell_identifier_continue(char c) {
  return shell_ascii_alnum((unsigned char)c) || c == '_';
}

/* Recognize assignment syntax that establishes an array without treating the
 * index as a glob or the compound value as a command group. */
/* input is immutable storage of length bytes; all outputs are required,
 * distinct writable offsets. position is a candidate within that span. */
static SHELL_NONNULL(1, 4, 5, 6, 7, 8) bool skip_array_assignment(
    const char *input, uint32_t length, uint32_t position, size_t *after,
    size_t *subscript_start, size_t *subscript_after, size_t *value_start,
    size_t *value_after) {
  if (position >= length || !shell_identifier_start(input[position]))
    return false;

  *subscript_start = 0;
  *subscript_after = 0;
  *value_start = 0;
  *value_after = 0;

  size_t cursor = shell_source_logical_following(input, length, position);
  while (cursor < length && shell_identifier_continue(input[cursor]))
    cursor = shell_source_logical_following(input, length, cursor);
  bool indexed = false;
  if (cursor < length && input[cursor] == '[') {
    *subscript_start = cursor;
    if (!shell_source_skip_array_subscript(input, length, cursor, &cursor))
      return false;
    *subscript_after = cursor;
    cursor = shell_source_skip_escaped_line_endings(input, length, cursor);
    indexed = true;
  }
  if (cursor < length && input[cursor] == '+')
    cursor = shell_source_logical_following(input, length, cursor);
  if (cursor >= length || input[cursor] != '=')
    return false;
  cursor = shell_source_logical_following(input, length, cursor);
  if (!indexed && (cursor >= length || input[cursor] != '('))
    return false;

  if (cursor < length && input[cursor] == '(') {
    size_t group_start = cursor;
    if (!shell_source_find_balanced_parentheses(input, length, cursor, &cursor))
      return false;
    *value_start = group_start + 1;
    *value_after = cursor - 1;
  }
  *after = cursor;
  return true;
}

/* The fast scanner is lexical, but an array-shaped assignment is an array
 * assignment only before a command word. Keep this tiny no-allocation view of
 * the full token stream so `echo a[0]=b` remains an ordinary glob-capable
 * argument while `a[0]=b command` is tagged as Bash array syntax. */
typedef struct {
  shell_tokenizer_state_t state;
  shell_token_t token;
  shell_pipeline_prefix_state_t prefix;
  /* Snapshot the stage before the current token. Byte-oriented clients may
   * query its interior, so these facts stay stable until the next token. */
  shell_pipeline_prefix_state_t before_prefix;
  size_t syntax_end, before_syntax_end;
  bool before_prefix_open;
  size_t word_end;
  bool ready;
  bool command_start;
  bool prefix_open;
  bool redirect_operand;
  bool token_array_assignment;
} fast_array_context_t;

static bool fast_token_is_redirection(const shell_token_t *token) {
  return token->type == SHELL_TOKEN_REDIRECT_IN ||
         token->type == SHELL_TOKEN_REDIRECT_OUT ||
         token->type == SHELL_TOKEN_REDIRECT_ERR ||
         token->type == SHELL_TOKEN_REDIRECT_APPEND ||
         token->type == SHELL_TOKEN_REDIRECT_READ_WRITE ||
         token->type == SHELL_TOKEN_REDIRECT_CLOBBER ||
         token->type == SHELL_TOKEN_REDIRECT_BOTH ||
         token->type == SHELL_TOKEN_REDIRECT_BOTH_APPEND ||
         token->type == SHELL_TOKEN_HEREDOC ||
         token->type == SHELL_TOKEN_HERESTRING;
}

/* Recognize a complete logical prefix word, never a quoted/escaped spelling
 * or one fragment of time"". Only constant-sized prefix probes are needed. */
static SHELL_NONNULL(1) shell_pipeline_prefix_word_t
    fast_pipeline_prefix_word(const fast_array_context_t *context) {
  const shell_token_t *token = &context->token;
  if (token->type == SHELL_TOKEN_PIPE_NEGATE)
    return SHELL_PIPE_PREFIX_WORD_NEGATE;
  if (shell_source_match_plain_word(context->state.input, context->state.length,
                                    token->position, "time", 4, NULL))
    return SHELL_PIPE_PREFIX_WORD_TIME;
  if (shell_source_match_plain_word(context->state.input, context->state.length,
                                    token->position, "-p", 2, NULL))
    return SHELL_PIPE_PREFIX_WORD_POSIX;
  if (shell_source_match_plain_word(context->state.input, context->state.length,
                                    token->position, "--", 2, NULL))
    return SHELL_PIPE_PREFIX_WORD_END_OPTIONS;
  return SHELL_PIPE_PREFIX_WORD_OTHER;
}

static SHELL_NONNULL(1, 2) bool fast_array_context_init(
    fast_array_context_t *context, const char *input, uint32_t length,
    bool allow_initial_time) {
  *context = (fast_array_context_t){
      .prefix = shell_pipeline_prefix_state_initial(allow_initial_time),
      .command_start = true,
      .prefix_open = true,
  };
  bool initialized = shell_tokenizer_init(&context->state, input, length, NULL);
  if (!allow_initial_time)
    context->state.lexical_prefix &= (uint8_t)~LEXICAL_TIME_MASK;
  return initialized;
}

static SHELL_NONNULL(1) bool fast_array_context_next(
    fast_array_context_t *context) {
  if (!shell_tokenizer_next(&context->state, &context->token))
    return false;
  context->ready = true;
  context->token_array_assignment = false;
  context->before_prefix = context->prefix;
  context->before_prefix_open = context->prefix_open;
  context->before_syntax_end = context->syntax_end;
  if (shell_source_is_escaped_line_ending(
          context->state.input, context->token.position,
          context->token.position + context->token.length))
    return true;
  context->syntax_end = context->token.position + context->token.length;
  /* Continuation LF does not start a new stage. Lexical time recognition is
   * maintained by the iterator; the list boundary rejects a reserved keyword
   * in a post-pipe stage before this prevalidated feature walk. */
  if (context->command_start && context->prefix_open &&
      context->word_end == 0 && context->token.type == SHELL_TOKEN_SEMICOLON &&
      (context->token.start[0] == '\n'))
    return true;
  if (context->token.type == SHELL_TOKEN_PIPE ||
      context->token.type == SHELL_TOKEN_PIPE_BOTH ||
      context->token.type == SHELL_TOKEN_SEMICOLON ||
      context->token.type == SHELL_TOKEN_AND ||
      context->token.type == SHELL_TOKEN_OR ||
      context->token.type == SHELL_TOKEN_BACKGROUND) {
    context->command_start = true;
    context->prefix_open = true;
    context->prefix = shell_pipeline_prefix_state_initial(
        context->token.type != SHELL_TOKEN_PIPE &&
        context->token.type != SHELL_TOKEN_PIPE_BOTH);
    context->word_end = 0;
    context->redirect_operand = false;
    return true;
  }
  if (context->token.type == SHELL_TOKEN_GROUP_START ||
      context->token.type == SHELL_TOKEN_SUBSHELL_START) {
    context->command_start = true;
    context->prefix_open = true;
    context->prefix = shell_pipeline_prefix_state_initial(true);
    context->word_end = 0;
    context->redirect_operand = false;
    return true;
  }
  if (context->token.type == SHELL_TOKEN_GROUP_END ||
      context->token.type == SHELL_TOKEN_SUBSHELL_END) {
    context->command_start = false;
    context->prefix_open = false;
    context->word_end = 0;
    context->redirect_operand = false;
    return true;
  }
  if (fast_token_is_redirection(&context->token)) {
    context->redirect_operand = shell_source_redirection_consumes_word(
        context->token.start, context->token.length);
    context->prefix_open = false;
    context->word_end = 0;
    return true;
  }
  /* Each logical word is classified once. Quoted values, expansions and
   * continued fragments retain that decision without rescanning a prefix or
   * treating a redirect's second fragment as an executable. */
  bool continues =
      context->word_end != 0 &&
      shell_tokenizer_token_continues_word(&context->token, context->word_end);
  context->word_end = context->token.position + context->token.length;
  if (continues)
    return true;
  if (context->redirect_operand) {
    context->redirect_operand = false;
    return true;
  }
  if (context->command_start && context->prefix_open &&
      shell_pipeline_prefix_step(&context->prefix,
                                 fast_pipeline_prefix_word(context)) !=
          SHELL_PIPE_PREFIX_NOT_ACCEPTED)
    return true;
  context->prefix_open = false;
  context->token_array_assignment =
      context->token.type == SHELL_TOKEN_ARRAY_ASSIGNMENT &&
      (context->command_start ||
       shell_source_array_assignment_is_compound(context->token.start,
                                                 context->token.length));
  shell_source_assignment_word_t assignment;
  if (context->command_start &&
      (context->token.type == SHELL_TOKEN_ARRAY_ASSIGNMENT ||
       shell_source_parse_scalar_assignment_word(
           context->token.start,
           context->state.length - context->token.position, &assignment)))
    return true;
  context->command_start = false;
  return true;
}

/* Keep the containing token until its end, including when another consumer
 * probes an interior byte for an assignment or delimiter. All probes are
 * ordered, so a literal '#' can be distinguished from a skipped comment
 * without reconstructing any source prefix. */
static SHELL_NONNULL(1) bool fast_lexical_token_contains(
    fast_array_context_t *context, uint32_t position) {
  while ((!context->ready ||
          context->token.position + context->token.length <= position) &&
         fast_array_context_next(context))
    ;
  return context->ready && context->token.position <= position &&
         position < context->token.position + context->token.length;
}

static SHELL_NONNULL(1) bool fast_lexical_token_at(
    fast_array_context_t *context, uint32_t position) {
  return fast_lexical_token_contains(context, position) &&
         context->token.position == position;
}

static SHELL_NONNULL(1) bool fast_array_assignment_at(
    fast_array_context_t *context, uint32_t position) {
  return fast_lexical_token_at(context, position) &&
         context->token_array_assignment;
}

/* The lexical redirect includes its descriptor prefix. Consume the ordered
 * stream once instead of guessing a word boundary from preceding bytes (a
 * descriptor close can be directly adjacent to the next named redirect). */
static SHELL_NONNULL(1) uint32_t
    fast_document_prefix(fast_array_context_t *context, uint32_t marker) {
  while ((!context->ready ||
          context->token.position + context->token.length <= marker) &&
         fast_array_context_next(context))
    ;
  return context->ready && context->token.position <= marker &&
                 (context->token.type == SHELL_TOKEN_HEREDOC ||
                  context->token.type == SHELL_TOKEN_HERESTRING)
             ? (uint32_t)context->token.position
             : marker;
}

typedef enum {
  FAST_FEATURE_WORD,
  FAST_FEATURE_CONDITIONAL_WORD,
  FAST_FEATURE_COMMAND_BODY,
} fast_feature_context_t;

static SHELL_NONNULL(1, 4) void detect_features(const char *cmd, uint32_t start,
                                                uint32_t len,
                                                uint32_t *features,
                                                bool allow_initial_time,
                                                fast_feature_context_t context);
static SHELL_NONNULL(1, 4) void detect_control_features(const char *cmd,
                                                        uint32_t start,
                                                        uint32_t len,
                                                        uint32_t *features);

/* A recognized command-substitution body begins after its opener. Check only
 * that prefix, not quoted source elsewhere in the containing command. */
static SHELL_NONNULL(1, 4) void detect_file_substitution_feature(
    const char *input, size_t length, size_t body_start, uint32_t *features) {
  size_t start, end;
  if (shell_source_file_substitution(input + body_start, length - body_start,
                                     &start, &end))
    *features |= SHELL_FEAT_SUBSHELL_FILE;
}

/* Gather a parameter operand, extglob word or arithmetic body in one
 * quote-aware stream.
 * Operand punctuation is not outer shell syntax. Only executable substitution
 * bodies get their separate shell-command walk; heredoc roots are data. */
static SHELL_NONNULL(1, 5) void detect_expansion_features(
    const char *input, size_t length, bool outer_double_quote,
    bool arithmetic_body, uint32_t *features, bool heredoc) {
  shell_source_substitution_scan_t scan = {.scope = {.heredoc = heredoc}};
  scan.scope.in_double_quote = outer_double_quote;
  scan.scope.arithmetic_scope = arithmetic_body;
  scan.scope.suppress_process = arithmetic_body || heredoc;
  size_t start = 0, end = 0;
  shell_source_substitution_kind_t kind = SHELL_SOURCE_SUBST_COMMAND;
  while (shell_source_next_executable_substitution(input, length, &scan, &start,
                                                   &end, &kind) ==
         SHELL_SOURCE_SCAN_FOUND) {
    size_t body_start = start + 1;
    if (kind == SHELL_SOURCE_SUBST_COMMAND) {
      *features |= SHELL_FEAT_SUBSHELL;
      body_start = shell_source_logical_following(input, length, start) + 1;
      detect_file_substitution_feature(input, end - 1, body_start, features);
    } else if (kind == SHELL_SOURCE_SUBST_BACKTICK) {
      *features |= SHELL_FEAT_SUBSHELL;
    } else {
      *features |= SHELL_FEAT_PROCESS_SUB;
      body_start = shell_source_logical_following(input, length, start) + 1;
    }
    if (end > body_start + 1)
      detect_features(input, (uint32_t)body_start,
                      (uint32_t)(end - body_start - 1), features, true,
                      FAST_FEATURE_COMMAND_BODY);
  }
  if (scan.has_variables || scan.has_arithmetic_variables)
    *features |= SHELL_FEAT_VARS;
  if (scan.has_arithmetic)
    *features |= SHELL_FEAT_ARITH;
  if (scan.has_arrays)
    *features |= SHELL_FEAT_ARRAY;
  if (scan.has_ansi_c)
    *features |= SHELL_FEAT_ANSI_C_QUOTE;
}

static SHELL_NONNULL(1, 5) void detect_parameter_features(
    const char *input, size_t position, size_t after, bool outer_double_quote,
    uint32_t *features) {
  detect_expansion_features(input + position, after - position,
                            outer_double_quote, false, features, false);
}

/* Bracket and identifier syntax belongs to arithmetic, not filename globbing.
 */
static SHELL_NONNULL(1, 4) void detect_arithmetic_features(const char *cmd,
                                                           size_t start,
                                                           size_t end,
                                                           uint32_t *features) {
  detect_expansion_features(cmd + start, end - start, false, true, features,
                            false);
}
/* Gather features in one immutable source range. Only command-body contexts
 * collect lexical control words; operand contexts still discover executable
 * children and give each child its own command-body context. */
static SHELL_NONNULL(1,
                     4) void detect_features(const char *cmd, uint32_t start,
                                             uint32_t len, uint32_t *features,
                                             bool allow_initial_time,
                                             fast_feature_context_t context) {
  static _Thread_local unsigned nesting;
  if (nesting >= SHELL_MAX_SUBCOMMANDS)
    return;
  nesting++;
  const char *p = cmd + start;
  shell_source_scope_t previous = shell_source_scope_begin(p, len);
  uint32_t i = 0;
  bool in_single_quotes = false;
  bool in_double_quotes = false;
  /* Nested command bodies are shell source with deferred documents, not a
   * single word. Preserve each body's own quoting rules and keep its raw
   * bytes out of the surrounding command-feature walk. */
  heredoc_body_span_t bodies[SHELL_MAX_SUBCOMMANDS];
  uint32_t body_count = 0, next_body = 0;
  if (!collect_heredoc_body_spans(p, len, bodies, SHELL_MAX_SUBCOMMANDS,
                                  &body_count))
    body_count = 0;
  fast_array_context_t array_context;
  bool have_array_context =
      fast_array_context_init(&array_context, p, len, allow_initial_time);
  if (have_array_context && context == FAST_FEATURE_CONDITIONAL_WORD) {
    array_context.command_start = array_context.prefix_open = false;
    array_context.state.lexical_command_position = false;
    array_context.state.lexical_prefix &= (uint8_t)~LEXICAL_ASSIGNMENT_ALLOWED;
  }

  while (i < len) {
    shell_source_scope_frontier(p, i);
    while (next_body < body_count && i >= bodies[next_body].end)
      next_body++;
    if (next_body < body_count && i >= bodies[next_body].start) {
      *features |= bodies[next_body].features;
      i = bodies[next_body++].end;
      continue;
    }
    char c = p[i];
    if (!in_single_quotes && !in_double_quotes && c == '[' &&
        have_array_context && fast_lexical_token_at(&array_context, i) &&
        array_context.token.type == SHELL_TOKEN_CONDITIONAL_COMMAND) {
      shell_conditional_t condition = shell_conditional_parse(p, len, i);
      *features |= shell_conditional_features(condition.predicate);
      shell_token_regions_t regions = shell_conditional_regions(p, &condition);
      for (unsigned operand = 0; operand < regions.count; ++operand) {
        const shell_token_region_t *region = &regions.regions[operand];
        if (region->length)
          detect_features(p, (uint32_t)(region->text - p),
                          (uint32_t)region->length, features, true,
                          FAST_FEATURE_CONDITIONAL_WORD);
      }
      i = (uint32_t)condition.after;
      continue;
    }
    if (!in_single_quotes && !in_double_quotes && c == '(' &&
        have_array_context && fast_lexical_token_at(&array_context, i) &&
        array_context.token.type == SHELL_TOKEN_ARITHMETIC_COMMAND) {
      *features |= SHELL_FEAT_ARITH;
      const char *content;
      size_t content_length;
      shell_tokenizer_arithmetic_content(&array_context.token,
                                         !array_context.state.in_arithmetic,
                                         &content, &content_length);
      detect_arithmetic_features(content, 0, content_length, features);
      i = (uint32_t)(array_context.token.position + array_context.token.length);
      continue;
    }

    if (!in_single_quotes && !in_double_quotes && c == '#' &&
        have_array_context && !fast_lexical_token_contains(&array_context, i)) {
      i = (uint32_t)shell_source_line_end(p, len, i);
      continue;
    }
    if (!in_single_quotes && !in_double_quotes && c == '<') {
      size_t after = 0;
      if (shell_source_match_logical_punctuation(p, len, i, "<<<", &after)) {
        *features |= SHELL_FEAT_HERESTRING;
        i = (uint32_t)after;
        continue;
      }
      if (shell_source_match_logical_punctuation(p, len, i, "<<", &after)) {
        *features |= SHELL_FEAT_HEREDOC;
        shell_source_pending_heredoc_t declaration;
        if (shell_source_parse_heredoc_delimiter(p, len, &after,
                                                 &declaration)) {
          i = (uint32_t)after;
          continue;
        }
      }
    }
    if (!in_single_quotes && !in_double_quotes && c == '|') {
      size_t after = shell_source_logical_following(p, len, i);
      if (after == len || p[after] != '|')
        *features |= SHELL_FEAT_PIPELINE;
      i = (uint32_t)(after < len && (p[after] == '|' || p[after] == '&')
                         ? after + 1
                         : after);
      continue;
    }

    // Handle single quotes - no expansion inside
    if (c == '\'' && !in_double_quotes) {
      in_single_quotes = !in_single_quotes;
      i++;
      continue;
    }

    if (in_single_quotes) {
      i++;
      continue;
    }

    // Handle double quotes - variables expand, globs don't
    if (c == '"' && !in_single_quotes) {
      in_double_quotes = !in_double_quotes;
      i++;
      continue;
    }

    // Backslash-LF is lexically removed. Otherwise skip exactly the quoted
    // byte, leaving a following LF to be recognized as source syntax.
    if (c == '\\' && i + 1 < len) {
      size_t continued = shell_source_skip_escaped_line_endings(p, len, i);
      i = (uint32_t)(continued != i ? continued : i + 2);
      continue;
    }

    if (c == '$' && shell_source_logical_next_is(p, len, i, '{', NULL)) {
      size_t after = 0;
      if (shell_source_skip_parameter_expansion(p, len, i, &after)) {
        detect_parameter_features(p, i, after, in_double_quotes, features);
        size_t subscript_start = 0, subscript_after = 0;
        if (shell_source_find_parameter_array_subscript(
                p, len, i, &subscript_after, &subscript_start))
          *features |= SHELL_FEAT_ARRAY;
        i = (uint32_t)after;
        continue;
      }
    }

    // Arithmetic expansions are opaque source units. Recurse into their
    // physical content range so a continuation inside either opener cannot
    // turn the following `(` into an ordinary command group.
    if (c == '$' && shell_source_dollar_arithmetic_open(p, len, i, NULL)) {
      *features |= SHELL_FEAT_ARITH;
      size_t content_start = 0, content_length = 0, arithmetic_after = 0;
      if (shell_source_arithmetic_content(p, len, i, &content_start,
                                          &content_length, &arithmetic_after)) {
        bool has_array = shell_tokenizer_arithmetic_has_array_semantics(
            p + content_start, content_length);
        if (has_array)
          *features |= SHELL_FEAT_ARRAY;
        size_t first = content_start;
        size_t content_end = content_start + content_length;
        while (first < content_end) {
          size_t continued =
              shell_source_skip_escaped_line_endings(p, content_end, first);
          if (continued != first) {
            first = continued;
            continue;
          }
          if (!shell_source_space((unsigned char)p[first]))
            break;
          first++;
        }
        if (!has_array && first < content_end &&
            (shell_ascii_alpha((unsigned char)p[first]) || p[first] == '_'))
          *features |= SHELL_FEAT_VARS;
        if (content_length != 0)
          detect_arithmetic_features(p, content_start,
                                     content_start + content_length, features);
        i = (uint32_t)arithmetic_after;
        continue;
      }
      /* Leave malformed arithmetic to the structural parser. */
      i++;
      continue;
    }
    if (in_double_quotes && (c == '$' || c == '`')) {
      bool recognized = false;
      size_t after = 0;
      if (shell_source_skip_double_quote_expansion(p, len, i, &recognized,
                                                   &after) &&
          recognized) {
        size_t content_start = i + 1;
        if (c == '`') {
          *features |= SHELL_FEAT_SUBSHELL;
        } else if (shell_source_logical_next_is(p, len, i, '{', NULL)) {
          *features |= SHELL_FEAT_VARS;
          /* Revisit the parameter as its own unquoted syntactic scope. This
           * preserves array-subscript detection as well as nested features,
           * without letting its quotes alter the enclosing quote state. */
          detect_features(p, i, (uint32_t)(after - i), features, true,
                          FAST_FEATURE_WORD);
          i = (uint32_t)after;
          continue;
        } else {
          *features |= SHELL_FEAT_SUBSHELL;
          content_start = shell_source_logical_following(p, len, i) + 1;
          detect_file_substitution_feature(p, after - 1, content_start,
                                           features);
        }
        if (after > content_start + 1)
          detect_features(p, (uint32_t)content_start,
                          (uint32_t)(after - content_start - 1), features, true,
                          FAST_FEATURE_COMMAND_BODY);
        i = (uint32_t)after;
        continue;
      }
    }
    // Grammar-only syntax is literal inside double quotes. Parameter, command,
    // and arithmetic expansions below intentionally remain visible there.
    if (!in_double_quotes && shell_identifier_start(c)) {
      size_t after = 0, subscript_start = 0, subscript_after = 0;
      size_t value_start = 0, value_after = 0;
      /* Probe assignment syntax only at a lexical assignment start, never at
       * every suffix of a long identifier. The context advances monotonically.
       */
      if (have_array_context && fast_array_assignment_at(&array_context, i) &&
          skip_array_assignment(p, len, i, &after, &subscript_start,
                                &subscript_after, &value_start, &value_after)) {
        *features |= SHELL_FEAT_ARRAY;
        if (subscript_after > subscript_start + 1)
          detect_features(p, (uint32_t)subscript_start + 1,
                          (uint32_t)(subscript_after - subscript_start - 2),
                          features, true, FAST_FEATURE_WORD);
        if (value_after > value_start)
          detect_features(p, (uint32_t)value_start,
                          (uint32_t)(value_after - value_start), features, true,
                          FAST_FEATURE_WORD);
        i = (uint32_t)after;
        continue;
      }
    }
    size_t combined_redirect = 0;
    if (!in_double_quotes && c == '&' &&
        shell_source_logical_next_is(p, len, i, '>', &combined_redirect)) {
      *features |= SHELL_FEAT_COMBINED_REDIRECT;
      size_t after = combined_redirect + 1;
      size_t append = 0;
      if (shell_source_logical_next_is(p, len, combined_redirect, '>', &append))
        after = append + 1;
      i = (uint32_t)after;
      continue;
    }
    if (!in_double_quotes && c == '$' &&
        shell_source_logical_next_is(p, len, i, '\'', NULL)) {
      *features |= SHELL_FEAT_ANSI_C_QUOTE;
      size_t after = 0;
      if (shell_source_skip_complete_ansi_c_quote(p, len, i, &after)) {
        i = (uint32_t)after;
        continue;
      }
    }
    if (!in_double_quotes &&
        (c == '?' || c == '*' || c == '+' || c == '@' || c == '!')) {
      size_t extglob_after = 0;
      if (shell_source_skip_extglob(p, len, i, &extglob_after)) {
        *features |= SHELL_FEAT_EXTGLOB;
        /* Pattern punctuation is literal here; active expansions still run.
         * Their executable children establish independent command contexts. */
        detect_expansion_features(p + i, extglob_after - i, false, false,
                                  features, false);
        i = (uint32_t)extglob_after;
        continue;
      }
    }
    if (!in_double_quotes && c == '{') {
      size_t operator_position = 0;
      if (have_array_context && fast_lexical_token_at(&array_context, i) &&
          fast_token_is_redirection(&array_context.token) &&
          shell_source_parse_named_fd_redirect_at_word_start(
              p, i, len, &operator_position))
        *features |= SHELL_FEAT_NAMED_FD;
    }
    size_t process_open = 0;
    if (!in_double_quotes && (c == '<' || c == '>') &&
        shell_source_process_substitution_open(p, len, i, &process_open)) {
      *features |= SHELL_FEAT_PROCESS_SUB;
      size_t after = 0;
      if (shell_source_find_balanced_parentheses(p, len, process_open,
                                                 &after)) {
        if (after > process_open + 1)
          detect_features(p, (uint32_t)process_open + 1,
                          (uint32_t)(after - process_open - 2), features, true,
                          FAST_FEATURE_COMMAND_BODY);
        i = (uint32_t)after;
        continue;
      }
      /* Syntax validation owns the incomplete opener. Feature discovery must
       * still advance past it instead of retrying the same `<(` or `>(`
       * indefinitely on diagnostic input. */
      i = (uint32_t)process_open + 1;
      continue;
    }
    bool arithmetic_paren =
        i > 1 && p[i - 1] == '(' && (p[i - 2] == '$' || p[i - 2] == '(');
    if (!in_double_quotes && c == '(' && !arithmetic_paren &&
        !(i > 0 && (p[i - 1] == '$' || p[i - 1] == '<' || p[i - 1] == '>')))
      *features |= SHELL_FEAT_GROUP;
    switch (c) {
    case '$':
      // Variables expand in double quotes
      {
        size_t next_position = shell_source_logical_following(p, len, i);
        if (next_position < len) {
          char next = p[next_position];
          if (next == '(') {
            if (shell_source_dollar_arithmetic_open(p, len, i, NULL)) {
              // This is handled by the arithmetic-expansion branch above.
              continue;
            }
            *features |= SHELL_FEAT_SUBSHELL;
            size_t after = 0;
            if (shell_source_find_balanced_parentheses(p, len, next_position,
                                                       &after)) {
              detect_file_substitution_feature(p, after - 1, next_position + 1,
                                               features);
              if (after > next_position + 1)
                detect_features(p, (uint32_t)next_position + 1,
                                (uint32_t)(after - next_position - 2), features,
                                true, FAST_FEATURE_COMMAND_BODY);
              i = (uint32_t)after;
              continue;
            }
          } else if (next == '`') {
            *features |= SHELL_FEAT_SUBSHELL;
          } else if (next == '{') {
            *features |= SHELL_FEAT_VARS;
            size_t after = 0, subscript_start = 0;
            if (shell_source_find_parameter_array_subscript(p, len, i, &after,
                                                            &subscript_start)) {
              *features |= SHELL_FEAT_ARRAY;
              if (after > subscript_start + 1)
                detect_features(p, (uint32_t)subscript_start + 1,
                                (uint32_t)(after - subscript_start - 2),
                                features, true, FAST_FEATURE_WORD);
              i = (uint32_t)after;
              continue;
            }
          } else if (shell_ascii_digit((unsigned char)next) || next == '#' ||
                     next == '?' || next == '$' || next == '!' || next == '@' ||
                     next == '*' || next == '-') {
            *features |= SHELL_FEAT_VARS;
          } else if (shell_ascii_alpha((unsigned char)next) || next == '_') {
            *features |= SHELL_FEAT_VARS;
          }
        }
      }
      break;
    case '`':
      *features |= SHELL_FEAT_SUBSHELL;
      {
        size_t after = 0;
        if (shell_source_skip_complete_backtick(p, len, i, &after)) {
          if (after > i + 2)
            detect_features(p, i + 1, (uint32_t)(after - i - 2), features, true,
                            FAST_FEATURE_COMMAND_BODY);
          i = (uint32_t)after;
          continue;
        }
      }
      break;
    case '&':
      if (!in_double_quotes && !(i + 1 < len && p[i + 1] == '&') &&
          !(i > 0 && (p[i - 1] == '<' || p[i - 1] == '>')))
        *features |= SHELL_FEAT_BACKGROUND;
      break;
    case '*':
    case '?':
      // Globs do NOT expand in double quotes
      if (!in_double_quotes && context != FAST_FEATURE_CONDITIONAL_WORD) {
        *features |= SHELL_FEAT_GLOBS;
      }
      break;
    case '[':
      // Globs do NOT expand in double quotes, and not in heredoc context
      if (!in_double_quotes && context != FAST_FEATURE_CONDITIONAL_WORD &&
          !(i > 0 && p[i - 1] == '<')) {
        *features |= SHELL_FEAT_GLOBS;
      }
      break;
    default:
      break;
    }

    i++;
  }
  if (context == FAST_FEATURE_COMMAND_BODY)
    detect_control_features(cmd, start, len, features);
  shell_source_scope_end(previous);
  nesting--;
}

/* The forward lexer supplies one complete logical word and its operand role.
 * Its keyword's feature bits are shared with the other frontend projections. */
static SHELL_NONNULL(1, 4) void detect_control_word(const char *input,
                                                    size_t start, size_t end,
                                                    uint32_t *features) {
  const shell_keyword_t *keyword =
      shell_source_keyword(input, end, start, NULL);
  if (keyword)
    *features |= keyword->features;
}

/* Each command body's lexer supplies words, operators, comments and deferred
 * document boundaries once. Redirect operands are data. Executable children
 * receive their own command-body feature walk through expansion discovery;
 * this pass never scans an enclosing word's substitution body again. Flags
 * remain lexical word recognition, not a complete control-flow grammar. */
static SHELL_NONNULL(1, 4) void detect_control_features(const char *cmd,
                                                        uint32_t start,
                                                        uint32_t len,
                                                        uint32_t *features) {
  const char *input = cmd + start;
  shell_tokenizer_state_t state;
  shell_tokenizer_init_prechecked(&state, input, len);
  size_t word_start = SIZE_MAX, word_end = 0;
  bool redirect_operand = false, word_data = false;
  shell_token_t token;
  while (shell_tokenizer_next(&state, &token)) {
    if (shell_source_is_escaped_line_ending(input, token.position,
                                            token.position + token.length))
      continue;
    bool redirect = shell_token_type_is_redirection(token.type);
    bool boundary = redirect;
    switch (token.type) {
    case SHELL_TOKEN_PIPE:
    case SHELL_TOKEN_PIPE_BOTH:
    case SHELL_TOKEN_SEMICOLON:
    case SHELL_TOKEN_AND:
    case SHELL_TOKEN_OR:
    case SHELL_TOKEN_BACKGROUND:
    case SHELL_TOKEN_SUBSHELL_START:
    case SHELL_TOKEN_SUBSHELL_END:
    case SHELL_TOKEN_GROUP_START:
    case SHELL_TOKEN_GROUP_END:
    case SHELL_TOKEN_CASE_TERMINATE:
    case SHELL_TOKEN_CASE_FALLTHROUGH:
    case SHELL_TOKEN_CASE_TEST_NEXT:
      boundary = true;
      break;
    default:
      break;
    }
    bool continues = !boundary && word_start != SIZE_MAX &&
                     shell_tokenizer_token_continues_word(&token, word_end);
    if (word_start != SIZE_MAX && !continues) {
      if (!word_data)
        detect_control_word(input, word_start, word_end, features);
      word_start = SIZE_MAX;
    }
    if (boundary) {
      redirect_operand =
          redirect && token.type != SHELL_TOKEN_HEREDOC &&
          shell_source_redirection_consumes_word(token.start, token.length);
      continue;
    }
    if (word_start == SIZE_MAX) {
      word_start = token.position;
      word_data = redirect_operand;
      redirect_operand = false;
    }
    word_end = token.position + token.length;
  }
  if (word_start != SIZE_MAX && !word_data)
    detect_control_word(input, word_start, word_end, features);
}

/* Deferred bodies and declaration operators have the same source order.
 * Merge only into retained declaration ranges, in one monotonic sweep; a
 * truncated parse need not have retained a later document's declaration. */
static SHELL_NONNULL(1, 2) void merge_heredoc_features(
    shell_parse_result_t *result, const heredoc_body_span_t *bodies,
    uint32_t body_count) {
  uint32_t range = 0;
  for (uint32_t h = 0; h < body_count; h++) {
    uint32_t position = bodies[h].operator_position;
    while (range < result->count &&
           result->cmds[range].start + result->cmds[range].len <= position)
      range++;
    if (range == result->count)
      break;
    if (result->cmds[range].start <= position)
      result->cmds[range].features |= bodies[h].features;
  }
}

/* Complete metadata that depends on the full set of recorded ranges. This is
 * also used on truncation so retained ranges have the same metadata as they
 * would in an otherwise identical complete parse. */
static void normalize_result_metadata(const char *cmd, size_t cmd_len,
                                      shell_parse_result_t *result) {
  for (uint32_t i = 0; i < result->count; i++) {
    shell_tokenizer_state_t lexer;
    shell_tokenizer_init_prechecked(&lexer, cmd + result->cmds[i].start,
                                    result->cmds[i].len);
    shell_token_t token;
    if (shell_tokenizer_next(&lexer, &token) &&
        token.type == SHELL_TOKEN_ARITHMETIC_COMMAND) {
      result->cmds[i].kind = SHELL_COMMAND_ARITHMETIC;
      result->cmds[i].features |= SHELL_FEAT_ARITH;
    }
    if (token.type == SHELL_TOKEN_CONDITIONAL_COMMAND) {
      result->cmds[i].kind = SHELL_COMMAND_CONDITIONAL;
      result->cmds[i].features |= SHELL_FEAT_CONDITIONALS;
    }
    if (result->cmds[i].type == SHELL_TYPE_SIMPLE &&
        (result->cmds[i].features & SHELL_FEAT_SUBSHELL)) {
      result->cmds[i].type = SHELL_TYPE_SUBSTITUTION;
    }
    if (result->cmds[i].type == SHELL_TYPE_PIPELINE &&
        result->cmds[i].pipe_input_mode == SHELL_PIPE_MODE_NONE)
      result->cmds[i].pipe_input_mode = SHELL_PIPE_MODE_STDOUT;
  }

  shell_execution_map_t execution;
  shell_execution_map_build(cmd, cmd_len, result, &execution);
  for (uint32_t i = 0; i < result->count; i++) {
    if (result->cmds[i].group_depth > 0)
      result->cmds[i].features |= SHELL_FEAT_GROUP;
    if (result->cmds[i].pipe_input_mode != SHELL_PIPE_MODE_NONE)
      result->cmds[i].features |= SHELL_FEAT_PIPELINE;
    if (execution.owner[i] == i && execution.stage[i]) {
      uint32_t cursor = i + 1;
      uint32_t end = execution.end[i];
      shell_pipeline_stage_t stage;
      if (shell_pipeline_next(
              cmd, cmd_len, result, &execution.pipeline,
              shell_pipeline_range_limit(result, &execution.pipeline, i),
              &cursor, &end, &stage)) {
        result->cmds[i].features |= SHELL_FEAT_PIPELINE;
        result->cmds[stage.range].features |= SHELL_FEAT_PIPELINE;
      }
    }
    if (result->cmds[i].type == SHELL_TYPE_BACKGROUND && i > 0)
      result->cmds[i - 1].features |= SHELL_FEAT_BACKGROUND;
  }
  for (uint32_t root = 0; root < result->count; root++) {
    if (execution.owner[root] != root || !execution.stage[root])
      continue;
    bool backgrounded = shell_execution_backgrounded(result, &execution, root);
    for (uint32_t member = root;
         member < result->count && execution.owner[member] == root; member++) {
      result->cmds[member].features |=
          result->cmds[root].features & SHELL_FEAT_PIPELINE;
      if (backgrounded)
        result->cmds[member].features |= SHELL_FEAT_BACKGROUND;
    }
  }
}

/* A flattened range that begins a compound can represent that compound as an
 * outer pipeline member. The prebuilt index selects its outermost descriptor,
 * so modifier metadata belongs to the GROUP rather than its first inner word.
 */
static void apply_pipeline_modifiers(shell_parse_result_t *result,
                                     const shell_pipeline_index_t *index,
                                     uint32_t range_index,
                                     uint32_t negation_count,
                                     shell_pipeline_time_mode_t time_mode) {
  const shell_group_t *opening =
      shell_pipeline_group_at(result, index, range_index);
  shell_group_t *group =
      opening ? &result->groups[opening - result->groups] : NULL;
  if (group &&
      result->cmds[range_index].pipe_input_mode != SHELL_PIPE_MODE_NONE) {
    if (negation_count != 0) {
      group->modifiers |= SHELL_CMD_MOD_PIPE_NEGATED;
      group->pipeline_negation_count = negation_count;
    }
    if (time_mode != SHELL_PIPE_TIME_NONE) {
      group->modifiers |= SHELL_CMD_MOD_PIPE_TIMED;
      group->pipeline_time_mode = (uint8_t)time_mode;
    }
    return;
  }

  shell_range_t *range = &result->cmds[range_index];
  if (negation_count != 0) {
    range->modifiers |= SHELL_CMD_MOD_PIPE_NEGATED;
    range->pipeline_negation_count = negation_count;
  }
  if (time_mode != SHELL_PIPE_TIME_NONE) {
    range->modifiers |= SHELL_CMD_MOD_PIPE_TIMED;
    range->pipeline_time_mode = (uint8_t)time_mode;
  }
}

/* Propagate one outer pipeline's modifiers through flattened ranges. A
 * compound member owns all of its enclosed ranges and any trailing redirect
 * list, so jump over that complete member before looking for the next pipe
 * stage. */
static void propagate_pipeline_modifiers(const char *cmd, size_t cmd_len,
                                         shell_parse_result_t *result,
                                         const shell_pipeline_index_t *index,
                                         uint32_t member, uint32_t member_limit,
                                         uint32_t end, uint32_t negation_count,
                                         shell_pipeline_time_mode_t time_mode) {
  shell_pipeline_stage_t stage;
  while (shell_pipeline_next(cmd, cmd_len, result, index, member_limit, &member,
                             &end, &stage))
    apply_pipeline_modifiers(result, index, stage.range, negation_count,
                             time_mode);
}

/* `!` is a reserved pipeline modifier, not an executable command word. The
 * range tokenizer keeps it inside the first range so it never becomes a
 * generic separator; remove that prefix here and attach one explicit modifier
 * to every range in the syntactic pipeline. */
static bool normalize_pipeline_modifiers(const char *cmd, size_t cmd_len,
                                         shell_parse_result_t *result) {
  /* Inline documents split one simple command into several lexical ranges.
   * Build stage ownership before stripping any modifier-looking words: `time`
   * and `!` after a leading << / <<< redirect are ordinary command words, and
   * removing them here would make the later ownership pass see a phantom
   * command boundary. */
  shell_execution_map_t execution;
  shell_execution_map_build(cmd, cmd_len, result, &execution);

  /* Redirect-only stages have no word range from which to strip `!`.  The
   * marker records the modifier directly; propagate it through its pipeline
   * just as a word-bearing first stage would. */
  for (uint32_t i = 0; i < result->count; i++) {
    shell_range_t *first = &result->cmds[i];
    if ((first->modifiers &
         (SHELL_CMD_MOD_PIPE_NEGATED | SHELL_CMD_MOD_PIPE_TIMED)) == 0)
      continue;
    if ((first->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0 &&
        first->pipeline_negation_count == 0)
      return false;
    if (i != 0 && first->type == SHELL_TYPE_PIPELINE)
      continue;
    propagate_pipeline_modifiers(
        cmd, cmd_len, result, &execution.pipeline, i + 1,
        shell_pipeline_range_limit(result, &execution.pipeline, i),
        first->start + first->len,
        (first->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0
            ? first->pipeline_negation_count
            : 0,
        (first->modifiers & SHELL_CMD_MOD_PIPE_TIMED) != 0
            ? (shell_pipeline_time_mode_t)first->pipeline_time_mode
            : SHELL_PIPE_TIME_NONE);
  }
  for (uint32_t i = 0; i < result->count; i++) {
    shell_range_t *first = &result->cmds[i];
    if (execution.owner[i] != i)
      continue;
    uint32_t offset = 0;
    while (offset < first->len &&
           shell_source_space((unsigned char)cmd[first->start + offset]))
      offset++;
    if (offset >= first->len)
      continue;
    uint32_t range_end = first->start + first->len;
    uint32_t stage_end = execution.end[i];
    shell_source_pipeline_prefix_t prefix = shell_source_parse_pipeline_prefix(
        cmd, first->start + offset, stage_end);
    uint32_t stage_start = (uint32_t)prefix.stage_start;
    if (!prefix.valid)
      return false;
    if (!prefix.has_modifier) {
      /* `!literal` is an ordinary command word, while a delimited but
       * incomplete negator is malformed source. */
      if (cmd[first->start + offset] == '!' &&
          (first->start + offset + 1 == range_end ||
           shell_source_space((unsigned char)cmd[first->start + offset + 1])))
        return false;
      continue;
    }
    /* Reserved modifiers begin a pipeline, never a later stage. `cmd | ! x`
     * and `cmd | time x` execute no supported modifier in that position. */
    bool begins_compound_member =
        shell_pipeline_group_at(result, &execution.pipeline, i) != NULL;
    if (i != 0 && first->type == SHELL_TYPE_PIPELINE &&
        !begins_compound_member) {
      if (prefix.time_mode != SHELL_PIPE_TIME_NONE)
        continue;
      return false;
    }
    if (stage_start == stage_end && prefix.ends_with_negator &&
        prefix.time_mode == SHELL_PIPE_TIME_NONE)
      return false;
    /* Preserve a nonempty source span for Bash's valid empty timed pipeline.
     * The allocating processor will retain its syntax tokens and zero argv. */
    if (stage_start != stage_end) {
      /* Document prefixes are attached to their document by the scanner.
       * Never reinterpret a prefix-only fragment as empty timing merely
       * because its execution stage continues in another lexical range. */
      if (stage_start >= range_end)
        return false;
      first->len = range_end - stage_start;
      first->start = stage_start;
    }
    if (prefix.negation_count != 0) {
      first->modifiers |= SHELL_CMD_MOD_PIPE_NEGATED;
      first->pipeline_negation_count = prefix.negation_count;
    }
    if (prefix.time_mode != SHELL_PIPE_TIME_NONE) {
      first->modifiers |= SHELL_CMD_MOD_PIPE_TIMED;
      first->pipeline_time_mode = (uint8_t)prefix.time_mode;
      first->pipeline_time_direct = true;
    }
    uint32_t member_limit =
        shell_pipeline_range_limit(result, &execution.pipeline, i);
    propagate_pipeline_modifiers(cmd, cmd_len, result, &execution.pipeline,
                                 i + 1, member_limit, first->start + first->len,
                                 prefix.negation_count, prefix.time_mode);
  }

  /* A group opener removes its delimiter and prefix from the inner command
   * range, so `! { list; } | cmd` has no range beginning with `!`. Retain the
   * modifier on the GROUP descriptor and apply it to later pipe stages. */
  for (uint32_t group_index = 0; group_index < result->group_count;
       group_index++) {
    shell_group_t *group = &result->groups[group_index];
    if ((group->modifiers &
         (SHELL_CMD_MOD_PIPE_NEGATED | SHELL_CMD_MOD_PIPE_TIMED)) == 0)
      continue;
    if ((group->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0 &&
        group->pipeline_negation_count == 0)
      group->pipeline_negation_count = 1;
    uint32_t member_limit = result->count;
    if (group->parent != UINT16_MAX && group->parent < result->group_count) {
      const shell_group_t *parent = &result->groups[group->parent];
      member_limit = (uint32_t)parent->first_command + parent->command_count;
    }
    propagate_pipeline_modifiers(
        cmd, cmd_len, result, &execution.pipeline,
        (uint32_t)group->first_command + group->command_count, member_limit,
        group->end,
        (group->modifiers & SHELL_CMD_MOD_PIPE_NEGATED) != 0
            ? group->pipeline_negation_count
            : 0,
        (group->modifiers & SHELL_CMD_MOD_PIPE_TIMED) != 0
            ? (shell_pipeline_time_mode_t)group->pipeline_time_mode
            : SHELL_PIPE_TIME_NONE);
  }
  return true;
}

/* Comment scanning records the first comment that belongs to the current
 * candidate subcommand. A comment may begin at that range's first byte (for
 * example after a newline or semicolon), in which case it contributes no
 * executable range. Keep every emission path on the same boundary rule so
 * feature detection never sees comment text as shell syntax. */
static uint32_t range_end_before_comment(uint32_t start, uint32_t end,
                                         uint32_t comment_start) {
  return comment_start != UINT32_MAX && comment_start >= start &&
                 comment_start < end
             ? comment_start
             : end;
}

/**
 * Fast shell command parser - zero-copy, bounded
 */
static shell_error_t shell_parse_fast_impl(const char *cmd, size_t cmd_len,
                                           const shell_limits_t *limits,
                                           shell_parse_result_t *result,
                                           bool prevalidated) {
  // Validate inputs

  /* Ranges store byte offsets in uint32_t, so larger inputs are not
   * representable by this API.  Reject before any traversal can narrow a
   * position or range length. */
  if (cmd_len > UINT32_MAX) {
    result->count = 0;
    result->status = SHELL_STATUS_ERROR;
    return SHELL_EINPUT;
  }

  if (cmd_len == 0) {
    result->count = 0;
    result->status = SHELL_STATUS_ERROR;
    return SHELL_EINPUT;
  }

  // Use default limits if not provided
  shell_limits_t local_limits;
  if (!limits) {
    local_limits = SHELL_LIMITS_DEFAULT;
    limits = &local_limits;
  }

  // Initialize result
  memset(result, 0, sizeof(shell_parse_result_t));

  /* Whole-source syntax validation owns the byte-domain check as well. It
   * checks every byte before any lexical path can skip or reinterpret it,
   * and before bounded range/group collection can stop. A malformed suffix
   * must never become a valid truncated prefix. Nested consumers reuse the
   * established byte-domain guarantee within this source operation. */
  if (!prevalidated &&
      !(limits->strict_mode
            ? shell_tokenizer_complete_syntax_valid(cmd, cmd_len)
            : shell_tokenizer_list_syntax_valid(cmd, cmd_len))) {
    result->status = SHELL_STATUS_ERROR;
    return SHELL_EPARSE;
  }

  /* The fast parser preserves lexical ranges for control compounds so the
   * higher-level semantic boundary can report them as unsupported syntax.
   * In particular, a `case` pattern closes with `)`, which is not a subshell
   * delimiter. Do not mistake that token for an unmatched parenthesized
   * group while scanning a source that the control classifier already owns. */
  bool has_unsupported_control =
      !prevalidated && shell_tokenizer_has_unsupported_control(cmd, cmd_len);

  uint32_t max_cmds = limits->max_subcommands;
  if (max_cmds > SHELL_MAX_SUBCOMMANDS) {
    max_cmds = SHELL_MAX_SUBCOMMANDS;
  }

  heredoc_body_span_t heredoc_bodies[SHELL_MAX_SUBCOMMANDS];
  uint32_t heredoc_body_count = 0;
  if (!collect_heredoc_body_spans(cmd, (uint32_t)cmd_len, heredoc_bodies,
                                  SHELL_MAX_SUBCOMMANDS, &heredoc_body_count))
    heredoc_body_count = 0;
  uint32_t next_heredoc_body = 0;
  fast_array_context_t documents = {
      .prefix = shell_pipeline_prefix_state_initial(true),
      .command_start = true,
      .prefix_open = true,
  };
  shell_tokenizer_init_prechecked(&documents.state, cmd, cmd_len);

  // Helper to trim outer whitespace and emit one parsed subcommand record.
#define RECORD_SUBCMD(s, e, type_val)                                          \
  do {                                                                         \
    uint32_t _s = (s);                                                         \
    uint32_t _e = range_end_before_comment(_s, (e), comment_start);            \
    _s = fast_range_trim_start(cmd, _s, _e);                                   \
    _e = fast_range_trim_end(cmd, _s, _e);                                     \
    if (_s < _e && subcmd_idx < max_cmds) {                                    \
      result->cmds[subcmd_idx].start = _s;                                     \
      result->cmds[subcmd_idx].len = _e - _s;                                  \
      result->cmds[subcmd_idx].type = (type_val);                              \
      result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;      \
      result->cmds[subcmd_idx].features = 0;                                   \
      result->cmds[subcmd_idx].group_depth = group_depth;                      \
      result->cmds[subcmd_idx].group_kinds = group_kinds;                      \
      detect_features(cmd, _s, _e - _s, &result->cmds[subcmd_idx].features,    \
                      execution_pipeline_start, FAST_FEATURE_COMMAND_BODY);    \
      subcmd_idx++;                                                            \
    } else if (_s < _e && subcmd_idx >= max_cmds) {                            \
      result->status = SHELL_STATUS_TRUNCATED;                                 \
      result->count = subcmd_idx;                                              \
      goto truncated;                                                          \
    }                                                                          \
  } while (0)

#define OPEN_GROUP(kind_val, start_val, modifiers_val, negation_count_val,     \
                   time_mode_val)                                              \
  do {                                                                         \
    if (result->group_count >= SHELL_MAX_GROUPS ||                             \
        group_descriptor_depth >= SHELL_MAX_GROUPS) {                          \
      result->status = SHELL_STATUS_TRUNCATED;                                 \
      result->count = subcmd_idx;                                              \
      goto truncated;                                                          \
    }                                                                          \
    shell_group_t *_group = &result->groups[result->group_count];              \
    _group->start = (start_val);                                               \
    _group->end = 0;                                                           \
    _group->first_command = (uint16_t)subcmd_idx;                              \
    _group->command_count = 0;                                                 \
    _group->parent = group_descriptor_depth                                    \
                         ? group_descriptor_stack[group_descriptor_depth - 1]  \
                         : UINT16_MAX;                                         \
    _group->kind = (kind_val);                                                 \
    _group->modifiers = (modifiers_val);                                       \
    _group->pipeline_negation_count = (negation_count_val);                    \
    _group->pipeline_time_mode = (uint8_t)(time_mode_val);                     \
    _group->pipeline_time_direct = (time_mode_val) != SHELL_PIPE_TIME_NONE;    \
    group_descriptor_stack[group_descriptor_depth++] =                         \
        (uint16_t)result->group_count++;                                       \
  } while (0)

#define CLOSE_GROUP(kind_val, end_val)                                         \
  do {                                                                         \
    if (group_descriptor_depth == 0 ||                                         \
        result->groups[group_descriptor_stack[group_descriptor_depth - 1]]     \
                .kind != (kind_val)) {                                         \
      result->status = SHELL_STATUS_ERROR;                                     \
      result->count = subcmd_idx;                                              \
      return SHELL_EPARSE;                                                     \
    }                                                                          \
    shell_group_t *_group =                                                    \
        &result->groups[group_descriptor_stack[--group_descriptor_depth]];     \
    _group->end = (end_val);                                                   \
    _group->command_count = (uint16_t)(subcmd_idx - _group->first_command);    \
  } while (0)

  uint32_t pos = 0;
  uint32_t subcmd_start = 0;
  /* Emitted fragments are not stage boundaries. Keep their grammar context
   * across inline documents; prefix facts come from the forward iterator. */
  bool execution_pipeline_start = true;
  uint32_t subcmd_idx = 0;
  uint16_t current_type = SHELL_TYPE_SIMPLE;
  uint8_t current_pipe_input_mode = SHELL_PIPE_MODE_NONE;
  uint16_t group_depth = 0;
  uint8_t group_kinds = SHELL_GROUP_NONE;
  uint16_t brace_group_depth = 0;
  uint8_t brace_group_stack[SHELL_MAX_SUBCOMMANDS];
  uint16_t brace_group_stack_depth = 0;
  uint16_t group_descriptor_stack[SHELL_MAX_GROUPS];
  uint16_t group_descriptor_depth = 0;
  uint32_t comment_start = UINT32_MAX;
  bool in_quotes = false;
  char quote_char = 0;
  int brace_depth = 0;
  int brace_start_pos = -1;
  uint32_t last_closed_group_end = UINT32_MAX;
  uint32_t function_paren_close = UINT32_MAX;
  uint32_t heredoc_prefix_start = UINT32_MAX;
  int paren_depth = 0;              // Track all non-arithmetic parentheses
  int group_paren_depth = 0;        // Track ordinary parenthesized groups
  int substitution_paren_depth = 0; // $(), <(), and >() delimiters
  int arith_depth = 0;              // Track when inside $((...))

  // Scan the command one byte at a time, maintaining quote and feature state.
  while (pos < cmd_len) {
    shell_source_scope_frontier(cmd, pos);
    while (next_heredoc_body < heredoc_body_count &&
           pos >= heredoc_bodies[next_heredoc_body].end)
      next_heredoc_body++;
    if (next_heredoc_body < heredoc_body_count &&
        pos >= heredoc_bodies[next_heredoc_body].start) {
      pos = heredoc_bodies[next_heredoc_body].end;
      subcmd_start = pos;
      execution_pipeline_start = true;
      comment_start = UINT32_MAX;
      continue;
    }
    char c = cmd[pos];
    if (!in_quotes && (c == '(' || c == '[') &&
        fast_lexical_token_at(&documents, pos) &&
        (documents.token.type == SHELL_TOKEN_ARITHMETIC_COMMAND ||
         documents.token.type == SHELL_TOKEN_CONDITIONAL_COMMAND)) {
      pos = (uint32_t)(documents.token.position + documents.token.length);
      continue;
    }
    /* The forward lexer has already established assignment eligibility and
     * its exact prefix span. Subscript operators and parentheses belong to
     * that word, not this enclosing command list. Reuse the token boundary;
     * feature collection inspects the subscript separately. */
    if (!in_quotes && shell_identifier_start(c) &&
        fast_array_assignment_at(&documents, pos)) {
      pos = (uint32_t)(documents.token.position + documents.token.length);
      continue;
    }
    /* A nested expansion owns its quotes even inside an outer double-quoted
     * word. Consume its whole span before the outer quote state sees any
     * delimiter or command-list operator from its body. */
    if (in_quotes && quote_char == '"' && (c == '$' || c == '`')) {
      size_t after = 0;
      bool recognized = false;
      bool complete = shell_source_skip_double_quote_expansion(
          cmd, cmd_len, pos, &recognized, &after);
      if (recognized) {
        if ((!complete && (c != '`' || limits->strict_mode)) ||
            (complete && after > UINT32_MAX)) {
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        pos = complete ? (uint32_t)after : cmd_len;
        continue;
      }
    }
    /* ANSI-C quoting is one shell-word fragment, even when its body contains
     * escaped quotes or delimiter-looking bytes. Consume it before generic
     * quote and delimiter handling so it remains opaque to this structural
     * parser. */
    if (!in_quotes && c == '$' &&
        shell_source_logical_next_is(cmd, cmd_len, pos, '\'', NULL)) {
      size_t after = 0;
      if (!shell_source_skip_complete_ansi_c_quote(cmd, cmd_len, pos, &after) ||
          after > UINT32_MAX) {
        if (limits->strict_mode) {
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
      } else {
        pos = (uint32_t)after;
        continue;
      }
    }
    /* A balanced parameter expansion is one shell-word fragment. Its default,
     * pattern, or replacement word may contain bytes that are operators at
     * the enclosing command-list level. */
    if (!in_quotes && c == '$') {
      size_t next =
          shell_source_skip_escaped_line_endings(cmd, cmd_len, pos + 1);
      if (next < cmd_len && cmd[next] == '{') {
        size_t after = 0;
        if (!shell_source_skip_parameter_expansion(cmd, cmd_len, pos, &after) ||
            after > UINT32_MAX) {
          /* A braced parameter expansion is syntactically complete or it is
           * invalid source; permissive range recovery must not turn `${}` or an
           * unterminated expansion into an unrelated ordinary brace word. */
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        pos = (uint32_t)after;
        continue;
      }
    }
    /* Command substitutions are one shell-word component at this layer. The
     * shared scanner owns their matching parentheses and deferred heredoc
     * bodies, so syntax in the nested command cannot split the outer range.
     * Arithmetic expansion remains on its dedicated depth-tracking path. */
    size_t substitution_open = 0;
    if (!in_quotes && c == '$' &&
        shell_source_dollar_parentheses_open(cmd, cmd_len, pos,
                                             &substitution_open) &&
        !shell_source_dollar_arithmetic_open(cmd, cmd_len, pos, NULL)) {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(cmd, cmd_len,
                                                  substitution_open, &after) ||
          after > UINT32_MAX) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      pos = (uint32_t)after;
      continue;
    }
    /* Process substitutions have the same balanced command-list body as
     * `$()`, but their leading redirection byte can be separated from `(` by
     * an escaped physical line ending. Consume the whole source fragment here
     * rather than relying on the immediately preceding physical byte when the
     * opening parenthesis is reached. */
    if (!in_quotes && (c == '<' || c == '>') &&
        shell_source_process_substitution_open(cmd, cmd_len, pos,
                                               &substitution_open)) {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(cmd, cmd_len,
                                                  substitution_open, &after) ||
          after > UINT32_MAX) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      /* Retain the fast parser's historical eager attribution: once a list
       * connector has closed a preceding range, its following process
       * substitution is recorded on that emitted range. The final range is
       * still classified as a substitution below when it starts a command. */
      if (subcmd_idx > 0 && subcmd_idx < max_cmds)
        result->cmds[subcmd_idx - 1].features |= SHELL_FEAT_PROCESS_SUB;
      if (current_type == SHELL_TYPE_SIMPLE)
        current_type = SHELL_TYPE_SUBSTITUTION;
      pos = (uint32_t)after;
      continue;
    }
    /* This parser's established lexical dialect treats `\$(...)` as an
     * escaped literal word component. Keep the complete parenthesized suffix
     * opaque so strict group validation cannot reinterpret it as a subshell
     * command. */
    if (!in_quotes && c == '\\' && pos + 2 < cmd_len && cmd[pos + 1] == '$' &&
        cmd[pos + 2] == '(') {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(cmd, cmd_len, pos + 2,
                                                  &after) ||
          after > UINT32_MAX) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      pos = (uint32_t)after;
      continue;
    }
    if (!in_quotes && arith_depth == 0 && substitution_paren_depth == 0) {
      size_t after = 0;
      if (shell_source_skip_extglob(cmd, cmd_len, pos, &after) &&
          after <= UINT32_MAX) {
        pos = (uint32_t)after;
        continue;
      }
    }
    bool function_paren = c == '(' && pos + 1 < cmd_len &&
                          cmd[pos + 1] == ')' && pos > subcmd_start &&
                          pos > 0 &&
                          !shell_source_space((unsigned char)cmd[pos - 1]) &&
                          !is_separator(cmd[pos - 1]);
    bool closes_group = c == ')' && arith_depth == 0 &&
                        substitution_paren_depth == 0 && group_paren_depth > 0;
    bool closes_arithmetic = c == ')' && arith_depth > 0;
    bool closes_function_paren = c == ')' && pos == function_paren_close;
    bool inside_parameter_expansion = brace_depth > 0;

    /* POSIX brace groups use reserved words, not ordinary argv words. The
     * delimiters must be separated from their list by shell whitespace or an
     * operator. Parameter expansion braces remain handled below. */
    bool brace_open = c == '{' && !in_quotes && arith_depth == 0 &&
                      substitution_paren_depth == 0 &&
                      !inside_parameter_expansion &&
                      fast_lexical_token_at(&documents, pos) &&
                      documents.token.type == SHELL_TOKEN_GROUP_START;
    bool brace_close_redirect = false;
    if (c == '}' && pos + 1 < cmd_len &&
        shell_ascii_digit((unsigned char)cmd[pos + 1])) {
      size_t redirect = 0;
      uint32_t descriptor = 0;
      shell_source_io_number_t io_number = shell_source_parse_io_number(
          cmd, pos + 1, cmd_len, &redirect, &descriptor);
      brace_close_redirect = io_number == SHELL_SOURCE_IO_NUMBER_VALID &&
                             redirect < cmd_len &&
                             (cmd[redirect] == '<' || cmd[redirect] == '>');
    }
    bool brace_close =
        c == '}' && brace_depth == 0 && brace_group_depth > 0 &&
        (pos == 0 || shell_source_space((unsigned char)cmd[pos - 1]) ||
         cmd[pos - 1] == ';' || cmd[pos - 1] == '\n' || cmd[pos - 1] == ')') &&
        (pos + 1 == cmd_len ||
         shell_source_space((unsigned char)cmd[pos + 1]) ||
         is_separator(cmd[pos + 1]) || cmd[pos + 1] == ')' ||
         brace_close_redirect);
    /* One forward token stream supplies trivia and prefix facts. Neither a
     * literal brace nor a continuation may restart at the stage's source
     * origin: many literal braces after one long gap would be quadratic. */
    bool check_group_boundary =
        !in_quotes && arith_depth == 0 && substitution_paren_depth == 0 &&
        (brace_open || brace_close || c == '(' ||
         ((c == '{' || c == '}') &&
          (pos == 0 || shell_source_space((unsigned char)cmd[pos - 1]) ||
           is_separator(cmd[pos - 1]) || cmd[pos - 1] == ')') &&
          group_word_ends_here(cmd, pos, cmd_len)));
    bool delimiter_token =
        check_group_boundary && fast_lexical_token_at(&documents, pos);
    bool only_whitespace_before_delimiter =
        delimiter_token && documents.before_syntax_end <= subcmd_start;
    bool directly_after_closed_group =
        delimiter_token && last_closed_group_end != UINT32_MAX &&
        documents.before_syntax_end <= last_closed_group_end;
    /* Fragment emission does not reopen command grammar. The forward lexer
     * has already classified literal braces after a document as word data. */
    bool structural_delimiter =
        delimiter_token &&
        (documents.token.type == SHELL_TOKEN_GROUP_START ||
         documents.token.type == SHELL_TOKEN_GROUP_END ||
         documents.token.type == SHELL_TOKEN_SUBSHELL_START ||
         documents.token.type == SHELL_TOKEN_SUBSHELL_END);
    bool command_boundary =
        delimiter_token &&
        (structural_delimiter || documents.before_prefix_open) &&
        (only_whitespace_before_delimiter ||
         (execution_pipeline_start && documents.before_prefix_open)) &&
        !directly_after_closed_group;
    /* When a compound is itself a later pipeline member, its first inner
     * command shares the flattened PIPELINE range type used to connect the
     * outer source to the group. That inherited type must not make an inner
     * `time (...)` or `time {...}` look like forbidden post-pipe modifier
     * syntax. */
    bool inherited_group_pipeline =
        current_type == SHELL_TYPE_PIPELINE && group_descriptor_depth != 0 &&
        result->groups[group_descriptor_stack[group_descriptor_depth - 1]]
                .first_command == subcmd_idx;

    bool redirect_prefix =
        check_group_boundary && brace_open &&
        (shell_source_redirect_list_before_group(cmd, subcmd_start, pos) ||
         (heredoc_prefix_start != UINT32_MAX &&
          shell_source_redirect_list_before_group(cmd, heredoc_prefix_start,
                                                  pos)));
    if (!in_quotes && arith_depth == 0 && substitution_paren_depth == 0 &&
        brace_open && redirect_prefix) {
      result->status = SHELL_STATUS_ERROR;
      result->count = subcmd_idx;
      return SHELL_EPARSE;
    }
    if (!in_quotes && arith_depth == 0 && substitution_paren_depth == 0 &&
        !inside_parameter_expansion && brace_open && command_boundary) {
      if (brace_group_stack_depth == SHELL_MAX_SUBCOMMANDS) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      brace_group_stack[brace_group_stack_depth++] = SHELL_GROUP_BRACE;
      shell_pipeline_prefix_state_t group_prefix = documents.before_prefix;
      if (group_prefix.has_modifier && current_type == SHELL_TYPE_PIPELINE &&
          !inherited_group_pipeline) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      uint16_t group_modifiers = 0;
      if (group_prefix.negation_count != 0)
        group_modifiers |= SHELL_CMD_MOD_PIPE_NEGATED;
      if (group_prefix.time_mode != SHELL_PIPE_TIME_NONE)
        group_modifiers |= SHELL_CMD_MOD_PIPE_TIMED;
      OPEN_GROUP(SHELL_GROUP_BRACE, pos, group_modifiers,
                 group_prefix.negation_count, group_prefix.time_mode);
      brace_group_depth++;
      group_depth++;
      group_kinds |= SHELL_GROUP_BRACE;
      subcmd_start = pos + 1;
      execution_pipeline_start = true;
      pos++;
      continue;
    }
    if (!in_quotes && limits->strict_mode && arith_depth == 0 &&
        substitution_paren_depth == 0 && !inside_parameter_expansion &&
        command_boundary && c == '{' &&
        group_word_ends_here(cmd, pos, cmd_len)) {
      /* A standalone opening brace needs an argument-list separator after it.
       * Otherwise it is neither a group delimiter nor an ordinary word. */
      result->status = SHELL_STATUS_ERROR;
      result->count = subcmd_idx;
      return SHELL_EPARSE;
    }
    if (!in_quotes && arith_depth == 0 && substitution_paren_depth == 0 &&
        brace_close && structural_delimiter &&
        (only_whitespace_before_delimiter || directly_after_closed_group)) {
      if (brace_group_stack_depth == 0 ||
          brace_group_stack[brace_group_stack_depth - 1] != SHELL_GROUP_BRACE) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      uint32_t probe = subcmd_start;
      while (probe < pos && shell_source_space((unsigned char)cmd[probe]))
        probe++;
      if (probe != pos) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      brace_group_depth--;
      brace_group_stack_depth--;
      group_depth--;
      CLOSE_GROUP(SHELL_GROUP_BRACE, pos + 1);
      last_closed_group_end = pos + 1;
      if (brace_group_depth == 0)
        group_kinds &= (uint8_t)~SHELL_GROUP_BRACE;
      pos++;
      subcmd_start = pos;
      continue;
    }
    if (!in_quotes && limits->strict_mode && arith_depth == 0 &&
        substitution_paren_depth == 0 && !inside_parameter_expansion &&
        command_boundary && c == '}' &&
        (group_word_ends_here(cmd, pos, cmd_len) || brace_close_redirect)) {
      result->status = SHELL_STATUS_ERROR;
      result->count = subcmd_idx;
      return SHELL_EPARSE;
    }

    /* A comment starts at a word boundary and extends to the next line. It
     * is data-free shell syntax, so operators in the comment must not split
     * the command range. */
    if (!in_quotes && c == '#' &&
        !fast_lexical_token_contains(&documents, pos)) {
      if (comment_start == UINT32_MAX)
        comment_start = pos;
      while (pos < cmd_len && cmd[pos] != '\n')
        pos++;
      continue;
    }

    /* An unquoted escaped physical line ending is removed before list
     * grammar is evaluated. In particular, it cannot become the missing
     * right-hand stage of a pipeline or AND/OR list. */
    if (!in_quotes && c == '\\' && pos + 1 < cmd_len && cmd[pos + 1] == '\n') {
      uint32_t after = pos + 2;
      /* A group closer, a pending list operator, or a redirect list may have
       * left `subcmd_start` at source trivia. Do not emit a phantom command
       * for a continuation that shell removes before parsing the next token. */
      bool standalone = fast_lexical_token_at(&documents, pos) &&
                        shell_source_is_escaped_line_ending(
                            cmd, documents.token.position,
                            documents.token.position + documents.token.length);
      if (standalone && documents.before_syntax_end <= subcmd_start) {
        subcmd_start = after;
        comment_start = UINT32_MAX;
      } else if (documents.prefix_open) {
        /* Keep pending pipeline modifiers with their following stage.
         * Normalization strips them after the complete range is emitted. */
        comment_start = UINT32_MAX;
      }
      pos = after;
      continue;
    }

    // Handle quotes
    if (!in_quotes && (c == '"' || c == '\'')) {
      in_quotes = true;
      quote_char = c;
      pos++;
      continue;
    }

    // Skip content inside quotes
    if (in_quotes) {
      if (quote_char == '\'') {
        // Single quotes: no escapes, everything is literal until closing '
        if (c == '\'') {
          in_quotes = false;
          quote_char = 0;
        }
        pos++;
      } else {
        // Double quotes: handle escapes for ", \, $, `
        if (c == '\\' && pos + 1 < cmd_len) {
          pos += 2; // Skip escaped char
        } else if (c == '"') {
          in_quotes = false;
          quote_char = 0;
          pos++;
        } else {
          pos++;
        }
      }
      continue;
    }

    // Track brace depth only for ${var...}. Literal braces are ordinary word
    // bytes unless they were already recognized above as brace-group syntax;
    // treating every `{` as a parameter expansion makes strict callers reject
    // valid arguments such as `echo {`.
    if (c == '{') {
      if (brace_depth == 0 && pos > 0 && cmd[pos - 1] == '$') {
        // This is ${ - start of variable expansion, remember position
        // Content starts AFTER this brace
        brace_start_pos = pos + 1;
        brace_depth = 1;
      } else if (brace_depth > 0) {
        brace_depth++;
      }
    } else if (c == '}' && brace_depth > 0) {
      // Check for empty ${} - no variable name between braces
      if (brace_start_pos > 0 && brace_depth == 1) {
        // We're closing the ${...} - check if there's any content
        // Content starts at brace_start_pos (after ${) and ends at pos (before
        // })
        bool has_content = false;
        for (uint32_t i = (uint32_t)brace_start_pos; i < pos; i++) {
          if (!shell_source_space((unsigned char)cmd[i])) {
            has_content = true;
            break;
          }
        }
        if (!has_content) {
          // Empty ${} - malformed
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        brace_start_pos = -1; // Reset
      }
      brace_depth--;
    }

    // Track arithmetic expansion $(( ... )) and (( ... ))
    // Note: $(( opens TWO parens - handle specially to avoid double counting
    if (c == '$' &&
        shell_source_dollar_arithmetic_open(cmd, cmd_len, pos, NULL)) {
      size_t after = 0;
      if (!shell_source_skip_arithmetic_expansion(cmd, cmd_len, pos, &after) ||
          after > UINT32_MAX) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      pos = (uint32_t)after;
      continue;
    }
    // Also handle plain (( )) - arithmetic in bash. Physical continuations
    // are removed before syntax recognition, so use the same logical
    // punctuation matcher as the full lexer.
    size_t arithmetic_command_after = 0;
    if (c == '(' && shell_source_match_logical_punctuation(
                        cmd, cmd_len, pos, "((", &arithmetic_command_after)) {
      /* `(( ... ))` is a shell arithmetic command only at a command
       * boundary. In argument position it is invalid shell syntax, not a
       * simple command containing literal parentheses. */
      if (limits->strict_mode && arith_depth == 0 &&
          !inside_parameter_expansion && !command_boundary) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      // This is ((...)) - arithmetic
      arith_depth += 2;
      pos = (uint32_t)arithmetic_command_after; // Skip logical ((
      continue;
    }
    /* Arithmetic parentheses can nest ordinary grouping parentheses as well
     * as nested `$((...))` forms. Track those opens so their matching close
     * cannot be mistaken for the end of the surrounding expansion. */
    if (c == '(' && arith_depth > 0) {
      arith_depth++;
      pos++;
      continue;
    }
    if (c == ')' && arith_depth > 0) {
      arith_depth--;
    }

    // Track regular parentheses () for subshell detection
    // But not inside arithmetic $(( )) or process substitution <( )
    // Only track when NOT inside arithmetic expansion
    if (arith_depth == 0) {
      if (c == '(' && !function_paren) {
        /* Extglob alternatives and array values are words, not command
         * groups. Their interior may contain spaces, pipes, or parentheses,
         * all of which are opaque to the command-list parser. */
        if (pos > 0 && (cmd[pos - 1] == '=' || cmd[pos - 1] == '?' ||
                        cmd[pos - 1] == '*' || cmd[pos - 1] == '+' ||
                        cmd[pos - 1] == '@' || cmd[pos - 1] == '!')) {
          size_t after = 0;
          if (!shell_source_find_balanced_parentheses(cmd, cmd_len, pos,
                                                      &after) ||
              after > UINT32_MAX) {
            if (limits->strict_mode) {
              result->status = SHELL_STATUS_ERROR;
              result->count = subcmd_idx;
              return SHELL_EPARSE;
            }
          } else {
            pos = (uint32_t)after;
            continue;
          }
        }
        /* A parenthesized group is a command, not a word expansion. `$(` and
         * `<(`/`>(` were consumed above by their dedicated scanners. */
        if (limits->strict_mode && !inside_parameter_expansion &&
            !command_boundary) {
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        paren_depth++;
        if (pos > 0 && (cmd[pos - 1] == '$' || cmd[pos - 1] == '<' ||
                        cmd[pos - 1] == '>')) {
          substitution_paren_depth++;
        } else {
          if (brace_group_depth > 0) {
            if (brace_group_stack_depth == SHELL_MAX_SUBCOMMANDS) {
              result->status = SHELL_STATUS_ERROR;
              result->count = subcmd_idx;
              return SHELL_EPARSE;
            }
            brace_group_stack[brace_group_stack_depth++] = SHELL_GROUP_SUBSHELL;
          }
          shell_pipeline_prefix_state_t group_prefix = documents.before_prefix;
          if (group_prefix.has_modifier &&
              current_type == SHELL_TYPE_PIPELINE &&
              !inherited_group_pipeline) {
            result->status = SHELL_STATUS_ERROR;
            result->count = subcmd_idx;
            return SHELL_EPARSE;
          }
          uint16_t group_modifiers = 0;
          if (group_prefix.negation_count != 0)
            group_modifiers |= SHELL_CMD_MOD_PIPE_NEGATED;
          if (group_prefix.time_mode != SHELL_PIPE_TIME_NONE)
            group_modifiers |= SHELL_CMD_MOD_PIPE_TIMED;
          OPEN_GROUP(SHELL_GROUP_SUBSHELL, pos, group_modifiers,
                     group_prefix.negation_count, group_prefix.time_mode);
          execution_pipeline_start = true;
          group_depth++, group_paren_depth++;
          group_kinds |= SHELL_GROUP_SUBSHELL;
          /* A group delimiter is syntax, not part of its first command. */
          if (shell_source_redirect_list_before_group(cmd, subcmd_start, pos) ||
              (heredoc_prefix_start != UINT32_MAX &&
               shell_source_redirect_list_before_group(
                   cmd, heredoc_prefix_start, pos))) {
            result->status = SHELL_STATUS_ERROR;
            result->count = subcmd_idx;
            return SHELL_EPARSE;
          }
          if (only_whitespace_before_delimiter || documents.before_prefix_open)
            subcmd_start = pos + 1;
        }
      } else if (function_paren) {
        function_paren_close = pos + 1;
      } else if (c == ')' && paren_depth > 0) {
        paren_depth--;
        if (substitution_paren_depth > 0) {
          substitution_paren_depth--;
        } else if (group_paren_depth > 0 && !closes_group) {
          if (brace_group_depth > 0) {
            if (brace_group_stack_depth == 0 ||
                brace_group_stack[brace_group_stack_depth - 1] !=
                    SHELL_GROUP_SUBSHELL) {
              result->status = SHELL_STATUS_ERROR;
              result->count = subcmd_idx;
              return SHELL_EPARSE;
            }
            brace_group_stack_depth--;
          }
          group_paren_depth--;
          group_depth--;
          if (group_paren_depth == 0)
            group_kinds &= (uint8_t)~SHELL_GROUP_SUBSHELL;
        }
      }
    }

    if (limits->strict_mode && !inside_parameter_expansion && c == ')' &&
        !closes_arithmetic && arith_depth == 0 &&
        substitution_paren_depth == 0 && !closes_group &&
        !closes_function_paren && !has_unsupported_control) {
      result->status = SHELL_STATUS_ERROR;
      result->count = subcmd_idx;
      return SHELL_EPARSE;
    }
    if (closes_function_paren)
      function_paren_close = UINT32_MAX;

    /* A dollar not starting one of the complete expansion forms handled
     * above is a literal shell-word byte. In particular, Bash accepts `$`,
     * `$:`, and `path$` as pathnames. Do not overload brace_depth as a
     * pseudo-error channel here: `${...}`, `$'...'`, and `$(...)` already
     * have structural validation at their respective scanners. */

    /* Bash combines stdout and stderr with &>word / &>>word. It is one
     * redirect, not a background separator followed by an ordinary word. */
    size_t combined_redirect = 0;
    if (!in_quotes && c == '&' &&
        shell_source_logical_next_is(cmd, cmd_len, pos, '>',
                                     &combined_redirect)) {
      size_t operator_end = combined_redirect + 1;
      size_t append = 0;
      if (shell_source_logical_next_is(cmd, cmd_len, combined_redirect, '>',
                                       &append))
        operator_end = append + 1;
      uint32_t operand = (uint32_t)operator_end;
      while (operand < cmd_len &&
             shell_source_space((unsigned char)cmd[operand]))
        operand++;
      size_t after = operand;
      if (!shell_source_skip_shell_word(cmd, cmd_len, operand, &after) ||
          after == operand || after > UINT32_MAX) {
        result->status = SHELL_STATUS_ERROR;
        result->count = subcmd_idx;
        return SHELL_EPARSE;
      }
      pos = (uint32_t)after;
      continue;
    }

    /* Command and backtick substitutions compose multiple processes. Keep
     * their concrete syntax in the feature mask and classify a standalone
     * subcommand with the substitution operator type. */
    if (current_type == SHELL_TYPE_SIMPLE &&
        ((c == '$' &&
          shell_source_dollar_parentheses_open(cmd, cmd_len, pos, NULL) &&
          !shell_source_dollar_arithmetic_open(cmd, cmd_len, pos, NULL)) ||
         (c == '`' && !(in_quotes && quote_char == '\'')))) {
      current_type = SHELL_TYPE_SUBSTITUTION;
    }

    /* A legacy substitution is one shell-word fragment. Operators inside it
     * belong to its nested command, never to this command list. */
    if (!in_quotes && c == '`') {
      size_t after = 0;
      if (!shell_source_skip_complete_backtick(cmd, cmd_len, pos, &after) ||
          after > UINT32_MAX) {
        if (limits->strict_mode) {
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        pos = cmd_len;
      } else {
        pos = (uint32_t)after;
      }
      continue;
    }

    // Handle escapes outside quotes
    if (c == '\\' && pos + 1 < cmd_len) {
      pos += 2;
      continue;
    }

    // Check for HERESTRING <<< (here-string) - must check before << and NOT
    // inside arithmetic
    size_t here_string_after = 0;
    if (arith_depth == 0 && c == '<' &&
        shell_source_match_logical_punctuation(cmd, cmd_len, pos, "<<<",
                                               &here_string_after)) {
      uint32_t redirect_prefix_start = fast_document_prefix(&documents, pos);
      shell_pipeline_prefix_state_t document_prefix = documents.before_prefix;
      bool modified_document_stage =
          document_prefix.valid && document_prefix.has_modifier &&
          documents.before_prefix_open && execution_pipeline_start;
      bool trailing_group_redirect =
          last_closed_group_end != UINT32_MAX &&
          shell_source_skip_inline_continuations(cmd, pos,
                                                 last_closed_group_end) == pos;
      if (!trailing_group_redirect && last_closed_group_end != UINT32_MAX &&
          redirect_prefix_start > last_closed_group_end)
        trailing_group_redirect =
            shell_source_skip_inline_continuations(cmd, redirect_prefix_start,
                                                   last_closed_group_end) ==
            redirect_prefix_start;
      // End current subcommand if it has content (trim whitespace)
      if (!modified_document_stage && subcmd_idx < max_cmds &&
          subcmd_start < pos) {
        uint32_t s = subcmd_start;
        uint32_t e =
            redirect_prefix_start >= subcmd_start ? redirect_prefix_start : pos;
        s = fast_range_trim_start(cmd, s, e);
        e = fast_range_trim_end(cmd, s, e);
        if (s < e) {
          result->cmds[subcmd_idx].start = s;
          result->cmds[subcmd_idx].len = e - s;
          result->cmds[subcmd_idx].type = current_type;
          result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
          result->cmds[subcmd_idx].features = 0;
          result->cmds[subcmd_idx].group_depth = group_depth;
          result->cmds[subcmd_idx].group_kinds = group_kinds;
          detect_features(cmd, s, e - s, &result->cmds[subcmd_idx].features,
                          execution_pipeline_start, FAST_FEATURE_COMMAND_BODY);
          subcmd_idx++;
          /* The incoming pipe belongs to the command stage, not to each
           * subsequently emitted redirect fragment. */
          current_pipe_input_mode = SHELL_PIPE_MODE_NONE;
        }
      }

      // Start herestring as new subcommand
      if (subcmd_idx >= max_cmds) {
        result->status = SHELL_STATUS_TRUNCATED;
        result->count = subcmd_idx;
        goto truncated;
      }

      // Record herestring subcommand: include <<< and the string
      uint32_t herestring_start = pos;
      pos = (uint32_t)here_string_after;

      pos = (uint32_t)shell_source_skip_inline_continuations(cmd, cmd_len, pos);

      // Find the complete shell word, including any quoted whitespace.
      uint32_t string_start = pos;
      pos = skip_shell_word(cmd, pos, cmd_len);
      uint32_t string_len = pos - string_start;

      if (string_len == 0) {
        // No string found - treat as less-than
        pos = herestring_start + 1;
      } else {
        if (trailing_group_redirect) {
          /* A here-string after a compound group is a redirection on that
           * group, not a synthetic executable stage. */
          subcmd_start = pos;
          current_type = SHELL_TYPE_SIMPLE;
          continue;
        }
        // Record herestring subcommand: <<< + string
        result->cmds[subcmd_idx].start = herestring_start;
        result->cmds[subcmd_idx].len = (pos - herestring_start);
        result->cmds[subcmd_idx].type = SHELL_TYPE_HERESTRING;
        result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
        result->cmds[subcmd_idx].features = SHELL_FEAT_HERESTRING;
        /* The operand is data, not a control-flow command, but its variable,
         * command and process expansions belong to this execution stage. */
        detect_expansion_features(cmd + string_start, string_len, false, false,
                                  &result->cmds[subcmd_idx].features, false);
        result->cmds[subcmd_idx].group_depth = group_depth;
        result->cmds[subcmd_idx].group_kinds = group_kinds;
        result->cmds[subcmd_idx].modifiers =
            modified_document_stage && document_prefix.negation_count != 0
                ? SHELL_CMD_MOD_PIPE_NEGATED
                : 0;
        result->cmds[subcmd_idx].pipeline_negation_count =
            modified_document_stage ? document_prefix.negation_count : 0;
        if (modified_document_stage &&
            document_prefix.time_mode != SHELL_PIPE_TIME_NONE) {
          result->cmds[subcmd_idx].modifiers |= SHELL_CMD_MOD_PIPE_TIMED;
          result->cmds[subcmd_idx].pipeline_time_mode =
              (uint8_t)document_prefix.time_mode;
          result->cmds[subcmd_idx].pipeline_time_direct = true;
        }
        subcmd_idx++;

        // Start next subcommand
        subcmd_start = pos;
        current_type = SHELL_TYPE_SIMPLE;
        current_pipe_input_mode = SHELL_PIPE_MODE_NONE;

        /* Real line endings terminate the stage; only inline trivia and
         * escaped line endings may be consumed here. */
        pos =
            (uint32_t)shell_source_skip_inline_continuations(cmd, cmd_len, pos);
        continue;
      }
    }

    // Check for HEREDOC << (heredoc) - only if not <<< and NOT inside
    // arithmetic
    size_t heredoc_operator_after = 0;
    if (arith_depth == 0 && c == '<' &&
        shell_source_match_logical_punctuation(cmd, cmd_len, pos, "<<",
                                               &heredoc_operator_after)) {
      uint32_t redirect_prefix_start = fast_document_prefix(&documents, pos);
      shell_pipeline_prefix_state_t document_prefix = documents.before_prefix;
      bool modified_document_stage =
          document_prefix.valid && document_prefix.has_modifier &&
          documents.before_prefix_open && execution_pipeline_start;
      /* A trailing group redirection may carry an io_number immediately
       * before `<<`.  It is still a redirect on the completed group, not a
       * synthetic command containing that number. */
      bool trailing_group_redirect =
          last_closed_group_end != UINT32_MAX &&
          shell_source_skip_inline_continuations(cmd, pos,
                                                 last_closed_group_end) == pos;
      if (!trailing_group_redirect) {
        size_t descriptor_after = 0;
        uint32_t descriptor = 0;
        bool numeric_prefix =
            shell_source_parse_io_number(cmd, redirect_prefix_start, pos,
                                         &descriptor_after, &descriptor) ==
                SHELL_SOURCE_IO_NUMBER_VALID &&
            descriptor_after == pos;
        trailing_group_redirect =
            last_closed_group_end != UINT32_MAX &&
            redirect_prefix_start > last_closed_group_end &&
            shell_source_skip_inline_continuations(cmd, redirect_prefix_start,
                                                   last_closed_group_end) ==
                redirect_prefix_start &&
            (numeric_prefix || redirect_prefix_start != pos);
      }
      // End current subcommand if it has content (trim whitespace)
      if (!trailing_group_redirect && !modified_document_stage &&
          subcmd_idx < max_cmds && subcmd_start < pos) {
        uint32_t s = subcmd_start;
        uint32_t e =
            redirect_prefix_start >= subcmd_start ? redirect_prefix_start : pos;
        s = fast_range_trim_start(cmd, s, e);
        e = fast_range_trim_end(cmd, s, e);
        if (s < e) {
          result->cmds[subcmd_idx].start = s;
          result->cmds[subcmd_idx].len = e - s;
          result->cmds[subcmd_idx].type = current_type;
          result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
          result->cmds[subcmd_idx].features = 0;
          result->cmds[subcmd_idx].group_depth = group_depth;
          result->cmds[subcmd_idx].group_kinds = group_kinds;
          detect_features(cmd, s, e - s, &result->cmds[subcmd_idx].features,
                          execution_pipeline_start, FAST_FEATURE_COMMAND_BODY);
          subcmd_idx++;
          current_pipe_input_mode = SHELL_PIPE_MODE_NONE;
        }
      }

      // Start heredoc as new subcommand
      if (subcmd_idx >= max_cmds) {
        result->status = SHELL_STATUS_TRUNCATED;
        result->count = subcmd_idx;
        goto truncated;
      }

      // Find heredoc delimiter (word after <<).  This is a shell word rather
      // than a whitespace-delimited string: quotes and backslash escapes may
      // be part of its spelling.  Keep this in lockstep with the body scanner
      // so the marker range ends after the complete raw delimiter word.
      uint32_t heredoc_start = pos;
      if (!trailing_group_redirect)
        heredoc_prefix_start = redirect_prefix_start;
      size_t delimiter_position = heredoc_operator_after;
      shell_source_pending_heredoc_t pending;
      bool delimiter_valid = shell_source_parse_heredoc_delimiter(
          cmd, cmd_len, &delimiter_position, &pending);

      if (!delimiter_valid) {
        size_t delimiter_start = heredoc_operator_after;
        if (delimiter_start < cmd_len && cmd[delimiter_start] == '-')
          delimiter_start++;
        while (delimiter_start < cmd_len &&
               (cmd[delimiter_start] == ' ' || cmd[delimiter_start] == '\t'))
          delimiter_start++;
        if (delimiter_start < cmd_len &&
            (cmd[delimiter_start] == '(' || cmd[delimiter_start] == ')')) {
          /* An unquoted parenthesis is shell syntax, not a heredoc delimiter.
           * In particular, `<< (word)` cannot become a redirect followed by
           * a command group. */
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        // No delimiter found - treat as less-than
        pos = heredoc_start + 1;
      } else {
        pos = (uint32_t)delimiter_position;
        // Record heredoc subcommand: include << and delimiter
        result->cmds[subcmd_idx].start = heredoc_start;
        result->cmds[subcmd_idx].len = (pos - heredoc_start); // << + delimiter
        result->cmds[subcmd_idx].type = SHELL_TYPE_HEREDOC;
        result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
        result->cmds[subcmd_idx].features = SHELL_FEAT_HEREDOC;
        result->cmds[subcmd_idx].group_depth = group_depth;
        result->cmds[subcmd_idx].group_kinds = group_kinds;
        result->cmds[subcmd_idx].modifiers =
            modified_document_stage && document_prefix.negation_count != 0
                ? SHELL_CMD_MOD_PIPE_NEGATED
                : 0;
        result->cmds[subcmd_idx].pipeline_negation_count =
            modified_document_stage ? document_prefix.negation_count : 0;
        if (modified_document_stage &&
            document_prefix.time_mode != SHELL_PIPE_TIME_NONE) {
          result->cmds[subcmd_idx].modifiers |= SHELL_CMD_MOD_PIPE_TIMED;
          result->cmds[subcmd_idx].pipeline_time_mode =
              (uint8_t)document_prefix.time_mode;
          result->cmds[subcmd_idx].pipeline_time_direct = true;
        }
        subcmd_idx++;

        // Start next subcommand after delimiter
        subcmd_start = pos;
        current_type = SHELL_TYPE_SIMPLE;
        current_pipe_input_mode = SHELL_PIPE_MODE_NONE;

        pos =
            (uint32_t)shell_source_skip_inline_continuations(cmd, cmd_len, pos);
        continue;
      }
    }

    /* Close an ordinary parenthesized group after recording its final
     * command.  The group itself is represented by group_depth metadata. */
    if (closes_group) {
      if (brace_group_depth > 0) {
        if (brace_group_stack_depth == 0 ||
            brace_group_stack[brace_group_stack_depth - 1] !=
                SHELL_GROUP_SUBSHELL) {
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        brace_group_stack_depth--;
      }
      if (subcmd_start < pos)
        RECORD_SUBCMD(subcmd_start, pos, current_type);
      CLOSE_GROUP(SHELL_GROUP_SUBSHELL, pos + 1);
      last_closed_group_end = pos + 1;
      group_paren_depth--;
      group_depth--;
      if (group_paren_depth == 0)
        group_kinds &= (uint8_t)~SHELL_GROUP_SUBSHELL;
      pos++;
      subcmd_start = pos;
      current_type = SHELL_TYPE_SIMPLE;
      comment_start = UINT32_MAX;
      continue;
    }

    // Check for separators (but not if inside arithmetic - there < > are
    // operators)
    if (arith_depth == 0 && substitution_paren_depth == 0 && is_separator(c)) {
      /* A lone '&' backgrounds the preceding command and starts a new
       * execution unit. It is distinct from logical AND (&&). */
      size_t operator_after = pos;
      bool logical_and =
          c == '&' && shell_source_match_logical_punctuation(
                          cmd, cmd_len, pos, "&&", &operator_after);
      bool logical_or =
          c == '|' && shell_source_match_logical_punctuation(
                          cmd, cmd_len, pos, "||", &operator_after);
      if (c == '&' && !logical_and) {
        if (subcmd_start < pos)
          RECORD_SUBCMD(subcmd_start, pos, current_type);
        if (subcmd_idx > 0)
          result->cmds[subcmd_idx - 1].features |= SHELL_FEAT_BACKGROUND;
        pos++;
        subcmd_start = pos;
        current_type = SHELL_TYPE_BACKGROUND;
        execution_pipeline_start = true;
        current_pipe_input_mode = SHELL_PIPE_MODE_NONE;
        comment_start = UINT32_MAX;
        last_closed_group_end = UINT32_MAX;
        continue;
      }

      // Handle &&
      if (logical_and) {
        // End current subcommand (trim whitespace)
        if (subcmd_start < pos) {
          uint32_t s = subcmd_start;
          uint32_t e = range_end_before_comment(s, pos, comment_start);
          s = fast_range_trim_start(cmd, s, e);
          e = fast_range_trim_end(cmd, s, e);
          if (s < e) {
            if (subcmd_idx >= max_cmds) {
              result->status = SHELL_STATUS_TRUNCATED;
              result->count = subcmd_idx;
              goto truncated;
            }
            result->cmds[subcmd_idx].start = s;
            result->cmds[subcmd_idx].len = e - s;
            result->cmds[subcmd_idx].type = current_type;
            result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
            result->cmds[subcmd_idx].features = 0;
            result->cmds[subcmd_idx].group_depth = group_depth;
            result->cmds[subcmd_idx].group_kinds = group_kinds;
            detect_features(cmd, s, e - s, &result->cmds[subcmd_idx].features,
                            execution_pipeline_start,
                            FAST_FEATURE_COMMAND_BODY);
            subcmd_idx++;
          }
        }

        // Start new subcommand with AND type
        pos = (uint32_t)operator_after;
        subcmd_start = pos;
        current_type = SHELL_TYPE_AND;
        execution_pipeline_start = true;
        current_pipe_input_mode = SHELL_PIPE_MODE_NONE;
        last_closed_group_end = UINT32_MAX;
        continue;
      }

      // Handle ||
      if (logical_or) {
        // End current subcommand (trim whitespace)
        if (subcmd_start < pos) {
          uint32_t s = subcmd_start;
          uint32_t e = pos;
          s = fast_range_trim_start(cmd, s, e);
          e = fast_range_trim_end(cmd, s, e);
          if (s < e) {
            if (subcmd_idx >= max_cmds) {
              result->status = SHELL_STATUS_TRUNCATED;
              result->count = subcmd_idx;
              goto truncated;
            }
            result->cmds[subcmd_idx].start = s;
            result->cmds[subcmd_idx].len = e - s;
            result->cmds[subcmd_idx].type = current_type;
            result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
            result->cmds[subcmd_idx].features = 0;
            result->cmds[subcmd_idx].group_depth = group_depth;
            result->cmds[subcmd_idx].group_kinds = group_kinds;
            detect_features(cmd, s, e - s, &result->cmds[subcmd_idx].features,
                            execution_pipeline_start,
                            FAST_FEATURE_COMMAND_BODY);
            subcmd_idx++;
          }
        }

        // Start new subcommand with OR type
        pos = (uint32_t)operator_after;
        subcmd_start = pos;
        current_type = SHELL_TYPE_OR;
        execution_pipeline_start = true;
        current_pipe_input_mode = SHELL_PIPE_MODE_NONE;
        last_closed_group_end = UINT32_MAX;
        continue;
      }

      // Handle |
      if (c == '|' && !(pos > 0 && cmd[pos - 1] == '>')) {
        // End current subcommand (trim whitespace)
        if (subcmd_start < pos) {
          uint32_t s = subcmd_start;
          uint32_t e = pos;
          s = fast_range_trim_start(cmd, s, e);
          e = fast_range_trim_end(cmd, s, e);
          if (s < e) {
            if (subcmd_idx >= max_cmds) {
              result->status = SHELL_STATUS_TRUNCATED;
              result->count = subcmd_idx;
              goto truncated;
            }
            result->cmds[subcmd_idx].start = s;
            result->cmds[subcmd_idx].len = e - s;
            result->cmds[subcmd_idx].type = current_type;
            result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
            result->cmds[subcmd_idx].features = 0;
            result->cmds[subcmd_idx].group_depth = group_depth;
            result->cmds[subcmd_idx].group_kinds = group_kinds;
            detect_features(cmd, s, e - s, &result->cmds[subcmd_idx].features,
                            execution_pipeline_start,
                            FAST_FEATURE_COMMAND_BODY);
            subcmd_idx++;
          }
        }

        // Start new subcommand with PIPELINE type
        if (subcmd_idx > 0)
          result->cmds[subcmd_idx - 1].features |= SHELL_FEAT_PIPELINE;
        size_t pipe_after = pos + 1;
        bool pipe_stderr = shell_source_match_logical_punctuation(
            cmd, cmd_len, pos, "|&", &pipe_after);
        /* A failed multi-byte match deliberately leaves `pipe_after` at the
         * first byte.  Ordinary `|` must still consume itself; otherwise the
         * fast parser revisits the same source offset forever. */
        pos = (uint32_t)(pipe_stderr ? pipe_after : (size_t)pos + 1);
        subcmd_start = pos;
        current_type = SHELL_TYPE_PIPELINE;
        execution_pipeline_start = false;
        current_pipe_input_mode = pipe_stderr
                                      ? SHELL_PIPE_MODE_STDOUT_AND_STDERR
                                      : SHELL_PIPE_MODE_STDOUT;
        last_closed_group_end = UINT32_MAX;
        continue;
      }

      // Handle ; and newlines as command separators
      if (c == ';' || c == '\n') {
        bool separator_token = fast_lexical_token_at(&documents, pos);
        // End current subcommand (trim whitespace)
        bool pending_list_continuation =
            (current_type == SHELL_TYPE_PIPELINE ||
             current_type == SHELL_TYPE_AND || current_type == SHELL_TYPE_OR) &&
            separator_token && documents.before_syntax_end <= subcmd_start;
        /* A bare negator cannot continue across LF. The shared grammar
         * boundary owns that diagnosis; no source-prefix rescan is needed. */
        if (subcmd_start < pos) {
          uint32_t s = subcmd_start;
          uint32_t e = range_end_before_comment(s, pos, comment_start);
          s = fast_range_trim_start(cmd, s, e);
          e = fast_range_trim_end(cmd, s, e);
          /* POSIX linebreaks after a pending pipeline or AND/OR connector
           * continue the next stage. The full tokenizer already recognizes
           * this grammar; retain the fast parser's connector metadata rather
           * than silently turning it into a semicolon relation. */
          if (s < e && !pending_list_continuation) {
            if (subcmd_idx >= max_cmds) {
              result->status = SHELL_STATUS_TRUNCATED;
              result->count = subcmd_idx;
              goto truncated;
            }
            result->cmds[subcmd_idx].start = s;
            result->cmds[subcmd_idx].len = e - s;
            result->cmds[subcmd_idx].type = current_type;
            result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
            result->cmds[subcmd_idx].features = 0;
            result->cmds[subcmd_idx].group_depth = group_depth;
            result->cmds[subcmd_idx].group_kinds = group_kinds;
            detect_features(cmd, s, e - s, &result->cmds[subcmd_idx].features,
                            execution_pipeline_start,
                            FAST_FEATURE_COMMAND_BODY);
            subcmd_idx++;
          }
        }

        if (pending_list_continuation) {
          pos++;
          subcmd_start = pos;
          comment_start = UINT32_MAX;
          continue;
        }
        // Start new subcommand with SEMICOLON type
        pos++;
        subcmd_start = pos;
        current_type = SHELL_TYPE_SEMICOLON;
        execution_pipeline_start = true;
        current_pipe_input_mode = SHELL_PIPE_MODE_NONE;
        comment_start = UINT32_MAX;
        last_closed_group_end = UINT32_MAX;
        continue;
      }

      // Handle < and > (redirects) - skip but don't break subcommand
      // But NOT if inside arithmetic - there they're operators, not redirects
      if ((c == '<' || c == '>') && arith_depth == 0) {
        // Check for process substitution: >(cmd) or <(cmd)
        size_t process_open = 0;
        if (shell_source_process_substitution_open(cmd, cmd_len, pos,
                                                   &process_open)) {
          size_t after = 0;
          if (!shell_source_find_balanced_parentheses(cmd, cmd_len,
                                                      process_open, &after) ||
              after > UINT32_MAX) {
            result->status = SHELL_STATUS_ERROR;
            result->count = subcmd_idx;
            return SHELL_EPARSE;
          }
          pos = (uint32_t)after;
          // Mark that we have process substitution (if we have at least one
          // subcommand)
          if (subcmd_idx > 0 && subcmd_idx < max_cmds) {
            result->cmds[subcmd_idx - 1].features |= SHELL_FEAT_PROCESS_SUB;
          }
          if (current_type == SHELL_TYPE_SIMPLE) {
            current_type = SHELL_TYPE_SUBSTITUTION;
          }
          continue;
        }
        // Check for multi-char redirects: >>, <<, >&, &>, <&, &<, etc.
        bool is_double_redirect = false;
        bool is_extended_redirect = false;
        bool is_fd_redirect = false; // >& or <& (file descriptor redirect)
        size_t redirect_after = (size_t)pos + 1;
        size_t redirect_next =
            shell_source_logical_following(cmd, cmd_len, pos);
        if (redirect_next < cmd_len) {
          if (cmd[redirect_next] == c) {
            // >>, <<
            is_double_redirect = true;
            redirect_after = redirect_next + 1;
          } else if ((c == '>' && cmd[redirect_next] == '|') ||
                     (c == '<' && cmd[redirect_next] == '>')) {
            is_extended_redirect = true;
            redirect_after = redirect_next + 1;
          } else if (cmd[redirect_next] == '&') {
            // >& or <& (fd redirect)
            is_fd_redirect = true;
            redirect_after = redirect_next + 1;
          }
        }
        pos = (uint32_t)redirect_after;
        // Skip file descriptor number if present (but not after >>, and not for
        // fd redirects) For 2>file, skip the 2. For 2>&1, don't skip the 1
        // (it's the target).
        if (!is_double_redirect && !is_fd_redirect && !is_extended_redirect) {
          size_t target_after = 0;
          uint32_t descriptor = 0;
          if (shell_source_parse_io_number(cmd, pos, cmd_len, &target_after,
                                           &descriptor) ==
              SHELL_SOURCE_IO_NUMBER_VALID)
            pos = (uint32_t)target_after;
        }
        pos =
            (uint32_t)shell_source_skip_inline_continuations(cmd, cmd_len, pos);
        // Validate: redirect must be followed by a valid target
        // Check for end of input or invalid next character
        if (pos >= cmd_len) {
          // No target after redirect - invalid
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }

        // Check for valid redirect operators: &>, &>>, <&, &<, etc.
        // These are valid bash redirects (e.g., >&1, 2>&1, &>file)
        char next_ch = cmd[pos];
        /* A process substitution may be the target of an ordinary redirect:
         * `2> >(consumer)` and `0< <(producer)`. Leave its opener for the
         * normal process-substitution scanner on the next iteration. */
        bool process_sub_target =
            (next_ch == '<' || next_ch == '>') &&
            shell_source_process_substitution_open(cmd, cmd_len, pos, NULL);
        /* Process substitution is one shell word. The opener must be
         * contiguous with `<` or `>`: `> (command)` is a syntax error, not a
         * redirect to a parenthesized command group. The same spelling is not
         * a valid unquoted heredoc delimiter either. */
        bool bare_group_operand = next_ch == '(';
        if (bare_group_operand) {
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        // Redirect target can't be an operator or an unquoted comment,
        // except process substitution.  Inline continuations have already
        // been removed; an ordinary physical line break remains an error.
        if (!process_sub_target &&
            (next_ch == '<' || next_ch == '>' || next_ch == '|' ||
             next_ch == ';' || next_ch == '&' || next_ch == '#' ||
             next_ch == '\n')) {
          result->status = SHELL_STATUS_ERROR;
          result->count = subcmd_idx;
          return SHELL_EPARSE;
        }
        continue;
      }
    }

    pos++;
  }

  if (brace_group_depth != 0 || brace_group_stack_depth != 0) {
    result->status = SHELL_STATUS_ERROR;
    result->count = subcmd_idx;
    return SHELL_EPARSE;
  }
  /* The historical non-strict fast-parser contract accepts an unfinished
   * parenthesized prefix. Do not expose an incomplete descriptor for it. */
  if (group_descriptor_depth != 0) {
    if (limits->strict_mode) {
      result->status = SHELL_STATUS_ERROR;
      result->count = subcmd_idx;
      return SHELL_EPARSE;
    }
    result->group_count = group_descriptor_stack[0];
  }

  // End final subcommand
  if (subcmd_start < pos) {
    // Trim only separator trivia; escaped whitespace remains word content.
    uint32_t start_pos = subcmd_start;
    uint32_t end_pos = range_end_before_comment(start_pos, pos, comment_start);
    start_pos = fast_range_trim_start(cmd, start_pos, end_pos);
    end_pos = fast_range_trim_end(cmd, start_pos, end_pos);

    if (start_pos < end_pos) {
      if (subcmd_idx == max_cmds) {
        result->status = SHELL_STATUS_TRUNCATED;
        result->count = subcmd_idx;
        goto truncated;
      }
      result->cmds[subcmd_idx].start = start_pos;
      result->cmds[subcmd_idx].len = end_pos - start_pos;
      result->cmds[subcmd_idx].type = current_type;
      result->cmds[subcmd_idx].pipe_input_mode = current_pipe_input_mode;
      result->cmds[subcmd_idx].features = 0;
      result->cmds[subcmd_idx].group_depth = group_depth;
      result->cmds[subcmd_idx].group_kinds = group_kinds;
      detect_features(cmd, start_pos, end_pos - start_pos,
                      &result->cmds[subcmd_idx].features,
                      execution_pipeline_start, FAST_FEATURE_COMMAND_BODY);
      subcmd_idx++;
    }
  }

  /* Control compounds are deliberately outside this range tokenizer's grammar.
   * The lexer-aware scan rejects incomplete forms while allowing complete
   * forms through to higher-level APIs, which reject unsupported execution
   * semantics before producing canonical records or dependency graphs. */
  if (shell_tokenizer_control_syntax(cmd, cmd_len) ==
      SHELL_CONTROL_SYNTAX_INCOMPLETE) {
    result->status = SHELL_STATUS_ERROR;
    result->count = subcmd_idx;
    return SHELL_EPARSE;
  }

  /* Nonempty trivia-only source is valid but has no executable range. Redirects
   * without an operand and incomplete list operators have already returned
   * from the structural scan above, so no second raw-byte operator pass is
   * needed here. */
  if (subcmd_idx == 0) {
    if (shell_source_empty_kind(cmd, cmd_len) != SHELL_SOURCE_NONEMPTY) {
      result->count = 0;
      normalize_result_metadata(cmd, cmd_len, result);
      result->status = SHELL_STATUS_OK;
      return SHELL_OK;
    }
    result->status = SHELL_STATUS_ERROR;
    result->count = 0;
    return SHELL_EPARSE;
  }

  // Ensure each parsed subcommand has real content beyond redirect/separator
  // syntax.
  bool has_command_content = false;
  for (uint32_t i = 0; i < subcmd_idx; i++) {
    uint32_t start = result->cmds[i].start;
    uint32_t len = result->cmds[i].len;

    // Check if this subcommand has actual content (not just redirect chars)
    for (uint32_t j = 0; j < len; j++) {
      char ch = cmd[start + j];
      // Skip redirect operators and separators
      if (ch == '<' || ch == '>' || ch == ';' || ch == '|' || ch == '&') {
        continue;
      }
      // Skip whitespace
      if (shell_source_space((unsigned char)ch)) {
        continue;
      }
      // This subcommand has actual command content
      has_command_content = true;
      break;
    }
    if (has_command_content)
      break;
  }

  if (!has_command_content) {
    result->status = SHELL_STATUS_ERROR;
    result->count = 0;
    return SHELL_EPARSE;
  }

  /* A literal final '|', ';', or '&' may be quoted or escaped. The scanner's
   * pending list state, rather than a raw source-byte check, is authoritative
   * for an actual trailing operator. */
  if (subcmd_start >= cmd_len && subcmd_idx > 0) {
    // The last thing we saw was a separator - check what type
    // If current_type is PIPELINE/SEMICOLON/AND/OR, we have a trailing
    // separator
    if (current_type == SHELL_TYPE_PIPELINE || current_type == SHELL_TYPE_AND ||
        current_type == SHELL_TYPE_OR) {
      result->status = SHELL_STATUS_ERROR;
      result->count = subcmd_idx;
      return SHELL_EPARSE;
    }
  }

  result->count = subcmd_idx;
  if (!normalize_pipeline_modifiers(cmd, cmd_len, result)) {
    result->status = SHELL_STATUS_ERROR;
    return SHELL_EPARSE;
  }
  merge_heredoc_features(result, heredoc_bodies, heredoc_body_count);
  normalize_result_metadata(cmd, cmd_len, result);
  result->status = SHELL_STATUS_OK;
  return SHELL_OK;

truncated:
  result->count = subcmd_idx;
  if (!normalize_pipeline_modifiers(cmd, cmd_len, result)) {
    result->status = SHELL_STATUS_ERROR;
    return SHELL_EPARSE;
  }
  merge_heredoc_features(result, heredoc_bodies, heredoc_body_count);
  normalize_result_metadata(cmd, cmd_len, result);
  result->status = SHELL_STATUS_TRUNCATED;
  return SHELL_ETRUNC;
}

shell_error_t shell_parse_fast(const char *cmd, size_t cmd_len,
                               const shell_limits_t *limits,
                               shell_parse_result_t *result) {
  shell_source_operation_begin(cmd, cmd_len);
  shell_source_workspace_scope_t previous = shell_source_workspace_begin(
      cmd, cmd_len, limits ? limits->workspace : NULL,
      limits ? limits->workspace_size : 0);
  shell_error_t error =
      shell_parse_fast_impl(cmd, cmd_len, limits, result, false);
  if (shell_source_scratch_exhausted()) {
    memset(result, 0, sizeof(*result));
    result->status = SHELL_STATUS_TRUNCATED;
    error = SHELL_ETRUNC;
  }
  shell_source_workspace_end(previous);
  shell_source_operation_end();
  return error;
}

shell_error_t shell_parse_prevalidated(const char *cmd, size_t cmd_len,
                                       const shell_limits_t *limits,
                                       shell_parse_result_t *result) {
  return shell_parse_fast_impl(cmd, cmd_len, limits, result, true);
}

/**
 * Copy subcommand to buffer (null-terminated)
 */
size_t shell_subcommand_copy(const char *cmd, const shell_range_t *range,
                             char *buf, size_t buf_len) {
  if (buf_len == 0) {
    return 0;
  }

  if (range->len == 0) {
    buf[0] = '\0';
    return 0;
  }

  size_t copy_len = range->len;
  if (copy_len >= buf_len) {
    copy_len = buf_len - 1;
  }

  memcpy(buf, cmd + range->start, copy_len);
  buf[copy_len] = '\0';
  return copy_len;
}

/**
 * Get subcommand pointer (not null-terminated)
 */
const char *shell_subcommand_view(const char *cmd, const shell_range_t *range,
                                  size_t *out_len) {
  if (out_len)
    *out_len = range->len;
  return cmd + range->start;
}

const char *shell_error_string(shell_error_t err) {
  switch (err) {
  case SHELL_OK:
    return "OK";
  case SHELL_EINPUT:
    return "Invalid input";
  case SHELL_ETRUNC:
    return "Truncated (limits exceeded)";
  case SHELL_EPARSE:
    return "Parse error";
  default:
    return "Unknown error";
  }
}

void shell_feature_flags_from_bits(uint32_t features,
                                   shell_feature_flags_t *flags) {
  if (!flags)
    return;
  flags->has_vars = (features & SHELL_FEAT_VARS) != 0;
  flags->has_globs = (features & SHELL_FEAT_GLOBS) != 0;
  flags->has_subshell = (features & SHELL_FEAT_SUBSHELL) != 0;
  flags->has_arith = (features & SHELL_FEAT_ARITH) != 0;
  flags->has_heredoc = (features & SHELL_FEAT_HEREDOC) != 0;
  flags->has_herestring = (features & SHELL_FEAT_HERESTRING) != 0;
  flags->has_process_sub = (features & SHELL_FEAT_PROCESS_SUB) != 0;
  flags->has_loops = (features & SHELL_FEAT_LOOPS) != 0;
  flags->has_conditionals = (features & SHELL_FEAT_CONDITIONALS) != 0;
  flags->has_case = (features & SHELL_FEAT_CASE) != 0;
  flags->has_subshell_file = (features & SHELL_FEAT_SUBSHELL_FILE) != 0;
  flags->has_pipeline = (features & SHELL_FEAT_PIPELINE) != 0;
  flags->has_group = (features & SHELL_FEAT_GROUP) != 0;
  flags->has_background = (features & SHELL_FEAT_BACKGROUND) != 0;
  flags->has_extglob = (features & SHELL_FEAT_EXTGLOB) != 0;
  flags->has_ansi_c_quote = (features & SHELL_FEAT_ANSI_C_QUOTE) != 0;
  flags->has_array = (features & SHELL_FEAT_ARRAY) != 0;
  flags->has_named_fd = (features & SHELL_FEAT_NAMED_FD) != 0;
  flags->has_combined_redirect = (features & SHELL_FEAT_COMBINED_REDIRECT) != 0;
}
