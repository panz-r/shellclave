#include "shell_arithmetic_internal.h"
#include "shell_ascii.h"
#include "shell_builtin_internal.h"
#include "shell_conditional_internal.h"
#include "shell_keywords_internal.h"
/* Supported-operation inspection and observer state. The lexer supplies token
 * framing; source admission and list/draft grammar own their classifications.
 */
#include "shell_semantics_internal.h"
#include "shell_source_internal.h"
#include "shell_token_context_internal.h"
#include "shell_token_regions_internal.h"
#include "shell_token_traits_internal.h"
#include <string.h>

static SHELL_NONNULL(1) bool arithmetic_has_unsupported_semantics(
    const char *input, size_t length);
static _Thread_local shell_semantic_token_observer_t semantic_token_observer;
static _Thread_local shell_semantic_read_fd_observer_t
    semantic_read_fd_observer;
static _Thread_local shell_semantic_process_observer_t
    semantic_process_observer;
static _Thread_local void *semantic_token_context;

static bool unsupported_semantics_scan(const char *input, size_t input_length,
                                       bool parenthesized_substitution);
static SHELL_NONNULL(1) bool unsupported_semantics_scan_impl(
    const char *input, size_t input_length, bool parenthesized_substitution);

/* Bash arithmetic accepts indexed and associative array references.  They do
 * not become ordinary scalar words merely because the outer lexer represents
 * the whole expression as one ARITHMETIC token, so inspect the expression
 * before canonical callers accept it. */
bool shell_tokenizer_arithmetic_has_array_semantics(const char *input,
                                                    size_t length) {
  if (!input)
    return false;
  shell_source_substitution_scan_t scan = {0};
  scan.scope.arithmetic_scope = true;
  scan.scope.suppress_process = true;
  size_t start = 0, after = 0;
  shell_source_substitution_kind_t kind = SHELL_SOURCE_SUBST_COMMAND;
  while (shell_source_next_executable_substitution(input, length, &scan, &start,
                                                   &after, &kind) ==
         SHELL_SOURCE_SCAN_FOUND) {
    size_t content_start = start + 1;
    if (kind != SHELL_SOURCE_SUBST_BACKTICK)
      content_start = shell_source_logical_following(input, length, start) + 1;
    if (unsupported_semantics_scan(input + content_start,
                                   after - content_start - 1,
                                   kind != SHELL_SOURCE_SUBST_BACKTICK))
      return true;
  }
  return scan.has_arrays;
}

/* Arithmetic grammar and proof belong to the shared private analyzer. */
static SHELL_NONNULL(1) bool arithmetic_has_unsupported_semantics(
    const char *input, size_t length) {
  return !shell_arithmetic_analyze(input, length).supported;
}

static SHELL_NONNULL(1) bool substring_has_unsupported_semantics(
    const char *input, size_t length) {
  return !shell_arithmetic_substring_supported(input, length);
}

/* The lexer deliberately exposes quote and expansion fragments separately,
 * while declaration builtins resolve their name and options after quote
 * removal across the complete shell word.  Start at the first fragment and
 * recover that full raw word before decoding static spelling.  This keeps
 * `de$'clare'` and `-$'a'` from bypassing the semantic boundary without ever
 * treating a dynamic expansion as a declaration name or option. Decode only
 * static shell spelling here: parameter, command, and arithmetic expansions
 * remain source bytes, so no runtime value can turn an ordinary word into a
 * declaration builtin. */
/* Required source/token/visitor; context follows the visitor's contract. */
static SHELL_NONNULL(1, 3, 4) bool token_visit_static_word(
    const char *input, size_t input_length, const shell_token_t *token,
    shell_source_byte_visitor_t visitor, void *context) {
  if ((!control_token_is_word(token) &&
       token->type != SHELL_TOKEN_PROCESS_SUB) ||
      token->position > input_length)
    return false;
  size_t word_end = 0;
  if (!shell_source_skip_shell_word(input, input_length, token->position,
                                    &word_end) ||
      word_end <= token->position || word_end > input_length)
    return false;
  const char *word = input + token->position;
  size_t word_length = word_end - token->position;
  return shell_source_visit_decoded_word(word, word_length, visitor, context);
}

typedef struct {
  const char *word;
  size_t length;
  size_t position;
  bool matches;
} static_word_match_t;

static SHELL_NONNULL(2) bool static_word_match_emit(unsigned char byte,
                                                    void *context) {
  static_word_match_t *match = context;
  if (match->position >= match->length ||
      byte != (unsigned char)match->word[match->position])
    match->matches = false;
  match->position++;
  return true;
}

static SHELL_NONNULL(1, 3,
                     4) bool token_is_static_word(const char *input,
                                                  size_t input_length,
                                                  const shell_token_t *token,
                                                  const char *word) {
  static_word_match_t match = {
      .word = word,
      .length = strlen(word),
      .matches = true,
  };
  return token_visit_static_word(input, input_length, token,
                                 static_word_match_emit, &match) &&
         match.matches && match.position == match.length;
}

static SHELL_NONNULL(1, 3) shell_source_builtin_kind_t
    token_static_builtin_kind(const char *input, size_t input_length,
                              const shell_token_t *token) {
  if ((!control_token_is_word(token) &&
       token->type != SHELL_TOKEN_PROCESS_SUB) ||
      token->position > input_length)
    return SHELL_SOURCE_BUILTIN_NONE;
  size_t word_end = 0;
  if (!shell_source_skip_shell_word(input, input_length, token->position,
                                    &word_end) ||
      word_end <= token->position || word_end > input_length)
    return SHELL_SOURCE_BUILTIN_NONE;
  return shell_source_static_builtin_kind(input + token->position,
                                          word_end - token->position);
}

typedef struct {
  const char *prefix;
  size_t length;
  size_t position;
  bool matches;
} word_prefix_match_t;

static SHELL_NONNULL(2) bool word_prefix_match_emit(unsigned char byte,
                                                    void *context) {
  word_prefix_match_t *match = context;
  if (match->position < match->length &&
      byte != (unsigned char)match->prefix[match->position])
    match->matches = false;
  match->position++;
  return true;
}

/* Quote removal can make several lexical tokens one option word.  Inspect its
 * leading decoded spelling without allocating so `-v\"$name\"` and
 * `'-v'\"$name\"` cannot bypass semantic admission. Dynamic material after
 * the prefix is deliberately not interpreted here. */
static SHELL_NONNULL(1, 3,
                     4) bool token_has_word_prefix(const char *input,
                                                   size_t input_length,
                                                   const shell_token_t *token,
                                                   const char *prefix) {
  word_prefix_match_t match = {
      .prefix = prefix,
      .length = strlen(prefix),
      .matches = true,
  };
  return token_visit_static_word(input, input_length, token,
                                 word_prefix_match_emit, &match) &&
         match.matches && match.position >= match.length;
}

/* Semantic roles are assigned to the full logical shell word, while lexical
 * iteration may expose quote or expansion fragments separately.  A missing
 * whole-word span is dynamic in a role where Bash would resolve a target. */
static SHELL_NONNULL(1, 3) bool semantic_word_has_dynamic_syntax(
    const char *input, size_t input_length, const shell_token_t *token,
    size_t semantic_word_end) {
  return semantic_word_end <= token->position ||
         semantic_word_end > input_length ||
         shell_source_word_has_dynamic_syntax(
             input + token->position, semantic_word_end - token->position);
}

/* These builtins either execute source in the current interpreter or mutate
 * its later command interpretation. Shellsplit models the submitted source,
 * not a second program assembled at runtime, so accepting one could let it
 * change descriptor or pipeline lifetime after validation. Reject the whole
 * static builtin form instead of attempting to parse trap handlers, aliases,
 * history replay, completion expansion/callbacks, Readline key bindings, or
 * dynamically loaded builtin grammars. */
static SHELL_NONNULL(1, 3) bool token_is_unmodeled_current_shell_builtin(
    const char *input, size_t input_length, const shell_token_t *token) {
  switch (token_static_builtin_kind(input, input_length, token)) {
  case SHELL_SOURCE_BUILTIN_ALIAS:
  case SHELL_SOURCE_BUILTIN_BIND:
  case SHELL_SOURCE_BUILTIN_COMPGEN:
  case SHELL_SOURCE_BUILTIN_COMPLETE:
  case SHELL_SOURCE_BUILTIN_COMPOPT:
  case SHELL_SOURCE_BUILTIN_DOT:
  case SHELL_SOURCE_BUILTIN_ENABLE:
  case SHELL_SOURCE_BUILTIN_EVAL:
  case SHELL_SOURCE_BUILTIN_FC:
  case SHELL_SOURCE_BUILTIN_LET:
  case SHELL_SOURCE_BUILTIN_MAPFILE:
  case SHELL_SOURCE_BUILTIN_POPD:
  case SHELL_SOURCE_BUILTIN_PUSHD:
  case SHELL_SOURCE_BUILTIN_READARRAY:
  case SHELL_SOURCE_BUILTIN_SOURCE:
  case SHELL_SOURCE_BUILTIN_TRAP:
  case SHELL_SOURCE_BUILTIN_UNALIAS:
    return true;
  default:
    return false;
  }
}

typedef struct {
  bool option;
  size_t position;
} static_option_scan_t;

static SHELL_NONNULL(2) bool static_option_emit(unsigned char byte,
                                                void *context) {
  static_option_scan_t *scan = context;
  if (scan->position == 0)
    scan->option = byte == '-' || byte == '+';
  scan->position++;
  return true;
}

static SHELL_NONNULL(1, 3, 4) bool token_scan_static_option(
    const char *input, size_t input_length, const shell_token_t *token,
    static_option_scan_t *scan) {
  *scan = (static_option_scan_t){0};
  return token_visit_static_word(input, input_length, token, static_option_emit,
                                 scan) &&
         scan->position > 0;
}

typedef struct {
  size_t position;
  size_t selectors;
  uint32_t names;
  unsigned char sign;
  bool valid, changes;
} static_set_option_t;

/* Bits distinguish complete valid names from prefixes/invalid names that stop
 * set processing. Every complete selector operand mutates option state. */
static const struct {
  /* NULL means that this flag has no named -o/+o spelling. */
  const char *name;
  unsigned char short_option;
} set_options[] = {
    {"posix", 0},       {"allexport", 'a'}, {"braceexpand", 'B'},
    {"emacs", 0},       {"errexit", 'e'},   {"errtrace", 'E'},
    {"functrace", 'T'}, {"hashall", 'h'},   {"histexpand", 'H'},
    {"history", 0},     {"ignoreeof", 0},   {"interactive-comments", 0},
    {"keyword", 'k'},   {"monitor", 'm'},   {"noclobber", 'C'},
    {"noexec", 'n'},    {"noglob", 'f'},    {"nolog", 0},
    {"notify", 'b'},    {"nounset", 'u'},   {"onecmd", 't'},
    {"physical", 'P'},  {"pipefail", 0},    {"privileged", 'p'},
    {"verbose", 'v'},   {"vi", 0},          {"xtrace", 'x'},
    {NULL, 'r'},
};

_Static_assert(sizeof(set_options) / sizeof(set_options[0]) < 32,
               "set option names must fit their selector mask");

static SHELL_NONNULL(2) bool static_set_option_emit(unsigned char byte,
                                                    void *context) {
  static_set_option_t *scan = context;
  bool changes = false;
  for (size_t i = 0; i < sizeof(set_options) / sizeof(set_options[0]); i++) {
    uint32_t bit = UINT32_C(1) << i;
    changes |=
        set_options[i].short_option != 0 && byte == set_options[i].short_option;
    /* Match payload bytes, never the name's terminator. An exhausted name
     * drops out before the next byte advances its candidate offset. */
    if ((scan->names & bit) != 0 &&
        (!set_options[i].name || set_options[i].name[scan->position] == '\0' ||
         byte != (unsigned char)set_options[i].name[scan->position]))
      scan->names &= ~bit;
  }
  if (scan->position++ == 0) {
    scan->sign = byte == '-' || byte == '+' ? byte : 0;
    return true;
  }
  if (!scan->sign || !scan->valid)
    return true;
  if (byte == 'o')
    scan->selectors++;
  else if (changes)
    scan->changes = true;
  else
    scan->valid = false;
  return true;
}

static SHELL_NONNULL(1) uint32_t
    static_set_selector_names(const static_set_option_t *scan) {
  uint32_t names = 0;
  for (size_t i = 0; i < sizeof(set_options) / sizeof(set_options[0]); i++) {
    uint32_t bit = UINT32_C(1) << i;
    if ((scan->names & bit) != 0 && set_options[i].name &&
        set_options[i].name[scan->position] == '\0')
      names |= bit;
  }
  return names;
}

typedef struct {
  unsigned char letter;
  size_t position;
  bool option;
  bool found;
} static_option_letter_scan_t;

static SHELL_NONNULL(2) bool static_option_letter_emit(unsigned char byte,
                                                       void *context) {
  static_option_letter_scan_t *scan = context;
  if (scan->position == 0)
    scan->option = byte == '-';
  else if (scan->option && byte == scan->letter)
    scan->found = true;
  scan->position++;
  return true;
}

static SHELL_NONNULL(1, 3) bool token_static_option_has_letter(
    const char *input, size_t input_length, const shell_token_t *token,
    unsigned char letter) {
  static_option_letter_scan_t scan = {.letter = letter};
  return token_visit_static_word(input, input_length, token,
                                 static_option_letter_emit, &scan) &&
         scan.option && scan.found;
}

typedef struct {
  bool option;
  bool enables;
  bool disables;
  size_t position;
} static_shopt_option_scan_t;

static SHELL_NONNULL(2) bool static_shopt_option_emit(unsigned char byte,
                                                      void *context) {
  static_shopt_option_scan_t *scan = context;
  if (scan->position == 0)
    scan->option = byte == '-';
  else if (scan->option && byte == 's')
    scan->enables = true;
  else if (scan->option && byte == 'u')
    scan->disables = true;
  scan->position++;
  return true;
}

static SHELL_NONNULL(1, 3, 4) bool token_scan_shopt_option(
    const char *input, size_t input_length, const shell_token_t *token,
    static_shopt_option_scan_t *scan) {
  *scan = (static_shopt_option_scan_t){0};
  return token_visit_static_word(input, input_length, token,
                                 static_shopt_option_emit, scan) &&
         scan->position > 0;
}

typedef enum {
  DECLARATION_ARRAY_NAME,
  DECLARATION_ARRAY_SUBSCRIPT,
  DECLARATION_ARRAY_COMPLETE,
  DECLARATION_ARRAY_PLUS,
  DECLARATION_ARRAY_VALUE,
  DECLARATION_ARRAY_OTHER,
} declaration_array_state_t;

typedef struct {
  declaration_array_state_t state;
  size_t subscript_depth;
  size_t skip;
  bool have_name;
} declaration_array_scan_t;

/* Declaration builtins interpret their operands after quote removal. This
 * scanner recognizes a complete static NAME[subscript] operand without
 * evaluating an expansion or allocating a temporary decoded word. */
static SHELL_NONNULL(2) bool declaration_array_emit(unsigned char byte,
                                                    void *context) {
  declaration_array_scan_t *scan = context;
  if (scan->state == DECLARATION_ARRAY_OTHER)
    return true;
  if (scan->skip != 0) {
    scan->skip--;
    return true;
  }

  switch (scan->state) {
  case DECLARATION_ARRAY_NAME:
    if (!scan->have_name) {
      if (!(shell_ascii_alpha(byte) || byte == '_')) {
        scan->state = DECLARATION_ARRAY_OTHER;
        return true;
      }
      scan->have_name = true;
      return true;
    }
    if (shell_ascii_alnum(byte) || byte == '_')
      return true;
    if (byte == '=') {
      scan->state = DECLARATION_ARRAY_OTHER;
      return true;
    }
    if (byte != '[') {
      scan->state = DECLARATION_ARRAY_OTHER;
      return true;
    }
    scan->state = DECLARATION_ARRAY_SUBSCRIPT;
    scan->subscript_depth = 1;
    return true;
  case DECLARATION_ARRAY_SUBSCRIPT:
    if (byte == '[') {
      scan->subscript_depth++;
    } else if (byte == ']' && --scan->subscript_depth == 0) {
      scan->state = DECLARATION_ARRAY_COMPLETE;
    }
    return true;
  case DECLARATION_ARRAY_COMPLETE:
    if (byte == '=') {
      scan->state = DECLARATION_ARRAY_VALUE;
      return true;
    }
    if (byte == '+') {
      scan->state = DECLARATION_ARRAY_PLUS;
      return true;
    }
    scan->state = DECLARATION_ARRAY_OTHER;
    return true;
  case DECLARATION_ARRAY_PLUS:
    if (byte == '=') {
      scan->state = DECLARATION_ARRAY_VALUE;
      return true;
    }
    scan->state = DECLARATION_ARRAY_OTHER;
    return true;
  case DECLARATION_ARRAY_VALUE:
    /* The declaration builtin has already recognized the array designator.
     * Its assigned value need not be parsed to reject the unsupported array
     * semantic without evaluating any runtime expansion. */
    return true;
  case DECLARATION_ARRAY_OTHER:
    return true;
  }
  return true;
}

static SHELL_NONNULL(1) bool word_has_array_designator_after(const char *input,
                                                             size_t length,
                                                             size_t skip) {
  declaration_array_scan_t scan = {
      .state = DECLARATION_ARRAY_NAME,
      .skip = skip,
  };
  bool in_single = false;
  bool in_double = false;
  for (size_t position = 0; position < length; position++) {
    char c = input[position];
    if (!in_single && !in_double && c == '$' &&
        shell_source_logical_next_is(input, length, position, '\'', NULL)) {
      size_t after = position;
      if (!shell_source_decode_ansi_c_word(input, length, &after,
                                           declaration_array_emit, &scan))
        return false;
      position = after - 1;
      continue;
    }
    if (c == '\\' && !in_single && position + 1 < length) {
      char next = input[++position];
      if (next == '\n')
        continue;
      if (in_double && next != '$' && next != '`' && next != '"' &&
          next != '\\')
        (void)declaration_array_emit('\\', &scan);
      (void)declaration_array_emit((unsigned char)next, &scan);
      continue;
    }
    if (c == '\'' && !in_double) {
      in_single = !in_single;
      continue;
    }
    if (c == '"' && !in_single) {
      in_double = !in_double;
      continue;
    }
    if (!in_single && c == '`') {
      size_t after = 0;
      if (!shell_source_skip_complete_quoted_text(input, length, position, c,
                                                  &after))
        return false;
      position = after - 1;
      continue;
    }
    if (!in_single && c == '$' &&
        shell_source_logical_next_is(input, length, position, '{', NULL)) {
      size_t after = 0;
      if (!shell_source_skip_parameter_expansion(input, length, position,
                                                 &after))
        return false;
      position = after - 1;
      continue;
    }
    size_t open = 0;
    if (!in_single && c == '$' &&
        shell_source_dollar_arithmetic_open(input, length, position, &open)) {
      size_t after = 0;
      if (!shell_source_skip_arithmetic_expansion(input, length, position,
                                                  &after))
        return false;
      position = after - 1;
      continue;
    }
    if (!in_single && c == '$' &&
        shell_source_dollar_parentheses_open(input, length, position, &open)) {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, open, &after))
        return false;
      position = after - 1;
      continue;
    }
    if (!in_single && !in_double && (c == '<' || c == '>') &&
        shell_source_process_substitution_open(input, length, position,
                                               &open)) {
      size_t after = 0;
      if (!shell_source_find_balanced_parentheses(input, length, open, &after))
        return false;
      position = after - 1;
      continue;
    }
    (void)declaration_array_emit((unsigned char)c, &scan);
  }
  return scan.state == DECLARATION_ARRAY_COMPLETE ||
         scan.state == DECLARATION_ARRAY_VALUE;
}

/* Inspect every active expansion regardless of the outer token's diagnostic
 * classification. Syntax validation owns malformed-source rejection; this
 * predicate classifies unsupported operations using the same
 * inherited quote contexts as graph and feature consumers. */
static SHELL_NONNULL(1) bool expansion_has_unsupported_semantics(
    const char *input, size_t length, bool heredoc) {
  shell_source_substitution_scan_t scan = {
      .scope = {.heredoc = heredoc, .suppress_process = heredoc}};
  size_t start, after;
  shell_source_substitution_kind_t kind;
  shell_source_scan_status_t status;
  while ((status = shell_source_next_word_expansion(input, length, &scan,
                                                    &start, &after, &kind)) ==
         SHELL_SOURCE_SCAN_FOUND) {
    /* A legacy body's escape layer is removed before its nested parse. Raw
     * borrowed spans cannot describe that logical source, so do not classify
     * or validate the raw body as though it were an ordinary command list. */
    if (scan.has_backtick_escapes)
      return true;
    if (semantic_process_observer &&
        (kind == SHELL_SOURCE_SUBST_PROCESS_INPUT ||
         kind == SHELL_SOURCE_SUBST_PROCESS_OUTPUT))
      semantic_process_observer(input + start, after - start,
                                semantic_token_context);
    if (kind == SHELL_SOURCE_EXPANSION_SUBSTRING) {
      if (substring_has_unsupported_semantics(input + start, after - start))
        return true;
      continue;
    }
    size_t content_start = start + 1;
    if (kind == SHELL_SOURCE_EXPANSION_ARITHMETIC) {
      size_t open = 0;
      (void)shell_source_dollar_arithmetic_open(input, length, start, &open);
      content_start = open + 1;
      /* The outer arithmetic scope owns nested math. The literal grammar
       * parses nested expansions once on its own forward cursor. */
      size_t close = after - 2;
      while (close > content_start && input[close] != ')')
        close--;
      if (arithmetic_has_unsupported_semantics(input + content_start,
                                               close - content_start))
        return true;
      continue;
    }
    if (kind != SHELL_SOURCE_SUBST_BACKTICK)
      content_start = shell_source_logical_following(input, length, start) + 1;
    if (unsupported_semantics_scan(input + content_start,
                                   after - content_start - 1,
                                   kind != SHELL_SOURCE_SUBST_BACKTICK))
      return true;
  }
  /* Complete raw framing can still require decoded or reconstructed source
   * which retained semantic products cannot represent. Preserve that
   * terminal as unsupported. Malformed and incomplete source remain owned by
   * their syntax-validation boundaries rather than being relabelled here. */
  return status == SHELL_SOURCE_SCAN_UNSUPPORTED || scan.has_arrays ||
         scan.has_locale_quote || scan.has_ansi_nul || scan.has_ansi_locale ||
         scan.has_parameter_write || scan.has_parameter_reevaluation;
}

static SHELL_NONNULL(1) bool word_has_unsupported_semantics(const char *input,
                                                            size_t length) {
  return expansion_has_unsupported_semantics(input, length, false);
}

/* Quote bytes at a heredoc root are data. The shared forward stream still
 * applies parameter-pattern quoting and visits only active expansions. */
static SHELL_NONNULL(1) bool heredoc_body_has_unsupported_semantics(
    const char *input, size_t length) {
  return expansion_has_unsupported_semantics(input, length, true);
}

typedef struct {
  bool unsupported;
} heredoc_semantic_scan_t;

static bool scan_heredoc_body_unsupported_semantics(const char *input,
                                                    size_t body_start,
                                                    size_t body_length,
                                                    bool delimiter_quoted,
                                                    void *context) {
  heredoc_semantic_scan_t *scan = context;
  if (!scan || delimiter_quoted)
    return true;
  if (!heredoc_body_has_unsupported_semantics(input + body_start, body_length))
    return true;
  scan->unsupported = true;
  return false;
}

static bool
heredoc_sequence_has_unsupported_semantics(const char *input, size_t length,
                                           const shell_token_t *token,
                                           size_t *sequence_after) {
  size_t operator_position = 0;
  if (!heredoc_token_operator_position(token, &operator_position))
    return false;
  heredoc_semantic_scan_t scan = {0};
  bool complete = false;
  size_t after = length;
  if (!shell_source_visit_heredoc_sequence(
          input, length, operator_position,
          scan_heredoc_body_unsupported_semantics, &scan, &after, &complete))
    return false;
  if (sequence_after)
    *sequence_after = after;
  return scan.unsupported;
}

/* token is a recognized heredoc in input's immutable span. Syntax completeness
 * belongs to the declaration probe; classify only its supported semantics. */
static SHELL_NONNULL(1, 3) bool heredoc_delimiter_has_unsupported_semantics(
    const char *input, size_t length, const shell_token_t *token,
    bool parenthesized_substitution) {
  size_t operator_position = 0;
  if (!heredoc_token_operator_position(token, &operator_position))
    return false;
  size_t delimiter = 0;
  if (!shell_source_match_logical_punctuation(input, length, operator_position,
                                              "<<", &delimiter))
    return false;
  shell_source_pending_heredoc_t pending = {0};
  if (!shell_source_parse_heredoc_delimiter(input, length, &delimiter,
                                            &pending))
    return false;
  if (shell_source_heredoc_word_has_unsupported_ansi_c(pending.word,
                                                       pending.word_length))
    return true;
  /* Bash print_comsub omits the separator before an unquoted delimiter. A
   * leading dash then becomes the <<- operator on the execution-time parse,
   * changing both the terminator and tab stripping. The resulting commands
   * cannot borrow the original body spans faithfully. Real quoting and an
   * already-strip-tabs operator preserve their original framing instead. */
  return parenthesized_substitution && !pending.strip_tabs &&
         pending.word[0] == '-' &&
         !shell_source_heredoc_delimiter_is_quoted(&pending);
}

/* Keep all current-shell builtin roles together.  A target reached through a
 * wrapper chain must receive exactly the same classification as a direct
 * command word; otherwise `command builtin shopt ...` could evade the
 * source-level semantic boundary. */
typedef struct {
  bool declaration;
  shell_builtin_declaration_t declaration_state;
  bool shopt;
  bool shopt_mutates;
  bool set_builtin;
  size_t set_selectors;
  bool set_invalid_after_selectors;
  bool printf_builtin;
  shell_builtin_printf_t printf_state;
  bool read_builtin;
  shell_builtin_read_t read;
  bool getopts_builtin;
  shell_builtin_getopts_t getopts;
  bool unset_builtin;
  shell_builtin_unset_t unset;
  bool wait_builtin;
  bool wait_options;
  bool test_builtin;
  shell_builtin_test_t test;
  shell_source_wrapper_state_t wrapper;
} semantic_builtin_state_t;

/* token borrows the required immutable input span; state is required writable
 * scanner-local storage, replaced by this command's builtin classification. */
static SHELL_NONNULL(1, 3, 4) bool semantic_set_builtin_target(
    const char *input, size_t input_length, const shell_token_t *token,
    semantic_builtin_state_t *state) {
  *state = (semantic_builtin_state_t){0};
  if (token_is_unmodeled_current_shell_builtin(input, input_length, token))
    return true;
  shell_source_builtin_kind_t kind =
      token_static_builtin_kind(input, input_length, token);
  state->declaration = kind == SHELL_SOURCE_BUILTIN_DECLARE ||
                       kind == SHELL_SOURCE_BUILTIN_TYPESET ||
                       kind == SHELL_SOURCE_BUILTIN_LOCAL ||
                       kind == SHELL_SOURCE_BUILTIN_READONLY ||
                       kind == SHELL_SOURCE_BUILTIN_EXPORT;
  state->declaration_state = (shell_builtin_declaration_t){
      .kind = kind,
      .options = true,
      .promotes_prefix = kind == SHELL_SOURCE_BUILTIN_EXPORT};
  state->shopt = kind == SHELL_SOURCE_BUILTIN_SHOPT;
  state->set_builtin = kind == SHELL_SOURCE_BUILTIN_SET;
  state->printf_builtin = kind == SHELL_SOURCE_BUILTIN_PRINTF;
  state->read_builtin = kind == SHELL_SOURCE_BUILTIN_READ;
  state->read.writing = SHELL_READ_OPTIONS;
  if (state->read_builtin && semantic_read_fd_observer)
    semantic_read_fd_observer(input + token->position, 0, 3, NULL, 0, false,
                              semantic_token_context);
  state->getopts_builtin = kind == SHELL_SOURCE_BUILTIN_GETOPTS;
  state->getopts.phases = SHELL_GETOPTS_OPTIONS;
  state->unset_builtin = kind == SHELL_SOURCE_BUILTIN_UNSET;
  state->unset.options = true;
  state->wait_builtin = kind == SHELL_SOURCE_BUILTIN_WAIT;
  state->wait_options = state->wait_builtin;
  state->test_builtin =
      kind == SHELL_SOURCE_BUILTIN_TEST || kind == SHELL_SOURCE_BUILTIN_BRACKET;
  state->test.bracket = kind == SHELL_SOURCE_BUILTIN_BRACKET;
  return false;
}

static bool unsupported_semantics_scan(const char *input, size_t input_length,
                                       bool parenthesized_substitution) {
  /* Expansion traversal owns nested command bodies. Do not recursively scan
   * every body's descendants again just to classify its control words. */
  static _Thread_local size_t depth;
  if (!input)
    return true;
  if (depth > SHELL_SOURCE_MAX_EXECUTABLE_NESTING)
    return true;
  depth++;
  shell_source_scope_t previous = shell_source_scope_begin(input, input_length);
  bool unsupported = unsupported_semantics_scan_impl(
      input, input_length, parenthesized_substitution);
  shell_source_scope_end(previous);
  depth--;
  return unsupported;
}

static SHELL_NONNULL(1) bool unsupported_semantics_scan_impl(
    const char *input, size_t input_length, bool parenthesized_substitution) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  shellsplit_test_metadata_charge(SHELLSPLIT_TEST_WORK_SEMANTIC_BODIES);
#endif
  shell_tokenizer_state_t state;
  /* This helper classifies valid shell source.  Let each public adapter keep
   * its established EINPUT result for raw control bytes or other invalid
   * source rather than relabelling them as unsupported semantics. */
  if (!shell_tokenizer_init(&state, input, input_length, NULL))
    return false;
  /* Readonly variables can make a later `{name}>...` allocation fail while
   * preserving the previous descriptor binding. Route resolution intentionally
   * has no shell-variable attribute table, so reject every state-changing
   * readonly declaration before it can reach that model. */
  semantic_builtin_state_t builtin = {0};
  bool command_start = true;
  bool awaiting_command = false;
  /* A plain leading integer assignment is temporary once an executable word
   * follows. Without one it performs arithmetic in the current shell. += can
   * perform that arithmetic even for temporary command-prefix assignments. */
  bool integer_assignment = false;
  semantic_pipeline_prefix_t pipeline_prefix =
      semantic_pipeline_prefix_initial();
  size_t redirect_operand_end = 0;
  /* Semantic roles apply to logical shell words, not their lexical quote and
   * escape fragments. Once the first fragment has been classified, skip the
   * remaining fragments until the recovered source-word boundary. */
  size_t semantic_word_end = 0;
  size_t expansion_word_end = 0;
  size_t heredoc_sequence_after = 0;
  bool terminal_empty_time = false;
  /* Prefix state belongs to a compound's command list. Closing an inner
   * subshell must validate its terminal state before restoring the outer
   * pipeline; a brace close, unlike a subshell close, permits empty `time`. */
  semantic_pipeline_prefix_t compound_prefixes[SHELL_MAX_GROUPS];
  uint32_t compound_depth = 0;
  shell_token_t token;
  while (shell_tokenizer_next(&state, &token)) {
    if (semantic_token_observer)
      semantic_token_observer(&token, semantic_token_context);
    if (shell_source_is_escaped_line_ending(input, token.position,
                                            token.position + token.length))
      continue;
    if (token.type == SHELL_TOKEN_CONDITIONAL_COMMAND) {
      shell_conditional_t condition =
          shell_conditional_parse(input, input_length, token.position);
      if (condition.frame != SHELL_CONDITIONAL_COMPLETE)
        return true;
      shell_token_regions_t regions =
          shell_conditional_regions(input, &condition);
      for (unsigned operand = 0; operand < regions.count; ++operand)
        if (word_has_unsupported_semantics(regions.regions[operand].text,
                                           regions.regions[operand].length))
          return true;
      command_start = false;
      pipeline_prefix.scanned = pipeline_prefix.has_stage = true;
      continue;
    }
    if (token.type == SHELL_TOKEN_ARITHMETIC_COMMAND) {
      if (state.in_arithmetic)
        return true;
      const char *content;
      size_t content_length;
      shell_tokenizer_arithmetic_content(&token, true, &content,
                                         &content_length);
      if (!shell_arithmetic_analyze(content, content_length).supported)
        return true;
      command_start = false;
      pipeline_prefix.scanned = true;
      pipeline_prefix.has_stage = true;
      continue;
    }
    /* Shellsplit deliberately does not execute or model case clauses.  The
     * clause terminators are meaningful only there, and Bash rejects them in
     * an ordinary command list.  Never reinterpret one as a plain separator.
     */
    if (token.type == SHELL_TOKEN_CASE_TERMINATE ||
        token.type == SHELL_TOKEN_CASE_FALLTHROUGH ||
        token.type == SHELL_TOKEN_CASE_TEST_NEXT)
      return true;
    /* Continuation LF does not begin a new pipeline stage. The lexical
     * iterator independently retains Bash's time-keyword history; the list
     * boundary rejects a reserved time where only a stage is permitted. */
    if (command_start && !pipeline_prefix.scanned &&
        !pipeline_prefix.has_stage && token.type == SHELL_TOKEN_SEMICOLON &&
        (token.start[0] == '\n'))
      continue;
    bool list_operator =
        token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_PIPE_BOTH ||
        token.type == SHELL_TOKEN_SEMICOLON || token.type == SHELL_TOKEN_AND ||
        token.type == SHELL_TOKEN_OR || token.type == SHELL_TOKEN_BACKGROUND;
    if (parenthesized_substitution &&
        (token.type == SHELL_TOKEN_SUBSHELL_END ||
         (token.type == SHELL_TOKEN_GROUP_END && token.start[0] == ')')) &&
        (terminal_empty_time || (command_start && pipeline_prefix.has_time &&
                                 !pipeline_prefix.has_stage)))
      return true;
    if (parenthesized_substitution && command_start && list_operator &&
        pipeline_prefix.has_time && !pipeline_prefix.has_stage)
      terminal_empty_time = token.type != SHELL_TOKEN_BACKGROUND;
    else if (!list_operator)
      terminal_empty_time = false;
    if (command_start && semantic_token_is_pipeline_prefix(
                             input, input_length, &token, &pipeline_prefix))
      continue;
    /* An assignment or redirect leaves argv[0] pending, but commits a simple
     * command: a later `if`, `then`, or `[[` is an executable word, not
     * reserved syntax. Reuse the first-stage fact instead of conflating the two
     * roles. */
    bool reserved_word_position = command_start && !pipeline_prefix.has_stage;
    if (command_start && !list_operator)
      pipeline_prefix.has_stage = true;
    /* A heredoc delimiter undergoes quote removal only. Its parameter-like
     * spelling is literal and must not be mistaken for an executable word
     * expansion; its body is inspected below with heredoc-specific rules. */
    bool word_token = control_token_is_word(&token) ||
                      token.type == SHELL_TOKEN_VARIABLE ||
                      token.type == SHELL_TOKEN_VARIABLE_QUOTED ||
                      token.type == SHELL_TOKEN_SPECIAL_VAR ||
                      token.type == SHELL_TOKEN_SUBSHELL ||
                      token.type == SHELL_TOKEN_ARITHMETIC ||
                      token.type == SHELL_TOKEN_PROCESS_SUB ||
                      token.type == SHELL_TOKEN_PIPE_NEGATE ||
                      token.type == SHELL_TOKEN_PIPE_TIME ||
                      token.type == SHELL_TOKEN_PIPE_TIME_OPTION;
    if (word_token && token.position >= expansion_word_end) {
      /* Classify the complete word, not separate $/quote fragments. Nested
       * executable bodies own their quote/comment state in the shared scoped
       * expansion stream. Keep visiting every lexical fragment for observers,
       * but never rescan a suffix with a fabricated fresh quote context. */
      if (!shell_source_skip_shell_word(input, input_length, token.position,
                                        &expansion_word_end))
        return false; /* Syntax validation owns incomplete words. */
      if (word_has_unsupported_semantics(input + token.position,
                                         expansion_word_end - token.position))
        return true;
    } else if (shell_token_type_is_redirection(token.type) &&
               token.type != SHELL_TOKEN_HEREDOC &&
               word_has_unsupported_semantics(token.start, token.length)) {
      /* Descriptor duplication tokens can own their complete operand. */
      return true;
    }
    if (token.type == SHELL_TOKEN_HEREDOC &&
        heredoc_delimiter_has_unsupported_semantics(input, input_length, &token,
                                                    parenthesized_substitution))
      return true;
    if (token.type == SHELL_TOKEN_HEREDOC &&
        token.position >= heredoc_sequence_after) {
      if (heredoc_sequence_has_unsupported_semantics(
              input, input_length, &token, &heredoc_sequence_after))
        return true;
    }
    if (redirect_operand_end != 0 && token.position < redirect_operand_end)
      continue;
    redirect_operand_end = 0;
    if (list_operator) {
      if (builtin.test_builtin && shell_builtin_test_unsupported(&builtin.test))
        return true;
      if (integer_assignment)
        return true;
      command_start = true;
      awaiting_command = false;
      pipeline_prefix = semantic_pipeline_prefix_initial();
      if (token.type == SHELL_TOKEN_PIPE || token.type == SHELL_TOKEN_PIPE_BOTH)
        pipeline_prefix.eligible = false;
      builtin = (semantic_builtin_state_t){0};
      semantic_word_end = 0;
      continue;
    }
    if (reserved_word_position &&
        token_starts_bash_compound_command(&token, input, input_length))
      return true;
    if (token.type == SHELL_TOKEN_GROUP_START ||
        token.type == SHELL_TOKEN_SUBSHELL_START) {
      if (integer_assignment)
        return true;
      /* Defer an over-capacity source to the parser's resource-limit boundary.
       * This classifier does not turn exhaustion into unsupported syntax. */
      if (compound_depth == SHELL_MAX_GROUPS)
        return false;
      compound_prefixes[compound_depth++] = pipeline_prefix;
      command_start = true;
      awaiting_command = false;
      pipeline_prefix = semantic_pipeline_prefix_initial();
      builtin = (semantic_builtin_state_t){0};
      semantic_word_end = 0;
      continue;
    }
    if (token.type == SHELL_TOKEN_GROUP_END ||
        token.type == SHELL_TOKEN_SUBSHELL_END) {
      if (builtin.test_builtin && shell_builtin_test_unsupported(&builtin.test))
        return true;
      if (integer_assignment)
        return true;
      command_start = false;
      awaiting_command = false;
      pipeline_prefix = compound_depth != 0
                            ? compound_prefixes[--compound_depth]
                            : (semantic_pipeline_prefix_t){0};
      builtin = (semantic_builtin_state_t){0};
      semantic_word_end = 0;
      continue;
    }
    if (shell_token_type_is_redirection(token.type)) {
      /* Resettable predefined names require graph-side path state. Names whose
       * prohibited capability can never be removed remain source-semantically
       * unsupported and need no deferred graph verdict. */
      size_t name_after;
      if (shell_source_parse_named_fd_at_word_start(
              token.start, 0, token.length, &name_after)) {
        unsigned properties =
            shell_builtin_name_properties(token.start + 1, name_after - 2);
        if ((properties & (SHELL_VARIABLE_UNSTABLE | SHELL_VARIABLE_READONLY |
                           SHELL_VARIABLE_ARRAY | SHELL_VARIABLE_FROZEN)) &&
            !(properties & SHELL_VARIABLE_DESPECIALIZES_ON_UNSET))
          return true;
      }
      redirect_operand_end = full_redirect_end(input, input_length, &token);
      continue;
    }

    if (semantic_word_end != 0 && token.position < semantic_word_end)
      continue;
    semantic_word_end = 0;
    if (word_token)
      semantic_word_end = expansion_word_end;

    /* A lexer can recognize the spelling NAME[index]=value without knowing
     * whether it occupies an assignment-prefix position.  Outside that
     * position Bash passes it as an ordinary argument (for example,
     * `echo a[0]=b`), so reject it only when it has array-assignment
     * semantics.  Declaration builtins also give their operands that meaning.
     */
    if (token.type == SHELL_TOKEN_ARRAY_ASSIGNMENT &&
        (command_start ||
         shell_source_array_assignment_is_compound(token.start, token.length)))
      return true;

    if (word_token &&
        shell_source_word_is_elided(input + token.position,
                                    semantic_word_end - token.position)) {
      /* Expansion can remove a command word, but cannot reopen the lexical
       * assignment/reserved-word prefix. Keep looking only for argv[0]. */
      awaiting_command |= command_start;
      command_start = false;
      continue;
    }
    if (command_start || awaiting_command) {
      if (command_start && token.type == SHELL_TOKEN_PIPE_NEGATE)
        continue;
      /* Control syntax is unsupported whether complete or incomplete. The
       * list validator retains its diagnostic control grammar separately;
       * this forward semantic pass only needs the command-position keyword
       * or function introducer, not another descendant walk. */
      if (reserved_word_position &&
          (shell_source_keyword(input, input_length, token.position, NULL) ||
           control_token_starts_function_definition(&token, input,
                                                    input_length)))
        return true;
      /* Scalar assignment prefixes do not consume the command-word position.
       * Keep looking so `VAR=x declare -a values` cannot evade the semantic
       * rejection. */
      shell_source_assignment_word_t assignment;
      if (command_start && control_token_is_word(&token) &&
          shell_source_parse_scalar_assignment_word(token.start, token.length,
                                                    &assignment)) {
        /* POSIXLY_CORRECT changes Bash's current-shell assignment lifetime.
         * A leading assignment is normally temporary, but rejecting this
         * spelling keeps the supported-source contract independent of which
         * command follows it. The executor separately makes the variable
         * readonly before source evaluation to contain dynamic writers. */
        unsigned properties =
            shell_builtin_name_properties(token.start, assignment.name_end);
        if (properties & SHELL_VARIABLE_FROZEN)
          return true;
        if ((properties & SHELL_VARIABLE_INTEGER) &&
            !(properties & SHELL_VARIABLE_DESPECIALIZES_ON_UNSET)) {
          if (assignment.append)
            return true;
          integer_assignment = true;
        }
        continue;
      }
      integer_assignment = false;
      size_t word_length = semantic_word_end > token.position
                               ? semantic_word_end - token.position
                               : 0;
      shell_source_wrapper_step_t wrapper_step = shell_source_wrapper_start(
          &builtin.wrapper, input + token.position, word_length);
      if (wrapper_step == SHELL_SOURCE_WRAPPER_STATIC_TARGET) {
        if (semantic_set_builtin_target(input, input_length, &token, &builtin))
          return true;
      } else if (wrapper_step != SHELL_SOURCE_WRAPPER_MORE) {
        builtin = (semantic_builtin_state_t){0};
      }
      command_start = false;
      awaiting_command = false;
      continue;
    }
    if (builtin.wrapper.kind != SHELL_SOURCE_WRAPPER_NONE) {
      size_t word_length = semantic_word_end > token.position
                               ? semantic_word_end - token.position
                               : 0;
      shell_source_wrapper_step_t wrapper_step = shell_source_wrapper_consume(
          &builtin.wrapper, input + token.position, word_length);
      if (wrapper_step == SHELL_SOURCE_WRAPPER_STATIC_TARGET) {
        if (semantic_set_builtin_target(input, input_length, &token, &builtin))
          return true;
      } else if (wrapper_step != SHELL_SOURCE_WRAPPER_MORE) {
        builtin = (semantic_builtin_state_t){0};
      }
      continue;
    }
    if (builtin.test_builtin) {
      /* The syntax boundary owns incomplete words. Retain compact role facts
       * until the command boundary supplies Bash's expression arity. */
      if (semantic_word_end <= token.position)
        return false;
      shell_builtin_test_word(&builtin.test, input + token.position,
                              semantic_word_end - token.position);
      continue;
    }
    if (builtin.set_builtin) {
      if (semantic_word_has_dynamic_syntax(input, input_length, &token,
                                           semantic_word_end))
        /* A runtime word can become either a short option or the operand of
         * a pending -o/+o selector. Option state is deliberately fixed for a
         * supported source, so this ambiguity is rejected at this boundary. */
        return true;
      static_set_option_t option = {
          .names =
              (UINT32_C(1) << (sizeof(set_options) / sizeof(set_options[0]))) -
              1,
          .valid = true};
      (void)token_visit_static_word(input, input_length, &token,
                                    static_set_option_emit, &option);
      if (builtin.set_selectors != 0 && option.sign == 0) {
        uint32_t names = static_set_selector_names(&option);
        if (names != 0)
          return true;
        builtin.set_selectors--;
        /* An invalid option name stops Bash before any later selectors. */
        if (names == 0 ||
            (builtin.set_selectors == 0 && builtin.set_invalid_after_selectors))
          builtin.set_builtin = false;
        continue;
      }
      /* A selector before an invalid flag is still applied. If that selector
       * has no operand because the next word is an option, it is only a query;
       * the invalid flag then stops processing before that next option. */
      if (builtin.set_invalid_after_selectors) {
        builtin.set_builtin = false;
        continue;
      }
      /* Bash applies valid short-option letters before diagnosing a later
       * invalid one in the same word. Any proved option mutation therefore
       * leaves the graph's fixed execution model, even on an error path. */
      if (option.changes)
        return true;
      /* A following option leaves pending `o` selectors as harmless queries.
       * Bare `+` continues; bare `-`, `--`, invalid flags, or a positional
       * argument end option processing. */
      if (option.sign == 0 || (!option.valid && option.selectors == 0) ||
          (option.sign == '-' && option.position == 1))
        builtin.set_builtin = false;
      builtin.set_selectors = option.selectors;
      builtin.set_invalid_after_selectors = !option.valid;
      continue;
    }
    if (builtin.getopts_builtin) {
      if (shell_builtin_getopts_word(&builtin.getopts, input + token.position,
                                     semantic_word_end - token.position) &
          SHELL_BUILTIN_ROLE_UNSUPPORTED)
        return true;
      continue;
    }
    if (builtin.read_builtin) {
      unsigned roles =
          shell_builtin_read_word(&builtin.read, input + token.position,
                                  semantic_word_end - token.position);
      if ((roles & SHELL_BUILTIN_ROLE_UNSUPPORTED) ||
          ((roles & SHELL_BUILTIN_ROLE_READ_CONTEXT) &&
           !semantic_read_fd_observer) ||
          ((roles & SHELL_BUILTIN_ROLE_TARGET) &&
           word_has_array_designator_after(
               input + token.position, semantic_word_end - token.position, 0)))
        return true;
      if (semantic_read_fd_observer &&
          (builtin.read.fd_kind || builtin.read.parameter))
        semantic_read_fd_observer(
            input + token.position, builtin.read.fd_number,
            builtin.read.fd_kind, builtin.read.parameter,
            builtin.read.parameter_length, builtin.read.parameter_identity,
            semantic_token_context);
      continue;
    }
    if (builtin.unset_builtin) {
      unsigned roles =
          shell_builtin_unset_word(&builtin.unset, input + token.position,
                                   semantic_word_end - token.position);
      if ((roles & SHELL_BUILTIN_ROLE_TARGET) &&
          word_has_array_designator_after(
              input + token.position, semantic_word_end - token.position, 0))
        return true;
      continue;
    }
    if (builtin.wait_builtin) {
      if (builtin.wait_options) {
        if (semantic_word_has_dynamic_syntax(input, input_length, &token,
                                             semantic_word_end))
          return true;
        if (token_is_static_word(input, input_length, &token, "--")) {
          builtin.wait_options = false;
          continue;
        }
        if (token_static_option_has_letter(input, input_length, &token, 'p'))
          return true;
        static_option_scan_t option;
        if (token_scan_static_option(input, input_length, &token, &option) &&
            option.option)
          continue;
        builtin.wait_options = false;
      }
      builtin.wait_builtin = false;
      continue;
    }
    if (builtin.printf_builtin) {
      /* An incomplete word belongs to the syntax-validation boundary, not
       * the supported-semantics classifier. */
      if (semantic_word_end <= token.position)
        return false;
      /* An unresolved attached target is rejected at the source boundary.
       * Fully dynamic option selection retains its unknown-writer role. */
      if (builtin.printf_state.phase == SHELL_PRINTF_OPTIONS &&
          token_has_word_prefix(input, input_length, &token, "-v") &&
          semantic_word_has_dynamic_syntax(input, input_length, &token,
                                           semantic_word_end))
        return true;
      size_t length = semantic_word_end - token.position;
      unsigned roles = shell_builtin_printf_word(
          &builtin.printf_state, input + token.position, length);
      if ((roles & SHELL_BUILTIN_ROLE_UNSUPPORTED) ||
          ((roles & SHELL_BUILTIN_ROLE_TARGET) &&
           ((roles & SHELL_BUILTIN_ROLE_DYNAMIC) ||
            word_has_array_designator_after(
                input + token.position, length,
                roles & SHELL_BUILTIN_ROLE_ATTACHED ? 2 : 0))))
        return true;
      continue;
    }
    if (builtin.shopt) {
      static_shopt_option_scan_t option;
      if (token_scan_shopt_option(input, input_length, &token, &option) &&
          option.option) {
        builtin.shopt_mutates =
            builtin.shopt_mutates || option.enables || option.disables;
        continue;
      }
      size_t word_end = semantic_word_end;
      bool dynamic = word_end <= token.position ||
                     shell_source_argument_has_dynamic_syntax(
                         input + token.position, word_end - token.position);
      /* A dynamic selector could be `-s` or `-u`, so it may alter the
       * lifetime contract even if the following source bytes look harmless. */
      if (dynamic)
        return true;
      /* All option state is part of the launch contract. Even options which
       * do not currently affect graph construction can change the meaning of
       * later syntax as support grows, so accept inspection-only shopt forms
       * and reject every static mutation attempt uniformly. */
      if (builtin.shopt_mutates)
        return true;
    }
    if (builtin.declaration) {
      if (semantic_word_end <= token.position)
        return false;
      size_t length = semantic_word_end - token.position;
      unsigned roles = shell_builtin_declaration_word(
          &builtin.declaration_state, input + token.position, length);
      if ((roles & SHELL_BUILTIN_ROLE_UNSUPPORTED) ||
          ((roles & SHELL_BUILTIN_ROLE_TARGET) &&
           word_has_array_designator_after(input + token.position, length, 0)))
        return true;
    }
  }
  return (builtin.test_builtin &&
          shell_builtin_test_unsupported(&builtin.test)) ||
         integer_assignment || terminal_empty_time ||
         (parenthesized_substitution && command_start &&
          pipeline_prefix.has_time && !pipeline_prefix.has_stage);
}

bool shell_tokenizer_has_unsupported_semantics(const char *input,
                                               size_t input_length) {
  shell_source_operation_begin(input ? input : "", input_length);
  bool unsupported = unsupported_semantics_scan(input, input_length, false);
  shell_source_operation_end();
  return unsupported;
}

bool shell_tokenizer_inspect_semantics(
    const char *input, size_t input_length,
    shell_semantic_token_observer_t observer,
    shell_semantic_read_fd_observer_t read_fd,
    shell_semantic_process_observer_t process, void *context) {
  shell_semantic_token_observer_t previous = semantic_token_observer;
  shell_semantic_read_fd_observer_t previous_read = semantic_read_fd_observer;
  shell_semantic_process_observer_t previous_process =
      semantic_process_observer;
  void *previous_context = semantic_token_context;
  semantic_token_observer = observer;
  semantic_read_fd_observer = read_fd;
  semantic_process_observer = process;
  semantic_token_context = context;
  bool unsupported =
      shell_tokenizer_has_unsupported_semantics(input, input_length);
  semantic_token_observer = previous;
  semantic_read_fd_observer = previous_read;
  semantic_process_observer = previous_process;
  semantic_token_context = previous_context;
  return unsupported;
}
