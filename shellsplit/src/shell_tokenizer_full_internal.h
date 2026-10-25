#ifndef SHELL_TOKENIZER_FULL_INTERNAL_H
#define SHELL_TOKENIZER_FULL_INTERNAL_H

#include "shell_tokenizer_full.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Private bits in the existing iterator byte; no additional public state.
 * Assignment eligibility survives prefix assignments and leading redirects,
 * unlike reserved-word eligibility. Declaration operands have their own role.
 */
enum {
  LEXICAL_TIME_ALLOWED = 1,
  LEXICAL_TIME_P_ALLOWED = 2,
  LEXICAL_TIME_DASH_ALLOWED = 4,
  LEXICAL_PREVIOUS_PIPE = 8,
  LEXICAL_ASSIGNMENT_ALLOWED = 16,
  LEXICAL_DECLARATION_OPERANDS = 32,
  LEXICAL_TIME_MASK = 15,
};

/* Initialize iteration over a domain-checked immutable source span. The
 * caller has excluded embedded NUL and invalid shell source bytes. This is
 * initialization, not another syntax or caller-correspondence boundary. */
void shell_tokenizer_init_prechecked(shell_tokenizer_state_t *state,
                                     const char *input, size_t input_length)
    SHELL_NONNULL(1, 2);

/* Classify a parser-produced token from its own lexical provenance. Skipped
 * comments cannot quote an emitted LF, and escaped physical continuations do
 * not quote structural operators. */
bool shell_token_is_literal(const shell_token_t *token) SHELL_NONNULL(1);

/* Borrow the expression of a lexer-produced complete ARITHMETIC token or a
 * complete/incomplete ARITHMETIC_COMMAND token. complete is the lexer's
 * framing fact, not semantic support; it is true for ARITHMETIC tokens. An
 * incomplete command token includes its full received tail. Source stays
 * immutable and live. Output destinations are distinct and do not alias the
 * token or its source. Only delimiter trivia
 * is inspected: no balancing, allocation or correspondence check is repeated.
 */
void shell_tokenizer_arithmetic_content(const shell_token_t *token,
                                        bool complete, const char **content,
                                        size_t *content_length)
    SHELL_NONNULL(1, 3, 4);

/* Complete-word extent beginning at a parser-produced word token. An indexed
 * assignment token already owns its balanced subscript and ends at '=';
 * scan only the RHS, never reinterpret its subscript as outer word syntax.
 * False means an unfinished word. source is the token's immutable source. */
bool shell_tokenizer_word_end(const char *source, size_t length,
                              const shell_token_t *token, size_t *end)
    SHELL_NONNULL(1, 3, 4);

/* Construct bounded fast ranges for a supported, syntax-validated immutable
 * list within the current source operation. This is the metadata counterpart
 * of prevalidated token construction, used for operational group-I/O limits.
 * The caller supplies the root boundary's complete/diagnostic guarantee;
 * range/group capacities and representation limits are still enforced. */
shell_error_t shell_parse_prevalidated(const char *input, size_t input_length,
                                       const shell_limits_t *limits,
                                       shell_parse_result_t *result)
    SHELL_NONNULL(1, 4);

typedef enum {
  SHELL_CONTROL_SYNTAX_NONE = 0,
  SHELL_CONTROL_SYNTAX_COMPLETE,
  SHELL_CONTROL_SYNTAX_INCOMPLETE,
} shell_control_syntax_t;

/* Lexer-aware control-flow classification of this command list only. Nested
 * expansion bodies remain opaque; the syntax/semantic expansion traversal
 * owns their independent classification. Do not recursively rescan them here.
 * Reserved words are recognized only in command positions. NULL is no source
 * and returns NONE. */
shell_control_syntax_t shell_tokenizer_control_syntax(const char *input,
                                                      size_t input_length);

/* Whole-source validation boundary: reject embedded NUL and prohibited
 * control/DEL bytes, then qualify high bytes by their source domain. Ordinary
 * word, comment and heredoc data admit them; code domains stay restricted.
 * A successful root check
 * is reused by contained immutable spans for the current source operation;
 * unrelated spans still receive their own byte check. NULL is rejected.
 * Validate the shell list operators exposed by the lexer. This is deliberately
 * narrower than complete shell grammar validation: it rejects impossible
 * operator chains while retaining the tokenizer's diagnostic tolerance for an
 * unfinished parenthesized group. These Boolean predicates also return false
 * on source-scratch exhaustion. Internal callers needing a classification
 * rather than bounded rejection establish an operation with sufficient
 * scratch and inspect shell_source_scratch_exhausted() before ending it. */
bool shell_tokenizer_list_syntax_valid(const char *input, size_t input_length);

/* Whole-source byte-domain and strict syntax boundary for a complete one-shot
 * shell command, with the same byte-validation guarantees and NULL rejection
 * as the diagnostic list validator above. This also rejects unfinished quotes,
 * expansions, groups, arithmetic, and here-documents. */
bool shell_tokenizer_complete_syntax_valid(const char *input,
                                           size_t input_length);

/* Identify a leading pipeline-modifier span that belongs to a directly timed
 * or negated compound command. The returned half-open span excludes the `{`
 * or `(` opener. This internal bridge lets C++ differential tests use the
 * same source grammar without including C-only scanner helpers. */
bool shell_tokenizer_compound_prefix_span(const char *input,
                                          size_t input_length, size_t start,
                                          size_t *prefix_end);

/* Semantic tokenizer boundary. Unlike the public diagnostic tokenizer, this
 * rejects syntax outside Shellclave's supported one-shot command model. Set
 * require_complete for consumers which cannot use an unfinished diagnostic
 * prefix; allow_initial_time is false for a slice known to begin after `|` or
 * `|&`. Validation precedes allocation and is performed with the selected
 * grammar policy rather than by a second caller-side scan. */
shell_tokenize_status_t shell_tokenize_supported_commands(
    const char *input, size_t input_length, bool allow_initial_time,
    bool require_complete, shell_command_t **commands, size_t *command_count)
    SHELL_NONNULL(1, 5, 6);

/* Construct borrowed records from a supported, syntax-validated immutable
 * list (or nested executable body) within the current source operation. The
 * caller already validated its byte domain and selected complete/diagnostic
 * grammar policy. This performs lexical construction, not recursive source
 * validation. Outputs are required storage; allocation failures clear them. */
shell_tokenize_status_t shell_tokenize_prevalidated_commands(
    const char *input, size_t input_length, bool allow_initial_time,
    shell_command_t **commands, size_t *command_count) SHELL_NONNULL(1, 4, 5);

/* Report an unescaped parameter expansion anywhere within one lexical token.
 * This includes a variable adjacent to literal word fragments, such as
 * `--limit=${count}`, without treating that one shell word as several argv
 * entries. */
bool shell_tokenizer_token_has_variable(const shell_token_t *token);

/* Tokens borrowing one source buffer belong to the same logical shell word
 * when physically adjacent or separated only by escaped line endings. token
 * is required; end is the preceding fragment's end offset in that source. */
static inline SHELL_NONNULL(1) bool shell_tokenizer_token_continues_word(
    const shell_token_t *token, size_t end) {
  if (end == token->position)
    return true;
  if (end > token->position)
    return false;
  size_t gap = token->position - end;
  const char *text = token->start - gap;
  for (size_t i = 0; i < gap;) {
    if (text[i] != '\\' || i + 1 >= gap || text[i + 1] != '\n')
      return false;
    i += 2;
  }
  return true;
}

static inline bool
shell_tokenizer_has_unsupported_control(const char *input,
                                        size_t input_length) {
  return shell_tokenizer_control_syntax(input, input_length) !=
         SHELL_CONTROL_SYNTAX_NONE;
}

#endif
