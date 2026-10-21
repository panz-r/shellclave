/* Retained source framing and qualified analysis of incomplete shell drafts. */
#ifndef SHELL_SOURCE_H
#define SHELL_SOURCE_H

#include "shell_depgraph.h"
#include "shell_processor.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SHELL_SOURCE_MAX_HEADERS SHELL_MAX_SUBCOMMANDS
#define SHELL_SOURCE_MAX_HEREDOCS SHELL_MAX_SUBCOMMANDS
#define SHELL_SOURCE_MAX_REDIRECTS                                             \
  (SHELL_MAX_SUBCOMMANDS * SHELL_DEP_MAX_TOKENS)

typedef struct {
  uint32_t start, length; /* Half-open byte span in the immutable source. */
} shell_source_span_t;

typedef enum {
  SHELL_SOURCE_COMPLETE = 0,
  SHELL_SOURCE_INCOMPLETE,
  /* A grammar error was established in a context the parser can classify. */
  SHELL_SOURCE_INVALID,
  SHELL_SOURCE_TRUNCATED,
  /* Analysis cannot establish the required grammar judgment. This does not
   * establish Bash validity; it includes unsupported source byte domains. */
  SHELL_SOURCE_UNSUPPORTED,
  /* The explicit-length input contains NUL and cannot be submitted unchanged
   * to the documented executor. This is not a Bash syntax judgment. */
  SHELL_SOURCE_INVALID_INPUT,
} shell_source_status_t;

typedef enum {
  SHELL_SOURCE_NEEDS_NONE = 0,
  SHELL_SOURCE_NEEDS_QUOTE,
  SHELL_SOURCE_NEEDS_SUBSTITUTION,
  SHELL_SOURCE_NEEDS_GROUP,
  SHELL_SOURCE_NEEDS_REDIRECT,
  SHELL_SOURCE_NEEDS_COMMAND,
  SHELL_SOURCE_NEEDS_HEREDOC_HEADER,
  SHELL_SOURCE_NEEDS_HEREDOC_BODY,
  SHELL_SOURCE_NEEDS_ESCAPE,
} shell_source_need_t;

/* One header record. A simple-command span excludes its deferred heredoc data
 * and following list operator. Nested source remains inside its word spelling.
 * A compound record spans the compound and its trailing redirects, has no
 * ordinary words, and keeps its enclosed headers separate.
 * words includes assignment prefixes; assignment_count identifies that initial
 * subset. first_redirect heads an ordered linked list in result.redirects;
 * follow next for redirect_count records (UINT32_MAX ends the list).
 * Quoted/expanded words retain their exact source spelling; use Shellsplit's
 * isolated-word interfaces when a static decoded value is needed. complete
 * establishes this header's grammar only, never execution or native-write
 * eligibility. A closed nested header can be complete inside an unfinished
 * enclosing group, word, or heredoc body. An open compound spans all received
 * bytes through EOF and is incomplete; its closed children remain complete.
 * COMPLETE source has complete headers. A comment ends at its raw LF even
 * when its final byte is a backslash; that LF separates headers normally.
 * Completed substitutions retain their headers, redirects and heredocs even
 * when a following word fragment is unfinished. Malformed closed children
 * invalidate the draft; appending cannot repair their enclosed grammar.
 * Closed children using Bash's implicit heredoc termination at EOF are
 * UNSUPPORTED: complete delimiter words exist, but exact termination framing
 * is not modeled. Missing delimiter words remain grammar errors.
 * Supported unfinished $(), process substitutions and backticks retain their
 * received local headers too. Their unfinished redirect operands remain
 * append-repairable recursively, including after compounds. Local recovery
 * facts do not replace the outer unfinished construct's public diagnostic;
 * only earlier complete top-level list units can qualify as a prefix.
 * Legacy backticks requiring escape-layer removal
 * are UNSUPPORTED (complete or unfinished); raw spans cannot faithfully
 * represent their decoded child source. Literal escaped/quoted backticks are
 * unaffected. group_depth and compound prevent treating a compound's redirects
 * as a simple command's. Parentheses/substitutions never expose their body as
 * outer words.
 */
typedef struct {
  shell_source_span_t source;
  shell_source_span_t words[SHELL_DEP_MAX_TOKENS];
  uint32_t word_count, assignment_count;
  uint32_t first_redirect, redirect_count;
  uint16_t group_depth;
  bool complete, compound;
} shell_source_header_t;

/* Reuse the processor's ordered I/O classification. group_index is UINT16_MAX:
 * ownership here is the containing header, not a processed group collection.
 * All io source offsets are relative to this source. heredoc is the associated
 * framing index, or UINT32_MAX for another kind of redirection. Dynamic DUP_FD
 * targets which are not exact scalar names retain target_fd NONE, empty name
 * spans, and their full source operand. This is lexical classification, not
 * routing: unresolved legacy >&word may become combined pathname output at
 * execution. No concrete target or effective byte flow is implied. */
typedef struct {
  shell_group_io_op_t io;
  uint32_t header, next, heredoc;
} shell_source_redirect_t;

/* A header and its ordered redirect bind every document to its source owner.
 * An unfinished declaration without a complete delimiter has redirect
 * UINT32_MAX: no typed complete I/O operation has been established yet.
 * delimiter_word preserves spelling; closing_delimiter includes its final LF
 * when present and can cover joined physical lines. content borrows the whole
 * received body prefix and is accepted by shell_dep_doc_content_*(). The
 * confirmed prefix excludes a final unterminated line which could still become
 * the delimiter, including a final unquoted backslash that can acquire LF on
 * append. Its length is a RAW source-byte count; apply content helpers
 * to a copy of content with value_len=confirmed_length for <<- stripping.
 * That tentative line is not inspected as code and contributes no nested
 * headers until it is confirmed as body data. Raw content still includes it.
 * A not-yet-started FIFO body has body_started=false and empty content.
 * complete proves the closing delimiter was received. Only a complete literal
 * body has an exact final payload; expandable content is always a template.
 */
typedef struct {
  uint32_t header, redirect;
  shell_source_span_t declaration, delimiter_word, closing_delimiter;
  shell_dep_doc_t content;
  uint32_t body_start, confirmed_length;
  bool header_complete, body_started, complete, delimiter_prefix;
} shell_source_heredoc_t;

/* Fixed-capacity retained product. Allocate separately from small call stacks;
 * no heap allocation is performed by shell_parse_draft(). Source spans borrow
 * the caller's immutable input for the result lifetime. Retain the returned
 * status alongside this product; record presence alone is not qualification.
 * prefix describes EXACTLY source[0..prefix_length), with strict syntax
 * established, and can be
 * passed unchanged to shell_dep_graph_parse_with_fast(). Zero prefix length
 * means there is no graph input. A syntactically qualified prefix can still
 * contain unsupported semantics, which graph construction rejects normally.
 * tail_start marks the unqualified tail, possibly including leading trivia.
 * incomplete_at locates its unfinished word, operator, or group (not
 * necessarily the quote character inside that word); need distinguishes its
 * missing grammar.
 * After a closed compound, an EOF numeric or {name} redirector prefix can
 * still acquire its operator. The compound then remains incomplete, with
 * no invented words, child groups or redirect records; closed children and
 * existing redirects remain intact. NEEDS_REDIRECT locates that prefix, or
 * NEEDS_ESCAPE locates a final backslash awaiting LF. Received whitespace,
 * invalid identifier spelling or numeric overflow commits an invalid tail.
 * A non-heredoc redirect with no operand marks its header incomplete and needs
 * a redirect word at received EOF, not an invented substitution. A committed
 * newline, separator or comment before that word makes the draft INVALID.
 * INVALID is a proven grammar error in a context the parser can classify.
 * UNSUPPORTED leaves syntax unclassified, rather than asserting validity.
 * This includes standalone empty negation and compound-array assignments in
 * lexical assignment/declaration positions. A compound-array form in an
 * ordinary argument or redirect-operand position is instead a grammar error.
 * Leading indexed assignments retain their balanced subscript and whole RHS as
 * one word, including subscript spaces/operators and quoted/expanded values.
 * Parameter and process substitutions own their internal brackets and
 * parentheses. Thus a[1 + 2]=x a=(y) is UNSUPPORTED, not a misplaced argument.
 * The framing is lexical, not subscript evaluation: fully framed indexed
 * assignments can be COMPLETE while semantic consumers reject their
 * unsupported array execution semantics.
 * Unresolved leading indexed candidates such as a[1 + ( are UNSUPPORTED,
 * not proven syntax errors; array recovery does not qualify a prefix.
 * A final backslash after the subscript can still join a following assignment
 * operator through a physical continuation and remains unclassified too.
 * Array-looking text in ordinary argument/redirect positions and scalar-looking
 * declaration operands has ordinary word boundaries: declare a[1 + 2]=x
 * contains four words. Compound-array declaration syntax remains UNSUPPORTED.
 * Document fragments do not reopen command positions:
 * : <<<x { has a literal brace argument, not a group opener.
 * Reserved time follows the reference Bash lexical context. After |, one LF
 * leaves time an ordinary command name; after |& and LF, or | and two LFs,
 * reserved time is misplaced pipeline syntax and the draft is INVALID.
 * INVALID_INPUT rejects embedded NUL. These outcomes and TRUNCATED clear
 * prefix qualification and every header's completeness.
 */
typedef struct shell_source_result {
  shell_parse_result_t prefix;
  uint32_t prefix_length, tail_start, incomplete_at;
  shell_source_need_t need;
  shell_source_header_t headers[SHELL_SOURCE_MAX_HEADERS];
  shell_source_redirect_t redirects[SHELL_SOURCE_MAX_REDIRECTS];
  shell_source_heredoc_t heredocs[SHELL_SOURCE_MAX_HEREDOCS];
  uint32_t header_count, redirect_count, heredoc_count;
} shell_source_result_t;

/* Source validation boundary for one immutable received draft, not an
 * incremental append state or an execution API. Required source is readable
 * for length bytes, including length zero; output is distinct writable storage
 * and need not be initialized. Unrepresentable lengths return TRUNCATED; NUL
 * returns INVALID_INPUT. Unsupported byte domains and grammar return
 * UNSUPPORTED, not a syntax-error claim. Distinguish append-repairable input
 * from a complete or invalid source. Retain complete top-level list units
 * before an unfinished tail, excluding every pending heredoc body from command
 * syntax. Ordinary literal word fragments, unquoted, escaped or quoted,
 * admit high bytes without encoding validation or normalization. Parameter
 * operands inherit that data domain and their applicable quote context.
 * Executable children
 * establish independent word contexts; arithmetic, substring arithmetic and
 * selectors retain restricted code bytes, including at unfinished EOF.
 * Heredoc literal text and parameter words retain their existing data domains.
 * The executor fixes LC_ALL to C/POSIX or UTF-8 before parsing submitted
 * source. Analysis uses fixed byte predicates independent of the embedding
 * application's locale and leaves that locale unchanged. Offsets remain byte
 * counts. Content remains a template, not evaluated
 * expansion output. Admitted non-ASCII heredoc data/delimiters do not change
 * later grammar or resource outcomes: a committed missing delimiter word is
 * INVALID, an unfinished word is INCOMPLETE, and pending document capacity
 * exhaustion is TRUNCATED. Unsupported delimiter forms remain UNSUPPORTED. Byte
 * admission still checks later code after a missing delimiter; it does not
 * invent a body or assume the remaining bytes are data. Unsupported
 * escape-sensitive backticks are UNSUPPORTED and invalidate prefix
 * qualification, not append-repairable input. Unfinished parameter heads, name
 * enumeration and pending backslash-LF continuations are INCOMPLETE;
 * unclassified selector failures are UNSUPPORTED. At received EOF, an unquoted
 * command-position unsupported keyword such as `if`, `function` or `[[` remains
 * INCOMPLETE (NEEDS_COMMAND): an appended suffix can make it an ordinary word.
 * Its header is incomplete. Whitespace or an operator commits that keyword and
 * makes the source UNSUPPORTED. A closed substitution likewise commits its
 * child's final word; appending outside its delimiter cannot repair it.
 * Quoted/escaped/suffixed lookalikes and words in argument or redirect-operand
 * positions are ordinary words. An assignment or redirection prefix also
 * commits a simple command: its pending executable word does not regain
 * reserved-word eligibility. Thus >out { names an ordinary executable word. An
 * unquoted escape protects its next byte only: echo \$(name) has literal '$'
 * followed by unquoted parentheses and is INVALID; quoted literal spellings
 * remain ordinary words. NEEDS_REDIRECT locates an unfinished compound-tail
 * descriptor prefix, or the operator of a missing non-heredoc operand,
 * including after inline blanks or removed backslash-LF. An actual unfinished
 * operand quote/escape/substitution retains its own need and local child
 * records. A final logical < or > in operand position may still acquire `(` and
 * uses NEEDS_SUBSTITUTION for simple commands and compound tails alike.
 * Whitespace after that punctuation rules out this process-substitution
 * completion. A final backslash there remains NEEDS_ESCAPE until LF has
 * arrived. Redirect operators use longest-match lexical boundaries, shared by
 * bare, numeric and named descriptors. A second operator cannot supply a
 * missing operand: <<<<x is INVALID, while <<<<(:) has a process-substitution
 * word. Named >| has the same clobber operator as the unprefixed spelling. NULL
 * limits uses defaults; only its command bound and optional source workspace
 * apply (draft grammar always distinguishes unfinished input). Decoded
 * delimiters and non-evicting subscript boundary facts use bounded private
 * scratch or a larger supplied buffer. shell_source_workspace_size() gives a
 * checked sufficient byte capacity, including lexical printing of
 * delimiter-only command fragments. Such fragments are not evaluated and do not
 * contribute executable child headers. Exhaustion returns TRUNCATED without a
 * qualified prefix, allowing a retry. The workspace is borrowed only for the
 * call and must not alias source or output. No partial result authorizes
 * executing a partial command or promoting a native operation. Applications
 * retain their operation/atomic-write policy.
 */
shell_source_status_t shell_parse_draft(const char *source, size_t length,
                                        const shell_limits_t *limits,
                                        shell_source_result_t *out)
    SHELL_NONNULL(1, 4);

#ifdef __cplusplus
}
#endif
#endif
