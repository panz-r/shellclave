#ifndef SHELL_PROCESSOR_INTERNAL_H
#define SHELL_PROCESSOR_INTERNAL_H

#include "shell_processor.h"

/* Private borrowed-token view used by single-buffer netsequence producers.
 * The caller frees command/token arrays with shell_commands_free(); token
 * text borrows the immutable source. Every returned record is nonempty, with
 * all tokens inside its declared source span; compound tails do not create
 * separate structural records. Source and
 * output destinations are required; limits may be NULL for defaults. Only
 * max_group_io_ops applies here, to immediate-list group metadata. Borrowed
 * source spans are not returned strings: byte limits are enforced by the
 * producer that renders these records into owned output. */
shell_process_status_t
shell_processed_commands_parse(const char *command_line, size_t command_length,
                               const shell_process_limits_t *limits,
                               shell_command_t **commands, size_t *count)
    SHELL_NONNULL(1, 4, 5);

/* Ordered owned anomaly-analysis view of every supported executable simple
 * command plus each argv-less structural stage that still needs an explicit
 * anomaly boundary. The latter includes redirect-only commands and empty
 * Bash `time` pipelines; public netsequence builders represent it with their
 * anomaly-only empty argv[0] sentinel, never as a policy subject. Nested
 * command and process substitutions precede their enclosing command; siblings
 * retain source order. This deterministic analysis order is intentionally not
 * a runtime scheduling claim for pipeline members. The entry boundary checks
 * the complete root's byte domain, syntax and supported semantics once;
 * collection constructs borrowed nested body records without revalidating
 * their descendants. Resource limits and allocation failures remain checked
 * during construction. Source storage stays immutable until return. */
typedef struct {
  shell_command_t *commands;
  size_t count;
} shell_anomaly_stages_t;

shell_process_status_t
shell_anomaly_stages_parse(const char *command_line, size_t command_length,
                           const shell_process_limits_t *limits,
                           shell_anomaly_stages_t *stages) SHELL_NONNULL(1, 4);

/* Construct the same owned stages after complete semantic graph acceptance.
 * The caller has successfully constructed a nontruncated graph from exactly
 * these immutable source bytes, including contextual read-option validation.
 * No byte, grammar, or supported-semantics validation is repeated here.
 * Construction still checks resource limits and allocation failures. stages
 * must be empty; it remains empty on failure. Source stays alive and unchanged
 * until the stages are freed. This is not valid for a partial/error graph. */
shell_process_status_t shell_anomaly_stages_collect_prevalidated(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_anomaly_stages_t *stages)
    SHELL_NONNULL(1, 4);

/* Render a collected, unchanged stage view without reparsing its source.
 * Stages and their borrowed source remain live throughout rendering. Output
 * buffers are distinct and empty, and remain empty on failure; count is zero
 * on failure. limits may be NULL for defaults. Encoded byte limits apply to
 * each output; the collector has already enforced the group-I/O budget.
 * Executable-name decoding and empty-executable rejection remain renderer
 * operations. The paired form publishes both outputs atomically. */
shell_process_status_t shell_build_command_netseq_from_stages(
    const shell_anomaly_stages_t *stages, const shell_process_limits_t *limits,
    shell_netstring_buffer_t *sequence, size_t *subcommand_count)
    SHELL_NONNULL(1, 3, 4);
shell_process_status_t shell_build_anomaly_netseqs_from_stages(
    const shell_anomaly_stages_t *stages, const shell_process_limits_t *limits,
    shell_netstring_buffer_t *command, shell_netstring_buffer_t *type,
    size_t *subcommand_count) SHELL_NONNULL(1, 3, 4, 5);
void shell_anomaly_stages_free(shell_anomaly_stages_t *stages);

/* Validate that complete source is representable by Shellsplit's semantic
 * command model. `parsed` is optional; when supplied it receives the strict
 * fast-parser result used for validation. The flat API uses this model for
 * complete compound groups, then retains its intentionally tolerant lexical
 * fallback for incomplete parenthesized input. */
shell_process_status_t shell_process_validate_supported_source(
    const char *command_line, size_t command_length,
    shell_parse_result_t *parsed) SHELL_NONNULL(1);

/* Return the storage needed for a NUL-terminated legacy adapter result.
 * Canonical buffers themselves are length-delimited, but their C-string
 * wrappers must reject SIZE_MAX rather than letting a trailing `+ 1` wrap. */
shell_process_status_t
shell_process_cstring_allocation_size(size_t content_length,
                                      size_t *allocation_size) SHELL_NONNULL(2);

/* Classify a fully static duplication operand after shell quote decoding.
 * This private helper is shared by the processed-command and dependency-graph
 * layers so `>&\"7\"`, `>&$'7'`, and `>&\"-\"` retain Bash descriptor
 * semantics instead of being confused with legacy combined-output paths.
 * A final source move suffix is interpreted before prefix quote decoding;
 * MOVE_INVALID means that suffix selected move grammar with an empty or
 * nonnumeric static source. It is a known setup failure, never a pathname.
 * INVALID retains decoding, embedded-NUL, and descriptor-overflow rejection. */
typedef enum {
  SHELL_PROCESS_FD_TARGET_PATH,
  SHELL_PROCESS_FD_TARGET_FD,
  SHELL_PROCESS_FD_TARGET_CLOSE,
  SHELL_PROCESS_FD_TARGET_MOVE,
  SHELL_PROCESS_FD_TARGET_MOVE_INVALID,
  SHELL_PROCESS_FD_TARGET_INVALID,
} shell_process_fd_target_t;

shell_process_fd_target_t
shell_process_classify_static_fd_target(const char *text, size_t length,
                                        uint32_t *fd) SHELL_NONNULL(1, 3);

/* Bash overloads `>&word`: an ordinary pathname redirects both stdout and
 * stderr, while a descriptor or `-` duplicates/closes stdout only. Keep this
 * conservative classifier shared by group metadata and the depgraph. Direct
 * process substitutions are pathnames in either direction. A decoded literal
 * byte other than a digit or `-` proves that every expansion result is a
 * pathname; otherwise unresolved words which could evaluate to either form
 * are unsupported. */
typedef enum {
  SHELL_PROCESS_LEGACY_REDIRECT_PATH,
  SHELL_PROCESS_LEGACY_REDIRECT_DUPLICATION,
  SHELL_PROCESS_LEGACY_REDIRECT_UNSUPPORTED,
} shell_process_legacy_redirect_target_t;

shell_process_legacy_redirect_target_t
shell_process_classify_legacy_output_target(const char *text, size_t length)
    SHELL_NONNULL(1);

/* Borrowed tokenizer records: token pointers and positions must refer to the
 * same source buffer, including gaps occupied by escaped line continuations.
 * Tokens have complete readable spans within that buffer in source order;
 * position + length fits size_t. The parser establishes those preconditions,
 * and iteration does not revalidate them or accept fabricated token metadata.
 * Each returned token is a synthetic span for one complete source word.
 * A NULL command initializes an exhausted iterator. Iterator and word output
 * pointers are required. The token type comes from the first lexical fragment
 * and its quoted/escaped flags are the union of every fragment in the word. */
typedef struct {
  const shell_command_t *command;
  size_t token_index;
  bool consume_redirection_operand;
  size_t redirection_operand_end;
} shell_processed_word_iterator_t;

void shell_processed_word_iterator_init(
    shell_processed_word_iterator_t *iterator, const shell_command_t *command)
    SHELL_NONNULL(1);
bool shell_processed_word_iterator_next(
    shell_processed_word_iterator_t *iterator, shell_token_t *word)
    SHELL_NONNULL(1, 2);
size_t shell_processed_command_word_count(const shell_command_t *command);
bool shell_processed_command_has_dangerous_features(
    const shell_command_t *command, bool has_pipe_input);
bool shell_processed_command_has_pipe_output(const shell_command_t *command);
#endif
