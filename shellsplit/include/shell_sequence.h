#ifndef SHELL_SEQUENCE_H
#define SHELL_SEQUENCE_H

#include "shell_contract.h"

#include "shell_processor.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Build a canonical netsequence with one outer netstring record per isolated
 * supported subcommand. Each record's payload is that subcommand's canonical
 * netargv. Bash `time` and its options are structural pipeline metadata and
 * never enter a record. Supported compound groups contain simple-command lists,
 * pipelines, and nested brace/subshell groups. Control compounds (loops,
 * conditionals, `case`, `select`, `coproc`, and function declarations),
 * shell-semantic array assignments, references, and declarations, and unmodeled
 * Bash `[[ … ]]`,
 * `(( … ))`, locale-quote `$"…"`, and `;&` / `;;&` forms are rejected
 * with SHELL_PROCESS_EPARSE. Active legacy backtick bodies requiring
 * escape-layer removal also return SHELL_PROCESS_EPARSE; see the
 * supported-source model in shell_depgraph.h. A pure empty `time` pipeline
 * contributes no policy record and sets `has_shell_features`; a mixed list
 * retains every executable record around it. Redirect-only simple commands,
 * including timed redirects, are rejected because they perform shell I/O but
 * have no argv to encode. Enclosing group I/O does not turn an empty timing
 * endpoint into a policy subject; full-shell evaluators must fail closed when
 * no real contained command can own that group context. The semantic model has
 * a fixed SHELL_MAX_SUBCOMMANDS capacity; a source that exceeds it returns
 * SHELL_PROCESS_EOUTPUT_LIMIT even when `limits` is NULL. When
 * limits->max_group_io_ops is nonzero, it is validated against the source
 * group I/O even though group metadata is not returned in the netsequence. The
 * caller owns *netargv_sequence and releases it with free(). This legacy
 * C-string form rejects a canonical payload containing NUL; use
 * shell_build_netargv_sequence_buffer() for lossless transport. */
shell_process_status_t
shell_build_netargv_sequence(const char *command_line, size_t command_length,
                             const shell_process_limits_t *limits,
                             char **netargv_sequence, size_t *subcommand_count,
                             bool *has_shell_features)
    SHELL_NONNULL(1, 4, 5, 6);

/* Binary-safe form of shell_build_netargv_sequence(). The outer sequence and
 * every nested netargv record are length-delimited; payloads may contain NUL.
 * `sequence` must be empty (initialized to {0} or released with
 * shell_netstring_buffer_free()); it is empty on failure. Release a successful
 * result before reusing it as an output argument. */
shell_process_status_t shell_build_netargv_sequence_buffer(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *sequence,
    size_t *subcommand_count, bool *has_shell_features)
    SHELL_NONNULL(1, 4, 5, 6);

/* Build one canonical netstring record per supported simple-command execution
 * stage. This includes stages reached through command substitutions,
 * backticks, process substitutions, and unquoted heredoc expansion bodies.
 * Dynamic or mutating arithmetic is rejected before stage collection. Nested
 * stages precede their enclosing
 * command; sibling stages retain source order. This is deterministic analysis
 * order, not a claim about runtime scheduling. An argv-less redirect-only or
 * structural empty Bash `time` stage is represented by one empty record: its
 * empty payload is the anomaly-only sentinel argv[0]. This is not a netargv
 * transport and must never be used to authorize execution. All executable
 * stages retain their decoded executable-name records.
 * Byte limits apply to the final encoded sequence, not unreturned arguments
 * or other borrowed source text. A nonzero max_group_io_ops is one cumulative
 * budget across the immediate list and all collected nested execution bodies.
 * Control compounds, function declarations, array semantics, dynamic or
 * mutating arithmetic, and unmodeled Bash `[[ … ]]`, `(( … ))`,
 * `$"…"`, and `;&` / `;;&` forms are rejected with SHELL_PROCESS_EPARSE. The
 * caller owns
 * *command_netseq and releases it
 * with free(). This legacy C-string form rejects a canonical payload
 * containing NUL; use shell_build_command_netseq_buffer() for lossless
 * transport. */
shell_process_status_t
shell_build_command_netseq(const char *command_line, size_t command_length,
                           const shell_process_limits_t *limits,
                           char **command_netseq, size_t *subcommand_count)
    SHELL_NONNULL(1, 4, 5);

/* Binary-safe form of shell_build_command_netseq(). `sequence` must be empty
 * (initialized to {0} or released with shell_netstring_buffer_free()) and is
 * empty on failure. Release a successful result before reusing it as an output
 * argument. */
shell_process_status_t shell_build_command_netseq_buffer(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *sequence,
    size_t *subcommand_count) SHELL_NONNULL(1, 4, 5);

/* Build one canonical netstring record per supported typed execution-stage
 * signature. Nested substitutions use the same child-before-parent,
 * source-order analysis sequence as shell_build_command_netseq(). An argv-less
 * redirect-only or structural empty Bash `time` stage is represented by a
 * one-word nested netargv with an empty sentinel argv[0]. That sentinel is
 * anomaly-only and is never a policy-evaluable netargv.
 * Control compounds, function declarations, array semantics, and unmodeled
 * Bash `[[ … ]]`, `(( … ))`, `$"…"`, and `;&` / `;;&` forms are
 * rejected with SHELL_PROCESS_EPARSE. The caller owns
 * *type_netseq and releases it
 * with free(). This legacy C-string form rejects a canonical payload
 * containing NUL; use shell_build_type_netseq_buffer() for lossless
 * transport. */
shell_process_status_t
shell_build_type_netseq(const char *command_line, size_t command_length,
                        const shell_process_limits_t *limits,
                        char **type_netseq, size_t *subcommand_count)
    SHELL_NONNULL(1, 4, 5);

/* Binary-safe form of shell_build_type_netseq(). `sequence` must be empty
 * (initialized to {0} or released with shell_netstring_buffer_free()) and is
 * empty on failure. Release a successful result before reusing it as an output
 * argument. */
shell_process_status_t
shell_build_type_netseq_buffer(const char *command_line, size_t command_length,
                               const shell_process_limits_t *limits,
                               shell_netstring_buffer_t *sequence,
                               size_t *subcommand_count) SHELL_NONNULL(1, 4, 5);

/* Build aligned raw-command and typed-command canonical netsequences from one
 * parse of shell source. Both include all supported nested execution stages in
 * child-before-parent, source-order analysis order. An argv-less redirect-only
 * or structural empty Bash `time` stage contributes the anomaly-only empty
 * argv[0] sentinel described above.
 * Each output independently observes `limits`. Control
 * compounds, function declarations, array semantics, and unmodeled Bash
 * `[[ … ]]`, `(( … ))`, `$"…"`, and `;&` / `;;&` forms are rejected
 * with SHELL_PROCESS_EPARSE. All outputs are required and must
 * point to distinct storage. These are caller preconditions. On failure all
 * output destinations are cleared.
 * The caller releases both successful strings with free(). This legacy
 * C-string form rejects a canonical payload containing NUL; use
 * shell_build_anomaly_netseqs_buffer() for lossless transport. */
shell_process_status_t
shell_build_anomaly_netseqs(const char *command_line, size_t command_length,
                            const shell_process_limits_t *limits,
                            char **command_netseq, char **type_netseq,
                            size_t *subcommand_count) SHELL_NONNULL(1, 4, 5, 6);

/* Byte-buffer form of shell_build_anomaly_netseqs(). Both outer netsequences
 * are canonical binary data and callers must use returned lengths rather than
 * strlen(). Complete-command processing rejects NUL-producing ANSI-C source
 * by default; this representation remains binary-capable. `command` and
 * `type` must point to distinct, empty buffers (initialized to {0} or released
 * with shell_netstring_buffer_free()). Distinct empty output objects are a
 * caller precondition. Both remain empty on failure. Release each successful
 * result before reusing it as an output argument. */
shell_process_status_t shell_build_anomaly_netseqs_buffer(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *command,
    shell_netstring_buffer_t *type, size_t *subcommand_count)
    SHELL_NONNULL(1, 4, 5, 6);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_SEQUENCE_H */
