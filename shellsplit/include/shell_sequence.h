#ifndef SHELL_SEQUENCE_H
#define SHELL_SEQUENCE_H

#include "shell_contract.h"

#include "shell_processor.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Build one outer netstring per isolated supported subcommand, containing its
 * canonical netargv. The outer sequence and every nested record are
 * length-delimited; payloads may contain NUL. Bash `time` prefixes are
 * structural metadata, never argv. Empty timing pipelines contribute no
 * record but set has_shell_features. Arithmetic commands likewise contribute
 * no argv record and set that flag; their anomaly signatures remain separate.
 * Redirect-only simple commands are rejected because they have no
 * policy-evaluable argv. Enclosing group I/O
 * cannot turn an empty timing endpoint into a policy subject.
 * Supported compound groups contain simple-command lists, pipelines and nested
 * brace/subshell groups. Control compounds, function declarations, array
 * semantics, dynamic/mutating arithmetic, wider [[ … ]] predicates, $"…", ;&
 * and
 * ;;&, and active legacy backtick bodies requiring escape-layer removal
 * return SHELL_PROCESS_EPARSE;
 * see shell_depgraph.h for the supported-source contract.
 * Exceeding SHELL_MAX_SUBCOMMANDS returns SHELL_PROCESS_EOUTPUT_LIMIT even
 * without limits. A nonzero max_group_io_ops checks source group I/O even
 * though group metadata is not returned.
 * `sequence` must be empty (initialized to {0} or released with
 * shell_netstring_buffer_free()); it is empty on failure. Release a successful
 * result before reusing it as an output argument. */
shell_process_status_t shell_build_netargv_sequence_buffer(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *sequence,
    size_t *subcommand_count, bool *has_shell_features)
    SHELL_NONNULL(1, 4, 5, 6);

/* Build one canonical netstring record per supported execution stage.
 * This includes stages reached through command substitutions,
 * backticks, process substitutions, and unquoted heredoc expansion bodies.
 * Dynamic or mutating arithmetic is rejected before stage collection. Nested
 * stages precede their enclosing
 * command; sibling stages retain source order. This is deterministic analysis
 * order, not a claim about runtime scheduling. An argv-less redirect-only or
 * structural empty Bash `time` stage, or arithmetic/conditional command, is
 * represented by one empty record: its empty payload is the anomaly-only
 * sentinel argv[0]. This is not a netargv transport and must never be used to
 * authorize execution. All executable stages retain their decoded
 * executable-name records. Source-only sequence builders validate without
 * descriptor-entry context; read roles/target projections requiring captured
 * scalar values may return SHELL_PROCESS_EPARSE even when semantic graph
 * construction proves support. Byte limits apply to the final encoded sequence,
 * not unreturned arguments or other borrowed source text. A nonzero
 * max_group_io_ops is one cumulative budget across the immediate list and all
 * collected nested execution bodies. Control compounds, function declarations,
 * array semantics, dynamic or mutating arithmetic, and wider Bash `[[ … ]]`
 * predicates, `$"…"`, and `;&` / `;;&` forms are rejected with
 * SHELL_PROCESS_EPARSE. The result is binary-safe. `sequence` must be empty
 * (initialized to {0} or released with shell_netstring_buffer_free()) and is
 * empty on failure. Release a successful result before reusing it as an output
 * argument. */
shell_process_status_t shell_build_command_netseq_buffer(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *sequence,
    size_t *subcommand_count) SHELL_NONNULL(1, 4, 5);

/* Build one canonical netstring record per supported typed execution-stage
 * signature. Nested substitutions use the same child-before-parent,
 * source-order analysis sequence and context-free supported-source boundary as
 * shell_build_command_netseq_buffer(). An argv-less redirect-only or structural
 * empty Bash `time` stage is represented
 * by a one-word nested netargv with an empty sentinel argv[0]. That sentinel is
 * anomaly-only and is never a policy-evaluable netargv. An arithmetic stage
 * extends this signature with AR after the empty argv[0]; a conditional
 * stage uses CT.
 * Control compounds, function declarations, array semantics,
 * wider Bash `[[ … ]]` predicates, dynamic/mutating arithmetic commands,
 * `$"…"`, and `;&` /
 * `;;&` forms are rejected with SHELL_PROCESS_EPARSE. `sequence` must be empty
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
 * argv[0] sentinel and context-free supported-source boundary described above.
 * Each output independently observes `limits`. Control
 * compounds, function declarations, array semantics, and wider Bash
 * `[[ … ]]` predicates, dynamic/mutating arithmetic commands, `$"…"`, and `;&`
 * / `;;&` forms are rejected with SHELL_PROCESS_EPARSE. All outputs are
 * required and must point to distinct storage. These are caller preconditions.
 * On failure all output destinations are cleared. Both outer netsequences are
 * canonical binary data and callers must use returned lengths rather than
 * strlen(). Source-derived ANSI-C values truncate at the first decoded NUL in
 * each fragment; directly supplied payloads remain binary-capable. `command`
 * and `type` must point to distinct, empty buffers (initialized to {0} or
 * released with shell_netstring_buffer_free()). Distinct empty output objects
 * are a caller precondition. Both remain empty on failure. Release each
 * successful result before reusing it as an output argument. */
shell_process_status_t shell_build_anomaly_netseqs_buffer(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *command,
    shell_netstring_buffer_t *type, size_t *subcommand_count)
    SHELL_NONNULL(1, 4, 5, 6);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_SEQUENCE_H */
