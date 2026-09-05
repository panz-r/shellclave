#ifndef SHELL_SEQUENCE_H
#define SHELL_SEQUENCE_H

#include "shell_processor.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Build a canonical netsequence with one outer netstring record per isolated
 * supported subcommand. Each record's payload is that subcommand's canonical
 * netargv. Supported compound groups contain simple-command lists, pipelines,
 * and nested brace/subshell groups. Control compounds (loops, conditionals,
 * and case statements) are rejected with SHELL_PROCESS_EPARSE. Redirect-only
 * simple commands are likewise rejected because they have no argv to encode.
 * The semantic model has a fixed SHELL_MAX_SUBCOMMANDS capacity; a source that
 * exceeds it returns SHELL_PROCESS_EOUTPUT_LIMIT even when `limits` is NULL.
 * When
 * limits->max_group_io_ops is nonzero, it is validated against the source
 * group I/O even though group metadata is not returned in the netsequence. The
 * caller owns *netargv_sequence and releases it with free(). This legacy
 * C-string form rejects a canonical payload containing NUL; use
 * shell_build_netargv_sequence_buffer() for lossless transport. */
shell_process_status_t
shell_build_netargv_sequence(const char *command_line, size_t command_length,
                             const shell_process_limits_t *limits,
                             char **netargv_sequence, size_t *subcommand_count,
                             bool *has_shell_features);

/* Binary-safe form of shell_build_netargv_sequence(). The outer sequence and
 * every nested netargv record are length-delimited; payloads may contain NUL.
 * `sequence` must be empty (initialized to {0} or released with
 * shell_netstring_buffer_free()); it is empty on failure. A populated or
 * inconsistent output is rejected without modification. Release a successful
 * result before reusing it as an output argument. */
shell_process_status_t shell_build_netargv_sequence_buffer(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *sequence,
    size_t *subcommand_count, bool *has_shell_features);

/* Build one canonical netstring record per isolated decoded executable name.
 * Control compounds (loops, conditionals, and case statements) are rejected
 * with SHELL_PROCESS_EPARSE. The caller owns *command_netseq and releases it
 * with free(). This legacy C-string form rejects a canonical payload
 * containing NUL; use shell_build_command_netseq_buffer() for lossless
 * transport. */
shell_process_status_t
shell_build_command_netseq(const char *command_line, size_t command_length,
                           const shell_process_limits_t *limits,
                           char **command_netseq, size_t *subcommand_count);

/* Binary-safe form of shell_build_command_netseq(). `sequence` must be empty
 * (initialized to {0} or released with shell_netstring_buffer_free()) and is
 * empty on failure. A populated or inconsistent output is rejected without
 * modification. Release a successful result before reusing it as an output
 * argument. */
shell_process_status_t shell_build_command_netseq_buffer(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *sequence,
    size_t *subcommand_count);

/* Build one canonical netstring record per isolated typed command signature.
 * Control compounds (loops, conditionals, and case statements) are rejected
 * with SHELL_PROCESS_EPARSE. The caller owns *type_netseq and releases it
 * with free(). This legacy C-string form rejects a canonical payload
 * containing NUL; use shell_build_type_netseq_buffer() for lossless
 * transport. */
shell_process_status_t
shell_build_type_netseq(const char *command_line, size_t command_length,
                        const shell_process_limits_t *limits,
                        char **type_netseq, size_t *subcommand_count);

/* Binary-safe form of shell_build_type_netseq(). `sequence` must be empty
 * (initialized to {0} or released with shell_netstring_buffer_free()) and is
 * empty on failure. A populated or inconsistent output is rejected without
 * modification. Release a successful result before reusing it as an output
 * argument. */
shell_process_status_t
shell_build_type_netseq_buffer(const char *command_line, size_t command_length,
                               const shell_process_limits_t *limits,
                               shell_netstring_buffer_t *sequence,
                               size_t *subcommand_count);

/* Build aligned raw-command and typed-command canonical netsequences from one
 * parse of shell source. Each output independently observes `limits`. Control
 * compounds (loops, conditionals, and case statements) are rejected with
 * SHELL_PROCESS_EPARSE. All outputs are required and must point to distinct
 * storage; aliased output destinations return SHELL_PROCESS_EINPUT. On failure
 * valid output destinations are cleared.
 * The caller releases both successful strings with free(). This legacy
 * C-string form rejects a canonical payload containing NUL; use
 * shell_build_anomaly_netseqs_buffer() for lossless transport. */
shell_process_status_t
shell_build_anomaly_netseqs(const char *command_line, size_t command_length,
                            const shell_process_limits_t *limits,
                            char **command_netseq, char **type_netseq,
                            size_t *subcommand_count);

/* Byte-buffer form of shell_build_anomaly_netseqs(). Both outer netsequences
 * are canonical binary data: an ANSI-C quoted executable may contain a NUL,
 * so callers must use the returned lengths rather than strlen(). `command` and
 * `type` must point to distinct, empty buffers (initialized to {0} or released
 * with shell_netstring_buffer_free()). Both are empty on failure. A populated
 * or inconsistent output is rejected without modification. Release each
 * successful result before reusing it as an output argument. */
shell_process_status_t shell_build_anomaly_netseqs_buffer(
    const char *command_line, size_t command_length,
    const shell_process_limits_t *limits, shell_netstring_buffer_t *command,
    shell_netstring_buffer_t *type, size_t *subcommand_count);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_SEQUENCE_H */
