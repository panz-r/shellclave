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
 * caller owns *netargv_sequence and releases it with free(). */
shell_process_status_t
shell_build_netargv_sequence(const char *command_line, size_t command_length,
                             const shell_process_limits_t *limits,
                             char **netargv_sequence, size_t *subcommand_count,
                             bool *has_shell_features);

/* Build one canonical netstring record per isolated decoded executable name.
 * Control compounds (loops, conditionals, and case statements) are rejected
 * with SHELL_PROCESS_EPARSE. The caller owns *command_netseq and releases it
 * with free(). */
shell_process_status_t
shell_build_command_netseq(const char *command_line, size_t command_length,
                           const shell_process_limits_t *limits,
                           char **command_netseq, size_t *subcommand_count);

/* Build one canonical netstring record per isolated typed command signature.
 * Control compounds (loops, conditionals, and case statements) are rejected
 * with SHELL_PROCESS_EPARSE. The caller owns *type_netseq and releases it
 * with free(). */
shell_process_status_t
shell_build_type_netseq(const char *command_line, size_t command_length,
                        const shell_process_limits_t *limits,
                        char **type_netseq, size_t *subcommand_count);

/* Build aligned raw-command and typed-command canonical netsequences from one
 * parse of shell source. Each output independently observes `limits`. Control
 * compounds (loops, conditionals, and case statements) are rejected with
 * SHELL_PROCESS_EPARSE. All outputs are required; on failure they are cleared.
 * The caller releases both successful strings with free(). */
shell_process_status_t
shell_build_anomaly_netseqs(const char *command_line, size_t command_length,
                            const shell_process_limits_t *limits,
                            char **command_netseq, char **type_netseq,
                            size_t *subcommand_count);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_SEQUENCE_H */
