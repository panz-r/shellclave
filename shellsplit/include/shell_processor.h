#ifndef SHELL_PROCESSOR_H
#define SHELL_PROCESSOR_H

#include "shell_tokenizer_full.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parsed command metadata for downstream consumers.
 */

/**
 * Parsed shell command metadata, including original text and tokenized details.
 */
typedef struct {
  const char *original_command; // Owned full command-stage text
  // Token text points into original_command, and positions are relative to it.
  shell_token_t *shell_tokens;   // Shell operators and redirections
  size_t shell_token_count;      // Number of shell tokens
  shell_token_t *command_tokens; // Command arguments only
  size_t command_token_count;    // Number of command arguments
  bool has_pipe_input;           // Has pipe input (|)
  bool has_pipe_output;          // Has pipe output (|)
  bool has_redirections;         // Has any redirections
  bool has_error_redirection;    // Has error redirection (2>)
} shell_command_info_t;

/* One source-order I/O or execution-list operation attached to a complete
 * compound group rather than any one of its enclosed simple commands.
 * Descriptor duplication and close semantics are order-sensitive: consumers
 * that model descriptor routing must apply consecutive operations in this
 * order. */
typedef enum {
  SHELL_GROUP_IO_READ_FILE,
  SHELL_GROUP_IO_WRITE_FILE,
  SHELL_GROUP_IO_APPEND_FILE,
  SHELL_GROUP_IO_HEREDOC,
  SHELL_GROUP_IO_HERESTRING,
  SHELL_GROUP_IO_DUP_FD,
  SHELL_GROUP_IO_CLOSE_FD,
  SHELL_GROUP_IO_PIPE_INPUT,
  SHELL_GROUP_IO_PIPE_OUTPUT,
  SHELL_GROUP_IO_BACKGROUND,
  /* `<>word` opens one descriptor for both input and output. */
  SHELL_GROUP_IO_READ_WRITE_FILE,
  /* `< <(command)` supplies dynamic input from a process substitution. */
  SHELL_GROUP_IO_PROCESS_SUB_IN,
  /* `> >(command)` or `>> >(command)` sends output to a process substitution.
   */
  SHELL_GROUP_IO_PROCESS_SUB_OUT,
  /* `<> <(command)` supplies dynamic input through the read side. */
  SHELL_GROUP_IO_PROCESS_SUB_RW_IN,
  /* `<> >(command)` delivers writes through the write side. */
  SHELL_GROUP_IO_PROCESS_SUB_RW_OUT,
  /* A cross-direction redirect such as `< >(command)` or `> <(command)`
   * evaluates the nested process but establishes no modeled byte route between
   * the group descriptor and that process. */
  SHELL_GROUP_IO_PROCESS_SUB_UNROUTED,
} shell_group_io_kind_t;

/** Source-relative metadata for one group-owned I/O operation. `source_*`
 * covers the complete operator and operand; `operand_*` isolates the operand
 * and excludes deferred heredoc body data. `fd` is always the effective file
 * descriptor. `target_fd` is meaningful only for SHELL_GROUP_IO_DUP_FD and
 * is UINT32_MAX for every other operation. Explicit descriptor values are
 * limited to INT_MAX, leaving UINT32_MAX as an unambiguous no-descriptor
 * sentinel. Process-substitution kinds retain
 * the complete `<(command)` or `>(command)` operand, rather than representing
 * it as a file. The caller retains the source input while inspecting these
 * spans. PROCESS_SUB_UNROUTED retains valid process-substitution syntax that
 * has no direct byte relation in the graph. The read/write process-substitution
 * kinds identify the operand's known stream direction without representing it
 * as a filesystem path. */
typedef struct {
  uint16_t group_index;
  uint32_t source_start;
  uint32_t source_end;
  uint32_t operand_start;
  uint32_t operand_end;
  uint32_t fd;
  uint32_t target_fd;
  shell_group_io_kind_t kind;
} shell_group_io_op_t;

/** Owned canonical command result with the structural group descriptors from
 * the same source command. `commands` has one entry per retained
 * simple-command range; each group's first_command and command_count index
 * this array, not the source fast-parser ranges.
 * group-attached I/O and external pipeline state are represented by ordered
 * `group_io_ops`, never attributed to the final enclosed command. Several
 * operations may share a group index and preserve source order; group indexes
 * refer to `groups`, whose source spans remain authoritative. */
typedef struct {
  shell_command_info_t *commands;
  size_t command_count;
  shell_group_t *groups;
  size_t group_count;
  shell_group_io_op_t *group_io_ops;
  size_t group_io_op_count;
} shell_processed_commands_t;

typedef enum {
  SHELL_PROCESS_OK = 0,
  SHELL_PROCESS_EINPUT,
  SHELL_PROCESS_EPARSE,
  SHELL_PROCESS_ENOMEM,
  SHELL_PROCESS_EOVERFLOW,
  SHELL_PROCESS_EOUTPUT_LIMIT
} shell_process_status_t;

/* Limits apply to each returned string, aggregate output, and compound-group
 * operation metadata of one call. A NULL limits pointer means unbounded
 * output. Sizes exclude the terminating NUL. `max_group_io_ops == 0` leaves
 * group-operation metadata unbounded, preserving existing initializers. */
typedef struct {
  size_t max_string_bytes;
  size_t max_total_bytes;
  size_t max_group_io_ops;
} shell_process_limits_t;

/**
 * Process exactly `command_length` shell-source bytes with proper separation.
 *
 * Separates shell logic from command arguments. On
 * success, returned command metadata owns all text it refers to and remains
 * valid independently of command_line. Use shell_render_netargv() for the
 * canonical processed-subcommand representation. This flat record API retains
 * the full tokenizer's tolerant lexical handling for incomplete source, while
 * shell_process_commands() requires a complete form it can model. Recognized
 * POSIX control compounds (loops,
 * conditionals, and case statements) are not modeled and return
 * SHELL_PROCESS_EPARSE. Supported compound groups contain simple-command
 * lists, pipelines, and nested brace/subshell groups; callers must not infer
 * support for POSIX control compounds from group support. On failure, writable
 * outputs are set to NULL and zero.
 */
shell_process_status_t
shell_process_command(const char *command_line, size_t command_length,
                      const shell_process_limits_t *limits,
                      shell_command_info_t **command_infos,
                      size_t *command_count);

/** Process supported canonical command records and return the complete
 * brace/subshell group descriptors from the same source. The fixed semantic
 * model accepts at most SHELL_MAX_SUBCOMMANDS ranges and returns
 * SHELL_PROCESS_EOUTPUT_LIMIT beyond that capacity. Group contents may be
 * simple-command lists, pipelines, and nested groups. Control compounds
 * return SHELL_PROCESS_EPARSE. The result owns all returned storage and is
 * cleared on failure. */
shell_process_status_t
shell_process_commands(const char *command_line, size_t command_length,
                       const shell_process_limits_t *limits,
                       shell_processed_commands_t *result);

/** Release a result returned by shell_process_commands(). Safe with NULL. */
void shell_processed_commands_free(shell_processed_commands_t *result);

/**
 * Free shell_command_info_t values and associated owned allocations.
 * Safe to call with a NULL pointer.
 */
void shell_command_infos_free(shell_command_info_t *infos, size_t count);

/** Measure the decoded payload of one already-isolated shell word, assembling
 * quote fragments and escapes. This is not shell tokenization: callers must
 * isolate the word before calling it. */
shell_process_status_t shell_measure_decoded_word(const char *text,
                                                  size_t length,
                                                  size_t *decoded_length);

/** Write the decoded payload of one already-isolated shell word into caller
 * storage. The destination is a byte buffer, not a C string; it must provide
 * at least the length returned by shell_measure_decoded_word(). */
shell_process_status_t shell_write_decoded_word(const char *text, size_t length,
                                                char *destination,
                                                size_t destination_size,
                                                size_t *written);

/** Measure one isolated shell word for canonical argv. Ordinary shell quotes
 * and escapes are removed, while executable substitution and arithmetic
 * fragments retain their exact source spelling so they remain inspectable and
 * syntactically unambiguous. */
shell_process_status_t shell_measure_processed_word(const char *text,
                                                    size_t length,
                                                    size_t *processed_length);

/** Write one word measured by shell_measure_processed_word(). The destination
 * is a byte buffer, not a C string. */
shell_process_status_t
shell_write_processed_word(const char *text, size_t length, char *destination,
                           size_t destination_size, size_t *written);

/** Decode one already-isolated shell word into an owned C string, assembling
 * quote fragments and escapes. Prefer the measure/write pair when the decoded
 * bytes will be written directly into another representation. */
shell_process_status_t shell_decode_word(const char *text, size_t length,
                                         char **decoded,
                                         size_t *decoded_length);

/** Return the bytes required to encode one command's already-processed
 * arguments as concatenated canonical netstrings, excluding the terminating
 * NUL. */
shell_process_status_t shell_measure_netargv(const shell_command_info_t *info,
                                             size_t *netargv_length);

/** Write one command's canonical netargv into caller storage. `destination`
 * must provide the measured encoded length plus one byte for the terminating
 * NUL. `written` excludes that NUL. On failure no partial netargv is exposed.
 */
shell_process_status_t shell_write_netargv(const shell_command_info_t *info,
                                           char *destination,
                                           size_t destination_size,
                                           size_t *written);

/** Encode one command's already-processed arguments as concatenated canonical
 * netstrings. This allocating convenience wrapper owns *netargv. */
shell_process_status_t
shell_render_netargv(const shell_command_info_t *info,
                     const shell_process_limits_t *limits, char **netargv);

/**
 * Check if a command uses shell operators, redirections, or execution-bearing
 * substitutions that require shell-aware handling.
 */
bool shell_command_info_has_dangerous_features(
    const shell_command_info_t *info);

#ifdef __cplusplus
}
#endif

#endif // SHELL_PROCESSOR_H
