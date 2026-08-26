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

typedef enum {
  SHELL_PROCESS_OK = 0,
  SHELL_PROCESS_EINPUT,
  SHELL_PROCESS_EPARSE,
  SHELL_PROCESS_ENOMEM,
  SHELL_PROCESS_EOVERFLOW,
  SHELL_PROCESS_EOUTPUT_LIMIT
} shell_process_status_t;

/* Limits apply to each returned string and to the aggregate output of one
 * call.  A NULL limits pointer means unbounded output.  Sizes exclude the
 * terminating NUL. */
typedef struct {
  size_t max_string_bytes;
  size_t max_total_bytes;
} shell_process_limits_t;

/**
 * Process exactly `command_length` shell-source bytes with proper separation.
 *
 * Separates shell logic from command arguments. On
 * success, returned command metadata owns all text it refers to and remains
 * valid independently of command_line. Use shell_render_netargv() for the
 * canonical processed-subcommand representation. On failure, writable outputs
 * are set to NULL and zero.
 */
shell_process_status_t
shell_process_command(const char *command_line, size_t command_length,
                      const shell_process_limits_t *limits,
                      shell_command_info_t **command_infos,
                      size_t *command_count);

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
