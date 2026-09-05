#ifndef SHELL_NETSTRING_H
#define SHELL_NETSTRING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A view into one canonical netstring. Both spans borrow from the input
 * passed to shell_netstring_iter_init(); they are never NUL-terminated. */
typedef struct {
  const unsigned char *record;
  size_t record_length;
  const unsigned char *payload;
  size_t payload_length;
} shell_netstring_view_t;

/* Owned binary storage for a canonical netstring or netstring sequence.
 * `data` is not a C string: payloads may contain NUL bytes and callers must
 * always use `length`. Initialize to {0}, and release with
 * shell_netstring_buffer_free(). Producer APIs require an empty buffer: call
 * shell_netstring_buffer_free() before reusing a successful result as an
 * output argument. Producers reject non-empty or inconsistent buffers without
 * modifying them. */
typedef struct {
  unsigned char *data;
  size_t length;
} shell_netstring_buffer_t;

/* Release an owned canonical buffer and reset it. NULL is a no-op. */
void shell_netstring_buffer_free(shell_netstring_buffer_t *buffer);

/* Return true only for a valid empty owned-output buffer. */
bool shell_netstring_buffer_is_empty(const shell_netstring_buffer_t *buffer);

/* Stateful, allocation-free iterator over concatenated canonical netstrings.
 * The input is byte-oriented: payloads may contain NUL bytes. */
typedef struct {
  const unsigned char *data;
  size_t length;
  size_t offset;
} shell_netstring_iter_t;

typedef enum {
  SHELL_NETSTRING_OK = 0,
  SHELL_NETSTRING_DONE,
  SHELL_NETSTRING_EINPUT,
  SHELL_NETSTRING_EFORMAT,
  SHELL_NETSTRING_EOVERFLOW,
  SHELL_NETSTRING_EIO,
  SHELL_NETSTRING_ENOMEM,
} shell_netstring_status_t;

/* Initialize an iterator over `length` bytes. NULL is valid only for an empty
 * sequence. The input remains owned by the caller and must outlive iteration.
 */
shell_netstring_status_t shell_netstring_iter_init(shell_netstring_iter_t *iter,
                                                   const void *data,
                                                   size_t length);

/* Return the next complete canonical record, DONE at end, or an error for
 * malformed/non-canonical framing. On error the iterator remains positioned at
 * the invalid record. */
shell_netstring_status_t
shell_netstring_iter_next(shell_netstring_iter_t *iter,
                          shell_netstring_view_t *view);

/* Validate a complete concatenation of canonical netstrings. If non-NULL,
 * `record_count` receives the number of records. */
shell_netstring_status_t
shell_netstring_validate(const void *data, size_t length, size_t *record_count);

/* Return the exact bytes required for one canonical record. */
shell_netstring_status_t shell_netstring_encoded_length(size_t payload_length,
                                                        size_t *record_length);

/* Write only the canonical decimal length and colon. This supports producers
 * that stream or generate the payload directly into its final destination. */
shell_netstring_status_t shell_netstring_write_prefix(void *record,
                                                      size_t record_capacity,
                                                      size_t payload_length,
                                                      size_t *prefix_length);

/* Encode one record into caller-provided storage. `payload` may be NULL only
 * for an empty payload. `written` receives the complete record length. */
shell_netstring_status_t
shell_netstring_write(void *record, size_t record_capacity, const void *payload,
                      size_t payload_length, size_t *written);

/* Read one complete canonical record from a byte stream. DONE means clean EOF.
 * `max_record_length` bounds the encoded record (zero means unbounded). The
 * returned allocation is NUL-terminated for convenience but its explicit
 * length excludes that terminator. The caller releases a successful record
 * with free(). */
shell_netstring_status_t shell_netstring_read_stream(FILE *stream,
                                                     size_t max_record_length,
                                                     unsigned char **record,
                                                     size_t *record_length);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_NETSTRING_H */
