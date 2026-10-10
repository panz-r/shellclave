#ifndef SHELL_NETSTRING_H
#define SHELL_NETSTRING_H

#include "shell_contract.h"

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
 * output argument. Empty initialized output storage is a caller requirement. */
typedef struct {
  unsigned char *data;
  size_t length;
} shell_netstring_buffer_t;

/* Release an owned canonical buffer and reset it. NULL is a no-op. */
void shell_netstring_buffer_free(shell_netstring_buffer_t *buffer);

/* Return true only for a valid empty owned-output buffer. */
bool shell_netstring_buffer_is_empty(const shell_netstring_buffer_t *buffer)
    SHELL_NONNULL(1);

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
                                                   size_t length)
    SHELL_NONNULL(1);

/* The iterator must be initialized and not edited by the caller. Both pointers
 * are required. Return the next complete record, DONE at end, or an error for
 * malformed/non-canonical framing. On error the iterator remains positioned at
 * the invalid record. */
shell_netstring_status_t shell_netstring_iter_next(shell_netstring_iter_t *iter,
                                                   shell_netstring_view_t *view)
    SHELL_NONNULL(1, 2);

/* Validate a complete concatenation of canonical netstrings. If non-NULL,
 * `record_count` receives the number of records. */
shell_netstring_status_t
shell_netstring_validate(const void *data, size_t length, size_t *record_count);

/* Return the exact bytes required for one canonical record. */
shell_netstring_status_t shell_netstring_encoded_length(size_t payload_length,
                                                        size_t *record_length)
    SHELL_NONNULL(2);

/* Write only the canonical decimal length and colon. This supports producers
 * that stream or generate the payload directly into its final destination.
 * record references record_capacity writable bytes. prefix_length may be NULL
 * when the caller does not need the count; otherwise it is distinct writable
 * storage, not part of the output span. */
shell_netstring_status_t
shell_netstring_write_prefix(void *record, size_t record_capacity,
                             size_t payload_length, size_t *prefix_length)
    SHELL_NONNULL(1);

/* Encode one record into caller-provided storage. `payload` may be NULL only
 * for an empty payload; otherwise it references payload_length readable bytes.
 * record references record_capacity writable bytes. The payload and encoded
 * output spans must not overlap. If non-NULL, written receives the record
 * length in distinct writable storage, not overlapping either byte span. */
shell_netstring_status_t
shell_netstring_write(void *record, size_t record_capacity, const void *payload,
                      size_t payload_length, size_t *written) SHELL_NONNULL(1);

/* Read one complete canonical record from a byte stream. DONE means clean EOF.
 * `max_record_length` bounds the encoded record (zero means unbounded). The
 * returned allocation is NUL-terminated for convenience but its explicit
 * length excludes that terminator. The caller releases a successful record
 * with free(). */
shell_netstring_status_t
shell_netstring_read_stream(FILE *stream, size_t max_record_length,
                            unsigned char **record, size_t *record_length)
    SHELL_NONNULL(1, 3, 4);

#ifdef __cplusplus
}
#endif

#endif /* SHELL_NETSTRING_H */
