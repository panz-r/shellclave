#include "shell_netstring.h"
#include "alloc.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static size_t decimal_digits(size_t value) {
  size_t digits = 1;
  while (value >= 10) {
    value /= 10;
    digits++;
  }
  return digits;
}

shell_netstring_status_t shell_netstring_iter_init(shell_netstring_iter_t *iter,
                                                   const void *data,
                                                   size_t length) {
  if (!iter || (!data && length != 0))
    return SHELL_NETSTRING_EINPUT;
  iter->data = data;
  iter->length = length;
  iter->offset = 0;
  return SHELL_NETSTRING_OK;
}

shell_netstring_status_t
shell_netstring_iter_next(shell_netstring_iter_t *iter,
                          shell_netstring_view_t *view) {
  if (!iter || !view || (!iter->data && iter->length != 0))
    return SHELL_NETSTRING_EINPUT;
  view->record = NULL;
  view->record_length = 0;
  view->payload = NULL;
  view->payload_length = 0;
  if (iter->offset == iter->length)
    return SHELL_NETSTRING_DONE;
  if (iter->offset > iter->length)
    return SHELL_NETSTRING_EINPUT;

  size_t start = iter->offset;
  size_t offset = start;
  if (iter->data[offset] < '0' || iter->data[offset] > '9')
    return SHELL_NETSTRING_EFORMAT;
  if (iter->data[offset] == '0' && offset + 1 < iter->length &&
      iter->data[offset + 1] >= '0' && iter->data[offset + 1] <= '9')
    return SHELL_NETSTRING_EFORMAT;

  size_t payload_length = 0;
  do {
    unsigned digit = (unsigned)(iter->data[offset] - '0');
    if (payload_length > (SIZE_MAX - digit) / 10)
      return SHELL_NETSTRING_EOVERFLOW;
    payload_length = payload_length * 10 + digit;
    offset++;
  } while (offset < iter->length && iter->data[offset] >= '0' &&
           iter->data[offset] <= '9');

  if (offset >= iter->length || iter->data[offset++] != ':')
    return SHELL_NETSTRING_EFORMAT;
  if (offset >= iter->length || payload_length >= iter->length - offset)
    return SHELL_NETSTRING_EFORMAT;
  if (iter->data[offset + payload_length] != ',')
    return SHELL_NETSTRING_EFORMAT;

  view->record = iter->data + start;
  view->record_length = offset + payload_length + 1 - start;
  view->payload = iter->data + offset;
  view->payload_length = payload_length;
  iter->offset = offset + payload_length + 1;
  return SHELL_NETSTRING_OK;
}

shell_netstring_status_t shell_netstring_validate(const void *data,
                                                  size_t length,
                                                  size_t *record_count) {
  if (record_count)
    *record_count = 0;
  shell_netstring_iter_t iter;
  shell_netstring_status_t status =
      shell_netstring_iter_init(&iter, data, length);
  if (status != SHELL_NETSTRING_OK)
    return status;
  shell_netstring_view_t view;
  size_t count = 0;
  while ((status = shell_netstring_iter_next(&iter, &view)) ==
         SHELL_NETSTRING_OK) {
    if (count == SIZE_MAX)
      return SHELL_NETSTRING_EOVERFLOW;
    count++;
  }
  if (status != SHELL_NETSTRING_DONE)
    return status;
  if (record_count)
    *record_count = count;
  return SHELL_NETSTRING_OK;
}

shell_netstring_status_t shell_netstring_encoded_length(size_t payload_length,
                                                        size_t *record_length) {
  if (!record_length)
    return SHELL_NETSTRING_EINPUT;
  size_t framing = decimal_digits(payload_length) + 2;
  if (payload_length > SIZE_MAX - framing)
    return SHELL_NETSTRING_EOVERFLOW;
  *record_length = payload_length + framing;
  return SHELL_NETSTRING_OK;
}

shell_netstring_status_t shell_netstring_write_prefix(void *record,
                                                      size_t record_capacity,
                                                      size_t payload_length,
                                                      size_t *prefix_length) {
  if (prefix_length)
    *prefix_length = 0;
  if (!record)
    return SHELL_NETSTRING_EINPUT;
  size_t length = decimal_digits(payload_length) + 1;
  if (record_capacity < length)
    return SHELL_NETSTRING_EOVERFLOW;
  unsigned char *out = record;
  size_t digits = length - 1;
  for (size_t i = digits; i != 0; i--) {
    out[i - 1] = (unsigned char)('0' + payload_length % 10);
    payload_length /= 10;
  }
  out[digits] = ':';
  if (prefix_length)
    *prefix_length = length;
  return SHELL_NETSTRING_OK;
}

shell_netstring_status_t
shell_netstring_write(void *record, size_t record_capacity, const void *payload,
                      size_t payload_length, size_t *written) {
  if (written)
    *written = 0;
  if (!record || (!payload && payload_length != 0))
    return SHELL_NETSTRING_EINPUT;
  size_t needed = 0;
  shell_netstring_status_t status =
      shell_netstring_encoded_length(payload_length, &needed);
  if (status != SHELL_NETSTRING_OK)
    return status;
  if (record_capacity < needed)
    return SHELL_NETSTRING_EOVERFLOW;
  unsigned char *out = record;
  size_t prefix = 0;
  if (shell_netstring_write_prefix(out, record_capacity, payload_length,
                                   &prefix) != SHELL_NETSTRING_OK)
    return SHELL_NETSTRING_EOVERFLOW;
  if (payload_length)
    memcpy(out + prefix, payload, payload_length);
  out[needed - 1] = ',';
  if (written)
    *written = needed;
  return SHELL_NETSTRING_OK;
}

shell_netstring_status_t shell_netstring_read_stream(FILE *stream,
                                                     size_t max_record_length,
                                                     unsigned char **record,
                                                     size_t *record_length) {
  if (record)
    *record = NULL;
  if (record_length)
    *record_length = 0;
  if (!stream || !record || !record_length)
    return SHELL_NETSTRING_EINPUT;
  int ch = fgetc(stream);
  if (ch == EOF)
    return ferror(stream) ? SHELL_NETSTRING_EIO : SHELL_NETSTRING_DONE;
  if (ch < '0' || ch > '9')
    return SHELL_NETSTRING_EFORMAT;
  bool leading_zero = ch == '0';
  size_t payload_length = 0, digits = 0;
  do {
    if (payload_length > (SIZE_MAX - (unsigned)(ch - '0')) / 10)
      return SHELL_NETSTRING_EOVERFLOW;
    payload_length = payload_length * 10 + (unsigned)(ch - '0');
    digits++;
    ch = fgetc(stream);
  } while (ch >= '0' && ch <= '9');
  if (ch != ':' || (leading_zero && digits != 1))
    return ch == EOF && ferror(stream) ? SHELL_NETSTRING_EIO
                                       : SHELL_NETSTRING_EFORMAT;
  size_t total = 0;
  if (shell_netstring_encoded_length(payload_length, &total) !=
          SHELL_NETSTRING_OK ||
      total == SIZE_MAX || (max_record_length && total > max_record_length))
    return SHELL_NETSTRING_EOVERFLOW;
  unsigned char *out = malloc(total + 1);
  if (!out)
    return SHELL_NETSTRING_ENOMEM;
  size_t prefix = 0;
  (void)shell_netstring_write_prefix(out, total, payload_length, &prefix);
  if (payload_length &&
      fread(out + prefix, 1, payload_length, stream) != payload_length) {
    free(out);
    return ferror(stream) ? SHELL_NETSTRING_EIO : SHELL_NETSTRING_EFORMAT;
  }
  ch = fgetc(stream);
  if (ch != ',') {
    free(out);
    return ch == EOF && ferror(stream) ? SHELL_NETSTRING_EIO
                                       : SHELL_NETSTRING_EFORMAT;
  }
  out[total - 1] = ',';
  out[total] = '\0';
  *record = out;
  *record_length = total;
  return SHELL_NETSTRING_OK;
}
