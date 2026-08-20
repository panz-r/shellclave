#ifndef SHELLTYPE_READ_LINE_H
#define SHELLTYPE_READ_LINE_H

#include <stddef.h>
#include <stdio.h>

typedef enum {
  ST_LINE_OK,
  ST_LINE_EOF,
  ST_LINE_IO,
  ST_LINE_NUL,
  ST_LINE_TOO_LONG,
} st_line_status_t;

#ifdef SHELLTYPE_TEST_IO
int st_test_read_line_should_fail(void);
#endif

/* Read one physical line while retaining the fixed 4095-byte serialized-line
 * contract. Unlike fgets/strlen, this can distinguish embedded NUL bytes from
 * the terminator added by the reader. */
static inline st_line_status_t st_read_line(FILE *fp, char *buffer,
                                            size_t capacity) {
#ifdef SHELLTYPE_TEST_IO
  if (st_test_read_line_should_fail())
    return ST_LINE_IO;
#endif
  size_t length = 0;
  int ch;
  while ((ch = fgetc(fp)) != EOF) {
    if (ch == 0)
      return ST_LINE_NUL;
    if (length + 1 >= capacity)
      return ST_LINE_TOO_LONG;
    buffer[length++] = (char)ch;
    if (ch == '\n')
      break;
  }
  if (ch == EOF) {
    if (ferror(fp))
      return ST_LINE_IO;
    if (length == 0)
      return ST_LINE_EOF;
  }
  buffer[length] = '\0';
  return ST_LINE_OK;
}

#endif
