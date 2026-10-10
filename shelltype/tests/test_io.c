#define _POSIX_C_SOURCE 200809L

#include "test_io.h"
#include "../../shellsplit/src/shell_file_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static _Thread_local size_t fail_at;
static _Thread_local size_t crash_after;
static _Thread_local size_t operation_count;
static _Thread_local size_t read_fail_at;
static _Thread_local size_t read_count;
static _Thread_local const unsigned char *temp_random;

static int should_fail(void) {
  operation_count++;
  return fail_at != 0 && operation_count == fail_at;
}

static void maybe_crash(void) {
  if (crash_after != 0 && operation_count == crash_after)
    _exit(91);
}

void st_test_io_fail_at(size_t operation_index) {
  fail_at = operation_index;
  operation_count = 0;
}

void st_test_io_crash_after(size_t operation_index) {
  crash_after = operation_index;
  operation_count = 0;
}

void st_test_io_reset(void) {
  fail_at = 0;
  crash_after = 0;
  operation_count = 0;
  read_fail_at = 0;
  read_count = 0;
  temp_random = NULL;
}

void st_test_io_temp_random_set(const unsigned char *random) {
  temp_random = random;
}

size_t st_test_io_count(void) { return operation_count; }

void st_test_read_fail_at(size_t line_index) {
  read_fail_at = line_index;
  read_count = 0;
}

size_t st_test_read_count(void) { return read_count; }

int st_test_read_line_should_fail(void) {
  read_count++;
  return read_fail_at != 0 && read_count == read_fail_at;
}

int st_test_fprintf(FILE *stream, const char *format, ...) {
  if (should_fail())
    return -1;
  va_list args;
  va_start(args, format);
  int result = vfprintf(stream, format, args);
  va_end(args);
  if (result >= 0)
    maybe_crash();
  return result;
}

int st_test_fflush(FILE *stream) {
  if (should_fail())
    return EOF;
  int result = fflush(stream);
  if (result == 0)
    maybe_crash();
  return result;
}

int st_test_fclose(FILE *stream) {
  int result = fclose(stream);
  if (should_fail())
    return EOF;
  if (result == 0)
    maybe_crash();
  return result;
}

int st_test_renameat(int old_directory, const char *old_name, int new_directory,
                     const char *new_name) {
  if (should_fail())
    return -1;
  int result = renameat(old_directory, old_name, new_directory, new_name);
  if (result == 0)
    maybe_crash();
  return result;
}

int st_test_create_temp_at(int directory, const char *destination_name,
                           char *name) {
  if (should_fail())
    return -1;
  int result =
      temp_random
          ? shell_file_create_temp_from_bytes(directory, destination_name,
                                              temp_random, name)
          : shell_file_create_temp_at(directory, destination_name, name);
  if (result >= 0)
    maybe_crash();
  return result;
}

FILE *st_test_fdopen(int fd, const char *mode) {
  if (should_fail())
    return NULL;
  FILE *result = fdopen(fd, mode);
  if (result)
    maybe_crash();
  return result;
}

int st_test_fsync(int fd) {
  if (should_fail())
    return -1;
  int result = fsync(fd);
  if (result == 0)
    maybe_crash();
  return result;
}

int st_test_open(const char *path, int flags) {
  if (should_fail())
    return -1;
  int result = open(path, flags);
  if (result >= 0)
    maybe_crash();
  return result;
}

int st_test_close(int fd) {
  int result = close(fd);
  if (should_fail())
    return -1;
  if (result == 0)
    maybe_crash();
  return result;
}

int st_test_unlinkat(int directory, const char *name, int flags) {
  if (should_fail())
    return -1;
  int result = unlinkat(directory, name, flags);
  if (result == 0)
    maybe_crash();
  return result;
}

int st_test_fstatat(int directory, const char *name, struct stat *status,
                    int flags) {
  if (should_fail()) {
    errno = EIO;
    return -1;
  }
  int result = fstatat(directory, name, status, flags);
  if (result == 0 || errno == ENOENT)
    maybe_crash();
  return result;
}

int st_test_fchmod(int fd, mode_t mode) {
  if (should_fail())
    return -1;
  int result = fchmod(fd, mode);
  if (result == 0)
    maybe_crash();
  return result;
}
