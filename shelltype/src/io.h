#ifndef SHELLTYPE_IO_H
#define SHELLTYPE_IO_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Test builds redirect save-side I/O through deterministic hooks. Production
 * builds continue to call libc directly. */
#ifdef SHELLTYPE_TEST_IO
int st_test_fprintf(FILE *stream, const char *format, ...);
int st_test_fflush(FILE *stream);
int st_test_fclose(FILE *stream);
int st_test_rename(const char *old_path, const char *new_path);
int st_test_mkstemp(char *template_path);
FILE *st_test_fdopen(int fd, const char *mode);
int st_test_fsync(int fd);
int st_test_open(const char *path, int flags);
int st_test_close(int fd);
int st_test_unlink(const char *path);
int st_test_lstat(const char *path, struct stat *status);
int st_test_fchmod(int fd, mode_t mode);
#define fprintf st_test_fprintf
#define fflush st_test_fflush
#define fclose st_test_fclose
#define rename st_test_rename
#define mkstemp st_test_mkstemp
#define fdopen st_test_fdopen
#define fsync st_test_fsync
#define open(path, flags) st_test_open(path, flags)
#define close st_test_close
#define unlink st_test_unlink
#define lstat st_test_lstat
#define fchmod st_test_fchmod
#endif

/* Synchronize the directory entry installed by rename(). */
static inline int st_sync_parent_directory(const char *path) {
  size_t length = strlen(path);
  if (length >= PATH_MAX)
    return -1;
  char copy[PATH_MAX];
  memcpy(copy, path, length + 1);
  char *slash = strrchr(copy, '/');
  const char *directory = ".";
  if (slash) {
    if (slash == copy)
      slash[1] = '\0';
    else
      *slash = '\0';
    directory = copy;
  }
  int fd = open(directory, O_RDONLY | O_DIRECTORY);
  int result = fd < 0 ? -1 : fsync(fd);
  if (fd >= 0 && close(fd) != 0)
    result = -1;
  return result;
}

typedef enum {
  ST_ATOMIC_OUTPUT_OK = 0,
  ST_ATOMIC_OUTPUT_MEMORY = -1,
  ST_ATOMIC_OUTPUT_IO = -2,
} st_atomic_output_result_t;

typedef struct {
  FILE *stream;
  char *temporary_path;
  const char *destination_path;
  bool renamed;
} st_atomic_output_t;

static inline st_atomic_output_result_t
st_atomic_output_begin(const char *path, st_atomic_output_t *output) {
  if (!path || !output)
    return ST_ATOMIC_OUTPUT_IO;
  memset(output, 0, sizeof(*output));
  size_t length = strlen(path);
  if (length > SIZE_MAX - 8)
    return ST_ATOMIC_OUTPUT_MEMORY;
  output->temporary_path = malloc(length + 8);
  if (!output->temporary_path)
    return ST_ATOMIC_OUTPUT_MEMORY;
  memcpy(output->temporary_path, path, length);
  memcpy(output->temporary_path + length, ".XXXXXX", 8);
  output->destination_path = path;

  mode_t preserved_mode = 0;
  bool preserve_mode = false;
  struct stat status;
  if (lstat(path, &status) == 0) {
    if (S_ISREG(status.st_mode)) {
      preserved_mode = status.st_mode & 07777;
      preserve_mode = true;
    }
  } else if (errno != ENOENT) {
    goto io_failure;
  }

  int fd = mkstemp(output->temporary_path);
  if (fd < 0)
    goto io_failure;
  if (preserve_mode && fchmod(fd, preserved_mode) != 0) {
    close(fd);
    goto io_failure;
  }
  output->stream = fdopen(fd, "w");
  if (!output->stream) {
    close(fd);
    goto io_failure;
  }
  return ST_ATOMIC_OUTPUT_OK;

io_failure:
  unlink(output->temporary_path);
  free(output->temporary_path);
  memset(output, 0, sizeof(*output));
  return ST_ATOMIC_OUTPUT_IO;
}

static inline void st_atomic_output_discard(st_atomic_output_t *output) {
  if (!output)
    return;
  if (output->stream) {
    (void)fclose(output->stream);
    output->stream = NULL;
  }
  if (output->temporary_path && !output->renamed)
    (void)unlink(output->temporary_path);
  free(output->temporary_path);
  memset(output, 0, sizeof(*output));
}

static inline int st_atomic_output_commit(st_atomic_output_t *output) {
  if (!output || !output->stream || !output->temporary_path ||
      !output->destination_path)
    return -1;

  int result = 0;
  if (fflush(output->stream) != 0)
    result = -1;
  if (result == 0 && fsync(fileno(output->stream)) != 0)
    result = -1;
  if (fclose(output->stream) != 0)
    result = -1;
  output->stream = NULL;
  if (result == 0) {
    if (rename(output->temporary_path, output->destination_path) != 0)
      result = -1;
    else
      output->renamed = true;
  }
  if (output->renamed &&
      st_sync_parent_directory(output->destination_path) != 0)
    result = -1;
  if (!output->renamed)
    (void)unlink(output->temporary_path);
  free(output->temporary_path);
  memset(output, 0, sizeof(*output));
  return result;
}

#endif
