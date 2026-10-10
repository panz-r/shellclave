#ifndef SHELLTYPE_IO_H
#define SHELLTYPE_IO_H

#include "../../shellsplit/src/shell_file_internal.h"
#include "shell_contract.h"

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
int st_test_renameat(int old_directory, const char *old_name, int new_directory,
                     const char *new_name);
int st_test_create_temp_at(int directory, const char *destination_name,
                           char *name);
FILE *st_test_fdopen(int fd, const char *mode);
int st_test_fsync(int fd);
int st_test_open(const char *path, int flags);
int st_test_close(int fd);
int st_test_unlinkat(int directory, const char *name, int flags);
int st_test_fstatat(int directory, const char *name, struct stat *status,
                    int flags);
int st_test_fchmod(int fd, mode_t mode);
#define fprintf st_test_fprintf
#define fflush st_test_fflush
#define fclose st_test_fclose
#define renameat st_test_renameat
#define fdopen st_test_fdopen
#define fsync st_test_fsync
#define open(path, flags) st_test_open(path, flags)
#define close st_test_close
#define unlinkat st_test_unlinkat
#define fstatat st_test_fstatat
#define fchmod st_test_fchmod
#define ST_CREATE_TEMP_AT st_test_create_temp_at
#else
#define ST_CREATE_TEMP_AT shell_file_create_temp_at
#endif

typedef enum {
  ST_ATOMIC_OUTPUT_OK = 0,
  ST_ATOMIC_OUTPUT_MEMORY = -1,
  ST_ATOMIC_OUTPUT_IO = -2,
} st_atomic_output_result_t;

typedef shell_file_output_t st_atomic_output_t;

/* Required path and empty output storage. The path remains immutable until
 * commit/discard. The entry boundary rejects pathname spellings that cannot
 * be reopened by pathname-based loaders; thereafter only allocation and
 * filesystem operations may fail. A failed begin clears output and removes
 * only a temporary file it actually created.
 * The opened parent is retained until commit/discard. Existing regular files
 * retain their mode, applied only after the final flush; a symlink is replaced,
 * not followed. Other existing file types are rejected. */
static inline SHELL_NONNULL(1, 2) st_atomic_output_result_t
    st_atomic_output_begin(const char *path, st_atomic_output_t *output) {
  memset(output, 0, sizeof(*output));
  size_t prefix_length;
  if (!shell_file_path_prefix(path, &prefix_length))
    return ST_ATOMIC_OUTPUT_IO;
  size_t directory_length = prefix_length ? prefix_length : 1;
  char *directory = malloc(directory_length + 1);
  if (!directory)
    return ST_ATOMIC_OUTPUT_MEMORY;
  shell_file_write_directory(path, prefix_length, directory);
  int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  free(directory);
  if (fd < 0)
    return ST_ATOMIC_OUTPUT_IO;
  output->directory_fd = fd;
  output->destination_name = path + prefix_length;

  struct stat status;
  /* A trailing slash names the opened directory itself, not a missing entry. */
  const char *entry = prefix_length && !output->destination_name[0]
                          ? "."
                          : output->destination_name;
  if (fstatat(fd, entry, &status, AT_SYMLINK_NOFOLLOW) == 0) {
    if (S_ISREG(status.st_mode)) {
      output->preserved_mode = status.st_mode & 07777;
      output->preserve_mode = true;
    } else if (!S_ISLNK(status.st_mode)) {
      errno = S_ISDIR(status.st_mode) ? EISDIR : EINVAL;
      goto io_failure;
    }
  } else if (errno != ENOENT) {
    goto io_failure;
  }

  fd = ST_CREATE_TEMP_AT(output->directory_fd, output->destination_name,
                         output->temporary_name);
  if (fd < 0)
    goto io_failure;
  output->stream = fdopen(fd, "w");
  if (!output->stream) {
    close(fd);
    goto created_file_failure;
  }
  return ST_ATOMIC_OUTPUT_OK;

created_file_failure:
  /* Only successful exclusive creation transfers ownership of the name. */
  unlinkat(output->directory_fd, output->temporary_name, 0);
io_failure:
  close(output->directory_fd);
  memset(output, 0, sizeof(*output));
  return ST_ATOMIC_OUTPUT_IO;
}

/* NULL or an empty output is a cleanup no-op. */
static inline void st_atomic_output_discard(st_atomic_output_t *output) {
  if (!output)
    return;
  if (output->stream) {
    (void)fclose(output->stream);
    output->stream = NULL;
  }
  if (output->temporary_name[0])
    (void)unlinkat(output->directory_fd, output->temporary_name, 0);
  if (output->destination_name)
    (void)close(output->directory_fd);
  memset(output, 0, sizeof(*output));
}

/* Requires a successful begin, with no intervening commit/discard. */
static inline SHELL_NONNULL(1) int st_atomic_output_commit(
    st_atomic_output_t *output) {
  int result = 0;
  if (fflush(output->stream) != 0)
    result = -1;
  if (result == 0 && output->preserve_mode &&
      fchmod(fileno(output->stream), output->preserved_mode) != 0)
    result = -1;
  if (result == 0 && fsync(fileno(output->stream)) != 0)
    result = -1;
  if (fclose(output->stream) != 0)
    result = -1;
  output->stream = NULL;
  if (result == 0) {
    if (renameat(output->directory_fd, output->temporary_name,
                 output->directory_fd, output->destination_name) != 0)
      result = -1;
    else {
      output->temporary_name[0] = '\0';
      if (fsync(output->directory_fd) != 0)
        result = -1;
    }
  }
  if (output->temporary_name[0])
    (void)unlinkat(output->directory_fd, output->temporary_name, 0);
  if (close(output->directory_fd) != 0)
    result = -1;
  memset(output, 0, sizeof(*output));
  return result;
}

#endif
