#ifndef SHELLGATE_IO_H
#define SHELLGATE_IO_H

#include "sg_alloc.h"
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

#ifdef SHELLGATE_TEST_IO
#include "test_sg_failures.h"
#define SG_IO_FAIL() sg_test_io_should_fail()
#else
#define SG_IO_FAIL() false
#endif

typedef enum {
  SG_ATOMIC_OUTPUT_OK = 0,
  SG_ATOMIC_OUTPUT_MEMORY = -1,
  SG_ATOMIC_OUTPUT_IO = -2,
} sg_atomic_output_result_t;

typedef struct {
  FILE *stream;
  char *temporary_path;
  const char *destination_path;
  bool renamed;
} sg_atomic_output_t;

static inline int sg_sync_parent_directory(const char *path) {
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
  int fd = SG_IO_FAIL() ? -1 : open(directory, O_RDONLY | O_DIRECTORY);
  int result = fd < 0 || SG_IO_FAIL() ? -1 : fsync(fd);
  bool close_failed = fd >= 0 && SG_IO_FAIL();
  if (fd >= 0 && close(fd) != 0)
    result = -1;
  if (close_failed)
    result = -1;
  return result;
}

static inline sg_atomic_output_result_t
sg_atomic_output_begin(const char *path, sg_atomic_output_t *output) {
  if (!path || !output)
    return SG_ATOMIC_OUTPUT_IO;
  memset(output, 0, sizeof(*output));
  size_t length = strlen(path);
  if (length > SIZE_MAX - 8)
    return SG_ATOMIC_OUTPUT_MEMORY;
  output->temporary_path = malloc(length + 8);
  if (!output->temporary_path)
    return SG_ATOMIC_OUTPUT_MEMORY;
  memcpy(output->temporary_path, path, length);
  memcpy(output->temporary_path + length, ".XXXXXX", 8);
  output->destination_path = path;

  mode_t preserved_mode = 0;
  bool preserve_mode = false;
  struct stat status;
  if (SG_IO_FAIL())
    goto io_failure;
  if (lstat(path, &status) == 0) {
    if (S_ISREG(status.st_mode)) {
      preserved_mode = status.st_mode & 07777;
      preserve_mode = true;
    }
  } else if (errno != ENOENT) {
    goto io_failure;
  }

  int fd = SG_IO_FAIL() ? -1 : mkstemp(output->temporary_path);
  if (fd < 0)
    goto io_failure;
  if (preserve_mode && (SG_IO_FAIL() || fchmod(fd, preserved_mode) != 0)) {
    close(fd);
    goto io_failure;
  }
  output->stream = SG_IO_FAIL() ? NULL : fdopen(fd, "w+b");
  if (!output->stream) {
    close(fd);
    goto io_failure;
  }
  return SG_ATOMIC_OUTPUT_OK;

io_failure:
  unlink(output->temporary_path);
  free(output->temporary_path);
  memset(output, 0, sizeof(*output));
  return SG_ATOMIC_OUTPUT_IO;
}

static inline void sg_atomic_output_discard(sg_atomic_output_t *output) {
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

static inline int sg_atomic_output_commit(sg_atomic_output_t *output) {
  if (!output || !output->stream || !output->temporary_path ||
      !output->destination_path)
    return -1;

  int result = 0;
  if (SG_IO_FAIL() || fflush(output->stream) != 0)
    result = -1;
  if (result == 0 && (SG_IO_FAIL() || fsync(fileno(output->stream)) != 0))
    result = -1;
  bool close_failed = SG_IO_FAIL();
  if (fclose(output->stream) != 0 || close_failed)
    result = -1;
  output->stream = NULL;
  if (result == 0) {
    if (SG_IO_FAIL() ||
        rename(output->temporary_path, output->destination_path) != 0)
      result = -1;
    else
      output->renamed = true;
  }
  if (output->renamed &&
      sg_sync_parent_directory(output->destination_path) != 0)
    result = -1;
  if (!output->renamed)
    (void)unlink(output->temporary_path);
  free(output->temporary_path);
  memset(output, 0, sizeof(*output));
  return result;
}

#endif
