#ifndef SHELLGATE_IO_H
#define SHELLGATE_IO_H

#include "../../shellsplit/src/shell_file_internal.h"
#include "sg_alloc.h"
#include "shell_contract.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
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

/* Test-only operation failures carry the same errno as a real libc failure. */
static inline bool sg_io_failure(void) {
#ifdef SHELLGATE_TEST_IO
  if (SG_IO_FAIL()) {
    errno = sg_test_io_error_number();
    return true;
  }
#endif
  return false;
}

/* Temporary streams are an operational boundary: production delegates to
 * libc, while tests can inject the exact errno that the public API must map.
 * Capture errno before performing any cleanup after a NULL result. */
static inline FILE *sg_io_tmpfile(void) {
  return sg_io_failure() ? NULL : tmpfile();
}

/* These stream boundaries distinguish clean EOF from an operational failure.
 * Buffers are required valid spans; line capacity includes a trailing NUL
 * and is at least two bytes. length is required distinct output storage.
 * Test-only injection reports an error directly, without fabricating ferror. */
typedef enum {
  SG_IO_READ_OK,
  SG_IO_READ_EOF,
  SG_IO_READ_ERROR,
} sg_io_read_result_t;

static inline SHELL_NONNULL(1, 2) sg_io_read_result_t
    sg_io_read(FILE *stream, void *buffer, size_t length) {
  if (sg_io_failure())
    return SG_IO_READ_ERROR;
  size_t read = fread(buffer, 1, length, stream);
#ifdef SHELLGATE_TEST_IO
  sg_test_io_observe_read(stream, read);
#endif
  if (read == length)
    return SG_IO_READ_OK;
  return ferror(stream) ? SG_IO_READ_ERROR : SG_IO_READ_EOF;
}

/* Report physical bytes, including embedded NUL. A partial line at EOF or
 * capacity is returned for the framing boundary to reject. No heap storage. */
static inline SHELL_NONNULL(1, 2, 4) sg_io_read_result_t
    sg_io_read_line(FILE *stream, char *buffer, size_t capacity,
                    size_t *length) {
  *length = 0;
  buffer[0] = '\0';
  if (sg_io_failure())
    return SG_IO_READ_ERROR;
  while (*length < capacity - 1) {
    int byte = fgetc(stream);
    if (byte == EOF) {
      buffer[*length] = '\0';
      if (ferror(stream))
        return SG_IO_READ_ERROR;
      break;
    }
    buffer[(*length)++] = (char)byte;
    if (byte == '\n')
      break;
  }
  buffer[*length] = '\0';
  return *length ? SG_IO_READ_OK : SG_IO_READ_EOF;
}

static inline SHELL_NONNULL(1, 2) int sg_io_write(FILE *stream,
                                                  const void *buffer,
                                                  size_t length) {
  if (sg_io_failure())
    return -1;
  return fwrite(buffer, 1, length, stream) == length ? 0 : -1;
}

/* Formatting, flush and close are real stream-operation boundaries too. A
 * simulated close error still releases the stream, exactly as fclose does. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
static inline SHELL_NONNULL(1, 2) int sg_io_printf(FILE *stream,
                                                   const char *format, ...) {
  if (sg_io_failure())
    return -1;
  va_list args;
  va_start(args, format);
  int result = vfprintf(stream, format, args);
  va_end(args);
  return result;
}

static inline SHELL_NONNULL(1) int sg_io_flush(FILE *stream) {
  return sg_io_failure() ? -1 : fflush(stream);
}

static inline SHELL_NONNULL(1) int sg_io_close(FILE *stream) {
  bool injected = sg_io_failure();
  int error_number = errno;
#ifdef SHELLGATE_TEST_IO
  int close_error = sg_test_io_close_take_error();
  if (close_error) {
    injected = true;
    error_number = close_error;
  }
#endif
  int result = fclose(stream);
  if (injected) {
    errno = error_number;
    return EOF;
  }
  return result;
}

static inline SHELL_NONNULL(1) int sg_io_seek(FILE *stream, long offset,
                                              int origin) {
  return sg_io_failure() ? -1 : fseek(stream, offset, origin);
}

static inline SHELL_NONNULL(1) long sg_io_tell(FILE *stream) {
  return sg_io_failure() ? -1 : ftell(stream);
}

typedef enum {
  SG_ATOMIC_OUTPUT_OK = 0,
  SG_ATOMIC_OUTPUT_MEMORY = -1,
  SG_ATOMIC_OUTPUT_IO = -2,
} sg_atomic_output_result_t;

typedef shell_file_output_t sg_atomic_output_t;

/* Closing an owned descriptor always releases it, including injected errors. */
static inline int sg_io_close_fd(int fd) {
  bool injected = sg_io_failure();
  int error_number = errno;
  int result = close(fd);
  if (injected) {
    errno = error_number;
    return -1;
  }
  return result;
}

/* Filesystem creation boundary; required name spans obey the shared creator's
 * contract. Test builds can supply deterministic entropy without fabricating
 * an owned output or changing the production selection algorithm. */
static inline SHELL_NONNULL(2, 3) int sg_io_create_temp_at(
    int directory_fd, const char *destination_name, char *name) {
  if (sg_io_failure())
    return -1;
#ifdef SHELLGATE_TEST_IO
  const unsigned char *random = sg_test_io_temp_random_bytes();
  if (random)
    return shell_file_create_temp_from_bytes(directory_fd, destination_name,
                                             random, name);
#endif
  return shell_file_create_temp_at(directory_fd, destination_name, name);
}

/* Required path and empty output storage. The path remains immutable until
 * commit/discard. The entry boundary rejects pathname spellings that cannot
 * be reopened by pathname-based loaders; thereafter only allocation and
 * filesystem operations may fail. A failed begin clears output and removes
 * only a temporary file it actually created.
 * The opened parent is retained until commit/discard. Existing regular files
 * retain their mode, applied only after the final flush; a symlink is replaced,
 * not followed. Other existing file types are rejected. Failures preserve
 * their errno. */
static inline SHELL_NONNULL(1, 2) sg_atomic_output_result_t
    sg_atomic_output_begin(const char *path, sg_atomic_output_t *output) {
  memset(output, 0, sizeof(*output));
  size_t prefix_length;
  if (!shell_file_path_prefix(path, &prefix_length))
    return SG_ATOMIC_OUTPUT_IO;
  size_t directory_length = prefix_length ? prefix_length : 1;
  char *directory = malloc(directory_length + 1);
  if (!directory) {
    errno = ENOMEM;
    return SG_ATOMIC_OUTPUT_MEMORY;
  }
  shell_file_write_directory(path, prefix_length, directory);
  int fd = sg_io_failure()
               ? -1
               : open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  int error_number = errno;
  free(directory);
  errno = error_number;
  if (fd < 0)
    return SG_ATOMIC_OUTPUT_IO;
  output->directory_fd = fd;
  output->destination_name = path + prefix_length;

  struct stat status;
  /* A trailing slash names the opened directory itself, not a missing entry. */
  const char *entry = prefix_length && !output->destination_name[0]
                          ? "."
                          : output->destination_name;
  if (sg_io_failure())
    goto io_failure;
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

  fd = sg_io_create_temp_at(output->directory_fd, output->destination_name,
                            output->temporary_name);
  if (fd < 0)
    goto io_failure;
  output->stream = sg_io_failure() ? NULL : fdopen(fd, "w+b");
  if (!output->stream) {
    goto created_file_failure;
  }
  return SG_ATOMIC_OUTPUT_OK;

created_file_failure:
  /* Only successful exclusive creation transfers ownership of the name. */
  error_number = errno;
  close(fd);
  unlinkat(output->directory_fd, output->temporary_name, 0);
  errno = error_number;
io_failure:
  error_number = errno;
  close(output->directory_fd);
  memset(output, 0, sizeof(*output));
  errno = error_number;
  return SG_ATOMIC_OUTPUT_IO;
}

/* NULL or an empty output is a cleanup no-op. Cleanup preserves errno. */
static inline void sg_atomic_output_discard(sg_atomic_output_t *output) {
  if (!output)
    return;
  int error_number = errno;
  if (output->stream) {
    (void)sg_io_close(output->stream);
    output->stream = NULL;
  }
  if (output->temporary_name[0])
    (void)unlinkat(output->directory_fd, output->temporary_name, 0);
  if (output->destination_name)
    (void)close(output->directory_fd);
  memset(output, 0, sizeof(*output));
  errno = error_number;
}

/* Requires a successful begin, with no intervening commit/discard. Always
 * releases output. Preserve the first failure's errno through close/cleanup.
 * A parent-sync failure occurs after a complete replacement is installed. */
static inline SHELL_NONNULL(1) int sg_atomic_output_commit(
    sg_atomic_output_t *output) {
  int result = sg_io_flush(output->stream);
  int error_number = errno;
  if (result == 0 && output->preserve_mode &&
      (sg_io_failure() ||
       fchmod(fileno(output->stream), output->preserved_mode) != 0)) {
    result = -1;
    error_number = errno;
  }
  if (result == 0 && (sg_io_failure() || fsync(fileno(output->stream)) != 0)) {
    result = -1;
    error_number = errno;
  }
  if (sg_io_close(output->stream) != 0 && result == 0) {
    result = -1;
    error_number = errno;
  }
  output->stream = NULL;
  if (result == 0) {
    if (sg_io_failure() ||
        renameat(output->directory_fd, output->temporary_name,
                 output->directory_fd, output->destination_name) != 0) {
      result = -1;
      error_number = errno;
    } else {
      output->temporary_name[0] = '\0';
      if (sg_io_failure() || fsync(output->directory_fd) != 0) {
        result = -1;
        error_number = errno;
      }
    }
  }
  if (output->temporary_name[0])
    (void)unlinkat(output->directory_fd, output->temporary_name, 0);
  if (sg_io_close_fd(output->directory_fd) != 0 && result == 0) {
    result = -1;
    error_number = errno;
  }
  memset(output, 0, sizeof(*output));
  errno = error_number;
  return result;
}

#endif
