#ifndef SHELL_FILE_INTERNAL_H
#define SHELL_FILE_INTERNAL_H

#include "shell_contract.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Private atomic-output mechanics shared by Shelltype and Shellgate. The
 * fixed basename fits the POSIX minimum NAME_MAX and is independent of the
 * destination basename. Temporary operations use only this basename relative
 * to the opened parent, independent of the full directory path length. */
#define SHELL_FILE_TEMP_NAME ".scl-XXXXXX"

/* Zero initialization denotes an empty output. destination_name is borrowed
 * from the immutable path and is non-NULL exactly while directory_fd is owned.
 * A nonempty temporary_name denotes an owned, not-yet-renamed file. */
typedef struct {
  FILE *stream;
  const char *destination_name;
  int directory_fd;
  char temporary_name[sizeof(SHELL_FILE_TEMP_NAME)];
  mode_t preserved_mode;
  bool preserve_mode;
} shell_file_output_t;

/* path is a readable NUL-terminated filesystem path. Return the directory
 * prefix, including its last slash, or zero for a relative basename. */
static inline SHELL_NONNULL(1) size_t
    shell_file_directory_prefix_length(const char *path) {
  const char *slash = strrchr(path, '/');
  return slash ? (size_t)(slash - path) + 1 : 0;
}

/* Persistence pathname boundary: path is a complete NUL-terminated string,
 * including filesystem-invalid spellings accepted for rejection. Saves use
 * directory-relative operations, but their pathname-based loaders require
 * the complete spelling (including NUL) to fit PATH_MAX. Reject longer paths
 * with ENAMETOOLONG before opening a directory or creating a file. On success,
 * prefix_length is distinct writable output storage; success supplies the
 * directory prefix for this same immutable path and failure clears it.
 * Scan once, bounded by the supported pathname size. */
static inline SHELL_NONNULL(1, 2) bool shell_file_path_prefix(
    const char *path, size_t *prefix_length) {
  *prefix_length = 0;
  size_t prefix = 0;
  for (size_t length = 0; path[length] != '\0'; length++) {
    if (length == PATH_MAX - 1) {
      errno = ENAMETOOLONG;
      return false;
    }
    if (path[length] == '/')
      prefix = length + 1;
  }
  *prefix_length = prefix;
  return true;
}

/* prefix_length is the result above for the same immutable path; output has
 * max(prefix_length, 1) + 1 writable bytes and does not
 * overlap path. No allocation or filesystem access is performed here. */
static inline SHELL_NONNULL(1, 3) void shell_file_write_directory(
    const char *path, size_t prefix_length, char *output) {
  if (prefix_length) {
    memcpy(output, path, prefix_length);
    output[prefix_length] = '\0';
  } else {
    memcpy(output, ".", 2);
  }
}

#define SHELL_FILE_TEMP_RANDOM_BYTES (32 * 6)

/* directory_fd is an owned open parent directory; destination_name is its
 * immutable NUL-terminated destination basename. random references exactly
 * SHELL_FILE_TEMP_RANDOM_BYTES initialized bytes and name has room for
 * sizeof(SHELL_FILE_TEMP_NAME) bytes, without aliasing either input. This
 * filesystem boundary creates an exclusive 0600 file, never follows a
 * preexisting entry, and retries collisions with the next candidate. The
 * destination itself is excluded even when absent: it must not be published
 * before rename. Exhausted candidates report EEXIST. Errors clear name. */
static inline SHELL_NONNULL(2, 3, 4) int shell_file_create_temp_from_bytes(
    int directory_fd, const char *destination_name, const unsigned char *random,
    char *name) {
  static const char alphabet[] =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
  for (size_t attempt = 0; attempt < 32; attempt++) {
    memcpy(name, SHELL_FILE_TEMP_NAME, sizeof(SHELL_FILE_TEMP_NAME));
    for (size_t i = 0; i < 6; i++)
      name[sizeof(SHELL_FILE_TEMP_NAME) - 7 + i] =
          alphabet[random[attempt * 6 + i] & 63];
    if (strcmp(name, destination_name) == 0) {
      errno = EEXIST;
      continue;
    }
    int fd =
        openat(directory_fd, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd >= 0)
      return fd;
    if (errno != EEXIST)
      break;
  }
  name[0] = '\0';
  return -1;
}

/* Same parent/name contract as above. Obtain randomness from the OS rather
 * than process-global PRNG state. Entropy I/O errors preserve errno and clear
 * name; no file is created until the complete random buffer is available. */
static inline SHELL_NONNULL(2, 3) int shell_file_create_temp_at(
    int directory_fd, const char *destination_name, char *name) {
  unsigned char random[SHELL_FILE_TEMP_RANDOM_BYTES];
  int random_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (random_fd < 0)
    goto failure;
  size_t offset = 0;
  while (offset < sizeof(random)) {
    ssize_t bytes = read(random_fd, random + offset, sizeof(random) - offset);
    if (bytes < 0 && errno == EINTR)
      continue;
    if (bytes <= 0) {
      int error_number = bytes == 0 ? EIO : errno;
      close(random_fd);
      errno = error_number;
      goto failure;
    }
    offset += (size_t)bytes;
  }
  if (close(random_fd) != 0)
    goto failure;

  return shell_file_create_temp_from_bytes(directory_fd, destination_name,
                                           random, name);
failure:
  name[0] = '\0';
  return -1;
}

#endif
