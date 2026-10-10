#ifndef SHELLCLAVE_ATOMIC_FILE_FIXTURE_H
#define SHELLCLAVE_ATOMIC_FILE_FIXTURE_H

#include "../shellsplit/src/shell_file_internal.h"
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* These helpers operate only inside a directory privately created by the test.
 * Inventory the fixed temporary basename, including failures before begin
 * returns an owned path and files intentionally left by crash-injection tests.
 */
static inline SHELL_NONNULL(1,
                            2) bool test_atomic_template_path(const char *path,
                                                              char *output,
                                                              size_t capacity) {
  size_t prefix = shell_file_directory_prefix_length(path);
  if (prefix + sizeof(SHELL_FILE_TEMP_NAME) > capacity)
    return false;
  memcpy(output, path, prefix);
  memcpy(output + prefix, SHELL_FILE_TEMP_NAME, sizeof(SHELL_FILE_TEMP_NAME));
  return true;
}

static inline SHELL_NONNULL(1) bool test_atomic_temp_files(const char *path,
                                                           bool remove) {
  char parent[PATH_MAX];
  size_t prefix = shell_file_directory_prefix_length(path);
  if (prefix >= sizeof(parent))
    return false;
  shell_file_write_directory(path, prefix, parent);
  DIR *entries = opendir(parent);
  if (!entries)
    return false;
  bool ok = true;
  struct dirent *entry;
  errno = 0;
  while ((entry = readdir(entries)) != NULL) {
    if (strlen(entry->d_name) == sizeof(SHELL_FILE_TEMP_NAME) - 1 &&
        memcmp(entry->d_name, SHELL_FILE_TEMP_NAME,
               sizeof(SHELL_FILE_TEMP_NAME) - 7) == 0) {
      if (!remove || unlinkat(dirfd(entries), entry->d_name, 0) != 0)
        ok = false;
    }
    errno = 0;
  }
  int read_error = errno;
  int closed = closedir(entries);
  if (read_error != 0 || closed != 0)
    ok = false;
  return ok;
}

/* directory is owned by this test after successful mkdtemp. It contains only
 * test-created files, FIFOs or symlinks; cleanup never follows links or
 * recurses. Attempt every removal even after a failure, then remove the private
 * directory. */
static inline SHELL_NONNULL(1) bool test_atomic_cleanup_directory(
    const char *directory) {
  DIR *entries = opendir(directory);
  if (!entries)
    return false;
  bool ok = true;
  struct dirent *entry;
  while ((entry = readdir(entries)) != NULL) {
    if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
      continue;
    if (unlinkat(dirfd(entries), entry->d_name, 0) != 0)
      ok = false;
  }
  if (closedir(entries) != 0)
    ok = false;
  if (rmdir(directory) != 0)
    ok = false;
  return ok;
}

/* Inventory a privately owned directory by its valid pathname, even when a
 * child pathname would exceed PATH_MAX. NULL expected means no entries. */
static inline SHELL_NONNULL(1) bool test_atomic_directory_only_entry(
    const char *directory, const char *expected) {
  DIR *entries = opendir(directory);
  if (!entries)
    return false;
  bool ok = true, found = false;
  struct dirent *entry;
  errno = 0;
  while ((entry = readdir(entries)) != NULL) {
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
      if (!expected || strcmp(entry->d_name, expected) != 0)
        ok = false;
      else
        found = true;
    }
    errno = 0;
  }
  int read_error = errno;
  int closed = closedir(entries);
  return ok && read_error == 0 && closed == 0 && found == (expected != NULL);
}

/* Create/check the fixed sentinel through its parent descriptor. This proves
 * that rejecting a too-long child pathname does not replace an existing file
 * which directory-relative operations could otherwise reach. */
static inline SHELL_NONNULL(1) bool test_atomic_directory_sentinel(
    const char *directory, bool create) {
  int parent = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (parent < 0)
    return false;
  int fd = openat(parent, "x", create ? O_WRONLY | O_CREAT | O_EXCL : O_RDONLY,
                  0600);
  bool ok = fd >= 0;
  if (ok && create)
    ok = write(fd, "keep", 4) == 4;
  else if (ok) {
    char bytes[5];
    ok = read(fd, bytes, sizeof(bytes)) == 4 && memcmp(bytes, "keep", 4) == 0;
  }
  if (fd >= 0 && close(fd) != 0)
    ok = false;
  if (close(parent) != 0)
    ok = false;
  return ok;
}

/* Owned directory chain for PATH_MAX regressions. root_template fits path;
 * length is below PATH_MAX and exceeds the resulting mkdtemp root length by
 * at least two. Cleanup is valid after any partial creation failure. */
typedef struct {
  char path[PATH_MAX];
  size_t levels[PATH_MAX / 14 + 2];
  size_t count;
} test_atomic_long_directory_t;

static inline SHELL_NONNULL(1, 2) bool test_atomic_long_directory_create(
    test_atomic_long_directory_t *directory, const char *root_template,
    size_t length) {
  strcpy(directory->path, root_template);
  if (!mkdtemp(directory->path))
    return false;
  directory->levels[directory->count++] = strlen(directory->path);
  long name_max = pathconf(directory->path, _PC_NAME_MAX);
  if (name_max < 14)
    return false;
  size_t maximum = (size_t)name_max < 200 ? (size_t)name_max : 200;
  size_t current = strlen(directory->path);
  while (current < length) {
    size_t remaining = length - current;
    size_t component = remaining > maximum + 1 ? maximum : remaining - 1;
    if (remaining == component + 2)
      component--;
    directory->path[current] = '/';
    memset(directory->path + current + 1, 'd', component);
    directory->path[current + component + 1] = '\0';
    if (mkdir(directory->path, 0700) != 0) {
      directory->path[current] = '\0';
      return false;
    }
    current += component + 1;
    directory->levels[directory->count++] = current;
  }
  return true;
}

static inline SHELL_NONNULL(1) bool test_atomic_long_directory_cleanup(
    test_atomic_long_directory_t *directory) {
  if (!directory->count)
    return true;
  bool ok = test_atomic_cleanup_directory(directory->path);
  directory->count--;
  while (directory->count) {
    directory->path[directory->levels[--directory->count]] = '\0';
    if (rmdir(directory->path) != 0)
      ok = false;
  }
  return ok;
}

#endif
