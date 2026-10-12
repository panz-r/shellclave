#define _POSIX_C_SOURCE 200809L

#include "../../tests/atomic_file_fixture.h"
#include "sg_io.h"
#include "test_sg_failures.h"

#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char failure_matrix_path[256];
static char failure_matrix_template[264];
static char failure_matrix_directory[256];

static void cleanup_failure_matrix_files(void) {
  if (failure_matrix_template[0])
    (void)unlink(failure_matrix_template);
  if (failure_matrix_path[0])
    (void)unlink(failure_matrix_path);
  if (failure_matrix_directory[0]) {
    (void)test_atomic_temp_files(failure_matrix_path, true);
    (void)rmdir(failure_matrix_directory);
    failure_matrix_directory[0] = '\0';
  }
}

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "check failed: %s at %s:%d\n", #condition, __FILE__,     \
              __LINE__);                                                       \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

static int make_destination(char path[256]) {
  strcpy(path, "/tmp/shellgate-io-XXXXXX");
  int fd = mkstemp(path);
  if (fd < 0)
    return 0;
  if (close(fd) != 0) {
    unlink(path);
    return 0;
  }
  return 1;
}

static int write_file(const char *path, const char *text) {
  FILE *stream = fopen(path, "wb");
  if (!stream)
    return 0;
  int ok = fputs(text, stream) >= 0 && fclose(stream) == 0;
  return ok;
}

static int file_is_complete(const char *path) {
  char data[16] = {0};
  FILE *stream = fopen(path, "rb");
  if (!stream)
    return 0;
  size_t length = fread(data, 1, sizeof(data) - 1, stream);
  int close_ok = fclose(stream) == 0;
  return close_ok && ((length == 3 && memcmp(data, "old", 3) == 0) ||
                      (length == 3 && memcmp(data, "new", 3) == 0));
}

static int file_equals(const char *path, const char *expected) {
  char data[16] = {0};
  FILE *stream = fopen(path, "rb");
  if (!stream)
    return 0;
  size_t length = fread(data, 1, sizeof(data), stream);
  int close_ok = fclose(stream) == 0;
  size_t expected_length = strlen(expected);
  return close_ok && length == expected_length &&
         memcmp(data, expected, expected_length) == 0;
}

static int test_discard_contract(void) {
  sg_atomic_output_discard(NULL);

  char path[256];
  CHECK(make_destination(path));
  CHECK(unlink(path) == 0);
  sg_atomic_output_t output;
  CHECK(sg_atomic_output_begin(path, &output) == SG_ATOMIC_OUTPUT_OK);
  char temporary[sizeof(output.temporary_name)];
  strcpy(temporary, output.temporary_name);
  int parent = output.directory_fd;
  int view = dup(parent);
  CHECK(view >= 0);
  CHECK((fcntl(parent, F_GETFD) & FD_CLOEXEC) != 0);
  CHECK((fcntl(fileno(output.stream), F_GETFD) & FD_CLOEXEC) != 0);
  struct stat status;
  CHECK(fstatat(view, temporary, &status, AT_SYMLINK_NOFOLLOW) == 0);
  CHECK(fputs("discarded", output.stream) >= 0);
  sg_atomic_output_discard(&output);
  CHECK(output.stream == NULL && output.destination_name == NULL &&
        output.temporary_name[0] == '\0');
  CHECK(fcntl(parent, F_GETFD) == -1 && errno == EBADF);
  CHECK(fstatat(view, temporary, &status, AT_SYMLINK_NOFOLLOW) == -1 &&
        errno == ENOENT);
  CHECK(close(view) == 0 && access(path, F_OK) != 0);

  CHECK(write_file(path, "old"));
  CHECK(sg_atomic_output_begin(path, &output) == SG_ATOMIC_OUTPUT_OK);
  CHECK(fputs("discarded", output.stream) >= 0);
  sg_atomic_output_discard(&output);
  CHECK(file_equals(path, "old"));
  CHECK(unlink(path) == 0);
  return 1;
}

static int test_commit_and_mode(void) {
  char path[256];
  CHECK(make_destination(path));
  static const mode_t modes[] = {0640, 0750, 04750, 02750, 01750};
  for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
    CHECK(chmod(path, modes[i]) == 0);
    sg_atomic_output_t output;
    CHECK(sg_atomic_output_begin(path, &output) == SG_ATOMIC_OUTPUT_OK);
    CHECK(fputs("new", output.stream) >= 0);
    struct stat status;
    CHECK(fstat(fileno(output.stream), &status) == 0 &&
          (status.st_mode & 07777) == 0600);
    CHECK(sg_atomic_output_commit(&output) == 0);
    CHECK(file_is_complete(path));
    CHECK(stat(path, &status) == 0 && (status.st_mode & 07777) == modes[i]);
  }
  CHECK(unlink(path) == 0);
  return 1;
}

static int test_contract_boundaries(void) {
  sg_atomic_output_t output = {0};
  sg_atomic_output_discard(&output);
  CHECK(output.stream == NULL && output.destination_name == NULL);

  char long_path[PATH_MAX + 1];
  memset(long_path, 'x', sizeof(long_path) - 1);
  long_path[sizeof(long_path) - 1] = '\0';
  size_t prefix = SIZE_MAX;
  CHECK(!shell_file_path_prefix(long_path, &prefix) && errno == ENAMETOOLONG &&
        prefix == 0);
  long_path[PATH_MAX - 1] = '\0';
  CHECK(shell_file_path_prefix(long_path, &prefix) && prefix == 0);
  static const struct {
    const char *path;
    size_t prefix;
  } paths[] = {{"model", 0},    {"./model", 2}, {"/model", 1},
               {"a//model", 3}, {"/", 1},       {"", 0}};
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    CHECK(shell_file_path_prefix(paths[i].path, &prefix) &&
          prefix == paths[i].prefix);
  }
  long_path[PATH_MAX - 1] = 'x';
  errno = 0;
  CHECK(sg_atomic_output_begin(long_path, &output) == SG_ATOMIC_OUTPUT_IO);
  CHECK(errno == ENAMETOOLONG);
  CHECK(sg_atomic_output_begin("/", &output) == SG_ATOMIC_OUTPUT_IO);
  CHECK(errno == EISDIR);

  char relative[128];
  snprintf(relative, sizeof(relative), "shellgate-relative-%ld",
           (long)getpid());
  CHECK(unlink(relative) != 0);
  CHECK(sg_atomic_output_begin(relative, &output) == SG_ATOMIC_OUTPUT_OK);
  CHECK(fputs("new", output.stream) >= 0);
  CHECK(sg_atomic_output_commit(&output) == 0);
  CHECK(file_is_complete(relative));
  CHECK(unlink(relative) == 0);

  char non_directory[256];
  CHECK(make_destination(non_directory));
  char nested[sizeof(non_directory) + 8];
  int nested_length =
      snprintf(nested, sizeof(nested), "%s/child", non_directory);
  CHECK(nested_length > 0 && (size_t)nested_length < sizeof(nested));
  CHECK(sg_atomic_output_begin(nested, &output) == SG_ATOMIC_OUTPUT_IO);
  CHECK(output.stream == NULL && output.destination_name == NULL);
  CHECK(unlink(non_directory) == 0);
  return 1;
}

static int test_failure_matrix(void) {
  char directory[] = "/tmp/shellgate-io-matrix-XXXXXX";
  CHECK(mkdtemp(directory) != NULL);
  strcpy(failure_matrix_directory, directory);
  char path[256];
  snprintf(path, sizeof(path), "%s/model", directory);
  strcpy(failure_matrix_path, path);
  CHECK(write_file(path, "old"));
  char template_path[sizeof(path) + 8];
  CHECK(test_atomic_template_path(path, template_path, sizeof(template_path)));

  sg_atomic_output_t probe;
  sg_test_io_reset();
  CHECK(sg_atomic_output_begin(path, &probe) == SG_ATOMIC_OUTPUT_OK);
  CHECK(fputs("new", probe.stream) >= 0);
  CHECK(sg_atomic_output_commit(&probe) == 0);
  size_t operations = sg_test_io_count();
  sg_test_io_reset();
  CHECK(operations > 0);

  int observed_post_rename_failure = 0;
  for (size_t fail_at = 1; fail_at <= operations; fail_at++) {
    CHECK(write_file(path, "old"));
    CHECK(write_file(template_path, "keep"));
    strcpy(failure_matrix_template, template_path);
    /* The single-threaded test releases the next available descriptor before
     * begin; every failure must close any temporary/parent descriptor. */
    int next_fd = open(path, O_RDONLY);
    CHECK(next_fd >= 0 && close(next_fd) == 0);
    sg_atomic_output_t output;
    sg_test_io_fail_at(fail_at);
    sg_atomic_output_result_t begin = sg_atomic_output_begin(path, &output);
    int commit = -1;
    if (begin == SG_ATOMIC_OUTPUT_OK) {
      CHECK(fputs("new", output.stream) >= 0);
      commit = sg_atomic_output_commit(&output);
    }
    sg_test_io_reset();
    CHECK(begin != SG_ATOMIC_OUTPUT_OK || commit != 0);
    CHECK(output.stream == NULL && output.destination_name == NULL &&
          output.temporary_name[0] == '\0');
    errno = 0;
    CHECK(fcntl(next_fd, F_GETFD) == -1 && errno == EBADF);
    CHECK(file_equals(template_path, "keep"));
    CHECK(unlink(template_path) == 0);
    failure_matrix_template[0] = '\0';
    CHECK(file_is_complete(path));
    if (begin != SG_ATOMIC_OUTPUT_OK)
      CHECK(file_equals(path, "old"));
    CHECK(test_atomic_temp_files(path, false));
    if (begin == SG_ATOMIC_OUTPUT_OK && commit != 0 && file_equals(path, "new"))
      observed_post_rename_failure = 1;
  }
  CHECK(observed_post_rename_failure);

  sg_atomic_output_t output;
  sg_test_alloc_fail_at(1);
  CHECK(sg_atomic_output_begin(path, &output) == SG_ATOMIC_OUTPUT_MEMORY);
  sg_test_alloc_reset();
  CHECK(output.stream == NULL && output.destination_name == NULL);
  CHECK(file_is_complete(path));
  CHECK(unlink(path) == 0);
  CHECK(rmdir(directory) == 0);
  failure_matrix_directory[0] = '\0';
  failure_matrix_path[0] = '\0';
  return 1;
}

static int test_read_line_bytes(void) {
  static const char input[] = "ab\0cd\nlast";
  FILE *stream = tmpfile();
  CHECK(stream != NULL);
  CHECK(fwrite(input, 1, sizeof(input) - 1, stream) == sizeof(input) - 1);
  CHECK(fseek(stream, 0, SEEK_SET) == 0);
  char buffer[16];
  size_t length = SIZE_MAX;
  sg_test_io_fail_at_with_errno(1, EIO);
  CHECK(sg_io_read_line(stream, buffer, sizeof(buffer), &length) ==
        SG_IO_READ_ERROR);
  CHECK(errno == EIO && length == 0 && buffer[0] == '\0');
  sg_test_io_reset();
  /* Restore a determinate position before further I/O after a read error. */
  CHECK(fseek(stream, 0, SEEK_SET) == 0);
  CHECK(ftell(stream) == 0);
  CHECK(sg_io_read_line(stream, buffer, sizeof(buffer), &length) ==
        SG_IO_READ_OK);
  CHECK(length == 6 && memcmp(buffer, input, length) == 0 &&
        buffer[length] == 0);
  CHECK(sg_io_read_line(stream, buffer, sizeof(buffer), &length) ==
        SG_IO_READ_OK);
  CHECK(length == 4 && memcmp(buffer, "last", length) == 0);
  CHECK(sg_io_read_line(stream, buffer, sizeof(buffer), &length) ==
        SG_IO_READ_EOF);
  CHECK(length == 0 && buffer[0] == '\0');
  CHECK(fseek(stream, 0, SEEK_SET) == 0);
  CHECK(sg_io_read_line(stream, buffer, 4, &length) == SG_IO_READ_OK);
  CHECK(length == 3 && memcmp(buffer, input, length) == 0 &&
        buffer[length] == 0);
  CHECK(sg_io_read_line(stream, buffer, 4, &length) == SG_IO_READ_OK);
  CHECK(length == 3 && memcmp(buffer, input + 3, length) == 0);
  CHECK(fclose(stream) == 0);
  return 1;
}

static int test_exclusive_temp_creation(void) {
  char directory[] = "/tmp/shellclave-exclusive-temp-XXXXXX";
  CHECK(mkdtemp(directory) != NULL);
  int parent = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  CHECK(parent >= 0);
  const char *sentinel = ".scl-aaaaaa";
  int fd = openat(parent, sentinel, O_CREAT | O_EXCL | O_WRONLY, 0600);
  CHECK(fd >= 0 && write(fd, "keep", 4) == 4 && close(fd) == 0);
  unsigned char random[SHELL_FILE_TEMP_RANDOM_BYTES] = {0};
  memset(random + 6, 1, 6);
  char name[sizeof(SHELL_FILE_TEMP_NAME)];
  fd = shell_file_create_temp_from_bytes(parent, "model", random, name);
  CHECK(fd >= 0 && strcmp(name, ".scl-bbbbbb") == 0);
  struct stat status;
  CHECK(fstat(fd, &status) == 0 && (status.st_mode & 07777) == 0600);
  CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
  CHECK(close(fd) == 0 && unlinkat(parent, name, 0) == 0);
  memset(random, 0, sizeof(random));
  CHECK(shell_file_create_temp_from_bytes(parent, "model", random, name) ==
            -1 &&
        errno == EEXIST && name[0] == '\0');
  fd = openat(parent, sentinel, O_RDONLY);
  char bytes[4];
  CHECK(fd >= 0 && read(fd, bytes, sizeof(bytes)) == sizeof(bytes) &&
        memcmp(bytes, "keep", sizeof(bytes)) == 0 && close(fd) == 0);
  CHECK(unlinkat(parent, sentinel, 0) == 0);
  /* An absent destination is just as forbidden as an existing collision. */
  CHECK(shell_file_create_temp_from_bytes(parent, sentinel, random, name) ==
            -1 &&
        errno == EEXIST && name[0] == '\0');
  CHECK(fstatat(parent, sentinel, &status, AT_SYMLINK_NOFOLLOW) == -1 &&
        errno == ENOENT);
  memset(random + 6, 1, 6);
  fd = shell_file_create_temp_from_bytes(parent, sentinel, random, name);
  CHECK(fd >= 0 && strcmp(name, ".scl-bbbbbb") == 0);
  CHECK(fstatat(parent, sentinel, &status, AT_SYMLINK_NOFOLLOW) == -1 &&
        errno == ENOENT);
  CHECK(close(fd) == 0 && unlinkat(parent, name, 0) == 0);
  CHECK(rmdir(directory) == 0);
  /* A valid open directory can become unlinked during a save. Creation must
   * report the real operational failure, not retain a candidate as owned. */
  CHECK(shell_file_create_temp_at(parent, "model", name) == -1 &&
        errno == ENOENT && name[0] == '\0');
  CHECK(close(parent) == 0);
  return 1;
}

static int test_destination_candidate_is_not_published(void) {
  char directory[] = "/tmp/shellgate-destination-candidate-XXXXXX";
  if (!mkdtemp(directory))
    return 0;
  char path[256];
  snprintf(path, sizeof(path), "%s/.scl-aaaaaa", directory);
  unsigned char random[SHELL_FILE_TEMP_RANDOM_BYTES] = {0};
  sg_atomic_output_t output = {0};
  sg_test_io_reset();
  sg_test_io_temp_random_set(random);
  bool ok = sg_atomic_output_begin(path, &output) == SG_ATOMIC_OUTPUT_IO &&
            errno == EEXIST &&
            test_atomic_directory_only_entry(directory, NULL);
  memset(random + 6, 1, 6);
  if (ok)
    ok = sg_atomic_output_begin(path, &output) == SG_ATOMIC_OUTPUT_OK &&
         strcmp(output.temporary_name, ".scl-bbbbbb") == 0 &&
         fputs("new", output.stream) >= 0 && fflush(output.stream) == 0 &&
         access(path, F_OK) == -1 && errno == ENOENT;
  sg_atomic_output_discard(&output);
  ok = test_atomic_directory_only_entry(directory, NULL) && ok;

  sg_test_io_reset();
  sg_test_io_temp_random_set(random);
  if (ok)
    ok = sg_atomic_output_begin(path, &output) == SG_ATOMIC_OUTPUT_OK &&
         fputs("new", output.stream) >= 0 &&
         sg_atomic_output_commit(&output) == 0 && file_equals(path, "new");
  size_t operations = sg_test_io_count();
  sg_test_io_reset();
  sg_atomic_output_discard(&output);
  if (ok)
    ok = unlink(path) == 0 && operations > 0;
  for (unsigned existing = 0; ok && existing < 2; existing++) {
    for (size_t fail_at = 1; ok && fail_at <= operations; fail_at++) {
      if (existing)
        ok = write_file(path, "old");
      sg_test_io_fail_at(fail_at);
      sg_test_io_temp_random_set(random);
      sg_atomic_output_result_t begin = sg_atomic_output_begin(path, &output);
      int commit = -1;
      if (begin == SG_ATOMIC_OUTPUT_OK) {
        ok = ok && (existing ? file_equals(path, "old")
                             : access(path, F_OK) == -1 && errno == ENOENT);
        ok = fputs("new", output.stream) >= 0 && ok;
        commit = sg_atomic_output_commit(&output);
      }
      sg_test_io_reset();
      sg_atomic_output_discard(&output);
      bool published = access(path, F_OK) == 0;
      ok = ok && (begin != SG_ATOMIC_OUTPUT_OK || commit != 0) &&
           test_atomic_directory_only_entry(directory,
                                            published ? ".scl-aaaaaa" : NULL);
      if (published)
        ok = file_is_complete(path) && unlink(path) == 0 && ok;
      if (existing)
        ok = published && ok;
    }
  }
  sg_test_io_reset();
  return test_atomic_cleanup_directory(directory) && ok;
}

int main(void) {
  atexit(cleanup_failure_matrix_files);
  int passed = test_discard_contract() && test_commit_and_mode() &&
               test_contract_boundaries() && test_failure_matrix() &&
               test_read_line_bytes() && test_exclusive_temp_creation() &&
               test_destination_candidate_is_not_published();
  printf("shellgate atomic-output tests: %s\n", passed ? "PASS" : "FAIL");
  return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}
