#define _POSIX_C_SOURCE 200809L

#include "sg_io.h"
#include "test_sg_failures.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "check failed: %s at %s:%d\n", #condition, __FILE__,     \
              __LINE__);                                                       \
      return 0;                                                                \
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
  char temporary[sizeof(path) + 8];
  CHECK(strlen(output.temporary_path) < sizeof(temporary));
  strcpy(temporary, output.temporary_path);
  CHECK(access(temporary, F_OK) == 0);
  CHECK(fputs("discarded", output.stream) >= 0);
  sg_atomic_output_discard(&output);
  CHECK(output.stream == NULL && output.temporary_path == NULL);
  CHECK(access(temporary, F_OK) != 0 && access(path, F_OK) != 0);

  CHECK(write_file(path, "old"));
  output =
      (sg_atomic_output_t){.temporary_path = strdup(path), .renamed = true};
  CHECK(output.temporary_path != NULL);
  sg_atomic_output_discard(&output);
  CHECK(access(path, F_OK) == 0);
  CHECK(unlink(path) == 0);
  return 1;
}

static int test_commit_and_mode(void) {
  char path[256];
  CHECK(make_destination(path));
  CHECK(chmod(path, 0640) == 0);
  sg_atomic_output_t output;
  CHECK(sg_atomic_output_begin(path, &output) == SG_ATOMIC_OUTPUT_OK);
  CHECK(fputs("new", output.stream) >= 0);
  CHECK(sg_atomic_output_commit(&output) == 0);
  CHECK(file_is_complete(path));
  struct stat status;
  CHECK(stat(path, &status) == 0 && (status.st_mode & 0777) == 0640);
  CHECK(unlink(path) == 0);
  return 1;
}

static int test_contract_boundaries(void) {
  sg_atomic_output_t output = {0};
  CHECK(sg_atomic_output_begin(NULL, &output) == SG_ATOMIC_OUTPUT_IO);
  CHECK(sg_atomic_output_begin("unused", NULL) == SG_ATOMIC_OUTPUT_IO);
  CHECK(sg_atomic_output_commit(NULL) == -1);
  CHECK(sg_atomic_output_commit(&output) == -1);

  char long_path[PATH_MAX + 1];
  memset(long_path, 'x', sizeof(long_path) - 1);
  long_path[sizeof(long_path) - 1] = '\0';
  CHECK(sg_sync_parent_directory(long_path) == -1);
  CHECK(sg_sync_parent_directory("/") == 0);

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
  CHECK(output.stream == NULL && output.temporary_path == NULL);
  CHECK(unlink(non_directory) == 0);
  return 1;
}

static int test_failure_matrix(void) {
  char path[256];
  CHECK(make_destination(path));
  CHECK(write_file(path, "old"));

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
    sg_atomic_output_t output;
    sg_test_io_fail_at(fail_at);
    sg_atomic_output_result_t begin = sg_atomic_output_begin(path, &output);
    int commit = -1;
    char temporary[sizeof(path) + 8] = {0};
    if (begin == SG_ATOMIC_OUTPUT_OK) {
      CHECK(strlen(output.temporary_path) < sizeof(temporary));
      strcpy(temporary, output.temporary_path);
      CHECK(fputs("new", output.stream) >= 0);
      commit = sg_atomic_output_commit(&output);
    }
    sg_test_io_reset();
    CHECK(begin != SG_ATOMIC_OUTPUT_OK || commit != 0);
    CHECK(file_is_complete(path));
    CHECK(temporary[0] == '\0' || access(temporary, F_OK) != 0);
    if (begin == SG_ATOMIC_OUTPUT_OK && commit != 0 && file_equals(path, "new"))
      observed_post_rename_failure = 1;
  }
  CHECK(observed_post_rename_failure);

  sg_atomic_output_t output;
  sg_test_alloc_fail_at(1);
  CHECK(sg_atomic_output_begin(path, &output) == SG_ATOMIC_OUTPUT_MEMORY);
  sg_test_alloc_reset();
  CHECK(output.stream == NULL && output.temporary_path == NULL);
  CHECK(file_is_complete(path));
  CHECK(unlink(path) == 0);
  return 1;
}

int main(void) {
  int passed = test_discard_contract() && test_commit_and_mode() &&
               test_contract_boundaries() && test_failure_matrix();
  printf("shellgate atomic-output tests: %s\n", passed ? "PASS" : "FAIL");
  return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}
