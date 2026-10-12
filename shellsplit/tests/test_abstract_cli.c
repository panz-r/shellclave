/* Exercise the actual CLI caller. Only this translation unit substitutes libc
 * operations; the shipping tool and library contain no fault hooks. */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "shell_abstract.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "failed: %s at %d\n", #condition, __LINE__);             \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

typedef struct {
  size_t fail_at, allocations, live, opens, closes, cwd_calls, expansions;
  void *owned[3];
  const char *expected_cwd;
  bool missing, read_error, close_error, unknown_cwd;
} cli_fixture_t;
static cli_fixture_t fixture;
static char *environment_entries[] = {"CLI_TEST=one", NULL};
static char **cli_environment = environment_entries;
static FILE *cli_stdin;

static bool allocation_fails(void) {
  fixture.allocations++;
  if (fixture.allocations == fixture.fail_at) {
    errno = ENOMEM;
    return true;
  }
  return false;
}

static void *own_allocation(void *pointer) {
  if (pointer) {
    CHECK(fixture.live < sizeof(fixture.owned) / sizeof(fixture.owned[0]));
    fixture.owned[fixture.live++] = pointer;
  }
  return pointer;
}

static void *cli_calloc(size_t count, size_t size) {
  return allocation_fails() ? NULL : own_allocation(calloc(count, size));
}

static void *cli_malloc(size_t size) {
  return allocation_fails() ? NULL : own_allocation(malloc(size));
}

static void cli_free(void *pointer) {
  if (!pointer)
    return;
  size_t slot = 0;
  while (slot < fixture.live && fixture.owned[slot] != pointer)
    slot++;
  CHECK(slot < fixture.live); /* Never release borrowed argv/stack storage. */
  fixture.owned[slot] = fixture.owned[--fixture.live];
  free(pointer);
}

static SHELL_NONNULL(1) char *cli_getcwd(char *buffer, size_t capacity) {
  fixture.cwd_calls++;
  if (fixture.unknown_cwd) {
    errno = ENOENT;
    return NULL;
  }
  CHECK(capacity >= sizeof("/workspace"));
  memcpy(buffer, "/workspace", sizeof("/workspace"));
  return buffer;
}

static SHELL_NONNULL(2) ssize_t
    failed_read(void *cookie, char *buffer, size_t capacity) {
  (void)cookie;
  (void)buffer;
  (void)capacity;
  errno = EIO;
  return -1;
}

static SHELL_NONNULL(1, 2) FILE *cli_fopen(const char *path, const char *mode) {
  CHECK(strcmp(path, "fixture") == 0 && strcmp(mode, "r") == 0);
  if (fixture.missing) {
    errno = ENOENT;
    return NULL;
  }
  FILE *stream;
  if (fixture.read_error) {
    stream =
        fopencookie(NULL, "r", (cookie_io_functions_t){.read = failed_read});
  } else {
    stream = tmpfile();
    CHECK(stream && fputs("echo ./sample\n", stream) >= 0);
    CHECK(fseek(stream, 0, SEEK_SET) == 0);
  }
  CHECK(stream);
  fixture.opens++;
  return stream;
}

static SHELL_NONNULL(1) int cli_fclose(FILE *stream) {
  fixture.closes++;
  int status = fclose(stream);
  if (fixture.close_error) {
    errno = EIO;
    return EOF;
  }
  return status;
}

static SHELL_NONNULL(1, 2) bool cli_expand(
    shell_abstract_command_t *command, const shell_runtime_context_t *context) {
  CHECK((fixture.expected_cwd == NULL && context->cwd == NULL) ||
        (fixture.expected_cwd && context->cwd &&
         strcmp(fixture.expected_cwd, context->cwd) == 0));
  fixture.expansions++;
  return shell_abstract_command_expand(command, context);
}

#define main abstract_cli_main
#define calloc cli_calloc
#define malloc cli_malloc
#define free cli_free
#define getcwd cli_getcwd
#define fopen cli_fopen
#define fclose cli_fclose
#define environ cli_environment
#undef stdin
#define stdin cli_stdin
#define shell_abstract_command_expand cli_expand
#include "../tools/shell_abstract_cli.c"
#undef shell_abstract_command_expand
#undef stdin
#undef environ
#undef fclose
#undef fopen
#undef getcwd
#undef free
#undef malloc
#undef calloc
#undef main

typedef enum {
  COMMAND,
  FILE_INPUT,
  STDIN_INPUT,
  HELP,
  BAD_OPTION
} input_kind_t;

static void run_case(unsigned cwd_mode, input_kind_t input_kind, size_t fail_at,
                     bool missing, bool read_error, bool close_error) {
  fixture = (cli_fixture_t){
      .fail_at = fail_at,
      .expected_cwd = cwd_mode == 2 ? NULL : "/workspace",
      .unknown_cwd = cwd_mode == 2,
      .missing = missing,
      .read_error = read_error,
      .close_error = close_error,
  };
  char *args[10] = {"abstract-cli"};
  int count = 1;
  if (cwd_mode == 0) {
    args[count++] = "-c";
    args[count++] = "/workspace";
  }
  args[count++] = "-x";
  if (input_kind == FILE_INPUT) {
    args[count++] = "-f";
    args[count++] = "fixture";
  } else if (input_kind == COMMAND) {
    args[count++] = "echo";
    args[count++] = "./sample";
  } else if (input_kind == HELP || input_kind == BAD_OPTION) {
    args[count++] = input_kind == HELP ? "-h" : "-z";
  }
  args[count] = NULL;
  FILE *out = tmpfile(), *err = tmpfile();
  cli_stdin =
      input_kind == STDIN_INPUT && read_error
          ? fopencookie(NULL, "r", (cookie_io_functions_t){.read = failed_read})
          : tmpfile();
  CHECK(out && err && cli_stdin);
  if (input_kind == STDIN_INPUT && !read_error) {
    CHECK(fputs("echo ./sample\n", cli_stdin) >= 0);
    CHECK(fseek(cli_stdin, 0, SEEK_SET) == 0);
  }
  CHECK(fflush(stdout) == 0 && fflush(stderr) == 0);
  int saved_out = dup(STDOUT_FILENO), saved_err = dup(STDERR_FILENO);
  CHECK(saved_out >= 0 && saved_err >= 0);
  CHECK(dup2(fileno(out), STDOUT_FILENO) >= 0);
  CHECK(dup2(fileno(err), STDERR_FILENO) >= 0);
  optind = 0; /* Reset GNU getopt's internal state between real main calls. */
  opterr = 0;
  int status = abstract_cli_main(count, args);
  CHECK(fflush(stdout) == 0 && fflush(stderr) == 0);
  CHECK(dup2(saved_out, STDOUT_FILENO) >= 0);
  CHECK(dup2(saved_err, STDERR_FILENO) >= 0);
  CHECK(close(saved_out) == 0 && close(saved_err) == 0);
  bool failure = fail_at || missing || read_error || close_error ||
                 input_kind == BAD_OPTION;
  CHECK(status == (failure ? EXIT_FAILURE : EXIT_SUCCESS));
  CHECK(fixture.live == 0 && fixture.opens == fixture.closes);
  if (fail_at)
    CHECK(fixture.allocations == fail_at && fixture.expansions == 0);
  if (!failure && input_kind != HELP) {
    CHECK(fixture.expansions == 1);
    CHECK(fixture.cwd_calls == (cwd_mode != 0));
    CHECK(fseek(out, 0, SEEK_SET) == 0);
    char output[4096];
    size_t length = fread(output, 1, sizeof(output) - 1, out);
    CHECK(!ferror(out) && feof(out));
    output[length] = '\0';
    CHECK(strstr(output, "Original:    echo ./sample") != NULL);
  }
  CHECK(fclose(out) == 0 && fclose(err) == 0 && fclose(cli_stdin) == 0);
}

int main(void) {
  for (unsigned cwd_mode = 0; cwd_mode < 3; cwd_mode++) {
    run_case(cwd_mode, COMMAND, 0, false, false, false);
    run_case(cwd_mode, FILE_INPUT, 0, false, false, false);
    run_case(cwd_mode, STDIN_INPUT, 0, false, false, false);
    run_case(cwd_mode, FILE_INPUT, 0, true, false, false);
    run_case(cwd_mode, FILE_INPUT, 0, false, true, false);
    run_case(cwd_mode, STDIN_INPUT, 0, false, true, false);
    run_case(cwd_mode, FILE_INPUT, 0, false, false, true);
    run_case(cwd_mode, HELP, 0, false, false, false);
    run_case(cwd_mode, BAD_OPTION, 0, false, false, false);
    for (size_t fail_at = 1; fail_at <= 3; fail_at++)
      run_case(cwd_mode, COMMAND, fail_at, false, false, false);
  }
  puts("abstract CLI ownership and operational failures passed");
  return 0;
}
