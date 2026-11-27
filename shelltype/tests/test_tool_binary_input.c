#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* The outer record contains `4:echo,2:\0x,` as its binary netargv payload. */
static const unsigned char binary_netargv_record[] = {
    '1', '2', ':', '4', ':',  'e', 'c', 'h',
    'o', ',', '2', ':', '\0', 'x', ',', ',',
};

static int write_all(int fd, const unsigned char *data, size_t length) {
  while (length != 0) {
    ssize_t written = write(fd, data, length);
    if (written > 0) {
      data += (size_t)written;
      length -= (size_t)written;
      continue;
    }
    if (written < 0 && errno == EINTR)
      continue;
    return -1;
  }
  return 0;
}

/* argv is a terminated argument vector for one tool invocation. Capture at
 * most output_size-1 bytes, always close descriptors and reap the child. */
static bool run_tool(const char *const *argv, char *output, size_t output_size,
                     int *exit_status) {
  int output_pipe[2];
  if (pipe(output_pipe) != 0)
    return false;
  pid_t child = fork();
  if (child == 0) {
    close(output_pipe[0]);
    if (dup2(output_pipe[1], STDOUT_FILENO) < 0 ||
        dup2(output_pipe[1], STDERR_FILENO) < 0)
      _exit(127);
    close(output_pipe[1]);
    execv(argv[0], (char *const *)argv);
    _exit(127);
  }
  if (child < 0) {
    close(output_pipe[0]);
    close(output_pipe[1]);
    return false;
  }

  close(output_pipe[1]);
  size_t output_length = 0;
  bool read_ok = true;
  while (output_length + 1 < output_size) {
    ssize_t read_count = read(output_pipe[0], output + output_length,
                              output_size - output_length - 1);
    if (read_count > 0) {
      output_length += (size_t)read_count;
      continue;
    }
    if (read_count < 0 && errno == EINTR)
      continue;
    if (read_count < 0)
      read_ok = false;
    break;
  }
  close(output_pipe[0]);
  output[output_length] = '\0';

  int status = 0;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) {
      return false;
    }
  }
  if (!read_ok || !WIFEXITED(status))
    return false;
  *exit_status = WEXITSTATUS(status);
  return true;
}

static bool test_binary_input(const char *tool) {
  char path[] = "/tmp/shelltype-tool-binary-input-XXXXXX";
  int fd = mkstemp(path);
  if (fd < 0)
    return false;
  int write_status =
      write_all(fd, binary_netargv_record, sizeof(binary_netargv_record));
  int close_status = close(fd);
  char output[4096];
  int status = -1;
  const char *args[] = {tool, "--input", path, "--suggest", "--min-support",
                        "1",  NULL};
  bool ok = write_status == 0 && close_status == 0 &&
            run_tool(args, output, sizeof(output), &status) && status == 0 &&
            strstr(output, "Fed 1 commands (0 errors)") != NULL &&
            strstr(output, "Total commands in trie: 1") != NULL &&
            strstr(output, "echo \"\\x00x\"") != NULL;
  unlink(path);
  return ok;
}

static bool test_validation_details(const char *tool) {
  static const size_t lengths[] = {125, 126, 255};
  char pattern[5 + 2 * 255 + 4 + 1], output[4096];
  const char *args[] = {tool, "--validate", pattern, NULL};
  int status = -1;
  for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
    memcpy(pattern, "tool ", 5);
    memset(pattern + 5, 'p', lengths[i]);
    memcpy(pattern + 5 + lengths[i], "{#n}", 4);
    memset(pattern + 9 + lengths[i], 's', lengths[i]);
    pattern[9 + 2 * lengths[i]] = '\0';
    if (!run_tool(args, output, sizeof(output), &status) || status != 0 ||
        strstr(output, "VALID: tool ") != output ||
        !strstr(output, " (2 tokens)") || !strstr(output, pattern + 5))
      return false;
  }
  args[2] = "tool \"pre\\x00\\u20ac\"{#n}\"\\x00post\"";
  if (!run_tool(args, output, sizeof(output), &status) || status != 0 ||
      !strstr(output, "pre\\x00\\xe2\\x82\\xac{#n}\\x00post"))
    return false;
  args[2] = "pre{#n}post arg";
  return run_tool(args, output, sizeof(output), &status) && status == 1 &&
         strstr(output, "INVALID:") == output;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <shelltype-tool>\n", argv[0]);
    return 2;
  }
  return test_binary_input(argv[1]) && test_validation_details(argv[1]) ? 0 : 1;
}
