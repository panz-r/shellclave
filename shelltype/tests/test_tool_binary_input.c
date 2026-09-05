#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
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

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <shelltype-tool>\n", argv[0]);
    return 2;
  }

  char path[] = "/tmp/shelltype-tool-binary-input-XXXXXX";
  int fd = mkstemp(path);
  if (fd < 0)
    return 1;
  int write_status =
      write_all(fd, binary_netargv_record, sizeof(binary_netargv_record));
  int close_status = close(fd);
  if (write_status != 0 || close_status != 0) {
    unlink(path);
    return 1;
  }

  int output_pipe[2];
  if (pipe(output_pipe) != 0) {
    unlink(path);
    return 1;
  }
  pid_t child = fork();
  if (child == 0) {
    close(output_pipe[0]);
    if (dup2(output_pipe[1], STDOUT_FILENO) < 0 ||
        dup2(output_pipe[1], STDERR_FILENO) < 0)
      _exit(127);
    close(output_pipe[1]);
    execl(argv[1], argv[1], "--input", path, "--suggest", "--min-support", "1",
          (char *)NULL);
    _exit(127);
  }
  if (child < 0) {
    close(output_pipe[0]);
    close(output_pipe[1]);
    unlink(path);
    return 1;
  }

  close(output_pipe[1]);
  char output[4096];
  size_t output_length = 0;
  while (output_length + 1 < sizeof(output)) {
    ssize_t read_count = read(output_pipe[0], output + output_length,
                              sizeof(output) - output_length - 1);
    if (read_count > 0) {
      output_length += (size_t)read_count;
      continue;
    }
    if (read_count < 0 && errno == EINTR)
      continue;
    if (read_count < 0) {
      close(output_pipe[0]);
      unlink(path);
      return 1;
    }
    break;
  }
  close(output_pipe[0]);
  output[output_length] = '\0';

  int status = 0;
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) {
      unlink(path);
      return 1;
    }
  }
  unlink(path);
  return WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
                 strstr(output, "Fed 1 commands (0 errors)") != NULL &&
                 strstr(output, "Total commands in trie: 1") != NULL &&
                 strstr(output, "echo \"\\x00x\"") != NULL
             ? 0
             : 1;
}
