/* The source probe of the Bash qualification driver
 * (tests/test_bash_source_status.py). The driver supplies bytes without shell
 * evaluation and compares the answer with Bash. One process serves a whole
 * run: each request is "MODE LENGTH\n" followed by LENGTH source bytes, and
 * each reply is "STATUS LENGTH\n" followed by LENGTH output bytes. MODE is
 *   p   the status of the source as a draft (shell_parse_draft), printed
 *       as a decimal line; STATUS is 0
 *   a   the argv of a single command as a netstring sequence; STATUS is 0, or
 *       1 with no output when the source is not a single supported command */
#include "shell_netstring.h"
#include "shell_sequence.h"
#include "shell_source.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static shell_source_result_t draft;
static char source[16384];

static void reply(int status, const void *output, size_t length) {
  printf("%d %zu\n", status, length);
  if (length)
    fwrite(output, 1, length, stdout);
  fflush(stdout);
}

int main(int argc, char **argv) {
  if (argc != 1) {
    fprintf(stderr, "usage: %s < requests\n", argv[0]);
    return 2;
  }
  char mode;
  size_t length;
  while (scanf(" %c %zu", &mode, &length) == 2 && getchar() == '\n') {
    if (length >= sizeof(source) ||
        (length && fread(source, 1, length, stdin) != length) ||
        (mode != 'p' && mode != 'a'))
      return EXIT_FAILURE;
    if (mode == 'p') {
      char line[16];
      int written = snprintf(line, sizeof(line), "%d\n",
                             shell_parse_draft(source, length, NULL, &draft));
      reply(0, line, (size_t)written);
      continue;
    }
    shell_netstring_buffer_t encoded = {0};
    size_t count = 0;
    bool features = false;
    if (shell_build_netargv_sequence_buffer(source, length, NULL, &encoded,
                                            &count,
                                            &features) != SHELL_PROCESS_OK ||
        count != 1)
      reply(1, NULL, 0);
    else
      reply(0, encoded.data, encoded.length);
    shell_netstring_buffer_free(&encoded);
  }
  return EXIT_SUCCESS;
}
