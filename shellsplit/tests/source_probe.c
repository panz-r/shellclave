/* The source probe of the Bash qualification driver
 * (tests/test_bash_source_status.py). The driver supplies bytes on stdin
 * without shell evaluation and compares the answer with Bash:
 *   --probe   the status of the source as a draft (shell_parse_draft)
 *   --argv    the argv of a single command as a netstring sequence */
#include "shell_netstring.h"
#include "shell_sequence.h"
#include "shell_source.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static shell_source_result_t draft;

int main(int argc, char **argv) {
  if (argc != 2 || (strcmp(argv[1], "--probe") && strcmp(argv[1], "--argv"))) {
    fprintf(stderr, "usage: %s --probe|--argv < source\n", argv[0]);
    return 2;
  }
  char source[16384];
  size_t length = fread(source, 1, sizeof(source), stdin);
  if (ferror(stdin) || length >= sizeof(source))
    return EXIT_FAILURE;
  if (!strcmp(argv[1], "--probe")) {
    printf("%d\n", shell_parse_draft(source, length, NULL, &draft));
    return EXIT_SUCCESS;
  }
  shell_netstring_buffer_t encoded = {0};
  size_t count = 0;
  bool features = false;
  if (shell_build_netargv_sequence_buffer(source, length, NULL, &encoded,
                                          &count,
                                          &features) != SHELL_PROCESS_OK ||
      count != 1 ||
      fwrite(encoded.data, 1, encoded.length, stdout) != encoded.length)
    return EXIT_FAILURE;
  shell_netstring_buffer_free(&encoded);
  return EXIT_SUCCESS;
}
