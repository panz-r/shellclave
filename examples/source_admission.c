/* Source classification for an application's admission boundary. This example
 * performs analysis only. It neither executes input nor grants approval. */
#include "shell_source.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static SHELL_NONNULL(1, 2) void report_source(const char *name,
                                              const char *source,
                                              size_t length) {
  const char *classification = "analysis resource unavailable";
  shell_source_result_t *draft = NULL;
  shell_dep_graph_t *graph = NULL;
  void *workspace = NULL;
  size_t fixed, delimiters, total;
  size_t alignment = shell_dep_workspace_alignment();
  if (!shell_dep_workspace_size(NULL, &fixed) ||
      !shell_source_workspace_size(length, &delimiters) ||
      delimiters > SIZE_MAX - fixed)
    goto done;
  total = fixed + delimiters;
  size_t padding = (alignment - total % alignment) % alignment;
  if (padding > SIZE_MAX - total)
    goto done;
  total += padding;
  /* Production applications also impose their own byte/work budgets before
   * allocating. One buffer is reused by sequential source and graph analysis.
   */
  workspace = aligned_alloc(alignment, total);
  draft = malloc(sizeof(*draft));
  if (!workspace || !draft)
    goto done;
  shell_limits_t source_limits = SHELL_LIMITS_DEFAULT;
  source_limits.workspace = workspace;
  source_limits.workspace_size = total;
  shell_source_status_t status =
      shell_parse_draft(source, length, &source_limits, draft);
  switch (status) {
  case SHELL_SOURCE_INVALID:
    classification = "syntax error; reject before dispatch";
    goto done;
  case SHELL_SOURCE_INVALID_INPUT:
    classification = "invalid input representation; reject before dispatch";
    goto done;
  case SHELL_SOURCE_UNSUPPORTED:
    classification = "explicit exact-source approval required";
    goto done;
  case SHELL_SOURCE_INCOMPLETE:
    classification = "incomplete input; request completion";
    goto done;
  case SHELL_SOURCE_TRUNCATED:
    goto done;
  case SHELL_SOURCE_COMPLETE:
    break;
  }
  if (!draft->prefix_length) {
    classification = "empty analysis; application authorization required";
    goto done;
  }
  graph = malloc(sizeof(*graph));
  if (!graph)
    goto done;
  shell_dep_limits_t graph_limits = SHELL_DEP_LIMITS_DEFAULT;
  graph_limits.workspace = workspace;
  graph_limits.workspace_size = total;
  /* The exact immutable prefix and its unchanged fast result travel together.
   * The graph borrows source, not scratch. Both results are owned here. */
  shell_dep_error_t error = shell_dep_graph_parse_with_fast(
      source, draft->prefix_length, "/workspace", &graph_limits, &draft->prefix,
      graph);
  switch (error) {
  case SHELL_DEP_OK:
    classification = "analysis available; application authorization required";
    break;
  case SHELL_DEP_EPARSE:
    classification = "explicit exact-source approval required";
    break;
  case SHELL_DEP_EINPUT:
    classification = "invalid analysis input; reject before dispatch";
    break;
  case SHELL_DEP_EEXPAND:
    classification = "expansion resolution failed";
    break;
  case SHELL_DEP_ETRUNC:
  case SHELL_DEP_EWORKSPACE:
    break;
  }
done:
  printf("%s: %s\n", name, classification);
  free(graph);
  free(draft);
  free(workspace);
}

int main(void) {
  static const struct {
    const char *name, *source;
  } cases[] = {
      {"ordinary", "printf ok"},
      {"malformed heredoc", "cat /workspace/before.txt\ncat <<\ncat tail"},
      {"quoted text", "printf '%s' '日本'"},
      {"unsupported bytes", "printf '%s' 日本"},
      {"unsupported grammar", "if true; then :; fi"},
      {"unsupported semantics", "eval 'printf ok'"},
      {"unfinished document", "cat <<EOF\npayload\n"},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
    report_source(cases[i].name, cases[i].source, strlen(cases[i].source));
  static const char nul[] = "printf\0ok";
  report_source("NUL input", nul, sizeof(nul) - 1);
  return EXIT_SUCCESS;
}
