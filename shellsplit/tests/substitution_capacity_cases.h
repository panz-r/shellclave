#ifndef SHELLSPLIT_SUBSTITUTION_CAPACITY_CASES_H
#define SHELLSPLIT_SUBSTITUTION_CAPACITY_CASES_H

#include "shell_depgraph.h"
#include <stdio.h>

/* Every tail contains a real nested command. Test the same descriptor snapshot
 * boundary through each consumer, including compound redirect events. */
static const char *const shellsplit_test_substitution_capacity_cases[] = {
    "echo \"$(producer)\"",
    "echo <(producer)",
    "echo >(producer)",
    "VALUE=$(producer) echo end",
    "VALUE=$(producer)",
    "export VALUE=$(producer)",
    "cat >\"$(producer)\"",
    "cat < <(producer)",
    "echo end > >(producer)",
    "cat <<<\"$(producer)\"",
    "cat <<EOF\n$(producer)\nEOF\n",
    "{ cat; } >\"$(producer)\"",
    "{ cat; } < <(producer)",
    "{ echo end; } > >(producer)",
    "{ cat; } <<<\"$(producer)\"",
    "{ cat; } <<EOF\n$(producer)\nEOF\n",
    "echo $(< <(producer))",
    "echo $(<$(producer))",
    "echo \"$(time producer)\"",
};

/* Unknown probe outcomes leave the initial route and each later route live.
 * `changes == MAX - 1` fits exactly; MAX exceeds the alternative budget by one.
 * Required outputs reference distinct writable storage; tail is terminated. */
static SHELL_NONNULL(1, 4, 5) bool shellsplit_test_substitution_capacity_source(
    char *source, size_t capacity, unsigned changes, const char *tail,
    size_t *length) {
  *length = 0;
  int written = snprintf(source, capacity, "exec 2>base || exit;");
  if (written < 0 || (size_t)written >= capacity)
    return false;
  size_t used = (size_t)written;
  for (unsigned i = 0; i < changes; i++) {
    written = snprintf(source + used, capacity - used,
                       " probe && exec 2>route%u;", i);
    if (written < 0 || (size_t)written >= capacity - used)
      return false;
    used += (size_t)written;
  }
  written = snprintf(source + used, capacity - used, " %s", tail);
  if (written < 0 || (size_t)written >= capacity - used)
    return false;
  *length = used + (size_t)written;
  return true;
}

#endif
