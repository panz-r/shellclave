#ifndef SHELLSPLIT_TEST_ANSI_PARAMETER_CASES_H
#define SHELLSPLIT_TEST_ANSI_PARAMETER_CASES_H

#include "shell_processor.h"

/* Complete parameter words whose ANSI-C decoding can introduce shell syntax.
 * Graph nodes borrow raw source, so these require UNSUPPORTED rather than a
 * successful graph which silently omits the decoded executable source.
 * The processor preserves its boundary distinction: byte-admission rejection
 * is EINPUT; ASCII decoded-syntax rejection is EPARSE. */
static const struct {
  const char *source;
  shell_process_status_t process_status;
} shellsplit_test_ansi_encoded_cases[] = {
    {"echo \"${v:-$'\\444(printf child)'}\"", SHELL_PROCESS_EPARSE},
    {"echo \"${v:-$'日本\\444(printf child)'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'\\540printf child\\540'}\"", SHELL_PROCESS_EPARSE},
    {"echo \"${v:-$'日本\\540printf child\\540'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\534'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\450'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\451'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\474'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\476'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\573'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\575'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\447'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\442'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\x24(printf child)'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\044(printf child)'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\u0024(printf child)'}\"", SHELL_PROCESS_EINPUT},
    {"echo \"${v:-$'日本\\U00000024(printf child)'}\"", SHELL_PROCESS_EINPUT},
};

#endif
