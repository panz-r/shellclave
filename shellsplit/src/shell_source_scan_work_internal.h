#ifndef SHELL_SOURCE_SCAN_WORK_INTERNAL_H
#define SHELL_SOURCE_SCAN_WORK_INTERNAL_H

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
#include "test_source_scans.h"
#define SHELL_SOURCE_PREFIX_SCAN(length)                                       \
  shellsplit_test_source_scan_charge(length)
#define SHELL_SOURCE_DELIMITER_SCAN(input, position)                           \
  shellsplit_test_delimiter_charge((input) + (position), 1)
#define SHELL_SOURCE_LINE_SCAN(length) shellsplit_test_line_scan_charge(length)
#else
#define SHELL_SOURCE_PREFIX_SCAN(length) ((void)0)
#define SHELL_SOURCE_DELIMITER_SCAN(input, position) ((void)0)
#define SHELL_SOURCE_LINE_SCAN(length) ((void)0)
#endif

/* Count actual word-scanner transitions, including failed delimiter probes.
 * This compiles away in shipping builds. */
#define SHELL_SOURCE_WORD_SCAN(length) SHELL_SOURCE_PREFIX_SCAN(length)

#endif
