#ifndef SHELLSPLIT_SYNTAX_BOUNDARY_CASES_H
#define SHELLSPLIT_SYNTAX_BOUNDARY_CASES_H

/* Shared source fixtures for API rejection/propagation checks. This operator
 * is deliberately outside the supported conditional subset. When support
 * grows, update its spelling here; callers retain independent expected
 * outcomes and their timing, nesting and continuation contexts. These fixtures
 * do not consult implementation predicate definitions or classify source. */
#define SHELLSPLIT_TEST_UNMODELED_FILE_LETTER "r"
#define SHELLSPLIT_TEST_UNMODELED_FILE_WORD                                    \
  "-" SHELLSPLIT_TEST_UNMODELED_FILE_LETTER
#define SHELLSPLIT_TEST_UNMODELED_FILE_CONTINUED_WORD                          \
  "-\\\n" SHELLSPLIT_TEST_UNMODELED_FILE_LETTER
#define SHELLSPLIT_TEST_UNMODELED_FILE_CONDITION(path)                         \
  "[[ " SHELLSPLIT_TEST_UNMODELED_FILE_WORD " " path " ]]"

#endif
