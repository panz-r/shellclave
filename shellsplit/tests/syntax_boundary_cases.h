#ifndef SHELLSPLIT_SYNTAX_BOUNDARY_CASES_H
#define SHELLSPLIT_SYNTAX_BOUNDARY_CASES_H

/* Shared source fixtures for API rejection/propagation checks. This integer
 * comparison is deliberately outside the conditional subset. When
 * support grows, update its spelling and operand framing here; callers retain
 * independent outcomes and their timing, nesting and continuation contexts.
 * These fixtures do not consult implementation definitions or classify source.
 */
#define SHELLSPLIT_TEST_UNMODELED_BINARY_LETTERS "eq"
#define SHELLSPLIT_TEST_UNMODELED_BINARY_WORD                                  \
  "-" SHELLSPLIT_TEST_UNMODELED_BINARY_LETTERS
#define SHELLSPLIT_TEST_UNMODELED_BINARY_CONTINUED_WORD                        \
  "-\\\n" SHELLSPLIT_TEST_UNMODELED_BINARY_LETTERS
#define SHELLSPLIT_TEST_UNMODELED_BINARY_CONDITION(path)                       \
  "[[ " path " " SHELLSPLIT_TEST_UNMODELED_BINARY_WORD " other ]]"

#endif
