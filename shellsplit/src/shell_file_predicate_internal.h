#ifndef SHELL_FILE_PREDICATE_INTERNAL_H
#define SHELL_FILE_PREDICATE_INTERNAL_H

/* Shared filesystem-predicate vocabulary. Each row supplies the public-kind
 * suffix, local name, ordinal and two equivalent spellings. Ordinals start at
 * zero and are contiguous; spellings are two-byte unary operators. A predicate
 * with one spelling repeats it; consumers fold the duplicate comparison away.
 * Expand into the caller's existing lexical/value comparisons and switches.
 * Source quoting, builtin argument grammar and graph effects stay with their
 * respective owners. Public enum declarations retain their stable values. */
#define SHELL_FILE_PREDICATES(X)                                               \
  X(EXISTS, exists, 0, "-e", "-a")                                             \
  X(REGULAR, regular, 1, "-f", "-f")                                           \
  X(DIRECTORY, directory, 2, "-d", "-d")                                       \
  X(SYMLINK, symlink, 3, "-L", "-h")                                           \
  X(NONEMPTY, nonempty, 4, "-s", "-s")                                         \
  X(BLOCK, block, 5, "-b", "-b")                                               \
  X(CHARACTER, character, 6, "-c", "-c")                                       \
  X(FIFO, fifo, 7, "-p", "-p")                                                 \
  X(SOCKET, socket, 8, "-S", "-S")                                             \
  X(READABLE, readable, 9, "-r", "-r")                                         \
  X(WRITABLE, writable, 10, "-w", "-w")                                        \
  X(EXECUTABLE, executable, 11, "-x", "-x")                                    \
  X(SETUID, setuid, 12, "-u", "-u")                                            \
  X(SETGID, setgid, 13, "-g", "-g")                                            \
  X(STICKY, sticky, 14, "-k", "-k")                                            \
  X(OWNED_BY_USER, owned_by_user, 15, "-O", "-O")                              \
  X(OWNED_BY_GROUP, owned_by_group, 16, "-G", "-G")                            \
  X(MODIFIED_SINCE_READ, modified_since_read, 17, "-N", "-N")

#define SHELL_FILE_COUNT(kind, name, ordinal, spelling, alias) +1
enum { SHELL_FILE_PREDICATE_COUNT = 0 SHELL_FILE_PREDICATES(SHELL_FILE_COUNT) };
#undef SHELL_FILE_COUNT

/* Binary pathname comparisons have ordered operands and their own graph
 * representation. Ordinals map to comparison-node kind bits, independently
 * of unary FILE_TEST flags and unary grammar roles. */
#define SHELL_FILE_COMPARISONS(X)                                              \
  X(NEWER, newer, 0, "-nt")                                                    \
  X(OLDER, older, 1, "-ot")                                                    \
  X(SAME, same, 2, "-ef")

#define SHELL_FILE_COMPARISON_COUNT_ROW(kind, name, ordinal, spelling) +1
enum {
  SHELL_FILE_COMPARISON_COUNT =
      0 SHELL_FILE_COMPARISONS(SHELL_FILE_COMPARISON_COUNT_ROW)
};
#undef SHELL_FILE_COMPARISON_COUNT_ROW

#endif
