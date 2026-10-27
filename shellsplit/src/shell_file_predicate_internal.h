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
  X(SOCKET, socket, 8, "-S", "-S")

#define SHELL_FILE_COUNT(kind, name, ordinal, spelling, alias) +1
enum { SHELL_FILE_PREDICATE_COUNT = 0 SHELL_FILE_PREDICATES(SHELL_FILE_COUNT) };
#undef SHELL_FILE_COUNT

#endif
