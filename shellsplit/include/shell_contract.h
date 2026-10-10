#ifndef SHELL_CONTRACT_H
#define SHELL_CONTRACT_H

/* Shared C/C++ API preconditions. Indices are one-based parameter positions.
 * Required pointers must address valid storage for the documented lifetime
 * and size. Violating a precondition is invalid API use, not a runtime error
 * recovery path. Unannotated pointers are nullable only where the API defines
 * a meaning for NULL (defaults, optional outputs, empty spans, or cleanup).
 * Annotations do not validate shell syntax, encoded data, sizes, or I/O. */
#if defined(__GNUC__) || defined(__clang__)
#define SHELL_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#else
#define SHELL_NONNULL(...)
#endif

#endif /* SHELL_CONTRACT_H */
