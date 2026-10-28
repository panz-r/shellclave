#ifndef SHELL_ARITHMETIC_INTERNAL_H
#define SHELL_ARITHMETIC_INTERNAL_H

#include "shell_contract.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Private analysis of immutable arithmetic source. Supported expressions use
 * only numeric literals, pure operators, parentheses and nested $((...)).
 * Recognition is independent of proof: arithmetic outside the checked signed
 * 64-bit proof domain remains supported with known == false. No runtime error
 * execution or variable lookup is performed. Outputs never borrow storage.
 * Required source is readable for length bytes, including length zero. */
typedef struct {
  bool supported;
  bool known;
  int64_t value;
} shell_arithmetic_result_t;

shell_arithmetic_result_t shell_arithmetic_analyze(const char *source,
                                                   size_t length)
    SHELL_NONNULL(1);
/* Expanded arithmetic values may read scalar names. Shell expansion syntax
 * and backslash escapes are not interpreted at this boundary. Their recursively
 * interpreted values remain unresolved; the observer records direct reads, not
 * a complete transitive dependency graph. Scalar mode retains pure operators;
 * prefix and postfix mutations are unsupported, including in skipped branches.
 * visitor may be NULL to classify only.
 */
typedef void (*shell_arithmetic_reference_fn)(const char *name, size_t length,
                                              void *context);
typedef struct {
  shell_arithmetic_result_t result;
  bool references;
  bool mutation; /* Proven unsupported mutation; survives source projection. */
  bool unresolved; /* Source expansion could not be reduced to pure arithmetic.
                    */
} shell_arithmetic_scalar_result_t;
shell_arithmetic_scalar_result_t
shell_arithmetic_analyze_scalar(const char *source, size_t length,
                                shell_arithmetic_reference_fn visitor,
                                void *context) SHELL_NONNULL(1);

bool shell_arithmetic_substring_supported(const char *source, size_t length)
    SHELL_NONNULL(1);

#endif
