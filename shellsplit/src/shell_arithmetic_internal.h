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
bool shell_arithmetic_substring_supported(const char *source, size_t length)
    SHELL_NONNULL(1);

#endif
