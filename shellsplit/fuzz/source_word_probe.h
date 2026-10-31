#ifndef SHELLSPLIT_FUZZ_SOURCE_WORD_PROBE_H
#define SHELLSPLIT_FUZZ_SOURCE_WORD_PROBE_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Fuzzer access to word predicates that exist only as C inline functions in
 * shell_source_internal.h. That header is C-only, so it is compiled as C in
 * source_word_probe.c and the C++ fuzzer sees only these declarations. Both
 * functions forward to the internal predicates and share their contracts. */
bool fuzz_source_word_has_glob(const char *input, size_t length);
bool fuzz_source_word_parameter_name(const char *input, size_t length,
                                     const char **name, size_t *name_length);

#ifdef __cplusplus
}
#endif

#endif
