#include "source_word_probe.h"

#include "../src/shell_source_internal.h"

bool fuzz_source_word_has_glob(const char *input, size_t length) {
  return shell_source_word_has_glob(input, length);
}

bool fuzz_source_word_parameter_name(const char *input, size_t length,
                                     const char **name, size_t *name_length) {
  return shell_source_word_parameter_name(input, length, name, name_length);
}
