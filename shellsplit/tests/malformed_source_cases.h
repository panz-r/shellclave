#ifndef SHELLSPLIT_TEST_MALFORMED_SOURCE_CASES_H
#define SHELLSPLIT_TEST_MALFORMED_SOURCE_CASES_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* Shared across component tests and fixed fuzz oracles. These inputs are
 * parsed only, never executed. Include failures inside otherwise closed words
 * and documents, not just visibly unfinished outer delimiters. */
static const char *const shellsplit_test_malformed_tails[] = {
    "echo `unfinished",
    "echo $(unfinished",
    "echo $((1",
    "echo ${unfinished",
    "echo <(unfinished",
    "echo >(unfinished",
    "echo 'unfinished",
    "echo \"unfinished",
    "printf $(printf $(printf 'unterminated))",
    "printf -v\"${unfinished",
    "declare name=\"unfinished",
    "{ echo unfinished;",
    "( echo unfinished",
    "if true; then echo unfinished",
    "while true; do echo unfinished",
    "cat <<EOF\nunfinished\n",
    "echo ${value:-$(unfinished}",
    "echo ${value:-`unfinished}",
    "echo ${value:-$(printf complete)",
    "echo $((1 + $(printf complete))",
    "cat <<EOF\n$(unfinished\nEOF\n",
    "cat <<EOF\n${value:-$(unfinished}\nEOF\n",
};

static inline bool shellsplit_test_source_with_tail(char *out, size_t capacity,
                                                    size_t commands,
                                                    const char *tail,
                                                    size_t *length) {
  static const char prefix[] = "echo ok; ";
  size_t tail_length = strlen(tail);
  if (tail_length >= capacity ||
      commands > (capacity - tail_length - 1) / (sizeof(prefix) - 1))
    return false;
  *length = commands * (sizeof(prefix) - 1);
  for (size_t i = 0; i < commands; i++)
    memcpy(out + i * (sizeof(prefix) - 1), prefix, sizeof(prefix) - 1);
  memcpy(out + *length, tail, tail_length + 1);
  *length += tail_length;
  return true;
}

#endif
