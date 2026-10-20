#ifndef SHELL_ASCII_H
#define SHELL_ASCII_H

#include "shell_contract.h"
#include <stdbool.h>
#include <stddef.h>

/* Private byte predicates for fixed-format syntax and classifications. High
 * bytes remain opaque data; the embedding application's locale never changes
 * these sets. Shell grammar blanks and line endings have narrower rules. */
static inline bool shell_ascii_alpha(unsigned char byte) {
  return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z');
}

static inline bool shell_ascii_digit(unsigned char byte) {
  return byte >= '0' && byte <= '9';
}

static inline bool shell_ascii_alnum(unsigned char byte) {
  return shell_ascii_alpha(byte) || shell_ascii_digit(byte);
}

static inline bool shell_ascii_xdigit(unsigned char byte) {
  return shell_ascii_digit(byte) || (byte >= 'A' && byte <= 'F') ||
         (byte >= 'a' && byte <= 'f');
}

static inline bool shell_ascii_lower(unsigned char byte) {
  return byte >= 'a' && byte <= 'z';
}

static inline bool shell_ascii_space(unsigned char byte) {
  return byte == ' ' || (byte >= '\t' && byte <= '\r');
}

static inline bool shell_ascii_print(unsigned char byte) {
  return byte >= 0x20 && byte <= 0x7e;
}

static inline unsigned char shell_ascii_fold(unsigned char byte) {
  return byte >= 'A' && byte <= 'Z' ? (unsigned char)(byte + ('a' - 'A'))
                                    : byte;
}

/* Both spans reference length readable bytes. No terminators are required. */
static inline SHELL_NONNULL(1, 2) bool shell_ascii_equal_ci(const char *left,
                                                            const char *right,
                                                            size_t length) {
  for (size_t i = 0; i < length; ++i)
    if (shell_ascii_fold((unsigned char)left[i]) !=
        shell_ascii_fold((unsigned char)right[i]))
      return false;
  return true;
}

#endif
