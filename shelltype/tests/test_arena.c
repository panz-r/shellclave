/*
 * Focused tests for ShellType's internal bump allocator.
 */

#include "arena.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ASSERT(condition)                                                      \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "Assertion failed: %s at %s:%d\n", #condition, __FILE__, \
              __LINE__);                                                       \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int main(void) {
  arena_t arena = {0};
  ASSERT(arena_init(&arena, 1));
  ASSERT(arena_used(&arena) == 0);

  unsigned char *first = arena_alloc(&arena, 1);
  ASSERT(first != NULL);
  ASSERT(arena_used(&arena) == 8);
  memset(first, 0xa5, 8);

  size_t capacity = arena.size;
  char *base = arena.base;
  unsigned char *exact = arena_alloc(&arena, capacity - arena.used);
  ASSERT(exact == (unsigned char *)base + 8);
  ASSERT(arena.base == base);
  ASSERT(arena_used(&arena) == capacity);
  exact[capacity - 9] = 0x5a;

  void *zero = arena_alloc(&arena, 0);
  ASSERT(zero == arena.base + capacity);
  ASSERT(arena.base == base);
  ASSERT(arena_used(&arena) == capacity);

  unsigned char *grown = arena_alloc(&arena, 1);
  ASSERT(grown == (unsigned char *)arena.base + capacity);
  ASSERT(arena.size == capacity * 2);
  ASSERT(arena_used(&arena) == capacity + 8);
  ASSERT(memcmp(arena.base, "\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5", 8) == 0);
  ASSERT((unsigned char)arena.base[capacity - 1] == 0x5a);

  static const struct {
    size_t size;
    size_t used;
    size_t request;
  } rejected[] = {
      {0, 1, 1},
      {SIZE_MAX, SIZE_MAX - 4, 8},
      {SIZE_MAX / 2 + 1, SIZE_MAX / 2 + 1, 1},
      {0, 0, SIZE_MAX},
  };
  char sentinel = 0;
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    arena_t invalid = {
        .base = &sentinel, .size = rejected[i].size, .used = rejected[i].used};
    ASSERT(arena_alloc(&invalid, rejected[i].request) == NULL);
    ASSERT(invalid.base == &sentinel);
    ASSERT(invalid.size == rejected[i].size);
    ASSERT(invalid.used == rejected[i].used);
  }

  arena_free(&arena);
  ASSERT(arena.base == NULL);
  ASSERT(arena.size == 0);
  ASSERT(arena_used(&arena) == 0);
  arena_free(&arena);
  return 0;
}
