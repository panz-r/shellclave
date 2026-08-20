/*
 * arena.c - Simple arena allocator
 */

#include "arena.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "alloc.h"

bool arena_init(arena_t *a, size_t size) {
  a->base = malloc(size);
  if (!a->base)
    return false;
  a->size = size;
  a->used = 0;
  return true;
}

void arena_free(arena_t *a) {
  free(a->base);
  a->base = NULL;
  a->size = 0;
  a->used = 0;
}

void *arena_alloc(arena_t *a, size_t n) {
  if (n > SIZE_MAX - 7)
    return NULL;
  n = (n + 7) & ~(size_t)7;
  if (a->used > a->size || n > SIZE_MAX - a->used)
    return NULL;
  size_t required = a->used + n;
  if (required > a->size) {
    if (a->size > SIZE_MAX / 2)
      return NULL;
    size_t new_size = a->size * 2;
    if (new_size < required) {
      if (required > SIZE_MAX - 1024)
        new_size = required;
      else
        new_size = required + 1024;
    }
    char *new_base = realloc(a->base, new_size);
    if (!new_base)
      return NULL;
    a->base = new_base;
    a->size = new_size;
  }
  void *p = a->base + a->used;
  a->used += n;
  return p;
}

bool arena_reserve(arena_t *a, size_t additional) {
  if (additional > SIZE_MAX - a->used)
    return false;
  size_t required = a->used + additional;
  if (required <= a->size)
    return true;
  size_t new_size = a->size;
  while (new_size < required) {
    if (new_size > SIZE_MAX / 2) {
      new_size = required;
      break;
    }
    new_size *= 2;
  }
  char *new_base = realloc(a->base, new_size);
  if (!new_base)
    return false;
  a->base = new_base;
  a->size = new_size;
  return true;
}

size_t arena_used(const arena_t *a) { return a->used; }
