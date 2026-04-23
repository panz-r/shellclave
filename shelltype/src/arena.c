/*
 * arena.c - Simple arena allocator
 */

#include "arena.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

bool arena_init(arena_t *a, size_t size)
{
    a->base = malloc(size);
    if (!a->base) return false;
    a->size = size;
    a->used = 0;
    return true;
}

void arena_free(arena_t *a)
{
    free(a->base);
    a->base = NULL;
    a->size = 0;
    a->used = 0;
}

void *arena_alloc(arena_t *a, size_t n)
{
    if (n > SIZE_MAX - 7) return NULL;
    n = (n + 7) & ~(size_t)7;
    if (a->used + n > a->size) {
        if (a->size > SIZE_MAX / 2) return NULL;
        size_t new_size = a->size * 2;
        if (new_size < a->used + n) new_size = a->used + n + 1024;
        char *new_base = realloc(a->base, new_size);
        if (!new_base) return NULL;
        a->base = new_base;
        a->size = new_size;
    }
    void *p = a->base + a->used;
    a->used += n;
    return p;
}

size_t arena_used(const arena_t *a)
{
    return a->used;
}
