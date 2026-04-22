#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

/*
 * policy_ctx.c - Shared policy context: arena allocator and string pool.
 *
 * Multiple policies share a context to deduplicate token strings across
 * policy sets and allocate all trie nodes from a contiguous arena.
 */

#include "shelltype.h"
#include "filter_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define DEFAULT_ARENA_SIZE (256 * 1024)  /* 256 KB default */
#define STR_POOL_INIT_CAP  1024

/* ============================================================
 * ARENA ALLOCATOR
 * ============================================================ */

typedef struct {
    char   *base;
    size_t  size;
    size_t  used;
} arena_t;

static bool arena_init(arena_t *a, size_t size)
{
    a->base = malloc(size);
    if (!a->base) return false;
    a->size = size;
    a->used = 0;
    return true;
}

static void arena_free(arena_t *a)
{
    free(a->base);
    a->base = NULL;
    a->size = 0;
    a->used = 0;
}

static void *arena_alloc(arena_t *a, size_t n)
{
    /* Align to 8 bytes */
    if (n > SIZE_MAX - 7) return NULL;
    n = (n + 7) & ~(size_t)7;
    if (a->used + n > a->size) {
        /* Grow arena: double size, or enough for request + 1KB padding */
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

__attribute__((unused))
static size_t arena_used(const arena_t *a)
{
    return a->used;
}

/* ============================================================
 * STRING POOL
 * ============================================================ */

typedef struct {
    const char **strings;
    uint64_t   *hashes;
    size_t       count;
    size_t       capacity;
} str_pool_t;

#define HASH_EMPTY 0

static bool str_pool_init(str_pool_t *p)
{
    p->strings = calloc(STR_POOL_INIT_CAP, sizeof(const char *));
    if (!p->strings) return false;
    p->hashes = calloc(STR_POOL_INIT_CAP, sizeof(uint64_t));
    if (!p->hashes) { free((void *)p->strings); return false; }
    p->count = 0;
    p->capacity = STR_POOL_INIT_CAP;
    return true;
}

static void str_pool_free(str_pool_t *p)
{
    /* Strings are arena-allocated, don't free individually */
    free((void *)p->strings);
    free(p->hashes);
    p->strings = NULL;
    p->hashes = NULL;
}

static bool str_pool_grow(str_pool_t *p)
{
    size_t new_cap = p->capacity * 2;
    const char **new_strings = realloc((void *)p->strings, new_cap * sizeof(const char *));
    if (!new_strings) return false;
    uint64_t *new_hashes = realloc(p->hashes, new_cap * sizeof(uint64_t));
    if (!new_hashes) { free(new_strings); return false; }
    memset(&new_hashes[p->capacity], 0, (new_cap - p->capacity) * sizeof(uint64_t));
    p->strings = new_strings;
    p->hashes = new_hashes;
    p->capacity = new_cap;
    return true;
}

/* ============================================================
 * CONTEXT LIFECYCLE
 * ============================================================ */

struct st_policy_ctx {
    arena_t    arena;
    str_pool_t str_pool;
};

st_policy_ctx_t *st_policy_ctx_new(void)
{
    return st_policy_ctx_new_with_arena(DEFAULT_ARENA_SIZE);
}

st_policy_ctx_t *st_policy_ctx_new_with_arena(size_t arena_size)
{
    st_policy_ctx_t *ctx = malloc(sizeof(st_policy_ctx_t));
    if (!ctx) return NULL;

    if (!arena_init(&ctx->arena, arena_size)) {
        free(ctx);
        return NULL;
    }

    if (!str_pool_init(&ctx->str_pool)) {
        arena_free(&ctx->arena);
        free(ctx);
        return NULL;
    }

    return ctx;
}

void st_policy_ctx_free(st_policy_ctx_t *ctx)
{
    if (!ctx) return;
    str_pool_free(&ctx->str_pool);
    arena_free(&ctx->arena);
    free(ctx);
}

/*
 * NOTE: This resets the context for reuse, clearing all interned strings
 * and freeing the arena. Use this before loading a new policy into
 * a cleared context. Any previously created policies using this context
 * become invalid after reset.
 */
void st_policy_ctx_reset(st_policy_ctx_t *ctx)
{
    if (!ctx) return;
    free(ctx->arena.base);
    ctx->arena.base = malloc(DEFAULT_ARENA_SIZE);
    ctx->arena.size = DEFAULT_ARENA_SIZE;
    ctx->arena.used = 0;
    str_pool_free(&ctx->str_pool);
    str_pool_init(&ctx->str_pool);
}

const char *st_policy_ctx_intern(st_policy_ctx_t *ctx, const char *str)
{
    if (!ctx || !str) return NULL;

    uint64_t h = filter_hash_fnv1a(str, strlen(str));

    /* Linear scan for existing string (hash array stored for future optimization) */
    for (size_t i = 0; i < ctx->str_pool.count; i++) {
        if (ctx->str_pool.hashes[i] == h &&
            strcmp(ctx->str_pool.strings[i], str) == 0) {
            return ctx->str_pool.strings[i];
        }
    }

    /* Allocate copy in arena */
    size_t len = strlen(str) + 1;
    char *copy = arena_alloc(&ctx->arena, len);
    if (!copy) return NULL;
    memcpy(copy, str, len);

    /* Add to pool */
    if (ctx->str_pool.count >= ctx->str_pool.capacity) {
        if (!str_pool_grow(&ctx->str_pool)) return NULL;
    }
    ctx->str_pool.hashes[ctx->str_pool.count] = h;
    ctx->str_pool.strings[ctx->str_pool.count++] = copy;
    return copy;
}

size_t st_policy_ctx_memory_usage(const st_policy_ctx_t *ctx)
{
    if (!ctx) return 0;
    return sizeof(st_policy_ctx_t) + ctx->arena.used
           + ctx->str_pool.capacity * sizeof(const char *);
}
