#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

/*
 * policy_ctx.c - Shared policy context: arena allocator and string pool.
 *
 * Multiple policies share a context to deduplicate token strings across
 * policy sets and allocate all trie nodes from a contiguous arena.
 */

#include "shelltype.h"
#include "arena.h"
#include "filter_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <stdatomic.h>

#define DEFAULT_ARENA_SIZE (256 * 1024)  /* 256 KB default */
#define STR_POOL_INIT_CAP  1024

/* ============================================================
 * STRING POOL
 * ============================================================ */

typedef struct {
    const char **slots;
    uint64_t   *hashes;
    size_t       count;
    size_t       capacity;
} str_pool_t;

#define HASH_EMPTY 0

static bool str_pool_init(str_pool_t *p)
{
    p->capacity = STR_POOL_INIT_CAP;
    p->slots = calloc(p->capacity, sizeof(const char *));
    if (!p->slots) return false;
    p->hashes = calloc(p->capacity, sizeof(uint64_t));
    if (!p->hashes) { free(p->slots); return false; }
    p->count = 0;
    for (size_t i = 0; i < p->capacity; i++) p->hashes[i] = HASH_EMPTY;
    return true;
}

static void str_pool_free(str_pool_t *p)
{
    free(p->slots);
    free(p->hashes);
    p->slots = NULL;
    p->hashes = NULL;
    p->count = 0;
    p->capacity = 0;
}

static bool str_pool_grow(str_pool_t *p)
{
    size_t new_cap = p->capacity * 2;
    const char **new_slots = calloc(new_cap, sizeof(const char *));
    if (!new_slots) return false;
    uint64_t *new_hashes = calloc(new_cap, sizeof(uint64_t));
    if (!new_hashes) { free(new_slots); return false; }
    for (size_t i = 0; i < new_cap; i++) new_hashes[i] = HASH_EMPTY;
    for (size_t i = 0; i < p->capacity; i++) {
        if (p->hashes[i] != HASH_EMPTY) {
            size_t pos = p->hashes[i] % new_cap;
            while (new_hashes[pos] != HASH_EMPTY) {
                pos = (pos + 1) % new_cap;
            }
            new_slots[pos] = p->slots[i];
            new_hashes[pos] = p->hashes[i];
        }
    }
    free(p->slots);
    free(p->hashes);
    p->slots = new_slots;
    p->hashes = new_hashes;
    p->capacity = new_cap;
    return true;
}

/* ============================================================
 * CONTEXT LIFECYCLE
 * ============================================================ */

struct st_policy_ctx {
    arena_t         arena;
    str_pool_t      str_pool;
    _Atomic unsigned refcount;  /* Reference count for safe cleanup */
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

    atomic_init(&ctx->refcount, 1);
    return ctx;
}

void st_policy_ctx_free(st_policy_ctx_t *ctx)
{
    if (!ctx) return;
    str_pool_free(&ctx->str_pool);
    arena_free(&ctx->arena);
    free(ctx);
}

void st_policy_ctx_retain(st_policy_ctx_t *ctx)
{
    if (!ctx) return;
    atomic_fetch_add(&ctx->refcount, 1);
}

void st_policy_ctx_release(st_policy_ctx_t *ctx)
{
    if (!ctx) return;
    if (atomic_fetch_sub(&ctx->refcount, 1) == 1) {
        st_policy_ctx_free(ctx);
    }
}

/*
 * Reset the context for reuse, clearing all interned strings and freeing the arena.
 * Use this before loading a new policy into a cleared context.
 *
 * Returns ST_ERR_INVALID if there are active references (policies using this context).
 * Use st_policy_ctx_release() to drop all references before resetting.
 */
st_error_t st_policy_ctx_reset(st_policy_ctx_t *ctx)
{
    if (!ctx) return ST_ERR_INVALID;
    
    /* Only allow reset if no policies are using the context.
     * refcount == 1: context only, no policies
     * refcount == 2: one policy exists, cannot reset */
    if (atomic_load(&ctx->refcount) > 1) {
        return ST_ERR_INVALID;
    }
    
    arena_free(&ctx->arena);
    arena_init(&ctx->arena, DEFAULT_ARENA_SIZE);
    str_pool_free(&ctx->str_pool);
    str_pool_init(&ctx->str_pool);
    return ST_OK;
}

bool st_policy_ctx_is_exclusive(const st_policy_ctx_t *ctx)
{
    if (!ctx) return false;
    /* Context is exclusive if exactly one policy is using it (refcount == 2).
     * refcount = 1: no policies (just ctx)
     * refcount = 2: one policy (safe to compact)
     * refcount > 2: multiple policies (not exclusive)
     * Compact requires exclusive context so it can safely rebuild the trie. */
    return atomic_load(&ctx->refcount) == 2;
}

static uint64_t str_pool_hash(const char *str, size_t len)
{
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)(uint8_t)str[i];
        h *= 1099511628211ull;
    }
    return h;
}

const char *st_policy_ctx_intern(st_policy_ctx_t *ctx, const char *str)
{
    if (!ctx || !str) return NULL;
    size_t len = strlen(str);
    if (len == 0) return "";

    uint64_t h = str_pool_hash(str, len);
    size_t pos = h % ctx->str_pool.capacity;

    while (ctx->str_pool.hashes[pos] != HASH_EMPTY) {
        if (ctx->str_pool.hashes[pos] == h) {
            const char *existing = ctx->str_pool.slots[pos];
            if (strcmp(existing, str) == 0) return existing;
        }
        pos = (pos + 1) % ctx->str_pool.capacity;
    }

    if (ctx->str_pool.count >= ctx->str_pool.capacity * 3 / 4) {
        if (!str_pool_grow(&ctx->str_pool)) return NULL;
        pos = h % ctx->str_pool.capacity;
        while (ctx->str_pool.hashes[pos] != HASH_EMPTY) {
            pos = (pos + 1) % ctx->str_pool.capacity;
        }
    }

    char *copy = arena_alloc(&ctx->arena, len + 1);
    if (!copy) return NULL;
    memcpy(copy, str, len);
    copy[len] = '\0';

    ctx->str_pool.slots[pos] = copy;
    ctx->str_pool.hashes[pos] = h;
    ctx->str_pool.count++;
    return copy;
}

size_t st_policy_ctx_memory_usage(const st_policy_ctx_t *ctx)
{
    if (!ctx) return 0;
    return sizeof(st_policy_ctx_t) + ctx->arena.used
           + ctx->str_pool.capacity * sizeof(const char *);
}

st_error_t st_policy_ctx_compact(st_policy_ctx_t *ctx)
{
    if (!ctx) return ST_ERR_INVALID;
    
    /* Only allow compact if no policies are using the context (refcount == 1) */
    if (atomic_load(&ctx->refcount) != 1) {
        return ST_ERR_INVALID;
    }
    
    /* Compact arena: reinit with current used size + 10% overhead for future allocations */
    size_t compact_size = arena_used(&ctx->arena) + arena_used(&ctx->arena) / 10;
    if (compact_size < DEFAULT_ARENA_SIZE) compact_size = DEFAULT_ARENA_SIZE;
    
    arena_free(&ctx->arena);
    if (!arena_init(&ctx->arena, compact_size)) {
        arena_init(&ctx->arena, DEFAULT_ARENA_SIZE);  /* Fallback */
        return ST_ERR_MEMORY;
    }
    
    /* Compact string pool: reinit to current count */
    str_pool_free(&ctx->str_pool);
    if (!str_pool_init(&ctx->str_pool)) {
        return ST_ERR_MEMORY;
    }
    
    return ST_OK;
}
