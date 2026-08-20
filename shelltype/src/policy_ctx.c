#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

/*
 * policy_ctx.c - Shared policy context: stable string chunks and string pool.
 *
 * Multiple policies share a context to deduplicate token strings across
 * policy sets. Chunks never move, so every interned pointer remains valid
 * until the context is reset or freed.
 */

#include "policy_ctx.h"
#include "filter_hash.h"
#include "shelltype.h"

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alloc.h"

#define DEFAULT_ARENA_SIZE (256 * 1024) /* 256 KB default */
#define STR_POOL_INIT_CAP 1024

/* --- STRING POOL --- */

typedef struct {
  const char **slots;
  uint64_t *hashes;
  size_t count;
  size_t capacity;
} str_pool_t;

typedef struct str_chunk {
  struct str_chunk *next;
  size_t used;
  size_t capacity;
  char data[];
} str_chunk_t;

#define HASH_EMPTY 0

static bool str_pool_init(str_pool_t *p) {
  p->capacity = STR_POOL_INIT_CAP;
  p->slots = calloc(p->capacity, sizeof(const char *));
  if (!p->slots)
    return false;
  p->hashes = calloc(p->capacity, sizeof(uint64_t));
  if (!p->hashes) {
    free(p->slots);
    return false;
  }
  p->count = 0;
  for (size_t i = 0; i < p->capacity; i++)
    p->hashes[i] = HASH_EMPTY;
  return true;
}

static void str_pool_free(str_pool_t *p) {
  free(p->slots);
  free(p->hashes);
  p->slots = NULL;
  p->hashes = NULL;
  p->count = 0;
  p->capacity = 0;
}

static str_chunk_t *str_chunk_new(size_t capacity) {
  if (capacity == 0)
    capacity = 1;
  if (capacity > SIZE_MAX - sizeof(str_chunk_t))
    return NULL;
  str_chunk_t *chunk = malloc(sizeof(*chunk) + capacity);
  if (!chunk)
    return NULL;
  chunk->next = NULL;
  chunk->used = 0;
  chunk->capacity = capacity;
  return chunk;
}

static void str_chunks_free(str_chunk_t *chunk) {
  while (chunk) {
    str_chunk_t *next = chunk->next;
    free(chunk);
    chunk = next;
  }
}

static bool str_pool_grow(str_pool_t *p) {
  size_t new_cap = p->capacity * 2;
  const char **new_slots = calloc(new_cap, sizeof(const char *));
  if (!new_slots)
    return false;
  uint64_t *new_hashes = calloc(new_cap, sizeof(uint64_t));
  if (!new_hashes) {
    free(new_slots);
    return false;
  }
  for (size_t i = 0; i < new_cap; i++)
    new_hashes[i] = HASH_EMPTY;
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

/* --- CONTEXT LIFECYCLE --- */

struct st_policy_ctx {
  str_pool_t str_pool;
  str_chunk_t *str_chunks;
  size_t chunk_size;
  pthread_mutex_t lock;
  _Atomic unsigned refcount; /* Reference count for safe cleanup */
};

static char *str_chunks_alloc(st_policy_ctx_t *ctx, size_t size) {
  str_chunk_t *chunk = ctx->str_chunks;
  if (size > chunk->capacity - chunk->used) {
    size_t capacity = ctx->chunk_size;
    if (capacity < size)
      capacity = size;
    chunk = str_chunk_new(capacity);
    if (!chunk)
      return NULL;
    chunk->next = ctx->str_chunks;
    ctx->str_chunks = chunk;
  }
  char *result = chunk->data + chunk->used;
  chunk->used += size;
  return result;
}

static bool context_storage_init(st_policy_ctx_t *ctx, size_t chunk_size) {
  memset(&ctx->str_pool, 0, sizeof(ctx->str_pool));
  ctx->chunk_size = chunk_size ? chunk_size : 1;
  ctx->str_chunks = str_chunk_new(ctx->chunk_size);
  if (!ctx->str_chunks)
    return false;
  if (!str_pool_init(&ctx->str_pool)) {
    str_chunks_free(ctx->str_chunks);
    ctx->str_chunks = NULL;
    return false;
  }
  return true;
}

static void context_storage_free(st_policy_ctx_t *ctx) {
  str_pool_free(&ctx->str_pool);
  str_chunks_free(ctx->str_chunks);
  ctx->str_chunks = NULL;
}

st_policy_ctx_t *st_policy_ctx_new(void) {
  return st_policy_ctx_new_with_arena(DEFAULT_ARENA_SIZE);
}

st_policy_ctx_t *st_policy_ctx_new_with_arena(size_t arena_size) {
  st_policy_ctx_t *ctx = malloc(sizeof(st_policy_ctx_t));
  if (!ctx)
    return NULL;

  if (pthread_mutex_init(&ctx->lock, NULL) != 0) {
    free(ctx);
    return NULL;
  }
  if (!context_storage_init(ctx, arena_size)) {
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
    return NULL;
  }

  atomic_init(&ctx->refcount, 1);
  return ctx;
}

void st_policy_ctx_free(st_policy_ctx_t *ctx) {
  if (!ctx)
    return;
  context_storage_free(ctx);
  pthread_mutex_destroy(&ctx->lock);
  free(ctx);
}

void st_policy_ctx_retain(st_policy_ctx_t *ctx) {
  if (!ctx)
    return;
  /* Serialize new users with reset's reference-count check and storage swap. */
  pthread_mutex_lock(&ctx->lock);
  atomic_fetch_add(&ctx->refcount, 1);
  pthread_mutex_unlock(&ctx->lock);
}

void st_policy_ctx_release(st_policy_ctx_t *ctx) {
  if (!ctx)
    return;
  if (atomic_fetch_sub(&ctx->refcount, 1) == 1) {
    st_policy_ctx_free(ctx);
  }
}

/*
 * Reset the context for reuse, clearing all interned strings and freeing the
 * arena. Use this before loading a new policy into a cleared context.
 *
 * Returns ST_ERR_INVALID if there are active references (policies using this
 * context). Use st_policy_ctx_release() to drop all references before
 * resetting.
 */
static st_error_t context_reset_with_refcount(st_policy_ctx_t *ctx,
                                              unsigned expected_refcount) {
  st_policy_ctx_t replacement;
  if (!context_storage_init(&replacement, DEFAULT_ARENA_SIZE))
    return ST_ERR_MEMORY;

  pthread_mutex_lock(&ctx->lock);
  if (atomic_load(&ctx->refcount) != expected_refcount) {
    pthread_mutex_unlock(&ctx->lock);
    context_storage_free(&replacement);
    return ST_ERR_INVALID;
  }
  context_storage_free(ctx);
  ctx->str_pool = replacement.str_pool;
  ctx->str_chunks = replacement.str_chunks;
  ctx->chunk_size = replacement.chunk_size;
  pthread_mutex_unlock(&ctx->lock);
  return ST_OK;
}

st_error_t st_policy_ctx_reset(st_policy_ctx_t *ctx) {
  if (!ctx)
    return ST_ERR_INVALID;
  return context_reset_with_refcount(ctx, 1);
}

st_error_t st_policy_ctx_swap_storage(st_policy_ctx_t *destination,
                                      st_policy_ctx_t *replacement) {
  if (!destination || !replacement || destination == replacement)
    return ST_ERR_INVALID;
  pthread_mutex_lock(&destination->lock);
  pthread_mutex_lock(&replacement->lock);
  if (atomic_load(&destination->refcount) != 2 ||
      atomic_load(&replacement->refcount) != 2) {
    pthread_mutex_unlock(&replacement->lock);
    pthread_mutex_unlock(&destination->lock);
    return ST_ERR_INVALID;
  }
  str_pool_t pool = destination->str_pool;
  destination->str_pool = replacement->str_pool;
  replacement->str_pool = pool;
  str_chunk_t *chunks = destination->str_chunks;
  destination->str_chunks = replacement->str_chunks;
  replacement->str_chunks = chunks;
  size_t chunk_size = destination->chunk_size;
  destination->chunk_size = replacement->chunk_size;
  replacement->chunk_size = chunk_size;
  pthread_mutex_unlock(&replacement->lock);
  pthread_mutex_unlock(&destination->lock);
  return ST_OK;
}

bool st_policy_ctx_is_exclusive(const st_policy_ctx_t *ctx) {
  if (!ctx)
    return false;
  /* Context is exclusive if exactly one policy is using it (refcount == 2).
   * refcount = 1: no policies (just ctx)
   * refcount = 2: one policy (safe to compact)
   * refcount > 2: multiple policies (not exclusive)
   * Compact requires exclusive context so it can safely rebuild the trie. */
  return atomic_load(&ctx->refcount) == 2;
}

static uint64_t str_pool_hash(const char *str, size_t len) {
  uint64_t h = 14695981039346656037ull;
  for (size_t i = 0; i < len; i++) {
    h ^= (uint64_t)(uint8_t)str[i];
    h *= 1099511628211ull;
  }
  return h;
}

const char *st_policy_ctx_intern(st_policy_ctx_t *ctx, const char *str) {
  if (!ctx || !str)
    return NULL;
  size_t len = strlen(str);
  if (len == 0)
    return "";

  pthread_mutex_lock(&ctx->lock);
  uint64_t h = str_pool_hash(str, len);
  size_t pos = h % ctx->str_pool.capacity;

  while (ctx->str_pool.hashes[pos] != HASH_EMPTY) {
    if (ctx->str_pool.hashes[pos] == h) {
      const char *existing = ctx->str_pool.slots[pos];
      if (strcmp(existing, str) == 0) {
        pthread_mutex_unlock(&ctx->lock);
        return existing;
      }
    }
    pos = (pos + 1) % ctx->str_pool.capacity;
  }

  if (ctx->str_pool.count >= ctx->str_pool.capacity * 3 / 4) {
    if (!str_pool_grow(&ctx->str_pool)) {
      pthread_mutex_unlock(&ctx->lock);
      return NULL;
    }
    pos = h % ctx->str_pool.capacity;
    while (ctx->str_pool.hashes[pos] != HASH_EMPTY) {
      pos = (pos + 1) % ctx->str_pool.capacity;
    }
  }

  char *copy = str_chunks_alloc(ctx, len + 1);
  if (!copy) {
    pthread_mutex_unlock(&ctx->lock);
    return NULL;
  }
  memcpy(copy, str, len);
  copy[len] = '\0';

  ctx->str_pool.slots[pos] = copy;
  ctx->str_pool.hashes[pos] = h;
  ctx->str_pool.count++;
  pthread_mutex_unlock(&ctx->lock);
  return copy;
}

st_error_t st_policy_ctx_compact(st_policy_ctx_t *ctx) {
  return st_policy_ctx_reset(ctx);
}
