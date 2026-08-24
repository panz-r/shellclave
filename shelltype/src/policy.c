#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

/*
 * policy.c - Compact Policy Trie (CPT) with arena allocation.
 *
 * Design:
 * - Fixed-size state headers (16 bytes) in a growable array
 * - All children in a flat arena; each node owns a contiguous region
 * - Children sorted: literals first (binary search), then wildcards (type
 * order)
 * - Wildcard bitmask per node for O(1) compatibility pre-filter
 * - String-interned token text via shared context
 * - Pattern registry: original strings stored once, referenced by ID
 */

#include "arena.h"
#include "draugr/vacuum_filter.h"
#include "filter_hash.h"
#include "netpattern.h"
#include "policy_ctx.h"
#include "shell_netstring.h"
#include "shelltype.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "alloc.h"
#include "crc32.h"
#include "io.h"
#include "metadata.h"
#include "read_line.h"

/* --- COMPATIBILITY MASK --- */

#define CHILDREN_ARENA_INIT 4096
#define STATES_INIT 4096
#define PATTERN_REG_INIT 256
#define MAX_CMD_TOKENS 128
#define FILTER_POS_LEVELS                                                      \
  8 /* Shell commands rarely exceed 8 tokens before diverging */
#define FILTER_POS_CAPACITY 1024

/* --- CHILD ENTRY — 16 bytes, packed --- */

typedef struct {
  const char *text;
  uint32_t target;
  uint8_t type;
  uint8_t compound;
  uint8_t _pad[2];
} child_entry_t;

/* --- POLICY STATE — 16 bytes, fixed size --- */

const char *st_error_string(st_error_t err) {
  switch (err) {
  case ST_OK:
    return "ok";
  case ST_ERR_INVALID:
    return "invalid";
  case ST_ERR_MEMORY:
    return "memory";
  case ST_ERR_IO:
    return "io";
  case ST_ERR_FAILED:
    return "failed";
  case ST_ERR_FORMAT:
    return "format";
  case ST_ERR_LIMIT:
    return "limit";
  default:
    return "unknown";
  }
}

typedef struct {
  uint32_t children_offset; /* Offset into policy->children_arena.base */
  uint16_t literal_count;
  uint16_t wildcard_count;
  uint16_t pattern_id;
  uint64_t
      wildcard_mask; /* uint64_t to support ST_TYPE_ANY=32 without overflow */
  uint16_t children_alloc; /* Slots allocated from arena */
} policy_state_t;

/* --- CHILDREN — offset-based access into policy children_arena --- */

#define CHILDREN_ARENA_SIZE (64 * 1024) /* 64KB default */

/* Grow a node's child array within the arena.
 * Allocates a new (larger) block, copies existing entries, updates the offset.
 * The old block remains in the arena as unreachable space; it is reclaimed
 * by st_policy_compact(), which rebuilds the entire trie. This is an acceptable
 * trade-off: child arrays grow rarely (doubling), and compaction is the
 * designated reclamation point. */
static bool children_arena_grow(arena_t *arena, uint32_t *offset,
                                uint16_t *alloc, uint16_t new_slots) {
  size_t old_bytes = (*alloc) * sizeof(child_entry_t);
  size_t new_bytes = new_slots * sizeof(child_entry_t);
  uint32_t old_offset = *offset;
  char *new_base = arena_alloc(arena, new_bytes);
  if (!new_base)
    return false;
  if ((size_t)(new_base - arena->base) > UINT32_MAX)
    return false;
  /* arena_alloc may move the arena, so resolve the old offset afterward. */
  char *old_base = arena->base + old_offset;
  memcpy(new_base, old_base, old_bytes);
  memset(new_base + old_bytes, 0, new_bytes - old_bytes);
  *offset = (uint32_t)(new_base - arena->base);
  *alloc = new_slots;
  return true;
}

/* --- STATES ARRAY --- */

typedef struct {
  policy_state_t *states;
  size_t count;
  size_t capacity;
} states_array_t;

static bool states_array_init(states_array_t *a) {
  a->capacity = STATES_INIT;
  a->states = calloc(a->capacity, sizeof(policy_state_t));
  if (!a->states)
    return false;
  a->count = 1;
  a->states[0].children_offset = 0;
  a->states[0].children_alloc = 0;
  a->states[0].pattern_id = UINT16_MAX;
  return true;
}

static void states_array_free(states_array_t *a) {
  free(a->states);
  a->states = NULL;
}

static uint32_t states_array_alloc(states_array_t *a) {
  if (a->count >= a->capacity) {
    size_t new_cap = a->capacity * 2;
    policy_state_t *new_states =
        realloc(a->states, new_cap * sizeof(policy_state_t));
    if (!new_states)
      return UINT32_MAX;
    a->states = new_states;
    a->capacity = new_cap;
  }
  assert(a->count < a->capacity);
  uint32_t idx = (uint32_t)a->count;
  a->states[idx].children_offset = 0;
  a->states[idx].children_alloc = 0;
  a->states[idx].pattern_id = UINT16_MAX;
  a->states[idx].literal_count = 0;
  a->states[idx].wildcard_count = 0;
  a->states[idx].wildcard_mask = 0;
  a->count++;
  return idx;
}

static bool states_array_reserve(states_array_t *a, size_t additional) {
  if (additional > SIZE_MAX - a->count)
    return false;
  size_t required = a->count + additional;
  if (required <= a->capacity)
    return true;
  size_t new_cap = a->capacity;
  while (new_cap < required) {
    if (new_cap > SIZE_MAX / 2)
      return false;
    new_cap *= 2;
  }
  policy_state_t *states = realloc(a->states, new_cap * sizeof(*states));
  if (!states)
    return false;
  a->states = states;
  a->capacity = new_cap;
  return true;
}

/* --- PATTERN REGISTRY (entry-based with token storage) --- */

/* Forward declaration — defined after parse_pattern */
static void free_pattern_tokens(st_token_t *tokens, size_t count);

typedef struct {
  const char *pattern; /* interned string */
  st_token_t *tokens;  /* malloc'd parsed tokens (NULL if inactive) */
  size_t token_count;
  bool active;
} pattern_entry_t;

typedef struct {
  pattern_entry_t *entries;
  size_t count;
  size_t capacity;
} pattern_reg_t;

static bool pattern_reg_init(pattern_reg_t *r) {
  r->capacity = PATTERN_REG_INIT;
  r->entries = calloc(r->capacity, sizeof(pattern_entry_t));
  if (!r->entries)
    return false;
  r->count = 0;
  return true;
}

static void pattern_reg_free(pattern_reg_t *r) {
  if (!r->entries)
    return;
  for (size_t i = 0; i < r->count; i++) {
    if (r->entries[i].tokens) {
      free_pattern_tokens(r->entries[i].tokens, r->entries[i].token_count);
      r->entries[i].tokens = NULL;
    }
  }
  free(r->entries);
  r->entries = NULL;
}

static bool pattern_reg_grow(pattern_reg_t *r) {
  size_t new_cap = r->capacity * 2;
  pattern_entry_t *new_entries =
      realloc(r->entries, new_cap * sizeof(pattern_entry_t));
  if (!new_entries)
    return false;
  memset(new_entries + r->capacity, 0,
         (new_cap - r->capacity) * sizeof(pattern_entry_t));
  r->entries = new_entries;
  r->capacity = new_cap;
  return true;
}

static bool pattern_reg_reserve(pattern_reg_t *r) {
  for (size_t i = 0; i < r->count; i++) {
    if (!r->entries[i].active)
      return true;
  }
  if (r->count >= ST_MAX_POLICY_PATTERNS)
    return false;
  return r->count < r->capacity || pattern_reg_grow(r);
}

static bool pattern_entry_prepare(st_policy_ctx_t *ctx, const char *pattern,
                                  const st_token_t *tokens, size_t token_count,
                                  pattern_entry_t *prepared) {
  memset(prepared, 0, sizeof(*prepared));
  const char *interned = st_policy_ctx_intern(ctx, pattern);
  if (!interned)
    return false;

  st_token_t *tok_copy = calloc(token_count, sizeof(st_token_t));
  if (!tok_copy)
    return false;
  for (size_t i = 0; i < token_count; i++) {
    tok_copy[i].text = strdup(tokens[i].text);
    if (!tok_copy[i].text) {
      for (size_t k = 0; k < i; k++)
        free(tok_copy[k].text);
      free(tok_copy);
      return false;
    }
    tok_copy[i].type = tokens[i].type;
    tok_copy[i].compound = tokens[i].compound;
    tok_copy[i].capture_type = tokens[i].capture_type;
    if (tokens[i].compound) {
      tok_copy[i].prefix = strdup(tokens[i].prefix);
      tok_copy[i].capture = strdup(tokens[i].capture);
      tok_copy[i].suffix = strdup(tokens[i].suffix);
      if (!tok_copy[i].prefix || !tok_copy[i].capture || !tok_copy[i].suffix) {
        free_pattern_tokens(tok_copy, token_count);
        return false;
      }
    }
  }

  prepared->pattern = interned;
  prepared->tokens = tok_copy;
  prepared->token_count = token_count;
  prepared->active = true;
  return true;
}

static uint16_t pattern_reg_commit(pattern_reg_t *r,
                                   pattern_entry_t *prepared) {
  size_t slot = r->count;
  for (size_t i = 0; i < r->count; i++) {
    if (!r->entries[i].active) {
      slot = i;
      break;
    }
  }
  if (slot == r->count &&
      (r->count >= ST_MAX_POLICY_PATTERNS || r->count >= r->capacity))
    return UINT16_MAX;

  uint16_t id = (uint16_t)slot;
  r->entries[id] = *prepared;
  memset(prepared, 0, sizeof(*prepared));
  if (slot == r->count)
    r->count++;
  return id;
}

static void pattern_reg_deactivate(pattern_reg_t *r, uint16_t id) {
  if (id >= r->count)
    return;
  if (r->entries[id].tokens) {
    free_pattern_tokens(r->entries[id].tokens, r->entries[id].token_count);
    r->entries[id].tokens = NULL;
  }
  r->entries[id].active = false;
  r->entries[id].pattern = NULL;
}

/* --- LENGTH BUCKET INDEX --- */

typedef struct {
  uint16_t *indices;
  size_t count;
  size_t capacity;
} len_bucket_t;

static void len_bucket_free(len_bucket_t *b) {
  free(b->indices);
  b->indices = NULL;
  b->count = 0;
  b->capacity = 0;
}

static bool len_bucket_add(len_bucket_t *b, uint16_t pattern_id) {
  if (b->count >= b->capacity) {
    size_t new_cap = b->capacity == 0 ? 8 : b->capacity * 2;
    uint16_t *new_indices = realloc(b->indices, new_cap * sizeof(uint16_t));
    if (!new_indices)
      return false;
    b->indices = new_indices;
    b->capacity = new_cap;
  }
  b->indices[b->count++] = pattern_id;
  return true;
}

static bool len_bucket_reserve(len_bucket_t *b, size_t additional) {
  if (additional > SIZE_MAX - b->count)
    return false;
  size_t required = b->count + additional;
  if (required <= b->capacity)
    return true;
  size_t new_cap = b->capacity == 0 ? 8 : b->capacity;
  while (new_cap < required) {
    if (new_cap > SIZE_MAX / 2)
      return false;
    new_cap *= 2;
  }
  uint16_t *indices = realloc(b->indices, new_cap * sizeof(*indices));
  if (!indices)
    return false;
  b->indices = indices;
  b->capacity = new_cap;
  return true;
}

static void len_bucket_remove(len_bucket_t *b, uint16_t pattern_id) {
  for (size_t i = 0; i < b->count; i++) {
    if (b->indices[i] == pattern_id) {
      b->indices[i] = b->indices[b->count - 1];
      b->count--;
      return;
    }
  }
}

/* --- POLICY STRUCTURE --- */

/* Internal atomic stats structure (separate from public st_policy_stats_t) */
typedef struct {
  _Atomic uint64_t eval_count;
  _Atomic uint64_t filter_reject_count;
  _Atomic uint64_t trie_walk_count;
  _Atomic uint64_t suggestion_count;
  _Atomic uint64_t filter_rebuild_count;
  _Atomic uint64_t filter_rebuild_us;
} policy_atomic_stats_t;

struct st_policy {
  st_policy_ctx_t *ctx;
  states_array_t states;
  pattern_reg_t patterns;
  _Atomic(uint64_t) epoch;
  pthread_rwlock_t rwlock;
  arena_t children_arena; /* Dedicated arena for all children arrays */
  vacuum_filter_t *pos_filters[FILTER_POS_LEVELS];
  uint64_t
      pos_wildcard_mask[FILTER_POS_LEVELS]; /* uint64_t for ST_TYPE_ANY=32 */
  bool pos_has_compound[FILTER_POS_LEVELS];
  uint64_t pos_built_epoch[FILTER_POS_LEVELS];
  len_bucket_t *len_buckets; /* Length-indexed pattern buckets */
  size_t num_buckets;        /* ST_MAX_CMD_TOKENS + 1 */
  size_t pattern_count;
  size_t children_count;
  policy_atomic_stats_t stats; /* Atomic runtime statistics */
};

/* --- RUNTIME MATCH MASK ---
 *
 * Runtime policy matching is intentionally stricter than the lattice relation.
 * LITERAL is the lattice bottom for joins and subsumption, but an unclassified
 * command token must not satisfy typed policies such as #n or #opt. Union
 * command types also accept their concrete policy forms. Each row therefore
 * lists policy wildcard types accepted by a classified command token.
 */

static const uint64_t st_runtime_match_mask[ST_TYPE_COUNT] = {
    /* LITERAL */ (1ULL << ST_TYPE_LITERAL) | (1ULL << ST_TYPE_ANY),
    /* HEXHASH */ (1ULL << ST_TYPE_HEXHASH) | (1ULL << ST_TYPE_NUMBER) |
        (1ULL << ST_TYPE_VALUE) | (1ULL << ST_TYPE_ANY),
    /* NUMBER */ (1ULL << ST_TYPE_NUMBER) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* IPV4 */ (1ULL << ST_TYPE_IPV4) | (1ULL << ST_TYPE_IPADDR) |
        (1ULL << ST_TYPE_VALUE) | (1ULL << ST_TYPE_ANY),
    /* IPV6 */ (1ULL << ST_TYPE_IPV6) | (1ULL << ST_TYPE_IPADDR) |
        (1ULL << ST_TYPE_VALUE) | (1ULL << ST_TYPE_ANY),
    /* IPADDR */ (1ULL << ST_TYPE_IPADDR) | (1ULL << ST_TYPE_IPV4) |
        (1ULL << ST_TYPE_IPV6) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* WORD */ (1ULL << ST_TYPE_WORD) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* QUOTED */ (1ULL << ST_TYPE_QUOTED) | (1ULL << ST_TYPE_QUOTED_SPACE) |
        (1ULL << ST_TYPE_VALUE) | (1ULL << ST_TYPE_ANY),
    /* QUOTED_SPACE */ (1ULL << ST_TYPE_QUOTED_SPACE) |
        (1ULL << ST_TYPE_VALUE) | (1ULL << ST_TYPE_ANY),
    /* FILENAME */ (1ULL << ST_TYPE_FILENAME) | (1ULL << ST_TYPE_REL_PATH) |
        (1ULL << ST_TYPE_PATH) | (1ULL << ST_TYPE_ANY),
    /* REL_PATH */ (1ULL << ST_TYPE_REL_PATH) | (1ULL << ST_TYPE_PATH) |
        (1ULL << ST_TYPE_ANY),
    /* ABS_PATH */ (1ULL << ST_TYPE_ABS_PATH) | (1ULL << ST_TYPE_PATH) |
        (1ULL << ST_TYPE_ANY),
    /* PATH */ (1ULL << ST_TYPE_PATH) | (1ULL << ST_TYPE_ANY),
    /* URL */ (1ULL << ST_TYPE_URL) | (1ULL << ST_TYPE_ANY),
    /* VALUE */ (1ULL << ST_TYPE_VALUE) | (1ULL << ST_TYPE_ANY),
    /* SHORTOPT */ (1ULL << ST_TYPE_SHORTOPT) | (1ULL << ST_TYPE_OPT) |
        (1ULL << ST_TYPE_VALUE) | (1ULL << ST_TYPE_ANY),
    /* LONGOPT */ (1ULL << ST_TYPE_LONGOPT) | (1ULL << ST_TYPE_OPT) |
        (1ULL << ST_TYPE_VALUE) | (1ULL << ST_TYPE_ANY),
    /* OPT */ (1ULL << ST_TYPE_OPT) | (1ULL << ST_TYPE_SHORTOPT) |
        (1ULL << ST_TYPE_LONGOPT) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* UUID */ (1ULL << ST_TYPE_UUID) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* EMAIL */ (1ULL << ST_TYPE_EMAIL) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* HOSTNAME */ (1ULL << ST_TYPE_HOSTNAME) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* PORT */ (1ULL << ST_TYPE_PORT) | (1ULL << ST_TYPE_NUMBER) |
        (1ULL << ST_TYPE_VALUE) | (1ULL << ST_TYPE_ANY),
    /* SIZE */ (1ULL << ST_TYPE_SIZE) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* SEMVER */ (1ULL << ST_TYPE_SEMVER) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* TIMESTAMP */ (1ULL << ST_TYPE_TIMESTAMP) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* HASH_ALGO */ (1ULL << ST_TYPE_HASH_ALGO) | (1ULL << ST_TYPE_WORD) |
        (1ULL << ST_TYPE_VALUE) | (1ULL << ST_TYPE_ANY),
    /* ENV_VAR */ (1ULL << ST_TYPE_ENV_VAR) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* HYPHENATED */ (1ULL << ST_TYPE_HYPHENATED) | (1ULL << ST_TYPE_WORD) |
        (1ULL << ST_TYPE_VALUE) | (1ULL << ST_TYPE_ANY),
    /* BRANCH */ (1ULL << ST_TYPE_BRANCH) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* SHA */ (1ULL << ST_TYPE_SHA) | (1ULL << ST_TYPE_HEXHASH) |
        (1ULL << ST_TYPE_VALUE) | (1ULL << ST_TYPE_ANY),
    /* IMAGE */ (1ULL << ST_TYPE_IMAGE) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* PKG */ (1ULL << ST_TYPE_PKG) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* USER */ (1ULL << ST_TYPE_USER) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* FINGERPRINT */ (1ULL << ST_TYPE_FINGERPRINT) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* MAC */ (1ULL << ST_TYPE_MAC) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* METHOD */ (1ULL << ST_TYPE_METHOD) | (1ULL << ST_TYPE_WORD) |
        (1ULL << ST_TYPE_VALUE) | (1ULL << ST_TYPE_ANY),
    /* CRON */ (1ULL << ST_TYPE_CRON) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* DURATION */ (1ULL << ST_TYPE_DURATION) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* REGEX */ (1ULL << ST_TYPE_REGEX) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* GLOB */ (1ULL << ST_TYPE_GLOB) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* RANGE */ (1ULL << ST_TYPE_RANGE) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* SIGNAL */ (1ULL << ST_TYPE_SIGNAL) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* USER_GROUP */ (1ULL << ST_TYPE_USER_GROUP) | (1ULL << ST_TYPE_VALUE) |
        (1ULL << ST_TYPE_ANY),
    /* PERM_OCTAL */ (1ULL << ST_TYPE_PERM_OCTAL) | (1ULL << ST_TYPE_NUMBER) |
        (1ULL << ST_TYPE_VALUE) | (1ULL << ST_TYPE_ANY),
    /* ANY */ (1ULL << ST_TYPE_ANY),
};

static inline uint64_t runtime_match_mask(st_token_type_t t) {
  return st_runtime_match_mask[t];
}

/* --- CHILD ACCESS --- */

/* --- CHILD LOOKUP --- */

static child_entry_t *find_literal_child(const policy_state_t *node,
                                         const char *arena_base,
                                         const char *text, bool compound) {
  uint16_t n = node->literal_count;
  if (n == 0 || !arena_base)
    return NULL;
  assert(n <= node->children_alloc);
  child_entry_t *children =
      (child_entry_t *)(arena_base + node->children_offset);
  for (uint16_t i = 0; i < n; i++) {
    if (children[i].compound == compound && strcmp(text, children[i].text) == 0)
      return &children[i];
  }
  return NULL;
}

/* --- CLOSED WILDCARD METADATA MATCHING --- */

/* Check if a base type supports parametrization. */
static bool type_supports_param(st_token_type_t t) {
  return st_type_supports_metadata(t);
}

/* Extract the parameter from a parametrized wildcard symbol.
 * E.g., "#path.cfg" → ".cfg", "#size.MiB" → ".MiB", "#path" → NULL. */
static const char *wildcard_param(const char *wild_text,
                                  st_token_type_t wild_type) {
  const st_metadata_entry_t *metadata =
      st_wildcard_metadata(wild_text, wild_type);
  return metadata ? wild_text + strlen(st_type_symbol[wild_type]) : NULL;
}

/* Extract the file extension from a path (including dot).
 * "/etc/app.cfg" → ".cfg", "app" → NULL. */
const char *st_path_extension(const char *text) {
  if (!text)
    return NULL;
  const char *dot = strrchr(text, '.');
  const char *slash = strrchr(text, '/');
  const char *basename = slash ? slash + 1 : text;
  if (!dot || dot == basename)
    return NULL;
  if (dot[1] == '\0')
    return NULL;
  if (strchr(dot, '/') != NULL)
    return NULL;
  return dot;
}

/* Extract the size suffix from a size token.
 * "10MiB" → "MiB", "2G" → "G", "42" → NULL.
 * Returns pointer into the token after the last digit/dot. */
const char *st_size_suffix(const char *text) {
  if (!text)
    return NULL;
  const char *p = text;
  /* skip optional negative sign */
  if (*p == '-')
    p++;
  /* skip digits and dots */
  while (*p && (isdigit((unsigned char)*p) || *p == '.'))
    p++;
  if (*p == '\0')
    return NULL; /* no suffix */
  return p;
}

/* --- PARAMETRIZED MATCHING --- */

static bool closed_metadata_matches(const char *cmd_text,
                                    st_token_type_t cmd_type,
                                    const char *wild_text,
                                    st_token_type_t wild_type) {
  const st_metadata_entry_t *metadata =
      st_wildcard_metadata(wild_text, wild_type);
  if (!metadata)
    return true;

  if (wild_type == ST_TYPE_SIZE) {
    const char *suffix =
        cmd_type == ST_TYPE_SIZE ? st_size_suffix(cmd_text) : NULL;
    const st_metadata_entry_t *observed =
        st_metadata_lookup(ST_TYPE_SIZE, suffix);
    return observed && observed->id == metadata->id;
  }
  if (wild_type == ST_TYPE_UUID) {
    if (cmd_type != ST_TYPE_UUID || !cmd_text || strlen(cmd_text) != 36)
      return false;
    return (metadata->id == ST_META_UUID_V4 && cmd_text[14] == '4') ||
           (metadata->id == ST_META_UUID_V5 && cmd_text[14] == '5');
  }
  if (wild_type == ST_TYPE_SEMVER)
    return cmd_type == ST_TYPE_SEMVER;
  if (wild_type == ST_TYPE_TIMESTAMP) {
    if (cmd_type != ST_TYPE_TIMESTAMP || !cmd_text)
      return false;
    size_t len = strlen(cmd_text);
    if (metadata->id == ST_META_TIMESTAMP_DATE)
      return len == 10 && cmd_text[4] == '-' && cmd_text[7] == '-';
    if (metadata->id == ST_META_TIMESTAMP_TIME)
      return len == 8 && cmd_text[2] == ':' && cmd_text[5] == ':';
    return metadata->id == ST_META_TIMESTAMP_DATETIME && len >= 19 &&
           (cmd_text[10] == 'T' || cmd_text[10] == ' ');
  }
  if (wild_type == ST_TYPE_SHA) {
    if ((cmd_type != ST_TYPE_SHA && cmd_type != ST_TYPE_HEXHASH) || !cmd_text)
      return false;
    size_t len = strlen(cmd_text);
    for (size_t i = 0; i < len; i++)
      if (!isxdigit((unsigned char)cmd_text[i]))
        return false;
    return (metadata->id == ST_META_SHA_SHORT && len == 7) ||
           (metadata->id == ST_META_SHA_40 && len == 40) ||
           (metadata->id == ST_META_SHA_64 && len == 64);
  }
  if (wild_type == ST_TYPE_FINGERPRINT) {
    if (cmd_type != ST_TYPE_FINGERPRINT || !cmd_text)
      return false;
    if (metadata->id == ST_META_FINGERPRINT_SHA256)
      return strncmp(cmd_text, "SHA256:", 7) == 0;
    return metadata->id == ST_META_FINGERPRINT_MD5 && strlen(cmd_text) == 47 &&
           cmd_text[2] == ':' && cmd_text[5] == ':';
  }
  if (wild_type == ST_TYPE_DURATION) {
    if (cmd_type != ST_TYPE_DURATION || !cmd_text)
      return false;
    const char *suffix = cmd_text;
    if (*suffix == '-')
      suffix++;
    while (*suffix && (isdigit((unsigned char)*suffix) || *suffix == '.'))
      suffix++;
    const st_metadata_entry_t *observed =
        st_metadata_lookup(ST_TYPE_DURATION, suffix);
    return observed && observed->id == metadata->id;
  }
  if (wild_type == ST_TYPE_RANGE)
    return cmd_type == ST_TYPE_RANGE;
  if (wild_type == ST_TYPE_PERM_OCTAL)
    return cmd_type == ST_TYPE_PERM_OCTAL;
  return false;
}

/* Check if a command token matches a (possibly parametrized) wildcard child.
 * Returns true for non-parametrized wildcards (text == NULL or no parameter).
 */
static bool param_matches(const char *cmd_text, st_token_type_t cmd_type,
                          const char *wild_text, st_token_type_t wild_type) {
  return closed_metadata_matches(cmd_text, cmd_type, wild_text, wild_type);
}

/* Find an exact wildcard child for pattern insertion or removal.
 * Non-parametrized wildcards: text=NULL stored, matches only a
 * non-parametrized search.
 * Parametrized wildcards: full symbol text stored (e.g., "#path.cfg").
 * Uses exact type + text comparison (strcmp), not param_matches.
 * This is the correct lookup for add/remove where we want to find
 * the existing child with the same parametrized parameter (e.g., #size.MiB). */
static child_entry_t *find_exact_wildcard_child(const policy_state_t *node,
                                                const char *arena_base,
                                                st_token_type_t type,
                                                const char *text) {
  if (node->wildcard_count == 0 || !arena_base)
    return NULL;
  child_entry_t *children =
      (child_entry_t *)(arena_base + node->children_offset);
  child_entry_t *base = children + node->literal_count;
  for (uint16_t i = 0; i < node->wildcard_count; i++) {
    if ((st_token_type_t)base[i].type != type)
      continue;
    const char *existing = base[i].text;
    /* Do not let a request for #type.parameter resolve to the generic #type
     * child. In particular, removing an absent subtype must not remove its
     * surviving generic rule. */
    if (existing == NULL && wildcard_param(text, type) == NULL)
      return &base[i];
    /* Parametrized wildcard: exact text match required */
    if (existing != NULL && text != NULL && strcmp(text, existing) == 0)
      return &base[i];
  }
  return NULL;
}

/* --- CHILD INSERTION --- */

/* Forward declaration for is_explicit_wildcard (used by insert_child) */
static bool is_explicit_wildcard(const char *text, st_token_type_t type);

/* Returns: -1 = allocation failure, 0 = success (filter updated), 1 = success
 * (filter needs rebuild) */
static int insert_child(policy_state_t *node, st_policy_t *policy,
                        const st_token_t *token, uint32_t target,
                        uint8_t depth) {
  const char *text = token->text;
  st_token_type_t type = token->type;
  assert(node->literal_count + node->wildcard_count <= node->children_alloc);
  /* Use is_explicit_wildcard to determine storage class.
   * Classified tokens like "-v" (SHORTOPT) are stored as literal children
   * (match by text). Only explicit wildcard symbols like "#opt" are
   * stored as wildcard children (match by type). */
  bool is_literal = token->compound || !is_explicit_wildcard(text, type);
  uint16_t total = node->literal_count + node->wildcard_count;
  uint16_t insert_pos;
  char *arena_base = policy->children_arena.base;
  child_entry_t *children =
      (child_entry_t *)(arena_base + node->children_offset);
  int filter_status = 0;

  if (is_literal) {
    insert_pos = 0;
    for (uint16_t i = 0; i < node->literal_count; i++) {
      if (strcmp(text, children[i].text) < 0)
        break;
      insert_pos = i + 1;
    }
    /* Check ALL existing literals for duplicate */
    for (uint16_t i = 0; i < node->literal_count; i++) {
      if (children[i].compound == token->compound &&
          strcmp(text, children[i].text) == 0)
        return -1;
    }
  } else {
    insert_pos = node->literal_count;
    for (uint16_t i = node->literal_count; i < total; i++) {
      if (type < children[i].type)
        break;
      insert_pos = i + 1;
    }
    /* Duplicate check: same base type AND same text (handles parametrized) */
    if (insert_pos < total && children[insert_pos].type == type) {
      bool is_param = text && strchr(text, '.');
      if (!is_param)
        return -1; /* non-parametrized: same type = dup */
      /* Parametrized: check if same parameter */
      if (children[insert_pos].text != NULL && text != NULL &&
          strcmp(children[insert_pos].text, text) == 0)
        return -1;
    }
  }
  assert(insert_pos <= total);

  const char *interned;
  if (is_literal) {
    interned = st_policy_ctx_intern(policy->ctx, text);
  } else {
    /* Store full symbol for parametrized wildcards (e.g., "#path.cfg") */
    interned = (text && strchr(text, '.'))
                   ? st_policy_ctx_intern(policy->ctx, text)
                   : NULL;
  }
  if ((is_literal || (text && strchr(text, '.'))) && !interned)
    return -1;
  child_entry_t new_child = {.text = interned,
                             .target = target,
                             .type = (uint8_t)type,
                             .compound = token->compound};

  if (total + 1 > node->children_alloc) {
    if (node->children_alloc > UINT16_MAX / 2)
      return -1;
    uint16_t new_alloc =
        node->children_alloc == 0 ? 4 : node->children_alloc * 2;
    uint16_t old_alloc = node->children_alloc;
    if (!children_arena_grow(&policy->children_arena, &node->children_offset,
                             &node->children_alloc, new_alloc)) {
      return -1;
    }
    policy->children_count += node->children_alloc - old_alloc;
  }

  children =
      (child_entry_t *)(policy->children_arena.base + node->children_offset);
  memmove(children + insert_pos + 1, children + insert_pos,
          (total - insert_pos) * sizeof(child_entry_t));
  children[insert_pos] = new_child;
  policy->children_count++;

  if (is_literal) {
    node->literal_count++;
  } else {
    node->wildcard_count++;
    node->wildcard_mask |= (1ULL << type);
  }

  if (depth < FILTER_POS_LEVELS) {
    if (token->compound) {
      policy->pos_has_compound[depth] = true;
      filter_status = 1;
    } else if (type == ST_TYPE_LITERAL) {
      if (policy->pos_filters[depth]) {
        uint64_t h = filter_hash_fnv1a(text, strlen(text));
        vacuum_err_t vrc = vacuum_filter_insert(policy->pos_filters[depth], h);
        if (vrc != VACUUM_OK) {
          vacuum_filter_destroy(policy->pos_filters[depth]);
          policy->pos_filters[depth] = NULL;
          filter_status = 1;
        }
      } else {
        /* Filter not yet built for this depth — needs rebuild */
        filter_status = 1;
      }
    } else {
      policy->pos_wildcard_mask[depth] |= (1ULL << type);
    }
  }

  return filter_status;
}

static void free_pattern_tokens(st_token_t *tokens, size_t count) {
  if (!tokens)
    return;
  for (size_t i = 0; i < count; i++) {
    free(tokens[i].text);
    free(tokens[i].prefix);
    free(tokens[i].capture);
    free(tokens[i].suffix);
  }
  free(tokens);
}

/**
 * Check if a token is an explicit wildcard — i.e., the user typed a type
 * symbol like "#path" or "#opt", as opposed to a literal value like "-v"
 * that was merely classified into a wildcard type.
 * Returns true if the token text matches a type symbol or is parametrized.
 */
static bool is_explicit_wildcard(const char *text, st_token_type_t type) {
  if (type == ST_TYPE_LITERAL)
    return false;
  if (type == ST_TYPE_ANY)
    return true; /* * is always a wildcard */
  if (!text)
    return false; /* defensive: NULL text is not a wildcard */
  const char *sym = st_type_symbol[type];
  size_t sym_len = strlen(sym);
  /* Exact match: "#opt" */
  if (strcmp(text, sym) == 0)
    return true;
  /* Parametrized: "#path.cfg" */
  if (strncmp(text, sym, sym_len) == 0 && text[sym_len] == '.')
    return true;
  return false;
}

/**
 * Check if pattern A subsumes pattern B.
 * Returns true if every command accepted by B is also accepted by A.
 * Requires same length and each token of A compatible with B.
 * For literals, values must match exactly.
 * A classified-literal token (e.g., "-v" typed as-is, classified as OPT)
 * is NOT considered a wildcard for subsumption — it must match exactly.
 * For parametrized wildcards:
 *   - #path subsumes #path.cfg (generic subsumes specific)
 *   - #path.cfg does NOT subsume #path (specific does not subsume generic)
 *   - #path.cfg does NOT subsume #path.log (different params are incomparable)
 */
static bool pattern_subsumes(const st_token_t *a, size_t a_len,
                             const st_token_t *b, size_t b_len) {
  if (a_len != b_len)
    return false;

  for (size_t i = 0; i < a_len; i++) {
    if (a[i].compound || b[i].compound) {
      if (a[i].compound && b[i].compound) {
        if (strcmp(a[i].prefix, b[i].prefix) != 0 ||
            strcmp(a[i].suffix, b[i].suffix) != 0 ||
            !st_is_compatible(b[i].capture_type, a[i].capture_type))
          return false;
        const char *a_param = wildcard_param(a[i].capture, a[i].capture_type);
        const char *b_param = wildcard_param(b[i].capture, b[i].capture_type);
        if ((a_param && !b_param) ||
            (a_param && b_param && strcmp(a_param, b_param) != 0))
          return false;
        continue;
      }
      if (!a[i].compound && is_explicit_wildcard(a[i].text, a[i].type) &&
          a[i].type == ST_TYPE_ANY)
        continue;
      return false;
    }
    bool a_wild = is_explicit_wildcard(a[i].text, a[i].type);
    bool b_wild = is_explicit_wildcard(b[i].text, b[i].type);

    if (!a_wild && !b_wild) {
      /* Both are concrete values: must match exactly */
      if (strcmp(a[i].text, b[i].text) != 0)
        return false;
    } else if (a_wild && b_wild) {
      /* Both are wildcards: B's type must be compatible with A's type.
       * For A to subsume B: A is more general, B's type must be subtype of A's
       * type. */
      if (!st_is_compatible(b[i].type, a[i].type))
        return false;
      /* Parametrized wildcard subsumption check */
      const char *a_param = wildcard_param(a[i].text, a[i].type);
      const char *b_param = wildcard_param(b[i].text, b[i].type);
      if (a_param && b_param) {
        if (strcmp(a_param, b_param) != 0)
          return false;
      } else if (a_param && !b_param) {
        /* a is parametrized, b is not: a is more specific, cannot subsume b */
        return false;
      } else if (!a_param && b_param) {
        /* a is not parametrized, b is: a is more general, OK */
      }
    } else if (!a_wild && b_wild) {
      /* a is concrete, b is wildcard: a cannot subsume b
       * (every command matching concrete A matches it exactly,
       * but B is a wildcard that accepts MORE commands,
       * so A does NOT subsume B) */
      return false;
    } else {
      /* a is wildcard, b is concrete: a can subsume b if a's type covers b's
       * type. For A (wildcard) to subsume B (concrete): A must be as general as
       * B's type. Check: st_is_compatible(B.type, A.type) — B's type must be
       * subtype of A's type. */
      st_token_type_t concrete_type = st_classify_token(b[i].text);
      if (!(runtime_match_mask(concrete_type) & (1ULL << a[i].type)) ||
          !param_matches(b[i].text, concrete_type, a[i].text, a[i].type))
        return false;
    }
  }
  return true;
}

/* --- PER-POSITION FILTER REBUILD ---
 *
 * BFS-walk the trie up to depth FILTER_POS_LEVELS (4).
 * At each depth N, collect all children across all nodes at that depth:
 *   - Literals → insert into pos_filters[N]
 *   - Wildcards → OR into pos_wildcard_mask[N]
 *
 * Called lazily when pos_built_epoch[N] != policy->epoch.
 */

static void policy_rebuild_filters(st_policy_t *policy) {
  struct timespec start, end;
  clock_gettime(CLOCK_MONOTONIC, &start);
  typedef struct {
    uint32_t idx;
    uint8_t depth;
  } bfs_q;
  vacuum_filter_t *new_filters[FILTER_POS_LEVELS] = {0};
  uint64_t new_wildcard_masks[FILTER_POS_LEVELS] = {0};
  bool new_has_compound[FILTER_POS_LEVELS] = {0};
  bfs_q *q = malloc(policy->states.count * sizeof(*q));
  size_t head = 0, tail = 0;
  bool complete = q != NULL;

  size_t cap = policy->states.count + policy->states.count / 4;
  if (cap < 64)
    cap = 64;
  for (int i = 0; complete && i < FILTER_POS_LEVELS; i++)
    new_filters[i] = vacuum_filter_create(cap, 0, 0, 0);

  if (complete)
    q[tail++] = (bfs_q){.idx = 0, .depth = 0};

  while (complete && head < tail) {
    bfs_q entry = q[head++];
    if (entry.depth >= FILTER_POS_LEVELS)
      continue;

    policy_state_t *node = &policy->states.states[entry.idx];
    uint16_t total = node->literal_count + node->wildcard_count;
    child_entry_t *children =
        (child_entry_t *)(policy->children_arena.base + node->children_offset);

    for (uint16_t i = 0; i < total; i++) {
      child_entry_t *c = &children[i];
      if (c->type == ST_TYPE_LITERAL && !c->text)
        continue;

      uint8_t d = entry.depth;

      if (c->compound) {
        new_has_compound[d] = true;
      } else if (c->type == ST_TYPE_LITERAL) {
        if (new_filters[d]) {
          uint64_t h = filter_hash_fnv1a(c->text, strlen(c->text));
          vacuum_err_t vrc = vacuum_filter_insert(new_filters[d], h);
          if (vrc != VACUUM_OK) {
            /* A disabled filter is conservative: it cannot reject a match. */
            vacuum_filter_destroy(new_filters[d]);
            new_filters[d] = NULL;
          }
        }
      } else {
        new_wildcard_masks[d] |= (1ULL << c->type);
      }

      if (tail >= policy->states.count) {
        complete = false;
        break;
      }
      q[tail++] = (bfs_q){.idx = c->target, .depth = d + 1};
    }
  }

  free(q);

  uint64_t epoch = atomic_load(&policy->epoch);
  for (int i = 0; i < FILTER_POS_LEVELS; i++) {
    vacuum_filter_destroy(policy->pos_filters[i]);
    policy->pos_filters[i] = complete ? new_filters[i] : NULL;
    policy->pos_wildcard_mask[i] = complete ? new_wildcard_masks[i] : 0;
    policy->pos_has_compound[i] = complete ? new_has_compound[i] : true;
    policy->pos_built_epoch[i] = epoch;
    if (!complete)
      vacuum_filter_destroy(new_filters[i]);
  }

  clock_gettime(CLOCK_MONOTONIC, &end);
  uint64_t elapsed_us = (end.tv_sec - start.tv_sec) * 1000000 +
                        (end.tv_nsec - start.tv_nsec) / 1000;

  atomic_fetch_add(&policy->stats.filter_rebuild_count, 1);
  atomic_fetch_add(&policy->stats.filter_rebuild_us, elapsed_us);
}

/* --- PATTERN VALIDATION (public API) --- */

st_error_t st_validate_netpattern(const char *pattern,
                                  st_pattern_info_t *info) {
  if (info)
    memset(info, 0, sizeof(*info));
  st_token_array_t decoded = {0};
  st_error_t decode_error = st_netpattern_decode(pattern, &decoded);
  if (decode_error != ST_OK)
    return decode_error;
  size_t token_count = decoded.count;
  st_token_t *tokens = decoded.tokens;
  if (token_count != 0 &&
      (tokens[0].type == ST_TYPE_ANY || tokens[0].compound)) {
    free_pattern_tokens(tokens, token_count);
    return ST_ERR_INVALID;
  }

  if (info) {
    info->token_count = token_count;
    for (size_t i = 0; i < token_count; i++) {
      strncpy(info->token_texts[i], tokens[i].text, ST_MAX_TOKEN_LEN - 1);
      info->token_texts[i][ST_MAX_TOKEN_LEN - 1] = '\0';
      info->token_types[i] = tokens[i].type;
    }
  }

  free_pattern_tokens(tokens, token_count);
  return ST_OK;
}

/* --- LIFECYCLE --- */

st_policy_t *st_policy_new(st_policy_ctx_t *ctx) {
  if (!ctx)
    return NULL;

  st_policy_t *policy = calloc(1, sizeof(st_policy_t));
  if (!policy)
    return NULL;

  if (!states_array_init(&policy->states)) {
    free(policy);
    return NULL;
  }
  if (!pattern_reg_init(&policy->patterns)) {
    states_array_free(&policy->states);
    free(policy);
    return NULL;
  }

  policy->ctx = ctx;
  atomic_store(&policy->epoch, 1);
  policy->pattern_count = 0;
  policy->children_count = 0;

  /* Length buckets for incremental subsumption */
  policy->num_buckets = ST_MAX_CMD_TOKENS + 1;
  policy->len_buckets = calloc(policy->num_buckets, sizeof(len_bucket_t));
  if (!policy->len_buckets) {
    pattern_reg_free(&policy->patterns);
    states_array_free(&policy->states);
    free(policy);
    return NULL;
  }

  /* Statistics - initialize atomics */
  atomic_init(&policy->stats.eval_count, 0);
  atomic_init(&policy->stats.filter_reject_count, 0);
  atomic_init(&policy->stats.trie_walk_count, 0);
  atomic_init(&policy->stats.suggestion_count, 0);
  atomic_init(&policy->stats.filter_rebuild_count, 0);
  atomic_init(&policy->stats.filter_rebuild_us, 0);

  if (!arena_init(&policy->children_arena, CHILDREN_ARENA_SIZE)) {
    free(policy->len_buckets);
    pattern_reg_free(&policy->patterns);
    states_array_free(&policy->states);
    free(policy);
    return NULL;
  }
  if (pthread_rwlock_init(&policy->rwlock, NULL) != 0) {
    arena_free(&policy->children_arena);
    free(policy->len_buckets);
    pattern_reg_free(&policy->patterns);
    states_array_free(&policy->states);
    free(policy);
    return NULL;
  }

  /* Retain context to prevent reset while policy is alive */
  st_policy_ctx_retain(ctx);

  return policy;
}

void st_policy_free(st_policy_t *policy) {
  if (!policy)
    return;
  pthread_rwlock_destroy(&policy->rwlock);
  for (int i = 0; i < FILTER_POS_LEVELS; i++) {
    vacuum_filter_destroy(policy->pos_filters[i]);
  }
  pattern_reg_free(&policy->patterns);
  states_array_free(&policy->states);
  arena_free(&policy->children_arena);
  if (policy->len_buckets) {
    for (size_t i = 0; i < policy->num_buckets; i++)
      len_bucket_free(&policy->len_buckets[i]);
    free(policy->len_buckets);
  }
  /* Release context reference */
  st_policy_ctx_release(policy->ctx);
  free(policy);
}

/* --- ADD / REMOVE --- */

/* Forward declaration */
static st_error_t remove_pattern_by_id_locked(st_policy_t *policy,
                                              uint16_t pid);

/* Internal: add pattern assuming write lock is already held.
 *
 * Performs incremental subsumption checks:
 *   1. If the new pattern is subsumed by an existing pattern, it is rejected.
 *   2. If the new pattern subsumes existing patterns, they are removed.
 * Only compares patterns of the same token length.
 */
static st_error_t st_policy_add_locked(st_policy_t *policy,
                                       const char *pattern) {
  if (!policy || !pattern || !pattern[0])
    return ST_ERR_INVALID;

  st_token_array_t decoded = {0};
  st_error_t decode_error = st_netpattern_decode(pattern, &decoded);
  if (decode_error != ST_OK)
    return decode_error;
  size_t token_count = decoded.count;
  st_token_t *tokens = decoded.tokens;
  if (token_count != 0 &&
      (tokens[0].type == ST_TYPE_ANY || tokens[0].compound)) {
    free_pattern_tokens(tokens, token_count);
    return ST_ERR_INVALID;
  }
  if (token_count == 0) {
    free_pattern_tokens(tokens, token_count);
    return ST_ERR_INVALID;
  }
  if (token_count > ST_MAX_CMD_TOKENS) {
    free_pattern_tokens(tokens, token_count);
    return ST_ERR_INVALID;
  }
  /* --- Incremental subsumption check --- */
  len_bucket_t *bucket = &policy->len_buckets[token_count];

  /* Step 1: Check if new pattern is subsumed by an existing pattern */
  for (size_t bi = 0; bi < bucket->count; bi++) {
    uint16_t eid = bucket->indices[bi];
    pattern_entry_t *entry = &policy->patterns.entries[eid];
    if (!entry->active || !entry->tokens)
      continue;
    /* A = existing entry, B = new pattern.
     * If existing (A) subsumes new (B), new is redundant.
     * Check: does existing subsume new? pattern_subsumes(existing, new) */
    if (pattern_subsumes(entry->tokens, entry->token_count, tokens,
                         token_count)) {
      free_pattern_tokens(tokens, token_count);
      return ST_OK;
    }
  }

  /* Step 2: Check if new pattern subsumes existing patterns.
   * Collect indices to remove first (avoid iterator invalidation). */
  uint16_t *to_remove = NULL;
  size_t to_remove_count = 0;
  size_t to_remove_cap = 0;

  for (size_t bi = 0; bi < bucket->count; bi++) {
    uint16_t eid = bucket->indices[bi];
    pattern_entry_t *entry = &policy->patterns.entries[eid];
    if (!entry->active || !entry->tokens)
      continue;
    /* A = new pattern, B = existing entry.
     * If new pattern (A) subsumes existing (B), existing is redundant.
     * Check: does new subsume existing? pattern_subsumes(new, existing) */
    if (pattern_subsumes(tokens, token_count, entry->tokens,
                         entry->token_count)) {
      if (to_remove_count >= to_remove_cap) {
        size_t new_cap = to_remove_cap == 0 ? 8 : to_remove_cap * 2;
        uint16_t *new_arr = realloc(to_remove, new_cap * sizeof(uint16_t));
        if (!new_arr) {
          free(to_remove);
          free_pattern_tokens(tokens, token_count);
          return ST_ERR_MEMORY;
        }
        to_remove = new_arr;
        to_remove_cap = new_cap;
      }
      to_remove[to_remove_count++] = eid;
    }
  }

  if (policy->pattern_count >= ST_MAX_POLICY_PATTERNS && to_remove_count == 0) {
    free(to_remove);
    free_pattern_tokens(tokens, token_count);
    return ST_ERR_LIMIT;
  }
  bool reuse_subsumed_slot =
      policy->patterns.count >= ST_MAX_POLICY_PATTERNS && to_remove_count != 0;

  /* Find the first absent trie edge. Every following token needs one state
   * and one child array. Reserve all fallible structural allocations before
   * removing subsumed rules or publishing a new edge. */
  uint32_t probe = 0;
  size_t first_missing = token_count;
  size_t arena_bytes = 0;
  for (size_t i = 0; i < token_count; i++) {
    policy_state_t *node = &policy->states.states[probe];
    bool is_wild = is_explicit_wildcard(tokens[i].text, tokens[i].type);
    child_entry_t *child =
        is_wild ? find_exact_wildcard_child(node, policy->children_arena.base,
                                            tokens[i].type, tokens[i].text)
                : find_literal_child(node, policy->children_arena.base,
                                     tokens[i].text, tokens[i].compound);
    if (!child) {
      first_missing = i;
      break;
    }
    probe = child->target;
  }
  size_t missing = token_count - first_missing;
  if (missing > 0) {
    policy_state_t *parent = &policy->states.states[probe];
    uint16_t total = parent->literal_count + parent->wildcard_count;
    if (total + 1 > parent->children_alloc) {
      if (parent->children_alloc > UINT16_MAX / 2) {
        free(to_remove);
        free_pattern_tokens(tokens, token_count);
        return ST_ERR_LIMIT;
      }
      uint16_t slots = parent->children_alloc == 0
                           ? 4
                           : (uint16_t)(parent->children_alloc * 2);
      arena_bytes += (size_t)slots * sizeof(child_entry_t) + 7;
    }
    if (missing > 1)
      arena_bytes += (missing - 1) * (4 * sizeof(child_entry_t) + 7);
  }
  if (!states_array_reserve(&policy->states, missing) ||
      !arena_reserve(&policy->children_arena, arena_bytes) ||
      (!reuse_subsumed_slot && !pattern_reg_reserve(&policy->patterns)) ||
      !len_bucket_reserve(bucket, 1)) {
    free(to_remove);
    free_pattern_tokens(tokens, token_count);
    return ST_ERR_MEMORY;
  }

  /* --- Trie insertion (existing logic) --- */
  uint32_t current = 0;
  bool needs_filter_rebuild = false;

  for (size_t i = 0; i < token_count; i++) {
    policy_state_t *node = &policy->states.states[current];
    child_entry_t *existing = NULL;
    char *arena_base = policy->children_arena.base;

    /* Use is_explicit_wildcard to determine storage class.
     * Tokens like "-v" (SHORTOPT) are classified types but NOT explicit
     * wildcards, so they should be stored as literal children (match by text).
     * Tokens like "#opt" (OPT) ARE explicit wildcards, stored as wildcard
     * children. */
    bool is_wild = is_explicit_wildcard(tokens[i].text, tokens[i].type);

    if (!is_wild) {
      existing = find_literal_child(node, arena_base, tokens[i].text,
                                    tokens[i].compound);
    } else {
      existing = find_exact_wildcard_child(node, arena_base, tokens[i].type,
                                           tokens[i].text);
    }

    if (existing) {
      current = existing->target;
    } else {
      uint32_t new_state = states_array_alloc(&policy->states);
      if (new_state == UINT32_MAX) {
        free(to_remove);
        free_pattern_tokens(tokens, token_count);
        return ST_ERR_MEMORY;
      }
      /* states_array_alloc() may realloc the state array. Re-resolve the
       * parent by index before using it again. */
      node = &policy->states.states[current];
      int rc = insert_child(node, policy, &tokens[i], new_state, (uint8_t)i);
      if (rc < 0) {
        free(to_remove);
        free_pattern_tokens(tokens, token_count);
        return ST_ERR_MEMORY;
      }
      if (rc == 1)
        needs_filter_rebuild = true;
      current = new_state;
    }
  }

  policy_state_t *end_node = &policy->states.states[current];
  if (end_node->pattern_id == UINT16_MAX) {
    char *stored_pattern = NULL;
    st_error_t encode_error =
        st_netpattern_encode(tokens, token_count, &stored_pattern);
    if (encode_error != ST_OK) {
      free(to_remove);
      free_pattern_tokens(tokens, token_count);
      return encode_error;
    }
    pattern_entry_t prepared;
    if (!pattern_entry_prepare(policy->ctx, stored_pattern, tokens, token_count,
                               &prepared)) {
      free(stored_pattern);
      free(to_remove);
      free_pattern_tokens(tokens, token_count);
      return ST_ERR_MEMORY;
    }
    free(stored_pattern);
    if (reuse_subsumed_slot) {
      for (size_t ri = 0; ri < to_remove_count; ri++)
        remove_pattern_by_id_locked(policy, to_remove[ri]);
      to_remove_count = 0;
    }
    uint16_t pid = pattern_reg_commit(&policy->patterns, &prepared);
    if (pid == UINT16_MAX) {
      free_pattern_tokens(prepared.tokens, prepared.token_count);
      free(to_remove);
      free_pattern_tokens(tokens, token_count);
      return ST_ERR_LIMIT;
    }
    end_node->pattern_id = pid;
    policy->pattern_count++;

    /* Add to length bucket */
    bool added = len_bucket_add(&policy->len_buckets[token_count], pid);
    assert(added);
  }

  /* Only now remove rules subsumed by the successfully published pattern.
   * Removal is allocation-free, so no later failure can expose a partial
   * semantic update. */
  for (size_t ri = 0; ri < to_remove_count; ri++)
    remove_pattern_by_id_locked(policy, to_remove[ri]);
  free(to_remove);

  if (needs_filter_rebuild)
    policy->epoch++;
  free_pattern_tokens(tokens, token_count);
  return ST_OK;
}

/* Remove a child entry from a trie node's children array.
 * Shifts subsequent entries to fill the gap. */
static void remove_child_from_node(policy_state_t *node, st_policy_t *policy,
                                   uint16_t child_idx, bool is_literal) {
  child_entry_t *children =
      (child_entry_t *)(policy->children_arena.base + node->children_offset);
  uint16_t total = node->literal_count + node->wildcard_count;

  /* Shift entries to fill the gap */
  memmove(children + child_idx, children + child_idx + 1,
          (total - child_idx - 1) * sizeof(child_entry_t));
  memset(children + total - 1, 0, sizeof(child_entry_t));

  if (is_literal) {
    node->literal_count--;
  } else {
    node->wildcard_count--;
    /* Recompute wildcard mask */
    node->wildcard_mask = 0;
    child_entry_t *wild_base = children + node->literal_count;
    for (uint16_t i = 0; i < node->wildcard_count; i++) {
      node->wildcard_mask |= (1ULL << wild_base[i].type);
    }
  }
}

/* Internal: remove a pattern by its registry ID, assuming write lock is held.
 * Walks the trie using the stored tokens, removes child entries along the path
 * (only if the target state has no other children and no other pattern_id),
 * unsets pattern_id, removes from length bucket, and deactivates the entry.
 *
 * For incremental subsumption, this removes the dead trie path to prevent
 * it from shadowing the new more-general pattern. */
static st_error_t remove_pattern_by_id_locked(st_policy_t *policy,
                                              uint16_t pid) {
  if (!policy || pid >= policy->patterns.count)
    return ST_ERR_INVALID;
  pattern_entry_t *entry = &policy->patterns.entries[pid];
  if (!entry->active)
    return ST_OK;

  /* Track the path through the trie so we can prune dead nodes */
  typedef struct {
    uint32_t state_idx;
    uint16_t child_idx;
    bool is_literal;
  } path_step_t;
  path_step_t path[ST_MAX_CMD_TOKENS];

  uint32_t current = 0;
  for (size_t i = 0; i < entry->token_count; i++) {
    policy_state_t *node = &policy->states.states[current];
    child_entry_t *child = NULL;
    char *arena_base = policy->children_arena.base;

    path[i].state_idx = current;
    path[i].is_literal =
        !is_explicit_wildcard(entry->tokens[i].text, entry->tokens[i].type);

    if (path[i].is_literal) {
      /* Find literal child index */
      uint16_t n = node->literal_count;
      child_entry_t *children =
          (child_entry_t *)(arena_base + node->children_offset);
      for (uint16_t ci = 0; ci < n; ci++) {
        if (children[ci].compound == entry->tokens[i].compound &&
            strcmp(entry->tokens[i].text, children[ci].text) == 0) {
          child = &children[ci];
          path[i].child_idx = ci;
          break;
        }
      }
    } else {
      /* Find exact wildcard child index */
      child = find_exact_wildcard_child(node, arena_base, entry->tokens[i].type,
                                        entry->tokens[i].text);
      if (child) {
        uint16_t ci =
            (uint16_t)(child -
                       (child_entry_t *)(arena_base + node->children_offset));
        path[i].child_idx = ci;
      }
    }

    if (!child) {
      return ST_OK;
    }
    current = child->target;
  }

  /* Unset the pattern_id on the end node */
  policy_state_t *end_node = &policy->states.states[current];
  if (end_node->pattern_id != pid) {
    return ST_OK;
  }
  end_node->pattern_id = UINT16_MAX;

  /* Prune dead nodes from leaf to root.
   * A node can be pruned if it has no children, no pattern_id, and is not the
   * root. */

  /* Simple pruning: remove child entries from the path, starting from the leaf.
   * Only remove if the target state has no children and no pattern_id. */
  for (size_t i = entry->token_count; i > 0; i--) {
    size_t step = i - 1;
    uint32_t state_idx = path[step].state_idx;
    policy_state_t *node = &policy->states.states[state_idx];

    /* Find the child that we followed at this step.
     * Note: child_idx may be stale if earlier steps removed children from this
     * node. Re-find by matching the entry tokens. */
    uint16_t child_idx = UINT16_MAX;
    child_entry_t *children =
        (child_entry_t *)(policy->children_arena.base + node->children_offset);
    uint16_t total = node->literal_count + node->wildcard_count;

    if (path[step].is_literal) {
      for (uint16_t ci = 0; ci < node->literal_count; ci++) {
        if (strcmp(entry->tokens[step].text, children[ci].text) == 0) {
          child_idx = ci;
          break;
        }
      }
    } else {
      for (uint16_t ci = node->literal_count; ci < total; ci++) {
        if ((st_token_type_t)children[ci].type == entry->tokens[step].type) {
          /* Check exact match for parametrized wildcards */
          if (entry->tokens[step].text && children[ci].text &&
              strcmp(entry->tokens[step].text, children[ci].text) == 0) {
            child_idx = ci;
            break;
          }
          if (!entry->tokens[step].text && !children[ci].text) {
            child_idx = ci;
            break;
          }
          /* For non-parametrized, text in entry->tokens is the symbol (e.g.,
           * "#path") */
          if (entry->tokens[step].text && !children[ci].text) {
            /* Entry has symbol text but trie stores NULL for non-parametrized.
             * Check if this is a non-parametrized wildcard by checking if entry
             * text is just the type symbol. */
            const char *sym = st_type_symbol[entry->tokens[step].type];
            if (strcmp(entry->tokens[step].text, sym) == 0) {
              child_idx = ci;
              break;
            }
          }
        }
      }
    }

    if (child_idx == UINT16_MAX)
      break; /* Already removed or can't find */

    uint32_t target = children[child_idx].target;
    policy_state_t *target_state = &policy->states.states[target];

    /* Only remove the child if the target state is a dead end */
    if (target_state->pattern_id == UINT16_MAX &&
        target_state->literal_count == 0 && target_state->wildcard_count == 0) {
      remove_child_from_node(node, policy, child_idx, path[step].is_literal);
    }
  }

  /* Remove from length bucket */
  if (entry->token_count < policy->num_buckets) {
    len_bucket_remove(&policy->len_buckets[entry->token_count], pid);
  }

  /* Deactivate and free tokens */
  pattern_reg_deactivate(&policy->patterns, pid);
  policy->pattern_count--;

  return ST_OK;
}

/* Public: add pattern (acquires write lock) */
st_error_t st_policy_add_netpattern(st_policy_t *policy, const char *pattern) {
  if (!policy || !pattern || !pattern[0])
    return ST_ERR_INVALID;
  pthread_rwlock_wrlock(&policy->rwlock);
  st_error_t err = st_policy_add_locked(policy, pattern);
  pthread_rwlock_unlock(&policy->rwlock);
  return err;
}

st_error_t st_policy_batch_add_netpatterns(st_policy_t *policy,
                                           const char **patterns,
                                           size_t count) {
  if (!policy || !patterns || count == 0)
    return ST_ERR_INVALID;

  pthread_rwlock_wrlock(&policy->rwlock);
  /* Build a complete replacement while the live policy remains untouched.
   * Besides making batches atomic, this prevents a failed insertion after
   * arena growth from leaving unreachable state in the live policy. */
  st_policy_t *staged = st_policy_new(policy->ctx);
  if (!staged) {
    pthread_rwlock_unlock(&policy->rwlock);
    return ST_ERR_MEMORY;
  }

  st_error_t first_err = ST_OK;
  for (size_t i = 0; i < policy->patterns.count; i++) {
    if (!policy->patterns.entries[i].active)
      continue;
    first_err =
        st_policy_add_locked(staged, policy->patterns.entries[i].pattern);
    if (first_err != ST_OK)
      break;
  }
  for (size_t i = 0; first_err == ST_OK && i < count; i++)
    first_err = st_policy_add_locked(staged, patterns[i]);

  if (first_err == ST_OK) {
    states_array_t old_states = policy->states;
    pattern_reg_t old_patterns = policy->patterns;
    arena_t old_arena = policy->children_arena;
    len_bucket_t *old_buckets = policy->len_buckets;
    size_t old_num_buckets = policy->num_buckets;
    size_t old_pattern_count = policy->pattern_count;
    size_t old_children_count = policy->children_count;
    vacuum_filter_t *old_filters[FILTER_POS_LEVELS];
    uint64_t old_wildcards[FILTER_POS_LEVELS];
    uint64_t old_filter_epochs[FILTER_POS_LEVELS];
    memcpy(old_filters, policy->pos_filters, sizeof old_filters);
    memcpy(old_wildcards, policy->pos_wildcard_mask, sizeof old_wildcards);
    memcpy(old_filter_epochs, policy->pos_built_epoch,
           sizeof old_filter_epochs);

    policy->states = staged->states;
    policy->patterns = staged->patterns;
    policy->children_arena = staged->children_arena;
    policy->len_buckets = staged->len_buckets;
    policy->num_buckets = staged->num_buckets;
    policy->pattern_count = staged->pattern_count;
    policy->children_count = staged->children_count;
    memcpy(policy->pos_filters, staged->pos_filters,
           sizeof policy->pos_filters);
    memcpy(policy->pos_wildcard_mask, staged->pos_wildcard_mask,
           sizeof policy->pos_wildcard_mask);
    memcpy(policy->pos_built_epoch, staged->pos_built_epoch,
           sizeof policy->pos_built_epoch);
    atomic_fetch_add(&policy->epoch, 1);

    staged->states = old_states;
    staged->patterns = old_patterns;
    staged->children_arena = old_arena;
    staged->len_buckets = old_buckets;
    staged->num_buckets = old_num_buckets;
    staged->pattern_count = old_pattern_count;
    staged->children_count = old_children_count;
    memcpy(staged->pos_filters, old_filters, sizeof old_filters);
    memcpy(staged->pos_wildcard_mask, old_wildcards, sizeof old_wildcards);
    memcpy(staged->pos_built_epoch, old_filter_epochs,
           sizeof old_filter_epochs);
  }
  st_policy_free(staged);
  pthread_rwlock_unlock(&policy->rwlock);
  return first_err;
}

st_error_t st_policy_merge(st_policy_t *dst, const st_policy_t *src) {
  if (!dst || !src)
    return ST_ERR_INVALID;
  if (dst == src)
    return ST_OK;

  /* Snapshot source strings before mutating the destination. batch_add then
   * provides the atomic replacement: any failure leaves dst unchanged. */
  pthread_rwlock_rdlock((pthread_rwlock_t *)&src->rwlock);
  size_t count = src->pattern_count;
  char **patterns = count ? calloc(count, sizeof(*patterns)) : NULL;
  if (count && !patterns) {
    pthread_rwlock_unlock((pthread_rwlock_t *)&src->rwlock);
    return ST_ERR_MEMORY;
  }
  size_t copied = 0;
  for (size_t i = 0; i < src->patterns.count; i++) {
    if (!src->patterns.entries[i].active)
      continue;
    patterns[copied] = strdup(src->patterns.entries[i].pattern);
    if (!patterns[copied]) {
      for (size_t j = 0; j < copied; j++)
        free(patterns[j]);
      free(patterns);
      pthread_rwlock_unlock((pthread_rwlock_t *)&src->rwlock);
      return ST_ERR_MEMORY;
    }
    copied++;
  }
  pthread_rwlock_unlock((pthread_rwlock_t *)&src->rwlock);

  st_error_t result = copied == 0 ? ST_OK
                                  : st_policy_batch_add_netpatterns(
                                        dst, (const char **)patterns, copied);
  for (size_t i = 0; i < copied; i++)
    free(patterns[i]);
  free(patterns);
  return result;
}

static bool pattern_array_contains_entry(const pattern_entry_t *entries,
                                         size_t count, const char *pat) {
  for (size_t i = 0; i < count; i++) {
    if (entries[i].active && strcmp(entries[i].pattern, pat) == 0)
      return true;
  }
  return false;
}

st_error_t st_policy_diff(const st_policy_t *a, const st_policy_t *b,
                          st_policy_diff_t *result) {
  if (!a || !b || !result)
    return ST_ERR_INVALID;

  memset(result, 0, sizeof(*result));

  if (a == b)
    return ST_OK;

  bool a_first = (uintptr_t)&a->rwlock < (uintptr_t)&b->rwlock;
  const st_policy_t *first = a_first ? a : b;
  const st_policy_t *second = a_first ? b : a;
  pthread_rwlock_rdlock((pthread_rwlock_t *)&first->rwlock);
  pthread_rwlock_rdlock((pthread_rwlock_t *)&second->rwlock);

  size_t a_count = a->patterns.count;
  size_t b_count = b->patterns.count;
  const pattern_entry_t *a_entries = a->patterns.entries;
  const pattern_entry_t *b_entries = b->patterns.entries;

  /* Collect patterns in b that are not in a */
  size_t added_cap = b_count > 0 ? b_count : 1;
  char **added = calloc(added_cap, sizeof(char *));
  if (!added) {
    pthread_rwlock_unlock((pthread_rwlock_t *)&second->rwlock);
    pthread_rwlock_unlock((pthread_rwlock_t *)&first->rwlock);
    return ST_ERR_MEMORY;
  }
  size_t added_count = 0;
  char **removed = NULL;
  size_t removed_count = 0;
  for (size_t i = 0; i < b_count; i++) {
    if (!b_entries[i].active)
      continue;
    if (!pattern_array_contains_entry(a_entries, a_count,
                                      b_entries[i].pattern)) {
      added[added_count] = strdup(b_entries[i].pattern);
      if (!added[added_count])
        goto diff_memory_fail;
      added_count++;
    }
  }

  /* Collect patterns in a that are not in b */
  size_t removed_cap = a_count > 0 ? a_count : 1;
  removed = calloc(removed_cap, sizeof(char *));
  if (!removed) {
    for (size_t i = 0; i < added_count; i++)
      free(added[i]);
    free(added);
    pthread_rwlock_unlock((pthread_rwlock_t *)&second->rwlock);
    pthread_rwlock_unlock((pthread_rwlock_t *)&first->rwlock);
    return ST_ERR_MEMORY;
  }
  for (size_t i = 0; i < a_count; i++) {
    if (!a_entries[i].active)
      continue;
    if (!pattern_array_contains_entry(b_entries, b_count,
                                      a_entries[i].pattern)) {
      removed[removed_count] = strdup(a_entries[i].pattern);
      if (!removed[removed_count])
        goto diff_memory_fail;
      removed_count++;
    }
  }

  result->added = added;
  result->added_count = added_count;
  result->removed = removed;
  result->removed_count = removed_count;

  pthread_rwlock_unlock((pthread_rwlock_t *)&second->rwlock);
  pthread_rwlock_unlock((pthread_rwlock_t *)&first->rwlock);
  return ST_OK;

diff_memory_fail:
  for (size_t i = 0; i < added_count; i++)
    free(added[i]);
  free(added);
  if (removed) {
    for (size_t i = 0; i < removed_count; i++)
      free(removed[i]);
    free(removed);
  }
  memset(result, 0, sizeof(*result));
  pthread_rwlock_unlock((pthread_rwlock_t *)&second->rwlock);
  pthread_rwlock_unlock((pthread_rwlock_t *)&first->rwlock);
  return ST_ERR_MEMORY;
}

void st_free_diff_result(st_policy_diff_t *result) {
  if (!result)
    return;
  for (size_t i = 0; i < result->added_count; i++)
    free(result->added[i]);
  for (size_t i = 0; i < result->removed_count; i++)
    free(result->removed[i]);
  free(result->added);
  free(result->removed);
  result->added = NULL;
  result->removed = NULL;
  result->added_count = 0;
  result->removed_count = 0;
}

/* Remove the exact active registry entry and prune dead transitions along its
 * trie path. Arena storage is reclaimed only by st_policy_compact(), but dead
 * generic wildcard transitions must not remain in the graph: they would
 * otherwise shadow a more-specific parameter branch added later. */
st_error_t st_policy_remove_netpattern(st_policy_t *policy,
                                       const char *pattern) {
  if (!policy || !pattern || !pattern[0])
    return ST_ERR_INVALID;

  pthread_rwlock_wrlock(&policy->rwlock);

  st_token_array_t decoded = {0};
  st_error_t decode_error = st_netpattern_decode(pattern, &decoded);
  if (decode_error != ST_OK) {
    pthread_rwlock_unlock(&policy->rwlock);
    return decode_error;
  }
  size_t token_count = decoded.count;
  st_token_t *tokens = decoded.tokens;
  if (token_count == 0) {
    free_pattern_tokens(tokens, token_count);
    pthread_rwlock_unlock(&policy->rwlock);
    return ST_ERR_INVALID;
  }
  char *canonical = NULL;
  st_error_t encode_error =
      st_netpattern_encode(tokens, token_count, &canonical);
  free_pattern_tokens(tokens, token_count);
  if (encode_error != ST_OK) {
    pthread_rwlock_unlock(&policy->rwlock);
    return encode_error;
  }
  for (size_t i = 0; i < policy->patterns.count; i++) {
    pattern_entry_t *entry = &policy->patterns.entries[i];
    if (!entry->active || strcmp(entry->pattern, canonical) != 0)
      continue;
    st_error_t error = remove_pattern_by_id_locked(policy, (uint16_t)i);
    if (error == ST_OK)
      atomic_fetch_add(&policy->epoch, 1);
    pthread_rwlock_unlock(&policy->rwlock);
    free(canonical);
    return error;
  }
  pthread_rwlock_unlock(&policy->rwlock);
  free(canonical);
  return ST_OK;
}

/*
 * Compact the policy by rebuilding from active patterns.
 * This reclaims arena memory after many add/remove cycles.
 * The context is reset and all trie nodes are rebuilt.
 *
 * NOTE: This function requires exclusive use of the context (no other policies
 * sharing the same context). If the context is shared, ST_ERR_INVALID is
 * returned.
 */
st_error_t st_policy_compact(st_policy_t *policy) {
  if (!policy)
    return ST_ERR_INVALID;

  if (policy->pattern_count == 0)
    return ST_OK;

  /* Check that context is not shared with other policies */
  if (!st_policy_ctx_is_exclusive(policy->ctx)) {
    return ST_ERR_INVALID;
  }

  pthread_rwlock_wrlock(&policy->rwlock);

  char **active = malloc(policy->pattern_count * sizeof(char *));
  if (!active) {
    pthread_rwlock_unlock(&policy->rwlock);
    return ST_ERR_MEMORY;
  }

  size_t n_active = 0;
  for (size_t i = 0; i < policy->patterns.count; i++) {
    if (policy->patterns.entries[i].active) {
      active[n_active++] = strdup(policy->patterns.entries[i].pattern);
      if (!active[n_active - 1]) {
        for (size_t j = 0; j < n_active - 1; j++)
          free(active[j]);
        free(active);
        pthread_rwlock_unlock(&policy->rwlock);
        return ST_ERR_MEMORY;
      }
    }
  }

  if (n_active == 0) {
    free(active);
    pthread_rwlock_unlock(&policy->rwlock);
    return ST_OK;
  }

  st_policy_ctx_t *replacement_ctx = st_policy_ctx_new();
  st_policy_t *staged = replacement_ctx ? st_policy_new(replacement_ctx) : NULL;
  if (!staged) {
    for (size_t i = 0; i < n_active; i++)
      free(active[i]);
    free(active);
    st_policy_ctx_free(replacement_ctx);
    pthread_rwlock_unlock(&policy->rwlock);
    return ST_ERR_MEMORY;
  }

  st_error_t build_error = ST_OK;
  for (size_t i = 0; i < n_active; i++) {
    build_error = st_policy_add_netpattern(staged, active[i]);
    if (build_error != ST_OK)
      break;
  }
  for (size_t i = 0; i < n_active; i++)
    free(active[i]);
  free(active);
  if (build_error != ST_OK) {
    st_policy_free(staged);
    st_policy_ctx_free(replacement_ctx);
    pthread_rwlock_unlock(&policy->rwlock);
    return build_error;
  }

  st_error_t swap_error =
      st_policy_ctx_swap_storage(policy->ctx, replacement_ctx);
  if (swap_error != ST_OK) {
    st_policy_free(staged);
    st_policy_ctx_free(replacement_ctx);
    pthread_rwlock_unlock(&policy->rwlock);
    return swap_error;
  }

#define SWAP_FIELD(field, type)                                                \
  do {                                                                         \
    type temporary = policy->field;                                            \
    policy->field = staged->field;                                             \
    staged->field = temporary;                                                 \
  } while (0)
  SWAP_FIELD(states, states_array_t);
  SWAP_FIELD(patterns, pattern_reg_t);
  SWAP_FIELD(children_arena, arena_t);
  SWAP_FIELD(len_buckets, len_bucket_t *);
  SWAP_FIELD(num_buckets, size_t);
  SWAP_FIELD(pattern_count, size_t);
  SWAP_FIELD(children_count, size_t);
#undef SWAP_FIELD
  for (int i = 0; i < FILTER_POS_LEVELS; i++) {
    vacuum_filter_t *filter = policy->pos_filters[i];
    policy->pos_filters[i] = staged->pos_filters[i];
    staged->pos_filters[i] = filter;
    uint64_t mask = policy->pos_wildcard_mask[i];
    policy->pos_wildcard_mask[i] = staged->pos_wildcard_mask[i];
    staged->pos_wildcard_mask[i] = mask;
    bool compound = policy->pos_has_compound[i];
    policy->pos_has_compound[i] = staged->pos_has_compound[i];
    staged->pos_has_compound[i] = compound;
    uint64_t epoch = policy->pos_built_epoch[i];
    policy->pos_built_epoch[i] = staged->pos_built_epoch[i];
    staged->pos_built_epoch[i] = epoch;
  }
  atomic_fetch_add(&policy->epoch, 1);
  pthread_rwlock_unlock(&policy->rwlock);
  st_policy_free(staged);
  st_policy_ctx_free(replacement_ctx);
  return ST_OK;
}

st_error_t st_policy_clear(st_policy_t *policy) {
  if (!policy)
    return ST_ERR_INVALID;

  pthread_rwlock_wrlock(&policy->rwlock);

  /* Clear filters */
  for (int i = 0; i < FILTER_POS_LEVELS; i++) {
    vacuum_filter_destroy(policy->pos_filters[i]);
    policy->pos_filters[i] = NULL;
    policy->pos_wildcard_mask[i] = 0;
    policy->pos_has_compound[i] = false;
    policy->pos_built_epoch[i] = 0;
  }

  /* Retain allocated storage so clear cannot fail halfway through. */
  memset(policy->states.states, 0,
         policy->states.capacity * sizeof(*policy->states.states));
  policy->states.count = 1;
  policy->states.states[0].pattern_id = UINT16_MAX;
  policy->children_arena.used = 0;

  for (size_t i = 0; i < policy->patterns.count; i++) {
    free_pattern_tokens(policy->patterns.entries[i].tokens,
                        policy->patterns.entries[i].token_count);
  }
  memset(policy->patterns.entries, 0,
         policy->patterns.capacity * sizeof(*policy->patterns.entries));
  policy->patterns.count = 0;

  for (size_t i = 0; i < policy->num_buckets; i++)
    policy->len_buckets[i].count = 0;

  policy->pattern_count = 0;
  policy->children_count = 0;
  atomic_fetch_add(&policy->epoch, 1);

  pthread_rwlock_unlock(&policy->rwlock);
  return ST_OK;
}

size_t st_policy_count(const st_policy_t *policy) {
  if (!policy)
    return 0;
  pthread_rwlock_rdlock((pthread_rwlock_t *)&policy->rwlock);
  size_t count = policy->pattern_count;
  pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
  return count;
}

/* --- VERIFICATION + SUGGESTIONS (unified) --- */

/* Select the display text for a token: use the original text for
 * parametrized wildcards (e.g., "#path.cfg"), otherwise use the
 * type symbol for plain wildcards. */
static const char *token_display_text(const st_token_t *tok) {
  if (tok->type == ST_TYPE_LITERAL)
    return tok->text;
  /* If text contains a parameter (e.g., "#path.cfg"), use it */
  if (tok->text && strchr(tok->text, '.') && type_supports_param(tok->type))
    return tok->text;
  return st_type_symbol[tok->type];
}

/* Build a canonical netpattern from typed suggestion tokens. */
static bool st_build_pattern(char *buf, size_t buf_size,
                             const st_token_t *tokens, size_t count) {
  st_token_t display[ST_MAX_CMD_TOKENS];
  if (count == 0 || count > ST_MAX_CMD_TOKENS)
    return false;
  for (size_t i = 0; i < count; i++) {
    display[i] = tokens[i];
    display[i].text = (char *)token_display_text(&tokens[i]);
  }
  char *encoded = NULL;
  if (st_netpattern_encode(display, count, &encoded) != ST_OK)
    return false;
  size_t length = strlen(encoded);
  if (length + 1 > buf_size) {
    free(encoded);
    return false;
  }
  memcpy(buf, encoded, length + 1);
  free(encoded);
  return true;
}

typedef struct {
  uint32_t state_idx;
  uint8_t token_idx;
} match_entry_t;

static bool pattern_entry_preferred(const pattern_entry_t *candidate,
                                    const pattern_entry_t *current) {
  bool current_covers_candidate =
      pattern_subsumes(current->tokens, current->token_count, candidate->tokens,
                       candidate->token_count);
  bool candidate_covers_current =
      pattern_subsumes(candidate->tokens, candidate->token_count,
                       current->tokens, current->token_count);
  if (current_covers_candidate != candidate_covers_current)
    return current_covers_candidate;
  return st_netpattern_compare(candidate->pattern, current->pattern) < 0;
}

typedef struct {
  uint32_t stack[64];
  uint32_t *states;
  size_t count;
  size_t capacity;
  size_t depth;
} match_frontier_t;

static void match_frontier_init(match_frontier_t *frontier) {
  frontier->states = frontier->stack;
  frontier->count = 0;
  frontier->capacity = sizeof(frontier->stack) / sizeof(frontier->stack[0]);
  frontier->depth = 0;
}

static void match_frontier_free(match_frontier_t *frontier) {
  if (frontier->states != frontier->stack)
    free(frontier->states);
  match_frontier_init(frontier);
}

static bool match_frontier_append(match_frontier_t *frontier,
                                  uint32_t state_idx) {
  if (frontier->count == frontier->capacity) {
    size_t grown_capacity = frontier->capacity * 2;
    uint32_t *grown = malloc(grown_capacity * sizeof(*grown));
    if (!grown)
      return false;
    memcpy(grown, frontier->states, frontier->count * sizeof(*grown));
    if (frontier->states != frontier->stack)
      free(frontier->states);
    frontier->states = grown;
    frontier->capacity = grown_capacity;
  }
  frontier->states[frontier->count++] = state_idx;
  return true;
}

static bool match_queue_append(match_entry_t **queue, match_entry_t *stack,
                               size_t *tail, size_t *capacity,
                               match_entry_t entry) {
  if (*tail == *capacity) {
    size_t grown_capacity = *capacity * 2;
    match_entry_t *grown = malloc(grown_capacity * sizeof(*grown));
    if (!grown)
      return false;
    memcpy(grown, *queue, *tail * sizeof(*grown));
    if (*queue != stack)
      free(*queue);
    *queue = grown;
    *capacity = grown_capacity;
  }
  (*queue)[(*tail)++] = entry;
  return true;
}

static bool compound_child_matches(const child_entry_t *child,
                                   const char *text) {
  if (!child->compound || !child->text || !text)
    return false;
  const char *open = strchr(child->text, '{');
  const char *close = open ? strchr(open + 1, '}') : NULL;
  if (!open || !close)
    return false;
  size_t prefix_length = (size_t)(open - child->text);
  size_t suffix_length = strlen(close + 1);
  size_t text_length = strlen(text);
  if (text_length < prefix_length + suffix_length ||
      memcmp(text, child->text, prefix_length) != 0 ||
      memcmp(text + text_length - suffix_length, close + 1, suffix_length) != 0)
    return false;
  size_t capture_length = text_length - prefix_length - suffix_length;
  if (capture_length >= ST_MAX_TOKEN_LEN)
    return false;
  char capture[ST_MAX_TOKEN_LEN];
  memcpy(capture, text + prefix_length, capture_length);
  capture[capture_length] = '\0';
  size_t symbol_length = (size_t)(close - open - 1);
  if (symbol_length >= ST_MAX_TOKEN_LEN)
    return false;
  char symbol[ST_MAX_TOKEN_LEN];
  memcpy(symbol, open + 1, symbol_length);
  symbol[symbol_length] = '\0';
  st_token_type_t wild_type = ST_TYPE_LITERAL;
  for (int candidate = ST_TYPE_LITERAL + 1; candidate < ST_TYPE_COUNT;
       candidate++) {
    const char *base = st_type_symbol[candidate];
    size_t base_length = strlen(base);
    if (strcmp(symbol, base) == 0 || (strncmp(symbol, base, base_length) == 0 &&
                                      symbol[base_length] == '.')) {
      wild_type = (st_token_type_t)candidate;
      break;
    }
  }
  if (wild_type == ST_TYPE_LITERAL)
    return false;
  st_token_type_t concrete_type = st_classify_token(capture);
  return (runtime_match_mask(concrete_type) & (1ULL << wild_type)) != 0 &&
         param_matches(capture, concrete_type, symbol, wild_type);
}

static st_error_t matching_walk_locked(const st_policy_t *policy,
                                       const st_token_array_t *cmd,
                                       match_frontier_t *frontier,
                                       const char **best) {
  *best = NULL;
  match_frontier_init(frontier);
  size_t queue_cap = 64;
  match_entry_t stack_queue[64];
  match_entry_t *queue = stack_queue;
  size_t head = 0, tail = 1;
  queue[0] = (match_entry_t){0, 0};
  const pattern_entry_t *best_entry = NULL;

  while (head < tail) {
    match_entry_t entry = queue[head++];
    policy_state_t *state = &policy->states.states[entry.state_idx];
    if (entry.token_idx > frontier->depth) {
      frontier->depth = entry.token_idx;
      frontier->count = 0;
    }
    if (entry.token_idx == frontier->depth &&
        !match_frontier_append(frontier, entry.state_idx))
      goto memory_failure;
    if (entry.token_idx == cmd->count) {
      if (state->pattern_id != UINT16_MAX &&
          state->pattern_id < policy->patterns.count) {
        const pattern_entry_t *candidate =
            &policy->patterns.entries[state->pattern_id];
        if (!best_entry || pattern_entry_preferred(candidate, best_entry))
          best_entry = candidate;
      }
      continue;
    }

    st_token_type_t type = cmd->tokens[entry.token_idx].type;
    const char *text = cmd->tokens[entry.token_idx].text;
    child_entry_t *children =
        (child_entry_t *)(policy->children_arena.base + state->children_offset);
    for (uint16_t i = 0; i < state->literal_count; i++)
      if ((!children[i].compound && strcmp(text, children[i].text) == 0) ||
          compound_child_matches(&children[i], text)) {
        if (!match_queue_append(
                &queue, stack_queue, &tail, &queue_cap,
                (match_entry_t){children[i].target, entry.token_idx + 1}))
          goto memory_failure;
        break;
      }
    child_entry_t *wild = children + state->literal_count;
    for (uint16_t i = 0; i < state->wildcard_count; i++) {
      child_entry_t *child = &wild[i];
      if (!(runtime_match_mask(type) & (1ULL << child->type)) ||
          !param_matches(text, type, child->text, (st_token_type_t)child->type))
        continue;
      if (!match_queue_append(
              &queue, stack_queue, &tail, &queue_cap,
              (match_entry_t){child->target, entry.token_idx + 1}))
        goto memory_failure;
    }
  }
  if (queue != stack_queue)
    free(queue);
  if (best_entry)
    *best = best_entry->pattern;
  return ST_OK;

memory_failure:
  if (queue != stack_queue)
    free(queue);
  match_frontier_free(frontier);
  return ST_ERR_MEMORY;
}

static void nearest_pattern_visit(const st_policy_t *policy, uint32_t state_idx,
                                  size_t depth, size_t *best_depth,
                                  const pattern_entry_t **best) {
  const policy_state_t *state = &policy->states.states[state_idx];
  if (depth > *best_depth)
    return;
  if (state->pattern_id != UINT16_MAX &&
      state->pattern_id < policy->patterns.count) {
    const pattern_entry_t *candidate =
        &policy->patterns.entries[state->pattern_id];
    if (!*best || depth < *best_depth ||
        (depth == *best_depth && pattern_entry_preferred(candidate, *best))) {
      *best = candidate;
      *best_depth = depth;
    }
    return;
  }
  uint16_t total = state->literal_count + state->wildcard_count;
  const child_entry_t *children =
      (const child_entry_t *)(policy->children_arena.base +
                              state->children_offset);
  for (uint16_t i = 0; i < total; i++)
    nearest_pattern_visit(policy, children[i].target, depth + 1, best_depth,
                          best);
}

static const char *st_find_based_on(const st_policy_t *policy,
                                    const match_frontier_t *frontier) {
  size_t best_depth = SIZE_MAX;
  const pattern_entry_t *best = NULL;
  for (size_t i = 0; i < frontier->count; i++)
    nearest_pattern_visit(policy, frontier->states[i], 0, &best_depth, &best);
  return best ? best->pattern : NULL;
}

st_error_t st_policy_eval(st_policy_t *policy, const char *netargv,
                          st_eval_result_t *result) {
  if (result) {
    result->matches = false;
    result->matching_pattern = NULL;
    result->suggestion_count = 0;
    result->error = ST_OK;
  }
  if (!policy || !netargv)
    return ST_ERR_INVALID;

  pthread_rwlock_rdlock(&policy->rwlock);

  /* Track statistics (atomic increment for thread safety) */
  atomic_fetch_add(&policy->stats.eval_count, 1);

  if (result) {
    result->matches = false;
    result->matching_pattern = NULL;
    result->suggestion_count = 0;
    result->error = ST_OK;
  }

  st_token_array_t cmd;
  cmd.tokens = NULL;
  cmd.count = 0;
  st_error_t err = st_classify(netargv, &cmd);
  if (err != ST_OK) {
    pthread_rwlock_unlock(&policy->rwlock);
    return err;
  }

  if (cmd.count == 0 || cmd.count > MAX_CMD_TOKENS) {
    st_free_token_array(&cmd);
    pthread_rwlock_unlock(&policy->rwlock);
    if (result)
      result->matches = false;
    return ST_OK;
  }

  /* --- PER-POSITION FILTER PRE-CHECK ---
   *
   * Runs before the trie walk. Rejects definite no-matches early.
   * Runs in ALL modes (verify-only and suggest).
   * Epoch comparison drives lazy rebuild — no spin-wait needed.
   *
   * NOTE: First evaluation after many additions may be slower due to
   * lazy filter rebuild. This is expected behavior.
   */
  bool filter_rejected = false;
  size_t check_len =
      cmd.count < FILTER_POS_LEVELS ? cmd.count : FILTER_POS_LEVELS;

  uint64_t current_epoch = atomic_load(&policy->epoch);
  bool needs_rebuild = false;
  for (size_t i = 0; i < check_len; i++) {
    if (policy->pos_built_epoch[i] != current_epoch) {
      needs_rebuild = true;
      break;
    }
  }

  if (needs_rebuild) {
    pthread_rwlock_unlock(&policy->rwlock);
    pthread_rwlock_wrlock(&policy->rwlock);
    /* Re-check all depths after acquiring write lock (another thread
     * may have rebuilt after a partial epoch update) */
    uint64_t recheck_epoch = atomic_load(&policy->epoch);
    bool still_stale = false;
    for (size_t i = 0; i < check_len; i++) {
      if (policy->pos_built_epoch[i] != recheck_epoch) {
        still_stale = true;
        break;
      }
    }
    if (still_stale) {
      policy_rebuild_filters(policy);
    }
    pthread_rwlock_unlock(&policy->rwlock);
    pthread_rwlock_rdlock(&policy->rwlock);
  }

  for (size_t i = 0; i < check_len; i++) {
    if (policy->pos_has_compound[i])
      continue;
    st_token_type_t ctype = cmd.tokens[i].type;
    /* A compatible wildcard may match without an exact literal. Otherwise an
     * available literal filter must contain this exact token, irrespective of
     * its classified type. A missing/disabled filter provides no evidence and
     * must remain conservative rather than causing a false rejection. */
    if ((policy->pos_wildcard_mask[i] & runtime_match_mask(ctype)) != 0)
      continue;
    if (!policy->pos_filters[i] || policy->pos_filters[i]->count == 0)
      continue;
    uint64_t h =
        filter_hash_fnv1a(cmd.tokens[i].text, strlen(cmd.tokens[i].text));
    if (!vacuum_filter_lookup(policy->pos_filters[i], h)) {
      filter_rejected = true;
      break;
    }
  }

  /* Verify-only fast path: filter rejected → skip trie walk entirely */
  if (filter_rejected && !result) {
    atomic_fetch_add(&policy->stats.filter_reject_count, 1);
    st_free_token_array(&cmd);
    pthread_rwlock_unlock(&policy->rwlock);
    return ST_OK;
  }

  /* Track trie walk (atomic increment for thread safety) */
  atomic_fetch_add(&policy->stats.trie_walk_count, 1);

  /* --- TRIE WALK ---
   *
   * Still needed even when filter rejected — we need match_depth
   * and match_state to produce useful suggestions.
   */
  match_frontier_t frontier;
  const char *best_pattern = NULL;
  err = matching_walk_locked(policy, &cmd, &frontier, &best_pattern);
  if (err != ST_OK) {
    st_free_token_array(&cmd);
    pthread_rwlock_unlock(&policy->rwlock);
    return err;
  }
  size_t match_depth = frontier.depth;
  assert(match_depth <= cmd.count);
  if (best_pattern) {
    match_frontier_free(&frontier);
    st_free_token_array(&cmd);
    if (result) {
      result->matches = true;
      result->matching_pattern = best_pattern;
    }
    pthread_rwlock_unlock(&policy->rwlock);
    return ST_OK;
  }

  /* Verify-only: no match, no suggestions needed */
  if (!result) {
    match_frontier_free(&frontier);
    st_free_token_array(&cmd);
    pthread_rwlock_unlock(&policy->rwlock);
    return ST_OK;
  }

  /* --- SUGGESTION GENERATION ---
   *
   * Uses existing cmd.tokens — no re-normalize, no trie re-walk.
   */
  double confidence = (double)match_depth / (double)cmd.count;
  const char *based_on =
      match_depth == 0 ? NULL : st_find_based_on(policy, &frontier);
  uint64_t divergence_wildcard_mask = 0;
  if (match_depth < cmd.count)
    for (size_t i = 0; i < frontier.count; i++)
      divergence_wildcard_mask |=
          policy->states.states[frontier.states[i]].wildcard_mask;
  match_frontier_free(&frontier);

  /* Suggestion A: minimal extension (matched prefix as-is + remaining as
   * literals) */
  {
    st_token_t *pat_tokens = calloc(cmd.count, sizeof(st_token_t));
    if (!pat_tokens) {
      st_free_token_array(&cmd);
      pthread_rwlock_unlock(&policy->rwlock);
      return ST_ERR_MEMORY;
    }

    for (size_t i = 0; i < match_depth; i++) {
      pat_tokens[i].text = (char *)cmd.tokens[i].text;
      pat_tokens[i].type = cmd.tokens[i].type;
    }
    for (size_t i = match_depth; i < cmd.count; i++) {
      pat_tokens[i].text = (char *)cmd.tokens[i].text;
      pat_tokens[i].type = ST_TYPE_LITERAL;
    }

    if (!st_build_pattern(result->suggestions[0].pattern,
                          sizeof(result->suggestions[0].pattern), pat_tokens,
                          cmd.count)) {
      free(pat_tokens);
      st_free_token_array(&cmd);
      result->error = ST_ERR_FAILED;
      pthread_rwlock_unlock(&policy->rwlock);
      return ST_OK;
    }
    result->suggestions[0].based_on = based_on;
    result->suggestions[0].confidence = confidence;
    free(pat_tokens);
  }

  /* Suggestion B: best generalization */
  size_t n_suggestions = 1;

  if (match_depth < cmd.count) {
    st_token_type_t div_type = cmd.tokens[match_depth].type;
    uint64_t wm = divergence_wildcard_mask;
    if (wm != 0 && (runtime_match_mask(div_type) & wm) != 0) {
      /* Wildcard widening: find narrowest compatible wildcard */
      st_token_type_t best_wild = ST_TYPE_ANY;
      uint64_t compat = runtime_match_mask(div_type) & wm;
      while (compat) {
        int t = __builtin_ctzll(compat);
        compat &= ~(1ULL << t);
        st_token_type_t wt = (st_token_type_t)t;
        st_token_type_t joined = st_join(wt, div_type);
        if (best_wild == ST_TYPE_ANY || st_is_compatible(joined, best_wild))
          best_wild = joined;
      }

      if (best_wild != ST_TYPE_ANY) {
        size_t pat_len = match_depth + 1;
        st_token_t *pat_tokens = calloc(pat_len, sizeof(st_token_t));
        if (pat_tokens) {
          for (size_t i = 0; i < match_depth; i++) {
            pat_tokens[i].text = (char *)cmd.tokens[i].text;
            pat_tokens[i].type = cmd.tokens[i].type;
          }
          pat_tokens[match_depth].text = (char *)st_type_symbol[best_wild];
          pat_tokens[match_depth].type = best_wild;

          if (!st_build_pattern(result->suggestions[1].pattern,
                                sizeof(result->suggestions[1].pattern),
                                pat_tokens, pat_len)) {
            free(pat_tokens);
            st_free_token_array(&cmd);
            result->error = ST_ERR_FAILED;
            pthread_rwlock_unlock(&policy->rwlock);
            return ST_OK;
          }
          result->suggestions[1].based_on = based_on;
          result->suggestions[1].confidence = confidence;
          free(pat_tokens);
          n_suggestions = 2;
        }
      }
    }
  }

  if (n_suggestions < 2) {
    if (!st_build_pattern(result->suggestions[1].pattern,
                          sizeof(result->suggestions[1].pattern), cmd.tokens,
                          cmd.count)) {
      st_free_token_array(&cmd);
      result->error = ST_ERR_FAILED;
      pthread_rwlock_unlock(&policy->rwlock);
      return ST_OK;
    }
    if (strcmp(result->suggestions[0].pattern,
               result->suggestions[1].pattern) != 0) {
      result->suggestions[1].based_on = NULL;
      result->suggestions[1].confidence = confidence;
      n_suggestions = 2;
    }
  }

  result->suggestion_count = n_suggestions;
  atomic_fetch_add(&policy->stats.suggestion_count, (uint64_t)n_suggestions);
  st_free_token_array(&cmd);
  pthread_rwlock_unlock(&policy->rwlock);
  return ST_OK;
}

/* --- VERIFY ALL --- */

typedef struct {
  uint32_t state_idx;
  uint8_t token_idx;
} bfs_entry_t;

st_error_t st_policy_verify_all(const st_policy_t *policy, const char *netargv,
                                const char ***matching_patterns,
                                size_t *match_count) {
  if (matching_patterns)
    *matching_patterns = NULL;
  if (match_count)
    *match_count = 0;
  if (!policy || !netargv || !matching_patterns || !match_count)
    return ST_ERR_INVALID;

  st_token_array_t cmd;
  cmd.tokens = NULL;
  cmd.count = 0;
  st_error_t err = st_classify(netargv, &cmd);
  if (err != ST_OK)
    return err;

  if (cmd.count == 0 || cmd.count > MAX_CMD_TOKENS) {
    st_free_token_array(&cmd);
    return ST_OK;
  }

  pthread_rwlock_rdlock((pthread_rwlock_t *)&policy->rwlock);

  const char **matches = NULL;
  size_t match_cap = 0;
  size_t match_n = 0;
  st_error_t result = ST_OK;

  size_t queue_cap = 64;
  bfs_entry_t *queue = malloc(queue_cap * sizeof(*queue));
  if (!queue) {
    result = ST_ERR_MEMORY;
    goto cleanup;
  }
  size_t head = 0, tail = 1;
  queue[0].state_idx = 0;
  queue[0].token_idx = 0;

  while (head < tail) {
    bfs_entry_t entry = queue[head++];

    policy_state_t *state = &policy->states.states[entry.state_idx];

    if (entry.token_idx == cmd.count) {
      if (state->pattern_id != UINT16_MAX &&
          state->pattern_id < policy->patterns.count) {
        if (match_n >= match_cap) {
          size_t new_cap = match_cap == 0 ? 8 : match_cap * 2;
          const char **new_matches =
              realloc(matches, new_cap * sizeof(const char *));
          if (!new_matches) {
            result = ST_ERR_MEMORY;
            goto cleanup;
          }
          matches = new_matches;
          match_cap = new_cap;
        }
        matches[match_n++] =
            policy->patterns.entries[state->pattern_id].pattern;
      }
      continue;
    }

    st_token_type_t ctype = cmd.tokens[entry.token_idx].type;
    const char *ctext = cmd.tokens[entry.token_idx].text;
    char *arena_base = policy->children_arena.base;

    {
      /* Check literal children by text match (regardless of command token
       * type). Tokens like "-m" may be classified as SHORTOPT but stored as
       * literal children in the trie with text="-m". */
      uint16_t n = state->literal_count;
      child_entry_t *children =
          (child_entry_t *)(arena_base + state->children_offset);
      for (uint16_t ci = 0; ci < n; ci++) {
        if (strcmp(ctext, children[ci].text) == 0) {
          if (tail == queue_cap) {
            if (queue_cap > SIZE_MAX / 2 ||
                queue_cap * 2 > SIZE_MAX / sizeof(*queue)) {
              result = ST_ERR_MEMORY;
              goto cleanup;
            }
            size_t new_cap = queue_cap * 2;
            bfs_entry_t *grown = realloc(queue, new_cap * sizeof(*queue));
            if (!grown) {
              result = ST_ERR_MEMORY;
              goto cleanup;
            }
            queue = grown;
            queue_cap = new_cap;
          }
          queue[tail].state_idx = children[ci].target;
          queue[tail].token_idx = entry.token_idx + 1;
          tail++;
          break;
        }
      }
    }

    child_entry_t *children =
        (child_entry_t *)(arena_base + state->children_offset);
    child_entry_t *wild = children + state->literal_count;
    for (uint16_t wi = 0; wi < state->wildcard_count; wi++) {
      child_entry_t *c = &wild[wi];
      if ((runtime_match_mask(ctype) & (1ULL << c->type)) &&
          param_matches(ctext, ctype, c->text, (st_token_type_t)c->type)) {
        if (tail == queue_cap) {
          if (queue_cap > SIZE_MAX / 2 ||
              queue_cap * 2 > SIZE_MAX / sizeof(*queue)) {
            result = ST_ERR_MEMORY;
            goto cleanup;
          }
          size_t new_cap = queue_cap * 2;
          bfs_entry_t *grown = realloc(queue, new_cap * sizeof(*queue));
          if (!grown) {
            result = ST_ERR_MEMORY;
            goto cleanup;
          }
          queue = grown;
          queue_cap = new_cap;
        }
        queue[tail].state_idx = c->target;
        queue[tail].token_idx = entry.token_idx + 1;
        tail++;
      }
    }
  }

cleanup:
  free(queue);
  pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
  st_free_token_array(&cmd);

  if (result != ST_OK) {
    free(matches);
    return result;
  }

  *matching_patterns = matches;
  *match_count = match_n;
  return ST_OK;
}

void st_policy_free_matches(const char **matches, size_t count) {
  (void)count;
  free((void *)matches);
}

/* --- NFA RENDERING ---
 *
 * Produces NFA-DSL format compatible with the c-dfa subproject's
 * nfa2dfa converter. Uses per-state transition arrays to ensure
 * correct output regardless of DFS traversal order.
 *
 * Two-pass approach:
 *   Pass 1: DFS walk the trie, assign NFA state IDs, collect
 *           transitions into per-state arrays.
 *   Pass 2: Write the complete NFA-DSL file with states in order.
 *
 * Format:
 *   NFA_ALPHABET / Identifier / AlphabetSize / States / Initial
 *   Alphabet: (0-255 byte symbols, 256-260 virtual symbols)
 *   State blocks: CategoryMask, PatternId, EosTarget, Tags, Transitions
 */

#define VSYM_BYTE_ANY 256
#define VSYM_EPS 257
#define VSYM_EOS 258
#define VSYM_SPACE 259
#define VSYM_TAB 260

typedef struct {
  int symbol;
  uint32_t target;
} nfa_trans_t;

typedef struct {
  bool is_accepting;
  uint8_t category_mask;
  uint32_t pattern_id;
  const char *tag;
  nfa_trans_t *trans;
  uint32_t trans_count;
  uint32_t trans_cap;
} nfa_state_t;

typedef struct {
  nfa_state_t *states;
  uint32_t state_count;
  uint32_t state_cap;
  uint32_t pattern_id_counter;
  uint8_t category_mask;
  bool include_tags;
  const char *identifier;
} nfa_ctx_t;

static nfa_ctx_t *nfa_ctx_new(uint8_t cat_mask, bool tags, const char *ident,
                              uint32_t pid_base) {
  nfa_ctx_t *c = calloc(1, sizeof(*c));
  if (!c)
    return NULL;
  c->state_cap = 256;
  c->states = calloc(c->state_cap, sizeof(nfa_state_t));
  if (!c->states) {
    free(c);
    return NULL;
  }
  c->category_mask = cat_mask;
  c->include_tags = tags;
  c->identifier = ident ? ident : "rbox policy";
  c->pattern_id_counter = pid_base;
  return c;
}

static void nfa_ctx_free(nfa_ctx_t *c) {
  if (!c)
    return;
  for (uint32_t i = 0; i < c->state_count; i++)
    free(c->states[i].trans);
  free(c->states);
  free(c);
}

static uint32_t nfa_new_state(nfa_ctx_t *c) {
  if (c->state_count >= c->state_cap) {
    uint32_t nc = c->state_cap * 2;
    nfa_state_t *ns = realloc(c->states, nc * sizeof(nfa_state_t));
    if (!ns)
      return UINT32_MAX;
    c->states = ns;
    c->state_cap = nc;
  }
  uint32_t id = c->state_count++;
  memset(&c->states[id], 0, sizeof(nfa_state_t));
  return id;
}

static bool nfa_add_trans(nfa_ctx_t *c, uint32_t from, int sym, uint32_t to) {
  nfa_state_t *s = &c->states[from];
  if (s->trans_count >= s->trans_cap) {
    uint32_t nc = s->trans_cap ? s->trans_cap * 2 : 4;
    nfa_trans_t *nt = realloc(s->trans, nc * sizeof(nfa_trans_t));
    if (!nt)
      return false;
    s->trans = nt;
    s->trans_cap = nc;
  }
  s->trans[s->trans_count].symbol = sym;
  s->trans[s->trans_count].target = to;
  s->trans_count++;
  return true;
}

static bool nfa_add_literal(nfa_ctx_t *c, uint32_t from, const char *text,
                            uint32_t target) {
  for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
    uint32_t next = p[1] == '\0' ? target : nfa_new_state(c);
    if (next == UINT32_MAX || !nfa_add_trans(c, from, *p, next))
      return false;
    from = next;
  }
  return true;
}

static bool nfa_add_wildcard(nfa_ctx_t *c, uint32_t from,
                             const child_entry_t *child, uint32_t target) {
  if (child->type == ST_TYPE_ANY) {
    uint32_t token = nfa_new_state(c);
    if (token == UINT32_MAX)
      return false;
    for (int byte = 1; byte < 256; byte++) {
      if (byte == ' ' || byte == '\t')
        continue;
      if (!nfa_add_trans(c, from, byte, token) ||
          !nfa_add_trans(c, token, byte, token))
        return false;
    }
    if (!nfa_add_trans(c, token, VSYM_EPS, target))
      return false;
    return true;
  }

  char parameter_buffer[32];
  const char *parameter = NULL;
  const st_metadata_entry_t *metadata =
      st_wildcard_metadata(child->text, child->type);
  if (metadata) {
    int parameter_length = snprintf(parameter_buffer, sizeof(parameter_buffer),
                                    ".%s", metadata->name);
    if (parameter_length < 0 ||
        (size_t)parameter_length >= sizeof(parameter_buffer))
      return false;
    parameter = parameter_buffer;
  }
  for (int command_type = 1; command_type < ST_TYPE_ANY; command_type++) {
    if (!st_is_compatible((st_token_type_t)command_type, child->type))
      continue;
    char normalized[ST_MAX_TOKEN_LEN];
    int written =
        snprintf(normalized, sizeof(normalized), "%s%s",
                 st_type_symbol[command_type], parameter ? parameter : "");
    if (written < 0 || (size_t)written >= sizeof(normalized) ||
        !nfa_add_literal(c, from, normalized, target))
      return false;
  }
  return true;
}

/* Pass 1: assign NFA state IDs and collect per-state transitions */
static bool nfa_build(nfa_ctx_t *c, st_policy_t *policy, uint32_t trie_idx,
                      uint32_t nfa_state, bool need_space, uint32_t *trie_map) {
  policy_state_t *node = &policy->states.states[trie_idx];
  uint16_t total = node->literal_count + node->wildcard_count;
  child_entry_t *children =
      (child_entry_t *)(policy->children_arena.base + node->children_offset);
  nfa_state_t *si = &c->states[nfa_state];

  if (node->pattern_id != UINT16_MAX) {
    si->is_accepting = true;
    si->category_mask = c->category_mask;
    si->pattern_id = c->pattern_id_counter++;
    if (c->include_tags && node->pattern_id < policy->patterns.count)
      si->tag = policy->patterns.entries[node->pattern_id].pattern;
  }

  for (uint16_t i = 0; i < total; i++) {
    child_entry_t *ch = &children[i];

    if (ch->type == ST_TYPE_LITERAL) {
      /* Byte-by-byte chain for literal tokens */
      uint32_t from = nfa_state;
      if (need_space) {
        uint32_t sp = nfa_new_state(c);
        if (sp == UINT32_MAX)
          return false;
        if (!nfa_add_trans(c, from, VSYM_SPACE, sp))
          return false;
        from = sp;
      }
      if (trie_map[ch->target] == UINT32_MAX) {
        uint32_t ns = nfa_new_state(c);
        if (ns == UINT32_MAX)
          return false;
        trie_map[ch->target] = ns;
      }
      if (!nfa_add_literal(c, from, ch->text, trie_map[ch->target]))
        return false;
    } else {
      /* Wildcard: VSYM_BYTE_ANY (matches any single token) */
      uint32_t from = nfa_state;
      if (need_space) {
        uint32_t sp = nfa_new_state(c);
        if (sp == UINT32_MAX)
          return false;
        if (!nfa_add_trans(c, from, VSYM_SPACE, sp))
          return false;
        from = sp;
      }
      if (trie_map[ch->target] == UINT32_MAX) {
        uint32_t ns = nfa_new_state(c);
        if (ns == UINT32_MAX)
          return false;
        trie_map[ch->target] = ns;
      }
      if (!nfa_add_wildcard(c, from, ch, trie_map[ch->target]))
        return false;
    }
  }

  /* Recurse into children */
  for (uint16_t i = 0; i < total; i++) {
    child_entry_t *ch = &children[i];
    if (trie_map[ch->target] == UINT32_MAX)
      continue;
    if (!nfa_build(c, policy, ch->target, trie_map[ch->target], true, trie_map))
      return false;
  }
  return true;
}

/* Pass 2: write the NFA-DSL file */
static bool nfa_write(nfa_ctx_t *c, FILE *fp) {
  if (fprintf(fp, "NFA_ALPHABET\n") < 0)
    return false;
  if (fprintf(fp, "Identifier: %s\n", c->identifier) < 0)
    return false;
  if (fprintf(fp, "AlphabetSize: 261\n") < 0)
    return false;
  if (fprintf(fp, "States: %u\n", c->state_count) < 0)
    return false;
  if (fprintf(fp, "Initial: 0\n\n") < 0)
    return false;

  if (fprintf(fp, "Alphabet:\n") < 0)
    return false;
  for (int i = 0; i < 256; i++) {
    if (fprintf(fp, "  Symbol %d: %d-%d\n", i, i, i) < 0)
      return false;
  }
  if (fprintf(fp, "  Symbol 256: 0-255 (special)\n") < 0)
    return false;
  if (fprintf(fp, "  Symbol 257: 1-1 (special)\n") < 0)
    return false;
  if (fprintf(fp, "  Symbol 258: 5-5 (special)\n") < 0)
    return false;
  if (fprintf(fp, "  Symbol 259: 32-32 (special)\n") < 0)
    return false;
  if (fprintf(fp, "  Symbol 260: 9-9 (special)\n\n") < 0)
    return false;

  for (uint32_t s = 0; s < c->state_count; s++) {
    nfa_state_t *si = &c->states[s];
    if (fprintf(fp, "State %u:\n", s) < 0)
      return false;
    if (fprintf(fp, "  CategoryMask: 0x%02x\n",
                si->is_accepting ? si->category_mask : 0) < 0)
      return false;
    if (fprintf(fp, "  PatternId: %u\n", si->pattern_id) < 0)
      return false;
    if (fprintf(fp, "  EosTarget: %s\n", si->is_accepting ? "yes" : "no") < 0)
      return false;
    if (si->tag) {
      char *cpl_tag = NULL;
      if (st_netpattern_to_cpl(si->tag, &cpl_tag) != ST_OK)
        return false;
      int written = fprintf(fp, "  Tags: %s\n", cpl_tag);
      free(cpl_tag);
      if (written < 0)
        return false;
    }
    if (fprintf(fp, "  Transitions: %u\n", si->trans_count) < 0)
      return false;
    for (uint32_t t = 0; t < si->trans_count; t++) {
      if (fprintf(fp, "    Symbol %d -> %u\n", si->trans[t].symbol,
                  si->trans[t].target) < 0)
        return false;
    }
    if (fprintf(fp, "\n") < 0)
      return false;
  }
  return true;
}

st_error_t st_policy_render_nfa(const st_policy_t *policy, const char *path,
                                const st_nfa_render_opts_t *opts) {
  if (!policy || !path)
    return ST_ERR_INVALID;

  const char *identifier = opts ? opts->identifier : NULL;
  if (identifier)
    for (const unsigned char *p = (const unsigned char *)identifier; *p; p++)
      if (*p < 0x20 || *p == 0x7f)
        return ST_ERR_INVALID;

  pthread_rwlock_rdlock((pthread_rwlock_t *)&policy->rwlock);

  uint32_t pattern_id_base = opts ? opts->pattern_id_base : 1;
  if (policy->pattern_count > 0 &&
      pattern_id_base > UINT32_MAX - (policy->pattern_count - 1)) {
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    return ST_ERR_LIMIT;
  }

  uint32_t num_trie = (uint32_t)((st_policy_t *)policy)->states.count;
  uint32_t *trie_map = malloc(num_trie * sizeof(uint32_t));
  if (!trie_map) {
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    return ST_ERR_MEMORY;
  }
  for (uint32_t i = 0; i < num_trie; i++)
    trie_map[i] = UINT32_MAX;

  nfa_ctx_t *c = nfa_ctx_new(
      opts ? opts->category_mask : 0x01, opts ? opts->include_tags : false,
      opts ? opts->identifier : "rbox policy", pattern_id_base);
  if (!c) {
    free(trie_map);
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    return ST_ERR_MEMORY;
  }

  trie_map[0] = nfa_new_state(c);
  if (trie_map[0] == UINT32_MAX) {
    nfa_ctx_free(c);
    free(trie_map);
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    return ST_ERR_MEMORY;
  }

  bool ok = nfa_build(c, (st_policy_t *)policy, 0, 0, false, trie_map);
  bool io_error = false;

  st_atomic_output_t output = {0};
  if (ok) {
    st_atomic_output_result_t begin = st_atomic_output_begin(path, &output);
    if (begin != ST_ATOMIC_OUTPUT_OK) {
      nfa_ctx_free(c);
      free(trie_map);
      pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
      return begin == ST_ATOMIC_OUTPUT_MEMORY ? ST_ERR_MEMORY : ST_ERR_IO;
    }
    ok = nfa_write(c, output.stream);
    if (!ok)
      io_error = true;
    if (ok && st_atomic_output_commit(&output) != 0) {
      ok = false;
      io_error = true;
    } else if (!ok) {
      st_atomic_output_discard(&output);
    }
  }

  nfa_ctx_free(c);
  free(trie_map);
  pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
  return ok ? ST_OK : (io_error ? ST_ERR_IO : ST_ERR_MEMORY);
}

/* --- SERIALIZATION ---
 *
 * Version 3 stores canonical netpatterns, including compound argument
 * records, in an additional netstring frame:
 *
 *   # shelltype-policy v3
 *   # patterns: <count>
 *   <byte-length>:<canonical-netpattern>,\n
 *   ...
 *   # CRC32: <hex>
 *
 * The CRC covers every complete framed record including its trailing newline.
 * The length frame makes embedded whitespace and newlines unambiguous. Version
 * 1 line-oriented CPL files remain loadable and are canonicalized on import.
 */

#define ST_SERIALIZATION_VERSION 3

typedef struct {
  FILE *fp;
  st_error_t error;
  uint32_t crc;
  size_t pattern_count;
} policy_save_ctx_t;

static void dfs_save(st_policy_t *policy, uint32_t idx,
                     policy_save_ctx_t *ctx) {
  if (ctx->error != ST_OK)
    return;

  policy_state_t *node = &policy->states.states[idx];
  uint16_t total = node->literal_count + node->wildcard_count;
  child_entry_t *children =
      (child_entry_t *)(policy->children_arena.base + node->children_offset);

  if (node->pattern_id != UINT16_MAX &&
      node->pattern_id < policy->patterns.count) {
    const char *pat = policy->patterns.entries[node->pattern_id].pattern;
    size_t len = strlen(pat);
    char prefix[32];
    size_t prefix_len = 0;
    if (shell_netstring_write_prefix(prefix, sizeof(prefix) - 1, len,
                                     &prefix_len) != SHELL_NETSTRING_OK) {
      ctx->error = ST_ERR_IO;
      return;
    }
    prefix[prefix_len] = '\0';
    if (fprintf(ctx->fp, "%s%s,\n", prefix, pat) < 0) {
      ctx->error = ST_ERR_IO;
      return;
    }
    ctx->crc = st_crc32_update(prefix, prefix_len, ctx->crc);
    ctx->crc = st_crc32_update(pat, len, ctx->crc);
    ctx->crc = st_crc32_update(",\n", 2, ctx->crc);
    ctx->pattern_count++;
  }

  for (uint16_t i = 0; i < total; i++) {
    child_entry_t *c = &children[i];
    if (c)
      dfs_save(policy, c->target, ctx);
  }
}

st_error_t st_policy_save(const st_policy_t *policy, const char *path) {
  if (!policy || !path)
    return ST_ERR_INVALID;

  st_atomic_output_t output;
  st_atomic_output_result_t begin = st_atomic_output_begin(path, &output);
  if (begin != ST_ATOMIC_OUTPUT_OK)
    return begin == ST_ATOMIC_OUTPUT_MEMORY ? ST_ERR_MEMORY : ST_ERR_IO;
  FILE *fp = output.stream;

  /* Keep the metadata count and trie traversal under one read lock so a
   * concurrent mutation cannot produce an internally inconsistent file. */
  pthread_rwlock_rdlock((pthread_rwlock_t *)&policy->rwlock);
  size_t snapshot_count = policy->pattern_count;

  if (fprintf(fp, "# shelltype-policy v%d\n", ST_SERIALIZATION_VERSION) < 0) {
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    st_atomic_output_discard(&output);
    return ST_ERR_IO;
  }
  if (fprintf(fp, "# patterns: %zu\n", snapshot_count) < 0) {
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    st_atomic_output_discard(&output);
    return ST_ERR_IO;
  }

  /* Patterns with running CRC */
  policy_save_ctx_t ctx = {
      .fp = fp, .error = ST_OK, .crc = 0, .pattern_count = 0};
  dfs_save((st_policy_t *)policy, 0, &ctx);

  pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);

  /* Footer: CRC32 */
  if (ctx.error == ST_OK) {
    if (fprintf(fp, "# CRC32: %08x\n", ctx.crc) < 0) {
      ctx.error = ST_ERR_IO;
    }
  }

  if (ctx.error == ST_OK) {
    if (st_atomic_output_commit(&output) != 0)
      ctx.error = ST_ERR_IO;
  } else {
    st_atomic_output_discard(&output);
  }
  return ctx.error;
}

/*
 * NOTE: By default, st_policy_load appends to an existing policy.
 * If clear_first is true, the policy is reset before loading.
 *
 * If clear_first is false and an error occurs (CRC mismatch, parse error,
 * memory failure), the policy counts are rolled back to their pre-load state.
 * Any arena memory allocated during the failed load is orphaned but will be
 * reclaimed on st_policy_ctx_reset or when the policy/context is freed.
 */
st_error_t st_policy_load(st_policy_t *policy, const char *path,
                          bool clear_first) {
  if (!policy || !path)
    return ST_ERR_INVALID;

  /* --- PASS 1: Read file, verify CRC, collect pattern lines ---
   * Do NOT modify the policy yet.
   */
  FILE *fp = fopen(path, "rb");
  if (!fp)
    return ST_ERR_IO;

  /* Dynamic array of pattern lines */
  char **pattern_lines = NULL;
  size_t pattern_count = 0;

  char line[4096];
  uint32_t expected_crc = 0;
  uint32_t computed_crc = 0;
  size_t declared_count = 0;
  bool got_pattern_count = false;
  bool got_header = false;
  bool got_crc = false;
  st_error_t pass1_error = ST_ERR_FORMAT;

  st_line_status_t line_status;
  line_status = st_read_line(fp, line, sizeof(line));
  if (line_status != ST_LINE_OK) {
    if (line_status == ST_LINE_IO)
      pass1_error = ST_ERR_IO;
    goto pass1_fail;
  }
  size_t header_len = strlen(line);
  while (header_len > 0 &&
         (line[header_len - 1] == '\n' || line[header_len - 1] == '\r'))
    line[--header_len] = '\0';

  if (strcmp(line, "# shelltype-policy v3") == 0) {
    got_header = true;
    line_status = st_read_line(fp, line, sizeof(line));
    if (line_status != ST_LINE_OK) {
      if (line_status == ST_LINE_IO)
        pass1_error = ST_ERR_IO;
      goto pass1_fail;
    }
    size_t count_len = strlen(line);
    while (count_len > 0 &&
           (line[count_len - 1] == '\n' || line[count_len - 1] == '\r'))
      line[--count_len] = '\0';
    if (strncmp(line, "# patterns:", 11) != 0)
      goto pass1_fail;
    char *count_end = NULL;
    unsigned long long count_value = strtoull(line + 11, &count_end, 10);
    if (count_end == line + 11 || *count_end != '\0' ||
        count_value > ST_MAX_POLICY_PATTERNS)
      goto pass1_fail;
    declared_count = (size_t)count_value;
    got_pattern_count = true;

    if (declared_count != 0) {
      pattern_lines = calloc(declared_count, sizeof(*pattern_lines));
      if (!pattern_lines) {
        pass1_error = ST_ERR_MEMORY;
        goto pass1_fail;
      }
    }
    for (size_t record_index = 0; record_index < declared_count;
         record_index++) {
      unsigned char *record = NULL;
      size_t record_length = 0;
      shell_netstring_status_t net_status = shell_netstring_read_stream(
          fp, ST_MAX_NETPATTERN_LEN + 32, &record, &record_length);
      if (net_status != SHELL_NETSTRING_OK) {
        pass1_error = net_status == SHELL_NETSTRING_ENOMEM      ? ST_ERR_MEMORY
                      : net_status == SHELL_NETSTRING_EIO       ? ST_ERR_IO
                      : net_status == SHELL_NETSTRING_EOVERFLOW ? ST_ERR_LIMIT
                                                                : ST_ERR_FORMAT;
        goto pass1_fail;
      }
      shell_netstring_iter_t iter;
      shell_netstring_view_t view, end_view;
      if (shell_netstring_iter_init(&iter, record, record_length) !=
              SHELL_NETSTRING_OK ||
          shell_netstring_iter_next(&iter, &view) != SHELL_NETSTRING_OK ||
          view.record_length != record_length ||
          shell_netstring_iter_next(&iter, &end_view) != SHELL_NETSTRING_DONE ||
          view.payload_length == 0 ||
          view.payload_length >= ST_MAX_NETPATTERN_LEN ||
          memchr(view.payload, '\0', view.payload_length)) {
        free(record);
        goto pass1_fail;
      }
      int newline = fgetc(fp);
      if (newline != '\n') {
        free(record);
        if (ferror(fp))
          pass1_error = ST_ERR_IO;
        goto pass1_fail;
      }
      size_t payload_len = view.payload_length;
      computed_crc = st_crc32_update(record, record_length, computed_crc);
      computed_crc = st_crc32_update("\n", 1, computed_crc);
      memmove(record, view.payload, payload_len);
      record[payload_len] = '\0';
      char *payload = (char *)record;
      st_token_array_t decoded_pattern = {0};
      st_error_t decode_error = st_netpattern_decode(payload, &decoded_pattern);
      st_free_token_array(&decoded_pattern);
      if (decode_error != ST_OK) {
        free(payload);
        if (decode_error == ST_ERR_MEMORY)
          pass1_error = ST_ERR_MEMORY;
        goto pass1_fail;
      }
      pattern_lines[pattern_count++] = payload;
    }
    line_status = st_read_line(fp, line, sizeof(line));
    if (line_status != ST_LINE_OK) {
      if (line_status == ST_LINE_IO)
        pass1_error = ST_ERR_IO;
      goto pass1_fail;
    }
    size_t footer_len = strlen(line);
    while (footer_len > 0 &&
           (line[footer_len - 1] == '\n' || line[footer_len - 1] == '\r'))
      line[--footer_len] = '\0';
    if (strncmp(line, "# CRC32: ", 9) != 0 || footer_len != 17)
      goto pass1_fail;
    char *crc_end = NULL;
    unsigned long crc_value = strtoul(line + 9, &crc_end, 16);
    if (crc_end != line + 17 || *crc_end != '\0' || crc_value > UINT32_MAX)
      goto pass1_fail;
    expected_crc = (uint32_t)crc_value;
    got_crc = true;
    int trailing = fgetc(fp);
    if (trailing != EOF || ferror(fp)) {
      if (ferror(fp))
        pass1_error = ST_ERR_IO;
      goto pass1_fail;
    }
    goto pass1_complete;
  }

  goto pass1_fail;
pass1_complete:
  if (fclose(fp) != 0) {
    fp = NULL;
    pass1_error = ST_ERR_IO;
    goto pass1_fail;
  }
  fp = NULL;

  if (!got_header || !got_pattern_count || !got_crc ||
      declared_count != pattern_count || computed_crc != expected_crc) {
    goto pass1_fail;
  }

  /* PASS 2: build a complete replacement off to the side. The live policy is
   * untouched until every pattern has been accepted. */
  st_policy_t *staged = st_policy_new(policy->ctx);
  if (!staged)
    goto pass2_memory_fail;
  if (!clear_first) {
    st_error_t merge_err = st_policy_merge(staged, policy);
    if (merge_err != ST_OK) {
      st_policy_free(staged);
      goto pass2_memory_fail;
    }
  }

  const char **lines = (const char **)pattern_lines;
  st_error_t add_err =
      pattern_count == 0
          ? ST_OK
          : st_policy_batch_add_netpatterns(staged, lines, pattern_count);
  if (add_err != ST_OK) {
    st_policy_free(staged);
    goto pass2_error;
  }

  pthread_rwlock_wrlock(&policy->rwlock);
  states_array_t old_states = policy->states;
  pattern_reg_t old_patterns = policy->patterns;
  arena_t old_arena = policy->children_arena;
  len_bucket_t *old_buckets = policy->len_buckets;
  size_t old_num_buckets = policy->num_buckets;
  size_t old_pattern_count = policy->pattern_count;
  size_t old_children_count = policy->children_count;
  vacuum_filter_t *old_filters[FILTER_POS_LEVELS];
  uint64_t old_wildcards[FILTER_POS_LEVELS];
  uint64_t old_filter_epochs[FILTER_POS_LEVELS];
  memcpy(old_filters, policy->pos_filters, sizeof old_filters);
  memcpy(old_wildcards, policy->pos_wildcard_mask, sizeof old_wildcards);
  memcpy(old_filter_epochs, policy->pos_built_epoch, sizeof old_filter_epochs);

  policy->states = staged->states;
  policy->patterns = staged->patterns;
  policy->children_arena = staged->children_arena;
  policy->len_buckets = staged->len_buckets;
  policy->num_buckets = staged->num_buckets;
  policy->pattern_count = staged->pattern_count;
  policy->children_count = staged->children_count;
  memcpy(policy->pos_filters, staged->pos_filters, sizeof policy->pos_filters);
  memcpy(policy->pos_wildcard_mask, staged->pos_wildcard_mask,
         sizeof policy->pos_wildcard_mask);
  memcpy(policy->pos_built_epoch, staged->pos_built_epoch,
         sizeof policy->pos_built_epoch);
  atomic_fetch_add(&policy->epoch, 1);
  pthread_rwlock_unlock(&policy->rwlock);

  staged->states = old_states;
  staged->patterns = old_patterns;
  staged->children_arena = old_arena;
  staged->len_buckets = old_buckets;
  staged->num_buckets = old_num_buckets;
  staged->pattern_count = old_pattern_count;
  staged->children_count = old_children_count;
  memcpy(staged->pos_filters, old_filters, sizeof old_filters);
  memcpy(staged->pos_wildcard_mask, old_wildcards, sizeof old_wildcards);
  memcpy(staged->pos_built_epoch, old_filter_epochs, sizeof old_filter_epochs);
  for (size_t i = 0; i < pattern_count; i++)
    free(pattern_lines[i]);
  free(pattern_lines);
  st_policy_free(staged);
  return ST_OK;

pass2_memory_fail:
  for (size_t i = 0; i < pattern_count; i++)
    free(pattern_lines[i]);
  free(pattern_lines);
  return ST_ERR_MEMORY;

pass2_error:
  for (size_t i = 0; i < pattern_count; i++)
    free(pattern_lines[i]);
  free(pattern_lines);
  return add_err;

pass1_fail:
  if (fp)
    fclose(fp);
  for (size_t i = 0; i < pattern_count; i++)
    free(pattern_lines[i]);
  free(pattern_lines);
  return pass1_error;
}

/* --- DIAGNOSTICS --- */

static size_t policy_memory_usage_unlocked(const st_policy_t *policy) {
  size_t states_alloc = policy->states.capacity * sizeof(policy_state_t);
  size_t patterns_alloc = policy->patterns.capacity * sizeof(pattern_entry_t);
  size_t filter_bytes = 0;
  for (int i = 0; i < FILTER_POS_LEVELS; i++) {
    if (policy->pos_filters[i]) {
      filter_bytes += vacuum_filter_memory_bytes(policy->pos_filters[i]);
    }
  }
  return sizeof(st_policy_t) + filter_bytes + states_alloc +
         policy->children_arena.used + patterns_alloc;
}

static size_t policy_working_set_unlocked(const st_policy_t *policy) {
  size_t states_used = policy->states.count * sizeof(policy_state_t);
  size_t patterns_used = policy->patterns.count * sizeof(pattern_entry_t);
  size_t filter_bytes = 0;
  for (int i = 0; i < FILTER_POS_LEVELS; i++) {
    if (policy->pos_filters[i]) {
      filter_bytes += vacuum_filter_memory_bytes(policy->pos_filters[i]);
    }
  }
  return sizeof(st_policy_t) + filter_bytes + states_used +
         policy->children_count * sizeof(child_entry_t) + patterns_used;
}

size_t st_policy_memory_usage(const st_policy_t *policy) {
  if (!policy)
    return 0;
  pthread_rwlock_rdlock((pthread_rwlock_t *)&policy->rwlock);
  size_t result = policy_memory_usage_unlocked(policy);
  pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
  return result;
}

size_t st_policy_working_set(const st_policy_t *policy) {
  if (!policy)
    return 0;
  pthread_rwlock_rdlock((pthread_rwlock_t *)&policy->rwlock);
  size_t result = policy_working_set_unlocked(policy);
  pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
  return result;
}

size_t st_policy_state_count(const st_policy_t *policy) {
  if (!policy)
    return 0;
  pthread_rwlock_rdlock((pthread_rwlock_t *)&policy->rwlock);
  size_t result = policy->states.count;
  pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
  return result;
}

/* --- STATISTICS --- */

void st_policy_get_stats(const st_policy_t *policy, st_policy_stats_t *stats) {
  if (!policy || !stats)
    return;

  pthread_rwlock_rdlock((pthread_rwlock_t *)&policy->rwlock);

  /* Read atomic counters */
  stats->eval_count = atomic_load(&policy->stats.eval_count);
  stats->filter_reject_count = atomic_load(&policy->stats.filter_reject_count);
  stats->trie_walk_count = atomic_load(&policy->stats.trie_walk_count);
  stats->suggestion_count = atomic_load(&policy->stats.suggestion_count);
  stats->filter_rebuild_count =
      atomic_load(&policy->stats.filter_rebuild_count);
  stats->filter_rebuild_us = atomic_load(&policy->stats.filter_rebuild_us);
  stats->pattern_count = policy->pattern_count;
  stats->state_count = policy->states.count;
  stats->memory_bytes = policy_memory_usage_unlocked(policy);

  pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
}

/* --- DOT GRAPH EXPORT --- */

static bool dot_write_label(FILE *fp, const char *label) {
  if (fputc('"', fp) == EOF)
    return false;
  for (const unsigned char *p = (const unsigned char *)label; *p; p++) {
    if (*p == '"' || *p == '\\') {
      if (fputc('\\', fp) == EOF)
        return false;
    } else if (*p == '\n' || *p == '\r' || *p == '\t') {
      if (fputc('\\', fp) == EOF ||
          fputc(*p == '\n' ? 'n' : (*p == '\r' ? 'r' : 't'), fp) == EOF)
        return false;
      continue;
    } else if (*p < 0x20 || *p == 0x7f) {
      if (fprintf(fp, "\\x%02x", *p) < 0)
        return false;
      continue;
    }
    if (fputc(*p, fp) == EOF)
      return false;
  }
  return fputc('"', fp) != EOF;
}

st_error_t st_policy_dump_dot(const st_policy_t *policy, const char *path) {
  if (!policy || !path)
    return ST_ERR_INVALID;

  pthread_rwlock_rdlock((pthread_rwlock_t *)&policy->rwlock);
  FILE *fp = fopen(path, "w");
  if (!fp) {
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    return ST_ERR_IO;
  }

  if (fprintf(fp, "digraph policy_trie {\n") < 0) {
    fclose(fp);
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    return ST_ERR_IO;
  }
  if (fprintf(fp, "  rankdir=LR;\n") < 0) {
    fclose(fp);
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    return ST_ERR_IO;
  }
  if (fprintf(fp, "  node [shape=circle];\n") < 0) {
    fclose(fp);
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    return ST_ERR_IO;
  }
  if (fprintf(fp, "  edge [];\n") < 0) {
    fclose(fp);
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    return ST_ERR_IO;
  }

  /* BFS to traverse and emit nodes/edges */
  typedef struct {
    uint32_t idx;
    uint32_t node_id;
  } dot_q;
  size_t queue_cap = 256;
  dot_q *queue = malloc(queue_cap * sizeof(*queue));
  if (!queue) {
    fclose(fp);
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    return ST_ERR_MEMORY;
  }
  size_t head = 0, tail = 0;
  uint32_t next_id = 0;

  /* Emit root node */
  if (fprintf(fp, "  n%d [label=", next_id) < 0 ||
      !dot_write_label(fp, "root") ||
      fprintf(fp, "%s];\n",
              policy->states.states[0].pattern_id != UINT16_MAX
                  ? ", style=filled, fillcolor=lightgreen"
                  : "") < 0) {
    free(queue);
    fclose(fp);
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    return ST_ERR_IO;
  }

  queue[tail].idx = 0;
  queue[tail].node_id = next_id++;
  tail++;

  while (head < tail) {
    dot_q entry = queue[head++];
    policy_state_t *node = &policy->states.states[entry.idx];
    uint16_t total = node->literal_count + node->wildcard_count;
    char *arena_base = policy->children_arena.base;
    child_entry_t *children =
        (child_entry_t *)(arena_base + node->children_offset);

    for (uint16_t i = 0; i < total; i++) {
      child_entry_t *c = &children[i];

      /* Emit child node */
      /* Classified command tokens are stored as literal children with text;
       * only plain wildcard children omit text. */
      const char *label = c->text ? c->text : st_type_symbol[c->type];
      policy_state_t *child = &policy->states.states[c->target];
      if (fprintf(fp, "  n%d [label=", next_id) < 0 ||
          !dot_write_label(fp, label) ||
          fprintf(fp, "%s];\n",
                  child->pattern_id != UINT16_MAX
                      ? ", style=filled, fillcolor=lightgreen"
                      : "") < 0) {
        free(queue);
        fclose(fp);
        pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
        return ST_ERR_IO;
      }

      /* Emit edge */
      if (fprintf(fp, "  n%d -> n%d;\n", entry.node_id, next_id) < 0) {
        free(queue);
        fclose(fp);
        pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
        return ST_ERR_IO;
      }

      if (tail == queue_cap) {
        size_t new_cap = queue_cap * 2;
        dot_q *grown = realloc(queue, new_cap * sizeof(*queue));
        if (!grown) {
          free(queue);
          fclose(fp);
          pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
          return ST_ERR_MEMORY;
        }
        queue = grown;
        queue_cap = new_cap;
      }
      queue[tail].idx = c->target;
      queue[tail].node_id = next_id;
      tail++;
      next_id++;
    }
  }

  free(queue);

  if (fprintf(fp, "}\n") < 0) {
    fclose(fp);
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    return ST_ERR_IO;
  }
  st_error_t result = fclose(fp) == 0 ? ST_OK : ST_ERR_IO;
  pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
  return result;
}

/* --- DRY-RUN MODE --- */

st_error_t st_policy_simulate_add_netpattern(st_policy_t *policy,
                                             const char *netpattern,
                                             bool *would_match,
                                             const char **conflicting_pattern) {
  if (would_match)
    *would_match = false;
  if (conflicting_pattern)
    *conflicting_pattern = NULL;
  if (!policy || !netpattern || !would_match)
    return ST_ERR_INVALID;

  st_token_array_t decoded = {0};
  st_error_t decode_error = st_netpattern_decode(netpattern, &decoded);
  if (decode_error != ST_OK)
    return decode_error;
  st_token_t *tokens = decoded.tokens;
  size_t token_count = decoded.count;
  if (token_count == 0 || token_count > ST_MAX_CMD_TOKENS ||
      tokens[0].type == ST_TYPE_ANY) {
    free_pattern_tokens(tokens, token_count);
    return ST_ERR_INVALID;
  }

  pthread_rwlock_rdlock(&policy->rwlock);
  const pattern_entry_t *best = NULL;
  len_bucket_t *bucket = &policy->len_buckets[token_count];
  for (size_t i = 0; i < bucket->count; i++) {
    pattern_entry_t *entry = &policy->patterns.entries[bucket->indices[i]];
    if (!entry->active || !entry->tokens ||
        !pattern_subsumes(entry->tokens, entry->token_count, tokens,
                          token_count))
      continue;
    if (!best || pattern_entry_preferred(entry, best))
      best = entry;
  }
  *would_match = best != NULL;
  if (best && conflicting_pattern)
    *conflicting_pattern = best->pattern;
  pthread_rwlock_unlock(&policy->rwlock);

  free_pattern_tokens(tokens, token_count);
  return ST_OK;
}

/* --- POLICY EXPANSION SUGGESTIONS (Miner — Step 2 only) --- */

static bool is_safe_immediate_cover(st_token_type_t type,
                                    st_token_type_t candidate) {
  if (type == candidate || candidate == ST_TYPE_ANY ||
      !st_is_compatible(type, candidate))
    return false;
  for (int i = ST_TYPE_LITERAL + 1; i < ST_TYPE_COUNT; i++) {
    st_token_type_t intermediate = (st_token_type_t)i;
    if (intermediate != type && intermediate != candidate &&
        st_is_compatible(type, intermediate) &&
        st_is_compatible(intermediate, candidate))
      return false;
  }
  return true;
}

size_t st_policy_suggest_variants(const st_policy_t *policy,
                                  const st_token_t *tokens, size_t token_count,
                                  st_expand_suggestion_t out[3]) {
  if (out)
    memset(out, 0, 3 * sizeof(*out));
  if (!policy || !tokens || !out || token_count == 0 ||
      token_count > ST_MAX_CMD_TOKENS)
    return 0;
  for (size_t i = 0; i < token_count; i++) {
    if (!tokens[i].text || tokens[i].type < ST_TYPE_LITERAL ||
        tokens[i].type >= ST_TYPE_COUNT)
      return 0;
  }

  /* Variant 0: exact match as literal */
  {
    st_token_t *lit_tokens = calloc(token_count, sizeof(st_token_t));
    if (!lit_tokens)
      return 0;
    for (size_t i = 0; i < token_count; i++) {
      lit_tokens[i].text = (char *)tokens[i].text;
      lit_tokens[i].type = ST_TYPE_LITERAL;
    }
    if (!st_build_pattern(out[0].pattern, sizeof(out[0].pattern), lit_tokens,
                          token_count) ||
        st_validate_netpattern(out[0].pattern, NULL) != ST_OK) {
      free(lit_tokens);
      memset(out, 0, 3 * sizeof(*out));
      return 0;
    }
    out[0].based_on = NULL;
    out[0].confidence = 1.0;
    free(lit_tokens);
  }

  /* Variants 1..N: widen one non-literal token at a time */
  size_t n_variants = 1;
  for (size_t i = 0; i < token_count && n_variants < 3; i++) {
    if (tokens[i].type == ST_TYPE_LITERAL)
      continue;

    for (int candidate = ST_TYPE_LITERAL + 1;
         candidate < ST_TYPE_COUNT && n_variants < 3; candidate++) {
      st_token_type_t wider = (st_token_type_t)candidate;
      if (!is_safe_immediate_cover(tokens[i].type, wider))
        continue;

      st_token_t *pat_tokens = calloc(token_count, sizeof(st_token_t));
      if (!pat_tokens) {
        memset(out, 0, 3 * sizeof(*out));
        return 0;
      }
      for (size_t j = 0; j < token_count; j++)
        pat_tokens[j] = tokens[j];
      pat_tokens[i].text = (char *)st_type_symbol[wider];
      pat_tokens[i].type = wider;

      if (!st_build_pattern(out[n_variants].pattern,
                            sizeof(out[n_variants].pattern), pat_tokens,
                            token_count) ||
          st_validate_netpattern(out[n_variants].pattern, NULL) != ST_OK) {
        free(pat_tokens);
        memset(out, 0, 3 * sizeof(*out));
        return 0;
      }
      out[n_variants].based_on = NULL;
      out[n_variants].confidence = 1.0;
      free(pat_tokens);
      n_variants++;
    }
  }

  return n_variants;
}
