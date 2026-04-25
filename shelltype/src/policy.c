#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

/*
 * policy.c - Compact Policy Trie (CPT) with arena allocation.
 *
 * Design:
 * - Fixed-size state headers (16 bytes) in a growable array
 * - All children in a flat arena; each node owns a contiguous region
 * - Children sorted: literals first (binary search), then wildcards (type order)
 * - Wildcard bitmask per node for O(1) compatibility pre-filter
 * - String-interned token text via shared context
 * - Pattern registry: original strings stored once, referenced by ID
 */

#include "shelltype.h"
#include "arena.h"
#include "vacuum_filter.h"
#include "filter_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>

/* ============================================================
 * CRC32 (for serialization integrity check)
 * ============================================================ */

static uint32_t crc32_table[256];
static bool crc32_initialized = false;

static void crc32_init_table(void)
{
    if (crc32_initialized) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_initialized = true;
}

static uint32_t crc32_compute(const void *data, size_t len, uint32_t prev)
{
    crc32_init_table();
    uint32_t c = prev ^ 0xFFFFFFFFu;
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++)
        c = crc32_table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* ============================================================
 * COMPATIBILITY MASK
 * ============================================================ */

#define CHILDREN_ARENA_INIT  4096
#define STATES_INIT          4096
#define PATTERN_REG_INIT     256
#define VERIFY_ALL_RING_CAP  4096
#define MAX_CMD_TOKENS       128
#define FILTER_POS_LEVELS    4   /* Shell commands rarely exceed 4 tokens before diverging */
#define FILTER_POS_CAPACITY  1024
#define LITERAL_THRESHOLD 3     /* 3+ literals at divergence point → generalize to wildcard */

/* ============================================================
 * CHILD ENTRY — 16 bytes, packed
 * ============================================================ */

typedef struct {
    const char   *text;
    uint32_t      target;
    uint8_t       type;
    uint8_t       _pad[3];
} child_entry_t;

/* ============================================================
 * POLICY STATE — 16 bytes, fixed size
 * ============================================================ */

typedef struct {
    uint32_t      children_offset;  /* Offset into policy->children_arena.base */
    uint16_t       literal_count;
    uint16_t       wildcard_count;
    uint16_t       pattern_id;
    uint32_t       wildcard_mask;
    uint16_t       children_alloc;   /* Slots allocated from arena */
} policy_state_t;

/* ============================================================
 * CHILDREN — offset-based access into policy children_arena
 * ============================================================ */

#define CHILDREN_ARENA_SIZE (64 * 1024)  /* 64KB default */

static inline child_entry_t *child_at(const policy_state_t *node,
                                     const char *arena_base, uint16_t idx)
{
    if (!arena_base || idx >= node->literal_count + node->wildcard_count)
        return NULL;
    return (child_entry_t *)(arena_base + node->children_offset) + idx;
}

/* Grow a node's child array within the arena.
 * Allocates a new (larger) block, copies existing entries, updates the offset.
 * The old block remains in the arena as unreachable space; it is reclaimed
 * by st_policy_compact(), which rebuilds the entire trie. This is an acceptable
 * trade-off: child arrays grow rarely (doubling), and compaction is the
 * designated reclamation point. */
static bool children_arena_grow(arena_t *arena, uint32_t *offset,
                                uint16_t *alloc, uint16_t new_slots)
{
    size_t old_bytes = (*alloc) * sizeof(child_entry_t);
    size_t new_bytes = new_slots * sizeof(child_entry_t);
    char *old_base = arena->base + *offset;
    char *new_base = arena_alloc(arena, new_bytes);
    if (!new_base) return false;
    memcpy(new_base, old_base, old_bytes);
    memset(new_base + old_bytes, 0, new_bytes - old_bytes);
    *offset = (uint32_t)(new_base - arena->base);
    *alloc = new_slots;
    return true;
}

/* ============================================================
 * STATES ARRAY
 * ============================================================ */

typedef struct {
    policy_state_t *states;
    size_t          count;
    size_t          capacity;
} states_array_t;

static bool states_array_init(states_array_t *a)
{
    a->capacity = STATES_INIT;
    a->states = calloc(a->capacity, sizeof(policy_state_t));
    if (!a->states) return false;
    a->count = 1;
    a->states[0].children_offset = 0;
    a->states[0].children_alloc = 0;
    a->states[0].pattern_id = UINT16_MAX;
    return true;
}

static void states_array_free(states_array_t *a)
{
    free(a->states);
    a->states = NULL;
}

static uint32_t states_array_alloc(states_array_t *a)
{
    if (a->count >= a->capacity) {
        size_t new_cap = a->capacity * 2;
        policy_state_t *new_states = realloc(a->states, new_cap * sizeof(policy_state_t));
        if (!new_states) return UINT32_MAX;
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

/* ============================================================
 * PATTERN REGISTRY (entry-based with token storage)
 * ============================================================ */

/* Forward declaration — defined after parse_pattern */
static void free_pattern_tokens(st_token_t *tokens, size_t count);

typedef struct {
    const char   *pattern;      /* interned string */
    st_token_t   *tokens;       /* malloc'd parsed tokens (NULL if inactive) */
    size_t        token_count;
    bool          active;
} pattern_entry_t;

typedef struct {
    pattern_entry_t *entries;
    size_t           count;
    size_t           capacity;
} pattern_reg_t;

static bool pattern_reg_init(pattern_reg_t *r)
{
    r->capacity = PATTERN_REG_INIT;
    r->entries = calloc(r->capacity, sizeof(pattern_entry_t));
    if (!r->entries) return false;
    r->count = 0;
    return true;
}

static void pattern_reg_free(pattern_reg_t *r)
{
    if (!r->entries) return;
    for (size_t i = 0; i < r->count; i++) {
        if (r->entries[i].tokens) {
            free_pattern_tokens(r->entries[i].tokens, r->entries[i].token_count);
            r->entries[i].tokens = NULL;
        }
    }
    free(r->entries);
    r->entries = NULL;
}

static bool pattern_reg_grow(pattern_reg_t *r)
{
    size_t new_cap = r->capacity * 2;
    pattern_entry_t *new_entries = realloc(r->entries, new_cap * sizeof(pattern_entry_t));
    if (!new_entries) return false;
    memset(new_entries + r->capacity, 0, (new_cap - r->capacity) * sizeof(pattern_entry_t));
    r->entries = new_entries;
    r->capacity = new_cap;
    return true;
}

static uint16_t pattern_reg_add(pattern_reg_t *r, st_policy_ctx_t *ctx,
                                const char *pattern,
                                st_token_t *tokens, size_t token_count)
{
    if (r->count >= r->capacity) {
        if (!pattern_reg_grow(r)) return UINT16_MAX;
    }
    const char *interned = st_policy_ctx_intern(ctx, pattern);
    if (!interned) return UINT16_MAX;

    /* Deep-copy the tokens array */
    st_token_t *tok_copy = calloc(token_count, sizeof(st_token_t));
    if (!tok_copy) return UINT16_MAX;
    for (size_t i = 0; i < token_count; i++) {
        tok_copy[i].text = strdup(tokens[i].text);
        if (!tok_copy[i].text) {
            for (size_t k = 0; k < i; k++) free(tok_copy[k].text);
            free(tok_copy);
            return UINT16_MAX;
        }
        tok_copy[i].type = tokens[i].type;
    }

    uint16_t id = (uint16_t)r->count;
    r->entries[id].pattern = interned;
    r->entries[id].tokens = tok_copy;
    r->entries[id].token_count = token_count;
    r->entries[id].active = true;
    r->count++;
    return id;
}

static void pattern_reg_deactivate(pattern_reg_t *r, uint16_t id)
{
    if (id >= r->count) return;
    if (r->entries[id].tokens) {
        free_pattern_tokens(r->entries[id].tokens, r->entries[id].token_count);
        r->entries[id].tokens = NULL;
    }
    r->entries[id].active = false;
    r->entries[id].pattern = NULL;
}

/* ============================================================
 * LENGTH BUCKET INDEX
 * ============================================================ */

typedef struct {
    uint16_t *indices;
    size_t    count;
    size_t    capacity;
} len_bucket_t;

static void len_bucket_free(len_bucket_t *b)
{
    free(b->indices);
    b->indices = NULL;
    b->count = 0;
    b->capacity = 0;
}

static bool len_bucket_add(len_bucket_t *b, uint16_t pattern_id)
{
    if (b->count >= b->capacity) {
        size_t new_cap = b->capacity == 0 ? 8 : b->capacity * 2;
        uint16_t *new_indices = realloc(b->indices, new_cap * sizeof(uint16_t));
        if (!new_indices) return false;
        b->indices = new_indices;
        b->capacity = new_cap;
    }
    b->indices[b->count++] = pattern_id;
    return true;
}

static void len_bucket_remove(len_bucket_t *b, uint16_t pattern_id)
{
    for (size_t i = 0; i < b->count; i++) {
        if (b->indices[i] == pattern_id) {
            b->indices[i] = b->indices[b->count - 1];
            b->count--;
            return;
        }
    }
}

/* ============================================================
 * POLICY STRUCTURE
 * ============================================================ */

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
    st_policy_ctx_t   *ctx;
    states_array_t      states;
    pattern_reg_t       patterns;
    _Atomic(uint64_t)  epoch;
    pthread_rwlock_t   rwlock;
    arena_t             children_arena;  /* Dedicated arena for all children arrays */
    vacuum_filter_t    *pos_filters[FILTER_POS_LEVELS];
    uint32_t             pos_wildcard_mask[FILTER_POS_LEVELS];
    uint64_t            pos_built_epoch[FILTER_POS_LEVELS];
    len_bucket_t       *len_buckets;     /* Length-indexed pattern buckets */
    size_t              num_buckets;     /* ST_MAX_CMD_TOKENS + 1 */
    size_t              pattern_count;
    size_t              children_count;
    policy_atomic_stats_t stats;  /* Atomic runtime statistics */
};

/* ============================================================
 * COMPATIBILITY MASK
 * ============================================================ */

static const uint32_t st_compat_mask[ST_TYPE_COUNT] = {
    /* LITERAL */      (1u << ST_TYPE_LITERAL) | (1u << ST_TYPE_ANY),
    /* HEXHASH */      (1u << ST_TYPE_HEXHASH) | (1u << ST_TYPE_NUMBER) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* NUMBER */       (1u << ST_TYPE_NUMBER) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* IPV4 */         (1u << ST_TYPE_IPV4) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* WORD */         (1u << ST_TYPE_WORD) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* QUOTED */       (1u << ST_TYPE_QUOTED) | (1u << ST_TYPE_QUOTED_SPACE) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* QUOTED_SPACE */ (1u << ST_TYPE_QUOTED_SPACE) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* FILENAME */     (1u << ST_TYPE_FILENAME) | (1u << ST_TYPE_REL_PATH) | (1u << ST_TYPE_PATH) | (1u << ST_TYPE_ANY),
    /* REL_PATH */     (1u << ST_TYPE_REL_PATH) | (1u << ST_TYPE_PATH) | (1u << ST_TYPE_ANY),
    /* ABS_PATH */     (1u << ST_TYPE_ABS_PATH) | (1u << ST_TYPE_PATH) | (1u << ST_TYPE_ANY),
    /* PATH */         (1u << ST_TYPE_PATH) | (1u << ST_TYPE_ANY),
    /* URL */          (1u << ST_TYPE_URL) | (1u << ST_TYPE_ANY),
    /* VALUE */        (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* OPT */          (1u << ST_TYPE_OPT) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* UUID */         (1u << ST_TYPE_UUID) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* EMAIL */        (1u << ST_TYPE_EMAIL) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* HOSTNAME */     (1u << ST_TYPE_HOSTNAME) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* PORT */         (1u << ST_TYPE_PORT) | (1u << ST_TYPE_NUMBER) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* SIZE */         (1u << ST_TYPE_SIZE) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* SEMVER */       (1u << ST_TYPE_SEMVER) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* TIMESTAMP */     (1u << ST_TYPE_TIMESTAMP) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* HASH_ALGO */    (1u << ST_TYPE_HASH_ALGO) | (1u << ST_TYPE_WORD) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* ENV_VAR */      (1u << ST_TYPE_ENV_VAR) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* HYPHENATED */    (1u << ST_TYPE_HYPHENATED) | (1u << ST_TYPE_WORD) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* BRANCH */       (1u << ST_TYPE_BRANCH) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* SHA */          (1u << ST_TYPE_SHA) | (1u << ST_TYPE_HEXHASH) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* IMAGE */        (1u << ST_TYPE_IMAGE) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* PKG */          (1u << ST_TYPE_PKG) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* USER */         (1u << ST_TYPE_USER) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* FINGERPRINT */  (1u << ST_TYPE_FINGERPRINT) | (1u << ST_TYPE_VALUE) | (1u << ST_TYPE_ANY),
    /* ANY */          (1u << ST_TYPE_ANY),
};

static inline uint32_t compat_mask(st_token_type_t t)
{
    return st_compat_mask[t];
}

/* ============================================================
 * CHILD ACCESS
 * ============================================================ */

static inline child_entry_t *get_child(const policy_state_t *node,
                                       const char *arena_base, uint16_t idx)
{
    if (!arena_base || idx >= node->literal_count + node->wildcard_count) return NULL;
    return (child_entry_t *)(arena_base + node->children_offset) + idx;
}

/* ============================================================
 * CHILD LOOKUP
 * ============================================================ */

static child_entry_t *find_literal_child(const policy_state_t *node,
                                         const char *arena_base, const char *text)
{
    uint16_t n = node->literal_count;
    if (n == 0 || !arena_base) return NULL;
    assert(n <= node->children_alloc);
    child_entry_t *children = (child_entry_t *)(arena_base + node->children_offset);
    for (uint16_t i = 0; i < n; i++) {
        if (strcmp(text, children[i].text) == 0) return &children[i];
    }
    return NULL;
}

/* ============================================================
 * PARAMETRIZED WILDCARD MATCHING
 *
 * A parametrized wildcard has the form "#path.cfg" or "#size.MiB" where:
 *   - base type is ST_TYPE_PATH (or other path/size types)
 *   - parameter is ".cfg" (extension) or ".MiB" (size suffix)
 *
 * The child entry stores the base type and full symbol text.
 * During matching, we extract the relevant part from the command token
 * and compare it against the wildcard's parameter.
 * ============================================================ */

/* Check if a base type supports parametrization. */
static bool type_supports_param(st_token_type_t t)
{
    return t == ST_TYPE_PATH || t == ST_TYPE_ABS_PATH ||
           t == ST_TYPE_REL_PATH || t == ST_TYPE_FILENAME ||
           t == ST_TYPE_SIZE ||
           t == ST_TYPE_UUID || t == ST_TYPE_SEMVER || t == ST_TYPE_TIMESTAMP ||
           t == ST_TYPE_BRANCH || t == ST_TYPE_SHA ||
           t == ST_TYPE_IMAGE || t == ST_TYPE_PKG ||
           t == ST_TYPE_USER || t == ST_TYPE_FINGERPRINT;
}

/* Extract the parameter from a parametrized wildcard symbol.
 * E.g., "#path.cfg" → ".cfg", "#size.MiB" → ".MiB", "#path" → NULL. */
static const char *wildcard_param(const char *wild_text, st_token_type_t wild_type)
{
    if (!wild_text || !type_supports_param(wild_type)) return NULL;
    const char *sym = st_type_symbol[wild_type];
    size_t sym_len = strlen(sym);
    if (strncmp(wild_text, sym, sym_len) != 0) return NULL;
    if (wild_text[sym_len] == '.' && wild_text[sym_len + 1] != '\0')
        return wild_text + sym_len;  /* includes the dot */
    return NULL;
}

/* Extract the file extension from a path (including dot).
 * "/etc/app.cfg" → ".cfg", "app" → NULL. */
const char *st_path_extension(const char *text)
{
    if (!text) return NULL;
    const char *dot = strrchr(text, '.');
    if (!dot || dot == text) return NULL;
    if (dot[1] == '\0') return NULL;
    if (strchr(dot, '/') != NULL) return NULL;
    return dot;
}

/* Extract the size suffix from a size token.
 * "10MiB" → "MiB", "2G" → "G", "42" → NULL.
 * Returns pointer into the token after the last digit/dot. */
const char *st_size_suffix(const char *text)
{
    if (!text) return NULL;
    const char *p = text;
    /* skip optional negative sign */
    if (*p == '-') p++;
    /* skip digits and dots */
    while (*p && (isdigit((unsigned char)*p) || *p == '.')) p++;
    if (*p == '\0') return NULL;  /* no suffix */
    return p;
}

/* ============================================================
 * PARAMETER VALIDATION
 *
 * Called from parse_pattern() to reject malformed parameters.
 * Returns true if the parameter is valid for the given base type.
 * ============================================================ */

static bool validate_param(st_token_type_t base_type, const char *param)
{
    /* param includes the leading dot: ".cfg", ".MiB" etc. */
    if (!param || param[0] != '.' || param[1] == '\0') return false;
    const char *p = param + 1;  /* skip dot */

    switch (base_type) {
    case ST_TYPE_PATH:
    case ST_TYPE_ABS_PATH:
    case ST_TYPE_REL_PATH:
    case ST_TYPE_FILENAME:
        /* Alphanumeric, dots, and hyphens allowed; no spaces or slashes */
        for (; *p; p++) {
            if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-' && *p != '_')
                return false;
        }
        return true;

    case ST_TYPE_SIZE: {
        /* Must be a known size suffix (case-insensitive) */
        static const char *size_params[] = {
            "K", "M", "G", "T", "Ki", "Mi", "Gi", "Ti",
            "KB", "MB", "GB", "TB", "B", "b", "bytes",
            "KiB", "MiB", "GiB", "TiB"
        };
        for (size_t i = 0; i < sizeof(size_params)/sizeof(size_params[0]); i++) {
            if (strcasecmp(p, size_params[i]) == 0) return true;
        }
        return false;
    }

    case ST_TYPE_UUID:
        return strcasecmp(p, "v4") == 0 || strcasecmp(p, "v5") == 0 ||
               strcmp(p, "4") == 0 || strcmp(p, "5") == 0;

    case ST_TYPE_SEMVER:
        return strcasecmp(p, "major") == 0 || strcasecmp(p, "minor") == 0 ||
               strcasecmp(p, "patch") == 0 || strcmp(p, "*") == 0;

    case ST_TYPE_TIMESTAMP:
        return strcasecmp(p, "date") == 0 || strcasecmp(p, "time") == 0 ||
               strcasecmp(p, "datetime") == 0;

    case ST_TYPE_BRANCH:
        /* Branch prefix: feature, release, hotfix, head, main, etc. */
        for (; *p; p++) {
            if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_')
                return false;
        }
        return true;

    case ST_TYPE_SHA:
        /* SHA length variant: short (7), 40 (SHA-1), 64 (SHA-256) */
        return strcmp(p, "short") == 0 || strcmp(p, "40") == 0 ||
               strcmp(p, "64") == 0;

    case ST_TYPE_IMAGE:
        /* Image name/tag prefix: latest, nginx, ghcr, alpine, etc. */
        for (; *p; p++) {
            if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-' &&
                *p != '_' && *p != '/')
                return false;
        }
        return true;

    case ST_TYPE_PKG:
        /* Package name prefix: react, types, @types, etc. */
        for (; *p; p++) {
            if (!isalnum((unsigned char)*p) && *p != '.' && *p != '-' &&
                *p != '_' && *p != '@' && *p != '/')
                return false;
        }
        return true;

    case ST_TYPE_USER:
        /* Known username or category: root, system, etc. */
        for (; *p; p++) {
            if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_')
                return false;
        }
        return true;

    case ST_TYPE_FINGERPRINT:
        /* Fingerprint type: sha256, md5 */
        return strcasecmp(p, "sha256") == 0 || strcasecmp(p, "md5") == 0;

    default:
        return false;
    }
}

/* ============================================================
 * PARAMETRIZED MATCHING
 * ============================================================ */

/* Check if a command token matches a (possibly parametrized) wildcard child.
 * Returns true for non-parametrized wildcards (text == NULL or no parameter). */
static bool param_matches(const char *cmd_text, st_token_type_t cmd_type,
                          const char *wild_text, st_token_type_t wild_type)
{
    const char *wparam = wildcard_param(wild_text, wild_type);
    if (!wparam) return true;  /* non-parametrized → any match */

    if (wild_type == ST_TYPE_PATH || wild_type == ST_TYPE_ABS_PATH ||
        wild_type == ST_TYPE_REL_PATH || wild_type == ST_TYPE_FILENAME) {
        /* Path types: match by file extension */
        if (cmd_type != ST_TYPE_ABS_PATH && cmd_type != ST_TYPE_REL_PATH &&
            cmd_type != ST_TYPE_FILENAME && cmd_type != ST_TYPE_PATH)
            return false;
        if (!cmd_text) return false;
        const char *cmd_ext = st_path_extension(cmd_text);
        if (!cmd_ext) return false;
        return strcmp(cmd_ext, wparam) == 0;
    }

    if (wild_type == ST_TYPE_SIZE) {
        /* Size type: match by suffix (case-insensitive) */
        if (cmd_type != ST_TYPE_SIZE) return false;
        if (!cmd_text) return false;
        const char *cmd_suf = st_size_suffix(cmd_text);
        if (!cmd_suf) return false;
        /* wparam includes leading dot: ".MiB" — compare after the dot */
        return strcasecmp(cmd_suf, wparam + 1) == 0;
    }

    if (wild_type == ST_TYPE_UUID) {
        /* UUID: match by version digit */
        if (cmd_type != ST_TYPE_UUID) return false;
        if (!cmd_text) return false;
        /* UUID format: xxxxxxxx-xxxx-Vxxx-xxxx-xxxxxxxxxxxx (V at position 14) */
        size_t len = strlen(cmd_text);
        if (len != 36 || cmd_text[8] != '-' || cmd_text[13] != '-' ||
            cmd_text[18] != '-' || cmd_text[23] != '-')
            return false;
        char version = cmd_text[14];
        /* wparam is ".v4" or ".4" — accept both */
        const char *expected = wparam + 1;  /* skip dot */
        if (tolower((unsigned char)expected[0]) == 'v') expected++;
        return version == expected[0] && expected[1] == '\0';
    }

    if (wild_type == ST_TYPE_SEMVER) {
        /* Semver: parameter is informational, matches any semver */
        return cmd_type == ST_TYPE_SEMVER;
    }

    if (wild_type == ST_TYPE_TIMESTAMP) {
        /* Timestamp: match by format */
        if (cmd_type != ST_TYPE_TIMESTAMP) return false;
        if (!cmd_text) return false;
        size_t len = strlen(cmd_text);
        const char *fmt = wparam + 1;  /* skip dot */
        if (strcasecmp(fmt, "date") == 0) {
            /* YYYY-MM-DD: exactly 10 chars, '-' at 4 and 7 */
            return len == 10 && cmd_text[4] == '-' && cmd_text[7] == '-';
        }
        if (strcasecmp(fmt, "time") == 0) {
            /* HH:MM:SS: exactly 8 chars, ':' at 2 and 5 */
            return len == 8 && cmd_text[2] == ':' && cmd_text[5] == ':';
        }
        if (strcasecmp(fmt, "datetime") == 0) {
            /* Combined: at least 19 chars with T or space separator */
            return len >= 19 && (cmd_text[10] == 'T' || cmd_text[10] == ' ');
        }
        return true;  /* unknown format → accept any timestamp */
    }

    if (wild_type == ST_TYPE_BRANCH) {
        /* Branch: parameter is a prefix (e.g., ".feature" matches "feature/login") */
        if (cmd_type != ST_TYPE_BRANCH && cmd_type != ST_TYPE_LITERAL &&
            cmd_type != ST_TYPE_WORD && cmd_type != ST_TYPE_HYPHENATED)
            return false;
        if (!cmd_text) return false;
        const char *prefix = wparam + 1;  /* skip dot */
        size_t prefix_len = strlen(prefix);
        return strncmp(cmd_text, prefix, prefix_len) == 0;
    }

    if (wild_type == ST_TYPE_SHA) {
        /* SHA: parameter is length variant (short/40/64) */
        if (cmd_type != ST_TYPE_SHA && cmd_type != ST_TYPE_HEXHASH)
            return false;
        if (!cmd_text) return false;
        size_t len = strlen(cmd_text);
        const char *variant = wparam + 1;
        if (strcmp(variant, "short") == 0) return len == 7;
        if (strcmp(variant, "40") == 0) return len == 40;
        if (strcmp(variant, "64") == 0) return len == 64;
        return true;
    }

    if (wild_type == ST_TYPE_IMAGE) {
        /* Image: parameter is name/registry prefix */
        if (cmd_type != ST_TYPE_IMAGE && cmd_type != ST_TYPE_LITERAL)
            return false;
        if (!cmd_text) return false;
        const char *prefix = wparam + 1;
        size_t prefix_len = strlen(prefix);
        return strncmp(cmd_text, prefix, prefix_len) == 0;
    }

    if (wild_type == ST_TYPE_PKG) {
        /* Package: parameter is name prefix */
        if (cmd_type != ST_TYPE_PKG && cmd_type != ST_TYPE_LITERAL)
            return false;
        if (!cmd_text) return false;
        const char *prefix = wparam + 1;
        size_t prefix_len = strlen(prefix);
        return strncmp(cmd_text, prefix, prefix_len) == 0;
    }

    if (wild_type == ST_TYPE_USER) {
        /* User: parameter is exact username or "system" for known system accounts */
        if (cmd_type != ST_TYPE_USER && cmd_type != ST_TYPE_LITERAL)
            return false;
        if (!cmd_text) return false;
        const char *name = wparam + 1;
        if (strcasecmp(name, "system") == 0) {
            static const char *sys_users[] = {
                "root", "nobody", "www-data", "daemon", "bin", "sys", "adm",
                "lp", "mail", "news", "uucp", "man", "proxy", "www", "backup",
                "list", "irc", "gnats", "systemd", "_apt", "postgres", "mysql",
                "nginx", "redis", "memcached", "sshd", NULL
            };
            for (const char **u = sys_users; *u; u++) {
                if (strcmp(cmd_text, *u) == 0) return true;
            }
            return false;
        }
        return strcmp(cmd_text, name) == 0;
    }

    if (wild_type == ST_TYPE_FINGERPRINT) {
        /* Fingerprint: parameter is type (sha256/md5) */
        if (cmd_type != ST_TYPE_FINGERPRINT) return false;
        if (!cmd_text) return false;
        const char *fmt = wparam + 1;
        if (strcasecmp(fmt, "sha256") == 0)
            return strncmp(cmd_text, "SHA256:", 7) == 0;
        if (strcasecmp(fmt, "md5") == 0) {
            size_t len = strlen(cmd_text);
            return len == 47 && cmd_text[2] == ':' && cmd_text[5] == ':';
        }
        return true;
    }

    return true;
}

static child_entry_t *find_wildcard_child(const policy_state_t *node,
                                         const char *arena_base,
                                         st_token_type_t type,
                                         const char *cmd_text)
{
    if (node->wildcard_count == 0 || !arena_base) return NULL;
    assert(node->literal_count + node->wildcard_count <= node->children_alloc);
    if (!(node->wildcard_mask & compat_mask(type))) return NULL;

    child_entry_t *children = (child_entry_t *)(arena_base + node->children_offset);
    child_entry_t *base = children + node->literal_count;

    /* First pass: prefer non-parametrized wildcards (more general, covers all cases) */
    for (uint16_t i = 0; i < node->wildcard_count; i++) {
        if (st_is_compatible(type, (st_token_type_t)base[i].type) &&
            !wildcard_param(base[i].text, (st_token_type_t)base[i].type))
            return &base[i];
    }

    /* Second pass: try parametrized wildcards */
    for (uint16_t i = 0; i < node->wildcard_count; i++) {
        if (st_is_compatible(type, (st_token_type_t)base[i].type) &&
            param_matches(cmd_text, type, base[i].text, (st_token_type_t)base[i].type))
            return &base[i];
    }
    return NULL;
}

/* Find an exact wildcard child for pattern insertion or removal.
 * Non-parametrized wildcards: text=NULL stored, matches ANY text search.
 * Parametrized wildcards: full symbol text stored (e.g., "#path.cfg").
 * Uses exact type + text comparison (strcmp), not param_matches.
 * This is the correct lookup for add/remove where we want to find
 * the existing child with the same parametrized parameter (e.g., #size.MiB). */
static child_entry_t *find_exact_wildcard_child(const policy_state_t *node,
                                               const char *arena_base,
                                               st_token_type_t type,
                                               const char *text)
{
    if (node->wildcard_count == 0 || !arena_base) return NULL;
    child_entry_t *children = (child_entry_t *)(arena_base + node->children_offset);
    child_entry_t *base = children + node->literal_count;
    for (uint16_t i = 0; i < node->wildcard_count; i++) {
        if ((st_token_type_t)base[i].type != type) continue;
        const char *existing = base[i].text;
        /* Non-parametrized wildcard (text=NULL stored): matches any text */
        if (existing == NULL) return &base[i];
        /* Parametrized wildcard: exact text match required */
        if (text != NULL && strcmp(text, existing) == 0) return &base[i];
    }
    return NULL;
}

/* ============================================================
 * CHILD INSERTION
 * ============================================================ */

/* Returns: -1 = allocation failure, 0 = success (filter updated), 1 = success (filter needs rebuild) */
static int insert_child(policy_state_t *node, st_policy_t *policy,
                         const char *text, st_token_type_t type, uint32_t target, uint8_t depth)
{
    assert(node->literal_count + node->wildcard_count <= node->children_alloc);
    bool is_literal = (type == ST_TYPE_LITERAL);
    uint16_t total = node->literal_count + node->wildcard_count;
    uint16_t insert_pos;
    char *arena_base = policy->children_arena.base;
    child_entry_t *children = (child_entry_t *)(arena_base + node->children_offset);
    int filter_status = 0;

    if (is_literal) {
        insert_pos = 0;
        for (uint16_t i = 0; i < node->literal_count; i++) {
            if (strcmp(text, children[i].text) < 0) break;
            insert_pos = i + 1;
        }
        /* Check ALL existing literals for duplicate */
        for (uint16_t i = 0; i < node->literal_count; i++) {
            if (children[i].type == ST_TYPE_LITERAL && strcmp(text, children[i].text) == 0) return -1;
        }
    } else {
        insert_pos = node->literal_count;
        for (uint16_t i = node->literal_count; i < total; i++) {
            if (type < children[i].type) break;
            insert_pos = i + 1;
        }
        /* Duplicate check: same base type AND same text (handles parametrized) */
        if (insert_pos < total && children[insert_pos].type == type) {
            bool is_param = text && strchr(text, '.');
            if (!is_param) return -1;  /* non-parametrized: same type = dup */
            /* Parametrized: check if same parameter */
            if (children[insert_pos].text != NULL && text != NULL &&
                strcmp(children[insert_pos].text, text) == 0) return -1;
        }
    }
    assert(insert_pos <= total);

    const char *interned;
    if (is_literal) {
        interned = st_policy_ctx_intern(policy->ctx, text);
    } else {
        /* Store full symbol for parametrized wildcards (e.g., "#path.cfg") */
        interned = (text && strchr(text, '.')) ? st_policy_ctx_intern(policy->ctx, text) : NULL;
    }
    child_entry_t new_child = { .text = interned, .target = target, .type = (uint8_t)type };

    if (total + 1 > node->children_alloc) {
        uint16_t new_alloc = node->children_alloc == 0 ? 4 : node->children_alloc * 2;
        uint16_t old_alloc = node->children_alloc;
        if (!children_arena_grow(&policy->children_arena, &node->children_offset, &node->children_alloc, new_alloc)) {
            return -1;
        }
        policy->children_count += node->children_alloc - old_alloc;
    }

    children = (child_entry_t *)(policy->children_arena.base + node->children_offset);
    memmove(children + insert_pos + 1,
            children + insert_pos,
            (total - insert_pos) * sizeof(child_entry_t));
    children[insert_pos] = new_child;
    policy->children_count++;

    if (is_literal) {
        node->literal_count++;
    } else {
        node->wildcard_count++;
        node->wildcard_mask |= (1u << type);
    }

    if (depth < FILTER_POS_LEVELS) {
        if (type == ST_TYPE_LITERAL) {
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
            policy->pos_wildcard_mask[depth] |= (1u << type);
        }
    }

    return filter_status;
}

/* ============================================================
 * PATTERN PARSING
 * ============================================================ */

/*
 * Validate pattern syntax:
 * - Reject patterns starting with * (too broad at first position)
 *
 * Returns true if valid, false otherwise.
 */
static bool validate_pattern(const char *pattern)
{
    if (!pattern || !pattern[0]) return false;
    
    /* Check first token - reject patterns starting with * (too broad) */
    const char *first = pattern;
    while (*first == ' ') first++;
    if (strncmp(first, "*", 1) == 0 && (first[1] == ' ' || first[1] == '\0')) {
        return false; /* Reject pattern starting with * */
    }
    
    return true;
}

static st_token_t *parse_pattern(const char *pattern, size_t *out_count)
{
    if (!validate_pattern(pattern)) return NULL;
    
    size_t count = 1;
    for (const char *p = pattern; *p; p++) {
        if (*p == ' ') count++;
    }

    char *copy = strdup(pattern);
    if (!copy) return NULL;

    st_token_t *tokens = calloc(count, sizeof(st_token_t));
    if (!tokens) { free(copy); return NULL; }

    size_t ti = 0;
    char *saveptr = NULL;
    char *tok = strtok_r(copy, " ", &saveptr);
    while (tok && ti < count) {
        st_token_type_t type = ST_TYPE_LITERAL;
        bool matched_prefix = false;
        for (int t = 1; t < ST_TYPE_COUNT; t++) {
            const char *sym = st_type_symbol[t];
            size_t sym_len = strlen(sym);
            if (strncmp(tok, sym, sym_len) == 0 && tok[sym_len] == '\0') {
                /* Exact match: e.g., "#path" */
                type = (st_token_type_t)t;
                break;
            }
            if (strncmp(tok, sym, sym_len) == 0 && tok[sym_len] == '.') {
                /* Has a parameter suffix */
                matched_prefix = true;
                if (type_supports_param((st_token_type_t)t) &&
                    validate_param((st_token_type_t)t, tok + sym_len)) {
                    type = (st_token_type_t)t;
                    break;
                }
                /* Invalid param or unsupported type -- keep checking other symbols */
            }
        }
        /* If a wildcard symbol prefix was matched but no valid parametrized
         * type was found, reject the pattern (user intended a parametrized wildcard
         * but provided an invalid parameter). */
        if (matched_prefix && type == ST_TYPE_LITERAL) {
            for (size_t k = 0; k < ti; k++) free(tokens[k].text);
            free(tokens);
            free(copy);
            *out_count = 0;
            return NULL;
        }
        if (type == ST_TYPE_LITERAL) {
            type = st_classify_token(tok);
        }
        tokens[ti].text = strdup(tok);
        if (!tokens[ti].text) {
            for (size_t k = 0; k < ti; k++) free(tokens[k].text);
            free(tokens);
            free(copy);
            *out_count = 0;
            return NULL;
        }
        tokens[ti].type = type;
        ti++;
        tok = strtok_r(NULL, " ", &saveptr);
    }
    *out_count = ti;
    free(copy);
    return tokens;
}

static void free_pattern_tokens(st_token_t *tokens, size_t count)
{
    if (!tokens) return;
    for (size_t i = 0; i < count; i++) free(tokens[i].text);
    free(tokens);
}

/**
 * Check if a token is an explicit wildcard — i.e., the user typed a type
 * symbol like "#path" or "#opt", as opposed to a literal value like "-v"
 * that was merely classified into a wildcard type.
 * Returns true if the token text matches a type symbol or is parametrized.
 */
static bool is_explicit_wildcard(const char *text, st_token_type_t type)
{
    if (type == ST_TYPE_LITERAL) return false;
    if (type == ST_TYPE_ANY) return true;  /* * is always a wildcard */
    const char *sym = st_type_symbol[type];
    size_t sym_len = strlen(sym);
    /* Exact match: "#opt" */
    if (strcmp(text, sym) == 0) return true;
    /* Parametrized: "#path.cfg" */
    if (strncmp(text, sym, sym_len) == 0 && text[sym_len] == '.') return true;
    return false;
}

/**
 * Check if pattern B subsumes pattern A.
 * B subsumes A iff every command accepted by A is also accepted by B.
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
                            const st_token_t *b, size_t b_len)
{
    if (a_len != b_len) return false;

    for (size_t i = 0; i < a_len; i++) {
        bool a_wild = is_explicit_wildcard(a[i].text, a[i].type);
        bool b_wild = is_explicit_wildcard(b[i].text, b[i].type);

        if (!a_wild && !b_wild) {
            /* Both are concrete values: must match exactly */
            if (strcmp(a[i].text, b[i].text) != 0) return false;
        } else if (a_wild && b_wild) {
            /* Both are wildcards: check type compatibility */
            if (!st_is_compatible(a[i].type, b[i].type)) return false;
            /* Parametrized wildcard subsumption check */
            const char *a_param = wildcard_param(a[i].text, a[i].type);
            const char *b_param = wildcard_param(b[i].text, b[i].type);
            if (a_param && b_param) {
                if (strcmp(a_param, b_param) != 0) return false;
            } else if (a_param && !b_param) {
                /* a is parametrized, b is not: b subsumes a (OK) */
            } else if (!a_param && b_param) {
                /* a is not parametrized, b is: b is more specific, cannot subsume a */
                return false;
            }
        } else if (!a_wild && b_wild) {
            /* a is concrete, b is wildcard: b can subsume a if compatible */
            if (!st_is_compatible(a[i].type, b[i].type)) return false;
        } else {
            /* a is wildcard, b is concrete: b cannot subsume a */
            return false;
        }
    }
    return true;
}

/* ============================================================
 * PER-POSITION FILTER REBUILD
 *
 * BFS-walk the trie up to depth FILTER_POS_LEVELS (4).
 * At each depth N, collect all children across all nodes at that depth:
 *   - Literals → insert into pos_filters[N]
 *   - Wildcards → OR into pos_wildcard_mask[N]
 *
 * Called lazily when pos_built_epoch[N] != policy->epoch.
 * ============================================================ */

static void policy_rebuild_filters(st_policy_t *policy)
{
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Count distinct literals at each depth first to size filters correctly */
    size_t depth_literal_count[FILTER_POS_LEVELS] = {0};

    {
        typedef struct { uint32_t idx; uint8_t depth; } bfs_q;
        bfs_q stack_q[128];
        bfs_q *q = stack_q;
        size_t q_cap = 128;
        size_t head = 0, tail = 0;

        q[tail].idx = 0;
        q[tail].depth = 0;
        tail++;

        while (head < tail) {
            bfs_q entry = q[head++];
            if (entry.depth >= FILTER_POS_LEVELS) continue;

            policy_state_t *node = &policy->states.states[entry.idx];
            uint16_t total = node->literal_count + node->wildcard_count;
            child_entry_t *children = (child_entry_t *)(policy->children_arena.base + node->children_offset);

            for (uint16_t i = 0; i < total; i++) {
                child_entry_t *c = &children[i];
                if (c->type == ST_TYPE_LITERAL && c->text)
                    depth_literal_count[entry.depth]++;

                if (tail >= q_cap) {
                    size_t new_cap = q_cap * 2;
                    bfs_q *new_q = realloc(q == stack_q ? NULL : q, new_cap * sizeof(bfs_q));
                    if (!new_q) break;
                    if (q == stack_q) memcpy(new_q, stack_q, sizeof(stack_q));
                    q = new_q;
                    q_cap = new_cap;
                }
                q[tail].idx = c->target;
                q[tail].depth = entry.depth + 1;
                tail++;
            }
        }
        if (q != stack_q) free(q);
    }

    /* Reset or create filters with proper capacity */
    for (int i = 0; i < FILTER_POS_LEVELS; i++) {
        vacuum_filter_destroy(policy->pos_filters[i]);
        policy->pos_filters[i] = NULL;
        policy->pos_wildcard_mask[i] = 0;

        if (depth_literal_count[i] > 0) {
            size_t cap = depth_literal_count[i] + depth_literal_count[i] / 4;
            if (cap < 64) cap = 64;
            policy->pos_filters[i] = vacuum_filter_create(cap, 0, 0, 0);
        }
    }

    /* BFS walk: insert literals into filters, accumulate wildcard masks */
    typedef struct { uint32_t idx; uint8_t depth; } bfs_q;
    bfs_q stack_q[128];
    bfs_q *q = stack_q;
    size_t q_cap = 128;
    size_t head = 0, tail = 0;

    q[tail].idx = 0;
    q[tail].depth = 0;
    tail++;

    while (head < tail) {
        bfs_q entry = q[head++];
        if (entry.depth >= FILTER_POS_LEVELS) continue;

        policy_state_t *node = &policy->states.states[entry.idx];
        uint16_t total = node->literal_count + node->wildcard_count;
        child_entry_t *children = (child_entry_t *)(policy->children_arena.base + node->children_offset);

        for (uint16_t i = 0; i < total; i++) {
            child_entry_t *c = &children[i];
            if (c->type == ST_TYPE_LITERAL && !c->text) continue;

            uint8_t d = entry.depth;

            if (c->type == ST_TYPE_LITERAL) {
                if (policy->pos_filters[d]) {
                    uint64_t h = filter_hash_fnv1a(c->text, strlen(c->text));
                    vacuum_err_t vrc = vacuum_filter_insert(policy->pos_filters[d], h);
                    if (vrc != VACUUM_OK) {
                        /* Filter full — disable for this depth */
                        vacuum_filter_destroy(policy->pos_filters[d]);
                        policy->pos_filters[d] = NULL;
                    }
                }
            } else {
                policy->pos_wildcard_mask[d] |= (1u << c->type);
            }

            if (tail >= q_cap) {
                size_t new_cap = q_cap * 2;
                bfs_q *new_q = realloc(q == stack_q ? NULL : q, new_cap * sizeof(bfs_q));
                if (!new_q) break;
                if (q == stack_q) memcpy(new_q, stack_q, sizeof(stack_q));
                q = new_q;
                q_cap = new_cap;
            }
            q[tail].idx = c->target;
            q[tail].depth = d + 1;
            tail++;
        }
    }

    if (q != stack_q) free(q);

    for (int i = 0; i < FILTER_POS_LEVELS; i++) {
        policy->pos_built_epoch[i] = atomic_load(&policy->epoch);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    uint64_t elapsed_us = (end.tv_sec - start.tv_sec) * 1000000 +
                          (end.tv_nsec - start.tv_nsec) / 1000;

    atomic_fetch_add(&policy->stats.filter_rebuild_count, 1);
    atomic_fetch_add(&policy->stats.filter_rebuild_us, elapsed_us);
}

/* ============================================================
 * PATTERN VALIDATION (public API)
 * ============================================================ */

st_error_t st_validate_pattern(const char *pattern, st_pattern_info_t *info)
{
    if (!pattern || !pattern[0]) return ST_ERR_INVALID;

    size_t token_count = 0;
    st_token_t *tokens = parse_pattern(pattern, &token_count);
    if (!tokens || token_count == 0) {
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

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

st_policy_t *st_policy_new(st_policy_ctx_t *ctx)
{
    if (!ctx) return NULL;

    st_policy_t *policy = calloc(1, sizeof(st_policy_t));
    if (!policy) return NULL;

    if (!states_array_init(&policy->states)) { free(policy); return NULL; }
    if (!pattern_reg_init(&policy->patterns)) {
        states_array_free(&policy->states); free(policy); return NULL;
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
        states_array_free(&policy->states);
        free(policy);
        return NULL;
    }
    if (pthread_rwlock_init(&policy->rwlock, NULL) != 0) {
        arena_free(&policy->children_arena);
        states_array_free(&policy->states);
        free(policy);
        return NULL;
    }
    
    /* Retain context to prevent reset while policy is alive */
    st_policy_ctx_retain(ctx);
    
    return policy;
}

void st_policy_free(st_policy_t *policy)
{
    if (!policy) return;
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

/* ============================================================
 * ADD / REMOVE
 * ============================================================ */

/* Forward declaration */
static st_error_t remove_pattern_by_id_locked(st_policy_t *policy, uint16_t pid);

/* Internal: add pattern assuming write lock is already held.
 *
 * Performs incremental subsumption checks:
 *   1. If the new pattern is subsumed by an existing pattern, it is rejected.
 *   2. If the new pattern subsumes existing patterns, they are removed.
 * Only compares patterns of the same token length.
 */
static st_error_t st_policy_add_locked(st_policy_t *policy, const char *pattern)
{
    if (!policy || !pattern || !pattern[0]) return ST_ERR_INVALID;

    size_t token_count = 0;
    st_token_t *tokens = parse_pattern(pattern, &token_count);
    if (!tokens) return ST_ERR_INVALID;
    if (token_count == 0) { free_pattern_tokens(tokens, token_count); return ST_ERR_INVALID; }
    if (token_count > ST_MAX_CMD_TOKENS) { free_pattern_tokens(tokens, token_count); return ST_ERR_INVALID; }

    /* --- Incremental subsumption check --- */
    len_bucket_t *bucket = &policy->len_buckets[token_count];

    /* Step 1: Check if new pattern is subsumed by an existing pattern */
    for (size_t bi = 0; bi < bucket->count; bi++) {
        uint16_t eid = bucket->indices[bi];
        pattern_entry_t *entry = &policy->patterns.entries[eid];
        if (!entry->active || !entry->tokens) continue;
        /* B subsumes A: every command matching A also matches B.
         * Here A = new pattern, B = existing entry.
         * If existing entry subsumes new, new is redundant. */
        if (pattern_subsumes(tokens, token_count, entry->tokens, entry->token_count)) {
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
        if (!entry->active || !entry->tokens) continue;
        /* A = existing entry, B = new pattern.
         * If new pattern subsumes existing, existing is redundant. */
        if (pattern_subsumes(entry->tokens, entry->token_count, tokens, token_count)) {
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

    /* Remove subsumed patterns */
    for (size_t ri = 0; ri < to_remove_count; ri++) {
        remove_pattern_by_id_locked(policy, to_remove[ri]);
    }
    free(to_remove);

    /* --- Trie insertion (existing logic) --- */
    uint32_t current = 0;
    bool needs_filter_rebuild = false;

    for (size_t i = 0; i < token_count; i++) {
        policy_state_t *node = &policy->states.states[current];
        child_entry_t *existing = NULL;
        char *arena_base = policy->children_arena.base;

        if (tokens[i].type == ST_TYPE_LITERAL) {
            existing = find_literal_child(node, arena_base, tokens[i].text);
        } else {
            existing = find_exact_wildcard_child(node, arena_base, tokens[i].type, tokens[i].text);
        }

        if (existing) {
            current = existing->target;
        } else {
            uint32_t new_state = states_array_alloc(&policy->states);
            if (new_state == UINT32_MAX) {
                free_pattern_tokens(tokens, token_count);
                return ST_ERR_MEMORY;
            }
            int rc = insert_child(node, policy,
                              tokens[i].text, tokens[i].type, new_state, (uint8_t)i);
            if (rc < 0) {
                free_pattern_tokens(tokens, token_count);
                return ST_ERR_MEMORY;
            }
            if (rc == 1) needs_filter_rebuild = true;
            current = new_state;
        }
    }

    policy_state_t *end_node = &policy->states.states[current];
    if (end_node->pattern_id == UINT16_MAX) {
        uint16_t pid = pattern_reg_add(&policy->patterns, policy->ctx,
                                       pattern, tokens, token_count);
        if (pid == UINT16_MAX) {
            free_pattern_tokens(tokens, token_count);
            return ST_ERR_MEMORY;
        }
        end_node->pattern_id = pid;
        policy->pattern_count++;

        /* Add to length bucket */
        if (token_count < policy->num_buckets) {
            len_bucket_add(&policy->len_buckets[token_count], pid);
        }
    }

    if (needs_filter_rebuild) policy->epoch++;
    free_pattern_tokens(tokens, token_count);
    return ST_OK;
}

/* Remove a child entry from a trie node's children array.
 * Shifts subsequent entries to fill the gap. */
static void remove_child_from_node(policy_state_t *node, st_policy_t *policy,
                                   uint16_t child_idx, bool is_literal)
{
    child_entry_t *children = (child_entry_t *)(policy->children_arena.base + node->children_offset);
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
            node->wildcard_mask |= (1u << wild_base[i].type);
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
static st_error_t remove_pattern_by_id_locked(st_policy_t *policy, uint16_t pid)
{
    if (!policy || pid >= policy->patterns.count) return ST_ERR_INVALID;
    pattern_entry_t *entry = &policy->patterns.entries[pid];
    if (!entry->active) return ST_OK;

    /* Track the path through the trie so we can prune dead nodes */
    typedef struct { uint32_t state_idx; uint16_t child_idx; bool is_literal; } path_step_t;
    path_step_t *path = malloc(entry->token_count * sizeof(path_step_t));
    if (!path) return ST_ERR_MEMORY;

    uint32_t current = 0;
    for (size_t i = 0; i < entry->token_count; i++) {
        policy_state_t *node = &policy->states.states[current];
        child_entry_t *child = NULL;
        char *arena_base = policy->children_arena.base;

        path[i].state_idx = current;
        path[i].is_literal = (entry->tokens[i].type == ST_TYPE_LITERAL);

        if (path[i].is_literal) {
            /* Find literal child index */
            uint16_t n = node->literal_count;
            child_entry_t *children = (child_entry_t *)(arena_base + node->children_offset);
            for (uint16_t ci = 0; ci < n; ci++) {
                if (strcmp(entry->tokens[i].text, children[ci].text) == 0) {
                    child = &children[ci];
                    path[i].child_idx = ci;
                    break;
                }
            }
        } else {
            /* Find exact wildcard child index */
            child = find_exact_wildcard_child(node, arena_base,
                                              entry->tokens[i].type, entry->tokens[i].text);
            if (child) {
                uint16_t ci = (uint16_t)(child - (child_entry_t *)(arena_base + node->children_offset));
                path[i].child_idx = ci;
            }
        }

        if (!child) {
            free(path);
            return ST_OK;
        }
        current = child->target;
    }

    /* Unset the pattern_id on the end node */
    policy_state_t *end_node = &policy->states.states[current];
    if (end_node->pattern_id != pid) {
        free(path);
        return ST_OK;
    }
    end_node->pattern_id = UINT16_MAX;

    /* Prune dead nodes from leaf to root.
     * A node can be pruned if it has no children, no pattern_id, and is not the root. */

    /* Simple pruning: remove child entries from the path, starting from the leaf.
     * Only remove if the target state has no children and no pattern_id. */
    for (size_t i = entry->token_count; i > 0; i--) {
        size_t step = i - 1;
        uint32_t state_idx = path[step].state_idx;
        policy_state_t *node = &policy->states.states[state_idx];

        /* Find the child that we followed at this step.
         * Note: child_idx may be stale if earlier steps removed children from this node.
         * Re-find by matching the entry tokens. */
        uint16_t child_idx = UINT16_MAX;
        child_entry_t *children = (child_entry_t *)(policy->children_arena.base + node->children_offset);
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
                    /* For non-parametrized, text in entry->tokens is the symbol (e.g., "#path") */
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

        if (child_idx == UINT16_MAX) break;  /* Already removed or can't find */

        uint32_t target = children[child_idx].target;
        policy_state_t *target_state = &policy->states.states[target];

        /* Only remove the child if the target state is a dead end */
        if (target_state->pattern_id == UINT16_MAX &&
            target_state->literal_count == 0 &&
            target_state->wildcard_count == 0) {
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

    free(path);
    return ST_OK;
}

/* Public: add pattern (acquires write lock) */
st_error_t st_policy_add(st_policy_t *policy, const char *pattern)
{
    if (!policy || !pattern || !pattern[0]) return ST_ERR_INVALID;

    pthread_rwlock_wrlock(&policy->rwlock);
    st_error_t err = st_policy_add_locked(policy, pattern);
    pthread_rwlock_unlock(&policy->rwlock);
    return err;
}

st_error_t st_policy_batch_add(st_policy_t *policy, const char **patterns, size_t count)
{
    if (!policy || !patterns || count == 0) return ST_ERR_INVALID;

    pthread_rwlock_wrlock(&policy->rwlock);

    st_error_t first_err = ST_OK;
    for (size_t i = 0; i < count; i++) {
        st_error_t err = st_policy_add_locked(policy, patterns[i]);
        if (err != ST_OK && first_err == ST_OK) {
            first_err = err;
        }
    }

    if (first_err == ST_OK) {
        policy_rebuild_filters(policy);
    }

    pthread_rwlock_unlock(&policy->rwlock);
    return first_err;
}

st_error_t st_policy_merge(st_policy_t *dst, const st_policy_t *src)
{
    if (!dst || !src) return ST_ERR_INVALID;

    pthread_rwlock_rdlock((pthread_rwlock_t *)&src->rwlock);
    pthread_rwlock_wrlock(&dst->rwlock);

    st_error_t first_err = ST_OK;
    size_t src_count = src->patterns.count;
    for (size_t i = 0; i < src_count; i++) {
        if (!src->patterns.entries[i].active) continue;
        const char *pat = src->patterns.entries[i].pattern;
        if (!pat) continue;
        st_error_t err = st_policy_add_locked(dst, pat);
        if (err != ST_OK && err != ST_ERR_INVALID && first_err == ST_OK) {
            first_err = err;
        }
    }

    pthread_rwlock_unlock(&dst->rwlock);
    pthread_rwlock_unlock((pthread_rwlock_t *)&src->rwlock);
    return first_err;
}

static bool pattern_array_contains_entry(const pattern_entry_t *entries, size_t count, const char *pat)
{
    for (size_t i = 0; i < count; i++) {
        if (entries[i].active && strcmp(entries[i].pattern, pat) == 0) return true;
    }
    return false;
}

st_error_t st_policy_diff(const st_policy_t *a, const st_policy_t *b,
                          st_policy_diff_t *result)
{
    if (!a || !b || !result) return ST_ERR_INVALID;

    memset(result, 0, sizeof(*result));

    pthread_rwlock_rdlock((pthread_rwlock_t *)&a->rwlock);
    pthread_rwlock_rdlock((pthread_rwlock_t *)&b->rwlock);

    size_t a_count = a->patterns.count;
    size_t b_count = b->patterns.count;
    const pattern_entry_t *a_entries = a->patterns.entries;
    const pattern_entry_t *b_entries = b->patterns.entries;

    /* Collect patterns in b that are not in a */
    size_t added_cap = b_count > 0 ? b_count : 1;
    char **added = calloc(added_cap, sizeof(char *));
    if (!added) {
        pthread_rwlock_unlock((pthread_rwlock_t *)&b->rwlock);
        pthread_rwlock_unlock((pthread_rwlock_t *)&a->rwlock);
        return ST_ERR_MEMORY;
    }
    size_t added_count = 0;
    for (size_t i = 0; i < b_count; i++) {
        if (!b_entries[i].active) continue;
        if (!pattern_array_contains_entry(a_entries, a_count, b_entries[i].pattern)) {
            added[added_count++] = strdup(b_entries[i].pattern);
        }
    }

    /* Collect patterns in a that are not in b */
    size_t removed_cap = a_count > 0 ? a_count : 1;
    char **removed = calloc(removed_cap, sizeof(char *));
    if (!removed) {
        for (size_t i = 0; i < added_count; i++) free(added[i]);
        free(added);
        pthread_rwlock_unlock((pthread_rwlock_t *)&b->rwlock);
        pthread_rwlock_unlock((pthread_rwlock_t *)&a->rwlock);
        return ST_ERR_MEMORY;
    }
    size_t removed_count = 0;
    for (size_t i = 0; i < a_count; i++) {
        if (!a_entries[i].active) continue;
        if (!pattern_array_contains_entry(b_entries, b_count, a_entries[i].pattern)) {
            removed[removed_count++] = strdup(a_entries[i].pattern);
        }
    }

    result->added = added;
    result->added_count = added_count;
    result->removed = removed;
    result->removed_count = removed_count;

    pthread_rwlock_unlock((pthread_rwlock_t *)&b->rwlock);
    pthread_rwlock_unlock((pthread_rwlock_t *)&a->rwlock);
    return ST_OK;
}

void st_free_diff_result(st_policy_diff_t *result)
{
    if (!result) return;
    for (size_t i = 0; i < result->added_count; i++) free(result->added[i]);
    for (size_t i = 0; i < result->removed_count; i++) free(result->removed[i]);
    free(result->added);
    free(result->removed);
    result->added = NULL;
    result->removed = NULL;
    result->added_count = 0;
    result->removed_count = 0;
}

/*
 * NOTE: This function performs a logical removal only. Since the policy
 * uses an arena allocator for trie nodes, removed patterns leave their
 * nodes in place. The pattern_id is unset so the node no longer represents
 * an active pattern, but the node itself cannot be freed without a
 * full trie compaction (rebuild from remaining patterns).
 *
 * Over time, with many add/remove cycles, unused nodes may accumulate.
 * If memory pressure becomes an issue, use st_policy_compact() to
 * rebuild the policy from scratch with only active patterns.
 */
st_error_t st_policy_remove(st_policy_t *policy, const char *pattern)
{
    if (!policy || !pattern || !pattern[0]) return ST_ERR_INVALID;

    pthread_rwlock_wrlock(&policy->rwlock);

    size_t token_count = 0;
    st_token_t *tokens = parse_pattern(pattern, &token_count);
    if (!tokens) { pthread_rwlock_unlock(&policy->rwlock); return ST_ERR_MEMORY; }
    if (token_count == 0) { free_pattern_tokens(tokens, token_count); pthread_rwlock_unlock(&policy->rwlock); return ST_ERR_INVALID; }

    uint32_t current = 0;

    for (size_t i = 0; i < token_count; i++) {
        policy_state_t *node = &policy->states.states[current];
        child_entry_t *child = NULL;
        char *arena_base = policy->children_arena.base;
        if (tokens[i].type == ST_TYPE_LITERAL) {
            child = find_literal_child(node, arena_base, tokens[i].text);
        } else {
            child = find_exact_wildcard_child(node, arena_base, tokens[i].type, tokens[i].text);
        }
        if (!child) {
            free_pattern_tokens(tokens, token_count);
            pthread_rwlock_unlock(&policy->rwlock);
            return ST_OK;
        }
        current = child->target;
    }

    policy_state_t *node = &policy->states.states[current];
    if (node->pattern_id == UINT16_MAX) {
        free_pattern_tokens(tokens, token_count);
        pthread_rwlock_unlock(&policy->rwlock);
        return ST_OK;
    }

    uint16_t pid = node->pattern_id;
    node->pattern_id = UINT16_MAX;
    policy->pattern_count--;

    /* Remove from length bucket and deactivate registry entry */
    if (pid < policy->patterns.count) {
        pattern_entry_t *entry = &policy->patterns.entries[pid];
        if (entry->token_count < policy->num_buckets) {
            len_bucket_remove(&policy->len_buckets[entry->token_count], pid);
        }
        pattern_reg_deactivate(&policy->patterns, pid);
    }

    atomic_fetch_add(&policy->epoch, 1);
    free_pattern_tokens(tokens, token_count);
    pthread_rwlock_unlock(&policy->rwlock);
    return ST_OK;
}

/*
 * Compact the policy by rebuilding from active patterns.
 * This reclaims arena memory after many add/remove cycles.
 * The context is reset and all trie nodes are rebuilt.
 *
 * NOTE: This function requires exclusive use of the context (no other policies
 * sharing the same context). If the context is shared, ST_ERR_INVALID is returned.
 */
st_error_t st_policy_compact(st_policy_t *policy)
{
    if (!policy) return ST_ERR_INVALID;

    if (policy->pattern_count == 0) return ST_OK;

    /* Check that context is not shared with other policies */
    if (!st_policy_ctx_is_exclusive(policy->ctx)) {
        return ST_ERR_INVALID;
    }

    pthread_rwlock_wrlock(&policy->rwlock);

    char **active = malloc(policy->pattern_count * sizeof(char *));
    if (!active) { pthread_rwlock_unlock(&policy->rwlock); return ST_ERR_MEMORY; }

    size_t n_active = 0;
    for (size_t i = 0; i < policy->patterns.count; i++) {
        if (policy->patterns.entries[i].active) {
            active[n_active++] = strdup(policy->patterns.entries[i].pattern);
        }
    }

    if (n_active == 0) {
        free(active);
        pthread_rwlock_unlock(&policy->rwlock);
        return ST_OK;
    }

    /* No batch subsumption needed — incremental on add handles it */

    /* FULLY tear down policy trie BEFORE resetting context */
    for (int i = 0; i < FILTER_POS_LEVELS; i++) {
        vacuum_filter_destroy(policy->pos_filters[i]);
        policy->pos_filters[i] = NULL;
        policy->pos_wildcard_mask[i] = 0;
        policy->pos_built_epoch[i] = 0;
    }
    free(policy->states.states);
    states_array_init(&policy->states);
    pattern_reg_free(&policy->patterns);
    pattern_reg_init(&policy->patterns);
    /* Clear length buckets */
    for (size_t i = 0; i < policy->num_buckets; i++)
        len_bucket_free(&policy->len_buckets[i]);
    arena_free(&policy->children_arena);
    arena_init(&policy->children_arena, CHILDREN_ARENA_SIZE);
    policy->pattern_count = 0;
    policy->children_count = 0;

    /* Release context reference so reset can proceed */
    st_policy_ctx_release(policy->ctx);

    /* Reset context */
    st_error_t reset_err = st_policy_ctx_reset(policy->ctx);
    if (reset_err != ST_OK) {
        st_policy_ctx_retain(policy->ctx);
        for (size_t j = 0; j < n_active; j++) free(active[j]);
        free(active);
        pthread_rwlock_unlock(&policy->rwlock);
        return reset_err;
    }

    /* Re-acquire reference for policy */
    st_policy_ctx_retain(policy->ctx);

    /* Rebuild trie with collected patterns */
    atomic_fetch_add(&policy->epoch, 1);

    for (size_t i = 0; i < n_active; i++) {
        st_error_t err = st_policy_add_locked(policy, active[i]);
        if (err != ST_OK) {
            for (size_t j = 0; j < n_active; j++) free(active[j]);
            free(active);
            pthread_rwlock_unlock(&policy->rwlock);
            return err;
        }
        free(active[i]);
    }
    free(active);
    pthread_rwlock_unlock(&policy->rwlock);
    return ST_OK;
}

st_error_t st_policy_clear(st_policy_t *policy)
{
    if (!policy) return ST_ERR_INVALID;

    pthread_rwlock_wrlock(&policy->rwlock);

    /* Clear filters */
    for (int i = 0; i < FILTER_POS_LEVELS; i++) {
        vacuum_filter_destroy(policy->pos_filters[i]);
        policy->pos_filters[i] = NULL;
        policy->pos_wildcard_mask[i] = 0;
        policy->pos_built_epoch[i] = 0;
    }

    /* Clear states and children arena */
    free(policy->states.states);
    states_array_init(&policy->states);
    arena_free(&policy->children_arena);
    arena_init(&policy->children_arena, CHILDREN_ARENA_SIZE);

    /* Clear pattern registry */
    pattern_reg_free(&policy->patterns);
    pattern_reg_init(&policy->patterns);

    /* Clear length buckets */
    for (size_t i = 0; i < policy->num_buckets; i++)
        len_bucket_free(&policy->len_buckets[i]);

    policy->pattern_count = 0;
    policy->children_count = 0;
    atomic_fetch_add(&policy->epoch, 1);

    pthread_rwlock_unlock(&policy->rwlock);
    return ST_OK;
}

size_t st_policy_count(const st_policy_t *policy)
{
    if (!policy) return 0;
    return policy->pattern_count;
}

/* ============================================================
 * VERIFICATION + SUGGESTIONS (unified)
 * ============================================================ */

/* Select the display text for a token: use the original text for
 * parametrized wildcards (e.g., "#path.cfg"), otherwise use the
 * type symbol for plain wildcards. */
static const char *token_display_text(const st_token_t *tok)
{
    if (tok->type == ST_TYPE_LITERAL)
        return tok->text;
    /* If text contains a parameter (e.g., "#path.cfg"), use it */
    if (tok->text && strchr(tok->text, '.') && type_supports_param(tok->type))
        return tok->text;
    return st_type_symbol[tok->type];
}

/* Build a pattern string from typed tokens into a fixed-size buffer. */
static bool st_build_pattern(char *buf, size_t buf_size,
                                 const st_token_t *tokens, size_t count)
{
    size_t total_len = 0;
    for (size_t i = 0; i < count; i++) {
        const char *part = token_display_text(&tokens[i]);
        total_len += strlen(part) + (i > 0 ? 1 : 0);
    }
    if (total_len + 1 > buf_size) return false;

    char *p = buf;
    for (size_t i = 0; i < count; i++) {
        if (i > 0) *p++ = ' ';
        const char *part = token_display_text(&tokens[i]);
        size_t len = strlen(part);
        memcpy(p, part, len);
        p += len;
    }
    *p = '\0';
    return true;
}

/* Collect the pattern string at the deepest accepting state reachable
 * from state_idx (checks state itself, then one BFS level). */
static const char *st_find_based_on(const st_policy_t *policy, uint32_t state_idx)
{
    policy_state_t *state = &policy->states.states[state_idx];
    if (state->pattern_id != UINT16_MAX && state->pattern_id < policy->patterns.count)
        return policy->patterns.entries[state->pattern_id].pattern;

    uint16_t total = state->literal_count + state->wildcard_count;
    child_entry_t *children = (child_entry_t *)(policy->children_arena.base + state->children_offset);
    for (uint16_t i = 0; i < total; i++) {
        child_entry_t *c = &children[i];
        policy_state_t *child = &policy->states.states[c->target];
        if (child->pattern_id != UINT16_MAX && child->pattern_id < policy->patterns.count)
            return policy->patterns.entries[child->pattern_id].pattern;
    }
    return NULL;
}

st_error_t st_policy_eval(st_policy_t *policy,
                             const char *raw_cmd,
                             st_eval_result_t *result)
{
    if (!policy || !raw_cmd) return ST_ERR_INVALID;

    pthread_rwlock_rdlock(&policy->rwlock);

    /* Track statistics (atomic increment for thread safety) */
    atomic_fetch_add(&policy->stats.eval_count, 1);

    if (result) {
        result->matches = false;
        result->matching_pattern = NULL;
        result->suggestion_count = 0;
    }

    st_token_array_t cmd;
    cmd.tokens = NULL;
    cmd.count = 0;
    st_error_t err = st_normalize_typed(raw_cmd, &cmd);
    if (err != ST_OK) { pthread_rwlock_unlock(&policy->rwlock); return err; }

    if (cmd.count == 0 || cmd.count > MAX_CMD_TOKENS) {
        st_free_token_array(&cmd);
        pthread_rwlock_unlock(&policy->rwlock);
        if (result) result->matches = false;
        return ST_OK;
    }

    /* ============================================================
     * PER-POSITION FILTER PRE-CHECK
     *
     * Runs before the trie walk. Rejects definite no-matches early.
     * Runs in ALL modes (verify-only and suggest).
     * Epoch comparison drives lazy rebuild — no spin-wait needed.
     *
     * NOTE: First evaluation after many additions may be slower due to
     * lazy filter rebuild. This is expected behavior.
     * ============================================================ */
    bool filter_rejected = false;
    size_t check_len = cmd.count < FILTER_POS_LEVELS ? cmd.count : FILTER_POS_LEVELS;

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
        st_token_type_t ctype = cmd.tokens[i].type;
        if (ctype == ST_TYPE_LITERAL) {
            /* Only skip filter if wildcard mask includes a type compatible with LITERAL.
             * Previously we skipped whenever ANY wildcard existed, which was too broad
             * and defeated the filter for unrelated wildcards (e.g., NUMBER wildcard
             * at a depth where we're checking a LITERAL token). */
            if (policy->pos_wildcard_mask[i] != 0 &&
                (policy->pos_wildcard_mask[i] & compat_mask(ctype)) != 0) continue;
            if (!policy->pos_filters[i] || policy->pos_filters[i]->count == 0) continue;
            uint64_t h = filter_hash_fnv1a(cmd.tokens[i].text, strlen(cmd.tokens[i].text));
            if (!vacuum_filter_lookup(policy->pos_filters[i], h)) {
                filter_rejected = true;
                break;
            }
        } else {
            if ((policy->pos_wildcard_mask[i] & compat_mask(ctype)) == 0) {
                if (!policy->pos_filters[i] || policy->pos_filters[i]->count == 0) {
                    filter_rejected = true;
                    break;
                }
            }
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

    /* ============================================================
     * TRIE WALK
     *
     * Still needed even when filter rejected — we need match_depth
     * and match_state to produce useful suggestions.
     * ============================================================ */
    uint32_t current = 0;
    size_t match_depth = 0;
    uint32_t match_state = 0;

    for (size_t i = 0; i < cmd.count; i++) {
        assert(current < policy->states.count);
        st_token_type_t ctype = cmd.tokens[i].type;
        const char *ctext = cmd.tokens[i].text;
        policy_state_t *node = &policy->states.states[current];
        child_entry_t *found = NULL;
        char *arena_base = policy->children_arena.base;

        if (ctype == ST_TYPE_LITERAL)
            found = find_literal_child(node, arena_base, ctext);

        if (!found) {
            uint32_t compat = compat_mask(ctype) & node->wildcard_mask;
            if (compat)
                found = find_wildcard_child(node, arena_base, ctype, ctext);
        }

        if (!found) break;

        current = found->target;
        match_depth = i + 1;
        match_state = current;
    }
    assert(match_depth <= cmd.count);

    policy_state_t *end_node = &policy->states.states[current];
    if (match_depth == cmd.count &&
        end_node->pattern_id != UINT16_MAX &&
        end_node->pattern_id < policy->patterns.count) {
        st_free_token_array(&cmd);
        if (result) {
            result->matches = true;
            result->matching_pattern = policy->patterns.entries[end_node->pattern_id].pattern;
        }
        pthread_rwlock_unlock(&policy->rwlock);
        return ST_OK;
    }

    /* Verify-only: no match, no suggestions needed */
    if (!result) {
        st_free_token_array(&cmd);
        pthread_rwlock_unlock(&policy->rwlock);
        return ST_OK;
    }

    /* ============================================================
     * SUGGESTION GENERATION
     *
     * Uses existing cmd.tokens — no re-normalize, no trie re-walk.
     * ============================================================ */
    double confidence = (double)match_depth / (double)cmd.count;
    const char *based_on = st_find_based_on(policy, match_state);

    /* Suggestion A: minimal extension (matched prefix as-is + remaining as literals) */
    {
        st_token_t *pat_tokens = malloc(cmd.count * sizeof(st_token_t));
        if (!pat_tokens) { st_free_token_array(&cmd); pthread_rwlock_unlock(&policy->rwlock); return ST_ERR_MEMORY; }

        for (size_t i = 0; i < match_depth; i++) {
            pat_tokens[i].text = (char *)cmd.tokens[i].text;
            pat_tokens[i].type = cmd.tokens[i].type;
        }
        for (size_t i = match_depth; i < cmd.count; i++) {
            pat_tokens[i].text = (char *)cmd.tokens[i].text;
            pat_tokens[i].type = ST_TYPE_LITERAL;
        }

        if (!st_build_pattern(result->suggestions[0].pattern,
                            sizeof(result->suggestions[0].pattern),
                            pat_tokens, cmd.count)) {
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
        policy_state_t *div_node = &policy->states.states[match_state];

        uint32_t wm = div_node->wildcard_mask;
        if (wm != 0 && (compat_mask(div_type) & wm) != 0) {
            /* Wildcard widening: find narrowest compatible wildcard */
            st_token_type_t best_wild = ST_TYPE_ANY;
            uint32_t compat = compat_mask(div_type) & wm;
            while (compat) {
                int t = __builtin_ctz(compat);
                compat &= ~(1u << t);
                st_token_type_t wt = (st_token_type_t)t;
                st_token_type_t joined = st_join(wt, div_type);
                if (best_wild == ST_TYPE_ANY || st_is_compatible(joined, best_wild))
                    best_wild = joined;
            }

            if (best_wild != ST_TYPE_ANY) {
                size_t pat_len = match_depth + 1;
                st_token_t *pat_tokens = malloc(pat_len * sizeof(st_token_t));
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

        /* Literal-to-wildcard fallback (independent of wildcard widening) */
        if (n_suggestions < 2 && wm == 0 && div_node->literal_count >= LITERAL_THRESHOLD) {
            /* Literal-to-wildcard: classify all existing literals + input token */
            st_token_type_t joined = ST_TYPE_LITERAL;
            uint16_t total = div_node->literal_count;
            child_entry_t *children = (child_entry_t *)(policy->children_arena.base + div_node->children_offset);
            for (uint16_t i = 0; i < total; i++) {
                child_entry_t *c = &children[i];
                if (c->type != ST_TYPE_LITERAL) continue;
                st_token_type_t ct = st_classify_token(c->text);
                if (joined == ST_TYPE_LITERAL) joined = ct;
                else joined = st_join(joined, ct);
            }
            joined = st_join(joined, div_type);

            /* Security: cap generalization at #w to prevent over-broad suggestions.
             * Jumping directly to * matches ANY token which is too permissive.
             * #w (#word) is broad but still restricts to identifier-like tokens. */
            if (joined == ST_TYPE_ANY) joined = ST_TYPE_WORD;

            if (joined != ST_TYPE_LITERAL) {
                size_t pat_len = cmd.count;
                st_token_t *pat_tokens = malloc(pat_len * sizeof(st_token_t));
                if (pat_tokens) {
                    for (size_t i = 0; i < match_depth; i++) {
                        pat_tokens[i].text = (char *)cmd.tokens[i].text;
                        pat_tokens[i].type = cmd.tokens[i].type;
                    }
                    pat_tokens[match_depth].text = (char *)st_type_symbol[joined];
                    pat_tokens[match_depth].type = joined;
                    for (size_t i = match_depth + 1; i < cmd.count; i++) {
                        pat_tokens[i].text = (char *)cmd.tokens[i].text;
                        pat_tokens[i].type = cmd.tokens[i].type;
                    }

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

                    /* Refinement: if all literal children share a common extension
                     * (paths) or suffix (sizes), suggest the parametrized wildcard
                     * instead of the generic one. */
                    if (n_suggestions == 2 && type_supports_param(joined)) {
                        const char *common_param = NULL;
                        bool all_match = true;
                        uint16_t n_literals = 0;

                        for (uint16_t i = 0; i < total && all_match; i++) {
                            child_entry_t *c = &children[i];
                            if (c->type != ST_TYPE_LITERAL) continue;
                            n_literals++;

                            const char *ext = NULL;
                            if (joined == ST_TYPE_PATH || joined == ST_TYPE_ABS_PATH ||
                                joined == ST_TYPE_REL_PATH || joined == ST_TYPE_FILENAME) {
                                ext = st_path_extension(c->text);
                            } else if (joined == ST_TYPE_SIZE) {
                                const char *suf = st_size_suffix(c->text);
                                if (suf) {
                                    char sufbuf[32];
                                    size_t slen = strlen(suf);
                                    if (slen + 1 < sizeof(sufbuf)) {
                                        sufbuf[0] = '.';
                                        memcpy(sufbuf + 1, suf, slen + 1);
                                        ext = sufbuf;
                                    }
                                }
                            }

                            if (!ext) { all_match = false; break; }
                            if (!common_param) common_param = ext;
                            else if (strcmp(ext, common_param) != 0) { all_match = false; break; }
                        }

                        /* Also check the divergent command token */
                        if (all_match && common_param && n_literals >= LITERAL_THRESHOLD) {
                            const char *cmd_ext = NULL;
                            if (joined == ST_TYPE_PATH || joined == ST_TYPE_ABS_PATH ||
                                joined == ST_TYPE_REL_PATH || joined == ST_TYPE_FILENAME) {
                                cmd_ext = st_path_extension(cmd.tokens[match_depth].text);
                            } else if (joined == ST_TYPE_SIZE) {
                                const char *suf = st_size_suffix(cmd.tokens[match_depth].text);
                                if (suf) {
                                    static char csufbuf[32];
                                    size_t slen = strlen(suf);
                                    if (slen + 1 < sizeof(csufbuf)) {
                                        csufbuf[0] = '.';
                                        memcpy(csufbuf + 1, suf, slen + 1);
                                        cmd_ext = csufbuf;
                                    }
                                }
                            }
                            if (!cmd_ext || strcmp(cmd_ext, common_param) != 0)
                                all_match = false;
                        }

                        if (all_match && common_param && n_literals >= LITERAL_THRESHOLD) {
                            /* Build parametrized wildcard symbol */
                            char param_sym[64];
                            snprintf(param_sym, sizeof(param_sym), "%s%s",
                                     st_type_symbol[joined], common_param);

                            size_t pat_len2 = cmd.count;
                            st_token_t *pat_tokens2 = malloc(pat_len2 * sizeof(st_token_t));
                            if (pat_tokens2) {
                                for (size_t i = 0; i < match_depth; i++) {
                                    pat_tokens2[i].text = (char *)cmd.tokens[i].text;
                                    pat_tokens2[i].type = cmd.tokens[i].type;
                                }
                                pat_tokens2[match_depth].text = param_sym;
                                pat_tokens2[match_depth].type = joined;
                                for (size_t i = match_depth + 1; i < cmd.count; i++) {
                                    pat_tokens2[i].text = (char *)cmd.tokens[i].text;
                                    pat_tokens2[i].type = cmd.tokens[i].type;
                                }
                                st_build_pattern(result->suggestions[1].pattern,
                                                sizeof(result->suggestions[1].pattern),
                                                pat_tokens2, pat_len2);
                                free(pat_tokens2);
                            }
                        }
                    }
                }
            }
        }
    }

    if (n_suggestions < 2) {
        if (!st_build_pattern(result->suggestions[1].pattern,
                            sizeof(result->suggestions[1].pattern),
                            cmd.tokens, cmd.count)) {
            st_free_token_array(&cmd);
            result->error = ST_ERR_FAILED;
            pthread_rwlock_unlock(&policy->rwlock);
            return ST_OK;
        }
        result->suggestions[1].based_on = NULL;
        result->suggestions[1].confidence = confidence;
        n_suggestions = 2;
    }

    result->suggestion_count = n_suggestions;
    atomic_fetch_add(&policy->stats.suggestion_count, (uint64_t)n_suggestions);
    st_free_token_array(&cmd);
    pthread_rwlock_unlock(&policy->rwlock);
    return ST_OK;
}

/* ============================================================
 * VERIFY ALL
 * ============================================================ */

typedef struct {
    uint32_t state_idx;
    uint8_t  token_idx;
} bfs_entry_t;

st_error_t st_policy_verify_all(const st_policy_t *policy,
                                  const char *raw_cmd,
                                  const char ***matching_patterns,
                                  size_t *match_count)
{
    if (!policy || !raw_cmd || !matching_patterns || !match_count) return ST_ERR_INVALID;
    *matching_patterns = NULL;
    *match_count = 0;

    st_token_array_t cmd;
    cmd.tokens = NULL;
    cmd.count = 0;
    st_error_t err = st_normalize_typed(raw_cmd, &cmd);
    if (err != ST_OK) return err;

    if (cmd.count == 0 || cmd.count > MAX_CMD_TOKENS) {
        st_free_token_array(&cmd);
        return ST_OK;
    }

    const char **matches = NULL;
    size_t match_cap = 0;
    size_t match_n = 0;

    bfs_entry_t ring[VERIFY_ALL_RING_CAP];
    size_t head = 0, tail = 0;

    ring[tail].state_idx = 0;
    ring[tail].token_idx = 0;
    tail = (tail + 1) % VERIFY_ALL_RING_CAP;

    while (head != tail) {
        bfs_entry_t entry = ring[head];
        head = (head + 1) % VERIFY_ALL_RING_CAP;

        policy_state_t *state = &policy->states.states[entry.state_idx];

        if (entry.token_idx == cmd.count) {
            if (state->pattern_id != UINT16_MAX && state->pattern_id < policy->patterns.count) {
                if (match_n >= match_cap) {
                    size_t new_cap = match_cap == 0 ? 8 : match_cap * 2;
                    const char **new_matches = realloc(matches, new_cap * sizeof(const char *));
                    if (!new_matches) {
                        free(matches);
                        st_free_token_array(&cmd);
                        return ST_ERR_MEMORY;
                    }
                    matches = new_matches;
                    match_cap = new_cap;
                }
                matches[match_n++] = policy->patterns.entries[state->pattern_id].pattern;
            }
            continue;
        }

        st_token_type_t ctype = cmd.tokens[entry.token_idx].type;
        const char *ctext = cmd.tokens[entry.token_idx].text;
        char *arena_base = policy->children_arena.base;

        if (ctype == ST_TYPE_LITERAL) {
            child_entry_t *c = find_literal_child(state, arena_base, ctext);
            if (c) {
                size_t next_tail = (tail + 1) % VERIFY_ALL_RING_CAP;
                if (next_tail == head) {
                    free(matches);
                    st_free_token_array(&cmd);
                    return ST_ERR_MEMORY;
                }
                ring[tail].state_idx = c->target;
                ring[tail].token_idx = entry.token_idx + 1;
                tail = next_tail;
            }
        }

        uint32_t compat = compat_mask(ctype) & state->wildcard_mask;
        while (compat) {
            int t = __builtin_ctz(compat);
            compat &= ~(1u << t);
            child_entry_t *c = find_wildcard_child(state, arena_base, (st_token_type_t)t, ctext);
            if (c) {
                size_t next_tail = (tail + 1) % VERIFY_ALL_RING_CAP;
                if (next_tail == head) {
                    free(matches);
                    st_free_token_array(&cmd);
                    return ST_ERR_MEMORY;
                }
                ring[tail].state_idx = c->target;
                ring[tail].token_idx = entry.token_idx + 1;
                tail = next_tail;
            }
        }
    }

    st_free_token_array(&cmd);

    *matching_patterns = matches;
    *match_count = match_n;
    return ST_OK;
}

void st_policy_free_matches(const char **matches, size_t count)
{
    (void)count;
    free((void *)matches);
}


/* ============================================================
 * NFA RENDERING
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
 * ============================================================ */

#define VSYM_BYTE_ANY 256
#define VSYM_EPS      257
#define VSYM_EOS      258
#define VSYM_SPACE    259
#define VSYM_TAB      260

typedef struct {
    int symbol;
    uint32_t target;
} nfa_trans_t;

typedef struct {
    bool is_accepting;
    uint8_t category_mask;
    uint16_t pattern_id;
    const char *tag;
    nfa_trans_t *trans;
    uint32_t trans_count;
    uint32_t trans_cap;
} nfa_state_t;

typedef struct {
    nfa_state_t *states;
    uint32_t state_count;
    uint32_t state_cap;
    uint16_t pattern_id_counter;
    uint8_t  category_mask;
    bool     include_tags;
    const char *identifier;
} nfa_ctx_t;

static nfa_ctx_t *nfa_ctx_new(uint8_t cat_mask, bool tags, const char *ident, uint16_t pid_base)
{
    nfa_ctx_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->state_cap = 256;
    c->states = calloc(c->state_cap, sizeof(nfa_state_t));
    if (!c->states) { free(c); return NULL; }
    c->category_mask = cat_mask;
    c->include_tags = tags;
    c->identifier = ident ? ident : "rbox policy";
    c->pattern_id_counter = pid_base;
    return c;
}

static void nfa_ctx_free(nfa_ctx_t *c)
{
    if (!c) return;
    for (uint32_t i = 0; i < c->state_count; i++) free(c->states[i].trans);
    free(c->states);
    free(c);
}

static uint32_t nfa_new_state(nfa_ctx_t *c)
{
    if (c->state_count >= c->state_cap) {
        uint32_t nc = c->state_cap * 2;
        nfa_state_t *ns = realloc(c->states, nc * sizeof(nfa_state_t));
        if (!ns) return UINT32_MAX;
        c->states = ns;
        c->state_cap = nc;
    }
    uint32_t id = c->state_count++;
    memset(&c->states[id], 0, sizeof(nfa_state_t));
    return id;
}

static bool nfa_add_trans(nfa_ctx_t *c, uint32_t from, int sym, uint32_t to)
{
    nfa_state_t *s = &c->states[from];
    if (s->trans_count >= s->trans_cap) {
        uint32_t nc = s->trans_cap ? s->trans_cap * 2 : 4;
        nfa_trans_t *nt = realloc(s->trans, nc * sizeof(nfa_trans_t));
        if (!nt) return false;
        s->trans = nt;
        s->trans_cap = nc;
    }
    s->trans[s->trans_count].symbol = sym;
    s->trans[s->trans_count].target = to;
    s->trans_count++;
    return true;
}

/* Pass 1: assign NFA state IDs and collect per-state transitions */
static bool nfa_build(nfa_ctx_t *c, st_policy_t *policy,
                      uint32_t trie_idx, uint32_t nfa_state,
                      bool need_space, uint32_t *trie_map)
{
    policy_state_t *node = &policy->states.states[trie_idx];
    uint16_t total = node->literal_count + node->wildcard_count;
    child_entry_t *children = (child_entry_t *)(policy->children_arena.base + node->children_offset);
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
                if (sp == UINT32_MAX) return false;
                if (!nfa_add_trans(c, from, VSYM_SPACE, sp)) return false;
                from = sp;
            }
            for (const char *p = ch->text; *p; p++) {
                uint32_t next;
                if (*(p + 1) == '\0') {
                    /* Last char: link to the trie child's NFA state */
                    if (trie_map[ch->target] == UINT32_MAX) {
                        uint32_t ns = nfa_new_state(c);
                        if (ns == UINT32_MAX) return false;
                        trie_map[ch->target] = ns;
                    }
                    next = trie_map[ch->target];
                } else {
                    next = nfa_new_state(c);
                    if (next == UINT32_MAX) return false;
                }
                if (!nfa_add_trans(c, from, (unsigned char)*p, next)) return false;
                from = next;
            }
        } else {
            /* Wildcard: VSYM_BYTE_ANY (matches any single token) */
            uint32_t from = nfa_state;
            if (need_space) {
                uint32_t sp = nfa_new_state(c);
                if (sp == UINT32_MAX) return false;
                if (!nfa_add_trans(c, from, VSYM_SPACE, sp)) return false;
                from = sp;
            }
            if (trie_map[ch->target] == UINT32_MAX) {
                uint32_t ns = nfa_new_state(c);
                if (ns == UINT32_MAX) return false;
                trie_map[ch->target] = ns;
            }
            if (!nfa_add_trans(c, from, VSYM_BYTE_ANY, trie_map[ch->target])) return false;
        }
    }

    /* Recurse into children */
    for (uint16_t i = 0; i < total; i++) {
        child_entry_t *ch = &children[i];
        if (trie_map[ch->target] == UINT32_MAX) continue;
        if (!nfa_build(c, policy, ch->target, trie_map[ch->target], true, trie_map))
            return false;
    }
    return true;
}

/* Pass 2: write the NFA-DSL file */
static bool nfa_write(nfa_ctx_t *c, FILE *fp)
{
    if (fprintf(fp, "NFA_ALPHABET\n") < 0) return false;
    if (fprintf(fp, "Identifier: %s\n", c->identifier) < 0) return false;
    if (fprintf(fp, "AlphabetSize: 261\n") < 0) return false;
    if (fprintf(fp, "States: %u\n", c->state_count) < 0) return false;
    if (fprintf(fp, "Initial: 0\n\n") < 0) return false;

    if (fprintf(fp, "Alphabet:\n") < 0) return false;
    for (int i = 0; i < 256; i++) {
        if (fprintf(fp, "  Symbol %d: %d-%d\n", i, i, i) < 0) return false;
    }
    if (fprintf(fp, "  Symbol 256: 0-255 (special)\n") < 0) return false;
    if (fprintf(fp, "  Symbol 257: 1-1 (special)\n") < 0) return false;
    if (fprintf(fp, "  Symbol 258: 5-5 (special)\n") < 0) return false;
    if (fprintf(fp, "  Symbol 259: 32-32 (special)\n") < 0) return false;
    if (fprintf(fp, "  Symbol 260: 9-9 (special)\n\n") < 0) return false;

    for (uint32_t s = 0; s < c->state_count; s++) {
        nfa_state_t *si = &c->states[s];
        if (fprintf(fp, "State %u:\n", s) < 0) return false;
        if (fprintf(fp, "  CategoryMask: 0x%02x\n", si->is_accepting ? si->category_mask : 0) < 0) return false;
        if (fprintf(fp, "  PatternId: %u\n", si->pattern_id) < 0) return false;
        if (fprintf(fp, "  EosTarget: %s\n", si->is_accepting ? "yes" : "no") < 0) return false;
        if (si->tag) {
            if (fprintf(fp, "  Tags: %s\n", si->tag) < 0) return false;
        }
        if (fprintf(fp, "  Transitions: %u\n", si->trans_count) < 0) return false;
        for (uint32_t t = 0; t < si->trans_count; t++) {
            if (fprintf(fp, "    Symbol %d -> %u\n", si->trans[t].symbol, si->trans[t].target) < 0) return false;
        }
        if (fprintf(fp, "\n") < 0) return false;
    }
    return true;
}

st_error_t st_policy_render_nfa(const st_policy_t *policy,
                                  const char *path,
                                  const st_nfa_render_opts_t *opts)
{
    if (!policy || !path) return ST_ERR_INVALID;

    pthread_rwlock_rdlock((pthread_rwlock_t *)&policy->rwlock);

    uint32_t num_trie = (uint32_t)((st_policy_t *)policy)->states.count;
    uint32_t *trie_map = malloc(num_trie * sizeof(uint32_t));
    if (!trie_map) {
        pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
        return ST_ERR_MEMORY;
    }
    for (uint32_t i = 0; i < num_trie; i++) trie_map[i] = UINT32_MAX;

    nfa_ctx_t *c = nfa_ctx_new(
        opts ? opts->category_mask : 0x01,
        opts ? opts->include_tags : false,
        opts ? opts->identifier : "rbox policy",
        opts ? opts->pattern_id_base : 1);
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

    if (ok) {
        FILE *fp = fopen(path, "w");
        if (!fp) {
            nfa_ctx_free(c);
            free(trie_map);
            pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
            return ST_ERR_IO;
        }
        ok = nfa_write(c, fp);
        fclose(fp);
    }

    nfa_ctx_free(c);
    free(trie_map);
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
    return ok ? ST_OK : ST_ERR_MEMORY;
}

/* ============================================================
 * SERIALIZATION
 *
 * Format:
 *   # CPL v1
 *   # patterns: <count>
 *   <pattern line 1>
 *   <pattern line 2>
 *   ...
 *   # CRC32: <hex>
 *
 * Version 1: one pattern per line, no wildcards in comments.
 * Vacuum filter state is NOT persisted — rebuilt on load.
 * ============================================================ */

#define ST_SERIALIZATION_VERSION 1

typedef struct {
    FILE *fp;
    st_error_t error;
    uint32_t crc;
    size_t pattern_count;
} policy_save_ctx_t;

static void dfs_save(st_policy_t *policy, uint32_t idx, policy_save_ctx_t *ctx)
{
    if (ctx->error != ST_OK) return;

    policy_state_t *node = &policy->states.states[idx];
    uint16_t total = node->literal_count + node->wildcard_count;
    child_entry_t *children = (child_entry_t *)(policy->children_arena.base + node->children_offset);

    if (node->pattern_id != UINT16_MAX && node->pattern_id < policy->patterns.count) {
        const char *pat = policy->patterns.entries[node->pattern_id].pattern;
        size_t len = strlen(pat);
        if (fprintf(ctx->fp, "%s\n", pat) < 0) {
            ctx->error = ST_ERR_IO;
            return;
        }
        ctx->crc = crc32_compute(pat, len, ctx->crc);
        ctx->crc = crc32_compute("\n", 1, ctx->crc);
        ctx->pattern_count++;
    }

    for (uint16_t i = 0; i < total; i++) {
        child_entry_t *c = &children[i];
        if (c) dfs_save(policy, c->target, ctx);
    }
}

st_error_t st_policy_save(const st_policy_t *policy, const char *path)
{
    if (!policy || !path) return ST_ERR_INVALID;

    FILE *fp = fopen(path, "w");
    if (!fp) return ST_ERR_IO;

    /* Header */
    if (fprintf(fp, "# CPL v%d\n", ST_SERIALIZATION_VERSION) < 0) {
        fclose(fp);
        return ST_ERR_IO;
    }
    if (fprintf(fp, "# patterns: %zu\n", policy->pattern_count) < 0) {
        fclose(fp);
        return ST_ERR_IO;
    }

    /* Patterns with running CRC */
    policy_save_ctx_t ctx = { .fp = fp, .error = ST_OK, .crc = 0, .pattern_count = 0 };
    dfs_save((st_policy_t *)policy, 0, &ctx);

    /* Footer: CRC32 */
    if (ctx.error == ST_OK) {
        if (fprintf(fp, "# CRC32: %08x\n", ctx.crc) < 0) {
            ctx.error = ST_ERR_IO;
        }
    }

    fclose(fp);
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
st_error_t st_policy_load(st_policy_t *policy, const char *path, bool clear_first)
{
    if (!policy || !path) return ST_ERR_INVALID;

    /* ============================================================
     * PASS 1: Read file, verify CRC, collect pattern lines.
     * Do NOT modify the policy yet.
     * ============================================================ */
    FILE *fp = fopen(path, "r");
    if (!fp) return ST_ERR_IO;

    /* Dynamic array of pattern lines */
    char **pattern_lines = NULL;
    size_t pattern_count = 0;
    size_t pattern_cap = 0;

    char line[4096];
    uint32_t expected_crc = 0;
    uint32_t computed_crc = 0;
    bool got_header = false;
    bool got_crc = false;
    bool in_patterns = false;

    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) continue;

        if (!got_header) {
            if (strncmp(line, "# CPL v", 7) != 0) {
                fclose(fp);
                goto pass1_fail;
            }
            int version = atoi(line + 7);
            if (version != ST_SERIALIZATION_VERSION) {
                fclose(fp);
                goto pass1_fail;
            }
            got_header = true;
            continue;
        }

        if (!in_patterns) {
            if (strncmp(line, "# patterns:", 11) == 0) continue;
            in_patterns = true;
        }

        if (strncmp(line, "# CRC32: ", 9) == 0) {
            char *end;
            expected_crc = (uint32_t)strtoul(line + 9, &end, 16);
            if (end != line + 17) {
                fclose(fp);
                goto pass1_fail;
            }
            got_crc = true;
            break;
        }

        if (line[0] == '#') continue;

        /* Pattern line — compute CRC and store */
        size_t plen = strlen(line);
        computed_crc = crc32_compute(line, plen, computed_crc);
        computed_crc = crc32_compute("\n", 1, computed_crc);

        if (pattern_count >= pattern_cap) {
            size_t new_cap = pattern_cap ? pattern_cap * 2 : 64;
            char **new_lines = realloc(pattern_lines, new_cap * sizeof(char *));
            if (!new_lines) {
                fclose(fp);
                goto pass1_fail;
            }
            pattern_lines = new_lines;
            pattern_cap = new_cap;
        }
        pattern_lines[pattern_count] = strdup(line);
        if (!pattern_lines[pattern_count]) {
            fclose(fp);
            goto pass1_fail;
        }
        pattern_count++;
    }

    fclose(fp);

    if (!got_header || !got_crc || computed_crc != expected_crc) {
        goto pass1_fail;
    }

    /* ============================================================
     * PASS 2: CRC verified. Now modify the policy.
     * ============================================================ */
    if (clear_first) {
        arena_free(&policy->children_arena);
        arena_init(&policy->children_arena, CHILDREN_ARENA_SIZE);
        free(policy->states.states);
        states_array_init(&policy->states);
        pattern_reg_free(&policy->patterns);
        pattern_reg_init(&policy->patterns);
        for (size_t i = 0; i < policy->num_buckets; i++)
            len_bucket_free(&policy->len_buckets[i]);
        policy->pattern_count = 0;
        policy->children_count = 0;
        for (int i = 0; i < FILTER_POS_LEVELS; i++) {
            vacuum_filter_destroy(policy->pos_filters[i]);
            policy->pos_filters[i] = NULL;
            policy->pos_built_epoch[i] = 0;
        }
        atomic_fetch_add(&policy->epoch, 1);
    }

    st_error_t first_err = ST_OK;
    for (size_t i = 0; i < pattern_count; i++) {
        st_error_t err = st_policy_add(policy, pattern_lines[i]);
        if (err != ST_OK && first_err == ST_OK) {
            first_err = err;
        }
        free(pattern_lines[i]);
    }
    free(pattern_lines);
    return first_err;

pass1_fail:
    for (size_t i = 0; i < pattern_count; i++)
        free(pattern_lines[i]);
    free(pattern_lines);
    return ST_ERR_FORMAT;
}

/* ============================================================
 * DIAGNOSTICS
 * ============================================================ */

size_t st_policy_memory_usage(const st_policy_t *policy)
{
    if (!policy) return 0;
    size_t states_alloc = policy->states.capacity * sizeof(policy_state_t);
    size_t patterns_alloc = policy->patterns.capacity * sizeof(pattern_entry_t);
    size_t filter_bytes = 0;
    for (int i = 0; i < FILTER_POS_LEVELS; i++) {
        if (policy->pos_filters[i]) {
            filter_bytes += vacuum_filter_memory_bytes(policy->pos_filters[i]);
        }
    }
    return sizeof(st_policy_t) + filter_bytes + states_alloc + policy->children_arena.used + patterns_alloc;
}

size_t st_policy_working_set(const st_policy_t *policy)
{
    if (!policy) return 0;
    size_t states_used = policy->states.count * sizeof(policy_state_t);
    size_t patterns_used = policy->patterns.count * sizeof(pattern_entry_t);
    size_t filter_bytes = 0;
    for (int i = 0; i < FILTER_POS_LEVELS; i++) {
        if (policy->pos_filters[i]) {
            filter_bytes += vacuum_filter_memory_bytes(policy->pos_filters[i]);
        }
    }
    return sizeof(st_policy_t) + filter_bytes + states_used + policy->children_count * sizeof(child_entry_t) + patterns_used;
}

size_t st_policy_state_count(const st_policy_t *policy)
{
    if (!policy) return 0;
    return policy->states.count;
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void st_policy_get_stats(const st_policy_t *policy, st_policy_stats_t *stats)
{
    if (!policy || !stats) return;
    
    pthread_rwlock_rdlock((pthread_rwlock_t *)&policy->rwlock);
    
    /* Read atomic counters */
    stats->eval_count = atomic_load(&policy->stats.eval_count);
    stats->filter_reject_count = atomic_load(&policy->stats.filter_reject_count);
    stats->trie_walk_count = atomic_load(&policy->stats.trie_walk_count);
    stats->suggestion_count = atomic_load(&policy->stats.suggestion_count);
    stats->filter_rebuild_count = atomic_load(&policy->stats.filter_rebuild_count);
    stats->filter_rebuild_us = atomic_load(&policy->stats.filter_rebuild_us);
    stats->pattern_count = policy->pattern_count;
    stats->state_count = policy->states.count;
    stats->memory_bytes = st_policy_memory_usage(policy);
    
    pthread_rwlock_unlock((pthread_rwlock_t *)&policy->rwlock);
}

/* ============================================================
 * DOT GRAPH EXPORT
 * ============================================================ */

st_error_t st_policy_dump_dot(const st_policy_t *policy, const char *path)
{
    if (!policy || !path) return ST_ERR_INVALID;
    
    FILE *fp = fopen(path, "w");
    if (!fp) return ST_ERR_IO;
    
    if (fprintf(fp, "digraph policy_trie {\n") < 0) { fclose(fp); return ST_ERR_IO; }
    if (fprintf(fp, "  rankdir=LR;\n") < 0) { fclose(fp); return ST_ERR_IO; }
    if (fprintf(fp, "  node [shape=circle];\n") < 0) { fclose(fp); return ST_ERR_IO; }
    if (fprintf(fp, "  edge [];\n") < 0) { fclose(fp); return ST_ERR_IO; }
    
    /* BFS to traverse and emit nodes/edges */
    typedef struct { uint32_t idx; uint32_t node_id; } dot_q;
    dot_q queue[4096];
    size_t head = 0, tail = 0;
    uint32_t next_id = 0;
    
    /* Emit root node */
    if (fprintf(fp, "  n%d [label=\"root\"%s];\n",
                next_id,
                policy->states.states[0].pattern_id != UINT16_MAX ? ", style=filled, fillcolor=lightgreen" : "")
        < 0) { fclose(fp); return ST_ERR_IO; }
    
    queue[tail].idx = 0;
    queue[tail].node_id = next_id++;
    tail++;
    
    while (head < tail && tail < 4096) {
        dot_q entry = queue[head++];
        policy_state_t *node = &policy->states.states[entry.idx];
        uint16_t total = node->literal_count + node->wildcard_count;
        char *arena_base = policy->children_arena.base;
        child_entry_t *children = (child_entry_t *)(arena_base + node->children_offset);
        
        for (uint16_t i = 0; i < total; i++) {
            child_entry_t *c = &children[i];
            
            /* Emit child node */
            const char *label = c->type == ST_TYPE_LITERAL ? c->text : st_type_symbol[c->type];
            if (fprintf(fp, "  n%d [label=\"%s\"%s];\n",
                        next_id, label,
                        node->pattern_id != UINT16_MAX ? "" : "")
                < 0) { fclose(fp); return ST_ERR_IO; }
            
            /* Emit edge */
            if (fprintf(fp, "  n%d -> n%d;\n", entry.node_id, next_id) < 0) {
                fclose(fp); return ST_ERR_IO;
            }
            
            if (tail < 4096) {
                queue[tail].idx = c->target;
                queue[tail].node_id = next_id;
                tail++;
            }
            next_id++;
        }
    }
    
    if (fprintf(fp, "}\n") < 0) { fclose(fp); return ST_ERR_IO; }
    fclose(fp);
    return ST_OK;
}

/* ============================================================
 * DRY-RUN MODE
 * ============================================================ */

st_error_t st_policy_simulate_add(st_policy_t *policy,
                                    const char *pattern,
                                    bool *would_match,
                                    const char **conflicting_pattern)
{
    if (!policy || !pattern || !would_match) return ST_ERR_INVALID;
    
    *would_match = false;
    if (conflicting_pattern) *conflicting_pattern = NULL;
    
    st_eval_result_t result;
    st_error_t err = st_policy_eval(policy, pattern, &result);
    if (err != ST_OK) return err;
    
    *would_match = result.matches;
    if (result.matches && conflicting_pattern) {
        *conflicting_pattern = result.matching_pattern;
    }
    
    return ST_OK;
}

/* ============================================================
 * POLICY EXPANSION SUGGESTIONS (Miner — Step 2 only)
 * ============================================================ */

/*
 * Next-wider type in the lattice, capped appropriately.
 *
 * Security: We cap generalization at reasonable types to prevent
 * over-broad suggestions. Path types stay as #path, others may go to #w.
 *
 * Type hierarchy (with caps):
 *   #h → #n → #val → #w (cap)
 *   #i → #val → #w (cap)
 *   #w → #w (cap - already at limit)
 *   #q → #qs → #val → #w (cap)
 *   #f → #r → #path → #path (cap - #path is appropriate for paths)
 *   #p → #path → #path (cap)
 *   #u → #w (cap)
 *   #val → #val (cap)
 *   #opt → #val → * (cap)
 *   #uuid, #email, #host, #size, #semver, #ts, #env → #val → * (cap)
 *   #port → #n → #val → * (cap)
 *   #hash, #hyp → #word → #val → * (cap)
 */
static st_token_type_t next_wider_type(st_token_type_t t)
{
    switch (t) {
        case ST_TYPE_HEXHASH:     return ST_TYPE_SHA;
        case ST_TYPE_SHA:         return ST_TYPE_VALUE;
        case ST_TYPE_NUMBER:      return ST_TYPE_VALUE;
        case ST_TYPE_IPV4:        return ST_TYPE_VALUE;
        case ST_TYPE_WORD:        return ST_TYPE_WORD; /* Cap reached */
        case ST_TYPE_QUOTED:      return ST_TYPE_QUOTED_SPACE;
        case ST_TYPE_QUOTED_SPACE:return ST_TYPE_VALUE;
        case ST_TYPE_FILENAME:    return ST_TYPE_REL_PATH;
        case ST_TYPE_REL_PATH:    return ST_TYPE_PATH;
        case ST_TYPE_ABS_PATH:    return ST_TYPE_PATH;
        case ST_TYPE_PATH:        return ST_TYPE_PATH; /* Cap: #path stays as #path */
        case ST_TYPE_URL:         return ST_TYPE_WORD; /* Cap: #u → #w */
        case ST_TYPE_VALUE:       return ST_TYPE_VALUE; /* Cap: #val stays as #val */
        case ST_TYPE_OPT:         return ST_TYPE_VALUE; /* Cap: #opt → #val */
        case ST_TYPE_UUID:        return ST_TYPE_VALUE; /* Cap: #uuid → #val */
        case ST_TYPE_EMAIL:       return ST_TYPE_VALUE; /* Cap: #email → #val */
        case ST_TYPE_HOSTNAME:    return ST_TYPE_VALUE; /* Cap: #host → #val */
        case ST_TYPE_PORT:        return ST_TYPE_NUMBER; /* Cap: #port → #n */
        case ST_TYPE_SIZE:        return ST_TYPE_VALUE; /* Cap: #size → #val */
        case ST_TYPE_SEMVER:      return ST_TYPE_VALUE; /* Cap: #semver → #val */
        case ST_TYPE_TIMESTAMP:   return ST_TYPE_VALUE; /* Cap: #ts → #val */
        case ST_TYPE_HASH_ALGO:   return ST_TYPE_WORD;   /* Cap: #hash → #word */
        case ST_TYPE_ENV_VAR:     return ST_TYPE_VALUE;  /* Cap: #env → #val */
        case ST_TYPE_HYPHENATED:  return ST_TYPE_WORD;   /* Cap: #hyp → #word */
        case ST_TYPE_BRANCH:      return ST_TYPE_VALUE;  /* Cap: #branch → #val */
        case ST_TYPE_IMAGE:       return ST_TYPE_VALUE;  /* Cap: #image → #val */
        case ST_TYPE_PKG:         return ST_TYPE_VALUE;  /* Cap: #pkg → #val */
        case ST_TYPE_USER:        return ST_TYPE_VALUE;  /* Cap: #user → #val */
        case ST_TYPE_FINGERPRINT: return ST_TYPE_VALUE;  /* Cap: #fp → #val */
        case ST_TYPE_ANY:         return ST_TYPE_ANY;    /* Already at top */
        default:                  return t;
    }
}

size_t st_policy_suggest_variants(const st_policy_t *policy,
                                    const st_token_t *tokens,
                                    size_t token_count,
                                    st_expand_suggestion_t out[3])
{
    if (!policy || !tokens || !out || token_count == 0) return 0;

    /* Variant 0: exact match as literal */
    {
        st_token_t *lit_tokens = malloc(token_count * sizeof(st_token_t));
        if (!lit_tokens) return 0;
        for (size_t i = 0; i < token_count; i++) {
            lit_tokens[i].text = (char *)tokens[i].text;
            lit_tokens[i].type = ST_TYPE_LITERAL;
        }
        st_build_pattern(out[0].pattern, sizeof(out[0].pattern),
                            lit_tokens, token_count);
        out[0].based_on = NULL;
        out[0].confidence = 1.0;
        free(lit_tokens);
    }

    /* Variants 1..N: widen one non-literal token at a time */
    size_t n_variants = 1;
    for (size_t i = 0; i < token_count && n_variants < 3; i++) {
        if (tokens[i].type == ST_TYPE_LITERAL) continue;

        st_token_type_t wider = next_wider_type(tokens[i].type);
        if (wider == tokens[i].type) continue;

        st_token_t *pat_tokens = malloc(token_count * sizeof(st_token_t));
        if (!pat_tokens) continue;
        for (size_t j = 0; j < token_count; j++)
            pat_tokens[j] = tokens[j];
        pat_tokens[i].text = (char *)st_type_symbol[wider];
        pat_tokens[i].type = wider;

        st_build_pattern(out[n_variants].pattern,
                            sizeof(out[n_variants].pattern),
                            pat_tokens, token_count);
        out[n_variants].based_on = NULL;
        out[n_variants].confidence = 1.0;
        free(pat_tokens);
        n_variants++;
    }

    return n_variants;
}
