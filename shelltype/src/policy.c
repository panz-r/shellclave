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
 * PATTERN REGISTRY
 * ============================================================ */

typedef struct {
    const char **strings;
    size_t       count;
    size_t       capacity;
} pattern_reg_t;

static bool pattern_reg_init(pattern_reg_t *r)
{
    r->capacity = PATTERN_REG_INIT;
    r->strings = calloc(r->capacity, sizeof(const char *));
    if (!r->strings) return false;
    r->count = 0;
    return true;
}

static void pattern_reg_free(pattern_reg_t *r)
{
    free((void *)r->strings);
    r->strings = NULL;
}

static bool pattern_reg_grow(pattern_reg_t *r)
{
    size_t new_cap = r->capacity * 2;
    const char **new_strings = realloc((void *)r->strings, new_cap * sizeof(const char *));
    if (!new_strings) return false;
    r->strings = new_strings;
    r->capacity = new_cap;
    return true;
}

static uint16_t pattern_reg_add(pattern_reg_t *r, st_policy_ctx_t *ctx, const char *pattern)
{
    if (r->count >= r->capacity) {
        if (!pattern_reg_grow(r)) return UINT16_MAX;
    }
    const char *interned = st_policy_ctx_intern(ctx, pattern);
    if (!interned) return UINT16_MAX;
    uint16_t id = (uint16_t)r->count;
    r->strings[r->count++] = interned;
    return id;
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

static int cmp_literal_child(const void *key, const void *entry)
{
    return strcmp((const char *)key, ((const child_entry_t *)entry)->text);
}

static child_entry_t *find_literal_child(const policy_state_t *node,
                                         const char *arena_base, const char *text)
{
    uint16_t n = node->literal_count;
    if (n == 0 || !arena_base) return NULL;
    assert(n <= node->children_alloc);
    /* Hybrid: linear scan for small fan-outs, bsearch for larger */
    if (n < 8) {
        child_entry_t *children = (child_entry_t *)(arena_base + node->children_offset);
        for (uint16_t i = 0; i < n; i++) {
            if (strcmp(text, children[i].text) == 0) return &children[i];
        }
        return NULL;
    }
    child_entry_t *children = (child_entry_t *)(arena_base + node->children_offset);
    return bsearch(text, children, n, sizeof(child_entry_t), cmp_literal_child);
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
           t == ST_TYPE_UUID || t == ST_TYPE_SEMVER || t == ST_TYPE_TIMESTAMP;
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
    for (uint16_t i = 0; i < node->wildcard_count; i++) {
        if (st_is_compatible(type, (st_token_type_t)base[i].type) &&
            param_matches(cmd_text, type, base[i].text, (st_token_type_t)base[i].type))
            return &base[i];
    }
    return NULL;
}

/* ============================================================
 * CHILD INSERTION
 * ============================================================ */

static bool insert_child(policy_state_t *node, st_policy_t *policy,
                         const char *text, st_token_type_t type, uint32_t target, uint8_t depth)
{
    assert(node->literal_count + node->wildcard_count <= node->children_alloc);
    bool is_literal = (type == ST_TYPE_LITERAL);
    uint16_t total = node->literal_count + node->wildcard_count;
    uint16_t insert_pos;
    char *arena_base = policy->children_arena.base;
    child_entry_t *children = (child_entry_t *)(arena_base + node->children_offset);

    if (is_literal) {
        insert_pos = 0;
        for (uint16_t i = 0; i < node->literal_count; i++) {
            if (strcmp(text, children[i].text) < 0) break;
            insert_pos = i + 1;
        }
        if (insert_pos < node->literal_count &&
            children[insert_pos].type == ST_TYPE_LITERAL &&
            strcmp(text, children[insert_pos].text) == 0) return false;
    } else {
        insert_pos = node->literal_count;
        for (uint16_t i = node->literal_count; i < total; i++) {
            if (type < children[i].type) break;
            insert_pos = i + 1;
        }
        /* Duplicate check: same base type AND same text (handles parametrized) */
        if (insert_pos < total && children[insert_pos].type == type) {
            bool is_param = text && strchr(text, '.');
            if (!is_param) return false;  /* non-parametrized: same type = dup */
            /* Parametrized: check if same parameter */
            if (children[insert_pos].text != NULL && text != NULL &&
                strcmp(children[insert_pos].text, text) == 0) return false;
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
            return false;
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
            uint64_t h = filter_hash_fnv1a(text, strlen(text));
            vacuum_filter_insert(policy->pos_filters[depth], h);
        } else {
            policy->pos_wildcard_mask[depth] |= (1u << type);
        }
    }

    return true;
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
        for (int t = 1; t < ST_TYPE_COUNT; t++) {
            const char *sym = st_type_symbol[t];
            size_t sym_len = strlen(sym);
            if (strncmp(tok, sym, sym_len) == 0 && tok[sym_len] == '\0') {
                /* Exact match: e.g., "#path" */
                type = (st_token_type_t)t;
                break;
            }
            if (strncmp(tok, sym, sym_len) == 0 && tok[sym_len] == '.' &&
                tok[sym_len + 1] != '\0' && type_supports_param((st_token_type_t)t)) {
                /* Parametrized match: e.g., "#path.cfg" — validate parameter */
                if (!validate_param((st_token_type_t)t, tok + sym_len)) {
                    /* Invalid parameter — treat as literal */
                    break;
                }
                type = (st_token_type_t)t;
                break;
            }
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
 * Check if pattern B subsumes pattern A.
 * B subsumes A iff every command accepted by A is also accepted by B.
 * Requires same length and each token of A compatible with B.
 * For literals, values must match exactly.
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
        /* For literals, values must match exactly */
        if (a[i].type == ST_TYPE_LITERAL && b[i].type == ST_TYPE_LITERAL) {
            if (strcmp(a[i].text, b[i].text) != 0) return false;
        } else {
            /* For wildcard compatibility, use the type lattice */
            if (!st_is_compatible(a[i].type, b[i].type)) return false;
            /* Parametrized wildcard subsumption check */
            const char *a_param = wildcard_param(a[i].text, a[i].type);
            const char *b_param = wildcard_param(b[i].text, b[i].type);
            if (a_param && b_param) {
                /* Both parametrized: must have same parameter */
                if (strcmp(a_param, b_param) != 0) return false;
            } else if (a_param && !b_param) {
                /* a is parametrized, b is not: b subsumes a (OK) */
            } else if (!a_param && b_param) {
                /* a is not parametrized, b is: b is more specific, cannot subsume a */
                return false;
            }
            /* else: neither parametrized, type compatibility already checked */
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
    /* Release context reference */
    st_policy_ctx_release(policy->ctx);
    free(policy);
}

/* ============================================================
 * ADD / REMOVE
 * ============================================================ */

/* Internal: add pattern assuming write lock is already held */
static st_error_t st_policy_add_locked(st_policy_t *policy, const char *pattern)
{
    if (!policy || !pattern || !pattern[0]) return ST_ERR_INVALID;

    size_t token_count = 0;
    st_token_t *tokens = parse_pattern(pattern, &token_count);
    if (!tokens) return ST_ERR_INVALID;
    if (token_count == 0) { free_pattern_tokens(tokens, token_count); return ST_ERR_INVALID; }

    uint32_t current = 0;

    for (size_t i = 0; i < token_count; i++) {
        policy_state_t *node = &policy->states.states[current];
        child_entry_t *existing = NULL;
        char *arena_base = policy->children_arena.base;

        if (tokens[i].type == ST_TYPE_LITERAL) {
            existing = find_literal_child(node, arena_base, tokens[i].text);
        } else {
            existing = find_wildcard_child(node, arena_base, tokens[i].type, tokens[i].text);
        }

        if (existing) {
            current = existing->target;
        } else {
            uint32_t new_state = states_array_alloc(&policy->states);
            if (new_state == UINT32_MAX) {
                free_pattern_tokens(tokens, token_count);
                return ST_ERR_MEMORY;
            }
            if (!insert_child(node, policy,
                              tokens[i].text, tokens[i].type, new_state, (uint8_t)i)) {
                free_pattern_tokens(tokens, token_count);
                return ST_ERR_MEMORY;
            }
            current = new_state;
        }
    }

    policy_state_t *node = &policy->states.states[current];
    if (node->pattern_id == UINT16_MAX) {
        uint16_t pid = pattern_reg_add(&policy->patterns, policy->ctx, pattern);
        if (pid == UINT16_MAX) {
            free_pattern_tokens(tokens, token_count);
            return ST_ERR_MEMORY;
        }
        node->pattern_id = pid;
        policy->pattern_count++;
    }

    policy->epoch++;
    free_pattern_tokens(tokens, token_count);
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
            child = find_wildcard_child(node, arena_base, tokens[i].type, tokens[i].text);
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

    node->pattern_id = UINT16_MAX;
    policy->pattern_count--;

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
        if (policy->patterns.strings[i] != NULL) {
            active[n_active++] = strdup(policy->patterns.strings[i]);
        }
    }

    if (n_active == 0) {
        free(active);
        pthread_rwlock_unlock(&policy->rwlock);
        return ST_OK;
    }

    /* Step 1.5: Remove patterns subsumed by more general patterns
     * B subsumes A iff every command matching A also matches B */
    if (n_active > 1) {
        st_token_t **pat_tokens = calloc(n_active, sizeof(st_token_t *));
        size_t *pat_lens = calloc(n_active, sizeof(size_t));
        bool *redundant = calloc(n_active, sizeof(bool));
        size_t orig_n = n_active;  /* Save for cleanup */
        
        if (!pat_tokens || !pat_lens || !redundant) {
            /* Allocation failed - clean up any partial allocations */
            free(pat_tokens);
            free(pat_lens);
            free(redundant);
            for (size_t i = 0; i < n_active; i++) {
                free(active[i]);
            }
            free(active);
            pthread_rwlock_unlock(&policy->rwlock);
            return ST_ERR_MEMORY;
        }
        
        /* Parse all patterns first */
        for (size_t i = 0; i < orig_n; i++) {
            pat_tokens[i] = parse_pattern(active[i], &pat_lens[i]);
        }
        
        /* Find subsumed patterns: j subsumes i if j is more general */
        for (size_t i = 0; i < orig_n; i++) {
            if (redundant[i] || !pat_tokens[i]) continue;
            for (size_t j = 0; j < orig_n; j++) {
                if (i == j || redundant[j] || !pat_tokens[j]) continue;
                if (pattern_subsumes(pat_tokens[i], pat_lens[i],
                                    pat_tokens[j], pat_lens[j])) {
                    redundant[i] = true;  /* i is subsumed by j */
                    break;
                }
            }
        }
        
        /* Compact active array to keep only non-redundant */
        size_t new_n = 0;
        for (size_t i = 0; i < orig_n; i++) {
            if (!redundant[i]) {
                active[new_n++] = active[i];
            } else {
                free(active[i]);
                active[i] = NULL;
            }
        }
        n_active = new_n;
        
        /* Cleanup parsed tokens */
        for (size_t i = 0; i < orig_n; i++) {
            if (pat_tokens[i]) {
                free_pattern_tokens(pat_tokens[i], pat_lens[i]);
            }
        }
        free(pat_tokens);
        free(pat_lens);
        free(redundant);
    }

    if (n_active == 0) {
        free(active);
        pthread_rwlock_unlock(&policy->rwlock);
        return ST_OK;
    }

    /* Step 2: FULLY tear down policy trie BEFORE resetting context
     * This ensures no dangling pointers to ctx->arena after reset */
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
    arena_free(&policy->children_arena);
    arena_init(&policy->children_arena, CHILDREN_ARENA_SIZE);
    policy->pattern_count = 0;
    policy->children_count = 0;

    /* Step 3: Release context reference so reset can proceed
     * (trie is torn down, no more references to ctx->arena) */
    st_policy_ctx_release(policy->ctx);  // refcount: 2 -> 1

    /* Step 4: Reset context (now safe with refcount == 1) */
    st_error_t reset_err = st_policy_ctx_reset(policy->ctx);
    if (reset_err != ST_OK) {
        /* Re-acquire reference if reset failed */
        st_policy_ctx_retain(policy->ctx);
        for (size_t j = 0; j < n_active; j++) free(active[j]);
        free(active);
        pthread_rwlock_unlock(&policy->rwlock);
        return reset_err;
    }

    /* Re-acquire reference for policy */
    st_policy_ctx_retain(policy->ctx);  // refcount: 1 -> 2

    /* Step 5: Rebuild trie with collected patterns */
    atomic_fetch_add(&policy->epoch, 1);

    for (size_t i = 0; i < n_active; i++) {
        /* Use _locked version since we already hold the write lock */
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
        return policy->patterns.strings[state->pattern_id];

    uint16_t total = state->literal_count + state->wildcard_count;
    child_entry_t *children = (child_entry_t *)(policy->children_arena.base + state->children_offset);
    for (uint16_t i = 0; i < total; i++) {
        child_entry_t *c = &children[i];
        policy_state_t *child = &policy->states.states[c->target];
        if (child->pattern_id != UINT16_MAX && child->pattern_id < policy->patterns.count)
            return policy->patterns.strings[child->pattern_id];
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
        /* Re-check epoch after acquiring write lock (another thread may have rebuilt) */
        uint64_t recheck_epoch = atomic_load(&policy->epoch);
        if (policy->pos_built_epoch[0] != recheck_epoch) {
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
            result->matching_pattern = policy->patterns.strings[end_node->pattern_id];
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
                                    static char sufbuf[32];
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
                matches[match_n++] = policy->patterns.strings[state->pattern_id];
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
 * ============================================================ */

#define VSYM_BYTE_ANY 256
#define VSYM_EPS      257
#define VSYM_EOS      258
#define VSYM_SPACE    259
#define VSYM_TAB      260

typedef struct {
    FILE *fp;
    st_error_t error;
    uint32_t state_count;
    uint32_t pattern_id_counter;
    uint8_t  category_mask;
    bool     include_tags;
    const char *identifier;
} nfa_render_ctx_t;

static uint32_t nfa_new_state(nfa_render_ctx_t *ctx)
{
    return ctx->state_count++;
}

typedef struct {
    uint32_t count;
} nfa_count_ctx_t;

static void nfa_count_states(nfa_count_ctx_t *ctx, st_policy_t *policy,
                             uint32_t trie_idx, bool need_space)
{
    ctx->count++;

    policy_state_t *node = &policy->states.states[trie_idx];
    uint16_t total = node->literal_count + node->wildcard_count;

    for (uint16_t i = 0; i < total; i++) {
        child_entry_t *c = child_at(node, policy->children_arena.base, i);
        if (!c) continue;

        if (need_space) ctx->count++;

        if (c->type == ST_TYPE_LITERAL) {
            ctx->count += (uint32_t)strlen(c->text);
        } else {
            ctx->count += 1;
        }

        nfa_count_states(ctx, policy, c->target, true);
    }
}

static void nfa_dfs_render(nfa_render_ctx_t *ctx, st_policy_t *policy,
                           uint32_t trie_idx, uint32_t nfa_state,
                           bool need_space)
{
    if (ctx->error != ST_OK) return;

    policy_state_t *node = &policy->states.states[trie_idx];
    uint16_t total = node->literal_count + node->wildcard_count;
    child_entry_t *children = (child_entry_t *)(policy->children_arena.base + node->children_offset);

    if (total == 0) {
        uint16_t pid = (node->pattern_id != UINT16_MAX) ? (ctx->pattern_id_counter++) : 0;
        if (fprintf(ctx->fp, "State %u:\n", nfa_state) < 0) { ctx->error = ST_ERR_IO; return; }
        if (fprintf(ctx->fp, "  CategoryMask: 0x%02x\n", ctx->category_mask) < 0) { ctx->error = ST_ERR_IO; return; }
        if (fprintf(ctx->fp, "  PatternId: %u\n", pid) < 0) { ctx->error = ST_ERR_IO; return; }
        if (fprintf(ctx->fp, "  EosTarget: yes\n") < 0) { ctx->error = ST_ERR_IO; return; }
        if (ctx->include_tags && node->pattern_id != UINT16_MAX &&
            node->pattern_id < policy->patterns.count) {
            if (fprintf(ctx->fp, "  Tags: %s\n",
                        policy->patterns.strings[node->pattern_id]) < 0) {
                ctx->error = ST_ERR_IO; return;
            }
        }
        if (fprintf(ctx->fp, "  Transitions: 0\n\n") < 0) { ctx->error = ST_ERR_IO; }
        return;
    }

    int trans_count = 0;
    for (uint16_t i = 0; i < total; i++) {
        child_entry_t *c = &children[i];
        if (c->type == ST_TYPE_LITERAL) {
            trans_count += (int)strlen(c->text);
        } else {
            trans_count += 1;
        }
    }

    uint16_t pid = (node->pattern_id != UINT16_MAX) ? (ctx->pattern_id_counter++) : 0;
    if (fprintf(ctx->fp, "State %u:\n", nfa_state) < 0) { ctx->error = ST_ERR_IO; return; }
    if (fprintf(ctx->fp, "  CategoryMask: 0x00\n") < 0) { ctx->error = ST_ERR_IO; return; }
    if (fprintf(ctx->fp, "  PatternId: %u\n", pid) < 0) { ctx->error = ST_ERR_IO; return; }
    if (fprintf(ctx->fp, "  EosTarget: no\n") < 0) { ctx->error = ST_ERR_IO; return; }
    if (ctx->include_tags && node->pattern_id != UINT16_MAX &&
        node->pattern_id < policy->patterns.count) {
        if (fprintf(ctx->fp, "  Tags: %s\n",
                    policy->patterns.strings[node->pattern_id]) < 0) {
            ctx->error = ST_ERR_IO; return;
        }
    }
    if (fprintf(ctx->fp, "  Transitions: %d\n", trans_count) < 0) { ctx->error = ST_ERR_IO; return; }

    for (uint16_t i = 0; i < total; i++) {
        child_entry_t *c = &children[i];

        if (need_space) {
            uint32_t space_state = nfa_new_state(ctx);
            if (fprintf(ctx->fp, "    Symbol %d -> %u\n", VSYM_SPACE, space_state) < 0) {
                ctx->error = ST_ERR_IO; return;
            }
            if (c->type == ST_TYPE_LITERAL) {
                uint32_t cur = space_state;
                for (const char *p = c->text; *p; p++) {
                    uint32_t next = nfa_new_state(ctx);
                    if (fprintf(ctx->fp, "    Symbol %d -> %u\n", (unsigned char)*p, next) < 0) {
                        ctx->error = ST_ERR_IO; return;
                    }
                    cur = next;
                }
                nfa_dfs_render(ctx, policy, c->target, cur, true);
            } else {
                uint32_t next = nfa_new_state(ctx);
                if (fprintf(ctx->fp, "    Symbol %d -> %u\n", VSYM_BYTE_ANY, next) < 0) {
                    ctx->error = ST_ERR_IO; return;
                }
                nfa_dfs_render(ctx, policy, c->target, next, true);
            }
        } else {
            if (c->type == ST_TYPE_LITERAL) {
                uint32_t cur = nfa_state;
                for (const char *p = c->text; *p; p++) {
                    uint32_t next = nfa_new_state(ctx);
                    if (fprintf(ctx->fp, "    Symbol %d -> %u\n", (unsigned char)*p, next) < 0) {
                        ctx->error = ST_ERR_IO; return;
                    }
                    cur = next;
                }
                nfa_dfs_render(ctx, policy, c->target, cur, false);
            } else {
                uint32_t next = nfa_new_state(ctx);
                if (fprintf(ctx->fp, "    Symbol %d -> %u\n", VSYM_BYTE_ANY, next) < 0) {
                    ctx->error = ST_ERR_IO; return;
                }
                nfa_dfs_render(ctx, policy, c->target, next, false);
            }
        }
    }
    if (fprintf(ctx->fp, "\n") < 0) { ctx->error = ST_ERR_IO; }
}

st_error_t st_policy_render_nfa(const st_policy_t *policy,
                                  const char *path,
                                  const st_nfa_render_opts_t *opts)
{
    if (!policy || !path) return ST_ERR_INVALID;

    FILE *fp = fopen(path, "w");
    if (!fp) return ST_ERR_IO;

    nfa_count_ctx_t count_ctx = { .count = 0 };
    nfa_count_states(&count_ctx, (st_policy_t *)policy, 0, false);

    nfa_render_ctx_t ctx = {
        .fp = fp,
        .error = ST_OK,
        .state_count = 0,
        .pattern_id_counter = opts ? opts->pattern_id_base : 1,
        .category_mask = opts ? opts->category_mask : 0x01,
        .include_tags = opts ? opts->include_tags : false,
		.identifier = opts ? opts->identifier : "rbox policy",
    };

    if (fprintf(fp, "NFA_ALPHABET\n") < 0) { fclose(fp); return ST_ERR_IO; }
    if (fprintf(fp, "Identifier: %s\n", ctx.identifier) < 0) { fclose(fp); return ST_ERR_IO; }
    if (fprintf(fp, "AlphabetSize: 261\n") < 0) { fclose(fp); return ST_ERR_IO; }
    if (fprintf(fp, "States: %u\n", count_ctx.count) < 0) { fclose(fp); return ST_ERR_IO; }
    if (fprintf(fp, "Initial: 0\n\n") < 0) { fclose(fp); return ST_ERR_IO; }

    if (fprintf(fp, "Alphabet:\n") < 0) { fclose(fp); return ST_ERR_IO; }
    for (int i = 0; i < 256; i++) {
        if (fprintf(fp, "  Symbol %d: %d-%d\n", i, i, i) < 0) { fclose(fp); return ST_ERR_IO; }
    }
    if (fprintf(fp, "  Symbol 256: 0-255 (special)\n") < 0) { fclose(fp); return ST_ERR_IO; }
    if (fprintf(fp, "  Symbol 257: 1-1 (special)\n") < 0) { fclose(fp); return ST_ERR_IO; }
    if (fprintf(fp, "  Symbol 258: 5-5 (special)\n") < 0) { fclose(fp); return ST_ERR_IO; }
    if (fprintf(fp, "  Symbol 259: 32-32 (special)\n") < 0) { fclose(fp); return ST_ERR_IO; }
    if (fprintf(fp, "  Symbol 260: 9-9 (special)\n\n") < 0) { fclose(fp); return ST_ERR_IO; }

    nfa_dfs_render(&ctx, (st_policy_t *)policy, 0, 0, false);

    fclose(fp);
    return ctx.error;
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
        const char *pat = policy->patterns.strings[node->pattern_id];
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
        policy->patterns.count = 0;
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
    size_t patterns_alloc = policy->patterns.capacity * sizeof(const char *);
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
    size_t patterns_used = policy->patterns.count * sizeof(const char *);
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

st_error_t st_policy_simulate_add(const st_policy_t *policy,
                                    const char *pattern,
                                    bool *would_match,
                                    const char **conflicting_pattern)
{
    if (!policy || !pattern || !would_match) return ST_ERR_INVALID;
    
    *would_match = false;
    if (conflicting_pattern) *conflicting_pattern = NULL;
    
    st_eval_result_t result;
    st_error_t err = st_policy_eval((st_policy_t *)policy, pattern, &result);
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
        case ST_TYPE_HEXHASH:     return ST_TYPE_NUMBER;
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
