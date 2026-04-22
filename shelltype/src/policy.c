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
#include "vacuum_filter.h"
#include "filter_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

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
    child_entry_t *children;
    uint16_t       literal_count;
    uint16_t       wildcard_count;
    uint16_t       pattern_id;
    uint16_t       wildcard_mask;
    uint16_t       children_cap;
} policy_state_t;

/* ============================================================
 * CHILDREN — per-node dynamically allocated array
 * ============================================================ */

static child_entry_t *children_grow(child_entry_t *old, uint16_t *cap)
{
    size_t new_cap = *cap == 0 ? 4 : (size_t)*cap * 2;
    child_entry_t *new = realloc(old, new_cap * sizeof(child_entry_t));
    if (!new) return NULL;
    memset(new + *cap, 0, (new_cap - *cap) * sizeof(child_entry_t));
    *cap = (uint16_t)new_cap;
    return new;
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
    a->states[0].children = NULL;
    a->states[0].pattern_id = UINT16_MAX;
    return true;
}

static void states_array_free(states_array_t *a)
{
    for (size_t i = 0; i < a->count; i++) {
        free(a->states[i].children);
    }
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
    uint32_t idx = (uint32_t)a->count;
    a->states[idx].children = NULL;
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

struct st_policy {
    st_policy_ctx_t   *ctx;
    states_array_t      states;
    pattern_reg_t       patterns;
    uint64_t            epoch;
    vacuum_filter_t    *pos_filters[FILTER_POS_LEVELS];
    uint16_t            pos_wildcard_mask[FILTER_POS_LEVELS];
    uint64_t            pos_built_epoch[FILTER_POS_LEVELS];
    size_t              pattern_count;
    size_t              children_count;
    size_t              children_alloc;
};

/* ============================================================
 * COMPATIBILITY MASK
 * ============================================================ */

static const uint16_t st_compat_mask[ST_TYPE_COUNT] = {
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
    /* ANY */          (1u << ST_TYPE_ANY),
};

static inline uint16_t compat_mask(st_token_type_t t)
{
    return st_compat_mask[t];
}

/* ============================================================
 * CHILD ACCESS
 * ============================================================ */

static inline child_entry_t *get_child(const policy_state_t *node, uint16_t idx)
{
    if (!node->children || idx >= node->literal_count + node->wildcard_count) return NULL;
    return &node->children[idx];
}

/* ============================================================
 * CHILD LOOKUP
 * ============================================================ */

static int cmp_literal_child(const void *key, const void *entry)
{
    return strcmp((const char *)key, ((const child_entry_t *)entry)->text);
}

static child_entry_t *find_literal_child(const policy_state_t *node, const char *text)
{
    uint16_t n = node->literal_count;
    if (n == 0 || !node->children) return NULL;
    /* Hybrid: linear scan for small fan-outs, bsearch for larger */
    if (n < 8) {
        for (uint16_t i = 0; i < n; i++) {
            if (strcmp(text, node->children[i].text) == 0) return &node->children[i];
        }
        return NULL;
    }
    return bsearch(text, node->children, n, sizeof(child_entry_t), cmp_literal_child);
}

static child_entry_t *find_wildcard_child(const policy_state_t *node, st_token_type_t type)
{
    if (node->wildcard_count == 0 || !node->children) return NULL;
    if (!(node->wildcard_mask & compat_mask(type))) return NULL;

    child_entry_t *base = node->children + node->literal_count;
    for (uint16_t i = 0; i < node->wildcard_count; i++) {
        if (st_is_compatible(type, (st_token_type_t)base[i].type)) return &base[i];
    }
    return NULL;
}

/* ============================================================
 * CHILD INSERTION
 * ============================================================ */

static bool insert_child(policy_state_t *node, st_policy_t *policy,
                         const char *text, st_token_type_t type, uint32_t target)
{
    bool is_literal = (type == ST_TYPE_LITERAL);
    uint16_t total = node->literal_count + node->wildcard_count;
    uint16_t insert_pos;

    if (is_literal) {
        insert_pos = 0;
        for (uint16_t i = 0; i < node->literal_count; i++) {
            if (strcmp(text, node->children[i].text) < 0) break;
            insert_pos = i + 1;
        }
        if (insert_pos < node->literal_count &&
            node->children[insert_pos].type == ST_TYPE_LITERAL &&
            strcmp(text, node->children[insert_pos].text) == 0) return false;
    } else {
        insert_pos = node->literal_count;
        for (uint16_t i = node->literal_count; i < total; i++) {
            if (type < node->children[i].type) break;
            insert_pos = i + 1;
        }
        if (insert_pos < total && node->children[insert_pos].type == type) return false;
    }

    const char *interned = is_literal ? st_policy_ctx_intern(policy->ctx, text) : NULL;
    child_entry_t new_child = { .text = interned, .target = target, .type = (uint8_t)type };

    if (total + 1 > node->children_cap) {
        size_t old_cap = node->children_cap;
        child_entry_t *grown = children_grow(node->children, &node->children_cap);
        if (!grown) return false;
        node->children = grown;
        policy->children_alloc += node->children_cap - old_cap;
    }

    memmove(node->children + insert_pos + 1,
            node->children + insert_pos,
            (total - insert_pos) * sizeof(child_entry_t));
    node->children[insert_pos] = new_child;
    policy->children_count++;

    if (is_literal) {
        node->literal_count++;
    } else {
        node->wildcard_count++;
        node->wildcard_mask |= (1u << type);
    }
    return true;
}

/* ============================================================
 * PATTERN PARSING
 * ============================================================ */

static st_token_t *parse_pattern(const char *pattern, size_t *out_count)
{
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
            if (strcmp(tok, st_type_symbol[t]) == 0) {
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
    /* Reset or create filters, clear masks */
    for (int i = 0; i < FILTER_POS_LEVELS; i++) {
        if (policy->pos_filters[i]) {
            vacuum_filter_reset(policy->pos_filters[i]);
        } else {
            policy->pos_filters[i] = vacuum_filter_create(FILTER_POS_CAPACITY, 0, 0, 0);
        }
        policy->pos_wildcard_mask[i] = 0;
    }

    /* BFS walk: track (state_idx, depth) pairs */
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

        for (uint16_t i = 0; i < total; i++) {
            child_entry_t *c = &node->children[i];
            if (c->type == ST_TYPE_LITERAL && !c->text) continue;

            uint8_t d = entry.depth;

            if (c->type == ST_TYPE_LITERAL) {
                if (policy->pos_filters[d]) {
                    uint64_t h = filter_hash_fnv1a(c->text, strlen(c->text));
                    vacuum_filter_insert(policy->pos_filters[d], h);
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
        policy->pos_built_epoch[i] = policy->epoch;
    }
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
    policy->epoch = 1;
    policy->pattern_count = 0;
    policy->children_count = 0;
    policy->children_alloc = 0;
    return policy;
}

void st_policy_free(st_policy_t *policy)
{
    if (!policy) return;
    for (int i = 0; i < FILTER_POS_LEVELS; i++) {
        vacuum_filter_destroy(policy->pos_filters[i]);
    }
    pattern_reg_free(&policy->patterns);
    states_array_free(&policy->states);
    free(policy);
}

/* ============================================================
 * ADD / REMOVE
 * ============================================================ */

st_error_t st_policy_add(st_policy_t *policy, const char *pattern)
{
    if (!policy || !pattern || !pattern[0]) return ST_ERR_INVALID;

    size_t token_count = 0;
    st_token_t *tokens = parse_pattern(pattern, &token_count);
    if (!tokens) return ST_ERR_MEMORY;
    if (token_count == 0) { free_pattern_tokens(tokens, token_count); return ST_ERR_INVALID; }

    uint32_t current = 0;

    for (size_t i = 0; i < token_count; i++) {
        policy_state_t *node = &policy->states.states[current];
        child_entry_t *existing = NULL;

        if (tokens[i].type == ST_TYPE_LITERAL) {
            existing = find_literal_child(node, tokens[i].text);
        } else {
            existing = find_wildcard_child(node, tokens[i].type);
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
                              tokens[i].text, tokens[i].type, new_state)) {
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

    size_t token_count = 0;
    st_token_t *tokens = parse_pattern(pattern, &token_count);
    if (!tokens) return ST_ERR_MEMORY;
    if (token_count == 0) { free_pattern_tokens(tokens, token_count); return ST_ERR_INVALID; }

    uint32_t current = 0;

    for (size_t i = 0; i < token_count; i++) {
        policy_state_t *node = &policy->states.states[current];
        child_entry_t *child = NULL;
        if (tokens[i].type == ST_TYPE_LITERAL) {
            child = find_literal_child(node, tokens[i].text);
        } else {
            child = find_wildcard_child(node, tokens[i].type);
        }
        if (!child) {
            free_pattern_tokens(tokens, token_count);
            return ST_OK;
        }
        current = child->target;
    }

    policy_state_t *node = &policy->states.states[current];
    if (node->pattern_id == UINT16_MAX) {
        free_pattern_tokens(tokens, token_count);
        return ST_OK;
    }

    node->pattern_id = UINT16_MAX;
    policy->pattern_count--;

    policy->epoch++;
    free_pattern_tokens(tokens, token_count);
    return ST_OK;
}

/*
 * Compact the policy by rebuilding from active patterns.
 * This reclaims arena memory after many add/remove cycles.
 * The context is reset and all trie nodes are rebuilt.
 */
st_error_t st_policy_compact(st_policy_t *policy)
{
    if (!policy) return ST_ERR_INVALID;

    if (policy->pattern_count == 0) return ST_OK;

    char **active = malloc(policy->pattern_count * sizeof(char *));
    if (!active) return ST_ERR_MEMORY;

    size_t n_active = 0;
    for (size_t i = 0; i < policy->patterns.count; i++) {
        if (policy->patterns.strings[i] != NULL) {
            active[n_active++] = strdup(policy->patterns.strings[i]);
        }
    }

    if (n_active == 0) {
        free(active);
        return ST_OK;
    }

    st_policy_ctx_reset(policy->ctx);

    for (size_t i = 0; i < policy->states.count; i++) {
        free(policy->states.states[i].children);
    }
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
    policy->epoch++;

    for (size_t i = 0; i < n_active; i++) {
        st_error_t err = st_policy_add(policy, active[i]);
        if (err != ST_OK) {
            for (size_t j = 0; j < n_active; j++) free(active[j]);
            free(active);
            return err;
        }
        free(active[i]);
    }
    free(active);
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

/* Build a pattern string from typed tokens into a fixed-size buffer. */
static bool st_build_pattern(char *buf, size_t buf_size,
                                 const st_token_t *tokens, size_t count)
{
    size_t total_len = 0;
    for (size_t i = 0; i < count; i++) {
        const char *part = tokens[i].type == ST_TYPE_LITERAL
            ? tokens[i].text
            : st_type_symbol[tokens[i].type];
        total_len += strlen(part) + (i > 0 ? 1 : 0);
    }
    if (total_len + 1 > buf_size) return false;

    char *p = buf;
    for (size_t i = 0; i < count; i++) {
        if (i > 0) *p++ = ' ';
        const char *part = tokens[i].type == ST_TYPE_LITERAL
            ? tokens[i].text
            : st_type_symbol[tokens[i].type];
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
    for (uint16_t i = 0; i < total; i++) {
        child_entry_t *c = &state->children[i];
        policy_state_t *child = &policy->states.states[c->target];
        if (child->pattern_id != UINT16_MAX && child->pattern_id < policy->patterns.count)
            return policy->patterns.strings[child->pattern_id];
    }
    return NULL;
}

st_error_t st_policy_eval(const st_policy_t *policy,
                             const char *raw_cmd,
                             st_eval_result_t *result)
{
    if (!policy || !raw_cmd) return ST_ERR_INVALID;

    if (result) {
        result->matches = false;
        result->matching_pattern = NULL;
        result->suggestion_count = 0;
    }

    st_token_array_t cmd;
    cmd.tokens = NULL;
    cmd.count = 0;
    st_error_t err = st_normalize_typed(raw_cmd, &cmd);
    if (err != ST_OK) return err;

    if (cmd.count == 0 || cmd.count > MAX_CMD_TOKENS) {
        st_free_token_array(&cmd);
        return ST_ERR_INVALID;
    }

    /* ============================================================
     * PER-POSITION FILTER PRE-CHECK
     *
     * Runs before the trie walk. Rejects definite no-matches early.
     * Runs in ALL modes (verify-only and suggest).
     * ============================================================ */
    bool filter_rejected = false;
    size_t check_len = cmd.count < FILTER_POS_LEVELS ? cmd.count : FILTER_POS_LEVELS;

    /* Rebuild filters if epoch stale */
    for (size_t i = 0; i < check_len; i++) {
        if (policy->pos_built_epoch[i] != policy->epoch) {
            st_policy_t *mutable = (st_policy_t *)policy;
            policy_rebuild_filters(mutable);
            break;
        }
    }

    for (size_t i = 0; i < check_len; i++) {
        st_token_type_t ctype = cmd.tokens[i].type;
        if (ctype == ST_TYPE_LITERAL) {
            if (policy->pos_wildcard_mask[i] != 0) continue;
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
        st_free_token_array(&cmd);
        return ST_ERR_INVALID;
    }

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
        st_token_type_t ctype = cmd.tokens[i].type;
        const char *ctext = cmd.tokens[i].text;
        policy_state_t *node = &policy->states.states[current];
        child_entry_t *found = NULL;

        if (ctype == ST_TYPE_LITERAL)
            found = find_literal_child(node, ctext);

        if (!found) {
            uint16_t compat = compat_mask(ctype) & node->wildcard_mask;
            if (compat)
                found = find_wildcard_child(node, ctype);
        }

        if (!found) break;

        current = found->target;
        match_depth = i + 1;
        match_state = current;
    }

    policy_state_t *end_node = &policy->states.states[current];
    if (match_depth == cmd.count &&
        end_node->pattern_id != UINT16_MAX &&
        end_node->pattern_id < policy->patterns.count) {
        st_free_token_array(&cmd);
        if (result) {
            result->matches = true;
            result->matching_pattern = policy->patterns.strings[end_node->pattern_id];
        }
        return ST_OK;
    }

    /* Verify-only: no match, no suggestions needed */
    if (!result) {
        st_free_token_array(&cmd);
        return ST_ERR_INVALID;
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
        if (!pat_tokens) { st_free_token_array(&cmd); return ST_ERR_MEMORY; }

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
            return ST_ERR_FAILED;
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

        uint16_t wm = div_node->wildcard_mask;
        if (wm != 0 && (compat_mask(div_type) & wm) != 0) {
            /* Wildcard widening: find narrowest compatible wildcard */
            st_token_type_t best_wild = ST_TYPE_ANY;
            uint16_t compat = compat_mask(div_type) & wm;
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
                        return ST_ERR_FAILED;
                    }
                    result->suggestions[1].based_on = based_on;
                    result->suggestions[1].confidence = confidence;
                    free(pat_tokens);
                    n_suggestions = 2;
                }
            }
    } else if (wm == 0 && div_node->literal_count >= LITERAL_THRESHOLD) {
            /* Literal-to-wildcard: classify all existing literals + input token */
            st_token_type_t joined = ST_TYPE_LITERAL;
            uint16_t total = div_node->literal_count;
            for (uint16_t i = 0; i < total; i++) {
                child_entry_t *c = &div_node->children[i];
                if (c->type != ST_TYPE_LITERAL) continue;
                st_token_type_t ct = st_classify_token(c->text);
                if (joined == ST_TYPE_LITERAL) joined = ct;
                else joined = st_join(joined, ct);
            }
            joined = st_join(joined, div_type);

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
                        return ST_ERR_FAILED;
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
                            sizeof(result->suggestions[1].pattern),
                            cmd.tokens, cmd.count)) {
            st_free_token_array(&cmd);
            result->error = ST_ERR_FAILED;
            return ST_ERR_FAILED;
        }
        result->suggestions[1].based_on = NULL;
        result->suggestions[1].confidence = confidence;
        n_suggestions = 2;
    }

    result->suggestion_count = n_suggestions;
    st_free_token_array(&cmd);
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

        if (ctype == ST_TYPE_LITERAL) {
            child_entry_t *c = find_literal_child(state, ctext);
            if (c) {
                ring[tail].state_idx = c->target;
                ring[tail].token_idx = entry.token_idx + 1;
                tail = (tail + 1) % VERIFY_ALL_RING_CAP;
            }
        }

        uint16_t compat = compat_mask(ctype) & state->wildcard_mask;
        while (compat) {
            int t = __builtin_ctz(compat);
            compat &= ~(1u << t);
            child_entry_t *c = find_wildcard_child(state, (st_token_type_t)t);
            if (c) {
                ring[tail].state_idx = c->target;
                ring[tail].token_idx = entry.token_idx + 1;
                tail = (tail + 1) % VERIFY_ALL_RING_CAP;
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
        child_entry_t *c = get_child(node, i);
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
        child_entry_t *c = get_child(node, i);
        if (!c) continue;
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
        child_entry_t *c = get_child(node, i);
        if (!c) continue;

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
                nfa_dfs_render(ctx, policy, c->target, cur, true);
            } else {
                uint32_t next = nfa_new_state(ctx);
                if (fprintf(ctx->fp, "    Symbol %d -> %u\n", VSYM_BYTE_ANY, next) < 0) {
                    ctx->error = ST_ERR_IO; return;
                }
                nfa_dfs_render(ctx, policy, c->target, next, true);
            }
        }
    }
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
        child_entry_t *c = get_child(node, i);
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
 * memory failure), the policy may be partially modified. The caller should
 * treat the policy as invalid and call st_policy_free + st_policy_new to
 * recover. For transactional loading, use clear_first=true.
 */
st_error_t st_policy_load(st_policy_t *policy, const char *path, bool clear_first)
{
    if (!policy || !path) return ST_ERR_INVALID;

    if (clear_first) {
        /* Clear active patterns and state (arena memory retained) */
        for (size_t i = 0; i < policy->states.count; i++) {
            free(policy->states.states[i].children);
            policy->states.states[i].children = NULL;
        }
        policy->states.count = 1;
        policy->patterns.count = 0;
        policy->pattern_count = 0;
        policy->children_count = 0;
        for (int i = 0; i < FILTER_POS_LEVELS; i++) {
            vacuum_filter_destroy(policy->pos_filters[i]);
            policy->pos_filters[i] = NULL;
            policy->pos_built_epoch[i] = 0;
        }
        policy->epoch++;
    }

    FILE *fp = fopen(path, "r");
    if (!fp) return ST_ERR_IO;

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

        /* Must start with version header */
        if (!got_header) {
            if (strncmp(line, "# CPL v", 7) != 0) {
                fclose(fp);
                return ST_ERR_FORMAT;
            }
            int version = atoi(line + 7);
            if (version != ST_SERIALIZATION_VERSION) {
                fclose(fp);
                return ST_ERR_FORMAT;
            }
            got_header = true;
            continue;
        }

        /* After header: pattern count line (skip) or patterns */
        if (!in_patterns) {
            if (strncmp(line, "# patterns:", 11) == 0) continue;
            in_patterns = true;
        }

        /* Footer: CRC32 — marks end of patterns */
        if (strncmp(line, "# CRC32: ", 9) == 0) {
            char *end;
            expected_crc = (uint32_t)strtoul(line + 9, &end, 16);
            if (end != line + 17) {
                fclose(fp);
                return ST_ERR_FORMAT;
            }
            got_crc = true;
            break;
        }

        /* Comment lines within pattern section (skip) */
        if (line[0] == '#') continue;

        /* Pattern line */
        size_t plen = strlen(line);
        computed_crc = crc32_compute(line, plen, computed_crc);
        computed_crc = crc32_compute("\n", 1, computed_crc);

        st_error_t err = st_policy_add(policy, line);
        if (err != ST_OK) {
            fclose(fp);
            return err;
        }
    }

    fclose(fp);

    if (!got_header || !got_crc) return ST_ERR_FORMAT;
    if (computed_crc != expected_crc) return ST_ERR_FORMAT;

    return ST_OK;
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
    return sizeof(st_policy_t) + filter_bytes + states_alloc + policy->children_alloc * sizeof(child_entry_t) + patterns_alloc;
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
 * POLICY EXPANSION SUGGESTIONS (Miner — Step 2 only)
 * ============================================================ */

/* Next-wider type in the lattice. */
static st_token_type_t next_wider_type(st_token_type_t t)
{
    switch (t) {
        case ST_TYPE_HEXHASH:     return ST_TYPE_NUMBER;
        case ST_TYPE_NUMBER:      return ST_TYPE_VALUE;
        case ST_TYPE_IPV4:        return ST_TYPE_VALUE;
        case ST_TYPE_WORD:        return ST_TYPE_VALUE;
        case ST_TYPE_QUOTED:      return ST_TYPE_QUOTED_SPACE;
        case ST_TYPE_QUOTED_SPACE:return ST_TYPE_VALUE;
        case ST_TYPE_FILENAME:    return ST_TYPE_REL_PATH;
        case ST_TYPE_REL_PATH:    return ST_TYPE_PATH;
        case ST_TYPE_ABS_PATH:    return ST_TYPE_PATH;
        case ST_TYPE_PATH:        return ST_TYPE_ANY;
        case ST_TYPE_URL:         return ST_TYPE_ANY;
        case ST_TYPE_VALUE:       return ST_TYPE_ANY;
        case ST_TYPE_ANY:         return ST_TYPE_ANY;
        default:                   return t;
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
