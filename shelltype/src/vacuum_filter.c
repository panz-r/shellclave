/**
 * vacuum_filter.c - Vacuum filter implementation
 *
 * A vacuum filter improves on cuckoo filters in three key ways:
 *
 * 1. Multi-range alternate function:
 *    Cuckoo filters require the table size to be a power of 2 (for XOR-based
 *    bucket indexing). When the ideal bucket count falls between powers of 2,
 *    up to ~50% of space is wasted (~25% on average). Vacuum filters lift this
 *    restriction by using a "chunked" design: the table is divided into chunks
 *    of size L (the alternate range), and both candidate buckets fall within
 *    the same chunk. The key insight is that different items can use different
 *    AR sizes - most use small ARs (good cache locality) while a few use large
 *    ARs (avoid fingerprint gathering). This achieves high load factor AND
 *    good locality simultaneously.
 *
 * 2. BFS-lookahead insertion:
 *    Standard cuckoo hashing evicts a random fingerprint and hopes its
 *    alternate bucket has space. Vacuum filters look one step ahead: before
 *    evicting, they check if ANY fingerprint in the current bucket has an
 *    empty alternate slot. If so, they evict that specific fingerprint to
 *    the empty slot, completing the insertion in 2 steps. This reduces
 *    eviction chain length and improves both load factor and throughput.
 *
 * 3. Fast modulo for arbitrary table sizes:
 *    When the table size m is not a power of 2, we cannot use bitwise AND
 *    for modulo. Instead we use the multiplication-based mapping:
 *      map(x, m) = (x * m) >> 32
 *    This produces a roughly uniform distribution over [0, m-1] using only
 *    two instructions, comparable in speed to bitwise AND.
 *
 * Memory layout:
 *   - Single allocation: struct + table in one malloc
 *   - Table organized into 64-byte sets (one cache line each)
 *   - Fingerprints are bit-packed within each set
 *   - No entry crosses a set boundary (avoids cross-cacheline loads)
 *
 * Hash-only API:
 *   All operations take a uint64_t hash, not raw data.
 *   The filter derives fingerprint and bucket index from the hash.
 *   Fingerprint size is capped at 32 bits.
 */

#include "vacuum_filter.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>

/* ============================================================================
 * Hash functions (internal mixer for fingerprint remapping)
 * ============================================================================ */

static uint32_t mix32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x85ebca6bu;
    x ^= x >> 13;
    x *= 0xc2b2ae35u;
    x ^= x >> 16;
    return x;
}

/* ============================================================================
 * Bit-packed set access
 *
 * Each set is 8 uint64_t words = 64 bytes = 1 cache line.
 * Entries are bit-packed sequentially within a set.
 * No entry crosses a set boundary.
 *
 * For fp_bits=10: 51 entries per set (510 bits used, 2 wasted)
 * For fp_bits=16: 32 entries per set (512 bits, exact)
 * For fp_bits=32: 16 entries per set (512 bits, exact)
 *
 * At most 2 uint64_t words are loaded per access, guaranteed within
 * the same cache line.
 * ============================================================================ */

static inline uint32_t set_get(const uint64_t *set, size_t off, uint8_t fp_bits)
{
    size_t bp = off * fp_bits;
    size_t wi = bp / 64;
    size_t bo = bp % 64;
    uint64_t val = set[wi] >> bo;
    if (wi + 1 < VACUUM_SET_WORDS && bo + fp_bits > 64)
        val |= set[wi + 1] << (64 - bo);
    return (uint32_t)(val & ((1ULL << fp_bits) - 1));
}

static inline void set_set(uint64_t *set, size_t off, uint8_t fp_bits, uint32_t v)
{
    size_t bp = off * fp_bits;
    size_t wi = bp / 64;
    size_t bo = bp % 64;
    uint64_t mask = ((1ULL << fp_bits) - 1) << bo;
    set[wi] = (set[wi] & ~mask) | ((uint64_t)v << bo);
    if (wi + 1 < VACUUM_SET_WORDS && bo + fp_bits > 64) {
        uint64_t mask2 = ((1ULL << fp_bits) - 1) >> (64 - bo);
        set[wi + 1] = (set[wi + 1] & ~mask2) | ((uint64_t)v >> (64 - bo));
    }
}

/* Get pointer to the start of set si within the embedded table */
static inline uint64_t *vf_set(vacuum_filter_t *vf, size_t si)
{
    return (uint64_t *)(vf + 1) + si * VACUUM_SET_WORDS;
}

static inline const uint64_t *vf_set_const(const vacuum_filter_t *vf, size_t si)
{
    return (const uint64_t *)(vf + 1) + si * VACUUM_SET_WORDS;
}

/* Get/set entry at global index idx */
static inline uint32_t vf_get(const vacuum_filter_t *vf, size_t idx)
{
    size_t si = idx / vf->entries_per_set;
    size_t off = idx % vf->entries_per_set;
    return set_get(vf_set_const(vf, si), off, vf->fingerprint_bits);
}

static inline void vf_set_entry(vacuum_filter_t *vf, size_t idx, uint32_t v)
{
    size_t si = idx / vf->entries_per_set;
    size_t off = idx % vf->entries_per_set;
    set_set(vf_set(vf, si), off, vf->fingerprint_bits, v);
}

/* ============================================================================
 * Fingerprint and bucket index computation (from hash)
 * ============================================================================ */

uint32_t vacuum_fingerprint(uint64_t hash, uint8_t fp_bits)
{
    uint32_t fp = (uint32_t)(hash & ((1ULL << fp_bits) - 1));
    return fp ? fp : 1;
}

size_t vacuum_hash_index(uint64_t hash, size_t num_buckets)
{
    return ((uint64_t)(hash >> 32) * num_buckets) >> 32;
}

/* ============================================================================
 * Alternate function
 *
 * The multi-range alternate function assigns each item to one of 4 AR sizes
 * based on the fingerprint's lower 2 bits. Items with small ARs have their
 * two candidate buckets close together (good cache locality). Items with
 * large ARs can reach farther across the table (avoid fingerprint gathering).
 *
 * For small tables (< 2^18 items), we use a different alternate function
 * that provides better distribution without the RangeSelection overhead.
 * ============================================================================ */

size_t vacuum_alt_index(const vacuum_filter_t *vf, size_t current_index, uint32_t fingerprint)
{
    if (vf->use_small_table_alt) {
        size_t delta = (size_t)mix32(fingerprint) % vf->num_buckets;
        size_t bp = (current_index + vf->num_buckets - delta) % vf->num_buckets;
        bp = (vf->num_buckets - 1 - bp + delta) % vf->num_buckets;
        return bp;
    }

    size_t l = vf->ar[fingerprint % VACUUM_NUM_AR];
    size_t delta = (size_t)mix32(fingerprint) % l;
    return current_index ^ delta;
}

/* ============================================================================
 * AR size selection (RangeSelection algorithm)
 * ============================================================================ */

static size_t range_selection(size_t num_items, double target_load, double ratio)
{
    size_t b = VACUUM_DEFAULT_BUCKET_SIZE;
    size_t m = (size_t)ceil((double)num_items / (b * target_load));
    size_t n = (size_t)(ratio * (double)num_items);

    size_t l = 1;
    while (l < m) {
        size_t c = m / l;
        if (c == 0) { l *= 2; continue; }

        double avg = (double)n / (double)c;
        double max_load = avg + 1.5 * sqrt(2.0 * avg * log((double)c));
        double capacity = 0.97 * (double)(b * l);

        if (max_load < capacity) break;
        l *= 2;
    }

    return l;
}

static void compute_ar_sizes(vacuum_filter_t *vf, size_t num_items)
{
    double target_load = 0.95;

    for (int i = 0; i < VACUUM_NUM_AR; i++) {
        double ratio = 1.0 - (double)i / (double)VACUUM_NUM_AR;
        vf->ar[i] = range_selection(num_items, target_load, ratio);
        if (vf->ar[i] < 1) vf->ar[i] = 1;
    }

    vf->ar[VACUUM_NUM_AR - 1] *= 2;
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

vacuum_filter_t *vacuum_filter_create(size_t capacity, uint8_t bucket_size,
                                       uint8_t fp_bits, uint8_t max_evicts)
{
    if (capacity == 0) return NULL;

    if (bucket_size == 0) bucket_size = VACUUM_DEFAULT_BUCKET_SIZE;
    if (fp_bits == 0) fp_bits = VACUUM_DEFAULT_FINGERPRINT_BITS;
    if (max_evicts == 0) max_evicts = VACUUM_MAX_EVICTS;

    if (fp_bits < VACUUM_MIN_FINGERPRINT_BITS || fp_bits > VACUUM_MAX_FINGERPRINT_BITS)
        return NULL;

    /* Size the table for the expected capacity at ~95% load factor.
     * Unlike cuckoo filters, we do NOT round up to a power of 2. */
    size_t num_buckets = (size_t)ceil((double)capacity / (bucket_size * 0.95));
    if (num_buckets < 1) num_buckets = 1;

    size_t num_entries = num_buckets * bucket_size;

    /* Compute entries per set: max entries that fit in 64 bytes (512 bits) */
    size_t entries_per_set = 512 / fp_bits;
    size_t num_sets = (num_entries + entries_per_set - 1) / entries_per_set;

    /* Single allocation: struct + table */
    size_t alloc_size = sizeof(vacuum_filter_t) + num_sets * VACUUM_SET_BYTES;
    vacuum_filter_t *vf = (vacuum_filter_t *)calloc(1, alloc_size);
    if (!vf) return NULL;

    vf->num_entries = (uint32_t)num_entries;
    vf->count = 0;
    vf->num_buckets = (uint32_t)num_buckets;
    vf->entries_per_set = (uint16_t)entries_per_set;
    vf->num_sets = (uint16_t)num_sets;
    vf->fingerprint_bits = fp_bits;
    vf->bucket_size = bucket_size;
    vf->max_evicts = max_evicts;
    vf->use_small_table_alt = (capacity < VACUUM_SMALL_TABLE_THRESHOLD);

    compute_ar_sizes(vf, capacity);

    return vf;
}

void vacuum_filter_destroy(vacuum_filter_t *vf)
{
    free(vf);
}

vacuum_err_t vacuum_filter_reset(vacuum_filter_t *vf)
{
    if (!vf) return VACUUM_ERR_INVALID_PARAM;
    size_t table_bytes = vf->num_sets * VACUUM_SET_BYTES;
    memset((uint64_t *)(vf + 1), 0, table_bytes);
    vf->count = 0;
    return VACUUM_OK;
}

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

static int find_empty_slot(const vacuum_filter_t *vf, size_t bucket_idx)
{
    size_t base = bucket_idx * vf->bucket_size;
    for (size_t i = 0; i < vf->bucket_size; i++) {
        if (vf_get(vf, base + i) == 0) return (int)i;
    }
    return -1;
}

static int find_fingerprint(const vacuum_filter_t *vf, size_t bucket_idx, uint32_t fp)
{
    size_t base = bucket_idx * vf->bucket_size;
    for (size_t i = 0; i < vf->bucket_size; i++) {
        if (vf_get(vf, base + i) == fp) return (int)i;
    }
    return -1;
}

/* ============================================================================
 * Core operations
 *
 * Insert (BFS-lookahead):
 *   1. Compute fingerprint and both candidate buckets (B1, B2).
 *   2. If either bucket has an empty slot, place the fingerprint there.
 *   3. If both are full, BFS-lookahead: check all fingerprints in the
 *      selected bucket to see if any has an empty alternate slot.
 *      If found, evict that fingerprint to the empty slot and place
 *      the new fingerprint in its former slot (2-step insertion).
 *   4. If lookahead fails, fall back to standard cuckoo eviction.
 *
 * Lookup:
 *   Check both candidate buckets for the fingerprint.
 *
 * Delete:
 *   Remove one copy of the fingerprint from either candidate bucket.
 * ============================================================================ */

vacuum_err_t vacuum_filter_insert(vacuum_filter_t *vf, uint64_t hash)
{
    if (!vf) return VACUUM_ERR_INVALID_PARAM;

    uint32_t fp = vacuum_fingerprint(hash, vf->fingerprint_bits);
    size_t b1 = vacuum_hash_index(hash, vf->num_buckets);
    size_t b2 = vacuum_alt_index(vf, b1, fp);

    /* Fast path: try both candidate buckets for an empty slot */
    int slot = find_empty_slot(vf, b1);
    if (slot >= 0) {
        vf_set_entry(vf, b1 * vf->bucket_size + (size_t)slot, fp);
        vf->count++;
        return VACUUM_OK;
    }
    slot = find_empty_slot(vf, b2);
    if (slot >= 0) {
        vf_set_entry(vf, b2 * vf->bucket_size + (size_t)slot, fp);
        vf->count++;
        return VACUUM_OK;
    }

    /* Both buckets full. BFS-lookahead */
    size_t b = ((b1 + b2) & 1) ? b1 : b2;

    for (uint8_t n = 0; n < vf->max_evicts; n++) {
        size_t base = b * vf->bucket_size;
        for (size_t i = 0; i < vf->bucket_size; i++) {
            uint32_t fp_in_slot = vf_get(vf, base + i);
            if (fp_in_slot == 0) continue;

            size_t alt = vacuum_alt_index(vf, b, fp_in_slot);
            int alt_slot = find_empty_slot(vf, alt);
            if (alt_slot >= 0) {
                vf_set_entry(vf, alt * vf->bucket_size + (size_t)alt_slot, fp_in_slot);
                vf_set_entry(vf, base + i, fp);
                vf->count++;
                return VACUUM_OK;
            }
        }

        /* Lookahead failed, fall back to standard eviction */
        size_t evict_slot = mix32(n) % vf->bucket_size;

        uint32_t temp = vf_get(vf, base + evict_slot);
        vf_set_entry(vf, base + evict_slot, fp);
        fp = temp;

        b = vacuum_alt_index(vf, b, fp);

        slot = find_empty_slot(vf, b);
        if (slot >= 0) {
            vf_set_entry(vf, b * vf->bucket_size + (size_t)slot, fp);
            vf->count++;
            return VACUUM_OK;
        }
    }

    return VACUUM_ERR_FULL;
}

bool vacuum_filter_lookup(const vacuum_filter_t *vf, uint64_t hash)
{
    if (!vf) return false;

    uint32_t fp = vacuum_fingerprint(hash, vf->fingerprint_bits);
    size_t b1 = vacuum_hash_index(hash, vf->num_buckets);
    size_t b2 = vacuum_alt_index(vf, b1, fp);

    return find_fingerprint(vf, b1, fp) >= 0 || find_fingerprint(vf, b2, fp) >= 0;
}

vacuum_err_t vacuum_filter_delete(vacuum_filter_t *vf, uint64_t hash)
{
    if (!vf) return VACUUM_ERR_INVALID_PARAM;

    uint32_t fp = vacuum_fingerprint(hash, vf->fingerprint_bits);
    size_t b1 = vacuum_hash_index(hash, vf->num_buckets);
    size_t b2 = vacuum_alt_index(vf, b1, fp);

    int slot = find_fingerprint(vf, b1, fp);
    if (slot >= 0) {
        vf_set_entry(vf, b1 * vf->bucket_size + (size_t)slot, 0);
        vf->count--;
        return VACUUM_OK;
    }

    slot = find_fingerprint(vf, b2, fp);
    if (slot >= 0) {
        vf_set_entry(vf, b2 * vf->bucket_size + (size_t)slot, 0);
        vf->count--;
        return VACUUM_OK;
    }

    return VACUUM_ERR_NOT_FOUND;
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

size_t vacuum_filter_memory_bytes(const vacuum_filter_t *vf)
{
    if (!vf) return 0;
    return sizeof(vacuum_filter_t) + vf->num_sets * VACUUM_SET_BYTES;
}

double vacuum_filter_estimated_fpr(const vacuum_filter_t *vf)
{
    if (!vf || vf->count == 0) return 0.0;
    double load = (double)vf->count / (double)vf->num_entries;
    double fp = (double)(2 * vf->bucket_size) / (double)(1ULL << vf->fingerprint_bits);
    return fp * load;
}
