/**
 * cuckoo_filter.c - Cuckoo filter implementation
 *
 * A cuckoo filter is a probabilistic data structure for set membership queries
 * that supports insertion, lookup, AND deletion. It stores only short
 * fingerprints (not full keys) in a cuckoo hash table.
 *
 * METHOD CHOICES
 * ==============
 *
 * Partial-key cuckoo hashing:
 *   Standard cuckoo hashing requires the original key to compute the alternate
 *   bucket during eviction. Since we store only fingerprints (to save space),
 *   we cannot recover the original key. Partial-key cuckoo hashing solves this
 *   by deriving both candidate buckets from the fingerprint itself:
 *     i1 = hash(x)
 *     i2 = i1 XOR hash(fingerprint)
 *   The XOR property ensures i1 = i2 XOR hash(fingerprint), so given any
 *   bucket index and the stored fingerprint, we can compute the alternate
 *   bucket without the original key. This is the key insight that makes
 *   cuckoo filters possible.
 *
 * Fingerprint non-zero invariant:
 *   Entry value 0 always means "empty." Fingerprints are forced to the range
 *   [1, 2^f - 1] so that a stored value of 0 is unambiguous. If a hash
 *   produces 0, it is bumped to 1. This avoids the need for a separate
 *   occupancy bitmap.
 *
 * Power-of-2 table size:
 *   The number of buckets is rounded up to the next power of 2. This lets us
 *   use bitwise AND with (num_buckets - 1) instead of modulo for bucket
 *   indexing, which is significantly faster. The tradeoff is up to ~2x space
 *   overhead vs. an exact-sized table, but the simplicity and speed justify it.
 *
 * Bucket size b=4 (default):
 *   With 4 entries per bucket, the table achieves ~95% load factor before
 *   insertions start failing. This is the sweet spot identified in the
 *   original paper: larger buckets increase occupancy but require longer
 *   fingerprints to maintain the same FPR (more entries probed per lookup).
 *
 * Eviction strategy:
 *   When both candidate buckets are full, we evict a randomly chosen entry
 *   and re-insert its fingerprint into its alternate bucket. This chain of
 *   evictions continues until an empty slot is found or max_kicks is reached.
 *   The amortized cost is O(1), and the max_kicks bound prevents infinite
 *   loops when the table is genuinely full.
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

#include "cuckoo_filter.h"

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
 * ============================================================================ */

static inline uint32_t set_get(const uint64_t *set, size_t off, uint8_t fp_bits)
{
    size_t bp = off * fp_bits;
    size_t wi = bp / 64;
    size_t bo = bp % 64;
    uint64_t val = set[wi] >> bo;
    if (wi + 1 < CUCKOO_SET_WORDS && bo + fp_bits > 64)
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
    if (wi + 1 < CUCKOO_SET_WORDS && bo + fp_bits > 64) {
        uint64_t mask2 = ((1ULL << fp_bits) - 1) >> (64 - bo);
        set[wi + 1] = (set[wi + 1] & ~mask2) | ((uint64_t)v >> (64 - bo));
    }
}

static inline uint64_t *cf_set(cuckoo_filter_t *cf, size_t si)
{
    return (uint64_t *)(cf + 1) + si * CUCKOO_SET_WORDS;
}

static inline const uint64_t *cf_set_const(const cuckoo_filter_t *cf, size_t si)
{
    return (const uint64_t *)(cf + 1) + si * CUCKOO_SET_WORDS;
}

static inline uint32_t cf_get(const cuckoo_filter_t *cf, size_t idx)
{
    size_t si = idx / cf->entries_per_set;
    size_t off = idx % cf->entries_per_set;
    return set_get(cf_set_const(cf, si), off, cf->fingerprint_bits);
}

static inline void cf_set_entry(cuckoo_filter_t *cf, size_t idx, uint32_t v)
{
    size_t si = idx / cf->entries_per_set;
    size_t off = idx % cf->entries_per_set;
    set_set(cf_set(cf, si), off, cf->fingerprint_bits, v);
}

/* ============================================================================
 * Fingerprint and bucket index computation (from hash)
 * ============================================================================ */

uint32_t cuckoo_fingerprint(uint64_t hash, uint8_t fp_bits)
{
    uint32_t fp = (uint32_t)(hash & ((1ULL << fp_bits) - 1));
    return fp ? fp : 1;
}

size_t cuckoo_hash_index(uint64_t hash, uint32_t bucket_mask)
{
    return (size_t)(hash >> 32) & bucket_mask;
}

/* Compute the alternate bucket index from the current bucket and fingerprint.
 * i2 = i1 XOR mix32(fp). The XOR symmetry means i1 = i2 XOR mix32(fp). */
size_t cuckoo_alt_index(size_t current_index, uint32_t fingerprint,
                         uint32_t bucket_mask)
{
    uint32_t h = mix32(fingerprint);
    return (current_index ^ h) & bucket_mask;
}

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

static size_t next_power_of_2(size_t n) {
    if (n == 0) return 1;
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;
    return n + 1;
}

cuckoo_filter_t *cuckoo_filter_create(size_t capacity, uint8_t bucket_size,
                                       uint8_t fp_bits, uint8_t max_kicks) {
    if (capacity == 0) return NULL;

    if (bucket_size == 0) bucket_size = CUCKOO_DEFAULT_BUCKET_SIZE;
    if (fp_bits == 0) fp_bits = CUCKOO_DEFAULT_FINGERPRINT_BITS;
    if (max_kicks == 0) max_kicks = CUCKOO_MAX_KICKS;

    if (bucket_size < CUCKOO_MIN_BUCKET_SIZE || bucket_size > CUCKOO_MAX_BUCKET_SIZE)
        return NULL;
    if (fp_bits < CUCKOO_MIN_FINGERPRINT_BITS || fp_bits > CUCKOO_MAX_FINGERPRINT_BITS)
        return NULL;

    size_t total_entries = (size_t)ceil((double)capacity / 0.95);
    size_t num_buckets = next_power_of_2((total_entries + bucket_size - 1) / bucket_size);
    if (num_buckets < 1) num_buckets = 1;

    size_t num_entries = num_buckets * bucket_size;

    /* Compute entries per set */
    size_t entries_per_set = 512 / fp_bits;
    size_t num_sets = (num_entries + entries_per_set - 1) / entries_per_set;

    /* Single allocation: struct + table */
    size_t alloc_size = sizeof(cuckoo_filter_t) + num_sets * CUCKOO_SET_BYTES;
    cuckoo_filter_t *cf = (cuckoo_filter_t *)calloc(1, alloc_size);
    if (!cf) return NULL;

    cf->num_entries = (uint32_t)num_entries;
    cf->count = 0;
    cf->num_buckets = (uint32_t)num_buckets;
    cf->entries_per_set = (uint16_t)entries_per_set;
    cf->num_sets = (uint16_t)num_sets;
    cf->fingerprint_bits = fp_bits;
    cf->bucket_size = bucket_size;
    cf->max_kicks = max_kicks;
    cf->bucket_mask = (uint32_t)(num_buckets - 1);

    return cf;
}

void cuckoo_filter_destroy(cuckoo_filter_t *cf) {
    free(cf);
}

cuckoo_err_t cuckoo_filter_reset(cuckoo_filter_t *cf) {
    if (!cf) return CUCKOO_ERR_INVALID_PARAM;
    size_t table_bytes = cf->num_sets * CUCKOO_SET_BYTES;
    memset((uint64_t *)(cf + 1), 0, table_bytes);
    cf->count = 0;
    return CUCKOO_OK;
}

/* ============================================================================
 * Internal helpers
 * ============================================================================ */

static int find_empty_slot(const cuckoo_filter_t *cf, size_t bucket_idx) {
    size_t base = bucket_idx * cf->bucket_size;
    for (size_t i = 0; i < cf->bucket_size; i++) {
        if (cf_get(cf, base + i) == 0) return (int)i;
    }
    return -1;
}

static int find_fingerprint(const cuckoo_filter_t *cf, size_t bucket_idx, uint32_t fp) {
    size_t base = bucket_idx * cf->bucket_size;
    for (size_t i = 0; i < cf->bucket_size; i++) {
        if (cf_get(cf, base + i) == fp) return (int)i;
    }
    return -1;
}

/* ============================================================================
 * Core operations
 * ============================================================================ */

cuckoo_err_t cuckoo_filter_insert(cuckoo_filter_t *cf, uint64_t hash) {
    if (!cf) return CUCKOO_ERR_INVALID_PARAM;

    uint32_t fp = cuckoo_fingerprint(hash, cf->fingerprint_bits);
    size_t i1 = cuckoo_hash_index(hash, cf->bucket_mask);
    size_t i2 = cuckoo_alt_index(i1, fp, cf->bucket_mask);

    /* Fast path: try both candidate buckets for an empty slot */
    int slot = find_empty_slot(cf, i1);
    if (slot >= 0) {
        cf_set_entry(cf, i1 * cf->bucket_size + (size_t)slot, fp);
        cf->count++;
        return CUCKOO_OK;
    }
    slot = find_empty_slot(cf, i2);
    if (slot >= 0) {
        cf_set_entry(cf, i2 * cf->bucket_size + (size_t)slot, fp);
        cf->count++;
        return CUCKOO_OK;
    }

    /* Slow path: both buckets full, must evict via cuckoo hashing */
    size_t i = ((i1 + i2) & 1) ? i1 : i2;

    for (uint8_t n = 0; n < cf->max_kicks; n++) {
        size_t base = i * cf->bucket_size;
        size_t evict_slot = mix32(n) % cf->bucket_size;

        uint32_t temp = cf_get(cf, base + evict_slot);
        cf_set_entry(cf, base + evict_slot, fp);
        fp = temp;

        i = cuckoo_alt_index(i, fp, cf->bucket_mask);

        slot = find_empty_slot(cf, i);
        if (slot >= 0) {
            cf_set_entry(cf, i * cf->bucket_size + (size_t)slot, fp);
            cf->count++;
            return CUCKOO_OK;
        }
    }

    return CUCKOO_ERR_FULL;
}

bool cuckoo_filter_lookup(const cuckoo_filter_t *cf, uint64_t hash) {
    if (!cf) return false;

    uint32_t fp = cuckoo_fingerprint(hash, cf->fingerprint_bits);
    size_t i1 = cuckoo_hash_index(hash, cf->bucket_mask);
    size_t i2 = cuckoo_alt_index(i1, fp, cf->bucket_mask);

    return find_fingerprint(cf, i1, fp) >= 0 || find_fingerprint(cf, i2, fp) >= 0;
}

cuckoo_err_t cuckoo_filter_delete(cuckoo_filter_t *cf, uint64_t hash) {
    if (!cf) return CUCKOO_ERR_INVALID_PARAM;

    uint32_t fp = cuckoo_fingerprint(hash, cf->fingerprint_bits);
    size_t i1 = cuckoo_hash_index(hash, cf->bucket_mask);
    size_t i2 = cuckoo_alt_index(i1, fp, cf->bucket_mask);

    int slot = find_fingerprint(cf, i1, fp);
    if (slot >= 0) {
        cf_set_entry(cf, i1 * cf->bucket_size + (size_t)slot, 0);
        cf->count--;
        return CUCKOO_OK;
    }

    slot = find_fingerprint(cf, i2, fp);
    if (slot >= 0) {
        cf_set_entry(cf, i2 * cf->bucket_size + (size_t)slot, 0);
        cf->count--;
        return CUCKOO_OK;
    }

    return CUCKOO_ERR_NOT_FOUND;
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

size_t cuckoo_filter_memory_bytes(const cuckoo_filter_t *cf) {
    if (!cf) return 0;
    return sizeof(cuckoo_filter_t) + cf->num_sets * CUCKOO_SET_BYTES;
}

double cuckoo_filter_estimated_fpr(const cuckoo_filter_t *cf) {
    if (!cf || cf->count == 0) return 0.0;
    double load = (double)cf->count / (double)cf->num_entries;
    double fp = (double)(2 * cf->bucket_size) / (double)(1ULL << cf->fingerprint_bits);
    return fp * load;
}
