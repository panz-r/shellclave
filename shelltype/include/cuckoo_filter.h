/**
 * cuckoo_filter.h - Cuckoo filter for approximate set membership with deletion support
 *
 * A cuckoo filter is a probabilistic data structure that supports:
 *   - Insert: add an item to the set
 *   - Lookup: test if an item is possibly in the set (with false positives)
 *   - Delete: remove an item from the set
 *
 * Based on: "Cuckoo Filter: Practically Better Than Bloom" (Fan et al., CoNEXT 2014)
 *
 * Design choices:
 *   - Default bucket size b=4 (95% load factor, good space/performance tradeoff)
 *   - Partial-key cuckoo hashing for O(1) alternate location computation
 *   - Fingerprint size capped at 32 bits
 *   - Table size rounded up to next power of 2 for efficient modulo via bitmask
 *
 * Memory layout:
 *   - Single allocation: struct header followed immediately by the table
 *   - Table organized into 64-byte sets (one cache line each)
 *   - Fingerprints are bit-packed within each set
 *   - No entry crosses a set boundary (avoids cross-cacheline loads)
 *   - For fp_bits=10: 51 entries per set (510/512 bits, 0.4% waste)
 *   - For fp_bits=16: 32 entries per set (0 waste)
 *   - For fp_bits=32: 16 entries per set (0 waste)
 *
 * Hash-only API:
 *   All operations take a uint64_t hash, not raw data.
 *   The filter derives fingerprint and bucket index from the hash.
 *   Fingerprint size is capped at 32 bits.
 */

#ifndef CUCKOO_FILTER_H
#define CUCKOO_FILTER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration constants
 * ============================================================================ */

/** Default bucket size (entries per bucket). b=4 gives ~95% load factor. */
#define CUCKOO_DEFAULT_BUCKET_SIZE 4

/** Default fingerprint size in bits. 10 bits gives ~0.2% FPR at 95% load. */
#define CUCKOO_DEFAULT_FINGERPRINT_BITS 10

/** Maximum number of kicks during insertion before declaring filter full */
#define CUCKOO_MAX_KICKS 200

/** Minimum fingerprint size (must be >= 1) */
#define CUCKOO_MIN_FINGERPRINT_BITS 1

/** Maximum fingerprint size. Capped at 32 to keep bit-packing simple
 *  (each entry fits within a uint64_t, at most 2 words per access). */
#define CUCKOO_MAX_FINGERPRINT_BITS 32

/** Minimum bucket size */
#define CUCKOO_MIN_BUCKET_SIZE 1

/** Maximum bucket size */
#define CUCKOO_MAX_BUCKET_SIZE 16

/** Bytes per cache-line set. Must be a power of 2. */
#define CUCKOO_SET_BYTES 64

/** Words per cache-line set (uint64_t). */
#define CUCKOO_SET_WORDS (CUCKOO_SET_BYTES / sizeof(uint64_t))

/* ============================================================================
 * Error codes
 * ============================================================================ */

typedef enum {
    CUCKOO_OK = 0,
    CUCKOO_ERR_INVALID_PARAM,   /* Invalid parameter (null ptr, bad size, etc.) */
    CUCKOO_ERR_FULL,            /* Filter is full, cannot insert */
    CUCKOO_ERR_NOT_FOUND,       /* Item not found for deletion */
    CUCKOO_ERR_DUP_OVERFLOW,    /* Same item inserted too many times */
    CUCKOO_ERR_ALLOC,           /* Memory allocation failed */
} cuckoo_err_t;

/* ============================================================================
 * Cuckoo filter structure
 *
 * Memory layout:
 *   cuckoo_filter_t
 *   └── table[num_sets][CUCKOO_SET_WORDS]  (embedded after struct)
 *
 * Each set is 64 bytes (one cache line). Entries are bit-packed within
 * a set; no entry crosses a set boundary.
 * ============================================================================ */

typedef struct cuckoo_filter {
    uint32_t  num_entries;        /* Total entry capacity */
    uint32_t  count;              /* Items currently stored */
    uint32_t  num_buckets;        /* Number of buckets (power of 2) */
    uint16_t  entries_per_set;    /* Entries that fit in one 64-byte set */
    uint16_t  num_sets;           /* Number of cache-line sets in table */
    uint8_t   fingerprint_bits;   /* Bits per fingerprint (1-32) */
    uint8_t   bucket_size;        /* Entries per bucket */
    uint8_t   max_kicks;          /* Max cuckoo kicks before declaring full */
    uint32_t  bucket_mask;        /* num_buckets - 1 (for fast modulo) */

    /* uint64_t table[num_sets][CUCKOO_SET_WORDS] follows in memory */
} cuckoo_filter_t;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

/**
 * Create a new cuckoo filter.
 *
 * Single allocation: struct + table in one malloc.
 *
 * @param capacity     Expected maximum number of items
 * @param bucket_size  Entries per bucket (1-16), or 0 for default (4)
 * @param fp_bits      Fingerprint size in bits, 1-32 (0 for default 10)
 * @param max_kicks    Max cuckoo kicks (0 for default 200)
 * @return             Pointer to allocated filter, or NULL on failure
 */
cuckoo_filter_t *cuckoo_filter_create(size_t capacity, uint8_t bucket_size,
                                       uint8_t fp_bits, uint8_t max_kicks);

/**
 * Destroy a cuckoo filter and free all memory.
 * @param cf  Filter to destroy (NULL is safe)
 */
void cuckoo_filter_destroy(cuckoo_filter_t *cf);

/**
 * Reset a cuckoo filter to empty state (keeps allocation).
 * @param cf  Filter to reset (must not be NULL)
 * @return    CUCKOO_OK on success
 */
cuckoo_err_t cuckoo_filter_reset(cuckoo_filter_t *cf);

/* ============================================================================
 * Core operations
 *
 * All operations take a 64-bit hash, not raw data.
 * The caller computes the hash (any hash function).
 * The filter derives fingerprint and bucket index from the hash.
 * ============================================================================ */

/**
 * Insert an item into the filter.
 *
 * @param cf    Filter (must not be NULL)
 * @param hash  64-bit hash of the item (caller-chosen hash function)
 * @return      CUCKOO_OK on success, CUCKOO_ERR_FULL if filter is full,
 *              CUCKOO_ERR_DUP_OVERFLOW if same item inserted too many times
 */
cuckoo_err_t cuckoo_filter_insert(cuckoo_filter_t *cf, uint64_t hash);

/**
 * Check if an item is possibly in the filter.
 *
 * @param cf    Filter (must not be NULL)
 * @param hash  64-bit hash of the item
 * @return      true if possibly present (may be false positive),
 *              false if definitely not present
 */
bool cuckoo_filter_lookup(const cuckoo_filter_t *cf, uint64_t hash);

/**
 * Delete an item from the filter.
 *
 * @param cf    Filter (must not be NULL)
 * @param hash  64-bit hash of the item
 * @return      CUCKOO_OK on success, CUCKOO_ERR_NOT_FOUND if item not present
 */
cuckoo_err_t cuckoo_filter_delete(cuckoo_filter_t *cf, uint64_t hash);

/* ============================================================================
 * Statistics and properties
 * ============================================================================ */

/** Get number of items currently stored */
static inline size_t cuckoo_filter_count(const cuckoo_filter_t *cf) {
    return cf->count;
}

/** Get total capacity (number of entries) */
static inline size_t cuckoo_filter_capacity(const cuckoo_filter_t *cf) {
    return cf->num_entries;
}

/** Get load factor (0.0 to 1.0) */
static inline double cuckoo_filter_load_factor(const cuckoo_filter_t *cf) {
    return (double)cf->count / (double)cf->num_entries;
}

/** Get memory usage in bytes (filter structure + table) */
size_t cuckoo_filter_memory_bytes(const cuckoo_filter_t *cf);

/** Get bits per item at current load */
static inline double cuckoo_filter_bits_per_item(const cuckoo_filter_t *cf) {
    if (cf->count == 0) return 0.0;
    return (double)(cf->num_entries * cf->fingerprint_bits) / (double)cf->count;
}

/** Estimate false positive rate based on current parameters */
double cuckoo_filter_estimated_fpr(const cuckoo_filter_t *cf);

/* ============================================================================
 * Hash helpers (exposed for testing)
 * ============================================================================ */

/**
 * Compute fingerprint from hash.
 * Returns a value in [1, 2^fp_bits - 1] (never 0, since 0 means empty).
 */
uint32_t cuckoo_fingerprint(uint64_t hash, uint8_t fp_bits);

/**
 * Compute primary bucket index from hash.
 * Uses bitmask: hash >> 32 & bucket_mask (num_buckets is power of 2).
 */
size_t cuckoo_hash_index(uint64_t hash, uint32_t bucket_mask);

/**
 * Compute alternate bucket index from current index and fingerprint hash.
 * i2 = i1 ^ mix32(fingerprint)
 */
size_t cuckoo_alt_index(size_t current_index, uint32_t fingerprint,
                         uint32_t bucket_mask);

#ifdef __cplusplus
}
#endif

#endif /* CUCKOO_FILTER_H */
