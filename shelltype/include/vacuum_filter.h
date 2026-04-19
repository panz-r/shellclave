/**
 * vacuum_filter.h - Vacuum filter for approximate set membership
 *
 * A vacuum filter is a probabilistic data structure that improves on both
 * Bloom and cuckoo filters in space efficiency while maintaining similar
 * throughput. Key advantages:
 *
 *   - Smallest space among known AMQ structures (25% less than cuckoo on avg)
 *   - No power-of-2 table size restriction (avoids ~25% average waste)
 *   - Better data locality (alternate buckets often share a cache line)
 *   - Supports insertions, deletions, and duplicate handling
 *
 * Based on: "Vacuum Filters: More Space-Efficient and Faster Replacement
 * for Bloom and Cuckoo Filters" (Wang et al., PVLDB 2019)
 *
 * Design choices:
 *   - 4-slot buckets with multi-range alternate function (4 AR sizes)
 *   - BFS-lookahead insertion: checks 1 step ahead to reduce eviction chains
 *   - Fast modulo via (x * m) >> 32 for arbitrary table sizes
 *   - Fingerprint non-zero invariant (0 = empty entry)
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
 * Fingerprint size:
 *   - Capped at 32 bits. This is sufficient for all practical FPR targets
 *     and keeps the bit-packing logic simple (entries fit in uint64_t).
 */

#ifndef VACUUM_FILTER_H
#define VACUUM_FILTER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration constants
 * ============================================================================ */

/** Default bucket size (entries per bucket). b=4 is the standard. */
#define VACUUM_DEFAULT_BUCKET_SIZE 4

/** Default fingerprint size in bits. 10 bits gives ~0.2% FPR at 95% load. */
#define VACUUM_DEFAULT_FINGERPRINT_BITS 10

/** Maximum number of eviction steps before declaring insertion failed */
#define VACUUM_MAX_EVICTS 200

/** Number of alternate ranges in the multi-range design */
#define VACUUM_NUM_AR 4

/** Minimum fingerprint size (must be >= 1) */
#define VACUUM_MIN_FINGERPRINT_BITS 1

/** Maximum fingerprint size. Capped at 32 to keep bit-packing simple
 *  (each entry fits within a uint64_t, at most 2 words per access). */
#define VACUUM_MAX_FINGERPRINT_BITS 32

/** Threshold for using the small-table alternate function */
#define VACUUM_SMALL_TABLE_THRESHOLD (1 << 18)

/** Bytes per cache-line set. Must be a power of 2. */
#define VACUUM_SET_BYTES 64

/** Words per cache-line set (uint64_t). */
#define VACUUM_SET_WORDS (VACUUM_SET_BYTES / sizeof(uint64_t))

/* ============================================================================
 * Error codes
 * ============================================================================ */

typedef enum {
    VACUUM_OK = 0,
    VACUUM_ERR_INVALID_PARAM,
    VACUUM_ERR_FULL,
    VACUUM_ERR_NOT_FOUND,
    VACUUM_ERR_ALLOC,
} vacuum_err_t;

/* ============================================================================
 * Vacuum filter structure
 *
 * Memory layout:
 *   vacuum_filter_t
 *   └── table[num_sets][VACUUM_SET_WORDS]  (embedded after struct)
 *
 * Each set is 64 bytes (one cache line). Entries are bit-packed within
 * a set; no entry crosses a set boundary.
 * ============================================================================ */

typedef struct vacuum_filter {
    uint32_t  num_entries;         /* Total entry capacity */
    uint32_t  count;               /* Items currently stored */
    uint32_t  num_buckets;         /* Number of buckets (arbitrary, not power-of-2) */
    uint16_t  entries_per_set;     /* Entries that fit in one 64-byte set */
    uint16_t  num_sets;            /* Number of cache-line sets in table */
    uint8_t   fingerprint_bits;    /* Bits per fingerprint (1-32) */
    uint8_t   bucket_size;         /* Entries per bucket */
    uint8_t   max_evicts;          /* Max eviction steps before declaring full */
    uint8_t   use_small_table_alt; /* Use small-table alternate function */

    /* Multi-range alternate function parameters.
     * Four AR sizes determined by the RangeSelection algorithm.
     * Most items use small ARs (good locality), few use large ARs
     * (avoid fingerprint gathering and maintain high load factor). */
    size_t    ar[VACUUM_NUM_AR];   /* Alternate range sizes L[0]..L[3] */

    /* uint64_t table[num_sets][VACUUM_SET_WORDS] follows in memory */
} vacuum_filter_t;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

/**
 * Create a new vacuum filter.
 *
 * Single allocation: struct + table in one malloc.
 *
 * @param capacity     Expected maximum number of items
 * @param bucket_size  Entries per bucket (0 for default 4)
 * @param fp_bits      Fingerprint size in bits, 1-32 (0 for default 10)
 * @param max_evicts   Max eviction steps (0 for default 200)
 * @return             Pointer to allocated filter, or NULL on failure
 */
vacuum_filter_t *vacuum_filter_create(size_t capacity, uint8_t bucket_size,
                                       uint8_t fp_bits, uint8_t max_evicts);

/**
 * Destroy a vacuum filter and free all memory.
 * @param vf  Filter to destroy (NULL is safe)
 */
void vacuum_filter_destroy(vacuum_filter_t *vf);

/**
 * Reset a vacuum filter to empty state (keeps allocation).
 * @param vf  Filter to reset (must not be NULL)
 * @return    VACUUM_OK on success
 */
vacuum_err_t vacuum_filter_reset(vacuum_filter_t *vf);

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
 * Uses BFS-lookahead insertion: when both candidate buckets are full,
 * checks if any fingerprint in those buckets has an empty alternate slot
 * before starting a full eviction chain. This reduces eviction steps
 * and improves both load factor and insertion throughput.
 *
 * @param vf    Filter (must not be NULL)
 * @param hash  64-bit hash of the item (caller-chosen hash function)
 * @return      VACUUM_OK on success, VACUUM_ERR_FULL if filter is full
 */
vacuum_err_t vacuum_filter_insert(vacuum_filter_t *vf, uint64_t hash);

/**
 * Check if an item is possibly in the filter.
 *
 * @param vf    Filter (must not be NULL)
 * @param hash  64-bit hash of the item
 * @return      true if possibly present (may be false positive),
 *              false if definitely not present
 */
bool vacuum_filter_lookup(const vacuum_filter_t *vf, uint64_t hash);

/**
 * Delete an item from the filter.
 *
 * @param vf    Filter (must not be NULL)
 * @param hash  64-bit hash of the item
 * @return      VACUUM_OK on success, VACUUM_ERR_NOT_FOUND if item not present
 */
vacuum_err_t vacuum_filter_delete(vacuum_filter_t *vf, uint64_t hash);

/* ============================================================================
 * Statistics and properties
 * ============================================================================ */

/** Get number of items currently stored */
static inline size_t vacuum_filter_count(const vacuum_filter_t *vf) {
    return vf->count;
}

/** Get total capacity (number of entries) */
static inline size_t vacuum_filter_capacity(const vacuum_filter_t *vf) {
    return vf->num_entries;
}

/** Get load factor (0.0 to 1.0) */
static inline double vacuum_filter_load_factor(const vacuum_filter_t *vf) {
    return (double)vf->count / (double)vf->num_entries;
}

/** Get memory usage in bytes (filter structure + table) */
size_t vacuum_filter_memory_bytes(const vacuum_filter_t *vf);

/** Get bits per item at current load */
static inline double vacuum_filter_bits_per_item(const vacuum_filter_t *vf) {
    if (vf->count == 0) return 0.0;
    return (double)(vf->num_entries * vf->fingerprint_bits) / (double)vf->count;
}

/** Estimate false positive rate based on current parameters */
double vacuum_filter_estimated_fpr(const vacuum_filter_t *vf);

/* ============================================================================
 * Hash helpers (exposed for testing and callers)
 * ============================================================================ */

/**
 * Compute fingerprint from hash.
 * Returns a value in [1, 2^fp_bits - 1] (never 0, since 0 means empty).
 */
uint32_t vacuum_fingerprint(uint64_t hash, uint8_t fp_bits);

/**
 * Compute primary bucket index from hash.
 * Uses fast modulo: (hash * num_buckets) >> 32 for arbitrary table sizes.
 */
size_t vacuum_hash_index(uint64_t hash, size_t num_buckets);

/**
 * Compute alternate bucket index using the multi-range alternate function.
 * Selects an AR based on the fingerprint's lower bits, then computes
 * B2 = B1 XOR (hash(f) mod L).
 */
size_t vacuum_alt_index(const vacuum_filter_t *vf, size_t current_index, uint32_t fingerprint);

#ifdef __cplusplus
}
#endif

#endif /* VACUUM_FILTER_H */
