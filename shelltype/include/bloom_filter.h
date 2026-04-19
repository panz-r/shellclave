/**
 * bloom_filter.h - Standard Bloom filter for approximate set membership
 *
 * A Bloom filter is a probabilistic data structure that supports:
 *   - Insert: add an item to the set
 *   - Lookup: test if an item is possibly in the set (with false positives)
 *
 * Does NOT support deletion (standard Bloom filter).
 * For deletion support, use the cuckoo filter instead.
 *
 * Space efficiency:
 *   - Optimal: k = ln(2) * (m/n) hash functions for m bits, n items
 *   - Uses ~1.44 * log2(1/fpr) bits per item (44% overhead over information-theoretic minimum)
 *   - Graceful degradation: can insert beyond capacity, FPR just increases
 */

#ifndef BLOOM_FILTER_H
#define BLOOM_FILTER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Bloom filter structure
 *
 * Memory layout:
 *   bloom_filter_t
 *   └── bits[]  (num_bits bits, stored as uint64_t array)
 * ============================================================================ */

typedef struct bloom_filter {
    uint64_t *bits;         /* Bit array */
    size_t    num_bits;     /* Total number of bits */
    size_t    count;        /* Number of items inserted */
    uint8_t   num_hashes;   /* Number of hash functions (k) */
} bloom_filter_t;

/* ============================================================================
 * Lifecycle
 * ============================================================================ */

/**
 * Create a new Bloom filter optimized for expected capacity and target FPR.
 *
 * @param expected_items  Expected number of items to store
 * @param target_fpr      Target false positive rate (e.g., 0.01 for 1%)
 * @return                Pointer to allocated filter, or NULL on failure
 */
bloom_filter_t *bloom_filter_create(size_t expected_items, double target_fpr);

/**
 * Create a Bloom filter with explicit size and hash count.
 *
 * @param num_bits    Number of bits in the filter
 * @param num_hashes  Number of hash functions
 * @return            Pointer to allocated filter, or NULL on failure
 */
bloom_filter_t *bloom_filter_create_raw(size_t num_bits, uint8_t num_hashes);

/**
 * Destroy a Bloom filter and free all memory.
 * @param bf  Filter to destroy (NULL is safe)
 */
void bloom_filter_destroy(bloom_filter_t *bf);

/**
 * Reset a Bloom filter to empty state (keeps allocation).
 * @param bf  Filter to reset (must not be NULL)
 */
void bloom_filter_reset(bloom_filter_t *bf);

/* ============================================================================
 * Core operations
 * ============================================================================ */

/**
 * Insert an item into the filter.
 * @param bf    Filter (must not be NULL)
 * @param data  Item data
 * @param len   Length of item data
 */
void bloom_filter_insert(bloom_filter_t *bf, const void *data, size_t len);

/**
 * Check if an item is possibly in the filter.
 * @param bf    Filter (must not be NULL)
 * @param data  Item data
 * @param len   Length of item data
 * @return      true if possibly present (may be false positive),
 *              false if definitely not present
 */
bool bloom_filter_lookup(const bloom_filter_t *bf, const void *data, size_t len);

/* ============================================================================
 * Statistics and properties
 * ============================================================================ */

/** Get number of items inserted */
static inline size_t bloom_filter_count(const bloom_filter_t *bf) {
    return bf->count;
}

/** Get total number of bits */
static inline size_t bloom_filter_num_bits(const bloom_filter_t *bf) {
    return bf->num_bits;
}

/** Get number of hash functions */
static inline uint8_t bloom_filter_num_hashes(const bloom_filter_t *bf) {
    return bf->num_hashes;
}

/** Get memory usage in bytes (filter structure + bit array) */
size_t bloom_filter_memory_bytes(const bloom_filter_t *bf);

/** Get bits per item */
static inline double bloom_filter_bits_per_item(const bloom_filter_t *bf) {
    if (bf->count == 0) return 0.0;
    return (double)bf->num_bits / (double)bf->count;
}

/**
 * Estimate current false positive rate based on fill level.
 * FPR ≈ (1 - e^(-k*n/m))^k
 */
double bloom_filter_estimated_fpr(const bloom_filter_t *bf);

/**
 * Calculate optimal number of bits for given capacity and FPR.
 * m = -n * ln(fpr) / (ln(2))^2
 */
size_t bloom_filter_optimal_bits(size_t expected_items, double target_fpr);

/**
 * Calculate optimal number of hash functions.
 * k = (m/n) * ln(2)
 */
uint8_t bloom_filter_optimal_hashes(size_t num_bits, size_t expected_items);

/* ============================================================================
 * Hash helpers (exposed for testing)
 * ============================================================================ */

/**
 * Compute double-hash values for Bloom filter using the Kirsch-Mitzenmacher
 * technique: h_i(x) = h1(x) + i * h2(x), requiring only 2 base hash computations.
 */
void bloom_filter_hashes(const void *data, size_t len, size_t num_bits,
                          uint8_t num_hashes, size_t *positions);

#ifdef __cplusplus
}
#endif

#endif /* BLOOM_FILTER_H */
