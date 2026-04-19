/**
 * bloom_filter.c - Standard Bloom filter implementation
 *
 * A Bloom filter is a space-efficient probabilistic data structure for set
 * membership queries. It guarantees no false negatives but permits a tunable
 * false positive rate. It does NOT support deletion.
 *
 * METHOD CHOICES
 * ==============
 *
 * Hash functions (Kirsch-Mitzenmacher optimization):
 *   A Bloom filter needs k independent hash functions. Computing k separate
 *   hashes is expensive. Instead, we compute only two base hashes (h1, h2)
 *   and derive the rest as h_i(x) = h1(x) + i * h2(x). Kirsch and Mitzenmacher
 *   proved this retains the same asymptotic false positive behavior as fully
 *   independent hashes, cutting hash computation from O(k) to O(1).
 *
 * Base hash selection (dual FNV-1a):
 *   We use two independent FNV-1a instances with different seeds. FNV-1a is
 *   fast, has no external dependencies, and provides sufficient mixing for
 *   Bloom filter purposes. The two different seeds ensure h1 and h2 are
 *   statistically independent.
 *
 * Bit storage (uint64_t array):
 *   The bit array is stored as uint64_t words. This aligns to 8-byte
 *   boundaries for efficient memory access and lets us set/test bits with
 *   a single shift-and-OR/AND operation.
 *
 * Optimal sizing:
 *   Given n items and target FPR epsilon, the optimal bit array size is
 *   m = -n * ln(epsilon) / (ln 2)^2, and the optimal number of hash
 *   functions is k = (m/n) * ln 2. The create() function computes these
 *   automatically so the caller only specifies capacity and desired FPR.
 *
 * Graceful degradation:
 *   Unlike cuckoo filters, a Bloom filter has no hard capacity limit.
 *   Inserting beyond the expected capacity simply increases the FPR.
 *   This makes it suitable for workloads where the item count is uncertain.
 */

#include "bloom_filter.h"

#include <stdlib.h>
#include <string.h>
#include <math.h>

/* FNV-1a constants (duplicated from cdfa_defines.h for standalone compilation) */
#define BLOOM_FNV_OFFSET_BASIS 2166136261u
#define BLOOM_FNV_PRIME        16777619u

/* ============================================================================
 * Hash functions
 *
 * Two independent FNV-1a hashes serve as the base for the Kirsch-Mitzenmacher
 * derivation. Each uses a different seed so the outputs are uncorrelated.
 * ============================================================================ */

static void double_hash(const void *data, size_t len, uint64_t *h1, uint64_t *h2) {
    const uint8_t *bytes = (const uint8_t *)data;

    /* First hash: standard FNV-1a with the canonical offset basis */
    uint64_t hash1 = BLOOM_FNV_OFFSET_BASIS;
    for (size_t i = 0; i < len; i++) {
        hash1 ^= bytes[i];
        hash1 *= BLOOM_FNV_PRIME;
    }

    /* Second hash: FNV-1a with a perturbed seed to ensure independence from h1.
     * The multiplier 0x00000100000001B3 is the 64-bit FNV prime; the seed
     * 0xcbf29ce484222325 ^ 0xdeadbeef differs from the standard offset basis. */
    uint64_t hash2 = 0xcbf29ce484222325ULL ^ 0xdeadbeef;
    for (size_t i = 0; i < len; i++) {
        hash2 ^= bytes[i];
        hash2 *= 0x00000100000001B3ULL;
    }

    *h1 = hash1;
    *h2 = hash2;
}

/* Public helper: compute all k probe positions for an item.
 * Uses the Kirsch-Mitzenmacher technique to derive positions[i] from
 * only two base hash values, avoiding k separate hash computations. */
void bloom_filter_hashes(const void *data, size_t len, size_t num_bits,
                          uint8_t num_hashes, size_t *positions) {
    uint64_t h1, h2;
    double_hash(data, len, &h1, &h2);

    for (uint8_t i = 0; i < num_hashes; i++) {
        positions[i] = (size_t)((h1 + (uint64_t)i * h2) % num_bits);
    }
}

/* ============================================================================
 * Lifecycle
 *
 * Two creation paths:
 *   bloom_filter_create()   - caller specifies expected items and target FPR;
 *                             optimal m and k are computed automatically.
 *   bloom_filter_create_raw() - caller specifies exact bit count and hash count;
 *                             used when the caller has pre-computed optimal values
 *                             or wants to share a bit array across filters.
 * ============================================================================ */

/* Compute the optimal bit array size for a given capacity and target FPR.
 * Derived from setting the derivative of the FPR formula to zero:
 *   m = -n * ln(epsilon) / (ln 2)^2
 * This minimizes space for the target false positive rate. */
size_t bloom_filter_optimal_bits(size_t expected_items, double target_fpr) {
    if (expected_items == 0 || target_fpr <= 0.0 || target_fpr >= 1.0) return 0;
    double ln2 = 0.6931471805599453;
    return (size_t)ceil(-((double)expected_items * log(target_fpr)) / (ln2 * ln2));
}

/* Compute the optimal number of hash functions for a given bit array and capacity.
 *   k = (m/n) * ln 2
 * Clamped to [1, 32] since fewer than 1 hash is meaningless and more than 32
 * provides diminishing returns while increasing CPU cost. */
uint8_t bloom_filter_optimal_hashes(size_t num_bits, size_t expected_items) {
    if (expected_items == 0) return 1;
    double k = ((double)num_bits / (double)expected_items) * 0.6931471805599453;
    uint8_t result = (uint8_t)round(k);
    return result < 1 ? 1 : (result > 32 ? 32 : result);
}

/* High-level constructor: auto-computes optimal parameters from capacity and FPR. */
bloom_filter_t *bloom_filter_create(size_t expected_items, double target_fpr) {
    if (expected_items == 0 || target_fpr <= 0.0 || target_fpr >= 1.0) return NULL;

    size_t num_bits = bloom_filter_optimal_bits(expected_items, target_fpr);
    uint8_t num_hashes = bloom_filter_optimal_hashes(num_bits, expected_items);

    return bloom_filter_create_raw(num_bits, num_hashes);
}

/* Low-level constructor: accepts explicit bit count and hash count. */
bloom_filter_t *bloom_filter_create_raw(size_t num_bits, uint8_t num_hashes) {
    if (num_bits == 0 || num_hashes == 0) return NULL;

    bloom_filter_t *bf = (bloom_filter_t *)calloc(1, sizeof(bloom_filter_t));
    if (!bf) return NULL;

    /* Allocate the bit array as uint64_t words. The ceiling division ensures
     * we have enough words to cover all num_bits, with any trailing bits unused. */
    size_t num_words = (num_bits + 63) / 64;
    bf->bits = (uint64_t *)calloc(num_words, sizeof(uint64_t));
    if (!bf->bits) {
        free(bf);
        return NULL;
    }

    bf->num_bits = num_bits;
    bf->count = 0;
    bf->num_hashes = num_hashes;

    return bf;
}

void bloom_filter_destroy(bloom_filter_t *bf) {
    if (!bf) return;
    free(bf->bits);
    free(bf);
}

/* Clear all bits and reset the item count. The allocation is retained so that
 * the filter can be reused without re-allocation overhead. */
void bloom_filter_reset(bloom_filter_t *bf) {
    if (!bf) return;
    size_t num_words = (bf->num_bits + 63) / 64;
    memset(bf->bits, 0, num_words * sizeof(uint64_t));
    bf->count = 0;
}

/* ============================================================================
 * Core operations
 *
 * Insert: set k bits in the array, one per hash function.
 * Lookup: check that all k bits are set; if any is 0, the item is definitely
 *         absent. If all are 1, the item is probably present (false positive
 *         occurs when other items set the same bits by chance).
 * ============================================================================ */

void bloom_filter_insert(bloom_filter_t *bf, const void *data, size_t len) {
    if (!bf || !data || len == 0) return;

    uint64_t h1, h2;
    double_hash(data, len, &h1, &h2);

    /* Set each of the k bits. The Kirsch-Mitzenmacher derivation avoids
     * computing k separate hashes: position i = (h1 + i*h2) mod m. */
    for (uint8_t i = 0; i < bf->num_hashes; i++) {
        size_t pos = (size_t)((h1 + (uint64_t)i * h2) % bf->num_bits);
        bf->bits[pos / 64] |= (1ULL << (pos % 64));
    }
    bf->count++;
}

bool bloom_filter_lookup(const bloom_filter_t *bf, const void *data, size_t len) {
    if (!bf || !data || len == 0) return false;

    uint64_t h1, h2;
    double_hash(data, len, &h1, &h2);

    /* All k bits must be set for a positive result. A single 0 bit proves
     * the item was never inserted (no false negatives). */
    for (uint8_t i = 0; i < bf->num_hashes; i++) {
        size_t pos = (size_t)((h1 + (uint64_t)i * h2) % bf->num_bits);
        if (!(bf->bits[pos / 64] & (1ULL << (pos % 64)))) {
            return false;
        }
    }
    return true;
}

/* ============================================================================
 * Statistics
 * ============================================================================ */

size_t bloom_filter_memory_bytes(const bloom_filter_t *bf) {
    if (!bf) return 0;
    size_t num_words = (bf->num_bits + 63) / 64;
    return sizeof(bloom_filter_t) + num_words * sizeof(uint64_t);
}

/* Estimate the current false positive rate from the filter's fill level.
 *
 * After inserting n items with k hash functions into m bits, the probability
 * that any specific bit is still 0 is (1 - 1/m)^(k*n) ≈ e^(-k*n/m).
 * The probability that all k bits for a non-member are 1 (false positive) is:
 *   FPR = (1 - e^(-k*n/m))^k
 *
 * This is an estimate because the actual FPR depends on hash quality and
 * the specific distribution of inserted items. */
double bloom_filter_estimated_fpr(const bloom_filter_t *bf) {
    if (!bf || bf->num_bits == 0 || bf->count == 0) return 0.0;
    double exponent = -((double)bf->num_hashes * (double)bf->count) / (double)bf->num_bits;
    double p = 1.0 - exp(exponent);
    return pow(p, (double)bf->num_hashes);
}
