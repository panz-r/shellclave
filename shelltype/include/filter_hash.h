/*
 * filter_hash.h - Hash functions for approximate membership filters.
 *
 * Provides FNV-1a 64-bit hash. Callers choose their own hash function;
 * this is the default. Filters never see raw data — only hashes.
 */

#ifndef FILTER_HASH_H
#define FILTER_HASH_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * FNV-1a 64-bit hash.
 *
 * Fast, non-cryptographic hash suitable for AMQ filters.
 * Callers may substitute their own hash function; the filter
 * only requires a 64-bit hash value.
 */
uint64_t filter_hash_fnv1a(const void *data, size_t len);

/**
 * Derive a fingerprint from a 64-bit hash.
 *
 * Extracts the lower @fp_bits from @h and forces non-zero
 * (0 is reserved for empty entries in cuckoo/vacuum filters).
 *
 * @fp_bits must be in [1, 32].
 */
static inline uint32_t filter_hash_to_fp(uint64_t h, uint8_t fp_bits)
{
    uint32_t fp = (uint32_t)(h & ((1ULL << fp_bits) - 1));
    return fp ? fp : 1;
}

/**
 * Derive a bucket index from a 64-bit hash.
 *
 * Uses the upper 32 bits of the hash for better distribution
 * when the table is small, then maps to [0, num_buckets) via
 * fast modulo: (x * m) >> 32.
 */
static inline size_t filter_hash_to_index(uint64_t h, size_t num_buckets)
{
    return ((uint64_t)(h >> 32) * num_buckets) >> 32;
}

#ifdef __cplusplus
}
#endif

#endif /* FILTER_HASH_H */
