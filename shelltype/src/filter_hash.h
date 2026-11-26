/*
 * filter_hash.h - Private hash helper for Shelltype membership filters.
 *
 * Provides FNV-1a 64-bit hash. Callers choose their own hash function;
 * this is the default. Filters never see raw data — only hashes.
 */

#ifndef FILTER_HASH_H
#define FILTER_HASH_H

#include <stddef.h>
#include <stdint.h>

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

#ifdef __cplusplus
}
#endif

#endif /* FILTER_HASH_H */
