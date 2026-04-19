#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

/*
 * filter_hash.c - FNV-1a 64-bit hash implementation.
 */

#include "filter_hash.h"

/* FNV-1a 64-bit constants */
#define FNV_OFFSET_BASIS 14695981039346656037ULL
#define FNV_PRIME        1099511628211ULL

uint64_t filter_hash_fnv1a(const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint64_t hash = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= FNV_PRIME;
    }
    return hash;
}
