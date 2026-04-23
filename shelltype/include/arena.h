#ifndef ARENA_H
#define ARENA_H

#include <stddef.h>
#include <stdbool.h>

typedef struct {
    char   *base;
    size_t  size;
    size_t  used;
} arena_t;

/*
 * Arena Allocator — Bump-Allocator Design
 *
 * This is a power-of-2 doubling arena. It is a bump allocator: memory is
 * allocated by advancing a pointer, never reused until arena_free() is called.
 *
 * Properties:
 * - O(1) allocation (just pointer advancement + alignment)
 * - Doubling growth: starts at initial_size, doubles on each resize
 * - No compact/reclaim between allocations (fragmentation accumulates)
 * - Copying GC: each grow copies all existing data to a new, larger block
 *
 * Operational expectations:
 * - Normal workload: arena grows once at startup, stays stable
 * - High churn: arena grows 2x per resize until st_policy_compact() resets it
 * - Compact: call st_policy_compact() periodically (e.g., cron or after bulk load)
 *   to reclaim memory. Compact resets the arena and rebuilds filters.
 *
 * Thread safety:
 * - Arena itself is NOT thread-safe. Caller must hold appropriate lock.
 * - In shelltype, the policy rwlock guards all arena access.
 */

bool arena_init(arena_t *a, size_t size);
void arena_free(arena_t *a);
void *arena_alloc(arena_t *a, size_t n);
size_t arena_used(const arena_t *a);

#endif /* ARENA_H */
