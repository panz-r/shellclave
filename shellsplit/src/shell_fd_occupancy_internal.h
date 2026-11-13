#ifndef SHELL_FD_OCCUPANCY_INTERNAL_H
#define SHELL_FD_OCCUPANCY_INTERNAL_H

#include "shell_contract.h"
#include <stdbool.h>
#include <stdint.h>

/* Non-relational descriptor occupancy for fds 0..63, the range in which Bash
 * searches for a free descriptor before its high tail. Bit f of `may_free`
 * (`may_occupied`) says descriptor f is free (open) on some path reaching
 * this point. Each descriptor is independent of the others, so a value is a
 * product of per-descriptor possibilities: joining two paths takes the union
 * of each descriptor's possibilities and forgets correlations between
 * descriptors. That only adds possibilities, so every query below answers
 * soundly for the paths that were joined. Every operation is a few word
 * operations.
 *
 * A value is valid when every descriptor has at least one possibility, i.e.
 * `may_free | may_occupied` is all ones. Callers keep that invariant; the
 * operations preserve it. */
typedef struct {
  uint64_t may_free, may_occupied;
} shell_fd_occupancy_t;

/* Where a lowest-free search can place a descriptor: `candidates` holds the
 * possible fds below 64, and `tail` says the search may pass fd 63 because
 * every searched descriptor may be occupied. The allocation is exact when
 * exactly one place is possible. */
typedef struct {
  uint64_t candidates;
  bool tail;
} shell_fd_allocation_t;

/* Descriptors minimum..63; minimum is at most 64. */
static inline uint64_t shell_fd_range_from(uint32_t minimum) {
  return minimum >= 64 ? 0 : UINT64_MAX << minimum;
}

/* Descriptors below limit; limit is at most 64. */
static inline uint64_t shell_fd_range_below(uint32_t limit) {
  return limit >= 64 ? UINT64_MAX : (UINT64_C(1) << limit) - 1;
}

/* Lowest set fd of mask, or 64 for an empty mask. */
static inline uint32_t shell_fd_lowest(uint64_t mask) {
  return mask ? (uint32_t)__builtin_ctzll(mask) : 64;
}

static inline SHELL_NONNULL(1) uint64_t
    shell_fd_certainly_free(const shell_fd_occupancy_t *occupancy) {
  return occupancy->may_free & ~occupancy->may_occupied;
}

/* Bash's F_DUPFD search: the rank-th lowest free descriptor at or above
 * minimum. rank is 1 for a duplicate or save, 2 when a temporary resource
 * descriptor was itself opened in that range first.
 *
 * Rank 1 lands on f when f is free and every searched descriptor below it is
 * occupied, so the candidates are the possibly free descriptors up to and
 * including the first certainly free one. Rank 2 lands on f when exactly one
 * searched descriptor below f is free: f must lie above the first possibly
 * free descriptor and at or below the second certainly free one. The tail is
 * possible when fewer than rank descriptors are certainly free. */
static inline SHELL_NONNULL(1) shell_fd_allocation_t
    shell_fd_allocate(const shell_fd_occupancy_t *occupancy, uint32_t minimum,
                      unsigned rank) {
  uint64_t searched = shell_fd_range_from(minimum);
  uint64_t certain = shell_fd_certainly_free(occupancy) & searched;
  uint64_t possible = occupancy->may_free & searched;
  uint32_t first_certain = shell_fd_lowest(certain);
  if (rank == 1)
    return (shell_fd_allocation_t){possible &
                                       shell_fd_range_below(first_certain + 1),
                                   first_certain == 64};
  uint64_t after_first =
      first_certain < 64 ? certain & ~(UINT64_C(1) << first_certain) : 0;
  uint32_t second_certain = shell_fd_lowest(after_first);
  uint32_t first_possible = shell_fd_lowest(possible);
  return (shell_fd_allocation_t){possible &
                                     shell_fd_range_from(first_possible + 1) &
                                     shell_fd_range_below(second_certain + 1),
                                 second_certain == 64};
}

/* Free descriptors in mask that are certainly / possibly free. */
static inline SHELL_NONNULL(1) unsigned shell_fd_certain_count(
    const shell_fd_occupancy_t *occupancy, uint64_t mask) {
  return (unsigned)__builtin_popcountll(shell_fd_certainly_free(occupancy) &
                                        mask);
}

static inline SHELL_NONNULL(1) unsigned shell_fd_possible_count(
    const shell_fd_occupancy_t *occupancy, uint64_t mask) {
  return (unsigned)__builtin_popcountll(occupancy->may_free & mask);
}

/* Some path has between minimum and maximum free descriptors in mask. With
 * independent descriptors that holds exactly when the certainly free ones do
 * not exceed maximum and the possibly free ones reach minimum. */
static inline SHELL_NONNULL(1) bool shell_fd_count_possible(
    const shell_fd_occupancy_t *occupancy, uint64_t mask, unsigned minimum,
    unsigned maximum) {
  return shell_fd_certain_count(occupancy, mask) <= maximum &&
         shell_fd_possible_count(occupancy, mask) >= minimum;
}

/* Restrict to the paths with between minimum and maximum free descriptors in
 * mask (maximum 2 or more means unbounded above), keeping per-descriptor
 * possibilities exactly: a possible descriptor stays possibly free unless the
 * count requires every remaining one occupied, and possibly occupied unless it
 * requires every possible one free. Returns false when no path qualifies. */
static inline SHELL_NONNULL(1) bool shell_fd_occupancy_restrict(
    shell_fd_occupancy_t *occupancy, uint64_t mask, unsigned minimum,
    unsigned maximum) {
  uint64_t certain = shell_fd_certainly_free(occupancy) & mask;
  unsigned certain_count = (unsigned)__builtin_popcountll(certain);
  unsigned possible_count =
      (unsigned)__builtin_popcountll(occupancy->may_free & mask);
  bool bounded = maximum < 2;
  if (possible_count < minimum || (bounded && certain_count > maximum))
    return false;
  if (possible_count == minimum)
    occupancy->may_occupied &= ~(mask & occupancy->may_free);
  if (bounded && certain_count == maximum)
    occupancy->may_free &= ~(mask & ~certain);
  return true;
}

/* The paths on which F_DUPFD's rank-th free descriptor at or above begin is
 * fd and, for low_mode 0 or 1, some or no descriptor below 10 is free (the
 * temporary resource open of a named file redirect). Restricts occupancy to
 * them before the allocation; returns false when there are none. */
static inline SHELL_NONNULL(1) bool shell_fd_occupancy_select(
    shell_fd_occupancy_t *occupancy, uint32_t begin, uint32_t fd, unsigned rank,
    int low_mode) {
  uint64_t bit = UINT64_C(1) << fd;
  if (!(occupancy->may_free & bit) ||
      !shell_fd_occupancy_restrict(
          occupancy, shell_fd_range_from(begin) & shell_fd_range_below(fd),
          rank - 1, rank - 1))
    return false;
  occupancy->may_occupied &= ~bit;
  return low_mode < 0 ||
         shell_fd_occupancy_restrict(occupancy, shell_fd_range_below(10),
                                     low_mode ? 0 : 1, low_mode ? 0 : 2);
}

/* Where the parent end of a process substitution's pipe lands. pipe() takes
 * the two lowest free descriptors; the parent keeps the rank-th (1 for the
 * read end of `<(...)`, 2 for the write end of `>(...)`). Bash then moves it
 * to the highest free descriptor above 3, if there is one, scanning from 63
 * down; otherwise it stays.
 *
 * It lands on f >= 4 by that move when f is free, both pipe ends lie below f,
 * and nothing above f is free. It stays on f when f is the rank-th free
 * descriptor and the move finds nothing: no descriptor from 4 up is free
 * except the pipe ends. The tail is possible when fewer than rank descriptors
 * below 64 are certainly free (the end lands above 63 and nothing below 64 is
 * left to move it to). Disjoint ranges are independent, so each case is a
 * conjunction of per-range count conditions. */
static inline SHELL_NONNULL(1) shell_fd_allocation_t
    shell_fd_pipe_end(const shell_fd_occupancy_t *occupancy, unsigned rank) {
  shell_fd_allocation_t result = {0, false};
  const uint64_t high = shell_fd_range_from(4);
  for (uint32_t fd = 0; fd < 64; fd++) {
    uint64_t bit = UINT64_C(1) << fd;
    if (!(occupancy->may_free & bit))
      continue;
    uint64_t below = shell_fd_range_below(fd);
    uint64_t above = shell_fd_range_from(fd + 1);
    bool moved = fd >= 4 && shell_fd_count_possible(occupancy, below, 2, 64) &&
                 shell_fd_count_possible(occupancy, above, 0, 0);
    bool stays = false;
    if (shell_fd_count_possible(occupancy, below, rank - 1, rank - 1)) {
      if (fd >= 4)
        /* Rank 1: the other pipe end may be the one free descriptor above. */
        stays = shell_fd_count_possible(occupancy, above, 0, rank == 1);
      else if (rank == 2)
        stays = shell_fd_count_possible(occupancy, high, 0, 0);
      else {
        /* The other end is the next free descriptor: either below 4, and
         * then nothing from 4 up may be free, or the only free one from 4. */
        uint64_t low_above = above & ~high;
        stays = (shell_fd_count_possible(occupancy, low_above, 1, 64) &&
                 shell_fd_count_possible(occupancy, high, 0, 0)) ||
                (shell_fd_count_possible(occupancy, low_above, 0, 0) &&
                 shell_fd_count_possible(occupancy, high, 0, 1));
      }
    }
    if (moved || stays)
      result.candidates |= bit;
  }
  result.tail = shell_fd_certain_count(occupancy, UINT64_MAX) < rank;
  return result;
}

/* The allocation places one descriptor at its single candidate, or, when
 * several places are possible, at one of them: a strong update of an exact
 * place and a weak one otherwise. Only rank 1 also proves the searched
 * descriptors below an exact place occupied. */
static inline SHELL_NONNULL(1, 2) void shell_fd_occupancy_take(
    shell_fd_occupancy_t *occupancy, const shell_fd_allocation_t *allocation,
    uint32_t minimum, unsigned rank) {
  uint64_t place = allocation->candidates;
  if (!allocation->tail && place && !(place & (place - 1))) {
    occupancy->may_free &= ~place;
    occupancy->may_occupied |= place;
    if (rank == 1)
      occupancy->may_free &= ~(shell_fd_range_from(minimum) & (place - 1));
    return;
  }
  occupancy->may_occupied |= place;
}

/* A strong update of one descriptor below 64. */
static inline SHELL_NONNULL(1) void shell_fd_occupancy_set(
    shell_fd_occupancy_t *occupancy, uint32_t fd, bool free, bool occupied) {
  uint64_t bit = UINT64_C(1) << fd;
  occupancy->may_free =
      free ? occupancy->may_free | bit : occupancy->may_free & ~bit;
  occupancy->may_occupied =
      occupied ? occupancy->may_occupied | bit : occupancy->may_occupied & ~bit;
}

/* Closing a descriptor known only as one of several places frees one of
 * them: each may now be free, none is certainly free. */
static inline SHELL_NONNULL(1) void shell_fd_occupancy_release(
    shell_fd_occupancy_t *occupancy, uint64_t places) {
  if (places && !(places & (places - 1))) {
    occupancy->may_free |= places;
    occupancy->may_occupied &= ~places;
    return;
  }
  occupancy->may_free |= places;
}

static inline SHELL_NONNULL(1, 2) void shell_fd_occupancy_join(
    shell_fd_occupancy_t *destination, const shell_fd_occupancy_t *source) {
  destination->may_free |= source->may_free;
  destination->may_occupied |= source->may_occupied;
}

/* Restrict occupancy to the paths on which the parent pipe end of
 * shell_fd_pipe_end lands on fd, before the pipe is created: the per-
 * descriptor union of its "moved there" and "stayed there" cases, each a
 * conjunction of count conditions on disjoint ranges. Returns false when no
 * path places it there. */
static inline SHELL_NONNULL(1) bool shell_fd_occupancy_pipe_select(
    shell_fd_occupancy_t *occupancy, uint32_t fd, unsigned rank) {
  uint64_t bit = UINT64_C(1) << fd;
  if (!(occupancy->may_free & bit))
    return false;
  const uint64_t high = shell_fd_range_from(4);
  uint64_t below = shell_fd_range_below(fd);
  uint64_t above = shell_fd_range_from(fd + 1);
  shell_fd_occupancy_t base = *occupancy, joined = {0, 0};
  base.may_occupied &= ~bit;
  bool any = false;
  shell_fd_occupancy_t moved = base;
  if (fd >= 4 && shell_fd_occupancy_restrict(&moved, below, 2, 64) &&
      shell_fd_occupancy_restrict(&moved, above, 0, 0)) {
    shell_fd_occupancy_join(&joined, &moved);
    any = true;
  }
  shell_fd_occupancy_t stays = base;
  if (shell_fd_occupancy_restrict(&stays, below, rank - 1, rank - 1)) {
    if (fd >= 4) {
      if (shell_fd_occupancy_restrict(&stays, above, 0, rank == 1)) {
        shell_fd_occupancy_join(&joined, &stays);
        any = true;
      }
    } else if (rank == 2) {
      if (shell_fd_occupancy_restrict(&stays, high, 0, 0)) {
        shell_fd_occupancy_join(&joined, &stays);
        any = true;
      }
    } else {
      uint64_t low_above = above & ~high;
      shell_fd_occupancy_t first = stays, second = stays;
      if (shell_fd_occupancy_restrict(&first, low_above, 1, 64) &&
          shell_fd_occupancy_restrict(&first, high, 0, 0)) {
        shell_fd_occupancy_join(&joined, &first);
        any = true;
      }
      if (shell_fd_occupancy_restrict(&second, low_above, 0, 0) &&
          shell_fd_occupancy_restrict(&second, high, 0, 1)) {
        shell_fd_occupancy_join(&joined, &second);
        any = true;
      }
    }
  }
  if (any)
    *occupancy = joined;
  return any;
}

/* Occupancy split by Bash's low interval, descriptors 0..9. Bash's
 * resource-open allocation behaves differently when some low descriptor is
 * free (case 0) and when all ten are open (case 1), so keeping one occupancy
 * per case keeps an allocation's place correlated with the case that chose
 * it. Part 2 * origin + case holds the paths currently in `case` whose
 * inherited low interval was in case `origin`, as first split: closing or
 * opening low descriptors moves a path between cases but never between
 * origins, so paths whose inherited layouts differ never share masks.
 * Constant size, so every operation stays a few word operations.
 *
 * A part is empty, holding no paths, when all its words are zero; otherwise
 * it is a valid occupancy. Its paths are those its masks allow that are in
 * its case: the masks cannot express "some low descriptor is free", so that
 * condition is part of the meaning, not of the masks. */
enum { SHELL_FD_PARTS = 4 };

typedef struct {
  shell_fd_occupancy_t part[SHELL_FD_PARTS];
} shell_fd_partition_t;

/* The current low-interval case of part i: 1 when every low descriptor is
 * open. */
static inline bool shell_fd_part_full(unsigned part) { return part & 1u; }

#define SHELL_FD_LOW_INTERVAL ((uint64_t)0x3ff)

static inline SHELL_NONNULL(1) bool shell_fd_occupancy_feasible(
    const shell_fd_occupancy_t *occupancy) {
  return (occupancy->may_free | occupancy->may_occupied) == UINT64_MAX;
}

/* The paths of a valid or empty occupancy on which the low interval is in
 * case `full`, or an empty value when there are none. With one possibly free
 * low descriptor, that descriptor is free on every path of case 0. */
static inline SHELL_NONNULL(1) shell_fd_occupancy_t
    shell_fd_occupancy_low_case(const shell_fd_occupancy_t *occupancy,
                                bool full) {
  shell_fd_occupancy_t result = *occupancy;
  uint64_t free_low = occupancy->may_free & SHELL_FD_LOW_INTERVAL;
  if (!shell_fd_occupancy_feasible(occupancy))
    return (shell_fd_occupancy_t){0, 0};
  if (full) {
    if ((occupancy->may_occupied & SHELL_FD_LOW_INTERVAL) !=
        SHELL_FD_LOW_INTERVAL)
      return (shell_fd_occupancy_t){0, 0};
    result.may_free &= ~SHELL_FD_LOW_INTERVAL;
    return result;
  }
  if (!free_low)
    return (shell_fd_occupancy_t){0, 0};
  if (!(free_low & (free_low - 1)))
    result.may_occupied &= ~free_low;
  return result;
}

/* Tighten each part's masks to the paths of its own case. Never loses a path:
 * a part only ever holds paths of its case. */
static inline SHELL_NONNULL(1) void shell_fd_partition_refine(
    shell_fd_partition_t *partition) {
  for (unsigned part = 0; part < SHELL_FD_PARTS; part++)
    partition->part[part] = shell_fd_occupancy_low_case(
        &partition->part[part], shell_fd_part_full(part));
}

/* Re-file the parts after an update of low descriptors, whose paths may have
 * changed case: closing a low descriptor moves full paths to case 0, and
 * opening the last free one moves case-0 paths to case 1. Each part's masks,
 * updated as if its case condition did not exist, are split by case again
 * within the same origin; that keeps every path, though it forgets which case
 * a path came from within its origin. */
static inline SHELL_NONNULL(1) void shell_fd_partition_normalize(
    shell_fd_partition_t *partition) {
  shell_fd_partition_t result;
  for (unsigned part = 0; part < SHELL_FD_PARTS; part++) {
    unsigned origin = part & ~1u;
    result.part[part] = shell_fd_occupancy_low_case(&partition->part[origin],
                                                    shell_fd_part_full(part));
    shell_fd_occupancy_t other = shell_fd_occupancy_low_case(
        &partition->part[origin | 1u], shell_fd_part_full(part));
    shell_fd_occupancy_join(&result.part[part], &other);
  }
  *partition = result;
}

/* The partition of a valid occupancy whose cases are not yet known: each path
 * is its own origin. */
static inline SHELL_NONNULL(1) shell_fd_partition_t
    shell_fd_partition_split(const shell_fd_occupancy_t *occupancy) {
  shell_fd_partition_t partition = {{{0, 0}}};
  partition.part[0] = shell_fd_occupancy_low_case(occupancy, false);
  partition.part[3] = shell_fd_occupancy_low_case(occupancy, true);
  return partition;
}

/* Occupancy over every part. */
static inline SHELL_NONNULL(1) shell_fd_occupancy_t
    shell_fd_partition_union(const shell_fd_partition_t *partition) {
  shell_fd_occupancy_t result = partition->part[0];
  for (unsigned part = 1; part < SHELL_FD_PARTS; part++)
    shell_fd_occupancy_join(&result, &partition->part[part]);
  return result;
}

/* Bit c is set when some path is currently in case c. */
static inline SHELL_NONNULL(1) unsigned shell_fd_partition_cases(
    const shell_fd_partition_t *partition) {
  unsigned cases = 0;
  for (unsigned part = 0; part < SHELL_FD_PARTS; part++)
    if (shell_fd_occupancy_feasible(&partition->part[part]))
      cases |= 1u << shell_fd_part_full(part);
  return cases;
}

/* Number of parts holding paths. */
static inline SHELL_NONNULL(1) unsigned shell_fd_partition_count(
    const shell_fd_partition_t *partition) {
  unsigned count = 0;
  for (unsigned part = 0; part < SHELL_FD_PARTS; part++)
    count += shell_fd_occupancy_feasible(&partition->part[part]);
  return count;
}

#endif
