#include "shell_fd_occupancy_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Each transfer function is checked against a direct reading of Bash's
 * lowest-free search over independent per-descriptor possibilities, for every
 * minimum and both ranks, on random valid occupancies. */

static int passed;
static int failed;

#define TEST(name, condition)                                                  \
  do {                                                                         \
    if (condition) {                                                           \
      passed++;                                                                \
    } else {                                                                   \
      printf("  [FAIL] %s\n", name);                                           \
      failed++;                                                                \
    }                                                                          \
  } while (0)

static uint64_t state = 0x9e3779b97f4a7c15u;

static uint64_t next(void) {
  state ^= state << 13;
  state ^= state >> 7;
  state ^= state << 17;
  return state;
}

/* Sparse and dense masks both matter: a few certainly free descriptors decide
 * where the search stops. */
static shell_fd_occupancy_t random_occupancy(void) {
  uint64_t free = next();
  for (unsigned i = next() % 4; i; i--)
    free &= next();
  uint64_t occupied = next();
  for (unsigned i = next() % 4; i; i--)
    occupied |= next();
  return (shell_fd_occupancy_t){free, occupied | ~free};
}

static int may_free(const shell_fd_occupancy_t *o, uint32_t fd) {
  return (o->may_free >> fd) & 1;
}

static int certainly_free(const shell_fd_occupancy_t *o, uint32_t fd) {
  return may_free(o, fd) && !((o->may_occupied >> fd) & 1);
}

/* Some path has exactly rank - 1 free descriptors in minimum..fd-1 and fd
 * free: per descriptor, the free count ranges from the certainly free ones to
 * the possibly free ones. */
static shell_fd_allocation_t reference(const shell_fd_occupancy_t *o,
                                       uint32_t minimum, unsigned rank) {
  shell_fd_allocation_t result = {0, false};
  unsigned certain = 0, possible = 0;
  for (uint32_t fd = minimum; fd < 64; fd++) {
    if (may_free(o, fd) && certain <= rank - 1 && possible >= rank - 1)
      result.candidates |= UINT64_C(1) << fd;
    certain += (unsigned)certainly_free(o, fd);
    possible += (unsigned)may_free(o, fd);
  }
  result.tail = certain < rank;
  return result;
}

static void test_allocation_matches_reference(void) {
  int ok = 1;
  for (unsigned round = 0; round < 20000 && ok; round++) {
    shell_fd_occupancy_t o = random_occupancy();
    for (uint32_t minimum = 0; minimum <= 64 && ok; minimum++)
      for (unsigned rank = 1; rank <= 2 && ok; rank++) {
        shell_fd_allocation_t a = shell_fd_allocate(&o, minimum, rank);
        shell_fd_allocation_t r = reference(&o, minimum, rank);
        if (a.candidates != r.candidates || a.tail != r.tail) {
          printf("    free %016llx occupied %016llx minimum %u rank %u: "
                 "%016llx/%d, want %016llx/%d\n",
                 (unsigned long long)o.may_free,
                 (unsigned long long)o.may_occupied, minimum, rank,
                 (unsigned long long)a.candidates, a.tail,
                 (unsigned long long)r.candidates, r.tail);
          ok = 0;
        }
      }
  }
  TEST("allocation candidates match the lowest-free search", ok);
}

static void test_known_tables(void) {
  /* 0..9 open, 10 closed: a save lands exactly on 10. */
  shell_fd_occupancy_t o = {UINT64_MAX << 10, ~(UINT64_C(1) << 10)};
  shell_fd_allocation_t a = shell_fd_allocate(&o, 10, 1);
  TEST("closed descriptor is the exact rank-1 place",
       a.candidates == UINT64_C(1) << 10 && !a.tail);
  a = shell_fd_allocate(&o, 10, 2);
  TEST("rank 2 lies above the certain first free",
       a.candidates == (UINT64_MAX << 11) && a.tail);
  /* Unknown inherited table above 9: every place and the tail. */
  shell_fd_occupancy_t unknown = {UINT64_MAX << 10, UINT64_MAX};
  a = shell_fd_allocate(&unknown, 10, 1);
  TEST("unknown table keeps every place and the tail",
       a.candidates == (UINT64_MAX << 10) && a.tail);
  /* Certainly full search range: only the tail. */
  shell_fd_occupancy_t full = {0, UINT64_MAX};
  a = shell_fd_allocate(&full, 10, 1);
  TEST("full range allocates in the tail", !a.candidates && a.tail);
}

/* After an exact rank-1 take, the place is occupied and the searched
 * descriptors below it are not free; a weak take only adds possibilities. */
static void test_take_and_release(void) {
  int ok = 1;
  for (unsigned round = 0; round < 20000 && ok; round++) {
    shell_fd_occupancy_t o = random_occupancy();
    uint32_t minimum = (uint32_t)(next() % 65);
    unsigned rank = 1 + (unsigned)(next() & 1);
    shell_fd_allocation_t a = shell_fd_allocate(&o, minimum, rank);
    shell_fd_occupancy_t after = o;
    shell_fd_occupancy_take(&after, &a, minimum, rank);
    ok &= (after.may_free | after.may_occupied) == UINT64_MAX;
    ok &= (after.may_occupied & a.candidates) == a.candidates;
    int exact = !a.tail && a.candidates && !(a.candidates & (a.candidates - 1));
    if (!exact)
      ok &= (after.may_free | o.may_free) == after.may_free &&
            (after.may_occupied & o.may_occupied) == o.may_occupied;
    shell_fd_occupancy_t released = after;
    shell_fd_occupancy_release(&released, a.candidates);
    ok &= (released.may_free & a.candidates) == a.candidates &&
          (released.may_free | released.may_occupied) == UINT64_MAX;
    shell_fd_occupancy_t joined = o;
    shell_fd_occupancy_join(&joined, &after);
    ok &= (joined.may_free & o.may_free) == o.may_free &&
          (joined.may_occupied & after.may_occupied) == after.may_occupied;
  }
  TEST("take, release and join keep valid, sound occupancies", ok);
}

/* Concrete Bash behavior on one complete table (bit set = free): F_DUPFD's
 * rank-th free descriptor at or above minimum, and the place a process
 * substitution's parent pipe end ends up after move_to_high_fd. 64 is the
 * tail above fd 63. */
static uint32_t concrete_dupfd(uint64_t free, uint32_t minimum, unsigned rank) {
  for (uint32_t fd = minimum; fd < 64; fd++)
    if (((free >> fd) & 1) && !--rank)
      return fd;
  return 64;
}

static uint32_t concrete_pipe_end(uint64_t free, unsigned rank) {
  uint32_t ends[2] = {64, 64};
  unsigned found = 0;
  for (uint32_t fd = 0; fd < 64 && found < 2; fd++)
    if ((free >> fd) & 1)
      ends[found++] = fd;
  uint64_t after = free;
  for (unsigned i = 0; i < 2; i++)
    if (ends[i] < 64)
      after &= ~(UINT64_C(1) << ends[i]);
  for (uint32_t fd = 63; fd > 3; fd--)
    if ((after >> fd) & 1)
      return fd;
  return ends[rank - 1];
}

/* Every complete table consistent with an occupancy that leaves at most ten
 * descriptors unknown: the abstract answers must be exactly the set of
 * concrete answers, since descriptors are independent. */
static void test_against_concrete_tables(void) {
  int ok = 1;
  for (unsigned round = 0; round < 3000 && ok; round++) {
    uint64_t unknown = 0;
    for (unsigned i = next() % 11; i; i--)
      unknown |= UINT64_C(1) << (next() % 64);
    if (next() & 1)
      unknown &= UINT64_C(0xffff);
    uint64_t fixed_free = next() & next() & next() & ~unknown;
    shell_fd_occupancy_t o = {fixed_free | unknown, ~fixed_free};
    uint32_t positions[64], count = 0;
    for (uint32_t fd = 0; fd < 64; fd++)
      if ((unknown >> fd) & 1)
        positions[count++] = fd;
    uint32_t minimum = (uint32_t)(next() % 20);
    for (unsigned rank = 1; rank <= 2 && ok; rank++) {
      shell_fd_allocation_t dup = {0, false}, pipe = {0, false};
      for (uint64_t world = 0; world < (UINT64_C(1) << count); world++) {
        uint64_t free = fixed_free;
        for (uint32_t i = 0; i < count; i++)
          if ((world >> i) & 1)
            free |= UINT64_C(1) << positions[i];
        uint32_t d = concrete_dupfd(free, minimum, rank);
        uint32_t p = concrete_pipe_end(free, rank);
        if (d < 64)
          dup.candidates |= UINT64_C(1) << d;
        else
          dup.tail = true;
        if (p < 64)
          pipe.candidates |= UINT64_C(1) << p;
        else
          pipe.tail = true;
      }
      shell_fd_allocation_t a = shell_fd_allocate(&o, minimum, rank);
      shell_fd_allocation_t b = shell_fd_pipe_end(&o, rank);
      if (a.candidates != dup.candidates || a.tail != dup.tail ||
          b.candidates != pipe.candidates || b.tail != pipe.tail) {
        printf("    free %016llx unknown %016llx minimum %u rank %u: dup "
               "%016llx/%d want %016llx/%d, pipe %016llx/%d want %016llx/%d\n",
               (unsigned long long)fixed_free, (unsigned long long)unknown,
               minimum, rank, (unsigned long long)a.candidates, a.tail,
               (unsigned long long)dup.candidates, dup.tail,
               (unsigned long long)b.candidates, b.tail,
               (unsigned long long)pipe.candidates, pipe.tail);
        ok = 0;
      }
    }
  }
  TEST("allocations equal the concrete answers over every consistent table",
       ok);
}

/* Selecting a candidate restricts the occupancy to exactly the per-descriptor
 * hull of the complete tables on which F_DUPFD picks it (and the low interval
 * has the requested state). */
static void test_select_is_the_exact_hull(void) {
  int ok = 1;
  for (unsigned round = 0; round < 3000 && ok; round++) {
    uint64_t unknown = 0;
    for (unsigned i = next() % 11; i; i--)
      unknown |= UINT64_C(1) << (next() % 24);
    uint64_t fixed_free = next() & next() & ~unknown;
    shell_fd_occupancy_t o = {fixed_free | unknown, ~fixed_free};
    uint32_t positions[64], count = 0;
    for (uint32_t fd = 0; fd < 64; fd++)
      if ((unknown >> fd) & 1)
        positions[count++] = fd;
    uint32_t begin = 10 + (uint32_t)(next() % 6);
    uint32_t fd = begin + (uint32_t)(next() % 10);
    unsigned rank = 1 + (unsigned)(next() & 1);
    int low_mode = (int)(next() % 3) - 1;
    shell_fd_occupancy_t hull = {0, 0};
    bool any = false;
    for (uint64_t world = 0; world < (UINT64_C(1) << count); world++) {
      uint64_t free = fixed_free;
      for (uint32_t i = 0; i < count; i++)
        if ((world >> i) & 1)
          free |= UINT64_C(1) << positions[i];
      bool low_free = (free & 0x3ff) != 0;
      if (concrete_dupfd(free, begin, rank) != fd ||
          (low_mode == 0 && !low_free) || (low_mode == 1 && low_free))
        continue;
      any = true;
      hull.may_free |= free;
      hull.may_occupied |= ~free;
    }
    shell_fd_occupancy_t selected = o;
    bool found =
        shell_fd_occupancy_select(&selected, begin, fd, rank, low_mode);
    if (found != any || (any && (selected.may_free != hull.may_free ||
                                 selected.may_occupied != hull.may_occupied))) {
      printf("    begin %u fd %u rank %u low %d: found %d want %d\n", begin, fd,
             rank, low_mode, found, any);
      ok = 0;
    }
  }
  TEST("selecting a candidate keeps exactly the hull of its tables", ok);
}

/* Restricting to a pipe-end place keeps exactly the per-descriptor hull of
 * the complete tables on which the parent end lands there. */
static void test_pipe_select_is_the_exact_hull(void) {
  int ok = 1;
  for (unsigned round = 0; round < 3000 && ok; round++) {
    uint64_t unknown = 0;
    for (unsigned i = next() % 11; i; i--)
      unknown |= UINT64_C(1) << (next() % 64);
    if (next() & 1)
      unknown &= UINT64_C(0xffff) | (UINT64_C(0xf) << 60);
    uint64_t fixed_free = next() & next() & next() & ~unknown;
    shell_fd_occupancy_t o = {fixed_free | unknown, ~fixed_free};
    uint32_t positions[64], count = 0;
    for (uint32_t fd = 0; fd < 64; fd++)
      if ((unknown >> fd) & 1)
        positions[count++] = fd;
    unsigned rank = 1 + (unsigned)(next() & 1);
    for (uint32_t fd = 0; fd < 64 && ok; fd++) {
      shell_fd_occupancy_t hull = {0, 0};
      bool any = false;
      for (uint64_t world = 0; world < (UINT64_C(1) << count); world++) {
        uint64_t free = fixed_free;
        for (uint32_t i = 0; i < count; i++)
          if ((world >> i) & 1)
            free |= UINT64_C(1) << positions[i];
        if (concrete_pipe_end(free, rank) != fd)
          continue;
        any = true;
        hull.may_free |= free;
        hull.may_occupied |= ~free;
      }
      shell_fd_occupancy_t selected = o;
      bool found = shell_fd_occupancy_pipe_select(&selected, fd, rank);
      if (found != any ||
          (any && (selected.may_free != hull.may_free ||
                   selected.may_occupied != hull.may_occupied))) {
        printf("    pipe fd %u rank %u: found %d want %d\n", fd, rank, found,
               any);
        ok = 0;
      }
    }
  }
  TEST("selecting a pipe-end place keeps exactly the hull of its tables", ok);
}

static bool table_allowed(const shell_fd_occupancy_t *o, uint64_t free) {
  return !(free & ~o->may_free) && !(~free & ~o->may_occupied);
}

/* Splitting by the low interval keeps exactly the hull of each case's
 * complete tables, and normalizing a partition files every table of either
 * part under the case it belongs to. */
static void test_partition_cases(void) {
  int ok = 1;
  for (unsigned round = 0; round < 3000 && ok; round++) {
    uint64_t unknown = 0;
    for (unsigned i = next() % 11; i; i--)
      unknown |= UINT64_C(1) << (next() % 16);
    uint64_t fixed_free = next() & next() & next() & ~unknown;
    if (next() & 1)
      fixed_free &= ~SHELL_FD_LOW_INTERVAL;
    shell_fd_occupancy_t o = {fixed_free | unknown, ~fixed_free};
    uint32_t positions[64], count = 0;
    for (uint32_t fd = 0; fd < 64; fd++)
      if ((unknown >> fd) & 1)
        positions[count++] = fd;
    shell_fd_occupancy_t hull[2] = {{0, 0}, {0, 0}};
    for (uint64_t world = 0; world < (UINT64_C(1) << count); world++) {
      uint64_t free = fixed_free;
      for (uint32_t i = 0; i < count; i++)
        if ((world >> i) & 1)
          free |= UINT64_C(1) << positions[i];
      unsigned full = (free & SHELL_FD_LOW_INTERVAL) == 0;
      hull[full].may_free |= free;
      hull[full].may_occupied |= ~free;
    }
    /* Each case is its own origin: parts 0 and 3. */
    shell_fd_partition_t split = shell_fd_partition_split(&o);
    for (unsigned full = 0; full < 2; full++) {
      const shell_fd_occupancy_t *part = &split.part[full ? 3 : 0];
      if (part->may_free != hull[full].may_free ||
          part->may_occupied != hull[full].may_occupied) {
        printf("    split case %u: %016llx/%016llx want %016llx/%016llx\n",
               full, (unsigned long long)part->may_free,
               (unsigned long long)part->may_occupied,
               (unsigned long long)hull[full].may_free,
               (unsigned long long)hull[full].may_occupied);
        ok = 0;
      }
    }
    if (split.part[1].may_free | split.part[1].may_occupied |
        split.part[2].may_free | split.part[2].may_occupied)
      ok = 0;
    /* Refining keeps every table of each part's own case; normalizing files
     * every table of a part, as left by updates that ignored the cases, under
     * its case within the same origin. */
    shell_fd_partition_t parts;
    for (unsigned part = 0; part < SHELL_FD_PARTS; part++)
      parts.part[part] = random_occupancy();
    shell_fd_partition_t refined = parts, normal = parts;
    shell_fd_partition_refine(&refined);
    shell_fd_partition_normalize(&normal);
    for (unsigned sample = 0; sample < 400 && ok; sample++) {
      unsigned part = sample % SHELL_FD_PARTS;
      const shell_fd_occupancy_t *from = &parts.part[part];
      uint64_t free = (from->may_free & ~from->may_occupied) |
                      (from->may_free & from->may_occupied & next());
      unsigned full = (free & SHELL_FD_LOW_INTERVAL) == 0;
      if (full == shell_fd_part_full(part) &&
          !table_allowed(&refined.part[part], free)) {
        printf("    refine lost a table of part %u\n", part);
        ok = 0;
      }
      if (!table_allowed(&normal.part[(part & ~1u) | full], free)) {
        printf("    normalize lost a table of part %u\n", part);
        ok = 0;
      }
    }
  }
  TEST("low-interval cases are exact hulls and keep every table", ok);
}

int main(void) {
  printf("fd occupancy\n");
  test_allocation_matches_reference();
  test_against_concrete_tables();
  test_select_is_the_exact_hull();
  test_pipe_select_is_the_exact_hull();
  test_known_tables();
  test_take_and_release();
  test_partition_cases();
  printf("%d passed, %d failed\n", passed, failed);
  return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
