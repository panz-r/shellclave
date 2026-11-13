/* Scaling suite for the descriptor analysis (docs/fd-engine-redesign.md).
 *
 * Each family repeats one unit n times, n = 4, 8, 16, 32 up to the largest
 * size that fits the graph capacity, and parses the source. Its work is all
 * counted metadata work, including persistent-map steps, so a cost hidden in
 * any analysis structure shows. Two bounds hold per family:
 * - work(2n) / work(n) <= 2.2 * bytes(2n) / bytes(n);
 * - work(n) <= C * n * log2(n), with C fixed per family.
 * Every parse must succeed: work measured after a capacity stop says nothing
 * about the analysis. */
#include "graph_fixture.h"
#include "shell_depgraph.h"
#include "test_source_scans.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition);          \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
typedef struct {
  const char *name;
  const char *prefix;
  /* printf format taking the unit's index once, as %1$u. */
  const char *unit;
  const char *suffix;
  /* Largest n within the graph capacity. */
  unsigned maximum;
  /* C: the measured worst work / (n log2 n), plus a quarter, rounded. */
  size_t constant;
} family_t;

static const family_t families[] = {
    {"opens x substitutions", "",
     "exec {f%1$u}<input || exit; true \"$(read -u\"$f%1$u\" -n0 v)\"; ", "",
     16, 1600},
    {"opens x redirecting commands", "",
     "exec {f%1$u}<input || exit; cat <&\"$f%1$u\" >out%1$u; ", "", 16, 1600},
    {"substitutions touching no descriptor", "exec {f}<input || exit; ",
     "v%1$u=$(true); ", "", 32, 500},
    {"nested substitutions", "", "echo \"$(", "", 8, 200},
    {"branch ladders over named descriptors", "",
     "choice && exec {f%1$u}>a%1$u || exec {f%1$u}>b%1$u; ", "", 16, 1150},
    {"groups with save and restore", "", "{ echo x; } >out%1$u 2>&1; ", "", 32,
     2500},
    {"named allocations", "", "exec {f%1$u}>out%1$u; ", "", 32, 500},
    {"pipelines", "", "printf x | cat >out%1$u; ", "", 32, 600},
    {"process substitutions", "", "cat <(printf x) >out%1$u; ", "", 32, 420},
    {"here-documents", "", "cat <<EOF >out%1$u\nx\nEOF\n", "", 8, 400},
};

/* The nested family closes what its units opened. */
static size_t append_suffix(char *source, size_t used, size_t capacity,
                            const family_t *family, unsigned count) {
  if (!strcmp(family->unit, "echo \"$(")) {
    for (unsigned i = 0; i < count; i++) {
      CHECK(used + 2 < capacity);
      memcpy(source + used, ")\"", 2);
      used += 2;
    }
  }
  size_t length = strlen(family->suffix);
  CHECK(used + length < capacity);
  memcpy(source + used, family->suffix, length + 1);
  return used + length;
}

static size_t total_work(void) {
  size_t work = 0;
  for (unsigned kind = 0; kind < SHELLSPLIT_TEST_WORK_COUNT; kind++)
    work +=
        shellsplit_test_metadata_work((shellsplit_test_metadata_kind_t)kind);
  return work;
}

static unsigned log2_ceiling(unsigned n) {
  unsigned bits = 0;
  while ((1u << bits) < n)
    bits++;
  return bits;
}

static void check_families(void) {
  shellsplit_graph_fixture_t fixture;
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_FIXED, 0, 1,
                                      false, 0));
  shell_dep_limits_t limits = fixture.limits;
  shell_dep_graph_t *graph = fixture.graph[0];
  bool report = getenv("FD_SCALING_REPORT") != NULL;
  for (size_t f = 0; f < sizeof(families) / sizeof(families[0]); f++) {
    const family_t *family = &families[f];
    size_t previous_work = 0, previous_bytes = 0, worst = 0;
    for (unsigned count = 4; count <= family->maximum; count *= 2) {
      static char source[16384];
      size_t used = strlen(family->prefix);
      memcpy(source, family->prefix, used);
      for (unsigned i = 0; i < count; i++) {
        int n = snprintf(source + used, sizeof(source) - used, family->unit, i);
        CHECK(n > 0 && (size_t)n < sizeof(source) - used);
        used += (size_t)n;
      }
      used = append_suffix(source, used, sizeof(source), family, count);
      shellsplit_test_source_scan_reset();
      shell_dep_error_t status =
          shell_dep_graph_parse(source, used, "/", &limits, graph);
      size_t work = total_work();
      size_t bound = (size_t)count * log2_ceiling(count);
      if (report || status != SHELL_DEP_OK)
        fprintf(
            stderr,
            "%-40s n=%2u bytes=%5zu status=%d work=%zu (%.1f per n log n)\n",
            family->name, count, used, status, work,
            (double)work / (double)bound);
      CHECK(status == SHELL_DEP_OK && shell_dep_graph_validate(graph).valid);
      if (previous_work) {
        /* work / previous <= 2.2 * used / previous_bytes, in integers. */
        bool ratio = work * previous_bytes * 10 <= 22 * used * previous_work;
        if (!ratio)
          fprintf(stderr, "%s: n=%u work %zu after %zu, bytes %zu after %zu\n",
                  family->name, count, work, previous_work, used,
                  previous_bytes);
        CHECK(ratio);
      }
      if (work > worst * bound)
        worst = (work + bound - 1) / bound;
      previous_work = work;
      previous_bytes = used;
    }
    if (family->constant) {
      if (worst > family->constant)
        fprintf(stderr, "%s: needs C=%zu, budget %zu\n", family->name, worst,
                family->constant);
      CHECK(worst <= family->constant);
    } else if (report)
      fprintf(stderr, "%s: C=%zu\n", family->name, worst);
  }
  shellsplit_graph_fixture_destroy(&fixture);
}
#endif

int main(void) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  check_families();
#endif
  puts("fd scaling tests passed");
  return EXIT_SUCCESS;
}
