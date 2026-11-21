/* Scaling suite for the descriptor analysis.
 *
 * Each family repeats one unit n times, n = 4, 8, 16, 32 up to the largest
 * size that fits the graph capacity, and parses the source. Its work is all
 * counted metadata work, including persistent-map steps, so a cost hidden in
 * any analysis structure shows. Two bounds hold per family:
 * - work(2n) / work(n) <= 2.2 * bytes(2n) / bytes(n);
 * - work(n) <= C * n * log2(n), with C fixed per family.
 * Every parse must succeed: work measured after a capacity stop says nothing
 * about the analysis. */
#include "../src/shell_depgraph_internal.h"
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
  /* Closes each unit's opening, once per unit, after the suffix. */
  const char *closer;
} family_t;

static const family_t families[] = {
    {"opens x substitutions", "",
     "exec {f%1$u}<input || exit; true \"$(read -u\"$f%1$u\" -n0 v)\"; ", "",
     16, 1600, NULL},
    {"opens x redirecting commands", "",
     "exec {f%1$u}<input || exit; cat <&\"$f%1$u\" >out%1$u; ", "", 16, 1600,
     NULL},
    {"substitutions touching no descriptor", "exec {f}<input || exit; ",
     "v%1$u=$(true); ", "", 32, 500, NULL},
    {"nested substitutions", "", "echo \"$(", "", 8, 200, ")\""},
    {"branch ladders over named descriptors", "",
     "choice && exec {f%1$u}>a%1$u || exec {f%1$u}>b%1$u; ", "", 16, 1150,
     NULL},
    {"groups with save and restore", "", "{ echo x; } >out%1$u 2>&1; ", "", 32,
     2500, NULL},
    {"named allocations", "", "exec {f%1$u}>out%1$u; ", "", 32, 500, NULL},
    {"pipelines", "", "printf x | cat >out%1$u; ", "", 32, 600, NULL},
    {"process substitutions", "", "cat <(printf x) >out%1$u; ", "", 32, 420,
     NULL},
    {"here-documents", "", "cat <<EOF >out%1$u\nx\nEOF\n", "", 8, 400, NULL},
    {"if ladders over named descriptors", "",
     "if choice; then exec {f%1$u}>a%1$u; else exec {f%1$u}>b%1$u; fi; ", "", 8,
     1180, NULL},
    {"nested ifs over named descriptors", "",
     "if choice; then exec {f%1$u}>a%1$u; else ", "true; ", 8, 720, "fi; "},
    {"nested ifs over one descriptor", "exec 3>base || exit; ",
     "if choice; then exec 3>a%1$u || exit; else ", "true; ", 8, 700, "fi; "},
    {"nested ifs over duplicated named descriptors", "",
     "if choice; then exec {f%1$u}>&2; else ", "true; ", 16, 1550, "fi; "},
    {"nested ifs over duplicated numbered descriptors", "",
     "if choice; then exec 3>&2 || exit; else ", "true; ", 16, 310, "fi; "},
    {"elif chains over named descriptors", "if choice; then :; ",
     "elif choice%1$u; then exec {f%1$u}>a%1$u; ", "else :; fi", 8, 650, NULL},
    {"if chains over one descriptor", "exec 3>base || exit; ",
     "if choice; then exec 3>a%1$u || exit; fi; ", "", 8, 660, NULL},
};

/* The nested families close what their units opened. */
static size_t append_suffix(char *source, size_t used, size_t capacity,
                            const family_t *family, unsigned count) {
  size_t length = strlen(family->suffix);
  CHECK(used + length < capacity);
  memcpy(source + used, family->suffix, length + 1);
  used += length;
  length = family->closer ? strlen(family->closer) : 0;
  for (unsigned i = 0; i < count; i++) {
    CHECK(used + length < capacity);
    if (length)
      memcpy(source + used, family->closer, length);
    used += length;
  }
  source[used] = '\0';
  return used;
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

/* The join of versions is a union of persistent maps: nested conditionals
 * that each write a descriptor of their own join the version holding every
 * write inside with the entry version at every level. A join that walked the
 * keys its two versions differ in would cost the writes inside it each time,
 * quadratic in the depth; the union costs the node pairs the two sides do not
 * share, so doubling the depth doubles the work up to a logarithm. The depth
 * is not bounded by the graph capacity here, since the hook builds versions
 * directly. */
static void check_nested_join(void) {
  shellsplit_graph_fixture_t fixture;
  CHECK(shellsplit_graph_fixture_init(&fixture, SHELLSPLIT_FIXTURE_FIXED, 0, 1,
                                      false, 0));
  bool report = getenv("FD_SCALING_REPORT") != NULL;
  size_t previous = 0;
  for (unsigned depth = 32; depth <= 256; depth *= 2) {
    shellsplit_test_source_scan_reset();
    CHECK(
        shellsplit_test_nested_join_contract(fixture.limits.workspace, depth));
    size_t work = total_work();
    size_t bound = (size_t)depth * log2_ceiling(depth);
    if (report)
      fprintf(stderr, "nested joins depth=%3u work=%zu (%.1f per n log n)\n",
              depth, work, (double)work / (double)bound);
    /* Quadratic work would quadruple; n log n grows by at most 2.5x. */
    if (previous)
      CHECK(work * 10 <= 25 * previous);
    CHECK(work <= 400 * bound);
    previous = work;
  }
  /* And through the exact merge, which must factor every level into one
   * version, deciding its exactness from a memoized fold. */
  previous = 0;
  for (unsigned depth = 32; depth <= 256; depth *= 2) {
    shellsplit_test_source_scan_reset();
    CHECK(
        shellsplit_test_nested_merge_contract(fixture.limits.workspace, depth));
    size_t work = total_work();
    size_t bound = (size_t)depth * log2_ceiling(depth);
    if (report)
      fprintf(stderr, "nested merges depth=%3u work=%zu (%.1f per n log n)\n",
              depth, work, (double)work / (double)bound);
    if (previous)
      CHECK(work * 10 <= 25 * previous);
    CHECK(work <= 400 * bound);
    previous = work;
  }
  shellsplit_graph_fixture_destroy(&fixture);
}
#endif

int main(void) {
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  check_families();
  check_nested_join();
#endif
  puts("fd scaling tests passed");
  return EXIT_SUCCESS;
}
