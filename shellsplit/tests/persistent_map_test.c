#include <stddef.h>
#include <stdint.h>

static size_t work;
#define SHELL_PMAP_WORK() (work++)
#include "shell_pmap_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The trie is checked against a sorted reference map under random updates:
 * lookups, ordered iteration, summaries, diffs and persistence of old
 * versions; canonicity (equal contents give equal roots, whatever the update
 * order); collection and suffix rollback; capacity failure leaving published
 * roots valid; and the structural cost bounds. */

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

enum { CAPACITY = 60000, TABLE = 1u << 17, MODEL = 512, VERSIONS = 64 };

static shell_pmap_node_t nodes[CAPACITY];
static uint16_t table[TABLE];
static uint8_t marks[CAPACITY];
static shell_pmap_pool_t pool;

typedef struct {
  uint64_t key;
  uint32_t value;
  uint8_t summary;
} entry_t;

typedef struct {
  entry_t entries[MODEL];
  uint32_t count;
  uint32_t root;
} version_t;

static version_t versions[VERSIONS];

/* Keys mix small descriptor-like values, shifted facets and high bits, so
 * tries share long prefixes and also branch near the top bit. */
static uint64_t random_key(void) {
  switch (next() % 4) {
  case 0:
    return next() % 64;
  case 1:
    return (next() % 32) << 6 | (next() % 40);
  case 2:
    return UINT64_C(1) << (next() % 64);
  default:
    return next() % 8 ? (next() % 200) << 20 : next();
  }
}

/* The summary is a function of the entry, as the map contract requires. */
static uint8_t summary_of(uint64_t key, uint32_t value) {
  return (uint8_t)(1u << ((key ^ value) % 8));
}

static int find(const version_t *v, uint64_t key) {
  for (uint32_t i = 0; i < v->count; i++)
    if (v->entries[i].key == key)
      return (int)i;
  return -1;
}

static void model_set(version_t *v, uint64_t key, uint32_t value) {
  int at = find(v, key);
  entry_t entry = {key, value, summary_of(key, value)};
  if (at >= 0) {
    v->entries[at] = entry;
    return;
  }
  uint32_t i = v->count++;
  while (i && v->entries[i - 1].key > key) {
    v->entries[i] = v->entries[i - 1];
    i--;
  }
  v->entries[i] = entry;
}

static void model_erase(version_t *v, uint64_t key) {
  int at = find(v, key);
  if (at < 0)
    return;
  memmove(&v->entries[at], &v->entries[at + 1],
          (v->count - (uint32_t)at - 1) * sizeof(entry_t));
  v->count--;
}

typedef struct {
  const version_t *expected;
  uint32_t seen;
  uint8_t mask;
  bool ok;
} walk_t;

static bool check_leaf(void *context, uint64_t key, uint32_t value,
                       uint8_t summary) {
  walk_t *walk = context;
  const version_t *v = walk->expected;
  while (walk->seen < v->count &&
         !(v->entries[walk->seen].summary & walk->mask))
    walk->seen++;
  if (walk->seen >= v->count || v->entries[walk->seen].key != key ||
      v->entries[walk->seen].value != value ||
      v->entries[walk->seen].summary != summary)
    walk->ok = false;
  walk->seen++;
  return walk->ok;
}

/* Lookups, ascending iteration and summary iteration agree with the model. */
static bool matches(const version_t *v) {
  for (uint32_t i = 0; i < v->count; i++) {
    uint32_t value;
    if (!shell_pmap_get(&pool, v->root, v->entries[i].key, &value) ||
        value != v->entries[i].value)
      return false;
  }
  for (unsigned probe = 0; probe < 16; probe++) {
    uint64_t key = random_key();
    uint32_t value;
    if (find(v, key) < 0 && shell_pmap_get(&pool, v->root, key, &value))
      return false;
  }
  walk_t all = {v, 0, 0xff, true};
  if (!shell_pmap_each(&pool, v->root, check_leaf, &all) ||
      all.seen != v->count)
    return false;
  uint8_t mask = (uint8_t)(1u << (next() % 8) | 1u << (next() % 8));
  walk_t some = {v, 0, mask, true};
  if (!shell_pmap_each_summary(&pool, v->root, mask, check_leaf, &some))
    return false;
  for (uint32_t i = some.seen; i < v->count; i++)
    if (v->entries[i].summary & mask)
      return false;
  return true;
}

/* Rebuilding the contents in a shuffled order yields the same root. */
static bool canonical(const version_t *v) {
  uint32_t order[MODEL];
  for (uint32_t i = 0; i < v->count; i++)
    order[i] = i;
  for (uint32_t i = v->count; i > 1; i--) {
    uint32_t j = (uint32_t)(next() % i), t = order[i - 1];
    order[i - 1] = order[j];
    order[j] = t;
  }
  uint32_t root = 0;
  for (uint32_t i = 0; i < v->count; i++) {
    const entry_t *e = &v->entries[order[i]];
    if (!shell_pmap_set(&pool, &root, e->key, e->value, e->summary))
      return false;
  }
  return root == v->root;
}

typedef struct {
  const version_t *left, *right;
  uint32_t li, ri, reported;
  bool ok;
} diff_t;

/* Advance the merged reference walk to the next differing key. */
static bool next_difference(diff_t *d, uint64_t *key, shell_pmap_sides_t *sides,
                            uint32_t *lv, uint32_t *rv) {
  while (d->li < d->left->count || d->ri < d->right->count) {
    const entry_t *l = d->li < d->left->count ? &d->left->entries[d->li] : NULL;
    const entry_t *r =
        d->ri < d->right->count ? &d->right->entries[d->ri] : NULL;
    if (l && (!r || l->key < r->key)) {
      d->li++;
      *key = l->key, *sides = SHELL_PMAP_LEFT, *lv = l->value, *rv = 0;
      return true;
    }
    if (r && (!l || r->key < l->key)) {
      d->ri++;
      *key = r->key, *sides = SHELL_PMAP_RIGHT, *lv = 0, *rv = r->value;
      return true;
    }
    d->li++, d->ri++;
    if (l->value != r->value || l->summary != r->summary) {
      *key = l->key, *sides = SHELL_PMAP_BOTH, *lv = l->value, *rv = r->value;
      return true;
    }
  }
  return false;
}

static bool check_difference(void *context, uint64_t key,
                             shell_pmap_sides_t present, uint32_t left_value,
                             uint32_t right_value) {
  diff_t *d = context;
  uint64_t k;
  shell_pmap_sides_t sides;
  uint32_t lv, rv;
  if (!next_difference(d, &k, &sides, &lv, &rv) || k != key ||
      sides != present || lv != left_value || rv != right_value)
    d->ok = false;
  d->reported++;
  return d->ok;
}

static bool diff_matches(const version_t *left, const version_t *right) {
  diff_t d = {left, right, 0, 0, 0, true};
  if (!shell_pmap_diff(&pool, left->root, right->root, check_difference, &d) ||
      !d.ok)
    return false;
  uint64_t k;
  shell_pmap_sides_t sides;
  uint32_t lv, rv;
  return !next_difference(&d, &k, &sides, &lv, &rv);
}

static bool update(version_t *v) {
  uint64_t key = random_key();
  if (v->count && next() % 4 == 0) {
    if (next() % 2)
      key = v->entries[next() % v->count].key;
    model_erase(v, key);
    return shell_pmap_erase(&pool, &v->root, key);
  }
  if (v->count >= MODEL)
    return true;
  uint32_t value = (uint32_t)(next() % 6);
  model_set(v, key, value);
  return shell_pmap_set(&pool, &v->root, key, value, summary_of(key, value));
}

static void reset(void) {
  shell_pmap_init(&pool, nodes, table, marks, CAPACITY, TABLE);
  memset(versions, 0, sizeof(versions));
}

static void test_matches_reference(void) {
  reset();
  bool ok = true;
  for (unsigned round = 0; round < 6000 && ok; round++) {
    version_t *v = &versions[next() % VERSIONS];
    if (next() % 8 == 0)
      *v = versions[next() % VERSIONS];
    ok = update(v) && matches(v);
    if (ok && round % 37 == 0) {
      /* Every earlier version stays intact. */
      for (unsigned i = 0; i < VERSIONS && ok; i++)
        ok = matches(&versions[i]);
      ok = ok && canonical(v) && diff_matches(v, &versions[next() % VERSIONS]);
    }
    if (pool.count > CAPACITY - 4000) {
      shell_pmap_mark_begin(&pool);
      for (unsigned i = 0; i < VERSIONS; i++)
        shell_pmap_mark(&pool, versions[i].root, NULL, NULL);
      shell_pmap_sweep(&pool);
    }
  }
  TEST("random updates match the reference map", ok);
  for (unsigned i = 0; i < VERSIONS && ok; i++)
    ok = matches(&versions[i]) && canonical(&versions[i]);
  TEST("versions survive collection and stay canonical", ok);
}

/* Restriction to a prefix equals the reference map filtered to that prefix,
 * and is an existing node: it allocates nothing. */
static void test_restrict(void) {
  reset();
  bool ok = true;
  for (unsigned round = 0; round < 400 && ok; round++) {
    version_t *v = &versions[0];
    ok = update(v);
    unsigned bit = (unsigned)(next() % 64);
    uint64_t prefix = shell_pmap_mask(random_key(), bit);
    uint32_t before = pool.count;
    uint32_t restricted = shell_pmap_restrict(&pool, v->root, prefix, bit);
    ok = ok && pool.count == before;
    version_t expected = {.count = 0};
    for (uint32_t i = 0; i < v->count; i++)
      if (shell_pmap_mask(v->entries[i].key, bit) == prefix)
        expected.entries[expected.count++] = v->entries[i];
    expected.root = restricted;
    ok = ok && matches(&expected) && canonical(&expected);
    if (pool.count > CAPACITY - 4000) {
      shell_pmap_mark_begin(&pool);
      shell_pmap_mark(&pool, v->root, NULL, NULL);
      shell_pmap_sweep(&pool);
    }
  }
  TEST("restriction is the filtered map, without allocation", ok);
}

static void test_rollback(void) {
  reset();
  version_t *v = &versions[0];
  for (unsigned i = 0; i < 200; i++)
    update(v);
  version_t kept = *v;
  pool.reuse = false;
  uint32_t mark = pool.count;
  for (unsigned i = 0; i < 300; i++)
    update(v);
  shell_pmap_rollback(&pool, mark);
  pool.reuse = true;
  TEST("rollback releases exactly the suffix", pool.count == mark);
  TEST("roots published before rollback survive", matches(&kept));
  /* The intern table no longer knows the released nodes, so rebuilding a
   * released version recreates it and canonicity still holds. */
  *v = kept;
  bool ok = true;
  for (unsigned i = 0; i < 300 && ok; i++)
    ok = update(v) && matches(v);
  TEST("updates after rollback stay canonical", ok && canonical(v));
}

static void test_capacity_failure(void) {
  enum { SMALL = 300 };
  static shell_pmap_node_t few[SMALL];
  static uint16_t few_table[1024];
  static uint8_t few_marks[SMALL];
  shell_pmap_init(&pool, few, few_table, few_marks, SMALL, 1024);
  memset(versions, 0, sizeof(versions));
  version_t *v = &versions[0];
  version_t last = *v;
  bool failed_once = false, intact = true;
  for (unsigned i = 0; i < 2000 && !failed_once; i++) {
    uint64_t key = random_key();
    uint32_t root = v->root;
    if (!shell_pmap_set(&pool, &root, key, 1, summary_of(key, 1))) {
      failed_once = true;
      intact = root == v->root && matches(&last);
    } else {
      model_set(v, key, 1);
      v->root = root;
      last = *v;
    }
  }
  TEST("a full pool fails the update", failed_once);
  TEST("a failed update leaves published roots valid", intact);
}

/* Cost: an update touches at most W + 2 levels, and a diff of maps sharing
 * structure costs in proportion to the differing keys, not their size. */
static void test_cost_bounds(void) {
  reset();
  version_t *big = &versions[0];
  for (uint64_t i = 0; i < 4096 && big->count < MODEL; i++) {
    uint64_t key = (i * UINT64_C(0x9e3779b97f4a7c15)) >> 20;
    model_set(big, key, 1);
    shell_pmap_set(&pool, &big->root, key, 1, summary_of(key, 1));
  }
  size_t worst_update = 0, worst_diff = 0;
  for (unsigned trial = 0; trial < 200; trial++) {
    version_t changed = *big;
    unsigned changes = 1 + (unsigned)(next() % 4);
    for (unsigned c = 0; c < changes; c++) {
      uint64_t key = changed.entries[next() % changed.count].key;
      model_set(&changed, key, 2 + c);
      work = 0;
      shell_pmap_set(&pool, &changed.root, key, 2 + c, summary_of(key, 2 + c));
      if (work > worst_update)
        worst_update = work;
    }
    work = 0;
    diff_t d = {big, &changed, 0, 0, 0, true};
    shell_pmap_diff(&pool, big->root, changed.root, check_difference, &d);
    size_t per_key = work / (d.reported ? d.reported : 1);
    if (per_key > worst_diff)
      worst_diff = per_key;
  }
  TEST("an update visits at most W + 2 levels", worst_update <= 66);
  TEST("a diff costs at most 2(W + 1) steps per differing key",
       worst_diff <= 130);
}

int main(void) {
  printf("persistent map\n");
  test_matches_reference();
  test_restrict();
  test_rollback();
  test_capacity_failure();
  test_cost_bounds();
  printf("%d passed, %d failed\n", passed, failed);
  return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
