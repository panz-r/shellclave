/* The leaf modules of the analysis, each checked against a reference model: the
 * persistent map and its union and fold, the AVL index, the file descriptor
 * occupancy tables, the netstring codec and the secret screener. */
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static size_t work, fresh, hits;
#define SHELL_PMAP_WORK() (work++)
#define SHELL_PMAP_FRESH() (fresh++)
#define SHELL_PMAP_MEMO_HIT() (hits++)
#include "env_screener.h"
#include "relative_permutation_entropy.h"
#include "shell_avl_index_internal.h"
#include "shell_fd_occupancy_internal.h"
#include "shell_netstring.h"
#include "shell_pmap_internal.h"
#include "test_allocator.h"

/* --- structures (from structures_test.c) --- */
/* The leaf data structures of the analysis, each checked against a reference
 * model: the persistent map and its union and fold, the AVL index, the file
 * descriptor occupancy tables and the netstring codec. */
static int structures_passed;
static int structures_failed;

#define TEST(name, condition)                                                  \
  do {                                                                         \
    if (condition) {                                                           \
      structures_passed++;                                                     \
    } else {                                                                   \
      printf("  [FAIL] %s\n", name);                                           \
      structures_failed++;                                                     \
    }                                                                          \
  } while (0)

/* --- pmap --- */
/* The trie is checked against a sorted reference map under random updates:
 * lookups, ordered iteration, summaries, diffs and persistence of old
 * versions; canonicity (equal contents give equal roots, whatever the update
 * order); collection and suffix rollback; capacity failure leaving published
 * roots valid; and the structural cost bounds. */

/* Every section starts its random stream from the same seed. */
#define RNG_SEED 0x9e3779b97f4a7c15u
static uint64_t structures_state = RNG_SEED;

static uint64_t structures_next(void) {
  structures_state ^= structures_state << 13;
  structures_state ^= structures_state >> 7;
  structures_state ^= structures_state << 17;
  return structures_state;
}

enum {
  structures_CAPACITY = 60000,
  structures_TABLE = 1u << 17,
  structures_MODEL = 512,
  structures_VERSIONS = 64
};

static shell_pmap_node_t structures_nodes[structures_CAPACITY];
static uint16_t structures_table[structures_TABLE];
static uint8_t structures_marks[structures_CAPACITY];
static shell_pmap_pool_t structures_pool;

typedef struct {
  uint64_t key;
  uint32_t value;
  uint8_t summary;
} structures_entry_t;

typedef struct {
  structures_entry_t entries[structures_MODEL];
  uint32_t count;
  uint32_t root;
} structures_version_t;

static structures_version_t structures_versions[structures_VERSIONS];

/* Keys mix small descriptor-like values, shifted facets and high bits, so
 * tries share long prefixes and also branch near the top bit. */
static uint64_t structures_random_key(void) {
  switch (structures_next() % 4) {
  case 0:
    return structures_next() % 64;
  case 1:
    return (structures_next() % 32) << 6 | (structures_next() % 40);
  case 2:
    return UINT64_C(1) << (structures_next() % 64);
  default:
    return structures_next() % 8 ? (structures_next() % 200) << 20
                                 : structures_next();
  }
}

/* The summary is a function of the entry, as the map contract requires. */
static uint8_t structures_summary_of(uint64_t key, uint32_t value) {
  return (uint8_t)(1u << ((key ^ value) % 8));
}

static int structures_find(const structures_version_t *v, uint64_t key) {
  for (uint32_t i = 0; i < v->count; i++)
    if (v->entries[i].key == key)
      return (int)i;
  return -1;
}

static void structures_model_set(structures_version_t *v, uint64_t key,
                                 uint32_t value) {
  int at = structures_find(v, key);
  structures_entry_t entry = {key, value, structures_summary_of(key, value)};
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

static void structures_model_erase(structures_version_t *v, uint64_t key) {
  int at = structures_find(v, key);
  if (at < 0)
    return;
  memmove(&v->entries[at], &v->entries[at + 1],
          (v->count - (uint32_t)at - 1) * sizeof(structures_entry_t));
  v->count--;
}

typedef struct {
  const structures_version_t *expected;
  uint32_t seen;
  uint8_t mask;
  bool ok;
} structures_walk_t;

static bool structures_check_leaf(void *context, uint64_t key, uint32_t value,
                                  uint8_t summary) {
  structures_walk_t *walk = context;
  const structures_version_t *v = walk->expected;
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
static bool structures_matches(const structures_version_t *v) {
  for (uint32_t i = 0; i < v->count; i++) {
    uint32_t value;
    if (!shell_pmap_get(&structures_pool, v->root, v->entries[i].key, &value) ||
        value != v->entries[i].value)
      return false;
  }
  for (unsigned probe = 0; probe < 16; probe++) {
    uint64_t key = structures_random_key();
    uint32_t value;
    if (structures_find(v, key) < 0 &&
        shell_pmap_get(&structures_pool, v->root, key, &value))
      return false;
  }
  structures_walk_t all = {v, 0, 0xff, true};
  if (!shell_pmap_each(&structures_pool, v->root, structures_check_leaf,
                       &all) ||
      all.seen != v->count)
    return false;
  uint8_t mask =
      (uint8_t)(1u << (structures_next() % 8) | 1u << (structures_next() % 8));
  structures_walk_t some = {v, 0, mask, true};
  if (!shell_pmap_each_summary(&structures_pool, v->root, mask,
                               structures_check_leaf, &some))
    return false;
  for (uint32_t i = some.seen; i < v->count; i++)
    if (v->entries[i].summary & mask)
      return false;
  return true;
}

/* Rebuilding the contents in a shuffled order yields the same root. */
static bool structures_canonical(const structures_version_t *v) {
  uint32_t order[structures_MODEL];
  for (uint32_t i = 0; i < v->count; i++)
    order[i] = i;
  for (uint32_t i = v->count; i > 1; i--) {
    uint32_t j = (uint32_t)(structures_next() % i), t = order[i - 1];
    order[i - 1] = order[j];
    order[j] = t;
  }
  uint32_t root = 0;
  for (uint32_t i = 0; i < v->count; i++) {
    const structures_entry_t *e = &v->entries[order[i]];
    if (!shell_pmap_set(&structures_pool, &root, e->key, e->value, e->summary))
      return false;
  }
  return root == v->root;
}

typedef struct {
  const structures_version_t *left, *right;
  uint32_t li, ri, reported;
  bool ok;
} structures_diff_t;

/* Advance the merged reference walk to the next differing key. */
static bool structures_next_difference(structures_diff_t *d, uint64_t *key,
                                       shell_pmap_sides_t *sides, uint32_t *lv,
                                       uint32_t *rv) {
  while (d->li < d->left->count || d->ri < d->right->count) {
    const structures_entry_t *l =
        d->li < d->left->count ? &d->left->entries[d->li] : NULL;
    const structures_entry_t *r =
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

static bool structures_check_difference(void *context, uint64_t key,
                                        shell_pmap_sides_t present,
                                        uint32_t left_value,
                                        uint32_t right_value) {
  structures_diff_t *d = context;
  uint64_t k;
  shell_pmap_sides_t sides;
  uint32_t lv, rv;
  if (!structures_next_difference(d, &k, &sides, &lv, &rv) || k != key ||
      sides != present || lv != left_value || rv != right_value)
    d->ok = false;
  d->reported++;
  return d->ok;
}

static bool structures_diff_matches(const structures_version_t *left,
                                    const structures_version_t *right) {
  structures_diff_t d = {left, right, 0, 0, 0, true};
  if (!shell_pmap_diff(&structures_pool, left->root, right->root,
                       structures_check_difference, &d) ||
      !d.ok)
    return false;
  uint64_t k;
  shell_pmap_sides_t sides;
  uint32_t lv, rv;
  return !structures_next_difference(&d, &k, &sides, &lv, &rv);
}

static bool structures_update(structures_version_t *v) {
  uint64_t key = structures_random_key();
  if (v->count && structures_next() % 4 == 0) {
    if (structures_next() % 2)
      key = v->entries[structures_next() % v->count].key;
    structures_model_erase(v, key);
    return shell_pmap_erase(&structures_pool, &v->root, key);
  }
  if (v->count >= structures_MODEL)
    return true;
  uint32_t value = (uint32_t)(structures_next() % 6);
  structures_model_set(v, key, value);
  return shell_pmap_set(&structures_pool, &v->root, key, value,
                        structures_summary_of(key, value));
}

static void structures_reset(void) {
  shell_pmap_init(&structures_pool, structures_nodes, structures_table,
                  structures_marks, structures_CAPACITY, structures_TABLE);
  memset(structures_versions, 0, sizeof(structures_versions));
}

static void structures_test_pmap_matches_reference(void) {
  structures_reset();
  bool ok = true;
  for (unsigned round = 0; round < 6000 && ok; round++) {
    structures_version_t *v =
        &structures_versions[structures_next() % structures_VERSIONS];
    if (structures_next() % 8 == 0)
      *v = structures_versions[structures_next() % structures_VERSIONS];
    ok = structures_update(v) && structures_matches(v);
    if (ok && round % 37 == 0) {
      /* Every earlier version stays intact. */
      for (unsigned i = 0; i < structures_VERSIONS && ok; i++)
        ok = structures_matches(&structures_versions[i]);
      ok =
          ok && structures_canonical(v) &&
          structures_diff_matches(
              v, &structures_versions[structures_next() % structures_VERSIONS]);
    }
    if (structures_pool.count > structures_CAPACITY - 4000) {
      shell_pmap_mark_begin(&structures_pool);
      for (unsigned i = 0; i < structures_VERSIONS; i++)
        shell_pmap_mark(&structures_pool, structures_versions[i].root, NULL,
                        NULL);
      shell_pmap_sweep(&structures_pool);
    }
  }
  TEST("random updates match the reference map", ok);
  for (unsigned i = 0; i < structures_VERSIONS && ok; i++)
    ok = structures_matches(&structures_versions[i]) &&
         structures_canonical(&structures_versions[i]);
  TEST("versions survive collection and stay canonical", ok);
}

/* Restriction to a prefix equals the reference map filtered to that prefix,
 * and is an existing node: it allocates nothing. */
static void structures_test_pmap_restrict(void) {
  structures_reset();
  bool ok = true;
  for (unsigned round = 0; round < 400 && ok; round++) {
    structures_version_t *v = &structures_versions[0];
    ok = structures_update(v);
    unsigned bit = (unsigned)(structures_next() % 64);
    uint64_t prefix = shell_pmap_mask(structures_random_key(), bit);
    uint32_t before = structures_pool.count;
    uint32_t restricted =
        shell_pmap_restrict(&structures_pool, v->root, prefix, bit);
    ok = ok && structures_pool.count == before;
    structures_version_t expected = {.count = 0};
    for (uint32_t i = 0; i < v->count; i++)
      if (shell_pmap_mask(v->entries[i].key, bit) == prefix)
        expected.entries[expected.count++] = v->entries[i];
    expected.root = restricted;
    ok = ok && structures_matches(&expected) && structures_canonical(&expected);
    if (structures_pool.count > structures_CAPACITY - 4000) {
      shell_pmap_mark_begin(&structures_pool);
      shell_pmap_mark(&structures_pool, v->root, NULL, NULL);
      shell_pmap_sweep(&structures_pool);
    }
  }
  TEST("restriction is the filtered map, without allocation", ok);
}

static void structures_test_pmap_rollback(void) {
  structures_reset();
  structures_version_t *v = &structures_versions[0];
  for (unsigned i = 0; i < 200; i++)
    structures_update(v);
  structures_version_t kept = *v;
  structures_pool.reuse = false;
  uint32_t mark = structures_pool.count;
  for (unsigned i = 0; i < 300; i++)
    structures_update(v);
  shell_pmap_rollback(&structures_pool, mark);
  structures_pool.reuse = true;
  TEST("rollback releases exactly the suffix", structures_pool.count == mark);
  TEST("roots published before rollback survive", structures_matches(&kept));
  /* The intern table no longer knows the released nodes, so rebuilding a
   * released version recreates it and canonicity still holds. */
  *v = kept;
  bool ok = true;
  for (unsigned i = 0; i < 300 && ok; i++)
    ok = structures_update(v) && structures_matches(v);
  TEST("updates after rollback stay canonical", ok && structures_canonical(v));
}

static void structures_test_pmap_capacity_failure(void) {
  enum { SMALL = 300 };
  static shell_pmap_node_t few[SMALL];
  static uint16_t few_table[1024];
  static uint8_t few_marks[SMALL];
  shell_pmap_init(&structures_pool, few, few_table, few_marks, SMALL, 1024);
  memset(structures_versions, 0, sizeof(structures_versions));
  structures_version_t *v = &structures_versions[0];
  structures_version_t last = *v;
  bool failed_once = false, intact = true;
  for (unsigned i = 0; i < 2000 && !failed_once; i++) {
    uint64_t key = structures_random_key();
    uint32_t root = v->root;
    if (!shell_pmap_set(&structures_pool, &root, key, 1,
                        structures_summary_of(key, 1))) {
      failed_once = true;
      intact = root == v->root && structures_matches(&last);
    } else {
      structures_model_set(v, key, 1);
      v->root = root;
      last = *v;
    }
  }
  TEST("a full pool fails the update", failed_once);
  TEST("a failed update leaves published roots valid", intact);
}

/* Cost: an update touches at most W + 2 levels, and a diff of maps sharing
 * structure costs in proportion to the differing keys, not their size. */
static void structures_test_pmap_cost_bounds(void) {
  structures_reset();
  structures_version_t *big = &structures_versions[0];
  for (uint64_t i = 0; i < 4096 && big->count < structures_MODEL; i++) {
    uint64_t key = (i * UINT64_C(0x9e3779b97f4a7c15)) >> 20;
    structures_model_set(big, key, 1);
    shell_pmap_set(&structures_pool, &big->root, key, 1,
                   structures_summary_of(key, 1));
  }
  size_t worst_update = 0, worst_diff = 0;
  for (unsigned trial = 0; trial < 200; trial++) {
    structures_version_t changed = *big;
    unsigned changes = 1 + (unsigned)(structures_next() % 4);
    for (unsigned c = 0; c < changes; c++) {
      uint64_t key = changed.entries[structures_next() % changed.count].key;
      structures_model_set(&changed, key, 2 + c);
      work = 0;
      shell_pmap_set(&structures_pool, &changed.root, key, 2 + c,
                     structures_summary_of(key, 2 + c));
      if (work > worst_update)
        worst_update = work;
    }
    work = 0;
    structures_diff_t d = {big, &changed, 0, 0, 0, true};
    shell_pmap_diff(&structures_pool, big->root, changed.root,
                    structures_check_difference, &d);
    size_t per_key = work / (d.reported ? d.reported : 1);
    if (per_key > worst_diff)
      worst_diff = per_key;
  }
  TEST("an update visits at most W + 2 levels", worst_update <= 66);
  TEST("a diff costs at most 2(W + 1) steps per differing key",
       worst_diff <= 130);
}

/* ---- Union ----------------------------------------------------------- */

enum { structures_MEMO_SIZE = 1u << 16, structures_UMODEL = 1024 };
static shell_pmap_memo_entry_t structures_memo[structures_MEMO_SIZE];
static uint8_t
    structures_memo_blocks[structures_MEMO_SIZE / SHELL_PMAP_MEMO_BLOCK];

typedef struct {
  uint64_t key;
  uint32_t value;
} structures_uentry_t;

typedef struct {
  structures_uentry_t entries[structures_UMODEL];
  uint32_t count, root;
} structures_umap_t;

static void structures_reset_union(void) {
  structures_reset();
  shell_pmap_attach_memo(&structures_pool, structures_memo,
                         structures_MEMO_SIZE, structures_memo_blocks);
  fresh = hits = 0;
}

static void structures_uset(structures_umap_t *m, uint64_t key,
                            uint32_t value) {
  uint32_t i = 0;
  while (i < m->count && m->entries[i].key < key)
    i++;
  if (i < m->count && m->entries[i].key == key) {
    m->entries[i].value = value;
  } else {
    memmove(&m->entries[i + 1], &m->entries[i],
            (m->count - i) * sizeof(structures_uentry_t));
    m->entries[i] = (structures_uentry_t){key, value};
    m->count++;
  }
  shell_pmap_set(&structures_pool, &m->root, key, value, 0);
}

static structures_umap_t structures_random_umap(uint32_t limit, bool high) {
  structures_umap_t m = {0};
  uint32_t n = (uint32_t)(structures_next() % (limit + 1));
  while (n--) {
    uint64_t key = structures_random_key();
    key = high ? key | (UINT64_C(1) << 63) : key & ~(UINT64_C(1) << 63);
    structures_uset(&m, key, 1 + (uint32_t)(structures_next() % 6));
  }
  return m;
}

static uint32_t structures_fn_or(void *context, uint64_t key, uint32_t l,
                                 uint32_t r) {
  (void)context, (void)key;
  return l | r;
}

/* An absent key reads as 1, so a one-sided key joins with that default. */
static uint32_t structures_fn_default(void *context, uint64_t key, uint32_t l,
                                      uint32_t r) {
  (void)context, (void)key;
  return (l ? l : 1) | (r ? r : 1);
}

static uint32_t structures_unite(uint32_t a, uint32_t b, bool neutral,
                                 bool *ok) {
  /* The two rules share the memo under their own tags. */
  uint32_t out = 0;
  *ok = *ok &&
        shell_pmap_union(&structures_pool, a, b,
                         neutral ? structures_fn_or : structures_fn_default,
                         NULL, &out, neutral, neutral ? 0 : 1);
  return out;
}

typedef struct {
  structures_uentry_t entries[structures_UMODEL * 2];
  uint32_t count;
} structures_usnap_t;

static bool structures_collect(void *context, uint64_t key, uint32_t value,
                               uint8_t summary) {
  (void)summary;
  structures_usnap_t *snap = context;
  snap->entries[snap->count++] = (structures_uentry_t){key, value};
  return true;
}

static bool structures_umap_is(uint32_t root,
                               const structures_usnap_t *expected) {
  structures_usnap_t snap = {.count = 0};
  shell_pmap_each(&structures_pool, root, structures_collect, &snap);
  if (snap.count != expected->count)
    return false;
  for (uint32_t i = 0; i < snap.count; i++)
    if (snap.entries[i].key != expected->entries[i].key ||
        snap.entries[i].value != expected->entries[i].value)
      return false;
  return true;
}

static structures_usnap_t structures_model_union(const structures_umap_t *a,
                                                 const structures_umap_t *b,
                                                 bool neutral) {
  structures_usnap_t out = {.count = 0};
  uint32_t i = 0, j = 0;
  while (i < a->count || j < b->count) {
    uint64_t key;
    uint32_t l = 0, r = 0;
    if (j >= b->count ||
        (i < a->count && a->entries[i].key < b->entries[j].key)) {
      key = a->entries[i].key, l = a->entries[i++].value;
    } else if (i >= a->count || b->entries[j].key < a->entries[i].key) {
      key = b->entries[j].key, r = b->entries[j++].value;
    } else {
      key = a->entries[i].key, l = a->entries[i++].value,
      r = b->entries[j++].value;
    }
    out.entries[out.count++] = (structures_uentry_t){
        key, neutral ? (l | r) : ((l ? l : 1) | (r ? r : 1))};
  }
  return out;
}

static void structures_test_pmap_union_matches_model(void) {
  structures_reset_union();
  bool ok = true;
  for (unsigned round = 0; round < 400 && ok; round++) {
    structures_reset_union();
    structures_umap_t a = structures_random_umap(100, false),
                      b = structures_random_umap(100, false);
    for (unsigned neutral = 0; neutral < 2; neutral++) {
      bool built = true;
      uint32_t r = structures_unite(a.root, b.root, neutral, &built);
      structures_usnap_t expected = structures_model_union(&a, &b, neutral);
      ok = ok && built && structures_umap_is(r, &expected);
    }
  }
  TEST("union agrees with a reference model, both absent rules", ok);
}

static void structures_test_pmap_union_laws(void) {
  structures_reset_union();
  bool ok = true, absorbed = true;
  for (unsigned round = 0; round < 300 && ok; round++) {
    structures_reset_union();
    structures_umap_t a = structures_random_umap(60, false),
                      b = structures_random_umap(60, false),
                      c = structures_random_umap(60, false);
    for (unsigned neutral = 0; neutral < 2; neutral++) {
      bool built = true;
      uint32_t ab = structures_unite(a.root, b.root, neutral, &built);
      uint32_t ba = structures_unite(b.root, a.root, neutral, &built);
      uint32_t aa = structures_unite(a.root, a.root, neutral, &built);
      uint32_t left = structures_unite(ab, c.root, neutral, &built);
      uint32_t right = structures_unite(
          a.root, structures_unite(b.root, c.root, neutral, &built), neutral,
          &built);
      /* The result already contains each operand: joining it back is free. */
      size_t before = fresh;
      uint32_t again_a = structures_unite(ab, a.root, neutral, &built);
      uint32_t again_b = structures_unite(ab, b.root, neutral, &built);
      absorbed = absorbed && again_a == ab && again_b == ab && fresh == before;
      ok = ok && built && ab == ba && aa == a.root && left == right;
    }
  }
  TEST("union is commutative, idempotent and associative by root id", ok);
  TEST("joining an operand into its union costs no fresh pair", absorbed);
}

/* The same subtrees give the same result whatever surrounds them. */
static void structures_test_pmap_union_context_free(void) {
  structures_reset_union();
  bool ok = true;
  for (unsigned round = 0; round < 300 && ok; round++) {
    structures_reset_union();
    structures_umap_t a = structures_random_umap(60, false),
                      b = structures_random_umap(60, false);
    structures_umap_t x = structures_random_umap(60, true),
                      y = structures_random_umap(60, true);
    structures_umap_t ax = a, by = b;
    for (uint32_t i = 0; i < x.count; i++)
      structures_uset(&ax, x.entries[i].key, x.entries[i].value);
    for (uint32_t i = 0; i < y.count; i++)
      structures_uset(&by, y.entries[i].key, y.entries[i].value);
    for (unsigned neutral = 0; neutral < 2; neutral++) {
      bool built = true;
      uint32_t alone = structures_unite(a.root, b.root, neutral, &built);
      uint32_t embedded = structures_unite(ax.root, by.root, neutral, &built);
      uint32_t low = shell_pmap_restrict(&structures_pool, embedded, 0, 62);
      ok = ok && built && low == alone;
    }
  }
  TEST("a union's low half does not depend on what the high half holds", ok);
}

/* D nested joins of one big result with unmodified entries that differ by a
 * key each: a join that re-examines the differing keys costs D·k; absorption
 * makes it O(k + D·W). */
static size_t structures_diamond_fresh(unsigned k, unsigned d) {
  structures_reset_union();
  structures_umap_t base = {0};
  for (uint64_t i = 0; i < 64; i++)
    structures_uset(&base, (i * UINT64_C(0x9e3779b97f4a7c15)) >> 20, 1);
  structures_umap_t then_exit = base;
  for (uint64_t i = 0; i < k; i++)
    structures_uset(&then_exit,
                    ((i + 1000) * UINT64_C(0x9e3779b97f4a7c15)) >> 20, 2);
  bool ok = true;
  uint32_t result = then_exit.root;
  for (uint64_t j = 0; j < d; j++) {
    structures_umap_t entry = base;
    structures_uset(&entry, ((j + 5000) * UINT64_C(0x9e3779b97f4a7c15)) >> 20,
                    1);
    result = structures_unite(result, entry.root, true, &ok);
  }
  return ok ? fresh : SIZE_MAX;
}

/* D nested joins of one big result with unmodified entries that differ by a
 * key each: a join that re-examines the differing keys costs D·k; absorption
 * makes it O(k + D·W). Doubling k and D must at most double the work (plus a
 * quarter), and the total stays under C·(k + D). */
static void structures_test_pmap_union_nested_diamonds(void) {
  size_t previous = 0;
  bool doubling = true, bounded = true;
  for (unsigned n = 32; n <= 256; n *= 2) {
    size_t total = structures_diamond_fresh(n, n);
    printf("  nested diamonds: %zu fresh pairs for k=D=%u (naive %u)\n", total,
           n, n * n);
    doubling = doubling && (!previous || total * 4 <= previous * 2 * 5);
    bounded = bounded && total <= 11 * 2 * n;
    previous = total;
  }
  TEST("doubling nested joins at most doubles the fresh pairs", doubling);
  TEST("nested joins cost O(k + D) fresh pairs, not D·k", bounded);
}

static void structures_test_pmap_union_collection(void) {
  structures_reset_union();
  bool ok = true;
  for (unsigned round = 0; round < 100 && ok; round++) {
    structures_reset_union();
    structures_umap_t a = structures_random_umap(80, false),
                      b = structures_random_umap(80, false);
    bool built = true;
    uint32_t first = structures_unite(a.root, b.root, true, &built);
    shell_pmap_mark_begin(&structures_pool);
    shell_pmap_mark(&structures_pool, a.root, NULL, NULL);
    shell_pmap_mark(&structures_pool, b.root, NULL, NULL);
    shell_pmap_mark(&structures_pool, first, NULL, NULL);
    shell_pmap_sweep(&structures_pool);
    ok = ok && built && structures_pool.memo_used == 0;
    uint32_t second = structures_unite(a.root, b.root, true, &built);
    structures_usnap_t expected = structures_model_union(&a, &b, true);
    ok =
        ok && built && second == first && structures_umap_is(second, &expected);
  }
  TEST("a collection clears the memo and unions stay correct", ok);
}

/* The memo only reuses work: a table far too small for the unions run through
 * it is cleared as it fills, and every union is still correct. */
/* The bits a fold returns for key pairs that differ. */
static uint32_t structures_fn_bits(void *context, uint64_t key, uint32_t l,
                                   uint32_t r) {
  (void)context;
  return 1u << ((l ^ r ^ (uint32_t)key) & 7u);
}

static uint32_t structures_model_bits(const structures_umap_t *a,
                                      const structures_umap_t *b) {
  uint32_t bits = 0, i = 0, j = 0;
  while (i < a->count || j < b->count) {
    uint64_t key;
    uint32_t l = 0, r = 0;
    if (j >= b->count ||
        (i < a->count && a->entries[i].key < b->entries[j].key)) {
      key = a->entries[i].key, l = a->entries[i++].value;
    } else if (i >= a->count || b->entries[j].key < a->entries[i].key) {
      key = b->entries[j].key, r = b->entries[j++].value;
    } else {
      key = a->entries[i].key, l = a->entries[i++].value,
      r = b->entries[j++].value;
    }
    if (l != r)
      bits |= structures_fn_bits(NULL, key, l, r);
  }
  return bits;
}

static void structures_test_pmap_fold_matches_model(void) {
  bool ok = true;
  uint32_t nodes_before = 0;
  for (unsigned round = 0; round < 400 && ok; round++) {
    structures_reset_union();
    structures_umap_t a = structures_random_umap(100, false),
                      b = structures_random_umap(100, false);
    nodes_before = structures_pool.count;
    uint32_t bits = 0, again = 0, plain = 0;
    ok = ok && shell_pmap_fold(&structures_pool, a.root, b.root,
                               structures_fn_bits, NULL, &bits, true, 5);
    ok = ok && bits == structures_model_bits(&a, &b) &&
         structures_pool.count == nodes_before;
    /* Again, answered from the memo. */
    ok = ok &&
         shell_pmap_fold(&structures_pool, a.root, b.root, structures_fn_bits,
                         NULL, &again, true, 5) &&
         again == bits;
    /* Without the memo the answer is the same. */
    ok = ok &&
         shell_pmap_fold(&structures_pool, a.root, b.root, structures_fn_bits,
                         NULL, &plain, false, 5) &&
         plain == bits;
  }
  TEST("a fold agrees with a reference model and makes no node", ok);
}

static void structures_test_pmap_union_memo_full(void) {
  static shell_pmap_memo_entry_t tiny[8];
  static uint8_t tiny_blocks[1];
  bool ok = true, refused = false, answered = false;
  for (unsigned round = 0; round < 200 && ok; round++) {
    structures_reset();
    shell_pmap_attach_memo(&structures_pool, tiny, 8, tiny_blocks);
    structures_umap_t a = structures_random_umap(100, false),
                      b = structures_random_umap(100, false);
    structures_usnap_t before_a = {.count = a.count},
                       before_b = {.count = b.count};
    memcpy(before_a.entries, a.entries, a.count * sizeof(structures_uentry_t));
    memcpy(before_b.entries, b.entries, b.count * sizeof(structures_uentry_t));
    for (unsigned neutral = 0; neutral < 2; neutral++) {
      uint32_t out = 0;
      size_t fresh_before = fresh;
      bool built =
          shell_pmap_union(&structures_pool, a.root, b.root,
                           neutral ? structures_fn_or : structures_fn_default,
                           NULL, &out, neutral, neutral ? 0 : 1);
      structures_usnap_t expected = structures_model_union(&a, &b, neutral);
      /* A full memo fails the union, as a full pool does; an answer is right,
       * and the pairs computed never exceed what the memo holds plus the
       * ancestors of the pair that found it full. */
      ok = ok && (!built || structures_umap_is(out, &expected)) &&
           fresh - fresh_before <= structures_pool.memo_size / 2 + 64;
      refused = refused || !built;
      answered = answered || built;
    }
    /* The operands stay valid after a failure. */
    ok = ok && structures_umap_is(a.root, &before_a) &&
         structures_umap_is(b.root, &before_b);
    /* A fold the memo cannot hold fails too. */
    uint32_t bits;
    if (shell_pmap_fold(&structures_pool, a.root, b.root, structures_fn_bits,
                        NULL, &bits, true, 5))
      ok = ok && bits == structures_model_bits(&a, &b);
    ok = ok &&
         shell_pmap_fold(&structures_pool, a.root, b.root, structures_fn_bits,
                         NULL, &bits, false, 5) &&
         bits == structures_model_bits(&a, &b);
  }
  TEST("a full memo fails a union and never changes an answer",
       ok && refused && answered);
}

static void structures_test_pmap_diff_within(void) {
  structures_reset_union();
  bool ok = true;
  for (unsigned round = 0; round < 300 && ok; round++) {
    structures_reset_union();
    structures_umap_t a = structures_random_umap(60, false);
    structures_umap_t b = a;
    unsigned edits = (unsigned)(structures_next() % 12);
    for (unsigned i = 0; i < edits; i++)
      structures_uset(&b, structures_random_key() & ~(UINT64_C(1) << 63),
                      1 + (uint32_t)(structures_next() % 6));
    uint32_t total = 0;
    structures_diff_t d = {0};
    (void)d;
    structures_usnap_t ua = {.count = a.count}, ub = {.count = b.count};
    memcpy(ua.entries, a.entries, a.count * sizeof(structures_uentry_t));
    memcpy(ub.entries, b.entries, b.count * sizeof(structures_uentry_t));
    for (uint32_t i = 0, j = 0; i < a.count || j < b.count;) {
      if (j >= b.count ||
          (i < a.count && a.entries[i].key < b.entries[j].key)) {
        total++, i++;
      } else if (i >= a.count || b.entries[j].key < a.entries[i].key) {
        total++, j++;
      } else {
        total += a.entries[i].value != b.entries[j].value, i++, j++;
      }
    }
    for (uint32_t limit = 0; limit < 14; limit++) {
      uint32_t seen = 0;
      bool within = shell_pmap_diff_within(&structures_pool, a.root, b.root,
                                           limit, &seen);
      ok = ok && within == (total <= limit) &&
           seen == (total <= limit ? total : limit + 1);
    }
  }
  TEST("a bounded diff counts differing keys and stops past the limit", ok);
}

static void structures_run_pmap(void) {
  structures_state = RNG_SEED;
  printf("persistent map\n");
  structures_test_pmap_matches_reference();
  structures_test_pmap_restrict();
  structures_test_pmap_rollback();
  structures_test_pmap_capacity_failure();
  structures_test_pmap_cost_bounds();
  structures_test_pmap_union_matches_model();
  structures_test_pmap_union_laws();
  structures_test_pmap_union_context_free();
  structures_test_pmap_union_nested_diamonds();
  structures_test_pmap_union_collection();
  structures_test_pmap_union_memo_full();
  structures_test_pmap_fold_matches_model();
  structures_test_pmap_diff_within();
}

/* --- avl --- */
/* The index is checked against a sorted reference under random insertions
 * and erasures, and for its failure-atomic capacity contract. */

static SHELL_NONNULL(1, 3) int compare_values(const void *context,
                                              uint32_t member,
                                              const void *key) {
  const uint32_t *values = context;
  uint32_t candidate = *(const uint32_t *)key;
  return values[member] < candidate ? -1 : values[member] > candidate;
}

/* A full index still finds existing keys, and a failed insertion leaves the
 * root, links and heights unchanged. */
static void structures_test_avl_capacity_is_failure_atomic(void) {
  shell_avl_node_t structures_nodes[3] = {{0}};
  const uint32_t values[] = {20, 10, 30};
  uint32_t root = 0;
  bool valid = true;
  for (uint32_t candidate = 1; candidate <= 3; candidate++) {
    uint32_t match = 0;
    root =
        shell_avl_insert(structures_nodes, root, candidate, 3, compare_values,
                         values, &values[candidate - 1], &match);
    valid &= match == candidate;
  }
  shell_avl_node_t expected[3];
  memcpy(expected, structures_nodes, sizeof(expected));
  uint32_t expected_root = root;
  const uint32_t missing[] = {5, 40};
  for (size_t i = 0; i < sizeof(missing) / sizeof(missing[0]); i++) {
    uint32_t match = 0;
    uint32_t unchanged =
        shell_avl_insert(structures_nodes, root, 4, 3, compare_values, values,
                         &missing[i], &match);
    valid &= unchanged == expected_root && match == 0 &&
             memcmp(structures_nodes, expected, sizeof(structures_nodes)) == 0;
  }
  for (uint32_t member = 0; member < 3; member++) {
    uint32_t match = 0;
    uint32_t unchanged =
        shell_avl_insert(structures_nodes, root, 4, 3, compare_values, values,
                         &values[member], &match);
    valid &= unchanged == expected_root && match == member + 1 &&
             memcmp(structures_nodes, expected, sizeof(structures_nodes)) == 0;
  }
  TEST("capacity is failure-atomic", valid);
}

enum { structures_RECORDS = 512 };

/* In-order walk into out; returns false on an order or balance violation. */
static bool structures_check_tree(const shell_avl_node_t *structures_nodes,
                                  const uint32_t *values, uint32_t root,
                                  uint32_t *out, uint32_t *count,
                                  unsigned *height) {
  if (!root) {
    *height = 0;
    return true;
  }
  const shell_avl_node_t *node = &structures_nodes[root - 1];
  unsigned left = 0, right = 0;
  if (!structures_check_tree(structures_nodes, values, node->left, out, count,
                             &left))
    return false;
  if (*count && values[out[*count - 1]] >= values[root - 1])
    return false;
  out[(*count)++] = root - 1;
  if (!structures_check_tree(structures_nodes, values, node->right, out, count,
                             &right))
    return false;
  *height = 1 + (left > right ? left : right);
  int balance = (int)left - (int)right;
  return node->height == *height && balance >= -1 && balance <= 1;
}

static void structures_test_avl_matches_reference(void) {
  static shell_avl_node_t structures_nodes[structures_RECORDS];
  static uint32_t values[structures_RECORDS];
  static bool present[1024];
  static uint32_t order[structures_RECORDS];
  bool valid = true;
  for (unsigned round = 0; valid && round < 64; round++) {
    memset(structures_nodes, 0, sizeof(structures_nodes));
    memset(present, 0, sizeof(present));
    uint32_t root = 0, used = 0;
    for (unsigned step = 0; valid && step < 4 * structures_RECORDS; step++) {
      uint32_t key = (uint32_t)(structures_next() % 1024);
      if (structures_next() % 3 == 0 && present[key]) {
        root = shell_avl_erase(structures_nodes, root, compare_values, values,
                               &key);
        present[key] = false;
      } else {
        uint32_t match = 0;
        if (used < structures_RECORDS)
          values[used] = key;
        root = shell_avl_insert(structures_nodes, root, used + 1,
                                structures_RECORDS, compare_values, values,
                                &key, &match);
        if (present[key])
          valid &= match && values[match - 1] == key;
        else if (used < structures_RECORDS) {
          valid &= match == used + 1;
          present[key] = true;
          used++;
        } else
          valid &= match == 0;
      }
      uint32_t count = 0;
      unsigned height = 0;
      valid &= structures_check_tree(structures_nodes, values, root, order,
                                     &count, &height);
      uint32_t expected = 0;
      for (uint32_t v = 0; v < 1024; v++)
        expected += present[v];
      valid &= count == expected;
      for (uint32_t i = 0; valid && i < count; i++)
        valid &= present[values[order[i]]];
    }
  }
  TEST("insert and erase match a sorted reference", valid);
}

static void structures_run_avl(void) {
  structures_state = RNG_SEED;
  printf("avl index\n");
  structures_test_avl_capacity_is_failure_atomic();
  structures_test_avl_matches_reference();
}

/* --- occupancy --- */
/* Each transfer function is checked against a direct reading of Bash's
 * lowest-free search over independent per-descriptor possibilities, for every
 * minimum and both ranks, on random valid occupancies. */

/* Sparse and dense masks both matter: a few certainly free descriptors decide
 * where the search stops. */
static shell_fd_occupancy_t structures_random_occupancy(void) {
  uint64_t free = structures_next();
  for (unsigned i = structures_next() % 4; i; i--)
    free &= structures_next();
  uint64_t occupied = structures_next();
  for (unsigned i = structures_next() % 4; i; i--)
    occupied |= structures_next();
  return (shell_fd_occupancy_t){free, occupied | ~free};
}

static int may_free(const shell_fd_occupancy_t *o, uint32_t fd) {
  return (o->may_free >> fd) & 1;
}

static int structures_certainly_free(const shell_fd_occupancy_t *o,
                                     uint32_t fd) {
  return may_free(o, fd) && !((o->may_occupied >> fd) & 1);
}

/* Some path has exactly rank - 1 free descriptors in minimum..fd-1 and fd
 * free: per descriptor, the free count ranges from the certainly free ones to
 * the possibly free ones. */
static shell_fd_allocation_t structures_reference(const shell_fd_occupancy_t *o,
                                                  uint32_t minimum,
                                                  unsigned rank) {
  shell_fd_allocation_t result = {0, false};
  unsigned certain = 0, possible = 0;
  for (uint32_t fd = minimum; fd < 64; fd++) {
    if (may_free(o, fd) && certain <= rank - 1 && possible >= rank - 1)
      result.candidates |= UINT64_C(1) << fd;
    certain += (unsigned)structures_certainly_free(o, fd);
    possible += (unsigned)may_free(o, fd);
  }
  result.tail = certain < rank;
  return result;
}

static void structures_test_occupancy_allocation_matches_reference(void) {
  int ok = 1;
  for (unsigned round = 0; round < 20000 && ok; round++) {
    shell_fd_occupancy_t o = structures_random_occupancy();
    for (uint32_t minimum = 0; minimum <= 64 && ok; minimum++)
      for (unsigned rank = 1; rank <= 2 && ok; rank++) {
        shell_fd_allocation_t a = shell_fd_allocate(&o, minimum, rank);
        shell_fd_allocation_t r = structures_reference(&o, minimum, rank);
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

static void structures_test_occupancy_known_tables(void) {
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
static void structures_test_occupancy_take_and_release(void) {
  int ok = 1;
  for (unsigned round = 0; round < 20000 && ok; round++) {
    shell_fd_occupancy_t o = structures_random_occupancy();
    uint32_t minimum = (uint32_t)(structures_next() % 65);
    unsigned rank = 1 + (unsigned)(structures_next() & 1);
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
static uint32_t structures_concrete_dupfd(uint64_t free, uint32_t minimum,
                                          unsigned rank) {
  for (uint32_t fd = minimum; fd < 64; fd++)
    if (((free >> fd) & 1) && !--rank)
      return fd;
  return 64;
}

static uint32_t structures_concrete_pipe_end(uint64_t free, unsigned rank) {
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
static void structures_test_occupancy_against_concrete_tables(void) {
  int ok = 1;
  for (unsigned round = 0; round < 3000 && ok; round++) {
    uint64_t unknown = 0;
    for (unsigned i = structures_next() % 11; i; i--)
      unknown |= UINT64_C(1) << (structures_next() % 64);
    if (structures_next() & 1)
      unknown &= UINT64_C(0xffff);
    uint64_t fixed_free =
        structures_next() & structures_next() & structures_next() & ~unknown;
    shell_fd_occupancy_t o = {fixed_free | unknown, ~fixed_free};
    uint32_t positions[64], count = 0;
    for (uint32_t fd = 0; fd < 64; fd++)
      if ((unknown >> fd) & 1)
        positions[count++] = fd;
    uint32_t minimum = (uint32_t)(structures_next() % 20);
    for (unsigned rank = 1; rank <= 2 && ok; rank++) {
      shell_fd_allocation_t dup = {0, false}, pipe = {0, false};
      for (uint64_t world = 0; world < (UINT64_C(1) << count); world++) {
        uint64_t free = fixed_free;
        for (uint32_t i = 0; i < count; i++)
          if ((world >> i) & 1)
            free |= UINT64_C(1) << positions[i];
        uint32_t d = structures_concrete_dupfd(free, minimum, rank);
        uint32_t p = structures_concrete_pipe_end(free, rank);
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
static void structures_test_occupancy_select_is_the_exact_hull(void) {
  int ok = 1;
  for (unsigned round = 0; round < 3000 && ok; round++) {
    uint64_t unknown = 0;
    for (unsigned i = structures_next() % 11; i; i--)
      unknown |= UINT64_C(1) << (structures_next() % 24);
    uint64_t fixed_free = structures_next() & structures_next() & ~unknown;
    shell_fd_occupancy_t o = {fixed_free | unknown, ~fixed_free};
    uint32_t positions[64], count = 0;
    for (uint32_t fd = 0; fd < 64; fd++)
      if ((unknown >> fd) & 1)
        positions[count++] = fd;
    uint32_t begin = 10 + (uint32_t)(structures_next() % 6);
    uint32_t fd = begin + (uint32_t)(structures_next() % 10);
    unsigned rank = 1 + (unsigned)(structures_next() & 1);
    int low_mode = (int)(structures_next() % 3) - 1;
    shell_fd_occupancy_t hull = {0, 0};
    bool any = false;
    for (uint64_t world = 0; world < (UINT64_C(1) << count); world++) {
      uint64_t free = fixed_free;
      for (uint32_t i = 0; i < count; i++)
        if ((world >> i) & 1)
          free |= UINT64_C(1) << positions[i];
      bool low_free = (free & 0x3ff) != 0;
      if (structures_concrete_dupfd(free, begin, rank) != fd ||
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
static void structures_test_occupancy_pipe_select_is_the_exact_hull(void) {
  int ok = 1;
  for (unsigned round = 0; round < 3000 && ok; round++) {
    uint64_t unknown = 0;
    for (unsigned i = structures_next() % 11; i; i--)
      unknown |= UINT64_C(1) << (structures_next() % 64);
    if (structures_next() & 1)
      unknown &= UINT64_C(0xffff) | (UINT64_C(0xf) << 60);
    uint64_t fixed_free =
        structures_next() & structures_next() & structures_next() & ~unknown;
    shell_fd_occupancy_t o = {fixed_free | unknown, ~fixed_free};
    uint32_t positions[64], count = 0;
    for (uint32_t fd = 0; fd < 64; fd++)
      if ((unknown >> fd) & 1)
        positions[count++] = fd;
    unsigned rank = 1 + (unsigned)(structures_next() & 1);
    for (uint32_t fd = 0; fd < 64 && ok; fd++) {
      shell_fd_occupancy_t hull = {0, 0};
      bool any = false;
      for (uint64_t world = 0; world < (UINT64_C(1) << count); world++) {
        uint64_t free = fixed_free;
        for (uint32_t i = 0; i < count; i++)
          if ((world >> i) & 1)
            free |= UINT64_C(1) << positions[i];
        if (structures_concrete_pipe_end(free, rank) != fd)
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

static bool structures_table_allowed(const shell_fd_occupancy_t *o,
                                     uint64_t free) {
  return !(free & ~o->may_free) && !(~free & ~o->may_occupied);
}

/* Splitting by the low interval keeps exactly the hull of each case's
 * complete tables, and normalizing a partition files every table of either
 * part under the case it belongs to. */
static void structures_test_occupancy_partition_cases(void) {
  int ok = 1;
  for (unsigned round = 0; round < 3000 && ok; round++) {
    uint64_t unknown = 0;
    for (unsigned i = structures_next() % 11; i; i--)
      unknown |= UINT64_C(1) << (structures_next() % 16);
    uint64_t fixed_free =
        structures_next() & structures_next() & structures_next() & ~unknown;
    if (structures_next() & 1)
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
      parts.part[part] = structures_random_occupancy();
    shell_fd_partition_t refined = parts, normal = parts;
    shell_fd_partition_refine(&refined);
    shell_fd_partition_normalize(&normal);
    for (unsigned sample = 0; sample < 400 && ok; sample++) {
      unsigned part = sample % SHELL_FD_PARTS;
      const shell_fd_occupancy_t *from = &parts.part[part];
      uint64_t free = (from->may_free & ~from->may_occupied) |
                      (from->may_free & from->may_occupied & structures_next());
      unsigned full = (free & SHELL_FD_LOW_INTERVAL) == 0;
      if (full == shell_fd_part_full(part) &&
          !structures_table_allowed(&refined.part[part], free)) {
        printf("    refine lost a table of part %u\n", part);
        ok = 0;
      }
      if (!structures_table_allowed(&normal.part[(part & ~1u) | full], free)) {
        printf("    normalize lost a table of part %u\n", part);
        ok = 0;
      }
    }
  }
  TEST("low-interval cases are exact hulls and keep every table", ok);
}

static void structures_run_occupancy(void) {
  structures_state = RNG_SEED;
  printf("fd occupancy\n");
  structures_test_occupancy_allocation_matches_reference();
  structures_test_occupancy_against_concrete_tables();
  structures_test_occupancy_select_is_the_exact_hull();
  structures_test_occupancy_pipe_select_is_the_exact_hull();
  structures_test_occupancy_known_tables();
  structures_test_occupancy_take_and_release();
  structures_test_occupancy_partition_cases();
}

/* --- netstring --- */
static void structures_test_netstring_iteration(void) {
  static const unsigned char input[] = "3:cat,0:,9:two words,";
  shell_netstring_iter_t iter;
  shell_netstring_view_t view;
  TEST("initialize sequence",
       shell_netstring_iter_init(&iter, input, sizeof(input) - 1) ==
           SHELL_NETSTRING_OK);
  TEST("first record",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK &&
           view.record_length == 6 && view.payload_length == 3 &&
           memcmp(view.payload, "cat", 3) == 0);
  TEST("empty payload",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK &&
           view.record_length == 3 && view.payload_length == 0);
  TEST("spaced payload",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK &&
           view.payload_length == 9 &&
           memcmp(view.payload, "two words", 9) == 0);
  TEST("iterator finishes",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_DONE);
}

static void structures_test_netstring_binary_and_nested_payloads(void) {
  static const unsigned char binary[] = {'3', ':', 'a', '\0', 'b', ',',
                                         '3', ':', '0', ':',  ',', ','};
  shell_netstring_iter_t iter;
  shell_netstring_view_t view;
  TEST("binary input initializes",
       shell_netstring_iter_init(&iter, binary, sizeof(binary)) ==
           SHELL_NETSTRING_OK);
  TEST("binary payload preserved",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK &&
           view.payload_length == 3 && view.payload[1] == '\0');
  TEST("nested record remains opaque",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK &&
           view.payload_length == 3 && memcmp(view.payload, "0:,", 3) == 0);
  TEST("nested payload can be iterated",
       shell_netstring_validate(view.payload, view.payload_length, NULL) ==
           SHELL_NETSTRING_OK);
}

static void structures_test_netstring_validation_failures(void) {
  static const struct {
    const char *input;
    shell_netstring_status_t expected;
  } cases[] = {
      {"00:,", SHELL_NETSTRING_EFORMAT},
      {"3:ab,", SHELL_NETSTRING_EFORMAT},
      {"3:abc", SHELL_NETSTRING_EFORMAT},
      {"0:", SHELL_NETSTRING_EFORMAT},
      {"3:abc,x", SHELL_NETSTRING_EFORMAT},
      {"x:abc,", SHELL_NETSTRING_EFORMAT},
      {"184467440737095516160:x,", SHELL_NETSTRING_EOVERFLOW},
      {"1:a,3:ab", SHELL_NETSTRING_EFORMAT},
      {"0:,3:ab,", SHELL_NETSTRING_EFORMAT},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    TEST("malformed framing rejected",
         shell_netstring_validate(cases[i].input, strlen(cases[i].input),
                                  NULL) == cases[i].expected);
  }
  size_t count = 99;
  TEST("empty sequence validates",
       shell_netstring_validate(NULL, 0, &count) == SHELL_NETSTRING_OK &&
           count == 0);
  static const struct {
    const char *input;
    size_t records;
  } counted[] = {{"0:,", 1}, {"0:,0:,", 2}, {"0:,1:a,0:,", 3}, {"1:a,", 1}};
  for (size_t i = 0; i < sizeof(counted) / sizeof(counted[0]); i++) {
    count = 99;
    TEST("empty and ordinary records are counted exactly",
         shell_netstring_validate(counted[i].input, strlen(counted[i].input),
                                  &count) == SHELL_NETSTRING_OK &&
             count == counted[i].records);
  }
  TEST("null non-empty input rejected",
       shell_netstring_validate(NULL, 1, NULL) == SHELL_NETSTRING_EINPUT);
}

static void structures_test_netstring_count_and_error_position(void) {
  shell_netstring_buffer_free(NULL);
  static const char input[] = "1:a,2:bc,";
  static const char broken[] = "1:a,01:b,";
  size_t count = 0;
  shell_netstring_iter_t iter;
  shell_netstring_view_t view;
  TEST("count validates complete sequence",
       shell_netstring_validate(input, sizeof(input) - 1, &count) ==
               SHELL_NETSTRING_OK &&
           count == 2);
  TEST("initialize broken sequence",
       shell_netstring_iter_init(&iter, broken, sizeof(broken) - 1) ==
           SHELL_NETSTRING_OK);
  TEST("prefix before malformed record succeeds",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_OK);
  size_t invalid_offset = iter.offset;
  TEST("error preserves invalid record position",
       shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_EFORMAT &&
           iter.offset == invalid_offset);
}

static void structures_test_netstring_encoding(void) {
  unsigned char record[16];
  size_t length = 0, written = 0;
  TEST("encoded length",
       shell_netstring_encoded_length(3, &length) == SHELL_NETSTRING_OK &&
           length == 6);
  TEST("encode record", shell_netstring_write(record, sizeof(record), "cat", 3,
                                              &written) == SHELL_NETSTRING_OK &&
                            written == 6 && memcmp(record, "3:cat,", 6) == 0);
  TEST("encode empty payload",
       shell_netstring_write(record, 3, NULL, 0, &written) ==
               SHELL_NETSTRING_OK &&
           written == 3 && memcmp(record, "0:,", 3) == 0);
  TEST("short output rejected",
       shell_netstring_write(record, 5, "cat", 3, NULL) ==
           SHELL_NETSTRING_EOVERFLOW);
}

/* The output buffer must hold the whole record: an exact fit succeeds at every
 * digit-count boundary, one byte less fails, and a failure writes nothing. */
static void structures_test_netstring_encoding_capacity_boundaries(void) {
  static const size_t lengths[] = {0, 1, 9, 10, 99, 100, 1000};
  unsigned char payload[1000];
  memset(payload, 'x', sizeof(payload));
  bool valid = true;
  for (size_t i = 0; valid && i < sizeof(lengths) / sizeof(lengths[0]); i++) {
    size_t needed = 0, written = 99;
    unsigned char record[1100];
    valid = shell_netstring_encoded_length(lengths[i], &needed) ==
                SHELL_NETSTRING_OK &&
            needed <= sizeof(record);
    memset(record, 0xa5, sizeof(record));
    valid = valid &&
            shell_netstring_write(record, needed - 1, payload, lengths[i],
                                  &written) == SHELL_NETSTRING_EOVERFLOW &&
            written == 0 && record[0] == 0xa5 && record[needed - 2] == 0xa5;
    valid =
        valid &&
        shell_netstring_write(record, needed, payload, lengths[i], &written) ==
            SHELL_NETSTRING_OK &&
        written == needed && record[needed - 1] == ',' &&
        shell_netstring_validate(record, needed, NULL) == SHELL_NETSTRING_OK;
  }
  TEST("record capacity is exact at every digit-count boundary", valid);
}

static void structures_test_netstring_malformed_record(void) {
  shell_netstring_iter_t iter;
  shell_netstring_view_t view;

  TEST("iterator rejects a length prefix without a colon",
       shell_netstring_iter_init(&iter, "1x", 2) == SHELL_NETSTRING_OK &&
           shell_netstring_iter_next(&iter, &view) == SHELL_NETSTRING_EFORMAT);
}

static void structures_test_netstring_stream_reader(void) {
  FILE *stream = tmpfile();
  unsigned char *record = NULL;
  size_t length = 0;
  TEST("open stream", stream != NULL);
  if (!stream)
    return;
  fputs("3:cat,0:,", stream);
  rewind(stream);
  TEST("read first stream record",
       shell_netstring_read_stream(stream, 0, &record, &length) ==
               SHELL_NETSTRING_OK &&
           length == 6 && memcmp(record, "3:cat,", 6) == 0);
  free(record);
  record = NULL;
  TEST("read empty stream record",
       shell_netstring_read_stream(stream, 3, &record, &length) ==
               SHELL_NETSTRING_OK &&
           length == 3 && memcmp(record, "0:,", 3) == 0);
  free(record);
  TEST("stream EOF", shell_netstring_read_stream(stream, 0, &record, &length) ==
                         SHELL_NETSTRING_DONE);
  fclose(stream);
}

static void structures_test_netstring_stream_reader_bounds_prefix_digits(void) {
  FILE *stream = tmpfile();
  unsigned char *record = NULL;
  size_t length = 0;
  TEST("open prefix stream", stream != NULL);
  if (!stream)
    return;
  for (int i = 0; i < 4096; i++)
    fputc('0', stream);
  fputs(":,", stream);
  rewind(stream);
  TEST("stream rejects leading zeros at the second digit",
       shell_netstring_read_stream(stream, 0, &record, &length) ==
               SHELL_NETSTRING_EFORMAT &&
           record == NULL && length == 0 && ftell(stream) == 2);
  fclose(stream);

  stream = tmpfile();
  TEST("open overflow prefix stream", stream != NULL);
  if (!stream)
    return;
  for (int i = 0; i < 4096; i++)
    fputc('9', stream);
  fputs(":,", stream);
  rewind(stream);
  TEST("stream stops reading an overflowing prefix",
       shell_netstring_read_stream(stream, 0, &record, &length) ==
               SHELL_NETSTRING_EOVERFLOW &&
           ftell(stream) < 32);
  fclose(stream);
}

static void structures_test_netstring_stream_reader_allocation_failures(void) {
  FILE *stream = tmpfile();
  unsigned char *record = NULL;
  size_t length = 0;
  TEST("open allocation stream", stream != NULL);
  if (!stream)
    return;
  fputs("3:cat,", stream);

  shellsplit_test_alloc_reset();
  rewind(stream);
  TEST("stream reader allocation probe",
       shell_netstring_read_stream(stream, 0, &record, &length) ==
               SHELL_NETSTRING_OK &&
           record != NULL && length == 6 && shellsplit_test_alloc_count() == 1);
  free(record);

  record = (unsigned char *)(void *)1;
  length = SIZE_MAX;
  shellsplit_test_alloc_fail_at(1);
  rewind(stream);
  TEST("stream reader clears outputs on allocation failure",
       shell_netstring_read_stream(stream, 0, &record, &length) ==
               SHELL_NETSTRING_ENOMEM &&
           record == NULL && length == 0);
  shellsplit_test_alloc_reset();
  fclose(stream);
}

static void
structures_test_netstring_stream_reader_rejects_unallocatable_record(void) {
  FILE *stream = tmpfile();
  unsigned char *record = (unsigned char *)(void *)1;
  size_t length = SIZE_MAX;
  TEST("open overflow stream", stream != NULL);
  if (!stream)
    return;

  size_t payload_length = SIZE_MAX;
  size_t total = 0;
  while (shell_netstring_encoded_length(payload_length, &total) !=
             SHELL_NETSTRING_OK ||
         total != SIZE_MAX)
    payload_length--;
  fprintf(stream, "%zu:", payload_length);
  rewind(stream);
  TEST("stream reader rejects record without terminator space",
       shell_netstring_read_stream(stream, 0, &record, &length) ==
               SHELL_NETSTRING_EOVERFLOW &&
           record == NULL && length == 0);
  fclose(stream);
}

static void structures_test_netstring_stream_reader_format_failures(void) {
  static const struct {
    const char *input;
    shell_netstring_status_t expected;
  } cases[] = {
      {"x", SHELL_NETSTRING_EFORMAT},
      {"01:,", SHELL_NETSTRING_EFORMAT},
      {"999999999999999999999999999999:", SHELL_NETSTRING_EOVERFLOW},
      {"3", SHELL_NETSTRING_EFORMAT},
      {"3:ab", SHELL_NETSTRING_EFORMAT},
      {"3:abc", SHELL_NETSTRING_EFORMAT},
      {"3:abc.", SHELL_NETSTRING_EFORMAT},
  };
  unsigned char *record = (unsigned char *)(void *)1;
  size_t length = SIZE_MAX;

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    FILE *stream = tmpfile();
    TEST("open malformed stream", stream != NULL);
    if (!stream)
      continue;
    fputs(cases[i].input, stream);
    rewind(stream);
    record = (unsigned char *)(void *)1;
    length = SIZE_MAX;
    TEST("stream reader rejects malformed framing",
         shell_netstring_read_stream(stream, 0, &record, &length) ==
                 cases[i].expected &&
             record == NULL && length == 0);
    fclose(stream);
  }
  FILE *limited = tmpfile();
  TEST("open limited stream", limited != NULL);
  if (limited) {
    fputs("3:cat,", limited);
    rewind(limited);
    TEST("stream reader enforces record limit",
         shell_netstring_read_stream(limited, 5, &record, &length) ==
                 SHELL_NETSTRING_EOVERFLOW &&
             record == NULL && length == 0);
    fclose(limited);
  }
}

static void structures_run_netstring(void) {
  structures_state = RNG_SEED;
  printf("=== Shellsplit Netstring Tests ===\n");
  structures_test_netstring_iteration();
  structures_test_netstring_binary_and_nested_payloads();
  structures_test_netstring_validation_failures();
  structures_test_netstring_count_and_error_position();
  structures_test_netstring_encoding();
  structures_test_netstring_encoding_capacity_boundaries();
  structures_test_netstring_malformed_record();
  structures_test_netstring_stream_reader();
  structures_test_netstring_stream_reader_bounds_prefix_digits();
  structures_test_netstring_stream_reader_allocation_failures();
  structures_test_netstring_stream_reader_rejects_unallocatable_record();
  structures_test_netstring_stream_reader_format_failures();
}

static int run_structures(int argc, char **argv) {
  (void)argc;
  (void)argv;
  structures_run_pmap();
  structures_run_avl();
  structures_run_occupancy();
  structures_run_netstring();
  printf("%d passed, %d failed\n", structures_passed, structures_failed);
  return structures_failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
#undef TEST
#undef RNG_SEED

/* --- entropy (from entropy_test.c) --- */
static int entropy_tests_run;
static int entropy_tests_passed;
static int entropy_tests_failed;

#define ASSERT(condition)                                                      \
  do {                                                                         \
    if (!(condition)) {                                                        \
      printf("    assertion failed: %s at %s:%d\n", #condition, __FILE__,      \
             __LINE__);                                                        \
      return 0;                                                                \
    }                                                                          \
  } while (0)

#define TEST(function)                                                         \
  do {                                                                         \
    entropy_tests_run++;                                                       \
    printf("  %-38s ", #function);                                             \
    if (function()) {                                                          \
      entropy_tests_passed++;                                                  \
      printf("PASS\n");                                                        \
    } else {                                                                   \
      entropy_tests_failed++;                                                  \
      printf("FAIL\n");                                                        \
    }                                                                          \
  } while (0)

static int entropy_near(double actual, double expected, double tolerance) {
  return isfinite(actual) && fabs(actual - expected) <= tolerance;
}

static int entropy_test_known_entropy_values(void) {
  static const struct {
    const char *text;
    double shannon;
    double bigram;
    double conditional;
  } cases[] = {{"", 0.0, 0.0, 0.0},
               {"aaaa", 0.0, 0.0, 0.0},
               {"abab", 1.0, 0.9182958340544896, 0.0},
               {"abcd", 2.0, 1.584962500721156, 0.0},
               {"aab", 0.9182958340544896, 1.0, 1.0}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT(entropy_near(shell_env_screener_calculate_entropy(cases[i].text),
                        cases[i].shannon, 1e-12));
    ASSERT(entropy_near(shell_rpe_ngram_entropy(cases[i].text, 1),
                        cases[i].shannon, 1e-12));
    ASSERT(entropy_near(shell_rpe_ngram_entropy(cases[i].text, 2),
                        cases[i].bigram, 1e-12));
    ASSERT(entropy_near(shell_rpe_conditional_entropy(cases[i].text),
                        cases[i].conditional, 1e-12));
  }

  ASSERT(shell_rpe_ngram_entropy("", 2) == 0.0);

  ASSERT(isnan(shell_rpe_ngram_entropy("abcd", 0)));
  ASSERT(isnan(shell_rpe_ngram_entropy("abcd", 3)));

  return 1;
}

static int entropy_test_permutation_boundaries_and_ranges(void) {
  ASSERT(entropy_near(shell_rpe_permutation_entropy("abcd", 5, 2),
                      shell_rpe_ngram_entropy("abcd", 2), 1e-12));
  ASSERT(
      entropy_near(shell_rpe_relative_entropy_ratio("abcd", 5, 2), 1.0, 1e-12));
  ASSERT(isnan(shell_rpe_permutation_entropy("abcd", 0, 2)));
  ASSERT(isnan(shell_rpe_permutation_entropy("abcd", 5, 3)));
  ASSERT(isnan(shell_rpe_permutation_conditional_entropy("abcd", 0)));

  char long_input[512];
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (size_t i = 0; i < sizeof(long_input) - 1; i++)
    long_input[i] = alphabet[(i * 37 + i / 7) % (sizeof(alphabet) - 1)];
  long_input[sizeof(long_input) - 1] = '\0';

  double values[] = {shell_rpe_permutation_entropy(long_input, 17, 2),
                     shell_rpe_permutation_conditional_entropy(long_input, 17),
                     shell_rpe_relative_entropy_ratio(long_input, 17, 2),
                     shell_rpe_relative_conditional_entropy(long_input, 17)};
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
    ASSERT(isfinite(values[i]) && values[i] >= 0.0);
  ASSERT(values[0] <= log2(strlen(long_input)));
  ASSERT(values[1] <= 8.0);
  return 1;
}

/* Unigram entropy depends only on character frequencies, which a permutation
 * keeps, so its permutation entropy is the ordinary entropy exactly, however
 * many permutations are requested, and needs no working memory to compute. */
static int entropy_test_unigram_permutation_entropy_ignores_order(void) {
  static const char *const inputs[] = {
      "",
      "a",
      "aabbcc",
      "abcabc",
      "ccbbaa",
      "abcdefghijk",
      "aaaaaaaaaaaaaaaaaaaaaaaa",
      "abcdefghijklmnopqrstuvwxyz0123456789",
      "aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz",
      "\xff\x80\xff\x80 mixed bytes \x01\x02\x01",
  };
  static const int permutations[] = {1, 2, 17, 100};
  for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
    double expected = shell_rpe_ngram_entropy(inputs[i], 1);
    for (size_t p = 0; p < sizeof(permutations) / sizeof(permutations[0]);
         p++) {
      ASSERT(shell_rpe_permutation_entropy(inputs[i], permutations[p], 1) ==
             expected);
      /* An allocation failure cannot make a computable entropy unavailable. */
      shellsplit_test_alloc_fail_at(1);
      double without_memory =
          shell_rpe_permutation_entropy(inputs[i], permutations[p], 1);
      size_t allocations = shellsplit_test_alloc_count();
      shellsplit_test_alloc_reset();
      ASSERT(without_memory == expected && allocations == 0);
    }
  }
  ASSERT(shell_rpe_relative_entropy_ratio("abcabcabcabc", 17, 1) == 1.0);
  ASSERT(shell_rpe_relative_entropy_ratio("aaaaaaaaaaaaaaaa", 17, 1) == 2.0);
  return 1;
}

static int entropy_test_permutation_allocation_failures(void) {
  static const char input[] = "abcdefghijklmnopqrstuvwxyz0123456789";
  for (size_t fail_at = 1; fail_at <= 2; fail_at++) {
    shellsplit_test_alloc_fail_at(fail_at);
    ASSERT(isnan(shell_rpe_permutation_entropy(input, 7, 2)));
    shellsplit_test_alloc_fail_at(fail_at);
    ASSERT(isnan(shell_rpe_relative_entropy_ratio(input, 7, 2)));
    shellsplit_test_alloc_fail_at(fail_at);
    ASSERT(isnan(shell_rpe_permutation_conditional_entropy(input, 7)));
    shellsplit_test_alloc_fail_at(fail_at);
    ASSERT(isnan(shell_rpe_relative_conditional_entropy(input, 7)));
  }
  shellsplit_test_alloc_reset();
  ASSERT(isfinite(shell_rpe_permutation_entropy(input, 7, 2)));
  ASSERT(isfinite(shell_rpe_permutation_conditional_entropy(input, 7)));
  return 1;
}

static int entropy_test_posterior_regression_matrix(void) {
  static const struct {
    const char *value;
    double expected;
  } cases[] = {
      {"sk-abcdef1234567890abcdef1234567890", 0.877750},
      {"AKIAIOSFODNN7EXAMPLE", 0.997336},
      {"ghp_abcdefghijklmnopqrstuvwxyz1234567890", 0.980423},
      {"mySecretPassword123!@#", 0.680517},
      {"SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBzZWNyZXQ=", 0.625894},
      {"/home/user/.config/some/app/config.json", 0.000009},
      {"The quick brown fox jumps over the lazy dog", 0.743211},
      {"password123", 0.406075},
      {"550e8400-e29b-41d4-a716-446655440000", 0.279652},
      {"aaaaaaaaaaaaaaaaaaaa", 0.000005},
      {"xK9mLp2nQ4rS6tU8vW0yZ2aB4cD6eF8gH0j", 0.828812},
      {"abc", 0.0},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    double score = shell_env_screener_combined_score_name(NULL, cases[i].value);
    double tolerance = fmax(1e-6, cases[i].expected * 0.01);
    ASSERT(entropy_near(score, cases[i].expected, tolerance));
    ASSERT(score >= 0.0 && score <= 1.0);
  }

  const char *value = "someRandomValue1234567890abcdef";
  double unnamed = shell_env_screener_combined_score_name(NULL, value);
  double named =
      shell_env_screener_combined_score_name("SERVICE_API_KEY", value);
  ASSERT(named > unnamed);
  return 1;
}

static int entropy_test_longest_prefix_suffix_entropy(void) {
  /* The longest overlapping prefix owns the suffix: AIzaSy, not AIza. */
  double entropy = -1.0;
  ASSERT(
      shell_env_screener_check_secret_prefix("AIzaSyAAAAAAAAAAAA", &entropy));
  ASSERT(entropy == 0.0);
  ASSERT(shell_env_screener_check_secret_prefix("AIzaXXXXXXX", &entropy));
  ASSERT(entropy == 0.0);
  entropy = -1.0;
  ASSERT(shell_env_screener_check_secret_prefix("AIzaSyAbCdEf", &entropy));
  ASSERT(entropy_near(entropy, shell_env_screener_calculate_entropy("AbCdEf"),
                      1e-12));
  /* A value with nothing after the longer prefix falls back to the shorter. */
  ASSERT(shell_env_screener_check_secret_prefix("AIzaSy", &entropy));
  ASSERT(
      entropy_near(entropy, shell_env_screener_calculate_entropy("Sy"), 1e-12));
  ASSERT(shell_env_screener_check_secret_prefix("sk-abc", NULL));
  ASSERT(!shell_env_screener_check_secret_prefix("sk-", NULL));
  return 1;
}

static int entropy_test_zero_entropy_suffix_score(void) {
  /* A zero-entropy suffix is a valid result, not a missing one: the score
   * must not fall back to the entropy of the whole value. */
  static const struct {
    const char *value;
    double expected;
  } cases[] = {
      {"sk-AAAAAAAAAAAA", 0.001305},
      {"AIzaXXXXXXX", 0.079024},
      {"AIzaSyAAAAAAAAAAAA", 0.026508},
      {"sk-abcdef123456", 0.883451},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    ASSERT(entropy_near(
        shell_env_screener_combined_score_name(NULL, cases[i].value),
        cases[i].expected, fmax(1e-6, cases[i].expected * 0.01)));
  return 1;
}

static int entropy_test_detector_matrices(void) {
  static const struct {
    const char *value;
    int path;
    int base64;
    int prefix;
  } values[] = {{"/tmp/some/path", 1, 0, 0},
                {"~/Documents/file", 1, 0, 0},
                {"prefix/tmp/file", 1, 0, 0},
                {"prefix/var/file", 1, 0, 0},
                {"prefix/home/file", 1, 1, 0},
                {"prefix/usr/file", 1, 0, 0},
                {"prefix/etc/file", 1, 0, 0},
                {"prefix/run/file", 1, 0, 0},
                {"prefix/.local/file", 1, 0, 0},
                {"prefix/.cache/file", 1, 0, 0},
                {"sk-abc123", 0, 0, 1},
                {"sk-", 0, 0, 0},
                {"AKIAIOSFODNN7EXAMPLE", 0, 1, 1},
                {"SGVsbG8gV29ybGQh", 0, 1, 0},
                {"abcdefghijklmnop", 0, 1, 0},
                {"0123456789012345", 0, 1, 0},
                {"++++++++++++++++", 0, 1, 0},
                {"////////////////", 1, 1, 0},
                {"YWJjZA==", 0, 1, 0},
                {"AAA=", 0, 1, 0},
                {"AA==", 0, 1, 0},
                {"==", 0, 0, 0},
                {"A=AA", 0, 0, 0},
                {"AAA", 0, 0, 0},
                {"QUJDRA", 0, 0, 0},
                {"====", 0, 0, 0},
                {"hello world!", 0, 0, 0},
                {"", 0, 0, 0},
                {"", 0, 0, 0}};
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    ASSERT(shell_env_screener_looks_like_path(values[i].value) ==
           (bool)values[i].path);
    ASSERT(shell_env_screener_looks_like_base64(values[i].value) ==
           (bool)values[i].base64);
    ASSERT(shell_env_screener_check_secret_prefix(values[i].value, NULL) ==
           (bool)values[i].prefix);
  }

  static const struct {
    const char *name;
    int whitelisted;
    int secret;
  } names[] = {{"DISPLAY", 1, 0},        {"TMUX", 1, 0},
               {"PATH", 1, 0},           {"SERVICE_API_KEY", 0, 1},
               {"MY_PASSWORD", 0, 1},    {"AUTH_TOKEN", 0, 1},
               {"ORDINARY_VALUE", 0, 0}, {"", 0, 0}};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    ASSERT(shell_env_screener_is_whitelisted(names[i].name) ==
           (bool)names[i].whitelisted);
    ASSERT(shell_env_screener_is_secret_pattern(names[i].name) ==
           (bool)names[i].secret);
  }

  double suffix_entropy = -1.0;
  ASSERT(shell_env_screener_check_secret_prefix("sk-abcdef123456",
                                                &suffix_entropy));
  ASSERT(entropy_near(suffix_entropy,
                      shell_env_screener_calculate_entropy("abcdef123456"),
                      1e-12));
  const char *whitelist = shell_env_screener_get_whitelist_doc();
  ASSERT(whitelist && strstr(whitelist, "DISPLAY") &&
         strstr(whitelist, "PATH"));
  ASSERT(shell_env_screener_get_whitelist_doc() == whitelist);
  ASSERT(shell_env_screener_is_whitelisted("DISPLAY"));
  ASSERT(shell_env_screener_is_whitelisted("WAYLAND_DISLOCK"));
  ASSERT(!shell_env_screener_is_whitelisted("DISPLA"));
  ASSERT(!shell_env_screener_is_whitelisted("PATHX"));
  ASSERT(!shell_env_screener_is_whitelisted("PS"));
  ASSERT(!shell_env_screener_is_whitelisted(""));
  return 1;
}

static int entropy_test_allocation_failure_is_not_a_non_detection(void) {
  extern char **environ;
  char **saved_environ = environ;
  char *controlled_environ[] = {
      "API_KEY=9fA3kLmP2qRsT7vWxY1zB4cD6eF8gH0j",
      NULL,
  };
  size_t indices[2] = {SIZE_MAX, SIZE_MAX};
  size_t count = SIZE_MAX;

  environ = controlled_environ;
  /* An entry takes four allocations to score, and the counting and filling
   * passes each score it: failing any of the eight must be an error. */
  for (size_t fail_at = 1; fail_at <= 8; fail_at++) {
    shellsplit_test_alloc_fail_at(fail_at);
    shell_env_screener_status_t status =
        shell_env_screener_scan(indices, 2, &count, 0.5, 8);
    shellsplit_test_alloc_reset();
    ASSERT(status == SHELL_ENV_SCREENER_ERROR);
    ASSERT(count == 0);
  }
  ASSERT(shell_env_screener_scan(indices, 2, &count, 0.5, 8) ==
         SHELL_ENV_SCREENER_OK);
  ASSERT(count == 1 && indices[0] == 0);
  environ = saved_environ;
  return 1;
}

static int entropy_test_environment_scan_contract(void) {
  extern char **environ;
  char **saved_environ = environ;
  char long_named_secret[320];
  memset(long_named_secret, 'X', 256);
  memcpy(long_named_secret + 256, "API_KEY=someRandomValue1234567890abcdef",
         sizeof("API_KEY=someRandomValue1234567890abcdef"));
  char *controlled_environ[] = {
      "DISPLAY=xK9mLp2nQ4rS6tU8vW0yZ2aB4cD6eF8gH0j",
      "missing-equals",
      "=missing-name",
      "EMPTY=",
      "SHORT=abc",
      "SERVICE_API_KEY=someRandomValue1234567890abcdef",
      "ORDINARY_VALUE=/home/user/.config/some/app/config.json",
      "GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
      long_named_secret,
      NULL,
  };
  size_t indices[3] = {SIZE_MAX, SIZE_MAX, SIZE_MAX};
  size_t count = SIZE_MAX;

  environ = controlled_environ;
  ASSERT(shell_env_screener_scan(indices, 1, &count, 0.5, 8) ==
         SHELL_ENV_SCREENER_BUFFER_TOO_SMALL);
  ASSERT(count == 3 && indices[0] == SIZE_MAX && indices[1] == SIZE_MAX &&
         indices[2] == SIZE_MAX);

  ASSERT(shell_env_screener_scan(indices, 3, &count, 0.5, 8) ==
         SHELL_ENV_SCREENER_OK);
  ASSERT(count == 3 && indices[0] == 5 && indices[1] == 7 && indices[2] == 8);

  /* A NULL buffer with capacity 0 is a sizing query: the required capacity is
   * reported and no index is written. The reported size then fits exactly. */
  count = SIZE_MAX;
  ASSERT(shell_env_screener_scan(NULL, 0, &count, 0.5, 8) ==
         SHELL_ENV_SCREENER_BUFFER_TOO_SMALL);
  ASSERT(count == 3);
  size_t required = count;
  ASSERT(shell_env_screener_scan(indices, required, &count, 0.5, 8) ==
             SHELL_ENV_SCREENER_OK &&
         count == required);
  count = SIZE_MAX;
  ASSERT(shell_env_screener_scan(NULL, 0, &count, 1.0, 8) ==
             SHELL_ENV_SCREENER_OK &&
         count == 0);
  count = SIZE_MAX;
  ASSERT(shell_env_screener_scan(NULL, 0, &count, 0.0, 100) ==
             SHELL_ENV_SCREENER_OK &&
         count == 0);
  count = SIZE_MAX;
  ASSERT(shell_env_screener_scan(NULL, 0, &count, NAN, 8) ==
             SHELL_ENV_SCREENER_ERROR &&
         count == 0);

  ASSERT(shell_env_screener_scan(indices, 3, &count, 1.0, 8) ==
         SHELL_ENV_SCREENER_OK);
  ASSERT(count == 0);
  ASSERT(shell_env_screener_scan(indices, 3, &count, 0.0, 100) ==
         SHELL_ENV_SCREENER_OK);
  ASSERT(count == 0);

  static const double invalid_thresholds[] = {-0.01, 1.01, NAN, INFINITY,
                                              -INFINITY};
  for (size_t i = 0;
       i < sizeof(invalid_thresholds) / sizeof(invalid_thresholds[0]); i++) {
    count = SIZE_MAX;
    ASSERT(shell_env_screener_scan(indices, 3, &count, invalid_thresholds[i],
                                   8) == SHELL_ENV_SCREENER_ERROR);
    ASSERT(count == 0);
  }

  environ = NULL;
  count = SIZE_MAX;
  ASSERT(shell_env_screener_scan(indices, 3, &count, 0.5, 8) ==
         SHELL_ENV_SCREENER_OK);
  ASSERT(count == 0);
  count = SIZE_MAX;
  ASSERT(shell_env_screener_scan(NULL, 0, &count, 0.5, 8) ==
             SHELL_ENV_SCREENER_OK &&
         count == 0);

  /* Long names bypass the fixed whitelist buffer. A non-secret long name
   * must still be scored safely when no bounded secret pattern is present. */
  char long_named_plain[320];
  memset(long_named_plain, 'X', 256);
  memcpy(long_named_plain + 256, "=ordinary-value", sizeof("=ordinary-value"));
  char *plain_environ[] = {long_named_plain, NULL};
  environ = plain_environ;
  ASSERT(shell_env_screener_scan(indices, 3, &count, 1.0, 8) ==
         SHELL_ENV_SCREENER_OK);
  ASSERT(count == 0);

  environ = saved_environ;
  return 1;
}

static int run_entropy(int argc, char **argv) {
  (void)argc;
  (void)argv;
  printf("Running entropy and environment-screening tests...\n\n");
  TEST(entropy_test_known_entropy_values);
  TEST(entropy_test_permutation_boundaries_and_ranges);
  TEST(entropy_test_permutation_allocation_failures);
  TEST(entropy_test_unigram_permutation_entropy_ignores_order);
  TEST(entropy_test_posterior_regression_matrix);
  TEST(entropy_test_longest_prefix_suffix_entropy);
  TEST(entropy_test_zero_entropy_suffix_score);
  TEST(entropy_test_detector_matrices);
  TEST(entropy_test_environment_scan_contract);
  TEST(entropy_test_allocation_failure_is_not_a_non_detection);
  printf("\nResults: %d/%d passed, %d failed\n", entropy_tests_passed,
         entropy_tests_run, entropy_tests_failed);
  return entropy_tests_failed > 0 ? 1 : 0;
}
#undef ASSERT
#undef TEST

int main(int argc, char **argv) {
  int status = 0;
  status |= run_structures(argc, argv);
  status |= run_entropy(argc, argv);
  return status != 0;
}
