#ifndef SHELL_PMAP_INTERNAL_H
#define SHELL_PMAP_INTERNAL_H

#include "shell_contract.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* Hash-consed persistent big-endian Patricia tries (Okasaki and Gill, "Fast
 * Mergeable Integer Maps") from 64-bit keys to 32-bit values.
 *
 * Canonical form. A trie's shape depends only on its key set, and every node
 * is interned: two maps with the same entries (key, value and leaf summary)
 * have the same root id. Root equality is therefore map equality, and the
 * structural walks below skip a subtree whose ids agree. diff() costs
 * O(d·W) for the d keys whose entries differ (W = 64), whatever the maps'
 * sizes; get/set/erase cost O(W).
 *
 * Summaries. Each leaf carries a caller-chosen summary byte, and a branch
 * holds the OR of its subtrees' summaries, so each_summary() visits only the
 * m leaves with a requested summary bit in O(m·W). Callers must give the same
 * summary to equal (key, value) pairs; it is part of the entry's identity.
 *
 * Storage. A pool borrows caller arrays: nodes, a power-of-two open-addressing
 * intern table of node ids, and a mark byte per node for collection. Ids are
 * one-based (0 is the empty map) and fit 16 bits. Nodes are immutable once
 * published. New nodes are appended, or reused from the free list that a
 * collection sweep builds when reuse is enabled. With reuse disabled, ids grow
 * monotonically and rollback() releases a suffix, so a nested parse can return
 * its storage. Interning is expected O(1): node contents are mixed with a
 * 64-bit finalizer before linear probing.
 *
 * Failure. An operation that would exceed capacity returns false and leaves
 * every published root valid; nodes it already created stay interned and are
 * reclaimed by rollback() or a collection. Callers that must not fail
 * preflight shell_pmap_available() against SHELL_PMAP_UPDATE_NODES per
 * update. */

/* Tests may count structural steps to check the cost bounds above. */
#ifndef SHELL_PMAP_WORK
#define SHELL_PMAP_WORK() ((void)0)
#endif

enum {
  /* Node bit value of a leaf; branches use 0..63. */
  SHELL_PMAP_LEAF = 64,
  /* Worst-case nodes one set() or erase() creates: a copy of each of at most
   * 64 branches on the path, plus a new leaf and the branch joining it. */
  SHELL_PMAP_UPDATE_NODES = 66,
};

typedef struct {
  /* Leaf: its key. Branch: the common prefix, bits at and below bit cleared. */
  uint64_t key;
  union {
    uint32_t value;
    struct {
      uint16_t left, right;
    } child;
  } u;
  /* SHELL_PMAP_LEAF, or the branch bit: left keys have it clear. A free
   * node uses SHELL_PMAP_LEAF + 1 and links the free list through left. */
  uint8_t bit;
  uint8_t summary;
} __attribute__((packed)) shell_pmap_node_t;
_Static_assert(sizeof(shell_pmap_node_t) == 14,
               "trie nodes carry no alignment padding");

typedef struct {
  shell_pmap_node_t *nodes;
  /* Intern table: node ids, 0 for an empty slot. Its size is a power of two
   * at least twice capacity, so probes stay short and always terminate. */
  uint16_t *table;
  uint8_t *marks;
  uint32_t capacity;
  uint32_t table_mask;
  /* High-water mark: ids 1..count are allocated or free. */
  uint32_t count;
  uint16_t free, free_count;
  bool reuse;
  /* Nodes created since init or the last sweep; callers pace collections. */
  uint32_t allocations;
} shell_pmap_pool_t;

/* nodes and marks hold capacity entries; table holds table_size entries, a
 * power of two at least 2 * capacity; capacity is at most UINT16_MAX. */
static SHELL_NONNULL(1, 2, 3, 4) inline void shell_pmap_init(
    shell_pmap_pool_t *pool, shell_pmap_node_t *nodes, uint16_t *table,
    uint8_t *marks, uint32_t capacity, uint32_t table_size) {
  *pool = (shell_pmap_pool_t){.nodes = nodes,
                              .table = table,
                              .marks = marks,
                              .capacity = capacity,
                              .table_mask = table_size - 1,
                              .reuse = true};
  memset(table, 0, table_size * sizeof(*table));
}

static SHELL_NONNULL(1) inline uint32_t
    shell_pmap_available(const shell_pmap_pool_t *pool) {
  return pool->capacity - pool->count + (pool->reuse ? pool->free_count : 0);
}

static SHELL_NONNULL(1) inline const shell_pmap_node_t *shell_pmap_node(
    const shell_pmap_pool_t *pool, uint32_t id) {
  return &pool->nodes[id - 1];
}

static inline uint64_t shell_pmap_mix(uint64_t x) {
  x ^= x >> 30;
  x *= UINT64_C(0xbf58476d1ce4e5b9);
  x ^= x >> 27;
  x *= UINT64_C(0x94d049bb133111eb);
  return x ^ (x >> 31);
}

static SHELL_NONNULL(1) inline uint32_t
    shell_pmap_hash(const shell_pmap_pool_t *pool,
                    const shell_pmap_node_t *node) {
  uint64_t payload =
      node->bit == SHELL_PMAP_LEAF
          ? node->u.value
          : (uint64_t)node->u.child.left << 16 | node->u.child.right;
  uint64_t h = shell_pmap_mix(
      node->key ^ shell_pmap_mix(payload ^ (uint64_t)node->bit << 40 ^
                                 (uint64_t)node->summary << 48));
  return (uint32_t)h & pool->table_mask;
}

static SHELL_NONNULL(1, 2) inline bool shell_pmap_same(
    const shell_pmap_node_t *a, const shell_pmap_node_t *b) {
  if (a->key != b->key || a->bit != b->bit || a->summary != b->summary)
    return false;
  return a->bit == SHELL_PMAP_LEAF ? a->u.value == b->u.value
                                   : a->u.child.left == b->u.child.left &&
                                         a->u.child.right == b->u.child.right;
}

/* Remove interned id from the table by backward-shift deletion, which keeps
 * every remaining probe sequence unbroken without tombstones. */
static SHELL_NONNULL(1) inline void shell_pmap_unintern(shell_pmap_pool_t *pool,
                                                        uint32_t id) {
  uint32_t slot = shell_pmap_hash(pool, shell_pmap_node(pool, id));
  while (pool->table[slot] != id)
    slot = (slot + 1) & pool->table_mask;
  for (uint32_t next = (slot + 1) & pool->table_mask;;
       next = (next + 1) & pool->table_mask) {
    uint16_t moved = pool->table[next];
    if (!moved)
      break;
    uint32_t home = shell_pmap_hash(pool, shell_pmap_node(pool, moved));
    /* moved may fill slot only if slot lies on its probe path home..next. */
    if (((next - home) & pool->table_mask) >=
        ((next - slot) & pool->table_mask)) {
      pool->table[slot] = moved;
      slot = next;
    }
  }
  pool->table[slot] = 0;
}

/* The interned id of node, creating it if needed; 0 when the pool is full. */
static SHELL_NONNULL(1, 2) inline uint32_t
    shell_pmap_intern(shell_pmap_pool_t *pool, const shell_pmap_node_t *node) {
  uint32_t slot = shell_pmap_hash(pool, node);
  for (uint16_t id; (id = pool->table[slot]) != 0;
       slot = (slot + 1) & pool->table_mask)
    if (shell_pmap_same(shell_pmap_node(pool, id), node))
      return id;
  uint32_t id;
  if (pool->reuse && pool->free) {
    id = pool->free;
    pool->free = pool->nodes[id - 1].u.child.left;
    pool->free_count--;
  } else if (pool->count < pool->capacity) {
    id = ++pool->count;
  } else {
    return 0;
  }
  pool->nodes[id - 1] = *node;
  pool->table[slot] = (uint16_t)id;
  pool->allocations++;
  return id;
}

static SHELL_NONNULL(1) inline uint32_t
    shell_pmap_leaf(shell_pmap_pool_t *pool, uint64_t key, uint32_t value,
                    uint8_t summary) {
  shell_pmap_node_t node = {
      .key = key, .u.value = value, .bit = SHELL_PMAP_LEAF, .summary = summary};
  return shell_pmap_intern(pool, &node);
}

/* Normalizing constructor: a branch with an empty side is its other side.
 * left and right are valid ids whose keys agree above bit, with bit clear in
 * left's keys and set in right's. Returns 0 only when the pool is full and
 * both sides are nonempty. */
static SHELL_NONNULL(1) inline uint32_t
    shell_pmap_branch(shell_pmap_pool_t *pool, uint64_t prefix, unsigned bit,
                      uint32_t left, uint32_t right) {
  if (!left)
    return right;
  if (!right)
    return left;
  shell_pmap_node_t node = {
      .key = prefix,
      .u.child = {(uint16_t)left, (uint16_t)right},
      .bit = (uint8_t)bit,
      .summary = (uint8_t)(shell_pmap_node(pool, left)->summary |
                           shell_pmap_node(pool, right)->summary)};
  return shell_pmap_intern(pool, &node);
}

/* Keys agreeing with prefix strictly above bit. */
static inline uint64_t shell_pmap_mask(uint64_t key, unsigned bit) {
  return key & ~((UINT64_C(2) << bit) - 1);
}

static inline unsigned shell_pmap_highest(uint64_t difference) {
  return 63u - (unsigned)__builtin_clzll(difference);
}

/* Join two nonempty tries with disjoint prefixes; 0 when the pool is full. */
static SHELL_NONNULL(1) inline uint32_t
    shell_pmap_join(shell_pmap_pool_t *pool, uint64_t first_prefix,
                    uint32_t first, uint64_t second_prefix, uint32_t second) {
  unsigned bit = shell_pmap_highest(first_prefix ^ second_prefix);
  uint64_t prefix = shell_pmap_mask(first_prefix, bit);
  return (first_prefix >> bit) & 1
             ? shell_pmap_branch(pool, prefix, bit, second, first)
             : shell_pmap_branch(pool, prefix, bit, first, second);
}

static SHELL_NONNULL(1, 4) inline bool shell_pmap_get(
    const shell_pmap_pool_t *pool, uint32_t root, uint64_t key,
    uint32_t *value) {
  while (root) {
    SHELL_PMAP_WORK();
    const shell_pmap_node_t *node = shell_pmap_node(pool, root);
    if (node->bit == SHELL_PMAP_LEAF) {
      if (node->key != key)
        return false;
      *value = node->u.value;
      return true;
    }
    if (shell_pmap_mask(key, node->bit) != node->key)
      return false;
    root = (key >> node->bit) & 1 ? node->u.child.right : node->u.child.left;
  }
  return false;
}

/* *root becomes root with key bound to (value, summary). */
static SHELL_NONNULL(1, 2) inline bool shell_pmap_set(shell_pmap_pool_t *pool,
                                                      uint32_t *root,
                                                      uint64_t key,
                                                      uint32_t value,
                                                      uint8_t summary) {
  SHELL_PMAP_WORK();
  uint32_t current = *root;
  if (!current) {
    uint32_t leaf = shell_pmap_leaf(pool, key, value, summary);
    if (leaf)
      *root = leaf;
    return leaf != 0;
  }
  shell_pmap_node_t node = *shell_pmap_node(pool, current);
  uint32_t result;
  if (node.bit == SHELL_PMAP_LEAF) {
    uint32_t leaf = shell_pmap_leaf(pool, key, value, summary);
    if (!leaf)
      return false;
    result = node.key == key
                 ? leaf
                 : shell_pmap_join(pool, key, leaf, node.key, current);
  } else if (shell_pmap_mask(key, node.bit) != node.key) {
    uint32_t leaf = shell_pmap_leaf(pool, key, value, summary);
    if (!leaf)
      return false;
    result = shell_pmap_join(pool, key, leaf, node.key, current);
  } else {
    bool right = (key >> node.bit) & 1;
    uint32_t child = right ? node.u.child.right : node.u.child.left;
    uint32_t original = child;
    if (!shell_pmap_set(pool, &child, key, value, summary))
      return false;
    if (child == original)
      return true;
    result = right ? shell_pmap_branch(pool, node.key, node.bit,
                                       node.u.child.left, child)
                   : shell_pmap_branch(pool, node.key, node.bit, child,
                                       node.u.child.right);
  }
  if (result)
    *root = result;
  return result != 0;
}

/* *root becomes root without key. */
static SHELL_NONNULL(1, 2) inline bool shell_pmap_erase(shell_pmap_pool_t *pool,
                                                        uint32_t *root,
                                                        uint64_t key) {
  SHELL_PMAP_WORK();
  uint32_t current = *root;
  if (!current)
    return true;
  shell_pmap_node_t node = *shell_pmap_node(pool, current);
  if (node.bit == SHELL_PMAP_LEAF) {
    if (node.key == key)
      *root = 0;
    return true;
  }
  if (shell_pmap_mask(key, node.bit) != node.key)
    return true;
  bool right = (key >> node.bit) & 1;
  uint32_t child = right ? node.u.child.right : node.u.child.left;
  uint32_t original = child;
  if (!shell_pmap_erase(pool, &child, key))
    return false;
  if (child == original)
    return true;
  uint32_t result = right ? shell_pmap_branch(pool, node.key, node.bit,
                                              node.u.child.left, child)
                          : shell_pmap_branch(pool, node.key, node.bit, child,
                                              node.u.child.right);
  if (result)
    *root = result;
  return result != 0;
}

/* The subtrie of root holding exactly its keys that agree with prefix above
 * bit (prefix has bit and the bits below it clear). In a Patricia trie those
 * keys form one subtree, so this is an existing node, found in O(W) without
 * allocating; 0 when no key matches. */
static SHELL_NONNULL(1) inline uint32_t
    shell_pmap_restrict(const shell_pmap_pool_t *pool, uint32_t root,
                        uint64_t prefix, unsigned bit) {
  while (root) {
    SHELL_PMAP_WORK();
    const shell_pmap_node_t *node = shell_pmap_node(pool, root);
    if (node->bit == SHELL_PMAP_LEAF || node->bit <= bit)
      return shell_pmap_mask(node->key, bit) == prefix ? root : 0;
    if (shell_pmap_mask(prefix, node->bit) != node->key)
      return 0;
    root = (prefix >> node->bit) & 1 ? node->u.child.right : node->u.child.left;
  }
  return 0;
}

/* visit returns false to stop; the walk then returns false. */
typedef bool (*shell_pmap_visit_t)(void *context, uint64_t key, uint32_t value,
                                   uint8_t summary);

/* Leaves whose summary intersects mask, in ascending key order. */
static SHELL_NONNULL(1, 4) inline bool shell_pmap_each_summary(
    const shell_pmap_pool_t *pool, uint32_t root, uint8_t mask,
    shell_pmap_visit_t visit, void *context) {
  if (!root)
    return true;
  SHELL_PMAP_WORK();
  const shell_pmap_node_t *node = shell_pmap_node(pool, root);
  if (!(node->summary & mask))
    return true;
  if (node->bit == SHELL_PMAP_LEAF)
    return visit(context, node->key, node->u.value, node->summary);
  return shell_pmap_each_summary(pool, node->u.child.left, mask, visit,
                                 context) &&
         shell_pmap_each_summary(pool, node->u.child.right, mask, visit,
                                 context);
}

/* Every leaf in ascending key order, summaries included. */
static SHELL_NONNULL(1, 3) inline bool shell_pmap_each(
    const shell_pmap_pool_t *pool, uint32_t root, shell_pmap_visit_t visit,
    void *context) {
  if (!root)
    return true;
  SHELL_PMAP_WORK();
  const shell_pmap_node_t *node = shell_pmap_node(pool, root);
  if (node->bit == SHELL_PMAP_LEAF)
    return visit(context, node->key, node->u.value, node->summary);
  return shell_pmap_each(pool, node->u.child.left, visit, context) &&
         shell_pmap_each(pool, node->u.child.right, visit, context);
}

/* A key whose entries differ: present tells which sides bind it. */
typedef enum {
  SHELL_PMAP_LEFT = 1,
  SHELL_PMAP_RIGHT = 2,
  SHELL_PMAP_BOTH = 3
} shell_pmap_sides_t;
typedef bool (*shell_pmap_diff_visit_t)(void *context, uint64_t key,
                                        shell_pmap_sides_t present,
                                        uint32_t left_value,
                                        uint32_t right_value);

typedef struct {
  shell_pmap_diff_visit_t visit;
  void *context;
  shell_pmap_sides_t side;
} shell_pmap_one_side_t;

static inline bool shell_pmap_one_side(void *context, uint64_t key,
                                       uint32_t value, uint8_t summary) {
  (void)summary;
  const shell_pmap_one_side_t *one = context;
  return one->side == SHELL_PMAP_LEFT
             ? one->visit(one->context, key, SHELL_PMAP_LEFT, value, 0)
             : one->visit(one->context, key, SHELL_PMAP_RIGHT, 0, value);
}

static SHELL_NONNULL(1, 4) inline bool shell_pmap_only(
    const shell_pmap_pool_t *pool, uint32_t root, shell_pmap_sides_t side,
    shell_pmap_diff_visit_t visit, void *context) {
  shell_pmap_one_side_t one = {visit, context, side};
  return shell_pmap_each(pool, root, shell_pmap_one_side, &one);
}

/* The prefix and bit of a nonempty node, a leaf having bit -1. */
static SHELL_NONNULL(1) inline int shell_pmap_span(
    const shell_pmap_pool_t *pool, uint32_t id, uint64_t *prefix) {
  const shell_pmap_node_t *node = shell_pmap_node(pool, id);
  *prefix = node->key;
  return node->bit == SHELL_PMAP_LEAF ? -1 : node->bit;
}

/* Keys whose entries differ between left and right, ascending. Identical
 * subtrees are skipped by id. A key bound on both sides to the same value
 * with different summaries is reported, with equal values. */
static SHELL_NONNULL(1, 4) inline bool shell_pmap_diff(
    const shell_pmap_pool_t *pool, uint32_t left, uint32_t right,
    shell_pmap_diff_visit_t visit, void *context) {
  SHELL_PMAP_WORK();
  if (left == right)
    return true;
  if (!left)
    return shell_pmap_only(pool, right, SHELL_PMAP_RIGHT, visit, context);
  if (!right)
    return shell_pmap_only(pool, left, SHELL_PMAP_LEFT, visit, context);
  uint64_t lp, rp;
  int lb = shell_pmap_span(pool, left, &lp);
  int rb = shell_pmap_span(pool, right, &rp);
  const shell_pmap_node_t *ln = shell_pmap_node(pool, left);
  const shell_pmap_node_t *rn = shell_pmap_node(pool, right);
  if (lb < 0 && rb < 0 && lp == rp)
    return visit(context, lp, SHELL_PMAP_BOTH, ln->u.value, rn->u.value);
  if (lb == rb && lp == rp)
    return shell_pmap_diff(pool, ln->u.child.left, rn->u.child.left, visit,
                           context) &&
           shell_pmap_diff(pool, ln->u.child.right, rn->u.child.right, visit,
                           context);
  if (lb > rb && shell_pmap_mask(rp, (unsigned)lb) == lp) {
    /* right lies within one side of left's branch; lb > rb >= -1, so left is
     * a branch with a bit in 0..63. */
    if ((rp >> (unsigned)lb) & 1)
      return shell_pmap_only(pool, ln->u.child.left, SHELL_PMAP_LEFT, visit,
                             context) &&
             shell_pmap_diff(pool, ln->u.child.right, right, visit, context);
    return shell_pmap_diff(pool, ln->u.child.left, right, visit, context) &&
           shell_pmap_only(pool, ln->u.child.right, SHELL_PMAP_LEFT, visit,
                           context);
  }
  if (rb > lb && shell_pmap_mask(lp, (unsigned)rb) == rp) {
    if ((lp >> (unsigned)rb) & 1)
      return shell_pmap_only(pool, rn->u.child.left, SHELL_PMAP_RIGHT, visit,
                             context) &&
             shell_pmap_diff(pool, left, rn->u.child.right, visit, context);
    return shell_pmap_diff(pool, left, rn->u.child.left, visit, context) &&
           shell_pmap_only(pool, rn->u.child.right, SHELL_PMAP_RIGHT, visit,
                           context);
  }
  /* Disjoint key ranges: report the lower one first. */
  if (lp < rp)
    return shell_pmap_only(pool, left, SHELL_PMAP_LEFT, visit, context) &&
           shell_pmap_only(pool, right, SHELL_PMAP_RIGHT, visit, context);
  return shell_pmap_only(pool, right, SHELL_PMAP_RIGHT, visit, context) &&
         shell_pmap_only(pool, left, SHELL_PMAP_LEFT, visit, context);
}

/* Collection. Clear marks with mark_begin(), mark every live root with
 * mark(), then sweep(): unmarked nodes leave the intern table and join the
 * free list (reused only while reuse is enabled), and a free suffix lowers
 * the high-water mark. Live ids never change. */
static SHELL_NONNULL(1) inline void shell_pmap_mark_begin(
    shell_pmap_pool_t *pool) {
  memset(pool->marks, 0, pool->count * sizeof(*pool->marks));
}

/* leaf, when not NULL, is called once per newly marked leaf, so values that
 * name other storage (such as nested maps) can be marked too. */
static SHELL_NONNULL(1) inline void shell_pmap_mark(
    shell_pmap_pool_t *pool, uint32_t root,
    void (*leaf)(void *context, uint64_t key, uint32_t value), void *context) {
  while (root && !pool->marks[root - 1]) {
    pool->marks[root - 1] = 1;
    const shell_pmap_node_t *node = shell_pmap_node(pool, root);
    if (node->bit == SHELL_PMAP_LEAF) {
      if (leaf)
        leaf(context, node->key, node->u.value);
      return;
    }
    shell_pmap_mark(pool, node->u.child.left, leaf, context);
    root = node->u.child.right;
  }
}

static SHELL_NONNULL(1) inline bool shell_pmap_is_free(
    const shell_pmap_pool_t *pool, uint32_t id) {
  return shell_pmap_node(pool, id)->bit > SHELL_PMAP_LEAF;
}

static SHELL_NONNULL(1) inline void shell_pmap_sweep(shell_pmap_pool_t *pool) {
  for (uint32_t id = 1; id <= pool->count; id++)
    if (!pool->marks[id - 1] && !shell_pmap_is_free(pool, id)) {
      shell_pmap_unintern(pool, id);
      pool->nodes[id - 1].bit = SHELL_PMAP_LEAF + 1;
    }
  while (pool->count && shell_pmap_is_free(pool, pool->count))
    pool->count--;
  pool->free = pool->free_count = 0;
  for (uint32_t id = pool->count; id; id--)
    if (shell_pmap_is_free(pool, id)) {
      pool->nodes[id - 1].u.child.left = pool->free;
      pool->free = (uint16_t)id;
      pool->free_count++;
    }
  pool->allocations = 0;
}

/* Release every node above count. Requires reuse disabled since count was
 * observed, so the released ids form exactly that suffix. */
static SHELL_NONNULL(1) inline void shell_pmap_rollback(shell_pmap_pool_t *pool,
                                                        uint32_t count) {
  while (pool->count > count) {
    if (!shell_pmap_is_free(pool, pool->count))
      shell_pmap_unintern(pool, pool->count);
    pool->count--;
  }
}

#endif
