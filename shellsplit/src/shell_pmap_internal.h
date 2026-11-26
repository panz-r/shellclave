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
 * Union. union() combines two maps key by key through a caller function and
 * is memoized on node-id pairs. It reads only node ids and key/value pairs, so
 * the combination of two subtrees cannot depend on anything around them. Each
 * result r = a ⊔ b also records r ⊔ a = r and r ⊔ b = r (absorption), the
 * memo being keyed on the ordered pair, since the join need not commute, so
 * joining an operand into a result that already contains it costs O(1) at the
 * highest node where that holds. Over a sequence of unions the number of
 * fresh node pairs, each costing O(1), is what the cost proofs count. The
 * memo only reuses work: within one union a node pair occurs at most once,
 * since nodes carry absolute key prefixes, so a union without it costs the
 * node pairs on which the operands differ, which is the cost of walking their
 * differing keys. A union that needs an entry once the table is full fails, as
 * shell_pmap_attach_memo states, so the work between two clears is bounded.
 * Only sweep() and rollback() clear it, since both recycle ids. The memo is
 * keyed on node ids alone, so every union on one pool must use, for one tag,
 * the same combining function. A function whose result depends on a small
 * amount of context beyond the two subtrees takes that context as its tag;
 * unions with different tags share the table without ever sharing an entry.
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
/* A union step that computed a node pair, and one answered from the memo. */
#ifndef SHELL_PMAP_FRESH
#define SHELL_PMAP_FRESH() ((void)0)
#endif
#ifndef SHELL_PMAP_MEMO_HIT
#define SHELL_PMAP_MEMO_HIT() ((void)0)
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

/* One memoized union: the unordered pair {low, high}, the combining
 * function's tag and its result. A slot is used when its epoch is the pool's;
 * low is 0 for a union with the empty map. */
typedef struct {
  uint16_t low, high, result;
  uint8_t tag;
} shell_pmap_memo_entry_t;
/* The memo is divided into blocks of this many entries. A directory holds one
 * epoch byte per block: a block whose byte is not the pool's memo epoch is
 * empty, whatever its memory holds, and is zeroed when first written. So a
 * memo needs no initialization of its table, and clearing it is an epoch
 * change. */
enum { SHELL_PMAP_MEMO_BLOCK = 128 };

typedef struct {
  shell_pmap_node_t *nodes;
  /* Memo of unions, or NULL when none is attached; see shell_pmap_attach_memo.
   * Cleared by every sweep and rollback. */
  shell_pmap_memo_entry_t *memo;
  uint8_t *memo_blocks;
  uint32_t memo_size, memo_used;
  uint8_t memo_epoch;
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

static SHELL_NONNULL(1) inline void shell_pmap_memo_clear(
    shell_pmap_pool_t *pool) {
  if (pool->memo && ++pool->memo_epoch == 0) {
    /* The epoch wrapped: blocks of 255 clears ago look current again. */
    memset(pool->memo_blocks, 0,
           (size_t)((pool->memo_size + SHELL_PMAP_MEMO_BLOCK - 1) /
                    SHELL_PMAP_MEMO_BLOCK));
    pool->memo_epoch = 1;
  }
  pool->memo_used = 0;
}

/* Give the pool a union memo of size entries, any size, with a directory of
 * (size + SHELL_PMAP_MEMO_BLOCK - 1) / SHELL_PMAP_MEMO_BLOCK bytes. Only the
 * directory is initialized; size is at least 2. Every union and fold on the
 * pool shares the memo. It holds at most size / 2 entries and is cleared only
 * by a sweep or rollback. A union or fold that needs an entry once it is full
 * fails, like one that needs a node once the pool is full, so the pairs
 * computed between two clears, and with them the work, never exceed size / 2
 * however the unions are chosen. How much a sequence of unions needs is a
 * property of its callers: size is the largest sequence that is answered. */
static SHELL_NONNULL(1, 2, 4) inline void shell_pmap_attach_memo(
    shell_pmap_pool_t *pool, shell_pmap_memo_entry_t *entries, uint32_t size,
    uint8_t *blocks) {
  pool->memo = entries;
  pool->memo_blocks = blocks;
  pool->memo_size = size;
  memset(blocks, 0,
         (size_t)((size + SHELL_PMAP_MEMO_BLOCK - 1) / SHELL_PMAP_MEMO_BLOCK));
  pool->memo_epoch = 1;
  pool->memo_used = 0;
}

/* Whether the memo slot is in a block written since the last clear. */
static inline bool shell_pmap_memo_block_live(const shell_pmap_pool_t *pool,
                                              uint32_t slot) {
  return pool->memo_blocks[slot / SHELL_PMAP_MEMO_BLOCK] == pool->memo_epoch;
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
  shell_pmap_memo_clear(pool);
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
  shell_pmap_memo_clear(pool);
}

/* Union of two maps. fn(context, key, left, right) gives the value of key in
 * the result, 0 for no entry; left or right is 0 where that map has no entry
 * for key. The result is the left map's, extended: fn need not be symmetric,
 * so a representation the left operand chooses is kept. It must be
 * associative and idempotent, with fn(k, v, v) == v, and absorbing, so that
 * with r = fn(k, a, b) both fn(k, r, a) and fn(k, r, b) equal r. Both maps
 * must carry summary 0 (results do). If absent_neutral, fn(k, v, 0) == v, so a
 * subtree present on one side only is shared unchanged instead of visited.
 * Needs a memo. Returns false when the pool or the memo is full; published
 * roots stay valid. tag names the combining function's context: results are
 * shared between unions only under the same tag. */
typedef uint32_t (*shell_pmap_union_fn)(void *context, uint64_t key,
                                        uint32_t left, uint32_t right);

typedef struct {
  shell_pmap_pool_t *pool;
  shell_pmap_union_fn fn;
  void *context;
  bool absent_neutral;
  /* A fold: fn gives bits for each key the maps differ at, and the result is
   * their OR over all such keys, 0 where the maps agree. No node is made. */
  bool bits;
  /* Without the memo every pair is computed, so fn may depend on more than its
   * arguments for the one call. */
  bool nomemo;
  uint8_t tag;
} shell_pmap_union_t;

/* The home slot of a pair: the mixed key scaled into the table, so a table
 * may have any size. */
static inline uint32_t shell_pmap_memo_home(const shell_pmap_pool_t *pool,
                                            uint32_t low, uint32_t high,
                                            uint8_t tag) {
  uint32_t mixed = (uint32_t)shell_pmap_mix((uint64_t)tag << 32 |
                                            (uint64_t)low << 16 | high);
  return (uint32_t)(((uint64_t)mixed * pool->memo_size) >> 32);
}

static inline uint32_t shell_pmap_memo_next(const shell_pmap_pool_t *pool,
                                            uint32_t slot) {
  return slot + 1 == pool->memo_size ? 0 : slot + 1;
}

/* The memo is keyed on the ordered pair: orientation is the top bit of the
 * entry's tag, so tags are below 0x80. */
static SHELL_NONNULL(1, 5) inline bool shell_pmap_memo_find(
    const shell_pmap_pool_t *pool, uint32_t a, uint32_t b, uint8_t tag,
    uint32_t *result) {
  uint32_t low = a < b ? a : b, high = a < b ? b : a;
  if (a > b)
    tag |= 0x80;
  uint32_t slot = shell_pmap_memo_home(pool, low, high, tag);
  for (const shell_pmap_memo_entry_t *entry;
       shell_pmap_memo_block_live(pool, slot) &&
       (entry = &pool->memo[slot])->high;
       slot = shell_pmap_memo_next(pool, slot))
    if (entry->low == low && entry->high == high && entry->tag == tag) {
      *result = entry->result;
      return true;
    }
  return false;
}

/* Record a result. False when the memo is full: it is cleared only by a
 * sweep or rollback, so the unions between two of them compute at most
 * memo_size / 2 pairs, and a union that would compute more fails. */
static SHELL_NONNULL(1) inline bool shell_pmap_memo_put(shell_pmap_pool_t *pool,
                                                        uint32_t a, uint32_t b,
                                                        uint8_t tag,
                                                        uint32_t result) {
  uint32_t low = a < b ? a : b, high = a < b ? b : a;
  if (a > b)
    tag |= 0x80;
  uint32_t home = shell_pmap_memo_home(pool, low, high, tag);
  uint32_t slot = home;
  for (const shell_pmap_memo_entry_t *entry;
       shell_pmap_memo_block_live(pool, slot) &&
       (entry = &pool->memo[slot])->high;
       slot = shell_pmap_memo_next(pool, slot))
    if (entry->low == low && entry->high == high && entry->tag == tag)
      return true;
  if ((pool->memo_used + 1) * 2 > pool->memo_size) {
    return false;
  }
  if (!shell_pmap_memo_block_live(pool, slot)) {
    uint32_t block = slot / SHELL_PMAP_MEMO_BLOCK;
    uint32_t end = (block + 1) * SHELL_PMAP_MEMO_BLOCK;
    memset(&pool->memo[block * SHELL_PMAP_MEMO_BLOCK], 0,
           (size_t)((end < pool->memo_size ? end : pool->memo_size) -
                    block * SHELL_PMAP_MEMO_BLOCK) *
               sizeof(*pool->memo));
    pool->memo_blocks[block] = pool->memo_epoch;
  }
  pool->memo[slot] = (shell_pmap_memo_entry_t){(uint16_t)low, (uint16_t)high,
                                               (uint16_t)result, tag};
  pool->memo_used++;
  return true;
}

static SHELL_NONNULL(1, 4) bool shell_pmap_union_pair(
    const shell_pmap_union_t *u, uint32_t left, uint32_t right, uint32_t *out);

static inline bool shell_pmap_union_find(const shell_pmap_union_t *u,
                                         uint32_t left, uint32_t right,
                                         uint32_t *result) {
  return !u->nomemo &&
         shell_pmap_memo_find(u->pool, left, right, u->tag, result);
}

static inline bool shell_pmap_union_put(const shell_pmap_union_t *u,
                                        uint32_t left, uint32_t right,
                                        uint32_t result) {
  return u->nomemo || shell_pmap_memo_put(u->pool, left, right, u->tag, result);
}

/* A trie only one side has: its keys joined with the absent side, which is the
 * right operand when the trie is the left one. */
static SHELL_NONNULL(1,
                     4) bool shell_pmap_union_side(const shell_pmap_union_t *u,
                                                   uint32_t id, bool on_left,
                                                   uint32_t *out) {
  SHELL_PMAP_WORK();
  shell_pmap_pool_t *pool = u->pool;
  if (!id || u->absent_neutral) {
    *out = id;
    return true;
  }
  uint32_t cached;
  if (shell_pmap_union_find(u, on_left ? id : 0, on_left ? 0 : id, &cached)) {
    SHELL_PMAP_MEMO_HIT();
    *out = cached;
    return true;
  }
  SHELL_PMAP_FRESH();
  shell_pmap_node_t node = *shell_pmap_node(pool, id);
  uint32_t result;
  if (node.bit == SHELL_PMAP_LEAF) {
    uint32_t value = on_left ? u->fn(u->context, node.key, node.u.value, 0)
                             : u->fn(u->context, node.key, 0, node.u.value);
    result = u->bits ? value
             : value ? shell_pmap_leaf(pool, node.key, value, 0)
                     : 0;
    if (!u->bits && value && !result)
      return false;
  } else {
    uint32_t left, right;
    if (!shell_pmap_union_side(u, node.u.child.left, on_left, &left) ||
        !shell_pmap_union_side(u, node.u.child.right, on_left, &right))
      return false;
    result = u->bits ? left | right
                     : shell_pmap_branch(pool, node.key, node.bit, left, right);
    if (!u->bits && left && right && !result)
      return false;
  }
  /* The result absorbs the trie, and, joined with an absent side again, is
   * itself: (x ⊔ absent) ⊔ absent = x ⊔ absent. */
  if (!shell_pmap_union_put(u, on_left ? id : 0, on_left ? 0 : id, result))
    return false;
  if (!u->bits && result && result != id &&
      !(shell_pmap_union_put(u, result, id, result) &&
        shell_pmap_union_put(u, on_left ? result : 0, on_left ? 0 : result,
                             result)))
    return false;
  *out = result;
  return true;
}

static SHELL_NONNULL(1, 4) bool shell_pmap_union_pair(
    const shell_pmap_union_t *u, uint32_t left, uint32_t right, uint32_t *out) {
  SHELL_PMAP_WORK();
  shell_pmap_pool_t *pool = u->pool;
  if (left == right) {
    *out = u->bits ? 0 : left;
    return true;
  }
  if (!left)
    return shell_pmap_union_side(u, right, false, out);
  if (!right)
    return shell_pmap_union_side(u, left, true, out);
  uint32_t cached;
  if (shell_pmap_union_find(u, left, right, &cached)) {
    SHELL_PMAP_MEMO_HIT();
    *out = cached;
    return true;
  }
  SHELL_PMAP_FRESH();
  uint64_t lp, rp;
  int lb = shell_pmap_span(pool, left, &lp);
  int rb = shell_pmap_span(pool, right, &rp);
  shell_pmap_node_t ln = *shell_pmap_node(pool, left);
  shell_pmap_node_t rn = *shell_pmap_node(pool, right);
  uint32_t result, one, other;
  bool built = true;
  if (lb < 0 && rb < 0 && lp == rp) {
    uint32_t value = u->fn(u->context, lp, ln.u.value, rn.u.value);
    result = u->bits ? value : value ? shell_pmap_leaf(pool, lp, value, 0) : 0;
    built = u->bits || !value || result;
  } else if (lb == rb && lp == rp) {
    if (!shell_pmap_union_pair(u, ln.u.child.left, rn.u.child.left, &one) ||
        !shell_pmap_union_pair(u, ln.u.child.right, rn.u.child.right, &other))
      return false;
    result = u->bits ? one | other
                     : shell_pmap_branch(pool, lp, (unsigned)lb, one, other);
    built = u->bits || !(one && other) || result;
  } else if (lb > rb && shell_pmap_mask(rp, (unsigned)lb) == lp) {
    /* right lies within one child of left; left's other child is left only. */
    bool within_right = (rp >> (unsigned)lb) & 1;
    if (!shell_pmap_union_side(
            u, within_right ? ln.u.child.left : ln.u.child.right, true, &one) ||
        !shell_pmap_union_pair(
            u, within_right ? ln.u.child.right : ln.u.child.left, right,
            &other))
      return false;
    result = u->bits ? one | other
             : within_right
                 ? shell_pmap_branch(pool, lp, (unsigned)lb, one, other)
                 : shell_pmap_branch(pool, lp, (unsigned)lb, other, one);
    built = u->bits || !(one && other) || result;
  } else if (rb > lb && shell_pmap_mask(lp, (unsigned)rb) == rp) {
    bool within_right = (lp >> (unsigned)rb) & 1;
    if (!shell_pmap_union_side(
            u, within_right ? rn.u.child.left : rn.u.child.right, false,
            &one) ||
        !shell_pmap_union_pair(
            u, left, within_right ? rn.u.child.right : rn.u.child.left, &other))
      return false;
    result = u->bits ? one | other
             : within_right
                 ? shell_pmap_branch(pool, rp, (unsigned)rb, one, other)
                 : shell_pmap_branch(pool, rp, (unsigned)rb, other, one);
    built = u->bits || !(one && other) || result;
  } else {
    /* Disjoint key ranges: each side's keys are joined with an absent side. */
    if (!shell_pmap_union_side(u, left, true, &one) ||
        !shell_pmap_union_side(u, right, false, &other))
      return false;
    if (u->bits) {
      result = one | other;
    } else if (!one || !other) {
      result = one ? one : other;
    } else {
      uint64_t op, tp;
      (void)shell_pmap_span(pool, one, &op);
      (void)shell_pmap_span(pool, other, &tp);
      result = shell_pmap_join(pool, op, one, tp, other);
      built = result != 0;
    }
  }
  if (!built)
    return false;
  /* The result absorbs both operands: r ⊔ a = r and r ⊔ b = r. */
  if (!shell_pmap_union_put(u, left, right, result) ||
      (!u->bits && result != left &&
       !shell_pmap_union_put(u, result, left, result)) ||
      (!u->bits && result != right &&
       !shell_pmap_union_put(u, result, right, result)))
    return false;
  *out = result;
  return true;
}

static SHELL_NONNULL(1, 4, 6) inline bool shell_pmap_union(
    shell_pmap_pool_t *pool, uint32_t left, uint32_t right,
    shell_pmap_union_fn fn, void *context, uint32_t *result,
    bool absent_neutral, uint8_t tag) {
  shell_pmap_union_t u = {pool, fn, context, absent_neutral, false, false, tag};
  return shell_pmap_union_pair(&u, left, right, result);
}

/* The OR of fn(context, key, left, right) over the keys at which the two maps
 * differ, with the same convention for a key one map lacks, and 0 where they
 * agree. fn gives at most 16 bits, the width of a memoized result. Makes no
 * node. With memoize, fn must be a function of its arguments alone for one
 * tag, and the cost is that of a union: the node pairs on which the maps
 * differ, less the pairs the memo already holds. Without it, fn may read
 * whatever it needs and the cost is those node pairs. A fold creates no node;
 * with memoize it fails, leaving *bits unspecified, when the memo is full. */
static SHELL_NONNULL(1, 4, 6) inline bool shell_pmap_fold(
    shell_pmap_pool_t *pool, uint32_t left, uint32_t right,
    shell_pmap_union_fn fn, void *context, uint32_t *bits, bool memoize,
    uint8_t tag) {
  shell_pmap_union_t u = {pool, fn, context, false, true, !memoize, tag};
  return shell_pmap_union_pair(&u, left, right, bits);
}

/* Whether left and right differ in at most limit keys; *count is the number
 * seen, at most limit + 1, since the walk stops there. Costs
 * O((limit + 1)·W), so candidates can be compared without paying for a long
 * difference. */
typedef struct {
  uint32_t count, limit;
} shell_pmap_bounded_t;

static bool shell_pmap_bounded_visit(void *context, uint64_t key,
                                     shell_pmap_sides_t present, uint32_t left,
                                     uint32_t right) {
  (void)key, (void)present, (void)left, (void)right;
  shell_pmap_bounded_t *bounded = context;
  return ++bounded->count <= bounded->limit;
}

static SHELL_NONNULL(1, 5) inline bool shell_pmap_diff_within(
    const shell_pmap_pool_t *pool, uint32_t left, uint32_t right,
    uint32_t limit, uint32_t *count) {
  shell_pmap_bounded_t bounded = {0, limit};
  (void)shell_pmap_diff(pool, left, right, shell_pmap_bounded_visit, &bounded);
  *count = bounded.count;
  return bounded.count <= limit;
}

#endif
