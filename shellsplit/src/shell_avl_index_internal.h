#ifndef SHELL_AVL_INDEX_INTERNAL_H
#define SHELL_AVL_INDEX_INTERNAL_H

#include "shell_contract.h"
#include <stdbool.h>
#include <stdint.h>

/* One-based AVL links into an append-only record array. The index does not
 * own records: comparison callbacks receive the pending key separately.
 * A lookup still traverses the complete tree when candidate exceeds capacity,
 * so an existing key remains discoverable in a full index. If that lookup
 * reaches an empty link, insertion fails with match still zero and leaves the
 * root, links and heights byte-for-byte unchanged. A successful lookup or
 * insertion replaces match with the one-based record index. */
/* An index has at most UINT16_MAX records. Callers preflight bounded
 * capacities; keys remain 32-bit.
 */
typedef struct {
  uint16_t left, right;
  uint8_t height;
} __attribute__((packed)) shell_avl_node_t;
_Static_assert(sizeof(shell_avl_node_t) == 5,
               "AVL links must not carry alignment padding");

typedef int (*shell_avl_compare_t)(const void *, uint32_t, const void *);

static inline SHELL_NONNULL(1) unsigned shell_avl_height(
    const shell_avl_node_t *nodes, uint32_t root) {
  return root ? nodes[root - 1].height : 0;
}

static inline SHELL_NONNULL(1) int shell_avl_balance(shell_avl_node_t *nodes,
                                                     uint32_t root) {
  shell_avl_node_t *node = &nodes[root - 1];
  unsigned left = shell_avl_height(nodes, node->left);
  unsigned right = shell_avl_height(nodes, node->right);
  node->height = (uint8_t)(1 + (left > right ? left : right));
  return (int)left - (int)right;
}

static inline SHELL_NONNULL(1) uint32_t
    shell_avl_rotate(shell_avl_node_t *nodes, uint32_t root, bool left) {
  shell_avl_node_t *node = &nodes[root - 1];
  uint32_t next = left ? node->right : node->left;
  shell_avl_node_t *pivot = &nodes[next - 1];
  if (left) {
    node->right = pivot->left;
    pivot->left = root;
  } else {
    node->left = pivot->right;
    pivot->right = root;
  }
  shell_avl_balance(nodes, root);
  shell_avl_balance(nodes, next);
  return next;
}

static inline SHELL_NONNULL(1) uint32_t
    shell_avl_rebalance(shell_avl_node_t *nodes, uint32_t root) {
  shell_avl_node_t *node = &nodes[root - 1];
  int balance = shell_avl_balance(nodes, root);
  if (balance > 1) {
    if (shell_avl_balance(nodes, node->left) < 0)
      node->left = shell_avl_rotate(nodes, node->left, true);
    return shell_avl_rotate(nodes, root, false);
  }
  if (balance < -1) {
    if (shell_avl_balance(nodes, node->right) > 0)
      node->right = shell_avl_rotate(nodes, node->right, false);
    return shell_avl_rotate(nodes, root, true);
  }
  return root;
}

static inline SHELL_NONNULL(1, 5, 6, 7, 8) uint32_t
    shell_avl_insert(shell_avl_node_t *nodes, uint32_t root, uint32_t candidate,
                     uint32_t capacity, shell_avl_compare_t compare,
                     const void *context, const void *key, uint32_t *match) {
  if (!root) {
    if (candidate > capacity)
      return 0;
    *match = candidate;
    nodes[candidate - 1] = (shell_avl_node_t){.height = 1};
    return candidate;
  }
  int order = compare(context, root - 1, key);
  if (!order) {
    *match = root;
    return root;
  }
  shell_avl_node_t *node = &nodes[root - 1];
  uint32_t child =
      shell_avl_insert(nodes, order > 0 ? node->left : node->right, candidate,
                       capacity, compare, context, key, match);
  if (!*match)
    return root;
  if (order > 0)
    node->left = (uint16_t)child;
  else
    node->right = (uint16_t)child;
  return shell_avl_rebalance(nodes, root);
}

/* Remove a known member without moving record identities. The caller keeps
 * record keys unchanged until removal completes. Both helpers receive a
 * nonempty subtree; erase's key is present in that subtree. */
static inline SHELL_NONNULL(1, 3) uint32_t
    shell_avl_extract_first(shell_avl_node_t *nodes, uint32_t root,
                            uint32_t *first) {
  shell_avl_node_t *node = &nodes[root - 1];
  if (!node->left) {
    *first = root;
    return node->right;
  }
  node->left = shell_avl_extract_first(nodes, node->left, first);
  return shell_avl_rebalance(nodes, root);
}

static inline SHELL_NONNULL(1, 3, 4, 5) uint32_t
    shell_avl_erase(shell_avl_node_t *nodes, uint32_t root,
                    shell_avl_compare_t compare, const void *context,
                    const void *key) {
  shell_avl_node_t *node = &nodes[root - 1];
  int order = compare(context, root - 1, key);
  if (order > 0)
    node->left = shell_avl_erase(nodes, node->left, compare, context, key);
  else if (order < 0)
    node->right = shell_avl_erase(nodes, node->right, compare, context, key);
  else {
    if (!node->left)
      return node->right;
    if (!node->right)
      return node->left;
    uint32_t first = 0;
    uint32_t right = shell_avl_extract_first(nodes, node->right, &first);
    nodes[first - 1].left = node->left;
    nodes[first - 1].right = right;
    root = first;
  }
  return shell_avl_rebalance(nodes, root);
}

#endif
