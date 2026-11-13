#include "shell_avl_index_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The index is checked against a sorted reference under random insertions
 * and erasures, and for its failure-atomic capacity contract. */

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

static SHELL_NONNULL(1, 3) int compare_values(const void *context,
                                              uint32_t member,
                                              const void *key) {
  const uint32_t *values = context;
  uint32_t candidate = *(const uint32_t *)key;
  return values[member] < candidate ? -1 : values[member] > candidate;
}

/* A full index still finds existing keys, and a failed insertion leaves the
 * root, links and heights unchanged. */
static void test_capacity_is_failure_atomic(void) {
  shell_avl_node_t nodes[3] = {{0}};
  const uint32_t values[] = {20, 10, 30};
  uint32_t root = 0;
  bool valid = true;
  for (uint32_t candidate = 1; candidate <= 3; candidate++) {
    uint32_t match = 0;
    root = shell_avl_insert(nodes, root, candidate, 3, compare_values, values,
                            &values[candidate - 1], &match);
    valid &= match == candidate;
  }
  shell_avl_node_t expected[3];
  memcpy(expected, nodes, sizeof(expected));
  uint32_t expected_root = root;
  const uint32_t missing[] = {5, 40};
  for (size_t i = 0; i < sizeof(missing) / sizeof(missing[0]); i++) {
    uint32_t match = 0;
    uint32_t unchanged = shell_avl_insert(nodes, root, 4, 3, compare_values,
                                          values, &missing[i], &match);
    valid &= unchanged == expected_root && match == 0 &&
             memcmp(nodes, expected, sizeof(nodes)) == 0;
  }
  for (uint32_t member = 0; member < 3; member++) {
    uint32_t match = 0;
    uint32_t unchanged = shell_avl_insert(nodes, root, 4, 3, compare_values,
                                          values, &values[member], &match);
    valid &= unchanged == expected_root && match == member + 1 &&
             memcmp(nodes, expected, sizeof(nodes)) == 0;
  }
  TEST("capacity is failure-atomic", valid);
}

enum { RECORDS = 512 };

/* In-order walk into out; returns false on an order or balance violation. */
static bool check_tree(const shell_avl_node_t *nodes, const uint32_t *values,
                       uint32_t root, uint32_t *out, uint32_t *count,
                       unsigned *height) {
  if (!root) {
    *height = 0;
    return true;
  }
  const shell_avl_node_t *node = &nodes[root - 1];
  unsigned left = 0, right = 0;
  if (!check_tree(nodes, values, node->left, out, count, &left))
    return false;
  if (*count && values[out[*count - 1]] >= values[root - 1])
    return false;
  out[(*count)++] = root - 1;
  if (!check_tree(nodes, values, node->right, out, count, &right))
    return false;
  *height = 1 + (left > right ? left : right);
  int balance = (int)left - (int)right;
  return node->height == *height && balance >= -1 && balance <= 1;
}

static void test_matches_reference(void) {
  static shell_avl_node_t nodes[RECORDS];
  static uint32_t values[RECORDS];
  static bool present[1024];
  static uint32_t order[RECORDS];
  bool valid = true;
  for (unsigned round = 0; valid && round < 64; round++) {
    memset(nodes, 0, sizeof(nodes));
    memset(present, 0, sizeof(present));
    uint32_t root = 0, used = 0;
    for (unsigned step = 0; valid && step < 4 * RECORDS; step++) {
      uint32_t key = (uint32_t)(next() % 1024);
      if (next() % 3 == 0 && present[key]) {
        root = shell_avl_erase(nodes, root, compare_values, values, &key);
        present[key] = false;
      } else {
        uint32_t match = 0;
        if (used < RECORDS)
          values[used] = key;
        root = shell_avl_insert(nodes, root, used + 1, RECORDS, compare_values,
                                values, &key, &match);
        if (present[key])
          valid &= match && values[match - 1] == key;
        else if (used < RECORDS) {
          valid &= match == used + 1;
          present[key] = true;
          used++;
        } else
          valid &= match == 0;
      }
      uint32_t count = 0;
      unsigned height = 0;
      valid &= check_tree(nodes, values, root, order, &count, &height);
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

int main(void) {
  printf("avl index\n");
  test_capacity_is_failure_atomic();
  test_matches_reference();
  printf("%d passed, %d failed\n", passed, failed);
  return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
