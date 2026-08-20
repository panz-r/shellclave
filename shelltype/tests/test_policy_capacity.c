#include "shelltype.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { PREFIX_DEPTH = 128, LEAVES_PER_DEPTH = 512 };

static int make_pattern(char *buffer, size_t capacity, size_t depth,
                        size_t leaf) {
  size_t used = 0;
  if (depth > 1) {
    int written =
        depth == 2 ? snprintf(buffer, capacity, "group ")
                   : snprintf(buffer, capacity, "g%03zu ", leaf % (size_t)512);
    if (written < 0 || (size_t)written >= capacity)
      return 0;
    used = (size_t)written;
  }
  for (size_t i = 1; i + 1 < depth; i++) {
    int written = snprintf(buffer + used, capacity - used, "p%03zu ", i);
    if (written < 0 || (size_t)written >= capacity - used)
      return 0;
    used += (size_t)written;
  }
  int written =
      snprintf(buffer + used, capacity - used, "leaf%03zu_%03zu", depth, leaf);
  return written >= 0 && (size_t)written < capacity - used;
}

static int matches(st_policy_t *policy, const char *command, bool expected) {
  st_eval_result_t result = {0};
  return st_policy_eval(policy, command, &result) == ST_OK &&
         result.matches == expected;
}

static int files_equal(const char *left_path, const char *right_path) {
  FILE *left = fopen(left_path, "rb");
  FILE *right = fopen(right_path, "rb");
  if (!left || !right) {
    if (left)
      fclose(left);
    if (right)
      fclose(right);
    return 0;
  }
  unsigned char left_buffer[8192], right_buffer[8192];
  int equal = 1;
  for (;;) {
    size_t left_count = fread(left_buffer, 1, sizeof(left_buffer), left);
    size_t right_count = fread(right_buffer, 1, sizeof(right_buffer), right);
    if (left_count != right_count ||
        memcmp(left_buffer, right_buffer, left_count) != 0) {
      equal = 0;
      break;
    }
    if (left_count < sizeof(left_buffer)) {
      equal = feof(left) && feof(right) && !ferror(left) && !ferror(right);
      break;
    }
  }
  if (fclose(left) != 0 || fclose(right) != 0)
    equal = 0;
  return equal;
}

static int nfa_ids_cover_capacity(const char *path, uint32_t base,
                                  const char *first, const char *middle,
                                  const char *last) {
  FILE *file = fopen(path, "r");
  if (!file)
    return 0;
  bool *seen = calloc(ST_MAX_POLICY_PATTERNS, sizeof(*seen));
  if (!seen) {
    fclose(file);
    return 0;
  }
  char line[ST_MAX_PATTERN_LEN + 128];
  size_t id_count = 0, tag_count = 0;
  bool saw_first = false, saw_middle = false, saw_last = false;
  uint32_t current_id = 0;
  while (fgets(line, sizeof(line), file)) {
    (void)sscanf(line, " PatternId: %u", &current_id);
    if (strstr(line, "EosTarget: yes")) {
      if (current_id < base || current_id - base >= ST_MAX_POLICY_PATTERNS ||
          seen[current_id - base]) {
        free(seen);
        fclose(file);
        return 0;
      }
      seen[current_id - base] = true;
      id_count++;
    }
    if (strstr(line, "Tags: ")) {
      tag_count++;
      saw_first = saw_first || strstr(line, first) != NULL;
      saw_middle = saw_middle || strstr(line, middle) != NULL;
      saw_last = saw_last || strstr(line, last) != NULL;
    }
  }
  int valid = fclose(file) == 0 && id_count == ST_MAX_POLICY_PATTERNS &&
              tag_count == ST_MAX_POLICY_PATTERNS && saw_first && saw_middle &&
              saw_last;
  for (size_t i = 0; i < ST_MAX_POLICY_PATTERNS; i++)
    valid = valid && seen[i];
  free(seen);
  return valid;
}

int main(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  char pattern[ST_MAX_PATTERN_LEN];
  if (!ctx || !policy)
    return 1;

  size_t added = 0;
  for (size_t depth = 1; depth <= PREFIX_DEPTH; depth++) {
    size_t leaves =
        depth == PREFIX_DEPTH ? LEAVES_PER_DEPTH - 1 : LEAVES_PER_DEPTH;
    for (size_t leaf = 0; leaf < leaves; leaf++) {
      if (!make_pattern(pattern, sizeof(pattern), depth, leaf) ||
          st_policy_add(policy, pattern) != ST_OK)
        return 1;
      added++;
    }
  }
  if (added != ST_MAX_POLICY_PATTERNS || st_policy_count(policy) != added)
    return 1;

  if (!make_pattern(pattern, sizeof(pattern), PREFIX_DEPTH,
                    LEAVES_PER_DEPTH - 1) ||
      st_policy_add(policy, pattern) != ST_ERR_LIMIT ||
      st_policy_count(policy) != ST_MAX_POLICY_PATTERNS)
    return 1;

  char first[ST_MAX_PATTERN_LEN], middle[ST_MAX_PATTERN_LEN];
  char last[ST_MAX_PATTERN_LEN], removed[ST_MAX_PATTERN_LEN];
  if (!make_pattern(first, sizeof(first), 1, 0) ||
      !make_pattern(middle, sizeof(middle), 64, 255) ||
      !make_pattern(last, sizeof(last), PREFIX_DEPTH, LEAVES_PER_DEPTH - 2) ||
      !make_pattern(removed, sizeof(removed), 64, 256) ||
      !matches(policy, first, true) || !matches(policy, middle, true) ||
      !matches(policy, last, true))
    return 1;

  if (st_policy_remove(policy, removed) != ST_OK ||
      st_policy_count(policy) != ST_MAX_POLICY_PATTERNS - 1 ||
      !matches(policy, removed, false) ||
      st_policy_add(policy, pattern) != ST_OK ||
      st_policy_count(policy) != ST_MAX_POLICY_PATTERNS ||
      !matches(policy, pattern, true))
    return 1;

  /* Reuse tombstoned registry slots and trie paths at several depths. */
  static const size_t depths[] = {1, 64, PREFIX_DEPTH};
  for (size_t i = 0; i < sizeof(depths) / sizeof(depths[0]); i++) {
    char old_pattern[ST_MAX_PATTERN_LEN];
    char replacement[ST_MAX_PATTERN_LEN];
    size_t old_leaf = i == 2 ? LEAVES_PER_DEPTH - 2 : 100 + i;
    if (!make_pattern(old_pattern, sizeof(old_pattern), depths[i], old_leaf) ||
        !make_pattern(replacement, sizeof(replacement), depths[i],
                      LEAVES_PER_DEPTH + i) ||
        st_policy_remove(policy, old_pattern) != ST_OK ||
        st_policy_count(policy) != ST_MAX_POLICY_PATTERNS - 1 ||
        st_policy_add(policy, replacement) != ST_OK ||
        st_policy_count(policy) != ST_MAX_POLICY_PATTERNS ||
        !matches(policy, replacement, true)) {
      fprintf(stderr, "tombstone reuse failed at depth %zu (count=%zu)\n",
              depths[i], st_policy_count(policy));
      return 1;
    }
  }

  char replacement_last[ST_MAX_PATTERN_LEN];
  if (!make_pattern(replacement_last, sizeof(replacement_last), PREFIX_DEPTH,
                    LEAVES_PER_DEPTH + 2) ||
      !matches(policy, first, true) || !matches(policy, middle, true) ||
      !matches(policy, replacement_last, true))
    return 1;

  /* Exercise the complete lifecycle while the 16-bit registry is full. */
  if (st_policy_compact(policy) != ST_OK ||
      st_policy_count(policy) != ST_MAX_POLICY_PATTERNS ||
      !matches(policy, first, true) || !matches(policy, middle, true) ||
      !matches(policy, replacement_last, true))
    return 1;

  char first_save[] = "/tmp/shelltype-capacity-a-XXXXXX";
  char second_save[] = "/tmp/shelltype-capacity-b-XXXXXX";
  char nfa_path[] = "/tmp/shelltype-capacity-nfa-XXXXXX";
  int first_fd = mkstemp(first_save);
  int second_fd = mkstemp(second_save);
  int nfa_fd = mkstemp(nfa_path);
  if (first_fd < 0 || second_fd < 0 || nfa_fd < 0)
    return 1;
  close(first_fd);
  close(second_fd);
  close(nfa_fd);
  if (st_policy_save(policy, first_save) != ST_OK)
    return 1;

  st_policy_ctx_t *loaded_context = st_policy_ctx_new();
  st_policy_t *loaded = loaded_context ? st_policy_new(loaded_context) : NULL;
  if (!loaded || st_policy_load(loaded, first_save, true) != ST_OK ||
      st_policy_count(loaded) != ST_MAX_POLICY_PATTERNS ||
      !matches(loaded, first, true) || !matches(loaded, middle, true) ||
      !matches(loaded, replacement_last, true) ||
      st_policy_save(loaded, second_save) != ST_OK ||
      !files_equal(first_save, second_save))
    return 1;

  uint32_t highest_base = UINT32_MAX - (uint32_t)ST_MAX_POLICY_PATTERNS + 1u;
  st_nfa_render_opts_t options = {.category_mask = 1,
                                  .pattern_id_base = highest_base,
                                  .include_tags = true,
                                  .identifier = "capacity"};
  if (st_policy_render_nfa(loaded, nfa_path, &options) != ST_OK ||
      !nfa_ids_cover_capacity(nfa_path, highest_base, first, middle,
                              replacement_last))
    return 1;
  options.pattern_id_base++;
  if (st_policy_render_nfa(loaded, nfa_path, &options) != ST_ERR_LIMIT)
    return 1;

  st_policy_free(loaded);
  st_policy_ctx_free(loaded_context);
  if (unlink(first_save) != 0 || unlink(second_save) != 0 ||
      unlink(nfa_path) != 0)
    return 1;

  /* Capacity checks must account for the narrower rules removed by a broader
   * insertion. All 512 two-token rules are replaced by one rule. */
  st_error_t broad_result = st_policy_add(policy, "group *");
  if (broad_result != ST_OK ||
      st_policy_count(policy) != ST_MAX_POLICY_PATTERNS - 511 ||
      !matches(policy, "group any-value", true)) {
    fprintf(stderr, "broad insertion failed: error=%d count=%zu\n",
            broad_result, st_policy_count(policy));
    return 1;
  }

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  puts("policy capacity: boundary, tombstone reuse, and subsumption passed");
  return 0;
}
