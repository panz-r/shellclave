#include "../../tests/atomic_file_fixture.h"
#include "shelltype.h"
#include "test_netargv.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { GROUP_COUNT = 256, LEAVES_PER_GROUP = 256 };

static int make_pattern(char *buffer, size_t capacity, size_t group,
                        size_t leaf) {
  int written = snprintf(buffer, capacity, "group%03zu leaf%03zu", group, leaf);
  return written >= 0 && (size_t)written < capacity;
}

static SHELL_NONNULL(1) void report_error(const char *operation,
                                          st_error_t error) {
  int error_number = errno;
  fprintf(stderr, "%s failed: %s (error=%d)", operation, st_error_string(error),
          error);
  if (error == ST_ERR_IO)
    fprintf(stderr, " errno=%d (%s)", error_number, strerror(error_number));
  fputc('\n', stderr);
}

static int matches(st_policy_t *policy, const char *command, bool expected) {
  st_eval_result_t result = {0};
  return test_st_policy_eval(policy, command, &result) == ST_OK &&
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
  int left_closed = fclose(left);
  int right_closed = fclose(right);
  if (left_closed != 0 || right_closed != 0)
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
  char line[ST_MAX_NETPATTERN_LEN + 128];
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
  int status = 1;
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  st_policy_ctx_t *loaded_context = NULL;
  st_policy_t *loaded = NULL;
  char directory[PATH_MAX], paths[3][PATH_MAX];
  char *first_save = paths[0], *second_save = paths[1], *nfa_path = paths[2];
  bool directory_created = false;
  char pattern[ST_MAX_NETPATTERN_LEN];
  if (!ctx || !policy) {
    fprintf(stderr, "policy allocation failed\n");
    goto cleanup;
  }

  /* The full-capacity NFA is much larger than the saved policies. Keep every
   * fixture in one private directory and honor the caller's storage choice. */
  const char *temporary_root = getenv("TMPDIR");
  if (!temporary_root || !temporary_root[0])
    temporary_root = "/tmp";
  int written = snprintf(directory, sizeof(directory),
                         "%s/shelltype-capacity-XXXXXX", temporary_root);
  if (written < 0 || (size_t)written >= sizeof(directory)) {
    fprintf(stderr, "capacity fixture directory path is too long\n");
    goto cleanup;
  }
  if (!mkdtemp(directory)) {
    perror("capacity fixture directory creation failed");
    goto cleanup;
  }
  directory_created = true;
  static const char *const filenames[] = {"first.policy", "second.policy",
                                          "policy.nfa"};
  for (size_t i = 0; i < sizeof(filenames) / sizeof(*filenames); ++i) {
    written =
        snprintf(paths[i], sizeof(paths[i]), "%s/%s", directory, filenames[i]);
    if (written < 0 || (size_t)written >= sizeof(paths[i])) {
      fprintf(stderr, "capacity fixture file path is too long\n");
      goto cleanup;
    }
  }

  size_t added = 0;
  for (size_t group = 0; group < GROUP_COUNT; group++) {
    size_t leaves =
        group + 1 == GROUP_COUNT ? LEAVES_PER_GROUP - 1 : LEAVES_PER_GROUP;
    for (size_t leaf = 0; leaf < leaves; leaf++) {
      if (!make_pattern(pattern, sizeof(pattern), group, leaf) ||
          test_st_policy_add(policy, pattern) != ST_OK) {
        fprintf(stderr, "initial add failed group=%zu leaf=%zu\n", group, leaf);
        goto cleanup;
      }
      added++;
    }
  }
  if (added != ST_MAX_POLICY_PATTERNS ||
      st_policy_rule_count(policy) != added) {
    fprintf(stderr, "initial count failed: %zu/%zu\n", added,
            st_policy_rule_count(policy));
    goto cleanup;
  }

  if (!make_pattern(pattern, sizeof(pattern), GROUP_COUNT - 1,
                    LEAVES_PER_GROUP - 1) ||
      test_st_policy_add(policy, pattern) != ST_ERR_LIMIT ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS) {
    fprintf(stderr, "capacity limit check failed\n");
    goto cleanup;
  }

  char first[ST_MAX_NETPATTERN_LEN], middle[ST_MAX_NETPATTERN_LEN];
  char last[ST_MAX_NETPATTERN_LEN], removed[ST_MAX_NETPATTERN_LEN];
  if (!make_pattern(first, sizeof(first), 0, 0) ||
      !make_pattern(middle, sizeof(middle), GROUP_COUNT / 2,
                    LEAVES_PER_GROUP / 2) ||
      !make_pattern(last, sizeof(last), GROUP_COUNT - 1,
                    LEAVES_PER_GROUP - 2) ||
      !make_pattern(removed, sizeof(removed), GROUP_COUNT / 2,
                    LEAVES_PER_GROUP / 2 + 1) ||
      !matches(policy, first, true) || !matches(policy, middle, true) ||
      !matches(policy, last, true)) {
    fprintf(stderr, "initial match check failed\n");
    goto cleanup;
  }

  if (test_st_policy_remove(policy, removed) != ST_OK ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS - 1 ||
      !matches(policy, removed, false) ||
      test_st_policy_add(policy, pattern) != ST_OK ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS ||
      !matches(policy, pattern, true)) {
    fprintf(stderr, "remove/readd check failed\n");
    goto cleanup;
  }

  /* Reuse tombstoned registry slots across existing and new trie branches. */
  static const struct {
    size_t group;
    size_t leaf;
  } replacements[] = {{1, 100},
                      {GROUP_COUNT / 2, 100},
                      {GROUP_COUNT - 1, LEAVES_PER_GROUP - 2}};
  for (size_t i = 0; i < sizeof(replacements) / sizeof(replacements[0]); i++) {
    char old_pattern[ST_MAX_NETPATTERN_LEN];
    char replacement[ST_MAX_NETPATTERN_LEN];
    if (!make_pattern(old_pattern, sizeof(old_pattern), replacements[i].group,
                      replacements[i].leaf) ||
        !make_pattern(replacement, sizeof(replacement), GROUP_COUNT, i) ||
        test_st_policy_remove(policy, old_pattern) != ST_OK ||
        st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS - 1 ||
        test_st_policy_add(policy, replacement) != ST_OK ||
        st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS ||
        !matches(policy, replacement, true)) {
      fprintf(stderr, "tombstone reuse failed at group %zu (count=%zu)\n",
              replacements[i].group, st_policy_rule_count(policy));
      goto cleanup;
    }
  }

  char replacement_last[ST_MAX_NETPATTERN_LEN];
  if (!make_pattern(replacement_last, sizeof(replacement_last), GROUP_COUNT,
                    2) ||
      !matches(policy, first, true) || !matches(policy, middle, true) ||
      !matches(policy, replacement_last, true)) {
    fprintf(stderr, "replacement last check failed\n");
    goto cleanup;
  }

  /* Exercise the complete lifecycle while the 16-bit registry is full. */
  if (st_policy_compact(policy) != ST_OK ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS ||
      !matches(policy, first, true) || !matches(policy, middle, true) ||
      !matches(policy, replacement_last, true)) {
    fprintf(stderr, "compact check failed\n");
    goto cleanup;
  }

  st_error_t error = st_policy_save(policy, first_save);
  if (error != ST_OK) {
    report_error("first save", error);
    goto cleanup;
  }

  loaded_context = st_policy_ctx_new();
  loaded = loaded_context ? st_policy_new(loaded_context) : NULL;
  if (!loaded) {
    fprintf(stderr, "loaded policy allocation failed\n");
    goto cleanup;
  }
  error = st_policy_load(loaded, first_save, true);
  if (error != ST_OK) {
    report_error("policy load", error);
    goto cleanup;
  }
  if (st_policy_rule_count(loaded) != ST_MAX_POLICY_PATTERNS ||
      !matches(loaded, first, true) || !matches(loaded, middle, true) ||
      !matches(loaded, replacement_last, true)) {
    fprintf(stderr, "loaded policy match check failed\n");
    goto cleanup;
  }
  error = st_policy_save(loaded, second_save);
  if (error != ST_OK) {
    report_error("second save", error);
    goto cleanup;
  }
  if (!files_equal(first_save, second_save)) {
    fprintf(stderr, "load/save equivalence failed\n");
    goto cleanup;
  }

  uint32_t highest_base = UINT32_MAX - (uint32_t)ST_MAX_POLICY_PATTERNS + 1u;
  st_nfa_render_opts_t options = {.category_mask = 1,
                                  .pattern_id_base = highest_base,
                                  .include_tags = true,
                                  .identifier = "capacity"};
  error = st_policy_render_nfa(loaded, nfa_path, &options);
  if (error != ST_OK) {
    report_error("nfa render", error);
    goto cleanup;
  }
  if (!nfa_ids_cover_capacity(nfa_path, highest_base, first, middle,
                              replacement_last)) {
    fprintf(stderr, "nfa capacity check failed\n");
    goto cleanup;
  }
  options.pattern_id_base++;
  if (st_policy_render_nfa(loaded, nfa_path, &options) != ST_ERR_LIMIT) {
    fprintf(stderr, "nfa pattern id limit check failed\n");
    goto cleanup;
  }

  /* Capacity checks must account for the narrower rules removed by a broader
   * insertion. All 256 group000 rules are replaced by one rule. */
  st_error_t broad_result = test_st_policy_add(policy, "group000 *");
  if (broad_result != ST_OK ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS - 255 ||
      !matches(policy, "group000 any-value", true)) {
    fprintf(stderr, "broad insertion failed: error=%d count=%zu\n",
            broad_result, st_policy_rule_count(policy));
    goto cleanup;
  }
  if (test_st_policy_add(policy, "group000 still-covered") != ST_OK ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS - 255 ||
      test_st_policy_remove(policy, "group000 *") != ST_OK ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS - 256 ||
      test_st_policy_add(policy, "group000 restored") != ST_OK ||
      st_policy_rule_count(policy) != ST_MAX_POLICY_PATTERNS - 255 ||
      !matches(policy, "group000 restored", true)) {
    fprintf(stderr, "literal fast-path wildcard check failed\n");
    goto cleanup;
  }

  status = 0;
cleanup:
  st_policy_free(loaded);
  st_policy_ctx_release(loaded_context);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  if (directory_created && !test_atomic_cleanup_directory(directory)) {
    fprintf(stderr, "capacity fixture directory cleanup failed: %s\n",
            directory);
    status = 1;
  }
  if (status == 0)
    puts("policy capacity: boundary, tombstone reuse, and subsumption passed");
  return status;
}
