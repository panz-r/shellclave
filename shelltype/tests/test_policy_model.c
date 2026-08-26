#define _POSIX_C_SOURCE 200809L

#include "shelltype.h"
#include "test_netargv.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool pattern_is_cpl(const char *actual, const char *cpl) {
  if (!actual || !cpl)
    return actual == cpl;
  char *encoded = NULL;
  bool equal = st_netpattern_from_cpl(cpl, &encoded) == ST_OK &&
               strcmp(actual, encoded) == 0;
  free(encoded);
  return equal;
}

static const char *const patterns[] = {
    "git status",
    "docker ps",
    "copy #duration.ms",
    "copy #duration.s",
    "copy #duration",
    "container #uuid.v4",
    "container #uuid.v5",
    "container #uuid",
    "run #size.MiB",
    "run #size.GiB",
    "run #size",
    "echo *",
    "net #i",
    "net #ipv6",
    "net #ipaddr",
    "option #sopt",
    "option #lopt",
    "option #opt",
    "scalar #n",
    "scalar #uuid",
    "scalar #val",
    "locate #p",
    "locate #r",
    "locate #path",
    "word #method",
    "word #hyp",
    "word #w",
};

static const char *const probes[] = {
    "git status",
    "docker ps",
    "copy 10ms",
    "copy 2s",
    "copy 3h",
    "container 550e8400-e29b-41d4-a716-446655440000",
    "container 550e8400-e29b-51d4-a716-446655440000",
    "run 12MiB",
    "run 2GiB",
    "run 4KB",
    "echo anything",
    "unknown command",
    "net 192.168.1.1",
    "net 2001:db8::1",
    "option -v",
    "option --verbose",
    "scalar 42",
    "scalar 550e8400-e29b-41d4-a716-446655440000",
    "locate /tmp/file",
    "locate src/main.c",
    "word GET",
    "word feature-flag",
};

static uint32_t random_next(uint32_t *state) {
  *state = *state * UINT32_C(1664525) + UINT32_C(1013904223);
  return *state;
}

#define PROBE_BIT(index) (UINT64_C(1) << (index))

/* A closed, hand-authored semantic domain for an independent matcher oracle.
 * The masks deliberately do not use normalization, the lattice tables, or
 * either production matcher.  The probe set contains every equivalence class
 * distinguished by these patterns, so set inclusion is also the subsumption
 * relation within this model. */
static const char *const cross_probes[] = {
    "mix /tmp/a 42",
    "mix /tmp/a 7",
    "mix /tmp/b 7",
    "mix /tmp/b 42",
    "mix ../relative 42",
    "mix file.txt 9",
    "mix /tmp/a 550e8400-e29b-41d4-a716-446655440000",
    "mix 550e8400-e29b-41d4-a716-446655440000 42",
    "mix 42 word",
    "mix word 42",
    "mix 7 other",
    "mix 42 7",
    "id 550e8400-e29b-41d4-a716-446655440000 1MiB",
    "id 550e8400-e29b-51d4-a716-446655440000 2MiB",
    "id 123e4567-e89b-42d3-a456-426614174000 3GiB",
    "id 123e4567-e89b-52d3-a456-426614174000 4GiB",
    "id 6ba7b810-9dad-41d1-80b4-00c04fd430c8 5KB",
    "id 550e8400-e29b-31d4-a716-446655440000 6MiB",
};

typedef struct {
  const char *pattern;
  uint64_t matches;
} reference_pattern_t;

static const reference_pattern_t cross_patterns[] = {
    {"mix /tmp/a 42", PROBE_BIT(0)},
    {"mix /tmp/a #n", PROBE_BIT(0) | PROBE_BIT(1)},
    {"mix #p 42", PROBE_BIT(0) | PROBE_BIT(3)},
    {"mix #p #n", PROBE_BIT(0) | PROBE_BIT(1) | PROBE_BIT(2) | PROBE_BIT(3)},
    {"mix #path #n", PROBE_BIT(0) | PROBE_BIT(1) | PROBE_BIT(2) | PROBE_BIT(3) |
                         PROBE_BIT(4) | PROBE_BIT(5)},
    {"mix #p #val",
     PROBE_BIT(0) | PROBE_BIT(1) | PROBE_BIT(2) | PROBE_BIT(3) | PROBE_BIT(6)},
    {"mix #path #val", PROBE_BIT(0) | PROBE_BIT(1) | PROBE_BIT(2) |
                           PROBE_BIT(3) | PROBE_BIT(4) | PROBE_BIT(5) |
                           PROBE_BIT(6)},
    {"mix * 42",
     PROBE_BIT(0) | PROBE_BIT(3) | PROBE_BIT(4) | PROBE_BIT(7) | PROBE_BIT(9)},
    {"mix 42 *", PROBE_BIT(8) | PROBE_BIT(11)},
    {"mix #n *", PROBE_BIT(8) | PROBE_BIT(10) | PROBE_BIT(11)},
    {"mix * #n", PROBE_BIT(0) | PROBE_BIT(1) | PROBE_BIT(2) | PROBE_BIT(3) |
                     PROBE_BIT(4) | PROBE_BIT(5) | PROBE_BIT(7) | PROBE_BIT(9) |
                     PROBE_BIT(11)},
    {"id #uuid.v4 #size.MiB", PROBE_BIT(12)},
    {"id #uuid.v5 #size.MiB", PROBE_BIT(13)},
    {"id #uuid.v4 #size.GiB", PROBE_BIT(14)},
    {"id #uuid #size", PROBE_BIT(12) | PROBE_BIT(13) | PROBE_BIT(14) |
                           PROBE_BIT(15) | PROBE_BIT(16) | PROBE_BIT(17)},
    {"id #uuid.v4 #size", PROBE_BIT(12) | PROBE_BIT(14) | PROBE_BIT(16)},
    {"id #uuid #size.MiB", PROBE_BIT(12) | PROBE_BIT(13) | PROBE_BIT(17)},
};

static bool reference_subsumes(size_t wider, size_t narrower) {
  return (cross_patterns[narrower].matches & ~cross_patterns[wider].matches) ==
         0;
}

static void reference_add(bool *active, size_t index) {
  for (size_t i = 0; i < sizeof(cross_patterns) / sizeof(cross_patterns[0]);
       i++)
    if (active[i] && reference_subsumes(i, index))
      return;
  for (size_t i = 0; i < sizeof(cross_patterns) / sizeof(cross_patterns[0]);
       i++)
    if (active[i] && reference_subsumes(index, i))
      active[i] = false;
  active[index] = true;
}

static const char *reference_selected(const bool *active, size_t probe) {
  const char *selected = NULL;
  size_t selected_index = 0;
  for (size_t i = 0; i < sizeof(cross_patterns) / sizeof(cross_patterns[0]);
       i++) {
    if (!active[i] || !(cross_patterns[i].matches & PROBE_BIT(probe)))
      continue;
    if (!selected) {
      selected = cross_patterns[i].pattern;
      selected_index = i;
      continue;
    }
    bool selected_covers_candidate = reference_subsumes(selected_index, i);
    bool candidate_covers_selected = reference_subsumes(i, selected_index);
    if ((selected_covers_candidate != candidate_covers_selected &&
         selected_covers_candidate) ||
        (selected_covers_candidate == candidate_covers_selected &&
         strcmp(cross_patterns[i].pattern, selected) < 0)) {
      selected = cross_patterns[i].pattern;
      selected_index = i;
    }
  }
  return selected;
}

static int cross_policy_matches_model(st_policy_t *actual, const bool *active,
                                      uint32_t seed, size_t step) {
  size_t expected_policy_count = 0;
  for (size_t i = 0; i < sizeof(cross_patterns) / sizeof(cross_patterns[0]);
       i++)
    expected_policy_count += active[i] ? 1u : 0u;
  if (st_policy_rule_count(actual) != expected_policy_count)
    return 0;

  for (size_t probe = 0; probe < sizeof(cross_probes) / sizeof(cross_probes[0]);
       probe++) {
    size_t expected_match_count = 0;
    for (size_t i = 0; i < sizeof(cross_patterns) / sizeof(cross_patterns[0]);
         i++)
      expected_match_count +=
          active[i] && (cross_patterns[i].matches & PROBE_BIT(probe)) ? 1u : 0u;
    const char *selected = reference_selected(active, probe);
    st_eval_result_t result = {0};
    if (test_st_policy_eval(actual, cross_probes[probe], &result) != ST_OK ||
        result.matches != (selected != NULL) ||
        ((result.matching_pattern == NULL) != (selected == NULL)) ||
        (selected && !pattern_is_cpl(result.matching_pattern, selected))) {
      fprintf(stderr, "cross seed %u step %zu probe %zu: eval differs\n", seed,
              step, probe);
      fprintf(stderr, "  actual=%s expected=%s\n",
              result.matching_pattern ? result.matching_pattern : "(none)",
              selected ? selected : "(none)");
      return 0;
    }

    const char **matches = NULL;
    size_t match_count = 0;
    if (test_st_policy_verify_all(actual, cross_probes[probe], &matches,
                                  &match_count) != ST_OK ||
        match_count != expected_match_count) {
      st_policy_matches_free(matches);
      return 0;
    }
    for (size_t i = 0; i < sizeof(cross_patterns) / sizeof(cross_patterns[0]);
         i++) {
      if (!active[i] || !(cross_patterns[i].matches & PROBE_BIT(probe)))
        continue;
      bool found = false;
      for (size_t j = 0; j < match_count; j++)
        found = found || pattern_is_cpl(matches[j], cross_patterns[i].pattern);
      if (!found) {
        st_policy_matches_free(matches);
        return 0;
      }
    }
    st_policy_matches_free(matches);
  }
  return 1;
}

static int run_cross_policy_model(const char *replace_path,
                                  const char *append_path) {
  for (uint32_t seed = 1; seed <= 8; seed++) {
    st_policy_ctx_t *actual_ctx = st_policy_ctx_new();
    st_policy_t *actual = actual_ctx ? st_policy_new(actual_ctx) : NULL;
    bool active[sizeof(cross_patterns) / sizeof(cross_patterns[0])] = {false};
    uint32_t state = seed * UINT32_C(17);
    if (!actual_ctx || !actual)
      return 0;

    for (size_t step = 0; step < 256; step++) {
      size_t index = random_next(&state) %
                     (sizeof(cross_patterns) / sizeof(cross_patterns[0]));
      size_t second = random_next(&state) %
                      (sizeof(cross_patterns) / sizeof(cross_patterns[0]));
      uint32_t operation = random_next(&state) % 9;
      if (operation <= 1) {
        if (test_st_policy_add(actual, cross_patterns[index].pattern) != ST_OK)
          return 0;
        reference_add(active, index);
      } else if (operation == 2) {
        if (test_st_policy_remove(actual, cross_patterns[index].pattern) !=
            ST_OK)
          return 0;
        active[index] = false;
      } else if (operation == 3) {
        const char *batch[] = {cross_patterns[index].pattern,
                               cross_patterns[second].pattern};
        if (test_st_policy_batch_add(actual, batch, 2) != ST_OK)
          return 0;
        reference_add(active, index);
        reference_add(active, second);
      } else if (operation == 4) {
        if (st_policy_compact(actual) != ST_OK)
          return 0;
      } else if (operation == 5) {
        if (st_policy_save(actual, replace_path) != ST_OK ||
            st_policy_load(actual, replace_path, true) != ST_OK)
          return 0;
      } else if (operation == 6 && (random_next(&state) & 7u) == 0) {
        if (st_policy_clear(actual) != ST_OK)
          return 0;
        memset(active, 0, sizeof(active));
      } else {
        st_policy_ctx_t *source_ctx = st_policy_ctx_new();
        st_policy_t *source = source_ctx ? st_policy_new(source_ctx) : NULL;
        if (!source ||
            test_st_policy_add(source, cross_patterns[index].pattern) !=
                ST_OK ||
            test_st_policy_add(source, cross_patterns[second].pattern) != ST_OK)
          return 0;
        st_error_t err;
        if (operation == 7) {
          err = st_policy_merge(actual, source);
        } else {
          err = st_policy_save(source, append_path);
          if (err == ST_OK)
            err = st_policy_load(actual, append_path, false);
        }
        st_policy_free(source);
        st_policy_ctx_release(source_ctx);
        if (err != ST_OK)
          return 0;
        reference_add(active, index);
        reference_add(active, second);
      }

      if (!cross_policy_matches_model(actual, active, seed, step))
        return 0;
    }
    st_policy_free(actual);
    st_policy_ctx_release(actual_ctx);
  }
  return 1;
}

static int family(size_t index) {
  if (index >= 2 && index <= 4)
    return 1;
  if (index >= 5 && index <= 7)
    return 2;
  if (index >= 8 && index <= 10)
    return 3;
  if (index >= 12 && index <= 14)
    return 4;
  if (index >= 15 && index <= 17)
    return 5;
  if (index >= 18 && index <= 20)
    return 6;
  if (index >= 21 && index <= 23)
    return 7;
  if (index >= 24 && index <= 26)
    return 8;
  return 0;
}

static bool is_generic(size_t index) {
  return index == 4 || index == 7 || index == 10 || index == 14 ||
         index == 17 || index == 20 || index == 23 || index == 26;
}

static void model_add(bool *active, size_t index) {
  int group = family(index);
  if (group != 0 && !is_generic(index)) {
    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
      if (active[i] && family(i) == group && is_generic(i))
        return;
  }
  if (group != 0 && is_generic(index))
    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
      if (family(i) == group)
        active[i] = false;
  active[index] = true;
}

static const char *expected_pattern(const bool *active, size_t probe) {
  static const int specific[] = {0,  1,  2,  3,  -1, 5,  6,  8,  9,  -1, 11,
                                 -1, 12, 13, 15, 16, 18, 19, 21, 22, 24, 25};
  static const int generic[] = {-1, -1, 4,  4,  4,  7,  7,  10, 10, 10, -1,
                                -1, 14, 14, 17, 17, 20, 20, 23, 23, 26, 26};
  if (specific[probe] >= 0 && active[specific[probe]])
    return patterns[specific[probe]];
  if (generic[probe] >= 0 && active[generic[probe]])
    return patterns[generic[probe]];
  return NULL;
}

static int policy_matches_model(st_policy_t *actual, const bool *active,
                                uint32_t seed, size_t step) {
  size_t expected_count = 0;
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
    expected_count += active[i] ? 1 : 0;
  if (st_policy_rule_count(actual) != expected_count) {
    fprintf(stderr, "seed %u step %zu: count differs (%zu != %zu)\n", seed,
            step, st_policy_rule_count(actual), expected_count);
    return 0;
  }
  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
    const char *expected = expected_pattern(active, i);
    st_eval_result_t result = {0};
    if (test_st_policy_eval(actual, probes[i], &result) != ST_OK ||
        result.matches != (expected != NULL) ||
        ((result.matching_pattern == NULL) != (expected == NULL)) ||
        (expected && !pattern_is_cpl(result.matching_pattern, expected))) {
      fprintf(stderr, "seed %u step %zu probe %zu: evaluation differs\n", seed,
              step, i);
      fprintf(stderr, "  actual=%s expected=%s\n",
              result.matching_pattern ? result.matching_pattern : "(none)",
              expected ? expected : "(none)");
      return 0;
    }
    const char **matches = NULL;
    size_t match_count = 0;
    if (test_st_policy_verify_all(actual, probes[i], &matches, &match_count) !=
            ST_OK ||
        match_count != (expected ? 1u : 0u) ||
        (expected && !pattern_is_cpl(matches[0], expected))) {
      st_policy_matches_free(matches);
      return 0;
    }
    st_policy_matches_free(matches);
  }
  return 1;
}

int main(void) {
  char path[] = "/tmp/shelltype-model-XXXXXX";
  int fd = mkstemp(path);
  if (fd < 0 || close(fd) != 0)
    return 1;
  char append_path[] = "/tmp/shelltype-cross-model-XXXXXX";
  fd = mkstemp(append_path);
  if (fd < 0 || close(fd) != 0) {
    unlink(path);
    return 1;
  }

  for (uint32_t seed = 1; seed <= 8; seed++) {
    st_policy_ctx_t *actual_ctx = st_policy_ctx_new();
    st_policy_t *actual = actual_ctx ? st_policy_new(actual_ctx) : NULL;
    bool active[sizeof(patterns) / sizeof(patterns[0])] = {false};
    uint32_t state = seed;
    if (!actual_ctx || !actual)
      return 1;

    for (size_t step = 0; step < 256; step++) {
      size_t index =
          random_next(&state) % (sizeof(patterns) / sizeof(patterns[0]));
      uint32_t operation = random_next(&state) % 7;
      switch (operation) {
      case 0:
      case 1:
        if (test_st_policy_add(actual, patterns[index]) != ST_OK)
          return 1;
        model_add(active, index);
        break;
      case 2:
        if (test_st_policy_remove(actual, patterns[index]) != ST_OK)
          return 1;
        active[index] = false;
        break;
      case 3: {
        size_t second =
            random_next(&state) % (sizeof(patterns) / sizeof(patterns[0]));
        const char *batch[] = {patterns[index], patterns[second]};
        if (test_st_policy_batch_add(actual, batch, 2) != ST_OK)
          return 1;
        model_add(active, index);
        model_add(active, second);
        break;
      }
      case 4:
        if (st_policy_compact(actual) != ST_OK)
          return 1;
        break;
      case 5:
        if (st_policy_save(actual, path) != ST_OK ||
            st_policy_load(actual, path, true) != ST_OK)
          return 1;
        break;
      case 6:
        if ((random_next(&state) & 15u) == 0) {
          if (st_policy_clear(actual) != ST_OK)
            return 1;
          memset(active, 0, sizeof(active));
        }
        break;
      }

      if (!policy_matches_model(actual, active, seed, step))
        return 1;
    }
    st_policy_free(actual);
    st_policy_ctx_release(actual_ctx);
  }
  if (!run_cross_policy_model(path, append_path)) {
    unlink(path);
    unlink(append_path);
    return 1;
  }
  unlink(path);
  unlink(append_path);
  puts("policy models: 2 domains x 8 seeds x 256 transitions passed");
  return 0;
}
