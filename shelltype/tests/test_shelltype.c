/* Core unit tests for the command policy learner. */

#define _POSIX_C_SOURCE 200809L
#include "shelltype.h"
#include "test_allocator.h"
#include "test_io.h"
#include "test_netargv.h"
#include <glob.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int tests_run;
static int tests_passed;
static int tests_failed;

static const st_suggestion_t *find_suggestion(const st_suggestion_t *items,
                                              size_t count,
                                              const char *pattern);

static int pattern_is_cpl(const char *actual, const char *cpl) {
  if (!actual || !cpl)
    return actual == cpl;
  char *encoded = NULL;
  int equal = st_netpattern_from_cpl(cpl, &encoded) == ST_OK &&
              strcmp(actual, encoded) == 0;
  free(encoded);
  return equal;
}
static char learner_temp_path[256];

static void cleanup_learner_temp_file(void) {
  if (learner_temp_path[0] != '\0') {
    (void)unlink(learner_temp_path);
    learner_temp_path[0] = '\0';
  }
}

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
    tests_run++;                                                               \
    printf("  %-38s ", #function);                                             \
    if (function()) {                                                          \
      tests_passed++;                                                          \
      printf("PASS\n");                                                        \
    } else {                                                                   \
      tests_failed++;                                                          \
      printf("FAIL\n");                                                        \
    }                                                                          \
  } while (0)

static st_node_t *find_child(st_node_t *parent, const char *token) {
  for (size_t i = 0; i < parent->num_children; i++)
    if (strcmp(parent->children[i]->token, token) == 0)
      return parent->children[i];
  return NULL;
}

static int nodes_equal(const st_node_t *a, const st_node_t *b) {
  if (!a || !b || strcmp(a->token, b->token) != 0 || a->type != b->type ||
      a->count != b->count || a->observed_types != b->observed_types ||
      a->metadata_observations != b->metadata_observations ||
      a->common_metadata != b->common_metadata ||
      a->metadata_mixed != b->metadata_mixed ||
      a->num_samples != b->num_samples || a->num_children != b->num_children)
    return 0;
  for (size_t i = 0; i < a->num_samples; i++)
    if (strcmp(a->sample_values[i], b->sample_values[i]) != 0)
      return 0;
  for (size_t i = 0; i < a->num_children; i++)
    if (!nodes_equal(a->children[i], b->children[i]))
      return 0;
  return 1;
}

static int trie_counts_equal(const st_node_t *a, const st_node_t *b) {
  if (!a || !b || strcmp(a->token, b->token) != 0 || a->type != b->type ||
      a->count != b->count || a->num_children != b->num_children)
    return 0;
  for (size_t i = 0; i < a->num_children; i++)
    if (!trie_counts_equal(a->children[i], b->children[i]))
      return 0;
  return 1;
}

static st_learner_t *baseline_learner(void) {
  st_learner_t *learner = st_learner_new(1, 0.0);
  if (!learner || test_st_feed(learner, "git status") != ST_OK ||
      test_st_feed(learner, "git log") != ST_OK) {
    st_learner_free(learner);
    return NULL;
  }
  return learner;
}

static int no_learner_save_temps(const char *path) {
  char pattern[512];
  glob_t matches = {0};
  if (snprintf(pattern, sizeof(pattern), "%s.*", path) < 0)
    return 0;
  int result = glob(pattern, 0, NULL, &matches);
  globfree(&matches);
  return result == GLOB_NOMATCH;
}

static void remove_learner_save_temps(const char *path) {
  char pattern[512];
  glob_t matches = {0};
  if (snprintf(pattern, sizeof(pattern), "%s.*", path) < 0)
    return;
  if (glob(pattern, 0, NULL, &matches) == 0)
    for (size_t i = 0; i < matches.gl_pathc; i++)
      (void)unlink(matches.gl_pathv[i]);
  globfree(&matches);
}

static int test_feed_is_atomic(void) {
  st_test_alloc_reset();
  st_learner_t *probe = baseline_learner();
  ASSERT(probe != NULL);
  st_test_alloc_reset();
  ASSERT(test_st_feed(probe, "git commit -m /tmp/message") == ST_OK);
  size_t allocations = st_test_alloc_count();
  st_learner_free(probe);
  ASSERT(allocations > 0);

  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_reset();
    st_learner_t *expected = baseline_learner();
    st_learner_t *actual = baseline_learner();
    ASSERT(expected && actual);
    st_test_alloc_fail_at(fail_at);
    st_error_t error = test_st_feed(actual, "git commit -m /tmp/message");
    st_test_alloc_reset();
    if (error == ST_ERR_MEMORY)
      ASSERT(actual->trie.total_commands == expected->trie.total_commands &&
             nodes_equal(actual->trie.root, expected->trie.root));
    else
      ASSERT(error == ST_OK && actual->trie.total_commands == 3);
    st_learner_free(expected);
    st_learner_free(actual);
  }

  st_token_array_t parsed = {0};
  ASSERT(test_st_classify("git push /tmp/repository", &parsed) == ST_OK);
  probe = baseline_learner();
  ASSERT(probe != NULL);
  st_test_alloc_reset();
  ASSERT(st_feed_parsed(probe, &parsed) == ST_OK);
  allocations = st_test_alloc_count();
  st_learner_free(probe);
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_reset();
    st_learner_t *expected = baseline_learner();
    st_learner_t *actual = baseline_learner();
    ASSERT(expected && actual);
    st_test_alloc_fail_at(fail_at);
    st_error_t error = st_feed_parsed(actual, &parsed);
    st_test_alloc_reset();
    if (error == ST_ERR_MEMORY)
      ASSERT(actual->trie.total_commands == expected->trie.total_commands &&
             nodes_equal(actual->trie.root, expected->trie.root));
    else
      ASSERT(error == ST_OK && actual->trie.total_commands == 3);
    st_learner_free(expected);
    st_learner_free(actual);
  }
  st_free_token_array(&parsed);

  st_learner_t *learner = baseline_learner();
  ASSERT(learner != NULL);
  st_token_t invalid_token = {.text = NULL, .type = ST_TYPE_WORD};
  st_token_array_t invalid = {.tokens = &invalid_token, .count = 1};
  ASSERT(st_feed_parsed(learner, &invalid) == ST_ERR_INVALID);
  invalid_token.text = "value";
  invalid_token.type = ST_TYPE_COUNT;
  ASSERT(st_feed_parsed(learner, &invalid) == ST_ERR_INVALID);
  ASSERT(learner->trie.total_commands == 2);

  learner->trie.total_commands = UINT32_MAX;
  learner->trie.root->count = UINT32_MAX;
  ASSERT(test_st_feed(learner, "git status") == ST_ERR_LIMIT);
  ASSERT(learner->trie.total_commands == UINT32_MAX &&
         learner->trie.root->count == UINT32_MAX);
  st_learner_free(learner);
  return 1;
}

static int test_expressive_literal_suggestions(void) {
  static const struct {
    const char *command;
    const char *argument;
    const char *expected_cpl;
  } cases[] = {{"space", "two words", "space \"two words\""},
               {"empty", "", "empty \"\""},
               {"hash", "#n", "hash \"#n\""},
               {"star", "*", "star \"*\""},
               {"line", "line\nfeed", "line \"line\\nfeed\""}};
  st_learner_t *learner = st_learner_new(1, 0.0);
  ASSERT(learner != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_token_t tokens[] = {
        {.text = (char *)cases[i].command, .type = ST_TYPE_LITERAL},
        {.text = (char *)cases[i].argument, .type = ST_TYPE_LITERAL}};
    st_token_array_t command = {.tokens = tokens, .count = 2};
    ASSERT(st_feed_parsed(learner, &command) == ST_OK);
  }
  size_t count = 0;
  st_suggestion_t *suggestions = st_suggest(learner, &count);
  ASSERT(suggestions != NULL && count == sizeof(cases) / sizeof(cases[0]));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    ASSERT(find_suggestion(suggestions, count, cases[i].expected_cpl));
  st_free_suggestions(suggestions, count);
  st_learner_free(learner);
  return 1;
}

static int test_compound_option_suggestion(void) {
  st_learner_t *learner = st_learner_new(2, 0.0);
  ASSERT(learner != NULL);
  ASSERT(test_st_feed(learner, "tool --output=/tmp/one") == ST_OK);
  ASSERT(test_st_feed(learner, "tool --output=/var/two") == ST_OK);
  size_t count = 0;
  st_suggestion_t *suggestions = st_suggest(learner, &count);
  ASSERT(suggestions != NULL);
  ASSERT(find_suggestion(suggestions, count, "tool --output={#p}"));
  st_free_suggestions(suggestions, count);
  st_learner_free(learner);
  return 1;
}

static int test_learner_state_transitions(void) {
  st_learner_t *learner = st_learner_new(1, 0.0);
  ASSERT(learner && learner->trie.root);
  ASSERT(learner->trie.total_commands == 0);
  ASSERT(learner->trie.root->count == 0);

  static const char *commands[] = {"git commit -m one", "git commit -m two",
                                   "git commit -m three", "git status",
                                   "git status"};
  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    ASSERT(test_st_feed(learner, commands[i]) == ST_OK);
    ASSERT(learner->trie.total_commands == i + 1);
    ASSERT(learner->trie.root->count == i + 1);
  }

  st_node_t *git = find_child(learner->trie.root, "git");
  ASSERT(git && git->count == 5);
  ASSERT(find_child(git, "commit") != NULL);
  ASSERT(find_child(git, "status") != NULL);
  ASSERT(learner->trie.total_commands == 5);

  st_token_array_t parsed = {0};
  ASSERT(test_st_classify("curl /tmp/data", &parsed) == ST_OK);
  ASSERT(st_feed_parsed(learner, &parsed) == ST_OK);
  st_free_token_array(&parsed);
  ASSERT(learner->trie.total_commands == 6);
  ASSERT(learner->trie.root->count == 6);
  ASSERT(find_child(learner->trie.root, "curl") != NULL);

  st_token_t too_many_tokens[ST_MAX_CMD_TOKENS + 1];
  for (size_t i = 0; i < sizeof(too_many_tokens) / sizeof(too_many_tokens[0]);
       i++)
    too_many_tokens[i] = (st_token_t){.text = "value", .type = ST_TYPE_LITERAL};
  st_token_array_t oversized = {
      .tokens = too_many_tokens,
      .count = sizeof(too_many_tokens) / sizeof(too_many_tokens[0]),
  };
  ASSERT(st_feed_parsed(learner, &oversized) == ST_ERR_INVALID);
  ASSERT(learner->trie.total_commands == 6);
  st_learner_free(learner);
  return 1;
}

static int test_learner_input_boundaries(void) {
  st_learner_t *learner = baseline_learner();
  ASSERT(learner != NULL);
  ASSERT(test_st_feed(learner, NULL) == ST_ERR_INVALID);
  ASSERT(test_st_feed(learner, "") == ST_ERR_INVALID);
  ASSERT(test_st_feed(learner, "   ") == ST_ERR_INVALID);

  st_token_array_t empty_tokens = {0};
  ASSERT(st_feed_parsed(learner, &empty_tokens) == ST_ERR_INVALID);
  ASSERT(st_feed_parsed(NULL, &empty_tokens) == ST_ERR_INVALID);
  ASSERT(st_feed_parsed(learner, NULL) == ST_ERR_INVALID);

  char many[(ST_MAX_CMD_TOKENS + 1) * 2 + 1];
  size_t used = 0;
  for (size_t i = 0; i < ST_MAX_CMD_TOKENS + 1; i++) {
    many[used++] = 'x';
    many[used++] = ' ';
  }
  many[used - 1] = '\0';
  ASSERT(test_st_feed(learner, many) == ST_ERR_LIMIT);
  ASSERT(learner->trie.total_commands == 2);

  st_learner_t *empty = st_learner_new(5, 0.05);
  ASSERT(empty != NULL);
  size_t count = 17;
  ASSERT(st_suggest(empty, &count) == NULL && count == 0);
  count = 17;
  ASSERT(st_suggest(NULL, &count) == NULL && count == 0);
  ASSERT(st_suggest(empty, NULL) == NULL);
  ASSERT(test_st_blacklist_add(NULL, "pattern") == ST_ERR_INVALID);
  ASSERT(test_st_blacklist_add(learner, NULL) == ST_ERR_INVALID);
  ASSERT(!test_st_is_blacklisted(NULL, "pattern"));
  ASSERT(!test_st_is_blacklisted(learner, NULL));
  ASSERT(st_save(NULL, "/tmp/unused") == ST_ERR_INVALID);
  ASSERT(st_save(learner, NULL) == ST_ERR_INVALID);
  ASSERT(st_load(NULL, "/tmp/unused") == ST_ERR_INVALID);
  ASSERT(st_load(learner, NULL) == ST_ERR_INVALID);
  st_learner_free(empty);
  st_learner_free(learner);
  return 1;
}

static int test_learner_configuration_boundaries(void) {
  st_learner_t *defaults = st_learner_new(0, 0.0);
  ASSERT(defaults != NULL);
  ASSERT(defaults->min_support == ST_DEFAULT_MIN_SUPPORT);
  ASSERT(defaults->min_confidence == 0.0);
  ASSERT(defaults->max_suggestions == ST_DEFAULT_MAX_SUGGESTIONS);
  st_learner_free(defaults);

  st_learner_t *configured = st_learner_new(UINT32_MAX, 1.0);
  ASSERT(configured != NULL);
  ASSERT(configured->min_support == UINT32_MAX);
  ASSERT(configured->min_confidence == 1.0);
  ASSERT(test_st_feed(configured, "git status") == ST_OK);
  size_t count = 99;
  ASSERT(st_suggest(configured, &count) == NULL && count == 0);
  st_learner_free(configured);
  return 1;
}

typedef struct {
  const char *pattern;
  uint32_t count;
  double confidence;
} expected_suggestion_t;

static int suggestions_equal(const st_suggestion_t *actual, size_t actual_count,
                             const expected_suggestion_t *expected,
                             size_t expected_count) {
  if (!actual || actual_count != expected_count) {
    fprintf(stderr, "suggestion count: actual=%zu expected=%zu\n", actual_count,
            expected_count);
    for (size_t i = 0; actual && i < actual_count; i++)
      fprintf(stderr, "  actual[%zu]=%s (%u, %.3f)\n", i, actual[i].pattern,
              actual[i].count, actual[i].confidence);
    return 0;
  }
  for (size_t i = 0; i < expected_count; i++)
    if (!actual[i].pattern ||
        !pattern_is_cpl(actual[i].pattern, expected[i].pattern) ||
        actual[i].count != expected[i].count ||
        fabs(actual[i].confidence - expected[i].confidence) > 0.000001) {
      fprintf(stderr,
              "suggestion[%zu]: actual=%s (%u, %.3f), expected=%s "
              "(%u, %.3f)\n",
              i, actual[i].pattern ? actual[i].pattern : "(null)",
              actual[i].count, actual[i].confidence, expected[i].pattern,
              expected[i].count, expected[i].confidence);
      return 0;
    }
  return 1;
}

static int suggestion_lists_equal(const st_suggestion_t *left,
                                  size_t left_count,
                                  const st_suggestion_t *right,
                                  size_t right_count) {
  if (left_count != right_count || (left_count != 0 && (!left || !right)))
    return 0;
  for (size_t i = 0; i < left_count; i++)
    if (strcmp(left[i].pattern, right[i].pattern) != 0 ||
        left[i].count != right[i].count ||
        left[i].confidence != right[i].confidence)
      return 0;
  return 1;
}

static int suggestions_replay_exactly(const st_suggestion_t *suggestions,
                                      size_t suggestion_count,
                                      const char *const *commands,
                                      size_t command_count) {
  for (size_t suggestion = 0; suggestion < suggestion_count; suggestion++) {
    ASSERT(test_st_validate_pattern(suggestions[suggestion].pattern, NULL) ==
           ST_OK);
    ASSERT(suggestions[suggestion].confidence >= 0.0 &&
           suggestions[suggestion].confidence <= 1.0);
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
    ASSERT(policy != NULL);
    ASSERT(test_st_policy_add(policy, suggestions[suggestion].pattern) ==
           ST_OK);
    uint32_t matches = 0;
    for (size_t command = 0; command < command_count; command++) {
      st_eval_result_t result = {0};
      ASSERT(test_st_policy_eval(policy, commands[command], &result) == ST_OK);
      matches += result.matches;
    }
    ASSERT(matches == suggestions[suggestion].count);
    st_policy_free(policy);
    st_policy_ctx_release(ctx);
  }
  return 1;
}

static int test_suggestion_order_is_input_order_independent(void) {
  static const char *commands[] = {
      "copy /tmp/alpha.cfg", "copy /tmp/beta.cfg", "copy /tmp/gamma.log",
      "move /tmp/alpha.cfg", "move /tmp/beta.cfg", "move /tmp/gamma.log"};
  static const size_t orders[][6] = {
      {0, 1, 2, 3, 4, 5}, {5, 4, 3, 2, 1, 0}, {2, 5, 1, 4, 0, 3}};
  st_suggestion_t *baseline = NULL;
  size_t baseline_count = 0;
  for (size_t order = 0; order < sizeof(orders) / sizeof(orders[0]); order++) {
    st_learner_t *learner = st_learner_new(1, 0.0);
    ASSERT(learner != NULL);
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++)
      ASSERT(test_st_feed(learner, commands[orders[order][i]]) == ST_OK);
    size_t count = 0;
    st_suggestion_t *suggestions = st_suggest(learner, &count);
    ASSERT(suggestions != NULL && count > 0);
    ASSERT(suggestions_replay_exactly(suggestions, count, commands,
                                      sizeof(commands) / sizeof(commands[0])));
    if (order == 0) {
      baseline = suggestions;
      baseline_count = count;
    } else {
      ASSERT(
          suggestion_lists_equal(baseline, baseline_count, suggestions, count));
      st_free_suggestions(suggestions, count);
    }
    st_learner_free(learner);
  }
  st_free_suggestions(baseline, baseline_count);
  return 1;
}

static uint32_t history_random_next(uint32_t *state) {
  *state = *state * UINT32_C(1664525) + UINT32_C(1013904223);
  return *state;
}

typedef struct {
  const char *command;
  const char *argument;
  st_token_type_t type;
} oracle_observation_t;

typedef struct {
  char pattern[ST_MAX_NETPATTERN_LEN];
  uint32_t count;
  double confidence;
} oracle_suggestion_t;

static int compare_oracle_suggestions(const void *left, const void *right) {
  const oracle_suggestion_t *a = left;
  const oracle_suggestion_t *b = right;
  if (a->confidence != b->confidence)
    return a->confidence > b->confidence ? -1 : 1;
  if (a->count != b->count)
    return a->count > b->count ? -1 : 1;
  return strcmp(a->pattern, b->pattern);
}

/* Independent two-token learner model.  It operates on the observation
 * multiset directly and never examines the production trie. */
static size_t oracle_two_token_suggestions(
    const oracle_observation_t *corpus, size_t corpus_count,
    const size_t *history, size_t history_count, uint32_t min_support,
    double min_confidence, size_t limit, const char *blacklist,
    oracle_suggestion_t *out, size_t capacity) {
  size_t out_count = 0;
  for (size_t command_index = 0; command_index < corpus_count;
       command_index++) {
    const char *command = corpus[command_index].command;
    bool command_seen = false;
    for (size_t earlier = 0; earlier < command_index; earlier++)
      command_seen =
          command_seen || strcmp(corpus[earlier].command, command) == 0;
    if (command_seen)
      continue;

    uint32_t total = 0;
    uint32_t typed_counts[ST_TYPE_COUNT] = {0};
    uint32_t literal_counts[32] = {0};
    size_t literal_indices[32] = {0};
    size_t literal_count = 0;
    for (size_t item = 0; item < history_count; item++) {
      size_t observed = history[item];
      if (observed >= corpus_count ||
          strcmp(corpus[observed].command, command) != 0)
        continue;
      total++;
      if (corpus[observed].type != ST_TYPE_LITERAL) {
        typed_counts[corpus[observed].type]++;
        continue;
      }
      size_t literal = 0;
      while (literal < literal_count &&
             strcmp(corpus[literal_indices[literal]].argument,
                    corpus[observed].argument) != 0)
        literal++;
      if (literal == literal_count) {
        ASSERT(literal_count < 32);
        literal_indices[literal_count++] = observed;
      }
      literal_counts[literal]++;
    }
    if (total == 0)
      continue;

    oracle_suggestion_t candidates[ST_TYPE_COUNT + 32] = {0};
    size_t candidate_count = 0;
    if (literal_count >= 2) {
      snprintf(candidates[0].pattern, sizeof(candidates[0].pattern), "%s *",
               command);
      candidates[0].count = total;
      candidates[0].confidence = 1.0;
      candidate_count = 1;
    } else {
      if (literal_count == 1) {
        snprintf(candidates[candidate_count].pattern,
                 sizeof(candidates[candidate_count].pattern), "%s %s", command,
                 corpus[literal_indices[0]].argument);
        candidates[candidate_count].count = literal_counts[0];
        candidates[candidate_count].confidence =
            (double)literal_counts[0] / (double)total;
        candidate_count++;
      }

      size_t typed_count = 0;
      uint64_t typed_total = 0;
      st_token_type_t joined = ST_TYPE_COUNT;
      st_token_type_t dominant = ST_TYPE_COUNT;
      uint32_t dominant_count = 0;
      for (int type = ST_TYPE_LITERAL + 1; type < ST_TYPE_COUNT; type++) {
        if (typed_counts[type] == 0)
          continue;
        typed_count++;
        typed_total += typed_counts[type];
        joined = joined == ST_TYPE_COUNT
                     ? (st_token_type_t)type
                     : st_join(joined, (st_token_type_t)type);
        if (typed_counts[type] > dominant_count ||
            (typed_counts[type] == dominant_count &&
             (st_token_type_t)type < dominant)) {
          dominant = (st_token_type_t)type;
          dominant_count = typed_counts[type];
        }
      }
      if (typed_count != 0) {
        st_token_type_t selected = dominant;
        uint32_t support = dominant_count;
        if (typed_count >= 2 &&
            (uint64_t)dominant_count * 10 < typed_total * 7) {
          selected = joined;
          support = (uint32_t)typed_total;
        }
        snprintf(candidates[candidate_count].pattern,
                 sizeof(candidates[candidate_count].pattern), "%s %s", command,
                 st_type_symbol[selected]);
        candidates[candidate_count].count = support;
        candidates[candidate_count].confidence =
            (double)support / (double)total;
        candidate_count++;
      }
    }

    for (size_t candidate = 0; candidate < candidate_count; candidate++) {
      oracle_suggestion_t value = candidates[candidate];
      if (value.count < min_support || value.confidence < min_confidence ||
          (blacklist && strcmp(value.pattern, blacklist) == 0))
        continue;
      ASSERT(out_count < capacity);
      out[out_count++] = value;
    }
  }
  qsort(out, out_count, sizeof(*out), compare_oracle_suggestions);
  return out_count > limit ? limit : out_count;
}

static int test_independent_two_token_learner_oracle(void) {
  static const oracle_observation_t corpus[] = {
      {"copy", "alpha", ST_TYPE_LITERAL},
      {"copy", "beta", ST_TYPE_LITERAL},
      {"probe", "42", ST_TYPE_NUMBER},
      {"probe", "43", ST_TYPE_NUMBER},
      {"probe", "550e8400-e29b-41d4-a716-446655440000", ST_TYPE_UUID},
      {"locate", "/absolute", ST_TYPE_ABS_PATH},
      {"locate", "../relative", ST_TYPE_REL_PATH},
      {"locate", "file.txt", ST_TYPE_FILENAME},
      {"method", "GET", ST_TYPE_METHOD},
      {"method", "7", ST_TYPE_NUMBER},
      {"mixed", "only", ST_TYPE_LITERAL},
      {"mixed", "9", ST_TYPE_NUMBER},
  };
  enum { HISTORY_COUNT = 64, ORACLE_CAPACITY = 64 };
  for (uint32_t seed = 1; seed <= 12; seed++) {
    size_t history[HISTORY_COUNT];
    uint32_t state = seed;
    for (size_t i = 0; i < HISTORY_COUNT; i++)
      history[i] =
          history_random_next(&state) % (sizeof(corpus) / sizeof(corpus[0]));

    for (size_t configuration = 0; configuration < 2; configuration++) {
      uint32_t min_support = configuration == 0 ? 1 : 3;
      double min_confidence = configuration == 0 ? 0.0 : 0.2;
      size_t limit = configuration == 0 ? 20 : 5;
      const char *blacklist = configuration == 0 ? NULL : "copy *";
      st_learner_t *learner = st_learner_new(min_support, min_confidence);
      ASSERT(learner != NULL);
      learner->max_suggestions = limit;
      if (blacklist)
        ASSERT(test_st_blacklist_add(learner, blacklist) == ST_OK);

      for (size_t i = 0; i < HISTORY_COUNT; i++) {
        const oracle_observation_t *item = &corpus[history[i]];
        st_token_t tokens[] = {
            {.text = (char *)item->command, .type = ST_TYPE_LITERAL},
            {.text = (char *)item->argument, .type = item->type},
        };
        st_token_array_t parsed = {.tokens = tokens, .count = 2};
        ASSERT(st_feed_parsed(learner, &parsed) == ST_OK);
      }

      oracle_suggestion_t expected[ORACLE_CAPACITY] = {0};
      size_t expected_count = oracle_two_token_suggestions(
          corpus, sizeof(corpus) / sizeof(corpus[0]), history, HISTORY_COUNT,
          min_support, min_confidence, limit, blacklist, expected,
          ORACLE_CAPACITY);
      size_t actual_count = 0;
      st_suggestion_t *actual = st_suggest(learner, &actual_count);
      ASSERT(actual_count == expected_count);
      for (size_t i = 0; i < expected_count; i++) {
        ASSERT(actual != NULL);
        ASSERT(pattern_is_cpl(actual[i].pattern, expected[i].pattern));
        ASSERT(actual[i].count == expected[i].count);
        ASSERT(actual[i].confidence == expected[i].confidence);
      }
      st_free_suggestions(actual, actual_count);
      st_learner_free(learner);
    }
  }
  return 1;
}

static int test_generated_suggestion_history_properties(void) {
  static const char *corpus[] = {
      "copy /tmp/alpha.cfg",
      "copy /tmp/beta.cfg",
      "copy /tmp/gamma.log",
      "move /tmp/alpha.cfg",
      "move ../beta.cfg",
      "move file.txt",
      "probe 10",
      "probe 11",
      "probe 550e8400-e29b-41d4-a716-446655440000",
      "probe 550e8400-e29b-51d4-a716-446655440000",
      "allocate 1MiB",
      "allocate 2MiB",
      "allocate 3GiB",
      "sleep 1ms",
      "sleep 2ms",
      "sleep 3s",
      "git status",
      "git log",
  };
  enum { HISTORY_COUNT = 48 };
  char path[] = "/tmp/shelltype-history-v4-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(learner_temp_path, sizeof(learner_temp_path), "%s", path);

  for (uint32_t seed = 1; seed <= 16; seed++) {
    const char *history[HISTORY_COUNT];
    uint32_t state = seed;
    for (size_t i = 0; i < HISTORY_COUNT; i++)
      history[i] = corpus[history_random_next(&state) %
                          (sizeof(corpus) / sizeof(corpus[0]))];

    st_learner_t *forward = st_learner_new(1, 0.0);
    st_learner_t *reverse = st_learner_new(1, 0.0);
    st_learner_t *permuted = st_learner_new(1, 0.0);
    st_learner_t *loaded = st_learner_new(1, 0.0);
    ASSERT(forward && reverse && permuted && loaded);
    for (size_t i = 0; i < HISTORY_COUNT; i++) {
      ASSERT(test_st_feed(forward, history[i]) == ST_OK);
      ASSERT(test_st_feed(reverse, history[HISTORY_COUNT - i - 1]) == ST_OK);
      ASSERT(test_st_feed(permuted, history[(i * 17) % HISTORY_COUNT]) ==
             ST_OK);
    }

    size_t forward_count = 0, reverse_count = 0, permuted_count = 0,
           loaded_count = 0;
    st_suggestion_t *forward_items = st_suggest(forward, &forward_count);
    st_suggestion_t *reverse_items = st_suggest(reverse, &reverse_count);
    st_suggestion_t *permuted_items = st_suggest(permuted, &permuted_count);
    if (!suggestion_lists_equal(forward_items, forward_count, reverse_items,
                                reverse_count) ||
        !suggestion_lists_equal(forward_items, forward_count, permuted_items,
                                permuted_count)) {
      fprintf(stderr, "generated suggestion order differs for seed %u\n", seed);
      return 0;
    }
    ASSERT(suggestions_replay_exactly(forward_items, forward_count, history,
                                      HISTORY_COUNT));
    ASSERT(st_save(forward, path) == ST_OK);
    ASSERT(st_load(loaded, path) == ST_OK);
    st_suggestion_t *loaded_items = st_suggest(loaded, &loaded_count);
    ASSERT(suggestion_lists_equal(forward_items, forward_count, loaded_items,
                                  loaded_count));

    st_free_suggestions(forward_items, forward_count);
    st_free_suggestions(reverse_items, reverse_count);
    st_free_suggestions(permuted_items, permuted_count);
    st_free_suggestions(loaded_items, loaded_count);
    st_learner_free(forward);
    st_learner_free(reverse);
    st_learner_free(permuted);
    st_learner_free(loaded);
  }

  ASSERT(unlink(path) == 0);
  learner_temp_path[0] = '\0';
  return 1;
}

static int test_suggestion_matrix(void) {
  static const struct {
    const char *name;
    const char *format;
    size_t repetitions;
    expected_suggestion_t expected[5];
    size_t expected_count;
  } cases[] = {
      {"path family", "ls -l /tmp/file%zu", 5, {{"ls #sopt #p", 5, 1.0}}, 1},
      {"pipeline family",
       "cat /var/log/file%zu.log | grep ERROR",
       4,
       {{"cat #p | grep ERROR", 4, 1.0}},
       1},
      {"extension family", "cat /etc/file%zu.cfg", 5, {{"cat #p", 5, 1.0}}, 1},
      {"size suffix family",
       "allocate %zuMiB",
       5,
       {{"allocate #size.MiB", 5, 1.0}},
       1},
  };

  for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
    st_learner_t *learner = st_learner_new(3, 0.0);
    ASSERT(learner != NULL);
    char command_storage[8][128];
    const char *commands[8];
    for (size_t i = 0; i < cases[c].repetitions; i++) {
      snprintf(command_storage[i], sizeof(command_storage[i]), cases[c].format,
               i);
      commands[i] = command_storage[i];
      ASSERT(test_st_feed(learner, commands[i]) == ST_OK);
    }

    size_t count = 0;
    st_suggestion_t *suggestions = st_suggest(learner, &count);
    ASSERT(suggestions_equal(suggestions, count, cases[c].expected,
                             cases[c].expected_count));
    ASSERT(suggestions_replay_exactly(suggestions, count, commands,
                                      cases[c].repetitions));
    st_free_suggestions(suggestions, count);
    st_learner_free(learner);
  }
  return 1;
}

static int test_suggestion_thresholds_and_limit(void) {
  static const expected_suggestion_t expected_capped[] = {
      {"alpha #n", 3, 1.0},
      {"beta #n", 3, 1.0},
      {"delta #n", 3, 1.0},
  };
  st_learner_t *learner = st_learner_new(6, 0.0);
  ASSERT(learner != NULL);
  for (size_t i = 0; i < 5; i++) {
    char command[64];
    snprintf(command, sizeof(command), "ls -l /tmp/file%zu", i);
    ASSERT(test_st_feed(learner, command) == ST_OK);
  }
  size_t count = 99;
  st_suggestion_t *suggestions = st_suggest(learner, &count);
  ASSERT(!suggestions && count == 0);
  st_learner_free(learner);

  learner = st_learner_new(3, 0.0);
  ASSERT(learner != NULL);
  learner->max_suggestions = 3;
  static const char *families[] = {"alpha", "beta", "delta", "gamma"};
  for (size_t family = 0; family < 4; family++)
    for (size_t i = 1; i <= 3; i++) {
      char command[32];
      snprintf(command, sizeof(command), "%s %zu", families[family], i);
      ASSERT(test_st_feed(learner, command) == ST_OK);
    }
  suggestions = st_suggest(learner, &count);
  ASSERT(
      suggestions_equal(suggestions, count, expected_capped,
                        sizeof(expected_capped) / sizeof(expected_capped[0])));
  st_free_suggestions(suggestions, count);
  learner->max_suggestions = 0;
  count = 17;
  ASSERT(st_suggest(learner, &count) == NULL && count == 0);
  st_learner_free(learner);
  return 1;
}

static int test_confidence_ranking(void) {
  static const expected_suggestion_t expected[] = {
      {"git commit #sopt *", 8, 1.0},
      {"git *", 2, 0.2},
  };
  st_learner_t *learner = st_learner_new(2, 0.0);
  ASSERT(learner != NULL);
  for (size_t i = 0; i < 8; i++) {
    char command[64];
    snprintf(command, sizeof(command), "git commit -m msg%zu", i);
    ASSERT(test_st_feed(learner, command) == ST_OK);
  }
  ASSERT(test_st_feed(learner, "git status") == ST_OK);
  ASSERT(test_st_feed(learner, "git log") == ST_OK);

  size_t count = 0;
  st_suggestion_t *suggestions = st_suggest(learner, &count);
  ASSERT(suggestions_equal(suggestions, count, expected,
                           sizeof(expected) / sizeof(expected[0])));
  static const char *commands[] = {"git commit -m msg0", "git commit -m msg1",
                                   "git commit -m msg2", "git commit -m msg3",
                                   "git commit -m msg4", "git commit -m msg5",
                                   "git commit -m msg6", "git commit -m msg7",
                                   "git status",         "git log"};
  ASSERT(suggestions_replay_exactly(suggestions, count, commands,
                                    sizeof(commands) / sizeof(commands[0])));
  st_free_suggestions(suggestions, count);
  st_learner_free(learner);
  return 1;
}

static int check_complete_rule_case(const char *const *commands,
                                    size_t command_count,
                                    const expected_suggestion_t *expected,
                                    size_t expected_count) {
  st_learner_t *learner = st_learner_new(1, 0.0);
  ASSERT(learner != NULL);
  for (size_t i = 0; i < command_count; i++)
    ASSERT(test_st_feed(learner, commands[i]) == ST_OK);
  size_t count = 0;
  st_suggestion_t *suggestions = st_suggest(learner, &count);
  ASSERT(suggestions_equal(suggestions, count, expected, expected_count));
  ASSERT(
      suggestions_replay_exactly(suggestions, count, commands, command_count));
  st_free_suggestions(suggestions, count);
  st_learner_free(learner);
  return 1;
}

static int test_complete_rule_branch_semantics(void) {
  static const char *dominant[] = {
      "probe 1 tail",
      "probe 2 tail",
      "probe 3 tail",
      "probe 4 tail",
      "probe 5 tail",
      "probe 6 tail",
      "probe 7 tail",
      "probe 550e8400-e29b-41d4-a716-446655440000 tail",
      "probe 123e4567-e89b-42d3-a456-426614174000 tail",
      "probe 987e6543-e21b-45d3-a456-426614174999 tail"};
  static const expected_suggestion_t dominant_expected[] = {
      {"probe #n tail", 7, 0.7}};
  ASSERT(check_complete_rule_case(
      dominant, sizeof(dominant) / sizeof(dominant[0]), dominant_expected,
      sizeof(dominant_expected) / sizeof(dominant_expected[0])));

  static const char *joined[] = {
      "probe 1 tail",
      "probe 2 tail",
      "probe 3 tail",
      "probe 550e8400-e29b-41d4-a716-446655440000 tail",
      "probe 123e4567-e89b-42d3-a456-426614174000 tail",
      "probe 987e6543-e21b-45d3-a456-426614174999 tail"};
  static const expected_suggestion_t joined_expected[] = {
      {"probe #val tail", 6, 1.0}};
  ASSERT(check_complete_rule_case(joined, sizeof(joined) / sizeof(joined[0]),
                                  joined_expected, 1));

  static const char *separate[] = {
      "probe 1 left", "probe 2 left",
      "probe 550e8400-e29b-41d4-a716-446655440000 right",
      "probe 123e4567-e89b-42d3-a456-426614174000 right"};
  static const expected_suggestion_t separate_expected[] = {
      {"probe #n left", 2, 1.0}, {"probe #uuid.v4 right", 2, 1.0}};
  ASSERT(check_complete_rule_case(
      separate, sizeof(separate) / sizeof(separate[0]), separate_expected, 2));

  static const char *prefixes[] = {"git",        "git",        "git",
                                   "git commit", "git commit", "git commit",
                                   "git commit"};
  static const expected_suggestion_t prefix_expected[] = {
      {"git commit", 4, 4.0 / 7.0}, {"git", 3, 3.0 / 7.0}};
  ASSERT(check_complete_rule_case(
      prefixes, sizeof(prefixes) / sizeof(prefixes[0]), prefix_expected, 2));

  static const char *literals[] = {"echo red tail", "echo green tail",
                                   "echo blue tail"};
  static const expected_suggestion_t literal_expected[] = {
      {"echo * tail", 3, 1.0}};
  ASSERT(check_complete_rule_case(
      literals, sizeof(literals) / sizeof(literals[0]), literal_expected, 1));
  return 1;
}

static int test_blacklist_filters_exact_suggestion(void) {
  st_learner_t *learner = st_learner_new(3, 0.0);
  ASSERT(learner != NULL);
  for (size_t i = 0; i < 5; i++) {
    char command[64];
    snprintf(command, sizeof(command), "ls -l /tmp/file%zu", i);
    ASSERT(test_st_feed(learner, command) == ST_OK);
  }
  ASSERT(test_st_blacklist_add(learner, "ls #sopt #p") == ST_OK);
  ASSERT(test_st_blacklist_add(learner, "ls #sopt #p") == ST_OK);
  ASSERT(test_st_blacklist_add(learner, "") == ST_ERR_INVALID);
  ASSERT(learner->blacklist_count == 1);
  ASSERT(test_st_is_blacklisted(learner, "ls #sopt #p"));
  ASSERT(!test_st_is_blacklisted(learner, "ls #sopt"));
  ASSERT(!test_st_is_blacklisted(learner, ""));

  size_t count = 0;
  st_suggestion_t *suggestions = st_suggest(learner, &count);
  ASSERT(suggestions == NULL && count == 0);
  st_free_suggestions(suggestions, count);
  st_learner_free(learner);
  return 1;
}

static int test_blacklist_allocation_failures_are_atomic(void) {
  st_test_alloc_reset();
  st_learner_t *probe = st_learner_new(1, 0.0);
  ASSERT(probe != NULL);
  for (size_t i = 0; i < 16; i++) {
    char pattern[32];
    snprintf(pattern, sizeof(pattern), "blocked-%zu", i);
    ASSERT(test_st_blacklist_add(probe, pattern) == ST_OK);
  }
  st_test_alloc_reset();
  ASSERT(test_st_blacklist_add(probe, "growth-entry") == ST_OK);
  size_t allocations = st_test_alloc_count();
  st_learner_free(probe);
  ASSERT(allocations > 0);

  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_reset();
    st_learner_t *learner = st_learner_new(1, 0.0);
    ASSERT(learner != NULL);
    for (size_t i = 0; i < 16; i++) {
      char pattern[32];
      snprintf(pattern, sizeof(pattern), "blocked-%zu", i);
      ASSERT(test_st_blacklist_add(learner, pattern) == ST_OK);
    }
    st_test_alloc_fail_at(fail_at);
    st_error_t error = test_st_blacklist_add(learner, "growth-entry");
    st_test_alloc_reset();
    ASSERT(error == ST_OK || error == ST_ERR_MEMORY);
    ASSERT(learner->blacklist_count == (error == ST_OK ? 17u : 16u));
    for (size_t i = 0; i < 16; i++) {
      char pattern[32];
      snprintf(pattern, sizeof(pattern), "blocked-%zu", i);
      ASSERT(test_st_is_blacklisted(learner, pattern));
    }
    ASSERT(test_st_is_blacklisted(learner, "growth-entry") == (error == ST_OK));
    st_learner_free(learner);
  }
  return 1;
}

static int test_serialization_roundtrip_and_validation(void) {
  char path[] = "/tmp/shelltype-learner-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  snprintf(learner_temp_path, sizeof(learner_temp_path), "%s", path);
  close(fd);

  st_learner_t *source = st_learner_new(3, 0.0);
  st_learner_t *loaded = st_learner_new(3, 0.0);
  ASSERT(source && loaded);
  ASSERT(test_st_feed(loaded, "obsolete command") == ST_OK);
  ASSERT(st_load(loaded, "/tmp/shelltype-file-does-not-exist") == ST_ERR_IO);
  ASSERT(find_child(loaded->trie.root, "obsolete") != NULL);
  for (size_t i = 0; i < 4; i++) {
    char command[128];
    snprintf(command, sizeof(command), "cat /var/log/file%zu | grep ERROR", i);
    ASSERT(test_st_feed(source, command) == ST_OK);
  }
  st_learner_t *empty_source = st_learner_new(1, 0.0);
  ASSERT(empty_source != NULL && st_save(empty_source, path) == ST_OK);
  st_learner_free(empty_source);
  ASSERT(st_load(loaded, path) == ST_OK);
  ASSERT(loaded->trie.total_commands == 0);
  ASSERT(find_child(loaded->trie.root, "obsolete") == NULL);

  /* A serialization allocation failure must not replace the previous file. */
  st_test_alloc_reset();
  ASSERT(st_save(source, path) == ST_OK);
  size_t save_allocations = st_test_alloc_count();
  ASSERT(save_allocations > 0);
  bool save_failure_observed = false;
  for (size_t fail_at = 1; fail_at <= save_allocations; fail_at++) {
    FILE *keep = fopen(path, "w");
    ASSERT(keep != NULL && fputs("keep-existing\n", keep) >= 0 &&
           fclose(keep) == 0);
    st_test_alloc_fail_at(fail_at);
    st_error_t save_error = st_save(source, path);
    st_test_alloc_reset();
    if (save_error == ST_ERR_MEMORY) {
      save_failure_observed = true;
      keep = fopen(path, "r");
      ASSERT(keep != NULL);
      char preserved[32] = {0};
      ASSERT(fgets(preserved, sizeof(preserved), keep) != NULL);
      ASSERT(fclose(keep) == 0);
      ASSERT(strcmp(preserved, "keep-existing\n") == 0);
    } else {
      ASSERT(save_error == ST_OK);
    }
  }
  ASSERT(save_failure_observed);
  ASSERT(st_save(source, path) == ST_OK);
  ASSERT(st_load(loaded, path) == ST_OK);
  ASSERT(loaded->trie.total_commands == source->trie.total_commands);
  ASSERT(find_child(loaded->trie.root, "obsolete") == NULL);

  /* A syntactically valid framed stream with a damaged checksum must be
   * rejected without replacing the learner's current state. */
  FILE *damaged = fopen(path, "r+b");
  ASSERT(damaged != NULL);
  char persisted_line[512];
  long checksum_offset = -1;
  while (fgets(persisted_line, sizeof(persisted_line), damaged)) {
    if (strncmp(persisted_line, "# CRC32: ", 9) == 0) {
      checksum_offset = ftell(damaged) - (long)strlen(persisted_line) + 9;
      break;
    }
  }
  ASSERT(checksum_offset >= 0 &&
         fseek(damaged, checksum_offset, SEEK_SET) == 0);
  int checksum_digit = fgetc(damaged);
  ASSERT(checksum_digit != EOF && fseek(damaged, -1, SEEK_CUR) == 0);
  ASSERT(fputc(checksum_digit == '0' ? '1' : '0', damaged) != EOF);
  ASSERT(fclose(damaged) == 0);
  ASSERT(st_load(loaded, path) == ST_ERR_FORMAT);
  ASSERT(loaded->trie.total_commands == source->trie.total_commands);
  ASSERT(find_child(loaded->trie.root, "git") == NULL);
  ASSERT(st_save(source, path) == ST_OK);

  size_t source_count = 0, loaded_count = 0;
  st_suggestion_t *source_items = st_suggest(source, &source_count);
  st_suggestion_t *loaded_items = st_suggest(loaded, &loaded_count);
  ASSERT(source_items && loaded_items && source_count == 1 &&
         suggestion_lists_equal(source_items, source_count, loaded_items,
                                loaded_count));

  static const char *malformed[] = {
      "not a record\n",
      "0\tgit\n",
      "12x\tgit\n",
      "4294967296\tgit\n",
      "1\t\n",
      "# total_commands=oops\n1\tgit\n",
      "# total_commands=1\n1\tgit\nbroken\n",
      "# total_commands=1\n2\tgit\n",
      "# total_commands=2\n1\tgit commit\n",
      "# total_commands=2\n1\tgit\n1\tgit\n",
      "# total_commands=1\n1git status\n",
      "1\tgit\n",
      "# total_commands=1\n1\tgit\n# total_commands=1\n",
      "# ST trie dump v4\n# total_commands=1\n",
      "# ST trie dump v4\n# total_commands=1\n"
      "2\t0\tL\t0\t1\t-\t0\t676974\n",
      "# ST trie dump v4\n# total_commands=1\n"
      "1\t1\tL\t0\t1\t-\t0\t676974\n",
      "# ST trie dump v4\n# total_commands=1\n"
      "1\t0\tL\t0\t1\t-\t0\tzz\n",
      "# ST trie dump v4\n# total_commands=1\n"
      "1\t0\tL\t6\t1\t-\t0\t676974\n",
      "# ST trie dump v4\n# total_commands=1\n"
      "1\t0\tT\t6\t1\t!\t1\t#w\n",
      "# ST trie dump v4\n# total_commands=1\n"
      "1\t0\tT\t6\t1\t-\t1\t-\n",
      "# ST trie dump v4\n# total_commands=1\n"
      "1\t0\tL\t0\t1\t-\t0\t676974\n"
      "2\t1\tL\t0\t2\t-\t0\t737461747573\n",
      /* Single-field mutations of a structurally valid UUID-v4 trie. */
      "# ST trie dump v4\n# total_commands=1\n"
      "1\t0\tL\t0\t1\t-\t0\t70726f6265\n"
      "2\t1\tT\t18\t1\tv4\t0\t-\n",
      "# ST trie dump v4\n# total_commands=1\n"
      "1\t0\tL\t0\t1\t-\t0\t70726f6265\n"
      "2\t1\tT\t18\t1\tv3\t1\t-\n",
      "# ST trie dump v4\n# total_commands=1\n"
      "1\t0\tL\t0\t1\t-\t0\t70726f6265\n"
      "2\t1\tT\t18\t1\tv4\t1\t7634\n",
      "# ST trie dump v4\n# total_commands=1\n"
      "1\t0\tL\t0\t1\t-\t0\t70726f6265\n"
      "2\t0\tT\t18\t1\tv4\t1\t-\n",
  };
  size_t original_children = loaded->trie.root->num_children;
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
    FILE *fixture = fopen(path, "w");
    ASSERT(fixture != NULL);
    ASSERT(fputs(malformed[i], fixture) >= 0);
    ASSERT(fclose(fixture) == 0);
    ASSERT(st_load(loaded, path) == ST_ERR_FORMAT);
    ASSERT(loaded->trie.total_commands == source->trie.total_commands);
    ASSERT(loaded->trie.root->num_children == original_children);
    ASSERT(find_child(loaded->trie.root, "git") == NULL);
  }

  static const char *const malformed_framed[] = {
      "# shelltype-learner v5\n# total-commands: x\n# nodes: 0\n"
      "# CRC32: 00000000\n",
      "# shelltype-learner v5\n# total-commands: 0x\n# nodes: 0\n"
      "# CRC32: 00000000\n",
      "# shelltype-learner v5\n# total-commands: 0\n# nodes: x\n"
      "# CRC32: 00000000\n",
      "# shelltype-learner v5\n# total-commands: 0\n# nodes: 4294967295\n"
      "# CRC32: 00000000\n",
      "# shelltype-learner v5\n# total-commands: 0\n# nodes: 0\n"
      "# CRC32: 0000000X\n",
      "# shelltype-learner v5\n# total-commands: 0\n# nodes: 0\n"
      "# CRC32: 00000000\ntrailing\n",
      "# shelltype-learner v5\n# total-commands: 1\n# nodes: 0\n"
      "# CRC32: 00000000\n",
      "# shelltype-learner v5\n# total-commands: 0\n# nodes: 1\n"
      "# CRC32: 00000000\n",
      "# shelltype-learner v5\n# total-commands: 1\n# nodes: 1\n"
      "4:1:x,,\n# CRC32: 00000000\n",
      "# shelltype-learner v5\n# total-commands: 1\n# nodes: 1\n"
      "31:1:2,1:0,1:L,1:0,1:1,0:,1:0,1:x,,\n# CRC32: 00000000\n",
      "# shelltype-learner v5\n# total-commands: 1\n# nodes: 1\n"
      "31:1:1,1:0,1:L,1:1,1:1,0:,1:0,1:x,,\n# CRC32: 00000000\n",
      "# shelltype-learner v5\n# total-commands: 1\n# nodes: 1\n"
      "33:1:1,1:0,1:T,1:6,1:1,1:-,1:1,1:x,,\n# CRC32: 00000000\n",
      "# shelltype-learner v5\n# total-commands: 1\n# nodes: 1\n"
      "33:1:1,1:0,1:L,1:0,1:1,1:!,1:0,1:x,,\n# CRC32: 00000000\n",
  };
  for (size_t i = 0; i < sizeof(malformed_framed) / sizeof(malformed_framed[0]);
       i++) {
    FILE *fixture = fopen(path, "wb");
    ASSERT(fixture != NULL && fputs(malformed_framed[i], fixture) >= 0);
    ASSERT(fclose(fixture) == 0);
    ASSERT(st_load(loaded, path) == ST_ERR_FORMAT);
    ASSERT(loaded->trie.total_commands == source->trie.total_commands);
    ASSERT(loaded->trie.root->num_children == original_children);
  }

  FILE *deep = fopen(path, "w");
  ASSERT(deep && fputs("# ST trie dump v4\n# total_commands=1\n", deep) >= 0);
  for (size_t i = 1; i <= ST_MAX_CMD_TOKENS + 1; i++)
    ASSERT(fprintf(deep, "%zu\t%zu\tL\t0\t1\t-\t0\t78\n", i, i - 1) > 0);
  ASSERT(fclose(deep) == 0);
  ASSERT(st_load(loaded, path) == ST_ERR_FORMAT);
  ASSERT(loaded->trie.total_commands == source->trie.total_commands);

  FILE *wide = fopen(path, "w");
  ASSERT(wide && fputs("# ST trie dump v4\n# total_commands=1\n"
                       "1\t0\tL\t0\t1\t-\t0\t",
                       wide) >= 0);
  for (size_t i = 0; i < ST_MAX_TOKEN_LEN; i++)
    ASSERT(fputs("61", wide) >= 0);
  ASSERT(fputc('\n', wide) != EOF && fclose(wide) == 0);
  ASSERT(st_load(loaded, path) == ST_ERR_FORMAT);
  ASSERT(loaded->trie.total_commands == source->trie.total_commands);

  /* The provisional line-oriented v4 was never released.  It must not be
   * mistaken for the canonical framed v4 format, including with CRLFs. */
  FILE *crlf = fopen(path, "w");
  ASSERT(crlf != NULL);
  ASSERT(fputs("# ST trie dump v4\r\n# total_commands=1\r\n"
               "1\t0\tT\t6\t1\t!\t1\t-\r\n",
               crlf) >= 0);
  ASSERT(fclose(crlf) == 0);
  ASSERT(st_load(loaded, path) == ST_ERR_FORMAT);
  ASSERT(loaded->trie.total_commands == source->trie.total_commands);
  ASSERT(loaded->trie.root->num_children == original_children);
  ASSERT(test_st_feed(loaded, "git status") == ST_OK);
  ASSERT(loaded->trie.total_commands == source->trie.total_commands + 1);

  if (access("/dev/full", W_OK) == 0)
    ASSERT(st_save(source, "/dev/full") == ST_ERR_IO);

  st_free_suggestions(source_items, source_count);
  st_free_suggestions(loaded_items, loaded_count);
  st_learner_free(source);
  st_learner_free(loaded);
  unlink(path);
  return 1;
}

static int test_serialization_preserves_prefix_nodes(void) {
  char path[] = "/tmp/shelltype-learner-prefix-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  snprintf(learner_temp_path, sizeof(learner_temp_path), "%s", path);
  ASSERT(close(fd) == 0);

  st_learner_t *source = st_learner_new(1, 0.0);
  st_learner_t *loaded = st_learner_new(1, 0.0);
  ASSERT(source != NULL && loaded != NULL);
  ASSERT(test_st_feed(source, "git") == ST_OK);
  ASSERT(test_st_feed(source, "git") == ST_OK);
  ASSERT(test_st_feed(source, "git") == ST_OK);
  ASSERT(test_st_feed(source, "git commit") == ST_OK);
  ASSERT(test_st_feed(source, "git commit") == ST_OK);
  ASSERT(test_st_feed(source, "git commit -m fix") == ST_OK);
  ASSERT(source->trie.total_commands == 6);
  ASSERT(source->trie.root->count == 6);
  st_node_t *git = find_child(source->trie.root, "git");
  ASSERT(git != NULL && git->count == 6);
  st_node_t *commit = find_child(git, "commit");
  ASSERT(commit != NULL && commit->count == 3);

  ASSERT(st_save(source, path) == ST_OK);
  ASSERT(st_load(loaded, path) == ST_OK);
  ASSERT(loaded->trie.total_commands == source->trie.total_commands);
  ASSERT(trie_counts_equal(source->trie.root, loaded->trie.root));

  size_t source_count = 0, loaded_count = 0;
  st_suggestion_t *source_items = st_suggest(source, &source_count);
  st_suggestion_t *loaded_items = st_suggest(loaded, &loaded_count);
  ASSERT(source_items != NULL && loaded_items != NULL &&
         suggestion_lists_equal(source_items, source_count, loaded_items,
                                loaded_count));
  st_free_suggestions(source_items, source_count);
  st_free_suggestions(loaded_items, loaded_count);
  st_learner_free(source);
  st_learner_free(loaded);
  ASSERT(unlink(path) == 0);
  learner_temp_path[0] = '\0';
  return 1;
}

static int test_learner_save_io_failures_are_atomic(void) {
  char path[] = "/tmp/shelltype-learner-io-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(learner_temp_path, sizeof(learner_temp_path), "%s", path);
  st_learner_t *learner = baseline_learner();
  ASSERT(learner != NULL);

  st_test_io_reset();
  ASSERT(st_save(learner, path) == ST_OK);
  size_t operation_count = st_test_io_count();
  ASSERT(operation_count >= 4);
  static const char sentinel[] = "preserve-existing-learner";

  for (size_t fail_at = 1; fail_at <= operation_count; fail_at++) {
    FILE *fp = fopen(path, "wb");
    ASSERT(fp != NULL);
    ASSERT(fwrite(sentinel, 1, sizeof(sentinel) - 1, fp) ==
           sizeof(sentinel) - 1);
    ASSERT(fclose(fp) == 0);
    st_test_io_fail_at(fail_at);
    st_error_t error = st_save(learner, path);
    st_test_io_reset();
    ASSERT(error == ST_ERR_IO);

    char contents[128] = {0};
    fp = fopen(path, "rb");
    ASSERT(fp != NULL);
    size_t length = fread(contents, 1, sizeof(contents), fp);
    ASSERT(!ferror(fp) && fclose(fp) == 0);
    bool old_file = length == sizeof(sentinel) - 1 &&
                    memcmp(contents, sentinel, length) == 0;
    if (!old_file) {
      st_learner_t *check = st_learner_new(1, 0.0);
      ASSERT(check != NULL && st_load(check, path) == ST_OK);
      ASSERT(check->trie.total_commands == learner->trie.total_commands);
      st_learner_free(check);
    }
    ASSERT(no_learner_save_temps(path));
    ASSERT(learner->trie.total_commands == 2);
  }

  st_learner_free(learner);
  ASSERT(unlink(path) == 0);
  learner_temp_path[0] = '\0';
  return 1;
}

static int test_learner_load_rejects_binary_and_overlong_lines(void) {
  char path[] = "/tmp/shelltype-learner-load-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(learner_temp_path, sizeof(learner_temp_path), "%s", path);
  st_learner_t *learner = baseline_learner();
  ASSERT(learner != NULL);

  static const unsigned char binary[] =
      "# ST trie dump v2\n# total_commands=1\n1\t!\t1\t#w\0evil\n";
  FILE *fp = fopen(path, "wb");
  ASSERT(fp != NULL);
  ASSERT(fwrite(binary, 1, sizeof(binary) - 1, fp) == sizeof(binary) - 1);
  ASSERT(fclose(fp) == 0);
  ASSERT(st_load(learner, path) == ST_ERR_FORMAT);
  ASSERT(learner->trie.total_commands == 2);
  ASSERT(find_child(learner->trie.root, "git") != NULL);

  fp = fopen(path, "wb");
  ASSERT(fp != NULL);
  ASSERT(fputs("# ST trie dump v2\n# total_commands=1\n1\t!\t1\t", fp) >= 0);
  for (size_t i = 0; i < 4096; i++)
    ASSERT(fputc('a', fp) != EOF);
  ASSERT(fputc('\n', fp) != EOF && fclose(fp) == 0);
  ASSERT(st_load(learner, path) == ST_ERR_FORMAT);
  ASSERT(learner->trie.total_commands == 2);
  ASSERT(find_child(learner->trie.root, "git") != NULL);

  st_learner_free(learner);
  ASSERT(unlink(path) == 0);
  learner_temp_path[0] = '\0';
  return 1;
}

static int test_suggestion_allocation_failures_are_clean(void) {
  st_test_alloc_reset();
  st_learner_t *probe = st_learner_new(1, 0.0);
  ASSERT(probe != NULL);
  for (size_t i = 0; i < 8; i++) {
    char command[64];
    snprintf(command, sizeof(command), "copy /tmp/file%zu", i);
    ASSERT(test_st_feed(probe, command) == ST_OK);
  }
  st_test_alloc_reset();
  size_t probe_count = 0;
  st_suggestion_t *probe_suggestions = st_suggest(probe, &probe_count);
  size_t allocations = st_test_alloc_count();
  ASSERT(probe_suggestions != NULL && probe_count > 0 && allocations > 0);
  st_free_suggestions(probe_suggestions, probe_count);
  st_learner_free(probe);

  bool observed = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_reset();
    st_learner_t *learner = st_learner_new(1, 0.0);
    ASSERT(learner != NULL);
    for (size_t i = 0; i < 8; i++) {
      char command[64];
      snprintf(command, sizeof(command), "copy /tmp/file%zu", i);
      ASSERT(test_st_feed(learner, command) == ST_OK);
    }
    size_t count = 99;
    st_test_alloc_fail_at(fail_at);
    st_suggestion_t *suggestions = st_suggest(learner, &count);
    st_test_alloc_reset();
    if (!suggestions) {
      observed = true;
      ASSERT(count == 0);
    } else {
      ASSERT(count > 0);
      st_free_suggestions(suggestions, count);
    }
    st_learner_free(learner);
  }
  ASSERT(observed);
  return 1;
}

static int test_load_allocation_failures_preserve_learner(void) {
  char path[] = "/tmp/shelltype-load-fail-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  snprintf(learner_temp_path, sizeof(learner_temp_path), "%s", path);
  close(fd);

  st_test_alloc_reset();
  st_learner_t *source = st_learner_new(1, 0.0);
  st_learner_t *loaded = st_learner_new(1, 0.0);
  ASSERT(source != NULL && loaded != NULL);
  ASSERT(test_st_feed(source, "source command") == ST_OK);
  ASSERT(st_save(source, path) == ST_OK);
  ASSERT(test_st_feed(loaded, "keep command") == ST_OK);

  st_test_alloc_reset();
  ASSERT(st_load(loaded, path) == ST_OK);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);
  st_learner_free(loaded);

  bool observed = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    loaded = st_learner_new(1, 0.0);
    ASSERT(loaded != NULL);
    ASSERT(test_st_feed(loaded, "keep command") == ST_OK);
    st_test_alloc_fail_at(fail_at);
    st_error_t err = st_load(loaded, path);
    st_test_alloc_reset();
    if (err == ST_ERR_MEMORY) {
      observed = true;
      ASSERT(find_child(loaded->trie.root, "keep") != NULL);
    } else {
      if (err != ST_OK)
        printf("    load fail_at=%zu returned %s\n", fail_at,
               st_error_string(err));
      ASSERT(err == ST_OK);
      ASSERT(loaded->trie.total_commands == source->trie.total_commands);
    }
    st_learner_free(loaded);
  }
  ASSERT(observed);
  st_learner_free(source);
  return 1;
}

static int test_learner_load_read_failures_preserve_state(void) {
  char path[] = "/tmp/shelltype-learner-read-fail-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(learner_temp_path, sizeof(learner_temp_path), "%s", path);
  st_learner_t *source = st_learner_new(1, 0.0);
  ASSERT(source != NULL);
  ASSERT(test_st_feed(source, "replacement 42") == ST_OK);
  ASSERT(test_st_feed(source, "replacement 43") == ST_OK);
  ASSERT(st_save(source, path) == ST_OK);

  st_learner_t *probe = baseline_learner();
  ASSERT(probe != NULL);
  st_test_io_reset();
  ASSERT(st_load(probe, path) == ST_OK);
  size_t read_count = st_test_read_count();
  st_test_io_reset();
  ASSERT(read_count > 0);
  st_learner_free(probe);

  for (size_t fail_at = 1; fail_at <= read_count; fail_at++) {
    st_learner_t *learner = baseline_learner();
    st_learner_t *expected = baseline_learner();
    ASSERT(learner && expected);
    st_test_read_fail_at(fail_at);
    ASSERT(st_load(learner, path) == ST_ERR_IO);
    st_test_io_reset();
    ASSERT(learner->trie.total_commands == expected->trie.total_commands);
    ASSERT(nodes_equal(learner->trie.root, expected->trie.root));
    ASSERT(test_st_feed(learner, "after failure") == ST_OK);
    st_learner_free(expected);
    st_learner_free(learner);
  }

  st_learner_t *close_failed = baseline_learner();
  st_learner_t *expected = baseline_learner();
  ASSERT(close_failed && expected);
  st_test_io_fail_at(1);
  ASSERT(st_load(close_failed, path) == ST_ERR_IO);
  st_test_io_reset();
  ASSERT(nodes_equal(close_failed->trie.root, expected->trie.root));
  st_learner_free(expected);
  st_learner_free(close_failed);
  st_learner_free(source);
  ASSERT(unlink(path) == 0);
  learner_temp_path[0] = '\0';
  return 1;
}

static const st_suggestion_t *find_suggestion(const st_suggestion_t *items,
                                              size_t count,
                                              const char *pattern) {
  for (size_t i = 0; i < count; i++)
    if (pattern_is_cpl(items[i].pattern, pattern))
      return &items[i];
  return NULL;
}

static int test_mixed_type_widening_and_v4_roundtrip(void) {
  char path[] = "/tmp/shelltype-mixed-v4-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(learner_temp_path, sizeof(learner_temp_path), "%s", path);

  static const char *number_commands[] = {"probe 10", "probe 11", "probe 12",
                                          "probe 13", "probe 14", "probe 15",
                                          "probe 16"};
  static const char *uuid_commands[] = {
      "probe 550e8400-e29b-41d4-a716-446655440000",
      "probe 123e4567-e89b-42d3-a456-426614174000",
      "probe 6ba7b810-9dad-41d1-80b4-00c04fd430c8"};
  static const size_t orders[][10] = {
      {0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
      {9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
      {7, 0, 8, 1, 9, 2, 3, 4, 5, 6},
  };
  st_suggestion_t *baseline = NULL;
  size_t baseline_count = 0;
  for (size_t order = 0; order < sizeof(orders) / sizeof(orders[0]); order++) {
    st_learner_t *learner = st_learner_new(1, 0.0);
    ASSERT(learner != NULL);
    for (size_t i = 0; i < 10; i++) {
      size_t index = orders[order][i];
      const char *command =
          index < 7 ? number_commands[index] : uuid_commands[index - 7];
      ASSERT(test_st_feed(learner, command) == ST_OK);
    }
    size_t count = 0;
    st_suggestion_t *items = st_suggest(learner, &count);
    const st_suggestion_t *dominant = find_suggestion(items, count, "probe #n");
    ASSERT(dominant && dominant->count == 7 && dominant->confidence == 0.7);
    ASSERT(!find_suggestion(items, count, "probe #val"));
    if (order == 0) {
      baseline = items;
      baseline_count = count;
      ASSERT(st_save(learner, path) == ST_OK);
    } else {
      ASSERT(suggestion_lists_equal(baseline, baseline_count, items, count));
      st_free_suggestions(items, count);
    }
    st_learner_free(learner);
  }

  st_learner_t *loaded = st_learner_new(1, 0.0);
  ASSERT(loaded && st_load(loaded, path) == ST_OK);
  size_t loaded_count = 0;
  st_suggestion_t *loaded_items = st_suggest(loaded, &loaded_count);
  ASSERT(suggestion_lists_equal(baseline, baseline_count, loaded_items,
                                loaded_count));

  st_learner_t *joined = st_learner_new(1, 0.0);
  ASSERT(joined != NULL);
  for (size_t i = 0; i < 6; i++)
    ASSERT(test_st_feed(joined, number_commands[i]) == ST_OK);
  for (size_t i = 0; i < 3; i++)
    ASSERT(test_st_feed(joined, uuid_commands[i]) == ST_OK);
  ASSERT(test_st_feed(joined, "probe 9.9.9") == ST_OK);
  size_t joined_count = 0;
  st_suggestion_t *joined_items = st_suggest(joined, &joined_count);
  const st_suggestion_t *generic =
      find_suggestion(joined_items, joined_count, "probe #val");
  ASSERT(generic && generic->count == 10 && generic->confidence == 1.0);

  st_free_suggestions(baseline, baseline_count);
  st_free_suggestions(loaded_items, loaded_count);
  st_free_suggestions(joined_items, joined_count);
  st_learner_free(loaded);
  st_learner_free(joined);
  ASSERT(unlink(path) == 0);
  learner_temp_path[0] = '\0';
  return 1;
}

static int test_v4_preserves_reserved_literal_spellings(void) {
  char path[] = "/tmp/shelltype-literal-v4-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(learner_temp_path, sizeof(learner_temp_path), "%s", path);
  st_learner_t *source = st_learner_new(1, 0.0);
  st_learner_t *loaded = st_learner_new(1, 0.0);
  ASSERT(source && loaded);

  for (int type = ST_TYPE_HEXHASH; type < ST_TYPE_COUNT; type++) {
    st_token_t token = {.text = (char *)st_type_symbol[type],
                        .type = ST_TYPE_LITERAL};
    st_token_array_t parsed = {.tokens = &token, .count = 1};
    ASSERT(st_feed_parsed(source, &parsed) == ST_OK);
  }
  ASSERT(st_save(source, path) == ST_OK);
  ASSERT(st_load(loaded, path) == ST_OK);
  ASSERT(source->trie.total_commands == loaded->trie.total_commands);
  for (int type = ST_TYPE_HEXHASH; type < ST_TYPE_COUNT; type++) {
    st_node_t *node = find_child(loaded->trie.root, st_type_symbol[type]);
    ASSERT(node && node->type == ST_TYPE_LITERAL && node->observed_types == 0);
  }
  size_t source_count = SIZE_MAX;
  size_t loaded_count = SIZE_MAX;
  st_suggestion_t *source_items = st_suggest(source, &source_count);
  st_suggestion_t *loaded_items = st_suggest(loaded, &loaded_count);
  ASSERT(source_items != NULL && loaded_items != NULL && source_count != 0 &&
         source_count == loaded_count);
  ASSERT(suggestion_lists_equal(source_items, source_count, loaded_items,
                                loaded_count));

  st_free_suggestions(source_items, source_count);
  st_free_suggestions(loaded_items, loaded_count);

  st_learner_free(source);
  st_learner_free(loaded);
  ASSERT(unlink(path) == 0);
  learner_temp_path[0] = '\0';
  return 1;
}

static int test_metadata_aggregation_and_v4_roundtrip(void) {
  char path[] = "/tmp/shelltype-metadata-v2-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(learner_temp_path, sizeof(learner_temp_path), "%s", path);

  st_learner_t *uniform = st_learner_new(1, 0.0);
  st_learner_t *mixed_a = st_learner_new(1, 0.0);
  st_learner_t *mixed_b = st_learner_new(1, 0.0);
  st_learner_t *loaded = st_learner_new(1, 0.0);
  ASSERT(uniform && mixed_a && mixed_b && loaded);
  for (size_t i = 0; i < ST_MAX_SAMPLE_VALUES + 8; i++) {
    char mib[64], gib[64];
    snprintf(mib, sizeof(mib), "allocate %zuMiB", i + 1);
    snprintf(gib, sizeof(gib), "allocate %zuGiB", i + 1);
    ASSERT(test_st_feed(uniform, mib) == ST_OK);
    ASSERT(test_st_feed(mixed_a, i == ST_MAX_SAMPLE_VALUES + 7 ? gib : mib) ==
           ST_OK);
    ASSERT(test_st_feed(mixed_b, i == 0 ? gib : mib) == ST_OK);
  }

  size_t uniform_count = 0, mixed_a_count = 0, mixed_b_count = 0;
  st_suggestion_t *uniform_items = st_suggest(uniform, &uniform_count);
  st_suggestion_t *mixed_a_items = st_suggest(mixed_a, &mixed_a_count);
  st_suggestion_t *mixed_b_items = st_suggest(mixed_b, &mixed_b_count);
  ASSERT(uniform_items && mixed_a_items && mixed_b_items);
  ASSERT(find_suggestion(uniform_items, uniform_count, "allocate #size.MiB"));
  ASSERT(find_suggestion(mixed_a_items, mixed_a_count, "allocate #size"));
  ASSERT(find_suggestion(mixed_b_items, mixed_b_count, "allocate #size"));
  ASSERT(!find_suggestion(mixed_a_items, mixed_a_count, "allocate #size.MiB"));
  ASSERT(!find_suggestion(mixed_b_items, mixed_b_count, "allocate #size.MiB"));

  ASSERT(st_save(uniform, path) == ST_OK);
  ASSERT(st_load(loaded, path) == ST_OK);
  size_t loaded_count = 0;
  st_suggestion_t *loaded_items = st_suggest(loaded, &loaded_count);
  ASSERT(loaded_items && suggestion_lists_equal(uniform_items, uniform_count,
                                                loaded_items, loaded_count));

  static const struct {
    const char *first;
    const char *second;
    const char *different;
    const char *specific;
    const char *generic;
  } metadata_cases[] = {
      {"sleep 1ms", "sleep 2ms", "sleep 3s", "sleep #duration.ms",
       "sleep #duration"},
      {"uuid 550e8400-e29b-41d4-a716-446655440000",
       "uuid 123e4567-e89b-42d3-a456-426614174000",
       "uuid 550e8400-e29b-51d4-a716-446655440000", "uuid #uuid.v4",
       "uuid #uuid"},
      {"log 2025-01-01", "log 2025-01-02", "log 15:30:00", "log #ts.date",
       "log #ts"},
      {"rev 0123456789abcdef0123456789abcdef01234567",
       "rev fedcba9876543210fedcba9876543210fedcba98", "rev abc1234",
       "rev #sha.40", "rev #sha"},
      {"key SHA256:uNiVztksCsDhcc0u9e8BgrJXVGL5Nr0iASdhO1tB9qE",
       "key SHA256:vNiVztksCsDhcc0u9e8BgrJXVGL5Nr0iASdhO1tB9qE",
       "key 1a:2b:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d", "key #fp.sha256",
       "key #fp"},
      {"seq 1-5", "seq 2-8", NULL, "seq #range.step", NULL},
      {"chmod 0755", "chmod 0644", NULL, "chmod #perm.bits", NULL},
  };
  for (size_t i = 0; i < sizeof(metadata_cases) / sizeof(metadata_cases[0]);
       i++) {
    st_learner_t *family = st_learner_new(1, 0.0);
    st_learner_t *family_loaded = st_learner_new(1, 0.0);
    ASSERT(family && family_loaded);
    ASSERT(test_st_feed(family, metadata_cases[i].first) == ST_OK);
    ASSERT(test_st_feed(family, metadata_cases[i].second) == ST_OK);
    size_t family_count = 0;
    st_suggestion_t *family_items = st_suggest(family, &family_count);
    ASSERT(find_suggestion(family_items, family_count,
                           metadata_cases[i].specific));
    ASSERT(st_save(family, path) == ST_OK);
    ASSERT(st_load(family_loaded, path) == ST_OK);
    size_t family_loaded_count = 0;
    st_suggestion_t *family_loaded_items =
        st_suggest(family_loaded, &family_loaded_count);
    ASSERT(suggestion_lists_equal(family_items, family_count,
                                  family_loaded_items, family_loaded_count));

    if (metadata_cases[i].different) {
      ASSERT(test_st_feed(family, metadata_cases[i].different) == ST_OK);
      st_free_suggestions(family_items, family_count);
      family_items = st_suggest(family, &family_count);
      ASSERT(find_suggestion(family_items, family_count,
                             metadata_cases[i].generic));
      ASSERT(!find_suggestion(family_items, family_count,
                              metadata_cases[i].specific));
    }
    st_free_suggestions(family_items, family_count);
    st_free_suggestions(family_loaded_items, family_loaded_count);
    st_learner_free(family);
    st_learner_free(family_loaded);
  }

  FILE *legacy = fopen(path, "w");
  ASSERT(legacy && fputs("# ST trie dump\n# total_commands=0\n", legacy) >= 0 &&
         fclose(legacy) == 0);
  ASSERT(st_load(loaded, path) == ST_ERR_FORMAT);
  ASSERT(loaded->trie.total_commands == uniform->trie.total_commands);

  static const char *malformed_v2[] = {
      "# ST trie dump v2\n# total_commands=1\n1\tunknown\t1\t#size\n",
      "# ST trie dump v2\n# total_commands=1\n1\tMiB\t2\t#size\n",
      "# ST trie dump v2\n# total_commands=1\n1\t-\t1\t#size\n",
      "# ST trie dump v2\n# total_commands=1\n1\tMiB\t1\t#n\n",
      "# ST trie dump v2\n# total_commands=1\n1\tmajor\t1\t#semver\n",
      ("# ST trie dump v2\n# total_commands=1\n1\t!\t1\t#w\n"
       "1\t!\t1\t#w\n"),
      "# ST trie dump v2\n# total_commands=1\n1\t!\t1\t#w\textra\n",
  };
  for (size_t i = 0; i < sizeof(malformed_v2) / sizeof(malformed_v2[0]); i++) {
    FILE *fixture = fopen(path, "w");
    ASSERT(fixture && fputs(malformed_v2[i], fixture) >= 0 &&
           fclose(fixture) == 0);
    ASSERT(st_load(loaded, path) == ST_ERR_FORMAT);
    ASSERT(loaded->trie.total_commands == uniform->trie.total_commands);
  }

  st_free_suggestions(uniform_items, uniform_count);
  st_free_suggestions(mixed_a_items, mixed_a_count);
  st_free_suggestions(mixed_b_items, mixed_b_count);
  st_free_suggestions(loaded_items, loaded_count);
  st_learner_free(uniform);
  st_learner_free(mixed_a);
  st_learner_free(mixed_b);
  st_learner_free(loaded);
  ASSERT(unlink(path) == 0);
  learner_temp_path[0] = '\0';
  return 1;
}

static int test_learner_save_crash_boundaries(void) {
  char path[] = "/tmp/shelltype-crash-save-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(learner_temp_path, sizeof(learner_temp_path), "%s", path);
  st_learner_t *old_state = st_learner_new(1, 0.0);
  st_learner_t *new_state = st_learner_new(1, 0.0);
  ASSERT(old_state && new_state);
  ASSERT(test_st_feed(old_state, "old 1MiB") == ST_OK);
  ASSERT(test_st_feed(new_state, "new 1GiB") == ST_OK);
  ASSERT(test_st_feed(new_state, "new 2GiB") == ST_OK);

  st_test_io_reset();
  ASSERT(st_save(new_state, path) == ST_OK);
  size_t operation_count = st_test_io_count();
  ASSERT(operation_count > 0);
  st_test_io_reset();

  for (size_t crash_after = 1; crash_after <= operation_count; crash_after++) {
    ASSERT(st_save(old_state, path) == ST_OK);
    pid_t child = fork();
    ASSERT(child >= 0);
    if (child == 0) {
      st_test_io_crash_after(crash_after);
      (void)st_save(new_state, path);
      _exit(92);
    }
    int status = 0;
    ASSERT(waitpid(child, &status, 0) == child);
    ASSERT(WIFEXITED(status) && WEXITSTATUS(status) == 91);
    st_test_io_reset();

    st_learner_t *loaded = st_learner_new(1, 0.0);
    ASSERT(loaded && st_load(loaded, path) == ST_OK);
    ASSERT(loaded->trie.total_commands == 1 ||
           loaded->trie.total_commands == 2);
    st_learner_free(loaded);
    remove_learner_save_temps(path);
  }

  st_learner_free(old_state);
  st_learner_free(new_state);
  ASSERT(unlink(path) == 0);
  learner_temp_path[0] = '\0';
  return 1;
}

int main(void) {
  atexit(cleanup_learner_temp_file);
  printf("Running shelltype unit tests...\n\n");
  TEST(test_learner_state_transitions);
  TEST(test_learner_input_boundaries);
  TEST(test_learner_configuration_boundaries);
  TEST(test_suggestion_matrix);
  TEST(test_suggestion_order_is_input_order_independent);
  TEST(test_generated_suggestion_history_properties);
  TEST(test_independent_two_token_learner_oracle);
  TEST(test_suggestion_thresholds_and_limit);
  TEST(test_confidence_ranking);
  TEST(test_complete_rule_branch_semantics);
  TEST(test_blacklist_filters_exact_suggestion);
  TEST(test_blacklist_allocation_failures_are_atomic);
  TEST(test_serialization_roundtrip_and_validation);
  TEST(test_serialization_preserves_prefix_nodes);
  TEST(test_learner_save_io_failures_are_atomic);
  TEST(test_learner_load_rejects_binary_and_overlong_lines);
  TEST(test_suggestion_allocation_failures_are_clean);
  TEST(test_load_allocation_failures_preserve_learner);
  TEST(test_learner_load_read_failures_preserve_state);
  TEST(test_mixed_type_widening_and_v4_roundtrip);
  TEST(test_v4_preserves_reserved_literal_spellings);
  TEST(test_metadata_aggregation_and_v4_roundtrip);
  TEST(test_learner_save_crash_boundaries);
  TEST(test_feed_is_atomic);
  TEST(test_expressive_literal_suggestions);
  TEST(test_compound_option_suggestion);
  printf("\nResults: %d/%d passed, %d failed\n", tests_passed, tests_run,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
