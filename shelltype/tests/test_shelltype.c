/* The shelltype unit checks: the tokenizing and typing of commands, the arena,
 * the policy verifier, and the integration of shelltype with shellsplit's
 * processed subcommands. */
#define _POSIX_C_SOURCE 200809L
#include "../../tests/atomic_file_fixture.h"
#include "arena.h"
#include "crc32.h"
#include "shell_processor.h"
#include "shelltype.h"
#include "test_allocator.h"
#include "test_io.h"
#include "test_netargv.h"
#include "trie_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/* --- unit (from test_shelltype.c) --- */
/* Core unit tests for the command policy learner. */

static int unit_tests_run;
static int unit_tests_passed;
static int unit_tests_failed;

static const st_suggestion_t *unit_find_suggestion(const st_suggestion_t *items,
                                                   size_t count,
                                                   const char *pattern);

static char unit_learner_temp_path[256];
static char unit_learner_template_path[264];
static char unit_learner_save_directory[256];

static void unit_cleanup_learner_temp_file(void) {
  if (unit_learner_template_path[0] != '\0') {
    (void)unlink(unit_learner_template_path);
    unit_learner_template_path[0] = '\0';
  }
  if (unit_learner_temp_path[0] != '\0') {
    (void)unlink(unit_learner_temp_path);
    unit_learner_temp_path[0] = '\0';
  }
  if (unit_learner_save_directory[0]) {
    char path[272];
    snprintf(path, sizeof(path), "%s/learner", unit_learner_save_directory);
    (void)test_atomic_temp_files(path, true);
    (void)rmdir(unit_learner_save_directory);
    unit_learner_save_directory[0] = '\0';
  }
}

#define ASSERT(condition)                                                      \
  do {                                                                         \
    if (!(condition)) {                                                        \
      printf("    assertion failed: %s at %s:%d\n", #condition, __FILE__,      \
             __LINE__);                                                        \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define TEST(function)                                                         \
  do {                                                                         \
    unit_tests_run++;                                                          \
    printf("  %-38s ", #function);                                             \
    if (function()) {                                                          \
      unit_tests_passed++;                                                     \
      printf("PASS\n");                                                        \
    } else {                                                                   \
      unit_tests_failed++;                                                     \
      printf("FAIL\n");                                                        \
    }                                                                          \
  } while (0)

static st_node_t *unit_find_child(st_node_t *parent, const char *token) {
  for (size_t i = 0; i < parent->num_children; i++)
    if (strcmp(parent->children[i]->token, token) == 0)
      return parent->children[i];
  return NULL;
}

static int unit_nodes_equal(const st_node_t *a, const st_node_t *b) {
  if (!a || !b || strcmp(a->token, b->token) != 0 || a->type != b->type ||
      a->count != b->count || a->observed_types != b->observed_types ||
      a->metadata_observations != b->metadata_observations ||
      a->common_metadata != b->common_metadata ||
      a->metadata_mixed != b->metadata_mixed ||
      a->num_children != b->num_children)
    return 0;
  for (size_t i = 0; i < a->num_children; i++)
    if (!unit_nodes_equal(a->children[i], b->children[i]))
      return 0;
  return 1;
}

static st_learner_t *unit_baseline_learner(void) {
  st_learner_t *learner = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  if (!learner || test_st_feed(learner, "git status") != ST_OK ||
      test_st_feed(learner, "git log") != ST_OK) {
    st_learner_free(learner);
    return NULL;
  }
  return learner;
}

static int unit_no_learner_save_temps(const char *path) {
  return test_atomic_temp_files(path, false);
}

static int unit_test_feed_is_atomic(void) {
  st_test_alloc_reset();
  st_learner_t *probe = unit_baseline_learner();
  ASSERT(probe != NULL);
  st_test_alloc_reset();
  ASSERT(test_st_feed(probe, "git commit -m /tmp/message") == ST_OK);
  size_t allocations = st_test_alloc_count();
  st_learner_free(probe);
  ASSERT(allocations > 0);

  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_reset();
    st_learner_t *expected = unit_baseline_learner();
    st_learner_t *actual = unit_baseline_learner();
    ASSERT(expected && actual);
    st_test_alloc_fail_at(fail_at);
    st_error_t error = test_st_feed(actual, "git commit -m /tmp/message");
    st_test_alloc_reset();
    if (error == ST_ERR_MEMORY)
      ASSERT(actual->trie.total_commands == expected->trie.total_commands &&
             unit_nodes_equal(actual->trie.root, expected->trie.root));
    else
      ASSERT(error == ST_OK && actual->trie.total_commands == 3);
    st_learner_free(expected);
    st_learner_free(actual);
  }

  st_token_array_t parsed = {0};
  ASSERT(test_st_classify("git push /tmp/repository", &parsed) == ST_OK);
  probe = unit_baseline_learner();
  ASSERT(probe != NULL);
  st_test_alloc_reset();
  ASSERT(st_learner_feed_tokens(probe, &parsed) == ST_OK);
  allocations = st_test_alloc_count();
  st_learner_free(probe);
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_reset();
    st_learner_t *expected = unit_baseline_learner();
    st_learner_t *actual = unit_baseline_learner();
    ASSERT(expected && actual);
    st_test_alloc_fail_at(fail_at);
    st_error_t error = st_learner_feed_tokens(actual, &parsed);
    st_test_alloc_reset();
    if (error == ST_ERR_MEMORY)
      ASSERT(actual->trie.total_commands == expected->trie.total_commands &&
             unit_nodes_equal(actual->trie.root, expected->trie.root));
    else
      ASSERT(error == ST_OK && actual->trie.total_commands == 3);
    st_learner_free(expected);
    st_learner_free(actual);
  }
  st_token_array_free(&parsed);

  st_learner_t *learner = unit_baseline_learner();
  ASSERT(learner != NULL);
  st_token_t invalid_token = {.text = NULL, .type = ST_TYPE_WORD};
  st_token_array_t invalid = {.tokens = &invalid_token, .count = 1};
  ASSERT(st_learner_feed_tokens(learner, &invalid) == ST_ERR_INVALID);
  invalid_token.text = "value";
  invalid_token.type = ST_TYPE_COUNT;
  ASSERT(st_learner_feed_tokens(learner, &invalid) == ST_ERR_INVALID);
  ASSERT(learner->trie.total_commands == 2);

  learner->trie.total_commands = UINT32_MAX;
  learner->trie.root->count = UINT32_MAX;
  ASSERT(test_st_feed(learner, "git status") == ST_ERR_LIMIT);
  ASSERT(learner->trie.total_commands == UINT32_MAX &&
         learner->trie.root->count == UINT32_MAX);
  st_learner_free(learner);
  return 1;
}

static int unit_test_compound_option_suggestion(void) {
  st_learner_t *learner = st_learner_new(
      &(st_learner_config_t){.min_support = 2,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(learner != NULL);
  ASSERT(test_st_feed(learner, "tool --output=/tmp/one") == ST_OK);
  ASSERT(test_st_feed(learner, "tool --output=/var/two") == ST_OK);
  size_t count = 0;
  st_suggestion_t *suggestions = st_learner_suggest(learner, &count);
  ASSERT(suggestions != NULL);
  ASSERT(unit_find_suggestion(suggestions, count, "tool --output={#p}"));
  st_suggestion_list_free(suggestions, count);
  st_learner_free(learner);
  return 1;
}

static int unit_test_learner_state_transitions(void) {
  st_learner_t *learner = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
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

  st_node_t *git = unit_find_child(learner->trie.root, "git");
  ASSERT(git && git->count == 5);
  ASSERT(unit_find_child(git, "commit") != NULL);
  ASSERT(unit_find_child(git, "status") != NULL);
  ASSERT(learner->trie.total_commands == 5);

  st_token_array_t parsed = {0};
  ASSERT(test_st_classify("curl /tmp/data", &parsed) == ST_OK);
  ASSERT(st_learner_feed_tokens(learner, &parsed) == ST_OK);
  st_token_array_free(&parsed);
  ASSERT(learner->trie.total_commands == 6);
  ASSERT(learner->trie.root->count == 6);
  ASSERT(unit_find_child(learner->trie.root, "curl") != NULL);

  st_token_t too_many_tokens[ST_MAX_CMD_TOKENS + 1];
  for (size_t i = 0; i < sizeof(too_many_tokens) / sizeof(too_many_tokens[0]);
       i++)
    too_many_tokens[i] = (st_token_t){.text = "value", .type = ST_TYPE_LITERAL};
  st_token_array_t oversized = {
      .tokens = too_many_tokens,
      .count = sizeof(too_many_tokens) / sizeof(too_many_tokens[0]),
  };
  ASSERT(st_learner_feed_tokens(learner, &oversized) == ST_ERR_INVALID);
  ASSERT(learner->trie.total_commands == 6);
  st_learner_free(learner);
  return 1;
}

static int unit_test_learner_input_boundaries(void) {
  st_learner_t *learner = unit_baseline_learner();
  ASSERT(learner != NULL);
  ASSERT(test_st_feed(learner, "") == ST_ERR_INVALID);
  ASSERT(test_st_feed(learner, "   ") == ST_ERR_INVALID);

  st_token_array_t empty_tokens = {0};
  ASSERT(st_learner_feed_tokens(learner, &empty_tokens) == ST_ERR_INVALID);

  char many[(ST_MAX_CMD_TOKENS + 1) * 2 + 1];
  size_t used = 0;
  for (size_t i = 0; i < ST_MAX_CMD_TOKENS + 1; i++) {
    many[used++] = 'x';
    many[used++] = ' ';
  }
  many[used - 1] = '\0';
  ASSERT(test_st_feed(learner, many) == ST_ERR_LIMIT);
  ASSERT(learner->trie.total_commands == 2);

  st_learner_t *empty = st_learner_new(
      &(st_learner_config_t){.min_support = 5,
                             .min_confidence = 0.05,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(empty != NULL);
  size_t count = 17;
  ASSERT(st_learner_suggest(empty, &count) == NULL && count == 0);
  count = 17;

  st_learner_free(empty);
  st_learner_free(learner);
  return 1;
}

static int unit_test_learner_configuration_boundaries(void) {
  st_learner_config_t config = {0};
  st_learner_config_default(&config);
  ASSERT(config.min_support == ST_DEFAULT_MIN_SUPPORT);
  ASSERT(config.min_confidence == ST_DEFAULT_MIN_CONFIDENCE);
  ASSERT(config.max_suggestions == ST_DEFAULT_MAX_SUGGESTIONS);
  st_learner_config_default(NULL);

  st_learner_t *defaults = st_learner_new(NULL);
  ASSERT(defaults != NULL);
  ASSERT(st_learner_get_config(defaults, &config) == ST_OK);
  ASSERT(config.min_support == ST_DEFAULT_MIN_SUPPORT);
  ASSERT(config.min_confidence == ST_DEFAULT_MIN_CONFIDENCE);
  ASSERT(config.max_suggestions == ST_DEFAULT_MAX_SUGGESTIONS);
  st_learner_free(defaults);

  st_learner_t *zeroes = st_learner_new(&(st_learner_config_t){0});
  ASSERT(zeroes != NULL);
  ASSERT(st_learner_get_config(zeroes, &config) == ST_OK);
  ASSERT(config.min_support == 0);
  ASSERT(config.min_confidence == 0.0);
  ASSERT(config.max_suggestions == 0);
  st_learner_free(zeroes);

  st_learner_t *configured = st_learner_new(
      &(st_learner_config_t){.min_support = UINT32_MAX,
                             .min_confidence = 1.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(configured != NULL);
  ASSERT(st_learner_get_config(configured, &config) == ST_OK);
  ASSERT(config.min_support == UINT32_MAX);
  ASSERT(config.min_confidence == 1.0);
  ASSERT(test_st_feed(configured, "git status") == ST_OK);
  size_t count = 99;
  ASSERT(st_learner_suggest(configured, &count) == NULL && count == 0);
  st_learner_free(configured);
  return 1;
}

static int unit_test_learner_stats_contract(void) {
  st_learner_stats_t stats = {.command_count = UINT32_MAX,
                              .blacklist_count = SIZE_MAX};

  st_learner_t *learner = st_learner_new(NULL);
  ASSERT(learner != NULL);
  st_learner_get_stats(learner, &stats);
  ASSERT(stats.command_count == 0 && stats.blacklist_count == 0);
  ASSERT(test_st_feed(learner, "echo one") == ST_OK);
  ASSERT(test_st_feed(learner, "printf two") == ST_OK);
  ASSERT(test_st_blacklist_add(learner, "echo *") == ST_OK);
  st_learner_get_stats(learner, &stats);
  ASSERT(stats.command_count == 2 && stats.blacklist_count == 1);

  st_learner_config_t before;
  st_learner_config_t after;
  ASSERT(st_learner_get_config(learner, &before) == ST_OK);

  ASSERT(st_learner_set_config(learner,
                               &(st_learner_config_t){.min_support = 1,
                                                      .min_confidence = NAN,
                                                      .max_suggestions = 1}) ==
         ST_ERR_INVALID);
  ASSERT(st_learner_get_config(learner, &after) == ST_OK);
  ASSERT(memcmp(&before, &after, sizeof(before)) == 0);
  ASSERT(st_learner_set_config(
             learner, &(st_learner_config_t){.min_support = 3,
                                             .min_confidence = 0.5,
                                             .max_suggestions = 2}) == ST_OK);
  ASSERT(st_learner_get_config(learner, &after) == ST_OK);
  ASSERT(after.min_support == 3 && after.min_confidence == 0.5 &&
         after.max_suggestions == 2);
  st_learner_free(learner);
  return 1;
}

typedef struct {
  const char *pattern;
  uint32_t count;
  double confidence;
} unit_expected_suggestion_t;

static int unit_suggestions_equal(const st_suggestion_t *actual,
                                  size_t actual_count,
                                  const unit_expected_suggestion_t *expected,
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
        !test_pattern_is_cpl(
            (st_netpattern_view_t){actual[i].pattern, actual[i].pattern_length},
            expected[i].pattern) ||
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

static int unit_suggestion_lists_equal(const st_suggestion_t *left,
                                       size_t left_count,
                                       const st_suggestion_t *right,
                                       size_t right_count) {
  if (left_count != right_count || (left_count != 0 && (!left || !right)))
    return 0;
  for (size_t i = 0; i < left_count; i++)
    if (left[i].pattern_length != right[i].pattern_length ||
        memcmp(left[i].pattern, right[i].pattern, left[i].pattern_length) !=
            0 ||
        left[i].count != right[i].count ||
        left[i].confidence != right[i].confidence)
      return 0;
  return 1;
}

static int unit_suggestions_replay_exactly(const st_suggestion_t *suggestions,
                                           size_t suggestion_count,
                                           const char *const *commands,
                                           size_t command_count) {
  for (size_t suggestion = 0; suggestion < suggestion_count; suggestion++) {
    ASSERT(st_netpattern_validate_view(
               (st_netpattern_view_t){suggestions[suggestion].pattern,
                                      suggestions[suggestion].pattern_length},
               NULL) == ST_OK);
    ASSERT(suggestions[suggestion].confidence >= 0.0 &&
           suggestions[suggestion].confidence <= 1.0);
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
    ASSERT(policy != NULL);
    ASSERT(st_policy_add_netpattern_view(
               policy, (st_netpattern_view_t){
                           suggestions[suggestion].pattern,
                           suggestions[suggestion].pattern_length}) == ST_OK);
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

static uint32_t unit_history_random_next(uint32_t *state) {
  *state = *state * UINT32_C(1664525) + UINT32_C(1013904223);
  return *state;
}

typedef struct {
  const char *command;
  const char *argument;
  st_token_type_t type;
} unit_oracle_observation_t;

typedef struct {
  char pattern[ST_MAX_NETPATTERN_LEN];
  uint32_t count;
  double confidence;
} unit_oracle_suggestion_t;

static int unit_compare_oracle_suggestions(const void *left,
                                           const void *right) {
  const unit_oracle_suggestion_t *a = left;
  const unit_oracle_suggestion_t *b = right;
  if (a->confidence != b->confidence)
    return a->confidence > b->confidence ? -1 : 1;
  if (a->count != b->count)
    return a->count > b->count ? -1 : 1;
  return strcmp(a->pattern, b->pattern);
}

/* Independent two-token learner model.  It operates on the observation
 * multiset directly and never examines the production trie. */
static size_t unit_oracle_two_token_suggestions(
    const unit_oracle_observation_t *corpus, size_t corpus_count,
    const size_t *history, size_t history_count, uint32_t min_support,
    double min_confidence, size_t limit, const char *blacklist,
    unit_oracle_suggestion_t *out, size_t capacity) {
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

    unit_oracle_suggestion_t candidates[ST_TYPE_COUNT + 32] = {0};
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
      unit_oracle_suggestion_t value = candidates[candidate];
      if (value.count < min_support || value.confidence < min_confidence ||
          (blacklist && strcmp(value.pattern, blacklist) == 0))
        continue;
      ASSERT(out_count < capacity);
      out[out_count++] = value;
    }
  }
  qsort(out, out_count, sizeof(*out), unit_compare_oracle_suggestions);
  return out_count > limit ? limit : out_count;
}

static int unit_test_independent_two_token_learner_oracle(void) {
  static const unit_oracle_observation_t corpus[] = {
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
      history[i] = unit_history_random_next(&state) %
                   (sizeof(corpus) / sizeof(corpus[0]));

    for (size_t configuration = 0; configuration < 2; configuration++) {
      uint32_t min_support = configuration == 0 ? 1 : 3;
      double min_confidence = configuration == 0 ? 0.0 : 0.2;
      size_t limit = configuration == 0 ? 20 : 5;
      const char *blacklist = configuration == 0 ? NULL : "copy *";
      st_learner_t *learner = st_learner_new(&(st_learner_config_t){
          .min_support = min_support,
          .min_confidence = min_confidence,
          .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
      ASSERT(learner != NULL);
      st_learner_config_t learner_config = {0};
      ASSERT(st_learner_get_config(learner, &learner_config) == ST_OK);
      learner_config.max_suggestions = limit;
      ASSERT(st_learner_set_config(learner, &learner_config) == ST_OK);
      if (blacklist)
        ASSERT(test_st_blacklist_add(learner, blacklist) == ST_OK);

      for (size_t i = 0; i < HISTORY_COUNT; i++) {
        const unit_oracle_observation_t *item = &corpus[history[i]];
        st_token_t tokens[] = {
            {.text = (char *)item->command, .type = ST_TYPE_LITERAL},
            {.text = (char *)item->argument, .type = item->type},
        };
        st_token_array_t parsed = {.tokens = tokens, .count = 2};
        ASSERT(st_learner_feed_tokens(learner, &parsed) == ST_OK);
      }

      unit_oracle_suggestion_t expected[ORACLE_CAPACITY] = {0};
      size_t expected_count = unit_oracle_two_token_suggestions(
          corpus, sizeof(corpus) / sizeof(corpus[0]), history, HISTORY_COUNT,
          min_support, min_confidence, limit, blacklist, expected,
          ORACLE_CAPACITY);
      size_t actual_count = 0;
      st_suggestion_t *actual = st_learner_suggest(learner, &actual_count);
      ASSERT(actual_count == expected_count);
      for (size_t i = 0; i < expected_count; i++) {
        ASSERT(actual != NULL);
        ASSERT(test_pattern_is_cpl(
            (st_netpattern_view_t){actual[i].pattern, actual[i].pattern_length},
            expected[i].pattern));
        ASSERT(actual[i].count == expected[i].count);
        ASSERT(actual[i].confidence == expected[i].confidence);
      }
      st_suggestion_list_free(actual, actual_count);
      st_learner_free(learner);
    }
  }
  return 1;
}

static int unit_test_suggestion_thresholds_and_limit(void) {
  static const unit_expected_suggestion_t expected_capped[] = {
      {"alpha #n", 3, 1.0},
      {"beta #n", 3, 1.0},
      {"delta #n", 3, 1.0},
  };
  st_learner_t *learner = st_learner_new(
      &(st_learner_config_t){.min_support = 6,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(learner != NULL);
  for (size_t i = 0; i < 5; i++) {
    char command[64];
    snprintf(command, sizeof(command), "ls -l /tmp/file%zu", i);
    ASSERT(test_st_feed(learner, command) == ST_OK);
  }
  size_t count = 99;
  st_suggestion_t *suggestions = st_learner_suggest(learner, &count);
  ASSERT(!suggestions && count == 0);
  st_learner_free(learner);

  learner = st_learner_new(
      &(st_learner_config_t){.min_support = 3,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(learner != NULL);
  st_learner_config_t learner_config = {0};
  ASSERT(st_learner_get_config(learner, &learner_config) == ST_OK);
  learner_config.max_suggestions = 3;
  ASSERT(st_learner_set_config(learner, &learner_config) == ST_OK);
  static const char *families[] = {"alpha", "beta", "delta", "gamma"};
  for (size_t family = 0; family < 4; family++)
    for (size_t i = 1; i <= 3; i++) {
      char command[32];
      snprintf(command, sizeof(command), "%s %zu", families[family], i);
      ASSERT(test_st_feed(learner, command) == ST_OK);
    }
  suggestions = st_learner_suggest(learner, &count);
  ASSERT(unit_suggestions_equal(suggestions, count, expected_capped,
                                sizeof(expected_capped) /
                                    sizeof(expected_capped[0])));
  st_suggestion_list_free(suggestions, count);
  learner_config.max_suggestions = 0;
  ASSERT(st_learner_set_config(learner, &learner_config) == ST_OK);
  count = 17;
  ASSERT(st_learner_suggest(learner, &count) == NULL && count == 0);
  st_learner_free(learner);
  return 1;
}

static int unit_test_confidence_ranking(void) {
  static const unit_expected_suggestion_t expected[] = {
      {"git commit #sopt *", 8, 1.0},
      {"git *", 2, 0.2},
  };
  st_learner_t *learner = st_learner_new(
      &(st_learner_config_t){.min_support = 2,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(learner != NULL);
  for (size_t i = 0; i < 8; i++) {
    char command[64];
    snprintf(command, sizeof(command), "git commit -m msg%zu", i);
    ASSERT(test_st_feed(learner, command) == ST_OK);
  }
  ASSERT(test_st_feed(learner, "git status") == ST_OK);
  ASSERT(test_st_feed(learner, "git log") == ST_OK);

  size_t count = 0;
  st_suggestion_t *suggestions = st_learner_suggest(learner, &count);
  ASSERT(unit_suggestions_equal(suggestions, count, expected,
                                sizeof(expected) / sizeof(expected[0])));
  static const char *commands[] = {"git commit -m msg0", "git commit -m msg1",
                                   "git commit -m msg2", "git commit -m msg3",
                                   "git commit -m msg4", "git commit -m msg5",
                                   "git commit -m msg6", "git commit -m msg7",
                                   "git status",         "git log"};
  ASSERT(unit_suggestions_replay_exactly(
      suggestions, count, commands, sizeof(commands) / sizeof(commands[0])));
  st_suggestion_list_free(suggestions, count);
  st_learner_free(learner);
  return 1;
}

static int unit_test_blacklist_filters_exact_suggestion(void) {
  st_learner_t *learner = st_learner_new(
      &(st_learner_config_t){.min_support = 3,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
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
  st_suggestion_t *suggestions = st_learner_suggest(learner, &count);
  ASSERT(suggestions == NULL && count == 0);
  st_suggestion_list_free(suggestions, count);
  st_learner_free(learner);
  return 1;
}

static int unit_test_blacklist_allocation_failures_are_atomic(void) {
  st_test_alloc_reset();
  st_learner_t *probe = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
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
    st_learner_t *learner = st_learner_new(
        &(st_learner_config_t){.min_support = 1,
                               .min_confidence = 0.0,
                               .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
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

static int unit_test_serialization_roundtrip_and_validation(void) {
  char path[] = "/tmp/shelltype-learner-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  snprintf(unit_learner_temp_path, sizeof(unit_learner_temp_path), "%s", path);
  close(fd);

  st_learner_t *source = st_learner_new(
      &(st_learner_config_t){.min_support = 3,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  st_learner_t *loaded = st_learner_new(
      &(st_learner_config_t){.min_support = 3,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(source && loaded);
  ASSERT(test_st_feed(loaded, "obsolete command") == ST_OK);
  ASSERT(st_learner_load(loaded, "/tmp/shelltype-file-does-not-exist") ==
         ST_ERR_IO);
  ASSERT(unit_find_child(loaded->trie.root, "obsolete") != NULL);
  for (size_t i = 0; i < 4; i++) {
    char command[128];
    snprintf(command, sizeof(command), "cat /var/log/file%zu | grep ERROR", i);
    ASSERT(test_st_feed(source, command) == ST_OK);
  }
  st_learner_t *empty_source = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(empty_source != NULL && st_learner_save(empty_source, path) == ST_OK);
  st_learner_free(empty_source);
  ASSERT(st_learner_load(loaded, path) == ST_OK);
  ASSERT(loaded->trie.total_commands == 0);
  ASSERT(unit_find_child(loaded->trie.root, "obsolete") == NULL);

  /* A serialization allocation failure must not replace the previous file. */
  st_test_alloc_reset();
  ASSERT(st_learner_save(source, path) == ST_OK);
  size_t save_allocations = st_test_alloc_count();
  ASSERT(save_allocations > 0);
  bool save_failure_observed = false;
  for (size_t fail_at = 1; fail_at <= save_allocations; fail_at++) {
    FILE *keep = fopen(path, "w");
    ASSERT(keep != NULL && fputs("keep-existing\n", keep) >= 0 &&
           fclose(keep) == 0);
    st_test_alloc_fail_at(fail_at);
    st_error_t save_error = st_learner_save(source, path);
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
  ASSERT(st_learner_save(source, path) == ST_OK);
  ASSERT(st_learner_load(loaded, path) == ST_OK);
  ASSERT(loaded->trie.total_commands == source->trie.total_commands);
  ASSERT(unit_find_child(loaded->trie.root, "obsolete") == NULL);

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
  ASSERT(st_learner_load(loaded, path) == ST_ERR_FORMAT);
  ASSERT(loaded->trie.total_commands == source->trie.total_commands);
  ASSERT(unit_find_child(loaded->trie.root, "git") == NULL);
  ASSERT(st_learner_save(source, path) == ST_OK);

  size_t source_count = 0, loaded_count = 0;
  st_suggestion_t *source_items = st_learner_suggest(source, &source_count);
  st_suggestion_t *loaded_items = st_learner_suggest(loaded, &loaded_count);
  ASSERT(source_items && loaded_items && source_count == 1 &&
         unit_suggestion_lists_equal(source_items, source_count, loaded_items,
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
    ASSERT(st_learner_load(loaded, path) == ST_ERR_FORMAT);
    ASSERT(loaded->trie.total_commands == source->trie.total_commands);
    ASSERT(loaded->trie.root->num_children == original_children);
    ASSERT(unit_find_child(loaded->trie.root, "git") == NULL);
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
    ASSERT(st_learner_load(loaded, path) == ST_ERR_FORMAT);
    ASSERT(loaded->trie.total_commands == source->trie.total_commands);
    ASSERT(loaded->trie.root->num_children == original_children);
  }

  FILE *deep = fopen(path, "w");
  ASSERT(deep && fputs("# ST trie dump v4\n# total_commands=1\n", deep) >= 0);
  for (size_t i = 1; i <= ST_MAX_CMD_TOKENS + 1; i++)
    ASSERT(fprintf(deep, "%zu\t%zu\tL\t0\t1\t-\t0\t78\n", i, i - 1) > 0);
  ASSERT(fclose(deep) == 0);
  ASSERT(st_learner_load(loaded, path) == ST_ERR_FORMAT);
  ASSERT(loaded->trie.total_commands == source->trie.total_commands);

  FILE *wide = fopen(path, "w");
  ASSERT(wide && fputs("# ST trie dump v4\n# total_commands=1\n"
                       "1\t0\tL\t0\t1\t-\t0\t",
                       wide) >= 0);
  for (size_t i = 0; i < ST_MAX_TOKEN_LEN; i++)
    ASSERT(fputs("61", wide) >= 0);
  ASSERT(fputc('\n', wide) != EOF && fclose(wide) == 0);
  ASSERT(st_learner_load(loaded, path) == ST_ERR_FORMAT);
  ASSERT(loaded->trie.total_commands == source->trie.total_commands);

  /* The provisional line-oriented v4 was never released.  It must not be
   * mistaken for the canonical framed v4 format, including with CRLFs. */
  FILE *crlf = fopen(path, "w");
  ASSERT(crlf != NULL);
  ASSERT(fputs("# ST trie dump v4\r\n# total_commands=1\r\n"
               "1\t0\tT\t6\t1\t!\t1\t-\r\n",
               crlf) >= 0);
  ASSERT(fclose(crlf) == 0);
  ASSERT(st_learner_load(loaded, path) == ST_ERR_FORMAT);
  ASSERT(loaded->trie.total_commands == source->trie.total_commands);
  ASSERT(loaded->trie.root->num_children == original_children);
  ASSERT(test_st_feed(loaded, "git status") == ST_OK);
  ASSERT(loaded->trie.total_commands == source->trie.total_commands + 1);

  if (access("/dev/full", W_OK) == 0)
    ASSERT(st_learner_save(source, "/dev/full") == ST_ERR_IO);

  st_suggestion_list_free(source_items, source_count);
  st_suggestion_list_free(loaded_items, loaded_count);
  st_learner_free(source);
  st_learner_free(loaded);
  unlink(path);
  return 1;
}

static int unit_test_learner_numeric_fields_reject_hidden_bytes(void) {
  char path[] = "/tmp/shelltype-numeric-fields-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(unit_learner_temp_path, sizeof(unit_learner_temp_path), "%s", path);
  st_learner_t *expected = unit_baseline_learner();
  st_learner_t *actual = unit_baseline_learner();
  ASSERT(expected && actual);
  const size_t numeric_fields[] = {0, 1, 3, 4, 6};
  const char *fields[] = {"1", "0", "L", "0", "1", "-", "0", "echo"};
  const char *tails[] = {"\0junk", "x", "42949672960"};
  const size_t tail_lengths[] = {5, 1, 11};
  /* Each corrupt fixture has valid framing and CRC so numeric validation,
   * rather than checksum rejection, must preserve the existing learner. */
  for (size_t field_index = 0; field_index <= 5; field_index++) {
    const bool valid_control = field_index == 5;
    for (size_t corruption = 0; corruption < (valid_control ? 1u : 3u);
         corruption++) {
      char payload[256], record[300];
      size_t used = 0, written = 0;
      for (size_t i = 0; i < 8; i++) {
        char altered[32];
        const char *value = fields[i];
        size_t length = strlen(value);
        if (!valid_control && i == numeric_fields[field_index]) {
          memcpy(altered, value, length);
          memcpy(altered + length, tails[corruption], tail_lengths[corruption]);
          length += tail_lengths[corruption];
          value = altered;
        }
        ASSERT(shell_netstring_write(payload + used, sizeof(payload) - used,
                                     value, length,
                                     &written) == SHELL_NETSTRING_OK);
        used += written;
      }
      ASSERT(shell_netstring_write(record, sizeof(record) - 1, payload, used,
                                   &written) == SHELL_NETSTRING_OK);
      record[written++] = '\n';
      uint32_t crc = st_crc32_update(record, written, 0);
      FILE *fp = fopen(path, "wb");
      ASSERT(fp != NULL);
      ASSERT(fputs("# shelltype-learner v5\n# total-commands: 1\n# nodes: 1\n",
                   fp) >= 0);
      ASSERT(fwrite(record, 1, written, fp) == written);
      ASSERT(fprintf(fp, "# CRC32: %08x\n", crc) > 0 && fclose(fp) == 0);
      if (valid_control) {
        ASSERT(st_learner_load(actual, path) == ST_OK);
        ASSERT(actual->trie.total_commands == 1);
      } else {
        ASSERT(st_learner_load(actual, path) == ST_ERR_FORMAT);
        ASSERT(actual->trie.total_commands == expected->trie.total_commands &&
               unit_nodes_equal(actual->trie.root, expected->trie.root));
      }
    }
  }
  st_learner_free(actual);
  st_learner_free(expected);
  ASSERT(unlink(path) == 0);
  unit_learner_temp_path[0] = '\0';
  return 1;
}

static int unit_test_learner_save_io_failures_are_atomic(void) {
  char directory[] = "/tmp/shelltype-learner-io-XXXXXX";
  ASSERT(mkdtemp(directory) != NULL);
  strcpy(unit_learner_save_directory, directory);
  char path[256];
  snprintf(path, sizeof(path), "%s/learner", directory);
  int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(unit_learner_temp_path, sizeof(unit_learner_temp_path), "%s", path);
  st_learner_t *learner = unit_baseline_learner();
  ASSERT(learner != NULL);

  st_test_io_reset();
  ASSERT(st_learner_save(learner, path) == ST_OK);
  size_t operation_count = st_test_io_count();
  ASSERT(operation_count >= 4);
  static const char sentinel[] = "preserve-existing-learner";
  char template_path[sizeof(path) + 8];
  ASSERT(test_atomic_template_path(path, template_path, sizeof(template_path)));

  for (size_t fail_at = 1; fail_at <= operation_count; fail_at++) {
    FILE *fp = fopen(path, "wb");
    ASSERT(fp != NULL);
    ASSERT(fwrite(sentinel, 1, sizeof(sentinel) - 1, fp) ==
           sizeof(sentinel) - 1);
    ASSERT(fclose(fp) == 0);
    fp = fopen(template_path, "wb");
    ASSERT(fp != NULL);
    strcpy(unit_learner_template_path, template_path);
    ASSERT(fwrite("keep", 1, 4, fp) == 4 && fclose(fp) == 0);
    int next_fd = open(path, O_RDONLY);
    ASSERT(next_fd >= 0 && close(next_fd) == 0);
    st_test_io_fail_at(fail_at);
    st_error_t error = st_learner_save(learner, path);
    st_test_io_reset();
    ASSERT(error == ST_ERR_IO);
    errno = 0;
    ASSERT(fcntl(next_fd, F_GETFD) == -1 && errno == EBADF);

    char contents[128] = {0};
    fp = fopen(template_path, "rb");
    ASSERT(fp != NULL);
    size_t template_length = fread(contents, 1, sizeof(contents), fp);
    ASSERT(!ferror(fp) && fclose(fp) == 0);
    ASSERT(template_length == 4 && memcmp(contents, "keep", 4) == 0);
    ASSERT(unlink(template_path) == 0);
    unit_learner_template_path[0] = '\0';
    fp = fopen(path, "rb");
    ASSERT(fp != NULL);
    size_t length = fread(contents, 1, sizeof(contents), fp);
    ASSERT(!ferror(fp) && fclose(fp) == 0);
    bool old_file = length == sizeof(sentinel) - 1 &&
                    memcmp(contents, sentinel, length) == 0;
    /* Begin's I/O steps open the parent, inspect the entry, create the
     * temporary file and fdopen it. None may
     * replace the destination on failure, even with a valid new save. */
    if (fail_at <= 4)
      ASSERT(old_file);
    if (!old_file) {
      st_learner_t *check = st_learner_new(&(st_learner_config_t){
          .min_support = 1,
          .min_confidence = 0.0,
          .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
      ASSERT(check != NULL && st_learner_load(check, path) == ST_OK);
      ASSERT(check->trie.total_commands == learner->trie.total_commands);
      st_learner_free(check);
    }
    ASSERT(unit_no_learner_save_temps(path));
    ASSERT(learner->trie.total_commands == 2);
  }

  st_learner_free(learner);
  ASSERT(unlink(path) == 0);
  unit_learner_temp_path[0] = '\0';
  ASSERT(rmdir(directory) == 0);
  unit_learner_save_directory[0] = '\0';
  return 1;
}

static int unit_feed_suggestion_allocation_fixture(st_learner_t *learner,
                                                   bool overlapping) {
  if (overlapping) {
    static const char *const records[] = {"4:tool,2:42,5:alpha,4:1MiB,",
                                          "4:tool,2:42,4:beta,4:2MiB,",
                                          "4:tool,2:42,5:gamma,4:1GiB,",
                                          "4:tool,2:42,5:delta,4:2GiB,",
                                          "4:tool,8:a1b2c3d4,4:zeta,4:1MiB,",
                                          "4:tool,8:a1b2c3d4,4:zeta,4:2GiB,",
                                          "5:ztool,2:42,",
                                          "6:zztool,2:42,"};
    for (size_t i = 0; i < sizeof(records) / sizeof(records[0]); i++)
      ASSERT(st_learner_feed_netargv_view(
                 learner,
                 (st_netargv_view_t){records[i], strlen(records[i])}) == ST_OK);
  }
  /* The second fixture also exceeds the initial candidate/result capacity.
   * Its output cap exercises cleanup of accounted but unpublished rules. */
  for (size_t i = 0; i < (overlapping ? 70 : 8); i++) {
    char command[64];
    if (overlapping)
      snprintf(command, sizeof(command), "command%zu /tmp/file", i);
    else
      snprintf(command, sizeof(command), "copy /tmp/file%zu", i);
    ASSERT(test_st_feed(learner, command) == ST_OK);
  }
  return 1;
}

static int unit_check_suggestion_allocation_failures(bool overlapping) {
  st_test_alloc_reset();
  st_learner_t *probe = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(probe != NULL);
  ASSERT(unit_feed_suggestion_allocation_fixture(probe, overlapping));
  st_test_alloc_reset();
  size_t probe_count = 0;
  st_suggestion_t *probe_suggestions = st_learner_suggest(probe, &probe_count);
  size_t allocations = st_test_alloc_count();
  ASSERT(probe_suggestions != NULL && probe_count > 0 && allocations > 0);

  st_learner_t *learner = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(learner != NULL);
  ASSERT(unit_feed_suggestion_allocation_fixture(learner, overlapping));

  bool observed = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_reset();
    size_t count = 99;
    st_test_alloc_fail_at(fail_at);
    st_suggestion_t *suggestions = st_learner_suggest(learner, &count);
    st_test_alloc_reset();
    if (!suggestions) {
      observed = true;
      ASSERT(count == 0);
    } else {
      ASSERT(count > 0);
      st_suggestion_list_free(suggestions, count);
    }
    ASSERT(unit_nodes_equal(probe->trie.root, learner->trie.root) &&
           probe->trie.total_commands == learner->trie.total_commands);
    /* An allocation failure must not consume observations or poison the next
     * accounting pass. The same learner recovers the identical ordered rules.
     */
    suggestions = st_learner_suggest(learner, &count);
    ASSERT(suggestions != NULL && count == probe_count);
    for (size_t i = 0; i < count; i++)
      ASSERT(suggestions[i].pattern_length ==
                 probe_suggestions[i].pattern_length &&
             memcmp(suggestions[i].pattern, probe_suggestions[i].pattern,
                    suggestions[i].pattern_length) == 0 &&
             suggestions[i].count == probe_suggestions[i].count &&
             suggestions[i].confidence == probe_suggestions[i].confidence);
    st_suggestion_list_free(suggestions, count);
  }
  ASSERT(observed);
  st_suggestion_list_free(probe_suggestions, probe_count);
  st_learner_free(probe);
  st_learner_free(learner);
  return 1;
}

static int unit_test_suggestion_allocation_failures_are_clean(void) {
  ASSERT(unit_check_suggestion_allocation_failures(false));
  ASSERT(unit_check_suggestion_allocation_failures(true));
  return 1;
}

static int unit_test_compound_support_uses_indexed_prefixes(void) {
  enum { FAMILIES = 256 };
  st_learner_t *learner = st_learner_new(&(st_learner_config_t){
      .min_support = 1, .min_confidence = 0.0, .max_suggestions = FAMILIES});
  ASSERT(learner != NULL);
  char command[128];
  for (size_t i = 0; i < FAMILIES; i++)
    for (size_t value = 42; value < 44; value++) {
      snprintf(command, sizeof(command), "tool --field%zu=%zu marker%zu", i,
               value, i);
      ASSERT(test_st_feed(learner, command) == ST_OK);
    }
  size_t count = 0;
  st_suggestion_t *suggestions = st_learner_suggest(learner, &count);
  ASSERT(suggestions != NULL && count == FAMILIES);
  /* Operation count, not a timing heuristic: each literal observation visits
   * its indexed compound, rather than testing all 256 alternative prefixes. */
  ASSERT(st_test_learner_support_work() <= FAMILIES * 64);
  st_policy_ctx_t *context = st_policy_ctx_new();
  ASSERT(context != NULL);
  for (size_t i = 0; i < count; i++) {
    ASSERT(suggestions[i].count == 2 &&
           suggestions[i].confidence == 1.0 / FAMILIES);
    st_policy_t *policy = st_policy_new(context);
    ASSERT(policy != NULL &&
           st_policy_add_netpattern_view(
               policy, (st_netpattern_view_t){suggestions[i].pattern,
                                              suggestions[i].pattern_length}) ==
               ST_OK);
    uint32_t replay = 0;
    for (size_t family = 0; family < FAMILIES; family++)
      for (size_t value = 42; value < 44; value++) {
        snprintf(command, sizeof(command), "tool --field%zu=%zu marker%zu",
                 family, value, family);
        st_eval_result_t result = {0};
        ASSERT(test_st_policy_eval(policy, command, &result) == ST_OK);
        replay += result.matches;
      }
    ASSERT(replay == suggestions[i].count);
    st_policy_free(policy);
  }
  st_policy_ctx_release(context);
  st_suggestion_list_free(suggestions, count);
  st_learner_free(learner);
  return 1;
}

static int unit_test_load_allocation_failures_preserve_learner(void) {
  char path[] = "/tmp/shelltype-load-fail-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  snprintf(unit_learner_temp_path, sizeof(unit_learner_temp_path), "%s", path);
  close(fd);

  st_test_alloc_reset();
  st_learner_t *source = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  st_learner_t *loaded = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(source != NULL && loaded != NULL);
  ASSERT(test_st_feed(source, "source command") == ST_OK);
  ASSERT(st_learner_save(source, path) == ST_OK);
  ASSERT(test_st_feed(loaded, "keep command") == ST_OK);

  st_test_alloc_reset();
  ASSERT(st_learner_load(loaded, path) == ST_OK);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);
  st_learner_free(loaded);

  bool observed = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    loaded = st_learner_new(
        &(st_learner_config_t){.min_support = 1,
                               .min_confidence = 0.0,
                               .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
    ASSERT(loaded != NULL);
    ASSERT(test_st_feed(loaded, "keep command") == ST_OK);
    st_test_alloc_fail_at(fail_at);
    st_error_t err = st_learner_load(loaded, path);
    st_test_alloc_reset();
    if (err == ST_ERR_MEMORY) {
      observed = true;
      ASSERT(unit_find_child(loaded->trie.root, "keep") != NULL);
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
  ASSERT(unlink(path) == 0);
  unit_learner_temp_path[0] = '\0';
  return 1;
}

static int unit_test_learner_load_read_failures_preserve_state(void) {
  char path[] = "/tmp/shelltype-learner-read-fail-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(unit_learner_temp_path, sizeof(unit_learner_temp_path), "%s", path);
  st_learner_t *source = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(source != NULL);
  ASSERT(test_st_feed(source, "replacement 42") == ST_OK);
  ASSERT(test_st_feed(source, "replacement 43") == ST_OK);
  ASSERT(st_learner_save(source, path) == ST_OK);

  st_learner_t *probe = unit_baseline_learner();
  ASSERT(probe != NULL);
  st_test_io_reset();
  ASSERT(st_learner_load(probe, path) == ST_OK);
  size_t read_count = st_test_read_count();
  st_test_io_reset();
  ASSERT(read_count > 0);
  st_learner_free(probe);

  for (size_t fail_at = 1; fail_at <= read_count; fail_at++) {
    st_learner_t *learner = unit_baseline_learner();
    st_learner_t *expected = unit_baseline_learner();
    ASSERT(learner && expected);
    st_test_read_fail_at(fail_at);
    ASSERT(st_learner_load(learner, path) == ST_ERR_IO);
    st_test_io_reset();
    ASSERT(learner->trie.total_commands == expected->trie.total_commands);
    ASSERT(unit_nodes_equal(learner->trie.root, expected->trie.root));
    ASSERT(test_st_feed(learner, "after failure") == ST_OK);
    st_learner_free(expected);
    st_learner_free(learner);
  }

  st_learner_t *close_failed = unit_baseline_learner();
  st_learner_t *expected = unit_baseline_learner();
  ASSERT(close_failed && expected);
  st_test_io_fail_at(1);
  ASSERT(st_learner_load(close_failed, path) == ST_ERR_IO);
  st_test_io_reset();
  ASSERT(unit_nodes_equal(close_failed->trie.root, expected->trie.root));
  st_learner_free(expected);
  st_learner_free(close_failed);
  st_learner_free(source);
  ASSERT(unlink(path) == 0);
  unit_learner_temp_path[0] = '\0';
  return 1;
}

static const st_suggestion_t *unit_find_suggestion(const st_suggestion_t *items,
                                                   size_t count,
                                                   const char *pattern) {
  for (size_t i = 0; i < count; i++)
    if (test_pattern_is_cpl(
            (st_netpattern_view_t){items[i].pattern, items[i].pattern_length},
            pattern))
      return &items[i];
  return NULL;
}

static int unit_test_metadata_aggregation_and_v4_roundtrip(void) {
  char path[] = "/tmp/shelltype-metadata-v2-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0 && close(fd) == 0);
  snprintf(unit_learner_temp_path, sizeof(unit_learner_temp_path), "%s", path);

  st_learner_t *uniform = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  st_learner_t *mixed_a = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  st_learner_t *mixed_b = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  st_learner_t *loaded = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  ASSERT(uniform && mixed_a && mixed_b && loaded);
  const size_t observation_count = 40;
  for (size_t i = 0; i < observation_count; i++) {
    char mib[64], gib[64];
    snprintf(mib, sizeof(mib), "allocate %zuMiB", i + 1);
    snprintf(gib, sizeof(gib), "allocate %zuGiB", i + 1);
    ASSERT(test_st_feed(uniform, mib) == ST_OK);
    ASSERT(test_st_feed(mixed_a, i == observation_count - 1 ? gib : mib) ==
           ST_OK);
    ASSERT(test_st_feed(mixed_b, i == 0 ? gib : mib) == ST_OK);
  }

  size_t uniform_count = 0, mixed_a_count = 0, mixed_b_count = 0;
  st_suggestion_t *uniform_items = st_learner_suggest(uniform, &uniform_count);
  st_suggestion_t *mixed_a_items = st_learner_suggest(mixed_a, &mixed_a_count);
  st_suggestion_t *mixed_b_items = st_learner_suggest(mixed_b, &mixed_b_count);
  ASSERT(uniform_items && mixed_a_items && mixed_b_items);
  ASSERT(
      unit_find_suggestion(uniform_items, uniform_count, "allocate #size.MiB"));
  ASSERT(unit_find_suggestion(mixed_a_items, mixed_a_count, "allocate #size"));
  ASSERT(unit_find_suggestion(mixed_b_items, mixed_b_count, "allocate #size"));
  ASSERT(!unit_find_suggestion(mixed_a_items, mixed_a_count,
                               "allocate #size.MiB"));
  ASSERT(!unit_find_suggestion(mixed_b_items, mixed_b_count,
                               "allocate #size.MiB"));

  ASSERT(st_learner_save(uniform, path) == ST_OK);
  ASSERT(st_learner_load(loaded, path) == ST_OK);
  size_t loaded_count = 0;
  st_suggestion_t *loaded_items = st_learner_suggest(loaded, &loaded_count);
  ASSERT(loaded_items &&
         unit_suggestion_lists_equal(uniform_items, uniform_count, loaded_items,
                                     loaded_count));

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
    st_learner_t *family = st_learner_new(
        &(st_learner_config_t){.min_support = 1,
                               .min_confidence = 0.0,
                               .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
    st_learner_t *family_loaded = st_learner_new(
        &(st_learner_config_t){.min_support = 1,
                               .min_confidence = 0.0,
                               .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
    ASSERT(family && family_loaded);
    ASSERT(test_st_feed(family, metadata_cases[i].first) == ST_OK);
    ASSERT(test_st_feed(family, metadata_cases[i].second) == ST_OK);
    size_t family_count = 0;
    st_suggestion_t *family_items = st_learner_suggest(family, &family_count);
    ASSERT(unit_find_suggestion(family_items, family_count,
                                metadata_cases[i].specific));
    ASSERT(st_learner_save(family, path) == ST_OK);
    ASSERT(st_learner_load(family_loaded, path) == ST_OK);
    size_t family_loaded_count = 0;
    st_suggestion_t *family_loaded_items =
        st_learner_suggest(family_loaded, &family_loaded_count);
    ASSERT(unit_suggestion_lists_equal(
        family_items, family_count, family_loaded_items, family_loaded_count));

    if (metadata_cases[i].different) {
      ASSERT(test_st_feed(family, metadata_cases[i].different) == ST_OK);
      st_suggestion_list_free(family_items, family_count);
      family_items = st_learner_suggest(family, &family_count);
      ASSERT(unit_find_suggestion(family_items, family_count,
                                  metadata_cases[i].generic));
      ASSERT(!unit_find_suggestion(family_items, family_count,
                                   metadata_cases[i].specific));
    }
    st_suggestion_list_free(family_items, family_count);
    st_suggestion_list_free(family_loaded_items, family_loaded_count);
    st_learner_free(family);
    st_learner_free(family_loaded);
  }

  FILE *legacy = fopen(path, "w");
  ASSERT(legacy && fputs("# ST trie dump\n# total_commands=0\n", legacy) >= 0 &&
         fclose(legacy) == 0);
  ASSERT(st_learner_load(loaded, path) == ST_ERR_FORMAT);
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
    ASSERT(st_learner_load(loaded, path) == ST_ERR_FORMAT);
    ASSERT(loaded->trie.total_commands == uniform->trie.total_commands);
  }

  st_suggestion_list_free(uniform_items, uniform_count);
  st_suggestion_list_free(mixed_a_items, mixed_a_count);
  st_suggestion_list_free(mixed_b_items, mixed_b_count);
  st_suggestion_list_free(loaded_items, loaded_count);
  st_learner_free(uniform);
  st_learner_free(mixed_a);
  st_learner_free(mixed_b);
  st_learner_free(loaded);
  ASSERT(unlink(path) == 0);
  unit_learner_temp_path[0] = '\0';
  return 1;
}

static int run_unit(int argc, char **argv) {
  (void)argc;
  (void)argv;
  atexit(unit_cleanup_learner_temp_file);
  printf("Running shelltype unit tests...\n\n");
  TEST(unit_test_learner_state_transitions);
  TEST(unit_test_learner_input_boundaries);
  TEST(unit_test_learner_configuration_boundaries);
  TEST(unit_test_learner_stats_contract);
  TEST(unit_test_independent_two_token_learner_oracle);
  TEST(unit_test_suggestion_thresholds_and_limit);
  TEST(unit_test_confidence_ranking);
  TEST(unit_test_blacklist_filters_exact_suggestion);
  TEST(unit_test_blacklist_allocation_failures_are_atomic);
  TEST(unit_test_serialization_roundtrip_and_validation);
  TEST(unit_test_learner_numeric_fields_reject_hidden_bytes);
  TEST(unit_test_learner_save_io_failures_are_atomic);
  TEST(unit_test_suggestion_allocation_failures_are_clean);
  TEST(unit_test_compound_support_uses_indexed_prefixes);
  TEST(unit_test_load_allocation_failures_preserve_learner);
  TEST(unit_test_learner_load_read_failures_preserve_state);
  TEST(unit_test_metadata_aggregation_and_v4_roundtrip);
  TEST(unit_test_feed_is_atomic);
  TEST(unit_test_compound_option_suggestion);
  printf("\nResults: %d/%d passed, %d failed\n", unit_tests_passed,
         unit_tests_run, unit_tests_failed);
  return unit_tests_failed > 0 ? 1 : 0;
}
#undef ASSERT
#undef TEST

/* --- arena (from test_arena.c) --- */
/*
 * Focused tests for ShellType's internal bump allocator.
 */

#define ASSERT(condition)                                                      \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "Assertion failed: %s at %s:%d\n", #condition, __FILE__, \
              __LINE__);                                                       \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static int run_arena(int argc, char **argv) {
  (void)argc;
  (void)argv;
  arena_t arena = {0};
  ASSERT(arena_init(&arena, 1));
  ASSERT(arena_used(&arena) == 0);

  unsigned char *first = arena_alloc(&arena, 1);
  ASSERT(first != NULL);
  ASSERT(arena_used(&arena) == 8);
  memset(first, 0xa5, 8);

  size_t capacity = arena.size;
  char *base = arena.base;
  unsigned char *exact = arena_alloc(&arena, capacity - arena.used);
  ASSERT(exact == (unsigned char *)base + 8);
  ASSERT(arena.base == base);
  ASSERT(arena_used(&arena) == capacity);
  exact[capacity - 9] = 0x5a;

  void *zero = arena_alloc(&arena, 0);
  ASSERT(zero == arena.base + capacity);
  ASSERT(arena.base == base);
  ASSERT(arena_used(&arena) == capacity);

  unsigned char *grown = arena_alloc(&arena, 1);
  ASSERT(grown == (unsigned char *)arena.base + capacity);
  ASSERT(arena.size == capacity * 2);
  ASSERT(arena_used(&arena) == capacity + 8);
  ASSERT(memcmp(arena.base, "\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5", 8) == 0);
  ASSERT((unsigned char)arena.base[capacity - 1] == 0x5a);

  size_t used_before_reserve = arena.used;
  size_t size_before_reserve = arena.size;
  ASSERT(arena_reserve(&arena, 0));
  ASSERT(arena.used == used_before_reserve &&
         arena.size == size_before_reserve);
  ASSERT(arena_reserve(&arena, arena.size));
  ASSERT(arena.used == used_before_reserve && arena.size > size_before_reserve);
  ASSERT(memcmp(arena.base, "\xa5\xa5\xa5\xa5\xa5\xa5\xa5\xa5", 8) == 0);
  ASSERT((unsigned char)arena.base[capacity - 1] == 0x5a);

  /* An arena of size 0 grows to the request instead of doubling zero. */
  arena_t empty;
  if (arena_init(&empty, 0)) {
    ASSERT(arena_reserve(&empty, 1) && empty.size >= 1 && empty.used == 0);
    ASSERT(arena_alloc(&empty, 1) != NULL);
    arena_free(&empty);
  }

  size_t reserved_size = arena.size;
  st_test_alloc_fail_at(1);
  ASSERT(!arena_reserve(&arena, reserved_size));
  st_test_alloc_reset();
  ASSERT(arena.used == used_before_reserve && arena.size == reserved_size);
  ASSERT(!arena_reserve(&arena, SIZE_MAX));
  ASSERT(arena.used == used_before_reserve && arena.size == reserved_size);

  static const struct {
    size_t size;
    size_t used;
    size_t request;
  } rejected[] = {
      {0, 1, 1},
      {SIZE_MAX, SIZE_MAX - 4, 8},
      {SIZE_MAX / 2 + 1, SIZE_MAX / 2 + 1, 1},
      {0, 0, SIZE_MAX},
  };
  char sentinel = 0;
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    arena_t invalid = {
        .base = &sentinel, .size = rejected[i].size, .used = rejected[i].used};
    ASSERT(arena_alloc(&invalid, rejected[i].request) == NULL);
    ASSERT(invalid.base == &sentinel);
    ASSERT(invalid.size == rejected[i].size);
    ASSERT(invalid.used == rejected[i].used);
  }

  /* Exercise the two overflow-adjacent growth branches without asking the
   * allocator for a real near-SIZE_MAX block. The deterministic hook rejects
   * the realloc after the arena has selected its exact required capacity. */
  arena_t exact_growth = {0};
  ASSERT(arena_init(&exact_growth, 1));
  st_test_alloc_fail_at(1);
  ASSERT(arena_alloc(&exact_growth, SIZE_MAX - 1023) == NULL);
  st_test_alloc_reset();
  ASSERT(exact_growth.size == 1 && exact_growth.used == 0);
  arena_free(&exact_growth);

  arena_t reserve_exact = {
      .base = &sentinel, .size = SIZE_MAX / 2 + 1, .used = 0};
  st_test_alloc_fail_at(1);
  ASSERT(!arena_reserve(&reserve_exact, SIZE_MAX / 2 + 2));
  st_test_alloc_reset();
  ASSERT(reserve_exact.base == &sentinel &&
         reserve_exact.size == SIZE_MAX / 2 + 1 && reserve_exact.used == 0);

  arena_free(&arena);
  ASSERT(arena.base == NULL);
  ASSERT(arena.size == 0);
  ASSERT(arena_used(&arena) == 0);
  return 0;
}
#undef ASSERT

/* --- verify (from test_verify.c) --- */
/* Verification and suggestion integration tests. */

static int verify_tests_run;
static int verify_tests_passed;
static int verify_tests_failed;

static int verify_pattern_view_is_cpl(st_netpattern_view_t actual,
                                      const char *cpl) {
  st_netpattern_t encoded = {0};
  int equal = actual.data &&
              st_netpattern_from_cpl_owned(cpl, &encoded) == ST_OK &&
              actual.length == encoded.length &&
              memcmp(actual.data, encoded.data, actual.length) == 0;
  st_netpattern_free(&encoded);
  return equal;
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
    verify_tests_run++;                                                        \
    printf("  %-38s ", #function);                                             \
    if (function()) {                                                          \
      verify_tests_passed++;                                                   \
      printf("PASS\n");                                                        \
    } else {                                                                   \
      verify_tests_failed++;                                                   \
      printf("FAIL\n");                                                        \
    }                                                                          \
  } while (0)

static st_policy_t *verify_new_policy(st_policy_ctx_t *context,
                                      const char *const *patterns,
                                      size_t count) {
  st_policy_t *policy = st_policy_new(context);
  if (!policy)
    return NULL;
  for (size_t i = 0; i < count; i++)
    if (test_st_policy_add(policy, patterns[i]) != ST_OK) {
      st_policy_free(policy);
      return NULL;
    }
  return policy;
}

typedef struct {
  st_netpattern_view_t patterns[4];
  size_t count;
  size_t stop_after;
} verify_match_visit_t;

static bool verify_visit_match(st_netpattern_view_t pattern, void *user_ctx) {
  verify_match_visit_t *visit = user_ctx;
  visit->patterns[visit->count++] = pattern;
  return visit->count < visit->stop_after;
}

static int verify_test_verify_all_matrix(void) {
  static const char *patterns[] = {"git commit -m *", "git commit -m fix",
                                   "git status", "typed #n #val",
                                   "typed #val #n"};
  st_policy_ctx_t *context = st_policy_ctx_new();
  ASSERT(context != NULL);
  st_policy_t *policy = verify_new_policy(
      context, patterns, sizeof(patterns) / sizeof(patterns[0]));
  ASSERT(policy != NULL);

  static const struct {
    const char *command;
    const char *expected[2];
    size_t count;
  } cases[] = {
      {"git commit -m hello", {"git commit -m *", NULL}, 1},
      {"git commit -m fix", {"git commit -m *", NULL}, 1},
      {"git status", {"git status", NULL}, 1},
      {"typed 1 2", {"typed #n #val", "typed #val #n"}, 2},
      {"rm -rf /", {NULL, NULL}, 0},
  };

  /* The wildcard subsumes the exact commit rule; the crossing typed rules do
   * not subsume one another. */
  ASSERT(st_policy_rule_count(policy) == 4);

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_netpattern_view_t *matches = NULL;
    size_t count = 99;
    ASSERT(test_st_policy_verify_all(policy, cases[i].command, &matches,
                                     &count) == ST_OK);
    ASSERT(count == cases[i].count);
    ASSERT((count == 0) == (matches == NULL));
    for (size_t j = 0; j < count; j++) {
      for (size_t k = j + 1; k < count; k++)
        ASSERT((matches[j].length != matches[k].length ||
                memcmp(matches[j].data, matches[k].data, matches[j].length)) !=
               0);
    }
    for (size_t j = 0; j < cases[i].count; j++) {
      bool found = false;
      for (size_t k = 0; k < count; k++)
        found = found || test_pattern_is_cpl(matches[k], cases[i].expected[j]);
      ASSERT(found);
    }
    st_policy_matches_free(matches);
  }

  st_netpattern_view_t *borrowed_matches = NULL;
  size_t borrowed_count = 0;
  st_eval_result_t borrowed_eval = {0};
  ASSERT(test_st_policy_verify_all(policy, "git status", &borrowed_matches,
                                   &borrowed_count) == ST_OK);
  ASSERT(test_st_policy_eval(policy, "git status", &borrowed_eval) == ST_OK);
  ASSERT(borrowed_count == 1 &&
         borrowed_matches[0].data == borrowed_eval.matching_pattern);
  st_policy_matches_free(borrowed_matches);

  shell_netstring_buffer_t netargv = test_netargv("typed 1 2");
  ASSERT(netargv.data != NULL);
  verify_match_visit_t visit = {.stop_after = 4};
  size_t visited = 0;
  ASSERT(st_policy_visit_matches_view(
             policy,
             (st_netargv_view_t){(const char *)netargv.data, netargv.length},
             verify_visit_match, &visit, &visited) == ST_OK);
  ASSERT(visited == 2 && visit.count == 2);
  ASSERT(verify_pattern_view_is_cpl(visit.patterns[0], "typed #n #val") ||
         verify_pattern_view_is_cpl(visit.patterns[1], "typed #n #val"));
  visit = (verify_match_visit_t){.stop_after = 1};
  ASSERT(st_policy_visit_matches_view(
             policy,
             (st_netargv_view_t){(const char *)netargv.data, netargv.length},
             verify_visit_match, &visit, &visited) == ST_OK);
  ASSERT(visited == 1 && visit.count == 1);
  shell_netstring_buffer_free(&netargv);

  st_netpattern_view_t *matches = NULL;
  size_t count = 99;
  ASSERT(test_st_policy_verify_all(policy, "", &matches, &count) == ST_OK);
  ASSERT(matches == NULL && count == 0);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return 1;
}

static int verify_test_policy_match_matrix(void) {
  static const char *patterns[] = {"echo #n", "kill #signal", "grep #regex",
                                   "assign value=1"};
  static const struct {
    const char *command;
    bool expected;
  } cases[] = {{"echo 42", true},        {"echo value", false},
               {"kill 9", true},         {"grep 'a.*'", true},
               {"assign value=1", true}, {"assign value=2", false}};

  st_policy_ctx_t *context = st_policy_ctx_new();
  ASSERT(context != NULL);
  st_policy_t *policy = verify_new_policy(
      context, patterns, sizeof(patterns) / sizeof(patterns[0]));
  ASSERT(policy != NULL);

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shell_netstring_buffer_t netargv = test_netargv(cases[i].command);
    ASSERT(netargv.data != NULL);
    st_eval_result_t eval = {0};
    bool matches = !cases[i].expected;
    ASSERT(st_policy_eval_view(
               policy,
               (st_netargv_view_t){(const char *)netargv.data, netargv.length},
               &eval) == ST_OK);
    ASSERT(st_policy_match_view(
               policy,
               (st_netargv_view_t){(const char *)netargv.data, netargv.length},
               &matches) == ST_OK);
    ASSERT(eval.matches == cases[i].expected && matches == eval.matches);
    shell_netstring_buffer_free(&netargv);
  }

  static char long_netargv[sizeof("4:echo,256:") + ST_MAX_TOKEN_LEN + 1];
  size_t long_prefix_length = sizeof("4:echo,256:") - 1;
  memcpy(long_netargv, "4:echo,256:", long_prefix_length);
  memset(long_netargv + long_prefix_length, 'x', ST_MAX_TOKEN_LEN);
  long_netargv[long_prefix_length + ST_MAX_TOKEN_LEN] = ',';
  long_netargv[long_prefix_length + ST_MAX_TOKEN_LEN + 1] = '\0';
  bool matches = true;
  ASSERT(st_policy_match_view(
             policy,
             (st_netargv_view_t){long_netargv,
                                 long_prefix_length + ST_MAX_TOKEN_LEN + 1},
             &matches) == ST_OK);
  ASSERT(!matches);

  matches = true;
  ASSERT(st_policy_match_view(policy,
                              (st_netargv_view_t){"1:x,x", sizeof("1:x,x") - 1},
                              &matches) == ST_ERR_FORMAT);
  ASSERT(!matches);

  ASSERT(!matches);

  shell_netstring_buffer_t netargv = test_netargv("echo 42");
  ASSERT(netargv.data != NULL);
  ASSERT(st_policy_match_view(
             policy,
             (st_netargv_view_t){(const char *)netargv.data, netargv.length},
             &matches) == ST_OK &&
         matches);
  st_test_alloc_reset();
  ASSERT(st_policy_match_view(
             policy,
             (st_netargv_view_t){(const char *)netargv.data, netargv.length},
             &matches) == ST_OK &&
         matches);
  ASSERT(st_test_alloc_count() == 0);
  st_test_alloc_reset();
  shell_netstring_buffer_free(&netargv);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return 1;
}

static int verify_test_verify_high_fanout_growth(void) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(context);
  ASSERT(context && policy);
  char expected[ST_MAX_NETPATTERN_LEN] = {0};
  size_t pattern_count = 0;
  for (unsigned mask = 0; mask < (1u << 9); mask++) {
    if (__builtin_popcount(mask) != 4)
      continue;
    char pattern[ST_MAX_NETPATTERN_LEN] = "x";
    for (unsigned pos = 0; pos < 9; pos++)
      strcat(pattern, (mask & (1u << pos)) ? " #n" : " #val");
    ASSERT(test_st_policy_add(policy, pattern) == ST_OK);
    if (expected[0] == '\0' || strcmp(pattern, expected) < 0)
      strcpy(expected, pattern);
    pattern_count++;
  }
  ASSERT(pattern_count == 126 && st_policy_rule_count(policy) == 126);
  const char *command = "x 1 2 3 4 5 6 7 8 9";
  st_netpattern_view_t *matches = NULL;
  size_t count = 0;
  ASSERT(test_st_policy_verify_all(policy, command, &matches, &count) == ST_OK);
  ASSERT(count == 126);
  st_policy_matches_free(matches);
  st_eval_result_t result = {0};
  ASSERT(test_st_policy_eval(policy, command, &result) == ST_OK);
  ASSERT(result.matches &&
         test_pattern_is_cpl(
             (st_netpattern_view_t){result.matching_pattern,
                                    result.matching_pattern_length},
             expected));

  st_test_alloc_reset();
  ASSERT(test_st_policy_eval(policy, command, &result) == ST_OK);
  size_t eval_allocations = st_test_alloc_count();
  bool eval_failure_observed = false;
  for (size_t fail_at = 1; fail_at <= eval_allocations; fail_at++) {
    memset(&result, 0xa5, sizeof(result));
    st_test_alloc_fail_at(fail_at);
    st_error_t error = test_st_policy_eval(policy, command, &result);
    st_test_alloc_reset();
    if (error == ST_ERR_MEMORY) {
      eval_failure_observed = true;
      ASSERT(!result.matches && result.matching_pattern == NULL &&
             result.suggestion_count == 0 && result.suggestion_error == ST_OK);
    } else {
      ASSERT(error == ST_OK && result.matches && result.matching_pattern &&
             test_pattern_is_cpl(
                 (st_netpattern_view_t){result.matching_pattern,
                                        result.matching_pattern_length},
                 expected));
    }
  }
  ASSERT(eval_failure_observed);

  st_test_alloc_reset();
  ASSERT(test_st_policy_verify_all(policy, command, &matches, &count) == ST_OK);
  size_t allocations = st_test_alloc_count();
  st_policy_matches_free(matches);
  bool observed = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    matches = NULL;
    count = 99;
    st_test_alloc_fail_at(fail_at);
    st_error_t error =
        test_st_policy_verify_all(policy, command, &matches, &count);
    st_test_alloc_reset();
    if (error == ST_ERR_MEMORY) {
      observed = true;
      ASSERT(matches == NULL && count == 0);
    } else {
      ASSERT(error == ST_OK && count == 126);
      st_policy_matches_free(matches);
    }
  }
  ASSERT(observed);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return 1;
}

static int run_verify(int argc, char **argv) {
  (void)argc;
  (void)argv;
  printf("Running verification tests...\n\n");
  TEST(verify_test_verify_all_matrix);
  TEST(verify_test_policy_match_matrix);
  TEST(verify_test_verify_high_fanout_growth);
  printf("\nResults: %d/%d passed, %d failed\n", verify_tests_passed,
         verify_tests_run, verify_tests_failed);
  return verify_tests_failed > 0 ? 1 : 0;
}
#undef ASSERT
#undef TEST

/* --- integration (from test_shelltype_integration.c) --- */
/* End-to-end tests for suggestion ranking across mixed command workloads. */

static int integration_tests_run;
static int integration_tests_passed;
static int integration_tests_failed;

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
    integration_tests_run++;                                                   \
    printf("  %-38s ", #function);                                             \
    if (function()) {                                                          \
      integration_tests_passed++;                                              \
      printf("PASS\n");                                                        \
    } else {                                                                   \
      integration_tests_failed++;                                              \
      printf("FAIL\n");                                                        \
    }                                                                          \
  } while (0)

typedef struct {
  const char *pattern;
  uint32_t count;
  double confidence;
} integration_expected_suggestion_t;

static int run_integration(int argc, char **argv) {
  (void)argc;
  (void)argv;
  printf("Running shelltype integration tests...\n\n");
  printf("\nResults: %d/%d passed, %d failed\n", integration_tests_passed,
         integration_tests_run, integration_tests_failed);
  return integration_tests_failed > 0 ? 1 : 0;
}
#undef ASSERT
#undef TEST

/* --- processed (from test_processed_subcommand.c) --- */
static int processed_check_pipeline(const char *input,
                                    const char *expected_clean,
                                    const char *const *expected_tokens,
                                    size_t expected_count) {
  (void)expected_clean;
  shell_command_info_t *commands = NULL;
  size_t command_count = 0;
  shell_netstring_buffer_t netargv = {0};
  if (shell_process_command(input, strlen(input), NULL, &commands,
                            &command_count) != SHELL_PROCESS_OK ||
      command_count != 1 ||
      shell_command_info_has_dangerous_features(&commands[0]))
    goto fail;
  if (shell_render_netargv_buffer(&commands[0], NULL, &netargv) !=
      SHELL_PROCESS_OK)
    goto fail;

  st_token_array_t typed = {0};
  if (st_netargv_classify_view(
          (st_netargv_view_t){(const char *)netargv.data, netargv.length},
          &typed) != ST_OK ||
      typed.count != expected_count) {
    st_token_array_free(&typed);
    goto fail;
  }
  for (size_t i = 0; i < expected_count; i++) {
    if (strcmp(typed.tokens[i].text, expected_tokens[i]) != 0) {
      st_token_array_free(&typed);
      goto fail;
    }
  }
  st_token_array_free(&typed);
  shell_command_infos_free(commands, command_count);
  shell_netstring_buffer_free(&netargv);
  return 1;

fail:
  shell_command_infos_free(commands, command_count);
  shell_netstring_buffer_free(&netargv);
  return 0;
}

static int processed_check_trusted_processed_input(void) {
  static const char netargv[] =
      "6:printf,9:two words,16:literal>operator,3:a\\b,";
  static const char *const expected[] = {"printf", "two words",
                                         "literal>operator", "a\\b"};
  st_token_array_t typed = {0};
  st_learner_t *learner = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.0,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  if (!learner ||
      st_netargv_classify_view(
          (st_netargv_view_t){netargv, sizeof(netargv) - 1}, &typed) != ST_OK ||
      typed.count != sizeof(expected) / sizeof(expected[0]))
    goto fail;
  for (size_t i = 0; i < typed.count; i++)
    if (strcmp(typed.tokens[i].text, expected[i]) != 0)
      goto fail;
  if (st_learner_feed_netargv_view(
          learner, (st_netargv_view_t){netargv, sizeof(netargv) - 1}) != ST_OK)
    goto fail;
  st_netpattern_t netpattern = {0};
  if (!policy ||
      st_netpattern_from_cpl_owned("printf * * *", &netpattern) != ST_OK ||
      st_policy_add_netpattern_view(
          policy, (st_netpattern_view_t){(const char *)netpattern.data,
                                         netpattern.length}) != ST_OK) {
    st_netpattern_free(&netpattern);
    goto fail;
  }
  st_netpattern_free(&netpattern);
  st_eval_result_t result = {0};
  if (st_policy_eval_view(policy,
                          (st_netargv_view_t){netargv, sizeof(netargv) - 1},
                          &result) != ST_OK ||
      !result.matches)
    goto fail;
  st_netpattern_view_t *matches = NULL;
  size_t match_count = 0;
  if (st_policy_verify_all_view(
          policy, (st_netargv_view_t){netargv, sizeof(netargv) - 1}, &matches,
          &match_count) != ST_OK ||
      match_count != 1) {
    st_policy_matches_free(matches);
    goto fail;
  }
  st_policy_matches_free(matches);
  st_token_array_free(&typed);
  st_learner_free(learner);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 1;

fail:
  st_token_array_free(&typed);
  st_learner_free(learner);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return 0;
}

static int run_processed(int argc, char **argv) {
  (void)argc;
  (void)argv;
  static const char *const assembled[] = {"echo", "foobar", "a b",
                                          "pre mid post"};
  static const char *const empty[] = {"printf", "", "", ">"};
  static const char *const escaped[] = {"printf", "a\"b", "c'd", "x\\y"};
  int passed = processed_check_pipeline("echo foo\"bar\" a\\ b pre' mid 'post",
                                        "echo foobar \"a b\" \"pre mid post\"",
                                        assembled, 4) &&
               processed_check_pipeline("printf '' \"\" '>'",
                                        "printf \"\" \"\" \">\"", empty, 4) &&
               processed_check_pipeline("printf 'a\"b' \"c'd\" 'x\\y'",
                                        "printf \"a\\\"b\" \"c'd\" \"x\\\\y\"",
                                        escaped, 4) &&
               processed_check_trusted_processed_input();
  printf("processed-subcommand integration: %s\n", passed ? "PASS" : "FAIL");
  return passed ? EXIT_SUCCESS : EXIT_FAILURE;
}

int main(int argc, char **argv) {
  int status = 0;
  status |= run_unit(argc, argv);
  status |= run_arena(argc, argv);
  status |= run_verify(argc, argv);
  status |= run_integration(argc, argv);
  status |= run_processed(argc, argv);
  return status != 0;
}
