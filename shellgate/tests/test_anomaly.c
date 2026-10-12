/* Unit tests for the standalone anomaly model. */

#define _POSIX_C_SOURCE 200809L
#include "../../tests/atomic_file_fixture.h"
#include "../src/sg_anomaly_internal.h"
#include "sg_anomaly.h"
#include "shell_netstring.h"
#include "test_numeric_locale.h"
#include "test_sg_failures.h"
#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <glob.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static sg_anomaly_model_t *test_model_with_config(double alpha,
                                                  double unknown_log_prior) {
  sg_anomaly_config_t config = {
      .alpha = alpha,
      .unknown_log_prior = unknown_log_prior,
  };
  return sg_anomaly_model_new_with_config(&config);
}

/* Fixture inputs are ordinary textual names; encoded output is a byte buffer.
 */
static shell_netstring_buffer_t test_encode_netseq(const char **sequence,
                                                   size_t count) {
  if (!sequence && count)
    return (shell_netstring_buffer_t){0};
  size_t total = 0;
  for (size_t i = 0; i < count; i++) {
    if (!sequence[i])
      return (shell_netstring_buffer_t){0};
    size_t length = strlen(sequence[i]);
    size_t record_length = 0;
    if (shell_netstring_encoded_length(length, &record_length) !=
            SHELL_NETSTRING_OK ||
        total > SIZE_MAX - record_length)
      return (shell_netstring_buffer_t){0};
    total += record_length;
  }
  if (total == SIZE_MAX)
    return (shell_netstring_buffer_t){0};
  char *encoded = malloc(total + 1);
  if (!encoded)
    return (shell_netstring_buffer_t){0};
  size_t used = 0;
  for (size_t i = 0; i < count; i++) {
    size_t length = strlen(sequence[i]);
    size_t written = 0;
    if (shell_netstring_write(encoded + used, total - used, sequence[i], length,
                              &written) != SHELL_NETSTRING_OK) {
      free(encoded);
      return (shell_netstring_buffer_t){0};
    }
    used += written;
  }
  encoded[used] = '\0';
  return (shell_netstring_buffer_t){(unsigned char *)encoded, used};
}

static bool test_has_observed(const sg_anomaly_model_t *model,
                              const char **sequence, size_t count) {
  shell_netstring_buffer_t encoded = test_encode_netseq(sequence, count);
  bool observed = false;
  if (!encoded.data || sg_anomaly_model_has_observed_netseq(
                           model, (const char *)encoded.data, encoded.length,
                           &observed) != SG_ANOMALY_OK)
    observed = false;
  shell_netstring_buffer_free(&encoded);
  return observed;
}

static double test_anomaly_score_array(const sg_anomaly_model_t *model,
                                       const char **sequence, size_t count) {
  shell_netstring_buffer_t encoded = test_encode_netseq(sequence, count);
  double score = INFINITY;
  if (encoded.data) {
    (void)sg_anomaly_model_score_netseq(model, (const char *)encoded.data,
                                        encoded.length, &score);
    shell_netstring_buffer_free(&encoded);
  }
  return score;
}

static void test_anomaly_update_array(sg_anomaly_model_t *model,
                                      const char **sequence, size_t count) {
  shell_netstring_buffer_t encoded = test_encode_netseq(sequence, count);
  if (encoded.data) {
    (void)sg_anomaly_model_update_netseq(model, (const char *)encoded.data,
                                         encoded.length);
    shell_netstring_buffer_free(&encoded);
  }
}

#define sg_anomaly_score test_anomaly_score_array
#define sg_anomaly_update test_anomaly_update_array

static int pass_count;
static int fail_count;
static char anomaly_temp_path[256];
static char anomaly_save_directory[256];

static void cleanup_anomaly_save_fixture(void) {
  if (!anomaly_save_directory[0])
    return;
  (void)test_atomic_cleanup_directory(anomaly_save_directory);
  anomaly_save_directory[0] = '\0';
}

static void cleanup_anomaly_temp_file(void) {
  if (anomaly_temp_path[0] != '\0') {
    (void)unlink(anomaly_temp_path);
    anomaly_temp_path[0] = '\0';
  }
}

#define ASSERT(condition)                                                      \
  do {                                                                         \
    if (!(condition)) {                                                        \
      printf("    FAIL: %s at %s:%d\n", #condition, __FILE__, __LINE__);       \
      fail_count++;                                                            \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define ASSERT_EQ_INT(actual, expected)                                        \
  do {                                                                         \
    if ((actual) != (expected)) {                                              \
      printf("    FAIL: %s != %s (%ld != %ld) at %s:%d\n", #actual, #expected, \
             (long)(actual), (long)(expected), __FILE__, __LINE__);            \
      fail_count++;                                                            \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define ASSERT_EQ_DBL(actual, expected, epsilon)                               \
  do {                                                                         \
    if (fabs((actual) - (expected)) > (epsilon)) {                             \
      printf("    FAIL: %s != %s (%.9f != %.9f) at %s:%d\n", #actual,          \
             #expected, (double)(actual), (double)(expected), __FILE__,        \
             __LINE__);                                                        \
      fail_count++;                                                            \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define TEST(name) static void test_##name(void)
#define RUN(name)                                                              \
  do {                                                                         \
    printf("  %-38s ", #name);                                                 \
    int previous_failures = fail_count;                                        \
    test_##name();                                                             \
    if (fail_count == previous_failures) {                                     \
      printf("PASS\n");                                                        \
      pass_count++;                                                            \
    }                                                                          \
  } while (0)

static const char *commands[] = {"a", "b", "c", "d", "e"};

typedef struct {
  size_t vocab;
  size_t total_uni;
  size_t total_bi;
  size_t total_tri;
  size_t total_quad;
  size_t contexts;
  size_t unk;
  double score;
} anomaly_snapshot_t;

static anomaly_snapshot_t snapshot_model(const sg_anomaly_model_t *model) {
  return (anomaly_snapshot_t){sg_anomaly_model_vocab_size(model),
                              sg_anomaly_model_total_unigrams(model),
                              sg_anomaly_model_total_bigrams(model),
                              sg_anomaly_model_total_trigrams(model),
                              sg_anomaly_model_total_fourgrams(model),
                              sg_anomaly_model_total_contexts(model),
                              sg_anomaly_model_unknown_count(model),
                              sg_anomaly_score(model, commands, 5)};
}

static bool snapshot_equal(anomaly_snapshot_t before,
                           anomaly_snapshot_t after) {
  return before.vocab == after.vocab && before.total_uni == after.total_uni &&
         before.total_bi == after.total_bi &&
         before.total_tri == after.total_tri &&
         before.total_quad == after.total_quad &&
         before.contexts == after.contexts && before.unk == after.unk &&
         fabs(before.score - after.score) < 0.000001;
}

static sg_anomaly_model_t *roundtrip_model(const sg_anomaly_model_t *model) {
  FILE *stream = tmpfile();
  sg_anomaly_model_t *loaded = NULL;
  if (!stream || sg_anomaly_write_stream(model, stream) != SG_ANOMALY_OK ||
      fseek(stream, 0, SEEK_SET) != 0 ||
      sg_anomaly_model_read_new(stream, &loaded) != SG_ANOMALY_OK) {
    if (stream)
      fclose(stream);
    sg_anomaly_model_free(loaded);
    return NULL;
  }
  if (fclose(stream) != 0) {
    sg_anomaly_model_free(loaded);
    return NULL;
  }
  return loaded;
}

static void update_repeated(sg_anomaly_model_t *model, const char **seq,
                            size_t length, size_t repetitions) {
  for (size_t i = 0; i < repetitions; i++)
    sg_anomaly_update(model, seq, length);
}

TEST(lifecycle_and_null_safety) {
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  ASSERT(model != NULL);
  ASSERT_EQ_INT(sg_anomaly_model_vocab_size(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_bigrams(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_trigrams(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_fourgrams(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_contexts(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_unknown_count(model), 0);
  ASSERT_EQ_DBL(sg_anomaly_model_kneser_ney_discount(model), 0.5, 0.000001);
  ASSERT(!sg_anomaly_model_had_error(model));
  size_t empty_removed = 99;
  ASSERT_EQ_INT(sg_anomaly_model_prune(model, 2, &empty_removed),
                SG_ANOMALY_OK);
  ASSERT_EQ_INT(empty_removed, 0);

  const char *invalid_sequences[][3] = {{"a", NULL, "c"}};
  sg_anomaly_update(model, commands, 5);
  for (size_t i = 0;
       i < sizeof(invalid_sequences) / sizeof(invalid_sequences[0]); i++) {
    ASSERT(isinf(sg_anomaly_score(model, invalid_sequences[i], 3)));
    ASSERT(!test_has_observed(model, invalid_sequences[i], 3));
    sg_anomaly_update(model, invalid_sequences[i], 3);
    ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(model), 5);
  }
  const char *empty_stage[] = {"a", "", "c"};
  ASSERT(isfinite(sg_anomaly_score(model, empty_stage, 3)));
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(
                    model, (sg_anomaly_item_view_t){"", (sizeof("") - 1)}),
                0);
  sg_anomaly_update(model, empty_stage, 3);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(model), 8);
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(
                    model, (sg_anomaly_item_view_t){"", (sizeof("") - 1)}),
                1);

  sg_anomaly_model_free(NULL);
  ASSERT(isinf(sg_anomaly_score(model, NULL, 5)));

  char oversized[8192];
  memset(oversized, 'x', sizeof(oversized) - 1);
  oversized[sizeof(oversized) - 1] = '\0';
  ASSERT_EQ_INT(sg_anomaly_model_bigram_count_view(
                    model, (sg_anomaly_item_view_t){"", (sizeof("") - 1)},
                    (sg_anomaly_item_view_t){"b", (sizeof("b") - 1)}),
                0);
  ASSERT_EQ_INT(sg_anomaly_model_bigram_count_view(
                    model,
                    (sg_anomaly_item_view_t){oversized, strlen(oversized)},
                    (sg_anomaly_item_view_t){"b", (sizeof("b") - 1)}),
                0);
  ASSERT_EQ_INT(sg_anomaly_model_trigram_count_view(
                    model, (sg_anomaly_item_view_t){"", (sizeof("") - 1)},
                    (sg_anomaly_item_view_t){"b", (sizeof("b") - 1)},
                    (sg_anomaly_item_view_t){"c", (sizeof("c") - 1)}),
                0);
  ASSERT_EQ_INT(sg_anomaly_model_trigram_count_view(
                    model,
                    (sg_anomaly_item_view_t){oversized, strlen(oversized)},
                    (sg_anomaly_item_view_t){"b", (sizeof("b") - 1)},
                    (sg_anomaly_item_view_t){"c", (sizeof("c") - 1)}),
                0);
  ASSERT_EQ_INT(sg_anomaly_model_fourgram_count_view(
                    model, (sg_anomaly_item_view_t){"", (sizeof("") - 1)},
                    (sg_anomaly_item_view_t){"b", (sizeof("b") - 1)},
                    (sg_anomaly_item_view_t){"c", (sizeof("c") - 1)},
                    (sg_anomaly_item_view_t){"d", (sizeof("d") - 1)}),
                0);
  ASSERT_EQ_INT(sg_anomaly_model_fourgram_count_view(
                    model,
                    (sg_anomaly_item_view_t){oversized, strlen(oversized)},
                    (sg_anomaly_item_view_t){"b", (sizeof("b") - 1)},
                    (sg_anomaly_item_view_t){"c", (sizeof("c") - 1)},
                    (sg_anomaly_item_view_t){"d", (sizeof("d") - 1)}),
                0);
  const char *oversized_sequence[] = {oversized, "b", "c", "d"};
  ASSERT(isfinite(sg_anomaly_score(model, oversized_sequence, 4)));
  const char *oversized_middle[] = {"a", oversized, "c", "d"};
  const char *oversized_late[] = {"a", "b", oversized, "d"};
  const char *oversized_last[] = {"a", "b", "c", oversized};
  ASSERT(isfinite(sg_anomaly_score(model, oversized_middle, 4)));
  ASSERT(isfinite(sg_anomaly_score(model, oversized_late, 4)));
  ASSERT(isfinite(sg_anomaly_score(model, oversized_last, 4)));

  FILE *stream = tmpfile();
  ASSERT(stream != NULL);
  rewind(stream);
  ASSERT_EQ_INT(sg_anomaly_read_stream(model, stream), SG_ANOMALY_ERR_FORMAT);
  int close_result = fclose(stream);
  ASSERT_EQ_INT(close_result, 0);
  FILE *read_only = fopen("/dev/null", "rb");
  ASSERT(read_only != NULL);
  ASSERT_EQ_INT(sg_anomaly_write_stream(model, read_only), SG_ANOMALY_ERR_IO);
  close_result = fclose(read_only);
  ASSERT_EQ_INT(close_result, 0);
  ASSERT_EQ_INT(
      sg_anomaly_model_save(model, "/tmp/shellclave-no-such-directory/model"),
      SG_ANOMALY_ERR_IO);
  ASSERT_EQ_INT(
      sg_anomaly_model_load(model, "/tmp/shellclave-no-such-directory/model"),
      SG_ANOMALY_ERR_IO);
  sg_anomaly_model_free(model);
}

TEST(config_contract) {
  sg_anomaly_config_t config;
  sg_anomaly_config_default(&config);
  ASSERT_EQ_DBL(config.alpha, 0.1, 0.0);
  ASSERT_EQ_DBL(config.unknown_log_prior, -10.0, 0.0);

  config.alpha = 0.25;
  config.unknown_log_prior = -7.0;
  sg_anomaly_model_t *model = sg_anomaly_model_new_with_config(&config);
  ASSERT(model != NULL);
  sg_anomaly_model_free(model);
  model = sg_anomaly_model_new_with_config(NULL);
  ASSERT(model != NULL);
  sg_anomaly_model_free(model);

  config.alpha = 0.0;
  ASSERT(sg_anomaly_model_new_with_config(&config) == NULL);
  config.alpha = NAN;
  ASSERT(sg_anomaly_model_new_with_config(&config) == NULL);
  config.alpha = 0.1;
  config.unknown_log_prior = INFINITY;
  ASSERT(sg_anomaly_model_new_with_config(&config) == NULL);
}

TEST(extreme_alpha_scores_are_finite) {
  static const double alphas[] = {DBL_TRUE_MIN, DBL_MIN, 0.1, DBL_MAX};
  static const char learned[] = "1:a,1:b,1:c,";
  static const char mixed[] = "1:b,1:c,1:x,";
  for (size_t i = 0; i < sizeof(alphas) / sizeof(alphas[0]); i++) {
    sg_anomaly_config_t config = {
        .alpha = alphas[i],
        .unknown_log_prior = -10.0,
    };
    sg_anomaly_model_t *model = sg_anomaly_model_new_with_config(&config);
    ASSERT(model != NULL);
    ASSERT_EQ_INT(
        sg_anomaly_model_update_netseq(model, learned, sizeof(learned) - 1),
        SG_ANOMALY_OK);
    double learned_score = INFINITY;
    double mixed_score = INFINITY;
    ASSERT_EQ_INT(sg_anomaly_model_score_netseq(
                      model, learned, sizeof(learned) - 1, &learned_score),
                  SG_ANOMALY_OK);
    ASSERT_EQ_INT(sg_anomaly_model_score_netseq(model, mixed, sizeof(mixed) - 1,
                                                &mixed_score),
                  SG_ANOMALY_OK);
    ASSERT(isfinite(learned_score) && learned_score >= 0.0);
    ASSERT(isfinite(mixed_score) && mixed_score >= 0.0);

    sg_anomaly_model_t *loaded = roundtrip_model(model);
    ASSERT(loaded != NULL);
    double loaded_score = INFINITY;
    ASSERT_EQ_INT(sg_anomaly_model_score_netseq(
                      loaded, learned, sizeof(learned) - 1, &loaded_score),
                  SG_ANOMALY_OK);
    ASSERT(isfinite(loaded_score) && loaded_score >= 0.0);
    ASSERT_EQ_DBL(loaded_score, learned_score, 0.000001);
    sg_anomaly_model_free(loaded);
    sg_anomaly_model_free(model);
  }
}

TEST(update_count_matrix) {
  ASSERT_EQ_INT(SG_ANOMALY_MAX_STAGE_LENGTH, 1023);

  for (size_t length = 1; length <= 5; length++) {
    sg_anomaly_model_t *model = sg_anomaly_model_new();
    ASSERT(model != NULL);
    update_repeated(model, commands, length, 3);

    ASSERT_EQ_INT(sg_anomaly_model_vocab_size(model), length);
    ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(model), length * 3);
    ASSERT_EQ_INT(sg_anomaly_model_total_bigrams(model),
                  length > 1 ? (length - 1) * 3 : 0);
    ASSERT_EQ_INT(sg_anomaly_model_total_trigrams(model),
                  length > 2 ? (length - 2) * 3 : 0);
    ASSERT_EQ_INT(sg_anomaly_model_total_fourgrams(model),
                  length > 3 ? (length - 3) * 3 : 0);
    ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(
                      model, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)}),
                  3);
    ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(
                      model, (sg_anomaly_item_view_t){"missing",
                                                      (sizeof("missing") - 1)}),
                  0);
    ASSERT_EQ_INT(sg_anomaly_model_bigram_count_view(
                      model, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)},
                      (sg_anomaly_item_view_t){"b", (sizeof("b") - 1)}),
                  length > 1 ? 3 : 0);
    ASSERT_EQ_INT(sg_anomaly_model_trigram_count_view(
                      model, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)},
                      (sg_anomaly_item_view_t){"b", (sizeof("b") - 1)},
                      (sg_anomaly_item_view_t){"c", (sizeof("c") - 1)}),
                  length > 2 ? 3 : 0);
    ASSERT_EQ_INT(sg_anomaly_model_fourgram_count_view(
                      model, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)},
                      (sg_anomaly_item_view_t){"b", (sizeof("b") - 1)},
                      (sg_anomaly_item_view_t){"c", (sizeof("c") - 1)},
                      (sg_anomaly_item_view_t){"d", (sizeof("d") - 1)}),
                  length > 3 ? 3 : 0);
    ASSERT((length < 3) == isinf(sg_anomaly_score(model, commands, length)));
    ASSERT(test_has_observed(model, commands, length));
    const char *unseen[] = {"missing"};
    ASSERT(!test_has_observed(model, unseen, 1));
    sg_anomaly_model_free(model);
  }

  char storage[4][SG_ANOMALY_MAX_STAGE_LENGTH + 1];
  const char *boundary[4];
  for (size_t i = 0; i < 4; i++) {
    memset(storage[i], 'a', SG_ANOMALY_MAX_STAGE_LENGTH);
    storage[i][SG_ANOMALY_MAX_STAGE_LENGTH - 1] = (char)('a' + i);
    storage[i][SG_ANOMALY_MAX_STAGE_LENGTH] = '\0';
    boundary[i] = storage[i];
  }
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  ASSERT(model != NULL);
  sg_anomaly_update(model, boundary, 4);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(model), 4);
  ASSERT_EQ_INT(sg_anomaly_model_total_bigrams(model), 3);
  ASSERT_EQ_INT(sg_anomaly_model_total_trigrams(model), 2);
  ASSERT_EQ_INT(sg_anomaly_model_total_fourgrams(model), 1);
  ASSERT_EQ_INT(sg_anomaly_model_fourgram_count_view(
                    model,
                    (sg_anomaly_item_view_t){boundary[0], strlen(boundary[0])},
                    (sg_anomaly_item_view_t){boundary[1], strlen(boundary[1])},
                    (sg_anomaly_item_view_t){boundary[2], strlen(boundary[2])},
                    (sg_anomaly_item_view_t){boundary[3], strlen(boundary[3])}),
                1);
  ASSERT(isfinite(sg_anomaly_score(model, boundary, 4)));

  char too_long[SG_ANOMALY_MAX_STAGE_LENGTH + 2];
  memset(too_long, 'x', sizeof(too_long) - 1);
  too_long[sizeof(too_long) - 1] = '\0';
  const char *invalid[] = {boundary[0], boundary[1], too_long};
  sg_anomaly_update(model, invalid, 3);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(model), 4);
  /* An over-long name is never learned, so it must score as an unknown command
   * rather than returning INFINITY, which callers read as "cannot score" and
   * would let it bypass anomaly detection entirely. */
  double over_long_score = sg_anomaly_score(model, invalid, 3);
  ASSERT(isfinite(over_long_score));
  const char *known[] = {boundary[0], boundary[1], boundary[2]};
  ASSERT(over_long_score > sg_anomaly_score(model, known, 3));
  ASSERT_EQ_INT(
      sg_anomaly_model_unigram_count_view(
          model, (sg_anomaly_item_view_t){too_long, strlen(too_long)}),
      0);
  sg_anomaly_model_free(model);
}

TEST(score_discrimination_matrix) {
  for (size_t length = 3; length <= 5; length++) {
    sg_anomaly_model_t *model = test_model_with_config(0.1, -10.0);
    ASSERT(model != NULL);
    sg_anomaly_update(model, commands, length);
    double initial_score = sg_anomaly_score(model, commands, length);
    update_repeated(model, commands, length, 19);

    double known_score = sg_anomaly_score(model, commands, length);
    const char *partly_unseen[5];
    memcpy(partly_unseen, commands, sizeof(partly_unseen));
    partly_unseen[length - 1] = "never-seen";
    const char *fully_unseen[] = {"v", "w", "x", "y", "z"};
    double partial_score = sg_anomaly_score(model, partly_unseen, length);
    double unseen_score = sg_anomaly_score(model, fully_unseen, length);
    ASSERT(isfinite(known_score) && known_score >= 0.0);
    ASSERT(known_score < initial_score);
    ASSERT(isfinite(partial_score) && partial_score > known_score);
    ASSERT(isfinite(unseen_score) && unseen_score > known_score);
    sg_anomaly_model_free(model);
  }
}

TEST(backoff_levels_are_usable) {
  const char *sequence[] = {"ls", "cd", "pwd"};
  sg_anomaly_model_t *unigram_model = test_model_with_config(0.1, -10.0);
  sg_anomaly_model_t *bigram_model = test_model_with_config(0.1, -10.0);
  ASSERT(unigram_model && bigram_model);

  for (size_t i = 0; i < 3; i++)
    sg_anomaly_update(unigram_model, &sequence[i], 1);
  sg_anomaly_update(bigram_model, sequence, 2);
  sg_anomaly_update(bigram_model, sequence + 1, 2);

  ASSERT(isfinite(sg_anomaly_score(unigram_model, sequence, 3)));
  ASSERT(isfinite(sg_anomaly_score(bigram_model, sequence, 3)));
  ASSERT_EQ_INT(sg_anomaly_model_total_trigrams(unigram_model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_trigrams(bigram_model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_bigrams(bigram_model), 2);
  sg_anomaly_model_free(unigram_model);
  sg_anomaly_model_free(bigram_model);
}

TEST(model_owns_string_copies) {
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  ASSERT(model != NULL);
  char *owned[] = {strdup("gcc"), strdup("make"), strdup("git")};
  ASSERT(owned[0] && owned[1] && owned[2]);
  const char *sequence[] = {owned[0], owned[1], owned[2]};
  sg_anomaly_update(model, sequence, 3);
  for (size_t i = 0; i < 3; i++)
    free(owned[i]);

  const char *probe[] = {"gcc", "make", "git"};
  ASSERT_EQ_INT(sg_anomaly_model_vocab_size(model), 3);
  for (size_t i = 0; i < 3; i++)
    ASSERT_EQ_INT(
        sg_anomaly_model_unigram_count_view(
            model, (sg_anomaly_item_view_t){probe[i], strlen(probe[i])}),
        1);
  ASSERT(isfinite(sg_anomaly_score(model, probe, 3)));
  sg_anomaly_model_free(model);
}

TEST(save_load_roundtrip) {
  char path[] = "/tmp/shellclave-anomaly-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  snprintf(anomaly_temp_path, sizeof(anomaly_temp_path), "%s", path);
  close(fd);

  sg_anomaly_model_t *source = test_model_with_config(0.5, -8.0);
  sg_anomaly_model_t *loaded = sg_anomaly_model_new();
  ASSERT(source && loaded);
  update_repeated(source, commands, 5, 5);
  const char *unseen[] = {"v", "w", "x", "y", "z"};
  double known_score = sg_anomaly_score(source, commands, 5);
  double unseen_score = sg_anomaly_score(source, unseen, 5);

  ASSERT_EQ_INT(sg_anomaly_model_save(source, path), SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_save(source, "/no/such/directory/model"),
                SG_ANOMALY_ERR_IO);
  if (access("/dev/full", W_OK) == 0) {
    errno = 0;
    ASSERT_EQ_INT(sg_anomaly_model_save(source, "/dev/full"),
                  SG_ANOMALY_ERR_IO);
    ASSERT(errno != 0);
  }
  ASSERT_EQ_INT(sg_anomaly_model_load(loaded, path), SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_load(loaded, path), SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_vocab_size(loaded), 5);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(loaded), 25);
  ASSERT_EQ_INT(sg_anomaly_model_total_bigrams(loaded), 20);
  ASSERT_EQ_INT(sg_anomaly_model_total_trigrams(loaded), 15);
  ASSERT_EQ_INT(sg_anomaly_model_total_fourgrams(loaded), 10);
  ASSERT_EQ_INT(sg_anomaly_model_unknown_count(loaded),
                sg_anomaly_model_unknown_count(source));
  ASSERT_EQ_DBL(sg_anomaly_score(loaded, commands, 5), known_score, 0.000001);
  ASSERT_EQ_DBL(sg_anomaly_score(loaded, unseen, 5), unseen_score, 0.000001);
  ASSERT_EQ_DBL(sg_anomaly_model_kneser_ney_discount(loaded),
                sg_anomaly_model_kneser_ney_discount(source), 0.000001);

  FILE *fixture = fopen(path, "rb");
  ASSERT(fixture != NULL);
  ASSERT(fseek(fixture, 0, SEEK_END) == 0);
  long file_length = ftell(fixture);
  ASSERT(file_length > 0 && fseek(fixture, 0, SEEK_SET) == 0);
  size_t valid_size = (size_t)file_length;
  unsigned char *valid = malloc(valid_size);
  ASSERT(valid != NULL);
  ASSERT(fread(valid, 1, valid_size, fixture) == valid_size);
  ASSERT(fclose(fixture) == 0);

  size_t binary_offset = 0;
  unsigned newlines = 0;
  while (binary_offset < valid_size && newlines < 2)
    if (valid[binary_offset++] == '\n')
      newlines++;
  ASSERT(newlines == 2 && binary_offset < valid_size);
  const unsigned char *first_newline = memchr(valid, '\n', valid_size);
  ASSERT(first_newline != NULL);
  size_t header_end = (size_t)(first_newline - valid) + 1;

  double preserved_score = sg_anomaly_score(loaded, commands, 5);
  ASSERT(unlink(path) == 0);
  errno = 0;
  ASSERT_EQ_INT(sg_anomaly_model_load(loaded, path), SG_ANOMALY_ERR_IO);
  ASSERT_EQ_INT(errno, ENOENT);
  ASSERT_EQ_DBL(sg_anomaly_score(loaded, commands, 5), preserved_score,
                0.000001);

  enum corruption {
    EMPTY,
    BAD_MAGIC,
    MISSING_METADATA,
    BAD_METADATA,
    TRUNCATED,
    BAD_TYPE,
    BAD_COMPONENT_COUNT,
    BAD_KEY_TERMINATOR,
    BAD_NEWLINE,
    BAD_COUNT
  };
  static const enum corruption corruptions[] = {
      EMPTY,       BAD_MAGIC, MISSING_METADATA,    BAD_METADATA,
      TRUNCATED,   BAD_TYPE,  BAD_COMPONENT_COUNT, BAD_KEY_TERMINATOR,
      BAD_NEWLINE, BAD_COUNT};
  for (size_t i = 0; i < sizeof(corruptions) / sizeof(corruptions[0]); i++) {
    unsigned char *data = malloc(valid_size);
    ASSERT(data != NULL);
    memcpy(data, valid, valid_size);
    size_t size = valid_size;
    switch (corruptions[i]) {
    case EMPTY:
      size = 0;
      break;
    case BAD_MAGIC:
      data[0] = '!';
      break;
    case MISSING_METADATA:
      size = header_end;
      break;
    case BAD_METADATA:
      data[header_end] = '!';
      break;
    case TRUNCATED:
      size--;
      break;
    case BAD_TYPE:
      data[binary_offset] = 99;
      break;
    case BAD_COMPONENT_COUNT:
      data[binary_offset] = 2;
      break;
    case BAD_KEY_TERMINATOR: {
      uint32_t key_length = 0;
      memcpy(&key_length, data + binary_offset + 1, sizeof(key_length));
      ASSERT(key_length > 0 && binary_offset + 5U + key_length <= size);
      data[binary_offset + 5U + key_length - 1U] = 'X';
      break;
    }
    case BAD_NEWLINE:
      data[size - 1] = 'X';
      break;
    case BAD_COUNT: {
      uint32_t key_length = 0;
      memcpy(&key_length, data + binary_offset + 1, sizeof(key_length));
      size_t count_offset = binary_offset + 5U + key_length;
      ASSERT(count_offset + sizeof(uint64_t) <= size);
      data[count_offset]--;
      break;
    }
    }
    fixture = fopen(path, "wb");
    ASSERT(fixture != NULL);
    ASSERT(fwrite(data, 1, size, fixture) == size);
    ASSERT(fclose(fixture) == 0);
    free(data);

    errno = 0;
    ASSERT_EQ_INT(sg_anomaly_model_load(loaded, path), SG_ANOMALY_ERR_FORMAT);
    ASSERT_EQ_INT(errno, EPROTO);
    ASSERT_EQ_INT(sg_anomaly_model_vocab_size(loaded), 5);
    ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(loaded), 25);
    ASSERT_EQ_DBL(sg_anomaly_score(loaded, commands, 5), preserved_score,
                  0.000001);
  }

  unsigned char *crlf_metadata = malloc(valid_size + 1U);
  ASSERT(crlf_metadata != NULL);
  size_t metadata_newline = binary_offset - 1U;
  memcpy(crlf_metadata, valid, metadata_newline);
  crlf_metadata[metadata_newline] = '\r';
  memcpy(crlf_metadata + metadata_newline + 1U, valid + metadata_newline,
         valid_size - metadata_newline);
  fixture = fopen(path, "wb");
  ASSERT(fixture != NULL);
  ASSERT(fwrite(crlf_metadata, 1, valid_size + 1U, fixture) == valid_size + 1U);
  ASSERT(fclose(fixture) == 0);
  free(crlf_metadata);
  ASSERT_EQ_INT(sg_anomaly_model_load(loaded, path), SG_ANOMALY_OK);
  ASSERT_EQ_DBL(sg_anomaly_score(loaded, commands, 5), known_score, 0.000001);

  fixture = fopen(path, "wb");
  ASSERT(fixture != NULL);
  /* Version 5 used NUL-delimited model keys and is deliberately not
   * compatible with binary-safe version 6. Loading remains atomic. */
  ASSERT(fprintf(fixture, "# anomaly-model-v5\n") > 0);
  ASSERT(fprintf(fixture, "# 0.1 -10 0.5 0 0 0 0 0 0\n") > 0);
  ASSERT(fclose(fixture) == 0);
  errno = 0;
  ASSERT_EQ_INT(sg_anomaly_model_load(loaded, path), SG_ANOMALY_ERR_FORMAT);
  ASSERT_EQ_INT(errno, EPROTO);
  ASSERT_EQ_DBL(sg_anomaly_score(loaded, commands, 5), known_score, 0.000001);

  fixture = fopen(path, "wb");
  ASSERT(fixture != NULL);
  ASSERT(fprintf(fixture, "# anomaly-model-v6\n") > 0);
  ASSERT(fprintf(fixture, "# 0.1 -10 0.5 0 0 0 0 0 0\n") > 0);
  for (unsigned char key = 'a'; key <= 'c'; key++) {
    const uint8_t type = 1;
    const uint32_t key_length = 4;
    const uint64_t count = INT64_MAX;
    const unsigned char record_key[] = {'1', ':', key, ','};
    ASSERT(fwrite(&type, 1, 1, fixture) == 1);
    ASSERT(fwrite(&key_length, sizeof(key_length), 1, fixture) == 1);
    ASSERT(fwrite(record_key, 1, sizeof(record_key), fixture) ==
           sizeof(record_key));
    ASSERT(fwrite(&count, sizeof(count), 1, fixture) == 1);
    ASSERT(fputc('\n', fixture) != EOF);
  }
  ASSERT(fclose(fixture) == 0);
  errno = 0;
  ASSERT_EQ_INT(sg_anomaly_model_load(loaded, path), SG_ANOMALY_ERR_LIMIT);
  ASSERT_EQ_INT(errno, EOVERFLOW);
  ASSERT_EQ_DBL(sg_anomaly_score(loaded, commands, 5), known_score, 0.000001);

  fixture = fopen(path, "wb");
  ASSERT(fixture != NULL);
  ASSERT(fwrite(valid, 1, valid_size, fixture) == valid_size);
  ASSERT(fclose(fixture) == 0);
  free(valid);
  ASSERT_EQ_INT(sg_anomaly_model_load(loaded, path), SG_ANOMALY_OK);
  ASSERT_EQ_DBL(sg_anomaly_score(loaded, commands, 5), known_score, 0.000001);

  sg_anomaly_model_free(source);
  sg_anomaly_model_free(loaded);
  unlink(path);
}

TEST(reset_and_error_state) {
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  ASSERT(model != NULL);
  update_repeated(model, commands, 5, 3);
  ASSERT(!sg_anomaly_model_had_error(model));
  sg_anomaly_model_clear_error(model);
  ASSERT(!sg_anomaly_model_had_error(model));
  ASSERT_EQ_INT(sg_anomaly_model_reset(model), SG_ANOMALY_OK);
  ASSERT(!sg_anomaly_model_had_error(model));
  ASSERT_EQ_INT(sg_anomaly_model_vocab_size(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_bigrams(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_trigrams(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_fourgrams(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_contexts(model), 0);
  ASSERT(isinf(sg_anomaly_score(model, commands, 5)));
  sg_anomaly_model_free(model);
}

TEST(maintenance_failures_are_atomic) {
  const size_t operation_count = 3;
  for (size_t operation = 0; operation < operation_count; operation++) {
    size_t allocation_failures = 0;
    size_t operation_failures = 0;
    sg_anomaly_model_t *probe = sg_anomaly_model_new();
    ASSERT(probe != NULL);
    update_repeated(probe, commands, 5, 4);
    sg_test_alloc_reset();
    sg_test_anomaly_op_reset();
    size_t probe_removed = 0;
    sg_anomaly_status_t probe_status;
    if (operation == 0)
      probe_status = sg_anomaly_model_reset(probe);
    else if (operation == 1)
      probe_status = sg_anomaly_model_decay(probe, 0.5);
    else
      probe_status = sg_anomaly_model_prune(probe, 2, &probe_removed);
    ASSERT_EQ_INT(probe_status, SG_ANOMALY_OK);
    allocation_failures = sg_test_alloc_count();
    operation_failures = sg_test_anomaly_op_count();
    sg_anomaly_model_free(probe);

    for (size_t fail_at = 1; fail_at <= allocation_failures; fail_at++) {
      sg_anomaly_model_t *model = sg_anomaly_model_new();
      ASSERT(model != NULL);
      update_repeated(model, commands, 5, 4);
      anomaly_snapshot_t before = snapshot_model(model);
      sg_test_alloc_fail_at(fail_at);
      sg_test_anomaly_op_reset();
      size_t removed = 123;
      sg_anomaly_status_t status =
          operation == 0   ? sg_anomaly_model_reset(model)
          : operation == 1 ? sg_anomaly_model_decay(model, 0.5)
                           : sg_anomaly_model_prune(model, 2, &removed);
      sg_test_alloc_reset();
      sg_test_anomaly_op_reset();
      ASSERT_EQ_INT(status, SG_ANOMALY_ERR_MEMORY);
      ASSERT(snapshot_equal(before, snapshot_model(model)));
      if (operation == 2)
        ASSERT_EQ_INT(removed, 123);
      ASSERT(sg_anomaly_model_had_error(model));
      sg_anomaly_model_clear_error(model);
      ASSERT(!sg_anomaly_model_had_error(model));
      sg_anomaly_model_free(model);
    }

    for (size_t fail_at = 1; fail_at <= operation_failures; fail_at++) {
      sg_anomaly_model_t *model = sg_anomaly_model_new();
      ASSERT(model != NULL);
      update_repeated(model, commands, 5, 4);
      anomaly_snapshot_t before = snapshot_model(model);
      sg_test_alloc_reset();
      sg_test_anomaly_op_fail_at(fail_at);
      size_t removed = 123;
      sg_anomaly_status_t status =
          operation == 0   ? sg_anomaly_model_reset(model)
          : operation == 1 ? sg_anomaly_model_decay(model, 0.5)
                           : sg_anomaly_model_prune(model, 2, &removed);
      sg_test_anomaly_op_reset();
      ASSERT_EQ_INT(status, SG_ANOMALY_ERR_MEMORY);
      ASSERT(snapshot_equal(before, snapshot_model(model)));
      if (operation == 2)
        ASSERT_EQ_INT(removed, 123);
      ASSERT(sg_anomaly_model_had_error(model));
      sg_anomaly_model_clear_error(model);
      ASSERT(!sg_anomaly_model_had_error(model));
      sg_anomaly_model_free(model);
    }
  }
}

TEST(decay_matrix) {
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  ASSERT(model != NULL);
  update_repeated(model, commands, 5, 4);
  ASSERT_EQ_INT(sg_anomaly_model_unknown_count(model), 5);
  static const double invalid_scales[] = {0.0, -0.5,     2.0,
                                          NAN, INFINITY, -INFINITY};
  for (size_t i = 0; i < sizeof(invalid_scales) / sizeof(invalid_scales[0]);
       i++)
    ASSERT_EQ_INT(sg_anomaly_model_decay(model, invalid_scales[i]),
                  SG_ANOMALY_ERR_INVALID);
  ASSERT_EQ_INT(sg_anomaly_model_decay(model, 1.0), SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(model), 20);
  ASSERT_EQ_INT(sg_anomaly_model_total_fourgrams(model), 8);

  ASSERT_EQ_INT(sg_anomaly_model_decay(model, 0.5), SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_vocab_size(model), 5);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(model), 10);
  ASSERT_EQ_INT(sg_anomaly_model_total_bigrams(model), 8);
  ASSERT_EQ_INT(sg_anomaly_model_total_trigrams(model), 6);
  ASSERT_EQ_INT(sg_anomaly_model_total_fourgrams(model), 4);
  ASSERT_EQ_INT(sg_anomaly_model_unknown_count(model), 2);
  for (size_t i = 0; i < 5; i++)
    ASSERT_EQ_INT(
        sg_anomaly_model_unigram_count_view(
            model, (sg_anomaly_item_view_t){commands[i], strlen(commands[i])}),
        2);
  ASSERT(isfinite(sg_anomaly_score(model, commands, 5)));
  sg_anomaly_model_free(model);
}

TEST(decay_removes_large_rare_model) {
  enum { COMMAND_COUNT = 96 };
  char storage[COMMAND_COUNT][16];
  const char *sequence[COMMAND_COUNT];
  for (size_t i = 0; i < COMMAND_COUNT; i++) {
    snprintf(storage[i], sizeof(storage[i]), "cmd%03zu", i);
    sequence[i] = storage[i];
  }
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  ASSERT(model != NULL);
  sg_anomaly_update(model, sequence, COMMAND_COUNT);
  ASSERT_EQ_INT(sg_anomaly_model_vocab_size(model), COMMAND_COUNT);
  ASSERT_EQ_INT(sg_anomaly_model_decay(model, 0.5), SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_vocab_size(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_bigrams(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_trigrams(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_fourgrams(model), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_contexts(model), 0);
  sg_anomaly_model_free(model);
}

TEST(prune_and_compact_preserve_common_behavior) {
  const char *common[] = {"ls", "cd", "pwd", "echo"};
  const char *rare[] = {"gcc", "make", "test", "install"};
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  ASSERT(model != NULL);
  update_repeated(model, common, 4, 4);
  sg_anomaly_update(model, rare, 4);
  size_t removed = 0;
  ASSERT_EQ_INT(sg_anomaly_model_prune(model, 2, &removed), SG_ANOMALY_OK);
  ASSERT(removed > 0);
  ASSERT_EQ_INT(sg_anomaly_model_vocab_size(model), 4);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(model), 16);
  ASSERT_EQ_INT(sg_anomaly_model_total_bigrams(model), 12);
  ASSERT_EQ_INT(sg_anomaly_model_total_trigrams(model), 8);
  ASSERT_EQ_INT(sg_anomaly_model_total_fourgrams(model), 4);
  ASSERT_EQ_INT(
      sg_anomaly_model_unigram_count_view(
          model, (sg_anomaly_item_view_t){"gcc", (sizeof("gcc") - 1)}),
      0);
  ASSERT_EQ_INT(
      sg_anomaly_model_fourgram_count_view(
          model, (sg_anomaly_item_view_t){"gcc", (sizeof("gcc") - 1)},
          (sg_anomaly_item_view_t){"make", (sizeof("make") - 1)},
          (sg_anomaly_item_view_t){"test", (sizeof("test") - 1)},
          (sg_anomaly_item_view_t){"install", (sizeof("install") - 1)}),
      0);
  ASSERT_EQ_INT(sg_anomaly_model_prune(model, 0, &removed), SG_ANOMALY_OK);
  ASSERT_EQ_INT(removed, 0);
  double score = sg_anomaly_score(model, common, 4);
  ASSERT_EQ_INT(sg_anomaly_model_compact(model), SG_ANOMALY_OK);
  ASSERT_EQ_DBL(sg_anomaly_score(model, common, 4), score, 0.000001);
  sg_anomaly_model_free(model);
}

TEST(maintenance_rebuilds_derived_contexts) {
  static const char common[] = "1:a,1:b,1:c,1:d,";
  static const char shared_rare[] = "1:a,1:b,1:c,1:e,";
  static const char disjoint_rare[] = "1:w,1:x,1:y,1:z,";
  for (unsigned operation = 0; operation < 2; operation++) {
    sg_anomaly_model_t *model = sg_anomaly_model_new();
    ASSERT(model != NULL);
    for (unsigned repetition = 0; repetition < 3; repetition++)
      ASSERT_EQ_INT(
          sg_anomaly_model_update_netseq(model, common, sizeof(common) - 1),
          SG_ANOMALY_OK);
    ASSERT_EQ_INT(sg_anomaly_model_update_netseq(model, shared_rare,
                                                 sizeof(shared_rare) - 1),
                  SG_ANOMALY_OK);
    ASSERT_EQ_INT(sg_anomaly_model_update_netseq(model, disjoint_rare,
                                                 sizeof(disjoint_rare) - 1),
                  SG_ANOMALY_OK);

    size_t removed = SIZE_MAX;
    sg_anomaly_status_t status =
        operation == 0 ? sg_anomaly_model_decay(model, 0.75)
                       : sg_anomaly_model_prune(model, 2, &removed);
    ASSERT_EQ_INT(status, SG_ANOMALY_OK);
    if (operation == 1)
      /* Four shared-tail and ten disjoint authoritative n-grams disappear;
       * derived context entries are deliberately not part of this count. */
      ASSERT_EQ_INT(removed, 14);

    double before = INFINITY;
    ASSERT_EQ_INT(sg_anomaly_model_score_netseq(model, common,
                                                sizeof(common) - 1, &before),
                  SG_ANOMALY_OK);
    ASSERT(isfinite(before));
    size_t contexts = sg_anomaly_model_total_contexts(model);
    sg_anomaly_model_t *loaded = roundtrip_model(model);
    ASSERT(loaded != NULL);
    double after = INFINITY;
    ASSERT_EQ_INT(sg_anomaly_model_score_netseq(loaded, common,
                                                sizeof(common) - 1, &after),
                  SG_ANOMALY_OK);
    ASSERT(after == before);
    ASSERT_EQ_INT(sg_anomaly_model_total_contexts(loaded), contexts);
    ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(loaded),
                  sg_anomaly_model_total_unigrams(model));
    ASSERT_EQ_INT(sg_anomaly_model_total_bigrams(loaded),
                  sg_anomaly_model_total_bigrams(model));
    ASSERT_EQ_INT(sg_anomaly_model_total_trigrams(loaded),
                  sg_anomaly_model_total_trigrams(model));
    ASSERT_EQ_INT(sg_anomaly_model_total_fourgrams(loaded),
                  sg_anomaly_model_total_fourgrams(model));
    sg_anomaly_model_free(loaded);
    sg_anomaly_model_free(model);
  }
}

/* Deliberately slow independent probability reference: derive each context
 * by enumerating the complete fixture vocabulary and public n-gram counts.
 * It neither reads internal context entries nor uses the production scorer. */
static size_t reference_ngram_count(const sg_anomaly_model_t *model,
                                    const sg_anomaly_item_view_t *items,
                                    size_t order) {
  switch (order) {
  case 1:
    return sg_anomaly_model_unigram_count_view(model, items[0]);
  case 2:
    return sg_anomaly_model_bigram_count_view(model, items[0], items[1]);
  case 3:
    return sg_anomaly_model_trigram_count_view(model, items[0], items[1],
                                               items[2]);
  default:
    return sg_anomaly_model_fourgram_count_view(model, items[0], items[1],
                                                items[2], items[3]);
  }
}

static double
reference_stage_probability(const sg_anomaly_model_t *model,
                            const sg_anomaly_item_view_t *window, size_t order,
                            const sg_anomaly_item_view_t *vocabulary,
                            size_t vocabulary_count) {
  const double alpha = 0.1;
  size_t count = reference_ngram_count(model, window + order - 1, 1);
  double probability;
  if (count) {
    probability = ((double)count + alpha) /
                  ((double)sg_anomaly_model_total_unigrams(model) +
                   alpha * (double)sg_anomaly_model_vocab_size(model));
  } else {
    double unknown = (double)sg_anomaly_model_unknown_count(model);
    probability = (unknown + alpha) /
                  ((double)sg_anomaly_model_total_unigrams(model) + unknown +
                   alpha * ((double)sg_anomaly_model_vocab_size(model) + 1.0));
  }
  double discount = sg_anomaly_model_kneser_ney_discount(model);
  for (size_t level = 2; level <= order; level++) {
    const sg_anomaly_item_view_t *items = window + order - level;
    count = reference_ngram_count(model, items, level);
    if (!count)
      continue;
    sg_anomaly_item_view_t candidate[4];
    memcpy(candidate, items, (level - 1) * sizeof(*candidate));
    size_t total = 0, continuations = 0;
    for (size_t i = 0; i < vocabulary_count; i++) {
      candidate[level - 1] = vocabulary[i];
      size_t observed = reference_ngram_count(model, candidate, level);
      total += observed;
      continuations += observed != 0;
    }
    probability = (fmax(0.0, (double)count - discount) +
                   discount * (double)continuations * probability) /
                  (double)total;
    probability = fmin(1.0, probability);
  }
  return probability;
}

static bool score_matches_reference(const sg_anomaly_model_t *model,
                                    const sg_anomaly_item_view_t *items,
                                    size_t count,
                                    const sg_anomaly_item_view_t *vocabulary,
                                    size_t vocabulary_count) {
  char encoded[512];
  size_t length = 0;
  for (size_t i = 0; i < count; i++) {
    size_t written;
    if (shell_netstring_write(encoded + length, sizeof(encoded) - length,
                              items[i].data, items[i].length,
                              &written) != SHELL_NETSTRING_OK)
      return false;
    length += written;
  }
  double actual = INFINITY;
  if (sg_anomaly_model_score_netseq(model, encoded, length, &actual) !=
      SG_ANOMALY_OK)
    return false;
  size_t order = count == 3 ? 3 : 4;
  double bits = 0.0;
  for (size_t end = order; end <= count; end++)
    bits -= log2(reference_stage_probability(model, items + end - order, order,
                                             vocabulary, vocabulary_count));
  double expected = bits / (double)(count - order + 1);
  return isfinite(actual) && fabs(actual - expected) <= 1e-9;
}

static bool reference_score_matrix(const sg_anomaly_model_t *model) {
  static const char binary[] = {'x', '\0'};
  static const sg_anomaly_item_view_t vocabulary[] = {
      {"a", 1},
      {"b", 1},
      {"c", 1},
      {"d", 1},
      {"e", 1},
      {"", 0},
      {binary, sizeof(binary)},
  };
  const sg_anomaly_item_view_t queries[][6] = {
      {{"a", 1}, {"b", 1}, {"c", 1}, {"d", 1}, {"a", 1}, {"b", 1}},
      {{"a", 1}, {"b", 1}, {"c", 1}, {"e", 1}, {"c", 1}, {"d", 1}},
      {{"b", 1}, {"b", 1}, {"c", 1}, {"d", 1}, {"c", 1}, {"e", 1}},
      {{"", 0},
       {"b", 1},
       {binary, sizeof(binary)},
       {"d", 1},
       {"", 0},
       {"b", 1}},
      {{"missing", 7}, {"b", 1}, {"c", 1}, {"d", 1}, {"missing", 7}, {"", 0}},
      {{"a", 1}, {"missing", 7}, {"c", 1}, {"e", 1}, {"b", 1}, {"d", 1}},
  };
  for (size_t i = 0; i < sizeof(queries) / sizeof(queries[0]); i++)
    for (size_t count = 3; count <= 6; count++)
      if (!score_matches_reference(model, queries[i], count, vocabulary,
                                   sizeof(vocabulary) / sizeof(vocabulary[0])))
        return false;
  return true;
}

TEST(context_statistics_match_probability_reference) {
  static const char binary_sample[] = "0:,1:b,2:x\0,1:d,0:,";
  static const struct {
    const char *sequence;
    size_t length, repetitions;
  } samples[] = {{"1:a,1:b,1:c,1:d,", 16, 5},
                 {"1:a,1:b,1:c,1:e,", 16, 3},
                 {"1:b,1:b,1:c,1:d,", 16, 2},
                 {binary_sample, sizeof(binary_sample) - 1, 1}};
  for (size_t maintenance = 0; maintenance < 3; maintenance++) {
    sg_anomaly_model_t *model = sg_anomaly_model_new();
    ASSERT(model != NULL);
    bool ok = true;
    for (size_t s = 0; ok && s < sizeof(samples) / sizeof(samples[0]); s++)
      for (size_t r = 0; ok && r < samples[s].repetitions; r++)
        ok = sg_anomaly_model_update_netseq(model, samples[s].sequence,
                                            samples[s].length) ==
                 SG_ANOMALY_OK &&
             reference_score_matrix(model);
    size_t removed;
    if (ok && maintenance == 1)
      ok = sg_anomaly_model_prune(model, 2, &removed) == SG_ANOMALY_OK;
    else if (ok && maintenance == 2)
      ok = sg_anomaly_model_decay(model, 0.75) == SG_ANOMALY_OK;
    ok = ok && reference_score_matrix(model);
    sg_anomaly_model_t *loaded = ok ? roundtrip_model(model) : NULL;
    ok = ok && loaded && reference_score_matrix(loaded) &&
         sg_anomaly_model_compact(loaded) == SG_ANOMALY_OK &&
         reference_score_matrix(loaded);
    sg_anomaly_model_free(loaded);
    sg_anomaly_model_free(model);
    ASSERT(ok);
  }
}

TEST(compaction_failures_preserve_counts_and_sticky_error) {
  static const char common[] = "1:a,1:b,1:c,1:d,";
  static const char alternative[] = "1:a,1:b,1:c,1:e,";
  static const char binary[] = "0:,1:b,2:x\0,1:d,0:,";
  for (size_t fail_at = 1; fail_at <= 7; fail_at++) {
    sg_anomaly_model_t *model = sg_anomaly_model_new();
    ASSERT(model != NULL);
    ASSERT_EQ_INT(
        sg_anomaly_model_update_netseq(model, common, sizeof(common) - 1),
        SG_ANOMALY_OK);
    ASSERT_EQ_INT(sg_anomaly_model_update_netseq(model, alternative,
                                                 sizeof(alternative) - 1),
                  SG_ANOMALY_OK);
    ASSERT_EQ_INT(
        sg_anomaly_model_update_netseq(model, binary, sizeof(binary) - 1),
        SG_ANOMALY_OK);
    anomaly_snapshot_t before = snapshot_model(model);
    bool correct =
        !sg_anomaly_model_had_error(model) && reference_score_matrix(model);
    sg_test_anomaly_op_fail_at(fail_at);
    sg_anomaly_status_t status = sg_anomaly_model_compact(model);
    size_t operations = sg_test_anomaly_op_count();
    sg_test_anomaly_op_reset();
    correct = correct && status == SG_ANOMALY_ERR_MEMORY && operations == 7 &&
              sg_anomaly_model_had_error(model) &&
              snapshot_equal(before, snapshot_model(model)) &&
              reference_score_matrix(model) &&
              sg_anomaly_model_unigram_count_view(
                  model, (sg_anomaly_item_view_t){"", 0}) == 2 &&
              sg_anomaly_model_fourgram_count_view(
                  model, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)},
                  (sg_anomaly_item_view_t){"b", (sizeof("b") - 1)},
                  (sg_anomaly_item_view_t){"c", (sizeof("c") - 1)},
                  (sg_anomaly_item_view_t){"e", (sizeof("e") - 1)}) == 1;
    sg_test_anomaly_op_reset();
    status = sg_anomaly_model_compact(model);
    operations = sg_test_anomaly_op_count();
    sg_test_anomaly_op_reset();
    correct = correct && status == SG_ANOMALY_OK && operations == 7 &&
              sg_anomaly_model_had_error(model) &&
              snapshot_equal(before, snapshot_model(model)) &&
              reference_score_matrix(model);
    size_t removed = SIZE_MAX;
    correct = correct &&
              sg_anomaly_model_prune(model, 1, &removed) == SG_ANOMALY_OK &&
              removed == 0 && sg_anomaly_model_had_error(model) &&
              sg_anomaly_model_decay(model, 0.75) == SG_ANOMALY_OK &&
              sg_anomaly_model_had_error(model);
    sg_anomaly_model_clear_error(model);
    correct = correct && !sg_anomaly_model_had_error(model) &&
              sg_anomaly_model_compact(model) == SG_ANOMALY_OK &&
              !sg_anomaly_model_had_error(model);
    sg_test_anomaly_op_fail_at(1);
    status = sg_anomaly_model_compact(model);
    sg_test_anomaly_op_reset();
    correct = correct && status == SG_ANOMALY_ERR_MEMORY &&
              sg_anomaly_model_had_error(model) &&
              sg_anomaly_model_reset(model) == SG_ANOMALY_OK &&
              !sg_anomaly_model_had_error(model);
    sg_anomaly_model_free(model);
    ASSERT(correct);
  }
}

TEST(context_statistics_rollback_is_atomic) {
  static const char common[] = "1:a,1:b,1:c,1:d,";
  static const char alternative[] = "1:a,1:b,1:c,1:e,";
  static const char update[] = "1:a,1:b,1:c,1:e,1:a,1:b,1:c,1:e,";
  static const char type_update[] = "1:a,1:b,1:c,1:d,1:a,1:b,1:c,1:d,";
  sg_anomaly_model_t *probe_raw = sg_anomaly_model_new();
  sg_anomaly_model_t *probe_type = sg_anomaly_model_new();
  ASSERT(probe_raw != NULL && probe_type != NULL);
  ASSERT_EQ_INT(sg_anomaly_models_update_netseq_pair(
                    probe_raw, common, sizeof(common) - 1, probe_type,
                    alternative, sizeof(alternative) - 1),
                SG_ANOMALY_OK);
  sg_test_anomaly_op_reset();
  ASSERT_EQ_INT(sg_anomaly_models_update_netseq_pair(
                    probe_raw, update, sizeof(update) - 1, probe_type,
                    type_update, sizeof(type_update) - 1),
                SG_ANOMALY_OK);
  size_t operations = sg_test_anomaly_op_count();
  sg_test_anomaly_op_reset();
  sg_anomaly_model_free(probe_raw);
  sg_anomaly_model_free(probe_type);
  ASSERT(operations > 1);

  /* New suffixes share existing contexts, and repeated suffixes in the same
   * transaction must not add another distinct continuation. Fail before and
   * after each mutation, including after the complete raw half has applied. */
  for (size_t fault = 1; fault <= operations; fault++) {
    sg_anomaly_model_t *raw = sg_anomaly_model_new();
    sg_anomaly_model_t *type = sg_anomaly_model_new();
    ASSERT(raw != NULL && type != NULL);
    bool ok = sg_anomaly_models_update_netseq_pair(
                  raw, common, sizeof(common) - 1, type, alternative,
                  sizeof(alternative) - 1) == SG_ANOMALY_OK;
    anomaly_snapshot_t raw_before = snapshot_model(raw);
    anomaly_snapshot_t type_before = snapshot_model(type);
    sg_test_anomaly_op_fail_at(fault);
    sg_anomaly_status_t status = sg_anomaly_models_update_netseq_pair(
        raw, update, sizeof(update) - 1, type, type_update,
        sizeof(type_update) - 1);
    sg_test_anomaly_op_reset();
    ok = ok && status == SG_ANOMALY_ERR_MEMORY &&
         snapshot_equal(raw_before, snapshot_model(raw)) &&
         snapshot_equal(type_before, snapshot_model(type)) &&
         reference_score_matrix(raw) && reference_score_matrix(type);
    if (ok)
      ok = sg_anomaly_models_update_netseq_pair(
               raw, update, sizeof(update) - 1, type, type_update,
               sizeof(type_update) - 1) == SG_ANOMALY_OK &&
           reference_score_matrix(raw) && reference_score_matrix(type);
    sg_anomaly_model_free(raw);
    sg_anomaly_model_free(type);
    ASSERT(ok);
  }
}

TEST(scoring_work_is_linear) {
  size_t previous_work = 0, previous_count = 0;
  for (size_t count = 128; count <= 2048; count *= 2) {
    char (*names)[24] = malloc(count * sizeof(*names));
    const char **items = malloc(count * sizeof(*items));
    sg_anomaly_model_t *model = sg_anomaly_model_new();
    bool ok = names && items && model;
    for (size_t i = 0; ok && i < count; i++) {
      int length = snprintf(names[i], sizeof(names[i]), "stage%zu", i);
      ok = length > 0 && (size_t)length < sizeof(names[i]);
      items[i] = names[i];
    }
    shell_netstring_buffer_t sequence =
        ok ? test_encode_netseq(items, count) : (shell_netstring_buffer_t){0};
    ok = ok && sequence.data &&
         sg_anomaly_model_update_netseq(model, (const char *)sequence.data,
                                        sequence.length) == SG_ANOMALY_OK;
    double score = INFINITY;
    sg_test_anomaly_work_reset();
    if (ok)
      ok = sg_anomaly_model_score_netseq(model, (const char *)sequence.data,
                                         sequence.length,
                                         &score) == SG_ANOMALY_OK &&
           isfinite(score);
    size_t work = sg_test_anomaly_work_count();
    ok = ok && work >= count && work <= 8 * count &&
         (!previous_count ||
          work <= previous_work + 8 * (count - previous_count));
    previous_work = work;
    previous_count = count;
    /* Growing the learned model must not increase the cost of a fixed query. */
    sg_test_anomaly_work_reset();
    if (ok)
      ok = isfinite(sg_anomaly_score(model, items, 4));
    ok = ok && sg_test_anomaly_work_count() <= 8;
    sg_anomaly_model_free(model);
    shell_netstring_buffer_free(&sequence);
    free(items);
    free(names);
    ASSERT(ok);
  }
}

TEST(one_pass_score_and_count) {
  static const char valid[] = "1:a,1:b,1:c,1:d,0:,";
  static const char *const malformed[] = {
      "1:a,x",
      "1:a,1:b,x",
      "1:a,1:b,1:c,x",
      "1:a,1:b,1:c,1:d,01:x,",
  };
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  ASSERT(model != NULL);
  for (int trained = 0; trained < 2; trained++) {
    double score = -1;
    size_t count = SIZE_MAX;
    ASSERT_EQ_INT(sg_anomaly_score_netseq_count(model, valid, sizeof(valid) - 1,
                                                &score, &count),
                  SG_ANOMALY_OK);
    ASSERT_EQ_INT(count, 5);
    ASSERT(trained ? isfinite(score) : isinf(score));
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
      score = -1;
      count = SIZE_MAX;
      ASSERT_EQ_INT(sg_anomaly_score_netseq_count(model, malformed[i],
                                                  strlen(malformed[i]), &score,
                                                  &count),
                    SG_ANOMALY_ERR_FORMAT);
      ASSERT(isinf(score) && count == 0);
    }
    static const char overflow[] = "999999999999999999999999999999:x,";
    ASSERT_EQ_INT(sg_anomaly_score_netseq_count(
                      model, overflow, sizeof(overflow) - 1, &score, &count),
                  SG_ANOMALY_ERR_LIMIT);
    ASSERT(isinf(score) && count == 0);
    ASSERT_EQ_INT(sg_anomaly_score_netseq_count(model, "", 0, &score, &count),
                  SG_ANOMALY_OK);
    ASSERT(isinf(score) && count == 0);
    ASSERT_EQ_INT(
        sg_anomaly_model_update_netseq(model, valid, sizeof(valid) - 1),
        SG_ANOMALY_OK);
  }
  double score = -1;
  size_t count = SIZE_MAX;
  sg_test_anomaly_score_fail_with(SG_ANOMALY_ERR_MEMORY);
  sg_anomaly_status_t status = sg_anomaly_score_netseq_count(
      model, valid, sizeof(valid) - 1, &score, &count);
  sg_test_anomaly_result_reset();
  ASSERT_EQ_INT(status, SG_ANOMALY_ERR_MEMORY);
  ASSERT(isinf(score) && count == 0);
  sg_anomaly_model_free(model);
}

TEST(canonical_netseq_contract) {
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  ASSERT(model != NULL);
  static const char valid[] = "9:two words,1::,1:,,";
  double score = -1;
  size_t count = SIZE_MAX;
  ASSERT_EQ_INT(sg_anomaly_score_netseq_count(model, valid, sizeof(valid) - 1,
                                              &score, &count),
                SG_ANOMALY_OK);
  ASSERT_EQ_INT(count, 3);
  ASSERT(isinf(score));
  ASSERT_EQ_INT(sg_anomaly_score_netseq_count(model, "", 0, &score, &count),
                SG_ANOMALY_OK);
  ASSERT_EQ_INT(count, 0);
  ASSERT(isinf(score));
  ASSERT_EQ_INT(
      sg_anomaly_score_netseq_count(model, "01:x,", 5, &score, &count),
      SG_ANOMALY_ERR_FORMAT);
  ASSERT(isinf(score) && count == 0);
  ASSERT_EQ_INT(sg_anomaly_model_update_netseq(model, valid, sizeof(valid) - 1),
                SG_ANOMALY_OK);
  bool observed = false;
  ASSERT_EQ_INT(sg_anomaly_model_has_observed_netseq(
                    model, valid, sizeof(valid) - 1, &observed),
                SG_ANOMALY_OK);
  ASSERT(observed);
  observed = true;
  ASSERT_EQ_INT(sg_anomaly_model_has_observed_netseq(model, "", 0, &observed),
                SG_ANOMALY_OK);
  ASSERT(!observed);
  ASSERT_EQ_INT(
      sg_anomaly_model_has_observed_netseq(model, "01:a,", 5, &observed),
      SG_ANOMALY_ERR_FORMAT);
  ASSERT_EQ_INT(sg_anomaly_model_vocab_size(model), 3);
  score = 0.0;
  ASSERT_EQ_INT(
      sg_anomaly_model_score_netseq(model, valid, sizeof(valid) - 1, &score),
      SG_ANOMALY_OK);
  ASSERT(isfinite(score));

  /* Netseq payloads are opaque bytes, including NUL. Canonical nested keys
   * must keep a NUL-bearing command distinct from a different record split. */
  static const char binary_known[] = {
      '3', ':', 'a', '\0', 'b', ',', '1', ':', 'c', ',', '1', ':', 'd', ',',
  };
  static const char binary_split[] = {
      '1', ':', 'a', ',', '3', ':', 'b', '\0', 'c', ',', '1', ':', 'd', ',',
  };
  ASSERT_EQ_INT(
      sg_anomaly_model_update_netseq(model, binary_known, sizeof(binary_known)),
      SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_has_observed_netseq(
                    model, binary_known, sizeof(binary_known), &observed),
                SG_ANOMALY_OK);
  ASSERT(observed);
  double binary_known_score = INFINITY;
  double binary_split_score = INFINITY;
  ASSERT_EQ_INT(sg_anomaly_model_score_netseq(model, binary_known,
                                              sizeof(binary_known),
                                              &binary_known_score),
                SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_score_netseq(model, binary_split,
                                              sizeof(binary_split),
                                              &binary_split_score),
                SG_ANOMALY_OK);
  ASSERT(isfinite(binary_known_score));
  ASSERT(isfinite(binary_split_score));
  ASSERT(binary_known_score < binary_split_score);

  static const char *invalid[] = {"01:x,", "1:x",  "2:x,", "x",
                                  "1x,",   "1:x;", "1:,"};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    score = 0.0;
    ASSERT_EQ_INT(sg_anomaly_model_score_netseq(model, invalid[i],
                                                strlen(invalid[i]), &score),
                  SG_ANOMALY_ERR_FORMAT);
    ASSERT(isinf(score));
  }
  ASSERT_EQ_INT(sg_anomaly_model_score_netseq(model, "0:,", 3, &score),
                SG_ANOMALY_OK);
  ASSERT(isinf(score));

  static const char framing_nul[] = {'1', ':', 'x', ',', '\0',
                                     '1', ':', 'y', ','};
  ASSERT_EQ_INT(sg_anomaly_model_score_netseq(model, framing_nul,
                                              sizeof(framing_nul), &score),
                SG_ANOMALY_ERR_FORMAT);
  ASSERT_EQ_INT(sg_anomaly_model_score_netseq(model, "", 0, &score),
                SG_ANOMALY_OK);
  ASSERT(isinf(score));
  ASSERT_EQ_INT(sg_anomaly_model_update_netseq(model, "", 0), SG_ANOMALY_OK);

  static const char overflow[] = "999999999999999999999999999999999999:x,";
  ASSERT_EQ_INT(
      sg_anomaly_model_update_netseq(model, overflow, sizeof(overflow) - 1),
      SG_ANOMALY_ERR_LIMIT);

  size_t large_length = SG_ANOMALY_MAX_STAGE_LENGTH + 1U;
  size_t large_capacity = large_length + 32U;
  char *large = malloc(large_capacity);
  ASSERT(large != NULL);
  int prefix = snprintf(large, large_capacity, "%zu:", large_length);
  ASSERT(prefix > 0);
  memset(large + prefix, 'z', large_length);
  large[prefix + large_length] = ',';
  size_t encoded_length = (size_t)prefix + large_length + 1U;
  large[encoded_length] = '\0';
  ASSERT(strlen(large) == encoded_length);
  ASSERT_EQ_INT(sg_anomaly_model_update_netseq(model, large, encoded_length),
                SG_ANOMALY_ERR_LIMIT);
  ASSERT_EQ_INT(
      sg_anomaly_model_score_netseq(model, large, encoded_length, &score),
      SG_ANOMALY_OK);
  ASSERT(isinf(score));

  const char *oversized_sequence[] = {large, "two words", ":"};
  shell_netstring_buffer_t oversized_netseq =
      test_encode_netseq(oversized_sequence, 3);
  ASSERT(oversized_netseq.data != NULL);
  ASSERT_EQ_INT(
      sg_anomaly_model_score_netseq(model, (const char *)oversized_netseq.data,
                                    oversized_netseq.length, &score),
      SG_ANOMALY_OK);
  ASSERT(isfinite(score));
  ASSERT_EQ_INT(sg_anomaly_model_has_observed_netseq(
                    model, (const char *)oversized_netseq.data,
                    oversized_netseq.length, &observed),
                SG_ANOMALY_OK);
  ASSERT(observed);
  shell_netstring_buffer_free(&oversized_netseq);

  const char *all_oversized[] = {large, large, large, large};
  shell_netstring_buffer_t all_oversized_netseq =
      test_encode_netseq(all_oversized, 4);
  ASSERT(all_oversized_netseq.data != NULL);
  ASSERT_EQ_INT(sg_anomaly_model_score_netseq(
                    model, (const char *)all_oversized_netseq.data,
                    all_oversized_netseq.length, &score),
                SG_ANOMALY_OK);
  ASSERT(isfinite(score));
  ASSERT_EQ_INT(sg_anomaly_model_has_observed_netseq(
                    model, (const char *)all_oversized_netseq.data,
                    all_oversized_netseq.length, &observed),
                SG_ANOMALY_OK);
  ASSERT(!observed);
  shell_netstring_buffer_free(&all_oversized_netseq);
  free(large);
  sg_anomaly_model_free(model);
}

TEST(binary_netseq_persistence) {
  static const char sequence[] = {
      '3', ':', 'a', '\0', 'b', ',', '1', ':', 'c',
      ',', '1', ':', 'd',  ',', '1', ':', 'e', ',',
  };
  const sg_anomaly_item_view_t binary = {.data = "a\0b", .length = 3};
  const sg_anomaly_item_view_t c = {.data = "c", .length = 1};
  const sg_anomaly_item_view_t d = {.data = "d", .length = 1};
  const sg_anomaly_item_view_t e = {.data = "e", .length = 1};
  char path[] = "/tmp/shellclave-anomaly-binary-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  close(fd);
  sg_anomaly_model_t *source = sg_anomaly_model_new();
  sg_anomaly_model_t *loaded = sg_anomaly_model_new();
  ASSERT(source != NULL && loaded != NULL);
  ASSERT_EQ_INT(
      sg_anomaly_model_update_netseq(source, sequence, sizeof(sequence)),
      SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(source, binary), 1);
  ASSERT_EQ_INT(sg_anomaly_model_bigram_count_view(source, binary, c), 1);
  ASSERT_EQ_INT(sg_anomaly_model_trigram_count_view(source, binary, c, d), 1);
  ASSERT_EQ_INT(sg_anomaly_model_fourgram_count_view(source, binary, c, d, e),
                1);
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(
                    source, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)}),
                0);
  ASSERT_EQ_INT(
      sg_anomaly_model_unigram_count_view(
          source, (sg_anomaly_item_view_t){.data = (const char *)binary.data,
                                           .length = 0}),
      0);
  ASSERT_EQ_INT(sg_anomaly_model_bigram_count_view(source, binary,
                                                   (sg_anomaly_item_view_t){0}),
                0);
  double source_score = INFINITY;
  ASSERT_EQ_INT(sg_anomaly_model_score_netseq(source, sequence,
                                              sizeof(sequence), &source_score),
                SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_save(source, path), SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_load(loaded, path), SG_ANOMALY_OK);
  bool observed = false;
  ASSERT_EQ_INT(sg_anomaly_model_has_observed_netseq(
                    loaded, sequence, sizeof(sequence), &observed),
                SG_ANOMALY_OK);
  ASSERT(observed);
  double loaded_score = INFINITY;
  ASSERT_EQ_INT(sg_anomaly_model_score_netseq(loaded, sequence,
                                              sizeof(sequence), &loaded_score),
                SG_ANOMALY_OK);
  ASSERT_EQ_DBL(loaded_score, source_score, 0.000001);
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(loaded, binary), 1);
  ASSERT_EQ_INT(sg_anomaly_model_bigram_count_view(loaded, binary, c), 1);
  ASSERT_EQ_INT(sg_anomaly_model_trigram_count_view(loaded, binary, c, d), 1);
  ASSERT_EQ_INT(sg_anomaly_model_fourgram_count_view(loaded, binary, c, d, e),
                1);
  sg_anomaly_model_free(source);
  sg_anomaly_model_free(loaded);
  ASSERT(unlink(path) == 0);
}

TEST(empty_stage_persistence_and_legacy_loading) {
  static const char sentinel_sequence[] = "4:echo,0:,4:sort,";
  static const char ordinary_sequence[] = "4:echo,4:sort,4:done,";
  sg_anomaly_model_t *source = sg_anomaly_model_new();
  sg_anomaly_model_t *loaded = sg_anomaly_model_new();
  ASSERT(source && loaded);
  ASSERT_EQ_INT(sg_anomaly_model_update_netseq(source, sentinel_sequence,
                                               sizeof(sentinel_sequence) - 1),
                SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(
                    source, (sg_anomaly_item_view_t){"", (sizeof("") - 1)}),
                1);

  FILE *stream = tmpfile();
  ASSERT(stream != NULL);
  ASSERT_EQ_INT(sg_anomaly_write_stream(source, stream), 0);
  ASSERT(fseek(stream, 0, SEEK_SET) == 0);
  char header[32] = {0};
  ASSERT(fgets(header, sizeof(header), stream) != NULL);
  ASSERT(strcmp(header, "# anomaly-model-v7\n") == 0);
  ASSERT(fseek(stream, 0, SEEK_SET) == 0);
  ASSERT_EQ_INT(sg_anomaly_read_stream(loaded, stream), 0);
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(
                    loaded, (sg_anomaly_item_view_t){"", (sizeof("") - 1)}),
                1);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(loaded), 3);
  ASSERT(fclose(stream) == 0);

  stream = tmpfile();
  ASSERT(stream != NULL);
  ASSERT_EQ_INT(sg_anomaly_model_update_netseq(loaded, ordinary_sequence,
                                               sizeof(ordinary_sequence) - 1),
                SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_write_stream(loaded, stream), 0);
  /* v6 uses canonical binary netstring keys but predates the empty
   * redirect-only-stage item, so relabeling this v7 sentinel model must fail
   * atomically. */
  ASSERT(fseek(stream, (sizeof("# anomaly-model-v") - 1), SEEK_SET) == 0);
  ASSERT(fputc('6', stream) == '6' && fflush(stream) == 0);
  ASSERT(fseek(stream, 0, SEEK_SET) == 0);
  size_t preserved_unigrams = sg_anomaly_model_total_unigrams(source);
  errno = 0;
  ASSERT_EQ_INT(sg_anomaly_read_stream(source, stream), SG_ANOMALY_ERR_FORMAT);
  ASSERT_EQ_INT(errno, EPROTO);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(source), preserved_unigrams);
  ASSERT(fclose(stream) == 0);

  sg_anomaly_model_t *legacy_source = sg_anomaly_model_new();
  ASSERT(legacy_source != NULL);
  ASSERT_EQ_INT(sg_anomaly_model_update_netseq(legacy_source, ordinary_sequence,
                                               sizeof(ordinary_sequence) - 1),
                SG_ANOMALY_OK);
  stream = tmpfile();
  ASSERT(stream != NULL);
  ASSERT_EQ_INT(sg_anomaly_write_stream(legacy_source, stream), 0);
  ASSERT(fseek(stream, (sizeof("# anomaly-model-v") - 1), SEEK_SET) == 0);
  ASSERT(fputc('6', stream) == '6' && fflush(stream) == 0);
  ASSERT(fseek(stream, 0, SEEK_SET) == 0);
  /* A non-empty legacy v6 model remains supported. */
  ASSERT_EQ_INT(sg_anomaly_read_stream(loaded, stream), 0);
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(
                    loaded, (sg_anomaly_item_view_t){"", (sizeof("") - 1)}),
                0);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(loaded), 3);
  ASSERT(fclose(stream) == 0);
  sg_anomaly_model_free(legacy_source);
  sg_anomaly_model_free(loaded);
  sg_anomaly_model_free(source);
}

TEST(typed_stream_io_failure_atomicity) {
  sg_anomaly_model_t *source = sg_anomaly_model_new();
  sg_anomaly_model_t *target = sg_anomaly_model_new();
  ASSERT(source && target);
  ASSERT_EQ_INT(sg_anomaly_model_update_netseq(source, "1:a,1:b,1:c,", 12),
                SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_update_netseq(target, "1:x,1:y,1:z,", 12),
                SG_ANOMALY_OK);
  FILE *stream = tmpfile();
  ASSERT(stream != NULL);
  sg_test_io_reset();
  ASSERT_EQ_INT(sg_anomaly_write_stream(source, stream), SG_ANOMALY_OK);
  size_t writes = sg_test_io_count();
  sg_test_io_reset();
  rewind(stream);
  ASSERT_EQ_INT(sg_anomaly_read_stream(source, stream), SG_ANOMALY_OK);
  size_t reads = sg_test_io_count();
  sg_test_io_reset();
  ASSERT(writes > 3 && reads > 2);
  static const int errors[] = {EIO, ENOMEM, EINVAL, EPROTO};
  for (size_t e = 0; e < sizeof(errors) / sizeof(errors[0]); e++) {
    for (size_t i = 1; i <= reads; i++) {
      rewind(stream);
      sg_test_io_fail_at_with_errno(i, errors[e]);
      sg_anomaly_status_t status = sg_anomaly_read_stream(target, stream);
      sg_test_io_reset();
      ASSERT_EQ_INT(status, errors[e] == ENOMEM ? SG_ANOMALY_ERR_MEMORY
                                                : SG_ANOMALY_ERR_IO);
      ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(target), 3);
      ASSERT_EQ_INT(
          sg_anomaly_model_unigram_count_view(
              target, (sg_anomaly_item_view_t){"x", (sizeof("x") - 1)}),
          1);
      ASSERT_EQ_INT(
          sg_anomaly_model_unigram_count_view(
              target, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)}),
          0);
    }
  }
  for (size_t i = 1; i <= writes; i++) {
    FILE *output = tmpfile();
    ASSERT(output != NULL);
    sg_test_io_fail_at(i);
    sg_anomaly_status_t status = sg_anomaly_write_stream(source, output);
    sg_test_io_reset();
    ASSERT_EQ_INT(status, SG_ANOMALY_ERR_IO);
    ASSERT(fclose(output) == 0);
  }
  rewind(stream);
  ASSERT_EQ_INT(sg_anomaly_read_stream(target, stream), SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(
                    target, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)}),
                1);
  ASSERT(fclose(stream) == 0);
  sg_anomaly_model_free(source);
  sg_anomaly_model_free(target);
}

TEST(owned_file_close_and_error_precedence) {
  char path[] = "/tmp/shellclave-anomaly-close-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  ASSERT(close(fd) == 0);
  snprintf(anomaly_temp_path, sizeof(anomaly_temp_path), "%s", path);
  sg_anomaly_model_t *source = test_model_with_config(0.5, -8.0);
  sg_anomaly_model_t *target = test_model_with_config(0.25, -12.0);
  ASSERT(source && target);
  update_repeated(source, commands, 5, 3);
  update_repeated(target, commands, 5, 1);
  sg_test_anomaly_op_fail_at(1);
  ASSERT_EQ_INT(sg_anomaly_model_update_netseq(target, "1:x,", 4),
                SG_ANOMALY_ERR_MEMORY);
  sg_test_anomaly_op_reset();
  ASSERT(sg_anomaly_model_had_error(target));
  anomaly_snapshot_t before = snapshot_model(target);
  ASSERT_EQ_INT(sg_anomaly_model_save(source, path), SG_ANOMALY_OK);

  static const int errors[] = {EIO, ENOMEM, EINVAL, EPROTO};
  for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
    sg_test_io_close_fail_with_errno(errors[i]);
    sg_anomaly_status_t status = sg_anomaly_model_load(target, path);
    int error_number = errno;
    sg_test_io_reset();
    ASSERT_EQ_INT(status, errors[i] == ENOMEM ? SG_ANOMALY_ERR_MEMORY
                                              : SG_ANOMALY_ERR_IO);
    ASSERT_EQ_INT(error_number, errors[i]);
    ASSERT(snapshot_equal(before, snapshot_model(target)));
    ASSERT(sg_anomaly_model_had_error(target));
  }
  /* Closing must preserve an earlier failure and release the actual FILE. */
  sg_test_io_fail_at_with_errno(1, ENOMEM);
  sg_test_io_close_fail_with_errno(EIO);
  ASSERT_EQ_INT(sg_anomaly_model_load(target, path), SG_ANOMALY_ERR_MEMORY);
  ASSERT_EQ_INT(errno, ENOMEM);
  sg_test_io_reset();
  ASSERT(snapshot_equal(before, snapshot_model(target)));
  ASSERT(sg_anomaly_model_had_error(target));

  /* Four begin operations precede the first serialization write. */
  sg_test_io_fail_at_with_errno(5, EINVAL);
  sg_test_io_close_fail_with_errno(ENOMEM);
  ASSERT_EQ_INT(sg_anomaly_model_save(source, path), SG_ANOMALY_ERR_IO);
  ASSERT_EQ_INT(errno, EINVAL);
  sg_test_io_reset();
  sg_test_io_close_fail_with_errno(EIO);
  ASSERT_EQ_INT(sg_anomaly_model_save(source, path), SG_ANOMALY_ERR_IO);
  ASSERT_EQ_INT(errno, EIO);
  sg_test_io_reset();

  FILE *malformed = fopen(path, "wb");
  ASSERT(malformed != NULL);
  ASSERT(fputs("broken\n", malformed) >= 0 && fclose(malformed) == 0);
  sg_test_io_close_fail_with_errno(ENOMEM);
  ASSERT_EQ_INT(sg_anomaly_model_load(target, path), SG_ANOMALY_ERR_FORMAT);
  ASSERT_EQ_INT(errno, EPROTO);
  sg_test_io_reset();
  ASSERT(snapshot_equal(before, snapshot_model(target)));
  ASSERT(sg_anomaly_model_had_error(target));

  ASSERT_EQ_INT(sg_anomaly_model_save(source, path), SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_load(target, path), SG_ANOMALY_OK);
  ASSERT(snapshot_equal(snapshot_model(source), snapshot_model(target)));
  ASSERT(!sg_anomaly_model_had_error(target));
  sg_anomaly_model_free(source);
  sg_anomaly_model_free(target);
  ASSERT(unlink(path) == 0);
  anomaly_temp_path[0] = '\0';
}

static bool write_count_record(FILE *stream, uint8_t type, const char *key,
                               uint64_t count) {
  uint32_t length = (uint32_t)strlen(key);
  return fwrite(&type, 1, 1, stream) == 1 &&
         fwrite(&length, sizeof(length), 1, stream) == 1 &&
         fwrite(key, 1, length, stream) == length &&
         fwrite(&count, sizeof(count), 1, stream) == 1 &&
         fputc('\n', stream) != EOF;
}

TEST(persisted_header_validation) {
  static const struct {
    const char *header;
    sg_anomaly_status_t status;
    int error_number;
  } cases[] = {
      {"# 0.1 -10 0.5 0 0 0 0 0 -1\n", SG_ANOMALY_ERR_FORMAT, EPROTO},
      {"# 0.1 -10 0.5 0 0 0 0 0 +1\n", SG_ANOMALY_ERR_FORMAT, EPROTO},
      {"# 0.1 -10 0.5 999999999999999999999999999999999999 0 0 0 0 "
       "0\n",
       SG_ANOMALY_ERR_LIMIT, EOVERFLOW},
      {"# 0.1 -10 0.5 0 0 0 0 0 "
       "999999999999999999999999999999999999\n",
       SG_ANOMALY_ERR_LIMIT, EOVERFLOW},
      {"# 0.1 -10 0 0 0 0 0 0 0\n", SG_ANOMALY_ERR_FORMAT, EPROTO},
      {"# 0.1 -10 1.00001 0 0 0 0 0 0\n", SG_ANOMALY_ERR_FORMAT, EPROTO},
      {"# 0.1 -10 0.5 0 0 0 0 0 0 trailing\n", SG_ANOMALY_ERR_FORMAT, EPROTO},
      {"# 0.1 -10 0.5 0 0 0 0 0\n", SG_ANOMALY_ERR_FORMAT, EPROTO},
      {"# nan -10 0.5 0 0 0 0 0 0\n", SG_ANOMALY_ERR_FORMAT, EPROTO},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_anomaly_model_t *target = sg_anomaly_model_new();
    ASSERT(target != NULL);
    update_repeated(target, commands, 5, 2);
    anomaly_snapshot_t before = snapshot_model(target);
    FILE *stream = tmpfile();
    ASSERT(stream != NULL);
    ASSERT(fputs("# anomaly-model-v7\n", stream) >= 0);
    ASSERT(fputs(cases[i].header, stream) >= 0);
    ASSERT(fflush(stream) == 0 && fseek(stream, 0, SEEK_SET) == 0);
    errno = 0;
    ASSERT_EQ_INT(sg_anomaly_read_stream(target, stream), cases[i].status);
    ASSERT_EQ_INT(errno, cases[i].error_number);
    ASSERT(snapshot_equal(before, snapshot_model(target)));
    ASSERT(fclose(stream) == 0);
    sg_anomaly_model_free(target);
  }

  /* The inclusive upper discount bound remains a valid empty model. */
  FILE *stream = tmpfile();
  ASSERT(stream != NULL);
  ASSERT(fputs("# anomaly-model-v7\n# 0.1 -10 1 0 0 0 0 0 0\n", stream) >= 0);
  ASSERT(fflush(stream) == 0 && fseek(stream, 0, SEEK_SET) == 0);
  sg_anomaly_model_t *loaded = NULL;
  ASSERT_EQ_INT(sg_anomaly_model_read_new(stream, &loaded), SG_ANOMALY_OK);
  ASSERT(loaded != NULL);
  ASSERT_EQ_DBL(sg_anomaly_model_kneser_ney_discount(loaded), 1.0, 0.0);
  sg_anomaly_model_free(loaded);
  ASSERT(fclose(stream) == 0);
}

TEST(persisted_header_framing) {
  static const char nul_header[] =
      "# anomaly-model-v7\n# 0.1 -10 0.5 0 0 0 0 0 0\0 hidden bytes\n";
  static const char nul_version[] =
      "# anomaly-model-v7\0 hidden bytes\n# 0.1 -10 0.5 0 0 0 0 0 0\n";
  static const char incomplete_version[] = "# anomaly-model-v7";
  static const char incomplete_header[] =
      "# anomaly-model-v7\n# 0.1 -10 0.5 0 0 0 0 0 0";
  static const char incomplete_crlf[] =
      "# anomaly-model-v7\n# 0.1 -10 0.5 0 0 0 0 0 0\r";
  static const struct {
    const char *data;
    size_t length;
  } cases[] = {{nul_header, sizeof(nul_header) - 1},
               {nul_version, sizeof(nul_version) - 1},
               {incomplete_version, sizeof(incomplete_version) - 1},
               {incomplete_header, sizeof(incomplete_header) - 1},
               {incomplete_crlf, sizeof(incomplete_crlf) - 1}};
  sg_anomaly_model_t *target = sg_anomaly_model_new();
  ASSERT(target != NULL);
  update_repeated(target, commands, 5, 2);
  anomaly_snapshot_t before = snapshot_model(target);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    FILE *stream = tmpfile();
    ASSERT(stream != NULL);
    ASSERT(fwrite(cases[i].data, 1, cases[i].length, stream) ==
           cases[i].length);
    ASSERT(fseek(stream, 0, SEEK_SET) == 0);
    ASSERT_EQ_INT(sg_anomaly_read_stream(target, stream),
                  SG_ANOMALY_ERR_FORMAT);
    ASSERT_EQ_INT(errno, EPROTO);
    ASSERT(snapshot_equal(before, snapshot_model(target)));
    ASSERT(fseek(stream, 0, SEEK_SET) == 0);
    sg_anomaly_model_t *loaded = NULL;
    ASSERT_EQ_INT(sg_anomaly_model_read_new(stream, &loaded),
                  SG_ANOMALY_ERR_FORMAT);
    ASSERT(loaded == NULL);
    ASSERT(fclose(stream) == 0);
  }
  sg_anomaly_model_free(target);

  /* At the physical buffer boundary a final newline is mandatory, but a
   * complete line filling all available byte positions is still valid. */
  static const char fields[] = "0.1 -10 0.5 0 0 0 0 0 0\n";
  for (size_t length = 254; length <= 256; length++) {
    char line[256];
    memset(line, ' ', length);
    line[0] = '#';
    memcpy(line + length - (sizeof(fields) - 1), fields, sizeof(fields) - 1);
    FILE *stream = tmpfile();
    ASSERT(stream != NULL);
    ASSERT(fputs("# anomaly-model-v7\n", stream) >= 0);
    ASSERT(fwrite(line, 1, length, stream) == length);
    ASSERT(fseek(stream, 0, SEEK_SET) == 0);
    sg_anomaly_model_t *loaded = NULL;
    ASSERT_EQ_INT(sg_anomaly_model_read_new(stream, &loaded),
                  length < 256 ? SG_ANOMALY_OK : SG_ANOMALY_ERR_FORMAT);
    ASSERT((loaded != NULL) == (length < 256));
    sg_anomaly_model_free(loaded);
    ASSERT(fclose(stream) == 0);
  }
  FILE *stream = tmpfile();
  ASSERT(stream != NULL);
  ASSERT(fputs("# anomaly-model-v6\r\n# 0.1 -10 0.5 0 0 0 0 0 0\r\n", stream) >=
         0);
  ASSERT(fseek(stream, 0, SEEK_SET) == 0);
  sg_anomaly_model_t *loaded = NULL;
  ASSERT_EQ_INT(sg_anomaly_model_read_new(stream, &loaded), SG_ANOMALY_OK);
  sg_anomaly_model_free(loaded);
  ASSERT(fclose(stream) == 0);
}

/* Always restore the thread locale before reporting an assertion failure. */
static bool locale_roundtrip_case(locale_t numeric, locale_t other,
                                  double alpha) {
  bool ok = false;
  FILE *stream = NULL;
  sg_anomaly_model_t *source = test_model_with_config(alpha, -10.0);
  sg_anomaly_model_t *loaded = NULL;
  locale_t previous = uselocale(numeric);
  if (!source)
    goto done;
  update_repeated(source, commands, 5, 2);
  stream = tmpfile();
  if (!stream || sg_anomaly_write_stream(source, stream) != SG_ANOMALY_OK ||
      uselocale((locale_t)0) != numeric || fseek(stream, 0, SEEK_SET) != 0)
    goto done;
  char version[64], header[256];
  if (!fgets(version, sizeof(version), stream) ||
      !fgets(header, sizeof(header), stream) || strchr(header, ',') ||
      fseek(stream, 0, SEEK_SET) != 0 ||
      sg_anomaly_model_read_new(stream, &loaded) != SG_ANOMALY_OK ||
      uselocale((locale_t)0) != numeric ||
      !snapshot_equal(snapshot_model(source), snapshot_model(loaded)))
    goto done;
  sg_anomaly_model_free(loaded);
  loaded = NULL;
  uselocale(other);
  if (fseek(stream, 0, SEEK_SET) != 0 ||
      sg_anomaly_model_read_new(stream, &loaded) != SG_ANOMALY_OK ||
      uselocale((locale_t)0) != other ||
      !snapshot_equal(snapshot_model(source), snapshot_model(loaded)))
    goto done;
  ok = true;
done:
  uselocale(previous);
  sg_anomaly_model_free(loaded);
  sg_anomaly_model_free(source);
  if (stream && fclose(stream) != 0)
    ok = false;
  return ok;
}

TEST(persistence_is_locale_independent) {
  locale_t comma = sg_test_comma_locale();
  if (!comma)
    return;
  locale_t numeric = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
  ASSERT(numeric != (locale_t)0);
  char *global = strdup(setlocale(LC_NUMERIC, NULL));
  ASSERT(global != NULL);
  bool ok = true;
  const double alphas[] = {DBL_TRUE_MIN, DBL_MIN, 0.1, DBL_MAX};
  for (size_t i = 0; i < sizeof(alphas) / sizeof(alphas[0]); i++) {
    ok = locale_roundtrip_case(comma, numeric, alphas[i]) && ok;
    ok = locale_roundtrip_case(numeric, comma, alphas[i]) && ok;
  }
  ok = strcmp(global, setlocale(LC_NUMERIC, NULL)) == 0 && ok;
  free(global);
  freelocale(numeric);
  freelocale(comma);
  ASSERT(ok);
}

TEST(persistence_locale_failures_are_atomic) {
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  ASSERT(model != NULL);
  update_repeated(model, commands, 5, 2);
  anomaly_snapshot_t before = snapshot_model(model);
  FILE *stream = tmpfile();
  ASSERT(stream != NULL);
  ASSERT_EQ_INT(sg_anomaly_write_stream(model, stream), SG_ANOMALY_OK);
  locale_t numeric = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
  ASSERT(numeric != (locale_t)0);
  locale_t previous = uselocale(numeric);
  bool ok = true;
  const int errors[] = {ENOMEM, EIO};
  for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++) {
    sg_anomaly_status_t expected =
        errors[i] == ENOMEM ? SG_ANOMALY_ERR_MEMORY : SG_ANOMALY_ERR_IO;
    sg_test_locale_fail_with_errno(errors[i]);
    sg_anomaly_status_t status = sg_anomaly_write_stream(model, stream);
    ok = status == expected && errno == errors[i] &&
         uselocale((locale_t)0) == numeric && ok;
    rewind(stream);
    sg_test_locale_fail_with_errno(errors[i]);
    status = sg_anomaly_read_stream(model, stream);
    ok = status == expected && errno == errors[i] &&
         uselocale((locale_t)0) == numeric &&
         snapshot_equal(before, snapshot_model(model)) && ok;
    sg_anomaly_model_t *loaded = NULL;
    sg_test_locale_fail_with_errno(errors[i]);
    status = sg_anomaly_model_read_new(stream, &loaded);
    ok = status == expected && errno == errors[i] && loaded == NULL &&
         uselocale((locale_t)0) == numeric && ok;
    sg_anomaly_model_free(loaded);
  }
  sg_test_io_fail_at_with_errno(1, EINVAL);
  sg_anomaly_status_t status = sg_anomaly_write_stream(model, stream);
  ok = status == SG_ANOMALY_ERR_IO && errno == EINVAL &&
       uselocale((locale_t)0) == numeric && ok;
  sg_test_io_reset();
  rewind(stream);
  sg_test_io_fail_at_with_errno(1, EIO);
  status = sg_anomaly_read_stream(model, stream);
  ok = status == SG_ANOMALY_ERR_IO && errno == EIO &&
       uselocale((locale_t)0) == numeric &&
       snapshot_equal(before, snapshot_model(model)) && ok;
  sg_test_io_reset();
  uselocale(previous);
  freelocale(numeric);
  sg_anomaly_model_free(model);
  ASSERT(fclose(stream) == 0);
  ASSERT(ok);
}

/* These owned fixtures fit the supplied buffers; inspect actual physical
 * bytes rather than C strings, since persisted keys may contain NUL. */
static SHELL_NONNULL(1, 2, 4) bool read_saved_bytes(const char *path,
                                                    unsigned char *bytes,
                                                    size_t capacity,
                                                    size_t *length) {
  FILE *stream = fopen(path, "rb");
  if (!stream)
    return false;
  *length = fread(bytes, 1, capacity, stream);
  bool complete = feof(stream) && !ferror(stream);
  int closed = fclose(stream);
  return complete && closed == 0;
}

static SHELL_NONNULL(1, 2) bool saved_bytes_equal(const char *path,
                                                  const unsigned char *bytes,
                                                  size_t length) {
  unsigned char actual[4096];
  size_t actual_length = 0;
  return read_saved_bytes(path, actual, sizeof(actual), &actual_length) &&
         actual_length == length && memcmp(actual, bytes, length) == 0;
}

static SHELL_NONNULL(1) bool saved_fixture_is_clean(const char *path,
                                                    int next_fd) {
  errno = 0;
  bool closed = fcntl(next_fd, F_GETFD) == -1 && errno == EBADF;
  struct stat status;
  return closed && test_atomic_temp_files(path, false) &&
         stat(path, &status) == 0 && (status.st_mode & 0777) == 0640;
}

TEST(path_save_failure_atomicity) {
  char directory[] = "/tmp/shellclave-anomaly-save-XXXXXX";
  ASSERT(mkdtemp(directory) != NULL);
  strcpy(anomaly_save_directory, directory);
  char path[272];
  snprintf(path, sizeof(path), "%s/model", anomaly_save_directory);
  sg_anomaly_model_t *previous = test_model_with_config(0.25, -12.0);
  sg_anomaly_model_t *replacement = test_model_with_config(0.5, -8.0);
  sg_anomaly_model_t *loaded = sg_anomaly_model_new();
  ASSERT(previous && replacement && loaded);
  update_repeated(previous, commands, 5, 1);
  update_repeated(replacement, commands, 5, 3);
  static const char binary[] = "3:a\0b,1:x,";
  ASSERT_EQ_INT(
      sg_anomaly_model_update_netseq(replacement, binary, sizeof(binary) - 1),
      SG_ANOMALY_OK);
  anomaly_snapshot_t old_state = snapshot_model(previous);
  anomaly_snapshot_t new_state = snapshot_model(replacement);
  unsigned char old_bytes[4096], new_bytes[4096];
  size_t old_length = 0, new_length = 0;
  ASSERT_EQ_INT(sg_anomaly_model_save(previous, path), SG_ANOMALY_OK);
  struct stat mode;
  ASSERT(stat(path, &mode) == 0 && (mode.st_mode & 0777) == 0600);
  ASSERT(chmod(path, 0640) == 0);
  ASSERT(read_saved_bytes(path, old_bytes, sizeof(old_bytes), &old_length));
  sg_test_io_reset();
  ASSERT_EQ_INT(sg_anomaly_model_save(replacement, path), SG_ANOMALY_OK);
  size_t operations = sg_test_io_count();
  sg_test_io_reset();
  ASSERT(read_saved_bytes(path, new_bytes, sizeof(new_bytes), &new_length));
  ASSERT(operations > 7 && (old_length != new_length ||
                            memcmp(old_bytes, new_bytes, old_length)));

  bool ok = true;
  static const int errors[] = {EIO, ENOMEM, EINVAL, EPROTO};
  for (size_t e = 0; e < sizeof(errors) / sizeof(errors[0]); e++) {
    for (size_t fail_at = 1; fail_at <= operations; fail_at++) {
      ASSERT_EQ_INT(sg_anomaly_model_save(previous, path), SG_ANOMALY_OK);
      int next_fd = open(path, O_RDONLY);
      ASSERT(next_fd >= 0 && close(next_fd) == 0);
      sg_test_io_fail_at_with_errno(fail_at, errors[e]);
      sg_anomaly_status_t result = sg_anomaly_model_save(replacement, path);
      int error_number = errno;
      sg_test_io_reset();
      /* Only synchronization and close of the retained parent follow rename. */
      bool installed = fail_at > operations - 2;
      sg_anomaly_status_t expected =
          errors[e] == ENOMEM ? SG_ANOMALY_ERR_MEMORY : SG_ANOMALY_ERR_IO;
      bool case_ok = result == expected && error_number == errors[e] &&
                     saved_bytes_equal(path, installed ? new_bytes : old_bytes,
                                       installed ? new_length : old_length) &&
                     saved_fixture_is_clean(path, next_fd) &&
                     sg_anomaly_model_load(loaded, path) == SG_ANOMALY_OK &&
                     snapshot_equal(installed ? new_state : old_state,
                                    snapshot_model(loaded));
      if (!case_ok)
        fprintf(stderr, "save fault %zu/%zu errno %d: status=%d errno=%d\n",
                fail_at, operations, errors[e], result, error_number);
      ok = case_ok && ok;
    }
  }

  for (size_t e = 0; e < 2; e++) {
    ASSERT_EQ_INT(sg_anomaly_model_save(previous, path), SG_ANOMALY_OK);
    int next_fd = open(path, O_RDONLY);
    ASSERT(next_fd >= 0 && close(next_fd) == 0);
    sg_test_locale_fail_with_errno(errors[e]);
    sg_test_io_close_fail_with_errno(EPROTO);
    sg_anomaly_status_t result = sg_anomaly_model_save(replacement, path);
    int error_number = errno;
    sg_test_io_reset();
    ok = result == (errors[e] == ENOMEM ? SG_ANOMALY_ERR_MEMORY
                                        : SG_ANOMALY_ERR_IO) &&
         error_number == errors[e] &&
         saved_bytes_equal(path, old_bytes, old_length) &&
         saved_fixture_is_clean(path, next_fd) &&
         sg_anomaly_model_load(loaded, path) == SG_ANOMALY_OK &&
         snapshot_equal(old_state, snapshot_model(loaded)) && ok;
  }

  /* A later close failure must not replace an earlier flush/sync error. */
  for (size_t fail_at = operations - 6; fail_at <= operations - 4; fail_at++) {
    int next_fd = open(path, O_RDONLY);
    ASSERT(next_fd >= 0 && close(next_fd) == 0);
    sg_test_io_fail_at_with_errno(fail_at, ENOMEM);
    sg_test_io_close_fail_with_errno(EIO);
    sg_anomaly_status_t result = sg_anomaly_model_save(replacement, path);
    int error_number = errno;
    sg_test_io_reset();
    ok = result == SG_ANOMALY_ERR_MEMORY && error_number == ENOMEM &&
         saved_bytes_equal(path, old_bytes, old_length) &&
         saved_fixture_is_clean(path, next_fd) && ok;
  }

  int next_fd = open(path, O_RDONLY);
  ASSERT(next_fd >= 0 && close(next_fd) == 0);
  sg_test_alloc_fail_at(1);
  sg_anomaly_status_t result = sg_anomaly_model_save(replacement, path);
  int error_number = errno;
  sg_test_alloc_reset();
  ok = result == SG_ANOMALY_ERR_MEMORY && error_number == ENOMEM &&
       saved_bytes_equal(path, old_bytes, old_length) &&
       saved_fixture_is_clean(path, next_fd) && ok;
  ok = snapshot_equal(old_state, snapshot_model(previous)) &&
       snapshot_equal(new_state, snapshot_model(replacement)) && ok;

  /* File saves must not replace special files, even with directory write
   * permission. The FIFO remains unopened and cannot block this test. */
  ASSERT(unlink(path) == 0 && mkfifo(path, 0600) == 0);
  result = sg_anomaly_model_save(replacement, path);
  error_number = errno;
  ok = result == SG_ANOMALY_ERR_IO && error_number == EINVAL &&
       lstat(path, &mode) == 0 && S_ISFIFO(mode.st_mode) && ok;
  result = sg_anomaly_model_save(replacement, anomaly_save_directory);
  error_number = errno;
  ok = result == SG_ANOMALY_ERR_IO && error_number == EISDIR &&
       stat(anomaly_save_directory, &mode) == 0 && S_ISDIR(mode.st_mode) && ok;

  /* A symlink names the entry to replace, not the file to modify. */
  ASSERT(unlink(path) == 0);
  char target[280];
  snprintf(target, sizeof(target), "%s.target", path);
  ASSERT_EQ_INT(sg_anomaly_model_save(previous, target), SG_ANOMALY_OK);
  ASSERT(symlink(target, path) == 0);
  result = sg_anomaly_model_save(replacement, path);
  ok = result == SG_ANOMALY_OK && lstat(path, &mode) == 0 &&
       S_ISREG(mode.st_mode) &&
       saved_bytes_equal(path, new_bytes, new_length) &&
       saved_bytes_equal(target, old_bytes, old_length) && ok;
  static const mode_t preserved_modes[] = {0750, 04750, 02750, 01750};
  for (size_t m = 0; m < sizeof(preserved_modes) / sizeof(preserved_modes[0]);
       m++) {
    ok = chmod(path, preserved_modes[m]) == 0 && ok;
    result = sg_anomaly_model_save(replacement, path);
    ok = result == SG_ANOMALY_OK && stat(path, &mode) == 0 &&
         (mode.st_mode & 07777) == preserved_modes[m] &&
         saved_bytes_equal(path, new_bytes, new_length) && ok;
  }

  long name_max = pathconf(anomaly_save_directory, _PC_NAME_MAX);
  size_t prefix = strlen(anomaly_save_directory) + 1;
  char long_path[PATH_MAX];
  if (name_max < 14 || (size_t)name_max + prefix + 2 > sizeof(long_path)) {
    ok = false;
  } else {
    const size_t names[] = {(size_t)name_max - 7, (size_t)name_max - 6,
                            (size_t)name_max, (size_t)name_max + 1};
    for (size_t n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
      memcpy(long_path, anomaly_save_directory, prefix - 1);
      long_path[prefix - 1] = '/';
      memset(long_path + prefix, 'x', names[n]);
      long_path[prefix + names[n]] = '\0';
      if (names[n] > (size_t)name_max) {
        result = sg_anomaly_model_save(replacement, long_path);
        ok = result == SG_ANOMALY_ERR_IO && errno == ENAMETOOLONG &&
             test_atomic_temp_files(long_path, false) && ok;
        continue;
      }
      for (unsigned existing = 0; existing < 2; existing++) {
        result = sg_anomaly_model_save(replacement, long_path);
        bool case_ok =
            result == SG_ANOMALY_OK &&
            saved_bytes_equal(long_path, new_bytes, new_length) &&
            lstat(long_path, &mode) == 0 && S_ISREG(mode.st_mode) &&
            (mode.st_mode & 0777) == (existing ? 0640 : 0600) &&
            sg_anomaly_model_load(loaded, long_path) == SG_ANOMALY_OK &&
            snapshot_equal(new_state, snapshot_model(loaded)) &&
            test_atomic_temp_files(long_path, false);
        if (!case_ok)
          fprintf(stderr, "anomaly save basename %zu existing=%u: status=%d\n",
                  names[n], existing, result);
        ok = case_ok && ok;
        ok = chmod(long_path, 0640) == 0 && ok;
      }
      ok = unlink(long_path) == 0 && ok;
    }
  }
  sg_anomaly_model_free(loaded);
  sg_anomaly_model_free(replacement);
  sg_anomaly_model_free(previous);
  cleanup_anomaly_save_fixture();
  ASSERT(ok);
}

TEST(path_save_near_path_max) {
  test_atomic_long_directory_t directory = {0};
  sg_anomaly_model_t *source = sg_anomaly_model_new();
  sg_anomaly_model_t *loaded = sg_anomaly_model_new();
  static const char binary[] = "3:a\0b,1:x,1:z,";
  bool ok = source && loaded;
  if (ok)
    ok = sg_anomaly_model_update_netseq(source, binary, sizeof(binary) - 1) ==
         SG_ANOMALY_OK;
  static const char *const roots[] = {"/tmp/shellclave-long-anomaly-XXXXXX",
                                      "shellclave-long-anomaly-XXXXXX"};
  const size_t lengths[] = {PATH_MAX - 12, PATH_MAX - 3, PATH_MAX - 2,
                            PATH_MAX - 1};
  for (size_t r = 0; ok && r < sizeof(roots) / sizeof(roots[0]); r++) {
    for (size_t l = 0; ok && l < sizeof(lengths) / sizeof(lengths[0]); l++) {
      ok = test_atomic_long_directory_create(&directory, roots[r], lengths[l]);
      if (!ok)
        break;
      char path[PATH_MAX + 2];
      memcpy(path, directory.path, lengths[l]);
      memcpy(path + lengths[l], "/x", 3);
      if (lengths[l] + 2 >= PATH_MAX) {
        anomaly_snapshot_t before = snapshot_model(loaded);
        for (unsigned existing = 0; ok && existing < 2; existing++) {
          if (existing)
            ok = test_atomic_directory_sentinel(directory.path, true);
          if (ok) {
            errno = 0;
            ok = sg_anomaly_model_save(source, path) == SG_ANOMALY_ERR_IO &&
                 errno == ENAMETOOLONG &&
                 test_atomic_directory_only_entry(directory.path,
                                                  existing ? "x" : NULL);
          }
          if (ok && existing)
            ok = test_atomic_directory_sentinel(directory.path, false);
        }
        if (ok)
          ok = sg_anomaly_model_load(loaded, path) == SG_ANOMALY_ERR_IO &&
               snapshot_equal(before, snapshot_model(loaded));
        ok = test_atomic_long_directory_cleanup(&directory) && ok;
        continue;
      }
      unsigned char expected[4096];
      size_t length = 0;
      for (unsigned existing = 0; ok && existing < 2; existing++) {
        struct stat mode;
        ok = sg_anomaly_model_save(source, path) == SG_ANOMALY_OK &&
             stat(path, &mode) == 0 &&
             (mode.st_mode & 07777) == (existing ? 04750 : 0600) &&
             test_atomic_temp_files(path, false) &&
             sg_anomaly_model_load(loaded, path) == SG_ANOMALY_OK &&
             snapshot_equal(snapshot_model(source), snapshot_model(loaded));
        if (ok && !existing)
          ok = read_saved_bytes(path, expected, sizeof(expected), &length);
        else if (ok)
          ok = saved_bytes_equal(path, expected, length);
        if (ok)
          ok = chmod(path, 04750) == 0;
      }
      ok = test_atomic_long_directory_cleanup(&directory) && ok;
    }
  }
  ok = test_atomic_long_directory_cleanup(&directory) && ok;
  sg_anomaly_model_free(loaded);
  sg_anomaly_model_free(source);
  ASSERT(ok);
}

TEST(persisted_counter_accumulation_is_exact) {
  /* Signed-key overflow below SIZE_MAX requires a 64-bit size_t. The generic
   * aggregate-total overflow fixture is exercised separately above. */
  if (SIZE_MAX <= INT64_MAX)
    return;
  sg_anomaly_model_t *target = sg_anomaly_model_new();
  ASSERT(target != NULL);
  update_repeated(target, commands, 5, 2);
  anomaly_snapshot_t before = snapshot_model(target);
  for (uint8_t order = 1; order <= 4; order++) {
    for (unsigned context = 0; context < (order == 1 ? 1u : 2u); context++) {
      FILE *stream = tmpfile();
      ASSERT(stream != NULL);
      size_t total = (size_t)INT64_MAX + 1u;
      ASSERT(
          fprintf(stream,
                  "# anomaly-model-v7\n# 0.1 -10 0.5 %zu %zu %zu %zu %zu 0\n",
                  order == 1 ? total : 0, order == 2 ? total : 0,
                  order == 3 ? total : 0, order == 4 ? total : 0,
                  (size_t)(order == 1 ? 1u : 0u)) > 0);
      static const char *keys[] = {"1:a,", "1:a,1:b,", "1:a,1:b,1:c,",
                                   "1:a,1:b,1:c,1:d,"};
      static const char *siblings[] = {"1:a,", "1:a,1:x,", "1:a,1:b,1:x,",
                                       "1:a,1:b,1:c,1:x,"};
      ASSERT(write_count_record(stream, order, keys[order - 1], INT64_MAX));
      ASSERT(write_count_record(
          stream, order, context ? siblings[order - 1] : keys[order - 1], 1));
      ASSERT(fflush(stream) == 0 && fseek(stream, 0, SEEK_SET) == 0);
      ASSERT_EQ_INT(sg_anomaly_read_stream(target, stream),
                    SG_ANOMALY_ERR_LIMIT);
      ASSERT_EQ_INT(errno, EOVERFLOW);
      ASSERT(snapshot_equal(before, snapshot_model(target)));
      ASSERT(fclose(stream) == 0);
    }
  }
  /* Representable duplicate records remain additive and become one exact
   * record when reserialized, rather than being silently saturated. */
  FILE *stream = tmpfile();
  ASSERT(stream != NULL);
  ASSERT(fprintf(stream, "# anomaly-model-v7\n# 0.1 -10 0.5 %zu 0 0 0 1 0\n",
                 (size_t)INT64_MAX) > 0);
  ASSERT(write_count_record(stream, 1, "1:a,", INT64_MAX - 1));
  ASSERT(write_count_record(stream, 1, "1:a,", 1));
  ASSERT(fflush(stream) == 0 && fseek(stream, 0, SEEK_SET) == 0);
  ASSERT_EQ_INT(sg_anomaly_read_stream(target, stream), SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(
                    target, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)}),
                (size_t)INT64_MAX);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(target), (size_t)INT64_MAX);
  ASSERT(fclose(stream) == 0);
  stream = tmpfile();
  ASSERT(stream != NULL);
  ASSERT_EQ_INT(sg_anomaly_write_stream(target, stream), SG_ANOMALY_OK);
  ASSERT(fseek(stream, 0, SEEK_SET) == 0);
  sg_anomaly_model_t *roundtrip = NULL;
  ASSERT_EQ_INT(sg_anomaly_model_read_new(stream, &roundtrip), SG_ANOMALY_OK);
  ASSERT_EQ_INT(
      sg_anomaly_model_unigram_count_view(
          roundtrip, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)}),
      (size_t)INT64_MAX);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(roundtrip), (size_t)INT64_MAX);
  ASSERT(fclose(stream) == 0);
  sg_anomaly_model_free(roundtrip);
  sg_anomaly_model_free(target);
}

static sg_anomaly_model_t *model_with_large_counts(uint64_t count,
                                                   size_t unknown) {
  static const char *keys[] = {"1:a,", "1:a,1:a,", "1:a,1:a,1:a,",
                               "1:a,1:a,1:a,1:a,"};
  FILE *stream = tmpfile();
  if (!stream)
    return NULL;
  sg_anomaly_model_t *model = NULL;
  bool ok = fprintf(stream,
                    "# anomaly-model-v7\n# 0.1 -10 0.5 %zu %zu %zu %zu 1 %zu\n",
                    (size_t)count, (size_t)count, (size_t)count, (size_t)count,
                    unknown) > 0;
  for (uint8_t order = 1; order <= 4 && ok; order++)
    ok = write_count_record(stream, order, keys[order - 1], count);
  if (ok && fseek(stream, 0, SEEK_SET) == 0)
    ok = sg_anomaly_model_read_new(stream, &model) == SG_ANOMALY_OK;
  else
    ok = false;
  if (fclose(stream) != 0)
    ok = false;
  if (!ok) {
    sg_anomaly_model_free(model);
    return NULL;
  }
  return model;
}

/* Independent integer quotient/remainder expectations for dyadic scales,
 * rather than duplicating the production wide-multiplication implementation. */
static uint64_t expected_dyadic_decay(uint64_t count, unsigned numerator,
                                      unsigned bits) {
  if (bits >= 64)
    return 0;
  uint64_t divisor = UINT64_C(1) << bits;
  return (count / divisor) * numerator +
         ((count % divisor) * numerator) / divisor;
}

static uint64_t expected_near_one_decay(uint64_t count) {
  if (DBL_MANT_DIG >= 64)
    return count ? count - 1 : 0;
  uint64_t divisor = UINT64_C(1) << DBL_MANT_DIG;
  return count - count / divisor - (count % divisor != 0);
}

TEST(decay_preserves_integer_precision) {
  const uint64_t counts[] = {1,
                             2,
                             3,
                             (UINT64_C(1) << 32) - 1,
                             (UINT64_C(1) << 32) + 1,
                             (UINT64_C(1) << 53) - 1,
                             UINT64_C(1) << 53,
                             (UINT64_C(1) << 53) + 1,
                             INT64_MAX};
  const struct {
    double scale;
    unsigned numerator;
    unsigned bits;
  } scales[] = {{0.5, 1, 1},
                {0.75, 3, 2},
                {0.125, 1, 3},
                {0x1p-32, 1, 32},
                {0x1p-64, 1, 64},
                {DBL_TRUE_MIN, 1, 1074},
                {nextafter(1.0, 0.0), 0, 0}};
  static const char sequence[] = "1:a,1:a,1:a,1:a,";
  for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
    if (counts[i] > SIZE_MAX)
      continue;
    for (size_t j = 0; j < sizeof(scales) / sizeof(scales[0]); j++) {
      sg_anomaly_model_t *model = model_with_large_counts(counts[i], SIZE_MAX);
      ASSERT(model != NULL);
      ASSERT_EQ_INT(sg_anomaly_model_decay(model, scales[j].scale),
                    SG_ANOMALY_OK);
      size_t expected =
          (size_t)(scales[j].numerator
                       ? expected_dyadic_decay(counts[i], scales[j].numerator,
                                               scales[j].bits)
                       : expected_near_one_decay(counts[i]));
      size_t expected_unknown =
          (size_t)(scales[j].numerator
                       ? expected_dyadic_decay(SIZE_MAX, scales[j].numerator,
                                               scales[j].bits)
                       : expected_near_one_decay(SIZE_MAX));
      ASSERT_EQ_INT(
          sg_anomaly_model_unigram_count_view(
              model, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)}),
          expected);
      ASSERT_EQ_INT(sg_anomaly_model_bigram_count_view(
                        model, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)},
                        (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)}),
                    expected);
      ASSERT_EQ_INT(sg_anomaly_model_trigram_count_view(
                        model, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)},
                        (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)},
                        (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)}),
                    expected);
      ASSERT_EQ_INT(sg_anomaly_model_fourgram_count_view(
                        model, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)},
                        (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)},
                        (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)},
                        (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)}),
                    expected);
      ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(model), expected);
      ASSERT_EQ_INT(sg_anomaly_model_total_bigrams(model), expected);
      ASSERT_EQ_INT(sg_anomaly_model_total_trigrams(model), expected);
      ASSERT_EQ_INT(sg_anomaly_model_total_fourgrams(model), expected);
      ASSERT_EQ_INT(sg_anomaly_model_unknown_count(model), expected_unknown);
      ASSERT_EQ_INT(sg_anomaly_model_total_contexts(model), expected ? 3 : 0);
      sg_anomaly_model_t *loaded = roundtrip_model(model);
      ASSERT(loaded != NULL);
      ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(loaded), expected);
      ASSERT_EQ_INT(sg_anomaly_model_unknown_count(loaded), expected_unknown);
      double before, after;
      ASSERT_EQ_INT(sg_anomaly_model_score_netseq(
                        model, sequence, sizeof(sequence) - 1, &before),
                    SG_ANOMALY_OK);
      ASSERT_EQ_INT(sg_anomaly_model_score_netseq(loaded, sequence,
                                                  sizeof(sequence) - 1, &after),
                    SG_ANOMALY_OK);
      ASSERT(before == after);
      sg_anomaly_model_free(loaded);
      sg_anomaly_model_free(model);
    }
  }
  if (SIZE_MAX < INT64_MAX)
    return;
  sg_anomaly_model_t *model = model_with_large_counts(INT64_MAX, SIZE_MAX);
  ASSERT(model != NULL);
  sg_test_alloc_fail_at(1);
  ASSERT_EQ_INT(sg_anomaly_model_decay(model, 0.5), SG_ANOMALY_ERR_MEMORY);
  sg_test_alloc_reset();
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(
                    model, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)}),
                (size_t)INT64_MAX);
  ASSERT_EQ_INT(sg_anomaly_model_unknown_count(model), SIZE_MAX);
  sg_test_anomaly_op_fail_at(1);
  ASSERT_EQ_INT(sg_anomaly_model_decay(model, 0.5), SG_ANOMALY_ERR_MEMORY);
  sg_test_anomaly_op_reset();
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(
                    model, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)}),
                (size_t)INT64_MAX);
  ASSERT_EQ_INT(sg_anomaly_model_unknown_count(model), SIZE_MAX);
  /* 0.1 is not exactly 1/10 in binary; these constants are the exact floor
   * of the product with its represented value, not decimal approximations. */
  ASSERT_EQ_INT(sg_anomaly_model_decay(model, 0.1), SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(
                    model, (sg_anomaly_item_view_t){"a", (sizeof("a") - 1)}),
                UINT64_C(922337203685477631));
  ASSERT_EQ_INT(sg_anomaly_model_unknown_count(model),
                UINT64_C(1844674407370955263));
  sg_anomaly_model_free(model);
}

TEST(canonical_netseq_allocation_failures) {
  static const char sequence[] = "1:a,1:b,1:c,1:d,1:e,1:f,1:g,1:h,1:i,";
  sg_anomaly_model_t *probe = sg_anomaly_model_new();
  ASSERT(probe != NULL);
  sg_test_anomaly_op_reset();
  ASSERT_EQ_INT(
      sg_anomaly_model_update_netseq(probe, sequence, sizeof(sequence) - 1),
      SG_ANOMALY_OK);
  size_t update_allocations = sg_test_anomaly_op_count();
  sg_test_anomaly_op_reset();
  ASSERT(update_allocations > 0);
  sg_anomaly_model_free(probe);

  for (size_t fail_at = 1; fail_at <= update_allocations; fail_at++) {
    sg_anomaly_model_t *model = sg_anomaly_model_new();
    ASSERT(model != NULL);
    sg_test_anomaly_op_fail_at(fail_at);
    sg_anomaly_status_t status =
        sg_anomaly_model_update_netseq(model, sequence, sizeof(sequence) - 1);
    sg_test_anomaly_op_reset();
    ASSERT_EQ_INT(status, SG_ANOMALY_ERR_MEMORY);
    sg_anomaly_model_free(model);
  }

  probe = sg_anomaly_model_new();
  ASSERT(probe != NULL);
  ASSERT_EQ_INT(
      sg_anomaly_model_update_netseq(probe, sequence, sizeof(sequence) - 1),
      SG_ANOMALY_OK);
  double score = 0.0;
  sg_test_anomaly_op_reset();
  ASSERT_EQ_INT(sg_anomaly_model_score_netseq(probe, sequence,
                                              sizeof(sequence) - 1, &score),
                SG_ANOMALY_OK);
  size_t score_allocations = sg_test_anomaly_op_count();
  sg_test_anomaly_op_reset();
  ASSERT_EQ_INT(score_allocations, 0);
  ASSERT(isfinite(score));
  sg_anomaly_model_free(probe);
}

TEST(paired_netseq_updates_are_failure_atomic) {
  static const char raw_baseline[] = "4:base,";
  static const char type_baseline[] = "4:WORD,";
  static const char raw_update[] = "5:alpha,4:beta,5:gamma,";
  static const char type_update[] = "3:CMD,3:CMD,3:CMD,";

  sg_anomaly_model_t *raw_probe = sg_anomaly_model_new();
  sg_anomaly_model_t *type_probe = sg_anomaly_model_new();
  ASSERT(raw_probe != NULL && type_probe != NULL);
  sg_test_anomaly_op_reset();
  ASSERT_EQ_INT(sg_anomaly_models_update_netseq_pair(
                    raw_probe, raw_update, sizeof(raw_update) - 1, type_probe,
                    type_update, sizeof(type_update) - 1),
                SG_ANOMALY_OK);
  size_t operation_count = sg_test_anomaly_op_count();
  sg_test_anomaly_op_reset();
  ASSERT(operation_count > 1);
  sg_anomaly_model_free(type_probe);
  sg_anomaly_model_free(raw_probe);

  /* An operation may fail in either half of the paired transaction. Each
   * iteration starts with retained learning, then verifies that every count
   * and the scoring result survive rollback unchanged. */
  for (size_t fail_at = 1; fail_at <= operation_count; fail_at++) {
    sg_anomaly_model_t *raw = sg_anomaly_model_new();
    sg_anomaly_model_t *type = sg_anomaly_model_new();
    ASSERT(raw != NULL && type != NULL);
    ASSERT_EQ_INT(sg_anomaly_models_update_netseq_pair(
                      raw, raw_baseline, sizeof(raw_baseline) - 1, type,
                      type_baseline, sizeof(type_baseline) - 1),
                  SG_ANOMALY_OK);
    anomaly_snapshot_t raw_before = snapshot_model(raw);
    anomaly_snapshot_t type_before = snapshot_model(type);

    sg_test_anomaly_op_fail_at(fail_at);
    ASSERT_EQ_INT(sg_anomaly_models_update_netseq_pair(
                      raw, raw_update, sizeof(raw_update) - 1, type,
                      type_update, sizeof(type_update) - 1),
                  SG_ANOMALY_ERR_MEMORY);
    sg_test_anomaly_op_reset();
    ASSERT(snapshot_equal(raw_before, snapshot_model(raw)));
    ASSERT(snapshot_equal(type_before, snapshot_model(type)));
    /* The error diagnostic remains sticky, but a rolled-back model is not
     * poisoned: the next paired update succeeds without clearing it. */
    ASSERT(sg_anomaly_model_had_error(raw) || sg_anomaly_model_had_error(type));
    ASSERT_EQ_INT(sg_anomaly_models_update_netseq_pair(
                      raw, raw_update, sizeof(raw_update) - 1, type,
                      type_update, sizeof(type_update) - 1),
                  SG_ANOMALY_OK);
    ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(raw), 4);
    ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(type), 4);
    sg_anomaly_model_clear_error(raw);
    sg_anomaly_model_clear_error(type);
    ASSERT(!sg_anomaly_model_had_error(raw) &&
           !sg_anomaly_model_had_error(type));
    sg_anomaly_model_free(type);
    sg_anomaly_model_free(raw);
  }

  /* Validation is completed for both sequences before either table changes. */
  sg_anomaly_model_t *raw = sg_anomaly_model_new();
  sg_anomaly_model_t *type = sg_anomaly_model_new();
  ASSERT(raw != NULL && type != NULL);
  ASSERT_EQ_INT(sg_anomaly_models_update_netseq_pair(
                    raw, raw_baseline, sizeof(raw_baseline) - 1, type,
                    type_baseline, sizeof(type_baseline) - 1),
                SG_ANOMALY_OK);
  anomaly_snapshot_t raw_before = snapshot_model(raw);
  anomaly_snapshot_t type_before = snapshot_model(type);
  ASSERT_EQ_INT(sg_anomaly_models_update_netseq_pair(
                    raw, raw_update, sizeof(raw_update) - 1, type, "01:x,",
                    sizeof("01:x,") - 1),
                SG_ANOMALY_ERR_FORMAT);
  ASSERT(snapshot_equal(raw_before, snapshot_model(raw)));
  ASSERT(snapshot_equal(type_before, snapshot_model(type)));
  ASSERT_EQ_INT(sg_anomaly_models_update_netseq_pair(
                    raw, raw_update, sizeof(raw_update) - 1, type,
                    type_baseline, sizeof(type_baseline) - 1),
                SG_ANOMALY_ERR_FORMAT);
  ASSERT(snapshot_equal(raw_before, snapshot_model(raw)));
  ASSERT(snapshot_equal(type_before, snapshot_model(type)));
  ASSERT_EQ_INT(sg_anomaly_models_update_netseq_pair(
                    raw, raw_baseline, sizeof(raw_baseline) - 1, type,
                    type_update, sizeof(type_update) - 1),
                SG_ANOMALY_ERR_FORMAT);
  ASSERT(snapshot_equal(raw_before, snapshot_model(raw)));
  ASSERT(snapshot_equal(type_before, snapshot_model(type)));
  sg_anomaly_model_free(type);
  sg_anomaly_model_free(raw);
}

TEST(count_views_preserve_exact_binary_spans) {
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  ASSERT(model != NULL);
  sg_anomaly_item_view_t items[4];
  char encoded[24];
  size_t used = 0;
  for (size_t i = 0; i < 4; i++) {
    char *bytes = malloc(3);
    ASSERT(bytes != NULL);
    bytes[0] = (char)('a' + i);
    bytes[1] = '\0';
    bytes[2] = 'x';
    items[i] = (sg_anomaly_item_view_t){bytes, 3};
    size_t written = 0;
    ASSERT_EQ_INT(shell_netstring_write(encoded + used, sizeof(encoded) - used,
                                        bytes, 3, &written),
                  SHELL_NETSTRING_OK);
    used += written;
  }
  ASSERT_EQ_INT(sg_anomaly_model_update_netseq(model, encoded, used),
                SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(model, items[0]), 1);
  ASSERT_EQ_INT(sg_anomaly_model_bigram_count_view(model, items[0], items[1]),
                1);
  ASSERT_EQ_INT(
      sg_anomaly_model_trigram_count_view(model, items[0], items[1], items[2]),
      1);
  ASSERT_EQ_INT(sg_anomaly_model_fourgram_count_view(model, items[0], items[1],
                                                     items[2], items[3]),
                1);
  for (size_t i = 0; i < 4; i++) {
    char *bytes = (char *)items[i].data;
    bytes[2] = 'y';
    ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(model, items[i]), 0);
    if (i < 2)
      ASSERT_EQ_INT(
          sg_anomaly_model_bigram_count_view(model, items[0], items[1]), 0);
    if (i < 3)
      ASSERT_EQ_INT(sg_anomaly_model_trigram_count_view(model, items[0],
                                                        items[1], items[2]),
                    0);
    ASSERT_EQ_INT(sg_anomaly_model_fourgram_count_view(
                      model, items[0], items[1], items[2], items[3]),
                  0);
    bytes[2] = 'x';
  }
  /* Empty stages represent argv-less commands, not absent keys. */
  ASSERT_EQ_INT(sg_anomaly_model_update_netseq(model, "0:,0:,0:,0:,", 12),
                SG_ANOMALY_OK);
  sg_anomaly_item_view_t empty = {encoded, 0};
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(model, empty), 4);
  ASSERT_EQ_INT(sg_anomaly_model_bigram_count_view(model, empty, empty), 3);
  ASSERT_EQ_INT(sg_anomaly_model_trigram_count_view(model, empty, empty, empty),
                2);
  ASSERT_EQ_INT(
      sg_anomaly_model_fourgram_count_view(model, empty, empty, empty, empty),
      1);
  char overlong[SG_ANOMALY_MAX_STAGE_LENGTH + 1];
  memset(overlong, 'x', sizeof(overlong));
  const sg_anomaly_item_view_t invalid[] = {
      {NULL, 0},
      {NULL, 1},
      {overlong, sizeof(overlong)},
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    ASSERT_EQ_INT(sg_anomaly_model_unigram_count_view(model, invalid[i]), 0);
    for (size_t position = 0; position < 4; position++) {
      sg_anomaly_item_view_t query[] = {items[0], items[1], items[2], items[3]};
      query[position] = invalid[i];
      if (position < 2)
        ASSERT_EQ_INT(
            sg_anomaly_model_bigram_count_view(model, query[0], query[1]), 0);
      if (position < 3)
        ASSERT_EQ_INT(sg_anomaly_model_trigram_count_view(model, query[0],
                                                          query[1], query[2]),
                      0);
      ASSERT_EQ_INT(sg_anomaly_model_fourgram_count_view(
                        model, query[0], query[1], query[2], query[3]),
                    0);
    }
  }
  for (size_t i = 0; i < 4; i++)
    free((void *)items[i].data);
  sg_anomaly_model_free(model);
}

int main(void) {
  atexit(cleanup_anomaly_temp_file);
  atexit(cleanup_anomaly_save_fixture);
  printf("sg_anomaly unit tests\n");
  RUN(lifecycle_and_null_safety);
  RUN(config_contract);
  RUN(extreme_alpha_scores_are_finite);
  RUN(update_count_matrix);
  RUN(count_views_preserve_exact_binary_spans);
  RUN(score_discrimination_matrix);
  RUN(backoff_levels_are_usable);
  RUN(model_owns_string_copies);
  RUN(save_load_roundtrip);
  RUN(reset_and_error_state);
  RUN(maintenance_failures_are_atomic);
  RUN(decay_matrix);
  RUN(decay_removes_large_rare_model);
  RUN(prune_and_compact_preserve_common_behavior);
  RUN(maintenance_rebuilds_derived_contexts);
  RUN(context_statistics_match_probability_reference);
  RUN(compaction_failures_preserve_counts_and_sticky_error);
  RUN(context_statistics_rollback_is_atomic);
  RUN(scoring_work_is_linear);
  RUN(one_pass_score_and_count);
  RUN(canonical_netseq_contract);
  RUN(binary_netseq_persistence);
  RUN(empty_stage_persistence_and_legacy_loading);
  RUN(typed_stream_io_failure_atomicity);
  RUN(owned_file_close_and_error_precedence);
  RUN(persisted_header_validation);
  RUN(persisted_header_framing);
  RUN(persistence_is_locale_independent);
  RUN(persistence_locale_failures_are_atomic);
  RUN(path_save_failure_atomicity);
  RUN(path_save_near_path_max);
  RUN(persisted_counter_accumulation_is_exact);
  RUN(decay_preserves_integer_precision);
  RUN(canonical_netseq_allocation_failures);
  RUN(paired_netseq_updates_are_failure_atomic);
  printf("\n%d passed, %d failed\n", pass_count, fail_count);
  return fail_count > 0 ? 1 : 0;
}
