/* Unit tests for the standalone anomaly model. */

#define _POSIX_C_SOURCE 200809L
#include "../src/sg_anomaly_internal.h"
#include "sg_anomaly.h"
#include "shell_netstring.h"
#include "test_sg_failures.h"
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static sg_anomaly_model_t *test_model_with_config(double alpha,
                                                  double unknown_log_prior) {
  sg_anomaly_config_t config = {
      .alpha = alpha,
      .unknown_log_prior = unknown_log_prior,
  };
  return sg_anomaly_model_new_with_config(&config);
}

static char *test_encode_netseq(const char **sequence, size_t count) {
  if (!sequence && count)
    return NULL;
  size_t total = 0;
  for (size_t i = 0; i < count; i++) {
    if (!sequence[i])
      return NULL;
    size_t length = strlen(sequence[i]);
    size_t record_length = 0;
    if (shell_netstring_encoded_length(length, &record_length) !=
            SHELL_NETSTRING_OK ||
        total > SIZE_MAX - record_length)
      return NULL;
    total += record_length;
  }
  if (total == SIZE_MAX)
    return NULL;
  char *encoded = malloc(total + 1);
  if (!encoded)
    return NULL;
  size_t used = 0;
  for (size_t i = 0; i < count; i++) {
    size_t length = strlen(sequence[i]);
    size_t written = 0;
    if (shell_netstring_write(encoded + used, total - used, sequence[i], length,
                              &written) != SHELL_NETSTRING_OK) {
      free(encoded);
      return NULL;
    }
    used += written;
  }
  encoded[used] = '\0';
  return encoded;
}

static bool test_has_observed(const sg_anomaly_model_t *model,
                              const char **sequence, size_t count) {
  char *encoded = test_encode_netseq(sequence, count);
  bool observed = false;
  if (!encoded ||
      sg_anomaly_model_has_observed_netseq(model, encoded, strlen(encoded),
                                           &observed) != SG_ANOMALY_OK)
    observed = false;
  free(encoded);
  return observed;
}

static double test_anomaly_score_array(const sg_anomaly_model_t *model,
                                       const char **sequence, size_t count) {
  char *encoded = test_encode_netseq(sequence, count);
  double score = INFINITY;
  if (encoded) {
    (void)sg_anomaly_model_score_netseq(model, encoded, strlen(encoded),
                                        &score);
    free(encoded);
  } else {
    (void)sg_anomaly_model_score_netseq(model, NULL, 0, &score);
  }
  return score;
}

static void test_anomaly_update_array(sg_anomaly_model_t *model,
                                      const char **sequence, size_t count) {
  char *encoded = test_encode_netseq(sequence, count);
  if (encoded) {
    (void)sg_anomaly_model_update_netseq(model, encoded, strlen(encoded));
    free(encoded);
  } else {
    (void)sg_anomaly_model_update_netseq(model, NULL, 0);
  }
}

#define sg_anomaly_score test_anomaly_score_array
#define sg_anomaly_update test_anomaly_update_array

static int pass_count;
static int fail_count;
static char anomaly_temp_path[256];

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
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_EQ_INT(actual, expected)                                        \
  do {                                                                         \
    if ((actual) != (expected)) {                                              \
      printf("    FAIL: %s != %s (%ld != %ld) at %s:%d\n", #actual, #expected, \
             (long)(actual), (long)(expected), __FILE__, __LINE__);            \
      fail_count++;                                                            \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_EQ_DBL(actual, expected, epsilon)                               \
  do {                                                                         \
    if (fabs((actual) - (expected)) > (epsilon)) {                             \
      printf("    FAIL: %s != %s (%.9f != %.9f) at %s:%d\n", #actual,          \
             #expected, (double)(actual), (double)(expected), __FILE__,        \
             __LINE__);                                                        \
      fail_count++;                                                            \
      return;                                                                  \
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
  ASSERT_EQ_INT(sg_anomaly_model_reset(NULL), SG_ANOMALY_ERR_INVALID);

  const char *invalid_sequences[][3] = {
      {"a", NULL, "c"},
      {"a", "", "c"},
  };
  sg_anomaly_update(model, commands, 5);
  for (size_t i = 0;
       i < sizeof(invalid_sequences) / sizeof(invalid_sequences[0]); i++) {
    ASSERT(isinf(sg_anomaly_score(model, invalid_sequences[i], 3)));
    ASSERT(!test_has_observed(model, invalid_sequences[i], 3));
    sg_anomaly_update(model, invalid_sequences[i], 3);
    ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(model), 5);
  }
  sg_anomaly_update(NULL, commands, 5);
  ASSERT_EQ_INT(sg_anomaly_model_decay(NULL, 0.5), SG_ANOMALY_ERR_INVALID);
  sg_anomaly_model_clear_error(NULL);
  sg_anomaly_model_free(NULL);
  ASSERT(isinf(sg_anomaly_score(NULL, commands, 5)));
  ASSERT(isinf(sg_anomaly_score(model, NULL, 5)));
  ASSERT_EQ_INT(sg_anomaly_model_vocab_size(NULL), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(NULL), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_bigrams(NULL), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_trigrams(NULL), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_fourgrams(NULL), 0);
  ASSERT_EQ_INT(sg_anomaly_model_total_contexts(NULL), 0);
  ASSERT_EQ_INT(sg_anomaly_model_unknown_count(NULL), 0);
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count(NULL, "a"), 0);
  ASSERT_EQ_INT(sg_anomaly_model_bigram_count(NULL, "a", "b"), 0);
  ASSERT_EQ_INT(sg_anomaly_model_trigram_count(NULL, "a", "b", "c"), 0);
  ASSERT_EQ_INT(sg_anomaly_model_fourgram_count(NULL, "a", "b", "c", "d"), 0);
  char oversized[8192];
  memset(oversized, 'x', sizeof(oversized) - 1);
  oversized[sizeof(oversized) - 1] = '\0';
  ASSERT_EQ_INT(sg_anomaly_model_bigram_count(model, "", "b"), 0);
  ASSERT_EQ_INT(sg_anomaly_model_bigram_count(model, oversized, "b"), 0);
  ASSERT_EQ_INT(sg_anomaly_model_trigram_count(model, "", "b", "c"), 0);
  ASSERT_EQ_INT(sg_anomaly_model_trigram_count(model, oversized, "b", "c"), 0);
  ASSERT_EQ_INT(sg_anomaly_model_fourgram_count(model, "", "b", "c", "d"), 0);
  ASSERT_EQ_INT(
      sg_anomaly_model_fourgram_count(model, oversized, "b", "c", "d"), 0);
  const char *oversized_sequence[] = {oversized, "b", "c", "d"};
  ASSERT(isfinite(sg_anomaly_score(model, oversized_sequence, 4)));
  const char *oversized_middle[] = {"a", oversized, "c", "d"};
  const char *oversized_late[] = {"a", "b", oversized, "d"};
  const char *oversized_last[] = {"a", "b", "c", oversized};
  ASSERT(isfinite(sg_anomaly_score(model, oversized_middle, 4)));
  ASSERT(isfinite(sg_anomaly_score(model, oversized_late, 4)));
  ASSERT(isfinite(sg_anomaly_score(model, oversized_last, 4)));
  ASSERT_EQ_DBL(sg_anomaly_model_kneser_ney_discount(NULL), 0.0, 0.0);
  bool observed = true;
  ASSERT_EQ_INT(sg_anomaly_model_has_observed_netseq(NULL, "", 0, &observed),
                SG_ANOMALY_ERR_INVALID);
  ASSERT(!observed);
  ASSERT_EQ_INT(sg_anomaly_model_has_observed_netseq(model, NULL, 0, &observed),
                SG_ANOMALY_ERR_INVALID);
  FILE *stream = tmpfile();
  ASSERT(stream != NULL);
  ASSERT_EQ_INT(sg_anomaly_write_stream(NULL, stream), -1);
  ASSERT_EQ_INT(sg_anomaly_write_stream(model, NULL), -1);
  ASSERT_EQ_INT(sg_anomaly_read_stream(NULL, stream), -1);
  ASSERT_EQ_INT(sg_anomaly_read_stream(model, NULL), -1);
  rewind(stream);
  ASSERT_EQ_INT(sg_anomaly_read_stream(model, stream), -1);
  int close_result = fclose(stream);
  ASSERT_EQ_INT(close_result, 0);
  FILE *read_only = fopen("/dev/null", "rb");
  ASSERT(read_only != NULL);
  ASSERT_EQ_INT(sg_anomaly_write_stream(model, read_only), -1);
  close_result = fclose(read_only);
  ASSERT_EQ_INT(close_result, 0);
  size_t removed = 0;
  ASSERT_EQ_INT(sg_anomaly_model_prune(NULL, 2, &removed),
                SG_ANOMALY_ERR_INVALID);
  ASSERT_EQ_INT(sg_anomaly_model_compact(NULL), SG_ANOMALY_ERR_INVALID);
  ASSERT_EQ_INT(sg_anomaly_model_save(NULL, "/tmp/unused"),
                SG_ANOMALY_ERR_INVALID);
  ASSERT_EQ_INT(errno, EINVAL);
  ASSERT_EQ_INT(sg_anomaly_model_load(NULL, "/tmp/unused"),
                SG_ANOMALY_ERR_INVALID);
  ASSERT_EQ_INT(errno, EINVAL);
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
  sg_anomaly_config_default(NULL);
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

TEST(update_count_matrix) {
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
    ASSERT_EQ_INT(sg_anomaly_model_unigram_count(model, "a"), 3);
    ASSERT_EQ_INT(sg_anomaly_model_unigram_count(model, "missing"), 0);
    ASSERT_EQ_INT(sg_anomaly_model_bigram_count(model, "a", "b"),
                  length > 1 ? 3 : 0);
    ASSERT_EQ_INT(sg_anomaly_model_trigram_count(model, "a", "b", "c"),
                  length > 2 ? 3 : 0);
    ASSERT_EQ_INT(sg_anomaly_model_fourgram_count(model, "a", "b", "c", "d"),
                  length > 3 ? 3 : 0);
    ASSERT((length < 3) == isinf(sg_anomaly_score(model, commands, length)));
    ASSERT(test_has_observed(model, commands, length));
    const char *unseen[] = {"missing"};
    ASSERT(!test_has_observed(model, unseen, 1));
    sg_anomaly_model_free(model);
  }

  char storage[4][SG_ANOMALY_MAX_COMMAND_LENGTH + 1];
  const char *boundary[4];
  for (size_t i = 0; i < 4; i++) {
    memset(storage[i], 'a', SG_ANOMALY_MAX_COMMAND_LENGTH);
    storage[i][SG_ANOMALY_MAX_COMMAND_LENGTH - 1] = (char)('a' + i);
    storage[i][SG_ANOMALY_MAX_COMMAND_LENGTH] = '\0';
    boundary[i] = storage[i];
  }
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  ASSERT(model != NULL);
  sg_anomaly_update(model, boundary, 4);
  ASSERT_EQ_INT(sg_anomaly_model_total_unigrams(model), 4);
  ASSERT_EQ_INT(sg_anomaly_model_total_bigrams(model), 3);
  ASSERT_EQ_INT(sg_anomaly_model_total_trigrams(model), 2);
  ASSERT_EQ_INT(sg_anomaly_model_total_fourgrams(model), 1);
  ASSERT_EQ_INT(sg_anomaly_model_fourgram_count(model, boundary[0], boundary[1],
                                                boundary[2], boundary[3]),
                1);
  ASSERT(isfinite(sg_anomaly_score(model, boundary, 4)));

  char too_long[SG_ANOMALY_MAX_COMMAND_LENGTH + 2];
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
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count(model, too_long), 0);
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
    ASSERT_EQ_INT(sg_anomaly_model_unigram_count(model, probe[i]), 1);
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
    ASSERT_EQ_INT(sg_anomaly_model_unigram_count(model, commands[i]), 2);
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
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count(model, "gcc"), 0);
  ASSERT_EQ_INT(
      sg_anomaly_model_fourgram_count(model, "gcc", "make", "test", "install"),
      0);
  ASSERT_EQ_INT(sg_anomaly_model_prune(model, 0, &removed), SG_ANOMALY_OK);
  ASSERT_EQ_INT(removed, 0);
  double score = sg_anomaly_score(model, common, 4);
  ASSERT_EQ_INT(sg_anomaly_model_compact(model), SG_ANOMALY_OK);
  ASSERT_EQ_DBL(sg_anomaly_score(model, common, 4), score, 0.000001);
  sg_anomaly_model_free(model);
}

TEST(canonical_netseq_contract) {
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  ASSERT(model != NULL);
  static const char valid[] = "9:two words,1::,1:,,";
  size_t count = SIZE_MAX;
  ASSERT_EQ_INT(
      sg_anomaly_netseq_count(valid, sizeof(valid) - 1, false, &count),
      SG_ANOMALY_OK);
  ASSERT_EQ_INT(count, 3);
  ASSERT_EQ_INT(sg_anomaly_netseq_count(valid, sizeof(valid) - 1, false, NULL),
                SG_ANOMALY_ERR_INVALID);
  ASSERT_EQ_INT(sg_anomaly_netseq_count(NULL, 0, false, &count),
                SG_ANOMALY_ERR_INVALID);
  ASSERT_EQ_INT(sg_anomaly_netseq_count("", 0, false, &count), SG_ANOMALY_OK);
  ASSERT_EQ_INT(count, 0);
  ASSERT_EQ_INT(sg_anomaly_netseq_count("01:x,", 5, false, &count),
                SG_ANOMALY_ERR_FORMAT);
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
  double score = 0.0;
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

  static const char *invalid[] = {"01:x,", "1:x", "2:x,", "0:,",
                                  "x",     "1x,", "1:x;", "1:,"};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    score = 0.0;
    ASSERT_EQ_INT(sg_anomaly_model_score_netseq(model, invalid[i],
                                                strlen(invalid[i]), &score),
                  SG_ANOMALY_ERR_FORMAT);
    ASSERT(isinf(score));
  }
  ASSERT_EQ_INT(
      sg_anomaly_model_score_netseq(NULL, valid, sizeof(valid) - 1, &score),
      SG_ANOMALY_ERR_INVALID);
  ASSERT_EQ_INT(
      sg_anomaly_model_score_netseq(model, valid, sizeof(valid) - 1, NULL),
      SG_ANOMALY_ERR_INVALID);
  ASSERT_EQ_INT(sg_anomaly_model_update_netseq(NULL, valid, sizeof(valid) - 1),
                SG_ANOMALY_ERR_INVALID);

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

  size_t large_length = SG_ANOMALY_MAX_COMMAND_LENGTH + 1U;
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
  char *oversized_netseq = test_encode_netseq(oversized_sequence, 3);
  ASSERT(oversized_netseq != NULL);
  ASSERT_EQ_INT(sg_anomaly_model_score_netseq(model, oversized_netseq,
                                              strlen(oversized_netseq), &score),
                SG_ANOMALY_OK);
  ASSERT(isfinite(score));
  ASSERT_EQ_INT(sg_anomaly_model_has_observed_netseq(model, oversized_netseq,
                                                     strlen(oversized_netseq),
                                                     &observed),
                SG_ANOMALY_OK);
  ASSERT(observed);
  free(oversized_netseq);

  const char *all_oversized[] = {large, large, large, large};
  char *all_oversized_netseq = test_encode_netseq(all_oversized, 4);
  ASSERT(all_oversized_netseq != NULL);
  ASSERT_EQ_INT(sg_anomaly_model_score_netseq(model, all_oversized_netseq,
                                              strlen(all_oversized_netseq),
                                              &score),
                SG_ANOMALY_OK);
  ASSERT(isfinite(score));
  ASSERT_EQ_INT(
      sg_anomaly_model_has_observed_netseq(
          model, all_oversized_netseq, strlen(all_oversized_netseq), &observed),
      SG_ANOMALY_OK);
  ASSERT(!observed);
  free(all_oversized_netseq);
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
  ASSERT_EQ_INT(sg_anomaly_model_unigram_count(source, "a"), 0);
  ASSERT_EQ_INT(
      sg_anomaly_model_unigram_count_view(
          source, (sg_anomaly_item_view_t){.data = binary.data, .length = 0}),
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

int main(void) {
  atexit(cleanup_anomaly_temp_file);
  printf("sg_anomaly unit tests\n");
  RUN(lifecycle_and_null_safety);
  RUN(config_contract);
  RUN(update_count_matrix);
  RUN(score_discrimination_matrix);
  RUN(backoff_levels_are_usable);
  RUN(model_owns_string_copies);
  RUN(save_load_roundtrip);
  RUN(reset_and_error_state);
  RUN(maintenance_failures_are_atomic);
  RUN(decay_matrix);
  RUN(decay_removes_large_rare_model);
  RUN(prune_and_compact_preserve_common_behavior);
  RUN(canonical_netseq_contract);
  RUN(binary_netseq_persistence);
  RUN(canonical_netseq_allocation_failures);
  printf("\n%d passed, %d failed\n", pass_count, fail_count);
  return fail_count > 0 ? 1 : 0;
}
