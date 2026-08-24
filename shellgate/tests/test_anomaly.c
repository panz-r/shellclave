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
      sg_anomaly_has_observed_netseq(model, encoded, strlen(encoded),
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
    (void)sg_anomaly_score_netseq(model, encoded, strlen(encoded), &score);
    free(encoded);
  } else {
    (void)sg_anomaly_score_netseq(model, NULL, 0, &score);
  }
  return score;
}

static void test_anomaly_update_array(sg_anomaly_model_t *model,
                                      const char **sequence, size_t count) {
  char *encoded = test_encode_netseq(sequence, count);
  if (encoded) {
    (void)sg_anomaly_update_netseq(model, encoded, strlen(encoded));
    free(encoded);
  } else {
    (void)sg_anomaly_update_netseq(model, NULL, 0);
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
  return (anomaly_snapshot_t){
      sg_anomaly_vocab_size(model), sg_anomaly_total_uni(model),
      sg_anomaly_total_bi(model),   sg_anomaly_total_tri(model),
      sg_anomaly_total_quad(model), sg_anomaly_total_contexts(model),
      sg_anomaly_unk_count(model),  sg_anomaly_score(model, commands, 5)};
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
  ASSERT_EQ_INT(sg_anomaly_vocab_size(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_uni(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_bi(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_tri(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_quad(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_contexts(model), 0);
  ASSERT_EQ_INT(sg_anomaly_unk_count(model), 0);
  ASSERT_EQ_DBL(sg_anomaly_kn_discount(model), 0.5, 0.000001);
  ASSERT(!sg_anomaly_model_had_error(model));
  size_t empty_removed = 99;
  ASSERT_EQ_INT(sg_anomaly_model_prune(model, 2, &empty_removed),
                SG_ANOMALY_OK);
  ASSERT_EQ_INT(empty_removed, 0);
  ASSERT_EQ_INT(sg_anomaly_reset(NULL), SG_ANOMALY_ERR_INVALID);

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
    ASSERT_EQ_INT(sg_anomaly_total_uni(model), 5);
  }
  sg_anomaly_update(NULL, commands, 5);
  ASSERT_EQ_INT(sg_anomaly_model_decay(NULL, 0.5), SG_ANOMALY_ERR_INVALID);
  sg_anomaly_model_clear_error(NULL);
  sg_anomaly_model_free(NULL);
  ASSERT(isinf(sg_anomaly_score(NULL, commands, 5)));
  ASSERT(isinf(sg_anomaly_score(model, NULL, 5)));
  ASSERT_EQ_INT(sg_anomaly_vocab_size(NULL), 0);
  ASSERT_EQ_INT(sg_anomaly_total_uni(NULL), 0);
  ASSERT_EQ_INT(sg_anomaly_total_bi(NULL), 0);
  ASSERT_EQ_INT(sg_anomaly_total_tri(NULL), 0);
  ASSERT_EQ_INT(sg_anomaly_total_quad(NULL), 0);
  ASSERT_EQ_INT(sg_anomaly_total_contexts(NULL), 0);
  ASSERT_EQ_INT(sg_anomaly_unk_count(NULL), 0);
  ASSERT_EQ_INT(sg_anomaly_uni_count(NULL, "a"), 0);
  ASSERT_EQ_INT(sg_anomaly_bi_count(NULL, "a", "b"), 0);
  ASSERT_EQ_INT(sg_anomaly_tri_count(NULL, "a", "b", "c"), 0);
  ASSERT_EQ_INT(sg_anomaly_quad_count(NULL, "a", "b", "c", "d"), 0);
  char oversized[8192];
  memset(oversized, 'x', sizeof(oversized) - 1);
  oversized[sizeof(oversized) - 1] = '\0';
  ASSERT_EQ_INT(sg_anomaly_bi_count(model, "", "b"), 0);
  ASSERT_EQ_INT(sg_anomaly_bi_count(model, oversized, "b"), 0);
  ASSERT_EQ_INT(sg_anomaly_tri_count(model, "", "b", "c"), 0);
  ASSERT_EQ_INT(sg_anomaly_tri_count(model, oversized, "b", "c"), 0);
  ASSERT_EQ_INT(sg_anomaly_quad_count(model, "", "b", "c", "d"), 0);
  ASSERT_EQ_INT(sg_anomaly_quad_count(model, oversized, "b", "c", "d"), 0);
  const char *oversized_sequence[] = {oversized, "b", "c", "d"};
  ASSERT(isfinite(sg_anomaly_score(model, oversized_sequence, 4)));
  const char *oversized_middle[] = {"a", oversized, "c", "d"};
  const char *oversized_late[] = {"a", "b", oversized, "d"};
  const char *oversized_last[] = {"a", "b", "c", oversized};
  ASSERT(isfinite(sg_anomaly_score(model, oversized_middle, 4)));
  ASSERT(isfinite(sg_anomaly_score(model, oversized_late, 4)));
  ASSERT(isfinite(sg_anomaly_score(model, oversized_last, 4)));
  ASSERT_EQ_DBL(sg_anomaly_kn_discount(NULL), 0.0, 0.0);
  bool observed = true;
  ASSERT_EQ_INT(sg_anomaly_has_observed_netseq(NULL, "", 0, &observed),
                SG_ANOMALY_ERR_INVALID);
  ASSERT(!observed);
  ASSERT_EQ_INT(sg_anomaly_has_observed_netseq(model, NULL, 0, &observed),
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
  ASSERT(!sg_anomaly_model_compact(NULL));
  ASSERT_EQ_INT(sg_anomaly_save(NULL, "/tmp/unused"), -1);
  ASSERT_EQ_INT(sg_anomaly_load(NULL, "/tmp/unused"), -1);
  sg_anomaly_model_free(model);
}

TEST(update_count_matrix) {
  for (size_t length = 1; length <= 5; length++) {
    sg_anomaly_model_t *model = sg_anomaly_model_new();
    ASSERT(model != NULL);
    update_repeated(model, commands, length, 3);

    ASSERT_EQ_INT(sg_anomaly_vocab_size(model), length);
    ASSERT_EQ_INT(sg_anomaly_total_uni(model), length * 3);
    ASSERT_EQ_INT(sg_anomaly_total_bi(model),
                  length > 1 ? (length - 1) * 3 : 0);
    ASSERT_EQ_INT(sg_anomaly_total_tri(model),
                  length > 2 ? (length - 2) * 3 : 0);
    ASSERT_EQ_INT(sg_anomaly_total_quad(model),
                  length > 3 ? (length - 3) * 3 : 0);
    ASSERT_EQ_INT(sg_anomaly_uni_count(model, "a"), 3);
    ASSERT_EQ_INT(sg_anomaly_uni_count(model, "missing"), 0);
    ASSERT_EQ_INT(sg_anomaly_bi_count(model, "a", "b"), length > 1 ? 3 : 0);
    ASSERT_EQ_INT(sg_anomaly_tri_count(model, "a", "b", "c"),
                  length > 2 ? 3 : 0);
    ASSERT_EQ_INT(sg_anomaly_quad_count(model, "a", "b", "c", "d"),
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
  ASSERT_EQ_INT(sg_anomaly_total_uni(model), 4);
  ASSERT_EQ_INT(sg_anomaly_total_bi(model), 3);
  ASSERT_EQ_INT(sg_anomaly_total_tri(model), 2);
  ASSERT_EQ_INT(sg_anomaly_total_quad(model), 1);
  ASSERT_EQ_INT(sg_anomaly_quad_count(model, boundary[0], boundary[1],
                                      boundary[2], boundary[3]),
                1);
  ASSERT(isfinite(sg_anomaly_score(model, boundary, 4)));

  char too_long[SG_ANOMALY_MAX_COMMAND_LENGTH + 2];
  memset(too_long, 'x', sizeof(too_long) - 1);
  too_long[sizeof(too_long) - 1] = '\0';
  const char *invalid[] = {boundary[0], boundary[1], too_long};
  sg_anomaly_update(model, invalid, 3);
  ASSERT_EQ_INT(sg_anomaly_total_uni(model), 4);
  /* An over-long name is never learned, so it must score as an unknown command
   * rather than returning INFINITY, which callers read as "cannot score" and
   * would let it bypass anomaly detection entirely. */
  double over_long_score = sg_anomaly_score(model, invalid, 3);
  ASSERT(isfinite(over_long_score));
  const char *known[] = {boundary[0], boundary[1], boundary[2]};
  ASSERT(over_long_score > sg_anomaly_score(model, known, 3));
  ASSERT_EQ_INT(sg_anomaly_uni_count(model, too_long), 0);
  sg_anomaly_model_free(model);
}

TEST(score_discrimination_matrix) {
  for (size_t length = 3; length <= 5; length++) {
    sg_anomaly_model_t *model = sg_anomaly_model_new_ex(0.1, -10.0);
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
  sg_anomaly_model_t *unigram_model = sg_anomaly_model_new_ex(0.1, -10.0);
  sg_anomaly_model_t *bigram_model = sg_anomaly_model_new_ex(0.1, -10.0);
  ASSERT(unigram_model && bigram_model);

  for (size_t i = 0; i < 3; i++)
    sg_anomaly_update(unigram_model, &sequence[i], 1);
  sg_anomaly_update(bigram_model, sequence, 2);
  sg_anomaly_update(bigram_model, sequence + 1, 2);

  ASSERT(isfinite(sg_anomaly_score(unigram_model, sequence, 3)));
  ASSERT(isfinite(sg_anomaly_score(bigram_model, sequence, 3)));
  ASSERT_EQ_INT(sg_anomaly_total_tri(unigram_model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_tri(bigram_model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_bi(bigram_model), 2);
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
  ASSERT_EQ_INT(sg_anomaly_vocab_size(model), 3);
  for (size_t i = 0; i < 3; i++)
    ASSERT_EQ_INT(sg_anomaly_uni_count(model, probe[i]), 1);
  ASSERT(isfinite(sg_anomaly_score(model, probe, 3)));
  sg_anomaly_model_free(model);
}

TEST(save_load_roundtrip) {
  char path[] = "/tmp/shellclave-anomaly-XXXXXX";
  int fd = mkstemp(path);
  ASSERT(fd >= 0);
  snprintf(anomaly_temp_path, sizeof(anomaly_temp_path), "%s", path);
  close(fd);

  sg_anomaly_model_t *source = sg_anomaly_model_new_ex(0.5, -8.0);
  sg_anomaly_model_t *loaded = sg_anomaly_model_new();
  ASSERT(source && loaded);
  update_repeated(source, commands, 5, 5);
  const char *unseen[] = {"v", "w", "x", "y", "z"};
  double known_score = sg_anomaly_score(source, commands, 5);
  double unseen_score = sg_anomaly_score(source, unseen, 5);

  ASSERT_EQ_INT(sg_anomaly_save(source, path), 0);
  ASSERT_EQ_INT(sg_anomaly_save(source, "/no/such/directory/model"), -1);
  if (access("/dev/full", W_OK) == 0) {
    errno = 0;
    ASSERT_EQ_INT(sg_anomaly_save(source, "/dev/full"), -1);
    ASSERT(errno != 0);
  }
  ASSERT_EQ_INT(sg_anomaly_load(loaded, path), 0);
  ASSERT_EQ_INT(sg_anomaly_load(loaded, path), 0);
  ASSERT_EQ_INT(sg_anomaly_vocab_size(loaded), 5);
  ASSERT_EQ_INT(sg_anomaly_total_uni(loaded), 25);
  ASSERT_EQ_INT(sg_anomaly_total_bi(loaded), 20);
  ASSERT_EQ_INT(sg_anomaly_total_tri(loaded), 15);
  ASSERT_EQ_INT(sg_anomaly_total_quad(loaded), 10);
  ASSERT_EQ_INT(sg_anomaly_unk_count(loaded), sg_anomaly_unk_count(source));
  ASSERT_EQ_DBL(sg_anomaly_score(loaded, commands, 5), known_score, 0.000001);
  ASSERT_EQ_DBL(sg_anomaly_score(loaded, unseen, 5), unseen_score, 0.000001);
  ASSERT_EQ_DBL(sg_anomaly_kn_discount(loaded), sg_anomaly_kn_discount(source),
                0.000001);

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
  ASSERT_EQ_INT(sg_anomaly_load(loaded, path), -1);
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
    BAD_KEY_TERMINATOR,
    BAD_NEWLINE
  };
  static const enum corruption corruptions[] = {
      EMPTY,     BAD_MAGIC, MISSING_METADATA,   BAD_METADATA,
      TRUNCATED, BAD_TYPE,  BAD_KEY_TERMINATOR, BAD_NEWLINE};
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
    }
    fixture = fopen(path, "wb");
    ASSERT(fixture != NULL);
    ASSERT(fwrite(data, 1, size, fixture) == size);
    ASSERT(fclose(fixture) == 0);
    free(data);

    errno = 0;
    ASSERT_EQ_INT(sg_anomaly_load(loaded, path), -1);
    ASSERT_EQ_INT(errno, EPROTO);
    ASSERT_EQ_INT(sg_anomaly_vocab_size(loaded), 5);
    ASSERT_EQ_INT(sg_anomaly_total_uni(loaded), 25);
    ASSERT_EQ_DBL(sg_anomaly_score(loaded, commands, 5), preserved_score,
                  0.000001);
  }

  fixture = fopen(path, "wb");
  ASSERT(fixture != NULL);
  ASSERT(fwrite(valid, 1, valid_size, fixture) == valid_size);
  ASSERT(fclose(fixture) == 0);
  free(valid);
  ASSERT_EQ_INT(sg_anomaly_load(loaded, path), 0);
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
  ASSERT_EQ_INT(sg_anomaly_reset(model), SG_ANOMALY_OK);
  ASSERT(!sg_anomaly_model_had_error(model));
  ASSERT_EQ_INT(sg_anomaly_vocab_size(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_uni(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_bi(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_tri(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_quad(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_contexts(model), 0);
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
      probe_status = sg_anomaly_reset(probe);
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
          operation == 0   ? sg_anomaly_reset(model)
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
          operation == 0   ? sg_anomaly_reset(model)
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
  ASSERT_EQ_INT(sg_anomaly_unk_count(model), 5);
  static const double invalid_scales[] = {0.0, -0.5,     2.0,
                                          NAN, INFINITY, -INFINITY};
  for (size_t i = 0; i < sizeof(invalid_scales) / sizeof(invalid_scales[0]);
       i++)
    ASSERT_EQ_INT(sg_anomaly_model_decay(model, invalid_scales[i]),
                  SG_ANOMALY_ERR_INVALID);
  ASSERT_EQ_INT(sg_anomaly_model_decay(model, 1.0), SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_total_uni(model), 20);
  ASSERT_EQ_INT(sg_anomaly_total_quad(model), 8);

  ASSERT_EQ_INT(sg_anomaly_model_decay(model, 0.5), SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_vocab_size(model), 5);
  ASSERT_EQ_INT(sg_anomaly_total_uni(model), 10);
  ASSERT_EQ_INT(sg_anomaly_total_bi(model), 8);
  ASSERT_EQ_INT(sg_anomaly_total_tri(model), 6);
  ASSERT_EQ_INT(sg_anomaly_total_quad(model), 4);
  ASSERT_EQ_INT(sg_anomaly_unk_count(model), 2);
  for (size_t i = 0; i < 5; i++)
    ASSERT_EQ_INT(sg_anomaly_uni_count(model, commands[i]), 2);
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
  ASSERT_EQ_INT(sg_anomaly_vocab_size(model), COMMAND_COUNT);
  ASSERT_EQ_INT(sg_anomaly_model_decay(model, 0.5), SG_ANOMALY_OK);
  ASSERT_EQ_INT(sg_anomaly_vocab_size(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_uni(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_bi(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_tri(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_quad(model), 0);
  ASSERT_EQ_INT(sg_anomaly_total_contexts(model), 0);
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
  ASSERT_EQ_INT(sg_anomaly_vocab_size(model), 4);
  ASSERT_EQ_INT(sg_anomaly_total_uni(model), 16);
  ASSERT_EQ_INT(sg_anomaly_total_bi(model), 12);
  ASSERT_EQ_INT(sg_anomaly_total_tri(model), 8);
  ASSERT_EQ_INT(sg_anomaly_total_quad(model), 4);
  ASSERT_EQ_INT(sg_anomaly_uni_count(model, "gcc"), 0);
  ASSERT_EQ_INT(sg_anomaly_quad_count(model, "gcc", "make", "test", "install"),
                0);
  ASSERT_EQ_INT(sg_anomaly_model_prune(model, 0, &removed), SG_ANOMALY_OK);
  ASSERT_EQ_INT(removed, 0);
  double score = sg_anomaly_score(model, common, 4);
  ASSERT(sg_anomaly_model_compact(model));
  ASSERT_EQ_DBL(sg_anomaly_score(model, common, 4), score, 0.000001);
  sg_anomaly_model_free(model);
}

TEST(canonical_netseq_contract) {
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  ASSERT(model != NULL);
  static const char valid[] = "9:two words,1::,1:,,";
  ASSERT_EQ_INT(sg_anomaly_update_netseq(model, valid, sizeof(valid) - 1),
                SG_ANOMALY_OK);
  bool observed = false;
  ASSERT_EQ_INT(sg_anomaly_has_observed_netseq(model, valid, sizeof(valid) - 1,
                                               &observed),
                SG_ANOMALY_OK);
  ASSERT(observed);
  observed = true;
  ASSERT_EQ_INT(sg_anomaly_has_observed_netseq(model, "", 0, &observed),
                SG_ANOMALY_OK);
  ASSERT(!observed);
  ASSERT_EQ_INT(sg_anomaly_has_observed_netseq(model, "01:a,", 5, &observed),
                SG_ANOMALY_ERR_FORMAT);
  ASSERT_EQ_INT(sg_anomaly_vocab_size(model), 3);
  double score = 0.0;
  ASSERT_EQ_INT(
      sg_anomaly_score_netseq(model, valid, sizeof(valid) - 1, &score),
      SG_ANOMALY_OK);
  ASSERT(isfinite(score));

  static const char *invalid[] = {"01:x,", "1:x", "2:x,", "0:,",
                                  "x",     "1x,", "1:x;", "1:,"};
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    score = 0.0;
    ASSERT_EQ_INT(
        sg_anomaly_score_netseq(model, invalid[i], strlen(invalid[i]), &score),
        SG_ANOMALY_ERR_FORMAT);
    ASSERT(isinf(score));
  }
  ASSERT_EQ_INT(sg_anomaly_score_netseq(NULL, valid, sizeof(valid) - 1, &score),
                SG_ANOMALY_ERR_INVALID);
  ASSERT_EQ_INT(sg_anomaly_score_netseq(model, valid, sizeof(valid) - 1, NULL),
                SG_ANOMALY_ERR_INVALID);
  ASSERT_EQ_INT(sg_anomaly_update_netseq(NULL, valid, sizeof(valid) - 1),
                SG_ANOMALY_ERR_INVALID);

  static const char embedded_nul[] = {'1', ':', 'x', ',', '\0',
                                      '1', ':', 'y', ','};
  ASSERT_EQ_INT(sg_anomaly_score_netseq(model, embedded_nul,
                                        sizeof(embedded_nul), &score),
                SG_ANOMALY_ERR_FORMAT);
  ASSERT_EQ_INT(sg_anomaly_score_netseq(model, "", 0, &score), SG_ANOMALY_OK);
  ASSERT(isinf(score));
  ASSERT_EQ_INT(sg_anomaly_update_netseq(model, "", 0), SG_ANOMALY_OK);

  static const char overflow[] = "999999999999999999999999999999999999:x,";
  ASSERT_EQ_INT(sg_anomaly_update_netseq(model, overflow, sizeof(overflow) - 1),
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
  ASSERT_EQ_INT(sg_anomaly_update_netseq(model, large, encoded_length),
                SG_ANOMALY_ERR_LIMIT);
  ASSERT_EQ_INT(sg_anomaly_score_netseq(model, large, encoded_length, &score),
                SG_ANOMALY_OK);
  ASSERT(isinf(score));
  free(large);
  sg_anomaly_model_free(model);
}

TEST(canonical_netseq_allocation_failures) {
  static const char sequence[] = "1:a,1:b,1:c,1:d,1:e,1:f,1:g,1:h,1:i,";
  sg_anomaly_model_t *probe = sg_anomaly_model_new();
  ASSERT(probe != NULL);
  sg_test_anomaly_op_reset();
  ASSERT_EQ_INT(sg_anomaly_update_netseq(probe, sequence, sizeof(sequence) - 1),
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
        sg_anomaly_update_netseq(model, sequence, sizeof(sequence) - 1);
    sg_test_anomaly_op_reset();
    ASSERT_EQ_INT(status, SG_ANOMALY_ERR_MEMORY);
    sg_anomaly_model_free(model);
  }

  probe = sg_anomaly_model_new();
  ASSERT(probe != NULL);
  ASSERT_EQ_INT(sg_anomaly_update_netseq(probe, sequence, sizeof(sequence) - 1),
                SG_ANOMALY_OK);
  double score = 0.0;
  sg_test_anomaly_op_reset();
  ASSERT_EQ_INT(
      sg_anomaly_score_netseq(probe, sequence, sizeof(sequence) - 1, &score),
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
  RUN(canonical_netseq_allocation_failures);
  printf("\n%d passed, %d failed\n", pass_count, fail_count);
  return fail_count > 0 ? 1 : 0;
}
