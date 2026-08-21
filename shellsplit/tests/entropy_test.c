#include "env_screener.h"
#include "relative_permutation_entropy.h"
#include "test_allocator.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static int tests_run;
static int tests_passed;
static int tests_failed;

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

static int near(double actual, double expected, double tolerance) {
  return isfinite(actual) && fabs(actual - expected) <= tolerance;
}

static int test_known_entropy_values(void) {
  static const struct {
    const char *text;
    double shannon;
    double bigram;
    double conditional;
  } cases[] = {{"", 0.0, 0.0, 0.0},
               {"aaaa", 0.0, 0.0, 0.0},
               {"abab", 1.0, 0.9182958340544896, 0.0},
               {"abcd", 2.0, 1.584962500721156, 0.0},
               {"aab", 0.9182958340544896, 1.0, 1.0}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT(near(env_screener_calculate_entropy(cases[i].text), cases[i].shannon,
                1e-12));
    ASSERT(near(ngram_entropy(cases[i].text, 1), cases[i].shannon, 1e-12));
    ASSERT(near(ngram_entropy(cases[i].text, 2), cases[i].bigram, 1e-12));
    ASSERT(
        near(conditional_entropy(cases[i].text), cases[i].conditional, 1e-12));
  }
  ASSERT(env_screener_calculate_entropy(NULL) == 0.0);
  ASSERT(isnan(ngram_entropy(NULL, 1)));
  ASSERT(isnan(ngram_entropy("abcd", 0)));
  ASSERT(isnan(ngram_entropy("abcd", 3)));
  ASSERT(isnan(conditional_entropy(NULL)));
  return 1;
}

static int test_permutation_boundaries_and_ranges(void) {
  ASSERT(
      near(permutation_entropy("abcd", 5, 2), ngram_entropy("abcd", 2), 1e-12));
  ASSERT(near(relative_entropy_ratio("abcd", 5, 2), 1.0, 1e-12));
  ASSERT(isnan(permutation_entropy("abcd", 0, 2)));
  ASSERT(isnan(permutation_entropy("abcd", 5, 3)));
  ASSERT(isnan(permutation_conditional_entropy("abcd", 0)));
  ASSERT(isnan(relative_entropy_ratio(NULL, 5, 2)));
  ASSERT(isnan(relative_conditional_entropy(NULL, 5)));

  char long_input[512];
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (size_t i = 0; i < sizeof(long_input) - 1; i++)
    long_input[i] = alphabet[(i * 37 + i / 7) % (sizeof(alphabet) - 1)];
  long_input[sizeof(long_input) - 1] = '\0';

  double values[] = {permutation_entropy(long_input, 17, 2),
                     permutation_conditional_entropy(long_input, 17),
                     relative_entropy_ratio(long_input, 17, 2),
                     relative_conditional_entropy(long_input, 17)};
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
    ASSERT(isfinite(values[i]) && values[i] >= 0.0);
  ASSERT(values[0] <= log2(strlen(long_input)));
  ASSERT(values[1] <= 8.0);
  return 1;
}

static int test_permutation_allocation_failures(void) {
  static const char input[] = "abcdefghijklmnopqrstuvwxyz0123456789";
  for (size_t fail_at = 1; fail_at <= 2; fail_at++) {
    shellsplit_test_alloc_fail_at(fail_at);
    ASSERT(isnan(permutation_entropy(input, 7, 2)));
    shellsplit_test_alloc_fail_at(fail_at);
    ASSERT(isnan(relative_entropy_ratio(input, 7, 2)));
    shellsplit_test_alloc_fail_at(fail_at);
    ASSERT(isnan(permutation_conditional_entropy(input, 7)));
    shellsplit_test_alloc_fail_at(fail_at);
    ASSERT(isnan(relative_conditional_entropy(input, 7)));
  }
  shellsplit_test_alloc_reset();
  ASSERT(isfinite(permutation_entropy(input, 7, 2)));
  ASSERT(isfinite(permutation_conditional_entropy(input, 7)));
  return 1;
}

static int test_posterior_regression_matrix(void) {
  static const struct {
    const char *value;
    double expected;
  } cases[] = {
      {"sk-abcdef1234567890abcdef1234567890", 0.877750},
      {"AKIAIOSFODNN7EXAMPLE", 0.997336},
      {"ghp_abcdefghijklmnopqrstuvwxyz1234567890", 0.980423},
      {"mySecretPassword123!@#", 0.680517},
      {"SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBzZWNyZXQ=", 0.625894},
      {"/home/user/.config/some/app/config.json", 0.000009},
      {"The quick brown fox jumps over the lazy dog", 0.743211},
      {"password123", 0.406075},
      {"550e8400-e29b-41d4-a716-446655440000", 0.279652},
      {"aaaaaaaaaaaaaaaaaaaa", 0.000005},
      {"xK9mLp2nQ4rS6tU8vW0yZ2aB4cD6eF8gH0j", 0.828812},
      {"abc", 0.0},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    double score = env_screener_combined_score_name(NULL, cases[i].value);
    double tolerance = fmax(1e-6, cases[i].expected * 0.01);
    ASSERT(near(score, cases[i].expected, tolerance));
    ASSERT(score >= 0.0 && score <= 1.0);
    ASSERT(score == env_screener_combined_score(cases[i].value));
  }
  ASSERT(env_screener_combined_score(NULL) == 0.0);

  const char *value = "someRandomValue1234567890abcdef";
  double unnamed = env_screener_combined_score_name(NULL, value);
  double named = env_screener_combined_score_name("SERVICE_API_KEY", value);
  ASSERT(named > unnamed);
  return 1;
}

static int test_detector_matrices(void) {
  static const struct {
    const char *value;
    int path;
    int base64;
    int prefix;
  } values[] = {{"/tmp/some/path", 1, 0, 0},
                {"~/Documents/file", 1, 0, 0},
                {"prefix/tmp/file", 1, 0, 0},
                {"sk-abc123", 0, 0, 1},
                {"AKIAIOSFODNN7EXAMPLE", 0, 1, 1},
                {"SGVsbG8gV29ybGQh", 0, 1, 0},
                {"YWJjZA==", 0, 1, 0},
                {"====", 0, 0, 0},
                {"hello world!", 0, 0, 0},
                {NULL, 0, 0, 0}};
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    ASSERT(looks_like_path(values[i].value) == (bool)values[i].path);
    ASSERT(looks_like_base64(values[i].value) == (bool)values[i].base64);
    ASSERT(check_secret_prefix(values[i].value, NULL) ==
           (bool)values[i].prefix);
  }

  static const struct {
    const char *name;
    int whitelisted;
    int secret;
  } names[] = {{"DISPLAY", 1, 0},        {"TMUX", 1, 0},
               {"PATH", 1, 0},           {"SERVICE_API_KEY", 0, 1},
               {"MY_PASSWORD", 0, 1},    {"AUTH_TOKEN", 0, 1},
               {"ORDINARY_VALUE", 0, 0}, {NULL, 0, 0}};
  for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    ASSERT(env_screener_is_whitelisted(names[i].name) ==
           (bool)names[i].whitelisted);
    ASSERT(env_screener_is_secret_pattern(names[i].name) ==
           (bool)names[i].secret);
  }

  double suffix_entropy = -1.0;
  ASSERT(check_secret_prefix("sk-abcdef123456", &suffix_entropy));
  ASSERT(near(suffix_entropy, env_screener_calculate_entropy("abcdef123456"),
              1e-12));
  const char *whitelist = env_screener_get_whitelist_doc();
  ASSERT(whitelist && strstr(whitelist, "DISPLAY") &&
         strstr(whitelist, "PATH"));
  ASSERT(env_screener_get_whitelist_doc() == whitelist);
  ASSERT(env_screener_recommended_capacity() > 0);
  return 1;
}

static int test_environment_scan_contract(void) {
  extern char **environ;
  char **saved_environ = environ;
  char long_named_secret[320];
  memset(long_named_secret, 'X', 256);
  memcpy(long_named_secret + 256, "API_KEY=someRandomValue1234567890abcdef",
         sizeof("API_KEY=someRandomValue1234567890abcdef"));
  char *controlled_environ[] = {
      "DISPLAY=xK9mLp2nQ4rS6tU8vW0yZ2aB4cD6eF8gH0j",
      "missing-equals",
      "=missing-name",
      "EMPTY=",
      "SHORT=abc",
      "SERVICE_API_KEY=someRandomValue1234567890abcdef",
      "ORDINARY_VALUE=/home/user/.config/some/app/config.json",
      "GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
      long_named_secret,
      NULL,
  };
  int indices[3] = {-1, -1, -1};
  int count = -1;

  environ = controlled_environ;
  ASSERT(env_screener_scan(indices, -1, &count, 0.5, 8) == ENV_SCREENER_ERROR);
  ASSERT(count == 0);
  count = -1;
  ASSERT(env_screener_scan(indices, 3, &count, 0.5, -1) == ENV_SCREENER_ERROR);
  ASSERT(count == 0);
  ASSERT(env_screener_scan(indices, 1, &count, 0.5, 8) ==
         ENV_SCREENER_BUFFER_TOO_SMALL);
  ASSERT(count == 3 && indices[0] == -1 && indices[1] == -1 &&
         indices[2] == -1);

  ASSERT(env_screener_scan(indices, 3, &count, 0.5, 8) == ENV_SCREENER_OK);
  ASSERT(count == 3 && indices[0] == 5 && indices[1] == 7 && indices[2] == 8);

  ASSERT(env_screener_scan(indices, 3, &count, 1.0, 8) == ENV_SCREENER_OK);
  ASSERT(count == 0);
  ASSERT(env_screener_scan(indices, 3, &count, 0.0, 100) == ENV_SCREENER_OK);
  ASSERT(count == 0);

  static const double invalid_thresholds[] = {-0.01, 1.01, NAN, INFINITY,
                                              -INFINITY};
  for (size_t i = 0;
       i < sizeof(invalid_thresholds) / sizeof(invalid_thresholds[0]); i++) {
    count = -1;
    ASSERT(env_screener_scan(indices, 3, &count, invalid_thresholds[i], 8) ==
           ENV_SCREENER_ERROR);
    ASSERT(count == 0);
  }

  environ = NULL;
  count = -1;
  ASSERT(env_screener_scan(indices, 3, &count, 0.5, 8) == ENV_SCREENER_OK);
  ASSERT(count == 0);

  environ = saved_environ;
  ASSERT(env_screener_scan(NULL, 3, &count, 0.5, 8) == ENV_SCREENER_ERROR);
  ASSERT(env_screener_scan(indices, 3, NULL, 0.5, 8) == ENV_SCREENER_ERROR);
  return 1;
}

int main(void) {
  printf("Running entropy and environment-screening tests...\n\n");
  TEST(test_known_entropy_values);
  TEST(test_permutation_boundaries_and_ranges);
  TEST(test_permutation_allocation_failures);
  TEST(test_posterior_regression_matrix);
  TEST(test_detector_matrices);
  TEST(test_environment_scan_contract);
  printf("\nResults: %d/%d passed, %d failed\n", tests_passed, tests_run,
         tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
