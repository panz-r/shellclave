/*
 * test_token_types.c – Unit tests for the wildcard lattice and token
 * classification.
 *
 * Tests all 12+1 types, the join table, and the compatibility table.
 */

#include "../src/netpattern.h"
#include "shell_netstring.h"
#include "shelltype.h"
#include "test_allocator.h"
#include "test_netargv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

static char *test_wrap_netstring(const char *payload) {
  size_t length = strlen(payload);
  size_t record_length = 0;
  if (shell_netstring_encoded_length(length, &record_length) !=
      SHELL_NETSTRING_OK)
    return NULL;
  char *encoded = malloc(record_length + 1);
  if (!encoded)
    return NULL;
  size_t written = 0;
  if (shell_netstring_write(encoded, record_length, payload, length,
                            &written) != SHELL_NETSTRING_OK ||
      written != record_length) {
    free(encoded);
    return NULL;
  }
  encoded[written] = '\0';
  return encoded;
}

static char *test_pattern_record(char tag, const char *value) {
  char tag_payload[2] = {tag, '\0'};
  char *tag_record = test_wrap_netstring(tag_payload);
  char *value_record = test_wrap_netstring(value);
  if (!tag_record || !value_record) {
    free(tag_record);
    free(value_record);
    return NULL;
  }
  size_t payload_length = strlen(tag_record) + strlen(value_record);
  char *payload = malloc(payload_length + 1);
  if (!payload) {
    free(tag_record);
    free(value_record);
    return NULL;
  }
  strcpy(payload, tag_record);
  strcat(payload, value_record);
  char *record = test_wrap_netstring(payload);
  free(payload);
  free(value_record);
  free(tag_record);
  return record;
}

static char *test_compound_pattern(const char *tags, const char *const *values,
                                   size_t count) {
  char *parts[4] = {0};
  size_t compound_length = 0;
  for (size_t i = 0; i < count; i++) {
    parts[i] = test_pattern_record(tags[i], values[i]);
    if (!parts[i])
      goto fail;
    compound_length += strlen(parts[i]);
  }
  char *compound = malloc(compound_length + 1);
  if (!compound)
    goto fail;
  compound[0] = '\0';
  for (size_t i = 0; i < count; i++)
    strcat(compound, parts[i]);
  char *pattern = test_pattern_record('C', compound);
  free(compound);
  for (size_t i = 0; i < count; i++)
    free(parts[i]);
  return pattern;

fail:
  for (size_t i = 0; i < count; i++)
    free(parts[i]);
  return NULL;
}

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  %-45s ", #name);                                                 \
    if (name()) {                                                              \
      tests_passed++;                                                          \
      printf("PASS\n");                                                        \
    } else {                                                                   \
      tests_failed++;                                                          \
      printf("FAIL\n");                                                        \
    }                                                                          \
  } while (0)

#define ASSERT(cond)                                                           \
  do {                                                                         \
    if (!(cond)) {                                                             \
      printf("  Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__);  \
      return 0;                                                                \
    }                                                                          \
  } while (0)

/* --- TYPE CLASSIFICATION --- */

static int test_classification_matrix(void) {
  static const struct {
    const char *token;
    st_token_type_t expected;
  } cases[] = {
      {"deadbeef", ST_TYPE_HEXHASH},
      {"a1B2c3D4e5F6", ST_TYPE_HEXHASH},
      {"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", ST_TYPE_SHA},
      {"deadbee", ST_TYPE_SHA},
      {"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", ST_TYPE_SHA},
      {"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
       ST_TYPE_SHA},
      {"42", ST_TYPE_NUMBER},
      {"-100", ST_TYPE_NUMBER},
      {"0xff", ST_TYPE_NUMBER},
      {"0755", ST_TYPE_PERM_OCTAL},
      {"0", ST_TYPE_NUMBER},
      {"755", ST_TYPE_PERM_OCTAL},
      {"644", ST_TYPE_PERM_OCTAL},
      {"0644", ST_TYPE_PERM_OCTAL},
      {"4755", ST_TYPE_PERM_OCTAL},
      {"2755", ST_TYPE_PERM_OCTAL},
      {"1755", ST_TYPE_PERM_OCTAL},
      {"07550", ST_TYPE_NUMBER},
      {"2025", ST_TYPE_NUMBER},
      {"1234", ST_TYPE_NUMBER},
      {"9999", ST_TYPE_NUMBER},
      {"HUP", ST_TYPE_SIGNAL},
      {"SIGTERM", ST_TYPE_SIGNAL},
      {"KILL", ST_TYPE_SIGNAL},
      {"INT", ST_TYPE_SIGNAL},
      {"9", ST_TYPE_NUMBER},
      {"15", ST_TYPE_NUMBER},
      {"1-5", ST_TYPE_RANGE},
      {"10-20", ST_TYPE_RANGE},
      {"0-100", ST_TYPE_RANGE},
      {"0,30", ST_TYPE_CRON},
      {"1,5", ST_TYPE_CRON},
      {"123", ST_TYPE_NUMBER},
      {"1-2-3", ST_TYPE_CRON},
      {"root:docker", ST_TYPE_USER_GROUP},
      {"www-data:www-data", ST_TYPE_USER_GROUP},
      {"alice:developers", ST_TYPE_USER_GROUP},
      {"nginx:latest", ST_TYPE_IMAGE},
      {"SHA1:abc", ST_TYPE_IMAGE},
      {"User:Group", ST_TYPE_LITERAL},
      {"user:pass", ST_TYPE_IMAGE},
      {"*.txt", ST_TYPE_GLOB},
      {"file?.log", ST_TYPE_GLOB},
      {"[abc]", ST_TYPE_GLOB},
      {"src/**/*.js", ST_TYPE_GLOB},
      {"/etc/passwd", ST_TYPE_ABS_PATH},
      {"--help", ST_TYPE_LONGOPT},
      {"foo", ST_TYPE_LITERAL},
      {"192.168.1.1", ST_TYPE_IPV4},
      {"127.0.0.1", ST_TYPE_IPV4},
      {"0.0.0.0", ST_TYPE_IPV4},
      {"255.255.255.255", ST_TYPE_IPV4},
      {"nginx", ST_TYPE_LITERAL},
      {"my_var", ST_TYPE_LITERAL},
      {"PATH", ST_TYPE_LITERAL},
      {"var123", ST_TYPE_LITERAL},
      {"_private", ST_TYPE_LITERAL},
      {"output.txt", ST_TYPE_FILENAME},
      {"main.c", ST_TYPE_FILENAME},
      {"archive.tar.gz", ST_TYPE_FILENAME},
      {".gitignore", ST_TYPE_FILENAME},
      {"src/main.c", ST_TYPE_REL_PATH},
      {"../lib/foo", ST_TYPE_REL_PATH},
      {"./configure", ST_TYPE_REL_PATH},
      {"src/utils/helpers.c", ST_TYPE_REL_PATH},
      {"/tmp", ST_TYPE_ABS_PATH},
      {"/usr/local/bin/gcc", ST_TYPE_ABS_PATH},
      {"https://example.com", ST_TYPE_URL},
      {"http://localhost:8080", ST_TYPE_URL},
      {"git://github.com/user/repo", ST_TYPE_URL},
      {"git+ssh://github.com/user/repo", ST_TYPE_URL},
      {"web1.test-case://example.com", ST_TYPE_URL},
      {"ftp://files.example.com/pub", ST_TYPE_URL},
      {"my-host.example.com", ST_TYPE_HOSTNAME},
      {"a-b.c", ST_TYPE_LITERAL},
      {"example.com", ST_TYPE_HOSTNAME},
      {"github.io", ST_TYPE_HOSTNAME},
      {"myapp.dev", ST_TYPE_HOSTNAME},
      {"server.local", ST_TYPE_HOSTNAME},
      {"build.log", ST_TYPE_FILENAME},
      {"main.go", ST_TYPE_FILENAME},
      {"localhost", ST_TYPE_LITERAL},
      {"myhost", ST_TYPE_LITERAL},
      {"hello", ST_TYPE_LITERAL},
      {"msg", ST_TYPE_LITERAL},
      {"hello world", ST_TYPE_QUOTED_SPACE},
      {"some test string", ST_TYPE_QUOTED_SPACE},
      {"-", ST_TYPE_LITERAL},
      {"foo@bar", ST_TYPE_LITERAL},
      {"%PATH%", ST_TYPE_LITERAL},
      {"-v", ST_TYPE_SHORTOPT},
      {"-h", ST_TYPE_SHORTOPT},
      {"-x", ST_TYPE_SHORTOPT},
      {"-a", ST_TYPE_SHORTOPT},
      {"-la", ST_TYPE_SHORTOPT},
      {"-rf", ST_TYPE_SHORTOPT},
      {"--version", ST_TYPE_LONGOPT},
      {"--verbose", ST_TYPE_LONGOPT},
      {"--output=file", ST_TYPE_LONGOPT},
      {"--max-count=10", ST_TYPE_LONGOPT},
      {"--name", ST_TYPE_LONGOPT},
      {"-42", ST_TYPE_NUMBER},
      {"-1", ST_TYPE_NUMBER},
      {"--", ST_TYPE_LITERAL},
      {"2001:0db8:85a3:0000:0000:8a2e:0370:7334", ST_TYPE_IPV6},
      {"2001:db8:85a3:0:0:8a2e:370:7334", ST_TYPE_IPV6},
      {"::1", ST_TYPE_IPV6},
      {"2001:db8::1", ST_TYPE_IPV6},
      {"::", ST_TYPE_IPV6},
      {"fe80::", ST_TYPE_IPV6},
      {"fe80::1%eth0", ST_TYPE_IPV6},
      {"::1%lo", ST_TYPE_IPV6},
      {"::ffff:192.168.1.1", ST_TYPE_IPV6},
      {"fe80::1%eth-0", ST_TYPE_IPV6},
      {"fe80::1%eth_0.1", ST_TYPE_IPV6},
      {":::", ST_TYPE_LITERAL},
      {"2001::db8::1", ST_TYPE_LITERAL},
      {"aa:bb:cc:dd:ee:ff", ST_TYPE_MAC},
      {"00:11:22:33:44:55", ST_TYPE_MAC},
      {"AA:BB:CC:DD:EE:FF", ST_TYPE_MAC},
      {"aa-bb-cc-dd-ee-ff", ST_TYPE_MAC},
      {"00-11-22-33-44-55", ST_TYPE_MAC},
      {"aa:bb:cc", ST_TYPE_IMAGE},
      {"gg:hh:ii:jj:kk:ll", ST_TYPE_IMAGE},
      {"aa:bb:cc:dd:ee", ST_TYPE_IMAGE},
      {"GET", ST_TYPE_METHOD},
      {"POST", ST_TYPE_METHOD},
      {"PUT", ST_TYPE_METHOD},
      {"DELETE", ST_TYPE_METHOD},
      {"PATCH", ST_TYPE_METHOD},
      {"get", ST_TYPE_LITERAL},
      {"Get", ST_TYPE_LITERAL},
      {"HEAD", ST_TYPE_BRANCH},
      {"head", ST_TYPE_LITERAL},
      {"OPTIONS", ST_TYPE_METHOD},
      {"30s", ST_TYPE_DURATION},
      {"1s", ST_TYPE_DURATION},
      {"0s", ST_TYPE_DURATION},
      {"1.5h", ST_TYPE_DURATION},
      {"-1.5s", ST_TYPE_DURATION},
      {"100ms", ST_TYPE_DURATION},
      {"500ns", ST_TYPE_DURATION},
      {"10us", ST_TYPE_DURATION},
      {"7d", ST_TYPE_DURATION},
      {"2w", ST_TYPE_DURATION},
      {"45m", ST_TYPE_DURATION},
      {"30M", ST_TYPE_SIZE},
      {"1Ki", ST_TYPE_SIZE},
      {"abc", ST_TYPE_LITERAL},
      {"s", ST_TYPE_LITERAL},
      {"*/5", ST_TYPE_CRON},
      {"*/15", ST_TYPE_CRON},
      {"*", ST_TYPE_CRON},
      {",", ST_TYPE_LITERAL},
      {"2025-04-24", ST_TYPE_TIMESTAMP},
      {"15:30:00", ST_TYPE_TIMESTAMP},
      {"2025-04-24T15:30:00", ST_TYPE_TIMESTAMP},
      {"2025-04-24T15:30:00Z", ST_TYPE_TIMESTAMP},
      {"2024-02-29T15:30:00+02:30", ST_TYPE_TIMESTAMP},
      {"550e8400-e29b-41d4-a716-446655440000", ST_TYPE_UUID},
      {"alice+build@example.com", ST_TYPE_EMAIL},
      {"1.2.3-alpha-beta.1+build.05", ST_TYPE_SEMVER},
      {"not-a-date", ST_TYPE_HYPHENATED},
      {"sha256", ST_TYPE_HASH_ALGO},
      {"md5", ST_TYPE_HASH_ALGO},
      {"blake2b", ST_TYPE_HASH_ALGO},
      {"sha512", ST_TYPE_HASH_ALGO},
      {"sha", ST_TYPE_LITERAL},
      {"MD5", ST_TYPE_LITERAL},
      {"hash", ST_TYPE_LITERAL},
      {"$PATH", ST_TYPE_ENV_VAR},
      {"$HOME", ST_TYPE_ENV_VAR},
      {"${HOME}", ST_TYPE_ENV_VAR},
      {"$_var", ST_TYPE_ENV_VAR},
      {"$", ST_TYPE_LITERAL},
      {"${}", ST_TYPE_LITERAL},
      {"${1ABC}", ST_TYPE_LITERAL},
      {"user-42", ST_TYPE_HYPHENATED},
      {"alice-smith", ST_TYPE_HYPHENATED},
      {"john-doe", ST_TYPE_HYPHENATED},
      {"_service-account", ST_TYPE_HYPHENATED},
      {"alice", ST_TYPE_LITERAL},
      {"john_doe", ST_TYPE_LITERAL},
      {"deploy_user2", ST_TYPE_LITERAL},
      {"123user", ST_TYPE_LITERAL},
      {"main", ST_TYPE_BRANCH},
      {"develop", ST_TYPE_BRANCH},
      {"feature/login", ST_TYPE_BRANCH},
      {"origin/main", ST_TYPE_BRANCH},
      {"release/v2.0", ST_TYPE_REL_PATH},
      {"release-1.0", ST_TYPE_LITERAL},
      {"fix-123-bug", ST_TYPE_HYPHENATED},
      {"abc1234", ST_TYPE_SHA},
      {"ghcr.io/org/app:v1", ST_TYPE_IMAGE},
      {"myimage@sha256:"
       "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
       ST_TYPE_IMAGE},
      {"express", ST_TYPE_LITERAL},
      {"lodash", ST_TYPE_LITERAL},
      {"react@18", ST_TYPE_PKG},
      {"lodash@4.17.21", ST_TYPE_PKG},
      {"@babel/core", ST_TYPE_PKG},
      {"@types/node", ST_TYPE_PKG},
      {"-verbose", ST_TYPE_SHORTOPT},
      {"root", ST_TYPE_USER},
      {"nobody", ST_TYPE_USER},
      {"_apt", ST_TYPE_USER},
      {"www-data", ST_TYPE_USER},
      {"deploy-user", ST_TYPE_HYPHENATED},
      {"_systemd", ST_TYPE_LITERAL},
      {"Root", ST_TYPE_LITERAL},
      {"POSTGRES", ST_TYPE_LITERAL},
      {"0user", ST_TYPE_LITERAL},
      {"SHA256:uNiVztksCsDhcc0u9e8BgrJXVGL5Nr0iASdhO1tB9qE",
       ST_TYPE_FINGERPRINT},
      {"1a:2b:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d", ST_TYPE_FINGERPRINT},
  };

  ASSERT(st_classify_token(NULL) == ST_TYPE_LITERAL);
  ASSERT(st_classify_token("") == ST_TYPE_LITERAL);

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_token_type_t actual = st_classify_token(cases[i].token);
    if ((unsigned)actual >= ST_TYPE_COUNT) {
      printf("  case %zu: classify('%s') returned invalid type %u\n", i,
             cases[i].token, (unsigned)actual);
      return 0;
    }
    if (actual != cases[i].expected) {
      printf("  case %zu: classify(%c%s%c) = %s, expected %s\n", i, 39,
             cases[i].token, 39, st_type_symbol[actual],
             st_type_symbol[cases[i].expected]);
      return 0;
    }
    ASSERT(st_type_symbol[actual] != NULL);
  }

  static const struct {
    const char *token;
    st_token_type_t forbidden;
  } rejection_cases[] = {
      {"256.0.0.1", ST_TYPE_IPV4},
      {"1..2.3", ST_TYPE_IPV4},
      {"1..2M", ST_TYPE_SIZE},
      {"01.2.3", ST_TYPE_SEMVER},
      {"1.2.3-01", ST_TYPE_SEMVER},
      {"550e8400-e29b-41d4-a716-44665544000g", ST_TYPE_UUID},
      {"alice@example", ST_TYPE_EMAIL},
      {"@example.com", ST_TYPE_EMAIL},
      {"alice@", ST_TYPE_EMAIL},
      {"ali!ce@example.com", ST_TYPE_EMAIL},
      {"alice@example!.com", ST_TYPE_EMAIL},
      {"host..example.com", ST_TYPE_HOSTNAME},
      {"host--name.example", ST_TYPE_HOSTNAME},
      {"2025-02-29", ST_TYPE_TIMESTAMP},
      {"2025-04-31", ST_TYPE_TIMESTAMP},
      {"2025-04-24T15:30:00garbage", ST_TYPE_TIMESTAMP},
      {"2025-04-24T15:30:00+24:00", ST_TYPE_TIMESTAMP},
      {"2025-04-24T15:30:00+01:60", ST_TYPE_TIMESTAMP},
      {"24:00:00", ST_TYPE_TIMESTAMP},
      {"${BAD-NAME}", ST_TYPE_ENV_VAR},
      {"$9BAD", ST_TYPE_ENV_VAR},
      {"@scope", ST_TYPE_PKG},
      {"@scope/", ST_TYPE_PKG},
      {"package@", ST_TYPE_PKG},
      {"image@sha256:abcd", ST_TYPE_IMAGE},
      {"SHA256:short", ST_TYPE_FINGERPRINT},
      {"[unterminated", ST_TYPE_GLOB},
      {"://example.com", ST_TYPE_URL},
      {"1http://example.com", ST_TYPE_URL},
      {"ht*tp://example.com", ST_TYPE_URL},
      {"fe80::1%", ST_TYPE_IPV6},
      {"fe80::1%eth0%bad", ST_TYPE_IPV6},
      {"fe80::1%eth/0", ST_TYPE_IPV6},
  };
  for (size_t i = 0; i < sizeof(rejection_cases) / sizeof(rejection_cases[0]);
       i++)
    ASSERT(st_classify_token(rejection_cases[i].token) !=
           rejection_cases[i].forbidden);
  return 1;
}

static int generated_token_is(const char *token, st_token_type_t expected) {
  st_token_array_t normalized = {0};
  if (st_classify_token(token) != expected ||
      test_st_classify(token, &normalized) != ST_OK || normalized.count != 1 ||
      normalized.tokens[0].type != expected ||
      strcmp(normalized.tokens[0].text, token) != 0) {
    st_free_token_array(&normalized);
    return 0;
  }
  st_free_token_array(&normalized);
  return 1;
}

/* Grammar-driven representatives complement the fixed regression matrix.
 * Invalid mutations assert rejection from the target family without assuming
 * which other lattice element receives the malformed text. */
static int test_generated_classification_boundaries(void) {
  static const char *size_suffixes[] = {"K",   "M",     "G", "KiB", "MiB",
                                        "GiB", "bytes", "B", "TB"};
  static const char *duration_suffixes[] = {"ns", "us", "ms", "s",
                                            "m",  "h",  "d",  "w"};
  char token[160];
  for (size_t i = 0; i < sizeof(size_suffixes) / sizeof(size_suffixes[0]);
       i++) {
    ASSERT(snprintf(token, sizeof(token), "%zu.5%s", i + 1, size_suffixes[i]) >
           0);
    ASSERT(generated_token_is(token, ST_TYPE_SIZE));
    ASSERT(snprintf(token, sizeof(token), "%zu..5%s", i + 1, size_suffixes[i]) >
           0);
    ASSERT(st_classify_token(token) != ST_TYPE_SIZE);
  }
  for (size_t i = 0;
       i < sizeof(duration_suffixes) / sizeof(duration_suffixes[0]); i++) {
    ASSERT(snprintf(token, sizeof(token), "-%zu.25%s", i + 1,
                    duration_suffixes[i]) > 0);
    ASSERT(generated_token_is(token, ST_TYPE_DURATION));
    ASSERT(snprintf(token, sizeof(token), "-%zu..25%s", i + 1,
                    duration_suffixes[i]) > 0);
    ASSERT(st_classify_token(token) != ST_TYPE_DURATION);
  }

  for (unsigned octet = 0; octet <= 255; octet += 51) {
    ASSERT(snprintf(token, sizeof(token), "192.0.2.%u", octet) > 0);
    ASSERT(generated_token_is(token, ST_TYPE_IPV4));
  }
  ASSERT(st_classify_token("192.0.2.256") != ST_TYPE_IPV4);

  static const char *uuids[] = {
      "550e8400-e29b-41d4-a716-446655440000",
      "550e8400-e29b-51d4-a716-446655440000",
  };
  for (size_t i = 0; i < sizeof(uuids) / sizeof(uuids[0]); i++)
    ASSERT(generated_token_is(uuids[i], ST_TYPE_UUID));
  ASSERT(st_classify_token("550e8400-e29b-41d4-a716-44665544000g") !=
         ST_TYPE_UUID);

  static const size_t sha_lengths[] = {7, 40, 64};
  for (size_t i = 0; i < sizeof(sha_lengths) / sizeof(sha_lengths[0]); i++) {
    memset(token, 'a', sha_lengths[i]);
    token[sha_lengths[i]] = '\0';
    ASSERT(generated_token_is(token, ST_TYPE_SHA));
    token[sha_lengths[i] - 1] = 'g';
    ASSERT(st_classify_token(token) != ST_TYPE_SHA);
  }

  static const char *timestamps[] = {"2024-02-29", "00:00:00", "23:59:59",
                                     "2025-12-31T23:59:59Z",
                                     "2025-01-01T00:00:00+02:30"};
  for (size_t i = 0; i < sizeof(timestamps) / sizeof(timestamps[0]); i++)
    ASSERT(generated_token_is(timestamps[i], ST_TYPE_TIMESTAMP));
  static const char *bad_timestamps[] = {"2025-02-29", "2025-13-01", "24:00:00",
                                         "23:60:00", "2025-01-01T00:00:60Z"};
  for (size_t i = 0; i < sizeof(bad_timestamps) / sizeof(bad_timestamps[0]);
       i++)
    ASSERT(st_classify_token(bad_timestamps[i]) != ST_TYPE_TIMESTAMP);
  return 1;
}

/* --- JOIN TABLE --- */

static int test_type_lattice(void) {
  static const struct {
    st_token_type_t a;
    st_token_type_t b;
    st_token_type_t join;
    bool a_le_b;
    bool b_le_a;
  } semantic_cases[] = {
      {ST_TYPE_HEXHASH, ST_TYPE_NUMBER, ST_TYPE_VALUE, false, false},
      {ST_TYPE_NUMBER, ST_TYPE_WORD, ST_TYPE_VALUE, false, false},
      {ST_TYPE_ABS_PATH, ST_TYPE_REL_PATH, ST_TYPE_PATH, false, false},
      {ST_TYPE_ABS_PATH, ST_TYPE_FILENAME, ST_TYPE_PATH, false, false},
      {ST_TYPE_REL_PATH, ST_TYPE_FILENAME, ST_TYPE_REL_PATH, false, true},
      {ST_TYPE_QUOTED, ST_TYPE_QUOTED_SPACE, ST_TYPE_QUOTED_SPACE, true, false},
      {ST_TYPE_NUMBER, ST_TYPE_ABS_PATH, ST_TYPE_ANY, false, false},
      {ST_TYPE_WORD, ST_TYPE_URL, ST_TYPE_ANY, false, false},
      {ST_TYPE_VALUE, ST_TYPE_PATH, ST_TYPE_ANY, false, false},
      {ST_TYPE_SHA, ST_TYPE_HEXHASH, ST_TYPE_HEXHASH, true, false},
      {ST_TYPE_BRANCH, ST_TYPE_IMAGE, ST_TYPE_VALUE, false, false},
      {ST_TYPE_PKG, ST_TYPE_USER, ST_TYPE_VALUE, false, false},
      {ST_TYPE_SHA, ST_TYPE_BRANCH, ST_TYPE_VALUE, false, false},
      {ST_TYPE_FINGERPRINT, ST_TYPE_IMAGE, ST_TYPE_VALUE, false, false},
      {ST_TYPE_BRANCH, ST_TYPE_VALUE, ST_TYPE_VALUE, true, false},
      {ST_TYPE_IMAGE, ST_TYPE_VALUE, ST_TYPE_VALUE, true, false},
      {ST_TYPE_PKG, ST_TYPE_VALUE, ST_TYPE_VALUE, true, false},
      {ST_TYPE_USER, ST_TYPE_VALUE, ST_TYPE_VALUE, true, false},
      {ST_TYPE_FINGERPRINT, ST_TYPE_VALUE, ST_TYPE_VALUE, true, false},
  };

  for (int t = 0; t < ST_TYPE_COUNT; t++)
    ASSERT(st_type_symbol[t] != NULL);

  /* Pin the intended hierarchy as well as checking its algebra below. */
  for (size_t i = 0; i < sizeof(semantic_cases) / sizeof(semantic_cases[0]);
       i++) {
    const st_token_type_t a = semantic_cases[i].a;
    const st_token_type_t b = semantic_cases[i].b;
    ASSERT(st_join(a, b) == semantic_cases[i].join);
    ASSERT(st_is_compatible(a, b) == semantic_cases[i].a_le_b);
    ASSERT(st_is_compatible(b, a) == semantic_cases[i].b_le_a);
  }

  for (int ai = 0; ai < ST_TYPE_COUNT; ai++) {
    const st_token_type_t a = (st_token_type_t)ai;
    ASSERT(st_join(a, a) == a);
    ASSERT(st_join(a, ST_TYPE_ANY) == ST_TYPE_ANY);
    ASSERT(st_is_compatible(a, a));
    ASSERT(st_is_compatible(ST_TYPE_LITERAL, a));
    ASSERT(st_is_compatible(a, ST_TYPE_ANY));

    for (int bi = 0; bi < ST_TYPE_COUNT; bi++) {
      const st_token_type_t b = (st_token_type_t)bi;
      const st_token_type_t joined = st_join(a, b);
      ASSERT((unsigned)joined < ST_TYPE_COUNT);
      ASSERT(joined == st_join(b, a));

      /* Compatibility is the order induced by join. */
      ASSERT(st_is_compatible(a, b) == (joined == b));
      ASSERT(st_is_compatible(a, joined));
      ASSERT(st_is_compatible(b, joined));

      for (int ci = 0; ci < ST_TYPE_COUNT; ci++) {
        const st_token_type_t c = (st_token_type_t)ci;
        ASSERT(st_join(joined, c) == st_join(a, st_join(b, c)));
        if (st_is_compatible(a, c) && st_is_compatible(b, c))
          ASSERT(st_is_compatible(joined, c));
        if (st_is_compatible(a, b) && st_is_compatible(b, c))
          ASSERT(st_is_compatible(a, c));
      }
    }
  }
  return 1;
}

static int test_classifier_adversarial_branch_matrix(void) {
  static const char *const tokens[] = {
      "0000-01-01",
      "2023-02-29",
      "2024-02-30",
      "2024-13-01",
      "2024-00-01",
      "2024-01-00",
      "2024-01-32",
      "2000-02-29",
      "1900-02-29",
      "2100-02-29",
      "2024-01-01T24:00:00",
      "2024-01-01T23:60:00",
      "2024-01-01T23:59:60",
      "2024-01-01t23:59:59z",
      "2024-01-01 23:59:59+2359",
      "2024-01-01T23:59:59-24:00",
      "2024-01-01T23:59:59+12:60",
      "2024-01-01T23:59:59UTC",
      "24:00:00",
      "23:60:00",
      "23:59:60",
      "ab:59:59",
      "${A",
      "${A}",
      "${_A1}",
      "${A-B}",
      "$1A",
      "$A-B",
      "",
      "-branch",
      "/branch",
      ".branch",
      "feature/",
      "feature//x",
      "feature/x_",
      "feature/x.y",
      "feature/x!y",
      "singlebranch",
      "User:tag",
      "A1:tag",
      "name::tag",
      "name@md5:value",
      "name@sha256:bad",
      ("name@sha256:"
       "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"),
      "name without tag",
      "-image:tag",
      ".image:tag",
      "@",
      "@scope",
      "@scope/",
      "@scope/na!me",
      "@scope/name@",
      "@scope/name@1!",
      "name@",
      "name@alpha",
      "name@1!",
      "bad!name@1",
      "name@^1",
      "name@~1",
      "name@<1",
      "name@>1",
      "name@=1",
      "@scope/name@^1",
      "@scope/name@~1",
      "@scope/name@<1",
      "@scope/name@>1",
      "@scope/name@=1",
      "abcdefghijklmnopqrstuvwxyzabcdefg",
      "Baduser",
      "user!name",
      "SHA256:short",
      "SHA256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!",
      "zz:2b:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d",
      "1a:zz:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d",
      "1a-2b:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d",
      "-*.txt",
      "/*.txt",
      "[abc",
      "a*|b",
      "a?b",
      "a[b]c",
      ":group",
      "user:",
      "user:group:extra",
      "user.name:group",
      "user/group:group",
      "User-name:group",
      "unknown:group",
      "root:GROUP",
      "root:gr!oup",
      "128",
      "399",
      "0123",
      "1234",
      "2014",
      "8888",
      "7777",
  };
  for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++) {
    st_token_type_t type = st_classify_token(tokens[i]);
    ASSERT((unsigned)type < ST_TYPE_COUNT);
  }
  return 1;
}

static int test_contextual_adversarial_branch_matrix(void) {
  static const char *const commands[] = {
      "kill 0",       "kill 1",        "kill 31",        "kill 32",
      "kill -1",      "-s 9",          "-s 0",           "grep plain",
      "grep a+",      "sed s/a/b/",    "awk [a]",        "perl a?",
      "egrep a|b",    "fgrep a*",      "rg a$",          "ag a^",
      "cmd -e a+",    "cmd -E a+",     "cmd -P a+",      "cmd -pe a+",
      "cmd -ne a+",   "cmd -pie a+",   "cmd -nle a+",    "cmd -F a+",
      "A=1 command",  "A-B=1 command", "=value command", "--flag value",
      "--flag=value", "--flag=",       "--=value",
  };
  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    st_token_array_t typed = {0};
    ASSERT(test_st_classify(commands[i], &typed) == ST_OK);
    st_free_token_array(&typed);
  }
  return 1;
}

static int test_normalization_matrix(void) {
  static const struct {
    const char *command;
    const char *text;
    st_token_type_t types[16];
    size_t count;
  } cases[] = {
      {"", "", {ST_TYPE_LITERAL}, 0},
      {"ls -la", "ls\t-la", {ST_TYPE_LITERAL, ST_TYPE_SHORTOPT}, 2},
      {"cat /etc/passwd",
       "cat\t/etc/passwd",
       {ST_TYPE_LITERAL, ST_TYPE_ABS_PATH},
       2},
      {"head -n 42",
       "head\t-n\t42",
       {ST_TYPE_LITERAL, ST_TYPE_SHORTOPT, ST_TYPE_NUMBER},
       3},
      {"git show deadbeef12345678",
       "git\tshow\tdeadbeef12345678",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_SHA},
       3},
      {"cat file.txt | grep ERROR",
       "cat\tfile.txt\t|\tgrep\tERROR",
       {ST_TYPE_LITERAL, ST_TYPE_FILENAME, ST_TYPE_LITERAL, ST_TYPE_LITERAL,
        ST_TYPE_LITERAL},
       5},
      {"one&&two || three; four & five",
       "one&&two\t||\tthree;\tfour\t&\tfive",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_LITERAL,
        ST_TYPE_LITERAL, ST_TYPE_LITERAL},
       6},
      {";;;;;;;;", ";;;;;;;;", {ST_TYPE_LITERAL}, 1},
      {"ls > /tmp/out.txt",
       "ls\t>\t/tmp/out.txt",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_ABS_PATH},
       3},
      {"sed 's/foo/bar/g'",
       "sed\ts/foo/bar/g",
       {ST_TYPE_LITERAL, ST_TYPE_REGEX},
       2},
      {"echo '[hello]'", "echo\t[hello]", {ST_TYPE_LITERAL, ST_TYPE_GLOB}, 2},
      {"echo \"hello world\"",
       "echo\thello world",
       {ST_TYPE_LITERAL, ST_TYPE_QUOTED_SPACE},
       2},
      {"export PATH=/usr/bin",
       "export\tPATH=/usr/bin",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL},
       2},
      {"tool --output=file.txt",
       "tool\t--output=file.txt",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL},
       2},
      {"tool --output=",
       "tool\t--output=",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL},
       2},
      {"export EMPTY=",
       "export\tEMPTY=",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL},
       2},
      {"echo sha256", "echo\tsha256", {ST_TYPE_LITERAL, ST_TYPE_HASH_ALGO}, 2},
      {"docker pull ghcr.io/org/app:v1",
       "docker\tpull\tghcr.io/org/app:v1",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_IMAGE},
       3},
      {"docker pull nginx:latest",
       "docker\tpull\tnginx:latest",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_IMAGE},
       3},
      {"npm install @babel/core",
       "npm\tinstall\t@babel/core",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_PKG},
       3},
      {"git checkout feature/login",
       "git\tcheckout\tfeature/login",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_BRANCH},
       3},
      {"echo deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
       "echo\tdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
       {ST_TYPE_LITERAL, ST_TYPE_SHA},
       2},
      {"sleep 100ms", "sleep\t100ms", {ST_TYPE_LITERAL, ST_TYPE_DURATION}, 2},
      {"kill SIGTERM", "kill\tSIGTERM", {ST_TYPE_LITERAL, ST_TYPE_SIGNAL}, 2},
      {"kill -s 9",
       "kill\t-s\t9",
       {ST_TYPE_LITERAL, ST_TYPE_SHORTOPT, ST_TYPE_SIGNAL},
       3},
      {"seq 0-100", "seq\t0-100", {ST_TYPE_LITERAL, ST_TYPE_RANGE}, 2},
      {"chmod 0644 file",
       "chmod\t0644\tfile",
       {ST_TYPE_LITERAL, ST_TYPE_PERM_OCTAL, ST_TYPE_LITERAL},
       3},
      {"echo a\\ b", "echo\ta b", {ST_TYPE_LITERAL, ST_TYPE_QUOTED_SPACE}, 2},
      {"printf '' \"\" x",
       "printf\t\t\tx",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_LITERAL},
       4},
      {"a||b&&c>>out<in;d&e", "a||b&&c>>out<in;d&e", {ST_TYPE_LITERAL}, 1},
      {"cmd 2>err 2>>log &>all &>>append >&fd",
       "cmd\t2>err\t2>>log\t&>all\t&>>append\t>&fd",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_LITERAL,
        ST_TYPE_LITERAL, ST_TYPE_LITERAL},
       6},
      {"cmd 2>&1 3>&- 4<&- <&0 >&10 >>&9 12>>log 1>out",
       "cmd\t2>&1\t3>&-\t4<&-\t<&0\t>&10\t>>&9\t12>>log\t1>out",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_LITERAL,
        ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_LITERAL, ST_TYPE_LITERAL,
        ST_TYPE_LITERAL},
       9},
      {"echo 'unterminated",
       "echo\tunterminated",
       {ST_TYPE_LITERAL, ST_TYPE_LITERAL},
       2},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_token_array_t typed = {0};
    ASSERT(test_st_classify(cases[i].command, &typed) == ST_OK);
    if (typed.count != cases[i].count) {
      printf("  normalization case '%s': got %zu tokens, expected %zu\n",
             cases[i].command, typed.count, cases[i].count);
      st_free_token_array(&typed);
      return 0;
    }
    const char *expected_text = cases[i].text;
    for (size_t j = 0; j < typed.count; j++) {
      size_t expected_length = strcspn(expected_text, "\t");
      ASSERT(typed.tokens[j].text != NULL);
      ASSERT(strlen(typed.tokens[j].text) == expected_length);
      ASSERT(memcmp(typed.tokens[j].text, expected_text, expected_length) == 0);
      ASSERT(typed.tokens[j].type == cases[i].types[j]);
      expected_text += expected_length;
      if (*expected_text == '\t')
        expected_text++;
    }
    ASSERT(*expected_text == '\0');

    st_free_token_array(&typed);
  }
  return 1;
}

static int test_normalization_boundaries(void) {
  st_token_array_t typed = {(st_token_t *)1, 99};
  ASSERT(test_st_classify(NULL, &typed) == ST_ERR_INVALID);
  ASSERT(typed.tokens == NULL && typed.count == 0);
  ASSERT(test_st_classify("echo ok", NULL) == ST_ERR_INVALID);

  /* Shelltype never re-tokenizes argv elements, including operator-looking
   * text. */
  char operators[129];
  for (size_t i = 0; i < sizeof(operators) - 1; i++)
    operators[i] = i % 2 == 0 ? '|' : '&';
  operators[sizeof(operators) - 1] = '\0';
  ASSERT(test_st_classify(operators, &typed) == ST_OK);
  ASSERT(typed.count == 1);
  ASSERT(typed.tokens[0].type == ST_TYPE_LITERAL);
  ASSERT(strcmp(typed.tokens[0].text, operators) == 0);
  st_free_token_array(&typed);

  ASSERT(test_st_classify("#literal | ;", &typed) == ST_OK);
  ASSERT(typed.count == 3);
  ASSERT(strcmp(typed.tokens[0].text, "#literal") == 0);
  ASSERT(strcmp(typed.tokens[1].text, "|") == 0);
  ASSERT(strcmp(typed.tokens[2].text, ";") == 0);
  st_free_token_array(&typed);

  char many[(ST_MAX_CMD_TOKENS + 1) * 2 + 1];
  size_t used = 0;
  for (size_t i = 0; i < ST_MAX_CMD_TOKENS + 1; i++) {
    many[used++] = 'x';
    many[used++] = ' ';
  }
  many[used - 1] = '\0';
  ASSERT(test_st_classify(many, &typed) == ST_ERR_LIMIT);
  ASSERT(typed.tokens == NULL && typed.count == 0);

  char long_token[ST_MAX_TOKEN_LEN + 2];
  memset(long_token, 'x', sizeof(long_token) - 1);
  long_token[sizeof(long_token) - 1] = '\0';
  char long_command[sizeof(long_token) + 6];
  snprintf(long_command, sizeof(long_command), "echo %s", long_token);
  /* Expansion callbacks may legitimately produce long scalar values; the
   * token-length constant constrains classification helpers, not input. */
  ASSERT(test_st_classify(long_command, &typed) == ST_OK);
  ASSERT(typed.count == 2 &&
         strlen(typed.tokens[1].text) == ST_MAX_TOKEN_LEN + 1);
  st_free_token_array(&typed);
  return 1;
}

static int test_normalization_allocation_failures(void) {
  static const char input[] = "grep 'a.*b' 2>&1 --output=log EMPTY= kill -s 9";
  st_token_array_t probe = {0};
  st_test_alloc_reset();
  ASSERT(test_st_classify(input, &probe) == ST_OK);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);
  st_free_token_array(&probe);

  bool observed = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_token_array_t typed = {(st_token_t *)1, 99};
    st_test_alloc_fail_at(fail_at);
    st_error_t err = test_st_classify(input, &typed);
    st_test_alloc_reset();
    if (err == ST_ERR_MEMORY) {
      observed = true;
      ASSERT(typed.tokens == NULL && typed.count == 0);
    } else {
      ASSERT(err == ST_OK);
      st_free_token_array(&typed);
    }
  }
  ASSERT(observed);

  return 1;
}

static int test_public_helper_matrix(void) {
  static const struct {
    st_error_t error;
    const char *name;
  } errors[] = {{ST_OK, "ok"},
                {ST_ERR_INVALID, "invalid"},
                {ST_ERR_MEMORY, "memory"},
                {ST_ERR_IO, "io"},
                {ST_ERR_FAILED, "failed"},
                {ST_ERR_FORMAT, "format"},
                {ST_ERR_LIMIT, "limit"},
                {(st_error_t)1, "unknown"}};
  for (size_t i = 0; i < sizeof(errors) / sizeof(errors[0]); i++)
    ASSERT(strcmp(st_error_string(errors[i].error), errors[i].name) == 0);

  static const struct {
    const char *input;
    const char *expected;
  } extensions[] = {{"/etc/app.cfg", ".cfg"}, {"archive.tar.gz", ".gz"},
                    {".profile", NULL},       {"dir/.profile", NULL},
                    {"dir/name.", NULL},      {"dir/name.tar.gz", ".gz"},
                    {"dir/name", NULL},       {"app", NULL},
                    {"app.", NULL},           {NULL, NULL}},
    suffixes[] = {{"10MiB", "MiB"}, {"-2.5G", "G"}, {"42", NULL}, {".5G", "G"},
                  {"-", NULL},      {"10", NULL},   {NULL, NULL}};
  for (size_t i = 0; i < sizeof(extensions) / sizeof(extensions[0]); i++) {
    const char *actual = st_path_extension(extensions[i].input);
    ASSERT((!actual && !extensions[i].expected) ||
           (actual && extensions[i].expected &&
            strcmp(actual, extensions[i].expected) == 0));
  }
  for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
    const char *actual = st_size_suffix(suffixes[i].input);
    ASSERT((!actual && !suffixes[i].expected) ||
           (actual && suffixes[i].expected &&
            strcmp(actual, suffixes[i].expected) == 0));
  }
  return 1;
}

static int test_netargv_contract(void) {
  st_token_array_t typed = {(st_token_t *)1, 99};
  ASSERT(st_classify("6:printf,9:two words,0:,1:>,", &typed) == ST_OK);
  ASSERT(typed.count == 4);
  ASSERT(strcmp(typed.tokens[0].text, "printf") == 0);
  ASSERT(strcmp(typed.tokens[1].text, "two words") == 0);
  ASSERT(strcmp(typed.tokens[2].text, "") == 0);
  ASSERT(strcmp(typed.tokens[3].text, ">") == 0);
  st_free_token_array(&typed);

  static const char *const malformed[] = {
      "01:x,", "-1:x,", "+1:x,", "1x,", "1:x", "2:x,", "0:;", "x",
  };
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
    typed.tokens = (st_token_t *)1;
    typed.count = 99;
    ASSERT(st_classify(malformed[i], &typed) == ST_ERR_FORMAT);
    ASSERT(typed.tokens == NULL && typed.count == 0);
  }
  ASSERT(st_classify("", &typed) == ST_OK);
  ASSERT(typed.tokens == NULL && typed.count == 0);

  ASSERT(st_classify("999999999999999999999999999999999999:x,", &typed) ==
         ST_ERR_LIMIT);
  ASSERT(st_classify("1:x,x", &typed) == ST_ERR_FORMAT);

  char too_many[ST_MAX_CMD_TOKENS * 4 + 2] = {0};
  for (size_t i = 0; i <= ST_MAX_CMD_TOKENS; i++)
    strcat(too_many, "0:,");
  ASSERT(st_classify(too_many, &typed) == ST_ERR_LIMIT);

  char split_overflow[1024] = {0};
  for (size_t i = 0; i < ST_MAX_CMD_TOKENS / 2 + 1; i++)
    strcat(split_overflow, "3:A=1,");
  ASSERT(st_classify(split_overflow, &typed) == ST_OK);
  ASSERT(typed.count == ST_MAX_CMD_TOKENS / 2 + 1);
  st_free_token_array(&typed);
  return 1;
}

static int test_netpattern_cpl_contract(void) {
  char *roundtrip = NULL;
  static const struct {
    const char *cpl;
    const char *canonical_cpl;
  } cases[] = {
      {"printf \"two words\" \"\" #n \"#n\" \"*\"",
       "printf \"two words\" \"\" #n \"#n\" \"*\""},
      {"echo \"outer \\\"inner\\\" text\"",
       "echo \"outer \\\"inner\\\" text\""},
      {"echo \"line\\nfeed\" \"\\u20ac\"", "echo \"line\\nfeed\" €"},
      {"echo \"\\b\\f\\r\\t\\u007f\"", "echo \"\\b\\f\\r\\t\\u007f\""},
      {"echo \"\\u00a2\" \"\\u20ac\" \"\\ud83d\\ude00\"", "echo ¢ € 😀"},
      {"echo \"quote: \\\" slash: \\\\\"", "echo \"quote: \\\" slash: \\\\\""},
      {"echo \"#unknown\" \"#CRC16:\"", "echo \"#unknown\" \"#CRC16:\""},
      {"dd bs={#size.MiB}", "dd bs={#size.MiB}"},
      {"echo \"{literal}\"", "echo \"{literal}\""},
      {"id #uuid.4", "id #uuid.v4"},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char *netpattern = NULL;
    char *rendered = NULL;
    ASSERT(st_netpattern_from_cpl(cases[i].cpl, &netpattern) == ST_OK);
    ASSERT(netpattern != NULL);
    ASSERT(st_netpattern_to_cpl(netpattern, &rendered) == ST_OK);
    ASSERT(rendered != NULL && strcmp(rendered, cases[i].canonical_cpl) == 0);
    char *again = NULL;
    ASSERT(st_netpattern_from_cpl(rendered, &again) == ST_OK);
    ASSERT(strcmp(netpattern, again) == 0);
    free(again);
    free(rendered);
    free(netpattern);
  }

  char *compare_a = NULL, *compare_b = NULL, *compare_typed = NULL;
  char *compare_literal_star = NULL;
  ASSERT(st_netpattern_from_cpl("a", &compare_a) == ST_OK);
  ASSERT(st_netpattern_from_cpl("bb", &compare_b) == ST_OK);
  ASSERT(st_netpattern_from_cpl("*", &compare_typed) == ST_OK);
  ASSERT(st_netpattern_from_cpl("\"*\"", &compare_literal_star) == ST_OK);
  ASSERT(st_netpattern_compare(NULL, NULL) == 0);
  ASSERT(st_netpattern_compare(compare_a, NULL) > 0);
  ASSERT(st_netpattern_compare(NULL, compare_a) < 0);
  ASSERT(st_netpattern_compare(compare_a, compare_a) == 0);
  ASSERT(st_netpattern_compare(compare_a, compare_b) < 0);
  ASSERT(st_netpattern_compare(compare_b, compare_a) > 0);
  ASSERT(st_netpattern_compare(compare_literal_star, compare_typed) < 0);
  ASSERT(st_netpattern_compare("malformed-a", "malformed-b") < 0);
  free(compare_literal_star);
  free(compare_typed);
  free(compare_b);
  free(compare_a);
  char *compound = NULL;
  char *widened = NULL;
  char *widened_cpl = NULL;
  ASSERT(st_netpattern_from_cpl("dd bs={#size.MiB}", &compound) == ST_OK);
  ASSERT(st_netpattern_apply_type_at(compound, 1, ST_TYPE_ANY, &widened) ==
         ST_OK);
  ASSERT(st_netpattern_to_cpl(widened, &widened_cpl) == ST_OK);
  ASSERT(strcmp(widened_cpl, "dd bs={*}") == 0);
  free(widened_cpl);
  free(widened);
  free(compound);

  st_token_t compound_token = {
      .text = "pre{#path}.log",
      .type = ST_TYPE_LITERAL,
      .compound = true,
      .capture_type = ST_TYPE_PATH,
      .prefix = "pre",
      .capture = "#path",
      .suffix = ".log",
  };
  st_token_t invalid_compound_token = compound_token;
  invalid_compound_token.prefix = NULL;
  ASSERT(st_netpattern_encode(&invalid_compound_token, 1, &roundtrip) ==
         ST_ERR_INVALID);
  invalid_compound_token = compound_token;
  invalid_compound_token.capture = NULL;
  ASSERT(st_netpattern_encode(&invalid_compound_token, 1, &roundtrip) ==
         ST_ERR_INVALID);
  invalid_compound_token = compound_token;
  invalid_compound_token.suffix = NULL;
  ASSERT(st_netpattern_encode(&invalid_compound_token, 1, &roundtrip) ==
         ST_ERR_INVALID);
  invalid_compound_token = compound_token;
  invalid_compound_token.capture_type = ST_TYPE_LITERAL;
  ASSERT(st_netpattern_encode(&invalid_compound_token, 1, &roundtrip) ==
         ST_ERR_INVALID);
  invalid_compound_token = compound_token;
  invalid_compound_token.capture_type = ST_TYPE_COUNT;
  ASSERT(st_netpattern_encode(&invalid_compound_token, 1, &roundtrip) ==
         ST_ERR_INVALID);
  invalid_compound_token = compound_token;
  invalid_compound_token.prefix = "";
  invalid_compound_token.suffix = "";
  ASSERT(st_netpattern_encode(&invalid_compound_token, 1, &roundtrip) ==
         ST_ERR_INVALID);
  invalid_compound_token = compound_token;
  invalid_compound_token.capture_type = ST_TYPE_NUMBER;
  ASSERT(st_netpattern_encode(&invalid_compound_token, 1, &roundtrip) ==
         ST_ERR_FORMAT);

  for (size_t fail_at = 1; fail_at <= 8; fail_at++) {
    char *failed = (char *)1;
    st_test_alloc_fail_at(fail_at);
    st_error_t error = st_netpattern_encode(&compound_token, 1, &failed);
    st_test_alloc_reset();
    ASSERT(error == ST_ERR_MEMORY || error == ST_OK);
    if (error == ST_ERR_MEMORY)
      ASSERT(failed == NULL);
    free(failed);
  }

  st_token_t spaced_affix = compound_token;
  spaced_affix.prefix = "bad prefix";
  ASSERT(st_netpattern_encode(&spaced_affix, 1, &roundtrip) == ST_OK);
  ASSERT(st_netpattern_to_cpl(roundtrip, &widened_cpl) == ST_ERR_INVALID);
  free(roundtrip);
  spaced_affix = compound_token;
  spaced_affix.suffix = "bad suffix";
  ASSERT(st_netpattern_encode(&spaced_affix, 1, &roundtrip) == ST_OK);
  ASSERT(st_netpattern_to_cpl(roundtrip, &widened_cpl) == ST_ERR_INVALID);
  free(roundtrip);
  static const char *const invalid[] = {
      NULL,
      "",
      "   ",
      "echo \"unterminated",
      "echo pre\"mid\"",
      "echo \"\\x41\"",
      "echo \"\\u0000\"",
      "echo \"\\ud800\"",
      "echo \"\\udc00\"",
      "echo \"\\ud800x\"",
      "echo \"\\ud800\\u0000\"",
      "echo \"\\u0x00\"",
      "echo \"\\u123\"",
      "echo \"x\"tail",
      "echo \\\\value",
      "echo bare\\value",
      "echo bare\"value",
      "dd {#path}",
      "dd pre{#path}{#n}",
      "dd pre{#unknown}",
      "echo \"line\nfeed\"",
      "echo bare\tvalue",
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    char *netpattern = (char *)1;
    ASSERT(st_netpattern_from_cpl(invalid[i], &netpattern) == ST_ERR_INVALID);
    ASSERT(netpattern == NULL);
  }
  st_token_array_t decoded = {0};
  ASSERT(st_netpattern_decode("9:1:T,2:#n,,", &decoded) == ST_OK);
  st_free_token_array(&decoded);
  ASSERT(st_netpattern_decode("09:1:T,2:#n,,", &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode("14:1:T,7:#uuid.4,,", &decoded) == ST_ERR_FORMAT);

  ASSERT(st_netpattern_decode(NULL, &decoded) == ST_ERR_INVALID);
  ASSERT(st_netpattern_decode("9:1:X,2:#n,,", &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode("9:1:T,2:no,,", &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode("8:1:L,1:x,", &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode("8:1:L,1:x,,junk", &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode("x", &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode("0:,", &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode("999999999999999999999999999999999999:x,",
                              &decoded) == ST_ERR_LIMIT);
  ASSERT(st_netpattern_decode("08:1:L,1:x,,", &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode("9:01:L,1:x,,", &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode("9:1:L,01:x,,", &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode("9:1:T,1:*, ,", &decoded) == ST_ERR_FORMAT);

  static const struct {
    const char *tags;
    const char *values[4];
  } invalid_compounds[] = {
      {"L", {"prefix"}},
      {"LL", {"prefix", "suffix"}},
      {"TT", {"*", "#n"}},
      {"LT", {"", "*"}},
      {"LT", {"prefix", "#unknown"}},
      {"LTT", {"prefix", "*", "#n"}},
      {"TLT", {"*", "suffix", "#n"}},
      {"LTLT", {"prefix", "*", "suffix", "#n"}},
      {"XT", {"prefix", "*"}},
  };
  for (size_t i = 0;
       i < sizeof(invalid_compounds) / sizeof(invalid_compounds[0]); i++) {
    char *malformed = test_compound_pattern(invalid_compounds[i].tags,
                                            invalid_compounds[i].values,
                                            strlen(invalid_compounds[i].tags));
    ASSERT(malformed != NULL);
    decoded.tokens = (st_token_t *)1;
    decoded.count = 99;
    ASSERT(st_netpattern_decode(malformed, &decoded) == ST_ERR_FORMAT);
    ASSERT(decoded.tokens == NULL && decoded.count == 0);
    free(malformed);
  }

  static const struct {
    const char *tags;
    const char *values[3];
  } valid_compounds[] = {
      {"LT", {"prefix", "*"}},
      {"TL", {"#n", "suffix"}},
      {"LTL", {"pre", "#path", ".log"}},
  };
  for (size_t i = 0; i < sizeof(valid_compounds) / sizeof(valid_compounds[0]);
       i++) {
    char *nested = test_compound_pattern(valid_compounds[i].tags,
                                         valid_compounds[i].values,
                                         strlen(valid_compounds[i].tags));
    ASSERT(nested != NULL);
    ASSERT(st_netpattern_decode(nested, &decoded) == ST_OK);
    ASSERT(decoded.count == 1 && decoded.tokens[0].compound);
    st_free_token_array(&decoded);
    free(nested);
  }
  ASSERT(st_netpattern_to_cpl(NULL, &roundtrip) == ST_ERR_INVALID);
  ASSERT(st_netpattern_to_cpl("x", &roundtrip) == ST_ERR_FORMAT);

  st_token_t invalid_token = {.text = NULL, .type = ST_TYPE_LITERAL};
  ASSERT(st_netpattern_encode(NULL, 1, &roundtrip) == ST_ERR_INVALID);
  ASSERT(st_netpattern_encode(&invalid_token, 1, &roundtrip) == ST_ERR_INVALID);
  invalid_token.text = "#n";
  invalid_token.type = ST_TYPE_PATH;
  ASSERT(st_netpattern_encode(&invalid_token, 1, &roundtrip) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_encode(&invalid_token, ST_MAX_CMD_TOKENS + 1,
                              &roundtrip) == ST_ERR_INVALID);

  char too_many_records[2048] = {0};
  for (size_t i = 0; i <= ST_MAX_CMD_TOKENS; i++)
    strcat(too_many_records, "7:1:L,0:,,");
  ASSERT(st_netpattern_decode(too_many_records, &decoded) == ST_ERR_LIMIT);

  char too_many_words[ST_MAX_CMD_TOKENS * 2 + 2] = {0};
  for (size_t i = 0; i <= ST_MAX_CMD_TOKENS; i++)
    strcat(too_many_words, i == 0 ? "x" : " x");
  ASSERT(st_netpattern_from_cpl(too_many_words, &roundtrip) == ST_ERR_INVALID);

  char controls[ST_MAX_TOKEN_LEN];
  memset(controls, 1, sizeof(controls) - 1);
  controls[sizeof(controls) - 1] = '\0';
  st_token_t expansive_tokens[4];
  for (size_t i = 0; i < 4; i++)
    expansive_tokens[i] =
        (st_token_t){.text = controls, .type = ST_TYPE_LITERAL};
  char *expansive = NULL, *expansive_cpl = NULL;
  ASSERT(st_netpattern_encode(expansive_tokens, 4, &expansive) == ST_OK);
  ASSERT(st_netpattern_to_cpl(expansive, &expansive_cpl) == ST_OK);
  ASSERT(strlen(expansive_cpl) > 1024);
  ASSERT(st_netpattern_from_cpl(expansive_cpl, &roundtrip) == ST_OK);
  ASSERT(strcmp(expansive, roundtrip) == 0);
  free(roundtrip);
  free(expansive_cpl);
  free(expansive);

  /* Every codec stage must clear outputs and release partial allocations. */
  char *canonical = NULL;
  ASSERT(st_netpattern_from_cpl("echo \"two words\" #n", &canonical) == ST_OK);
  for (size_t fail_at = 1; fail_at <= 8; fail_at++) {
    char *output = (char *)1;
    st_test_alloc_fail_at(fail_at);
    st_error_t error = st_netpattern_from_cpl("echo \"two words\" #n", &output);
    st_test_alloc_reset();
    ASSERT(error == ST_ERR_MEMORY || error == ST_OK);
    if (error == ST_ERR_MEMORY)
      ASSERT(output == NULL);
    free(output);

    st_token_array_t failed = {(st_token_t *)1, 99};
    st_test_alloc_fail_at(fail_at);
    error = st_netpattern_decode(canonical, &failed);
    st_test_alloc_reset();
    ASSERT(error == ST_ERR_MEMORY || error == ST_OK);
    if (error == ST_ERR_MEMORY)
      ASSERT(failed.tokens == NULL && failed.count == 0);
    st_free_token_array(&failed);

    output = (char *)1;
    st_test_alloc_fail_at(fail_at);
    error = st_netpattern_to_cpl(canonical, &output);
    st_test_alloc_reset();
    ASSERT(error == ST_ERR_MEMORY || error == ST_OK);
    if (error == ST_ERR_MEMORY)
      ASSERT(output == NULL);
    free(output);
  }
  free(canonical);
  return 1;
}

static int test_canonical_policy_boundary(void) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(context);
  ASSERT(context != NULL && policy != NULL);

  ASSERT(st_validate_netpattern("git status", NULL) == ST_ERR_FORMAT);
  ASSERT(st_policy_add_netpattern(policy, "git status") == ST_ERR_FORMAT);

  char *netpattern = NULL;
  ASSERT(st_netpattern_from_cpl("git status", &netpattern) == ST_OK);
  ASSERT(st_validate_netpattern(netpattern, NULL) == ST_OK);
  ASSERT(st_policy_add_netpattern(policy, netpattern) == ST_OK);
  ASSERT(st_policy_count(policy) == 1);

  free(netpattern);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return 1;
}

/* --- MAIN --- */

int main(void) {
  printf("Running token type tests...\n\n");

  printf("Classification matrix:\n");
  TEST(test_classification_matrix);
  TEST(test_generated_classification_boundaries);
  TEST(test_classifier_adversarial_branch_matrix);
  TEST(test_contextual_adversarial_branch_matrix);

  printf("\nType lattice:\n");
  TEST(test_type_lattice);

  printf("\nNormalisation:\n");
  TEST(test_normalization_matrix);
  TEST(test_normalization_boundaries);
  TEST(test_normalization_allocation_failures);
  TEST(test_netargv_contract);
  TEST(test_netpattern_cpl_contract);
  TEST(test_canonical_policy_boundary);
  TEST(test_public_helper_matrix);

  printf("\n========================================\n");
  printf("Results: %d/%d passed, %d failed\n", tests_passed, tests_run,
         tests_failed);

  return tests_failed > 0 ? 1 : 0;
}
