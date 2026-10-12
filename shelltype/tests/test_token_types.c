/*
 * test_token_types.c – Unit tests for the wildcard lattice and token
 * classification.
 *
 * Tests all 12+1 types, the join table, and the compatibility table.
 */

#include "../src/netpattern.h"
#include "../src/normalize_internal.h"
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

static shell_netstring_buffer_t test_wrap_netstring(const void *payload,
                                                    size_t length) {
  size_t record_length = 0;
  if (shell_netstring_encoded_length(length, &record_length) !=
      SHELL_NETSTRING_OK)
    return (shell_netstring_buffer_t){0};
  unsigned char *encoded = malloc(record_length);
  if (!encoded)
    return (shell_netstring_buffer_t){0};
  size_t written = 0;
  if (shell_netstring_write(encoded, record_length, payload, length,
                            &written) != SHELL_NETSTRING_OK ||
      written != record_length) {
    free(encoded);
    return (shell_netstring_buffer_t){0};
  }
  return (shell_netstring_buffer_t){encoded, written};
}

static shell_netstring_buffer_t test_pattern_record(char tag, const void *value,
                                                    size_t value_length) {
  shell_netstring_buffer_t tag_record = test_wrap_netstring(&tag, 1);
  shell_netstring_buffer_t value_record =
      test_wrap_netstring(value, value_length);
  if (!tag_record.data || !value_record.data) {
    shell_netstring_buffer_free(&tag_record);
    shell_netstring_buffer_free(&value_record);
    return (shell_netstring_buffer_t){0};
  }
  size_t payload_length = tag_record.length + value_record.length;
  unsigned char *payload = malloc(payload_length);
  if (!payload) {
    shell_netstring_buffer_free(&tag_record);
    shell_netstring_buffer_free(&value_record);
    return (shell_netstring_buffer_t){0};
  }
  memcpy(payload, tag_record.data, tag_record.length);
  memcpy(payload + tag_record.length, value_record.data, value_record.length);
  shell_netstring_buffer_t record =
      test_wrap_netstring(payload, payload_length);
  free(payload);
  shell_netstring_buffer_free(&value_record);
  shell_netstring_buffer_free(&tag_record);
  return record;
}

/* Fixture inputs supply at most four textual components. */
static shell_netstring_buffer_t test_compound_pattern(const char *tags,
                                                      const char *const *values,
                                                      size_t count) {
  shell_netstring_buffer_t parts[4] = {{0}};
  size_t compound_length = 0;
  for (size_t i = 0; i < count; i++) {
    parts[i] = test_pattern_record(tags[i], values[i], strlen(values[i]));
    if (!parts[i].data)
      goto fail;
    compound_length += parts[i].length;
  }
  unsigned char *compound = malloc(compound_length ? compound_length : 1);
  if (!compound)
    goto fail;
  size_t offset = 0;
  for (size_t i = 0; i < count; i++) {
    memcpy(compound + offset, parts[i].data, parts[i].length);
    offset += parts[i].length;
  }
  shell_netstring_buffer_t pattern =
      test_pattern_record('C', compound, compound_length);
  free(compound);
  for (size_t i = 0; i < count; i++)
    shell_netstring_buffer_free(&parts[i]);
  return pattern;

fail:
  for (size_t i = 0; i < count; i++)
    shell_netstring_buffer_free(&parts[i]);
  return (shell_netstring_buffer_t){0};
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
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

/* --- TYPE CLASSIFICATION --- */

typedef struct {
  const char *text;
  st_token_type_t type;
  size_t count;
} single_visit_expect_t;

static bool check_single_visit(const st_token_view_t *token, void *user_ctx) {
  single_visit_expect_t *expect = user_ctx;
  size_t length = strlen(expect->text);
  if (token->text_length != length ||
      memcmp(token->text, expect->text, length) || token->type != expect->type)
    return false;
  expect->count++;
  return true;
}

static int visit_single_classification(const char *text, st_token_type_t type) {
  shell_netstring_buffer_t netargv = test_wrap_netstring(text, strlen(text));
  if (!netargv.data)
    return 0;
  single_visit_expect_t expect = {.text = text, .type = type};
  size_t visited = 0;
  st_error_t error = st_netargv_visit_view(
      (st_netargv_view_t){(const char *)netargv.data, netargv.length},
      check_single_visit, &expect, &visited);
  shell_netstring_buffer_free(&netargv);
  return error == ST_OK && visited == 1 && expect.count == 1;
}

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

  ASSERT(st_token_classify("", (sizeof("") - 1)) == ST_TYPE_LITERAL);

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_token_type_t actual =
        st_token_classify(cases[i].token, strlen(cases[i].token));
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
    if (!strchr(cases[i].token, '='))
      ASSERT(visit_single_classification(cases[i].token, actual));
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
       i++) {
    ASSERT(st_token_classify(rejection_cases[i].token,
                             strlen(rejection_cases[i].token)) !=
           rejection_cases[i].forbidden);
    ASSERT(visit_single_classification(
        rejection_cases[i].token,
        st_token_classify(rejection_cases[i].token,
                          strlen(rejection_cases[i].token))));
  }
  return 1;
}

static int generated_token_is(const char *token, st_token_type_t expected) {
  st_token_array_t normalized = {0};
  if (st_token_classify(token, strlen(token)) != expected ||
      !visit_single_classification(token, expected) ||
      test_st_classify(token, &normalized) != ST_OK || normalized.count != 1 ||
      normalized.tokens[0].type != expected ||
      strcmp(normalized.tokens[0].text, token) != 0) {
    st_token_array_free(&normalized);
    return 0;
  }
  st_token_array_free(&normalized);
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
    ASSERT(st_token_classify(token, strlen(token)) != ST_TYPE_SIZE);
  }
  for (size_t i = 0;
       i < sizeof(duration_suffixes) / sizeof(duration_suffixes[0]); i++) {
    ASSERT(snprintf(token, sizeof(token), "-%zu.25%s", i + 1,
                    duration_suffixes[i]) > 0);
    ASSERT(generated_token_is(token, ST_TYPE_DURATION));
    ASSERT(snprintf(token, sizeof(token), "-%zu..25%s", i + 1,
                    duration_suffixes[i]) > 0);
    ASSERT(st_token_classify(token, strlen(token)) != ST_TYPE_DURATION);
  }

  for (unsigned octet = 0; octet <= 255; octet += 51) {
    ASSERT(snprintf(token, sizeof(token), "192.0.2.%u", octet) > 0);
    ASSERT(generated_token_is(token, ST_TYPE_IPV4));
  }
  ASSERT(st_token_classify("192.0.2.256", (sizeof("192.0.2.256") - 1)) !=
         ST_TYPE_IPV4);

  static const char *uuids[] = {
      "550e8400-e29b-41d4-a716-446655440000",
      "550e8400-e29b-51d4-a716-446655440000",
  };
  for (size_t i = 0; i < sizeof(uuids) / sizeof(uuids[0]); i++)
    ASSERT(generated_token_is(uuids[i], ST_TYPE_UUID));
  ASSERT(st_token_classify("550e8400-e29b-41d4-a716-44665544000g",
                           (sizeof("550e8400-e29b-41d4-a716-44665544000g") -
                            1)) != ST_TYPE_UUID);

  static const size_t sha_lengths[] = {7, 40, 64};
  for (size_t i = 0; i < sizeof(sha_lengths) / sizeof(sha_lengths[0]); i++) {
    memset(token, 'a', sha_lengths[i]);
    token[sha_lengths[i]] = '\0';
    ASSERT(generated_token_is(token, ST_TYPE_SHA));
    token[sha_lengths[i] - 1] = 'g';
    ASSERT(st_token_classify(token, strlen(token)) != ST_TYPE_SHA);
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
    ASSERT(st_token_classify(bad_timestamps[i], strlen(bad_timestamps[i])) !=
           ST_TYPE_TIMESTAMP);
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
    st_token_type_t type = st_token_classify(tokens[i], strlen(tokens[i]));
    ASSERT((unsigned)type < ST_TYPE_COUNT);
    if (!strchr(tokens[i], '='))
      ASSERT(visit_single_classification(tokens[i], type));
  }
  return 1;
}

static int test_bounded_recognizer_boundary_matrix(void) {
  static const struct {
    const char *token;
    st_token_type_t expected;
  } cases[] = {
      {"::", ST_TYPE_IPV6},
      {"::1", ST_TYPE_IPV6},
      {"1:2:3:4:5:6:7:8", ST_TYPE_IPV6},
      {"1:2:3:4:5:6:7::", ST_TYPE_IPV6},
      {"1:2:3:4:5:6:7:8:9", ST_TYPE_IMAGE},
      {"1:2:3:4:5:6:7", ST_TYPE_IMAGE},
      {"::ffff:192.0.2.1", ST_TYPE_IPV6},
      {"::ffff:192.0.2.256", ST_TYPE_FILENAME},
      {"fe80::1%eth0", ST_TYPE_IPV6},
      {"fe80::1%eth 0", ST_TYPE_QUOTED_SPACE},
      {"fe80::1%", ST_TYPE_LITERAL},
      {"1.2.3.4", ST_TYPE_IPV4},
      {"1.2.3.04", ST_TYPE_IPV4},
      {"1.2.3.4.", ST_TYPE_FILENAME},
      {"1.2.3", ST_TYPE_SEMVER},
      {"00:11:22:33:44:55", ST_TYPE_MAC},
      {"00-11-22-33-44-55", ST_TYPE_MAC},
      {"00:11-22:33-44:55", ST_TYPE_IMAGE},
      {"@scope/name", ST_TYPE_PKG},
      {"@scope/name@1.0", ST_TYPE_PKG},
      {"name@1.0", ST_TYPE_PKG},
      {"name@alpha", ST_TYPE_LITERAL},
      {"name@1", ST_TYPE_PKG},
      {"name@^1", ST_TYPE_PKG},
      {"nginx:latest", ST_TYPE_IMAGE},
      {"registry/name:tag", ST_TYPE_IMAGE},
      {"image@sha256:"
       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
       ST_TYPE_IMAGE},
      {"image@sha256:"
       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
       ST_TYPE_LITERAL},
      {"2024-02-29", ST_TYPE_TIMESTAMP},
      {"2023-02-29", ST_TYPE_CRON},
      {"2024-01-01T00:00:00+0000", ST_TYPE_TIMESTAMP},
      {"2024-01-01T00:00:00+00:00", ST_TYPE_TIMESTAMP},
      {"2024-01-01T00:00:00+24:00", ST_TYPE_LITERAL},
      {"2024-01-01T00:00:00+00:60", ST_TYPE_LITERAL},
      {"0B", ST_TYPE_SIZE},
      {"0bytes", ST_TYPE_SIZE},
      {"0.5KiB", ST_TYPE_SIZE},
      {"0..5KiB", ST_TYPE_REL_PATH},
      {"-0.5ms", ST_TYPE_DURATION},
      {"-.5ms", ST_TYPE_DURATION},
      {"1.0.0-0", ST_TYPE_SEMVER},
      {"1.0.0-00", ST_TYPE_LITERAL},
      {"1.0.0+00", ST_TYPE_SEMVER},
      {"root:wheel", ST_TYPE_USER_GROUP},
      {"www-data:users", ST_TYPE_USER_GROUP},
      {"root:WHEEL", ST_TYPE_IMAGE},
      {"*.c", ST_TYPE_GLOB},
      {"[ab]", ST_TYPE_GLOB},
      {"[ab", ST_TYPE_LITERAL},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_token_type_t actual =
        st_token_classify(cases[i].token, strlen(cases[i].token));
    if (actual != cases[i].expected) {
      printf("  bounded case %zu: '%s' = %s, expected %s\n", i, cases[i].token,
             st_type_symbol[actual], st_type_symbol[cases[i].expected]);
      return 0;
    }
    ASSERT(visit_single_classification(cases[i].token, cases[i].expected));
  }
  return 1;
}

static int test_bounded_classifier_stress_matrix(void) {
  /* Deterministic mixed syntax keeps rare bounded-parser exits covered without
   * depending on a fuzzer or asserting an arbitrary lattice result. */
  static const char alphabet[] =
      "0123456789abcdefABCDEF.-_/:@%+=*?[]{}|\\$abcdefghijklmnopqrstuvwxyz";
  uint32_t state = UINT32_C(0x5eed1234);
  char token[80];
  for (size_t sample = 0; sample < 4096; sample++) {
    state = state * UINT32_C(1664525) + UINT32_C(1013904223);
    size_t length = state % (sizeof(token) - 1);
    for (size_t i = 0; i < length; i++) {
      state = state * UINT32_C(1664525) + UINT32_C(1013904223);
      token[i] = alphabet[state % (sizeof(alphabet) - 1)];
    }
    token[length] = '\0';
    st_token_type_t type = st_token_classify(token, strlen(token));
    ASSERT((unsigned)type < ST_TYPE_COUNT);
    if (!strchr(token, '='))
      ASSERT(visit_single_classification(token, type));
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
    st_token_array_free(&typed);
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
      st_token_array_free(&typed);
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

    st_token_array_free(&typed);
  }
  return 1;
}

static int test_normalization_boundaries(void) {
  st_token_array_t typed = {0};

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
  st_token_array_free(&typed);

  ASSERT(test_st_classify("#literal | ;", &typed) == ST_OK);
  ASSERT(typed.count == 3);
  ASSERT(strcmp(typed.tokens[0].text, "#literal") == 0);
  ASSERT(strcmp(typed.tokens[1].text, "|") == 0);
  ASSERT(strcmp(typed.tokens[2].text, ";") == 0);
  st_token_array_free(&typed);

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
  st_token_array_free(&typed);
  return 1;
}

static int test_normalization_allocation_failures(void) {
  static const char input[] = "grep 'a.*b' 2>&1 --output=log EMPTY= kill -s 9";
  st_token_array_t probe = {0};
  st_test_alloc_reset();
  ASSERT(test_st_classify(input, &probe) == ST_OK);
  size_t allocations = st_test_alloc_count();
  ASSERT(allocations > 0);
  st_token_array_free(&probe);

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
      st_token_array_free(&typed);
    }
  }
  ASSERT(observed);

  return 1;
}

static int test_borrowed_policy_classifier(void) {
  static const char input[] = "4:kill,2:-s,1:9,0:,3:a\0b,";
  st_token_scratch_t scratch;
  st_test_alloc_reset();
  st_test_alloc_fail_at(1);
  st_error_t error = st_netargv_classify_scratch_view(
      (st_netargv_view_t){input, sizeof(input) - 1}, &scratch);
  size_t allocations = st_test_alloc_count();
  st_test_alloc_reset();
  ASSERT(error == ST_OK && allocations == 0 && scratch.count == 5);
  ASSERT(scratch.tokens[0].text == input + 2);
  ASSERT(scratch.tokens[2].type == ST_TYPE_SIGNAL);
  ASSERT(scratch.tokens[3].text_length == 0 &&
         scratch.tokens[3].text[0] == '\0');
  ASSERT(scratch.tokens[4].text_length == 3 &&
         memcmp(scratch.tokens[4].text, "a\0b", 3) == 0);

  char long_payload[ST_MAX_TOKEN_LEN * 2];
  memset(long_payload, 'x', sizeof(long_payload));
  char encoded[sizeof(long_payload) + 32];
  size_t length = 0;
  ASSERT(shell_netstring_write(encoded, sizeof(encoded), long_payload,
                               sizeof(long_payload),
                               &length) == SHELL_NETSTRING_OK);
  ASSERT(st_netargv_classify_scratch_view((st_netargv_view_t){encoded, length},
                                          &scratch) == ST_OK);
  ASSERT(scratch.count == 1 &&
         scratch.tokens[0].text_length == sizeof(long_payload) &&
         scratch.tokens[0].type == ST_TYPE_LITERAL &&
         memcmp(scratch.tokens[0].text, long_payload, sizeof(long_payload)) ==
             0);
  /* Malformed tails cannot publish a partially classified prefix. */
  encoded[length] = 'x';
  ASSERT(
      st_netargv_classify_scratch_view((st_netargv_view_t){encoded, length + 1},
                                       &scratch) == ST_ERR_FORMAT);
  ASSERT(scratch.count == 0);

  char records[(ST_MAX_CMD_TOKENS + 1) * 4];
  for (size_t i = 0; i < ST_MAX_CMD_TOKENS + 1; i++)
    memcpy(records + i * 4, "1:x,", 4);
  ASSERT(st_netargv_classify_scratch_view(
             (st_netargv_view_t){records, ST_MAX_CMD_TOKENS * 4}, &scratch) ==
         ST_OK);
  ASSERT(scratch.count == ST_MAX_CMD_TOKENS);
  ASSERT(st_netargv_classify_scratch_view(
             (st_netargv_view_t){records, sizeof(records)}, &scratch) ==
         ST_ERR_LIMIT);
  ASSERT(scratch.count == 0);
  return 1;
}

static int test_canonical_invalid_boundaries(void) {
  ASSERT(st_token_classify(NULL, 0) == ST_TYPE_LITERAL);
  st_token_array_free(NULL);

  st_token_scratch_t scratch;
  ASSERT(st_netargv_classify_scratch_view((st_netargv_view_t){NULL, 1},
                                          &scratch) == ST_ERR_INVALID);
  ASSERT(scratch.count == 0);
  ASSERT(st_netargv_classify_scratch_view((st_netargv_view_t){"bad", 3},
                                          &scratch) == ST_ERR_FORMAT);
  ASSERT(scratch.count == 0);
  return 1;
}

/* Exercise malformed input directly at the binary-safe public boundary. */
static int test_netpattern_view_boundary_contract(void) {
  shell_netstring_buffer_t valid =
      test_pattern_record('L', "value", sizeof("value") - 1);
  ASSERT(valid.data != NULL);

  st_token_array_t decoded = {(st_token_t *)(uintptr_t)1, SIZE_MAX};
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){.data = NULL, .length = 1}, &decoded) ==
         ST_ERR_INVALID);
  ASSERT(decoded.tokens == NULL && decoded.count == 0);
  decoded.tokens = (st_token_t *)(uintptr_t)1;
  decoded.count = SIZE_MAX;
  ASSERT(
      st_netpattern_decode_view((st_netpattern_view_t){.data = "", .length = 0},
                                &decoded) == ST_ERR_FORMAT);
  ASSERT(decoded.tokens == NULL && decoded.count == 0);

  char *cpl = (char *)(uintptr_t)1;
  ASSERT(st_netpattern_to_cpl_view(
             (st_netpattern_view_t){.data = NULL, .length = 1}, &cpl) ==
         ST_ERR_INVALID);
  ASSERT(cpl == NULL);
  cpl = (char *)(uintptr_t)1;
  ASSERT(
      st_netpattern_to_cpl_view((st_netpattern_view_t){.data = "", .length = 0},
                                &cpl) == ST_ERR_FORMAT);
  ASSERT(cpl == NULL);

  st_netpattern_t occupied = {.data = (char *)valid.data,
                              .length = valid.length};
  st_netpattern_free(&occupied);
  ASSERT(occupied.data == NULL && occupied.length == 0);
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
                    {"app.", NULL},           {"", NULL}},
    suffixes[] = {{"10MiB", "MiB"}, {"-2.5G", "G"}, {"42", NULL}, {".5G", "G"},
                  {"-", NULL},      {"10", NULL},   {"", NULL}};
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
  ASSERT(st_netargv_classify_view(
             (st_netargv_view_t){"6:printf,9:two words,0:,1:>,",
                                 sizeof("6:printf,9:two words,0:,1:>,") - 1},
             &typed) == ST_OK);
  ASSERT(typed.count == 4);
  ASSERT(strcmp(typed.tokens[0].text, "printf") == 0);
  ASSERT(strcmp(typed.tokens[1].text, "two words") == 0);
  ASSERT(strcmp(typed.tokens[2].text, "") == 0);
  ASSERT(strcmp(typed.tokens[3].text, ">") == 0);
  st_token_array_free(&typed);

  static const char *const malformed[] = {
      "01:x,", "-1:x,", "+1:x,", "1x,", "1:x", "2:x,", "0:;", "x",
  };
  for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); i++) {
    typed.tokens = (st_token_t *)1;
    typed.count = 99;
    ASSERT(st_netargv_classify_view(
               (st_netargv_view_t){malformed[i], strlen(malformed[i])},
               &typed) == ST_ERR_FORMAT);
    ASSERT(typed.tokens == NULL && typed.count == 0);
  }
  ASSERT(st_netargv_classify_view((st_netargv_view_t){"", sizeof("") - 1},
                                  &typed) == ST_OK);
  ASSERT(typed.tokens == NULL && typed.count == 0);

  ASSERT(st_netargv_classify_view(
             (st_netargv_view_t){
                 "999999999999999999999999999999999999:x,",
                 sizeof("999999999999999999999999999999999999:x,") - 1},
             &typed) == ST_ERR_LIMIT);
  ASSERT(st_netargv_classify_view(
             (st_netargv_view_t){"1:x,x", sizeof("1:x,x") - 1}, &typed) ==
         ST_ERR_FORMAT);

  char too_many[ST_MAX_CMD_TOKENS * 4 + 2] = {0};
  for (size_t i = 0; i <= ST_MAX_CMD_TOKENS; i++)
    strcat(too_many, "0:,");
  ASSERT(
      st_netargv_classify_view((st_netargv_view_t){too_many, strlen(too_many)},
                               &typed) == ST_ERR_LIMIT);

  char split_overflow[1024] = {0};
  for (size_t i = 0; i < ST_MAX_CMD_TOKENS / 2 + 1; i++)
    strcat(split_overflow, "3:A=1,");
  ASSERT(st_netargv_classify_view(
             (st_netargv_view_t){split_overflow, strlen(split_overflow)},
             &typed) == ST_OK);
  ASSERT(typed.count == ST_MAX_CMD_TOKENS / 2 + 1);
  st_token_array_free(&typed);
  return 1;
}

static bool count_netargv_view(const st_token_view_t *token, void *user_ctx) {
  size_t *count = user_ctx;
  if (!token || !count)
    return false;
  (*count)++;
  return true;
}

static int test_netargv_view_contract(void) {
  static const char framed_with_trailer[] = "4:echo,5:hello,not netargv";
  st_netargv_view_t bounded = {
      .data = framed_with_trailer,
      .length = (sizeof("4:echo,5:hello,") - 1),
  };
  st_token_array_t typed = {0};
  ASSERT(st_netargv_classify_view(bounded, &typed) == ST_OK);
  ASSERT(typed.count == 2);
  ASSERT(strcmp(typed.tokens[0].text, "echo") == 0);
  ASSERT(strcmp(typed.tokens[1].text, "hello") == 0);
  st_token_array_free(&typed);

  size_t visited = 0;
  ASSERT(st_netargv_visit_view(bounded, count_netargv_view, &visited,
                               &visited) == ST_OK);
  ASSERT(visited == 2);

  static const char embedded_nul[] = {'1', ':', 'x', ',', '\0'};
  ASSERT(st_netargv_classify_view(
             (st_netargv_view_t){.data = embedded_nul,
                                 .length = sizeof(embedded_nul)},
             &typed) == ST_ERR_FORMAT);
  ASSERT(typed.tokens == NULL && typed.count == 0);
  ASSERT(st_netargv_classify_view((st_netargv_view_t){0}, &typed) == ST_OK);
  ASSERT(typed.tokens == NULL && typed.count == 0);
  return 1;
}

typedef struct {
  const char *expected_text[8];
  st_token_type_t expected_type[8];
  size_t count;
  size_t stop_after;
} netargv_visit_expect_t;

static bool check_netargv_visit(const st_token_view_t *token, void *user_ctx) {
  netargv_visit_expect_t *expect = user_ctx;
  if (!token || expect->count >= 8)
    return false;
  size_t index = expect->count++;
  size_t length = strlen(expect->expected_text[index]);
  if (token->text_length != length ||
      memcmp(token->text, expect->expected_text[index], length) != 0 ||
      token->type != expect->expected_type[index])
    return false;
  return expect->stop_after == 0 || expect->count < expect->stop_after;
}

static int test_netargv_visit_contract(void) {
  netargv_visit_expect_t expect = {
      .expected_text = {"grep", "a.*b", "--output", "123", "kill", "9", "A=1"},
      .expected_type = {ST_TYPE_LITERAL, ST_TYPE_REGEX, ST_TYPE_LONGOPT,
                        ST_TYPE_NUMBER, ST_TYPE_LITERAL, ST_TYPE_SIGNAL,
                        ST_TYPE_LITERAL},
  };
  size_t visited = SIZE_MAX;
  ASSERT(
      st_netargv_visit_view(
          (st_netargv_view_t){
              "4:grep,4:a.*b,8:--output,3:123,4:kill,1:9,3:A=1,",
              sizeof("4:grep,4:a.*b,8:--output,3:123,4:kill,1:9,3:A=1,") - 1},
          check_netargv_visit, &expect, &visited) == ST_OK);
  ASSERT(visited == 7 && expect.count == 7);

  expect.count = 0;
  expect.stop_after = 2;
  ASSERT(
      st_netargv_visit_view(
          (st_netargv_view_t){
              "4:grep,4:a.*b,8:--output,3:123,4:kill,1:9,3:A=1,",
              sizeof("4:grep,4:a.*b,8:--output,3:123,4:kill,1:9,3:A=1,") - 1},
          check_netargv_visit, &expect, &visited) == ST_OK);
  ASSERT(visited == 2 && expect.count == 2);

  netargv_visit_expect_t empty_expect = {.expected_text = {""},
                                         .expected_type = {ST_TYPE_LITERAL}};
  ASSERT(st_netargv_visit_view((st_netargv_view_t){"0:,", sizeof("0:,") - 1},
                               check_netargv_visit, &empty_expect,
                               &visited) == ST_OK);
  ASSERT(visited == 1 && empty_expect.count == 1);

  ASSERT(st_netargv_visit_view((st_netargv_view_t){"1:x", sizeof("1:x") - 1},
                               check_netargv_visit, &expect,
                               &visited) == ST_ERR_FORMAT);
  ASSERT(visited == 0);

  return 1;
}

typedef struct {
  const char *payload;
  size_t length;
  st_token_type_t type;
  size_t calls;
} netargv_borrowed_expect_t;

static bool check_netargv_borrowed(const st_token_view_t *token,
                                   void *user_ctx) {
  netargv_borrowed_expect_t *expect = user_ctx;
  ASSERT(token->text == expect->payload);
  ASSERT(token->text_length == expect->length);
  ASSERT(token->type == expect->type);
  expect->calls++;
  return true;
}

static int test_netargv_visit_is_borrowed_and_allocation_free(void) {
  static const char netargv[] = "4:grep,";
  netargv_borrowed_expect_t short_expect = {
      .payload = netargv + 2, .length = 4, .type = ST_TYPE_LITERAL};
  size_t visited = 0;
  st_test_alloc_reset();
  ASSERT(st_netargv_visit_view(
             (st_netargv_view_t){netargv, sizeof(netargv) - 1},
             check_netargv_borrowed, &short_expect, &visited) == ST_OK);
  ASSERT(visited == 1 && short_expect.calls == 1);
  ASSERT(st_test_alloc_count() == 0);

  size_t length = ST_MAX_TOKEN_LEN + 32;
  size_t record_length = 0;
  ASSERT(shell_netstring_encoded_length(length, &record_length) ==
         SHELL_NETSTRING_OK);
  char *long_netargv = malloc(record_length + 1);
  ASSERT(long_netargv != NULL);
  char *payload = malloc(length);
  ASSERT(payload != NULL);
  memset(payload, 'x', length);
  size_t written = 0;
  ASSERT(shell_netstring_write(long_netargv, record_length, payload, length,
                               &written) == SHELL_NETSTRING_OK);
  ASSERT(written == record_length);
  long_netargv[written] = '\0';
  netargv_borrowed_expect_t long_expect = {
      .payload = long_netargv + (record_length - length - 1),
      .length = length,
      .type = ST_TYPE_LITERAL,
  };
  st_test_alloc_reset();
  ASSERT(st_netargv_visit_view((st_netargv_view_t){long_netargv, written},
                               check_netargv_borrowed, &long_expect,
                               &visited) == ST_OK);
  ASSERT(visited == 1 && long_expect.calls == 1);
  ASSERT(st_test_alloc_count() == 0);
  free(payload);
  free(long_netargv);
  return 1;
}

static int test_netargv_visit_accepts_binary_payloads(void) {
  static const char netargv[] = {'3', ':', 'a', '\0', 'b', ','};
  netargv_borrowed_expect_t expect = {
      .payload = netargv + 2,
      .length = 3,
      .type = ST_TYPE_LITERAL,
  };
  size_t visited = 0;
  ASSERT(st_netargv_visit_view(
             (st_netargv_view_t){.data = netargv, .length = sizeof(netargv)},
             check_netargv_borrowed, &expect, &visited) == ST_OK);
  ASSERT(visited == 1 && expect.calls == 1);
  st_token_array_t classified = {0};
  ASSERT(st_netargv_classify_view(
             (st_netargv_view_t){.data = netargv, .length = sizeof(netargv)},
             &classified) == ST_OK);
  ASSERT(classified.count == 1 && classified.tokens != NULL);
  ASSERT(classified.tokens[0].text_length == 3);
  ASSERT(memcmp(classified.tokens[0].text, netargv + 2, 3) == 0);
  st_token_array_free(&classified);

  st_learner_t *learner = st_learner_new(NULL);
  ASSERT(learner != NULL);
  ASSERT(st_learner_feed_netargv_view(
             learner, (st_netargv_view_t){.data = netargv,
                                          .length = sizeof(netargv)}) == ST_OK);
  st_learner_stats_t stats = {0};
  st_learner_get_stats(learner, &stats);
  ASSERT(stats.command_count == 1);
  st_learner_free(learner);
  return 1;
}

static int test_cpl_parse_work_is_linear(void) {
  static const size_t escapes[] = {16, 32, 64, 128, 255};
  static const char prefix[] = "\"cmd\" \"";
  char cpl[ST_MAX_CPL_LEN];
  for (size_t i = 0; i < sizeof(escapes) / sizeof(escapes[0]); i++) {
    size_t used = sizeof(prefix) - 1;
    memcpy(cpl, prefix, used);
    for (size_t j = 0; j < escapes[i]; j++) {
      memcpy(cpl + used, "\\u0061", 6);
      used += 6;
    }
    cpl[used++] = '"';
    cpl[used] = '\0';
    st_netpattern_t pattern = {0};
    st_error_t error = st_netpattern_from_cpl_owned(cpl, &pattern);
    size_t work = st_test_cpl_parse_work();
    st_token_array_t decoded = {0};
    bool correct =
        error == ST_OK &&
        st_netpattern_decode_view(
            (st_netpattern_view_t){(const char *)pattern.data, pattern.length},
            &decoded) == ST_OK &&
        decoded.count == 2 && decoded.tokens[1].text_length == escapes[i];
    if (correct)
      for (size_t j = 0; j < escapes[i]; j++)
        correct = correct && decoded.tokens[1].text[j] == 'a';
    st_token_array_free(&decoded);
    st_netpattern_free(&pattern);
    ASSERT(correct);
    ASSERT(work <= used * 3 + 64);
  }

  /* Neither short words nor an escape-heavy trailing word may trigger suffix
   * allocation or one-entry vector growth. Count requested bytes before the
   * decoder, so its independently allocated output is not part of this bound.
   */
  static const size_t words[] = {8, 16, 32, 64, ST_MAX_CMD_TOKENS};
  for (size_t tail = 0; tail < 2; tail++) {
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      size_t used = 0;
      for (size_t j = 0; j < words[i]; j++) {
        if (j)
          cpl[used++] = ' ';
        cpl[used++] = '"';
        size_t repeats = tail && j == words[i] - 1 ? ST_MAX_TOKEN_LEN - 1 : 1;
        for (size_t k = 0; k < repeats; k++) {
          if (tail && j == words[i] - 1) {
            memcpy(cpl + used, "\\u0061", 6);
            used += 6;
          } else {
            cpl[used++] = 'a';
          }
        }
        cpl[used++] = '"';
      }
      cpl[used] = '\0';
      st_netpattern_t pattern = {0};
      st_test_alloc_reset();
      st_error_t error = st_netpattern_from_cpl_owned(cpl, &pattern);
      size_t work = st_test_cpl_parse_work();
      size_t requested = st_test_alloc_bytes();
      size_t allocations = st_test_alloc_count();
      st_test_alloc_reset();
      st_token_array_t decoded = {0};
      bool correct = error == ST_OK &&
                     st_netpattern_decode_view(
                         (st_netpattern_view_t){(const char *)pattern.data,
                                                pattern.length},
                         &decoded) == ST_OK &&
                     decoded.count == words[i];
      if (correct) {
        for (size_t j = 0; j < words[i]; j++) {
          size_t expected =
              tail && j == words[i] - 1 ? ST_MAX_TOKEN_LEN - 1 : 1;
          correct = correct && decoded.tokens[j].text_length == expected;
          if (correct)
            for (size_t k = 0; k < expected; k++)
              correct = correct && decoded.tokens[j].text[k] == 'a';
        }
      }
      st_token_array_free(&decoded);
      st_netpattern_free(&pattern);
      ASSERT(correct);
      ASSERT(work <= used * 3 + 64);
      ASSERT(requested <= 192 * words[i] + 8 * used + 2048);
      ASSERT(allocations <= 2 * words[i] + 8);
    }
  }
  return 1;
}

static int test_cpl_decoded_token_limits(void) {
  static const struct {
    const char *spelling;
    const char *decoded;
    size_t width;
    bool quoted;
  } cases[] = {
      {"z", "z", 1, false},
      {"z", "z", 1, true},
      {"\\n", "\n", 1, true},
      {"\\x00", "\0", 1, true},
      {"\\u007f", "\x7f", 1, true},
      {"\\u00a2", "\xc2\xa2", 2, true},
      {"\\u20ac", "\xe2\x82\xac", 3, true},
      {"\\ud83d\\ude00", "\xf0\x9f\x98\x80", 4, true},
  };
  char cpl[ST_MAX_CPL_LEN];
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    /* Exactly full, then every partial fit of a multibyte code point, plus
     * an already-full buffer. All failures must leave no published output. */
    for (size_t extra = 0; extra <= cases[i].width; extra++) {
      size_t padding = ST_MAX_TOKEN_LEN - 1 - cases[i].width + extra;
      size_t used = 4;
      memcpy(cpl, "cmd ", used);
      if (cases[i].quoted)
        cpl[used++] = '"';
      memset(cpl + used, 'a', padding);
      used += padding;
      size_t spelling_length = strlen(cases[i].spelling);
      memcpy(cpl + used, cases[i].spelling, spelling_length);
      used += spelling_length;
      if (cases[i].quoted)
        cpl[used++] = '"';
      cpl[used] = '\0';
      st_netpattern_t pattern = {0};
      st_error_t error = st_netpattern_from_cpl_owned(cpl, &pattern);
      st_token_array_t decoded = {0};
      bool correct;
      if (extra == 0) {
        correct = error == ST_OK &&
                  st_netpattern_decode_view(
                      (st_netpattern_view_t){(const char *)pattern.data,
                                             pattern.length},
                      &decoded) == ST_OK &&
                  decoded.count == 2 &&
                  decoded.tokens[1].text_length == ST_MAX_TOKEN_LEN - 1 &&
                  memcmp(decoded.tokens[1].text + padding, cases[i].decoded,
                         cases[i].width) == 0;
        if (correct)
          for (size_t j = 0; j < padding; j++)
            correct = correct && decoded.tokens[1].text[j] == 'a';
      } else {
        correct = error == ST_ERR_INVALID && pattern.data == NULL &&
                  pattern.length == 0;
      }
      st_token_array_free(&decoded);
      st_netpattern_free(&pattern);
      ASSERT(correct);
    }
  }

  /* Prefix and suffix have independent decoded-byte limits. Marker bytes
   * are structural, not part of either literal component's capacity. */
  for (size_t suffix = 0; suffix < 2; suffix++) {
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      for (size_t extra = 0; extra <= cases[i].width; extra++) {
        size_t padding = ST_MAX_TOKEN_LEN - 1 - cases[i].width + extra;
        size_t used = 4;
        memcpy(cpl, "cmd ", used);
        if (suffix) {
          memset(cpl + used, 'a', ST_MAX_TOKEN_LEN - 1);
          used += ST_MAX_TOKEN_LEN - 1;
          memcpy(cpl + used, "{#n}", 4);
          used += 4;
        }
        if (cases[i].quoted)
          cpl[used++] = '"';
        memset(cpl + used, 'a', padding);
        used += padding;
        size_t spelling_length = strlen(cases[i].spelling);
        memcpy(cpl + used, cases[i].spelling, spelling_length);
        used += spelling_length;
        if (cases[i].quoted)
          cpl[used++] = '"';
        if (!suffix) {
          memcpy(cpl + used, "{#n}", 4);
          used += 4;
          memset(cpl + used, 'a', ST_MAX_TOKEN_LEN - 1);
          used += ST_MAX_TOKEN_LEN - 1;
        }
        cpl[used] = '\0';
        st_netpattern_t pattern = {0};
        st_error_t error = st_netpattern_from_cpl_owned(cpl, &pattern);
        st_token_array_t decoded = {0};
        bool correct;
        if (extra == 0) {
          correct = error == ST_OK &&
                    st_netpattern_decode_view(
                        (st_netpattern_view_t){(const char *)pattern.data,
                                               pattern.length},
                        &decoded) == ST_OK &&
                    decoded.count == 2 && decoded.tokens[1].compound &&
                    decoded.tokens[1].prefix_length == ST_MAX_TOKEN_LEN - 1 &&
                    decoded.tokens[1].suffix_length == ST_MAX_TOKEN_LEN - 1 &&
                    decoded.tokens[1].capture_type == ST_TYPE_NUMBER;
          if (correct) {
            const char *fragment =
                suffix ? decoded.tokens[1].suffix : decoded.tokens[1].prefix;
            correct = memcmp(fragment + padding, cases[i].decoded,
                             cases[i].width) == 0;
          }
        } else {
          correct = error == ST_ERR_INVALID && pattern.data == NULL &&
                    pattern.length == 0;
        }
        st_token_array_free(&decoded);
        st_netpattern_free(&pattern);
        ASSERT(correct);
      }
    }
  }
  /* Capture text is bounded too, even before its vocabulary is validated. */
  memcpy(cpl, "cmd a{", 6);
  memset(cpl + 6, 'x', ST_MAX_TOKEN_LEN);
  strcpy(cpl + 6 + ST_MAX_TOKEN_LEN, "}z");
  st_netpattern_t pattern = {0};
  ASSERT(st_netpattern_from_cpl_owned(cpl, &pattern) == ST_ERR_INVALID);
  ASSERT(pattern.data == NULL && pattern.length == 0);
  return 1;
}

static int test_netpattern_decode_allocation_contract(void) {
  static const size_t counts[] = {4, 8, 16, 32, 64, ST_MAX_CMD_TOKENS};
  static const char binary[] = {'a', '\0', 'b', '}'};
  char prefix[ST_MAX_TOKEN_LEN - 1], suffix[ST_MAX_TOKEN_LEN - 1];
  memset(prefix, 'p', sizeof(prefix));
  memset(suffix, 's', sizeof(suffix));
  prefix[0] = '\0';
  suffix[sizeof(suffix) - 1] = '\0';
  st_token_t tokens[ST_MAX_CMD_TOKENS];
  for (size_t mixed = 0; mixed < 2; mixed++) {
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
      for (size_t j = 0; j < counts[i]; j++)
        tokens[j] = (st_token_t){.text = mixed ? binary : "a",
                                 .text_length = mixed ? sizeof(binary) : 1,
                                 .type = ST_TYPE_LITERAL};
      if (mixed) {
        tokens[0] = (st_token_t){.text = "tool", .type = ST_TYPE_LITERAL};
        tokens[1] = (st_token_t){.text = "#n", .type = ST_TYPE_NUMBER};
        tokens[counts[i] - 1] = (st_token_t){.text = "compound",
                                             .type = ST_TYPE_LITERAL,
                                             .compound = true,
                                             .prefix = prefix,
                                             .prefix_length = sizeof(prefix),
                                             .capture = "#n",
                                             .capture_length = 2,
                                             .capture_type = ST_TYPE_NUMBER,
                                             .suffix = suffix,
                                             .suffix_length = sizeof(suffix)};
      }
      st_netpattern_t pattern = {0};
      ASSERT(st_netpattern_encode_owned(tokens, counts[i], &pattern) == ST_OK);
      st_netpattern_view_t view = {pattern.data, pattern.length};
      st_token_array_t decoded = {0};
      st_test_alloc_reset();
      st_error_t error = st_netpattern_decode_view(view, &decoded);
      size_t allocations = st_test_alloc_count();
      size_t requested = st_test_alloc_bytes();
      st_test_alloc_reset();
      bool correct = error == ST_OK && decoded.count == counts[i];
      if (correct) {
        for (size_t j = 0; j < counts[i]; j++) {
          const st_token_t *token = &decoded.tokens[j];
          if (tokens[j].compound) {
            correct = correct && token->compound &&
                      token->prefix_length == sizeof(prefix) &&
                      token->suffix_length == sizeof(suffix) &&
                      token->capture_type == ST_TYPE_NUMBER &&
                      memcmp(token->prefix, prefix, sizeof(prefix)) == 0 &&
                      memcmp(token->suffix, suffix, sizeof(suffix)) == 0;
          } else {
            size_t length = tokens[j].text_length ? tokens[j].text_length
                                                  : strlen(tokens[j].text);
            correct = correct && token->type == tokens[j].type &&
                      token->text_length == length &&
                      memcmp(token->text, tokens[j].text, length) == 0;
          }
        }
      }
      st_token_array_free(&decoded);
      /* Validation must reuse decoding's allocations, including for large
       * binary compounds; requesting details introduces no extra copies. */
      for (unsigned details = 0; details < 2; details++) {
        st_test_alloc_reset();
        error = st_netpattern_validate_view(view, details ? &decoded : NULL);
        size_t validation_allocations = st_test_alloc_count();
        size_t validation_bytes = st_test_alloc_bytes();
        st_test_alloc_reset();
        correct = correct && error == ST_OK &&
                  validation_allocations == allocations &&
                  validation_bytes == requested &&
                  decoded.count == (details ? counts[i] : 0);
        st_token_array_free(&decoded);
      }
      bool linear = requested <= 4 * sizeof(st_token_t) * counts[i] +
                                     8 * pattern.length + 2048 &&
                    allocations <= 2 * counts[i] + 16;
      bool atomic = true;
      for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
        st_test_alloc_fail_at(fail_at);
        error = st_netpattern_decode_view(view, &decoded);
        st_test_alloc_reset();
        atomic = atomic && error == ST_ERR_MEMORY && decoded.tokens == NULL &&
                 decoded.count == 0;
        st_token_array_free(&decoded);
        for (unsigned details = 0; details < 2; details++) {
          st_test_alloc_fail_at(fail_at);
          error = st_netpattern_validate_view(view, details ? &decoded : NULL);
          st_test_alloc_reset();
          atomic = atomic && error == ST_ERR_MEMORY && decoded.tokens == NULL &&
                   decoded.count == 0;
          st_token_array_free(&decoded);
        }
        if (!mixed) {
          st_test_alloc_fail_at(fail_at);
          error = st_netpattern_validate_view(
              (st_netpattern_view_t){(const char *)pattern.data,
                                     pattern.length},
              &decoded);
          st_test_alloc_reset();
          atomic = atomic && error == ST_ERR_MEMORY && decoded.tokens == NULL &&
                   decoded.count == 0;
          st_token_array_free(&decoded);
        }
      }
      st_netpattern_free(&pattern);
      ASSERT(correct);
      ASSERT(atomic);
      ASSERT(linear);
    }
  }
  return 1;
}

static int test_cpl_allocation_failures(void) {
  static const char prefix[] =
      "\"cmd\" \"\" \"a\" \"b\" \"c\" \"d\" \"\\x00\" "
      "\"\\u0061\\u20ac\\ud83d\\ude00\" \"pre\"{#n}\"post\"";
  static const size_t counts[] = {9, 10, ST_MAX_CMD_TOKENS};
  char cpl[ST_MAX_CPL_LEN];
  for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
    memcpy(cpl, prefix, sizeof(prefix));
    size_t used = sizeof(prefix) - 1;
    if (counts[i] > 9) {
      memcpy(cpl + used, " \"", 2);
      used += 2;
      memset(cpl + used, 'a', ST_MAX_TOKEN_LEN - 1);
      used += ST_MAX_TOKEN_LEN - 1;
      memcpy(cpl + used, "\"{#n}\"", 6);
      used += 6;
      memset(cpl + used, 'z', ST_MAX_TOKEN_LEN - 2);
      used += ST_MAX_TOKEN_LEN - 2;
      memcpy(cpl + used, "\\x00\"", 5);
      used += 5;
    }
    for (size_t j = 10; j < counts[i]; j++) {
      memcpy(cpl + used, " \"a\"", 4);
      used += 4;
    }
    cpl[used] = '\0';
    st_netpattern_t pattern = {0};
    st_test_alloc_reset();
    st_error_t error = st_netpattern_from_cpl_owned(cpl, &pattern);
    size_t allocations = st_test_alloc_count();
    st_test_alloc_reset();
    st_netpattern_free(&pattern);
    ASSERT(error == ST_OK && allocations > 0);
    for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
      st_test_alloc_fail_at(fail_at);
      error = st_netpattern_from_cpl_owned(cpl, &pattern);
      st_test_alloc_reset();
      bool empty = pattern.data == NULL && pattern.length == 0;
      st_netpattern_free(&pattern);
      ASSERT(error == ST_ERR_MEMORY && empty);
    }
  }
  return 1;
}

static int test_netpattern_cpl_contract(void) {
  st_netpattern_t roundtrip = {0};
  char *roundtrip_cpl = NULL;
  static const struct {
    const char *cpl;
    const char *canonical_cpl;
  } cases[] = {
      {"printf \"two words\" \"\" #n \"#n\" \"*\"",
       "printf \"two words\" \"\" #n \"#n\" \"*\""},
      {"echo \"outer \\\"inner\\\" text\"",
       "echo \"outer \\\"inner\\\" text\""},
      {"echo \"line\\nfeed\" \"\\u20ac\"", "echo \"line\\nfeed\" €"},
      {"echo \"\\b\\f\\r\\t\\u007f\"", "echo \"\\b\\f\\r\\t\\x7f\""},
      {"echo \"\\u00a2\" \"\\u20ac\" \"\\ud83d\\ude00\"", "echo ¢ € 😀"},
      {"echo \"\\u00A2\" \"\\u20AC\"", "echo ¢ €"},
      {"echo \"quote: \\\" slash: \\\\\"", "echo \"quote: \\\" slash: \\\\\""},
      {"echo \"#unknown\" \"#CRC16:\"", "echo \"#unknown\" \"#CRC16:\""},
      {"dd bs={#size.MiB}", "dd bs={#size.MiB}"},
      {"echo \"{literal}\"", "echo \"{literal}\""},
      {"id #uuid.4", "id #uuid.v4"},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_netpattern_t netpattern = {0};
    char *rendered = NULL;
    ASSERT(st_netpattern_from_cpl_owned(cases[i].cpl, &netpattern) == ST_OK);
    ASSERT(netpattern.data != NULL);
    ASSERT(st_netpattern_to_cpl_view(
               (st_netpattern_view_t){(const char *)netpattern.data,
                                      netpattern.length},
               &rendered) == ST_OK);
    ASSERT(rendered != NULL && strcmp(rendered, cases[i].canonical_cpl) == 0);
    st_netpattern_t again = {0};
    ASSERT(st_netpattern_from_cpl_owned(rendered, &again) == ST_OK);
    ASSERT((netpattern.length != again.length ||
            memcmp(netpattern.data, again.data, netpattern.length)) == 0);
    st_netpattern_free(&again);
    free(rendered);
    st_netpattern_free(&netpattern);
  }

  st_netpattern_t compare_a = {0};
  st_netpattern_t compare_aa = {0};
  st_netpattern_t compare_b = {0};
  st_netpattern_t compare_pair = {0};
  st_netpattern_t compare_typed = {0};
  st_netpattern_t compare_literal_star = {0};
  ASSERT(st_netpattern_from_cpl_owned("a", &compare_a) == ST_OK);
  ASSERT(st_netpattern_from_cpl_owned("aa", &compare_aa) == ST_OK);
  ASSERT(st_netpattern_from_cpl_owned("bb", &compare_b) == ST_OK);
  ASSERT(st_netpattern_from_cpl_owned("a a", &compare_pair) == ST_OK);
  ASSERT(st_netpattern_from_cpl_owned("*", &compare_typed) == ST_OK);
  ASSERT(st_netpattern_from_cpl_owned("\"*\"", &compare_literal_star) == ST_OK);
  ASSERT(st_netpattern_compare_view((st_netpattern_view_t){0},
                                    (st_netpattern_view_t){0}) == 0);
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){compare_a.data, compare_a.length},
             (st_netpattern_view_t){0}) > 0);
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){0},
             (st_netpattern_view_t){compare_a.data, compare_a.length}) < 0);
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){compare_a.data, compare_a.length},
             (st_netpattern_view_t){compare_a.data, compare_a.length}) == 0);
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){compare_a.data, compare_a.length},
             (st_netpattern_view_t){compare_b.data, compare_b.length}) < 0);
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){compare_b.data, compare_b.length},
             (st_netpattern_view_t){compare_a.data, compare_a.length}) > 0);
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){compare_a.data, compare_a.length},
             (st_netpattern_view_t){compare_aa.data, compare_aa.length}) < 0);
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){compare_aa.data, compare_aa.length},
             (st_netpattern_view_t){compare_a.data, compare_a.length}) > 0);
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){compare_a.data, compare_a.length},
             (st_netpattern_view_t){compare_pair.data, compare_pair.length}) <
         0);
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){compare_pair.data, compare_pair.length},
             (st_netpattern_view_t){compare_a.data, compare_a.length}) > 0);
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){compare_literal_star.data,
                                    compare_literal_star.length},
             (st_netpattern_view_t){compare_typed.data, compare_typed.length}) <
         0);
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){compare_typed.data, compare_typed.length},
             (st_netpattern_view_t){compare_literal_star.data,
                                    compare_literal_star.length}) > 0);
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){"malformed-a", sizeof("malformed-a") - 1},
             (st_netpattern_view_t){"malformed-b", sizeof("malformed-b") - 1}) <
         0);
  /* A valid outer netstring can still contain a malformed netpattern record.
   * Comparison falls back to its bytewise order without treating it as a
   * canonical typed token. */
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){"3:bad,", sizeof("3:bad,") - 1},
             (st_netpattern_view_t){"3:bae,", sizeof("3:bae,") - 1}) < 0);
  static const char malformed_short[] = "3:bad,";
  static const char malformed_long[] = "3:bad,4:more,";
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){.data = malformed_short, .length = 0},
             (st_netpattern_view_t){.data = malformed_short,
                                    .length = sizeof(malformed_short) - 1}) <
         0);
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){.data = malformed_short,
                                    .length = sizeof(malformed_short) - 1},
             (st_netpattern_view_t){.data = malformed_short, .length = 0}) > 0);
  ASSERT(
      st_netpattern_compare_view(
          (st_netpattern_view_t){malformed_short, sizeof(malformed_short) - 1},
          (st_netpattern_view_t){malformed_long, sizeof(malformed_long) - 1}) <
      0);
  ASSERT(st_netpattern_compare_view(
             (st_netpattern_view_t){malformed_long, sizeof(malformed_long) - 1},
             (st_netpattern_view_t){malformed_short,
                                    sizeof(malformed_short) - 1}) > 0);
  st_netpattern_free(&compare_literal_star);
  st_netpattern_free(&compare_typed);
  st_netpattern_free(&compare_pair);
  st_netpattern_free(&compare_b);
  st_netpattern_free(&compare_aa);
  st_netpattern_free(&compare_a);
  st_netpattern_t compound = {0};
  st_netpattern_t widened = {0};
  char *widened_cpl = NULL;
  ASSERT(st_netpattern_from_cpl_owned("dd bs={#size.MiB}", &compound) == ST_OK);
  ASSERT(
      st_netpattern_apply_type_at_owned(
          (st_netpattern_view_t){(const char *)compound.data, compound.length},
          1, ST_TYPE_ANY, &widened) == ST_OK);
  ASSERT(st_netpattern_to_cpl_view(
             (st_netpattern_view_t){(const char *)widened.data, widened.length},
             &widened_cpl) == ST_OK);
  ASSERT(strcmp(widened_cpl, "dd bs={*}") == 0);
  free(widened_cpl);
  st_netpattern_free(&widened);
  st_netpattern_free(&compound);

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
  ASSERT(st_netpattern_encode_owned(&invalid_compound_token, 1, &roundtrip) ==
         ST_ERR_INVALID);
  invalid_compound_token = compound_token;
  invalid_compound_token.capture = NULL;
  ASSERT(st_netpattern_encode_owned(&invalid_compound_token, 1, &roundtrip) ==
         ST_ERR_INVALID);
  invalid_compound_token = compound_token;
  invalid_compound_token.suffix = NULL;
  ASSERT(st_netpattern_encode_owned(&invalid_compound_token, 1, &roundtrip) ==
         ST_ERR_INVALID);
  invalid_compound_token = compound_token;
  invalid_compound_token.capture_type = ST_TYPE_LITERAL;
  ASSERT(st_netpattern_encode_owned(&invalid_compound_token, 1, &roundtrip) ==
         ST_ERR_INVALID);
  invalid_compound_token = compound_token;
  invalid_compound_token.capture_type = ST_TYPE_COUNT;
  ASSERT(st_netpattern_encode_owned(&invalid_compound_token, 1, &roundtrip) ==
         ST_ERR_INVALID);
  invalid_compound_token = compound_token;
  invalid_compound_token.prefix = "";
  invalid_compound_token.suffix = "";
  ASSERT(st_netpattern_encode_owned(&invalid_compound_token, 1, &roundtrip) ==
         ST_ERR_INVALID);
  invalid_compound_token = compound_token;
  invalid_compound_token.capture_type = ST_TYPE_NUMBER;
  ASSERT(st_netpattern_encode_owned(&invalid_compound_token, 1, &roundtrip) ==
         ST_ERR_FORMAT);

  for (size_t fail_at = 1; fail_at <= 8; fail_at++) {
    st_netpattern_t failed = {0};
    st_test_alloc_fail_at(fail_at);
    st_error_t error = st_netpattern_encode_owned(&compound_token, 1, &failed);
    st_test_alloc_reset();
    ASSERT(error == ST_ERR_MEMORY || error == ST_OK);
    if (error == ST_ERR_MEMORY)
      ASSERT(failed.data == NULL && failed.length == 0);
    st_netpattern_free(&failed);
  }

  st_token_t spaced_affix = compound_token;
  spaced_affix.prefix = "bad prefix";
  ASSERT(st_netpattern_encode_owned(&spaced_affix, 1, &roundtrip) == ST_OK);
  ASSERT(st_netpattern_to_cpl_view(
             (st_netpattern_view_t){(const char *)roundtrip.data,
                                    roundtrip.length},
             &widened_cpl) == ST_OK);
  ASSERT(strcmp(widened_cpl, "\"bad prefix\"{#path}.log") == 0);
  free(widened_cpl);
  st_netpattern_free(&roundtrip);
  spaced_affix = compound_token;
  spaced_affix.suffix = "bad suffix";
  ASSERT(st_netpattern_encode_owned(&spaced_affix, 1, &roundtrip) == ST_OK);
  ASSERT(st_netpattern_to_cpl_view(
             (st_netpattern_view_t){(const char *)roundtrip.data,
                                    roundtrip.length},
             &widened_cpl) == ST_OK);
  ASSERT(strcmp(widened_cpl, "pre{#path}\"bad suffix\"") == 0);
  free(widened_cpl);
  st_netpattern_free(&roundtrip);
  static const char *const invalid[] = {
      "",
      "   ",
      "echo \"unterminated",
      "echo pre\"mid\"",
      "echo \"\\u0000\"",
      "echo \"\\ud800\"",
      "echo \"\\udc00\"",
      "echo \"\\ud800x\"",
      "echo \"\\ud800\\u0000\"",
      "echo \"\\u0x00\"",
      "echo \"\\u123\"",
      "echo \"\\x\"",
      "echo \"\\xG0\"",
      "echo \"\\q\"",
      "echo \"x\"tail",
      "echo \\\\value",
      "echo bare\\value",
      "echo bare\"value",
      "echo }",
      "echo {unterminated",
      "dd {#path}",
      "dd pre{#path}{#n}",
      "dd pre{#unknown}",
      "echo \"line\nfeed\"",
      "echo bare\tvalue",
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    st_netpattern_t netpattern = {0};
    ASSERT(st_netpattern_from_cpl_owned(invalid[i], &netpattern) ==
           ST_ERR_INVALID);
    ASSERT(netpattern.data == NULL);
  }
  st_token_array_t decoded = {0};
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){"9:1:T,2:#n,,", sizeof("9:1:T,2:#n,,") - 1},
             &decoded) == ST_OK);
  st_token_array_free(&decoded);
  ASSERT(
      st_netpattern_decode_view(
          (st_netpattern_view_t){"09:1:T,2:#n,,", sizeof("09:1:T,2:#n,,") - 1},
          &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){"14:1:T,7:#uuid.4,,",
                                    sizeof("14:1:T,7:#uuid.4,,") - 1},
             &decoded) == ST_ERR_FORMAT);

  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){"9:1:X,2:#n,,", sizeof("9:1:X,2:#n,,") - 1},
             &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){"9:1:T,2:no,,", sizeof("9:1:T,2:no,,") - 1},
             &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){"8:1:L,1:x,", sizeof("8:1:L,1:x,") - 1},
             &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){"8:1:L,1:x,,junk",
                                    sizeof("8:1:L,1:x,,junk") - 1},
             &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode_view((st_netpattern_view_t){"x", sizeof("x") - 1},
                                   &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){"0:,", sizeof("0:,") - 1}, &decoded) ==
         ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){
                 "999999999999999999999999999999999999:x,",
                 sizeof("999999999999999999999999999999999999:x,") - 1},
             &decoded) == ST_ERR_LIMIT);
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){"08:1:L,1:x,,", sizeof("08:1:L,1:x,,") - 1},
             &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){"9:01:L,1:x,,", sizeof("9:01:L,1:x,,") - 1},
             &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){"9:1:L,01:x,,", sizeof("9:1:L,01:x,,") - 1},
             &decoded) == ST_ERR_FORMAT);
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){"9:1:T,1:*, ,", sizeof("9:1:T,1:*, ,") - 1},
             &decoded) == ST_ERR_FORMAT);

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
    shell_netstring_buffer_t malformed = test_compound_pattern(
        invalid_compounds[i].tags, invalid_compounds[i].values,
        strlen(invalid_compounds[i].tags));
    ASSERT(malformed.data != NULL);
    decoded.tokens = (st_token_t *)1;
    decoded.count = 99;
    ASSERT(st_netpattern_decode_view(
               (st_netpattern_view_t){(const char *)malformed.data,
                                      malformed.length},
               &decoded) == ST_ERR_FORMAT);
    ASSERT(decoded.tokens == NULL && decoded.count == 0);
    shell_netstring_buffer_free(&malformed);
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
    shell_netstring_buffer_t nested = test_compound_pattern(
        valid_compounds[i].tags, valid_compounds[i].values,
        strlen(valid_compounds[i].tags));
    ASSERT(nested.data != NULL);
    ASSERT(st_netpattern_decode_view(
               (st_netpattern_view_t){(const char *)nested.data, nested.length},
               &decoded) == ST_OK);
    ASSERT(decoded.count == 1 && decoded.tokens[0].compound);
    st_token_array_free(&decoded);
    shell_netstring_buffer_free(&nested);
  }

  ASSERT(st_netpattern_to_cpl_view((st_netpattern_view_t){"x", sizeof("x") - 1},
                                   &roundtrip_cpl) == ST_ERR_FORMAT);

  /* Canonical views carry arbitrary literal bytes through CPL round trips. */
  st_netpattern_t binary_pattern = {0};
  ASSERT(st_netpattern_from_cpl_owned("echo \"\\x00x\"", &binary_pattern) ==
         ST_OK);
  ASSERT(binary_pattern.length != 0 &&
         memchr(binary_pattern.data, '\0', binary_pattern.length) != NULL);
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){.data = (const char *)binary_pattern.data,
                                    .length = binary_pattern.length},
             &decoded) == ST_OK);
  ASSERT(decoded.count == 2 && decoded.tokens[1].text_length == 2 &&
         decoded.tokens[1].text[0] == '\0' && decoded.tokens[1].text[1] == 'x');
  st_token_array_free(&decoded);
  ASSERT(st_netpattern_to_cpl_view(
             (st_netpattern_view_t){.data = (const char *)binary_pattern.data,
                                    .length = binary_pattern.length},
             &roundtrip_cpl) == ST_OK);
  ASSERT(strcmp(roundtrip_cpl, "echo \"\\x00x\"") == 0);
  free(roundtrip_cpl);
  roundtrip_cpl = NULL;
  ASSERT(st_netpattern_from_cpl_owned("echo \"\\x00x\"", &roundtrip) == ST_OK);
  ASSERT(roundtrip.length == binary_pattern.length &&
         memcmp(roundtrip.data, binary_pattern.data, roundtrip.length) == 0);
  st_netpattern_free(&roundtrip);
  st_netpattern_t widened_binary = {0};
  ASSERT(st_netpattern_apply_type_at_owned(
             (st_netpattern_view_t){.data = (const char *)binary_pattern.data,
                                    .length = binary_pattern.length},
             0, ST_TYPE_WORD, &widened_binary) == ST_OK);
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){.data = (const char *)widened_binary.data,
                                    .length = widened_binary.length},
             &decoded) == ST_OK &&
         decoded.count == 2 && decoded.tokens[0].type == ST_TYPE_WORD &&
         decoded.tokens[1].text_length == 2 &&
         decoded.tokens[1].text[0] == '\0' && decoded.tokens[1].text[1] == 'x');
  st_token_array_free(&decoded);
  st_netpattern_free(&widened_binary);
  st_netpattern_free(&binary_pattern);

  /* Quoted CPL fragments keep arbitrary literal affixes separate from the
   * unquoted compound capture marker. The canonical pattern is byte-for-byte
   * reversible even when the affixes contain braces and NUL. */
  static const char compound_prefix[] = {'a', '\0', '{'};
  static const char compound_suffix[] = {'}', '\0', 'z'};
  st_token_t compound_tokens[] = {
      {.text = "tool", .type = ST_TYPE_LITERAL},
      {.text = "compound",
       .type = ST_TYPE_LITERAL,
       .compound = true,
       .prefix = compound_prefix,
       .prefix_length = sizeof(compound_prefix),
       .capture = "#n",
       .capture_length = 2,
       .suffix = compound_suffix,
       .suffix_length = sizeof(compound_suffix),
       .capture_type = ST_TYPE_NUMBER},
  };
  st_netpattern_t compound_pattern = {0};
  st_netpattern_t reparsed_compound = {0};
  ASSERT(st_netpattern_encode_owned(compound_tokens, 2, &compound_pattern) ==
         ST_OK);
  ASSERT(st_netpattern_to_cpl_view(
             (st_netpattern_view_t){.data = (const char *)compound_pattern.data,
                                    .length = compound_pattern.length},
             &roundtrip_cpl) == ST_OK);
  ASSERT(strcmp(roundtrip_cpl, "tool \"a\\x00{\"{#n}\"}\\x00z\"") == 0);
  ASSERT(st_netpattern_from_cpl_owned(roundtrip_cpl, &reparsed_compound) ==
         ST_OK);
  ASSERT(reparsed_compound.length == compound_pattern.length &&
         memcmp(reparsed_compound.data, compound_pattern.data,
                compound_pattern.length) == 0);
  free(roundtrip_cpl);
  roundtrip_cpl = NULL;
  st_netpattern_free(&reparsed_compound);
  st_netpattern_free(&compound_pattern);

  /* Explicit binary lengths must be bounded before intermediate netstring
   * allocations, and successful encodings must always be decodable. */
  char oversized_component[ST_MAX_TOKEN_LEN];
  memset(oversized_component, 'x', sizeof(oversized_component));
  st_token_t oversized_compound = {
      .text = "compound",
      .type = ST_TYPE_LITERAL,
      .compound = true,
      .prefix = oversized_component,
      .prefix_length = sizeof(oversized_component),
      .capture = "#n",
      .capture_length = 2,
      .suffix = "x",
      .suffix_length = 1,
      .capture_type = ST_TYPE_NUMBER,
  };
  st_netpattern_t oversized_pattern = {0};
  ASSERT(st_netpattern_encode_owned(&oversized_compound, 1,
                                    &oversized_pattern) == ST_ERR_LIMIT);
  ASSERT(oversized_pattern.data == NULL && oversized_pattern.length == 0);
  oversized_compound.prefix = "x";
  oversized_compound.prefix_length = 1;
  oversized_compound.suffix = oversized_component;
  oversized_compound.suffix_length = sizeof(oversized_component);
  ASSERT(st_netpattern_encode_owned(&oversized_compound, 1,
                                    &oversized_pattern) == ST_ERR_LIMIT);
  ASSERT(oversized_pattern.data == NULL && oversized_pattern.length == 0);
  oversized_compound.suffix = "x";
  oversized_compound.suffix_length = 1;
  oversized_compound.capture_length = sizeof(oversized_component);
  ASSERT(st_netpattern_encode_owned(&oversized_compound, 1,
                                    &oversized_pattern) == ST_ERR_LIMIT);
  ASSERT(oversized_pattern.data == NULL && oversized_pattern.length == 0);

  st_token_t invalid_token = {.text = NULL, .type = ST_TYPE_LITERAL};
  ASSERT(st_netpattern_encode_owned(NULL, 1, &roundtrip) == ST_ERR_INVALID);
  ASSERT(st_netpattern_encode_owned(&invalid_token, 1, &roundtrip) ==
         ST_ERR_INVALID);
  invalid_token.text = "#n";
  invalid_token.type = ST_TYPE_PATH;
  ASSERT(st_netpattern_encode_owned(&invalid_token, 1, &roundtrip) ==
         ST_ERR_FORMAT);
  ASSERT(st_netpattern_encode_owned(&invalid_token, ST_MAX_CMD_TOKENS + 1,
                                    &roundtrip) == ST_ERR_INVALID);

  char too_many_records[2048] = {0};
  for (size_t i = 0; i <= ST_MAX_CMD_TOKENS; i++)
    strcat(too_many_records, "7:1:L,0:,,");
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){too_many_records, strlen(too_many_records)},
             &decoded) == ST_ERR_LIMIT);

  char too_many_words[ST_MAX_CMD_TOKENS * 2 + 2] = {0};
  for (size_t i = 0; i <= ST_MAX_CMD_TOKENS; i++)
    strcat(too_many_words, i == 0 ? "x" : " x");
  ASSERT(st_netpattern_from_cpl_owned(too_many_words, &roundtrip) ==
         ST_ERR_INVALID);

  char controls[ST_MAX_TOKEN_LEN];
  memset(controls, 1, sizeof(controls) - 1);
  controls[sizeof(controls) - 1] = '\0';
  st_token_t expansive_tokens[4];
  for (size_t i = 0; i < 4; i++)
    expansive_tokens[i] =
        (st_token_t){.text = controls, .type = ST_TYPE_LITERAL};
  st_netpattern_t expansive = {0};
  char *expansive_cpl = NULL;
  ASSERT(st_netpattern_encode_owned(expansive_tokens, 4, &expansive) == ST_OK);
  ASSERT(st_netpattern_to_cpl_view(
             (st_netpattern_view_t){(const char *)expansive.data,
                                    expansive.length},
             &expansive_cpl) == ST_OK);
  ASSERT(strlen(expansive_cpl) > 1024);
  ASSERT(st_netpattern_from_cpl_owned(expansive_cpl, &roundtrip) == ST_OK);
  ASSERT((expansive.length != roundtrip.length ||
          memcmp(expansive.data, roundtrip.data, expansive.length)) == 0);
  st_netpattern_free(&roundtrip);
  free(expansive_cpl);
  st_netpattern_free(&expansive);

  /* Every codec stage must clear outputs and release partial allocations. */
  st_netpattern_t canonical = {0};
  ASSERT(st_netpattern_from_cpl_owned("echo \"two words\" #n", &canonical) ==
         ST_OK);
  for (size_t fail_at = 1; fail_at <= 8; fail_at++) {
    st_netpattern_t output = {0};
    st_test_alloc_fail_at(fail_at);
    st_error_t error =
        st_netpattern_from_cpl_owned("echo \"two words\" #n", &output);
    st_test_alloc_reset();
    ASSERT(error == ST_ERR_MEMORY || error == ST_OK);
    if (error == ST_ERR_MEMORY)
      ASSERT(output.data == NULL);
    st_netpattern_free(&output);

    st_token_array_t failed = {(st_token_t *)1, 99};
    st_test_alloc_fail_at(fail_at);
    error = st_netpattern_decode_view(
        (st_netpattern_view_t){(const char *)canonical.data, canonical.length},
        &failed);
    st_test_alloc_reset();
    ASSERT(error == ST_ERR_MEMORY || error == ST_OK);
    if (error == ST_ERR_MEMORY)
      ASSERT(failed.tokens == NULL && failed.count == 0);
    st_token_array_free(&failed);

    char *cpl_output = (char *)1;
    st_test_alloc_fail_at(fail_at);
    error = st_netpattern_to_cpl_view(
        (st_netpattern_view_t){(const char *)canonical.data, canonical.length},
        &cpl_output);
    st_test_alloc_reset();
    ASSERT(error == ST_ERR_MEMORY || error == ST_OK);
    if (error == ST_ERR_MEMORY)
      ASSERT(cpl_output == NULL);
    free(cpl_output);
  }
  st_netpattern_free(&canonical);
  return 1;
}

static int test_canonical_policy_boundary(void) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = st_policy_new(context);
  ASSERT(context != NULL && policy != NULL);

  ASSERT(st_netpattern_validate_view(
             (st_netpattern_view_t){"git status", sizeof("git status") - 1},
             NULL) == ST_ERR_FORMAT);
  ASSERT(st_policy_add_netpattern_view(
             policy,
             (st_netpattern_view_t){"git status", sizeof("git status") - 1}) ==
         ST_ERR_FORMAT);

  st_netpattern_t netpattern = {0};
  ASSERT(st_netpattern_from_cpl_owned("git status", &netpattern) == ST_OK);
  ASSERT(st_netpattern_validate_view(
             (st_netpattern_view_t){(const char *)netpattern.data,
                                    netpattern.length},
             NULL) == ST_OK);
  ASSERT(st_policy_add_netpattern_view(
             policy, (st_netpattern_view_t){(const char *)netpattern.data,
                                            netpattern.length}) == ST_OK);
  ASSERT(st_policy_rule_count(policy) == 1);

  st_netpattern_free(&netpattern);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return 1;
}

static int test_netpattern_validation_failures(void) {
  static const struct {
    const char *data;
    size_t length;
    st_error_t error;
  } cases[] = {
      {NULL, 0, ST_ERR_FORMAT},
      {"", 0, ST_ERR_FORMAT},
      {"git status", 10, ST_ERR_FORMAT},
      {"07:1:L,0:,,", 11, ST_ERR_FORMAT},
      {"7:1:L,0:,", 9, ST_ERR_FORMAT},
      {"7:1:X,0:,,", 10, ST_ERR_FORMAT},
      {"9:1:T,2:#x,,", sizeof("9:1:T,2:#x,,") - 1, ST_ERR_FORMAT},
      {"13:1:T,6:#n.bad,,", sizeof("13:1:T,6:#n.bad,,") - 1, ST_ERR_FORMAT},
  };
  st_token_array_t tokens = {0};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    st_netpattern_view_t view = {cases[i].data, cases[i].length};
    ASSERT(st_netpattern_validate_view(view, NULL) == cases[i].error);
    ASSERT(st_netpattern_validate_view(view, &tokens) == cases[i].error);
    ASSERT(tokens.tokens == NULL && tokens.count == 0);
  }
  char too_many[16 * (ST_MAX_CMD_TOKENS + 1)] = {0};
  for (size_t i = 0; i <= ST_MAX_CMD_TOKENS; i++)
    strcat(too_many, "7:1:L,0:,,");
  ASSERT(st_netpattern_validate_view(
             (st_netpattern_view_t){too_many, strlen(too_many)}, NULL) ==
         ST_ERR_LIMIT);
  ASSERT(st_netpattern_validate_view(
             (st_netpattern_view_t){too_many, strlen(too_many)}, &tokens) ==
         ST_ERR_LIMIT);
  ASSERT(tokens.tokens == NULL && tokens.count == 0);

  /* Framing may decode completely before policy-head grammar fails. Every
   * decoding allocation failure still releases its partial owned output. */
  static const char *const unsupported[] = {"* arg", "pre{#n}post arg"};
  for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); i++) {
    st_netpattern_t pattern = {0};
    ASSERT(st_netpattern_from_cpl_owned(unsupported[i], &pattern) == ST_OK);
    st_netpattern_view_t view = {pattern.data, pattern.length};
    st_test_alloc_reset();
    st_error_t error = st_netpattern_validate_view(view, &tokens);
    size_t allocations = st_test_alloc_count();
    st_test_alloc_reset();
    bool correct = error == ST_ERR_INVALID && allocations > 0 &&
                   tokens.tokens == NULL && tokens.count == 0;
    for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
      st_test_alloc_fail_at(fail_at);
      error = st_netpattern_validate_view(view, &tokens);
      st_test_alloc_reset();
      correct = correct && error == ST_ERR_MEMORY && tokens.tokens == NULL &&
                tokens.count == 0;
      st_token_array_free(&tokens);
    }
    st_netpattern_free(&pattern);
    ASSERT(correct);
  }
  return 1;
}

static int test_owned_netpattern_output_contract(void) {
  st_token_t tokens[] = {
      {.text = "printf", .type = ST_TYPE_LITERAL},
      {.text = "value", .type = ST_TYPE_LITERAL},
  };
  st_netpattern_t pattern = {0};

  for (size_t i = 0; i < 2; i++) {
    ASSERT(st_netpattern_encode_owned(tokens, 2, &pattern) == ST_OK);
    ASSERT(pattern.data != NULL && pattern.length != 0);
    st_netpattern_free(&pattern);
    ASSERT(pattern.data == NULL && pattern.length == 0);
    ASSERT(st_netpattern_from_cpl_owned("printf value", &pattern) == ST_OK);
    ASSERT(pattern.data != NULL && pattern.length != 0);
    st_netpattern_free(&pattern);
    ASSERT(pattern.data == NULL && pattern.length == 0);
  }
  ASSERT(st_netpattern_encode_owned(NULL, 1, &pattern) == ST_ERR_INVALID);
  ASSERT(pattern.data == NULL && pattern.length == 0);

  /* The owned encoder publishes both fields together, even when a binary
   * literal's record or the final joined buffer cannot be allocated. */
  static const char binary[] = {'v', '\0', 'x'};
  st_token_t binary_tokens[] = {
      tokens[0],
      {.text = binary, .text_length = sizeof(binary), .type = ST_TYPE_LITERAL},
  };
  st_test_alloc_reset();
  st_error_t error = st_netpattern_encode_owned(binary_tokens, 2, &pattern);
  size_t allocations = st_test_alloc_count();
  st_test_alloc_reset();
  ASSERT(error == ST_OK && allocations > 0);
  st_netpattern_free(&pattern);
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_fail_at(fail_at);
    error = st_netpattern_encode_owned(binary_tokens, 2, &pattern);
    st_test_alloc_reset();
    ASSERT(error == ST_ERR_MEMORY);
    ASSERT(pattern.data == NULL && pattern.length == 0);
  }

  st_netpattern_t source = {0};
  ASSERT(st_netpattern_encode_owned(tokens, 2, &source) == ST_OK);
  for (size_t i = 0; i < 2; i++) {
    ASSERT(st_netpattern_apply_type_at_owned(
               (st_netpattern_view_t){.data = (const char *)source.data,
                                      .length = source.length},
               1, ST_TYPE_WORD, &pattern) == ST_OK);
    ASSERT(pattern.data != NULL && pattern.length != 0);
    st_netpattern_free(&pattern);
  }
  ASSERT(st_netpattern_apply_type_at_owned((st_netpattern_view_t){0}, 1,
                                           ST_TYPE_WORD,
                                           &pattern) == ST_ERR_INVALID);
  ASSERT(pattern.data == NULL && pattern.length == 0);
  st_netpattern_free(&source);

  /* Explicit-length token bytes are borrowed views: neither literals nor
   * typed wildcard spellings need a trailing NUL. */
  static const char literal_bytes[] = {'#', 'n'};
  static const char typed_bytes[] = {'#', 'n'};
  static const char binary_bytes[] = {'a', '\0', 'b'};
  st_token_t viewed_tokens[] = {
      {.text = literal_bytes,
       .text_length = sizeof(literal_bytes),
       .type = ST_TYPE_LITERAL},
      {.text = typed_bytes,
       .text_length = sizeof(typed_bytes),
       .type = ST_TYPE_NUMBER},
      {.text = binary_bytes,
       .text_length = sizeof(binary_bytes),
       .type = ST_TYPE_LITERAL},
  };
  ASSERT(st_netpattern_encode_owned(viewed_tokens, 3, &pattern) == ST_OK);
  st_token_array_t decoded = {0};
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){.data = (const char *)pattern.data,
                                    .length = pattern.length},
             &decoded) == ST_OK);
  ASSERT(
      decoded.count == 3 && decoded.tokens[0].type == ST_TYPE_LITERAL &&
      decoded.tokens[0].text_length == sizeof(literal_bytes) &&
      memcmp(decoded.tokens[0].text, literal_bytes, sizeof(literal_bytes)) ==
          0 &&
      decoded.tokens[1].type == ST_TYPE_NUMBER &&
      decoded.tokens[1].text_length == sizeof(typed_bytes) &&
      memcmp(decoded.tokens[1].text, typed_bytes, sizeof(typed_bytes)) == 0 &&
      decoded.tokens[2].type == ST_TYPE_LITERAL &&
      decoded.tokens[2].text_length == sizeof(binary_bytes) &&
      memcmp(decoded.tokens[2].text, binary_bytes, sizeof(binary_bytes)) == 0);
  st_token_array_free(&decoded);
  st_netpattern_free(&pattern);

  static const char capture_bytes[] = {'#', 'n'};
  st_token_t viewed_compound = {
      .text = "ignored",
      .type = ST_TYPE_LITERAL,
      .compound = true,
      .prefix = "id-",
      .prefix_length = 3,
      .capture = capture_bytes,
      .capture_length = sizeof(capture_bytes),
      .suffix = ".log",
      .suffix_length = 4,
      .capture_type = ST_TYPE_NUMBER,
  };
  ASSERT(st_netpattern_encode_owned(&viewed_compound, 1, &pattern) == ST_OK);
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){.data = (const char *)pattern.data,
                                    .length = pattern.length},
             &decoded) == ST_OK &&
         decoded.count == 1 && decoded.tokens[0].compound &&
         decoded.tokens[0].capture_type == ST_TYPE_NUMBER &&
         decoded.tokens[0].capture_length == sizeof(capture_bytes) &&
         memcmp(decoded.tokens[0].capture, capture_bytes,
                sizeof(capture_bytes)) == 0);
  st_token_array_free(&decoded);
  st_netpattern_free(&pattern);
  return 1;
}

static int test_token_variant_api(void) {
  st_token_t tokens[] = {
      {.text = "42", .type = ST_TYPE_LITERAL},
      {.text = "#opt", .type = ST_TYPE_OPT},
  };
  st_token_array_t pattern = {.tokens = tokens, .count = 2};
  st_token_variant_t variants[ST_MAX_TOKEN_VARIANTS];
  size_t count =
      st_token_variants_at(&pattern, 0, variants, ST_MAX_TOKEN_VARIANTS);
  ASSERT(count >= 2);
  ASSERT(variants[0].type == ST_TYPE_LITERAL);
  ASSERT(variants[1].type == ST_TYPE_NUMBER);
  char *unterminated = malloc(2);
  ASSERT(unterminated != NULL);
  memcpy(unterminated, "42", 2);
  tokens[0].text = unterminated;
  tokens[0].text_length = 2;
  count = st_token_variants_at(&pattern, 0, variants, ST_MAX_TOKEN_VARIANTS);
  free(unterminated);
  tokens[0].text = "42ignored";
  ASSERT(count >= 2 && variants[1].type == ST_TYPE_NUMBER);
  count = st_token_variants_at(&pattern, 0, variants, ST_MAX_TOKEN_VARIANTS);
  ASSERT(count >= 2 && variants[1].type == ST_TYPE_NUMBER);
  ASSERT(st_token_variants_at(&pattern, 2, variants, ST_MAX_TOKEN_VARIANTS) ==
         0);

  return 1;
}

/* --- MAIN --- */

static int test_netpattern_iterator_boundaries(void) {
  static const struct {
    const char *payload;
    st_error_t expected;
  } records[] = {
      {"", ST_ERR_FORMAT},
      {"1:L,", ST_ERR_FORMAT},
      {"0:,1:x,", ST_ERR_FORMAT},
      {"2:LL,1:x,", ST_ERR_FORMAT},
      {"1:L,1:x,0:,", ST_ERR_FORMAT},
      {"01:L,1:x,", ST_ERR_FORMAT},
      {"1:L,184467440737095516160:", ST_ERR_FORMAT},
      {"184467440737095516160:", ST_ERR_FORMAT},
      {"1:L,3:a,b,", ST_OK},
  };
  for (size_t i = 0; i < sizeof(records) / sizeof(records[0]); i++) {
    shell_netstring_buffer_t encoded =
        test_wrap_netstring(records[i].payload, strlen(records[i].payload));
    ASSERT(encoded.data != NULL);
    st_token_array_t tokens = {0};
    ASSERT(
        st_netpattern_decode_view(
            (st_netpattern_view_t){(const char *)encoded.data, encoded.length},
            &tokens) == records[i].expected);
    if (records[i].expected != ST_OK)
      ASSERT(tokens.tokens == NULL && tokens.count == 0);
    else {
      ASSERT(tokens.count == 1 && tokens.tokens[0].text_length == 3);
      ASSERT(memcmp(tokens.tokens[0].text, "a,b", 3) == 0);
    }
    st_token_array_free(&tokens);
    if (records[i].expected != ST_OK) {
      /* Both argument orders must take the bytewise fallback for malformed
       * nested framing, not compare it as a partially decoded token. */
      static const char other[] = "8:1:L,1:z,,";
      int byte_order =
          memcmp(encoded.data, other,
                 encoded.length < sizeof(other) - 1 ? encoded.length
                                                    : sizeof(other) - 1);
      ASSERT(byte_order != 0);
      st_netpattern_view_t bad = {(const char *)encoded.data, encoded.length};
      st_netpattern_view_t raw = {other, sizeof(other) - 1};
      int forward = st_netpattern_compare_view(bad, raw);
      int backward = st_netpattern_compare_view(raw, bad);
      ASSERT((forward < 0) == (byte_order < 0));
      ASSERT((backward > 0) == (byte_order < 0));
    }
    shell_netstring_buffer_free(&encoded);
  }
  static const char overflow[] = "184467440737095516160:";
  st_token_array_t tokens = {0};
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){overflow, sizeof(overflow) - 1}, &tokens) ==
         ST_ERR_LIMIT);
  ASSERT(tokens.tokens == NULL && tokens.count == 0);
  shell_netstring_buffer_t compound =
      test_pattern_record('C', overflow, sizeof(overflow) - 1);
  ASSERT(compound.data != NULL);
  ASSERT(
      st_netpattern_decode_view(
          (st_netpattern_view_t){(const char *)compound.data, compound.length},
          &tokens) == ST_ERR_FORMAT);
  shell_netstring_buffer_free(&compound);
  static const char inner_overflow[] = "1:L,184467440737095516160:";
  shell_netstring_buffer_t part =
      test_wrap_netstring(inner_overflow, sizeof(inner_overflow) - 1);
  ASSERT(part.data != NULL);
  compound = test_pattern_record('C', part.data, part.length);
  ASSERT(compound.data != NULL);
  ASSERT(
      st_netpattern_decode_view(
          (st_netpattern_view_t){(const char *)compound.data, compound.length},
          &tokens) == ST_ERR_FORMAT);
  shell_netstring_buffer_free(&part);
  shell_netstring_buffer_free(&compound);

  /* Every prefix of a complete record is malformed, not an empty token. */
  static const char binary[] = {'x', '\0', ',', ':'};
  shell_netstring_buffer_t valid =
      test_pattern_record('L', binary, sizeof(binary));
  ASSERT(valid.data != NULL);
  for (size_t length = 0; length < valid.length; length++) {
    ASSERT(st_netpattern_decode_view(
               (st_netpattern_view_t){(const char *)valid.data, length},
               &tokens) == ST_ERR_FORMAT);
    ASSERT(tokens.tokens == NULL && tokens.count == 0);
  }
  ASSERT(st_netpattern_decode_view(
             (st_netpattern_view_t){(const char *)valid.data, valid.length},
             &tokens) == ST_OK);
  ASSERT(tokens.count == 1 && tokens.tokens[0].text_length == sizeof(binary));
  ASSERT(memcmp(tokens.tokens[0].text, binary, sizeof(binary)) == 0);
  st_token_array_free(&tokens);
  shell_netstring_buffer_free(&valid);
  return 1;
}

static int test_single_token_span_contract(void) {
  ASSERT(st_token_classify(NULL, 0) == ST_TYPE_LITERAL);
  ASSERT(st_token_classify("ignored", 0) == ST_TYPE_LITERAL);
  ASSERT(st_token_classify("42ignored", 2) == ST_TYPE_NUMBER);
  ASSERT(st_token_classify("42ignored", 9) == ST_TYPE_LITERAL);
  static const struct {
    const char *bytes;
    size_t length;
    st_token_type_t expected;
  } cases[] = {
      {"42", 2, ST_TYPE_NUMBER},        {"/tmp/a", 6, ST_TYPE_ABS_PATH},
      {"a b", 3, ST_TYPE_QUOTED_SPACE}, {"42\0x", 4, ST_TYPE_LITERAL},
      {"/a\0b", 4, ST_TYPE_ABS_PATH},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char *span = malloc(cases[i].length);
    ASSERT(span != NULL);
    memcpy(span, cases[i].bytes, cases[i].length);
    st_token_type_t actual = st_token_classify(span, cases[i].length);
    free(span);
    ASSERT(actual == cases[i].expected);
  }
  return 1;
}

int main(void) {
  printf("Running token type tests...\n\n");

  printf("Classification matrix:\n");
  TEST(test_classification_matrix);
  TEST(test_single_token_span_contract);
  TEST(test_generated_classification_boundaries);
  TEST(test_classifier_adversarial_branch_matrix);
  TEST(test_bounded_recognizer_boundary_matrix);
  TEST(test_bounded_classifier_stress_matrix);
  TEST(test_contextual_adversarial_branch_matrix);

  printf("\nType lattice:\n");
  TEST(test_type_lattice);

  printf("\nNormalisation:\n");
  TEST(test_normalization_matrix);
  TEST(test_normalization_boundaries);
  TEST(test_normalization_allocation_failures);
  TEST(test_netargv_contract);
  TEST(test_netargv_view_contract);
  TEST(test_netargv_visit_contract);
  TEST(test_netargv_visit_is_borrowed_and_allocation_free);
  TEST(test_netargv_visit_accepts_binary_payloads);
  TEST(test_netpattern_cpl_contract);
  TEST(test_cpl_parse_work_is_linear);
  TEST(test_cpl_decoded_token_limits);
  TEST(test_cpl_allocation_failures);
  TEST(test_netpattern_decode_allocation_contract);
  TEST(test_netpattern_validation_failures);
  TEST(test_netpattern_iterator_boundaries);
  TEST(test_owned_netpattern_output_contract);
  TEST(test_canonical_policy_boundary);
  TEST(test_public_helper_matrix);
  TEST(test_borrowed_policy_classifier);
  TEST(test_canonical_invalid_boundaries);
  TEST(test_netpattern_view_boundary_contract);
  TEST(test_token_variant_api);

  printf("\n========================================\n");
  printf("Results: %d/%d passed, %d failed\n", tests_passed, tests_run,
         tests_failed);

  return tests_failed > 0 ? 1 : 0;
}
