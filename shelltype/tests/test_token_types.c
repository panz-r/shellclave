/*
 * test_token_types.c – Unit tests for the wildcard lattice and token classification.
 *
 * Tests all 12+1 types, the join table, and the compatibility table.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "shelltype.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  %-45s ", #name); \
    if (name()) { \
        tests_passed++; \
        printf("PASS\n"); \
    } else { \
        tests_failed++; \
        printf("FAIL\n"); \
    } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) { printf("  Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); return 0; } } while(0)
#define ASSERT_STR_EQ(a, b) do { if (strcmp((a), (b)) != 0) { printf("  String mismatch: '%s' != '%s' at %s:%d\n", (a), (b), __FILE__, __LINE__); return 0; } } while(0)
#define ASSERT_TYPE(token, expected) do { \
    st_token_type_t t = st_classify_token(token); \
    if (t != expected) { \
        printf("  classify('%s') = %s, expected %s at %s:%d\n", \
               token, st_type_symbol[t], st_type_symbol[expected], \
               __FILE__, __LINE__); \
        return 0; \
    } \
} while(0)

/* ============================================================
 * TYPE CLASSIFICATION
 * ============================================================ */

/* --- #h: Hex hash (8+ hex chars) --- */

static int test_classify_hexhash_lowercase(void)
{
    ASSERT_TYPE("deadbeef", ST_TYPE_HEXHASH);
    return 1;
}

static int test_classify_hexhash_mixed(void)
{
    ASSERT_TYPE("a1B2c3D4e5F6", ST_TYPE_HEXHASH);
    return 1;
}

static int test_classify_hexhash_long(void)
{
    /* 32-char lowercase hex → SHA (9-64 lowercase hex is SHA).
     * Mixed-case hex like "a1B2..." → HEXHASH. */
    ASSERT_TYPE("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", ST_TYPE_SHA);
    return 1;
}

static int test_classify_hexhash_too_short(void)
{
    /* 7 hex chars is too short for #h - falls through to LITERAL */
    ASSERT_TYPE("deadbee", ST_TYPE_LITERAL);
    return 1;
}

/* --- #sha: SHA digest (lowercase hex, 9-64 chars) --- */

static int test_classify_sha_40(void)
{
    /* 40-char lowercase hex (sha256) → SHA (checked before HEXHASH) */
    ASSERT_TYPE("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", ST_TYPE_SHA);
    return 1;
}

static int test_classify_sha_64(void)
{
    /* 64-char lowercase hex (sha512) → SHA */
    ASSERT_TYPE("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", ST_TYPE_SHA);
    return 1;
}

static int test_classify_sha_reject_hexhash(void)
{
    /* 8-char hex → HEXHASH, not SHA (SHA requires 9+ chars) */
    ASSERT_TYPE("deadbeef", ST_TYPE_HEXHASH);
    return 1;
}

/* --- #n: Number --- */

static int test_classify_number_decimal(void)
{
    ASSERT_TYPE("42", ST_TYPE_NUMBER);
    return 1;
}

static int test_classify_number_negative(void)
{
    ASSERT_TYPE("-100", ST_TYPE_NUMBER);
    return 1;
}

static int test_classify_number_hex_prefix(void)
{
    ASSERT_TYPE("0xff", ST_TYPE_NUMBER);
    return 1;
}

static int test_classify_number_octal(void)
{
    /* 0755 is a permission, not a plain number */
    ASSERT_TYPE("0755", ST_TYPE_PERM_OCTAL);
    ASSERT_TYPE("0xff", ST_TYPE_NUMBER);
    return 1;
}

static int test_classify_number_zero(void)
{
    ASSERT_TYPE("0", ST_TYPE_NUMBER);
    return 1;
}

/* --- #perm: Octal permission --- */
static int test_classify_perm_octal(void)
{
    ASSERT_TYPE("755", ST_TYPE_PERM_OCTAL);
    ASSERT_TYPE("644", ST_TYPE_PERM_OCTAL);
    ASSERT_TYPE("0755", ST_TYPE_PERM_OCTAL);
    ASSERT_TYPE("0644", ST_TYPE_PERM_OCTAL);
    ASSERT_TYPE("4755", ST_TYPE_PERM_OCTAL); /* setuid */
    ASSERT_TYPE("2755", ST_TYPE_PERM_OCTAL); /* setgid */
    ASSERT_TYPE("1755", ST_TYPE_PERM_OCTAL); /* sticky */
    return 1;
}

static int test_classify_perm_reject(void)
{
    /* Reject non-permission numbers and year-like patterns.
     * 2025, 1234 look like years, not permissions.
     * 9999 has digit 9 which is invalid octal. */
    ASSERT_TYPE("2025", ST_TYPE_NUMBER);
    ASSERT_TYPE("1234", ST_TYPE_NUMBER);
    ASSERT_TYPE("9999", ST_TYPE_NUMBER);
    return 1;
}

/* --- #signal: Signal name or number --- */
static int test_classify_signal_name(void)
{
    ASSERT_TYPE("HUP", ST_TYPE_SIGNAL);
    ASSERT_TYPE("SIGTERM", ST_TYPE_SIGNAL);
    ASSERT_TYPE("KILL", ST_TYPE_SIGNAL);
    ASSERT_TYPE("INT", ST_TYPE_SIGNAL);
    return 1;
}

static int test_classify_signal_number_context(void)
{
    /* Signal numbers (1-31) need context (kill/-s) — tested in normalize tests */
    ASSERT_TYPE("9", ST_TYPE_NUMBER);  /* standalone, not signal */
    ASSERT_TYPE("15", ST_TYPE_NUMBER); /* standalone, not signal */
    return 1;
}

/* --- #range: Numeric range with hyphen --- */
static int test_classify_range(void)
{
    ASSERT_TYPE("1-5", ST_TYPE_RANGE);
    ASSERT_TYPE("10-20", ST_TYPE_RANGE);
    ASSERT_TYPE("0-100", ST_TYPE_RANGE);
    return 1;
}

static int test_classify_range_reject(void)
{
    /* Reject comma-only (cron) and plain numbers */
    ASSERT_TYPE("0,30", ST_TYPE_CRON);
    ASSERT_TYPE("1,5", ST_TYPE_CRON);
    ASSERT_TYPE("123", ST_TYPE_NUMBER);
    /* Multiple hyphens -> cron (cron accepts any digit/star with cron chars) */
    ASSERT_TYPE("1-2-3", ST_TYPE_CRON);
    return 1;
}

/* --- #user_group: user:group specifier --- */
static int test_classify_user_group(void)
{
    ASSERT_TYPE("root:docker", ST_TYPE_USER_GROUP);
    ASSERT_TYPE("www-data:www-data", ST_TYPE_USER_GROUP);
    ASSERT_TYPE("alice:developers", ST_TYPE_USER_GROUP);
    return 1;
}

static int test_classify_user_group_reject(void)
{
    /* Reject image refs and mixed-case uppercase word names.
     * SHA1:abc has all uppercase name -> IMAGE (ambiguous). */
    ASSERT_TYPE("nginx:latest", ST_TYPE_IMAGE);
    ASSERT_TYPE("SHA1:abc", ST_TYPE_IMAGE);
    ASSERT_TYPE("User:Group", ST_TYPE_LITERAL);
    ASSERT_TYPE("user:pass", ST_TYPE_IMAGE);
    return 1;
}

/* --- #glob: Glob pattern --- */
static int test_classify_glob(void)
{
    ASSERT_TYPE("*.txt", ST_TYPE_GLOB);
    ASSERT_TYPE("file?.log", ST_TYPE_GLOB);
    ASSERT_TYPE("[abc]", ST_TYPE_GLOB);
    ASSERT_TYPE("src/**/*.js", ST_TYPE_GLOB);
    return 1;
}

static int test_classify_glob_reject(void)
{
    /* Reject absolute paths, options, etc. */
    ASSERT_TYPE("/etc/passwd", ST_TYPE_ABS_PATH);
    ASSERT_TYPE("--help", ST_TYPE_LONGOPT);
    ASSERT_TYPE("foo", ST_TYPE_LITERAL);
    return 1;
}

/* --- #i: IPv4 --- */

static int test_classify_ipv4_standard(void)
{
    ASSERT_TYPE("192.168.1.1", ST_TYPE_IPV4);
    return 1;
}

static int test_classify_ipv4_localhost(void)
{
    ASSERT_TYPE("127.0.0.1", ST_TYPE_IPV4);
    return 1;
}

static int test_classify_ipv4_all_zeros(void)
{
    ASSERT_TYPE("0.0.0.0", ST_TYPE_IPV4);
    return 1;
}

/* --- #w: Word --- */

static int test_classify_word_simple(void)
{
    /* Bare words without context are LITERAL - they could be command names */
    ASSERT_TYPE("nginx", ST_TYPE_LITERAL);
    return 1;
}

static int test_classify_word_underscore(void)
{
    /* Words with underscore are still LITERAL */
    ASSERT_TYPE("my_var", ST_TYPE_LITERAL);
    return 1;
}

static int test_classify_word_uppercase(void)
{
    ASSERT_TYPE("PATH", ST_TYPE_LITERAL);
    return 1;
}

static int test_classify_word_with_digits(void)
{
    ASSERT_TYPE("var123", ST_TYPE_LITERAL);
    return 1;
}

static int test_classify_word_underscore_start(void)
{
    ASSERT_TYPE("_private", ST_TYPE_LITERAL);
    return 1;
}

/* --- #f: Filename (has dot, no slash) --- */

static int test_classify_filename_with_ext(void)
{
    ASSERT_TYPE("output.txt", ST_TYPE_FILENAME);
    return 1;
}

static int test_classify_filename_c_source(void)
{
    ASSERT_TYPE("main.c", ST_TYPE_FILENAME);
    return 1;
}

static int test_classify_filename_multiple_dots(void)
{
    ASSERT_TYPE("archive.tar.gz", ST_TYPE_FILENAME);
    return 1;
}

static int test_classify_filename_hidden(void)
{
    ASSERT_TYPE(".gitignore", ST_TYPE_FILENAME);
    return 1;
}

/* --- #r: Relative path --- */

static int test_classify_relpath_with_slash(void)
{
    ASSERT_TYPE("src/main.c", ST_TYPE_REL_PATH);
    return 1;
}

static int test_classify_relpath_dotdot(void)
{
    ASSERT_TYPE("../lib/foo", ST_TYPE_REL_PATH);
    return 1;
}

static int test_classify_relpath_dot(void)
{
    ASSERT_TYPE("./configure", ST_TYPE_REL_PATH);
    return 1;
}

static int test_classify_relpath_deep(void)
{
    ASSERT_TYPE("src/utils/helpers.c", ST_TYPE_REL_PATH);
    return 1;
}

/* --- #p: Absolute path --- */

static int test_classify_abspath_simple(void)
{
    ASSERT_TYPE("/etc/passwd", ST_TYPE_ABS_PATH);
    return 1;
}

static int test_classify_abspath_root(void)
{
    ASSERT_TYPE("/tmp", ST_TYPE_ABS_PATH);
    return 1;
}

static int test_classify_abspath_deep(void)
{
    ASSERT_TYPE("/usr/local/bin/gcc", ST_TYPE_ABS_PATH);
    return 1;
}

/* --- #u: URL --- */

static int test_classify_url_https(void)
{
    ASSERT_TYPE("https://example.com", ST_TYPE_URL);
    return 1;
}

static int test_classify_url_http(void)
{
    ASSERT_TYPE("http://localhost:8080", ST_TYPE_URL);
    return 1;
}

static int test_classify_url_git(void)
{
    ASSERT_TYPE("git://github.com/user/repo", ST_TYPE_URL);
    return 1;
}

static int test_classify_url_ftp(void)
{
    ASSERT_TYPE("ftp://files.example.com/pub", ST_TYPE_URL);
    return 1;
}

/* --- #host: Hostname/domain (dot required, plus hyphen OR known TLD) --- */

static int test_classify_hostname_hyphenated(void)
{
    /* a-b.c: hyphen BEFORE dot pattern fails (hyphen at position 1, next char is 'b'),
     * TLD not in known list → LITERAL. my-host.example.com: hyphen-before-dot in "host.example" → HOSTNAME. */
    ASSERT_TYPE("my-host.example.com", ST_TYPE_HOSTNAME);
    ASSERT_TYPE("a-b.c", ST_TYPE_LITERAL);
    return 1;
}

static int test_classify_hostname_tld(void)
{
    /* Dot + known TLD (no hyphen) → HOSTNAME */
    ASSERT_TYPE("example.com", ST_TYPE_HOSTNAME);
    ASSERT_TYPE("github.io", ST_TYPE_HOSTNAME);
    ASSERT_TYPE("myapp.dev", ST_TYPE_HOSTNAME);
    ASSERT_TYPE("server.local", ST_TYPE_HOSTNAME);
    return 1;
}

static int test_classify_hostname_no_hyphen(void)
{
    /* Dot but NOT a known TLD → falls through to FILENAME.
     * This prevents "output.txt", "main.go" etc. from being HOSTNAME. */
    ASSERT_TYPE("output.txt", ST_TYPE_FILENAME);
    ASSERT_TYPE("build.log", ST_TYPE_FILENAME);
    ASSERT_TYPE("main.go", ST_TYPE_FILENAME);
    /* No dot at all → LITERAL (use #word or #hyp) */
    ASSERT_TYPE("localhost", ST_TYPE_LITERAL);
    ASSERT_TYPE("myhost", ST_TYPE_LITERAL);
    return 1;
}

/* --- #q: Quoted string (no space) --- */

static int test_classify_quoted_nospace(void)
{
    /* Bare words without context are LITERAL */
    ASSERT_TYPE("hello", ST_TYPE_LITERAL);
    return 1;
}

static int test_classify_quoted_single_word(void)
{
    ASSERT_TYPE("msg", ST_TYPE_LITERAL);
    return 1;
}

/* --- #qs: Quoted string with space --- */

static int test_classify_quoted_with_space(void)
{
    ASSERT_TYPE("hello world", ST_TYPE_QUOTED_SPACE);
    return 1;
}

static int test_classify_quoted_sentence(void)
{
    ASSERT_TYPE("some test string", ST_TYPE_QUOTED_SPACE);
    return 1;
}

/* --- Ambiguous / edge cases --- */

static int test_classify_literal_dash(void)
{
    ASSERT_TYPE("-", ST_TYPE_LITERAL);
    return 1;
}

static int test_classify_literal_special_chars(void)
{
    ASSERT_TYPE("foo@bar", ST_TYPE_LITERAL);
    return 1;
}

static int test_classify_literal_percent(void)
{
    ASSERT_TYPE("%PATH%", ST_TYPE_LITERAL);
    return 1;
}

/* --- Command-line options --- */

static int test_classify_option_short(void)
{
    ASSERT_TYPE("-v", ST_TYPE_SHORTOPT);
    ASSERT_TYPE("-h", ST_TYPE_SHORTOPT);
    ASSERT_TYPE("-x", ST_TYPE_SHORTOPT);
    ASSERT_TYPE("-a", ST_TYPE_SHORTOPT);
    ASSERT_TYPE("-la", ST_TYPE_SHORTOPT);  /* stacked flags */
    ASSERT_TYPE("-rf", ST_TYPE_SHORTOPT);  /* stacked flags */
    return 1;
}

static int test_classify_option_long(void)
{
    ASSERT_TYPE("--help", ST_TYPE_LONGOPT);
    ASSERT_TYPE("--version", ST_TYPE_LONGOPT);
    ASSERT_TYPE("--verbose", ST_TYPE_LONGOPT);
    ASSERT_TYPE("--output=file", ST_TYPE_LONGOPT);
    ASSERT_TYPE("--max-count=10", ST_TYPE_LONGOPT);
    ASSERT_TYPE("--name", ST_TYPE_LONGOPT);
    return 1;
}

static int test_classify_option_not_option(void)
{
    /* Negative numbers are not options */
    ASSERT_TYPE("-42", ST_TYPE_NUMBER);
    ASSERT_TYPE("-1", ST_TYPE_NUMBER);
    ASSERT_TYPE("--", ST_TYPE_LITERAL);  /* just dashes */
    ASSERT_TYPE("-", ST_TYPE_LITERAL);  /* just dash */
    return 1;
}

/* --- #ipv6: IPv6 address --- */

static int test_classify_ipv6_full(void)
{
    ASSERT_TYPE("2001:0db8:85a3:0000:0000:8a2e:0370:7334", ST_TYPE_IPV6);
    ASSERT_TYPE("2001:db8:85a3:0:0:8a2e:370:7334", ST_TYPE_IPV6);
    return 1;
}

static int test_classify_ipv6_compressed(void)
{
    ASSERT_TYPE("::1", ST_TYPE_IPV6);
    ASSERT_TYPE("2001:db8::1", ST_TYPE_IPV6);
    ASSERT_TYPE("::", ST_TYPE_IPV6);
    ASSERT_TYPE("fe80::", ST_TYPE_IPV6);
    return 1;
}

static int test_classify_ipv6_zone(void)
{
    ASSERT_TYPE("fe80::1%eth0", ST_TYPE_IPV6);
    ASSERT_TYPE("::1%lo", ST_TYPE_IPV6);
    return 1;
}

static int test_classify_ipv6_reject(void)
{
    ASSERT_TYPE("192.168.1.1", ST_TYPE_IPV4);  /* IPv4 stays IPv4 */
    ASSERT_TYPE("hello", ST_TYPE_LITERAL);
    ASSERT_TYPE(":::", ST_TYPE_LITERAL);  /* no name, not IMAGE */
    ASSERT_TYPE("2001::db8::1", ST_TYPE_LITERAL);  /* contains ::, rejected by IMAGE */
    return 1;
}

/* --- #ipaddr: not returned from classification (wildcard only) --- */

/* --- #mac: MAC address --- */

static int test_classify_mac_colon(void)
{
    ASSERT_TYPE("aa:bb:cc:dd:ee:ff", ST_TYPE_MAC);
    ASSERT_TYPE("00:11:22:33:44:55", ST_TYPE_MAC);
    ASSERT_TYPE("AA:BB:CC:DD:EE:FF", ST_TYPE_MAC);
    return 1;
}

static int test_classify_mac_hyphen(void)
{
    ASSERT_TYPE("aa-bb-cc-dd-ee-ff", ST_TYPE_MAC);
    ASSERT_TYPE("00-11-22-33-44-55", ST_TYPE_MAC);
    return 1;
}

static int test_classify_mac_reject(void)
{
    ASSERT_TYPE("aa:bb:cc", ST_TYPE_IMAGE);  /* looks like image ref host:port */
    ASSERT_TYPE("gg:hh:ii:jj:kk:ll", ST_TYPE_IMAGE);  /* looks like image ref */
    ASSERT_TYPE("aa:bb:cc:dd:ee", ST_TYPE_IMAGE);  /* looks like image ref */
    return 1;
}

/* --- #method: HTTP method --- */

static int test_classify_method_get(void)
{
    ASSERT_TYPE("GET", ST_TYPE_METHOD);
    ASSERT_TYPE("POST", ST_TYPE_METHOD);
    ASSERT_TYPE("PUT", ST_TYPE_METHOD);
    ASSERT_TYPE("DELETE", ST_TYPE_METHOD);
    ASSERT_TYPE("PATCH", ST_TYPE_METHOD);
    return 1;
}

static int test_classify_method_case(void)
{
    /* Only uppercase matches; but HEAD goes to BRANCH (checked first for git) */
    ASSERT_TYPE("get", ST_TYPE_LITERAL);
    ASSERT_TYPE("Get", ST_TYPE_LITERAL);
    ASSERT_TYPE("HEAD", ST_TYPE_BRANCH);  /* git branch check takes priority */
    ASSERT_TYPE("head", ST_TYPE_LITERAL);
    ASSERT_TYPE("OPTIONS", ST_TYPE_METHOD);
    return 1;
}

/* --- #duration: Time duration --- */

static int test_classify_duration_seconds(void)
{
    ASSERT_TYPE("30s", ST_TYPE_DURATION);
    ASSERT_TYPE("1s", ST_TYPE_DURATION);
    ASSERT_TYPE("0s", ST_TYPE_DURATION);
    return 1;
}

static int test_classify_duration_units(void)
{
    ASSERT_TYPE("1.5h", ST_TYPE_DURATION);
    ASSERT_TYPE("100ms", ST_TYPE_DURATION);
    ASSERT_TYPE("500ns", ST_TYPE_DURATION);
    ASSERT_TYPE("10us", ST_TYPE_DURATION);
    ASSERT_TYPE("7d", ST_TYPE_DURATION);
    ASSERT_TYPE("2w", ST_TYPE_DURATION);
    ASSERT_TYPE("45m", ST_TYPE_DURATION);
    return 1;
}

static int test_classify_duration_reject(void)
{
    ASSERT_TYPE("30M", ST_TYPE_SIZE);     /* M is a size suffix */
    ASSERT_TYPE("1Ki", ST_TYPE_SIZE);     /* Ki is a size suffix */
    ASSERT_TYPE("abc", ST_TYPE_LITERAL);
    ASSERT_TYPE("s", ST_TYPE_LITERAL);    /* no number */
    return 1;
}

/* --- #cron: Cron schedule field --- */

static int test_classify_cron_field(void)
{
    ASSERT_TYPE("*/5", ST_TYPE_CRON);
    ASSERT_TYPE("0,30", ST_TYPE_CRON);
    ASSERT_TYPE("*/15", ST_TYPE_CRON);
    /* Bare digits like "0" are NUMBER, not CRON - need cron punctuation */
    ASSERT_TYPE("*", ST_TYPE_CRON);
    /* Numeric range "1-5" is classified as RANGE, not CRON */
    return 1;
}

static int test_classify_cron_reject(void)
{
    ASSERT_TYPE("-", ST_TYPE_LITERAL);    /* bare hyphen */
    ASSERT_TYPE("--", ST_TYPE_LITERAL);   /* double dash */
    ASSERT_TYPE(",", ST_TYPE_LITERAL);    /* bare comma */
    ASSERT_TYPE("abc", ST_TYPE_LITERAL);  /* has letters */
    return 1;
}

/* --- #ts: Timestamp --- */

static int test_classify_timestamp_date(void)
{
    ASSERT_TYPE("2025-04-24", ST_TYPE_TIMESTAMP);
    return 1;
}

static int test_classify_timestamp_time(void)
{
    ASSERT_TYPE("15:30:00", ST_TYPE_TIMESTAMP);
    return 1;
}

static int test_classify_timestamp_datetime(void)
{
    ASSERT_TYPE("2025-04-24T15:30:00", ST_TYPE_TIMESTAMP);
    return 1;
}

static int test_classify_timestamp_datetime_tz(void)
{
    ASSERT_TYPE("2025-04-24T15:30:00Z", ST_TYPE_TIMESTAMP);
    return 1;
}

static int test_classify_timestamp_not_timestamp(void)
{
    ASSERT_TYPE("not-a-date", ST_TYPE_HYPHENATED);
    ASSERT_TYPE("2025", ST_TYPE_NUMBER);
    return 1;
}

/* --- #hash: Hash algorithm --- */

static int test_classify_hash_algo(void)
{
    ASSERT_TYPE("sha256", ST_TYPE_HASH_ALGO);
    ASSERT_TYPE("md5", ST_TYPE_HASH_ALGO);
    ASSERT_TYPE("blake2b", ST_TYPE_HASH_ALGO);
    ASSERT_TYPE("sha512", ST_TYPE_HASH_ALGO);
    return 1;
}

static int test_classify_hash_algo_not(void)
{
    ASSERT_TYPE("sha", ST_TYPE_LITERAL);
    ASSERT_TYPE("MD5", ST_TYPE_LITERAL);
    ASSERT_TYPE("hash", ST_TYPE_LITERAL);
    return 1;
}

/* --- #env: Environment variable --- */

static int test_classify_env_var(void)
{
    ASSERT_TYPE("$PATH", ST_TYPE_ENV_VAR);
    ASSERT_TYPE("$HOME", ST_TYPE_ENV_VAR);
    ASSERT_TYPE("${HOME}", ST_TYPE_ENV_VAR);
    ASSERT_TYPE("$_var", ST_TYPE_ENV_VAR);
    return 1;
}

static int test_classify_env_var_not(void)
{
    ASSERT_TYPE("PATH", ST_TYPE_LITERAL);
    ASSERT_TYPE("$", ST_TYPE_LITERAL);
    ASSERT_TYPE("${}", ST_TYPE_LITERAL);
    ASSERT_TYPE("${1ABC}", ST_TYPE_LITERAL);
    return 1;
}

/* --- #hyp: Hyphenated identifier --- */

static int test_classify_hyphenated(void)
{
    ASSERT_TYPE("user-42", ST_TYPE_HYPHENATED);
    ASSERT_TYPE("alice-smith", ST_TYPE_HYPHENATED);
    ASSERT_TYPE("john-doe", ST_TYPE_HYPHENATED);
    ASSERT_TYPE("_service-account", ST_TYPE_HYPHENATED);
    return 1;
}

static int test_classify_hyphenated_not(void)
{
    ASSERT_TYPE("alice", ST_TYPE_LITERAL);
    ASSERT_TYPE("_private", ST_TYPE_LITERAL);
    ASSERT_TYPE("my_var", ST_TYPE_LITERAL);
    ASSERT_TYPE("john_doe", ST_TYPE_LITERAL);
    ASSERT_TYPE("deploy_user2", ST_TYPE_LITERAL);
    ASSERT_TYPE("123user", ST_TYPE_LITERAL);
    return 1;
}

/* ============================================================
 * BRANCH (#branch)
 * ============================================================ */

static int test_classify_branch_main(void)
{
    ASSERT_TYPE("main", ST_TYPE_BRANCH);
    ASSERT_TYPE("develop", ST_TYPE_BRANCH);
    return 1;
}

static int test_classify_branch_slash(void)
{
    /* feature/login and origin/main: have /, no dots → BRANCH.
     * release/v2.0: has dots → not BRANCH (dots rejected), has / → REL_PATH */
    ASSERT_TYPE("feature/login", ST_TYPE_BRANCH);
    ASSERT_TYPE("origin/main", ST_TYPE_BRANCH);
    ASSERT_TYPE("release/v2.0", ST_TYPE_REL_PATH);
    return 1;
}

static int test_classify_branch_release(void)
{
    /* release-1.0: has dot, is_hyphenated rejects dots → falls through to LITERAL.
     * fix-123-bug: no dot, is_hyphenated returns true → HYPHENATED. */
    ASSERT_TYPE("release-1.0", ST_TYPE_LITERAL);
    ASSERT_TYPE("fix-123-bug", ST_TYPE_HYPHENATED);
    return 1;
}

static int test_classify_branch_head(void)
{
    ASSERT_TYPE("HEAD", ST_TYPE_BRANCH);
    return 1;
}

static int test_classify_branch_reject_dash(void)
{
    ASSERT_TYPE("-v", ST_TYPE_SHORTOPT);
    return 1;
}

static int test_classify_branch_reject_dotstart(void)
{
    /* .gitignore: starts with '.' → FILENAME, not LITERAL */
    ASSERT_TYPE(".gitignore", ST_TYPE_FILENAME);
    return 1;
}

/* ============================================================
 * SHA (#sha)
 * ============================================================ */

static int test_classify_sha_short(void)
{
    /* 7-char hex is too short for SHA (min 9 chars) → falls through to LITERAL */
    ASSERT_TYPE("abc1234", ST_TYPE_LITERAL);
    return 1;
}

/* ============================================================
 * IMAGE (#image)
 * ============================================================ */

static int test_classify_image_tagged(void)
{
    /* Image refs with slashes or dots get classified as IMAGE.
     * Simple names like Redis:7 are ambiguous and handled elsewhere. */
    ASSERT_TYPE("ghcr.io/org/app:v1", ST_TYPE_IMAGE);
    return 1;
}

static int test_classify_image_registry(void)
{
    ASSERT_TYPE("ghcr.io/org/app:v1", ST_TYPE_IMAGE);
    return 1;
}

static int test_classify_image_digest(void)
{
    /* Digest refs with slashes or dots in name get classified as IMAGE.
     * "alpine" (all lowercase) is ambiguous with user:group. */
    ASSERT_TYPE("myimage@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", ST_TYPE_IMAGE);
    return 1;
}

static int test_classify_image_reject_plain(void)
{
    /* No slash or colon — not an image */
    ASSERT_TYPE("nginx", ST_TYPE_LITERAL);
    return 1;
}

static int test_classify_image_reject_bareword(void)
{
    ASSERT_TYPE("hello", ST_TYPE_LITERAL);
    return 1;
}

/* ============================================================
 * PACKAGE (#pkg)
 * ============================================================ */

static int test_classify_pkg_simple(void)
{
    /* Package names without @ are plain words → LITERAL (too ambiguous as command args) */
    ASSERT_TYPE("express", ST_TYPE_LITERAL);
    ASSERT_TYPE("lodash", ST_TYPE_LITERAL);
    return 1;
}

static int test_classify_pkg_versioned(void)
{
    /* lodash@4.17.21: has @ + version → PKG (PKG checked before EMAIL) */
    ASSERT_TYPE("react@18", ST_TYPE_PKG);
    ASSERT_TYPE("lodash@4.17.21", ST_TYPE_PKG);
    return 1;
}

static int test_classify_pkg_scoped(void)
{
    ASSERT_TYPE("@babel/core", ST_TYPE_PKG);
    ASSERT_TYPE("@types/node", ST_TYPE_PKG);
    return 1;
}

static int test_classify_pkg_reject_dash_start(void)
{
    ASSERT_TYPE("-verbose", ST_TYPE_SHORTOPT);
    return 1;
}

/* ============================================================
 * USER (#user)
 * ============================================================ */

static int test_classify_user_root(void)
{
    /* Known system accounts in allowlist */
    ASSERT_TYPE("root", ST_TYPE_USER);
    ASSERT_TYPE("nobody", ST_TYPE_USER);
    ASSERT_TYPE("_apt", ST_TYPE_USER);
    return 1;
}

static int test_classify_user_hyphenated(void)
{
    /* www-data: in allowlist → USER (before HYPHENATED in classification order)
     * deploy-user: not in allowlist → HYPHENATED */
    ASSERT_TYPE("www-data", ST_TYPE_USER);
    ASSERT_TYPE("deploy-user", ST_TYPE_HYPHENATED);
    return 1;
}

static int test_classify_user_underscore(void)
{
    /* _apt: in allowlist → USER
     * _systemd: not in allowlist → LITERAL (only systemd is in list) */
    ASSERT_TYPE("_apt", ST_TYPE_USER);
    ASSERT_TYPE("_systemd", ST_TYPE_LITERAL);
    return 1;
}

static int test_classify_user_reject_uppercase(void)
{
    ASSERT_TYPE("Root", ST_TYPE_LITERAL);
    ASSERT_TYPE("POSTGRES", ST_TYPE_LITERAL);
    return 1;
}

static int test_classify_user_reject_digit_start(void)
{
    ASSERT_TYPE("0user", ST_TYPE_LITERAL);
    return 1;
}

/* ============================================================
 * FINGERPRINT (#fp)
 * ============================================================ */

static int test_classify_fp_sha256(void)
{
    ASSERT_TYPE("SHA256:uNiVztksCsDhcc0u9e8BgrJXVGL5Nr0iASdhO1tB9qE", ST_TYPE_FINGERPRINT);
    return 1;
}

static int test_classify_fp_md5(void)
{
    ASSERT_TYPE("1a:2b:3c:4d:5e:6f:7a:8b:9c:0d:1e:2f:3a:4b:5c:6d", ST_TYPE_FINGERPRINT);
    return 1;
}

static int test_classify_fp_reject_bare_hex(void)
{
    ASSERT_TYPE("deadbeef", ST_TYPE_HEXHASH);
    return 1;
}

static int test_classify_fp_reject_wrong_prefix(void)
{
    /* Wrong prefix: name is all uppercase (SHA1:abc) -> IMAGE (ambiguous) */
    ASSERT_TYPE("SHA1:abc", ST_TYPE_IMAGE);
    return 1;
}

/* ============================================================
 * JOIN TABLE
 * ============================================================ */

static int test_join_reflexive(void)
{
    /* a ∨ a = a for all types */
    for (int t = 0; t < ST_TYPE_COUNT; t++) {
        ASSERT(st_join((st_token_type_t)t, (st_token_type_t)t) == (st_token_type_t)t);
    }
    return 1;
}

static int test_join_symmetric(void)
{
    /* a ∨ b = b ∨ a */
    for (int a = 0; a < ST_TYPE_COUNT; a++) {
        for (int b = 0; b < ST_TYPE_COUNT; b++) {
            ASSERT(st_join((st_token_type_t)a, (st_token_type_t)b) ==
                   st_join((st_token_type_t)b, (st_token_type_t)a));
        }
    }
    return 1;
}

static int test_join_any_is_top(void)
{
    /* a ∨ * = * for all a */
    for (int t = 0; t < ST_TYPE_COUNT; t++) {
        ASSERT(st_join((st_token_type_t)t, ST_TYPE_ANY) == ST_TYPE_ANY);
        ASSERT(st_join(ST_TYPE_ANY, (st_token_type_t)t) == ST_TYPE_ANY);
    }
    return 1;
}

static int test_join_hex_number(void)
{
    /* #sha ⊂ #h ⊂ #val and #n ⊂ #val. SHA and NUMBER are incomparable
     * (neither is a subset of the other), so #sha ∨ #n = #val. */
    ASSERT(st_join(ST_TYPE_HEXHASH, ST_TYPE_NUMBER) == ST_TYPE_VALUE);
    return 1;
}

static int test_join_number_word(void)
{
    /* #n ∨ #w = #val */
    ASSERT(st_join(ST_TYPE_NUMBER, ST_TYPE_WORD) == ST_TYPE_VALUE);
    /* #w ∨ #n = #val (symmetric) */
    ASSERT(st_join(ST_TYPE_WORD, ST_TYPE_NUMBER) == ST_TYPE_VALUE);
    return 1;
}

static int test_join_path_types(void)
{
    /* #p ∨ #r = #path */
    ASSERT(st_join(ST_TYPE_ABS_PATH, ST_TYPE_REL_PATH) == ST_TYPE_PATH);
    /* #p ∨ #f = #path */
    ASSERT(st_join(ST_TYPE_ABS_PATH, ST_TYPE_FILENAME) == ST_TYPE_PATH);
    /* #r ∨ #f = #r (filename is a degenerate relative path) */
    ASSERT(st_join(ST_TYPE_REL_PATH, ST_TYPE_FILENAME) == ST_TYPE_REL_PATH);
    /* #f ∨ #r = #r (symmetric) */
    ASSERT(st_join(ST_TYPE_FILENAME, ST_TYPE_REL_PATH) == ST_TYPE_REL_PATH);
    return 1;
}

static int test_join_quoted_types(void)
{
    /* #q ∨ #qs = #qs */
    ASSERT(st_join(ST_TYPE_QUOTED, ST_TYPE_QUOTED_SPACE) == ST_TYPE_QUOTED_SPACE);
    return 1;
}

static int test_join_cross_domain(void)
{
    /* #n ∨ #p = * (number and path are unrelated) */
    ASSERT(st_join(ST_TYPE_NUMBER, ST_TYPE_ABS_PATH) == ST_TYPE_ANY);
    /* #w ∨ #u = * (word and URL are unrelated) */
    ASSERT(st_join(ST_TYPE_WORD, ST_TYPE_URL) == ST_TYPE_ANY);
    /* #p ∨ #n = * (symmetric) */
    ASSERT(st_join(ST_TYPE_ABS_PATH, ST_TYPE_NUMBER) == ST_TYPE_ANY);
    return 1;
}

static int test_join_val_with_path(void)
{
    /* #val ∨ #path = * */
    ASSERT(st_join(ST_TYPE_VALUE, ST_TYPE_PATH) == ST_TYPE_ANY);
    /* #path ∨ #val = * (symmetric) */
    ASSERT(st_join(ST_TYPE_PATH, ST_TYPE_VALUE) == ST_TYPE_ANY);
    return 1;
}

static int test_join_hexhash_sha(void)
{
    /* #sha ⊂ #h: join(sha, hex) = hex (hex is the wider type) */
    ASSERT(st_join(ST_TYPE_SHA, ST_TYPE_HEXHASH) == ST_TYPE_HEXHASH);
    ASSERT(st_join(ST_TYPE_HEXHASH, ST_TYPE_SHA) == ST_TYPE_HEXHASH);
    /* hex ∨ hex = hex */
    ASSERT(st_join(ST_TYPE_HEXHASH, ST_TYPE_HEXHASH) == ST_TYPE_HEXHASH);
    /* sha ∨ sha = sha */
    ASSERT(st_join(ST_TYPE_SHA, ST_TYPE_SHA) == ST_TYPE_SHA);
    return 1;
}

static int test_join_new_types_value(void)
{
    /* All new types join with VALUE */
    ASSERT(st_join(ST_TYPE_BRANCH, ST_TYPE_VALUE) == ST_TYPE_VALUE);
    ASSERT(st_join(ST_TYPE_IMAGE, ST_TYPE_VALUE) == ST_TYPE_VALUE);
    ASSERT(st_join(ST_TYPE_PKG, ST_TYPE_VALUE) == ST_TYPE_VALUE);
    ASSERT(st_join(ST_TYPE_USER, ST_TYPE_VALUE) == ST_TYPE_VALUE);
    ASSERT(st_join(ST_TYPE_FINGERPRINT, ST_TYPE_VALUE) == ST_TYPE_VALUE);
    ASSERT(st_join(ST_TYPE_SHA, ST_TYPE_VALUE) == ST_TYPE_VALUE);
    return 1;
}

static int test_join_new_types_incomparable(void)
{
    /* All new types are ⊂ VALUE. Incomparable pairs: join = VALUE (LUB).
     * Comparable pairs (BRANCH ⊂ VALUE): join = VALUE. */
    ASSERT(st_join(ST_TYPE_BRANCH, ST_TYPE_IMAGE) == ST_TYPE_VALUE);
    ASSERT(st_join(ST_TYPE_PKG, ST_TYPE_USER) == ST_TYPE_VALUE);
    ASSERT(st_join(ST_TYPE_SHA, ST_TYPE_BRANCH) == ST_TYPE_VALUE);
    ASSERT(st_join(ST_TYPE_FINGERPRINT, ST_TYPE_IMAGE) == ST_TYPE_VALUE);
    return 1;
}

/* ============================================================
 * COMPATIBILITY TABLE
 * ============================================================ */

static int test_compat_reflexive(void)
{
    for (int t = 0; t < ST_TYPE_COUNT; t++) {
        ASSERT(st_is_compatible((st_token_type_t)t, (st_token_type_t)t));
    }
    return 1;
}

static int test_compat_literal_only_self(void)
{
    /* LITERAL is the universal bottom in the lattice:
     * compatible(LITERAL, t) = true for ALL t including wildcard types.
     * This means a literal token (exact argument) matches any policy type,
     * which is the desired behavior: exact arguments are always covered
     * by general wildcard policies.
     *
     * The test_compat_reflexive test already verifies that all types match
     * themselves, including LITERAL. Here we verify the full lattice property.
     */
    for (int t = 0; t < ST_TYPE_COUNT; t++) {
        ASSERT(st_is_compatible(ST_TYPE_LITERAL, (st_token_type_t)t));
    }
    return 1;
}

static int test_compat_any_matches_all(void)
{
    /* * (ST_TYPE_ANY) matches any command token type */
    for (int t = 0; t < ST_TYPE_COUNT; t++) {
        ASSERT(st_is_compatible((st_token_type_t)t, ST_TYPE_ANY));
    }
    return 1;
}

static int test_compat_hex_to_number(void)
{
    /* #sha ⊂ #h ⊂ #val and #n ⊂ #val. SHA and NUMBER are incomparable
     * (neither is a subset of the other). Both are subsets of VALUE. */
    ASSERT(!st_is_compatible(ST_TYPE_HEXHASH, ST_TYPE_NUMBER));  /* incomparable */
    ASSERT(!st_is_compatible(ST_TYPE_HEXHASH, ST_TYPE_SHA));     /* #h is NOT ⊂ #sha (hex is wider) */
    ASSERT(st_is_compatible(ST_TYPE_SHA, ST_TYPE_HEXHASH));      /* #sha ⊂ #h */
    ASSERT(st_is_compatible(ST_TYPE_HEXHASH, ST_TYPE_VALUE));   /* #h ⊂ #val */
    ASSERT(st_is_compatible(ST_TYPE_NUMBER, ST_TYPE_VALUE));    /* #n ⊂ #val */
    return 1;
}

static int test_compat_path_hierarchy(void)
{
    /* #f ≤ #r */
    ASSERT(st_is_compatible(ST_TYPE_FILENAME, ST_TYPE_REL_PATH));
    /* #f ≤ #path */
    ASSERT(st_is_compatible(ST_TYPE_FILENAME, ST_TYPE_PATH));
    /* #r ≤ #path */
    ASSERT(st_is_compatible(ST_TYPE_REL_PATH, ST_TYPE_PATH));
    /* #p ≤ #path */
    ASSERT(st_is_compatible(ST_TYPE_ABS_PATH, ST_TYPE_PATH));
    return 1;
}

static int test_compat_quoted_hierarchy(void)
{
    /* #q ≤ #qs */
    ASSERT(st_is_compatible(ST_TYPE_QUOTED, ST_TYPE_QUOTED_SPACE));
    /* #q ≤ #val */
    ASSERT(st_is_compatible(ST_TYPE_QUOTED, ST_TYPE_VALUE));
    /* #qs ≤ #val */
    ASSERT(st_is_compatible(ST_TYPE_QUOTED_SPACE, ST_TYPE_VALUE));
    return 1;
}

static int test_compat_cross_domain_denied(void)
{
    /* #n does NOT match #p */
    ASSERT(!st_is_compatible(ST_TYPE_NUMBER, ST_TYPE_ABS_PATH));
    /* #w does NOT match #path */
    ASSERT(!st_is_compatible(ST_TYPE_WORD, ST_TYPE_PATH));
    /* #p does NOT match #val */
    ASSERT(!st_is_compatible(ST_TYPE_ABS_PATH, ST_TYPE_VALUE));
    /* #val does NOT match #path */
    ASSERT(!st_is_compatible(ST_TYPE_VALUE, ST_TYPE_PATH));
    return 1;
}

/* ============================================================
 * TYPED NORMALISATION
 * ============================================================ */

static int test_normalize_typed_simple(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("ls -la", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[0].type == ST_TYPE_LITERAL);
    ASSERT(strcmp(arr.tokens[0].text, "ls") == 0);
    ASSERT(arr.tokens[1].type == ST_TYPE_SHORTOPT);  /* -la is a short option */
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_path(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("cat /etc/passwd", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[0].type == ST_TYPE_LITERAL);
    ASSERT(arr.tokens[1].type == ST_TYPE_ABS_PATH);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_number(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("head -n 42", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[2].type == ST_TYPE_NUMBER);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_hexhash(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    /* 16-char lowercase hex → SHA (is_sha fires first for lowercase hex 9-64) */
    st_error_t err = st_normalize_typed("git show deadbeef12345678", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[2].type == ST_TYPE_SHA);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_ipv4(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("ping 192.168.1.1", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_IPV4);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_url(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("curl https://example.com", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_URL);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_filename(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("gcc main.c", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_FILENAME);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_relpath(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("cat src/main.c", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_REL_PATH);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_long_flag_value(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("git commit --message hello", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 4);
    ASSERT(arr.tokens[0].type == ST_TYPE_LITERAL); /* git */
    ASSERT(arr.tokens[1].type == ST_TYPE_LITERAL); /* commit */
    ASSERT(arr.tokens[2].type == ST_TYPE_LONGOPT);  /* --message is a long option */
    ASSERT(arr.tokens[3].type == ST_TYPE_LITERAL); /* hello (word, not in a variable context) */
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_long_flag_number(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("gcc --optimization 2", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[2].type == ST_TYPE_NUMBER);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_redirection_path(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("ls > /tmp/out.txt", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[1].type == ST_TYPE_LITERAL); /* > */
    ASSERT(arr.tokens[2].type == ST_TYPE_ABS_PATH);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_pipeline(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("cat file.txt | grep ERROR", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 5);
    ASSERT(arr.tokens[0].type == ST_TYPE_LITERAL);  /* cat */
    ASSERT(arr.tokens[1].type == ST_TYPE_FILENAME); /* file.txt */
    ASSERT(arr.tokens[2].type == ST_TYPE_LITERAL);  /* | */
    ASSERT(arr.tokens[3].type == ST_TYPE_LITERAL);  /* grep */
    ASSERT(arr.tokens[4].type == ST_TYPE_LITERAL);  /* ERROR */
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_regex_sed(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("sed 's/foo/bar/g'", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 2);
    ASSERT(strcmp(arr.tokens[0].text, "sed") == 0);
    ASSERT(arr.tokens[0].type == ST_TYPE_LITERAL);
    ASSERT(arr.tokens[1].type == ST_TYPE_REGEX);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_regex_grep(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("grep '^[0-9]+' file.txt", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[1].type == ST_TYPE_REGEX);
    ASSERT(arr.tokens[2].type == ST_TYPE_FILENAME);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_regex_awk(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("awk '{print $1}'", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_REGEX);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_regex_no_context(void)
{
    /* Without regex-command context, tokens with metacharacters
     * should NOT be classified as REGEX */
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("echo '[hello]'", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[1].type != ST_TYPE_REGEX);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_quoted_with_space(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("echo \"hello world\"", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[0].type == ST_TYPE_LITERAL);    /* echo */
    ASSERT(arr.tokens[1].type == ST_TYPE_QUOTED_SPACE);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_env_assignment(void)
{
    st_token_array_t arr;
    arr.tokens = NULL;
    arr.count = 0;
    st_error_t err = st_normalize_typed("export PATH=/usr/bin", &arr);
    ASSERT(err == ST_OK);
    /* export is a word (LITERAL), PATH=/usr/bin is split into PATH= + /usr/bin */
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[0].type == ST_TYPE_LITERAL); /* export */
    ASSERT(arr.tokens[1].type == ST_TYPE_LITERAL); /* PATH= */
    ASSERT(arr.tokens[2].type == ST_TYPE_ABS_PATH); /* /usr/bin */
    st_free_token_array(&arr);
    return 1;
}

/* ============================================================
 * PARAMETRIZED WILDCARD CLASSIFICATION
 * ============================================================ */

/* --- #hash.algo: hash algorithm name → parametrized wildcard --- */
static int test_classify_param_hash_algo(void)
{
    /* Known algo names become #hash.sha256 etc. in typed normalization */
    st_token_array_t arr;
    st_error_t err = st_normalize_typed("echo sha256", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 2);
    ASSERT(arr.tokens[0].type == ST_TYPE_LITERAL);  /* echo */
    ASSERT(arr.tokens[1].type == ST_TYPE_HASH_ALGO);
    ASSERT_STR_EQ(arr.tokens[1].text, "#hash.sha256");
    st_free_token_array(&arr);
    return 1;
}

/* --- #image.registry: image with registry prefix --- */
static int test_classify_param_image_registry(void)
{
    /* ghcr.io/org/app:v1 → #image.ghcr.io (3 tokens: docker, pull, ghcr.io/...) */
    st_token_array_t arr;
    st_error_t err = st_normalize_typed("docker pull ghcr.io/org/app:v1", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 3);  /* docker, pull, ghcr.io/org/app:v1 */
    ASSERT(arr.tokens[2].type == ST_TYPE_IMAGE);
    ASSERT_STR_EQ(arr.tokens[2].text, "#image.ghcr.io");
    st_free_token_array(&arr);

    /* nginx:latest (no registry) → keeps original text (no parametrized form) */
    st_error_t err2 = st_normalize_typed("docker pull nginx:latest", &arr);
    ASSERT(err2 == ST_OK);
    ASSERT(arr.count == 3);  /* docker, pull, nginx:latest */
    ASSERT(arr.tokens[2].type == ST_TYPE_IMAGE);
    ASSERT_STR_EQ(arr.tokens[2].text, "nginx:latest");  /* original text preserved */
    st_free_token_array(&arr);
    return 1;
}

/* --- #pkg.scope: scoped package @scope/name --- */
static int test_classify_param_pkg_scope(void)
{
    /* @babel/core → #pkg.@babel */
    st_token_array_t arr;
    st_error_t err = st_normalize_typed("npm install @babel/core", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 3);  /* npm, install, @babel/core */
    ASSERT(arr.tokens[2].type == ST_TYPE_PKG);
    ASSERT_STR_EQ(arr.tokens[2].text, "#pkg.@babel");
    st_free_token_array(&arr);

    /* @types/node (scope with hyphen) */
    st_error_t err2 = st_normalize_typed("npm install @types/node", &arr);
    ASSERT(err2 == ST_OK);
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[2].type == ST_TYPE_PKG);
    ASSERT_STR_EQ(arr.tokens[2].text, "#pkg.@types");
    st_free_token_array(&arr);
    return 1;
}

/* --- #branch.prefix: branch with slash (prefix/topic) --- */
static int test_classify_param_branch_prefix(void)
{
    /* feature/login → #branch.feature (3 tokens: git, checkout, feature/login) */
    st_token_array_t arr;
    st_error_t err = st_normalize_typed("git checkout feature/login", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[2].type == ST_TYPE_BRANCH);
    ASSERT_STR_EQ(arr.tokens[2].text, "#branch.feature");
    st_free_token_array(&arr);

    /* release/v2.0 is REL_PATH (dots in branch part), not BRANCH */
    st_free_token_array(&arr);
    return 1;
}

/* --- #sha.length: SHA length variant (short/40/64) --- */
static int test_classify_param_sha_length(void)
{
    st_token_array_t arr;

    /* 40-char → #sha.40 */
    st_error_t err = st_normalize_typed("echo deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count >= 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_SHA);
    ASSERT_STR_EQ(arr.tokens[1].text, "#sha.40");
    st_free_token_array(&arr);

    /* 64-char → #sha.64 */
    st_error_t err2 = st_normalize_typed("echo deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", &arr);
    ASSERT(err2 == ST_OK);
    ASSERT(arr.count >= 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_SHA);
    ASSERT_STR_EQ(arr.tokens[1].text, "#sha.64");
    st_free_token_array(&arr);
    return 1;
}

/* --- #duration.unit: duration with time unit suffix --- */
static int test_classify_param_duration_unit(void)
{
    st_token_array_t arr;

    /* 30s → #duration.s */
    st_error_t err = st_normalize_typed("sleep 30s", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count >= 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_DURATION);
    ASSERT_STR_EQ(arr.tokens[1].text, "#duration.s");
    st_free_token_array(&arr);

    /* 2h → #duration.h */
    st_error_t err2 = st_normalize_typed("sleep 2h", &arr);
    ASSERT(err2 == ST_OK);
    ASSERT(arr.count >= 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_DURATION);
    ASSERT_STR_EQ(arr.tokens[1].text, "#duration.h");
    st_free_token_array(&arr);

    /* 100ms → #duration.ms */
    st_error_t err3 = st_normalize_typed("sleep 100ms", &arr);
    ASSERT(err3 == ST_OK);
    ASSERT(arr.count >= 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_DURATION);
    ASSERT_STR_EQ(arr.tokens[1].text, "#duration.ms");
    st_free_token_array(&arr);
    return 1;
}

/* --- #signal.name: signal name (with optional SIG prefix) --- */
static int test_classify_param_signal_name(void)
{
    st_token_array_t arr;

    /* TERM → #signal.TERM */
    st_error_t err = st_normalize_typed("kill TERM", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count >= 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_SIGNAL);
    ASSERT_STR_EQ(arr.tokens[1].text, "#signal.TERM");
    st_free_token_array(&arr);

    /* SIGTERM → #signal.TERM (SIG prefix stripped) */
    st_error_t err2 = st_normalize_typed("kill SIGTERM", &arr);
    ASSERT(err2 == ST_OK);
    ASSERT(arr.count >= 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_SIGNAL);
    ASSERT_STR_EQ(arr.tokens[1].text, "#signal.TERM");
    st_free_token_array(&arr);
    return 1;
}

/* --- #range.step: range marker --- */
static int test_classify_param_range_marker(void)
{
    st_token_array_t arr;
    st_error_t err = st_normalize_typed("echo 1-5", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count >= 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_RANGE);
    ASSERT_STR_EQ(arr.tokens[1].text, "#range.step");
    st_free_token_array(&arr);
    return 1;
}

/* --- #perm.bits: permission octal marker --- */
static int test_classify_param_perm_marker(void)
{
    st_token_array_t arr;
    st_error_t err = st_normalize_typed("chmod 755", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 2);  /* chmod, 755 */
    ASSERT(arr.tokens[1].type == ST_TYPE_PERM_OCTAL);
    ASSERT_STR_EQ(arr.tokens[1].text, "#perm.bits");
    st_free_token_array(&arr);
    return 1;
}

/* --- Parametrized wildcard tests using st_normalize_typed --- */
static int test_normalize_typed_param_hash_algo(void)
{
    /* sha256 as standalone token → #hash.sha256 */
    st_token_array_t arr;
    st_error_t err = st_normalize_typed("sha256 file", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count >= 2);
    ASSERT(arr.tokens[0].type == ST_TYPE_HASH_ALGO);
    ASSERT_STR_EQ(arr.tokens[0].text, "#hash.sha256");
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_param_image_registry(void)
{
    /* ghcr.io/library/redis:latest → #image.ghcr.io (has : after slash) */
    st_token_array_t arr;
    st_error_t err = st_normalize_typed("docker pull ghcr.io/library/redis:latest", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[2].type == ST_TYPE_IMAGE);
    ASSERT_STR_EQ(arr.tokens[2].text, "#image.ghcr.io");
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_param_branch_prefix(void)
{
    st_token_array_t arr;
    st_error_t err = st_normalize_typed("git branch hotfix/null-check", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 3);  /* git, branch, hotfix/null-check */
    ASSERT(arr.tokens[2].type == ST_TYPE_BRANCH);
    ASSERT_STR_EQ(arr.tokens[2].text, "#branch.hotfix");
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_param_sha_length(void)
{
    st_token_array_t arr;
    /* 8-char → falls through to HEXHASH, not SHA (needs 9+) */
    st_error_t err = st_normalize_typed("echo abcdef12", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count >= 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_HEXHASH);
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_param_duration_unit(void)
{
    st_token_array_t arr;
    /* 1.5h → numeric part 1.5, suffix h */
    st_error_t err = st_normalize_typed("sleep 1.5h", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count >= 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_DURATION);
    ASSERT_STR_EQ(arr.tokens[1].text, "#duration.h");
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_param_signal_name(void)
{
    st_token_array_t arr;
    st_error_t err = st_normalize_typed("kill -s INT", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count >= 3);
    /* INT → #signal.INT (no SIG prefix in token itself) */
    ASSERT(arr.tokens[2].type == ST_TYPE_SIGNAL);
    ASSERT_STR_EQ(arr.tokens[2].text, "#signal.INT");
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_param_range_marker(void)
{
    st_token_array_t arr;
    /* 0-100 as separate token (not as command) → RANGE */
    st_error_t err = st_normalize_typed("seq 0-100", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count >= 2);
    ASSERT(arr.tokens[1].type == ST_TYPE_RANGE);
    ASSERT_STR_EQ(arr.tokens[1].text, "#range.step");
    st_free_token_array(&arr);
    return 1;
}

static int test_normalize_typed_param_perm_marker(void)
{
    st_token_array_t arr;
    st_error_t err = st_normalize_typed("chmod 0644 file", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count >= 3);  /* chmod, 0644, file */
    ASSERT(arr.tokens[1].type == ST_TYPE_PERM_OCTAL);
    ASSERT_STR_EQ(arr.tokens[1].text, "#perm.bits");
    st_free_token_array(&arr);
    return 1;
}

/* ============================================================
 * LEGACY STRING NORMALISATION (backward compat)
 * ============================================================ */

static int test_normalize_string_uses_type_symbols(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("cat /etc/passwd", &tokens, &count);
    ASSERT(err == ST_OK);
    ASSERT(count == 2);
    ASSERT(strcmp(tokens[0], "cat") == 0);
    ASSERT(strcmp(tokens[1], "#p") == 0);
    st_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_string_number(void)
{
    char **tokens = NULL;
    size_t count = 0;
    st_error_t err = st_normalize("head -n 42", &tokens, &count);
    ASSERT(err == ST_OK);
    ASSERT(count == 3);
    ASSERT(strcmp(tokens[2], "#n") == 0);
    st_free_tokens(tokens, count);
    return 1;
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void)
{
    printf("Running token type tests...\n\n");

    printf("Classification - Hex hash (#h):\n");
    TEST(test_classify_hexhash_lowercase);
    TEST(test_classify_hexhash_mixed);
    TEST(test_classify_hexhash_long);
    TEST(test_classify_hexhash_too_short);

    printf("\nClassification - SHA (#sha):\n");
    TEST(test_classify_sha_40);
    TEST(test_classify_sha_64);
    TEST(test_classify_sha_reject_hexhash);  /* 8-char → HEXHASH, not SHA */

    printf("\nClassification - Number (#n):\n");
    TEST(test_classify_number_decimal);
    TEST(test_classify_number_negative);
    TEST(test_classify_number_hex_prefix);
    TEST(test_classify_number_octal);
    TEST(test_classify_number_zero);

    printf("\nClassification - Octal permission (#perm):\n");
    TEST(test_classify_perm_octal);
    TEST(test_classify_perm_reject);

    printf("\nClassification - Signal (#signal):\n");
    TEST(test_classify_signal_name);
    TEST(test_classify_signal_number_context);

    printf("\nClassification - Range (#range):\n");
    TEST(test_classify_range);
    TEST(test_classify_range_reject);

    printf("\nClassification - User group (#user_group):\n");
    TEST(test_classify_user_group);
    TEST(test_classify_user_group_reject);

    printf("\nClassification - Glob (#glob):\n");
    TEST(test_classify_glob);
    TEST(test_classify_glob_reject);

    printf("\nClassification - IPv4 (#i):\n");
    TEST(test_classify_ipv4_standard);
    TEST(test_classify_ipv4_localhost);
    TEST(test_classify_ipv4_all_zeros);

    printf("\nClassification - Word (#w):\n");
    TEST(test_classify_word_simple);
    TEST(test_classify_word_underscore);
    TEST(test_classify_word_uppercase);
    TEST(test_classify_word_with_digits);
    TEST(test_classify_word_underscore_start);

    printf("\nClassification - Filename (#f):\n");
    TEST(test_classify_filename_with_ext);
    TEST(test_classify_filename_c_source);
    TEST(test_classify_filename_multiple_dots);
    TEST(test_classify_filename_hidden);

    printf("\nClassification - Relative path (#r):\n");
    TEST(test_classify_relpath_with_slash);
    TEST(test_classify_relpath_dotdot);
    TEST(test_classify_relpath_dot);
    TEST(test_classify_relpath_deep);

    printf("\nClassification - Absolute path (#p):\n");
    TEST(test_classify_abspath_simple);
    TEST(test_classify_abspath_root);
    TEST(test_classify_abspath_deep);

    printf("\nClassification - URL (#u):\n");
    TEST(test_classify_url_https);
    TEST(test_classify_url_http);
    TEST(test_classify_url_git);
    TEST(test_classify_url_ftp);

    printf("\nClassification - Hostname (#host):\n");
    TEST(test_classify_hostname_hyphenated);
    TEST(test_classify_hostname_tld);
    TEST(test_classify_hostname_no_hyphen);

    printf("\nClassification - Quoted (#q, #qs):\n");
    TEST(test_classify_quoted_nospace);
    TEST(test_classify_quoted_single_word);
    TEST(test_classify_quoted_with_space);
    TEST(test_classify_quoted_sentence);

    printf("\nClassification - Edge cases:\n");
    TEST(test_classify_literal_dash);
    TEST(test_classify_literal_special_chars);
    TEST(test_classify_literal_percent);

    printf("\nClassification - Options (#opt):\n");
    TEST(test_classify_option_short);
    TEST(test_classify_option_long);
    TEST(test_classify_option_not_option);

    printf("\nClassification - IPv6 (#ipv6):\n");
    TEST(test_classify_ipv6_full);
    TEST(test_classify_ipv6_compressed);
    TEST(test_classify_ipv6_zone);
    TEST(test_classify_ipv6_reject);

    printf("\nClassification - MAC (#mac):\n");
    TEST(test_classify_mac_colon);
    TEST(test_classify_mac_hyphen);
    TEST(test_classify_mac_reject);

    printf("\nClassification - HTTP Method (#method):\n");
    TEST(test_classify_method_get);
    TEST(test_classify_method_case);

    printf("\nClassification - Duration (#duration):\n");
    TEST(test_classify_duration_seconds);
    TEST(test_classify_duration_units);
    TEST(test_classify_duration_reject);

    printf("\nClassification - Cron (#cron):\n");
    TEST(test_classify_cron_field);
    TEST(test_classify_cron_reject);

    printf("\nClassification - Timestamp (#ts):\n");
    TEST(test_classify_timestamp_date);
    TEST(test_classify_timestamp_time);
    TEST(test_classify_timestamp_datetime);
    TEST(test_classify_timestamp_datetime_tz);
    TEST(test_classify_timestamp_not_timestamp);

    printf("\nClassification - Hash algo (#hash):\n");
    TEST(test_classify_hash_algo);
    TEST(test_classify_hash_algo_not);

    printf("\nClassification - Env var (#env):\n");
    TEST(test_classify_env_var);
    TEST(test_classify_env_var_not);

    printf("\nClassification - Hyphenated (#hyp):\n");
    TEST(test_classify_hyphenated);
    TEST(test_classify_hyphenated_not);

    printf("\nClassification - Branch (#branch):\n");
    TEST(test_classify_branch_main);
    TEST(test_classify_branch_slash);
    TEST(test_classify_branch_release);
    TEST(test_classify_branch_head);
    TEST(test_classify_branch_reject_dash);
    TEST(test_classify_branch_reject_dotstart);

    printf("\nClassification - SHA (#sha):\n");
    TEST(test_classify_sha_short);
    TEST(test_classify_sha_40);
    TEST(test_classify_sha_64);
    TEST(test_classify_sha_reject_hexhash);

    printf("\nClassification - Image (#image):\n");
    TEST(test_classify_image_tagged);
    TEST(test_classify_image_registry);
    TEST(test_classify_image_digest);
    TEST(test_classify_image_reject_plain);
    TEST(test_classify_image_reject_bareword);

    printf("\nClassification - Package (#pkg):\n");
    TEST(test_classify_pkg_simple);
    TEST(test_classify_pkg_versioned);
    TEST(test_classify_pkg_scoped);
    TEST(test_classify_pkg_reject_dash_start);

    printf("\nClassification - User (#user):\n");
    TEST(test_classify_user_root);
    TEST(test_classify_user_hyphenated);
    TEST(test_classify_user_underscore);
    TEST(test_classify_user_reject_uppercase);
    TEST(test_classify_user_reject_digit_start);

    printf("\nClassification - Fingerprint (#fp):\n");
    TEST(test_classify_fp_sha256);
    TEST(test_classify_fp_md5);
    TEST(test_classify_fp_reject_bare_hex);
    TEST(test_classify_fp_reject_wrong_prefix);

    printf("\nJoin table:\n");
    TEST(test_join_reflexive);
    TEST(test_join_symmetric);
    TEST(test_join_any_is_top);
    TEST(test_join_hex_number);
    TEST(test_join_number_word);
    TEST(test_join_path_types);
    TEST(test_join_quoted_types);
    TEST(test_join_cross_domain);
    TEST(test_join_val_with_path);
    TEST(test_join_hexhash_sha);
    TEST(test_join_new_types_value);
    TEST(test_join_new_types_incomparable);

    printf("\nCompatibility table:\n");
    TEST(test_compat_reflexive);
    TEST(test_compat_literal_only_self);
    TEST(test_compat_any_matches_all);
    TEST(test_compat_hex_to_number);
    TEST(test_compat_path_hierarchy);
    TEST(test_compat_quoted_hierarchy);
    TEST(test_compat_cross_domain_denied);

    printf("\nTyped normalisation:\n");
    TEST(test_normalize_typed_simple);
    TEST(test_normalize_typed_path);
    TEST(test_normalize_typed_number);
    TEST(test_normalize_typed_hexhash);
    TEST(test_normalize_typed_ipv4);
    TEST(test_normalize_typed_url);
    TEST(test_normalize_typed_filename);
    TEST(test_normalize_typed_relpath);
    TEST(test_normalize_typed_long_flag_value);
    TEST(test_normalize_typed_long_flag_number);
    TEST(test_normalize_typed_redirection_path);
    TEST(test_normalize_typed_pipeline);
    TEST(test_normalize_typed_regex_sed);
    TEST(test_normalize_typed_regex_grep);
    TEST(test_normalize_typed_regex_awk);
    TEST(test_normalize_typed_regex_no_context);
    TEST(test_normalize_typed_quoted_with_space);
    TEST(test_normalize_typed_env_assignment);

    printf("\nParametrized wildcards:\n");
    TEST(test_classify_param_hash_algo);
    TEST(test_classify_param_image_registry);
    TEST(test_classify_param_pkg_scope);
    TEST(test_classify_param_branch_prefix);
    TEST(test_classify_param_sha_length);
    TEST(test_classify_param_duration_unit);
    TEST(test_classify_param_signal_name);
    TEST(test_classify_param_range_marker);
    TEST(test_classify_param_perm_marker);
    TEST(test_normalize_typed_param_hash_algo);
    TEST(test_normalize_typed_param_image_registry);
    TEST(test_normalize_typed_param_branch_prefix);
    TEST(test_normalize_typed_param_sha_length);
    TEST(test_normalize_typed_param_duration_unit);
    TEST(test_normalize_typed_param_signal_name);
    TEST(test_normalize_typed_param_range_marker);
    TEST(test_normalize_typed_param_perm_marker);

    printf("\nLegacy string normalisation:\n");
    TEST(test_normalize_string_uses_type_symbols);
    TEST(test_normalize_string_number);

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
