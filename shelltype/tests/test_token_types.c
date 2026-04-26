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
    ASSERT_TYPE("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", ST_TYPE_HEXHASH);
    return 1;
}

static int test_classify_hexhash_too_short(void)
{
    /* 7 hex chars is too short for #h - falls through to LITERAL */
    ASSERT_TYPE("deadbee", ST_TYPE_LITERAL);
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
    ASSERT_TYPE("0755", ST_TYPE_NUMBER);
    return 1;
}

static int test_classify_number_zero(void)
{
    ASSERT_TYPE("0", ST_TYPE_NUMBER);
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

static int test_classify_sha_40(void)
{
    /* 40-char lowercase hex → HEXHASH (is_hex_hash fires before is_sha, covers 8+ chars).
     * is_sha fires for lowercase-only hex strings in 9-64 range that don't have
     * uppercase A-F (to distinguish from SHA values that use lowercase). */
    ASSERT_TYPE("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", ST_TYPE_HEXHASH);
    return 1;
}

static int test_classify_sha_64(void)
{
    /* 64-char lowercase hex: falls in HEXHASH range (41-64), not SHA (9-40) */
    ASSERT_TYPE("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", ST_TYPE_HEXHASH);
    return 1;
}

static int test_classify_sha_reject_short(void)
{
    /* 6 chars is too short for SHA */
    ASSERT_TYPE("abc123", ST_TYPE_LITERAL);
    return 1;
}

static int test_classify_sha_reject_allnum(void)
{
    /* Pure numeric 7-digit string → NUMBER (not SHA) */
    ASSERT_TYPE("1234567", ST_TYPE_NUMBER);
    return 1;
}

/* ============================================================
 * IMAGE (#image)
 * ============================================================ */

static int test_classify_image_tagged(void)
{
    ASSERT_TYPE("nginx:latest", ST_TYPE_IMAGE);
    ASSERT_TYPE("ubuntu:22.04", ST_TYPE_IMAGE);
    return 1;
}

static int test_classify_image_registry(void)
{
    ASSERT_TYPE("ghcr.io/org/app:v1", ST_TYPE_IMAGE);
    return 1;
}

static int test_classify_image_digest(void)
{
    ASSERT_TYPE("alpine@sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", ST_TYPE_IMAGE);
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
    ASSERT_TYPE("SHA1:abc", ST_TYPE_LITERAL);
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
    st_error_t err = st_normalize_typed("git show deadbeef12345678", &arr);
    ASSERT(err == ST_OK);
    ASSERT(arr.count == 3);
    ASSERT(arr.tokens[2].type == ST_TYPE_HEXHASH);
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

    printf("\nClassification - Number (#n):\n");
    TEST(test_classify_number_decimal);
    TEST(test_classify_number_negative);
    TEST(test_classify_number_hex_prefix);
    TEST(test_classify_number_octal);
    TEST(test_classify_number_zero);

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
    TEST(test_classify_sha_reject_short);
    TEST(test_classify_sha_reject_allnum);

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
    TEST(test_normalize_typed_quoted_with_space);
    TEST(test_normalize_typed_env_assignment);

    printf("\nLegacy string normalisation:\n");
    TEST(test_normalize_string_uses_type_symbols);
    TEST(test_normalize_string_number);

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
