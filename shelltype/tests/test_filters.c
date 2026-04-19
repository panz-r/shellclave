/**
 * test_filters.c - Unified unit tests for Bloom, Cuckoo, and Vacuum filters
 *
 * Uses a vtable (function pointer table) to run the same test logic against
 * all three filter implementations. Each filter provides a vtable that maps
 * generic operations to its type-specific functions.
 *
 * This approach eliminates code duplication and makes it trivial to add
 * tests for new filter implementations.
 */

#include "bloom_filter.h"
#include "cuckoo_filter.h"
#include "vacuum_filter.h"
#include "filter_hash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>

/* ============================================================================
 * Filter vtable - abstract interface for all filter implementations
 *
 * Each filter implementation provides a vtable that maps these generic
 * operations to its type-specific functions. The test code calls through
 * the vtable, so the same test logic works for all filters.
 *
 * The void* filter handle is the concrete filter instance (bloom_filter_t*,
 * cuckoo_filter_t*, or vacuum_filter_t*). The vtable functions cast it
 * to the correct type internally.
 * ============================================================================ */

typedef struct filter_vtable {
    const char *name;

    /* Lifecycle */
    void *(*create)(size_t capacity);
    void  (*destroy)(void *f);
    int   (*reset)(void *f);

    /* Core operations - insert/delete return 0 on success, non-zero on failure */
    int   (*insert)(void *f, const void *data, size_t len);
    bool  (*lookup)(const void *f, const void *data, size_t len);
    int   (*delete)(void *f, const void *data, size_t len);

    /* Statistics */
    size_t (*count)(const void *f);
    size_t (*memory_bytes)(const void *f);
    double (*load_factor)(const void *f);
    double (*estimated_fpr)(const void *f);

    /* Capability flags */
    bool supports_delete;
} filter_vtable_t;

/* ============================================================================
 * Bloom filter vtable implementation
 *
 * Bloom filters don't support deletion, so the delete function pointer is NULL
 * and supports_delete is false. The create function takes a target FPR, so we
 * wrap bloom_filter_create with a fixed 1% FPR for the generic interface.
 * ============================================================================ */

static void *bloom_create_wrapper(size_t capacity) {
    return (void *)bloom_filter_create(capacity, 0.01);
}

static int bloom_reset_wrapper(void *f) {
    if (!f) return -1;
    bloom_filter_reset((bloom_filter_t *)f);
    return 0;
}

static int bloom_insert_wrapper(void *f, const void *data, size_t len) {
    if (!f || !data || len == 0) return -1;
    bloom_filter_insert((bloom_filter_t *)f, data, len);
    return 0;
}

static bool bloom_lookup_wrapper(const void *f, const void *data, size_t len) {
    return bloom_filter_lookup((const bloom_filter_t *)f, data, len);
}

static int bloom_delete_wrapper(void *f, const void *data, size_t len) {
    (void)f; (void)data; (void)len;
    return -1; /* Bloom doesn't support deletion */
}

static size_t bloom_count_wrapper(const void *f) {
    if (!f) return 0;
    return bloom_filter_count((const bloom_filter_t *)f);
}

static size_t bloom_memory_wrapper(const void *f) {
    return bloom_filter_memory_bytes((const bloom_filter_t *)f);
}

static double bloom_load_wrapper(const void *f) {
    if (!f) return 0.0;
    const bloom_filter_t *bf = (const bloom_filter_t *)f;
    if (bf->count == 0) return 0.0;
    /* Bloom doesn't have a hard capacity limit, but we can estimate
     * fill level as the fraction of bits set to 1. */
    size_t num_words = (bf->num_bits + 63) / 64;
    size_t bits_set = 0;
    for (size_t i = 0; i < num_words; i++) {
        bits_set += __builtin_popcountll(bf->bits[i]);
    }
    return (double)bits_set / (double)bf->num_bits;
}

static double bloom_fpr_wrapper(const void *f) {
    return bloom_filter_estimated_fpr((const bloom_filter_t *)f);
}

static const filter_vtable_t bloom_vtable = {
    .name            = "Bloom",
    .create          = bloom_create_wrapper,
    .destroy         = (void (*)(void *))bloom_filter_destroy,
    .reset           = bloom_reset_wrapper,
    .insert          = bloom_insert_wrapper,
    .lookup          = bloom_lookup_wrapper,
    .delete          = bloom_delete_wrapper,
    .count           = bloom_count_wrapper,
    .memory_bytes    = bloom_memory_wrapper,
    .load_factor     = bloom_load_wrapper,
    .estimated_fpr   = bloom_fpr_wrapper,
    .supports_delete = false,
};

/* ============================================================================
 * Cuckoo filter vtable implementation
 *
 * Cuckoo filters support all operations. Error codes are mapped to 0 (success)
 * and non-zero (failure) for the generic interface.
 * ============================================================================ */

static void *cuckoo_create_wrapper(size_t capacity) {
    return (void *)cuckoo_filter_create(capacity, 4, 10, 0);
}

static int cuckoo_reset_wrapper(void *f) {
    if (!f) return -1;
    return cuckoo_filter_reset((cuckoo_filter_t *)f);
}

static int cuckoo_insert_wrapper(void *f, const void *data, size_t len) {
    if (!f || !data || len == 0) return -1;
    uint64_t h = filter_hash_fnv1a(data, len);
    return cuckoo_filter_insert((cuckoo_filter_t *)f, h);
}

static bool cuckoo_lookup_wrapper(const void *f, const void *data, size_t len) {
    if (!data || len == 0) return false;
    uint64_t h = filter_hash_fnv1a(data, len);
    return cuckoo_filter_lookup((const cuckoo_filter_t *)f, h);
}

static int cuckoo_delete_wrapper(void *f, const void *data, size_t len) {
    if (!f || !data || len == 0) return -1;
    uint64_t h = filter_hash_fnv1a(data, len);
    return cuckoo_filter_delete((cuckoo_filter_t *)f, h);
}

static size_t cuckoo_count_wrapper(const void *f) {
    if (!f) return 0;
    return cuckoo_filter_count((const cuckoo_filter_t *)f);
}

static size_t cuckoo_memory_wrapper(const void *f) {
    return cuckoo_filter_memory_bytes((const cuckoo_filter_t *)f);
}

static double cuckoo_load_wrapper(const void *f) {
    return cuckoo_filter_load_factor((const cuckoo_filter_t *)f);
}

static double cuckoo_fpr_wrapper(const void *f) {
    return cuckoo_filter_estimated_fpr((const cuckoo_filter_t *)f);
}

static const filter_vtable_t cuckoo_vtable = {
    .name            = "Cuckoo",
    .create          = cuckoo_create_wrapper,
    .destroy         = (void (*)(void *))cuckoo_filter_destroy,
    .reset           = cuckoo_reset_wrapper,
    .insert          = cuckoo_insert_wrapper,
    .lookup          = cuckoo_lookup_wrapper,
    .delete          = cuckoo_delete_wrapper,
    .count           = cuckoo_count_wrapper,
    .memory_bytes    = cuckoo_memory_wrapper,
    .load_factor     = cuckoo_load_wrapper,
    .estimated_fpr   = cuckoo_fpr_wrapper,
    .supports_delete = true,
};

/* ============================================================================
 * Vacuum filter vtable implementation
 * ============================================================================ */

static void *vacuum_create_wrapper(size_t capacity) {
    return (void *)vacuum_filter_create(capacity, 4, 10, 0);
}

static int vacuum_reset_wrapper(void *f) {
    if (!f) return -1;
    return vacuum_filter_reset((vacuum_filter_t *)f);
}

static int vacuum_insert_wrapper(void *f, const void *data, size_t len) {
    if (!f || !data || len == 0) return -1;
    uint64_t h = filter_hash_fnv1a(data, len);
    return vacuum_filter_insert((vacuum_filter_t *)f, h);
}

static bool vacuum_lookup_wrapper(const void *f, const void *data, size_t len) {
    if (!data || len == 0) return false;
    uint64_t h = filter_hash_fnv1a(data, len);
    return vacuum_filter_lookup((const vacuum_filter_t *)f, h);
}

static int vacuum_delete_wrapper(void *f, const void *data, size_t len) {
    if (!f || !data || len == 0) return -1;
    uint64_t h = filter_hash_fnv1a(data, len);
    return vacuum_filter_delete((vacuum_filter_t *)f, h);
}

static size_t vacuum_count_wrapper(const void *f) {
    if (!f) return 0;
    return vacuum_filter_count((const vacuum_filter_t *)f);
}

static size_t vacuum_memory_wrapper(const void *f) {
    return vacuum_filter_memory_bytes((const vacuum_filter_t *)f);
}

static double vacuum_load_wrapper(const void *f) {
    return vacuum_filter_load_factor((const vacuum_filter_t *)f);
}

static double vacuum_fpr_wrapper(const void *f) {
    return vacuum_filter_estimated_fpr((const vacuum_filter_t *)f);
}

static const filter_vtable_t vacuum_vtable = {
    .name            = "Vacuum",
    .create          = vacuum_create_wrapper,
    .destroy         = (void (*)(void *))vacuum_filter_destroy,
    .reset           = vacuum_reset_wrapper,
    .insert          = vacuum_insert_wrapper,
    .lookup          = vacuum_lookup_wrapper,
    .delete          = vacuum_delete_wrapper,
    .count           = vacuum_count_wrapper,
    .memory_bytes    = vacuum_memory_wrapper,
    .load_factor     = vacuum_load_wrapper,
    .estimated_fpr   = vacuum_fpr_wrapper,
    .supports_delete = true,
};

/* All filter vtables - the test runner iterates over this array */
static const filter_vtable_t *all_vtables[] = {
    &bloom_vtable,
    &cuckoo_vtable,
    &vacuum_vtable,
};
static const int num_vtables = sizeof(all_vtables) / sizeof(all_vtables[0]);

/* ============================================================================
 * Test framework helpers
 * ============================================================================ */

static int tests_passed = 0;
static int tests_failed = 0;
static int groups_passed = 0;
static int groups_failed = 0;
static int group_tests_passed;
static int group_tests_failed;

#define TEST(name) \
    printf("  %-50s", #name)

#define PASS() \
    do { printf("[PASS]\n"); tests_passed++; group_tests_passed++; } while(0)

#define FAIL_MSG(msg) \
    do { printf("[FAIL] %s\n", msg); tests_failed++; group_tests_failed++; } while(0)

#define ASSERT(cond, msg) \
    do { if (!(cond)) { FAIL_MSG(msg); return; } } while(0)

#define ASSERT_EQ(a, b, msg) \
    do { if ((long)(a) != (long)(b)) { printf("[FAIL] %s (got %ld, expected %ld)\n", msg, (long)(a), (long)(b)); tests_failed++; group_tests_failed++; return; } } while(0)

#define ASSERT_DBL_EQ(a, b, tol, msg) \
    do { if (fabs((a) - (b)) > (tol)) { printf("[FAIL] %s (got %f, expected %f, tol %f)\n", msg, (double)(a), (double)(b), (double)(tol)); tests_failed++; group_tests_failed++; return; } } while(0)

#define START_GROUP(name) \
    do { \
        group_tests_passed = 0; \
        group_tests_failed = 0; \
        printf("\n=== %s ===\n", name); \
    } while(0)

#define END_GROUP() \
    do { \
        if (group_tests_failed == 0) { groups_passed++; printf("  Group passed: %d/%d tests\n", group_tests_passed, group_tests_passed); } \
        else { groups_failed++; printf("  Group failed: %d/%d tests passed\n", group_tests_passed, group_tests_passed + group_tests_failed); } \
    } while(0)

/* ============================================================================
 * Test data generation
 * ============================================================================ */

static void make_test_key(uint64_t id, void *buf, size_t len) {
    memset(buf, 0, len);
    memcpy(buf, &id, sizeof(id));
}

/* ============================================================================
 * Generic tests - run against any filter via its vtable
 * ============================================================================ */

static void test_generic_create_destroy(const filter_vtable_t *vt) {
    TEST(create_destroy);
    void *f = vt->create(1000);
    ASSERT(f != NULL, "Failed to create filter");
    ASSERT_EQ(vt->count(f), 0, "New filter should have count 0");
    vt->destroy(f);
    PASS();
}

static void test_generic_insert_lookup(const filter_vtable_t *vt) {
    TEST(insert_lookup);
    void *f = vt->create(100);
    ASSERT(f != NULL, "Failed to create filter");

    const char *items[] = {"hello", "world", "test", "foo", "bar"};
    int n = sizeof(items) / sizeof(items[0]);

    for (int i = 0; i < n; i++) {
        int err = vt->insert(f, items[i], strlen(items[i]));
        ASSERT_EQ(err, 0, "Insert should succeed");
    }
    ASSERT_EQ(vt->count(f), (long)n, "Count should match inserted items");

    for (int i = 0; i < n; i++) {
        ASSERT(vt->lookup(f, items[i], strlen(items[i])),
               "Should find inserted item");
    }
    vt->destroy(f);
    PASS();
}

static void test_generic_no_false_negatives(const filter_vtable_t *vt) {
    TEST(no_false_negatives);
    void *f = vt->create(1000);
    ASSERT(f != NULL, "Failed to create filter");

    char buf[32];
    for (uint64_t i = 0; i < 500; i++) {
        make_test_key(i, buf, sizeof(buf));
        int err = vt->insert(f, buf, sizeof(buf));
        ASSERT_EQ(err, 0, "Insert should succeed");
    }

    for (uint64_t i = 0; i < 500; i++) {
        make_test_key(i, buf, sizeof(buf));
        ASSERT(vt->lookup(f, buf, sizeof(buf)),
               "No false negatives: item should be found");
    }
    vt->destroy(f);
    PASS();
}

static void test_generic_fpr(const filter_vtable_t *vt) {
    TEST(false_positive_rate);
    void *f = vt->create(10000);
    ASSERT(f != NULL, "Failed to create filter");

    char buf[32];
    int inserted = 0;
    for (uint64_t i = 0; i < 9000; i++) {
        make_test_key(i, buf, sizeof(buf));
        if (vt->insert(f, buf, sizeof(buf)) == 0) {
            inserted++;
        } else {
            break;
        }
    }

    int false_positives = 0;
    int total_queries = 100000;
    for (uint64_t i = 100000; i < 100000 + (uint64_t)total_queries; i++) {
        make_test_key(i, buf, sizeof(buf));
        if (vt->lookup(f, buf, sizeof(buf))) {
            false_positives++;
        }
    }

    double measured_fpr = (double)false_positives / (double)total_queries;
    ASSERT(measured_fpr < 0.05, "FPR too high");
    printf(" [FPR=%.4f, %d items]", measured_fpr, inserted);
    PASS();
}

static void test_generic_reset(const filter_vtable_t *vt) {
    TEST(reset);
    void *f = vt->create(100);
    ASSERT(f != NULL, "Failed to create filter");

    vt->insert(f, "test", 4);
    ASSERT(vt->lookup(f, "test", 4), "Should find item before reset");

    vt->reset(f);
    ASSERT_EQ(vt->count(f), 0, "Count should be 0 after reset");
    ASSERT(!vt->lookup(f, "test", 4), "Should not find item after reset");

    vt->destroy(f);
    PASS();
}

static void test_generic_null_ops(const filter_vtable_t *vt) {
    TEST(null_ops);
    void *f = vt->create(100);
    ASSERT(f != NULL, "Failed to create filter");

    ASSERT_EQ(vt->insert(NULL, "test", 4), -1, "NULL filter insert should fail");
    ASSERT_EQ(vt->insert(f, NULL, 4), -1, "NULL data insert should fail");
    ASSERT_EQ(vt->insert(f, "test", 0), -1, "Zero length insert should fail");

    ASSERT(!vt->lookup(NULL, "test", 4), "NULL filter lookup should return false");
    ASSERT(!vt->lookup(f, NULL, 4), "NULL data lookup should return false");
    ASSERT(!vt->lookup(f, "test", 0), "Zero length lookup should return false");

    if (vt->delete) {
        ASSERT_EQ(vt->delete(NULL, "test", 4), -1, "NULL filter delete should fail");
        ASSERT_EQ(vt->delete(f, NULL, 4), -1, "NULL data delete should fail");
    }

    vt->destroy(f);
    PASS();
}

static void test_generic_memory(const filter_vtable_t *vt) {
    TEST(memory_usage);
    void *f = vt->create(1000);
    ASSERT(f != NULL, "Failed to create filter");

    size_t mem = vt->memory_bytes(f);
    ASSERT(mem > 0, "Memory should be > 0");
    ASSERT(vt->memory_bytes(NULL) == 0, "NULL should return 0");

    vt->destroy(f);
    PASS();
}

static void test_generic_load_factor(const filter_vtable_t *vt) {
    TEST(load_factor);
    void *f = vt->create(100);
    ASSERT(f != NULL, "Failed to create filter");

    double lf = vt->load_factor(f);
    ASSERT_DBL_EQ(lf, 0.0, 0.001, "Empty filter should have 0 load factor");

    char buf[32];
    for (int i = 0; i < 50; i++) {
        make_test_key((uint64_t)i, buf, sizeof(buf));
        vt->insert(f, buf, sizeof(buf));
    }

    lf = vt->load_factor(f);
    ASSERT(lf > 0.0 && lf < 1.0, "Load factor should be between 0 and 1");
    vt->destroy(f);
    PASS();
}

static void test_generic_full_detection(const filter_vtable_t *vt) {
    TEST(full_detection);
    /* Use a small capacity to trigger full detection quickly */
    void *f = vt->create(10);
    ASSERT(f != NULL, "Failed to create filter");

    char buf[32];
    int inserted = 0;
    for (uint64_t i = 0; i < 100; i++) {
        make_test_key(i, buf, sizeof(buf));
        int err = vt->insert(f, buf, sizeof(buf));
        if (err == 0) {
            inserted++;
        } else {
            break;
        }
    }

    ASSERT(inserted > 0, "Should have inserted at least some items");
    ASSERT_EQ(vt->count(f), (long)inserted, "Count should match inserted");
    printf(" [inserted %d]", inserted);
    vt->destroy(f);
    PASS();
}

static void test_generic_different_fp_sizes(const filter_vtable_t *vt) {
    TEST(different_fp_sizes);
    /* Only cuckoo and vacuum support configurable fp sizes */
    if (vt == &bloom_vtable) {
        printf("[SKIP]");
        tests_passed++;
        group_tests_passed++;
        return;
    }

    uint8_t fp_sizes[] = {4, 8, 12, 16};
    int n = sizeof(fp_sizes) / sizeof(fp_sizes[0]);

    for (int i = 0; i < n; i++) {
        void *f;
        if (vt == &cuckoo_vtable) {
            f = cuckoo_filter_create(500, 4, fp_sizes[i], 0);
        } else {
            f = vacuum_filter_create(500, 4, fp_sizes[i], 0);
        }
        ASSERT(f != NULL, "Failed to create with fp_bits");

        char buf[32];
        int inserted = 0;
        for (uint64_t j = 0; j < 400; j++) {
            make_test_key(j, buf, sizeof(buf));
            if (vt->insert(f, buf, sizeof(buf)) == 0) {
                inserted++;
            }
        }

        int fn = 0;
        for (uint64_t j = 0; j < (uint64_t)inserted && j < 400; j++) {
            make_test_key(j, buf, sizeof(buf));
            if (!vt->lookup(f, buf, sizeof(buf))) fn++;
        }
        ASSERT(fn == 0, "False negatives in fp_bits test");

        vt->destroy(f);
    }
    PASS();
}

/* ============================================================================
 * Delete-specific tests - only for filters that support deletion
 * ============================================================================ */

static void test_generic_delete(const filter_vtable_t *vt) {
    TEST(delete);
    void *f = vt->create(100);
    ASSERT(f != NULL, "Failed to create filter");
    ASSERT(vt->supports_delete, "Filter must support delete");

    vt->insert(f, "hello", 5);
    vt->insert(f, "world", 5);
    ASSERT(vt->lookup(f, "hello", 5), "Should find hello");
    ASSERT(vt->lookup(f, "world", 5), "Should find world");

    int err = vt->delete(f, "hello", 5);
    ASSERT_EQ(err, 0, "Delete should succeed");
    ASSERT_EQ(vt->count(f), 1, "Count should be 1 after delete");

    ASSERT(!vt->lookup(f, "hello", 5), "Should not find deleted hello");
    ASSERT(vt->lookup(f, "world", 5), "Should still find world");

    vt->destroy(f);
    PASS();
}

static void test_generic_delete_not_found(const filter_vtable_t *vt) {
    TEST(delete_not_found);
    void *f = vt->create(100);
    ASSERT(f != NULL, "Failed to create filter");
    ASSERT(vt->supports_delete, "Filter must support delete");

    int err = vt->delete(f, "nonexistent", 11);
    ASSERT(err != 0, "Delete of non-existent should fail");

    vt->destroy(f);
    PASS();
}

static void test_generic_delete_reinsert(const filter_vtable_t *vt) {
    TEST(delete_reinsert);
    void *f = vt->create(100);
    ASSERT(f != NULL, "Failed to create filter");
    ASSERT(vt->supports_delete, "Filter must support delete");

    vt->insert(f, "item", 4);
    ASSERT(vt->lookup(f, "item", 4), "Should find item");

    vt->delete(f, "item", 4);
    ASSERT(!vt->lookup(f, "item", 4), "Should not find after delete");

    vt->insert(f, "item", 4);
    ASSERT(vt->lookup(f, "item", 4), "Should find after re-insert");

    vt->destroy(f);
    PASS();
}

/* ============================================================================
 * Hash helper tests - implementation-specific
 * ============================================================================ */

static void test_cuckoo_hash_helpers(void) {
    TEST(cuckoo_hash_helpers);
    for (int i = 0; i < 100; i++) {
        uint64_t h = (uint64_t)i * 0x9e3779b97f4a7c15ULL;
        uint32_t fp = cuckoo_fingerprint(h, 8);
        ASSERT(fp != 0, "Fingerprint should never be 0");
        ASSERT(fp < 256, "Fingerprint should fit in 8 bits");
    }

    uint32_t mask = 1023;
    for (int i = 0; i < 100; i++) {
        uint64_t h = (uint64_t)i * 0x9e3779b97f4a7c15ULL;
        size_t i1 = cuckoo_hash_index(h, mask);
        uint32_t fp = cuckoo_fingerprint(h, 8);
        size_t i2 = cuckoo_alt_index(i1, fp, mask);
        size_t i1_back = cuckoo_alt_index(i2, fp, mask);
        ASSERT(i1 == i1_back, "XOR symmetry broken");
    }
    PASS();
}

static void test_vacuum_hash_helpers(void) {
    TEST(vacuum_hash_helpers);
    for (int i = 0; i < 100; i++) {
        uint64_t h = (uint64_t)i * 0x9e3779b97f4a7c15ULL;
        uint32_t fp = vacuum_fingerprint(h, 8);
        ASSERT(fp != 0, "Fingerprint should never be 0");
        ASSERT(fp < 256, "Fingerprint should fit in 8 bits");
    }

    size_t num_buckets = 1000;
    for (int i = 0; i < 100; i++) {
        uint64_t h = (uint64_t)i * 0x9e3779b97f4a7c15ULL;
        size_t idx = vacuum_hash_index(h, num_buckets);
        ASSERT(idx < num_buckets, "Hash index should be within bounds");
    }
    PASS();
}

static void test_vacuum_arbitrary_table_size(void) {
    TEST(vacuum_arbitrary_table_size);
    size_t capacities[] = {100, 150, 200, 333, 500, 777, 1000};
    int n = sizeof(capacities) / sizeof(capacities[0]);

    for (int i = 0; i < n; i++) {
        vacuum_filter_t *vf = vacuum_filter_create(capacities[i], 4, 10, 0);
        ASSERT(vf != NULL, "Failed to create with capacity");

        char buf[32];
        int inserted = 0;
        int target = (int)(capacities[i] * 0.8);
        for (uint64_t j = 0; j < (uint64_t)target; j++) {
            make_test_key(j, buf, sizeof(buf));
            uint64_t h = filter_hash_fnv1a(buf, sizeof(buf));
            if (vacuum_filter_insert(vf, h) == VACUUM_OK) {
                inserted++;
            }
        }

        int fn = 0;
        for (uint64_t j = 0; j < (uint64_t)inserted; j++) {
            make_test_key(j, buf, sizeof(buf));
            uint64_t h = filter_hash_fnv1a(buf, sizeof(buf));
            if (!vacuum_filter_lookup(vf, h)) fn++;
        }
        ASSERT(fn == 0, "False negatives in arbitrary table size test");

        vacuum_filter_destroy(vf);
    }
    PASS();
}

static void test_bloom_optimal_params(void) {
    TEST(bloom_optimal_params);
    size_t bits = bloom_filter_optimal_bits(1000, 0.01);
    ASSERT(bits > 0, "Optimal bits should be > 0");

    uint8_t hashes = bloom_filter_optimal_hashes(bits, 1000);
    ASSERT(hashes > 0 && hashes <= 32, "Optimal hashes should be in valid range");

    ASSERT(bits >= 9000, "Bits should be ~9585 for 1%% FPR");
    PASS();
}

/* ============================================================================
 * Comparison tests - run all filters side by side
 * ============================================================================ */

static void test_comparison_space_efficiency(void) {
    TEST(comparison_space_efficiency);
    size_t capacity = 10000;

    void *filters[3];
    size_t mem[3];
    for (int i = 0; i < num_vtables; i++) {
        filters[i] = all_vtables[i]->create(capacity);
        ASSERT(filters[i] != NULL, "Failed to create filter");
        mem[i] = all_vtables[i]->memory_bytes(filters[i]);
    }

    printf(" [");
    for (int i = 0; i < num_vtables; i++) {
        if (i > 0) printf(", ");
        printf("%s: %zu bytes", all_vtables[i]->name, mem[i]);
    }
    printf("]");

    for (int i = 0; i < num_vtables; i++) {
        all_vtables[i]->destroy(filters[i]);
    }
    PASS();
}

static void test_comparison_insert_throughput(void) {
    TEST(comparison_insert_throughput);
    size_t capacity = 50000;

    void *filters[3];
    for (int i = 0; i < num_vtables; i++) {
        filters[i] = all_vtables[i]->create(capacity);
        ASSERT(filters[i] != NULL, "Failed to create filter");
    }

    char buf[32];
    int n = 40000;
    double times[3];

    for (int i = 0; i < num_vtables; i++) {
        clock_t start = clock();
        for (int j = 0; j < n; j++) {
            make_test_key((uint64_t)j, buf, sizeof(buf));
            all_vtables[i]->insert(filters[i], buf, sizeof(buf));
        }
        times[i] = (double)(clock() - start) / CLOCKS_PER_SEC;
    }

    printf(" [");
    for (int i = 0; i < num_vtables; i++) {
        if (i > 0) printf(", ");
        printf("%s: %.3fs", all_vtables[i]->name, times[i]);
    }
    printf("]");

    for (int i = 0; i < num_vtables; i++) {
        all_vtables[i]->destroy(filters[i]);
    }
    PASS();
}

static void test_comparison_lookup_throughput(void) {
    TEST(comparison_lookup_throughput);
    size_t capacity = 50000;

    void *filters[3];
    for (int i = 0; i < num_vtables; i++) {
        filters[i] = all_vtables[i]->create(capacity);
        ASSERT(filters[i] != NULL, "Failed to create filter");
    }

    char buf[32];
    int n = 40000;

    /* Populate all filters */
    for (int j = 0; j < n; j++) {
        make_test_key((uint64_t)j, buf, sizeof(buf));
        for (int i = 0; i < num_vtables; i++) {
            all_vtables[i]->insert(filters[i], buf, sizeof(buf));
        }
    }

    double times[3];
    for (int i = 0; i < num_vtables; i++) {
        clock_t start = clock();
        volatile int hits = 0;
        for (int j = 0; j < n; j++) {
            make_test_key((uint64_t)j, buf, sizeof(buf));
            if (all_vtables[i]->lookup(filters[i], buf, sizeof(buf))) hits++;
        }
        times[i] = (double)(clock() - start) / CLOCKS_PER_SEC;
    }

    printf(" [");
    for (int i = 0; i < num_vtables; i++) {
        if (i > 0) printf(", ");
        printf("%s: %.3fs", all_vtables[i]->name, times[i]);
    }
    printf("]");

    for (int i = 0; i < num_vtables; i++) {
        all_vtables[i]->destroy(filters[i]);
    }
    PASS();
}

static void test_comparison_deletion(void) {
    TEST(comparison_deletion_support);
    /* Only cuckoo and vacuum support deletion */
    const filter_vtable_t *deletable[] = { &cuckoo_vtable, &vacuum_vtable };
    int nd = sizeof(deletable) / sizeof(deletable[0]);

    void *filters[2];
    for (int i = 0; i < nd; i++) {
        filters[i] = deletable[i]->create(1000);
        ASSERT(filters[i] != NULL, "Failed to create filter");
    }

    char buf[32];
    for (int i = 0; i < 500; i++) {
        make_test_key((uint64_t)i, buf, sizeof(buf));
        for (int j = 0; j < nd; j++) {
            deletable[j]->insert(filters[j], buf, sizeof(buf));
        }
    }

    for (int i = 0; i < 500; i += 2) {
        make_test_key((uint64_t)i, buf, sizeof(buf));
        for (int j = 0; j < nd; j++) {
            deletable[j]->delete(filters[j], buf, sizeof(buf));
        }
    }

    for (int j = 0; j < nd; j++) {
        int errors = 0;
        for (int i = 0; i < 500; i++) {
            make_test_key((uint64_t)i, buf, sizeof(buf));
            bool found = deletable[j]->lookup(filters[j], buf, sizeof(buf));
            if (i % 2 == 0 && found) errors++;
            if (i % 2 == 1 && !found) errors++;
        }
        ASSERT(errors == 0, "Deletion errors");
    }

    for (int i = 0; i < nd; i++) {
        deletable[i]->destroy(filters[i]);
    }
    PASS();
}

/* ============================================================================
 * Main - orchestrates all tests
 *
 * Generic tests run against every filter via the vtable.
 * Implementation-specific tests run individually.
 * Comparison tests run all filters side by side.
 * ============================================================================ */

int main(void) {
    printf("FILTER UNIT TESTS\n");
    printf("=================\n");

    /* Generic tests - same logic, all filters via vtable */
    START_GROUP("Generic: Create/Destroy");
    for (int i = 0; i < num_vtables; i++) {
        printf("\n  --- %s ---\n", all_vtables[i]->name);
        test_generic_create_destroy(all_vtables[i]);
    }
    END_GROUP();

    START_GROUP("Generic: Insert/Lookup");
    for (int i = 0; i < num_vtables; i++) {
        printf("\n  --- %s ---\n", all_vtables[i]->name);
        test_generic_insert_lookup(all_vtables[i]);
    }
    END_GROUP();

    START_GROUP("Generic: No False Negatives");
    for (int i = 0; i < num_vtables; i++) {
        printf("\n  --- %s ---\n", all_vtables[i]->name);
        test_generic_no_false_negatives(all_vtables[i]);
    }
    END_GROUP();

    START_GROUP("Generic: False Positive Rate");
    for (int i = 0; i < num_vtables; i++) {
        printf("\n  --- %s ---\n", all_vtables[i]->name);
        test_generic_fpr(all_vtables[i]);
    }
    END_GROUP();

    START_GROUP("Generic: Reset");
    for (int i = 0; i < num_vtables; i++) {
        printf("\n  --- %s ---\n", all_vtables[i]->name);
        test_generic_reset(all_vtables[i]);
    }
    END_GROUP();

    START_GROUP("Generic: Null Ops");
    for (int i = 0; i < num_vtables; i++) {
        printf("\n  --- %s ---\n", all_vtables[i]->name);
        test_generic_null_ops(all_vtables[i]);
    }
    END_GROUP();

    START_GROUP("Generic: Memory");
    for (int i = 0; i < num_vtables; i++) {
        printf("\n  --- %s ---\n", all_vtables[i]->name);
        test_generic_memory(all_vtables[i]);
    }
    END_GROUP();

    START_GROUP("Generic: Load Factor");
    for (int i = 0; i < num_vtables; i++) {
        printf("\n  --- %s ---\n", all_vtables[i]->name);
        test_generic_load_factor(all_vtables[i]);
    }
    END_GROUP();

    START_GROUP("Generic: Full Detection");
    for (int i = 0; i < num_vtables; i++) {
        printf("\n  --- %s ---\n", all_vtables[i]->name);
        test_generic_full_detection(all_vtables[i]);
    }
    END_GROUP();

    START_GROUP("Generic: Different FP Sizes");
    for (int i = 0; i < num_vtables; i++) {
        printf("\n  --- %s ---\n", all_vtables[i]->name);
        test_generic_different_fp_sizes(all_vtables[i]);
    }
    END_GROUP();

    /* Delete-specific tests - only for filters that support it */
    START_GROUP("Delete: Basic");
    for (int i = 0; i < num_vtables; i++) {
        if (!all_vtables[i]->supports_delete) continue;
        printf("\n  --- %s ---\n", all_vtables[i]->name);
        test_generic_delete(all_vtables[i]);
    }
    END_GROUP();

    START_GROUP("Delete: Not Found");
    for (int i = 0; i < num_vtables; i++) {
        if (!all_vtables[i]->supports_delete) continue;
        printf("\n  --- %s ---\n", all_vtables[i]->name);
        test_generic_delete_not_found(all_vtables[i]);
    }
    END_GROUP();

    START_GROUP("Delete: Reinsert");
    for (int i = 0; i < num_vtables; i++) {
        if (!all_vtables[i]->supports_delete) continue;
        printf("\n  --- %s ---\n", all_vtables[i]->name);
        test_generic_delete_reinsert(all_vtables[i]);
    }
    END_GROUP();

    /* Implementation-specific tests */
    START_GROUP("Bloom: Optimal Params");
    test_bloom_optimal_params();
    END_GROUP();

    START_GROUP("Cuckoo: Hash Helpers");
    test_cuckoo_hash_helpers();
    END_GROUP();

    START_GROUP("Vacuum: Hash Helpers");
    test_vacuum_hash_helpers();
    END_GROUP();

    START_GROUP("Vacuum: Arbitrary Table Size");
    test_vacuum_arbitrary_table_size();
    END_GROUP();

    /* Comparison tests */
    START_GROUP("Comparison: Space Efficiency");
    test_comparison_space_efficiency();
    END_GROUP();

    START_GROUP("Comparison: Insert Throughput");
    test_comparison_insert_throughput();
    END_GROUP();

    START_GROUP("Comparison: Lookup Throughput");
    test_comparison_lookup_throughput();
    END_GROUP();

    START_GROUP("Comparison: Deletion");
    test_comparison_deletion();
    END_GROUP();

    /* Summary */
    printf("\n=================\n");
    printf("SUMMARY: %d/%d tests passed, %d/%d groups passed\n",
           tests_passed, tests_passed + tests_failed,
           groups_passed, groups_passed + groups_failed);
    if (tests_failed > 0) {
        printf("  %d test(s) failed\n", tests_failed);
    }

    return tests_failed > 0 ? 1 : 0;
}
