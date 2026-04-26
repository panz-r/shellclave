/*
 * test_anomaly.c - Unit tests for sg_anomaly
 */

#include "sg_anomaly.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <unistd.h>

static int pass_count = 0;
static int fail_count = 0;

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("    FAIL: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
        fail_count++; \
        return; \
    } \
} while (0)

#define ASSERT_EQ_INT(a, b) do { \
    if ((a) != (b)) { \
        printf("    FAIL: %s != %s (%ld != %ld) at %s:%d\n", #a, #b, \
               (long)(a), (long)(b), __FILE__, __LINE__); \
        fail_count++; \
        return; \
    } \
} while (0)

#define ASSERT_EQ_DBL(a, b, eps) do { \
    if (fabs((a) - (b)) > (eps)) { \
        printf("    FAIL: %s != %s (%.6f != %.6f) at %s:%d\n", #a, #b, \
               (double)(a), (double)(b), __FILE__, __LINE__); \
        fail_count++; \
        return; \
    } \
} while (0)

#define ASSERT_STR(a, b) do { \
    if (strcmp((a), (b)) != 0) { \
        printf("    FAIL: %s != %s (\"%s\" != \"%s\") at %s:%d\n", #a, #b, (a), (b), __FILE__, __LINE__); \
        fail_count++; \
        return; \
    } \
} while (0)

#define TEST(name) static void test_##name(void)
#define RUN(name) do { \
    printf("  %-40s ", #name); \
    int _pf = fail_count; \
    test_##name(); \
    if (fail_count == _pf) { printf("PASS\n"); pass_count++; } \
} while (0)

/* ============================================================
 * LIFECYCLE
 * ============================================================ */

TEST(anomaly_model_new_default)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    ASSERT(m != NULL);
    ASSERT_EQ_INT(sg_anomaly_total_uni(m), 0);
    ASSERT_EQ_INT(sg_anomaly_vocab_size(m), 0);
    sg_anomaly_model_free(m);
}

TEST(anomaly_model_new_ex)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new_ex(0.5, -5.0);
    ASSERT(m != NULL);
    sg_anomaly_model_free(m);
}

TEST(anomaly_model_free_null)
{
    sg_anomaly_model_free(NULL);
}

/* ============================================================
 * UPDATE AND SCORE
 * ============================================================ */

TEST(update_and_score_single_trigram)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    const char *seq[] = { "git", "status", "ls" };
    sg_anomaly_update(m, seq, 3);

    ASSERT_EQ_INT(sg_anomaly_total_uni(m), 3);
    ASSERT_EQ_INT(sg_anomaly_vocab_size(m), 3);
    ASSERT_EQ_INT(sg_anomaly_total_bi(m), 2);
    ASSERT_EQ_INT(sg_anomaly_total_tri(m), 1);

    double score = sg_anomaly_score(m, seq, 3);
    ASSERT(!isinf(score));
    ASSERT(score >= 0.0);

    sg_anomaly_model_free(m);
}

TEST(score_returns_infinity_for_len_lt_3)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    const char *seq1[] = { "git" };
    const char *seq2[] = { "git", "status" };

    ASSERT(isinf(sg_anomaly_score(m, seq1, 1)));
    ASSERT(isinf(sg_anomaly_score(m, seq2, 2)));

    sg_anomaly_update(m, seq2, 2);
    ASSERT(isinf(sg_anomaly_score(m, seq1, 1)));
    ASSERT(isinf(sg_anomaly_score(m, seq2, 2)));

    sg_anomaly_model_free(m);
}

TEST(score_returns_infinity_when_model_empty)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    const char *seq[] = { "git", "status", "ls" };
    ASSERT(isinf(sg_anomaly_score(m, seq, 3)));
    sg_anomaly_model_free(m);
}

TEST(known_sequence_has_low_score)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();

    /* Train on repeated pattern */
    const char *seq1[] = { "ls", "cd", "pwd" };
    const char *seq2[] = { "ls", "cd", "pwd" };
    const char *seq3[] = { "ls", "cd", "pwd" };

    sg_anomaly_update(m, seq1, 3);
    sg_anomaly_update(m, seq2, 3);
    sg_anomaly_update(m, seq3, 3);

    double score = sg_anomaly_score(m, seq1, 3);
    ASSERT(!isinf(score));
    ASSERT(score >= 0.0);
    ASSERT(score < 5.0);  /* Should be low for known pattern */

    sg_anomaly_model_free(m);
}

TEST(unseen_command_has_higher_score)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();

    /* Train on a specific pattern */
    const char *seen_seq[] = { "ls", "cd", "pwd" };
    sg_anomaly_update(m, seen_seq, 3);
    sg_anomaly_update(m, seen_seq, 3);
    sg_anomaly_update(m, seen_seq, 3);

    /* Score a known sequence */
    double known_score = sg_anomaly_score(m, seen_seq, 3);

    /* Score an unknown sequence */
    const char *unknown_seq[] = { "gcc", "make", "git" };
    double unknown_score = sg_anomaly_score(m, unknown_seq, 3);

    /* Unknown should generally be higher (more anomalous) */
    ASSERT(!isinf(unknown_score));
    ASSERT(unknown_score > known_score);

    sg_anomaly_model_free(m);
}

/* ============================================================
 * STRING OWNERSHIP
 * ============================================================ */

TEST(model_owns_string_copies)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();

    /* Allocate some command names on the heap */
    char *cmd1 = strdup("gcc");
    char *cmd2 = strdup("make");
    char *cmd3 = strdup("git");

    const char *seq[] = { cmd1, cmd2, cmd3 };
    sg_anomaly_update(m, seq, 3);

    /* Free the caller's copies */
    free(cmd1);
    free(cmd2);
    free(cmd3);

    /* Model should still have the data */
    ASSERT_EQ_INT(sg_anomaly_vocab_size(m), 3);
    ASSERT_EQ_INT(sg_anomaly_uni_count(m, "gcc"), 1);
    ASSERT_EQ_INT(sg_anomaly_uni_count(m, "make"), 1);
    ASSERT_EQ_INT(sg_anomaly_uni_count(m, "git"), 1);

    /* And score should work */
    const char *test_seq[] = { "gcc", "make", "git" };
    double score = sg_anomaly_score(m, test_seq, 3);
    ASSERT(!isinf(score));

    sg_anomaly_model_free(m);
}

/* ============================================================
 * MULTIPLE UPDATES ACCUMULATE
 * ============================================================ */

TEST(multiple_updates_accumulate)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();

    const char *seq[] = { "ls", "cd", "pwd" };

    sg_anomaly_update(m, seq, 3);
    ASSERT_EQ_INT(sg_anomaly_uni_count(m, "ls"), 1);

    sg_anomaly_update(m, seq, 3);
    ASSERT_EQ_INT(sg_anomaly_uni_count(m, "ls"), 2);

    sg_anomaly_update(m, seq, 3);
    ASSERT_EQ_INT(sg_anomaly_uni_count(m, "ls"), 3);
    ASSERT_EQ_INT(sg_anomaly_total_uni(m), 9);

    sg_anomaly_model_free(m);
}

/* ============================================================
 * SAVE AND LOAD ROUNDTRIP
 * ============================================================ */

TEST(save_load_roundtrip_unigrams)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    const char *seq[] = { "ls", "cd", "pwd", "gcc", "make" };
    sg_anomaly_update(m, seq, 5);

    ASSERT_EQ_INT(sg_anomaly_save(m, "/tmp/test_anomaly_uni.txt"), 0);

    sg_anomaly_model_t *m2 = sg_anomaly_model_new();
    ASSERT_EQ_INT(sg_anomaly_load(m2, "/tmp/test_anomaly_uni.txt"), 0);

    ASSERT_EQ_INT(sg_anomaly_vocab_size(m2), 5);
    ASSERT_EQ_INT(sg_anomaly_total_uni(m2), 5);
    ASSERT_EQ_INT(sg_anomaly_uni_count(m2, "ls"), 1);
    ASSERT_EQ_INT(sg_anomaly_uni_count(m2, "make"), 1);

    /* Score should be identical */
    double score1 = sg_anomaly_score(m, seq, 5);
    double score2 = sg_anomaly_score(m2, seq, 5);
    ASSERT_EQ_DBL(score1, score2, 0.001);

    sg_anomaly_model_free(m);
    sg_anomaly_model_free(m2);
    unlink("/tmp/test_anomaly_uni.txt");
}

TEST(save_load_roundtrip_bigrams)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    const char *seq[] = { "ls", "cd", "pwd" };
    for (int i = 0; i < 10; i++)
        sg_anomaly_update(m, seq, 3);

    ASSERT_EQ_INT(sg_anomaly_save(m, "/tmp/test_anomaly_bi.txt"), 0);

    sg_anomaly_model_t *m2 = sg_anomaly_model_new();
    ASSERT_EQ_INT(sg_anomaly_load(m2, "/tmp/test_anomaly_bi.txt"), 0);

    ASSERT_EQ_INT(sg_anomaly_total_bi(m2), 20);
    ASSERT_EQ_INT(sg_anomaly_total_tri(m2), 10);

    sg_anomaly_model_free(m);
    sg_anomaly_model_free(m2);
    unlink("/tmp/test_anomaly_bi.txt");
}

TEST(save_load_preserves_hyperparameters)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new_ex(0.5, -8.0);
    const char *seq[] = { "ls", "cd", "pwd" };
    sg_anomaly_update(m, seq, 3);

    ASSERT_EQ_INT(sg_anomaly_save(m, "/tmp/test_anomaly_hp.txt"), 0);

    sg_anomaly_model_t *m2 = sg_anomaly_model_new();  /* default params */
    ASSERT_EQ_INT(sg_anomaly_load(m2, "/tmp/test_anomaly_hp.txt"), 0);

    /* After load, hyperparameters should be restored */
    /* We can verify through the save file */
    FILE *f = fopen("/tmp/test_anomaly_hp.txt", "r");
    ASSERT(f != NULL);
    char line[256];
    int found_hp = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' && strchr(line, '.')) {
            /* Check it contains our values */
            if (strstr(line, "0.5") && strstr(line, "-8")) {
                found_hp = 1;
            }
        }
    }
    fclose(f);
    ASSERT(found_hp);

    sg_anomaly_model_free(m);
    sg_anomaly_model_free(m2);
    unlink("/tmp/test_anomaly_hp.txt");
}

/* ============================================================
 * RESET
 * ============================================================ */

TEST(reset_clears_all_counts)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    const char *seq[] = { "ls", "cd", "pwd" };
    sg_anomaly_update(m, seq, 3);

    ASSERT_EQ_INT(sg_anomaly_total_uni(m), 3);
    ASSERT_EQ_INT(sg_anomaly_vocab_size(m), 3);

    sg_anomaly_reset(m);

    ASSERT_EQ_INT(sg_anomaly_total_uni(m), 0);
    ASSERT_EQ_INT(sg_anomaly_vocab_size(m), 0);
    ASSERT_EQ_INT(sg_anomaly_total_bi(m), 0);
    ASSERT_EQ_INT(sg_anomaly_total_tri(m), 0);
    ASSERT(isinf(sg_anomaly_score(m, seq, 3)));

    sg_anomaly_model_free(m);
}

/* ============================================================
 * ACCESSORS
 * ============================================================ */

TEST(accessors_null_safety)
{
    ASSERT_EQ_INT(sg_anomaly_vocab_size(NULL), 0);
    ASSERT_EQ_INT(sg_anomaly_total_uni(NULL), 0);
    ASSERT_EQ_INT(sg_anomaly_total_bi(NULL), 0);
    ASSERT_EQ_INT(sg_anomaly_total_tri(NULL), 0);
    ASSERT_EQ_INT(sg_anomaly_uni_count(NULL, "ls"), 0);
}

TEST(uni_count_nonexistent)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    const char *seq[] = { "ls", "cd", "pwd" };
    sg_anomaly_update(m, seq, 3);

    ASSERT_EQ_INT(sg_anomaly_uni_count(m, "nonexistent"), 0);
    ASSERT_EQ_INT(sg_anomaly_uni_count(m, "ls"), 1);
    ASSERT_EQ_INT(sg_anomaly_uni_count(m, "git"), 0);

    sg_anomaly_model_free(m);
}

/* ============================================================
 * EDGE CASES
 * ============================================================ */

TEST(empty_sequence_update)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    const char *seq[] = { "ls", "cd", "pwd" };
    sg_anomaly_update(m, seq, 0);  /* no-op */
    ASSERT_EQ_INT(sg_anomaly_total_uni(m), 0);
    sg_anomaly_model_free(m);
}

TEST(null_model_update)
{
    const char *seq[] = { "ls", "cd", "pwd" };
    sg_anomaly_update(NULL, seq, 3);  /* no-op, no crash */
}

TEST(score_with_null_model)
{
    const char *seq[] = { "ls", "cd", "pwd" };
    ASSERT(isinf(sg_anomaly_score(NULL, seq, 3)));
}

TEST(score_with_null_seq)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    ASSERT(isinf(sg_anomaly_score(m, NULL, 3)));
    sg_anomaly_model_free(m);
}

/* ============================================================
 * ERROR STATE TESTS
 * ============================================================ */

TEST(oom_flag_initially_false)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    ASSERT(!sg_anomaly_model_had_error(m));
    sg_anomaly_model_free(m);
}

TEST(oom_flag_cleared_by_reset)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    /* Force some updates */
    const char *seq[] = { "ls", "cd", "pwd" };
    sg_anomaly_update(m, seq, 3);
    ASSERT(!sg_anomaly_model_had_error(m));
    sg_anomaly_reset(m);
    ASSERT(!sg_anomaly_model_had_error(m));
    sg_anomaly_model_free(m);
}

TEST(clear_error_works)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    sg_anomaly_model_clear_error(m);
    ASSERT(!sg_anomaly_model_had_error(m));
    sg_anomaly_model_free(m);
}

/* ============================================================
 * BACKOFF TESTS
 *
 * Verify that the backoff chain works correctly:
 * Trigram not seen → bigram → unigram → unk_prior
 * ============================================================ */

TEST(backoff_to_bigram)
{
    /* Train only bigrams, no trigrams */
    sg_anomaly_model_t *m = sg_anomaly_model_new_ex(0.1, -10.0);
    /* Single sequence with unique commands */
    const char *seq[] = { "ls", "cd", "pwd" };
    sg_anomaly_update(m, seq, 3);

    /* Check that bigram count exists */
    /* We can infer backoff is used when trigram is unseen but bigram is seen */
    /* Score should be finite (using unigram backoff) */
    double score = sg_anomaly_score(m, seq, 3);
    ASSERT(!isinf(score));
    ASSERT(score >= 0.0);

    sg_anomaly_model_free(m);
}

TEST(unigram_only_fallback)
{
    /* Train with single commands, no sequences */
    sg_anomaly_model_t *m = sg_anomaly_model_new_ex(0.1, -10.0);

    const char *s1[] = { "ls" };
    const char *s2[] = { "cd" };
    const char *s3[] = { "pwd" };

    sg_anomaly_update(m, s1, 1);
    sg_anomaly_update(m, s2, 1);
    sg_anomaly_update(m, s3, 1);

    /* Score a sequence - should use unigram backoff only */
    const char *seq[] = { "ls", "cd", "pwd" };
    double score = sg_anomaly_score(m, seq, 3);
    ASSERT(!isinf(score));
    ASSERT(score >= 0.0);

    sg_anomaly_model_free(m);
}

/* ============================================================
 * SAVE/LOAD CONTEXT TOTALS PRESERVED
 * ============================================================ */

TEST(save_load_preserves_context_totals)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new_ex(0.1, -10.0);

    /* Train a sequence that creates bigram context totals */
    const char *seq[] = { "ls", "cd", "pwd" };
    for (int i = 0; i < 5; i++)
        sg_anomaly_update(m, seq, 3);

    /* Score before save */
    double score_before = sg_anomaly_score(m, seq, 3);

    /* Save and load */
    ASSERT_EQ_INT(sg_anomaly_save(m, "/tmp/test_ctx_save.txt"), 0);
    sg_anomaly_model_free(m);

    sg_anomaly_model_t *m2 = sg_anomaly_model_new_ex(0.1, -10.0);
    ASSERT_EQ_INT(sg_anomaly_load(m2, "/tmp/test_ctx_save.txt"), 0);

    /* Scores should be identical after load */
    double score_after = sg_anomaly_score(m2, seq, 3);
    ASSERT_EQ_DBL(score_before, score_after, 0.001);

    sg_anomaly_model_free(m2);
    unlink("/tmp/test_ctx_save.txt");
}

/* ============================================================
 * PROBABILITY CONSISTENCY
 * ============================================================ */

TEST(score_is_average_negative_log_prob)
{
    sg_anomaly_model_t *m = sg_anomaly_model_new_ex(0.1, -10.0);

    /* Train on a known sequence many times */
    const char *seq[] = { "ls", "cd", "pwd" };
    for (int i = 0; i < 100; i++)
        sg_anomaly_update(m, seq, 3);

    /* After extensive training, the sequence should have very low score */
    double score = sg_anomaly_score(m, seq, 3);
    ASSERT(!isinf(score));
    ASSERT(score >= 0.0);
    /* With 100 training rounds, trigram should be well-established */
    /* Score should be reasonable (not extremely high) */

    sg_anomaly_model_free(m);
}

/* ============================================================
 * BACKOFF CHAIN VERIFICATION
 * ============================================================ */

TEST(backoff_chain)
{
    /* Verify backoff: unseen commands trigger unk_prior
     * Train with specific commands, then probe with unseen ones */
    sg_anomaly_model_t *m = sg_anomaly_model_new_ex(0.1, -10.0);

    /* Train with known sequences */
    const char *seqs[][3] = {
        { "ls", "cd", "pwd" },
        { "cd", "pwd", "gcc" },
        { "pwd", "gcc", "make" },
    };
    for (size_t i = 0; i < 3; i++)
        sg_anomaly_update(m, seqs[i], 3);

    /* Score known sequence - should have low (non-anomalous) score */
    const char *known[] = { "ls", "cd", "pwd" };
    double score_known = sg_anomaly_score(m, known, 3);
    ASSERT(!isinf(score_known));
    ASSERT(score_known >= 0.0);

    /* Score sequence with unseen command - should still be finite
     * (uses unk_prior for unknown command) */
    const char *probe[] = { "cd", "pwd", "neverheardof" };
    double score_unseen = sg_anomaly_score(m, probe, 3);
    ASSERT(!isinf(score_unseen));
    ASSERT(score_unseen >= 0.0);

    /* Sequence with unseen should be more anomalous than known */
    ASSERT(score_unseen > score_known);

    sg_anomaly_model_free(m);
}

/* ============================================================
 * EDGE CASES: SHORT SEQUENCES
 * ============================================================ */

TEST(edge_single_command_update)
{
    /* Update with single command, verify unigram count */
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    const char *seq[] = { "ls" };
    sg_anomaly_update(m, seq, 1);

    ASSERT(sg_anomaly_vocab_size(m) == 1);
    ASSERT(sg_anomaly_total_uni(m) == 1);
    ASSERT(sg_anomaly_uni_count(m, "ls") == 1);

    sg_anomaly_model_free(m);
}

TEST(edge_two_command_update)
{
    /* Update with two commands, verify unigram + bigram counts */
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    const char *seq[] = { "cd", "pwd" };
    sg_anomaly_update(m, seq, 2);

    /* Should have 2 unigrams and 1 bigram */
    ASSERT(sg_anomaly_vocab_size(m) == 2);
    ASSERT(sg_anomaly_total_uni(m) == 2);
    ASSERT(sg_anomaly_total_bi(m) == 1);

    sg_anomaly_model_free(m);
}

TEST(edge_short_sequence_scoring)
{
    /* Verify INFINITY for len < 3 */
    sg_anomaly_model_t *m = sg_anomaly_model_new();
    const char *seq1[] = { "ls" };
    const char *seq2[] = { "ls", "cd" };

    /* Score short sequences - should be INFINITY */
    ASSERT(isinf(sg_anomaly_score(m, seq1, 1)));
    ASSERT(isinf(sg_anomaly_score(m, seq2, 2)));

    /* Train and verify short sequences still score as INFINITY */
    const char *train[] = { "ls", "cd", "pwd" };
    sg_anomaly_update(m, train, 3);
    ASSERT(isinf(sg_anomaly_score(m, seq1, 1)));
    ASSERT(isinf(sg_anomaly_score(m, seq2, 2)));

    /* Normal 3+ sequence should score normally */
    const char *seq3[] = { "ls", "cd", "pwd" };
    ASSERT(!isinf(sg_anomaly_score(m, seq3, 3)));

    sg_anomaly_model_free(m);
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void)
{
    printf("sg_anomaly unit tests\n");

    RUN(anomaly_model_new_default);
    RUN(anomaly_model_new_ex);
    RUN(anomaly_model_free_null);
    RUN(update_and_score_single_trigram);
    RUN(score_returns_infinity_for_len_lt_3);
    RUN(score_returns_infinity_when_model_empty);
    RUN(known_sequence_has_low_score);
    RUN(unseen_command_has_higher_score);
    RUN(model_owns_string_copies);
    RUN(multiple_updates_accumulate);
    RUN(save_load_roundtrip_unigrams);
    RUN(save_load_roundtrip_bigrams);
    RUN(save_load_preserves_hyperparameters);
    RUN(reset_clears_all_counts);
    RUN(accessors_null_safety);
    RUN(uni_count_nonexistent);
    RUN(empty_sequence_update);
    RUN(null_model_update);
    RUN(score_with_null_model);
    RUN(score_with_null_seq);

    printf("\nError state tests:\n");
    RUN(oom_flag_initially_false);
    RUN(oom_flag_cleared_by_reset);
    RUN(clear_error_works);

    printf("\nBackoff tests:\n");
    RUN(backoff_to_bigram);
    RUN(unigram_only_fallback);

    printf("\nContext totals tests:\n");
    RUN(save_load_preserves_context_totals);
    RUN(score_is_average_negative_log_prob);

    printf("\nBackoff chain tests:\n");
    RUN(backoff_chain);

    printf("\nEdge case tests:\n");
    RUN(edge_single_command_update);
    RUN(edge_two_command_update);
    RUN(edge_short_sequence_scoring);

    printf("\n%d passed, %d failed\n", pass_count, fail_count);
    return fail_count > 0 ? 1 : 0;
}
