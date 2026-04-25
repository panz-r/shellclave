/*
 * bench_policy.c - Micro-benchmark for policy evaluation.
 *
 * Measures throughput and latency of st_policy_eval with a mixed
 * policy of literals, wildcards, and parametrized wildcards.
 *
 * Usage: make bench
 */
#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "shelltype.h"

#define N_PATTERNS  500
#define N_EVALS     10000

static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(void)
{
    st_policy_ctx_t *ctx = st_policy_ctx_new();
    st_policy_t *policy = st_policy_new(ctx);

    /* Build a policy with varied patterns */
    char buf[256];
    for (int i = 0; i < 200; i++) {
        snprintf(buf, sizeof(buf), "cmd%d arg", i);
        st_policy_add(policy, buf);
    }
    for (int i = 0; i < 100; i++) {
        snprintf(buf, sizeof(buf), "svc%d #path", i);
        st_policy_add(policy, buf);
    }
    for (int i = 0; i < 100; i++) {
        snprintf(buf, sizeof(buf), "tool%d #val", i);
        st_policy_add(policy, buf);
    }
    for (int i = 0; i < 50; i++) {
        snprintf(buf, sizeof(buf), "cat #path.cfg");
        st_policy_add(policy, buf);
    }
    for (int i = 0; i < 50; i++) {
        snprintf(buf, sizeof(buf), "dd #size.MiB");
        st_policy_add(policy, buf);
    }

    printf("Policy: %zu patterns, %zu states\n",
           st_policy_count(policy), st_policy_state_count(policy));

    /* Warm up (triggers lazy filter rebuild) */
    st_eval_result_t r;
    st_policy_eval(policy, "cmd0 arg", &r);

    /* Measure matching evaluations */
    double t0 = now_sec();
    int match_count = 0;
    for (int i = 0; i < N_EVALS; i++) {
        int idx = i % 200;
        snprintf(buf, sizeof(buf), "cmd%d arg", idx);
        st_policy_eval(policy, buf, &r);
        if (r.matches) match_count++;
    }
    double t_match = now_sec() - t0;

    /* Measure non-matching evaluations */
    t0 = now_sec();
    int miss_count = 0;
    for (int i = 0; i < N_EVALS; i++) {
        snprintf(buf, sizeof(buf), "nonexist%d baz", i);
        st_policy_eval(policy, buf, &r);
        if (!r.matches) miss_count++;
    }
    double t_miss = now_sec() - t0;

    /* Measure wildcard matching */
    t0 = now_sec();
    int wild_count = 0;
    for (int i = 0; i < N_EVALS; i++) {
        int idx = i % 100;
        snprintf(buf, sizeof(buf), "svc%d /etc/hosts", idx);
        st_policy_eval(policy, buf, &r);
        if (r.matches) wild_count++;
    }
    double t_wild = now_sec() - t0;

    printf("\n=== Benchmark results (%d evaluations each) ===\n", N_EVALS);
    printf("Literal match:    %.3f ms  (%.0f evals/sec)  %d/%d matched\n",
           t_match * 1000, N_EVALS / t_match, match_count, N_EVALS);
    printf("Literal miss:     %.3f ms  (%.0f evals/sec)  %d/%d rejected\n",
           t_miss * 1000, N_EVALS / t_miss, miss_count, N_EVALS);
    printf("Wildcard match:   %.3f ms  (%.0f evals/sec)  %d/%d matched\n",
           t_wild * 1000, N_EVALS / t_wild, wild_count, N_EVALS);

    st_policy_stats_t stats;
    st_policy_get_stats(policy, &stats);
    printf("\nPolicy stats:\n");
    printf("  Total evals:     %lu\n", (unsigned long)stats.eval_count);
    printf("  Filter rejects:  %lu\n", (unsigned long)stats.filter_reject_count);
    printf("  Trie walks:      %lu\n", (unsigned long)stats.trie_walk_count);
    printf("  Filter rebuilds: %lu\n", (unsigned long)stats.filter_rebuild_count);

    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 0;
}
