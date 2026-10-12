/*
 * policy_benchmark.c - Micro-benchmark for policy evaluation.
 *
 * Measures throughput and latency of st_policy_eval_view with a mixed
 * policy of literals, wildcards, and parametrized wildcards.
 *
 * Build: cmake -S . -B build -DSHELLCLAVE_BUILD_BENCHMARKS=ON
 * Run: build/shelltype_policy_benchmark
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "shell_netstring.h"
#include "shelltype.h"

#define N_PATTERNS 500
#ifndef N_EVALS
#define N_EVALS 10000
#endif

static bool now_sec(const char *phase, double *seconds) SHELL_NONNULL(1, 2);
static bool now_sec(const char *phase, double *seconds) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    fprintf(stderr, "%s: clock_gettime failed: %s\n", phase, strerror(errno));
    return false;
  }
  *seconds = ts.tv_sec + ts.tv_nsec * 1e-9;
  return true;
}

static st_error_t add_cpl(st_policy_t *policy, const char *cpl)
    SHELL_NONNULL(1, 2);
static st_error_t add_cpl(st_policy_t *policy, const char *cpl) {
  st_netpattern_t netpattern = {0};
  st_error_t error = st_netpattern_from_cpl_owned(cpl, &netpattern);
  const char *operation = "pattern conversion";
  if (error == ST_OK) {
    operation = "pattern insertion";
    error = st_policy_add_netpattern_view(
        policy, (st_netpattern_view_t){netpattern.data, netpattern.length});
  }
  if (error != ST_OK)
    fprintf(stderr, "%s failed for %s: %s\n", operation, cpl,
            st_error_string(error));
  st_netpattern_free(&netpattern);
  return error;
}

/* output supplies capacity bytes; the words are C-string fixtures, while the
 * encoded result is consumed using its explicit length. */
static bool encode_two(char *output, size_t capacity, const char *first,
                       const char *second, size_t *length)
    SHELL_NONNULL(1, 3, 4, 5);
static bool encode_two(char *output, size_t capacity, const char *first,
                       const char *second, size_t *length) {
  *length = 0;
  size_t first_length = strlen(first), second_length = strlen(second);
  size_t first_record = 0, second_record = 0;
  if (shell_netstring_encoded_length(first_length, &first_record) !=
          SHELL_NETSTRING_OK ||
      shell_netstring_encoded_length(second_length, &second_record) !=
          SHELL_NETSTRING_OK ||
      first_record > SIZE_MAX - second_record ||
      first_record + second_record > capacity)
    return false;
  size_t written = 0;
  if (shell_netstring_write(output, capacity, first, first_length, &written) !=
      SHELL_NETSTRING_OK)
    return false;
  size_t second_written = 0;
  if (shell_netstring_write(output + written, capacity - written, second,
                            second_length,
                            &second_written) != SHELL_NETSTRING_OK)
    return false;
  *length = written + second_written;
  return true;
}

static bool eval_two(st_policy_t *policy, const char *phase, int iteration,
                     const char *first, const char *second,
                     st_eval_result_t *result) SHELL_NONNULL(1, 2, 4, 5, 6);
static bool eval_two(st_policy_t *policy, const char *phase, int iteration,
                     const char *first, const char *second,
                     st_eval_result_t *result) {
  char netargv[512];
  size_t length = 0;
  if (!encode_two(netargv, sizeof(netargv), first, second, &length)) {
    fprintf(stderr, "%s iteration %d: netargv encoding failed\n", phase,
            iteration);
    return false;
  }
  st_error_t error =
      st_policy_eval_view(policy, (st_netargv_view_t){netargv, length}, result);
  if (error != ST_OK) {
    fprintf(stderr, "%s iteration %d: evaluation failed: %s\n", phase,
            iteration, st_error_string(error));
    return false;
  }
  if (result->suggestion_error != ST_OK) {
    fprintf(stderr, "%s iteration %d: suggestion generation failed: %s\n",
            phase, iteration, st_error_string(result->suggestion_error));
    return false;
  }
  return true;
}

int main(void) {
  int status = EXIT_FAILURE;
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  if (!ctx) {
    fprintf(stderr, "benchmark context creation failed\n");
    goto cleanup;
  }
  policy = st_policy_new(ctx);
  if (!policy) {
    fprintf(stderr, "benchmark policy creation failed\n");
    goto cleanup;
  }

  /* Build a policy with varied patterns */
  char buf[256];
  for (int i = 0; i < 200; i++) {
    snprintf(buf, sizeof(buf), "cmd%d arg", i);
    if (add_cpl(policy, buf) != ST_OK)
      goto cleanup;
  }
  for (int i = 0; i < 100; i++) {
    snprintf(buf, sizeof(buf), "svc%d #path", i);
    if (add_cpl(policy, buf) != ST_OK)
      goto cleanup;
  }
  for (int i = 0; i < 100; i++) {
    snprintf(buf, sizeof(buf), "tool%d #val", i);
    if (add_cpl(policy, buf) != ST_OK)
      goto cleanup;
  }
  for (int i = 0; i < 50; i++) {
    snprintf(buf, sizeof(buf), "id%d #uuid.v4", i);
    if (add_cpl(policy, buf) != ST_OK)
      goto cleanup;
  }
  for (int i = 0; i < 50; i++) {
    snprintf(buf, sizeof(buf), "dd%d #size.MiB", i);
    if (add_cpl(policy, buf) != ST_OK)
      goto cleanup;
  }

  size_t pattern_count = st_policy_rule_count(policy);
  if (pattern_count != N_PATTERNS) {
    fprintf(stderr, "benchmark policy has %zu patterns, expected %d\n",
            pattern_count, N_PATTERNS);
    goto cleanup;
  }

  /* Warm up (triggers lazy filter rebuild) */
  st_eval_result_t r;
  if (!eval_two(policy, "warm-up", 0, "cmd0", "arg", &r))
    goto cleanup;
  if (!r.matches) {
    fprintf(stderr, "warm-up: expected a matching evaluation\n");
    goto cleanup;
  }

  /* Measure matching evaluations */
  double t0, t1;
  if (!now_sec("literal match", &t0))
    goto cleanup;
  int match_count = 0;
  for (int i = 0; i < N_EVALS; i++) {
    int idx = i % 200;
    snprintf(buf, sizeof(buf), "cmd%d", idx);
    if (!eval_two(policy, "literal match", i, buf, "arg", &r))
      goto cleanup;
    if (r.matches)
      match_count++;
  }
  if (!now_sec("literal match", &t1))
    goto cleanup;
  double t_match = t1 - t0;
  if (match_count != N_EVALS) {
    fprintf(stderr, "literal match: %d/%d matched, expected all\n", match_count,
            N_EVALS);
    goto cleanup;
  }

  /* Measure non-matching evaluations */
  if (!now_sec("literal miss", &t0))
    goto cleanup;
  int miss_count = 0;
  for (int i = 0; i < N_EVALS; i++) {
    snprintf(buf, sizeof(buf), "nonexist%d", i);
    if (!eval_two(policy, "literal miss", i, buf, "baz", &r))
      goto cleanup;
    if (!r.matches)
      miss_count++;
  }
  if (!now_sec("literal miss", &t1))
    goto cleanup;
  double t_miss = t1 - t0;
  if (miss_count != N_EVALS) {
    fprintf(stderr, "literal miss: %d/%d rejected, expected all\n", miss_count,
            N_EVALS);
    goto cleanup;
  }

  /* Measure wildcard matching */
  if (!now_sec("wildcard match", &t0))
    goto cleanup;
  int wild_count = 0;
  for (int i = 0; i < N_EVALS; i++) {
    int idx = i % 100;
    snprintf(buf, sizeof(buf), "svc%d", idx);
    if (!eval_two(policy, "wildcard match", i, buf, "/etc/hosts", &r))
      goto cleanup;
    if (r.matches)
      wild_count++;
  }
  if (!now_sec("wildcard match", &t1))
    goto cleanup;
  double t_wild = t1 - t0;
  if (wild_count != N_EVALS) {
    fprintf(stderr, "wildcard match: %d/%d matched, expected all\n", wild_count,
            N_EVALS);
    goto cleanup;
  }

  printf("Policy: %zu patterns, %zu states\n", pattern_count,
         st_policy_state_count(policy));
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

  status = EXIT_SUCCESS;
cleanup:
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return status;
}
