/* Compile the actual benchmark with a bounded workload. Only this translation
 * unit substitutes operations; the shipping benchmark has no test hooks. */
#define _POSIX_C_SOURCE 200809L

#include "shell_netstring.h"
#include "shelltype.h"
#include "test_allocator.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef enum {
  FAIL_NONE,
  FAIL_CONTEXT,
  FAIL_POLICY,
  FAIL_CONVERSION,
  FAIL_INSERTION,
  FAIL_EVALUATION,
  FAIL_SUGGESTION,
  FAIL_CLOCK,
  WRONG_RULE_COUNT,
  WRONG_DECISION,
} failure_kind_t;

static struct {
  failure_kind_t kind;
  size_t at_call;
  size_t fired;
  size_t policy_calls;
  size_t conversion_calls;
  size_t insertion_calls;
  size_t eval_calls;
  size_t clock_calls;
  size_t policy_frees;
  size_t context_releases;
} fault;

static bool fail_operation(failure_kind_t kind, size_t call) {
  if (fault.kind != kind || call != fault.at_call)
    return false;
  fault.fired++;
  return true;
}

static st_policy_ctx_t *benchmark_context_new(void) {
  if (fail_operation(FAIL_CONTEXT, 1))
    st_test_alloc_fail_at(1);
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_test_alloc_reset();
  return context;
}

static st_policy_t *benchmark_policy_new(st_policy_ctx_t *context)
    SHELL_NONNULL(1);
static st_policy_t *benchmark_policy_new(st_policy_ctx_t *context) {
  fault.policy_calls++;
  if (fail_operation(FAIL_POLICY, fault.policy_calls))
    st_test_alloc_fail_at(1);
  st_policy_t *policy = st_policy_new(context);
  st_test_alloc_reset();
  return policy;
}

static st_error_t benchmark_convert(const char *cpl, st_netpattern_t *pattern)
    SHELL_NONNULL(1, 2);
static st_error_t benchmark_convert(const char *cpl, st_netpattern_t *pattern) {
  fault.conversion_calls++;
  if (fail_operation(FAIL_CONVERSION, fault.conversion_calls))
    st_test_alloc_fail_at(1);
  st_error_t error = st_netpattern_from_cpl_owned(cpl, pattern);
  st_test_alloc_reset();
  return error;
}

static st_error_t benchmark_insert(st_policy_t *policy,
                                   st_netpattern_view_t pattern)
    SHELL_NONNULL(1);
static st_error_t benchmark_insert(st_policy_t *policy,
                                   st_netpattern_view_t pattern) {
  fault.insertion_calls++;
  if (fail_operation(FAIL_INSERTION, fault.insertion_calls))
    st_test_alloc_fail_at(1);
  st_error_t error = st_policy_add_netpattern_view(policy, pattern);
  st_test_alloc_reset();
  return error;
}

static st_error_t benchmark_eval(const st_policy_t *policy,
                                 st_netargv_view_t netargv,
                                 st_eval_result_t *result) SHELL_NONNULL(1, 3);
static st_error_t benchmark_eval(const st_policy_t *policy,
                                 st_netargv_view_t netargv,
                                 st_eval_result_t *result) {
  fault.eval_calls++;
  if (fail_operation(FAIL_EVALUATION, fault.eval_calls)) {
    *result = (st_eval_result_t){0};
    return ST_ERR_MEMORY;
  }
  st_error_t error = st_policy_eval_view(policy, netargv, result);
  if (error == ST_OK && fail_operation(FAIL_SUGGESTION, fault.eval_calls)) {
    /* A completed non-match can have an unsuccessful suggestion batch. */
    result->suggestion_count = 0;
    result->suggestion_error = ST_ERR_MEMORY;
  }
  if (error == ST_OK && fail_operation(WRONG_DECISION, fault.eval_calls))
    result->matches = !result->matches;
  return error;
}

static int benchmark_clock(clockid_t clock, struct timespec *value)
    SHELL_NONNULL(2);
static int benchmark_clock(clockid_t clock, struct timespec *value) {
  fault.clock_calls++;
  if (fail_operation(FAIL_CLOCK, fault.clock_calls)) {
    errno = EIO;
    return -1;
  }
  return clock_gettime(clock, value);
}

static size_t benchmark_rule_count(const st_policy_t *policy) SHELL_NONNULL(1);
static size_t benchmark_rule_count(const st_policy_t *policy) {
  size_t count = st_policy_rule_count(policy);
  return fail_operation(WRONG_RULE_COUNT, 1) ? count - 1 : count;
}

/* Cleanup APIs accept NULL as a no-op; count releases of acquired resources. */
static void benchmark_policy_free(st_policy_t *policy) {
  if (policy)
    fault.policy_frees++;
  st_policy_free(policy);
}

static void benchmark_context_release(st_policy_ctx_t *context) {
  if (context)
    fault.context_releases++;
  st_policy_ctx_release(context);
}

#define N_EVALS 4
#define main benchmark_main
#define st_policy_ctx_new benchmark_context_new
#define st_policy_new benchmark_policy_new
#define st_netpattern_from_cpl_owned benchmark_convert
#define st_policy_add_netpattern_view benchmark_insert
#define st_policy_eval_view benchmark_eval
#define st_policy_rule_count benchmark_rule_count
#define st_policy_free benchmark_policy_free
#define st_policy_ctx_release benchmark_context_release
#define clock_gettime benchmark_clock
#include "../benchmarks/policy_benchmark.c"
#undef clock_gettime
#undef st_policy_ctx_release
#undef st_policy_free
#undef st_policy_eval_view
#undef st_policy_rule_count
#undef st_policy_add_netpattern_view
#undef st_netpattern_from_cpl_owned
#undef st_policy_new
#undef st_policy_ctx_new
#undef main

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "check failed: %s at %s:%d\n", #condition, __FILE__,     \
              __LINE__);                                                       \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

typedef struct {
  const char *name;
  failure_kind_t kind;
  size_t at_call;
  const char *diagnostic;
  size_t evaluations;
  size_t clocks;
} benchmark_case_t;

static bool run_case(const benchmark_case_t *test) SHELL_NONNULL(1);
static bool run_case(const benchmark_case_t *test) {
  bool ok = false;
  FILE *output = tmpfile();
  FILE *errors = tmpfile();
  int saved_out = -1, saved_err = -1;
  char out[4096], err[4096];
  fault.kind = test->kind;
  fault.at_call = test->at_call;
  fault.fired = fault.policy_calls = fault.conversion_calls = 0;
  fault.insertion_calls = fault.eval_calls = fault.clock_calls = 0;
  fault.policy_frees = fault.context_releases = 0;
  st_test_alloc_reset();

  CHECK(output != NULL && errors != NULL);
  CHECK(fflush(stdout) == 0 && fflush(stderr) == 0);
  saved_out = dup(STDOUT_FILENO);
  saved_err = dup(STDERR_FILENO);
  CHECK(saved_out >= 0 && saved_err >= 0);
  CHECK(dup2(fileno(output), STDOUT_FILENO) >= 0);
  CHECK(dup2(fileno(errors), STDERR_FILENO) >= 0);
  int status = benchmark_main();
  CHECK(fflush(stdout) == 0 && fflush(stderr) == 0);
  CHECK(dup2(saved_out, STDOUT_FILENO) >= 0);
  CHECK(dup2(saved_err, STDERR_FILENO) >= 0);
  CHECK(fseek(output, 0, SEEK_SET) == 0 && fseek(errors, 0, SEEK_SET) == 0);
  size_t out_length = fread(out, 1, sizeof(out) - 1, output);
  size_t err_length = fread(err, 1, sizeof(err) - 1, errors);
  CHECK(!ferror(output) && !ferror(errors));
  CHECK(feof(output) && feof(errors));
  out[out_length] = '\0';
  err[err_length] = '\0';

  CHECK(fault.eval_calls == test->evaluations);
  CHECK(fault.clock_calls == test->clocks);
  CHECK(fault.policy_frees ==
        (test->kind == FAIL_CONTEXT || test->kind == FAIL_POLICY ? 0u : 1u));
  CHECK(fault.context_releases == (test->kind == FAIL_CONTEXT ? 0u : 1u));
  CHECK(fault.policy_calls == (test->kind == FAIL_CONTEXT ? 0u : 1u));
  if (test->kind == FAIL_CONTEXT || test->kind == FAIL_POLICY)
    CHECK(fault.conversion_calls == 0 && fault.insertion_calls == 0);
  if (test->kind == FAIL_CONVERSION)
    CHECK(fault.conversion_calls == test->at_call &&
          fault.insertion_calls == test->at_call - 1);
  if (test->kind == FAIL_INSERTION)
    CHECK(fault.conversion_calls == test->at_call &&
          fault.insertion_calls == test->at_call);

  if (test->kind == FAIL_NONE) {
    CHECK(status == EXIT_SUCCESS && fault.fired == 0 && err_length == 0);
    CHECK(fault.conversion_calls == N_PATTERNS);
    CHECK(fault.insertion_calls == N_PATTERNS);
    CHECK(strstr(out, "Policy: 500 patterns,") != NULL);
    CHECK(strstr(out, "Benchmark results (4 evaluations each)") != NULL);
    const char *match = strstr(out, "Literal match:");
    const char *miss = strstr(out, "Literal miss:");
    const char *wild = strstr(out, "Wildcard match:");
    CHECK(match != NULL && miss != NULL && wild != NULL);
    const char *matched = strstr(match, "4/4 matched\n");
    const char *rejected = strstr(miss, "4/4 rejected\n");
    CHECK(matched != NULL && matched < miss);
    CHECK(rejected != NULL && rejected < wild);
    CHECK(strstr(wild, "4/4 matched\n") != NULL);
    CHECK(strstr(out, "Total evals:     13\n") != NULL);
  } else {
    CHECK(status == EXIT_FAILURE && fault.fired == 1);
    CHECK(out_length == 0);
    CHECK(strstr(err, test->diagnostic) != NULL);
  }
  ok = true;
cleanup:
  st_test_alloc_reset();
  if (saved_out >= 0) {
    fflush(stdout);
    dup2(saved_out, STDOUT_FILENO);
    close(saved_out);
  }
  if (saved_err >= 0) {
    fflush(stderr);
    dup2(saved_err, STDERR_FILENO);
    close(saved_err);
  }
  if (output)
    fclose(output);
  if (errors)
    fclose(errors);
  fprintf(stderr, "%s: %s\n", test->name, ok ? "PASS" : "FAIL");
  return ok;
}

static bool test_encoding_capacity(void) {
  bool ok = false;
  char buffer[9];
  memset(buffer, 'z', sizeof(buffer));
  size_t length = 99;
  CHECK(!encode_two(buffer, 7, "a", "b", &length));
  CHECK(length == 0 && memcmp(buffer, "zzzzzzzzz", sizeof(buffer)) == 0);
  CHECK(encode_two(buffer, 8, "a", "b", &length));
  CHECK(length == 8 && memcmp(buffer, "1:a,1:b,", 8) == 0);
  CHECK(buffer[8] == 'z');
  ok = true;
cleanup:
  return ok;
}

int main(void) {
  static const benchmark_case_t cases[] = {
      {"success", FAIL_NONE, 0, NULL, 13, 6},
      {"context allocation", FAIL_CONTEXT, 1, "context creation failed", 0, 0},
      {"policy allocation", FAIL_POLICY, 1, "policy creation failed", 0, 0},
      {"CPL allocation", FAIL_CONVERSION, 1, "pattern conversion failed", 0, 0},
      {"insertion allocation", FAIL_INSERTION, 1, "pattern insertion failed", 0,
       0},
      {"partial policy conversion", FAIL_CONVERSION, 201,
       "pattern conversion failed for svc0", 0, 0},
      {"partial policy insertion", FAIL_INSERTION, 301,
       "pattern insertion failed for tool0", 0, 0},
      {"pattern count", WRONG_RULE_COUNT, 1,
       "benchmark policy has 499 patterns, expected 500", 0, 0},
      {"warm-up failure", FAIL_EVALUATION, 1,
       "warm-up iteration 0: evaluation failed", 1, 0},
      {"matching failure", FAIL_EVALUATION, 3,
       "literal match iteration 1: evaluation failed", 3, 1},
      {"non-matching failure", FAIL_EVALUATION, 7,
       "literal miss iteration 1: evaluation failed", 7, 3},
      {"wildcard failure", FAIL_EVALUATION, 11,
       "wildcard match iteration 1: evaluation failed", 11, 5},
      {"suggestion failure", FAIL_SUGGESTION, 7,
       "literal miss iteration 1: suggestion generation failed", 7, 3},
      {"warm-up decision", WRONG_DECISION, 1, "expected a matching evaluation",
       1, 0},
      {"matching decision", WRONG_DECISION, 3,
       "literal match: 3/4 matched, expected all", 5, 2},
      {"non-matching decision", WRONG_DECISION, 7,
       "literal miss: 3/4 rejected, expected all", 9, 4},
      {"wildcard decision", WRONG_DECISION, 11,
       "wildcard match: 3/4 matched, expected all", 13, 6},
      {"match start clock", FAIL_CLOCK, 1,
       "literal match: clock_gettime failed", 1, 1},
      {"match end clock", FAIL_CLOCK, 2, "literal match: clock_gettime failed",
       5, 2},
      {"miss start clock", FAIL_CLOCK, 3, "literal miss: clock_gettime failed",
       5, 3},
      {"miss end clock", FAIL_CLOCK, 4, "literal miss: clock_gettime failed", 9,
       4},
      {"wildcard start clock", FAIL_CLOCK, 5,
       "wildcard match: clock_gettime failed", 9, 5},
      {"wildcard end clock", FAIL_CLOCK, 6,
       "wildcard match: clock_gettime failed", 13, 6},
  };
  bool ok = test_encoding_capacity();
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    if (!run_case(&cases[i]))
      ok = false;
  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
