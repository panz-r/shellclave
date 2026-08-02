#define _XOPEN_SOURCE 700

#include "shelltype.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
  READER_COUNT = 6,
  WRITER_COUNT = 2,
  READER_ITERATIONS = 2000,
  WRITER_ITERATIONS = 500,
  REFCOUNT_THREAD_COUNT = 8,
  REFCOUNT_ITERATIONS = 10000,
  RESET_ITERATIONS = 5000,
  INTERN_THREAD_COUNT = 6,
  INTERN_UNIQUE_COUNT = 1536,
  INTERN_SHARED_COUNT = 8,
};

typedef struct {
  st_policy_t *policy;
  pthread_barrier_t *barrier;
  atomic_uint *failures;
  unsigned id;
} policy_thread_args_t;

typedef struct {
  st_policy_ctx_t *ctx;
  pthread_barrier_t *barrier;
  atomic_uint *failures;
  unsigned id;
} refcount_thread_args_t;

typedef struct {
  st_policy_ctx_t *ctx;
  pthread_barrier_t *barrier;
  atomic_uint *failures;
  const char *shared[INTERN_SHARED_COUNT];
  const char *unique[INTERN_UNIQUE_COUNT];
  unsigned id;
} intern_thread_args_t;

typedef struct {
  st_policy_t *destination;
  st_policy_t *source;
  pthread_barrier_t *barrier;
  atomic_uint *failures;
  unsigned id;
} merge_thread_args_t;

static void record_failure(atomic_uint *failures, const char *operation,
                           unsigned id, size_t iteration) {
  fprintf(stderr, "thread %u: %s failed at iteration %zu\n", id, operation,
          iteration);
  atomic_fetch_add(failures, 1);
}

static bool await_start(pthread_barrier_t *barrier, atomic_uint *failures,
                        unsigned id) {
  int result = pthread_barrier_wait(barrier);
  if (result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD)
    return true;
  record_failure(failures, "barrier wait", id, 0);
  return false;
}

static bool policy_matches_exact(st_policy_t *policy, const char *command) {
  st_eval_result_t result = {0};
  return st_policy_eval(policy, command, &result) == ST_OK && result.matches &&
         result.matching_pattern &&
         strcmp(result.matching_pattern, command) == 0;
}

static void *policy_reader(void *opaque) {
  policy_thread_args_t *args = opaque;
  if (!await_start(args->barrier, args->failures, args->id))
    return NULL;

  for (size_t i = 0; i < READER_ITERATIONS; i++) {
    const char *command = (i & 1) == 0 ? "git status" : "docker ps";
    if (!policy_matches_exact(args->policy, command)) {
      record_failure(args->failures, "policy evaluation", args->id, i);
      break;
    }
    size_t count = st_policy_count(args->policy);
    if (count < 2 || count > 2 + WRITER_COUNT) {
      record_failure(args->failures, "policy count", args->id, i);
      break;
    }
  }
  return NULL;
}

static void *policy_writer(void *opaque) {
  policy_thread_args_t *args = opaque;
  if (!await_start(args->barrier, args->failures, args->id))
    return NULL;

  for (size_t i = 0; i < WRITER_ITERATIONS; i++) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "temporary%u_%zu value", args->id, i);
    if (st_policy_add(args->policy, pattern) != ST_OK) {
      record_failure(args->failures, "policy add", args->id, i);
      break;
    }
    if (st_policy_remove(args->policy, pattern) != ST_OK) {
      record_failure(args->failures, "policy remove", args->id, i);
      break;
    }
  }
  return NULL;
}

static int test_concurrent_policy_reads_and_writes(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  if (!ctx || !policy) {
    fprintf(stderr, "failed to create policy context\n");
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 0;
  }
  if (st_policy_add(policy, "git status") != ST_OK ||
      st_policy_add(policy, "docker ps") != ST_OK) {
    fprintf(stderr, "failed to add baseline patterns\n");
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 0;
  }

  pthread_barrier_t barrier;
  if (pthread_barrier_init(&barrier, NULL, READER_COUNT + WRITER_COUNT) != 0) {
    fprintf(stderr, "failed to initialize policy barrier\n");
    st_policy_free(policy);
    st_policy_ctx_free(ctx);
    return 0;
  }

  atomic_uint failures;
  atomic_init(&failures, 0);
  pthread_t readers[READER_COUNT];
  policy_thread_args_t reader_args[READER_COUNT];
  pthread_t writers[WRITER_COUNT];
  policy_thread_args_t writer_args[WRITER_COUNT];

  size_t readers_started = 0;
  for (size_t i = 0; i < READER_COUNT; i++) {
    reader_args[i].policy = policy;
    reader_args[i].barrier = &barrier;
    reader_args[i].failures = &failures;
    reader_args[i].id = (unsigned)i;
    if (pthread_create(&readers[i], NULL, policy_reader, &reader_args[i]) != 0)
      break;
    readers_started++;
  }
  size_t writers_started = 0;
  if (readers_started == READER_COUNT)
    for (size_t i = 0; i < WRITER_COUNT; i++) {
      writer_args[i] = (policy_thread_args_t){.policy = policy,
                                              .barrier = &barrier,
                                              .failures = &failures,
                                              .id = READER_COUNT + (unsigned)i};
      if (pthread_create(&writers[i], NULL, policy_writer, &writer_args[i]) !=
          0)
        break;
      writers_started++;
    }

  if (writers_started != WRITER_COUNT) {
    fprintf(stderr, "failed to create policy threads\n");
    /* Releasing an incomplete barrier would be unsafe; this is a test-host
     * resource failure, so terminate the process after reporting it. */
    exit(EXIT_FAILURE);
  }

  for (size_t i = 0; i < READER_COUNT; i++)
    if (pthread_join(readers[i], NULL) != 0)
      record_failure(&failures, "reader join", (unsigned)i, 0);
  for (size_t i = 0; i < WRITER_COUNT; i++)
    if (pthread_join(writers[i], NULL) != 0)
      record_failure(&failures, "writer join", READER_COUNT + (unsigned)i, 0);
  if (pthread_barrier_destroy(&barrier) != 0)
    record_failure(&failures, "barrier destroy", READER_COUNT, 0);

  bool passed = atomic_load(&failures) == 0;
  static const char *baseline[] = {"git status", "docker ps"};
  for (size_t i = 0; i < sizeof(baseline) / sizeof(baseline[0]); i++)
    if (!policy_matches_exact(policy, baseline[i]))
      passed = false;

  st_policy_stats_t stats;
  st_policy_get_stats(policy, &stats);
  if (stats.eval_count != READER_COUNT * READER_ITERATIONS + 2) {
    fprintf(stderr, "eval_count: expected %u, got %llu\n",
            READER_COUNT * READER_ITERATIONS + 2,
            (unsigned long long)stats.eval_count);
    passed = false;
  }
  if (st_policy_count(policy) != 2) {
    fprintf(stderr, "writer did not restore the baseline pattern count\n");
    passed = false;
  }

  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return passed;
}

static void *refcount_worker(void *opaque) {
  refcount_thread_args_t *args = opaque;
  if (!await_start(args->barrier, args->failures, args->id))
    return NULL;
  for (size_t i = 0; i < REFCOUNT_ITERATIONS; i++) {
    st_policy_ctx_retain(args->ctx);
    const char *value = st_policy_ctx_intern(args->ctx, "retained-value");
    sched_yield();
    if (!value || strcmp(value, "retained-value") != 0) {
      record_failure(args->failures, "retained intern", args->id, i);
      st_policy_ctx_release(args->ctx);
      break;
    }
    st_policy_ctx_release(args->ctx);
  }
  return NULL;
}

static void *reset_worker(void *opaque) {
  refcount_thread_args_t *args = opaque;
  if (!await_start(args->barrier, args->failures, args->id))
    return NULL;
  for (size_t i = 0; i < RESET_ITERATIONS; i++) {
    st_error_t result = st_policy_ctx_reset(args->ctx);
    if (result != ST_OK && result != ST_ERR_INVALID) {
      record_failure(args->failures, "context reset", args->id, i);
      break;
    }
  }
  return NULL;
}

static int test_concurrent_context_refcount(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  if (!ctx)
    return 0;

  pthread_barrier_t barrier;
  if (pthread_barrier_init(&barrier, NULL, REFCOUNT_THREAD_COUNT + 1) != 0) {
    st_policy_ctx_free(ctx);
    return 0;
  }

  pthread_t threads[REFCOUNT_THREAD_COUNT];
  refcount_thread_args_t args[REFCOUNT_THREAD_COUNT];
  pthread_t resetter;
  refcount_thread_args_t reset_args;
  atomic_uint failures;
  atomic_init(&failures, 0);
  for (size_t i = 0; i < REFCOUNT_THREAD_COUNT; i++) {
    args[i] = (refcount_thread_args_t){.ctx = ctx,
                                       .barrier = &barrier,
                                       .failures = &failures,
                                       .id = (unsigned)i};
    if (pthread_create(&threads[i], NULL, refcount_worker, &args[i]) != 0) {
      fprintf(stderr, "failed to create refcount thread\n");
      exit(EXIT_FAILURE);
    }
  }
  reset_args = (refcount_thread_args_t){.ctx = ctx,
                                        .barrier = &barrier,
                                        .failures = &failures,
                                        .id = REFCOUNT_THREAD_COUNT};
  if (pthread_create(&resetter, NULL, reset_worker, &reset_args) != 0)
    exit(EXIT_FAILURE);
  for (size_t i = 0; i < REFCOUNT_THREAD_COUNT; i++)
    if (pthread_join(threads[i], NULL) != 0)
      record_failure(&failures, "thread join", (unsigned)i, 0);
  if (pthread_join(resetter, NULL) != 0)
    record_failure(&failures, "reset join", REFCOUNT_THREAD_COUNT, 0);
  if (pthread_barrier_destroy(&barrier) != 0)
    record_failure(&failures, "barrier destroy", 0, 0);

  st_policy_t *policy = st_policy_new(ctx);
  st_error_t add_result =
      policy ? st_policy_add(policy, "echo ok") : ST_ERR_MEMORY;
  size_t policy_count = policy ? st_policy_count(policy) : 0;
  bool policy_usable = policy && add_result == ST_OK && policy_count == 1 &&
                       policy_matches_exact(policy, "echo ok");
  bool passed = atomic_load(&failures) == 0 && policy_usable;
  st_policy_free(policy);
  st_policy_ctx_free(ctx);
  return passed;
}

static void *intern_worker(void *opaque) {
  intern_thread_args_t *args = opaque;
  if (!await_start(args->barrier, args->failures, args->id))
    return NULL;

  for (size_t i = 0; i < INTERN_SHARED_COUNT; i++) {
    char value[32];
    snprintf(value, sizeof(value), "shared-%zu", i);
    args->shared[i] = st_policy_ctx_intern(args->ctx, value);
    if (!args->shared[i]) {
      record_failure(args->failures, "shared intern", args->id, i);
      return NULL;
    }
  }

  /* Each thread visits the same set in a different order. This crosses the
   * pool's growth threshold while exercising duplicate lookup during rehash. */
  for (size_t i = 0; i < INTERN_UNIQUE_COUNT; i++) {
    size_t index = (i * 769 + args->id * 257) % INTERN_UNIQUE_COUNT;
    char value[48];
    snprintf(value, sizeof(value), "thread-shared-value-%zu", index);
    const char *first = st_policy_ctx_intern(args->ctx, value);
    const char *second = st_policy_ctx_intern(args->ctx, value);
    if (!first || first != second || strcmp(first, value) != 0) {
      record_failure(args->failures, "unique intern", args->id, i);
      return NULL;
    }
    args->unique[index] = first;
  }
  return NULL;
}

static int test_concurrent_context_interning(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new_with_arena(1);
  if (!ctx)
    return 0;

  pthread_barrier_t barrier;
  if (pthread_barrier_init(&barrier, NULL, INTERN_THREAD_COUNT) != 0) {
    st_policy_ctx_free(ctx);
    return 0;
  }

  pthread_t threads[INTERN_THREAD_COUNT];
  intern_thread_args_t args[INTERN_THREAD_COUNT] = {0};
  atomic_uint failures;
  atomic_init(&failures, 0);
  for (size_t i = 0; i < INTERN_THREAD_COUNT; i++) {
    args[i].ctx = ctx;
    args[i].barrier = &barrier;
    args[i].failures = &failures;
    args[i].id = (unsigned)i;
    if (pthread_create(&threads[i], NULL, intern_worker, &args[i]) != 0)
      exit(EXIT_FAILURE);
  }
  for (size_t i = 0; i < INTERN_THREAD_COUNT; i++)
    if (pthread_join(threads[i], NULL) != 0)
      record_failure(&failures, "intern join", (unsigned)i, 0);
  if (pthread_barrier_destroy(&barrier) != 0)
    record_failure(&failures, "barrier destroy", 0, 0);

  bool passed = atomic_load(&failures) == 0;
  for (size_t value = 0; value < INTERN_SHARED_COUNT; value++)
    for (size_t thread = 1; thread < INTERN_THREAD_COUNT; thread++)
      if (args[thread].shared[value] != args[0].shared[value])
        passed = false;
  for (size_t value = 0; value < INTERN_UNIQUE_COUNT; value++) {
    if (!args[0].unique[value])
      passed = false;
    for (size_t thread = 1; thread < INTERN_THREAD_COUNT; thread++)
      if (args[thread].unique[value] != args[0].unique[value])
        passed = false;
  }

  st_policy_ctx_free(ctx);
  return passed;
}

static int test_concurrent_shared_context_writes(void) {
  st_policy_ctx_t *ctx = st_policy_ctx_new_with_arena(1);
  st_policy_t *policies[] = {ctx ? st_policy_new(ctx) : NULL,
                             ctx ? st_policy_new(ctx) : NULL};
  if (!policies[0] || !policies[1]) {
    st_policy_free(policies[0]);
    st_policy_free(policies[1]);
    st_policy_ctx_free(ctx);
    return 0;
  }

  pthread_barrier_t barrier;
  if (pthread_barrier_init(&barrier, NULL, 2) != 0)
    exit(EXIT_FAILURE);
  atomic_uint failures;
  atomic_init(&failures, 0);
  pthread_t threads[2];
  policy_thread_args_t args[] = {
      {.policy = policies[0],
       .barrier = &barrier,
       .failures = &failures,
       .id = 0},
      {.policy = policies[1],
       .barrier = &barrier,
       .failures = &failures,
       .id = 1},
  };
  for (size_t i = 0; i < 2; i++)
    if (pthread_create(&threads[i], NULL, policy_writer, &args[i]) != 0)
      exit(EXIT_FAILURE);
  for (size_t i = 0; i < 2; i++)
    if (pthread_join(threads[i], NULL) != 0)
      record_failure(&failures, "shared-context join", (unsigned)i, 0);
  if (pthread_barrier_destroy(&barrier) != 0)
    record_failure(&failures, "barrier destroy", 0, 0);

  bool passed = atomic_load(&failures) == 0;
  static const char *patterns[] = {"left final", "right final"};
  for (size_t i = 0; i < 2; i++) {
    if (st_policy_count(policies[i]) != 0 ||
        st_policy_add(policies[i], patterns[i]) != ST_OK ||
        !policy_matches_exact(policies[i], patterns[i]))
      passed = false;
  }

  st_policy_free(policies[0]);
  st_policy_free(policies[1]);
  st_policy_ctx_free(ctx);
  return passed;
}

static void *reciprocal_merge_worker(void *opaque) {
  merge_thread_args_t *args = opaque;
  if (!await_start(args->barrier, args->failures, args->id))
    return NULL;
  if (st_policy_merge(args->destination, args->source) != ST_OK)
    record_failure(args->failures, "policy merge", args->id, 0);
  return NULL;
}

static int test_concurrent_reciprocal_merge(void) {
  st_policy_ctx_t *contexts[] = {st_policy_ctx_new(), st_policy_ctx_new()};
  st_policy_t *policies[] = {
      contexts[0] ? st_policy_new(contexts[0]) : NULL,
      contexts[1] ? st_policy_new(contexts[1]) : NULL,
  };
  if (!policies[0] || !policies[1] ||
      st_policy_add(policies[0], "git status") != ST_OK ||
      st_policy_add(policies[1], "docker ps") != ST_OK) {
    st_policy_free(policies[0]);
    st_policy_free(policies[1]);
    st_policy_ctx_free(contexts[0]);
    st_policy_ctx_free(contexts[1]);
    return 0;
  }

  pthread_barrier_t barrier;
  if (pthread_barrier_init(&barrier, NULL, 2) != 0)
    exit(EXIT_FAILURE);
  atomic_uint failures;
  atomic_init(&failures, 0);
  pthread_t threads[2];
  merge_thread_args_t args[] = {
      {.destination = policies[0],
       .source = policies[1],
       .barrier = &barrier,
       .failures = &failures,
       .id = 0},
      {.destination = policies[1],
       .source = policies[0],
       .barrier = &barrier,
       .failures = &failures,
       .id = 1},
  };
  for (size_t i = 0; i < 2; i++)
    if (pthread_create(&threads[i], NULL, reciprocal_merge_worker, &args[i]) !=
        0)
      exit(EXIT_FAILURE);
  for (size_t i = 0; i < 2; i++)
    if (pthread_join(threads[i], NULL) != 0)
      record_failure(&failures, "merge join", (unsigned)i, 0);
  if (pthread_barrier_destroy(&barrier) != 0)
    record_failure(&failures, "barrier destroy", 0, 0);

  bool passed = atomic_load(&failures) == 0;
  static const char *commands[] = {"git status", "docker ps"};
  for (size_t p = 0; p < 2; p++) {
    if (st_policy_count(policies[p]) != 2)
      passed = false;
    for (size_t c = 0; c < 2; c++)
      if (!policy_matches_exact(policies[p], commands[c]))
        passed = false;
  }

  st_policy_free(policies[0]);
  st_policy_free(policies[1]);
  st_policy_ctx_free(contexts[0]);
  st_policy_ctx_free(contexts[1]);
  return passed;
}

int main(void) {
  int failures = 0;
  if (!test_concurrent_policy_reads_and_writes()) {
    fprintf(stderr, "concurrent policy read/write test failed\n");
    failures++;
  }
  if (!test_concurrent_context_refcount()) {
    fprintf(stderr, "concurrent context refcount test failed\n");
    failures++;
  }
  if (!test_concurrent_context_interning()) {
    fprintf(stderr, "concurrent context interning test failed\n");
    failures++;
  }
  if (!test_concurrent_shared_context_writes()) {
    fprintf(stderr, "concurrent shared-context write test failed\n");
    failures++;
  }
  if (!test_concurrent_reciprocal_merge()) {
    fprintf(stderr, "concurrent reciprocal merge test failed\n");
    failures++;
  }
  return failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
