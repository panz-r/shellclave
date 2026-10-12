#define _POSIX_C_SOURCE 200809L
#include "shellgate.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "failed: %s\n", #condition);                             \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

enum { READER_COUNT = 2, CASE_REPETITIONS = 12 };

static const struct {
  const char *command;
  sg_verdict_t verdict;
} cases[] = {
    {"echo ok", SG_VERDICT_ALLOW},
    {"echo blocked", SG_VERDICT_DENY},
    {"echo missing", SG_VERDICT_UNDETERMINED},
};

enum { CASE_COUNT = sizeof(cases) / sizeof(cases[0]) };

static SHELL_NONNULL(1) st_policy_t *binding_policy(const char *cpl) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  if (!context)
    return NULL;
  st_policy_t *policy = st_policy_new(context);
  st_policy_ctx_release(context);
  if (policy) {
    st_netpattern_t pattern = {0};
    st_error_t error = st_netpattern_from_cpl_owned(cpl, &pattern);
    if (error == ST_OK)
      error = st_policy_add_netpattern_view(
          policy, (st_netpattern_view_t){pattern.data, pattern.length});
    st_netpattern_free(&pattern);
    if (error != ST_OK) {
      st_policy_free(policy);
      return NULL;
    }
  }
  return policy;
}

typedef struct {
  sg_gate_t *gate;
  pthread_barrier_t *barrier;
  char *buffer;
  size_t capacity;
  size_t outcomes[CASE_COUNT];
  bool success;
} shared_gate_reader_t;

static void *shared_gate_reader(void *context) {
  shared_gate_reader_t *reader = context;
  int status = pthread_barrier_wait(reader->barrier);
  reader->success = status == 0 || status == PTHREAD_BARRIER_SERIAL_THREAD;
  /* Start with both policy caches cold; the first case reaches both policies.
   */
  for (size_t repeat = 0; reader->success && repeat < CASE_REPETITIONS;
       repeat++)
    for (size_t i = 0; reader->success && i < CASE_COUNT; i++) {
      const char *command = cases[i].command;
      sg_result_t result;
      reader->success = sg_gate_evaluate(reader->gate, command, strlen(command),
                                         reader->buffer, reader->capacity,
                                         &result) == SG_OK &&
                        result.subcommand_count == 1 &&
                        result.verdict == cases[i].verdict &&
                        result.subcommands[0].verdict == cases[i].verdict;
      if (reader->success)
        reader->outcomes[i]++;
    }
  return NULL;
}

int main(void) {
  st_policy_t *allow = binding_policy("echo ok");
  st_policy_t *deny = binding_policy("echo blocked");
  CHECK(allow && deny);
  pthread_barrier_t barrier;
  CHECK(pthread_barrier_init(&barrier, NULL, READER_COUNT + 1) == 0);
  size_t max_command_length = 0;
  for (size_t i = 0; i < CASE_COUNT; i++) {
    size_t length = strlen(cases[i].command);
    if (length > max_command_length)
      max_command_length = length;
  }
  shared_gate_reader_t readers[READER_COUNT] = {{0}};
  pthread_t threads[READER_COUNT];
  for (size_t i = 0; i < READER_COUNT; i++) {
    readers[i].gate = sg_gate_new_with_policies_borrowed(allow, deny);
    readers[i].barrier = &barrier;
    readers[i].capacity = sg_gate_evaluate_size_hint(max_command_length);
    readers[i].buffer = malloc(readers[i].capacity);
    CHECK(readers[i].gate && readers[i].buffer);
    CHECK(pthread_create(&threads[i], NULL, shared_gate_reader, &readers[i]) ==
          0);
  }
  int status = pthread_barrier_wait(&barrier);
  CHECK(status == 0 || status == PTHREAD_BARRIER_SERIAL_THREAD);
  for (size_t i = 0; i < READER_COUNT; i++) {
    CHECK(pthread_join(threads[i], NULL) == 0 && readers[i].success);
    for (size_t j = 0; j < CASE_COUNT; j++)
      CHECK(readers[i].outcomes[j] == CASE_REPETITIONS);
    free(readers[i].buffer);
    sg_gate_free(readers[i].gate);
  }
  CHECK(pthread_barrier_destroy(&barrier) == 0);
  st_policy_stats_t stats;
  st_policy_get_stats(allow, &stats);
  CHECK(stats.eval_count == 48 && st_policy_rule_count(allow) == 1);
  st_policy_get_stats(deny, &stats);
  CHECK(stats.eval_count == 72 && st_policy_rule_count(deny) == 1);
  st_policy_free(allow);
  st_policy_free(deny);
  puts("shared policy gate readers passed");
  return 0;
}
