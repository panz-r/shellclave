/* End-to-end regression coverage for the anonymous coding-agent command set.
 * Fixture commands are data only: this test never executes them. */

#include "shell_netstring.h"
#include "shellgate.h"
#include "shellgate_corpus_fixtures.h"
#include "shelltype.h"
#include <float.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ARRAY_COUNT(values) (sizeof(values) / sizeof((values)[0]))
#define EVAL_BUFFER_SIZE 65536u

static int passed;
static int failed;

/* This is a deliberately exact corpus baseline, not a policy claim. Update
 * it only alongside an intentional fixture or evaluator behavior change. */
static const struct {
  size_t commands;
  size_t allows;
  size_t denies;
  size_t undetermined;
  size_t multi_stage;
  size_t shell_word_substitutions;
  size_t dynamic_substitution_io;
  uint64_t outcome_fingerprint;
} corpus_baseline = {246u, 120u, 21u, 105u,
                     141u, 2u,   17u, UINT64_C(0xfc034c8d13cbde41)};

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      printf("    FAIL: %s at %s:%d\n", #condition, __FILE__, __LINE__);       \
      failed++;                                                                \
      return false;                                                            \
    }                                                                          \
  } while (0)

#define TEST(name) static bool test_##name(void)
#define RUN(name)                                                              \
  do {                                                                         \
    printf("  %-42s ", #name);                                                 \
    if (test_##name()) {                                                       \
      puts("PASS");                                                            \
      passed++;                                                                \
    }                                                                          \
  } while (0)

static const char *const allow_rules[] = {
    "cd #path",
    "make",
    "make *",
    "ctest *",
    "cat #path",
    "cat #path #path",
    "cat #path #path #path",
    "grep * #path",
    "grep * * #path",
    "grep * * #path *",
    "head *",
    "head * #path",
    "tail *",
    "tail * #path",
    "wc *",
    "wc * #path",
    "find #path * *",
    "ls",
    "ls *",
    "nm #path",
    "diff * *",
    "test * #path",
    "echo *",
    "true",
    "sort *",
    "valgrind * * #path",
    "gcc * #path",
    "objdump * #path",
    "strings #path",
    "stat #path",
};

static const char *const deny_rules[] = {
    "rm * *",       "rm * * *",       "rm * * * *",
    "rm * * * * *", "sed -i * #path", "sed -i * #path *",
    "mkdir #path",  "mkdir * #path",  "make clean",
};

static sg_gate_t *new_policy_gate(void) {
  sg_gate_t *gate = sg_gate_new();
  if (!gate)
    return NULL;
  if (sg_gate_set_stop_mode(gate, SG_EVAL_ALL) != SG_OK ||
      sg_gate_set_reject_mask(gate, 0) != SG_OK)
    goto fail;
  for (size_t i = 0; i < ARRAY_COUNT(allow_rules); i++)
    if (sg_gate_add_allow_cpl(gate, allow_rules[i]) != SG_OK)
      goto fail;
  for (size_t i = 0; i < ARRAY_COUNT(deny_rules); i++)
    if (sg_gate_add_deny_cpl(gate, deny_rules[i]) != SG_OK)
      goto fail;
  return gate;

fail:
  sg_gate_free(gate);
  return NULL;
}

static sg_error_t evaluate(sg_gate_t *gate, const char *command,
                           sg_result_t *result) {
  static char buffer[EVAL_BUFFER_SIZE];
  memset(buffer, 0, sizeof(buffer));
  return sg_gate_evaluate(gate, command, strlen(command), buffer,
                          sizeof(buffer), result);
}

static bool netargv_is_valid(const sg_subcommand_result_t *subcommand) {
  if (!subcommand->netargv ||
      strlen(subcommand->netargv) != subcommand->netargv_length)
    return false;
  size_t records = 0;
  if (shell_netstring_validate(subcommand->netargv, subcommand->netargv_length,
                               &records) != SHELL_NETSTRING_OK ||
      records == 0)
    return false;
  st_token_array_t tokens = {0};
  st_error_t error = st_netargv_classify(subcommand->netargv, &tokens);
  bool valid = error == ST_OK && tokens.count == records;
  st_token_array_free(&tokens);
  return valid;
}

static const char *find_fixture(const char *fragment) {
  for (size_t i = 0; i < SHELLGATE_CORPUS_COMMAND_COUNT; i++)
    if (strstr(shellgate_corpus_commands[i], fragment))
      return shellgate_corpus_commands[i];
  return NULL;
}

/* Keep fixture position in the regression contract without hashing source
 * text. The sanitized data may be intentionally refreshed, while a changed
 * evaluation outcome for any existing position must be reviewed explicitly. */
static uint64_t hash_u32(uint64_t hash, uint32_t value) {
  for (size_t i = 0; i < sizeof(value); i++) {
    hash ^= (uint8_t)(value & 0xffu);
    hash *= UINT64_C(1099511628211);
    value >>= 8;
  }
  return hash;
}

static uint64_t fingerprint_result(uint64_t hash, const sg_result_t *result) {
  hash = hash_u32(hash, (uint32_t)result->verdict);
  hash = hash_u32(hash, result->subcommand_count);
  hash = hash_u32(hash, result->requires_substitution_evaluation);
  hash = hash_u32(hash, result->has_dynamic_substitution_io);
  hash = hash_u32(hash, result->violation_category_flags);
  return hash_u32(hash, result->violation_type_flags);
}

TEST(fixture_contract) {
  CHECK(SHELLGATE_CORPUS_COMMAND_COUNT == corpus_baseline.commands);
  for (size_t i = 0; i < SHELLGATE_CORPUS_COMMAND_COUNT; i++) {
    const unsigned char *cursor =
        (const unsigned char *)shellgate_corpus_commands[i];
    CHECK(*cursor != '\0');
    for (; *cursor != '\0'; cursor++)
      CHECK(*cursor < 0x80u);
  }
  CHECK(find_fixture("diff <(grep -E") != NULL);
  CHECK(find_fixture("rm -f /reports/incoming") != NULL);
  return true;
}

TEST(policy_and_canonical_results) {
  sg_gate_t *gate = new_policy_gate();
  CHECK(gate != NULL);

  size_t allows = 0, denies = 0, undetermined = 0;
  size_t multi_stage = 0, shell_word_substitutions = 0;
  size_t dynamic_substitution_io = 0;
  uint64_t fingerprint = UINT64_C(1469598103934665603);
  bool saw_suggestion = false;
  for (size_t i = 0; i < SHELLGATE_CORPUS_COMMAND_COUNT; i++) {
    sg_result_t result = {0};
    CHECK(evaluate(gate, shellgate_corpus_commands[i], &result) == SG_OK);
    CHECK(!result.truncated);
    CHECK(!result.short_circuited);
    CHECK(result.subcommand_count > 0);
    if (result.subcommand_count > 1)
      multi_stage++;
    if (result.requires_substitution_evaluation)
      shell_word_substitutions++;
    if (result.has_dynamic_substitution_io)
      dynamic_substitution_io++;
    fingerprint = fingerprint_result(fingerprint, &result);
    for (uint32_t j = 0; j < result.subcommand_count; j++)
      CHECK(netargv_is_valid(&result.subcommands[j]));
    if (result.verdict == SG_VERDICT_ALLOW)
      allows++;
    else if (result.verdict == SG_VERDICT_DENY)
      denies++;
    else if (result.verdict == SG_VERDICT_UNDETERMINED) {
      undetermined++;
      saw_suggestion |= result.suggestion_count > 0;
    } else {
      CHECK(false);
    }
  }
  if (allows != corpus_baseline.allows || denies != corpus_baseline.denies ||
      undetermined != corpus_baseline.undetermined ||
      multi_stage != corpus_baseline.multi_stage ||
      shell_word_substitutions != corpus_baseline.shell_word_substitutions ||
      dynamic_substitution_io != corpus_baseline.dynamic_substitution_io ||
      fingerprint != corpus_baseline.outcome_fingerprint)
    printf("    observed outcomes: allow=%zu deny=%zu undetermined=%zu "
           "multi-stage=%zu shell-word=%zu dynamic-I/O=%zu fingerprint=%" PRIx64
           "\n",
           allows, denies, undetermined, multi_stage, shell_word_substitutions,
           dynamic_substitution_io, fingerprint);
  CHECK(allows == corpus_baseline.allows);
  CHECK(denies == corpus_baseline.denies);
  CHECK(undetermined == corpus_baseline.undetermined);
  CHECK(multi_stage == corpus_baseline.multi_stage);
  CHECK(shell_word_substitutions == corpus_baseline.shell_word_substitutions);
  CHECK(dynamic_substitution_io == corpus_baseline.dynamic_substitution_io);
  CHECK(fingerprint == corpus_baseline.outcome_fingerprint);
  CHECK(saw_suggestion);

  sg_result_t result = {0};
  const char *allow = find_fixture("cd /project/build && make 2>&1");
  const char *deny = find_fixture("rm -rf build");
  const char *unknown = find_fixture("cmake --build .");
  const char *process_substitution = find_fixture("diff <(grep -E");
  CHECK(allow && deny && unknown && process_substitution);
  CHECK(evaluate(gate, allow, &result) == SG_OK &&
        result.verdict == SG_VERDICT_ALLOW);
  CHECK(evaluate(gate, deny, &result) == SG_OK &&
        result.verdict == SG_VERDICT_DENY);
  CHECK(evaluate(gate, unknown, &result) == SG_OK &&
        result.verdict == SG_VERDICT_UNDETERMINED);
  CHECK(evaluate(gate, process_substitution, &result) == SG_OK &&
        !result.requires_substitution_evaluation &&
        result.has_dynamic_substitution_io);
  sg_gate_free(gate);
  return true;
}

static bool train_corpus_model(sg_gate_t *gate) {
  for (size_t i = 0; i < SHELLGATE_CORPUS_COMMAND_COUNT; i++) {
    sg_result_t result = {0};
    if (evaluate(gate, shellgate_corpus_commands[i], &result) != SG_OK)
      return false;
  }
  return sg_gate_anomaly_vocab_size(gate) > 0;
}

TEST(anomaly_cache_equivalence) {
  const char *normal =
      "cd /project && grep -n data_store /project/src/data_store.c | wc -l "
      "&& echo done";
  const char *reordered =
      "echo done && wc -l /project/src/data_store.c | grep -n data_store "
      "/project/src/data_store.c && cd /project";
  sg_gate_t *cached = new_policy_gate();
  sg_gate_t *plain = new_policy_gate();
  CHECK(cached && plain);
  for (size_t i = 0; i < 2; i++) {
    sg_gate_t *gate = i == 0 ? cached : plain;
    CHECK(sg_gate_enable_anomaly(gate, DBL_MAX, NULL) == SG_OK);
    CHECK(sg_gate_set_anomaly_update_mode(gate, true) == SG_OK);
    CHECK(sg_gate_set_anomaly_skip_on_detected(gate, false) == SG_OK);
    if (gate == cached)
      CHECK(sg_gate_set_anomaly_cache_size(gate, 32) == SG_OK);
    CHECK(train_corpus_model(gate));
    for (size_t repeat = 0; repeat < 16; repeat++) {
      sg_result_t result = {0};
      CHECK(evaluate(gate, normal, &result) == SG_OK);
      CHECK(result.verdict == SG_VERDICT_ALLOW);
    }
  }

  sg_result_t cached_normal = {0}, plain_normal = {0};
  sg_result_t cached_reordered = {0}, plain_reordered = {0};
  CHECK(evaluate(cached, normal, &cached_normal) == SG_OK);
  CHECK(evaluate(plain, normal, &plain_normal) == SG_OK);
  CHECK(evaluate(cached, reordered, &cached_reordered) == SG_OK);
  CHECK(evaluate(plain, reordered, &plain_reordered) == SG_OK);
  CHECK(isfinite(cached_normal.anomaly_score));
  CHECK(isfinite(cached_normal.anomaly_score_raw));
  CHECK(isfinite(cached_normal.anomaly_score_type));
  CHECK(cached_reordered.anomaly_score > cached_normal.anomaly_score);
  CHECK(fabs(cached_normal.anomaly_score - plain_normal.anomaly_score) < 1e-12);
  CHECK(fabs(cached_normal.anomaly_score_raw - plain_normal.anomaly_score_raw) <
        1e-12);
  CHECK(fabs(cached_normal.anomaly_score_type -
             plain_normal.anomaly_score_type) < 1e-12);
  CHECK(fabs(cached_reordered.anomaly_score - plain_reordered.anomaly_score) <
        1e-12);
  sg_gate_free(cached);
  sg_gate_free(plain);
  return true;
}

TEST(corpus_violation_configuration) {
  sg_gate_t *gate = new_policy_gate();
  CHECK(gate != NULL);
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_dirs[0] = "/reports/incoming";
  config.sensitive_dir_count = 1;
  CHECK(sg_gate_set_violation_config_borrowed(gate, &config) == SG_OK);
  const char *fixture = find_fixture("rm -f /reports/incoming");
  sg_result_t result = {0};
  CHECK(fixture != NULL);
  CHECK(evaluate(gate, fixture, &result) == SG_OK);
  CHECK(result.has_violations);
  CHECK(result.violation_type_flags & SG_VIOL_REMOVE_SYSTEM);
  CHECK(result.violation_count > 0);
  for (uint32_t i = 0; i < result.violation_count; i++) {
    CHECK(result.violations[i].type != 0);
    CHECK(result.violations[i].description != NULL);
  }
  sg_gate_free(gate);
  return true;
}

int main(void) {
  puts("shellgate corpus tests\n");
  RUN(fixture_contract);
  RUN(policy_and_canonical_results);
  RUN(anomaly_cache_equivalence);
  RUN(corpus_violation_configuration);
  printf("\n%d passed, %d failed\n", passed, failed);
  return failed != 0;
}
