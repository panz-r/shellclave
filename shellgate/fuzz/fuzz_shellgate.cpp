/*
 * fuzz_shellgate - Fuzzing harness for shellgate with anomaly detection
 *
 * Exercises sg_eval with anomaly detection enabled (raw + type models),
 * trained-model scoring, cache hits, deny-rule evaluation, and variably-
 * sized output buffers that exercise the truncation paths.
 *
 * Build with libFuzzer:
 *   cmake -S ../.. -B ../../build-fuzz -DSHELLCLAVE_BUILD_FUZZERS=ON \
 *     -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
 *   cmake --build ../../build-fuzz --target fuzz_shellgate
 *
 * Run:
 *   ../../build-fuzz/fuzz_shellgate -max_total_time=300 \
 *     -artifact_prefix=../../build-fuzz/fuzz-artifacts/shellgate/ \
 *     ../../build-fuzz/fuzz-corpus/shellgate
 */

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "shellgate.h"
}

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

namespace {

constexpr int kPoolSize = 8;

/* Curated deny patterns. Variability comes from the pool: each entry gets a
 * different subset of these, so the rule-evaluation path is exercised with
 * varied policy state across invocations. Allow rules are intentionally
 * avoided: sg_gate_set_anomaly_update_mode(true) only freezes the model on
 * ALLOW verdicts, and adding allow rules would let the model drift between
 * the eval and replay calls and silently break the determinism check. */
const char *kDenyRules[] = {"rm -rf *", "chmod 777 *", "dd if=* of=*",
                            "mkfs *",   ":(){:|:&};:", "shutdown *",
                            "reboot",   "wget * | sh", "curl * | sh"};
constexpr int kDenyRulesN = sizeof(kDenyRules) / sizeof(kDenyRules[0]);

/* Seed commands for pre-training the anomaly model. */
const char *kSeedCmds[] = {"ls",
                           "cd /tmp",
                           "pwd",
                           "cat file.txt",
                           "grep pattern file.txt",
                           "echo hello",
                           "mkdir dir",
                           "cp a b",
                           "mv b c",
                           "rm c",
                           "ls ; cd /tmp ; pwd",
                           "cat file.txt ; grep pattern ; sort",
                           "echo hello ; sleep 1 ; true",
                           "mkdir dir ; chmod 755 dir ; ls dir",
                           "cp a b ; mv b c ; rm c",
                           "find . -name '*.c' ; xargs grep TODO ; wc -l",
                           "git status ; git add . ; git commit -m fix",
                           "make clean ; make -j4 ; make test",
                           "sort file.txt ; uniq ; wc -l",
                           "head -n 10 file.txt ; tail -n 10 file.txt"};
constexpr int kSeedCmdsN = sizeof(kSeedCmds) / sizeof(kSeedCmds[0]);

sg_gate_t *g_pool[kPoolSize];

void invariant_failure(const char *message) {
  fprintf(stderr, "shellgate fuzz invariant failed: %s\n", message);
  abort();
}

int valid_buffer_string(const char *value, const char *buffer, size_t size) {
  if (!value)
    return 1;
  uintptr_t address = (uintptr_t)value;
  uintptr_t begin = (uintptr_t)buffer;
  if (address < begin || address >= begin + size)
    return 0;
  return memchr(value, '\0', size - (size_t)(address - begin)) != NULL;
}

void validate_result(const sg_result_t *result, sg_error_t error,
                     const char *buffer, size_t buffer_size) {
  if (result->verdict < SG_VERDICT_ALLOW ||
      result->verdict > SG_VERDICT_UNDETERMINED ||
      result->subcmd_count > SG_MAX_SUBCMD_RESULTS ||
      result->violation_count > SG_MAX_VIOLATIONS ||
      result->suggestion_count > 2 || result->deny_suggestion_count > 2 ||
      (error == SG_ERR_TRUNC) != result->truncated ||
      !valid_buffer_string(result->deny_reason, buffer, buffer_size))
    invariant_failure("result field outside its documented bounds");

  for (uint32_t i = 0; i < result->subcmd_count; i++)
    if (!valid_buffer_string(result->subcmds[i].command, buffer, buffer_size) ||
        !valid_buffer_string(result->subcmds[i].reject_reason, buffer,
                             buffer_size))
      invariant_failure("subcommand string outside the output buffer");
  for (uint32_t i = 0; i < result->suggestion_count; i++)
    if (!valid_buffer_string(result->suggestions[i], buffer, buffer_size))
      invariant_failure("suggestion outside the output buffer");
  for (uint32_t i = 0; i < result->deny_suggestion_count; i++)
    if (!valid_buffer_string(result->deny_suggestions[i], buffer, buffer_size))
      invariant_failure("deny suggestion outside the output buffer");
  for (uint32_t i = 0; i < result->violation_count; i++)
    if (!valid_buffer_string(result->violations[i].description, buffer,
                             buffer_size) ||
        !valid_buffer_string(result->violations[i].detail, buffer, buffer_size))
      invariant_failure("violation string outside the output buffer");
}

sg_gate_t *create_pool_gate(int idx) {
  sg_gate_t *g = sg_gate_new();
  if (!g)
    invariant_failure("sg_gate_new failed");
  if (sg_gate_enable_anomaly(g, 5.0, 0.1, -10.0) != SG_OK)
    invariant_failure("sg_gate_enable_anomaly failed");

  char train_buf[8192];
  sg_result_t training_result;
  for (int i = 0; i < kSeedCmdsN; i++) {
    if (sg_eval(g, kSeedCmds[i], strlen(kSeedCmds[i]), train_buf,
                sizeof(train_buf), &training_result) != SG_OK)
      invariant_failure("anomaly model training failed");
  }
  if (sg_gate_set_anomaly_update_mode(g, true) != SG_OK)
    invariant_failure("sg_gate_set_anomaly_update_mode failed");

  int nrules = idx % 4;
  for (int j = 0; j < nrules; j++) {
    const char *p = kDenyRules[(idx * 3 + j * 7) % kDenyRulesN];
    sg_gate_add_deny_rule(g, p);
  }
  return g;
}

void cleanup() {
  for (int i = 0; i < kPoolSize; i++) {
    if (g_pool[i]) {
      sg_gate_free(g_pool[i]);
      g_pool[i] = nullptr;
    }
  }
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;

  for (int i = 0; i < kPoolSize; i++)
    g_pool[i] = create_pool_gate(i);

  atexit(cleanup);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0)
    return 0;

  FuzzedDataProvider fdp(data, size);
  int pool_idx = fdp.ConsumeIntegral<uint8_t>() & (kPoolSize - 1);

  if (fdp.remaining_bytes() < 2)
    return 0;
  uint16_t raw = fdp.ConsumeIntegral<uint16_t>();
  size_t buf_size = 16 + (size_t)((uint32_t)raw * 4080u / 65535u);

  std::string cmd = fdp.ConsumeRemainingBytesAsString();
  if (cmd.empty())
    return 0;

  /* sg_eval requires cmd_len == strlen(cmd). Map embedded NUL bytes to spaces
   * so arbitrary fuzzer data stays within that public API contract. */
  for (char &c : cmd) {
    if (c == 0)
      c = ' ';
  }

  std::vector<char> result_buf(buf_size);
  std::vector<char> replay_buf(buf_size);

  sg_gate_t *g = g_pool[pool_idx];
  sg_result_t result, replay;

  sg_error_t err =
      sg_eval(g, cmd.data(), cmd.size(), result_buf.data(), buf_size, &result);
  if (err != SG_OK && err != SG_ERR_TRUNC && err != SG_ERR_MEMORY)
    invariant_failure("unexpected sg_eval error");
  if (err == SG_ERR_MEMORY)
    return 0;

  if (!isfinite(result.anomaly_score) || !isfinite(result.anomaly_score_raw) ||
      !isfinite(result.anomaly_score_type))
    invariant_failure("non-finite anomaly score with a trained model");

  validate_result(&result, err, result_buf.data(), buf_size);

  sg_error_t replay_err =
      sg_eval(g, cmd.data(), cmd.size(), replay_buf.data(), buf_size, &replay);
  if (replay_err != err || replay.verdict != result.verdict ||
      replay.subcmd_count != result.subcmd_count ||
      replay.violation_count != result.violation_count ||
      replay.violation_flags != result.violation_flags ||
      replay.anomaly_detected != result.anomaly_detected ||
      replay.anomaly_score != result.anomaly_score ||
      replay.anomaly_score_raw != result.anomaly_score_raw ||
      replay.anomaly_score_type != result.anomaly_score_type)
    invariant_failure("frozen-model replay was not deterministic");
  validate_result(&replay, replay_err, replay_buf.data(), buf_size);

  return 0;
}

/* Standalone driver for environments without libFuzzer */
#if !defined(HAS_LIBFUZZER) && !defined(__AFL_COMPILER)
int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  LLVMFuzzerInitialize(NULL, NULL);

  std::vector<char> cmd_buf(8192);
  size_t n = fread(cmd_buf.data(), 1, cmd_buf.size() - 1, stdin);
  if (n == 0) {
    fprintf(stderr, "Usage: echo 'cmd' | ./fuzz_shellgate\n");
    return 0;
  }
  LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t *>(cmd_buf.data()), n);
  fprintf(stderr, "OK\n");
  return 0;
}
#endif
