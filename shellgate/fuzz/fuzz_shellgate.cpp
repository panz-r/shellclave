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
 * Run a bounded session (successful discoveries are disposable):
 *   ./shellgate/fuzz/run_fuzzing_4h.sh 1 300
 */

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "shellgate.h"
}

#include <algorithm>
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

sg_gate_t *g_anomaly_pool[kPoolSize];
sg_gate_t *g_policy_pool[kPoolSize];

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

bool valid_verdict(sg_verdict_t verdict) {
  switch (verdict) {
  case SG_VERDICT_ALLOW:
  case SG_VERDICT_DENY:
  case SG_VERDICT_REJECT:
  case SG_VERDICT_UNDETERMINED:
  case SG_VERDICT_ALLOW_CONDITIONAL:
    return true;
  }
  return false;
}

bool equal_string(const char *left, const char *right) {
  if (!left || !right)
    return left == right;
  return std::strcmp(left, right) == 0;
}

void validate_result(const sg_result_t *result, sg_error_t error,
                     const char *buffer, size_t buffer_size) {
  if (!valid_verdict(result->verdict) ||
      result->subcmd_count > SG_MAX_SUBCMD_RESULTS ||
      result->violation_count > SG_MAX_VIOLATIONS ||
      result->suggestion_count > 2 || result->deny_suggestion_count > 2 ||
      (error == SG_ERR_TRUNC) != result->truncated ||
      (error == SG_ERR_TRUNC &&
       (result->verdict == SG_VERDICT_ALLOW ||
        result->verdict == SG_VERDICT_ALLOW_CONDITIONAL)) ||
      result->violation_flags != result->violation_type_flags ||
      result->has_violations != (result->violation_count != 0) ||
      !valid_buffer_string(result->deny_reason, buffer, buffer_size)) {
    invariant_failure("result field outside its documented bounds");
  }

  bool linked_substitution = false;
  for (uint32_t i = 0; i < result->subcmd_count; i++) {
    if (!valid_buffer_string(result->subcmds[i].command, buffer, buffer_size) ||
        !valid_buffer_string(result->subcmds[i].reject_reason, buffer,
                             buffer_size) ||
        !valid_verdict(result->subcmds[i].verdict) ||
        result->subcmds[i].violation_flags !=
            result->subcmds[i].violation_type_flags ||
        result->subcmds[i].substitution_parent_index >=
            static_cast<int32_t>(result->subcmd_count))
      invariant_failure("subcommand string outside the output buffer");
    linked_substitution = linked_substitution ||
                          result->subcmds[i].substitution_parent_index >= 0;
  }
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

  if (result->verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
      (!result->requires_substitution_evaluation || !linked_substitution))
    invariant_failure("conditional allowance lacks a substitution dependency");
  if (result->short_circuited && result->subcmd_count == 0)
    invariant_failure("short-circuit result has no evaluated prefix");
}

bool results_equal(const sg_result_t &left, const sg_result_t &right) {
  if (left.verdict != right.verdict ||
      !equal_string(left.deny_reason, right.deny_reason) ||
      left.subcmd_count != right.subcmd_count ||
      left.suggestion_count != right.suggestion_count ||
      left.deny_suggestion_count != right.deny_suggestion_count ||
      left.attention_index != right.attention_index ||
      left.truncated != right.truncated ||
      left.subcmd_truncated != right.subcmd_truncated ||
      left.violation_truncated != right.violation_truncated ||
      left.short_circuited != right.short_circuited ||
      left.violation_count != right.violation_count ||
      left.violation_category_flags != right.violation_category_flags ||
      left.violation_type_flags != right.violation_type_flags ||
      left.requires_substitution_evaluation !=
          right.requires_substitution_evaluation ||
      left.violation_flags != right.violation_flags ||
      left.violation_dropped_count != right.violation_dropped_count ||
      left.has_violations != right.has_violations ||
      left.anomaly_detected != right.anomaly_detected ||
      left.anomaly_score != right.anomaly_score ||
      left.anomaly_score_raw != right.anomaly_score_raw ||
      left.anomaly_score_type != right.anomaly_score_type)
    return false;

  for (uint32_t i = 0; i < left.subcmd_count; i++) {
    const sg_subcmd_result_t &a = left.subcmds[i];
    const sg_subcmd_result_t &b = right.subcmds[i];
    if (a.matches != b.matches || a.verdict != b.verdict ||
        !equal_string(a.command, b.command) ||
        !equal_string(a.reject_reason, b.reject_reason) ||
        a.write_count != b.write_count || a.read_count != b.read_count ||
        a.env_count != b.env_count ||
        a.requires_substitution_evaluation !=
            b.requires_substitution_evaluation ||
        a.substitution_parent_index != b.substitution_parent_index ||
        a.violation_category_flags != b.violation_category_flags ||
        a.violation_type_flags != b.violation_type_flags ||
        a.violation_flags != b.violation_flags)
      return false;
  }
  for (uint32_t i = 0; i < left.suggestion_count; i++)
    if (!equal_string(left.suggestions[i], right.suggestions[i]))
      return false;
  for (uint32_t i = 0; i < left.deny_suggestion_count; i++)
    if (!equal_string(left.deny_suggestions[i], right.deny_suggestions[i]))
      return false;
  for (uint32_t i = 0; i < left.violation_count; i++) {
    const sg_violation_t &a = left.violations[i];
    const sg_violation_t &b = right.violations[i];
    if (a.type != b.type || a.category_flags != b.category_flags ||
        a.severity != b.severity || a.cmd_node_index != b.cmd_node_index ||
        !equal_string(a.description, b.description) ||
        !equal_string(a.detail, b.detail))
      return false;
  }
  return true;
}

/* A compact, parser-independent semantic reference set. These cases describe
 * the supported shell dialect rather than duplicating the production parser:
 * each executable substitution must become one command node, point at its
 * containing command, and contribute to conditional allowance exactly once. */
void run_semantic_reference_oracles() {
  struct oracle_case {
    const char *input;
    const char *const *rules;
    size_t rule_count;
    uint32_t command_count;
    int32_t parents[4];
    sg_verdict_t verdict;
  };
  static const char *const echo_id_pwd[] = {"echo *", "id", "pwd"};
  static const char *const nested[] = {"echo *", "echo $(printf x $(id))",
                                       "printf x $(id)", "id"};
  static const char *const process[] = {"cat", "sort", "cat #path"};
  static const char *const quoted[] = {"echo *", "id"};
  static const oracle_case cases[] = {
      {"echo $(id)$(pwd)",
       echo_id_pwd,
       3,
       3,
       {-1, 0, 0},
       SG_VERDICT_ALLOW_CONDITIONAL},
      {"echo $(printf x $(id))",
       nested,
       4,
       3,
       {-1, 0, 1},
       SG_VERDICT_ALLOW_CONDITIONAL},
      {"cat <(sort <(cat /tmp/a))",
       process,
       3,
       3,
       {-1, 0, 1},
       SG_VERDICT_ALLOW_CONDITIONAL},
      {"echo \"$(id)\"",
       quoted,
       2,
       2,
       {-1, 0, -1},
       SG_VERDICT_ALLOW_CONDITIONAL},
  };

  for (const oracle_case &item : cases) {
    sg_gate_t *gate = sg_gate_new();
    if (!gate || sg_gate_set_reject_mask(gate, 0) != SG_OK ||
        sg_gate_set_stop_mode(gate, SG_EVAL_ALL) != SG_OK)
      invariant_failure("semantic oracle gate setup failed");
    for (size_t i = 0; i < item.rule_count; i++)
      if (sg_gate_add_rule(gate, item.rules[i]) != SG_OK)
        invariant_failure("semantic oracle rule setup failed");

    char buffer[4096];
    sg_result_t result = {};
    sg_error_t error = sg_eval(gate, item.input, std::strlen(item.input),
                               buffer, sizeof(buffer), &result);
    if (error != SG_OK || result.verdict != item.verdict ||
        result.subcmd_count != item.command_count ||
        result.requires_substitution_evaluation !=
            (item.verdict == SG_VERDICT_ALLOW_CONDITIONAL))
      invariant_failure("semantic oracle verdict or command count mismatch");
    for (uint32_t i = 0; i < item.command_count; i++)
      if (result.subcmds[i].substitution_parent_index != item.parents[i])
        invariant_failure("semantic oracle parent relationship mismatch");
    sg_gate_free(gate);
  }
}

void validate_gate_pair(sg_gate_t *left, sg_gate_t *right) {
  if (sg_gate_rule_count(left) != sg_gate_rule_count(right) ||
      sg_gate_deny_rule_count(left) != sg_gate_deny_rule_count(right) ||
      sg_gate_anomaly_vocab_size(left) != sg_gate_anomaly_vocab_size(right) ||
      sg_gate_anomaly_had_error(left) != sg_gate_anomaly_had_error(right))
    invariant_failure("mirrored gate state diverged");
}

void run_stateful(FuzzedDataProvider &fdp) {
  static const char *rules[] = {"echo *",  "ls",         "cat #path", "rm *",
                                "git * *", "chmod #n *", "whoami"};
  sg_gate_t *left = sg_gate_new();
  sg_gate_t *right = sg_gate_new();
  if (!left || !right)
    invariant_failure("stateful gate construction failed");

  size_t steps = fdp.ConsumeIntegralInRange<size_t>(1, 24);
  for (size_t step = 0; step < steps && fdp.remaining_bytes() > 0; step++) {
    uint8_t operation = fdp.ConsumeIntegral<uint8_t>() % 13;
    sg_error_t a = SG_OK, b = SG_OK;
    switch (operation) {
    case 0: {
      const char *rule = rules[fdp.ConsumeIntegral<uint8_t>() % 7];
      a = sg_gate_add_rule(left, rule);
      b = sg_gate_add_rule(right, rule);
      break;
    }
    case 1: {
      const char *rule = rules[fdp.ConsumeIntegral<uint8_t>() % 7];
      a = sg_gate_remove_rule(left, rule);
      b = sg_gate_remove_rule(right, rule);
      break;
    }
    case 2: {
      const char *rule = rules[fdp.ConsumeIntegral<uint8_t>() % 7];
      a = sg_gate_add_deny_rule(left, rule);
      b = sg_gate_add_deny_rule(right, rule);
      break;
    }
    case 3: {
      const char *rule = rules[fdp.ConsumeIntegral<uint8_t>() % 7];
      a = sg_gate_remove_deny_rule(left, rule);
      b = sg_gate_remove_deny_rule(right, rule);
      break;
    }
    case 4: {
      sg_stop_mode_t mode =
          static_cast<sg_stop_mode_t>(fdp.ConsumeIntegral<uint8_t>() % 5);
      a = sg_gate_set_stop_mode(left, mode);
      b = sg_gate_set_stop_mode(right, mode);
      break;
    }
    case 5: {
      uint32_t mask = fdp.ConsumeIntegral<uint16_t>();
      a = sg_gate_set_reject_mask(left, mask);
      b = sg_gate_set_reject_mask(right, mask);
      break;
    }
    case 6: {
      bool enabled = fdp.ConsumeBool();
      a = sg_gate_set_suggestions(left, enabled);
      b = sg_gate_set_suggestions(right, enabled);
      break;
    }
    case 7:
      a = sg_gate_enable_anomaly(left, 5.0, 0.1, -10.0);
      b = sg_gate_enable_anomaly(right, 5.0, 0.1, -10.0);
      break;
    case 8:
      sg_gate_disable_anomaly(left);
      sg_gate_disable_anomaly(right);
      break;
    case 9: {
      size_t cache_size = fdp.ConsumeIntegral<uint8_t>() % 9;
      a = sg_gate_set_anomaly_cache_size(left, cache_size);
      b = sg_gate_set_anomaly_cache_size(right, cache_size);
      break;
    }
    case 10: {
      bool adaptive = fdp.ConsumeBool();
      size_t window = 1 + fdp.ConsumeIntegral<uint8_t>() % 16;
      a = sg_gate_set_anomaly_adaptive(left, adaptive, window);
      b = sg_gate_set_anomaly_adaptive(right, adaptive, window);
      break;
    }
    case 11: {
      sg_anomaly_combine_mode_t mode = fdp.ConsumeBool()
                                           ? SG_ANOMALY_COMBINE_BAYESIAN
                                           : SG_ANOMALY_COMBINE_WEIGHTED;
      a = sg_gate_set_anomaly_combine_mode(left, mode);
      b = sg_gate_set_anomaly_combine_mode(right, mode);
      break;
    }
    case 12: {
      size_t remaining = fdp.remaining_bytes();
      size_t length = remaining == 0 ? 0
                                     : fdp.ConsumeIntegralInRange<size_t>(
                                           1, std::min<size_t>(128, remaining));
      std::string command =
          length == 0 ? std::string("x") : fdp.ConsumeBytesAsString(length);
      for (char &c : command)
        if (c == 0)
          c = ' ';
      char left_buffer[4096], right_buffer[4096];
      sg_result_t left_result = {}, right_result = {};
      a = sg_eval(left, command.c_str(), command.size(), left_buffer,
                  sizeof(left_buffer), &left_result);
      b = sg_eval(right, command.c_str(), command.size(), right_buffer,
                  sizeof(right_buffer), &right_result);
      validate_result(&left_result, a, left_buffer, sizeof(left_buffer));
      validate_result(&right_result, b, right_buffer, sizeof(right_buffer));
      if (a != b || !results_equal(left_result, right_result))
        invariant_failure("mirrored stateful evaluation diverged");
      break;
    }
    }
    if (a != b)
      invariant_failure("mirrored state transition diverged");
    validate_gate_pair(left, right);
  }
  sg_gate_free(right);
  sg_gate_free(left);
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

sg_gate_t *create_policy_gate(int idx) {
  static const char *allow_rules[] = {
      "echo *",    "whoami",    "ls",     "sort", "pwd",
      "cat #path", "git * * *", "curl *", "rm *", "chmod #n *"};
  static const char *deny_rules[] = {"whoami", "cat /etc/shadow", "rm *",
                                     "curl *", "chmod 777 *"};

  sg_gate_t *gate = sg_gate_new();
  if (!gate)
    invariant_failure("sg_gate_new failed");
  if (sg_gate_set_reject_mask(gate, idx == 0 ? 0 : SG_REJECT_MASK_DEFAULT) !=
          SG_OK ||
      sg_gate_set_stop_mode(gate, static_cast<sg_stop_mode_t>(idx % 5)) !=
          SG_OK ||
      sg_gate_set_suggestions(gate, (idx & 1) == 0) != SG_OK)
    invariant_failure("policy gate configuration failed");

  int allow_count =
      static_cast<int>(sizeof(allow_rules) / sizeof(*allow_rules));
  int deny_count = static_cast<int>(sizeof(deny_rules) / sizeof(*deny_rules));
  for (int i = 0; i < 4; i++)
    if (sg_gate_add_rule(gate, allow_rules[(idx * 3 + i) % allow_count]) !=
        SG_OK)
      invariant_failure("allow-rule setup failed");
  /* Pool zero deliberately permits both sides of a substitution so the
   * conditional verdict is reachable. */
  if (idx == 0) {
    if (sg_gate_add_rule(gate, "echo *") != SG_OK ||
        sg_gate_add_rule(gate, "whoami") != SG_OK)
      invariant_failure("conditional policy setup failed");
  } else {
    for (int i = 0; i < 2; i++)
      if (sg_gate_add_deny_rule(gate, deny_rules[(idx * 2 + i) % deny_count]) !=
          SG_OK)
        invariant_failure("deny-rule setup failed");
  }
  return gate;
}

void cleanup() {
  for (int i = 0; i < kPoolSize; i++) {
    sg_gate_free(g_anomaly_pool[i]);
    sg_gate_free(g_policy_pool[i]);
    g_anomaly_pool[i] = nullptr;
    g_policy_pool[i] = nullptr;
  }
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;

  for (int i = 0; i < kPoolSize; i++)
    g_anomaly_pool[i] = create_pool_gate(i);
  for (int i = 0; i < kPoolSize; i++)
    g_policy_pool[i] = create_policy_gate(i);

  atexit(cleanup);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static bool semantic_oracles_checked = false;
  if (!semantic_oracles_checked) {
    run_semantic_reference_oracles();
    semantic_oracles_checked = true;
  }
  if (size == 0)
    return 0;

  FuzzedDataProvider fdp(data, size);
  if (fdp.ConsumeBool()) {
    run_stateful(fdp);
    return 0;
  }
  bool anomaly_mode = fdp.ConsumeBool();
  int pool_idx = fdp.ConsumeIntegral<uint8_t>() & (kPoolSize - 1);

  if (fdp.remaining_bytes() < 2)
    return 0;
  uint16_t raw = fdp.ConsumeIntegral<uint16_t>();
  size_t buf_size = 16 + (size_t)((uint32_t)raw * 16368u / 65535u);

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

  sg_gate_t *g =
      anomaly_mode ? g_anomaly_pool[pool_idx] : g_policy_pool[pool_idx];
  sg_result_t result, replay;

  sg_error_t err =
      sg_eval(g, cmd.data(), cmd.size(), result_buf.data(), buf_size, &result);
  /* Arbitrary bytes routinely form malformed shell syntax. Parse errors are
   * expected outcomes of the public evaluator, not harness failures. */
  if (err != SG_OK && err != SG_ERR_PARSE && err != SG_ERR_TRUNC &&
      err != SG_ERR_MEMORY)
    invariant_failure("unexpected sg_eval error");
  if (err == SG_ERR_MEMORY)
    return 0;

  if (!isfinite(result.anomaly_score) || !isfinite(result.anomaly_score_raw) ||
      !isfinite(result.anomaly_score_type))
    invariant_failure("non-finite anomaly score with a trained model");

  validate_result(&result, err, result_buf.data(), buf_size);

  sg_error_t replay_err =
      sg_eval(g, cmd.data(), cmd.size(), replay_buf.data(), buf_size, &replay);
  if (replay_err != err || !results_equal(result, replay))
    invariant_failure("frozen-model replay was not deterministic");
  validate_result(&replay, replay_err, replay_buf.data(), buf_size);

  if (err == SG_OK) {
    size_t hint = sg_eval_size_hint(cmd.size());
    size_t large_size = hint == SIZE_MAX ? 65536 : hint + SG_BUF_MIN;
    if (large_size > 65536)
      large_size = 65536;
    if (large_size < buf_size)
      large_size = buf_size;
    std::vector<char> large_buf(large_size);
    sg_result_t large = {};
    sg_error_t large_err = sg_eval(g, cmd.data(), cmd.size(), large_buf.data(),
                                   large_buf.size(), &large);
    validate_result(&large, large_err, large_buf.data(), large_buf.size());
    if (large_err != SG_OK || !results_equal(result, large)) {
      std::fprintf(
          stderr,
          "buffer mismatch: small=%zu large=%zu errors=%d/%d "
          "verdicts=%d/%d subcmds=%u/%u violations=%u/%u "
          "suggestions=%u/%u deny-suggestions=%u/%u\n",
          buf_size, large_size, static_cast<int>(err),
          static_cast<int>(large_err), static_cast<int>(result.verdict),
          static_cast<int>(large.verdict), result.subcmd_count,
          large.subcmd_count, result.violation_count, large.violation_count,
          result.suggestion_count, large.suggestion_count,
          result.deny_suggestion_count, large.deny_suggestion_count);
      invariant_failure("successful result changed with a larger buffer");
    }
  }

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
