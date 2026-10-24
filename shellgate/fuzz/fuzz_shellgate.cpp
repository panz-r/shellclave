/*
 * fuzz_shellgate - Fuzzing harness for shellgate with anomaly detection
 *
 * Exercises sg_gate_evaluate with anomaly detection enabled (raw + type
 * models), trained-model scoring, cache hits, deny-rule evaluation, and
 * variably- sized output buffers that exercise the truncation paths.
 *
 * Build with libFuzzer:
 *   cmake -S ../.. -B ../../build-fuzz -DSHELLCLAVE_BUILD_FUZZERS=ON \
 *     -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
 *   cmake --build ../../build-fuzz --target fuzz_shellgate
 *
 * Run a bounded session (successful discoveries are disposable):
 *   ./shellgate/fuzz/run_fuzzing_4h.sh 1 300
 */

#include "../../shellsplit/tests/word_expansion_cases.h"
#include "brace_fuzz_case.h"

#include <fuzzer/FuzzedDataProvider.h>

extern "C" {
#include "../tests/test_eval_buffer.h"
#include "../tests/test_policy_fixture.h"
#include "shell_depgraph.h"
#include "shell_netstring.h"
#include "shell_tokenizer.h"
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

/* Shellgate's public evaluation buffer owns the bounded depgraph workspace as
 * well as result strings. Fuzz inputs vary only the result-prefix budget; the
 * same caller-owned allocation always retains enough aligned route storage. */
size_t eval_buffer_size(size_t command_length, size_t minimum_prefix = 0) {
  size_t hint = sg_gate_evaluate_size_hint(command_length);
  if (hint == SIZE_MAX)
    return 0;
  size_t workspace = sg_test_eval_workspace_size(command_length);
  size_t alignment = shell_dep_workspace_alignment();
  if (workspace == 0 || minimum_prefix > SIZE_MAX - workspace ||
      minimum_prefix + workspace > SIZE_MAX - (alignment - 1))
    return 0;
  size_t minimum = minimum_prefix + workspace + alignment - 1;
  return hint > minimum ? hint : minimum;
}

/* The hot fuzzer path evaluates, replays, and sometimes enlarges the same
 * command. Reuse its caller-owned workspaces instead of feeding multi-megabyte
 * allocations into ASan's quarantine on every input. */
struct reusable_eval_buffer {
  std::vector<char> storage;

  bool reset_for(size_t command_length, size_t minimum_prefix = 0) {
    size_t size = eval_buffer_size(command_length, minimum_prefix);
    if (size == 0)
      return false;
    reset(size);
    return true;
  }

  char *reset(size_t size) {
    storage.resize(size);
    /* sg_gate_evaluate overwrites every published byte. Clearing a bounded
     * multi-megabyte depgraph workspace here would turn every fuzz input into
     * an unnecessary memory sweep. */
    return storage.data();
  }

  char *data() { return storage.data(); }
  size_t size() const { return storage.size(); }
};

struct eval_buffer_set {
  reusable_eval_buffer result;
  reusable_eval_buffer replay;
  reusable_eval_buffer large;
};

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
sg_gate_t *g_expansion_gate;
eval_buffer_set g_eval_buffers;

void invariant_failure(const char *message) {
  fprintf(stderr, "shellgate fuzz invariant failed: %s\n", message);
  abort();
}

reusable_eval_buffer &eval_buffer_for(reusable_eval_buffer &buffer,
                                      size_t command_length,
                                      size_t minimum_prefix = 0) {
  if (!buffer.reset_for(command_length, minimum_prefix))
    invariant_failure("evaluation buffer size overflow");
  return buffer;
}

int valid_buffer_string(const char *value, const char *buffer, size_t size) {
  if (!value)
    return 1;
  uintptr_t address = (uintptr_t)value;
  uintptr_t begin = (uintptr_t)buffer;
  if (address < begin)
    return 0;
  uintptr_t offset = address - begin;
  if (offset >= size)
    return 0;
  return memchr(value, '\0', size - (size_t)offset) != NULL;
}

int valid_buffer_span(const char *value, size_t length, const char *buffer,
                      size_t size) {
  if (!value)
    return length == 0;
  uintptr_t address = (uintptr_t)value;
  uintptr_t begin = (uintptr_t)buffer;
  if (address < begin)
    return 0;
  uintptr_t offset = address - begin;
  if (offset > size)
    return 0;
  return length <= size - (size_t)offset;
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
      result->subcommand_count > SG_MAX_SUBCOMMAND_RESULTS ||
      result->violation_count > SG_MAX_VIOLATIONS ||
      result->suggestion_count > 2 || result->deny_suggestion_count > 2 ||
      (result->unresolved_expansion_flags &
       ~(SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH)) != 0 ||
      (error == SG_ERR_TRUNC && !result->truncated) ||
      (result->truncated && result->verdict != SG_VERDICT_UNDETERMINED) ||
      (error == SG_ERR_TRUNC &&
       (result->verdict == SG_VERDICT_ALLOW ||
        result->verdict == SG_VERDICT_ALLOW_CONDITIONAL)) ||
      result->has_violations != (result->violation_count != 0) ||
      !valid_buffer_string(result->deny_reason, buffer, buffer_size)) {
    invariant_failure("result field outside its documented bounds");
  }

  for (uint32_t i = 0; i < result->subcommand_count; i++) {
    const sg_subcommand_result_t *subcommand = &result->subcommands[i];
    if ((subcommand->unresolved_expansion_flags &
         ~result->unresolved_expansion_flags) != 0)
      invariant_failure("subcommand unresolved flags lack aggregate flags");
    if (!valid_buffer_string(subcommand->display_command, buffer,
                             buffer_size) ||
        !valid_buffer_string(subcommand->reject_reason, buffer, buffer_size) ||
        !valid_buffer_span(subcommand->netargv, subcommand->netargv_length,
                           buffer, buffer_size) ||
        (subcommand->netargv != nullptr &&
         shell_netstring_validate(subcommand->netargv,
                                  subcommand->netargv_length,
                                  nullptr) != SHELL_NETSTRING_OK) ||
        !valid_verdict(subcommand->verdict))
      invariant_failure("subcommand string outside the output buffer");
    if (subcommand->requires_substitution_evaluation &&
        !result->requires_substitution_evaluation)
      invariant_failure("subcommand dynamic-content flag lacks top-level flag");
    if (subcommand->has_dynamic_substitution_io &&
        !result->has_dynamic_substitution_io)
      invariant_failure("subcommand dynamic-I/O flag lacks top-level flag");
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
      !result->requires_substitution_evaluation)
    invariant_failure("conditional allowance lacks a substitution dependency");
  /* A conditional result can describe a dynamic route outside the evaluated
   * prefix: short-circuiting need not publish the consumer as a result row. */
  if (result->short_circuited && result->subcommand_count == 0)
    invariant_failure("short-circuit result has no evaluated prefix");
}

void validate_known_graph_result_prefix(const sg_result_t *result,
                                        sg_error_t error, const char *buffer,
                                        size_t buffer_size,
                                        size_t command_length) {
  size_t prefix_size =
      sg_test_eval_prefix_size(buffer, buffer_size, command_length);
  if (prefix_size == 0)
    invariant_failure("graph result had no public output prefix");
  validate_result(result, error, buffer, prefix_size);
}

void validate_graph_result_prefix(const sg_result_t *result, sg_error_t error,
                                  const char *buffer, size_t buffer_size,
                                  size_t command_length) {
  if (error != SG_OK || result->verdict == SG_VERDICT_REJECT)
    return;
  validate_known_graph_result_prefix(result, error, buffer, buffer_size,
                                     command_length);
}

bool results_equal(const sg_result_t &left, const sg_result_t &right) {
  if (left.verdict != right.verdict ||
      !equal_string(left.deny_reason, right.deny_reason) ||
      left.subcommand_count != right.subcommand_count ||
      left.suggestion_count != right.suggestion_count ||
      left.deny_suggestion_count != right.deny_suggestion_count ||
      left.attention_index != right.attention_index ||
      left.truncated != right.truncated ||
      left.subcommand_truncated != right.subcommand_truncated ||
      left.violation_truncated != right.violation_truncated ||
      left.short_circuited != right.short_circuited ||
      left.violation_count != right.violation_count ||
      left.violation_category_flags != right.violation_category_flags ||
      left.violation_type_flags != right.violation_type_flags ||
      left.requires_substitution_evaluation !=
          right.requires_substitution_evaluation ||
      left.has_dynamic_substitution_io != right.has_dynamic_substitution_io ||
      left.unresolved_expansion_flags != right.unresolved_expansion_flags ||
      left.violation_dropped_count != right.violation_dropped_count ||
      left.has_violations != right.has_violations ||
      left.anomaly_detected != right.anomaly_detected ||
      left.anomaly_score != right.anomaly_score ||
      left.anomaly_score_raw != right.anomaly_score_raw ||
      left.anomaly_score_type != right.anomaly_score_type)
    return false;

  for (uint32_t i = 0; i < left.subcommand_count; i++) {
    const sg_subcommand_result_t &a = left.subcommands[i];
    const sg_subcommand_result_t &b = right.subcommands[i];
    if (a.matches != b.matches || a.verdict != b.verdict ||
        !equal_string(a.display_command, b.display_command) ||
        !equal_string(a.reject_reason, b.reject_reason) ||
        a.netargv_length != b.netargv_length ||
        (a.netargv_length != 0 &&
         memcmp(a.netargv, b.netargv, a.netargv_length) != 0) ||
        a.write_count != b.write_count || a.read_count != b.read_count ||
        a.env_count != b.env_count ||
        a.requires_substitution_evaluation !=
            b.requires_substitution_evaluation ||
        a.has_dynamic_substitution_io != b.has_dynamic_substitution_io ||
        a.unresolved_expansion_flags != b.unresolved_expansion_flags ||
        a.violation_category_flags != b.violation_category_flags ||
        a.violation_type_flags != b.violation_type_flags)
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
        a.severity != b.severity ||
        a.command_node_index != b.command_node_index ||
        !equal_string(a.description, b.description) ||
        !equal_string(a.detail, b.detail))
      return false;
  }
  return true;
}

/* Callback eligibility is a source-word contract, not a raw punctuation scan.
 */
struct expansion_query_oracle {
  const char *expected;
  size_t calls;
  const char *records = "3:hit,";
  bool unresolved = false;
  bool check_cwd = false;
  const char *cwd = nullptr;
  bool cwd_absolute = false;
};

shell_expand_status_t
oracle_expand_word(const shell_expand_word_request_t *request,
                   const char **netargv, size_t *netargv_length,
                   void *userdata) {
  auto *state = static_cast<expansion_query_oracle *>(userdata);
  const char *query = request->source + request->word_offset;
  size_t length = request->word_length;
  state->calls++;
  if (!state->expected || strlen(state->expected) != length ||
      memcmp(state->expected, query, length) != 0)
    invariant_failure("unexpected source-word expansion query");
  if (state->check_cwd &&
      (request->cwd_known != (state->cwd != nullptr) ||
       (state->cwd && (request->cwd_absolute != state->cwd_absolute ||
                       strcmp(request->cwd, state->cwd) != 0))))
    invariant_failure("tilde CWD expansion query mismatch");
  if (state->unresolved)
    return SHELL_EXPAND_UNRESOLVED;
  *netargv = state->records;
  *netargv_length = strlen(state->records);
  return SHELL_EXPAND_RESOLVED;
}

shell_expand_status_t
oracle_empty_file_path(const shell_expand_word_request_t *request,
                       const char **netargv, size_t *length, void *) {
  if (request->purpose != SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH)
    return SHELL_EXPAND_UNRESOLVED;
  *netargv = "0:,";
  *length = 3;
  return SHELL_EXPAND_RESOLVED;
}

void run_expansion_query_oracles() {
  sg_gate_t *gate = sg_gate_new();
  expansion_query_oracle state = {};
  if (!gate ||
      sg_gate_set_expand_word_netargv(gate, oracle_expand_word, &state) !=
          SG_OK ||
      sg_gate_set_reject_mask(gate, 0) != SG_OK ||
      sg_gate_set_suggestions(gate, false) != SG_OK)
    invariant_failure("expansion oracle setup failed");
  reusable_eval_buffer buffer;
  auto check = [&](const char *word, const char *expected,
                   bool unsupported = false, bool unresolved = false) {
    std::string source = std::string("echo ") + word;
    state = {expected, 0};
    state.unresolved = unresolved;
    if (!buffer.reset_for(source.size()))
      invariant_failure("expansion oracle buffer allocation failed");
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(gate, source.data(), source.size(),
                                        buffer.data(), buffer.size(), &result);
    if (error != (unsupported ? SG_ERR_PARSE : SG_OK) ||
        (unsupported && result.verdict != SG_VERDICT_REJECT) ||
        state.calls != static_cast<size_t>(expected != nullptr)) {
      fprintf(stderr,
              "expansion oracle word=%s unsupported=%d expected=%s "
              "error=%d verdict=%d calls=%zu\n",
              word, unsupported, expected ? expected : "<none>", error,
              result.verdict, state.calls);
      invariant_failure("source-word expansion callback contract mismatch");
    }
  };
  for (const auto &fixture : shellsplit_test_glob_words) {
    check(fixture.word, fixture.expand ? fixture.word : nullptr);
  }
  for (const auto &fixture : shellsplit_test_tilde_words)
    check(fixture.word, fixture.argument_dynamic ? fixture.word : nullptr,
          false, true);
  for (const auto &fixture : shellsplit_test_parameter_words) {
    check(fixture.word, fixture.expand ? fixture.word : nullptr,
          fixture.unsupported);
  }
  if (sg_gate_set_cwd(gate, "/workspace") != SG_OK)
    invariant_failure("tilde CWD oracle configuration");
  for (const auto &fixture : shellsplit_test_tilde_cwd) {
    if (fixture.other_dynamic)
      continue; /* These retained cd queries are covered by the component suite.
                 */
    state = {"\"$ARG\"", 0};
    state.unresolved = true;
    state.check_cwd = true;
    state.cwd = fixture.cwd;
    state.cwd_absolute = fixture.absolute;
    std::string source =
        std::string("cd ") + fixture.word + " && echo \"$ARG\"";
    if (!buffer.reset_for(source.size()))
      invariant_failure("tilde CWD oracle buffer allocation");
    sg_result_t result = {};
    if (sg_gate_evaluate(gate, source.data(), source.size(), buffer.data(),
                         buffer.size(), &result) != SG_OK ||
        state.calls != 1 ||
        result.unresolved_expansion_flags !=
            (SG_EXPANSION_UNRESOLVED_ARGV |
             (fixture.leading_tilde && strchr(fixture.word, '/')
                  ? SG_EXPANSION_UNRESOLVED_PATH
                  : 0))) {
      fprintf(stderr, "tilde CWD source=%s calls=%zu flags=%u leading=%d\n",
              source.c_str(), state.calls, result.unresolved_expansion_flags,
              fixture.leading_tilde);
      invariant_failure("tilde CWD callback contract");
    }
  }
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  if (sg_gate_set_violation_config_borrowed(gate, &config) != SG_OK ||
      sg_gate_set_stop_mode(gate, SG_EVAL_ALL) != SG_OK)
    invariant_failure("resolved expansion oracle configuration");
  for (const auto &fixture : shellsplit_test_tilde_path_aliases) {
    for (unsigned mode = 0; mode < 3; mode++) {
      state = {fixture.dynamic ? fixture.word : nullptr, 0, fixture.record};
      state.unresolved = mode != 2;
      if (sg_gate_set_expand_word_netargv(
              gate, mode ? oracle_expand_word : nullptr, &state) != SG_OK)
        invariant_failure("tilde identity oracle configuration");
      size_t length = strlen(fixture.source);
      if (!buffer.reset_for(length))
        invariant_failure("tilde identity oracle buffer allocation");
      sg_result_t result = {};
      size_t calls = fixture.dynamic && mode
                         ? (strcmp(fixture.word, "\"$OUT\"") == 0 ? 2u : 1u)
                         : 0;
      bool alias = (!fixture.dynamic || mode == 2) && fixture.resolved_alias;
      if (sg_gate_evaluate(gate, fixture.source, length, buffer.data(),
                           buffer.size(), &result) != SG_OK ||
          state.calls != calls || result.subcommand_count != 2 ||
          result.unresolved_expansion_flags !=
              (fixture.dynamic && mode != 2 ? SG_EXPANSION_UNRESOLVED_PATH
                                            : 0) ||
          !!(result.violation_type_flags & SG_VIOL_WRITE_THEN_READ) != alias)
        invariant_failure("tilde path identity alias contract");
    }
  }
  if (sg_gate_set_expand_word_netargv(gate, oracle_expand_word, &state) !=
      SG_OK)
    invariant_failure("restore expansion oracle callback");
  static const struct {
    const char *command, *word, *records;
    uint32_t violation;
    bool inspection, dynamic;
  } resolved[] = {
      {"curl $OPTION", "$OPTION", "2:-T,", SG_VIOL_NET_UPLOAD, false, false},
      {"base64 $OPTION | sh", "$OPTION", "2:-d,", SG_VIOL_SHELL_OBFUSCATION,
       false, false},
      {"base64 $OPTION | sh", "$OPTION", "4:'-d',", 0, false, false},
      {"cat \"$(printf file)\"", "\"$(printf file)\"", "13:/root/.ssh/id,",
       SG_VIOL_READ_SECRETS, true, true},
      {"echo >\"$(cat /root/.ssh/id)\"", "\"$(cat /root/.ssh/id)\"",
       "8:/tmp/out,", SG_VIOL_SUBST_SENSITIVE, false, true},
      {"true {fd}>\"$(cat /root/.ssh/id)\"", "\"$(cat /root/.ssh/id)\"", "0:,",
       0, false, false},
      {"exec {fd}>\"$FAIL\"", "\"$FAIL\"", "0:,", 0, false, false},
      {"echo >\"$FAIL\" {fd}>/etc/later", "\"$FAIL\"", "0:,", 0, false, false},
      {"{ echo hi; } >\"$FAIL\" {fd}>/etc/later", "\"$FAIL\"", "0:,", 0, false,
       false},
  };
  for (const auto &fixture : resolved) {
    state = {fixture.word, 0, fixture.records};
    size_t length = strlen(fixture.command);
    if (!buffer.reset_for(length))
      invariant_failure("resolved expansion oracle buffer allocation");
    sg_result_t result = {};
    if (sg_gate_evaluate(gate, fixture.command, length, buffer.data(),
                         buffer.size(), &result) != SG_OK ||
        state.calls != 1 || result.subcommand_count == 0 ||
        result.unresolved_expansion_flags != 0 ||
        result.requires_substitution_evaluation != fixture.inspection ||
        result.subcommands[0].has_dynamic_substitution_io != fixture.dynamic)
      invariant_failure("resolved expansion topology or callback contract");
    uint32_t flags = fixture.violation == SG_VIOL_SHELL_OBFUSCATION
                         ? result.violation_type_flags
                         : result.subcommands[0].violation_type_flags;
    if (fixture.violation ? (flags & fixture.violation) == 0 : flags != 0)
      invariant_failure("resolved expansion violation contract");
  }
  static const struct {
    const char *source, *records;
    uint32_t violation;
  } equivalents[] = {
      {"rsync /tmp/x remote$'\\x3a'out", "6:/tmp/x,10:remote:out,",
       SG_VIOL_NET_UPLOAD},
      {"rsync /tmp/x remote\\:out", "6:/tmp/x,10:remote:out,",
       SG_VIOL_NET_UPLOAD},
      {"socat TCP-LI\"ST\"EN:8000 STDIO", "15:TCP-LISTEN:8000,5:STDIO,",
       SG_VIOL_NET_LISTENER},
      {"socat TCP-li\"st\"en:8000 STDIO", "15:TCP-listen:8000,5:STDIO,",
       SG_VIOL_NET_LISTENER},
      {"socat TCP-LiStEn:8000 STDIO", "15:TCP-LiStEn:8000,5:STDIO,", 0},
  };
  for (const auto &fixture : equivalents) {
    sg_gate_set_expand_word_netargv(gate, nullptr, nullptr);
    size_t length = strlen(fixture.source);
    buffer.reset_for(length);
    sg_result_t literal = {};
    if (sg_gate_evaluate(gate, fixture.source, length, buffer.data(),
                         buffer.size(), &literal) != SG_OK ||
        literal.subcommand_count != 1 ||
        literal.violation_type_flags != fixture.violation)
      invariant_failure("static decoded substring oracle");
    std::string argv(literal.subcommands[0].netargv,
                     literal.subcommands[0].netargv_length);
    const char *source = fixture.violation == SG_VIOL_NET_UPLOAD
                             ? "rsync $OPTION"
                             : "socat $OPTION";
    state = {"$OPTION", 0, fixture.records};
    sg_gate_set_expand_word_netargv(gate, oracle_expand_word, &state);
    length = strlen(source);
    buffer.reset_for(length);
    sg_result_t expanded = {};
    if (sg_gate_evaluate(gate, source, length, buffer.data(), buffer.size(),
                         &expanded) != SG_OK ||
        state.calls != 1 || expanded.subcommand_count != 1 ||
        expanded.violation_type_flags != literal.violation_type_flags ||
        expanded.verdict != literal.verdict ||
        argv.size() != expanded.subcommands[0].netargv_length ||
        memcmp(argv.data(), expanded.subcommands[0].netargv, argv.size()) != 0)
      invariant_failure("canonical argv substring equivalence");
  }
  static const struct {
    const char *source;
    bool expand;
  } printf_cases[] = {
      {"printf '%b%n' \"$V\" fd", false},
      {"command printf '%b%n' \"$V\" fd", false},
      {"{ printf '%b%n' \"$V\" fd; }", false},
      {"printf '%n%b' other \"$V\" fd \"$V\"", false},
      {"printf '%s%n' \"$V\" fd", true},
      {"printf '%b' \"$V\"", true},
  };
  for (const auto &fixture : printf_cases) {
    state = {fixture.expand ? "\"$V\"" : nullptr, 0, "2:\\c,"};
    size_t length = strlen(fixture.source);
    if (!buffer.reset_for(length))
      invariant_failure("printf expansion oracle buffer allocation failed");
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(gate, fixture.source, length,
                                        buffer.data(), buffer.size(), &result);
    uint32_t flags = fixture.expand ? 0 : SG_EXPANSION_UNRESOLVED_ARGV;
    if (error != SG_OK || state.calls != fixture.expand ||
        result.subcommand_count != 1 ||
        result.unresolved_expansion_flags != flags ||
        result.subcommands[0].unresolved_expansion_flags != flags)
      invariant_failure("printf state-controlling operand was expanded");
    validate_known_graph_result_prefix(&result, error, buffer.data(),
                                       buffer.size(), length);
  }
  sg_gate_set_expand_word_netargv(gate, nullptr, nullptr);
  static const struct {
    const char *source;
    uint32_t flags;
  } unresolved[] = {
      {"echo \"$DATA\"", SG_EXPANSION_UNRESOLVED_ARGV},
      {"echo >\"$OUT\"", SG_EXPANSION_UNRESOLVED_PATH},
      {"{ echo \"$DATA\"; } >\"$OUT\"",
       SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH},
  };
  for (const auto &fixture : unresolved) {
    size_t length = strlen(fixture.source);
    if (!buffer.reset_for(length))
      invariant_failure("unresolved oracle buffer allocation failed");
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(gate, fixture.source, length,
                                        buffer.data(), buffer.size(), &result);
    if (error != SG_OK || result.subcommand_count != 1 ||
        result.unresolved_expansion_flags != fixture.flags ||
        result.subcommands[0].unresolved_expansion_flags != fixture.flags)
      invariant_failure("unresolved expansion flags mismatch");
    validate_known_graph_result_prefix(&result, error, buffer.data(),
                                       buffer.size(), length);
    sg_result_t changed = result;
    changed.unresolved_expansion_flags ^= SG_EXPANSION_UNRESOLVED_ARGV;
    if (results_equal(result, changed))
      invariant_failure("replay ignored aggregate unresolved expansion flags");
    changed = result;
    changed.subcommands[0].unresolved_expansion_flags ^=
        SG_EXPANSION_UNRESOLVED_PATH;
    if (results_equal(result, changed))
      invariant_failure("replay ignored command unresolved expansion flags");
  }
  if (test_policy_replace_cpl(gate, false, "echo ok", false) != ST_OK ||
      test_policy_replace_cpl(gate, true, "echo denied", false) != ST_OK)
    invariant_failure("early-stop expansion oracle policy setup");
  static const struct {
    sg_stop_mode_t mode;
    const char *first;
  } stops[] = {{SG_STOP_FIRST_FAIL, "echo missing"},
               {SG_STOP_FIRST_PASS, "echo ok"},
               {SG_STOP_FIRST_ALLOW, "echo ok"},
               {SG_STOP_FIRST_DENY, "echo denied"}};
  for (const auto &stop : stops) {
    for (const auto &fixture : unresolved) {
      std::string source = std::string(stop.first) + "; " + fixture.source;
      buffer.reset_for(source.size());
      sg_gate_set_stop_mode(gate, SG_EVAL_ALL);
      sg_result_t full = {};
      sg_error_t error = sg_gate_evaluate(gate, source.data(), source.size(),
                                          buffer.data(), buffer.size(), &full);
      if (error != SG_OK || full.subcommand_count != 2 ||
          full.unresolved_expansion_flags != fixture.flags ||
          full.subcommands[0].unresolved_expansion_flags != 0 ||
          full.subcommands[1].unresolved_expansion_flags != fixture.flags)
        invariant_failure("full-graph expansion flags mismatch");
      sg_gate_set_stop_mode(gate, stop.mode);
      sg_result_t result = {};
      error = sg_gate_evaluate(gate, source.data(), source.size(),
                               buffer.data(), buffer.size(), &result);
      if (error != SG_OK || !result.short_circuited ||
          result.subcommand_count != 1 ||
          result.subcommands[0].unresolved_expansion_flags != 0 ||
          result.unresolved_expansion_flags != full.unresolved_expansion_flags)
        invariant_failure("early-stop omitted graph expansion uncertainty");
      validate_known_graph_result_prefix(&result, error, buffer.data(),
                                         buffer.size(), source.size());
    }
  }
  sg_gate_set_stop_mode(gate, SG_EVAL_ALL);
  const uint32_t both =
      SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH;
  for (const char *source : {"echo ok; echo \"$DATA\" >\"$OUT\"",
                             "echo >/etc/private; echo \"$DATA\" >\"$OUT\""}) {
    size_t length = strlen(source);
    buffer.reset(sg_test_eval_workspace_size(length) +
                 shell_dep_workspace_alignment());
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(gate, source, length, buffer.data(),
                                        buffer.size(), &result);
    if (error != SG_ERR_TRUNC || !result.truncated ||
        result.verdict != SG_VERDICT_UNDETERMINED ||
        result.unresolved_expansion_flags != both)
      invariant_failure("truncation omitted graph expansion uncertainty");
    validate_known_graph_result_prefix(&result, error, buffer.data(),
                                       buffer.size(), length);
  }
  sg_gate_free(gate);
}

/* Immutable, bounded application results are generated before evaluation.
 * Source offsets identify physical words; repeated callbacks within one
 * evaluation are a defect, not a reason to mutate or recycle payload storage.
 */
struct generated_expansion_fixture {
  std::string source;
  std::string records[3];
  unsigned modes[3] = {};
  size_t calls[3] = {};
  std::vector<uint8_t> seen;
  bool error_seen = false;
  bool unresolved_leaf = false;
};

shell_expand_status_t
generated_expand_word(const shell_expand_word_request_t *request,
                      const char **netargv, size_t *length, void *context) {
  auto &fixture = *static_cast<generated_expansion_fixture *>(context);
  if (request->source != fixture.source.data() ||
      request->source_length != fixture.source.size() ||
      request->word_offset >= fixture.source.size() ||
      request->word_length > fixture.source.size() - request->word_offset ||
      request->owner_offset > fixture.source.size() ||
      request->owner_length > fixture.source.size() - request->owner_offset ||
      request->purpose > SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH ||
      fixture.seen[request->word_offset]++)
    invariant_failure("generated expansion request or call count mismatch");
  unsigned purpose = request->purpose;
  fixture.calls[purpose]++;
  if (purpose == SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH &&
      fixture.unresolved_leaf && request->word_length == 7 &&
      memcmp(request->source + request->word_offset, "\"$FILE\"", 7) == 0)
    return SHELL_EXPAND_UNRESOLVED;
  unsigned mode = fixture.modes[purpose];
  if (mode == 1)
    return SHELL_EXPAND_UNRESOLVED;
  if (mode == 2) {
    fixture.error_seen = true;
    return SHELL_EXPAND_FAILED;
  }
  fixture.error_seen |= mode == 3 || (mode == 7 && purpose != 0);
  *netargv = fixture.records[purpose].data();
  *length = fixture.records[purpose].size();
  return SHELL_EXPAND_RESOLVED;
}

void append_generated_record(std::string &records, const std::string &payload) {
  char record[136];
  size_t written;
  if (shell_netstring_write(record, sizeof(record), payload.data(),
                            payload.size(), &written) != SHELL_NETSTRING_OK)
    invariant_failure("bounded expansion record encoding failed");
  records.append(record, written);
}

void run_generated_expansion_case(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  generated_expansion_fixture fixture;
  unsigned shape = fdp.ConsumeIntegralInRange<unsigned>(0, 6);
  unsigned depth = fdp.ConsumeIntegralInRange<unsigned>(1, 4);
  for (unsigned purpose = 0; purpose < 3; purpose++)
    fixture.modes[purpose] = fdp.ConsumeIntegralInRange<unsigned>(0, 7);
  fixture.unresolved_leaf = fdp.ConsumeBool();
  for (unsigned purpose = 0; purpose < 3; purpose++) {
    unsigned mode = fixture.modes[purpose];
    auto &records = fixture.records[purpose];
    switch (mode) {
    case 0: {
      unsigned count =
          purpose == 0 ? fdp.ConsumeIntegralInRange<unsigned>(1, 4) : 1;
      for (unsigned i = 0; i < count; i++) {
        std::string payload = fdp.ConsumeRandomLengthString(128);
        if (purpose != 0) {
          std::replace(payload.begin(), payload.end(), '\0', 'x');
          payload.insert(0, "/tmp/");
          payload.resize(std::min(payload.size(), size_t(128)));
        }
        append_generated_record(records, payload);
      }
      break;
    }
    case 3: {
      static const char *malformed[] = {"01:a,", "1:a;", "2:a,",
                                        "999999999999999999999999999999:x,",
                                        "1:a,garbage"};
      records = malformed[fdp.ConsumeIntegralInRange<unsigned>(0, 4)];
      break;
    }
    case 5:
      append_generated_record(records, "");
      break;
    case 6:
      append_generated_record(records, "one two");
      append_generated_record(records, "three");
      break;
    case 7:
      append_generated_record(records, std::string("a\0b", 3));
      break;
    default:
      break; /* Unresolved, failed, or a canonical zero-record result. */
    }
  }
  std::string file_word = "\"$FILE\"";
  for (unsigned i = 0; i < depth; i++)
    file_word = "\"$(<" + file_word + ")\"";
  switch (shape) {
  case 0:
    fixture.source = "echo \"$ARG\"";
    break;
  case 1:
    fixture.source = "echo >" + file_word;
    break;
  case 2:
    fixture.source = "{ echo one; echo two; } >" + file_word;
    break;
  case 3:
    fixture.source = "echo \"$(echo >" + file_word + ")\"";
    break;
  case 4:
    fixture.source = "echo > >(echo >" + file_word + ") >out";
    break;
  case 5:
    fixture.source = "exec {fd}>\"$OUT\"; echo >&\"$fd\"";
    break;
  default:
    fixture.source = "echo ok; echo \"$ARG\" >\"$OUT\"";
    break;
  }
  fixture.seen.resize(fixture.source.size());
  /* A failed named open leaves `$fd` unbound. Its later numeric redirection
   * is unsupported dynamic-FD syntax, rather than a successful alias use. */
  bool unsupported_fd =
      shape == 5 && fixture.modes[1] >= 4 && fixture.modes[1] <= 6;
  if (sg_gate_set_expand_word_netargv(g_expansion_gate, generated_expand_word,
                                      &fixture) != SG_OK ||
      sg_gate_set_stop_mode(g_expansion_gate, SG_EVAL_ALL) != SG_OK)
    invariant_failure("generated expansion gate configuration failed");

  auto evaluate = [&](reusable_eval_buffer &buffer, sg_result_t &result) {
    std::fill(fixture.seen.begin(), fixture.seen.end(), 0);
    std::fill(std::begin(fixture.calls), std::end(fixture.calls), 0);
    fixture.error_seen = false;
    sg_error_t error = sg_gate_evaluate(g_expansion_gate, fixture.source.data(),
                                        fixture.source.size(), buffer.data(),
                                        buffer.size(), &result);
    if (error != SG_OK && error != SG_ERR_TRUNC && error != SG_ERR_EXPAND &&
        !(unsupported_fd && error == SG_ERR_PARSE)) {
      fprintf(stderr,
              "generated expansion shape=%u modes=%u/%u/%u error=%d "
              "source=%s reason=%s\n",
              shape, fixture.modes[0], fixture.modes[1], fixture.modes[2],
              error, fixture.source.c_str(),
              result.deny_reason ? result.deny_reason : "<none>");
      invariant_failure("unexpected generated expansion evaluation error");
    }
    if (fixture.error_seen && error != SG_ERR_EXPAND)
      invariant_failure("diagnostic truncation hid the callback failure");
    if ((error == SG_ERR_EXPAND || fixture.error_seen) &&
        result.verdict != SG_VERDICT_UNDETERMINED)
      invariant_failure("callback error did not fail closed");
    if (error == SG_ERR_PARSE && result.verdict != SG_VERDICT_REJECT)
      invariant_failure("unbound descriptor did not fail closed");
    validate_result(&result, error, buffer.data(), buffer.size());
    validate_graph_result_prefix(&result, error, buffer.data(), buffer.size(),
                                 fixture.source.size());
    return error;
  };
  auto &small_buffer = g_eval_buffers.result;
  auto &replay_buffer = g_eval_buffers.replay;
  size_t prefix = fdp.ConsumeIntegralInRange<size_t>(1, 128);
  size_t small_size = sg_test_eval_workspace_size(fixture.source.size()) +
                      shell_dep_workspace_alignment() + prefix;
  small_buffer.reset(small_size);
  replay_buffer.reset(small_size);
  sg_result_t small = {}, replay = {};
  sg_error_t small_error = evaluate(small_buffer, small);
  size_t calls[3];
  std::copy(std::begin(fixture.calls), std::end(fixture.calls), calls);
  sg_error_t replay_error = evaluate(replay_buffer, replay);
  if (replay_error != small_error || !results_equal(small, replay) ||
      !std::equal(std::begin(calls), std::end(calls), fixture.calls))
    invariant_failure("generated callback replay differed");

  auto &large_buffer = eval_buffer_for(
      g_eval_buffers.large, fixture.source.size(), SG_DIAGNOSTIC_BUF_MIN);
  sg_result_t full = {};
  sg_error_t full_error = evaluate(large_buffer, full);
  if (fixture.error_seen) {
    if (full_error != SG_ERR_EXPAND)
      invariant_failure("invalid callback data was not rejected");
  } else if (unsupported_fd) {
    if (full_error != SG_ERR_PARSE || fixture.calls[1] != 1)
      invariant_failure("failed named open did not reject unbound alias");
  } else {
    static const unsigned purposes[] = {1, 6, 6, 7, 6, 2, 3};
    uint32_t expected_flags = 0;
    for (unsigned purpose = 0; purpose < 3; purpose++) {
      size_t expected_calls = (purposes[shape] >> purpose) & 1u;
      if (purpose == 2)
        expected_calls *= depth;
      if (fixture.calls[purpose] != expected_calls)
        invariant_failure("generated expansion queries were omitted");
      if (expected_calls && fixture.modes[purpose] == 1)
        expected_flags |= purpose == 0 ? SG_EXPANSION_UNRESOLVED_ARGV
                                       : SG_EXPANSION_UNRESOLVED_PATH;
    }
    if ((purposes[shape] & 4) && fixture.unresolved_leaf)
      expected_flags |= SG_EXPANSION_UNRESOLVED_PATH;
    if (full_error != SG_OK ||
        full.unresolved_expansion_flags != expected_flags)
      invariant_failure("generated expansion uncertainty mismatch");
    if (small.unresolved_expansion_flags != full.unresolved_expansion_flags ||
        !std::equal(std::begin(calls), std::end(calls), fixture.calls))
      invariant_failure("result truncation changed expansion accounting");
    if (shape == 0) {
      std::string expected = "4:echo,";
      if (fixture.modes[0] == 1)
        append_generated_record(expected, "$ARG");
      else
        expected += fixture.records[0];
      if (full.subcommand_count != 1 ||
          full.subcommands[0].netargv_length != expected.size() ||
          memcmp(full.subcommands[0].netargv, expected.data(), expected.size()))
        invariant_failure("generated binary argv differed from callback data");
    }
    if (shape == 6) {
      sg_gate_set_stop_mode(g_expansion_gate, SG_STOP_FIRST_ALLOW);
      sg_result_t stopped = {};
      if (evaluate(large_buffer, stopped) != SG_OK ||
          !stopped.short_circuited || stopped.subcommand_count != 1 ||
          stopped.unresolved_expansion_flags != expected_flags)
        invariant_failure("callback uncertainty changed after early stop");
    }
  }
  /* Fixture payloads must outlive every callback and result copy. Never leave
   * their borrowed context installed on a reusable gate after returning. */
  sg_gate_set_expand_word_netargv(g_expansion_gate, nullptr, nullptr);
}

/* A buffer can be too small both for the mandatory depgraph workspace and for
 * its explanatory diagnostic. SG_ERR_MEMORY remains the primary failure;
 * truncation describes the independently incomplete diagnostic result. Keep
 * this mixed-status contract in the deterministic oracle path because normal
 * fuzz buffers always reserve the workspace tail. */
void run_evaluation_buffer_contract_oracle() {
  sg_gate_t *gate = sg_gate_new();
  if (!gate)
    invariant_failure("buffer contract gate setup failed");
  char tiny_buffer[1];
  sg_result_t result = {};
  sg_error_t error = sg_gate_evaluate(gate, "ls", 2, tiny_buffer,
                                      sizeof(tiny_buffer), &result);
  if (error != SG_ERR_MEMORY || !result.truncated ||
      result.verdict != SG_VERDICT_UNDETERMINED)
    invariant_failure("workspace and diagnostic failure contract mismatch");
  validate_result(&result, error, tiny_buffer, sizeof(tiny_buffer));
  reusable_eval_buffer buffer;
  for (size_t length : {size_t(11), size_t(64), size_t(4096)}) {
    size_t alignment = shell_dep_workspace_alignment();
    size_t size = eval_buffer_size(length);
    buffer.reset(size + alignment);
    for (size_t offset = 0; offset < alignment; offset++) {
      char *base = buffer.data() + offset;
      size_t prefix = sg_test_eval_prefix_size(base, size, length);
      if (prefix == 0 || prefix >= size)
        invariant_failure("buffer prefix calculation failed");
      base[prefix - 1] = base[prefix] = 0;
      if (!valid_buffer_string(base + prefix - 1, base, prefix) ||
          valid_buffer_string(base + prefix, base, prefix) ||
          !valid_buffer_span(base + prefix - 1, 1, base, prefix) ||
          valid_buffer_span(base + prefix, 1, base, prefix))
        invariant_failure("private evaluation cache accepted as public output");
    }
  }
  const char source[] = "echo $VALUE";
  size_t length = sizeof(source) - 1;
  size_t workspace = sg_test_eval_workspace_size(length);
  size_t alignment = shell_dep_workspace_alignment();
  buffer.reset(workspace + 128 + 2 * alignment);
  sg_gate_set_reject_mask(gate, 0);
  sg_gate_set_suggestions(gate, false);
  for (size_t offset = 0; offset < alignment; offset++) {
    char *base = buffer.data() + offset;
    const size_t capacities[] = {workspace - 1, workspace,
                                 workspace + alignment,
                                 workspace + 128 + alignment - 1};
    const sg_error_t errors[] = {SG_ERR_MEMORY, SG_ERR_MEMORY, SG_ERR_TRUNC,
                                 SG_OK};
    for (size_t boundary = 0; boundary < 4; boundary++) {
      size_t size = capacities[boundary];
      result = {};
      error = sg_gate_evaluate(gate, source, length, base, size, &result);
      if (error != errors[boundary] ||
          result.verdict != SG_VERDICT_UNDETERMINED ||
          result.truncated != (boundary == 2) ||
          result.unresolved_expansion_flags !=
              (boundary < 2 ? 0u : SG_EXPANSION_UNRESOLVED_ARGV))
        invariant_failure("complete evaluation workspace boundary mismatch");
      if (boundary < 2) {
        if (sg_test_eval_prefix_size(base, size, length) != 0 ||
            !equal_string(result.deny_reason, "depgraph workspace unavailable"))
          invariant_failure("workspace failure diagnostic mismatch");
        validate_result(&result, error, base, size);
      } else {
        validate_known_graph_result_prefix(&result, error, base, size, length);
      }
    }
  }
  /* Require the same primary callback error with exact diagnostic capacities,
   * independently of how mutation happens to select the generated prefix. */
  generated_expansion_fixture failure;
  failure.source = "echo \"$ARG\"";
  failure.seen.resize(failure.source.size());
  failure.records[0] = "01:a,";
  length = failure.source.size();
  workspace = sg_test_eval_workspace_size(length);
  buffer.reset(workspace + 512 + alignment - 1);
  if (sg_gate_set_expand_word_netargv(gate, generated_expand_word, &failure) !=
      SG_OK)
    invariant_failure("callback error oracle configuration failed");
  for (unsigned mode : {2u, 3u}) {
    failure.modes[0] = mode;
    for (size_t prefix :
         {size_t(1), size_t(8), size_t(21), size_t(22), size_t(512)}) {
      char *base = sg_test_eval_buffer_for_prefix(buffer.data(), prefix);
      size_t size = workspace + prefix;
      if (sg_test_eval_prefix_size(base, size, length) != prefix)
        invariant_failure("callback oracle diagnostic capacity mismatch");
      std::fill(failure.seen.begin(), failure.seen.end(), 0);
      std::fill(std::begin(failure.calls), std::end(failure.calls), 0);
      failure.error_seen = false;
      result = {};
      error = sg_gate_evaluate(gate, failure.source.data(), length, base, size,
                               &result);
      if (error != SG_ERR_EXPAND || !failure.error_seen ||
          failure.calls[0] != 1 || result.verdict != SG_VERDICT_UNDETERMINED ||
          result.truncated != (prefix < sizeof("word expansion failed")))
        invariant_failure("callback and diagnostic failure contract mismatch");
      validate_known_graph_result_prefix(&result, error, base, size, length);
    }
  }
  sg_gate_set_expand_word_netargv(gate, nullptr, nullptr);
  sg_gate_free(gate);
}

/* A compact, parser-independent semantic reference set. These cases describe
 * the supported shell dialect rather than duplicating the production parser:
 * each executable substitution must become one command node and point at its
 * containing command. Shell-word substitutions contribute to conditional
 * allowance; process substitutions instead expose dynamic descriptor I/O. */
void run_semantic_reference_oracles() {
  sg_gate_t *option_gate = sg_gate_new();
  if (!option_gate || sg_gate_set_reject_mask(option_gate, 0) != SG_OK ||
      sg_gate_set_stop_mode(option_gate, SG_EVAL_ALL) != SG_OK)
    invariant_failure("builtin option oracle gate setup failed");
  sg_violation_config_t expansion_config = {};
  expansion_config.redirect_fanout_threshold = UINT32_MAX;
  expansion_config.sensitive_write_path_count = 1;
  expansion_config.sensitive_write_paths[0] = "out";
  if (sg_gate_set_violation_config_borrowed(option_gate, &expansion_config) !=
      SG_OK)
    invariant_failure("expansion control violation configuration failed");
  for (const char *source : {"wc -l file.txt", "wc -l file.txt 2>&1",
                             "wc -l file.txt 1>&0; wc -l other.txt"}) {
    auto &buffer = eval_buffer_for(g_eval_buffers.result, strlen(source));
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, source, strlen(source),
                                        buffer.data(), buffer.size(), &result);
    if (error != SG_OK || result.truncated ||
        result.requires_substitution_evaluation ||
        result.has_dynamic_substitution_io)
      invariant_failure(
          "inherited boundary changed shell evaluation semantics");
    for (uint32_t i = 0; i < result.subcommand_count; i++)
      if (result.subcommands[i].write_count || result.subcommands[i].read_count)
        invariant_failure("inherited boundary counted as explicit redirection");
    validate_result(&result, error, buffer.data(), buffer.size());
  }
  for (const char *source : {"cat <<${x:-\"EOF\"}\npayload\n${x:-\"EOF\"}\n",
                             "cat <<$(printf   eof)\npayload\n$(printf eof)\n",
                             "cat <<$(a 1>f)\npayload\n$(a > f)\n",
                             "cat <<$(a|&b)\npayload\n$(a 2>&1 | b)\n",
                             "cat <<$(a >&-file)\npayload\n$(a file 1>&-)\n",
                             "cat <<\"${x:-$'\\0'}\"\npayload\n${x:-\n",
                             "cat <<$(a >&$fd-)\npayload\n$(a 1>&$fd-)\n"}) {
    auto &buffer = eval_buffer_for(g_eval_buffers.result, strlen(source));
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, source, strlen(source),
                                        buffer.data(), buffer.size(), &result);
    if (error != SG_OK || result.truncated || result.subcommand_count != 1 ||
        result.requires_substitution_evaluation ||
        result.has_dynamic_substitution_io)
      invariant_failure("literal delimiter introduced executable children");
    validate_result(&result, error, buffer.data(), buffer.size());
  }
  static const struct {
    const char *source;
    bool capture;
  } cd_captures[] = {
      {"sh -c \"$(exec 2>&1; cd one two)\"", true},
      {"sh -c \"$(cd /; cd -)\"", true},
      {"sh -c \"$({ exec 2>&1; cd one two; })\"", true},
      {"sh -c \"$(exec 1>&- 2>&-; cd one two)\"", false},
      {"sh -c \"$(false >&- 2>&- && cd one two)\"", false},
  };
  for (const auto &fixture : cd_captures) {
    auto &buffer =
        eval_buffer_for(g_eval_buffers.result, strlen(fixture.source));
    sg_result_t result = {};
    sg_error_t error =
        sg_gate_evaluate(option_gate, fixture.source, strlen(fixture.source),
                         buffer.data(), buffer.size(), &result);
    if (error != SG_OK || result.truncated ||
        result.has_dynamic_substitution_io != fixture.capture ||
        result.requires_substitution_evaluation != fixture.capture)
      invariant_failure("cd command output/capture contract mismatch");
    validate_result(&result, error, buffer.data(), buffer.size());
  }
  static const struct {
    const char *source;
    bool capture;
  } assignment_captures[] = {
      {"sh -c \"$(x=1)\"", false},
      {"sh -c \"$(UID=1 2>&1)\"", false},
      {"sh -c \"$(exec 2>&1; UID=1)\"", true},
      {"sh -c \"$(exec 2>&1; UID=1 true 1>&- 2>&-)\"", true},
      {"sh -c \"$(exec 1>&- 2>&-; UID=1)\"", false},
      {"sh -c \"$(UID=$(printf skipped) true 1>&- 2>&-)\"", false},
      {"sh -c \"$(exec 2>&1; x=${missing:?expansion-marker})\"", true},
      {"sh -c \"$(exec 2>&1; x=$((1/0)))\"", true},
      {"sh -c \"$(exec 2>&1; : ${missing:?expansion-marker} 1>&- 2>&-)\"",
       true},
      {"sh -c \"$(: 2>&1 >${missing:?expansion-marker})\"", true},
      {"sh -c \"$(: >${missing:?expansion-marker} 2>&1)\"", false},
      {"sh -c \"$(exec 2>&1; x=$(<input))\"", true},
      {"sh -c \"$(exec 2>&1; x=$(<''))\"", true},
      {"sh -c \"$(exec 2>&1; x=$(< <(true 1>&- 2>&-)))\"", true},
  };
  for (const auto &fixture : assignment_captures) {
    auto &buffer =
        eval_buffer_for(g_eval_buffers.result, strlen(fixture.source));
    sg_result_t result = {};
    sg_error_t error =
        sg_gate_evaluate(option_gate, fixture.source, strlen(fixture.source),
                         buffer.data(), buffer.size(), &result);
    if (error != SG_OK || result.truncated || result.subcommand_count == 0 ||
        result.requires_substitution_evaluation != fixture.capture ||
        result.subcommands[0].requires_substitution_evaluation !=
            fixture.capture)
      invariant_failure("assignment diagnostic capture contract mismatch");
    validate_result(&result, error, buffer.data(), buffer.size());
  }
  static const char empty_file_source[] =
      "sh -c \"$(exec 2>&1; x=$(<\"$FILE\"))\"";
  if (sg_gate_set_expand_word_netargv(option_gate, oracle_empty_file_path,
                                      nullptr) != SG_OK)
    invariant_failure("file diagnostic callback setup failed");
  {
    auto &buffer =
        eval_buffer_for(g_eval_buffers.result, sizeof(empty_file_source) - 1);
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, empty_file_source,
                                        sizeof(empty_file_source) - 1,
                                        buffer.data(), buffer.size(), &result);
    if (error != SG_OK || result.truncated || result.subcommand_count == 0 ||
        !result.requires_substitution_evaluation ||
        !result.subcommands[0].requires_substitution_evaluation)
      invariant_failure("failed file read lost its outer inspection consumer");
    validate_result(&result, error, buffer.data(), buffer.size());
  }
  sg_gate_set_expand_word_netargv(option_gate, nullptr, nullptr);
  static const struct {
    const char *source;
    uint32_t environments;
    bool inspect;
  } assignment_effects[] = {
      {"UID=1 true", 0, false},
      {"UID=1 EUID+=2 command true", 0, false},
      {"UID=1 x=2 true", 1, false},
      {"export 'U''ID=1' x=2", 1, false},
      {"export -Z x=2", 0, false},
      {"UID=$(printf skipped) true", 0, false},
      {"UID=$(printf data) $missing", 0, true},
      {"UID=$(printf data) $(true)", 0, true},
      {"UID=$(printf data) \"$@\"", 0, true},
      {"UID=$(printf data) \"${!prefix@}\"", 0, true},
      {"UID=$(printf data) \"${@:+data}\"", 0, true},
      {"UID=$(printf skipped) \"${!prefix*}\"", 0, false},
      {"UID=$(printf skipped) \"${@:-data}\"", 0, false},
      {"UID=$(printf skipped) \"${@:-}\"", 0, false},
      {"UID=$(printf skipped) \"${@:?error}\"", 0, false},
      {"UID=$(printf skipped) \"$missing\"", 0, false},
      {"UID=$(printf skipped) $missing true", 0, false},
      {"UID=$(printf skipped) $missing-suffix", 0, false},
      {"export UID=$(printf data)", 0, true},
  };
  for (const auto &fixture : assignment_effects) {
    auto &buffer =
        eval_buffer_for(g_eval_buffers.result, strlen(fixture.source));
    sg_result_t result = {};
    sg_error_t error =
        sg_gate_evaluate(option_gate, fixture.source, strlen(fixture.source),
                         buffer.data(), buffer.size(), &result);
    if (error != SG_OK || result.truncated || result.subcommand_count == 0 ||
        result.subcommands[0].env_count != fixture.environments ||
        result.requires_substitution_evaluation != fixture.inspect)
      invariant_failure("rejected assignment ENV effect mismatch");
    validate_result(&result, error, buffer.data(), buffer.size());
  }
  for (const auto &fixture : shellsplit_test_substitution_status_cases) {
    for (unsigned success = 0; success < 2; success++) {
      std::string source = std::string(fixture.source) +
                           (success ? " && echo >out" : " || echo >out");
      auto &buffer = eval_buffer_for(g_eval_buffers.result, source.size());
      sg_result_t result = {};
      sg_error_t error =
          sg_gate_evaluate(option_gate, source.data(), source.size(),
                           buffer.data(), buffer.size(), &result);
      bool reached =
          (result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0;
      if (error != SG_OK || result.truncated ||
          reached != (success ? fixture.succeeds : fixture.fails))
        invariant_failure("substitution outcome reachability mismatch");
      validate_result(&result, error, buffer.data(), buffer.size());
    }
  }
  for (const auto &fixture : shellsplit_test_empty_paths) {
    char source[256];
    int length = std::snprintf(source, sizeof(source), fixture.source, "\"\"");
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(source))
      invariant_failure("empty pathname fixture capacity mismatch");
    auto &buffer = eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, source, length,
                                        buffer.data(), buffer.size(), &result);
    unsigned writes = 0, reads = 0;
    for (uint32_t command = 0; command < result.subcommand_count; command++) {
      writes += result.subcommands[command].write_count;
      reads += result.subcommands[command].read_count;
    }
    if (error != SG_OK || result.truncated ||
        writes != fixture.opens + fixture.writes || reads != fixture.reads ||
        result.requires_substitution_evaluation != fixture.shell_word)
      invariant_failure("static empty pathname setup contract mismatch");
    validate_result(&result, error, buffer.data(), buffer.size());
  }
  for (const auto &fixture : shellsplit_test_expansion_time_routes) {
    size_t length = std::strlen(fixture.source);
    auto &buffer = eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, fixture.source, length,
                                        buffer.data(), buffer.size(), &result);
    validate_result(&result, error, buffer.data(), buffer.size());
    bool named_write = false;
    for (uint32_t c = 0; c < result.subcommand_count; c++) {
      const auto &command = result.subcommands[c];
      named_write |=
          std::strcmp(command.netargv, "6:printf,7:payload,") == 0 &&
          (command.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0;
    }
    if (error != SG_OK || result.truncated ||
        result.requires_substitution_evaluation ||
        result.has_dynamic_substitution_io ||
        named_write != fixture.named_write)
      invariant_failure("expansion control timing contract mismatch");
  }
  for (bool redirect : {false, true}) {
    expansion_config.sensitive_write_paths[0] =
        redirect ? "redirect-out" : "argv-out";
    if (sg_gate_set_cwd(option_gate, "/workspace") != SG_OK ||
        sg_gate_set_violation_config_borrowed(option_gate, &expansion_config) !=
            SG_OK)
      invariant_failure("expansion setup violation configuration failed");
    for (const auto &fixture : shellsplit_test_expansion_setup) {
      size_t length = std::strlen(fixture.source);
      auto &buffer = eval_buffer_for(g_eval_buffers.result, length);
      sg_result_t result = {};
      sg_error_t error =
          sg_gate_evaluate(option_gate, fixture.source, length, buffer.data(),
                           buffer.size(), &result);
      validate_result(&result, error, buffer.data(), buffer.size());
      bool inspection = fixture.active && fixture.shell_word;
      bool writer = !redirect && fixture.active && fixture.writer;
      if (error != SG_OK || result.truncated ||
          result.requires_substitution_evaluation != inspection ||
          (inspection && !result.has_dynamic_substitution_io) ||
          (!fixture.active && result.has_dynamic_substitution_io) ||
          ((result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0) !=
              writer) {
        std::fprintf(stderr, "expansion setup oracle: %s\n", fixture.source);
        invariant_failure("expansion phase eligibility contract mismatch");
      }
    }
  }
  for (const auto &fixture : shellsplit_test_builtin_options) {
    size_t length = std::strlen(fixture.source);
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, fixture.source, length,
                                        buffer.data(), buffer.size(), &result);
    if (fixture.supported
            ? error != SG_OK || result.verdict == SG_VERDICT_REJECT
            : error != SG_ERR_PARSE || result.verdict != SG_VERDICT_REJECT)
      invariant_failure("builtin option grammar contract mismatch");
    validate_result(&result, error, buffer.data(), buffer.size());
  }
  for (const auto &fixture : shellsplit_test_builtin_routes) {
    size_t length = std::strlen(fixture.source);
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, fixture.source, length,
                                        buffer.data(), buffer.size(), &result);
    if (fixture.resolved
            ? error != SG_OK || result.verdict == SG_VERDICT_REJECT
            : error != SG_ERR_PARSE || result.verdict != SG_VERDICT_REJECT)
      invariant_failure("builtin operand routing contract mismatch");
    validate_result(&result, error, buffer.data(), buffer.size());
  }
  sg_violation_config_t outcome_config;
  sg_violation_config_default(&outcome_config);
  outcome_config.sensitive_write_paths[0] = "out";
  outcome_config.sensitive_write_path_count = 1;
  if (sg_gate_set_cwd(option_gate, "/workspace") != SG_OK ||
      sg_gate_set_violation_config_borrowed(option_gate, &outcome_config) !=
          SG_OK)
    invariant_failure("scope outcome violation configuration failed");
  for (const auto &fixture : shellsplit_test_ifs_routes) {
    size_t length = std::strlen(fixture.source);
    auto &buffer = eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, fixture.source, length,
                                        buffer.data(), buffer.size(), &result);
    validate_result(&result, error, buffer.data(), buffer.size());
    if (!fixture.supported) {
      if (error != SG_ERR_PARSE || result.verdict != SG_VERDICT_REJECT)
        invariant_failure("IFS unsupported route contract mismatch");
      continue;
    }
    if (error != SG_OK || result.truncated)
      invariant_failure("IFS route evaluation failed");
    bool found = false;
    for (uint32_t c = 0; c < result.subcommand_count; c++) {
      const auto &command = result.subcommands[c];
      if (std::strcmp(command.netargv, "6:printf,7:payload,"))
        continue;
      found = true;
      bool writes =
          (command.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0;
      if (writes != fixture.writes)
        invariant_failure("IFS sensitive-write route mismatch");
    }
    if (!found)
      invariant_failure("IFS route lost its printf command");
  }
  for (const auto &fixture : shellsplit_test_setup_time_outcomes) {
    size_t length = std::strlen(fixture.source);
    auto &buffer = eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, fixture.source, length,
                                        buffer.data(), buffer.size(), &result);
    if (error != SG_OK || result.truncated ||
        result.verdict == SG_VERDICT_REJECT)
      invariant_failure("setup outcome timing contract mismatch");
    validate_result(&result, error, buffer.data(), buffer.size());
  }
  static const struct {
    const char *source;
    bool sensitive;
    uint32_t write_count;
  } moves[] = {
      {"exec 4>out 10>base || exit; exec 11>&- 12>&-; "
       "printf payload 10>&4- >&12",
       true, 1},
      {"exec 4>out 10>base || exit; exec 11>&- 12>&- 13>&- 14>&-; "
       "{ printf payload >&14; } 10>&4- 14>&12-",
       true, 1},
      {"exec 3>out 4>base || exit; exec 10>&- 11>&- 12>&-; "
       ": 4>&- 10>&3-; printf payload >&3",
       true, 1},
      {"exec 3>out || exit; exec 10>&- 11>&-; "
       "exec {fd}>&3 {fd}>&3; printf payload >&10",
       true, 1},
      {"exec 3>out || exit; exec 10>&- 11>&-; "
       ": {fd}>&3 10>&-; printf payload >&\"$fd\"",
       true, 1},
      {"exec 3>out || exit; exec 10>&- 11>&-; "
       "{ :; } {fd}>&3 10>&3-; printf payload >&10",
       true, 1},
      {"exec 3>out || exit; builtin command /bin/true {fd}>&3; "
       "printf payload >&\"$fd\"",
       true, 1},
      {"exec 3>out || exit; exec 4>&-; "
       "builtin command /bin/true 4>&3-; printf payload >&3",
       false, 0},
      {"exec 3>out || exit; exec 4>&-; "
       "builtin \"$runner\" 4>&3-; printf payload >&3",
       false, 0},
      {"exec 3>out 4>base || exit; exec 10>&- 11>&-; "
       "exec {fd}>&3 {fd}>&4; echo \"$(printf payload >&10)\"",
       true, 1},
      {"exec 3>base 4>out; : 3>&4- 3>&4; printf payload >&4", true, 1},
      {"exec 3>base 4>out; { :; } 3>&4- 3>&4; printf payload >&4", true, 1},
      {"exec 3>&- 10>&- 11>&-; { probe && exec {fd}>one || "
       "exec {pad}>out {fd}>two; } && "
       "{ exec 10>&${fd}-; printf payload >&10; }",
       false, 2},
      {"exec 3>&- 10>&- 11>&-; { probe && exec {fd}>one || "
       "exec {pad}>out {fd}>two; } && "
       "{ exec 4>&${fd}-; printf payload >&4; }",
       false, 2},
      {"exec 3>&- 10>&- 11>&-; { probe && exec {fd}>one || "
       "exec {pad}>out {fd}>two; } && "
       "echo \"$(exec 4>&${fd}-; printf payload >&4)\"",
       false, 2},
      {"exec 1>out || exit; exec 10>&-; exec 10>&10-; exec {fd}>&1; "
       "printf payload >&10",
       true, 1},
      {"exec 1>out || exit; exec 10>&-; { :; } 10>&10; exec {fd}>&1; "
       "printf payload >&10",
       true, 1},
      {"exec 3>out || exit; exec 10>& - 11>& - 12>& -; "
       "{ printf payload >&11; } 3>&1",
       false, 0},
      {"exec {out}>out; exec {fd}>&1; IFS=0123456789; "
       ": {out}>&${fd}-; printf payload >&\"$out\"",
       true, 1},
      {"exec {out}>out; exec {fd}>&1; IFS=0123456789; "
       "{ :; } {out}>&${fd}-; printf payload >&\"$out\"",
       true, 1},
      {"exec {out}>out; exec {fd}>&1; IFS=0123456789; "
       "exec {out}>&${fd}-; printf payload",
       false, 0},
      {"exec 3>out 4>base || exit; exec 10>&- 11>&- 12>&-; "
       "exec {fd}>&3; : 3>&${fd}- {fd}>&4; printf payload >&10",
       true, 1},
      {"exec 3>out || exit; exec 10>&- 11>&- 12>&-; "
       "exec {fd}>&3; : 3>&${fd}- {fd}>&-; printf payload >&10",
       true, 1},
      {"exec 3>out || exit; exec 10>&- 11>&- 12>&-; "
       "exec {fd}>&3; : 3>&${fd}- 11>&3-; printf payload >&10",
       true, 1},
      {"exec 3>out 4>base || exit; exec 8>&- 10>&- 11>&- 12>&-; "
       "exec {fd}>&3; : 3>&${fd}- {fd}>&4 5>&8; printf payload >&10",
       true, 1},
      {"exec 4>&-; exec 3>out || exit; { :; } 4>&3-; printf payload >&3", false,
       0},
      {"exec 4>&-; exec 3>out || exit; { :; } 4>&3- || printf payload >&3",
       false, 0},
      {"exec 3>base 20>out || exit; exec 10>&- 11>&- 21>&- 22>&-; "
       "{ printf payload >&10; } 3>&20-",
       true, 1},
      {"exec 3>out 4>base || exit; exec 10>&- 11>&- 12>&-; "
       "exec {fd}>&3; : 3>&${fd}- {fd}>&4; echo \"$(printf payload >&10)\"",
       true, 1},
      {"exec 3>out || exit; exec 10>&- 11>&- 12>&-; "
       "exec {fd}>&3; : 3>&${fd}- {fd}>&-; cat < <(printf payload >&10)",
       true, 1},
      {"exec 3>out || exit; exec 10>&- 11>&- 12>&-; "
       "exec {fd}>&3; exec {fd}>&- 11>&3-; printf payload >&11",
       false, 0},
      {"exec 10>&-; exec {fd}>&1; : 10>&- 3>&${fd}-; printf payload", false, 0},
  };
  outcome_config.sensitive_write_paths[0] = "out";
  if (sg_gate_set_violation_config_borrowed(option_gate, &outcome_config) !=
      SG_OK)
    invariant_failure("move outcome configuration failed");
  for (const auto &fixture : moves) {
    size_t length = std::strlen(fixture.source);
    auto &buffer = eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, fixture.source, length,
                                        buffer.data(), buffer.size(), &result);
    if (error != SG_OK || result.truncated ||
        result.verdict == SG_VERDICT_REJECT)
      invariant_failure("move outcome evaluation failed");
    validate_result(&result, error, buffer.data(), buffer.size());
    bool found = false;
    for (uint32_t c = 0; c < result.subcommand_count; c++) {
      const auto &command = result.subcommands[c];
      if (std::strcmp(command.netargv, "6:printf,7:payload,"))
        continue;
      found = true;
      bool sensitive =
          (command.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0;
      if (sensitive != fixture.sensitive ||
          command.write_count != fixture.write_count)
        invariant_failure("move outcome consumer routes mismatch");
    }
    if (!found)
      invariant_failure("move outcome consumer missing");
  }
  static const struct {
    const char *source, *netargv;
    bool sensitive;
    uint32_t writes;
  } dispatch[] = {
      {"exec 3>out || exit; exec 10>&- 11>&- 12>&-; "
       "\"$cmd\" payload 1>&3 {fd}>&3 1>&10",
       "4:$cmd,7:payload,", true, 1},
      {"exec 3>out || exit; exec 10>&- 11>&- 12>&-; "
       "command \"$cmd\" payload 1>&3 {fd}>&3 1>&10",
       "7:command,4:$cmd,7:payload,", true, 1},
      {"exec 3>out || exit; exec 10>&- 11>&- 12>&-; "
       "builtin \"$cmd\" payload 1>&3 {fd}>&3 1>&10",
       "7:builtin,4:$cmd,7:payload,", false, 0},
      {"exec 3>&1 || exit; exec 10>&- 11>&- 12>&-; "
       "! 0<&0 1>&3 2>&10 && printf payload >out",
       "6:printf,7:payload,", true, 1},
      {"exec 3>&1 || exit; exec 10>&- 11>&- 12>&-; "
       "0<&0 1>&3 2>&10 && printf payload >out",
       "6:printf,7:payload,", false, 0},
      {"exec 1>original 4>out || exit; exec 10>&- 11>&- 12>&-; "
       ": 1>&4- 12>&11- 1>&11; printf payload",
       "6:printf,7:payload,", true, 1},
      {"exec 1>original 4>out || exit; exec 10>&- 11>&- 12>&-; "
       "{ :; } 1>&4- 12>&11- 1>&11; printf payload",
       "6:printf,7:payload,", true, 1},
      {"exec 1>original 4>out || exit; exec 10>&- 11>&- 12>&-; "
       "\"$cmd\" 1>&4- 12>&11- 1>&11; printf payload",
       "6:printf,7:payload,", true, 2},
      {"exec 1>original || exit; exec 9>&- 10>&- 11>&- 12>&-; "
       "{ echo \"$(exec 10>out; printf payload >&10)\"; } 1>temporary",
       "6:printf,7:payload,", false, 1},
      {"exec 1>out || exit; exec 9>&- 10>&- 11>&- 12>&-; "
       "{ cat < <(exec 10>original; printf payload >&10); } 1>temporary",
       "6:printf,7:payload,", true, 1},
      {"exec 1>original || exit; exec 9>&- 10>&- 11>&- 12>&-; "
       "{ : > >(exec 10>&-; exec 10>out; printf payload >&10); } 1>temporary",
       "6:printf,7:payload,", true, 1},
  };
  for (const auto &fixture : dispatch) {
    size_t length = std::strlen(fixture.source);
    auto &buffer = eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, fixture.source, length,
                                        buffer.data(), buffer.size(), &result);
    if (error != SG_OK || result.truncated)
      invariant_failure("dispatch evaluation failed");
    validate_result(&result, error, buffer.data(), buffer.size());
    bool found = false;
    for (uint32_t c = 0; c < result.subcommand_count; c++) {
      const auto &command = result.subcommands[c];
      if (std::strcmp(command.netargv, fixture.netargv))
        continue;
      found = true;
      if (!!(command.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) !=
              fixture.sensitive ||
          command.write_count != fixture.writes)
        invariant_failure("dispatch consumer routes mismatch");
    }
    if (!found)
      invariant_failure("dispatch consumer missing");
  }
  static const char untracked_ifs_move[] =
      "exec {fd}>&1; IFS=0123456789; : {out}>&${fd}-; printf payload";
  auto &untracked_buffer =
      eval_buffer_for(g_eval_buffers.result, sizeof(untracked_ifs_move) - 1);
  sg_result_t untracked_result = {};
  sg_error_t untracked_error = sg_gate_evaluate(
      option_gate, untracked_ifs_move, sizeof(untracked_ifs_move) - 1,
      untracked_buffer.data(), untracked_buffer.size(), &untracked_result);
  if (untracked_error != SG_ERR_PARSE ||
      untracked_result.verdict != SG_VERDICT_REJECT)
    invariant_failure("untracked IFS move outcome mismatch");
  validate_result(&untracked_result, untracked_error, untracked_buffer.data(),
                  untracked_buffer.size());
  for (const char *path : {"base", "one", "two"}) {
    for (const auto &fixture : shellsplit_test_named_cleanup) {
      outcome_config.sensitive_write_paths[0] = path;
      if (sg_gate_set_violation_config_borrowed(option_gate, &outcome_config) !=
          SG_OK)
        invariant_failure("named cleanup violation configuration failed");
      size_t length = std::strlen(fixture.source);
      auto &buffer = eval_buffer_for(g_eval_buffers.result, length);
      sg_result_t result = {};
      sg_error_t error =
          sg_gate_evaluate(option_gate, fixture.source, length, buffer.data(),
                           buffer.size(), &result);
      if (error != SG_OK || result.truncated)
        invariant_failure("named cleanup evaluation failed");
      validate_result(&result, error, buffer.data(), buffer.size());
      char netargv[80];
      if (fixture.read)
        std::snprintf(netargv, sizeof(netargv), "3:cat,");
      else if (fixture.timer)
        std::snprintf(netargv, sizeof(netargv), "4:exec,");
      else
        std::snprintf(netargv, sizeof(netargv), "6:printf,%zu:%s,",
                      std::strlen(fixture.argument), fixture.argument);
      bool found = false;
      for (uint32_t c = 0; c < result.subcommand_count; c++) {
        const auto &command = result.subcommands[c];
        if (std::strcmp(command.netargv, netargv))
          continue;
        found = true;
        bool sensitive =
            (command.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0;
        bool expected = std::strcmp(path, fixture.file) == 0 ||
                        (fixture.alternative_file &&
                         std::strcmp(path, fixture.alternative_file) == 0);
        if (fixture.read ? command.read_count !=
                               1u + (fixture.alternative_file != nullptr)
                         : !fixture.timer && sensitive != expected)
          invariant_failure("named cleanup consumer route mismatch");
      }
      if (!found)
        invariant_failure("named cleanup consumer missing");
    }
  }
  for (const char *source : shellsplit_test_invalidated_reallocation) {
    size_t length = std::strlen(source);
    auto &buffer = eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, source, length,
                                        buffer.data(), buffer.size(), &result);
    if (error != SG_ERR_PARSE || result.verdict != SG_VERDICT_REJECT)
      invariant_failure("invalidated reallocation proof was revived");
    validate_result(&result, error, buffer.data(), buffer.size());
  }
  for (bool base : {false, true}) {
    outcome_config.sensitive_write_paths[0] = base ? "base" : "out";
    if (sg_gate_set_violation_config_borrowed(option_gate, &outcome_config) !=
        SG_OK)
      invariant_failure("descriptor outcome configuration failed");
    for (const auto &fixture : shellsplit_test_descriptor_outcomes) {
      size_t length = std::strlen(fixture.source);
      auto &buffer = eval_buffer_for(g_eval_buffers.result, length);
      sg_result_t result = {};
      sg_error_t error =
          sg_gate_evaluate(option_gate, fixture.source, length, buffer.data(),
                           buffer.size(), &result);
      if (error != SG_OK || result.truncated ||
          result.verdict == SG_VERDICT_REJECT)
        invariant_failure("descriptor outcome evaluation mismatch");
      validate_result(&result, error, buffer.data(), buffer.size());
      bool found = false;
      for (uint32_t c = 0; c < result.subcommand_count; c++) {
        const auto &item = result.subcommands[c];
        if (std::strcmp(item.netargv, "6:printf,7:payload,"))
          continue;
        found = true;
        bool writes =
            (item.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0;
        if (writes != (base ? fixture.base : fixture.out))
          invariant_failure("descriptor outcome writer effect mismatch");
      }
      if (!found)
        invariant_failure("descriptor outcome writer missing");
    }
  }
  outcome_config.sensitive_write_paths[0] = "out";
  if (sg_gate_set_violation_config_borrowed(option_gate, &outcome_config) !=
      SG_OK)
    invariant_failure("scope outcome configuration failed");
  for (const auto &fixture : shellsplit_test_scope_outcomes) {
    size_t length = std::strlen(fixture.source);
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, fixture.source, length,
                                        buffer.data(), buffer.size(), &result);
    if (error != SG_OK || result.verdict == SG_VERDICT_REJECT)
      invariant_failure("scope outcome routing contract mismatch");
    validate_result(&result, error, buffer.data(), buffer.size());
    bool found = false;
    for (uint32_t command = 0; command < result.subcommand_count; command++) {
      const sg_subcommand_result_t &item = result.subcommands[command];
      if (std::strcmp(item.netargv, "6:printf,7:payload,") != 0)
        continue;
      found = true;
      bool writes = (item.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0;
      if (writes != fixture.writes_to_out)
        invariant_failure("scope outcome writer effect mismatch");
    }
    if (!found)
      invariant_failure("scope outcome writer syntax missing");
  }
  for (const auto &fixture : shellsplit_test_assignment_snapshots) {
    size_t length = std::strlen(fixture.source);
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, fixture.source, length,
                                        buffer.data(), buffer.size(), &result);
    if (fixture.resolved
            ? error != SG_OK || result.verdict == SG_VERDICT_REJECT
            : error != SG_ERR_PARSE || result.verdict != SG_VERDICT_REJECT)
      invariant_failure("assignment value snapshot contract mismatch");
    validate_result(&result, error, buffer.data(), buffer.size());
  }
  outcome_config.sensitive_write_paths[0] = "/workspace/out";
  if (sg_gate_set_violation_config_borrowed(option_gate, &outcome_config) !=
      SG_OK)
    invariant_failure("CWD outcome violation configuration failed");
  for (const auto &fixture : shellsplit_test_cwd_reachability) {
    if (std::strcmp(fixture.file, "out") ||
        !std::strstr(fixture.source, "printf payload"))
      continue;
    size_t length = std::strlen(fixture.source);
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, fixture.source, length,
                                        buffer.data(), buffer.size(), &result);
    if (error != SG_OK)
      invariant_failure("CWD outcome evaluation failed");
    validate_result(&result, error, buffer.data(), buffer.size());
    bool expected =
        fixture.identity && !std::strcmp(fixture.identity, "/workspace/out");
    bool found = false;
    for (uint32_t c = 0; c < result.subcommand_count; c++) {
      const auto &item = result.subcommands[c];
      if (std::strcmp(item.netargv, "6:printf,7:payload,"))
        continue;
      found = true;
      if (((item.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0) !=
          expected)
        invariant_failure("CWD outcome writer identity mismatch");
    }
    if (!found)
      invariant_failure("CWD outcome writer missing");
  }
  for (const auto &fixture : shellsplit_test_skipped_dup_operands) {
    size_t length = std::strlen(fixture.source);
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t error = sg_gate_evaluate(option_gate, fixture.source, length,
                                        buffer.data(), buffer.size(), &result);
    if (error != SG_OK || result.subcommand_count != fixture.commands)
      invariant_failure("skipped duplication syntax missing");
    validate_result(&result, error, buffer.data(), buffer.size());
    if (result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE)
      invariant_failure("skipped duplication has an output effect");
  }
  sg_gate_free(option_gate);
  struct oracle_case {
    const char *input;
    const char *const *rules;
    size_t rule_count;
    uint32_t command_count;
    sg_verdict_t verdict;
    bool requires_shell_word_evaluation;
    bool has_dynamic_substitution_io;
  };
  static const char *const echo_id_pwd[] = {"echo *", "id", "pwd"};
  static const char *const nested[] = {"echo *", "echo $(printf x $(id))",
                                       "printf x $(id)", "id"};
  /* Process substitution supplies a generated pathname argument to `sort`.
   * Keep that argument in canonical netargv, so the reference policy must
   * permit one operand rather than treating `sort` as a zero-argument command.
   */
  static const char *const process[] = {"cat", "sort", "cat #path", "sort *"};
  static const char *const quoted[] = {"echo *", "id"};
  static const char *const composite[] = {"echo", "echo *", "id"};
  static const char *const redirect_rules[] = {"cat", "cat 0"};
  static const char *const timed_executables[] = {"true", "cat", "echo *",
                                                  "time", "time *"};
  static const oracle_case cases[] = {
      {"time <<<body cat", timed_executables, 5, 1, SG_VERDICT_ALLOW, false,
       false},
      {"true | time <<<body", timed_executables, 5, 2, SG_VERDICT_ALLOW, false,
       false},
      {"time true | time -p <<EOF\nbody\nEOF\n", timed_executables, 5, 2,
       SG_VERDICT_ALLOW, false, false},
      {"true |& 3<<<body cat", timed_executables, 5, 2, SG_VERDICT_ALLOW, false,
       false},
      {"time true | time", timed_executables, 5, 2, SG_VERDICT_ALLOW, false,
       false},
      {"time true | time -p", timed_executables, 5, 2, SG_VERDICT_ALLOW, false,
       false},
      {"time true | time --", timed_executables, 5, 2, SG_VERDICT_ALLOW, false,
       false},
      {"time true | time !", timed_executables, 5, 2, SG_VERDICT_ALLOW, false,
       false},
      {"time -p true | time", timed_executables, 5, 2, SG_VERDICT_ALLOW, false,
       false},
      {"time true |& time", timed_executables, 5, 2, SG_VERDICT_ALLOW, false,
       false},
      {"time true | time | cat", timed_executables, 5, 3, SG_VERDICT_ALLOW,
       false, false},
      {"time true | \"time\"", timed_executables, 5, 2, SG_VERDICT_ALLOW, false,
       false},
      {"time true | { time -p; }", timed_executables, 5, 1, SG_VERDICT_ALLOW,
       false, false},
      {"echo \"$(time true | time)\"", timed_executables, 5, 3,
       SG_VERDICT_ALLOW_CONDITIONAL, true, true},
      {"cat && time", redirect_rules, 2, 1, SG_VERDICT_ALLOW, false, false},
      {"cat || time", redirect_rules, 2, 1, SG_VERDICT_ALLOW, false, false},
      {"cat && time; time", redirect_rules, 2, 1, SG_VERDICT_ALLOW, false,
       false},
      {"{ cat; } 1\\\n2<<EOF\nbody\nEOF\n>out", redirect_rules, 2, 1,
       SG_VERDICT_UNDETERMINED, false, false},
      {"cat 1\\\n2<<<body", redirect_rules, 2, 1, SG_VERDICT_ALLOW, false,
       false},
      {"cat $'x'3>out", redirect_rules, 2, 1, SG_VERDICT_UNDETERMINED, false,
       false},
      {"{ cat; } >out; >a; >b", redirect_rules, 2, 1, SG_VERDICT_UNDETERMINED,
       false, false},
      {"cat 0 <<<body", redirect_rules, 2, 1, SG_VERDICT_ALLOW, false, false},
      {"cat 0<<EOF\nwhile true; do :; done\nEOF\n", redirect_rules, 2, 1,
       SG_VERDICT_ALLOW, false, false},
      {"echo < prefix<(id)", composite, 3, 2, SG_VERDICT_ALLOW, false, false},
      {"echo $(<prefix<(id))", composite, 3, 2, SG_VERDICT_ALLOW_CONDITIONAL,
       true, true},
      {"echo $(id)$(pwd)", echo_id_pwd, 3, 3, SG_VERDICT_ALLOW_CONDITIONAL,
       true, true},
      {"echo $(printf x $(id))", nested, 4, 3, SG_VERDICT_ALLOW_CONDITIONAL,
       true, true},
      {"cat <(sort <(cat /tmp/a))", process, 4, 3, SG_VERDICT_ALLOW, false,
       true},
      {"echo \"$(id)\"", quoted, 2, 2, SG_VERDICT_ALLOW_CONDITIONAL, true,
       true},
  };

  for (const oracle_case &item : cases) {
    sg_gate_t *gate = sg_gate_new();
    if (!gate || sg_gate_set_reject_mask(gate, 0) != SG_OK ||
        sg_gate_set_stop_mode(gate, SG_EVAL_ALL) != SG_OK)
      invariant_failure("semantic oracle gate setup failed");
    for (size_t i = 0; i < item.rule_count; i++)
      if (test_policy_replace_cpl(gate, false, item.rules[i], false) != ST_OK)
        invariant_failure("semantic oracle rule setup failed");

    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, std::strlen(item.input));
    sg_result_t result = {};
    sg_error_t error =
        sg_gate_evaluate(gate, item.input, std::strlen(item.input),
                         buffer.data(), buffer.size(), &result);
    if (error != SG_OK || result.verdict != item.verdict ||
        result.subcommand_count != item.command_count ||
        result.requires_substitution_evaluation !=
            item.requires_shell_word_evaluation ||
        result.has_dynamic_substitution_io !=
            item.has_dynamic_substitution_io) {
      fprintf(stderr, "semantic oracle input: %s\n", item.input);
      invariant_failure("semantic oracle verdict or command count mismatch");
    }
    sg_gate_free(gate);
  }

  sg_gate_t *compound_gate = sg_gate_new();
  if (!compound_gate || sg_gate_set_reject_mask(compound_gate, 0) != SG_OK ||
      test_policy_replace_cpl(compound_gate, false, "c3", false) != ST_OK ||
      test_policy_replace_cpl(compound_gate, false, "cat *", false) != ST_OK ||
      test_policy_replace_cpl(compound_gate, false, "mycommand *", false) !=
          ST_OK)
    invariant_failure("compound-word oracle gate setup failed");
  static const char compound_input[] =
      "$'c'3>out;cat \"x\"${y}z;my\\\ncommand value";
  reusable_eval_buffer &compound_buffer =
      eval_buffer_for(g_eval_buffers.result, sizeof(compound_input) - 1);
  sg_result_t compound_result = {};
  if (sg_gate_evaluate(compound_gate, compound_input,
                       sizeof(compound_input) - 1, compound_buffer.data(),
                       compound_buffer.size(), &compound_result) != SG_OK ||
      compound_result.subcommand_count != 3 ||
      !compound_result.subcommands[0].netargv ||
      !compound_result.subcommands[1].netargv ||
      !compound_result.subcommands[2].netargv ||
      strcmp(compound_result.subcommands[0].netargv, "2:c3,") != 0 ||
      strcmp(compound_result.subcommands[1].netargv, "3:cat,6:x${y}z,") != 0 ||
      strcmp(compound_result.subcommands[2].netargv, "9:mycommand,5:value,") !=
          0)
    invariant_failure("compound-word policy netargv oracle mismatch");
  sg_gate_free(compound_gate);

  /* Assignment prefixes do not replace a current-shell descriptor-variable
   * binding. Keep this fixed oracle independent of the checked-in fuzz seeds:
   * a regression must not turn a valid redirect into a graph parse error. */
  sg_gate_t *named_fd_prefix_gate = sg_gate_new();
  if (!named_fd_prefix_gate ||
      sg_gate_set_reject_mask(named_fd_prefix_gate, 0) != SG_OK ||
      test_policy_replace_cpl(named_fd_prefix_gate, false, "exec", false) !=
          ST_OK ||
      test_policy_replace_cpl(named_fd_prefix_gate, false, "producer", false) !=
          ST_OK ||
      test_policy_replace_cpl(named_fd_prefix_gate, false, "printf *", false) !=
          ST_OK)
    invariant_failure("named-fd prefix oracle gate setup failed");
  static const char named_fd_prefix_input[] =
      "exec {fd}>/tmp/fuzz-prefix; fd=shadow printf bytes >&$fd; "
      "printf later >&$fd";
  reusable_eval_buffer &named_fd_buffer =
      eval_buffer_for(g_eval_buffers.result, sizeof(named_fd_prefix_input) - 1);
  sg_result_t named_fd_result = {};
  if (sg_gate_evaluate(named_fd_prefix_gate, named_fd_prefix_input,
                       sizeof(named_fd_prefix_input) - 1,
                       named_fd_buffer.data(), named_fd_buffer.size(),
                       &named_fd_result) != SG_OK ||
      named_fd_result.verdict != SG_VERDICT_ALLOW ||
      named_fd_result.subcommand_count != 3)
    invariant_failure("named-fd prefix oracle mismatch");
  static const char named_fd_append_prefix_input[] =
      "exec {fd}>/tmp/fuzz-append-prefix; fd+=shadow printf bytes >&$fd; "
      "printf later >&$fd";
  eval_buffer_for(named_fd_buffer, sizeof(named_fd_append_prefix_input) - 1);
  if (sg_gate_evaluate(named_fd_prefix_gate, named_fd_append_prefix_input,
                       sizeof(named_fd_append_prefix_input) - 1,
                       named_fd_buffer.data(), named_fd_buffer.size(),
                       &named_fd_result) != SG_OK ||
      named_fd_result.verdict != SG_VERDICT_ALLOW ||
      named_fd_result.subcommand_count != 3)
    invariant_failure("named-fd append-prefix oracle mismatch");

  /* A persistent close is valid setup, but it must remove the named route
   * before a later exact redirect can reach policy evaluation. */
  static const char named_fd_close_input[] =
      "exec {fd}>/tmp/fuzz-close; exec {fd}>&-";
  eval_buffer_for(named_fd_buffer, sizeof(named_fd_close_input) - 1);
  if (sg_gate_evaluate(named_fd_prefix_gate, named_fd_close_input,
                       sizeof(named_fd_close_input) - 1, named_fd_buffer.data(),
                       named_fd_buffer.size(), &named_fd_result) != SG_OK ||
      named_fd_result.verdict != SG_VERDICT_ALLOW ||
      named_fd_result.subcommand_count != 2)
    invariant_failure("named-fd close oracle mismatch");
  static const char named_fd_closed_use_input[] =
      "exec {fd}>/tmp/fuzz-close; exec {fd}>&-; printf bytes >&$fd";
  eval_buffer_for(named_fd_buffer, sizeof(named_fd_closed_use_input) - 1);
  if (sg_gate_evaluate(named_fd_prefix_gate, named_fd_closed_use_input,
                       sizeof(named_fd_closed_use_input) - 1,
                       named_fd_buffer.data(), named_fd_buffer.size(),
                       &named_fd_result) != SG_ERR_PARSE ||
      named_fd_result.verdict != SG_VERDICT_REJECT)
    invariant_failure("named-fd closed-use oracle mismatch");

  static const char named_fd_assignment_input[] =
      "exec {fd}>/tmp/fuzz-assignment; f\\\nd=shadow; printf bytes >&$fd";
  eval_buffer_for(named_fd_buffer, sizeof(named_fd_assignment_input) - 1);
  if (sg_gate_evaluate(named_fd_prefix_gate, named_fd_assignment_input,
                       sizeof(named_fd_assignment_input) - 1,
                       named_fd_buffer.data(), named_fd_buffer.size(),
                       &named_fd_result) != SG_ERR_PARSE ||
      named_fd_result.verdict != SG_VERDICT_REJECT)
    invariant_failure("named-fd assignment oracle mismatch");
  static const char named_fd_append_assignment_input[] =
      "exec {fd}>/tmp/fuzz-append-assignment; f\\\n"
      "d+=shadow; printf bytes >&$fd";
  eval_buffer_for(named_fd_buffer,
                  sizeof(named_fd_append_assignment_input) - 1);
  if (sg_gate_evaluate(named_fd_prefix_gate, named_fd_append_assignment_input,
                       sizeof(named_fd_append_assignment_input) - 1,
                       named_fd_buffer.data(), named_fd_buffer.size(),
                       &named_fd_result) != SG_ERR_PARSE ||
      named_fd_result.verdict != SG_VERDICT_REJECT)
    invariant_failure("named-fd append-assignment oracle mismatch");

  /* A readonly descriptor variable makes a later `{fd}>...` allocation fail
   * while retaining its old value in Bash. Shellgate must reject the entire
   * source at the shared semantic boundary instead of evaluating a graph with
   * a fictitious route to the replacement file. */
  static const char *const named_fd_readonly_inputs[] = {
      "exec {fd}>/tmp/fuzz-readonly-first; readonly fd; "
      "exec {fd}>/tmp/fuzz-readonly-second; printf bytes >&$fd",
      "exec {fd}>/tmp/fuzz-readonly-first; declare -r fd; "
      "exec {fd}>/tmp/fuzz-readonly-second; printf bytes >&$fd",
      "exec {fd}>/tmp/fuzz-readonly-first; typeset -r fd; "
      "exec {fd}>/tmp/fuzz-readonly-second; printf bytes >&$fd",
  };
  for (const char *input : named_fd_readonly_inputs) {
    eval_buffer_for(named_fd_buffer, std::strlen(input));
    if (sg_gate_evaluate(named_fd_prefix_gate, input, std::strlen(input),
                         named_fd_buffer.data(), named_fd_buffer.size(),
                         &named_fd_result) != SG_ERR_PARSE ||
        named_fd_result.verdict != SG_VERDICT_REJECT)
      invariant_failure("named-fd readonly oracle mismatch");
  }

  /* Dynamic words after `set -o` and `printf -v` are not ordinary argv: they
   * can respectively change POSIX mode or write POSIXLY_CORRECT in the current
   * shell. The lexer exposes parameter expansions as fragments, so keep this
   * fixed oracle at the public Shellgate boundary. */
  static const char *const dynamic_current_shell_inputs[] = {
      "set -o \"$option\"; printf bytes",
      "target='POSIXLY_CORRECT=1'; declare \"$target\"; printf bytes",
      "target='POSIXLY_CORRECT=1'; typeset \"$target\"; printf bytes",
      "target='POSIXLY_CORRECT=1'; export \"$target\"; printf bytes",
      "printf -v \"$target\" enabled; printf bytes",
      "printf -v\"$target\" enabled; printf bytes",
      "printf -v${target} enabled; printf bytes",
  };
  for (const char *input : dynamic_current_shell_inputs) {
    eval_buffer_for(named_fd_buffer, std::strlen(input));
    if (sg_gate_evaluate(named_fd_prefix_gate, input, std::strlen(input),
                         named_fd_buffer.data(), named_fd_buffer.size(),
                         &named_fd_result) != SG_ERR_PARSE ||
        named_fd_result.verdict != SG_VERDICT_REJECT)
      invariant_failure("dynamic current-shell oracle mismatch");
  }

  static const char named_fd_input_process_substitution[] =
      "exec {source}< <(producer); printf bytes";
  eval_buffer_for(named_fd_buffer,
                  sizeof(named_fd_input_process_substitution) - 1);
  if (sg_gate_evaluate(named_fd_prefix_gate,
                       named_fd_input_process_substitution,
                       sizeof(named_fd_input_process_substitution) - 1,
                       named_fd_buffer.data(), named_fd_buffer.size(),
                       &named_fd_result) != SG_OK ||
      named_fd_result.verdict != SG_VERDICT_ALLOW ||
      named_fd_result.subcommand_count != 3 ||
      !named_fd_result.has_dynamic_substitution_io ||
      named_fd_result.requires_substitution_evaluation)
    invariant_failure("named-fd process-substitution topology oracle mismatch");
  sg_gate_free(named_fd_prefix_gate);

  /* Shellgate must receive one policy subject only when shell syntax actually
   * quotes the metacharacter. Keep feature rejection disabled: this oracle
   * tests structure, while an empty policy deliberately remains undecided. */
  static const char *const opaque_word_cases[] = {
      "echo ${value:-left|&right}",
      "echo ${value:-left>file}",
      "echo prefix@(left|right)suffix",
      "echo prefix\\{left\\|right\\}suffix",
      "echo '[left|right]'",
      "echo \\|",
      "echo \\&",
      "echo \\;",
      "echo \\|\\&",
  };
  sg_gate_t *opaque_word_gate = sg_gate_new();
  if (!opaque_word_gate ||
      sg_gate_set_reject_mask(opaque_word_gate, 0) != SG_OK)
    invariant_failure("opaque-word oracle gate setup failed");
  for (const char *input : opaque_word_cases) {
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, std::strlen(input));
    sg_result_t result = {};
    if (sg_gate_evaluate(opaque_word_gate, input, std::strlen(input),
                         buffer.data(), buffer.size(), &result) != SG_OK ||
        result.verdict != SG_VERDICT_UNDETERMINED ||
        result.subcommand_count != 1 || !result.subcommands[0].netargv ||
        result.truncated)
      invariant_failure("opaque-word semantic oracle mismatch");
  }
  for (const auto &fixture : shellsplit_test_quoted_arithmetic) {
    size_t length = std::strlen(fixture.source);
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t status =
        sg_gate_evaluate(opaque_word_gate, fixture.source, length,
                         buffer.data(), buffer.size(), &result);
    if (fixture.supported
            ? status != SG_OK || result.verdict != SG_VERDICT_UNDETERMINED ||
                  result.subcommand_count != 1
            : status != SG_ERR_PARSE || result.verdict != SG_VERDICT_REJECT)
      invariant_failure("quoted arithmetic semantic oracle mismatch");
  }
  for (const auto &fixture : shellsplit_test_scoped_expansions) {
    size_t length = std::strlen(fixture.source);
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, length);
    sg_result_t result = {};
    sg_error_t status =
        sg_gate_evaluate(opaque_word_gate, fixture.source, length,
                         buffer.data(), buffer.size(), &result);
    if (fixture.supported
            ? status != SG_OK || result.verdict != SG_VERDICT_UNDETERMINED ||
                  result.subcommand_count + fixture.file_stages !=
                      fixture.stages
            : status != SG_ERR_PARSE || result.verdict != SG_VERDICT_REJECT)
      invariant_failure("heredoc expansion semantic oracle mismatch");
  }
  sg_gate_free(opaque_word_gate);

  static const char *const structural_word_cases[] = {
      "echo prefix{left|right}suffix",
      "echo [left|right]",
      "echo [[:alpha:]|]",
  };
  sg_gate_t *structural_word_gate = sg_gate_new();
  if (!structural_word_gate ||
      sg_gate_set_reject_mask(structural_word_gate, 0) != SG_OK)
    invariant_failure("structural-word oracle gate setup failed");
  for (const char *input : structural_word_cases) {
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, std::strlen(input));
    sg_result_t result = {};
    if (sg_gate_evaluate(structural_word_gate, input, std::strlen(input),
                         buffer.data(), buffer.size(), &result) != SG_OK ||
        result.verdict != SG_VERDICT_UNDETERMINED ||
        result.subcommand_count != 2 || !result.subcommands[0].netargv ||
        !result.subcommands[1].netargv || result.truncated)
      invariant_failure("structural-word semantic oracle mismatch");
  }
  sg_gate_free(structural_word_gate);

  sg_gate_t *timed_gate = sg_gate_new();
  if (!timed_gate || sg_gate_set_reject_mask(timed_gate, 0) != SG_OK ||
      sg_gate_set_stop_mode(timed_gate, SG_EVAL_ALL) != SG_OK ||
      test_policy_replace_cpl(timed_gate, false, "echo *", false) != ST_OK ||
      test_policy_replace_cpl(timed_gate, false, "true", false) != ST_OK ||
      test_policy_replace_cpl(timed_gate, false, "false", false) != ST_OK ||
      test_policy_replace_cpl(timed_gate, false, "exit", false) != ST_OK ||
      test_policy_replace_cpl(timed_gate, false, "exec", false) != ST_OK ||
      test_policy_replace_cpl(timed_gate, false, "printf *", false) != ST_OK ||
      test_policy_replace_cpl(timed_gate, false, "printf * *", false) !=
          ST_OK ||
      test_policy_replace_cpl(timed_gate, false, "cat *", false) != ST_OK ||
      test_policy_replace_cpl(timed_gate, false, "cat", false) != ST_OK)
    invariant_failure("timed-pipeline oracle gate setup failed");
  static const char timed_input[] = "time -p>/tmp/timing echo x";
  reusable_eval_buffer &timed_buffer =
      eval_buffer_for(g_eval_buffers.result, sizeof(timed_input) - 1);
  sg_result_t timed_result = {};
  if (sg_gate_evaluate(timed_gate, timed_input, sizeof(timed_input) - 1,
                       timed_buffer.data(), timed_buffer.size(),
                       &timed_result) != SG_OK ||
      timed_result.verdict != SG_VERDICT_ALLOW ||
      timed_result.subcommand_count != 1 ||
      timed_result.subcommands[0].netargv_length != strlen("4:echo,1:x,") ||
      memcmp(timed_result.subcommands[0].netargv, "4:echo,1:x,",
             strlen("4:echo,1:x,")) != 0)
    invariant_failure("timed-pipeline semantic oracle mismatch");
  static const struct {
    const char *input;
    uint32_t count;
    bool inspection;
    bool dynamic;
  } timing_stream_cases[] = {
      {"time ({ echo x; })", 1, false, false},
      {"time ({(echo x)})", 1, false, false},
      {"(false; exit <<< <(printf '%s' \"$(true)\")) && printf x >/tmp/skipped",
       5, true, true},
      {"(true; exit <<< <(printf '%s' \"$(false)\")) || printf x >/tmp/skipped",
       5, true, true},
      {"echo \"$(time; true)\"", 2, true, true},
      {"echo \"`time; true`\"", 2, true, true},
      {"echo \"$(exec 2>&1; time; true)\"", 3, true, true},
      {"cat <(time; printf x)", 2, false, true},
      {"printf x > >(time; cat)", 2, false, true},
      {"echo \"$(time &)\"", 1, false, false},
      {"echo \"$(time { time; })\"", 1, false, false},
      {"echo \"$(time (time; true))\"", 2, true, true},
      {"echo \"$(time (time &))\"", 1, false, false},
      {"printf x | { exec 2>err; time true; }", 3, false, false},
      {"printf x | { exec {fd}>out; printf value >&$fd; }", 3, false, false},
  };
  for (const auto &item : timing_stream_cases) {
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, std::strlen(item.input));
    sg_result_t result = {};
    if (sg_gate_evaluate(timed_gate, item.input, std::strlen(item.input),
                         buffer.data(), buffer.size(), &result) != SG_OK ||
        result.verdict != (item.inspection ? SG_VERDICT_ALLOW_CONDITIONAL
                                           : SG_VERDICT_ALLOW) ||
        result.subcommand_count != item.count || result.truncated ||
        result.requires_substitution_evaluation != item.inspection ||
        result.has_dynamic_substitution_io != item.dynamic)
      invariant_failure("timing-stream semantic oracle mismatch");
    if (std::strstr(item.input, "/tmp/skipped") &&
        result.subcommands[result.subcommand_count - 1].write_count != 0)
      invariant_failure("process-child status escaped into skipped writer");
  }
  for (const char *input :
       {"echo \"$(time)\"", "echo \"$(time;)\"", "echo \"$(exec 2>&1; time;)\"",
        "cat <(time;)", "printf x > >(time;)", "echo \"$( (time;) )\"",
        "echo \"$(time (time;))\"", "echo \"$( (time;); : )\"",
        "cat <( (time;) )", "printf x > >( (time;) )"}) {
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, std::strlen(input));
    sg_result_t result = {};
    if (sg_gate_evaluate(timed_gate, input, std::strlen(input), buffer.data(),
                         buffer.size(), &result) != SG_ERR_PARSE ||
        result.verdict != SG_VERDICT_REJECT)
      invariant_failure("parenthesized empty-time rejection oracle mismatch");
  }
  sg_gate_free(timed_gate);

  /* Lexical recognition must never become a policy subject when Shellsplit
   * cannot construct the command's execution semantics. These fixed cases
   * intentionally live in the harness rather than the smoke corpus. */
  static const char *const unmodeled_semantic_cases[] = {
      "[[ -f /tmp/x ]]",
      "(( count += 1 ))",
      "time eval echo hidden",
      "time coproc echo hidden",
      "time [[ -f /tmp/x ]]",
      "echo \"$(time eval echo hidden)\"",
      "printf '%s' $\"localized\"",
      "echo $( [[ -f /tmp/x ]] )",
      "{ (( count )); }",
      "cat <<EOF\n$(while true; do :; done)\nEOF\n",
      "cat <<EOF\n`select item in one; do :; done`\nEOF\n",
      "cat <<EOF\n${items[0]}\nEOF\n",
      "cat <<EOF\n$((items[0]))\nEOF\n",
  };
  sg_gate_t *unmodeled_gate = sg_gate_new();
  if (!unmodeled_gate || sg_gate_set_reject_mask(unmodeled_gate, 0) != SG_OK)
    invariant_failure("unmodeled semantic oracle gate setup failed");
  for (const char *input : unmodeled_semantic_cases) {
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, std::strlen(input));
    sg_result_t result = {};
    if (sg_gate_evaluate(unmodeled_gate, input, std::strlen(input),
                         buffer.data(), buffer.size(),
                         &result) != SG_ERR_PARSE ||
        result.verdict != SG_VERDICT_REJECT || result.subcommand_count != 1 ||
        result.truncated)
      invariant_failure("unmodeled semantic rejection mismatch");
  }
  sg_gate_free(unmodeled_gate);

  static const char *const named_fd_cases[] = {
      "cmd {fd}< <(producer)",
      "cmd {fd}< prefix<(producer)",
      "cmd {fd}> >(consumer)",
      "cmd {fd}> prefix>(consumer)",
      "cmd {fd}<> <(producer)",
      "exec {fd}< >(true </dev/null); cat <&$fd",
      "exec {fd}> <(printf ignored >/dev/null); printf value >&$fd",
      "exec {fd}<> <(printf input); printf value >&$fd",
      "exec {fd}<> >(true </dev/null); cat <&$fd",
      "printf x {fd}>out >&$fd",
      "printf x {fd}>out; printf x >&$fd",
      "exec {fd}>out; ( printf x >&$fd )",
      "( printf x >&$fd ) {fd}>out",
      "exec {fd}<&0; printf x \"$(cat <&$fd)\"",
      "exec {source}<in; exec {copy}<&$source; printf x \"$(cat <&$copy)\"",
      "exec {out}>out; exec {copy}<&$out; printf x >&$copy",
      "exec {in}<in; exec {copy}>&$in; cat <&$copy",
      "exec {out}>out; exec {out}>&$out; printf x >&$out",
      "printf {fd}<in > >(cat <&$fd)",
      "printf x >&combined",
      "printf x 1>&combined",
      "printf x >&$",
      "printf x >&[",
      "printf x >&file[part",
      "printf x >&literal{path}",
      "printf x >&literal$destination",
      "printf x >&literal${destination}",
      "printf x >&literal$((1 + 2))",
      "printf x >&\"\"literal$(printf target)",
      "printf x >&file{one,two}",
      "printf x >&*.log",
      "printf x >& >(consumer)",
      "exec 3>out; printf x >&3",
      "exec 3<in; printf x \"$(cat <&3)\"",
      "exec 3> >(consumer); printf x >&3",
  };
  sg_gate_t *named_fd_gate = sg_gate_new();
  if (!named_fd_gate || sg_gate_set_reject_mask(named_fd_gate, 0) != SG_OK)
    invariant_failure("named-fd semantic oracle gate setup failed");
  for (const char *input : named_fd_cases) {
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, std::strlen(input));
    sg_result_t result = {};
    if (sg_gate_evaluate(named_fd_gate, input, std::strlen(input),
                         buffer.data(), buffer.size(), &result) != SG_OK ||
        result.verdict != SG_VERDICT_UNDETERMINED ||
        result.subcommand_count < 1 || !result.subcommands[0].netargv ||
        result.truncated)
      invariant_failure("named-fd semantic oracle mismatch");
  }
  sg_gate_free(named_fd_gate);

  static const char *const named_fd_snapshot_rejections[] = {
      "printf x {fd}<in \"$(cat <&$fd)\"",
      "exec {fd}<in; exec {fd}<&-; printf x \"$(cat <&$fd)\"",
      "exec {fd}>&-",
      "exec {fd}<&-",
      "printf x >&$destination",
      "printf x >&~",
      "printf x >&*",
      "printf x >&@(file)",
      "printf x >&[[:digit:]]",
      "printf x >&[[=a=]]",
      "printf x >&[[.a.]]",
      "printf x >&\\\n~",
      "printf > >(cat <&$fd) {fd}<in",
      "shopt -u varredir_close; : {fd}<in; printf x \"$(cat <&$fd)\"",
      "x+=value shopt -s varredir_close; : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      "x+\\\n=value shopt -u varredir_close; : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      "shopt -s lastpipe; printf source | : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      "eval 'shopt -s lastpipe'; printf source | : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      ". /tmp/shell-state; printf source | : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      "command source /tmp/shell-state; printf source | : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      "trap 'shopt -s lastpipe' DEBUG; printf source | : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      "alias change_scope='shopt -s lastpipe'; "
      "printf source | : {fd}<in; printf x \"$(cat <&$fd)\"",
      "shopt -s expand_aliases; printf source | : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      "history -s 'shopt -s lastpipe'; fc -s -1; "
      "printf source | : {fd}<in; printf x \"$(cat <&$fd)\"",
      "enable -f /tmp/shell-state change_scope; "
      "printf source | : {fd}<in; printf x \"$(cat <&$fd)\"",
      "( : ) {fd}>out; printf x >&$fd",
  };
  named_fd_gate = sg_gate_new();
  if (!named_fd_gate || sg_gate_set_reject_mask(named_fd_gate, 0) != SG_OK)
    invariant_failure("named-fd snapshot rejection gate setup failed");
  for (const char *input : named_fd_snapshot_rejections) {
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, std::strlen(input));
    sg_result_t result = {};
    if (sg_gate_evaluate(named_fd_gate, input, std::strlen(input),
                         buffer.data(), buffer.size(),
                         &result) != SG_ERR_PARSE ||
        result.verdict != SG_VERDICT_REJECT || result.subcommand_count != 1 ||
        result.truncated)
      invariant_failure("named-fd snapshot rejection mismatch");
  }
  sg_gate_free(named_fd_gate);

  /* A syntactically valid redirect-only list element has no argv policy
   * subject. It must remain explicitly undetermined, while preserving normal
   * policy results for preceding executable commands and learning the full
   * structural sequence through Shellsplit's empty-stage sentinel. */
  sg_gate_t *redirect_gate = sg_gate_new();
  if (!redirect_gate || sg_gate_set_reject_mask(redirect_gate, 0) != SG_OK ||
      sg_gate_set_stop_mode(redirect_gate, SG_EVAL_ALL) != SG_OK ||
      sg_gate_enable_anomaly(redirect_gate, 100.0, nullptr) != SG_OK ||
      sg_gate_set_anomaly_skip_on_detected(redirect_gate, false) != SG_OK ||
      test_policy_replace_cpl(redirect_gate, false, "echo ok", false) != ST_OK)
    invariant_failure("redirect-only oracle gate setup failed");
  size_t redirect_vocabulary = test_anomaly_vocabulary(redirect_gate);
  static const char *const redirect_reason =
      "redirect-only shell operation is not argv-policy-evaluable";
  struct redirect_oracle_case {
    const char *input;
    uint32_t command_count;
  };
  static const redirect_oracle_case redirect_cases[] = {
      {">/tmp/fuzz-redirect-only", 0},
      {"echo ok; >/tmp/fuzz-redirect-only", 1},
      {"echo ok | >/tmp/fuzz-redirect-only", 1},
      {"{ time; } >/tmp/fuzz-redirect-only", 0},
      {"{ { time; }; } </dev/null", 0},
      {"(time;) &>/tmp/fuzz-redirect-only", 0},
  };
  for (size_t i = 0; i < std::size(redirect_cases); i++) {
    const redirect_oracle_case &item = redirect_cases[i];
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, std::strlen(item.input));
    sg_result_t result = {};
    size_t vocabulary_before = test_anomaly_vocabulary(redirect_gate);
    if (sg_gate_evaluate(redirect_gate, item.input, std::strlen(item.input),
                         buffer.data(), buffer.size(), &result) != SG_OK ||
        result.verdict != SG_VERDICT_UNDETERMINED ||
        result.subcommand_count != item.command_count || !result.deny_reason ||
        std::strcmp(result.deny_reason, redirect_reason) != 0 ||
        test_anomaly_vocabulary(redirect_gate) < vocabulary_before ||
        (i < 2 &&
         test_anomaly_vocabulary(redirect_gate) <= vocabulary_before) ||
        (item.command_count != 0 &&
         (!result.subcommands[0].matches ||
          result.subcommands[0].verdict != SG_VERDICT_ALLOW)))
      invariant_failure("redirect-only policy oracle mismatch");
    redirect_vocabulary = test_anomaly_vocabulary(redirect_gate);
  }
  if (redirect_vocabulary == 0)
    invariant_failure("redirect-only anomaly sentinel was not learned");
  sg_gate_free(redirect_gate);

  sg_gate_t *strong_redirect_gate = sg_gate_new();
  if (!strong_redirect_gate ||
      sg_gate_set_stop_mode(strong_redirect_gate, SG_EVAL_ALL) != SG_OK ||
      sg_gate_set_reject_mask(strong_redirect_gate, 0) != SG_OK ||
      test_policy_replace_cpl(strong_redirect_gate, true, "blocked", false) !=
          ST_OK)
    invariant_failure("strong redirect-only oracle gate setup failed");
  reusable_eval_buffer &strong_buffer = eval_buffer_for(
      g_eval_buffers.result, std::strlen("blocked; >/tmp/fuzz-redirect-only"));
  sg_result_t strong_result = {};
  if (sg_gate_evaluate(strong_redirect_gate,
                       "blocked; >/tmp/fuzz-redirect-only",
                       std::strlen("blocked; >/tmp/fuzz-redirect-only"),
                       strong_buffer.data(), strong_buffer.size(),
                       &strong_result) != SG_OK ||
      strong_result.verdict != SG_VERDICT_DENY ||
      strong_result.subcommand_count != 1 ||
      strong_result.subcommands[0].verdict != SG_VERDICT_DENY ||
      !strong_result.deny_reason ||
      std::strcmp(strong_result.deny_reason, redirect_reason) == 0)
    invariant_failure("redirect-only verdict priority mismatch");
  sg_gate_free(strong_redirect_gate);

  /* Semantic graph context, not a second source-only check, proves these
   * read-option roles. Keep the cold/warm anomaly paths in the fixed sweep. */
  sg_gate_t *read_gate = sg_gate_new();
  if (!read_gate || sg_gate_set_reject_mask(read_gate, 0) != SG_OK ||
      sg_gate_set_stop_mode(read_gate, SG_EVAL_ALL) != SG_OK ||
      sg_gate_enable_anomaly(read_gate, 1e300, nullptr) != SG_OK ||
      sg_gate_set_anomaly_cache_size(read_gate, 8) != SG_OK)
    invariant_failure("contextual read anomaly oracle setup failed");
  for (const char *input :
       {"exec {fd}<<<payload && read -p\"$fd\" -u \"$fd\" value",
        "exec {fd}<<<payload && echo \"$(read -p\"$fd\" -u \"$fd\" value)\""}) {
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, std::strlen(input));
    uint32_t count = std::strstr(input, "echo") ? 3 : 2;
    for (unsigned repeat = 0; repeat < 2; repeat++) {
      sg_result_t result = {};
      sg_error_t error =
          sg_gate_evaluate(read_gate, input, std::strlen(input), buffer.data(),
                           buffer.size(), &result);
      if (error != SG_OK || result.verdict != SG_VERDICT_UNDETERMINED ||
          result.subcommand_count != count || result.truncated ||
          !isfinite(result.anomaly_score))
        invariant_failure("contextual read anomaly oracle mismatch");
      validate_result(&result, error, buffer.data(), buffer.size());
    }
  }
  sg_gate_free(read_gate);
}

/* Graph paths preserve source spelling, so quote and escape fragments must not
 * evade literal path rules. Exercise the allocation-free decoded-word scans
 * through the public violation result rather than duplicating their lexer. */
void run_decoded_path_oracles() {
  struct oracle_case {
    const char *input;
    uint32_t expected_flag;
    bool expected;
  };
  static const oracle_case cases[] = {
      {"cat ~/.s\"sh\"/id_rsa", SG_VIOL_READ_SECRETS, true},
      {"cat ~/.s\\sh/id_rsa", SG_VIOL_READ_SECRETS, true},
      {"echo payload >> ~/.b\"ashrc\"", SG_VIOL_PERSISTENCE, true},
      {"echo payload >> ~/.b\\ashrc", SG_VIOL_PERSISTENCE, true},
      {"printf x >/etc/replaced >/tmp/out", SG_VIOL_WRITE_SENSITIVE, true},
      {"echo payload >> ~/.bashrc >/tmp/out", SG_VIOL_PERSISTENCE, true},
      {"cat ~/.s\"sh-backup\"/id_rsa", SG_VIOL_READ_SECRETS, false},
      {"echo payload >> ~/.b\"ash-profile\"", SG_VIOL_PERSISTENCE, false},
  };

  sg_gate_t *gate = sg_gate_new();
  if (!gate || sg_gate_set_reject_mask(gate, 0) != SG_OK ||
      sg_gate_set_stop_mode(gate, SG_EVAL_ALL) != SG_OK ||
      test_policy_replace_cpl(gate, false, "cat *", false) != ST_OK ||
      test_policy_replace_cpl(gate, false, "echo *", false) != ST_OK ||
      test_policy_replace_cpl(gate, false, "printf *", false) != ST_OK)
    invariant_failure("decoded path oracle gate setup failed");
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  if (sg_gate_set_violation_config_borrowed(gate, &config) != SG_OK)
    invariant_failure("decoded path oracle configuration failed");

  for (const oracle_case &item : cases) {
    reusable_eval_buffer &buffer =
        eval_buffer_for(g_eval_buffers.result, std::strlen(item.input));
    sg_result_t result = {};
    sg_error_t error =
        sg_gate_evaluate(gate, item.input, std::strlen(item.input),
                         buffer.data(), buffer.size(), &result);
    if (error != SG_OK ||
        (!!(result.violation_type_flags & item.expected_flag) != item.expected))
      invariant_failure("decoded path oracle violation mismatch");
    validate_result(&result, error, buffer.data(), buffer.size());
  }

  static const char dynamic_setup[] =
      "{ printf x; } >\"$(cat /etc/shadow)\" >/tmp/out";
  reusable_eval_buffer &dynamic_buffer =
      eval_buffer_for(g_eval_buffers.result, sizeof(dynamic_setup) - 1);
  sg_result_t dynamic_result = {};
  sg_error_t dynamic_error = sg_gate_evaluate(
      gate, dynamic_setup, sizeof(dynamic_setup) - 1, dynamic_buffer.data(),
      dynamic_buffer.size(), &dynamic_result);
  bool dynamic_owner = false;
  for (uint32_t i = 0; i < dynamic_result.subcommand_count; i++)
    dynamic_owner |=
        dynamic_result.subcommands[i].has_dynamic_substitution_io &&
        (dynamic_result.subcommands[i].violation_type_flags &
         SG_VIOL_SUBST_SENSITIVE) != 0;
  if (dynamic_error != SG_OK || !dynamic_result.has_dynamic_substitution_io ||
      dynamic_result.requires_substitution_evaluation ||
      !(dynamic_result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE) ||
      !dynamic_owner) {
    invariant_failure("FD_OPEN dynamic-path oracle mismatch");
  }
  sg_gate_free(gate);
}

void run_brace_group_oracles() {
  static const char *const rules[] = {"echo *", "cat", "printf *"};
  const char *input =
      "{ { echo one; } | cat; printf two; } > /tmp/nested-brace.out";
  const char *sibling_input =
      "{ printf left; } 3>/tmp/left | { cat; } 2>>/tmp/right && "
      "{ printf tail; }";
  const char *document_input = "{ printf one; cat; } <<'EOF'\n}\nEOF";
  const char *crlf_document_input =
      "{ printf one; cat; } <<'EOF'\r\n}\r\nEOF\r\n";
  const char *named_document_input = "printf x {fd}<<<body";
  const char *named_group_document_input = "{ cat; } {fd}<<EOF\nbody\nEOF\n";
  sg_gate_t *gate = sg_gate_new();
  if (!gate || sg_gate_set_reject_mask(gate, 0) != SG_OK ||
      sg_gate_set_stop_mode(gate, SG_EVAL_ALL) != SG_OK)
    invariant_failure("brace oracle gate setup failed");
  for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++)
    if (test_policy_replace_cpl(gate, false, rules[i], false) != ST_OK)
      invariant_failure("brace oracle rule setup failed");
  size_t maximum_input_length =
      std::max({std::strlen(input), std::strlen(sibling_input),
                std::strlen(document_input), std::strlen(crlf_document_input),
                std::strlen(named_document_input),
                std::strlen(named_group_document_input)});
  reusable_eval_buffer &buffer =
      eval_buffer_for(g_eval_buffers.result, maximum_input_length);
  sg_result_t result = {};
  sg_error_t error = sg_gate_evaluate(gate, input, std::strlen(input),
                                      buffer.data(), buffer.size(), &result);
  if (error != SG_OK || result.verdict != SG_VERDICT_ALLOW ||
      result.subcommand_count != 3 ||
      std::strcmp(result.subcommands[0].netargv, "4:echo,3:one,") != 0 ||
      std::strcmp(result.subcommands[1].netargv, "3:cat,") != 0 ||
      std::strcmp(result.subcommands[2].netargv, "6:printf,3:two,") != 0)
    invariant_failure("brace oracle result mismatch");

  memset(&result, 0, sizeof(result));
  error = sg_gate_evaluate(gate, sibling_input, std::strlen(sibling_input),
                           buffer.data(), buffer.size(), &result);
  if (error != SG_OK || result.verdict != SG_VERDICT_ALLOW ||
      result.subcommand_count != 3 ||
      std::strcmp(result.subcommands[0].netargv, "6:printf,4:left,") != 0 ||
      std::strcmp(result.subcommands[1].netargv, "3:cat,") != 0 ||
      std::strcmp(result.subcommands[2].netargv, "6:printf,4:tail,") != 0)
    invariant_failure("brace sibling pipeline oracle result mismatch");

  memset(&result, 0, sizeof(result));
  error = sg_gate_evaluate(gate, document_input, std::strlen(document_input),
                           buffer.data(), buffer.size(), &result);
  if (error != SG_OK || result.verdict != SG_VERDICT_ALLOW ||
      result.subcommand_count != 2 ||
      std::strcmp(result.subcommands[0].netargv, "6:printf,3:one,") != 0 ||
      std::strcmp(result.subcommands[1].netargv, "3:cat,") != 0)
    invariant_failure("brace document oracle result mismatch");

  memset(&result, 0, sizeof(result));
  error = sg_gate_evaluate(gate, crlf_document_input,
                           std::strlen(crlf_document_input), buffer.data(),
                           buffer.size(), &result);
  if (error != SG_OK || result.verdict != SG_VERDICT_ALLOW ||
      result.subcommand_count != 2 ||
      std::strcmp(result.subcommands[0].netargv, "6:printf,3:one,") != 0 ||
      std::strcmp(result.subcommands[1].netargv, "3:cat,") != 0)
    invariant_failure("brace CRLF document oracle result mismatch");

  memset(&result, 0, sizeof(result));
  error = sg_gate_evaluate(gate, named_document_input,
                           std::strlen(named_document_input), buffer.data(),
                           buffer.size(), &result);
  if (error != SG_OK || result.verdict != SG_VERDICT_ALLOW ||
      result.subcommand_count != 1 ||
      std::strcmp(result.subcommands[0].netargv, "6:printf,1:x,") != 0)
    invariant_failure("named document oracle result mismatch");

  memset(&result, 0, sizeof(result));
  error = sg_gate_evaluate(gate, named_group_document_input,
                           std::strlen(named_group_document_input),
                           buffer.data(), buffer.size(), &result);
  if (error != SG_OK || result.verdict != SG_VERDICT_ALLOW ||
      result.subcommand_count != 1 ||
      std::strcmp(result.subcommands[0].netargv, "3:cat,") != 0)
    invariant_failure("named group document oracle result mismatch");
  sg_gate_free(gate);
}

void run_generated_brace_case(const uint8_t *data, size_t size) {
  shell_brace_fuzz_case_t item = shell_brace_fuzz_case(data, size);
  sg_gate_t *gate = sg_gate_new();
  if (!gate || sg_gate_set_reject_mask(gate, 0) != SG_OK ||
      sg_gate_set_stop_mode(gate, SG_EVAL_ALL) != SG_OK)
    invariant_failure("generated brace gate setup failed");
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/tmp/brace-sensitive";
  config.sensitive_write_path_count = 1;
  if (sg_gate_set_violation_config_borrowed(gate, &config) != SG_OK)
    invariant_failure("generated brace violation setup failed");

  reusable_eval_buffer &buffer =
      eval_buffer_for(g_eval_buffers.result, item.command.size());
  sg_result_t result = {};
  sg_error_t error =
      sg_gate_evaluate(gate, item.command.data(), item.command.size(),
                       buffer.data(), buffer.size(), &result);
  if (!item.valid || !item.strict_valid) {
    if (error != SG_ERR_PARSE)
      invariant_failure("strict generated brace input was accepted");
    sg_gate_free(gate);
    return;
  }
  if (error != SG_OK || result.subcommand_count != item.command_count ||
      result.subcommand_count > SHELL_MAX_SUBCOMMANDS)
    invariant_failure(
        "generated brace result is outside bounded command limits");
  validate_result(&result, error, buffer.data(), buffer.size());
  /* Inspect group ownership in its owning component. Reuse bounded scratch
   * rather than quarantining a fresh graph workspace on every fuzz input. */
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  size_t workspace_size;
  if (!shell_dep_workspace_size(&limits, &workspace_size))
    invariant_failure("generated brace graph workspace sizing failed");
  size_t alignment = shell_dep_workspace_alignment();
  static std::vector<char> workspace;
  workspace.resize(workspace_size + alignment - 1);
  uintptr_t address = reinterpret_cast<uintptr_t>(workspace.data());
  limits.workspace = reinterpret_cast<void *>(
      address + (alignment - address % alignment) % alignment);
  limits.workspace_size = workspace_size;
  shell_dep_graph_t graph;
  if (shell_dep_graph_parse(item.command.data(), item.command.size(), nullptr,
                            &limits, &graph) != SHELL_DEP_OK)
    invariant_failure("generated brace graph parse failed");
  uint32_t command_nodes[SHELL_MAX_SUBCOMMANDS];
  uint32_t command_count = 0;
  for (uint32_t i = 0; i < graph.node_count; i++) {
    if (graph.nodes[i].type != SHELL_NODE_CMD ||
        graph.nodes[i].cmd.token_count == 0)
      continue;
    if (command_count == SHELL_MAX_SUBCOMMANDS)
      invariant_failure("generated brace graph command limit exceeded");
    command_nodes[command_count++] = i;
  }
  if (command_count != result.subcommand_count)
    invariant_failure("generated brace graph/result command count mismatch");
  bool saw_group = false;
  for (uint32_t i = 0; i < result.subcommand_count; i++)
    saw_group = saw_group || graph.nodes[command_nodes[i]].cmd.group_depth != 0;
  if (!saw_group)
    invariant_failure("generated brace result lost group metadata");
  const bool uniform_group_io = !item.has_background_sibling &&
                                !item.heterogeneous_group_io &&
                                !item.command_local_documents;
  if (!item.has_background_sibling && !item.heterogeneous_group_io) {
    uint32_t group_commands_checked = 0;
    for (uint32_t i = 0; i < result.subcommand_count; i++) {
      const sg_subcommand_result_t *command = &result.subcommands[i];
      uint16_t depth = graph.nodes[command_nodes[i]].cmd.group_depth;
      if (depth == 0)
        continue;
      uint32_t nested_layers = depth - 1;
      uint32_t expected_writes =
          item.base_write_count +
          nested_layers * item.nested_write_count_per_layer;
      if (uniform_group_io &&
          (command->read_count != item.base_read_count ||
           command->write_count != expected_writes ||
           (!!(command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) !=
            item.sensitive_write))) {
        fprintf(stderr,
                "generated brace I/O: %s\ncommand %u depth %u: read %u/%u "
                "write %u/%u sensitive %u/%u\n",
                item.command.c_str(), i, depth, command->read_count,
                item.base_read_count, command->write_count, expected_writes,
                !!(command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE),
                item.sensitive_write);
        invariant_failure("generated brace inherited I/O context mismatch");
      }
      group_commands_checked++;
    }
    if (group_commands_checked != item.group_command_count)
      invariant_failure("generated brace group membership mismatch");
  }
  uint16_t deepest_group = 0;
  for (uint32_t i = 0; i < result.subcommand_count; i++)
    if (graph.nodes[command_nodes[i]].cmd.group_depth > deepest_group)
      deepest_group = graph.nodes[command_nodes[i]].cmd.group_depth;
  uint32_t group_commands_checked = 0;
  for (uint32_t i = 0; i < result.subcommand_count; i++) {
    const sg_subcommand_result_t *command = &result.subcommands[i];
    if (graph.nodes[command_nodes[i]].cmd.group_depth != deepest_group)
      continue;
    if (uniform_group_io &&
        (command->read_count != item.read_count ||
         command->write_count != item.write_count ||
         (!!(command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) !=
          item.sensitive_write)))
      invariant_failure("generated brace group I/O context mismatch");
    group_commands_checked++;
  }
  /* A top-level background sibling can share depth one with the generated
   * group. Its I/O intentionally differs, so leave that ambiguous shape to
   * the dedicated composition checks; every other generated deepest group is
   * checked in full. */
  if (item.heterogeneous_group_io &&
      group_commands_checked != item.group_command_count)
    invariant_failure("generated brace group membership mismatch");
  if (item.has_background_sibling && item.group_count > 2 &&
      group_commands_checked != item.deepest_command_count)
    invariant_failure("generated brace group membership mismatch");
  if ((!!(result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) !=
       item.sensitive_write))
    invariant_failure("generated brace violation propagation mismatch");
  sg_gate_free(gate);
}

/* Exercise Shellgate's verdict and dynamic-byte flags. Exact source/consumer
 * relations remain a Shellsplit graph contract, not a result projection. */
void run_substitution_case(const shell_substitution_fuzz_case_t &item) {
  static const char *const rules[] = {
      "echo *", "sleep *",   "printf *", "printf * *", "./clock", "cat",
      "cat *",  "cat #path", "date",     "id",         "pwd",     "sort",
      "sort *", "sh",        "sh *",     "exec",       "probe",   "true"};
  sg_gate_t *gate = sg_gate_new();
  if (!gate || sg_gate_set_reject_mask(gate, 0) != SG_OK ||
      sg_gate_set_stop_mode(gate, SG_EVAL_ALL) != SG_OK)
    invariant_failure("generated substitution gate setup failed");
  for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++)
    if (test_policy_replace_cpl(gate, false, rules[i], false) != ST_OK)
      invariant_failure("generated substitution rule setup failed");

  reusable_eval_buffer &buffer =
      eval_buffer_for(g_eval_buffers.result, item.command.size());
  sg_result_t result = {};
  sg_error_t error =
      sg_gate_evaluate(gate, item.command.data(), item.command.size(),
                       buffer.data(), buffer.size(), &result);
  if (item.source_rejected) {
    if (error != SG_ERR_PARSE || result.verdict != SG_VERDICT_REJECT)
      invariant_failure("generated unsafe ANSI source was not rejected");
    validate_result(&result, error, buffer.data(), buffer.size());
    sg_gate_free(gate);
    return;
  }
  if (item.depgraph_rejected) {
    if (error != SG_ERR_PARSE || result.verdict != SG_VERDICT_REJECT)
      invariant_failure("generated substitution rejection contract mismatch");
    validate_result(&result, error, buffer.data(), buffer.size());
    sg_gate_free(gate);
    return;
  }
  if (item.depgraph_truncated) {
    if (error != SG_ERR_TRUNC || !result.truncated ||
        result.verdict == SG_VERDICT_ALLOW ||
        result.verdict == SG_VERDICT_ALLOW_CONDITIONAL)
      invariant_failure("generated substitution truncation contract mismatch");
    validate_result(&result, error, buffer.data(), buffer.size());
    sg_gate_free(gate);
    return;
  }
  uint32_t dynamic_consumers = 0;
  uint32_t shell_word_consumers = 0;
  for (uint32_t i = 0; i < result.subcommand_count; i++) {
    const sg_subcommand_result_t *subcommand = &result.subcommands[i];
    dynamic_consumers += subcommand->has_dynamic_substitution_io;
    shell_word_consumers += subcommand->requires_substitution_evaluation;
  }
  sg_verdict_t expected_verdict = item.requires_substitution_evaluation
                                      ? SG_VERDICT_ALLOW_CONDITIONAL
                                      : SG_VERDICT_ALLOW;
  if (error != SG_OK || result.verdict != expected_verdict ||
      result.subcommand_count != item.command_count ||
      result.requires_substitution_evaluation !=
          item.requires_substitution_evaluation ||
      result.has_dynamic_substitution_io !=
          (item.substitution_edge_count != 0) ||
      dynamic_consumers != item.result_dynamic_consumer_count) {
    fprintf(stderr,
            "generated substitution result mismatch: %s (error=%d "
            "verdict=%d/%d commands=%u/%u shell-word=%d/%d dynamic=%d/%d "
            "consumers=%u/%u shell-word-consumers=%u)\n",
            item.command.c_str(), error, result.verdict, expected_verdict,
            result.subcommand_count, item.command_count,
            result.requires_substitution_evaluation,
            item.requires_substitution_evaluation,
            result.has_dynamic_substitution_io,
            item.substitution_edge_count != 0, dynamic_consumers,
            item.result_dynamic_consumer_count, shell_word_consumers);
    invariant_failure("generated substitution result contract mismatch");
  }
  validate_result(&result, error, buffer.data(), buffer.size());
  sg_gate_free(gate);
}

void run_generated_substitution_case(const uint8_t *data, size_t size) {
  run_substitution_case(shell_brace_fuzz_substitution_case(data, size));
}

void run_composed_substitution_case(const uint8_t *data, size_t size) {
  run_substitution_case(
      shell_brace_fuzz_composed_substitution_case(data, size));
}

void run_composed_substitution_matrix() {
  uint8_t data[7] = {};
  for (uint8_t form = 0; form < 6; form++) {
    uint8_t pipeline_count = form == 5 ? 1 : 2;
    uint8_t literal_count = form == 5 ? 2 : 1;
    for (uint8_t depth = 0; depth < 3; depth++) {
      for (uint8_t pipeline = 0; pipeline < pipeline_count; pipeline++) {
        for (uint8_t literal = 0; literal < literal_count; literal++) {
          for (uint8_t group_mask = 0; group_mask < (1u << (depth + 1));
               group_mask++) {
            data[0] = form;
            data[1] = depth;
            data[2] = pipeline;
            data[3] = literal;
            for (uint8_t level = 0; level <= depth; level++)
              data[4 + level] =
                  ((group_mask >> level) & 1u) | ((form & 1u) ? 2u : 0u);
            run_composed_substitution_case(data, sizeof(data));
          }
        }
      }
    }
  }
}

void validate_gate_pair(sg_gate_t *left, sg_gate_t *right) {
  if (st_policy_rule_count(sg_gate_allow_policy_borrowed(left)) !=
          st_policy_rule_count(sg_gate_allow_policy_borrowed(right)) ||
      st_policy_rule_count(sg_gate_deny_policy_borrowed(left)) !=
          st_policy_rule_count(sg_gate_deny_policy_borrowed(right)) ||
      test_anomaly_vocabulary(left) != test_anomaly_vocabulary(right) ||
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
    int a = 0, b = 0;
    switch (operation) {
    case 0: {
      const char *rule = rules[fdp.ConsumeIntegral<uint8_t>() % 7];
      a = test_policy_replace_cpl(left, false, rule, false);
      b = test_policy_replace_cpl(right, false, rule, false);
      break;
    }
    case 1: {
      const char *rule = rules[fdp.ConsumeIntegral<uint8_t>() % 7];
      a = test_policy_replace_cpl(left, false, rule, true);
      b = test_policy_replace_cpl(right, false, rule, true);
      break;
    }
    case 2: {
      const char *rule = rules[fdp.ConsumeIntegral<uint8_t>() % 7];
      a = test_policy_replace_cpl(left, true, rule, false);
      b = test_policy_replace_cpl(right, true, rule, false);
      break;
    }
    case 3: {
      const char *rule = rules[fdp.ConsumeIntegral<uint8_t>() % 7];
      a = test_policy_replace_cpl(left, true, rule, true);
      b = test_policy_replace_cpl(right, true, rule, true);
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
      a = sg_gate_enable_anomaly(left, 5.0, NULL);
      b = sg_gate_enable_anomaly(right, 5.0, NULL);
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
      reusable_eval_buffer &left_buffer =
          eval_buffer_for(g_eval_buffers.result, command.size());
      reusable_eval_buffer &right_buffer =
          eval_buffer_for(g_eval_buffers.replay, command.size());
      sg_result_t left_result = {}, right_result = {};
      a = sg_gate_evaluate(left, command.c_str(), command.size(),
                           left_buffer.data(), left_buffer.size(),
                           &left_result);
      b = sg_gate_evaluate(right, command.c_str(), command.size(),
                           right_buffer.data(), right_buffer.size(),
                           &right_result);
      validate_result(&left_result, static_cast<sg_error_t>(a),
                      left_buffer.data(), left_buffer.size());
      validate_result(&right_result, static_cast<sg_error_t>(b),
                      right_buffer.data(), right_buffer.size());
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
  if (sg_gate_enable_anomaly(g, 5.0, NULL) != SG_OK)
    invariant_failure("sg_gate_enable_anomaly failed");

  reusable_eval_buffer &train_buf = eval_buffer_for(g_eval_buffers.result, 128);
  sg_result_t training_result;
  for (int i = 0; i < kSeedCmdsN; i++) {
    if (sg_gate_evaluate(g, kSeedCmds[i], strlen(kSeedCmds[i]),
                         train_buf.data(), train_buf.size(),
                         &training_result) != SG_OK)
      invariant_failure("anomaly model training failed");
  }
  if (sg_gate_set_anomaly_update_mode(g, true) != SG_OK)
    invariant_failure("sg_gate_set_anomaly_update_mode failed");

  int nrules = idx % 4;
  for (int j = 0; j < nrules; j++) {
    const char *p = kDenyRules[(idx * 3 + j * 7) % kDenyRulesN];
    test_policy_replace_cpl(g, true, p, false);
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
    if (test_policy_replace_cpl(gate, false,
                                allow_rules[(idx * 3 + i) % allow_count],
                                false) != ST_OK)
      invariant_failure("allow-rule setup failed");
  /* Pool zero deliberately permits both sides of a substitution so the
   * conditional verdict is reachable. */
  if (idx == 0) {
    if (test_policy_replace_cpl(gate, false, "echo *", false) != ST_OK ||
        test_policy_replace_cpl(gate, false, "whoami", false) != ST_OK)
      invariant_failure("conditional policy setup failed");
  } else {
    for (int i = 0; i < 2; i++)
      if (test_policy_replace_cpl(gate, true,
                                  deny_rules[(idx * 2 + i) % deny_count],
                                  false) != ST_OK)
        invariant_failure("deny-rule setup failed");
  }
  return gate;
}

void cleanup() {
  sg_gate_free(g_expansion_gate);
  g_expansion_gate = nullptr;
  for (int i = 0; i < kPoolSize; i++) {
    sg_gate_free(g_anomaly_pool[i]);
    sg_gate_free(g_policy_pool[i]);
    g_anomaly_pool[i] = nullptr;
    g_policy_pool[i] = nullptr;
  }
}

} // namespace

static void run_fixed_oracles();

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;

  for (int i = 0; i < kPoolSize; i++)
    g_anomaly_pool[i] = create_pool_gate(i);
  for (int i = 0; i < kPoolSize; i++)
    g_policy_pool[i] = create_policy_gate(i);
  g_expansion_gate = sg_gate_new();
  if (!g_expansion_gate ||
      sg_gate_set_reject_mask(g_expansion_gate, 0) != SG_OK ||
      sg_gate_set_suggestions(g_expansion_gate, false) != SG_OK ||
      test_policy_replace_cpl(g_expansion_gate, false, "echo ok", false) !=
          ST_OK)
    invariant_failure("generated expansion gate setup failed");

  atexit(cleanup);
  run_fixed_oracles();
  return 0;
}

/* Fixed sweeps belong to startup, not one fuzz input's timeout budget. */
static void run_fixed_oracles() {
  run_expansion_query_oracles();
  for (uint8_t shape = 0; shape < 7; shape++)
    for (uint8_t mode = 0; mode < 8; mode++) {
      /* FuzzedDataProvider consumes integral choices from the tail. Keep
       * every shape/outcome reachable in the deterministic startup pass. */
      const uint8_t expansion_case[] = {128, mode, mode, mode, 0, shape};
      run_generated_expansion_case(expansion_case, sizeof(expansion_case));
    }
  for (uint8_t shape = 1; shape < 5; shape++) {
    const uint8_t mixed_path_case[] = {0, 1, 0, 0, 0, 3, shape};
    run_generated_expansion_case(mixed_path_case, sizeof(mixed_path_case));
  }
  run_evaluation_buffer_contract_oracle();
  run_semantic_reference_oracles();
  run_decoded_path_oracles();
  run_brace_group_oracles();
  for (uint8_t selector = 0;
       selector < SHELL_BRACE_FUZZ_SUBSTITUTION_CASE_COUNT; selector++)
    run_generated_substitution_case(&selector, 1);
  for (uint8_t selector = 0;
       selector < SHELL_BRACE_FUZZ_COMPOSED_SUBSTITUTION_CASE_COUNT; selector++)
    run_composed_substitution_case(&selector, 1);
  run_composed_substitution_matrix();
  static const uint8_t background_group_io_case[] = {
      0, 27, 99, 100, 32, 47, 57, 116,
  };
  run_generated_brace_case(background_group_io_case,
                           sizeof(background_group_io_case));
  /* Keep heredoc-plus-pipeline generation deterministic. Byte three once made
   * the shared generator mistake CRLF for a shell newline and label an
   * unterminated heredoc valid. */
  static const uint8_t heredoc_pipeline_group_case[] = {0, 1, 2, 1, 1,
                                                        2, 7, 1, 1};
  run_generated_brace_case(heredoc_pipeline_group_case,
                           sizeof(heredoc_pipeline_group_case));
  for (uint8_t depth = 0; depth < 8; depth++)
    for (uint8_t composition = 0; composition < 6; composition++) {
      const uint8_t diagnostic_group_case[] = {0,           1, 2, 0, depth,
                                               composition, 1, 0, 1};
      run_generated_brace_case(diagnostic_group_case,
                               sizeof(diagnostic_group_case));
    }
  /* Keep the shared generated invalid/strict-only matrix deterministic.
   * Byte four selects these forms when byte zero is seven. */
  for (uint8_t selector = 0; selector < 12; selector++) {
    const uint8_t invalid_case[] = {7, 0, 0, 0, selector};
    run_generated_brace_case(invalid_case, sizeof(invalid_case));
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0)
    return 0;

  /* The fixed oracle pass exhausts every generated case. Select one matrix
   * for each fuzzed payload so the random-input path remains economical. */
  switch (data[0] % 4) {
  case 0:
    run_generated_brace_case(data, size);
    break;
  case 1:
    run_generated_substitution_case(data, size);
    break;
  case 2:
    run_composed_substitution_case(data, size);
    break;
  default:
    run_generated_expansion_case(data, size);
    break;
  }

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
  size_t result_prefix = 16 + (size_t)((uint32_t)raw * 16368u / 65535u);

  std::string cmd = fdp.ConsumeRemainingBytesAsString();
  if (cmd.empty())
    return 0;

  /* sg_gate_evaluate accepts a bounded span, but rejects embedded NUL bytes.
   * Map them to spaces so arbitrary fuzzer data stays within that contract. */
  for (char &c : cmd) {
    if (c == 0)
      c = ' ';
  }

  size_t buf_size = eval_buffer_size(cmd.size(), result_prefix);
  if (buf_size == 0)
    return 0;
  char *result_buf = g_eval_buffers.result.reset(buf_size);
  char *replay_buf = g_eval_buffers.replay.reset(buf_size);

  sg_gate_t *g =
      anomaly_mode ? g_anomaly_pool[pool_idx] : g_policy_pool[pool_idx];
  sg_result_t result, replay;

  sg_error_t err = sg_gate_evaluate(g, cmd.data(), cmd.size(), result_buf,
                                    buf_size, &result);
  /* Arbitrary bytes routinely form malformed shell syntax. Parse errors are
   * expected outcomes of the public evaluator, not harness failures. */
  if (err != SG_OK && err != SG_ERR_PARSE && err != SG_ERR_TRUNC &&
      err != SG_ERR_MEMORY)
    invariant_failure("unexpected sg_gate_evaluate error");
  if (err == SG_ERR_MEMORY)
    return 0;

  if (!isfinite(result.anomaly_score) || !isfinite(result.anomaly_score_raw) ||
      !isfinite(result.anomaly_score_type))
    invariant_failure("non-finite anomaly score with a trained model");

  validate_result(&result, err, result_buf, buf_size);
  validate_graph_result_prefix(&result, err, result_buf, buf_size, cmd.size());

  sg_error_t replay_err = sg_gate_evaluate(g, cmd.data(), cmd.size(),
                                           replay_buf, buf_size, &replay);
  if (replay_err != err || !results_equal(result, replay))
    invariant_failure("frozen-model replay was not deterministic");
  validate_result(&replay, replay_err, replay_buf, buf_size);
  validate_graph_result_prefix(&replay, replay_err, replay_buf, buf_size,
                               cmd.size());

  if (err == SG_OK || err == SG_ERR_TRUNC) {
    size_t large_size = eval_buffer_size(cmd.size(), SG_DIAGNOSTIC_BUF_MIN);
    if (large_size == 0)
      return 0;
    if (large_size < buf_size)
      large_size = buf_size;
    char *large_buf = g_eval_buffers.large.reset(large_size);
    sg_result_t large = {};
    sg_error_t large_err = sg_gate_evaluate(g, cmd.data(), cmd.size(),
                                            large_buf, large_size, &large);
    validate_result(&large, large_err, large_buf, large_size);
    validate_graph_result_prefix(&large, large_err, large_buf, large_size,
                                 cmd.size());
    if (err == SG_ERR_TRUNC && large_err == SG_OK &&
        large.verdict != SG_VERDICT_REJECT)
      validate_known_graph_result_prefix(&result, err, result_buf, buf_size,
                                         cmd.size());
    if (err == SG_OK && (large_err != SG_OK || !results_equal(result, large))) {
      std::fprintf(
          stderr,
          "buffer mismatch: small=%zu large=%zu errors=%d/%d "
          "verdicts=%d/%d subcommands=%u/%u violations=%u/%u "
          "suggestions=%u/%u deny-suggestions=%u/%u\n",
          buf_size, large_size, static_cast<int>(err),
          static_cast<int>(large_err), static_cast<int>(result.verdict),
          static_cast<int>(large.verdict), result.subcommand_count,
          large.subcommand_count, result.violation_count, large.violation_count,
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
