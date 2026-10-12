#include "policy_ctx.h"
#include "shell_netstring.h"
#include "shelltype.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <vector>

static void require(bool condition) {
  if (!condition)
    std::abort();
}

struct NetargvVisitCheck {
  const st_token_array_t *tokens;
  size_t index;
};

static bool check_netargv_visit(const st_token_view_t *token, void *user_ctx) {
  auto *check = static_cast<NetargvVisitCheck *>(user_ctx);
  if (check->index >= check->tokens->count)
    return false;
  const st_token_t &owned = check->tokens->tokens[check->index++];
  return token->type == owned.type && token->text_length == owned.text_length &&
         std::memcmp(token->text, owned.text, token->text_length) == 0;
}

static st_netargv_view_t argv_view(const std::string &encoded) {
  return {encoded.data(), encoded.size()};
}

static st_netpattern_view_t pattern_view(const std::string &encoded) {
  return {encoded.data(), encoded.size()};
}

static void append_netarg(std::string &output, const char *data,
                          size_t length) {
  size_t record_length = 0;
  require(shell_netstring_encoded_length(length, &record_length) ==
          SHELL_NETSTRING_OK);
  size_t offset = output.size();
  output.resize(offset + record_length);
  require(shell_netstring_write(&output[offset], record_length, data, length,
                                nullptr) == SHELL_NETSTRING_OK);
}

/* Tabs delimit up to eight byte-oriented fields, including empty fields. NUL
 * is payload, not a terminator or delimiter. The final field retains any tabs
 * beyond the field bound. Learner operations share a stable command head so
 * mutations explore argument continuations rather than unrelated root words.
 */
static std::string fields_netargv(const std::string &input, bool learner_head) {
  std::string encoded;
  if (learner_head)
    append_netarg(encoded, "fuzz", 4);
  size_t start = 0;
  for (size_t field = 0; field < 8; field++) {
    size_t end = field == 7 ? std::string::npos : input.find('\t', start);
    if (end == std::string::npos) {
      append_netarg(encoded, input.data() + start, input.size() - start);
      break;
    }
    append_netarg(encoded, input.data() + start, end - start);
    start = end + 1;
  }
  return encoded;
}

static std::string canonical_pattern(const std::string &cpl) {
  st_netpattern_t encoded = {};
  if (st_netpattern_from_cpl_owned(cpl.c_str(), &encoded) != ST_OK)
    return {};
  std::string result(encoded.data, encoded.length);
  st_netpattern_free(&encoded);
  return result;
}

static void check_validation_detail_references() {
  static const size_t lengths[] = {125, 126, 255};
  for (size_t length : lengths) {
    for (unsigned binary = 0; binary < 2; binary++) {
      std::string prefix(length, 'p'), suffix(length, 's');
      if (binary) {
        prefix[0] = '\0';
        suffix[length - 1] = '\0';
      }
      st_token_t tokens[2] = {};
      tokens[0].text = "tool";
      tokens[0].type = ST_TYPE_LITERAL;
      tokens[1].text = "compound";
      tokens[1].type = ST_TYPE_LITERAL;
      tokens[1].compound = true;
      tokens[1].prefix = prefix.data();
      tokens[1].prefix_length = prefix.size();
      tokens[1].capture = "#n";
      tokens[1].capture_length = 2;
      tokens[1].capture_type = ST_TYPE_NUMBER;
      tokens[1].suffix = suffix.data();
      tokens[1].suffix_length = suffix.size();
      st_netpattern_t pattern = {}, roundtrip = {};
      require(st_netpattern_encode_owned(tokens, 2, &pattern) == ST_OK);
      st_netpattern_view_t view{pattern.data, pattern.length};
      st_token_array_t details = {};
      require(st_netpattern_validate_view(view, nullptr) == ST_OK);
      require(st_netpattern_validate_view(view, &details) == ST_OK);
      require(details.count == 2 && details.tokens[1].compound &&
              details.tokens[1].prefix_length == length &&
              details.tokens[1].suffix_length == length &&
              details.tokens[1].capture_type == ST_TYPE_NUMBER);
      require(st_netpattern_encode_owned(details.tokens, details.count,
                                         &roundtrip) == ST_OK);
      require(roundtrip.length == pattern.length &&
              std::memcmp(roundtrip.data, pattern.data, pattern.length) == 0);
      st_netpattern_free(&roundtrip);
      st_token_array_free(&details);
      st_netpattern_free(&pattern);
    }
  }
}

static void check_policy_command_grammar_references() {
  static const struct {
    const char *cpl;
    st_error_t expected;
  } cases[] = {
      {"cmd{#n} arg", ST_ERR_INVALID},
      {"{#n}cmd arg", ST_ERR_INVALID},
      {"pre{#n}post arg", ST_ERR_INVALID},
      {"pre{*} arg", ST_ERR_INVALID},
      {"* arg", ST_ERR_INVALID},
      {"cmd{#n} pre{*} arg", ST_ERR_INVALID},
      {"* pre{#n} arg", ST_ERR_INVALID},
      {"tool arg", ST_OK},
      {"#n arg", ST_OK},
      {"\"*\" arg", ST_OK},
      {"\"#n\" arg", ST_OK},
      {"\"pre{#n}\" arg", ST_OK},
      {"tool pre{#n}", ST_OK},
      {"tool {#n}post", ST_OK},
      {"tool pre{#n}post", ST_OK},
      {"tool pre{*}", ST_OK},
      {"tool *", ST_OK},
  };
  st_policy_ctx_t *context = st_policy_ctx_new();
  require(context != nullptr);
  std::string baseline = canonical_pattern("keep existing");
  require(!baseline.empty());
  for (const auto &reference : cases) {
    std::string pattern = canonical_pattern(reference.cpl);
    require(!pattern.empty());
    require(st_netpattern_validate_view(pattern_view(pattern), nullptr) ==
            reference.expected);
    st_token_array_t decoded = {};
    require(st_netpattern_decode_view(pattern_view(pattern), &decoded) ==
            ST_OK);
    for (size_t position = 0; position < decoded.count; position++) {
      for (unsigned type = ST_TYPE_LITERAL + 1; type < ST_TYPE_COUNT; type++) {
        st_error_t expected =
            (position == 0 ? !decoded.tokens[0].compound && type != ST_TYPE_ANY
                           : reference.expected == ST_OK)
                ? ST_OK
                : ST_ERR_INVALID;
        st_netpattern_t edited = {};
        require(st_netpattern_apply_type_at_owned(
                    pattern_view(pattern), position, (st_token_type_t)type,
                    &edited) == expected);
        if (expected == ST_OK) {
          require(st_netpattern_validate_view({edited.data, edited.length},
                                              nullptr) == ST_OK);
        } else {
          require(!edited.data && edited.length == 0);
        }
        st_netpattern_free(&edited);
      }
    }
    st_token_array_free(&decoded);
    for (unsigned populated = 0; populated < 2; populated++) {
      st_policy_t *policy = st_policy_new(context);
      require(policy != nullptr);
      if (populated)
        require(st_policy_add_netpattern_view(policy, pattern_view(baseline)) ==
                ST_OK);
      size_t before = st_policy_rule_count(policy);
      for (unsigned omit_conflict = 0; omit_conflict < 2; omit_conflict++) {
        bool covered = true;
        st_netpattern_view_t conflict = pattern_view(pattern);
        require(st_policy_simulate_add_netpattern_view(
                    policy, pattern_view(pattern), &covered,
                    omit_conflict ? nullptr : &conflict) == reference.expected);
        require(!covered &&
                (omit_conflict || (!conflict.data && conflict.length == 0)));
        require(st_policy_rule_count(policy) == before);
      }
      require(st_policy_add_netpattern_view(policy, pattern_view(pattern)) ==
              reference.expected);
      require(st_policy_rule_count(policy) ==
              before + (reference.expected == ST_OK));
      bool matches = false;
      require(st_policy_match_view(policy, argv_view("4:keep,8:existing,"),
                                   &matches) == ST_OK &&
              matches == (populated != 0));
      st_policy_free(policy);
    }
  }
  st_policy_ctx_release(context);
}

static bool same_pattern_token(const st_token_t &left,
                               const st_token_t &right) {
  if (left.type != right.type || left.compound != right.compound ||
      left.text_length != right.text_length ||
      std::memcmp(left.text, right.text, left.text_length) != 0)
    return false;
  return !left.compound ||
         (left.capture_type == right.capture_type &&
          left.prefix_length == right.prefix_length &&
          left.capture_length == right.capture_length &&
          left.suffix_length == right.suffix_length &&
          std::memcmp(left.prefix, right.prefix, left.prefix_length) == 0 &&
          std::memcmp(left.capture, right.capture, left.capture_length) == 0 &&
          std::memcmp(left.suffix, right.suffix, left.suffix_length) == 0);
}

/* pattern is a validated policy pattern, not classified command payloads.
 * Small fixtures must produce variants; oversized literal spellings or output
 * frames may legitimately fail atomically. Probe acceptance is established
 * against the original rule, never inferred from a token's display spelling.
 */
static size_t
check_policy_pattern_variants(st_policy_t *policy, const std::string &pattern,
                              const std::vector<std::string> &probes,
                              bool require_accepted = false) {
  st_token_array_t original = {};
  require(st_netpattern_decode_view(pattern_view(pattern), &original) == ST_OK);
  bool bounded = pattern.size() < ST_MAX_NETPATTERN_LEN / 2;
  std::string literal_input;
  for (size_t i = 0; i < original.count; i++) {
    const st_token_t &token = original.tokens[i];
    bounded = bounded && token.text_length < ST_MAX_TOKEN_LEN;
    append_netarg(literal_input, token.text, token.text_length);
  }
  st_expand_suggestion_t variants[3];
  std::memset(variants, 0xa5, sizeof(variants));
  size_t count = st_policy_suggest_variants(policy, original.tokens,
                                            original.count, variants);
  require(count <= 3 && (!bounded || count != 0));
  if (count == 0) {
    for (const auto &variant : variants)
      require(variant.pattern_length == 0 && variant.pattern[0] == '\0' &&
              variant.based_on == nullptr && variant.based_on_length == 0 &&
              variant.confidence == 0.0);
    st_token_array_free(&original);
    return 0;
  }

  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *base = context ? st_policy_new(context) : nullptr;
  require(base &&
          st_policy_add_netpattern_view(base, pattern_view(pattern)) == ST_OK);
  std::vector<bool> accepted;
  for (const std::string &probe : probes) {
    bool matches = false;
    require(st_policy_match_view(base, argv_view(probe), &matches) == ST_OK);
    require(!require_accepted || matches);
    accepted.push_back(matches);
  }
  for (size_t i = 0; i < count; i++) {
    st_netpattern_view_t view{variants[i].pattern, variants[i].pattern_length};
    require(st_netpattern_validate_view(view, nullptr) == ST_OK);
    st_token_array_t decoded = {};
    require(st_netpattern_decode_view(view, &decoded) == ST_OK);
    require(decoded.count == original.count);
    size_t changed = 0;
    for (size_t j = 0; j < original.count; j++) {
      const st_token_t &before = original.tokens[j];
      const st_token_t &after = decoded.tokens[j];
      if (i == 0) {
        require(!after.compound && after.type == ST_TYPE_LITERAL &&
                after.text_length == before.text_length &&
                std::memcmp(after.text, before.text, before.text_length) == 0);
      } else if (!same_pattern_token(before, after)) {
        changed++;
        require(before.compound == after.compound);
        st_token_type_t from =
            before.compound ? before.capture_type : before.type;
        st_token_type_t to = after.compound ? after.capture_type : after.type;
        require(from != ST_TYPE_LITERAL && from != to && to != ST_TYPE_ANY &&
                st_is_compatible(from, to));
        if (before.compound)
          require(before.prefix_length == after.prefix_length &&
                  before.suffix_length == after.suffix_length &&
                  std::memcmp(before.prefix, after.prefix,
                              before.prefix_length) == 0 &&
                  std::memcmp(before.suffix, after.suffix,
                              before.suffix_length) == 0);
      }
    }
    require(i == 0 || changed == 1);
    st_token_array_free(&decoded);
    st_policy_t *candidate = st_policy_new(context);
    require(candidate &&
            st_policy_add_netpattern_view(candidate, view) == ST_OK);
    bool matches = false;
    if (i == 0) {
      require(st_policy_match_view(candidate, argv_view(literal_input),
                                   &matches) == ST_OK &&
              matches);
    } else {
      for (size_t j = 0; j < probes.size(); j++) {
        if (accepted[j])
          require(st_policy_match_view(candidate, argv_view(probes[j]),
                                       &matches) == ST_OK &&
                  matches);
      }
    }
    st_policy_free(candidate);
  }
  st_policy_free(base);
  st_policy_ctx_release(context);
  st_token_array_free(&original);
  return count;
}

static void check_policy_variant_references() {
  static const struct {
    const char *cpl;
    std::string first, second;
    size_t count;
  } cases[] = {
      {"tool #n #n", "tool\t42\t43", "tool\t44\t45", 3},
      {"tool \"*\" #n", "tool\t*\t42", "tool\t*\t43", 2},
      {"grep \"#size.MiB\" #n", "grep\t#size.MiB\t42", "grep\t#size.MiB\t43",
       2},
      {"tool #size.MiB #n", "tool\t10MiB\t42", "tool\t20MiB\t43", 3},
      {"tool pre{#n}post #n", "tool\tpre42post\t43", "tool\tpre44post\t45", 3},
      {"tool \"a b\" #n", "tool\ta b\t42", "tool\ta b\t43", 2},
      {"tool \"\" #n", "tool\t\t42", "tool\t\t43", 2},
      {"tool \"a\\x00b\" #n",
       std::string("tool\ta\0b\t42", sizeof("tool\ta\0b\t42") - 1),
       std::string("tool\ta\0b\t43", sizeof("tool\ta\0b\t43") - 1), 2},
      {"tool \"pre\\x00\"{#n}\"\\x00post\" #n",
       std::string("tool\tpre\0"
                   "42\0post\t43",
                   sizeof("tool\tpre\0"
                          "42\0post\t43") -
                       1),
       std::string("tool\tpre\0"
                   "44\0post\t45",
                   sizeof("tool\tpre\0"
                          "44\0post\t45") -
                       1),
       3},
  };
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = context ? st_policy_new(context) : nullptr;
  require(policy != nullptr);
  for (const auto &reference : cases) {
    std::string pattern = canonical_pattern(reference.cpl);
    require(st_netpattern_validate_view(pattern_view(pattern), nullptr) ==
            ST_OK);
    require(
        check_policy_pattern_variants(policy, pattern,
                                      {fields_netargv(reference.first, false),
                                       fields_netargv(reference.second, false)},
                                      true) == reference.count);
  }
  st_policy_free(policy);
  st_policy_ctx_release(context);
}

static void check_eval_is_verified(st_policy_t *policy,
                                   st_netargv_view_t command) {
  st_eval_result_t result = {};
  if (st_policy_eval_view(policy, command, &result) != ST_OK)
    return;
  st_netpattern_view_t *matches = nullptr;
  size_t count = 0;
  if (st_policy_verify_all_view(policy, command, &matches, &count) != ST_OK)
    return;
  if (result.matches) {
    bool found = false;
    for (size_t i = 0; i < count; i++)
      found = found || (result.matching_pattern &&
                        result.matching_pattern_length == matches[i].length &&
                        std::memcmp(result.matching_pattern, matches[i].data,
                                    matches[i].length) == 0);
    require(found);
  } else {
    require(count == 0);
  }
  st_policy_matches_free(matches);
}

static bool netpattern_set_equal(const st_netpattern_t *left, size_t left_count,
                                 const st_netpattern_t *right,
                                 size_t right_count) {
  if (left_count != right_count)
    return false;
  for (size_t i = 0; i < left_count; i++) {
    bool found = false;
    for (size_t j = 0; j < right_count; j++)
      found = found ||
              (left[i].length == right[j].length &&
               std::memcmp(left[i].data, right[j].data, left[i].length) == 0);
    if (!found)
      return false;
  }
  return true;
}

static bool policies_equal(const st_policy_t *left, const st_policy_t *right) {
  st_policy_diff_t forward = {};
  st_policy_diff_t reverse = {};
  if (st_policy_diff(left, right, &forward) != ST_OK ||
      st_policy_diff(right, left, &reverse) != ST_OK) {
    st_policy_diff_free(&forward);
    st_policy_diff_free(&reverse);
    return false;
  }
  bool equal = forward.added_count == 0 && forward.removed_count == 0 &&
               reverse.added_count == 0 && reverse.removed_count == 0;
  st_policy_diff_free(&forward);
  st_policy_diff_free(&reverse);
  return equal;
}

static uint64_t input_hash(const uint8_t *data, size_t size) {
  uint64_t hash = UINT64_C(1469598103934665603);
  for (size_t i = 0; i < size; i++) {
    hash ^= data[i];
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

static void check_suggestions_replay(const st_suggestion_t *suggestions,
                                     size_t suggestion_count,
                                     const std::vector<std::string> &history) {
  for (size_t suggestion = 0; suggestion < suggestion_count; suggestion++) {
    require(suggestions != nullptr && suggestions[suggestion].pattern);
    st_netpattern_view_t pattern{suggestions[suggestion].pattern,
                                 suggestions[suggestion].pattern_length};
    require(st_netpattern_validate_view(pattern, nullptr) == ST_OK);
    require(suggestions[suggestion].confidence >= 0.0 &&
            suggestions[suggestion].confidence <= 1.0);
    st_policy_ctx_t *context = st_policy_ctx_new();
    st_policy_t *policy = context ? st_policy_new(context) : nullptr;
    require(policy && st_policy_add_netpattern_view(policy, pattern) == ST_OK);
    uint32_t matches = 0;
    for (const std::string &command : history) {
      st_eval_result_t result = {};
      require(st_policy_eval_view(policy, argv_view(command), &result) ==
              ST_OK);
      matches += result.matches ? 1u : 0u;
    }
    require(matches == suggestions[suggestion].count);
    st_policy_free(policy);
    st_policy_ctx_release(context);
  }
}

/* Fixed semantic references run once even for the initial empty fuzz input;
 * they are not dependent on mutations rediscovering meaningful trie prefixes.
 */
static void check_learner_variant_references() {
  static const struct {
    const char *cpl;
    size_t position;
    st_token_type_t types[3];
    size_t count;
  } cases[] = {
      {"missing pre{#p}post",
       1,
       {ST_TYPE_ABS_PATH, ST_TYPE_PATH, ST_TYPE_ANY},
       3},
      {"tool pre{#n}post", 1, {ST_TYPE_NUMBER, ST_TYPE_ANY}, 2},
      {"tool pre{#n}post #val", 2, {ST_TYPE_ABS_PATH, ST_TYPE_ANY}, 2},
      {"tool /tmp/a #val", 2, {ST_TYPE_NUMBER, ST_TYPE_ANY}, 2},
      {"tool * #val", 2, {ST_TYPE_NUMBER, ST_TYPE_ABS_PATH, ST_TYPE_ANY}, 3},
      {"tool #semver.major #val", 2, {ST_TYPE_NUMBER, ST_TYPE_ANY}, 2},
      {"tool #semver.minor #val", 2, {ST_TYPE_NUMBER, ST_TYPE_ANY}, 2},
      {"tool #semver.patch #val", 2, {ST_TYPE_NUMBER, ST_TYPE_ANY}, 2},
      {"tool #semver.* #val", 2, {ST_TYPE_NUMBER, ST_TYPE_ANY}, 2},
      {"tool #ts.datetime #val", 2, {ST_TYPE_NUMBER, ST_TYPE_ANY}, 2},
      {"tool \"pre\\x00\"{#n}\"\\x00post\" #val",
       2,
       {ST_TYPE_ABS_PATH, ST_TYPE_ANY},
       2},
  };
  st_learner_t *learner = st_learner_new(nullptr);
  require(learner != nullptr);
  require(st_learner_feed_netargv_view(
              learner,
              st_netargv_view_t{"4:tool,9:pre42post,6:/tmp/x,",
                                sizeof("4:tool,9:pre42post,6:/tmp/x,") - 1}) ==
          ST_OK);
  require(st_learner_feed_netargv_view(
              learner,
              st_netargv_view_t{"4:tool,6:/tmp/a,2:42,",
                                sizeof("4:tool,6:/tmp/a,2:42,") - 1}) == ST_OK);
  require(st_learner_feed_netargv_view(
              learner, st_netargv_view_t{"4:tool,5:1.2.3,2:42,",
                                         sizeof("4:tool,5:1.2.3,2:42,") - 1}) ==
          ST_OK);
  require(st_learner_feed_netargv_view(
              learner, st_netargv_view_t{"4:tool,5:2.7.1,2:42,",
                                         sizeof("4:tool,5:2.7.1,2:42,") - 1}) ==
          ST_OK);
  require(st_learner_feed_netargv_view(
              learner,
              st_netargv_view_t{"4:tool,20:2026-10-05t12:34:56Z,2:42,",
                                sizeof("4:tool,20:2026-10-05t12:34:56Z,2:42,") -
                                    1}) == ST_OK);
  static const char binary[] = "4:tool,11:pre\0"
                               "42\0post,6:/tmp/x,";
  require(st_learner_feed_netargv_view(learner, {binary, sizeof(binary) - 1}) ==
          ST_OK);
  for (const auto &reference : cases) {
    st_netpattern_t encoded = {};
    st_token_array_t decoded = {};
    require(st_netpattern_from_cpl_owned(reference.cpl, &encoded) == ST_OK);
    require(st_netpattern_decode_view({encoded.data, encoded.length},
                                      &decoded) == ST_OK);
    st_token_variant_t choices[ST_MAX_TOKEN_VARIANTS] = {};
    size_t count = st_learner_suggest_token_variants(
        learner, &decoded, reference.position, choices);
    if (count != reference.count)
      std::fprintf(stderr, "learner reference failed: %s (%zu choices)\n",
                   reference.cpl, count);
    require(count == reference.count);
    for (size_t i = 0; i < count; i++)
      require(choices[i].type == reference.types[i] &&
              strcmp(choices[i].type_symbol,
                     st_type_symbol[reference.types[i]]) == 0);
    st_token_array_free(&decoded);
    st_netpattern_free(&encoded);
  }
  st_learner_free(learner);
}

static void check_timestamp_suggestion_reference() {
  static const char input[] = "4:tool,20:2026-10-05t12:34:56Z,2:42,";
  st_learner_t *learner = st_learner_new(nullptr);
  require(learner != nullptr);
  std::vector<std::string> history;
  for (size_t i = 0; i < ST_DEFAULT_MIN_SUPPORT; i++) {
    require(st_learner_feed_netargv_view(
                learner, st_netargv_view_t{input, strlen(input)}) == ST_OK);
    history.emplace_back(input);
  }
  size_t count = 0;
  st_suggestion_t *suggestions = st_learner_suggest(learner, &count);
  require(suggestions != nullptr && count == 1 &&
          suggestions[0].count == ST_DEFAULT_MIN_SUPPORT);
  check_suggestions_replay(suggestions, count, history);
  st_suggestion_list_free(suggestions, count);
  st_learner_free(learner);
}

static void check_overlapping_suggestion_reference() {
  static const struct {
    const char *records[3];
    unsigned weights[3];
    const char *cpl;
    uint32_t support;
  } cases[] = {
      {{"4:tool,2:42,", "4:tool,8:a1b2c3d4,"}, {7, 3}, "tool #n", 10},
      {{"4:tool,2:42,2:43,", "4:tool,8:a1b2c3d4,8:e5f6a7b8,"},
       {7, 3},
       "tool #n #n",
       10},
      {{"4:tool,2:42,4:1MiB,", "4:tool,8:a1b2c3d4,4:2MiB,",
        "4:tool,8:a1b2c3d4,4:4GiB,"},
       {7, 3, 3},
       "tool #n #size",
       13},
  };
  for (const auto &reference : cases) {
    st_learner_config_t config{reference.support, 0.8,
                               ST_DEFAULT_MAX_SUGGESTIONS};
    st_learner_t *learner = st_learner_new(&config);
    require(learner != nullptr);
    std::vector<std::string> history;
    for (size_t i = 0; i < 3; i++)
      for (unsigned j = 0; j < reference.weights[i]; j++) {
        require(st_learner_feed_netargv_view(
                    learner, st_netargv_view_t{reference.records[i],
                                               strlen(reference.records[i])}) ==
                ST_OK);
        history.emplace_back(reference.records[i]);
      }
    size_t count = 0;
    st_suggestion_t *suggestions = st_learner_suggest(learner, &count);
    std::string expected = canonical_pattern(reference.cpl);
    bool found = false;
    for (size_t i = 0; i < count; i++)
      found |= suggestions[i].pattern_length == expected.size() &&
               std::memcmp(suggestions[i].pattern, expected.data(),
                           expected.size()) == 0 &&
               suggestions[i].count == reference.support &&
               suggestions[i].confidence == 1.0;
    require(found);
    check_suggestions_replay(suggestions, count, history);
    st_suggestion_list_free(suggestions, count);
    st_learner_free(learner);
  }
}

static void check_binary_classification_references() {
  static const char literal[] = "4:grep,3:a\0b,";
  static const char nul_only[] = "4:grep,1:\0,";
  static const char regex[] = "4:grep,3:a\0^,";
  static const char glob[] = "4:tool,3:*\0x,";
  static const char leading_nul[] = "4:tool,3:\0*x,";
  static const char blocked_glob[] = "4:tool,3:*\0|,";
  static const struct {
    st_netargv_view_t input;
    st_token_type_t type;
    const char *cpl;
    bool matches;
  } cases[] = {
      {{literal, sizeof(literal) - 1}, ST_TYPE_LITERAL, "grep #regex", false},
      {{nul_only, sizeof(nul_only) - 1}, ST_TYPE_LITERAL, "grep #regex", false},
      {{regex, sizeof(regex) - 1}, ST_TYPE_REGEX, "grep #regex", true},
      {{glob, sizeof(glob) - 1}, ST_TYPE_GLOB, "tool #glob", true},
      {{leading_nul, sizeof(leading_nul) - 1},
       ST_TYPE_GLOB,
       "tool #glob",
       true},
      {{blocked_glob, sizeof(blocked_glob) - 1},
       ST_TYPE_LITERAL,
       "tool #glob",
       false},
  };
  st_policy_ctx_t *context = st_policy_ctx_new();
  require(context != nullptr);
  for (const auto &reference : cases) {
    st_token_array_t classified = {};
    require(st_netargv_classify_view(reference.input, &classified) == ST_OK);
    require(classified.count == 2 &&
            classified.tokens[1].type == reference.type);
    st_netpattern_t pattern = {};
    st_policy_t *policy = st_policy_new(context);
    require(policy != nullptr);
    require(st_netpattern_from_cpl_owned(reference.cpl, &pattern) == ST_OK);
    require(st_policy_add_netpattern_view(
                policy, {pattern.data, pattern.length}) == ST_OK);
    bool matched = !reference.matches;
    require(st_policy_match_view(policy, reference.input, &matched) == ST_OK &&
            matched == reference.matches);
    st_policy_free(policy);
    st_netpattern_free(&pattern);
    st_token_array_free(&classified);
  }
  st_policy_ctx_release(context);
}

static void check_binary_continuation_references() {
  static const char binary[] = "\0x\t";
  static const char nested[] = "\t\0x\t";
  static const struct {
    std::string prefix;
    const char *wildcard;
    const char *compound;
  } cases[] = {
      {"\t", "fuzz \"\" *", "fuzz \"\" --limit={#n}"},
      {std::string(binary, sizeof(binary) - 1), "fuzz \"\\x00x\" *",
       "fuzz \"\\x00x\" --limit={#n}"},
      {std::string(nested, sizeof(nested) - 1), "fuzz \"\" \"\\x00x\" *",
       "fuzz \"\" \"\\x00x\" --limit={#n}"},
  };
  static const char *const alternatives[][2] = {{"alpha", "beta"},
                                                {"--limit=42", "--limit=43"}};
  for (const auto &reference : cases) {
    for (size_t kind = 0; kind < 2; kind++) {
      st_learner_config_t config{6, 0.8, ST_DEFAULT_MAX_SUGGESTIONS};
      st_learner_t *learner = st_learner_new(&config);
      require(learner != nullptr);
      std::vector<std::string> history;
      for (size_t i = 0; i < 6; i++) {
        std::string record =
            fields_netargv(reference.prefix + alternatives[kind][i % 2], true);
        require(st_learner_feed_netargv_view(learner, argv_view(record)) ==
                ST_OK);
        history.push_back(record);
      }
      size_t count = 0;
      st_suggestion_t *suggestions = st_learner_suggest(learner, &count);
      std::string expected =
          canonical_pattern(kind ? reference.compound : reference.wildcard);
      require(suggestions && count == 1 &&
              suggestions[0].pattern_length == expected.size() &&
              std::memcmp(suggestions[0].pattern, expected.data(),
                          expected.size()) == 0 &&
              suggestions[0].count == 6 && suggestions[0].confidence == 1.0);
      check_suggestions_replay(suggestions, count, history);
      st_suggestion_list_free(suggestions, count);
      st_learner_free(learner);
    }
  }
  /* Check the mutation decoder's trailing empty field and bounded field count
   * independently of classification or learning. */
  std::string trailing = fields_netargv("alpha\t", true);
  require(trailing == "4:fuzz,5:alpha,0:,");
  std::string bounded = fields_netargv(std::string(9, '\t'), true);
  size_t records = 0;
  require(shell_netstring_validate(bounded.data(), bounded.size(), &records) ==
              SHELL_NETSTRING_OK &&
          records == 9 &&
          bounded.compare(bounded.size() - 5, 5, "2:\t\t,") == 0);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static bool checked_variants = false;
  if (!checked_variants) {
    check_learner_variant_references();
    check_timestamp_suggestion_reference();
    check_overlapping_suggestion_reference();
    check_binary_classification_references();
    check_binary_continuation_references();
    check_policy_command_grammar_references();
    check_policy_variant_references();
    check_validation_detail_references();
    checked_variants = true;
  }
  if (!data || size == 0)
    return 0;

  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = context ? st_policy_new(context) : nullptr;
  st_policy_ctx_t *context_b = st_policy_ctx_new();
  st_policy_t *policy_b = context_b ? st_policy_new(context_b) : nullptr;
  st_learner_config_t learner_config{1, 0.0, ST_DEFAULT_MAX_SUGGESTIONS};
  st_learner_t *learner = st_learner_new(&learner_config);
  if (!context || !policy || !context_b || !policy_b || !learner) {
    st_policy_free(policy);
    st_policy_free(policy_b);
    st_policy_ctx_release(context);
    st_policy_ctx_release(context_b);
    st_learner_free(learner);
    return 0;
  }

  std::vector<std::string> learner_history;
  bool learner_history_complete = true;

  size_t offset = 0;
  while (offset < size) {
    size_t end = offset;
    while (end < size && data[end] != '\n' &&
           end - offset < ST_MAX_NETPATTERN_LEN)
      end++;
    if (end > offset) {
      uint8_t operation = data[offset] % 16;
      std::string text(reinterpret_cast<const char *>(data + offset + 1),
                       end - offset - 1);
      std::string netargv = fields_netargv(text, operation == 6);
      switch (operation) {
      case 0:
        /* Exercise the complete byte span, including embedded NULs. */
        (void)st_token_classify(text.data(), text.size());
        break;
      case 1: {
        st_token_array_t tokens = {};
        if (st_netargv_classify_view(argv_view(netargv), &tokens) == ST_OK) {
          NetargvVisitCheck visit_check{&tokens, 0};
          size_t visited = 0;
          require(st_netargv_visit_view(argv_view(netargv), check_netargv_visit,
                                        &visit_check, &visited) == ST_OK);
          require(visited == tokens.count && visit_check.index == tokens.count);
          for (size_t i = 0; i < tokens.count; i++) {
            require(tokens.tokens[i].text != nullptr);
            if (tokens.tokens[i].text[0] == '#')
              require(text.find(std::string(tokens.tokens[i].text,
                                            tokens.tokens[i].text_length)) !=
                      std::string::npos);
          }
        }
        st_token_array_free(&tokens);
        break;
      }
      case 2: {
        std::string pattern = canonical_pattern(text);
        st_netpattern_view_t input =
            pattern_view(pattern.empty() ? text : pattern);
        st_token_array_t info = {};
        st_error_t validation = st_netpattern_validate_view(input, &info);
        require(st_netpattern_validate_view(input, nullptr) == validation);
        require(validation == ST_OK || (!info.tokens && info.count == 0));
        st_token_array_free(&info);
        (void)st_policy_add_netpattern_view(policy, input);
        break;
      }
      case 3: {
        std::string pattern = canonical_pattern(text);
        (void)st_policy_remove_netpattern_view(
            policy, pattern_view(pattern.empty() ? text : pattern));
        break;
      }
      case 4: {
        check_eval_is_verified(policy, argv_view(netargv));
        break;
      }
      case 5: {
        st_netpattern_view_t *matches = nullptr;
        size_t count = 0;
        (void)st_policy_verify_all_view(policy, argv_view(netargv), &matches,
                                        &count);
        st_policy_matches_free(matches);
        break;
      }
      case 6: {
        /* Bound weighted histories while keeping replay enabled for every
         * successfully fed mutated record. Upper operation bits choose weight.
         */
        unsigned weight = 1u + ((data[offset] >> 4u) & 3u);
        for (unsigned i = 0; i < weight && learner_history.size() < 64; i++) {
          if (st_learner_feed_netargv_view(learner, argv_view(netargv)) !=
              ST_OK)
            break;
          learner_history.push_back(netargv);
        }
        break;
      }
      case 7: {
        st_eval_result_t before = {};
        st_eval_result_t after = {};
        size_t before_count = st_policy_rule_count(policy);
        (void)st_policy_eval_view(policy, argv_view(netargv), &before);
        std::string before_pattern =
            before.matches && before.matching_pattern
                ? std::string(before.matching_pattern,
                              before.matching_pattern_length)
                : "";
        if (st_policy_compact(policy) == ST_OK) {
          require(st_policy_rule_count(policy) == before_count);
          require(st_policy_eval_view(policy, argv_view(netargv), &after) ==
                  ST_OK);
          require(before.matches == after.matches);
          if (before.matches)
            require(after.matching_pattern &&
                    before_pattern.size() == after.matching_pattern_length &&
                    std::memcmp(before_pattern.data(), after.matching_pattern,
                                before_pattern.size()) == 0);
        }
        break;
      }
      case 8: {
        std::string pattern = canonical_pattern(text);
        (void)st_policy_add_netpattern_view(
            policy_b, pattern_view(pattern.empty() ? text : pattern));
        break;
      }
      case 9: {
        std::string pattern = canonical_pattern(text);
        (void)st_policy_remove_netpattern_view(
            policy_b, pattern_view(pattern.empty() ? text : pattern));
        break;
      }
      case 10:
        check_eval_is_verified(policy_b, argv_view(netargv));
        break;
      case 11: {
        st_policy_t *destination = (text.size() & 1u) ? policy : policy_b;
        st_policy_t *source = destination == policy ? policy_b : policy;
        (void)st_policy_merge(destination, source);
        check_eval_is_verified(destination, argv_view(netargv));
        break;
      }
      case 12: {
        st_policy_diff_t forward = {};
        st_policy_diff_t reverse = {};
        if (st_policy_diff(policy, policy_b, &forward) == ST_OK &&
            st_policy_diff(policy_b, policy, &reverse) == ST_OK) {
          require(netpattern_set_equal(forward.added, forward.added_count,
                                       reverse.removed, reverse.removed_count));
          require(netpattern_set_equal(forward.removed, forward.removed_count,
                                       reverse.added, reverse.added_count));
        }
        st_policy_diff_free(&forward);
        st_policy_diff_free(&reverse);
        break;
      }
      case 13: {
        std::string first = canonical_pattern(text);
        std::string second = canonical_pattern("fuzz batch");
        st_netpattern_view_t batch[] = {
            pattern_view(first.empty() ? text : first), pattern_view(second)};
        size_t before = st_policy_rule_count(policy);
        st_error_t error =
            st_policy_batch_add_netpattern_views(policy, batch, 2);
        if (error != ST_OK)
          require(st_policy_rule_count(policy) == before);
        else
          check_eval_is_verified(policy, argv_view("4:fuzz,5:batch,"));
        break;
      }
      case 14: {
        size_t before = st_policy_rule_count(policy);
        bool redundant = false;
        st_netpattern_view_t conflict = {};
        std::string pattern = canonical_pattern(text);
        (void)st_policy_simulate_add_netpattern_view(
            policy, pattern_view(pattern.empty() ? text : pattern), &redundant,
            &conflict);
        require(st_policy_rule_count(policy) == before);
        if (!text.empty() && (static_cast<unsigned char>(text[0]) & 1u) != 0) {
          require(st_policy_clear(policy_b) == ST_OK);
          require(st_policy_rule_count(policy_b) == 0);
        }
        break;
      }
      case 15: {
        std::string pattern = canonical_pattern(text);
        if (st_netpattern_validate_view(pattern_view(pattern), nullptr) ==
            ST_OK)
          (void)check_policy_pattern_variants(policy, pattern, {netargv});
        st_token_array_t tokens = {};
        if (!pattern.empty() &&
            st_netpattern_decode_view(pattern_view(pattern), &tokens) ==
                ST_OK &&
            tokens.count != 0) {
          st_token_variant_t variants[ST_MAX_TOKEN_VARIANTS] = {};
          size_t count = st_learner_suggest_token_variants(
              learner, &tokens, tokens.count - 1, variants);
          for (size_t i = 0; i < count; i++) {
            st_netpattern_t edited = {};
            require(st_netpattern_apply_type_at_owned(
                        pattern_view(pattern), tokens.count - 1,
                        variants[i].type, &edited) == ST_OK);
            require(edited.data != nullptr);
            st_error_t validation = st_netpattern_validate_view(
                {edited.data, edited.length}, nullptr);
            if (validation != ST_OK)
              std::fprintf(
                  stderr,
                  "invalid token variant: source='%s' edited='%s' "
                  "type=%d symbol='%s'\n",
                  text.c_str(), edited.data, static_cast<int>(variants[i].type),
                  variants[i].type_symbol ? variants[i].type_symbol : "(null)");
            require(validation == ST_OK);
            st_netpattern_free(&edited);
          }
        }
        st_token_array_free(&tokens);
        break;
      }
      }
    }
    offset = end < size && data[end] == '\n' ? end + 1 : end;
  }

  char raw_path[] = "/tmp/shelltype-fuzz-raw-XXXXXX";
  int raw_fd = mkstemp(raw_path);
  if (raw_fd >= 0) {
    size_t written = 0;
    while (written < size) {
      ssize_t result = write(raw_fd, data + written, size - written);
      if (result <= 0)
        break;
      written += static_cast<size_t>(result);
    }
    close(raw_fd);
    st_policy_ctx_t *snapshot_context = st_policy_ctx_new();
    st_policy_t *snapshot =
        snapshot_context ? st_policy_new(snapshot_context) : nullptr;
    bool snapshot_ready =
        snapshot && st_policy_merge(snapshot, policy) == ST_OK;
    bool clear_first = (data[0] & 1u) != 0;
    st_error_t policy_load = st_policy_load(policy, raw_path, clear_first);
    if (policy_load != ST_OK && snapshot_ready)
      require(policies_equal(policy, snapshot));
    st_policy_free(snapshot);
    st_policy_ctx_release(snapshot_context);

    size_t learner_before_count = 0;
    st_suggestion_t *learner_before =
        st_learner_suggest(learner, &learner_before_count);
    st_error_t learner_load = st_learner_load(learner, raw_path);
    if (learner_load != ST_OK) {
      size_t learner_after_count = 0;
      st_suggestion_t *learner_after =
          st_learner_suggest(learner, &learner_after_count);
      require(learner_before_count == learner_after_count);
      for (size_t i = 0; i < learner_before_count; i++) {
        require(learner_before && learner_after);
        require(learner_before[i].pattern_length ==
                    learner_after[i].pattern_length &&
                std::memcmp(learner_before[i].pattern, learner_after[i].pattern,
                            learner_before[i].pattern_length) == 0);
        require(learner_before[i].count == learner_after[i].count);
        require(learner_before[i].confidence == learner_after[i].confidence);
      }
      st_suggestion_list_free(learner_after, learner_after_count);
    } else
      learner_history_complete = false;
    st_suggestion_list_free(learner_before, learner_before_count);
    unlink(raw_path);
  }

  bool deep_checks = size <= 1024 || (input_hash(data, size) & 63u) == 0;
  if (deep_checks) {
    char policy_path[] = "/tmp/shelltype-fuzz-policy-XXXXXX";
    int policy_fd = mkstemp(policy_path);
    if (policy_fd >= 0) {
      close(policy_fd);
      size_t before_count = st_policy_rule_count(policy);
      if (st_policy_save(policy, policy_path) == ST_OK) {
        st_policy_ctx_t *clone_context = st_policy_ctx_new();
        st_policy_t *clone =
            clone_context ? st_policy_new(clone_context) : nullptr;
        if (clone) {
          require(st_policy_load(clone, policy_path, true) == ST_OK);
          require(st_policy_rule_count(clone) == before_count);

          st_policy_diff_t forward = {};
          st_policy_diff_t reverse = {};
          require(st_policy_diff(policy, clone, &forward) == ST_OK);
          require(st_policy_diff(clone, policy, &reverse) == ST_OK);
          require(forward.added_count == 0 && forward.removed_count == 0);
          require(reverse.added_count == 0 && reverse.removed_count == 0);
          st_policy_diff_free(&forward);
          st_policy_diff_free(&reverse);

          require(st_policy_merge(clone, policy) == ST_OK);
          require(st_policy_rule_count(clone) == before_count);
        }
        st_policy_free(clone);
        st_policy_ctx_release(clone_context);

        require(st_policy_load(policy, policy_path, true) == ST_OK);
        require(st_policy_rule_count(policy) == before_count);
      }
      unlink(policy_path);
    }

    char nfa_path[] = "/tmp/shelltype-fuzz-nfa-XXXXXX";
    int nfa_fd = mkstemp(nfa_path);
    if (nfa_fd >= 0) {
      close(nfa_fd);
      (void)st_policy_render_nfa(policy, nfa_path, nullptr);
      unlink(nfa_path);
    }

    char learner_path[] = "/tmp/shelltype-fuzz-learner-XXXXXX";
    int learner_fd = mkstemp(learner_path);
    if (learner_fd >= 0) {
      close(learner_fd);
      size_t before_count = 0;
      st_suggestion_t *before = st_learner_suggest(learner, &before_count);
      if (learner_history_complete)
        check_suggestions_replay(before, before_count, learner_history);
      if (st_learner_save(learner, learner_path) == ST_OK) {
        st_learner_config_t clone_config = {};
        require(st_learner_get_config(learner, &clone_config) == ST_OK);
        st_learner_t *clone = st_learner_new(&clone_config);
        if (clone && st_learner_load(clone, learner_path) == ST_OK) {
          size_t after_count = 0;
          st_suggestion_t *after = st_learner_suggest(clone, &after_count);
          require(before_count == after_count);
          for (size_t i = 0; i < before_count; i++) {
            require(before && after);
            require(before[i].pattern_length == after[i].pattern_length &&
                    std::memcmp(before[i].pattern, after[i].pattern,
                                before[i].pattern_length) == 0);
            require(before[i].count == after[i].count);
            require(before[i].confidence == after[i].confidence);
            st_token_array_t info = {};
            require(st_netpattern_validate_view(
                        {after[i].pattern, after[i].pattern_length}, &info) ==
                    ST_OK);
            st_token_array_free(&info);
          }
          st_suggestion_list_free(after, after_count);
        }
        st_learner_free(clone);
      }
      st_suggestion_list_free(before, before_count);
      unlink(learner_path);
    }

    st_policy_ctx_t *roundtrip_context = st_policy_ctx_new();
    st_policy_t *roundtrip =
        roundtrip_context ? st_policy_new(roundtrip_context) : nullptr;
    if (roundtrip) {
      st_eval_result_t result = {};
      std::string probe_pattern = canonical_pattern("fuzz probe");
      require(!probe_pattern.empty());
      require(
          st_policy_eval_view(roundtrip,
                              st_netargv_view_t{"4:fuzz,5:probe,",
                                                sizeof("4:fuzz,5:probe,") - 1},
                              &result) == ST_OK);
      require(!result.matches);
      require(st_policy_add_netpattern_view(
                  roundtrip, st_netpattern_view_t{probe_pattern.data(),
                                                  probe_pattern.size()}) ==
              ST_OK);
      require(
          st_policy_eval_view(roundtrip,
                              st_netargv_view_t{"4:fuzz,5:probe,",
                                                sizeof("4:fuzz,5:probe,") - 1},
                              &result) == ST_OK);
      require(result.matches);
      require(st_policy_remove_netpattern_view(
                  roundtrip, st_netpattern_view_t{probe_pattern.data(),
                                                  probe_pattern.size()}) ==
              ST_OK);
      require(
          st_policy_eval_view(roundtrip,
                              st_netargv_view_t{"4:fuzz,5:probe,",
                                                sizeof("4:fuzz,5:probe,") - 1},
                              &result) == ST_OK);
      require(!result.matches);
    }
    st_policy_free(roundtrip);
    st_policy_ctx_release(roundtrip_context);

    st_policy_ctx_t *scratch = st_policy_ctx_new();
    if (scratch) {
      st_policy_t *scratch_policy = st_policy_new(scratch);
      std::string scratch_pattern = canonical_pattern("fuzz interned");
      require(scratch_policy != nullptr && !scratch_pattern.empty());
      require(st_policy_add_netpattern_view(
                  scratch_policy,
                  st_netpattern_view_t{scratch_pattern.data(),
                                       scratch_pattern.size()}) == ST_OK);
      st_policy_free(scratch_policy);
      require(st_policy_ctx_reset(scratch) == ST_OK);
      scratch_policy = st_policy_new(scratch);
      scratch_pattern = canonical_pattern("after reset");
      require(scratch_policy != nullptr && !scratch_pattern.empty());
      require(st_policy_add_netpattern_view(
                  scratch_policy,
                  st_netpattern_view_t{scratch_pattern.data(),
                                       scratch_pattern.size()}) == ST_OK);
      st_policy_free(scratch_policy);
      require(st_policy_ctx_reset(scratch) == ST_OK);
    }
    st_policy_ctx_release(scratch);
  }

  st_learner_free(learner);
  st_policy_free(policy);
  st_policy_free(policy_b);
  st_policy_ctx_release(context);
  st_policy_ctx_release(context_b);
  return 0;
}
