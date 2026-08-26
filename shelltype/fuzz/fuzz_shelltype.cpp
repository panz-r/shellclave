#include "policy_ctx.h"
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
  if (!token || check->index >= check->tokens->count)
    return false;
  const st_token_t &owned = check->tokens->tokens[check->index++];
  return token->type == owned.type &&
         token->text_length == std::strlen(owned.text) &&
         std::memcmp(token->text, owned.text, token->text_length) == 0;
}

static std::string one_arg_netargv(const std::string &input) {
  size_t length = input.find('\0');
  if (length == std::string::npos)
    length = input.size();
  return std::to_string(length) + ":" + input.substr(0, length) + ",";
}

static std::string canonical_pattern(const std::string &cpl) {
  char *encoded = nullptr;
  if (st_netpattern_from_cpl(cpl.c_str(), &encoded) != ST_OK)
    return {};
  std::string result(encoded);
  std::free(encoded);
  return result;
}

static void check_eval_is_verified(st_policy_t *policy, const char *command) {
  st_eval_result_t result = {};
  if (st_policy_eval(policy, command, &result) != ST_OK)
    return;
  const char **matches = nullptr;
  size_t count = 0;
  if (st_policy_verify_all(policy, command, &matches, &count) != ST_OK)
    return;
  if (result.matches) {
    bool found = false;
    for (size_t i = 0; i < count; i++)
      found = found || (result.matching_pattern &&
                        std::strcmp(result.matching_pattern, matches[i]) == 0);
    require(found);
  } else {
    require(count == 0);
  }
  st_policy_matches_free(matches);
}

static bool string_set_equal(char *const *left, size_t left_count,
                             char *const *right, size_t right_count) {
  if (left_count != right_count)
    return false;
  for (size_t i = 0; i < left_count; i++) {
    bool found = false;
    for (size_t j = 0; j < right_count; j++)
      found = found || std::strcmp(left[i], right[j]) == 0;
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
    require(st_netpattern_validate(suggestions[suggestion].pattern, nullptr) ==
            ST_OK);
    require(suggestions[suggestion].confidence >= 0.0 &&
            suggestions[suggestion].confidence <= 1.0);
    st_policy_ctx_t *context = st_policy_ctx_new();
    st_policy_t *policy = context ? st_policy_new(context) : nullptr;
    require(policy && st_policy_add_netpattern(
                          policy, suggestions[suggestion].pattern) == ST_OK);
    uint32_t matches = 0;
    for (const std::string &command : history) {
      st_eval_result_t result = {};
      require(st_policy_eval(policy, command.c_str(), &result) == ST_OK);
      matches += result.matches ? 1u : 0u;
    }
    require(matches == suggestions[suggestion].count);
    st_policy_free(policy);
    st_policy_ctx_release(context);
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
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
      std::string netargv = one_arg_netargv(text);
      switch (operation) {
      case 0:
        (void)st_token_classify(text.c_str());
        break;
      case 1: {
        st_token_array_t tokens = {};
        if (st_netargv_classify(netargv.c_str(), &tokens) == ST_OK) {
          NetargvVisitCheck visit_check{&tokens, 0};
          size_t visited = 0;
          require(st_netargv_visit(netargv.c_str(), check_netargv_visit,
                                   &visit_check, &visited) == ST_OK);
          require(visited == tokens.count && visit_check.index == tokens.count);
          for (size_t i = 0; i < tokens.count; i++) {
            require(tokens.tokens[i].text != nullptr);
            if (tokens.tokens[i].text[0] == '#')
              require(text.find(tokens.tokens[i].text) != std::string::npos);
          }
          st_expand_suggestion_t variants[3] = {};
          bool concrete_source = true;
          for (size_t i = 0; i < tokens.count; i++) {
            st_pattern_info_t token_info = {};
            if (st_netpattern_validate(tokens.tokens[i].text, &token_info) ==
                    ST_OK &&
                token_info.token_count == 1 &&
                token_info.token_types[0] != ST_TYPE_LITERAL)
              concrete_source = false;
          }
          size_t variant_count = st_policy_suggest_variants(
              policy, tokens.tokens, tokens.count, variants);
          for (size_t i = 0; i < variant_count; i++) {
            st_pattern_info_t info = {};
            require(st_netpattern_validate(variants[i].pattern, &info) ==
                    ST_OK);
            st_policy_ctx_t *variant_context = st_policy_ctx_new();
            st_policy_t *variant_policy =
                variant_context ? st_policy_new(variant_context) : nullptr;
            if (variant_policy &&
                st_policy_add_netpattern(variant_policy, variants[i].pattern) ==
                    ST_OK) {
              st_eval_result_t result = {};
              require(st_policy_eval(variant_policy, netargv.c_str(),
                                     &result) == ST_OK);
              if (concrete_source && !result.matches)
                std::fprintf(stderr,
                             "variant did not match source: pattern='%s' "
                             "source='%s'\n",
                             variants[i].pattern, text.c_str());
              if (concrete_source)
                require(result.matches);
            }
            st_policy_free(variant_policy);
            st_policy_ctx_release(variant_context);
          }
        }
        st_token_array_free(&tokens);
        break;
      }
      case 2: {
        std::string pattern = canonical_pattern(text);
        const char *input = pattern.empty() ? text.c_str() : pattern.c_str();
        st_pattern_info_t info = {};
        (void)st_netpattern_validate(input, &info);
        (void)st_policy_add_netpattern(policy, input);
        break;
      }
      case 3: {
        std::string pattern = canonical_pattern(text);
        (void)st_policy_remove_netpattern(
            policy, pattern.empty() ? text.c_str() : pattern.c_str());
        break;
      }
      case 4: {
        check_eval_is_verified(policy, netargv.c_str());
        break;
      }
      case 5: {
        const char **matches = nullptr;
        size_t count = 0;
        (void)st_policy_verify_all(policy, netargv.c_str(), &matches, &count);
        st_policy_matches_free(matches);
        break;
      }
      case 6:
        if (st_learner_feed_netargv(learner, netargv.c_str()) == ST_OK) {
          if (learner_history.size() < 64)
            learner_history.push_back(netargv);
          else
            learner_history_complete = false;
        }
        break;
      case 7: {
        st_eval_result_t before = {};
        st_eval_result_t after = {};
        size_t before_count = st_policy_rule_count(policy);
        (void)st_policy_eval(policy, netargv.c_str(), &before);
        std::string before_pattern = before.matches && before.matching_pattern
                                         ? before.matching_pattern
                                         : "";
        if (st_policy_compact(policy) == ST_OK) {
          require(st_policy_rule_count(policy) == before_count);
          require(st_policy_eval(policy, netargv.c_str(), &after) == ST_OK);
          require(before.matches == after.matches);
          if (before.matches)
            require(after.matching_pattern &&
                    before_pattern == after.matching_pattern);
        }
        break;
      }
      case 8: {
        std::string pattern = canonical_pattern(text);
        (void)st_policy_add_netpattern(
            policy_b, pattern.empty() ? text.c_str() : pattern.c_str());
        break;
      }
      case 9: {
        std::string pattern = canonical_pattern(text);
        (void)st_policy_remove_netpattern(
            policy_b, pattern.empty() ? text.c_str() : pattern.c_str());
        break;
      }
      case 10:
        check_eval_is_verified(policy_b, netargv.c_str());
        break;
      case 11: {
        st_policy_t *destination = (text.size() & 1u) ? policy : policy_b;
        st_policy_t *source = destination == policy ? policy_b : policy;
        (void)st_policy_merge(destination, source);
        check_eval_is_verified(destination, netargv.c_str());
        break;
      }
      case 12: {
        st_policy_diff_t forward = {};
        st_policy_diff_t reverse = {};
        if (st_policy_diff(policy, policy_b, &forward) == ST_OK &&
            st_policy_diff(policy_b, policy, &reverse) == ST_OK) {
          require(string_set_equal(forward.added, forward.added_count,
                                   reverse.removed, reverse.removed_count));
          require(string_set_equal(forward.removed, forward.removed_count,
                                   reverse.added, reverse.added_count));
        }
        st_policy_diff_free(&forward);
        st_policy_diff_free(&reverse);
        break;
      }
      case 13: {
        std::string first = canonical_pattern(text);
        std::string second = canonical_pattern("fuzz batch");
        const char *batch[] = {first.empty() ? text.c_str() : first.c_str(),
                               second.c_str()};
        size_t before = st_policy_rule_count(policy);
        st_error_t error = st_policy_batch_add_netpatterns(policy, batch, 2);
        if (error != ST_OK)
          require(st_policy_rule_count(policy) == before);
        else
          check_eval_is_verified(policy, "fuzz batch");
        break;
      }
      case 14: {
        size_t before = st_policy_rule_count(policy);
        bool redundant = false;
        const char *conflict = nullptr;
        std::string pattern = canonical_pattern(text);
        (void)st_policy_simulate_add_netpattern(
            policy, pattern.empty() ? text.c_str() : pattern.c_str(),
            &redundant, &conflict);
        require(st_policy_rule_count(policy) == before);
        if (!text.empty() && (static_cast<unsigned char>(text[0]) & 1u) != 0) {
          require(st_policy_clear(policy_b) == ST_OK);
          require(st_policy_rule_count(policy_b) == 0);
        }
        break;
      }
      case 15: {
        st_token_array_t tokens = {};
        if (st_netargv_classify(netargv.c_str(), &tokens) == ST_OK &&
            tokens.count != 0) {
          st_token_variant_t variants[ST_MAX_TOKEN_VARIANTS] = {};
          size_t count = st_learner_suggest_token_variants(
              learner, &tokens, tokens.count - 1, variants);
          char *pattern = nullptr;
          require(st_netpattern_encode(tokens.tokens, tokens.count, &pattern) ==
                  ST_OK);
          for (size_t i = 0; i < count; i++) {
            char *edited = nullptr;
            require(st_netpattern_apply_type_at(pattern, tokens.count - 1,
                                                variants[i].type,
                                                &edited) == ST_OK);
            require(edited != nullptr);
            st_error_t validation = st_netpattern_validate(edited, nullptr);
            if (validation != ST_OK)
              std::fprintf(
                  stderr,
                  "invalid token variant: source='%s' edited='%s' "
                  "type=%d symbol='%s'\n",
                  text.c_str(), edited, static_cast<int>(variants[i].type),
                  variants[i].type_symbol ? variants[i].type_symbol : "(null)");
            require(validation == ST_OK);
            std::free(edited);
          }
          std::free(pattern);
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
        require(std::strcmp(learner_before[i].pattern,
                            learner_after[i].pattern) == 0);
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
            require(std::strcmp(before[i].pattern, after[i].pattern) == 0);
            require(before[i].count == after[i].count);
            require(before[i].confidence == after[i].confidence);
            st_pattern_info_t info = {};
            require(st_netpattern_validate(after[i].pattern, &info) == ST_OK);
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
      require(st_policy_eval(roundtrip, "4:fuzz,5:probe,", &result) == ST_OK);
      require(!result.matches);
      require(st_policy_add_netpattern(roundtrip, probe_pattern.c_str()) ==
              ST_OK);
      require(st_policy_eval(roundtrip, "4:fuzz,5:probe,", &result) == ST_OK);
      require(result.matches);
      require(st_policy_remove_netpattern(roundtrip, probe_pattern.c_str()) ==
              ST_OK);
      require(st_policy_eval(roundtrip, "4:fuzz,5:probe,", &result) == ST_OK);
      require(!result.matches);
    }
    st_policy_free(roundtrip);
    st_policy_ctx_release(roundtrip_context);

    st_policy_ctx_t *scratch = st_policy_ctx_new();
    if (scratch) {
      st_policy_t *scratch_policy = st_policy_new(scratch);
      std::string scratch_pattern = canonical_pattern("fuzz interned");
      require(scratch_policy != nullptr && !scratch_pattern.empty());
      require(st_policy_add_netpattern(scratch_policy,
                                       scratch_pattern.c_str()) == ST_OK);
      st_policy_free(scratch_policy);
      require(st_policy_ctx_reset(scratch) == ST_OK);
      scratch_policy = st_policy_new(scratch);
      scratch_pattern = canonical_pattern("after reset");
      require(scratch_policy != nullptr && !scratch_pattern.empty());
      require(st_policy_add_netpattern(scratch_policy,
                                       scratch_pattern.c_str()) == ST_OK);
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
