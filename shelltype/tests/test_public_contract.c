/* The same public contracts run against shipping and fault-injection libraries.
 * No allocator hooks or production API overrides are used. Private filesystem
 * fixtures only manage test-owned directories and inventory temporary files. */
#define _POSIX_C_SOURCE 200809L

#include "../../tests/atomic_file_fixture.h"
#include "shell_netstring.h"
#include "shelltype.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "check failed: %s at %s:%d\n", #condition, __FILE__,     \
              __LINE__);                                                       \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

typedef struct {
  const st_token_array_t *owned;
  size_t seen;
} visit_state_t;

static bool compare_token(const st_token_view_t *token, void *context) {
  visit_state_t *state = context;
  if (state->seen == state->owned->count)
    return false;
  const st_token_t *owned = &state->owned->tokens[state->seen++];
  return owned->type == token->type &&
         owned->text_length == token->text_length &&
         memcmp(owned->text, token->text, token->text_length) == 0;
}

static bool count_match(st_netpattern_view_t pattern, void *context) {
  size_t *count = context;
  (*count)++;
  return pattern.length != 0;
}

static bool check_match(st_policy_t *policy, st_netargv_view_t input,
                        bool expected) {
  bool matched = !expected;
  st_eval_result_t evaluated = {0};
  st_netpattern_view_t *patterns = NULL;
  size_t count = 0;
  size_t callbacks = 0, visited = 0;
  bool ok =
      st_policy_match_view(policy, input, &matched) == ST_OK &&
      matched == expected &&
      st_policy_eval_view(policy, input, &evaluated) == ST_OK &&
      evaluated.matches == expected &&
      st_policy_verify_all_view(policy, input, &patterns, &count) == ST_OK &&
      (count != 0) == expected &&
      st_policy_visit_matches_view(policy, input, count_match, &callbacks,
                                   &visited) == ST_OK &&
      callbacks == visited && visited == count;
  st_policy_matches_free(patterns);
  return ok;
}

/* Exact-size framed storage: no terminator or spare bytes can hide a span
 * overread. Framing itself is provided by the shared Shellsplit utilities.
 * out is empty on entry; word supplies length readable bytes. */
static bool build_tool_netargv(const void *word, size_t length,
                               shell_netstring_buffer_t *out)
    SHELL_NONNULL(1, 3);
static bool build_tool_netargv(const void *word, size_t length,
                               shell_netstring_buffer_t *out) {
  size_t first = 0, second = 0;
  if (shell_netstring_encoded_length(4, &first) != SHELL_NETSTRING_OK ||
      shell_netstring_encoded_length(length, &second) != SHELL_NETSTRING_OK ||
      first > SIZE_MAX - second)
    return false;
  out->data = malloc(first + second);
  if (!out->data)
    return false;
  out->length = first + second;
  if (shell_netstring_write(out->data, first, "tool", 4, NULL) !=
          SHELL_NETSTRING_OK ||
      shell_netstring_write(out->data + first, second, word, length, NULL) !=
          SHELL_NETSTRING_OK) {
    shell_netstring_buffer_free(out);
    return false;
  }
  return true;
}

static bool check_policy_command_grammar(void) {
  static const struct {
    const char *cpl;
    bool supported;
    const char *netargv;
  } cases[] = {
      {"cmd{#n} arg", false, NULL},
      {"{#n}cmd arg", false, NULL},
      {"pre{#n}post arg", false, NULL},
      {"pre{*} arg", false, NULL},
      {"* arg", false, NULL},
      {"cmd{#n} pre{*} arg", false, NULL},
      {"* pre{#n} arg", false, NULL},
      {"tool arg", true, "4:tool,3:arg,"},
      {"#n arg", true, "2:42,3:arg,"},
      {"\"*\" arg", true, "1:*,3:arg,"},
      {"\"#n\" arg", true, "2:#n,3:arg,"},
      {"\"pre{#n}\" arg", true, "7:pre{#n},3:arg,"},
      {"tool pre{#n}", true, "4:tool,5:pre42,"},
      {"tool {#n}post", true, "4:tool,6:42post,"},
      {"tool pre{#n}post", true, "4:tool,9:pre42post,"},
      {"tool pre{*}", true, "4:tool,8:prevalue,"},
      {"tool *", true, "4:tool,3:arg,"},
  };
  static const char existing[] = "4:keep,8:existing,";
  static const char missing[] = "4:keep,7:missing,";
  bool ok = false;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  st_learner_t *learner = NULL;
  st_netpattern_t pattern = {0}, baseline = {0}, edited = {0};
  st_token_array_t decoded = {0}, validated = {0};
  st_learner_config_t config;
  CHECK(context != NULL);
  st_learner_config_default(&config);
  learner = st_learner_new(&config);
  CHECK(learner != NULL);
  CHECK(st_netpattern_from_cpl_owned("keep existing", &baseline) == ST_OK);

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    CHECK(st_netpattern_from_cpl_owned(cases[i].cpl, &pattern) == ST_OK);
    st_netpattern_view_t view = {pattern.data, pattern.length};
    st_error_t expected = cases[i].supported ? ST_OK : ST_ERR_INVALID;
    CHECK(st_netpattern_validate_view(view, NULL) == expected);
    CHECK(st_netpattern_validate_view(view, &validated) == expected);
    if (expected == ST_OK) {
      CHECK(validated.count == 2);
      st_token_array_free(&validated);
    } else
      CHECK(validated.tokens == NULL && validated.count == 0);
    CHECK(st_netpattern_decode_view(view, &decoded) == ST_OK);

    /* Canonical codecs can describe an unsupported policy command word.
     * Editor queries consume those decoded tokens without fabricating them. */
    st_token_variant_t choices[ST_MAX_TOKEN_VARIANTS];
    for (size_t position = 0; position < decoded.count; position++) {
      CHECK((st_token_variants_at(&decoded, position, choices,
                                  ST_MAX_TOKEN_VARIANTS) != 0) ==
            cases[i].supported);
      CHECK((st_learner_suggest_token_variants(learner, &decoded, position,
                                               choices) != 0) ==
            cases[i].supported);
    }
    CHECK(st_netpattern_apply_type_at_owned(view, 0, ST_TYPE_ANY, &edited) ==
          ST_ERR_INVALID);
    CHECK(edited.data == NULL && edited.length == 0);
    /* Replacing ANY with a supported type repairs that command word, whereas
     * changing a compound capture cannot make it a supported command word. */
    CHECK(st_netpattern_apply_type_at_owned(view, 0, ST_TYPE_VALUE, &edited) ==
          (decoded.tokens[0].compound ? ST_ERR_INVALID : ST_OK));
    if (decoded.tokens[0].compound) {
      CHECK(edited.data == NULL && edited.length == 0);
    } else {
      CHECK(
          st_netpattern_validate_view(
              (st_netpattern_view_t){(const char *)edited.data, edited.length},
              NULL) == ST_OK);
    }
    st_netpattern_free(&edited);

    /* Edits must leave a valid policy head, including when an unchanged head
     * is outside policy grammar. Only a whole-token head edit can repair ANY.
     * Exercise every position and every accepted type. */
    for (size_t position = 0; position < decoded.count; position++) {
      for (st_token_type_t type = ST_TYPE_LITERAL + 1; type < ST_TYPE_COUNT;
           type++) {
        st_error_t edit_expected =
            (position == 0 ? !decoded.tokens[0].compound && type != ST_TYPE_ANY
                           : cases[i].supported)
                ? ST_OK
                : ST_ERR_INVALID;
        CHECK(st_netpattern_apply_type_at_owned(view, position, type,
                                                &edited) == edit_expected);
        if (edit_expected == ST_OK)
          CHECK(st_netpattern_validate_view(
                    (st_netpattern_view_t){(const char *)edited.data,
                                           edited.length},
                    NULL) == ST_OK);
        else
          CHECK(edited.data == NULL && edited.length == 0);
        st_netpattern_free(&edited);
      }
    }

    for (unsigned populated = 0; populated < 2; populated++) {
      policy = st_policy_new(context);
      CHECK(policy != NULL);
      if (populated)
        CHECK(st_policy_add_netpattern_view(
                  policy, (st_netpattern_view_t){(const char *)baseline.data,
                                                 baseline.length}) == ST_OK);
      size_t before = st_policy_rule_count(policy);
      CHECK(check_match(policy,
                        (st_netargv_view_t){existing, sizeof(existing) - 1},
                        populated != 0));
      for (unsigned omit_conflict = 0; omit_conflict < 2; omit_conflict++) {
        bool covered = true;
        st_netpattern_view_t conflict = view;
        st_error_t status = st_policy_simulate_add_netpattern_view(
            policy, view, &covered, omit_conflict ? NULL : &conflict);
        CHECK(status == expected && !covered);
        if (!omit_conflict) {
          CHECK(conflict.data == NULL && conflict.length == 0);
        }
        CHECK(st_policy_rule_count(policy) == before);
      }

      st_expand_suggestion_t suggestions[3];
      memset(suggestions, 0xa5, sizeof(suggestions));
      size_t count = st_policy_suggest_variants(policy, decoded.tokens,
                                                decoded.count, suggestions);
      CHECK((count != 0) == cases[i].supported);
      if (cases[i].supported) {
        CHECK(count <= 3);
        for (size_t j = 0; j < count; j++)
          CHECK(st_netpattern_validate_view(
                    (st_netpattern_view_t){suggestions[j].pattern,
                                           suggestions[j].pattern_length},
                    NULL) == ST_OK);
      } else {
        for (size_t j = 0; j < 3; j++)
          CHECK(suggestions[j].pattern_length == 0 &&
                suggestions[j].pattern[0] == '\0' &&
                suggestions[j].based_on == NULL &&
                suggestions[j].based_on_length == 0 &&
                suggestions[j].confidence == 0.0);
      }

      CHECK(st_policy_add_netpattern_view(policy, view) == expected);
      CHECK(st_policy_rule_count(policy) == before + cases[i].supported);
      CHECK(check_match(policy,
                        (st_netargv_view_t){existing, sizeof(existing) - 1},
                        populated != 0));
      CHECK(check_match(
          policy, (st_netargv_view_t){missing, sizeof(missing) - 1}, false));
      if (cases[i].supported)
        CHECK(check_match(
            policy,
            (st_netargv_view_t){cases[i].netargv, strlen(cases[i].netargv)},
            true));
      st_policy_free(policy);
      policy = NULL;
    }
    st_token_array_free(&decoded);
    st_netpattern_free(&pattern);
  }
  ok = true;
cleanup:
  st_netpattern_free(&edited);
  st_netpattern_free(&baseline);
  st_netpattern_free(&pattern);
  st_token_array_free(&decoded);
  st_token_array_free(&validated);
  st_learner_free(learner);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return ok;
}

static bool check_compound_capture_spans(void) {
  static const struct {
    const char *cpl;
    const char *prefix, *suffix;
    size_t prefix_length, suffix_length;
  } cases[] = {
      {"tool --output={#path}", "--output=", "", 9, 0},
      {"tool \"pre\"{#path}\"post\"", "pre", "post", 3, 4},
      {"tool \"pre\\x00\"{#path}\"\\x00post\"", "pre\0", "\0post", 4, 5},
  };
  static const size_t lengths[] = {ST_MAX_TOKEN_LEN - 1, ST_MAX_TOKEN_LEN,
                                   ST_MAX_TOKEN_LEN + 1,
                                   ST_MAX_NETPATTERN_LEN + 32};
  bool ok = false;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  st_netpattern_t pattern = {0};
  shell_netstring_buffer_t input = {0};
  unsigned char *word = NULL;
  CHECK(context != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    policy = st_policy_new(context);
    CHECK(policy != NULL);
    CHECK(st_netpattern_from_cpl_owned(cases[i].cpl, &pattern) == ST_OK);
    CHECK(st_policy_add_netpattern_view(
              policy, (st_netpattern_view_t){(const char *)pattern.data,
                                             pattern.length}) == ST_OK);
    for (size_t j = 0; j < sizeof(lengths) / sizeof(lengths[0]); j++) {
      size_t total =
          cases[i].prefix_length + lengths[j] + cases[i].suffix_length;
      word = malloc(total);
      CHECK(word != NULL);
      memcpy(word, cases[i].prefix, cases[i].prefix_length);
      memset(word + cases[i].prefix_length, 'x', lengths[j]);
      word[cases[i].prefix_length] = '/';
      memcpy(word + cases[i].prefix_length + lengths[j], cases[i].suffix,
             cases[i].suffix_length);
      for (unsigned binary = 0; binary < 2; binary++) {
        size_t middle = cases[i].prefix_length + lengths[j] / 2;
        word[middle] = binary ? '\0' : 'x';
        CHECK(build_tool_netargv(word, total, &input));
        CHECK(check_match(policy,
                          (st_netargv_view_t){(char *)input.data, input.length},
                          true));
        shell_netstring_buffer_free(&input);
        /* Literal affixes remain exact even after NUL. */
        size_t changed = cases[i].suffix_length ? total - 1 : 0;
        unsigned char saved = word[changed];
        word[changed] = 'Q';
        CHECK(build_tool_netargv(word, total, &input));
        CHECK(check_match(policy,
                          (st_netargv_view_t){(char *)input.data, input.length},
                          false));
        shell_netstring_buffer_free(&input);
        word[changed] = saved;
      }
      if (j + 1 == sizeof(lengths) / sizeof(lengths[0])) {
        CHECK(st_policy_compact(policy) == ST_OK);
        CHECK(build_tool_netargv(word, total, &input));
        CHECK(check_match(policy,
                          (st_netargv_view_t){(char *)input.data, input.length},
                          true));
        shell_netstring_buffer_free(&input);
      }
      free(word);
      word = NULL;
    }
    CHECK(st_policy_compact(policy) == ST_OK);
    CHECK(build_tool_netargv(cases[i].prefix, cases[i].prefix_length, &input));
    CHECK(check_match(
        policy, (st_netargv_view_t){(char *)input.data, input.length}, false));
    shell_netstring_buffer_free(&input);
    st_netpattern_free(&pattern);
    st_policy_free(policy);
    policy = NULL;
  }
  /* Textual metadata must still inspect the full capture, never a shortened
   * C-string prefix before NUL. */
  policy = st_policy_new(context);
  CHECK(policy != NULL);
  CHECK(st_netpattern_from_cpl_owned("tool --size={#size.MiB}", &pattern) ==
        ST_OK);
  CHECK(st_policy_add_netpattern_view(
            policy, (st_netpattern_view_t){(const char *)pattern.data,
                                           pattern.length}) == ST_OK);
  static const char good[] = "--size=10MiB";
  static const char wrong[] = "--size=10MiB\0tail";
  CHECK(build_tool_netargv(good, sizeof(good) - 1, &input));
  CHECK(check_match(
      policy, (st_netargv_view_t){(char *)input.data, input.length}, true));
  shell_netstring_buffer_free(&input);
  CHECK(build_tool_netargv(wrong, sizeof(wrong) - 1, &input));
  CHECK(check_match(
      policy, (st_netargv_view_t){(char *)input.data, input.length}, false));
  ok = true;
cleanup:
  free(word);
  shell_netstring_buffer_free(&input);
  st_netpattern_free(&pattern);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return ok;
}

static bool check_binary_literal_classification(void) {
  static const struct {
    const char *cpl, *word;
    size_t length;
    st_token_type_t type;
  } cases[] = {
      {"tool \"/tmp/a\\x00b\"", "/tmp/a\0b", 8, ST_TYPE_ABS_PATH},
      {"tool \"./a\\x00b\"", "./a\0b", 5, ST_TYPE_REL_PATH},
      {"tool \"a\\x00.txt\"", "a\0.txt", 6, ST_TYPE_FILENAME},
  };
  bool ok = false;
  st_policy_ctx_t *left_context = st_policy_ctx_new();
  st_policy_ctx_t *right_context = st_policy_ctx_new();
  st_policy_t *left = NULL, *right = NULL;
  st_netpattern_t literal = {0}, wildcard = {0};
  st_token_array_t decoded = {0}, classified = {0};
  st_policy_diff_t diff = {0};
  shell_netstring_buffer_t input = {0};
  CHECK(left_context != NULL && right_context != NULL);
  CHECK(st_netpattern_from_cpl_owned("tool #path", &wildcard) == ST_OK);
  st_netpattern_view_t wildcard_view = {wildcard.data, wildcard.length};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    left = st_policy_new(left_context);
    right = st_policy_new(right_context);
    CHECK(left != NULL && right != NULL);
    CHECK(st_netpattern_from_cpl_owned(cases[i].cpl, &literal) == ST_OK);
    st_netpattern_view_t literal_view = {literal.data, literal.length};
    CHECK(build_tool_netargv(cases[i].word, cases[i].length, &input));
    st_netargv_view_t argv = {(char *)input.data, input.length};
    CHECK(st_netargv_classify_view(argv, &classified) == ST_OK);
    CHECK(classified.count == 2 && classified.tokens[1].type == cases[i].type);
    CHECK(st_netpattern_decode_view(literal_view, &decoded) == ST_OK);
    CHECK(decoded.count == 2 && decoded.tokens[1].type == ST_TYPE_LITERAL &&
          decoded.tokens[1].text_length == cases[i].length &&
          memcmp(decoded.tokens[1].text, cases[i].word, cases[i].length) == 0);
    st_token_variant_t variants[ST_TYPE_COUNT];
    size_t count = st_token_variants_at(&decoded, 1, variants, ST_TYPE_COUNT);
    CHECK(count >= 2 && variants[0].type == ST_TYPE_LITERAL &&
          variants[1].type == cases[i].type);
    CHECK(st_policy_add_netpattern_view(left, literal_view) == ST_OK);
    CHECK(check_match(left, argv, true));
    /* Matching the literal must not truncate at its embedded NUL. */
    input.data[input.length - 2] ^= 1;
    CHECK(check_match(left, argv, false));
    input.data[input.length - 2] ^= 1;
    CHECK(st_policy_add_netpattern_view(right, wildcard_view) == ST_OK);
    CHECK(check_match(right, argv, true));
    bool redundant = false;
    st_netpattern_view_t conflict = {0};
    CHECK(st_policy_simulate_add_netpattern_view(
              right, literal_view, &redundant, &conflict) == ST_OK);
    CHECK(redundant && conflict.length == wildcard.length &&
          memcmp(conflict.data, wildcard.data, wildcard.length) == 0);
    CHECK(st_policy_add_netpattern_view(right, literal_view) == ST_OK &&
          st_policy_rule_count(right) == 1);
    CHECK(st_policy_add_netpattern_view(left, wildcard_view) == ST_OK &&
          st_policy_rule_count(left) == 1);
    CHECK(st_policy_diff(left, right, &diff) == ST_OK &&
          diff.added_count == 0 && diff.removed_count == 0);
    st_policy_diff_free(&diff);
    CHECK(st_policy_compact(left) == ST_OK &&
          st_policy_compact(right) == ST_OK);
    CHECK(check_match(left, argv, true) && check_match(right, argv, true));
    st_token_array_free(&classified);
    st_token_array_free(&decoded);
    shell_netstring_buffer_free(&input);
    st_netpattern_free(&literal);
    st_policy_free(left);
    st_policy_free(right);
    left = right = NULL;
  }
  ok = true;
cleanup:
  st_policy_diff_free(&diff);
  st_token_array_free(&classified);
  st_token_array_free(&decoded);
  shell_netstring_buffer_free(&input);
  st_netpattern_free(&literal);
  st_netpattern_free(&wildcard);
  st_policy_free(left);
  st_policy_free(right);
  st_policy_ctx_release(left_context);
  st_policy_ctx_release(right_context);
  return ok;
}

static bool check_compound_cpl_component_limits(void) {
  static const struct {
    size_t prefix, suffix;
  } cases[] = {{125, 125}, {126, 126}, {200, 200},
               {255, 255}, {0, 255},   {255, 0}};
  bool ok = false;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  st_netpattern_t pattern = {0}, roundtrip = {0};
  st_token_array_t decoded = {0};
  shell_netstring_buffer_t input = {0};
  char *cpl = NULL;
  char *span = NULL;
  char prefix[ST_MAX_TOKEN_LEN - 1], suffix[ST_MAX_TOKEN_LEN - 1];
  char word[2 * (ST_MAX_TOKEN_LEN - 1) + 2];
  CHECK(context != NULL);
  for (unsigned binary = 0; binary < 2; binary++) {
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      memset(prefix, 'p', sizeof(prefix));
      memset(suffix, 's', sizeof(suffix));
      if (binary) {
        /* Explicit-length components are not terminated; CPL must preserve
         * embedded NUL, quote/brace bytes and a complete UTF-8 code point. */
        if (cases[i].prefix) {
          prefix[0] = '\0';
          prefix[1] = '{';
          memcpy(prefix + cases[i].prefix - 4, "\xf0\x9f\x98\x80", 4);
        }
        if (cases[i].suffix) {
          suffix[0] = '"';
          suffix[1] = '}';
          suffix[cases[i].suffix - 1] = '\0';
        }
      }
      st_token_t tokens[] = {
          {.text = "tool", .type = ST_TYPE_LITERAL},
          {.text = "compound",
           .type = ST_TYPE_LITERAL,
           .compound = true,
           .prefix = cases[i].prefix ? prefix : "",
           .prefix_length = cases[i].prefix,
           .capture = "#n",
           .capture_length = 2,
           .capture_type = ST_TYPE_NUMBER,
           .suffix = cases[i].suffix ? suffix : "",
           .suffix_length = cases[i].suffix},
      };
      CHECK(st_netpattern_encode_owned(tokens, 2, &pattern) == ST_OK);
      /* The validator accepts exact, unterminated bytes and transfers all
       * component metadata, independent of whether details are requested. */
      span = malloc(pattern.length);
      CHECK(span != NULL);
      memcpy(span, pattern.data, pattern.length);
      st_netpattern_view_t view = {span, pattern.length};
      CHECK(st_netpattern_validate_view(view, NULL) == ST_OK);
      CHECK(st_netpattern_validate_view(view, &decoded) == ST_OK);
      CHECK(decoded.count == 2 && decoded.tokens[1].compound &&
            decoded.tokens[1].prefix_length == cases[i].prefix &&
            decoded.tokens[1].suffix_length == cases[i].suffix &&
            decoded.tokens[1].capture_type == ST_TYPE_NUMBER &&
            memcmp(decoded.tokens[1].prefix, prefix, cases[i].prefix) == 0 &&
            memcmp(decoded.tokens[1].suffix, suffix, cases[i].suffix) == 0);
      /* Ownership is independent of the input, including embedded NULs. */
      free(span);
      span = NULL;
      CHECK(st_netpattern_encode_owned(decoded.tokens, decoded.count,
                                       &roundtrip) == ST_OK);
      CHECK(roundtrip.length == pattern.length &&
            memcmp(roundtrip.data, pattern.data, pattern.length) == 0);
      st_netpattern_free(&roundtrip);
      view = (st_netpattern_view_t){(const char *)pattern.data, pattern.length};
      if (!binary) {
        st_token_array_free(&decoded);
        CHECK(st_netpattern_validate_view(
                  (st_netpattern_view_t){(const char *)pattern.data,
                                         pattern.length},
                  &decoded) == ST_OK);
        CHECK(decoded.count == 2 && decoded.tokens[1].compound &&
              decoded.tokens[1].prefix_length == cases[i].prefix &&
              decoded.tokens[1].suffix_length == cases[i].suffix);
      }
      CHECK(st_netpattern_to_cpl_view(view, &cpl) == ST_OK);
      CHECK(st_netpattern_from_cpl_owned(cpl, &roundtrip) == ST_OK);
      CHECK(roundtrip.length == pattern.length &&
            memcmp(roundtrip.data, pattern.data, pattern.length) == 0);
      policy = st_policy_new(context);
      CHECK(policy != NULL);
      CHECK(st_policy_add_netpattern_view(
                policy, (st_netpattern_view_t){(const char *)roundtrip.data,
                                               roundtrip.length}) == ST_OK);
      memcpy(word, prefix, cases[i].prefix);
      memcpy(word + cases[i].prefix, "42", 2);
      memcpy(word + cases[i].prefix + 2, suffix, cases[i].suffix);
      size_t length = cases[i].prefix + 2 + cases[i].suffix;
      CHECK(build_tool_netargv(word, length, &input));
      st_netargv_view_t argv = {(const char *)input.data, input.length};
      CHECK(check_match(policy, argv, true));
      CHECK(st_policy_compact(policy) == ST_OK);
      CHECK(check_match(policy, argv, true));
      shell_netstring_buffer_free(&input);
      word[cases[i].prefix] = 'x';
      CHECK(build_tool_netargv(word, length, &input));
      CHECK(check_match(
          policy, (st_netargv_view_t){(const char *)input.data, input.length},
          false));
      shell_netstring_buffer_free(&input);
      st_policy_free(policy);
      policy = NULL;
      st_token_array_free(&decoded);
      st_netpattern_free(&roundtrip);
      st_netpattern_free(&pattern);
      free(cpl);
      cpl = NULL;
    }
  }
  ok = true;
cleanup:
  free(cpl);
  free(span);
  shell_netstring_buffer_free(&input);
  st_token_array_free(&decoded);
  st_netpattern_free(&roundtrip);
  st_netpattern_free(&pattern);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return ok;
}

static bool check_compound_editor_choices(void) {
  static const char *const cases[] = {
      "tool --output={#path}",
      "tool pre{#n}post",
      "tool \"pre\\x00\"{#path}\"\\x00post\"",
      "tool pre{#size.MiB}",
  };
  bool ok = false;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  shell_netstring_buffer_t input = {0};
  st_netpattern_t pattern = {0}, edited = {0};
  st_token_array_t decoded = {0}, changed = {0};
  CHECK(context != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    CHECK(st_netpattern_from_cpl_owned(cases[i], &pattern) == ST_OK);
    CHECK(
        st_netpattern_decode_view(
            (st_netpattern_view_t){(const char *)pattern.data, pattern.length},
            &decoded) == ST_OK);
    const st_token_t *token = &decoded.tokens[1];
    const char *capture = token->capture_type == ST_TYPE_NUMBER ? "42"
                          : token->capture_type == ST_TYPE_SIZE ? "10MiB"
                                                                : "/tmp/x";
    size_t capture_length = strlen(capture);
    unsigned char word[64];
    memcpy(word, token->prefix, token->prefix_length);
    memcpy(word + token->prefix_length, capture, capture_length);
    memcpy(word + token->prefix_length + capture_length, token->suffix,
           token->suffix_length);
    CHECK(build_tool_netargv(
        word, token->prefix_length + capture_length + token->suffix_length,
        &input));
    st_token_variant_t choices[ST_TYPE_COUNT] = {0};
    size_t count = st_token_variants_at(&decoded, 1, choices, ST_TYPE_COUNT);
    CHECK(count > 0 && choices[0].type == token->capture_type);
    CHECK(st_token_variants_at(&decoded, 1, choices, 1) == 1 &&
          choices[0].type == token->capture_type);
    for (size_t j = 0; j < count; j++) {
      CHECK(choices[j].type != ST_TYPE_LITERAL &&
            st_is_compatible(token->capture_type, choices[j].type));
      CHECK(st_netpattern_apply_type_at_owned(
                (st_netpattern_view_t){(const char *)pattern.data,
                                       pattern.length},
                1, choices[j].type, &edited) == ST_OK);
      CHECK(
          st_netpattern_decode_view(
              (st_netpattern_view_t){(const char *)edited.data, edited.length},
              &changed) == ST_OK);
      const st_token_t *replacement = &changed.tokens[1];
      CHECK(replacement->compound &&
            replacement->capture_type == choices[j].type &&
            replacement->prefix_length == token->prefix_length &&
            replacement->suffix_length == token->suffix_length &&
            memcmp(replacement->prefix, token->prefix, token->prefix_length) ==
                0 &&
            memcmp(replacement->suffix, token->suffix, token->suffix_length) ==
                0);
      policy = st_policy_new(context);
      CHECK(policy != NULL);
      CHECK(st_policy_add_netpattern_view(
                policy, (st_netpattern_view_t){(const char *)edited.data,
                                               edited.length}) == ST_OK);
      bool matches = false;
      CHECK(st_policy_match_view(
                policy,
                (st_netargv_view_t){(const char *)input.data, input.length},
                &matches) == ST_OK &&
            matches);
      st_policy_free(policy);
      policy = NULL;
      st_token_array_free(&changed);
      st_netpattern_free(&edited);
    }
    st_token_array_free(&decoded);
    st_netpattern_free(&pattern);
    shell_netstring_buffer_free(&input);
  }
  ok = true;
cleanup:
  shell_netstring_buffer_free(&input);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  st_token_array_free(&changed);
  st_token_array_free(&decoded);
  st_netpattern_free(&edited);
  st_netpattern_free(&pattern);
  return ok;
}

/* Every published suggestion must cover the complete originating argv. */
static bool suggestions_cover_input(st_policy_ctx_t *context,
                                    const st_eval_result_t *result,
                                    st_netargv_view_t input) {
  for (size_t i = 0; i < result->suggestion_count; i++) {
    st_policy_t *policy = st_policy_new(context);
    if (!policy)
      return false;
    bool matches = false;
    bool ok =
        st_policy_add_netpattern_view(
            policy,
            (st_netpattern_view_t){result->suggestions[i].pattern,
                                   result->suggestions[i].pattern_length}) ==
            ST_OK &&
        st_policy_match_view(policy, input, &matches) == ST_OK && matches;
    st_policy_free(policy);
    if (!ok)
      return false;
  }
  return true;
}

static bool check_complete_suggestions(void) {
  static const struct {
    const char *policy, *input;
    size_t length;
  } cases[] = {
      {"tool #size.MiB done", "4:tool,4:10GB,5:extra,",
       sizeof("4:tool,4:10GB,5:extra,") - 1},
      {"tool #size.MiB done", "4:tool,4:10GB,0:,",
       sizeof("4:tool,4:10GB,0:,") - 1},
      {"tool #size.MiB done", "4:tool,4:10GB,3:a b,",
       sizeof("4:tool,4:10GB,3:a b,") - 1},
      {"tool #size.MiB done", "4:tool,4:10GB,3:a\0b,",
       sizeof("4:tool,4:10GB,3:a\0b,") - 1},
      {"tool fixed #size.MiB", "4:tool,5:fixed,4:10GB,",
       sizeof("4:tool,5:fixed,4:10GB,") - 1},
  };
  bool ok = false;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  st_netpattern_t pattern = {0};
  shell_netstring_buffer_t input = {0};
  st_eval_result_t result = {0};
  CHECK(context != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    policy = st_policy_new(context);
    CHECK(policy != NULL);
    CHECK(st_netpattern_from_cpl_owned(cases[i].policy, &pattern) == ST_OK);
    CHECK(st_policy_add_netpattern_view(
              policy, (st_netpattern_view_t){(const char *)pattern.data,
                                             pattern.length}) == ST_OK);
    st_netargv_view_t view = {cases[i].input, cases[i].length};
    CHECK(st_policy_eval_view(policy, view, &result) == ST_OK);
    CHECK(!result.matches && result.suggestion_count == 2 &&
          result.suggestion_error == ST_OK);
    CHECK(suggestions_cover_input(context, &result, view));
    st_netpattern_free(&pattern);
    st_policy_free(policy);
    policy = NULL;
  }
  policy = st_policy_new(context);
  CHECK(policy != NULL);
  unsigned char word[300];
  memset(word, 'a', sizeof(word));
  for (size_t binary = 0; binary < 2; binary++) {
    word[0] = '/';
    word[150] = binary ? '\0' : 'a';
    CHECK(build_tool_netargv(word, sizeof(word), &input));
    st_netargv_view_t view = {(const char *)input.data, input.length};
    CHECK(st_policy_eval_view(policy, view, &result) == ST_OK);
    CHECK(!result.matches && result.suggestion_count == 1 &&
          result.suggestion_error == ST_ERR_LIMIT);
    CHECK(suggestions_cover_input(context, &result, view));
    shell_netstring_buffer_free(&input);
  }
  /* An unclassifiable oversized literal has no representable alternative. */
  memset(word, 'z', sizeof(word));
  CHECK(build_tool_netargv(word, sizeof(word), &input));
  CHECK(st_policy_eval_view(
            policy, (st_netargv_view_t){(const char *)input.data, input.length},
            &result) == ST_OK);
  CHECK(!result.matches && result.suggestion_count == 0 &&
        result.suggestion_error == ST_ERR_LIMIT);
  ok = true;
cleanup:
  shell_netstring_buffer_free(&input);
  st_netpattern_free(&pattern);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return ok;
}

static bool check_late_suggestion_limit(void) {
  bool ok = false;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  shell_netstring_buffer_t input = {0};
  st_netpattern_t exact = {0};
  st_token_t tokens[128] = {0};
  char literal[79];
  memset(literal, 'z', sizeof(literal) - 1);
  literal[sizeof(literal) - 1] = '\0';
  CHECK(context != NULL);
  policy = st_policy_new(context);
  CHECK(policy != NULL);
  size_t total = 0;
  for (size_t i = 0; i < 128; i++) {
    const char *text = i == 0 ? "tool" : i <= 90 ? literal : "1";
    tokens[i] =
        (st_token_t){.text = text,
                     .text_length = i > 1 && i <= 90 ? 28 : strlen(text),
                     .type = ST_TYPE_LITERAL};
    size_t length = 0;
    CHECK(shell_netstring_encoded_length(tokens[i].text_length, &length) ==
          SHELL_NETSTRING_OK);
    total += length;
  }
  CHECK(st_netpattern_encode_owned(tokens, 128, &exact) == ST_OK);
  CHECK(exact.length < ST_MAX_NETPATTERN_LEN);
  input.data = malloc(total);
  CHECK(input.data != NULL);
  input.length = total;
  size_t used = 0;
  for (size_t i = 0; i < 128; i++) {
    size_t written = 0;
    CHECK(shell_netstring_write(input.data + used, total - used, tokens[i].text,
                                tokens[i].text_length,
                                &written) == SHELL_NETSTRING_OK);
    used += written;
  }
  st_eval_result_t result = {0};
  st_netargv_view_t view = {(const char *)input.data, input.length};
  CHECK(st_policy_eval_view(policy, view, &result) == ST_OK);
  /* Widening 37 one-byte numbers to #n exceeds the encoded pattern capacity,
   * but the already completed literal candidate must remain available. */
  CHECK(!result.matches && result.suggestion_count == 1 &&
        result.suggestion_error == ST_ERR_LIMIT);
  CHECK(result.suggestions[0].pattern_length == exact.length &&
        memcmp(result.suggestions[0].pattern, exact.data, exact.length) == 0);
  CHECK(suggestions_cover_input(context, &result, view));
  ok = true;
cleanup:
  st_netpattern_free(&exact);
  shell_netstring_buffer_free(&input);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return ok;
}

static bool check_suggestion_rendering(void) {
  static const struct {
    const char *input;
    const char *other;
    const char *wrong;
    const char *typed;
    st_token_type_t type;
  } cases[] = {
      {"7:install,5:1.2.3,", "7:install,5:2.3.4,", "7:install,3:abc,",
       "install #semver", ST_TYPE_SEMVER},
      {"5:sleep,4:1.5s,", "5:sleep,4:2.5s,", "5:sleep,3:abc,",
       "sleep #duration", ST_TYPE_DURATION},
      {"3:cmd,5:1.5GB,", "3:cmd,5:2.5GB,", "3:cmd,3:abc,", "cmd #size",
       ST_TYPE_SIZE},
  };
  bool ok = false;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  st_netpattern_t expected = {0};
  st_netpattern_t widened_expected = {0};
  st_policy_t *variant_policy = NULL;
  st_token_array_t decoded = {0};
  st_token_array_t variant = {0};
  st_eval_result_t result = {0};
  CHECK(context != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    policy = st_policy_new(context);
    CHECK(policy != NULL);
    CHECK(st_policy_eval_view(
              policy,
              (st_netargv_view_t){cases[i].input, strlen(cases[i].input)},
              &result) == ST_OK);
    CHECK(!result.matches && result.suggestion_error == ST_OK &&
          result.suggestion_count == 2);
    st_netpattern_view_t literal = {result.suggestions[0].pattern,
                                    result.suggestions[0].pattern_length};
    CHECK(st_netpattern_decode_view(literal, &decoded) == ST_OK);
    CHECK(decoded.count == 2 && decoded.tokens[1].type == ST_TYPE_LITERAL);
    st_token_array_free(&decoded);
    st_netpattern_view_t typed = {result.suggestions[1].pattern,
                                  result.suggestions[1].pattern_length};
    CHECK(st_netpattern_from_cpl_owned(cases[i].typed, &expected) == ST_OK);
    CHECK(typed.length == expected.length &&
          memcmp(typed.data, expected.data, typed.length) == 0);
    CHECK(st_netpattern_decode_view(typed, &decoded) == ST_OK);
    CHECK(decoded.count == 2 && decoded.tokens[1].type == cases[i].type);
    st_token_array_free(&decoded);
    CHECK(st_policy_add_netpattern_view(policy, typed) == ST_OK);
    CHECK(check_match(
        policy, (st_netargv_view_t){cases[i].input, strlen(cases[i].input)},
        true));
    CHECK(check_match(
        policy, (st_netargv_view_t){cases[i].other, strlen(cases[i].other)},
        true));
    CHECK(check_match(
        policy, (st_netargv_view_t){cases[i].wrong, strlen(cases[i].wrong)},
        false));
    st_netpattern_free(&expected);
    st_policy_free(policy);
    policy = NULL;
  }

  /* Widening one token must preserve other policy tokens, including metadata,
   * compound parts, and binary literals. These are policy spellings, not
   * classified command payloads. */
#define VARIANT_CASE(cpl, first, second, input, other)                         \
  {                                                                            \
    cpl, {first, second}, {                                                    \
      {input, sizeof(input) - 1}, {other, sizeof(other) - 1}                   \
    }                                                                          \
  }
  static const struct {
    const char *cpl, *widened[2];
    st_netargv_view_t accepted[2];
  } patterns[] = {
      VARIANT_CASE("cmd #n #n", "cmd #val #n", "cmd #n #val",
                   "3:cmd,2:42,2:43,", "3:cmd,2:44,2:45,"),
      VARIANT_CASE("cmd #semver.major #n", "cmd #val #n",
                   "cmd #semver.major #val", "3:cmd,5:1.2.3,2:42,",
                   "3:cmd,5:2.3.4,2:43,"),
      VARIANT_CASE("cmd #size.MiB #n", "cmd #val #n", "cmd #size.MiB #val",
                   "3:cmd,5:10MiB,2:42,", "3:cmd,5:20MiB,2:43,"),
      VARIANT_CASE("cmd pre{#n}post #n", "cmd pre{#val}post #n",
                   "cmd pre{#n}post #val", "3:cmd,9:pre42post,2:43,",
                   "3:cmd,9:pre44post,2:45,"),
      VARIANT_CASE("cmd \"pre\\x00\"{#n}\"\\x00post\" #n",
                   "cmd \"pre\\x00\"{#val}\"\\x00post\" #n",
                   "cmd \"pre\\x00\"{#n}\"\\x00post\" #val",
                   "3:cmd,11:pre\0"
                   "42\0post,2:43,",
                   "3:cmd,11:pre\0"
                   "44\0post,2:45,"),
      VARIANT_CASE("cmd \"a\\x00b\" #n", "cmd \"a\\x00b\" #val", NULL,
                   "3:cmd,3:a\0b,2:42,", "3:cmd,3:a\0b,2:43,"),
      VARIANT_CASE("cmd \"\" #n", "cmd \"\" #val", NULL, "3:cmd,0:,2:42,",
                   "3:cmd,0:,2:43,"),
      VARIANT_CASE("cmd \"a b\" #n", "cmd \"a b\" #val", NULL,
                   "3:cmd,3:a b,2:42,", "3:cmd,3:a b,2:43,"),
      VARIANT_CASE("cmd \"#n\" #n", "cmd \"#n\" #val", NULL, "3:cmd,2:#n,2:42,",
                   "3:cmd,2:#n,2:43,"),
      VARIANT_CASE("cmd \"*\" #n", "cmd \"*\" #val", NULL, "3:cmd,1:*,2:42,",
                   "3:cmd,1:*,2:43,"),
      VARIANT_CASE("cmd \"#size.MiB\" #n", "cmd \"#size.MiB\" #val", NULL,
                   "3:cmd,9:#size.MiB,2:42,", "3:cmd,9:#size.MiB,2:43,"),
      VARIANT_CASE("cmd \"*\" \"a\\x00b\"", NULL, NULL, "3:cmd,1:*,3:a\0b,",
                   "3:cmd,1:*,3:a\0b,"),
  };
#undef VARIANT_CASE
  policy = st_policy_new(context);
  CHECK(policy != NULL);
  for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
    st_error_t error = st_netpattern_from_cpl_owned(patterns[i].cpl, &expected);
    if (error != ST_OK)
      fprintf(stderr, "suggestion fixture rejected: %s (%d)\n", patterns[i].cpl,
              error);
    CHECK(error == ST_OK);
    CHECK(st_netpattern_decode_view(
              (st_netpattern_view_t){(const char *)expected.data,
                                     expected.length},
              &decoded) == ST_OK);
    CHECK(st_policy_clear(policy) == ST_OK);
    CHECK(st_policy_add_netpattern_view(
              policy, (st_netpattern_view_t){(const char *)expected.data,
                                             expected.length}) == ST_OK);
    for (size_t probe = 0; probe < 2; probe++)
      CHECK(check_match(policy, patterns[i].accepted[probe], true));
    st_expand_suggestion_t variants[3] = {0};
    size_t count = st_policy_suggest_variants(policy, decoded.tokens,
                                              decoded.count, variants);
    CHECK(count == 1u + (patterns[i].widened[0] != NULL) +
                       (patterns[i].widened[1] != NULL));
    char literal_input[1024];
    size_t literal_length = 0;
    for (size_t j = 0; j < decoded.count; j++) {
      size_t written = 0;
      CHECK(shell_netstring_write(
                literal_input + literal_length,
                sizeof(literal_input) - literal_length, decoded.tokens[j].text,
                decoded.tokens[j].text_length, &written) == SHELL_NETSTRING_OK);
      literal_length += written;
    }
    for (size_t j = 0; j < count; j++) {
      st_netpattern_view_t view = {variants[j].pattern,
                                   variants[j].pattern_length};
      CHECK(st_netpattern_validate_view(view, NULL) == ST_OK);
      CHECK(st_netpattern_decode_view(view, &variant) == ST_OK);
      CHECK(variant.count == decoded.count);
      if (j == 0) {
        for (size_t k = 0; k < decoded.count; k++)
          CHECK(!variant.tokens[k].compound &&
                variant.tokens[k].type == ST_TYPE_LITERAL &&
                variant.tokens[k].text_length ==
                    decoded.tokens[k].text_length &&
                memcmp(variant.tokens[k].text, decoded.tokens[k].text,
                       decoded.tokens[k].text_length) == 0);
      } else {
        CHECK(st_netpattern_from_cpl_owned(patterns[i].widened[j - 1],
                                           &widened_expected) == ST_OK);
        CHECK(view.length == widened_expected.length &&
              memcmp(view.data, widened_expected.data, view.length) == 0);
        st_netpattern_free(&widened_expected);
      }
      variant_policy = st_policy_new(context);
      CHECK(variant_policy != NULL);
      CHECK(st_policy_add_netpattern_view(variant_policy, view) == ST_OK);
      if (j == 0)
        CHECK(check_match(variant_policy,
                          (st_netargv_view_t){literal_input, literal_length},
                          true));
      else
        for (size_t probe = 0; probe < 2; probe++)
          CHECK(check_match(variant_policy, patterns[i].accepted[probe], true));
      st_policy_free(variant_policy);
      variant_policy = NULL;
      st_token_array_free(&variant);
    }
    st_token_array_free(&decoded);
    st_netpattern_free(&expected);
  }
  ok = true;
cleanup:
  st_token_array_free(&variant);
  st_token_array_free(&decoded);
  st_netpattern_free(&expected);
  st_netpattern_free(&widened_expected);
  st_policy_free(variant_policy);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return ok;
}

static bool check_contextual_policy_subsumption(void) {
  static const struct {
    const char *exact, *general, *input;
    size_t length;
  } cases[] = {
      {"kill 9", "kill #n", "4:kill,1:9,", sizeof("4:kill,1:9,") - 1},
      {"grep /tmp/x", "grep #p", "4:grep,6:/tmp/x,",
       sizeof("4:grep,6:/tmp/x,") - 1},
      {"cmd -s 9", "cmd -s #n", "3:cmd,2:-s,1:9,",
       sizeof("3:cmd,2:-s,1:9,") - 1},
      {"cmd -e /tmp/x", "cmd -e #p", "3:cmd,2:-e,6:/tmp/x,",
       sizeof("3:cmd,2:-e,6:/tmp/x,") - 1},
      {"cmd --value=9", "cmd #lopt", "3:cmd,9:--value=9,",
       sizeof("3:cmd,9:--value=9,") - 1},
      {"cmd #opt 9", "cmd #opt #n", "3:cmd,2:-s,1:9,",
       sizeof("3:cmd,2:-s,1:9,") - 1},
      {"grep \"/tmp/x\\x00y\"", "grep #p", "4:grep,8:/tmp/x\0y,",
       sizeof("4:grep,8:/tmp/x\0y,") - 1},
  };
  bool ok = false, file_created = false;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  st_netpattern_t exact = {0}, general = {0};
  char path[] = "/tmp/shellclave-context-policy-XXXXXX";
  CHECK(context != NULL);
  int fd = mkstemp(path);
  CHECK(fd >= 0);
  file_created = true;
  CHECK(close(fd) == 0);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    CHECK(st_netpattern_from_cpl_owned(cases[i].exact, &exact) == ST_OK);
    CHECK(st_netpattern_from_cpl_owned(cases[i].general, &general) == ST_OK);
    st_netpattern_view_t views[] = {{exact.data, exact.length},
                                    {general.data, general.length}};
    st_netargv_view_t input = {cases[i].input, cases[i].length};
    for (unsigned mode = 0; mode < 4; mode++) {
      policy = st_policy_new(context);
      CHECK(policy != NULL);
      unsigned first = mode & 1u;
      if (mode < 2) {
        CHECK(st_policy_add_netpattern_view(policy, views[first]) == ST_OK);
        CHECK(check_match(policy, input, first == 0));
        bool covered = true;
        CHECK(st_policy_simulate_add_netpattern_view(policy, views[1 - first],
                                                     &covered, NULL) == ST_OK &&
              !covered);
        CHECK(st_policy_add_netpattern_view(policy, views[1 - first]) == ST_OK);
      } else {
        st_netpattern_view_t batch[] = {views[first], views[1 - first]};
        CHECK(st_policy_batch_add_netpattern_views(policy, batch, 2) == ST_OK);
      }
      CHECK(check_match(policy, input, true));
      CHECK(st_policy_compact(policy) == ST_OK);
      CHECK(check_match(policy, input, true));
      CHECK(st_policy_save(policy, path) == ST_OK);
      CHECK(st_policy_clear(policy) == ST_OK);
      CHECK(st_policy_load(policy, path, true) == ST_OK);
      CHECK(check_match(policy, input, true));
      st_policy_free(policy);
      policy = NULL;
    }
    st_netpattern_free(&exact);
    st_netpattern_free(&general);
  }
  ok = true;
cleanup:
  st_policy_free(policy);
  st_policy_ctx_release(context);
  st_netpattern_free(&exact);
  st_netpattern_free(&general);
  if (file_created)
    unlink(path);
  return ok;
}

static bool check_literal_editor_choices(void) {
  static const struct {
    const char *cpl, *input;
    size_t length, pos;
    st_token_type_t first_type;
  } cases[] = {
      {"timeout 42 ls", "7:timeout,2:42,2:ls,",
       sizeof("7:timeout,2:42,2:ls,") - 1, 1, ST_TYPE_NUMBER},
      {"emit \"two words\" 42", "4:emit,9:two words,2:42,",
       sizeof("4:emit,9:two words,2:42,") - 1, 2, ST_TYPE_NUMBER},
      {"emit \"#n\"", "4:emit,2:#n,", sizeof("4:emit,2:#n,") - 1, 1,
       ST_TYPE_ANY},
      {"tool zzz", "4:tool,3:zzz,", sizeof("4:tool,3:zzz,") - 1, 1,
       ST_TYPE_ANY},
      {"tool \"\"", "4:tool,0:,", sizeof("4:tool,0:,") - 1, 1, ST_TYPE_ANY},
      {"tool \"a\\x00b\"", "4:tool,3:a\0b,", sizeof("4:tool,3:a\0b,") - 1, 1,
       ST_TYPE_ANY},
      {"kill 9", "4:kill,1:9,", sizeof("4:kill,1:9,") - 1, 1, ST_TYPE_SIGNAL},
      {"grep /tmp/x", "4:grep,6:/tmp/x,", sizeof("4:grep,6:/tmp/x,") - 1, 1,
       ST_TYPE_REGEX},
      {"cmd --flag --value=9", "3:cmd,6:--flag,9:--value=9,",
       sizeof("3:cmd,6:--flag,9:--value=9,") - 1, 2, ST_TYPE_LONGOPT},
      {"tool #opt 9", "4:tool,2:-s,1:9,", sizeof("4:tool,2:-s,1:9,") - 1, 2,
       ST_TYPE_VALUE},
      {"tool", "4:tool,", sizeof("4:tool,") - 1, 0, ST_TYPE_LITERAL},
  };
  bool ok = false;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  st_netpattern_t pattern = {0}, edited = {0};
  st_token_array_t decoded = {0};
  CHECK(context != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    CHECK(st_netpattern_from_cpl_owned(cases[i].cpl, &pattern) == ST_OK);
    st_netpattern_view_t view = {pattern.data, pattern.length};
    CHECK(st_netpattern_decode_view(view, &decoded) == ST_OK);
    st_token_variant_t choices[ST_TYPE_COUNT] = {0};
    size_t count =
        st_token_variants_at(&decoded, cases[i].pos, choices, ST_TYPE_COUNT);
    CHECK(count > 0);
    size_t typed_pos = decoded.tokens[cases[i].pos].compound ? 0 : 1;
    if (cases[i].first_type == ST_TYPE_LITERAL)
      CHECK(count == 1 && choices[0].type == ST_TYPE_LITERAL);
    else
      CHECK(count > typed_pos &&
            choices[typed_pos].type == cases[i].first_type);
    st_token_variant_t bounded = {0};
    CHECK(st_token_variants_at(&decoded, cases[i].pos, &bounded, 0) == 0);
    CHECK(st_token_variants_at(&decoded, cases[i].pos, &bounded, 1) == 1 &&
          bounded.type == choices[0].type);
    struct {
      st_token_variant_t choice;
      unsigned canary;
    } one = {.canary = 0x51a7u};
    CHECK(st_token_variants_at(&decoded, cases[i].pos, &one.choice, 1) == 1);
    CHECK(one.choice.type == choices[0].type && one.canary == 0x51a7u);
    CHECK(st_token_variants_at(&decoded, decoded.count, choices,
                               ST_TYPE_COUNT) == 0);
    for (size_t j = 0; j < count; j++) {
      for (size_t k = 0; k < j; k++)
        CHECK(choices[k].type != choices[j].type);
      if (choices[j].type == ST_TYPE_LITERAL)
        continue;
      CHECK(st_netpattern_apply_type_at_owned(
                view, cases[i].pos, choices[j].type, &edited) == ST_OK);
      policy = st_policy_new(context);
      CHECK(policy != NULL);
      CHECK(st_policy_add_netpattern_view(
                policy, (st_netpattern_view_t){(const char *)edited.data,
                                               edited.length}) == ST_OK);
      CHECK(check_match(
          policy, (st_netargv_view_t){cases[i].input, cases[i].length}, true));
      st_policy_free(policy);
      policy = NULL;
      st_netpattern_free(&edited);
    }
    if (cases[i].pos == 0 && !decoded.tokens[0].compound) {
      CHECK(st_netpattern_apply_type_at_owned(view, 0, ST_TYPE_ANY, &edited) ==
            ST_ERR_INVALID);
      CHECK(edited.data == NULL && edited.length == 0);
    }
    st_token_array_free(&decoded);
    st_netpattern_free(&pattern);
  }
  CHECK(st_netpattern_from_cpl_owned("pre{#n}post", &pattern) == ST_OK);
  CHECK(st_netpattern_decode_view(
            (st_netpattern_view_t){(const char *)pattern.data, pattern.length},
            &decoded) == ST_OK);
  st_token_variant_t invalid_head[ST_MAX_TOKEN_VARIANTS] = {0};
  CHECK(st_token_variants_at(&decoded, 0, invalid_head,
                             ST_MAX_TOKEN_VARIANTS) == 0);
  CHECK(st_netpattern_apply_type_at_owned(
            (st_netpattern_view_t){(const char *)pattern.data, pattern.length},
            0, ST_TYPE_VALUE, &edited) == ST_ERR_INVALID);
  ok = true;
cleanup:
  st_policy_free(policy);
  st_policy_ctx_release(context);
  st_token_array_free(&decoded);
  st_netpattern_free(&pattern);
  st_netpattern_free(&edited);
  return ok;
}

static bool check_compound_miner_choices(void) {
  static const struct {
    const char *cpl, *input;
    size_t length;
    st_token_type_t widened;
  } cases[] = {
      {"tool pre{#n}post", "4:tool,9:pre42post,",
       sizeof("4:tool,9:pre42post,") - 1, ST_TYPE_VALUE},
      {"tool pre{#size.MiB}post", "4:tool,12:pre10MiBpost,",
       sizeof("4:tool,12:pre10MiBpost,") - 1, ST_TYPE_VALUE},
      {"tool pre{#p}post", "4:tool,13:pre/tmp/xpost,",
       sizeof("4:tool,13:pre/tmp/xpost,") - 1, ST_TYPE_PATH},
      {"tool \"pre\\x00\"{#n}\"\\x00post\"",
       "4:tool,11:pre\0"
       "42\0post,",
       sizeof("4:tool,11:pre\0"
              "42\0post,") -
           1,
       ST_TYPE_VALUE},
  };
  bool ok = false;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  st_netpattern_t pattern = {0};
  st_token_array_t decoded = {0}, changed = {0};
  CHECK(context != NULL);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    policy = st_policy_new(context);
    CHECK(policy != NULL);
    CHECK(st_netpattern_from_cpl_owned(cases[i].cpl, &pattern) == ST_OK);
    CHECK(
        st_netpattern_decode_view(
            (st_netpattern_view_t){(const char *)pattern.data, pattern.length},
            &decoded) == ST_OK);
    st_expand_suggestion_t choices[3] = {0};
    size_t count = st_policy_suggest_variants(policy, decoded.tokens,
                                              decoded.count, choices);
    CHECK(count == 2);
    st_netpattern_view_t widened = {choices[1].pattern,
                                    choices[1].pattern_length};
    CHECK(st_netpattern_decode_view(widened, &changed) == ST_OK);
    const st_token_t *before = &decoded.tokens[1], *after = &changed.tokens[1];
    CHECK(after->compound && after->capture_type == cases[i].widened &&
          after->prefix_length == before->prefix_length &&
          after->suffix_length == before->suffix_length &&
          memcmp(after->prefix, before->prefix, before->prefix_length) == 0 &&
          memcmp(after->suffix, before->suffix, before->suffix_length) == 0);
    CHECK(st_policy_add_netpattern_view(policy, widened) == ST_OK);
    CHECK(check_match(
        policy, (st_netargv_view_t){cases[i].input, cases[i].length}, true));
    st_token_array_free(&changed);
    st_token_array_free(&decoded);
    st_netpattern_free(&pattern);
    st_policy_free(policy);
    policy = NULL;
  }
  ok = true;
cleanup:
  st_policy_free(policy);
  st_policy_ctx_release(context);
  st_token_array_free(&changed);
  st_token_array_free(&decoded);
  st_netpattern_free(&pattern);
  return ok;
}

/* Query decoded canonical tokens with exact-size, unterminated component
 * storage as well as decoder-owned C strings. The explicit span contract is
 * unchanged; only the spare terminator is removed. */
static bool learner_choices_are(st_learner_t *learner, const char *cpl,
                                size_t position,
                                const st_token_type_t *expected,
                                size_t expected_count) {
  bool ok = false;
  st_netpattern_t pattern = {0}, edited = {0};
  st_token_array_t decoded = {0};
  CHECK(st_netpattern_from_cpl_owned(cpl, &pattern) == ST_OK);
  CHECK(st_netpattern_decode_view(
            (st_netpattern_view_t){(const char *)pattern.data, pattern.length},
            &decoded) == ST_OK);
  for (unsigned terminated = 1;; terminated--) {
    st_token_variant_t choices[ST_MAX_TOKEN_VARIANTS];
    size_t count =
        st_learner_suggest_token_variants(learner, &decoded, position, choices);
    if (count != expected_count) {
      fprintf(stderr, "learner query %s: got %zu choices, expected %zu\n", cpl,
              count, expected_count);
      for (size_t i = 0; i < count; i++)
        fprintf(stderr, "  %s\n", choices[i].type_symbol);
    }
    CHECK(count == expected_count);
    for (size_t i = 0; i < count; i++) {
      CHECK(choices[i].type == expected[i] &&
            strcmp(choices[i].type_symbol, st_type_symbol[expected[i]]) == 0);
      CHECK(st_netpattern_apply_type_at_owned(
                (st_netpattern_view_t){(const char *)pattern.data,
                                       pattern.length},
                position, choices[i].type, &edited) == ST_OK);
      CHECK(
          st_netpattern_validate_view(
              (st_netpattern_view_t){(const char *)edited.data, edited.length},
              NULL) == ST_OK);
      st_netpattern_free(&edited);
    }
    if (!terminated)
      break;
    for (size_t i = 0; i < decoded.count; i++) {
      st_token_t *token = &decoded.tokens[i];
      const char **components[] = {&token->text, &token->prefix,
                                   &token->capture, &token->suffix};
      size_t lengths[] = {token->text_length, token->prefix_length,
                          token->capture_length, token->suffix_length};
      for (size_t j = 0; j < 4; j++) {
        if (!lengths[j])
          continue;
        char *bytes = malloc(lengths[j]);
        CHECK(bytes != NULL);
        memcpy(bytes, *components[j], lengths[j]);
        free((void *)*components[j]);
        *components[j] = bytes;
      }
    }
  }
  ok = true;
cleanup:
  st_token_array_free(&decoded);
  st_netpattern_free(&pattern);
  st_netpattern_free(&edited);
  return ok;
}

static bool check_binary_punctuation_classification(void) {
  static const struct {
    const char *word;
    size_t length;
    st_token_type_t standalone, contextual;
  } cases[] = {
      {"ab", 2, ST_TYPE_LITERAL, ST_TYPE_LITERAL},
      {"a\0b", 3, ST_TYPE_LITERAL, ST_TYPE_LITERAL},
      {"\0ab", 3, ST_TYPE_LITERAL, ST_TYPE_LITERAL},
      {"ab\0", 3, ST_TYPE_LITERAL, ST_TYPE_LITERAL},
      {"\0", 1, ST_TYPE_LITERAL, ST_TYPE_LITERAL},
      {"*x", 2, ST_TYPE_GLOB, ST_TYPE_REGEX},
      {"*\0x", 3, ST_TYPE_GLOB, ST_TYPE_REGEX},
      {"\0*x", 3, ST_TYPE_GLOB, ST_TYPE_REGEX},
      {"*x\0", 3, ST_TYPE_GLOB, ST_TYPE_REGEX},
      {"a\0?", 3, ST_TYPE_GLOB, ST_TYPE_REGEX},
      {"[a\0b]", 5, ST_TYPE_GLOB, ST_TYPE_REGEX},
      {"[a\0b", 4, ST_TYPE_LITERAL, ST_TYPE_REGEX},
      {"a\0^", 3, ST_TYPE_LITERAL, ST_TYPE_REGEX},
      {"a\0/", 3, ST_TYPE_REL_PATH, ST_TYPE_REGEX},
      {"*\0|", 3, ST_TYPE_LITERAL, ST_TYPE_REGEX},
      {"*\0&", 3, ST_TYPE_LITERAL, ST_TYPE_REGEX},
      {"a\0&", 3, ST_TYPE_LITERAL, ST_TYPE_LITERAL},
      {"a\xff\0b", 4, ST_TYPE_LITERAL, ST_TYPE_LITERAL},
  };
  bool ok = false;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  st_netpattern_t pattern = {0};
  st_token_array_t classified = {0};
  shell_netstring_buffer_t input = {0};
  CHECK(context != NULL);
  for (unsigned regex = 0; regex < 2; regex++) {
    policy = st_policy_new(context);
    CHECK(policy != NULL);
    CHECK(st_netpattern_from_cpl_owned(regex ? "grep #regex" : "tool #glob",
                                       &pattern) == ST_OK);
    CHECK(st_policy_add_netpattern_view(
              policy, (st_netpattern_view_t){(const char *)pattern.data,
                                             pattern.length}) == ST_OK);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      CHECK(build_tool_netargv(cases[i].word, cases[i].length, &input));
      if (regex)
        memcpy(input.data + 2, "grep", 4);
      st_netargv_view_t argv = {(char *)input.data, input.length};
      CHECK(st_netargv_classify_view(argv, &classified) == ST_OK);
      st_token_type_t expected =
          regex ? cases[i].contextual : cases[i].standalone;
      if (classified.count == 2 && classified.tokens[1].type != expected)
        fprintf(
            stderr,
            "binary punctuation case %zu, regex context %u: %s, expected %s\n",
            i, regex, st_type_symbol[classified.tokens[1].type],
            st_type_symbol[expected]);
      CHECK(classified.count == 2 && classified.tokens[1].type == expected &&
            classified.tokens[1].text_length == cases[i].length &&
            memcmp(classified.tokens[1].text, cases[i].word, cases[i].length) ==
                0);
      visit_state_t state = {&classified, 0};
      size_t visited = 0;
      CHECK(st_netargv_visit_view(argv, compare_token, &state, &visited) ==
                ST_OK &&
            visited == 2 && state.seen == 2);
      CHECK(check_match(policy, argv,
                        expected == (regex ? ST_TYPE_REGEX : ST_TYPE_GLOB)));
      st_token_array_free(&classified);
      shell_netstring_buffer_free(&input);
    }
    st_netpattern_free(&pattern);
    st_policy_free(policy);
    policy = NULL;
  }
  ok = true;
cleanup:
  st_token_array_free(&classified);
  shell_netstring_buffer_free(&input);
  st_netpattern_free(&pattern);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return ok;
}

/* Parameter predicates and learner evidence share their semantics, not their
 * mechanics: policies inspect values, while queries use retained bucket facts.
 * Test every family, both feed orders and framed persistence, including mixed
 * observations for which value-specific evidence cannot be established. */
static bool check_parameterized_learner_prefixes(void) {
  static const char sha40[] = "abcdef0123456789"
                              "abcdef0123456789"
                              "abcdef01";
  static const char sha64[] = "abcdef0123456789"
                              "abcdef0123456789"
                              "abcdef0123456789"
                              "abcdef0123456789";
  static const char fp_sha[] =
      "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
  static const char fp_md5[] =
      "ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89";
  static const struct {
    const char *cpl, *matching, *other;
    st_token_type_t type;
    bool type_wide;
  } cases[] = {
      {"tool #size.MiB #val", "10MiB", "10GiB", ST_TYPE_SIZE, false},
      {"tool #size.bytes #val", "10bytes", "10B", ST_TYPE_SIZE, false},
      {"tool #size.b #val", "10b", "10K", ST_TYPE_SIZE, false},
      {"tool #duration.ms #val", "10ms", "10s", ST_TYPE_DURATION, false},
      {"tool #duration.h #val", "-1.5h", "10ms", ST_TYPE_DURATION, false},
      {"tool #uuid.v4 #val", "550e8400-e29b-41d4-a716-446655440000",
       "550e8400-e29b-51d4-a716-446655440000", ST_TYPE_UUID, false},
      {"tool #uuid.4 #val", "550e8400-e29b-41d4-a716-446655440000",
       "550e8400-e29b-11d4-a716-446655440000", ST_TYPE_UUID, false},
      {"tool #uuid.v5 #val", "550e8400-e29b-51d4-a716-446655440000",
       "550e8400-e29b-41d4-a716-446655440000", ST_TYPE_UUID, false},
      {"tool #semver.major #val", "1.2.3", "2.7.1-beta+build", ST_TYPE_SEMVER,
       true},
      {"tool #semver.minor #val", "1.2.3", "2.7.1-beta+build", ST_TYPE_SEMVER,
       true},
      {"tool #semver.patch #val", "1.2.3", "2.7.1-beta+build", ST_TYPE_SEMVER,
       true},
      {"tool #semver.* #val", "1.2.3", "2.7.1-beta+build", ST_TYPE_SEMVER,
       true},
      {"tool #ts.date #val", "2026-10-05", "12:34:56", ST_TYPE_TIMESTAMP,
       false},
      {"tool #ts.time #val", "12:34:56", "2026-10-05", ST_TYPE_TIMESTAMP,
       false},
      {"tool #ts.datetime #val", "2026-10-05T12:34:56Z", "2026-10-05",
       ST_TYPE_TIMESTAMP, false},
      {"tool #ts.datetime #val", "2026-10-05t12:34:56Z", "2026-10-05",
       ST_TYPE_TIMESTAMP, false},
      {"tool #ts.datetime #val", "2026-10-05t12:34:56z", "12:34:56",
       ST_TYPE_TIMESTAMP, false},
      {"tool #ts.datetime #val", "2026-10-05t12:34:56+02:30", "12:34:56",
       ST_TYPE_TIMESTAMP, false},
      {"tool #sha.short #val", "abcdef0", sha40, ST_TYPE_SHA, false},
      {"tool #sha.40 #val", sha40, sha64, ST_TYPE_SHA, false},
      {"tool #sha.64 #val", sha64, sha40, ST_TYPE_SHA, false},
      {"tool #sha.64 #val", sha64, "abcdef012", ST_TYPE_SHA, false},
      {"tool #sha.40 #val", sha40, "abcdef012", ST_TYPE_SHA, false},
      {"tool #sha.short #val", "abcdef0", "abcdef012", ST_TYPE_SHA, false},
      {"tool #fp.sha256 #val", fp_sha, fp_md5, ST_TYPE_FINGERPRINT, false},
      {"tool #fp.md5 #val", fp_md5, fp_sha, ST_TYPE_FINGERPRINT, false},
      {"tool #range.step #val", "1-9", "2-8", ST_TYPE_RANGE, true},
      {"tool #perm.bits #val", "0644", "0755", ST_TYPE_PERM_OCTAL, true},
  };
  bool ok = false, file_created = false;
  char path[] = "/tmp/shellclave-public-parameter-XXXXXX";
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  st_learner_t *learner = NULL, *loaded = NULL;
  st_netpattern_t pattern = {0};
  shell_netstring_buffer_t records[3] = {{0}};
  CHECK(context != NULL);
  int descriptor = mkstemp(path);
  CHECK(descriptor >= 0);
  file_created = true;
  CHECK(close(descriptor) == 0);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    const char *words[] = {cases[i].matching, cases[i].other, "zzz"};
    for (size_t j = 0; j < 3; j++) {
      st_token_type_t expected_type = j < 2 ? cases[i].type : ST_TYPE_LITERAL;
      if (st_token_classify(words[j], strlen(words[j])) != expected_type)
        fprintf(stderr,
                "parameter query %s: %s classified as %s, expected %s\n",
                cases[i].cpl, words[j],
                st_type_symbol[st_token_classify(words[j], strlen(words[j]))],
                st_type_symbol[expected_type]);
      CHECK(st_token_classify(words[j], strlen(words[j])) == expected_type);
      CHECK(build_tool_netargv(words[j], strlen(words[j]), &records[j]));
      size_t tail = 0;
      CHECK(shell_netstring_encoded_length(2, &tail) == SHELL_NETSTRING_OK);
      unsigned char *bytes = realloc(records[j].data, records[j].length + tail);
      CHECK(bytes != NULL);
      records[j].data = bytes;
      CHECK(shell_netstring_write(bytes + records[j].length, tail, "42", 2,
                                  NULL) == SHELL_NETSTRING_OK);
      records[j].length += tail;
    }
    CHECK(st_netpattern_from_cpl_owned(cases[i].cpl, &pattern) == ST_OK);
    policy = st_policy_new(context);
    CHECK(policy != NULL);
    CHECK(st_policy_add_netpattern_view(
              policy, (st_netpattern_view_t){(const char *)pattern.data,
                                             pattern.length}) == ST_OK);
    for (size_t j = 0; j < 3; j++) {
      bool matches = check_match(
          policy,
          (st_netargv_view_t){(char *)records[j].data, records[j].length},
          j == 0 || (j == 1 && cases[i].type_wide));
      if (!matches)
        fprintf(stderr, "parameter policy %s: unexpected match for %s\n",
                cases[i].cpl, words[j]);
      CHECK(matches);
    }
    for (unsigned selection = 0; selection < 8; selection++) {
      for (unsigned reverse = 0; reverse < 2; reverse++) {
        learner = st_learner_new(NULL);
        loaded = st_learner_new(NULL);
        CHECK(learner != NULL && loaded != NULL);
        for (size_t j = 0; j < 3; j++) {
          size_t index = reverse ? 2 - j : j;
          if (selection & (1u << index))
            CHECK(st_learner_feed_netargv_view(
                      learner, (st_netargv_view_t){(char *)records[index].data,
                                                   records[index].length}) ==
                  ST_OK);
        }
        /* Unrelated literal buckets neither prove a type-wide predicate nor
         * contaminate the evidence retained by a matching typed bucket. */
        unsigned typed_selection = selection & 3u;
        bool observed =
            cases[i].type_wide ? typed_selection != 0 : typed_selection == 1;
        st_token_type_t expected[] = {observed ? ST_TYPE_NUMBER : ST_TYPE_VALUE,
                                      ST_TYPE_ANY};
        CHECK(learner_choices_are(learner, cases[i].cpl, 2, expected, 2));
        CHECK(st_learner_save(learner, path) == ST_OK);
        CHECK(st_learner_load(loaded, path) == ST_OK);
        CHECK(learner_choices_are(loaded, cases[i].cpl, 2, expected, 2));
        st_learner_free(learner);
        st_learner_free(loaded);
        learner = loaded = NULL;
      }
    }
    st_netpattern_free(&pattern);
    st_policy_free(policy);
    policy = NULL;
    for (size_t j = 0; j < 3; j++)
      shell_netstring_buffer_free(&records[j]);
  }
  ok = true;
cleanup:
  st_netpattern_free(&pattern);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  st_learner_free(learner);
  st_learner_free(loaded);
  for (size_t j = 0; j < 3; j++)
    shell_netstring_buffer_free(&records[j]);
  if (file_created)
    (void)unlink(path);
  return ok;
}

/* Weighted replay checks the complete rule, not the classifier bucket that
 * originally supplied it. The records are valid canonical public inputs. */
static bool check_learner_support_rules(st_learner_t *learner,
                                        const char *const *records,
                                        const uint32_t *weights, size_t count,
                                        const char *expected_cpl,
                                        uint32_t expected_support,
                                        double expected_confidence) {
  bool ok = false, found = false;
  st_netpattern_t expected = {0};
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  size_t suggestion_count = 0;
  st_suggestion_t *suggestions = st_learner_suggest(learner, &suggestion_count);
  CHECK(context != NULL);
  CHECK(st_netpattern_from_cpl_owned(expected_cpl, &expected) == ST_OK);
  for (size_t i = 0; i < suggestion_count; i++) {
    st_netpattern_view_t rule = {suggestions[i].pattern,
                                 suggestions[i].pattern_length};
    policy = st_policy_new(context);
    CHECK(policy != NULL &&
          st_policy_add_netpattern_view(policy, rule) == ST_OK);
    uint32_t replay = 0;
    for (size_t j = 0; j < count; j++) {
      bool matched = false;
      CHECK(st_policy_match_view(
                policy, (st_netargv_view_t){records[j], strlen(records[j])},
                &matched) == ST_OK);
      replay += matched ? weights[j] : 0;
    }
    CHECK(replay == suggestions[i].count);
    for (size_t j = 0; j < i; j++)
      CHECK(rule.length != suggestions[j].pattern_length ||
            memcmp(rule.data, suggestions[j].pattern, rule.length) != 0);
    if (rule.length == expected.length &&
        memcmp(rule.data, expected.data, rule.length) == 0) {
      CHECK(suggestions[i].count == expected_support &&
            suggestions[i].confidence == expected_confidence);
      found = true;
    }
    st_policy_free(policy);
    policy = NULL;
  }
  CHECK(found);
  ok = true;
cleanup:
  st_policy_free(policy);
  st_policy_ctx_release(context);
  st_netpattern_free(&expected);
  st_suggestion_list_free(suggestions, suggestion_count);
  return ok;
}

static bool check_learner_overlapping_support(void) {
  static const struct {
    const char *records[8];
    uint32_t weights[8];
    size_t count;
    const char *cpl;
    uint32_t support;
    double confidence;
  } cases[] = {
      {{"4:tool,2:42,", "4:tool,8:a1b2c3d4,"}, {7, 3}, 2, "tool #n", 10, 1.0},
      {{"4:tool,2:42,", "4:tool,8:a1b2c3d4,"}, {8, 2}, 2, "tool #n", 10, 1.0},
      {{"4:tool,2:42,", "4:tool,8:a1b2c3d4,"}, {6, 4}, 2, "tool #val", 10, 1.0},
      /* Independently generated suffixes differ, but #n accepts both. */
      {{"4:tool,2:42,2:43,", "4:tool,8:a1b2c3d4,8:e5f6a7b8,"},
       {7, 3},
       2,
       "tool #n #n",
       10,
       1.0},
      /* An unrelated complete continuation must not inflate support. */
      {{"4:tool,2:42,2:43,", "4:tool,8:a1b2c3d4,8:e5f6a7b8,",
        "4:tool,8:a1b2c3d4,6:/tmp/x,"},
       {7, 3, 10},
       3,
       "tool #n #n",
       10,
       0.5},
      {{"4:tool,2:42,", "4:tool,4:0644,"}, {7, 3}, 2, "tool #n", 10, 1.0},
      {{"4:tool,5:alpha,", "4:tool,4:beta,"}, {7, 3}, 2, "tool *", 10, 1.0},
      /* A literal-family ANY also accepts the classified sibling bucket. */
      {{"4:tool,5:alpha,", "4:tool,4:beta,", "4:tool,2:42,"},
       {4, 4, 2},
       3,
       "tool *",
       10,
       1.0},
      /* A parameter in a sibling continuation has mixed value evidence.
       * Publish its fully accounted type fallback, not an invented partial
       * count for MiB values no longer retained in that bucket. */
      {{"4:tool,2:42,4:1MiB,", "4:tool,8:a1b2c3d4,4:2MiB,",
        "4:tool,8:a1b2c3d4,4:4GiB,"},
       {7, 3, 3},
       3,
       "tool #n #size",
       13,
       1.0},
      /* Uniform incompatible metadata contributes no support. */
      {{"4:tool,2:42,4:1MiB,", "4:tool,8:a1b2c3d4,4:4GiB,"},
       {7, 3},
       2,
       "tool #n #size.MiB",
       7,
       0.7},
      /* A same-prefix shorter command does not match a longer rule. */
      {{"4:tool,2:42,", "4:tool,2:42,2:43,"}, {3, 7}, 2, "tool #n #n", 7, 0.7},
      /* Two precise proposals need the same type fallback. Deduplication must
       * keep it once and safely compact multiple following owned patterns. */
      {{"4:tool,2:42,5:alpha,4:1MiB,", "4:tool,2:42,4:beta,4:2MiB,",
        "4:tool,2:42,5:gamma,4:1GiB,", "4:tool,2:42,5:delta,4:2GiB,",
        "4:tool,8:a1b2c3d4,4:zeta,4:1MiB,", "4:tool,8:a1b2c3d4,4:zeta,4:2GiB,",
        "5:ztool,2:42,", "6:zztool,2:42,"},
       {1, 1, 1, 1, 1, 1, 1, 1},
       8,
       "tool #n * #size",
       6,
       1.0},
  };
  bool ok = false;
  st_learner_t *learner = NULL, *loaded = NULL;
  char path[] = "/tmp/shellclave-public-support-XXXXXX";
  int fd = mkstemp(path);
  CHECK(fd >= 0);
  CHECK(close(fd) == 0);
  fd = -1;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    for (unsigned reverse = 0; reverse < 2; reverse++) {
      st_learner_config_t config = {
          .min_support = 1, .min_confidence = 0, .max_suggestions = 64};
      learner = st_learner_new(&config);
      loaded = st_learner_new(&config);
      CHECK(learner != NULL && loaded != NULL);
      for (size_t j = 0; j < cases[i].count; j++) {
        size_t index = reverse ? cases[i].count - j - 1 : j;
        for (uint32_t n = 0; n < cases[i].weights[index]; n++)
          CHECK(st_learner_feed_netargv_view(
                    learner, (st_netargv_view_t){
                                 cases[i].records[index],
                                 strlen(cases[i].records[index])}) == ST_OK);
      }
      CHECK(check_learner_support_rules(
          learner, cases[i].records, cases[i].weights, cases[i].count,
          cases[i].cpl, cases[i].support, cases[i].confidence));
      CHECK(st_learner_save(learner, path) == ST_OK &&
            st_learner_load(loaded, path) == ST_OK);
      CHECK(check_learner_support_rules(
          loaded, cases[i].records, cases[i].weights, cases[i].count,
          cases[i].cpl, cases[i].support, cases[i].confidence));
      config.min_support = cases[i].support;
      config.min_confidence =
          cases[i].confidence == 1.0 ? 0.8 : cases[i].confidence;
      CHECK(st_learner_set_config(learner, &config) == ST_OK);
      CHECK(check_learner_support_rules(
          learner, cases[i].records, cases[i].weights, cases[i].count,
          cases[i].cpl, cases[i].support, cases[i].confidence));
      /* Raising support past the complete observed history must reject every
       * proposal; filters are applied to the final accounted values. */
      uint32_t total = 0;
      for (size_t j = 0; j < cases[i].count; j++)
        total += cases[i].weights[j];
      config.min_support = total + 1;
      CHECK(st_learner_set_config(learner, &config) == ST_OK);
      size_t excluded_count = 99;
      st_suggestion_t *excluded = st_learner_suggest(learner, &excluded_count);
      bool excluded_ok = excluded == NULL && excluded_count == 0;
      st_suggestion_list_free(excluded, excluded_count);
      CHECK(excluded_ok);
      st_learner_free(learner);
      st_learner_free(loaded);
      learner = loaded = NULL;
    }
  }
  ok = true;
cleanup:
  if (fd >= 0)
    close(fd);
  unlink(path);
  st_learner_free(learner);
  st_learner_free(loaded);
  return ok;
}

static bool check_timestamp_rule(st_learner_t *learner, const char *cpl,
                                 const shell_netstring_buffer_t *records,
                                 size_t first, size_t count,
                                 uint32_t expected_support) {
  bool ok = false;
  st_netpattern_t expected = {0};
  size_t suggestion_count = 0;
  st_suggestion_t *suggestions = st_learner_suggest(learner, &suggestion_count);
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = context ? st_policy_new(context) : NULL;
  CHECK(policy != NULL && suggestions != NULL && suggestion_count == 1);
  CHECK(st_netpattern_from_cpl_owned(cpl, &expected) == ST_OK);
  CHECK(suggestions[0].pattern_length == expected.length &&
        memcmp(suggestions[0].pattern, expected.data, expected.length) == 0 &&
        suggestions[0].count == expected_support);
  CHECK(st_policy_add_netpattern_view(
            policy, (st_netpattern_view_t){suggestions[0].pattern,
                                           suggestions[0].pattern_length}) ==
        ST_OK);
  for (size_t i = first; i < first + count; i++)
    CHECK(check_match(
        policy, (st_netargv_view_t){(char *)records[i].data, records[i].length},
        true));
  ok = true;
cleanup:
  st_policy_free(policy);
  st_policy_ctx_release(context);
  st_suggestion_list_free(suggestions, suggestion_count);
  st_netpattern_free(&expected);
  return ok;
}

static bool check_timestamp_metadata_agreement(void) {
  static const struct {
    const char *value, *cpl, *compound;
  } cases[] = {
      {"2026-10-05", "tool #ts.date", "tool pre{#ts.date}post"},
      {"12:34:56", "tool #ts.time", "tool pre{#ts.time}post"},
      {"2026-10-05T12:34:56", "tool #ts.datetime",
       "tool pre{#ts.datetime}post"},
      {"2026-10-05t12:34:56", "tool #ts.datetime",
       "tool pre{#ts.datetime}post"},
      {"2026-10-05 12:34:56", "tool #ts.datetime",
       "tool pre{#ts.datetime}post"},
      {"2026-10-05T12:34:56Z", "tool #ts.datetime",
       "tool pre{#ts.datetime}post"},
      {"2026-10-05T12:34:56z", "tool #ts.datetime",
       "tool pre{#ts.datetime}post"},
      {"2026-10-05t12:34:56Z", "tool #ts.datetime",
       "tool pre{#ts.datetime}post"},
      {"2026-10-05t12:34:56z", "tool #ts.datetime",
       "tool pre{#ts.datetime}post"},
      {"2026-10-05 12:34:56Z", "tool #ts.datetime",
       "tool pre{#ts.datetime}post"},
      {"2026-10-05t12:34:56+02:30", "tool #ts.datetime",
       "tool pre{#ts.datetime}post"},
      {"2026-10-05t12:34:56-0230", "tool #ts.datetime",
       "tool pre{#ts.datetime}post"},
  };
  const size_t case_count = sizeof(cases) / sizeof(cases[0]);
  bool ok = false, file_created = false;
  char path[] = "/tmp/shellclave-public-timestamp-XXXXXX";
  shell_netstring_buffer_t records[sizeof(cases) / sizeof(cases[0])] = {{0}};
  shell_netstring_buffer_t compound = {0};
  st_token_array_t typed = {0};
  st_netpattern_t pattern = {0};
  st_learner_t *learner = NULL, *loaded = NULL;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  CHECK(context != NULL);
  int descriptor = mkstemp(path);
  CHECK(descriptor >= 0);
  file_created = true;
  CHECK(close(descriptor) == 0);
  for (size_t i = 0; i < case_count; i++) {
    size_t length = strlen(cases[i].value);
    CHECK(build_tool_netargv(cases[i].value, length, &records[i]));
    st_netargv_view_t input = {(char *)records[i].data, records[i].length};
    CHECK(st_netargv_classify_view(input, &typed) == ST_OK);
    CHECK(typed.count == 2 && typed.tokens[1].type == ST_TYPE_TIMESTAMP);
    /* Feed a borrowed exact-size span as well as canonical netargv. No spare
     * terminator is available to the shared value-metadata helper. */
    char *bytes = malloc(length);
    CHECK(bytes != NULL);
    memcpy(bytes, typed.tokens[1].text, length);
    free((void *)typed.tokens[1].text);
    typed.tokens[1].text = bytes;
    learner = st_learner_new(NULL);
    loaded = st_learner_new(NULL);
    CHECK(learner != NULL && loaded != NULL);
    for (size_t repetition = 0; repetition < ST_DEFAULT_MIN_SUPPORT;
         repetition++)
      CHECK((repetition % 2
                 ? st_learner_feed_tokens(learner, &typed)
                 : st_learner_feed_netargv_view(learner, input)) == ST_OK);
    CHECK(check_timestamp_rule(learner, cases[i].cpl, records, i, 1,
                               ST_DEFAULT_MIN_SUPPORT));
    CHECK(st_learner_save(learner, path) == ST_OK);
    CHECK(st_learner_load(loaded, path) == ST_OK);
    CHECK(check_timestamp_rule(loaded, cases[i].cpl, records, i, 1,
                               ST_DEFAULT_MIN_SUPPORT));
    st_learner_free(learner);
    st_learner_free(loaded);
    learner = loaded = NULL;
    st_token_array_free(&typed);

    CHECK(st_netpattern_from_cpl_owned(cases[i].compound, &pattern) == ST_OK);
    policy = st_policy_new(context);
    CHECK(policy != NULL);
    CHECK(st_policy_add_netpattern_view(
              policy, (st_netpattern_view_t){(const char *)pattern.data,
                                             pattern.length}) == ST_OK);
    for (size_t j = 0; j < case_count; j++) {
      char word[64];
      size_t value_length = strlen(cases[j].value);
      memcpy(word, "pre", 3);
      memcpy(word + 3, cases[j].value, value_length);
      memcpy(word + 3 + value_length, "post", 4);
      CHECK(build_tool_netargv(word, value_length + 7, &compound));
      CHECK(check_match(
          policy, (st_netargv_view_t){(char *)compound.data, compound.length},
          strcmp(cases[i].cpl, cases[j].cpl) == 0));
      shell_netstring_buffer_free(&compound);
      /* A NUL within a would-be timestamp must not make metadata matching
       * operate on a shortened capture. */
      word[3 + value_length / 2] = '\0';
      CHECK(build_tool_netargv(word, value_length + 7, &compound));
      CHECK(check_match(
          policy, (st_netargv_view_t){(char *)compound.data, compound.length},
          false));
      shell_netstring_buffer_free(&compound);
    }
    st_policy_free(policy);
    policy = NULL;
    st_netpattern_free(&pattern);
  }
  for (unsigned reverse = 0; reverse < 2; reverse++) {
    learner = st_learner_new(NULL);
    loaded = st_learner_new(NULL);
    CHECK(learner != NULL && loaded != NULL);
    for (size_t i = 0; i < case_count; i++) {
      size_t index = reverse ? case_count - i - 1 : i;
      CHECK(st_learner_feed_netargv_view(
                learner, (st_netargv_view_t){(char *)records[index].data,
                                             records[index].length}) == ST_OK);
    }
    CHECK(check_timestamp_rule(learner, "tool #ts", records, 0, case_count,
                               (uint32_t)case_count));
    CHECK(st_learner_save(learner, path) == ST_OK);
    CHECK(st_learner_load(loaded, path) == ST_OK);
    CHECK(check_timestamp_rule(loaded, "tool #ts", records, 0, case_count,
                               (uint32_t)case_count));
    st_learner_free(learner);
    st_learner_free(loaded);
    learner = loaded = NULL;
  }
  ok = true;
cleanup:
  st_policy_free(policy);
  st_policy_ctx_release(context);
  st_learner_free(learner);
  st_learner_free(loaded);
  st_token_array_free(&typed);
  st_netpattern_free(&pattern);
  for (size_t i = 0; i < case_count; i++)
    shell_netstring_buffer_free(&records[i]);
  shell_netstring_buffer_free(&compound);
  if (file_created)
    (void)unlink(path);
  return ok;
}

static bool check_learner_prefix_and_capture_choices(void) {
  static const char literal_path[] = "4:tool,9:pre42post,6:/tmp/x,";
  static const char literal_signal[] = "4:tool,10:preHUPpost,8:../rel/x,";
  static const char literal_size[] = "4:tool,12:pre10MiBpost,6:/tmp/x,";
  static const char literal_other_size[] = "4:tool,12:pre10GiBpost,2:42,";
  static const char literal_datetime[] =
      "4:tool,28:tag=2026-10-05t12:34:56Zpost,6:/tmp/x,";
  static const char literal_date[] = "4:tool,18:tag=2026-10-05post,2:42,";
  static const char typed_path[] = "4:tool,6:/tmp/a,2:42,";
  static const char other_typed_path[] = "4:tool,6:/tmp/b,10:https://xy,";
  static const char typed_size[] = "4:tool,5:10MiB,6:/tmp/x,";
  static const char other_typed_size[] = "4:tool,5:10GiB,2:42,";
  static const char wrong_affix[] = "4:tool,9:pre42poXX,6:/tmp/x,";
  static const char empty_capture[] = "4:tool,7:prepost,6:/tmp/x,";
  static const char whole_word_path[] = "4:tool,13:pre/tmp/xpost,6:/tmp/x,";
  static const char output_path[] = "4:tool,15:--output=/tmp/x,6:/tmp/x,";
  static const char binary_affixes[] = "4:tool,11:pre\0"
                                       "42\0post,6:/tmp/x,";
  static const char binary_capture[] = "4:tool,11:pre42\0xpost,6:/tmp/x,";
  static const char binary_path[] = "4:tool,8:/tmp/a\0b,2:42,";
  static const char signal_context[] = "4:kill,1:9,6:/tmp/x,";
  static const char regex_context[] = "4:grep,6:/tmp/a,2:42,";
  static const char unknown_context[] = "2:-s,1:9,6:/tmp/x,";
  static const struct {
    const char *cpl;
    size_t position;
    st_netargv_view_t records[2];
    st_token_type_t expected[ST_MAX_TOKEN_VARIANTS];
    size_t count;
  } cases[] = {
      {"tool pre{#p}post",
       1,
       {{0}},
       {ST_TYPE_ABS_PATH, ST_TYPE_PATH, ST_TYPE_ANY},
       3},
      {"tool pre{#size.MiB}post", 1, {{0}}, {ST_TYPE_SIZE, ST_TYPE_ANY}, 2},
      {"tool pre{#n}post",
       1,
       {{literal_path, sizeof(literal_path) - 1},
        {literal_signal, sizeof(literal_signal) - 1}},
       {ST_TYPE_NUMBER, ST_TYPE_SIGNAL, ST_TYPE_ANY},
       3},
      {"tool pre{#path}post",
       1,
       {{wrong_affix, sizeof(wrong_affix) - 1}},
       {ST_TYPE_PATH, ST_TYPE_ANY},
       2},
      {"tool pre{#path}post",
       1,
       {{empty_capture, sizeof(empty_capture) - 1}},
       {ST_TYPE_ANY},
       1},
      {"tool pre{#n}post",
       1,
       {{whole_word_path, sizeof(whole_word_path) - 1}},
       {ST_TYPE_NUMBER, ST_TYPE_ANY},
       2},
      {"tool --output={#p}",
       1,
       {{output_path, sizeof(output_path) - 1}},
       {ST_TYPE_ABS_PATH, ST_TYPE_PATH, ST_TYPE_ANY},
       3},
      {"tool --output={#p} #val",
       2,
       {{output_path, sizeof(output_path) - 1}},
       {ST_TYPE_ABS_PATH, ST_TYPE_ANY},
       2},
      {"tool pre{#n}post",
       1,
       {{binary_capture, sizeof(binary_capture) - 1}},
       {ST_TYPE_ANY},
       1},
      {"tool pre42post #val",
       2,
       {{literal_path, sizeof(literal_path) - 1},
        {literal_signal, sizeof(literal_signal) - 1}},
       {ST_TYPE_ABS_PATH, ST_TYPE_ANY},
       2},
      {"tool pre{#n}post #val",
       2,
       {{literal_path, sizeof(literal_path) - 1},
        {literal_signal, sizeof(literal_signal) - 1}},
       {ST_TYPE_ABS_PATH, ST_TYPE_ANY},
       2},
      {"tool pre{#size.MiB}post #val",
       2,
       {{literal_size, sizeof(literal_size) - 1},
        {literal_other_size, sizeof(literal_other_size) - 1}},
       {ST_TYPE_ABS_PATH, ST_TYPE_ANY},
       2},
      {"tool tag={#ts.datetime}post #val",
       2,
       {{literal_datetime, sizeof(literal_datetime) - 1},
        {literal_date, sizeof(literal_date) - 1}},
       {ST_TYPE_ABS_PATH, ST_TYPE_ANY},
       2},
      {"tool pre{#path}post #val",
       2,
       {{literal_path, sizeof(literal_path) - 1}},
       {ST_TYPE_VALUE, ST_TYPE_ANY},
       2},
      {"tool * #val",
       2,
       {{literal_path, sizeof(literal_path) - 1},
        {typed_path, sizeof(typed_path) - 1}},
       {ST_TYPE_NUMBER, ST_TYPE_ABS_PATH, ST_TYPE_ANY},
       3},
      {"tool /tmp/a #val",
       2,
       {{typed_path, sizeof(typed_path) - 1},
        {other_typed_path, sizeof(other_typed_path) - 1}},
       {ST_TYPE_NUMBER, ST_TYPE_URL, ST_TYPE_ANY},
       3},
      {"tool #p #val",
       2,
       {{typed_path, sizeof(typed_path) - 1}},
       {ST_TYPE_NUMBER, ST_TYPE_ANY},
       2},
      {"tool #size.MiB #val",
       2,
       {{typed_size, sizeof(typed_size) - 1}},
       {ST_TYPE_ABS_PATH, ST_TYPE_ANY},
       2},
      {"tool #size.GiB #val",
       2,
       {{typed_size, sizeof(typed_size) - 1}},
       {ST_TYPE_VALUE, ST_TYPE_ANY},
       2},
      {"tool #size.MiB #val",
       2,
       {{typed_size, sizeof(typed_size) - 1},
        {other_typed_size, sizeof(other_typed_size) - 1}},
       {ST_TYPE_VALUE, ST_TYPE_ANY},
       2},
      {"tool \"pre\\x00\"{#n}\"\\x00post\"",
       1,
       {{binary_affixes, sizeof(binary_affixes) - 1}},
       {ST_TYPE_NUMBER, ST_TYPE_ANY},
       2},
      {"tool \"pre\\x00\"{#n}\"\\x00post\" #val",
       2,
       {{binary_affixes, sizeof(binary_affixes) - 1}},
       {ST_TYPE_ABS_PATH, ST_TYPE_ANY},
       2},
      {"tool \"/tmp/a\\x00b\" #val",
       2,
       {{binary_path, sizeof(binary_path) - 1}},
       {ST_TYPE_NUMBER, ST_TYPE_ANY},
       2},
      {"kill 9 #val",
       2,
       {{signal_context, sizeof(signal_context) - 1}},
       {ST_TYPE_ABS_PATH, ST_TYPE_ANY},
       2},
      {"grep /tmp/a #val",
       2,
       {{regex_context, sizeof(regex_context) - 1}},
       {ST_TYPE_NUMBER, ST_TYPE_ANY},
       2},
      {"#val 9 #val",
       2,
       {{unknown_context, sizeof(unknown_context) - 1}},
       {ST_TYPE_ABS_PATH, ST_TYPE_ANY},
       2},
  };
  bool ok = false;
  st_learner_t *learner = NULL;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    /* Reverse insertion must preserve alternatives and their total order. */
    for (unsigned reverse = 0; reverse < 2; reverse++) {
      learner = st_learner_new(NULL);
      CHECK(learner != NULL);
      for (size_t j = 0; j < 2; j++) {
        st_netargv_view_t record = cases[i].records[reverse ? 1 - j : j];
        if (record.length)
          CHECK(st_learner_feed_netargv_view(learner, record) == ST_OK);
      }
      CHECK(learner_choices_are(learner, cases[i].cpl, cases[i].position,
                                cases[i].expected, cases[i].count));
      st_learner_free(learner);
      learner = NULL;
    }
  }
  ok = true;
cleanup:
  st_learner_free(learner);
  return ok;
}

static bool check_lattice_is_not_runtime_acceptance(void) {
  bool ok = false;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = context ? st_policy_new(context) : NULL;
  st_netpattern_t pattern = {0};
  CHECK(policy != NULL);
  CHECK(st_is_compatible(ST_TYPE_LITERAL, ST_TYPE_NUMBER));
  CHECK(st_is_compatible(ST_TYPE_LITERAL, ST_TYPE_OPT));
  CHECK(st_netpattern_from_cpl_owned("tool #n", &pattern) == ST_OK);
  CHECK(st_policy_add_netpattern_view(
            policy, (st_netpattern_view_t){(const char *)pattern.data,
                                           pattern.length}) == ST_OK);
  CHECK(check_match(policy, (st_netargv_view_t){"4:tool,3:zzz,", 13}, false));
  CHECK(check_match(policy, (st_netargv_view_t){"4:tool,2:42,", 12}, true));
  ok = true;
cleanup:
  st_netpattern_free(&pattern);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return ok;
}

static bool check_cpl_unicode_boundaries(void) {
  static const struct {
    const char *source;
    const char *decoded;
    size_t decoded_length;
  } cases[] = {
      {"\\x00", "\0", 1},
      {"\\x41", "A", 1},
      {"\\u0041", "A", 1},
      {"\\u00a2", "\xc2\xa2", 2},
      {"\\u20ac", "\xe2\x82\xac", 3},
      {"\\ud7ff", "\xed\x9f\xbf", 3},
      {"\\ue000", "\xee\x80\x80", 3},
      {"\\ud83d\\ude00", "\xf0\x9f\x98\x80", 4},
      {"\\udbff\\udfff", "\xf4\x8f\xbf\xbf", 4},
  };
  static const char prefix[] = "cmd \"";
  char *input = NULL;
  st_netpattern_t pattern = {0};
  st_token_array_t tokens = {0};
  bool ok = false;
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    size_t source_length = strlen(cases[i].source);
    size_t length = sizeof(prefix) - 1 + source_length + 1;
    /* Exact allocation makes every escape lookahead meet a real boundary. */
    input = malloc(length + 1);
    CHECK(input != NULL);
    memcpy(input, prefix, sizeof(prefix) - 1);
    memcpy(input + sizeof(prefix) - 1, cases[i].source, source_length);
    input[length - 1] = '"';
    input[length] = '\0';
    CHECK(st_netpattern_from_cpl_owned(input, &pattern) == ST_OK);
    CHECK(
        st_netpattern_decode_view(
            (st_netpattern_view_t){(const char *)pattern.data, pattern.length},
            &tokens) == ST_OK);
    CHECK(tokens.count == 2 && tokens.tokens[1].type == ST_TYPE_LITERAL &&
          tokens.tokens[1].text_length == cases[i].decoded_length &&
          memcmp(tokens.tokens[1].text, cases[i].decoded,
                 cases[i].decoded_length) == 0);
    st_token_array_free(&tokens);
    st_netpattern_free(&pattern);
    free(input);
    input = NULL;

    for (size_t cut = 1; cut <= source_length; cut++) {
      for (unsigned closed = 0; closed < 2; closed++) {
        if (closed && cut == source_length)
          continue;
        length = sizeof(prefix) - 1 + cut + closed;
        input = malloc(length + 1);
        CHECK(input != NULL);
        memcpy(input, prefix, sizeof(prefix) - 1);
        memcpy(input + sizeof(prefix) - 1, cases[i].source, cut);
        if (closed)
          input[length - 1] = '"';
        input[length] = '\0';
        CHECK(st_netpattern_from_cpl_owned(input, &pattern) == ST_ERR_INVALID);
        CHECK(pattern.data == NULL && pattern.length == 0);
        free(input);
        input = NULL;
      }
    }
  }

  static const char *const invalid[] = {
      "cmd \"\\u0000\"",        "cmd \"\\udc00\"",
      "cmd \"\\ud800x\"",       "cmd \"\\ud800\\u0000\"",
      "cmd \"\\ud800\\ud800\"", "cmd \"\\ud800\\uzzzz\"",
      "cmd \"\\u0x00\"",        "cmd \"\\xG0\"",
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    CHECK(st_netpattern_from_cpl_owned(invalid[i], &pattern) == ST_ERR_INVALID);
    CHECK(pattern.data == NULL && pattern.length == 0);
  }

  for (size_t decoded = ST_MAX_TOKEN_LEN - 1; decoded <= ST_MAX_TOKEN_LEN;
       decoded++) {
    size_t length = sizeof(prefix) - 1 + decoded * 6 + 1;
    input = malloc(length + 1);
    CHECK(input != NULL);
    memcpy(input, prefix, sizeof(prefix) - 1);
    for (size_t i = 0; i < decoded; i++)
      memcpy(input + sizeof(prefix) - 1 + i * 6, "\\u0061", 6);
    input[length - 1] = '"';
    input[length] = '\0';
    CHECK(st_netpattern_from_cpl_owned(input, &pattern) ==
          (decoded < ST_MAX_TOKEN_LEN ? ST_OK : ST_ERR_INVALID));
    if (decoded < ST_MAX_TOKEN_LEN) {
      CHECK(st_netpattern_decode_view(
                (st_netpattern_view_t){(const char *)pattern.data,
                                       pattern.length},
                &tokens) == ST_OK);
      CHECK(tokens.count == 2 && tokens.tokens[1].text_length == decoded);
      st_token_array_free(&tokens);
      st_netpattern_free(&pattern);
    } else
      CHECK(pattern.data == NULL && pattern.length == 0);
    free(input);
    input = NULL;
  }
  ok = true;
cleanup:
  free(input);
  st_token_array_free(&tokens);
  st_netpattern_free(&pattern);
  return ok;
}

static SHELL_NONNULL(2, 3, 4) st_error_t
    save_file_fixture(unsigned kind, const st_learner_t *learner,
                      const st_policy_t *policy, const char *path) {
  switch (kind) {
  case 0:
    return st_learner_save(learner, path);
  case 1:
    return st_policy_save(policy, path);
  default:
    return st_policy_render_nfa(policy, path, NULL);
  }
}

static SHELL_NONNULL(1, 2, 4) bool read_file_fixture(const char *path,
                                                     unsigned char *bytes,
                                                     size_t capacity,
                                                     size_t *length) {
  FILE *stream = fopen(path, "rb");
  if (!stream)
    return false;
  *length = fread(bytes, 1, capacity, stream);
  bool ok = !ferror(stream) && feof(stream);
  return fclose(stream) == 0 && ok;
}

static SHELL_NONNULL(1,
                     2) bool file_fixture_equals(const char *path,
                                                 const unsigned char *expected,
                                                 size_t length) {
  unsigned char bytes[8192];
  size_t actual = 0;
  return read_file_fixture(path, bytes, sizeof(bytes), &actual) &&
         actual == length && memcmp(bytes, expected, length) == 0;
}

/* Run against both shipping and fault-injection libraries. Valid filesystem
 * names and entry types are external inputs, not fabricated internal objects.
 */
static bool check_save_file_boundaries(void) {
  bool ok = false, owns_directory = false;
  char directory[] = "/tmp/shellclave-public-save-XXXXXX";
  char path[PATH_MAX] = {0}, target[PATH_MAX];
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL, *loaded_policy = NULL;
  st_learner_t *learner = st_learner_new(NULL);
  st_learner_t *loaded_learner = st_learner_new(NULL);
  st_netpattern_t pattern = {0};
  FILE *stream = NULL;
  static const char netargv[] = "4:echo,3:a\0b,";
  CHECK(context && learner && loaded_learner);
  policy = st_policy_new(context);
  loaded_policy = st_policy_new(context);
  CHECK(policy && loaded_policy);
  CHECK(st_netpattern_from_cpl_owned("echo \"a\\x00b\"", &pattern) == ST_OK);
  CHECK(st_policy_add_netpattern_view(
            policy, (st_netpattern_view_t){(const char *)pattern.data,
                                           pattern.length}) == ST_OK);
  CHECK(st_learner_feed_netargv_view(
            learner, (st_netargv_view_t){netargv, sizeof(netargv) - 1}) ==
        ST_OK);
  CHECK(mkdtemp(directory) != NULL);
  owns_directory = true;
  snprintf(target, sizeof(target), "%s/target", directory);
  long name_max = pathconf(directory, _PC_NAME_MAX);
  size_t prefix = strlen(directory) + 1;
  CHECK(name_max >= 14 && (size_t)name_max + prefix + 2 <= sizeof(path));
  static const unsigned char sentinel[] = "symlink-target-unchanged";

  for (unsigned kind = 0; kind < 3; kind++) {
    snprintf(path, sizeof(path), "%s/model", directory);
    CHECK(save_file_fixture(kind, learner, policy, path) == ST_OK);
    unsigned char expected[8192];
    size_t length = 0;
    CHECK(read_file_fixture(path, expected, sizeof(expected), &length));
    struct stat status;
    CHECK(lstat(path, &status) == 0 && S_ISREG(status.st_mode) &&
          (status.st_mode & 0777) == 0600);
    static const mode_t modes[] = {0640, 0750, 04750, 02750, 01750};
    for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); m++) {
      CHECK(chmod(path, modes[m]) == 0);
      CHECK(save_file_fixture(kind, learner, policy, path) == ST_OK);
      CHECK(lstat(path, &status) == 0 && (status.st_mode & 07777) == modes[m]);
      CHECK(file_fixture_equals(path, expected, length));
    }
    CHECK(unlink(path) == 0 && mkfifo(path, 0600) == 0);
    int next_fd = open(directory, O_RDONLY | O_DIRECTORY);
    CHECK(next_fd >= 0 && close(next_fd) == 0);
    CHECK(save_file_fixture(kind, learner, policy, path) == ST_ERR_IO);
    CHECK(lstat(path, &status) == 0 && S_ISFIFO(status.st_mode));
    CHECK(save_file_fixture(kind, learner, policy, directory) == ST_ERR_IO);
    CHECK(lstat(directory, &status) == 0 && S_ISDIR(status.st_mode));
    errno = 0;
    CHECK(fcntl(next_fd, F_GETFD) == -1 && errno == EBADF);
    CHECK(test_atomic_temp_files(path, false));
    CHECK(unlink(path) == 0);

    stream = fopen(target, "wb");
    CHECK(stream != NULL);
    CHECK(fwrite(sentinel, 1, sizeof(sentinel) - 1, stream) ==
          sizeof(sentinel) - 1);
    int closed = fclose(stream);
    stream = NULL;
    CHECK(closed == 0);
    CHECK(symlink("target", path) == 0);
    CHECK(save_file_fixture(kind, learner, policy, path) == ST_OK);
    CHECK(lstat(path, &status) == 0 && S_ISREG(status.st_mode));
    CHECK(file_fixture_equals(path, expected, length));
    CHECK(file_fixture_equals(target, sentinel, sizeof(sentinel) - 1));
    CHECK(unlink(path) == 0 && unlink(target) == 0);
    CHECK(symlink("absent-target", path) == 0);
    CHECK(save_file_fixture(kind, learner, policy, path) == ST_OK);
    CHECK(lstat(path, &status) == 0 && S_ISREG(status.st_mode));
    CHECK(file_fixture_equals(path, expected, length));
    CHECK(unlink(path) == 0);

    /* The former suffix broke NAME_MAX-6 and larger basenames. Exercise both
     * creation and replacement up to NAME_MAX, then an actually invalid name.
     */
    const size_t names[] = {(size_t)name_max - 7, (size_t)name_max - 6,
                            (size_t)name_max, (size_t)name_max + 1};
    for (size_t n = 0; n < sizeof(names) / sizeof(names[0]); n++) {
      memcpy(path, directory, prefix - 1);
      path[prefix - 1] = '/';
      memset(path + prefix, 'x', names[n]);
      path[prefix + names[n]] = '\0';
      if (names[n] > (size_t)name_max) {
        CHECK(save_file_fixture(kind, learner, policy, path) == ST_ERR_IO);
        CHECK(test_atomic_temp_files(path, false));
        continue;
      }
      for (unsigned existing = 0; existing < 2; existing++) {
        CHECK(save_file_fixture(kind, learner, policy, path) == ST_OK);
        CHECK(lstat(path, &status) == 0 && S_ISREG(status.st_mode) &&
              (status.st_mode & 0777) == (existing ? 0640 : 0600));
        CHECK(file_fixture_equals(path, expected, length));
        CHECK(test_atomic_temp_files(path, false));
        if (kind == 0) {
          CHECK(st_learner_load(loaded_learner, path) == ST_OK);
          st_learner_stats_t stats;
          st_learner_get_stats(loaded_learner, &stats);
          CHECK(stats.command_count == 1);
        } else if (kind == 1) {
          CHECK(st_policy_load(loaded_policy, path, true) == ST_OK);
          CHECK(check_match(loaded_policy,
                            (st_netargv_view_t){netargv, sizeof(netargv) - 1},
                            true));
        }
        CHECK(chmod(path, 0640) == 0);
      }
      CHECK(unlink(path) == 0);
    }
  }
  ok = true;
cleanup:
  if (stream)
    (void)fclose(stream);
  st_netpattern_free(&pattern);
  st_learner_free(loaded_learner);
  st_learner_free(learner);
  st_policy_free(loaded_policy);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  if (owns_directory)
    ok = test_atomic_cleanup_directory(directory) && ok;
  return ok;
}

static bool check_long_save_paths(void) {
  bool ok = false;
  test_atomic_long_directory_t directory = {0};
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL, *loaded_policy = NULL;
  st_learner_t *learner = st_learner_new(NULL);
  st_learner_t *loaded_learner = st_learner_new(NULL);
  st_netpattern_t pattern = {0};
  static const char netargv[] = "4:echo,3:a\0b,";
  CHECK(context && learner && loaded_learner);
  policy = st_policy_new(context);
  loaded_policy = st_policy_new(context);
  CHECK(policy && loaded_policy);
  CHECK(st_netpattern_from_cpl_owned("echo \"a\\x00b\"", &pattern) == ST_OK);
  CHECK(st_policy_add_netpattern_view(
            policy, (st_netpattern_view_t){(const char *)pattern.data,
                                           pattern.length}) == ST_OK);
  CHECK(st_learner_feed_netargv_view(
            learner, (st_netargv_view_t){netargv, sizeof(netargv) - 1}) ==
        ST_OK);
  static const char *const roots[] = {"/tmp/shellclave-long-save-XXXXXX",
                                      "shellclave-long-save-XXXXXX"};
  const size_t lengths[] = {PATH_MAX - 12, PATH_MAX - 3, PATH_MAX - 2,
                            PATH_MAX - 1};
  for (size_t r = 0; r < sizeof(roots) / sizeof(roots[0]); r++) {
    for (size_t l = 0; l < sizeof(lengths) / sizeof(lengths[0]); l++) {
      CHECK(
          test_atomic_long_directory_create(&directory, roots[r], lengths[l]));
      char path[PATH_MAX + 2];
      memcpy(path, directory.path, lengths[l]);
      memcpy(path + lengths[l], "/x", 3);
      if (lengths[l] + 2 >= PATH_MAX) {
        for (unsigned existing = 0; existing < 2; existing++) {
          if (existing)
            CHECK(test_atomic_directory_sentinel(directory.path, true));
          for (unsigned kind = 0; kind < 3; kind++) {
            errno = 0;
            CHECK(save_file_fixture(kind, learner, policy, path) == ST_ERR_IO &&
                  errno == ENAMETOOLONG);
            CHECK(test_atomic_directory_only_entry(directory.path,
                                                   existing ? "x" : NULL));
            if (existing)
              CHECK(test_atomic_directory_sentinel(directory.path, false));
          }
        }
        st_learner_stats_t before, after;
        st_learner_get_stats(loaded_learner, &before);
        CHECK(st_learner_load(loaded_learner, path) == ST_ERR_IO);
        st_learner_get_stats(loaded_learner, &after);
        CHECK(after.command_count == before.command_count);
        CHECK(st_policy_load(loaded_policy, path, true) == ST_ERR_IO);
        CHECK(check_match(loaded_policy,
                          (st_netargv_view_t){netargv, sizeof(netargv) - 1},
                          true));
        CHECK(test_atomic_long_directory_cleanup(&directory));
        continue;
      }
      for (unsigned kind = 0; kind < 3; kind++) {
        unsigned char expected[8192];
        size_t length = 0;
        for (unsigned existing = 0; existing < 2; existing++) {
          CHECK(save_file_fixture(kind, learner, policy, path) == ST_OK);
          struct stat status;
          CHECK(stat(path, &status) == 0 && S_ISREG(status.st_mode) &&
                (status.st_mode & 07777) == (existing ? 04750 : 0600));
          CHECK(test_atomic_temp_files(path, false));
          if (!existing)
            CHECK(read_file_fixture(path, expected, sizeof(expected), &length));
          else
            CHECK(file_fixture_equals(path, expected, length));
          if (kind == 0) {
            CHECK(st_learner_load(loaded_learner, path) == ST_OK);
            st_learner_stats_t stats;
            st_learner_get_stats(loaded_learner, &stats);
            CHECK(stats.command_count == 1);
          } else if (kind == 1) {
            CHECK(st_policy_load(loaded_policy, path, true) == ST_OK);
            CHECK(check_match(loaded_policy,
                              (st_netargv_view_t){netargv, sizeof(netargv) - 1},
                              true));
          }
          CHECK(chmod(path, 04750) == 0);
        }
        CHECK(unlink(path) == 0);
      }
      CHECK(test_atomic_long_directory_cleanup(&directory));
    }
  }
  ok = true;
cleanup:
  st_netpattern_free(&pattern);
  st_learner_free(loaded_learner);
  st_learner_free(learner);
  st_policy_free(loaded_policy);
  st_policy_free(policy);
  st_policy_ctx_release(context);
  return test_atomic_long_directory_cleanup(&directory) && ok;
}

int main(void) {
  static const struct {
    const char *cpl;
    const char *netargv;
    size_t length;
  } cases[] = {
      {"echo \"\"", "4:echo,0:,", sizeof("4:echo,0:,") - 1},
      {"echo \"a b\"", "4:echo,3:a b,", sizeof("4:echo,3:a b,") - 1},
      {"echo \"#n\"", "4:echo,2:#n,", sizeof("4:echo,2:#n,") - 1},
      {"echo \"a\\x00b\"", "4:echo,3:a\0b,", sizeof("4:echo,3:a\0b,") - 1},
      {"cat #path", "3:cat,10:/tmp/input,", sizeof("3:cat,10:/tmp/input,") - 1},
      {"git status #opt", "3:git,6:status,7:--short,",
       sizeof("3:git,6:status,7:--short,") - 1},
      {"grep \"--id=\"{#n}", "4:grep,7:--id=42,",
       sizeof("4:grep,7:--id=42,") - 1},
  };
  int failed = 1;
  st_policy_ctx_t *context = st_policy_ctx_new();
  st_policy_t *policy = NULL;
  st_policy_t *loaded = NULL;
  st_learner_t *learner = NULL;
  st_learner_t *loaded_learner = NULL;
  st_netpattern_t pattern = {0};
  st_netpattern_t roundtrip = {0};
  st_token_array_t classified = {0};
  char *borrowed = NULL;
  char *cpl = NULL;
  st_suggestion_t *suggestions = NULL;
  size_t suggestion_count = 0;
  char policy_path[] = "/tmp/shellclave-public-policy-XXXXXX";
  char learner_path[] = "/tmp/shellclave-public-learner-XXXXXX";
  bool policy_file = false, learner_file = false;
  CHECK(context != NULL);
  CHECK(check_save_file_boundaries());
  CHECK(check_long_save_paths());
  CHECK(check_cpl_unicode_boundaries());
  CHECK(check_policy_command_grammar());
  CHECK(check_compound_cpl_component_limits());
  bool compound_spans = check_compound_capture_spans();
  bool binary_literals = check_binary_literal_classification();
  CHECK(compound_spans && binary_literals);
  bool editor_choices = check_compound_editor_choices();
  bool complete_suggestions = check_complete_suggestions();
  CHECK(editor_choices && complete_suggestions);
  CHECK(check_late_suggestion_limit());
  CHECK(check_suggestion_rendering());
  CHECK(check_contextual_policy_subsumption());
  CHECK(check_literal_editor_choices());
  CHECK(check_compound_miner_choices());
  CHECK(check_learner_prefix_and_capture_choices());
  CHECK(check_binary_punctuation_classification());
  CHECK(check_parameterized_learner_prefixes());
  CHECK(check_timestamp_metadata_agreement());
  CHECK(check_learner_overlapping_support());
  CHECK(check_lattice_is_not_runtime_acceptance());
  policy = st_policy_new(context);
  CHECK(policy != NULL);
  st_learner_config_t config;
  st_learner_config_default(&config);
  config.min_support = 1;
  learner = st_learner_new(&config);
  loaded_learner = st_learner_new(&config);
  CHECK(learner != NULL && loaded_learner != NULL);

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    CHECK(st_netpattern_from_cpl_owned(cases[i].cpl, &pattern) == ST_OK);
    st_netpattern_view_t view = {pattern.data, pattern.length};
    CHECK(st_netpattern_to_cpl_view(view, &cpl) == ST_OK);
    CHECK(st_netpattern_from_cpl_owned(cpl, &roundtrip) == ST_OK);
    CHECK(pattern.length == roundtrip.length &&
          memcmp(pattern.data, roundtrip.data, pattern.length) == 0);
    CHECK(st_policy_add_netpattern_view(policy, view) == ST_OK);
    free(cpl);
    cpl = NULL;
    st_netpattern_free(&roundtrip);
    st_netpattern_free(&pattern);

    /* Exact allocation: neither a trailing NUL nor spare bytes are available.
     */
    borrowed = malloc(cases[i].length);
    CHECK(borrowed != NULL);
    memcpy(borrowed, cases[i].netargv, cases[i].length);
    st_netargv_view_t input = {borrowed, cases[i].length};
    CHECK(st_netargv_classify_view(input, &classified) == ST_OK);
    visit_state_t state = {&classified, 0};
    size_t visited = 0;
    CHECK(st_netargv_visit_view(input, compare_token, &state, &visited) ==
          ST_OK);
    CHECK(state.seen == classified.count && visited == classified.count);
    if (!check_match(policy, input, true)) {
      fprintf(stderr, "public policy case failed: %s\n", cases[i].cpl);
      goto cleanup;
    }
    CHECK(st_learner_feed_netargv_view(learner, input) == ST_OK);
    CHECK(st_learner_feed_tokens(learner, &classified) == ST_OK);
    st_token_array_free(&classified);
    free(borrowed);
    borrowed = NULL;
  }
  CHECK(check_match(
      policy,
      (st_netargv_view_t){"4:echo,5:other,", sizeof("4:echo,5:other,") - 1},
      false));
  /* Learner payload limits apply to borrowed byte spans, including NUL bytes.
   * The frame allocation has no terminator or spare storage. */
  for (unsigned binary = 0; binary < 2; binary++) {
    for (size_t length = ST_MAX_TOKEN_LEN - 1; length <= ST_MAX_TOKEN_LEN;
         length++) {
      char header[32];
      int header_length = snprintf(header, sizeof(header), "%zu:", length);
      CHECK(header_length > 0 && (size_t)header_length < sizeof(header));
      size_t frame_length = (size_t)header_length + length + 1;
      borrowed = malloc(frame_length);
      CHECK(borrowed != NULL);
      memcpy(borrowed, header, (size_t)header_length);
      memset(borrowed + header_length, 'x', length);
      if (binary)
        borrowed[header_length + length / 2] = '\0';
      borrowed[frame_length - 1] = ',';
      st_learner_stats_t before_limit, after_limit;
      st_learner_get_stats(learner, &before_limit);
      CHECK(st_learner_feed_netargv_view(
                learner, (st_netargv_view_t){borrowed, frame_length}) ==
            (length < ST_MAX_TOKEN_LEN ? ST_OK : ST_ERR_INVALID));
      st_learner_get_stats(learner, &after_limit);
      CHECK(after_limit.command_count ==
            before_limit.command_count + (length < ST_MAX_TOKEN_LEN ? 1u : 0u));
      free(borrowed);
      borrowed = NULL;
    }
  }
  bool matched = true;
  CHECK(st_policy_match_view(
            policy, (st_netargv_view_t){"4:echo,x", sizeof("4:echo,x") - 1},
            &matched) == ST_ERR_FORMAT &&
        !matched);
  CHECK(st_policy_compact(policy) == ST_OK);
  /* Create the destination after compaction: a nonempty policy cannot compact
   * while another policy shares its context. */
  loaded = st_policy_new(context);
  CHECK(loaded != NULL);

  int descriptor = mkstemp(policy_path);
  CHECK(descriptor >= 0);
  policy_file = true;
  CHECK(close(descriptor) == 0);
  descriptor = mkstemp(learner_path);
  CHECK(descriptor >= 0);
  learner_file = true;
  CHECK(close(descriptor) == 0);
  CHECK(st_policy_save(policy, policy_path) == ST_OK);
  CHECK(st_policy_load(loaded, policy_path, true) == ST_OK);
  CHECK(st_policy_rule_count(loaded) == st_policy_rule_count(policy));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    CHECK(check_match(
        loaded, (st_netargv_view_t){cases[i].netargv, cases[i].length}, true));
  CHECK(st_learner_save(learner, learner_path) == ST_OK);
  CHECK(st_learner_load(loaded_learner, learner_path) == ST_OK);
  st_learner_stats_t before, after;
  st_learner_get_stats(learner, &before);
  st_learner_get_stats(loaded_learner, &after);
  CHECK(before.command_count == after.command_count &&
        before.blacklist_count == after.blacklist_count);
  suggestions = st_learner_suggest(loaded_learner, &suggestion_count);
  CHECK(suggestions != NULL && suggestion_count != 0);
  for (size_t i = 0; i < suggestion_count; i++) {
    CHECK(st_netpattern_decode_view(
              (st_netpattern_view_t){suggestions[i].pattern,
                                     suggestions[i].pattern_length},
              &classified) == ST_OK);
    st_token_array_free(&classified);
  }
  failed = 0;
  puts("Public canonical, policy and persistence contracts passed");

cleanup:
  st_suggestion_list_free(suggestions, suggestion_count);
  st_token_array_free(&classified);
  st_netpattern_free(&roundtrip);
  st_netpattern_free(&pattern);
  free(cpl);
  free(borrowed);
  st_learner_free(learner);
  st_learner_free(loaded_learner);
  st_policy_free(policy);
  st_policy_free(loaded);
  st_policy_ctx_release(context);
  if (policy_file)
    (void)unlink(policy_path);
  if (learner_file)
    (void)unlink(learner_path);
  return failed;
}
