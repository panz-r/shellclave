#ifndef SHELLTYPE_TEST_NETARGV_H
#define SHELLTYPE_TEST_NETARGV_H

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Compatibility helpers for older readable test fixtures. Their names make
 * conversion explicit at each call site; canonical-boundary tests call the
 * production APIs directly. */
static inline char *test_netargv(const char *command) {
  if (!command)
    return NULL;
  size_t input_length = strlen(command);
  size_t capacity = input_length * 3 + 32;
  char *encoded = malloc(capacity);
  char *word = malloc(input_length + 1);
  if (!encoded || !word) {
    free(encoded);
    free(word);
    return NULL;
  }
  size_t input = 0, output = 0;
  while (input < input_length) {
    while (input < input_length && isspace((unsigned char)command[input]))
      input++;
    if (input == input_length)
      break;
    size_t word_length = 0;
    char quote = 0;
    while (input < input_length) {
      char c = command[input];
      if (!quote && isspace((unsigned char)c))
        break;
      if ((c == '\'' || c == '"') && (!quote || quote == c)) {
        quote = quote ? 0 : c;
        input++;
        continue;
      }
      if (c == '\\' && quote != '\'' && input + 1 < input_length) {
        input++;
        if (command[input] == '\n') {
          input++;
          continue;
        }
        c = command[input];
      }
      word[word_length++] = c;
      input++;
    }
    int prefix =
        snprintf(encoded + output, capacity - output, "%zu:", word_length);
    if (prefix < 0 || output + (size_t)prefix + word_length + 2 > capacity) {
      free(encoded);
      free(word);
      return NULL;
    }
    output += (size_t)prefix;
    memcpy(encoded + output, word, word_length);
    output += word_length;
    encoded[output++] = ',';
  }
  encoded[output] = '\0';
  free(word);
  return encoded;
}

static inline st_error_t test_st_classify(const char *command,
                                          st_token_array_t *out) {
  char *encoded = test_netargv(command);
  if (!encoded)
    return command ? ST_ERR_MEMORY : st_classify(NULL, out);
  st_error_t error = st_classify(encoded, out);
  free(encoded);
  return error;
}

static inline st_error_t test_st_normalize(const char *command, char ***tokens,
                                           size_t *count) {
  if (tokens)
    *tokens = NULL;
  if (count)
    *count = 0;
  if (!command || !tokens || !count)
    return ST_ERR_INVALID;
  char *encoded = test_netargv(command);
  if (!encoded)
    return ST_ERR_MEMORY;
  st_token_array_t typed = {0};
  st_error_t error = st_classify(encoded, &typed);
  free(encoded);
  if (error != ST_OK)
    return error;
  char **legacy = typed.count ? calloc(typed.count, sizeof(*legacy)) : NULL;
  if (typed.count && !legacy) {
    st_free_token_array(&typed);
    return ST_ERR_MEMORY;
  }
  for (size_t i = 0; i < typed.count; i++) {
    const char *value = typed.tokens[i].type == ST_TYPE_LITERAL
                            ? typed.tokens[i].text
                            : st_type_symbol[typed.tokens[i].type];
    legacy[i] = strdup(value);
    if (!legacy[i]) {
      for (size_t j = 0; j < i; j++)
        free(legacy[j]);
      free(legacy);
      st_free_token_array(&typed);
      return ST_ERR_MEMORY;
    }
  }
  *tokens = legacy;
  *count = typed.count;
  st_free_token_array(&typed);
  return error;
}

static inline st_error_t test_st_feed(st_learner_t *learner,
                                      const char *command) {
  char *encoded = test_netargv(command);
  if (!encoded)
    return command ? ST_ERR_MEMORY : st_feed(learner, NULL);
  st_error_t error = st_feed(learner, encoded);
  free(encoded);
  return error;
}

static inline st_error_t test_st_policy_eval(st_policy_t *policy,
                                             const char *command,
                                             st_eval_result_t *result) {
  char *encoded = test_netargv(command);
  if (!encoded)
    return command ? ST_ERR_MEMORY : st_policy_eval(policy, NULL, result);
  st_error_t error = st_policy_eval(policy, encoded, result);
  free(encoded);
  return error;
}

static inline st_error_t
test_st_policy_verify_all(const st_policy_t *policy, const char *command,
                          const char ***matching_patterns,
                          size_t *match_count) {
  char *encoded = test_netargv(command);
  if (!encoded)
    return command ? ST_ERR_MEMORY
                   : st_policy_verify_all(policy, NULL, matching_patterns,
                                          match_count);
  st_error_t error =
      st_policy_verify_all(policy, encoded, matching_patterns, match_count);
  free(encoded);
  return error;
}

static inline st_error_t test_st_policy_add(st_policy_t *policy,
                                            const char *cpl) {
  st_token_array_t decoded = {0};
  if (cpl && st_netpattern_decode(cpl, &decoded) == ST_OK) {
    st_free_token_array(&decoded);
    return st_policy_add_netpattern(policy, cpl);
  }
  st_free_token_array(&decoded);
  char *pattern = NULL;
  st_error_t error = st_netpattern_from_cpl(cpl, &pattern);
  if (error != ST_OK)
    return cpl ? error : st_policy_add_netpattern(policy, NULL);
  error = st_policy_add_netpattern(policy, pattern);
  free(pattern);
  return error;
}

static inline st_error_t test_st_policy_remove(st_policy_t *policy,
                                               const char *cpl) {
  st_token_array_t decoded = {0};
  if (cpl && st_netpattern_decode(cpl, &decoded) == ST_OK) {
    st_free_token_array(&decoded);
    return st_policy_remove_netpattern(policy, cpl);
  }
  st_free_token_array(&decoded);
  char *pattern = NULL;
  st_error_t error = st_netpattern_from_cpl(cpl, &pattern);
  if (error != ST_OK)
    return cpl ? error : st_policy_remove_netpattern(policy, NULL);
  error = st_policy_remove_netpattern(policy, pattern);
  free(pattern);
  return error;
}

static inline st_error_t
test_st_policy_batch_add(st_policy_t *policy, const char **cpl, size_t count) {
  if (!cpl)
    return st_policy_batch_add_netpatterns(policy, NULL, count);
  char **patterns = calloc(count, sizeof(*patterns));
  if (!patterns && count != 0)
    return ST_ERR_MEMORY;
  st_error_t error = ST_OK;
  size_t converted = 0;
  for (; converted < count; converted++) {
    error = st_netpattern_from_cpl(cpl[converted], &patterns[converted]);
    if (error != ST_OK)
      break;
  }
  if (error == ST_OK)
    error =
        st_policy_batch_add_netpatterns(policy, (const char **)patterns, count);
  for (size_t i = 0; i < converted; i++)
    free(patterns[i]);
  free(patterns);
  return error;
}

static inline st_error_t test_st_validate_pattern(const char *cpl,
                                                  st_pattern_info_t *info) {
  if (info)
    memset(info, 0, sizeof(*info));
  char *pattern = NULL;
  st_error_t error = st_netpattern_from_cpl(cpl, &pattern);
  if (error != ST_OK)
    return cpl ? error : st_validate_netpattern(NULL, info);
  error = st_validate_netpattern(pattern, info);
  free(pattern);
  return error;
}

static inline st_error_t test_st_blacklist_add(st_learner_t *learner,
                                               const char *cpl) {
  char *pattern = NULL;
  st_error_t error = st_netpattern_from_cpl(cpl, &pattern);
  if (error == ST_OK)
    error = st_blacklist_add_netpattern(learner, pattern);
  free(pattern);
  return error;
}

static inline bool test_st_is_blacklisted(const st_learner_t *learner,
                                          const char *cpl) {
  char *pattern = NULL;
  if (st_netpattern_from_cpl(cpl, &pattern) != ST_OK)
    return false;
  bool found = st_is_netpattern_blacklisted(learner, pattern);
  free(pattern);
  return found;
}

#endif
