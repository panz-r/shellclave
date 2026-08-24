#ifndef SHELLTYPE_TEST_NETARGV_H
#define SHELLTYPE_TEST_NETARGV_H

#include "shell_netstring.h"
#include "shell_processor.h"
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Readable argv-fixture notation for tests. It splits whitespace outside
 * quotes but is deliberately not shell source: operator-looking and leading
 * '#' values remain literal fixture words. Production boundaries receive
 * canonical netargv directly. */
static inline bool test_netargv_next_word(const char *fixture, size_t length,
                                          size_t *offset, size_t *start,
                                          size_t *word_length) {
  size_t input = *offset;
  while (input < length && isspace((unsigned char)fixture[input]))
    input++;
  if (input == length) {
    *offset = input;
    return false;
  }
  *start = input;
  char quote = 0;
  while (input < length) {
    char c = fixture[input];
    if (quote == 0 && isspace((unsigned char)c))
      break;
    if ((c == '\'' || c == '"') && (quote == 0 || quote == c)) {
      quote = quote == 0 ? c : 0;
      input++;
      continue;
    }
    if (c == '\\' && quote != '\'' && input + 1 < length) {
      input += 2;
      continue;
    }
    input++;
  }
  *word_length = input - *start;
  *offset = input;
  return true;
}

static inline char *test_netargv(const char *command) {
  if (!command)
    return NULL;
  size_t input_length = strlen(command);
  size_t input = 0, total = 0, start = 0, word_length = 0;
  while (test_netargv_next_word(command, input_length, &input, &start,
                                &word_length)) {
    size_t decoded_length = 0, record_length = 0;
    if (shell_measure_decoded_word(command + start, word_length,
                                   &decoded_length) != SHELL_PROCESS_OK ||
        shell_netstring_encoded_length(decoded_length, &record_length) !=
            SHELL_NETSTRING_OK ||
        total > SIZE_MAX - record_length)
      return NULL;
    total += record_length;
  }
  if (total == SIZE_MAX)
    return NULL;
  char *encoded = malloc(total + 1);
  if (!encoded)
    return NULL;
  input = 0;
  size_t output = 0;
  while (test_netargv_next_word(command, input_length, &input, &start,
                                &word_length)) {
    size_t decoded_length = 0, prefix_length = 0, written = 0;
    if (shell_measure_decoded_word(command + start, word_length,
                                   &decoded_length) != SHELL_PROCESS_OK ||
        shell_netstring_write_prefix(encoded + output, total - output,
                                     decoded_length,
                                     &prefix_length) != SHELL_NETSTRING_OK ||
        shell_write_decoded_word(
            command + start, word_length, encoded + output + prefix_length,
            decoded_length, &written) != SHELL_PROCESS_OK ||
        written != decoded_length) {
      free(encoded);
      return NULL;
    }
    output += prefix_length + written;
    encoded[output++] = ',';
  }
  encoded[output] = '\0';
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
