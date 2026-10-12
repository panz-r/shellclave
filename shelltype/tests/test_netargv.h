#ifndef SHELLTYPE_TEST_NETARGV_H
#define SHELLTYPE_TEST_NETARGV_H

#include "shell_netstring.h"
#include "shell_processor.h"
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static inline bool test_pattern_is_cpl(st_netpattern_view_t pattern,
                                       const char *cpl) {
  st_netpattern_t expected = {0};
  bool equal = st_netpattern_from_cpl_owned(cpl, &expected) == ST_OK &&
               pattern.length == expected.length &&
               memcmp(pattern.data, expected.data, pattern.length) == 0;
  st_netpattern_free(&expected);
  return equal;
}

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

static inline shell_netstring_buffer_t test_netargv(const char *command) {
  if (!command)
    return (shell_netstring_buffer_t){0};
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
      return (shell_netstring_buffer_t){0};
    total += record_length;
  }
  if (total == SIZE_MAX)
    return (shell_netstring_buffer_t){0};
  char *encoded = malloc(total + 1);
  if (!encoded)
    return (shell_netstring_buffer_t){0};
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
      return (shell_netstring_buffer_t){0};
    }
    output += prefix_length + written;
    encoded[output++] = ',';
  }
  encoded[output] = '\0';
  return (shell_netstring_buffer_t){(unsigned char *)encoded, output};
}

static inline st_error_t test_st_classify(const char *command,
                                          st_token_array_t *out) {
  shell_netstring_buffer_t encoded = test_netargv(command);
  if (!encoded.data)
    return ST_ERR_MEMORY;
  st_error_t error = st_netargv_classify_view(
      (st_netargv_view_t){(const char *)encoded.data, encoded.length}, out);
  shell_netstring_buffer_free(&encoded);
  return error;
}

static inline st_error_t test_st_feed(st_learner_t *learner,
                                      const char *command) {
  shell_netstring_buffer_t encoded = test_netargv(command);
  if (!encoded.data)
    return ST_ERR_MEMORY;
  st_error_t error = st_learner_feed_netargv_view(
      learner, (st_netargv_view_t){(const char *)encoded.data, encoded.length});
  shell_netstring_buffer_free(&encoded);
  return error;
}

static inline st_error_t test_st_policy_eval(st_policy_t *policy,
                                             const char *command,
                                             st_eval_result_t *result) {
  shell_netstring_buffer_t encoded = test_netargv(command);
  if (!encoded.data)
    return ST_ERR_MEMORY;
  st_error_t error = st_policy_eval_view(
      policy, (st_netargv_view_t){(const char *)encoded.data, encoded.length},
      result);
  shell_netstring_buffer_free(&encoded);
  return error;
}

static inline st_error_t
test_st_policy_match(st_policy_t *policy, const char *command, bool *matches) {
  shell_netstring_buffer_t encoded = test_netargv(command);
  if (!encoded.data)
    return ST_ERR_MEMORY;
  st_error_t error = st_policy_match_view(
      policy, (st_netargv_view_t){(const char *)encoded.data, encoded.length},
      matches);
  shell_netstring_buffer_free(&encoded);
  return error;
}

static inline st_error_t
test_st_policy_verify_all(const st_policy_t *policy, const char *command,
                          st_netpattern_view_t **matching_patterns,
                          size_t *match_count) {
  if (matching_patterns)
    *matching_patterns = NULL;
  if (match_count)
    *match_count = 0;
  shell_netstring_buffer_t encoded = test_netargv(command);
  if (!encoded.data && command)
    return ST_ERR_MEMORY;
  st_error_t error = st_policy_verify_all_view(
      policy, (st_netargv_view_t){(const char *)encoded.data, encoded.length},
      matching_patterns, match_count);
  shell_netstring_buffer_free(&encoded);
  return error;
}

static inline st_error_t test_st_policy_add(st_policy_t *policy,
                                            const char *cpl) {
  st_netpattern_t pattern = {0};
  st_error_t error = st_netpattern_from_cpl_owned(cpl, &pattern);
  if (error != ST_OK)
    return error;
  error = st_policy_add_netpattern_view(
      policy,
      (st_netpattern_view_t){(const char *)pattern.data, pattern.length});
  st_netpattern_free(&pattern);
  return error;
}

static inline st_error_t test_st_policy_remove(st_policy_t *policy,
                                               const char *cpl) {
  st_netpattern_t pattern = {0};
  st_error_t error = st_netpattern_from_cpl_owned(cpl, &pattern);
  if (error != ST_OK)
    return error;
  error = st_policy_remove_netpattern_view(
      policy,
      (st_netpattern_view_t){(const char *)pattern.data, pattern.length});
  st_netpattern_free(&pattern);
  return error;
}

static inline st_error_t
test_st_policy_batch_add(st_policy_t *policy, const char **cpl, size_t count) {
  if (!cpl)
    return st_policy_batch_add_netpattern_views(policy, NULL, count);
  st_netpattern_t *patterns = calloc(count, sizeof(*patterns));
  st_netpattern_view_t *views = calloc(count, sizeof(*views));
  if ((!patterns || !views) && count != 0) {
    free(patterns);
    free(views);
    return ST_ERR_MEMORY;
  }
  st_error_t error = ST_OK;
  size_t converted = 0;
  for (; converted < count; converted++) {
    error = st_netpattern_from_cpl_owned(cpl[converted], &patterns[converted]);
    if (error != ST_OK)
      break;
    views[converted] = (st_netpattern_view_t){patterns[converted].data,
                                              patterns[converted].length};
  }
  if (error == ST_OK)
    error = st_policy_batch_add_netpattern_views(policy, views, count);
  for (size_t i = 0; i < converted; i++)
    st_netpattern_free(&patterns[i]);
  free(patterns);
  free(views);
  return error;
}

static inline st_error_t test_st_validate_pattern(const char *cpl,
                                                  st_token_array_t *tokens) {
  st_netpattern_t pattern = {0};
  st_error_t error = st_netpattern_from_cpl_owned(cpl, &pattern);
  if (error != ST_OK)
    return error;
  error = st_netpattern_validate_view(
      (st_netpattern_view_t){(const char *)pattern.data, pattern.length},
      tokens);
  st_netpattern_free(&pattern);
  return error;
}

static inline st_error_t test_st_blacklist_add(st_learner_t *learner,
                                               const char *cpl) {
  st_netpattern_t pattern = {0};
  st_error_t error = st_netpattern_from_cpl_owned(cpl, &pattern);
  if (error == ST_OK)
    error = st_learner_blacklist_add_netpattern(
        learner, (st_netpattern_view_t){.data = (const char *)pattern.data,
                                        .length = pattern.length});
  st_netpattern_free(&pattern);
  return error;
}

static inline bool test_st_is_blacklisted(const st_learner_t *learner,
                                          const char *cpl) {
  st_netpattern_t pattern = {0};
  if (st_netpattern_from_cpl_owned(cpl, &pattern) != ST_OK)
    return false;
  bool found = st_learner_is_netpattern_blacklisted(
      learner, (st_netpattern_view_t){.data = (const char *)pattern.data,
                                      .length = pattern.length});
  st_netpattern_free(&pattern);
  return found;
}

#endif
