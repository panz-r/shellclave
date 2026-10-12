#ifndef SHELLGATE_TEST_POLICY_FIXTURE_H
#define SHELLGATE_TEST_POLICY_FIXTURE_H

#include "shellgate.h"

/* Fixture edits build a new policy, never mutate an installed one. A fresh
 * context also lets tests exercise replacement across unrelated contexts. */
static inline st_error_t test_policy_copy(const st_policy_t *source,
                                          st_policy_t **replacement) {
  *replacement = NULL;
  st_policy_ctx_t *context = st_policy_ctx_new();
  if (!context)
    return ST_ERR_MEMORY;
  st_policy_t *policy = st_policy_new(context);
  st_policy_ctx_release(context);
  if (!policy)
    return ST_ERR_MEMORY;
  st_error_t error = st_policy_merge(policy, source);
  if (error != ST_OK) {
    st_policy_free(policy);
    return error;
  }
  *replacement = policy;
  return ST_OK;
}

static inline st_error_t
test_policy_replace_patterns(sg_gate_t *gate, bool deny,
                             const st_netpattern_view_t *patterns, size_t count,
                             bool remove) {
  st_policy_t *replacement;
  st_error_t error =
      test_policy_copy(deny ? sg_gate_deny_policy_borrowed(gate)
                            : sg_gate_allow_policy_borrowed(gate),
                       &replacement);
  if (error != ST_OK)
    return error;
  error = remove ? st_policy_remove_netpattern_view(replacement, patterns[0])
                 : st_policy_batch_add_netpattern_views(replacement, patterns,
                                                        count);
  if (error != ST_OK) {
    st_policy_free(replacement);
    return error;
  }
  if (deny)
    sg_gate_set_deny_policy_owned(gate, replacement);
  else
    sg_gate_set_allow_policy_owned(gate, replacement);
  return ST_OK;
}

static inline st_error_t
test_policy_replace_pattern(sg_gate_t *gate, bool deny,
                            st_netpattern_view_t pattern, bool remove) {
  return test_policy_replace_patterns(gate, deny, &pattern, 1, remove);
}

static inline st_error_t test_policy_replace_cpl(sg_gate_t *gate, bool deny,
                                                 const char *cpl, bool remove) {
  st_netpattern_t pattern = {NULL, 0};
  st_error_t error = st_netpattern_from_cpl_owned(cpl, &pattern);
  if (error == ST_OK) {
    st_netpattern_view_t view = {pattern.data, pattern.length};
    error = test_policy_replace_pattern(gate, deny, view, remove);
  }
  st_netpattern_free(&pattern);
  return error;
}

static inline st_error_t test_policy_replace_from_file(sg_gate_t *gate,
                                                       const char *path) {
  st_policy_t *replacement;
  st_error_t error =
      test_policy_copy(sg_gate_allow_policy_borrowed(gate), &replacement);
  if (error != ST_OK)
    return error;
  error = st_policy_load(replacement, path, false);
  if (error != ST_OK) {
    st_policy_free(replacement);
    return error;
  }
  sg_gate_set_allow_policy_owned(gate, replacement);
  return ST_OK;
}

static inline size_t test_anomaly_vocabulary(const sg_gate_t *gate) {
  const sg_anomaly_model_t *model = sg_gate_anomaly_raw_model_borrowed(gate);
  return model ? sg_anomaly_model_vocab_size(model) : 0;
}

#endif
