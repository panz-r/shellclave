#include <env_screener.h>
#include <shell_sequence.h>
#include <shell_tokenizer.h>
#include <shellgate.h>
#include <shelltype.h>

#include <stdlib.h>
#include <string.h>

static bool count_token(const st_token_view_t *token, void *user_ctx) {
  size_t *count = user_ctx;
  if (!token || !count)
    return false;
  (*count)++;
  return true;
}

static bool count_policy_match(const char *netpattern, void *user_ctx) {
  size_t *count = user_ctx;
  if (!netpattern || !count)
    return false;
  (*count)++;
  return true;
}

static bool count_policy_diff(st_policy_diff_kind_t kind,
                              const char *netpattern, void *user_ctx) {
  size_t *count = user_ctx;
  if (kind != ST_POLICY_DIFF_ADDED || !netpattern || !count)
    return false;
  (*count)++;
  return true;
}

static bool check_policy_view_apis(st_netargv_view_t netargv) {
  st_policy_ctx_t *ctx = st_policy_ctx_new();
  st_policy_t *policy = ctx ? st_policy_new(ctx) : NULL;
  st_policy_t *empty = ctx ? st_policy_new(ctx) : NULL;
  char *netpattern = NULL;
  const char **all_matches = NULL;
  size_t all_count = 0;
  size_t visited_count = 0;
  size_t diff_count = 0;
  st_eval_result_t eval = {0};
  bool matches = false;
  bool ok =
      ctx && policy && empty &&
      st_netpattern_from_cpl("echo hello", &netpattern) == ST_OK &&
      st_policy_add_netpattern(policy, netpattern) == ST_OK &&
      st_policy_eval_view(policy, netargv, &eval) == ST_OK && eval.matches &&
      st_policy_match_view(policy, netargv, &matches) == ST_OK && matches &&
      st_policy_verify_all_view(policy, netargv, &all_matches, &all_count) ==
          ST_OK &&
      all_count == 1 && strcmp(all_matches[0], netpattern) == 0 &&
      st_policy_visit_matches_view(policy, netargv, count_policy_match,
                                   &visited_count, &visited_count) == ST_OK &&
      visited_count == 1 &&
      st_policy_visit_diff(empty, policy, count_policy_diff, &diff_count,
                           &diff_count) == ST_OK &&
      diff_count == 1;

  st_policy_matches_free(all_matches);
  free(netpattern);
  st_policy_free(empty);
  st_policy_free(policy);
  st_policy_ctx_release(ctx);
  return ok;
}

int main(void) {
  static const char command[] = "echo hello && printf done";
  shell_parse_result_t parsed = {0};
  shell_error_t error =
      shell_parse_fast(command, strlen(command), NULL, &parsed);
  if (error != SHELL_OK || parsed.status != SHELL_STATUS_OK ||
      parsed.count != 2 || parsed.cmds[0].start != 0 ||
      parsed.cmds[0].len != strlen("echo hello") ||
      parsed.cmds[1].type != SHELL_TYPE_AND ||
      parsed.cmds[1].start != strlen("echo hello && ") ||
      parsed.cmds[1].len != strlen("printf done"))
    return 1;

  char *command_netseq = NULL;
  char *type_netseq = NULL;
  size_t subcommand_count = 0;
  if (shell_build_anomaly_netseqs(command, strlen(command), NULL,
                                  &command_netseq, &type_netseq,
                                  &subcommand_count) != SHELL_PROCESS_OK ||
      subcommand_count != 2) {
    free(command_netseq);
    free(type_netseq);
    return 2;
  }
  free(command_netseq);
  free(type_netseq);

  size_t environment_indices[1] = {0};
  size_t environment_count = 0;
  (void)shell_env_screener_scan(environment_indices,
                                sizeof(environment_indices) /
                                    sizeof(environment_indices[0]),
                                &environment_count, 0.5, 1);

  st_learner_t *learner = st_learner_new(
      &(st_learner_config_t){.min_support = 1,
                             .min_confidence = 0.01,
                             .max_suggestions = ST_DEFAULT_MAX_SUGGESTIONS});
  static const char netargv_data[] = "4:echo,5:hello,unframed trailer";
  st_netargv_view_t netargv = {
      .data = netargv_data,
      .length = strlen("4:echo,5:hello,"),
  };
  if (!learner || st_learner_feed_netargv_view(learner, netargv) != ST_OK) {
    st_learner_free(learner);
    return 3;
  }
  size_t visited_count = 0;
  if (st_netargv_visit_view(netargv, count_token, &visited_count, NULL) !=
          ST_OK ||
      visited_count != 2) {
    st_learner_free(learner);
    return 4;
  }
  if (!check_policy_view_apis(netargv)) {
    st_learner_free(learner);
    return 5;
  }
  size_t suggestion_count = 0;
  st_suggestion_t *suggestions = st_learner_suggest(learner, &suggestion_count);
  char *suggestion_cpl = NULL;
  if (suggestions && suggestion_count == 1)
    (void)st_netpattern_to_cpl(suggestions[0].pattern, &suggestion_cpl);
  if (!suggestions || suggestion_count != 1 || !suggestion_cpl ||
      strcmp(suggestion_cpl, "echo hello") != 0 || suggestions[0].count != 1 ||
      suggestions[0].confidence != 1.0) {
    free(suggestion_cpl);
    st_suggestion_list_free(suggestions, suggestion_count);
    st_learner_free(learner);
    return 6;
  }
  free(suggestion_cpl);
  st_suggestion_list_free(suggestions, suggestion_count);
  st_learner_free(learner);

  sg_gate_t *gate = sg_gate_new();
  if (!gate || sg_gate_add_allow_cpl(gate, "echo hello") != SG_OK) {
    sg_gate_free(gate);
    return 7;
  }
  char buffer[SG_BUF_MIN];
  sg_result_t result;
  sg_error_t gate_error =
      sg_gate_evaluate(gate, "echo hello", strlen("echo hello"), buffer,
                       sizeof(buffer), &result);
  sg_gate_free(gate);
  return gate_error == SG_OK && result.verdict == SG_VERDICT_ALLOW ? 0 : 8;
}
