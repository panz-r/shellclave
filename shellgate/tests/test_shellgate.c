#define _POSIX_C_SOURCE 200809L
#include "../../deps/xxhash/xxhash.h"
#include "../../shellsplit/tests/ansi_parameter_cases.h"
#include "../../shellsplit/tests/malformed_source_cases.h"
#include "../../shellsplit/tests/substitution_capacity_cases.h"
#include "../../shellsplit/tests/word_expansion_cases.h"
#include "../../tests/atomic_file_fixture.h"
#include "sg_anomaly.h"
#include "shell_abstract.h"
#include "shell_depgraph.h"
#include "shell_netstring.h"
#include "shell_processor.h"
#include "shell_sequence.h"
#include "shell_tokenizer.h"
#include "shellgate.h"
#include "test_allocator.h"
#include "test_eval_buffer.h"
#include "test_io.h"
#include "test_numeric_locale.h"
#include "test_policy_fixture.h"
#include "test_sg_failures.h"
#include "test_source_scans.h"
#include <errno.h>
#include <float.h>
#include <math.h>
#include <stdint.h>
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
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define ASSERT_EQ_INT(a, b)                                                    \
  do {                                                                         \
    if ((a) != (b)) {                                                          \
      printf("    FAIL: %s != %s (%ld != %ld) at %s:%d\n", #a, #b, (long)(a),  \
             (long)(b), __FILE__, __LINE__);                                   \
      fail_count++;                                                            \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define ASSERT_EQ_UINT(a, b)                                                   \
  do {                                                                         \
    if ((a) != (b)) {                                                          \
      printf("    FAIL: %s != %s (%lu != %lu) at %s:%d\n", #a, #b,             \
             (unsigned long)(a), (unsigned long)(b), __FILE__, __LINE__);      \
      fail_count++;                                                            \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define ASSERT_STR(a, b)                                                       \
  do {                                                                         \
    if (strcmp((a), (b)) != 0) {                                               \
      printf("    FAIL: %s != %s (\"%s\" != \"%s\") at %s:%d\n", #a, #b, (a),  \
             (b), __FILE__, __LINE__);                                         \
      fail_count++;                                                            \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define ASSERT_NULL(ptr)                                                       \
  do {                                                                         \
    if ((ptr) != NULL) {                                                       \
      printf("    FAIL: %s should be NULL at %s:%d\n", #ptr, __FILE__,         \
             __LINE__);                                                        \
      fail_count++;                                                            \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define ASSERT_NOT_NULL(ptr)                                                   \
  do {                                                                         \
    if ((ptr) == NULL) {                                                       \
      printf("    FAIL: %s should not be NULL at %s:%d\n", #ptr, __FILE__,     \
             __LINE__);                                                        \
      fail_count++;                                                            \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)
#define ASSERT_SG_OK(expression) ASSERT((expression) == SG_OK)
#define ASSERT_ST_OK(expression) ASSERT((expression) == ST_OK)

/* SHELLCLAVE_TEST_ONLY=name runs only the case of that name; a name that
 * matches no case is a failure, not an empty green run. */
static unsigned selected_count;
static bool selected(const char *name) {
  const char *only = getenv("SHELLCLAVE_TEST_ONLY");
  bool match = !only || strcmp(only, name) == 0;
  selected_count += match;
  return match;
}
static bool selection_matched_nothing(void) {
  if (getenv("SHELLCLAVE_TEST_ONLY") && selected_count == 0) {
    fprintf(stderr, "SHELLCLAVE_TEST_ONLY=%s matches no test\n",
            getenv("SHELLCLAVE_TEST_ONLY"));
    return true;
  }
  return false;
}

#define TEST(name) static void test_##name(void)
#define RUN(name)                                                              \
  if (selected(#name))                                                         \
    do {                                                                       \
      printf("  %-40s ", #name);                                               \
      int _pf = fail_count;                                                    \
      test_##name();                                                           \
      cleanup_temp_files();                                                    \
      if (fail_count == _pf) {                                                 \
        printf("PASS\n");                                                      \
        pass_count++;                                                          \
      }                                                                        \
  } while (0)

/* The evaluation buffer owns both diagnostic strings and the bounded
 * dependency-graph workspace. Keep normal test evaluation on the public
 * size-hint path's safe side; small-prefix contracts below deliberately pass
 * a narrower view of this same storage. */
static char eval_buf[48u * 1024u * 1024u];
static char **temp_files = NULL;
static size_t temp_file_count = 0;
static size_t temp_file_capacity = 0;

static uint64_t test_load_u64_le(const unsigned char *source) {
  uint64_t value = 0;
  for (unsigned i = 0; i < 8; i++)
    value |= (uint64_t)source[i] << (i * 8);
  return value;
}

static void test_store_u64_le(unsigned char *destination, uint64_t value) {
  for (unsigned i = 0; i < 8; i++)
    destination[i] = (unsigned char)(value >> (i * 8));
}

static void cleanup_temp_files(void) {
  for (size_t i = 0; i < temp_file_count; i++) {
    unlink(temp_files[i]);
    free(temp_files[i]);
  }
  free(temp_files);
  temp_files = NULL;
  temp_file_count = 0;
  temp_file_capacity = 0;
}

static void register_temp_file(const char *path) {
  if (temp_file_count == temp_file_capacity) {
    size_t capacity = temp_file_capacity ? temp_file_capacity * 2 : 16;
    char **files = realloc(temp_files, capacity * sizeof(*files));
    ASSERT_NOT_NULL(files);
    temp_files = files;
    temp_file_capacity = capacity;
  }
  temp_files[temp_file_count] = strdup(path);
  ASSERT_NOT_NULL(temp_files[temp_file_count]);
  temp_file_count++;
}

/* path has capacity writable bytes; stem is a trusted fixture basename.
 * This filesystem boundary checks environment-derived path length and creates
 * the unique file. Callers own the returned descriptor and generated path. */
static SHELL_NONNULL(1, 3) int temp_fixture_file(char *path, size_t capacity,
                                                 const char *stem) {
  const char *directory = getenv("TMPDIR");
  if (!directory || !directory[0])
    directory = "/tmp";
  int length = snprintf(path, capacity, "%s/%s-XXXXXX", directory, stem);
  if (length < 0)
    return -1;
  if ((size_t)length >= capacity) {
    errno = ENAMETOOLONG;
    return -1;
  }
  return mkstemp(path);
}

static const char *temp_policy_file(void) {
  static char path[256];
  int fd = temp_fixture_file(path, sizeof(path), "shellgate-test");
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
    if (test_policy_replace_cpl(g, false, rules[i], false) != ST_OK) {
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
  shell_netstring_buffer_t netargv = {0};
  if (shell_render_netargv_buffer(&commands[0], NULL, &netargv) !=
      SHELL_PROCESS_OK) {
    shell_command_infos_free(commands, count);
    return SG_ERR_PARSE;
  }
  st_token_array_t tokens = {0};
  st_error_t error = st_netargv_classify_view(
      (st_netargv_view_t){(const char *)netargv.data, netargv.length}, &tokens);
  st_netpattern_t netpattern = {0};
  if (error == ST_OK) {
    for (size_t i = 0; i < tokens.count; i++)
      tokens.tokens[i].type = ST_TYPE_LITERAL;
    error =
        st_netpattern_encode_owned(tokens.tokens, tokens.count, &netpattern);
  }
  if (error == ST_OK)
    error = test_policy_replace_pattern(
        gate, false, (st_netpattern_view_t){netpattern.data, netpattern.length},
        false);
  sg_error_t result = error == ST_OK           ? SG_OK
                      : error == ST_ERR_MEMORY ? SG_ERR_MEMORY
                                               : SG_ERR_PARSE;
  st_netpattern_free(&netpattern);
  st_token_array_free(&tokens);
  shell_netstring_buffer_free(&netargv);
  shell_command_infos_free(commands, count);
  return result;
}

static sg_error_t eval_cmd(sg_gate_t *g, const char *cmd, sg_result_t *r) {
  /* The evaluation buffer is reusable without clearing; result strings are
   * consumed before the next evaluation overwrites its storage. */
  return sg_gate_evaluate(g, cmd, strlen(cmd), eval_buf, sizeof(eval_buf), r);
}

/* Reserve the evaluator's aligned depgraph tail while constraining only the
 * result-string prefix. This keeps truncation tests about diagnostics rather
 * than accidentally testing the separate workspace contract. */
static size_t eval_buffer_size_for_prefix(const char *command,
                                          size_t prefix_size) {
  size_t workspace_size = sg_test_eval_workspace_size(strlen(command));
  size_t alignment = shell_dep_workspace_alignment();
  if (workspace_size == 0)
    return 0;
  uintptr_t begin = (uintptr_t)(void *)eval_buf;
  if (prefix_size > UINTPTR_MAX - begin)
    return 0;
  uintptr_t workspace = begin + prefix_size;
  uintptr_t remainder = workspace % alignment;
  if (remainder != 0)
    workspace += alignment - remainder;
  if (workspace > UINTPTR_MAX - workspace_size)
    return 0;
  size_t total = (size_t)(workspace + workspace_size - begin);
  return total <= sizeof(eval_buf) ? total : 0;
}

/* Mirror only the public workspace-placement contract so boundary tests can
 * prove graph-backed result fields do not escape into the private tail. */
static size_t eval_result_prefix_size(const char *command, size_t buffer_size) {
  return sg_test_eval_prefix_size(eval_buf, buffer_size, strlen(command));
}

/* buffer references prefix_size readable bytes. Missing optional result
 * strings are NULL; a missing byte span is NULL only with length zero. */
static SHELL_NONNULL(2) bool result_string_in_prefix(const char *value,
                                                     const char *buffer,
                                                     size_t prefix_size) {
  if (!value)
    return true;
  uintptr_t begin = (uintptr_t)(const void *)buffer;
  uintptr_t address = (uintptr_t)(void *)value;
  if (address < begin || address - begin >= prefix_size)
    return false;
  return memchr(value, '\0', prefix_size - (size_t)(address - begin)) != NULL;
}

static SHELL_NONNULL(3) bool result_span_in_prefix(const char *value,
                                                   size_t length,
                                                   const char *buffer,
                                                   size_t prefix_size) {
  if (!value)
    return length == 0;
  uintptr_t begin = (uintptr_t)(const void *)buffer;
  uintptr_t address = (uintptr_t)(void *)value;
  if (address < begin || address - begin > prefix_size)
    return false;
  return length <= prefix_size - (size_t)(address - begin);
}

/* The depgraph workspace occupies the buffer tail after graph construction.
 * Every public result pointer must stay in the prefix; this checks every
 * distinct string-bearing result field rather than only command/netargv. */
static SHELL_NONNULL(1, 2) bool result_fields_stay_in_buffer(
    const sg_result_t *result, const char *buffer, size_t prefix_size) {
  if (!result_string_in_prefix(result->deny_reason, buffer, prefix_size))
    return false;
  for (uint32_t i = 0; i < result->subcommand_count; i++) {
    const sg_subcommand_result_t *subcommand = &result->subcommands[i];
    if (!result_string_in_prefix(subcommand->display_command, buffer,
                                 prefix_size) ||
        !result_string_in_prefix(subcommand->reject_reason, buffer,
                                 prefix_size) ||
        !result_span_in_prefix(subcommand->netargv, subcommand->netargv_length,
                               buffer, prefix_size))
      return false;
  }
  for (uint32_t i = 0; i < result->suggestion_count; i++)
    if (!result_string_in_prefix(result->suggestions[i], buffer, prefix_size))
      return false;
  for (uint32_t i = 0; i < result->deny_suggestion_count; i++)
    if (!result_string_in_prefix(result->deny_suggestions[i], buffer,
                                 prefix_size))
      return false;
  return true;
}

static SHELL_NONNULL(1) bool result_fields_stay_in_prefix(
    const sg_result_t *result, size_t prefix_size) {
  return result_fields_stay_in_buffer(result, eval_buf, prefix_size);
}

static sg_error_t eval_with_prefix(sg_gate_t *gate, const char *command,
                                   size_t prefix_size, sg_result_t *result) {
  size_t buffer_size = eval_buffer_size_for_prefix(command, prefix_size);
  /* Prefix tests require a representable fixture buffer before evaluation. */
  ASSERT(buffer_size != 0);
  return sg_gate_evaluate(gate, command, strlen(command), eval_buf, buffer_size,
                          result);
}

/* --- LIFECYCLE --- */

static st_policy_t *binding_policy(const char *cpl) {
  st_policy_ctx_t *context = st_policy_ctx_new();
  if (!context)
    return NULL;
  st_policy_t *policy = st_policy_new(context);
  st_policy_ctx_release(context);
  if (policy && cpl) {
    st_netpattern_t pattern = {0};
    st_error_t error = st_netpattern_from_cpl_owned(cpl, &pattern);
    if (error == ST_OK)
      error = st_policy_add_netpattern_view(
          policy, (st_netpattern_view_t){pattern.data, pattern.length});
    st_netpattern_free(&pattern);
    if (error != ST_OK) {
      st_policy_free(policy);
      return NULL;
    }
  }
  return policy;
}

TEST(policy_binding_lifecycle) {
  st_policy_t *allow = binding_policy("echo ok");
  st_policy_t *deny = binding_policy("echo blocked");
  ASSERT(allow && deny);
  sg_test_alloc_fail_at(1);
  sg_gate_t *owner = sg_gate_new_with_policies_owned(allow, deny);
  sg_test_alloc_reset();
  ASSERT(owner == NULL);
  ASSERT(st_policy_rule_count(allow) == 1);
  owner = sg_gate_new_with_policies_owned(allow, deny);
  ASSERT(owner != NULL);
  ASSERT(sg_gate_allow_policy_borrowed(owner) == allow &&
         sg_gate_deny_policy_borrowed(owner) == deny);
  sg_gate_t *borrower = sg_gate_new_with_policies_borrowed(allow, deny);
  ASSERT(borrower != NULL);
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(borrower, "echo ok", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  /* Setters may borrow policies already owned by another gate. */
  sg_gate_t *setter_borrower = sg_gate_new();
  ASSERT(setter_borrower != NULL);
  sg_gate_set_allow_policy_borrowed(setter_borrower,
                                    sg_gate_allow_policy_borrowed(owner));
  sg_gate_set_deny_policy_borrowed(setter_borrower,
                                   sg_gate_deny_policy_borrowed(owner));
  ASSERT(sg_gate_allow_policy_borrowed(setter_borrower) == allow &&
         sg_gate_deny_policy_borrowed(setter_borrower) == deny);
  ASSERT_SG_OK(eval_cmd(setter_borrower, "echo ok", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_SG_OK(eval_cmd(setter_borrower, "echo blocked", &result));
  ASSERT(result.verdict == SG_VERDICT_DENY);
  sg_gate_free(setter_borrower);
  ASSERT_SG_OK(eval_cmd(owner, "echo ok", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_SG_OK(eval_cmd(owner, "echo blocked", &result));
  ASSERT(result.verdict == SG_VERDICT_DENY);
  st_policy_t *next_allow = binding_policy("pwd");
  st_policy_t *next_deny = binding_policy("pwd");
  ASSERT(next_allow && next_deny);
  /* Detach both borrowed slots before the owner retires their old objects. */
  sg_gate_set_allow_policy_borrowed(borrower, next_allow);
  sg_gate_set_deny_policy_borrowed(borrower, next_deny);
  sg_gate_set_allow_policy_owned(owner, next_allow);
  sg_gate_set_deny_policy_owned(owner, next_deny);
  ASSERT_SG_OK(eval_cmd(borrower, "pwd", &result));
  ASSERT(result.verdict == SG_VERDICT_DENY);
  sg_gate_free(borrower);
  ASSERT(st_policy_rule_count(next_allow) == 1);
  sg_gate_free(owner);

  allow = binding_policy("true");
  deny = binding_policy(NULL);
  ASSERT(allow && deny);
  sg_gate_t *mixed = sg_gate_new();
  ASSERT(mixed);
  sg_gate_set_allow_policy_borrowed(mixed, allow);
  sg_gate_set_deny_policy_borrowed(mixed, deny);
  st_policy_t *owned_deny = binding_policy("false");
  ASSERT(owned_deny);
  sg_gate_set_deny_policy_owned(mixed, owned_deny);
  sg_gate_free(mixed);
  ASSERT(st_policy_rule_count(allow) == 1 && st_policy_rule_count(deny) == 0);
  st_policy_free(allow);
  st_policy_free(deny);
}

/* --- POLICY LIST --- */

static int list_tags[8];

/* A gate whose list holds every outcome: allow `echo *`, deny `rm *`, and one
 * policy per further outcome. Each extra carries its list index as its user
 * pointer. */
static sg_gate_t *list_gate(void) {
  static const struct {
    const char *cpl;
    sg_verdict_t outcome;
  } extras[] = {
      {"ls", SG_VERDICT_REVIEW},
      {"cat *", SG_VERDICT_DISCOURAGE},
      {"sudo *", SG_VERDICT_NEEDS_REASON},
      {"shutdown", SG_VERDICT_DENY_ESCALATE},
      {"date *", SG_VERDICT_AUDIT},
  };
  st_policy_t *allow = binding_policy("echo *");
  st_policy_t *deny = binding_policy("rm *");
  sg_gate_t *gate =
      allow && deny ? sg_gate_new_with_policies_owned(allow, deny) : NULL;
  if (!gate) {
    st_policy_free(allow);
    st_policy_free(deny);
    return NULL;
  }
  for (size_t i = 0; i < sizeof(extras) / sizeof(extras[0]); i++) {
    st_policy_t *policy = binding_policy(extras[i].cpl);
    if (!policy ||
        sg_gate_add_policy_owned(gate, policy, extras[i].outcome) != SG_OK) {
      st_policy_free(policy);
      sg_gate_free(gate);
      return NULL;
    }
    st_policy_set_user_data(policy, &list_tags[2 + i]);
  }
  if (sg_gate_set_reject_mask(gate, 0) != SG_OK) {
    sg_gate_free(gate);
    return NULL;
  }
  return gate;
}

TEST(policy_list_command_verdict_is_most_restrictive) {
  static const struct {
    const char *command;
    sg_verdict_t verdict;
  } cases[] = {
      {"echo a; ls", SG_VERDICT_REVIEW},
      {"ls; rm x", SG_VERDICT_DENY},
      {"rm x; shutdown", SG_VERDICT_DENY_ESCALATE},
      {"cat f; sudo x", SG_VERDICT_NEEDS_REASON},
      {"echo a; date +%s", SG_VERDICT_AUDIT},
      {"cat f; echo a", SG_VERDICT_DISCOURAGE},
      {"echo a; date +%s; cat f", SG_VERDICT_DISCOURAGE},
      /* A discouragement never masks a subcommand that matched nothing. */
      {"cat f; zzz", SG_VERDICT_UNDETERMINED},
      {"ls; zzz", SG_VERDICT_REVIEW},
  };
  sg_gate_t *gate = list_gate();
  ASSERT_NOT_NULL(gate);
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    if (result.verdict != cases[i].verdict)
      fprintf(stderr, "policy list: %s -> %s, expected %s\n", cases[i].command,
              sg_verdict_name(result.verdict),
              sg_verdict_name(cases[i].verdict));
    ASSERT(result.verdict == cases[i].verdict);
  }
  /* The reason and attention index name the first subcommand that needs it. */
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "echo a; ls", &result));
  ASSERT_STR(result.deny_reason, "review policy match");
  ASSERT(result.attention_index == 1);
  ASSERT_SG_OK(eval_cmd(gate, "echo a; echo b", &result));
  ASSERT(result.deny_reason == NULL);
  /* A weak allow denies nothing: no command-level reason, but the advice is
   * on its subcommand. */
  ASSERT_SG_OK(eval_cmd(gate, "cat f", &result));
  ASSERT(result.verdict == SG_VERDICT_DISCOURAGE);
  ASSERT(result.deny_reason == NULL);
  ASSERT_STR(result.subcommands[0].reject_reason, "discourage policy match");
  sg_gate_free(gate);
}

TEST(policy_list_accessors_and_user_pointers) {
  static const sg_verdict_t outcomes[] = {
      SG_VERDICT_ALLOW,      SG_VERDICT_DENY,         SG_VERDICT_REVIEW,
      SG_VERDICT_DISCOURAGE, SG_VERDICT_NEEDS_REASON, SG_VERDICT_DENY_ESCALATE,
      SG_VERDICT_AUDIT,
  };
  sg_gate_t *gate = list_gate();
  ASSERT_NOT_NULL(gate);
  ASSERT(sg_gate_policy_count(gate) == 7);
  for (uint32_t i = 0; i < 7; i++) {
    sg_verdict_t outcome = SG_VERDICT_UNDETERMINED;
    const st_policy_t *policy = sg_gate_policy_at(gate, i, &outcome);
    ASSERT(policy != NULL && outcome == outcomes[i]);
    ASSERT(st_policy_user_data(policy) == (i < 2 ? NULL : &list_tags[i]));
    ASSERT(sg_gate_policy_at(gate, i, NULL) == policy);
  }
  ASSERT(sg_gate_policy_at(gate, 0, NULL) ==
         sg_gate_allow_policy_borrowed(gate));
  ASSERT(sg_gate_policy_at(gate, 1, NULL) ==
         sg_gate_deny_policy_borrowed(gate));
  /* A result's matched bits lead back to the application's own records. */
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "sudo x", &result));
  uint32_t matched = result.subcommands[0].matched_policies;
  ASSERT(matched == 1u << 4);
  uint32_t index = 0;
  while (!(matched & (1u << index)))
    index++;
  ASSERT(st_policy_user_data(sg_gate_policy_at(gate, index, NULL)) ==
         &list_tags[4]);
  /* An output carries the deciding policy's pointer itself, with no lookup
   * through the gate, at the subcommand and at the command. A policy that
   * set none, and an output nothing decided, give NULL. */
  ASSERT(result.outputs[0].policy == 4 &&
         result.outputs[0].user_data == &list_tags[4]);
  ASSERT(result.subcommands[0].outputs[0].user_data == &list_tags[4]);
  /* The scalar verdict carries the pointer the same way. */
  ASSERT(result.deciding_user_data == &list_tags[4]);
  ASSERT(result.subcommands[0].deciding_user_data == &list_tags[4]);
  ASSERT_SG_OK(eval_cmd(gate, "echo hi", &result));
  ASSERT(result.outputs[0].policy == 0 && result.outputs[0].user_data == NULL);
  ASSERT_SG_OK(eval_cmd(gate, "zzz", &result));
  ASSERT(result.outputs[0].policy == UINT32_MAX &&
         result.outputs[0].user_data == NULL);
  ASSERT(result.deciding_user_data == NULL);
  sg_gate_free(gate);
}

TEST(policy_list_add_remove_and_limits) {
  sg_gate_t *gate = sg_gate_new_with_policies_owned(binding_policy("echo *"),
                                                    binding_policy("never"));
  ASSERT_NOT_NULL(gate);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT(sg_gate_policy_count(gate) == 2);

  /* Only the policy outcomes can be installed; an error changes nothing and
   * leaves an owned policy with the caller. */
  static const sg_verdict_t rejected[] = {
      SG_VERDICT_REJECT, SG_VERDICT_UNDETERMINED, (sg_verdict_t)99};
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    st_policy_t *spare = binding_policy("ls");
    ASSERT_NOT_NULL(spare);
    ASSERT(sg_gate_add_policy_owned(gate, spare, rejected[i]) ==
           SG_ERR_INVALID);
    ASSERT(sg_gate_add_policy_borrowed(gate, spare, rejected[i]) ==
           SG_ERR_INVALID);
    ASSERT(sg_gate_policy_count(gate) == 2);
    st_policy_free(spare);
  }

  /* Removal frees an owned policy and renumbers the ones after it. */
  ASSERT_SG_OK(
      sg_gate_add_policy_owned(gate, binding_policy("ls"), SG_VERDICT_AUDIT));
  ASSERT_SG_OK(sg_gate_add_policy_owned(gate, binding_policy("cat *"),
                                        SG_VERDICT_REVIEW));
  ASSERT_SG_OK(
      sg_gate_add_policy_owned(gate, binding_policy("pwd"), SG_VERDICT_DENY));
  ASSERT(sg_gate_policy_count(gate) == 5);
  sg_gate_remove_policy(gate, 3);
  ASSERT(sg_gate_policy_count(gate) == 4);
  sg_verdict_t outcome = SG_VERDICT_ALLOW;
  ASSERT(sg_gate_policy_at(gate, 3, &outcome) != NULL &&
         outcome == SG_VERDICT_DENY);
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "cat f", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT_SG_OK(eval_cmd(gate, "pwd", &result));
  ASSERT(result.verdict == SG_VERDICT_DENY);
  ASSERT(result.subcommands[0].matched_policies == 1u << 3);

  /* The list is bounded. */
  while (sg_gate_policy_count(gate) < SG_MAX_POLICIES)
    ASSERT_SG_OK(
        sg_gate_add_policy_owned(gate, binding_policy("ls"), SG_VERDICT_AUDIT));
  st_policy_t *extra = binding_policy("ls");
  ASSERT_NOT_NULL(extra);
  ASSERT(sg_gate_add_policy_owned(gate, extra, SG_VERDICT_AUDIT) ==
         SG_ERR_INVALID);
  ASSERT(sg_gate_policy_count(gate) == SG_MAX_POLICIES);
  st_policy_free(extra);
  sg_gate_free(gate);
}

TEST(policy_list_stop_outcome) {
  sg_gate_t *gate = list_gate();
  ASSERT_NOT_NULL(gate);
  sg_result_t result = {0};

  /* Stop on the first subcommand with the chosen outcome. */
  ASSERT_SG_OK(sg_gate_set_stop_outcome(gate, SG_VERDICT_REVIEW));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_STOP_FIRST_OUTCOME));
  ASSERT_SG_OK(eval_cmd(gate, "echo a; ls; rm x", &result));
  ASSERT(result.subcommand_count == 2 && result.short_circuited);
  ASSERT(result.verdict == SG_VERDICT_REVIEW);

  /* The default outcome is ALLOW. */
  sg_gate_t *fresh = list_gate();
  ASSERT_NOT_NULL(fresh);
  ASSERT_SG_OK(sg_gate_set_stop_mode(fresh, SG_STOP_FIRST_OUTCOME));
  ASSERT_SG_OK(eval_cmd(fresh, "ls; echo a; rm x", &result));
  ASSERT(result.subcommand_count == 2 && result.short_circuited);
  sg_gate_free(fresh);

  /* Any match stops FIRST_PASS, including a new outcome. */
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_STOP_FIRST_PASS));
  ASSERT_SG_OK(eval_cmd(gate, "cat f; echo a", &result));
  ASSERT(result.subcommand_count == 1 && result.short_circuited);

  /* A value that is not a policy outcome changes nothing. */
  ASSERT(sg_gate_set_stop_outcome(gate, SG_VERDICT_UNDETERMINED) ==
         SG_ERR_INVALID);
  ASSERT(sg_gate_set_stop_outcome(gate, SG_VERDICT_REJECT) == SG_ERR_INVALID);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_STOP_FIRST_OUTCOME));
  ASSERT_SG_OK(eval_cmd(gate, "echo a; ls; rm x", &result));
  ASSERT(result.subcommand_count == 2);
  ASSERT(sg_gate_set_stop_mode(gate, (sg_stop_mode_t)(SG_EVAL_ALL + 1)) ==
         SG_ERR_INVALID);
  sg_gate_free(gate);
}

/* --- OUTPUTS AND OVERRIDES --- */

/* A gate whose allow and deny policies match nothing, so that the policies
 * under test start at index 2 in the order given. */
static sg_gate_t *chain_gate(const char *const *cpls,
                             const sg_verdict_t *outcomes, size_t count) {
  sg_gate_t *gate = sg_gate_new_with_policies_owned(binding_policy("zz-a"),
                                                    binding_policy("zz-b"));
  if (!gate || sg_gate_set_reject_mask(gate, 0) != SG_OK) {
    sg_gate_free(gate);
    return NULL;
  }
  for (size_t i = 0; i < count; i++)
    if (sg_gate_add_policy_owned(gate, binding_policy(cpls[i]), outcomes[i]) !=
        SG_OK) {
      sg_gate_free(gate);
      return NULL;
    }
  return gate;
}

TEST(gate_setter_contract) {
  static const char *paths[] = {"/tmp", "/home/user"};
  static const sg_stop_mode_t modes[] = {
      SG_STOP_FIRST_FAIL, SG_STOP_FIRST_PASS,    SG_STOP_FIRST_ALLOW,
      SG_STOP_FIRST_DENY, SG_STOP_FIRST_OUTCOME, SG_EVAL_ALL};
  static const uint32_t masks[] = {0, UINT32_MAX, SG_REJECT_MASK_DEFAULT};
  sg_gate_t *g = sg_gate_new();
  ASSERT_NOT_NULL(g);
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
    ASSERT_SG_OK(sg_gate_set_cwd(g, paths[i]));
  /* A working directory that does not fit is refused and changes nothing. */
  char long_cwd[513];
  memset(long_cwd, 'x', sizeof(long_cwd) - 1);
  long_cwd[sizeof(long_cwd) - 1] = '\0';
  ASSERT_SG_OK(sg_gate_set_cwd(g, "/stable"));
  ASSERT(sg_gate_set_cwd(g, long_cwd) == SG_ERR_TRUNC);
  for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
    ASSERT_SG_OK(sg_gate_set_stop_mode(g, modes[i]));
  for (size_t i = 0; i < sizeof(masks) / sizeof(masks[0]); i++)
    ASSERT_SG_OK(sg_gate_set_reject_mask(g, masks[i]));
  ASSERT_SG_OK(sg_gate_set_suggestions(g, true));
  ASSERT_SG_OK(sg_gate_set_suggestions(g, false));
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(g, NULL, NULL));
  ASSERT(sg_gate_set_stop_mode(g, (sg_stop_mode_t)-1) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_stop_mode(g, (sg_stop_mode_t)(SG_EVAL_ALL + 1)) ==
         SG_ERR_INVALID);
  sg_gate_free(g);
}

TEST(policy_list_equal_outcomes_keep_the_first) {
  static const char *const cpls[] = {"ls", "ls"};
  static const sg_verdict_t outcomes[] = {SG_VERDICT_REVIEW, SG_VERDICT_REVIEW};
  sg_gate_t *gate = chain_gate(cpls, outcomes, 2); /* 2 and 3 tie */
  ASSERT_NOT_NULL(gate);
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));
  ASSERT(result.subcommands[0].matched_policies == ((1u << 2) | (1u << 3)));
  /* With no outputs declared, the first of equal matches is the decider. */
  ASSERT(result.outputs[0].verdict == SG_VERDICT_REVIEW &&
         result.outputs[0].policy == 2);
  sg_gate_free(gate);
}

TEST(output_vector_and_scalar_projection) {
  sg_gate_t *gate = list_gate();
  ASSERT_NOT_NULL(gate);
  /* A three-dimensional gate: allow, review and discourage policies. */
  ASSERT_SG_OK(sg_gate_add_output(gate, 0, NULL, 0));
  ASSERT_SG_OK(sg_gate_add_output(gate, 2, NULL, 0));
  ASSERT_SG_OK(sg_gate_add_output(gate, 3, NULL, 0));
  ASSERT(sg_gate_output_count(gate) == 3);
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));
  ASSERT(result.output_count == 3);
  ASSERT(result.outputs[0].verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(result.outputs[1].verdict == SG_VERDICT_REVIEW &&
         result.outputs[1].policy == 2);
  ASSERT(result.outputs[2].verdict == SG_VERDICT_UNDETERMINED);
  /* The scalar is the most restrictive output. */
  ASSERT(result.verdict == SG_VERDICT_REVIEW);
  ASSERT_SG_OK(eval_cmd(gate, "echo a", &result));
  ASSERT(result.outputs[0].verdict == SG_VERDICT_ALLOW &&
         result.outputs[0].policy == 0);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  /* Over two commands an output is the most restrictive of its subcommands. */
  ASSERT_SG_OK(eval_cmd(gate, "echo a; ls", &result));
  ASSERT(result.subcommand_count == 2);
  ASSERT(result.outputs[0].verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(result.outputs[1].verdict == SG_VERDICT_REVIEW);
  ASSERT_SG_OK(eval_cmd(gate, "ls; ls", &result));
  ASSERT(result.outputs[1].verdict == SG_VERDICT_REVIEW);

  /* The outputs are bounded and must be installed policies. */
  ASSERT(sg_gate_add_output(gate, 7, NULL, 0) == SG_ERR_INVALID);
  while (sg_gate_output_count(gate) < SG_MAX_OUTPUTS)
    ASSERT_SG_OK(sg_gate_add_output(gate, 0, NULL, 0));
  ASSERT(sg_gate_add_output(gate, 0, NULL, 0) == SG_ERR_INVALID);
  sg_gate_clear_outputs(gate);
  ASSERT(sg_gate_output_count(gate) == 0);
  sg_gate_free(gate);
}

TEST(output_scalar_decider_needs_a_unique_most_restrictive) {
  sg_gate_t *gate = list_gate();
  ASSERT_NOT_NULL(gate);
  /* Three dimensions: allow, review and discourage policies. */
  ASSERT_SG_OK(sg_gate_add_output(gate, 0, NULL, 0));
  ASSERT_SG_OK(sg_gate_add_output(gate, 2, NULL, 0));
  ASSERT_SG_OK(sg_gate_add_output(gate, 3, NULL, 0));
  sg_result_t result = {0};
  /* Only the review output is the most restrictive: it decides the scalar. */
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));
  ASSERT(result.verdict == SG_VERDICT_REVIEW);
  ASSERT(result.deciding_user_data == &list_tags[2]);
  ASSERT(result.subcommands[0].deciding_user_data == &list_tags[2]);
  /* Every output is UNDETERMINED: a tie, and nothing decided it. */
  ASSERT_SG_OK(eval_cmd(gate, "zzz", &result));
  ASSERT(result.deciding_user_data == NULL);

  /* Two outputs tied at the most restrictive name no single policy, even when
   * the same policy decided both. */
  ASSERT_SG_OK(sg_gate_add_output(gate, 2, NULL, 0));
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));
  ASSERT(result.verdict == SG_VERDICT_REVIEW);
  ASSERT(result.outputs[1].user_data == &list_tags[2] &&
         result.outputs[3].user_data == &list_tags[2]);
  ASSERT(result.deciding_user_data == NULL);
  ASSERT(result.subcommands[0].deciding_user_data == NULL);

  /* A gate with a single output is always unique. */
  sg_gate_clear_outputs(gate);
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));
  ASSERT(result.deciding_user_data == &list_tags[2]);
  sg_gate_free(gate);
}

TEST(override_cycle_gives_two_outputs) {
  static const sg_verdict_t outcomes[] = {SG_VERDICT_ALLOW, SG_VERDICT_DENY};
  static int marks[2];
  /* A=2 allow, B=3 deny, each with its own pointer set before installing. */
  sg_gate_t *gate = sg_gate_new_with_policies_owned(binding_policy("zz-a"),
                                                    binding_policy("zz-b"));
  ASSERT_NOT_NULL(gate);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  for (size_t i = 0; i < 2; i++) {
    st_policy_t *policy = binding_policy("echo *");
    ASSERT_NOT_NULL(policy);
    st_policy_set_user_data(policy, &marks[i]);
    ASSERT_SG_OK(sg_gate_add_policy_owned(gate, policy, outcomes[i]));
  }
  uint32_t both[2] = {0};
  ASSERT_SG_OK(sg_gate_add_override(gate, 2, 3, &both[0]));
  ASSERT_SG_OK(sg_gate_add_override(gate, 3, 2, &both[1]));
  /* Both outputs follow both relations, which form a cycle. */
  ASSERT_SG_OK(sg_gate_add_output(gate, 2, both, 2));
  ASSERT_SG_OK(sg_gate_add_output(gate, 3, both, 2));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "echo hi", &result));
  ASSERT(result.output_count == 2);
  /* A overriding B, and B overriding A. */
  ASSERT(result.outputs[0].verdict == SG_VERDICT_ALLOW &&
         result.outputs[0].policy == 2);
  ASSERT(result.outputs[1].verdict == SG_VERDICT_DENY &&
         result.outputs[1].policy == 3);
  ASSERT(result.verdict == SG_VERDICT_DENY);
  /* Each dimension reports the pointer of the policy that decided it, and the
   * scalar the pointer of the most restrictive one. */
  ASSERT(result.outputs[0].user_data == &marks[0] &&
         result.outputs[1].user_data == &marks[1]);
  ASSERT(result.deciding_user_data == &marks[1]);
  ASSERT(result.subcommands[0].deciding_user_data == &marks[1]);
  /* A traversal that matches nothing still ends. */
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));
  ASSERT(result.outputs[0].verdict == SG_VERDICT_UNDETERMINED &&
         result.outputs[1].verdict == SG_VERDICT_UNDETERMINED);
  sg_gate_free(gate);
}

TEST(override_fan_out_tries_relations_in_creation_order) {
  static const char *const cpls[] = {"echo ok", "echo *", "echo *"};
  static const sg_verdict_t outcomes[] = {SG_VERDICT_ALLOW, SG_VERDICT_REVIEW,
                                          SG_VERDICT_DENY};
  sg_result_t result = {0};
  /* The root (2) does not match; it fans out to 3 (review) and 4 (deny). */
  for (unsigned reversed = 0; reversed < 2; reversed++) {
    sg_gate_t *gate = chain_gate(cpls, outcomes, 3);
    ASSERT_NOT_NULL(gate);
    uint32_t relations[2] = {0};
    ASSERT_SG_OK(
        sg_gate_add_override(gate, 2, reversed ? 4 : 3, &relations[0]));
    ASSERT_SG_OK(
        sg_gate_add_override(gate, 2, reversed ? 3 : 4, &relations[1]));
    ASSERT_SG_OK(sg_gate_add_output(gate, 2, relations, 2));
    ASSERT_SG_OK(eval_cmd(gate, "echo no", &result));
    /* The first relation created that reaches a match decides, not the
     * strictest. */
    ASSERT(result.outputs[0].verdict ==
           (reversed ? SG_VERDICT_DENY : SG_VERDICT_REVIEW));
    sg_gate_free(gate);
  }
}

TEST(override_declaration_validation_and_removal) {
  static const char *const cpls[] = {"echo *", "echo ok", "ls"};
  static const sg_verdict_t outcomes[] = {SG_VERDICT_DENY, SG_VERDICT_ALLOW,
                                          SG_VERDICT_REVIEW};
  sg_gate_t *gate = chain_gate(cpls, outcomes, 3); /* 2 broad, 3 ok, 4 ls */
  ASSERT_NOT_NULL(gate);
  uint32_t relation = 0, ok_over_broad = 0, ls_over_ok = 0;
  ASSERT(sg_gate_add_override(gate, 9, 2, &relation) == SG_ERR_INVALID);
  ASSERT(sg_gate_add_override(gate, 2, 9, &relation) == SG_ERR_INVALID);
  ASSERT(sg_gate_add_override(gate, 2, 2, &relation) == SG_ERR_INVALID);
  ASSERT(sg_gate_relation_count(gate) == 0);
  /* The relations are bounded; the same pair may be related again. */
  for (uint32_t i = 0; i < SG_MAX_RELATIONS; i++)
    ASSERT_SG_OK(sg_gate_add_override(gate, 3, 2, &relation));
  ASSERT(relation == SG_MAX_RELATIONS - 1);
  ASSERT(sg_gate_add_override(gate, 3, 2, &relation) == SG_ERR_INVALID);
  ASSERT(sg_gate_relation_count(gate) == SG_MAX_RELATIONS);
  sg_gate_clear_overrides(gate);
  ASSERT(sg_gate_relation_count(gate) == 0);
  ASSERT_SG_OK(sg_gate_add_override(gate, 3, 2, &ok_over_broad));
  ASSERT_SG_OK(sg_gate_add_override(gate, 4, 3, &ls_over_ok));
  ASSERT(ok_over_broad == 0 && ls_over_ok == 1);
  /* An output may only name relations that exist. */
  const uint32_t unknown[] = {5};
  ASSERT(sg_gate_add_output(gate, 3, unknown, 1) == SG_ERR_INVALID);
  ASSERT(sg_gate_add_output(gate, 9, NULL, 0) == SG_ERR_INVALID);
  ASSERT(sg_gate_output_count(gate) == 0);
  const uint32_t first[] = {ok_over_broad};
  const uint32_t both[] = {ok_over_broad, ls_over_ok};
  ASSERT_SG_OK(sg_gate_add_output(gate, 3, first, 1));
  ASSERT_SG_OK(sg_gate_add_output(gate, 4, both, 2));

  /* Removing the broad policy removes the relation that names it, renumbers
   * the rest, and keeps the other relation in the second output: "echo ok" is
   * now 2 and "ls" is 3, with the relation 3 -> 2 now stored as id 0. */
  sg_gate_remove_policy(gate, 2);
  ASSERT(sg_gate_policy_count(gate) == 4);
  ASSERT(sg_gate_relation_count(gate) == 1);
  uint32_t overrider = 0, overridden = 0;
  sg_gate_relation_at(gate, 0, &overrider, &overridden);
  ASSERT(overrider == 3 && overridden == 2);
  ASSERT(sg_gate_output_count(gate) == 2);
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));
  ASSERT(result.outputs[1].verdict == SG_VERDICT_REVIEW &&
         result.outputs[1].policy == 3);
  ASSERT_SG_OK(eval_cmd(gate, "echo ok", &result));
  ASSERT(result.outputs[0].verdict == SG_VERDICT_ALLOW &&
         result.outputs[0].policy == 2);
  /* An output rooted at a removed policy is dropped. */
  sg_gate_remove_policy(gate, 2);
  ASSERT(sg_gate_output_count(gate) == 1);
  sg_gate_clear_overrides(gate);
  ASSERT(sg_gate_relation_count(gate) == 0);
  sg_gate_free(gate);
}

TEST(override_removal_of_an_overrider_and_a_borrowed_policy) {
  st_policy_t *borrowed = binding_policy("pwd");
  ASSERT_NOT_NULL(borrowed);
  static const char *const cpls[] = {"echo *", "echo ok"};
  static const sg_verdict_t outcomes[] = {SG_VERDICT_DENY, SG_VERDICT_ALLOW};
  sg_gate_t *gate = chain_gate(cpls, outcomes, 2); /* 2 broad, 3 specific */
  ASSERT_NOT_NULL(gate);
  ASSERT_SG_OK(sg_gate_add_policy_borrowed(gate, borrowed, SG_VERDICT_AUDIT));
  uint32_t over_broad = 0, over_borrowed = 0;
  ASSERT_SG_OK(sg_gate_add_override(gate, 3, 2, &over_broad));
  ASSERT_SG_OK(sg_gate_add_override(gate, 3, 4, &over_borrowed));
  const uint32_t both[] = {over_broad, over_borrowed};
  ASSERT_SG_OK(sg_gate_add_output(gate, 3, both, 2));
  ASSERT_SG_OK(sg_gate_add_output(gate, 4, NULL, 0));

  /* Removing the overrider drops both relations and the output rooted at it;
   * the output rooted at the borrowed policy keeps its place. */
  sg_gate_remove_policy(gate, 3);
  ASSERT(sg_gate_relation_count(gate) == 0);
  ASSERT(sg_gate_output_count(gate) == 1);
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "pwd", &result));
  ASSERT(result.outputs[0].verdict == SG_VERDICT_AUDIT &&
         result.outputs[0].policy == 3);

  /* Removing a borrowed policy does not free it: it is still ours. */
  sg_gate_remove_policy(gate, 3);
  ASSERT(sg_gate_policy_count(gate) == 3 && sg_gate_output_count(gate) == 0);
  ASSERT(st_policy_rule_count(borrowed) == 1);
  sg_gate_free(gate);
  st_policy_free(borrowed);
}

TEST(policy_allocation_failure_returns_the_error_and_no_verdict) {
  /* A three-dimensional gate, so the vector is covered as well. */
  sg_result_t result = {0};
  size_t allocations = 0;
  sg_output_t expected[3] = {{0}};
  sg_verdict_t expected_verdict = SG_VERDICT_UNDETERMINED;
  for (unsigned pass = 0; pass < 2; pass++) {
    sg_gate_t *probe = list_gate();
    ASSERT_NOT_NULL(probe);
    ASSERT_SG_OK(sg_gate_add_output(probe, 0, NULL, 0));
    ASSERT_SG_OK(sg_gate_add_output(probe, 2, NULL, 0));
    ASSERT_SG_OK(sg_gate_add_output(probe, 3, NULL, 0));
    st_test_alloc_reset();
    ASSERT_SG_OK(eval_cmd(probe, "ls; cat f", &result));
    if (pass == 0) {
      allocations = st_test_alloc_count();
      ASSERT(result.output_count == 3);
      memcpy(expected, result.outputs, sizeof(expected));
      expected_verdict = result.verdict;
    }
    st_test_alloc_reset();
    sg_gate_free(probe);
  }
  ASSERT(allocations > 0);

  bool saw_error = false, saw_deny_slot = false, saw_policy = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    sg_gate_t *gate = list_gate();
    ASSERT_NOT_NULL(gate);
    ASSERT_SG_OK(sg_gate_add_output(gate, 0, NULL, 0));
    ASSERT_SG_OK(sg_gate_add_output(gate, 2, NULL, 0));
    ASSERT_SG_OK(sg_gate_add_output(gate, 3, NULL, 0));
    st_test_alloc_fail_at(fail_at);
    sg_error_t error = eval_cmd(gate, "ls; cat f", &result);
    st_test_alloc_reset();
    if (error == SG_OK) {
      /* The failure fell where it costs nothing: the answer is unchanged. */
      ASSERT(result.verdict == expected_verdict);
      for (uint32_t k = 0; k < 3; k++)
        ASSERT(result.outputs[k].verdict == expected[k].verdict &&
               result.outputs[k].policy == expected[k].policy);
    } else {
      /* The error is returned and no verdict is claimed, in the scalar or in
       * any dimension. */
      saw_error = true;
      ASSERT(error == SG_ERR_MEMORY);
      /* A policy that could not be evaluated says so on its subcommand; a
       * failure while rendering suggestions afterwards has no such message. */
      for (uint32_t i = 0; i < result.subcommand_count; i++) {
        const char *reason = result.subcommands[i].reject_reason;
        if (reason && !strcmp(reason, "deny policy evaluation failed"))
          saw_deny_slot = true;
        else if (reason && !strcmp(reason, "policy evaluation failed"))
          saw_policy = true;
      }
      ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
      ASSERT(result.output_count == 3);
      for (uint32_t k = 0; k < result.output_count; k++)
        ASSERT(result.outputs[k].verdict == SG_VERDICT_UNDETERMINED &&
               result.outputs[k].policy == UINT32_MAX);
    }
    sg_gate_free(gate);
  }
  ASSERT(saw_error && saw_deny_slot && saw_policy);
}

TEST(anomaly_component_borrowed_views) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate);
  ASSERT(sg_gate_anomaly_raw_model_borrowed(gate) == NULL &&
         sg_gate_anomaly_type_model_borrowed(gate) == NULL);
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));
  const sg_anomaly_model_t *raw = sg_gate_anomaly_raw_model_borrowed(gate);
  const sg_anomaly_model_t *type = sg_gate_anomaly_type_model_borrowed(gate);
  ASSERT(raw && type && raw != type);
  ASSERT(sg_anomaly_model_vocab_size(raw) == 0 &&
         sg_anomaly_model_vocab_size(type) == 0);
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "echo ok; true; pwd", &result));
  ASSERT(sg_anomaly_model_vocab_size(raw) == 3 &&
         sg_anomaly_model_total_unigrams(type) == 3);
  sg_test_alloc_fail_at(1);
  sg_error_t error = sg_gate_enable_anomaly(gate, 100.0, NULL);
  sg_test_alloc_reset();
  ASSERT(error == SG_ERR_MEMORY);
  ASSERT(sg_gate_anomaly_raw_model_borrowed(gate) == raw &&
         sg_gate_anomaly_type_model_borrowed(gate) == type);
  sg_gate_disable_anomaly(gate);
  ASSERT(sg_gate_anomaly_raw_model_borrowed(gate) == NULL &&
         sg_gate_anomaly_type_model_borrowed(gate) == NULL);
  sg_gate_free(gate);
}

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

  ASSERT(!sg_gate_anomaly_had_error(g));
  sg_gate_free(NULL);

  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "ls", false));
  char buf[64];
  sg_result_t r;

  ASSERT(sg_gate_evaluate(g, "ls", 0, buf, sizeof(buf), &r) == SG_ERR_INVALID);

  ASSERT(sg_gate_evaluate(g, "ls", 2, buf, 0, &r) == SG_ERR_INVALID);
  ASSERT(sg_gate_evaluate(g, "", 0, buf, sizeof(buf), &r) == SG_ERR_INVALID);
  static const char embedded_nul[] = {'l', 's', '\0', ';', 'i', 'd'};
  ASSERT(sg_gate_evaluate(g, embedded_nul, sizeof(embedded_nul), buf,
                          sizeof(buf), &r) == SG_ERR_INVALID);

  sg_gate_free(g);
}

/* Shellgate consumes Shellsplit's completed command ranges. Only syntax that
 * actually quotes a word fragment may hide metacharacters from the outer
 * command list; ordinary brace and bracket text remains structural. */
TEST(word_fragment_operator_shellgate_contract) {
  static const char *const opaque_cases[] = {
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

  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  for (size_t i = 0; i < sizeof(opaque_cases) / sizeof(opaque_cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, opaque_cases[i], &result));
    ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
    ASSERT(result.subcommand_count == 1);
    ASSERT(result.subcommands[0].netargv != NULL);
    ASSERT(!result.truncated);
  }
  static const char *const structural_cases[] = {
      "echo prefix{left|right}suffix",
      "echo [left|right]",
      "echo [[:alpha:]|]",
  };
  for (size_t i = 0; i < sizeof(structural_cases) / sizeof(structural_cases[0]);
       i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, structural_cases[i], &result));
    ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
    ASSERT(result.subcommand_count == 2);
    ASSERT(result.subcommands[0].netargv != NULL);
    ASSERT(result.subcommands[1].netargv != NULL);
    ASSERT(!result.truncated);
  }
  sg_gate_free(gate);
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
      st_token_array_t decoded = {0};
      ASSERT(st_netargv_classify_view(
                 (st_netargv_view_t){
                     .data = result.subcommands[j].netargv,
                     .length = result.subcommands[j].netargv_length,
                 },
                 &decoded) == ST_OK);
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

  static const char *const whitespace_function_declarations[] = {
      "foo () { echo x; }",          "foo ( ) { echo x; }",
      "foo\t(\t) ( echo x )",        "foo\\\n() { echo x; }",
      "function foo () { echo x; }", "function foo ( ) ( echo x )",
  };
  for (size_t i = 0; i < sizeof(whitespace_function_declarations) /
                             sizeof(whitespace_function_declarations[0]);
       i++) {
    memset(&result, 0, sizeof(result));
    memset(diagnostic, 0, sizeof(diagnostic));
    ASSERT(sg_gate_evaluate(g, whitespace_function_declarations[i],
                            strlen(whitespace_function_declarations[i]),
                            diagnostic, sizeof(diagnostic),
                            &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT && !result.truncated);
    ASSERT(strcmp(diagnostic, "parse error") == 0);
  }

  ASSERT(eval_with_prefix(g, "{ echo x; }", 4, &result) == SG_ERR_TRUNC);
  ASSERT(result.truncated);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  sg_gate_free(g);
}

/* --- FEATURE REJECTION --- */

/* A named descriptor allocation is not an outer-command write by itself.
 * Shellgate should still evaluate every executable stage, preserve the
 * ordinary process-substitution dynamic-I/O marker, and allow the later exact
 * `$name` descriptor use to carry the payload to its consumer. */
TEST(named_fd_process_substitution_policy_contract) {
  static const char command[] =
      "exec {sink}> >(cat); printf payload >&\"${sink}\"";
  sg_gate_t *gate = gate_with_rules(
      (const char *[]){"exec", "cat", "producer", "printf *", ": *"}, 5);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));

  sg_result_t result = {0};
  for (size_t pass = 0; pass < 3; pass++) {
    ASSERT_SG_OK(eval_cmd(gate, command, &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW);
    ASSERT(result.subcommand_count == 3);
    ASSERT(result.has_dynamic_substitution_io);
    ASSERT(
        !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
    ASSERT(!result.subcommands[0].has_dynamic_substitution_io);
    ASSERT(result.subcommands[1].has_dynamic_substitution_io);
    ASSERT(!result.subcommands[2].has_dynamic_substitution_io);
    ASSERT_STR(result.subcommands[2].netargv, "6:printf,7:payload,");
    if (pass == 0)
      ASSERT(isinf(result.anomaly_score));
    else
      ASSERT(isfinite(result.anomaly_score));
  }
  ASSERT(test_anomaly_vocabulary(gate) > 0);

  /* Input process substitution is retained as a named-FD setup until a later
   * exact `$source` use. Its producer-to-exec route is still represented
   * dynamic topology, but setup neither moves bytes nor asks the caller to
   * inspect data as code. */
  ASSERT_SG_OK(
      eval_cmd(gate, "exec {source}< <(producer); printf payload", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3 &&
         result.has_dynamic_substitution_io &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  bool source_setup_owner = false;
  bool source_producer = false;
  bool source_payload = false;
  for (uint32_t i = 0; i < result.subcommand_count; i++) {
    const sg_subcommand_result_t *subcommand = &result.subcommands[i];
    if (subcommand->display_command == NULL)
      continue;
    if (strcmp(subcommand->display_command, "exec") == 0)
      source_setup_owner = subcommand->has_dynamic_substitution_io &&
                           !((subcommand->requirements &
                              SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0);
    else if (strcmp(subcommand->display_command, "producer") == 0)
      source_producer = !subcommand->has_dynamic_substitution_io;
    else if (strncmp(subcommand->display_command, "printf", 6) == 0)
      source_payload = !subcommand->has_dynamic_substitution_io;
  }
  ASSERT(source_setup_owner && source_producer && source_payload);

  /* Both nested producers redirect their inherited stdout away. The retained
   * endpoint has no producer command edge, but the named input setup remains
   * dynamic topology and the later exact descriptor use supplies cat. */
  ASSERT_SG_OK(eval_cmd(gate,
                        "exec {source}< <(printf first >/tmp/source-first; "
                        "printf second >/tmp/source-second); cat <&\"$source\"",
                        &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 4 &&
         result.has_dynamic_substitution_io &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  uint32_t redirected_producers = 0;
  bool unconnected_source_setup = false;
  bool unconnected_source_consumer = false;
  for (uint32_t i = 0; i < result.subcommand_count; i++) {
    const sg_subcommand_result_t *subcommand = &result.subcommands[i];
    if (subcommand->display_command == NULL)
      continue;
    if (strcmp(subcommand->display_command, "exec") == 0)
      unconnected_source_setup = subcommand->has_dynamic_substitution_io;
    else if (strncmp(subcommand->display_command, "printf", 6) == 0) {
      redirected_producers++;
      ASSERT(!subcommand->has_dynamic_substitution_io);
    } else if (strcmp(subcommand->display_command, "cat") == 0)
      unconnected_source_consumer = subcommand->has_dynamic_substitution_io;
  }
  ASSERT(unconnected_source_setup && redirected_producers == 2 &&
         unconnected_source_consumer);

  /* The matching output form has setup topology but no nested stdin flow:
   * the nested cat supplied its own input. The result remains dynamically
   * structured, while no simple command is falsely reported as its byte-flow
   * consumer. */
  ASSERT_SG_OK(eval_cmd(gate,
                        "exec {sink}> >(cat </tmp/named-sink); "
                        "printf payload >&\"$sink\"",
                        &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3 &&
         result.has_dynamic_substitution_io &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  for (uint32_t i = 0; i < result.subcommand_count; i++)
    ASSERT(!result.subcommands[i].has_dynamic_substitution_io);

  /* Ordinary named file setup and descriptor duplication are not process
   * substitutions and must not inherit the dynamic-topology marker. */
  ASSERT_SG_OK(
      eval_cmd(gate, "exec {source}</tmp/input; printf payload", &result));
  ASSERT(!result.has_dynamic_substitution_io &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT_SG_OK(eval_cmd(gate, "exec {source}<&0; printf payload", &result));
  ASSERT(!result.has_dynamic_substitution_io &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  /* The group body's exec allocation is visible when a later word starts a
   * nested shell. It must reach policy evaluation, not fail graph parsing. */
  ASSERT_SG_OK(eval_cmd(gate,
                        "{ exec {fd}</tmp/group-input; "
                        "printf '%s' \"$(cat <&$fd)\"; }",
                        &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommand_count == 3 &&
         ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  /* A comment after the group's redirects cannot make its descriptor state
   * conditional merely by containing connector punctuation. The group's own
   * redirect is a duplication of a contract descriptor, which cannot fail,
   * so the body's allocation is proven for the later read. */
  static const char *const commented_connectors[] = {
      "{ exec {fd}</tmp/group-input; } >&2 # && comment\n"
      "printf '%s' \"$(cat <&$fd)\"",
      "{ exec {fd}</tmp/group-input; } >&2 # || comment\n"
      "printf '%s' \"$(cat <&$fd)\"",
  };
  for (size_t i = 0;
       i < sizeof(commented_connectors) / sizeof(commented_connectors[0]);
       i++) {
    ASSERT_SG_OK(eval_cmd(gate, commented_connectors[i], &result));
    ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
           ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  }
  ASSERT_SG_OK(
      eval_cmd(gate, "echo `printf x; printf y`; printf done", &result));
  ASSERT(result.subcommand_count >= 3 &&
         ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT(sg_gate_evaluate(gate, "printf payload >&\"$missing\"",
                          strlen("printf payload >&\"$missing\""), eval_buf,
                          sizeof(eval_buf), &result) == SG_ERR_PARSE);
  /* A semantic parse rejection exposes Shellgate's documented one synthetic
   * result, never a partially evaluated executable command. */
  ASSERT(result.verdict == SG_VERDICT_REJECT && result.subcommand_count == 1 &&
         result.subcommands[0].verdict == SG_VERDICT_REJECT &&
         strcmp(eval_buf, "parse error") == 0);

  /* A complete glob may expand to a descriptor number, so legacy `>&word`
   * must reject it rather than claiming combined file output. An unmatched
   * bracket is literal and therefore keeps a dynamic filename topology. */
  ASSERT(sg_gate_evaluate(gate, "printf payload >&[[:digit:]]",
                          strlen("printf payload >&[[:digit:]]"), eval_buf,
                          sizeof(eval_buf), &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT && result.subcommand_count == 1 &&
         result.subcommands[0].verdict == SG_VERDICT_REJECT &&
         strcmp(eval_buf, "parse error") == 0);
  ASSERT_SG_OK(sg_gate_evaluate(gate, "printf payload >&[$fd",
                                strlen("printf payload >&[$fd"), eval_buf,
                                sizeof(eval_buf), &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1 &&
         result.subcommands[0].verdict == SG_VERDICT_ALLOW &&
         strcmp(result.subcommands[0].netargv, "6:printf,7:payload,") == 0);

  /* The descriptor is not visible to a word expansion in the command which
   * allocates it. Under Bash's default `varredir_close` behavior, however, a
   * preceding ordinary command does retain an open named descriptor. */
  static const char *const snapshot_rejections[] = {
      "printf payload {fd}</tmp/in \"$(cat <&$fd)\"",
      "exec {fd}</tmp/in; exec {fd}<&-; printf payload \"$(cat <&$fd)\"",
      "printf > >(cat <&$fd) {fd}</tmp/in",
      ("shopt -s varredir_close; : {fd}</tmp/in; "
       "printf payload \"$(cat <&$fd)\""),
      ("x+=value shopt -u varredir_close; : {fd}</tmp/in; "
       "printf payload \"$(cat <&$fd)\""),
      ("x+\\\n=value shopt -s varredir_close; : {fd}</tmp/in; "
       "printf payload \"$(cat <&$fd)\""),
      ("sh'opt' '-s' varredir_close; : {fd}</tmp/in; "
       "printf payload \"$(cat <&$fd)\""),
      ("shopt -s lastpipe; printf source | : {fd}</tmp/in; "
       "printf payload \"$(cat <&$fd)\""),
      ("command shopt -u lastpipe; printf source | : {fd}</tmp/in; "
       "printf payload \"$(cat <&$fd)\""),
      ("eval 'shopt -s lastpipe'; printf source | : {fd}</tmp/in; "
       "printf payload \"$(cat <&$fd)\""),
      (". /tmp/shell-state; printf source | : {fd}</tmp/in; "
       "printf payload \"$(cat <&$fd)\""),
      ("command source /tmp/shell-state; printf source | : {fd}</tmp/in; "
       "printf payload \"$(cat <&$fd)\""),
      ("trap 'shopt -s lastpipe' DEBUG; printf source | : {fd}</tmp/in; "
       "printf payload \"$(cat <&$fd)\""),
      ("alias change_scope='shopt -s lastpipe'; "
       "printf source | : {fd}</tmp/in; printf payload \"$(cat <&$fd)\""),
      ("shopt -s expand_aliases; printf source | : {fd}</tmp/in; "
       "printf payload \"$(cat <&$fd)\""),
      ("history -s 'shopt -s lastpipe'; fc -s -1; "
       "printf source | : {fd}</tmp/in; printf payload \"$(cat <&$fd)\""),
      ("enable -f /tmp/shell-state change_scope; "
       "printf source | : {fd}</tmp/in; printf payload \"$(cat <&$fd)\""),
      /* Dynamic selectors can mutate current-shell POSIX mode or assign a
       * mode-changing variable. Shellgate must reject them before policy
       * evaluation, regardless of the eventual expansion value. */
      "set -o \"$option\"; printf payload",
      "shopt -s -o posix; printf payload",
      "shopt -so posix; printf payload",
      "command shopt -s -o posix; printf payload",
      "shopt -s -o \"$option\"; printf payload",
      "printf -v \"$target\" enabled; printf payload",
      ": $((fd1++)); printf payload",
      ": $(( $(printf 'fd=12') )); printf payload",
      "command pushd /tmp; printf payload",
      "builtin popd; printf payload",
      ("exec {fd}>/tmp/out; printf -v 'fd[0]' enabled; "
       "printf payload >&$fd"),
      ("exec {fd}>/tmp/out; read -a fd; printf payload >&$fd"),
      ("exec {fd}>/tmp/out; wait -p fd; printf payload >&$fd"),
      ("exec {fd}>/tmp/out; : $((fd=9)); printf payload >&$fd"),
      "mapfile -c 1 -C 'printf callback' values </tmp/input; printf payload",
      ("exec {fd}>/tmp/readonly-first; readonly fd; "
       "exec {fd}>/tmp/readonly-second; printf payload >&$fd"),
      ("exec {fd}>/tmp/readonly-first; declare -r fd; "
       "exec {fd}>/tmp/readonly-second; printf payload >&$fd"),
      ("exec {fd}>/tmp/readonly-first; typeset -r fd; "
       "exec {fd}>/tmp/readonly-second; printf payload >&$fd"),
      ("exec {fd}>/tmp/readonly-first; command -p readonly fd; "
       "exec {fd}>/tmp/readonly-second; printf payload >&$fd"),
      ("( printf payload >&$fd ) {fd}>/tmp/subshell-out; "
       "printf payload >&$fd"),
      ("false && { :; exec {fd}</tmp/skipped; }; "
       "printf payload \"$(cat <&$fd)\""),
      ("true || { :; exec {fd}</tmp/skipped; }; "
       "printf payload \"$(cat <&$fd)\""),
  };
  for (size_t i = 0;
       i < sizeof(snapshot_rejections) / sizeof(snapshot_rejections[0]); i++) {
    /* A bound-then-closed name still resolves, so reading it is a certain
     * descriptor failure (unmodeled), unlike an unbound name, which is a
     * parse error. */
    if (i == 1) {
      ASSERT(sg_gate_evaluate(gate, snapshot_rejections[i],
                              strlen(snapshot_rejections[i]), eval_buf,
                              sizeof(eval_buf), &result) == SG_ERR_UNMODELED);
      ASSERT(result.verdict == SG_VERDICT_REJECT);
      continue;
    }
    ASSERT(sg_gate_evaluate(gate, snapshot_rejections[i],
                            strlen(snapshot_rejections[i]), eval_buf,
                            sizeof(eval_buf), &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           result.subcommand_count == 1 &&
           result.subcommands[0].verdict == SG_VERDICT_REJECT &&
           strcmp(eval_buf, "parse error") == 0);
  }

  static const char persisted_named_fd[] =
      "printf payload {fd}>/tmp/out; printf payload >&$fd";
  ASSERT_SG_OK(sg_gate_evaluate(gate, persisted_named_fd,
                                sizeof(persisted_named_fd) - 1, eval_buf,
                                sizeof(eval_buf), &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 2);
  ASSERT(result.subcommands[0].verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommands[1].verdict == SG_VERDICT_ALLOW);

  static const char *const adjacent_named_fd[] = {
      "exec {fd}>/dev/null; exec {fd}>&-{out}>/dev/null; printf payload >&$out",
      "exec {fd}</dev/null; exec {fd}<&-{out}</dev/null; cat <&$out",
      "exec 9>/dev/null; exec 9>&-{out}>/dev/null; printf payload >&$out",
      "exec 9</dev/null; exec 9<&-{out}</dev/null; cat <&$out",
  };
  for (size_t i = 0;
       i < sizeof(adjacent_named_fd) / sizeof(adjacent_named_fd[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, adjacent_named_fd[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3);
    ASSERT_STR(result.subcommands[0].netargv, "4:exec,");
    ASSERT_STR(result.subcommands[1].netargv, "4:exec,");
    ASSERT_STR(result.subcommands[2].netargv,
               i % 2 ? "3:cat," : "6:printf,7:payload,");
    ASSERT(
        !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
        !result.has_dynamic_substitution_io);
  }

  /* Descriptor identity erases backslash-LF, so a binding and its later
   * reference need not share one raw spelling. CR remains significant; the
   * cases below remain valid ordinary syntax without forming a named FD. */
  static const char *const continued_named_fd[] = {
      "exec {f\\\nd}>/tmp/lf-declaration; printf payload >&$fd",
      "exec {fd}>/tmp/lf-reference; printf payload >&$f\\\nd",
      "exec {fd}>/tmp/lf-braced-reference; printf payload >&\"${f\\\nd}\"",
      "exec {fd}>/tmp/dollar-lf-reference; printf payload >&$\\\n{fd}",
      "exec {fd}>/tmp/dollar-quoted-reference; printf payload >&\"$\\\n{fd}\"",
  };
  for (size_t i = 0;
       i < sizeof(continued_named_fd) / sizeof(continued_named_fd[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, continued_named_fd[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2 &&
           result.subcommands[0].verdict == SG_VERDICT_ALLOW &&
           result.subcommands[1].verdict == SG_VERDICT_ALLOW &&
           result.subcommands[1].write_count == 1);
  }
  static const char *const non_continued_named_fd[] = {
      ": {f\\\rd}>/tmp/bare-cr-out",
      ": {f\\\r\n: d}>/tmp/crlf-out",
  };
  for (size_t i = 0;
       i < sizeof(non_continued_named_fd) / sizeof(non_continued_named_fd[0]);
       i++) {
    ASSERT_SG_OK(eval_cmd(gate, non_continued_named_fd[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW &&
           result.subcommand_count == i + 1);
  }

  /* A persistent named-FD close is valid setup in its own right, but a later
   * exact descriptor use must fail graph resolution rather than be evaluated
   * against the retired binding. */
  static const char closed_named_fd[] =
      "exec {fd}>/tmp/closed-out; exec {fd}>&-";
  ASSERT_SG_OK(sg_gate_evaluate(gate, closed_named_fd,
                                sizeof(closed_named_fd) - 1, eval_buf,
                                sizeof(eval_buf), &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2 &&
         result.subcommands[0].verdict == SG_VERDICT_ALLOW &&
         result.subcommands[1].verdict == SG_VERDICT_ALLOW);

  /* A bound-then-closed name still resolves, so using it is a certain
   * descriptor failure (unmodeled), unlike an unbound name, which is a
   * parse error. */
  static const char closed_named_fd_use[] =
      "exec {fd}>/tmp/closed-out; exec {fd}>&-; printf payload >&$fd";
  ASSERT(sg_gate_evaluate(gate, closed_named_fd_use,
                          sizeof(closed_named_fd_use) - 1, eval_buf,
                          sizeof(eval_buf), &result) == SG_ERR_UNMODELED);
  ASSERT(result.verdict == SG_VERDICT_REJECT && result.subcommand_count == 1 &&
         result.subcommands[0].verdict == SG_VERDICT_REJECT &&
         strcmp(eval_buf, "no safe dependency model") == 0);

  /* Assignment prefixes are temporary in Bash. Shellgate must not reject the
   * command by discarding the descriptor route before its redirect expands. */
  static const char prefixed_named_fd[] =
      "exec {fd}>/tmp/prefix-out; fd=shadow printf payload >&$fd; "
      "printf payload >&$fd";
  ASSERT_SG_OK(sg_gate_evaluate(gate, prefixed_named_fd,
                                sizeof(prefixed_named_fd) - 1, eval_buf,
                                sizeof(eval_buf), &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3 &&
         result.subcommands[1].verdict == SG_VERDICT_ALLOW &&
         result.subcommands[2].verdict == SG_VERDICT_ALLOW);

  static const char prefixed_append_named_fd[] =
      "exec {fd}>/tmp/prefix-append-out; fd+=shadow printf payload >&$fd; "
      "printf payload >&$fd";
  ASSERT_SG_OK(sg_gate_evaluate(gate, prefixed_append_named_fd,
                                sizeof(prefixed_append_named_fd) - 1, eval_buf,
                                sizeof(eval_buf), &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3 &&
         result.subcommands[1].verdict == SG_VERDICT_ALLOW &&
         result.subcommands[2].verdict == SG_VERDICT_ALLOW);

  /* An assignment-only command changes the descriptor variable instead. */
  static const char reassigned_named_fd[] =
      "exec {fd}>/tmp/reassigned-out; f\\\nd=shadow; printf payload >&$fd";
  ASSERT(sg_gate_evaluate(gate, reassigned_named_fd,
                          sizeof(reassigned_named_fd) - 1, eval_buf,
                          sizeof(eval_buf), &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT && result.subcommand_count == 1 &&
         result.subcommands[0].verdict == SG_VERDICT_REJECT &&
         strcmp(eval_buf, "parse error") == 0);

  static const char reassigned_append_named_fd[] =
      "exec {fd}>/tmp/reassigned-append-out; f\\\n"
      "d+=shadow; printf payload >&$fd";
  ASSERT(sg_gate_evaluate(gate, reassigned_append_named_fd,
                          sizeof(reassigned_append_named_fd) - 1, eval_buf,
                          sizeof(eval_buf), &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT && result.subcommand_count == 1 &&
         result.subcommands[0].verdict == SG_VERDICT_REJECT &&
         strcmp(eval_buf, "parse error") == 0);

  /* The policy surface receives canonical argv after quote removal, while the
   * graph must also preserve the current-shell numeric descriptor route. */
  static const char quoted_persistent_exec[] =
      "e'x'ec 3>/tmp/quoted-out; printf payload >&3";
  ASSERT_SG_OK(sg_gate_evaluate(gate, quoted_persistent_exec,
                                sizeof(quoted_persistent_exec) - 1, eval_buf,
                                sizeof(eval_buf), &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2 &&
         result.subcommands[0].verdict == SG_VERDICT_ALLOW &&
         result.subcommands[1].verdict == SG_VERDICT_ALLOW);
  ASSERT_STR(result.subcommands[0].netargv, "4:exec,");
  ASSERT_STR(result.subcommands[1].netargv, "6:printf,7:payload,");

  /* Shellgate's anomaly path builds canonical command sequences after graph
   * analysis. A group-tail symbolic duplication with whitespace must reach
   * both surfaces successfully, rather than becoming a late parse failure. */
  static const char grouped_whitespace_named_fd[] =
      "exec {sink}> >(cat); { printf payload; } >& \"${sink}\"";
  ASSERT_SG_OK(sg_gate_evaluate(gate, grouped_whitespace_named_fd,
                                sizeof(grouped_whitespace_named_fd) - 1,
                                eval_buf, sizeof(eval_buf), &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 3);
  ASSERT(result.has_dynamic_substitution_io);
  ASSERT(result.subcommands[2].verdict == SG_VERDICT_ALLOW);
  ASSERT_STR(result.subcommands[2].netargv, "6:printf,7:payload,");
  sg_gate_free(gate);
}

/* Static quote removal applies to descriptor-variable mutations too. Shellgate
 * must keep an unrelated named route usable while a dynamic target continues
 * to reject the graph before partially evaluating its command sequence. */
TEST(named_fd_builtin_operand_policy_contract) {
  sg_gate_t *gate =
      gate_with_rules((const char *[]){"exec", "read *", "read", "unset *",
                                       "printf *", "command *"},
                      6);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1000000.0, NULL));
  for (size_t i = 0; i < sizeof(shellsplit_test_builtin_routes) /
                             sizeof(shellsplit_test_builtin_routes[0]);
       i++) {
    sg_result_t result;
    sg_error_t status =
        eval_cmd(gate, shellsplit_test_builtin_routes[i].source, &result);
    if (shellsplit_test_builtin_routes[i].unmodeled) {
      ASSERT(status == SG_ERR_UNMODELED && result.verdict == SG_VERDICT_REJECT);
      continue;
    }
    if (shellsplit_test_builtin_routes[i].resolved) {
      if (status != SG_OK || result.verdict == SG_VERDICT_REJECT)
        fprintf(stderr, "builtin policy route case %zu failed: %s (%d, %d)\n",
                i, shellsplit_test_builtin_routes[i].source, status,
                result.verdict);
      ASSERT(status == SG_OK && result.verdict != SG_VERDICT_REJECT);
      /* A node-free cd transition can be omitted from the policy command
       * projection; exec and the following writer are still retained. */
      ASSERT(result.subcommand_count >= 2);
      ASSERT(result.subcommands[result.subcommand_count - 1].verdict ==
             SG_VERDICT_ALLOW);
      ASSERT_STR(result.subcommands[result.subcommand_count - 1].netargv,
                 "6:printf,1:x,");
    } else {
      ASSERT(status == SG_ERR_PARSE && result.verdict == SG_VERDICT_REJECT &&
             result.subcommand_count == 1);
    }
  }
  for (size_t i = 0; i < sizeof(shellsplit_test_assignment_snapshots) /
                             sizeof(shellsplit_test_assignment_snapshots[0]);
       i++) {
    sg_result_t result;
    sg_error_t error =
        eval_cmd(gate, shellsplit_test_assignment_snapshots[i].source, &result);
    ASSERT(error == (shellsplit_test_assignment_snapshots[i].resolved
                         ? SG_OK
                         : SG_ERR_PARSE));
    ASSERT(shellsplit_test_assignment_snapshots[i].resolved
               ? result.verdict != SG_VERDICT_REJECT && !result.truncated
               : result.verdict == SG_VERDICT_REJECT);
  }
  sg_gate_free(gate);
}

/* Exact rules ensure these are complete policy evaluations, not merely a
 * successful graph with an unrelated undetermined builtin. */
TEST(named_fd_builtin_ordered_assignment_policy_contract) {
  static const char *const rules[] = {
      "exec",
      "printf *",
      "printf -vfd -vother %s one",
      "printf -vother -vfd %s one",
      "printf -v fd",
      "printf -vfd -Z",
      "printf -v scratch \"%n\" other",
      "printf \"%%n\" fd",
      "printf \"%b%n\" \"\\\\c\" fd",
      "declare -p fd=changed",
      "declare bad-name",
      "declare bad-name fd=changed",
      "local fd=changed",
      "read UID fd",
      "read EUID fd",
  };
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1000000.0, NULL));
  static const char *const preserved[] = {
      ("exec {fd}>/tmp/builtin-route; printf -vfd -vother %s one >&$fd; "
       "printf x >&$fd"),
      "exec {fd}>/tmp/builtin-route; printf -v fd; printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; printf -vfd -Z; printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; declare -p fd=changed; printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; declare bad-name; printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; local fd=changed; printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; printf -v scratch '%n' other; "
      "printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; printf '%%n' fd; printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; printf '%b%n' '\\c' fd; printf x >&$fd",
  };
  sg_result_t result = {0};
  /* A readonly read target is a reported read error: no dependency model. */
  static const char *const readonly_targets[] = {
      "exec {fd}>/tmp/builtin-route; read UID fd <<<one; printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; read EUID fd <<<one; printf x >&$fd",
  };
  for (size_t i = 0; i < sizeof(readonly_targets) / sizeof(readonly_targets[0]);
       i++)
    ASSERT(eval_cmd(gate, readonly_targets[i], &result) == SG_ERR_UNMODELED &&
           result.verdict == SG_VERDICT_REJECT);
  for (size_t i = 0; i < sizeof(preserved) / sizeof(preserved[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, preserved[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3);
    for (size_t j = 0; j < result.subcommand_count; j++)
      ASSERT(result.subcommands[j].verdict == SG_VERDICT_ALLOW);
    ASSERT_STR(result.subcommands[2].netargv, "6:printf,1:x,");
  }
  static const char *const invalidated[] = {
      ("exec {fd}>/tmp/builtin-route; printf -vother -vfd %s one >&$fd; "
       "printf x >&$fd"),
      ("exec {fd}>/tmp/builtin-route; declare bad-name fd=changed; "
       "printf x >&$fd"),
      "exec {fd}>/tmp/builtin-route; printf -vother -v 'values[0]' %s one",
      "exec {fd}>/tmp/builtin-route; printf -v scratch 'abc%n' fd; "
      "printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; printf '%s%n' x other y fd; "
      "printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; declare -i scratch='fd=2'; "
      "printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; OPTIND='fd=2'; printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; OPTIND+='fd=2' printf x; printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; printf '\\%n' fd; printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; printf '\\%s%n' other fd; printf x >&$fd",
      "exec {RANDOM}>/tmp/builtin-route; printf x >&$RANDOM",
      "exec {UID}>/tmp/builtin-route; printf x >&$UID",
      "exec {POSIXLY_CORRECT}>/tmp/builtin-route",
  };
  for (size_t i = 0; i < sizeof(invalidated) / sizeof(invalidated[0]); i++) {
    ASSERT(eval_cmd(gate, invalidated[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           result.subcommand_count == 1 &&
           result.subcommands[0].verdict == SG_VERDICT_REJECT);
  }
  sg_gate_free(gate);
}

TEST(bash_pipeline_time_policy_contract) {
  static const char *rules[] = {"printf *", "cat",  "sort", "eval *",
                                "echo *",   "exec", "true"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "time -p -- printf value | cat", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2);
  ASSERT_STR(result.subcommands[0].netargv, "6:printf,5:value,");
  ASSERT_STR(result.subcommands[1].netargv, "3:cat,");

  static const char *const document_pipelines[] = {
      "time -p printf value <<<body | cat",
      "time -p printf value <<EOF | cat\nbody\nEOF\n",
      "time -p printf value <<<one 3<<<two |& cat",
  };
  for (size_t i = 0;
       i < sizeof(document_pipelines) / sizeof(document_pipelines[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, document_pipelines[i], &result));
    if (result.verdict != SG_VERDICT_ALLOW || result.subcommand_count != 2)
      printf("    document pipeline: %s (verdict %d, commands %u, reason %s)\n",
             document_pipelines[i], result.verdict, result.subcommand_count,
             result.deny_reason ? result.deny_reason : "none");
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2);

    ASSERT_STR(result.subcommands[0].netargv, "6:printf,5:value,");
    ASSERT_STR(result.subcommands[1].netargv, "3:cat,");
  }

  ASSERT_SG_OK(eval_cmd(gate, "time time -p true", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT_STR(result.subcommands[0].netargv, "4:true,");

  ASSERT_SG_OK(eval_cmd(gate, "time>/tmp/timing printf value", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT_STR(result.subcommands[0].netargv, "6:printf,5:value,");

  ASSERT(result.subcommands[0].write_count == 1);

  ASSERT_SG_OK(eval_cmd(gate, "time -p>/tmp/timing printf value", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT_STR(result.subcommands[0].netargv, "6:printf,5:value,");

  ASSERT_SG_OK(eval_cmd(gate, "time { printf value; } | cat", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2);

  ASSERT_SG_OK(eval_cmd(gate, "{ time printf value; } 2>/tmp/outer", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);

  /* The group redirect is one command context effect. The shell-owned timing
   * report follows the same route without becoming a second policy write. */
  ASSERT(result.subcommands[0].write_count == 1);

  ASSERT_SG_OK(
      eval_cmd(gate, "time printf value | { time -p cat; printf tail; } | sort",
               &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 4);

  ASSERT(sg_gate_evaluate(gate, "time eval echo hidden",
                          strlen("time eval echo hidden"), eval_buf,
                          sizeof(eval_buf), &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT);

  ASSERT_SG_OK(
      eval_cmd(gate, "time { printf value; } 2>/tmp/err | cat", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2);

  ASSERT(result.subcommands[0].write_count == 1);
  ASSERT(result.subcommands[1].write_count == 0);

  ASSERT_SG_OK(eval_cmd(gate, "echo \"$(exec 2>&1; time true)\"", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         result.has_dynamic_substitution_io &&
         ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "cat <(exec 2>&1; time true)", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.has_dynamic_substitution_io &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "exec 0</tmp/input; echo \"$(cat)\"", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3);
  ASSERT_STR(result.subcommands[2].netargv, "3:cat,");
  ASSERT(result.subcommands[2].read_count == 1);

  ASSERT_SG_OK(
      eval_cmd(gate, "exec 3>/tmp/old; echo \"$(printf child >&3 >/tmp/new)\"",
               &result));
  ASSERT(result.subcommand_count == 3);
  ASSERT_STR(result.subcommands[2].netargv, "6:printf,5:child,");
  ASSERT(result.subcommands[2].write_count == 1);

  static const char *const self_duplication[] = {
      "exec 0<&0; echo \"$(printf value)\"",
      "exec 1>&1; echo \"$(printf value)\"",
      "exec 2>&2; echo \"$(printf value)\"",
      "printf value 2>&2 >\"$(printf target)\"",
      "{ echo \"$(printf value)\"; } 2>&2",
  };
  for (size_t i = 0; i < sizeof(self_duplication) / sizeof(self_duplication[0]);
       i++) {
    ASSERT_SG_OK(eval_cmd(gate, self_duplication[i], &result));
    ASSERT(result.subcommand_count == (i < 3 ? 3u : 2u));
    ASSERT(result.has_dynamic_substitution_io);
    ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) !=
            0) == (i != 3));
  }

  ASSERT_SG_OK(eval_cmd(gate, "{ time true; } |& cat 3<&0", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2);
  ASSERT_STR(result.subcommands[1].netargv, "3:cat,");

  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));
  static const char *const empty_timing[] = {
      "time", "time -p", "time --", "time !", "! time", "! time !",
  };
  for (size_t i = 0; i < sizeof(empty_timing) / sizeof(empty_timing[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, empty_timing[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 0 &&
           result.deny_reason == NULL && result.anomaly_score == 0.0 &&
           !result.anomaly_detected);
  }

  static const char *const empty_timing_connectors[] = {
      "time & printf value",  "printf value && time",
      "printf value || time", "printf value && time; time",
      "printf value; time",   "printf value; time -p; time",
  };
  for (size_t i = 0;
       i < sizeof(empty_timing_connectors) / sizeof(empty_timing_connectors[0]);
       i++) {
    sg_error_t error = eval_cmd(gate, empty_timing_connectors[i], &result);
    if (error != SG_OK)
      printf("    case: %s (error %d)\n", empty_timing_connectors[i], error);
    ASSERT_SG_OK(error);
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1 &&
           result.deny_reason == NULL);
    ASSERT_STR(result.subcommands[0].netargv, "6:printf,5:value,");
  }

  static const char *const invalid_empty_timing[] = {
      "(time)",
      "echo \"$(time)\"",
      "echo \"$(time;)\"",
      "echo \"$(exec 2>&1; time;)\"",
      "cat <(time)",
      "cat <(time;)",
      "printf x > >(time;)",
      "echo \"$( (time;) )\"",
      "echo \"$(time (time;))\"",
      "echo \"$( (time;); : )\"",
      "cat <( (time;) )",
      "printf x > >( (time;) )",
      "time && printf value",
      "time || printf value",
  };
  for (size_t i = 0;
       i < sizeof(invalid_empty_timing) / sizeof(invalid_empty_timing[0]);
       i++) {
    ASSERT(sg_gate_evaluate(gate, invalid_empty_timing[i],
                            strlen(invalid_empty_timing[i]), eval_buf,
                            sizeof(eval_buf), &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           result.subcommand_count == 1 && result.deny_reason != NULL);
    ASSERT_STR(result.deny_reason, "parse error");
  }

  ASSERT_SG_OK(eval_cmd(gate, "!>/tmp/negated printf value", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT_STR(result.subcommands[0].netargv, "6:printf,5:value,");

  ASSERT_SG_OK(eval_cmd(gate, "time !; printf value >/tmp/value", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1 &&
         result.deny_reason == NULL);
  ASSERT_STR(result.subcommands[0].netargv, "6:printf,5:value,");

  ASSERT_SG_OK(eval_cmd(gate, "time >/tmp/timing", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommand_count == 0 && result.deny_reason != NULL);
  ASSERT_STR(result.deny_reason,
             "redirect-only shell operation is not argv-policy-evaluable");
  sg_gate_free(gate);
}

TEST(timed_pipeline_ordinary_time_policy_contract) {
  static const char *rules[] = {"true", "cat",    "echo *",
                                "time", "time *", "time * *"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));
  static const struct {
    const char *source;
    const char *netargv;
    uint32_t count;
  } cases[] = {
      {"time true | time", "4:time,", 2},
      {"time true | time -p", "4:time,2:-p,", 2},
      {"time true | time --", "4:time,2:--,", 2},
      {"time true | time !", "4:time,1:!,", 2},
      {"time -p true | time", "4:time,", 2},
      {"time true |& time", "4:time,", 2},
      {"time true | time | cat", "4:time,", 3},
      {"time true | \"time\"", "4:time,", 2},
      {"time true | time <<<body", "4:time,", 2},
      {"time true | time -p <<EOF\nbody\nEOF\n", "4:time,2:-p,", 2},
      {"time true | cat <<<body", "3:cat,", 2},
      {"time true |& 3<<<body cat", "3:cat,", 2},
      {"time <<<body true | cat", "3:cat,", 2},
  };
  sg_result_t result = {0};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW &&
           result.subcommand_count == cases[i].count &&
           result.deny_reason == NULL);
    ASSERT_STR(result.subcommands[1].netargv, cases[i].netargv);
  }
  ASSERT_SG_OK(eval_cmd(gate, "echo \"$(time true | time)\"", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3 &&
         ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io);
  ASSERT_STR(result.subcommands[2].netargv, "4:time,");

  ASSERT_SG_OK(eval_cmd(gate, "time <<<body cat", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1 &&
         result.subcommands[0].read_count == 1);
  ASSERT_STR(result.subcommands[0].netargv, "3:cat,");
  static const struct {
    const char *source;
    const char *netargv;
    uint32_t count;
    uint32_t reads;
  } document_prefixes[] = {
      {"<<<one time <<<two cat", "4:time,3:cat,", 1, 1},
      {"<<<one time -p 3<<<two cat <&3", "4:time,2:-p,3:cat,", 1, 2},
      {"true | <<<one time <<<two cat", "4:time,3:cat,", 2, 1},
      {"time true | <<<one time <<<two cat", "4:time,3:cat,", 2, 1},
      {"echo one <<<one\ntime <<<two cat", "3:cat,", 2, 1},
      {"echo one <<<one\n! <<<two cat", "3:cat,", 2, 1},
      {"echo one <<<one\r\ntime -p <<<two cat", "3:cat,", 2, 1},
  };
  for (size_t i = 0;
       i < sizeof(document_prefixes) / sizeof(document_prefixes[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, document_prefixes[i].source, &result));
    if (result.verdict != SG_VERDICT_ALLOW ||
        result.subcommand_count != document_prefixes[i].count)
      fprintf(stderr, "document policy: %s verdict=%d count=%u reason=%s\n",
              document_prefixes[i].source, result.verdict,
              result.subcommand_count,
              result.deny_reason ? result.deny_reason : "none");
    ASSERT(result.verdict == SG_VERDICT_ALLOW &&
           result.subcommand_count == document_prefixes[i].count &&
           result.deny_reason == NULL);
    uint32_t command = result.subcommand_count - 1;
    ASSERT_STR(result.subcommands[command].netargv,
               document_prefixes[i].netargv);
    /* The fd-3 fixture leaves the second document reachable through both fd
     * 3 and its fd-0 alias; the remaining fixtures have one live read route. */
    ASSERT(result.subcommands[command].read_count ==
           document_prefixes[i].reads);
  }
  ASSERT_SG_OK(eval_cmd(gate, "echo \"$(time <<<body cat)\"", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2 &&
         result.subcommands[1].read_count == 1);
  ASSERT_SG_OK(eval_cmd(gate, "time true | { time -p; }", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1 &&
         result.deny_reason == NULL);
  sg_gate_free(gate);

  /* An unmatched ordinary executable is a normal policy decision, not an
   * argv-less timing placeholder or an invented redirect-only diagnostic. */
  static const char *restricted_rules[] = {"true"};
  gate = gate_with_rules(restricted_rules, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(eval_cmd(gate, "time true | time", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommand_count == 2 && result.deny_reason == NULL);
  ASSERT_STR(result.subcommands[1].netargv, "4:time,");
  ASSERT_SG_OK(eval_cmd(gate, "<<<one time <<<two cat", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommand_count == 1 && result.deny_reason == NULL);
  ASSERT_STR(result.subcommands[0].netargv, "4:time,3:cat,");
  sg_gate_free(gate);
}

TEST(grouped_empty_time_io_policy_contract) {
  static const char *rules[] = {"printf *", "cat", "exec"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  sg_result_t result = {0};
  static const char *const neutral[] = {
      "{ time; }",
      "{ { time; }; }",
      "{ time; printf value; } >/tmp/timed-group",
      "(time; printf value) >/tmp/timed-subshell",
  };
  static const uint32_t neutral_counts[] = {0, 0, 1, 1};
  for (size_t i = 0; i < sizeof(neutral) / sizeof(neutral[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, neutral[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW &&
           result.subcommand_count == neutral_counts[i] &&
           result.deny_reason == NULL);
  }

  static const struct {
    const char *input;
    uint32_t command_count;
  } unpolicyable[] = {
      {"{ time; } >/tmp/timed-group", 0},
      {"{ time; } </dev/null", 0},
      {"{ time; } >>/tmp/timed-group", 0},
      {"{ time; } <<EOF\nbody\nEOF\n", 0},
      {"{ time; } {log}>/tmp/timed-group", 0},
      {"exec {log}>/tmp/timed-log; { time; } {log}>&-", 1},
      {"{ time; } &>/tmp/timed-group", 0},
      {"{ { time; }; } >/tmp/timed-group", 0},
      {"(time;) >/tmp/timed-subshell", 0},
      {"{ time; } > >(cat)", 1},
  };
  for (size_t i = 0; i < sizeof(unpolicyable) / sizeof(unpolicyable[0]); i++) {
    sg_error_t error = eval_cmd(gate, unpolicyable[i].input, &result);
    if (error != SG_OK)
      printf("    case: %s (error %d)\n", unpolicyable[i].input, error);
    ASSERT_SG_OK(error);
    if (result.verdict != SG_VERDICT_UNDETERMINED ||
        result.subcommand_count != unpolicyable[i].command_count ||
        result.deny_reason == NULL)
      printf("    case: %s (verdict %d, commands %u)\n", unpolicyable[i].input,
             result.verdict, result.subcommand_count);
    ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
           result.subcommand_count == unpolicyable[i].command_count &&
           result.deny_reason != NULL);
    ASSERT_STR(result.deny_reason,
               "redirect-only shell operation is not argv-policy-evaluable");
  }
  sg_gate_free(gate);
}

TEST(empty_timing_substitution_policy_contract) {
  static const char *rules[] = {"echo *",   "true", "exec",
                                "printf *", "cat",  "cat *"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  static const struct {
    const char *source;
    uint32_t count;
    bool inspection;
    bool dynamic;
  } cases[] = {
      {"echo \"$(time; true)\"", 2, true, true},
      {"echo \"$(time !; true)\"", 2, true, true},
      {"echo \"`time; true`\"", 2, true, true},
      {"echo \"$(exec 2>&1; time; true)\"", 3, true, true},
      {"cat <(time; printf x)", 2, false, true},
      {"printf x > >(time; cat)", 2, false, true},
      {"echo \"$(time &)\"", 1, false, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    if (result.verdict !=
        (cases[i].inspection ? SG_VERDICT_ALLOW : SG_VERDICT_ALLOW))
      printf("\n    empty timing result: %s verdict=%d reason=%s\n",
             cases[i].source, result.verdict,
             result.deny_reason ? result.deny_reason : "none");
    ASSERT(result.verdict ==
           (cases[i].inspection ? SG_VERDICT_ALLOW : SG_VERDICT_ALLOW));
    ASSERT(result.subcommand_count == cases[i].count && !result.truncated);
    ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) !=
            0) == cases[i].inspection);
    ASSERT(result.has_dynamic_substitution_io == cases[i].dynamic);
    ASSERT(result.deny_reason == NULL);
  }
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "echo \"$(time >output; true)\"", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.deny_reason != NULL);
  ASSERT_STR(result.deny_reason,
             "redirect-only shell operation is not argv-policy-evaluable");
  ASSERT_SG_OK(
      eval_cmd(gate, "printf x | { exec 2>err; time true; }", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3);

  ASSERT(result.subcommands[2].write_count == 1);
  ASSERT_SG_OK(eval_cmd(
      gate, "printf x | { exec {fd}>out; printf value >&$fd; }", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3);
  ASSERT(result.subcommands[2].write_count == 1);
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

  memmove(command + 2, command, length + 1);
  memcpy(command, "{ ", 2);
  length += 2;
  memcpy(command + length, "; }", 3);
  length += 3;
  command[length] = '\0';
  memset(&result, 0xA5, sizeof(result));
  ASSERT(eval_cmd(gate, command, &result) == SG_ERR_TRUNC);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED && result.truncated &&
         result.subcommand_truncated && !result.subcommand_count);
  sg_gate_free(gate);
}

TEST(nested_quoted_expansion_boundaries) {
  static const struct {
    const char *command;
    uint32_t count;
  } cases[] = {
      {"echo \"${value:-\"x;y\"}\"", 1},
      {"echo \"$(printf \"x;y\")\"", 2},
      {"echo \"`printf \"x;y\"`\"", 2},
      {"echo \"${value:-\"<(printf hi)\"}\"", 1},
      {"echo ${value:-<(printf hi)}", 2},
      {"echo ${value:-$(printf hi)}", 2},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *gate = sg_gate_new();
    ASSERT(gate != NULL);
    ASSERT_SG_OK(add_exact_outer_rule(gate, cases[i].command));
    sg_result_t result;
    sg_error_t status = eval_cmd(gate, cases[i].command, &result);
    if (status != SG_OK || result.subcommand_count != cases[i].count)
      fprintf(stderr, "nested quote case %zu: status=%d count=%u\n", i, status,
              status == SG_OK ? result.subcommand_count : 0);
    ASSERT(status == SG_OK);
    ASSERT_EQ_UINT(result.subcommand_count, cases[i].count);
    sg_gate_free(gate);
  }
}

TEST(nested_feature_rejection_contract) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"printf *", "cat"}, 2);
  ASSERT(gate != NULL);
  static const struct {
    const char *source;
    uint32_t feature;
    bool present;
  } cases[] = {
      {"printf \"$(cat <<EOF\nbody\nEOF\n)\"", SHELL_FEAT_HEREDOC, true},
      {"printf \"$(cat <<<word)\"", SHELL_FEAT_HERESTRING, true},
      {"printf \"$(printf x | cat)\"", SHELL_FEAT_PIPELINE, true},
      {"printf ${v:-$(printf x | cat)}", SHELL_FEAT_PIPELINE, true},
      {"printf \"`cat <<EOF\nbody\nEOF\n`\"", SHELL_FEAT_HEREDOC, true},
      {"printf \"$(printf ok # <<<word\n)\"", SHELL_FEAT_HERESTRING, false},
      {"printf \"$(printf ok # $VALUE * &>file\n)\"",
       SHELL_FEAT_VARS | SHELL_FEAT_GLOBS | SHELL_FEAT_COMBINED_REDIRECT,
       false},
      {"printf \"$(printf 'a|b')\"", SHELL_FEAT_PIPELINE, false},
      {"printf \"$(printf x || cat)\"", SHELL_FEAT_PIPELINE, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT_SG_OK(sg_gate_set_reject_mask(gate, cases[i].feature));
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT((result.verdict == SG_VERDICT_REJECT) == cases[i].present);
    shell_parse_result_t parsed;
    ASSERT(shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                            &parsed) == SHELL_OK);
    uint32_t features = 0;
    for (uint32_t j = 0; j < parsed.count; j++)
      features |= parsed.cmds[j].features;
    ASSERT(((features & cases[i].feature) != 0) == cases[i].present);
  }
  for (unsigned conditional = 0; conditional < 2; ++conditional) {
    for (size_t i = 0; i < sizeof(shellsplit_test_extglob_features) /
                               sizeof(shellsplit_test_extglob_features[0]);
         ++i) {
      char source[256];
      snprintf(source, sizeof(source),
               conditional ? "[[ -n %s ]]" : "printf %s",
               shellsplit_test_extglob_features[i].word);
      for (uint32_t bit = 1; bit <= SHELL_FEAT_COMBINED_REDIRECT; bit <<= 1) {
        if (bit == SHELL_FEAT_CONDITIONALS)
          continue;
        ASSERT_SG_OK(sg_gate_set_reject_mask(gate, bit));
        sg_result_t result;
        ASSERT_SG_OK(eval_cmd(gate, source, &result));
        ASSERT((result.verdict == SG_VERDICT_REJECT) ==
               ((shellsplit_test_extglob_features[i].features & bit) != 0));
      }
    }
  }
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, SG_REJECT_MASK_DEFAULT));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, cases[0].source, &result));
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  ASSERT_SG_OK(eval_cmd(gate, cases[1].source, &result));
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  sg_gate_free(gate);
}

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    conditional_value(const shell_expand_word_request_t *request,
                      const char **value, size_t *length, void *context) {
  if (request->purpose != SHELL_EXPAND_WORD_CONDITIONAL)
    return SHELL_EXPAND_UNRESOLVED;
  *value = context;
  *length = strlen(context);
  return SHELL_EXPAND_RESOLVED;
}

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    resolve_numeric_condition(const shell_expand_word_request_t *request,
                              const char **value, size_t *length,
                              void *context) {
  if (request->purpose != SHELL_EXPAND_WORD_CONDITIONAL_ARITHMETIC)
    return SHELL_EXPAND_UNRESOLVED;
  *value = context;
  *length = strlen(*value);
  return SHELL_EXPAND_RESOLVED;
}

TEST(builtin_argument_read_setup_contract) {
  sg_gate_t *gate =
      gate_with_rules((const char *[]){"test * -eq 0", "\"[\" * -eq 0 ]"}, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  static const struct {
    const char *source;
    bool unmodeled;
  } cases[] = {
      /* Closing stdout then duplicating it certainly fails: no dependency
       * model, and the gate rejects what it cannot model. */
      {"test \"$count\" -eq 0 1>&- 2>&1", true},
      {"[ \"$count\" -eq 0 ] 1>&- 2>&1", true},
      /* The same builtin arguments over fallible-but-modelable redirects
       * keep the original contract: parsed, allowed, argv-unresolved. */
      {"test \"$count\" -eq 0 1>/dev/null 2>&1", false},
      {"[ \"$count\" -eq 0 ] 1>/dev/null 2>&1", false},
  };
  for (unsigned i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
    sg_result_t result;
    if (cases[i].unmodeled) {
      ASSERT(eval_cmd(gate, cases[i].source, &result) == SG_ERR_UNMODELED);
      ASSERT(result.verdict == SG_VERDICT_REJECT);
      continue;
    }
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
    ASSERT(result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARGV);
    ASSERT(!(result.unresolved_expansion_flags &
             SG_EXPANSION_UNRESOLVED_ARITHMETIC));
    ASSERT(result.subcommands[0].env_count == 0);
  }
  sg_gate_free(gate);
}

TEST(numeric_condition_policy_contract) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"cat *", "printf *"}, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "[[ 2 -gt 1 ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.unresolved_expansion_flags);
  ASSERT_SG_OK(eval_cmd(gate, "[[ ~+0 -eq -1 ]] || cat fallback", &result));
  ASSERT(
      result.verdict == SG_VERDICT_UNDETERMINED &&
      (result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARITHMETIC));
  ASSERT_SG_OK(eval_cmd(gate, "[[ '~+0' -eq -1 ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.unresolved_expansion_flags);
  ASSERT_SG_OK(eval_cmd(gate, "[[ \"${1:-$fallback}\" -eq 0 ]]", &result));
  ASSERT(
      result.verdict == SG_VERDICT_UNDETERMINED &&
      (result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARITHMETIC));
  ASSERT_SG_OK(eval_cmd(gate, "[[ count -gt 0 ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(result.unresolved_expansion_flags &
         SG_EXPANSION_UNRESOLVED_ARITHMETIC);
  ASSERT_SG_OK(eval_cmd(gate, "[[ \"$count\" -gt 0 ]]; cat after", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommand_count == 1);
  ASSERT(result.subcommands[0].unresolved_expansion_flags &
         SG_EXPANSION_UNRESOLVED_ARITHMETIC);
  ASSERT_SG_OK(eval_cmd(gate, "[[ -z x && count -gt 0 ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !(result.unresolved_expansion_flags &
           SG_EXPANSION_UNRESOLVED_ARITHMETIC));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_STOP_FIRST_ALLOW));
  ASSERT_SG_OK(
      eval_cmd(gate, "cat before; [[ count -gt 0 ]]; cat after", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED && result.short_circuited);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));
  size_t vocabulary = test_anomaly_vocabulary(gate);
  ASSERT_SG_OK(
      eval_cmd(gate, "[[ count -gt 0 ]]; printf blocked-new", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         test_anomaly_vocabulary(gate) == vocabulary);
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, resolve_numeric_condition, "1:3,"));
  ASSERT_SG_OK(eval_cmd(gate, "[[ count -gt 0 ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !(result.unresolved_expansion_flags &
           SG_EXPANSION_UNRESOLVED_ARITHMETIC));
  ASSERT_SG_OK(eval_cmd(gate, "[[ \"${1:-$fallback}\" -eq 0 ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.unresolved_expansion_flags);
  /* The application supplies a state with HOME=3 and proves its pure value. */
  ASSERT_SG_OK(eval_cmd(gate, "[[ ~ -gt 0 ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.unresolved_expansion_flags);
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, resolve_numeric_condition,
                                               "7:count=1,"));
  ASSERT(eval_cmd(gate, "[[ count -gt 0 ]]", &result) == SG_ERR_EXPAND);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, resolve_numeric_condition,
                                               "6:$((1)),"));
  ASSERT(eval_cmd(gate, "[[ count -gt 0 ]]", &result) == SG_ERR_EXPAND);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(eval_cmd(gate, "[[ '$((1))' -eq 1 ]]", &result) == SG_ERR_PARSE);
  static const char *const mutation_values[] = {"7:++count,", "8:count++1,"};
  for (unsigned i = 0; i < sizeof(mutation_values) / sizeof(*mutation_values);
       ++i) {
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(
        gate, resolve_numeric_condition, (void *)mutation_values[i]));
    ASSERT(eval_cmd(gate, "[[ count -eq 0 ]]", &result) == SG_ERR_EXPAND);
    ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  }
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, NULL, NULL));
  static const char *const mutation_sources[] = {
      "[[ ++count -eq 0 ]]",
      "[[ --count -eq 0 ]]",
      "[[ 'count++1' -eq 0 ]]",
      "[[ '0&&++count' -eq 0 ]]",
      "[[ -z x && ++count -eq 0 ]]",
      "[[ \"++count\"$((0)) -eq 0 ]]",
      "cat before; [[ ++count -eq 0 ]]",
  };
  for (unsigned i = 0; i < sizeof(mutation_sources) / sizeof(*mutation_sources);
       ++i) {
    ASSERT(eval_cmd(gate, mutation_sources[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT);
  }
  ASSERT_SG_OK(eval_cmd(gate, "[[ 'count + +1' -eq 0 ]]", &result));
  ASSERT(
      result.verdict == SG_VERDICT_UNDETERMINED &&
      (result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARITHMETIC));
  ASSERT(test_policy_replace_cpl(gate, true, "cat after", false) == ST_OK);
  ASSERT_SG_OK(eval_cmd(gate, "[[ count -gt 0 ]]; cat after", &result));
  ASSERT(result.verdict == SG_VERDICT_DENY && result.subcommand_count == 1);
  sg_gate_free(gate);
}

TEST(conditional_string_contract) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"printf *"}, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "[[ -n x ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(eval_cmd(gate, "[[ source -nt target && -r source ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && !result.subcommand_count &&
         !result.unresolved_expansion_flags);
  ASSERT_SG_OK(eval_cmd(gate, "[[ -e first || -f \"$path\" ]]", &result));
  ASSERT(
      result.verdict == SG_VERDICT_ALLOW &&
      (result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_PATH) &&
      (result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_CONDITION));
  ASSERT_SG_OK(eval_cmd(gate, "[[ x || -f \"$path\" ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.unresolved_expansion_flags);
  ASSERT_SG_OK(eval_cmd(gate, "[[ x || -n $(printf skipped) ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         !result.has_dynamic_substitution_io);
  static const char *const invalid_boundaries[] = {
      "[[ x == \"x\" ]", "[[ -n x ]",  "[[ x !",       "[[ x =\\",
      "[[ x\n]]",        "[[ ! x\n]]", "[[ ! ! x\n]]", "[[ '-n'\n]]",
      "[[ x # note\n]]", "[[ x\n",
  };
  for (size_t i = 0;
       i < sizeof(invalid_boundaries) / sizeof(invalid_boundaries[0]); ++i)
    ASSERT(eval_cmd(gate, invalid_boundaries[i], &result) == SG_ERR_PARSE);
  ASSERT_SG_OK(eval_cmd(gate, "[[ -z '' ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 0);
  ASSERT_SG_OK(eval_cmd(gate, "[[ -f config.json ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && !result.subcommand_count &&
         !result.unresolved_expansion_flags);
  ASSERT_SG_OK(eval_cmd(gate, "[[ -N \"$path\" ]]", &result));
  ASSERT(
      result.verdict == SG_VERDICT_ALLOW &&
      (result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_PATH) &&
      (result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_CONDITION));
  ASSERT_SG_OK(eval_cmd(gate, "[[ x == \"x\" ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && !result.subcommand_count);
  ASSERT_SG_OK(eval_cmd(gate, "[[ file.txt == *.txt ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && !result.subcommand_count &&
         !result.unresolved_expansion_flags);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, SHELL_FEAT_GLOBS));
  ASSERT_SG_OK(eval_cmd(gate, "[[ file.txt == *.txt ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  ASSERT_STR(result.deny_reason, "glob pattern not allowed");
  ASSERT_SG_OK(eval_cmd(gate, "printf '%s' *.txt", &result));
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  ASSERT_STR(result.deny_reason, "glob pattern not allowed");
  ASSERT_SG_OK(eval_cmd(gate, "[[ '*' == '*' ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_SG_OK(eval_cmd(gate, "[[ x == \"$value\".txt ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         result.unresolved_expansion_flags ==
             SG_EXPANSION_UNRESOLVED_CONDITION);
  ASSERT_SG_OK(eval_cmd(gate, "[[ x == \"$value\"'?[()]' ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  static const char *const comparisons[] = {
      "[[ $left == \"x\" ]]",
      "[[ x == \"$right\" ]]",
      "[[ $left != \"$right\" ]]",
      "[[ name=~ == 'name=~' ]]",
      "[[ name=prefix:~ == 'name=prefix:~' ]]",
      "[[ arr[0]=~ == 'arr[0]=~' ]]",
      "[[ arr['0']+=~ == 'arr[0]+=~' ]]",
      "[[ $left == *.txt ]]",
      "[[ $left == \"$right\".txt ]]",
      "[[ $left != release-\"$right\" ]]",
  };
  for (unsigned i = 0; i < sizeof(comparisons) / sizeof(comparisons[0]); ++i) {
    ASSERT_SG_OK(eval_cmd(gate, comparisons[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && !result.subcommand_count);
    ASSERT(result.unresolved_expansion_flags ==
           SG_EXPANSION_UNRESOLVED_CONDITION);
  }
  static const char *const literal_tildes[] = {
      "[[ name='~' == 'name=~' ]]",
      "[[ name=~'' == 'name=~' ]]",
      "[[ name\\=~ == 'name=~' ]]",
      "[[ ~'' == '~' ]]",
  };
  for (size_t i = 0; i < sizeof(literal_tildes) / sizeof(literal_tildes[0]);
       ++i) {
    ASSERT_SG_OK(eval_cmd(gate, literal_tildes[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && !result.subcommand_count &&
           !result.unresolved_expansion_flags);
  }
  ASSERT_SG_OK(eval_cmd(gate, "[[ x == \"$(printf value)\" ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1 &&
         ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io &&
         result.unresolved_expansion_flags ==
             SG_EXPANSION_UNRESOLVED_CONDITION);
  ASSERT_SG_OK(
      eval_cmd(gate, "[[ x == pre\"$(printf value)\"post ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1 &&
         ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io &&
         result.unresolved_expansion_flags ==
             SG_EXPANSION_UNRESOLVED_CONDITION);
  ASSERT_SG_OK(eval_cmd(gate, "[[ x == \"$(cat)\" ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommand_count == 1);
  ASSERT_SG_OK(eval_cmd(gate, "[[ x == \"x\" ]] >report", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED && !result.subcommand_count);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, SHELL_FEAT_SUBSHELL));
  ASSERT_SG_OK(eval_cmd(gate, "[[ x == \"$(printf x)\" ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, SHELL_FEAT_ARITH));
  ASSERT_SG_OK(eval_cmd(gate, "[[ x == \"$((1))\" ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  ASSERT_SG_OK(eval_cmd(gate, "[[ -n x # note\n]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 0);
  static const char *const commented[] = {
      "[[ # $(|)\n-n x ]]",
      "[[ ! # $(\n-n x ]]",
      "[[ -n x # ` ' \" ]] <(cat) $comment $((7)) ${bad\n]]",
  };
  for (size_t i = 0; i < sizeof(commented) / sizeof(commented[0]); ++i) {
    ASSERT_SG_OK(eval_cmd(gate, commented[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 0);
    ASSERT(
        !result.has_dynamic_substitution_io &&
        !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
        !result.unresolved_expansion_flags);
  }
  ASSERT_SG_OK(
      eval_cmd(gate, "[[ # ' comment\n-n $(printf value) # $(|)\n]]", &result));
  ASSERT(
      result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1 &&
      ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
      result.has_dynamic_substitution_io &&
      (result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_CONDITION));
  ASSERT(eval_cmd(gate, "[[ # ignored\n-n $(|) ]]", &result) == SG_ERR_PARSE);
  ASSERT_SG_OK(eval_cmd(gate, "[[ -n $value ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 0);
  ASSERT(result.unresolved_expansion_flags ==
         SG_EXPANSION_UNRESOLVED_CONDITION);
  ASSERT_SG_OK(eval_cmd(gate, "[[ -n $(printf value) ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT(result.has_dynamic_substitution_io &&
         ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_CONDITION);
  ASSERT_SG_OK(eval_cmd(gate, "[[ -n <(printf value) ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT(result.has_dynamic_substitution_io &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT_SG_OK(eval_cmd(gate, "[[ -n x ]] >report", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED && !result.subcommand_count);
  ASSERT_SG_OK(eval_cmd(gate, "[[ -n $(printf value) ]] >report", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommand_count == 1);
  ASSERT_SG_OK(eval_cmd(gate, "{ [[ -n x ]]; } >report", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, conditional_value, "0:,"));
  ASSERT_SG_OK(eval_cmd(gate, "[[ -n $value ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.unresolved_expansion_flags);
  ASSERT(result.subcommand_count == 0);
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, conditional_value, "1:x,"));
  ASSERT_SG_OK(eval_cmd(gate, "[[ $left == \"$right\" ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.unresolved_expansion_flags);
  for (size_t i = 0; i < sizeof(comparisons) / sizeof(comparisons[0]); ++i) {
    ASSERT_SG_OK(eval_cmd(gate, comparisons[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW &&
           !result.unresolved_expansion_flags);
  }
  ASSERT_SG_OK(eval_cmd(gate, "[[ x == \"$(printf x)\" ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io &&
         !result.unresolved_expansion_flags);

  ASSERT_SG_OK(eval_cmd(gate, "[[ -n $value ]] && cat", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommand_count == 1);
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, conditional_value, ""));
  ASSERT(eval_cmd(gate, "[[ -n $value ]]", &result) == SG_ERR_EXPAND);
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, NULL, NULL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));
  ASSERT_SG_OK(eval_cmd(gate, "[[ -z '' ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(eval_cmd(gate, "[[ x == ? ]]", &result) == SG_ERR_PARSE);
  sg_gate_free(gate);
}

TEST(static_arithmetic_literal_contract) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"echo *"}, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(
      gate, "echo $((2#1010 + 8#17 + 16#ff + 36#Z + 37#A + 64#_@ + (2**3)))",
      &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT_SG_OK(eval_cmd(gate, "echo $((0x))", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  static const char *const invalid[] = {
      "echo $((08))",
      "echo $((2#))",
      "echo $((2#2))",
      "echo $((65#1))",
      "echo $((1 2))",
      "echo $((1 + ))",
      "((02#1))",
      "((010#1))",
      "((016#f))",
      "((064#1))",
      "echo $((02#1))",
      "echo \"${value:02#1}\"",
      "echo \"${value:0:02#1}\"",
      "echo <<EOF\n$((02#1))\nEOF\n",
      "((02#1)) || echo fallback",
      "((02#1)) && echo success",
      "((1\r)) || echo fallback",
      "((1\v)) && echo success",
      "echo before; ((1\f)) || echo fallback",
      "echo $((1\r))",
      "echo \"${value:\v}\"",
      "echo \"${value:0:\f}\"",
      "(( $(printf 1; : 日本) ))",
      "(( `printf '%s' 日本` ))",
  };
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
    ASSERT(eval_cmd(gate, invalid[i], &result) == SG_ERR_PARSE &&
           result.verdict == SG_VERDICT_REJECT);
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

  sg_result_t result;
  ASSERT_SG_OK(
      eval_cmd(gate, "echo $( { sleep 2; printf q; } | ./clock )", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 4);
  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  /* A syntactic substitution is not automatically a live dynamic I/O flow:
   * descriptor closes and diversions can disconnect it before its bytes reach
   * a shell word or process-substitution consumer. */
  ASSERT_SG_OK(eval_cmd(gate, "echo $(printf x >&-)", &result));
  ASSERT(!((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         !result.has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(printf x 1>&2)", &result));
  ASSERT(!((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         !result.has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(printf x 2>&1 1>&2)", &result));
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "printf x > >(sh 0<&-)", &result));
  ASSERT(!((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         !result.has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "printf x > >(sh 0<&0)", &result));
  ASSERT(!((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(printf first; printf second)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 3);
  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "echo $(<\"/etc/shadow\")", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 1);
  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT(result.subcommands[0].read_count == 0);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(</etc/shadow)", &result));
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "echo $(</etc/sha\\dow)", &result));
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "echo $(<\"$dynamic_path\")", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "echo $(</tmp/direct)$(id)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 2);
  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "echo $(< <(printf q))", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         ((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         !((result.subcommands[1].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  /* The nested printf selects a pathname, while the selected file's contents
   * are what later enter echo's shell word. Do not make the filename producer
   * itself a second-inspection consumer. */
  ASSERT_SG_OK(eval_cmd(gate, "echo $(<$(printf /tmp/dynamic-name))", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         ((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         !((result.subcommands[1].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "{ echo $(</tmp/group-input); }", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 1);

  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(
      eval_cmd(gate, "echo $( { printf $(</tmp/nested-input); } )", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 2);
  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(((result.subcommands[1].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "printf value 2> >(cat)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(!((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.has_dynamic_substitution_io);
  ASSERT(result.subcommand_count == 2);
  ASSERT(!((result.subcommands[0].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(!((result.subcommands[1].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommands[1].has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "cat <(cat <<EOF\n)\nEOF\n)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         result.subcommands[0].has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "echo $(cat <<EOF\n)\nEOF\n)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         ((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  /* Arithmetic shifts are not heredocs, while their enclosing substitution
   * still carries the correct shell-word or dynamic-descriptor semantics. */
  ASSERT_SG_OK(eval_cmd(gate, "echo $(printf '%s' $((1 << 2)))", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.subcommand_count == 2 &&
         ((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "cat <(printf '%s' $((1 << 2)))", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         result.subcommands[0].has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "{ echo $((1 << 2)); }", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.subcommand_count == 1);

  /* A substitution in a redirect selects an I/O pathname. It remains visible
   * on the redirect owner, but it is not shell-word content to inspect again.
   */
  ASSERT_SG_OK(eval_cmd(gate, "cat >$(id)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2);
  ASSERT(result.subcommands[0].has_dynamic_substitution_io &&
         !((result.subcommands[0].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         !result.subcommands[1].has_dynamic_substitution_io &&
         !((result.subcommands[1].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(
      eval_cmd(gate, "{ echo ok; } >prefix$(printf /tmp/out)suffix", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2);
  ASSERT(!result.subcommands[0].has_dynamic_substitution_io &&
         !((result.subcommands[0].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.subcommands[1].has_dynamic_substitution_io &&
         !((result.subcommands[1].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  /* Literal braces do not quote their contents. The substitution computes an
   * I/O pathname, so it remains visible as dynamic I/O but never becomes data
   * supplied to a shell word for another inspection. A path-forcing literal
   * prefix keeps the legacy combined-output spelling unambiguous. */
  ASSERT_SG_OK(
      eval_cmd(gate, "printf value >{$(printf /tmp/brace-output)}", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2);
  ASSERT(result.subcommands[0].has_dynamic_substitution_io &&
         !((result.subcommands[0].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         !result.subcommands[1].has_dynamic_substitution_io &&
         !((result.subcommands[1].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(
      gate, "printf value >&path-$(printf /tmp/brace-combined)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2);
  ASSERT(result.subcommands[0].has_dynamic_substitution_io &&
         !((result.subcommands[0].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         !result.subcommands[1].has_dynamic_substitution_io &&
         !((result.subcommands[1].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "echo $( { cat /etc/shadow; } )", &result));
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "cat <<EOF\n$(id)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 2);
  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "cat <<-EOF\r\n\t$(id)\r\n\tEOF\r\n", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 2);
  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "cat <<'EOF'\n$(id)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(!((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 1);
  ASSERT(!((result.subcommands[0].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "cat <<\\EOF\n$(id)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(!((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 1);
  ASSERT(!((result.subcommands[0].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "cat <<EOF </dev/null\n$(id)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 2);
  ASSERT(!((result.subcommands[0].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(
      eval_cmd(gate, "cat <<A <<-B\n$(id)\nA\n\t$(pwd)\n\tB\n", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 3);
  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  /* The later heredoc's substitution inherits the first document on stdin. */

  ASSERT_SG_OK(
      eval_cmd(gate, "cat <<EOF\n$(printf one; printf two)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 3);
  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(gate, "cat <<EOF\n$(</etc/shadow)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 1);
  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  /* The heredoc is an internal transport node. The sensitive substitution
   * belongs to the GROUP-owned descriptor and must reach every simple command
   * which inherits that group context. */
  ASSERT_SG_OK(
      eval_cmd(gate, "{ cat; cat; } <<EOF\n$(</etc/shadow)\nEOF", &result));
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0) &&
         result.subcommand_count == 2);

  ASSERT_SG_OK(eval_cmd(gate, "{ cat; cat; } <<EOF\n$(id)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 3);
  ASSERT(!((result.subcommands[0].requirements &
            SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(((result.subcommands[1].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(((result.subcommands[2].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  ASSERT_SG_OK(eval_cmd(
      gate, "cat <<EOF\n$( { sleep 2; printf q; } | ./clock )\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count == 4);
  ASSERT(((result.subcommands[0].requirements &
           SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));

  sg_gate_free(gate);
}

TEST(expansion_phases_survive_failed_setup) {
  static const char *const rules[] = {"true",     "true *",   "false",
                                      "printf *", "export *", "echo *"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/workspace"));
  bool valid = true;
  for (unsigned anomaly = 0; anomaly < 2; anomaly++) {
    if (anomaly) {
      ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));
      ASSERT_SG_OK(sg_gate_set_anomaly_cache_size(gate, 32));
    }
    for (size_t i = 0; i < sizeof(shellsplit_test_expansion_setup) /
                               sizeof(shellsplit_test_expansion_setup[0]);
         i++) {
      const shellsplit_test_expansion_setup_case_t *fixture =
          &shellsplit_test_expansion_setup[i];
      /* Repeat the anomaly-enabled evaluation to cover cached results too. */
      for (unsigned repeat = 0; repeat < 1u + anomaly; repeat++) {
        sg_result_t result;
        sg_error_t error = eval_cmd(gate, fixture->source, &result);
        bool inspection = fixture->active && fixture->shell_word;
        bool expected =
            error == SG_OK && !result.truncated &&
            ((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) !=
             0) == inspection &&
            (!inspection || result.has_dynamic_substitution_io) &&
            (fixture->active || !result.has_dynamic_substitution_io);
        if (!expected) {
          printf("\n    expansion setup gate: %s (error %d, inspection %d, "
                 "dynamic %d, anomaly %u)\n",
                 fixture->source, error,
                 ((result.requirements &
                   SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0),
                 result.has_dynamic_substitution_io, anomaly);
          valid = false;
        }
      }
    }
  }
  sg_gate_free(gate);
  ASSERT(valid);
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
    ASSERT(
        result.verdict == SG_VERDICT_REJECT &&
        !((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  }

  sg_result_t result = {0};
  ASSERT_SG_OK(
      eval_cmd(gate, "echo $(printf value # )\nprintf done)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
  ASSERT(result.subcommand_count >= 2);

  for (int process_substitution = 0; process_substitution <= 1;
       process_substitution++) {
    char command[512];
    ASSERT(make_nested_heredoc_substitution(command, sizeof(command),
                                            process_substitution != 0));
    memset(&result, 0, sizeof(result));
    ASSERT(eval_cmd(gate, command, &result) == SG_ERR_TRUNC);
    ASSERT(result.truncated && result.verdict == SG_VERDICT_UNDETERMINED);
  }
  sg_gate_free(gate);
}

TEST(anomaly_large_quoted_delimiter_workspace) {
  char command[4096];
  char nested[4200];
  size_t at = 0, delimiter_length = 1024;
  memcpy(command + at, "cat <<'", 7);
  at += 7;
  memset(command + at, 'E', delimiter_length);
  at += delimiter_length;
  memcpy(command + at, "'\npayload\n", 10);
  at += 10;
  memset(command + at, 'E', delimiter_length);
  at += delimiter_length;
  command[at++] = '\n';
  command[at] = '\0';
  snprintf(nested, sizeof(nested), "echo \"$(%s)\"", command);
  sg_gate_t *gate = gate_with_rules((const char *[]){"cat", "echo *"}, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));
  for (unsigned variant = 0; variant < 2; variant++) {
    for (unsigned pass = 0; pass < 3; pass++) {
      sg_result_t result;
      ASSERT_SG_OK(eval_cmd(gate, variant ? nested : command, &result));
      ASSERT(result.verdict ==
                 (variant ? SG_VERDICT_ALLOW : SG_VERDICT_ALLOW) &&
             !result.truncated);
      ASSERT(result.subcommand_count == (variant ? 2 : 1));
      ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_APPLIED);
    }
  }
  ASSERT(test_anomaly_vocabulary(gate) > 0);
  /* Protected ANSI-C spelling survives the later double-quote-removal state.
   * This delimiter expands beyond its header's source length. */
  static const char opening[] = "cat <<`\"`$'";
  at = sizeof(opening) - 1;
  memcpy(command, opening, at);
  for (unsigned i = 0; i < 300; i++) {
    memcpy(command + at, "\\'", 2);
    at += 2;
  }
  memcpy(command + at, "'\npayload\n``'", 13);
  at += 13;
  for (unsigned i = 0; i < 300; i++) {
    memcpy(command + at, "'\\''", 4);
    at += 4;
  }
  memcpy(command + at, "'\n", 3);
  snprintf(nested, sizeof(nested), "echo \"$(%s)\"", command);
  for (unsigned variant = 0; variant < 2; variant++) {
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, variant ? nested : command, &result));
    ASSERT(result.verdict == (variant ? SG_VERDICT_ALLOW : SG_VERDICT_ALLOW) &&
           !result.truncated);
    ASSERT(result.subcommand_count == (variant ? 2 : 1));
    ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_APPLIED);
  }
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
    ASSERT(result.verdict == SG_VERDICT_ALLOW);
    ASSERT(((result.requirements & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0));
    ASSERT(result.subcommand_count == 4);
    /* Five nested execution stages are scoreable from the first complete
     * learned observation onward; the empty model correctly reports unknown
     * on the first pass. */
    if (pass == 0) {
      ASSERT(isinf(result.anomaly_score));
      ASSERT(isinf(result.anomaly_score_raw));
      ASSERT(isinf(result.anomaly_score_type));
    } else {
      ASSERT(isfinite(result.anomaly_score));
      ASSERT(isfinite(result.anomaly_score_raw));
      ASSERT(isfinite(result.anomaly_score_type));
    }
  }

  size_t vocabulary = test_anomaly_vocabulary(gate);
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
  ASSERT_EQ_UINT(test_anomaly_vocabulary(gate), vocabulary);
  sg_gate_free(gate);
}

/* --- SUGGESTIONS --- */

/* A suggestion is rendered with an allocation of its own. Failing it must not
 * return success with the suggestion missing: every injected failure either
 * reports the memory error or leaves the suggestions identical to a run
 * without faults. */
TEST(suggestion_rendering_failure_is_not_silent) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"tool #size.MiB done"}, 1);
  ASSERT(gate != NULL);
  ASSERT_ST_OK(
      test_policy_replace_cpl(gate, true, "tool #size.MiB done", false));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, true));
  static const char command[] = "tool 10GB 'a b'";
  sg_result_t baseline;
  st_test_alloc_reset();
  ASSERT_SG_OK(eval_cmd(gate, command, &baseline));
  size_t allocations = st_test_alloc_count();
  st_test_alloc_reset();
  ASSERT(baseline.suggestion_count == 2 && baseline.deny_suggestion_count == 2);
  ASSERT(allocations > 0);
  char expected[4][128];
  for (size_t i = 0; i < 2; i++) {
    ASSERT(strlen(baseline.suggestions[i]) < sizeof(expected[0]));
    ASSERT(strlen(baseline.deny_suggestions[i]) < sizeof(expected[0]));
    strcpy(expected[i], baseline.suggestions[i]);
    strcpy(expected[2 + i], baseline.deny_suggestions[i]);
  }
  size_t memory_failures = 0;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    sg_result_t result;
    st_test_alloc_fail_at(fail_at);
    sg_error_t error = eval_cmd(gate, command, &result);
    st_test_alloc_reset();
    if (error == SG_ERR_MEMORY) {
      memory_failures++;
      ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
      continue;
    }
    ASSERT_SG_OK(error);
    ASSERT(result.suggestion_count == 2 && result.deny_suggestion_count == 2);
    for (size_t i = 0; i < 2; i++) {
      ASSERT(strcmp(result.suggestions[i], expected[i]) == 0);
      ASSERT(strcmp(result.deny_suggestions[i], expected[2 + i]) == 0);
    }
  }
  ASSERT(memory_failures > 0);
  sg_gate_free(gate);
}

/* The conversion to a bucket index is undefined for a double that size_t
 * cannot represent, so a large finite score must saturate before it. */
TEST(cdf_bucket_saturates_before_conversion) {
  ASSERT_EQ_UINT(sg_test_cdf_bucket(0.0), 0);
  ASSERT_EQ_UINT(sg_test_cdf_bucket(0.1), 0);
  ASSERT_EQ_UINT(sg_test_cdf_bucket(25.0), 64);
  ASSERT_EQ_UINT(sg_test_cdf_bucket(49.99), 127);
  ASSERT_EQ_UINT(sg_test_cdf_bucket(50.0), 127);
  ASSERT_EQ_UINT(sg_test_cdf_bucket(1e9), 127);
  ASSERT_EQ_UINT(sg_test_cdf_bucket(1e300), 127);
  ASSERT_EQ_UINT(sg_test_cdf_bucket(DBL_MAX), 127);
}

/* --- EDGE CASES --- */

/* `&>` and `&>>` do not have an io-number or `{name}` descriptor form. A
 * prefix therefore remains an argv word for a simple command, while the same
 * text after a compound group is not a legal group redirect list. Keep this
 * boundary at Shellgate's public API so policy evaluation cannot silently see
 * a different command from Shellsplit's canonical records. */
TEST(combined_redirect_prefix_word_contract) {
  static const struct {
    const char *command;
    const char *rule;
  } direct[] = {
      {"printf x 2&>combined", "printf x 2"},
      {"printf x 3&>>combined", "printf x 3"},
      {"printf x {fd}&>combined", "printf x {fd}"},
  };
  for (size_t i = 0; i < sizeof(direct) / sizeof(direct[0]); i++) {
    sg_gate_t *gate = sg_gate_new();
    ASSERT(gate != NULL);
    ASSERT_SG_OK(add_exact_outer_rule(gate, direct[i].rule));
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, direct[i].command, &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
    sg_gate_free(gate);
  }

  static const char *const invalid_groups[] = {
      "{ printf x; } 2&>combined",
      "{ printf x; } 3&>>combined",
      "{ printf x; } {fd}&>combined",
  };
  for (size_t i = 0; i < sizeof(invalid_groups) / sizeof(invalid_groups[0]);
       i++) {
    sg_gate_t *gate = sg_gate_new();
    ASSERT(gate != NULL);
    sg_result_t result = {0};
    ASSERT(eval_cmd(gate, invalid_groups[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT);
    sg_gate_free(gate);
  }
}

/* Named descriptor documents are redirections, not words.  Policy evaluation
 * must therefore see exactly the executable argv while anomaly sequences keep
 * the redirect-only stage (including its pipeline-negation metadata). */
TEST(named_document_policy_and_stage_contract) {
  static const char *const rules[] = {"printf x", "cat"};
  static const char *const commands[] = {
      "printf x {fd}<<<body",
      "printf x {fd}<<EOF\nbody\nEOF\n",
      "{ cat; } {fd}<<<body",
      "{ cat; } {fd}<<EOF\nbody\nEOF\n",
  };
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));
  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, commands[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1 &&
           result.subcommands[0].matches);
    ASSERT_STR(result.subcommands[0].netargv,
               i < 2 ? "6:printf,1:x," : "3:cat,");
  }

  static const char *const negated[] = {
      "! <<<body",
      "! ! <<<body",
      "! <<EOF\nbody\nEOF\n",
      "! ! <<EOF\nbody\nEOF\n",
  };
  for (size_t i = 0; i < sizeof(negated) / sizeof(negated[0]); i++) {
    shell_netstring_buffer_t raw = {0};
    shell_netstring_buffer_t type = {0};
    size_t stages = 0;
    ASSERT(shell_build_anomaly_netseqs_buffer(negated[i], strlen(negated[i]),
                                              NULL, &raw, &type,
                                              &stages) == SHELL_PROCESS_OK);
    ASSERT(stages == 1 && (raw.length != sizeof("0:,") - 1 ||
                           memcmp(raw.data, "0:,", raw.length)) == 0);
    sg_anomaly_sequence_score_t score = {0};
    ASSERT_SG_OK(sg_gate_score_anomaly_netseq(
        gate, (const char *)raw.data, raw.length, (const char *)type.data,
        type.length, &score));
    ASSERT(score.stage_count == 1);
    shell_netstring_buffer_free(&type);
    shell_netstring_buffer_free(&raw);

    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, negated[i], &result));
    ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
           result.subcommand_count == 0);
  }
  sg_gate_free(gate);
}

/* --- CONFIGURATION --- */

/* --- POLICY MANAGEMENT --- */

TEST(arithmetic_command_policy) {
  const char *rules[] = {"printf *", "cat"};
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "((1))", &result));
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  const char *neutral[] = {"((1))",      "((0))",      "((1/0))", "{ ((1)); }",
                           "! ((1))",    "time ((1))", "((1)) &", "((1<<(2)))",
                           "((8>>(1)))", "((1<(2)))"};
  for (size_t i = 0; i < sizeof(neutral) / sizeof(neutral[0]); ++i) {
    ASSERT_SG_OK(eval_cmd(gate, neutral[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 0);
  }
  const char *io[] = {"((1)) >output",      "((1)) <input",
                      "((1)) 2>&1",         "((1)) <<<payload",
                      "{ ((1)); } >output", "((1)) {fd}>output"};
  for (size_t i = 0; i < sizeof(io) / sizeof(io[0]); ++i) {
    ASSERT_SG_OK(eval_cmd(gate, io[i], &result));
    if (result.verdict != SG_VERDICT_UNDETERMINED)
      fprintf(stderr, "arithmetic I/O policy: %s verdict %d\n", io[i],
              result.verdict);
    ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
           result.subcommand_count == 0);
  }
  ASSERT_SG_OK(eval_cmd(gate, "((1)) && printf yes", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "printf denied", false));
  ASSERT_SG_OK(eval_cmd(gate, "((1)) >output; printf denied", &result));
  ASSERT(result.verdict == SG_VERDICT_DENY);
  ASSERT_EQ_INT(eval_cmd(gate, "((value++))", &result), SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, SHELL_FEAT_SUBSHELL));
  ASSERT_SG_OK(eval_cmd(gate, "(( $x + $(printf 1) ))", &result));
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  sg_gate_free(gate);
}

TEST(policy_replacement_failure_atomicity) {
  const char *path = temp_policy_file();
  ASSERT(path != NULL);

  sg_gate_t *source = sg_gate_new();
  sg_gate_t *gate = sg_gate_new();
  ASSERT(source != NULL && gate != NULL);
  ASSERT_ST_OK(test_policy_replace_cpl(source, false, "cat #path", false));
  ASSERT_ST_OK(st_policy_save(sg_gate_allow_policy_borrowed(source), path));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "ls", false));

  st_test_alloc_fail_at(1);
  st_error_t error = test_policy_replace_cpl(gate, false, "pwd", false);
  st_test_alloc_reset();
  ASSERT(error == ST_ERR_MEMORY);
  ASSERT(st_policy_rule_count(sg_gate_allow_policy_borrowed(gate)) == 1);
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_SG_OK(eval_cmd(gate, "pwd", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);

  st_test_alloc_fail_at(1);
  error = test_policy_replace_from_file(gate, path);
  st_test_alloc_reset();
  ASSERT(error == ST_ERR_MEMORY);
  ASSERT(st_policy_rule_count(sg_gate_allow_policy_borrowed(gate)) == 1);

  st_test_io_fail_at(1);
  error = st_policy_save(sg_gate_allow_policy_borrowed(gate), path);
  st_test_io_reset();
  ASSERT(error == ST_ERR_IO);

  ASSERT_ST_OK(test_policy_replace_from_file(gate, path));
  ASSERT(st_policy_rule_count(sg_gate_allow_policy_borrowed(gate)) == 2);
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_SG_OK(eval_cmd(gate, "cat /etc/hosts", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);

  char missing[256];
  int fd = temp_fixture_file(missing, sizeof(missing), "shellgate-missing");
  ASSERT(fd >= 0);
  ASSERT(close(fd) == 0);
  ASSERT(unlink(missing) == 0);
  ASSERT(test_policy_replace_from_file(gate, missing) == ST_ERR_IO);
  ASSERT(test_policy_replace_cpl(gate, false, "", false) == ST_ERR_INVALID);

  FILE *malformed = fopen(path, "wb");
  ASSERT(malformed != NULL);
  ASSERT(fputs("not a policy\n", malformed) >= 0);
  ASSERT(fclose(malformed) == 0);
  ASSERT(test_policy_replace_from_file(gate, path) == ST_ERR_FORMAT);
  ASSERT(st_policy_rule_count(sg_gate_allow_policy_borrowed(gate)) == 2);

  sg_gate_free(gate);
  sg_gate_free(source);
}

/* --- SERIALIZATION --- */

/* --- BUFFER MANAGEMENT --- */

TEST(output_writer_exact_fit_boundaries) {
  char buffer[8];
  size_t used;
  bool overflow;

  /* One byte left holds only the terminator, which an empty string needs. */
  memset(buffer, 'x', sizeof(buffer));
  const char *copy = sg_test_writer_copy(buffer, 4, 3, "", 0, &used, &overflow);
  ASSERT(copy == buffer + 3 && copy[0] == '\0');
  ASSERT(used == 4 && !overflow);

  /* A full buffer has no room even for that terminator. */
  ASSERT(sg_test_writer_copy(buffer, 4, 4, "", 0, &used, &overflow) == NULL);
  ASSERT(overflow);

  /* A nonempty string cannot be cut to nothing in the last byte. */
  overflow = false;
  ASSERT(sg_test_writer_copy(buffer, 4, 3, "a", 1, &used, &overflow) == NULL);
  ASSERT(overflow);

  /* An empty string fits at the start of any nonempty buffer. */
  overflow = true;
  copy = sg_test_writer_copy(buffer, 1, 0, "", 0, &used, &overflow);
  ASSERT(copy == buffer && copy[0] == '\0' && used == 1 && !overflow);

  /* Nonempty strings keep their fit, truncation and overflow behavior. */
  overflow = true;
  copy = sg_test_writer_copy(buffer, 4, 0, "abc", 3, &used, &overflow);
  ASSERT(copy != NULL && strcmp(copy, "abc") == 0 && used == 4);
  copy = sg_test_writer_copy(buffer, 4, 0, "abcd", 4, &used, &overflow);
  ASSERT(copy != NULL && strcmp(copy, "abc") == 0 && used == 4 && overflow);
  overflow = false;
  copy = sg_test_writer_copy(buffer, 4, 1, "ab", 2, &used, &overflow);
  ASSERT(copy != NULL && strcmp(copy, "ab") == 0 && used == 4 && !overflow);
}

TEST(buffer_contract_matrix) {
  static const struct {
    const char *command;
    size_t buffer_size;
  } cases[] = {
      {"ls | sort | cat", 4}, {"rm -rf /", 8}, {"cat /etc/passwd", 16}};
  const char *rules[] = {"ls", "sort", "cat #path"};
  sg_gate_t *g = gate_with_rules(rules, 3);
  ASSERT_ST_OK(test_policy_replace_cpl(g, true, "rm", false));

  ASSERT_SG_OK(sg_gate_set_reject_mask(g, SHELL_FEAT_VARS));
  char feature_buffer[4];
  sg_result_t feature_result;
  ASSERT(sg_gate_evaluate(g, "echo $VALUE", strlen("echo $VALUE"),
                          feature_buffer, sizeof(feature_buffer),
                          &feature_result) == SG_ERR_TRUNC);
  ASSERT(feature_result.truncated);
  ASSERT(feature_result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT_SG_OK(sg_gate_set_reject_mask(g, SG_REJECT_MASK_DEFAULT));

  /* Early feature rejections run before workspace partitioning. The complete
   * caller buffer is available even when the capacity was constructed with a
   * deliberately tiny hypothetical graph-result prefix. */
  size_t early_feature_buffer_size =
      eval_buffer_size_for_prefix("echo $VALUE", 4);
  size_t early_feature_prefix =
      eval_result_prefix_size("echo $VALUE", early_feature_buffer_size);
  ASSERT(early_feature_buffer_size != 0 && early_feature_prefix != 0);
  ASSERT_SG_OK(sg_gate_set_reject_mask(g, SHELL_FEAT_VARS));
  ASSERT(eval_with_prefix(g, "echo $VALUE", 4, &feature_result) == SG_OK);
  ASSERT(!feature_result.truncated &&
         feature_result.verdict == SG_VERDICT_REJECT &&
         feature_result.deny_reason != NULL &&
         strlen(feature_result.deny_reason) > 4 &&
         result_fields_stay_in_prefix(&feature_result,
                                      early_feature_buffer_size) &&
         !result_fields_stay_in_prefix(&feature_result, early_feature_prefix));
  ASSERT_SG_OK(sg_gate_set_reject_mask(g, SG_REJECT_MASK_DEFAULT));

  /* A syntactically valid evaluation cannot silently allocate resolver state
   * when the caller left room only for diagnostics. */
  char workspace_too_small[SG_DIAGNOSTIC_BUF_MIN] = {0};
  sg_result_t workspace_result;
  ASSERT(sg_gate_evaluate(g, "ls", 2, workspace_too_small,
                          sizeof(workspace_too_small),
                          &workspace_result) == SG_ERR_MEMORY);
  ASSERT(workspace_result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(!workspace_result.truncated);
  ASSERT_STR(workspace_result.deny_reason, "depgraph workspace unavailable");

  /* The resolver tail also cannot consume the entire caller buffer: the
   * evaluator needs at least one byte in its result prefix.  Align this test
   * buffer explicitly so its exact size reaches that boundary on every
   * supported allocator. */
  size_t workspace_size = sg_test_eval_workspace_size(2);
  size_t workspace_alignment = shell_dep_workspace_alignment();
  ASSERT(workspace_size != 0);
  ASSERT(workspace_alignment != 0);
  ASSERT(workspace_size <= SIZE_MAX - workspace_alignment);
  char *exact_workspace_raw = malloc(workspace_size + workspace_alignment);
  ASSERT(exact_workspace_raw != NULL);
  uintptr_t raw_address = (uintptr_t)(void *)exact_workspace_raw;
  uintptr_t remainder = raw_address % workspace_alignment;
  char *exact_workspace =
      exact_workspace_raw +
      (remainder == 0 ? 0 : workspace_alignment - remainder);
  ASSERT(sg_gate_evaluate(g, "ls", 2, exact_workspace, workspace_size,
                          &workspace_result) == SG_ERR_MEMORY);
  ASSERT(workspace_result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(!workspace_result.truncated);
  ASSERT_STR(workspace_result.deny_reason, "depgraph workspace unavailable");
  free(exact_workspace_raw);

  /* Failed parsing happens before the depgraph workspace is partitioned.  A
   * caller that cannot retain even its short diagnostic still gets an explicit
   * undetermined result, whether parsing failed before or after a command. */
  char one_byte_buffer[1];
  ASSERT(sg_gate_evaluate(g, "ls", 2, one_byte_buffer, sizeof(one_byte_buffer),
                          &workspace_result) == SG_ERR_MEMORY);
  ASSERT(workspace_result.truncated);
  ASSERT(workspace_result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(sg_gate_evaluate(g, "'", 1, one_byte_buffer, sizeof(one_byte_buffer),
                          &workspace_result) == SG_ERR_TRUNC);
  ASSERT(workspace_result.truncated);
  ASSERT(workspace_result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(sg_gate_evaluate(g, "ls; '", strlen("ls; '"), one_byte_buffer,
                          sizeof(one_byte_buffer),
                          &workspace_result) == SG_ERR_TRUNC);
  ASSERT(workspace_result.truncated);
  ASSERT(workspace_result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(sg_gate_evaluate(g, "{ echo }", strlen("{ echo }"), one_byte_buffer,
                          sizeof(one_byte_buffer),
                          &workspace_result) == SG_ERR_TRUNC);
  ASSERT(workspace_result.truncated);
  ASSERT(workspace_result.verdict == SG_VERDICT_UNDETERMINED);

  /* A syntactically valid command reaches the partitioned writer, so a tiny
   * result prefix still fails closed after the resolver workspace is carved
   * from the tail. Syntax errors above that stage intentionally retain the
   * full diagnostic buffer and return SG_ERR_PARSE instead. */
  sg_result_t diagnostic_result;
  ASSERT(eval_with_prefix(g, "echo $(id)", 4, &diagnostic_result) ==
         SG_ERR_TRUNC);
  ASSERT(diagnostic_result.truncated);
  ASSERT(diagnostic_result.verdict == SG_VERDICT_UNDETERMINED);

  /* A graph-only rejection uses the same partitioned result prefix.  It must
   * not surface a partial rejection reason as a definite policy decision. */
  ASSERT_SG_OK(sg_gate_set_reject_mask(g, 0));
  ASSERT(eval_with_prefix(g, "printf x >&$missing", 4, &diagnostic_result) ==
         SG_ERR_TRUNC);
  ASSERT(diagnostic_result.truncated);
  ASSERT(diagnostic_result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT_SG_OK(sg_gate_set_reject_mask(g, SG_REJECT_MASK_DEFAULT));

  for (size_t repeat = 0; repeat < 2; repeat++) {
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      sg_result_t r = {0};
      memset(eval_buf, 0xFF, sizeof(eval_buf));
      sg_error_t status =
          eval_with_prefix(g, cases[i].command, cases[i].buffer_size, &r);
      if (status != SG_ERR_TRUNC || !r.truncated ||
          r.verdict != SG_VERDICT_UNDETERMINED)
        fprintf(stderr,
                "prefix case %zu repeat %zu: %s, prefix %zu, "
                "status %d, truncated %d, verdict %d\n",
                i, repeat, cases[i].command, cases[i].buffer_size, status,
                r.truncated, r.verdict);
      ASSERT(status == SG_ERR_TRUNC);
      ASSERT(r.truncated);
      ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
      size_t size =
          eval_buffer_size_for_prefix(cases[i].command, cases[i].buffer_size);
      size_t prefix = eval_result_prefix_size(cases[i].command, size);
      /* An empty partial result need not write a string. Every string it
       * does publish must be terminated inside the usable prefix. */
      bool fields_valid = result_fields_stay_in_prefix(&r, prefix);
      if (!fields_valid)
        fprintf(stderr,
                "prefix case %zu repeat %zu: %s, invalid result "
                "fields in %zu-byte prefix\n",
                i, repeat, cases[i].command, prefix);
      ASSERT(fields_valid);
    }
  }

  sg_result_t pipe_result;
  ASSERT(eval_with_prefix(g, "curl example.test | sh", 2, &pipe_result) ==
         SG_ERR_TRUNC);
  ASSERT(pipe_result.truncated);
  ASSERT(result_fields_stay_in_prefix(
      &pipe_result, eval_result_prefix_size("curl example.test | sh",
                                            eval_buffer_size_for_prefix(
                                                "curl example.test | sh", 2))));

  static const struct {
    const char *command;
    sg_verdict_t verdict;
  } reuse_cases[] = {{"ls", SG_VERDICT_ALLOW},
                     {"unknown", SG_VERDICT_UNDETERMINED}};
  for (size_t i = 0; i < sizeof(reuse_cases) / sizeof(reuse_cases[0]); i++) {
    sg_result_t result;
    ASSERT(eval_with_prefix(g, reuse_cases[i].command, 256, &result) == SG_OK);
    ASSERT(result.verdict == reuse_cases[i].verdict);
    ASSERT(!result.truncated);
    ASSERT(result.subcommand_count == 1);
    ASSERT_STR(result.subcommands[0].display_command, reuse_cases[i].command);
  }

  sg_result_t result;

  ASSERT(sg_gate_evaluate(g, "ls", 2, one_byte_buffer, 0, &result) ==
         SG_ERR_INVALID);
  ASSERT(sg_gate_evaluate(g, "", 0, one_byte_buffer, 1, &result) ==
         SG_ERR_INVALID);

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
  cmd[len] = '\0';
  ASSERT(eval_with_prefix(g, cmd, 4096, &result) == SG_ERR_TRUNC);
  ASSERT(result.subcommand_count == SG_MAX_SUBCOMMAND_RESULTS);
  ASSERT(result.truncated);
  ASSERT(result.subcommand_truncated);

  size_t graph_buffer_size = eval_buffer_size_for_prefix("ls", 32);
  size_t graph_result_prefix = eval_result_prefix_size("ls", graph_buffer_size);
  ASSERT(graph_buffer_size != 0 && graph_result_prefix != 0);
  memset(eval_buf, 0xFF, sizeof(eval_buf));
  ASSERT(eval_with_prefix(g, "ls", 32, &result) == SG_OK);
  ASSERT(!result.truncated);
  ASSERT_STR(result.subcommands[0].display_command, "ls");
  ASSERT(result.subcommands[0].netargv != NULL &&
         (uintptr_t)(void *)result.subcommands[0].display_command >=
             (uintptr_t)(void *)eval_buf &&
         (size_t)((uintptr_t)(void *)result.subcommands[0].display_command -
                  (uintptr_t)(void *)eval_buf) < graph_result_prefix &&
         (uintptr_t)(void *)result.subcommands[0].netargv >=
             (uintptr_t)(void *)eval_buf &&
         (size_t)((uintptr_t)(void *)result.subcommands[0].netargv -
                  (uintptr_t)(void *)eval_buf) <= graph_result_prefix &&
         result.subcommands[0].netargv_length <=
             graph_result_prefix -
                 (size_t)((uintptr_t)(void *)result.subcommands[0].netargv -
                          (uintptr_t)(void *)eval_buf));
  ASSERT(memchr(eval_buf, '\0', 32) != NULL);

  ASSERT_SG_OK(sg_gate_enable_anomaly(g, 5.0, NULL));
  static const char anomaly_command[] =
      "ls -la /tmp ; cd /var/log ; pwd ; cat somefile.txt";
  size_t anomaly_vocab_before = test_anomaly_vocabulary(g);
  memset(eval_buf, 0xFF, sizeof(eval_buf));
  ASSERT(eval_with_prefix(g, anomaly_command, 16, &result) == SG_ERR_TRUNC);
  ASSERT(result.truncated);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT_EQ_UINT(test_anomaly_vocabulary(g), anomaly_vocab_before);
  ASSERT(result_fields_stay_in_prefix(
      &result,
      eval_result_prefix_size(
          anomaly_command, eval_buffer_size_for_prefix(anomaly_command, 16))));

  size_t hint = sg_gate_evaluate_size_hint(strlen(anomaly_command));
  char *hint_buffer = malloc(hint);
  ASSERT(hint_buffer != NULL);
  ASSERT(sg_gate_evaluate(g, anomaly_command, strlen(anomaly_command),
                          hint_buffer, hint, &result) == SG_OK);
  ASSERT(!result.truncated);
  /* A truncated attempt must be a complete no-op for anomaly learning. The
   * successful retry therefore has the same model and pre-update score as one
   * complete evaluation on a fresh equivalent gate. */
  sg_gate_t *retry_reference = gate_with_rules(rules, 3);
  ASSERT(retry_reference != NULL);
  ASSERT_ST_OK(test_policy_replace_cpl(retry_reference, true, "rm", false));
  ASSERT_SG_OK(sg_gate_enable_anomaly(retry_reference, 5.0, NULL));
  char *reference_buffer = malloc(hint);
  ASSERT(reference_buffer != NULL);
  sg_result_t reference_result;
  ASSERT(sg_gate_evaluate(retry_reference, anomaly_command,
                          strlen(anomaly_command), reference_buffer, hint,
                          &reference_result) == SG_OK);
  ASSERT_EQ_UINT(test_anomaly_vocabulary(g),
                 test_anomaly_vocabulary(retry_reference));
  sg_result_t retry_probe, reference_probe;
  ASSERT_SG_OK(eval_cmd(g, "printf unique retry probe", &retry_probe));
  ASSERT_SG_OK(
      eval_cmd(retry_reference, "printf unique retry probe", &reference_probe));
  ASSERT(fabs(retry_probe.anomaly_score - reference_probe.anomaly_score) <
         1e-12);
  ASSERT(fabs(retry_probe.anomaly_score_raw -
              reference_probe.anomaly_score_raw) < 1e-12);
  ASSERT(fabs(retry_probe.anomaly_score_type -
              reference_probe.anomaly_score_type) < 1e-12);
  free(reference_buffer);
  sg_gate_free(retry_reference);
  free(hint_buffer);
  /* Every caller-buffer alignment must reserve the same usable workspace
   * without requiring a hidden allocation or an aligned buffer base. */
  char *alignment_buffer = malloc(hint + workspace_alignment - 1);
  ASSERT(alignment_buffer != NULL);
  for (size_t offset = 0; offset < workspace_alignment; offset++) {
    ASSERT(sg_gate_evaluate(g, anomaly_command, strlen(anomaly_command),
                            alignment_buffer + offset, hint, &result) == SG_OK);
    ASSERT(!result.truncated);
  }
  free(alignment_buffer);
  ASSERT_SG_OK(eval_cmd(g, anomaly_command, &result));
  ASSERT(!result.truncated);

  /* Nested substitutions can make the rendered stage list grow faster than
   * the source itself. The public hint is intentionally advisory, and a
   * truncation must remain safe to retry without learning a partial record. */
  char nested_command[1024] = "echo nested";
  for (size_t depth = 0; depth < 16; depth++) {
    char wrapped[sizeof(nested_command)];
    int written = snprintf(wrapped, sizeof(wrapped), "printf '%%s' \"$(%s)\"",
                           nested_command);
    ASSERT(written > 0 && (size_t)written < sizeof(wrapped));
    memcpy(nested_command, wrapped, (size_t)written + 1);
  }
  sg_gate_t *nested_gate = sg_gate_new();
  ASSERT(nested_gate != NULL);
  ASSERT_SG_OK(sg_gate_enable_anomaly(nested_gate, 5.0, NULL));
  size_t nested_hint = sg_gate_evaluate_size_hint(strlen(nested_command));
  ASSERT(nested_hint != SIZE_MAX);
  char *nested_buffer = malloc(nested_hint);
  ASSERT(nested_buffer != NULL);
  sg_result_t nested_result;
  ASSERT(sg_gate_evaluate(nested_gate, nested_command, strlen(nested_command),
                          nested_buffer, nested_hint,
                          &nested_result) == SG_ERR_TRUNC);
  ASSERT(nested_result.truncated && !nested_result.subcommand_truncated);
  ASSERT_EQ_UINT(test_anomaly_vocabulary(nested_gate), 0);
  char *nested_grown = realloc(nested_buffer, nested_hint * 2);
  ASSERT(nested_grown != NULL);
  nested_buffer = nested_grown;
  ASSERT(sg_gate_evaluate(nested_gate, nested_command, strlen(nested_command),
                          nested_buffer, nested_hint * 2,
                          &nested_result) == SG_OK);
  ASSERT(test_anomaly_vocabulary(nested_gate) > 0);
  free(nested_buffer);
  sg_gate_free(nested_gate);
  sg_gate_free(g);
}

TEST(graph_result_fields_stay_out_of_workspace) {
  static const char *const allow_rules[] = {"ls", "cat #path", "echo *"};
  const size_t requested_prefix = 2048;
  size_t buffer_size = eval_buffer_size_for_prefix("ls", requested_prefix);
  size_t result_prefix = eval_result_prefix_size("ls", buffer_size);
  ASSERT(buffer_size != 0 && result_prefix >= requested_prefix);

  sg_gate_t *gate = gate_with_rules(allow_rules, sizeof(allow_rules) /
                                                     sizeof(allow_rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "blocked", false));

  sg_result_t result = {0};
  ASSERT(eval_with_prefix(gate, "ls", requested_prefix, &result) == SG_OK);
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         result_fields_stay_in_prefix(&result, result_prefix));

  ASSERT(eval_with_prefix(gate, "blocked", requested_prefix, &result) == SG_OK);
  buffer_size = eval_buffer_size_for_prefix("blocked", requested_prefix);
  result_prefix = eval_result_prefix_size("blocked", buffer_size);
  ASSERT(result.verdict == SG_VERDICT_DENY &&
         result.subcommands[0].reject_reason != NULL &&
         result_fields_stay_in_prefix(&result, result_prefix));

  ASSERT(eval_with_prefix(gate, "echo data > /workspace/result-prefix",
                          requested_prefix, &result) == SG_OK);
  buffer_size = eval_buffer_size_for_prefix(
      "echo data > /workspace/result-prefix", requested_prefix);
  result_prefix = eval_result_prefix_size(
      "echo data > /workspace/result-prefix", buffer_size);
  ASSERT(result.subcommand_count == 1 &&
         result_fields_stay_in_prefix(&result, result_prefix));

  /* A graph-backed truncation may retain a useful command prefix, but no
   * public pointer may cross into the route workspace tail. */
  bool saw_graph_truncation = false;
  bool saw_retained_graph_result = false;
  for (size_t prefix = 1; prefix <= 256; prefix++) {
    size_t buffer_size = eval_buffer_size_for_prefix(
        "echo data > /workspace/result-prefix", prefix);
    size_t result_prefix = eval_result_prefix_size(
        "echo data > /workspace/result-prefix", buffer_size);
    ASSERT(buffer_size != 0 && result_prefix != 0);
    sg_error_t error = eval_with_prefix(
        gate, "echo data > /workspace/result-prefix", prefix, &result);
    if (error != SG_ERR_TRUNC)
      continue;
    saw_graph_truncation = true;
    ASSERT(result.truncated && result.verdict == SG_VERDICT_UNDETERMINED &&
           result_fields_stay_in_prefix(&result, result_prefix));
    saw_retained_graph_result = saw_retained_graph_result ||
                                result.subcommand_count != 0 ||
                                result.deny_reason != NULL;
  }
  ASSERT(saw_graph_truncation && saw_retained_graph_result);
  sg_gate_free(gate);

  const char *const suggestion_rules[] = {"lss"};
  gate = gate_with_rules(suggestion_rules, sizeof(suggestion_rules) /
                                               sizeof(suggestion_rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, true));
  ASSERT(eval_with_prefix(gate, "ls", requested_prefix, &result) == SG_OK);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.suggestion_count > 0 &&
         result_fields_stay_in_prefix(&result, result_prefix));
  sg_gate_free(gate);
}

/* Suggestions are separately rendered diagnostics.  Exercise two allow and
 * two deny candidates through both the complete result and every useful
 * short-prefix boundary: a truncated rendering must never retain a definite
 * policy verdict, while a sufficiently large caller buffer retains each
 * independently useful suggestion. */
TEST(suggestion_streaming_buffer_contract) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "cat #path", false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "rm #path", false));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, true));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));

  static const char command[] = "cat /tmp/one /tmp/two; rm /tmp/one /tmp/two";
  sg_result_t complete;
  ASSERT_SG_OK(eval_cmd(gate, command, &complete));
  ASSERT(complete.suggestion_count == 2);
  ASSERT(complete.deny_suggestion_count == 2);
  ASSERT(complete.suggestions[0] != NULL && complete.suggestions[1] != NULL);
  ASSERT(complete.deny_suggestions[0] != NULL &&
         complete.deny_suggestions[1] != NULL);

  bool saw_truncation = false;
  for (size_t prefix = 1; prefix <= 256; prefix++) {
    sg_result_t result;
    sg_error_t error = eval_with_prefix(gate, command, prefix, &result);
    ASSERT(result.truncated == (error == SG_ERR_TRUNC));
    if (error == SG_ERR_TRUNC) {
      saw_truncation = true;
      ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
    } else {
      ASSERT(error == SG_OK);
      ASSERT(result.suggestion_count == 2);
      ASSERT(result.deny_suggestion_count == 2);
    }
  }
  ASSERT(saw_truncation);
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
                  {SG_VERDICT_REVIEW, "REVIEW"},
                  {SG_VERDICT_AUDIT, "AUDIT"},
                  {SG_VERDICT_NEEDS_REASON, "NEEDS_REASON"},
                  {SG_VERDICT_DISCOURAGE, "DISCOURAGE"},
                  {SG_VERDICT_DENY_ESCALATE, "DENY_ESCALATE"},
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
  /* Long inputs also reserve decoded/identity scratch, not just diagnostics. */
  size_t long_length = 16u * 1024u * 1024u;
  ASSERT(sg_gate_evaluate_size_hint(long_length) >= long_length * 8);
  ASSERT(sg_gate_evaluate_size_hint(SIZE_MAX / 4) == SIZE_MAX);

  /* Inspect large-source lifetimes without allocating multi-gigabyte arenas.
   * These inequalities exercise the retained/reusable capacity contract. */
  static const size_t layout_lengths[] = {0, 128, 65536, 16u * 1024u * 1024u};
  for (unsigned i = 0; i < sizeof(layout_lengths) / sizeof(*layout_lengths);
       ++i) {
    size_t length = layout_lengths[i];
    sg_test_eval_layout_t layout;
    if (!sg_test_eval_workspace_layout(length, &layout)) {
      /* Large source arenas can exceed SIZE_MAX on narrower platforms. */
      ASSERT(sg_gate_evaluate_size_hint(length) == SIZE_MAX);
      continue;
    }
    ASSERT(layout.reusable >= layout.graph);
    ASSERT((layout.reusable - layout.graph) % shell_dep_workspace_alignment() ==
           0);
    ASSERT(layout.reusable >= layout.index + layout.source);
    ASSERT(layout.reusable >=
           layout.index + 4 * (length + SHELL_DEP_CWD_BUF_SIZE + 1u));
    ASSERT(layout.total == layout.reusable + layout.source);
    ASSERT(sg_test_eval_workspace_size(length) >= layout.total);
  }
  sg_test_eval_layout_t exhausted;
  ASSERT(!sg_test_eval_workspace_layout(SIZE_MAX, &exhausted));
  ASSERT(!sg_test_eval_workspace_layout(SIZE_MAX / 4, &exhausted));

  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "ls", false));
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "cat #path", false));
  ASSERT_ST_OK(test_policy_replace_cpl(g, true, "cat /etc/shadow", false));

  sg_result_t result;
  ASSERT(eval_cmd(g, "ls ; cat /etc/shadow", &result) == SG_OK);
  ASSERT(result.attention_index == 1);
  sg_gate_free(g);
}

TEST(contextual_policy_mutations_preserve_verdicts) {
  static const struct {
    const char *exact, *general, *command;
  } cases[] = {
      {"kill 9", "kill #n", "kill 9"},
      {"grep /tmp/x", "grep #p", "grep /tmp/x"},
      {"tool #opt 9", "tool #opt #n", "tool -s 9"},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    for (unsigned deny = 0; deny < 2; deny++) {
      for (unsigned order = 0; order < 2; order++) {
        sg_gate_t *gate = sg_gate_new();
        ASSERT(gate != NULL);
        const char *rules[] = {cases[i].exact, cases[i].general};
        for (unsigned step = 0; step < 2; step++) {
          const char *rule = rules[order ^ step];
          ASSERT_ST_OK(deny
                           ? test_policy_replace_cpl(gate, true, rule, false)
                           : test_policy_replace_cpl(gate, false, rule, false));
        }
        sg_result_t result;
        ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
        ASSERT(result.verdict == (deny ? SG_VERDICT_DENY : SG_VERDICT_ALLOW));
        sg_gate_free(gate);
      }
    }
  }
}

/* --- EXPANSION CALLBACKS --- */

static shell_expand_status_t
expand_canonical_cstr(const shell_expand_word_request_t *request,
                      const char **netargv, size_t *length, void *ctx) {
  (void)request;
  const char *encoded = ctx;
  if (!encoded)
    return SHELL_EXPAND_UNRESOLVED;
  *netargv = encoded;
  *length = strlen(encoded);
  return SHELL_EXPAND_RESOLVED;
}

static shell_expand_status_t
expand_home_canonical(const shell_expand_word_request_t *request,
                      const char **netargv, size_t *length, void *ctx) {
  const char *word = request->source + request->word_offset;
  size_t word_length = request->word_length;
  bool home = (word_length == 5 && memcmp(word, "$HOME", 5) == 0) ||
              (word_length == 7 && memcmp(word, "${HOME}", 7) == 0);
  return home ? expand_canonical_cstr(request, netargv, length, ctx)
              : SHELL_EXPAND_UNRESOLVED;
}

static shell_expand_status_t
expand_txt_canonical(const shell_expand_word_request_t *request,
                     const char **netargv, size_t *length, void *ctx) {
  const char *pattern = request->source + request->word_offset;
  size_t pattern_length = request->word_length;
  return pattern_length == 5 && memcmp(pattern, "*.txt", 5) == 0
             ? expand_canonical_cstr(request, netargv, length, ctx)
             : SHELL_EXPAND_UNRESOLVED;
}

static shell_expand_status_t
expand_invalid_canonical(const shell_expand_word_request_t *request,
                         const char **netargv, size_t *length, void *ctx) {
  (void)request;
  (void)ctx;
  *netargv = NULL;
  *length = 0;
  return (shell_expand_status_t)2;
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
    ASSERT_ST_OK(test_policy_replace_cpl(g, false, cases[i].rule, false));
    if (cases[i].kind == EXPAND_VARIABLE)
      ASSERT_SG_OK(sg_gate_set_expand_word_netargv(g, expand_home_canonical,
                                                   cases[i].context));
    else if (cases[i].kind == EXPAND_GLOB)
      ASSERT_SG_OK(sg_gate_set_expand_word_netargv(g, expand_txt_canonical,
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
  ASSERT_ST_OK(test_policy_replace_cpl(canonical, false, "cat #f #f", false));
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(canonical, expand_canonical_cstr,
                                               "7:one.txt,7:two.txt,"));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(canonical, "cat *.txt", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_STR(result.subcommands[0].netargv, "3:cat,7:one.txt,7:two.txt,");
  sg_gate_free(canonical);

  canonical = sg_gate_new();
  ASSERT(canonical != NULL);
  ASSERT_ST_OK(test_policy_replace_cpl(canonical, false, "cat hit hit", false));
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(canonical, expand_canonical_cstr,
                                               "3:hit,"));
  ASSERT_SG_OK(eval_cmd(canonical, "cat ?.txt [ab].txt", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_STR(result.subcommands[0].netargv, "3:cat,3:hit,3:hit,");
  sg_gate_free(canonical);

  canonical = sg_gate_new();
  ASSERT(canonical != NULL);
  ASSERT_ST_OK(
      test_policy_replace_cpl(canonical, false, "echo \"two words\"", false));
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(canonical, expand_canonical_cstr,
                                               "9:two words,"));
  ASSERT_SG_OK(eval_cmd(canonical, "echo $VALUE", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_STR(result.subcommands[0].netargv, "4:echo,9:two words,");
  ASSERT_STR(result.subcommands[0].display_command, "echo two words");
  ASSERT(strcmp(result.subcommands[0].display_command,
                result.subcommands[0].netargv) != 0);
  sg_gate_free(canonical);

  /* Every portable identifier character class must permit callback expansion;
   * the extractor must not accept only the common lowercase-name path. */
  canonical = sg_gate_new();
  ASSERT(canonical != NULL);
  ASSERT_ST_OK(test_policy_replace_cpl(canonical, false,
                                       "echo value value value", false));
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(canonical, expand_canonical_cstr,
                                               "5:value,"));
  ASSERT_SG_OK(eval_cmd(canonical, "echo ${UPPER} ${A1} ${_}", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_STR(result.subcommands[0].netargv, "4:echo,5:value,5:value,5:value,");
  sg_gate_free(canonical);

  /* A lone dollar is static text. A special parameter is a dynamic whole
   * source word and therefore reaches the application callback unchanged. */
  canonical = sg_gate_new();
  ASSERT(canonical != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(canonical, 0));
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(canonical, expand_canonical_cstr,
                                               "5:value,"));
  ASSERT_SG_OK(eval_cmd(canonical, "echo $", &result));
  ASSERT_STR(result.subcommands[0].netargv, "4:echo,1:$,");
  ASSERT_SG_OK(eval_cmd(canonical, "echo $-", &result));
  ASSERT_STR(result.subcommands[0].netargv, "4:echo,5:value,");
  sg_gate_free(canonical);

  canonical = sg_gate_new();
  ASSERT(canonical != NULL);
  ASSERT_ST_OK(test_policy_replace_cpl(canonical, false, "echo tail", false));
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(canonical, expand_canonical_cstr, ""));
  ASSERT_SG_OK(eval_cmd(canonical, "echo $DROP tail", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_STR(result.subcommands[0].netargv, "4:echo,4:tail,");
  sg_gate_free(canonical);

  canonical = sg_gate_new();
  ASSERT(canonical != NULL);
  ASSERT_ST_OK(
      test_policy_replace_cpl(canonical, false, "echo \"\" tail", false));
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(canonical, expand_canonical_cstr, "0:,"));
  ASSERT_SG_OK(eval_cmd(canonical, "echo $EMPTY tail", &result));
  ASSERT_STR(result.subcommands[0].netargv, "4:echo,0:,4:tail,");
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  sg_gate_free(canonical);

  canonical = sg_gate_new();
  ASSERT(canonical != NULL);
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(canonical, expand_canonical_cstr,
                                               "3:bad"));
  ASSERT(eval_cmd(canonical, "echo $BAD", &result) == SG_ERR_EXPAND);
  sg_gate_free(canonical);

  canonical = sg_gate_new();
  ASSERT(canonical != NULL);
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(canonical,
                                               expand_invalid_canonical, NULL));
  ASSERT(eval_cmd(canonical, "echo $BAD", &result) == SG_ERR_EXPAND);
  sg_gate_free(canonical);
}

typedef struct {
  const char *expected;
  size_t calls;
  bool matched;
} expansion_query_capture_t;

struct expansion_view {
  const char *netargv;
  size_t length;
};

static shell_expand_status_t
expand_requested_length(const shell_expand_word_request_t *request,
                        const char **netargv, size_t *length, void *ctx) {
  (void)request;
  const struct expansion_view *view = ctx;
  *netargv = view->netargv;
  *length = view->length;
  return SHELL_EXPAND_RESOLVED;
}

/* Callback-produced netargv is a byte span, unlike the C-string fixtures
 * above. Exercise distinct dynamic spellings with a payload that cannot
 * survive accidental strlen()-based handling. */
TEST(binary_expansion_callback_contract) {
  static const unsigned char expansion[] = {
      '3', ':', 'a', '\0', 'b', ',',
  };
  static const unsigned char expected_netargv[] = {
      '4', ':', 'e', 'c', 'h', 'o', ',', '3', ':', 'a', '\0', 'b', ',',
  };
  static const char *const cases[] = {
      "echo $VALUE",
      "echo *.binary",
  };
  const struct expansion_view view = {
      .netargv = (const char *)expansion,
      .length = sizeof(expansion),
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *gate = sg_gate_new();
    ASSERT(gate != NULL);
    ASSERT_ST_OK(
        test_policy_replace_cpl(gate, false, "echo \"a\\x00b\"", false));
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_requested_length,
                                                 (void *)&view));

    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
    const sg_subcommand_result_t *subcommand = &result.subcommands[0];
    ASSERT(subcommand->netargv != NULL &&
           subcommand->netargv_length == sizeof(expected_netargv) &&
           memcmp(subcommand->netargv, expected_netargv,
                  sizeof(expected_netargv)) == 0);
    ASSERT_STR(subcommand->display_command, "echo a\\x00b");

    st_token_array_t tokens = {0};
    ASSERT(st_netargv_classify_view(
               (st_netargv_view_t){.data = subcommand->netargv,
                                   .length = subcommand->netargv_length},
               &tokens) == ST_OK);
    ASSERT(tokens.count == 2 && tokens.tokens[1].text_length == 3 &&
           memcmp(tokens.tokens[1].text, "a\0b", 3) == 0);
    st_token_array_free(&tokens);
    sg_gate_free(gate);
  }

  sg_gate_t *path_gate = sg_gate_new();
  ASSERT(path_gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(path_gate, 0));
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(
      path_gate, expand_requested_length, (void *)&view));
  sg_result_t path_result = {0};
  ASSERT(eval_cmd(path_gate, "echo >\"$OUT\"", &path_result) == SG_ERR_EXPAND);
  sg_gate_free(path_gate);
}

typedef struct {
  shell_expand_word_purpose_t purpose;
  shell_expand_status_t status;
  struct expansion_view view;
  size_t calls;
} expansion_error_fixture_t;

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    expand_error_fixture(const shell_expand_word_request_t *request,
                         const char **netargv, size_t *length, void *context) {
  expansion_error_fixture_t *fixture = context;
  if (request->purpose != fixture->purpose)
    return SHELL_EXPAND_UNRESOLVED;
  fixture->calls++;
  *netargv = fixture->view.netargv;
  *length = fixture->view.length;
  return fixture->status;
}

TEST(expansion_error_diagnostic_boundaries) {
  static const char binary[] = "3:a\0b,";
  static const struct {
    shell_expand_status_t status;
    struct expansion_view view;
  } failures[] = {
      {SHELL_EXPAND_FAILED, {NULL, 0}},
      {(shell_expand_status_t)2, {NULL, 0}},
      {SHELL_EXPAND_RESOLVED, {"01:a,", 5}},
      {SHELL_EXPAND_RESOLVED, {"2:a,", 4}},
      {SHELL_EXPAND_RESOLVED, {"1:a;", 4}},
      {SHELL_EXPAND_RESOLVED, {"1:a,garbage", 11}},
      {SHELL_EXPAND_RESOLVED, {binary, sizeof(binary) - 1}},
  };
  static const struct {
    const char *source;
    shell_expand_word_purpose_t purpose;
  } sources[] = {
      {"echo \"$ARG\"", SHELL_EXPAND_WORD_ARGUMENT},
      {"echo >\"$OUT\"", SHELL_EXPAND_WORD_REDIRECT_PATH},
      {"echo \"$(<\"$FILE\")\"", SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH},
  };
  static const size_t prefixes[] = {1, 8, 21, 22, 512};
  static const char diagnostic[] = "word expansion failed";
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo \"a\\x00b\"", false));

  for (size_t source = 0; source < sizeof(sources) / sizeof(sources[0]);
       source++) {
    size_t source_length = strlen(sources[source].source);
    size_t workspace = sg_test_eval_workspace_size(source_length);
    size_t alignment = shell_dep_workspace_alignment();
    char *storage = malloc(workspace + 512 + alignment - 1);
    ASSERT(storage != NULL && workspace != 0);
    expansion_error_fixture_t fixture = {.purpose = sources[source].purpose};
    ASSERT_SG_OK(
        sg_gate_set_expand_word_netargv(gate, expand_error_fixture, &fixture));
    for (size_t failure = 0; failure < sizeof(failures) / sizeof(failures[0]);
         failure++) {
      if (failure == sizeof(failures) / sizeof(failures[0]) - 1 && source == 0)
        continue; /* Binary argv is valid; only pathnames reject NUL. */
      fixture.status = failures[failure].status;
      fixture.view = failures[failure].view;
      for (size_t capacity = 0;
           capacity < sizeof(prefixes) / sizeof(prefixes[0]); capacity++) {
        size_t prefix = prefixes[capacity];
        char *buffer = sg_test_eval_buffer_for_prefix(storage, prefix);
        size_t buffer_size = workspace + prefix;
        ASSERT(sg_test_eval_prefix_size(buffer, buffer_size, source_length) ==
               prefix);
        fixture.calls = 0;
        sg_result_t result = {0};
        sg_error_t error =
            sg_gate_evaluate(gate, sources[source].source, source_length,
                             buffer, buffer_size, &result);
        if (error != SG_ERR_EXPAND)
          printf("\n    expansion error source=%zu failure=%zu prefix=%zu "
                 "error=%d\n",
                 source, failure, prefix, error);
        ASSERT(error == SG_ERR_EXPAND && fixture.calls == 1);
        ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
               result.truncated == (prefix < sizeof(diagnostic)) &&
               result.subcommand_count == 0);
        ASSERT(result_fields_stay_in_buffer(&result, buffer, prefix));
        if (prefix == 1) {
          ASSERT(result.deny_reason == NULL);
        } else {
          ASSERT(result.deny_reason != NULL);
          size_t length =
              prefix < sizeof(diagnostic) ? prefix - 1 : sizeof(diagnostic) - 1;
          ASSERT(strlen(result.deny_reason) == length &&
                 memcmp(result.deny_reason, diagnostic, length) == 0);
        }
      }
    }

    /* A valid binary argument succeeds. Canonically empty/ambiguous pathname
     * results are shell setup failures, not callback failures. */
    static const struct expansion_view controls[] = {
        {NULL, 0}, {"0:,", 3}, {"1:a,1:b,", 8}};
    size_t control_count =
        source == 0 ? 1 : sizeof(controls) / sizeof(controls[0]);
    for (size_t control = 0; control < control_count; control++) {
      fixture.status = SHELL_EXPAND_RESOLVED;
      fixture.view = source == 0
                         ? (struct expansion_view){binary, sizeof(binary) - 1}
                         : controls[control];
      fixture.calls = 0;
      char *buffer = sg_test_eval_buffer_for_prefix(storage, 512);
      sg_result_t result = {0};
      sg_error_t error =
          sg_gate_evaluate(gate, sources[source].source, source_length, buffer,
                           workspace + 512, &result);
      if (source != 0) {
        /* A reached pathname the resolver cannot make usable certainly
         * fails: no dependency model. (An empty argv word stays valid, so
         * source 0 keeps SG_OK.) */
        ASSERT(error == SG_ERR_UNMODELED &&
               result.verdict == SG_VERDICT_REJECT);
        continue;
      }
      ASSERT(error == SG_OK);
      ASSERT(fixture.calls == 1 && !result.truncated &&
             result_fields_stay_in_buffer(&result, buffer, 512));
      if (source == 0) {
        static const char expected[] = "4:echo,3:a\0b,";
        ASSERT(result.verdict == SG_VERDICT_ALLOW &&
               result.subcommand_count == 1 &&
               result.subcommands[0].netargv_length == sizeof(expected) - 1 &&
               memcmp(result.subcommands[0].netargv, expected,
                      sizeof(expected) - 1) == 0);
      }
    }
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, NULL, NULL));
    free(storage);
  }
  sg_gate_free(gate);
}

typedef struct {
  const char *word;
  shell_expand_word_purpose_t purpose;
  shell_expand_status_t status;
  const char *netargv;
  size_t calls;
} expansion_rule_t;

typedef struct {
  expansion_rule_t *rules;
  size_t rule_count;
  size_t calls;
  bool valid;
  const char *expected_cwd;
  const char *expected_owner;
  const char *unexpected_word;
  size_t unexpected_word_length;
  shell_expand_word_purpose_t unexpected_purpose;
} expansion_contract_t;

static shell_expand_status_t
expand_by_source_word(const shell_expand_word_request_t *request,
                      const char **netargv, size_t *netargv_length,
                      void *context) {
  expansion_contract_t *contract = context;
  contract->calls++;
  contract->valid =
      contract->valid && request->word_offset <= request->source_length &&
      request->word_length <= request->source_length - request->word_offset &&
      request->owner_offset <= request->source_length &&
      request->owner_length <= request->source_length - request->owner_offset;
  if (contract->expected_cwd) {
    contract->valid = contract->valid && request->cwd_known &&
                      request->cwd_absolute && request->cwd != NULL &&
                      strcmp(request->cwd, contract->expected_cwd) == 0;
  }
  if (contract->expected_owner)
    contract->valid &=
        request->owner_length == strlen(contract->expected_owner) &&
        memcmp(request->source + request->owner_offset,
               contract->expected_owner, request->owner_length) == 0;

  const char *word = request->source + request->word_offset;
  for (size_t i = 0; i < contract->rule_count; i++) {
    expansion_rule_t *rule = &contract->rules[i];
    size_t length = strlen(rule->word);
    if (rule->purpose != request->purpose || length != request->word_length ||
        memcmp(rule->word, word, length) != 0)
      continue;
    rule->calls++;
    if (rule->status == SHELL_EXPAND_RESOLVED) {
      *netargv = rule->netargv;
      *netargv_length = strlen(rule->netargv);
    }
    return rule->status;
  }
  contract->valid = false;
  contract->unexpected_word = word;
  contract->unexpected_word_length = request->word_length;
  contract->unexpected_purpose = request->purpose;
  return SHELL_EXPAND_UNRESOLVED;
}

typedef struct {
  const char *cwd;
  bool absolute, valid;
  unsigned arguments, paths;
} tilde_cwd_contract_t;

TEST(expansion_operand_eligibility_contract) {
  expansion_rule_t rules[] = {
      {"\"$DATA\"", SHELL_EXPAND_WORD_ARGUMENT, SHELL_EXPAND_RESOLVED, "3:hit,",
       0},
      {"\"$ENVARG\"", SHELL_EXPAND_WORD_ARGUMENT, SHELL_EXPAND_RESOLVED,
       "3:hit,", 0},
      {"\"$WRAPPED\"", SHELL_EXPAND_WORD_ARGUMENT, SHELL_EXPAND_RESOLVED,
       "3:hit,", 0},
      {"\"$EXECARG\"", SHELL_EXPAND_WORD_ARGUMENT, SHELL_EXPAND_RESOLVED,
       "3:hit,", 0},
  };
  expansion_contract_t contract = {
      .rules = rules,
      .rule_count = sizeof(rules) / sizeof(rules[0]),
      .valid = true,
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, expand_by_source_word, &contract));
  static const char command[] =
      "\"$COMMAND\" \"$ARG\"; cd \"$DIR\"; printf '%s' \"$DATA\"; "
      "NAME=\"$VALUE\" echo \"$ENVARG\"; command echo \"$WRAPPED\"; "
      "exec echo \"$EXECARG\"";
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  if (!contract.valid || contract.calls != 4)
    printf("\n    eligibility callbacks: valid=%d calls=%zu "
           "rules=%zu/%zu/%zu/%zu "
           "unexpected=%.*s purpose=%d\n",
           contract.valid, contract.calls, rules[0].calls, rules[1].calls,
           rules[2].calls, rules[3].calls, (int)contract.unexpected_word_length,
           contract.unexpected_word ? contract.unexpected_word : "",
           contract.unexpected_purpose);
  ASSERT(contract.valid && contract.calls == 4);
  for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++)
    ASSERT(rules[i].calls == 1);
  if (result.subcommand_count != 6) {
    printf("\n    eligibility result commands=%u\n", result.subcommand_count);
    for (uint32_t i = 0; i < result.subcommand_count; i++)
      printf("      %u: %s\n", i, result.subcommands[i].display_command);
  }
  ASSERT(result.subcommand_count == 6);
  ASSERT_STR(result.subcommands[1].netargv, "2:cd,4:$DIR,");
  ASSERT_STR(result.subcommands[2].netargv, "6:printf,2:%s,3:hit,");
  ASSERT_STR(result.subcommands[3].netargv, "4:echo,3:hit,");
  ASSERT_STR(result.subcommands[4].netargv, "7:command,4:echo,3:hit,");
  ASSERT_STR(result.subcommands[5].netargv, "4:exec,4:echo,3:hit,");
  ASSERT((result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARGV) !=
         0);
  sg_gate_free(gate);
}

TEST(printf_expansion_control_contract) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  expansion_rule_t rule = {"\"$V\"", SHELL_EXPAND_WORD_ARGUMENT,
                           SHELL_EXPAND_RESOLVED, "2:\\c,", 0};
  expansion_contract_t contract = {
      .rules = &rule, .rule_count = 1, .valid = true};
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, expand_by_source_word, &contract));
  for (size_t i = 0; i < sizeof(shellsplit_test_printf_expansion_cases) /
                             sizeof(shellsplit_test_printf_expansion_cases[0]);
       i++) {
    const char *source = shellsplit_test_printf_expansion_cases[i].source;
    size_t queries = shellsplit_test_printf_expansion_cases[i].queries;
    contract.calls = rule.calls = 0;
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, source, &result));
    if (!contract.valid || contract.calls != queries)
      printf("\n    printf eligibility: %s queries=%zu expected=%zu\n", source,
             contract.calls, queries);
    ASSERT(contract.valid && contract.calls == queries &&
           rule.calls == queries && result.subcommand_count == 1);
    uint32_t flags = queries ? 0 : SG_EXPANSION_UNRESOLVED_ARGV;
    ASSERT(result.unresolved_expansion_flags == flags &&
           result.subcommands[0].unresolved_expansion_flags == flags);
  }
  /* Dynamic state control remains outside callback resolution. Do not publish
   * a resolution whose cached descriptor-mutation schedule cannot honor it. */
  contract.calls = rule.calls = 0;
  sg_result_t result = {0};
  ASSERT(eval_cmd(gate,
                  "exec {fd}>out; printf '%b%n' \"$V\" fd; echo >&\"$fd\"",
                  &result) == SG_ERR_PARSE);
  ASSERT(contract.valid && contract.calls == 0 && rule.calls == 0);
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  ASSERT(eval_cmd(gate,
                  "exec {fd}>out; printf <() '%b%n' <() \"$V\" fd; "
                  "echo >&\"$fd\"",
                  &result) == SG_ERR_PARSE);
  ASSERT(contract.valid && contract.calls == 0 && rule.calls == 0);
  ASSERT_SG_OK(eval_cmd(
      gate, "exec {fd}>out; printf '%b%n' '\\c' fd; echo >&\"$fd\"", &result));
  ASSERT(result.subcommand_count == 3 &&
         result.subcommands[2].write_count == 1 && contract.calls == 0);
  sg_gate_free(gate);
}

TEST(expansion_flags_stop_modes) {
  static const struct {
    sg_stop_mode_t mode;
    const char *first;
  } stops[] = {{SG_STOP_FIRST_FAIL, "echo missing"},
               {SG_STOP_FIRST_PASS, "echo ok"},
               {SG_STOP_FIRST_ALLOW, "echo ok"},
               {SG_STOP_FIRST_DENY, "echo denied"}};
  static const struct {
    const char *tail;
    uint32_t flags;
  } tails[] = {
      {"echo \"$DATA\"", SG_EXPANSION_UNRESOLVED_ARGV},
      {"echo >\"$OUT\"", SG_EXPANSION_UNRESOLVED_PATH},
      {"echo \"$DATA\" >\"$OUT\"",
       SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH},
      {"{ { echo \"$DATA\"; }; echo plain; } >\"$OUT\"",
       SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH},
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo ok", false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "echo denied", false));
  for (size_t si = 0; si < sizeof(stops) / sizeof(stops[0]); si++) {
    for (size_t ti = 0; ti < sizeof(tails) / sizeof(tails[0]); ti++) {
      char source[256];
      int length = snprintf(source, sizeof(source), "%s; %s", stops[si].first,
                            tails[ti].tail);
      ASSERT(length > 0 && (size_t)length < sizeof(source));
      ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
      shellsplit_test_source_scan_reset();
      sg_result_t full = {0};
      ASSERT_SG_OK(eval_cmd(gate, source, &full));
      ASSERT(!full.short_circuited && full.subcommand_count >= 2 &&
             full.unresolved_expansion_flags == tails[ti].flags &&
             full.subcommands[0].unresolved_expansion_flags == 0);
      ASSERT(full.subcommands[1].unresolved_expansion_flags == tails[ti].flags);
      if (ti == 3)
        ASSERT(full.subcommand_count == 3 &&
               full.subcommands[2].unresolved_expansion_flags ==
                   SG_EXPANSION_UNRESOLVED_PATH);
      size_t full_work =
          shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_GATE_EXPANSIONS);
      ASSERT_SG_OK(sg_gate_set_stop_mode(gate, stops[si].mode));
      sg_result_t stopped = {0};
      ASSERT_SG_OK(eval_cmd(gate, source, &stopped));
      ASSERT(stopped.short_circuited && stopped.subcommand_count == 1 &&
             stopped.unresolved_expansion_flags ==
                 full.unresolved_expansion_flags &&
             stopped.subcommands[0].unresolved_expansion_flags == 0 &&
             stopped.subcommands[0].verdict == full.subcommands[0].verdict);
      ASSERT(shellsplit_test_metadata_work(
                 SHELLSPLIT_TEST_WORK_GATE_EXPANSIONS) == 2 * full_work);
      shellsplit_test_source_scan_reset();
    }
  }
  sg_gate_free(gate);
}

typedef struct {
  shell_expand_status_t leaf_status;
  bool empty_redirect;
  bool empty_file_parent;
  bool valid;
  size_t leaf_calls;
  size_t calls;
} nested_path_expansion_t;

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    expand_nested_path(const shell_expand_word_request_t *request,
                       const char **netargv, size_t *length, void *context) {
  nested_path_expansion_t *state = context;
  state->calls++;
  state->valid &=
      request->word_offset <= request->source_length &&
      request->word_length <= request->source_length - request->word_offset &&
      request->owner_offset <= request->source_length &&
      request->owner_length <= request->source_length - request->owner_offset;
  static const char leaf[] = "\"$FILE\"";
  bool is_leaf = request->word_length == sizeof(leaf) - 1 &&
                 memcmp(request->source + request->word_offset, leaf,
                        sizeof(leaf) - 1) == 0;
  if (is_leaf) {
    state->leaf_calls++;
    state->valid &=
        request->purpose == SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH;
    if (state->leaf_status == SHELL_EXPAND_UNRESOLVED)
      return SHELL_EXPAND_UNRESOLVED;
  }
  bool empty = (state->empty_redirect &&
                request->purpose == SHELL_EXPAND_WORD_REDIRECT_PATH) ||
               (state->empty_file_parent && !is_leaf &&
                request->purpose == SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH);
  *netargv = empty ? "" : "8:/tmp/out,";
  *length = empty ? 0 : 11;
  return SHELL_EXPAND_RESOLVED;
}

TEST(nested_path_expansion_ownership) {
  static const struct {
    const char *source;
    unsigned commands;
    unsigned owners;
    unsigned leaves;
  } cases[] = {
      {"echo >\"$(<\"$FILE\")\"", 1, 1, 1},
      {"echo <\"$(<\"$FILE\")\"", 1, 1, 1},
      {"echo >>\"$(<\"$FILE\")\"", 1, 1, 1},
      {"echo <>\"$(<\"$FILE\")\"", 1, 1, 1},
      {"exec {fd}>\"$(<\"$FILE\")\"", 1, 1, 1},
      {"echo >\"$(<\"$(<\"$FILE\")\")\"", 1, 1, 1},
      {"echo \"$(<\"$FILE\")\"", 1, 1, 1},
      {"NAME=\"$(<\"$FILE\")\" echo", 1, 1, 1},
      {"{ echo one; echo two; } >\"$(<\"$FILE\")\"", 2, 3, 1},
      {"{ { echo one; }; echo two; } >\"$(<\"$FILE\")\"", 2, 3, 1},
      {"echo >\"$(<\"$FILE\")\"; echo plain", 2, 1, 1},
      {"echo \"$(echo >\"$(<\"$FILE\")\")\"", 2, 2, 1},
      {"echo > >(echo >\"$(<\"$FILE\")\") >out", 2, 2, 1},
      {"echo < <(echo >\"$(<\"$FILE\")\")", 2, 2, 1},
      {"echo ok; >\"$(<\"$FILE\")\"", 1, 0, 1},
      {"false && echo >\"$(<\"$FILE\")\"", 2, 0, 0},
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    for (unsigned resolved = 0; resolved < 2; resolved++) {
      nested_path_expansion_t state = {.leaf_status =
                                           resolved ? SHELL_EXPAND_RESOLVED
                                                    : SHELL_EXPAND_UNRESOLVED,
                                       .valid = true};
      ASSERT_SG_OK(
          sg_gate_set_expand_word_netargv(gate, expand_nested_path, &state));
      sg_result_t result = {0};
      ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
      uint32_t expected =
          !resolved && cases[i].leaves ? SG_EXPANSION_UNRESOLVED_PATH : 0;
      if (result.unresolved_expansion_flags != expected)
        printf("\n    nested path case %zu: flags=%u expected=%u\n", i,
               result.unresolved_expansion_flags, expected);
      ASSERT(state.valid && state.leaf_calls == cases[i].leaves &&
             result.subcommand_count == cases[i].commands &&
             result.unresolved_expansion_flags == expected);
      for (unsigned ci = 0; ci < cases[i].commands; ci++) {
        uint32_t owner_flag = !resolved && (cases[i].owners & (1u << ci))
                                  ? SG_EXPANSION_UNRESOLVED_PATH
                                  : 0;
        ASSERT(result.subcommands[ci].unresolved_expansion_flags == owner_flag);
      }
    }
  }
  /* A known failed open does not undo nested pathname expansions already
   * reached while producing that operand: the resolver still runs for the
   * inner path (leaf_calls proves reachability). But a reached empty
   * pathname certainly fails, so there is no dependency model. */
  for (unsigned failed_parent = 0; failed_parent < 2; failed_parent++) {
    nested_path_expansion_t state = {.leaf_status = SHELL_EXPAND_UNRESOLVED,
                                     .empty_redirect = !failed_parent,
                                     .empty_file_parent = failed_parent,
                                     .valid = true};
    ASSERT_SG_OK(
        sg_gate_set_expand_word_netargv(gate, expand_nested_path, &state));
    sg_result_t result = {0};
    ASSERT(eval_cmd(gate, "echo >\"$(<\"$(<\"$FILE\")\")\"", &result) ==
               SG_ERR_UNMODELED &&
           result.verdict == SG_VERDICT_REJECT);
    ASSERT(state.valid && state.leaf_calls == 1);
  }
  sg_gate_free(gate);
}

typedef struct {
  const char *path_record;
  size_t path_length;
  unsigned argument_calls;
  bool cwd_valid;
} substitution_status_fixture_t;

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    expand_substitution_status(const shell_expand_word_request_t *request,
                               const char **netargv, size_t *length,
                               void *context) {
  substitution_status_fixture_t *fixture = context;
  const char *word = request->source + request->word_offset;
  if (request->word_length == 6 && memcmp(word, "\"$ARG\"", 6) == 0) {
    fixture->argument_calls++;
    fixture->cwd_valid &= request->cwd_known && request->cwd_absolute &&
                          strcmp(request->cwd, "/workspace") == 0;
    *netargv = "3:hit,";
    *length = 6;
    return SHELL_EXPAND_RESOLVED;
  }
  if (request->word_length == 7 && memcmp(word, "\"$PATH\"", 7) == 0) {
    *netargv = fixture->path_record;
    *length = fixture->path_length;
    return SHELL_EXPAND_RESOLVED;
  }
  return SHELL_EXPAND_UNRESOLVED;
}

TEST(substitution_status_callback_reachability) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/workspace"));
  substitution_status_fixture_t fixture = {.cwd_valid = true};
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_substitution_status,
                                               &fixture));
  for (size_t i = 0;
       i < sizeof(shellsplit_test_substitution_status_cases) /
               sizeof(shellsplit_test_substitution_status_cases[0]);
       i++) {
    for (unsigned success = 0; success < 2; success++) {
      char source[512];
      int length =
          snprintf(source, sizeof(source), "%s %s echo \"$ARG\" >/etc/reached",
                   shellsplit_test_substitution_status_cases[i].source,
                   success ? "&&" : "||");
      ASSERT(length > 0 && (size_t)length < sizeof(source));
      fixture.argument_calls = 0;
      sg_result_t result = {0};
      if (shellsplit_test_substitution_status_cases[i].unmodeled) {
        ASSERT(eval_cmd(gate, source, &result) == SG_ERR_UNMODELED &&
               result.verdict == SG_VERDICT_REJECT);
        continue;
      }
      ASSERT_SG_OK(eval_cmd(gate, source, &result));
      bool expected =
          success ? shellsplit_test_substitution_status_cases[i].succeeds
                  : shellsplit_test_substitution_status_cases[i].fails;
      if (fixture.argument_calls != (unsigned)expected)
        printf("\n    status callback: %s calls=%u expected=%d\n", source,
               fixture.argument_calls, expected);
      ASSERT(fixture.argument_calls == (unsigned)expected && fixture.cwd_valid);
    }
  }
  fixture.path_record = "0:,";
  fixture.path_length = 3;
  static const char *controls[] = {
      "X=\"$(<\"\")\" && cd /etc; echo \"$ARG\"",
      "X=\"$(<\"$PATH\")\" && cd /etc; echo \"$ARG\"",
      "X=\"$(<\"$PATH\")\" || echo \"$ARG\"",
      "echo \"$(<\"$PATH\")\" \"$ARG\"",
      "X=\"$(false)\" <\"$PATH\" || echo \"$ARG\"",
      "X=\"$(false)\" <\"$PATH\" && cd /etc; echo \"$ARG\"",
      "X=\"$(false)\" {fd}>\"$PATH\" || echo \"$ARG\"",
      "3<<<\"${MAYBE:?}\" 0>&0 || echo \"$ARG\"",
  };
  for (size_t i = 0; i < sizeof(controls) / sizeof(controls[0]); i++) {
    fixture.argument_calls = 0;
    sg_result_t result = {0};
    if (i < 7) {
      /* Every file-substitution or redirect control reaches an empty
       * pathname: a certain failure with no dependency model. The
       * resolver still runs once for the reached word. */
      ASSERT(eval_cmd(gate, controls[i], &result) == SG_ERR_UNMODELED &&
             result.verdict == SG_VERDICT_REJECT);
      ASSERT(fixture.argument_calls == 1 && fixture.cwd_valid);
      continue;
    }
    /* A here-string whose expansion may abort (`${MAYBE:?}`) has no
     * pathname to resolve; that possible abort is modeled control flow. */
    ASSERT_SG_OK(eval_cmd(gate, controls[i], &result));
    ASSERT(fixture.argument_calls == 1 && fixture.cwd_valid);
  }
  sg_gate_free(gate);
}

typedef struct {
  const char *value;
  unsigned calls;
} file_diagnostic_fixture_t;

TEST(static_empty_path_callback_reachability) {
  static const struct {
    const char *source;
    size_t argument_calls, tail_calls;
  } cases[] = {
      {"echo \"$ARG\" >\"\" >\"$LATER\"", 1, 0},
      {"{ echo \"$ARG\"; } >\"\" >\"$LATER\"", 0, 0},
      {"false && { echo \"$ARG\"; } >\"\"; echo \"$TAIL\"", 0, 1},
      {"echo >\"\" || echo \"$TAIL\"", 0, 1},
      {"echo >\"\" && echo \"$TAIL\"", 0, 0},
      {"! { echo \"$ARG\"; } >\"\" || echo \"$TAIL\"", 0, 1},
      {"echo \"$(<\"\")\" \"$TAIL\"", 0, 1},
      {"{ echo \"$ARG\"; } >\"$BEFORE\" >\"\" >\"$LATER\"", 0, 0},
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    expansion_rule_t rules[] = {
        {"\"$ARG\"", SHELL_EXPAND_WORD_ARGUMENT, SHELL_EXPAND_RESOLVED,
         "3:hit,", 0},
        {"\"$TAIL\"", SHELL_EXPAND_WORD_ARGUMENT, SHELL_EXPAND_RESOLVED,
         "4:tail,", 0},
        {"\"$LATER\"", SHELL_EXPAND_WORD_REDIRECT_PATH, SHELL_EXPAND_FAILED,
         NULL, 0},
        {"\"$(<\"\")\"", SHELL_EXPAND_WORD_ARGUMENT, SHELL_EXPAND_UNRESOLVED,
         NULL, 0},
        {"\"$BEFORE\"", SHELL_EXPAND_WORD_REDIRECT_PATH, SHELL_EXPAND_RESOLVED,
         "11:/tmp/before,", 0},
    };
    expansion_contract_t contract = {.rules = rules,
                                     .rule_count =
                                         sizeof(rules) / sizeof(rules[0]),
                                     .valid = true};
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_by_source_word,
                                                 &contract));
    sg_result_t result = {0};
    if (i == 2) {
      /* `false &&` short-circuits before the empty redirect is reached. */
      ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    } else {
      /* A literal empty redirect certainly fails: no dependency model. The
       * argument callbacks reached before it still run, and later redirect
       * words stay suppressed (call counts below verify both). */
      ASSERT(eval_cmd(gate, cases[i].source, &result) == SG_ERR_UNMODELED &&
             result.verdict == SG_VERDICT_REJECT);
    }
    ASSERT(contract.valid && rules[0].calls == cases[i].argument_calls &&
           rules[1].calls == cases[i].tail_calls && rules[2].calls == 0);
    ASSERT(rules[3].calls == (i == 6) && rules[4].calls == (i == 7));
  }
  sg_gate_free(gate);
}

TEST(resolved_named_redirect_failure_effects) {
  static const struct {
    const char *source;
    unsigned writes;
    bool sensitive;
  } cases[] = {
      {"exec {fd}>\"$FAIL\"", 0, false},
      {"true {fd}<>\"$FAIL\"", 0, false},
      {"echo >\"$FAIL\" {fd}>/etc/later", 0, false},
      {"{ echo hi; } >\"$FAIL\" {fd}>/etc/later", 0, false},
      {"true {fd}>/etc/kept >\"$FAIL\"; echo >&\"$fd\"", 2, true},
      {"exec {fd}>/etc/kept >\"$FAIL\"; echo >&\"$fd\"", 2, true},
      {"true {fd}>\"$FAIL\" && echo >/etc/later", 0, false},
      {"true {fd}>\"$FAIL\" || echo >/etc/later", 1, true},
  };
  static const char *failures[] = {"", "0:,", "1:a,1:b,"};
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  for (size_t failure = 0; failure < sizeof(failures) / sizeof(failures[0]);
       failure++) {
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      expansion_rule_t rule = {"\"$FAIL\"", SHELL_EXPAND_WORD_REDIRECT_PATH,
                               SHELL_EXPAND_RESOLVED, failures[failure], 0};
      expansion_contract_t contract = {
          .rules = &rule, .rule_count = 1, .valid = true};
      ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_by_source_word,
                                                   &contract));
      sg_result_t result = {0};
      /* None of the mock views resolves to a single usable pathname
       * (empty, empty payload, or multi-segment): every reached redirect
       * certainly fails, so there is no dependency model. The resolver
       * still runs once for the failing word, and no write is reported. */
      ASSERT(eval_cmd(gate, cases[i].source, &result) == SG_ERR_UNMODELED &&
             result.verdict == SG_VERDICT_REJECT);
      unsigned writes = 0;
      for (uint32_t command = 0; command < result.subcommand_count; command++)
        writes += result.subcommands[command].write_count;
      ASSERT(contract.valid && rule.calls == 1 && writes == 0);
    }
  }
  sg_gate_free(gate);
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
      if (test_policy_replace_cpl(g, false, suggestion_buf, false) != ST_OK) {
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
  ASSERT_EQ_UINT(test_anomaly_vocabulary(g), 0);

  /* Enabling starts a fresh model that learns the evaluated sequence. */
  sg_error_t err = sg_gate_enable_anomaly(g, 5.0, NULL);
  ASSERT(err == SG_OK);
  ASSERT(!sg_gate_anomaly_had_error(g));
  ASSERT_SG_OK(eval_cmd(g, sequence, &r));
  ASSERT(isinf(r.anomaly_score));
  ASSERT(r.anomaly_detected == false);
  ASSERT_EQ_UINT(test_anomaly_vocabulary(g), 3);

  /* Disabling drops the model and restores inert anomaly results. */
  sg_gate_disable_anomaly(g);
  ASSERT(!sg_gate_anomaly_had_error(g));
  ASSERT_SG_OK(eval_cmd(g, sequence, &r));
  ASSERT(r.anomaly_score == 0.0);
  ASSERT(r.anomaly_detected == false);
  ASSERT_EQ_UINT(test_anomaly_vocabulary(g), 0);

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
    ASSERT(test_policy_replace_cpl(g, false, "allowed", false) == ST_OK);
    ASSERT(test_policy_replace_cpl(g, true, "denied", false) == ST_OK);

    sg_result_t result;
    ASSERT(eval_cmd(g, verdict_cases[i].command, &result) == SG_OK);
    ASSERT(result.verdict == verdict_cases[i].verdict);
    ASSERT_EQ_UINT(test_anomaly_vocabulary(g), verdict_cases[i].expected_vocab);
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
    ASSERT_EQ_UINT(test_anomaly_vocabulary(g), 3);
    ASSERT(eval_cmd(g, "novel1 ; novel2 ; novel3", &result) == SG_OK);
    ASSERT(result.anomaly_detected);
    ASSERT_EQ_UINT(test_anomaly_vocabulary(g), skip_anomalous[i] ? 3 : 6);
    sg_gate_free(g);
  }
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
  ASSERT_EQ_UINT(test_anomaly_vocabulary(g2), test_anomaly_vocabulary(g));

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
  ASSERT_EQ_UINT(test_anomaly_vocabulary(invalid), 4);

  /* Gate persistence intentionally rejects standalone single-model files. */
  sg_anomaly_model_t *legacy = sg_anomaly_model_new();
  ASSERT(legacy != NULL);
  const char legacy_seq[] = "3:one,3:two,5:three,";
  ASSERT(sg_anomaly_model_update_netseq(
             legacy, legacy_seq, sizeof(legacy_seq) - 1) == SG_ANOMALY_OK);
  ASSERT(sg_anomaly_model_save(legacy, path) == SG_ANOMALY_OK);
  sg_anomaly_model_free(legacy);
  ASSERT(sg_gate_load_anomaly_model(invalid, path) == SG_ERR_PARSE);
  ASSERT_EQ_UINT(test_anomaly_vocabulary(invalid), 4);

  char missing_path[256];
  snprintf(missing_path, sizeof(missing_path), "/tmp/shellgate_missing_%d",
           getpid());
  unlink(missing_path);
  ASSERT(sg_gate_load_anomaly_model(invalid, missing_path) == SG_ERR_IO);
  sg_gate_free(invalid);
  sg_gate_free(g2);
  sg_gate_free(g);
}

/* v7 permits the empty raw stage used for an argv-less redirect-only simple
 * command. Exercise it through Shellgate's paired-model bundle rather than
 * only through the lower-level anomaly model serializer. */
TEST(anomaly_bundle_roundtrip_retains_empty_stage) {
  static const char *training =
      "echo ok; >/tmp/shellgate-roundtrip-empty-stage; sort";
  static const char *probe =
      "echo next; >/tmp/shellgate-roundtrip-empty-stage; sort";
  sg_gate_t *source = sg_gate_new();
  sg_gate_t *loaded = sg_gate_new();
  ASSERT(source != NULL && loaded != NULL);
  sg_anomaly_config_t config;
  sg_anomaly_config_default(&config);
  config.alpha = DBL_MAX;
  ASSERT_SG_OK(sg_gate_enable_anomaly(source, 100.0, &config));
  ASSERT_SG_OK(sg_gate_enable_anomaly(loaded, 100.0, NULL));

  sg_result_t result = {0};
  for (size_t i = 0; i < 30; i++)
    ASSERT_SG_OK(eval_cmd(source, training, &result));
  ASSERT_EQ_UINT(test_anomaly_vocabulary(source), 3);

  shell_netstring_buffer_t raw = {0};
  shell_netstring_buffer_t typed = {0};
  size_t stage_count = 0;
  ASSERT(shell_build_anomaly_netseqs_buffer(probe, strlen(probe), NULL, &raw,
                                            &typed,
                                            &stage_count) == SHELL_PROCESS_OK);
  ASSERT(stage_count == 3);
  ASSERT((raw.length != sizeof("4:echo,0:,4:sort,") - 1 ||
          memcmp(raw.data, "4:echo,0:,4:sort,", raw.length)) == 0);

  sg_anomaly_sequence_score_t expected = {0};
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(
      source, (const char *)raw.data, raw.length, (const char *)typed.data,
      typed.length, &expected));
  ASSERT(expected.stage_count == 3 && isfinite(expected.raw_score) &&
         isfinite(expected.type_score) && isfinite(expected.combined_score));

  const char *path = temp_policy_file();
  ASSERT(path != NULL);
  ASSERT_SG_OK(sg_gate_save_anomaly_model(source, path));
  ASSERT_SG_OK(sg_gate_load_anomaly_model(loaded, path));
  ASSERT_EQ_UINT(test_anomaly_vocabulary(loaded),
                 test_anomaly_vocabulary(source));

  sg_anomaly_sequence_score_t actual = {0};
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(
      loaded, (const char *)raw.data, raw.length, (const char *)typed.data,
      typed.length, &actual));
  ASSERT(actual.stage_count == expected.stage_count);
  ASSERT(actual.raw_score == expected.raw_score);
  ASSERT(actual.type_score == expected.type_score);
  ASSERT(actual.combined_score == expected.combined_score);

  shell_netstring_buffer_free(&typed);
  shell_netstring_buffer_free(&raw);
  sg_gate_free(loaded);
  sg_gate_free(source);
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
  size_t preserved_vocab = test_anomaly_vocabulary(target);
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

  enum corruption {
    BAD_MAGIC,
    BAD_LENGTH,
    BAD_CHECKSUM,
    BAD_INNER_HEADER,
    TRUNCATED,
    TRAILING
  };
  static const enum corruption cases[] = {BAD_MAGIC,    BAD_LENGTH,
                                          BAD_CHECKSUM, BAD_INNER_HEADER,
                                          TRUNCATED,    TRAILING};
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
    case BAD_INNER_HEADER: {
      uint64_t raw_size = test_load_u64_le(data + 8);
      uint64_t type_size = test_load_u64_le(data + 16);
      ASSERT(raw_size <= (uint64_t)length - 32 &&
             type_size == (uint64_t)length - 32 - raw_size);
      static const unsigned char discount[] = {' ', '0', '.', '5', ' '};
      unsigned char *field = NULL;
      for (size_t offset = 32;
           offset + sizeof(discount) <= 32 + (size_t)raw_size; offset++) {
        if (memcmp(data + offset, discount, sizeof(discount)) == 0) {
          field = data + offset + 1;
          break;
        }
      }
      ASSERT(field != NULL);
      memcpy(field, "2.0", 3);
      test_store_u64_le(data + 24,
                        XXH3_64bits(data + 32, (size_t)(raw_size + type_size)));
      break;
    }
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
    ASSERT_EQ_UINT(test_anomaly_vocabulary(target), preserved_vocab);
  }

  file = fopen(path, "wb");
  ASSERT(file != NULL);
  ASSERT(fwrite(valid, 1, (size_t)length, file) == (size_t)length);
  ASSERT(fclose(file) == 0);
  ASSERT_SG_OK(sg_gate_load_anomaly_model(target, path));
  ASSERT_EQ_UINT(test_anomaly_vocabulary(target),
                 test_anomaly_vocabulary(source));
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
  size_t first_vocab = test_anomaly_vocabulary(first);
  size_t second_vocab = test_anomaly_vocabulary(second);
  ASSERT(first_vocab != second_vocab);

  sg_test_io_reset();
  ASSERT_SG_OK(sg_gate_save_anomaly_model(second, path));
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
    size_t loaded_vocab = test_anomaly_vocabulary(loaded);
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
  ASSERT_EQ_UINT(test_anomaly_vocabulary(preserved), second_vocab);
  sg_gate_free(preserved);
  sg_gate_free(second);
  sg_gate_free(first);
}

TEST(anomaly_bundle_stream_failure_matrix) {
  const char *path = temp_policy_file();
  ASSERT(path != NULL);
  sg_gate_t *source = sg_gate_new();
  sg_gate_t *target = sg_gate_new();
  sg_gate_t *control = sg_gate_new();
  sg_gate_t *probe = sg_gate_new();
  ASSERT(source && target && control && probe);
  sg_gate_t *gates[] = {source, target, control, probe};
  for (size_t i = 0; i < 4; i++) {
    ASSERT_SG_OK(sg_gate_enable_anomaly(gates[i], 100.0, NULL));
    ASSERT_SG_OK(sg_gate_set_anomaly_cache_size(gates[i], 4));
    ASSERT_SG_OK(sg_gate_set_anomaly_adaptive(gates[i], true, 4));
  }
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(source, "cat a; grep b; sort", &result));
  for (size_t i = 0; i < 5; i++) {
    ASSERT_SG_OK(eval_cmd(target, "one; two; three; four", &result));
    ASSERT_SG_OK(eval_cmd(control, "one; two; three; four", &result));
  }
  size_t preserved_vocab = test_anomaly_vocabulary(target);
  shell_netstring_buffer_t raw = {0};
  shell_netstring_buffer_t typed = {0};
  size_t stages = 0;
  const char *command = "one; two; three; four";
  ASSERT(shell_build_anomaly_netseqs_buffer(command, strlen(command), NULL,
                                            &raw, &typed,
                                            &stages) == SHELL_PROCESS_OK);
  sg_anomaly_sequence_score_t expected = {0};
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(
      target, (const char *)raw.data, raw.length, (const char *)typed.data,
      typed.length, &expected));
  ASSERT_SG_OK(sg_gate_save_anomaly_model(source, path));
  sg_test_io_reset();
  ASSERT_SG_OK(sg_gate_load_anomaly_model(probe, path));
  size_t operations = sg_test_io_count();
  sg_test_io_reset();
  /* Includes both temporary streams, staging, EOF probe and inner readers;
   * unlike saving, loading does not create its temporary streams first. */
  ASSERT(operations > 12);
  static const int errors[] = {EIO, ENOMEM, EINVAL, EPROTO};
  for (size_t error = 0; error < sizeof(errors) / sizeof(errors[0]); error++) {
    for (size_t operation = 1; operation <= operations; operation++) {
      sg_test_io_fail_at_with_errno(operation, errors[error]);
      sg_error_t actual = sg_gate_load_anomaly_model(target, path);
      sg_test_io_reset();
      ASSERT(actual == (errors[error] == ENOMEM ? SG_ERR_MEMORY : SG_ERR_IO));
      ASSERT_EQ_UINT(test_anomaly_vocabulary(target), preserved_vocab);
      sg_anomaly_sequence_score_t score = {0};
      ASSERT_SG_OK(sg_gate_score_anomaly_netseq(
          target, (const char *)raw.data, raw.length, (const char *)typed.data,
          typed.length, &score));
      ASSERT(score.raw_score == expected.raw_score &&
             score.type_score == expected.type_score &&
             score.combined_score == expected.combined_score &&
             score.detected == expected.detected &&
             score.stage_count == stages);
    }
  }
  /* A normal cached evaluation after every failed load must agree with an
   * untouched gate, including adaptive detection and learning progression. */
  sg_result_t expected_result = {0};
  ASSERT_SG_OK(eval_cmd(control, command, &expected_result));
  double raw_score = expected_result.anomaly_score_raw;
  double type_score = expected_result.anomaly_score_type;
  double combined = expected_result.anomaly_score;
  bool detected = expected_result.anomaly_detected;
  sg_anomaly_update_t update = expected_result.anomaly_update;
  ASSERT_SG_OK(eval_cmd(target, command, &result));
  ASSERT(result.anomaly_score_raw == raw_score &&
         result.anomaly_score_type == type_score &&
         result.anomaly_score == combined &&
         result.anomaly_detected == detected &&
         result.anomaly_update == update);
  ASSERT_EQ_UINT(test_anomaly_vocabulary(target),
                 test_anomaly_vocabulary(control));
  ASSERT_SG_OK(sg_gate_load_anomaly_model(target, path));
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(
      source, (const char *)raw.data, raw.length, (const char *)typed.data,
      typed.length, &expected));
  sg_anomaly_sequence_score_t score = {0};
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(
      target, (const char *)raw.data, raw.length, (const char *)typed.data,
      typed.length, &score));
  ASSERT(score.raw_score == expected.raw_score &&
         score.type_score == expected.type_score);
  shell_netstring_buffer_free(&raw);
  shell_netstring_buffer_free(&typed);
  for (size_t i = 0; i < 4; i++)
    sg_gate_free(gates[i]);
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
    ASSERT_EQ_UINT(test_anomaly_vocabulary(gate), 0);
    sg_gate_free(gate);
  }

  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));
  ASSERT_SG_OK(eval_cmd(gate, "gcc ; make ; test", &result));
  size_t preserved_vocab = test_anomaly_vocabulary(gate);
  sg_test_alloc_fail_at(1);
  ASSERT(sg_gate_enable_anomaly(gate, 5.0, NULL) == SG_ERR_MEMORY);
  sg_test_alloc_reset();
  ASSERT_EQ_UINT(test_anomaly_vocabulary(gate), preserved_vocab);
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

TEST(anomaly_netseq_score_contract) {
  static const char *training = "cat /etc/hosts ; grep root ; sort";
  static const char *probe = "cat /tmp/x ; grep error ; sort";
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  sg_anomaly_sequence_score_t score = {0};
  ASSERT(sg_gate_score_anomaly_netseq(gate, "1:x,", 4, "1:y,", 4, &score) ==
         SG_ERR_INVALID);
  ASSERT(score.stage_count == 0 && !score.detected && isinf(score.raw_score) &&
         isinf(score.type_score) && isinf(score.combined_score));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));
  const double untrained_weights[][2] = {{0.5, 0.5}, {1.0, 0.0}, {0.0, 1.0}};
  for (size_t i = 0;
       i < sizeof(untrained_weights) / sizeof(untrained_weights[0]); i++) {
    ASSERT_SG_OK(sg_gate_set_anomaly_weights(gate, untrained_weights[i][0],
                                             untrained_weights[i][1]));
    ASSERT_SG_OK(sg_gate_score_anomaly_netseq(gate, "1:a,1:b,1:c,", 12,
                                              "1:x,1:y,1:z,", 12, &score));
    ASSERT(score.stage_count == 3 && !score.detected &&
           isinf(score.raw_score) && isinf(score.type_score) &&
           isinf(score.combined_score));
  }
  ASSERT_SG_OK(sg_gate_set_anomaly_weights(gate, 0.5, 0.5));
  sg_result_t result;
  for (int i = 0; i < 8; i++)
    ASSERT_SG_OK(eval_cmd(gate, training, &result));
  ASSERT_SG_OK(sg_gate_set_anomaly_update_mode(gate, true));
  ASSERT_SG_OK(eval_cmd(gate, probe, &result));

  shell_netstring_buffer_t raw = {0};
  shell_netstring_buffer_t type = {0};
  size_t raw_count = 0, type_count = 0;
  ASSERT(shell_build_command_netseq_buffer(probe, strlen(probe), NULL, &raw,
                                           &raw_count) == SHELL_PROCESS_OK);
  ASSERT(shell_build_type_netseq_buffer(probe, strlen(probe), NULL, &type,
                                        &type_count) == SHELL_PROCESS_OK);
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(gate, (const char *)raw.data,
                                            raw.length, (const char *)type.data,
                                            type.length, &score));
  ASSERT(score.stage_count == raw_count && raw_count == type_count);
  ASSERT(score.raw_score == result.anomaly_score_raw);
  ASSERT(score.type_score == result.anomaly_score_type);
  ASSERT(score.combined_score == result.anomaly_score);
  ASSERT(score.detected == result.anomaly_detected);
  ASSERT(sg_gate_score_anomaly_netseq(gate, (const char *)raw.data, raw.length,
                                      "4:cat,", 6, &score) == SG_ERR_PARSE);
  ASSERT(score.stage_count == 0 && !score.detected && isinf(score.raw_score) &&
         isinf(score.type_score) && isinf(score.combined_score));
  ASSERT(sg_gate_score_anomaly_netseq(gate, (const char *)raw.data, raw.length,
                                      "1:x,tail", 8, &score) == SG_ERR_PARSE);
  ASSERT(score.stage_count == 0 && !score.detected && isinf(score.raw_score) &&
         isinf(score.type_score) && isinf(score.combined_score));

  ASSERT(sg_gate_score_anomaly_netseq(gate, "1:x,tail", 8,
                                      (const char *)type.data, type.length,
                                      &score) == SG_ERR_PARSE);
  ASSERT(score.stage_count == 0 && !score.detected && isinf(score.raw_score) &&
         isinf(score.type_score) && isinf(score.combined_score));
  ASSERT_SG_OK(
      sg_gate_score_anomaly_netseq(gate, "1:x,", 4, "1:y,", 4, &score));
  ASSERT(score.stage_count == 1 && !score.detected && score.raw_score == 0.0 &&
         score.type_score == 0.0 && score.combined_score == 0.0);
  shell_netstring_buffer_free(&raw);
  shell_netstring_buffer_free(&type);
  sg_gate_free(gate);
}

TEST(anomaly_configuration_validation) {

  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);
  static const struct {
    double threshold;
    double alpha;
  } invalid_enable[] = {
      {NAN, 0.1},  {INFINITY, 0.1}, {5.0, 0.0},
      {5.0, -0.1}, {5.0, NAN},      {5.0, INFINITY},
  };
  for (size_t i = 0; i < sizeof(invalid_enable) / sizeof(invalid_enable[0]);
       i++) {
    sg_anomaly_config_t config = {
        .alpha = invalid_enable[i].alpha,
    };
    ASSERT(sg_gate_enable_anomaly(g, invalid_enable[i].threshold, &config) ==
           SG_ERR_INVALID);
  }

  ASSERT(sg_gate_enable_anomaly(g, 100.0, NULL) == SG_OK);
  sg_result_t result;
  ASSERT(eval_cmd(g, "one ; two ; three", &result) == SG_OK);
  size_t preserved_vocab = test_anomaly_vocabulary(g);
  ASSERT(preserved_vocab == 3);
  sg_anomaly_config_t invalid_config = {
      .alpha = 0.0,
  };
  ASSERT(sg_gate_enable_anomaly(g, 5.0, &invalid_config) == SG_ERR_INVALID);
  ASSERT_EQ_UINT(test_anomaly_vocabulary(g), preserved_vocab);

  sg_anomaly_config_t custom_config = {
      .alpha = 0.25,
  };
  ASSERT_SG_OK(sg_gate_enable_anomaly(g, 5.0, &custom_config));

  ASSERT(sg_gate_set_anomaly_weights(g, -0.1, 1.1) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_weights(g, 0.5, -0.1) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_weights(g, 0.2, 0.2) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_weights(g, 0.6, 0.6) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_weights(g, NAN, NAN) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_weights(g, INFINITY, 0.0) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_weights(g, 0.0, NAN) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_anomaly_weights(g, 0.0, INFINITY) == SG_ERR_INVALID);
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
  ASSERT(test_policy_replace_cpl(g, false, "ls", false) == ST_OK);
  ASSERT(test_policy_replace_cpl(g, false, "cat *", false) == ST_OK);
  ASSERT(test_policy_replace_cpl(g, false, "pwd", false) == ST_OK);

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
    ASSERT_EQ_UINT(test_anomaly_vocabulary(cached),
                   test_anomaly_vocabulary(control));
  }

  ASSERT(test_anomaly_vocabulary(cached) > 0);
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

TEST(contextual_read_anomaly_contract) {
  static const struct {
    const char *source;
    sg_verdict_t verdict;
  } commands[] = {
      {"exec {out}>&1 && { unset empty; read -n0 other\"$empty\"; "
       "printf kept >&\"$out\"; }",
       SG_VERDICT_ALLOW},
      {"exec {fd}<<<payload && read -n-\"$fd\" value", SG_VERDICT_REJECT},
      {"exec {fd}<<<payload && read -n-1\"$fd\" value", SG_VERDICT_REJECT},
      {"exec {fd}<<<payload && read -n-00\"$fd\" value", SG_VERDICT_REJECT},
      {"exec {fd}<<<payload && read -u00\"$fd\" value", SG_VERDICT_ALLOW},
      {"unset fd; read -u0\"$fd\" value <<<payload", SG_VERDICT_ALLOW},
      {"read -u-1\"$unknown\" value <<<payload", SG_VERDICT_REJECT},
      {"read -n\"$unknown\"x value <<<payload", SG_VERDICT_REJECT},
      {"read -- pre\"$unknown\"- value <<<payload", SG_VERDICT_REJECT},
      {"unset fd; read -p\"$fd\" -e value <<<payload", SG_VERDICT_ALLOW},
      {"unset fd; echo \"$(read -p\"$fd\" -e value <<<payload)\"",
       SG_VERDICT_ALLOW},
      {"unset RANDOM; echo \"$(read -r RANDOM <<<payload)\"", SG_VERDICT_ALLOW},
      {"unset RANDOM; echo <(read -r RANDOM <<<payload)", SG_VERDICT_ALLOW},
      {"unset RANDOM; echo \"$(read -p\"$RANDOM\" -e value <<<payload)\"",
       SG_VERDICT_ALLOW},
      {"unset fd; read -n\"$fd\" -a value <<<payload", SG_VERDICT_REJECT},
      {"read -t0.0000000\"$unknown\" value <<<payload", SG_VERDICT_ALLOW},
      {"unset empty; read -- $empty~ value <<<payload", SG_VERDICT_REJECT},
      {"read -- pre<(printf generated) value <<<payload", SG_VERDICT_REJECT},
      {"unset empty; read -- -p\"$empty\" RANDOM <<<payload",
       SG_VERDICT_REJECT},
      {"exec {out}>&1 && { unset empty; read -- -p\"$empty\" out "
       "<<<payload; printf kept >&\"$out\"; }",
       SG_VERDICT_REJECT},
      {"exec {fd}<<<payload && read -p\"$fd\" -u \"$fd\" value",
       SG_VERDICT_ALLOW},
      {"exec {fd}<<<payload && read -d\"$fd\" -u${fd} value", SG_VERDICT_ALLOW},
      {"exec {fd}<<<payload && read -n\"$fd\" -u $fd value", SG_VERDICT_ALLOW},
      {"exec {fd}<<<payload && { read -p\"$fd\" -u \"$fd\" value; }",
       SG_VERDICT_ALLOW},
      {"exec {fd}<<<payload && echo \"$(read -p\"$fd\" -u \"$fd\" value)\"",
       SG_VERDICT_ALLOW},
      {"exec {fd}<<<payload && echo <(read -p\"$fd\" -u \"$fd\" value)",
       SG_VERDICT_ALLOW},
  };
  static const char *const rules[] = {"exec",         "read * *", "read * * *",
                                      "read * * * *", "echo *",   "unset *",
                                      "printf *"};
  size_t rule_count = sizeof(rules) / sizeof(rules[0]);
  sg_gate_t *plain = gate_with_rules(rules, rule_count);
  sg_gate_t *cached = gate_with_rules(rules, rule_count);
  sg_gate_t *uncached = gate_with_rules(rules, rule_count);
  ASSERT(plain && cached && uncached);
  sg_gate_t *gates[] = {plain, cached, uncached};
  for (size_t g = 0; g < 3; g++) {
    ASSERT_SG_OK(sg_gate_set_reject_mask(gates[g], 0));
    ASSERT_SG_OK(sg_gate_set_stop_mode(gates[g], SG_EVAL_ALL));
    if (g) {
      ASSERT_SG_OK(sg_gate_enable_anomaly(gates[g], 1e300, NULL));
      ASSERT_SG_OK(sg_gate_set_anomaly_cache_size(gates[g], g == 1 ? 16 : 0));
    }
  }
  /* A REJECT row's read reports an error, or has an operand the graph
   * cannot prove valid: it has no dependency model (SG_ERR_UNMODELED), and
   * cached evaluation must reject it identically. */
  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    sg_result_t baseline;
    sg_error_t expected =
        commands[i].verdict == SG_VERDICT_REJECT ? SG_ERR_UNMODELED : SG_OK;
    shellsplit_test_source_scan_reset();
    ASSERT(eval_cmd(plain, commands[i].source, &baseline) == expected);
    if (expected != SG_OK) {
      /* An error result defines only its verdict; every gate agrees. */
      ASSERT(baseline.verdict == SG_VERDICT_REJECT);
      for (size_t g = 1; g < 3; g++) {
        sg_result_t result;
        ASSERT(eval_cmd(gates[g], commands[i].source, &result) == expected);
        ASSERT(result.verdict == SG_VERDICT_REJECT);
      }
      continue;
    }
    size_t baseline_semantics =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_SEMANTIC_BODIES);
    if (baseline.verdict != commands[i].verdict) {
      fprintf(stderr, "contextual read policy fixture: %s (verdict %d)\n",
              commands[i].source, baseline.verdict);
      for (size_t c = 0; c < baseline.subcommand_count; c++)
        fprintf(stderr, "  command %zu: %s (verdict %d)\n", c,
                baseline.subcommands[c].netargv,
                baseline.subcommands[c].verdict);
    }
    ASSERT(baseline.verdict == commands[i].verdict);
    char baseline_args[4][256];
    ASSERT(baseline.subcommand_count <= 4);
    for (size_t c = 0; c < baseline.subcommand_count; c++) {
      ASSERT(baseline.subcommands[c].netargv_length <=
             sizeof(baseline_args[c]));
      memcpy(baseline_args[c], baseline.subcommands[c].netargv,
             baseline.subcommands[c].netargv_length);
    }
    for (unsigned repeat = 0; repeat < 2; repeat++) {
      sg_result_t results[2];
      for (size_t g = 0; g < 2; g++) {
        shellsplit_test_source_scan_reset();
        ASSERT(eval_cmd(gates[g + 1], commands[i].source, &results[g]) ==
               expected);
        size_t work =
            shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_SEMANTIC_BODIES);
        ASSERT(work == baseline_semantics);
        ASSERT(shellsplit_test_metadata_work(
                   SHELLSPLIT_TEST_WORK_PROCESS_STRICT_PARSE) == 0);
        ASSERT(results[g].verdict == baseline.verdict);
        ASSERT(results[g].subcommand_count == baseline.subcommand_count);
        ASSERT(results[g].unresolved_expansion_flags ==
               baseline.unresolved_expansion_flags);
        for (size_t c = 0; c < baseline.subcommand_count; c++) {
          ASSERT(results[g].subcommands[c].netargv_length ==
                 baseline.subcommands[c].netargv_length);
          ASSERT(memcmp(results[g].subcommands[c].netargv, baseline_args[c],
                        baseline.subcommands[c].netargv_length) == 0);
        }
        /* A cold model has no trigrams for the first multi-command fixture.
         * The repeat must be finite after both models learn that sequence. */
        ASSERT(!isnan(results[g].anomaly_score));
        if (repeat)
          ASSERT(isfinite(results[g].anomaly_score));
      }
      assert_anomaly_results_equal(&results[0], &results[1]);
      ASSERT(test_anomaly_vocabulary(cached) ==
             test_anomaly_vocabulary(uncached));
    }
  }
  static const char *const rejected[] = {
      "read -p\"$prompt\" -u \"$fd\" value",
      "exec {fd}<<<payload && read -p\"$fd\" -u \"$fd\" -e value",
      "exec {fd}<<<payload && read -p\"$fd\" -u \"$fd\" -a values",
      "exec {fd}<<<payload && read -p\"$fd\" -u \"${fd:-3}\" value",
      "exec {fd}<<<payload && read -p\"$fd\" -u \"$fd\" value |",
  };
  for (size_t g = 0; g < 3; g++) {
    size_t vocabulary = test_anomaly_vocabulary(gates[g]);
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
      sg_result_t result;
      ASSERT(eval_cmd(gates[g], rejected[i], &result) == SG_ERR_PARSE);
      ASSERT(result.verdict == SG_VERDICT_REJECT);
      ASSERT(test_anomaly_vocabulary(gates[g]) == vocabulary);
    }
    sg_gate_free(gates[g]);
  }
}

TEST(contextual_read_anomaly_allocation_failures) {
  static const char command[] =
      "exec {fd}<<<payload && read -p\"$fd\" -u \"$fd\" value";
  for (unsigned warm = 0; warm < 2; warm++) {
    sg_gate_t *probe = anomaly_gate_with_cache(1);
    ASSERT(probe != NULL);
    ASSERT_SG_OK(sg_gate_set_reject_mask(probe, 0));
    sg_result_t result;
    if (warm)
      ASSERT_SG_OK(eval_cmd(probe, command, &result));
    shellsplit_test_alloc_reset();
    ASSERT_SG_OK(eval_cmd(probe, command, &result));
    size_t allocations = shellsplit_test_alloc_count();
    shellsplit_test_alloc_reset();
    ASSERT(allocations != 0);
    sg_gate_free(probe);
    for (size_t fail = 1; fail <= allocations; fail++) {
      sg_gate_t *gate = anomaly_gate_with_cache(1);
      ASSERT(gate != NULL);
      ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
      if (warm)
        ASSERT_SG_OK(eval_cmd(gate, command, &result));
      size_t vocabulary = test_anomaly_vocabulary(gate);
      shellsplit_test_alloc_fail_at(fail);
      sg_error_t error = eval_cmd(gate, command, &result);
      shellsplit_test_alloc_reset();
      ASSERT(error == SG_ERR_MEMORY);
      ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
      ASSERT(test_anomaly_vocabulary(gate) == vocabulary);
      ASSERT_SG_OK(eval_cmd(gate, command, &result));
      sg_gate_free(gate);
    }
  }
}

TEST(truncated_graph_skips_anomaly_work) {
  sg_gate_t *gate = anomaly_gate_with_cache(4);
  ASSERT(gate != NULL);
  sg_result_t result;
  char source[512] = {0};
  for (unsigned graph_only = 0; graph_only < 2; graph_only++) {
    size_t length = 0;
    if (graph_only) {
      memcpy(source, "true", 4);
      length = 4;
      for (size_t i = 0; i < SHELL_DEP_MAX_TOKENS; i++) {
        memcpy(source + length, " x", 2);
        length += 2;
      }
      shell_parse_result_t fast;
      shell_limits_t limits = {.max_subcommands = 64, .strict_mode = true};
      ASSERT(shell_parse_fast(source, length, &limits, &fast) == SHELL_OK);
    } else {
      for (size_t i = 0; i < 65; i++) {
        memcpy(source + length, "true;", 5);
        length += 5;
      }
    }
    source[length] = '\0';
    for (unsigned repeat = 0; repeat < 2; repeat++) {
      shellsplit_test_source_scan_reset();
      ASSERT(eval_cmd(gate, source, &result) == SG_ERR_TRUNC);
      ASSERT(result.verdict == SG_VERDICT_UNDETERMINED && result.truncated &&
             result.subcommand_truncated && result.subcommand_count != 0);
      ASSERT(result.anomaly_score == 0 && !result.anomaly_detected);
      ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_NOT_ATTEMPTED);
      ASSERT(test_anomaly_vocabulary(gate) == 0);
      ASSERT(shellsplit_test_metadata_work(
                 SHELLSPLIT_TEST_WORK_ANOMALY_BODIES) == 0);
    }
  }
  ASSERT_SG_OK(eval_cmd(gate, "true", &result));
  ASSERT(test_anomaly_vocabulary(gate) == 1);
  sg_gate_free(gate);
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

TEST(anomaly_model_failure_verdict_contract) {
  static const char *command = "cat a ; grep b ; sort";
  sg_result_t result = {0};

  sg_gate_t *gate = anomaly_gate_with_cache(0);
  ASSERT(gate != NULL);
  sg_test_anomaly_score_fail_with(SG_ANOMALY_ERR_MEMORY);
  ASSERT(eval_cmd(gate, command, &result) == SG_ERR_MEMORY);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  sg_test_anomaly_result_reset();
  sg_gate_free(gate);

  gate = anomaly_gate_with_cache(0);
  ASSERT(gate != NULL);
  sg_test_anomaly_score_fail_with(SG_ANOMALY_ERR_FORMAT);
  ASSERT(eval_cmd(gate, command, &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  sg_test_anomaly_result_reset();
  sg_gate_free(gate);

  gate = anomaly_gate_with_cache(0);
  ASSERT(gate != NULL);
  sg_test_anomaly_update_fail_with(SG_ANOMALY_ERR_FORMAT);
  ASSERT(eval_cmd(gate, command, &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  sg_test_anomaly_result_reset();
  sg_gate_free(gate);
}

TEST(anomaly_update_outcome_contract) {
  static const char *command = "cat a ; grep b ; sort";
  sg_result_t result = {0};

  sg_gate_t *disabled = sg_gate_new();
  ASSERT(disabled != NULL);
  ASSERT_SG_OK(eval_cmd(disabled, command, &result));
  ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_NOT_ATTEMPTED);
  sg_gate_free(disabled);

  sg_gate_t *updated = anomaly_gate_with_cache(0);
  ASSERT(updated != NULL);
  ASSERT_SG_OK(eval_cmd(updated, command, &result));
  ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_APPLIED);
  sg_gate_free(updated);

  sg_gate_t *allow_only = anomaly_gate_with_cache(0);
  ASSERT(allow_only != NULL);
  ASSERT_SG_OK(sg_gate_set_anomaly_update_mode(allow_only, true));
  ASSERT_SG_OK(eval_cmd(allow_only, command, &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_SKIPPED_VERDICT);
  sg_gate_free(allow_only);

  char overlong[SG_ANOMALY_MAX_STAGE_LENGTH + 2];
  memset(overlong, 'x', sizeof(overlong) - 1);
  overlong[sizeof(overlong) - 1] = '\0';
  sg_gate_t *limited = anomaly_gate_with_cache(0);
  ASSERT(limited != NULL);
  ASSERT_SG_OK(eval_cmd(limited, overlong, &result));
  ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_REJECTED_LIMIT);
  sg_gate_free(limited);

  sg_gate_t *memory = anomaly_gate_with_cache(0);
  ASSERT(memory != NULL);
  sg_test_anomaly_update_fail_with(SG_ANOMALY_ERR_MEMORY);
  ASSERT_SG_OK(eval_cmd(memory, command, &result));
  ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_FAILED_MEMORY);
  sg_test_anomaly_result_reset();
  ASSERT(sg_gate_anomaly_had_error(memory));
  ASSERT_EQ_UINT(test_anomaly_vocabulary(memory), 0);
  ASSERT_SG_OK(eval_cmd(memory, command, &result));
  ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_APPLIED);
  ASSERT(test_anomaly_vocabulary(memory) > 0);
  ASSERT(sg_gate_anomaly_had_error(memory));
  sg_gate_free(memory);

  sg_gate_t *format = anomaly_gate_with_cache(0);
  ASSERT(format != NULL);
  sg_test_anomaly_update_fail_with(SG_ANOMALY_ERR_FORMAT);
  ASSERT(eval_cmd(format, command, &result) == SG_ERR_PARSE);
  ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_FAILED_FORMAT);
  sg_test_anomaly_result_reset();
  sg_gate_free(format);
}

/* --- SEPARATE SCORE TESTS --- */

/* --- BAYESIAN COMBINATION TESTS --- */

static const char *const calibration_commands[] = {
    "ls ; cat file.txt ; pwd",
    "cat file.txt ; grep pattern ; sort",
    "echo hello ; sleep 1 ; true",
    "cp a b ; mv b c ; rm c",
};

/* Freeze learning after training so calibration transitions can be compared
 * without replacing the score population under test. No allow rules means
 * update-only-on-allow skips learning but still collects normal history. */
static sg_gate_t *calibration_gate(size_t samples) {
  sg_gate_t *gate = sg_gate_new();
  if (!gate)
    return NULL;
  sg_result_t result;
  bool ok = sg_gate_enable_anomaly(gate, 100.0, NULL) == SG_OK;
  for (size_t i = 0; ok && i < samples; i++)
    ok = eval_cmd(gate, calibration_commands[i % 4], &result) == SG_OK;
  ok = ok && sg_gate_set_anomaly_update_mode(gate, true) == SG_OK;
  if (!ok) {
    sg_gate_free(gate);
    return NULL;
  }
  return gate;
}

static SHELL_NONNULL(1, 2, 3) bool calibration_score(
    sg_gate_t *gate, const char *source, sg_anomaly_sequence_score_t *out) {
  shell_netstring_buffer_t raw = {0}, type = {0};
  size_t count = 0;
  bool ok =
      shell_build_anomaly_netseqs_buffer(source, strlen(source), NULL, &raw,
                                         &type, &count) == SHELL_PROCESS_OK &&
      sg_gate_score_anomaly_netseq(gate, (const char *)raw.data, raw.length,
                                   (const char *)type.data, type.length,
                                   out) == SG_OK;
  shell_netstring_buffer_free(&type);
  shell_netstring_buffer_free(&raw);
  return ok;
}

typedef struct {
  sg_gate_t *source;
  char path[256];
  size_t size;
  size_t raw_size;
  long raw_alpha_offset;
  long type_alpha_offset;
} test_bundle_fixture_t;

/* A real serialized model, large enough that the type header remains unread
 * after the first payload chunk even with stdio read-ahead. Caller frees source
 * on success or failure and unlinks a nonempty path; fixture starts zeroed. */
static SHELL_NONNULL(1) bool test_bundle_fixture_create(
    test_bundle_fixture_t *fixture) {
  int fd = temp_fixture_file(fixture->path, sizeof(fixture->path),
                             "shellgate-bundle-snapshot");
  if (fd < 0) {
    fixture->path[0] = '\0';
    return false;
  }
  if (close(fd) != 0)
    return false;
  fixture->source = sg_gate_new();
  if (!fixture->source)
    return false;
  sg_anomaly_config_t config;
  sg_anomaly_config_default(&config);
  config.alpha = 0.25;
  bool ok = sg_gate_enable_anomaly(fixture->source, 100.0, &config) == SG_OK &&
            sg_gate_set_stop_mode(fixture->source, SG_EVAL_ALL) == SG_OK &&
            sg_gate_set_suggestions(fixture->source, false) == SG_OK;
  sg_result_t result;
  for (size_t batch = 0; ok && batch < 8; batch++) {
    char commands[1024];
    size_t used = 0;
    for (size_t command = 0; command < 32; command++) {
      int length = snprintf(commands + used, sizeof(commands) - used,
                            "%scorpus_stage_%03zu", command ? "; " : "",
                            batch * 32 + command);
      if (length < 0 || (size_t)length >= sizeof(commands) - used) {
        ok = false;
        break;
      }
      used += (size_t)length;
    }
    ok = ok && eval_cmd(fixture->source, commands, &result) == SG_OK;
  }
  ok =
      ok && sg_gate_save_anomaly_model(fixture->source, fixture->path) == SG_OK;
  if (!ok)
    return false;
  FILE *file = fopen(fixture->path, "rb");
  if (!file)
    return false;
  unsigned char header[32];
  ok = fread(header, 1, sizeof(header), file) == sizeof(header) &&
       fseek(file, 0, SEEK_END) == 0;
  long size = ok ? ftell(file) : -1;
  ok = ok && size > 32;
  if (ok) {
    fixture->size = (size_t)size;
    fixture->raw_size = (size_t)test_load_u64_le(header + 8);
    ok = fixture->raw_size > 16384 + BUFSIZ &&
         fixture->raw_size < fixture->size - 32;
  }
  for (unsigned model = 0; ok && model < 2; model++) {
    char line[128];
    long start = model ? (long)(32 + fixture->raw_size) : 32;
    ok = fseek(file, start, SEEK_SET) == 0 &&
         fgets(line, sizeof(line), file) != NULL;
    long numeric_header = ok ? ftell(file) : -1;
    ok = ok && numeric_header >= 0 && fgets(line, sizeof(line), file) != NULL &&
         strncmp(line, "# 0.25 ", 7) == 0;
    if (ok) {
      long *offset =
          model ? &fixture->type_alpha_offset : &fixture->raw_alpha_offset;
      *offset = numeric_header + 4; /* Change 0.25 to valid 0.75. */
    }
  }
  return fclose(file) == 0 && ok;
}

typedef enum {
  TEST_BUNDLE_CHANGE_STAGED,
  TEST_BUNDLE_CHANGE_UNREAD,
  TEST_BUNDLE_APPEND,
  TEST_BUNDLE_TRUNCATE,
} test_bundle_mutation_t;

typedef struct {
  const test_bundle_fixture_t *fixture;
  test_bundle_mutation_t mutation;
  FILE *source_stream;
  size_t bytes_read;
  bool mutated;
  bool mutation_ok;
} test_bundle_read_t;

/* Mutate through a separate file handle only after a specific source read has
 * completed. No sleeps, threads, or source-buffer changes. Staging streams are
 * created while the source stream is alive, so their FILE pointers are
 * distinct.
 */
static SHELL_NONNULL(1, 3) void test_bundle_mutate_after_read(FILE *stream,
                                                              size_t length,
                                                              void *context) {
  test_bundle_read_t *state = context;
  if (!state->source_stream)
    state->source_stream = stream;
  if (stream != state->source_stream)
    return;
  state->bytes_read += length;
  if (length == 0) {
    sg_test_io_read_observer_set(NULL, NULL);
    return;
  }
  if (state->mutated)
    return;
  bool after_payload = state->mutation == TEST_BUNDLE_CHANGE_STAGED ||
                       state->mutation == TEST_BUNDLE_APPEND;
  if (after_payload ? state->bytes_read < state->fixture->size
                    : state->bytes_read <= 32)
    return;
  state->mutated = true;
  if (state->mutation == TEST_BUNDLE_TRUNCATE) {
    state->mutation_ok =
        truncate(state->fixture->path,
                 (off_t)(32 + state->fixture->raw_size / 2)) == 0;
    return;
  }
  FILE *file = fopen(state->fixture->path, "r+b");
  if (!file)
    return;
  long offset = state->mutation == TEST_BUNDLE_CHANGE_UNREAD
                    ? state->fixture->type_alpha_offset
                    : state->fixture->raw_alpha_offset;
  bool ok = state->mutation == TEST_BUNDLE_APPEND
                ? fseek(file, 0, SEEK_END) == 0
                : fseek(file, offset, SEEK_SET) == 0;
  ok = ok &&
       fputc(state->mutation == TEST_BUNDLE_APPEND ? 'x' : '7', file) != EOF;
  state->mutation_ok = fclose(file) == 0 && ok;
}

static bool test_bundle_rejected_mutation(test_bundle_mutation_t mutation,
                                          bool bayesian) {
  test_bundle_fixture_t fixture = {0};
  sg_gate_t *target = calibration_gate(40);
  sg_gate_t *control = calibration_gate(40);
  bool ok = target && control && test_bundle_fixture_create(&fixture);
  sg_gate_t *gates[] = {target, control};
  sg_result_t result;
  for (size_t gate = 0; ok && gate < 2; gate++) {
    ok = sg_gate_set_anomaly_cache_size(gates[gate], 4) == SG_OK &&
         sg_gate_set_anomaly_adaptive(gates[gate], true, 4) == SG_OK &&
         sg_gate_set_anomaly_k_factor(gates[gate], 0.0) == SG_OK;
    if (bayesian)
      ok = ok && sg_gate_set_anomaly_combine_mode(
                     gates[gate], SG_ANOMALY_COMBINE_BAYESIAN) == SG_OK;
    for (size_t sample = 0; ok && sample < 8; sample++)
      ok = eval_cmd(gates[gate], calibration_commands[0], &result) == SG_OK;
  }
  size_t vocabulary = target ? test_anomaly_vocabulary(target) : 0;
  sg_anomaly_sequence_score_t before = {0}, after = {0};
  ok = ok && calibration_score(target, "gcc ; make ; strip", &before) &&
       before.detected;
  test_bundle_read_t read = {.fixture = &fixture, .mutation = mutation};
  sg_error_t status = SG_ERR_INVALID;
  if (ok) {
    sg_test_io_read_observer_set(test_bundle_mutate_after_read, &read);
    status = sg_gate_load_anomaly_model(target, fixture.path);
    sg_test_io_reset();
  }
  ok = ok && read.mutated && read.mutation_ok && status == SG_ERR_PARSE &&
       test_anomaly_vocabulary(target) == vocabulary &&
       calibration_score(target, "gcc ; make ; strip", &after) &&
       after.raw_score == before.raw_score &&
       after.type_score == before.type_score &&
       after.combined_score == before.combined_score &&
       after.detected == before.detected;
  if (ok) {
    if (mutation == TEST_BUNDLE_TRUNCATE)
      ok = read.bytes_read < fixture.size;
    else
      ok = read.bytes_read == fixture.size + (mutation == TEST_BUNDLE_APPEND);
  }
  /* Retaining identical numeric results is not sufficient to prove the cache
   * survived. A cache miss also adds key/signature allocations. */
  sg_result_t expected;
  if (ok) {
    sg_test_alloc_reset();
    shellsplit_test_alloc_reset();
    ok = eval_cmd(control, calibration_commands[0], &expected) == SG_OK;
    size_t gate_allocations = sg_test_alloc_count();
    size_t split_allocations = shellsplit_test_alloc_count();
    sg_test_alloc_reset();
    shellsplit_test_alloc_reset();
    ok = ok && eval_cmd(target, calibration_commands[0], &result) == SG_OK &&
         sg_test_alloc_count() == gate_allocations &&
         shellsplit_test_alloc_count() == split_allocations &&
         result.anomaly_score_raw == expected.anomaly_score_raw &&
         result.anomaly_score_type == expected.anomaly_score_type &&
         result.anomaly_score == expected.anomaly_score &&
         result.anomaly_detected == expected.anomaly_detected &&
         result.anomaly_update == expected.anomaly_update;
    sg_test_alloc_reset();
    shellsplit_test_alloc_reset();
  }
  if (!ok)
    printf("    bundle mutation %d, Bayesian %d, status %d, bytes %zu/%zu\n",
           mutation, bayesian, status, read.bytes_read, fixture.size);
  sg_gate_free(control);
  sg_gate_free(target);
  sg_gate_free(fixture.source);
  if (fixture.path[0])
    ok = unlink(fixture.path) == 0 && ok;
  return ok;
}

TEST(anomaly_bundle_mutation_failure_atomicity) {
  for (unsigned bayesian = 0; bayesian < 2; bayesian++) {
    ASSERT(test_bundle_rejected_mutation(TEST_BUNDLE_CHANGE_UNREAD, bayesian));
    ASSERT(test_bundle_rejected_mutation(TEST_BUNDLE_APPEND, bayesian));
    ASSERT(test_bundle_rejected_mutation(TEST_BUNDLE_TRUNCATE, bayesian));
  }
}

TEST(bayesian_adaptive_effective_transition) {
  sg_gate_t *gate = calibration_gate(100);
  ASSERT(gate != NULL);
  bool ok = sg_gate_set_anomaly_adaptive(gate, true, 4) == SG_OK &&
            sg_gate_set_anomaly_combine_mode(
                gate, SG_ANOMALY_COMBINE_BAYESIAN) == SG_OK;
  sg_result_t result;
  for (size_t i = 0; ok && i < 4; i++)
    ok = eval_cmd(gate, calibration_commands[0], &result) == SG_OK;
  /* Histogram readiness changes the effective score definition. The weighted
   * window must be discarded, not immediately applied to log-odds. Read-only
   * probes must not themselves advance either warm-up. */
  sg_anomaly_sequence_score_t score = {0};
  for (size_t i = 0; ok && i < 4; i++) {
    ok = calibration_score(gate, "gcc ; make ; strip", &score) &&
         score.combined_score > 1.0 && !score.detected;
    if (ok)
      ok = eval_cmd(gate, calibration_commands[0], &result) == SG_OK &&
           result.anomaly_score == 0.0 && !result.anomaly_detected;
  }
  ok = ok && calibration_score(gate, "gcc ; make ; strip", &score) &&
       score.detected;
  double preserved = score.combined_score;
  /* Same-mode setters and weights ignored by ready Bayesian scoring must not
   * erase an armed log-odds window or its component distributions. */
  ok = ok &&
       sg_gate_set_anomaly_combine_mode(gate, SG_ANOMALY_COMBINE_BAYESIAN) ==
           SG_OK &&
       sg_gate_set_anomaly_weights(gate, 0.25, 0.75) == SG_OK &&
       calibration_score(gate, "gcc ; make ; strip", &score) &&
       score.combined_score == preserved && score.detected;
  sg_gate_free(gate);
  ASSERT(ok);
}

TEST(anomaly_weight_calibration_transitions) {
  sg_gate_t *gate = calibration_gate(100);
  ASSERT(gate != NULL);
  bool ok = sg_gate_set_anomaly_adaptive(gate, true, 3) == SG_OK;
  sg_result_t result;
  for (unsigned transition = 0; ok && transition < 2; transition++) {
    for (size_t i = 0; ok && i < 3; i++)
      ok = eval_cmd(gate, calibration_commands[0], &result) == SG_OK;
    sg_anomaly_sequence_score_t score = {0};
    ok = ok && calibration_score(gate, "gcc ; make ; strip", &score) &&
         score.detected;
    double raw = transition == 0 ? 0.5 : 1.0;
    double type = 1.0 - raw;
    ok = ok && sg_gate_set_anomaly_weights(gate, raw, type) == SG_OK &&
         calibration_score(gate, "gcc ; make ; strip", &score) &&
         score.detected;
    /* Identical settings above are a no-op. Changing the weighted definition
     * below starts a fresh adaptive window, retaining the trained models. */
    double next_raw = transition == 0 ? 1.0 : 0.0;
    ok = ok &&
         sg_gate_set_anomaly_weights(gate, next_raw, 1.0 - next_raw) == SG_OK;
    ok = ok && calibration_score(gate, "gcc ; make ; strip", &score) &&
         !score.detected;
  }
  sg_gate_free(gate);
  ASSERT(ok);
}

TEST(anomaly_model_load_resets_calibration) {
  const char *path = temp_policy_file();
  ASSERT(path != NULL);
  sg_gate_t *source = calibration_gate(1);
  ASSERT(source != NULL);
  bool ok = sg_gate_save_anomaly_model(source, path) == SG_OK;
  sg_gate_free(source);
  for (unsigned bayesian = 0; ok && bayesian < 2; bayesian++) {
    sg_gate_t *target = calibration_gate(100);
    sg_gate_t *control = calibration_gate(100);
    ASSERT(target != NULL && control != NULL);
    ok = sg_gate_set_anomaly_adaptive(target, true, 3) == SG_OK &&
         sg_gate_set_anomaly_adaptive(control, true, 3) == SG_OK &&
         sg_gate_set_anomaly_k_factor(target, 0.0) == SG_OK &&
         sg_gate_set_anomaly_k_factor(control, 0.0) == SG_OK;
    if (bayesian)
      ok = ok &&
           sg_gate_set_anomaly_combine_mode(
               target, SG_ANOMALY_COMBINE_BAYESIAN) == SG_OK &&
           sg_gate_set_anomaly_combine_mode(
               control, SG_ANOMALY_COMBINE_BAYESIAN) == SG_OK;
    sg_result_t actual, expected;
    for (size_t i = 0; ok && i < 6; i++)
      ok = eval_cmd(target, calibration_commands[0], &actual) == SG_OK;
    ok = ok && sg_gate_load_anomaly_model(target, path) == SG_OK &&
         sg_gate_load_anomaly_model(control, path) == SG_OK;
    for (size_t i = 0; ok && i < 7; i++) {
      ok = eval_cmd(target, calibration_commands[0], &actual) == SG_OK &&
           eval_cmd(control, calibration_commands[0], &expected) == SG_OK &&
           actual.anomaly_score == expected.anomaly_score &&
           actual.anomaly_detected == expected.anomaly_detected &&
           !actual.anomaly_detected;
      if (ok && i == 0)
        ok = actual.anomaly_score > 0.25;
    }
    sg_gate_free(control);
    sg_gate_free(target);
  }
  ASSERT(ok);
}

TEST(anomaly_calibration_failure_atomicity) {
  const char *path = temp_policy_file();
  ASSERT(path != NULL);
  sg_gate_t *source = calibration_gate(1);
  ASSERT(source != NULL);
  bool ok = sg_gate_save_anomaly_model(source, path) == SG_OK;
  sg_gate_free(source);
  char malformed[320];
  snprintf(malformed, sizeof(malformed), "%s.bad", path);
  FILE *file = fopen(malformed, "wb");
  ASSERT(file != NULL);
  ok = ok && fputs("not an anomaly bundle", file) >= 0;
  ok = fclose(file) == 0 && ok;
  register_temp_file(malformed);
  for (unsigned bayesian = 0; ok && bayesian < 2; bayesian++) {
    sg_gate_t *gate = calibration_gate(100);
    ASSERT(gate != NULL);
    ok = sg_gate_set_anomaly_adaptive(gate, true, 4) == SG_OK;
    if (bayesian)
      ok = ok && sg_gate_set_anomaly_combine_mode(
                     gate, SG_ANOMALY_COMBINE_BAYESIAN) == SG_OK;
    sg_result_t result;
    for (size_t i = 0; ok && i < 8; i++)
      ok = eval_cmd(gate, calibration_commands[0], &result) == SG_OK;
    sg_anomaly_sequence_score_t before = {0}, after = {0};
    ok = ok && calibration_score(gate, "gcc ; make ; strip", &before) &&
         before.detected;
    size_t vocab = test_anomaly_vocabulary(gate);
    for (unsigned failure = 0; ok && failure < 10; failure++) {
      sg_error_t status, expected = SG_ERR_MEMORY;
      switch (failure) {
      case 0:
        sg_test_alloc_fail_at(1);
        status = sg_gate_set_anomaly_adaptive(gate, true, 16);
        sg_test_alloc_reset();
        break;
      case 1:
      case 2:
        if (bayesian)
          continue; /* Histograms already exist: no allocation is needed. */
        sg_test_alloc_fail_at(failure);
        status =
            sg_gate_set_anomaly_combine_mode(gate, SG_ANOMALY_COMBINE_BAYESIAN);
        sg_test_alloc_reset();
        break;
      case 3:
        status = sg_gate_set_anomaly_combine_mode(
            gate, (sg_anomaly_combine_mode_t)99);
        expected = SG_ERR_INVALID;
        break;
      case 4:
        status = sg_gate_set_anomaly_weights(gate, -1.0, 2.0);
        expected = SG_ERR_INVALID;
        break;
      case 5:
        status = sg_gate_set_anomaly_k_factor(gate, NAN);
        expected = SG_ERR_INVALID;
        break;
      case 6:
        sg_test_alloc_fail_at(1);
        status = sg_gate_load_anomaly_model(gate, path);
        sg_test_alloc_reset();
        break;
      case 7:
        sg_test_io_fail_at(1);
        status = sg_gate_load_anomaly_model(gate, path);
        sg_test_io_reset();
        expected = SG_ERR_IO;
        break;
      case 8:
        sg_test_locale_fail_with_errno(ENOMEM);
        status = sg_gate_load_anomaly_model(gate, path);
        break;
      default:
        status = sg_gate_load_anomaly_model(gate, malformed);
        expected = SG_ERR_PARSE;
        break;
      }
      ok = status == expected && test_anomaly_vocabulary(gate) == vocab &&
           calibration_score(gate, "gcc ; make ; strip", &after) &&
           after.detected == before.detected &&
           after.combined_score == before.combined_score &&
           after.raw_score == before.raw_score &&
           after.type_score == before.type_score;
    }
    sg_gate_free(gate);
  }
  ASSERT(ok);
}

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

/* A FILE name supplied by a substitution route is dynamic substitution I/O,
 * and its pathname is also unresolved. A name that is only an unresolved
 * parameter reports the unresolved pathname and no substitution I/O. */
TEST(substitution_supplied_filename_dynamic_io) {
  static const struct {
    const char *command;
    bool dynamic_io;
    bool unresolved_path;
  } cases[] = {
      {"echo ok >\"$(printf out)\"", true, true},
      {"cat < <(printf out)", true, false},
      {"echo ok >\"$OUT\"", false, true},
  };
  const char *rules[] = {"echo *", "printf *", "cat"};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *gate = gate_with_rules(rules, 3);
    ASSERT(gate != NULL);
    ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
    ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    ASSERT(result.has_dynamic_substitution_io == cases[i].dynamic_io);
    ASSERT(((result.unresolved_expansion_flags &
             SG_EXPANSION_UNRESOLVED_PATH) != 0) == cases[i].unresolved_path);
    sg_gate_free(gate);
  }
}

TEST(substitution_capacity_fails_closed) {
  sg_gate_t *gate =
      gate_with_rules((const char *[]){"exec", "probe", "echo *", "cat *",
                                       "cat", "producer", "export *"},
                      7);
  ASSERT_NOT_NULL(gate);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  bool valid = true;
  for (unsigned anomaly = 0; anomaly < 2; anomaly++) {
    if (anomaly && sg_gate_enable_anomaly(gate, 1e300, NULL) != SG_OK) {
      valid = false;
      break;
    }
    for (size_t i = 0;
         i < sizeof(shellsplit_test_substitution_capacity_cases) /
                 sizeof(shellsplit_test_substitution_capacity_cases[0]);
         i++) {
      for (unsigned changes = SHELL_DEP_TIME_MAX_EXTERNAL_FDS - 1;
           changes <= SHELL_DEP_TIME_MAX_EXTERNAL_FDS; changes++) {
        char source[4096];
        size_t length;
        if (!shellsplit_test_substitution_capacity_source(
                source, sizeof(source), changes,
                shellsplit_test_substitution_capacity_cases[i], &length)) {
          valid = false;
          continue;
        }
        sg_result_t result;
        sg_error_t error = eval_cmd(gate, source, &result);
        bool complete = changes < SHELL_DEP_TIME_MAX_EXTERNAL_FDS;
        bool expected = complete
                            ? error == SG_OK && !result.truncated
                            : error == SG_ERR_TRUNC && result.truncated &&
                                  result.subcommand_truncated &&
                                  result.verdict == SG_VERDICT_UNDETERMINED;
        if (complete) {
          bool producer = false;
          for (size_t command = 0; command < result.subcommand_count; command++)
            producer |= result.subcommands[command].netargv_length == 11 &&
                        memcmp(result.subcommands[command].netargv,
                               "8:producer,", 11) == 0;
          expected = expected && producer;
        }
        if (!expected) {
          printf("\n    capacity tail %s changes=%u anomaly=%u: error=%d "
                 "verdict=%d truncated=%d\n",
                 shellsplit_test_substitution_capacity_cases[i], changes,
                 anomaly, error, result.verdict, result.truncated);
          valid = false;
        }
      }
    }
  }
  sg_gate_free(gate);
  ASSERT(valid);
}

int main(int argc, char **argv) {
  ASSERT(atexit(cleanup_temp_files) == 0);
  if (argc == 2 && strcmp(argv[1], "--contextual-anomaly") == 0) {
    RUN(contextual_read_anomaly_contract);
    RUN(contextual_read_anomaly_allocation_failures);
    RUN(truncated_graph_skips_anomaly_work);
    return fail_count ? EXIT_FAILURE : EXIT_SUCCESS;
  }
  RUN(policy_binding_lifecycle);
  RUN(policy_list_command_verdict_is_most_restrictive);
  RUN(policy_list_accessors_and_user_pointers);
  RUN(policy_list_add_remove_and_limits);
  RUN(policy_list_stop_outcome);
  RUN(gate_setter_contract);
  RUN(policy_list_equal_outcomes_keep_the_first);
  RUN(output_vector_and_scalar_projection);
  RUN(output_scalar_decider_needs_a_unique_most_restrictive);
  RUN(override_cycle_gives_two_outputs);
  RUN(override_fan_out_tries_relations_in_creation_order);
  RUN(override_declaration_validation_and_removal);
  RUN(override_removal_of_an_overrider_and_a_borrowed_policy);
  RUN(policy_allocation_failure_returns_the_error_and_no_verdict);
  RUN(anomaly_component_borrowed_views);
  RUN(substitution_capacity_fails_closed);
  printf("shellgate tests\n\n");

  printf("Lifecycle:\n");
  RUN(gate_api_contract_matrix);
  RUN(word_fragment_operator_shellgate_contract);

  printf("\nBasic evaluation:\n");
  RUN(basic_evaluation_matrix);
  RUN(bash_pipeline_time_policy_contract);
  RUN(timed_pipeline_ordinary_time_policy_contract);
  RUN(grouped_empty_time_io_policy_contract);
  RUN(empty_timing_substitution_policy_contract);
  RUN(brace_group_maximum_depth_contract);
  RUN(nested_quoted_expansion_boundaries);
  RUN(nested_feature_rejection_contract);
  RUN(static_arithmetic_literal_contract);
  RUN(builtin_argument_read_setup_contract);
  RUN(numeric_condition_policy_contract);
  RUN(conditional_string_contract);
  RUN(dynamic_substitution_flow_contract);
  RUN(expansion_phases_survive_failed_setup);
  RUN(substitution_comment_and_heredoc_capacity_contract);
  RUN(anomaly_large_quoted_delimiter_workspace);
  RUN(anomaly_mixed_heredoc_substitution_contract);

  printf("\nFeature rejection:\n");
  RUN(named_fd_process_substitution_policy_contract);
  RUN(named_fd_builtin_operand_policy_contract);
  RUN(named_fd_builtin_ordered_assignment_policy_contract);

  printf("\nSuggestions:\n");
  RUN(suggestion_rendering_failure_is_not_silent);
  RUN(cdf_bucket_saturates_before_conversion);
  RUN(contextual_policy_mutations_preserve_verdicts);

  printf("\nEdge cases:\n");
  RUN(combined_redirect_prefix_word_contract);
  RUN(named_document_policy_and_stage_contract);

  printf("\nConfiguration:\n");

  printf("\nPolicy management:\n");
  RUN(arithmetic_command_policy);
  RUN(policy_replacement_failure_atomicity);

  printf("\nSerialization:\n");

  printf("\nBuffer management:\n");
  RUN(output_writer_exact_fit_boundaries);
  RUN(buffer_contract_matrix);
  RUN(graph_result_fields_stay_out_of_workspace);
  RUN(suggestion_streaming_buffer_contract);

  printf("\nExpansion callbacks:\n");
  RUN(expansion_callback_matrix);
  RUN(binary_expansion_callback_contract);
  RUN(expansion_error_diagnostic_boundaries);
  RUN(expansion_operand_eligibility_contract);
  RUN(printf_expansion_control_contract);
  RUN(expansion_flags_stop_modes);
  RUN(nested_path_expansion_ownership);
  RUN(resolved_named_redirect_failure_effects);
  RUN(static_empty_path_callback_reachability);
  RUN(substitution_status_callback_reachability);

  printf("\nGraph effects:\n");

  printf("\nHelpers:\n");
  RUN(helper_contracts);

  printf("\nProperty tests:\n");
  srand(42);
  RUN(property_suggestion_leads_to_allow);

  printf("\nAnomaly detection:\n");
  RUN(anomaly_enable_disable);
  RUN(anomaly_learning_policy_matrix);
  RUN(anomaly_model_roundtrip);
  RUN(anomaly_bundle_roundtrip_retains_empty_stage);
  RUN(anomaly_bundle_corruption_matrix);
  RUN(anomaly_bundle_failure_atomicity);
  RUN(anomaly_bundle_stream_failure_matrix);
  RUN(anomaly_bundle_mutation_failure_atomicity);
  RUN(anomaly_allocation_failure_matrix);
  RUN(anomaly_netseq_score_contract);
  RUN(anomaly_configuration_validation);

  printf("\nAdaptive threshold:\n");
  RUN(anomaly_adaptive_threshold_transitions);

  printf("\nType sequence cache:\n");
  RUN(anomaly_cache_equivalence_matrix);
  RUN(contextual_read_anomaly_contract);
  RUN(contextual_read_anomaly_allocation_failures);
  RUN(truncated_graph_skips_anomaly_work);
  RUN(anomaly_cache_allocation_failure_matrix);
  RUN(anomaly_model_failure_verdict_contract);
  RUN(anomaly_update_outcome_contract);

  printf("\nSeparate scores:\n");

  printf("\nBayesian combination:\n");
  RUN(bayesian_adaptive_effective_transition);
  RUN(anomaly_weight_calibration_transitions);
  RUN(anomaly_model_load_resets_calibration);
  RUN(anomaly_calibration_failure_atomicity);
  RUN(bayesian_combination_transitions);
  RUN(substitution_supplied_filename_dynamic_io);

  cleanup_temp_files();
  printf("\n========================================\n");
  printf("Results: %d passed, %d failed\n", pass_count, fail_count);
  return fail_count > 0 || selection_matched_nothing() ? 1 : 0;
}
