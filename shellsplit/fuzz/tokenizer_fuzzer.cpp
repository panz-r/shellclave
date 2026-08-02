// LibFuzzer harness for shellsplit - fuzzes all parsers
// Fuzzes: fast parser, full parser, transformer, processor

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shell_depgraph.h"
#include "shell_processor.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include "shell_transform.h"

#include <fuzzer/FuzzedDataProvider.h>

#include <algorithm>
#include <string>

extern "C" {

static const size_t MAX_INPUT_SIZE = 8192;
static int g_verbose = 0;

/* CWD strategies for shell_parse_depgraph. NULL tests the early substitution to
 * "." inside the parser; the rest cover the realistic path shapes used in
 * existing depgraph tests plus a few edge cases. */
static const char *kCwdStrategies[] = {
    nullptr, "/home/user", "/tmp", "$HOME/long/nested/path", "a/../b//c", "."};
constexpr int kCwdStrategiesN =
    sizeof(kCwdStrategies) / sizeof(kCwdStrategies[0]);

extern "C" void LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  const char *verbose = getenv("SHELLSPLIT_FUZZ_VERBOSE");
  if (verbose && (*verbose == '1' || *verbose == 'y' || *verbose == 'Y')) {
    g_verbose = 1;
  }
  if (g_verbose) {
    fprintf(stderr, "DEBUG: ShellSplit fuzzer initialized\n");
  }
}

static int validate_fast_result(const char *input, size_t length,
                                shell_error_t err,
                                const shell_parse_result_t *result,
                                uint32_t max_commands) {
  if (err != SHELL_OK && err != SHELL_EINPUT && err != SHELL_ETRUNC &&
      err != SHELL_EPARSE) {
    if (g_verbose)
      fprintf(stderr, "\n=== FAST PARSER ERROR: Invalid return code %d ===\n",
              err);
    return 1;
  }

  if ((err == SHELL_OK && result->status != SHELL_STATUS_OK) ||
      (err == SHELL_ETRUNC && !(result->status & SHELL_STATUS_TRUNCATED)) ||
      ((err == SHELL_EINPUT || err == SHELL_EPARSE) &&
       !(result->status & SHELL_STATUS_ERROR))) {
    if (g_verbose)
      fprintf(stderr, "\n=== FAST PARSER ERROR: Return/status mismatch ===\n");
    return 1;
  }

  if (result->count > max_commands) {
    if (g_verbose)
      fprintf(stderr, "\n=== FAST PARSER ERROR: Invalid count %u ===\n",
              result->count);
    return 1;
  }

  static const uint16_t valid_types =
      SHELL_TYPE_PIPELINE | SHELL_TYPE_AND | SHELL_TYPE_OR |
      SHELL_TYPE_SEMICOLON | SHELL_TYPE_HEREDOC | SHELL_TYPE_HERESTRING;
  static const uint16_t valid_features =
      SHELL_FEAT_VARS | SHELL_FEAT_GLOBS | SHELL_FEAT_SUBSHELL |
      SHELL_FEAT_ARITH | SHELL_FEAT_HEREDOC | SHELL_FEAT_HERESTRING |
      SHELL_FEAT_PROCESS_SUB | SHELL_FEAT_LOOPS | SHELL_FEAT_CONDITIONALS |
      SHELL_FEAT_CASE | SHELL_FEAT_SUBSHELL_FILE;
  for (uint32_t i = 0; i < result->count; i++) {
    const shell_range_t *r = &result->cmds[i];
    bool known_type =
        r->type == SHELL_TYPE_SIMPLE || r->type == SHELL_TYPE_PIPELINE ||
        r->type == SHELL_TYPE_AND || r->type == SHELL_TYPE_OR ||
        r->type == SHELL_TYPE_SEMICOLON || r->type == SHELL_TYPE_HEREDOC ||
        r->type == SHELL_TYPE_HERESTRING;
    if (r->len == 0 || r->start > length || r->len > length - r->start ||
        !known_type || (r->type & (uint16_t)~valid_types) != 0 ||
        (r->features & (uint16_t)~valid_features) != 0) {
      if (g_verbose)
        fprintf(stderr,
                "\n=== FAST PARSER ERROR: Invalid range at idx %u ===\n", i);
      return 1;
    }

    char buf[256];
    size_t copied = shell_copy_subcommand(input, r, buf, sizeof(buf));
    size_t expected = r->len < sizeof(buf) ? r->len : sizeof(buf) - 1;
    if (copied != expected || buf[copied] != '\0' ||
        memcmp(buf, input + r->start, copied) != 0) {
      if (g_verbose)
        fprintf(stderr, "\n=== FAST PARSER ERROR: Copy overflow ===\n");
      return 1;
    }

    uint32_t out_len = 0;
    const char *ptr = shell_get_subcommand(input, r, &out_len);
    if (ptr != input + r->start || out_len != r->len) {
      if (g_verbose)
        fprintf(stderr, "\n=== FAST PARSER ERROR: Length mismatch ===\n");
      return 1;
    }
  }

  return 0;
}

// Test default, strict, and bounded fast-parser modes through one invariant
// matrix so every input exercises all public configurations.
static int test_fast_parser(const char *input, size_t length) {
  static const shell_limits_t limits[] = {
      SHELL_LIMITS_DEFAULT,
      {SHELL_MAX_SUBCOMMANDS, true},
      {1, false},
  };

  for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
    shell_parse_result_t result = {};
    shell_error_t err = shell_parse_fast(input, length, &limits[i], &result);
    if (validate_fast_result(input, length, err, &result,
                             limits[i].max_subcommands))
      return 1;
  }
  return 0;
}

static bool range_in_input(const char *input, size_t length, const char *ptr,
                           uint32_t span) {
  if (!ptr)
    return span == 0;
  uintptr_t begin = (uintptr_t)input;
  uintptr_t end = begin + length;
  uintptr_t value = (uintptr_t)ptr;
  return value >= begin && value <= end && span <= end - value;
}

static int validate_depgraph(const char *input, size_t length,
                             shell_dep_error_t error,
                             const shell_dep_graph_t *graph,
                             const shell_dep_limits_t *limits) {
  uint32_t max_nodes = limits->max_nodes < SHELL_DEP_MAX_NODES
                           ? limits->max_nodes
                           : SHELL_DEP_MAX_NODES;
  uint32_t max_edges = limits->max_edges < SHELL_DEP_MAX_EDGES
                           ? limits->max_edges
                           : SHELL_DEP_MAX_EDGES;
  uint32_t max_tokens = limits->max_tokens_per_cmd < SHELL_DEP_MAX_TOKENS
                            ? limits->max_tokens_per_cmd
                            : SHELL_DEP_MAX_TOKENS;
  if (error != SHELL_DEP_OK && error != SHELL_DEP_EINPUT &&
      error != SHELL_DEP_ETRUNC && error != SHELL_DEP_EPARSE)
    return 1;
  if ((error == SHELL_DEP_OK && graph->status != SHELL_DEP_STATUS_OK) ||
      (error == SHELL_DEP_ETRUNC &&
       !(graph->status & SHELL_DEP_STATUS_TRUNCATED)) ||
      ((error == SHELL_DEP_EINPUT || error == SHELL_DEP_EPARSE) &&
       graph->status != SHELL_DEP_STATUS_ERROR) ||
      graph->node_count > max_nodes || graph->edge_count > max_edges ||
      graph->cwd_buf.len > SHELL_DEP_CWD_BUF_SIZE ||
      (graph->cwd_buf.len > 0 &&
       graph->cwd_buf.data[graph->cwd_buf.len - 1] != '\0'))
    return 1;

  if (error == SHELL_DEP_EINPUT || error == SHELL_DEP_EPARSE)
    return graph->node_count != 0 || graph->edge_count != 0;
  if (!shell_dep_validate(graph).valid)
    return 1;

  for (uint32_t i = 0; i < graph->node_count; i++) {
    const shell_dep_node_t *node = &graph->nodes[i];
    if (node->type == SHELL_NODE_CMD) {
      if (node->cmd.token_count > max_tokens)
        return 1;
      for (uint32_t j = 0; j < node->cmd.token_count; j++)
        if (!range_in_input(input, length, node->cmd.tokens[j],
                            node->cmd.token_lens[j]))
          return 1;
      continue;
    }
    if (node->type != SHELL_NODE_DOC || node->doc.kind < SHELL_DOC_FILE ||
        node->doc.kind > SHELL_DOC_ENVVAR ||
        !range_in_input(input, length, node->doc.path, node->doc.path_len) ||
        !range_in_input(input, length, node->doc.name, node->doc.name_len) ||
        !range_in_input(input, length, node->doc.value, node->doc.value_len))
      return 1;
  }
  return 0;
}

static int test_depgraph(const char *input, size_t length, const char *cwd,
                         uint32_t depth) {
  static const shell_dep_limits_t limits[] = {
      SHELL_DEP_LIMITS_DEFAULT,
      {4, 4, 2, 32, true},
  };
  for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
    shell_dep_graph_t graph = {};
    shell_dep_error_t error =
        shell_parse_depgraph(input, length, cwd, &limits[i], depth, &graph);
    if (validate_depgraph(input, length, error, &graph, &limits[i]))
      return 1;
  }
  return 0;
}

// Test full parser
static int test_full_parser(const char *input, size_t length) {
  shell_command_t *commands = NULL;
  size_t command_count = 0;

  bool success = shell_tokenize_commands(input, &commands, &command_count);

  if (!success)
    return commands != NULL || command_count != 0;

  if ((commands == NULL) != (command_count == 0)) {
    shell_free_commands(commands, command_count);
    return 1;
  }

  if (commands) {
    for (size_t i = 0; i < command_count; i++) {
      shell_command_t *cmd = &commands[i];
      if (cmd->start_pos > length || cmd->end_pos < cmd->start_pos ||
          cmd->end_pos > length ||
          (cmd->tokens == NULL) != (cmd->token_count == 0)) {
        shell_free_commands(commands, command_count);
        return 1;
      }
      for (size_t j = 0; j < cmd->token_count; j++) {
        const shell_token_t *tok = &cmd->tokens[j];
        if (tok->type < TOKEN_COMMAND || tok->type > TOKEN_HERESTRING ||
            tok->position > length || tok->length > length - tok->position ||
            tok->start != input + tok->position) {
          if (g_verbose)
            fprintf(stderr,
                    "\n=== FULL PARSER ERROR: invalid token range/type ===\n");
          shell_free_commands(commands, command_count);
          return 1;
        }
      }
    }
    shell_free_commands(commands, command_count);
  }

  return 0;
}

// Test transformer
static int test_transformer(const char *input, size_t length) {
  transformed_command_t **transformed_cmds = NULL;
  size_t transformed_count = 0;

  bool success = shell_transform_command_line(input, &transformed_cmds,
                                              &transformed_count);

  // Clean up on failure
  if (!success) {
    shell_free_transformed_commands(transformed_cmds, transformed_count);
    free(transformed_cmds);
    return 0;
  }

  if ((transformed_cmds == NULL) != (transformed_count == 0)) {
    shell_free_transformed_commands(transformed_cmds, transformed_count);
    free(transformed_cmds);
    return 1;
  }

  if (transformed_cmds) {
    for (size_t i = 0; i < transformed_count; i++) {
      transformed_command_t *tcmd = transformed_cmds[i];
      if (!tcmd || !tcmd->original_command || !tcmd->transformed_command ||
          (tcmd->tokens == NULL) != (tcmd->token_count == 0) ||
          shell_get_dfa_input(tcmd) != tcmd->transformed_command ||
          shell_has_transformations(tcmd) != tcmd->has_transformations ||
          !memchr(tcmd->original_command, '\0', length + 1) ||
          !memchr(tcmd->transformed_command, '\0', length * 16 + 1)) {
        shell_free_transformed_commands(transformed_cmds, transformed_count);
        free(transformed_cmds);
        return 1;
      }

      for (size_t j = 0; j < tcmd->token_count; j++) {
        const transformed_token_t *tok = &tcmd->tokens[j];
        bool transformed = tok->type != TRANSFORM_NONE;
        if (tok->type < TRANSFORM_NONE || tok->type > TRANSFORM_REDIRECTION ||
            !tok->original || !tok->transformed ||
            (!transformed && tok->transformed != tok->original) ||
            (transformed && tok->transformed == tok->original) ||
            tok->is_shell_construct != transformed) {
          if (g_verbose)
            fprintf(stderr, "\n=== TRANSFORMER ERROR: invalid token ===\n");
          shell_free_transformed_commands(transformed_cmds, transformed_count);
          free(transformed_cmds);
          return 1;
        }
        if (strlen(tok->original) > length ||
            strlen(tok->transformed) > length * 16 + 1) {
          shell_free_transformed_commands(transformed_cmds, transformed_count);
          free(transformed_cmds);
          return 1;
        }
      }
    }
    shell_free_transformed_commands(transformed_cmds, transformed_count);
    free(transformed_cmds);
  }

  return 0;
}

static void free_dfa_inputs(const char **inputs, size_t count) {
  for (size_t i = 0; i < count; i++)
    free((void *)inputs[i]);
  free(inputs);
}

static bool tokens_refer_to_owned_command(const shell_token_t *tokens,
                                          size_t count, const char *command) {
  uintptr_t begin = (uintptr_t)command;
  uintptr_t end = begin + strlen(command);
  for (size_t i = 0; i < count; i++) {
    uintptr_t token = (uintptr_t)tokens[i].start;
    if (token < begin || token > end || tokens[i].length > end - token)
      return false;
    if (tokens[i].position > end - begin ||
        tokens[i].start != command + tokens[i].position)
      return false;
  }
  return true;
}

// Test processor and its convenience extraction API against each other.
static int test_processor(const char *input, size_t length) {
  shell_command_info_t *infos = NULL;
  size_t command_count = 0;
  bool success = shell_process_command(input, &infos, &command_count);
  const char **dfa_inputs = NULL;
  size_t dfa_input_count = 0;
  bool has_shell_features = false;
  bool extracted = shell_extract_dfa_inputs(
      input, &dfa_inputs, &dfa_input_count, &has_shell_features);

  if (success != extracted) {
    shell_free_command_infos(infos, command_count);
    free_dfa_inputs(dfa_inputs, dfa_input_count);
    return 1;
  }
  if (!success) {
    shell_free_command_infos(infos, command_count);
    free_dfa_inputs(dfa_inputs, dfa_input_count);
    return 0;
  }

  if ((infos == NULL) != (command_count == 0) ||
      (dfa_inputs == NULL) != (dfa_input_count == 0) ||
      dfa_input_count != command_count) {
    shell_free_command_infos(infos, command_count);
    free_dfa_inputs(dfa_inputs, dfa_input_count);
    return 1;
  }

  bool expected_features = false;
  if (infos) {
    for (size_t i = 0; i < command_count; i++) {
      shell_command_info_t *info = &infos[i];
      if (!info->original_command || !info->clean_command ||
          shell_get_clean_command(info) != info->clean_command ||
          (info->shell_tokens == NULL) != (info->shell_token_count == 0) ||
          (info->command_tokens == NULL) != (info->command_token_count == 0) ||
          !memchr(info->original_command, '\0', length + 1) ||
          !memchr(info->clean_command, '\0', length * 2 + 1) ||
          !tokens_refer_to_owned_command(info->shell_tokens,
                                         info->shell_token_count,
                                         info->original_command) ||
          !tokens_refer_to_owned_command(info->command_tokens,
                                         info->command_token_count,
                                         info->original_command) ||
          !dfa_inputs[i] || strcmp(dfa_inputs[i], info->clean_command) != 0) {
        shell_free_command_infos(infos, command_count);
        free_dfa_inputs(dfa_inputs, dfa_input_count);
        return 1;
      }
      if (info->command_tokens) {
        size_t expected_length = info->command_token_count - 1;
        for (size_t j = 0; j < info->command_token_count; j++)
          expected_length += info->command_tokens[j].length;
        if (info->clean_command[expected_length] != '\0') {
          shell_free_command_infos(infos, command_count);
          free_dfa_inputs(dfa_inputs, dfa_input_count);
          return 1;
        }
      }
      expected_features |= shell_has_dangerous_features(info);
    }
  }

  shell_free_command_infos(infos, command_count);
  free_dfa_inputs(dfa_inputs, dfa_input_count);
  return expected_features != has_shell_features;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0)
    return 0;

  FuzzedDataProvider fdp(data, size);
  uint8_t cwd_selector = fdp.ConsumeIntegral<uint8_t>();
  uint8_t depth_byte = fdp.ConsumeIntegral<uint8_t>();
  /* depth is a recursion cap: shell_parse_depgraph rejects values > 16 with
   * SHELL_DEP_EPARSE (shell_depgraph.c:670). Map a byte to [0, 31] so the
   * fuzzer can find the boundary and exercise both sides. */
  uint32_t depth = depth_byte >> 3;

  /* CWD selection: the first 2*kCwdStrategiesN selectors pick from the
   * curated list (each entry twice for slightly higher weight); the rest
   * derive a random CWD from input bytes. The depgraph parser treats CWD as
   * a plain string, so any sequence of bytes is in scope. */
  constexpr size_t kMaxCwdBytes = 32;
  const char *cwd;
  char random_cwd_buf[kMaxCwdBytes];
  if (cwd_selector < (uint8_t)(kCwdStrategiesN * 2)) {
    cwd = kCwdStrategies[cwd_selector / 2];
  } else {
    size_t n = std::min(fdp.remaining_bytes(), kMaxCwdBytes - 1);
    std::string s = fdp.ConsumeBytesAsString(n);
    size_t nul = s.find('\0');
    size_t copy = (nul == std::string::npos) ? s.size() : nul;
    if (copy == 0) {
      cwd = ".";
    } else {
      memcpy(random_cwd_buf, s.data(), copy);
      random_cwd_buf[copy] = '\0';
      cwd = random_cwd_buf;
    }
  }

  /* Remaining bytes become the command. The fast parser still sees the raw
   * full input (including the FDP-extracted header bytes), which preserves
   * the existing NUL-asymmetry: the fast parser rejects bytes <0x20 with
   * SHELL_EPARSE, while the NUL-terminated parsers truncate at the first NUL.
   * That asymmetry is what makes the fast parser strictly more thorough on
   * control bytes. */
  std::string cmd = fdp.ConsumeRemainingBytesAsString();
  if (cmd.empty())
    return 0;
  if (cmd.size() > MAX_INPUT_SIZE)
    cmd.resize(MAX_INPUT_SIZE);

  char *input = (char *)malloc(cmd.size() + 1);
  if (!input)
    return 0;
  memcpy(input, cmd.data(), cmd.size());
  input[cmd.size()] = '\0';
  size_t text_length = strlen(input);

  // A non-zero helper result represents a violated parser invariant. Returning
  // success here would make libFuzzer discard the finding.
  bool failed = false;
  failed |= test_fast_parser((const char *)data, size);
  failed |= test_depgraph(input, text_length, cwd, depth);
  failed |= test_full_parser(input, text_length);
  failed |= test_transformer(input, text_length);
  failed |= test_processor(input, text_length);
  free(input);
  if (failed)
    abort();

  return 0;
}

} // extern "C"
