// LibFuzzer harness for shellsplit - fuzzes all parsers
// Fuzzes: fast parser, full parser, transformer, processor

#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "env_screener.h"
#include "relative_permutation_entropy.h"
#include "shell_abstract.h"
#include "shell_depgraph.h"
#include "shell_interop.h"
#include "shell_processor.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include "shell_transform.h"

#include <algorithm>
#include <string>
#include <vector>

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
      SHELL_TYPE_SEMICOLON | SHELL_TYPE_HEREDOC | SHELL_TYPE_HERESTRING |
      SHELL_TYPE_SUBSTITUTION;
  static const uint16_t valid_features =
      SHELL_FEAT_VARS | SHELL_FEAT_GLOBS | SHELL_FEAT_SUBSHELL |
      SHELL_FEAT_ARITH | SHELL_FEAT_HEREDOC | SHELL_FEAT_HERESTRING |
      SHELL_FEAT_PROCESS_SUB | SHELL_FEAT_LOOPS | SHELL_FEAT_CONDITIONALS |
      SHELL_FEAT_CASE | SHELL_FEAT_SUBSHELL_FILE | SHELL_FEAT_PIPELINE;
  for (uint32_t i = 0; i < result->count; i++) {
    const shell_range_t *r = &result->cmds[i];
    bool known_type =
        r->type == SHELL_TYPE_SIMPLE || r->type == SHELL_TYPE_PIPELINE ||
        r->type == SHELL_TYPE_AND || r->type == SHELL_TYPE_OR ||
        r->type == SHELL_TYPE_SEMICOLON || r->type == SHELL_TYPE_HEREDOC ||
        r->type == SHELL_TYPE_HERESTRING || r->type == SHELL_TYPE_SUBSTITUTION;
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

/* Independent expected results for a small supported-dialect corpus. These
 * checks make the fuzzer fail on semantic regressions, not only malformed
 * output structures. */
static int test_fixed_oracles(void) {
  struct oracle_case {
    const char *input;
    uint32_t count;
    uint16_t first_type;
    uint16_t second_type;
    uint16_t features;
  };
  static const oracle_case cases[] = {
      {"ls", 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE, 0},
      {"ls | wc", 2, SHELL_TYPE_SIMPLE, SHELL_TYPE_PIPELINE,
       SHELL_FEAT_PIPELINE},
      {"ls && pwd", 2, SHELL_TYPE_SIMPLE, SHELL_TYPE_AND, 0},
      {"ls || pwd", 2, SHELL_TYPE_SIMPLE, SHELL_TYPE_OR, 0},
      {"echo 'a|b'", 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE, 0},
      {"echo $(id)", 1, SHELL_TYPE_SUBSTITUTION, SHELL_TYPE_SIMPLE,
       SHELL_FEAT_SUBSHELL},
      {"echo $((1+2))", 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE,
       SHELL_FEAT_ARITH},
      {"echo $HOME", 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE, SHELL_FEAT_VARS},
      {"echo $-", 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE, SHELL_FEAT_VARS},
      {"echo *.txt", 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE, SHELL_FEAT_GLOBS},
      {"cat <(id)", 1, SHELL_TYPE_SUBSTITUTION, SHELL_TYPE_SIMPLE,
       SHELL_FEAT_PROCESS_SUB},
      {"while true", 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE, SHELL_FEAT_LOOPS},
      {"if true", 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE,
       SHELL_FEAT_CONDITIONALS},
      {"case value", 1, SHELL_TYPE_SIMPLE, SHELL_TYPE_SIMPLE, SHELL_FEAT_CASE},
      {"echo $(<file)", 1, SHELL_TYPE_SUBSTITUTION, SHELL_TYPE_SIMPLE,
       SHELL_FEAT_SUBSHELL | SHELL_FEAT_SUBSHELL_FILE},
  };
  for (const oracle_case &item : cases) {
    shell_parse_result_t fast = {};
    if (shell_parse_fast(item.input, strlen(item.input), NULL, &fast) !=
            SHELL_OK ||
        fast.count != item.count || fast.cmds[0].type != item.first_type ||
        (item.features != 0 &&
         (fast.cmds[0].features & item.features) != item.features) ||
        (item.count > 1 && fast.cmds[1].type != item.second_type))
      return 1;
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    bool ok = shell_tokenize_commands(item.input, &commands, &command_count);
    shell_free_commands(commands, command_count);
    if (!ok || command_count != item.count)
      return 1;
  }
  static const char *const invalid[] = {"echo é"};
  for (const char *input : invalid) {
    shell_parse_result_t fast = {};
    if (shell_parse_fast(input, strlen(input), NULL, &fast) != SHELL_EPARSE ||
        !(fast.status & SHELL_STATUS_ERROR))
      return 1;
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    if (shell_tokenize_commands(input, &commands, &command_count)) {
      shell_free_commands(commands, command_count);
      return 1;
    }
    shell_free_commands(commands, command_count);
  }
  struct full_feature_case {
    const char *input;
    bool loops;
    bool conditionals;
    bool case_stmt;
  };
  static const full_feature_case full_cases[] = {
      {"while true", true, false, false},
      {"if true", false, true, false},
      {"case value", false, false, true},
  };
  for (const full_feature_case &item : full_cases) {
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    if (!shell_tokenize_commands(item.input, &commands, &command_count) ||
        command_count == 0 || commands[0].has_loops != item.loops ||
        commands[0].has_conditionals != item.conditionals ||
        commands[0].has_case != item.case_stmt) {
      shell_free_commands(commands, command_count);
      return 1;
    }
    shell_free_commands(commands, command_count);
  }
  return 0;
}

static int test_plain_differential(const char *input, size_t length) {
  if (length == 0)
    return 0;
  bool plain = false;
  bool at_word_start = true;
  size_t word_start = 0;

  /* The fast parser deliberately reports shell control forms such as
   * "while ... do ..." as parse errors.  They are not plain commands even
   * when every byte happens to belong to the plain-character set below. */
  auto is_reserved_word = [](const char *word, size_t word_length) {
    static const char *const reserved[] = {
        "if",    "then",     "else",   "elif", "fi",    "for",
        "while", "until",    "do",     "done", "case",  "esac",
        "in",    "function", "select", "time", "coproc"};
    for (const char *candidate : reserved) {
      if (strlen(candidate) == word_length &&
          memcmp(candidate, word, word_length) == 0)
        return true;
    }
    return false;
  };

  for (size_t i = 0; i < length; i++) {
    unsigned char c = (unsigned char)input[i];
    if (isalnum(c) || c == '_' || c == '-' || c == '.' || c == '/' ||
        c == ' ' || c == '\t') {
      plain = plain || !isspace(c);
      if (isspace(c)) {
        if (!at_word_start &&
            is_reserved_word(input + word_start, i - word_start))
          return 0;
        at_word_start = true;
      } else if (at_word_start) {
        word_start = i;
        at_word_start = false;
      }
      continue;
    }
    if (!at_word_start &&
        is_reserved_word(input + word_start, length - word_start))
      return 0;
    return 0;
  }
  if (!at_word_start &&
      is_reserved_word(input + word_start, length - word_start))
    return 0;
  if (!plain)
    return 0;

  shell_parse_result_t fast = {};
  if (shell_parse_fast(input, length, NULL, &fast) != SHELL_OK ||
      fast.count != 1)
    return 1;
  shell_command_t *commands = NULL;
  size_t command_count = 0;
  bool full_ok = shell_tokenize_commands(input, &commands, &command_count);
  shell_free_commands(commands, command_count);
  if (!full_ok || command_count != 1)
    return 1;
  shell_command_info_t *infos = NULL;
  size_t info_count = 0;
  shell_process_status_t processed =
      shell_process_command(input, NULL, &infos, &info_count);
  shell_free_command_infos(infos, info_count);
  return processed != SHELL_PROCESS_OK || info_count != 1;
}

static int validate_depgraph(const char *input, size_t length,
                             shell_dep_error_t error,
                             const shell_dep_graph_t *graph,
                             const shell_dep_limits_t *limits);
static int test_full_parser(const char *input, size_t length);

static int test_structured_variants(const char *input, size_t length,
                                    uint32_t depth) {
  if (length == 0 || length > 256)
    return 0;
  std::string base(input, length);
  const std::string variants[] = {base + " | cat", "echo $(" + base + ")",
                                  "'" + base + "'"};
  for (const std::string &variant : variants) {
    shell_parse_result_t fast = {};
    shell_error_t fast_error =
        shell_parse_fast(variant.data(), variant.size(), NULL, &fast);
    if (validate_fast_result(variant.data(), variant.size(), fast_error, &fast,
                             SHELL_MAX_SUBCOMMANDS))
      return 1;
    shell_dep_graph_t graph = {};
    shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
    shell_dep_error_t dep_error = shell_parse_depgraph(
        variant.data(), variant.size(), ".", &limits, depth, &graph);
    if (validate_depgraph(variant.data(), variant.size(), dep_error, &graph,
                          &limits))
      return 1;
    if (test_full_parser(variant.c_str(), variant.size()))
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
  uint32_t max_cwd =
      limits->cwd_buf_size == 0
          ? SHELL_DEP_CWD_BUF_SIZE
          : std::min(limits->cwd_buf_size, (uint32_t)SHELL_DEP_CWD_BUF_SIZE);
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
      graph->cwd_buf.len > max_cwd ||
      (graph->cwd_buf.len > 0 &&
       graph->cwd_buf.data[graph->cwd_buf.len - 1] != '\0'))
    return 1;

  if (error == SHELL_DEP_EINPUT || error == SHELL_DEP_EPARSE)
    return graph->node_count != 0 || graph->edge_count != 0;
  if (!shell_dep_validate(graph).valid)
    return 1;

  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    if (edge->from >= graph->node_count || edge->to >= graph->node_count ||
        edge->type > SHELL_EDGE_CWD || edge->dir > SHELL_DIR_UNDIR)
      return 1;
  }

  for (uint32_t i = 0; i < graph->node_count; i++) {
    const shell_dep_node_t *node = &graph->nodes[i];
    if (node->type == SHELL_NODE_CMD) {
      if (node->cmd.token_count > max_tokens)
        return 1;
      if (node->cmd.cwd_offset >= graph->cwd_buf.len ||
          !memchr(graph->cwd_buf.data + node->cmd.cwd_offset, '\0',
                  graph->cwd_buf.len - node->cmd.cwd_offset))
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
      {0, 0, 0, 2, false},
      {4, 4, 2, 32, true},
      {SHELL_DEP_MAX_NODES, SHELL_DEP_MAX_EDGES, SHELL_DEP_MAX_TOKENS, 1,
       false},
      {SHELL_DEP_MAX_NODES, SHELL_DEP_MAX_EDGES, SHELL_DEP_MAX_TOKENS, 2,
       false},
      {SHELL_DEP_MAX_NODES, SHELL_DEP_MAX_EDGES, SHELL_DEP_MAX_TOKENS,
       SHELL_DEP_CWD_BUF_SIZE - 1, false},
      {SHELL_DEP_MAX_NODES, SHELL_DEP_MAX_EDGES, SHELL_DEP_MAX_TOKENS,
       SHELL_DEP_CWD_BUF_SIZE, false},
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

static int test_tokenizer_state(const char *input, size_t length) {
  shell_tokenizer_state_t state = {};
  shell_tokenizer_init(&state, input);

  size_t steps = 0;
  size_t previous_end = 0;
  std::vector<shell_token_t> iterated;
  bool terminated = false;
  while (steps++ <= length + 32) {
    shell_token_t token = {};
    bool produced = shell_tokenizer_next(&state, &token);
    if (!produced || token.type == TOKEN_END) {
      terminated = true;
      break;
    }
    if (token.type < TOKEN_COMMAND || token.type > TOKEN_HERESTRING ||
        token.position > length || token.length > length - token.position ||
        token.start != input + token.position || token.position < previous_end)
      return 1;
    iterated.push_back(token);
    previous_end = token.position + token.length;
  }
  if (!terminated)
    return 1;

  shell_command_t *commands = NULL;
  size_t command_count = 0;
  bool full_ok = shell_tokenize_commands(input, &commands, &command_count);
  if (!full_ok) {
    shell_free_commands(commands, command_count);
    return 0;
  }
  size_t expected = 0;
  for (size_t i = 0; i < command_count; i++)
    expected += commands[i].token_count;
  if (iterated.size() != expected) {
    shell_free_commands(commands, command_count);
    return 1;
  }
  size_t offset = 0;
  for (size_t i = 0; i < command_count; i++) {
    for (size_t j = 0; j < commands[i].token_count; j++, offset++) {
      const shell_token_t &a = iterated[offset];
      const shell_token_t &b = commands[i].tokens[j];
      if (a.type != b.type || a.position != b.position ||
          a.length != b.length || a.is_quoted != b.is_quoted ||
          a.is_escaped != b.is_escaped) {
        shell_free_commands(commands, command_count);
        return 1;
      }
    }
  }
  shell_free_commands(commands, command_count);
  return 0;
}

static int test_interop(const char *input, size_t length) {
  shell_interop_handle_t *handle = shell_interop_create();
  if (!handle)
    return 0;

  int count = shell_interop_parse(handle, input, (int)length);
  if (count < -1 || (count == -1 && length < SHELL_INTEROP_BUFFER_SIZE))
    goto fail;
  if (count > 0) {
    if (shell_interop_subcommand_count(handle) != count)
      goto fail;
    for (int i = -1; i <= count; i++) {
      int type = shell_interop_subcommand_type(handle, i);
      int features = shell_interop_subcommand_features(handle, i);
      int start = shell_interop_subcommand_start(handle, i);
      int len = shell_interop_subcommand_len(handle, i);
      char *text = shell_interop_subcommand_str(handle, i);
      if (i < 0 || i == count) {
        if (type != 0 || features != 0 || start != 0 || len != 0 ||
            text != NULL) {
          goto fail;
        }
      } else {
        if (type < 0 || features < 0 || start < 0 || len <= 0 ||
            (size_t)start > length || (size_t)len > length - (size_t)start ||
            !text || strlen(text) != (size_t)len) {
          goto fail;
        }
        shell_interop_free_str(text);
      }
    }
  } else if (shell_interop_subcommand_count(handle) != 0 ||
             shell_interop_subcommand_type(handle, 0) != 0 ||
             shell_interop_subcommand_features(handle, 0) != 0 ||
             shell_interop_subcommand_start(handle, 0) != 0 ||
             shell_interop_subcommand_len(handle, 0) != 0 ||
             shell_interop_subcommand_str(handle, 0) != NULL) {
    goto fail;
  }

  {
    char *features = shell_interop_features_str(UINT16_MAX);
    char *type = shell_interop_type_str(UINT16_MAX);
    if (!features || !type) {
      shell_interop_free_str(features);
      shell_interop_free_str(type);
      goto fail;
    }
    shell_interop_free_str(features);
    shell_interop_free_str(type);
  }
  /* Reuse the handle after both a successful and an invalid/empty parse. */
  if (shell_interop_parse(handle, "echo ok", 7) != 1 ||
      shell_interop_subcommand_count(handle) != 1 ||
      shell_interop_parse(handle, NULL, 0) != 0 ||
      shell_interop_subcommand_count(handle) != 0 ||
      shell_interop_subcommand_str(handle, 0) != NULL)
    goto fail;
  shell_interop_destroy(handle);
  return 0;

fail:
  shell_interop_destroy(handle);
  return 1;
}

static int test_abstraction(const char *input, size_t length) {
  if (length == 0)
    return shell_classify_raw_token(NULL, 0) == TOKEN_END ? 0 : 1;

  (void)shell_classify_raw_token(input, length);
  abstracted_command_t *command = NULL;
  bool success = shell_abstract_command(input, &command);
  if (!success)
    return command != NULL;
  if (!command || !shell_get_original(command) ||
      !shell_get_abstracted(command)) {
    shell_abstracted_destroy(command);
    return 1;
  }

  size_t count = 0;
  abstract_element_t **elements = shell_get_elements(command, &count);
  if (count > 0 && !elements) {
    shell_abstracted_destroy(command);
    return 1;
  }

  if (shell_get_element_at(command, count) != NULL ||
      shell_get_element_by_abstract(command, "__missing__") != NULL ||
      shell_has_variables(command) != command->has_variables ||
      shell_has_pos_vars(command) != command->has_pos_vars ||
      shell_has_special_vars(command) != command->has_special_vars ||
      shell_has_globs(command) != command->has_globs ||
      shell_has_paths(command) != command->has_paths ||
      shell_has_abs_paths(command) != command->has_abs_paths ||
      shell_has_rel_paths(command) != command->has_rel_paths ||
      shell_has_home_paths(command) != command->has_home_paths ||
      shell_has_cmd_subst(command) != command->has_cmd_subst ||
      shell_has_redirects(command) != command->has_redirects ||
      shell_has_strings(command) != command->has_strings ||
      shell_has_arithmetic(command) != command->has_arithmetic) {
    shell_abstracted_destroy(command);
    return 1;
  }

  char home[] = "HOME=/tmp";
  char *env[] = {home, NULL};
  for (size_t i = 0; i < count; i++) {
    if (!elements[i] || elements[i]->start > length ||
        elements[i]->end < elements[i]->start || elements[i]->end > length) {
      shell_abstracted_destroy(command);
      return 1;
    }
    if (elements[i]->abstraction &&
        shell_get_element_by_abstract(command, elements[i]->abstraction) !=
            elements[i]) {
      shell_abstracted_destroy(command);
      return 1;
    }
  }
  runtime_context_t contexts[] = {{env, (char *)"/tmp", false},
                                  {env, NULL, false},
                                  {env, (char *)".", true},
                                  {NULL, (char *)"/tmp", true}};
  for (runtime_context_t &context : contexts) {
    for (size_t i = 0; i < count; i++) {
      char *expanded = shell_expand_element(elements[i], &context);
      if (expanded)
        (void)shell_get_path_category(expanded);
      free(expanded);
    }
    if (!shell_expand_all_elements(command, &context)) {
      shell_abstracted_destroy(command);
      return 1;
    }
  }
  shell_abstracted_destroy(command);
  return 0;
}

static int test_data_helpers(const char *input, size_t length,
                             uint8_t selector) {
  /* Entropy calculations scan fixed 256x256 frequency tables.  Rotate the
   * sample shapes across inputs so every mode is exercised without making
   * the unified smoke target dominated by helper cost. */
  if ((selector & 3u) != 0)
    return 0;
  size_t sample_length = std::min(length, (size_t)32);
  std::string sample(input, sample_length);
  for (char &byte : sample)
    if (byte == '\0')
      byte = 'x';
  const std::string samples[] = {sample, "", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"};
  const std::string &value = samples[(selector >> 2) % 3];
  const char *text = value.c_str();
  int permutations = 1 + (value.size() % 3);
  double first = ngram_entropy(text, 1);
  if (!isfinite(first) || first != ngram_entropy(text, 1) ||
      !isfinite(ngram_entropy(text, 2)) ||
      !isfinite(conditional_entropy(text)) ||
      !isfinite(permutation_entropy(text, permutations, 1)) ||
      !isfinite(permutation_conditional_entropy(text, permutations)) ||
      !isfinite(relative_entropy_ratio(text, permutations, 2)) ||
      !isfinite(relative_conditional_entropy(text, permutations)))
    return 1;
  (void)env_screener_calculate_entropy(text);
  (void)env_screener_is_secret_pattern(text);
  (void)env_screener_is_whitelisted(text);
  (void)env_screener_combined_score(text);
  (void)env_screener_combined_score_name("FUZZ_KEY", text);
  (void)looks_like_path(text);
  (void)looks_like_base64(text);
  double suffix = 0.0;
  (void)check_secret_prefix(text, &suffix);
  for (int capacity : {0, 1, 8}) {
    int indices[8] = {0};
    int count = 0;
    env_screener_status_t status =
        env_screener_scan(indices, capacity, &count, 0.5, 8);
    if (status != ENV_SCREENER_OK && status != ENV_SCREENER_BUFFER_TOO_SMALL)
      return 1;
    if (count < 0 || (status == ENV_SCREENER_OK && count > capacity))
      return 1;
  }
  return 0;
}

// Test transformer
static int test_transformer(const char *input) {
  transformed_command_t **transformed_cmds = NULL;
  size_t transformed_count = 0;

  static const shell_transform_limits_t limits = {1u << 20, 4u << 20};
  shell_transform_status_t status = shell_transform_command_line(
      input, &limits, &transformed_cmds, &transformed_count);
  bool success = status == SHELL_TRANSFORM_OK;

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
          shell_has_transformations(tcmd) != tcmd->has_transformations) {
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
static int test_processor(const char *input) {
  shell_command_info_t *infos = NULL;
  size_t command_count = 0;
  static const shell_process_limits_t limits = {1u << 20, 4u << 20};
  shell_process_status_t status =
      shell_process_command(input, &limits, &infos, &command_count);
  bool success = status == SHELL_PROCESS_OK;
  const char **dfa_inputs = NULL;
  size_t dfa_input_count = 0;
  bool has_shell_features = false;
  shell_process_status_t extracted_status = shell_extract_dfa_inputs(
      input, &limits, &dfa_inputs, &dfa_input_count, &has_shell_features);
  bool extracted = extracted_status == SHELL_PROCESS_OK;

  if (success != extracted) {
    shell_free_command_infos(infos, command_count);
    free_dfa_inputs(dfa_inputs, dfa_input_count);
    return 1;
  }
  if (!success) {
    if (status != extracted_status &&
        !(status == SHELL_PROCESS_EPARSE &&
          extracted_status == SHELL_PROCESS_EPARSE)) {
      shell_free_command_infos(infos, command_count);
      free_dfa_inputs(dfa_inputs, dfa_input_count);
      return 1;
    }
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

static int test_output_limits(const char *input) {
  static const shell_process_limits_t process_limits = {8, 16};
  static const shell_transform_limits_t transform_limits = {8, 16};

  shell_command_info_t *infos = NULL;
  size_t info_count = 0;
  shell_process_status_t process_status =
      shell_process_command(input, &process_limits, &infos, &info_count);
  if (process_status != SHELL_PROCESS_OK &&
      process_status != SHELL_PROCESS_EINPUT &&
      process_status != SHELL_PROCESS_EPARSE &&
      process_status != SHELL_PROCESS_ENOMEM &&
      process_status != SHELL_PROCESS_EOVERFLOW &&
      process_status != SHELL_PROCESS_EOUTPUT_LIMIT) {
    shell_free_command_infos(infos, info_count);
    return 1;
  }
  shell_free_command_infos(infos, info_count);

  transformed_command_t **transformed = NULL;
  size_t transformed_count = 0;
  shell_transform_status_t transform_status = shell_transform_command_line(
      input, &transform_limits, &transformed, &transformed_count);
  if (transform_status != SHELL_TRANSFORM_OK &&
      transform_status != SHELL_TRANSFORM_EINPUT &&
      transform_status != SHELL_TRANSFORM_EPARSE &&
      transform_status != SHELL_TRANSFORM_ENOMEM &&
      transform_status != SHELL_TRANSFORM_EOVERFLOW &&
      transform_status != SHELL_TRANSFORM_EOUTPUT_LIMIT) {
    shell_free_transformed_commands(transformed, transformed_count);
    free(transformed);
    return 1;
  }
  shell_free_transformed_commands(transformed, transformed_count);
  free(transformed);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static bool fixed_oracles_checked = false;
  if (!fixed_oracles_checked) {
    if (test_fixed_oracles())
      abort();
    fixed_oracles_checked = true;
  }

  /* Metadata is derived without consuming command bytes.  Every byte in the
   * fuzz input must remain available to the parsers, including short and
   * malformed prefixes. */
  uint8_t cwd_selector = size > 0 ? data[0] : 0;
  uint8_t depth_byte = size > 1 ? data[1] : 0;
  /* depth is a recursion cap: shell_parse_depgraph rejects values > 16 with
   * SHELL_DEP_EPARSE (shell_depgraph.c:670). Map a byte to [0, 31] so the
   * fuzzer can find the boundary and exercise both sides. */
  uint32_t depth = depth_byte >> 3;

  /* Derive a CWD without consuming payload bytes, so every remaining byte
   * remains available to the parsers. */
  constexpr size_t kMaxCwdBytes = 32;
  const char *cwd;
  char random_cwd_buf[kMaxCwdBytes];
  if (cwd_selector < (uint8_t)(kCwdStrategiesN * 2)) {
    cwd = kCwdStrategies[cwd_selector / 2];
  } else {
    std::string s(reinterpret_cast<const char *>(data), size);
    size_t n = std::min(s.size(), kMaxCwdBytes - 1);
    size_t nul = s.find('\0');
    size_t copy = (nul == std::string::npos) ? n : std::min(n, nul);
    if (copy == 0) {
      cwd = ".";
    } else {
      memcpy(random_cwd_buf, s.data(), copy);
      random_cwd_buf[copy] = '\0';
      cwd = random_cwd_buf;
    }
  }

  /* Remaining bytes become the command. Length-based APIs receive the raw
   * payload; NUL-terminated APIs receive a separate textual view. */
  std::string cmd(reinterpret_cast<const char *>(data), size);
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
  auto run_check = [&failed](const char *name, int result) {
    if (result) {
      failed = true;
      fprintf(stderr, "shellsplit fuzz invariant failed: %s\n", name);
    }
  };
  run_check("fast parser", test_fast_parser(cmd.data(), cmd.size()));
  run_check("dependency graph",
            test_depgraph(cmd.data(), cmd.size(), cwd, depth));
  run_check("full parser", test_full_parser(input, text_length));
  run_check("tokenizer iterator", test_tokenizer_state(input, text_length));
  run_check("transformer", test_transformer(input));
  run_check("processor", test_processor(input));
  run_check("output limits", test_output_limits(input));
  run_check("interop", test_interop(cmd.data(), cmd.size()));
  run_check("abstraction", test_abstraction(input, text_length));
  run_check("entropy/environment helpers",
            test_data_helpers(input, text_length, cwd_selector));
  run_check("plain differential", test_plain_differential(input, text_length));
  run_check("structured variants",
            test_structured_variants(input, text_length, depth));
  free(input);
  if (failed)
    abort();

  return 0;
}

} // extern "C"
