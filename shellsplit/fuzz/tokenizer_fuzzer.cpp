// LibFuzzer harness for shellsplit - fuzzes all parsers
// Fuzzes: fast parser, full parser, transformer, processor

#include "brace_fuzz_case.h"

#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../tests/depgraph_compare.h"
#include "../tests/malformed_source_cases.h"
#include "../tests/source_compare.h"
#include "../tests/word_byte_cases.h"
#include "../tests/word_expansion_cases.h"
#include "depgraph_invariants.h"
#include "env_screener.h"
#include "relative_permutation_entropy.h"
#include "shell_abstract.h"
#include "shell_depgraph.h"
#include "shell_interop.h"
#include "shell_netstring.h"
#include "shell_processor.h"
#include "shell_sequence.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include "shell_transform.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include "../src/shell_depgraph_internal.h"
#include "../src/shell_source_internal.h"
#include "../src/shell_tokenizer_full_internal.h"
#include "shell_source.h"

static const size_t MAX_INPUT_SIZE = 8192;
static int g_verbose = 0;

static int test_generated_brace_case(const uint8_t *data, size_t size,
                                     const char *cwd);
static int test_tokenizer_state(const char *input, size_t length);
static int test_transformer(const char *input, size_t input_length);
static int test_processor(const char *input, size_t length);
static bool
processed_argv_matches_sequence(const shell_processed_commands_t &processed,
                                const void *sequence, size_t sequence_length,
                                size_t count);

static bool token_logically_equals(const shell_token_t &token,
                                   const char *spelling) {
  if (!token.start || !spelling)
    return false;
  size_t source = 0;
  size_t expected = 0;
  while (source < token.length) {
    if (token.start[source] == '\\' && source + 1 < token.length &&
        token.start[source + 1] == '\n') {
      source += 2;
      continue;
    }
    if (spelling[expected] == '\0' || token.start[source] != spelling[expected])
      return false;
    source++;
    expected++;
  }
  return spelling[expected] == '\0';
}

static bool tokenizer_semantic_type_matches(const shell_token_t &lexical,
                                            const shell_token_t &structured) {
  if (structured.type == SHELL_TOKEN_PIPE_NEGATE)
    return (lexical.type == SHELL_TOKEN_PIPE_NEGATE ||
            lexical.type == SHELL_TOKEN_COMMAND ||
            lexical.type == SHELL_TOKEN_ARGUMENT) &&
           token_logically_equals(lexical, "!");
  if (structured.type == SHELL_TOKEN_PIPE_TIME)
    return (lexical.type == SHELL_TOKEN_COMMAND ||
            lexical.type == SHELL_TOKEN_ARGUMENT) &&
           token_logically_equals(lexical, "time");
  if (structured.type == SHELL_TOKEN_PIPE_TIME_OPTION)
    return (lexical.type == SHELL_TOKEN_COMMAND ||
            lexical.type == SHELL_TOKEN_ARGUMENT) &&
           (token_logically_equals(lexical, "-p") ||
            token_logically_equals(lexical, "--"));
  return lexical.type == structured.type;
}

/* A compound pipeline owns leading `!`/`time` syntax on the compound
 * descriptor, while the allocating tokenizer deliberately exposes only its
 * flattened simple-command records.  The lexical iterator still sees those
 * words.  Keep this exception narrowly source-derived: an unconsumed iterator
 * token may be skipped only when the shared prefix parser proves that it is
 * part of a modifier sequence immediately followed by a compound opener.
 *
 * In particular, do not derive visibility from the command records under
 * test.  Doing that would let a tokenizer regression shrink a command span
 * and silently remove the corresponding lexical token from both sides of the
 * differential check. */
struct tokenizer_structural_prefix_span {
  size_t start;
  size_t end;
};

static bool
tokenizer_structural_prefix_starts_at(const char *input, size_t length,
                                      const shell_token_t &token,
                                      tokenizer_structural_prefix_span *out) {
  if (!input || !out || token.position > length ||
      token.length > length - token.position)
    return false;
  size_t prefix_end = 0;
  if (!shell_tokenizer_compound_prefix_span(input, length, token.position,
                                            &prefix_end))
    return false;
  out->start = token.position;
  out->end = prefix_end;
  return true;
}

static bool tokenizer_token_is_structural_prefix(
    const shell_token_t &token,
    const std::vector<tokenizer_structural_prefix_span> &prefixes) {
  for (const tokenizer_structural_prefix_span &prefix : prefixes)
    if (token.position >= prefix.start && token.position <= prefix.end &&
        token.length <= prefix.end - token.position)
      return true;
  return false;
}

static bool tokenizer_iterated_matches_structured(
    const char *input, size_t length,
    const std::vector<shell_token_t> &iterated, const shell_command_t *commands,
    size_t command_count) {
  if (!input || !commands || command_count == 0)
    return false;
  std::vector<tokenizer_structural_prefix_span> structural_prefixes;
  for (const shell_token_t &token : iterated) {
    tokenizer_structural_prefix_span prefix = {};
    if (tokenizer_structural_prefix_starts_at(input, length, token, &prefix))
      structural_prefixes.push_back(prefix);
  }

  std::vector<const shell_token_t *> structured;
  for (size_t i = 0; i < command_count; i++) {
    if (commands[i].start_pos > commands[i].end_pos ||
        commands[i].end_pos > length)
      return false;
    for (size_t token = 0; token < commands[i].token_count; token++) {
      const shell_token_t &item = commands[i].tokens[token];
      if (item.position < commands[i].start_pos ||
          item.position > commands[i].end_pos ||
          item.length > commands[i].end_pos - item.position)
        return false;
      structured.push_back(&item);
    }
  }

  /* Compare both streams in source order.  A mismatch is acceptable only for
   * a proven compound-owned prefix as described above; every ordinary lexical
   * word and operator must have a matching structured token. */
  size_t offset = 0;
  for (const shell_token_t &token : iterated) {
    if (offset < structured.size()) {
      const shell_token_t &expected = *structured[offset];
      bool same_type = tokenizer_semantic_type_matches(token, expected);
      if (same_type && token.position == expected.position &&
          token.length == expected.length &&
          token.is_quoted == expected.is_quoted &&
          token.is_escaped == expected.is_escaped) {
        offset++;
        continue;
      }
    }
    if (!tokenizer_token_is_structural_prefix(token, structural_prefixes))
      return false;
  }
  return offset == structured.size();
}

static shell_dep_error_t fuzz_dep_graph_parse(const char *cmd, size_t cmd_len,
                                              const char *initial_cwd,
                                              const shell_dep_limits_t *limits,
                                              shell_dep_graph_t *out);

static void tokenizer_observe_semantic_token(const shell_token_t *token,
                                             void *context) {
  (void)token;
  (void)context;
}

static void tokenizer_observe_read_fd(const char *word, uint32_t fd,
                                      unsigned kind, const char *parameter,
                                      size_t length, bool identity,
                                      void *context) {
  (void)word;
  (void)fd;
  (void)kind;
  (void)parameter;
  (void)length;
  (void)identity;
  (void)context;
}

static void tokenizer_observe_process(const char *word, size_t length,
                                      void *context) {
  (void)word;
  (void)length;
  (void)context;
}

static bool tokenizer_unsupported_semantics_rejected(const char *input,
                                                     size_t length) {
  shell_processed_commands_t processed = {};
  shell_netstring_buffer_t sequence = {};
  size_t sequence_count = 0;
  bool has_features = false;
  shell_transformed_command_t **transformed = nullptr;
  size_t transformed_count = 0;
  shell_abstract_command_t *abstract = nullptr;
  shell_dep_graph_t graph = {};

  bool source_only = false;
  bool definitely_unsupported = shell_tokenizer_inspect_semantics(
      input, length, tokenizer_observe_semantic_token,
      tokenizer_observe_read_fd, tokenizer_observe_process, &source_only);
  const shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  shell_dep_error_t graph_status =
      fuzz_dep_graph_parse(input, length, ".", &limits, &graph);
  /* Only explicitly deferred read interpretations may differ. They must
   * still produce a complete validated graph or a valid rejection/truncation;
   * fixed oracles separately assert contextual acceptance and rejection. */
  bool graph_contract =
      definitely_unsupported
          ? graph_status == SHELL_DEP_EPARSE && graph.node_count == 0 &&
                graph.edge_count == 0 && graph.status == SHELL_DEP_STATUS_ERROR
          : graph_status != SHELL_DEP_EWORKSPACE &&
                shellsplit_test_depgraph_invariants(input, length, graph_status,
                                                    &graph, &limits);
  bool rejected =
      graph_contract &&
      shell_process_commands(input, length, nullptr, &processed) ==
          SHELL_PROCESS_EPARSE &&
      processed.commands == nullptr && processed.command_count == 0 &&
      processed.groups == nullptr && processed.group_count == 0 &&
      processed.group_io_ops == nullptr && processed.group_io_op_count == 0 &&
      shell_build_netargv_sequence_buffer(input, length, nullptr, &sequence,
                                          &sequence_count, &has_features) ==
          SHELL_PROCESS_EPARSE &&
      sequence.data == nullptr && sequence_count == 0 && !has_features &&
      shell_transform_command_line(input, length, nullptr, &transformed,
                                   &transformed_count) ==
          SHELL_TRANSFORM_EPARSE &&
      transformed == nullptr && transformed_count == 0 &&
      shell_abstract_command_parse(input, length, &abstract) ==
          SHELL_ABSTRACT_EPARSE &&
      abstract == nullptr;

  shell_processed_commands_free(&processed);
  shell_netstring_buffer_free(&sequence);
  shell_transformed_command_list_free(transformed, transformed_count);
  shell_abstract_command_free(abstract);
  return rejected;
}

static bool tokenizer_structured_has_span(const shell_command_t *commands,
                                          size_t command_count, size_t position,
                                          size_t length) {
  for (size_t command = 0; command < command_count; command++)
    for (size_t token = 0; token < commands[command].token_count; token++) {
      const shell_token_t &current = commands[command].tokens[token];
      if (current.position == position && current.length == length)
        return true;
    }
  return false;
}

/* Unsupported shell semantics still have valid shell grammar. Their
 * diagnostic records must preserve words and operators throughout. Keep this as
 * a fixed oracle rather than depending on mutations to rediscover every
 * surrounding context. */
static bool tokenizer_unsupported_context_visible(const char *input) {
  if (!input)
    return false;
  size_t length = strlen(input);
  const char *first_echo = strstr(input, "echo");
  const char *before = strstr(input, "before");
  const char *second_echo = first_echo ? strstr(first_echo + 1, "echo") : NULL;
  const char *after = strstr(input, "after");
  const char *pipe = strrchr(input, '|');
  const char *cat = pipe ? strstr(pipe + 1, "cat") : NULL;
  shell_command_t *commands = NULL;
  size_t command_count = 0;
  bool visible =
      first_echo != NULL && before != NULL && second_echo != NULL &&
      after != NULL && pipe != NULL && cat != NULL &&
      shell_tokenizer_list_syntax_valid(input, length) &&
      shell_tokenizer_has_unsupported_semantics(input, length) &&
      tokenizer_unsupported_semantics_rejected(input, length) &&
      shell_tokenize_commands(input, length, &commands, &command_count) ==
          SHELL_TOKENIZE_OK &&
      tokenizer_structured_has_span(commands, command_count,
                                    (size_t)(first_echo - input),
                                    strlen("echo")) &&
      tokenizer_structured_has_span(commands, command_count,
                                    (size_t)(before - input),
                                    strlen("before")) &&
      tokenizer_structured_has_span(commands, command_count,
                                    (size_t)(second_echo - input),
                                    strlen("echo")) &&
      tokenizer_structured_has_span(commands, command_count,
                                    (size_t)(after - input), strlen("after")) &&
      tokenizer_structured_has_span(commands, command_count,
                                    (size_t)(pipe - input), strlen("|")) &&
      tokenizer_structured_has_span(commands, command_count,
                                    (size_t)(cat - input), strlen("cat"));
  shell_commands_free(commands, command_count);
  return visible;
}

/* CWD strategies for shell_dep_graph_parse. NULL tests the early substitution
 * to
 * "." inside the parser; the rest cover the realistic path shapes used in
 * existing depgraph tests plus a few edge cases. */
static const char *kCwdStrategies[] = {
    nullptr, "/home/user", "/tmp", "$HOME/long/nested/path", "a/../b//c", "."};
constexpr int kCwdStrategiesN =
    sizeof(kCwdStrategies) / sizeof(kCwdStrategies[0]);

/* Fuzzing is a caller too: keep resolver storage explicit and reuse it across
 * inputs instead of relying on the library to allocate a hidden multi-MiB
 * route table. */
static std::vector<std::max_align_t> g_depgraph_workspace;

/* Existing reference fixtures describe internal document/pipe relations.
 * Boundary routing has a separate fixed oracle and is never projected out of
 * the graph or its complete independent invariants. */
static bool internal_graph_relation(const shell_dep_graph_t &graph,
                                    const shell_dep_edge_t &edge) {
  return graph.nodes[edge.from].type != SHELL_NODE_FD &&
         graph.nodes[edge.to].type != SHELL_NODE_FD &&
         !(graph.nodes[edge.from].type == SHELL_NODE_DOC &&
           (graph.nodes[edge.from].doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT)) &&
         !(graph.nodes[edge.to].type == SHELL_NODE_DOC &&
           (graph.nodes[edge.to].doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT));
}

static bool fuzz_dep_limits(const shell_dep_limits_t *limits,
                            shell_dep_limits_t *effective) {
  if (!effective)
    return false;
  *effective = limits ? *limits : SHELL_DEP_LIMITS_DEFAULT;
  if (effective->workspace)
    return true;
  size_t required = 0;
  size_t alignment = shell_dep_workspace_alignment();
  if (!shell_dep_workspace_size(effective, &required) || alignment == 0 ||
      alignment > alignof(std::max_align_t))
    return false;
  size_t units =
      (required + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t);
  g_depgraph_workspace.resize(units);
  effective->workspace = g_depgraph_workspace.data();
  effective->workspace_size = units * sizeof(std::max_align_t);
  return true;
}

static shell_dep_error_t fuzz_dep_graph_parse(const char *cmd, size_t cmd_len,
                                              const char *initial_cwd,
                                              const shell_dep_limits_t *limits,
                                              shell_dep_graph_t *out) {
  shell_dep_limits_t effective;
  if (!fuzz_dep_limits(limits, &effective))
    return SHELL_DEP_EWORKSPACE;
  return shell_dep_graph_parse(cmd, cmd_len, initial_cwd, &effective, out);
}

#define shell_dep_graph_parse fuzz_dep_graph_parse

static void run_fixed_oracles();
static int test_draft_closed_children(uint8_t selector, uint8_t value);
static int test_draft_redirect_operand(uint8_t selector, uint8_t value);
static int test_draft_redirector_prefix(uint8_t selector, uint8_t value);
static int test_draft_nested_redirect(uint8_t selector, uint8_t value);

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  const char *verbose = getenv("SHELLSPLIT_FUZZ_VERBOSE");
  if (verbose && (*verbose == '1' || *verbose == 'y' || *verbose == 'Y')) {
    g_verbose = 1;
  }
  run_fixed_oracles();
  if (g_verbose) {
    fprintf(stderr, "DEBUG: ShellSplit fuzzer initialized\n");
  }
  return 0;
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

  if (result->count > max_commands || result->group_count > SHELL_MAX_GROUPS) {
    if (g_verbose)
      fprintf(stderr, "\n=== FAST PARSER ERROR: Invalid count %u ===\n",
              result->count);
    return 1;
  }

  static const uint16_t valid_types =
      SHELL_TYPE_PIPELINE | SHELL_TYPE_AND | SHELL_TYPE_OR |
      SHELL_TYPE_SEMICOLON | SHELL_TYPE_HEREDOC | SHELL_TYPE_HERESTRING |
      SHELL_TYPE_SUBSTITUTION | SHELL_TYPE_BACKGROUND;
  static const uint32_t valid_features =
      SHELL_FEAT_VARS | SHELL_FEAT_GLOBS | SHELL_FEAT_SUBSHELL |
      SHELL_FEAT_ARITH | SHELL_FEAT_HEREDOC | SHELL_FEAT_HERESTRING |
      SHELL_FEAT_PROCESS_SUB | SHELL_FEAT_LOOPS | SHELL_FEAT_CONDITIONALS |
      SHELL_FEAT_CASE | SHELL_FEAT_SUBSHELL_FILE | SHELL_FEAT_PIPELINE |
      SHELL_FEAT_GROUP | SHELL_FEAT_BACKGROUND | SHELL_FEAT_EXTGLOB |
      SHELL_FEAT_ANSI_C_QUOTE | SHELL_FEAT_ARRAY | SHELL_FEAT_NAMED_FD |
      SHELL_FEAT_COMBINED_REDIRECT;
  for (uint32_t i = 0; i < result->count; i++) {
    const shell_range_t *r = &result->cmds[i];
    bool known_type =
        r->type == SHELL_TYPE_SIMPLE || r->type == SHELL_TYPE_PIPELINE ||
        r->type == SHELL_TYPE_AND || r->type == SHELL_TYPE_OR ||
        r->type == SHELL_TYPE_SEMICOLON || r->type == SHELL_TYPE_HEREDOC ||
        r->type == SHELL_TYPE_HERESTRING ||
        r->type == SHELL_TYPE_SUBSTITUTION || r->type == SHELL_TYPE_BACKGROUND;
    if (r->len == 0 || r->start > length || r->len > length - r->start ||
        !known_type || (r->type & (uint16_t)~valid_types) != 0 ||
        (r->features & ~valid_features) != 0 ||
        (r->modifiers &
         ~(SHELL_CMD_MOD_PIPE_NEGATED | SHELL_CMD_MOD_PIPE_TIMED)) != 0 ||
        r->pipeline_time_mode > SHELL_PIPE_TIME_POSIX ||
        ((r->pipeline_time_mode != SHELL_PIPE_TIME_NONE) !=
         ((r->modifiers & SHELL_CMD_MOD_PIPE_TIMED) != 0)) ||
        (r->pipeline_time_direct &&
         r->pipeline_time_mode == SHELL_PIPE_TIME_NONE) ||
        r->pipe_input_mode > SHELL_PIPE_MODE_STDOUT_AND_STDERR) {
      if (g_verbose)
        fprintf(stderr,
                "\n=== FAST PARSER ERROR: Invalid range at idx %u ===\n", i);
      return 1;
    }

    char buf[256];
    size_t copied = shell_subcommand_copy(input, r, buf, sizeof(buf));
    size_t expected = r->len < sizeof(buf) ? r->len : sizeof(buf) - 1;
    if (copied != expected || buf[copied] != '\0' ||
        memcmp(buf, input + r->start, copied) != 0) {
      if (g_verbose)
        fprintf(stderr, "\n=== FAST PARSER ERROR: Copy overflow ===\n");
      return 1;
    }

    size_t out_len = 0;
    const char *ptr = shell_subcommand_view(input, r, &out_len);
    if (ptr != input + r->start || out_len != r->len) {
      if (g_verbose)
        fprintf(stderr, "\n=== FAST PARSER ERROR: Length mismatch ===\n");
      return 1;
    }
  }

  /* Truncation may expose an in-progress descriptor so callers can retain
   * completed command ranges. Full descriptor invariants apply only to a
   * successful parse. */
  if (err != SHELL_OK)
    return 0;
  for (uint32_t i = 0; i < result->group_count; i++) {
    const shell_group_t *group = &result->groups[i];
    if (group->start >= group->end || group->end > length ||
        group->first_command > result->count ||
        group->command_count > result->count - group->first_command ||
        (group->kind != SHELL_GROUP_BRACE &&
         group->kind != SHELL_GROUP_SUBSHELL) ||
        (group->modifiers &
         ~(SHELL_CMD_MOD_PIPE_NEGATED | SHELL_CMD_MOD_PIPE_TIMED)) != 0 ||
        group->pipeline_time_mode > SHELL_PIPE_TIME_POSIX ||
        ((group->pipeline_time_mode != SHELL_PIPE_TIME_NONE) !=
         ((group->modifiers & SHELL_CMD_MOD_PIPE_TIMED) != 0)) ||
        (group->pipeline_time_direct &&
         group->pipeline_time_mode == SHELL_PIPE_TIME_NONE) ||
        (group->parent != UINT16_MAX && group->parent >= i)) {
      if (g_verbose)
        fprintf(stderr, "\n=== FAST PARSER ERROR: Invalid group %u ===\n", i);
      return 1;
    }
    if (group->parent != UINT16_MAX) {
      const shell_group_t *parent = &result->groups[group->parent];
      if (group->start < parent->start || group->end > parent->end ||
          group->first_command < parent->first_command ||
          group->first_command + group->command_count >
              parent->first_command + parent->command_count) {
        if (g_verbose)
          fprintf(stderr,
                  "\n=== FAST PARSER ERROR: Group parent mismatch %u ===\n", i);
        return 1;
      }
    }
  }

  return 0;
}

// Test default, strict, and bounded fast-parser modes through one invariant
// matrix so every input exercises all public configurations.
static int test_fast_parser(const char *input, size_t length) {
  static const shell_limits_t limits[] = {
      SHELL_LIMITS_DEFAULT,
      {SHELL_MAX_SUBCOMMANDS, true, nullptr, 0},
      {1, false, nullptr, 0},
      {1, true, nullptr, 0},
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
static int fixed_oracle_failure(int line) {
  fprintf(stderr, "shellsplit fixed oracle failed at line %d\n", line);
  return 1;
}

/* These generated sources belong to the supported dialect by construction.
 * Equality of adapter failures is not an oracle: require acceptance, command
 * boundaries, canonical argv agreement, and the actual document read route. */
static int test_supported_document(const std::string &source, size_t commands,
                                   bool named) {
  shell_parse_result_t parsed = {};
  shell_limits_t limits = {SHELL_MAX_SUBCOMMANDS, true, nullptr, 0};
  shell_processed_commands_t processed = {};
  shell_netstring_buffer_t sequence = {}, raw = {}, typed = {};
  size_t count = 0, anomaly_count = 0;
  bool features = false;
  bool valid =
      shell_parse_fast(source.data(), source.size(), &limits, &parsed) ==
          SHELL_OK &&
      shell_process_commands(source.data(), source.size(), nullptr,
                             &processed) == SHELL_PROCESS_OK &&
      processed.command_count == commands &&
      shell_build_netargv_sequence_buffer(source.data(), source.size(), nullptr,
                                          &sequence, &count,
                                          &features) == SHELL_PROCESS_OK &&
      count == commands &&
      processed_argv_matches_sequence(processed, sequence.data, sequence.length,
                                      count) &&
      shell_build_anomaly_netseqs_buffer(source.data(), source.size(), nullptr,
                                         &raw, &typed,
                                         &anomaly_count) == SHELL_PROCESS_OK &&
      anomaly_count >= commands;
  shell_processed_commands_free(&processed);
  shell_netstring_buffer_free(&sequence);
  shell_netstring_buffer_free(&raw);
  shell_netstring_buffer_free(&typed);
  shell_dep_graph_t graph = {};
  valid = valid &&
          shell_dep_graph_parse(source.data(), source.size(), "/workspace",
                                nullptr, &graph) == SHELL_DEP_OK &&
          shell_dep_graph_validate(&graph).valid;
  size_t documents = 0, reads = 0, opens = 0;
  for (uint32_t i = 0; i < graph.node_count; i++) {
    const shell_dep_node_t &node = graph.nodes[i];
    if (node.type != SHELL_NODE_DOC || (node.doc.kind != SHELL_DOC_HEREDOC &&
                                        node.doc.kind != SHELL_DOC_HERESTRING))
      continue;
    documents++;
    for (uint32_t j = 0; j < graph.edge_count; j++) {
      const shell_dep_edge_t &edge = graph.edges[j];
      if (edge.from != i)
        continue;
      if (edge.type == SHELL_EDGE_READ) {
        reads++;
        valid = valid && edge.target_fd == 0 &&
                graph.nodes[edge.to].type == SHELL_NODE_CMD &&
                graph.nodes[edge.to].cmd.token_count != 0 &&
                graph.nodes[edge.to].cmd.token_lens[0] == 3 &&
                memcmp(graph.nodes[edge.to].cmd.tokens[0], "cat", 3) == 0;
      }
      if (edge.type == SHELL_EDGE_FD_OPEN) {
        opens++;
        valid = valid && edge.target_fd == SHELL_DEP_FD_NAMED &&
                edge.target_fd_name_len == 3 &&
                memcmp(edge.target_fd_name, "out", 3) == 0;
      }
    }
  }
  if (!valid || documents != 1 || reads != 1 || opens != (named ? 1u : 0u)) {
    fprintf(stderr, "supported document oracle failed: %s\n", source.c_str());
    return 1;
  }
  return 0;
}

static int test_generated_document_boundary(uint8_t selector) {
  static const char *const operands[] = {
      "body",           "'a)b'",         "a\\)b",  "$'a)b'",
      "$(printf body)", "${value:-a)b}", "@(a|b)", "\"a)b\""};
  const char *operand = operands[selector % 8];
  unsigned form = selector / 8 % 6;
  if (form < 3) {
    std::string source = form == 0 ? "(" : form == 1 ? "time (" : "(time -p (";
    source += "cat <<<";
    source += operand;
    source += form == 2 ? "))" : ")";
    return test_supported_document(source, 1, false);
  }
  std::string source = "exec {fd}>/dev/null; exec {fd}>&-";
  if (form == 5)
    source += "\\\n";
  source += "{out}";
  if (form == 4)
    source += "<<'EOF'; cat <&$out\nbody\nEOF\n";
  else {
    source += "<<<";
    source += operand;
    source += "; cat <&$out";
  }
  return test_supported_document(source, 3, true);
}

static int test_fixed_oracles(void) {
  for (const auto &fixture : shellsplit_test_substitution_status_cases) {
    for (unsigned success = 0; success < 2; success++) {
      std::string source =
          std::string(fixture.source) +
          (success ? " && echo >/etc/reached" : " || echo >/etc/reached");
      shell_dep_graph_t graph = {};
      if (shell_dep_graph_parse(source.data(), source.size(), ".", nullptr,
                                &graph) != SHELL_DEP_OK ||
          !shell_dep_graph_validate(&graph).valid)
        return fixed_oracle_failure(__LINE__);
      bool reached = false;
      for (uint32_t e = 0; e < graph.edge_count; e++) {
        const auto &edge = graph.edges[e];
        if (!internal_graph_relation(graph, edge))
          continue;
        const auto &target = graph.nodes[edge.to];
        reached |=
            edge.type == SHELL_EDGE_WRITE && target.type == SHELL_NODE_DOC &&
            target.doc.kind == SHELL_DOC_FILE && target.doc.path_len == 12 &&
            !std::memcmp(target.doc.path, "/etc/reached", 12);
      }
      if (reached != (success ? fixture.succeeds : fixture.fails)) {
        fprintf(stderr, "substitution status oracle: %s\n", source.c_str());
        return fixed_oracle_failure(__LINE__);
      }
    }
  }
  for (const auto &fixture : shellsplit_test_comment_words) {
    if (test_processor(fixture.source, std::strlen(fixture.source)))
      return fixed_oracle_failure(__LINE__);
  }
  for (const auto &fixture : shellsplit_test_expansion_time_routes) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(fixture.source, std::strlen(fixture.source), ".",
                              nullptr, &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    unsigned timers = 0;
    uint32_t writer = UINT32_MAX, file = UINT32_MAX;
    for (uint32_t n = 0; n < graph.node_count; n++) {
      const auto &node = graph.nodes[n];
      if (node.type == SHELL_NODE_CMD && node.cmd.token_count == 2 &&
          node.cmd.token_lens[0] == 6 &&
          !std::memcmp(node.cmd.tokens[0], "printf", 6) &&
          node.cmd.token_lens[1] == 7 &&
          !std::memcmp(node.cmd.tokens[1], "payload", 7))
        writer = n;
      if (node.type == SHELL_NODE_DOC && node.doc.kind == SHELL_DOC_FILE &&
          node.doc.path_len == 3 && !std::memcmp(node.doc.path, "out", 3))
        file = n;
      if (node.type != SHELL_NODE_TIME)
        continue;
      bool stdout_route = false, stderr_route = false;
      for (uint32_t f = 0; f < node.time.report_external_fd_count; f++) {
        stdout_route |= node.time.report_external_fds[f] == 1;
        stderr_route |= node.time.report_external_fds[f] == 2;
      }
      if (!stdout_route || stderr_route != fixture.stderr_possible ||
          node.time.report_external_fd_count != 1u + fixture.stderr_possible ||
          node.time.report_route_flags != SHELL_TIME_REPORT_ROUTE_EXTERNAL ||
          node.time.report_route != (fixture.stderr_possible
                                         ? SHELL_TIME_REPORT_MULTIPLE
                                         : SHELL_TIME_REPORT_EXTERNAL)) {
        std::fprintf(stderr, "expansion control oracle: %s\n", fixture.source);
        return fixed_oracle_failure(__LINE__);
      }
      timers++;
    }
    bool named_write = false;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const auto &edge = graph.edges[e];
      if (!internal_graph_relation(graph, edge))
        continue;
      named_write |= edge.type == SHELL_EDGE_WRITE && edge.from == writer &&
                     edge.to == file && edge.source_fd == 1;
    }
    if (!timers || named_write != fixture.named_write)
      return fixed_oracle_failure(__LINE__);
  }
  for (const auto &fixture : shellsplit_test_expansion_setup) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(fixture.source, std::strlen(fixture.source), ".",
                              nullptr, &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    bool file = false, writer = false, redirect = false;
    bool substitution = false, inspection = false;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const auto &edge = graph.edges[e];
      if (!internal_graph_relation(graph, edge))
        continue;
      if (edge.type == SHELL_EDGE_SUBST) {
        substitution = true;
        inspection |= (edge.flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0;
        const auto &from = graph.nodes[edge.from];
        file |= from.type == SHELL_NODE_DOC &&
                from.doc.kind == SHELL_DOC_FILE && from.doc.path_len == 5 &&
                !std::memcmp(from.doc.path, "input", 5);
      }
      if (edge.type == SHELL_EDGE_WRITE) {
        const auto &to = graph.nodes[edge.to];
        if (to.type != SHELL_NODE_DOC || to.doc.kind != SHELL_DOC_FILE)
          continue;
        writer |=
            to.doc.path_len == 8 && !std::memcmp(to.doc.path, "argv-out", 8);
        redirect |= to.doc.path_len == 12 &&
                    !std::memcmp(to.doc.path, "redirect-out", 12);
      }
    }
    if (file != (fixture.active && fixture.file) ||
        writer != (fixture.active && fixture.writer) ||
        inspection != (fixture.active && fixture.shell_word) || redirect ||
        (!fixture.active && substitution)) {
      std::fprintf(stderr, "expansion setup oracle: %s\n", fixture.source);
      return fixed_oracle_failure(__LINE__);
    }
  }
  for (const auto &fixture : shellsplit_test_exec_continuations) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(fixture.source, std::strlen(fixture.source), ".",
                              nullptr, &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    uint32_t writer = UINT32_MAX, file = UINT32_MAX;
    for (uint32_t n = 0; n < graph.node_count; n++) {
      const auto &node = graph.nodes[n];
      if (node.type == SHELL_NODE_CMD && node.cmd.token_count == 2 &&
          node.cmd.token_lens[0] == 6 &&
          !std::memcmp(node.cmd.tokens[0], "printf", 6) &&
          node.cmd.token_lens[1] == 7 &&
          !std::memcmp(node.cmd.tokens[1], "payload", 7))
        writer = n;
      if (node.type == SHELL_NODE_DOC && node.doc.kind == SHELL_DOC_FILE &&
          node.doc.path_len == 3 && !std::memcmp(node.doc.path, "out", 3))
        file = n;
    }
    bool writes = false;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const auto &edge = graph.edges[e];
      if (!internal_graph_relation(graph, edge))
        continue;
      writes |= edge.type == SHELL_EDGE_WRITE && edge.from == writer &&
                edge.to == file && edge.source_fd == 1;
    }
    if (writer == UINT32_MAX || file == UINT32_MAX || writes != fixture.writes)
      return fixed_oracle_failure(__LINE__);
  }
  for (const auto &fixture : shellsplit_test_assignment_snapshots) {
    shell_dep_graph_t graph = {};
    shell_dep_error_t error = shell_dep_graph_parse(
        fixture.source, std::strlen(fixture.source), ".", nullptr, &graph);
    if (fixture.resolved
            ? error != SHELL_DEP_OK || !shell_dep_graph_validate(&graph).valid
            : error != SHELL_DEP_EPARSE || graph.node_count ||
                  graph.edge_count) {
      fprintf(stderr, "assignment snapshot oracle: %s (error %d)\n",
              fixture.source, error);
      return fixed_oracle_failure(__LINE__);
    }
  }
  for (const auto &fixture : shellsplit_test_builtin_routes) {
    shell_dep_graph_t graph = {};
    shell_dep_error_t error = shell_dep_graph_parse(
        fixture.source, std::strlen(fixture.source), ".", nullptr, &graph);
    if (fixture.resolved
            ? error != SHELL_DEP_OK || !shell_dep_graph_validate(&graph).valid
            : error != SHELL_DEP_EPARSE || graph.node_count || graph.edge_count)
      return fixed_oracle_failure(__LINE__);
  }
  for (const auto &fixture : shellsplit_test_ifs_routes) {
    shell_dep_graph_t graph = {};
    shell_dep_error_t error = shell_dep_graph_parse(
        fixture.source, std::strlen(fixture.source), ".", nullptr, &graph);
    if (!fixture.supported) {
      if (error != SHELL_DEP_EPARSE || graph.node_count || graph.edge_count)
        return fixed_oracle_failure(__LINE__);
      continue;
    }
    if (error != SHELL_DEP_OK || !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    uint32_t writer = UINT32_MAX, document = UINT32_MAX;
    for (uint32_t n = 0; n < graph.node_count; n++) {
      const auto &node = graph.nodes[n];
      if (node.type == SHELL_NODE_CMD && node.cmd.token_count == 2 &&
          node.cmd.token_lens[0] == 6 && node.cmd.token_lens[1] == 7 &&
          !std::memcmp(node.cmd.tokens[0], "printf", 6) &&
          !std::memcmp(node.cmd.tokens[1], "payload", 7))
        writer = n;
      if (node.type == SHELL_NODE_DOC && node.doc.kind == SHELL_DOC_FILE &&
          node.doc.path_len == 3 && !std::memcmp(node.doc.path, "out", 3))
        document = n;
    }
    bool writes = false;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const auto &edge = graph.edges[e];
      if (!internal_graph_relation(graph, edge))
        continue;
      writes |= edge.type == SHELL_EDGE_WRITE && edge.from == writer &&
                edge.to == document && edge.source_fd == 1;
    }
    if (writer == UINT32_MAX || document == UINT32_MAX ||
        writes != fixture.writes)
      return fixed_oracle_failure(__LINE__);
  }
  for (const auto &fixture : shellsplit_test_builtin_options) {
    size_t length = std::strlen(fixture.source);
    bool syntax_supported = fixture.supported || fixture.stateful;
    if (shell_tokenizer_has_unsupported_semantics(fixture.source, length) !=
        !syntax_supported)
      return fixed_oracle_failure(__LINE__);
    if (!syntax_supported &&
        !tokenizer_unsupported_semantics_rejected(fixture.source, length))
      return fixed_oracle_failure(__LINE__);
    shell_processed_commands_t processed = {};
    bool processed_ok = shell_process_commands(fixture.source, length, nullptr,
                                               &processed) == SHELL_PROCESS_OK;
    shell_processed_commands_free(&processed);
    if (processed_ok != syntax_supported)
      return fixed_oracle_failure(__LINE__);
    shell_dep_graph_t graph = {};
    shell_dep_error_t graph_error =
        shell_dep_graph_parse(fixture.source, length, ".", nullptr, &graph);
    if (fixture.supported ? graph_error != SHELL_DEP_OK ||
                                !shell_dep_graph_validate(&graph).valid
                          : graph_error != SHELL_DEP_EPARSE ||
                                graph.node_count || graph.edge_count)
      return fixed_oracle_failure(__LINE__);
  }
  for (const auto &fixture : shellsplit_test_setup_time_outcomes) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(fixture.source, std::strlen(fixture.source), ".",
                              nullptr, &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    uint32_t timer = UINT32_MAX, base = UINT32_MAX, out = UINT32_MAX;
    for (uint32_t n = 0; n < graph.node_count; n++) {
      const auto &node = graph.nodes[n];
      if (node.type == SHELL_NODE_TIME)
        timer = n;
      if (node.type == SHELL_NODE_DOC && node.doc.kind == SHELL_DOC_FILE) {
        if (node.doc.path_len == 4 && !std::memcmp(node.doc.path, "base", 4))
          base = n;
        if (node.doc.path_len == 3 && !std::memcmp(node.doc.path, "out", 3))
          out = n;
      }
    }
    bool to_base = false, to_out = false;
    unsigned writes = 0;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const auto &edge = graph.edges[e];
      if (!internal_graph_relation(graph, edge))
        continue;
      if (edge.type == SHELL_EDGE_WRITE && edge.from == timer) {
        writes++;
        to_base |= edge.to == base;
        to_out |= edge.to == out;
      }
    }
    if (timer == UINT32_MAX ||
        graph.nodes[timer].time.report_route_flags != fixture.flags ||
        !to_out || to_base != fixture.base || writes != 1u + fixture.base)
      return fixed_oracle_failure(__LINE__);
  }
  /* Some rows inspect different routes of the same retained graph. Reuse an
   * adjacent identical source rather than repeating its full semantic parse;
   * every row's independent route expectation is still checked below. */
  shell_dep_graph_t cleanup_graph = {};
  const char *cleanup_source = nullptr;
  shell_dep_error_t cleanup_status = SHELL_DEP_OK;
  shell_dep_graph_validation_t cleanup_validation = {};
  size_t cleanup_case = 0;
  for (const auto &fixture : shellsplit_test_named_cleanup) {
    if (g_verbose)
      fprintf(stderr, "DEBUG: named cleanup case %zu\n", cleanup_case);
    cleanup_case++;
    shell_dep_graph_t &graph = cleanup_graph;
    if (!cleanup_source || std::strcmp(cleanup_source, fixture.source)) {
      const auto parse_start = std::chrono::steady_clock::now();
      cleanup_status = shell_dep_graph_parse(
          fixture.source, std::strlen(fixture.source), ".", nullptr, &graph);
      if (g_verbose)
        fprintf(stderr, "DEBUG: named cleanup parse %.3fs\n",
                std::chrono::duration<double>(std::chrono::steady_clock::now() -
                                              parse_start)
                    .count());
      cleanup_validation = shell_dep_graph_validate(&graph);
      cleanup_source = fixture.source;
    }
    shell_dep_error_t status = cleanup_status;
    shell_dep_graph_validation_t validation = cleanup_validation;
    if (status != SHELL_DEP_OK || !validation.valid) {
      fprintf(stderr, "named cleanup oracle parse=%d valid=%d: %s\n", status,
              validation.valid, fixture.source);
      shell_dep_graph_dump(&graph, stderr);
      return fixed_oracle_failure(__LINE__);
    }
    uint32_t consumer = UINT32_MAX, target = UINT32_MAX;
    uint32_t alternative = UINT32_MAX;
    const char *command = fixture.read ? "cat" : "printf";
    for (uint32_t n = 0; n < graph.node_count; n++) {
      const auto &node = graph.nodes[n];
      if (fixture.timer && node.type == SHELL_NODE_TIME)
        consumer = n;
      else if (!fixture.timer && node.type == SHELL_NODE_CMD &&
               node.cmd.token_count == (fixture.read ? 1u : 2u) &&
               node.cmd.token_lens[0] == std::strlen(command) &&
               !std::memcmp(node.cmd.tokens[0], command,
                            std::strlen(command)) &&
               (fixture.read ||
                (node.cmd.token_lens[1] == std::strlen(fixture.argument) &&
                 !std::memcmp(node.cmd.tokens[1], fixture.argument,
                              std::strlen(fixture.argument)))))
        consumer = n;
      if (node.type == SHELL_NODE_DOC && node.doc.kind == SHELL_DOC_FILE &&
          node.doc.path_len == std::strlen(fixture.file) &&
          !std::memcmp(node.doc.path, fixture.file, node.doc.path_len))
        target = n;
      if (fixture.alternative_file && node.type == SHELL_NODE_DOC &&
          node.doc.kind == SHELL_DOC_FILE &&
          node.doc.path_len == std::strlen(fixture.alternative_file) &&
          !std::memcmp(node.doc.path, fixture.alternative_file,
                       node.doc.path_len))
        alternative = n;
    }
    unsigned flows = 0;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const auto &edge = graph.edges[e];
      if (!internal_graph_relation(graph, edge))
        continue;
      if (edge.type != (fixture.read ? SHELL_EDGE_READ : SHELL_EDGE_WRITE) ||
          (fixture.read ? edge.to : edge.from) != consumer ||
          graph.nodes[fixture.read ? edge.from : edge.to].type !=
              SHELL_NODE_DOC)
        continue;
      uint32_t endpoint = fixture.read ? edge.from : edge.to;
      if ((endpoint != target && endpoint != alternative) ||
          (fixture.read ? edge.target_fd : edge.source_fd) !=
              (fixture.timer  ? 2u
               : fixture.read ? 0u
                              : 1u))
        return fixed_oracle_failure(__LINE__);
      flows++;
    }
    if (consumer == UINT32_MAX || target == UINT32_MAX ||
        (fixture.alternative_file && alternative == UINT32_MAX) ||
        flows != 1u + (fixture.alternative_file != nullptr))
      return fixed_oracle_failure(__LINE__);
  }
  for (const char *source : shellsplit_test_invalidated_reallocation) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(source, std::strlen(source), ".", nullptr,
                              &graph) != SHELL_DEP_EPARSE ||
        graph.node_count || graph.edge_count)
      return fixed_oracle_failure(__LINE__);
  }
  for (const auto &fixture : shellsplit_test_descriptor_outcomes) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(fixture.source, std::strlen(fixture.source), ".",
                              nullptr, &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    uint32_t writer = UINT32_MAX, base = UINT32_MAX, out = UINT32_MAX;
    for (uint32_t n = 0; n < graph.node_count; n++) {
      const auto &node = graph.nodes[n];
      if (node.type == SHELL_NODE_CMD && node.cmd.token_count == 2 &&
          node.cmd.token_lens[0] == 6 && node.cmd.token_lens[1] == 7 &&
          !std::memcmp(node.cmd.tokens[0], "printf", 6) &&
          !std::memcmp(node.cmd.tokens[1], "payload", 7))
        writer = n;
      if (node.type == SHELL_NODE_DOC && node.doc.kind == SHELL_DOC_FILE) {
        if (node.doc.path_len == 4 && !std::memcmp(node.doc.path, "base", 4))
          base = n;
        if (node.doc.path_len == 3 && !std::memcmp(node.doc.path, "out", 3))
          out = n;
      }
    }
    bool to_base = false, to_out = false;
    unsigned writes = 0;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const auto &edge = graph.edges[e];
      if (!internal_graph_relation(graph, edge))
        continue;
      if (edge.type == SHELL_EDGE_WRITE && edge.from == writer &&
          edge.source_fd == 1 && graph.nodes[edge.to].type != SHELL_NODE_FD) {
        writes++;
        to_base |= edge.to == base;
        to_out |= edge.to == out;
      }
    }
    if (writer == UINT32_MAX || to_base != fixture.base ||
        to_out != fixture.out || writes != fixture.base + fixture.out)
      return fixed_oracle_failure(__LINE__);
  }
  for (const auto &fixture : shellsplit_test_scope_outcomes) {
    shell_dep_graph_t graph = {};
    bool valid =
        shell_dep_graph_parse(fixture.source, std::strlen(fixture.source), ".",
                              nullptr, &graph) == SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    uint32_t writer = UINT32_MAX, target = UINT32_MAX;
    for (uint32_t node = 0; valid && node < graph.node_count; node++) {
      const shell_dep_node_t &item = graph.nodes[node];
      if (item.type == SHELL_NODE_CMD && item.cmd.token_count >= 2 &&
          item.cmd.token_lens[0] == 6 && item.cmd.token_lens[1] == 7 &&
          !std::memcmp(item.cmd.tokens[0], "printf", 6) &&
          !std::memcmp(item.cmd.tokens[1], "payload", 7))
        writer = node;
      if (item.type == SHELL_NODE_DOC && item.doc.kind == SHELL_DOC_FILE &&
          item.doc.path_len == 3 && !std::memcmp(item.doc.path, "out", 3))
        target = node;
    }
    bool writes = false;
    for (uint32_t edge = 0; valid && edge < graph.edge_count; edge++) {
      const shell_dep_edge_t &item = graph.edges[edge];
      writes |= item.type == SHELL_EDGE_WRITE && item.from == writer &&
                item.to == target;
    }
    if (!valid || writer == UINT32_MAX || target == UINT32_MAX ||
        writes != fixture.writes_to_out)
      return fixed_oracle_failure(__LINE__);
  }
  for (const auto &fixture : shellsplit_test_cwd_reachability) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(fixture.source, std::strlen(fixture.source),
                              "/workspace", nullptr, &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    bool found = false;
    for (uint32_t n = 0; n < graph.node_count; n++) {
      const auto &node = graph.nodes[n];
      if (node.type != SHELL_NODE_DOC || node.doc.kind != SHELL_DOC_FILE ||
          node.doc.path_len != std::strlen(fixture.file) ||
          std::memcmp(node.doc.path, fixture.file, node.doc.path_len))
        continue;
      found = true;
      char identity[512];
      size_t written = 0;
      bool absolute = false;
      bool known = shell_dep_doc_file_identity_write(
          &graph, &node.doc, identity, sizeof(identity), &written, &absolute);
      if (known != (fixture.identity != nullptr) ||
          (known && (!absolute || std::strcmp(identity, fixture.identity))))
        return fixed_oracle_failure(__LINE__);
    }
    if (!found)
      return fixed_oracle_failure(__LINE__);
  }
  for (const auto &fixture : shellsplit_test_skipped_dup_operands) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(fixture.source, std::strlen(fixture.source), ".",
                              nullptr, &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    uint32_t commands = 0;
    for (uint32_t n = 0; n < graph.node_count; n++)
      commands += graph.nodes[n].type == SHELL_NODE_CMD;
    if (commands != fixture.commands)
      return fixed_oracle_failure(__LINE__);
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      if (!internal_graph_relation(graph, graph.edges[e]))
        continue;
      auto type = graph.edges[e].type;
      if (type == SHELL_EDGE_READ || type == SHELL_EDGE_WRITE ||
          type == SHELL_EDGE_APPEND || type == SHELL_EDGE_SUBST ||
          type == SHELL_EDGE_FD_OPEN || type == SHELL_EDGE_FD_CLOSE)
        return fixed_oracle_failure(__LINE__);
    }
  }
  for (uint8_t selector = 0; selector < 48; selector++)
    if (test_generated_document_boundary(selector))
      return fixed_oracle_failure(__LINE__);
  static const char *const compound_modifier_spans[] = {
      "{ time cat; }",
      "(time -p cat)",
      "{ ! cat; }",
      "{ ! time -p cat; }",
      "{ { ! time -p cat; }; }",
      "{ time cat | printf x; }",
      "{ time cat <<'EOF'; } |& cat\nliteral $(ignored)\nEOF\n",
  };
  for (const char *source : compound_modifier_spans) {
    size_t length = strlen(source);
    if (test_tokenizer_state(source, length) ||
        test_transformer(source, length) || test_processor(source, length))
      return fixed_oracle_failure(__LINE__);
  }

  static const struct {
    const char *source;
    const char *identity;
  } cwd_files[] = {
      {"( : | cd /tmp; printf x >out )", "/workspace/out"},
      {"cd /tmp <<<body | :; printf x >out", "/workspace/out"},
      {"time cd /tmp <<<body | :; printf x >out", "/workspace/out"},
      {"{ cd /tmp; printf x >out; } &", nullptr},
      {"( : | cd /tmp; echo \"$(<out)\" )", "/workspace/out"},
      {"cd /tmp; echo \"$(<out)\"", nullptr},
      {"cd \"$value\"; echo \"$(<out)\"", nullptr},
  };
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  for (const auto &item : cwd_files) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(item.source, strlen(item.source), "/workspace",
                              &limits, &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    bool found = false;
    for (uint32_t i = 0; i < graph.node_count; i++) {
      const shell_dep_node_t &node = graph.nodes[i];
      if (node.type != SHELL_NODE_DOC || node.doc.kind != SHELL_DOC_FILE ||
          node.doc.path_len != 3 || memcmp(node.doc.path, "out", 3))
        continue;
      char identity[256];
      size_t length = 0;
      bool absolute = false;
      bool known = shell_dep_doc_file_identity_write(
          &graph, &node.doc, identity, sizeof(identity), &length, &absolute);
      if (known != (item.identity != nullptr) ||
          (known && (!absolute || length != strlen(item.identity) ||
                     strcmp(identity, item.identity))))
        return fixed_oracle_failure(__LINE__);
      found = true;
    }
    if (!found)
      return fixed_oracle_failure(__LINE__);
  }
  static const struct {
    const char *source;
    const char *command;
    const char *argument;
    bool write;
  } process_pipes[] = {
      {"cat outer <input < >(true </dev/null)", "cat", "outer", false},
      {"printf value >out > <(printf ignored >/dev/null)", "printf", "value",
       true},
      {"exec {fd}< >(true </dev/null); cat outer <&$fd", "cat", "outer", false},
      {"exec {fd}> <(printf ignored >/dev/null); printf value >&$fd", "printf",
       "value", true},
      {"exec {fd}<> <(printf input); printf value >&$fd", "printf", "value",
       true},
      {"exec {fd}<> >(true </dev/null); cat outer <&$fd", "cat", "outer",
       false},
  };
  for (const auto &item : process_pipes) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(item.source, strlen(item.source), ".", nullptr,
                              &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    uint32_t owner = UINT32_MAX;
    for (uint32_t i = 0; i < graph.node_count; i++) {
      const shell_dep_node_t &node = graph.nodes[i];
      if (node.type == SHELL_NODE_CMD && node.cmd.token_count >= 2 &&
          node.cmd.token_lens[0] == strlen(item.command) &&
          node.cmd.token_lens[1] == strlen(item.argument) &&
          !memcmp(node.cmd.tokens[0], item.command, strlen(item.command)) &&
          !memcmp(node.cmd.tokens[1], item.argument, strlen(item.argument)))
        owner = i;
    }
    bool installed = false;
    for (uint32_t i = 0; i < graph.edge_count; i++) {
      const shell_dep_edge_t &edge = graph.edges[i];
      if (item.write && edge.from == owner && edge.source_fd == 1 &&
          edge.type == SHELL_EDGE_WRITE) {
        if (graph.nodes[edge.to].type != SHELL_NODE_ENDPOINT)
          return fixed_oracle_failure(__LINE__);
        installed = true;
      }
      if (!item.write && edge.to == owner && edge.target_fd == 0 &&
          (edge.type == SHELL_EDGE_READ || edge.type == SHELL_EDGE_SUBST)) {
        if (graph.nodes[edge.from].type != SHELL_NODE_ENDPOINT)
          return fixed_oracle_failure(__LINE__);
        installed = true;
      }
    }
    if (!installed)
      return fixed_oracle_failure(__LINE__);
  }
  for (size_t prefix : {size_t(0), size_t(SHELL_MAX_SUBCOMMANDS + 1)}) {
    for (const char *tail : shellsplit_test_malformed_tails) {
      char source[4096];
      size_t length = 0;
      if (!shellsplit_test_source_with_tail(source, sizeof(source), prefix,
                                            tail, &length))
        return fixed_oracle_failure(__LINE__);
      for (uint32_t capacity : {uint32_t(1), uint32_t(SHELL_MAX_SUBCOMMANDS)}) {
        shell_parse_result_t fast = {};
        shell_limits_t limits = {capacity, true, nullptr, 0};
        if (shell_parse_fast(source, length, &limits, &fast) != SHELL_EPARSE ||
            fast.count || fast.group_count || fast.status != SHELL_STATUS_ERROR)
          return fixed_oracle_failure(__LINE__);
      }
      shell_dep_graph_t graph = {};
      if (shell_dep_graph_parse(source, length, ".", nullptr, &graph) !=
              SHELL_DEP_EPARSE ||
          graph.node_count || graph.edge_count || graph.cwd_buf.len)
        return fixed_oracle_failure(__LINE__);
    }
  }
  static const char *const scoped_quotes[] = {
      "echo \"${value:-\"x;y\"}\"",
      "echo \"$(printf \"x;y\")\"",
      "echo \"`printf \"x;y\"`\"",
  };
  for (const char *source : scoped_quotes) {
    shell_parse_result_t fast = {};
    shell_command_t *commands = nullptr;
    size_t count = 0;
    shell_processed_commands_t processed = {};
    bool valid =
        shell_parse_fast(source, strlen(source), NULL, &fast) == SHELL_OK &&
        fast.count == 1 &&
        shell_tokenize_commands(source, strlen(source), &commands, &count) ==
            SHELL_TOKENIZE_OK &&
        count == 1 &&
        shell_process_commands(source, strlen(source), nullptr, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == 1;
    shell_commands_free(commands, count);
    shell_processed_commands_free(&processed);
    if (!valid)
      return fixed_oracle_failure(__LINE__);
  }
  const char *incomplete_ansi = "echo $'foo\\'";
  shell_parse_result_t incomplete = {};
  shell_limits_t strict = SHELL_LIMITS_DEFAULT;
  strict.strict_mode = true;
  if (shell_parse_fast(incomplete_ansi, strlen(incomplete_ansi), &strict,
                       &incomplete) != SHELL_EPARSE)
    return fixed_oracle_failure(__LINE__);
  /* The iterator intentionally exposes a standalone escaped physical line
   * ending while the structured tokenizer omits it from command records.
   * Keep this exact smoke finding deterministic so their comparison remains
   * semantic rather than byte-for-byte lexical. */
  static const char iterator_continuation[] = "echo first \\\nsecond | cat\n";
  if (test_tokenizer_state(iterator_continuation,
                           sizeof(iterator_continuation) - 1))
    return fixed_oracle_failure(__LINE__);
  static const char iterator_heredoc_boundary[] = "cat& <<EOF\nvalue\nEOF\n";
  if (test_tokenizer_state(iterator_heredoc_boundary,
                           sizeof(iterator_heredoc_boundary) - 1))
    return fixed_oracle_failure(__LINE__);
  /* A heredoc that remains attached to a command retains its following
   * newline. This complements the input-only heredoc case above. */
  static const char iterator_attached_heredoc[] = "cat <<EOF\nvalue\nEOF\n";
  if (test_tokenizer_state(iterator_attached_heredoc,
                           sizeof(iterator_attached_heredoc) - 1))
    return fixed_oracle_failure(__LINE__);
  static const char *const iterator_document_lists[] = {
      " <<OLDPvcat <<OLDPvalue0EOF\n",
      "<<A <<B\nA\nB\n",
      "2>err <<EOF\nEOF\n",
      "cat <<A <<B\nA\nB\n",
      "printf x; <<A <<B\nA\nB\n",
  };
  for (const char *source : iterator_document_lists)
    if (test_tokenizer_state(source, strlen(source)))
      return fixed_oracle_failure(__LINE__);
  /* Diagnostic function-like headers can leave an ordinary word in the
   * current flat record before an empty body/group. A later opener must not
   * erase that word's pending newline. No function semantics are accepted. */
  static const char *const empty_function_diagnostics[] = {
      "foo() { }\n", "foo() {\n}\n", "foo() ( )\n", "foo() { { }; }\n",
      "foo() {\n:; }\n"};
  for (const char *source : empty_function_diagnostics)
    if (test_tokenizer_state(source, strlen(source)) ||
        !tokenizer_unsupported_semantics_rejected(source, strlen(source)))
      return fixed_oracle_failure(__LINE__);
  static const char *const bang_context_cases[] = {
      "printf '%s' !\n",      "printf '%s' ! !\n", "printf '%s' ! | cat\n",
      "printf '%s' >out !\n", "! printf '%s'\n",   "! ! printf '%s'\n",
  };
  for (const char *source : bang_context_cases)
    if (test_tokenizer_state(source, strlen(source))) {
      fprintf(stderr, "fixed tokenizer bang-context oracle failed: %s", source);
      return fixed_oracle_failure(__LINE__);
    }
  static const char *const time_context_cases[] = {
      "time printf x\n",
      "time -p -- ! printf x\n",
      "! time ! printf x | cat\n",
      "time { printf x; } | cat\n",
      "! { printf x; }\n",
      "time !\n",
      "printf x | time cat\n",
      "!>/tmp/out printf x\n",
      "!2>/tmp/out printf x\n",
      "time -- true\n",
      "time time -p true\n",
      "echo a; time echo b\n",
      "echo a && time -p echo b\n",
      "echo a || time -- echo b\n",
      "echo a & time echo b\n",
      "time echo a; time -p echo b\n",
      "echo a; ! echo b\n",
      "echo a; time\n",
      "echo a; time; echo b\n",
      "echo a; time { echo b; }\n",
      "ti\\\nme -\\\np true\n",
      "VALUE=x time true\n",
      ">out time true\n",
      "echo \"unterminated\n",
      "(echo \"unterminated",
      "if :; then echo \"unterminated",
      "{ echo 'unterminated",
  };
  for (const char *source : time_context_cases)
    if (test_tokenizer_state(source, strlen(source))) {
      fprintf(stderr, "fixed tokenizer time-context oracle failed: %s", source);
      return fixed_oracle_failure(__LINE__);
    }

  /* Regression for the former span-filtered comparison: a malformed
   * structured record that stops before an ordinary lexical argument must be
   * rejected. Compound-owned `time` prefixes are the only permitted skip. */
  static const char dropped_word_source[] = "echo dropped";
  shell_token_t dropped_lexical[2] = {};
  dropped_lexical[0].type = SHELL_TOKEN_COMMAND;
  dropped_lexical[0].start = dropped_word_source;
  dropped_lexical[0].length = 4;
  dropped_lexical[0].position = 0;
  dropped_lexical[1].type = SHELL_TOKEN_ARGUMENT;
  dropped_lexical[1].start = dropped_word_source + 5;
  dropped_lexical[1].length = 7;
  dropped_lexical[1].position = 5;
  shell_command_t truncated_record = {};
  truncated_record.tokens = dropped_lexical;
  truncated_record.token_count = 1;
  truncated_record.start_pos = 0;
  truncated_record.end_pos = 4;
  std::vector<shell_token_t> dropped_iterated = {
      dropped_lexical[0],
      dropped_lexical[1],
  };
  if (tokenizer_iterated_matches_structured(
          dropped_word_source, sizeof(dropped_word_source) - 1,
          dropped_iterated, &truncated_record, 1))
    return fixed_oracle_failure(__LINE__);

  /* Unsupported control flow and current-shell constructs are not a
   * reconciliation escape hatch: their surrounding ordinary words and
   * operators must remain visible to the diagnostic tokenizer. */
  static const char *const unsupported_surrounding[] = {
      "echo before; for item in one; do :; done; echo after | cat",
      "echo before; if :; then :; fi; echo after | cat",
      "echo before; case value in value) : ;; esac; echo after | cat",
      "echo before; items=(one); echo after | cat",
      "echo before; eval echo hidden; echo after | cat",
      "echo before; foo() { }\necho after | cat",
      "echo before; foo() {\n:; }\necho after | cat",
      ("echo before; for ((i=0; i<3; i++)); do echo inside; done; echo after | "
       "cat"),
  };
  for (const char *source : unsupported_surrounding)
    if (!tokenizer_unsupported_context_visible(source) ||
        test_tokenizer_state(source, strlen(source)))
      return fixed_oracle_failure(__LINE__);

  /* Comment/continuation-only input has no visible diagnostic tokens. The
   * command tokenizer may reject such non-command source rather than return
   * empty records; ordinary words must never use this empty-stream escape. */
  static const char *const empty_visible_sources[] = {
      "#hile do7",
      "# time ! echo hidden",
      "\n# comment\n",
      "\\\n",
  };
  for (const char *source : empty_visible_sources)
    if (test_tokenizer_state(source, strlen(source)))
      return fixed_oracle_failure(__LINE__);

  /* Clause terminators without a case construct are malformed grammar, not
   * empty valid lists. They must reject atomically without weakening the
   * ordered diagnostic reconciliation for actual control constructs. */
  static const char *const bare_clause_sources[] = {
      ";;",
      ";&",
      ";;&",
      "echo one ;; echo two",
      "echo one ;& echo two",
      "echo one ;;& echo two",
  };
  for (const char *source : bare_clause_sources)
    if (shell_tokenizer_list_syntax_valid(source, strlen(source)) ||
        !tokenizer_unsupported_semantics_rejected(source, strlen(source)) ||
        test_tokenizer_state(source, strlen(source)))
      return fixed_oracle_failure(__LINE__);

  /* Deliberately corrupt diagnostic records before, within, and after an
   * unsupported construct. Neither ordinary words nor operators may be
   * omitted, invented, or reordered. These sources have no structural
   * delimiters or prefixes to elide, so every lexical token must match. */
  static const char *const unsupported_loss_cases[] = {
      "echo before; for item in one; do echo inside; done; echo after | cat",
      "echo before; eval echo inside; echo after | cat",
  };
  for (const char *source : unsupported_loss_cases) {
    size_t length = strlen(source);
    shell_tokenizer_state_t state = {};
    shell_tokenizer_init(&state, source, length, NULL);
    std::vector<shell_token_t> lexical;
    shell_token_t token = {};
    while (shell_tokenizer_next(&state, &token))
      lexical.push_back(token);
    shell_command_t record = {};
    record.start_pos = 0;
    record.end_pos = length;
    record.tokens = lexical.data();
    record.token_count = lexical.size();
    if (!tokenizer_iterated_matches_structured(source, length, lexical, &record,
                                               1))
      return fixed_oracle_failure(__LINE__);
    for (size_t omitted = 0; omitted < lexical.size(); omitted++) {
      std::vector<shell_token_t> damaged = lexical;
      damaged.erase(damaged.begin() + omitted);
      record.tokens = damaged.data();
      record.token_count = damaged.size();
      if (tokenizer_iterated_matches_structured(source, length, lexical,
                                                &record, 1))
        return fixed_oracle_failure(__LINE__);
    }
    std::vector<shell_token_t> invented = lexical;
    invented.push_back(lexical.back());
    record.tokens = invented.data();
    record.token_count = invented.size();
    if (tokenizer_iterated_matches_structured(source, length, lexical, &record,
                                              1))
      return fixed_oracle_failure(__LINE__);
    std::swap(invented[0], invented[1]);
    invented.pop_back();
    record.token_count = invented.size();
    if (tokenizer_iterated_matches_structured(source, length, lexical, &record,
                                              1))
      return fixed_oracle_failure(__LINE__);
  }

  struct oracle_case {
    const char *input;
    uint32_t count;
    uint16_t first_type;
    uint16_t second_type;
    uint32_t features;
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
      {"echo $(id)$(pwd)", 1, SHELL_TYPE_SUBSTITUTION, SHELL_TYPE_SIMPLE,
       SHELL_FEAT_SUBSHELL},
      {"echo prefix$(id)suffix$(pwd)", 1, SHELL_TYPE_SUBSTITUTION,
       SHELL_TYPE_SIMPLE, SHELL_FEAT_SUBSHELL},
      {"echo $(id)`pwd`", 1, SHELL_TYPE_SUBSTITUTION, SHELL_TYPE_SIMPLE,
       SHELL_FEAT_SUBSHELL},
      {"echo \"$(id)$(pwd)\"", 1, SHELL_TYPE_SUBSTITUTION, SHELL_TYPE_SIMPLE,
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
      {"echo ok # ignored\npwd", 2, SHELL_TYPE_SIMPLE, SHELL_TYPE_SEMICOLON, 0},
      {"echo one & echo two", 2, SHELL_TYPE_SIMPLE, SHELL_TYPE_BACKGROUND,
       SHELL_FEAT_BACKGROUND},
      {"(echo one; echo two)", 2, SHELL_TYPE_SIMPLE, SHELL_TYPE_SEMICOLON,
       SHELL_FEAT_GROUP},
      {"{ echo one; echo two; }", 2, SHELL_TYPE_SIMPLE, SHELL_TYPE_SEMICOLON,
       SHELL_FEAT_GROUP},
      {"{( echo one ) ; echo two; }", 2, SHELL_TYPE_SIMPLE,
       SHELL_TYPE_SEMICOLON, SHELL_FEAT_GROUP},
  };
  for (const oracle_case &item : cases) {
    shell_parse_result_t fast = {};
    if (shell_parse_fast(item.input, strlen(item.input), NULL, &fast) !=
            SHELL_OK ||
        fast.count != item.count || fast.cmds[0].type != item.first_type ||
        (item.features != 0 &&
         (fast.cmds[0].features & item.features) != item.features) ||
        (item.count > 1 && fast.cmds[1].type != item.second_type))
      return fixed_oracle_failure(__LINE__);
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    bool ok =
        (shell_tokenize_commands(item.input, strlen(item.input), &commands,
                                 &command_count) == SHELL_TOKENIZE_OK);
    shell_commands_free(commands, command_count);
    if (!ok || command_count != item.count)
      return fixed_oracle_failure(__LINE__);
  }

  /* Metadata must distinguish executable substitutions from literal spelling
   * lookalikes, even when the full tokenizer retains one compound word. Keep
   * these in-code so every fuzzing session exercises the contract without
   * growing the checked-in smoke corpus. */
  struct word_metadata_oracle {
    const char *input;
    bool has_cmd_subst;
    bool has_globs;
    bool has_strings;
    bool has_transformations;
    bool has_shell_syntax;
    const char *display;
    shell_transform_type_t argument_type;
  };
  static const word_metadata_oracle word_metadata_cases[] = {
      {"echo \"$(id)\"", true, false, true, false, true, "echo \"$(id)\"",
       SHELL_TRANSFORM_NONE},
      {"echo \"<(id)\"", false, false, true, false, false, "echo \"<(id)\"",
       SHELL_TRANSFORM_NONE},
      {"echo $'$(id)'", false, false, true, false, false, "echo $'$(id)'",
       SHELL_TRANSFORM_NONE},
      {"echo $'it\\'s $(id)'", false, false, true, false, false,
       "echo $'it\\'s $(id)'", SHELL_TRANSFORM_NONE},
      {"echo @(left|right)", false, true, false, true, true,
       "echo FILE_PATTERN", SHELL_TRANSFORM_GLOB},
      {"echo $'a\\n'", false, false, true, false, false, "echo $'a\\n'",
       SHELL_TRANSFORM_NONE},
  };
  for (const word_metadata_oracle &item : word_metadata_cases) {
    shell_abstract_command_t *abstract = NULL;
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    shell_command_info_t *processed = NULL;
    size_t processed_count = 0;
    shell_netstring_buffer_t sequence = {};
    size_t sequence_count = 0;
    bool sequence_features = !item.has_cmd_subst;
    bool metadata_ok =
        shell_abstract_command_parse(item.input, strlen(item.input),
                                     &abstract) == SHELL_ABSTRACT_OK &&
        abstract && abstract->has_cmd_subst == item.has_cmd_subst &&
        abstract->has_globs == item.has_globs &&
        abstract->has_strings == item.has_strings &&
        shell_transform_command_line(item.input, strlen(item.input), NULL,
                                     &transformed, &transformed_count) ==
            SHELL_TRANSFORM_OK &&
        transformed_count == 1 && transformed && transformed[0] &&
        transformed[0]->token_count == 2 &&
        transformed[0]->has_transformations == item.has_transformations &&
        transformed[0]->has_shell_syntax == item.has_shell_syntax &&
        strcmp(transformed[0]->display_text, item.display) == 0 &&
        transformed[0]->tokens[1].type == item.argument_type &&
        shell_process_command(item.input, strlen(item.input), NULL, &processed,
                              &processed_count) == SHELL_PROCESS_OK &&
        processed_count == 1 && processed != nullptr &&
        shell_command_info_has_dangerous_features(processed) ==
            item.has_cmd_subst &&
        shell_build_netargv_sequence_buffer(
            item.input, strlen(item.input), NULL, &sequence, &sequence_count,
            &sequence_features) == SHELL_PROCESS_OK &&
        sequence_count == 1 && sequence_features == item.has_cmd_subst;
    shell_netstring_buffer_free(&sequence);
    shell_command_infos_free(processed, processed_count);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
    if (!metadata_ok) {
      fprintf(stderr, "word metadata oracle failed: %s\n", item.input);
      return fixed_oracle_failure(__LINE__);
    }
  }

  /* Keep newly supported spelling families in the always-run oracle set. The
   * literal forms also become comparison material for libFuzzer's dictionary
   * discovery, so mutations reach their boundary handling quickly. */
  shell_parse_result_t modern = {};
  if (shell_parse_fast("! false | cat", strlen("! false | cat"), NULL,
                       &modern) != SHELL_OK ||
      modern.count != 2 ||
      (modern.cmds[0].modifiers & SHELL_CMD_MOD_PIPE_NEGATED) == 0 ||
      (modern.cmds[1].modifiers & SHELL_CMD_MOD_PIPE_NEGATED) == 0)
    return fixed_oracle_failure(__LINE__);
  shell_command_t *pipe_both_commands = NULL;
  size_t pipe_both_count = 0;
  shell_command_info_t *pipe_both_infos = NULL;
  size_t pipe_both_info_count = 0;
  shell_dep_graph_t pipe_both_graph = {};
  bool pipe_both_ok =
      shell_parse_fast("printf x |& cat", strlen("printf x |& cat"), NULL,
                       &modern) == SHELL_OK &&
      modern.count == 2 &&
      modern.cmds[1].pipe_input_mode == SHELL_PIPE_MODE_STDOUT_AND_STDERR &&
      shell_tokenize_commands("printf x |& cat", strlen("printf x |& cat"),
                              &pipe_both_commands,
                              &pipe_both_count) == SHELL_TOKENIZE_OK &&
      pipe_both_count == 2 &&
      pipe_both_commands[0].pipe_output_mode ==
          SHELL_PIPE_MODE_STDOUT_AND_STDERR &&
      shell_process_command("printf x |& cat", strlen("printf x |& cat"), NULL,
                            &pipe_both_infos,
                            &pipe_both_info_count) == SHELL_PROCESS_OK &&
      pipe_both_info_count == 2 &&
      pipe_both_infos[0].pipe_output_mode ==
          SHELL_PIPE_MODE_STDOUT_AND_STDERR &&
      shell_dep_graph_parse("printf x |& cat", strlen("printf x |& cat"), NULL,
                            NULL, &pipe_both_graph) == SHELL_DEP_OK;
  uint32_t pipe_both_edges = 0;
  for (uint32_t i = 0; i < pipe_both_graph.edge_count; i++)
    pipe_both_edges += pipe_both_graph.edges[i].type == SHELL_EDGE_PIPE;
  bool pipe_both_valid = pipe_both_ok && pipe_both_edges == 2 &&
                         shell_dep_graph_validate(&pipe_both_graph).valid;
  shell_command_infos_free(pipe_both_infos, pipe_both_info_count);
  shell_commands_free(pipe_both_commands, pipe_both_count);
  if (!pipe_both_valid)
    return fixed_oracle_failure(__LINE__);

  /* Group-owned redirects are structure rather than flat output, but a later
   * redirect-only list member is a returned empty-argv record. Exercise both
   * limits without adding a long-lived smoke seed. */
  static const char structural_group_redirect[] =
      "{ echo ok; } >/tmp/shellsplit-group-owned-redirect-that-is-not-a-"
      "returned-flat-record";
  static const char long_independent_redirect[] =
      "{ echo ok; } >/tmp/group-owned; >/tmp/shellsplit-returned-redirect-"
      "operand-that-exceeds-the-flat-record-limit";
  static const char group_then_redirect[] =
      "{ echo ok; } >/tmp/group-owned; >/tmp/independent";
  const shell_process_limits_t returned_only_limit = {32, 32, 0};
  const shell_process_limits_t aggregate_flat_limit = {
      SIZE_MAX, strlen("echo ok") + strlen(">/tmp/independent") - 1, 0};
  shell_command_info_t *flat_limit_infos = nullptr;
  size_t flat_limit_count = 0;
  bool flat_limit_valid =
      shell_process_command(structural_group_redirect,
                            sizeof(structural_group_redirect) - 1,
                            &returned_only_limit, &flat_limit_infos,
                            &flat_limit_count) == SHELL_PROCESS_OK &&
      flat_limit_infos != nullptr && flat_limit_count == 1 &&
      strcmp(flat_limit_infos[0].original_command, "echo ok") == 0;
  shell_command_infos_free(flat_limit_infos, flat_limit_count);

  flat_limit_infos = reinterpret_cast<shell_command_info_t *>(uintptr_t{1});
  flat_limit_count = SIZE_MAX;
  flat_limit_valid =
      flat_limit_valid &&
      shell_process_command(long_independent_redirect,
                            sizeof(long_independent_redirect) - 1,
                            &returned_only_limit, &flat_limit_infos,
                            &flat_limit_count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
      flat_limit_infos == nullptr && flat_limit_count == 0;

  flat_limit_infos = reinterpret_cast<shell_command_info_t *>(uintptr_t{1});
  flat_limit_count = SIZE_MAX;
  flat_limit_valid = flat_limit_valid &&
                     shell_process_command(
                         group_then_redirect, sizeof(group_then_redirect) - 1,
                         &aggregate_flat_limit, &flat_limit_infos,
                         &flat_limit_count) == SHELL_PROCESS_EOUTPUT_LIMIT &&
                     flat_limit_infos == nullptr && flat_limit_count == 0;
  if (!flat_limit_valid)
    return fixed_oracle_failure(__LINE__);

  /* The legacy flat result retains independently executable redirect-only
   * stages adjacent to groups. Their range must stay self-contained: group
   * delimiters and group-owned redirects belong only to structure. Keep these
   * in the always-run oracle set instead of adding a long-lived smoke seed. */
  struct flat_group_record_oracle {
    const char *input;
    const char *first;
    const char *second;
  };
  static const flat_group_record_oracle flat_group_record_cases[] = {
      {">first; { :; } >out", ">first", ":"},
      {"{ :; >inner; } >out", ":", ">inner"},
      {"{ :; } >out; >after", ":", ">after"},
  };
  bool flat_group_records_valid = true;
  for (const flat_group_record_oracle &item : flat_group_record_cases) {
    shell_command_info_t *records = nullptr;
    size_t record_count = 0;
    flat_group_records_valid =
        flat_group_records_valid &&
        shell_process_command(item.input, strlen(item.input), NULL, &records,
                              &record_count) == SHELL_PROCESS_OK &&
        records != nullptr && record_count == 2 &&
        strcmp(records[0].original_command, item.first) == 0 &&
        strcmp(records[1].original_command, item.second) == 0 &&
        records[0].has_redirections && records[1].has_redirections;
    shell_command_infos_free(records, record_count);
  }
  if (!flat_group_records_valid)
    return fixed_oracle_failure(__LINE__);

  /* Bash consumes an immediate raw `-` as a duplication close marker even
   * when a word follows without whitespace. Keep the lexer, canonical argv,
   * and dependency graph aligned without adding a checked-in smoke seed. */
  static const char raw_close_suffix[] = "printf x >&-file";
  shell_command_t *close_tokens = NULL;
  size_t close_token_count = 0;
  shell_command_info_t *close_infos = NULL;
  size_t close_info_count = 0;
  shell_netstring_buffer_t close_netargv = {};
  shell_dep_graph_t close_graph = {};
  bool raw_close_suffix_ok =
      shell_tokenize_commands(raw_close_suffix, sizeof(raw_close_suffix) - 1,
                              &close_tokens,
                              &close_token_count) == SHELL_TOKENIZE_OK &&
      close_token_count == 1 && close_tokens != nullptr &&
      close_tokens[0].token_count == 4 &&
      close_tokens[0].tokens[2].type == SHELL_TOKEN_REDIRECT_ERR &&
      close_tokens[0].tokens[2].length == 3 &&
      memcmp(close_tokens[0].tokens[2].start, ">&-", 3) == 0 &&
      close_tokens[0].tokens[3].type == SHELL_TOKEN_COMMAND &&
      close_tokens[0].tokens[3].length == 4 &&
      memcmp(close_tokens[0].tokens[3].start, "file", 4) == 0 &&
      shell_process_command(raw_close_suffix, sizeof(raw_close_suffix) - 1,
                            NULL, &close_infos,
                            &close_info_count) == SHELL_PROCESS_OK &&
      close_info_count == 1 && close_infos != nullptr &&
      shell_render_netargv_buffer(&close_infos[0], NULL, &close_netargv) ==
          SHELL_PROCESS_OK &&
      close_netargv.data != nullptr &&
      (close_netargv.length != sizeof("6:printf,1:x,4:file,") - 1 ||
       memcmp(close_netargv.data, "6:printf,1:x,4:file,",
              close_netargv.length)) == 0 &&
      shell_dep_graph_parse(raw_close_suffix, sizeof(raw_close_suffix) - 1, ".",
                            NULL, &close_graph) == SHELL_DEP_OK &&
      shell_dep_graph_validate(&close_graph).valid;
  bool close_edge = false;
  bool file_document = false;
  for (uint32_t i = 0; i < close_graph.edge_count; i++)
    close_edge =
        close_edge || (close_graph.edges[i].type == SHELL_EDGE_FD_CLOSE &&
                       close_graph.edges[i].source_fd == 1 &&
                       close_graph.edges[i].target_fd == SHELL_DEP_FD_NONE);
  for (uint32_t i = 0; i < close_graph.node_count; i++)
    file_document =
        file_document || (close_graph.nodes[i].type == SHELL_NODE_DOC &&
                          close_graph.nodes[i].doc.kind == SHELL_DOC_FILE);
  shell_commands_free(close_tokens, close_token_count);
  shell_command_infos_free(close_infos, close_info_count);
  shell_netstring_buffer_free(&close_netargv);
  if (!raw_close_suffix_ok || !close_edge || file_document)
    return fixed_oracle_failure(__LINE__);

  /* A persistent named close retires its setup document. An aliased name keeps
   * that document live, so the resolver must not use the historical FD_OPEN
   * edge as its only liveness signal. Keep these semantic cases in code rather
   * than growing the checked-in smoke corpus. */
  static const char named_close[] = "exec {fd}>out; exec {fd}>&-";
  static const char named_alias_close[] =
      "exec {fd}>out; exec {copy}>&$fd; exec {fd}>&-";
  shell_dep_graph_t named_close_graph = {};
  shell_dep_graph_t named_alias_close_graph = {};
  bool named_close_ok =
      shell_dep_graph_parse(named_close, sizeof(named_close) - 1, ".", NULL,
                            &named_close_graph) == SHELL_DEP_OK &&
      shell_dep_graph_parse(named_alias_close, sizeof(named_alias_close) - 1,
                            ".", NULL,
                            &named_alias_close_graph) == SHELL_DEP_OK &&
      shell_dep_graph_validate(&named_close_graph).valid &&
      shell_dep_graph_validate(&named_alias_close_graph).valid;
  bool named_close_transient = false;
  bool named_close_edge = false;
  for (uint32_t i = 0; i < named_close_graph.node_count; i++)
    named_close_transient =
        named_close_transient ||
        (named_close_graph.nodes[i].type == SHELL_NODE_DOC &&
         named_close_graph.nodes[i].doc.kind == SHELL_DOC_FILE &&
         (named_close_graph.nodes[i].doc.flags &
          SHELL_DEP_DOC_FLAG_TRANSIENT) != 0);
  for (uint32_t i = 0; i < named_close_graph.edge_count; i++)
    named_close_edge =
        named_close_edge ||
        (named_close_graph.edges[i].type == SHELL_EDGE_FD_CLOSE &&
         named_close_graph.edges[i].source_fd == SHELL_DEP_FD_NAMED &&
         named_close_graph.edges[i].target_fd == SHELL_DEP_FD_NONE);
  bool alias_remains_live = false;
  for (uint32_t i = 0; i < named_alias_close_graph.node_count; i++)
    alias_remains_live =
        alias_remains_live ||
        (named_alias_close_graph.nodes[i].type == SHELL_NODE_DOC &&
         named_alias_close_graph.nodes[i].doc.kind == SHELL_DOC_FILE &&
         (named_alias_close_graph.nodes[i].doc.flags &
          SHELL_DEP_DOC_FLAG_TRANSIENT) == 0);
  if (!named_close_ok || !named_close_transient || !named_close_edge ||
      !alias_remains_live)
    return fixed_oracle_failure(__LINE__);

  static const char raw_close_group[] = "{ printf x; } >&-file";
  shell_processed_commands_t rejected_group = {};
  shell_dep_graph_t rejected_graph = {};
  bool raw_close_group_ok =
      shell_process_commands(raw_close_group, sizeof(raw_close_group) - 1, NULL,
                             &rejected_group) == SHELL_PROCESS_EPARSE &&
      rejected_group.commands == nullptr && rejected_group.groups == nullptr &&
      rejected_group.group_io_ops == nullptr &&
      shell_dep_graph_parse(raw_close_group, sizeof(raw_close_group) - 1, ".",
                            NULL, &rejected_graph) == SHELL_DEP_EPARSE &&
      rejected_graph.node_count == 0 && rejected_graph.edge_count == 0;
  shell_processed_commands_free(&rejected_group);
  if (!raw_close_group_ok)
    return fixed_oracle_failure(__LINE__);

  /* Only syntax that actually quotes a word fragment hides outer list or
   * redirection operators. Keep every parser layer aligned on that boundary. */
  static const char *const opaque_word_cases[] = {
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
  for (const char *input : opaque_word_cases) {
    shell_parse_result_t parsed = {};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {};
    shell_dep_graph_t graph = {};
    bool opaque_word_ok =
        shell_parse_fast(input, strlen(input), NULL, &parsed) == SHELL_OK &&
        parsed.count == 1 && parsed.cmds[0].type == SHELL_TYPE_SIMPLE &&
        parsed.cmds[0].pipe_input_mode == SHELL_PIPE_MODE_NONE &&
        shell_tokenize_commands(input, strlen(input), &commands,
                                &command_count) == SHELL_TOKENIZE_OK &&
        command_count == 1 &&
        shell_process_commands(input, strlen(input), NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == 1 && !processed.commands[0].has_pipe_input &&
        !processed.commands[0].has_pipe_output &&
        shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        graph.edge_count == 3 && shell_dep_graph_validate(&graph).valid;
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    if (!opaque_word_ok)
      return fixed_oracle_failure(__LINE__);
  }

  /* A raw opening brace is literal in a parameter word. Keep both the
   * accepted operand forms and the outer-pipeline boundary in the always-run
   * oracle set without adding checked-in smoke seeds. */
  static const struct {
    const char *input;
    uint32_t command_count;
    uint32_t pipe_count;
  } parameter_literal_brace_cases[] = {
      {"echo ${value:-{}", 1, 0},
      {"echo ${value#{}", 1, 0},
      {"echo ${value/{}", 1, 0},
      {"echo ${value:-${fallback:-{}}", 1, 0},
      {"echo ${value:-{left}| cat", 2, 1},
  };
  for (const auto &item : parameter_literal_brace_cases) {
    shell_parse_result_t parsed = {};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {};
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    shell_abstract_command_t *abstract = NULL;
    shell_dep_graph_t graph = {};
    bool parameter_brace_ok =
        shell_parse_fast(item.input, strlen(item.input), NULL, &parsed) ==
            SHELL_OK &&
        parsed.count == item.command_count &&
        shell_tokenize_commands(item.input, strlen(item.input), &commands,
                                &command_count) == SHELL_TOKENIZE_OK &&
        command_count == item.command_count &&
        shell_process_commands(item.input, strlen(item.input), NULL,
                               &processed) == SHELL_PROCESS_OK &&
        processed.command_count == item.command_count &&
        shell_transform_command_line(item.input, strlen(item.input), NULL,
                                     &transformed, &transformed_count) ==
            SHELL_TRANSFORM_OK &&
        transformed_count == item.command_count &&
        shell_abstract_command_parse(item.input, strlen(item.input),
                                     &abstract) == SHELL_ABSTRACT_OK &&
        abstract != NULL &&
        shell_dep_graph_parse(item.input, strlen(item.input), ".", NULL,
                              &graph) == SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    uint32_t pipe_count = 0;
    for (uint32_t edge = 0; parameter_brace_ok && edge < graph.edge_count;
         edge++)
      pipe_count += graph.edges[edge].type == SHELL_EDGE_PIPE;
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
    if (!parameter_brace_ok || pipe_count != item.pipe_count)
      return fixed_oracle_failure(__LINE__);
  }

  for (const char *input : {"{ printf ok; <(); } 2>errors",
                            "{ { printf ok; <(); } 2>inner; >(); } >outer"}) {
    shell_processed_commands_t structured = {};
    shell_command_info_t *flat = nullptr;
    size_t flat_count = 0;
    bool ok = shell_process_commands(input, strlen(input), nullptr,
                                     &structured) == SHELL_PROCESS_OK &&
              structured.command_count == 1 &&
              shell_process_command(input, strlen(input), nullptr, &flat,
                                    &flat_count) == SHELL_PROCESS_OK &&
              flat_count >= 2 && flat[0].has_redirections &&
              flat[0].has_error_redirection;
    for (size_t i = 1; ok && i < flat_count; i++)
      ok = !flat[i].has_redirections && !flat[i].has_error_redirection;
    shell_processed_commands_free(&structured);
    shell_command_infos_free(flat, flat_count);
    if (!ok)
      return fixed_oracle_failure(__LINE__);
  }

  static const struct {
    const char *source;
    const char *paths[2];
  } file_argument_cases[] = {
      {"/bin/echo hello", {nullptr, nullptr}},
      {"<() /bin/echo hello", {nullptr, nullptr}},
      {"X=x </dev/null <()>() /bin/echo hello", {nullptr, nullptr}},
      {"<() /bin/echo /tmp/input", {"/tmp/input", nullptr}},
      {"''<() /bin/echo /tmp/input", {"/bin/echo", "/tmp/input"}},
      {"command <() /bin/echo /tmp/input", {"/bin/echo", "/tmp/input"}},
      {"$(printf program) /tmp/input", {"/tmp/input", nullptr}}};
  for (const auto &item : file_argument_cases) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(item.source, strlen(item.source), "/workspace",
                              nullptr, &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    size_t seen = 0;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const shell_dep_edge_t &edge = graph.edges[e];
      if (edge.type != SHELL_EDGE_ARG)
        continue;
      if (seen == 2 || !item.paths[seen])
        return fixed_oracle_failure(__LINE__);
      const shell_dep_doc_t &doc = graph.nodes[edge.to].doc;
      if (doc.path_len != strlen(item.paths[seen]) ||
          memcmp(doc.path, item.paths[seen], doc.path_len))
        return fixed_oracle_failure(__LINE__);
      seen++;
    }
    if (seen != static_cast<size_t>(item.paths[0] != nullptr) +
                    static_cast<size_t>(item.paths[1] != nullptr))
      return fixed_oracle_failure(__LINE__);
  }

  static const char *const structural_word_cases[] = {
      "echo prefix{left|right}suffix",
      "echo [left|right]",
      "echo [[:alpha:]|]",
  };
  for (const char *input : structural_word_cases) {
    shell_parse_result_t parsed = {};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {};
    shell_dep_graph_t graph = {};
    uint32_t pipe_count = 0;
    bool structural_word_ok =
        shell_parse_fast(input, strlen(input), NULL, &parsed) == SHELL_OK &&
        parsed.count == 2 && parsed.cmds[1].type == SHELL_TYPE_PIPELINE &&
        parsed.cmds[1].pipe_input_mode == SHELL_PIPE_MODE_STDOUT &&
        shell_tokenize_commands(input, strlen(input), &commands,
                                &command_count) == SHELL_TOKENIZE_OK &&
        command_count == 2 &&
        shell_process_commands(input, strlen(input), NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == 2 && processed.commands[0].has_pipe_output &&
        processed.commands[1].has_pipe_input &&
        shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    for (uint32_t edge = 0; structural_word_ok && edge < graph.edge_count;
         edge++)
      pipe_count += graph.edges[edge].type == SHELL_EDGE_PIPE;
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    if (!structural_word_ok || pipe_count != 1)
      return fixed_oracle_failure(__LINE__);
  }

  static const struct {
    const char *input;
    uint32_t command_count;
    uint32_t pipe_count;
  } redirect_fragment_cases[] = {
      {"printf x >out@(left|right)", 1, 0},
      {"printf x >out{left|right}", 2, 0},
      {"printf x >out[left|right]", 2, 0},
      {"printf x >&$", 1, 0},
      {"printf x >&[", 1, 0},
      {"printf x >&file[part", 1, 0},
  };
  for (const auto &item : redirect_fragment_cases) {
    shell_parse_result_t parsed = {};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {};
    shell_dep_graph_t graph = {};
    uint32_t pipe_count = 0;
    bool redirect_fragment_ok =
        shell_parse_fast(item.input, strlen(item.input), NULL, &parsed) ==
            SHELL_OK &&
        parsed.count == item.command_count &&
        shell_tokenize_commands(item.input, strlen(item.input), &commands,
                                &command_count) == SHELL_TOKENIZE_OK &&
        command_count == item.command_count &&
        shell_process_commands(item.input, strlen(item.input), NULL,
                               &processed) == SHELL_PROCESS_OK &&
        processed.command_count == item.command_count &&
        shell_dep_graph_parse(item.input, strlen(item.input), ".", NULL,
                              &graph) == SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    for (uint32_t edge = 0; redirect_fragment_ok && edge < graph.edge_count;
         edge++)
      pipe_count += graph.edges[edge].type == SHELL_EDGE_PIPE;
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    if (!redirect_fragment_ok || pipe_count != item.pipe_count)
      return fixed_oracle_failure(__LINE__);
  }

  /* A document-only right pipeline member still owns its document input, but
   * the preceding command retains the real pipe route to an endpoint. */
  static const struct {
    const char *input;
    uint16_t marker_type;
    shell_pipe_mode_t mode;
    uint32_t pipe_count;
  } document_pipeline_cases[] = {
      {"printf x | <<EOF\nbody\nEOF\n", SHELL_TYPE_HEREDOC,
       SHELL_PIPE_MODE_STDOUT, 1},
      {"printf x | <<<body", SHELL_TYPE_HERESTRING, SHELL_PIPE_MODE_STDOUT, 1},
      {"printf x |& <<EOF\nbody\nEOF\n", SHELL_TYPE_HEREDOC,
       SHELL_PIPE_MODE_STDOUT_AND_STDERR, 2},
      {"printf x |& <<<body", SHELL_TYPE_HERESTRING,
       SHELL_PIPE_MODE_STDOUT_AND_STDERR, 2},
  };
  for (const auto &item : document_pipeline_cases) {
    shell_parse_result_t parsed = {};
    shell_processed_commands_t processed = {};
    shell_dep_graph_t graph = {};
    bool document_pipeline_ok =
        shell_parse_fast(item.input, strlen(item.input), NULL, &parsed) ==
            SHELL_OK &&
        parsed.count == 2 && parsed.cmds[1].type == item.marker_type &&
        parsed.cmds[1].pipe_input_mode == item.mode &&
        shell_process_commands(item.input, strlen(item.input), NULL,
                               &processed) == SHELL_PROCESS_OK &&
        processed.command_count == 1 && processed.commands[0].has_pipe_output &&
        processed.commands[0].pipe_output_mode == item.mode &&
        shell_dep_graph_parse(item.input, strlen(item.input), ".", NULL,
                              &graph) == SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    uint32_t pipe_count = 0;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      pipe_count += graph.edges[edge].type == SHELL_EDGE_PIPE;
    shell_processed_commands_free(&processed);
    if (!document_pipeline_ok || pipe_count != item.pipe_count)
      return fixed_oracle_failure(__LINE__);
  }

  /* Named descriptors prefix document redirects; neither the descriptor nor
   * the document marker may become argv.  Keep these fixed cross-layer
   * oracles outside the checked-in smoke corpus. */
  static const char *const named_document_cases[] = {
      "printf x {fd}<<<body",     "printf x {fd}<<EOF\nbody\nEOF\n",
      "{ cat; } {fd}<<<body",     "{ cat; } {fd}<<EOF\nbody\nEOF\n",
      "printf x {f\\\nd}<<<body", "{ cat; } {f\\\nd}\\\n<<EOF\nbody\nEOF\n",
  };
  for (const char *input : named_document_cases) {
    shell_parse_result_t parsed = {};
    shell_processed_commands_t processed = {};
    shell_dep_graph_t graph = {};
    bool named_document_ok =
        shell_parse_fast(input, strlen(input), NULL, &parsed) == SHELL_OK &&
        shell_process_commands(input, strlen(input), NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == 1 &&
        shell_dep_graph_parse(input, strlen(input), "/tmp", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    uint32_t command_nodes = 0;
    bool named_document_edge = false;
    for (uint32_t node = 0; node < graph.node_count; node++)
      command_nodes += graph.nodes[node].type == SHELL_NODE_CMD;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      named_document_edge = named_document_edge ||
                            (graph.edges[edge].type == SHELL_EDGE_FD_OPEN &&
                             graph.edges[edge].source_fd == SHELL_DEP_FD_NONE &&
                             graph.edges[edge].target_fd == SHELL_DEP_FD_NAMED);
    shell_processed_commands_free(&processed);
    if (!named_document_ok || command_nodes != 1 || !named_document_edge) {
      return fixed_oracle_failure(__LINE__);
    }
  }

  /* Named FD lifecycle and process substitutions have a dynamic numeric value
   * but a stable logical identity. Exercise the supported forms independently
   * of the bounded checked-in smoke corpus. */
  static const char *const named_fd_route_cases[] = {
      "printf x {fd}>out >&\"$fd\"",
      "printf x {fd}<in <&${fd}",
      "cmd {fd}< <(producer)",
      "cmd {fd}> >(consumer)",
      "printf x {fd}>out; printf x >&$fd",
      "exec {fd}>out; printf x >&$fd",
      "exec {fd}>out; unset unrelated >&$fd; printf x >&$fd",
      "exec {fd}>out; export OTHER=1 >fd=shadow; printf x >&$fd",
      "exec {fd}>out; ( printf x >&$fd )",
      "exec {fd}<in; printf x \"$(cat <&$fd)\"",
      "exec {fd}<&0; printf x \"$(cat <&$fd)\"",
      "exec {source}<in; exec {copy}<&$source; printf x \"$(cat <&$copy)\"",
      "exec {out}>out; exec {copy}<&$out; printf x >&$copy",
      "exec {in}<in; exec {copy}>&$in; cat <&$copy",
      "printf {fd}<in > >(cat <&$fd)",
      "printf x {f\\\nd}>out >&$f\\\nd",
      "exec {f\\\nd}>out; printf x >&$fd",
      "exec {fd}>out; printf x >&$f\\\nd",
      "exec {fd}>out; printf x >&\"${f\\\nd}\"",
      "exec {fd}>out; printf x >&$\\\n{fd}",
      "exec {source}< <(printf x >/tmp/fuzz-source); cat <&$source",
      "exec {sink}> >(cat </tmp/fuzz-sink); printf x >&$sink",
      "printf x >&combined",
      "printf x 1>&combined",
      "printf x >& >(consumer)",
      "exec 3>out; printf x >&3",
      "exec 3<in; printf x \"$(cat <&3)\"",
      "exec 3> >(consumer); printf x >&3",
  };
  for (const char *input : named_fd_route_cases) {
    shell_processed_commands_t processed = {};
    shell_dep_graph_t graph = {};
    bool named_fd_ok = shell_process_commands(input, strlen(input), NULL,
                                              &processed) == SHELL_PROCESS_OK &&
                       processed.command_count >= 1 &&
                       shell_dep_graph_parse(input, strlen(input), "/tmp", NULL,
                                             &graph) == SHELL_DEP_OK &&
                       shell_dep_graph_validate(&graph).valid;
    bool named_metadata = false;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      named_metadata = named_metadata ||
                       (graph.edges[edge].source_fd == SHELL_DEP_FD_NAMED &&
                        graph.edges[edge].source_fd_name != nullptr) ||
                       (graph.edges[edge].target_fd == SHELL_DEP_FD_NAMED &&
                        graph.edges[edge].target_fd_name != nullptr);
    if (std::strncmp(input, "printf x {", std::strlen("printf x {")) == 0)
      named_fd_ok =
          named_fd_ok && processed.commands[0].command_token_count == 2;
    shell_processed_commands_free(&processed);
    /* The same oracle also covers static legacy `>&path` output routing.
     * Those forms have no Bash `{name}` identity, so only named-descriptor
     * syntax is required to produce named edge metadata. */
    if (!named_fd_ok || (std::strchr(input, '{') != nullptr && !named_metadata))
      return fixed_oracle_failure(__LINE__);
  }

  /* Only backslash-LF joins a named descriptor. CR is an ordinary byte, and
   * CR before LF leaves the CR in the preceding word before LF starts another
   * command. Keep the distinction in fixed oracles, not evolving seeds. */
  static const struct {
    const char *input;
    uint32_t named_edges;
    uint32_t commands;
  } non_joining_named_cases[] = {
      {": {f\\\rd}>out", 0, 1},
      {": {f\\\r\n: d}>out", 0, 2},
      {"exec {fd}>out; printf x >&$f\\\rd", 1, 2},
      {"exec {fd}>out; printf x >&$\\\r{fd}", 1, 2},
      {"exec {fd}>out; printf x >&$\\\r\n{fd}", 1, 3},
  };
  for (size_t index = 0; index < sizeof(non_joining_named_cases) /
                                     sizeof(non_joining_named_cases[0]);
       index++) {
    const char *input = non_joining_named_cases[index].input;
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(input, std::strlen(input), "/tmp", nullptr,
                              &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    uint32_t named_edges = 0;
    uint32_t commands = 0;
    for (uint32_t node = 0; node < graph.node_count; node++)
      commands += graph.nodes[node].type == SHELL_NODE_CMD;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      named_edges += graph.edges[edge].source_fd == SHELL_DEP_FD_NAMED ||
                     graph.edges[edge].target_fd == SHELL_DEP_FD_NAMED;
    if (named_edges != non_joining_named_cases[index].named_edges ||
        commands != non_joining_named_cases[index].commands)
      return fixed_oracle_failure(__LINE__);
  }

  /* The route model intentionally has no readonly-variable attribute state.
   * A setter can make a later named-FD allocation fail while retaining an old
   * binding, so every canonical producer must reject it atomically rather than
   * fabricate a replacement route. Keep the regression outside smoke seeds. */
  static const char *const named_fd_readonly_cases[] = {
      "exec {fd}>/tmp/fuzz-readonly-first; readonly fd; "
      "exec {fd}>/tmp/fuzz-readonly-second; printf x >&$fd",
      "exec {fd}>/tmp/fuzz-readonly-first; declare -r fd; "
      "exec {fd}>/tmp/fuzz-readonly-second; printf x >&$fd",
      "exec {fd}>/tmp/fuzz-readonly-first; typeset -r fd; "
      "exec {fd}>/tmp/fuzz-readonly-second; printf x >&$fd",
  };
  for (const char *input : named_fd_readonly_cases) {
    shell_processed_commands_t processed = {};
    processed.commands = reinterpret_cast<shell_command_info_t *>(uintptr_t{1});
    processed.command_count = SIZE_MAX;
    shell_dep_graph_t graph = {};
    bool named_fd_readonly_ok =
        shell_process_commands(input, std::strlen(input), nullptr,
                               &processed) == SHELL_PROCESS_EPARSE &&
        processed.commands == nullptr && processed.command_count == 0 &&
        shell_dep_graph_parse(input, std::strlen(input), "/tmp", nullptr,
                              &graph) == SHELL_DEP_EPARSE &&
        graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
        graph.edge_count == 0;
    shell_processed_commands_free(&processed);
    if (!named_fd_readonly_ok)
      return fixed_oracle_failure(__LINE__);
  }

  /* A parameter-expansion fragment after `set -o` can select POSIX mode, and
   * one after `printf -v` can target POSIXLY_CORRECT. Exercise the shared
   * semantic gate through both processed-command and depgraph producers. */
  static const char *const dynamic_current_shell_cases[] = {
      "set -o \"$option\"; printf x",
      "printf -v \"$target\" enabled; printf x",
  };
  for (const char *input : dynamic_current_shell_cases) {
    shell_processed_commands_t processed = {};
    processed.commands = reinterpret_cast<shell_command_info_t *>(uintptr_t{1});
    processed.command_count = SIZE_MAX;
    shell_dep_graph_t graph = {};
    bool dynamic_current_shell_ok =
        shell_process_commands(input, std::strlen(input), nullptr,
                               &processed) == SHELL_PROCESS_EPARSE &&
        processed.commands == nullptr && processed.command_count == 0 &&
        shell_dep_graph_parse(input, std::strlen(input), "/tmp", nullptr,
                              &graph) == SHELL_DEP_EPARSE &&
        graph.status == SHELL_DEP_STATUS_ERROR && graph.node_count == 0 &&
        graph.edge_count == 0;
    shell_processed_commands_free(&processed);
    if (!dynamic_current_shell_ok)
      return fixed_oracle_failure(__LINE__);
  }

  /* Escaped physical line endings disappear before `${name}` recognition.
   * Keep this precise no-crash oracle independent of the bounded smoke
   * corpus: it must remain a stdout-only named-FD duplication, never a
   * legacy combined stdout-and-stderr redirect. */
  static const char braced_named_continuation[] =
      "exec {fd}>out; printf x >&$\\\n{fd}";
  shell_dep_graph_t braced_named_graph = {};
  if (shell_dep_graph_parse(braced_named_continuation,
                            sizeof(braced_named_continuation) - 1, "/tmp",
                            nullptr, &braced_named_graph) != SHELL_DEP_OK ||
      !shell_dep_graph_validate(&braced_named_graph).valid)
    return fixed_oracle_failure(__LINE__);
  uint32_t stdout_writes = 0;
  uint32_t stderr_writes = 0;
  for (uint32_t edge = 0; edge < braced_named_graph.edge_count; edge++) {
    const shell_dep_edge_t *current = &braced_named_graph.edges[edge];
    if (!internal_graph_relation(braced_named_graph, *current))
      continue;
    if (current->type != SHELL_EDGE_WRITE)
      continue;
    stdout_writes += current->source_fd == 1;
    stderr_writes += current->source_fd == 2;
  }
  if (stdout_writes != 1 || stderr_writes != 0)
    return fixed_oracle_failure(__LINE__);

  /* An overridden output-process collector can be pruned while a later
   * command in the same recursive scope still uses an imported descriptor.
   * The private owner index must follow node compaction so the concrete route
   * reaches that final command, for named and numeric descriptors alike. */
  static const struct {
    const char *input;
    const char *path;
    const char *final_command;
    const char *final_argument;
    shell_dep_edge_type_t edge_type;
    uint32_t source_fd;
    uint32_t target_fd;
  } recursive_import_pruning_cases[] = {
      {"exec {fd}>/tmp/import-out; printf \"$(printf x > >(sink) "
       ">/tmp/replaced; printf y >&$fd)\"",
       "/tmp/import-out", "printf", "y", SHELL_EDGE_WRITE, 1,
       SHELL_DEP_FD_NONE},
      {"exec 3>/tmp/import-out; printf \"$(printf x > >(sink) "
       ">/tmp/replaced; printf y >&3)\"",
       "/tmp/import-out", "printf", "y", SHELL_EDGE_WRITE, 1,
       SHELL_DEP_FD_NONE},
      {"exec {fd}</tmp/import-in; printf \"$(printf x > >(sink) "
       ">/tmp/replaced; cat <&$fd)\"",
       "/tmp/import-in", "cat", nullptr, SHELL_EDGE_READ, SHELL_DEP_FD_NONE, 0},
      {"exec 3</tmp/import-in; printf \"$(printf x > >(sink) "
       ">/tmp/replaced; cat <&3)\"",
       "/tmp/import-in", "cat", nullptr, SHELL_EDGE_READ, SHELL_DEP_FD_NONE, 0},
  };
  for (const auto &item : recursive_import_pruning_cases) {
    shell_processed_commands_t processed = {};
    shell_dep_graph_t graph = {};
    bool recursive_import_ok =
        shell_process_commands(item.input, strlen(item.input), nullptr,
                               &processed) == SHELL_PROCESS_OK &&
        processed.command_count >= 1 &&
        shell_dep_graph_parse(item.input, strlen(item.input), "/tmp", nullptr,
                              &graph) == SHELL_DEP_OK &&
        graph.status == SHELL_DEP_STATUS_OK &&
        shell_dep_graph_validate(&graph).valid;
    int document = -1;
    int final = -1;
    int sink = -1;
    for (uint32_t node = 0; node < graph.node_count; node++) {
      const shell_dep_node_t *current = &graph.nodes[node];
      if (current->type == SHELL_NODE_DOC &&
          current->doc.kind == SHELL_DOC_FILE &&
          current->doc.path_len == strlen(item.path) &&
          std::memcmp(current->doc.path, item.path, current->doc.path_len) == 0)
        document = (int)node;
      if (current->type != SHELL_NODE_CMD || current->cmd.token_count == 0)
        continue;
      if (current->cmd.token_lens[0] == std::strlen("sink") &&
          std::memcmp(current->cmd.tokens[0], "sink", std::strlen("sink")) == 0)
        sink = (int)node;
      if (current->cmd.token_lens[0] == std::strlen(item.final_command) &&
          std::memcmp(current->cmd.tokens[0], item.final_command,
                      current->cmd.token_lens[0]) == 0 &&
          (!item.final_argument ||
           (current->cmd.token_count > 1 &&
            current->cmd.token_lens[1] == std::strlen(item.final_argument) &&
            std::memcmp(current->cmd.tokens[1], item.final_argument,
                        current->cmd.token_lens[1]) == 0)))
        final = (int)node;
    }
    bool route = false;
    bool stale_collector_substitution = false;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      const shell_dep_edge_t *current = &graph.edges[edge];
      if (!internal_graph_relation(graph, *current))
        continue;
      stale_collector_substitution =
          stale_collector_substitution ||
          (sink >= 0 && current->type == SHELL_EDGE_SUBST &&
           current->to == (uint32_t)sink);
      route = route ||
              (document >= 0 && final >= 0 && current->type == item.edge_type &&
               current->source_fd == item.source_fd &&
               current->target_fd == item.target_fd &&
               (item.edge_type == SHELL_EDGE_READ
                    ? current->from == (uint32_t)document &&
                          current->to == (uint32_t) final
                    : current->from == (uint32_t) final &&
                          current->to == (uint32_t)document));
    }
    shell_processed_commands_free(&processed);
    if (!recursive_import_ok || document < 0 || final < 0 || sink < 0 ||
        stale_collector_substitution || !route)
      return fixed_oracle_failure(__LINE__);
  }

  static const char *const static_legacy_redirect_cases[] = {
      "printf x >&\"\"",
      "printf x >&literal{path}",
      "printf x >&literal$destination",
      "printf x >&literal${destination}",
      "printf x >&literal$((1 + 2))",
      "printf x >&\"\"literal$(printf target)",
      "printf x >&file{one,two}",
      "printf x >&{$destination}",
      "printf x >&{{1,2}}",
      "printf x >&{{1,2}",
      "printf x >&file[[[[[:unfinished",
      "printf x >&{[$'a']}",
      "printf x >&{[$'']}",
  };
  for (const char *input : static_legacy_redirect_cases) {
    shell_processed_commands_t processed = {};
    shell_dep_graph_t graph = {};
    bool static_redirect_ok =
        shell_process_commands(input, strlen(input), NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == 1 &&
        shell_dep_graph_parse(input, strlen(input), "/tmp", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    shell_processed_commands_free(&processed);
    if (!static_redirect_ok)
      return fixed_oracle_failure(__LINE__);
  }

  /* Invalid static descriptor targets must be rejected by the processors as
   * well as the graph. Keep this independent of corpus seeds: it protects the
   * shared legacy `>&word` classifier's fail-closed outcome. */
  static const char *const invalid_static_legacy_redirects[] = {
      "printf x >&2147483648",
      "printf x >&00000000000000000000000000000000002147483648",
      "printf x >&$'a\\0b'",
  };
  for (const char *input : invalid_static_legacy_redirects) {
    shell_processed_commands_t processed = {};
    shell_command_info_t *flat = nullptr;
    size_t flat_count = 0;
    shell_dep_graph_t graph = {};
    if (shell_process_commands(input, strlen(input), NULL, &processed) !=
            SHELL_PROCESS_EPARSE ||
        processed.commands != nullptr || processed.command_count != 0 ||
        shell_process_command(input, strlen(input), NULL, &flat, &flat_count) !=
            SHELL_PROCESS_EPARSE ||
        flat != nullptr || flat_count != 0 ||
        shell_dep_graph_parse(input, strlen(input), "/tmp", NULL, &graph) !=
            SHELL_DEP_EPARSE ||
        graph.node_count != 0 || graph.edge_count != 0)
      return fixed_oracle_failure(__LINE__);
  }

  /* `&>` is two dynamic descriptor routes, not one combined byte edge. Later
   * redirections must replace only the route they target. */
  struct combined_process_route_oracle {
    const char *input;
    const char *stdout_file;
    const char *stderr_file;
    shell_dep_edge_type_t stdout_type;
    shell_dep_edge_type_t stderr_type;
    bool stdout_endpoint;
    bool stderr_endpoint;
  };
  static const combined_process_route_oracle combined_process_route_cases[] = {
      {"cat log >old &> >(sh </dev/null)", nullptr, nullptr, SHELL_EDGE_WRITE,
       SHELL_EDGE_WRITE, true, true},
      {"cat log &> >(sh) >out", "out", nullptr, SHELL_EDGE_WRITE,
       SHELL_EDGE_WRITE, false, true},
      {"cat log &>> >(sh) 2>>err", nullptr, "err", SHELL_EDGE_WRITE,
       SHELL_EDGE_APPEND, true, true},
      {"cat log >& >(sh) 2>&-", nullptr, nullptr, SHELL_EDGE_WRITE,
       SHELL_EDGE_WRITE, true, false},
      {"cat log &> >(sh) >out 2>&1", "out", "out", SHELL_EDGE_WRITE,
       SHELL_EDGE_WRITE, false, true},
  };
  for (const combined_process_route_oracle &item :
       combined_process_route_cases) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(item.input, strlen(item.input), "/tmp", NULL,
                              &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    int writer = -1;
    int stdout_file = -1;
    int stderr_file = -1;
    for (uint32_t node = 0; node < graph.node_count; node++) {
      if (writer < 0 && graph.nodes[node].type == SHELL_NODE_CMD)
        writer = (int)node;
      if (graph.nodes[node].type != SHELL_NODE_DOC ||
          graph.nodes[node].doc.kind != SHELL_DOC_FILE)
        continue;
      if (item.stdout_file &&
          graph.nodes[node].doc.path_len == strlen(item.stdout_file) &&
          memcmp(graph.nodes[node].doc.path, item.stdout_file,
                 graph.nodes[node].doc.path_len) == 0)
        stdout_file = (int)node;
      if (item.stderr_file &&
          graph.nodes[node].doc.path_len == strlen(item.stderr_file) &&
          memcmp(graph.nodes[node].doc.path, item.stderr_file,
                 graph.nodes[node].doc.path_len) == 0)
        stderr_file = (int)node;
    }
    bool stdout_endpoint = false;
    bool stderr_endpoint = false;
    bool stdout_file_route = item.stdout_file == nullptr;
    bool stderr_file_route = item.stderr_file == nullptr;
    for (uint32_t edge = 0; writer >= 0 && edge < graph.edge_count; edge++) {
      const shell_dep_edge_t &current = graph.edges[edge];
      if (current.from != (uint32_t)writer)
        continue;
      if (current.type == SHELL_EDGE_WRITE &&
          graph.nodes[current.to].type == SHELL_NODE_ENDPOINT) {
        stdout_endpoint = stdout_endpoint || current.source_fd == 1;
        stderr_endpoint = stderr_endpoint || current.source_fd == 2;
      }
      stdout_file_route =
          stdout_file_route ||
          (stdout_file >= 0 && current.to == (uint32_t)stdout_file &&
           current.type == item.stdout_type && current.source_fd == 1);
      stderr_file_route =
          stderr_file_route ||
          (stderr_file >= 0 && current.to == (uint32_t)stderr_file &&
           current.type == item.stderr_type && current.source_fd == 2);
    }
    if (writer < 0 || stdout_endpoint != item.stdout_endpoint ||
        stderr_endpoint != item.stderr_endpoint || !stdout_file_route ||
        !stderr_file_route)
      return fixed_oracle_failure(__LINE__);
  }

  /* Descriptor references in nested shell evaluations are meaningful only
   * after an unconditional persistent binding at that exact expansion point.
   * Bash's default `varredir_close` also keeps a preceding ordinary command's
   * open `{name}` binding; option mutations and isolated groups must not
   * silently change that model. */
  static const char *const named_fd_snapshot_rejections[] = {
      "printf x {fd}<in \"$(cat <&$fd)\"",
      "exec {fd}<in; exec {fd}<&-; printf x \"$(cat <&$fd)\"",
      "printf > >(cat <&$fd) {fd}<in",
      "shopt -s varredir_close; : {fd}<in; printf x \"$(cat <&$fd)\"",
      "x+=value shopt -u varredir_close; : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      "x+\\\n=value shopt -s varredir_close; : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      "shopt -s lastpipe; printf source | : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      "eval 'shopt -s lastpipe'; printf source | : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      ". /tmp/shell-state; printf source | : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      "command source /tmp/shell-state; printf source | : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      "trap 'shopt -s lastpipe' DEBUG; printf source | : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      "alias change_scope='shopt -s lastpipe'; "
      "printf source | : {fd}<in; printf x \"$(cat <&$fd)\"",
      "shopt -s expand_aliases; printf source | : {fd}<in; "
      "printf x \"$(cat <&$fd)\"",
      "history -s 'shopt -s lastpipe'; fc -s -1; "
      "printf source | : {fd}<in; printf x \"$(cat <&$fd)\"",
      "enable -f /tmp/shell-state change_scope; "
      "printf source | : {fd}<in; printf x \"$(cat <&$fd)\"",
      "( : ) {fd}>out; printf x >&$fd",
      "{ :; } {fd}>out | cat; printf x >&$fd",
      "exec {fd}>base; probe && unset fd; printf after >&$fd",
      "exec {fd}>base; probe || { unset fd; }; printf after >&$fd",
      "exec {fd}>base; probe && { fd=1; }; printf after >&$fd",
      "exec {fd}<base; probe && { unset fd; }; echo \"$(cat <&$fd)\"",
  };
  for (const char *input : named_fd_snapshot_rejections) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(input, strlen(input), "/tmp", NULL, &graph) !=
            SHELL_DEP_EPARSE ||
        graph.node_count != 0 || graph.edge_count != 0 ||
        graph.status != SHELL_DEP_STATUS_ERROR)
      return fixed_oracle_failure(__LINE__);
  }

  static const char *const dynamic_legacy_redirect_rejections[] = {
      "printf x >&?(one|two)",  "printf x >&*(one|two)",
      "printf x >&+(one|two)",  "printf x >&@(one|two)",
      "printf x >&!(one|two)",  "printf x >&\\\n~",
      "printf x >&[[:digit:]]", "printf x >&[[=a=]]",
      "printf x >&[[.a.]]",     "printf x >&$(printf 2)",
      "printf x >&`printf 2`",  "exec {fd}>out; fd+=shadow; printf x >&$fd",
  };
  for (const char *input : dynamic_legacy_redirect_rejections) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(input, strlen(input), "/tmp", NULL, &graph) !=
            SHELL_DEP_EPARSE ||
        graph.node_count != 0 || graph.edge_count != 0 ||
        graph.status != SHELL_DEP_STATUS_ERROR)
      return fixed_oracle_failure(__LINE__);
  }

  static const char *const literal_named_fd_cases[] = {
      "cat $'x'{fd}>out",
      "cat ''{fd}>out",
      "cat ${x}{fd}<<<body",
      "cat $(id){fd}>out",
  };
  for (const char *input : literal_named_fd_cases) {
    shell_processed_commands_t processed = {};
    shell_dep_graph_t graph = {};
    bool ok = shell_process_commands(input, strlen(input), NULL, &processed) ==
                  SHELL_PROCESS_OK &&
              processed.command_count == 1 &&
              processed.commands[0].command_token_count == 2 &&
              shell_dep_graph_parse(input, strlen(input), "/tmp", NULL,
                                    &graph) == SHELL_DEP_OK &&
              shell_dep_graph_validate(&graph).valid;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      if (graph.edges[edge].type == SHELL_EDGE_FD_OPEN &&
          (graph.edges[edge].source_fd == SHELL_DEP_FD_NAMED ||
           graph.edges[edge].target_fd == SHELL_DEP_FD_NAMED))
        ok = false;
    shell_processed_commands_free(&processed);
    if (!ok)
      return fixed_oracle_failure(__LINE__);
  }

  static const char compound_words[] =
      "$'c'3>out;cat \"x\"${y}z;my\\\ncommand value";
  shell_netstring_buffer_t raw = {};
  shell_netstring_buffer_t typed = {};
  size_t compound_count = 0;
  bool compound_ok =
      shell_build_anomaly_netseqs_buffer(
          compound_words, sizeof(compound_words) - 1, NULL, &raw, &typed,
          &compound_count) == SHELL_PROCESS_OK &&
      compound_count == 3 && raw.data && typed.data &&
      (raw.length != sizeof("2:c3,3:cat,9:mycommand,") - 1 ||
       memcmp(raw.data, "2:c3,3:cat,9:mycommand,", raw.length)) == 0 &&
      (typed.length !=
           sizeof("5:2:c3,,12:3:cat,3:STR,,18:9:mycommand,3:STR,,") - 1 ||
       memcmp(typed.data, "5:2:c3,,12:3:cat,3:STR,,18:9:mycommand,3:STR,,",
              typed.length)) == 0;
  shell_netstring_buffer_free(&typed);
  shell_netstring_buffer_free(&raw);
  if (!compound_ok)
    return fixed_oracle_failure(__LINE__);

  static const char *const negated_document_cases[] = {
      "! <<<body",
      "! ! <<<body",
      "! <<EOF\nbody\nEOF\n",
      "! ! <<EOF\nbody\nEOF\n",
  };
  for (const char *input : negated_document_cases) {
    shell_parse_result_t parsed = {};
    shell_dep_graph_t graph = {};
    if (shell_parse_fast(input, strlen(input), NULL, &parsed) != SHELL_OK ||
        parsed.count != 1 || parsed.cmds[0].pipeline_negation_count == 0 ||
        shell_dep_graph_parse(input, strlen(input), "/tmp", NULL, &graph) !=
            SHELL_DEP_OK ||
        graph.node_count == 0 || graph.nodes[0].type != SHELL_NODE_CMD ||
        graph.nodes[0].cmd.token_count != 0 ||
        graph.nodes[0].cmd.pipeline_negation_count !=
            parsed.cmds[0].pipeline_negation_count ||
        !shell_dep_graph_validate(&graph).valid) {
      return fixed_oracle_failure(__LINE__);
    }
  }

  struct timed_pipeline_oracle {
    const char *input;
    uint32_t timer_count;
  };
  static const timed_pipeline_oracle timed_pipeline_cases[] = {
      {"time printf x | cat", 1},
      {"time ({ printf x; })", 1},
      {"time ({(printf x)}) | cat", 1},
      {"time printf x <<<body | cat", 1},
      {"time printf x <<EOF | cat\nbody\nEOF\n", 1},
      {"time printf x | <<<body", 1},
      {"time { printf x; } | <<<body", 1},
      {"time -p -- { printf x; } | cat", 1},
      {"{ time { printf nested; }; printf outer; }", 1},
      {"time { printf x; } 2>err | cat", 1},
      {"time printf x | { cat; } 2>err | sort", 1},
      {"time>/tmp/timing printf x", 1},
      {"ti\\\nme printf x", 1},
      {"time -p ! 3<<<body", 1},
      {"time$(printf x)", 0},
      {"time>(printf x)", 0},
      {"time !", 1},
      {"time printf x | { time -p cat; printf tail; } | sort", 2},
      {"time { time a | b; } | c", 2},
      {"time (time a | b) | c", 2},
      {"time { time; } | c", 2},
  };
  for (const timed_pipeline_oracle &item : timed_pipeline_cases) {
    const char *input = item.input;
    shell_parse_result_t parsed = {};
    shell_processed_commands_t processed = {};
    shell_dep_graph_t graph = {};
    shell_error_t fast_status =
        shell_parse_fast(input, strlen(input), NULL, &parsed);
    shell_process_status_t process_status =
        shell_process_commands(input, strlen(input), NULL, &processed);
    shell_dep_error_t graph_status =
        shell_dep_graph_parse(input, strlen(input), "/tmp", NULL, &graph);
    bool graph_valid = shell_dep_graph_validate(&graph).valid;
    bool timed = fast_status == SHELL_OK && parsed.count != 0 &&
                 process_status == SHELL_PROCESS_OK &&
                 graph_status == SHELL_DEP_OK && graph_valid;
    uint32_t timers = 0;
    uint32_t timing_edges = 0;
    for (uint32_t node = 0; node < graph.node_count; node++)
      timers += graph.nodes[node].type == SHELL_NODE_TIME;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      timing_edges += graph.edges[edge].type == SHELL_EDGE_TIME;
    timed =
        timed && timers == item.timer_count && timing_edges == item.timer_count;
    shell_processed_commands_free(&processed);
    if (!timed) {
      fprintf(stderr,
              "shellsplit fuzz invariant failed: timed pipeline oracle (%s, "
              "fast=%d processed=%d graph=%d valid=%d timers=%u edges=%u)\n",
              input, (int)fast_status, (int)process_status, (int)graph_status,
              graph_valid, timers, timing_edges);
      return fixed_oracle_failure(__LINE__);
    }
  }

  {
    static const char input[] = "time { time a | b; } | c";
    static const char outer_span[] = "{ time a | b; } | c";
    static const char inner_span[] = "a | b";
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(input, sizeof(input) - 1, "/tmp", nullptr,
                              &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    uint32_t commands[3] = {UINT32_MAX, UINT32_MAX, UINT32_MAX};
    uint32_t command_count = 0;
    uint32_t outer_timer = UINT32_MAX;
    uint32_t inner_timer = UINT32_MAX;
    for (uint32_t node = 0; node < graph.node_count; node++) {
      if (graph.nodes[node].type == SHELL_NODE_CMD && command_count < 3)
        commands[command_count++] = node;
      if (graph.nodes[node].type != SHELL_NODE_TIME)
        continue;
      const shell_dep_time_t &timing = graph.nodes[node].time;
      if (timing.length == sizeof(outer_span) - 1 &&
          memcmp(timing.start, outer_span, sizeof(outer_span) - 1) == 0)
        outer_timer = node;
      if (timing.length == sizeof(inner_span) - 1 &&
          memcmp(timing.start, inner_span, sizeof(inner_span) - 1) == 0)
        inner_timer = node;
    }
    if (command_count != 3 || outer_timer == UINT32_MAX ||
        inner_timer == UINT32_MAX || outer_timer == inner_timer ||
        graph.nodes[commands[0]].cmd.pipeline_time_id != inner_timer + 1 ||
        graph.nodes[commands[1]].cmd.pipeline_time_id != inner_timer + 1 ||
        graph.nodes[commands[2]].cmd.pipeline_time_id != outer_timer + 1)
      return fixed_oracle_failure(__LINE__);
  }

  struct nested_modifier_oracle {
    const char *input;
    shell_pipeline_time_mode_t modes[3];
    uint32_t negations[3];
  };
  static const nested_modifier_oracle nested_modifier_cases[] = {
      {"time -p { time a | b; } | c",
       {SHELL_PIPE_TIME_DEFAULT, SHELL_PIPE_TIME_DEFAULT,
        SHELL_PIPE_TIME_POSIX},
       {0, 0, 0}},
      {"! { ! ! a | b; } | c",
       {SHELL_PIPE_TIME_NONE, SHELL_PIPE_TIME_NONE, SHELL_PIPE_TIME_NONE},
       {2, 2, 1}},
  };
  for (const nested_modifier_oracle &item : nested_modifier_cases) {
    shell_command_t *commands = nullptr;
    size_t count = 0;
    bool valid =
        shell_tokenize_commands(item.input, strlen(item.input), &commands,
                                &count) == SHELL_TOKENIZE_OK &&
        count == 3;
    for (size_t command = 0; valid && command < count; command++)
      valid =
          commands[command].pipeline_time_mode == item.modes[command] &&
          commands[command].pipeline_negation_count == item.negations[command];
    shell_commands_free(commands, count);
    if (!valid)
      return fixed_oracle_failure(__LINE__);

    shell_command_info_t *processed = nullptr;
    size_t processed_count = 0;
    valid = shell_process_command(item.input, strlen(item.input), nullptr,
                                  &processed,
                                  &processed_count) == SHELL_PROCESS_OK &&
            processed_count == 3;
    for (size_t command = 0; valid && command < processed_count; command++)
      valid =
          processed[command].pipeline_time_mode == item.modes[command] &&
          processed[command].pipeline_negation_count == item.negations[command];
    shell_command_infos_free(processed, processed_count);
    if (!valid)
      return fixed_oracle_failure(__LINE__);
  }

  struct timed_route_oracle {
    const char *input;
    shell_dep_time_report_route_t route;
    uint32_t flags;
    uint32_t external_fd;
    bool graph_flow;
    const char *target_file = nullptr;
  };
  static const timed_route_oracle timed_route_cases[] = {
      {"(false; exit <<< <(printf '%s' \"$(true)\")) && time true",
       SHELL_TIME_REPORT_UNAVAILABLE, SHELL_TIME_REPORT_ROUTE_UNAVAILABLE,
       SHELL_DEP_FD_NONE, false},
      {"(true; exit <<< <(printf '%s' \"$(false)\")) || time true",
       SHELL_TIME_REPORT_UNAVAILABLE, SHELL_TIME_REPORT_ROUTE_UNAVAILABLE,
       SHELL_DEP_FD_NONE, false},
      {"(true; exit <<<\"$(false)\") || time true", SHELL_TIME_REPORT_EXTERNAL,
       SHELL_TIME_REPORT_ROUTE_EXTERNAL, 2, false},
      {"time (true) 2>local", SHELL_TIME_REPORT_GRAPH,
       SHELL_TIME_REPORT_ROUTE_GRAPH, SHELL_DEP_FD_NONE, true},
      {"time { true; } 2>local", SHELL_TIME_REPORT_EXTERNAL,
       SHELL_TIME_REPORT_ROUTE_EXTERNAL, 2, false},
      {"time { true; } 2>local &", SHELL_TIME_REPORT_GRAPH,
       SHELL_TIME_REPORT_ROUTE_GRAPH, SHELL_DEP_FD_NONE, true},
      {"probe && exec 2>new; time true", SHELL_TIME_REPORT_MULTIPLE,
       SHELL_TIME_REPORT_ROUTE_EXTERNAL | SHELL_TIME_REPORT_ROUTE_GRAPH, 2,
       true},
      {"probe && exec 2>new && time true", SHELL_TIME_REPORT_GRAPH,
       SHELL_TIME_REPORT_ROUTE_GRAPH, SHELL_DEP_FD_NONE, true},
      {"probe && exec 3>new && time exec 2>&3", SHELL_TIME_REPORT_GRAPH,
       SHELL_TIME_REPORT_ROUTE_GRAPH, SHELL_DEP_FD_NONE, true},
      {"probe && exec 2>&-; time true", SHELL_TIME_REPORT_MULTIPLE,
       SHELL_TIME_REPORT_ROUTE_EXTERNAL | SHELL_TIME_REPORT_ROUTE_CLOSED, 2,
       false},
      {"exec 2>old || exit; exec 2<input && time true",
       SHELL_TIME_REPORT_UNAVAILABLE, SHELL_TIME_REPORT_ROUTE_UNAVAILABLE,
       SHELL_DEP_FD_NONE, false},
      {"exec 2>old || exit; probe && exec 2<input; time true",
       SHELL_TIME_REPORT_MULTIPLE,
       SHELL_TIME_REPORT_ROUTE_GRAPH | SHELL_TIME_REPORT_ROUTE_UNAVAILABLE,
       SHELL_DEP_FD_NONE, true, "old"},
      {"true && exec 2>new; time true", SHELL_TIME_REPORT_MULTIPLE,
       SHELL_TIME_REPORT_ROUTE_GRAPH | SHELL_TIME_REPORT_ROUTE_EXTERNAL, 2,
       true, "new"},
      {"false && exec 2>new; time true", SHELL_TIME_REPORT_EXTERNAL,
       SHELL_TIME_REPORT_ROUTE_EXTERNAL, 2, false},
      {"! false && exec 2>new; time true", SHELL_TIME_REPORT_MULTIPLE,
       SHELL_TIME_REPORT_ROUTE_GRAPH | SHELL_TIME_REPORT_ROUTE_EXTERNAL, 2,
       true, "new"},
      {"! true && exec 2>new; time true", SHELL_TIME_REPORT_EXTERNAL,
       SHELL_TIME_REPORT_ROUTE_EXTERNAL, 2, false},
      {"echo \"$(exec 2>&1; time true)\"", SHELL_TIME_REPORT_GRAPH,
       SHELL_TIME_REPORT_ROUTE_GRAPH, SHELL_DEP_FD_NONE, true},
      {"exec 2>old || exit; time { exec 2>new; } 2>local",
       SHELL_TIME_REPORT_GRAPH, SHELL_TIME_REPORT_ROUTE_GRAPH,
       SHELL_DEP_FD_NONE, true, "old"},
      {"time { { exec 2>new; } 2>local; true; }", SHELL_TIME_REPORT_EXTERNAL,
       SHELL_TIME_REPORT_ROUTE_EXTERNAL, 2, false},
      {"time { exec 2>new; } 2>&2", SHELL_TIME_REPORT_MULTIPLE,
       SHELL_TIME_REPORT_ROUTE_GRAPH | SHELL_TIME_REPORT_ROUTE_EXTERNAL, 2,
       true, "new"},
      {"exec 2>old || exit; { exec 3>&2; } 2>local; time exec 2>&3",
       SHELL_TIME_REPORT_MULTIPLE, SHELL_TIME_REPORT_ROUTE_GRAPH,
       SHELL_DEP_FD_NONE, true, "local"},
      {"{ exec 3>keep 2>new; } 2>local && time exec 2>&3",
       SHELL_TIME_REPORT_GRAPH, SHELL_TIME_REPORT_ROUTE_GRAPH,
       SHELL_DEP_FD_NONE, true, "keep"},
      {"exec 2>old || exit; exec 3>new && exec 2<&3 && time true",
       SHELL_TIME_REPORT_GRAPH, SHELL_TIME_REPORT_ROUTE_GRAPH,
       SHELL_DEP_FD_NONE, true, "new"},
      {"exec 2>old || exit; exec 3>new && { time true; } 2<&3",
       SHELL_TIME_REPORT_GRAPH, SHELL_TIME_REPORT_ROUTE_GRAPH,
       SHELL_DEP_FD_NONE, true, "new"},
      {"exec {fd}>old || exit; : {fd}>new && exec 2>&$fd && time true",
       SHELL_TIME_REPORT_GRAPH, SHELL_TIME_REPORT_ROUTE_GRAPH,
       SHELL_DEP_FD_NONE, true, "new"},
      {"exec {fd}>old || exit; : 3>new {fd}>&3 && exec 2>&$fd && time true",
       SHELL_TIME_REPORT_GRAPH, SHELL_TIME_REPORT_ROUTE_GRAPH,
       SHELL_DEP_FD_NONE, true, "new"},
      {"exec {fd}>old || exit; : {fd}<&1; exec 2>&$fd && time true",
       SHELL_TIME_REPORT_EXTERNAL, SHELL_TIME_REPORT_ROUTE_EXTERNAL, 1, false},
      {"time exec 2>new <<<body | cat", SHELL_TIME_REPORT_EXTERNAL,
       SHELL_TIME_REPORT_ROUTE_EXTERNAL, 2, false},
      {"probe && exec 3>new && exec 2<&3 && time true", SHELL_TIME_REPORT_GRAPH,
       SHELL_TIME_REPORT_ROUTE_GRAPH, SHELL_DEP_FD_NONE, true, "new"},
      {"exec 2>old || exit; probe && exec 2>new; echo \"$(time true)\"",
       SHELL_TIME_REPORT_MULTIPLE, SHELL_TIME_REPORT_ROUTE_GRAPH,
       SHELL_DEP_FD_NONE, true, "new"},
      {"exec 2>old || exit; probe && exec 2>&-; echo \"$(time true)\"",
       SHELL_TIME_REPORT_MULTIPLE,
       SHELL_TIME_REPORT_ROUTE_GRAPH | SHELL_TIME_REPORT_ROUTE_CLOSED,
       SHELL_DEP_FD_NONE, true, "old"},
      {"{ time true; } |& cat 3<&0", SHELL_TIME_REPORT_MULTIPLE,
       SHELL_TIME_REPORT_ROUTE_GRAPH, SHELL_DEP_FD_NONE, true},
      {"printf x | { exec 2>err && time true; }", SHELL_TIME_REPORT_GRAPH,
       SHELL_TIME_REPORT_ROUTE_GRAPH, SHELL_DEP_FD_NONE, true, "err"},
      {"printf x |& { exec 2>err && time true; }", SHELL_TIME_REPORT_GRAPH,
       SHELL_TIME_REPORT_ROUTE_GRAPH, SHELL_DEP_FD_NONE, true, "err"},
      {"printf x | { { exec 2>err; } && time true; }", SHELL_TIME_REPORT_GRAPH,
       SHELL_TIME_REPORT_ROUTE_GRAPH, SHELL_DEP_FD_NONE, true, "err"},
      {"printf x | { exec {fd}>err; exec 2>&$fd && time true; }",
       SHELL_TIME_REPORT_GRAPH, SHELL_TIME_REPORT_ROUTE_GRAPH,
       SHELL_DEP_FD_NONE, true, "err"},
      {"printf x | { exec 2>err && echo \"$(time true)\"; }",
       SHELL_TIME_REPORT_GRAPH, SHELL_TIME_REPORT_ROUTE_GRAPH,
       SHELL_DEP_FD_NONE, true, "err"},
      {"(exec 2>base || exit; exec 2>changed | :; time true)",
       SHELL_TIME_REPORT_GRAPH, SHELL_TIME_REPORT_ROUTE_GRAPH,
       SHELL_DEP_FD_NONE, true, "base"},
      {"(exec 2>base || exit; exec 2>changed & wait; time true)",
       SHELL_TIME_REPORT_GRAPH, SHELL_TIME_REPORT_ROUTE_GRAPH,
       SHELL_DEP_FD_NONE, true, "base"},
      {"(exec {fd}>base || exit; unset fd | :; exec 2>&$fd && time true)",
       SHELL_TIME_REPORT_GRAPH, SHELL_TIME_REPORT_ROUTE_GRAPH,
       SHELL_DEP_FD_NONE, true, "base"},
  };
  for (const timed_route_oracle &item : timed_route_cases) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(item.input, strlen(item.input), "/tmp", NULL,
                              &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    const shell_dep_time_t *timing = nullptr;
    uint32_t timer = UINT32_MAX;
    for (uint32_t node = 0; node < graph.node_count; node++)
      if (graph.nodes[node].type == SHELL_NODE_TIME) {
        if (timing)
          return fixed_oracle_failure(__LINE__);
        timing = &graph.nodes[node].time;
        timer = node;
      }
    if (!timing || timing->report_route != item.route ||
        timing->report_route_flags != item.flags) {
      fprintf(stderr, "timing outcome oracle: %s route=%u flags=%u\n",
              item.input, timing ? timing->report_route : UINT32_MAX,
              timing ? timing->report_route_flags : UINT32_MAX);
      return fixed_oracle_failure(__LINE__);
    }
    bool external_found = item.external_fd == SHELL_DEP_FD_NONE;
    for (uint32_t fd = 0; fd < timing->report_external_fd_count; fd++)
      external_found =
          external_found || timing->report_external_fds[fd] == item.external_fd;
    bool graph_flow = false;
    bool target_found = item.target_file == nullptr;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      const shell_dep_edge_t &candidate = graph.edges[edge];
      graph_flow = graph_flow || (candidate.from == timer &&
                                  candidate.type != SHELL_EDGE_TIME &&
                                  internal_graph_relation(graph, candidate) &&
                                  candidate.source_fd == timing->report_fd);
      if (item.target_file && candidate.from == timer &&
          candidate.type == SHELL_EDGE_WRITE &&
          candidate.to < graph.node_count) {
        const shell_dep_node_t &target = graph.nodes[candidate.to];
        target_found =
            target_found || (target.type == SHELL_NODE_DOC &&
                             target.doc.kind == SHELL_DOC_FILE &&
                             target.doc.path_len == strlen(item.target_file) &&
                             memcmp(target.doc.path, item.target_file,
                                    target.doc.path_len) == 0);
      }
    }
    if (!external_found || graph_flow != item.graph_flow || !target_found)
      return fixed_oracle_failure(__LINE__);
  }

  for (const char *input : shellsplit_test_enumeration_time_routes) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(input, strlen(input), "/tmp", nullptr, &graph) !=
            SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    uint32_t timers = 0;
    for (uint32_t node = 0; node < graph.node_count; node++) {
      if (graph.nodes[node].type != SHELL_NODE_TIME)
        continue;
      const shell_dep_time_t &time = graph.nodes[node].time;
      if (time.report_route != SHELL_TIME_REPORT_EXTERNAL ||
          time.report_target_fd != 1 ||
          time.report_route_flags != SHELL_TIME_REPORT_ROUTE_EXTERNAL ||
          time.report_external_fd_count != 1 ||
          time.report_external_fds[0] != 1)
        return fixed_oracle_failure(__LINE__);
      timers++;
    }
    if (!timers)
      return fixed_oracle_failure(__LINE__);
  }

  /* Effective timing metadata is inherited, but only the pipeline root owns
   * reserved syntax. Later executables named `time` must retain both argv and
   * byte routes, even when their spelling also forms an empty time prefix. */
  static const struct {
    const char *input;
    uint32_t commands;
    uint32_t pipes;
    uint32_t first;
    shell_pipeline_time_mode_t mode;
  } ordinary_timed_stages[] = {
      {"time true | time", 2, 1, 0, SHELL_PIPE_TIME_DEFAULT},
      {"time true | time -p", 2, 1, 0, SHELL_PIPE_TIME_DEFAULT},
      {"time true | time --", 2, 1, 0, SHELL_PIPE_TIME_DEFAULT},
      {"time true | time !", 2, 1, 0, SHELL_PIPE_TIME_DEFAULT},
      {"time -p true | time", 2, 1, 0, SHELL_PIPE_TIME_POSIX},
      {"time true |& time", 2, 2, 0, SHELL_PIPE_TIME_DEFAULT},
      {"time true | time | cat", 3, 2, 0, SHELL_PIPE_TIME_DEFAULT},
      {"time true | \"time\"", 2, 1, 0, SHELL_PIPE_TIME_DEFAULT},
      {"echo \"$(time true | time)\"", 3, 1, 1, SHELL_PIPE_TIME_DEFAULT},
  };
  for (const auto &item : ordinary_timed_stages) {
    shell_dep_graph_t graph = {};
    if (test_tokenizer_state(item.input, strlen(item.input)) ||
        shell_dep_graph_parse(item.input, strlen(item.input), "/tmp", nullptr,
                              &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    std::vector<uint32_t> commands;
    uint32_t timer = UINT32_MAX, timers = 0, pipes = 0;
    for (uint32_t node = 0; node < graph.node_count; node++) {
      if (graph.nodes[node].type == SHELL_NODE_CMD) {
        if (graph.nodes[node].cmd.token_count == 0)
          return fixed_oracle_failure(__LINE__);
        commands.push_back(node);
      } else if (graph.nodes[node].type == SHELL_NODE_TIME) {
        timer = node;
        timers++;
      }
    }
    if (commands.size() != item.commands || timers != 1)
      return fixed_oracle_failure(__LINE__);
    uint32_t first = commands[item.first];
    uint32_t ordinary_time = commands[item.first + 1];
    bool timed_root = false, input_pipe = false, output_pipe = false;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      const shell_dep_edge_t &route = graph.edges[edge];
      pipes += route.type == SHELL_EDGE_PIPE;
      timed_root = timed_root || (route.type == SHELL_EDGE_TIME &&
                                  route.from == timer && route.to == first);
      input_pipe =
          input_pipe || (route.type == SHELL_EDGE_PIPE && route.from == first &&
                         route.to == ordinary_time && route.source_fd == 1 &&
                         route.target_fd == 0);
      output_pipe = output_pipe ||
                    (item.first == 0 && item.commands == 3 &&
                     route.type == SHELL_EDGE_PIPE &&
                     route.from == ordinary_time && route.to == commands[2]);
    }
    if (!timed_root || !input_pipe || pipes != item.pipes ||
        (item.first == 0 && item.commands == 3 && !output_pipe))
      return fixed_oracle_failure(__LINE__);
    for (size_t stage = item.first; stage < commands.size(); stage++)
      if (graph.nodes[commands[stage]].cmd.pipeline_time_id != timer + 1 ||
          graph.nodes[commands[stage]].cmd.pipeline_time_mode != item.mode)
        return fixed_oracle_failure(__LINE__);
  }

  static const struct {
    const char *input;
    uint32_t commands;
    uint32_t timed;
    const char *last_argv = nullptr;
  } document_stages[] = {
      {"time <<<body cat", 1, 1},
      {"time <input <<<body cat", 1, 1},
      {"time <<<body <input cat", 1, 1},
      {"time 3<<<body cat <&3", 1, 1},
      {"time <<EOF cat\nbody\nEOF\n", 1, 1},
      {"true | time <<<body", 2, 0},
      {"time true | time -p <<<body", 2, 2},
      {"<<<body time true", 1, 0},
      {"<<<body ! true", 1, 0},
      {"true | <<<body time -p", 2, 0},
      {"time true | <<<body time -p", 2, 2},
      {"<<EOF time\nbody\nEOF\n", 1, 0},
      {"true |& 3<<<body cat", 2, 0},
      {"true | cat <<EOF | cat\nbody\nEOF\n", 3, 0},
      {"<<<one time <<<two cat", 1, 0, "4:time,3:cat,"},
      {"<<<one ! <<<two cat", 1, 0, "1:!,3:cat,"},
      {"<<<one time -p 3<<<two cat <&3", 1, 0, "4:time,2:-p,3:cat,"},
      {"<<EOF time <<<two cat\none\nEOF\n", 1, 0, "4:time,3:cat,"},
      {"<<<one time \\\n<<<two cat", 1, 0, "4:time,3:cat,"},
      {"time true | <<<one time <<<two cat", 2, 2, "4:time,3:cat,"},
      {"printf one <<<one\ntime <<<two cat", 2, 1, "3:cat,"},
      {"printf one <<<one\n! <<<two cat", 2, 0, "3:cat,"},
      {"printf one <<<one\r\ntime -p <<<two cat", 2, 1, "3:cat,"},
  };
  for (const auto &item : document_stages) {
    shell_dep_graph_t graph = {};
    if (test_tokenizer_state(item.input, strlen(item.input)) ||
        test_processor(item.input, strlen(item.input)) ||
        shell_dep_graph_parse(item.input, strlen(item.input), "/tmp", nullptr,
                              &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    uint32_t commands = 0, timed = 0, last_command = UINT32_MAX;
    for (uint32_t node = 0; node < graph.node_count; node++) {
      if (graph.nodes[node].type != SHELL_NODE_CMD)
        continue;
      if (graph.nodes[node].cmd.token_count == 0)
        return fixed_oracle_failure(__LINE__);
      commands++;
      last_command = node;
      timed += graph.nodes[node].cmd.pipeline_time_mode != SHELL_PIPE_TIME_NONE;
    }
    if (commands != item.commands || timed != item.timed)
      return fixed_oracle_failure(__LINE__);
    if (item.last_argv) {
      shell_netstring_iter_t words;
      shell_netstring_view_t word;
      shell_netstring_iter_init(&words, item.last_argv, strlen(item.last_argv));
      const shell_dep_cmd_t &cmd = graph.nodes[last_command].cmd;
      uint32_t token = 0;
      while (shell_netstring_iter_next(&words, &word) == SHELL_NETSTRING_OK) {
        if (token >= cmd.token_count ||
            cmd.token_lens[token] != word.payload_length ||
            memcmp(cmd.tokens[token], word.payload, word.payload_length) != 0)
          return fixed_oracle_failure(__LINE__);
        token++;
      }
      if (token != cmd.token_count)
        return fixed_oracle_failure(__LINE__);
    }
  }

  /* Consume real parser output unchanged. Fabricating omitted commands or
   * groups violates the internal API contract and is not a runtime oracle. */
  for (const char *source :
       {"time { true; }", "time true; false", "{ true; }", "true; false"}) {
    shell_parse_result_t fast = {};
    shell_dep_graph_t graph = {};
    shell_dep_limits_t limits;
    const shell_limits_t strict = {SHELL_MAX_SUBCOMMANDS, true, nullptr, 0};
    if (shell_parse_fast(source, strlen(source), &strict, &fast) != SHELL_OK ||
        !fuzz_dep_limits(nullptr, &limits))
      return fixed_oracle_failure(__LINE__);
    shell_parse_result_t unchanged;
    /* This byte-for-byte snapshot checks immutability of one object, not
     * semantic equality of independently constructed results or C copies. */
    memcpy(&unchanged, &fast, sizeof(unchanged));
    if (shell_dep_graph_parse_with_fast(source, strlen(source), ".", &limits,
                                        &fast, &graph) != SHELL_DEP_OK ||
        !shellsplit_test_depgraph_invariants(source, strlen(source),
                                             SHELL_DEP_OK, &graph, &limits) ||
        memcmp(&fast, &unchanged, sizeof(fast)) != 0)
      return fixed_oracle_failure(__LINE__);
  }

  /* Empty timing targets have no body I/O. An asynchronous shell can still
   * emit its implicit-stdin-open diagnostic through inherited stderr. */
  static const char *const empty_timing_stream_cases[] = {
      "echo \"$(time; true)\"",
      "echo \"`time; true`\"",
      "echo \"$(exec 2>&1; time; true)\"",
      "cat <(time; printf x)",
      "printf x > >(time; cat)",
      "echo \"$(time &)\"",
  };
  for (const char *input : empty_timing_stream_cases) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(input, strlen(input), "/tmp", nullptr, &graph) !=
            SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    uint32_t placeholder = UINT32_MAX;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      if (graph.edges[edge].type == SHELL_EDGE_TIME &&
          graph.nodes[graph.edges[edge].from].time.length == 0)
        placeholder = graph.edges[edge].to;
    if (placeholder == UINT32_MAX ||
        graph.nodes[placeholder].cmd.token_count != 0)
      return fixed_oracle_failure(__LINE__);
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      const shell_dep_edge_t &item = graph.edges[edge];
      if (item.from != placeholder && item.to != placeholder)
        continue;
      if (item.type == SHELL_EDGE_WRITE && item.from == placeholder &&
          item.source_fd == 2 && graph.nodes[item.to].type == SHELL_NODE_FD &&
          graph.nodes[item.to].fd.number == 2)
        continue;
      if (item.type != SHELL_EDGE_TIME && item.type != SHELL_EDGE_SEQ &&
          item.type != SHELL_EDGE_AND && item.type != SHELL_EDGE_OR &&
          item.type != SHELL_EDGE_BACKGROUND && item.type != SHELL_EDGE_GROUP)
        return fixed_oracle_failure(__LINE__);
    }
  }
  for (const char *input :
       {"echo \"$(time)\"", "echo \"$(time;)\"", "echo \"$(exec 2>&1; time;)\"",
        "cat <(time;)", "printf x > >(time;)", "echo \"$( (time;) )\"",
        "echo \"$(time (time;))\"", "echo \"$( (time;); : )\"",
        "cat <( (time;) )", "printf x > >( (time;) )"}) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(input, strlen(input), "/tmp", nullptr, &graph) !=
            SHELL_DEP_EPARSE ||
        graph.node_count != 0 || graph.edge_count != 0)
      return fixed_oracle_failure(__LINE__);
  }

  for (const char *input :
       {"cat <input < <(printf ignored >/dev/null)",
        "cat < <(printf old) < <(printf ignored >/dev/null)"}) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(input, strlen(input), "/tmp", nullptr, &graph) !=
            SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    bool replacement = false;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      const shell_dep_edge_t &item = graph.edges[edge];
      if (item.to != 0 ||
          (item.type != SHELL_EDGE_SUBST && item.type != SHELL_EDGE_READ))
        continue;
      if (item.type != SHELL_EDGE_SUBST ||
          graph.nodes[item.from].type != SHELL_NODE_ENDPOINT ||
          graph.nodes[item.from].endpoint.reserved != 2 || item.target_fd != 0)
        return fixed_oracle_failure(__LINE__);
      replacement = true;
    }
    if (!replacement)
      return fixed_oracle_failure(__LINE__);
  }

  {
    static const char input[] = "exec 2>base; probe && exec 2>new; time true";
    shell_dep_graph_t full = {};
    if (shell_dep_graph_parse(input, sizeof(input) - 1, "/tmp", nullptr,
                              &full) != SHELL_DEP_OK)
      return fixed_oracle_failure(__LINE__);
    for (uint32_t max_edges = 0; max_edges <= full.edge_count; max_edges++) {
      shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
      limits.max_edges = max_edges;
      shell_dep_graph_t bounded = {};
      shell_dep_error_t status = shell_dep_graph_parse(
          input, sizeof(input) - 1, "/tmp", &limits, &bounded);
      if ((status != SHELL_DEP_OK && status != SHELL_DEP_ETRUNC) ||
          !shell_dep_graph_validate(&bounded).valid)
        return fixed_oracle_failure(__LINE__);
    }
  }

  struct timed_boundary_oracle {
    const char *input;
    uint32_t expected_start;
    shell_pipeline_time_mode_t mode;
    uint32_t negation_count;
  };
  static const timed_boundary_oracle timed_boundary_cases[] = {
      {"time printf x", 5, SHELL_PIPE_TIME_DEFAULT, 0},
      {"time -p -- ! printf x", 13, SHELL_PIPE_TIME_POSIX, 1},
      {"! time ! printf x", 9, SHELL_PIPE_TIME_DEFAULT, 2},
      {"time>/tmp/timing printf x", 4, SHELL_PIPE_TIME_DEFAULT, 0},
      {"ti\\\nme printf x", 7, SHELL_PIPE_TIME_DEFAULT, 0},
      {"time !", 0, SHELL_PIPE_TIME_DEFAULT, 1},
      {"!>/tmp/out true", 1, SHELL_PIPE_TIME_NONE, 1},
      {"!2>/tmp/out true", 0, SHELL_PIPE_TIME_NONE, 0},
      {"time$(printf x)", 0, SHELL_PIPE_TIME_NONE, 0},
      {"echo time", 0, SHELL_PIPE_TIME_NONE, 0},
  };
  for (const timed_boundary_oracle &item : timed_boundary_cases) {
    shell_parse_result_t fast = {};
    shell_command_t *full = nullptr;
    size_t full_count = 0;
    bool valid = shell_parse_fast(item.input, strlen(item.input), nullptr,
                                  &fast) == SHELL_OK &&
                 fast.count == 1 && fast.group_count == 0 &&
                 shell_tokenize_commands(item.input, strlen(item.input), &full,
                                         &full_count) == SHELL_TOKENIZE_OK &&
                 full_count == 1 && full[0].token_count != 0;
    size_t full_stage_start = full_count == 1 ? full[0].start_pos : 0;
    if (valid) {
      bool all_modifiers = true;
      for (size_t token = 0; token < full[0].token_count; token++) {
        shell_token_type_t type = full[0].tokens[token].type;
        bool modifier = type == SHELL_TOKEN_PIPE_NEGATE ||
                        type == SHELL_TOKEN_PIPE_TIME ||
                        type == SHELL_TOKEN_PIPE_TIME_OPTION;
        if (!modifier) {
          full_stage_start = full[0].tokens[token].position;
          all_modifiers = false;
          break;
        }
      }
      if (all_modifiers)
        full_stage_start = full[0].tokens[0].position;
    }
    valid = valid && full_stage_start == item.expected_start &&
            fast.cmds[0].start == item.expected_start &&
            fast.cmds[0].pipeline_time_mode == item.mode &&
            fast.cmds[0].pipeline_negation_count == item.negation_count &&
            full[0].pipeline_time_mode == item.mode &&
            full[0].pipeline_negation_count == item.negation_count;
    shell_commands_free(full, full_count);
    if (!valid) {
      fprintf(stderr,
              "shellsplit fuzz invariant failed: timed boundary oracle (%s, "
              "fast-start=%u full-start=%zu expected=%u)\n",
              item.input, fast.count ? fast.cmds[0].start : UINT32_MAX,
              full_stage_start, item.expected_start);
      return fixed_oracle_failure(__LINE__);
    }
  }

  static const char *const invalid_timed_close_cases[] = {
      "(time)",      "(time !)",      "echo \"$(time)\"",
      "cat <(time)", "cat >(time !)", "cat <<EOF\n$(time)\nEOF\n",
  };
  for (const char *input : invalid_timed_close_cases) {
    shell_parse_result_t fast = {};
    shell_command_t *full = nullptr;
    size_t full_count = 0;
    shell_processed_commands_t processed = {};
    shell_dep_graph_t graph = {};
    shell_error_t fast_status =
        shell_parse_fast(input, strlen(input), nullptr, &fast);
    shell_tokenize_status_t full_status =
        shell_tokenize_commands(input, strlen(input), &full, &full_count);
    shell_process_status_t process_status =
        shell_process_commands(input, strlen(input), nullptr, &processed);
    shell_dep_error_t graph_status =
        shell_dep_graph_parse(input, strlen(input), "/tmp", nullptr, &graph);
    bool rejected = fast_status == SHELL_EPARSE && fast.count == 0 &&
                    full_status == SHELL_TOKENIZE_EPARSE && full == nullptr &&
                    full_count == 0 && process_status == SHELL_PROCESS_EPARSE &&
                    processed.commands == nullptr &&
                    processed.command_count == 0 &&
                    graph_status == SHELL_DEP_EPARSE && graph.node_count == 0 &&
                    graph.edge_count == 0;
    shell_commands_free(full, full_count);
    shell_processed_commands_free(&processed);
    if (!rejected) {
      fprintf(stderr,
              "shellsplit fuzz invariant failed: timed close oracle (%s)\n",
              input);
      return fixed_oracle_failure(__LINE__);
    }
  }

  /* Line continuations after a list connector are structural syntax, not a
   * semicolon separator. Keep a compact semantic oracle here so random input
   * mutation cannot regress the agreement between fast ranges, processing,
   * and dependency routing. */
  struct continued_list_oracle {
    const char *input;
    uint16_t type;
    shell_pipe_mode_t pipe_mode;
    shell_dep_edge_type_t relation;
    uint32_t relation_count;
  };
  static const continued_list_oracle continued_lists[] = {
      {"printf x | # note\ncat", SHELL_TYPE_PIPELINE, SHELL_PIPE_MODE_STDOUT,
       SHELL_EDGE_PIPE, 1},
      {"printf x |& \\\ncat", SHELL_TYPE_PIPELINE,
       SHELL_PIPE_MODE_STDOUT_AND_STDERR, SHELL_EDGE_PIPE, 2},
      {"printf x &&\ncat", SHELL_TYPE_AND, SHELL_PIPE_MODE_NONE, SHELL_EDGE_AND,
       1},
      {"printf x || # note\ncat", SHELL_TYPE_OR, SHELL_PIPE_MODE_NONE,
       SHELL_EDGE_OR, 1},
  };
  for (const continued_list_oracle &item : continued_lists) {
    shell_parse_result_t continued_fast = {};
    shell_processed_commands_t continued_processed = {};
    shell_dep_graph_t continued_graph = {};
    bool continued_ok =
        shell_parse_fast(item.input, strlen(item.input), NULL,
                         &continued_fast) == SHELL_OK &&
        continued_fast.count == 2 && continued_fast.cmds[1].type == item.type &&
        continued_fast.cmds[1].pipe_input_mode == item.pipe_mode &&
        shell_process_commands(item.input, strlen(item.input), NULL,
                               &continued_processed) == SHELL_PROCESS_OK &&
        continued_processed.command_count == 2 &&
        shell_dep_graph_parse(item.input, strlen(item.input), ".", NULL,
                              &continued_graph) == SHELL_DEP_OK;
    if (item.type == SHELL_TYPE_PIPELINE)
      continued_ok =
          continued_ok && continued_processed.commands[0].has_pipe_output &&
          continued_processed.commands[0].pipe_output_mode == item.pipe_mode &&
          continued_processed.commands[1].has_pipe_input;
    uint32_t relations = 0;
    for (uint32_t edge = 0; edge < continued_graph.edge_count; edge++)
      relations += continued_graph.edges[edge].type == item.relation;
    continued_ok = continued_ok && relations == item.relation_count &&
                   shell_dep_graph_validate(&continued_graph).valid;
    shell_processed_commands_free(&continued_processed);
    if (!continued_ok)
      return fixed_oracle_failure(__LINE__);
  }

  /* Shell removal also applies within an expansion opener. Keep the physical
   * spellings in the fixed oracle set: a mutated corpus rarely rediscovers a
   * valid continuation at exactly these grammar boundaries. */
  struct continued_expansion_oracle {
    const char *input;
    uint32_t command_nodes;
    uint32_t substitution_edges;
  };
  static const continued_expansion_oracle continued_expansions[] = {
      {"printf %s ${f\\\nd}", 1, 0},
      {"printf %s $\\\n(printf child)", 2, 1},
      {"printf %s $\\\n((1 + 2))", 1, 0},
      {"printf %s $((1)\\\n)", 1, 0},
      {"printf %s $\\\n'ansi'", 1, 0},
      {"cat <\\\n(printf input) > \\\n>(cat)", 3, 2},
  };
  for (const continued_expansion_oracle &item : continued_expansions) {
    shell_parse_result_t fast = {};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {};
    shell_dep_graph_t graph = {};
    bool expansion_ok =
        shell_parse_fast(item.input, strlen(item.input), NULL, &fast) ==
            SHELL_OK &&
        fast.count == 1 &&
        shell_tokenize_commands(item.input, strlen(item.input), &commands,
                                &command_count) == SHELL_TOKENIZE_OK &&
        command_count == 1 &&
        shell_process_commands(item.input, strlen(item.input), NULL,
                               &processed) == SHELL_PROCESS_OK &&
        processed.command_count == 1 &&
        shell_dep_graph_parse(item.input, strlen(item.input), ".", NULL,
                              &graph) == SHELL_DEP_OK &&
        shellsplit_test_depgraph_invariants(item.input, strlen(item.input),
                                            SHELL_DEP_OK, &graph,
                                            &SHELL_DEP_LIMITS_DEFAULT);
    uint32_t command_nodes = 0;
    uint32_t substitution_edges = 0;
    for (uint32_t node = 0; node < graph.node_count; node++)
      command_nodes += graph.nodes[node].type == SHELL_NODE_CMD;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      substitution_edges += graph.edges[edge].type == SHELL_EDGE_SUBST;
    shell_processed_commands_free(&processed);
    shell_commands_free(commands, command_count);
    if (!expansion_ok || command_nodes != item.command_nodes ||
        substitution_edges != item.substitution_edges) {
      fprintf(stderr,
              "continued expansion oracle failed: %s (%u/%u commands, "
              "%u/%u substitutions)\n",
              item.input, command_nodes, item.command_nodes, substitution_edges,
              item.substitution_edges);
      return fixed_oracle_failure(__LINE__);
    }
  }

  /* Standalone word decoding preserves bytes, including a NUL produced by an
   * ANSI-C quote after an escaped LF. Complete-command semantics
   * reject that source: Bash truncates the quoted segment at the NUL. Keep
   * these distinct contracts outside the bounded smoke corpus. */
  static const char *const continued_ansi_words[] = {
      "$\\\n'\\x41\\0B'",
  };
  static const unsigned char continued_ansi_expected[] = {'A', '\0', 'B'};
  for (size_t index = 0;
       index < sizeof(continued_ansi_words) / sizeof(continued_ansi_words[0]);
       index++) {
    const char *word = continued_ansi_words[index];
    char command[64] = {};
    int command_length =
        snprintf(command, sizeof(command), "printf %%s %s", word);
    char decoded[sizeof(continued_ansi_expected)] = {};
    size_t measured = 0, written = 0;
    shell_command_info_t *infos = nullptr;
    size_t info_count = 0;
    shell_netstring_buffer_t command_netseq = {}, type_netseq = {};
    size_t sequence_count = 0;
    bool ansi_boundary_ok =
        shell_measure_decoded_word(word, strlen(word), &measured) ==
            SHELL_PROCESS_OK &&
        measured == sizeof(continued_ansi_expected) &&
        shell_write_decoded_word(word, strlen(word), decoded, sizeof(decoded),
                                 &written) == SHELL_PROCESS_OK &&
        written == sizeof(continued_ansi_expected) &&
        memcmp(decoded, continued_ansi_expected,
               sizeof(continued_ansi_expected)) == 0 &&
        command_length > 0 && (size_t)command_length < sizeof(command) &&
        shell_process_command(command, (size_t)command_length, nullptr, &infos,
                              &info_count) == SHELL_PROCESS_EPARSE &&
        infos == nullptr && info_count == 0 &&
        shell_build_anomaly_netseqs_buffer(
            command, (size_t)command_length, nullptr, &command_netseq,
            &type_netseq, &sequence_count) == SHELL_PROCESS_EPARSE &&
        command_netseq.data == nullptr && type_netseq.data == nullptr &&
        sequence_count == 0;
    shell_netstring_buffer_free(&command_netseq);
    shell_netstring_buffer_free(&type_netseq);
    shell_command_infos_free(infos, info_count);
    if (!ansi_boundary_ok) {
      fprintf(stderr, "fixed ANSI-C NUL oracle failed: continuation %zu\n",
              index);
      return fixed_oracle_failure(__LINE__);
    }
  }

  /* Directly supplied processed arguments are canonical binary data, not
   * shell source; rendering them must remain byte-faithful. */
  shell_token_t binary_tokens[2] = {};
  binary_tokens[0].type = SHELL_TOKEN_COMMAND;
  binary_tokens[0].start = "printf";
  binary_tokens[0].length = 6;
  binary_tokens[1].type = SHELL_TOKEN_ARGUMENT;
  binary_tokens[1].start =
      reinterpret_cast<const char *>(continued_ansi_expected);
  binary_tokens[1].length = sizeof(continued_ansi_expected);
  shell_command_info_t binary_info = {};
  binary_info.command_tokens = binary_tokens;
  binary_info.command_token_count = 2;
  shell_netstring_buffer_t binary_netargv = {};
  shell_netstring_iter_t binary_iterator = {};
  shell_netstring_view_t binary_first = {}, binary_second = {};
  bool binary_netargv_ok =
      shell_render_netargv_buffer(&binary_info, nullptr, &binary_netargv) ==
          SHELL_PROCESS_OK &&
      shell_netstring_iter_init(&binary_iterator, binary_netargv.data,
                                binary_netargv.length) == SHELL_NETSTRING_OK &&
      shell_netstring_iter_next(&binary_iterator, &binary_first) ==
          SHELL_NETSTRING_OK &&
      binary_first.payload_length == 6 &&
      memcmp(binary_first.payload, "printf", 6) == 0 &&
      shell_netstring_iter_next(&binary_iterator, &binary_second) ==
          SHELL_NETSTRING_OK &&
      binary_second.payload_length == sizeof(continued_ansi_expected) &&
      memcmp(binary_second.payload, continued_ansi_expected,
             sizeof(continued_ansi_expected)) == 0 &&
      shell_netstring_iter_next(&binary_iterator, &binary_second) ==
          SHELL_NETSTRING_DONE;
  shell_netstring_buffer_free(&binary_netargv);
  if (!binary_netargv_ok) {
    fprintf(stderr, "fixed ANSI-C NUL oracle failed: direct binary netargv\n");
    return fixed_oracle_failure(__LINE__);
  }

  /* Reserved words are recognized from their logical, unquoted spelling. A
   * continued keyword must reach the same unsupported-semantics boundary as
   * its ordinary spelling, rather than becoming an executable command. */
  static const char *const continued_control_cases[] = {
      "whi\\\nle true; do :; done",
      "i\\\nf true; then :; fi",
      "ca\\\nse value in value) :;; esac",
  };
  for (const char *input : continued_control_cases) {
    shell_processed_commands_t processed = {};
    shell_netstring_buffer_t netargv = {};
    size_t netargv_count = 0;
    bool has_shell_features = false;
    bool control_rejected =
        shell_process_commands(input, strlen(input), nullptr, &processed) ==
            SHELL_PROCESS_EPARSE &&
        processed.commands == nullptr && processed.command_count == 0 &&
        shell_build_netargv_sequence_buffer(
            input, strlen(input), nullptr, &netargv, &netargv_count,
            &has_shell_features) == SHELL_PROCESS_EPARSE &&
        netargv.data == nullptr && netargv_count == 0 && !has_shell_features;
    shell_processed_commands_free(&processed);
    shell_netstring_buffer_free(&netargv);
    if (!control_rejected)
      return fixed_oracle_failure(__LINE__);
  }

  static const char continued_group[] = "{ printf x; } \\\n|& { cat; }";
  shell_processed_commands_t continued_group_processed = {};
  shell_dep_graph_t continued_group_graph = {};
  bool continued_group_ok =
      shell_process_commands(continued_group, sizeof(continued_group) - 1, NULL,
                             &continued_group_processed) == SHELL_PROCESS_OK &&
      continued_group_processed.command_count == 2 &&
      continued_group_processed.group_count == 2 &&
      continued_group_processed.group_io_op_count == 2 &&
      continued_group_processed.group_io_ops[0].kind ==
          SHELL_GROUP_IO_PIPE_OUTPUT_STDERR &&
      continued_group_processed.group_io_ops[1].kind ==
          SHELL_GROUP_IO_PIPE_INPUT &&
      continued_group_processed.group_io_ops[0].source_start ==
          continued_group_processed.group_io_ops[1].source_start &&
      continued_group_processed.group_io_ops[0].source_end ==
          continued_group_processed.group_io_ops[1].source_end &&
      shell_dep_graph_parse(continued_group, sizeof(continued_group) - 1, ".",
                            NULL, &continued_group_graph) == SHELL_DEP_OK;
  uint32_t continued_group_pipe_count = 0;
  for (uint32_t i = 0; i < continued_group_graph.edge_count; i++)
    continued_group_pipe_count +=
        continued_group_graph.edges[i].type == SHELL_EDGE_PIPE;
  continued_group_ok = continued_group_ok && continued_group_pipe_count == 2 &&
                       shell_dep_graph_validate(&continued_group_graph).valid;
  shell_processed_commands_free(&continued_group_processed);
  if (!continued_group_ok)
    return fixed_oracle_failure(__LINE__);

  shell_processed_commands_t negated_pipeline = {};
  bool negation_ok =
      shell_process_commands("! false |& cat | sort",
                             strlen("! false |& cat | sort"), NULL,
                             &negated_pipeline) == SHELL_PROCESS_OK &&
      negated_pipeline.command_count == 3 &&
      negated_pipeline.commands[0].pipeline_negated &&
      negated_pipeline.commands[1].pipeline_negated &&
      negated_pipeline.commands[2].pipeline_negated &&
      negated_pipeline.commands[0].pipe_output_mode ==
          SHELL_PIPE_MODE_STDOUT_AND_STDERR &&
      negated_pipeline.commands[1].pipe_output_mode == SHELL_PIPE_MODE_STDOUT &&
      !negated_pipeline.commands[2].has_pipe_output &&
      negated_pipeline.commands[2].pipe_output_mode == SHELL_PIPE_MODE_NONE;
  shell_processed_commands_free(&negated_pipeline);
  if (!negation_ok)
    return fixed_oracle_failure(__LINE__);

  /* Every leading `!` is a modifier, so the count and parity must survive the
   * fast/full processor boundary without leaking a synthetic `!` argv word. */
  shell_processed_commands_t repeated_negation = {};
  bool repeated_negation_ok =
      shell_process_commands("! ! false |& cat | sort",
                             strlen("! ! false |& cat | sort"), NULL,
                             &repeated_negation) == SHELL_PROCESS_OK &&
      repeated_negation.command_count == 3;
  for (size_t i = 0;
       repeated_negation_ok && i < repeated_negation.command_count; i++)
    repeated_negation_ok =
        repeated_negation.commands[i].pipeline_negation_count == 2 &&
        !repeated_negation.commands[i].pipeline_negated;
  repeated_negation_ok =
      repeated_negation_ok &&
      repeated_negation.commands[0].command_token_count == 1 &&
      repeated_negation.commands[0].command_tokens[0].length == 5 &&
      memcmp(repeated_negation.commands[0].command_tokens[0].start, "false",
             5) == 0;
  shell_processed_commands_free(&repeated_negation);
  if (!repeated_negation_ok)
    return fixed_oracle_failure(__LINE__);

  static const struct {
    const char *input;
    size_t command_count;
  } valid_list_cases[] = {
      {"! ! true", 1},
      {"! ! ! true", 1},
      {"a && ! b", 2},
      {"a & ! b", 2},
  };
  for (const auto &item : valid_list_cases) {
    shell_parse_result_t parsed = {};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {};
    shell_dep_graph_t graph = {};
    bool valid =
        shell_parse_fast(item.input, strlen(item.input), NULL, &parsed) ==
            SHELL_OK &&
        parsed.count == item.command_count &&
        shell_tokenize_commands(item.input, strlen(item.input), &commands,
                                &command_count) == SHELL_TOKENIZE_OK &&
        command_count == item.command_count &&
        shell_process_commands(item.input, strlen(item.input), NULL,
                               &processed) == SHELL_PROCESS_OK &&
        processed.command_count == item.command_count &&
        shell_dep_graph_parse(item.input, strlen(item.input), NULL, NULL,
                              &graph) == SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    if (!valid)
      return fixed_oracle_failure(__LINE__);
  }

  struct parameter_word_oracle {
    const char *input;
    bool has_substitution;
  };
  static const parameter_word_oracle parameter_word_cases[] = {
      {"printf ${VALUE#prefix${SUFFIX:-$(producer)}}", true},
      {"printf ${VALUE##prefix${SUFFIX}}", false},
      {"printf ${VALUE%tail${SUFFIX}}", false},
      {"printf ${VALUE%%tail${SUFFIX}}", false},
      {"printf ${VALUE/pattern/${REPLACEMENT}}", false},
      {"printf ${VALUE:-{left,right}}", false},
  };
  for (const parameter_word_oracle &item : parameter_word_cases) {
    size_t length = strlen(item.input);
    shell_parse_result_t parsed = {};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {};
    shell_netstring_buffer_t netargv = {};
    size_t netargv_count = 0;
    bool features = false;
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    shell_abstract_command_t *abstract = NULL;
    shell_dep_graph_t graph = {};
    bool valid =
        shell_parse_fast(item.input, length, NULL, &parsed) == SHELL_OK &&
        parsed.count == 1 &&
        shell_tokenize_commands(item.input, length, &commands,
                                &command_count) == SHELL_TOKENIZE_OK &&
        command_count == 1 &&
        shell_process_commands(item.input, length, NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == 1 &&
        shell_build_netargv_sequence_buffer(item.input, length, NULL, &netargv,
                                            &netargv_count,
                                            &features) == SHELL_PROCESS_OK &&
        netargv.data != NULL && netargv_count == 1 &&
        shell_transform_command_line(item.input, length, NULL, &transformed,
                                     &transformed_count) ==
            SHELL_TRANSFORM_OK &&
        transformed != NULL && transformed_count == 1 &&
        shell_abstract_command_parse(item.input, length, &abstract) ==
            SHELL_ABSTRACT_OK &&
        abstract != NULL && abstract->has_cmd_subst == item.has_substitution &&
        shell_dep_graph_parse(item.input, length, ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    shell_netstring_buffer_free(&netargv);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
    if (!valid)
      return fixed_oracle_failure(__LINE__);
  }

  static const char *const invalid_list_cases[] = {
      "a |",
      "a &&",
      "a ||",
      "a || || b",
      "a && && b",
      "a & & b",
      "a | ! b",
      "! !",
      "! \nprintf x |& cat",
      "! # note\nprintf x |& cat",
      "{ printf x; } 2&>combined",
      "{ printf x; } 3&>>combined",
      "{ printf x; } {fd}&>combined",
      "printf ${VALUE${SUFFIX}}",
      "printf ${VALUE$SUFFIX}",
      "printf ${VALUE.suffix}",
      "printf ${?suffix}",
      "printf ${10suffix}",
  };
  for (const char *input : invalid_list_cases) {
    shell_parse_result_t parsed = {};
    shell_command_t *commands = (shell_command_t *)(uintptr_t)1;
    size_t command_count = SIZE_MAX;
    shell_processed_commands_t processed = {
        (shell_command_info_t *)(uintptr_t)1, SIZE_MAX,
        (shell_group_t *)(uintptr_t)1,        SIZE_MAX,
        (shell_group_io_op_t *)(uintptr_t)1,  SIZE_MAX,
    };
    shell_dep_graph_t graph = {};
    bool invalid =
        shell_parse_fast(input, strlen(input), NULL, &parsed) == SHELL_EPARSE &&
        shell_tokenize_commands(input, strlen(input), &commands,
                                &command_count) == SHELL_TOKENIZE_EPARSE &&
        commands == NULL && command_count == 0 &&
        shell_process_commands(input, strlen(input), NULL, &processed) ==
            SHELL_PROCESS_EPARSE &&
        processed.commands == NULL && processed.command_count == 0 &&
        processed.groups == NULL && processed.group_count == 0 &&
        processed.group_io_ops == NULL && processed.group_io_op_count == 0 &&
        shell_dep_graph_parse(input, strlen(input), NULL, NULL, &graph) ==
            SHELL_DEP_EPARSE;
    if (!invalid)
      return fixed_oracle_failure(__LINE__);
  }

  /* Static nonnumeric duplicate operands fail setup; they never become FILE
   * resources or execute the group body. */
  static const char *const invalid_group_legacy_redirects[] = {
      "{ printf x; } 2>&combined",
      "{ printf x; } {fd}>&combined",
  };
  for (const char *input : invalid_group_legacy_redirects) {
    shell_processed_commands_t processed = {
        (shell_command_info_t *)(uintptr_t)1, SIZE_MAX,
        (shell_group_t *)(uintptr_t)1,        SIZE_MAX,
        (shell_group_io_op_t *)(uintptr_t)1,  SIZE_MAX,
    };
    shell_dep_graph_t graph = {};
    if (shell_process_commands(input, strlen(input), NULL, &processed) !=
            SHELL_PROCESS_OK ||
        processed.group_io_op_count != 1 ||
        processed.group_io_ops[0].kind != SHELL_GROUP_IO_FAILED_REDIRECT ||
        shell_dep_graph_parse(input, strlen(input), NULL, NULL, &graph) !=
            SHELL_DEP_OK)
      return fixed_oracle_failure(__LINE__);
    shell_processed_commands_free(&processed);
  }

  /* Shellsplit preserves an exact named-FD parameter as a deferred
   * descriptor duplication. The graph resolver, which has the binding scope,
   * rejects this unbound reference rather than treating it as a filename. */
  shell_processed_commands_t deferred_named_fd = {};
  shell_dep_graph_t deferred_named_graph = {};
  const char *deferred_named_source = "{ printf x; } >&$destination";
  if (shell_process_commands(deferred_named_source,
                             strlen(deferred_named_source), NULL,
                             &deferred_named_fd) != SHELL_PROCESS_OK ||
      deferred_named_fd.group_io_op_count != 1 ||
      deferred_named_fd.group_io_ops[0].kind != SHELL_GROUP_IO_DUP_FD ||
      shell_dep_graph_parse(deferred_named_source,
                            strlen(deferred_named_source), NULL, NULL,
                            &deferred_named_graph) != SHELL_DEP_EPARSE)
    return fixed_oracle_failure(__LINE__);
  shell_processed_commands_free(&deferred_named_fd);

  if (shell_parse_fast("printf $'a\\0b' @(one|two) xs=(one two) &>out",
                       strlen("printf $'a\\0b' @(one|two) xs=(one two) &>out"),
                       NULL, &modern) != SHELL_EPARSE)
    return fixed_oracle_failure(__LINE__);
  if (shell_parse_fast("xs=(one two) printf $'a\\0b' @(one|two) &>out",
                       strlen("xs=(one two) printf $'a\\0b' @(one|two) &>out"),
                       NULL, &modern) != SHELL_OK ||
      modern.count != 1 ||
      (modern.cmds[0].features &
       (SHELL_FEAT_ANSI_C_QUOTE | SHELL_FEAT_EXTGLOB | SHELL_FEAT_ARRAY |
        SHELL_FEAT_COMBINED_REDIRECT)) !=
          (SHELL_FEAT_ANSI_C_QUOTE | SHELL_FEAT_EXTGLOB | SHELL_FEAT_ARRAY |
           SHELL_FEAT_COMBINED_REDIRECT))
    return fixed_oracle_failure(__LINE__);
  shell_dep_graph_t modern_graph = {};
  if (shell_dep_graph_parse("cmd {trace}> trace.log &>> combined.log",
                            strlen("cmd {trace}> trace.log &>> combined.log"),
                            NULL, NULL, &modern_graph) != SHELL_DEP_OK ||
      !shell_dep_graph_validate(&modern_graph).valid)
    return fixed_oracle_failure(__LINE__);
  shell_processed_commands_t unsupported = {};
  if (shell_process_commands("select x in one; do :; done",
                             strlen("select x in one; do :; done"), NULL,
                             &unsupported) != SHELL_PROCESS_EPARSE ||
      shell_process_commands("coproc worker { :; }",
                             strlen("coproc worker { :; }"), NULL,
                             &unsupported) != SHELL_PROCESS_EPARSE)
    return fixed_oracle_failure(__LINE__);
  shell_processed_commands_free(&unsupported);

  static const char *const redirect_boundaries[] = {
      "cat >out;echo hi",
      "cat >out|echo hi",
      "cat >out|&echo hi",
      "cat >out&&echo hi",
      "cat >out||echo hi",
      "cat >out&echo hi",
      "{ cat; } >out;echo hi",
      "> <(cat)while echo ok",
      "> prefix<(cat)while echo ok",
      "> <(cat)foo time echo ok",
      "> <(cat)foo [[ x ]]",
  };
  for (const char *input : redirect_boundaries) {
    shell_netstring_buffer_t sequence = {};
    size_t command_count = 0;
    bool features = false;
    if (shell_build_netargv_sequence_buffer(input, strlen(input), NULL,
                                            &sequence, &command_count,
                                            &features) != SHELL_PROCESS_OK ||
        command_count != (strstr(input, "echo hi") ? 2u : 1u)) {
      shell_netstring_buffer_free(&sequence);
      return fixed_oracle_failure(__LINE__);
    }
    shell_netstring_buffer_free(&sequence);
  }
  static const char *const redirect_followed_by_unsupported[] = {
      "> <(cat)foo declare -a values",
      "> <(cat)foo while true; do :; done",
  };
  for (const char *input : redirect_followed_by_unsupported) {
    shell_processed_commands_t result = {};
    if (shell_process_commands(input, strlen(input), NULL, &result) !=
            SHELL_PROCESS_EPARSE ||
        result.commands != NULL || result.command_count != 0)
      return fixed_oracle_failure(__LINE__);
  }

  /* Declaration-like words containing process-substitution syntax require
   * stateful builtin interpretation before their assignment-name semantics
   * are known. The source-preserving layers accept them, but the dependency
   * graph must fail closed rather than invent execution semantics. Keep this
   * boundary independent of checked-in smoke seeds so it runs in every
   * session.
   */
  static const char *const stateful_unmodeled_cases[] = {
      "export OPT<()IND='x[$(printf ARITH >&2)0]'",
      "declare OPT<()IND=1",
      "typeset RAN<()DOM=1",
  };
  for (const char *input : stateful_unmodeled_cases) {
    shell_command_t *lexical = NULL;
    size_t lexical_count = 0;
    shell_processed_commands_t canonical = {};
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    shell_abstract_command_t *abstract = NULL;
    shell_dep_graph_t graph = {};
    bool rejected =
        shell_tokenize_commands(input, strlen(input), &lexical,
                                &lexical_count) == SHELL_TOKENIZE_OK &&
        lexical != NULL && lexical_count > 0 &&
        shell_process_commands(input, strlen(input), NULL, &canonical) ==
            SHELL_PROCESS_OK &&
        canonical.commands != NULL && canonical.command_count > 0 &&
        shell_transform_command_line(input, strlen(input), NULL, &transformed,
                                     &transformed_count) ==
            SHELL_TRANSFORM_OK &&
        transformed != NULL && transformed_count > 0 &&
        shell_abstract_command_parse(input, strlen(input), &abstract) ==
            SHELL_ABSTRACT_OK &&
        abstract != NULL &&
        shell_dep_graph_parse(input, strlen(input), NULL, NULL, &graph) ==
            SHELL_DEP_EPARSE &&
        graph.node_count == 0 && graph.edge_count == 0;
    shell_commands_free(lexical, lexical_count);
    shell_processed_commands_free(&canonical);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
    if (!rejected)
      return fixed_oracle_failure(__LINE__);
  }

  /* These Bash forms remain lexically visible for diagnostics, but every
   * semantic consumer must refuse a model it cannot faithfully provide.
   */
  static const char *const unmodeled_semantic_cases[] = {
      "readonly v<()=text",
      "export POSIX<()LY_CORRECT=x",
      "[[ -f /tmp/x ]]",
      "(( count += 1 ))",
      "time eval echo hidden",
      "time coproc echo hidden",
      "time [[ -f /tmp/x ]]",
      "time (( count += 1 ))",
      "time shopt -s varredir_close",
      "time command declare -a values",
      "echo \"$(time eval echo hidden)\"",
      "printf '%s' $\"localized\"",
      "echo \"${value:-$\"localized\"}\"",
      "declare arr[0]",
      "declare 'arr[0]'",
      "declare arr\\[0\\]",
      "declare arr$'[0]'",
      "\"declare\" -a values",
      "d\\eclare -a values",
      "de$'clare' -a values",
      "command \"declare\" -a values",
      "command -$'p' de$'clare' -a values",
      "declare \"-a\" values",
      "declare -$'a' values",
      "declare \"arr[0]=value\"",
      "readonly \"map[key]+=value\"",
      "typeset map[key]",
      "command -- declare \"arr[$(printf 0)]\"",
      "echo $( [[ -f /tmp/x ]] )",
      "{ (( 1 )); }",
      "cat <<EOF\n$(while true; do :; done)\nEOF\n",
      "cat <<EOF\n`select item in one; do :; done`\nEOF\n",
      "cat <<EOF\n${items[0]}\nEOF\n",
      "cat <<EOF\n$((items[0]))\nEOF\n",
      "echo $(( $(id) + 1 ))",
  };
  for (const char *input : unmodeled_semantic_cases) {
    shell_command_t *lexical = NULL;
    size_t lexical_count = 0;
    shell_processed_commands_t canonical = {};
    shell_transformed_command_t **transformed = NULL;
    size_t transformed_count = 0;
    shell_abstract_command_t *abstract = NULL;
    shell_dep_graph_t graph = {};
    bool rejected =
        shell_tokenize_commands(input, strlen(input), &lexical,
                                &lexical_count) == SHELL_TOKENIZE_OK &&
        lexical != NULL && lexical_count > 0 &&
        shell_process_commands(input, strlen(input), NULL, &canonical) ==
            SHELL_PROCESS_EPARSE &&
        canonical.commands == NULL && canonical.command_count == 0 &&
        shell_transform_command_line(input, strlen(input), NULL, &transformed,
                                     &transformed_count) ==
            SHELL_TRANSFORM_EPARSE &&
        transformed == NULL && transformed_count == 0 &&
        shell_abstract_command_parse(input, strlen(input), &abstract) ==
            SHELL_ABSTRACT_EPARSE &&
        abstract == NULL &&
        shell_dep_graph_parse(input, strlen(input), NULL, NULL, &graph) ==
            SHELL_DEP_EPARSE &&
        graph.node_count == 0 && graph.edge_count == 0;
    shell_commands_free(lexical, lexical_count);
    shell_processed_commands_free(&canonical);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
    if (!rejected)
      return fixed_oracle_failure(__LINE__);
  }

  static const struct {
    const char *input;
    size_t command_count;
  } brace_descriptor_cases[] = {
      {"{ echo one; echo two; }", 2},
      {"{ ( echo one; ); { echo two; }; }", 2},
      {"{ echo \"$(printf '}')\"; # }\n echo two; }", 2},
      {"{\n echo one\n} | { cat; }", 2},
      {"{\n echo one\r\n} | { cat; }", 2},
      {"{ { echo one; } | cat; printf two; } > /tmp/nested-brace.out", 3},
      {"{ cat; cat; } <<< value", 2},
      {"{ cat; cat; } <<< \"two words\"", 2},
      {"{ echo one; } & { cat; }", 2},
  };
  for (const auto &item : brace_descriptor_cases) {
    const char *input = item.input;
    shell_parse_result_t fast = {};
    shell_processed_commands_t processed = {};
    shell_error_t fast_status =
        shell_parse_fast(input, strlen(input), NULL, &fast);
    shell_process_status_t processed_status =
        shell_process_commands(input, strlen(input), NULL, &processed);
    if (fast_status != SHELL_OK || fast.group_count == 0 ||
        processed_status != SHELL_PROCESS_OK ||
        processed.command_count != item.command_count ||
        processed.group_count != fast.group_count ||
        !shellsplit_test_groups_equal(processed.groups, fast.groups,
                                      fast.group_count)) {
      if (g_verbose)
        fprintf(stderr,
                "brace oracle mismatch: %s (fast=%d count=%u groups=%u "
                "processed=%d count=%zu groups=%zu)\n",
                input, fast_status, fast.count, fast.group_count,
                processed_status, processed.command_count,
                processed.group_count);
      shell_processed_commands_free(&processed);
      return fixed_oracle_failure(__LINE__);
    }
    shell_processed_commands_free(&processed);
  }
  struct group_document_oracle {
    const char *input;
    shell_dep_doc_kind_t kind;
    uint32_t command_count;
    uint32_t pipe_count;
  };
  static const group_document_oracle group_document_cases[] = {
      {"{ cat; cat; } <<'EOF'\n}\nEOF", SHELL_DOC_HEREDOC, 2, 0},
      {"{ cat; cat; } <<EOF\r\n}\r\nEOF\r\n", SHELL_DOC_HEREDOC, 2, 0},
      {"{ cat; cat; } <<EOF | sort > /tmp/brace.out 2>>/tmp/brace.err\n"
       "payload\nEOF",
       SHELL_DOC_HEREDOC, 3, 1},
      {"{ cat; cat; } <<< \"two words\"", SHELL_DOC_HERESTRING, 2, 0},
  };
  for (const group_document_oracle &item : group_document_cases) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(item.input, strlen(item.input), ".", NULL,
                              &graph) != SHELL_DEP_OK ||
        !shellsplit_test_depgraph_invariants(item.input, strlen(item.input),
                                             SHELL_DEP_OK, &graph,
                                             &SHELL_DEP_LIMITS_DEFAULT))
      return fixed_oracle_failure(__LINE__);
    uint32_t command_count = 0;
    uint32_t document_count = 0;
    uint32_t read_count = 0;
    uint32_t pipe_count = 0;
    for (uint32_t i = 0; i < graph.node_count; i++) {
      command_count += graph.nodes[i].type == SHELL_NODE_CMD;
      document_count += graph.nodes[i].type == SHELL_NODE_DOC &&
                        graph.nodes[i].doc.kind == item.kind;
    }
    for (uint32_t i = 0; i < graph.edge_count; i++)
      read_count += (graph.edges[i].type == SHELL_EDGE_READ &&
                     internal_graph_relation(graph, graph.edges[i]));
    for (uint32_t i = 0; i < graph.edge_count; i++)
      pipe_count += graph.edges[i].type == SHELL_EDGE_PIPE;
    /* Group-owned input is represented as one DOC -> GROUP relation, not a
     * synthetic fan-out to each member command. */
    if (command_count != item.command_count || document_count != 1 ||
        read_count != 1 || pipe_count != item.pipe_count)
      return fixed_oracle_failure(__LINE__);
  }
  static const char group_herestring_override[] =
      "{ cat; } 3>&1 <<< stale 0<<< $(printf live)";
  shell_dep_graph_t group_herestring_graph = {};
  if (shell_dep_graph_parse(group_herestring_override,
                            strlen(group_herestring_override), ".", NULL,
                            &group_herestring_graph) != SHELL_DEP_OK ||
      !shellsplit_test_depgraph_invariants(
          group_herestring_override, strlen(group_herestring_override),
          SHELL_DEP_OK, &group_herestring_graph, &SHELL_DEP_LIMITS_DEFAULT))
    return fixed_oracle_failure(__LINE__);
  uint32_t here_documents = 0;
  uint32_t transient_here_documents = 0;
  uint32_t here_reads = 0;
  uint32_t here_substitutions = 0;
  for (uint32_t node = 0; node < group_herestring_graph.node_count; node++) {
    const shell_dep_node_t *current = &group_herestring_graph.nodes[node];
    if (current->type != SHELL_NODE_DOC ||
        current->doc.kind != SHELL_DOC_HERESTRING)
      continue;
    here_documents++;
    transient_here_documents +=
        (current->doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) != 0;
  }
  for (uint32_t edge = 0; edge < group_herestring_graph.edge_count; edge++) {
    const shell_dep_edge_t *current = &group_herestring_graph.edges[edge];
    if (!internal_graph_relation(group_herestring_graph, *current))
      continue;
    here_reads += current->type == SHELL_EDGE_READ;
    here_substitutions +=
        current->type == SHELL_EDGE_SUBST &&
        current->to < group_herestring_graph.node_count &&
        group_herestring_graph.nodes[current->to].type == SHELL_NODE_DOC &&
        group_herestring_graph.nodes[current->to].doc.kind ==
            SHELL_DOC_HERESTRING;
  }
  if (here_documents != 2 || transient_here_documents != 0 || here_reads != 2 ||
      here_substitutions != 1)
    return fixed_oracle_failure(__LINE__);
  struct dep_oracle_case {
    const char *input;
    uint32_t command_count;
    uint32_t substitution_edges;
  };
  static const dep_oracle_case dep_cases[] = {
      {"cd /tmp", 1, 0},
      {"cd /tmp >out", 1, 0},
      {"cd \"$(id)\"", 2, 1},
      {"export VALUE=$(id) >out", 2, 1},
      {"echo $(id)", 2, 1},
      {"echo $(id)$(pwd)", 3, 2},
      {"echo prefix$(id)suffix$(pwd)", 3, 2},
      {"cat < prefix<(id)", 2, 0},
      {"{ cat; } > >(id)suffix", 2, 0},
      {"cat < <(id)<(pwd)", 3, 0},
      {"echo $(<prefix<(id))", 2, 1},
      {"echo $(id)`pwd`", 3, 2},
      {"echo \"\\$(id)\"", 1, 0},
      {"echo \\\\$(id)", 2, 1},
      {"echo \"$(id)$(pwd)\"", 3, 2},
      {"sh <<< $(printf data)", 2, 1},
      {"cat <(printf \\))", 2, 1},
      {"cat <(printf \\\\)", 2, 1},
  };
  for (const dep_oracle_case &item : dep_cases) {
    shell_dep_graph_t graph = {};
    shell_dep_error_t status = shell_dep_graph_parse(
        item.input, strlen(item.input), ".", NULL, &graph);
    if (status != SHELL_DEP_OK ||
        !shellsplit_test_depgraph_invariants(item.input, strlen(item.input),
                                             SHELL_DEP_OK, &graph,
                                             &SHELL_DEP_LIMITS_DEFAULT))
      return fixed_oracle_failure(__LINE__);
    uint32_t command_count = 0;
    uint32_t substitution_edges = 0;
    for (uint32_t i = 0; i < graph.node_count; i++)
      command_count += graph.nodes[i].type == SHELL_NODE_CMD;
    for (uint32_t i = 0; i < graph.edge_count; i++)
      substitution_edges += graph.edges[i].type == SHELL_EDGE_SUBST;
    if (command_count != item.command_count ||
        substitution_edges != item.substitution_edges)
      return fixed_oracle_failure(__LINE__);
  }

  /* A literal non-descriptor prefix makes the command-substitution result a
   * pathname. Keep both ordinary and legacy combined-output spelling in the
   * always-run oracle set: their producer must flow to a dynamic FILE DOC,
   * never to a shell-word consumer. This also preserves the paired
   * stdout/stderr routes of `>&word` without adding another smoke seed. */
  struct brace_dynamic_redirect_oracle {
    const char *input;
    const char *path;
    bool combined_output;
  };
  static const brace_dynamic_redirect_oracle brace_dynamic_redirect_cases[] = {
      {"printf value >{$(printf /tmp/brace-output)}",
       "{$(printf /tmp/brace-output)}", false},
      {"printf value >&path-$(printf /tmp/brace-combined)",
       "path-$(printf /tmp/brace-combined)", true},
  };
  for (const brace_dynamic_redirect_oracle &item :
       brace_dynamic_redirect_cases) {
    shell_dep_graph_t graph = {};
    bool graph_ok =
        shell_dep_graph_parse(item.input, strlen(item.input), "/tmp", NULL,
                              &graph) == SHELL_DEP_OK &&
        shellsplit_test_depgraph_invariants(item.input, strlen(item.input),
                                            SHELL_DEP_OK, &graph,
                                            &SHELL_DEP_LIMITS_DEFAULT);
    uint32_t commands[2] = {};
    uint32_t command_count = 0;
    int document = -1;
    for (uint32_t node = 0; graph_ok && node < graph.node_count; node++) {
      if (graph.nodes[node].type == SHELL_NODE_CMD && command_count < 2)
        commands[command_count++] = node;
      if (graph.nodes[node].type == SHELL_NODE_DOC &&
          graph.nodes[node].doc.kind == SHELL_DOC_FILE &&
          graph.nodes[node].doc.path_len == strlen(item.path) &&
          memcmp(graph.nodes[node].doc.path, item.path,
                 graph.nodes[node].doc.path_len) == 0 &&
          (graph.nodes[node].doc.flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) != 0)
        document = (int)node;
    }
    bool dynamic_name_flow = false;
    bool stdout_route = false;
    bool stderr_route = false;
    for (uint32_t edge = 0; graph_ok && edge < graph.edge_count; edge++) {
      const shell_dep_edge_t &current = graph.edges[edge];
      dynamic_name_flow =
          dynamic_name_flow ||
          (command_count == 2 && document >= 0 &&
           current.type == SHELL_EDGE_SUBST && current.from == commands[1] &&
           current.to == static_cast<uint32_t>(document) &&
           current.source_fd == 1 && current.target_fd == SHELL_DEP_FD_NONE &&
           (current.flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0 &&
           (current.flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) == 0);
      stdout_route =
          stdout_route ||
          (command_count == 2 && document >= 0 &&
           current.type == SHELL_EDGE_WRITE && current.from == commands[0] &&
           current.to == static_cast<uint32_t>(document) &&
           current.source_fd == 1 && current.target_fd == SHELL_DEP_FD_NONE);
      stderr_route =
          stderr_route ||
          (command_count == 2 && document >= 0 &&
           current.type == SHELL_EDGE_WRITE && current.from == commands[0] &&
           current.to == static_cast<uint32_t>(document) &&
           current.source_fd == 2 && current.target_fd == SHELL_DEP_FD_NONE);
    }
    if (!graph_ok || command_count != 2 || document < 0 || !dynamic_name_flow ||
        !stdout_route || (item.combined_output && !stderr_route))
      return fixed_oracle_failure(__LINE__);
  }

  struct composition_oracle {
    const char *input;
    uint32_t command_count;
    shell_dep_edge_type_t edge;
    uint16_t group_depth;
    bool backgrounded;
  };
  static const composition_oracle composition_cases[] = {
      {"echo one & echo two", 2, SHELL_EDGE_BACKGROUND, 0, true},
      {"(echo one; echo two)", 2, SHELL_EDGE_GROUP, 1, false},
      {"echo one | echo two", 2, SHELL_EDGE_PIPE, 0, false},
  };
  for (const composition_oracle &item : composition_cases) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(item.input, strlen(item.input), ".", NULL,
                              &graph) != SHELL_DEP_OK)
      return fixed_oracle_failure(__LINE__);
    uint32_t command_count = 0;
    bool edge_seen = false;
    for (uint32_t i = 0; i < graph.node_count; i++) {
      if (graph.nodes[i].type != SHELL_NODE_CMD)
        continue;
      if (command_count++ == 0 &&
          (graph.nodes[i].cmd.group_depth != item.group_depth ||
           graph.nodes[i].cmd.backgrounded != item.backgrounded))
        return fixed_oracle_failure(__LINE__);
    }
    for (uint32_t i = 0; i < graph.edge_count; i++)
      edge_seen = edge_seen || graph.edges[i].type == item.edge;
    if (command_count != item.command_count || !edge_seen)
      return fixed_oracle_failure(__LINE__);
  }
  static const char *const invalid[] = {"echo $'é'", "echo $((é))"};
  for (const char *input : invalid) {
    shell_parse_result_t fast = {};
    if (shell_parse_fast(input, strlen(input), NULL, &fast) != SHELL_EPARSE ||
        !(fast.status & SHELL_STATUS_ERROR))
      return fixed_oracle_failure(__LINE__);
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    if ((shell_tokenize_commands(input, strlen(input), &commands,
                                 &command_count) == SHELL_TOKENIZE_OK)) {
      shell_commands_free(commands, command_count);
      return fixed_oracle_failure(__LINE__);
    }
    shell_commands_free(commands, command_count);
  }
  static const char *const unsupported_nested_documents[] = {
      "echo $(cat <<EOF\nbody\nEOF)",
      "echo $(cat <<'EOF'\n$(id)\nEOF) && pwd",
      "cat <(cat <<EOF\nbody\nEOF)",
  };
  for (const char *input : unsupported_nested_documents) {
    shell_parse_result_t fast = {};
    if (shell_parse_fast(input, strlen(input), NULL, &fast) != SHELL_EPARSE ||
        !(fast.status & SHELL_STATUS_ERROR))
      return fixed_oracle_failure(__LINE__);
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) !=
            SHELL_DEP_EPARSE ||
        graph.status != SHELL_DEP_STATUS_ERROR)
      return fixed_oracle_failure(__LINE__);
  }
  static const char *const unsupported_nested_structures[] = {
      "echo $(case value in x)",
      "cat <(for ((i=0; i<1; i++)); do echo x; done)",
  };
  for (const char *input : unsupported_nested_structures) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) !=
            SHELL_DEP_EPARSE ||
        graph.status != SHELL_DEP_STATUS_ERROR || graph.node_count != 0 ||
        graph.edge_count != 0)
      return fixed_oracle_failure(__LINE__);
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
    if (!(shell_tokenize_commands(item.input, strlen(item.input), &commands,
                                  &command_count) == SHELL_TOKENIZE_OK) ||
        command_count == 0 || commands[0].has_loops != item.loops ||
        commands[0].has_conditionals != item.conditionals ||
        commands[0].has_case != item.case_stmt) {
      shell_commands_free(commands, command_count);
      return fixed_oracle_failure(__LINE__);
    }
    shell_commands_free(commands, command_count);
  }

  /* Redirect operands are attached grammar, so only horizontal whitespace and
   * escaped physical line endings may separate them from their operator. Keep
   * the complete API family in this fixed oracle: accepting one of these
   * malformed inputs in only a downstream representation would fabricate a
   * different command stream for policy and graph consumers. */
  static const char *const invalid_redirect_operands[] = {
      "echo >\nout",
      "echo > # comment",
      "echo <\nin",
      "echo 2>\nerr",
      "echo &>\nout",
      "echo <<<\nword",
      "echo <<\nEOF\nbody\nEOF\n",
      "echo >#comment",
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
  for (const char *input : invalid_redirect_operands) {
    size_t length = strlen(input);
    shell_parse_result_t fast = {};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    shell_processed_commands_t processed = {};
    shell_netstring_buffer_t netargv = {};
    size_t netargv_count = 0;
    bool has_shell_features = false;
    shell_netstring_buffer_t command_netseq = {};
    size_t command_netseq_count = 0;
    shell_netstring_buffer_t type_netseq = {};
    size_t type_netseq_count = 0;
    shell_netstring_buffer_t anomaly_commands = {};
    shell_netstring_buffer_t anomaly_types = {};
    size_t anomaly_count = 0;
    shell_dep_graph_t graph = {};
    bool rejected =
        shell_parse_fast(input, length, NULL, &fast) == SHELL_EPARSE &&
        shell_tokenize_commands(input, length, &commands, &command_count) ==
            SHELL_TOKENIZE_EPARSE &&
        commands == NULL && command_count == 0 &&
        shell_process_command(input, length, NULL, &infos, &info_count) ==
            SHELL_PROCESS_EPARSE &&
        infos == NULL && info_count == 0 &&
        shell_process_commands(input, length, NULL, &processed) ==
            SHELL_PROCESS_EPARSE &&
        processed.commands == NULL && processed.command_count == 0 &&
        shell_build_netargv_sequence_buffer(
            input, length, NULL, &netargv, &netargv_count,
            &has_shell_features) == SHELL_PROCESS_EPARSE &&
        netargv.data == NULL && netargv_count == 0 &&
        shell_build_command_netseq_buffer(input, length, NULL, &command_netseq,
                                          &command_netseq_count) ==
            SHELL_PROCESS_EPARSE &&
        command_netseq.data == NULL && command_netseq_count == 0 &&
        shell_build_type_netseq_buffer(input, length, NULL, &type_netseq,
                                       &type_netseq_count) ==
            SHELL_PROCESS_EPARSE &&
        type_netseq.data == NULL && type_netseq_count == 0 &&
        shell_build_anomaly_netseqs_buffer(
            input, length, NULL, &anomaly_commands, &anomaly_types,
            &anomaly_count) == SHELL_PROCESS_EPARSE &&
        anomaly_commands.data == NULL && anomaly_types.data == NULL &&
        anomaly_count == 0 &&
        shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
            SHELL_DEP_EPARSE &&
        graph.status == SHELL_DEP_STATUS_ERROR;
    shell_commands_free(commands, command_count);
    shell_command_infos_free(infos, info_count);
    shell_processed_commands_free(&processed);
    shell_netstring_buffer_free(&netargv);
    shell_netstring_buffer_free(&command_netseq);
    shell_netstring_buffer_free(&type_netseq);
    shell_netstring_buffer_free(&anomaly_commands);
    shell_netstring_buffer_free(&anomaly_types);
    if (!rejected)
      return fixed_oracle_failure(__LINE__);
  }

  static const char *const accepted_redirect_operands[] = {
      "echo > \\\nout",
      "echo 2> \\\nerr",
      "echo >\"#name\"",
      "echo >\\#name",
      "echo <<<\"#value\"",
      "echo <<<\\#value",
      "echo <<'#marker'\nbody\n#marker\n",
      "echo <<\\#marker\nbody\n#marker\n",
      "echo <<-'#marker'\n\tbody\n\t#marker\n",
      "{ echo; } \\\n>out",
      "{ echo; } \\\n<<<payload",
      "{ echo; } \\\n<<EOF\npayload\nEOF\n",
  };
  for (const char *input : accepted_redirect_operands) {
    size_t length = strlen(input);
    shell_parse_result_t fast = {};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {};
    shell_netstring_buffer_t netargv = {};
    size_t netargv_count = 0;
    bool has_shell_features = false;
    shell_dep_graph_t graph = {};
    bool accepted =
        shell_parse_fast(input, length, NULL, &fast) == SHELL_OK &&
        shell_tokenize_commands(input, length, &commands, &command_count) ==
            SHELL_TOKENIZE_OK &&
        shell_process_commands(input, length, NULL, &processed) ==
            SHELL_PROCESS_OK &&
        shell_build_netargv_sequence_buffer(
            input, length, NULL, &netargv, &netargv_count,
            &has_shell_features) == SHELL_PROCESS_OK &&
        shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    shell_netstring_buffer_free(&netargv);
    if (!accepted)
      return fixed_oracle_failure(__LINE__);
  }

  struct redirect_owner_oracle {
    const char *input;
    shell_dep_doc_kind_t document_kind;
    bool continued;
  };
  static const redirect_owner_oracle redirect_owners[] = {
      {"{ echo; }\n<<<payload", SHELL_DOC_HERESTRING, false},
      {"{ echo; } \\\n<<<payload", SHELL_DOC_HERESTRING, true},
      {"{ echo; }\n<<EOF\npayload\nEOF\n", SHELL_DOC_HEREDOC, false},
      {"{ echo; } \\\n<<EOF\npayload\nEOF\n", SHELL_DOC_HEREDOC, true},
  };
  for (const redirect_owner_oracle &item : redirect_owners) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(item.input, strlen(item.input), ".", NULL,
                              &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return fixed_oracle_failure(__LINE__);
    uint32_t group = UINT32_MAX;
    uint32_t document = UINT32_MAX;
    uint32_t empty_command = UINT32_MAX;
    uint32_t command_count = 0;
    for (uint32_t node = 0; node < graph.node_count; node++) {
      if (graph.nodes[node].type == SHELL_NODE_GROUP &&
          graph.nodes[node].group.parent == UINT32_MAX)
        group = node;
      if (graph.nodes[node].type == SHELL_NODE_DOC &&
          graph.nodes[node].doc.kind == item.document_kind)
        document = node;
      if (graph.nodes[node].type == SHELL_NODE_CMD) {
        command_count++;
        if (graph.nodes[node].cmd.token_count == 0)
          empty_command = node;
      }
    }
    uint32_t reader = UINT32_MAX;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      if ((graph.edges[edge].type == SHELL_EDGE_READ &&
           internal_graph_relation(graph, graph.edges[edge])) &&
          graph.edges[edge].from == document) {
        reader = graph.edges[edge].to;
        break;
      }
    }
    if (group == UINT32_MAX || document == UINT32_MAX || reader == UINT32_MAX ||
        (item.continued ? command_count != 1 || reader != group
                        : command_count != 2 || empty_command == UINT32_MAX ||
                              reader != empty_command))
      return fixed_oracle_failure(__LINE__);
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
      plain = plain || !shell_source_space(c);
      if (shell_source_space(c)) {
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

  /* A plain character set does not imply a supported shell command: `.` and
   * other statically recognized current-shell builtins are intentionally
   * rejected by the semantic boundary. Compare strict APIs against that
   * boundary rather than claiming every such word must execute. */
  bool unsupported = shell_tokenizer_has_unsupported_semantics(input, length);
  shell_parse_result_t fast = {};
  shell_error_t fast_status = shell_parse_fast(input, length, NULL, &fast);
  if (unsupported) {
    shell_command_info_t *infos = NULL;
    size_t info_count = 0;
    shell_process_status_t status =
        shell_process_command(input, length, NULL, &infos, &info_count);
    bool valid = fast_status == SHELL_OK && fast.count == 1 &&
                 status == SHELL_PROCESS_EPARSE && infos == NULL &&
                 info_count == 0;
    shell_command_infos_free(infos, info_count);
    return valid ? 0 : 1;
  }
  if (fast_status != SHELL_OK || fast.count != 1)
    return 1;
  shell_command_t *commands = NULL;
  size_t command_count = 0;
  bool full_ok = (shell_tokenize_commands(input, strlen(input), &commands,
                                          &command_count) == SHELL_TOKENIZE_OK);
  shell_commands_free(commands, command_count);
  if (!full_ok || command_count != 1)
    return 1;
  shell_command_info_t *infos = NULL;
  size_t info_count = 0;
  shell_process_status_t processed =
      shell_process_command(input, strlen(input), NULL, &infos, &info_count);
  shell_command_infos_free(infos, info_count);
  return processed != SHELL_PROCESS_OK || info_count != 1;
}

static int validate_depgraph(const char *input, size_t length,
                             shell_dep_error_t error,
                             const shell_dep_graph_t *graph,
                             const shell_dep_limits_t *limits);
static int test_full_parser(const char *input, size_t length);

static int test_structured_variants(const char *input, size_t length) {
  if (length == 0 || length > 256)
    return 0;
  std::string base(input, length);
  const std::string variants[] = {base + " | cat", "echo $(" + base + ")",
                                  "'" + base + "'", "{ " + base + "; }"};
  for (const std::string &variant : variants) {
    shell_parse_result_t fast = {};
    shell_error_t fast_error =
        shell_parse_fast(variant.data(), variant.size(), NULL, &fast);
    if (validate_fast_result(variant.data(), variant.size(), fast_error, &fast,
                             SHELL_MAX_SUBCOMMANDS)) {
      if (g_verbose)
        fprintf(stderr, "structured variant fast failure: %s\n",
                variant.c_str());
      return 1;
    }
    shell_dep_graph_t graph = {};
    shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
    shell_dep_error_t dep_error = shell_dep_graph_parse(
        variant.data(), variant.size(), ".", &limits, &graph);
    if (validate_depgraph(variant.data(), variant.size(), dep_error, &graph,
                          &limits)) {
      if (g_verbose)
        fprintf(stderr, "structured variant graph failure: %s\n",
                variant.c_str());
      return 1;
    }
    if (test_full_parser(variant.c_str(), variant.size())) {
      if (g_verbose)
        fprintf(stderr, "structured variant full failure: %s\n",
                variant.c_str());
      return 1;
    }
  }
  return 0;
}

static int validate_depgraph(const char *input, size_t length,
                             shell_dep_error_t error,
                             const shell_dep_graph_t *graph,
                             const shell_dep_limits_t *limits) {
  return shellsplit_test_depgraph_invariants(input, length, error, graph,
                                             limits)
             ? 0
             : 1;
}

struct resolved_fuzz_context {
  const char *source;
  size_t length;
  uint8_t mode;
  bool invalid_request;
  size_t calls;
  std::vector<uint8_t> seen;
  const char *payload;
  size_t payload_length;
};

static shell_expand_status_t
resolved_fuzz_word(const shell_expand_word_request_t *request,
                   const char **netargv, size_t *length, void *context) {
  auto *fixture = static_cast<resolved_fuzz_context *>(context);
  if (request->source != fixture->source ||
      request->source_length != fixture->length ||
      request->word_offset >= fixture->length ||
      request->word_length > fixture->length - request->word_offset ||
      request->owner_offset > request->word_offset ||
      request->owner_length > fixture->length - request->owner_offset ||
      fixture->seen[request->word_offset]++) {
    fixture->invalid_request = true;
    return SHELL_EXPAND_FAILED;
  }
  fixture->calls++;
  *netargv = fixture->payload;
  *length = fixture->payload_length;
  if (fixture->mode == 0)
    return SHELL_EXPAND_UNRESOLVED;
  if (fixture->mode == 6)
    return SHELL_EXPAND_FAILED;
  return SHELL_EXPAND_RESOLVED;
}

static int test_resolved_depgraph(const char *input, size_t length,
                                  const char *cwd, uint8_t selector,
                                  bool truncate) {
  auto &workspace = g_depgraph_workspace;
  shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
  if (truncate) {
    limits.max_nodes = 1;
    limits.max_edges = 1;
  }
  size_t required = 0;
  if (!shell_dep_resolved_workspace_size(length, &limits, &required))
    return 1;
  size_t slots =
      (required + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t);
  if (workspace.size() < slots)
    workspace.resize(slots);
  limits.workspace = workspace.data();
  limits.workspace_size = required;
  static const char binary[] = {'3', ':', 'a', '\0', 'b', ','};
  resolved_fuzz_context fixture = {
      input,   length, (uint8_t)(selector % 7),
      false,   0,      std::vector<uint8_t>(length),
      nullptr, 0};
  switch (fixture.mode) {
  case 0:
  case 1:
    fixture.payload = "9:/tmp/path,";
    fixture.payload_length = 12;
    break;
  case 3:
    fixture.payload = "1:a,1:b,";
    fixture.payload_length = 8;
    break;
  case 4:
    fixture.payload = binary;
    fixture.payload_length = sizeof(binary);
    break;
  case 5:
    fixture.payload = "01:x,";
    fixture.payload_length = 5;
    break;
  default:
    break; /* Empty successful expansion, or explicit callback failure. */
  }
  shell_dep_graph_t graph = {};
  uint8_t unresolved[SHELL_DEP_MAX_NODES];
  memset(unresolved, 0xff, sizeof(unresolved));
  shell_dep_error_t error =
      shell_dep_graph_parse_resolved(input, length, cwd, &limits, &graph,
                                     resolved_fuzz_word, &fixture, unresolved);
  if (fixture.invalid_request ||
      validate_depgraph(input, length, error, &graph, &limits) ||
      (fixture.calls && fixture.mode >= 5 && error != SHELL_DEP_EEXPAND))
    return 1;
  for (size_t i = 0; i < SHELL_DEP_MAX_NODES; i++) {
    if (unresolved[i] > 1 || (i >= graph.node_count && unresolved[i]))
      return 1;
    if (i < graph.node_count && graph.nodes[i].type == SHELL_NODE_DOC &&
        (graph.nodes[i].doc.flags & SHELL_DEP_DOC_FLAG_RESOLVED_PATH)) {
      const auto &doc = graph.nodes[i].doc;
      /* Values borrow exactly the callback's immutable encoded buffer. */
      uintptr_t value = reinterpret_cast<uintptr_t>(doc.value);
      uintptr_t start = reinterpret_cast<uintptr_t>(fixture.payload);
      if (!fixture.payload || value < start ||
          value - start > fixture.payload_length ||
          doc.value_len > fixture.payload_length - (value - start))
        return 1;
    }
  }
  return 0;
}

/* Dispatch uses the low bits of data[0]. Do not reuse those constrained bits
 * as the fixture selector: multi-byte inputs reach the full selector domain,
 * and the quotient makes every form reachable even with one input byte. */
static uint8_t descriptor_move_selector(const uint8_t *data, size_t size) {
  return size > 1 ? data[1] : data[0] / 8;
}

static constexpr unsigned descriptor_move_form_count = 77;
static constexpr unsigned descriptor_move_single_byte_selector_count = 32;

static void descriptor_move_source(uint8_t selector, char (&input)[512]) {
  unsigned source = 3u + selector % 5u, destination = 8u + selector % 5u;
  unsigned form = selector % descriptor_move_form_count;
  const char *action = form == 2 ? "exec" : ":";
  if (form >= 73) {
    const char *body = "exec 10>/tmp/move-pad; printf next >&10";
    char wrapper[192];
    if (form == 73)
      snprintf(wrapper, sizeof(wrapper), "echo \"$(%s)\"", body);
    else if (form == 74)
      snprintf(wrapper, sizeof(wrapper), "echo \"$(echo \"$(%s)\")\"", body);
    else if (form == 75)
      snprintf(wrapper, sizeof(wrapper), "cat < <(%s)", body);
    else
      snprintf(wrapper, sizeof(wrapper), ": > >(%s)", body);
    snprintf(input, sizeof(input),
             "exec 1>/tmp/move-fuzz || exit; "
             "exec 9>&- 10>&- 11>&- 12>&-; { %s; } 1>/tmp/move-first",
             wrapper);
  } else if (form >= 70)
    snprintf(input, sizeof(input),
             "exec 1>/tmp/move-pad 4>/tmp/move-fuzz || exit; "
             "exec 10>&- 11>&- 12>&-; %s 1>&4- 12>&11- 1>&11; echo next",
             form == 70   ? ":"
             : form == 71 ? "{ :; }"
                          : "\"$cmd\"");
  else if (form == 64 || form == 65 || form == 68)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz || exit; exec 10>&- 11>&- 12>&-; "
             "%s\"$cmd\" next 1>&3 {fd}>&3 1>&10",
             form == 65   ? "command "
             : form == 68 ? "builtin "
                          : "");
  else if (form == 66 || form == 67 || form == 69)
    snprintf(input, sizeof(input),
             "exec 3>&1 || exit; exec 10>&- 11>&- 12>&-; "
             "%s %s 1>&3 2>&10 && echo next >/tmp/move-fuzz",
             form == 67 ? "" : "!", form == 69 ? "0<<<literal" : "0<&0");
  else if (form == 63)
    snprintf(input, sizeof(input),
             "exec 4>/tmp/move-fuzz 10>/tmp/move-pad || exit; "
             "exec 11>&- 12>&-; : \"$(echo next >&12)\" 10>&4-");
  else if (form == 62)
    snprintf(input, sizeof(input),
             "exec 4>/tmp/move-fuzz 10>/tmp/move-pad || exit; "
             "exec 11>&- 12>&-; "
             ": 10>&4- >\"$(echo next >&12; printf /dev/null)\"");
  else if (form == 61)
    snprintf(input, sizeof(input),
             "exec 4>/tmp/move-fuzz 10>/tmp/move-pad || exit; "
             "exec 11>&- 12>&-; /bin/echo next 10>&4- >&12");
  else if (form == 60)
    snprintf(input, sizeof(input),
             "exec 4</tmp/move-fuzz 10</tmp/move-pad || exit; "
             "exec 11<&- 12<&- 13<&- 14<&-; "
             "exec 10<&4- 14<&12-; cat <&14");
  else if (form == 59)
    snprintf(input, sizeof(input),
             "exec 4>/tmp/move-fuzz 10>/tmp/move-pad || exit; "
             "exec 11>&- 12>&-; echo next 10>&4- >&12");
  else if (form == 58)
    snprintf(input, sizeof(input),
             "exec 3</tmp/move-pad 4</tmp/move-fuzz || exit; "
             "exec 10<&3 11<&- 12<&- 13<&-; "
             "exec 3<&10- 11<&4 10<&-; cat <&11");
  else if (form == 57)
    snprintf(input, sizeof(input),
             "exec 1>/tmp/move-fuzz 3>/tmp/move-pad 4>/tmp/move-pad || exit; "
             "exec 10>&- 11>&- 12>&-; "
             "{ probe && exec 11>&-; } 3>&1 4>&1; echo next >&4");
  else if (form == 56)
    snprintf(input, sizeof(input),
             "exec 1>/tmp/move-fuzz 3>/tmp/move-pad 4>/tmp/move-pad || exit; "
             "exec 10>&- 11>&- 12>&-; "
             "{ exec 11>&-; } 3>&1 4>&1; echo next >&3");
  else if (form == 55)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-pad 4>/tmp/move-fuzz || exit; "
             "exec 10>&3 11>&- 12>&- 13>&-; "
             "exec 3>&10- 11>&4 10>&-; echo next >&11");
  else if (form == 54)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz || exit; exec 10>&- 11>&-; "
             "{ exec 10>/tmp/move-pad; echo next >&10; } 3>&1");
  else if (form == 53)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz || exit; exec 10>&- 11>&- 12>&-; "
             "exec {fd}>&3; exec {fd}>&- 11>&3-; echo next >&11");
  else if (form == 52)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz 4>/tmp/move-pad || exit; "
             "exec 8>&- 10>&- 11>&- 12>&-; exec {fd}>&3; "
             ": 3>&${fd}- {fd}>&4 5>&8; echo next >&10");
  else if (form == 51)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-pad 20>/tmp/move-fuzz || exit; "
             "exec 10>&- 11>&- 21>&- 22>&-; { echo next >&10; } 3>&20-");
  else if (form == 50)
    snprintf(input, sizeof(input),
             "exec 4>&-; exec 3>/tmp/move-fuzz || exit; "
             "{ :; } 4>&3- || echo next >&3");
  else if (form == 49)
    snprintf(input, sizeof(input),
             "exec 4>&-; exec 3>/tmp/move-fuzz || exit; "
             "{ :; } 4>&3-; echo next >&3");
  else if (form >= 46)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz 4>/tmp/move-pad || exit; "
             "exec 10>&- 11>&- 12>&-; exec {fd}>&3; : 3>&${fd}- %s; "
             "echo next >&10",
             form == 46   ? "{fd}>&4"
             : form == 47 ? "{fd}>&-"
                          : "11>&3-");
  else if (form == 45)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz 4>/tmp/move-pad || exit; exec 10>&- 11>&-; "
             "exec {fd}>&3 {fd}>&4; echo \"$(printf next >&10)\"");
  else if (form == 44)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz || exit; exec 4>&-; "
             "builtin \"$runner\" 4>&3-; echo next >&3");
  else if (form == 43)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz || exit; "
             "builtin command /bin/true {fd}>&3; echo next >&\"$fd\"");
  else if (form == 42)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz || exit; exec 4>&-; "
             "builtin command /bin/true 4>&3-; echo next >&3");
  else if (form == 41)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz || exit; exec 10>&- 11>&-; "
             "{ :; } {fd}>&3 10>&3-; echo next >&10");
  else if (form == 40)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz || exit; exec 10>&- 11>&-; "
             ": {fd}>&3 10>&-; echo next >&\"$fd\"");
  else if (form == 39)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz || exit; exec 10>&- 11>&-; "
             "exec {fd}>&3 {fd}>&3; echo next >&10");
  else if (form == 38)
    snprintf(input, sizeof(input),
             "exec 3</tmp/move-fuzz 4</tmp/move-pad || exit; "
             "exec 10<&- 11<&- 12<&-; : 4<&- 10<& 3-; cat <&3");
  else if (form == 37)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz 4>/tmp/move-pad || exit; "
             "exec 10>&- 11>&- 12>&-; : 4>&- 10>&3-; echo next >&3");
  else if (form == 36)
    snprintf(input, sizeof(input),
             "exec 3</tmp/move-fuzz || exit; exec 10<& - 11<& - 12<& -; "
             "{ cat <&11; } 3<&0");
  else if (form == 35)
    snprintf(input, sizeof(input),
             "exec 0</tmp/move-fuzz || exit; exec 10<&-; { :; } 10<&10; "
             "exec {fd}<&0; cat <&10");
  else if (form == 34)
    snprintf(input, sizeof(input),
             "exec 0</tmp/move-fuzz || exit; exec 10<&-; exec 10<&10-; "
             "exec {fd}<&0; cat <&10");
  else if (form == 33)
    snprintf(input, sizeof(input),
             "exec {out}>/tmp/move-fuzz; exec {fd}>&1; IFS=0123456789; "
             "exec {out}>&${fd}-; echo next");
  else if (form == 32)
    snprintf(input, sizeof(input),
             "exec {out}>/tmp/move-fuzz; exec {fd}>&1; IFS=0123456789; "
             "{ :; } {out}>&${fd}-; echo next >&\"$out\"");
  else if (form == 31)
    snprintf(input, sizeof(input),
             "exec {out}>/tmp/move-fuzz; exec {fd}>&1; IFS=0123456789; "
             ": {out}>&${fd}-; echo next >&\"$out\"");
  else if (form == 30)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz || exit; exec 10>& - 11>& - 12>& -; "
             "{ echo next >&11; } 3>&1");
  else if (form == 29)
    snprintf(input, sizeof(input),
             "exec 1>/tmp/move-fuzz || exit; exec 10>&-; { :; } 10>&10; "
             "exec {fd}>&1; echo next >&10");
  else if (form == 28)
    snprintf(input, sizeof(input),
             "exec 1>/tmp/move-fuzz || exit; exec 10>&-; exec 10>&10-; "
             "exec {fd}>&1; echo next >&10");
  else if (form == 27)
    snprintf(input, sizeof(input),
             "exec 3</tmp/move-fuzz || exit; exec 11<&- 12<&-; "
             "{ :; } 3<&0; cat <&11");
  else if (form == 26)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/move-fuzz || exit; exec 11>&- 12>&-; "
             "{ :; } 3>&1; echo next >&11");
  else if (form == 25)
    snprintf(input, sizeof(input),
             "exec 4>/tmp/move-fuzz; { :; } 4>&\"\"; echo next >&4");
  else if (form == 24)
    snprintf(input, sizeof(input),
             "exec 4>/tmp/move-fuzz; : 4>&\"\"-; echo next >&4");
  else if (form == 23)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/old || exit; exec 4>/tmp/move-fuzz || exit; "
             "exec 10>&- 11>&- 12>&- 13>&-; "
             ": 3>&1 3>&4 {fd}>&3; echo next >&12");
  else if (form == 22)
    snprintf(input, sizeof(input),
             "exec 3>/tmp/old || exit; exec 4>/tmp/move-fuzz || exit; "
             "exec 10>&- 11>&- 12>&- 13>&-; "
             ": 3>&4- {fd}>&3; echo next >&12");
  else if (form == 21)
    snprintf(input, sizeof(input),
             "exec 3>&- 10>&- 11>&-; "
             "{ probe && exec {fd}>/tmp/move-first || "
             "exec {pad}>/tmp/move-pad {fd}>/tmp/move-fuzz; } && "
             "echo \"$(exec 4>&${fd}-; printf next >&4)\"");
  else if (form >= 17)
    snprintf(input, sizeof(input),
             "exec 3%c/tmp/old 4%c/tmp/move-fuzz; %s 3%c&4- 3%c&4; %s",
             form == 19 ? '<' : '>', form == 19 ? '<' : '>',
             form == 18   ? "{ :; }"
             : form == 20 ? "exec"
                          : ":",
             form == 19 ? '<' : '>', form == 19 ? '<' : '>',
             form == 19 ? "cat <&4" : "echo next >&4");
  else if (form == 16)
    snprintf(input, sizeof(input),
             "exec 3>&- 10>&- 11>&-; "
             "{ probe && exec {fd}>/tmp/move-first || "
             "exec {pad}>/tmp/move-pad {fd}>/tmp/move-fuzz; } && "
             "{ exec 10>&${fd}-; echo next >&10; }");
  else if (form == 8 || form == 11 || form == 12 || form == 13)
    snprintf(input, sizeof(input),
             "exec %u>&-; exec %u>/tmp/move-fuzz; %s %u>&%u-; echo next >&%u",
             destination, source,
             form == 8    ? "/bin/true"
             : form == 11 ? "\"$runner\""
             : form == 12 ? "builtin true"
                          : "command /bin/true",
             destination, source, source);
  else if (form == 9 || form == 15)
    snprintf(input, sizeof(input),
             "exec %u>&-; exec %u>/tmp/old; { %sexec %u>/tmp/move-fuzz; %s} "
             "%u>&%u-; echo next >&%u",
             destination, source, form == 15 ? "{ " : "", source,
             form == 15 ? "}; " : "", destination, source, source);
  else if (form == 10)
    snprintf(input, sizeof(input),
             "exec 1>/tmp/move-fuzz; exec 10>&-; exec {fd}>&1 10>&${fd}-; "
             "echo next >&\"$fd\"");
  else if (form == 14)
    snprintf(input, sizeof(input),
             "exec {fd}>/tmp/move-fuzz; /bin/true {fd}>/tmp/local; "
             "echo next >&\"$fd\"");
  else if (form == 7)
    snprintf(input, sizeof(input),
             "exec {fd}>/tmp/move-fuzz; exec 1>&${fd}-; echo next");
  else if (form == 3 || form == 4)
    snprintf(
        input, sizeof(input),
        "exec %u>&%s; exec %u>/tmp/move-fuzz; { :; } %u>&%u-; echo next >&%u",
        destination, form == 4 ? "1" : "-", source, destination, source,
        source);
  else if (form == 5 || form == 6)
    snprintf(
        input, sizeof(input),
        "exec %u>&-; exec %u>/tmp/move-fuzz; : %u>&\"%u%s\"%s; echo next >&%u",
        destination, source, destination, source, form == 5 ? "-" : "",
        form == 6 ? "-" : "", source);
  else
    snprintf(input, sizeof(input),
             "exec %u>&%s; exec %u>/tmp/move-fuzz; %s %u>&%u-; echo next >&%u",
             destination, form == 1 ? "1" : "-", source, action, destination,
             source, source);
}

static int test_descriptor_move(uint8_t selector, const char *input) {
  unsigned form = selector % descriptor_move_form_count;
  bool expected_route =
      form == 1 || form == 4 || form == 5 || form == 7 ||
      (form >= 8 && form != 12 && form < 26) || form == 28 || form == 29 ||
      form == 31 || form == 32 || form == 34 || form == 35 ||
      (form >= 37 && form <= 41) || form == 43 || form == 45 || form == 46 ||
      form == 47 || form == 48 || form == 51 || form == 52 ||
      (form >= 54 && form < 64 && form != 61 && form != 63) || form == 64 ||
      form == 65 || form == 66 || form == 69 || form >= 70;
  shell_dep_graph_t graph = {};
  shell_dep_error_t graph_error =
      shell_dep_graph_parse(input, strlen(input), nullptr, nullptr, &graph);
  if (graph_error != SHELL_DEP_OK || !shell_dep_graph_validate(&graph).valid) {
    fprintf(stderr, "descriptor move graph oracle %u (error %d): %s\n",
            selector, graph_error, input);
    return 1;
  }
  bool actual = false;
  unsigned routes = 0;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const auto &edge = graph.edges[i];
    if (!internal_graph_relation(graph, edge))
      continue;
    bool reads = form == 19 || form == 27 || (form >= 34 && form <= 36) ||
                 form == 38 || form == 58 || form == 60;
    if (edge.type != (reads ? SHELL_EDGE_READ : SHELL_EDGE_WRITE))
      continue;
    const auto &owner = graph.nodes[reads ? edge.to : edge.from];
    const auto &file = graph.nodes[reads ? edge.from : edge.to];
    if (file.type == SHELL_NODE_FD)
      continue;
    const char *command = form == 64                               ? "\"$cmd\""
                          : form == 65                             ? "command"
                          : form == 68                             ? "builtin"
                          : reads                                  ? "cat"
                          : form == 61                             ? "/bin/echo"
                          : form == 21 || form == 45 || form >= 73 ? "printf"
                                                                   : "echo";
    if (owner.type == SHELL_NODE_CMD && owner.cmd.token_count &&
        owner.cmd.token_lens[0] == strlen(command) &&
        !memcmp(owner.cmd.tokens[0], command, strlen(command))) {
      bool expected =
          file.type == SHELL_NODE_DOC && file.doc.kind == SHELL_DOC_FILE &&
          file.doc.path_len == strlen("/tmp/move-fuzz") &&
          !memcmp(file.doc.path, "/tmp/move-fuzz", file.doc.path_len);
      actual |= expected;
      if (form >= 16) {
        bool first =
            (form == 16 || form == 21) && file.type == SHELL_NODE_DOC &&
            file.doc.kind == SHELL_DOC_FILE &&
            file.doc.path_len == strlen("/tmp/move-first") &&
            !memcmp(file.doc.path, "/tmp/move-first", file.doc.path_len);
        bool unchanged =
            (form == 57 || form == 72) && file.type == SHELL_NODE_DOC &&
            file.doc.kind == SHELL_DOC_FILE &&
            file.doc.path_len == strlen("/tmp/move-pad") &&
            !memcmp(file.doc.path, "/tmp/move-pad", file.doc.path_len);
        if ((!expected && !first && !unchanged) ||
            (reads ? edge.target_fd : edge.source_fd) != (reads ? 0u : 1u))
          return 1;
        routes++;
      }
    }
  }
  unsigned expected_routes =
      expected_route
          ? (form == 16 || form == 21 || form == 57 || form == 72 ? 2u : 1u)
          : 0u;
  if (actual != expected_route || (form >= 16 && routes != expected_routes)) {
    fprintf(stderr, "descriptor move oracle %u: %s\n", selector, input);
    return 1;
  }
  shell_processed_commands_t processed = {};
  if (shell_process_commands(input, strlen(input), nullptr, &processed) !=
      SHELL_PROCESS_OK) {
    fprintf(stderr, "descriptor move processor oracle %u: %s\n", selector,
            input);
    return 1;
  }
  shell_processed_commands_free(&processed);
  return 0;
}

static int test_generated_descriptor_move(uint8_t selector) {
  char input[512];
  descriptor_move_source(selector, input);
  return test_descriptor_move(selector, input);
}

static int test_generated_resolved_depgraph(uint8_t selector, bool truncate) {
  static const char *sources[] = {
      "echo \"$V\"",
      "echo \"$(cat <\"$IN\")\"",
      "{ { cat; }; } <\"$IN\"",
      "false && cat <\"$IN\"; true || echo \"$V\"",
      "maybe && cat <\"$IN\" || echo \"$V\"",
      "cat $(<\"$IN\") | cat",
      "cat < <(cat <\"$IN\")",
      "{ echo \"$V\"; } > >(cat <\"$IN\")",
  };
  const char *source = sources[selector % 8];
  return test_resolved_depgraph(source, strlen(source), "/workspace",
                                selector / 8, truncate);
}

static int test_depgraph(const char *input, size_t length, const char *cwd) {
  static const shell_dep_limits_t limits[] = {
      SHELL_DEP_LIMITS_DEFAULT,
      {0, 0, 0, 2, nullptr, 0},
      {4, 4, 2, 32, nullptr, 0},
      {SHELL_DEP_MAX_NODES, SHELL_DEP_MAX_EDGES, SHELL_DEP_MAX_TOKENS, 1,
       nullptr, 0},
      {SHELL_DEP_MAX_NODES, SHELL_DEP_MAX_EDGES, SHELL_DEP_MAX_TOKENS, 2,
       nullptr, 0},
      {SHELL_DEP_MAX_NODES, SHELL_DEP_MAX_EDGES, SHELL_DEP_MAX_TOKENS,
       SHELL_DEP_CWD_BUF_SIZE - 1, nullptr, 0},
      {SHELL_DEP_MAX_NODES, SHELL_DEP_MAX_EDGES, SHELL_DEP_MAX_TOKENS,
       SHELL_DEP_CWD_BUF_SIZE, nullptr, 0},
  };
  for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
    shell_dep_graph_t graph = {};
    shell_dep_error_t error =
        shell_dep_graph_parse(input, length, cwd, &limits[i], &graph);
    if (validate_depgraph(input, length, error, &graph, &limits[i]))
      return 1;
    if (i == 0) {
      /* The supplied path consumes the same strict parse as the public path.
       * Compare real results, not arbitrary source/metadata combinations. */
      const shell_limits_t strict = {SHELL_MAX_SUBCOMMANDS, true, nullptr, 0};
      shell_parse_result_t fast = {};
      shell_error_t fast_error =
          shell_parse_fast(input, length, &strict, &fast);
      if (fast_error == SHELL_OK || fast_error == SHELL_ETRUNC) {
        shell_parse_result_t unchanged;
        /* A memcpy snapshot preserves even padding for this immutability
         * check; independently constructed metadata uses field comparison. */
        memcpy(&unchanged, &fast, sizeof(unchanged));
        shell_dep_limits_t effective;
        if (!fuzz_dep_limits(&limits[i], &effective))
          return 1;
        shell_dep_graph_t supplied = {};
        shell_dep_error_t supplied_error = shell_dep_graph_parse_with_fast(
            input, length, cwd, &effective, &fast, &supplied);
        if (supplied_error != error ||
            validate_depgraph(input, length, supplied_error, &supplied,
                              &limits[i]) ||
            supplied.node_count != graph.node_count ||
            supplied.edge_count != graph.edge_count ||
            supplied.status != graph.status ||
            supplied.cwd_buf.len != graph.cwd_buf.len ||
            memcmp(&fast, &unchanged, sizeof(fast)) != 0 ||
            !shellsplit_test_graph_equal(&supplied, &graph))
          return 1;
      }
    }
  }
  return 0;
}

// Test full parser
static int test_full_parser(const char *input, size_t length) {
  shell_command_t *commands = NULL;
  size_t command_count = 0;

  shell_tokenize_status_t status =
      shell_tokenize_commands(input, strlen(input), &commands, &command_count);
  bool success = status == SHELL_TOKENIZE_OK;

  if (!success) {
    if (g_verbose && (commands != NULL || command_count != 0))
      fprintf(
          stderr,
          "full parser retained rejected output: status=%d commands=%p/%zu\n",
          status, (void *)commands, command_count);
    return commands != NULL || command_count != 0;
  }

  if ((commands == NULL) != (command_count == 0)) {
    if (g_verbose)
      fprintf(stderr, "full parser pointer/count mismatch: %p/%zu\n",
              (void *)commands, command_count);
    shell_commands_free(commands, command_count);
    return 1;
  }

  if (commands) {
    for (size_t i = 0; i < command_count; i++) {
      shell_command_t *cmd = &commands[i];
      if (cmd->start_pos > length || cmd->end_pos < cmd->start_pos ||
          cmd->end_pos > length ||
          (cmd->tokens == NULL) != (cmd->token_count == 0)) {
        if (g_verbose)
          fprintf(stderr,
                  "full parser invalid command range: %zu..%zu tokens=%p/%zu\n",
                  cmd->start_pos, cmd->end_pos, (void *)cmd->tokens,
                  cmd->token_count);
        shell_commands_free(commands, command_count);
        return 1;
      }
      for (size_t j = 0; j < cmd->token_count; j++) {
        const shell_token_t *tok = &cmd->tokens[j];
        if (tok->type < SHELL_TOKEN_COMMAND ||
            tok->type >= SHELL_TOKEN_TYPE_COUNT || tok->position > length ||
            tok->length > length - tok->position ||
            tok->start != input + tok->position) {
          if (g_verbose)
            fprintf(stderr,
                    "\n=== FULL PARSER ERROR: invalid token range/type ===\n");
          shell_commands_free(commands, command_count);
          return 1;
        }
      }
    }
    shell_commands_free(commands, command_count);
  }

  return 0;
}

/* The public iterator preserves every lexical separator. The full command
 * model deliberately elides physical newlines while a list is waiting for its
 * next stage, so compare it to the iterator's semantic-token subsequence. */
static bool tokenizer_token_is_newline(const shell_token_t &token) {
  return token.type == SHELL_TOKEN_SEMICOLON && token.length != 0 &&
         token.start[0] == '\n';
}

static bool tokenizer_token_starts_command(const shell_token_t &token) {
  switch (token.type) {
  case SHELL_TOKEN_COMMAND:
  case SHELL_TOKEN_ARGUMENT:
  case SHELL_TOKEN_SUBSHELL:
  case SHELL_TOKEN_VARIABLE:
  case SHELL_TOKEN_VARIABLE_QUOTED:
  case SHELL_TOKEN_SPECIAL_VAR:
  case SHELL_TOKEN_ARITHMETIC:
  case SHELL_TOKEN_GLOB:
  case SHELL_TOKEN_ANSI_C_QUOTED:
  case SHELL_TOKEN_EXTGLOB:
  case SHELL_TOKEN_ARRAY_ASSIGNMENT:
  case SHELL_TOKEN_HEREDOC:
  case SHELL_TOKEN_HERESTRING:
  case SHELL_TOKEN_REDIRECT_IN:
  case SHELL_TOKEN_REDIRECT_OUT:
  case SHELL_TOKEN_REDIRECT_ERR:
  case SHELL_TOKEN_REDIRECT_APPEND:
  case SHELL_TOKEN_REDIRECT_READ_WRITE:
  case SHELL_TOKEN_REDIRECT_CLOBBER:
  case SHELL_TOKEN_REDIRECT_BOTH:
  case SHELL_TOKEN_REDIRECT_BOTH_APPEND:
  case SHELL_TOKEN_PROCESS_SUB:
    return true;
  default:
    return false;
  }
}

static bool tokenizer_token_is_list_operator(const shell_token_t &token) {
  return token.type == SHELL_TOKEN_PIPE ||
         token.type == SHELL_TOKEN_PIPE_BOTH ||
         token.type == SHELL_TOKEN_SEMICOLON || token.type == SHELL_TOKEN_AND ||
         token.type == SHELL_TOKEN_OR || token.type == SHELL_TOKEN_BACKGROUND;
}

static bool tokenizer_token_is_redirect(const shell_token_t &token) {
  switch (token.type) {
  case SHELL_TOKEN_REDIRECT_IN:
  case SHELL_TOKEN_REDIRECT_OUT:
  case SHELL_TOKEN_REDIRECT_ERR:
  case SHELL_TOKEN_REDIRECT_APPEND:
  case SHELL_TOKEN_REDIRECT_READ_WRITE:
  case SHELL_TOKEN_REDIRECT_CLOBBER:
  case SHELL_TOKEN_REDIRECT_BOTH:
  case SHELL_TOKEN_REDIRECT_BOTH_APPEND:
  case SHELL_TOKEN_HEREDOC:
  case SHELL_TOKEN_HERESTRING:
    return true;
  default:
    return false;
  }
}

/* The iterator exposes a standalone escaped physical line ending so list
 * validation can discard it before classifying the token that follows. The
 * structured tokenizer intentionally omits this grammar-only token from its
 * command records, so the iterator/reference comparison must do likewise. */
static bool tokenizer_token_is_line_continuation(const shell_token_t &token) {
  if (token.type != SHELL_TOKEN_ARGUMENT || !token.is_escaped ||
      token.length < 2 || token.start[0] != '\\')
    return false;
  return token.start[1] == '\n' && token.length == 2;
}

static int test_tokenizer_state(const char *input, size_t length) {
  shell_tokenizer_state_t state = {};
  shell_tokenizer_init(&state, input, length, NULL);
  bool unsupported = shell_tokenizer_has_unsupported_semantics(input, length);

  size_t steps = 0;
  size_t previous_end = 0;
  std::vector<shell_token_t> iterated;
  bool expect_command = true;
  size_t stage_token = 0;
  bool document_only = true;
  bool has_heredoc = false;
  bool terminated = false;
  while (steps++ <= length + 32) {
    shell_token_t token = {};
    const bool group_command_position =
        state.lexical_command_position && !state.lexical_redirect_operand;
    bool produced = shell_tokenizer_next(&state, &token);
    if (!produced || token.type == SHELL_TOKEN_END) {
      terminated = true;
      break;
    }
    if (token.type < SHELL_TOKEN_COMMAND ||
        token.type >= SHELL_TOKEN_TYPE_COUNT || token.position > length ||
        token.length > length - token.position ||
        token.start != input + token.position || token.position < previous_end)
      return 1;
    if (tokenizer_token_is_line_continuation(token)) {
      previous_end = token.position + token.length;
      continue;
    }
    /* A declaration-only stage can contain several document/redirect tokens.
     * Its closing newline is structural; an ordinary command's newline is a
     * retained list token. Track the whole lexical stage independently of the
     * structured records so dropping an ordinary word cannot make it qualify
     * as an argv-less stage. */
    if (has_heredoc && document_only && tokenizer_token_is_newline(token)) {
      has_heredoc = false;
      expect_command = true;
      stage_token = iterated.size();
      previous_end = token.position + token.length;
      continue;
    }
    /* The iterator reports a standalone `!` lexically. The allocating
     * tokenizer resolves its context: after a command has begun it is argv,
     * not a pipeline negator. Compare the same contextual token stream. */
    if (token.type == SHELL_TOKEN_PIPE_NEGATE && !expect_command)
      token.type = SHELL_TOKEN_ARGUMENT;
    if (token.type == SHELL_TOKEN_GROUP_START) {
      /* The allocating tokenizer treats only command-position openers as
       * structural. An opener appended to an ordinary word or redirect
       * pathname is diagnostic input and must not hide the retained newline
       * that terminates the preceding record. Capture the lexical state
       * before advancing because the iterator updates it for the opener. */
      tokenizer_structural_prefix_span prefix = {};
      bool modifier_only = group_command_position && !expect_command &&
                           stage_token < iterated.size() &&
                           tokenizer_structural_prefix_starts_at(
                               input, length, iterated[stage_token], &prefix) &&
                           prefix.end == token.position;
      /* The allocating API flattens group punctuation without discarding an
       * ordinary diagnostic word already in this stage (for example foo in
       * `foo() { }`). Only a proved compound-owned modifier prefix starts a
       * fresh empty inner record here. Track its first token directly, not by
       * rescanning all preceding lexical tokens at each opener. */
      if (group_command_position && (expect_command || modifier_only)) {
        expect_command = true;
        stage_token = iterated.size();
        document_only = true;
        has_heredoc = false;
      }
    } else if (token.type == SHELL_TOKEN_GROUP_END) {
      /* A trailing group redirect remains owned by its compound record. */
      document_only = false;
    } else {
      if (!(expect_command && tokenizer_token_is_newline(token)))
        iterated.push_back(token);
      if (tokenizer_token_starts_command(token))
        expect_command = false;
      if (tokenizer_token_is_list_operator(token)) {
        expect_command = true;
        stage_token = iterated.size();
        document_only = true;
        has_heredoc = false;
      } else {
        document_only = document_only && tokenizer_token_is_redirect(token);
        has_heredoc = has_heredoc || token.type == SHELL_TOKEN_HEREDOC;
      }
    }
    previous_end = token.position + token.length;
  }
  if (!terminated)
    return 1;

  if (unsupported && !tokenizer_unsupported_semantics_rejected(input, length))
    return 1;

  shell_command_t *commands = NULL;
  size_t command_count = 0;
  bool syntax_valid = shell_tokenizer_list_syntax_valid(input, length);
  /* List grammar alone is not complete lexical validity: the iterator keeps
   * an unfinished quote/document for diagnostics, while the allocating API
   * rejects these specific unfinished lexical states. */
  bool lexical_complete = !state.in_quotes && state.brace_depth == 0 &&
                          state.brace_group_depth == 0 && !state.heredoc_error;
  shell_tokenize_status_t full_status =
      shell_tokenize_commands(input, length, &commands, &command_count);
  if (full_status != SHELL_TOKENIZE_OK) {
    bool outputs_cleared = commands == NULL && command_count == 0;
    shell_commands_free(commands, command_count);
    /* Malformed input has no complete command stream to reconcile. A valid
     * source with visible tokens may only take this escape for the documented
     * output-capacity limit. Comment/continuation-only source has no command
     * to return and may be rejected with EParse. All other valid grammar,
     * including unsupported semantics, must yield diagnostic records. */
    return outputs_cleared && (!syntax_valid ||
                               (full_status == SHELL_TOKENIZE_EPARSE &&
                                (!lexical_complete || iterated.empty())) ||
                               full_status == SHELL_TOKENIZE_EOVERFLOW)
               ? 0
               : 1;
  }
  if (!syntax_valid) {
    shell_commands_free(commands, command_count);
    return 1;
  }
  if (command_count == 0) {
    shell_commands_free(commands, command_count);
    return unsupported || !iterated.empty() ? 1 : 0;
  }
  /* Unsupported semantics do not excuse a disappearing diagnostic token.
   * Reconcile both streams with the same source-proven structural omissions. */
  bool streams_match = tokenizer_iterated_matches_structured(
      input, length, iterated, commands, command_count);
  if (!streams_match && g_verbose) {
    for (const shell_token_t &token : iterated)
      fprintf(stderr, "lexical token: type=%d span=%zu+%zu\n", token.type,
              token.position, token.length);
    for (size_t command = 0; command < command_count; command++) {
      fprintf(stderr, "structured command: span=%zu..%zu\n",
              commands[command].start_pos, commands[command].end_pos);
      for (size_t index = 0; index < commands[command].token_count; index++) {
        const shell_token_t &token = commands[command].tokens[index];
        fprintf(stderr, "structured token: type=%d span=%zu+%zu\n", token.type,
                token.position, token.length);
      }
    }
  }
  shell_commands_free(commands, command_count);
  return streams_match ? 0 : 1;
}

static int test_interop(const char *input, size_t length) {
  shell_interop_handle_t *handle = shell_interop_new();
  if (!handle)
    return 0;

  size_t count = 0;
  shell_error_t status = shell_interop_parse(handle, input, length, &count);
  if (status == SHELL_OK) {
    if (shell_interop_subcommand_count(handle) != count)
      goto fail;
    for (size_t i = 0; i <= count; i++) {
      shell_range_t range{};
      bool has_range = shell_interop_subcommand_range(handle, i, &range);
      char *text = shell_interop_subcommand_dup(handle, i);
      if (i == count) {
        if (has_range || text != NULL)
          goto fail;
      } else {
        if (!has_range || range.start > length ||
            range.len > length - range.start || !text ||
            strlen(text) != range.len) {
          goto fail;
        }
        free(text);
      }
    }
  } else if (shell_interop_subcommand_count(handle) != 0 ||
             shell_interop_subcommand_dup(handle, 0) != NULL) {
    goto fail;
  }

  {
    char features[256];
    size_t written = 0;
    if (shell_interop_format_features(UINT32_MAX, features, sizeof(features),
                                      &written) != SHELL_OK ||
        written == 0 ||
        !shell_interop_command_type_name(
            static_cast<shell_cmd_type_t>(UINT16_MAX)))
      goto fail;
  }
  /* Reuse the handle after both a successful and an invalid/empty parse. */

  shell_interop_free(handle);
  return 0;

fail:
  shell_interop_free(handle);
  return 1;
}

static int test_abstraction(const char *input, size_t length) {

  (void)shell_classify_raw_token(input, length);
  shell_abstract_command_t *command = nullptr;
  if (shell_abstract_command_parse(input, length, &command) !=
      SHELL_ABSTRACT_OK)
    command = nullptr;
  bool success = command != NULL;
  if (!success)
    return command != NULL;
  if (!command || !command->original || !command->display_text) {
    shell_abstract_command_free(command);
    return 1;
  }

  size_t count = 0;
  shell_abstract_element_t *const *elements =
      shell_abstract_command_get_mutable_elements(command, &count);
  if (count > 0 && !elements) {
    shell_abstract_command_free(command);
    return 1;
  }

  if (shell_abstract_command_get_element(command, count) != NULL ||
      shell_abstract_command_find_element(command, "__missing__") != NULL) {
    shell_abstract_command_free(command);
    return 1;
  }

  char home[] = "HOME=/tmp";
  char *env[] = {home, NULL};
  for (size_t i = 0; i < count; i++) {
    if (!elements[i] || elements[i]->start > length ||
        elements[i]->end < elements[i]->start || elements[i]->end > length) {
      shell_abstract_command_free(command);
      return 1;
    }
    if (elements[i]->abstraction &&
        shell_abstract_command_find_element(
            command, elements[i]->abstraction) != elements[i]) {
      shell_abstract_command_free(command);
      return 1;
    }
  }
  shell_runtime_context_t contexts[] = {{env, (char *)"/tmp", false},
                                        {env, NULL, false},
                                        {env, (char *)".", true},
                                        {NULL, (char *)"/tmp", true}};
  for (shell_runtime_context_t &context : contexts) {
    for (size_t i = 0; i < count; i++) {
      char *expanded = shell_abstract_element_expand(elements[i], &context);
      if (expanded)
        (void)shell_path_category_from_path(expanded);
      free(expanded);
    }
    if (!shell_abstract_command_expand(command, &context)) {
      shell_abstract_command_free(command);
      return 1;
    }
  }
  shell_abstract_command_free(command);
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
  double first = shell_rpe_ngram_entropy(text, 1);
  if (!isfinite(first) || first != shell_rpe_ngram_entropy(text, 1) ||
      !isfinite(shell_rpe_ngram_entropy(text, 2)) ||
      !isfinite(shell_rpe_conditional_entropy(text)) ||
      !isfinite(shell_rpe_permutation_entropy(text, permutations, 1)) ||
      !isfinite(
          shell_rpe_permutation_conditional_entropy(text, permutations)) ||
      !isfinite(shell_rpe_relative_entropy_ratio(text, permutations, 2)) ||
      !isfinite(shell_rpe_relative_conditional_entropy(text, permutations)))
    return 1;
  (void)shell_env_screener_calculate_entropy(text);
  (void)shell_env_screener_is_secret_pattern(text);
  (void)shell_env_screener_is_whitelisted(text);
  (void)shell_env_screener_combined_score_name(NULL, text);
  (void)shell_env_screener_combined_score_name("FUZZ_KEY", text);
  (void)shell_env_screener_looks_like_path(text);
  (void)shell_env_screener_looks_like_base64(text);
  double suffix = 0.0;
  (void)shell_env_screener_check_secret_prefix(text, &suffix);
  for (size_t capacity : {size_t{0}, size_t{1}, size_t{8}}) {
    size_t indices[8] = {0};
    size_t count = 0;
    shell_env_screener_status_t status =
        shell_env_screener_scan(indices, capacity, &count, 0.5, 8);
    if (status != SHELL_ENV_SCREENER_OK &&
        status != SHELL_ENV_SCREENER_BUFFER_TOO_SMALL)
      return 1;
    if (status == SHELL_ENV_SCREENER_OK && count > capacity)
      return 1;
  }
  return 0;
}

// Test transformer
static int test_transformer(const char *input, size_t input_length) {
  shell_transformed_command_t **transformed_cmds = NULL;
  size_t transformed_count = 0;

  static const shell_transform_limits_t limits = {1u << 20, 4u << 20};
  shell_transform_status_t status = shell_transform_command_line(
      input, input_length, &limits, &transformed_cmds, &transformed_count);
  bool success = status == SHELL_TRANSFORM_OK;

  // Clean up on failure
  if (!success) {
    shell_transformed_command_list_free(transformed_cmds, transformed_count);
    return 0;
  }

  if ((transformed_cmds == NULL) != (transformed_count == 0)) {
    shell_transformed_command_list_free(transformed_cmds, transformed_count);
    return 1;
  }

  if (transformed_cmds) {
    for (size_t i = 0; i < transformed_count; i++) {
      shell_transformed_command_t *tcmd = transformed_cmds[i];
      if (!tcmd || !tcmd->original_command || !tcmd->display_text ||
          (tcmd->tokens == NULL) != (tcmd->token_count == 0)) {
        shell_transformed_command_list_free(transformed_cmds,
                                            transformed_count);
        return 1;
      }

      for (size_t j = 0; j < tcmd->token_count; j++) {
        const shell_transformed_token_t *tok = &tcmd->tokens[j];
        bool transformed = tok->type != SHELL_TRANSFORM_NONE;
        if (tok->type < SHELL_TRANSFORM_NONE ||
            tok->type > SHELL_TRANSFORM_REDIRECTION || !tok->original ||
            !tok->transformed ||
            (!transformed && tok->transformed != tok->original) ||
            (transformed && tok->transformed == tok->original) ||
            (transformed && !tok->is_shell_construct)) {
          if (g_verbose)
            fprintf(stderr, "\n=== TRANSFORMER ERROR: invalid token ===\n");
          shell_transformed_command_list_free(transformed_cmds,
                                              transformed_count);
          return 1;
        }
      }
    }
    shell_transformed_command_list_free(transformed_cmds, transformed_count);
  }

  return 0;
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

static bool
processed_groups_match_fast(const shell_parse_result_t *fast,
                            const shell_processed_commands_t *result) {
  if (fast->group_count != result->group_count ||
      (result->groups == NULL) != (result->group_count == 0))
    return false;
  for (uint32_t i = 0; i < fast->group_count; i++) {
    const shell_group_t *source = &fast->groups[i];
    const shell_group_t *processed = &result->groups[i];
    if (source->start != processed->start || source->end != processed->end ||
        source->parent != processed->parent ||
        source->kind != processed->kind ||
        processed->first_command > result->command_count ||
        processed->command_count >
            result->command_count - processed->first_command)
      return false;
  }
  return true;
}

static bool
processed_argv_matches_sequence(const shell_processed_commands_t &processed,
                                const void *sequence, size_t sequence_length,
                                size_t count) {
  if (!sequence || processed.command_count != count)
    return false;
  shell_netstring_iter_t records;
  shell_netstring_view_t record = {};
  if (shell_netstring_iter_init(&records, sequence, sequence_length) !=
      SHELL_NETSTRING_OK)
    return false;
  for (size_t command = 0; command < count; command++) {
    shell_netstring_buffer_t argv = {};
    bool matches =
        shell_netstring_iter_next(&records, &record) == SHELL_NETSTRING_OK &&
        shell_render_netargv_buffer(&processed.commands[command], nullptr,
                                    &argv) == SHELL_PROCESS_OK &&
        argv.length == record.payload_length &&
        memcmp(argv.data, record.payload, argv.length) == 0;
    if (!matches && g_verbose)
      fprintf(stderr,
              "processor argv mismatch at %zu: structured=%.*s "
              "sequence=%.*s\n",
              command, (int)argv.length,
              argv.data ? (const char *)argv.data : "",
              (int)record.payload_length,
              record.payload ? (const char *)record.payload : "");
    shell_netstring_buffer_free(&argv);
    if (!matches)
      return false;
  }
  return shell_netstring_iter_next(&records, &record) == SHELL_NETSTRING_DONE;
}

// Test processor metadata and canonical sequence rendering together.
static int test_processor(const char *input, size_t input_length) {
  shell_command_info_t *infos = NULL;
  size_t command_count = 0;
  static const shell_process_limits_t limits = {1u << 20, 4u << 20, 0};
  shell_process_status_t status = shell_process_command(
      input, input_length, &limits, &infos, &command_count);
  bool success = status == SHELL_PROCESS_OK;
  shell_netstring_buffer_t sequence = {};
  size_t sequence_count = 0;
  bool has_shell_features = false;
  shell_process_status_t extracted_status = shell_build_netargv_sequence_buffer(
      input, input_length, &limits, &sequence, &sequence_count,
      &has_shell_features);
  bool extracted = extracted_status == SHELL_PROCESS_OK;

  /* The flat processor preserves an empty lexical result for diagnostics,
   * whereas a canonical netargv sequence requires source that contains a
   * command. This is an intentional semantic boundary, not a differential
   * parser failure. */
  if (success && command_count == 0 && !extracted &&
      extracted_status == SHELL_PROCESS_EINPUT && sequence.data == NULL &&
      sequence_count == 0 && !has_shell_features) {
    shell_command_infos_free(infos, command_count);
    return 0;
  }

  /* The legacy flat processor preserves lexically useful but semantically
   * incomplete records for diagnostic callers.  Canonical sequence builders
   * reject an unrepresentable lexical record, while the structured processor
   * may either reject the source or retain only the executable simple-command
   * ranges it can represent.  The latter result is independently canonical;
   * the APIs need not make the same choice for malformed surrounding syntax. */
  if (success && !extracted && extracted_status == SHELL_PROCESS_EPARSE) {
    shell_processed_commands_t processed = {};
    shell_process_status_t processed_status =
        shell_process_commands(input, input_length, &limits, &processed);
    bool structured_canonical =
        processed_status == SHELL_PROCESS_OK &&
        (processed.commands != NULL || processed.command_count == 0);
    for (size_t i = 0; structured_canonical && i < processed.command_count;
         i++) {
      shell_netstring_buffer_t netargv = {};
      structured_canonical =
          processed.commands[i].command_token_count != 0 &&
          shell_render_netargv_buffer(&processed.commands[i], &limits,
                                      &netargv) == SHELL_PROCESS_OK &&
          netargv.data != NULL;
      shell_netstring_buffer_free(&netargv);
    }
    bool canonical_boundary =
        (processed_status == SHELL_PROCESS_EPARSE &&
         processed.commands == NULL && processed.command_count == 0 &&
         processed.groups == NULL && processed.group_count == 0 &&
         processed.group_io_ops == NULL && processed.group_io_op_count == 0) ||
        structured_canonical;
    if (!canonical_boundary && g_verbose)
      fprintf(stderr,
              "processor canonical-boundary mismatch: flat=%d/%zu "
              "sequence=%d/%zu structured=%d/%zu groups=%zu ops=%zu\n",
              status, command_count, extracted_status, sequence_count,
              processed_status, processed.command_count, processed.group_count,
              processed.group_io_op_count);
    shell_processed_commands_free(&processed);
    shell_command_infos_free(infos, command_count);
    shell_netstring_buffer_free(&sequence);
    return canonical_boundary ? 0 : 1;
  }

  /* The flat processor retains arbitrarily many lexical records for
   * diagnostics, while canonical sequence builders use the fixed-size
   * semantic model. Confirm a model-capacity rejection through the
   * structured API instead of requiring the two surfaces to agree. */
  if (success && !extracted &&
      extracted_status == SHELL_PROCESS_EOUTPUT_LIMIT) {
    shell_processed_commands_t processed = {};
    shell_process_status_t processed_status =
        shell_process_commands(input, input_length, &limits, &processed);
    bool canonical_capacity =
        processed_status == SHELL_PROCESS_EOUTPUT_LIMIT &&
        processed.commands == NULL && processed.command_count == 0 &&
        processed.groups == NULL && processed.group_count == 0 &&
        processed.group_io_ops == NULL && processed.group_io_op_count == 0 &&
        sequence.data == NULL && sequence_count == 0 && !has_shell_features;
    if (!canonical_capacity && g_verbose)
      fprintf(stderr,
              "processor canonical-capacity mismatch: flat=%d/%zu "
              "sequence=%d/%zu structured=%d/%zu groups=%zu ops=%zu\n",
              status, command_count, extracted_status, sequence_count,
              processed_status, processed.command_count, processed.group_count,
              processed.group_io_op_count);
    shell_processed_commands_free(&processed);
    shell_command_infos_free(infos, command_count);
    shell_netstring_buffer_free(&sequence);
    return canonical_capacity ? 0 : 1;
  }

  if (success != extracted) {
    if (g_verbose)
      fprintf(stderr,
              "processor success mismatch: flat=%d/%zu sequence=%d/%zu\n",
              status, command_count, extracted_status, sequence_count);
    shell_command_infos_free(infos, command_count);
    shell_netstring_buffer_free(&sequence);
    return 1;
  }
  if (!success) {
    if (status != extracted_status &&
        !(status == SHELL_PROCESS_EPARSE &&
          extracted_status == SHELL_PROCESS_EPARSE)) {
      if (g_verbose)
        fprintf(stderr, "processor rejection mismatch: flat=%d sequence=%d\n",
                status, extracted_status);
      shell_command_infos_free(infos, command_count);
      shell_netstring_buffer_free(&sequence);
      return 1;
    }
    shell_command_infos_free(infos, command_count);
    shell_netstring_buffer_free(&sequence);
    return 0;
  }

  if ((infos == NULL) != (command_count == 0) || (sequence.data == NULL) ||
      sequence_count != command_count) {
    if (g_verbose)
      fprintf(
          stderr, "processor output mismatch: infos=%p/%zu sequence=%p/%zu\n",
          (void *)infos, command_count, (void *)sequence.data, sequence_count);
    shell_command_infos_free(infos, command_count);
    shell_netstring_buffer_free(&sequence);
    return 1;
  }

  bool expected_features = false;
  if (infos) {
    for (size_t i = 0; i < command_count; i++) {
      shell_command_info_t *info = &infos[i];
      shell_netstring_buffer_t netargv = {};
      if (!info->original_command ||
          (info->shell_tokens == NULL) != (info->shell_token_count == 0) ||
          (info->command_tokens == NULL) != (info->command_token_count == 0) ||
          !tokens_refer_to_owned_command(info->shell_tokens,
                                         info->shell_token_count,
                                         info->original_command) ||
          !tokens_refer_to_owned_command(info->command_tokens,
                                         info->command_token_count,
                                         info->original_command) ||
          shell_render_netargv_buffer(info, &limits, &netargv) !=
              SHELL_PROCESS_OK) {
        shell_netstring_buffer_free(&netargv);
        shell_command_infos_free(infos, command_count);
        shell_netstring_buffer_free(&sequence);
        return 1;
      }
      shell_netstring_buffer_free(&netargv);
      expected_features |= shell_command_info_has_dangerous_features(info);
    }
  }

  /* shell_process_command permits a syntactically valid comment-only input
   * with no command records; the descriptor-bearing API deliberately treats
   * that as no command line. Its result contract is exercised for every
   * material command below. */
  if (command_count == 0) {
    shell_command_infos_free(infos, command_count);
    shell_netstring_buffer_free(&sequence);
    return expected_features != has_shell_features;
  }

  shell_parse_result_t fast = {};
  if (shell_parse_fast(input, input_length, NULL, &fast) == SHELL_OK) {
    /* Group delimiters are intentionally absent from each flattened legacy
     * command record, but remain shell syntax on the canonical call-wide
     * result. Include that source-level fact in this differential oracle. */
    for (size_t i = 0; i < fast.count; i++)
      expected_features |= (fast.cmds[i].features & SHELL_FEAT_GROUP) != 0;
    shell_processed_commands_t processed = {};
    shell_process_status_t processed_status =
        shell_process_commands(input, input_length, &limits, &processed);
    bool descriptor_outputs_cleared =
        processed.commands == NULL && processed.command_count == 0 &&
        processed.groups == NULL && processed.group_count == 0 &&
        processed.group_io_ops == NULL && processed.group_io_op_count == 0;
    /* The flat processor deliberately preserves the full tokenizer's
     * permissive lexical records for diagnostics. The descriptor-bearing API
     * must reject and clear a construct whose compound semantics it cannot
     * model, even when that flat view remains available. */
    bool semantic_rejection = status == SHELL_PROCESS_OK &&
                              processed_status == SHELL_PROCESS_EPARSE &&
                              descriptor_outputs_cleared;
    /* The flat API preserves lexical structural records, while the descriptor
     * API exposes only executable simple commands. Group source spans, kind,
     * and parent stay stable, but command intervals are remapped to the
     * retained command array and must not be compared byte-for-byte. */
    if ((processed_status != status && !semantic_rejection) ||
        (processed_status == SHELL_PROCESS_OK &&
         ((processed.commands == NULL) != (processed.command_count == 0) ||
          !processed_groups_match_fast(&fast, &processed) ||
          !processed_argv_matches_sequence(processed, sequence.data,
                                           sequence.length, sequence_count)))) {
      if (g_verbose)
        fprintf(stderr,
                "processor descriptor mismatch: input=%.*s process=%d/%zu "
                "processed=%d/%zu groups=%zu fast-groups=%u\n",
                (int)input_length, input, status, command_count,
                processed_status, processed.command_count,
                processed.group_count, fast.group_count);
      shell_processed_commands_free(&processed);
      shell_command_infos_free(infos, command_count);
      shell_netstring_buffer_free(&sequence);
      return 1;
    }
    shell_processed_commands_free(&processed);
  }

  shell_command_infos_free(infos, command_count);
  shell_netstring_buffer_free(&sequence);
  if (expected_features != has_shell_features && g_verbose)
    fprintf(stderr,
            "processor feature mismatch: input=%.*s flat=%d sequence=%d\n",
            (int)input_length, input, expected_features, has_shell_features);
  return expected_features != has_shell_features;
}

static int test_output_limits(const char *input, size_t input_length) {
  static const shell_process_limits_t process_limits = {8, 16, 0};
  static const shell_transform_limits_t transform_limits = {8, 16};

  shell_command_info_t *infos = NULL;
  size_t info_count = 0;
  shell_process_status_t process_status = shell_process_command(
      input, input_length, &process_limits, &infos, &info_count);
  if (process_status != SHELL_PROCESS_OK &&
      process_status != SHELL_PROCESS_EINPUT &&
      process_status != SHELL_PROCESS_EPARSE &&
      process_status != SHELL_PROCESS_ENOMEM &&
      process_status != SHELL_PROCESS_EOVERFLOW &&
      process_status != SHELL_PROCESS_EOUTPUT_LIMIT) {
    shell_command_infos_free(infos, info_count);
    return 1;
  }
  shell_command_infos_free(infos, info_count);

  shell_transformed_command_t **transformed = NULL;
  size_t transformed_count = 0;
  shell_transform_status_t transform_status = shell_transform_command_line(
      input, input_length, &transform_limits, &transformed, &transformed_count);
  if (transform_status != SHELL_TRANSFORM_OK &&
      transform_status != SHELL_TRANSFORM_EINPUT &&
      transform_status != SHELL_TRANSFORM_EPARSE &&
      transform_status != SHELL_TRANSFORM_ENOMEM &&
      transform_status != SHELL_TRANSFORM_EOVERFLOW &&
      transform_status != SHELL_TRANSFORM_EOUTPUT_LIMIT) {
    shell_transformed_command_list_free(transformed, transformed_count);
    return 1;
  }
  shell_transformed_command_list_free(transformed, transformed_count);
  return 0;
}

static uint16_t processed_group_depth(const shell_processed_commands_t *result,
                                      uint16_t group_index) {
  uint16_t depth = 0;
  while (group_index != UINT16_MAX && group_index < result->group_count) {
    depth++;
    group_index = result->groups[group_index].parent;
  }
  return depth;
}

static uint16_t graph_group_depth(const shell_dep_graph_t *graph,
                                  uint32_t group_index) {
  uint16_t depth = 0;
  while (group_index != UINT32_MAX && group_index < graph->node_count) {
    depth++;
    group_index = graph->nodes[group_index].group.parent;
  }
  return depth;
}

static bool
valid_generated_outer_netsequence(const shell_netstring_buffer_t &sequence,
                                  uint32_t expected_count) {
  size_t count = 0;
  return sequence.data != NULL &&
         shell_netstring_validate(sequence.data, sequence.length, &count) ==
             SHELL_NETSTRING_OK &&
         count == expected_count;
}

static bool
valid_generated_netargv_sequence(const shell_netstring_buffer_t &sequence,
                                 uint32_t expected_count) {
  if (!valid_generated_outer_netsequence(sequence, expected_count))
    return false;
  shell_netstring_iter_t iterator = {};
  if (shell_netstring_iter_init(&iterator, sequence.data, sequence.length) !=
      SHELL_NETSTRING_OK)
    return false;
  for (;;) {
    shell_netstring_view_t record = {};
    shell_netstring_status_t status =
        shell_netstring_iter_next(&iterator, &record);
    if (status == SHELL_NETSTRING_DONE)
      return true;
    size_t argument_count = 0;
    if (status != SHELL_NETSTRING_OK ||
        shell_netstring_validate(record.payload, record.payload_length,
                                 &argument_count) != SHELL_NETSTRING_OK ||
        argument_count == 0)
      return false;
  }
}

static bool
generated_artifact_relation_present(const shell_dep_graph_t *graph,
                                    const shell_brace_fuzz_io_t &expected) {
  bool read = expected.kind == SHELL_GROUP_IO_READ_FILE ||
              expected.kind == SHELL_GROUP_IO_HEREDOC ||
              expected.kind == SHELL_GROUP_IO_HERESTRING;
  shell_dep_edge_type_t type = expected.kind == SHELL_GROUP_IO_APPEND_FILE
                                   ? SHELL_EDGE_APPEND
                                   : SHELL_EDGE_WRITE;
  for (uint32_t i = 0; i < graph->edge_count; i++) {
    const shell_dep_edge_t *edge = &graph->edges[i];
    uint32_t group = read ? edge->to : edge->from;
    if ((read ? edge->target_fd : edge->source_fd) != expected.fd ||
        edge->type != (read ? SHELL_EDGE_READ : type) ||
        group >= graph->node_count ||
        graph->nodes[group].type != SHELL_NODE_GROUP ||
        graph_group_depth(graph, group) != expected.group_depth)
      continue;
    return true;
  }
  return false;
}

static int test_generated_brace_case(const uint8_t *data, size_t size,
                                     const char *cwd) {
  shell_brace_fuzz_case_t item = shell_brace_fuzz_case(data, size);
  shell_parse_result_t fast = {};
  shell_error_t fast_error =
      shell_parse_fast(item.command.data(), item.command.size(), NULL, &fast);
  shell_limits_t strict_limits = {SHELL_MAX_SUBCOMMANDS, true, nullptr, 0};
  shell_parse_result_t strict_fast = {};
  shell_error_t strict_error = shell_parse_fast(
      item.command.data(), item.command.size(), &strict_limits, &strict_fast);
  shell_command_t *commands = NULL;
  size_t command_count = 0;
  shell_tokenize_status_t full_error = shell_tokenize_commands(
      item.command.data(), item.command.size(), &commands, &command_count);
  shell_processed_commands_t processed = {};
  shell_process_status_t process_error = shell_process_commands(
      item.command.data(), item.command.size(), NULL, &processed);
  shell_dep_graph_t graph = {};
  shell_dep_error_t dep_error = shell_dep_graph_parse(
      item.command.data(), item.command.size(), cwd, NULL, &graph);

  if (!item.valid) {
    bool failed = fast_error != SHELL_EPARSE ||
                  (!item.tokenizer_tolerates_malformed &&
                   full_error == SHELL_TOKENIZE_OK) ||
                  process_error == SHELL_PROCESS_OK ||
                  dep_error != SHELL_DEP_EPARSE;
    if (failed && g_verbose)
      fprintf(stderr,
              "generated invalid brace case failed: %s (fast=%d full=%d "
              "process=%d dep=%d)\n",
              item.command.c_str(), fast_error, full_error, process_error,
              dep_error);
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    return failed;
  }
  /* Unterminated heredocs are intentionally retained by the permissive
   * tokenizer so callers can report useful source locations, but strict
   * parsing rejects them. Exercise the tolerant surfaces above without
   * imposing an invented semantic graph contract on incomplete source. */
  if (!item.strict_valid) {
    bool failed = fast_error != SHELL_OK || strict_error != SHELL_EPARSE;
    if (failed && g_verbose)
      fprintf(stderr,
              "generated strict-only brace case failed: %s (fast=%d "
              "strict=%d)\n",
              item.command.c_str(), fast_error, strict_error);
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    return failed;
  }

  uint32_t graph_commands = 0;
  uint32_t graph_documents = 0;
  uint32_t graph_reads = 0;
  uint32_t graph_pipes = 0;
  uint32_t graph_writes = 0;
  uint32_t processed_dups = 0;
  uint32_t processed_closes = 0;
  size_t generated_redirect_index = 0;
  uint32_t outer_group = UINT32_MAX;
  for (uint32_t i = 0; i < graph.node_count; i++) {
    graph_commands += graph.nodes[i].type == SHELL_NODE_CMD;
    graph_documents += graph.nodes[i].type == SHELL_NODE_DOC &&
                       (graph.nodes[i].doc.kind == SHELL_DOC_HEREDOC ||
                        graph.nodes[i].doc.kind == SHELL_DOC_HERESTRING);
    if (graph.nodes[i].type == SHELL_NODE_GROUP &&
        graph.nodes[i].group.parent == UINT32_MAX &&
        (outer_group == UINT32_MAX ||
         graph.nodes[i].group.start < graph.nodes[outer_group].group.start))
      outer_group = i;
  }
  bool group_endpoints_valid = outer_group != UINT32_MAX;
  bool operations_valid = true;
  for (size_t i = 0; i < processed.group_io_op_count; i++) {
    const shell_group_io_op_t *op = &processed.group_io_ops[i];
    bool relation = op->kind == SHELL_GROUP_IO_PIPE_INPUT ||
                    op->kind == SHELL_GROUP_IO_PIPE_OUTPUT ||
                    op->kind == SHELL_GROUP_IO_PIPE_OUTPUT_STDERR ||
                    op->kind == SHELL_GROUP_IO_BACKGROUND;
    bool shared_pipeline_operator =
        i > 0 &&
        (processed.group_io_ops[i - 1].kind == SHELL_GROUP_IO_PIPE_OUTPUT ||
         processed.group_io_ops[i - 1].kind ==
             SHELL_GROUP_IO_PIPE_OUTPUT_STDERR) &&
        op->kind == SHELL_GROUP_IO_PIPE_INPUT &&
        processed.group_io_ops[i - 1].source_start == op->source_start &&
        processed.group_io_ops[i - 1].source_end == op->source_end;
    if (op->group_index >= processed.group_count ||
        op->source_start >= op->source_end ||
        (!relation && op->operand_start >= op->operand_end) ||
        (i > 0 && processed.group_io_ops[i - 1].source_end > op->source_start &&
         !shared_pipeline_operator))
      operations_valid = false;
    processed_dups += op->kind == SHELL_GROUP_IO_DUP_FD;
    processed_closes += op->kind == SHELL_GROUP_IO_CLOSE_FD;
    if (op->kind == SHELL_GROUP_IO_DUP_FD && op->target_fd == UINT32_MAX)
      operations_valid = false;
    if (op->kind == SHELL_GROUP_IO_CLOSE_FD && op->target_fd != UINT32_MAX)
      operations_valid = false;
    if (!relation) {
      if (generated_redirect_index >= item.redirect_ops.size()) {
        operations_valid = false;
        continue;
      }
      const shell_brace_fuzz_io_t &expected =
          item.redirect_ops[generated_redirect_index++];
      size_t source_length = op->source_end - op->source_start;
      if (op->kind != expected.kind || op->fd != expected.fd ||
          op->target_fd != expected.target_fd ||
          processed_group_depth(&processed, op->group_index) !=
              expected.group_depth ||
          op->source_start != expected.source_offset ||
          source_length != expected.spelling.size() ||
          memcmp(item.command.data() + op->source_start,
                 expected.spelling.data(), source_length) != 0)
        operations_valid = false;
    }
  }
  if (generated_redirect_index != item.redirect_ops.size())
    operations_valid = false;
  for (const shell_brace_fuzz_io_t &expected : item.redirect_ops)
    if (expected.artifact_relation &&
        !generated_artifact_relation_present(&graph, expected))
      operations_valid = false;
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    if (!internal_graph_relation(graph, *edge))
      continue;
    bool timing_report = edge->from < graph.node_count &&
                         graph.nodes[edge->from].type == SHELL_NODE_TIME;
    graph_reads += (graph.edges[i].type == SHELL_EDGE_READ &&
                    internal_graph_relation(graph, graph.edges[i]));
    graph_pipes += edge->type == SHELL_EDGE_PIPE && !timing_report;
    graph_writes += !timing_report && (edge->type == SHELL_EDGE_WRITE ||
                                       edge->type == SHELL_EDGE_APPEND);
    if (edge->type == SHELL_EDGE_READ &&
        graph.nodes[edge->to].type != SHELL_NODE_GROUP &&
        (!item.command_local_documents ||
         graph.nodes[edge->to].type != SHELL_NODE_CMD))
      group_endpoints_valid = false;
    if (!timing_report &&
        (edge->type == SHELL_EDGE_WRITE || edge->type == SHELL_EDGE_APPEND) &&
        graph.nodes[edge->from].type != SHELL_NODE_GROUP)
      group_endpoints_valid = false;
    /* A redirected group input leaves its upstream writer connected to a
     * terminal ENDPOINT.  That is intentionally not a group endpoint: it
     * records the real pipe write after fd 0 has been replaced. */
    if (!timing_report && edge->type == SHELL_EDGE_PIPE &&
        edge->from != outer_group && edge->to != outer_group &&
        graph.nodes[edge->to].type != SHELL_NODE_ENDPOINT)
      group_endpoints_valid = false;
  }

  shell_dep_graph_validation_t graph_validation =
      shell_dep_graph_validate(&graph);
  shell_netstring_buffer_t netargv_sequence = {};
  shell_netstring_buffer_t command_netseq = {};
  shell_netstring_buffer_t type_netseq = {};
  shell_netstring_buffer_t paired_command_netseq = {};
  shell_netstring_buffer_t paired_type_netseq = {};
  size_t netargv_count = 0;
  size_t command_netseq_count = 0;
  size_t type_netseq_count = 0;
  size_t paired_count = 0;
  bool has_shell_features = false;
  shell_process_status_t netargv_status = shell_build_netargv_sequence_buffer(
      item.command.data(), item.command.size(), NULL, &netargv_sequence,
      &netargv_count, &has_shell_features);
  shell_process_status_t command_netseq_status =
      shell_build_command_netseq_buffer(item.command.data(),
                                        item.command.size(), NULL,
                                        &command_netseq, &command_netseq_count);
  shell_process_status_t type_netseq_status =
      shell_build_type_netseq_buffer(item.command.data(), item.command.size(),
                                     NULL, &type_netseq, &type_netseq_count);
  shell_process_status_t paired_netseq_status =
      shell_build_anomaly_netseqs_buffer(
          item.command.data(), item.command.size(), NULL,
          &paired_command_netseq, &paired_type_netseq, &paired_count);
  bool sequences_valid =
      netargv_status == SHELL_PROCESS_OK && netargv_count != 0 &&
      valid_generated_netargv_sequence(netargv_sequence, netargv_count) &&
      command_netseq_status == SHELL_PROCESS_OK &&
      /* Netargv models only immediate list members. Canonical anomaly
       * sequences additionally retain executable substitutions, so their
       * stage count may be larger while raw, typed, and paired forms must
       * still agree exactly. */
      command_netseq_count >= netargv_count &&
      valid_generated_outer_netsequence(command_netseq, command_netseq_count) &&
      type_netseq_status == SHELL_PROCESS_OK &&
      type_netseq_count == command_netseq_count &&
      valid_generated_outer_netsequence(type_netseq, type_netseq_count) &&
      paired_netseq_status == SHELL_PROCESS_OK &&
      paired_count == command_netseq_count &&
      (command_netseq.length != paired_command_netseq.length ||
       memcmp(command_netseq.data, paired_command_netseq.data,
              command_netseq.length)) == 0 &&
      (type_netseq.length != paired_type_netseq.length ||
       memcmp(type_netseq.data, paired_type_netseq.data, type_netseq.length)) ==
          0;
  if (!sequences_valid && g_verbose)
    fprintf(stderr,
            "generated sequence mismatch: netargv=%d/%zu command=%d/%zu "
            "type=%d/%zu paired=%d/%zu features=%d\n",
            netargv_status, netargv_count, command_netseq_status,
            command_netseq_count, type_netseq_status, type_netseq_count,
            paired_netseq_status, paired_count, has_shell_features);
  shell_netstring_buffer_free(&paired_type_netseq);
  shell_netstring_buffer_free(&paired_command_netseq);
  shell_netstring_buffer_free(&type_netseq);
  shell_netstring_buffer_free(&command_netseq);
  shell_netstring_buffer_free(&netargv_sequence);
  bool group_limits_valid = true;
  bool failed =
      fast_error != SHELL_OK ||
      (item.strict_valid ? strict_error != SHELL_OK
                         : strict_error != SHELL_EPARSE) ||
      fast.group_count != item.group_count || full_error != SHELL_TOKENIZE_OK ||
      process_error != SHELL_PROCESS_OK || command_count == 0 ||
      command_count > SHELL_MAX_SUBCOMMANDS ||
      processed.command_count != item.command_count ||
      processed.group_io_op_count != item.group_io_count ||
      processed_dups != item.dup_count ||
      processed_closes != item.close_count || dep_error != SHELL_DEP_OK ||
      graph_commands != item.command_count ||
      graph_documents != item.document_count ||
      graph_reads != item.read_count || graph_pipes != item.pipe_count ||
      graph_writes != item.write_count || !group_endpoints_valid ||
      !operations_valid || !sequences_valid ||
      graph.nodes[outer_group].group.kind !=
          (item.outer_subshell ? SHELL_GROUP_SUBSHELL : SHELL_GROUP_BRACE) ||
      !graph_validation.valid;

  /* Zero means unlimited in the public limits contract, so only operations
   * above one have a representable immediately-smaller rejecting limit. */
  if (!failed && item.strict_valid && item.group_io_count > 1) {
    shell_process_limits_t exact_limits = {SIZE_MAX, SIZE_MAX,
                                           item.group_io_count};
    shell_processed_commands_t limited = {};
    shell_process_status_t limited_status = shell_process_commands(
        item.command.data(), item.command.size(), &exact_limits, &limited);
    if (limited_status != SHELL_PROCESS_OK ||
        limited.group_io_op_count != item.group_io_count)
      group_limits_valid = false;
    shell_processed_commands_free(&limited);

    exact_limits.max_group_io_ops = item.group_io_count - 1;
    limited.commands = (shell_command_info_t *)(uintptr_t)1;
    limited.command_count = SIZE_MAX;
    limited.groups = (shell_group_t *)(uintptr_t)1;
    limited.group_count = SIZE_MAX;
    limited.group_io_ops = (shell_group_io_op_t *)(uintptr_t)1;
    limited.group_io_op_count = SIZE_MAX;
    limited_status = shell_process_commands(
        item.command.data(), item.command.size(), &exact_limits, &limited);
    bool rejected_limit_cleared =
        limited.commands == NULL && limited.command_count == 0 &&
        limited.groups == NULL && limited.group_count == 0 &&
        limited.group_io_ops == NULL && limited.group_io_op_count == 0;
    if (limited_status != SHELL_PROCESS_EOUTPUT_LIMIT ||
        !rejected_limit_cleared)
      group_limits_valid = false;
    if (!group_limits_valid)
      failed = true;
  }
  if (failed && g_verbose) {
    uint8_t outer_kind = outer_group < graph.node_count
                             ? graph.nodes[outer_group].group.kind
                             : 0;
    fprintf(stderr,
            "generated brace case failed: %s (fast=%d strict=%d groups=%u "
            "full=%d commands=%zu process=%d processed=%zu/%zu dep=%d "
            "graph=%u/%u/%u/%u/%u expected=%u/%u/%u/%u/%u/%u "
            "endpoints=%d operations=%d sequences=%d limits=%d kind=%u "
            "validation=%d)\n",
            item.command.c_str(), fast_error, strict_error, fast.group_count,
            full_error, command_count, process_error, processed.command_count,
            processed.group_io_op_count, dep_error, graph_commands,
            graph_documents, graph_reads, graph_pipes, graph_writes,
            item.command_count, item.group_io_count, item.document_count,
            item.read_count, item.pipe_count, item.write_count,
            group_endpoints_valid, operations_valid, sequences_valid,
            group_limits_valid, outer_kind, graph_validation.valid);
  }
  shell_commands_free(commands, command_count);
  shell_processed_commands_free(&processed);
  return failed;
}

/* The ordinary brace generator checks command ownership and group I/O. These
 * cases instead assert the dynamic-byte topology produced by substitutions:
 * direct streams stay direct, while ambiguous fan-in is made explicit with an
 * ENDPOINT collector. */
static int test_substitution_case(const shell_substitution_fuzz_case_t &item,
                                  const char *cwd) {
  shell_parse_result_t fast = {};
  shell_command_t *commands = NULL;
  size_t command_count = 0;
  shell_processed_commands_t processed = {};
  shell_dep_graph_t graph = {};
  shell_netstring_buffer_t netargv_sequence = {};
  size_t netargv_count = 0;
  bool has_shell_features = false;

  shell_error_t fast_error =
      shell_parse_fast(item.command.data(), item.command.size(), NULL, &fast);
  shell_tokenize_status_t full_error = shell_tokenize_commands(
      item.command.data(), item.command.size(), &commands, &command_count);
  shell_process_status_t process_error = shell_process_commands(
      item.command.data(), item.command.size(), NULL, &processed);
  shell_dep_error_t graph_error = shell_dep_graph_parse(
      item.command.data(), item.command.size(), cwd, NULL, &graph);
  shell_process_status_t netargv_error = shell_build_netargv_sequence_buffer(
      item.command.data(), item.command.size(), NULL, &netargv_sequence,
      &netargv_count, &has_shell_features);

  uint32_t graph_commands = 0;
  uint32_t graph_groups = 0;
  uint32_t graph_endpoints = 0;
  uint32_t substitution_edges = 0;
  uint32_t shell_word_substitution_edges = 0;
  uint32_t dynamic_name_substitution_edges = 0;
  uint32_t file_substitution_edges = 0;
  uint32_t collector_writes = 0;
  uint32_t heredoc_count = 0;
  uint32_t literal_heredoc_count = 0;
  uint32_t transient_heredoc_count = 0;
  uint32_t heredoc_substitution_count = 0;
  uint32_t herestring_count = 0;
  uint32_t herestring_substitution_count = 0;
  bool direct_file_consumers[SHELL_DEP_MAX_NODES] = {false};
  bool topology_valid = true;
  for (uint32_t i = 0; i < graph.node_count; i++) {
    const shell_dep_node_t *node = &graph.nodes[i];
    graph_commands += node->type == SHELL_NODE_CMD;
    graph_groups += node->type == SHELL_NODE_GROUP;
    graph_endpoints += node->type == SHELL_NODE_ENDPOINT;
    if (node->type == SHELL_NODE_DOC && node->doc.kind == SHELL_DOC_HEREDOC) {
      heredoc_count++;
      literal_heredoc_count +=
          (node->doc.flags & SHELL_DEP_DOC_FLAG_HEREDOC_LITERAL) != 0;
      transient_heredoc_count +=
          (node->doc.flags & SHELL_DEP_DOC_FLAG_TRANSIENT) != 0;
    }
    if (node->type == SHELL_NODE_DOC && node->doc.kind == SHELL_DOC_HERESTRING)
      herestring_count++;
  }
  for (uint32_t i = 0; i < graph.edge_count; i++) {
    const shell_dep_edge_t *edge = &graph.edges[i];
    if (edge->from >= graph.node_count || edge->to >= graph.node_count) {
      topology_valid = false;
      continue;
    }
    if (!internal_graph_relation(graph, *edge))
      continue;
    if (edge->type == SHELL_EDGE_SUBST) {
      substitution_edges++;
      if ((edge->flags & ~(SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD |
                           SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME)) != 0 ||
          ((edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0 &&
           (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0))
        topology_valid = false;
      shell_word_substitution_edges +=
          (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) != 0;
      dynamic_name_substitution_edges +=
          (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) != 0;
      if (graph.nodes[edge->from].type == SHELL_NODE_ENDPOINT) {
        if (edge->source_fd != SHELL_DEP_FD_NONE)
          topology_valid = false;
      } else if (graph.nodes[edge->from].type == SHELL_NODE_DOC) {
        if (graph.nodes[edge->from].doc.kind != SHELL_DOC_FILE ||
            edge->source_fd != SHELL_DEP_FD_NONE ||
            edge->target_fd != SHELL_DEP_FD_NONE)
          topology_valid = false;
        else {
          file_substitution_edges++;
          direct_file_consumers[edge->to] = true;
        }
      } else {
        uint32_t expected_source_fd =
            graph.nodes[edge->from].type == SHELL_NODE_TIME
                ? graph.nodes[edge->from].time.report_fd
                : 1;
        if (edge->source_fd != expected_source_fd)
          topology_valid = false;
      }
      if (graph.nodes[edge->to].type != SHELL_NODE_CMD &&
          graph.nodes[edge->to].type != SHELL_NODE_GROUP &&
          graph.nodes[edge->to].type != SHELL_NODE_DOC)
        topology_valid = false;
      if (graph.nodes[edge->to].type == SHELL_NODE_DOC &&
          graph.nodes[edge->to].doc.kind == SHELL_DOC_HEREDOC)
        heredoc_substitution_count++;
      if (graph.nodes[edge->to].type == SHELL_NODE_DOC &&
          graph.nodes[edge->to].doc.kind == SHELL_DOC_HERESTRING)
        herestring_substitution_count++;
      if (edge->flags & SHELL_DEP_EDGE_FLAG_SUBST_DYNAMIC_NAME) {
        if (graph.nodes[edge->to].type != SHELL_NODE_DOC ||
            graph.nodes[edge->to].doc.kind != SHELL_DOC_FILE ||
            (graph.nodes[edge->to].doc.flags &
             (SHELL_DEP_DOC_FLAG_DYNAMIC_NAME |
              SHELL_DEP_DOC_FLAG_RESOLVED_PATH |
              SHELL_DEP_DOC_FLAG_EXPANSION_FAILED)) == 0)
          topology_valid = false;
      }
    }
    if (edge->type == SHELL_EDGE_WRITE &&
        graph.nodes[edge->to].type == SHELL_NODE_ENDPOINT) {
      collector_writes++;
      bool timing_report =
          graph.nodes[edge->from].type == SHELL_NODE_TIME &&
          edge->source_fd == graph.nodes[edge->from].time.report_fd;
      if (!timing_report && edge->source_fd != item.outer_fd &&
          edge->source_fd != 1)
        topology_valid = false;
    }
  }
  for (uint32_t i = 0; i < graph.edge_count; i++)
    if ((graph.edges[i].type == SHELL_EDGE_READ &&
         internal_graph_relation(graph, graph.edges[i])) &&
        graph.edges[i].to < graph.node_count &&
        direct_file_consumers[graph.edges[i].to])
      topology_valid = false;

  if (item.output_process && item.collector_write_count != 0) {
    bool output_collector_valid = false;
    for (uint32_t i = 0; i < graph.node_count; i++) {
      if (graph.nodes[i].type != SHELL_NODE_ENDPOINT)
        continue;
      bool outer_write = false;
      bool nested_consumer = false;
      for (uint32_t edge_index = 0; edge_index < graph.edge_count;
           edge_index++) {
        const shell_dep_edge_t *edge = &graph.edges[edge_index];
        if (!internal_graph_relation(graph, *edge))
          continue;
        outer_write =
            outer_write || (edge->type == SHELL_EDGE_WRITE && edge->to == i &&
                            edge->source_fd == item.outer_fd &&
                            (graph.nodes[edge->from].type == SHELL_NODE_CMD ||
                             graph.nodes[edge->from].type == SHELL_NODE_GROUP));
        nested_consumer = nested_consumer ||
                          (edge->type == SHELL_EDGE_SUBST && edge->from == i &&
                           (graph.nodes[edge->to].type == SHELL_NODE_CMD ||
                            graph.nodes[edge->to].type == SHELL_NODE_GROUP) &&
                           edge->target_fd == 0);
      }
      output_collector_valid =
          output_collector_valid || (outer_write && nested_consumer);
    }
    topology_valid = topology_valid && output_collector_valid;
  }

  if (item.group_substitution_owner) {
    bool group_owned_flow = false;
    bool group_owned_descriptor = false;
    bool expected_group_pipe = item.group_pipe_target_fd == UINT32_MAX;
    for (uint32_t edge_index = 0; edge_index < graph.edge_count; edge_index++) {
      const shell_dep_edge_t *edge = &graph.edges[edge_index];
      if (!internal_graph_relation(graph, *edge))
        continue;
      if (item.output_process && item.collector_write_count != 0) {
        group_owned_flow = group_owned_flow ||
                           (edge->type == SHELL_EDGE_WRITE &&
                            graph.nodes[edge->from].type == SHELL_NODE_GROUP &&
                            graph.nodes[edge->to].type == SHELL_NODE_ENDPOINT &&
                            edge->source_fd == item.outer_fd);
      } else {
        group_owned_flow = group_owned_flow ||
                           (edge->type == SHELL_EDGE_SUBST &&
                            graph.nodes[edge->to].type == SHELL_NODE_GROUP &&
                            edge->target_fd != SHELL_DEP_FD_NONE);
      }
      expected_group_pipe = expected_group_pipe ||
                            (edge->type == SHELL_EDGE_PIPE &&
                             graph.nodes[edge->to].type == SHELL_NODE_GROUP &&
                             edge->target_fd == item.group_pipe_target_fd);
    }
    shell_group_io_kind_t expected_kind = item.output_process
                                              ? SHELL_GROUP_IO_PROCESS_SUB_OUT
                                              : SHELL_GROUP_IO_PROCESS_SUB_IN;
    uint32_t expected_fd = item.output_process ? item.outer_fd : 0;
    for (size_t op_index = 0; op_index < processed.group_io_op_count;
         op_index++) {
      const shell_group_io_op_t *op = &processed.group_io_ops[op_index];
      group_owned_descriptor =
          group_owned_descriptor ||
          (op->kind == expected_kind && op->fd == expected_fd &&
           op->group_index < processed.group_count);
    }
    topology_valid = topology_valid && group_owned_flow &&
                     group_owned_descriptor && expected_group_pipe;
  }

  shell_dep_graph_validation_t validation = shell_dep_graph_validate(&graph);
  if (item.source_rejected) {
    bool failed = fast_error != SHELL_EPARSE ||
                  full_error != SHELL_TOKENIZE_OK ||
                  process_error != SHELL_PROCESS_EPARSE ||
                  netargv_error != SHELL_PROCESS_EPARSE ||
                  graph_error != SHELL_DEP_EPARSE || graph.node_count != 0 ||
                  graph.edge_count != 0 || processed.command_count != 0 ||
                  processed.commands != NULL || netargv_sequence.data != NULL ||
                  netargv_count != 0 || has_shell_features;
    if (failed && g_verbose)
      fprintf(stderr,
              "generated unsafe ANSI source accepted: %s "
              "(fast=%d full=%d process=%d netargv=%d graph=%d)\n",
              item.command.c_str(), fast_error, full_error, process_error,
              netargv_error, graph_error);
    shell_netstring_buffer_free(&netargv_sequence);
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    return failed;
  }
  if (item.depgraph_rejected) {
    bool failed = fast_error != SHELL_OK || full_error != SHELL_TOKENIZE_OK ||
                  process_error != SHELL_PROCESS_OK ||
                  netargv_error != SHELL_PROCESS_OK ||
                  graph_error != SHELL_DEP_EPARSE || graph.node_count != 0 ||
                  graph.edge_count != 0;
    if (failed && g_verbose)
      fprintf(stderr,
              "generated substitution rejection case failed: %s "
              "(fast=%d full=%d process=%d netargv=%d graph=%d "
              "nodes=%u edges=%u)\n",
              item.command.c_str(), fast_error, full_error, process_error,
              netargv_error, graph_error, graph.node_count, graph.edge_count);
    shell_netstring_buffer_free(&netargv_sequence);
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    return failed;
  }
  if (item.depgraph_truncated) {
    bool failed = graph_error != SHELL_DEP_ETRUNC ||
                  !(graph.status & SHELL_DEP_STATUS_TRUNCATED) ||
                  !validation.valid;
    if (failed && g_verbose)
      fprintf(stderr,
              "generated substitution truncation case failed: %s "
              "(graph=%d status=%u validation=%d)\n",
              item.command.c_str(), graph_error, graph.status,
              validation.valid);
    shell_netstring_buffer_free(&netargv_sequence);
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    return failed;
  }
  bool failed =
      fast_error != SHELL_OK || full_error != SHELL_TOKENIZE_OK ||
      process_error != SHELL_PROCESS_OK || graph_error != SHELL_DEP_OK ||
      netargv_error != SHELL_PROCESS_OK ||
      has_shell_features != item.expected_shell_features ||
      graph_commands != item.command_count ||
      graph_groups != item.group_count ||
      graph_endpoints != item.endpoint_count ||
      substitution_edges != item.substitution_edge_count ||
      (item.dynamic_name_substitution_count != UINT32_MAX &&
       dynamic_name_substitution_edges !=
           item.dynamic_name_substitution_count) ||
      file_substitution_edges != item.file_substitution_count ||
      collector_writes != item.collector_write_count ||
      heredoc_count != item.heredoc_count ||
      literal_heredoc_count != item.literal_heredoc_count ||
      transient_heredoc_count != item.transient_heredoc_count ||
      heredoc_substitution_count != item.heredoc_substitution_count ||
      herestring_count != item.herestring_count ||
      herestring_substitution_count != item.herestring_substitution_count ||
      !topology_valid || !validation.valid;
  if (item.surface_command_count != 0 &&
      (command_count != item.surface_command_count ||
       processed.command_count != item.surface_command_count ||
       netargv_count != item.surface_command_count))
    failed = true;
  if (item.requires_substitution_evaluation !=
      (shell_word_substitution_edges != 0))
    failed = true;
  if (failed && g_verbose)
    fprintf(
        stderr,
        "generated substitution case failed: %s (fast=%d full=%d "
        "process=%d graph=%d netargv=%d features=%d surface=%zu/%zu/%zu/%u "
        "nodes=%u/%u groups=%u/%u "
        "endpoints=%u/%u substitutions=%u/%u shell-words=%u "
        "dynamic-names=%u/%u "
        "file-substitutions=%u/%u "
        "writes=%u/%u heredocs=%u/%u literal=%u/%u transient=%u/%u "
        "heredoc-substitutions=%u/%u herestrings=%u/%u "
        "herestring-substitutions=%u/%u topology=%d validation=%d)\n",
        item.command.c_str(), fast_error, full_error, process_error,
        graph_error, netargv_error, has_shell_features, command_count,
        processed.command_count, netargv_count, item.surface_command_count,
        graph_commands, item.command_count, graph_groups, item.group_count,
        graph_endpoints, item.endpoint_count, substitution_edges,
        item.substitution_edge_count, shell_word_substitution_edges,
        dynamic_name_substitution_edges, item.dynamic_name_substitution_count,
        file_substitution_edges, item.file_substitution_count, collector_writes,
        item.collector_write_count, heredoc_count, item.heredoc_count,
        literal_heredoc_count, item.literal_heredoc_count,
        transient_heredoc_count, item.transient_heredoc_count,
        heredoc_substitution_count, item.heredoc_substitution_count,
        herestring_count, item.herestring_count, herestring_substitution_count,
        item.herestring_substitution_count, topology_valid, validation.valid);
  shell_netstring_buffer_free(&netargv_sequence);
  shell_commands_free(commands, command_count);
  shell_processed_commands_free(&processed);
  return failed;
}

static int test_composite_redirect_operand(unsigned selector, const char *cwd) {
  /* Exercise literal concatenation without growing the checked-in corpus. */
  std::string operand = (selector & 1) ? "<(printf x)" : ">(cat)";
  operand = (selector & 2) ? "prefix" + operand : operand + "suffix";
  std::string command = (selector & 4) ? "{ cat; } " : "cat ";
  command += (selector & 8) ? "< " : "> ";
  command += operand;
  shell_dep_graph_t graph = {};
  if (shell_dep_graph_parse(command.data(), command.size(), cwd, NULL,
                            &graph) != SHELL_DEP_OK ||
      !shell_dep_graph_validate(&graph).valid)
    return 1;
  unsigned commands = 0;
  for (uint32_t n = 0; n < graph.node_count; n++)
    commands += graph.nodes[n].type == SHELL_NODE_CMD;
  for (uint32_t e = 0; e < graph.edge_count; e++)
    if (graph.edges[e].type == SHELL_EDGE_SUBST)
      return 1;
  if (commands != 2 || test_processor(command.data(), command.size()))
    return 1;
  return 0;
}

static int test_generated_redirect_boundary(unsigned selector) {
  static const char *const separators[] = {";", "\n", "&&", "||",
                                           "&", "|",  "|&"};
  unsigned mode = selector % 6;
  std::string number = std::to_string(selector / 6);
  std::string input;
  if (mode == 0)
    input = std::string("{ cat; } >out") + separators[(selector / 3) % 7] +
            " >other";
  else if (mode == 1)
    input = "cat " + number + " <<<body";
  else if (mode == 2)
    input = "cat " + number + "<<'EOF'\nwhile true; do :; done\nEOF\n";
  else if (mode == 3)
    input = "{ cat; } " + number + "\\\n2<<EOF\nbody\nEOF\n>out";
  else if (mode == 4)
    input = "cat " + number + "\\\n2<<<body";
  else
    input = "cat $'x'" + number + ">out";
  bool empty_stage = mode == 0 || mode == 3;
  shell_netstring_buffer_t raw = {};
  shell_netstring_buffer_t typed = {};
  size_t count = 0;
  bool valid =
      shell_build_anomaly_netseqs_buffer(input.data(), input.size(), NULL, &raw,
                                         &typed, &count) == SHELL_PROCESS_OK;
  valid =
      valid && count == (empty_stage ? 2u : 1u) &&
      (raw.length != strlen(empty_stage ? "3:cat,0:," : "3:cat,") ||
       memcmp(raw.data, empty_stage ? "3:cat,0:," : "3:cat,", raw.length)) == 0;
  shell_netstring_buffer_free(&raw);
  shell_netstring_buffer_free(&typed);
  shell_netstring_buffer_t sequence = {};
  bool features = false;
  shell_process_status_t status = shell_build_netargv_sequence_buffer(
      input.data(), input.size(), NULL, &sequence, &count, &features);
  if (empty_stage) {
    valid = valid && status == SHELL_PROCESS_EPARSE && sequence.data == NULL &&
            count == 0 && !features;
  } else {
    shell_netstring_iter_t outer, inner;
    shell_netstring_view_t record, word;
    valid = valid && status == SHELL_PROCESS_OK && count == 1 &&
            shell_netstring_iter_init(&outer, sequence.data, sequence.length) ==
                SHELL_NETSTRING_OK &&
            shell_netstring_iter_next(&outer, &record) == SHELL_NETSTRING_OK &&
            shell_netstring_iter_init(&inner, record.payload,
                                      record.payload_length) ==
                SHELL_NETSTRING_OK &&
            shell_netstring_iter_next(&inner, &word) == SHELL_NETSTRING_OK &&
            word.payload_length == 3 && memcmp(word.payload, "cat", 3) == 0;
    if (mode == 1 || mode == 5) {
      std::string expected = mode == 5 ? "x" + number : number;
      valid = valid &&
              shell_netstring_iter_next(&inner, &word) == SHELL_NETSTRING_OK &&
              word.payload_length == expected.size() &&
              memcmp(word.payload, expected.data(), expected.size()) == 0;
    }
    valid = valid &&
            shell_netstring_iter_next(&inner, &word) == SHELL_NETSTRING_DONE;
  }
  shell_netstring_buffer_free(&sequence);
  shell_dep_graph_t graph = {};
  valid = valid &&
          shell_dep_graph_parse(input.data(), input.size(), "/tmp", NULL,
                                &graph) == SHELL_DEP_OK &&
          shell_dep_graph_validate(&graph).valid;
  unsigned commands = 0, empty_commands = 0, document_routes = 0;
  for (uint32_t n = 0; valid && n < graph.node_count; n++) {
    if (graph.nodes[n].type == SHELL_NODE_CMD) {
      commands++;
      empty_commands += graph.nodes[n].cmd.token_count == 0;
    }
  }
  valid = valid && commands == (empty_stage ? 2u : 1u) &&
          empty_commands == (empty_stage ? 1u : 0u);
  if (mode == 3 || mode == 4) {
    for (uint32_t e = 0; valid && e < graph.edge_count; e++) {
      if ((graph.edges[e].type == SHELL_EDGE_READ &&
           internal_graph_relation(graph, graph.edges[e]))) {
        valid = graph.edges[e].target_fd == (selector / 6) * 10 + 2;
        document_routes++;
      }
    }
    valid = valid && document_routes == 1;
  }
  int failed = valid ? test_processor(input.data(), input.size()) : 1;
  if (failed)
    fprintf(stderr, "redirect boundary selector %u (canonical=%d): %s\n",
            selector, valid, input.c_str());
  return failed;
}

static int test_generated_substitution_case(const uint8_t *data, size_t size,
                                            const char *cwd) {
  shell_substitution_fuzz_case_t item =
      shell_brace_fuzz_substitution_case(data, size);
  int failed = test_substitution_case(item, cwd);
  if (failed)
    fprintf(stderr, "substitution case selector %u: %s\n",
            size ? (unsigned)data[0] : 0, item.command.c_str());
  return failed;
}

static int test_composed_substitution_case(const uint8_t *data, size_t size,
                                           const char *cwd) {
  shell_substitution_fuzz_case_t item =
      shell_brace_fuzz_composed_substitution_case(data, size);
  int failed = test_substitution_case(item, cwd);
  if (failed)
    fprintf(stderr, "composed substitution case selector %u: %s\n",
            size ? (unsigned)data[0] : 0, item.command.c_str());
  return failed;
}

static int test_composed_substitution_matrix(const char *cwd) {
  uint8_t data[7] = {0};
  for (uint8_t form = 0; form < 6; form++) {
    uint8_t pipeline_count = form == 5 ? 1 : 2;
    uint8_t literal_count = form == 5 ? 2 : 1;
    for (uint8_t depth = 0; depth < 3; depth++) {
      for (uint8_t pipeline = 0; pipeline < pipeline_count; pipeline++) {
        for (uint8_t literal = 0; literal < literal_count; literal++) {
          for (uint8_t group_mask = 0; group_mask < (1u << (depth + 1));
               group_mask++) {
            data[0] = form;
            data[1] = depth;
            data[2] = pipeline;
            data[3] = literal;
            for (uint8_t level = 0; level <= depth; level++)
              data[4 + level] =
                  ((group_mask >> level) & 1u) | ((form & 1u) ? 2u : 0u);
            if (test_composed_substitution_case(data, sizeof(data), cwd))
              return 1;
          }
        }
      }
    }
  }
  return 0;
}

/* Generate both sides of the static arithmetic nesting boundary. This keeps
 * the fuzzer exercising the guarded semantic recognizer rather than relying
 * on arbitrary byte mutations to rediscover deeply balanced expressions. */
static int test_generated_static_arithmetic_case(const uint8_t *data,
                                                 size_t size) {
  uint8_t selector = size == 0 ? 0 : data[0];
  unsigned int family = selector % 4u;
  bool expect_reject = (selector & 4u) != 0;
  size_t nesting =
      expect_reject ? SHELL_MAX_SUBCOMMANDS : SHELL_MAX_SUBCOMMANDS - 1;
  std::string input = "echo $((";
  if (family == 0) {
    input.append(nesting, '(');
    input += '1';
    input.append(nesting, ')');
  } else if (family == 1) {
    for (size_t i = 0; i < nesting; i++)
      input += "1**";
    input += '1';
  } else if (family == 2) {
    for (size_t i = 0; i < nesting; i++)
      input += "1?1:";
    input += '1';
  } else {
    /* Unary syntax must remain linear even when the input asks for a large
     * number of prefix operators. */
    input.append(SHELL_MAX_SUBCOMMANDS * 4, '-');
    input += '1';
    expect_reject = false;
  }
  input += "))";
  shell_netstring_buffer_t raw = {};
  shell_netstring_buffer_t type = {};
  size_t count = 0;
  shell_process_status_t status = shell_build_anomaly_netseqs_buffer(
      input.data(), input.size(), nullptr, &raw, &type, &count);
  bool valid = expect_reject
                   ? status == SHELL_PROCESS_EPARSE && raw.data == nullptr &&
                         type.data == nullptr && count == 0
                   : status == SHELL_PROCESS_OK && raw.data != nullptr &&
                         type.data != nullptr && count == 1;
  shell_netstring_buffer_free(&raw);
  shell_netstring_buffer_free(&type);
  return valid ? 0 : 1;
}

static void fixed_oracle_phase(const char *name) {
  if (!g_verbose)
    return;
  static const auto start = std::chrono::steady_clock::now();
  const double elapsed =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - start)
          .count();
  fprintf(stderr, "DEBUG: fixed oracle phase %s at %.3fs\n", name, elapsed);
}

/* Fixed sweeps belong to startup, not one fuzz input's timeout budget. */
static void run_fixed_oracles() {
  /* CI's background_operator.txt selects this generated pending redirector.
   * Keep the exact pair independently of corpus staging and mutation. */
  if (test_draft_redirector_prefix(99, 109))
    abort();
  for (uint8_t selector = 0; selector < 12; selector++)
    for (uint8_t operand = 0; operand < 3; operand++)
      if (test_draft_nested_redirect(selector, operand)) {
        fprintf(stderr, "nested draft redirect oracle failed: %u, %u\n",
                selector, operand);
        abort();
      }
  for (uint8_t selector = 0; selector < 16; selector++)
    for (uint8_t value = 0; value < 24; value++)
      if (test_draft_redirector_prefix(selector, value)) {
        fprintf(stderr, "pending redirector oracle failed: %u, %u\n", selector,
                value);
        abort();
      }
  for (uint8_t selector = 0; selector < 18; selector++)
    for (uint8_t ending = 0; ending < 10; ending++)
      if (test_draft_redirect_operand(selector, ending)) {
        fprintf(stderr, "missing redirect operand oracle failed: %u, %u\n",
                selector, ending);
        abort();
      }
  for (uint8_t selector = 0; selector < 18; selector++)
    if (test_draft_closed_children(selector, selector))
      abort();
  fixed_oracle_phase("read outcomes");
  /* These sequential sweeps never need two retained graphs simultaneously.
   * Reuse one heap-owned result so adding a fixture family cannot enlarge
   * the sanitizer startup stack by another full graph object. */
  std::unique_ptr<shell_dep_graph_t> graph_storage(new shell_dep_graph_t{});
  shell_dep_graph_t &graph = *graph_storage;
  for (const auto &fixture : shellsplit_test_printf_expansion_cases) {
    size_t length = strlen(fixture.source), required = 0;
    shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
    if (!shell_dep_resolved_workspace_size(length, &limits, &required))
      abort();
    g_depgraph_workspace.resize((required + sizeof(std::max_align_t) - 1) /
                                sizeof(std::max_align_t));
    limits.workspace = g_depgraph_workspace.data();
    limits.workspace_size = required;
    resolved_fuzz_context context = {
        fixture.source, length, 1, false, 0, std::vector<uint8_t>(length),
        "2:\\c,",       5};
    if (shell_dep_graph_parse_resolved(fixture.source, length, "/", &limits,
                                       &graph, resolved_fuzz_word, &context,
                                       nullptr) != SHELL_DEP_OK ||
        context.invalid_request || context.calls != fixture.queries ||
        !shell_dep_graph_validate(&graph).valid) {
      fprintf(stderr, "elided printf resolver oracle failed: %s\n",
              fixture.source);
      abort();
    }
  }
  for (const auto &fixture : shellsplit_test_control_byte_words) {
    shell_processed_commands_t processed = {};
    shell_netstring_buffer_t netargv = {};
    bool valid =
        shell_process_commands(fixture.source, strlen(fixture.source), nullptr,
                               &processed) == SHELL_PROCESS_OK &&
        processed.command_count == 1 &&
        shell_render_netargv_buffer(&processed.commands[0], nullptr,
                                    &netargv) == SHELL_PROCESS_OK &&
        netargv.length == strlen(fixture.netargv) &&
        memcmp(netargv.data, fixture.netargv, netargv.length) == 0;
    shell_netstring_buffer_free(&netargv);
    shell_processed_commands_free(&processed);
    if (!valid || test_processor(fixture.source, strlen(fixture.source))) {
      fprintf(stderr, "control-byte canonical argv oracle failed\n");
      abort();
    }
  }
  for (const char *body : shellsplit_test_nonblank_bodies) {
    std::string source =
        std::string("value=$(true;") + body + ") || printf fallback >out";
    shell_processed_commands_t processed = {};
    bool valid = shell_dep_graph_parse(source.data(), source.size(), "/",
                                       nullptr, &graph) == SHELL_DEP_OK &&
                 shell_dep_graph_validate(&graph).valid &&
                 shell_process_commands(source.data(), source.size(), nullptr,
                                        &processed) == SHELL_PROCESS_OK;
    bool fallback_write = false;
    for (uint32_t e = 0; e < graph.edge_count; e++)
      fallback_write |= graph.edges[e].type == SHELL_EDGE_WRITE;
    valid &= fallback_write;
    shell_processed_commands_free(&processed);
    if (!valid) {
      fprintf(stderr, "control-byte substitution outcome oracle failed\n");
      abort();
    }
  }
  static const struct {
    const char *source;
    uint32_t fd;
    bool input;
  } read_inputs[] = {
      {"exec {fd}<<<saved && read -n-0\"$fd\" value <<<payload", 0, false},
      {"exec {fd}<<<saved && read -N \"-00${fd} \" value <<<payload", 0, false},
      {"exec {fd}<<<saved && read -u-00\"$fd\" value <<<payload", 0, false},
      {"exec {fd}<<<saved && read -u00\"$fd\" value", SHELL_DEP_FD_NAMED, true},
      {"unset fd; read -u-00\"$fd\" value <<<payload", 0, true},
      {"unset fd; read -u3\"$fd\" value 3<<<payload", 3, true},
      {"unset RANDOM; result=$(read RANDOM <<<payload)", 0, true},
      {"unset RANDOM; result=`read RANDOM <<<payload`", 0, true},
      {"unset RANDOM; : <(read RANDOM <<<payload)", 0, true},
      {"unset BASH_REMATCH; result=$(inner=$(read BASH_REMATCH <<<payload))", 0,
       true},
      {"unset RANDOM; result=$(read -n0 RANDOM)", 0, false},
      {"unset _; : 1; read -n\"$_\" value <<<payload", 0, true},
      {"unset '_'; builtin : 1; builtin read -n\"${_}\" value <<<payload", 0,
       true},
      {"unset count; read -n0 -- \"$target\"; "
       "read -n\"$count\" value <<<payload",
       0, true},
      {"unset fd; read -n\"$fd\" -p\"$fd\" value <<<payload", 0, false},
      {"unset fd; read -u\"$fd\" -n\"$fd\" value <<<payload", 0, false},
      {"unset fd; read -n0\"$fd\" value <<<payload", 0, false},
      {"unset fd; read -- -p\"$fd\" value <<<payload", 0, false},
      {"unset fd; read -- \"$fd\"- value <<<payload", 0, false},
      {"exec {fd}<<<saved && read -n-\"$fd\" value <<<payload", 0, false},
      {"exec {fd}<<<saved && read -N -\"$fd\" value <<<payload", 0, false},
      {"exec {fd}<<<saved && read -t-\"$fd\" value <<<payload", 0, false},
      {"exec {fd}<<<saved && read -u-\"$fd\" value <<<payload", 0, false},
      {"read -n-1\"$unknown\" value <<<payload", 0, false},
      {"read -u-1\"$unknown\" value <<<payload", 0, false},
      {"read -n\"$unknown\"x value <<<payload", 0, false},
      {"read -u\"$unknown\"x value <<<payload", 0, false},
      {"read -- pre\"$unknown\"- value <<<payload", 0, false},
      {"read -- \"$unknown\"~ value <<<payload", 0, false},
      {"unset fd; read -p\"$fd\" -e value <<<payload", 0, true},
      {"unset fd; read -n\"$fd\" -a value <<<payload", 0, false},
      {"exec 3<&-; read -u3 -e value <<<payload", 0, false},
      {"read -t0.0000000\"$unknown\" value <<<payload", 0, false},
      {"read -t0.0000005\"$unknown\" value <<<payload", 0, true},
      {"unset empty; read -- $empty~ value <<<payload", 0, false},
      {"read -- pre<(printf generated >child) value <<<payload", 0, false},
      {"read -- >(printf generated >child)suffix value <<<payload", 0, false},
      {"read -p pre<(printf generated >child) value <<<payload", 0, true},
      {"exec {input}<<<saved && { unset empty; "
       "read -u\"$input\" oth\"$empty\"er; }",
       SHELL_DEP_FD_NAMED, true},
      {"unset empty; read -- -p\"$empty\" RANDOM <<<payload", 0, false},
      {"read -u3 RANDOM 3<&-", 0, false},
      {"unset empty; read -n0 other\"$empty\"", 0, false},
      {"read -- bad-\"$unknown\" value <<<payload", 0, false},
      {"read -- first bad-\"$unknown\" value <<<payload", 0, true},
      {"read -t0 -- -p\"$unknown\" value <<<payload", 0, false},
      {"exec 3<<<payload; <() read -u3 value", 3, true},
      {"exec 3<<<payload; command <() read <() -u3 value", 3, true},
      {"<() read -n0 value <<<payload", 0, false},
      {"printf payload | read value", 0, true},
      {"read -u3 value <unused 3<input", 3, true},
      {"read -u3 -u4 value 3<&- 4<<<payload", 0, false},
      {"read -t0 value <input", 0, false},
      {"read -N0 value <input", 0, false},
      {"read -- \"$target\" later <<<payload", 0, true},
      {"read first \"$target\" later <<<payload", 0, true},
      {"read -t0 first \"$target\" later <<<payload", 0, false},
      {"exec 63<&-; read -u63 value <(printf payload)", 63, true},
      {"exec 63<&-; read -p <(printf payload) -u63 value", 63, true},
      {"exec 63<&-; read -u63 <(printf payload)", 63, false},
      {"read -u3 value 3>writeonly", 3, false},
      {"exec {out}>out && { read out 0<&-; printf x >&\"$out\"; }", 0, false},
      {"unset fd; exec {fd}<input; read -u\"$fd\" 3 value 3<<<payload", 3,
       true},
      {"exec {fd}<<<old; read -u \"$fd\" value {fd}<<<new", SHELL_DEP_FD_NAMED,
       true},
      {"exec 3<&-; exec {fd}<<<payload; "
       "result=$(read -u\"$fd\" -n0 probe) || read -u\"$fd\" value",
       SHELL_DEP_FD_NAMED, false},
      {"exec {fd}< <(printf payload); echo \"$(read -u \"$fd\" value)\"",
       SHELL_DEP_FD_NAMED, true},
      {"exec 3<&-; test \"$choice\" = yes || exec 3<<<payload; "
       "read -u3 value && echo reached >reached",
       3, true},
      {"exec {fd}<<<payload && read -p\"$fd\" -u\"$fd\" value <unused",
       SHELL_DEP_FD_NAMED, true},
      {"exec {fd}<<<payload && read -p\"$fd\" -u \"$fd\" value <unused",
       SHELL_DEP_FD_NAMED, true},
      {"read -t4294967296 value <<<payload", 0, false},
      {"read -t4294967296.5 value <<<payload", 0, true},
      {"read -t18446744073709551617 value <<<payload", 0, true},
      {"read -t-18446744073709551615.5 value <<<payload", 0, true},
      {"read -t18446744073709551616 value <<<payload", 0, false},
      {"read -t-18446744073709551616.5 value <<<payload", 0, false},
      {"exec {input}<<<payload && read -u\"$input\" -- \"$input\"",
       SHELL_DEP_FD_NAMED, false},
      {"exec {input}<<<payload {out}>out && { "
       "read -u\"$input\" -- first \"$input\" out; printf x >&\"$out\"; }",
       SHELL_DEP_FD_NAMED, true},
      {"exec {out}>out && { unset empty; exec 9<&-; exec {empty}<&9; "
       "read -- $empty value <<<payload; printf x >&\"$out\"; }",
       0, true},
      {"exec {out}>out && { unset empty; exec 9<&-; exec {empty}<&9; "
       "read -- \"\"$empty value <<<payload; printf x >&\"$out\"; }",
       0, false},
      {"exec {fd}>out && { read -p\"$fd\" -u3 fd 3<&-; "
       "printf x >&\"$fd\"; }",
       0, false},
      {"{ time printf payload; } 2>&1 | "
       "{ exec {fd}<&0; read -u\"$fd\" value; }",
       SHELL_DEP_FD_NAMED, true},
      {"exec {out}>out && { unset empty; exec 9<&-; exec {empty}<&9; "
       "read -p\"$empty\" out value <<<payload; printf x >&\"$out\"; }",
       0, true},
  };
  const shell_dep_limits_t read_limits = SHELL_DEP_LIMITS_DEFAULT;
  static const struct {
    const char *source, *required, *forbidden;
  } conditional_inputs[] = {
      {"exec <() 3>out; printf reached >&3", "out", nullptr},
      {"(true; exit <()) && printf reached >reached", "reached", nullptr},
      {"(false; builtin exit >()) || printf reached >reached", "reached",
       nullptr},
      {"exec {out}>out && { unset empty; read -n0 other\"$empty\"; "
       "printf kept >&\"$out\"; }",
       "out", nullptr},
      {"exec {fd}<<<saved && read -n-\"$fd\" value <<<payload "
       "&& printf accepted >accepted || printf failed >failed",
       "failed", "accepted"},
      {"read -n-1\"$unknown\" value <<<payload "
       "&& printf accepted >accepted || printf failed >failed",
       "failed", "accepted"},
      {"read -- pre<(printf generated) value <<<payload "
       "&& printf accepted >accepted || printf failed >failed",
       "failed", "accepted"},
      {"read -t0.0000000\"$unknown\" value <<<payload "
       "&& printf accepted >accepted",
       "accepted", nullptr},
      {"unset empty; read -- -p\"$empty\" RANDOM <<<payload "
       "&& printf accepted >accepted || printf failed >failed",
       "failed", "accepted"},
      {"unset fd; read -n\"$fd\" -p\"$fd\" value <<<payload "
       "&& printf accepted >accepted || printf failed >failed",
       "failed", "accepted"},
      {"unset fd; read -u\"$fd\" -n\"$fd\" value <<<payload "
       "&& printf accepted >accepted || printf failed >failed",
       "failed", "accepted"},
      {"target=bad-name; read -n0 first \"$target\" last <<<payload "
       "|| printf fallback >fallback",
       "fallback", nullptr},
      {"value=$(read -N0 first \"$target\" last <<<payload) "
       "|| printf fallback >fallback",
       "fallback", nullptr},
      {"! read -n0 first \"$target\" last <<<payload "
       "&& printf fallback >fallback",
       "fallback", nullptr},
      {"read -n0 first last <<<payload || printf fallback >fallback", nullptr,
       "fallback"},
      {"a=$(true) b=${choice:+$(false)$(true)} || printf fallback >fallback",
       nullptr, "fallback"},
      {"a=$(false) b=${choice:+$(true)$(false)} && printf fallback >fallback",
       nullptr, "fallback"},
      {"exec 3<&-; a=$(true) b=${choice:+$(read -u11 -n0 probe)$(true)} && "
       "{ true 3<&11 || printf fallback >fallback; }",
       "fallback", nullptr},
      {"a=$(false) b=$(\\\n) || printf fallback >fallback", "fallback",
       nullptr},
      {"exec 3<&-; value=${choice:+$(read -u11 -n0 probe)} && "
       "{ true 3<&11 || printf fallback >fallback; }",
       "fallback", nullptr},
      {"exec 3<&-; choice || read -u11 -n0 probe && "
       "{ true 3<&11 || printf fallback >fallback; }",
       "fallback", nullptr},
      {"a=$(false) b=$() || printf fallback >fallback", "fallback", nullptr},
      {"a=$(false) b=$(# comment\n) || printf fallback >fallback", "fallback",
       nullptr},
      {"a=$(false) b=`` || printf fallback >fallback", "fallback", nullptr},
      {"a=$(false) b=` # comment\n` || printf fallback >fallback", nullptr,
       "fallback"},
      {"false; value=$() || printf fallback >fallback", nullptr, "fallback"},
      {"exec 3<&-; a=$(read -u11 -n0 probe) b=$(</dev/null) && "
       "{ true 3<&11 || printf fallback >fallback; }",
       "fallback", nullptr},
      {"exec 3<&-; a=$(read -u11 -n0 probe) b=$() && "
       "{ true 3<&11 || printf fallback >fallback; }",
       nullptr, "fallback"},
      {"value=$(< <()) && printf success >success || printf fallback >fallback",
       "fallback", "success"},
      {"value=$(< >( \n)) && printf success >success || printf fallback "
       ">fallback",
       "fallback", "success"},
      {"value=$(< <(# comment\n)) && printf success >success || printf "
       "fallback >fallback",
       "fallback", "success"},
      {"printf '%s' \"$(< <())\" && printf success >success", "success",
       nullptr},
      {"read -n \"$count\" -u11 -n0 probe 11<<<input || "
       "printf fallback >fallback",
       "fallback", nullptr},
      {"read -N \"$count\" -u11 -N0 probe 11<<<input || "
       "printf fallback >fallback",
       "fallback", nullptr},
      {"read -t \"$timeout\" -t1 -u11 -n0 probe 11<<<input || "
       "printf fallback >fallback",
       "fallback", nullptr},
      {"exec 1>&-; value=$(read -u1 -n0 probe); "
       "true 3>&1 || printf fallback >fallback",
       "fallback", nullptr},
      {"exec 3<&- 4<&- 63<&-; path=${choice:+<(:)} read -u63 -n0 value "
       "|| printf fallback >fallback",
       "fallback", nullptr},
      {"exec 3<&- 4<&- 63<&-; path=${outer:+${inner:+<(:)}} "
       "read -u63 -n0 value || printf fallback >fallback",
       "fallback", nullptr},
      {"exec 3<&- 4<&- 63<&-; "
       "path=${choice:+<(:)$(read -u63 -n0 inner || printf bad >bad)} "
       "read -u63 -n0 value || printf fallback >fallback",
       "fallback", "bad"},
      {"exec 3<&- 4<&- 63<&-; path=<(:) read -u63 -n0 value "
       "|| printf fallback >fallback",
       nullptr, "fallback"},
      {"exec 3<&- 4<&- 63<&-; echo \"$(<prefix<(:))\" "
       "\"$(read -u63 -n0 value || printf fallback >fallback)\"",
       nullptr, "fallback"},
      {"exec 3<&- 4<&- 63<&-; echo \"$(< <(:))\" "
       "\"$(read -u63 -n0 value || printf fallback >fallback)\"",
       nullptr, "fallback"},
  };
  for (const auto &fixture : conditional_inputs) {
    shell_dep_error_t status = shell_dep_graph_parse(
        fixture.source, strlen(fixture.source), nullptr, &read_limits, &graph);
    bool required = fixture.required == nullptr, forbidden = false;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const auto &edge = graph.edges[e];
      const auto &target = graph.nodes[edge.to];
      if (edge.type != SHELL_EDGE_WRITE || target.type != SHELL_NODE_DOC ||
          target.doc.kind != SHELL_DOC_FILE)
        continue;
      if (fixture.required && target.doc.path_len == strlen(fixture.required) &&
          !memcmp(target.doc.path, fixture.required, target.doc.path_len))
        required = true;
      if (fixture.forbidden &&
          target.doc.path_len == strlen(fixture.forbidden) &&
          !memcmp(target.doc.path, fixture.forbidden, target.doc.path_len))
        forbidden = true;
    }
    if (status != SHELL_DEP_OK || !required || forbidden ||
        !shellsplit_test_depgraph_invariants(fixture.source,
                                             strlen(fixture.source), status,
                                             &graph, &read_limits)) {
      fprintf(stderr, "conditional input oracle failed: %s\n", fixture.source);
      shell_dep_graph_dump(&graph, stderr);
      abort();
    }
  }
  for (bool success : {false, true}) {
    std::string source = "exec 3<&- 4<&- 63<&-; : ${choice:+<(printf payload)} "
                         "\"$(read -u63 -n0 first ";
    source += success ? "&&" : "||";
    source += " read -u63 second)\"";
    shell_dep_error_t status = shell_dep_graph_parse(
        source.data(), source.size(), nullptr, &read_limits, &graph);
    bool input = false;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const auto &edge = graph.edges[e];
      const auto &node = graph.nodes[edge.to];
      if (edge.type != SHELL_EDGE_SUBST || node.type != SHELL_NODE_CMD)
        continue;
      for (uint32_t t = 0; t < node.cmd.token_count; t++)
        input |= node.cmd.token_lens[t] == 6 &&
                 !memcmp(node.cmd.tokens[t], "second", 6);
    }
    if (status != SHELL_DEP_OK || input != success ||
        !shellsplit_test_depgraph_invariants(source.data(), source.size(),
                                             status, &graph, &read_limits)) {
      fprintf(stderr, "process descriptor outcome correlation: %s\n",
              source.c_str());
      abort();
    }
  }
  static const struct {
    const char *source;
    uint32_t fd;
    bool input;
  } private_inputs[] = {
      {"exec 3<&- 4<&- 63<&-; : ${choice:+<(printf payload)} "
       "\"$(: | read -u63 -n0 first || read -u63 second)\"",
       63, false},
      {"exec 3<&- 4<&- 63<&-; : ${choice:+<(printf payload)} "
       "\"$(: | read -u63 -n0 first && read -u63 second)\"",
       63, true},
      {"exec 3<&- 4<&- 62<&- 63<&-; : ${choice:+<(printf payload)} "
       "\"$(exec 62<&63; : | { read -u62 -n0 first; } || read -u62 second)\"",
       62, false},
      {"exec 3<&- 4<&- 63<&-; : ${choice:+<(printf payload)} "
       "\"$(: | { read -u63 -n0 first; } && read -u63 second)\"",
       63, false},
  };
  for (const auto &fixture : private_inputs) {
    shell_dep_error_t status = shell_dep_graph_parse(
        fixture.source, strlen(fixture.source), nullptr, &read_limits, &graph);
    bool input = false;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const auto &edge = graph.edges[e];
      const auto &target = graph.nodes[edge.to];
      if (edge.type != SHELL_EDGE_SUBST || target.type != SHELL_NODE_CMD)
        continue;
      for (uint32_t t = 0; t < target.cmd.token_count; t++)
        if (target.cmd.token_lens[t] == 6 &&
            !memcmp(target.cmd.tokens[t], "second", 6)) {
          input = true;
          if (edge.target_fd != fixture.fd ||
              edge.flags != SHELL_DEP_EDGE_FLAG_NONE)
            abort();
        }
    }
    if (status != SHELL_DEP_OK || input != fixture.input ||
        !shellsplit_test_depgraph_invariants(fixture.source,
                                             strlen(fixture.source), status,
                                             &graph, &read_limits)) {
      fprintf(stderr, "private input outcome oracle failed: %s\n",
              fixture.source);
      abort();
    }
  }
  fixed_oracle_phase("allocation routing");
  static const struct {
    const char *source;
    bool payload;
  } allocation_cases[] = {
      {"read -u11 value {fd}<<<payload", true},
      {"exec 3<&-; read -u11 -n0 probe && "
       "read -u11 value {fd}<<<payload",
       false},
      {"exec 3<&-; (read -u11 -n0 probe) && "
       "read -u11 value {fd}<<<payload",
       false},
      {"exec 3<&-; : | read -u11 -n0 probe && "
       "read -u11 value {fd}<<<payload",
       false},
      {"exec 3<&-; : <(:) \"$(read -u3 -n0 probe && "
       "read -u11 value {fd}<<<payload)\"",
       false},
      {"exec 3<&- 11<>/dev/null && exec {a}<<<first && "
       "{ exec 11<&-; : <(:) \"$(read -u3 -n0 probe && "
       "{ exec {a}<&-; read -u11 value {b}<<<payload; })\"; }",
       true},
      {"exec 3<&-; : <(:) \"$(read -u3 -n0 probe && "
       "{ exec 8>&9- && read -u11 value {fd}<<<payload; })\"",
       true}};
  for (const auto &test : allocation_cases) {
    shell_dep_error_t status = shell_dep_graph_parse(
        test.source, strlen(test.source), nullptr, &read_limits, &graph);
    uint32_t reader = UINT32_MAX;
    unsigned readers = 0, payload_inputs = 0;
    bool routing = true, inherited_input = false;
    for (uint32_t n = 0; n < graph.node_count; n++) {
      const auto &node = graph.nodes[n];
      if (node.type != SHELL_NODE_CMD || node.cmd.token_count < 3 ||
          node.cmd.token_lens[0] != 4 || memcmp(node.cmd.tokens[0], "read", 4))
        continue;
      for (uint32_t t = 1; t < node.cmd.token_count; t++)
        if (node.cmd.token_lens[t] == 5 &&
            !memcmp(node.cmd.tokens[t], "value", 5)) {
          reader = n;
          readers++;
        }
    }
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const auto &edge = graph.edges[e];
      bool input = edge.type == SHELL_EDGE_READ ||
                   edge.type == SHELL_EDGE_PIPE ||
                   edge.type == SHELL_EDGE_SUBST;
      if (input && edge.to == reader)
        routing &= edge.target_fd == 11 && !edge.target_fd_name &&
                   !edge.target_fd_name_len &&
                   edge.flags == SHELL_DEP_EDGE_FLAG_NONE;
      const auto &document = graph.nodes[edge.from];
      inherited_input |= input && edge.to == reader &&
                         document.type == SHELL_NODE_FD &&
                         document.fd.number == 11;
      if (!input || document.type != SHELL_NODE_DOC ||
          document.doc.kind != SHELL_DOC_HERESTRING ||
          document.doc.value_len != 7 ||
          memcmp(document.doc.value, "payload", 7))
        continue;
      routing &= edge.to == reader && edge.type == SHELL_EDGE_READ &&
                 edge.source_fd == SHELL_DEP_FD_NONE;
      payload_inputs++;
    }
    if (status != SHELL_DEP_OK || readers != 1 || !routing ||
        (!strcmp(test.source, "read -u11 value {fd}<<<payload") &&
         !inherited_input) ||
        payload_inputs != static_cast<unsigned>(test.payload) ||
        !shellsplit_test_depgraph_invariants(test.source, strlen(test.source),
                                             status, &graph, &read_limits)) {
      fprintf(stderr, "named allocation input route mismatch: %s\n",
              test.source);
      abort();
    }
  }
  fixed_oracle_phase("process lifetime pressure");
  for (bool before : {false, true}) {
    std::string source = "exec 10<&-; ";
    if (!before)
      source += "read -n0 -u63 value <(:) <(:); ";
    for (unsigned i = 0; i < 16; i++)
      source += ": <(:); ";
    if (before)
      source += "read -n0 -u63 value <(:) <(:)";
    shell_dep_error_t status = shell_dep_graph_parse(
        source.data(), source.size(), nullptr, &read_limits, &graph);
    if (status != SHELL_DEP_OK ||
        !shellsplit_test_depgraph_invariants(source.data(), source.size(),
                                             status, &graph, &read_limits)) {
      fprintf(stderr, "process descriptor lifetime pressure: %s\n",
              source.c_str());
      abort();
    }
  }
  for (const char *prefix :
       {"exec 3<<<payload; ", "exec 3<<<payload; time ",
        "exec 3<<<payload; : 0<&-; ", "exec 3<<<payload; (exec 0<&-); ",
        "exec 3<<<payload; exec 0<&-; "
        "exec 0<<<restored && "}) {
    for (unsigned count : {8u, 16u}) {
      std::string source = std::string(prefix) + "cat";
      for (unsigned i = 0; i < count; i++)
        source += " ${v" + std::to_string(i) + ":+<(printf p" +
                  std::to_string(i) + ")}";
      source += "; read -u3 value";
      shell_dep_error_t status = shell_dep_graph_parse(
          source.data(), source.size(), nullptr, &read_limits, &graph);
      unsigned producers = 0;
      for (uint32_t e = 0; e < graph.edge_count; e++) {
        const auto &edge = graph.edges[e];
        const auto &target = graph.nodes[edge.to];
        if (edge.type == SHELL_EDGE_SUBST && target.type == SHELL_NODE_CMD &&
            target.cmd.token_count && target.cmd.token_lens[0] == 3 &&
            !memcmp(target.cmd.tokens[0], "cat", 3))
          producers++;
      }
      if (status != SHELL_DEP_OK || producers != count ||
          !shellsplit_test_depgraph_invariants(source.data(), source.size(),
                                               status, &graph, &read_limits)) {
        fprintf(stderr, "independent process guard oracle failed: %s\n",
                source.c_str());
        shell_dep_graph_dump(&graph, stderr);
        abort();
      }
    }
  }
  std::string occupied;
  for (unsigned fd = 3; fd < 64; fd++) {
    if ((fd - 3) % 8 == 0)
      occupied += "exec";
    occupied += " " + std::to_string(fd) + "<>/dev/null";
    if ((fd - 3) % 8 == 7 || fd == 63)
      occupied += "; ";
  }
  for (const char *value : {"${choice:+<(printf payload)}",
                            "${outer:+${inner:+<(printf payload)}}"}) {
    std::string source = occupied + "exec 0<&-; path=" + value + " read value";
    shell_dep_error_t status = shell_dep_graph_parse(
        source.data(), source.size(), nullptr, &read_limits, &graph);
    bool input = false;
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const auto &edge = graph.edges[e];
      const auto &target = graph.nodes[edge.to];
      input |= edge.type == SHELL_EDGE_SUBST && edge.target_fd == 0 &&
               !(edge.flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD) &&
               target.type == SHELL_NODE_CMD && target.cmd.token_count &&
               target.cmd.token_lens[0] == 4 &&
               !memcmp(target.cmd.tokens[0], "read", 4);
    }
    if (status != SHELL_DEP_OK || !input ||
        !shellsplit_test_depgraph_invariants(source.data(), source.size(),
                                             status, &graph, &read_limits)) {
      fprintf(stderr, "conditional low-pipe oracle failed: %s\n",
              source.c_str());
      shell_dep_graph_dump(&graph, stderr);
      abort();
    }
  }
  for (const auto &fixture : read_inputs) {
    shell_dep_error_t status = shell_dep_graph_parse(
        fixture.source, strlen(fixture.source), nullptr, &read_limits, &graph);
    bool valid = status == SHELL_DEP_OK;
    bool input = false, found = false;
    for (uint32_t node = 0; node < graph.node_count; node++) {
      const auto &owner = graph.nodes[node];
      if (owner.type != SHELL_NODE_CMD || !owner.cmd.effective_command_known)
        continue;
      uint32_t target = owner.cmd.effective_command_token;
      if (owner.cmd.token_lens[target] != 4 ||
          memcmp(owner.cmd.tokens[target], "read", 4))
        continue;
      found = true;
      for (uint32_t e = 0; e < graph.edge_count; e++) {
        const auto &edge = graph.edges[e];
        if (edge.to != node ||
            (edge.type != SHELL_EDGE_READ && edge.type != SHELL_EDGE_PIPE &&
             edge.type != SHELL_EDGE_SUBST))
          continue;
        input = true;
        valid = valid && edge.target_fd == fixture.fd &&
                !(edge.flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD);
      }
    }
    if (!valid || !found || input != fixture.input ||
        !shellsplit_test_depgraph_invariants(fixture.source,
                                             strlen(fixture.source), status,
                                             &graph, &read_limits)) {
      fprintf(stderr, "read input oracle failed: %s\n", fixture.source);
      shell_dep_graph_dump(&graph, stderr);
      abort();
    }
  }
  fixed_oracle_phase("boundary routing");
  static const struct {
    const char *source;
    uint32_t nodes, edges;
  } terminal_capacity[] = {
      {"exec 3>&-; echo 2>&1 >&3 | cat <input", 5, 3},
      {"exec 3>&-; { echo 2>&1 >&3; } | cat <input", 6, 4},
      {"echo | : <&-", 3, 1},
      {"{ time echo; } 2>&1 | cat <input", 7, 3},
  };
  for (const auto &fixture : terminal_capacity) {
    shell_dep_limits_t limits = SHELL_DEP_LIMITS_DEFAULT;
    limits.max_nodes = fixture.nodes;
    limits.max_edges = fixture.edges;
    shell_dep_error_t status = shell_dep_graph_parse(
        fixture.source, strlen(fixture.source), nullptr, &limits, &graph);
    if (status != SHELL_DEP_ETRUNC ||
        !shellsplit_test_depgraph_invariants(
            fixture.source, strlen(fixture.source), status, &graph, &limits)) {
      fprintf(stderr, "terminal-pipe capacity oracle failed: %s\n",
              fixture.source);
      shell_dep_graph_dump(&graph, stderr);
      abort();
    }
  }
  static const struct {
    const char *source;
    bool capture;
  } setup_diagnostics[] = {
      {"exec 3>&-; sh -c \"$(echo 2>&1 >&3)\"", true},
      {"exec 3>&-; sh -c \"$(echo >&3 2>&1)\"", false},
      {"exec 3>&-; sh -c \"$({ echo body; } 2>&1 >&3)\"", true},
      {"exec 3>&-; sh -c \"$(false && echo 2>&1 >&3)\"", false},
      {"exec 3>&-; cat <(echo 2>&1 >&3)", true},
      {"sh -c \"$(exec 2>&1; x=${missing:?expansion-marker})\"", true},
      {"sh -c \"$(exec 2>&1; x=$((1/0)))\"", true},
      {"sh -c \"$(exec 2>&1; : ${missing:?expansion-marker} 1>&- 2>&-)\"",
       true},
      {"sh -c \"$(: 2>&1 >${missing:?expansion-marker})\"", true},
      {"sh -c \"$(: >${missing:?expansion-marker} 2>&1)\"", false},
      {"sh -c \"$(exec 2>&1; false 1>&- 2>&- && x=$((1/0)))\"", false},
      {"sh -c \"$(x=1)\"", false},
      {"sh -c \"$(exec 2>&1; x=$(<input))\"", true},
      {"sh -c \"$(exec 2>&1; x=$(<''))\"", true},
      {"sh -c \"$(exec 2>&1; x=$(< <(true 1>&- 2>&-)))\"", true},
      {"sh -c \"$(: 2>&1 >$(<input) 1>&- 2>&-)\"", true},
  };
  for (const auto &fixture : setup_diagnostics) {
    shell_dep_error_t status = shell_dep_graph_parse(
        fixture.source, strlen(fixture.source), nullptr, nullptr, &graph);
    bool capture = false;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      capture |= graph.edges[edge].type == SHELL_EDGE_SUBST &&
                 graph.edges[edge].source_fd == 2;
    if (status != SHELL_DEP_OK || !shell_dep_graph_validate(&graph).valid ||
        capture != fixture.capture) {
      fprintf(stderr, "setup diagnostic oracle failed: %s\n", fixture.source);
      shell_dep_graph_dump(&graph, stderr);
      abort();
    }
  }
  static const char diagnostic_redirect_opener[] =
      "while IFS= read -r line; do echo \"$line\"; done < input(\n";
  if (test_tokenizer_state(diagnostic_redirect_opener,
                           sizeof(diagnostic_redirect_opener) - 1)) {
    fputs("diagnostic redirect-opener oracle failed\n", stderr);
    abort();
  }
  static const struct {
    const char *source;
    bool capture;
  } cd_captures[] = {
      {"sh -c \"$(exec 2>&1; cd one two)\"", true},
      {"sh -c \"$(cd /; cd -)\"", true},
      {"sh -c \"$({ exec 2>&1; cd one two; })\"", true},
      {"sh -c \"$(exec 1>&- 2>&-; cd one two)\"", false},
      {"sh -c \"$(false >&- 2>&- && cd one two)\"", false},
  };
  for (const auto &fixture : cd_captures) {
    shell_dep_error_t status = shell_dep_graph_parse(
        fixture.source, strlen(fixture.source), nullptr, nullptr, &graph);
    bool capture = false, cd = false;
    for (uint32_t node = 0; node < graph.node_count; node++)
      cd |= graph.nodes[node].type == SHELL_NODE_CMD &&
            graph.nodes[node].cmd.token_count &&
            graph.nodes[node].cmd.token_lens[0] == 2 &&
            !memcmp(graph.nodes[node].cmd.tokens[0], "cd", 2);
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      capture |= graph.edges[edge].type == SHELL_EDGE_SUBST;
    if (status != SHELL_DEP_OK || !shell_dep_graph_validate(&graph).valid ||
        !cd || capture != fixture.capture) {
      fprintf(stderr, "cd capture oracle failed: %s\n", fixture.source);
      shell_dep_graph_dump(&graph, stderr);
      abort();
    }
  }
  static const struct {
    const char *source;
    bool capture;
  } assignment_captures[] = {
      {"sh -c \"$(x=1)\"", false},
      {"sh -c \"$(UID=1 2>&1)\"", false},
      {"sh -c \"$(exec 2>&1; UID=1)\"", true},
      {"sh -c \"$(exec 2>&1; UID=1 true 1>&- 2>&-)\"", true},
      {"sh -c \"$(exec 1>&- 2>&-; UID=1)\"", false},
      {"sh -c \"$(UID=$(printf skipped) true 1>&- 2>&-)\"", false},
  };
  for (const auto &fixture : assignment_captures) {
    shell_dep_error_t status = shell_dep_graph_parse(
        fixture.source, strlen(fixture.source), nullptr, nullptr, &graph);
    bool capture = false;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++)
      capture |=
          graph.edges[edge].type == SHELL_EDGE_SUBST &&
          graph.edges[edge].to == 0 &&
          (graph.edges[edge].flags & SHELL_DEP_EDGE_FLAG_SUBST_SHELL_WORD);
    if (status != SHELL_DEP_OK || !shell_dep_graph_validate(&graph).valid ||
        capture != fixture.capture) {
      fprintf(stderr, "assignment capture oracle failed: %s\n", fixture.source);
      shell_dep_graph_dump(&graph, stderr);
      abort();
    }
  }
  static const struct {
    const char *source;
    uint32_t environments, substitutions;
  } assignment_effects[] = {
      {"UID=1 true", 0, 0},
      {"UID=1 EUID+=2 command true", 0, 0},
      {"UID=1 x=2 true", 1, 0},
      {"export 'U''ID=1' x=2", 1, 0},
      {"export -Z x=2", 0, 0},
      {"UID=$(printf skipped) true", 0, 0},
      {"UID=$(printf data) $missing", 0, 1},
      {"UID=$(printf data) $(true)", 0, 2},
      {"UID=$(printf data) \"$@\"", 0, 1},
      {"UID=$(printf data) \"${!prefix@}\"", 0, 1},
      {"UID=$(printf data) \"${@:+data}\"", 0, 1},
      {"UID=$(printf skipped) \"${!prefix*}\"", 0, 0},
      {"UID=$(printf skipped) \"${@:-data}\"", 0, 0},
      {"UID=$(printf skipped) \"${@:-}\"", 0, 0},
      {"UID=$(printf skipped) \"${@:?error}\"", 0, 0},
      {"UID=$(printf skipped) \"$missing\"", 0, 0},
      {"UID=$(printf skipped) $missing true", 0, 0},
      {"UID=$(printf skipped) $missing-suffix", 0, 0},
      {"export UID=$(printf data)", 0, 1},
  };
  for (const auto &fixture : assignment_effects) {
    shell_dep_error_t status = shell_dep_graph_parse(
        fixture.source, strlen(fixture.source), nullptr, nullptr, &graph);
    uint32_t environments = 0, substitutions = 0;
    for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
      environments += graph.edges[edge].type == SHELL_EDGE_ENV;
      substitutions += graph.edges[edge].type == SHELL_EDGE_SUBST;
    }
    if (status != SHELL_DEP_OK || environments != fixture.environments ||
        substitutions != fixture.substitutions) {
      fputs("rejected assignment ENV effect mismatch\n", stderr);
      abort();
    }
  }
  static const char *const timed_group_lines[] = {
      "time (\nwc\n)",
      "time {\nwc;\n}",
      "while true; do :; done; time (\nwc\n)",
      "while true; do :; done; time {\nwc;\n}",
  };
  for (const char *source : timed_group_lines)
    if (test_tokenizer_state(source, strlen(source))) {
      fputs("timed-group newline oracle failed\n", stderr);
      abort();
    }
  static const struct {
    const char *source;
    bool wc_null;
  } async_inputs[] = {
      {"wc -c &", true},
      {"wc -c &\n", true},
      {"wc -c &\nwait", true},
      {"wc -c & # note\n\nwait", true},
      {"time wc -c &\nwait", true},
      {"true && wc -c &\nwait", true},
      {"false || wc -c &\nwait", true},
      {"printf '%s' \"$(wc -c &\nwait)\"", true},
      {"cat <(wc -c &\nwait)", true},
      {"wc -c 3<<EOF &\nbody\nEOF\nwait", false},
      {"wc -c <&0 &", false},
      {"wc -c 3</dev/null &", false},
      {"printf '%s' \"$(wc -c)\" &", false},
      {"time printf '%s' \"$(wc -c)\" &", true},
      {"true && printf '%s' \"$(wc -c)\" &", true},
      {": 3>\"$(wc -c >&2; printf /dev/null)\" &", true},
      {"UID=1\ntime wc -c & wait", true},
      {"UID=1\ntrue && wc -c & wait", true},
      {"UID=1\ntrue && printf '%s' \"$(wc -c)\" & wait", true},
      {"UID=1; time wc -c & wait", false},
      {"UID=1; : &\nwc -c &\nwait", true},
      {"exit 0\ntime wc -c & wait", false},
  };
  for (const auto &fixture : async_inputs) {
    shell_dep_error_t status = shell_dep_graph_parse(
        fixture.source, strlen(fixture.source), nullptr, nullptr, &graph);
    bool valid =
        status == SHELL_DEP_OK && shell_dep_graph_validate(&graph).valid;
    bool found = false;
    for (uint32_t edge = 0; valid && edge < graph.edge_count; edge++) {
      const auto &item = graph.edges[edge];
      const auto &source = graph.nodes[item.from];
      const auto &target = graph.nodes[item.to];
      if (item.type == SHELL_EDGE_READ && item.target_fd == 0 &&
          source.type == SHELL_NODE_DOC &&
          (source.doc.flags & SHELL_DEP_DOC_FLAG_IMPLICIT) &&
          target.type == SHELL_NODE_CMD && target.cmd.token_count &&
          target.cmd.token_lens[0] == 2 &&
          !memcmp(target.cmd.tokens[0], "wc", 2))
        found = true;
    }
    if (!valid || found != fixture.wc_null) {
      fprintf(stderr, "asynchronous stdin oracle failed: %s\n", fixture.source);
      shell_dep_graph_dump(&graph, stderr);
      abort();
    }
  }
  static const struct {
    const char *source;
    bool reached;
  } async_completion[] = {
      {"{ false & } || printf bad >out", false},
      {"{ false & } && printf good >out", true},
      {"{ false && true & } || printf bad >out", false},
      {"{ { false; } & } || printf bad >out", false},
      {"(false &) || printf bad >out", false},
      {"{ { false & }; } || printf bad >out", false},
      {"! { false & } && printf bad >out", false},
      {"time { false & } || printf bad >out", false},
      {"echo \"$( { false & } || printf bad >out )\"", false},
      {"{ true & false; } || printf good >out", true},
  };
  for (const auto &fixture : async_completion) {
    shell_dep_error_t status = shell_dep_graph_parse(
        fixture.source, strlen(fixture.source), nullptr, nullptr, &graph);
    bool valid =
        status == SHELL_DEP_OK && shell_dep_graph_validate(&graph).valid;
    bool found = false, effects = false;
    for (uint32_t node = 0; valid && node < graph.node_count; node++) {
      const auto &command = graph.nodes[node];
      if (command.type != SHELL_NODE_CMD || !command.cmd.token_count ||
          command.cmd.token_lens[0] != 6 ||
          memcmp(command.cmd.tokens[0], "printf", 6))
        continue;
      found = true;
      for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
        const auto &item = graph.edges[edge];
        effects |= (item.type == SHELL_EDGE_READ && item.to == node) ||
                   (item.type == SHELL_EDGE_WRITE && item.from == node);
      }
    }
    if (!valid || !found || effects != fixture.reached) {
      fprintf(stderr, "asynchronous completion oracle failed: %s\n",
              fixture.source);
      shell_dep_graph_dump(&graph, stderr);
      abort();
    }
  }
  static const char *const background_isolation[] = {
      "exec 0<&- && true &\ncat", "exec 0<&- && true & # note\n\ncat",
      "cd /tmp && true &\ncat", "exec 0<&- && true &\ncd /tmp && true &\ncat"};
  for (const char *source : background_isolation) {
    shell_dep_error_t status =
        shell_dep_graph_parse(source, strlen(source), "/", nullptr, &graph);
    bool valid =
        status == SHELL_DEP_OK && shell_dep_graph_validate(&graph).valid;
    bool inherited_stdin = false, background = false;
    for (uint32_t node = 0; valid && node < graph.node_count; node++) {
      const auto &command = graph.nodes[node];
      if (command.type != SHELL_NODE_CMD || !command.cmd.token_count ||
          command.cmd.token_lens[0] != 3 ||
          memcmp(command.cmd.tokens[0], "cat", 3))
        continue;
      valid = command.cmd.cwd_known &&
              !strcmp(graph.cwd_buf.data + command.cmd.cwd_offset, "/");
      for (uint32_t edge = 0; edge < graph.edge_count; edge++) {
        const auto &item = graph.edges[edge];
        if (item.to != node)
          continue;
        background |= item.type == SHELL_EDGE_BACKGROUND;
        if (item.type == SHELL_EDGE_READ && item.target_fd == 0) {
          const auto &resource = graph.nodes[item.from];
          valid &= resource.type == SHELL_NODE_FD && resource.fd.number == 0;
          inherited_stdin = true;
        }
      }
    }
    if (!valid || !inherited_stdin || !background) {
      fprintf(stderr, "background isolation oracle failed: %s\n", source);
      shell_dep_graph_dump(&graph, stderr);
      abort();
    }
  }
  static const struct {
    const char *source;
    uint32_t inherited;
  } boundaries[] = {{"wc -l file.txt", 2},
                    {"wc -l file.txt 2>&1", 1},
                    {"wc -l file.txt 2>&1 >out", 1},
                    {"exec {fd}>&1; wc 2>&$fd", 1},
                    {"time wc 2>&1", 1}};
  for (const auto &fixture : boundaries) {
    shell_dep_error_t status = shell_dep_graph_parse(
        fixture.source, strlen(fixture.source), nullptr, nullptr, &graph);
    if (status != SHELL_DEP_OK || !shell_dep_graph_validate(&graph).valid) {
      fprintf(stderr, "boundary oracle parse failed: %s (%d)\n", fixture.source,
              status);
      shell_dep_graph_dump(&graph, stderr);
      abort();
    }
    bool found = false;
    for (uint32_t i = 0; i < graph.edge_count; i++) {
      const auto &edge = graph.edges[i];
      const auto &owner = graph.nodes[edge.from];
      const auto &target = graph.nodes[edge.to];
      if (edge.type == SHELL_EDGE_WRITE && edge.source_fd == 2 &&
          owner.type == SHELL_NODE_CMD && owner.cmd.token_count &&
          owner.cmd.token_lens[0] == 2 &&
          !memcmp(owner.cmd.tokens[0], "wc", 2) &&
          target.type == SHELL_NODE_FD && target.fd.number == fixture.inherited)
        found = true;
    }
    if (!found) {
      fprintf(stderr, "boundary oracle route failed: %s\n", fixture.source);
      abort();
    }
  }
  static const struct {
    const char *source;
    uint32_t fd, inherited;
    bool input;
  } standard_directions[] = {
      {"wc 0>&1", 0, 1, false},     {"wc 1<&0", 1, 0, true},
      {"wc 2<&0", 2, 0, true},      {"wc 0>&1 1>&-", 0, 1, false},
      {"wc 1<&0 0<&-", 1, 0, true}, {"echo \"$(wc 1<&0)\"", 1, 0, true},
  };
  for (const auto &fixture : standard_directions) {
    shell_dep_error_t status = shell_dep_graph_parse(
        fixture.source, strlen(fixture.source), nullptr, nullptr, &graph);
    bool valid =
        status == SHELL_DEP_OK && shell_dep_graph_validate(&graph).valid;
    unsigned found = 0;
    for (uint32_t edge = 0; valid && edge < graph.edge_count; edge++) {
      const auto &item = graph.edges[edge];
      const auto &owner = graph.nodes[fixture.input ? item.to : item.from];
      const auto &resource = graph.nodes[fixture.input ? item.from : item.to];
      if (item.type == (fixture.input ? SHELL_EDGE_READ : SHELL_EDGE_WRITE) &&
          (fixture.input ? item.target_fd : item.source_fd) == fixture.fd &&
          owner.type == SHELL_NODE_CMD && owner.cmd.token_count &&
          owner.cmd.token_lens[0] == 2 &&
          !memcmp(owner.cmd.tokens[0], "wc", 2)) {
        valid = resource.type == SHELL_NODE_FD &&
                resource.fd.number == fixture.inherited;
        found++;
      }
    }
    if (!valid || found != 1) {
      fprintf(stderr, "standard direction oracle failed: %s\n", fixture.source);
      abort();
    }
  }
  bool reachable[256] = {};
  bool single_byte_selectors[descriptor_move_single_byte_selector_count] = {};
  for (unsigned first = 6; first < 256; first += 8) {
    uint8_t input[2] = {(uint8_t)first, 0};
    single_byte_selectors[descriptor_move_selector(input, 1)] = true;
    for (unsigned second = 0; second < 256; second++) {
      input[1] = (uint8_t)second;
      reachable[descriptor_move_selector(input, 2)] = true;
    }
  }
  for (bool reached : single_byte_selectors)
    if (!reached)
      abort();
  for (bool reached : reachable)
    if (!reached)
      abort();
  /* Every selector remains reachable above. Many selectors render the exact
   * same program with the same form-specific oracle; verify each such pair
   * once at startup, not several times after expensive descriptor analysis.
   * Keying on both values preserves differing expectations for equal source.
   */
  fixed_oracle_phase("descriptor moves");
  std::set<std::pair<unsigned, std::string>> move_cases;
  for (unsigned i = 0; i < 256; i++) {
    char input[512];
    descriptor_move_source(static_cast<uint8_t>(i), input);
    if (move_cases.emplace(i % descriptor_move_form_count, input).second &&
        test_descriptor_move(static_cast<uint8_t>(i), input))
      abort();
  }
  fixed_oracle_phase("word and syntax matrices");
  for (const auto &fixture : shellsplit_test_word_bytes) {
    char source[256], expected[256];
    int length =
        snprintf(source, sizeof(source), "printf %%s %s", fixture.word);
    int encoded = snprintf(expected, sizeof(expected), "6:printf,2:%%s,%zu:%s,",
                           strlen(fixture.value), fixture.value);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(source) ||
        encoded <= 0 || static_cast<size_t>(encoded) >= sizeof(expected))
      abort();
    shell_parse_result_t parsed = {};
    shell_processed_commands_t processed = {};
    shell_netstring_buffer_t argv = {};
    bool valid =
        shell_parse_fast(source, length, nullptr, &parsed) == SHELL_OK &&
        parsed.count == 1 &&
        !(parsed.cmds[0].features &
          (SHELL_FEAT_LOOPS | SHELL_FEAT_CONDITIONALS | SHELL_FEAT_CASE)) &&
        shell_process_commands(source, length, nullptr, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == 1;
    if (valid)
      valid = shell_render_netargv_buffer(&processed.commands[0], nullptr,
                                          &argv) == SHELL_PROCESS_OK &&
              argv.length == static_cast<size_t>(encoded) &&
              !memcmp(argv.data, expected, argv.length) &&
              shell_dep_graph_parse(source, length, "/workspace", nullptr,
                                    &graph) == SHELL_DEP_OK &&
              shell_dep_graph_validate(&graph).valid;
    shell_netstring_buffer_free(&argv);
    shell_processed_commands_free(&processed);
    if (!valid) {
      fprintf(stderr, "literal word byte oracle failed: %s\n", source);
      abort();
    }
  }
  {
    static const char *const lists[] = {
        "printf 'é\\'; cat file; printf 'a\\'",
        "printf '\xe9\\'\ncat file\nprintf 'a\\'",
    };
    for (const char *source : lists) {
      shell_processed_commands_t processed = {};
      shell_transformed_command_t **transformed = nullptr;
      size_t count = 0;
      bool valid = shell_process_commands(source, strlen(source), nullptr,
                                          &processed) == SHELL_PROCESS_OK &&
                   processed.command_count == 3 &&
                   shell_transform_command_line(source, strlen(source), nullptr,
                                                &transformed,
                                                &count) == SHELL_TRANSFORM_OK &&
                   count == 3;
      if (valid)
        for (size_t i = 0; i < count; ++i)
          valid &= processed.commands[i].command_token_count == 2 &&
                   transformed[i]->token_count == (i == 2 ? 2 : 3) &&
                   !strcmp(transformed[i]->tokens[0].original,
                           i == 1 ? "cat" : "printf");
      shell_transformed_command_list_free(transformed, count);
      shell_processed_commands_free(&processed);
      if (!valid) {
        fprintf(stderr, "quoted backslash command boundary oracle failed: %s\n",
                source);
        abort();
      }
    }
  }
  {
    const struct {
      const char *source;
      shell_source_status_t status;
    } cases[] = {
        {"printf ok", SHELL_SOURCE_COMPLETE},
        {"cat <<<<x", SHELL_SOURCE_INVALID},
        {"{ :; } <<<>x", SHELL_SOURCE_INVALID},
        {"echo $(: >>&x)", SHELL_SOURCE_INVALID},
        {": {fd}>|out", SHELL_SOURCE_COMPLETE},
        {": <<<<(:)", SHELL_SOURCE_COMPLETE},
        {"a[1 + 2]=x", SHELL_SOURCE_COMPLETE},
        {"v=0; a[${v:-]}]=x", SHELL_SOURCE_COMPLETE},
        {"a[${v:-]} + (2)]=x", SHELL_SOURCE_COMPLETE},
        {"a[<(printf ]) + (2)]=x", SHELL_SOURCE_COMPLETE},
        {"a[>(printf [) + (2)]=x", SHELL_SOURCE_COMPLETE},
        {"a[1 + 2]=x a=(x)", SHELL_SOURCE_UNSUPPORTED},
        {"a[1 + 2]=x : a=(x)", SHELL_SOURCE_INVALID},
        {"echo a[1 + 2]=x", SHELL_SOURCE_COMPLETE},
        {"time <<<x {", SHELL_SOURCE_COMPLETE},
        {"{ : <<<x }; }", SHELL_SOURCE_COMPLETE},
        {": <<'Q' {\npayload\nQ\n", SHELL_SOURCE_COMPLETE},
        {"cat <<'EOF'\né\nEOF\ncat <<\n", SHELL_SOURCE_INVALID},
        {"cat <<'é'\né\ncat <<#comment", SHELL_SOURCE_INVALID},
        {"cat <<'EOF'\né\nEOF\ncat <<", SHELL_SOURCE_INCOMPLETE},
        {"cat <<'EOF'\né\nEOF\ncat <<\nprintf é", SHELL_SOURCE_INVALID},
        {"cat <<'EOF'\né\nEOF\ncat <<\nprintf $'é'", SHELL_SOURCE_UNSUPPORTED},
        {"echo before #comment \\\necho after", SHELL_SOURCE_COMPLETE},
        {": #comment \\\na=(x)", SHELL_SOURCE_UNSUPPORTED},
        {": #comment \\\n{ :; }", SHELL_SOURCE_COMPLETE},
        {": |\ntime {", SHELL_SOURCE_COMPLETE},
        {": |& time {", SHELL_SOURCE_COMPLETE},
        {": |&\ntime :", SHELL_SOURCE_INVALID},
        {": |\n\ntime :", SHELL_SOURCE_INVALID},
        {"echo $(: |&\ntime :)", SHELL_SOURCE_INVALID},
        {"cat /workspace/before.txt\ncat <<\ncat /workspace/not-a-read.txt",
         SHELL_SOURCE_INVALID},
        {"printf '%s' '日本'", SHELL_SOURCE_COMPLETE},
        {"printf '%s' 日本", SHELL_SOURCE_COMPLETE},
        {"printf '%s' $'日本'", SHELL_SOURCE_UNSUPPORTED},
        {"if true; then :; fi", SHELL_SOURCE_UNSUPPORTED},
        {"foo.bar() { :; }", SHELL_SOURCE_UNSUPPORTED},
        {"echo $[1 + (2)]", SHELL_SOURCE_UNSUPPORTED},
        {"cat <<", SHELL_SOURCE_INCOMPLETE},
        {"cat <<EOF\npayload\n", SHELL_SOURCE_INCOMPLETE},
        {"echo ${x!}", SHELL_SOURCE_UNSUPPORTED},
        {"printf ok > !", SHELL_SOURCE_COMPLETE},
        {"{ printf ok; } > !", SHELL_SOURCE_COMPLETE},
        {"printf ok <<< !", SHELL_SOURCE_COMPLETE},
        {"!", SHELL_SOURCE_UNSUPPORTED},
        {"!; :", SHELL_SOURCE_UNSUPPORTED},
        {"! &", SHELL_SOURCE_UNSUPPORTED},
        {"echo `!`", SHELL_SOURCE_UNSUPPORTED},
        {"echo $(!)", SHELL_SOURCE_INVALID},
        {"echo $(!", SHELL_SOURCE_INCOMPLETE},
        {"echo a=(x)", SHELL_SOURCE_INVALID},
        {"a=(", SHELL_SOURCE_UNSUPPORTED},
        {"a=\\\n(x)", SHELL_SOURCE_UNSUPPORTED},
        {"declare a=(x)", SHELL_SOURCE_UNSUPPORTED},
        {"declare >out a=(x)", SHELL_SOURCE_INVALID},
        {"de\"clare\" a=(x)", SHELL_SOURCE_INVALID},
        {"command declare a=(x)", SHELL_SOURCE_INVALID},
        {"echo \"$((1+))\"", SHELL_SOURCE_COMPLETE},
        {"echo \\$(whoami)", SHELL_SOURCE_INVALID},
        {"echo \\$((1+2))", SHELL_SOURCE_INVALID},
        {"echo \"\\$(whoami)\"", SHELL_SOURCE_COMPLETE},
        {"echo \\$\\(whoami\\)", SHELL_SOURCE_COMPLETE},
        {"echo \\\\$(whoami)", SHELL_SOURCE_COMPLETE},
        {"a[0]=x a=(x)", SHELL_SOURCE_UNSUPPORTED},
        {"a[0]=x\"\" declare a=(x)", SHELL_SOURCE_UNSUPPORTED},
        {"a[0]=x : a=(x)", SHELL_SOURCE_INVALID},
        {"a[1 + (", SHELL_SOURCE_UNSUPPORTED},
        {"a[1 + (2)]", SHELL_SOURCE_UNSUPPORTED},
        {"a=(x\\ y)", SHELL_SOURCE_UNSUPPORTED},
        {"declare a=(x\\ y)", SHELL_SOURCE_UNSUPPORTED},
        {"a[\\(]=(x", SHELL_SOURCE_UNSUPPORTED},
        {"declare a[1 + 2]=x", SHELL_SOURCE_COMPLETE},
        {"declare a[1 + (2)]=x", SHELL_SOURCE_INVALID},
        {">out {", SHELL_SOURCE_COMPLETE},
        {"2>&1 {", SHELL_SOURCE_COMPLETE},
        {">out { :; }", SHELL_SOURCE_INVALID},
        {"echo $(: <<EOF)", SHELL_SOURCE_UNSUPPORTED},
        {"echo `: <<EOF\npayload\n`", SHELL_SOURCE_UNSUPPORTED},
        {"echo `: <<EOF; !`", SHELL_SOURCE_UNSUPPORTED},
        {"echo $(: <<)", SHELL_SOURCE_INVALID},
        {"echo $(: <<EOF &&)", SHELL_SOURCE_INVALID},
        {"echo $(: <<EOF >)", SHELL_SOURCE_INVALID},
    };
    auto *draft = static_cast<shell_source_result_t *>(
        malloc(sizeof(shell_source_result_t)));
    if (draft) {
      for (const auto &fixture : cases) {
        if (shell_parse_draft(fixture.source, strlen(fixture.source), nullptr,
                              draft) != fixture.status) {
          fprintf(stderr, "source classification oracle failed: %s\n",
                  fixture.source);
          abort();
        }
        if (fixture.status == SHELL_SOURCE_COMPLETE)
          for (uint32_t h = 0; h < draft->header_count; ++h)
            if (!draft->headers[h].complete) {
              fprintf(stderr, "complete source has unfinished header: %s\n",
                      fixture.source);
              abort();
            }
      }
      for (const char *source :
           {"a[1 + (2)]=x", "a[$(printf 1) + (2)]=x", "a[${v:-]} + (2)]=x",
            "a[<(printf ]) + (2)]=x", "a\\\n[$\\\n{v:-]} + (2)]\\\n=\\\nx"}) {
        for (size_t end = 0; end <= strlen(source); ++end) {
          if (shell_parse_draft(source, end, nullptr, draft) ==
              SHELL_SOURCE_INVALID) {
            fprintf(stderr, "false INVALID indexed prefix: %.*s\n", (int)end,
                    source);
            abort();
          }
        }
      }
      static const char declaration[] = "declare a[1 + 2]=x";
      if (shell_parse_draft(declaration, sizeof(declaration) - 1, nullptr,
                            draft) != SHELL_SOURCE_COMPLETE ||
          draft->headers[0].word_count != 4 ||
          draft->headers[0].words[1].length != 3) {
        fputs("declaration operand boundary oracle failed\n", stderr);
        abort();
      }
      free(draft);
    }
  }
  for (const auto &fixture : shellsplit_test_array_prefixes) {
    size_t length = strlen(fixture.source);
    shell_parse_result_t parsed = {};
    shell_limits_t strict = SHELL_LIMITS_DEFAULT;
    strict.strict_mode = true;
    bool valid =
        shell_parse_fast(fixture.source, length, &strict, &parsed) == SHELL_OK;
    uint32_t features = 0;
    for (uint32_t i = 0; i < parsed.count; i++)
      features |= parsed.cmds[i].features;
    shell_processed_commands_t processed = {};
    valid =
        valid && !!(features & SHELL_FEAT_ARRAY) == fixture.array &&
        !!(features & SHELL_FEAT_GLOBS) == fixture.glob &&
        shell_process_commands(fixture.source, length, nullptr, &processed) ==
            (fixture.array ? SHELL_PROCESS_EPARSE : SHELL_PROCESS_OK) &&
        shell_dep_graph_parse(fixture.source, length, nullptr, nullptr,
                              &graph) ==
            (fixture.array ? SHELL_DEP_EPARSE : SHELL_DEP_OK) &&
        (fixture.array ? graph.node_count == 0 && graph.edge_count == 0
                       : shell_dep_graph_validate(&graph).valid);
    shell_processed_commands_free(&processed);
    if (!valid) {
      fprintf(stderr, "array prefix oracle failed: %s\n", fixture.source);
      abort();
    }
  }
  for (const auto &fixture : shellsplit_test_scoped_expansions) {
    size_t length = strlen(fixture.source);
    shell_parse_result_t parsed = {};
    shell_netstring_buffer_t raw = {}, type = {};
    size_t stages = 0;
    shell_process_status_t status = shell_build_anomaly_netseqs_buffer(
        fixture.source, length, nullptr, &raw, &type, &stages);
    bool valid =
        shell_parse_fast(fixture.source, length, nullptr, &parsed) == SHELL_OK;
    uint32_t features = 0;
    for (uint32_t i = 0; i < parsed.count; i++)
      features |= parsed.cmds[i].features;
    valid = valid &&
            (features & shellsplit_test_expansion_feature_mask) ==
                fixture.features &&
            status ==
                (fixture.supported ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE) &&
            stages == fixture.stages;
    shell_netstring_buffer_free(&raw);
    shell_netstring_buffer_free(&type);
    if (!valid) {
      fprintf(stderr, "heredoc expansion oracle failed: %s\n", fixture.source);
      abort();
    }
  }
  for (const auto &fixture : shellsplit_test_quoted_arithmetic) {
    size_t length = strlen(fixture.source);
    shell_parse_result_t parsed = {};
    shell_processed_commands_t processed = {};
    shell_process_status_t status =
        shell_process_commands(fixture.source, length, NULL, &processed);
    bool valid =
        shell_parse_fast(fixture.source, length, NULL, &parsed) == SHELL_OK &&
        ((parsed.cmds[0].features & SHELL_FEAT_ARITH) != 0) ==
            fixture.arithmetic &&
        status ==
            (fixture.supported ? SHELL_PROCESS_OK : SHELL_PROCESS_EPARSE) &&
        (fixture.supported
             ? processed.command_count == 1
             : processed.command_count == 0 && !processed.commands);
    shell_processed_commands_free(&processed);
    if (!valid) {
      fprintf(stderr, "quoted arithmetic oracle failed: %s\n", fixture.source);
      abort();
    }
  }
  for (const auto &fixture : shellsplit_test_expansion_features) {
    shell_abstract_command_t *abstract = nullptr;
    bool valid =
        shell_abstract_command_parse(fixture.source, strlen(fixture.source),
                                     &abstract) == SHELL_ABSTRACT_OK;
    if (valid) {
      valid = abstract->has_variables == fixture.variables &&
              abstract->has_pos_vars == fixture.positional &&
              abstract->has_special_vars == fixture.special &&
              abstract->has_arithmetic == fixture.arithmetic &&
              abstract->has_cmd_subst == fixture.substitution &&
              abstract->has_globs == fixture.glob &&
              strcmp(abstract->display_text, fixture.display) == 0;
      for (size_t j = 1; j < abstract->element_count; j++)
        valid = valid &&
                abstract->elements[j - 1]->end <= abstract->elements[j]->start;
    }
    shell_abstract_command_free(abstract);
    if (!valid) {
      fprintf(stderr, "expansion feature oracle failed: %s\n", fixture.source);
      abort();
    }
  }
  for (const auto &fixture : shellsplit_test_glob_words) {
    char source[256];
    int length = snprintf(source, sizeof(source), "echo %s", fixture.word);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(source) ||
        shell_source_word_has_glob(fixture.word, strlen(fixture.word)) !=
            fixture.glob ||
        (shell_classify_raw_token(fixture.word, strlen(fixture.word)) ==
         SHELL_TOKEN_GLOB) != fixture.glob ||
        test_tokenizer_state(source, static_cast<size_t>(length)))
      abort();
  }
  for (const auto &fixture : shellsplit_test_tilde_words) {
    size_t length = strlen(fixture.word), decoded = 0;
    std::string source = std::string("echo >") + fixture.word;
    bool valid = shell_visit_static_word(fixture.word, length, nullptr, nullptr,
                                         &decoded) != fixture.generic_dynamic &&
                 shell_dep_graph_parse(source.data(), source.size(), ".",
                                       nullptr, &graph) == SHELL_DEP_OK &&
                 shell_dep_graph_validate(&graph).valid;
    size_t files = 0;
    for (uint32_t n = 0; valid && n < graph.node_count; n++) {
      const auto &node = graph.nodes[n];
      if (node.type != SHELL_NODE_DOC || node.doc.kind != SHELL_DOC_FILE)
        continue;
      files++;
      valid = node.doc.path_len == length &&
              !std::memcmp(node.doc.path, fixture.word, length) &&
              ((node.doc.flags & SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) != 0) ==
                  fixture.argument_dynamic;
      char identity[128];
      std::memset(identity, 'x', sizeof(identity));
      size_t written = SIZE_MAX;
      bool absolute = true;
      bool known = shell_dep_doc_file_identity_write(
          &graph, &node.doc, identity, sizeof(identity), &written, &absolute);
      valid = valid && known == !fixture.argument_dynamic;
      if (!known) {
        valid = valid && written == 0 && !absolute;
        for (char byte : identity)
          valid = valid && byte == 'x';
      }
    }
    if (!valid || files != 1) {
      fprintf(stderr, "tilde expansion oracle failed: %s\n", fixture.word);
      abort();
    }
  }
  for (const auto &fixture : shellsplit_test_tilde_cwd) {
    std::string source = std::string("cd ") + fixture.word + " && pwd >out";
    bool valid =
        shell_dep_graph_parse(source.data(), source.size(), "/workspace",
                              nullptr, &graph) == SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    size_t files = 0;
    for (uint32_t n = 0; valid && n < graph.node_count; n++) {
      const auto &node = graph.nodes[n];
      if (node.type != SHELL_NODE_DOC || node.doc.kind != SHELL_DOC_FILE ||
          node.doc.path_len != 3 || std::memcmp(node.doc.path, "out", 3))
        continue;
      files++;
      char identity[128];
      size_t written = 0;
      bool absolute = false;
      bool known = shell_dep_doc_file_identity_write(
          &graph, &node.doc, identity, sizeof(identity), &written, &absolute);
      valid = known == (fixture.cwd != nullptr) && node.doc.cwd_known == known;
      if (known) {
        std::string expected = std::string(fixture.cwd) + "/out";
        valid = valid && absolute == fixture.absolute &&
                written == expected.size() && identity == expected;
      } else
        valid = valid && written == 0 && !absolute;
    }
    if (!valid || files != 1) {
      fprintf(stderr, "tilde CWD identity oracle failed: %s\n", fixture.word);
      abort();
    }
  }
  for (const auto &fixture : shellsplit_test_fragment_words) {
    shell_abstract_command_t *abstract = nullptr;
    bool valid =
        shell_abstract_command_parse(fixture.source, strlen(fixture.source),
                                     &abstract) == SHELL_ABSTRACT_OK;
    if (valid) {
      valid = abstract->element_count == (fixture.has_variable ? 2u : 1u) &&
              abstract->has_strings == fixture.string_fragment &&
              abstract->has_cmd_subst == !fixture.string_fragment &&
              abstract->has_variables == fixture.has_variable;
      if (valid) {
        const shell_abstract_element_t *element = abstract->elements[0];
        size_t start = static_cast<size_t>(
            strstr(fixture.source, fixture.fragment) - fixture.source);
        valid =
            element->type == (fixture.string_fragment ? SHELL_ABSTRACT_STR
                                                      : SHELL_ABSTRACT_CS) &&
            element->start == start &&
            element->end == start + strlen(fixture.fragment) &&
            strcmp(element->original, fixture.fragment) == 0 &&
            element->data.cmd_subst.content &&
            strcmp(element->data.cmd_subst.content, fixture.content) == 0;
      }
    }
    shell_abstract_command_free(abstract);
    if (!valid) {
      fprintf(stderr, "fragment content oracle failed: %s\n", fixture.source);
      abort();
    }
  }
  for (const auto &fixture : shellsplit_test_parameter_words) {
    const char *name = nullptr;
    size_t length = 0;
    bool matched = shell_source_word_parameter_name(
        fixture.word, strlen(fixture.word), &name, &length);
    if (matched != (fixture.name != nullptr) ||
        (matched && (length != strlen(fixture.name) ||
                     memcmp(name, fixture.name, length) != 0)))
      abort();
  }
  if (test_fixed_oracles())
    abort();
  fixed_oracle_phase("generated substitution matrices");
  static const char *const plain_boundary_cases[] = {
      ".",     "source", "eval",      "trap",   "alias",
      "pushd", "popd",   "command .", "/bin/.", "printf .",
  };
  for (const char *source : plain_boundary_cases)
    if (test_plain_differential(source, strlen(source)))
      abort();
  for (unsigned selector = 0; selector < 48; selector++)
    if (test_generated_redirect_boundary(selector))
      abort();
  for (unsigned selector = 0; selector < 16; selector++)
    if (test_composite_redirect_operand(selector, "/tmp"))
      abort();
  for (uint8_t selector = 0;
       selector < SHELL_BRACE_FUZZ_SUBSTITUTION_CASE_COUNT; selector++)
    if (test_generated_substitution_case(&selector, 1, "/tmp"))
      abort();
  for (uint8_t selector = 0;
       selector < SHELL_BRACE_FUZZ_COMPOSED_SUBSTITUTION_CASE_COUNT; selector++)
    if (test_composed_substitution_case(&selector, 1, "/tmp"))
      abort();
  static const uint8_t local_document_selectors[] = {58, 59, 60};
  /* Regression for a trailing heredoc redirect on a nested group followed by
   * a pipeline. Byte three used to make the shared generator mistake CRLF for
   * a shell newline and declare the resulting unterminated heredoc valid. */
  static const uint8_t heredoc_pipeline_group_case[] = {0, 1, 2, 1, 1,
                                                        2, 7, 1, 1};
  if (test_generated_brace_case(heredoc_pipeline_group_case,
                                sizeof(heredoc_pipeline_group_case), "/tmp"))
    abort();
  for (uint8_t depth = 0; depth < 8; depth++)
    for (uint8_t composition = 0; composition < 6; composition++) {
      const uint8_t diagnostic_group_case[] = {0,           1, 2, 0, depth,
                                               composition, 1, 0, 1};
      if (test_generated_brace_case(diagnostic_group_case,
                                    sizeof(diagnostic_group_case), "/tmp"))
        abort();
    }
  for (uint8_t selector : local_document_selectors)
    if (test_generated_brace_case(&selector, 1, "/tmp"))
      abort();
  /* The invalid/strict-only family encodes its form selector in byte four;
   * exercise every member at startup so a parser-boundary change cannot
   * leave a stale expectation to be found only by random mutation. */
  for (uint8_t selector = 0; selector < 12; selector++) {
    const uint8_t invalid_case[] = {7, 0, 0, 0, selector};
    if (test_generated_brace_case(invalid_case, sizeof(invalid_case), "/tmp"))
      abort();
  }
  if (test_composed_substitution_matrix("/tmp"))
    abort();
  static const uint8_t arithmetic_selectors[] = {0, 4, 1, 5, 2, 6, 3};
  for (uint8_t selector : arithmetic_selectors)
    if (test_generated_static_arithmetic_case(&selector, 1))
      abort();
  for (uint8_t selector = 0; selector < 8 * 7; selector++)
    for (bool truncate : {false, true})
      if (test_generated_resolved_depgraph(selector, truncate)) {
        fprintf(stderr, "resolved graph oracle failed: %u, truncate=%d\n",
                selector, truncate);
        abort();
      }
  fixed_oracle_phase("complete");
}

static int test_draft_source(const char *source, size_t length) {
  auto *draft = static_cast<shell_source_result_t *>(
      malloc(sizeof(shell_source_result_t)));
  if (!draft)
    return 0;
  shell_source_status_t status = shell_parse_draft(source, length, NULL, draft);
  bool valid = draft->prefix_length <= length && draft->tail_start <= length;
  if (status != SHELL_SOURCE_COMPLETE && status != SHELL_SOURCE_INCOMPLETE)
    valid &= draft->prefix_length == 0 && draft->prefix.count == 0;
  else {
    valid &= status != SHELL_SOURCE_COMPLETE || draft->prefix_length == length;
    if (draft->prefix_length) {
      shell_parse_result_t strict = {};
      shell_limits_t limits = SHELL_LIMITS_DEFAULT;
      limits.strict_mode = true;
      valid &= shell_parse_fast(source, draft->prefix_length, &limits,
                                &strict) == SHELL_OK;
      valid &= shellsplit_test_parse_equal(&strict, &draft->prefix);
    }
    for (uint32_t h = 0; h < draft->header_count; h++) {
      const auto &header = draft->headers[h];
      valid &= status != SHELL_SOURCE_COMPLETE || header.complete;
      valid &= header.source.start <= length &&
               header.source.length <= length - header.source.start;
      uint32_t redirect = header.first_redirect;
      for (uint32_t r = 0; r < header.redirect_count; r++) {
        if (redirect >= draft->redirect_count) {
          valid = false;
          break;
        }
        valid &= draft->redirects[redirect].header == h;
        redirect = draft->redirects[redirect].next;
      }
      valid &= redirect == UINT32_MAX;
      for (uint32_t w = 0; w < header.word_count; w++)
        valid &= header.words[w].start <= length &&
                 header.words[w].length <= length - header.words[w].start;
    }
    for (uint32_t d = 0; d < draft->heredoc_count; d++) {
      const auto &doc = draft->heredocs[d];
      valid &= doc.header < draft->header_count &&
               doc.confirmed_length <= doc.content.value_len;
      valid &= !doc.complete || (doc.body_started && doc.header_complete);
      if (doc.redirect != UINT32_MAX)
        valid &= doc.redirect < draft->redirect_count &&
                 draft->redirects[doc.redirect].heredoc == d;
    }
  }
  free(draft);
  return !valid;
}

/* Missing words stay in list grammar; actual word fragments use expansion
 * recovery. Independently prescribed separators must invalidate the whole
 * draft rather than hiding behind an invented unfinished substitution. */
static int test_draft_redirect_operand(uint8_t selector, uint8_t value) {
  static const char prefix[] = "echo before; ";
  static const char *const commands[] = {"cat ", "{ :; } ", "( : ) "};
  static const char *const redirects[] = {">&",  "<&",     "2>&",
                                          "0<&", "{fd}>&", "{fd}<&"};
  static const char *const trivia[] = {"", " ", "\t", "\\\n", " \t\\\n "};
  static const char *const invalid[] = {
      "\n", ";",   " #comment", " && cat", " | cat",
      " )", " < ", " > ",       " <\\\n ", " >\\\n "};
  const char *command = commands[selector % 3];
  std::string source =
      std::string(prefix) + command + redirects[selector / 3 % 6];
  auto *draft = static_cast<shell_source_result_t *>(
      malloc(sizeof(shell_source_result_t)));
  if (!draft)
    return 0;
  std::string pending = source + trivia[value % 5];
  bool valid = shell_parse_draft(pending.data(), pending.size(), nullptr,
                                 draft) == SHELL_SOURCE_INCOMPLETE;
  valid &= draft->need == SHELL_SOURCE_NEEDS_REDIRECT &&
           draft->incomplete_at == strlen(prefix) + strlen(command) &&
           draft->prefix_length == sizeof("echo before;") - 1 &&
           draft->tail_start == draft->prefix_length &&
           draft->header_count >= 2 && draft->headers[0].complete &&
           !draft->headers[1].complete;
  std::string completed = pending + " \"$(printf 1)\"";
  valid &= shell_parse_draft(completed.data(), completed.size(), nullptr,
                             draft) == SHELL_SOURCE_COMPLETE;
  valid &=
      draft->prefix_length == completed.size() && draft->headers[1].complete;
  std::string rejected = source + invalid[value % 10];
  valid &= shell_parse_draft(rejected.data(), rejected.size(), nullptr,
                             draft) == SHELL_SOURCE_INVALID;
  valid &= !draft->prefix_length && !draft->prefix.count && !draft->tail_start;
  for (uint32_t h = 0; h < draft->header_count; h++)
    valid &= !draft->headers[h].complete;
  std::string process = source + ((value & 1) ? " <\\" : " >");
  valid &= shell_parse_draft(process.data(), process.size(), nullptr, draft) ==
           SHELL_SOURCE_INCOMPLETE;
  valid &= draft->need == ((value & 1) ? SHELL_SOURCE_NEEDS_ESCAPE
                                       : SHELL_SOURCE_NEEDS_SUBSTITUTION) &&
           draft->incomplete_at == source.size() + ((value & 1) ? 2 : 1) &&
           draft->prefix_length == sizeof("echo before;") - 1;
  if (value & 1) {
    process += '\n';
    valid &= shell_parse_draft(process.data(), process.size(), nullptr,
                               draft) == SHELL_SOURCE_INCOMPLETE;
    valid &= draft->need == SHELL_SOURCE_NEEDS_SUBSTITUTION &&
             draft->incomplete_at == source.size() + 1;
  }
  process += "(cat)";
  valid &= shell_parse_draft(process.data(), process.size(), nullptr, draft) ==
           SHELL_SOURCE_COMPLETE;
  if (!valid)
    fprintf(stderr, "draft redirect operand: selector=%u value=%u\n", selector,
            value);
  free(draft);
  return !valid;
}

/* Received EOF may still turn a compound-tail number or identifier into a
 * redirector. It must not invent an ordinary word, child group, or redirect;
 * a closed substitution instead commits its final word and must reject it. */
static int test_draft_redirector_prefix(uint8_t selector, uint8_t value) {
  static const char prefix[] = "echo before; ";
  static const char *const compounds[] = {"{ :; } ", "( : ) ", "time { :; } ",
                                          "{ :; } >existing ",
                                          "( : ) >existing "};
  static const struct {
    const char *received, *completion;
    bool escape;
  } cases[] = {
      {"2", ">out", false},          {"0002", ">out", false},
      {"2147483647", ">out", false}, {"{", "fd}>out", false},
      {"{f", "d}>out", false},       {"{fd", "}>out", false},
      {"{fd}", ">out", false},       {"{_x9}", ">out", false},
      {"00\\\n02", ">out", false},   {"{f\\\nd}", ">out", false},
      {"{fd}\\\n", ">out", false},   {"{\\\n", "fd}>out", false},
      {"2\\", "\n>out", true},       {"{\\", "\nfd}>out", true},
      {"{fd\\", "\n}>out", true},    {"{fd}\\", "\n>out", true},
  };
  static const char *const invalid[] = {
      "2 ",         "2\n",        "2;",
      "2 #comment", "2147483648", "99999999999999999999999999999999999",
      "'2'",        "\\2",        "{9",
      "{}",         "{fd-x",      "{fd}x",
      "{fd} ",      "{fd}\\ ",    "{fd}\\\\",
      "{ ",         "'",          "\"",
      "`",          "$(",         "${",
      "{fd}'",      "{f'",        "2\""};
  const auto &fixture = cases[selector % 16];
  const char *compound = compounds[value % 5];
  auto *draft = static_cast<shell_source_result_t *>(
      malloc(sizeof(shell_source_result_t)));
  if (!draft)
    return 0;
  std::string source = std::string(prefix) + compound;
  bool valid = shell_parse_draft(source.data(), source.size(), nullptr,
                                 draft) == SHELL_SOURCE_COMPLETE;
  valid &= draft->header_count == 3 && draft->headers[2].complete;
  shell_source_header_t child = draft->headers[2];
  uint32_t redirects = draft->redirect_count;
  shell_source_redirect_t existing = {};
  if (redirects)
    existing = draft->redirects[0];
  size_t start = source.size();
  source += fixture.received;
  valid &= shell_parse_draft(source.data(), source.size(), nullptr, draft) ==
           SHELL_SOURCE_INCOMPLETE;
  valid &=
      draft->need == (fixture.escape ? SHELL_SOURCE_NEEDS_ESCAPE
                                     : SHELL_SOURCE_NEEDS_REDIRECT) &&
      draft->incomplete_at == (fixture.escape ? source.size() - 1 : start) &&
      draft->prefix_length == sizeof("echo before;") - 1 &&
      draft->tail_start == draft->prefix_length && draft->header_count == 3 &&
      draft->headers[0].complete && !draft->headers[1].complete &&
      draft->headers[1].compound && !draft->headers[1].word_count &&
      !draft->headers[1].assignment_count &&
      draft->headers[1].source.start + draft->headers[1].source.length ==
          source.size() &&
      shellsplit_test_header_equal(&child, &draft->headers[2]) &&
      draft->redirect_count == redirects;
  if (redirects)
    valid &= shellsplit_test_redirect_equal(&existing, &draft->redirects[0]);
  source += fixture.completion;
  valid &= shell_parse_draft(source.data(), source.size(), nullptr, draft) ==
           SHELL_SOURCE_COMPLETE;
  valid &= draft->headers[1].complete && !draft->headers[1].word_count &&
           draft->redirect_count == redirects + 1 &&
           shellsplit_test_header_equal(&child, &draft->headers[2]);
  if (redirects)
    valid &= shellsplit_test_io_equal(&existing.io, &draft->redirects[0].io) &&
             existing.header == draft->redirects[0].header &&
             existing.heredoc == draft->redirects[0].heredoc &&
             draft->redirects[0].next == redirects;
  source = std::string(prefix) + "echo $( " + compound + fixture.received +
           (fixture.escape ? "\n)" : ")");
  valid &= shell_parse_draft(source.data(), source.size(), nullptr, draft) ==
           SHELL_SOURCE_INVALID;
  valid &= !draft->prefix_length && !draft->prefix.count && !draft->tail_start;
  source = std::string(prefix) + compound + invalid[value % 24];
  valid &= shell_parse_draft(source.data(), source.size(), nullptr, draft) ==
           SHELL_SOURCE_INVALID;
  valid &= !draft->prefix_length && !draft->prefix.count && !draft->tail_start;
  source = std::string(prefix) + "{ " + compound + fixture.received;
  valid &= shell_parse_draft(source.data(), source.size(), nullptr, draft) ==
           SHELL_SOURCE_INCOMPLETE;
  valid &= draft->header_count == 4 && !draft->headers[1].complete &&
           !draft->headers[2].complete && !draft->headers[2].word_count &&
           draft->headers[3].complete &&
           draft->prefix_length == sizeof("echo before;") - 1;
  child = draft->headers[3];
  source += std::string(fixture.completion) + "; }";
  valid &= shell_parse_draft(source.data(), source.size(), nullptr, draft) ==
           SHELL_SOURCE_COMPLETE;
  valid &= draft->header_count == 4 && draft->headers[1].complete &&
           draft->headers[2].complete && !draft->headers[2].word_count &&
           shellsplit_test_header_equal(&child, &draft->headers[3]);
  source = (value & 1) ? "echo 2" : "echo {fd}";
  valid &= shell_parse_draft(source.data(), source.size(), nullptr, draft) ==
           SHELL_SOURCE_COMPLETE;
  valid &= draft->header_count == 1 && draft->headers[0].word_count == 2;
  source = std::string(prefix) + "{";
  valid &= shell_parse_draft(source.data(), source.size(), nullptr, draft) ==
           SHELL_SOURCE_INCOMPLETE;
  valid &= draft->need == SHELL_SOURCE_NEEDS_GROUP;
  if (!valid)
    fprintf(stderr,
            "draft redirector prefix: selector=%u value=%u compound=[%s] "
            "received=[%s] completion=[%s]\n",
            selector, value, compound, fixture.received, fixture.completion);
  free(draft);
  return !valid;
}

/* Each received body needs its own unfinished-word facts, even while its
 * enclosing substitution owns the root diagnostic and qualified boundary. */
static int test_draft_nested_redirect(uint8_t selector, uint8_t value) {
  static const char prefix[] = "echo before; ";
  static const char *const heads[] = {"echo $( ", "cat <( ", "cat >( ",
                                      "echo `"};
  static const char *const closes[] = {")", ")", ")", "`"};
  static const char *const commands[] = {"cat 2>existing", "{ :; } 2>existing",
                                         "( : ) 2>existing"};
  static const char *const operands[] = {" > <(printf ", " > >(printf ",
                                         " >`printf "};
  static const char *const ends[] = {")", ")", "`"};
  unsigned outer = selector % 4, command = selector / 4 % 3,
           operand = value % 3;
  if (outer == 3 && operand == 2)
    operand = 0; /* Escaped nested backticks are outside supported source. */
  std::string source = std::string(prefix) + heads[outer] + commands[command] +
                       operands[operand] + std::to_string(value);
  auto *draft = static_cast<shell_source_result_t *>(
      malloc(sizeof(shell_source_result_t)));
  if (!draft)
    return 0;
  uint32_t headers = command == 0 ? 4 : 5;
  bool valid = shell_parse_draft(source.data(), source.size(), nullptr,
                                 draft) == SHELL_SOURCE_INCOMPLETE;
  size_t opening = source.find(outer == 3 ? '`' : '(');
  valid &= draft->need == SHELL_SOURCE_NEEDS_SUBSTITUTION &&
           draft->incomplete_at == (outer == 3 ? opening : opening - 1) &&
           draft->prefix_length == sizeof("echo before;") - 1 &&
           draft->tail_start == draft->prefix_length &&
           draft->header_count == headers && draft->headers[0].complete &&
           !draft->headers[1].complete && !draft->headers[2].complete &&
           draft->redirect_count == (operand == 2 ? 2u : 1u) &&
           draft->redirects[0].header == 2;
  shell_source_header_t leaf = draft->headers[headers - 1];
  shell_source_header_t closed = draft->headers[3];
  shell_group_io_op_t existing = draft->redirects[0].io;
  valid &= leaf.complete && leaf.word_count == 2;
  source += std::string(ends[operand]) + closes[outer];
  valid &= shell_parse_draft(source.data(), source.size(), nullptr, draft) ==
           SHELL_SOURCE_COMPLETE;
  valid &= draft->header_count == headers && draft->redirect_count == 2 &&
           shellsplit_test_header_equal(&leaf, &draft->headers[headers - 1]) &&
           shellsplit_test_io_equal(&existing, &draft->redirects[0].io);
  if (command != 0)
    valid &= shellsplit_test_header_equal(&closed, &draft->headers[3]);
  source = std::string(prefix) + heads[outer] + commands[command] +
           " > <(echo &&) tail";
  valid &= shell_parse_draft(source.data(), source.size(), nullptr, draft) ==
           SHELL_SOURCE_INVALID;
  valid &= !draft->prefix_length && !draft->prefix.count && !draft->tail_start;
  if (command != 0) {
    source =
        std::string(prefix) + heads[outer] + commands[command] + " ordinary'";
    valid &= shell_parse_draft(source.data(), source.size(), nullptr, draft) ==
             SHELL_SOURCE_INVALID;
    valid &=
        !draft->prefix_length && !draft->prefix.count && !draft->tail_start;
  }
  if (!valid)
    fprintf(stderr, "nested draft redirect: selector=%u value=%u\n", selector,
            value);
  free(draft);
  return !valid;
}

/* Completing only a suffix preserves earlier children in confirmed code.
 * Tentative delimiter lines instead contribute no children until they become
 * body data. Derive known syntax from fuzz bytes, including selector EOFs. */
static int test_draft_closed_children(uint8_t selector, uint8_t value) {
  std::string token = std::to_string(value);
  std::string child = "$(printf " + token + ")";
  std::string word, completion;
  std::string payload;
  unsigned children = 1;
  bool document = false;
  switch (selector % 18) {
  case 0:
    word = "echo \"" + child + " tail";
    completion = "\"";
    break;
  case 1:
    word = "echo " + child + "\\";
    completion = "x";
    break;
  case 2:
    word = "cat >\"" + child + " tail";
    completion = "\"";
    break;
  case 3:
    word = "cat <(printf " + token + ")'tail";
    completion = "'";
    break;
  case 4:
    word = "echo \"`printf " + token + "` tail";
    completion = "\"";
    break;
  case 5:
    word = "echo \"${value:-" + child + "} tail";
    completion = "\"";
    break;
  case 6:
    word = "echo \"$(( " + child + " + 1 )) tail";
    completion = "\"";
    break;
  case 7:
    word = "echo \"$(cat <<'DRAFT_CHILD'\n" + token + "\nDRAFT_CHILD\n) tail";
    completion = "\"";
    document = true;
    payload = token + "\n";
    break;
  case 8:
    word = "echo " + child + "$(printf " + token;
    completion = ")";
    children = 2;
    break;
  case 9:
    word = "echo `printf " + token;
    completion = "`";
    break;
  case 10:
    word = "cat >`printf " + token;
    completion = "`";
    break;
  case 11:
    word = "echo ${value:-`printf " + token;
    completion = "`}";
    break;
  case 12:
    word = "echo `echo " + child;
    completion = "`";
    children = 2;
    break;
  case 13:
    word = "echo \"`cat <<'DRAFT_CHILD'\n" + token + "\nDRAFT_CHILD\n";
    completion = "`\"";
    document = true;
    payload = token + "\n";
    break;
  case 16:
    word = "cat 2>&\"" + child + " tail";
    completion = "\"";
    break;
  case 17:
    word = "cat <&\"" + child + " tail";
    completion = "\"";
    break;
  default:
    payload = selector % 16 == 14 ? "日本 $((" + token + " + 1)) 語\n"
                                  : "日本 ${value:1} 語\n";
    word = "echo \"$(cat <<DRAFT_CHILD\n" + payload + "DRAFT_CHILD\n) tail";
    completion = "\"";
    document = true;
    break;
  }
  std::string source = "echo before; " + word + completion;
  auto *received = static_cast<shell_source_result_t *>(
      malloc(sizeof(shell_source_result_t)));
  auto *completed = static_cast<shell_source_result_t *>(
      malloc(sizeof(shell_source_result_t)));
  if (!received || !completed) {
    free(received);
    free(completed);
    return 0;
  }
  shell_source_status_t received_status = shell_parse_draft(
      source.data(), source.size() - completion.size(), NULL, received);
  shell_source_status_t completed_status =
      shell_parse_draft(source.data(), source.size(), NULL, completed);
  bool valid = received_status == SHELL_SOURCE_INCOMPLETE &&
               completed_status == SHELL_SOURCE_COMPLETE;
  valid &= received->prefix_length == sizeof("echo before;") - 1 &&
           received->header_count == children + 2 &&
           completed->header_count == children + 2 &&
           !received->headers[1].complete;
  for (unsigned c = 0; c < children; c++)
    valid &= received->headers[c + 2].complete &&
             shellsplit_test_header_equal(&received->headers[c + 2],
                                          &completed->headers[c + 2]);
  valid &= received->heredoc_count == unsigned(document) &&
           received->heredoc_count == completed->heredoc_count;
  if (document)
    valid &= received->heredocs[0].complete &&
             received->heredocs[0].content.value_len == payload.size() &&
             shellsplit_test_heredoc_equal(&received->heredocs[0],
                                           &completed->heredocs[0]);
  std::string malformed = (value & 1) ? "echo before; cat <(printf "
                                      : "echo before; echo \"$(printf ";
  malformed += token + " &&) tail";
  valid &= shell_parse_draft(malformed.data(), malformed.size(), NULL,
                             received) == SHELL_SOURCE_INVALID;
  valid &= !received->prefix_length && !received->prefix.count;
  for (uint32_t h = 0; h < received->header_count; h++)
    valid &= !received->headers[h].complete;
  /* A later EOF cannot repair a closed invalid child in a received backtick.
   * Neither a child nor a completion event may hide non-ASCII arithmetic code.
   * Escape-sensitive raw backticks have no faithful borrowed body view. */
  const std::string rejected[] = {
      "echo before; echo `echo $(printf " + token + " &&) tail",
      "echo before; cat <<EOF\n$(( 日本 + $(printf " + token + ") ))\nEOF\n",
      "echo before; cat <<EOF\n${value:$(printf " + token + ") + 日本",
      "echo before; echo `printf \\$value" + std::string(value & 1 ? "`" : ""),
  };
  for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); ++i) {
    const std::string &input = rejected[i];
    valid &= shell_parse_draft(input.data(), input.size(), NULL, received) ==
             (i == 0 ? SHELL_SOURCE_INVALID : SHELL_SOURCE_UNSUPPORTED);
    valid &= !received->prefix_length && !received->prefix.count;
  }
  /* A tentative delimiter line is not body code, even if its received prefix
   * contains a closed backtick or non-ASCII bytes inside an apparent child. */
  bool unicode = (selector & 1) != 0;
  bool malformed_child = !unicode && (selector & 2);
  std::string command = malformed_child ? "|" : token;
  std::string candidate = "`" + command + "`" + (unicode ? "`日" : "");
  std::string delimiter = "`" + command + "`" + (unicode ? "`日本`" : "tail");
  std::string opening = "echo before; cat <<" + delimiter + "\n";
  std::string pending = opening + candidate;
  std::string closed = opening + delimiter + "\n";
  valid &= shell_parse_draft(pending.data(), pending.size(), NULL, received) ==
           SHELL_SOURCE_INCOMPLETE;
  valid &= received->prefix_length == sizeof("echo before;") - 1 &&
           received->header_count == 2 && received->heredoc_count == 1 &&
           received->heredocs[0].delimiter_prefix &&
           received->heredocs[0].confirmed_length == 0 &&
           received->heredocs[0].content.value_len == candidate.size();
  valid &= shell_parse_draft(closed.data(), closed.size(), NULL, completed) ==
           SHELL_SOURCE_COMPLETE;
  valid &= completed->header_count == 2 && completed->heredoc_count == 1 &&
           completed->heredocs[0].complete &&
           completed->heredocs[0].content.value_len == 0;
  std::string body = opening + candidate + "x\n" + delimiter + "\n";
  bool invalid_body = unicode || malformed_child;
  valid &= shell_parse_draft(body.data(), body.size(), NULL, received) ==
           (unicode           ? SHELL_SOURCE_UNSUPPORTED
            : malformed_child ? SHELL_SOURCE_INVALID
                              : SHELL_SOURCE_COMPLETE);
  valid &= invalid_body
               ? received->prefix_length == 0 && received->prefix.count == 0
               : received->header_count == 3;

  static const char *const heads[] = {"${#",   "${!",   "${!v*",
                                      "${v\\", "${#\\", "${!v*\\"};
  static const char *const ends[] = {"v}", "v}", "}", "\n}", "\nv}", "\n}"};
  unsigned head = selector % (sizeof(heads) / sizeof(heads[0]));
  std::string partial = std::string("echo before; echo ") + heads[head];
  std::string full = partial + ends[head];
  valid &= shell_parse_draft(partial.data(), partial.size(), NULL, received) ==
           SHELL_SOURCE_INCOMPLETE;
  valid &= received->prefix_length == sizeof("echo before;") - 1;
  valid &= shell_parse_draft(full.data(), full.size(), NULL, completed) ==
           SHELL_SOURCE_COMPLETE;

  /* Known Bash phase boundaries, not merely agreement between consumers of
   * the same decoder. The command after the terminator must remain visible. */
  std::string declaration, terminator;
  std::string data = token + "\n";
  switch (selector % 4) {
  case 0:
    declaration = "cat <<`\"`$'\\x3a'\n";
    terminator = "``':'";
    data.clear();
    break;
  case 1:
    declaration = "cat <<`'a\\\nb'`''\n";
    terminator = "`ab`";
    break;
  case 2:
    declaration = "cat <<- \t\\\n \tEOF\n";
    terminator = "EOF";
    break;
  default:
    declaration = "cat <<`\"`$'";
    terminator = "``'";
    for (unsigned i = 0; i < 2u + value % 8u; i++) {
      declaration += "\\'";
      terminator += "'\\''";
    }
    declaration += "'\n";
    terminator += "'";
    break;
  }
  std::string phase_opening = "echo before; " + declaration;
  std::string phase_closed =
      phase_opening + data + terminator + "\nprintf " + token;
  if (selector % 4 == 0)
    phase_closed += "\n``:\n:\n";
  std::string phase_pending =
      phase_opening + data + terminator.substr(0, terminator.size() / 2);
  valid &= shell_parse_draft(phase_pending.data(), phase_pending.size(), NULL,
                             received) == SHELL_SOURCE_INCOMPLETE;
  valid &= received->prefix_length == sizeof("echo before;") - 1 &&
           received->heredoc_count == 1 &&
           received->heredocs[0].confirmed_length == data.size();
  valid &= shell_parse_draft(phase_closed.data(), phase_closed.size(), NULL,
                             completed) == SHELL_SOURCE_COMPLETE;
  valid &= completed->header_count == (selector % 4 == 0 ? 5u : 3u) &&
           completed->heredoc_count == 1 && completed->heredocs[0].complete &&
           completed->heredocs[0].content.value_len == data.size() &&
           completed->heredocs[0].closing_delimiter.start ==
               phase_opening.size() + data.size() &&
           completed->heredocs[0].closing_delimiter.length ==
               terminator.size() + 1 &&
           completed->headers[2].words[0].length == sizeof("printf") - 1 &&
           !memcmp(phase_closed.data() + completed->headers[2].words[0].start,
                   "printf", sizeof("printf") - 1);

  /* Close-token boundaries, raw ANSI-C NUL, word-form moves and continuation
   * phase ordering must select Bash's actual terminator, not merely agree
   * across our own parsers. */
  static const char *const delimiter_words[] = {
      "$(a >&-file)", "\"${x:-$'\\0'}\"", "$(a >&$fd-)", "\"${\\\n#x:-$'a'}\""};
  static const char *const delimiter_lines[] = {"$(a file 1>&-)", "${x:-",
                                                "$(a 1>&$fd-)", "${#x:-a}"};
  unsigned boundary = selector % 4;
  std::string boundary_open = std::string("echo before; cat <<") +
                              delimiter_words[boundary] + "\n" + data;
  std::string boundary_closed =
      boundary_open + delimiter_lines[boundary] + "\nprintf " + token;
  size_t delimiter_size;
  if (!shell_source_workspace_size(boundary_closed.size(), &delimiter_size))
    abort();
  std::vector<unsigned char> delimiter_storage(delimiter_size);
  shell_limits_t source_limits = SHELL_LIMITS_DEFAULT;
  source_limits.workspace = delimiter_storage.data();
  source_limits.workspace_size = delimiter_storage.size();
  valid &=
      shell_parse_draft(boundary_closed.data(), boundary_closed.size(),
                        &source_limits, completed) == SHELL_SOURCE_COMPLETE;
  valid &=
      completed->header_count == 3 && completed->heredoc_count == 1 &&
      completed->heredocs[0].complete &&
      completed->heredocs[0].content.value_len == data.size() &&
      completed->heredocs[0].closing_delimiter.start == boundary_open.size();
  std::string boundary_pending =
      boundary_open + std::string(delimiter_lines[boundary]).substr(0, 3);
  valid &=
      shell_parse_draft(boundary_pending.data(), boundary_pending.size(),
                        &source_limits, received) == SHELL_SOURCE_INCOMPLETE;
  valid &= received->prefix_length == sizeof("echo before;") - 1 &&
           received->heredoc_count == 1 &&
           received->heredocs[0].confirmed_length == data.size();
  std::string continued_control =
      "echo before; cat <<$(i\\\nf true; th\\\nen :; f\\\ni)\n";
  valid &=
      shell_parse_draft(continued_control.data(), continued_control.size(),
                        &source_limits, received) == SHELL_SOURCE_UNSUPPORTED;
  valid &= !received->prefix_length && !received->prefix.count;
  static const char *const keywords[] = {"if", "function", "[[", "]]"};
  std::string keyword = keywords[selector % 4];
  std::string keyword_open = "echo before; " + keyword;
  valid &= shell_parse_draft(keyword_open.data(), keyword_open.size(), NULL,
                             received) == SHELL_SOURCE_INCOMPLETE;
  valid &= received->need == SHELL_SOURCE_NEEDS_COMMAND &&
           received->incomplete_at == sizeof("echo before; ") - 1 &&
           received->prefix_length == sizeof("echo before;") - 1 &&
           received->header_count == 2 && !received->headers[1].complete;
  std::string keyword_repaired = keyword_open + "x";
  valid &= shell_parse_draft(keyword_repaired.data(), keyword_repaired.size(),
                             NULL, completed) == SHELL_SOURCE_COMPLETE;
  std::string keyword_closed = "echo before; echo $(" + keyword + ")";
  valid &= shell_parse_draft(keyword_closed.data(), keyword_closed.size(), NULL,
                             received) == SHELL_SOURCE_UNSUPPORTED;
  valid &= !received->prefix_length && !received->prefix.count;
  std::string reprinted =
      "echo $(cat << -EOF\n" + token + "\nEOF\nprintf EXPOSED\n-EOF\n)";
  shell_processed_commands_t unsupported = {};
  valid &= shell_process_commands(reprinted.data(), reprinted.size(), NULL,
                                  &unsupported) == SHELL_PROCESS_EPARSE;
  valid &= !unsupported.commands && !unsupported.command_count;
  shell_processed_commands_free(&unsupported);
  if (!valid)
    fprintf(stderr, "draft child retention: selector=%u value=%u\n", selector,
            value);
  free(received);
  free(completed);
  return !valid;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Metadata is derived without consuming command bytes.  Every byte in the
   * fuzz input must remain available to the parsers, including short and
   * malformed prefixes. */
  uint8_t cwd_selector = size > 0 ? data[0] : 0;
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
  run_check("draft source", test_draft_source(cmd.data(), cmd.size()));
  run_check(
      "draft redirect operand",
      test_draft_redirect_operand(size ? data[0] : 0, size > 1 ? data[1] : 0));
  run_check(
      "draft redirector prefix",
      test_draft_redirector_prefix(size ? data[0] : 0, size > 1 ? data[1] : 0));
  run_check(
      "nested draft redirect",
      test_draft_nested_redirect(size ? data[0] : 0, size > 1 ? data[1] : 0));
  run_check(
      "draft child retention",
      test_draft_closed_children(size ? data[0] : 0, size > 1 ? data[1] : 0));
  std::string draft_document = (size && (data[0] & 1))
                                   ? "echo before\ncat <<DRAFT_END\n"
                                   : "echo before\ncat <<'DRAFT_END'\n";
  draft_document += cmd;
  run_check("draft document",
            test_draft_source(draft_document.data(), draft_document.size()));
  run_check("dependency graph", test_depgraph(cmd.data(), cmd.size(), cwd));
  run_check("resolved dependency graph",
            test_resolved_depgraph(cmd.data(), cmd.size(), cwd,
                                   size ? data[size - 1] : 0,
                                   size > 1 && (data[1] & 1)));
  run_check("full parser", test_full_parser(input, text_length));
  run_check("tokenizer iterator", test_tokenizer_state(input, text_length));
  run_check("transformer", test_transformer(input, text_length));
  run_check("processor", test_processor(input, text_length));
  run_check("output limits", test_output_limits(input, text_length));
  run_check("interop", test_interop(cmd.data(), cmd.size()));
  run_check("abstraction", test_abstraction(input, text_length));
  run_check("entropy/environment helpers",
            test_data_helpers(input, text_length, cwd_selector));
  run_check("plain differential", test_plain_differential(input, text_length));
  run_check("structured variants",
            test_structured_variants(input, text_length));
  /* Startup exhaustively checks each generated matrix. On fuzzed payloads,
   * choose one without consuming input bytes, so structural coverage does not
   * multiply the cost of every arbitrary-parser iteration. */
  switch (size == 0 ? 0 : data[0] % 8) {
  case 0:
    run_check("generated brace case",
              test_generated_brace_case(data, size, cwd));
    break;
  case 1:
    run_check("generated substitution case",
              test_generated_substitution_case(data, size, cwd));
    break;
  case 2:
    run_check("composed substitution case",
              test_composed_substitution_case(data, size, cwd));
    break;
  case 3:
    run_check("generated redirect boundary",
              test_generated_redirect_boundary(data[0]));
    break;
  case 4:
    run_check("generated static arithmetic",
              test_generated_static_arithmetic_case(data, size));
    break;
  case 5:
    run_check("generated document boundary",
              test_generated_document_boundary(data[0]));
    break;
  case 6:
    run_check(
        "generated descriptor move",
        test_generated_descriptor_move(descriptor_move_selector(data, size)));
    break;
  default:
    run_check(
        "generated resolved graph",
        test_generated_resolved_depgraph(data[0], size > 1 && (data[1] & 1)));
    break;
  }
  free(input);
  if (failed)
    abort();

  return 0;
}

} // extern "C"
