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
#include <string>
#include <vector>

extern "C" {

static const size_t MAX_INPUT_SIZE = 8192;
static int g_verbose = 0;

static int test_generated_brace_case(const uint8_t *data, size_t size,
                                     const char *cwd);

/* CWD strategies for shell_dep_graph_parse. NULL tests the early substitution
 * to
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
      SHELL_FEAT_GROUP | SHELL_FEAT_BACKGROUND;
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
        (r->features & ~valid_features) != 0) {
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
      return 1;
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    bool ok =
        (shell_tokenize_commands(item.input, strlen(item.input), &commands,
                                 &command_count) == SHELL_TOKENIZE_OK);
    shell_commands_free(commands, command_count);
    if (!ok || command_count != item.count)
      return 1;
  }
  static const struct {
    const char *input;
    size_t command_count;
  } brace_descriptor_cases[] = {
      {"{ echo one; echo two; }", 2},
      {"{ ( echo one; ); { echo two; }; }", 2},
      {"{ echo \"$(printf '}')\"; # }\n echo two; }", 2},
      {"{\n echo one\n} | { cat; }", 2},
      {"{\r\n echo one\r\n} | { cat; }", 2},
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
        memcmp(processed.groups, fast.groups,
               fast.group_count * sizeof(*fast.groups)) != 0) {
      if (g_verbose)
        fprintf(stderr,
                "brace oracle mismatch: %s (fast=%d count=%u groups=%u "
                "processed=%d count=%zu groups=%zu)\n",
                input, fast_status, fast.count, fast.group_count,
                processed_status, processed.command_count,
                processed.group_count);
      shell_processed_commands_free(&processed);
      return 1;
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
      return 1;
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
      read_count += graph.edges[i].type == SHELL_EDGE_READ;
    for (uint32_t i = 0; i < graph.edge_count; i++)
      pipe_count += graph.edges[i].type == SHELL_EDGE_PIPE;
    /* Group-owned input is represented as one DOC -> GROUP relation, not a
     * synthetic fan-out to each member command. */
    if (command_count != item.command_count || document_count != 1 ||
        read_count != 1 || pipe_count != item.pipe_count)
      return 1;
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
    return 1;
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
    here_reads += current->type == SHELL_EDGE_READ;
    here_substitutions +=
        current->type == SHELL_EDGE_SUBST &&
        current->to < group_herestring_graph.node_count &&
        group_herestring_graph.nodes[current->to].type == SHELL_NODE_DOC &&
        group_herestring_graph.nodes[current->to].doc.kind ==
            SHELL_DOC_HERESTRING;
  }
  if (here_documents != 2 || transient_here_documents != 1 || here_reads != 1 ||
      here_substitutions != 1)
    return 1;
  struct dep_oracle_case {
    const char *input;
    uint32_t command_count;
    uint32_t substitution_edges;
  };
  static const dep_oracle_case dep_cases[] = {
      {"echo $(id)", 2, 1},
      {"echo $(id)$(pwd)", 3, 2},
      {"echo prefix$(id)suffix$(pwd)", 3, 2},
      {"echo $(id)`pwd`", 3, 2},
      {"echo $(( $(id) + 1 ))", 2, 1},
      {"echo \\$(id)", 1, 0},
      {"echo \\\\$(id)", 2, 1},
      {"echo \"$(id)$(pwd)\"", 3, 2},
      {"sh <<< $(printf data)", 2, 1},
      {"cat <(printf \\))", 2, 1},
      {"cat <(printf \\\\)", 2, 1},
  };
  for (const dep_oracle_case &item : dep_cases) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(item.input, strlen(item.input), ".", NULL,
                              &graph) != SHELL_DEP_OK ||
        !shellsplit_test_depgraph_invariants(item.input, strlen(item.input),
                                             SHELL_DEP_OK, &graph,
                                             &SHELL_DEP_LIMITS_DEFAULT))
      return 1;
    uint32_t command_count = 0;
    uint32_t substitution_edges = 0;
    for (uint32_t i = 0; i < graph.node_count; i++)
      command_count += graph.nodes[i].type == SHELL_NODE_CMD;
    for (uint32_t i = 0; i < graph.edge_count; i++)
      substitution_edges += graph.edges[i].type == SHELL_EDGE_SUBST;
    if (command_count != item.command_count ||
        substitution_edges != item.substitution_edges)
      return 1;
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
      return 1;
    uint32_t command_count = 0;
    bool edge_seen = false;
    for (uint32_t i = 0; i < graph.node_count; i++) {
      if (graph.nodes[i].type != SHELL_NODE_CMD)
        continue;
      if (command_count++ == 0 &&
          (graph.nodes[i].cmd.group_depth != item.group_depth ||
           graph.nodes[i].cmd.backgrounded != item.backgrounded))
        return 1;
    }
    for (uint32_t i = 0; i < graph.edge_count; i++)
      edge_seen = edge_seen || graph.edges[i].type == item.edge;
    if (command_count != item.command_count || !edge_seen)
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
    if ((shell_tokenize_commands(input, strlen(input), &commands,
                                 &command_count) == SHELL_TOKENIZE_OK)) {
      shell_commands_free(commands, command_count);
      return 1;
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
      return 1;
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) !=
            SHELL_DEP_EPARSE ||
        graph.status != SHELL_DEP_STATUS_ERROR)
      return 1;
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
      return 1;
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
      return 1;
    }
    shell_commands_free(commands, command_count);
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

static int test_depgraph(const char *input, size_t length, const char *cwd) {
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
        shell_dep_graph_parse(input, length, cwd, &limits[i], &graph);
    if (validate_depgraph(input, length, error, &graph, &limits[i]))
      return 1;
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
            tok->type > SHELL_TOKEN_REDIRECT_CLOBBER ||
            tok->position > length || tok->length > length - tok->position ||
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

static int test_tokenizer_state(const char *input, size_t length) {
  shell_tokenizer_state_t state = {};
  shell_tokenizer_init(&state, input, strlen(input));

  size_t steps = 0;
  size_t previous_end = 0;
  std::vector<shell_token_t> iterated;
  bool terminated = false;
  while (steps++ <= length + 32) {
    shell_token_t token = {};
    bool produced = shell_tokenizer_next(&state, &token);
    if (!produced || token.type == SHELL_TOKEN_END) {
      terminated = true;
      break;
    }
    if (token.type < SHELL_TOKEN_COMMAND ||
        token.type > SHELL_TOKEN_REDIRECT_CLOBBER || token.position > length ||
        token.length > length - token.position ||
        token.start != input + token.position || token.position < previous_end)
      return 1;
    if (token.type != SHELL_TOKEN_GROUP_START &&
        token.type != SHELL_TOKEN_GROUP_END)
      iterated.push_back(token);
    previous_end = token.position + token.length;
  }
  if (!terminated)
    return 1;

  shell_command_t *commands = NULL;
  size_t command_count = 0;
  bool full_ok = (shell_tokenize_commands(input, strlen(input), &commands,
                                          &command_count) == SHELL_TOKENIZE_OK);
  if (!full_ok) {
    shell_commands_free(commands, command_count);
    return 0;
  }
  if (command_count == 0) {
    shell_commands_free(commands, command_count);
    return 0;
  }
  size_t expected = 0;
  for (size_t i = 0; i < command_count; i++)
    expected += commands[i].token_count;
  if (iterated.size() != expected) {
    shell_commands_free(commands, command_count);
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
        shell_commands_free(commands, command_count);
        return 1;
      }
    }
  }
  shell_commands_free(commands, command_count);
  return 0;
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
    if (shell_interop_format_features(UINT16_MAX, features, sizeof(features),
                                      &written) != SHELL_OK ||
        written == 0 ||
        !shell_interop_command_type_name(
            static_cast<shell_cmd_type_t>(UINT16_MAX)))
      goto fail;
  }
  /* Reuse the handle after both a successful and an invalid/empty parse. */
  if (shell_interop_parse(handle, "echo ok", 7, &count) != SHELL_OK ||
      count != 1 || shell_interop_subcommand_count(handle) != 1 ||
      shell_interop_parse(handle, NULL, 0, &count) != SHELL_EINPUT ||
      shell_interop_subcommand_count(handle) != 0 ||
      shell_interop_subcommand_dup(handle, 0) != NULL)
    goto fail;
  shell_interop_free(handle);
  return 0;

fail:
  shell_interop_free(handle);
  return 1;
}

static int test_abstraction(const char *input, size_t length) {
  if (length == 0)
    return shell_classify_raw_token(NULL, 0) == SHELL_TOKEN_END ? 0 : 1;

  (void)shell_classify_raw_token(input, length);
  shell_abstract_command_t *command = nullptr;
  if (shell_abstract_command_parse(input, length, &command) !=
      SHELL_ABSTRACT_OK)
    command = nullptr;
  bool success = command != NULL;
  if (!success)
    return command != NULL;
  if (!command || !shell_abstract_command_get_source(command) ||
      !shell_abstract_command_get_display_text(command)) {
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
      shell_abstract_command_find_element(command, "__missing__") != NULL ||
      shell_abstract_command_has_variables(command) != command->has_variables ||
      shell_abstract_command_has_pos_vars(command) != command->has_pos_vars ||
      shell_abstract_command_has_special_vars(command) !=
          command->has_special_vars ||
      shell_abstract_command_has_globs(command) != command->has_globs ||
      shell_abstract_command_has_paths(command) != command->has_paths ||
      shell_abstract_command_has_abs_paths(command) != command->has_abs_paths ||
      shell_abstract_command_has_rel_paths(command) != command->has_rel_paths ||
      shell_abstract_command_has_home_paths(command) !=
          command->has_home_paths ||
      shell_abstract_command_has_cmd_subst(command) != command->has_cmd_subst ||
      shell_abstract_command_has_redirects(command) != command->has_redirects ||
      shell_abstract_command_has_strings(command) != command->has_strings ||
      shell_abstract_command_has_arithmetic(command) !=
          command->has_arithmetic) {
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
  (void)shell_env_screener_combined_score(text);
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
          (tcmd->tokens == NULL) != (tcmd->token_count == 0) ||
          shell_transformed_command_get_display_text(tcmd) !=
              tcmd->display_text ||
          shell_transformed_command_has_transformations(tcmd) !=
              tcmd->has_transformations) {
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
            tok->is_shell_construct != transformed) {
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

// Test processor metadata and canonical sequence rendering together.
static int test_processor(const char *input, size_t input_length) {
  shell_command_info_t *infos = NULL;
  size_t command_count = 0;
  static const shell_process_limits_t limits = {1u << 20, 4u << 20, 0};
  shell_process_status_t status = shell_process_command(
      input, input_length, &limits, &infos, &command_count);
  bool success = status == SHELL_PROCESS_OK;
  char *sequence = NULL;
  size_t sequence_count = 0;
  bool has_shell_features = false;
  shell_process_status_t extracted_status =
      shell_build_netargv_sequence(input, input_length, &limits, &sequence,
                                   &sequence_count, &has_shell_features);
  bool extracted = extracted_status == SHELL_PROCESS_OK;

  /* The flat processor preserves an empty lexical result for diagnostics,
   * whereas a canonical netargv sequence requires source that contains a
   * command. This is an intentional semantic boundary, not a differential
   * parser failure. */
  if (success && command_count == 0 && !extracted &&
      extracted_status == SHELL_PROCESS_EINPUT && sequence == NULL &&
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
      char *netargv = NULL;
      structured_canonical =
          processed.commands[i].command_token_count != 0 &&
          shell_render_netargv(&processed.commands[i], &limits, &netargv) ==
              SHELL_PROCESS_OK &&
          netargv != NULL;
      free(netargv);
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
    free(sequence);
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
        sequence == NULL && sequence_count == 0 && !has_shell_features;
    if (!canonical_capacity && g_verbose)
      fprintf(stderr,
              "processor canonical-capacity mismatch: flat=%d/%zu "
              "sequence=%d/%zu structured=%d/%zu groups=%zu ops=%zu\n",
              status, command_count, extracted_status, sequence_count,
              processed_status, processed.command_count, processed.group_count,
              processed.group_io_op_count);
    shell_processed_commands_free(&processed);
    shell_command_infos_free(infos, command_count);
    free(sequence);
    return canonical_capacity ? 0 : 1;
  }

  if (success != extracted) {
    if (g_verbose)
      fprintf(stderr,
              "processor success mismatch: flat=%d/%zu sequence=%d/%zu\n",
              status, command_count, extracted_status, sequence_count);
    shell_command_infos_free(infos, command_count);
    free(sequence);
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
      free(sequence);
      return 1;
    }
    shell_command_infos_free(infos, command_count);
    free(sequence);
    return 0;
  }

  if ((infos == NULL) != (command_count == 0) || (sequence == NULL) ||
      sequence_count != command_count) {
    if (g_verbose)
      fprintf(stderr,
              "processor output mismatch: infos=%p/%zu sequence=%p/%zu\n",
              (void *)infos, command_count, (void *)sequence, sequence_count);
    shell_command_infos_free(infos, command_count);
    free(sequence);
    return 1;
  }

  bool expected_features = false;
  if (infos) {
    for (size_t i = 0; i < command_count; i++) {
      shell_command_info_t *info = &infos[i];
      char *netargv = NULL;
      if (!info->original_command ||
          (info->shell_tokens == NULL) != (info->shell_token_count == 0) ||
          (info->command_tokens == NULL) != (info->command_token_count == 0) ||
          !tokens_refer_to_owned_command(info->shell_tokens,
                                         info->shell_token_count,
                                         info->original_command) ||
          !tokens_refer_to_owned_command(info->command_tokens,
                                         info->command_token_count,
                                         info->original_command) ||
          shell_render_netargv(info, &limits, &netargv) != SHELL_PROCESS_OK) {
        free(netargv);
        shell_command_infos_free(infos, command_count);
        free(sequence);
        return 1;
      }
      free(netargv);
      expected_features |= shell_command_info_has_dangerous_features(info);
    }
  }

  /* shell_process_command permits a syntactically valid comment-only input
   * with no command records; the descriptor-bearing API deliberately treats
   * that as no command line. Its result contract is exercised for every
   * material command below. */
  if (command_count == 0) {
    shell_command_infos_free(infos, command_count);
    free(sequence);
    return expected_features != has_shell_features;
  }

  shell_parse_result_t fast = {};
  if (shell_parse_fast(input, input_length, NULL, &fast) == SHELL_OK) {
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
          !processed_groups_match_fast(&fast, &processed)))) {
      if (g_verbose)
        fprintf(stderr,
                "processor descriptor mismatch: input=%.*s process=%d/%zu "
                "processed=%d/%zu groups=%zu fast-groups=%u\n",
                (int)input_length, input, status, command_count,
                processed_status, processed.command_count,
                processed.group_count, fast.group_count);
      shell_processed_commands_free(&processed);
      shell_command_infos_free(infos, command_count);
      free(sequence);
      return 1;
    }
    shell_processed_commands_free(&processed);
  }

  shell_command_infos_free(infos, command_count);
  free(sequence);
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

static bool valid_generated_outer_netsequence(const char *sequence,
                                              uint32_t expected_count) {
  size_t count = 0;
  return sequence != NULL &&
         shell_netstring_validate(sequence, strlen(sequence), &count) ==
             SHELL_NETSTRING_OK &&
         count == expected_count;
}

static bool valid_generated_netargv_sequence(const char *sequence,
                                             uint32_t expected_count) {
  if (!valid_generated_outer_netsequence(sequence, expected_count))
    return false;
  shell_netstring_iter_t iterator = {};
  if (shell_netstring_iter_init(&iterator, sequence, strlen(sequence)) !=
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
  shell_limits_t strict_limits = {SHELL_MAX_SUBCOMMANDS, true};
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
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    return fast_error != SHELL_OK || strict_error != SHELL_EPARSE;
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
                    op->kind == SHELL_GROUP_IO_BACKGROUND;
    bool shared_pipeline_operator =
        i > 0 &&
        processed.group_io_ops[i - 1].kind == SHELL_GROUP_IO_PIPE_OUTPUT &&
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
    graph_reads += graph.edges[i].type == SHELL_EDGE_READ;
    graph_pipes += edge->type == SHELL_EDGE_PIPE;
    graph_writes +=
        edge->type == SHELL_EDGE_WRITE || edge->type == SHELL_EDGE_APPEND;
    if (edge->type == SHELL_EDGE_READ &&
        graph.nodes[edge->to].type != SHELL_NODE_GROUP &&
        (!item.command_local_documents ||
         graph.nodes[edge->to].type != SHELL_NODE_CMD))
      group_endpoints_valid = false;
    if ((edge->type == SHELL_EDGE_WRITE || edge->type == SHELL_EDGE_APPEND) &&
        graph.nodes[edge->from].type != SHELL_NODE_GROUP)
      group_endpoints_valid = false;
    /* A redirected group input leaves its upstream writer connected to a
     * terminal ENDPOINT.  That is intentionally not a group endpoint: it
     * records the real pipe write after fd 0 has been replaced. */
    if (edge->type == SHELL_EDGE_PIPE && edge->from != outer_group &&
        edge->to != outer_group &&
        graph.nodes[edge->to].type != SHELL_NODE_ENDPOINT)
      group_endpoints_valid = false;
  }

  shell_dep_graph_validation_t graph_validation =
      shell_dep_graph_validate(&graph);
  char *netargv_sequence = NULL;
  char *command_netseq = NULL;
  char *type_netseq = NULL;
  char *paired_command_netseq = NULL;
  char *paired_type_netseq = NULL;
  size_t netargv_count = 0;
  size_t command_netseq_count = 0;
  size_t type_netseq_count = 0;
  size_t paired_count = 0;
  bool has_shell_features = false;
  shell_process_status_t netargv_status = shell_build_netargv_sequence(
      item.command.data(), item.command.size(), NULL, &netargv_sequence,
      &netargv_count, &has_shell_features);
  shell_process_status_t command_netseq_status =
      shell_build_command_netseq(item.command.data(), item.command.size(), NULL,
                                 &command_netseq, &command_netseq_count);
  shell_process_status_t type_netseq_status =
      shell_build_type_netseq(item.command.data(), item.command.size(), NULL,
                              &type_netseq, &type_netseq_count);
  shell_process_status_t paired_netseq_status = shell_build_anomaly_netseqs(
      item.command.data(), item.command.size(), NULL, &paired_command_netseq,
      &paired_type_netseq, &paired_count);
  bool sequences_valid =
      netargv_status == SHELL_PROCESS_OK && netargv_count != 0 &&
      valid_generated_netargv_sequence(netargv_sequence, netargv_count) &&
      command_netseq_status == SHELL_PROCESS_OK &&
      command_netseq_count == netargv_count &&
      valid_generated_outer_netsequence(command_netseq, command_netseq_count) &&
      type_netseq_status == SHELL_PROCESS_OK &&
      type_netseq_count == netargv_count &&
      valid_generated_outer_netsequence(type_netseq, type_netseq_count) &&
      paired_netseq_status == SHELL_PROCESS_OK &&
      paired_count == netargv_count &&
      strcmp(command_netseq, paired_command_netseq) == 0 &&
      strcmp(type_netseq, paired_type_netseq) == 0;
  if (!sequences_valid && g_verbose)
    fprintf(stderr,
            "generated sequence mismatch: netargv=%d/%zu command=%d/%zu "
            "type=%d/%zu paired=%d/%zu features=%d\n",
            netargv_status, netargv_count, command_netseq_status,
            command_netseq_count, type_netseq_status, type_netseq_count,
            paired_netseq_status, paired_count, has_shell_features);
  free(paired_type_netseq);
  free(paired_command_netseq);
  free(type_netseq);
  free(command_netseq);
  free(netargv_sequence);
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
  char *netargv_sequence = NULL;
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
  shell_process_status_t netargv_error = shell_build_netargv_sequence(
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
        if (edge->source_fd != 1)
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
             SHELL_DEP_DOC_FLAG_DYNAMIC_NAME) == 0)
          topology_valid = false;
      }
    }
    if (edge->type == SHELL_EDGE_WRITE &&
        graph.nodes[edge->to].type == SHELL_NODE_ENDPOINT) {
      collector_writes++;
      if (edge->source_fd != item.outer_fd && edge->source_fd != 1)
        topology_valid = false;
    }
  }
  for (uint32_t i = 0; i < graph.edge_count; i++)
    if (graph.edges[i].type == SHELL_EDGE_READ &&
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
    free(netargv_sequence);
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    return failed;
  }
  bool failed =
      fast_error != SHELL_OK || full_error != SHELL_TOKENIZE_OK ||
      process_error != SHELL_PROCESS_OK || graph_error != SHELL_DEP_OK ||
      netargv_error != SHELL_PROCESS_OK || !has_shell_features ||
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
        "process=%d graph=%d netargv=%d surface=%zu/%zu/%zu/%u "
        "nodes=%u/%u groups=%u/%u "
        "endpoints=%u/%u substitutions=%u/%u shell-words=%u "
        "dynamic-names=%u/%u "
        "file-substitutions=%u/%u "
        "writes=%u/%u heredocs=%u/%u literal=%u/%u transient=%u/%u "
        "heredoc-substitutions=%u/%u herestrings=%u/%u "
        "herestring-substitutions=%u/%u topology=%d validation=%d)\n",
        item.command.c_str(), fast_error, full_error, process_error,
        graph_error, netargv_error, command_count, processed.command_count,
        netargv_count, item.surface_command_count, graph_commands,
        item.command_count, graph_groups, item.group_count, graph_endpoints,
        item.endpoint_count, substitution_edges, item.substitution_edge_count,
        shell_word_substitution_edges, dynamic_name_substitution_edges,
        item.dynamic_name_substitution_count, file_substitution_edges,
        item.file_substitution_count, collector_writes,
        item.collector_write_count, heredoc_count, item.heredoc_count,
        literal_heredoc_count, item.literal_heredoc_count,
        transient_heredoc_count, item.transient_heredoc_count,
        heredoc_substitution_count, item.heredoc_substitution_count,
        herestring_count, item.herestring_count, herestring_substitution_count,
        item.herestring_substitution_count, topology_valid, validation.valid);
  free(netargv_sequence);
  shell_commands_free(commands, command_count);
  shell_processed_commands_free(&processed);
  return failed;
}

static int test_generated_substitution_case(const uint8_t *data, size_t size,
                                            const char *cwd) {
  return test_substitution_case(shell_brace_fuzz_substitution_case(data, size),
                                cwd);
}

static int test_composed_substitution_case(const uint8_t *data, size_t size,
                                           const char *cwd) {
  return test_substitution_case(
      shell_brace_fuzz_composed_substitution_case(data, size), cwd);
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
              data[4 + level] = (group_mask >> level) & 1u;
            if (test_composed_substitution_case(data, sizeof(data), cwd))
              return 1;
          }
        }
      }
    }
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static bool fixed_oracles_checked = false;
  if (!fixed_oracles_checked) {
    if (test_fixed_oracles())
      abort();
    for (uint8_t selector = 0;
         selector < SHELL_BRACE_FUZZ_SUBSTITUTION_CASE_COUNT; selector++)
      if (test_generated_substitution_case(&selector, 1, "/tmp"))
        abort();
    for (uint8_t selector = 0;
         selector < SHELL_BRACE_FUZZ_COMPOSED_SUBSTITUTION_CASE_COUNT;
         selector++)
      if (test_composed_substitution_case(&selector, 1, "/tmp"))
        abort();
    static const uint8_t local_document_selectors[] = {58, 59, 60};
    for (uint8_t selector : local_document_selectors)
      if (test_generated_brace_case(&selector, 1, "/tmp"))
        abort();
    if (test_composed_substitution_matrix("/tmp"))
      abort();
    fixed_oracles_checked = true;
  }

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
  run_check("dependency graph", test_depgraph(cmd.data(), cmd.size(), cwd));
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
  switch (size == 0 ? 0 : data[0] % 3) {
  case 0:
    run_check("generated brace case",
              test_generated_brace_case(data, size, cwd));
    break;
  case 1:
    run_check("generated substitution case",
              test_generated_substitution_case(data, size, cwd));
    break;
  default:
    run_check("composed substitution case",
              test_composed_substitution_case(data, size, cwd));
    break;
  }
  free(input);
  if (failed)
    abort();

  return 0;
}

} // extern "C"
