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
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "../src/shell_tokenizer_full_internal.h"

static const size_t MAX_INPUT_SIZE = 8192;
static int g_verbose = 0;

static int test_generated_brace_case(const uint8_t *data, size_t size,
                                     const char *cwd);
static int test_tokenizer_state(const char *input, size_t length);

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
        (r->modifiers & ~SHELL_CMD_MOD_PIPE_NEGATED) != 0 ||
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
        (group->modifiers & ~SHELL_CMD_MOD_PIPE_NEGATED) != 0 ||
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
      return 1;
  }
  const char *incomplete_ansi = "echo $'foo\\'";
  shell_parse_result_t incomplete = {};
  shell_limits_t strict = SHELL_LIMITS_DEFAULT;
  strict.strict_mode = true;
  if (shell_parse_fast(incomplete_ansi, strlen(incomplete_ansi), &strict,
                       &incomplete) != SHELL_EPARSE)
    return 1;
  /* The iterator intentionally exposes a standalone escaped physical line
   * ending while the structured tokenizer omits it from command records.
   * Keep this exact smoke finding deterministic so their comparison remains
   * semantic rather than byte-for-byte lexical. */
  static const char iterator_continuation[] = "echo first \\\nsecond | cat\n";
  if (test_tokenizer_state(iterator_continuation,
                           sizeof(iterator_continuation) - 1))
    return 1;
  static const char iterator_heredoc_boundary[] = "cat& <<EOF\nvalue\nEOF\n";
  if (test_tokenizer_state(iterator_heredoc_boundary,
                           sizeof(iterator_heredoc_boundary) - 1))
    return 1;
  /* A heredoc that remains attached to a command retains its following
   * newline. This complements the input-only heredoc case above. */
  static const char iterator_attached_heredoc[] = "cat <<EOF\nvalue\nEOF\n";
  if (test_tokenizer_state(iterator_attached_heredoc,
                           sizeof(iterator_attached_heredoc) - 1))
    return 1;
  static const char *const bang_context_cases[] = {
      "printf '%s' !\n",      "printf '%s' ! !\n", "printf '%s' ! | cat\n",
      "printf '%s' >out !\n", "! printf '%s'\n",   "! ! printf '%s'\n",
  };
  for (const char *source : bang_context_cases)
    if (test_tokenizer_state(source, strlen(source))) {
      fprintf(stderr, "fixed tokenizer bang-context oracle failed: %s", source);
      return 1;
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
    char *sequence = NULL;
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
        shell_build_netargv_sequence(item.input, strlen(item.input), NULL,
                                     &sequence, &sequence_count,
                                     &sequence_features) == SHELL_PROCESS_OK &&
        sequence_count == 1 && sequence_features == item.has_cmd_subst;
    free(sequence);
    shell_command_infos_free(processed, processed_count);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
    if (!metadata_ok)
      return 1;
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
    return 1;
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
    return 1;

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
    return 1;

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
    return 1;

  /* Bash consumes an immediate raw `-` as a duplication close marker even
   * when a word follows without whitespace. Keep the lexer, canonical argv,
   * and dependency graph aligned without adding a checked-in smoke seed. */
  static const char raw_close_suffix[] = "printf x >&-file";
  shell_command_t *close_tokens = NULL;
  size_t close_token_count = 0;
  shell_command_info_t *close_infos = NULL;
  size_t close_info_count = 0;
  char *close_netargv = NULL;
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
      shell_render_netargv(&close_infos[0], NULL, &close_netargv) ==
          SHELL_PROCESS_OK &&
      close_netargv != nullptr &&
      strcmp(close_netargv, "6:printf,1:x,4:file,") == 0 &&
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
  free(close_netargv);
  if (!raw_close_suffix_ok || !close_edge || file_document)
    return 1;

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
    return 1;

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
    return 1;

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
        graph.edge_count == 0 && shell_dep_graph_validate(&graph).valid;
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    if (!opaque_word_ok)
      return 1;
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
      return 1;
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
      return 1;
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
      return 1;
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
      return 1;
  }

  /* Named descriptors prefix document redirects; neither the descriptor nor
   * the document marker may become argv.  Keep these fixed cross-layer
   * oracles outside the checked-in smoke corpus. */
  static const char *const named_document_cases[] = {
      "printf x {fd}<<<body",     "printf x {fd}<<EOF\nbody\nEOF\n",
      "{ cat; } {fd}<<<body",     "{ cat; } {fd}<<EOF\nbody\nEOF\n",
      "printf x {f\\\nd}<<<body", "{ cat; } {f\\\r\nd}\\\n<<EOF\nbody\nEOF\n",
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
      return 1;
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
      "exec {f\\\rd}>out; printf x >&$fd",
      "exec {fd}>out; printf x >&$f\\\rd",
      "exec {f\\\r\nd}>out; printf x >&$fd",
      "exec {fd}>out; printf x >&\"${f\\\r\nd}\"",
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
      return 1;
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
      return 1;
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
      return 1;
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
    return 1;
  uint32_t stdout_writes = 0;
  uint32_t stderr_writes = 0;
  for (uint32_t edge = 0; edge < braced_named_graph.edge_count; edge++) {
    const shell_dep_edge_t *current = &braced_named_graph.edges[edge];
    if (current->type != SHELL_EDGE_WRITE)
      continue;
    stdout_writes += current->source_fd == 1;
    stderr_writes += current->source_fd == 2;
  }
  if (stdout_writes != 1 || stderr_writes != 0)
    return 1;

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
      return 1;
  }

  static const char *const static_legacy_redirect_cases[] = {
      "printf x >&literal{path}",
      "printf x >&literal$destination",
      "printf x >&literal${destination}",
      "printf x >&literal$((1 + 2))",
      "printf x >&\"\"literal$(printf target)",
      "printf x >&file{one,two}",
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
      return 1;
  }

  /* Invalid static descriptor targets must be rejected by the processors as
   * well as the graph. Keep this independent of corpus seeds: it protects the
   * shared legacy `>&word` classifier's fail-closed outcome. */
  static const char *const invalid_static_legacy_redirects[] = {
      "printf x >&2147483648",
      "printf x >&00000000000000000000000000000000002147483648",
      "printf x >&\"\"",
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
      return 1;
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
      {"cat log &> >(sh) >out", "out", nullptr, SHELL_EDGE_WRITE,
       SHELL_EDGE_WRITE, false, true},
      {"cat log &>> >(sh) 2>>err", nullptr, "err", SHELL_EDGE_WRITE,
       SHELL_EDGE_APPEND, true, false},
      {"cat log >& >(sh) 2>&-", nullptr, nullptr, SHELL_EDGE_WRITE,
       SHELL_EDGE_WRITE, true, false},
      {"cat log &> >(sh) >out 2>&1", "out", "out", SHELL_EDGE_WRITE,
       SHELL_EDGE_WRITE, false, false},
  };
  for (const combined_process_route_oracle &item :
       combined_process_route_cases) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(item.input, strlen(item.input), "/tmp", NULL,
                              &graph) != SHELL_DEP_OK ||
        !shell_dep_graph_validate(&graph).valid)
      return 1;
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
      return 1;
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
  };
  for (const char *input : named_fd_snapshot_rejections) {
    shell_dep_graph_t graph = {};
    if (shell_dep_graph_parse(input, strlen(input), "/tmp", NULL, &graph) !=
            SHELL_DEP_EPARSE ||
        graph.node_count != 0 || graph.edge_count != 0 ||
        graph.status != SHELL_DEP_STATUS_ERROR)
      return 1;
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
      return 1;
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
      return 1;
  }

  static const char compound_words[] =
      "$'c'3>out;cat \"x\"${y}z;my\\\r\ncommand value";
  char *raw = nullptr;
  char *typed = nullptr;
  size_t compound_count = 0;
  bool compound_ok =
      shell_build_anomaly_netseqs(compound_words, sizeof(compound_words) - 1,
                                  NULL, &raw, &typed,
                                  &compound_count) == SHELL_PROCESS_OK &&
      compound_count == 3 && raw && typed &&
      strcmp(raw, "2:c3,3:cat,9:mycommand,") == 0 &&
      strcmp(typed, "5:2:c3,,12:3:cat,3:STR,,18:9:mycommand,3:STR,,") == 0;
  free(typed);
  free(raw);
  if (!compound_ok)
    return 1;

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
      return 1;
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
      {"printf x |& \\\r\ncat", SHELL_TYPE_PIPELINE,
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
      return 1;
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
      {"printf %s $\\\r\n(printf child)", 2, 1},
      {"printf %s $\\\r((1 + 2))", 1, 0},
      {"printf %s $((1)\\\n)", 1, 0},
      {"printf %s $\\\n'ansi'", 1, 0},
      {"cat <\\\n(printf input) > \\\r\n>(cat)", 3, 2},
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
      return 1;
    }
  }

  /* Standalone word decoding preserves bytes, including a NUL produced by an
   * ANSI-C quote after an escaped LF or CRLF. Complete-command semantics
   * reject that source: Bash truncates the quoted segment at the NUL. Keep
   * these distinct contracts outside the bounded smoke corpus. */
  static const char *const continued_ansi_words[] = {
      "$\\\n'\\x41\\0B'",
      "$\\\r\n'\\x41\\0B'",
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
      return 1;
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
    return 1;
  }

  /* Reserved words are recognized from their logical, unquoted spelling. A
   * continued keyword must reach the same unsupported-semantics boundary as
   * its ordinary spelling, rather than becoming an executable command. */
  static const char *const continued_control_cases[] = {
      "whi\\\nle true; do :; done",
      "i\\\r\nf true; then :; fi",
      "ca\\\nse value in value) :;; esac",
  };
  for (const char *input : continued_control_cases) {
    shell_processed_commands_t processed = {};
    char *netargv = nullptr;
    size_t netargv_count = 0;
    bool has_shell_features = false;
    bool control_rejected =
        shell_process_commands(input, strlen(input), nullptr, &processed) ==
            SHELL_PROCESS_EPARSE &&
        processed.commands == nullptr && processed.command_count == 0 &&
        shell_build_netargv_sequence(input, strlen(input), nullptr, &netargv,
                                     &netargv_count, &has_shell_features) ==
            SHELL_PROCESS_EPARSE &&
        netargv == nullptr && netargv_count == 0 && !has_shell_features;
    shell_processed_commands_free(&processed);
    free(netargv);
    if (!control_rejected)
      return 1;
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
    return 1;

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
    return 1;

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
    return 1;

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
      return 1;
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
    char *netargv = NULL;
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
        shell_build_netargv_sequence(item.input, length, NULL, &netargv,
                                     &netargv_count,
                                     &features) == SHELL_PROCESS_OK &&
        netargv != NULL && netargv_count == 1 &&
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
    free(netargv);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
    if (!valid)
      return 1;
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
      return 1;
  }

  /* The lexer preserves descriptor-looking prefix words; the structured
   * group and graph APIs reject them because Bash gives legacy `>&word`
   * combined-output syntax only to stdout. */
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
            SHELL_PROCESS_EPARSE ||
        processed.commands != NULL || processed.command_count != 0 ||
        processed.groups != NULL || processed.group_count != 0 ||
        processed.group_io_ops != NULL || processed.group_io_op_count != 0 ||
        shell_dep_graph_parse(input, strlen(input), NULL, NULL, &graph) !=
            SHELL_DEP_EPARSE)
      return 1;
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
    return 1;
  shell_processed_commands_free(&deferred_named_fd);

  if (shell_parse_fast("printf $'a\\0b' @(one|two) xs=(one two) &>out",
                       strlen("printf $'a\\0b' @(one|two) xs=(one two) &>out"),
                       NULL, &modern) != SHELL_OK ||
      modern.count != 1 ||
      (modern.cmds[0].features &
       (SHELL_FEAT_ANSI_C_QUOTE | SHELL_FEAT_EXTGLOB | SHELL_FEAT_ARRAY |
        SHELL_FEAT_COMBINED_REDIRECT)) !=
          (SHELL_FEAT_ANSI_C_QUOTE | SHELL_FEAT_EXTGLOB | SHELL_FEAT_ARRAY |
           SHELL_FEAT_COMBINED_REDIRECT))
    return 1;
  shell_dep_graph_t modern_graph = {};
  if (shell_dep_graph_parse("cmd {trace}> trace.log &>> combined.log",
                            strlen("cmd {trace}> trace.log &>> combined.log"),
                            NULL, NULL, &modern_graph) != SHELL_DEP_OK ||
      !shell_dep_graph_validate(&modern_graph).valid)
    return 1;
  shell_processed_commands_t unsupported = {};
  if (shell_process_commands("select x in one; do :; done",
                             strlen("select x in one; do :; done"), NULL,
                             &unsupported) != SHELL_PROCESS_EPARSE ||
      shell_process_commands("coproc worker { :; }",
                             strlen("coproc worker { :; }"), NULL,
                             &unsupported) != SHELL_PROCESS_EPARSE)
    return 1;
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
  };
  for (const char *input : redirect_boundaries) {
    char *sequence = NULL;
    size_t command_count = 0;
    bool features = false;
    if (shell_build_netargv_sequence(input, strlen(input), NULL, &sequence,
                                     &command_count,
                                     &features) != SHELL_PROCESS_OK ||
        command_count != (strstr(input, "echo hi") ? 2u : 1u)) {
      free(sequence);
      return 1;
    }
    free(sequence);
  }
  static const char *const redirect_followed_by_unsupported[] = {
      "> <(cat)foo declare -a values",
      "> <(cat)foo time echo ok",
      "> <(cat)foo [[ x ]]",
      "> <(cat)foo while true; do :; done",
  };
  for (const char *input : redirect_followed_by_unsupported) {
    shell_processed_commands_t result = {};
    if (shell_process_commands(input, strlen(input), NULL, &result) !=
            SHELL_PROCESS_EPARSE ||
        result.commands != NULL || result.command_count != 0)
      return 1;
  }

  /* These Bash forms remain lexically visible for diagnostics, but the
   * canonical argv, transform, abstraction, and graph APIs must refuse a
   * semantic model they cannot faithfully provide. Keep this independent of
   * checked-in smoke seeds so the fail-closed boundary runs in every session.
   */
  static const char *const unmodeled_semantic_cases[] = {
      "[[ -f /tmp/x ]]",
      "(( count += 1 ))",
      "time -p echo x",
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
      {"cd /tmp", 0, 0},
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
      {"echo \\$(id)", 1, 0},
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
    char *netargv = NULL;
    size_t netargv_count = 0;
    bool has_shell_features = false;
    char *command_netseq = NULL;
    size_t command_netseq_count = 0;
    char *type_netseq = NULL;
    size_t type_netseq_count = 0;
    char *anomaly_commands = NULL;
    char *anomaly_types = NULL;
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
        shell_build_netargv_sequence(input, length, NULL, &netargv,
                                     &netargv_count, &has_shell_features) ==
            SHELL_PROCESS_EPARSE &&
        netargv == NULL && netargv_count == 0 &&
        shell_build_command_netseq(input, length, NULL, &command_netseq,
                                   &command_netseq_count) ==
            SHELL_PROCESS_EPARSE &&
        command_netseq == NULL && command_netseq_count == 0 &&
        shell_build_type_netseq(input, length, NULL, &type_netseq,
                                &type_netseq_count) == SHELL_PROCESS_EPARSE &&
        type_netseq == NULL && type_netseq_count == 0 &&
        shell_build_anomaly_netseqs(input, length, NULL, &anomaly_commands,
                                    &anomaly_types,
                                    &anomaly_count) == SHELL_PROCESS_EPARSE &&
        anomaly_commands == NULL && anomaly_types == NULL &&
        anomaly_count == 0 &&
        shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
            SHELL_DEP_EPARSE &&
        graph.status == SHELL_DEP_STATUS_ERROR;
    shell_commands_free(commands, command_count);
    shell_command_infos_free(infos, info_count);
    shell_processed_commands_free(&processed);
    free(netargv);
    free(command_netseq);
    free(type_netseq);
    free(anomaly_commands);
    free(anomaly_types);
    if (!rejected)
      return 1;
  }

  static const char *const accepted_redirect_operands[] = {
      "echo > \\\nout",
      "echo 2> \\\r\nerr",
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
    char *netargv = NULL;
    size_t netargv_count = 0;
    bool has_shell_features = false;
    shell_dep_graph_t graph = {};
    bool accepted =
        shell_parse_fast(input, length, NULL, &fast) == SHELL_OK &&
        shell_tokenize_commands(input, length, &commands, &command_count) ==
            SHELL_TOKENIZE_OK &&
        shell_process_commands(input, length, NULL, &processed) ==
            SHELL_PROCESS_OK &&
        shell_build_netargv_sequence(input, length, NULL, &netargv,
                                     &netargv_count,
                                     &has_shell_features) == SHELL_PROCESS_OK &&
        shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    shell_commands_free(commands, command_count);
    shell_processed_commands_free(&processed);
    free(netargv);
    if (!accepted)
      return 1;
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
      return 1;
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
      if (graph.edges[edge].type == SHELL_EDGE_READ &&
          graph.edges[edge].from == document) {
        reader = graph.edges[edge].to;
        break;
      }
    }
    if (group == UINT32_MAX || document == UINT32_MAX || reader == UINT32_MAX ||
        (item.continued ? command_count != 1 || reader != group
                        : command_count != 2 || empty_command == UINT32_MAX ||
                              reader != empty_command))
      return 1;
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

static int test_depgraph(const char *input, size_t length, const char *cwd) {
  static const shell_dep_limits_t limits[] = {
      SHELL_DEP_LIMITS_DEFAULT,
      {0, 0, 0, 2, false, nullptr, 0},
      {4, 4, 2, 32, true, nullptr, 0},
      {SHELL_DEP_MAX_NODES, SHELL_DEP_MAX_EDGES, SHELL_DEP_MAX_TOKENS, 1, false,
       nullptr, 0},
      {SHELL_DEP_MAX_NODES, SHELL_DEP_MAX_EDGES, SHELL_DEP_MAX_TOKENS, 2, false,
       nullptr, 0},
      {SHELL_DEP_MAX_NODES, SHELL_DEP_MAX_EDGES, SHELL_DEP_MAX_TOKENS,
       SHELL_DEP_CWD_BUF_SIZE - 1, false, nullptr, 0},
      {SHELL_DEP_MAX_NODES, SHELL_DEP_MAX_EDGES, SHELL_DEP_MAX_TOKENS,
       SHELL_DEP_CWD_BUF_SIZE, false, nullptr, 0},
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
         (token.start[0] == '\n' || token.start[0] == '\r');
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

/* The iterator exposes a standalone escaped physical line ending so list
 * validation can discard it before classifying the token that follows. The
 * structured tokenizer intentionally omits this grammar-only token from its
 * command records, so the iterator/reference comparison must do likewise. */
static bool tokenizer_token_is_line_continuation(const shell_token_t &token) {
  if (token.type != SHELL_TOKEN_ARGUMENT || !token.is_escaped ||
      token.length < 2 || token.start[0] != '\\')
    return false;
  if (token.start[1] == '\n')
    return token.length == 2;
  return token.start[1] == '\r' &&
         (token.length == 2 || (token.length == 3 && token.start[2] == '\n'));
}

static int test_tokenizer_state(const char *input, size_t length) {
  shell_tokenizer_state_t state = {};
  shell_tokenizer_init(&state, input, length);

  size_t steps = 0;
  size_t previous_end = 0;
  std::vector<shell_token_t> iterated;
  bool expect_command = true;
  bool follows_empty_heredoc = false;
  bool terminated = false;
  while (steps++ <= length + 32) {
    shell_token_t token = {};
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
    /* An input-only heredoc after a list separator has no command record to
     * own its document-closing separator. The iterator still exposes that
     * newline while the structured tokenizer intentionally drops the empty
     * trailing record. A heredoc attached to an ordinary command retains its
     * newline and must continue through the normal comparison below. */
    if (follows_empty_heredoc && tokenizer_token_is_newline(token)) {
      follows_empty_heredoc = false;
      previous_end = token.position + token.length;
      continue;
    }
    /* The iterator reports a standalone `!` lexically. The allocating
     * tokenizer resolves its context: after a command has begun it is argv,
     * not a pipeline negator. Compare the same contextual token stream. */
    if (token.type == SHELL_TOKEN_PIPE_NEGATE && !expect_command)
      token.type = SHELL_TOKEN_ARGUMENT;
    bool begins_empty_heredoc =
        token.type == SHELL_TOKEN_HEREDOC && expect_command;
    if (token.type == SHELL_TOKEN_GROUP_START) {
      expect_command = true;
    } else if (token.type != SHELL_TOKEN_GROUP_END) {
      if (!(expect_command && tokenizer_token_is_newline(token)))
        iterated.push_back(token);
      if (tokenizer_token_starts_command(token))
        expect_command = false;
      if (tokenizer_token_is_list_operator(token))
        expect_command = true;
    }
    follows_empty_heredoc = begins_empty_heredoc;
    previous_end = token.position + token.length;
  }
  if (!terminated)
    return 1;

  shell_command_t *commands = NULL;
  size_t command_count = 0;
  bool full_ok = (shell_tokenize_commands(input, length, &commands,
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
    if (shell_interop_format_features(UINT32_MAX, features, sizeof(features),
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
  if (item.source_rejected) {
    bool failed = fast_error != SHELL_EPARSE ||
                  full_error != SHELL_TOKENIZE_OK ||
                  process_error != SHELL_PROCESS_EPARSE ||
                  netargv_error != SHELL_PROCESS_EPARSE ||
                  graph_error != SHELL_DEP_EPARSE || graph.node_count != 0 ||
                  graph.edge_count != 0 || processed.command_count != 0 ||
                  processed.commands != NULL || netargv_sequence != NULL ||
                  netargv_count != 0 || has_shell_features;
    if (failed && g_verbose)
      fprintf(stderr,
              "generated unsafe ANSI source accepted: %s "
              "(fast=%d full=%d process=%d netargv=%d graph=%d)\n",
              item.command.c_str(), fast_error, full_error, process_error,
              netargv_error, graph_error);
    free(netargv_sequence);
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
    free(netargv_sequence);
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
    free(netargv_sequence);
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
  free(netargv_sequence);
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
    input = "cat " + number + "\\\r\n2<<<body";
  else
    input = "cat $'x'" + number + ">out";
  bool empty_stage = mode == 0 || mode == 3;
  char *raw = NULL, *typed = NULL;
  size_t count = 0;
  bool valid =
      shell_build_anomaly_netseqs(input.data(), input.size(), NULL, &raw,
                                  &typed, &count) == SHELL_PROCESS_OK;
  valid = valid && count == (empty_stage ? 2u : 1u) &&
          strcmp(raw, empty_stage ? "3:cat,0:," : "3:cat,") == 0;
  free(raw);
  free(typed);
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
      if (graph.edges[e].type == SHELL_EDGE_READ) {
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static bool fixed_oracles_checked = false;
  if (!fixed_oracles_checked) {
    if (test_fixed_oracles())
      abort();
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
         selector < SHELL_BRACE_FUZZ_COMPOSED_SUBSTITUTION_CASE_COUNT;
         selector++)
      if (test_composed_substitution_case(&selector, 1, "/tmp"))
        abort();
    static const uint8_t local_document_selectors[] = {58, 59, 60};
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
  switch (size == 0 ? 0 : data[0] % 5) {
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
  default:
    run_check("generated static arithmetic",
              test_generated_static_arithmetic_case(data, size));
    break;
  }
  free(input);
  if (failed)
    abort();

  return 0;
}

} // extern "C"
