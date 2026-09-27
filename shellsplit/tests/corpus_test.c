/* Cross-surface regression coverage for the anonymous coding-agent corpus.
 * Fixtures are data only: this test only parses and models them. */

#include "depgraph_test_workspace.h"
#include "shell_abstract.h"
#include "shell_depgraph.h"
#include "shell_netstring.h"
#include "shell_processor.h"
#include "shell_sequence.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"
#include "shell_transform.h"
#include "shellclave_command_corpus_fixtures.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned passed;
static unsigned failed;

#define ARRAY_COUNT(values) (sizeof(values) / sizeof((values)[0]))

#define CHECK(condition)                                                       \
  do {                                                                         \
    if (!(condition)) {                                                        \
      printf("    FAIL: %s at %s:%d\n", #condition, __FILE__, __LINE__);       \
      return false;                                                            \
    }                                                                          \
  } while (0)

#define TEST(name) static bool test_##name(void)
#define RUN(name)                                                              \
  do {                                                                         \
    printf("  %-42s ", #name);                                                 \
    if (test_##name()) {                                                       \
      puts("PASS");                                                            \
      passed++;                                                                \
    } else {                                                                   \
      failed++;                                                                \
    }                                                                          \
  } while (0)

static bool valid_netsequence(const shell_netstring_buffer_t *sequence,
                              size_t expected_records) {
  size_t records = 0;
  return sequence->data != NULL && sequence->length != 0 &&
         shell_netstring_validate(sequence->data, sequence->length, &records) ==
             SHELL_NETSTRING_OK &&
         records == expected_records;
}

/* Anomaly netsequences are the sole canonical transport that retains an
 * argv-less stage. Its raw record is empty and its corresponding typed record
 * contains exactly one empty argv[0]. Check both forms together so a later
 * refactor cannot silently turn that structural stage into an executable. */
static bool anomaly_empty_stage_count(const shell_netstring_buffer_t *raw,
                                      const shell_netstring_buffer_t *typed,
                                      size_t *out_count) {
  if (!raw || !typed || !out_count)
    return false;
  *out_count = 0;
  shell_netstring_iter_t raw_records;
  shell_netstring_iter_t typed_records;
  if (shell_netstring_iter_init(&raw_records, raw->data, raw->length) !=
          SHELL_NETSTRING_OK ||
      shell_netstring_iter_init(&typed_records, typed->data, typed->length) !=
          SHELL_NETSTRING_OK)
    return false;
  for (;;) {
    shell_netstring_view_t raw_record;
    shell_netstring_view_t typed_record;
    shell_netstring_status_t raw_status =
        shell_netstring_iter_next(&raw_records, &raw_record);
    shell_netstring_status_t typed_status =
        shell_netstring_iter_next(&typed_records, &typed_record);
    if (raw_status == SHELL_NETSTRING_DONE ||
        typed_status == SHELL_NETSTRING_DONE)
      return raw_status == SHELL_NETSTRING_DONE &&
             typed_status == SHELL_NETSTRING_DONE;
    if (raw_status != SHELL_NETSTRING_OK || typed_status != SHELL_NETSTRING_OK)
      return false;
    if (raw_record.payload_length != 0)
      continue;
    shell_netstring_iter_t argv;
    shell_netstring_view_t argv0;
    if (shell_netstring_iter_init(&argv, typed_record.payload,
                                  typed_record.payload_length) !=
            SHELL_NETSTRING_OK ||
        shell_netstring_iter_next(&argv, &argv0) != SHELL_NETSTRING_OK ||
        argv0.payload_length != 0 ||
        shell_netstring_iter_next(&argv, &argv0) != SHELL_NETSTRING_DONE)
      return false;
    (*out_count)++;
  }
}

TEST(fixture_contract) {
  CHECK(SHELLCLAVE_COMMAND_CORPUS_COUNT > 0);
  for (size_t i = 0; i < SHELLCLAVE_COMMAND_CORPUS_COUNT; i++) {
    const unsigned char *cursor =
        (const unsigned char *)shellclave_command_corpus_commands[i];
    CHECK(*cursor != '\0');
    for (; *cursor != '\0'; cursor++)
      CHECK(*cursor < 0x80u);
  }
  return true;
}

TEST(canonical_processing_surfaces_agree) {
  for (size_t i = 0; i < SHELLCLAVE_COMMAND_CORPUS_COUNT; i++) {
    const char *input = shellclave_command_corpus_commands[i];
    size_t length = strlen(input);
    shell_limits_t strict = {SHELL_MAX_SUBCOMMANDS, true};
    shell_parse_result_t fast = {0};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t command_netseq = {0};
    shell_netstring_buffer_t type_netseq = {0};
    shell_netstring_buffer_t anomaly_commands = {0};
    shell_netstring_buffer_t anomaly_types = {0};
    shell_dep_graph_t graph = {0};
    size_t netargv_count = 0;
    size_t command_count_out = 0;
    size_t type_count = 0;
    size_t anomaly_count = 0;
    bool features = false;

    bool valid =
        shell_parse_fast(input, length, &strict, &fast) == SHELL_OK &&
        fast.count > 0 &&
        shell_tokenize_commands(input, length, &commands, &command_count) ==
            SHELL_TOKENIZE_OK &&
        command_count >= fast.count &&
        shell_process_commands(input, length, NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count > 0 &&
        shell_build_netargv_sequence_buffer(input, length, NULL, &netargv,
                                            &netargv_count,
                                            &features) == SHELL_PROCESS_OK &&
        netargv_count == processed.command_count &&
        valid_netsequence(&netargv, netargv_count) &&
        shell_build_command_netseq_buffer(input, length, NULL, &command_netseq,
                                          &command_count_out) ==
            SHELL_PROCESS_OK &&
        command_count_out >= processed.command_count &&
        valid_netsequence(&command_netseq, command_count_out) &&
        shell_build_type_netseq_buffer(input, length, NULL, &type_netseq,
                                       &type_count) == SHELL_PROCESS_OK &&
        type_count == command_count_out &&
        valid_netsequence(&type_netseq, type_count) &&
        shell_build_anomaly_netseqs_buffer(
            input, length, NULL, &anomaly_commands, &anomaly_types,
            &anomaly_count) == SHELL_PROCESS_OK &&
        anomaly_count == command_count_out &&
        valid_netsequence(&anomaly_commands, anomaly_count) &&
        valid_netsequence(&anomaly_types, anomaly_count) &&
        shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;

    if (!valid) {
      printf("    fixture %zu failed: %s\n", i, input);
      shell_netstring_buffer_free(&netargv);
      shell_netstring_buffer_free(&command_netseq);
      shell_netstring_buffer_free(&type_netseq);
      shell_netstring_buffer_free(&anomaly_commands);
      shell_netstring_buffer_free(&anomaly_types);
      shell_processed_commands_free(&processed);
      shell_commands_free(commands, command_count);
      return false;
    }
    shell_netstring_iter_t records;
    valid = shell_netstring_iter_init(&records, netargv.data, netargv.length) ==
            SHELL_NETSTRING_OK;
    for (size_t c = 0; valid && c < processed.command_count; c++) {
      shell_netstring_view_t record;
      shell_netstring_buffer_t rendered = {0};
      valid =
          shell_netstring_iter_next(&records, &record) == SHELL_NETSTRING_OK &&
          shell_render_netargv_buffer(&processed.commands[c], NULL,
                                      &rendered) == SHELL_PROCESS_OK &&
          record.payload_length == rendered.length &&
          memcmp(record.payload, rendered.data, rendered.length) == 0;
      shell_netstring_buffer_free(&rendered);
    }
    valid =
        valid && command_netseq.length == anomaly_commands.length &&
        type_netseq.length == anomaly_types.length &&
        memcmp(command_netseq.data, anomaly_commands.data,
               command_netseq.length) == 0 &&
        memcmp(type_netseq.data, anomaly_types.data, type_netseq.length) == 0;
    shell_netstring_buffer_free(&netargv);
    shell_netstring_buffer_free(&command_netseq);
    shell_netstring_buffer_free(&type_netseq);
    shell_netstring_buffer_free(&anomaly_commands);
    shell_netstring_buffer_free(&anomaly_types);
    shell_processed_commands_free(&processed);
    shell_commands_free(commands, command_count);
    CHECK(valid);
  }
  return true;
}

TEST(supported_syntax_model_matrix) {
  /* These are compact representatives for paths that are uncommon in the
   * anonymized corpus. Keep them as parser inputs only; none is executed. */
  static const char *const cases[] = {
      "printf x >out",
      "printf x >>out",
      "cat <in",
      "cat <>read-write",
      "printf x >|forced",
      "printf x 2>err 3>>trace 4>&1 5<&0 6>&-",
      "printf x &>all",
      "printf x &>>all",
      "printf x >&combined",
      "printf x 1>&\"combined name\"",
      "printf x >&\\$literal",
      "printf x >&\"7\"",
      "printf x >&$'7'",
      "printf x >&\"-\"",
      "printf x {trace}>out {input}<in {both}<>read-write",
      "cat <<EOF\nbody\nEOF\n",
      "cat <<-'EOF'\n\tbody\n\tEOF\n",
      "cat <<<\"body\"",
      "printf x > >(cat)",
      "cat < <(printf x)",
      "cat <(printf x)",
      "printf x | cat",
      "printf x |& cat",
      "! printf x |& cat | sort",
      "printf x && cat",
      "printf x || cat",
      "printf x & cat",
      "printf x; cat",
      "{ printf x; } | { cat; }",
      "{ printf x; } |& { cat; }",
      "{ printf x; } >out 2>&1",
      "{ printf x; } &>all",
      "{ printf x; } &>>all",
      "{ printf x; } &> >(cat)",
      "{ printf x; } >&combined",
      "{ printf x; } >&\"7\"",
      "{ printf x; } >&$'7'",
      "{ printf x; } >&\"-\"",
      "{ printf x; } {trace}>out {input}<in {both}<>read-write",
      "{ cat; } <<EOF\nbody\nEOF\n",
      "(printf x) | cat",
      "echo $(printf x)",
      "echo $(<input)",
      "echo `printf x`",
      "echo \"$(( 1 + 2 ))\"",
      "echo ${value:-$(printf x)}",
      "echo $'a\\tb'",
      "echo @(foo|bar)",
      "echo prefix@(foo|bar)suffix",
      "echo !(foo)",
      "echo \\! \"!\" '!'",
      "VAR=value command",
      "export VAR=$(printf x)",
      "exec {out}>out; exec {copy}<&$out; printf x >&$copy",
      "exec {in}<in; exec {copy}>&$in; cat <&$copy",
      "cd /tmp && pwd",
      "cd ./relative; pwd",
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i];
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    bool valid = shell_process_commands(input, strlen(input), NULL,
                                        &processed) == SHELL_PROCESS_OK &&
                 shell_dep_graph_parse(input, strlen(input), "/work/base", NULL,
                                       &graph) == SHELL_DEP_OK &&
                 shell_dep_graph_validate(&graph).valid;
    if (!valid) {
      printf("    syntax case %zu failed: %s\n", i, input);
      shell_processed_commands_free(&processed);
      return false;
    }
    shell_processed_commands_free(&processed);
  }
  return true;
}

/* Run the less common, but fully supported, spellings through every exported
 * representation.  The fixture corpus deliberately favours short everyday
 * commands; this compact matrix makes the shipping and allocator-linked test
 * libraries exercise the same substitution, word-shape, and redirection
 * paths without treating any diagnostic display as shell input. */
TEST(cross_surface_edge_syntax) {
  static const char *const cases[] = {
      "printf /a/${VALUE:-$(producer)}/$1",
      "printf x >&literal{path}",
      "cat < <(producer) |& sed x > >(consumer)",
      "cat < prefix<(producer)",
      "cat > >(consumer)suffix",
      "{ cat; } <> <(producer)suffix",
      "cat < <(producer)<(consumer)",
      "echo $(<prefix<(producer))",
      "cat < prefix<(producer)$(printf path)",
      "printf x 2>&1 3>&- {out}>out {in}<in {both}<>read-write",
      "printf x {out\\\r\nfd}>out {in\\\r\nfd}<in",
      "cat >out\\\r\nsuffix next",
      "$'c'3>out;cat \"x\"${y}z;my\\\r\ncommand value",
      "printf prefix$'literal'${NAME} \"$ONE$TWO\"",
      "cat <<EOF\n$(producer)\nEOF\n",
      "cat <<EOF\nwhile true; do :; done\n$\"locale\"\n\\$(literal)\n"
      "\\${items[0]}\n$(printf value)\n$((1 + 2))\nEOF\n",
      "cat <<'EOF'\n$(while true; do :; done)\n${items[0]}\n"
      "$((items[0]))\n$\"locale\"\nEOF\n",
      "cat <<${items[0]}\nbody\n${items[0]}\n",
      "cat <<EOF <<-'LITERAL'\r\n$(printf value)\r\nEOF\r\n"
      "\t$(while true; do :; done)\r\n\tLITERAL\r\n",
      "printf $'a\\tb' @(left|right)",
      "printf ${VALUE#prefix${SUFFIX:-$(producer)}}",
      "printf ${VALUE##prefix${SUFFIX}} ${VALUE%tail${SUFFIX}}",
      "printf ${VALUE%%tail${SUFFIX}} ${VALUE/pattern/${REPLACEMENT}}",
      "printf ${VALUE:-{left,right}}",
      "printf ${VALUE:-{}",
      "printf ${VALUE#{}",
      "printf ${VALUE/{}",
      "printf ${VALUE:-${FALLBACK:-{}}",
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i];
    size_t length = strlen(input);
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t command_netseq = {0};
    shell_netstring_buffer_t type_netseq = {0};
    shell_netstring_buffer_t anomaly_commands = {0};
    shell_netstring_buffer_t anomaly_types = {0};
    shell_transformed_command_t **transformed = NULL;
    shell_abstract_command_t *abstract = NULL;
    shell_dep_graph_t graph = {0};
    size_t netargv_count = 0;
    size_t command_count = 0;
    size_t type_count = 0;
    size_t anomaly_count = 0;
    size_t transformed_count = 0;
    bool features = false;

    bool valid =
        shell_process_commands(input, length, NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count > 0 &&
        shell_build_netargv_sequence_buffer(input, length, NULL, &netargv,
                                            &netargv_count,
                                            &features) == SHELL_PROCESS_OK &&
        netargv_count == processed.command_count &&
        valid_netsequence(&netargv, netargv_count) &&
        shell_build_command_netseq_buffer(input, length, NULL, &command_netseq,
                                          &command_count) == SHELL_PROCESS_OK &&
        command_count >= processed.command_count &&
        valid_netsequence(&command_netseq, command_count) &&
        shell_build_type_netseq_buffer(input, length, NULL, &type_netseq,
                                       &type_count) == SHELL_PROCESS_OK &&
        type_count == command_count &&
        valid_netsequence(&type_netseq, type_count) &&
        shell_build_anomaly_netseqs_buffer(
            input, length, NULL, &anomaly_commands, &anomaly_types,
            &anomaly_count) == SHELL_PROCESS_OK &&
        anomaly_count == command_count &&
        valid_netsequence(&anomaly_commands, anomaly_count) &&
        valid_netsequence(&anomaly_types, anomaly_count) &&
        shell_transform_command_line(input, length, NULL, &transformed,
                                     &transformed_count) ==
            SHELL_TRANSFORM_OK &&
        transformed_count == processed.command_count &&
        shell_abstract_command_parse(input, length, &abstract) ==
            SHELL_ABSTRACT_OK &&
        abstract != NULL &&
        shell_dep_graph_parse(input, length, "/work/base", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    shell_netstring_buffer_free(&netargv);
    shell_netstring_buffer_free(&command_netseq);
    shell_netstring_buffer_free(&type_netseq);
    shell_netstring_buffer_free(&anomaly_commands);
    shell_netstring_buffer_free(&anomaly_types);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
    shell_processed_commands_free(&processed);
    if (!valid) {
      printf("    cross-surface case %zu failed: %s\n", i, input);
      return false;
    }
  }
  return true;
}

/* Parameter operands are lexical shell words. Check the literal-brace repair
 * at every public representation rather than allowing one layer to accept a
 * command that another layer rejects or reinterprets. */
TEST(parameter_word_literal_braces_cross_surface) {
  static const struct {
    const char *input;
    size_t command_count;
  } cases[] = {
      {"printf ${VALUE:-{}", 1},
      {"printf ${VALUE#{}", 1},
      {"printf ${VALUE/{}", 1},
      {"printf ${VALUE:-${FALLBACK:-{}}", 1},
      {"printf ${VALUE:-{left,right}}", 1},
  };

  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i].input;
    size_t length = strlen(input);
    shell_limits_t strict = {SHELL_MAX_SUBCOMMANDS, true};
    shell_parse_result_t fast = {0};
    shell_command_t *commands = NULL;
    size_t tokenized_count = 0;
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t command_netseq = {0};
    shell_netstring_buffer_t type_netseq = {0};
    shell_netstring_buffer_t anomaly_commands = {0};
    shell_netstring_buffer_t anomaly_types = {0};
    shell_transformed_command_t **transformed = NULL;
    shell_abstract_command_t *abstract = NULL;
    shell_dep_graph_t graph = {0};
    size_t netargv_count = 0;
    size_t command_netseq_count = 0;
    size_t type_netseq_count = 0;
    size_t anomaly_count = 0;
    size_t transformed_count = 0;
    bool features = false;

    bool valid =
        shell_parse_fast(input, length, &strict, &fast) == SHELL_OK &&
        fast.count == cases[i].command_count &&
        shell_tokenize_commands(input, length, &commands, &tokenized_count) ==
            SHELL_TOKENIZE_OK &&
        tokenized_count == cases[i].command_count &&
        shell_process_commands(input, length, NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == cases[i].command_count &&
        shell_build_netargv_sequence_buffer(input, length, NULL, &netargv,
                                            &netargv_count,
                                            &features) == SHELL_PROCESS_OK &&
        netargv_count == cases[i].command_count &&
        valid_netsequence(&netargv, netargv_count) &&
        shell_build_command_netseq_buffer(input, length, NULL, &command_netseq,
                                          &command_netseq_count) ==
            SHELL_PROCESS_OK &&
        command_netseq_count == cases[i].command_count &&
        valid_netsequence(&command_netseq, command_netseq_count) &&
        shell_build_type_netseq_buffer(input, length, NULL, &type_netseq,
                                       &type_netseq_count) ==
            SHELL_PROCESS_OK &&
        type_netseq_count == cases[i].command_count &&
        valid_netsequence(&type_netseq, type_netseq_count) &&
        shell_build_anomaly_netseqs_buffer(
            input, length, NULL, &anomaly_commands, &anomaly_types,
            &anomaly_count) == SHELL_PROCESS_OK &&
        anomaly_count == cases[i].command_count &&
        valid_netsequence(&anomaly_commands, anomaly_count) &&
        valid_netsequence(&anomaly_types, anomaly_count) &&
        shell_transform_command_line(input, length, NULL, &transformed,
                                     &transformed_count) ==
            SHELL_TRANSFORM_OK &&
        transformed_count == cases[i].command_count &&
        shell_abstract_command_parse(input, length, &abstract) ==
            SHELL_ABSTRACT_OK &&
        abstract != NULL &&
        shell_dep_graph_parse(input, length, "/work/base", NULL, &graph) ==
            SHELL_DEP_OK &&
        shell_dep_graph_validate(&graph).valid;
    shell_netstring_buffer_free(&netargv);
    shell_netstring_buffer_free(&command_netseq);
    shell_netstring_buffer_free(&type_netseq);
    shell_netstring_buffer_free(&anomaly_commands);
    shell_netstring_buffer_free(&anomaly_types);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
    shell_processed_commands_free(&processed);
    shell_commands_free(commands, tokenized_count);
    if (!valid) {
      printf("    literal-brace case %zu failed: %s\n", i, input);
      return false;
    }
  }
  return true;
}

/* A bare opening brace in a parameter word is literal. Its following closing
 * brace ends the expansion, so a connector after that boundary remains outer
 * shell syntax rather than becoming an opaque parameter-word byte. */
TEST(parameter_word_literal_brace_boundary) {
  static const char input[] = "printf ${VALUE:-{left}| cat";
  shell_limits_t strict = {SHELL_MAX_SUBCOMMANDS, true};
  shell_parse_result_t fast = {0};
  shell_command_t *commands = NULL;
  size_t command_count = 0;
  shell_processed_commands_t processed = {0};
  shell_dep_graph_t graph = {0};

  bool valid =
      shell_parse_fast(input, sizeof(input) - 1, &strict, &fast) == SHELL_OK &&
      fast.count == 2 && fast.cmds[1].type == SHELL_TYPE_PIPELINE &&
      fast.cmds[1].pipe_input_mode == SHELL_PIPE_MODE_STDOUT &&
      shell_tokenize_commands(input, sizeof(input) - 1, &commands,
                              &command_count) == SHELL_TOKENIZE_OK &&
      command_count == 2 &&
      shell_process_commands(input, sizeof(input) - 1, NULL, &processed) ==
          SHELL_PROCESS_OK &&
      processed.command_count == 2 && processed.commands[0].has_pipe_output &&
      processed.commands[1].has_pipe_input &&
      shell_dep_graph_parse(input, sizeof(input) - 1, ".", NULL, &graph) ==
          SHELL_DEP_OK &&
      shell_dep_graph_validate(&graph).valid;
  uint32_t pipes = 0;
  for (uint32_t edge = 0; valid && edge < graph.edge_count; edge++)
    pipes += graph.edges[edge].type == SHELL_EDGE_PIPE;
  shell_commands_free(commands, command_count);
  shell_processed_commands_free(&processed);
  CHECK(valid && pipes == 1);
  return true;
}

/* Exercise public rejection and aggregate-size paths through both the
 * allocator-instrumented and shipping Shellsplit libraries. The successful
 * corpus matrices above cannot reach these cleanup paths. */
TEST(public_failure_and_limit_contracts) {
  shell_transformed_command_t **transformed =
      (shell_transformed_command_t **)(uintptr_t)1;
  size_t transformed_count = SIZE_MAX;
  bool valid = shell_transform_command_line(NULL, 0, NULL, &transformed,
                                            &transformed_count) ==
                   SHELL_TRANSFORM_EINPUT &&
               transformed == NULL && transformed_count == 0;

  transformed = (shell_transformed_command_t **)(uintptr_t)1;
  transformed_count = SIZE_MAX;
  valid = valid &&
          shell_transform_command_line(
              "while true; do :; done", strlen("while true; do :; done"), NULL,
              &transformed, &transformed_count) == SHELL_TRANSFORM_EPARSE &&
          transformed == NULL && transformed_count == 0;

  shell_transform_limits_t transform_limits = {
      .max_string_bytes = SIZE_MAX,
      .max_total_bytes = 7,
  };
  transformed = (shell_transformed_command_t **)(uintptr_t)1;
  transformed_count = SIZE_MAX;
  valid = valid &&
          shell_transform_command_line("x;y", 3, &transform_limits,
                                       &transformed, &transformed_count) ==
              SHELL_TRANSFORM_EOUTPUT_LIMIT &&
          transformed == NULL && transformed_count == 0;

  shell_processed_commands_t processed = {
      .commands = (shell_command_info_t *)(uintptr_t)1,
      .command_count = SIZE_MAX,
  };
  valid = valid &&
          shell_process_commands("while true; do :; done",
                                 strlen("while true; do :; done"), NULL,
                                 &processed) == SHELL_PROCESS_EPARSE &&
          processed.commands == NULL && processed.command_count == 0;

  shell_netstring_buffer_t netargv = {0};
  size_t subcommand_count = SIZE_MAX;
  bool features = true;
  shell_process_limits_t process_limits = {
      .max_string_bytes = 1,
      .max_total_bytes = SIZE_MAX,
  };
  valid = valid &&
          shell_build_netargv_sequence_buffer(
              "echo x", strlen("echo x"), &process_limits, &netargv,
              &subcommand_count, &features) == SHELL_PROCESS_EOUTPUT_LIMIT &&
          netargv.data == NULL && netargv.length == 0 &&
          subcommand_count == 0 && !features;
  shell_netstring_buffer_free(&netargv);
  shell_processed_commands_free(&processed);
  shell_transformed_command_list_free(transformed, transformed_count);
  return valid;
}

/* Exercise the public source-validation and decoded-word contracts directly.
 * The corpus only reaches successful command text, whereas canonical callers
 * also rely on these APIs to reject unsupported bytes and leave every owned
 * output clear on limit failures. */
TEST(source_and_word_boundary_contracts) {
  static const char unsupported_byte[] = {'e', 'c', 'h', 'o', '\x01'};
  static const char crlf_continuation[] = "left\\\r\nright";
  static const char expected_word[] = "leftright";
  static const char *const unsupported = "while true; do :; done";

  shell_processed_commands_t processed = {
      .commands = (shell_command_info_t *)(uintptr_t)1,
      .command_count = SIZE_MAX,
  };
  CHECK(shell_process_commands(NULL, 0, NULL, &processed) ==
        SHELL_PROCESS_EINPUT);
  CHECK(processed.commands == NULL && processed.command_count == 0);
  processed.commands = (shell_command_info_t *)(uintptr_t)1;
  processed.command_count = SIZE_MAX;
  CHECK(shell_process_commands(unsupported_byte, sizeof(unsupported_byte), NULL,
                               &processed) == SHELL_PROCESS_EINPUT);
  CHECK(processed.commands == NULL && processed.command_count == 0);
  processed.commands = (shell_command_info_t *)(uintptr_t)1;
  processed.command_count = SIZE_MAX;
  CHECK(shell_process_commands(unsupported, strlen(unsupported), NULL,
                               &processed) == SHELL_PROCESS_EPARSE);
  CHECK(processed.commands == NULL && processed.command_count == 0);
  CHECK(shell_process_commands("printf x", 8, NULL, &processed) ==
        SHELL_PROCESS_OK);
  CHECK(processed.command_count == 1);
  shell_processed_commands_free(&processed);

  shell_process_limits_t limits = {
      .max_string_bytes = 1,
      .max_total_bytes = SIZE_MAX,
  };
  CHECK(shell_process_commands("printf x", 8, &limits, &processed) ==
        SHELL_PROCESS_EOUTPUT_LIMIT);
  CHECK(processed.commands == NULL && processed.command_count == 0);

  limits.max_string_bytes = SIZE_MAX;
  limits.max_total_bytes = 8;
  CHECK(shell_process_commands("echo x; echo y", 14, &limits, &processed) ==
        SHELL_PROCESS_EOUTPUT_LIMIT);
  CHECK(processed.commands == NULL && processed.command_count == 0);

  limits.max_total_bytes = SIZE_MAX;
  limits.max_group_io_ops = 1;
  CHECK(shell_process_commands("{ cat; } >one >two", 18, &limits, &processed) ==
        SHELL_PROCESS_EOUTPUT_LIMIT);
  CHECK(processed.commands == NULL && processed.command_count == 0);

  size_t measured = 0;
  char decoded[sizeof(expected_word)];
  size_t written = SIZE_MAX;
  CHECK(shell_measure_decoded_word(crlf_continuation,
                                   sizeof(crlf_continuation) - 1,
                                   &measured) == SHELL_PROCESS_OK);
  CHECK(measured == sizeof(expected_word) - 1);
  CHECK(shell_write_decoded_word(
            crlf_continuation, sizeof(crlf_continuation) - 1, decoded,
            measured - 1, &written) == SHELL_PROCESS_EOUTPUT_LIMIT);
  CHECK(written == 0);
  CHECK(shell_write_decoded_word(
            crlf_continuation, sizeof(crlf_continuation) - 1, decoded,
            sizeof(decoded), &written) == SHELL_PROCESS_OK);
  CHECK(written == measured && memcmp(decoded, expected_word, written) == 0);
  CHECK(shell_visit_decoded_word(NULL, 0, NULL, NULL, &measured) ==
        SHELL_PROCESS_EINPUT);
  CHECK(shell_write_decoded_word("x", 1, NULL, 0, &written) ==
        SHELL_PROCESS_EINPUT);
  return true;
}

/* Success-only corpus checks are insufficient for list connectors: every
 * surface could accept the same source while agreeing on a wrong sequencing
 * relation. Keep the semantic expectations explicit here. */
TEST(continued_list_topology) {
  static const struct {
    const char *input;
    uint16_t type;
    shell_pipe_mode_t pipe_mode;
    shell_dep_edge_type_t relation;
    uint32_t relation_count;
  } cases[] = {
      {"printf x | # note\ncat", SHELL_TYPE_PIPELINE, SHELL_PIPE_MODE_STDOUT,
       SHELL_EDGE_PIPE, 1},
      {"printf x |& \\\r\ncat", SHELL_TYPE_PIPELINE,
       SHELL_PIPE_MODE_STDOUT_AND_STDERR, SHELL_EDGE_PIPE, 2},
      {"printf x |\\\n& cat", SHELL_TYPE_PIPELINE,
       SHELL_PIPE_MODE_STDOUT_AND_STDERR, SHELL_EDGE_PIPE, 2},
      {"printf x |\\\r& cat", SHELL_TYPE_PIPELINE,
       SHELL_PIPE_MODE_STDOUT_AND_STDERR, SHELL_EDGE_PIPE, 2},
      {"printf x |\\\r\n& cat", SHELL_TYPE_PIPELINE,
       SHELL_PIPE_MODE_STDOUT_AND_STDERR, SHELL_EDGE_PIPE, 2},
      {"echo prefix{left|right}suffix", SHELL_TYPE_PIPELINE,
       SHELL_PIPE_MODE_STDOUT, SHELL_EDGE_PIPE, 1},
      {"echo [left|right]", SHELL_TYPE_PIPELINE, SHELL_PIPE_MODE_STDOUT,
       SHELL_EDGE_PIPE, 1},
      {"printf x &&\ncat", SHELL_TYPE_AND, SHELL_PIPE_MODE_NONE, SHELL_EDGE_AND,
       1},
      {"printf x &\\\n& cat", SHELL_TYPE_AND, SHELL_PIPE_MODE_NONE,
       SHELL_EDGE_AND, 1},
      {"printf x || # note\ncat", SHELL_TYPE_OR, SHELL_PIPE_MODE_NONE,
       SHELL_EDGE_OR, 1},
      {"printf x |\\\r\n| cat", SHELL_TYPE_OR, SHELL_PIPE_MODE_NONE,
       SHELL_EDGE_OR, 1},
      {"printf x\ncat", SHELL_TYPE_SEMICOLON, SHELL_PIPE_MODE_NONE,
       SHELL_EDGE_SEQ, 1},
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i].input;
    size_t length = strlen(input);
    shell_limits_t strict = {SHELL_MAX_SUBCOMMANDS, true};
    shell_parse_result_t fast = {0};
    shell_processed_commands_t processed = {0};
    shell_dep_graph_t graph = {0};
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t command_netseq = {0};
    shell_netstring_buffer_t type_netseq = {0};
    shell_netstring_buffer_t anomaly_commands = {0};
    shell_netstring_buffer_t anomaly_types = {0};
    size_t netargv_count = 0;
    size_t command_count = 0;
    size_t type_count = 0;
    size_t anomaly_count = 0;
    bool features = false;
    bool valid = shell_parse_fast(input, length, &strict, &fast) == SHELL_OK &&
                 fast.count == 2 && fast.cmds[1].type == cases[i].type &&
                 fast.cmds[1].pipe_input_mode == cases[i].pipe_mode &&
                 shell_process_commands(input, length, NULL, &processed) ==
                     SHELL_PROCESS_OK &&
                 processed.command_count == 2;
    if (valid && cases[i].type == SHELL_TYPE_PIPELINE)
      valid = processed.commands[0].has_pipe_output &&
              processed.commands[0].pipe_output_mode == cases[i].pipe_mode &&
              processed.commands[1].has_pipe_input;
    else if (valid)
      valid = !processed.commands[0].has_pipe_output &&
              !processed.commands[1].has_pipe_input;
    if (valid)
      valid = shell_build_netargv_sequence_buffer(input, length, NULL, &netargv,
                                                  &netargv_count, &features) ==
                  SHELL_PROCESS_OK &&
              netargv_count == 2 && valid_netsequence(&netargv, netargv_count);
    if (valid)
      valid = shell_build_command_netseq_buffer(
                  input, length, NULL, &command_netseq, &command_count) ==
                  SHELL_PROCESS_OK &&
              command_count == 2 &&
              valid_netsequence(&command_netseq, command_count);
    if (valid)
      valid = shell_build_type_netseq_buffer(input, length, NULL, &type_netseq,
                                             &type_count) == SHELL_PROCESS_OK &&
              type_count == 2 && valid_netsequence(&type_netseq, type_count);
    if (valid)
      valid = shell_build_anomaly_netseqs_buffer(
                  input, length, NULL, &anomaly_commands, &anomaly_types,
                  &anomaly_count) == SHELL_PROCESS_OK &&
              anomaly_count == 2 &&
              valid_netsequence(&anomaly_commands, anomaly_count) &&
              valid_netsequence(&anomaly_types, anomaly_count);
    if (valid)
      valid = shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
              SHELL_DEP_OK;
    uint32_t relations = 0;
    if (valid) {
      for (uint32_t edge = 0; edge < graph.edge_count; edge++)
        relations += graph.edges[edge].type == cases[i].relation;
      valid = relations == cases[i].relation_count &&
              shell_dep_graph_validate(&graph).valid;
    }
    shell_netstring_buffer_free(&netargv);
    shell_netstring_buffer_free(&command_netseq);
    shell_netstring_buffer_free(&type_netseq);
    shell_netstring_buffer_free(&anomaly_commands);
    shell_netstring_buffer_free(&anomaly_types);
    shell_processed_commands_free(&processed);
    if (!valid) {
      printf("    continuation case %zu failed: %s\n", i, input);
      return false;
    }
  }
  return true;
}

static bool has_raw_operator_token(const char *input,
                                   shell_token_type_t expected_type,
                                   size_t expected_length) {
  shell_tokenizer_state_t state;
  shell_token_t token;
  if (!shell_tokenizer_init(&state, input, strlen(input)))
    return false;
  while (shell_tokenizer_next(&state, &token))
    if (token.type == expected_type && token.length == expected_length &&
        memchr(token.start, '\\', token.length) != NULL)
      return true;
  return false;
}

static bool has_operator_token(const char *input,
                               shell_token_type_t expected_type) {
  shell_tokenizer_state_t state;
  shell_token_t token;
  if (!shell_tokenizer_init(&state, input, strlen(input)))
    return false;
  while (shell_tokenizer_next(&state, &token))
    if (token.type == expected_type)
      return true;
  return false;
}

static uint32_t graph_edge_type_count(const shell_dep_graph_t *graph,
                                      shell_dep_edge_type_t type) {
  uint32_t count = 0;
  for (uint32_t edge = 0; graph && edge < graph->edge_count; edge++)
    count += graph->edges[edge].type == type;
  return count;
}

/* Shell source remains zero-copy, so a continued operator must retain its
 * physical span while every canonical result agrees with the compact spelling.
 * Exercise each redirect family that has more than one punctuation byte; this
 * is exactly where a raw adjacent-byte test can silently alter shell grammar.
 */
TEST(continued_punctuation_is_lossless_and_canonical) {
  static const struct {
    const char *compact;
    const char *continued;
    shell_token_type_t operator_type;
    size_t raw_operator_length;
  } cases[] = {
      {"printf x &>out", "printf x &\\\n>out", SHELL_TOKEN_REDIRECT_BOTH, 4},
      {"printf x &>>out", "printf x &\\\r\n>\\\r\n>out",
       SHELL_TOKEN_REDIRECT_BOTH_APPEND, 9},
      {"printf x >&1", "printf x >\\\n&1", SHELL_TOKEN_REDIRECT_ERR, 5},
      {"cat <>state", "cat <\\\r>state", SHELL_TOKEN_REDIRECT_READ_WRITE, 4},
      {"printf x >|out", "printf x >\\\r\n|out", SHELL_TOKEN_REDIRECT_CLOBBER,
       5},
      {"cat <<<word", "cat <\\\n<\\\n<word", SHELL_TOKEN_HERESTRING, 7},
      {"cat <<EOF\nbody\nEOF\n", "cat <\\\n<EOF\nbody\nEOF\n",
       SHELL_TOKEN_HEREDOC, 7},
  };

  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *compact = cases[i].compact;
    const char *continued = cases[i].continued;
    size_t compact_length = strlen(compact);
    size_t continued_length = strlen(continued);
    shell_limits_t strict = {SHELL_MAX_SUBCOMMANDS, true};
    shell_parse_result_t compact_fast = {0};
    shell_parse_result_t continued_fast = {0};
    shell_command_t *compact_tokens = NULL;
    shell_command_t *continued_tokens = NULL;
    size_t compact_token_count = 0;
    size_t continued_token_count = 0;
    shell_processed_commands_t compact_processed = {0};
    shell_processed_commands_t continued_processed = {0};
    shell_netstring_buffer_t compact_argv = {0};
    shell_netstring_buffer_t continued_argv = {0};
    shell_netstring_buffer_t compact_commands = {0};
    shell_netstring_buffer_t continued_commands = {0};
    shell_netstring_buffer_t compact_types = {0};
    shell_netstring_buffer_t continued_types = {0};
    shell_netstring_buffer_t compact_anomaly_commands = {0};
    shell_netstring_buffer_t continued_anomaly_commands = {0};
    shell_netstring_buffer_t compact_anomaly_types = {0};
    shell_netstring_buffer_t continued_anomaly_types = {0};
    shell_dep_graph_t compact_graph = {0};
    shell_dep_graph_t continued_graph = {0};
    size_t compact_argv_count = 0;
    size_t continued_argv_count = 0;
    size_t compact_command_count = 0;
    size_t continued_command_count = 0;
    size_t compact_type_count = 0;
    size_t continued_type_count = 0;
    size_t compact_anomaly_count = 0;
    size_t continued_anomaly_count = 0;
    bool compact_features = false;
    bool continued_features = false;

    bool valid =
        shell_parse_fast(compact, compact_length, &strict, &compact_fast) ==
            SHELL_OK &&
        shell_parse_fast(continued, continued_length, &strict,
                         &continued_fast) == SHELL_OK &&
        compact_fast.count == continued_fast.count &&
        shell_tokenize_commands(compact, compact_length, &compact_tokens,
                                &compact_token_count) == SHELL_TOKENIZE_OK &&
        shell_tokenize_commands(continued, continued_length, &continued_tokens,
                                &continued_token_count) == SHELL_TOKENIZE_OK &&
        compact_token_count == continued_token_count &&
        has_raw_operator_token(continued, cases[i].operator_type,
                               cases[i].raw_operator_length) &&
        shell_process_commands(compact, compact_length, NULL,
                               &compact_processed) == SHELL_PROCESS_OK &&
        shell_process_commands(continued, continued_length, NULL,
                               &continued_processed) == SHELL_PROCESS_OK &&
        compact_processed.command_count == continued_processed.command_count &&
        shell_build_netargv_sequence_buffer(
            compact, compact_length, NULL, &compact_argv, &compact_argv_count,
            &compact_features) == SHELL_PROCESS_OK &&
        shell_build_netargv_sequence_buffer(
            continued, continued_length, NULL, &continued_argv,
            &continued_argv_count, &continued_features) == SHELL_PROCESS_OK &&
        compact_argv_count == continued_argv_count &&
        compact_argv.length == continued_argv.length &&
        memcmp(compact_argv.data, continued_argv.data, compact_argv.length) ==
            0 &&
        compact_features == continued_features &&
        shell_build_command_netseq_buffer(
            compact, compact_length, NULL, &compact_commands,
            &compact_command_count) == SHELL_PROCESS_OK &&
        shell_build_command_netseq_buffer(
            continued, continued_length, NULL, &continued_commands,
            &continued_command_count) == SHELL_PROCESS_OK &&
        compact_command_count == continued_command_count &&
        compact_commands.length == continued_commands.length &&
        memcmp(compact_commands.data, continued_commands.data,
               compact_commands.length) == 0 &&
        shell_build_type_netseq_buffer(compact, compact_length, NULL,
                                       &compact_types, &compact_type_count) ==
            SHELL_PROCESS_OK &&
        shell_build_type_netseq_buffer(
            continued, continued_length, NULL, &continued_types,
            &continued_type_count) == SHELL_PROCESS_OK &&
        compact_type_count == continued_type_count &&
        compact_types.length == continued_types.length &&
        memcmp(compact_types.data, continued_types.data,
               compact_types.length) == 0 &&
        shell_build_anomaly_netseqs_buffer(
            compact, compact_length, NULL, &compact_anomaly_commands,
            &compact_anomaly_types,
            &compact_anomaly_count) == SHELL_PROCESS_OK &&
        shell_build_anomaly_netseqs_buffer(
            continued, continued_length, NULL, &continued_anomaly_commands,
            &continued_anomaly_types,
            &continued_anomaly_count) == SHELL_PROCESS_OK &&
        compact_anomaly_count == continued_anomaly_count &&
        compact_anomaly_commands.length == continued_anomaly_commands.length &&
        compact_anomaly_types.length == continued_anomaly_types.length &&
        memcmp(compact_anomaly_commands.data, continued_anomaly_commands.data,
               compact_anomaly_commands.length) == 0 &&
        memcmp(compact_anomaly_types.data, continued_anomaly_types.data,
               compact_anomaly_types.length) == 0 &&
        shell_dep_graph_parse(compact, compact_length, ".", NULL,
                              &compact_graph) == SHELL_DEP_OK &&
        shell_dep_graph_parse(continued, continued_length, ".", NULL,
                              &continued_graph) == SHELL_DEP_OK &&
        compact_graph.node_count == continued_graph.node_count &&
        compact_graph.edge_count == continued_graph.edge_count &&
        graph_edge_type_count(&compact_graph, SHELL_EDGE_READ) ==
            graph_edge_type_count(&continued_graph, SHELL_EDGE_READ) &&
        graph_edge_type_count(&compact_graph, SHELL_EDGE_WRITE) ==
            graph_edge_type_count(&continued_graph, SHELL_EDGE_WRITE) &&
        graph_edge_type_count(&compact_graph, SHELL_EDGE_APPEND) ==
            graph_edge_type_count(&continued_graph, SHELL_EDGE_APPEND) &&
        graph_edge_type_count(&compact_graph, SHELL_EDGE_FD_OPEN) ==
            graph_edge_type_count(&continued_graph, SHELL_EDGE_FD_OPEN) &&
        graph_edge_type_count(&compact_graph, SHELL_EDGE_FD_CLOSE) ==
            graph_edge_type_count(&continued_graph, SHELL_EDGE_FD_CLOSE) &&
        shell_dep_graph_validate(&compact_graph).valid &&
        shell_dep_graph_validate(&continued_graph).valid;

    shell_netstring_buffer_free(&compact_argv);
    shell_netstring_buffer_free(&continued_argv);
    shell_netstring_buffer_free(&compact_commands);
    shell_netstring_buffer_free(&continued_commands);
    shell_netstring_buffer_free(&compact_types);
    shell_netstring_buffer_free(&continued_types);
    shell_netstring_buffer_free(&compact_anomaly_commands);
    shell_netstring_buffer_free(&continued_anomaly_commands);
    shell_netstring_buffer_free(&compact_anomaly_types);
    shell_netstring_buffer_free(&continued_anomaly_types);
    shell_processed_commands_free(&compact_processed);
    shell_processed_commands_free(&continued_processed);
    shell_commands_free(compact_tokens, compact_token_count);
    shell_commands_free(continued_tokens, continued_token_count);
    if (!valid) {
      printf("    continued punctuation case %zu failed\n", i);
      return false;
    }
  }
  return true;
}

/* The splice rule is lexical, not a general source normalizer. In particular
 * it must not see punctuation inside a quoted word as an operator, and
 * physical whitespace still prevents two punctuation bytes from forming a
 * multi-byte operator. */
TEST(continued_punctuation_respects_lexical_boundaries) {
  static const struct {
    const char *input;
    shell_token_type_t forbidden;
  } cases[] = {
      {"printf '%s' '|\\\n&'", SHELL_TOKEN_PIPE_BOTH},
      {"printf '%s' '&\\\n>'", SHELL_TOKEN_REDIRECT_BOTH},
      {"printf x | \\\n& cat", SHELL_TOKEN_PIPE_BOTH},
      {"printf x & \\\n>out", SHELL_TOKEN_REDIRECT_BOTH},
  };

  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    shell_tokenizer_state_t state;
    shell_token_t token;
    CHECK(shell_tokenizer_init(&state, cases[i].input, strlen(cases[i].input)));
    while (shell_tokenizer_next(&state, &token))
      CHECK(token.type != cases[i].forbidden);
    CHECK(!has_operator_token(cases[i].input, cases[i].forbidden));
  }
  return true;
}

/* Redirect-only shell operations are meaningful graph nodes even though they
 * have no executable argv. Keep that distinction visible at every public
 * boundary: executable argv output rejects any composition containing such a
 * stage, while the anomaly sequences preserve it with their empty argv[0]
 * sentinel and the graph retains its I/O operation. */
TEST(redirect_only_stages_remain_graph_visible) {
  static const struct {
    const char *input;
    size_t processed_count;
    size_t anomaly_stage_count;
    uint32_t minimum_reads;
    uint32_t minimum_writes;
  } cases[] = {
      {">output", 0, 1, 0, 1},
      {"<input >output", 0, 1, 1, 1},
      {"printf x; >output", 1, 2, 0, 1},
      {"{ cat; } >out; >a; >b", 1, 3, 0, 3},
      {"{ cat; } >out\n>a", 1, 2, 0, 2},
      {"{ cat; }\n>a", 1, 2, 0, 1},
      {"{ cat; }; >a", 1, 2, 0, 1},
      {"{ cat; } # comment\n>a", 1, 2, 0, 1},
      {"{ cat; } >out && >a", 1, 2, 0, 2},
      {"{ cat; } >out || >a", 1, 2, 0, 2},
      {"{ cat; } >out & >a", 1, 2, 0, 2},
      {"{ cat; } >out | >a", 1, 2, 0, 2},
      {"{ cat; } >out |& >a", 1, 2, 0, 2},
      {"{ { cat; } >out; >a; }", 1, 2, 0, 2},
      {"echo 3\n>out", 1, 2, 0, 1},
      {"{ cat; } <<EOF\nbody\nEOF\n>out", 1, 2, 1, 1},
      {"{ cat; } 0<<EOF\nbody\nEOF\n>out", 1, 2, 1, 1},
      {"{ cat; } 1\\\n2<<EOF\nbody\nEOF\n>out", 1, 2, 1, 1},
      {"{ cat; } <<-'EOF'\n\tbody\n\tEOF\n# separate stage\n>out", 1, 2, 1, 1},
  };

  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i].input;
    size_t length = strlen(input);
    shell_limits_t strict = {SHELL_MAX_SUBCOMMANDS, true};
    shell_parse_result_t fast = {0};
    shell_command_t *commands = NULL;
    size_t command_count = 0;
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t anomaly_commands = {0};
    shell_netstring_buffer_t anomaly_types = {0};
    shell_dep_graph_t graph = {0};
    size_t netargv_count = SIZE_MAX;
    bool features = true;
    uint32_t empty_commands = 0;
    uint32_t reads = 0;
    uint32_t writes = 0;
    size_t empty_anomaly_stages = SIZE_MAX;

    bool valid = shell_parse_fast(input, length, &strict, &fast) == SHELL_OK &&
                 fast.count > 0 &&
                 shell_tokenize_commands(input, length, &commands,
                                         &command_count) == SHELL_TOKENIZE_OK &&
                 command_count > 0 &&
                 shell_process_commands(input, length, NULL, &processed) ==
                     SHELL_PROCESS_OK &&
                 processed.command_count == cases[i].processed_count &&
                 (processed.command_count == 0 ? processed.commands == NULL
                                               : processed.commands != NULL) &&
                 shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
                     SHELL_DEP_OK &&
                 shell_dep_graph_validate(&graph).valid;
    shell_process_status_t netargv_status = shell_build_netargv_sequence_buffer(
        input, length, NULL, &netargv, &netargv_count, &features);
    size_t anomaly_count = SIZE_MAX;
    valid = valid && netargv_status == SHELL_PROCESS_EPARSE &&
            netargv.data == NULL && netargv.length == 0 && netargv_count == 0 &&
            !features &&
            shell_build_anomaly_netseqs_buffer(
                input, length, NULL, &anomaly_commands, &anomaly_types,
                &anomaly_count) == SHELL_PROCESS_OK &&
            anomaly_count == cases[i].anomaly_stage_count &&
            valid_netsequence(&anomaly_commands, anomaly_count) &&
            valid_netsequence(&anomaly_types, anomaly_count) &&
            anomaly_empty_stage_count(&anomaly_commands, &anomaly_types,
                                      &empty_anomaly_stages);
    for (uint32_t node = 0; valid && node < graph.node_count; node++)
      empty_commands += graph.nodes[node].type == SHELL_NODE_CMD &&
                        graph.nodes[node].cmd.token_count == 0;
    for (uint32_t edge = 0; valid && edge < graph.edge_count; edge++) {
      reads += graph.edges[edge].type == SHELL_EDGE_READ;
      writes += graph.edges[edge].type == SHELL_EDGE_WRITE;
    }
    valid = valid &&
            empty_commands ==
                cases[i].anomaly_stage_count - cases[i].processed_count &&
            empty_anomaly_stages ==
                cases[i].anomaly_stage_count - cases[i].processed_count &&
            reads >= cases[i].minimum_reads &&
            writes >= cases[i].minimum_writes;
    shell_netstring_buffer_free(&netargv);
    shell_netstring_buffer_free(&anomaly_commands);
    shell_netstring_buffer_free(&anomaly_types);
    shell_processed_commands_free(&processed);
    shell_commands_free(commands, command_count);
    if (!valid) {
      printf("    redirect-only case %zu failed: %s\n", i, input);
      return false;
    }
  }
  return true;
}

/* A syntax rejection must agree at every canonical boundary. In particular,
 * a malformed modern operator cannot be retained by the processor or graph
 * after the fast parser rejects it. */
TEST(malformed_syntax_is_rejected_atomically) {
  static const char *const cases[] = {
      "printf x |&",
      "printf x |& | cat",
      "printf x | # note",
      "printf x |& \\\n",
      "printf x && # note",
      "printf x ||\r\n",
      "! # note\nprintf x",
      "! \nprintf x",
      "! !",
      "echo then { x; }",
      "echo one; }",
      "echo one | )",
      "echo one { literal; }",
      "echo one (cat)",
      "echo one ((1))",
      "printf x > (consumer)",
      "printf x && && cat",
      "printf $'unterminated",
      "printf $(unterminated",
      "cat < prefix<(unterminated",
      "cat >",
      "cat >;echo hi",
      "cat 0<<<",
      "cat 0<<<&1 echo hi",
      "cat 0<<",
      "cat 3<<-",
      "cat 0<<EOF\nunterminated\n",
      "{ cat; } 0<<<",
      "{ cat; } 0<<<;echo hi",
      "{ cat; } >;echo hi",
      "printf ${VALUE${SUFFIX}}",
      "printf ${VALUE$SUFFIX}",
      "printf ${VALUE.suffix}",
      "printf ${?suffix}",
      "printf ${10suffix}",
      "while true; do :; done",
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i];
    shell_processed_commands_t processed = {
        .commands = (shell_command_info_t *)(uintptr_t)1,
        .command_count = SIZE_MAX,
    };
    shell_netstring_buffer_t netargv = {0};
    shell_dep_graph_t graph = {0};
    shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    shell_parse_result_t fast = {0};
    shell_error_t fast_status =
        shell_parse_fast(input, strlen(input), &strict, &fast);
    CHECK(strcmp(input, "while true; do :; done") == 0
              ? fast_status == SHELL_OK
              : fast_status == SHELL_EPARSE);
    CHECK(shell_process_commands(input, strlen(input), NULL, &processed) ==
          SHELL_PROCESS_EPARSE);
    CHECK(processed.commands == NULL && processed.command_count == 0);
    size_t subcommands = SIZE_MAX;
    bool features = true;
    CHECK(shell_build_netargv_sequence_buffer(
              input, strlen(input), NULL, &netargv, &subcommands, &features) ==
          SHELL_PROCESS_EPARSE);
    CHECK(netargv.data == NULL && netargv.length == 0 && subcommands == 0 &&
          !features);
    CHECK(shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph) ==
          SHELL_DEP_EPARSE);
    CHECK(graph.node_count == 0 && graph.edge_count == 0 &&
          graph.cwd_buf.len == 0 &&
          (graph.status & SHELL_DEP_STATUS_ERROR) != 0);
  }
  return true;
}

/* These sources are valid shell syntax and must remain lexically available for
 * diagnostics. The semantic adapters deliberately reject them together: they
 * must never flatten definition, control, or array semantics into executable
 * argv records. This test runs against both Shellsplit library variants. */
TEST(unsupported_semantics_are_rejected_atomically) {
  static const char *const cases[] = {
      "worker () { :; }",
      "worker ( ) { :; }",
      "worker\t(\t) ( : )",
      "worker\\\n() { :; }",
      "function worker () { :; }",
      "function worker ( ) ( : )",
      "select item in one; do :; done",
      "coproc worker { :; }",
      "items=(one two)",
      "declare -a items",
      "declare arr[0]",
      "declare 'arr[0]'",
      "declare arr\\[0\\]",
      "declare arr$'[0]'",
      "typeset map[key]",
      "command -- declare \"arr[$(printf 0)]\"",
      "printf '%s' \"${items[0]}\"",
      "echo \"${value:-$\"localized\"}\"",
      "echo \"${outer:-${inner:-$\"localized\"}}\"",
      "cat <<EOF\n$(while true; do :; done)\nEOF\n",
      "cat <<EOF\n`select item in one; do :; done`\nEOF\n",
      "cat <<EOF\n${items[0]}\nEOF\n",
      "cat <<EOF\n$((items[0]))\nEOF\n",
      "cat <<EOF\n\"${items[0]}\"\nEOF\n",
      "echo $(cat <<EOF\n$(while true; do :; done)\nEOF\n)",
      "case value in x) : ;& esac",
      "case value in x) : ;;& esac",
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i];
    size_t length = strlen(input);
    shell_limits_t strict = {.max_subcommands = SHELL_MAX_SUBCOMMANDS,
                             .strict_mode = true};
    shell_parse_result_t fast = {0};
    shell_command_t *lexical = NULL;
    size_t lexical_count = 0;
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t command_netseq = {0};
    shell_netstring_buffer_t type_netseq = {0};
    shell_netstring_buffer_t anomaly_commands = {0};
    shell_netstring_buffer_t anomaly_types = {0};
    shell_transformed_command_t **transformed = NULL;
    shell_abstract_command_t *abstract = NULL;
    shell_dep_graph_t graph = {0};
    size_t count = SIZE_MAX;
    size_t transformed_count = SIZE_MAX;
    bool features = true;

    /* The fast parser intentionally remains a bounded structural scanner:
     * accepted lexical extensions may report either its retained range or an
     * unsupported grammar result. The complete tokenizer is the contract that
     * must preserve these valid spellings for later semantic rejection. */
    shell_error_t fast_status = shell_parse_fast(input, length, &strict, &fast);
    CHECK(fast_status == SHELL_OK || fast_status == SHELL_EPARSE);
    shell_tokenize_status_t lexical_status =
        shell_tokenize_commands(input, length, &lexical, &lexical_count);
    if (lexical_status != SHELL_TOKENIZE_OK) {
      printf("    lexical unsupported case %zu: status=%d for %s\n", i,
             (int)lexical_status, input);
      return false;
    }
    CHECK(lexical != NULL && lexical_count != 0);
    shell_commands_free(lexical, lexical_count);

    CHECK(shell_process_commands(input, length, NULL, &processed) ==
          SHELL_PROCESS_EPARSE);
    CHECK(processed.commands == NULL && processed.command_count == 0 &&
          processed.groups == NULL && processed.group_count == 0 &&
          processed.group_io_ops == NULL && processed.group_io_op_count == 0);
    CHECK(shell_build_netargv_sequence_buffer(input, length, NULL, &netargv,
                                              &count, &features) ==
          SHELL_PROCESS_EPARSE);
    CHECK(netargv.data == NULL && netargv.length == 0 && count == 0 &&
          !features);
    count = SIZE_MAX;
    CHECK(shell_build_command_netseq_buffer(input, length, NULL,
                                            &command_netseq,
                                            &count) == SHELL_PROCESS_EPARSE);
    CHECK(command_netseq.data == NULL && command_netseq.length == 0 &&
          count == 0);
    count = SIZE_MAX;
    CHECK(shell_build_type_netseq_buffer(input, length, NULL, &type_netseq,
                                         &count) == SHELL_PROCESS_EPARSE);
    CHECK(type_netseq.data == NULL && type_netseq.length == 0 && count == 0);
    count = SIZE_MAX;
    CHECK(shell_build_anomaly_netseqs_buffer(input, length, NULL,
                                             &anomaly_commands, &anomaly_types,
                                             &count) == SHELL_PROCESS_EPARSE);
    CHECK(anomaly_commands.data == NULL && anomaly_commands.length == 0 &&
          anomaly_types.data == NULL && anomaly_types.length == 0 &&
          count == 0);
    CHECK(shell_transform_command_line(input, length, NULL, &transformed,
                                       &transformed_count) ==
          SHELL_TRANSFORM_EPARSE);
    CHECK(transformed == NULL && transformed_count == 0);
    CHECK(shell_abstract_command_parse(input, length, &abstract) ==
          SHELL_ABSTRACT_EPARSE);
    CHECK(abstract == NULL);
    CHECK(shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
          SHELL_DEP_EPARSE);
    CHECK(graph.node_count == 0 && graph.edge_count == 0 &&
          graph.cwd_buf.len == 0 &&
          (graph.status & SHELL_DEP_STATUS_ERROR) != 0);
  }
  return true;
}

/* Named descriptors retain process-substitution structure through every
 * canonical surface. Direct forms create symbolic descriptor routes; composite
 * operands remain dynamic filename expressions, just as their numeric-FD
 * counterparts do. */
TEST(named_fd_process_substitutions_are_canonical) {
  static const char *const cases[] = {
      "cmd {fd}< <(producer)",  "cmd {fd}< prefix<(producer)",
      "cmd {fd}> >(consumer)",  "cmd {fd}> prefix>(consumer)",
      "cmd {fd}>> >(consumer)", "cmd {fd}>> prefix>(consumer)",
      "cmd {fd}<> <(producer)", "cmd {fd}<> prefix<(producer)",
      "cmd {fd}<> >(consumer)",
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i];
    size_t length = strlen(input);
    shell_limits_t strict = {SHELL_MAX_SUBCOMMANDS, true};
    shell_parse_result_t fast = {0};
    shell_processed_commands_t processed = {0};
    shell_netstring_buffer_t netargv = {0};
    shell_netstring_buffer_t command_netseq = {0};
    shell_netstring_buffer_t type_netseq = {0};
    shell_netstring_buffer_t anomaly_commands = {0};
    shell_netstring_buffer_t anomaly_types = {0};
    shell_transformed_command_t **transformed = NULL;
    shell_abstract_command_t *abstract = NULL;
    shell_dep_graph_t graph = {0};
    size_t count = SIZE_MAX;
    size_t transformed_count = SIZE_MAX;
    bool features = true;

    CHECK(shell_parse_fast(input, length, &strict, &fast) == SHELL_OK);
    CHECK(shell_process_commands(input, length, NULL, &processed) ==
          SHELL_PROCESS_OK);
    CHECK(processed.commands != NULL && processed.command_count >= 1);
    CHECK(shell_build_netargv_sequence_buffer(input, length, NULL, &netargv,
                                              &count,
                                              &features) == SHELL_PROCESS_OK);
    CHECK(count >= 1 && features && valid_netsequence(&netargv, count));
    count = SIZE_MAX;
    CHECK(shell_build_command_netseq_buffer(input, length, NULL,
                                            &command_netseq,
                                            &count) == SHELL_PROCESS_OK);
    CHECK(count >= 1 && valid_netsequence(&command_netseq, count));
    count = SIZE_MAX;
    CHECK(shell_build_type_netseq_buffer(input, length, NULL, &type_netseq,
                                         &count) == SHELL_PROCESS_OK);
    CHECK(count >= 1 && valid_netsequence(&type_netseq, count));
    count = SIZE_MAX;
    CHECK(shell_build_anomaly_netseqs_buffer(input, length, NULL,
                                             &anomaly_commands, &anomaly_types,
                                             &count) == SHELL_PROCESS_OK);
    CHECK(count >= 1 && valid_netsequence(&anomaly_commands, count) &&
          valid_netsequence(&anomaly_types, count));
    CHECK(shell_transform_command_line(input, length, NULL, &transformed,
                                       &transformed_count) ==
          SHELL_TRANSFORM_OK);
    CHECK(transformed != NULL && transformed_count >= 1);
    CHECK(shell_abstract_command_parse(input, length, &abstract) ==
          SHELL_ABSTRACT_OK);
    CHECK(abstract != NULL);
    CHECK(shell_dep_graph_parse(input, length, ".", NULL, &graph) ==
          SHELL_DEP_OK);
    CHECK(graph.node_count >= 1 && shell_dep_graph_validate(&graph).valid);
    shell_processed_commands_free(&processed);
    shell_netstring_buffer_free(&netargv);
    shell_netstring_buffer_free(&command_netseq);
    shell_netstring_buffer_free(&type_netseq);
    shell_netstring_buffer_free(&anomaly_commands);
    shell_netstring_buffer_free(&anomaly_types);
    shell_transformed_command_list_free(transformed, transformed_count);
    shell_abstract_command_free(abstract);
  }
  return true;
}

/* The outer word is lexically complete in each case, so the graph reaches the
 * nested command before rejecting its incomplete redirect.  Keep these
 * failure-atomic checks separate from top-level syntax rejection: they guard
 * the hand-off between substitution, redirect, and heredoc graph builders. */
TEST(nested_semantic_failures_are_atomic) {
  static const char *const cases[] = {
      "VALUE=$(echo >) command",
      "echo $(echo >)",
      "echo $(<)",
      "echo <(echo >)",
      "echo $(< <(echo >))",
      "echo > >(echo >)",
      "echo > prefix>(echo >)",
      "{ cat; } < <(echo >)suffix",
      "echo $(<prefix<(echo >))",
      "echo >$(echo >)",
      "cat <<EOF\n$(echo >)\nEOF\n",
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    const char *input = cases[i];
    shell_dep_graph_t graph = {0};
    shell_dep_error_t status =
        shell_dep_graph_parse(input, strlen(input), ".", NULL, &graph);
    bool rejected = status == SHELL_DEP_EPARSE && graph.node_count == 0 &&
                    graph.edge_count == 0 && graph.cwd_buf.len == 0 &&
                    (graph.status & SHELL_DEP_STATUS_ERROR) != 0;
    if (!rejected) {
      printf("    nested failure case %zu: status=%d for %s\n", i, (int)status,
             input);
      return false;
    }
  }
  return true;
}

static bool check_redirect_command_boundary(const char *input) {
  shell_netstring_buffer_t sequence = {0};
  size_t count = 0;
  bool features = false;
  CHECK(shell_build_netargv_sequence_buffer(input, strlen(input), NULL,
                                            &sequence, &count,
                                            &features) == SHELL_PROCESS_OK);
  static const char expected[] = "6:3:cat,,12:4:echo,2:hi,,";
  bool valid = count == 2 && sequence.length == sizeof(expected) - 1 &&
               memcmp(sequence.data, expected, sizeof(expected) - 1) == 0;
  shell_netstring_buffer_free(&sequence);
  CHECK(valid);

  shell_netstring_buffer_t anomaly = {0};
  count = 0;
  CHECK(shell_build_command_netseq_buffer(input, strlen(input), NULL, &anomaly,
                                          &count) == SHELL_PROCESS_OK);
  /* Process substitutions and expandable here-strings add child execution
   * stages ahead of the two top-level commands. The redirect-boundary matrix
   * is intentionally shared by both forms, so preserve the top-level netargv
   * assertion above and check the full anomaly sequence separately. */
  valid = count >= 2 && valid_netsequence(&anomaly, count);
  CHECK(valid);

  shell_netstring_buffer_t raw = {0}, typed = {0};
  size_t paired_count = 0;
  CHECK(shell_build_anomaly_netseqs_buffer(input, strlen(input), NULL, &raw,
                                           &typed,
                                           &paired_count) == SHELL_PROCESS_OK);
  valid = valid && paired_count == count && raw.length == anomaly.length &&
          memcmp(raw.data, anomaly.data, raw.length) == 0 &&
          valid_netsequence(&typed, paired_count);
  shell_netstring_buffer_free(&anomaly);
  shell_netstring_buffer_free(&raw);
  shell_netstring_buffer_free(&typed);
  CHECK(valid);
  return true;
}

TEST(redirect_separator_boundaries) {
  static const char *separators[] = {";", "|", "|&", "&&", "||", "&", "\n"};
  static const char *prefixes[] = {"cat >out", "{ cat; } >out"};
  static const char *spacing[] = {"", " "};
  for (size_t prefix = 0; prefix < ARRAY_COUNT(prefixes); prefix++)
    for (size_t i = 0; i < ARRAY_COUNT(separators); i++) {
      for (size_t space = 0; space < ARRAY_COUNT(spacing); space++) {
        char input[128];
        snprintf(input, sizeof(input), "%s%s%secho hi", prefixes[prefix],
                 separators[i], spacing[space]);
        CHECK(check_redirect_command_boundary(input));
      }
    }
  return true;
}

TEST(redirect_family_boundaries) {
  static const char *const inputs[] = {
      "cat <in;echo hi",
      "cat >>out;echo hi",
      "cat <>rw;echo hi",
      "cat >|out;echo hi",
      "cat &>out;echo hi",
      "cat &>>out;echo hi",
      "cat 3>out;echo hi",
      "cat {fd}>out;echo hi",
      "cat 2>&1;echo hi",
      "cat 2>&-;echo hi",
      "cat 0<&3;echo hi",
      "cat 0<<<x;echo hi",
      "cat <<<value;echo hi",
      "cat <<EOF;echo hi\nbody\nEOF\n",
      "cat 0<<EOF;echo hi\nwhile true; do :; done\nEOF\n",
      "cat 12<<-'EOF';echo hi\n\twhile $(not_a_command)\n\tEOF\n",
      "cat 0<<A 3<<B;echo hi\none\nA\ntwo\nB\n",
      "cat < <(printf x);echo hi",
      "cat > >(cat);echo hi",
      "{ cat; } <in;echo hi",
      "{ cat; } &>>out;echo hi",
      "{ cat; } 2>&1;echo hi",
      "{ cat; } 0<<<x;echo hi",
      "{ cat; } 0<<< x;echo hi",
      "{ cat; } 0<<<'x';echo hi",
      "{ cat; } 0<<< $(printf x);echo hi",
      "{ cat; } 0<<<$(printf x)suffix;echo hi",
      "{ cat; } <<EOF;echo hi\nbody\nEOF\n",
      "{ cat; } 0<<EOF;echo hi\nwhile true; do :; done\nEOF\n",
      "{ cat; } < <(printf x);echo hi",
      "{ cat; } > >(cat);echo hi",
  };
  for (size_t i = 0; i < ARRAY_COUNT(inputs); i++) {
    if (!check_redirect_command_boundary(inputs[i])) {
      fprintf(stderr, "Redirect boundary case: %s\n", inputs[i]);
      return false;
    }
  }
  return true;
}

TEST(numeric_herestring_operator_boundaries) {
  static const char *const inputs[] = {"0<<<x", "3<<<'x'", "12<<<$(printf x)"};
  static const size_t lengths[] = {4, 4, 5};
  for (size_t i = 0; i < ARRAY_COUNT(inputs); i++) {
    shell_tokenizer_state_t state;
    shell_token_t token;
    CHECK(shell_tokenizer_init(&state, inputs[i], strlen(inputs[i])));
    CHECK(shell_tokenizer_next(&state, &token));
    CHECK(token.type == SHELL_TOKEN_HERESTRING && token.position == 0 &&
          token.length == lengths[i] && token.start == inputs[i]);
    CHECK(shell_tokenizer_next(&state, &token));
    CHECK(token.position == lengths[i] && token.length != 0);
    CHECK(!shell_tokenizer_next(&state, &token));
  }
  return true;
}

TEST(numeric_redirect_canonical_boundaries) {
  static const struct {
    const char *input;
    const char *argv;
  } cases[] = {
      {"cat 0 <<<x", "3:cat,1:0,"},
      {"cat 0\t<<<x", "3:cat,1:0,"},
      {"cat 2 >&1", "3:cat,1:2,"},
      {"cat 0<<<x", "3:cat,"},
      {"cat 3\\\n>out", "3:cat,"},
      {"cat 3\\\r\n>out", "3:cat,"},
      {"cat 1\\\n2>out", "3:cat,"},
      {"cat 3\\\n >out", "3:cat,1:3,"},
      {"cat \"3\">out", "3:cat,1:3,"},
      {"cat 2147483648>out", "3:cat,10:2147483648,"},
      {"printf '%s' $'x'3>out", "6:printf,2:%s,2:x3,"},
      {"cat $'x'0<<<body", "3:cat,2:x0,"},
      {"cat ''3>out", "3:cat,1:3,"},
      {"cat \"\"3>out", "3:cat,1:3,"},
      {"cat x\\ 3>out", "3:cat,3:x 3,"},
      {"cat $'x'\\\n3>out", "3:cat,2:x3,"},
      {"cat 1\\\n2<<EOF\nbody\nEOF\n", "3:cat,"},
      {"cat 1\\\r\n2<<-'EOF'\n\tbody\n\tEOF\n", "3:cat,"},
      {"cat 1\\\n2<<<body", "3:cat,"},
      {"{ cat; } 1\\\n2<<<body", "3:cat,"},
      {"{ cat; } 1\\\n2<<EOF\nbody\nEOF\n", "3:cat,"},
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    shell_netstring_buffer_t sequence = {0}, rendered = {0};
    shell_processed_commands_t processed = {0};
    size_t count = 0;
    bool features = false;
    shell_netstring_iter_t iter;
    shell_netstring_view_t record;
    size_t length = strlen(cases[i].input);
    bool valid =
        shell_process_commands(cases[i].input, length, NULL, &processed) ==
            SHELL_PROCESS_OK &&
        processed.command_count == 1 &&
        shell_render_netargv_buffer(&processed.commands[0], NULL, &rendered) ==
            SHELL_PROCESS_OK &&
        shell_build_netargv_sequence_buffer(cases[i].input, length, NULL,
                                            &sequence, &count,
                                            &features) == SHELL_PROCESS_OK &&
        count == 1 &&
        shell_netstring_iter_init(&iter, sequence.data, sequence.length) ==
            SHELL_NETSTRING_OK &&
        shell_netstring_iter_next(&iter, &record) == SHELL_NETSTRING_OK &&
        record.payload_length == strlen(cases[i].argv) &&
        memcmp(record.payload, cases[i].argv, record.payload_length) == 0 &&
        rendered.length == record.payload_length &&
        memcmp(rendered.data, record.payload, rendered.length) == 0;
    shell_netstring_buffer_free(&sequence);
    shell_netstring_buffer_free(&rendered);
    shell_processed_commands_free(&processed);
    if (!valid) {
      fprintf(stderr, "Numeric redirect case: %s\n", cases[i].input);
      return false;
    }
  }
  return true;
}

TEST(descriptor_graph_routes_and_identities) {
  static const struct {
    const char *input;
    const char *argument;
    uint32_t fd;
    bool write;
  } cases[] = {
      {"cat $'x'3>out", "x3", 1, true},
      {"cat ''3>out", "3", 1, true},
      {"cat \"\"0<<<body", "0", 0, false},
      {"cat $'x'0<<EOF\nbody\nEOF\n", "x0", 0, false},
      {"cat 1\\\n2>out", NULL, 12, true},
      {"cat 1\\\r\n2<<<body", NULL, 12, false},
      {"cat 1\\\n2<<EOF\nbody\nEOF\n", NULL, 12, false},
      {"cat 1\\\r\n2<<-'EOF'\n\tbody\n\tEOF\n", NULL, 12, false},
      {"{ cat; } 1\\\n2<<<body", NULL, 12, false},
      {"{ cat; } 1\\\r\n2<<EOF\nbody\nEOF\n", NULL, 12, false},
      {"(cat)3>out", NULL, 3, true},
  };
  for (size_t i = 0; i < ARRAY_COUNT(cases); i++) {
    shell_dep_graph_t graph = {0};
    CHECK(shell_dep_graph_parse(cases[i].input, strlen(cases[i].input), ".",
                                NULL, &graph) == SHELL_DEP_OK);
    CHECK(shell_dep_graph_validate(&graph).valid);
    uint32_t commands = 0, routes = 0;
    for (uint32_t n = 0; n < graph.node_count; n++) {
      if (graph.nodes[n].type != SHELL_NODE_CMD)
        continue;
      const shell_dep_cmd_t *cmd = &graph.nodes[n].cmd;
      commands++;
      CHECK(cmd->token_count == (cases[i].argument ? 2u : 1u));
      CHECK(cmd->token_lens[0] == 3 && memcmp(cmd->tokens[0], "cat", 3) == 0);
      if (cases[i].argument) {
        char decoded[16];
        size_t written = 0;
        CHECK(shell_write_decoded_word(cmd->tokens[1], cmd->token_lens[1],
                                       decoded, sizeof(decoded),
                                       &written) == SHELL_PROCESS_OK);
        CHECK(written == strlen(cases[i].argument) &&
              memcmp(decoded, cases[i].argument, written) == 0);
      }
    }
    for (uint32_t e = 0; e < graph.edge_count; e++) {
      const shell_dep_edge_t *edge = &graph.edges[e];
      if (cases[i].write && edge->type == SHELL_EDGE_WRITE) {
        CHECK(edge->source_fd == cases[i].fd);
        CHECK(graph.nodes[edge->from].type ==
              (cases[i].input[0] == '(' ? SHELL_NODE_GROUP : SHELL_NODE_CMD));
        routes++;
      } else if (!cases[i].write && edge->type == SHELL_EDGE_READ) {
        CHECK(edge->target_fd == cases[i].fd);
        CHECK(graph.nodes[edge->to].type ==
              (cases[i].input[0] == '{' ? SHELL_NODE_GROUP : SHELL_NODE_CMD));
        routes++;
      }
    }
    if (commands != 1 || routes != 1) {
      fprintf(stderr, "Descriptor graph case: %s (commands=%u routes=%u)\n",
              cases[i].input, commands, routes);
      return false;
    }
  }
  return true;
}

TEST(redirect_boundaries_preserve_lexical_tolerance) {
  static const char *const inputs[] = {
      "cat >out && (",
      "cat 0<<<x && (",
      "cat > <(printf x)suffix && (",
  };
  for (size_t i = 0; i < ARRAY_COUNT(inputs); i++) {
    shell_command_t *commands = NULL;
    size_t count = 0;
    shell_tokenize_status_t status = shell_tokenize_commands(
        inputs[i], strlen(inputs[i]), &commands, &count);
    bool valid = status == SHELL_TOKENIZE_OK && commands != NULL && count == 1;
    shell_commands_free(commands, count);
    CHECK(valid);
    shell_processed_commands_t processed = {0};
    shell_process_status_t processed_status =
        shell_process_commands(inputs[i], strlen(inputs[i]), NULL, &processed);
    valid = processed_status == SHELL_PROCESS_EPARSE &&
            processed.commands == NULL && processed.command_count == 0;
    shell_processed_commands_free(&processed);
    CHECK(valid);
  }
  return true;
}

TEST(composite_redirect_word_boundaries) {
  static const char *const supported[] = {
      "> <(cat)while echo ok",       "> <(cat)if echo ok",
      "> <(cat)for echo ok",         "> <(cat)time echo ok",
      "> <(cat)declare echo ok",     "> <(cat)\"while\" echo ok",
      "> prefix<(cat)while echo ok", "> prefix<(cat)\\\nwhile echo ok",
      "{ cat; } > <(cat)while",      "{ cat; } > prefix<(cat)while",
  };
  for (size_t i = 0; i < ARRAY_COUNT(supported); i++) {
    shell_processed_commands_t processed = {0};
    CHECK(shell_process_commands(supported[i], strlen(supported[i]), NULL,
                                 &processed) == SHELL_PROCESS_OK);
    CHECK(processed.command_count == 1);
    shell_processed_commands_free(&processed);
  }

  static const char *const unsupported[] = {
      "> <(cat)foo declare -a values",
      "> <(cat)foo time echo ok",
      "> <(cat)foo [[ x ]]",
      "> <(cat)foo while true; do :; done",
      "{ cat; } > <(cat)foo while true; do :; done",
  };
  for (size_t i = 0; i < ARRAY_COUNT(unsupported); i++) {
    shell_processed_commands_t processed = {
        .commands = (shell_command_info_t *)(uintptr_t)1,
        .command_count = SIZE_MAX,
    };
    CHECK(shell_process_commands(unsupported[i], strlen(unsupported[i]), NULL,
                                 &processed) == SHELL_PROCESS_EPARSE);
    CHECK(processed.commands == NULL && processed.command_count == 0);
  }
  return true;
}

int main(void) {
  puts("shellsplit corpus tests");
  RUN(fixture_contract);
  RUN(canonical_processing_surfaces_agree);
  RUN(supported_syntax_model_matrix);
  RUN(cross_surface_edge_syntax);
  RUN(parameter_word_literal_braces_cross_surface);
  RUN(parameter_word_literal_brace_boundary);
  RUN(public_failure_and_limit_contracts);
  RUN(source_and_word_boundary_contracts);
  RUN(continued_list_topology);
  RUN(continued_punctuation_is_lossless_and_canonical);
  RUN(continued_punctuation_respects_lexical_boundaries);
  RUN(redirect_only_stages_remain_graph_visible);
  RUN(malformed_syntax_is_rejected_atomically);
  RUN(unsupported_semantics_are_rejected_atomically);
  RUN(named_fd_process_substitutions_are_canonical);
  RUN(nested_semantic_failures_are_atomic);
  RUN(redirect_separator_boundaries);
  RUN(redirect_family_boundaries);
  RUN(numeric_herestring_operator_boundaries);
  RUN(numeric_redirect_canonical_boundaries);
  RUN(descriptor_graph_routes_and_identities);
  RUN(redirect_boundaries_preserve_lexical_tolerance);
  RUN(composite_redirect_word_boundaries);
  printf("\n%u passed, %u failed\n", passed, failed);
  return failed == 0 ? 0 : 1;
}
