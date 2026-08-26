#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "shell_ast_generator.h"
#include "shell_processor.h"
#include "shell_tokenizer.h"
#include "shell_tokenizer_full.h"

static bool parse_positive_count(const char *text, size_t *value) {
  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(text, &end, 10);
  if (text[0] == '-' || errno || end == text || *end != '\0' || parsed == 0 ||
      parsed > SIZE_MAX)
    return false;
  *value = (size_t)parsed;
  return true;
}

static bool parse_seed(const char *text, uint64_t *value) {
  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(text, &end, 10);
  if (text[0] == '-' || errno || end == text || *end != '\0' ||
      parsed > UINT64_MAX)
    return false;
  *value = (uint64_t)parsed;
  return true;
}

static size_t inspect_nodes(const ast_node_t *node, uint32_t *types,
                            bool *valid) {
  if (!node)
    return 0;
  if ((unsigned)node->type > AST_BACKTICK) {
    *valid = false;
    return 0;
  }
  *types |= UINT32_C(1) << node->type;
  return 1 + inspect_nodes(node->child, types, valid) +
         inspect_nodes(node->next, types, valid);
}

static uint32_t metadata_mask(const shell_ast_t *ast) {
  return (uint32_t)ast->has_valid_structure |
         (uint32_t)ast->has_unclosed_quote << 1 |
         (uint32_t)ast->has_unclosed_paren << 2 |
         (uint32_t)ast->has_unclosed_brace << 3 | (uint32_t)ast->has_case << 4 |
         (uint32_t)ast->has_loops << 5 | (uint32_t)ast->has_conditionals << 6 |
         (uint32_t)ast->has_process_sub << 7 | (uint32_t)ast->has_heredoc << 8 |
         (uint32_t)ast->has_arithmetic << 9 | (uint32_t)ast->has_glob << 10 |
         (uint32_t)ast->has_redirect << 11 | (uint32_t)ast->has_subshell << 12 |
         (uint32_t)ast->has_binary << 13 |
         (uint32_t)ast->has_control_char << 14 |
         (uint32_t)ast->has_high_bytes << 15;
}

static bool validate_metadata(const shell_ast_t *ast, uint32_t *types) {
  if (!ast || !ast->root)
    return false;
  bool valid = true;
  uint32_t node_types = 0;
  size_t nodes = inspect_nodes(ast->root, &node_types, &valid);
  if (!valid || nodes != ast->node_count ||
      ast->has_case != !!(node_types & (UINT32_C(1) << AST_CASE)) ||
      ast->has_loops != !!(node_types & (UINT32_C(1) << AST_LOOP)) ||
      ast->has_conditionals != !!(node_types & (UINT32_C(1) << AST_IF)) ||
      ast->has_process_sub !=
          !!(node_types & (UINT32_C(1) << AST_PROCESS_SUB)) ||
      ast->has_heredoc != !!(node_types & (UINT32_C(1) << AST_HEREDOC)) ||
      ast->has_arithmetic != !!(node_types & (UINT32_C(1) << AST_ARITHMETIC)) ||
      ast->has_glob != !!(node_types & (UINT32_C(1) << AST_GLOB)) ||
      ast->has_redirect != !!(node_types & (UINT32_C(1) << AST_REDIRECT)) ||
      ast->has_subshell != !!(node_types & ((UINT32_C(1) << AST_SUBSHELL) |
                                            (UINT32_C(1) << AST_BACKTICK))) ||
      shell_ast_is_valid(ast) != ast->has_valid_structure ||
      shell_ast_has_unclosed_quote(ast) != ast->has_unclosed_quote ||
      shell_ast_has_unclosed_paren(ast) != ast->has_unclosed_paren ||
      shell_ast_has_unclosed_brace(ast) != ast->has_unclosed_brace)
    return false;
  *types |= node_types;
  return true;
}

static bool seed_zero_is_stable(void) {
  shell_ast_generator_t *generator = shell_ast_generator_create(0);
  shell_ast_t *ast = shell_ast_generator_generate(generator);
  char buffer[128] = {0};
  bool stable = ast &&
                shell_ast_serialize(ast, buffer, sizeof(buffer)) == buffer &&
                strcmp(buffer, "ps< /tmp/test2.txt ; id> /tmp/test0.txt") == 0;
  shell_ast_destroy(ast);
  shell_ast_generator_destroy(generator);
  return stable;
}

static int verify_command(const char *cmd, size_t cmd_len,
                          bool expects_parse_success) {
  shell_parse_result_t result = {0};
  shell_limits_t limits = SHELL_LIMITS_DEFAULT;
  limits.strict_mode = true;
  shell_error_t err = shell_parse_fast(cmd, cmd_len, &limits, &result);

  if (expects_parse_success) {
    if (err != SHELL_OK) {
      printf("FAIL: expected parse success but got error %d for: %s\n", err,
             cmd);
      return 1;
    }
  } else {
    if (err == SHELL_OK) {
      printf("FAIL: invalid syntax not detected: %s\n", cmd);
      return 1;
    }
  }

  shell_command_t *commands = NULL;
  size_t command_count = 0;
  bool full_ok = (shell_tokenize_commands(cmd, strlen(cmd), &commands,
                                          &command_count) == SHELL_TOKENIZE_OK);

  shell_command_info_t *infos = NULL;
  size_t info_count = 0;
  bool proc_ok = shell_process_command(cmd, strlen(cmd), NULL, &infos,
                                       &info_count) == SHELL_PROCESS_OK;

  int failed = 0;
  if (expects_parse_success && (!full_ok || !proc_ok)) {
    printf("FAIL: parser disagreement (fast=%d full=%d processor=%d) for: "
           "%s\n",
           err == SHELL_OK, full_ok, proc_ok, cmd);
    failed = 1;
  } else if (expects_parse_success &&
             (result.count != command_count || command_count != info_count)) {
    printf("FAIL: parser count disagreement (fast=%u full=%zu processor=%zu) "
           "for: %s\n",
           result.count, command_count, info_count, cmd);
    failed = 1;
  } else if (expects_parse_success) {
    for (size_t i = 0; i < command_count; i++) {
      size_t full_length = commands[i].end_pos - commands[i].start_pos;
      if (result.cmds[i].start != commands[i].start_pos ||
          result.cmds[i].len > full_length) {
        printf("FAIL: incompatible parser range at command %zu "
               "(fast=%u+%u full=%zu+%zu) for: %s\n",
               i, result.cmds[i].start, result.cmds[i].len,
               commands[i].start_pos, full_length, cmd);
        failed = 1;
        break;
      }
    }
  }

  if (commands)
    shell_commands_free(commands, command_count);
  if (infos)
    shell_command_infos_free(infos, info_count);

  return failed;
}

int main(int argc, char **argv) {
  size_t num_tests = 100;
  uint64_t seed = 0;
  bool seed_provided = false;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
      if (!parse_positive_count(argv[++i], &num_tests)) {
        fprintf(stderr, "invalid test count: %s\n", argv[i]);
        return 2;
      }
    } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
      if (!parse_seed(argv[++i], &seed)) {
        fprintf(stderr, "invalid seed: %s\n", argv[i]);
        return 2;
      }
      seed_provided = true;
    } else if (strcmp(argv[i], "--help") == 0) {
      printf("Usage: %s [-n count] [-s seed]\n", argv[0]);
      return 0;
    } else {
      fprintf(stderr, "Usage: %s [-n count] [-s seed]\n", argv[0]);
      return 2;
    }
  }

  printf("Running %zu AST-based generated shell command tests...\n", num_tests);

  if (!seed_zero_is_stable()) {
    fprintf(stderr, "FAIL: seed zero does not reproduce its golden AST\n");
    return 1;
  }

  if (!seed_provided)
    seed = ((uint64_t)time(NULL) << 32) | (getpid() & 0xFFFFFFFF);
  printf("Using seed: %" PRIu64 "\n", seed);

  shell_ast_generator_t *gen = shell_ast_generator_create(seed);
  shell_ast_generator_t *replay = shell_ast_generator_create(seed);
  if (!gen || !replay) {
    fprintf(stderr, "FAIL: could not create AST generator\n");
    shell_ast_generator_destroy(gen);
    shell_ast_generator_destroy(replay);
    return 1;
  }
  if (shell_ast_generator_generate(NULL) != NULL) {
    fprintf(stderr, "FAIL: NULL generator was accepted\n");
    shell_ast_generator_destroy(gen);
    shell_ast_generator_destroy(replay);
    return 1;
  }

  char buffer[4096];
  char replay_buffer[4096];
  size_t passed = 0;
  size_t correctly_rejected = 0;
  size_t failed = 0;
  uint32_t generated_types = 0;

  for (size_t i = 0; i < num_tests; i++) {
    shell_ast_t *ast = shell_ast_generator_generate(gen);
    shell_ast_t *replayed_ast = shell_ast_generator_generate(replay);

    if (!ast || !replayed_ast) {
      printf("FAIL: generator returned NULL at case %zu\n", i);
      failed++;
      shell_ast_destroy(ast);
      shell_ast_destroy(replayed_ast);
      continue;
    }

    buffer[0] = '\0';
    replay_buffer[0] = '\0';
    if (shell_ast_serialize(ast, buffer, sizeof(buffer)) != buffer ||
        shell_ast_serialize(replayed_ast, replay_buffer,
                            sizeof(replay_buffer)) != replay_buffer) {
      printf("FAIL: generator serialization failed at case %zu\n", i);
      failed++;
      shell_ast_destroy(ast);
      shell_ast_destroy(replayed_ast);
      continue;
    }
    size_t cmd_len = strlen(buffer);

    uint32_t current_types = 0;
    uint32_t replayed_types = 0;
    if (cmd_len == 0 || strcmp(buffer, replay_buffer) != 0 ||
        metadata_mask(ast) != metadata_mask(replayed_ast) ||
        !validate_metadata(ast, &current_types) ||
        !validate_metadata(replayed_ast, &replayed_types) ||
        current_types != replayed_types ||
        ast->node_count != replayed_ast->node_count) {
      printf("FAIL: non-deterministic or invalid AST metadata at case %zu\n",
             i);
      failed++;
      shell_ast_destroy(ast);
      shell_ast_destroy(replayed_ast);
      continue;
    }
    generated_types |= current_types;

    char tiny[1] = {'x'};
    if (shell_ast_serialize(ast, tiny, sizeof(tiny)) != tiny ||
        tiny[0] != '\0') {
      printf("FAIL: bounded serialization failed at case %zu\n", i);
      failed++;
      shell_ast_destroy(ast);
      shell_ast_destroy(replayed_ast);
      continue;
    }

    bool expects_success = shell_ast_expects_parse_success(ast);

    int result = verify_command(buffer, cmd_len, expects_success);

    if (result == 0) {
      if (expects_success) {
        passed++;
      } else {
        correctly_rejected++;
      }
    } else {
      failed++;
      printf("FAIL: generated case %zu with seed %" PRIu64 "\n", i, seed);
    }

    shell_ast_destroy(ast);
    shell_ast_destroy(replayed_ast);

    if ((i + 1) % 100 == 0) {
      printf("Progress: %zu/%zu (passed: %zu, rejected: %zu, failed: %zu)\n",
             i + 1, num_tests, passed, correctly_rejected, failed);
    }
  }

  printf("\n=== RESULTS ===\n");
  printf("Total: %zu\n", num_tests);
  printf("Passed (valid commands parsed): %zu\n", passed);
  printf("Correctly rejected (invalid detected): %zu\n", correctly_rejected);
  printf("Failed: %zu\n", failed);
  if (passed + correctly_rejected + failed != num_tests) {
    fprintf(stderr,
            "FAIL: only %zu of %zu generated cases were accounted for\n",
            passed + correctly_rejected + failed, num_tests);
    failed++;
  }
  if (passed == 0 || correctly_rejected == 0) {
    fprintf(stderr,
            "FAIL: generated corpus did not exercise both acceptance paths\n");
    failed++;
  }
  uint32_t all_node_types = (UINT32_C(1) << (AST_BACKTICK + 1)) - 1;
  if (num_tests >= 1000 && generated_types != all_node_types) {
    fprintf(stderr,
            "FAIL: generated node coverage 0x%" PRIx32 ", expected 0x%" PRIx32
            "\n",
            generated_types, all_node_types);
    failed++;
  }
  printf("Success rate: %.2f%%\n",
         (double)(passed + correctly_rejected) / num_tests * 100.0);

  shell_ast_generator_destroy(gen);
  shell_ast_generator_destroy(replay);
  shell_ast_generator_destroy(NULL);
  return failed > 0 ? 1 : 0;
}
