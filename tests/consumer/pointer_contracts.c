#define _POSIX_C_SOURCE 200809L

#include "../../shellgate/src/sg_io.h"
#include "../../shellsplit/src/shell_pipeline_internal.h"
#include "../../shellsplit/src/shell_source_internal.h"
#include "../../shellsplit/src/shell_tokenizer_full_internal.h"
#include "../../shelltype/src/io.h"
#include "../../shelltype/src/policy_ctx.h"
#include "shell_netstring.h"
#include "shell_processor.h"
#include "shell_transform.h"
#include "shellgate.h"
#include "shelltype.h"

/* Compile-only access to private leaves: their required-pointer annotations
 * are checked without exporting test seams or executing invalid API calls. */
#if TEST_BAD >= 29 && TEST_BAD <= 46
#include "../../shellsplit/src/shell_tokenizer_full.c"
#elif (TEST_BAD >= 51 && TEST_BAD <= 53) ||                                    \
    (TEST_BAD >= 56 && TEST_BAD <= 75) || TEST_BAD == 149
#include "../../shellsplit/src/shell_processor.c"
#elif TEST_BAD == 106
#include "../../shellsplit/src/shell_tokenizer.c"
#elif TEST_BAD >= 107 && TEST_BAD <= 109
#include "../../shellsplit/src/shell_depgraph.c"
#endif

static bool visit_token(const st_token_view_t *token, void *context) {
  (void)token;
  (void)context;
  return true;
}

static bool visit_byte(unsigned char byte, void *context) {
  (void)byte;
  (void)context;
  return true;
}

/* Compile only: invalid calls must be diagnosed, never executed. */
void pointer_contracts(sg_gate_t *gate, st_policy_t *policy) {
  shell_netstring_iter_t iter;
  shell_netstring_view_t view;
  shell_processed_commands_t processed = {0};
  st_eval_result_t evaluation;
  sg_result_t result;
  char buffer[1024];
  sg_atomic_output_t gate_output = {0};
  st_atomic_output_t type_output = {0};
  shell_source_substitution_scan_t scan = {0};
  shell_source_substitution_kind_t kind;
  size_t start = 0, after = 0;
  shell_token_t token = {.start = "x", .length = 1};
#if TEST_BAD >= 110
  shell_parse_result_t parsed = {0};
  shell_pipeline_index_t pipeline;
  shell_execution_map_t execution;
  shell_pipeline_stage_t stage;
  uint32_t cursor = 0, end = 0;
#endif

#if TEST_BAD == 1
  (void)shell_netstring_iter_next(NULL, &view);
#elif TEST_BAD == 2
  (void)shell_netstring_iter_next(&iter, NULL);
#elif TEST_BAD == 3
  (void)st_policy_eval_view(policy, (st_netargv_view_t){"1:x,", 4}, NULL);
#elif TEST_BAD == 4
  (void)st_policy_eval_view(NULL, (st_netargv_view_t){"1:x,", 4}, &evaluation);
#elif TEST_BAD == 5
  (void)sg_gate_evaluate(NULL, "echo", 4, buffer, sizeof(buffer), &result);
#elif TEST_BAD == 6
  (void)sg_gate_evaluate(gate, "echo", 4, buffer, sizeof(buffer), NULL);
#elif TEST_BAD == 7
  (void)shell_process_commands(NULL, 0, NULL, &processed);
#elif TEST_BAD == 8
  (void)shell_write_decoded_word("x", 1, buffer, sizeof(buffer), NULL);
#elif TEST_BAD == 9
  sg_anomaly_model_t *model = sg_anomaly_model_new();
  (void)sg_anomaly_model_fourgram_count(model, NULL, "b", "c", "d");
#elif TEST_BAD == 10
  (void)sg_atomic_output_begin(NULL, &gate_output);
#elif TEST_BAD == 11
  (void)sg_atomic_output_begin("unused", NULL);
#elif TEST_BAD == 12
  (void)sg_atomic_output_commit(NULL);
#elif TEST_BAD == 13
  (void)st_atomic_output_begin(NULL, &type_output);
#elif TEST_BAD == 14
  (void)st_atomic_output_begin("unused", NULL);
#elif TEST_BAD == 15
  (void)st_atomic_output_commit(NULL);
#elif TEST_BAD == 16
  (void)shell_file_directory_prefix_length(NULL);
#elif TEST_BAD == 17
  shell_file_write_directory(NULL, 0, (char[2]){0});
#elif TEST_BAD == 18
  char *netpattern = NULL;
  (void)st_netpattern_from_cpl(NULL, &netpattern);
#elif TEST_BAD == 19
  (void)st_netpattern_from_cpl("echo", NULL);
#elif TEST_BAD == 20
  (void)shell_pipeline_prefix_step(NULL, SHELL_PIPE_PREFIX_WORD_TIME);
#elif TEST_BAD == 21
  (void)shell_source_parse_pipeline_prefix(NULL, 0, 0);
#elif TEST_BAD == 22
  (void)shell_source_next_executable_substitution("x", 1, NULL, &start, &after,
                                                  &kind);
#elif TEST_BAD == 23
  (void)shell_source_next_executable_substitution("x", 1, &scan, NULL, &after,
                                                  &kind);
#elif TEST_BAD == 24
  (void)shell_source_next_executable_substitution("x", 1, &scan, &start, NULL,
                                                  &kind);
#elif TEST_BAD == 25
  (void)shell_source_next_executable_substitution("x", 1, &scan, &start, &after,
                                                  NULL);
#elif TEST_BAD == 26
  (void)shell_tokenizer_token_continues_word(NULL, 0);
#elif TEST_BAD == 27
  shell_transformed_command_t *transformed = NULL;
  (void)shell_transform_command(NULL, NULL, &transformed);
#elif TEST_BAD == 28
  shell_command_t command = {0};
  (void)shell_transform_command(&command, NULL, NULL);
#elif TEST_BAD == 29
  arithmetic_skip_space(NULL);
#elif TEST_BAD == 30
  (void)arithmetic_match(NULL, "+");
#elif TEST_BAD == 31
  static_arithmetic_parser_t parser = {.input = "1", .length = 1};
  (void)arithmetic_match(&parser, NULL);
#elif TEST_BAD == 32
  (void)arithmetic_parse_primary(NULL, 1);
#elif TEST_BAD == 33
  (void)arithmetic_parse_unary(NULL, 1);
#elif TEST_BAD == 34
  bool right_associative;
  (void)arithmetic_binary_precedence(NULL, &right_associative);
#elif TEST_BAD == 35
  static_arithmetic_parser_t parser = {.input = "1", .length = 1};
  (void)arithmetic_binary_precedence(&parser, NULL);
#elif TEST_BAD == 36
  (void)arithmetic_parse_binary(NULL, 1, 1);
#elif TEST_BAD == 37
  (void)arithmetic_parse_conditional(NULL, 1);
#elif TEST_BAD == 38
  (void)arithmetic_parse_comma(NULL, 1);
#elif TEST_BAD == 39
  semantic_pipeline_prefix_t prefix = semantic_pipeline_prefix_initial();
  (void)semantic_token_is_pipeline_prefix(NULL, 1, &token, &prefix);
#elif TEST_BAD == 40
  semantic_pipeline_prefix_t prefix = semantic_pipeline_prefix_initial();
  (void)semantic_token_is_pipeline_prefix("x", 1, NULL, &prefix);
#elif TEST_BAD == 41
  (void)semantic_token_is_pipeline_prefix("x", 1, &token, NULL);
#elif TEST_BAD == 42
  semantic_builtin_state_t builtin;
  (void)semantic_set_builtin_target(NULL, 1, &token, &builtin);
#elif TEST_BAD == 43
  semantic_builtin_state_t builtin;
  (void)semantic_set_builtin_target("x", 1, NULL, &builtin);
#elif TEST_BAD == 44
  (void)semantic_set_builtin_target("x", 1, &token, NULL);
#elif TEST_BAD == 45
  (void)arithmetic_has_unsupported_semantics(NULL, 0);
#elif TEST_BAD == 46
  (void)arithmetic_has_unsupported_semantics_depth(NULL, 0, 1);
#elif TEST_BAD == 47
  (void)shell_source_bytes_valid(NULL, 0);
#elif TEST_BAD == 48
  shell_command_t *commands = NULL;
  (void)shell_tokenize_prevalidated_commands(NULL, 0, true, &commands, &start);
#elif TEST_BAD == 49
  (void)shell_tokenize_prevalidated_commands("echo", 4, true, NULL, &start);
#elif TEST_BAD == 50
  shell_command_t *commands = NULL;
  (void)shell_tokenize_prevalidated_commands("echo", 4, true, &commands, NULL);
#elif TEST_BAD == 51
  rebase_tokens(NULL, 0, 0, NULL);
#elif TEST_BAD == 52
  shell_command_info_t info = {0};
  own_token_text(NULL, &info);
#elif TEST_BAD == 53
  shell_command_t command = {0};
  own_token_text(&command, NULL);
#elif TEST_BAD == 54
  shell_parse_result_t parsed;
  (void)shell_parse_prevalidated(NULL, 0, NULL, &parsed);
#elif TEST_BAD == 55
  (void)shell_parse_prevalidated("echo", 4, NULL, NULL);
#elif TEST_BAD == 56
  const char *content;
  anomaly_substitution_content(NULL, 4, 0, 4, SHELL_SOURCE_SUBST_COMMAND,
                               &content, &start);
#elif TEST_BAD == 57
  anomaly_substitution_content("$(x)", 4, 0, 4, SHELL_SOURCE_SUBST_COMMAND,
                               NULL, &start);
#elif TEST_BAD == 58
  const char *content;
  anomaly_substitution_content("$(x)", 4, 0, 4, SHELL_SOURCE_SUBST_COMMAND,
                               &content, NULL);
#elif TEST_BAD == 59
  (void)shell_source_match_plain_word(NULL, 0, 0, "time", 4, &after);
#elif TEST_BAD == 60
  (void)shell_source_match_plain_word("time", 4, 0, NULL, 4, &after);
#elif TEST_BAD == 61
  (void)shell_source_match_pipeline_negator(NULL, 0, 0, &after);
#elif TEST_BAD == 62
  shell_source_pending_heredoc_t pending = {.word = "EOF", .word_length = 3};
  (void)shell_source_visit_pending_heredoc_bodies(NULL, 0, 0, &pending, 1, NULL,
                                                  NULL, &after);
#elif TEST_BAD == 63
  (void)shell_source_visit_pending_heredoc_bodies("", 0, 0, NULL, 1, NULL, NULL,
                                                  &after);
#elif TEST_BAD == 64
  shell_source_pending_heredoc_t pending = {.word = "EOF", .word_length = 3};
  (void)shell_source_visit_pending_heredoc_bodies("", 0, 0, &pending, 1, NULL,
                                                  NULL, NULL);
#elif TEST_BAD == 65
  shell_source_pending_heredoc_t pending = {.word = "EOF", .word_length = 3};
  (void)shell_source_skip_pending_heredoc_bodies("", 0, 0, &pending, 1, NULL);
#elif TEST_BAD == 66
  bool complete;
  (void)shell_source_visit_heredoc_sequence(NULL, 0, 0, NULL, NULL, &after,
                                            &complete);
#elif TEST_BAD == 67
  bool complete;
  (void)shell_source_visit_heredoc_sequence("<<EOF", 5, 0, NULL, NULL, NULL,
                                            &complete);
#elif TEST_BAD == 68
  (void)shell_source_visit_heredoc_sequence("<<EOF", 5, 0, NULL, NULL, &after,
                                            NULL);
#elif TEST_BAD == 69
  bool complete;
  (void)shell_source_skip_heredoc_sequence("<<EOF", 5, 0, NULL, &complete);
#elif TEST_BAD == 70
  (void)shell_source_skip_heredoc_sequence("<<EOF", 5, 0, &after, NULL);
#elif TEST_BAD == 71
  (void)shell_source_parse_compound_tail(NULL, 0, 0);
#elif TEST_BAD == 72
  (void)shell_source_redirect_list_before_group(NULL, 0, 0);
#elif TEST_BAD == 73
  const shell_source_pending_heredoc_t pending = {.word = "EOF",
                                                  .word_length = 3};
  (void)shell_source_line_is_heredoc_delimiter(NULL, 0, 0, &pending);
#elif TEST_BAD == 74
  (void)shell_source_line_is_heredoc_delimiter("EOF", 3, 0, NULL);
#elif TEST_BAD == 75
  (void)shell_source_heredoc_delimiter_is_quoted(NULL);
#elif TEST_BAD == 76
  (void)shell_source_next_variable_expansion("$x", 2, NULL, &start, &after);
#elif TEST_BAD == 77
  shell_source_variable_scan_t variables = {0};
  (void)shell_source_next_variable_expansion("$x", 2, &variables, NULL, &after);
#elif TEST_BAD == 78
  shell_source_variable_scan_t variables = {0};
  (void)shell_source_next_variable_expansion("$x", 2, &variables, &start, NULL);
#elif TEST_BAD == 79
  (void)shell_source_visit_static_word(NULL, 0, visit_byte, NULL);
#elif TEST_BAD == 80
  (void)shell_source_visit_static_word("x", 1, NULL, NULL);
#elif TEST_BAD == 81
  shell_source_decoded_assignment_t assignment;
  (void)shell_source_scan_decoded_assignment(NULL, 0, NULL, NULL, &assignment);
#elif TEST_BAD == 82
  (void)shell_source_scan_decoded_assignment("x=y", 3, NULL, NULL, NULL);
#elif TEST_BAD == 83
  (void)shell_source_word_static_equals(NULL, 0, "");
#elif TEST_BAD == 84
  (void)shell_source_word_static_equals("x", 1, NULL);
#elif TEST_BAD == 85
  (void)shell_source_static_word_match_byte('x', NULL);
#elif TEST_BAD == 86
  shell_source_assignment_word_t assignment;
  (void)shell_source_parse_scalar_assignment_word(NULL, 0, &assignment);
#elif TEST_BAD == 87
  (void)shell_source_parse_scalar_assignment_word("x=y", 3, NULL);
#elif TEST_BAD == 88
  (void)shell_source_static_dash_byte('-', NULL);
#elif TEST_BAD == 89
  (void)shell_source_command_option_byte('p', NULL);
#elif TEST_BAD == 90
  (void)shell_source_word_static_starts_dash(NULL, 0);
#elif TEST_BAD == 91
  (void)shell_source_classify_command_option(NULL, 0);
#elif TEST_BAD == 92
  (void)shell_source_static_builtin_kind(NULL, 0);
#elif TEST_BAD == 93
  (void)shell_source_wrapper_kind(NULL, 0);
#elif TEST_BAD == 94
  (void)shell_source_wrapper_start(NULL, "command", 7);
#elif TEST_BAD == 95
  shell_source_wrapper_state_t state = {0};
  (void)shell_source_wrapper_start(&state, NULL, 0);
#elif TEST_BAD == 96
  (void)shell_source_wrapper_consume(NULL, "printf", 6);
#elif TEST_BAD == 97
  shell_source_wrapper_state_t state = {0};
  (void)shell_source_wrapper_consume(&state, NULL, 0);
#elif TEST_BAD == 98
  uint32_t fd;
  (void)shell_source_parse_io_number("2", 0, 1, NULL, &fd);
#elif TEST_BAD == 99
  (void)shell_source_parse_io_number("2", 0, 1, &after, NULL);
#elif TEST_BAD == 100
  (void)shell_source_skip_complete_backtick("`x`", 3, 0, NULL);
#elif TEST_BAD == 101
  (void)shell_source_skip_complete_ansi_c_quote("$'x'", 4, 0, NULL);
#elif TEST_BAD == 102
  (void)shell_source_skip_array_subscript("[0]", 3, 0, NULL);
#elif TEST_BAD == 103
  (void)shell_source_find_parameter_array_subscript("${x[0]}", 7, 0, NULL,
                                                    &start);
#elif TEST_BAD == 104
  (void)shell_source_find_parameter_array_subscript("${x[0]}", 7, 0, &after,
                                                    NULL);
#elif TEST_BAD == 105
  (void)shell_source_decode_ansi_c_quote("$'x'", 4, NULL, NULL, NULL);
#elif TEST_BAD == 106
  size_t subscript, value, end;
  (void)skip_array_assignment("x=(a)", 5, 0, NULL, &subscript, &after, &value,
                              &end);
#elif TEST_BAD == 107
  (void)dep_analyze_exec(NULL, 0, true);
#elif TEST_BAD == 108
  unsigned char byte;
  (void)dep_fd_name_next_byte("fd", 2, NULL, &byte);
#elif TEST_BAD == 109
  uint32_t position = 0;
  (void)dep_fd_name_next_byte("fd", 2, &position, NULL);
#elif TEST_BAD == 110
  (void)shell_pipeline_range_is_empty_timing(NULL, &parsed.cmds[0]);
#elif TEST_BAD == 111
  (void)shell_pipeline_range_is_empty_timing("time", NULL);
#elif TEST_BAD == 112
  shell_pipeline_index_build(NULL, 0, &parsed, &pipeline);
#elif TEST_BAD == 113
  shell_pipeline_index_build("", 0, NULL, &pipeline);
#elif TEST_BAD == 114
  shell_pipeline_index_build("", 0, &parsed, NULL);
#elif TEST_BAD == 115
  (void)shell_pipeline_group_at(NULL, &pipeline, 0);
#elif TEST_BAD == 116
  (void)shell_pipeline_group_at(&parsed, NULL, 0);
#elif TEST_BAD == 117
  (void)shell_pipeline_group_context("", 0, &parsed, &pipeline, NULL);
#elif TEST_BAD == 118
  (void)shell_pipeline_group_limit(&parsed, NULL);
#elif TEST_BAD == 119
  (void)shell_pipeline_range_limit(&parsed, NULL, 0);
#elif TEST_BAD == 120
  (void)shell_pipeline_extend_stage("", 0, &parsed, &pipeline, 0, NULL, &end);
#elif TEST_BAD == 121
  (void)shell_pipeline_extend_stage("", 0, &parsed, &pipeline, 0, &cursor,
                                    NULL);
#elif TEST_BAD == 122
  (void)shell_pipeline_next("", 0, &parsed, &pipeline, 0, &cursor, &end, NULL);
#elif TEST_BAD == 123
  shell_execution_map_build("", 0, &parsed, NULL);
#elif TEST_BAD == 124
  (void)shell_execution_range(&parsed, NULL, 0);
#elif TEST_BAD == 125
  (void)shell_execution_document(NULL);
#elif TEST_BAD == 126
  (void)shell_execution_backgrounded(&parsed, NULL, 0);
#elif TEST_BAD == 127
  (void)shell_pipeline_tail_interval_compare(NULL, &stage);
#elif TEST_BAD == 128
  (void)shell_source_skip_parameter_selector("x", 1, 0, NULL);
#elif TEST_BAD == 129
  (void)shell_source_skip_glob_bracket("[x]", 3, 0, NULL);
#elif TEST_BAD == 130
  (void)shell_source_skip_double_quote_expansion("$x", 2, 0, NULL, &after);
#elif TEST_BAD == 131
  bool recognized;
  (void)shell_source_skip_double_quote_expansion("$x", 2, 0, &recognized, NULL);
#elif TEST_BAD == 132
  (void)shell_source_skip_complete_quoted_text("'x'", 3, 0, '\'', NULL);
#elif TEST_BAD == 133
  (void)shell_source_skip_variable_expansion("$x", 2, 0, NULL);
#elif TEST_BAD == 134
  (void)shell_source_skip_extglob("@(x)", 4, 0, NULL);
#elif TEST_BAD == 135
  (void)st_policy_ctx_is_exclusive(NULL);
#elif TEST_BAD == 136
  (void)st_policy_ctx_intern(NULL, "value");
#elif TEST_BAD == 137
  (void)st_policy_ctx_intern(st_policy_ctx_new(), NULL);
#elif TEST_BAD == 138
  (void)st_policy_ctx_intern_view(NULL, NULL, 0);
#elif TEST_BAD == 139
  (void)st_policy_ctx_swap_storage(NULL, st_policy_ctx_new());
#elif TEST_BAD == 140
  (void)st_policy_ctx_swap_storage(st_policy_ctx_new(), NULL);
#elif TEST_BAD == 141
  shell_file_write_directory("unused", 0, NULL);
#elif TEST_BAD == 142
  (void)shell_file_create_temp_at(0, "destination", NULL);
#elif TEST_BAD == 143
  (void)shell_file_create_temp_from_bytes(0, "destination", NULL,
                                          (char[12]){0});
#elif TEST_BAD == 144
  (void)shell_file_create_temp_from_bytes(
      0, "destination", (const unsigned char[SHELL_FILE_TEMP_RANDOM_BYTES]){0},
      NULL);
#elif TEST_BAD == 145
  (void)shell_file_create_temp_at(0, NULL, (char[12]){0});
#elif TEST_BAD == 146
  (void)shell_file_create_temp_from_bytes(
      0, NULL, (const unsigned char[SHELL_FILE_TEMP_RANDOM_BYTES]){0},
      (char[12]){0});
#elif TEST_BAD == 147
  size_t prefix;
  (void)shell_file_path_prefix(NULL, &prefix);
#elif TEST_BAD == 148
  (void)shell_file_path_prefix("destination", NULL);
#elif TEST_BAD == 149
  (void)shell_processed_command_is_empty_timing(NULL);
#else
  /* These NULL values have API meanings and must stay accepted. */
  (void)shell_netstring_iter_init(&iter, NULL, 0);
  (void)shell_netstring_iter_next(&iter, &view);
  (void)shell_source_next_executable_substitution(NULL, 0, &scan, &start,
                                                  &after, &kind);
  shell_source_variable_scan_t variables = {0};
  (void)shell_source_next_variable_expansion(NULL, 0, &variables, &start,
                                             &after);
  bool recognized;
  (void)shell_source_skip_parameter_selector(NULL, 0, 0, &after);
  (void)shell_source_skip_glob_bracket(NULL, 0, 0, &after);
  (void)shell_source_skip_double_quote_expansion(NULL, 0, 0, &recognized,
                                                 &after);
  (void)shell_source_skip_complete_quoted_text(NULL, 0, 0, '\'', &after);
  (void)shell_source_skip_variable_expansion(NULL, 0, 0, &after);
  (void)shell_source_skip_extglob(NULL, 0, 0, &after);
  (void)shell_tokenizer_token_continues_word(&token, 0);
  (void)shell_source_bytes_valid("", 0);
  shell_source_decoded_assignment_t assignment;
  (void)shell_source_scan_decoded_assignment("x=y", 3, NULL, NULL, &assignment);
  (void)shell_source_match_plain_word("time", 4, 0, "time", 4, NULL);
  (void)shell_source_match_pipeline_negator("!", 1, 0, NULL);
  bool complete;
  (void)shell_source_visit_heredoc_sequence("<<EOF\nx\nEOF\n", 12, 0, NULL,
                                            NULL, &after, &complete);
  (void)shell_process_commands("echo", 4, NULL, &processed);
  (void)st_netargv_visit_view((st_netargv_view_t){NULL, 0}, visit_token, NULL,
                              NULL);
  (void)sg_gate_set_expand_var_netargv(gate, NULL, NULL);
  (void)sg_gate_set_expand_glob_netargv(gate, NULL, NULL);
  st_learner_t *learner = st_learner_new(NULL);
  st_policy_ctx_t *context = st_policy_ctx_new();
  (void)st_policy_ctx_intern_view(context, NULL, 0);
  st_policy_ctx_release(context);
  sg_anomaly_model_t *model = sg_anomaly_model_new_with_config(NULL);
  st_learner_free(learner);
  sg_anomaly_model_free(model);
  shell_netstring_buffer_free(NULL);
  st_netpattern_free(NULL);
  st_policy_free(NULL);
  sg_gate_free(NULL);
  sg_atomic_output_discard(NULL);
  st_atomic_output_discard(NULL);
#endif
}
