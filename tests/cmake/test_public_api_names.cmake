cmake_minimum_required(VERSION 3.20)

file(GLOB public_headers
  "${SHELLCLAVE_SOURCE_DIR}/shellsplit/include/*.h"
  "${SHELLCLAVE_SOURCE_DIR}/shelltype/include/*.h"
  "${SHELLCLAVE_SOURCE_DIR}/shellgate/include/*.h")

set(removed_identifiers
  sg_gate_load_policy
  sg_gate_save_policy
  sg_gate_add_allow_netpattern
  sg_gate_remove_allow_netpattern
  sg_gate_batch_add_allow_netpatterns
  sg_gate_add_deny_netpattern
  sg_gate_remove_deny_netpattern
  sg_gate_batch_add_deny_netpatterns
  sg_gate_add_allow_cpl
  sg_gate_remove_allow_cpl
  sg_gate_allow_rule_count
  sg_gate_add_deny_cpl
  sg_gate_remove_deny_cpl
  sg_gate_deny_rule_count
  sg_gate_anomaly_vocab_size
  sg_expand_status_t
  sg_expand_word_purpose_t
  sg_expand_word_request_t
  sg_expand_word_netargv_fn
  SG_EXPAND_UNRESOLVED
  SG_EXPAND_RESOLVED
  SG_EXPAND_FAILED
  SG_EXPAND_WORD_ARGUMENT
  SG_EXPAND_WORD_REDIRECT_PATH
  SG_EXPAND_WORD_FILE_SUBSTITUTION_PATH
  sg_anomaly_model_unigram_count
  sg_anomaly_model_bigram_count
  sg_anomaly_model_trigram_count
  sg_anomaly_model_fourgram_count
  SG_ANOMALY_MAX_COMMAND_LENGTH
  shell_command_has_shell_features
  shell_env_screener_recommended_capacity
  shell_abstract_command_get_source
  shell_abstract_command_get_display_text
  shell_abstract_command_has_variables
  shell_abstract_command_has_pos_vars
  shell_abstract_command_has_special_vars
  shell_abstract_command_has_globs
  shell_abstract_command_has_paths
  shell_abstract_command_has_abs_paths
  shell_abstract_command_has_rel_paths
  shell_abstract_command_has_home_paths
  shell_abstract_command_has_cmd_subst
  shell_abstract_command_has_redirects
  shell_abstract_command_has_arithmetic
  shell_abstract_command_has_strings
  shell_netstring_buffer_is_empty
  shell_render_netargv
  shell_build_netargv_sequence
  shell_build_command_netseq
  shell_build_type_netseq
  shell_build_anomaly_netseqs
  st_learner_feed_netargv
  st_netargv_classify
  st_netargv_visit
  st_netpattern_from_cpl
  st_netpattern_to_cpl
  st_netpattern_encode
  st_netpattern_decode
  st_netpattern_apply_type_at
  st_netpattern_validate
  st_policy_add_netpattern
  st_policy_remove_netpattern
  st_policy_batch_add_netpatterns
  st_policy_eval
  st_policy_match
  st_policy_verify_all
  st_policy_visit_matches
  st_policy_simulate_add_netpattern
  sg_cpl_token_variants_at
  sg_result_violation_dropped
  shell_transformed_command_get_display_text
  shell_transformed_command_has_transformations
  shell_env_screener_combined_score
  sample_value
  sample_value_length
  st_policy_ctx_free
  st_policy_ctx_compact
  st_policy_ctx_intern
  st_policy_ctx_is_exclusive
  st_node_t
  st_trie_t
  st_policy_count
  st_policy_free_matches
  st_feed
  st_feed_parsed
  st_suggest
  st_free_suggestions
  st_free_token_array
  st_free_diff_result
  st_blacklist_add_netpattern
  st_is_netpattern_blacklisted
  st_save
  st_load
  st_classify
  st_classify_token
  st_validate_netpattern
  sg_eval
  sg_eval_size_hint
  sg_gate_set_violation_config
  sg_subcmd_result_t
  sg_gate_set_anomaly_update_on_non_anomaly
  sg_gate_add_rule
  sg_gate_remove_rule
  sg_gate_add_deny_rule
  sg_gate_remove_deny_rule
  sg_gate_rule_count
  sg_gate_add_allow_cpl_rule
  sg_gate_remove_allow_cpl_rule
  sg_gate_add_deny_cpl_rule
  sg_gate_remove_deny_cpl_rule
  sg_gate_suggestion_token_variants_at
  sg_anomaly_model_new_ex
  sg_anomaly_model_total_uni
  sg_anomaly_model_total_bi
  sg_anomaly_model_total_tri
  sg_anomaly_model_total_quad
  sg_anomaly_model_uni_count
  sg_anomaly_model_unk_count
  sg_anomaly_model_kn_discount
  sg_anomaly_model_bi_count
  sg_anomaly_model_tri_count
  sg_anomaly_model_quad_count
  sg_anomaly_score_netseq
  sg_anomaly_update_netseq
  sg_anomaly_save
  sg_anomaly_load
  sg_anomaly_vocab_size
  sg_anomaly_total_uni
  sg_anomaly_total_bi
  sg_anomaly_total_tri
  sg_anomaly_total_quad
  sg_anomaly_uni_count
  sg_anomaly_unk_count
  sg_anomaly_kn_discount
  sg_anomaly_bi_count
  sg_anomaly_tri_count
  sg_anomaly_quad_count
  sg_anomaly_total_contexts
  sg_anomaly_has_observed_netseq
  sg_anomaly_reset
  token_type_t
  abstract_type_t
  path_category_t
  abstract_element_t
  abstracted_command_t
  runtime_context_t
  transform_type_t
  transformed_token_t
  transformed_command_t
  ngram_entropy
  permutation_entropy
  relative_entropy_ratio
  conditional_entropy
  permutation_conditional_entropy
  relative_conditional_entropy
  env_screener_status_t
  env_screener_scan
  env_screener_calculate_entropy
  env_screener_is_secret_pattern
  env_screener_is_whitelisted
  env_screener_recommended_capacity
  env_screener_get_whitelist_doc
  env_screener_combined_score
  env_screener_combined_name
  looks_like_path
  looks_like_base64
  check_secret_prefix
  shell_abstracted_destroy
  shell_abstracted_command_t
  shell_abstracted_command_free
  shell_abstract_command
  shell_get_abstracted
  shell_get_original
  shell_get_elements
  shell_get_element_by_abstract
  shell_get_element_at
  shell_expand_element
  shell_expand_all_elements
  shell_get_path_category
  shell_get_subcommand
  shell_copy_subcommand
  shell_command_has_features
  shell_interop_create
  shell_interop_destroy
  shell_interop_subcommand_str
  shell_interop_free_str
  shell_interop_features_str
  shell_interop_type_str
  shell_free_command_infos
  shell_has_dangerous_features
  shell_free_commands
  shell_has_features
  shell_get_feature_flags
  shell_free_transformed_command
  shell_free_transformed_commands
  shell_get_dfa_input
  shell_has_transformations
  shell_parse_depgraph
  shell_transformed_command_get_dfa_input
  shell_transformed_commands_free
  shell_extract_netargv_sequence
  shell_interop_subcommand_type
  shell_interop_subcommand_features
  shell_interop_subcommand_start
  shell_interop_subcommand_len
  shell_interop_string_free
  shell_interop_feature_flags_to_string
  shell_interop_subcommand_type_to_string
  shell_abstract_command_get_text
  shell_transformed_command_get_text
  shell_dep_validate_result_t
  shell_dep_validate
  SG_MAX_SUBCMD_RESULTS
  subcmd_count
  subcmd_truncated
  cmd_node_index)

foreach(header IN LISTS public_headers)
  file(READ "${header}" contents)
  if(header MATCHES "/shellgate.h$")
    foreach(identifier substitution_consumer_index group_parent_index
        group_depth group_kinds backgrounded pipeline_time_mode)
      if(contents MATCHES "(^|[^A-Za-z0-9_])${identifier}([^A-Za-z0-9_]|$)")
        message(FATAL_ERROR "graph projection ${identifier} in ${header}")
      endif()
    endforeach()
  endif()
  foreach(identifier IN LISTS removed_identifiers)
    if(contents MATCHES "(^|[^A-Za-z0-9_])${identifier}([^A-Za-z0-9_]|$)")
      message(FATAL_ERROR "removed public API identifier ${identifier} in ${header}")
    endif()
  endforeach()
  if(contents MATCHES "(^|[^A-Za-z0-9_])TOKEN_")
    message(FATAL_ERROR "unprefixed token enum in ${header}")
  endif()
  if(contents MATCHES "(^|[^A-Za-z0-9_])(ABSTRACT_|TRANSFORM_|PATH_(ROOT|ETC|VAR|USR|HOME|TMP|PROC|SYS|DEV|OPT|SRV|RUN|SYSROOT|BOOT|MNT|MEDIA|SNAPSHOT|OTHER))")
    message(FATAL_ERROR "unprefixed Shellsplit enum in ${header}")
  endif()
endforeach()

# Forwarding helpers must not reappear behind the public headers either.
file(GLOB internal_sources
  "${SHELLCLAVE_SOURCE_DIR}/shellgate/src/*.[ch]"
  "${SHELLCLAVE_SOURCE_DIR}/shellsplit/src/*.[ch]"
  "${SHELLCLAVE_SOURCE_DIR}/shelltype/src/*.[ch]")
foreach(source IN LISTS internal_sources)
  file(READ "${source}" contents)
  foreach(identifier shell_tokenizer_word_has_glob
      shell_tokenizer_word_parameter_name st_token_classify_bytes
      st_policy_ctx_intern policy_visit_matches
      source_range_is_list_continuation_trivia redirect_list_precedes_group
      range_pipeline_prefix dep_pipeline_member_limit_for_range
      dep_pipeline_member_limit_for_group is_glob_pattern
      trie_type_supports_param control_token_is rendered_word_length
      fast_redirection_consumes_next netpattern_encode_impl control_syntax_scan
      sg_anomaly_netseq_count shell_source_redirect_word_has_dynamic_path_syntax
      dep_token_parse_assignment_word)
    if(contents MATCHES "(^|[^A-Za-z0-9_])${identifier}([^A-Za-z0-9_]|$)")
      message(FATAL_ERROR "removed forwarding helper ${identifier} in ${source}")
    endif()
  endforeach()
endforeach()
