/* Private shell_depgraph.c implementation, included after word expansion.
 * Conditional primaries share the test program's state facts. Ordered branch
 * traversal owns expansion reachability; unknown short-circuit decisions use
 * the existing borrowed process guards to preserve possible descriptor effects.
 * Scanner expansion-stop flags record possibilities, not proved runtime
 * failures. These flags alone leave later operands possible under the bounded
 * expansion model.
 */

typedef struct {
  shell_dep_graph_t *graph;
  uint32_t max_nodes, max_edges, cwd_size;
  dep_subgraph_streams_t *streams;
  const char *cwd;
  const shell_dep_limits_t *limits;
  uint32_t depth, owner;
  const dep_parse_context_t *context;
  const shell_conditional_t *condition;
  shell_test_program_t *program;
} dep_condition_context_t;

/* Completion follows the last primary in this subtree, including skipped
 * primaries. Carry its parsed boundary through the existing traversal so guard
 * release precedes later operands without rescanning or reordering events. */
typedef struct {
  uint32_t end;
  uint8_t status;
} dep_condition_result_t;

static SHELL_NONNULL(1, 2) const dep_process_guard_t *dep_condition_guard(
    dep_condition_context_t *ctx, const char *source,
    const dep_process_guard_t *parent) {
  dep_process_route_map_t *map = ctx->context->process_routes;
  const dep_process_guard_t *found = dep_process_guard_find(map, source);
  if (found)
    return found;
  uint32_t candidate = map->guard_count + 1, match = 0;
  map->guard_root =
      dep_index_insert(map->guard_index, map->guard_root, candidate,
                       sizeof(map->guards) / sizeof(map->guards[0]),
                       dep_process_guard_compare, map, source, &match);
  if (!match)
    return NULL;
  map->guards[map->guard_count++] =
      (dep_process_guard_t){.source = source,
                            .parent = parent,
                            .depth = parent ? parent->depth + 1 : 1};
  return &map->guards[match - 1];
}

static SHELL_NONNULL(1, 5) shell_dep_error_t
    dep_evaluate_condition(dep_condition_context_t *ctx, uint16_t index,
                           bool active, const dep_process_guard_t *guard,
                           dep_condition_result_t *result) {
  const shell_condition_node_t *node = &ctx->condition->nodes[index];
  shell_dep_error_t error;
  if (node->operation != SHELL_CONDITION_PRIMARY) {
    dep_condition_result_t left;
    error = dep_evaluate_condition(ctx, node->left, active, guard, &left);
    if (error != SHELL_DEP_OK)
      return error;
    if (node->operation == SHELL_CONDITION_NOT) {
      result->end = left.end;
      result->status =
          ((left.status & DEP_STATUS_MAY_SUCCEED) ? DEP_STATUS_MAY_FAIL : 0) |
          ((left.status & DEP_STATUS_MAY_FAIL) ? DEP_STATUS_MAY_SUCCEED : 0);
      return SHELL_DEP_OK;
    }
    bool executes = node->operation == SHELL_CONDITION_AND
                        ? (left.status & DEP_STATUS_MAY_SUCCEED) != 0
                        : (left.status & DEP_STATUS_MAY_FAIL) != 0;
    const dep_process_guard_t *right_guard = guard;
    bool conditional = active && executes && left.status == DEP_STATUS_EITHER;
    if (conditional) {
      uint16_t first = node->right;
      while (ctx->condition->nodes[first].operation != SHELL_CONDITION_PRIMARY)
        first = ctx->condition->nodes[first].left;
      right_guard = dep_condition_guard(
          ctx, ctx->context->cmd + ctx->condition->nodes[first].primary.content,
          guard);
      if (!right_guard)
        return SHELL_DEP_ETRUNC;
    }
    dep_condition_result_t right;
    error = dep_evaluate_condition(ctx, node->right, active && executes,
                                   right_guard, &right);
    if (error != SHELL_DEP_OK)
      return error;
    result->end = right.end;
    result->status =
        node->operation == SHELL_CONDITION_AND
            ? (left.status & DEP_STATUS_MAY_FAIL) |
                  ((left.status & DEP_STATUS_MAY_SUCCEED) ? right.status : 0)
            : (left.status & DEP_STATUS_MAY_SUCCEED) |
                  ((left.status & DEP_STATUS_MAY_FAIL) ? right.status : 0);
    if (conditional) {
      error = dep_complete_substitution(ctx->graph, ctx->streams, ctx->context,
                                        ctx->owner, UINT32_MAX, result->end,
                                        DEP_SNAPSHOT_BODY_WORD, false,
                                        DEP_EXPANSION_INCOMING, NULL, guard);
      if (error != SHELL_DEP_OK)
        return error;
    }

  } else {
    const shell_conditional_primary_t *primary = &node->primary;
    result->end = (uint32_t)primary->end;
    shell_conditional_value_t values[2] = {0};
    dep_file_comparison_operand_t operands[2] = {0};
    for (unsigned i = 0; i < primary->operand_count; ++i) {
      operands[i].source =
          (dep_token_t){ctx->context->cmd + primary->operands[i],
                        (uint32_t)primary->operand_lengths[i]};
      bool reached =
          active && dep_owner_phase_active(ctx->context, ctx->owner,
                                           DEP_SNAPSHOT_BODY_WORD, UINT32_MAX);
      if (reached && primary->predicate != SHELL_CONDITIONAL_VARIABLE_SET) {
        error = dep_resolve_word(ctx->graph, ctx->context, &operands[i].source,
                                 ctx->cwd, ctx->owner,
                                 SHELL_EXPAND_WORD_CONDITIONAL, true,
                                 UINT32_MAX, &operands[i].value);
        if (error != SHELL_DEP_OK)
          return error;
        const shell_dep_word_value_t *value = operands[i].value;
        operands[i].dynamic =
            value ? value->dynamic
                  : shell_conditional_word_dynamic(operands[i].source.start,
                                                   operands[i].source.len);
        if (value && value->resolved)
          values[i] = (shell_conditional_value_t){value->first,
                                                  value->first_length, true};
        if ((!value || !value->resolved) && operands[i].dynamic)
          ctx->graph->nodes[ctx->owner].cmd.conditional_unresolved = true;
      }
      error = dep_connect_expansions_kind(
          ctx->graph, ctx->max_nodes, ctx->max_edges, ctx->cwd_size,
          ctx->streams, &operands[i].source, ctx->cwd, ctx->limits, ctx->depth,
          ctx->context, ctx->owner, UINT32_MAX, DEP_SNAPSHOT_BODY_WORD,
          ctx->owner, DEP_SUBST_SHELL_WORD, false, !reached, guard);
      if (error != SHELL_DEP_OK)
        return error;
    }
    if (active && dep_owner_phase_active(ctx->context, ctx->owner,
                                         DEP_SNAPSHOT_BODY_WORD, UINT32_MAX)) {
      if (primary->predicate >= SHELL_CONDITIONAL_FILE_NEWER &&
          primary->predicate <= SHELL_CONDITIONAL_FILE_SAME) {
        for (unsigned i = 0; i < 2; ++i) {
          if (values[i].known)
            operands[i].empty = values[i].length == 0;
          else if (!operands[i].dynamic) {
            bool static_empty;
            operands[i].empty = shell_conditional_static_empty(
                                    operands[i].source.start,
                                    operands[i].source.len, &static_empty) &&
                                static_empty;
          }
        }
        dep_add_file_comparison(
            ctx->graph, ctx->max_nodes, ctx->max_edges, ctx->owner, operands,
            SHELL_FILE_COMPARE_NEWER
                << (primary->predicate - SHELL_CONDITIONAL_FILE_NEWER),
            ctx->context->unresolved_paths);
      } else
        dep_observe_conditional_file(ctx->graph, ctx->context, ctx->max_nodes,
                                     ctx->max_edges, ctx->owner,
                                     &operands[0].source, operands[0].value,
                                     primary->predicate);
    }
    bool truth = false;
    bool known =
        shell_conditional_evaluate(ctx->context->cmd, primary, values, &truth);
    shell_test_set_condition_result(ctx->program, index, known, truth);
    if (shell_source_scratch_exhausted())
      return SHELL_DEP_ETRUNC;
    if (primary->predicate == SHELL_CONDITIONAL_VARIABLE_SET)
      return dep_test_body_status_at(ctx->graph, ctx->streams, ctx->context,
                                     ctx->owner, index, true, &result->status);
    result->status = known
                         ? truth ? DEP_STATUS_MAY_SUCCEED : DEP_STATUS_MAY_FAIL
                         : DEP_STATUS_EITHER;
  }
  return SHELL_DEP_OK;
}
