/* Private shell_depgraph.c implementation; included at its dependency point. */

/* Predicate observations and graph attachment share this translation unit
 * with execution-state lookup and outcome selection. Consume existing word
 * resolution results after ordered substitutions; paths can remain unresolved.
 */
#define FILE_FLAG(kind, name, ordinal, spelling, alias)                        \
  | SHELL_DEP_EDGE_FLAG_FILE_TEST_##kind
enum { DEP_FILE_TEST_FLAGS = 0 SHELL_FILE_PREDICATES(FILE_FLAG) };
#undef FILE_FLAG
_Static_assert((DEP_FILE_TEST_FLAGS & ~UINT16_MAX) == 0,
               "filesystem predicates fit graph edge flags");

/* The operand and optional resolved value borrow source/resolver storage.
 * Predicate checks use the command's CWD and never imply content reads.
 * Record active path uncertainty even if output capacity omits the relation. */
static SHELL_NONNULL(1, 5, 9) void dep_add_file_test(
    shell_dep_graph_t *graph, uint32_t max_nodes, uint32_t max_edges,
    uint32_t owner, const dep_token_t *source,
    const shell_dep_word_value_t *value, bool dynamic, unsigned tests,
    uint8_t *unresolved_paths) {
  if (value && value->resolved && value->count == 1 && !value->first_length)
    return;
  bool resolved =
      value && value->resolved && value->count == 1 && value->first_length;
  if (resolved && value->first_length > UINT32_MAX) {
    graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    return;
  }
  /* Argument callbacks may return embedded NUL bytes. Such a value is not a
   * representable filesystem pathname; retain uncertainty rather than store
   * it as a resolved FILE path. Conditional callbacks already reject NUL. */
  if (resolved && memchr(value->first, '\0', value->first_length)) {
    resolved = false;
    dynamic = true;
  }
  if (dynamic && !resolved)
    unresolved_paths[owner] = true;
  if (graph->node_count >= max_nodes || graph->edge_count >= max_edges) {
    graph->status |= SHELL_DEP_STATUS_TRUNCATED;
    return;
  }
  uint32_t document = graph->node_count++;
  graph->nodes[document].type = SHELL_NODE_DOC;
  graph->nodes[document].doc =
      (shell_dep_doc_t){.kind = SHELL_DOC_FILE,
                        .path = source->start,
                        .path_len = source->len,
                        .flags = dynamic ? SHELL_DEP_DOC_FLAG_DYNAMIC_NAME : 0};
  shell_dep_doc_t *doc = &graph->nodes[document].doc;
  const shell_dep_cmd_t *command = &graph->nodes[owner].cmd;
  doc->cwd_known = command->cwd_known;
  doc->cwd_offset = command->cwd_known ? command->cwd_offset : 0;
  doc->cwd_absolute = command->cwd_absolute;
  if (resolved) {
    doc->value = value->first;
    doc->value_len = (uint32_t)value->first_length;
    doc->flags = SHELL_DEP_DOC_FLAG_RESOLVED_PATH;
  }
  shell_dep_edge_t *edge = &graph->edges[graph->edge_count++];
  dep_init_edge(edge, owner, document, SHELL_EDGE_FILE_TEST, SHELL_DIR_FORWARD,
                SHELL_DEP_FD_NONE, SHELL_DEP_FD_NONE);
  edge->flags = (uint16_t)tests;
}

typedef struct {
  shell_dep_graph_t *graph;
  uint32_t max_nodes, max_edges, owner;
  const shell_dep_word_value_t *const *values;
  uint8_t *unresolved_paths;
} dep_test_file_context_t;

static SHELL_NONNULL(1, 3) void dep_observe_test_file(
    const shell_test_value_t *word, unsigned tests, void *context) {
  dep_test_file_context_t *ctx = context;
  if (word->known && !word->value_length)
    return;
  dep_token_t source = {word->source, (uint32_t)word->length};
  const shell_dep_word_value_t *value = ctx->values[word->token];
  bool dynamic =
      shell_source_argument_has_dynamic_syntax(word->source, word->length);
  dep_add_file_test(ctx->graph, ctx->max_nodes, ctx->max_edges, ctx->owner,
                    &source, value, dynamic, tests, ctx->unresolved_paths);
}

/* Keep this attachment in the construction loop even in large graph builds;
 * extraction must not introduce an out-of-line call on each first operand. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((always_inline))
#endif
static inline SHELL_NONNULL(1, 2, 6) void dep_observe_conditional_file(
    shell_dep_graph_t *graph, const dep_parse_context_t *context,
    uint32_t max_nodes, uint32_t max_edges, uint32_t owner,
    const dep_token_t *operand, const shell_dep_word_value_t *value,
    shell_conditional_predicate_t predicate) {
  if (!shell_conditional_file(predicate) ||
      !dep_owner_phase_active(context, owner, DEP_SNAPSHOT_BODY_WORD,
                              UINT32_MAX))
    return;
  bool empty = false;
  bool static_empty =
      shell_conditional_static_empty(operand->start, operand->len, &empty) &&
      empty;
  if (!static_empty)
    dep_add_file_test(
        graph, max_nodes, max_edges, owner, operand, value,
        shell_conditional_word_dynamic(operand->start, operand->len),
        SHELL_DEP_EDGE_FLAG_FILE_TEST_EXISTS
            << (predicate - SHELL_CONDITIONAL_FILE_EXISTS),
        context->unresolved_paths);
}

typedef struct {
  dep_route_state_t *state;
  dep_route_journal_t *journal;
  const dep_owner_routes_t *baseline;
  const dep_prefix_assignment_set_t *prefixes;
  bool impossible;
} dep_test_context_t;

static SHELL_NONNULL(1, 3) unsigned dep_test_lookup(const char *name,
                                                    size_t length,
                                                    void *context) {
  dep_test_context_t *test = context;
  dep_token_t word = {name, (uint32_t)length};
  unsigned result = 0;
  dep_route_iterator_t iterator = dep_route_iterator(test->state);
  uint32_t root;
  while (dep_route_next(&iterator, test->journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    unsigned prefix =
        test->prefixes
            ? dep_prefix_assignment_visible(test->prefixes, &word, &one,
                                            test->journal, test->baseline)
            : SHELL_TEST_FALSE;
    if (prefix & SHELL_TEST_TRUE)
      result |= SHELL_TEST_TRUE;
    if (prefix & SHELL_TEST_FALSE)
      result |= dep_presence_root(root, test->journal, test->baseline,
                                  (dep_fd_ref_t){.name = name,
                                                 .name_len = (uint32_t)length,
                                                 .value = SHELL_DEP_FD_NAMED});
  }
  return result ? result : 3u;
}

static SHELL_NONNULL(1, 4) bool dep_test_assume(const char *name, size_t length,
                                                unsigned presence,
                                                void *context) {
  dep_test_context_t *test = context;
  if (!(dep_test_lookup(name, length, test) & presence)) {
    test->impossible = true;
    return true;
  }
  dep_token_t word = {name, (uint32_t)length};
  if (test->prefixes && dep_prefix_assignment_visible(
                            test->prefixes, &word, test->state, test->journal,
                            test->baseline) == SHELL_TEST_TRUE)
    return true;
  bool possible;
  bool stored = dep_presence_assume(test->state, test->journal, test->baseline,
                                    (dep_fd_ref_t){.name = name,
                                                   .name_len = (uint32_t)length,
                                                   .value = SHELL_DEP_FD_NAMED},
                                    presence, &possible);
  test->impossible |= !possible;
  return stored;
}

static SHELL_NONNULL(1, 2, 3, 4, 5, 6, 8) bool dep_test_select(
    const dep_snapshot_source_t *source, const dep_route_state_t *input,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline,
    dep_route_state_t *output, bool *ready, unsigned desired, bool *failed) {
  *output = (dep_route_state_t){0};
  *ready = false;
  dep_route_state_t entries = *input;
  if (!dep_prefixes_resolve(&entries, &source->prefix_assignments, journal,
                            baseline))
    return false;
  dep_route_iterator_t iterator = dep_route_iterator(&entries);
  uint32_t root;
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_test_context_t test = {.state = &one,
                               .journal = journal,
                               .baseline = baseline,
                               .prefixes = &source->prefix_assignments};
    unsigned result = shell_test_evaluate(source->test, dep_test_lookup, &test);
    if (!(result & (desired == SHELL_TEST_FALSE
                        ? SHELL_TEST_FALSE | SHELL_TEST_ERROR_RESULT
                        : desired)))
      continue;
    if (!shell_test_require(source->test, desired, dep_test_lookup,
                            dep_test_assume, &test)) {
      *failed = true;
      return false;
    }
    if (test.impossible)
      continue;
    if (!*ready)
      *output = one;
    else if (!dep_route_state_add_root(output, journal, one.root))
      return false;
    *ready = true;
  }
  output->correlated |= input->correlated;
  output->correlated |= entries.correlated;
  output->truncated |= input->truncated;
  return true;
}

static SHELL_NONNULL(1, 2, 3, 5) shell_dep_error_t
    dep_test_body_status(const shell_dep_graph_t *graph,
                         const dep_subgraph_streams_t *streams,
                         const dep_parse_context_t *context, uint32_t owner,
                         uint8_t *status) {
  const dep_snapshot_source_t *source =
      &context->workspace
           ->snapshot_sources[context->snapshot->prepared_source[owner]];
  uint32_t table;
  shell_dep_error_t error =
      dep_snapshot_phase_table(graph, streams, context, owner, UINT32_MAX,
                               DEP_SNAPSHOT_BODY_WORD, &table);
  if (error != SHELL_DEP_OK)
    return error;
  dep_route_state_t state =
      dep_snapshot_alternatives(&context->workspace->snapshot_tables[table]);
  const dep_owner_routes_t *baseline =
      &context->workspace->snapshot_tables[context->snapshot->persistent[0]]
           .routes;
  unsigned result = 0;
  dep_route_iterator_t iterator = dep_route_iterator(&state);
  uint32_t root;
  while (
      dep_route_next(&iterator, &context->workspace->snapshot_journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    for (unsigned wanted = SHELL_TEST_FALSE; wanted <= SHELL_TEST_TRUE;
         ++wanted) {
      dep_route_state_t selected;
      bool ready, failed = false;
      if (!dep_test_select(source, &one, &context->workspace->snapshot_journal,
                           baseline, &selected, &ready, wanted, &failed))
        return SHELL_DEP_ETRUNC;
      if (ready)
        result |= wanted;
    }
  }
  *status = (result & SHELL_TEST_TRUE ? DEP_STATUS_MAY_SUCCEED : 0) |
            (result & (SHELL_TEST_FALSE | SHELL_TEST_ERROR_RESULT)
                 ? DEP_STATUS_MAY_FAIL
                 : 0);
  return SHELL_DEP_OK;
}
