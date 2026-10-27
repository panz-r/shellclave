/* Private shell_depgraph.c implementation; included at its dependency point. */

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
