/* Private shell_depgraph.c implementation; included at its dependency point. */

/* Return every predefined capability still possible at this execution point.
 * Successful whole-variable unsets record a compact registry mask in the same
 * immutable version as descriptor bindings. Unlike descriptor-orphan state,
 * these capabilities are inherited by recursive shells. Keeping alternatives
 * separate makes conditional unsets conservative without scanning variables. */
static SHELL_NONNULL(2, 3, 4) unsigned dep_variable_properties(
    uint8_t variable, const dep_route_state_t *state,
    const dep_route_journal_t *journal, const dep_owner_routes_t *baseline) {
  unsigned initial = shell_builtin_variable_index_properties(variable);
  if (!(initial & SHELL_VARIABLE_DESPECIALIZES_ON_UNSET))
    return initial;
  unsigned properties = 0;
  uint32_t word = (variable - 1u) / 32u;
  uint32_t bit = UINT32_C(1) << ((variable - 1u) % 32u);
  dep_route_iterator_t versions = dep_route_iterator(state);
  uint32_t root;
  while (dep_route_next(&versions, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_set_t marker = dep_variable_state(&one, journal, baseline);
    if (!(marker.routes[word].value & bit))
      properties |= initial;
  }
  return properties;
}

static SHELL_NONNULL(1, 2) bool dep_route_state_store_access(
    dep_route_state_t *state, dep_route_journal_t *changes, dep_fd_ref_t fd,
    dep_fd_access_t access, dep_route_set_t routes);

/* Two registry words each for definite and possible despecialization. The
 * marker is analytic state, independent of scalar values and presence epochs.
 * state contains one execution version. Read the positional snapshot directly;
 * a route union would deduplicate equal words and lose their mask positions. */
static SHELL_NONNULL(1, 2, 3) dep_route_set_t
    dep_variable_state(const dep_route_state_t *state,
                       const dep_route_journal_t *journal,
                       const dep_owner_routes_t *baseline) {
  (void)baseline;
  const dep_route_change_t *entry = dep_route_state_change(
      state, journal, dep_fd_numeric(DEP_VARIABLE_STATE_EVENT),
      DEP_FD_ACCESS_EFFECT_STATE);
  dep_route_set_t marker = {0};
  if (entry)
    marker = journal->snapshots[entry->snapshot - 1];
  else {
    marker.count = 4;
    for (unsigned i = 0; i < 4; ++i)
      marker.routes[i] = (dep_fd_route_t){DEP_ROUTE_INHERITED, 0};
  }
  return marker;
}

/* Resolve only requested resettable assignment restrictions, retaining both
 * versions when an opaque unset may have removed one. No variable/source
 * inventory is traversed, and ordinary writes take the unchanged fast path. */
static SHELL_NONNULL(1, 2, 3) bool dep_variable_resolve(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, uint8_t variable) {
  unsigned initial = shell_builtin_variable_index_properties(variable);
  if ((initial &
       (SHELL_VARIABLE_NOASSIGN | SHELL_VARIABLE_DESPECIALIZES_ON_UNSET)) !=
      (SHELL_VARIABLE_NOASSIGN | SHELL_VARIABLE_DESPECIALIZES_ON_UNSET))
    return true;
  unsigned word = (variable - 1u) / 32u;
  uint32_t bit = UINT32_C(1) << ((variable - 1u) % 32u);
  dep_route_state_t result = {0};
  dep_route_iterator_t versions = dep_route_iterator(state);
  uint32_t root;
  bool ready = false, split = false;
  while (dep_route_next(&versions, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_set_t marker = dep_variable_state(&one, journal, baseline);
    bool uncertain = !(marker.routes[word].value & bit) &&
                     (marker.routes[word + 2].value & bit);
    for (unsigned branch = 0; branch < (uncertain ? 2u : 1u); ++branch) {
      dep_route_state_t selected = one;
      if (uncertain) {
        dep_route_set_t assumed = marker;
        if (branch)
          assumed.routes[word].value |= bit;
        else
          assumed.routes[word + 2].value &= ~bit;
        if (!dep_route_state_store_access(
                &selected, journal, dep_fd_numeric(DEP_VARIABLE_STATE_EVENT),
                DEP_FD_ACCESS_EFFECT_STATE, assumed))
          return false;
        split = true;
      }
      if (!ready)
        result = selected;
      else if (!dep_route_state_add_root(&result, journal, selected.root))
        return false;
      ready = true;
    }
  }
  dep_route_state_inherit(&result, state);
  result.correlated |= split;
  *state = result;
  return true;
}

static SHELL_NONNULL(1, 2, 3, 4) bool dep_prefixes_resolve(
    dep_route_state_t *state, const dep_prefix_assignment_set_t *prefixes,
    dep_route_journal_t *journal, const dep_owner_routes_t *baseline) {
  for (uint32_t i = 0; i < prefixes->count; ++i)
    if (!dep_variable_resolve(state, journal, baseline,
                              prefixes->names[i].variable))
      return false;
  return true;
}

static SHELL_NONNULL(2, 3, 4) shell_builtin_variable_t
    dep_variable_classification(uint8_t variable,
                                const dep_route_state_t *state,
                                const dep_route_journal_t *journal,
                                const dep_owner_routes_t *baseline) {
  unsigned properties =
      dep_variable_properties(variable, state, journal, baseline);
  if (properties & SHELL_VARIABLE_INTEGER)
    return SHELL_BUILTIN_VARIABLE_ARITHMETIC;
  if (properties & SHELL_VARIABLE_FROZEN)
    return SHELL_BUILTIN_VARIABLE_FROZEN;
  if (properties & SHELL_VARIABLE_NOASSIGN)
    return SHELL_BUILTIN_VARIABLE_NOASSIGN;
  return properties & SHELL_VARIABLE_READONLY ? SHELL_BUILTIN_VARIABLE_READONLY
                                              : SHELL_BUILTIN_VARIABLE_STATIC;
}

/* The lexical prefix index includes attempted assignments. Visibility depends
 * on whether this execution version can actually install that binding. */
static SHELL_NONNULL(1, 2, 3, 4, 5) unsigned dep_prefix_assignment_visible(
    const dep_prefix_assignment_set_t *assignments, const dep_token_t *word,
    const dep_route_state_t *state, const dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline) {
  uint32_t root = assignments->root;
  while (root) {
    int order =
        dep_prefix_assignment_compare_word(assignments, root - 1, word, false);
    if (!order) {
      uint8_t variable = assignments->names[root - 1].variable;
      unsigned properties =
          dep_variable_properties(variable, state, journal, baseline);
      if (properties & SHELL_VARIABLE_READONLY)
        return SHELL_TEST_FALSE;
      if (!(properties & SHELL_VARIABLE_NOASSIGN))
        return SHELL_TEST_TRUE;
      if (!(properties & SHELL_VARIABLE_DESPECIALIZES_ON_UNSET))
        return SHELL_TEST_FALSE;
      dep_route_set_t marker = dep_variable_state(state, journal, baseline);
      unsigned word = (variable - 1u) / 32u;
      uint32_t bit = UINT32_C(1) << ((variable - 1u) % 32u);
      return marker.routes[word + 2].value & bit
                 ? SHELL_TEST_FALSE | SHELL_TEST_TRUE
                 : SHELL_TEST_FALSE;
    }
    root = order > 0 ? assignments->index[root - 1].left
                     : assignments->index[root - 1].right;
  }
  return SHELL_TEST_FALSE;
}

static SHELL_NONNULL(1, 2, 3, 4) bool dep_effects_supported(
    const dep_named_mutations_t *mutations, const dep_route_state_t *state,
    const dep_route_journal_t *journal, const dep_owner_routes_t *baseline) {
  for (uint32_t i = 0; i < mutations->count; i++) {
    const dep_named_effect_t *effect = &mutations->effects[i];
    if (effect->variable && effect->prohibited_properties &&
        (dep_variable_properties(effect->variable, state, journal, baseline) &
         effect->prohibited_properties))
      return false;
  }
  return true;
}
