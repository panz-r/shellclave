/* Private shell_depgraph.c implementation; included at its dependency point. */

/* Presence is a scalar fact. Epochs let opaque writes invalidate all names
 * without traversing the observation inventory; subsequent writes override
 * that epoch locally. Parent maps are borrowed lazily at recursive entry. */
static SHELL_NONNULL(2, 3) unsigned dep_presence_root(
    uint32_t root, const dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, dep_fd_ref_t name) {
  const dep_route_change_t *epoch = dep_route_root_change(
      root, journal, dep_fd_numeric(0), DEP_FD_ACCESS_VARIABLE_PRESENCE);
  uint32_t generation =
      epoch ? journal->snapshots[epoch->snapshot - 1].routes[0].value : 0;
  const dep_route_change_t *entry = dep_route_root_change(
      root, journal, name, DEP_FD_ACCESS_VARIABLE_PRESENCE);
  if (entry) {
    dep_fd_route_t fact = journal->snapshots[entry->snapshot - 1].routes[0];
    if (fact.value == generation)
      return fact.kind == DEP_ROUTE_INHERITED     ? SHELL_TEST_TRUE
             : fact.kind == DEP_ROUTE_UNAVAILABLE ? SHELL_TEST_FALSE
                                                  : 3u;
  }
  if (epoch)
    return 3u;
  const dep_fd_imports_t *imports = baseline->scalar_imports;
  if (imports && imports->scalar_journal) {
    const dep_route_change_t *paths =
        dep_route_root_change(root, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
                              DEP_FD_ACCESS_READ_ARGUMENT);
    if (paths) {
      const dep_route_set_t *versions =
          &journal->snapshots[paths->snapshot - 1];
      unsigned result = 0;
      for (uint32_t i = 0; i < versions->count; ++i) {
        uint32_t path = versions->routes[i].value;
        if (imports->path_assignment_only[path] &&
            dep_assignment_precedes(
                imports->assignment_source, imports->assignment_command, name,
                imports->assignment_position, imports->path_scalar_root[path],
                imports->scalar_journal, imports->scalar_baseline))
          result |= SHELL_TEST_TRUE;
        else
          result |= dep_presence_root(imports->path_scalar_root[path],
                                      imports->scalar_journal,
                                      imports->scalar_baseline, name);
      }
      return result ? result : 3u;
    }
  }
  uint8_t variable = shell_builtin_name_index(name.name, name.name_len);
  if (variable) {
    const char *spelling = shell_builtin_variable_index_name(variable);
    if (!strcmp(spelling, "LC_ALL") || !strcmp(spelling, "UID") ||
        !strcmp(spelling, "EUID") || !strcmp(spelling, "PPID") ||
        !strcmp(spelling, "SHELLOPTS") || !strcmp(spelling, "BASHOPTS"))
      return SHELL_TEST_TRUE;
    if (shell_builtin_variable_index_properties(variable) &
        SHELL_VARIABLE_FROZEN)
      return SHELL_TEST_FALSE;
  }
  return 3u;
}

static SHELL_NONNULL(1,
                     3) int dep_presence_writer_compare(const void *context,
                                                        uint32_t index,
                                                        const void *pending) {
  const dep_route_journal_t *journal = context;
  const dep_presence_writer_t *a = &journal->presence_writers[index],
                              *b = pending;
  if (a->operation != b->operation)
    return (uintptr_t)a->operation < (uintptr_t)b->operation ? -1 : 1;
  return dep_fd_ref_compare(a->name, b->name);
}

static SHELL_NONNULL(1, 3) uint32_t
    dep_presence_writer(dep_route_journal_t *journal, dep_fd_ref_t name,
                        const char *operation) {
  dep_presence_writer_t key = {.operation = operation, .name = name};
  uint32_t candidate = journal->presence_writer_count + 1, match = 0;
  journal->presence_writer_root = dep_index_insert(
      journal->presence_writer_index, journal->presence_writer_root, candidate,
      DEP_PRESENCE_WRITER_CAPACITY, dep_presence_writer_compare, journal, &key,
      &match);
  if (match == candidate)
    journal->presence_writers[journal->presence_writer_count++] = key;
  return match;
}

static SHELL_NONNULL(1, 2) bool dep_presence_store_kind(
    dep_route_state_t *state, dep_route_journal_t *journal, dep_fd_ref_t name,
    unsigned presence, const char *operation) {
  if (!journal->read_observations.presence)
    return true;
  /* Root-inventory names outlive recursive program scratch and its views. */
  name = dep_read_observation_find(&journal->read_observations, name)->fd;
  uint32_t stamp =
      operation ? dep_presence_writer(journal, name, operation) : 0;
  if (operation && !stamp)
    return false;
  dep_route_state_t result = {0};
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  bool ready = false;
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    const dep_route_change_t *epoch = dep_route_root_change(
        root, journal, dep_fd_numeric(0), DEP_FD_ACCESS_VARIABLE_PRESENCE);
    uint32_t generation =
        epoch ? journal->snapshots[epoch->snapshot - 1].routes[0].value : 0;
    const dep_route_change_t *old = dep_route_root_change(
        root, journal, name, DEP_FD_ACCESS_VARIABLE_PRESENCE);
    const dep_route_set_t *previous =
        old ? &journal->snapshots[old->snapshot - 1] : NULL;
    uint32_t identity = stamp;
    if (!operation && previous && previous->count > 1 &&
        previous->routes[0].value == generation)
      identity = previous->routes[1].value;
    dep_route_set_t fact = {.count = 2};
    fact.routes[0] =
        (dep_fd_route_t){presence == SHELL_TEST_TRUE    ? DEP_ROUTE_INHERITED
                         : presence == SHELL_TEST_FALSE ? DEP_ROUTE_UNAVAILABLE
                                                        : DEP_ROUTE_DYNAMIC,
                         generation};
    fact.routes[1] = (dep_fd_route_t){DEP_ROUTE_INHERITED, identity};
    if (!dep_route_state_append_one(&one, journal, name,
                                    DEP_FD_ACCESS_VARIABLE_PRESENCE, fact))
      return false;
    if (!ready)
      result = one;
    else if (!dep_route_state_add_root(&result, journal, one.root))
      return false;
    ready = true;
  }
  result.correlated |= state->correlated;
  result.truncated |= state->truncated;
  *state = result;
  return true;
}

static SHELL_NONNULL(1, 2, 5) bool dep_presence_store(
    dep_route_state_t *state, dep_route_journal_t *journal, dep_fd_ref_t name,
    unsigned presence, const char *operation) {
  return dep_presence_store_kind(state, journal, name, presence, operation);
}

/* Observe only an unchanged inherited scalar. Equal-valued writes carry a
 * distinct identity, so a child's assignment cannot constrain its parent. */
static SHELL_NONNULL(1, 2, 3, 6) bool dep_presence_assume(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline, dep_fd_ref_t name, unsigned presence,
    bool *possible) {
  name = dep_read_observation_find(&journal->read_observations, name)->fd;
  *possible =
      (dep_presence_root(state->root, journal, baseline, name) & presence) != 0;
  if (!*possible)
    return true;
  dep_route_state_t before = *state;
  if (!dep_presence_store_kind(state, journal, name, presence, NULL))
    return false;
  dep_route_set_t scope = dep_fd_raw_fact(&before, journal, baseline,
                                          dep_fd_numeric(SHELL_DEP_FD_NONE),
                                          DEP_FD_ACCESS_PRIVATE_SCOPE);
  if (!scope.count)
    return true;
  const dep_route_change_t *entry = dep_route_root_change(
      before.root, journal, name, DEP_FD_ACCESS_VARIABLE_PRESENCE);
  const dep_route_change_t *epoch = dep_route_root_change(
      before.root, journal, dep_fd_numeric(0), DEP_FD_ACCESS_VARIABLE_PRESENCE);
  if (scope.routes[0].value == UINT32_MAX) {
    /* Earlier assignment RHS commits are visible in this expansion overlay,
     * rather than in the parent's pre-command journal. They are not an
     * observation of the unchanged inherited binding. */
    const dep_fd_imports_t *imports = baseline->scalar_imports;
    const dep_route_change_t *paths = dep_route_root_change(
        before.root, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
        DEP_FD_ACCESS_READ_ARGUMENT);
    if (imports && paths) {
      const dep_route_set_t *versions =
          &journal->snapshots[paths->snapshot - 1];
      for (uint32_t i = 0; i < versions->count; ++i) {
        uint32_t path = versions->routes[i].value;
        if (imports->path_assignment_only[path] &&
            dep_assignment_precedes(
                imports->assignment_source, imports->assignment_command, name,
                imports->assignment_position, imports->path_scalar_root[path],
                imports->scalar_journal, imports->scalar_baseline))
          return true;
      }
    }
    const dep_route_set_t *fact =
        entry ? &journal->snapshots[entry->snapshot - 1] : NULL;
    if (!epoch && (!fact || fact->count < 2 || !fact->routes[1].value)) {
      dep_route_set_t observation = {0};
      dep_route_set_set(&observation,
                        (dep_fd_route_t){DEP_ROUTE_INHERITED, presence});
      return dep_observation_remember(state, journal, baseline, name,
                                      DEP_FD_ACCESS_VARIABLE_PRESENCE,
                                      observation);
    }
    return true;
  }
  dep_fd_ref_t event = dep_fd_numeric(scope.routes[0].value - 1);
  dep_route_set_t origin = dep_fd_raw_fact(&before, journal, baseline, event,
                                           DEP_FD_ACCESS_PRIVATE_ENTRY);
  dep_route_state_t parent = dep_route_state_single(origin.routes[0].value);
  const dep_route_change_t *parent_entry = dep_route_root_change(
      parent.root, journal, name, DEP_FD_ACCESS_VARIABLE_PRESENCE);
  const dep_route_change_t *parent_epoch = dep_route_root_change(
      parent.root, journal, dep_fd_numeric(0), DEP_FD_ACCESS_VARIABLE_PRESENCE);
  if ((entry ? entry->snapshot : 0) !=
          (parent_entry ? parent_entry->snapshot : 0) ||
      (epoch ? epoch->snapshot : 0) !=
          (parent_epoch ? parent_epoch->snapshot : 0))
    return true;
  if (!dep_presence_assume(&parent, journal, baseline, name, presence,
                           possible))
    return false;
  if (!*possible)
    return true;
  origin.routes[0].value = parent.root;
  return dep_route_state_store_access(state, journal, event,
                                      DEP_FD_ACCESS_PRIVATE_ENTRY, origin);
}

static SHELL_NONNULL(1, 2, 3, 5) bool dep_presence_clear(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_owner_routes_t *baseline,
    const dep_prefix_assignment_set_t *restored, const char *operation,
    uint32_t entry) {
  if (!journal->read_observations.presence)
    return true;
  uint32_t generation =
      dep_presence_writer(journal, dep_fd_numeric(0), operation);
  if (!generation)
    return false;
  dep_route_state_t result = {0};
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  bool ready = false;
  dep_route_state_t installed = dep_route_state_single(entry);
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_set_t epoch = {0};
    dep_route_set_set(&epoch, (dep_fd_route_t){DEP_ROUTE_DYNAMIC, generation});
    if (!dep_route_state_append_one(&one, journal, dep_fd_numeric(0),
                                    DEP_FD_ACCESS_VARIABLE_PRESENCE, epoch))
      return false;
    for (uint32_t i = 0; restored && i < restored->count; ++i) {
      dep_token_t prefix = {restored->names[i].start, restored->names[i].len};
      if (dep_prefix_assignment_visible(restored, &prefix, &installed, journal,
                                        baseline) != SHELL_TEST_TRUE)
        continue;
      dep_fd_ref_t name = {.name = restored->names[i].start,
                           .name_len = restored->names[i].len,
                           .value = SHELL_DEP_FD_NAMED};
      if (!(dep_read_observation(&journal->read_observations, name) &
            DEP_READ_OBSERVE_PRESENCE))
        continue;
      if (!dep_presence_store_kind(
              &one, journal, name,
              dep_presence_root(root, journal, baseline, name), NULL))
        return false;
    }
    if (!ready)
      result = one;
    else if (!dep_route_state_add_root(&result, journal, one.root))
      return false;
    ready = true;
  }
  result.correlated |= state->correlated;
  result.truncated |= state->truncated;
  *state = result;
  return true;
}
