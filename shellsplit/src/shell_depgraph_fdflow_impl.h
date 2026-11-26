/* Transfer functions of the descriptor dataflow analysis.
 *
 * Included once, by shell_depgraph.c, at this point of its single
 * translation unit, so its definitions inline as before.
 *
 * These interpret descriptor facts in the fact maps of
 * shell_depgraph_factmap_impl.h: per-descriptor occupancy partitioned by
 * low-interval case, lowest-free allocation (named descriptors, Bash saves,
 * process-substitution ends), redirection operations with their undo
 * registration and cleanup, joins of versions, the routes publication reads,
 * and the single forward pass over a redirect list that derives its
 * setup-failure outcomes. */

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
static SHELL_NONNULL(1) bool dep_test_domain_joins(
    dep_route_workspace_t *workspace);

bool shellsplit_test_route_state_contract(void *workspace, uint32_t count) {
  dep_route_journal_t *journal = &((dep_route_workspace_t *)workspace)->journal;
  dep_route_arena_reset(&((dep_route_workspace_t *)workspace)->route_arena);
  dep_route_journal_reset(journal,
                          &((dep_route_workspace_t *)workspace)->route_arena);
  dep_route_state_t state = {0}, preserved = {0};
  uint32_t roots[SHELL_DEP_MAX_NODES] = {0}, ordered[SHELL_DEP_MAX_NODES] = {0};
  uint32_t prefix = count / 2;
  for (uint32_t i = 1; i < count; i++) {
    dep_route_state_t one = {0};
    dep_route_set_t fact = {0};
    dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_INHERITED, i});
    if (!dep_route_state_append_one(&one, journal, dep_fd_numeric(3),
                                    DEP_FD_ACCESS_WRITE, fact))
      return false;
    roots[i] = one.root;
  }
  /* Zigzag valid root identities to exercise both AVL rotation directions. */
  for (uint32_t i = 1; i < count; i++) {
    ordered[i] = roots[(i & 1u) ? count - (i + 1) / 2 : i / 2];
    if (!dep_route_state_add_root(&state, journal, ordered[i]))
      return false;
    if (i + 1 == prefix)
      preserved = state;
  }
  uint32_t members = journal->arena->member_count,
           links = journal->arena->link_count;
  dep_route_iterator_t iterator = dep_route_iterator(&state);
  uint32_t root, seen = 0;
  while (dep_route_next(&iterator, journal, &root)) {
    if (root != (seen == 0 ? 0 : ordered[count - seen]) ||
        !dep_route_state_add_root(&state, journal, root))
      return false;
    seen++;
  }
  if (seen != count || members != journal->arena->member_count ||
      links != journal->arena->link_count)
    return false;
  iterator = dep_route_iterator(&preserved);
  seen = 0;
  while (dep_route_next(&iterator, journal, &root)) {
    if (root != (seen == 0 ? 0 : ordered[prefix - seen]))
      return false;
    seen++;
  }
  if (seen != prefix)
    return false;
  if (count == DEP_ROUTE_STATE_CAPACITY) {
    dep_route_state_t one = {0};
    dep_route_set_t fact = {0};
    dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_INHERITED, count});
    if (!dep_route_state_append_one(&one, journal, dep_fd_numeric(3),
                                    DEP_FD_ACCESS_WRITE, fact) ||
        dep_route_state_add_root(&state, journal, one.root) ||
        !state.truncated || dep_route_state_count(&state) != count)
      return false;
  }
  return dep_test_domain_joins(workspace);
}
#endif

/* A selected single execution version; ownership never comes from a concrete
 * capability baseline. Missing and explicitly empty sets both mean no ends. */
static SHELL_NONNULL(1, 2) uint32_t
    dep_process_owned_root(const dep_route_state_t *state,
                           const dep_route_journal_t *journal) {
  uint32_t change = dep_route_state_snapshot(state, journal,
                                             dep_fd_numeric(SHELL_DEP_FD_NONE),
                                             DEP_FD_ACCESS_PROCESS_OWNED);
  dep_route_set_t owned = change ? journal->arena->snapshots[change - 1]
                                 : (dep_route_set_t){.ready = true};
  return owned.count ? owned.routes[0].value : 0;
}

static SHELL_NONNULL(1, 2) bool dep_process_owned(
    const dep_route_state_t *state, const dep_route_journal_t *journal,
    dep_fd_ref_t fd) {
  return dep_route_root_snapshot(dep_process_owned_root(state, journal),
                                 journal, fd, DEP_FD_ACCESS_PROCESS_OWNED) != 0;
}

/* state contains one immutable execution version. Ownership is shell cleanup
 * metadata, not capability copying: dup/open/close do not transfer this set. */
static SHELL_NONNULL(1,
                     2) bool dep_process_owned_set(dep_route_state_t *state,
                                                   dep_route_journal_t *journal,
                                                   dep_fd_ref_t fd,
                                                   bool present) {
  uint32_t root = dep_process_owned_root(state, journal);
  if (!dep_route_map_put(journal, &root, fd, DEP_FD_ACCESS_PROCESS_OWNED,
                         present ? DEP_OWNED_CERTAIN : 0))
    return false;
  dep_route_set_t owned = {.ready = true};
  if (root)
    dep_route_set_set(&owned, (dep_fd_route_t){DEP_ROUTE_INHERITED, root});
  return dep_route_state_store_access(state, journal,
                                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                                      DEP_FD_ACCESS_PROCESS_OWNED, owned);
}

/* Join two ownership sets. An end owned in both is certainly owned; an end
 * owned in only one of them, or maybe owned in either, is maybe owned. Branches
 * that put one process-substitution end at different places own different
 * descriptors, and the end is at exactly one of them. */
static uint32_t dep_owned_join_value(void *context, uint64_t key, uint32_t left,
                                     uint32_t right) {
  (void)context;
  (void)key;
  return left == right ? left : DEP_OWNED_MAYBE;
}

/* The join reads node ids, keys and these flags only, so it is the union of
 * the two sets (shell_pmap_union): its memo makes repeated joins of sets
 * that share structure cost the fresh node pairs, not the sets' difference.
 * False when the pool or the memo is full. */
static SHELL_NONNULL(1, 2) bool dep_owned_join(dep_route_journal_t *journal,
                                               uint32_t *left, uint32_t right) {
  return shell_pmap_union(&journal->arena->maps, *left, right,
                          dep_owned_join_value, NULL, left, false,
                          DEP_UNION_OWNED);
}

/* Visit only live owned ends, not every descriptor or earlier source command.
 * The child keeps these FDs but clears its ownership set; the forking parent
 * closes exactly these original numbers, including an overwritten original. A
 * maybe-owned end may be somewhere else: it keeps what it held beside CLOSED.
 */
typedef struct {
  dep_route_state_t *parent;
  dep_route_journal_t *journal;
} dep_process_fork_t;

static bool dep_process_fork_close(void *context, dep_fd_ref_t fd,
                                   dep_fd_access_t access, uint32_t owned) {
  (void)access;
  dep_process_fork_t *fork = context;
  for (uint32_t facet = DEP_FD_ACCESS_READ; facet <= DEP_FD_ACCESS_BINDING;
       facet <<= 1) {
    dep_route_set_t closed = owned == DEP_OWNED_MAYBE
                                 ? dep_fd_raw_fact(fork->parent, fork->journal,
                                                   fd, (dep_fd_access_t)facet)
                                 : (dep_route_set_t){.ready = true};
    if (!dep_route_set_add(&closed,
                           (dep_fd_route_t){DEP_ROUTE_CLOSED, UINT32_MAX}) ||
        !dep_route_state_store_access(fork->parent, fork->journal, fd,
                                      (dep_fd_access_t)facet, closed))
      return false;
  }
  return true;
}

static SHELL_NONNULL(1, 2) bool dep_process_fork_parent(
    dep_route_state_t *parent, dep_route_journal_t *journal, uint32_t root) {
  dep_process_fork_t fork = {parent, journal};
  return dep_route_map_each(journal, root, dep_process_fork_close, &fork);
}

static SHELL_NONNULL(1,
                     2) bool dep_process_cleanup(dep_route_state_t *state,
                                                 dep_route_journal_t *journal) {
  dep_route_iterator_t iterator = dep_route_iterator(state);
  dep_route_state_t result = {0};
  uint32_t root;
  bool first = true;
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    uint32_t owned = dep_process_owned_root(&one, journal);
    if (owned &&
        (!dep_process_fork_parent(&one, journal, owned) ||
         !dep_route_state_store_access(
             &one, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
             DEP_FD_ACCESS_PROCESS_OWNED, (dep_route_set_t){.ready = true})))
      return false;
    if (first) {
      result = one;
      first = false;
    } else if (!dep_route_state_add_root(&result, journal, one.root))
      return false;
  }
  dep_route_state_inherit(&result, state);
  *state = result;
  return true;
}

/* Fixed scopes need no journal tag. Ambiguous setup is forked once; the tag
 * keeps every later prefix and failure walk on that same dispatch choice. */
static SHELL_NONNULL(1, 2) bool dep_setup_begin(dep_route_state_t *state,
                                                dep_route_journal_t *journal,
                                                uint8_t modes) {
  if (modes != DEP_UNDO_BOTH)
    return true;
  dep_route_iterator_t iterator = dep_route_iterator(state);
  dep_route_state_t result = {0};
  uint32_t root;
  bool first = true;
  while (dep_route_next(&iterator, journal, &root)) {
    for (uint8_t mode = DEP_UNDO_CHILD; mode <= DEP_UNDO_COMMAND; mode <<= 1) {
      dep_route_state_t one = dep_route_state_single(root);
      dep_route_set_t fact = {0};
      dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_INHERITED, mode});
      if (!dep_route_state_store_access(&one, journal,
                                        dep_fd_numeric(SHELL_DEP_FD_NONE),
                                        DEP_FD_ACCESS_SETUP_MODE, fact))
        return false;
      if (first) {
        result = one;
        first = false;
      } else if (!dep_route_state_add_root(&result, journal, one.root))
        return false;
    }
  }
  dep_route_state_inherit(&result, state);
  *state = result;
  return true;
}

static SHELL_NONNULL(1, 2) uint8_t
    dep_setup_mode(const dep_route_state_t *state,
                   const dep_route_journal_t *journal, uint8_t modes) {
  if (modes != DEP_UNDO_BOTH)
    return modes;
  dep_route_set_t fact =
      dep_fd_raw_fact(state, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
                      DEP_FD_ACCESS_SETUP_MODE);
  return fact.count == 1 ? (uint8_t)fact.routes[0].value : modes;
}

/* The capture pipe replaces fd: a fresh descriptor carrying the capture,
 * neither a save place nor a process-substitution end. */
static SHELL_NONNULL(1, 2) bool dep_child_install_capture(
    dep_route_state_t *state, dep_route_journal_t *journal, uint32_t fd) {
  dep_fd_access_t access = fd == 0 ? DEP_FD_ACCESS_READ : DEP_FD_ACCESS_WRITE;
  for (uint32_t facet = DEP_FD_ACCESS_READ; facet <= DEP_FD_ACCESS_BINDING;
       facet <<= 1) {
    dep_route_set_t routes = {0};
    dep_route_set_set(
        &routes, facet == DEP_FD_ACCESS_BINDING
                     ? (dep_fd_route_t){DEP_ROUTE_INHERITED, UINT32_MAX}
                 : facet == access
                     ? (dep_fd_route_t){DEP_ROUTE_CAPTURE,
                                        dep_resource_value(journal->depth, fd)}
                     : (dep_fd_route_t){DEP_ROUTE_UNAVAILABLE, UINT32_MAX});
    if (!dep_route_state_store_access(state, journal, dep_fd_numeric(fd),
                                      (dep_fd_access_t)facet, routes))
      return false;
  }
  return dep_route_state_store_access(state, journal, dep_fd_numeric(fd),
                                      DEP_FD_ACCESS_SELECTOR,
                                      (dep_route_set_t){.ready = true}) &&
         dep_route_state_store_access(state, journal, dep_fd_numeric(fd),
                                      DEP_FD_ACCESS_SCRATCH,
                                      (dep_route_set_t){.ready = true}) &&
         dep_process_owned_set(state, journal, dep_fd_numeric(fd), false);
}

/* Names assigned before a nested expansion by the same command hold a
 * temporary value: they enter the shadow set (dep_read_scalar_shadowed). On
 * an assignment-only path that value is also assigned: present, and bound to
 * no descriptor of the nested parse. A no-assign variable rejects the write
 * and keeps its value. Applies names [from, to) of assignments to the single
 * version *root, in place. Each name is independent of the others, so the
 * result does not depend on how the range is split. Presence is stored
 * whether or not the nested parse observes it: the facts are keyed by name
 * and only an observed name reads them. */
static SHELL_NONNULL(1, 2, 3) bool dep_prior_assignments_apply(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_prefix_assignment_set_t *assignments, uint32_t from, uint32_t to,
    bool assignment_only) {
  uint32_t marker = dep_route_state_snapshot(
      state, journal, dep_fd_numeric(DEP_SCALAR_IMPORT_EVENT),
      DEP_FD_ACCESS_PRIVATE_ENTRY);
  uint32_t shadowed =
      marker ? journal->arena->snapshots[marker - 1].routes[0].value : 0;
  uint32_t initial = shadowed;
  dep_route_set_t present = {0};
  dep_route_set_set(&present, (dep_fd_route_t){DEP_ROUTE_INHERITED, 1});
  uint32_t present_snapshot = dep_route_set_intern(journal, &present);
  if (!present_snapshot)
    return false;
  for (uint32_t i = from; i < to; i++) {
    const dep_variable_token_t *name = &assignments->names[i];
    if (name->variable &&
        (dep_variable_properties(name->variable, state, journal) &
         SHELL_VARIABLE_NOASSIGN))
      continue;
    dep_fd_ref_t ref = {.name = name->start,
                        .value = SHELL_DEP_FD_NAMED,
                        .name_len = name->len};
    if (!dep_route_map_put(journal, &shadowed, ref, DEP_FD_ACCESS_READ_ARGUMENT,
                           present_snapshot))
      return false;
    if (!assignment_only)
      continue;
    /* The assigned string is no descriptor the nested parse allocated. */
    dep_route_set_t unseen = {0};
    dep_route_set_set(&unseen, (dep_fd_route_t){DEP_ROUTE_UNSEEN, UINT32_MAX});
    if (!dep_route_state_store_access(state, journal, ref,
                                      DEP_FD_ACCESS_BINDING, unseen) ||
        !dep_presence_put(state, journal, ref, SHELL_TEST_TRUE, name->start))
      return false;
  }
  if (shadowed == initial)
    return true;
  dep_route_set_t fact = {0};
  dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_INHERITED, shadowed});
  return dep_route_state_store_access(state, journal,
                                      dep_fd_numeric(DEP_SCALAR_IMPORT_EVENT),
                                      DEP_FD_ACCESS_PRIVATE_ENTRY, fact);
}

/* Moves a prior-assignment result from one parent version's facts to
 * another's: each differing fact key takes the new parent's value. A key the
 * transform reads or writes (dep_prior_assignments_apply) stops the rebase;
 * the caller then applies the names from scratch. */
typedef struct {
  dep_route_journal_t *journal;
  uint32_t root;
  bool affected;
} dep_prior_rebase_t;

static bool dep_prior_rebase_key(void *context, dep_fd_ref_t fd,
                                 dep_fd_access_t access, uint32_t previous,
                                 uint32_t current) {
  (void)previous;
  dep_prior_rebase_t *rebase = context;
  if (access == DEP_FD_ACCESS_NAMED_BINDINGS ||
      access == DEP_FD_ACCESS_PRESENCE_MAP ||
      access == DEP_FD_ACCESS_VARIABLE_PRESENCE ||
      access == DEP_FD_ACCESS_EFFECT_STATE ||
      (access == DEP_FD_ACCESS_PRIVATE_ENTRY &&
       fd.value == DEP_SCALAR_IMPORT_EVENT)) {
    rebase->affected = true;
    return false;
  }
  return dep_route_map_put(rebase->journal, &rebase->root, fd, access, current);
}

/* Each version of *state, restricted to its facts, with the command's
 * assignments before position applied (dep_prior_assignments_apply). The
 * parent applies them before the nested parse starts, in its own journal, so
 * the nested parse borrows the result. A later expansion of the same command
 * resumes from the previous one's result for the same version
 * (source->prior_memo): it rebases that result onto its own parent version,
 * whose facts usually differ in a few keys, and applies only the names
 * between the two positions. */
static SHELL_NONNULL(1, 2, 3, 4) bool dep_prior_assignments(
    dep_route_state_t *state, dep_route_journal_t *journal,
    dep_snapshot_source_t *source, const char *position, bool assignment_only) {
  const dep_prefix_assignment_set_t *assignments = &source->prefix_assignments;
  dep_route_state_t result = {0};
  uint32_t version = 0;
  dep_route_iterator_t versions = dep_route_iterator(state);
  uint32_t parent;
  for (; dep_route_next(&versions, journal, &parent); version++) {
    uint32_t facts = dep_route_facts(journal, parent);
    dep_prior_memo_t *memo = NULL;
    for (uint32_t i = 0; i < DEP_PRIOR_MEMO_CAPACITY; i++)
      if (source->prior_memo[i].valid &&
          source->prior_memo[i].version == version &&
          source->prior_memo[i].assignment_only == assignment_only)
        memo = &source->prior_memo[i];
    uint32_t count = 0;
    dep_route_state_t one = dep_route_state_single(facts);
    if (memo && (!memo->count ||
                 assignments->names[memo->count - 1].start < position)) {
      dep_prior_rebase_t rebase = {journal, memo->result, false};
      uint32_t previous = dep_route_facts(journal, memo->parent);
      if (dep_route_map_diff(journal, previous, facts, dep_prior_rebase_key,
                             &rebase)) {
        one = dep_route_state_single(rebase.root);
        count = memo->count;
      } else if (!rebase.affected) {
        return false;
      }
    }
    uint32_t end = count;
    while (end < assignments->count && assignments->names[end].start < position)
      end++;
    if (!dep_prior_assignments_apply(&one, journal, assignments, count, end,
                                     assignment_only))
      return false;
    if (!memo) {
      memo = &source->prior_memo[source->prior_memo_next];
      source->prior_memo_next =
          (source->prior_memo_next + 1) % DEP_PRIOR_MEMO_CAPACITY;
    }
    *memo = (dep_prior_memo_t){parent,  one.root,        end,
                               version, assignment_only, true};
    if (!version)
      result = one;
    else if (!dep_route_state_add_root(&result, journal, one.root))
      return false;
  }
  dep_route_state_inherit(&result, state);
  *state = result;
  return true;
}

/* A nested parse starts each execution version from its parent's version on
 * the same path: the parent's facts, without its scope bookkeeping, read in
 * place (resources are depth-tagged and slots are evaluation-wide, so nothing
 * is translated). Each path then applies only its own entry transforms. */
static SHELL_NONNULL(1, 2) bool dep_import_route_alternatives(
    dep_route_state_t *state, dep_route_journal_t *changes,
    const dep_fd_imports_t *imports) {
  if (!imports)
    return true;
  uint32_t paths = imports->path_count ? imports->path_count : 1;
  /* Facts of a kind the parent's pass has stored may be inherited. A root
   * parse's import table has no parent journal. */
  if (imports->scalar_journal) {
    changes->ifs_seen |= imports->scalar_journal->ifs_seen;
    changes->save_marks |= imports->scalar_journal->save_marks;
  }
  dep_route_state_t result = {0};
  bool first = true;
  for (uint32_t path = 0; path < paths; path++) {
    /* A root parse's table holds one empty version: the contract. */
    dep_route_iterator_t versions =
        dep_route_iterator(&imports->path_state[path]);
    uint32_t parent;
    while (dep_route_next(&versions, changes, &parent)) {
      dep_route_state_t one =
          dep_route_state_single(dep_route_facts(changes, parent));
      /* The path's IFS includes this command's assignments
       * (dep_assignment_ifs_t) and so may differ from the inherited fact, even
       * when empty. */
      uint32_t ifs =
          imports->path_count ? imports->path_ifs[path] : imports->ifs;
      if (ifs != dep_ifs_get(&one, changes) &&
          !dep_ifs_store(&one, changes, ifs))
        return false;
      for (uint32_t fd = 0; fd < 3; fd++)
        if ((imports->process_capture_mask & (1u << fd)) &&
            !dep_child_install_capture(&one, changes, fd))
          return false;
      if (imports->path_process_domain_present[path]) {
        shell_fd_partition_t domain = imports->path_process_domain[path];
        /* A capture replaces the child's standard stream with its own pipe. */
        for (uint32_t part = 0; part < SHELL_FD_PARTS; part++)
          for (uint32_t fd = 0; fd < 3; fd++)
            if ((imports->process_capture_mask & (1u << fd)) &&
                shell_fd_occupancy_feasible(&domain.part[part]))
              shell_fd_occupancy_set(&domain.part[part], fd, false, true);
        if (imports->process_capture_mask)
          shell_fd_partition_normalize(&domain);
        if (!dep_fd_domain_store(&one, changes, &domain))
          return false;
      }
      if (first)
        result = one;
      else if (!dep_route_state_add_root(&result, changes, one.root))
        return false;
      first = false;
    }
  }
  *state = result;
  if (imports->observe_return && changes->read_observations.active) {
    dep_route_set_t marker = {0};
    dep_route_set_set(&marker,
                      (dep_fd_route_t){DEP_ROUTE_INHERITED, UINT32_MAX});
    /* Keep immutable entry anchors only. Actual argument/descriptor uses
     * capture their sparse dependencies before consuming the entry facts. */
    if (!dep_route_state_store_access(state, changes,
                                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                                      DEP_FD_ACCESS_PRIVATE_SCOPE, marker) ||
        !dep_fd_private_begin(state, changes, DEP_OBSERVATION_ROOT_EVENT))
      return false;
  }
  return true;
}

static dep_route_set_t dep_route_state_get(const dep_route_state_t *state,
                                           const dep_route_journal_t *changes,
                                           dep_fd_ref_t fd) {
  return dep_route_state_get_access(state, changes, fd, DEP_FD_ACCESS_WRITE);
}

/* Replay successful setup against its immutable entry. Duplications copy
 * capabilities, not absence: absence makes setup fail before replacement.
 * The outcome stream separately retains those failed setup prefixes. */
static SHELL_NONNULL(1) bool dep_allocation_remove_candidate(
    dep_route_set_t *available, uint32_t fd) {
  for (uint32_t i = 0; i < available->count; i++) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
    if (available->routes[i].value == fd) {
      memmove(available->routes + i, available->routes + i + 1,
              (available->count - i - 1) * sizeof(available->routes[0]));
      available->count--;
      return true;
    }
  }
  return false;
}

typedef struct {
  bool may_be_free;
  bool may_be_occupied;
} dep_fd_occupancy_t;

/* The stored process domain of a single version: occupancy partitioned by
 * the low interval, part c under numeric key c, with the parts' union under
 * key DEP_DOMAIN_UNION for the per-descriptor reads that need only that. All
 * are stored together. Returns false when no allocation has needed a domain
 * yet. */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_domain_stored(
    const dep_route_state_t *state, const dep_route_journal_t *journal,
    shell_fd_partition_t *partition) {
  for (uint32_t part = 0; part < SHELL_FD_PARTS; part++) {
    dep_route_set_t fact = dep_fd_raw_fact(state, journal, dep_fd_numeric(part),
                                           DEP_FD_ACCESS_PROCESS_DOMAIN);
    if (!fact.count)
      return false;
    partition->part[part] = dep_domain_value(&fact);
  }
  return true;
}

static SHELL_NONNULL(1, 2) dep_fd_occupancy_t
    dep_fd_occupancy(const dep_route_state_t *state,
                     const dep_route_journal_t *journal, uint32_t fd) {
  dep_route_set_t domain =
      fd < 64
          ? dep_fd_raw_fact(state, journal, dep_fd_numeric(DEP_DOMAIN_UNION),
                            DEP_FD_ACCESS_PROCESS_DOMAIN)
          : (dep_route_set_t){.ready = true};
  if (domain.count) {
    shell_fd_occupancy_t value = dep_domain_value(&domain);
    uint64_t bit = UINT64_C(1) << fd;
    return (dep_fd_occupancy_t){(value.may_free & bit) != 0,
                                (value.may_occupied & bit) != 0};
  }
  dep_route_set_t binding =
      dep_fd_fact(state, journal, dep_fd_numeric(fd), DEP_FD_ACCESS_BINDING);
  dep_fd_occupancy_t result = {0};
  for (uint32_t route = 0; route < binding.count; route++) {
    switch (binding.routes[route].kind) {
    case DEP_ROUTE_CLOSED:
    case DEP_ROUTE_ABSENT:
    case DEP_ROUTE_UNAVAILABLE:
      result.may_be_free = true;
      break;
    case DEP_ROUTE_UNSEEN:
    case DEP_ROUTE_DYNAMIC:
      result.may_be_free = true;
      result.may_be_occupied = true;
      break;
    default:
      result.may_be_occupied = true;
      break;
    }
  }
  return result;
}

/* Occupancy of fds 0..63 on this version: the union of its process domain,
 * or, before any allocation needed one, its binding facts. */
static SHELL_NONNULL(1, 2) shell_fd_occupancy_t
    dep_fd_occupancy_masks(const dep_route_state_t *state,
                           const dep_route_journal_t *journal) {
  dep_route_set_t domain =
      dep_fd_raw_fact(state, journal, dep_fd_numeric(DEP_DOMAIN_UNION),
                      DEP_FD_ACCESS_PROCESS_DOMAIN);
  if (domain.count)
    return dep_domain_value(&domain);
  shell_fd_occupancy_t masks = {0, 0};
  for (uint32_t fd = 0; fd < 64; fd++) {
    dep_fd_occupancy_t one = dep_fd_occupancy(state, journal, fd);
    /* A descriptor without any binding fact is unconstrained. */
    if (!one.may_be_free && !one.may_be_occupied)
      one.may_be_free = one.may_be_occupied = true;
    masks.may_free |= (uint64_t)one.may_be_free << fd;
    masks.may_occupied |= (uint64_t)one.may_be_occupied << fd;
  }
  return masks;
}

/* The low-interval partition of this version's occupancy: its stored
 * domain, or the split of its binding facts. */
static SHELL_NONNULL(1, 2) shell_fd_partition_t
    dep_fd_domain(const dep_route_state_t *state,
                  const dep_route_journal_t *journal) {
  shell_fd_partition_t partition;
  if (dep_fd_domain_stored(state, journal, &partition))
    return partition;
  shell_fd_occupancy_t masks = dep_fd_occupancy_masks(state, journal);
  return shell_fd_partition_split(&masks);
}

/* Store every part of a domain, each tightened to its case. On a single
 * version, parts equal to the stored ones are left as they are. This is the
 * writer that makes the parts of a domain present together: readers that find
 * the first part stored read all of them. */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_domain_store(
    dep_route_state_t *state, dep_route_journal_t *journal,
    shell_fd_partition_t *partition) {
  shell_fd_partition_refine(partition);
  for (uint32_t part = 0; part < SHELL_FD_PARTS; part++) {
    uint32_t prior = dep_route_state_snapshot(
        state, journal, dep_fd_numeric(part), DEP_FD_ACCESS_PROCESS_DOMAIN);
    if (dep_route_state_count(state) == 1 && prior &&
        journal->arena->snapshots[prior - 1].count) {
      shell_fd_occupancy_t stored =
          dep_domain_value(&journal->arena->snapshots[prior - 1]);
      if (stored.may_free == partition->part[part].may_free &&
          stored.may_occupied == partition->part[part].may_occupied)
        continue;
    }
    if (!dep_route_state_store_access(state, journal, dep_fd_numeric(part),
                                      DEP_FD_ACCESS_PROCESS_DOMAIN,
                                      dep_domain_fact(partition->part[part])))
      return false;
  }
  return dep_route_state_store_access(
      state, journal, dep_fd_numeric(DEP_DOMAIN_UNION),
      DEP_FD_ACCESS_PROCESS_DOMAIN,
      dep_domain_fact(shell_fd_partition_union(partition)));
}

static SHELL_NONNULL(1, 2) unsigned dep_fd_low_modes(
    const dep_route_state_t *state, const dep_route_journal_t *journal);

/* The views of one version that an allocation runs on separately: one per
 * current low-interval case with paths, each holding only that case's parts,
 * or the version itself when one case holds every path. A place then stays
 * correlated with the low-interval case that chose it.
 *
 * An allocation sees the inherited case only through the current one. When
 * the two inherited cases' paths cover different current cases, and a later
 * operation can tell places apart (an observable descriptor or a named
 * close), the views are per part instead, and origins[v] names the inherited
 * case whose outcomes view v joins; otherwise every origins[v] is 0. views
 * and origins have SHELL_FD_PARTS entries. */
static SHELL_NONNULL(1, 2, 3, 4, 5) bool dep_fd_domain_views(
    const dep_route_state_t *state, dep_route_journal_t *journal,
    dep_route_state_t *views, uint8_t *origins, uint32_t *count) {
  *count = 0;
  origins[0] = 0;
  shell_fd_partition_t partition;
  /* Without a stored domain, a split exists only when both low cases do. */
  if (!dep_fd_domain_stored(state, journal, &partition) &&
      dep_fd_low_modes(state, journal) != 3) {
    views[(*count)++] = *state;
    return true;
  }
  partition = dep_fd_domain(state, journal);
  unsigned cases[2] = {0, 0};
  for (uint32_t part = 0; part < SHELL_FD_PARTS; part++)
    if (shell_fd_occupancy_feasible(&partition.part[part]))
      cases[part >> 1] |= 1u << (part & 1u);
  bool split = cases[0] && cases[1] && cases[0] != cases[1] &&
               (journal->observable_fd_count || journal->named_closes);
  shell_fd_partition_t grouped[SHELL_FD_PARTS] = {{{{0, 0}}}};
  bool used[SHELL_FD_PARTS] = {false};
  for (uint32_t part = 0; part < SHELL_FD_PARTS; part++) {
    if (!shell_fd_occupancy_feasible(&partition.part[part]))
      continue;
    uint32_t key = split ? part : part & 1u;
    grouped[key].part[part] = partition.part[part];
    used[key] = true;
  }
  if (used[0] + used[1] + used[2] + used[3] < 2) {
    views[(*count)++] = *state;
    return true;
  }
  for (uint32_t key = 0; key < SHELL_FD_PARTS; key++) {
    if (!used[key])
      continue;
    views[*count] = *state;
    origins[*count] = split ? (uint8_t)(key >> 1) : 0;
    if (!dep_fd_domain_store(&views[(*count)++], journal, &grouped[key]))
      return false;
  }
  return true;
}

/* The inherited low-interval cases a version's paths may have, one bit per
 * case. */
static SHELL_NONNULL(1, 2) unsigned dep_fd_domain_origins(
    const dep_route_state_t *state, const dep_route_journal_t *journal) {
  shell_fd_partition_t partition = dep_fd_domain(state, journal);
  unsigned origins = 0;
  for (uint32_t part = 0; part < SHELL_FD_PARTS; part++)
    if (shell_fd_occupancy_feasible(&partition.part[part]))
      origins |= 1u << (part >> 1);
  return origins;
}

/* Select the possible descriptor at one Bash lowest-free rank. Observable
 * numeric spellings retain their exact identity. Unmentioned intervals are one
 * private identity because no later source operation can distinguish members
 * of that interval. rank is one or two. */
static SHELL_NONNULL(1, 2, 3) bool dep_allocation_rank_slots(
    const dep_route_state_t *state, dep_route_journal_t *journal,
    dep_route_set_t *numeric, uint32_t rank, bool *abstract, uint32_t minimum) {
  bool possible[2] = {true, false};
  uint32_t previous = minimum;
  for (uint32_t i = 0; i < journal->observable_fd_count; i++) {
    uint32_t fd = journal->observable_fds[i];
    if (fd < minimum)
      continue;
    if (fd > previous) {
      /* There are only two ranks. Any nonempty unobserved interval can
       * contribute the one extra free slot needed to reach the second. */
      *abstract |= possible[0] || possible[1];
      if (rank == 2 && possible[0])
        possible[1] = true;
    }

    dep_fd_occupancy_t occupancy = dep_fd_occupancy(state, journal, fd);
    bool next[2] = {false, false};
    for (uint32_t count = 0; count < rank; count++) {
      if (!possible[count])
        continue;
      if (occupancy.may_be_occupied)
        next[count] = true;
      if (!occupancy.may_be_free)
        continue;
      if (count + 1 == rank) {
        if (!dep_route_set_add(numeric, (dep_fd_route_t){DEP_ROUTE_ALIAS, fd}))
          return false;
      } else {
        next[count + 1] = true;
      }
    }
    possible[0] = next[0];
    possible[1] = next[1];
    if (fd == UINT32_MAX)
      break;
    previous = fd + 1;
  }
  for (uint32_t count = 0; count < rank; count++)
    *abstract |= possible[count];
  return true;
}

typedef struct {
  /* Visible numeric routes remain separate, each with the occupancy of the
   * paths that select it. Unobserved places share the private slot `key`,
   * whose possible places are `places`. An occupancy with no possible state
   * (all zero) is no path. */
  dep_fd_route_t slots[64 + SHELL_DEP_TIME_MAX_EXTERNAL_FDS];
  shell_fd_occupancy_t domains[64 + SHELL_DEP_TIME_MAX_EXTERNAL_FDS];
  /* The low-interval state (0 some free, 1 full) every path of the choice
   * shares, or -1. Masks cannot express "some descriptor below 10 is free",
   * so selecting a choice records it as the version's low-state fact. */
  int8_t low_states[64 + SHELL_DEP_TIME_MAX_EXTERNAL_FDS];
  uint32_t count;
  /* Paths on which the search passes fd 63. */
  shell_fd_occupancy_t tail_domain;
  shell_fd_allocation_t places;
  uint32_t selector, key;
} dep_allocation_choices_t;

typedef struct {
  dep_allocation_choices_t slots[2];
  bool resource;
} dep_named_allocation_choices_t;

static SHELL_NONNULL(1, 2,
                     4) bool dep_fd_assume_binding(dep_route_state_t *state,
                                                   dep_route_journal_t *journal,
                                                   uint32_t fd, bool *possible,
                                                   bool free);

/* choices is an empty caller-owned destination. rank is 1 or 2. low_mode is
 * -1 for no temporary resource open, 0 for a free low slot, and 1 for a full
 * low interval (the temporary open consumes a high slot). source_places,
 * when not NULL, are the places of a named source whose F_DUPFD search starts
 * above its own descriptor. Each choice keeps the per-descriptor occupancy of
 * the paths that select it. */
static SHELL_NONNULL(1, 2, 8) bool dep_allocation_domain_choices(
    const dep_route_state_t *state, dep_route_journal_t *journal, uint32_t key,
    unsigned rank, uint32_t minimum, int low_mode,
    const shell_fd_allocation_t *source_places,
    dep_allocation_choices_t *choices);
static SHELL_NONNULL(1) bool dep_allocation_choice_add(
    dep_allocation_choices_t *choices, dep_fd_route_t slot,
    shell_fd_occupancy_t domain, int low_state);

/* Low-descriptor occupancy determines whether Bash's temporary file open
 * consumes a high slot: bit 0 when some path has a free low descriptor, bit
 * 1 when some path has all ten open. */
static SHELL_NONNULL(1, 2) unsigned dep_fd_low_modes(
    const dep_route_state_t *state, const dep_route_journal_t *journal) {
  shell_fd_partition_t partition;
  if (dep_fd_domain_stored(state, journal, &partition))
    return shell_fd_partition_cases(&partition);
  /* The split of the binding facts: only the low descriptors decide. */
  bool low_free = false, low_full = true;
  for (uint32_t fd = 0; fd < DEP_BASH_VARREDIR_MIN_FD; fd++) {
    dep_fd_occupancy_t occupancy = dep_fd_occupancy(state, journal, fd);
    if (!occupancy.may_be_free && !occupancy.may_be_occupied)
      occupancy.may_be_free = occupancy.may_be_occupied = true;
    low_free |= occupancy.may_be_free;
    low_full &= occupancy.may_be_occupied;
  }
  return (low_free ? 1u : 0u) | (low_full ? 2u : 0u);
}

static SHELL_NONNULL(1, 2, 5) bool dep_allocation_rank_choices(
    const dep_route_state_t *state, dep_route_journal_t *journal,
    uint32_t private_slot, uint32_t rank, dep_route_set_t *slots,
    uint32_t minimum) {
  dep_route_set_t numeric = {0};
  bool abstract = false;
  if (!dep_allocation_rank_slots(state, journal, &numeric, rank, &abstract,
                                 minimum))
    return false;
  if (private_slot == SHELL_DEP_FD_NONE)
    return false;
  if (abstract && !dep_route_set_add(
                      slots, (dep_fd_route_t){DEP_ROUTE_ALIAS, private_slot}))
    return false;
  for (uint32_t candidate = 0; candidate < numeric.count; candidate++)
    if (!dep_route_set_add(slots, numeric.routes[candidate]))
      return false;
  return slots->count != 0;
}

static SHELL_NONNULL(1, 2, 3, 4) bool dep_named_allocation_choices(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_fd_op_t *op, dep_named_allocation_choices_t *choices) {
  uint32_t private_slot = dep_allocation_slot(journal, op);
  if (private_slot == SHELL_DEP_FD_NONE)
    return false;
  bool low_free = true;
  if (dep_fd_op_copies(op->kind)) {
    if (!dep_allocation_domain_choices(state, journal, private_slot, 1,
                                       DEP_BASH_VARREDIR_MIN_FD, -1, NULL,
                                       &choices->slots[0]))
      return false;
  } else {
    /* Bash opens the resource first, duplicates it with F_DUPFD starting at
     * 10, and closes the temporary open. A low temporary fd leaves the first
     * high slot free; a high temporary fd consumes it, so the retained slot
     * is the second free high fd. */
    unsigned modes = dep_fd_low_modes(state, journal);
    bool low_full = (modes & 2u) != 0;
    low_free = (modes & 1u) != 0;
    choices->resource = true;
    if ((low_free &&
         !dep_allocation_domain_choices(state, journal, private_slot, 1,
                                        DEP_BASH_VARREDIR_MIN_FD, 0, NULL,
                                        &choices->slots[0])) ||
        (low_full &&
         !dep_allocation_domain_choices(state, journal, private_slot, 2,
                                        DEP_BASH_VARREDIR_MIN_FD, 1, NULL,
                                        &choices->slots[1])))
      return false;
  }
  /* A closed private allocation above the searched range keeps its slot
   * available to a later search that passes fd 63. */
  dep_route_set_t available =
      dep_fd_raw_fact(state, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
                      DEP_FD_ACCESS_AVAILABLE);
  for (uint32_t candidate = 0; candidate < available.count; candidate++)
    if (available.routes[candidate].kind == DEP_ROUTE_ALIAS &&
        available.routes[candidate].value > SHELL_DEP_FD_MAX &&
        !dep_fd_raw_fact(state, journal,
                         dep_fd_numeric(available.routes[candidate].value),
                         DEP_FD_ACCESS_SELECTOR)
             .count &&
        low_free &&
        (choices->slots[0].tail_domain.may_free ||
         choices->slots[0].tail_domain.may_occupied) &&
        !dep_allocation_choice_add(&choices->slots[0],
                                   available.routes[candidate],
                                   choices->slots[0].tail_domain, -1))
      return false;
  return choices->slots[0].count || choices->slots[1].count;
}

static SHELL_NONNULL(1, 2) uint32_t
    dep_process_key(dep_route_journal_t *journal, const dep_fd_op_t *op,
                    bool create) {
  dep_allocation_t key = {
      .name = op->fd_name, .position = op->pos, .role = DEP_ALLOCATION_PROCESS};
  return dep_allocation_key_slot(journal, &key, create);
}

static SHELL_NONNULL(1, 2) uint32_t
    dep_process_guard_key(dep_route_journal_t *journal,
                          const dep_process_guard_t *guard, bool create) {
  dep_allocation_t key = {.name = guard->source,
                          .role = DEP_ALLOCATION_PROCESS_GUARD};
  return dep_allocation_key_slot(journal, &key, create);
}

/* One source operand makes one decision per version. Parent guards dominate
 * nested operands; repeated substitutions and indexed replay reuse that
 * decision instead of independently forking or reviving a skipped pipe. */
static SHELL_NONNULL(1, 2, 3) bool dep_process_guard_prepare(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_process_guard_t *guard) {
  uint32_t key = dep_process_guard_key(journal, guard, true);
  if (key == SHELL_DEP_FD_NONE)
    return false;
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  bool pending = false;
  while (dep_route_next(&iterator, journal, &root)) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
    dep_route_state_t one = dep_route_state_single(root);
    pending |= !dep_fd_raw_fact(&one, journal, dep_fd_numeric(key),
                                DEP_FD_ACCESS_PROCESS_SLOT)
                    .count;
  }
  if (!pending)
    return true;
  uint32_t parent_key = SHELL_DEP_FD_NONE;
  if (guard->parent) {
    if (!dep_process_guard_prepare(state, journal, guard->parent))
      return false;
    parent_key = dep_process_guard_key(journal, guard->parent, false);
  }
  dep_route_state_t result = {0};
  bool first = true;
  iterator = dep_route_iterator(state);
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_set_t fact = dep_fd_raw_fact(&one, journal, dep_fd_numeric(key),
                                           DEP_FD_ACCESS_PROCESS_SLOT);
    bool parent = !guard->parent ||
                  dep_fd_raw_fact(&one, journal, dep_fd_numeric(parent_key),
                                  DEP_FD_ACCESS_PROCESS_SLOT)
                      .routes[0]
                      .value;
    unsigned count = fact.count || !parent ? 1 : 2;
    for (unsigned choice = 0; choice < count; choice++) {
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
      dep_route_state_t branch = one;
      if (!fact.count) {
        dep_route_set_t decision = {.ready = true};
        dep_route_set_set(&decision,
                          (dep_fd_route_t){DEP_ROUTE_INHERITED, choice});
        if (!dep_route_state_store_access(&branch, journal, dep_fd_numeric(key),
                                          DEP_FD_ACCESS_PROCESS_SLOT, decision))
          return false;
      }
      if (first) {
        result = branch;
        first = false;
      } else if (!dep_route_state_add_root(&result, journal, branch.root))
        return false;
    }
  }
  dep_route_state_inherit(&result, state);
  *state = result;
  return true;
}

/* Reuse the nearest established operand decision. A newly encountered scope
 * has not forked yet; its nearest established ancestor still dominates it. */
static SHELL_NONNULL(1, 2, 3, 4, 5) bool dep_process_guard_select(
    const dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_process_guard_t *guard, dep_route_state_t *selected,
    bool *possible) {
  uint32_t key = SHELL_DEP_FD_NONE;
  const dep_process_guard_t *cursor = guard;
  for (; cursor; cursor = cursor->parent) {
    key = dep_process_guard_key(journal, cursor, false);
    if (key != SHELL_DEP_FD_NONE)
      break;
  }
  if (key == SHELL_DEP_FD_NONE) {
    *selected = *state;
    *possible = true;
    return true;
  }
  *selected = (dep_route_state_t){0};
  *possible = false;
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  while (dep_route_next(&iterator, journal, &root)) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_PROCESS_ROUTES);
    dep_route_state_t one = dep_route_state_single(root);
    if (!dep_fd_raw_fact(&one, journal, dep_fd_numeric(key),
                         DEP_FD_ACCESS_PROCESS_SLOT)
             .routes[0]
             .value)
      continue;
    if (!*possible) {
      *selected = one;
      *possible = true;
    } else if (!dep_route_state_add_root(selected, journal, root))
      return false;
  }
  dep_route_state_inherit(selected, state);
  return true;
}

/* Repeated tail identities have the same completed occupancy. Concrete low
 * identities are emitted once. This helper does not merge distinct domains. */
static SHELL_NONNULL(1) bool dep_allocation_choice_add(
    dep_allocation_choices_t *choices, dep_fd_route_t slot,
    shell_fd_occupancy_t domain, int low_state) {
  for (uint32_t i = 0; i < choices->count; i++)
    if (choices->slots[i].value == slot.value)
      return true;
  if (choices->count == sizeof(choices->slots) / sizeof(choices->slots[0]))
    return false;
  choices->slots[choices->count] = slot;
  choices->low_states[choices->count] = (int8_t)low_state;
  choices->domains[choices->count++] = domain;
  return true;
}

/* A closed named variable still stores its numeric value. Reusing that
 * physical descriptor updates the old alias too. Without a relation between
 * the two allocations, every closed private slot whose places meet the new
 * allocation's places may be the one reused. */
static SHELL_NONNULL(1, 2, 6) bool dep_allocation_reuse_hidden(
    const dep_route_state_t *state, dep_route_journal_t *journal,
    shell_fd_allocation_t places, shell_fd_occupancy_t hidden, int hidden_low,
    dep_allocation_choices_t *choices) {
  dep_route_set_t available =
      dep_fd_raw_fact(state, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
                      DEP_FD_ACCESS_AVAILABLE);
  if (available.truncated)
    return false;
  for (uint32_t i = 0; i < available.count; i++) {
    uint32_t slot = available.routes[i].value;
    if (available.routes[i].kind != DEP_ROUTE_ALIAS || slot <= SHELL_DEP_FD_MAX)
      continue;
    dep_route_set_t identity = dep_fd_raw_fact(
        state, journal, dep_fd_numeric(slot), DEP_FD_ACCESS_SELECTOR);
    if (!identity.count)
      continue;
    shell_fd_allocation_t closed = dep_slot_places(&identity);
    if (((closed.candidates & places.candidates) ||
         (closed.tail && places.tail)) &&
        !dep_allocation_choice_add(choices,
                                   (dep_fd_route_t){DEP_ROUTE_ALIAS, slot},
                                   hidden, hidden_low))
      return false;
  }
  return true;
}

/* The occupancy after an allocation, computed from this version's union, for
 * the paths of each domain part the version has, or only of the parts in
 * low-interval case low_state when it is not negative. The allocation can
 * itself change a path's case, by taking the last free low descriptor, so
 * each origin's paths are filed by their case afterwards. */
static SHELL_NONNULL(1,
                     2) bool dep_allocation_select(dep_route_state_t *state,
                                                   dep_route_journal_t *journal,
                                                   shell_fd_occupancy_t domain,
                                                   int low_state) {
  shell_fd_partition_t current = dep_fd_domain(state, journal);
  shell_fd_partition_t partition = {{{0, 0}}};
  for (uint32_t part = 0; part < SHELL_FD_PARTS; part++) {
    if (!shell_fd_occupancy_feasible(&current.part[part]) ||
        (low_state >= 0 && (int)shell_fd_part_full(part) != low_state))
      continue;
    for (uint32_t full = 0; full < 2; full++) {
      shell_fd_occupancy_t filed =
          shell_fd_occupancy_low_case(&domain, full != 0);
      shell_fd_occupancy_join(&partition.part[(part & ~1u) | full], &filed);
    }
  }
  return dep_fd_domain_store(state, journal, &partition);
}

/* A private slot records its possible places on the operation key and, unless
 * it already has its own, on the reused slot. */
static SHELL_NONNULL(1, 2, 3) bool dep_allocation_select_slot(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_allocation_choices_t *choices, uint32_t index) {
  if (!dep_allocation_select(state, journal, choices->domains[index],
                             choices->low_states[index]))
    return false;
  uint32_t slot = choices->slots[index].value;
  if (slot <= SHELL_DEP_FD_MAX)
    return true;
  dep_route_set_t places =
      dep_slot_places_fact(choices->selector, choices->places);
  if (!dep_route_state_store_access(state, journal,
                                    dep_fd_numeric(choices->key),
                                    DEP_FD_ACCESS_SELECTOR, places))
    return false;
  uint32_t prior = dep_route_state_snapshot(
      state, journal, dep_fd_numeric(slot), DEP_FD_ACCESS_SELECTOR);
  if (prior && journal->arena->snapshots[prior - 1].count)
    return true;
  return dep_route_state_store_access(state, journal, dep_fd_numeric(slot),
                                      DEP_FD_ACCESS_SELECTOR, places);
}

/* A successful existence check constrains the entry world; it does not open
 * a closed descriptor. Actual opens/closes use store_access's assignment
 * operation instead. possible=false is an infeasible path, not exhaustion. */
static SHELL_NONNULL(1, 2,
                     4) bool dep_fd_assume_binding(dep_route_state_t *state,
                                                   dep_route_journal_t *journal,
                                                   uint32_t fd, bool *possible,
                                                   bool free) {
  *possible = true;
  shell_fd_partition_t partition;
  if (fd < 64 && dep_fd_domain_stored(state, journal, &partition)) {
    uint64_t bit = UINT64_C(1) << fd;
    *possible = false;
    for (uint32_t part = 0; part < SHELL_FD_PARTS; part++) {
      shell_fd_occupancy_t *value = &partition.part[part];
      if (!shell_fd_occupancy_feasible(value) ||
          !((free ? value->may_free : value->may_occupied) & bit)) {
        *value = (shell_fd_occupancy_t){0, 0};
        continue;
      }
      if (free)
        value->may_occupied &= ~bit;
      else
        value->may_free &= ~bit;
      *possible = true;
    }
    if (!*possible)
      return true;
    if (!dep_fd_domain_store(state, journal, &partition))
      return false;
  }
  dep_route_set_t fact = {0};
  dep_route_set_set(
      &fact, (dep_fd_route_t){free ? DEP_ROUTE_CLOSED : DEP_ROUTE_INHERITED,
                              UINT32_MAX});
  return dep_route_state_store_access(state, journal, dep_fd_numeric(fd),
                                      DEP_FD_ACCESS_BINDING, fact);
}

/* One requested rank and low-interval state. Returns the low-interval state
 * the choice implies: low_mode, or -2 when no path selects fd. */
static SHELL_NONNULL(1, 2) int dep_allocation_choice_masks(
    shell_fd_occupancy_t *chosen, const shell_fd_occupancy_t *domain,
    uint32_t begin, uint32_t fd, unsigned rank, int low_mode) {
  *chosen = *domain;
  return shell_fd_occupancy_select(chosen, begin, fd, rank, low_mode) ? low_mode
                                                                      : -2;
}

/* Join of low-interval states, with -2 for "no path yet". */
static int dep_low_state_join(int joined, int added) {
  return joined == -2 || joined == added ? added : -1;
}

static SHELL_NONNULL(1, 2, 8) bool dep_allocation_domain_choices(
    const dep_route_state_t *state, dep_route_journal_t *journal, uint32_t key,
    unsigned rank, uint32_t minimum, int low_mode,
    const shell_fd_allocation_t *source_places,
    dep_allocation_choices_t *choices) {
  choices->key = key;
  choices->selector = dep_allocation_selector(journal, key);
  if (!choices->selector)
    return false;
  choices->places = (shell_fd_allocation_t){0, false};
  choices->tail_domain = (shell_fd_occupancy_t){0, 0};
  /* An exactly known source fixes the start of its search. */
  bool source_known = false;
  if (source_places && !source_places->tail && source_places->candidates &&
      !(source_places->candidates & (source_places->candidates - 1))) {
    uint32_t source = shell_fd_lowest(source_places->candidates);
    if (source + 1 > minimum)
      minimum = source + 1;
    source_known = true;
  }
  bool relative = source_places && !source_known;
  shell_fd_occupancy_t domain = dep_fd_occupancy_masks(state, journal);
  bool observable[64] = {false};
  for (uint32_t i = 0; i < journal->observable_fd_count; i++)
    if (journal->observable_fds[i] < 64)
      observable[journal->observable_fds[i]] = true;
  shell_fd_occupancy_t hidden = {0, 0}, hidden_only = {0, 0};
  unsigned hidden_count = 0;
  uint32_t hidden_fd = 0;
  int hidden_low = -2, hidden_only_low = -1;
  unsigned certain = 0;
  bool bounded = false;
  for (uint32_t fd = minimum; fd < 64; fd++) {
    if (!(domain.may_free & (UINT64_C(1) << fd)))
      continue;
    /* Without a known source, any lower start is possible, so no preceding
     * descriptor is forced occupied. */
    shell_fd_occupancy_t selected;
    int selected_low = dep_allocation_choice_masks(
        &selected, &domain, relative ? fd : minimum, fd, rank, low_mode);
    if (selected_low != -2) {
      if (observable[fd]) {
        if (!dep_allocation_choice_add(choices,
                                       (dep_fd_route_t){DEP_ROUTE_ALIAS, fd},
                                       selected, selected_low))
          return false;
      } else {
        hidden_count++;
        hidden_fd = fd;
        hidden_only = selected;
        hidden_only_low = selected_low;
        hidden_low = dep_low_state_join(hidden_low, selected_low);
        choices->places.candidates |= UINT64_C(1) << fd;
        shell_fd_occupancy_join(&hidden, &selected);
      }
    }
    /* With a fixed start, enough certainly free lower slots prove every
     * higher candidate impossible. */
    if (!relative && !(domain.may_occupied & (UINT64_C(1) << fd)) &&
        ++certain == rank) {
      bounded = true;
      break;
    }
  }
  /* Above Bash's fixed high search range, retain the existing observed/private
   * tail model, but only with feasible free-count and low-open conditions. */
  dep_route_set_t tail = {0};
  shell_fd_occupancy_t tail_domains[SHELL_DEP_TIME_MAX_EXTERNAL_FDS];
  int tail_lows[SHELL_DEP_TIME_MAX_EXTERNAL_FDS];
  uint64_t searched = shell_fd_range_from(minimum < 64 ? minimum : 64);
  /* low of the rank free descriptors lie in the searched range. */
  for (unsigned low = 0; !bounded && low < rank; low++) {
    shell_fd_occupancy_t selected = domain;
    if ((!relative &&
         !shell_fd_occupancy_restrict(&selected, searched, low, low)) ||
        (low_mode >= 0 &&
         !shell_fd_occupancy_restrict(&selected, shell_fd_range_below(10),
                                      low_mode ? 0 : 1, low_mode ? 0 : 2)))
      continue;
    dep_route_set_t slots = {0};
    if (!dep_allocation_rank_choices(state, journal, key, rank - low, &slots,
                                     minimum < 64 ? 64 : minimum))
      return false;
    shell_fd_occupancy_join(&choices->tail_domain, &selected);
    for (uint32_t i = 0; i < slots.count; i++) {
      uint32_t match = 0;
      while (match < tail.count &&
             tail.routes[match].value != slots.routes[i].value)
        match++;
      if (match == tail.count) {
        if (!dep_route_set_add(&tail, slots.routes[i]))
          return false;
        tail_domains[match] = (shell_fd_occupancy_t){0, 0};
        tail_lows[match] = -2;
      }
      shell_fd_occupancy_join(&tail_domains[match], &selected);
      tail_lows[match] = dep_low_state_join(tail_lows[match], low_mode);
    }
  }
  for (uint32_t i = 0; i < tail.count; i++)
    if (tail.routes[i].value == key) {
      choices->places.tail = true;
      hidden_count += 2;
      shell_fd_occupancy_join(&hidden, &tail_domains[i]);
      hidden_low = dep_low_state_join(hidden_low, tail_lows[i]);
    } else if (!dep_allocation_choice_add(choices, tail.routes[i],
                                          tail_domains[i], tail_lows[i]))
      return false;
  /* One unobserved place is an exact descriptor, not a private identity. */
  if (hidden_count == 1) {
    choices->places = (shell_fd_allocation_t){0, false};
    return dep_allocation_choice_add(
        choices, (dep_fd_route_t){DEP_ROUTE_ALIAS, hidden_fd}, hidden_only,
        hidden_only_low);
  }
  if (!hidden_count)
    return true;
  return dep_allocation_reuse_hidden(state, journal, choices->places, hidden,
                                     hidden_low, choices) &&
         dep_allocation_choice_add(choices,
                                   (dep_fd_route_t){DEP_ROUTE_ALIAS, key},
                                   hidden, hidden_low);
}

static SHELL_NONNULL(1, 2) bool dep_process_add_choice(
    dep_route_set_t *slots, shell_fd_occupancy_t *domains, uint32_t slot,
    shell_fd_occupancy_t domain) {
  uint32_t i = 0;
  for (; i < slots->count; i++)
    if (slots->routes[i].value == slot)
      break;
  if (i == slots->count) {
    if (!dep_route_set_add(slots, (dep_fd_route_t){DEP_ROUTE_ALIAS, slot}))
      return false;
    domains[i] = domain;
  } else {
    shell_fd_occupancy_join(&domains[i], &domain);
  }
  return true;
}

/* The descriptor a process substitution's parent end can occupy. Each
 * observable place is its own choice; unobserved places, including the tail,
 * share the private slot key with its possible places. domains[i] is the
 * occupancy after the end is installed on that choice. *places receives the
 * private slot's places. */
static SHELL_NONNULL(1, 2, 3, 4, 6, 7) bool dep_process_choices(
    const dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_fd_op_t *op, dep_route_set_t *slots, uint32_t key,
    shell_fd_occupancy_t *domains, shell_fd_allocation_t *places) {
  bool observable[64] = {false};
  for (uint32_t i = 0; i < journal->observable_fd_count; i++)
    if (journal->observable_fds[i] < 64 &&
        (journal->observable_fds[i] >= DEP_BASH_VARREDIR_MIN_FD ||
         (op->process_observed_low & (1u << journal->observable_fds[i]))))
      observable[journal->observable_fds[i]] = true;
  shell_fd_occupancy_t domain = dep_fd_occupancy_masks(state, journal);
  unsigned rank = op->access == DEP_FD_ACCESS_READ ? 1 : 2;
  shell_fd_allocation_t end = shell_fd_pipe_end(&domain, rank);
  *places = (shell_fd_allocation_t){0, false};
  shell_fd_occupancy_t hidden = {0, 0}, hidden_only = {0, 0};
  unsigned hidden_count = 0;
  uint32_t hidden_fd = 0;
  for (uint64_t rest = end.candidates; rest; rest &= rest - 1) {
    uint32_t fd = shell_fd_lowest(rest);
    /* The tables that place the end here, with the end installed. */
    shell_fd_occupancy_t after = domain;
    if (!shell_fd_occupancy_pipe_select(&after, fd, rank))
      continue;
    shell_fd_occupancy_set(&after, fd, false, true);
    if (observable[fd]) {
      if (!dep_process_add_choice(slots, domains, fd, after))
        return false;
    } else {
      hidden_count++;
      hidden_fd = fd;
      hidden_only = after;
      places->candidates |= UINT64_C(1) << fd;
      shell_fd_occupancy_join(&hidden, &after);
    }
  }
  if (end.tail) {
    dep_route_set_t fallback = {.ready = true};
    for (unsigned low = 0; low < rank; low++)
      if (shell_fd_count_possible(&domain, UINT64_MAX, low, low) &&
          !dep_allocation_rank_choices(state, journal, key, rank - low,
                                       &fallback, 64))
        return false;
    for (uint32_t i = 0; i < fallback.count; i++)
      if (fallback.routes[i].value >= 64) {
        if (fallback.routes[i].value == key) {
          places->tail = true;
          hidden_count += 2;
          shell_fd_occupancy_join(&hidden, &domain);
        } else if (!dep_process_add_choice(slots, domains,
                                           fallback.routes[i].value, domain))
          return false;
      }
  }
  /* One unobserved place is an exact descriptor. */
  if (hidden_count == 1) {
    *places = (shell_fd_allocation_t){0, false};
    return dep_process_add_choice(slots, domains, hidden_fd, hidden_only);
  }
  if (hidden_count) {
    dep_allocation_choices_t reuse = {0};
    if (!dep_allocation_reuse_hidden(state, journal, *places, hidden, -1,
                                     &reuse) ||
        !dep_process_add_choice(slots, domains, key, hidden))
      return false;
    for (uint32_t i = 0; i < reuse.count; i++)
      if (!dep_process_add_choice(slots, domains, reuse.slots[i].value,
                                  reuse.domains[i]))
        return false;
  }
  return slots->count != 0;
}

static SHELL_NONNULL(1, 2,
                     3) bool dep_process_open(dep_route_state_t *state,
                                              dep_route_journal_t *journal,
                                              const dep_fd_op_t *op) {
  uint32_t key = dep_process_key(journal, op, true);
  if (key == SHELL_DEP_FD_NONE)
    return false;
  uint32_t guard_key = SHELL_DEP_FD_NONE;
  if (op->guard) {
    if (!dep_process_guard_prepare(state, journal, op->guard))
      return false;
    guard_key = dep_process_guard_key(journal, op->guard, false);
  }
  dep_route_state_t result = {0};
  bool first = true;
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_set_t installed = dep_fd_raw_fact(
        &one, journal, dep_fd_numeric(key), DEP_FD_ACCESS_PROCESS_SLOT);
    if (!installed.count && op->guard &&
        !dep_fd_raw_fact(&one, journal, dep_fd_numeric(guard_key),
                         DEP_FD_ACCESS_PROCESS_SLOT)
             .routes[0]
             .value) {
      dep_route_set_t skipped = {.ready = true};
      dep_route_set_set(&skipped,
                        (dep_fd_route_t){DEP_ROUTE_ABSENT, UINT32_MAX});
      if (!dep_route_state_store_access(&one, journal, dep_fd_numeric(key),
                                        DEP_FD_ACCESS_PROCESS_SLOT, skipped))
        return false;
      if (first) {
        result = one;
        first = false;
      } else if (!dep_route_state_add_root(&result, journal, one.root))
        return false;
      continue;
    }
    /* The possible places of one end, in the low-interval views of this
     * version with one inherited case, are one joined version, not a version
     * per place. */
    dep_route_state_t views[SHELL_FD_PARTS], joined[2] = {{0}};
    uint8_t origins[SHELL_FD_PARTS] = {0};
    uint32_t view_count = 1;
    bool have_joined[2] = {false, false};
    views[0] = one;
    if (!installed.count &&
        !dep_fd_domain_views(&one, journal, views, origins, &view_count))
      return false;
    for (uint32_t view = 0; view < view_count; view++) {
      unsigned origin = origins[view];
      dep_route_set_t choices = {.ready = true};
      shell_fd_occupancy_t domains[SHELL_DEP_TIME_MAX_EXTERNAL_FDS];
      shell_fd_allocation_t places = {0, false};
      if (installed.count)
        choices = installed;
      else if (!dep_process_choices(&views[view], journal, op, &choices, key,
                                    domains, &places))
        return false;
      for (uint32_t i = 0; i < choices.count; i++) {
        dep_route_state_t branch = views[view];
        if (!installed.count) {
          /* The choice's occupancy already includes this end. */
          if (!dep_allocation_select(&branch, journal, domains[i], -1))
            return false;
          dep_fd_ref_t fd = dep_fd_numeric(choices.routes[i].value);
          if (fd.value > SHELL_DEP_FD_MAX) {
            uint32_t selector = dep_allocation_selector(journal, key);
            if (!selector)
              return false;
            dep_route_set_t identity = dep_slot_places_fact(selector, places);
            if (!dep_route_state_store_access(&branch, journal,
                                              dep_fd_numeric(key),
                                              DEP_FD_ACCESS_SELECTOR, identity))
              return false;
            if (!dep_fd_raw_fact(&one, journal, fd, DEP_FD_ACCESS_SELECTOR)
                     .count &&
                !dep_route_state_store_access(&branch, journal, fd,
                                              DEP_FD_ACCESS_SELECTOR, identity))
              return false;
          }
          for (unsigned access = DEP_FD_ACCESS_READ;
               access <= DEP_FD_ACCESS_BINDING; access <<= 1) {
            dep_route_set_t fact = {.ready = true};
            dep_route_set_set(
                &fact,
                access == DEP_FD_ACCESS_BINDING
                    ? (dep_fd_route_t){DEP_ROUTE_INHERITED, UINT32_MAX}
                : access == op->access
                    ? (dep_fd_route_t){DEP_ROUTE_DYNAMIC, op->edge_index}
                    : (dep_fd_route_t){DEP_ROUTE_UNAVAILABLE, UINT32_MAX});
            /* The selected occupancy already includes this pipe end; publish
             * its binding without updating the occupancy again. */
            if (!(access == DEP_FD_ACCESS_BINDING
                      ? dep_route_state_append_one(
                            &branch, journal, fd, (dep_fd_access_t)access, fact)
                      : dep_route_state_store_allocated(&branch, journal, fd,
                                                        (dep_fd_access_t)access,
                                                        fact)))
              return false;
          }
          dep_route_set_t selected = {.ready = true};
          dep_route_set_set(
              &selected,
              (dep_fd_route_t){DEP_ROUTE_ALIAS, choices.routes[i].value});
          if (!dep_route_state_store_access(
                  &branch, journal, dep_fd_numeric(key),
                  DEP_FD_ACCESS_PROCESS_SLOT, selected))
            return false;
          if (!dep_process_owned_set(&branch, journal, fd, true))
            return false;
        }
        if (!dep_route_state_join_choice(&joined[origin], &have_joined[origin],
                                         &branch, journal))
          return false;
      }
    }
    if (!dep_fd_factor_choices(joined, have_joined, journal))
      return false;
    for (unsigned origin = 0; origin < 2; origin++) {
      if (!have_joined[origin])
        continue;
      if (first) {
        result = joined[origin];
        first = false;
      } else if (!dep_route_state_add_root(&result, journal,
                                           joined[origin].root))
        return false;
    }
  }
  dep_route_state_inherit(&result, state);
  *state = result;
  return !first;
}

static SHELL_NONNULL(1, 2, 3) bool dep_process_close_owner(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_parse_context_t *context, uint32_t owner) {
  if (!context->process_routes->track[owner] ||
      !context->process_routes->first[owner])
    return true;
  uint32_t order[SHELL_DEP_MAX_EDGES * 2], count = 0;
  for (uint32_t i = context->process_routes->first[owner]; i;
       i = context->process_routes->entries[i - 1].next)
    if (context->process_routes->entries[i - 1].temporary)
      order[count++] = i - 1;
  dep_route_state_t result = {0};
  bool first = true;
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    for (uint32_t i = count; i-- != 0;) {
      const dep_process_route_t *route =
          &context->process_routes->entries[order[i]];
      dep_fd_op_t op = {.pos = route->position, .fd_name = route->source};
      uint32_t key = dep_process_key(journal, &op, false);
      if (key == SHELL_DEP_FD_NONE)
        continue;
      dep_route_set_t slots = dep_fd_raw_fact(
          &one, journal, dep_fd_numeric(key), DEP_FD_ACCESS_PROCESS_SLOT);
      /* The end occupies exactly one of its possible places. Closing it is a
       * strong update only when there is one; otherwise each place may now be
       * closed or still hold what it held. */
      uint32_t places = 0;
      for (uint32_t slot = 0; slot < slots.count; slot++)
        places += slots.routes[slot].kind == DEP_ROUTE_ALIAS;
      for (uint32_t slot = 0; slot < slots.count; slot++) {
        if (slots.routes[slot].kind != DEP_ROUTE_ALIAS)
          continue;
        dep_fd_ref_t fd = dep_fd_numeric(slots.routes[slot].value);
        if (!dep_process_owned(&one, journal, fd))
          continue;
        /* A place that may not hold this end keeps what it held: the same
         * byte route can be a duplicate there, so only an exact place is
         * replaced. */
        for (unsigned access = DEP_FD_ACCESS_READ;
             access <= DEP_FD_ACCESS_BINDING; access <<= 1) {
          dep_route_set_t closed =
              places == 1
                  ? (dep_route_set_t){.ready = true}
                  : dep_fd_raw_fact(&one, journal, fd, (dep_fd_access_t)access);
          if (!dep_route_set_add(
                  &closed, (dep_fd_route_t){DEP_ROUTE_CLOSED, UINT32_MAX}) ||
              !dep_route_state_store_access(&one, journal, fd,
                                            (dep_fd_access_t)access, closed))
            return false;
        }
      }
      for (uint32_t slot = 0; slot < slots.count; slot++)
        if (slots.routes[slot].kind == DEP_ROUTE_ALIAS &&
            !dep_process_owned_set(
                &one, journal, dep_fd_numeric(slots.routes[slot].value), false))
          return false;
      if (!dep_route_state_store_access(&one, journal, dep_fd_numeric(key),
                                        DEP_FD_ACCESS_SELECTOR,
                                        (dep_route_set_t){.ready = true}))
        return false;
      if (slots.count &&
          !dep_route_state_store_access(&one, journal, dep_fd_numeric(key),
                                        DEP_FD_ACCESS_PROCESS_SLOT,
                                        (dep_route_set_t){.ready = true}))
        return false;
      /* Guard choices have the same owner lifetime as its expansion-created
       * pipes. Retaining them would correlate unrelated later commands and
       * multiply versions after all observable descriptor effects agree. */
      for (const dep_process_guard_t *guard = route->guard; guard;
           guard = guard->parent) {
        uint32_t guard_key = dep_process_guard_key(journal, guard, false);
        if (guard_key == SHELL_DEP_FD_NONE ||
            !dep_fd_raw_fact(&one, journal, dep_fd_numeric(guard_key),
                             DEP_FD_ACCESS_PROCESS_SLOT)
                 .count)
          break;
        if (!dep_route_state_store_access(
                &one, journal, dep_fd_numeric(guard_key),
                DEP_FD_ACCESS_PROCESS_SLOT, (dep_route_set_t){.ready = true}))
          return false;
      }
    }
    dep_route_state_inherit(&one, state);
    if (first) {
      result = one;
      first = false;
    } else if (!dep_fd_merge_versions(&result, &one, journal))
      return false;
  }
  *state = result;
  return !first;
}

/* Adds to `saved` the no-save undo records of a descriptor with `binding`:
 * ABSENT carrying each failed-open cause behind a missing binding (see
 * dep_fd_binding_exists), so the undo that closes the descriptor again keeps
 * that cause. A plain miss adds a plain ABSENT. */
static SHELL_NONNULL(1, 2) bool dep_fd_add_free_saves(
    const dep_route_set_t *binding, dep_route_set_t *saved) {
  bool plain = binding->truncated;
  for (uint32_t i = 0; i < binding->count; i++) {
    dep_fd_route_t route = binding->routes[i];
    if (route.kind != DEP_ROUTE_CLOSED && route.kind != DEP_ROUTE_UNAVAILABLE &&
        route.kind != DEP_ROUTE_ABSENT)
      continue;
    if (route.value == UINT32_MAX)
      plain = true;
    else if (!dep_route_set_add(
                 saved, (dep_fd_route_t){DEP_ROUTE_ABSENT, route.value}))
      return false;
  }
  return !plain || dep_route_set_add(
                       saved, (dep_fd_route_t){DEP_ROUTE_ABSENT, UINT32_MAX});
}

/* Each immutable version owns either one selected scratch slot or no save.
 * Keep that ownership separate from the contents of a slot on another path;
 * disposing an undo must never revive its own temporary saved copy. */
static SHELL_NONNULL(1, 2, 3, 4) bool dep_prepare_numeric_undo_one(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_fd_op_t *op, const dep_fd_op_t *key_op, uint32_t rank,
    dep_allocation_role_t role, bool optional) {
  bool symbolic_target = op->fd > SHELL_DEP_FD_MAX &&
                         op->fd < SHELL_DEP_FD_NAMED &&
                         dep_fd_raw_fact(state, journal, dep_fd_numeric(op->fd),
                                         DEP_FD_ACCESS_SELECTOR)
                             .count;
  bool observable = op->undo_observable &&
                    (symbolic_target || (journal->scratch_observable &&
                                         journal->observable_fd_count &&
                                         op->fd <= SHELL_DEP_FD_MAX));
  dep_fd_ref_t target = dep_fd_numeric(op->fd);
  dep_route_set_t binding =
      dep_fd_fact(state, journal, target, DEP_FD_ACCESS_BINDING);
  bool may_be_free = false, may_be_live = false;
  for (uint32_t route = 0; route < binding.count; route++) {
    switch (binding.routes[route].kind) {
    case DEP_ROUTE_CLOSED:
    case DEP_ROUTE_ABSENT:
    case DEP_ROUTE_UNAVAILABLE:
      may_be_free = true;
      break;
    case DEP_ROUTE_UNSEEN:
    case DEP_ROUTE_DYNAMIC:
      may_be_free = may_be_live = true;
      break;
    default:
      may_be_live = true;
      break;
    }
  }

  dep_route_state_t before = *state, result = {0};
  uint32_t undo_key = dep_undo_slot(journal, key_op, role, true);
  if (undo_key == SHELL_DEP_FD_NONE)
    return false;
  {
    dep_route_set_t entry = {0};
    dep_route_set_set(&entry,
                      (dep_fd_route_t){DEP_ROUTE_INHERITED, before.root});
    dep_route_set_t physical = {0};
    dep_route_set_set(&physical, (dep_fd_route_t){DEP_ROUTE_ALIAS, op->fd});
    dep_route_set_t scratch =
        dep_fd_raw_fact(state, journal, target, DEP_FD_ACCESS_SCRATCH);
    /* exec restores a target that was a shell-owned scratch descriptor. A
     * place only marked as possibly holding a save may or may not be one:
     * record both answers. */
    bool definite_scratch = false, possible_scratch = false;
    for (uint32_t i = 0; i < scratch.count; i++) {
      definite_scratch |= scratch.routes[i].kind != DEP_ROUTE_ALIAS;
      possible_scratch |= scratch.routes[i].kind == DEP_ROUTE_ALIAS;
    }
    dep_route_set_t exec_restore = {0};
    dep_route_set_set(
        &exec_restore,
        (dep_fd_route_t){DEP_ROUTE_INHERITED,
                         op->kind != DEP_FD_OP_CLOSE && definite_scratch});
    if (op->kind != DEP_FD_OP_CLOSE && possible_scratch && !definite_scratch)
      (void)dep_route_set_add(&exec_restore,
                              (dep_fd_route_t){DEP_ROUTE_INHERITED, 1});
    if (!dep_route_state_store_access(&before, journal,
                                      dep_fd_numeric(undo_key),
                                      DEP_FD_ACCESS_UNDO_ENTRY, entry) ||
        !dep_route_state_store_access(&before, journal,
                                      dep_fd_numeric(undo_key),
                                      DEP_FD_ACCESS_UNDO_TARGET, physical) ||
        !dep_route_state_store_access(&before, journal,
                                      dep_fd_numeric(undo_key),
                                      DEP_FD_ACCESS_UNDO_EXEC, exec_restore))
      return false;
  }
  if (!observable) {
    dep_route_set_t saved = {0};
    if (may_be_live &&
        !dep_route_set_add(&saved, (dep_fd_route_t){DEP_ROUTE_ALIAS, undo_key}))
      return false;
    if ((may_be_free || optional) && !dep_fd_add_free_saves(&binding, &saved))
      return false;
    if (!dep_route_state_store_access(&before, journal,
                                      dep_fd_numeric(undo_key),
                                      DEP_FD_ACCESS_SAVED, saved))
      return false;
    if (op->kind == DEP_FD_OP_MOVE && may_be_live && may_be_free) {
      dep_route_state_t live = before, free = before;
      dep_route_set_t fact = {0};
      dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_ALIAS, undo_key});
      if (!dep_route_state_store_access(&live, journal,
                                        dep_fd_numeric(undo_key),
                                        DEP_FD_ACCESS_SAVED, fact))
        return false;
      bool possible;
      if (!dep_fd_assume_binding(&live, journal, op->fd, &possible, false))
        return false;
      fact = (dep_route_set_t){.ready = true};
      if (!dep_fd_add_free_saves(&binding, &fact) ||
          !dep_route_state_store_access(&free, journal,
                                        dep_fd_numeric(undo_key),
                                        DEP_FD_ACCESS_SAVED, fact))
        return false;
      /* The save and no-save paths are one joined version: the undo
       * restores from the union of their saved facts. */
      if (!dep_fd_assume_binding(&free, journal, op->fd, &possible, true) ||
          !dep_fd_join(&live, &free, journal))
        return false;
      *state = live;
      return true;
    }
    *state = before;
    return true;
  }
  bool have_result = false;
  if (may_be_free || optional) {
    dep_route_state_t unsaved = before;
    dep_route_set_t absent = {.ready = true};
    if (!dep_fd_add_free_saves(&binding, &absent) ||
        !dep_route_state_store_access(&unsaved, journal,
                                      dep_fd_numeric(undo_key),
                                      DEP_FD_ACCESS_SAVED, absent))
      return false;
    if (may_be_free && !optional) {
      dep_route_set_t closed = {0};
      dep_route_set_set(&closed,
                        (dep_fd_route_t){DEP_ROUTE_CLOSED, UINT32_MAX});
      bool possible;
      if (!dep_fd_assume_binding(&unsaved, journal, op->fd, &possible, true))
        return false;
      for (uint32_t access = DEP_FD_ACCESS_READ;
           access <= DEP_FD_ACCESS_BINDING; access <<= 1)
        if (!dep_route_state_store_access(&unsaved, journal, target,
                                          (dep_fd_access_t)access, closed))
          return false;
    }
    result = unsaved;
    have_result = true;
  }
  if (may_be_live) {
    dep_allocation_choices_t slots = {0};
    dep_route_state_t occupied = before;
    dep_route_set_t live = {0};
    dep_route_set_set(&live, (dep_fd_route_t){DEP_ROUTE_INHERITED, UINT32_MAX});
    uint32_t minimum = DEP_BASH_VARREDIR_MIN_FD;
    uint32_t source_fd = op->target_fd;
    shell_fd_allocation_t source_places = {0, false};
    bool source_private = false;
    if (source_fd == SHELL_DEP_FD_NAMED) {
      dep_route_set_t source =
          dep_fd_raw_fact(&before, journal,
                          (dep_fd_ref_t){.name = op->target_fd_name,
                                         .value = source_fd,
                                         .name_len = op->target_fd_name_len},
                          DEP_FD_ACCESS_BINDING);
      if (source.count == 1 && source.routes[0].kind == DEP_ROUTE_ALIAS)
        source_fd = source.routes[0].value;
    }
    if (role == DEP_ALLOCATION_TARGET_UNDO && dep_fd_op_copies(op->kind) &&
        source_fd >= minimum && source_fd <= SHELL_DEP_FD_MAX)
      minimum = source_fd + 1;
    if (role == DEP_ALLOCATION_TARGET_UNDO && dep_fd_op_copies(op->kind) &&
        source_fd > SHELL_DEP_FD_MAX && source_fd < SHELL_DEP_FD_NAMED) {
      dep_route_set_t identity = dep_fd_raw_fact(
          &before, journal, dep_fd_numeric(source_fd), DEP_FD_ACCESS_SELECTOR);
      if (identity.count) {
        source_places = dep_slot_places(&identity);
        source_private = true;
      }
    }
    bool possible;
    int low_mode = op->resets_descriptor &&
                           (op->kind == DEP_FD_OP_DOCUMENT ||
                            op->kind == DEP_FD_OP_DYNAMIC) &&
                           rank
                       ? (int)rank - 1
                       : -1;
    if (!dep_fd_assume_binding(&occupied, journal, op->fd, &possible, false))
      return false;
    /* Every branch restores from the same entry, so the joined version has
     * one: its binding includes the no-save world, which only adds
     * possibilities to the restored target. */
    if (!dep_allocation_domain_choices(
            &occupied, journal, undo_key, rank, minimum, low_mode,
            source_private ? &source_places : NULL, &slots))
      return false;
    /* With several possible places, the saved descriptor lives on the
     * operation's own key, whose places are all of them, and each candidate
     * is only marked as possibly holding it. Reads of a marked place see the
     * save as well; disposal closes the key and clears the marks, so no place
     * keeps a copy of the saved descriptor afterwards. */
    if (slots.count > 1) {
      dep_route_state_t saved = occupied;
      shell_fd_occupancy_t domain = {0, 0};
      shell_fd_allocation_t places = slots.places;
      int low = -2;
      for (uint32_t slot = 0; slot < slots.count; slot++) {
        shell_fd_occupancy_join(&domain, &slots.domains[slot]);
        low = low == -2 || low == slots.low_states[slot]
                  ? slots.low_states[slot]
                  : -1;
        uint32_t place = slots.slots[slot].value;
        if (place < 64)
          places.candidates |= UINT64_C(1) << place;
        else if (place != undo_key)
          places.tail = true;
      }
      if (!dep_allocation_select(&saved, journal, domain, low))
        return false;
      dep_fd_ref_t holder = dep_fd_numeric(undo_key);
      dep_route_set_t undo = {0}, mark = {0};
      dep_route_set_set(&undo, (dep_fd_route_t){DEP_ROUTE_ALIAS, undo_key});
      if (!dep_route_state_store_access(
              &saved, journal, holder, DEP_FD_ACCESS_SELECTOR,
              dep_slot_places_fact(slots.selector, places)))
        return false;
      for (uint32_t access = DEP_FD_ACCESS_READ;
           access <= DEP_FD_ACCESS_BINDING; access <<= 1) {
        dep_route_set_t routes = access == DEP_FD_ACCESS_BINDING
                                     ? live
                                     : dep_fd_raw_fact(&before, journal, target,
                                                       (dep_fd_access_t)access);
        if (!dep_route_state_store_access(&saved, journal, holder,
                                          (dep_fd_access_t)access, routes))
          return false;
      }
      if (!dep_route_state_store_access(&saved, journal, holder,
                                        DEP_FD_ACCESS_SAVED, undo) ||
          !dep_route_state_store_access(&saved, journal, holder,
                                        DEP_FD_ACCESS_SCRATCH, live))
        return false;
      journal->save_marks = true;
      for (uint32_t slot = 0; slot < slots.count; slot++) {
        uint32_t place = slots.slots[slot].value;
        if (place == undo_key)
          continue;
        mark = dep_fd_raw_fact(&saved, journal, dep_fd_numeric(place),
                               DEP_FD_ACCESS_SCRATCH);
        if (!dep_route_set_add(&mark,
                               (dep_fd_route_t){DEP_ROUTE_ALIAS, undo_key}) ||
            !dep_route_state_store_access(&saved, journal,
                                          dep_fd_numeric(place),
                                          DEP_FD_ACCESS_SCRATCH, mark))
          return false;
      }
      if (!have_result) {
        result = saved;
        have_result = true;
      } else if (!dep_fd_join(&result, &saved, journal)) {
        return false;
      }
    }
    /* Saved descriptors have the target's capabilities. The chosen slot is
     * live only in this version, so later allocation and cleanup retain the
     * same physical identity instead of an independent union of candidates. */
    for (uint32_t slot = 0; slots.count == 1 && slot < slots.count; slot++) {
      dep_route_state_t saved = occupied;
      if (!dep_allocation_select_slot(&saved, journal, &slots, slot))
        return false;
      dep_route_set_t undo = {0};
      dep_route_set_set(&undo, slots.slots[slot]);
      dep_fd_ref_t scratch = dep_fd_numeric(slots.slots[slot].value);
      /* The selection predicate already records preceding occupancy, including
       * a named source's path-dependent F_DUPFD minimum. Do not assign extra
       * descriptor facts independently of that relation. */
      for (uint32_t access = DEP_FD_ACCESS_READ;
           access <= DEP_FD_ACCESS_BINDING; access <<= 1) {
        dep_route_set_t routes = access == DEP_FD_ACCESS_BINDING
                                     ? live
                                     : dep_fd_raw_fact(&before, journal, target,
                                                       (dep_fd_access_t)access);
        if (!dep_route_state_store_allocated(&saved, journal, scratch,
                                             (dep_fd_access_t)access, routes))
          return false;
      }
      if (!dep_route_state_store_access(&saved, journal,
                                        dep_fd_numeric(undo_key),
                                        DEP_FD_ACCESS_SAVED, undo) ||
          !dep_route_state_store_access(&saved, journal, scratch,
                                        DEP_FD_ACCESS_SCRATCH, live))
        return false;
      /* Every possible save place, and the no-save path, are one joined
       * version: the undo restores from the union of their saved facts. */
      if (!have_result) {
        result = saved;
        have_result = true;
      } else if (!dep_fd_join(&result, &saved, journal)) {
        return false;
      }
    }
  }
  dep_route_state_inherit(&result, &before);
  *state = result;
  return have_result;
}

/* state contains selected execution versions; optional is the no-save choice
 * imposed by an enclosing move. rank is 1, or 2 when a full low interval
 * makes the save's temporary resource open consume the first high slot. */
static SHELL_NONNULL(1, 2, 3, 4) bool dep_prepare_numeric_undo(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_fd_op_t *op, const dep_fd_op_t *key_op, uint32_t rank,
    dep_allocation_role_t role, bool optional) {
  if (op->undo_mode == DEP_UNDO_CHILD || op->paired_open ||
      op->kind == DEP_FD_OP_IDENTITY || dep_fd_op_numeric_self_dup(op))
    return true;
  dep_fd_op_t effective = *op;
  if (!effective.undo_observable) {
    dep_route_set_t scratch = dep_fd_raw_fact(
        state, journal, dep_fd_numeric(op->fd), DEP_FD_ACCESS_SCRATCH);
    if (!scratch.count)
      return true;
    /* An inner command can overwrite a save owned by an enclosing compound.
     * Its cleanup is observable even without a numeric reader in this owner. */
    effective.undo_observable = true;
  }
  if (!journal->scratch_observable && !journal->named_closes &&
      op->undo_mode != DEP_UNDO_COMPOUND && op->kind != DEP_FD_OP_MOVE &&
      key_op->fd != SHELL_DEP_FD_NAMED && role != DEP_ALLOCATION_MOVE_UNDO)
    return true;
  dep_route_state_t before = *state, result = {0};
  bool have_result = false;
  dep_route_iterator_t iterator = dep_route_iterator(&before);
  uint32_t source_root;
  while (dep_route_next(&iterator, journal, &source_root)) {
    dep_route_state_t one = dep_route_state_single(source_root);
    dep_route_state_inherit(&one, &before);
    if (!dep_prepare_numeric_undo_one(&one, journal, &effective, key_op, rank,
                                      role, optional))
      return false;
    dep_route_iterator_t branches = dep_route_iterator(&one);
    uint32_t root;
    while (dep_route_next(&branches, journal, &root)) {
      if (!have_result) {
        result = dep_route_state_single(root);
        have_result = true;
      } else if (!dep_route_state_add_root(&result, journal, root)) {
        return false;
      }
    }
    result.truncated |= one.truncated;
  }
  dep_route_state_inherit(&result, &before);
  *state = result;
  return have_result;
}

/* The source close belongs to the MOVE, with the same lexical ordering key.
 * It never performs a second operand expansion or source traversal. */
static SHELL_NONNULL(1) dep_fd_op_t dep_fd_move_close(const dep_fd_op_t *op) {
  return (dep_fd_op_t){.pos = op->pos,
                       .kind = DEP_FD_OP_CLOSE,
                       .fd = op->target_fd,
                       .fd_name = op->target_fd_name,
                       .fd_name_len = op->target_fd_name_len,
                       .target_fd = SHELL_DEP_FD_NONE,
                       .edge_index = UINT32_MAX,
                       .access = DEP_FD_ACCESS_BOTH,
                       .undo_observable = op->undo_observable,
                       .undo_mode = op->undo_mode};
}

/* The undo frame needs every physical slot reached by this operation across
 * execution paths. Per-path entry and slot facts remain in the journal;
 * this bounded union only selects which descriptors the frame must restore.
 * allocation is a prepared operation key in journal->arena->allocations. */
static SHELL_NONNULL(1, 3) bool dep_record_closed_slots(
    dep_route_journal_t *journal, uint32_t allocation,
    const dep_route_set_t *slots) {
  dep_allocation_t *record =
      &journal->arena->allocations[allocation - SHELL_DEP_FD_MAX - 1];
  dep_route_set_t all_slots = *slots;
  if (record->closed_slots) {
    const dep_route_set_t *prior =
        &journal->arena->snapshots[record->closed_slots - 1];
    for (uint32_t slot = 0; slot < prior->count; slot++)
      if (!dep_route_set_add(&all_slots, prior->routes[slot]))
        return false;
  }
  uint32_t snapshot = dep_route_set_intern(journal, &all_slots);
  if (!snapshot)
    return false;
  record->closed_slots = snapshot;
  return true;
}

static SHELL_NONNULL(1, 2) bool dep_route_state_apply_one(
    dep_route_state_t *route_state, dep_route_journal_t *changes,
    const dep_fd_op_t *ops, uint32_t op_count, const dep_fd_route_t *allocated,
    const dep_domain_collection_t *collection) {
  if (op_count == 0)
    return !route_state->truncated;
  if (dep_route_state_count(route_state) > 1) {
    dep_route_state_t before = *route_state, result = {0};
    bool have_result = false;
    dep_route_iterator_t iterator = dep_route_iterator(&before);
    uint32_t source_root;
    while (dep_route_next(&iterator, changes, &source_root)) {
      dep_route_state_t one = dep_route_state_single(source_root);
      dep_route_state_inherit(&one, &before);
      dep_domain_collection_t branch_pins = {.roots = {&result, &one},
                                             .remaining = &iterator,
                                             .parent = collection};
      if (collection) {
        branch_pins.workspace = collection->workspace;
        branch_pins.frame = collection->frame;
      }
      if (!dep_route_state_apply_one(&one, changes, ops, op_count, allocated,
                                     collection ? &branch_pins : NULL))
        return false;
      dep_route_iterator_t branches = dep_route_iterator(&one);
      uint32_t root;
      while (dep_route_next(&branches, changes, &root)) {
        if (!have_result) {
          result = dep_route_state_single(root);
          have_result = true;
        } else if (!dep_route_state_add_root(&result, changes, root)) {
          return false;
        }
      }
      result.truncated |= one.truncated;
    }
    dep_route_state_inherit(&result, &before);
    *route_state = result;
    return have_result;
  }
  dep_route_state_t after = *route_state;
  bool complete = true;

  for (uint32_t i = 0; i < op_count; i++) {
    dep_fd_op_t scoped = ops[i];
    scoped.undo_mode = dep_setup_mode(&after, changes, scoped.undo_mode);
    const dep_fd_op_t *op = &scoped;
    dep_route_state_t before_operation = after;
    /* Move publication and restoration consume the operation's entry after
     * allocation/refinement can collect older versions. Retain both that
     * immutable entry and the evolving map for the entire operation. */
    dep_domain_collection_t operation_pins = {
        .roots = {&before_operation, &after}, .parent = collection};
    if (collection) {
      operation_pins.workspace = collection->workspace;
      operation_pins.frame = collection->frame;
    }
    const dep_domain_collection_t *operation_collection =
        collection ? &operation_pins : NULL;
    dep_fd_op_t effective = dep_fd_effective_operation(op, &after, changes);
    if (effective.kind == DEP_FD_OP_IDENTITY)
      continue;
    if (op->kind == DEP_FD_OP_MOVE && effective.kind == DEP_FD_OP_CLOSE) {
      if (!dep_route_state_apply_one(&after, changes, &effective, 1, NULL,
                                     operation_collection))
        return false;
      continue;
    }
    if (op->kind == DEP_FD_OP_FAILED)
      continue;
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FD_OPERATIONS);
    dep_fd_ref_t target = {
        .name = op->fd_name, .value = op->fd, .name_len = op->fd_name_len};
    dep_route_set_t available =
        dep_fd_raw_fact(&after, changes, dep_fd_numeric(SHELL_DEP_FD_NONE),
                        DEP_FD_ACCESS_AVAILABLE);
    dep_route_set_t slots = {0};
    bool named = target.value == SHELL_DEP_FD_NAMED;
    bool indirect =
        named && (changes->observable_fd_count || changes->named_closes);
    /* A named reset reaches this leaf only after dep_route_state_apply has
     * selected its physical allocation. All other effective operations pass
     * no allocation and carry resets_descriptor == false. */
    if (named && op->resets_descriptor && op->kind != DEP_FD_OP_CLOSE) {
      if (!dep_read_note_assignment(&after, changes, target))
        return false;
      /* Allocation assigns the scalar during setup. A later redirect can
       * fail while retaining this binding and its assigned presence. */
      if ((dep_read_observation(&changes->read_observations, target) &
           DEP_READ_OBSERVE_PRESENCE) &&
          !dep_presence_store(&after, changes, target, SHELL_TEST_TRUE,
                              op->fd_name))
        return false;
    }
    if (named && op->resets_descriptor) {
      dep_route_set_set(
          &slots, indirect
                      ? *allocated
                      : (dep_fd_route_t){DEP_ROUTE_ALIAS, SHELL_DEP_FD_NAMED});
    } else if (named) {
      slots = dep_fd_raw_fact(&after, changes, target, DEP_FD_ACCESS_READ);
      dep_route_set_t identities = {0};
      for (uint32_t slot = 0; slot < slots.count; slot++)
        if (slots.routes[slot].kind == DEP_ROUTE_ALIAS &&
            !dep_route_set_add(&identities, slots.routes[slot]))
          return false;
      /* Imported variables may not retain an abstract slot identity. Adopt
       * one once, before a close or the second half of a paired open. */
      if (!identities.count && op->kind != DEP_FD_OP_CLOSE) {
        indirect = false;
      } else if (!identities.count) {
        uint32_t slot = dep_allocation_slot(changes, op);
        if (slot == SHELL_DEP_FD_NONE)
          return false;
        for (uint32_t access = DEP_FD_ACCESS_READ;
             access <= DEP_FD_ACCESS_BINDING; access <<= 1) {
          dep_route_set_t entry =
              dep_fd_raw_fact(&after, changes, target, (dep_fd_access_t)access);
          if (!dep_route_state_store_access(&after, changes,
                                            dep_fd_numeric(slot),
                                            (dep_fd_access_t)access, entry))
            return false;
        }
        before_operation = after;
        dep_route_set_set(&slots, (dep_fd_route_t){DEP_ROUTE_ALIAS, slot});
      } else
        slots = identities;
    } else {
      dep_route_set_set(&slots,
                        (dep_fd_route_t){DEP_ROUTE_ALIAS, target.value});
    }
    if (named && !indirect)
      dep_route_set_set(&slots,
                        (dep_fd_route_t){DEP_ROUTE_ALIAS, SHELL_DEP_FD_NAMED});
    if (named && indirect && op->resets_descriptor) {
      uint32_t key = dep_allocation_slot(changes, op);
      if (key == SHELL_DEP_FD_NONE ||
          !dep_route_state_store_access(&after, changes, dep_fd_numeric(key),
                                        DEP_FD_ACCESS_ALLOCATION_SLOTS, slots))
        return false;
    }
    if (named && op->kind == DEP_FD_OP_CLOSE) {
      for (uint32_t slot = 0; slot < slots.count; slot++) {
        dep_fd_op_t physical = *op;
        physical.fd = slots.routes[slot].value;
        physical.fd_name = NULL;
        physical.fd_name_len = 0;
        if (!dep_prepare_numeric_undo(&after, changes, &physical, op, 1,
                                      DEP_ALLOCATION_TARGET_UNDO, false))
          return false;
      }
      uint32_t allocation = dep_allocation_slot(changes, op);
      if (allocation == SHELL_DEP_FD_NONE)
        return false;
      if (!dep_record_closed_slots(changes, allocation, &slots))
        return false;
    }
    dep_route_set_t copied_routes[2] = {0}, copied_scratch = {.ready = true};
    if (dep_fd_op_copies(op->kind)) {
      dep_fd_ref_t source = {.name = op->target_fd_name,
                             .value = op->target_fd,
                             .name_len = op->target_fd_name_len};
      if (dep_fd_op_numeric_self_dup(op))
        continue;
      if (source.value == SHELL_DEP_FD_NAMED) {
        dep_route_set_t binding =
            dep_fd_raw_fact(&after, changes, source, DEP_FD_ACCESS_BINDING);
        if (binding.count == 1 && binding.routes[0].kind == DEP_ROUTE_ALIAS)
          source = dep_fd_numeric(binding.routes[0].value);
      }
      copied_scratch =
          dep_fd_raw_fact(&after, changes, source, DEP_FD_ACCESS_SCRATCH);
      for (unsigned direction = 0; direction < 2; direction++) {
        dep_route_set_t source_routes =
            dep_fd_fact(&after, changes, source,
                        direction ? DEP_FD_ACCESS_WRITE : DEP_FD_ACCESS_READ);
        for (uint32_t route = 0; route < source_routes.count; route++)
          if (source_routes.routes[route].kind != DEP_ROUTE_ABSENT &&
              source_routes.routes[route].kind != DEP_ROUTE_CLOSED &&
              !dep_route_set_add(&copied_routes[direction],
                                 source_routes.routes[route]))
            return false;
        copied_routes[direction].truncated = source_routes.truncated;
      }
    }
    if (op->resets_descriptor) {
      dep_route_set_t unavailable = {0};
      dep_route_set_set(&unavailable,
                        (dep_fd_route_t){DEP_ROUTE_UNAVAILABLE, UINT32_MAX});
      for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_WRITE;
           access <<= 1)
        if (!dep_route_state_store_access(
                &after, changes,
                named && !indirect ? target
                                   : dep_fd_numeric(slots.routes[0].value),
                (dep_fd_access_t)access, unavailable))
          return false;
    }

    dep_fd_access_t operation_access =
        dep_fd_op_copies(op->kind) || op->kind == DEP_FD_OP_CLOSE
            ? DEP_FD_ACCESS_BOTH
            : op->access;
    for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_WRITE;
         access <<= 1) {
      if ((operation_access & access) == 0)
        continue;
      dep_route_set_t routes = {0};
      if (dep_fd_op_copies(op->kind)) {
        routes = copied_routes[access == DEP_FD_ACCESS_READ ? 0 : 1];
      } else if (op->kind == DEP_FD_OP_DOCUMENT ||
                 op->kind == DEP_FD_OP_DYNAMIC) {
        dep_route_set_set(
            &routes, (dep_fd_route_t){
                         op->kind == DEP_FD_OP_DOCUMENT ? DEP_ROUTE_DOC
                                                        : DEP_ROUTE_DYNAMIC,
                         dep_resource_value(changes->depth, op->edge_index)});
      } else {
        dep_route_set_set(&routes,
                          (dep_fd_route_t){DEP_ROUTE_CLOSED, UINT32_MAX});
      }
      complete = complete && !routes.truncated;
      for (uint32_t slot = 0; slot < slots.count; slot++) {
        dep_fd_ref_t fd = named && !indirect
                              ? target
                              : dep_fd_numeric(slots.routes[slot].value);
        dep_route_set_t installed = routes;
        if (slots.count > 1 && (slots.routes[slot].value <= SHELL_DEP_FD_MAX ||
                                op->kind == DEP_FD_OP_CLOSE)) {
          dep_route_set_t prior = dep_fd_raw_fact(&before_operation, changes,
                                                  fd, (dep_fd_access_t)access);
          for (uint32_t route = 0; route < prior.count; route++)
            if (!dep_route_set_add(&installed, prior.routes[route]))
              return false;
        }
        if (!dep_route_state_store_binding(&after, changes, fd,
                                           (dep_fd_access_t)access, installed,
                                           NULL, allocated != NULL))
          return false;
      }
    }
    {
      dep_route_set_t bound = {0};
      dep_route_set_set(&bound, (dep_fd_route_t){op->kind == DEP_FD_OP_CLOSE
                                                     ? DEP_ROUTE_CLOSED
                                                     : DEP_ROUTE_INHERITED,
                                                 UINT32_MAX});
      for (uint32_t slot = 0; slot < slots.count; slot++) {
        uint32_t value = slots.routes[slot].value;
        dep_route_set_t installed = bound;
        dep_fd_ref_t fd = named && !indirect ? target : dep_fd_numeric(value);
        /* One of several places: it keeps its prior binding on the paths
         * where the descriptor went elsewhere. */
        bool weak = slots.count > 1 &&
                    (value <= SHELL_DEP_FD_MAX || op->kind == DEP_FD_OP_CLOSE);
        if (weak) {
          dep_route_set_t prior = dep_fd_raw_fact(&before_operation, changes,
                                                  fd, DEP_FD_ACCESS_BINDING);
          for (uint32_t route = 0; route < prior.count; route++)
            if (!dep_route_set_add(&installed, prior.routes[route]))
              return false;
        }
        if (!dep_route_state_store_binding(
                &after, changes, fd, DEP_FD_ACCESS_BINDING, installed,
                weak ? &bound : NULL, allocated != NULL))
          return false;
        /* dup2 clears close-on-exec; Bash propagates it from a scratch
         * source only to nonstandard descriptors. Opens and closes discard
         * the previous scratch identity. Capture UNDO_EXEC before this
         * mutation so exec cleanup can restore an overwritten shell save. */
        dep_route_set_t prior_scratch = dep_fd_raw_fact(
            &before_operation, changes, fd, DEP_FD_ACCESS_SCRATCH);
        dep_route_set_t scratch =
            value > 2 ? copied_scratch : (dep_route_set_t){.ready = true};
        if ((prior_scratch.count || scratch.count) &&
            !dep_route_state_store_access(&after, changes, fd,
                                          DEP_FD_ACCESS_SCRATCH, scratch))
          return false;
        if (changes->named_closes) {
          dep_route_set_t frame = dep_fd_raw_fact(
              &before_operation, changes, dep_fd_numeric(SHELL_DEP_FD_NONE),
              DEP_FD_ACCESS_ENTRY);
          if (!dep_route_state_store_access(&after, changes, fd,
                                            DEP_FD_ACCESS_SETUP_FRAME, frame))
            return false;
        }
        if (value >= DEP_BASH_VARREDIR_MIN_FD && value != SHELL_DEP_FD_NAMED) {
          if (op->kind == DEP_FD_OP_CLOSE) {
            /* Overflow matters only when a later allocation needs more
             * alternatives than the route budget, not for a plain close. */
            (void)dep_route_set_add(&available,
                                    (dep_fd_route_t){DEP_ROUTE_ALIAS, value});
          } else {
            /* Every candidate represented by this allocation is unavailable
             * to a later allocation in the same redirect list. It is either
             * the retained named slot, or the transient file-open slot which
             * Bash must consume before choosing the retained slot. */
            dep_allocation_remove_candidate(&available, value);
          }
        }
      }
    }
    if (named && indirect)
      for (uint32_t slot = 0; slot < slots.count; slot++)
        if (slots.routes[slot].kind == DEP_ROUTE_ALIAS &&
            slots.routes[slot].value > SHELL_DEP_FD_MAX)
          changes->arena
              ->allocations[slots.routes[slot].value - SHELL_DEP_FD_MAX - 1]
              .observations |=
              dep_read_observation(&changes->read_observations, target);
    if (named && indirect)
      for (uint32_t access = DEP_FD_ACCESS_READ;
           access <= DEP_FD_ACCESS_BINDING; access <<= 1)
        if (!dep_route_state_store_access(&after, changes, target,
                                          (dep_fd_access_t)access, slots))
          return false;
    if (named && op->resets_descriptor) {
      dep_route_set_t prior =
          dep_fd_raw_fact(&after, changes, target, DEP_FD_ACCESS_EFFECT_STATE);
      if (dep_effect_state_has(&prior, DEP_EFFECT_STATE_ORPHANED_ALLOCATION)) {
        dep_route_set_t retained = {.ready = true};
        if (!dep_route_state_store_access(&after, changes, target,
                                          DEP_FD_ACCESS_EFFECT_STATE, retained))
          return false;
      }
    }
    if (!dep_route_state_store_access(&after, changes,
                                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                                      DEP_FD_ACCESS_AVAILABLE, available))
      return false;
    if (named && op->resets_descriptor &&
        dep_fd_name_equal(op->fd_name, op->fd_name_len, "IFS", 3) &&
        !dep_ifs_store(&after, changes, DEP_IFS_DIGITS | DEP_IFS_SELF))
      return false;
    if (op->kind == DEP_FD_OP_MOVE) {
      /* Bash saves the source close only when the numeric destination was
       * already open (a newly allocated named destination is open too).
       * Retain this reached operation's entry and physical source identities
       * for publication/restoration, independently of later redirects. */
      uint32_t key = dep_allocation_slot(changes, op);
      if (key == SHELL_DEP_FD_NONE)
        return false;
      dep_route_set_t moved = {0};
      dep_fd_occupancy_t occupancy =
          named ? (dep_fd_occupancy_t){.may_be_occupied = true}
                : dep_fd_occupancy(&before_operation, changes, op->fd);
      dep_fd_op_t close = dep_fd_move_close(op);
      if (close.fd == SHELL_DEP_FD_NAMED) {
        moved = dep_fd_raw_fact(&before_operation, changes,
                                (dep_fd_ref_t){.name = close.fd_name,
                                               .value = close.fd,
                                               .name_len = close.fd_name_len},
                                DEP_FD_ACCESS_READ);
        for (uint32_t j = 0; j < moved.count; j++) {
          if (moved.routes[j].kind != DEP_ROUTE_ALIAS)
            continue;
          dep_fd_op_t physical = close;
          physical.fd = moved.routes[j].value;
          physical.fd_name = NULL;
          physical.fd_name_len = 0;
          if ((occupancy.may_be_occupied &&
               !dep_prepare_numeric_undo(&after, changes, &physical, &close, 1,
                                         DEP_ALLOCATION_MOVE_UNDO,
                                         occupancy.may_be_free)) ||
              !dep_route_state_apply_one(&after, changes, &physical, 1, NULL,
                                         operation_collection))
            return false;
        }
      } else {
        dep_route_set_set(&moved, (dep_fd_route_t){DEP_ROUTE_ALIAS, close.fd});
        if ((occupancy.may_be_occupied &&
             !dep_prepare_numeric_undo(&after, changes, &close, &close, 1,
                                       DEP_ALLOCATION_MOVE_UNDO,
                                       occupancy.may_be_free)) ||
            !dep_route_state_apply_one(&after, changes, &close, 1, NULL,
                                       operation_collection))
          return false;
      }
      if (!dep_record_closed_slots(changes, key, &moved))
        return false;
    }
  }
  *route_state = after;
  return complete && !route_state->truncated;
}

/* Whether applying op can allocate a descriptor: a named allocation, or a
 * save that dep_prepare_numeric_undo may need. Only such an operation depends
 * on the low-interval case. Over-inclusion merely splits a version into its
 * case views for one operation. */
static SHELL_NONNULL(1, 2) bool dep_fd_op_may_allocate(
    const dep_fd_op_t *op, const dep_route_journal_t *journal) {
  if (op->fd == SHELL_DEP_FD_NAMED)
    return op->resets_descriptor;
  return op->undo_mode != DEP_UNDO_CHILD && !op->paired_open &&
         op->kind != DEP_FD_OP_IDENTITY && !dep_fd_op_numeric_self_dup(op) &&
         (op->undo_observable || journal->scratch_observable ||
          journal->named_closes || op->undo_mode == DEP_UNDO_COMPOUND ||
          op->kind == DEP_FD_OP_MOVE);
}

/* Views of one operation can save its target on different places, and their
 * join then names several places, each holding the save on some paths and
 * something else on others. Restoring from their union, or stopping when one
 * of them is closed on some path, would mix those paths. Record such a save
 * in the indirect form instead, as the allocation of a save with several
 * places does: the saved descriptor, the target as of entry, lives on the
 * operation's own key, whose places are all of them, and each place is
 * marked as possibly holding it. key is SHELL_DEP_FD_NONE when the operation
 * registered no undo. */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_undo_indirect(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_route_state_t *entry, uint32_t key) {
  if (key == SHELL_DEP_FD_NONE)
    return true;
  dep_fd_ref_t holder = dep_fd_numeric(key);
  dep_route_set_t saved =
      dep_fd_raw_fact(state, journal, holder, DEP_FD_ACCESS_SAVED);
  dep_route_set_t identity =
      dep_fd_raw_fact(state, journal, holder, DEP_FD_ACCESS_SELECTOR);
  shell_fd_allocation_t places = identity.count
                                     ? dep_slot_places(&identity)
                                     : (shell_fd_allocation_t){0, false};
  uint32_t direct = 0;
  bool indirect = false;
  for (uint32_t i = 0; i < saved.count; i++) {
    if (saved.routes[i].kind != DEP_ROUTE_ALIAS)
      continue;
    uint32_t place = saved.routes[i].value;
    if (place == key) {
      indirect = true;
    } else if (place <= SHELL_DEP_FD_MAX) {
      direct++;
      if (place < 64)
        places.candidates |= UINT64_C(1) << place;
      else
        places.tail = true;
    }
  }
  if (!direct || direct + indirect < 2)
    return true;
  dep_route_set_t target =
      dep_fd_raw_fact(state, journal, holder, DEP_FD_ACCESS_UNDO_TARGET);
  dep_route_set_t live = {0};
  dep_route_set_set(&live, (dep_fd_route_t){DEP_ROUTE_INHERITED, UINT32_MAX});
  for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_BINDING;
       access <<= 1) {
    dep_route_set_t routes =
        access == DEP_FD_ACCESS_BINDING
            ? live
            : dep_fd_raw_fact(entry, journal,
                              dep_fd_numeric(target.routes[0].value),
                              (dep_fd_access_t)access);
    if (indirect) {
      dep_route_set_t held =
          dep_fd_raw_fact(state, journal, holder, (dep_fd_access_t)access);
      for (uint32_t i = 0; i < held.count; i++)
        if (!dep_route_set_add(&routes, held.routes[i]))
          return false;
    }
    if (!dep_route_state_store_access(state, journal, holder,
                                      (dep_fd_access_t)access, routes))
      return false;
  }
  uint32_t selector = dep_allocation_selector(journal, key);
  dep_route_set_t undo = {0};
  dep_route_set_set(&undo, (dep_fd_route_t){DEP_ROUTE_ALIAS, key});
  if (!selector ||
      !dep_route_state_store_access(state, journal, holder,
                                    DEP_FD_ACCESS_SELECTOR,
                                    dep_slot_places_fact(selector, places)) ||
      !dep_route_state_store_access(state, journal, holder, DEP_FD_ACCESS_SAVED,
                                    undo) ||
      !dep_route_state_store_access(state, journal, holder,
                                    DEP_FD_ACCESS_SCRATCH, live))
    return false;
  journal->save_marks = true;
  for (uint32_t i = 0; i < saved.count; i++) {
    uint32_t place = saved.routes[i].value;
    if (saved.routes[i].kind != DEP_ROUTE_ALIAS || place == key ||
        place > SHELL_DEP_FD_MAX)
      continue;
    /* The place keeps the scratch identity it had at entry; this save is
     * only possibly on it. */
    dep_route_set_t mark = dep_fd_raw_fact(
        entry, journal, dep_fd_numeric(place), DEP_FD_ACCESS_SCRATCH);
    if (!dep_route_set_add(&mark, (dep_fd_route_t){DEP_ROUTE_ALIAS, key}) ||
        !dep_route_state_store_access(state, journal, dep_fd_numeric(place),
                                      DEP_FD_ACCESS_SCRATCH, mark))
      return false;
  }
  return true;
}

/* Add one applied version to next, the first one initializing it. */
static SHELL_NONNULL(1, 2, 3, 4) bool dep_route_state_join_version(
    dep_route_state_t *next, bool *have_next, const dep_route_state_t *version,
    dep_route_journal_t *journal) {
  if (!*have_next) {
    *next = *version;
    *have_next = true;
    return true;
  }
  return dep_route_state_add_root(next, journal, version->root);
}

/* Apply ops to every version independently. An operation runs on each
 * low-interval view of a version. The outcomes of a named allocation (one per
 * possible place) over the views with one inherited low-interval case are
 * joined into one version, with places kept as weak sets and occupancy kept
 * per low-interval case. A version therefore splits at most once, into one
 * version per inherited case, and keeps allocations correlated with the
 * inherited layout that chose them. */
static SHELL_NONNULL(1, 2) bool dep_route_state_apply(
    dep_route_state_t *route_state, dep_route_journal_t *changes,
    const dep_fd_op_t *ops, uint32_t op_count, bool begin_frame,
    const dep_domain_collection_t *collection) {
  dep_route_state_t current = *route_state;
  if (begin_frame && op_count &&
      !dep_setup_begin(&current, changes, ops[0].undo_mode))
    return false;
  if (begin_frame && op_count &&
      (changes->named_closes || changes->observable_fd_count)) {
    dep_route_state_t framed = {0};
    dep_route_iterator_t iterator = dep_route_iterator(&current);
    uint32_t root;
    bool first = true;
    while (dep_route_next(&iterator, changes, &root)) {
      dep_route_state_t one = dep_route_state_single(root);
      dep_route_set_t entry = {0};
      dep_route_set_set(&entry, (dep_fd_route_t){DEP_ROUTE_INHERITED, root});
      if (!dep_route_state_store_access(&one, changes,
                                        dep_fd_numeric(SHELL_DEP_FD_NONE),
                                        DEP_FD_ACCESS_ENTRY, entry))
        return false;
      if (first) {
        framed.root = one.root;
        first = false;
      } else if (!dep_route_state_add_root(&framed, changes, one.root))
        return false;
    }
    dep_route_state_inherit(&framed, &current);
    current = framed;
  }
  for (uint32_t op_index = 0; op_index < op_count; op_index++) {
    if (collection)
      dep_route_domains_collect(changes, collection, &current, NULL);
    const dep_fd_op_t *op = &ops[op_index];
    if (op->kind == DEP_FD_OP_PROCESS) {
      if (!dep_process_open(&current, changes, op))
        return false;
      continue;
    }
    /* Construction snapshots carry no diagnostics and only partial facts;
     * the final execution walk decides the descriptor contract. */
    /* A copy whose source may be missing on a path, or another reached
     * operation which cannot succeed, is a shell-level error which no
     * dependency graph represents. */
    if (changes->diagnostics &&
        (dep_fd_op_copies(op->kind)
             ? !dep_fd_copy_source_exists(op, &current, changes, NULL)
             : !(dep_fd_operation_outcomes(op, &current, changes) &
                 DEP_STATUS_MAY_SUCCEED))) {
      changes->unmodeled = true;
      return false;
    }
    dep_route_state_t next = {0};
    bool have_next = false;
    dep_route_iterator_t iterator = dep_route_iterator(&current);
    uint32_t root;
    while (dep_route_next(&iterator, changes, &root)) {
      dep_route_state_t entry = dep_route_state_single(root);
      dep_route_state_inherit(&entry, &current);
      /* Every outcome of this operation on one version, over its low-interval
       * views and allocation places, is joined into one version per inherited
       * low-interval case. */
      dep_route_state_t views[SHELL_FD_PARTS] = {{0}}, one = {0},
                        chosen[2] = {{0}};
      uint8_t origins[SHELL_FD_PARTS] = {0};
      uint32_t view_count, origin_views[2] = {0, 0};
      bool have_choice[2] = {false, false};
      /* The pins keep this root, its views, the accumulated results and the
       * unconsumed remainder. Roots already consumed are superseded, so a
       * collection here may sweep them, and `current` must not be a root of
       * any later one. */
      dep_domain_collection_t allocation_pins = {
          .roots = {&next, &entry, &one, &chosen[0], &chosen[1]},
          .states = views,
          .state_count = SHELL_FD_PARTS,
          .remaining = &iterator,
          .parent = collection};
      if (collection) {
        allocation_pins.workspace = collection->workspace;
        allocation_pins.frame = collection->frame;
        dep_route_domains_collect(changes, &allocation_pins, &entry, &next);
      }
      const dep_domain_collection_t *branch_collection =
          collection ? &allocation_pins : NULL;
      views[0] = entry;
      view_count = 1;
      if (dep_fd_op_may_allocate(op, changes) &&
          !dep_fd_domain_views(&entry, changes, views, origins, &view_count))
        return false;
      DEP_TRACE(SHELLSPLIT_TRACE_ALLOC_VIEWS,
                view_count | (origins[view_count - 1] ? 8u : 0u));
      for (uint32_t view = 0; view < view_count; view++) {
        one = views[view];
        unsigned origin = origins[view];
        origin_views[origin]++;
        dep_fd_op_t effective = dep_fd_effective_operation(op, &one, changes);
        /* Overwriting an existing shell-owned save makes this operation's
         * undo observable too. Establish that before choosing low-open
         * modes, not later inside undo preparation after a fixed rank was
         * selected. */
        if (!effective.undo_observable &&
            dep_fd_raw_fact(&one, changes, dep_fd_numeric(effective.fd),
                            DEP_FD_ACCESS_SCRATCH)
                .count)
          effective.undo_observable = true;
        DEP_TRACE(SHELLSPLIT_TRACE_OPERATION,
                  dep_fd_operation_outcomes(&effective, &one, changes) & 31u);
        if (!(dep_fd_operation_outcomes(&effective, &one, changes) &
              DEP_STATUS_MAY_SUCCEED))
          continue;
        /* A reached successful duplication proves its numeric source is
         * live. In particular a move cannot save an absent source; retaining
         * that alternative both invents allocation paths and loses the
         * source-close lifetime. Capability uncertainty remains in the
         * read/write facts. */
        if (dep_fd_op_copies(effective.kind) &&
            effective.target_fd <= SHELL_DEP_FD_MAX) {
          bool possible;
          if (!dep_fd_assume_binding(&one, changes, effective.target_fd,
                                     &possible, false))
            return false;
          if (!possible)
            continue;
        }
        /* A view has one low-interval case. With every low descriptor open,
         * the save's temporary resource open consumes the first high slot. */
        uint32_t undo_rank = effective.fd != SHELL_DEP_FD_NAMED &&
                                     effective.resets_descriptor &&
                                     effective.undo_mode != DEP_UNDO_CHILD &&
                                     (effective.kind == DEP_FD_OP_DOCUMENT ||
                                      effective.kind == DEP_FD_OP_DYNAMIC) &&
                                     (effective.undo_observable ||
                                      dep_route_state_correlated(&current)) &&
                                     changes->observable_fd_count &&
                                     dep_fd_low_modes(&one, changes) == 2
                                 ? 2
                                 : 1;
        bool identity = effective.kind == DEP_FD_OP_IDENTITY;
        if (!identity && effective.fd != SHELL_DEP_FD_NAMED &&
            !dep_prepare_numeric_undo(&one, changes, &effective, op, undo_rank,
                                      DEP_ALLOCATION_TARGET_UNDO, false))
          return false;
        if (effective.fd == SHELL_DEP_FD_NAMED && effective.resets_descriptor &&
            (changes->observable_fd_count || changes->named_closes)) {
          dep_named_allocation_choices_t choices = {0};
          if (!dep_named_allocation_choices(&one, changes, &effective,
                                            &choices))
            return false;
          DEP_TRACE(SHELLSPLIT_TRACE_ALLOC_MODES,
                    (choices.slots[0].count ? 1u : 0u) |
                        (choices.slots[1].count ? 2u : 0u));
          for (uint32_t mode = 0; mode < 2; mode++)
            for (uint32_t slot = 0; slot < choices.slots[mode].count; slot++) {
              dep_fd_route_t selected = choices.slots[mode].slots[slot];
              dep_route_state_t branch = one;
              if (!dep_allocation_select_slot(&branch, changes,
                                              &choices.slots[mode], slot) ||
                  !dep_route_state_apply_one(&branch, changes, op, 1, &selected,
                                             branch_collection) ||
                  !dep_route_state_join_choice(
                      &chosen[origin], &have_choice[origin], &branch, changes))
                return false;
            }
        } else if (!dep_route_state_apply_one(&one, changes, op, 1, NULL,
                                              branch_collection) ||
                   !dep_route_state_join_choice(
                       &chosen[origin], &have_choice[origin], &one, changes)) {
          return false;
        }
      }
      dep_fd_op_t source_close = dep_fd_move_close(op);
      if (!dep_fd_factor_choices(chosen, have_choice, changes))
        return false;
      if (!have_choice[1])
        origin_views[0] += origin_views[1];
      for (unsigned origin = 0; origin < 2; origin++) {
        if (!have_choice[origin])
          continue;
        if (origin_views[origin] > 1 &&
            (!dep_fd_undo_indirect(&chosen[origin], changes, &entry,
                                   dep_undo_slot(changes, op,
                                                 DEP_ALLOCATION_TARGET_UNDO,
                                                 false)) ||
             (op->kind == DEP_FD_OP_MOVE && !dep_fd_op_numeric_self_dup(op) &&
              !dep_fd_undo_indirect(&chosen[origin], changes, &entry,
                                    dep_undo_slot(changes, &source_close,
                                                  DEP_ALLOCATION_MOVE_UNDO,
                                                  false)))))
          return false;
        if (!dep_route_state_join_version(&next, &have_next, &chosen[origin],
                                          changes))
          return false;
      }
    }
    dep_route_state_inherit(&next, &current);
    current = next;
  }
  *route_state = current;
  return !route_state->truncated;
}

static SHELL_NONNULL(1) dep_fd_ref_t
    dep_fd_operation_target(const dep_fd_op_t *op) {
  return (dep_fd_ref_t){
      .name = op->fd_name, .value = op->fd, .name_len = op->fd_name_len};
}

/* Discard a consumed undo registration without closing its physical save.
 * Bash disposes the whole list even when a restoration stopped execution;
 * older scratch descriptors then remain live (with their existing CLEXEC
 * markers) and may still be observed by the caller or an enclosing frame. */
static SHELL_NONNULL(1,
                     2) bool dep_fd_discard_undo(dep_route_state_t *state,
                                                 dep_route_journal_t *journal,
                                                 uint32_t key) {
  if (key == SHELL_DEP_FD_NONE)
    return true;
  dep_fd_ref_t operation = dep_fd_numeric(key);
  if (journal->arena->allocations[key - SHELL_DEP_FD_MAX - 1].role ==
      DEP_ALLOCATION_BINDING)
    return dep_route_state_store_access(state, journal, operation,
                                        DEP_FD_ACCESS_ALLOCATION_SLOTS,
                                        (dep_route_set_t){.ready = true});
  return dep_route_state_store_access(state, journal, operation,
                                      DEP_FD_ACCESS_SAVED,
                                      (dep_route_set_t){.ready = true}) &&
         dep_route_state_store_access(state, journal, operation,
                                      DEP_FD_ACCESS_UNDO_ENTRY,
                                      (dep_route_set_t){.ready = true}) &&
         dep_route_state_store_access(state, journal, operation,
                                      DEP_FD_ACCESS_UNDO_TARGET,
                                      (dep_route_set_t){.ready = true}) &&
         dep_route_state_store_access(state, journal, operation,
                                      DEP_FD_ACCESS_UNDO_EXEC,
                                      (dep_route_set_t){.ready = true});
}

/* source selects one ownership version. Undo saves are singleton aliases,
 * ABSENT for a no-save path, or empty for an unreached operation. Allocation
 * keys retire only their setup metadata, preserving the allocated descriptor.
 * Parent publication and compound completion share this retirement rule. */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_retire_operation(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_route_state_t *source, uint32_t undo_key) {
  if (undo_key == SHELL_DEP_FD_NONE)
    return true;
  if (journal->arena->allocations[undo_key - SHELL_DEP_FD_MAX - 1].role ==
      DEP_ALLOCATION_BINDING)
    return dep_fd_discard_undo(state, journal, undo_key);
  dep_route_set_t undo = dep_fd_raw_fact(
      source, journal, dep_fd_numeric(undo_key), DEP_FD_ACCESS_SAVED);
  /* The save occupies exactly one of its possible places, or none on a
   * no-save path. Disposal replaces a place's facts only when it is the one
   * place; otherwise each place may keep what it held. */
  uint32_t places = 0;
  bool unsaved = false;
  for (uint32_t slot = 0; slot < undo.count; slot++) {
    places += undo.routes[slot].kind == DEP_ROUTE_ALIAS;
    unsaved |= undo.routes[slot].kind != DEP_ROUTE_ALIAS;
  }
  bool exact = places == 1 && !unsaved;
  for (uint32_t slot = 0; slot < undo.count; slot++) {
    if (undo.routes[slot].kind != DEP_ROUTE_ALIAS)
      continue;
    dep_fd_ref_t fd = dep_fd_numeric(undo.routes[slot].value);
    for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_BINDING;
         access <<= 1) {
      dep_route_set_t disposed =
          exact ? (dep_route_set_t){0}
                : dep_fd_raw_fact(state, journal, fd, (dep_fd_access_t)access);
      if (!dep_route_set_add(&disposed,
                             (dep_fd_route_t){access == DEP_FD_ACCESS_BINDING
                                                  ? DEP_ROUTE_CLOSED
                                                  : DEP_ROUTE_ABSENT,
                                              UINT32_MAX}))
        return false;
      if (!dep_route_state_store_access(state, journal, fd,
                                        (dep_fd_access_t)access, disposed))
        return false;
    }
  }
  /* A save held on its own key marked its candidate places; clear those
   * marks so each place keeps only its own facts. */
  dep_route_set_t identity = dep_fd_raw_fact(
      state, journal, dep_fd_numeric(undo_key), DEP_FD_ACCESS_SELECTOR);
  if (identity.count == 4) {
    uint64_t candidates = dep_slot_places(&identity).candidates;
    for (; candidates; candidates &= candidates - 1) {
      dep_fd_ref_t place = dep_fd_numeric(shell_fd_lowest(candidates));
      dep_route_set_t marks =
          dep_fd_raw_fact(state, journal, place, DEP_FD_ACCESS_SCRATCH);
      dep_route_set_t kept = {.ready = true};
      bool marked = false;
      for (uint32_t i = 0; i < marks.count; i++) {
        if (marks.routes[i].kind == DEP_ROUTE_ALIAS &&
            marks.routes[i].value == undo_key) {
          marked = true;
          continue;
        }
        (void)dep_route_set_add(&kept, marks.routes[i]);
      }
      if (marked && !dep_route_state_store_access(state, journal, place,
                                                  DEP_FD_ACCESS_SCRATCH, kept))
        return false;
    }
  }
  if (!dep_selector_retire(state, journal, undo_key))
    return false;
  /* A disposed operation-private save has no remaining numeric identity. Its
   * physical close is already in the domain; retain only the ordinary absent
   * facts so a no-save path and a completed-save path can share this map. A
   * reused named slot keeps its own selector and its closed binding. */
  for (uint32_t slot = 0; slot < undo.count; slot++)
    if (undo.routes[slot].kind == DEP_ROUTE_ALIAS &&
        undo.routes[slot].value == undo_key) {
      for (uint32_t access = DEP_FD_ACCESS_READ;
           access <= DEP_FD_ACCESS_BINDING; access <<= 1) {
        dep_route_set_t absent = {0};
        dep_route_set_set(&absent,
                          (dep_fd_route_t){access == DEP_FD_ACCESS_BINDING
                                               ? DEP_ROUTE_UNAVAILABLE
                                               : DEP_ROUTE_ABSENT,
                                           UINT32_MAX});
        if (!dep_route_state_append_one(state, journal,
                                        dep_fd_numeric(undo_key),
                                        (dep_fd_access_t)access, absent))
          return false;
      }
      if (!dep_route_state_store_access(
              state, journal, dep_fd_numeric(undo_key), DEP_FD_ACCESS_SCRATCH,
              (dep_route_set_t){.ready = true}))
        return false;
    }
  return dep_fd_discard_undo(state, journal, undo_key);
}

/* The state of an undo list, after each entry: still running, stopped by a
 * failed restore, or stopped on some paths only. EXHAUSTED is a capacity
 * failure, never a list state. */
typedef enum {
  DEP_UNDO_DONE,
  DEP_UNDO_STOPPED,
  DEP_UNDO_MAYBE_STOPPED,
  DEP_UNDO_EXHAUSTED,
} dep_undo_result_t;

/* Apply one undo in the selected execution version. Numeric and symbolic
 * scratch descriptors are read at unwind time, not copied from a stale entry
 * map. Only unobserved saves without a selector reuse the immutable entry.
 * MOVE_UNDO absence means no source undo; target
 * absence means Bash registered a close of the initially unopened target.
 * exec discards ordinary restoration, but disposes saves and restores targets
 * which themselves were shell-owned scratch descriptors. A failed dup stops
 * this list without changing command status; stopped consumes later metadata
 * but must not execute later restores or scratch closes. list is the state of
 * the list before this entry, DEP_UNDO_DONE for its first; the result is its
 * state after. A save whose descriptor is closed on some paths only stops
 * the list on those: the result joins the restored and the stopped outcome,
 * and every later entry of a maybe-stopped list joins running and only
 * disposing it. */
static SHELL_NONNULL(1, 2) dep_undo_result_t
    dep_fd_unwind_key(dep_route_state_t *state, dep_route_journal_t *journal,
                      uint32_t key, bool exec, dep_undo_result_t list) {
  if (key == SHELL_DEP_FD_NONE)
    return list;
  if (list == DEP_UNDO_STOPPED)
    return dep_fd_discard_undo(state, journal, key) ? DEP_UNDO_STOPPED
                                                    : DEP_UNDO_EXHAUSTED;
  if (list == DEP_UNDO_MAYBE_STOPPED) {
    dep_route_state_t disposed = *state;
    if (dep_fd_unwind_key(state, journal, key, exec, DEP_UNDO_DONE) ==
            DEP_UNDO_EXHAUSTED ||
        !dep_fd_discard_undo(&disposed, journal, key) ||
        !dep_fd_join(state, &disposed, journal))
      return DEP_UNDO_EXHAUSTED;
    return DEP_UNDO_MAYBE_STOPPED;
  }
  dep_fd_ref_t operation = dep_fd_numeric(key);
  dep_route_set_t target =
      dep_fd_raw_fact(state, journal, operation, DEP_FD_ACCESS_UNDO_TARGET);
  if (!target.count)
    return dep_fd_retire_operation(state, journal, state, key)
               ? DEP_UNDO_DONE
               : DEP_UNDO_EXHAUSTED;
  dep_fd_ref_t fd = dep_fd_numeric(target.routes[0].value);
  dep_route_set_t undo =
      dep_fd_raw_fact(state, journal, operation, DEP_FD_ACCESS_SAVED);
  dep_route_set_t entry =
      dep_fd_raw_fact(state, journal, operation, DEP_FD_ACCESS_UNDO_ENTRY);
  dep_route_set_t exec_restore =
      dep_fd_raw_fact(state, journal, operation, DEP_FD_ACCESS_UNDO_EXEC);
  /* exec keeps its targets unless a target was itself a shell-owned scratch
   * descriptor. A joined version can hold both answers: then the result is
   * the join of restoring and keeping. */
  bool restore = !exec, keep = exec && !exec_restore.count;
  for (uint32_t i = 0; exec && i < exec_restore.count; i++) {
    restore |= exec_restore.routes[i].value != 0;
    keep |= exec_restore.routes[i].value == 0;
  }
  bool move_source =
      journal->arena->allocations[key - SHELL_DEP_FD_MAX - 1].role ==
      DEP_ALLOCATION_MOVE_UNDO;
  dep_route_state_t before = *state, stopped_paths = {0};
  bool may_stop = false;
  if (restore && undo.count) {
    /* Saves are path-local. A body can close its physical scratch descriptor;
     * Bash then fails dup2 before touching the destination or closing the
     * save, and do_redirections stops the remainder of this undo list. */
    for (uint32_t slot = 0; slot < undo.count; slot++) {
      dep_fd_route_t saved = undo.routes[slot];
      if (saved.kind != DEP_ROUTE_ALIAS)
        continue;
      dep_route_set_t binding = dep_fd_raw_fact(
          &before, journal, dep_fd_numeric(saved.value), DEP_FD_ACCESS_BINDING);
      bool closed = false, open = false;
      for (uint32_t i = 0; i < binding.count; i++) {
        closed |= binding.routes[i].kind == DEP_ROUTE_CLOSED;
        open |= binding.routes[i].kind != DEP_ROUTE_CLOSED;
      }
      if (closed) {
        dep_route_state_t halted = *state;
        if (journal->diagnostic_cleanup &&
            !dep_record_diagnostic(&halted, journal))
          return DEP_UNDO_EXHAUSTED;
        if (!dep_fd_discard_undo(&halted, journal, key))
          return DEP_UNDO_EXHAUSTED;
        if (!open) {
          *state = halted;
          return DEP_UNDO_STOPPED;
        }
        stopped_paths = halted;
        may_stop = true;
      }
    }
    for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_BINDING;
         access <<= 1) {
      dep_route_set_t restored = {.ready = true};
      for (uint32_t slot = 0; slot < undo.count; slot++) {
        dep_fd_route_t saved = undo.routes[slot];
        dep_route_set_t routes;
        if (saved.kind == DEP_ROUTE_ABSENT) {
          if (move_source)
            routes =
                dep_fd_raw_fact(&before, journal, fd, (dep_fd_access_t)access);
          else {
            /* The binding keeps the failed-open cause the record carries. */
            routes = (dep_route_set_t){0};
            dep_route_set_set(&routes,
                              (dep_fd_route_t){DEP_ROUTE_CLOSED,
                                               access == DEP_FD_ACCESS_BINDING
                                                   ? saved.value
                                                   : UINT32_MAX});
          }
        } else if (saved.value > SHELL_DEP_FD_MAX &&
                   !dep_fd_raw_fact(&before, journal,
                                    dep_fd_numeric(saved.value),
                                    DEP_FD_ACCESS_SELECTOR)
                        .count) {
          dep_route_state_t original =
              dep_route_state_single(entry.routes[0].value);
          routes =
              dep_fd_raw_fact(&original, journal, fd, (dep_fd_access_t)access);
        } else {
          routes =
              dep_fd_raw_fact(&before, journal, dep_fd_numeric(saved.value),
                              (dep_fd_access_t)access);
        }
        /* A path whose save is closed fails dup2 and keeps the descriptor:
         * that is the stopped outcome above, never a restored closure. */
        for (uint32_t i = 0; i < routes.count; i++)
          if ((saved.kind != DEP_ROUTE_ALIAS ||
               routes.routes[i].kind != DEP_ROUTE_CLOSED) &&
              !dep_route_set_add(&restored, routes.routes[i]))
            return DEP_UNDO_EXHAUSTED;
      }
      if (!dep_route_state_store_access(state, journal, fd,
                                        (dep_fd_access_t)access, restored))
        return DEP_UNDO_EXHAUSTED;
    }
    dep_route_state_t original = dep_route_state_single(entry.routes[0].value);
    if (!dep_route_state_store_access(
            state, journal, fd, DEP_FD_ACCESS_SCRATCH,
            dep_fd_raw_fact(&original, journal, fd, DEP_FD_ACCESS_SCRATCH)))
      return DEP_UNDO_EXHAUSTED;
    if (keep && !dep_fd_join(state, &before, journal))
      return DEP_UNDO_EXHAUSTED;
  }
  if (!dep_fd_retire_operation(state, journal, &before, key))
    return DEP_UNDO_EXHAUSTED;
  dep_route_set_t available =
      dep_fd_raw_fact(state, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
                      DEP_FD_ACCESS_AVAILABLE);
  if (fd.value >= DEP_BASH_VARREDIR_MIN_FD) {
    dep_route_set_t binding =
        dep_fd_raw_fact(state, journal, fd, DEP_FD_ACCESS_BINDING);
    if (binding.count == 1 && binding.routes[0].kind == DEP_ROUTE_CLOSED)
      (void)dep_route_set_add(&available,
                              (dep_fd_route_t){DEP_ROUTE_ALIAS, fd.value});
    else
      (void)dep_allocation_remove_candidate(&available, fd.value);
  }
  for (uint32_t slot = 0; slot < undo.count; slot++)
    if (undo.routes[slot].kind == DEP_ROUTE_ALIAS) {
      if (undo.routes[slot].value <= SHELL_DEP_FD_MAX ||
          dep_fd_raw_fact(state, journal,
                          dep_fd_numeric(undo.routes[slot].value),
                          DEP_FD_ACCESS_SELECTOR)
              .count)
        (void)dep_route_set_add(&available, undo.routes[slot]);
      if (!dep_route_state_store_access(
              state, journal, dep_fd_numeric(undo.routes[slot].value),
              DEP_FD_ACCESS_SCRATCH, (dep_route_set_t){.ready = true}))
        return DEP_UNDO_EXHAUSTED;
    }
  if (!dep_route_state_store_access(state, journal,
                                    dep_fd_numeric(SHELL_DEP_FD_NONE),
                                    DEP_FD_ACCESS_AVAILABLE, available))
    return DEP_UNDO_EXHAUSTED;
  if (!may_stop)
    return DEP_UNDO_DONE;
  return dep_fd_join(state, &stopped_paths, journal) ? DEP_UNDO_MAYBE_STOPPED
                                                     : DEP_UNDO_EXHAUSTED;
}

/* Publish completed mutations, not a replay against the destination table:
 * a duplication can read a temporary group route even when its target survives
 * the group. The outcome stream handles joins and restoration separately. */
static SHELL_NONNULL(1, 2, 3) bool dep_route_state_publish_one(
    dep_route_state_t *route_state, dep_route_journal_t *changes,
    const dep_route_state_t *executed_state, const dep_fd_op_t *ops,
    uint32_t op_count, bool descriptor_exec,
    const dep_domain_collection_t *collection) {
  dep_route_state_t original = *route_state;
  *route_state = *executed_state;
  dep_route_state_inherit(route_state, &original);
  dep_undo_result_t list = DEP_UNDO_DONE;
  /* Bash prepends each newly registered undo. Source-close undo is registered
   * after a move's destination save, so it runs first during unwind. */
  for (uint32_t i = op_count; i != 0; i--) {
    if (collection)
      dep_route_domains_collect(changes, collection, route_state,
                                executed_state);
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_PUBLICATION);
    const dep_fd_op_t *op = ops + i - 1;
    if (op->kind == DEP_FD_OP_PROCESS)
      continue;
    if (op->kind == DEP_FD_OP_MOVE && !dep_fd_op_numeric_self_dup(op)) {
      dep_fd_op_t close = dep_fd_move_close(op);
      list = dep_fd_unwind_key(
          route_state, changes,
          dep_undo_slot(changes, &close, DEP_ALLOCATION_MOVE_UNDO, false),
          descriptor_exec, list);
      if (list == DEP_UNDO_EXHAUSTED)
        return false;
    }
    uint32_t target_key =
        dep_undo_slot(changes, op, DEP_ALLOCATION_TARGET_UNDO, false);
    list = dep_fd_unwind_key(route_state, changes, target_key, descriptor_exec,
                             list);
    if (list == DEP_UNDO_EXHAUSTED)
      return false;
    if (list != DEP_UNDO_STOPPED && !descriptor_exec &&
        target_key == SHELL_DEP_FD_NONE && dep_fd_op_saves_numeric(op)) {
      /* No live observer can distinguish a save in this simple command.
       * Restore only the changed target from the selected parent version;
       * do not manufacture scratch state for unrelated later commands. A
       * maybe-stopped list restores it on some paths only. */
      dep_route_state_t unrestored = *route_state;
      for (uint32_t access = DEP_FD_ACCESS_READ;
           access <= DEP_FD_ACCESS_BINDING; access <<= 1)
        if (!dep_route_state_store_access(
                route_state, changes, dep_fd_numeric(op->fd),
                (dep_fd_access_t)access,
                dep_fd_raw_fact(&original, changes, dep_fd_numeric(op->fd),
                                (dep_fd_access_t)access)))
          return false;
      if (list == DEP_UNDO_MAYBE_STOPPED &&
          !dep_fd_join(route_state, &unrestored, changes))
        return false;
    }
    if (op->fd == SHELL_DEP_FD_NAMED && op->resets_descriptor &&
        (changes->observable_fd_count || changes->named_closes) &&
        !dep_fd_retire_operation(route_state, changes, executed_state,
                                 dep_allocation_slot(changes, op)))
      return false;
  }
  return !route_state->truncated &&
         dep_route_state_store_access(
             route_state, changes, dep_fd_numeric(SHELL_DEP_FD_NONE),
             DEP_FD_ACCESS_ENTRY, (dep_route_set_t){.ready = true}) &&
         (!dep_fd_raw_fact(route_state, changes,
                           dep_fd_numeric(SHELL_DEP_FD_NONE),
                           DEP_FD_ACCESS_SETUP_MODE)
               .count ||
          dep_route_state_store_access(
              route_state, changes, dep_fd_numeric(SHELL_DEP_FD_NONE),
              DEP_FD_ACCESS_SETUP_MODE, (dep_route_set_t){.ready = true}));
}

static SHELL_NONNULL(1, 2,
                     4) bool dep_fd_merge_root(dep_route_state_t *destination,
                                               dep_route_journal_t *journal,
                                               uint32_t source_root,
                                               bool *apart);

static SHELL_NONNULL(1, 2, 3) bool dep_fd_merge_versions(
    dep_route_state_t *destination, const dep_route_state_t *source,
    dep_route_journal_t *journal) {
  /* Preserve only distinguishable observation classes. Unrelated changes
   * may still factor inside each class after one observed name forced a
   * split; keeping every whole-state combination grows exponentially. Joins
   * use immutable changed-key paths and their cache, never source rescans. */
  /* Every state includes its primary root, including the empty-map root.
   * Seed it directly, then join remaining destination versions and source. */
  uint32_t roots[DEP_ROUTE_STATE_CAPACITY], count = 1;
  roots[0] = destination->root;
  for (unsigned side = 0; side < 2; side++) {
    dep_route_iterator_t iterator =
        dep_route_iterator(side ? source : destination);
    if (!side)
      (void)dep_route_take(&iterator, journal);
    uint32_t root;
    while (dep_route_next(&iterator, journal, &root)) {
      bool merged = false;
      for (uint32_t i = 0; i < count; i++) {
        DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_ALTERNATIVES);
        dep_route_state_t candidate = dep_route_state_single(roots[i]);
        bool apart = false;
        if (!dep_fd_merge_root(&candidate, journal, root, &apart))
          return false;
        if (!apart) {
          roots[i] = candidate.root;
          merged = true;
          break;
        }
      }
      if (!merged) {
        if (count == DEP_ROUTE_STATE_CAPACITY)
          return false;
        roots[count++] = root;
      }
    }
  }
  dep_route_state_t result = dep_route_state_single(roots[0]);
  for (uint32_t i = 1; i < count; i++)
    if (!dep_route_state_add_root(&result, journal, roots[i]))
      return false;
  dep_route_state_inherit(&result, destination);
  dep_route_state_inherit(&result, source);
  *destination = result;
  return true;
}

static SHELL_NONNULL(1, 2, 3) bool dep_route_state_publish(
    dep_route_state_t *route_state, dep_route_journal_t *changes,
    const dep_route_state_t *executed_state, const dep_fd_op_t *ops,
    uint32_t op_count, bool descriptor_exec,
    const dep_domain_collection_t *collection) {
  dep_route_state_t entry = *route_state;
  if (op_count == 0) {
    /* No descriptor setup needs undoing. In particular a builtin evaluated
     * one path of a correlated entry: its continuation is that path, not all
     * of the owner's original alternatives. Argument captures are private
     * journal facts; scalar mutations/restoration are published below. */
    *route_state = *executed_state;
    dep_route_state_inherit(route_state, &entry);
    return !route_state->truncated;
  }
  dep_route_state_t published = {0};
  dep_domain_collection_t pins = {.roots = {&entry, executed_state, &published},
                                  .parent = collection};
  if (collection) {
    pins.workspace = collection->workspace;
    pins.frame = collection->frame;
  }
  bool have_published = false;
  uint32_t entry_count = dep_route_state_count(&entry);
  uint32_t executed_count = dep_route_state_count(executed_state);
  uint32_t pairs = executed_count;
  dep_route_iterator_t executed_iterator = dep_route_iterator(executed_state);
  dep_route_iterator_t entry_iterator = dep_route_iterator(&entry);
  for (uint32_t pair = 0; pair < pairs; pair++) {
    uint32_t root = dep_route_take(&executed_iterator, changes);
    uint32_t entry_root = entry.root;
    if (entry_count == executed_count)
      entry_root = dep_route_take(&entry_iterator, changes);
    dep_route_state_t executed_branch = dep_route_state_single(root);
    dep_route_state_inherit(&executed_branch, executed_state);
    dep_route_set_t saved =
        dep_fd_raw_fact(&executed_branch, changes,
                        dep_fd_numeric(SHELL_DEP_FD_NONE), DEP_FD_ACCESS_ENTRY);
    uint32_t original = saved.count == 1 ? saved.routes[0].value : entry_root;
    dep_route_state_t branch = dep_route_state_single(original);
    dep_route_state_inherit(&branch, &entry);
    dep_route_state_inherit(&branch, executed_state);
    if (!dep_route_state_publish_one(&branch, changes, &executed_branch, ops,
                                     op_count, descriptor_exec,
                                     collection ? &pins : NULL))
      return false;
    if (!have_published) {
      published = branch;
      have_published = true;
    } else {
      if (dep_route_state_correlated(&entry) ||
          dep_route_state_correlated(executed_state)) {
        if (!dep_route_state_add_root(&published, changes, branch.root))
          return false;
      } else if (!dep_fd_merge(&published, &branch, changes)) {
        return false;
      }
    }
  }
  dep_route_state_inherit(&published, &entry);
  dep_route_state_inherit(&published, executed_state);
  *route_state = published;
  return !route_state->truncated;
}

/* Apply one prepared undo frame. Variables keep their physical associations;
 * scratch_keys may be NULL exactly when scratch_count is zero. */
static SHELL_NONNULL(1, 2) bool dep_fd_restore_slots_one(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const uint32_t *scratch_keys, uint32_t scratch_count) {
  /* The membership index serves scope crossing; physical restoration uses
   * the ordered operation keys, exactly as ordinary command publication. */
  dep_undo_result_t list = DEP_UNDO_DONE;
  for (uint32_t i = scratch_count; i != 0; i--) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_REDIRECT_FRAMES);
    list = dep_fd_unwind_key(state, journal, scratch_keys[i - 1], false, list);
    if (list == DEP_UNDO_EXHAUSTED)
      return false;
  }
  return true;
}

static SHELL_NONNULL(1,
                     2) bool dep_fd_restore_slots(dep_route_state_t *state,
                                                  dep_route_journal_t *journal,
                                                  const uint32_t *scratch_keys,
                                                  uint32_t scratch_count) {
  dep_route_state_t restored = {0};
  uint32_t paths = dep_route_state_count(state);
  dep_route_iterator_t iterator = dep_route_iterator(state);
  for (uint32_t path = 0; path < paths; path++) {
    uint32_t root = dep_route_take(&iterator, journal);
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_state_inherit(&one, state);
    if (!dep_fd_restore_slots_one(&one, journal, scratch_keys, scratch_count))
      return false;
    if (path == 0)
      restored = one;
    else if (!dep_route_state_add_root(&restored, journal, one.root))
      return false;
  }
  dep_route_state_inherit(&restored, state);
  *state = restored;
  return true;
}

static bool dep_restore_continuation_route_state(
    dep_route_state_t *continuation, dep_route_journal_t *changes,
    const dep_route_publication_t *publication) {
  for (int32_t group = publication->source_group;
       dep_publication_crosses_group(publication, group);) {
    const dep_redirect_frame_t *frame = &publication->frames[group];
    if (!dep_fd_restore_slots(continuation, changes, frame->scratch_keys,
                              frame->scratch_count))
      return false;
    uint16_t parent = publication->fast->groups[group].parent;
    group = parent == UINT16_MAX ? -1 : (int32_t)parent;
  }
  return true;
}

static dep_route_set_t
dep_time_report_for_fd2(const dep_route_state_t *state,
                        const dep_route_journal_t *changes) {
  return dep_route_state_get(state, changes, dep_fd_numeric(2));
}

#include "shell_depgraph_presence_impl.h"

/* The value of a key no version stores: the executor contract, a function of
 * the key alone. proven_live is the one outside fact it takes, that the
 * descriptor is proved occupied. */
static dep_route_set_t
dep_fd_default_fact(dep_fd_ref_t fd, dep_fd_access_t access, bool proven_live) {
  if (access == DEP_FD_ACCESS_IFS || access == DEP_FD_ACCESS_STDIN_REDIR) {
    dep_route_set_t result = {0};
    dep_route_set_set(&result, (dep_fd_route_t){DEP_ROUTE_INHERITED, 0});
    return result;
  }
  if (access == DEP_FD_ACCESS_AVAILABLE)
    return (dep_route_set_t){.ready = true};
  if (access == DEP_FD_ACCESS_VARIABLE_PRESENCE ||
      access == DEP_FD_ACCESS_PRESENCE_MAP ||
      access == DEP_FD_ACCESS_PROCESS_OWNED ||
      access == DEP_FD_ACCESS_PRIVATE_SCOPE ||
      access == DEP_FD_ACCESS_READ_ARGUMENT ||
      access == DEP_FD_ACCESS_EFFECT_STATE ||
      access == DEP_FD_ACCESS_SUBSTITUTION_STATUS ||
      access == DEP_FD_ACCESS_PRIVATE_ENTRY || access == DEP_FD_ACCESS_SAVED ||
      access == DEP_FD_ACCESS_SETUP_FRAME ||
      access == DEP_FD_ACCESS_ALLOCATION_SLOTS ||
      access == DEP_FD_ACCESS_UNDO_ENTRY ||
      access == DEP_FD_ACCESS_UNDO_TARGET ||
      access == DEP_FD_ACCESS_UNDO_EXEC || access == DEP_FD_ACCESS_SCRATCH ||
      access == DEP_FD_ACCESS_SETUP_MODE ||
      access == DEP_FD_ACCESS_PROCESS_SLOT ||
      access == DEP_FD_ACCESS_SELECTOR ||
      access == DEP_FD_ACCESS_PROCESS_DOMAIN)
    return (dep_route_set_t){.ready = true};
  if (access == DEP_FD_ACCESS_ENTRY)
    return (dep_route_set_t){.ready = true};
  /* Executor contract (SHELL_DEP_EUNMODELED) for keys no version stores. */
  dep_route_set_t result = {0};
  if (fd.value > SHELL_DEP_FD_MAX && fd.value < SHELL_DEP_FD_NAMED) {
    dep_route_set_set(&result, (dep_fd_route_t){access == DEP_FD_ACCESS_BINDING
                                                    ? DEP_ROUTE_UNAVAILABLE
                                                    : DEP_ROUTE_ABSENT,
                                                UINT32_MAX});
    return result;
  }
  /* The analyzed input starts with 0, 1 and 2 open and every other numeric
   * descriptor closed. */
  if (fd.value != SHELL_DEP_FD_NAMED && fd.value >= 3 && !proven_live) {
    dep_route_set_set(&result, (dep_fd_route_t){DEP_ROUTE_CLOSED, UINT32_MAX});
    return result;
  }
  dep_fd_route_t route =
      access == DEP_FD_ACCESS_BINDING
          ? (dep_fd_route_t){proven_live || fd.value != SHELL_DEP_FD_NAMED
                                 ? DEP_ROUTE_INHERITED
                                 : DEP_ROUTE_UNSEEN,
                             UINT32_MAX}
          : (dep_fd_route_t){DEP_ROUTE_INHERITED, fd.value};
  dep_route_set_set(&result, route);
  return result;
}

/* A key no version stores has its executor-contract value. Binding visibility
 * is an explicit journal fact, not a table test. A single-root lookup preserves
 * every stored snapshot position, including equal words in private metadata
 * records. */
static SHELL_NONNULL(2) dep_route_set_t
    dep_fd_raw_root_own_fact(uint32_t root, const dep_route_journal_t *journal,
                             dep_fd_ref_t fd, dep_fd_access_t access);

/* A descriptor marked as a possible place of a save that has several places
 * (an ALIAS in its scratch fact) may hold that save, whose facts live on the
 * save's own key. Reading it sees both, one hop. Disposing the save clears
 * the mark and leaves the descriptor's own facts. */
static SHELL_NONNULL(2) dep_route_set_t
    dep_fd_raw_root_fact(uint32_t root, const dep_route_journal_t *journal,
                         dep_fd_ref_t fd, dep_fd_access_t access) {
  dep_route_set_t own = dep_fd_raw_root_own_fact(root, journal, fd, access);
  if ((access != DEP_FD_ACCESS_READ && access != DEP_FD_ACCESS_WRITE &&
       access != DEP_FD_ACCESS_BINDING) ||
      !journal->save_marks || fd.value == SHELL_DEP_FD_NAMED ||
      fd.value == SHELL_DEP_FD_NONE)
    return own;
  dep_route_set_t marks =
      dep_fd_raw_root_own_fact(root, journal, fd, DEP_FD_ACCESS_SCRATCH);
  for (uint32_t i = 0; i < marks.count; i++) {
    if (marks.routes[i].kind != DEP_ROUTE_ALIAS ||
        marks.routes[i].value == fd.value)
      continue;
    dep_route_set_t held = dep_fd_raw_root_own_fact(
        root, journal, dep_fd_numeric(marks.routes[i].value), access);
    own.truncated |= held.truncated;
    for (uint32_t j = 0; j < held.count; j++)
      (void)dep_route_set_add(&own, held.routes[j]);
  }
  return own;
}

static SHELL_NONNULL(2) dep_route_set_t
    dep_fd_raw_root_own_fact(uint32_t root, const dep_route_journal_t *journal,
                             dep_fd_ref_t fd, dep_fd_access_t access) {
  if (access == DEP_FD_ACCESS_VARIABLE_PRESENCE &&
      fd.value == SHELL_DEP_FD_NAMED) {
    unsigned presence = dep_presence_root(root, journal, fd);
    dep_route_set_t result = {0};
    dep_route_set_set(&result, (dep_fd_route_t){presence == SHELL_TEST_TRUE
                                                    ? DEP_ROUTE_INHERITED
                                                : presence == SHELL_TEST_FALSE
                                                    ? DEP_ROUTE_UNAVAILABLE
                                                    : DEP_ROUTE_DYNAMIC,
                                                0});
    return result;
  }
  if (access == DEP_FD_ACCESS_NAMED_BINDINGS) {
    dep_route_set_t result = {0};
    dep_route_set_set(&result, dep_named_bindings(root, journal));
    return result;
  }
  bool proven_live = false;
  if (fd.value < 64 &&
      (access == DEP_FD_ACCESS_BINDING || access == DEP_FD_ACCESS_READ ||
       access == DEP_FD_ACCESS_WRITE)) {
    uint32_t domain =
        dep_route_root_snapshot(root, journal, dep_fd_numeric(DEP_DOMAIN_UNION),
                                DEP_FD_ACCESS_PROCESS_DOMAIN);
    if (domain && journal->arena->snapshots[domain - 1].count) {
      shell_fd_occupancy_t value =
          dep_domain_value(&journal->arena->snapshots[domain - 1]);
      uint64_t bit = UINT64_C(1) << fd.value;
      if (!(value.may_occupied & bit)) {
        /* A stored closed binding may record the failed open behind it. */
        uint32_t stored =
            dep_route_root_snapshot(root, journal, fd, DEP_FD_ACCESS_BINDING);
        if (access == DEP_FD_ACCESS_BINDING && stored &&
            journal->arena->snapshots[stored - 1].count &&
            journal->arena->snapshots[stored - 1].routes[0].kind ==
                DEP_ROUTE_CLOSED)
          return journal->arena->snapshots[stored - 1];
        dep_route_set_t closed = {0};
        dep_route_set_set(&closed,
                          (dep_fd_route_t){DEP_ROUTE_CLOSED, UINT32_MAX});
        return closed;
      }
      proven_live = !(value.may_free & bit);
    }
  }
  uint32_t change = dep_route_root_snapshot(root, journal, fd, access);
  if (change) {
    dep_route_set_t fact = journal->arena->snapshots[change - 1];
    if (proven_live && access == DEP_FD_ACCESS_BINDING && fact.count == 1 &&
        fact.routes[0].kind == DEP_ROUTE_UNSEEN)
      fact.routes[0].kind = DEP_ROUTE_INHERITED;
    return fact;
  }
  if (fd.value == SHELL_DEP_FD_NAMED && access == DEP_FD_ACCESS_BINDING &&
      dep_named_bindings(root, journal).kind == DEP_ROUTE_DYNAMIC) {
    dep_route_set_t result = {0};
    dep_route_set_set(&result, (dep_fd_route_t){DEP_ROUTE_DYNAMIC, UINT32_MAX});
    return result;
  }
  return dep_fd_default_fact(fd, access, proven_live);
}

/* Bash's temporary assignment environment is visible to ordinary argument
 * lookup inside a later RHS substitution, but not to redirection expansion.
 * A nested parse starts with those names in its shadow set: present in
 * value, but not as tracked here. Nested parses inherit the set; a
 * child-local write removes the name (dep_read_note_assignment). */
static SHELL_NONNULL(2) bool dep_read_scalar_shadowed(
    uint32_t root, const dep_route_journal_t *journal, dep_fd_ref_t fd) {
  uint32_t marker = dep_route_root_snapshot(
      root, journal, dep_fd_numeric(DEP_SCALAR_IMPORT_EVENT),
      DEP_FD_ACCESS_PRIVATE_ENTRY);
  return marker && dep_route_map_snapshot(
                       journal->arena->snapshots[marker - 1].routes[0].value,
                       journal, fd, DEP_FD_ACCESS_READ_ARGUMENT) != 0;
}

/* Union route alternatives across versions, deduplicating equal kind/value
 * pairs even within one snapshot. Positional metadata requires root lookup. */
static SHELL_NONNULL(1, 2) dep_route_set_t
    dep_fd_raw_fact(const dep_route_state_t *state,
                    const dep_route_journal_t *journal, dep_fd_ref_t fd,
                    dep_fd_access_t access) {
  dep_route_set_t result = {.ready = true, .truncated = state->truncated};
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_set_t one = dep_fd_raw_root_fact(root, journal, fd, access);
    result.truncated |= one.truncated;
    for (uint32_t route = 0; route < one.count; route++)
      if (!dep_route_set_add(&result, one.routes[route]))
        return result;
  }
  return result;
}

static SHELL_NONNULL(1, 2) dep_route_set_t
    dep_fd_fact(const dep_route_state_t *state,
                const dep_route_journal_t *journal, dep_fd_ref_t fd,
                dep_fd_access_t access) {
  dep_route_set_t result = {.ready = true, .truncated = state->truncated};
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_set_t raw = dep_fd_raw_root_fact(root, journal, fd, access);
    result.truncated |= raw.truncated;
    for (uint32_t i = 0; i < raw.count; i++) {
      dep_fd_route_t route = raw.routes[i];
      if (route.kind != DEP_ROUTE_ALIAS) {
        (void)dep_route_set_add(&result, route);
        continue;
      }
      /* Resolve the association within its own version before taking the
       * public union. A slot from another allocation path is not its route. */
      dep_route_set_t slots = dep_fd_raw_root_fact(
          root, journal, dep_fd_numeric(route.value), access);
      result.truncated |= slots.truncated;
      for (uint32_t slot = 0; slot < slots.count; slot++)
        (void)dep_route_set_add(&result, slots.routes[slot]);
    }
  }
  return result;
}

static SHELL_NONNULL(1, 2) bool dep_fd_bound(const dep_route_state_t *state,
                                             const dep_route_journal_t *journal,
                                             dep_fd_ref_t fd) {
  if (fd.value != SHELL_DEP_FD_NAMED)
    return true;
  dep_route_set_t facts =
      dep_fd_raw_fact(state, journal, fd, DEP_FD_ACCESS_BINDING);
  dep_route_set_t effect_state =
      dep_fd_raw_fact(state, journal, fd, DEP_FD_ACCESS_EFFECT_STATE);
  if (dep_effect_state_has(&effect_state, DEP_EFFECT_STATE_ORPHANED_ALLOCATION))
    return false;
  bool live = false;
  for (uint32_t i = 0; i < facts.count; i++) {
    if (facts.routes[i].kind == DEP_ROUTE_DYNAMIC ||
        facts.routes[i].kind == DEP_ROUTE_UNSEEN)
      return false;
    live |= facts.routes[i].kind == DEP_ROUTE_INHERITED ||
            facts.routes[i].kind == DEP_ROUTE_ALIAS;
  }
  return live;
}

/* Derived tables need one usable representative. Only the journal determines
 * setup outcomes and carries all correlated alternatives, including closed
 * or unavailable directions. A representative is never a validity proof. */
static dep_fd_route_t dep_fd_representative(dep_route_set_t routes) {
  for (uint32_t i = 0; i < routes.count; i++)
    if (routes.routes[i].kind != DEP_ROUTE_CLOSED &&
        routes.routes[i].kind != DEP_ROUTE_UNAVAILABLE &&
        routes.routes[i].kind != DEP_ROUTE_ABSENT)
      return routes.routes[i];
  return routes.routes[0];
}

/* One representative route of fd for a single-route consumer, not the
 * authoritative union. Keep usable physical associations, so numeric
 * restoration remains visible; skip an association whose direction is
 * unavailable on every route version. All actual alternatives remain in the
 * immutable journal. */
static SHELL_NONNULL(1, 2) dep_fd_route_t
    dep_fd_published_route(const dep_route_state_t *state,
                           const dep_route_journal_t *journal, dep_fd_ref_t fd,
                           dep_fd_access_t access) {
  dep_route_set_t raw = dep_fd_raw_fact(state, journal, fd, access);
  for (uint32_t i = 0; i < raw.count; i++) {
    dep_fd_route_t route = raw.routes[i];
    if (route.kind != DEP_ROUTE_ALIAS) {
      if (route.kind != DEP_ROUTE_CLOSED && route.kind != DEP_ROUTE_ABSENT &&
          route.kind != DEP_ROUTE_UNAVAILABLE)
        return route;
      continue;
    }
    dep_route_set_t actual =
        dep_fd_raw_fact(state, journal, dep_fd_numeric(route.value), access);
    for (uint32_t j = 0; j < actual.count; j++)
      if (actual.routes[j].kind != DEP_ROUTE_CLOSED &&
          actual.routes[j].kind != DEP_ROUTE_ABSENT &&
          actual.routes[j].kind != DEP_ROUTE_UNAVAILABLE)
        return route;
  }
  return dep_fd_representative(raw);
}

/* The route publication reads for an owner's descriptor fd: its
 * representative route in the owner's final state, one alias hop resolved.
 * A descriptor without one (dep_owner_use_present) is untouched: INHERITED. */
static SHELL_NONNULL(1, 2) dep_fd_route_t
    dep_owner_state_route(const dep_route_state_t *state,
                          const dep_route_journal_t *journal, dep_fd_ref_t fd,
                          dep_fd_access_t access) {
  if (!dep_owner_use_present(state, journal, fd))
    return (dep_fd_route_t){DEP_ROUTE_INHERITED, fd.value};
  dep_fd_route_t route = dep_fd_published_route(state, journal, fd, access);
  if (route.kind != DEP_ROUTE_ALIAS)
    return route;
  dep_fd_ref_t target = dep_fd_numeric(route.value);
  return dep_owner_use_present(state, journal, target)
             ? dep_fd_published_route(state, journal, target, access)
             : (dep_fd_route_t){DEP_ROUTE_INHERITED, route.value};
}

/* Binding outcomes are independent of access mode: a write-only descriptor
 * passes read's -u existence check, but never contributes a READ capability.
 * Unknown inherited descriptors retain both possible validation outcomes. */
static SHELL_NONNULL(1) uint8_t
    dep_read_binding_outcomes(const dep_route_set_t *facts) {
  uint8_t outcomes = 0;
  for (uint32_t i = 0; i < facts->count; i++) {
    dep_route_kind_t kind = facts->routes[i].kind;
    if (kind == DEP_ROUTE_CLOSED || kind == DEP_ROUTE_ABSENT ||
        kind == DEP_ROUTE_UNAVAILABLE)
      outcomes |= DEP_STATUS_MAY_FAIL;
    else if (kind == DEP_ROUTE_UNSEEN || kind == DEP_ROUTE_DYNAMIC)
      outcomes |= DEP_STATUS_EITHER;
    else
      outcomes |= DEP_STATUS_MAY_SUCCEED;
  }
  return outcomes;
}

/* The routes of facts that remain possible under the graph's requirements: a
 * missing route carrying a failed-open cause (dep_fd_binding_exists) exists
 * only where a required open failed, so it never distinguishes a feasible
 * execution alternative. */
static SHELL_NONNULL(1) dep_route_set_t
    dep_required_feasible(const dep_route_set_t *facts) {
  dep_route_set_t feasible = {.ready = facts->ready,
                              .truncated = facts->truncated};
  for (uint32_t i = 0; i < facts->count; i++) {
    dep_fd_route_t route = facts->routes[i];
    if ((route.kind == DEP_ROUTE_CLOSED || route.kind == DEP_ROUTE_ABSENT ||
         route.kind == DEP_ROUTE_UNAVAILABLE) &&
        route.value != UINT32_MAX)
      continue;
    feasible.routes[feasible.count++] = route;
  }
  return feasible;
}

/* The access facts of fd in root that remain possible under the graph's
 * requirements. Access facts carry no failed-open cause; the binding does.
 * When every missing binding route of root carries one, the descriptor is
 * missing only where a required open failed, so the closed access routes
 * are as infeasible as those binding routes. An unavailable access route is
 * an open descriptor without that access: it stays. */
static SHELL_NONNULL(2, 4) dep_route_set_t
    dep_access_required_feasible(uint32_t root,
                                 const dep_route_journal_t *journal,
                                 dep_fd_ref_t fd,
                                 const dep_route_set_t *facts) {
  dep_route_set_t binding =
      dep_fd_raw_root_fact(root, journal, fd, DEP_FD_ACCESS_BINDING);
  for (uint32_t i = 0; i < binding.count; i++)
    if ((binding.routes[i].kind == DEP_ROUTE_CLOSED ||
         binding.routes[i].kind == DEP_ROUTE_ABSENT ||
         binding.routes[i].kind == DEP_ROUTE_UNAVAILABLE) &&
        binding.routes[i].value == UINT32_MAX)
      return *facts;
  dep_route_set_t feasible = {.ready = facts->ready,
                              .truncated = facts->truncated};
  for (uint32_t i = 0; i < facts->count; i++)
    if (facts->routes[i].kind != DEP_ROUTE_CLOSED)
      feasible.routes[feasible.count++] = facts->routes[i];
  return feasible;
}

/* Empty, nonempty decimal, or unknown. Value-only observations need no
 * allocation identity; different nonempty aliases have the same option role. */
static SHELL_NONNULL(1) unsigned dep_read_value_class(
    const dep_route_set_t *facts) {
  unsigned value = 0;
  for (uint32_t i = 0; i < facts->count; i++) {
    dep_route_kind_t kind = facts->routes[i].kind;
    value |= kind == DEP_ROUTE_ABSENT || kind == DEP_ROUTE_UNAVAILABLE ? 1u
             : kind == DEP_ROUTE_ALIAS || kind == DEP_ROUTE_INHERITED ||
                     kind == DEP_ROUTE_CLOSED
                 ? 2u
                 : 3u;
  }
  return value ? value : 3u;
}

static SHELL_NONNULL(1) unsigned dep_read_binding_observation(
    const dep_route_journal_t *journal, dep_fd_ref_t fd) {
  if (fd.value > SHELL_DEP_FD_MAX && fd.value < SHELL_DEP_FD_NAMED) {
    const dep_allocation_t *allocation =
        &journal->arena->allocations[fd.value - SHELL_DEP_FD_MAX - 1];
    if ((allocation->role != DEP_ALLOCATION_BINDING &&
         allocation->role != DEP_ALLOCATION_IMPORT) ||
        !allocation->name)
      return 0;
    return (allocation->observations |
            dep_read_observation(
                &journal->read_observations,
                (dep_fd_ref_t){.name = allocation->name,
                               .value = SHELL_DEP_FD_NAMED,
                               .name_len = allocation->name_length})) &
           (DEP_READ_OBSERVE_IDENTITY | DEP_READ_OBSERVE_ACCESS);
  }
  unsigned role = dep_read_observation(&journal->read_observations, fd);
  if (role || !journal->read_observations.identity ||
      fd.value < DEP_BASH_VARREDIR_MIN_FD || fd.value > SHELL_DEP_FD_MAX)
    return role;
  /* Explicit physical slots can coincide with an observed named allocation.
   * The source inventory already contains their sorted identities; private
   * allocations above use their owning name instead of observing every slot. */
  uint32_t begin = 0, end = journal->observable_fd_count;
  while (begin < end) {
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_LOOKUP);
    uint32_t middle = begin + (end - begin) / 2;
    if (journal->observable_fds[middle] < fd.value)
      begin = middle + 1;
    else
      end = middle;
  }
  return begin < journal->observable_fd_count &&
                 journal->observable_fds[begin] == fd.value
             ? DEP_READ_OBSERVE_IDENTITY | DEP_READ_OBSERVE_ACCESS
             : 0;
}

/* The forced join: one version over-approximating two, a union of their
 * persistent maps (shell_pmap_union). The value of a key in the result is a
 * function of the two values alone, so the union's memo makes joining
 * versions that share structure cost the node pairs they do not share. The
 * two kinds of key whose value is not a function of the key's two values
 * alone are set apart and computed per version afterwards:
 * - the occupancy of fds 0..63 (SHELL_FD_PARTS parts and their union), and
 *   the binding, read and write facts of those descriptors, whose default
 *   when a version does not store one is decided by its occupancy;
 * - nothing else: a named binding's default depends on the fallback kind of
 *   its override map, which is the union's tag, and a presence entry's on a
 *   generation that the joined epoch invalidates.
 * Marks of a save held at another descriptor are read when the descriptor is
 * read, so a joined version keeps them and reads the same facts. */
typedef struct {
  dep_route_journal_t *journal;
  /* Fallback kind of the override map being joined: INHERITED or DYNAMIC. */
  dep_route_kind_t fallback;
  bool failed;
} dep_fd_union_t;

static bool dep_route_sets_equal(const dep_route_set_t *a,
                                 const dep_route_set_t *b) {
  if (a->count != b->count)
    return false;
  for (uint32_t i = 0; i < a->count; i++)
    if (a->routes[i].kind != b->routes[i].kind ||
        a->routes[i].value != b->routes[i].value)
      return false;
  return true;
}

static bool dep_fd_union_roots(dep_route_journal_t *journal, uint32_t left,
                               uint32_t right, uint8_t tag, uint32_t *out);
static bool dep_fd_force_join_roots(dep_route_journal_t *journal, uint32_t left,
                                    uint32_t right, uint32_t *out);

/* Whether the key's join is decided per version (see above). */
static bool dep_fd_union_context_key(dep_fd_ref_t fd, dep_fd_access_t access) {
  return access == DEP_FD_ACCESS_PROCESS_DOMAIN ||
         (fd.value < 64 &&
          (access == DEP_FD_ACCESS_READ || access == DEP_FD_ACCESS_WRITE ||
           access == DEP_FD_ACCESS_BINDING));
}

/* The join of one key's two facts into *out; an empty fact in *out is no
 * entry. routes and additional are the facts of the two versions, a default
 * where one stores none. Symmetric: operands are ordered by the caller. */
static bool dep_fd_force_fact(dep_fd_union_t *u, dep_fd_ref_t fd,
                              dep_fd_access_t access,
                              const dep_route_set_t *left,
                              const dep_route_set_t *right,
                              dep_route_set_t *out) {
  dep_route_set_t routes = *left, additional = *right;
  bool equal = dep_route_sets_equal(&routes, &additional);
  if (!equal)
    DEP_TRACE(SHELLSPLIT_TRACE_FORCE, DEP_ACCESS_INDEX(access));
  *out = routes;
  if (access == DEP_FD_ACCESS_NAMED_BINDINGS) {
    dep_fd_route_t a = routes.count ? routes.routes[0]
                                    : (dep_fd_route_t){DEP_ROUTE_INHERITED, 0};
    dep_fd_route_t b = additional.count
                           ? additional.routes[0]
                           : (dep_fd_route_t){DEP_ROUTE_INHERITED, 0};
    if (a.kind != b.kind) {
      /* Bindings established on one side only are not proven on the other:
       * every name is unknown, with an empty override map. */
      dep_route_set_set(out, (dep_fd_route_t){DEP_ROUTE_DYNAMIC, 0});
      return true;
    }
    uint32_t map;
    if (!dep_fd_union_roots(u->journal, a.value, b.value,
                            a.kind == DEP_ROUTE_DYNAMIC
                                ? DEP_UNION_NAMED_DYNAMIC
                                : DEP_UNION_NAMED_INHERITED,
                            &map))
      return false;
    dep_route_set_set(out, (dep_fd_route_t){a.kind, map});
    return true;
  }
  if (!equal && access == DEP_FD_ACCESS_PRESENCE_MAP) {
    /* Presence facts live in a sub-map whose root is this fact: join it
     * name by name rather than keeping either root. */
    uint32_t map;
    if (!dep_fd_union_roots(u->journal,
                            routes.count ? routes.routes[0].value : 0,
                            additional.count ? additional.routes[0].value : 0,
                            DEP_UNION_FACTS, &map))
      return false;
    dep_route_set_set(out, (dep_fd_route_t){DEP_ROUTE_INHERITED, map});
    return true;
  }
  if (!equal && access == DEP_FD_ACCESS_VARIABLE_PRESENCE) {
    /* A presence read takes one fact, so a joined name is unknown. Differing
     * epochs (key 0) take a generation no entry carries, which reads every
     * name without an agreeing entry as unknown too. */
    dep_route_set_set(out, (dep_fd_route_t){DEP_ROUTE_DYNAMIC, UINT32_MAX});
    return true;
  }
  if (!equal && access == DEP_FD_ACCESS_PRIVATE_ENTRY &&
      fd.value != DEP_SCALAR_IMPORT_EVENT && routes.count == 1 &&
      additional.count == 1) {
    /* The fact holds the parent's state at the fork. Two versions forked from
     * different parents return to the join of both, not to the first. */
    uint32_t origin;
    if (!dep_fd_force_join_roots(u->journal, routes.routes[0].value,
                                 additional.routes[0].value, &origin))
      return false;
    dep_route_set_set(out, (dep_fd_route_t){DEP_ROUTE_INHERITED, origin});
    out->ready = true;
    return true;
  }
  if (!equal && access == DEP_FD_ACCESS_PROCESS_OWNED) {
    /* The fact holds the root of an ownership set; join the sets, not two
     * roots, of which a reader takes the first. */
    uint32_t joined = routes.count ? routes.routes[0].value : 0;
    if (!dep_owned_join(u->journal, &joined,
                        additional.count ? additional.routes[0].value : 0))
      return false;
    *out = (dep_route_set_t){.ready = true};
    if (joined)
      dep_route_set_set(out, (dep_fd_route_t){DEP_ROUTE_INHERITED, joined});
    out->ready = true;
    return true;
  }
  if (access == DEP_FD_ACCESS_SELECTOR && !equal) {
    /* One allocation identity, placed on either side's places. */
    if (!routes.count || !additional.count) {
      *out = routes.count ? routes : additional;
      return true;
    }
    shell_fd_allocation_t places = dep_slot_places(&routes);
    shell_fd_allocation_t other = dep_slot_places(&additional);
    places.candidates |= other.candidates;
    places.tail |= other.tail;
    *out = dep_slot_places_fact(routes.routes[0].value, places);
    return true;
  }
  if (access == DEP_FD_ACCESS_IFS) {
    uint32_t value =
        dep_ifs_join(routes.routes[0].value, additional.routes[0].value);
    if (value != routes.routes[0].value)
      dep_route_set_set(out, (dep_fd_route_t){DEP_ROUTE_INHERITED, value});
    return true;
  }
  if (access == DEP_FD_ACCESS_BINDING) {
    /* A read's operand value, descriptor existence and byte route are one
     * execution alternative. Do not manufacture a closed binding with a live
     * capability. */
    bool unknown = false, unseen = false, live = false;
    for (unsigned side = 0; side < 2; side++) {
      const dep_route_set_t *facts = side ? &additional : &routes;
      for (uint32_t i = 0; i < facts->count; i++) {
        unknown |= facts->routes[i].kind == DEP_ROUTE_DYNAMIC;
        unseen |= facts->routes[i].kind == DEP_ROUTE_UNSEEN;
        live |= facts->routes[i].kind == DEP_ROUTE_INHERITED ||
                facts->routes[i].kind == DEP_ROUTE_ALIAS;
      }
    }
    if (unknown || (unseen && live)) {
      if (!(routes.count == 1 && routes.routes[0].kind == DEP_ROUTE_DYNAMIC))
        dep_route_set_set(out, (dep_fd_route_t){DEP_ROUTE_DYNAMIC, UINT32_MAX});
      return true;
    }
  }
  /* Facts that keep their order, or are sets: every alternative of both. */
  for (uint32_t i = 0; i < additional.count; i++)
    if (!dep_route_set_add(out, additional.routes[i]))
      return false;
  return true;
}

/* The default a version gives a key it does not store, as far as the key
 * alone and the override map's fallback decide it. */
static dep_route_set_t dep_fd_union_default(const dep_fd_union_t *u,
                                            dep_fd_ref_t fd,
                                            dep_fd_access_t access) {
  if (fd.value == SHELL_DEP_FD_NAMED) {
    dep_route_set_t result = {0};
    if (access == DEP_FD_ACCESS_BINDING && u->fallback == DEP_ROUTE_DYNAMIC) {
      dep_route_set_set(&result,
                        (dep_fd_route_t){DEP_ROUTE_DYNAMIC, UINT32_MAX});
      return result;
    }
    if (access == DEP_FD_ACCESS_VARIABLE_PRESENCE) {
      dep_route_set_set(&result, (dep_fd_route_t){DEP_ROUTE_DYNAMIC, 0});
      return result;
    }
  }
  if (access == DEP_FD_ACCESS_NAMED_BINDINGS) {
    dep_route_set_t result = {0};
    dep_route_set_set(&result, (dep_fd_route_t){DEP_ROUTE_INHERITED, 0});
    return result;
  }
  return dep_fd_default_fact(fd, access, false);
}

static uint32_t dep_fd_union_leaf(void *context, uint64_t key, uint32_t left,
                                  uint32_t right) {
  dep_fd_union_t *u = context;
  dep_route_journal_t *journal = u->journal;
  dep_fd_ref_t fd = dep_route_key_fd(journal, key);
  dep_fd_access_t access = dep_route_key_access(key);
  /* Placeholder, replaced per version by dep_fd_force_context_keys. */
  if (dep_fd_union_context_key(fd, access))
    return left > right ? left : right;
  dep_route_set_t absent = dep_fd_union_default(u, fd, access);
  const dep_route_set_t *a =
      left ? &journal->arena->snapshots[left - 1] : &absent;
  const dep_route_set_t *b =
      right ? &journal->arena->snapshots[right - 1] : &absent;
  dep_route_set_t joined;
  if (!dep_fd_force_fact(u, fd, access, a, b, &joined)) {
    u->failed = true;
    return left;
  }
  /* The left version's representation is kept: a fact it stores stays, one it
   * does not store stays unstored when the join says no more than the default.
   * (An empty stored fact is a marker, so it too is the left version's.) */
  if (left ? dep_route_sets_equal(&joined, a)
           : dep_route_sets_equal(&joined, &absent))
    return left;
  uint32_t id = dep_route_set_intern(journal, &joined);
  if (!id)
    u->failed = true;
  return id;
}

static bool dep_fd_union_roots(dep_route_journal_t *journal, uint32_t left,
                               uint32_t right, uint8_t tag, uint32_t *out) {
  dep_fd_union_t u = {journal,
                      tag == DEP_UNION_NAMED_DYNAMIC ? DEP_ROUTE_DYNAMIC
                                                     : DEP_ROUTE_INHERITED,
                      false};
  bool built = shell_pmap_union(&journal->arena->maps, left, right,
                                dep_fd_union_leaf, &u, out, false, tag);
  if (u.failed) {
    /* The leaf's failure is out of band, so the pool recorded the unions it
     * completed as if they had succeeded. Drop them. */
    shell_pmap_memo_clear(&journal->arena->maps);
    return false;
  }
  return built;
}

/* The occupancy fact joining part of the two versions' process domains; l and
 * r are the facts they store. A version without one has the occupancy of its
 * binding facts. */
static dep_route_set_t dep_fd_domain_joined(dep_route_journal_t *journal,
                                            uint32_t left_root,
                                            uint32_t right_root, uint32_t part,
                                            uint32_t l, uint32_t r) {
  dep_route_state_t left = dep_route_state_single(left_root);
  dep_route_state_t right = dep_route_state_single(right_root);
  shell_fd_occupancy_t joined =
      l ? dep_domain_value(&journal->arena->snapshots[l - 1])
      : part == DEP_DOMAIN_UNION ? dep_fd_occupancy_masks(&left, journal)
                                 : dep_fd_domain(&left, journal).part[part];
  shell_fd_occupancy_t other =
      r ? dep_domain_value(&journal->arena->snapshots[r - 1])
      : part == DEP_DOMAIN_UNION ? dep_fd_occupancy_masks(&right, journal)
                                 : dep_fd_domain(&right, journal).part[part];
  shell_fd_occupancy_join(&joined, &other);
  return dep_domain_fact(joined);
}

/* Join the fact of one key of the version rooted at source into state, whose
 * root before the join is left. */
static bool dep_fd_force_key(dep_route_state_t *state,
                             dep_route_journal_t *journal, uint32_t left,
                             uint32_t source, dep_fd_ref_t fd,
                             dep_fd_access_t access) {
  if (access == DEP_FD_ACCESS_PROCESS_DOMAIN) {
    uint32_t l = dep_route_map_snapshot(left, journal, fd, access);
    uint32_t r = dep_route_map_snapshot(source, journal, fd, access);
    if (l == r)
      return true;
    dep_route_set_t fact =
        dep_fd_domain_joined(journal, left, source, fd.value, l, r);
    return dep_route_state_append_one(state, journal, fd, access, fact);
  }
  dep_fd_union_t u = {journal, DEP_ROUTE_INHERITED, false};
  dep_route_set_t a = dep_fd_raw_root_own_fact(left, journal, fd, access),
                  b = dep_fd_raw_root_own_fact(source, journal, fd, access),
                  joined;
  if (!dep_fd_force_fact(&u, fd, access, &a, &b, &joined))
    return false;
  return dep_route_sets_equal(&joined, &a) ||
         dep_route_state_append_one(state, journal, fd, access, joined);
}

typedef struct {
  dep_route_journal_t *journal;
  uint32_t left_root, right_root, *root;
} dep_fd_context_keys_t;

/* A key decided per version, stored differently by the two versions: the
 * join of the two versions' own facts, a version's default included. A
 * version's stored form is kept when it already says the joined fact. */
static bool dep_fd_context_key(void *context, dep_fd_ref_t fd,
                               dep_fd_access_t access, uint32_t l, uint32_t r) {
  dep_fd_context_keys_t *walk = context;
  dep_route_journal_t *journal = walk->journal;
  if (!dep_fd_union_context_key(fd, access))
    return true;
  uint32_t id;
  if (access == DEP_FD_ACCESS_PROCESS_DOMAIN) {
    dep_route_set_t fact = dep_fd_domain_joined(
        journal, walk->left_root, walk->right_root, fd.value, l, r);
    id = dep_route_set_intern(journal, &fact);
    if (!id)
      return false;
  } else {
    dep_fd_union_t u = {journal, DEP_ROUTE_INHERITED, false};
    dep_route_set_t a = dep_fd_raw_root_own_fact(walk->left_root, journal, fd,
                                                 access),
                    b = dep_fd_raw_root_own_fact(walk->right_root, journal, fd,
                                                 access),
                    joined;
    if (!dep_fd_force_fact(&u, fd, access, &a, &b, &joined))
      return false;
    if (dep_route_sets_equal(&joined, &a))
      id = l;
    else if (dep_route_sets_equal(&joined, &b))
      id = r;
    else if (!(id = dep_route_set_intern(journal, &joined)))
      return false;
  }
  return id == dep_route_map_snapshot(*walk->root, journal, fd, access) ||
         dep_route_map_put(journal, walk->root, fd, access, id);
}

/* Set the keys of *root decided per version (see dep_fd_union_t). They are
 * the keys below 4096, so the subtries of the two versions that hold them
 * are found without a walk, and only the keys they store differently are
 * visited: at most those of fds 0..63 and the domain. */
static bool dep_fd_force_context_keys(dep_route_journal_t *journal,
                                      uint32_t left_root, uint32_t right_root,
                                      uint32_t *root) {
  uint32_t left = shell_pmap_restrict(&journal->arena->maps, left_root, 0, 12);
  uint32_t right =
      shell_pmap_restrict(&journal->arena->maps, right_root, 0, 12);
  dep_fd_context_keys_t walk = {journal, left_root, right_root, root};
  return left == right ||
         dep_route_map_diff(journal, left, right, dep_fd_context_key, &walk);
}

/* The single version over-approximating the versions rooted at left and
 * right. */
static bool dep_fd_force_join_roots(dep_route_journal_t *journal, uint32_t left,
                                    uint32_t right, uint32_t *out) {
  if (left == right) {
    *out = left;
    return true;
  }
  return dep_fd_union_roots(journal, left, right, DEP_UNION_FACTS, out) &&
         dep_fd_force_context_keys(journal, left, right, out);
}

typedef struct {
  /* Join versions whose inherited low-interval cases differ when nothing
   * else keeps them apart. */
  bool origins;
  /* Set when the join of the two versions is not exact: a correlation or an
   * alias would be lost. The caller keeps the versions apart. */
  bool apart;
} dep_fd_merge_relation_t;

typedef struct {
  uint32_t left, right;
} dep_fd_roots_t;

/* What a fold over two versions' maps returns (shell_pmap_fold). */
enum {
  /* The join at some key is not exact. */
  DEP_EXACT_APART = 1u,
  /* The answer at some key needs other facts of the two versions. */
  DEP_EXACT_CONTEXT = 2u
};

/* Whether the join of the two versions at one key keeps what a later read
 * of either can tell apart: sets relation->apart if it does not. left_set and
 * right_set are the two versions' facts at the key, a version's default where
 * it stores none. roots are the two versions' roots, for the keys whose
 * answer needs other facts of them; NULL where the caller has left those
 * keys to a pass that has the roots (dep_fd_exact_roots). access is not
 * DEP_FD_ACCESS_NAMED_BINDINGS, whose facts are maps compared by a fold of
 * their own (dep_fd_named_exact). The join itself is dep_fd_force_join_roots.
 */
static SHELL_NONNULL(1, 5, 6, 7) void dep_fd_key_exact(
    dep_route_journal_t *journal, const dep_fd_roots_t *roots, dep_fd_ref_t fd,
    dep_fd_access_t access, const dep_route_set_t *left_set,
    const dep_route_set_t *right_set, dep_fd_merge_relation_t *relation) {
  dep_route_set_t routes = *left_set;
  dep_route_set_t additional = *right_set;
  bool equal = dep_route_sets_equal(&routes, &additional);
  if (access == DEP_FD_ACCESS_VARIABLE_PRESENCE ||
      access == DEP_FD_ACCESS_PRESENCE_MAP ||
      access == DEP_FD_ACCESS_PROCESS_OWNED ||
      access == DEP_FD_ACCESS_PRIVATE_SCOPE ||
      access == DEP_FD_ACCESS_EFFECT_STATE ||
      access == DEP_FD_ACCESS_SUBSTITUTION_STATUS ||
      access == DEP_FD_ACCESS_PRIVATE_ENTRY || access == DEP_FD_ACCESS_SAVED ||
      access == DEP_FD_ACCESS_ALLOCATION_SLOTS ||
      access == DEP_FD_ACCESS_UNDO_ENTRY ||
      access == DEP_FD_ACCESS_UNDO_TARGET ||
      access == DEP_FD_ACCESS_UNDO_EXEC || access == DEP_FD_ACCESS_SCRATCH ||
      access == DEP_FD_ACCESS_SETUP_MODE ||
      access == DEP_FD_ACCESS_STDIN_REDIR ||
      access == DEP_FD_ACCESS_READ_ARGUMENT ||
      access == DEP_FD_ACCESS_PROCESS_SLOT ||
      access == DEP_FD_ACCESS_SELECTOR) {
    /* A scratch slot and an ordinary descriptor on another path cannot share
     * a factored map. Preserve ownership until the frame disposes its saves. */
    if (!equal)
      relation->apart = true;
    return;
  }
  if (access == DEP_FD_ACCESS_PROCESS_DOMAIN) {
    if (equal)
      return;
    /* Versions split by inherited low-interval case keep allocations
     * correlated with that case; a join would lose it. */
    if (!relation->origins) {
      dep_route_state_t left = dep_route_state_single(roots->left);
      dep_route_state_t right = dep_route_state_single(roots->right);
      if (dep_fd_domain_origins(&left, journal) !=
          dep_fd_domain_origins(&right, journal))
        relation->apart = true;
    }
    return;
  }
  if (fd.value == SHELL_DEP_FD_NAMED &&
      (access == DEP_FD_ACCESS_READ || access == DEP_FD_ACCESS_WRITE)) {
    /* Factoring is safe only when selecting an alias cannot select another
     * path's slot contents. Private allocation identities missing on a path
     * carry no competing resource; observable numeric identities do. */
    for (unsigned side = 0; side < 2; side++) {
      const dep_route_set_t *aliases = side ? &additional : &routes;
      for (uint32_t i = 0; i < aliases->count; i++) {
        dep_fd_route_t alias = aliases->routes[i];
        if (alias.kind != DEP_ROUTE_ALIAS)
          continue;
        dep_fd_ref_t slot = dep_fd_numeric(alias.value);
        dep_route_set_t left =
            dep_fd_raw_root_own_fact(roots->left, journal, slot, access);
        dep_route_set_t right =
            dep_fd_raw_root_own_fact(roots->right, journal, slot, access);
        bool private_slot = alias.value > SHELL_DEP_FD_MAX;
        bool present[2] = {false, false};
        bool agree = true;
        /* Neither fact needs interning just to decide whether the join may
         * discard its association. */
        for (unsigned direction = 0; direction < 2; direction++) {
          const dep_route_set_t *from = direction ? &right : &left;
          const dep_route_set_t *to = direction ? &left : &right;
          for (uint32_t j = 0; j < from->count; j++) {
            dep_fd_route_t route = from->routes[j];
            if (private_slot && (route.kind == DEP_ROUTE_ABSENT ||
                                 route.kind == DEP_ROUTE_UNAVAILABLE ||
                                 route.kind == DEP_ROUTE_CLOSED))
              continue;
            present[direction] = true;
            bool found = false;
            for (uint32_t k = 0; k < to->count; k++)
              found |= route.kind == to->routes[k].kind &&
                       route.value == to->routes[k].value;
            agree &= found;
          }
        }
        bool missing = private_slot && (!present[0] || !present[1]);
        if (!missing && !agree) {
          relation->apart = true;
          return;
        }
      }
    }
  }
  if (access == DEP_FD_ACCESS_READ &&
      (dep_read_binding_observation(journal, fd) & DEP_READ_OBSERVE_ACCESS)) {
    /* Alternatives infeasible under the requirements need no version. */
    dep_route_set_t left =
        dep_access_required_feasible(roots->left, journal, fd, &routes);
    dep_route_set_t right =
        dep_access_required_feasible(roots->right, journal, fd, &additional);
    if (left.count && right.count &&
        dep_read_access_outcomes(&left) != dep_read_access_outcomes(&right)) {
      relation->apart = true;
      return;
    }
  }
  if (access == DEP_FD_ACCESS_BINDING) {
    /* A read's operand value, descriptor existence and byte route are one
     * execution alternative. Do not manufacture a closed binding with a live
     * capability (or let the representative discard a feasible open path). */
    unsigned observation = dep_read_binding_observation(journal, fd);
    /* Alternatives infeasible under the requirements need no version. */
    dep_route_set_t left = dep_required_feasible(&routes);
    dep_route_set_t right = dep_required_feasible(&additional);
    bool different_argument = left.count != right.count;
    if (fd.value == SHELL_DEP_FD_NAMED &&
        (observation & DEP_READ_OBSERVE_IDENTITY))
      for (uint32_t i = 0; !different_argument && i < left.count; i++)
        different_argument = left.routes[i].kind != right.routes[i].kind ||
                             left.routes[i].value != right.routes[i].value;
    if (observation && left.count && right.count &&
        (fd.value == SHELL_DEP_FD_NAMED
             ? (observation & DEP_READ_OBSERVE_IDENTITY
                    ? different_argument
                    : dep_read_value_class(&left) !=
                          dep_read_value_class(&right))
             : dep_read_binding_outcomes(&left) !=
                   dep_read_binding_outcomes(&right)))
      relation->apart = true;
  }
}
/* Whether the answer of dep_fd_key_exact at this key needs the roots: the
 * alias check of a named read or write, and the feasibility of an observed
 * read. */
static bool dep_fd_exact_needs_roots(const dep_route_journal_t *journal,
                                     dep_fd_ref_t fd, dep_fd_access_t access,
                                     const dep_route_set_t *left,
                                     const dep_route_set_t *right) {
  if (access == DEP_FD_ACCESS_READ &&
      (dep_read_binding_observation(journal, fd) & DEP_READ_OBSERVE_ACCESS))
    return true;
  if (fd.value != SHELL_DEP_FD_NAMED ||
      (access != DEP_FD_ACCESS_READ && access != DEP_FD_ACCESS_WRITE))
    return false;
  for (unsigned side = 0; side < 2; side++) {
    const dep_route_set_t *facts = side ? right : left;
    for (uint32_t i = 0; i < facts->count; i++)
      if (facts->routes[i].kind == DEP_ROUTE_ALIAS)
        return true;
  }
  return false;
}

typedef struct {
  dep_route_journal_t *journal;
  /* Fallback kind of the override map being compared. */
  dep_route_kind_t fallback;
  /* Set for the pass that decides the keys that need them. */
  const dep_fd_roots_t *roots;
  /* Set when the memo was full at a key: the fold decided nothing. */
  bool failed;
} dep_fd_exact_t;

static uint32_t dep_fd_exact_leaf(void *context, uint64_t key, uint32_t left,
                                  uint32_t right);

/* Named bindings: each version's fact is the root of a map of overrides keyed
 * by name, and a name a map lacks reads as its fallback kind. The join keeps
 * the versions' correlation only if the maps' fold finds nothing a read could
 * tell apart; any bit, including a need for the roots, is apart. A fold the
 * memo cannot hold sets exact->failed. */
static uint32_t dep_fd_named_exact(dep_fd_exact_t *exact,
                                   const dep_route_set_t *left_set,
                                   const dep_route_set_t *right_set) {
  dep_fd_route_t left = left_set->count
                            ? left_set->routes[0]
                            : (dep_fd_route_t){DEP_ROUTE_INHERITED, 0};
  dep_fd_route_t right = right_set->count
                             ? right_set->routes[0]
                             : (dep_fd_route_t){DEP_ROUTE_INHERITED, 0};
  if (left.kind != right.kind)
    return DEP_EXACT_APART;
  bool dynamic = left.kind == DEP_ROUTE_DYNAMIC;
  dep_fd_exact_t nested = {exact->journal,
                           dynamic ? DEP_ROUTE_DYNAMIC : DEP_ROUTE_INHERITED,
                           NULL, false};
  uint32_t bits;
  if (!shell_pmap_fold(&exact->journal->arena->maps, left.value, right.value,
                       dep_fd_exact_leaf, &nested, &bits, true,
                       dynamic ? DEP_FOLD_NAMED_DYNAMIC
                               : DEP_FOLD_NAMED_INHERITED) ||
      nested.failed) {
    exact->failed = true;
    return DEP_EXACT_APART;
  }
  return bits ? DEP_EXACT_APART : 0;
}

/* One key where the two versions differ, in the pass over their maps that
 * needs no roots: the bit of an inexact join, or that the key needs them.
 * Keys decided per version (see dep_fd_union_t) are left to
 * dep_fd_exact_context_key. */
static uint32_t dep_fd_exact_leaf(void *context, uint64_t key, uint32_t left,
                                  uint32_t right) {
  dep_fd_exact_t *exact = context;
  dep_route_journal_t *journal = exact->journal;
  dep_fd_ref_t fd = dep_route_key_fd(journal, key);
  dep_fd_access_t access = dep_route_key_access(key);
  if (dep_fd_union_context_key(fd, access))
    return 0;
  dep_fd_union_t defaults = {journal, exact->fallback, false};
  dep_route_set_t absent = dep_fd_union_default(&defaults, fd, access);
  const dep_route_set_t *a =
      left ? &journal->arena->snapshots[left - 1] : &absent;
  const dep_route_set_t *b =
      right ? &journal->arena->snapshots[right - 1] : &absent;
  if (access == DEP_FD_ACCESS_NAMED_BINDINGS)
    return dep_fd_named_exact(exact, a, b);
  if (dep_fd_exact_needs_roots(journal, fd, access, a, b))
    return exact->roots ? 0 : DEP_EXACT_CONTEXT;
  dep_fd_merge_relation_t relation = {0};
  dep_fd_key_exact(journal, NULL, fd, access, a, b, &relation);
  if (relation.apart)
    DEP_TRACE(SHELLSPLIT_TRACE_APART, DEP_ACCESS_INDEX(access));
  return relation.apart ? DEP_EXACT_APART : 0;
}

/* The same key in the pass that has the roots, for the keys that need them:
 * an observed read, or a named one that may select a slot. The two versions'
 * own facts stand for a key one does not store. */
static uint32_t dep_fd_exact_roots_leaf(void *context, uint64_t key,
                                        uint32_t left, uint32_t right) {
  dep_fd_exact_t *exact = context;
  dep_route_journal_t *journal = exact->journal;
  dep_fd_ref_t fd = dep_route_key_fd(journal, key);
  dep_fd_access_t access = dep_route_key_access(key);
  if (dep_fd_union_context_key(fd, access))
    return 0;
  dep_route_set_t a = left ? journal->arena->snapshots[left - 1]
                           : dep_fd_raw_root_own_fact(exact->roots->left,
                                                      journal, fd, access),
                  b = right ? journal->arena->snapshots[right - 1]
                            : dep_fd_raw_root_own_fact(exact->roots->right,
                                                       journal, fd, access);
  if (!dep_fd_exact_needs_roots(journal, fd, access, &a, &b))
    return 0;
  dep_fd_merge_relation_t relation = {0};
  dep_fd_key_exact(journal, exact->roots, fd, access, &a, &b, &relation);
  if (relation.apart)
    DEP_TRACE(SHELLSPLIT_TRACE_APART, DEP_ACCESS_INDEX(access));
  return relation.apart ? DEP_EXACT_APART : 0;
}

typedef struct {
  dep_route_journal_t *journal;
  dep_fd_roots_t roots;
  dep_fd_merge_relation_t *relation;
} dep_fd_context_walk_t;

/* A key decided per version, stored differently by the two versions. */
static bool dep_fd_exact_context_key(void *context, dep_fd_ref_t fd,
                                     dep_fd_access_t access, uint32_t l,
                                     uint32_t r) {
  dep_fd_context_walk_t *walk = context;
  dep_route_journal_t *journal = walk->journal;
  if (!dep_fd_union_context_key(fd, access))
    return true;
  dep_route_set_t a = l ? journal->arena->snapshots[l - 1]
                        : dep_fd_raw_root_own_fact(walk->roots.left, journal,
                                                   fd, access),
                  b = r ? journal->arena->snapshots[r - 1]
                        : dep_fd_raw_root_own_fact(walk->roots.right, journal,
                                                   fd, access);
  dep_fd_key_exact(journal, &walk->roots, fd, access, &a, &b, walk->relation);
  if (walk->relation->apart)
    DEP_TRACE(SHELLSPLIT_TRACE_APART, DEP_ACCESS_INDEX(access));
  return !walk->relation->apart;
}

/* Whether the join of the versions rooted at left and right loses what a
 * later read of either tells apart at some key: *apart is true then, and the
 * versions stay apart. Most keys are decided from their two facts alone, in a
 * fold of the two maps that costs the node pairs they do not share and is
 * memoized across merges. The keys below 4096 (fds 0..63 and the occupancy)
 * have defaults that depend on the version, and are decided from a walk of the
 * at most 197 of them that differ. An observed read, or a named one that may
 * select a slot, needs the roots: only when one of them differs is there a
 * further pass over the maps, which is not memoized. False when the memo is
 * full: the exactness is then unknown. Keeping the versions apart would be
 * sound, but could admit a source the full memo refuses (the versions need not
 * merge into the imprecise one), so the merge fails like one that finds the
 * pool full, and a memo too small only ever refuses. */
static bool dep_fd_exact_roots(dep_route_journal_t *journal, uint32_t left,
                               uint32_t right, bool origins, bool *apart) {
  dep_fd_exact_t exact = {journal, DEP_ROUTE_INHERITED, NULL, false};
  uint32_t bits;
  if (!shell_pmap_fold(&journal->arena->maps, left, right, dep_fd_exact_leaf,
                       &exact, &bits, true, DEP_FOLD_FACTS) ||
      exact.failed)
    return false;
  *apart = bits & DEP_EXACT_APART;
  if (*apart)
    return true;
  dep_fd_merge_relation_t relation = {.origins = origins};
  dep_fd_context_walk_t walk = {journal, {left, right}, &relation};
  dep_route_map_diff(journal,
                     shell_pmap_restrict(&journal->arena->maps, left, 0, 12),
                     shell_pmap_restrict(&journal->arena->maps, right, 0, 12),
                     dep_fd_exact_context_key, &walk);
  if (!relation.apart && (bits & DEP_EXACT_CONTEXT)) {
    exact.roots = &walk.roots;
    uint32_t more = 0;
    /* Without the memo a fold needs no entry, so it cannot fail. */
    (void)shell_pmap_fold(&journal->arena->maps, left, right,
                          dep_fd_exact_roots_leaf, &exact, &more, false,
                          DEP_FOLD_FACTS);
    relation.apart = more & DEP_EXACT_APART;
  }
  *apart = relation.apart;
  return true;
}

static SHELL_NONNULL(1) dep_route_join_t *dep_fd_join_cache(
    dep_route_journal_t *journal, uint32_t left, uint32_t right) {
  uint32_t low = left < right ? left : right;
  uint32_t high = left < right ? right : left;
  size_t bucket =
      ((size_t)low * 2654435761u + high) % DEP_ROUTE_OPERATION_CAPACITY;
  return &journal->arena->joins[bucket];
}

/* destination is a single provisional factorized root. If *apart becomes
 * true, its caller discards that candidate and retains the original versions.
 */
static SHELL_NONNULL(1, 2,
                     4) bool dep_fd_merge_root(dep_route_state_t *destination,
                                               dep_route_journal_t *journal,
                                               uint32_t source_root,
                                               bool *apart) {
  if (destination->root == source_root) {
    DEP_TRACE(SHELLSPLIT_TRACE_MERGE, 0);
    return true;
  }
  uint32_t left_root = destination->root;
  uint32_t low = left_root < source_root ? left_root : source_root;
  uint32_t high = left_root < source_root ? source_root : left_root;
  dep_route_join_t *cached = dep_fd_join_cache(journal, left_root, source_root);
  if (cached->left == low && cached->right == high) {
    if (cached->result == UINT32_MAX) {
      DEP_TRACE(SHELLSPLIT_TRACE_MERGE, 1);
      *apart = true;
      return true;
    }
    DEP_TRACE(SHELLSPLIT_TRACE_MERGE, 2);
    destination->root = cached->result;
    return true;
  }
  if (!dep_fd_exact_roots(journal, left_root, source_root, false, apart))
    return false;
  if (!*apart && !dep_fd_force_join_roots(journal, left_root, source_root,
                                          &destination->root))
    return false;
  DEP_TRACE(SHELLSPLIT_TRACE_MERGE, *apart ? 3 : 4);
  /* UINT32_MAX caches an unfactorable association, not a journal root. */
  *cached =
      (dep_route_join_t){low, high, *apart ? UINT32_MAX : destination->root};
  return true;
}

/* Join source_root into destination's primary root when the versions differ
 * in their inherited low-interval cases but in nothing a join must keep
 * apart; otherwise set *apart. Not cached: the cache holds joins that keep
 * the cases apart. */
static SHELL_NONNULL(1, 2, 4) bool dep_fd_factor_origins(
    dep_route_state_t *destination, dep_route_journal_t *journal,
    uint32_t source_root, bool *apart) {
  if (destination->root == source_root)
    return true;
  uint32_t left_root = destination->root;
  if (!dep_fd_exact_roots(journal, left_root, source_root, true, apart))
    return false;
  return *apart || dep_fd_force_join_roots(journal, left_root, source_root,
                                           &destination->root);
}

/* The outcomes of one operation, joined per inherited low-interval case, as
 * one version when the cases' outcomes factor. */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_factor_choices(
    dep_route_state_t *chosen, bool *have_choice,
    dep_route_journal_t *journal) {
  if (!have_choice[0] || !have_choice[1])
    return true;
  dep_route_state_t factored = chosen[0];
  bool apart = false;
  if (!dep_fd_factor_origins(&factored, journal, chosen[1].root, &apart))
    return false;
  if (apart)
    return true;
  chosen[0] = factored;
  have_choice[1] = false;
  return true;
}

/* The single version over-approximating destination's and source_root's
 * paths, joined in place of destination's primary root. */
static SHELL_NONNULL(1, 2) bool dep_fd_join_root(dep_route_state_t *destination,
                                                 dep_route_journal_t *journal,
                                                 uint32_t source_root) {
  return dep_fd_force_join_roots(journal, destination->root, source_root,
                                 &destination->root);
}

/* Join every version of source into the single version of destination. */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_join(dep_route_state_t *destination,
                                               const dep_route_state_t *source,
                                               dep_route_journal_t *journal) {
  if (destination->truncated || source->truncated)
    return false;
  dep_route_state_t joined = dep_route_state_single(destination->root);
  for (unsigned side = 0; side < 2; side++) {
    dep_route_iterator_t iterator =
        dep_route_iterator(side ? source : destination);
    uint32_t root;
    while (dep_route_next(&iterator, journal, &root))
      if (!dep_fd_join_root(&joined, journal, root))
        return false;
  }
  dep_route_state_inherit(&joined, destination);
  dep_route_state_inherit(&joined, source);
  *destination = joined;
  return true;
}

static SHELL_NONNULL(1, 2, 3) bool dep_fd_merge_classes(
    dep_route_state_t *destination, const dep_route_state_t *source,
    dep_route_journal_t *journal) {
  if (journal->read_observations.active && !journal->named_closes)
    return dep_fd_merge_versions(destination, source, journal);
  bool correlated = dep_route_state_correlated(destination) ||
                    dep_route_state_correlated(source);
  if (correlated && journal->named_closes)
    return dep_fd_merge_versions(destination, source, journal);
  dep_route_state_t collapsed = dep_route_state_single(destination->root);
  dep_route_iterator_t iterator = dep_route_iterator(destination);
  /* The primary version is already represented by collapsed. */
  iterator.first = false;
  uint32_t root;
  bool apart = false;
  while (!apart && dep_route_next(&iterator, journal, &root))
    if (!dep_fd_merge_root(&collapsed, journal, root, &apart))
      return false;
  iterator = dep_route_iterator(source);
  while (!apart && dep_route_next(&iterator, journal, &root))
    if (!dep_fd_merge_root(&collapsed, journal, root, &apart))
      return false;
  if (apart) {
    iterator = dep_route_iterator(source);
    while (dep_route_next(&iterator, journal, &root))
      if (!dep_route_state_add_root(destination, journal, root))
        return false;
  } else {
    *destination = collapsed;
  }
  return true;
}

/* Bounded disjunctive completion: a merge keeps correlated versions apart
 * only up to DEP_ROUTE_VERSION_LIMIT. Beyond it the pair whose join loses the
 * least is replaced by that join, until the limit holds: a sound
 * over-approximation, so every later operation costs at most that many
 * versions however many paths kept their correlation. Which versions merge
 * never depends on where they sit: the loss of a pair is the number of keys
 * its two versions differ in, found with doubling budgets so the cost follows
 * the cheapest pair, not the unknown size of the others. Versions that
 * diverged at one fork sit within DEP_ROUTE_MERGE_WINDOW of each other, so
 * only those neighbours are candidates, which keeps a step linear in the
 * version count. */
enum { DEP_ROUTE_MERGE_WINDOW = 4, DEP_ROUTE_MERGE_BUDGET = 256 };

static SHELL_NONNULL(1, 2) bool dep_fd_widen(dep_route_state_t *state,
                                             dep_route_journal_t *journal) {
  uint32_t count = dep_route_state_count(state);
  if (count <= DEP_ROUTE_VERSION_LIMIT)
    return true;
  uint32_t roots[DEP_ROUTE_STATE_CAPACITY], n = 0, root;
  dep_route_iterator_t iterator = dep_route_iterator(state);
  while (dep_route_next(&iterator, journal, &root))
    roots[n++] = root;
  while (n > DEP_ROUTE_VERSION_LIMIT) {
    uint32_t best_low = 0, best_high = 0;
    for (uint32_t budget = 1; !best_high; budget *= 2) {
      uint32_t limit = budget;
      for (uint32_t low = 0; low + 1 < n && !best_high; low++)
        for (uint32_t high = low + 1;
             high < n && high <= low + DEP_ROUTE_MERGE_WINDOW; high++) {
          DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_ROUTE_ALTERNATIVES);
          uint32_t differing;
          if (shell_pmap_diff_within(&journal->arena->maps, roots[low],
                                     roots[high], limit, &differing)) {
            best_low = low;
            best_high = high;
            break;
          }
        }
      /* No neighbours within the budget: any pair loses about as much, and a
       * join costs the fresh node pairs only. Which pair is joined affects
       * precision, never soundness. */
      if (budget > DEP_ROUTE_MERGE_BUDGET && !best_high) {
        best_low = 0;
        best_high = 1;
        DEP_TRACE(SHELLSPLIT_TRACE_WIDEN, 2);
      }
    }
    DEP_TRACE(SHELLSPLIT_TRACE_WIDEN, 1);
    dep_route_state_t joined = dep_route_state_single(roots[best_low]);
    if (!dep_fd_join_root(&joined, journal, roots[best_high]))
      return false;
    roots[best_low] = joined.root;
    memmove(&roots[best_high], &roots[best_high + 1],
            (n - best_high - 1) * sizeof(roots[0]));
    n--;
  }
  dep_route_state_t widened = {0};
  for (uint32_t i = 0; i < n; i++) {
    if (i == 0)
      widened = dep_route_state_single(roots[i]);
    else if (!dep_route_state_add_root(&widened, journal, roots[i]))
      return false;
  }
  widened.truncated = state->truncated || widened.truncated;
  *state = widened;
  return !state->truncated;
}

/* Merge the classes, then bound the versions they keep. */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_merge(dep_route_state_t *destination,
                                                const dep_route_state_t *source,
                                                dep_route_journal_t *journal) {
  if (destination->truncated || source->truncated)
    return false;
  return dep_fd_merge_classes(destination, source, journal) &&
         dep_fd_widen(destination, journal);
}

/* A path which has not needed a symbolic relation still contributes all of
 * its ordinary occupancy possibilities when joined with a refined path. */
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
static SHELL_NONNULL(1) bool dep_test_domain_joins(
    dep_route_workspace_t *workspace) {
  dep_route_journal_t *journal = &workspace->journal;
  for (unsigned reverse = 0; reverse < 2; reverse++) {
    dep_route_arena_reset(&workspace->route_arena);
    dep_route_journal_reset(journal, &workspace->route_arena);
    /* fds 0..2 open and 10 free on the refined path; nothing else known. */
    shell_fd_occupancy_t constrained = {~UINT64_C(7), UINT64_MAX};
    constrained.may_occupied &= ~(UINT64_C(1) << 10);
    dep_route_state_t ordinary = {0}, refined = {0};
    if (!dep_allocation_select(&refined, journal, constrained, -1))
      return false;
    shell_fd_occupancy_t plain = dep_fd_occupancy_masks(&ordinary, journal);
    dep_route_state_t joined = reverse ? refined : ordinary;
    if (!dep_fd_merge(&joined, reverse ? &ordinary : &refined, journal))
      return false;
    shell_fd_partition_t partition;
    if (dep_route_state_count(&joined) != 1 ||
        !dep_fd_domain_stored(&joined, journal, &partition))
      return false;
    shell_fd_occupancy_t value = shell_fd_partition_union(&partition);
    if ((value.may_free & plain.may_free) != plain.may_free ||
        (value.may_occupied & plain.may_occupied) != plain.may_occupied ||
        (value.may_free & constrained.may_free) != constrained.may_free ||
        (value.may_occupied & constrained.may_occupied) !=
            constrained.may_occupied)
      return false;
  }
  return true;
}
#endif

static SHELL_NONNULL(1, 4) bool dep_fd_add(dep_fd_flow_t *flow,
                                           unsigned outcome,
                                           dep_route_state_t state,
                                           dep_route_journal_t *journal) {
  uint8_t bit = (uint8_t)(1u << outcome);
  if (flow->mask & bit) {
    /* A terminated path (exit, replacement or abort) reaches no later
     * command of its shell, so no correlation between its versions can
     * matter: join them into one, a sound over-approximation. Keeping them
     * apart would grow one version per exit point. */
    if (!((bit & DEP_STATUS_STOP)
              ? dep_fd_join(&flow->state[outcome], &state, journal)
              : dep_fd_merge(&flow->state[outcome], &state, journal)))
      return false;
  } else {
    flow->state[outcome] = state;
    flow->mask |= bit;
  }
  return true;
}

static SHELL_NONNULL(1, 3, 4) bool dep_fd_select(const dep_fd_flow_t *flow,
                                                 uint8_t mask,
                                                 dep_route_journal_t *journal,
                                                 dep_route_state_t *selected) {
  bool found = false;
  *selected = (dep_route_state_t){0};
  for (unsigned i = 0; i < 5; i++)
    if (flow->mask & mask & (1u << i)) {
      if (found) {
        if (!dep_fd_merge(selected, &flow->state[i], journal))
          return false;
      } else {
        *selected = flow->state[i];
        found = true;
      }
    }
  return true;
}

/* Concrete caches hold one immutable version. They are not a new control-flow
 * join: the next semantic consumer selects and joins its required outcomes. */
static SHELL_NONNULL(1, 2) dep_route_state_t
    dep_fd_point_version(const dep_fd_flow_t *flow,
                         const dep_route_state_t *fallback) {
  for (unsigned outcome = 0; outcome < 5; outcome++)
    if (flow->mask & (1u << outcome))
      return flow->state[outcome];
  return *fallback;
}

static SHELL_NONNULL(1, 2) uint8_t
    dep_fd_run_mask(const dep_parse_context_t *context,
                    const dep_fd_stream_t *stream, uint32_t event) {
  const shell_pipeline_index_t *pipeline = &context->execution->pipeline;
  uint16_t connector =
      event < SHELL_MAX_GROUPS
          ? pipeline->group_connector[event]
          : pipeline->range_connector[event - SHELL_MAX_GROUPS];
  if (connector == SHELL_TYPE_PIPELINE) {
    event =
        stream->pipeline_event[dep_snapshot_event_group(context, event) + 1] -
        1;
    connector = event < SHELL_MAX_GROUPS
                    ? pipeline->group_connector[event]
                    : pipeline->range_connector[event - SHELL_MAX_GROUPS];
  }
  return connector == SHELL_TYPE_AND  ? DEP_STATUS_MAY_SUCCEED
         : connector == SHELL_TYPE_OR ? DEP_STATUS_MAY_FAIL
                                      : DEP_STATUS_EITHER;
}

static SHELL_NONNULL(1) bool dep_fd_private(const dep_parse_context_t *context,
                                            uint32_t event) {
  return event < SHELL_MAX_GROUPS
             ? context->group_exec[event].isolated
             : context->execution->pipeline
                   .local_process[event - SHELL_MAX_GROUPS];
}

static SHELL_NONNULL(1) bool dep_fd_outgoing_pipeline(
    const dep_parse_context_t *context, uint32_t event) {
  const shell_pipeline_index_t *pipeline = &context->execution->pipeline;
  return event < SHELL_MAX_GROUPS
             ? pipeline->group_tail[event].has_pipeline
             : pipeline->range_successor[event - SHELL_MAX_GROUPS] ==
                   SHELL_TYPE_PIPELINE;
}

/* Tag each actual entry alternative before installing child pipes, capturing
 * words or applying redirects. Nested private scopes use distinct event keys;
 * restoring the immutable root also restores the enclosing scope's tag.
 * Joins keep distinct origins separate until their outcomes are projected.
 */
static SHELL_NONNULL(1,
                     2) bool dep_fd_private_begin(dep_route_state_t *state,
                                                  dep_route_journal_t *journal,
                                                  uint32_t event) {
  dep_route_state_t tagged = {0};
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  bool first = true;
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    uint32_t owned = dep_process_owned_root(&one, journal);
    dep_route_state_t returned = one;
    if (owned && event != DEP_OBSERVATION_ROOT_EVENT) {
      if (event < SHELL_MAX_GROUPS &&
          !dep_process_fork_parent(&returned, journal, owned))
        return false;
      if (!dep_route_state_store_access(
              &one, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
              DEP_FD_ACCESS_PROCESS_OWNED, (dep_route_set_t){.ready = true}))
        return false;
      if (event < SHELL_MAX_GROUPS &&
          !dep_route_state_store_access(
              &returned, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
              DEP_FD_ACCESS_PROCESS_OWNED, (dep_route_set_t){.ready = true}))
        return false;
    }
    dep_route_set_t origin = {0};
    dep_route_set_set(&origin,
                      (dep_fd_route_t){DEP_ROUTE_INHERITED, returned.root});
    if (!dep_route_state_store_access(&one, journal, dep_fd_numeric(event),
                                      DEP_FD_ACCESS_PRIVATE_ENTRY, origin))
      return false;
    dep_route_set_t scope = {0};
    dep_route_set_set(&scope, (dep_fd_route_t){DEP_ROUTE_INHERITED, event + 1});
    if (!dep_route_state_store_access(&one, journal,
                                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                                      DEP_FD_ACCESS_PRIVATE_SCOPE, scope))
      return false;
    if (first) {
      tagged = one;
      first = false;
    } else if (!dep_route_state_add_root(&tagged, journal, one.root))
      return false;
  }
  dep_route_state_inherit(&tagged, state);
  *state = tagged;
  return true;
}

/* state is a completed alternative from this event's private_begin frame.
 * Project observations/status, never child bindings or local setup. Immutable
 * origins avoid matching a child against an unrelated parent version, and do
 * not infer parent availability from a descriptor opened in the child.
 */
static SHELL_NONNULL(1, 2, 4) bool dep_fd_private_project(
    const dep_route_state_t *state, dep_route_journal_t *journal,
    uint32_t event, dep_route_state_t *projected) {
  dep_route_iterator_t iterator = dep_route_iterator(state);
  uint32_t root;
  bool first = true;
  while (dep_route_next(&iterator, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    dep_route_set_t origin = dep_fd_raw_fact(
        &one, journal, dep_fd_numeric(event), DEP_FD_ACCESS_PRIVATE_ENTRY);
    dep_route_state_t parent = dep_route_state_single(origin.routes[0].value);
    dep_route_state_inherit(&parent, state);
    if (first) {
      *projected = parent;
      first = false;
    } else if (!dep_fd_merge(projected, &parent, journal))
      return false;
  }
  dep_route_state_inherit(projected, state);
  return true;
}

/* The lists of an `if` are alternatives: the first command of a `then` list
 * starts from the condition's success and that of an `else` list or `elif`
 * condition from its failure. When the walk moves from a condition to its
 * `then` list the failed outcome is parked, so the list's later commands
 * cannot run on it; when it leaves a `then` list the finished outcomes are
 * banked and the parked failure resumes. dep_fd_if_finish joins them. */
static SHELL_NONNULL(1, 2,
                     4) bool dep_fd_if_enter(const dep_parse_context_t *context,
                                             dep_fd_stream_t *stream,
                                             uint32_t event,
                                             dep_route_journal_t *journal) {
  uint8_t role, arm;
  if (!dep_event_section(context, event, &role, &arm))
    return true;
  uint32_t group = (uint32_t)dep_snapshot_event_group(context, event);
  uint8_t *section = stream->if_section[group];
  if (role == section[0] && arm == section[1])
    return true;
  dep_fd_flow_t *flow = &stream->scope[group + 1];
  if (section[0] != SHELL_RANGE_ROLE_NONE) {
    if (role == SHELL_RANGE_ROLE_THEN) {
      DEP_TRACE(SHELLSPLIT_TRACE_IF,
                (flow->mask & DEP_STATUS_MAY_FAIL) ? 0 : 1);
      stream->if_failure[group] = (dep_fd_flow_t){0};
      if (flow->mask & DEP_STATUS_MAY_FAIL) {
        stream->if_failure[group].mask = DEP_STATUS_MAY_FAIL;
        stream->if_failure[group].state[1] = flow->state[1];
        flow->mask &= (uint8_t)~DEP_STATUS_MAY_FAIL;
      }
    } else {
      DEP_TRACE(SHELLSPLIT_TRACE_IF, 2);
      for (unsigned outcome = 0; outcome < 5; outcome++)
        if ((flow->mask & (1u << outcome)) &&
            !dep_fd_add(&stream->if_exit[group], outcome, flow->state[outcome],
                        journal))
          return false;
      *flow = stream->if_failure[group];
      stream->if_failure[group] = (dep_fd_flow_t){0};
    }
  }
  section[0] = role;
  section[1] = arm;
  return true;
}

/* The group's body flow becomes the outcomes of every list that ran. With no
 * `else`, the last condition failing returns success without running a list. */
static SHELL_NONNULL(1, 2, 4) bool dep_fd_if_finish(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t group,
    dep_route_journal_t *journal) {
  if (context->fast->groups[group].kind != SHELL_GROUP_IF ||
      stream->if_section[group][0] == SHELL_RANGE_ROLE_NONE)
    return true;
  dep_fd_flow_t *flow = &stream->scope[group + 1];
  dep_fd_flow_t *exit = &stream->if_exit[group];
  for (unsigned outcome = 0; outcome < 5; outcome++)
    if ((flow->mask & (1u << outcome)) &&
        !dep_fd_add(exit, outcome, flow->state[outcome], journal))
      return false;
  DEP_TRACE(SHELLSPLIT_TRACE_IF,
            stream->if_section[group][0] == SHELL_RANGE_ROLE_THEN &&
                    (stream->if_failure[group].mask & DEP_STATUS_MAY_FAIL)
                ? 3
                : 4);
  if (stream->if_section[group][0] == SHELL_RANGE_ROLE_THEN &&
      (stream->if_failure[group].mask & DEP_STATUS_MAY_FAIL) &&
      !dep_fd_add(exit, 0, stream->if_failure[group].state[1], journal))
    return false;
  *flow = *exit;
  *exit = (dep_fd_flow_t){0};
  stream->if_failure[group] = (dep_fd_flow_t){0};
  stream->if_section[group][0] = stream->if_section[group][1] = 0;
  return true;
}

static SHELL_NONNULL(1, 2, 4, 5) bool dep_fd_begin(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    dep_route_journal_t *journal, dep_route_state_t *selected) {
  uint32_t scope = (uint32_t)(dep_snapshot_event_group(context, event) + 1);
  if (!dep_fd_if_enter(context, stream, event, journal))
    return false;
  dep_fd_flow_t *flow = &stream->scope[scope];
  const shell_pipeline_index_t *pipeline = &context->execution->pipeline;
  if (scope == 0) {
    uint32_t unit = event < SHELL_MAX_GROUPS
                        ? pipeline->group_input_unit[event]
                        : pipeline->range_input_unit[event - SHELL_MAX_GROUPS];
    if (context->input_unit_recovery && unit != stream->input_unit &&
        (flow->mask & DEP_STATUS_ABORT_FAILURE)) {
      if (!dep_fd_add(flow, 1, flow->state[4], journal))
        return false;
      flow->mask &= (uint8_t)~DEP_STATUS_ABORT_FAILURE;
    }
    stream->input_unit = unit;
  }
  /* Recovery belongs to the parent input unit. Save that recovered state
   * before installing stdin in the asynchronous interpreter, so snapshots
   * and final routing see the same executing alternatives. */
  uint32_t async_unit = context->async->unit[event];
  if (async_unit == event + 1) {
    stream->async_entry[event] = *flow;
    if (context->async->wrapper[event]) {
      for (unsigned outcome = 0; outcome < 2; outcome++)
        if (flow->mask & (1u << outcome)) {
          bool executing =
              (dep_fd_run_mask(context, stream, event) & (1u << outcome)) != 0;
          if (executing &&
              (!dep_process_cleanup(&stream->async_entry[event].state[outcome],
                                    journal) ||
               !dep_route_state_store_access(&flow->state[outcome], journal,
                                             dep_fd_numeric(SHELL_DEP_FD_NONE),
                                             DEP_FD_ACCESS_PROCESS_OWNED,
                                             (dep_route_set_t){.ready = true})))
            return false;
          if (!dep_async_stdin(&flow->state[outcome], journal,
                               context->effects_active && executing))
            return false;
        }
    }
  }
  uint16_t connector =
      event < SHELL_MAX_GROUPS
          ? pipeline->group_connector[event]
          : pipeline->range_connector[event - SHELL_MAX_GROUPS];
  if (connector == SHELL_TYPE_PIPELINE) {
    stream->entry[event] = stream->entry[stream->pipeline_event[scope] - 1];
  } else {
    stream->entry[event] = *flow;
    bool outgoing = dep_fd_outgoing_pipeline(context, event);
    stream->pipeline_event[scope] = outgoing ? event + 1 : 0;
  }
  if (!dep_fd_select(&stream->entry[event],
                     dep_fd_run_mask(context, stream, event), journal,
                     selected))
    return false;
  if (dep_fd_private(context, event) &&
      !dep_fd_private_begin(selected, journal, event))
    return false;
  if (event < SHELL_MAX_GROUPS && dep_fd_private(context, event)) {
    /* A following pipeline stage forks from the parent *after* compound-fork
     * process-end cleanup, not from the first stage's untouched entry table.
     * The current child's selected version was captured before that cleanup.
     */
    uint32_t first = stream->pipeline_event[scope]
                         ? stream->pipeline_event[scope] - 1
                         : event;
    uint8_t run = dep_fd_run_mask(context, stream, event);
    for (unsigned outcome = 0; outcome < 5; outcome++)
      if ((stream->entry[first].mask & run & (1u << outcome)) &&
          !dep_process_cleanup(&stream->entry[first].state[outcome], journal))
        return false;
    stream->entry[event] = stream->entry[first];
    if (async_unit == event + 1 && !context->async->wrapper[event])
      for (unsigned outcome = 0; outcome < 5; outcome++)
        if ((stream->async_entry[event].mask & run & (1u << outcome)) &&
            !dep_process_cleanup(&stream->async_entry[event].state[outcome],
                                 journal))
          return false;
  }
  stream->selected[event] = *selected;
  return true;
}

static SHELL_NONNULL(1, 2, 4, 5) bool dep_fd_finish(
    const dep_parse_context_t *context, dep_fd_stream_t *stream, uint32_t event,
    const dep_fd_flow_t *executed, dep_route_journal_t *journal) {
  const dep_fd_flow_t *entry = &stream->entry[event];
  uint8_t run = dep_fd_run_mask(context, stream, event);
  dep_fd_flow_t result = *entry;
  result.mask &= (uint8_t)~run;
  if (entry->mask & run)
    for (unsigned i = 0; i < 5; i++)
      if (executed->mask & (1u << i)) {
        dep_route_state_t returned = executed->state[i];
        if (!dep_fd_retire_owner_facts(context, event, &returned, journal) ||
            (dep_fd_private(context, event) &&
             !dep_fd_private_project(&returned, journal, event, &returned)) ||
            !dep_fd_add(&result, i, returned, journal))
          return false;
      }
  if (executed->mask & DEP_STATUS_EXIT_INCOMING)
    for (unsigned i = 0; i < 2; i++)
      if (entry->mask & run & (1u << i)) {
        unsigned target = i + 2;
        if (dep_fd_private(context, event))
          target = i ^ (context->fast->cmds[event - SHELL_MAX_GROUPS]
                            .pipeline_negation_count &
                        1u);
        if (!dep_fd_add(&result, target, entry->state[i], journal))
          return false;
      }
  stream->scope[dep_snapshot_event_group(context, event) + 1] = result;
  uint32_t unit = context->async->unit[event];
  if (unit && context->async->last[unit - 1] == event) {
    /* The asynchronous interpreter's mutations never escape to its parent.
     * Launching the list returns success; stopped incoming paths do not
     * create a child. */
    result = stream->async_entry[unit - 1];
    if (result.mask & DEP_STATUS_EITHER) {
      dep_route_state_t launched;
      if (!dep_fd_select(&result, DEP_STATUS_EITHER, journal, &launched))
        return false;
      result.mask &= (uint8_t)~DEP_STATUS_EITHER;
      if (!dep_fd_add(&result, 0, launched, journal))
        return false;
    }
    stream->scope[dep_snapshot_event_group(context, event) + 1] = result;
    stream->async_entry[unit - 1] = (dep_fd_flow_t){0};
  }
  /* Per-event entries are live only while that event is being completed. A
   * pipeline additionally retains its first entry until the final stage, since
   * every stage starts from the same pre-pipeline shell state. Clearing dead
   * slots here lets bounded domain collection reclaim terminal alternatives
   * instead of retaining the whole historical event stream. */
  uint32_t scope = (uint32_t)(dep_snapshot_event_group(context, event) + 1);
  uint32_t first =
      stream->pipeline_event[scope] ? stream->pipeline_event[scope] - 1 : event;
  bool outgoing = dep_fd_outgoing_pipeline(context, event);
  if (event != first)
    stream->entry[event] = (dep_fd_flow_t){0};
  if (!outgoing) {
    stream->entry[first] = (dep_fd_flow_t){0};
    stream->pipeline_event[scope] = 0;
  }
  stream->selected[event] = (dep_route_state_t){0};
  return true;
}

/* Explicit targets have a prepared observation key even before the first
 * allocation of that name: every descriptor variable is in that inventory, so
 * an effect without a key or a predefined variable binds none. Bulk writes
 * reset the scalar map instead of enumerating this source-wide inventory.
 * index is below mutations->count. */
static SHELL_NONNULL(1, 2) dep_fd_ref_t
    dep_mutation_binding_target(const dep_named_mutations_t *mutations,
                                const dep_route_journal_t *journal,
                                uint32_t index) {
  const dep_named_effect_t *effect = &mutations->effects[index];
  if (effect->kind == DEP_NAMED_EFFECT_OPAQUE_WRITE ||
      effect->kind == DEP_NAMED_EFFECT_OPAQUE_UNSET)
    return dep_fd_numeric(SHELL_DEP_FD_NONE);
  if (effect->variable)
    return dep_variable_ref(effect->variable);
  if (effect->observation)
    return journal->read_observations.entries[effect->observation - 1].fd;
  return dep_fd_numeric(SHELL_DEP_FD_NONE);
}

/* Effect state belongs to each immutable execution version. Representative
 * before/after tables enumerate changed names but cannot prove whether one
 * version still has a live named binding. Preserve an existing orphan's
 * original scope: Bash does not close its physical descriptor on a redundant
 * unset. A successful named allocation clears that marker in the setup path.
 * variable is the resettable predefined registry identity, or zero for an
 * ordinary unset. Its capability mask is separate from named orphan facts so
 * descendants inherit attributes without importing journal-local scopes. */
static SHELL_NONNULL(1, 2) bool dep_fd_note_unset_effects(
    dep_route_state_t *state, dep_route_journal_t *journal, dep_fd_ref_t fd,
    uint8_t variable, uint8_t scope, bool conditional) {
  dep_route_state_t previous = *state;
  dep_route_state_t updated = {0};
  dep_route_iterator_t versions = dep_route_iterator(&previous);
  uint32_t count = dep_route_state_count(&previous);
  for (uint32_t path = 0; path < count; path++) {
    dep_route_state_t one =
        dep_route_state_single(dep_route_take(&versions, journal));
    dep_route_set_t marker =
        dep_fd_raw_fact(&one, journal, fd, DEP_FD_ACCESS_EFFECT_STATE);
    dep_route_set_t binding =
        dep_fd_raw_fact(&one, journal, fd, DEP_FD_ACCESS_BINDING);
    bool was_despecialized = false;
    if (variable) {
      dep_route_set_t capabilities = dep_variable_state(&one, journal);
      uint32_t word = (variable - 1u) / 32u;
      uint32_t bit = UINT32_C(1) << ((variable - 1u) % 32u);
      was_despecialized = (capabilities.routes[word].value & bit) != 0;
      if (!was_despecialized) {
        if (!conditional)
          capabilities.routes[word].value |= bit;
        capabilities.routes[word + 2].value |= bit;
        if (!dep_route_state_append_one(
                &one, journal, dep_fd_numeric(DEP_VARIABLE_STATE_EVENT),
                DEP_FD_ACCESS_EFFECT_STATE, capabilities)) {
          state->truncated = true;
          return false;
        }
      }
    }
    bool live = false;
    for (uint32_t route = 0; route < binding.count; route++)
      live |= binding.routes[route].kind == DEP_ROUTE_INHERITED ||
              binding.routes[route].kind == DEP_ROUTE_ALIAS;
    /* A resettable predefined variable has an inherited scalar/array binding,
     * not an inherited named descriptor. Its first unset establishes the
     * distinction; only a later binding can own an allocation. */
    if (variable && !was_despecialized)
      live = false;

    uint32_t additions = 0;
    if (live)
      additions |= DEP_EFFECT_STATE_ORPHANED_ALLOCATION |
                   ((uint32_t)scope << DEP_EFFECT_STATE_SCOPE_SHIFT);
    bool changed = false;
    if (additions) {
      if (!marker.count) {
        dep_route_set_set(&marker,
                          (dep_fd_route_t){DEP_ROUTE_INHERITED, additions});
        changed = true;
      } else {
        for (uint32_t route = 0; route < marker.count; route++) {
          uint32_t prior = marker.routes[route].value;
          if ((additions & DEP_EFFECT_STATE_ORPHANED_ALLOCATION) &&
              !(marker.routes[route].value &
                DEP_EFFECT_STATE_ORPHANED_ALLOCATION))
            marker.routes[route].value |= additions;
          changed |= marker.routes[route].value != prior;
        }
      }
    }
    if (changed) {
      if (!dep_route_state_append_one(&one, journal, fd,
                                      DEP_FD_ACCESS_EFFECT_STATE, marker)) {
        state->truncated = true;
        return false;
      }
    }
    if (path == 0)
      updated.root = one.root;
    else if (!dep_route_state_add_root(&updated, journal, one.root)) {
      state->truncated = true;
      return false;
    }
  }
  updated.truncated = previous.truncated;
  *state = updated;
  return true;
}

/* An opaque event forgets values at this exact commit boundary. It may also
 * remove resettable attributes, but never those of an installed temporary
 * prefix. Later explicit effects still run and can reestablish precise facts.
 */
static SHELL_NONNULL(1, 2, 3, 4) bool dep_fd_opaque_mutation(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_named_mutations_t *mutations, const dep_named_effect_t *effect,
    uint32_t entry) {
  if (!dep_presence_clear(state, journal, mutations->restored_prefixes,
                          effect->token.start, entry))
    return false;
  dep_route_state_t before = *state;
  dep_route_state_t installed = dep_route_state_single(entry);
  dep_route_set_t holder = {0};
  dep_route_set_set(&holder, (dep_fd_route_t){DEP_ROUTE_DYNAMIC, 0});
  if (!dep_route_state_append_one(state, journal, dep_fd_numeric(0),
                                  DEP_FD_ACCESS_NAMED_BINDINGS, holder))
    return false;
  const dep_prefix_assignment_set_t *prefixes = mutations->restored_prefixes;
  for (uint32_t p = 0; prefixes && p < prefixes->count; ++p) {
    dep_token_t name = {prefixes->names[p].start, prefixes->names[p].len};
    if (dep_prefix_assignment_visible(prefixes, &name, &installed, journal) !=
        SHELL_TEST_TRUE)
      continue;
    dep_fd_ref_t fd = {
        .name = name.start, .name_len = name.len, .value = SHELL_DEP_FD_NAMED};
    if (!dep_route_state_append_one(
            state, journal, fd, DEP_FD_ACCESS_BINDING,
            dep_fd_raw_fact(&before, journal, fd, DEP_FD_ACCESS_BINDING)))
      return false;
  }
  if (effect->kind == DEP_NAMED_EFFECT_OPAQUE_UNSET) {
    dep_route_set_t marker = dep_variable_state(state, journal);
    for (uint8_t variable = 1; variable <= SHELL_BUILTIN_VARIABLE_NAMES;
         ++variable) {
      if (!(shell_builtin_variable_index_properties(variable) &
            SHELL_VARIABLE_DESPECIALIZES_ON_UNSET))
        continue;
      dep_token_t name = {
          shell_builtin_variable_index_name(variable),
          (uint32_t)shell_builtin_variable_index_length(variable)};
      if (prefixes && dep_prefix_assignment_visible(prefixes, &name, &installed,
                                                    journal) == SHELL_TEST_TRUE)
        continue;
      marker.routes[2 + (variable - 1u) / 32u].value |=
          UINT32_C(1) << ((variable - 1u) % 32u);
    }
    if (!dep_route_state_append_one(state, journal,
                                    dep_fd_numeric(DEP_VARIABLE_STATE_EVENT),
                                    DEP_FD_ACCESS_EFFECT_STATE, marker))
      return false;
  }
  return true;
}

/* Apply one complete explicit mutation bundle to a single execution version.
 * Dependent writes read this version's immutable entry, while ordered effects
 * update its current state. Merge only completed bundles: intermediate writes
 * can erase distinctions needed by a later effect (PWD before OLDPWD). */
static SHELL_NONNULL(1, 2, 3, 4) bool dep_fd_mutation_version(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_named_mutations_t *mutations, const dep_fd_ref_t *targets,
    uint32_t entry, uint32_t first) {
  dep_route_state_t installed = dep_route_state_single(entry);
  for (uint32_t i = first; i < mutations->count; i++) {
    dep_fd_ref_t fd = targets[i];
    const dep_named_effect_t *effect = &mutations->effects[i];
    if (effect->kind == DEP_NAMED_EFFECT_OPAQUE_WRITE ||
        effect->kind == DEP_NAMED_EFFECT_OPAQUE_UNSET) {
      if (!dep_fd_opaque_mutation(state, journal, mutations, effect, entry))
        return false;
      continue;
    }
    if (mutations->restored_prefixes && fd.value == SHELL_DEP_FD_NAMED &&
        dep_prefix_assignment_visible(mutations->restored_prefixes,
                                      &(dep_token_t){fd.name, fd.name_len},
                                      &installed, journal) == SHELL_TEST_TRUE)
      continue;
    if (!dep_variable_resolve(state, journal, effect->variable))
      return false;
    if (dep_route_state_count(state) > 1) {
      dep_route_state_t result = {0};
      dep_route_iterator_t alternatives = dep_route_iterator(state);
      uint32_t root;
      bool ready = false;
      while (dep_route_next(&alternatives, journal, &root)) {
        dep_route_state_t one = dep_route_state_single(root);
        if (!dep_fd_mutation_version(&one, journal, mutations, targets, entry,
                                     i))
          return false;
        if (!ready)
          result = one;
        else {
          dep_route_iterator_t completed = dep_route_iterator(&one);
          while (dep_route_next(&completed, journal, &root))
            if (!dep_route_state_add_root(&result, journal, root))
              return false;
        }
        ready = true;
      }
      dep_route_state_inherit(&result, state);
      *state = result;
      return true;
    }
    bool unset = effect->kind == DEP_NAMED_EFFECT_UNSET;
    /* Candidate effects include resettable special names. A rejected write
     * changes neither presence nor binding/writer identity in this version.
     * Unset has its own admission rules and can remove the restriction. */
    if (!unset && effect->variable &&
        (dep_variable_properties(effect->variable, state, journal) &
         SHELL_VARIABLE_NOASSIGN))
      continue;
    if (fd.value == SHELL_DEP_FD_NAMED &&
        (dep_read_observation(&journal->read_observations, fd) &
         DEP_READ_OBSERVE_PRESENCE)) {
      unsigned presence = effect->presence ? effect->presence
                          : unset          ? SHELL_TEST_FALSE
                                           : SHELL_TEST_TRUE;
      if (effect->presence_from_pwd) {
        dep_fd_ref_t pwd = {
            .name = "PWD", .name_len = 3, .value = SHELL_DEP_FD_NAMED};
        dep_token_t word = {"PWD", 3};
        presence = mutations->presence_prefixes &&
                           dep_prefix_assignment_contains(
                               mutations->presence_prefixes, &word)
                       ? SHELL_TEST_TRUE
                       : dep_presence_root(entry, journal, pwd);
      }
      if (effect->presence_may_skip)
        presence |= dep_presence_root(state->root, journal, fd);
      if (!dep_presence_store(state, journal, fd, presence,
                              mutations->operation))
        return false;
    }
    bool despecializes =
        unset && effect->variable &&
        (shell_builtin_variable_index_properties(effect->variable) &
         SHELL_VARIABLE_DESPECIALIZES_ON_UNSET);
    if (fd.value != SHELL_DEP_FD_NAMED)
      continue;
    if (unset && !dep_fd_note_unset_effects(
                     state, journal, fd, despecializes ? effect->variable : 0,
                     mutations->scope, effect->presence_may_skip))
      return false;
    dep_route_set_t bound = {0};
    dep_route_set_set(&bound,
                      (dep_fd_route_t){unset && !effect->presence_may_skip
                                           ? DEP_ROUTE_UNAVAILABLE
                                           : DEP_ROUTE_DYNAMIC,
                                       UINT32_MAX});
    if (despecializes) {
      /* The predefined name entered the descriptor inventory before it was
       * removed. Invalidate every access through that spelling; otherwise a
       * failed later allocation would fall back to the inventory's inherited
       * named endpoint. Any orphaned physical descriptor remains tracked by
       * the separate marker below. */
      for (uint32_t access = DEP_FD_ACCESS_READ;
           access <= DEP_FD_ACCESS_BINDING; access <<= 1)
        if (!dep_route_state_store_access(state, journal, fd,
                                          (dep_fd_access_t)access, bound))
          return false;
    } else if (!dep_route_state_store_access(state, journal, fd,
                                             DEP_FD_ACCESS_BINDING, bound)) {
      return false;
    }
    if (!dep_read_note_assignment(state, journal, fd))
      return false;
  }
  return true;
}

/* Update prepared mutation targets, including observed variables which have
 * never named an allocation. A stable explicit unset establishes emptiness;
 * ordinary writes invalidate that value just like an allocation association. */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_mutation_bindings(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_named_mutations_t *mutations) {
  if (!mutations->count)
    return true;
  dep_fd_ref_t targets[SHELL_DEP_MAX_TOKENS];
  for (uint32_t i = 0; i < mutations->count; ++i)
    targets[i] = dep_mutation_binding_target(mutations, journal, i);
  dep_route_state_t entries = *state;
  if (mutations->restored_prefixes &&
      !dep_prefixes_resolve(&entries, mutations->restored_prefixes, journal))
    return false;
  dep_route_state_t result = {0};
  dep_route_iterator_t versions = dep_route_iterator(&entries);
  uint32_t root;
  bool ready = false;
  while (dep_route_next(&versions, journal, &root)) {
    dep_route_state_t one = dep_route_state_single(root);
    if (!dep_fd_mutation_version(&one, journal, mutations, targets, root, 0))
      return false;
    if (!ready)
      result = one;
    else {
      dep_route_iterator_t completed = dep_route_iterator(&one);
      uint32_t completed_root;
      while (dep_route_next(&completed, journal, &completed_root))
        if (!dep_route_state_add_root(&result, journal, completed_root))
          return false;
    }
    ready = true;
    dep_route_state_inherit(&result, &one);
  }
  result.truncated |= state->truncated;
  *state = result;
  return true;
}

/* Empty/unknown scalar values and allocation identities are facts of each
 * execution version. A named operation's variable is bound to a live
 * descriptor; this command's own later writes to the name, and a setup failure
 * before the operation, replace that binding on their paths. */
static SHELL_NONNULL(1, 2, 5) bool dep_fd_bindings(
    dep_route_state_t *state, dep_route_journal_t *journal,
    const dep_fd_op_t *ops, uint32_t op_count,
    const dep_named_mutations_t *mutations) {
  /* Allocations come only from this owner's prepared operations. Ordinary
   * numeric commands must not search every inherited descriptor variable. */
  for (uint32_t i = 0; i < op_count; i++) {
    if (ops[i].fd != SHELL_DEP_FD_NAMED)
      continue;
    dep_fd_ref_t fd = {.name = ops[i].fd_name,
                       .value = ops[i].fd,
                       .name_len = ops[i].fd_name_len};
    if (ops[i].resets_descriptor && ops[i].kind != DEP_FD_OP_CLOSE &&
        !dep_read_note_assignment(state, journal, fd))
      return false;
    /* An allocation identity already names the descriptor's place. */
    if (dep_fd_raw_fact(state, journal, fd, DEP_FD_ACCESS_BINDING)
            .routes[0]
            .kind == DEP_ROUTE_ALIAS)
      continue;
    dep_route_set_t bound = {0};
    dep_route_set_set(&bound,
                      (dep_fd_route_t){DEP_ROUTE_INHERITED, UINT32_MAX});
    if (!dep_route_state_store_access(state, journal, fd, DEP_FD_ACCESS_BINDING,
                                      bound))
      return false;
  }
  return dep_fd_mutation_bindings(state, journal, mutations) &&
         (mutations->before_redirect ||
          dep_ifs_apply(state, journal, mutations));
}

/* Only a not-yet-established allocation may become known absent when skipped.
 * An explicitly invalidated variable is UNKNOWN and must stay that way. */
static SHELL_NONNULL(1, 2) bool dep_fd_mark_absent(dep_route_state_t *state,
                                                   dep_route_journal_t *journal,
                                                   dep_fd_ref_t fd) {
  dep_route_set_t fact = dep_fd_fact(state, journal, fd, DEP_FD_ACCESS_BINDING);
  if (fact.routes[0].kind != DEP_ROUTE_UNSEEN)
    return true;
  dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_ABSENT, UINT32_MAX});
  for (uint32_t access = DEP_FD_ACCESS_READ; access <= DEP_FD_ACCESS_WRITE;
       access <<= 1)
    if (!dep_route_state_store_access(state, journal, fd,
                                      (dep_fd_access_t)access, fact))
      return false;
  dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_UNAVAILABLE, UINT32_MAX});
  return dep_route_state_store_access(state, journal, fd, DEP_FD_ACCESS_BINDING,
                                      fact);
}

/* Successful descriptor setup proves existence independently of access mode.
 * A self-dup is a no-op, even when closed. Inherited numeric descriptors may
 * be closed by the caller; document/pipe capabilities prove an installed FD.
 * A copy's source missing only where a failed open left it fails only on
 * paths the requirements exclude (dep_required_feasible): construction marks
 * those opens required (dep_fd_copy_source_exists), so that failure has no
 * outcome, as for a read. */
static SHELL_NONNULL(1, 2, 3) uint8_t
    dep_fd_operation_outcomes(const dep_fd_op_t *op,
                              const dep_route_state_t *state,
                              const dep_route_journal_t *journal) {
  dep_fd_op_t effective = dep_fd_effective_operation(op, state, journal);
  op = &effective;
  if (op->kind == DEP_FD_OP_FAILED)
    return DEP_STATUS_MAY_FAIL;
  if (op->kind == DEP_FD_OP_IDENTITY || op->kind == DEP_FD_OP_PROCESS)
    return DEP_STATUS_MAY_SUCCEED;
  if (op->kind == DEP_FD_OP_DOCUMENT && op->document_flags &&
      (*op->document_flags & SHELL_DEP_DOC_FLAG_EXPANSION_FAILED))
    return DEP_STATUS_MAY_FAIL;
  if (op->kind == DEP_FD_OP_CLOSE) {
    if (op->fd != SHELL_DEP_FD_NAMED)
      return DEP_STATUS_MAY_SUCCEED;
    dep_fd_ref_t target = {
        .name = op->fd_name, .value = op->fd, .name_len = op->fd_name_len};
    dep_route_set_t facts =
        dep_fd_raw_fact(state, journal, target, DEP_FD_ACCESS_BINDING);
    uint8_t outcomes = 0;
    for (uint32_t i = 0; i < facts.count; i++) {
      if (facts.routes[i].kind == DEP_ROUTE_UNAVAILABLE ||
          facts.routes[i].kind == DEP_ROUTE_ABSENT)
        outcomes |= DEP_STATUS_MAY_FAIL;
      else if (facts.routes[i].kind == DEP_ROUTE_UNSEEN ||
               facts.routes[i].kind == DEP_ROUTE_DYNAMIC)
        outcomes |= DEP_STATUS_EITHER;
      else
        outcomes |= DEP_STATUS_MAY_SUCCEED;
    }
    return outcomes;
  }
  if (!dep_fd_op_copies(op->kind))
    return DEP_STATUS_EITHER;
  dep_fd_ref_t target = {
      .name = op->fd_name, .value = op->fd, .name_len = op->fd_name_len};
  dep_fd_ref_t source = {.name = op->target_fd_name,
                         .value = op->target_fd,
                         .name_len = op->target_fd_name_len};
  if (target.value != SHELL_DEP_FD_NAMED && dep_fd_ref_equal(target, source))
    return DEP_STATUS_MAY_SUCCEED;
  dep_route_set_t binding =
      dep_fd_fact(state, journal, source, DEP_FD_ACCESS_BINDING);
  dep_route_set_t facts = dep_required_feasible(&binding);
  uint8_t outcomes = 0;
  for (uint32_t i = 0; i < facts.count; i++) {
    if (facts.routes[i].kind == DEP_ROUTE_UNAVAILABLE ||
        facts.routes[i].kind == DEP_ROUTE_ABSENT ||
        facts.routes[i].kind == DEP_ROUTE_CLOSED)
      outcomes |= DEP_STATUS_MAY_FAIL;
    else if (facts.routes[i].kind == DEP_ROUTE_UNSEEN ||
             facts.routes[i].kind == DEP_ROUTE_DYNAMIC)
      outcomes |= DEP_STATUS_EITHER;
    else
      outcomes |= DEP_STATUS_MAY_SUCCEED;
  }
  return outcomes;
}

/* The outcomes of one redirection: the operations at one source position
 * (count of them, at least one), such as a process substitution and the
 * installation of its path, or the two halves of `<>`. It may fail when any
 * of them may, and succeed only when all of them may. A process
 * substitution's own path (its DYNAMIC installation) always opens; a word
 * that only begins with one, such as `>(cmd)suffix`, names a document whose
 * open may fail. */
static SHELL_NONNULL(1, 3, 4) uint8_t
    dep_fd_level_outcomes(const dep_fd_op_t *ops, uint32_t count,
                          const dep_route_state_t *state,
                          const dep_route_journal_t *journal) {
  bool process = false;
  for (uint32_t op = 0; op < count; op++)
    process |= ops[op].kind == DEP_FD_OP_PROCESS;
  uint8_t outcomes = DEP_STATUS_MAY_SUCCEED;
  for (uint32_t op = 0; op < count; op++) {
    uint8_t one = process && ops[op].kind == DEP_FD_OP_DYNAMIC
                      ? DEP_STATUS_MAY_SUCCEED
                      : dep_fd_operation_outcomes(ops + op, state, journal);
    outcomes = (uint8_t)((outcomes & (one | DEP_STATUS_MAY_FAIL)) |
                         (one & DEP_STATUS_MAY_FAIL));
  }
  return outcomes;
}

/* A descriptor's binding facts say it exists on every path, except where a
 * failed open (a CLOSED route recording its cause) left it missing. Those
 * opens become requirements of a safe run, marked in requirements, which may
 * be NULL when only the verdict is needed. Any other closed, unavailable or
 * absent route means the descriptor may be missing: no dependency graph
 * models the use. */
static SHELL_NONNULL(1) bool dep_fd_binding_exists(
    const dep_route_set_t *binding, dep_route_journal_t *requirements) {
  for (uint32_t i = 0; i < binding->count; i++) {
    dep_fd_route_t route = binding->routes[i];
    bool missing = route.kind == DEP_ROUTE_CLOSED ||
                   route.kind == DEP_ROUTE_UNAVAILABLE ||
                   route.kind == DEP_ROUTE_ABSENT;
    if (missing && route.value != UINT32_MAX) {
      if (requirements)
        requirements->open_cause_required[route.value] = true;
    } else if (route.kind == DEP_ROUTE_CLOSED ||
               route.kind == DEP_ROUTE_UNAVAILABLE ||
               route.kind == DEP_ROUTE_ABSENT)
      return false;
  }
  return !binding->truncated;
}

/* Whether a reached operation which cannot succeed fails only where a
 * recorded failed open already requires success (dep_failure_mark_opens):
 * every missing route of the source it reads carries a failed-open cause,
 * which the final walk marks required. Copies and moves read their source;
 * a named close reads the closed name. Any other operation fails by itself
 * (an empty pathname, a poisoned expansion), which no requirement excuses.
 * A binding with no routes, a truncated one, or any uncaused or live route
 * is not excused. An excused operation marks its causes required in
 * `requirements`, so the graph carries every open its success needs. */
static SHELL_NONNULL(1, 2, 3, 4) bool dep_fd_missing_excused(
    const dep_fd_op_t *op, const dep_route_state_t *state,
    const dep_route_journal_t *journal, dep_route_journal_t *requirements) {
  dep_fd_ref_t source;
  bool raw;
  if (dep_fd_op_copies(op->kind)) {
    source = (dep_fd_ref_t){.name = op->target_fd_name,
                            .value = op->target_fd,
                            .name_len = op->target_fd_name_len};
    raw = false;
  } else if (op->kind == DEP_FD_OP_CLOSE && op->fd == SHELL_DEP_FD_NAMED) {
    source = (dep_fd_ref_t){
        .name = op->fd_name, .value = op->fd, .name_len = op->fd_name_len};
    raw = true;
  } else {
    return false;
  }
  dep_route_set_t binding =
      raw ? dep_fd_raw_fact(state, journal, source, DEP_FD_ACCESS_BINDING)
          : dep_fd_fact(state, journal, source, DEP_FD_ACCESS_BINDING);
  if (!binding.count || binding.truncated)
    return false;
  for (uint32_t i = 0; i < binding.count; i++) {
    dep_fd_route_t route = binding.routes[i];
    if (route.kind != DEP_ROUTE_CLOSED && route.kind != DEP_ROUTE_UNAVAILABLE &&
        route.kind != DEP_ROUTE_ABSENT)
      return false;
    if (route.value == UINT32_MAX)
      return false;
  }
  for (uint32_t i = 0; i < binding.count; i++)
    requirements->open_cause_required[binding.routes[i].value] = true;
  return true;
}

/* The prepared copy or move's source exists on every path of state, up to
 * required opens (dep_fd_binding_exists). A numeric self-copy reads nothing. */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_copy_source_exists(
    const dep_fd_op_t *op, const dep_route_state_t *state,
    const dep_route_journal_t *journal, dep_route_journal_t *requirements) {
  if (op->target_fd != SHELL_DEP_FD_NAMED && op->target_fd == op->fd)
    return true;
  dep_route_set_t binding =
      dep_fd_fact(state, journal,
                  (dep_fd_ref_t){.name = op->target_fd_name,
                                 .value = op->target_fd,
                                 .name_len = op->target_fd_name_len},
                  DEP_FD_ACCESS_BINDING);
  return dep_fd_binding_exists(&binding, requirements);
}

/* Whether fd may hold a Bash save in state that it held in none of the
 * versions of earlier, the state some frame started from. */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_save_added(
    const dep_route_state_t *state, const dep_route_state_t *earlier,
    const dep_route_journal_t *journal, dep_fd_ref_t fd) {
  dep_route_set_t current =
      dep_fd_raw_fact(state, journal, fd, DEP_FD_ACCESS_SCRATCH);
  dep_route_set_t before =
      dep_fd_raw_fact(earlier, journal, fd, DEP_FD_ACCESS_SCRATCH);
  for (uint32_t i = 0; i < current.count; i++) {
    bool held = false;
    for (uint32_t j = 0; !held && j < before.count; j++)
      held = current.routes[i].kind == before.routes[j].kind &&
             current.routes[i].value == before.routes[j].value;
    if (!held)
      return true;
  }
  return false;
}

/* The descriptor contract (SHELL_DEP_EUNMODELED) of a descriptor-only
 * `exec`, which discards its undo list but still runs Bash's exec undo list:
 * a close of each save it made, and a restore of each target that was
 * itself a save. op is reached in state; entry is its owner's state before
 * its first redirection and shell the state its shell started from (a child
 * shell's saves of its parent are copies the parent never restores from).
 * - A close of a save made by an enclosing frame of this shell destroys it:
 *   no restore entry is recorded for a close, so that frame's restore fails.
 * - Any other redirection onto a save this list made is undone too late: the
 *   save's close runs after the target's restore and closes the target.
 * A close of this list's own save, and a redirection onto an enclosing save
 * (restored afterwards), keep the contract. */
static SHELL_NONNULL(1, 2, 3, 4, 5) bool dep_fd_exec_contract_holds(
    const dep_fd_op_t *op, const dep_route_state_t *state,
    const dep_route_state_t *entry, const dep_route_state_t *shell,
    const dep_route_journal_t *journal) {
  if (op->fd == SHELL_DEP_FD_NAMED || op->fd < DEP_BASH_VARREDIR_MIN_FD ||
      op->fd > SHELL_DEP_FD_MAX || op->paired_open ||
      op->kind == DEP_FD_OP_IDENTITY || dep_fd_op_numeric_self_dup(op))
    return true;
  dep_fd_ref_t fd = dep_fd_numeric(op->fd);
  return op->kind == DEP_FD_OP_CLOSE
             ? !dep_fd_save_added(entry, shell, journal, fd)
             : !dep_fd_save_added(state, entry, journal, fd);
}

/* Join one changed capability/proof slot. Callers already know which prepared
 * operations differ, so a prefix join need not walk the whole descriptor map.
 */
static SHELL_NONNULL(1, 2, 3) bool dep_fd_join_slot(
    dep_route_state_t *destination, const dep_route_state_t *source,
    dep_route_journal_t *journal, dep_fd_ref_t fd, dep_fd_access_t access) {
  dep_route_set_t routes = dep_fd_raw_fact(destination, journal, fd, access);
  dep_route_set_t other = dep_fd_raw_fact(source, journal, fd, access);
  for (uint32_t i = 0; i < other.count; i++)
    if (!dep_route_set_add(&routes, other.routes[i]))
      return false;
  return dep_route_state_store_access(destination, journal, fd, access, routes);
}

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
static _Thread_local bool dep_failure_reference;

void shellsplit_test_failure_cleanup_reference(bool enabled) {
  dep_failure_reference = enabled;
}
#endif

/* The undo keys one prepared operation registers, in the order Bash runs
 * them on cleanup: a move's source restore, the target restore, then a named
 * allocation's retirement. Returns how many of keys[3] are set. */
static SHELL_NONNULL(1, 2, 3) uint32_t
    dep_fd_cleanup_keys(dep_route_journal_t *journal, const dep_fd_op_t *op,
                        uint32_t *keys) {
  uint32_t count = 0;
  if (op->paired_open)
    return 0;
  if (op->kind == DEP_FD_OP_MOVE && !dep_fd_op_numeric_self_dup(op)) {
    dep_fd_op_t close = dep_fd_move_close(op);
    keys[count++] =
        dep_undo_slot(journal, &close, DEP_ALLOCATION_MOVE_UNDO, false);
  }
  keys[count++] = dep_undo_slot(journal, op, DEP_ALLOCATION_TARGET_UNDO, false);
  if (op->fd == SHELL_DEP_FD_NAMED && op->resets_descriptor)
    keys[count++] = dep_allocation_slot(journal, op);
  return count;
}

/* Whether state holds a registration of the undo key, and its access. */
static SHELL_NONNULL(1, 2) bool dep_fd_cleanup_registered(
    const dep_route_state_t *state, const dep_route_journal_t *journal,
    uint32_t key, dep_fd_access_t *access) {
  if (key == SHELL_DEP_FD_NONE)
    return false;
  *access = journal->arena->allocations[key - SHELL_DEP_FD_MAX - 1].role ==
                    DEP_ALLOCATION_BINDING
                ? DEP_FD_ACCESS_ALLOCATION_SLOTS
                : DEP_FD_ACCESS_UNDO_TARGET;
  return dep_fd_raw_fact(state, journal, dep_fd_numeric(key), *access).count !=
         0;
}

/* Run the undos ops[begin..end) registered in state, newest first, from
 * list. Returns the list state after them, or DEP_UNDO_EXHAUSTED. */
static SHELL_NONNULL(1, 2, 3) dep_undo_result_t
    dep_fd_cleanup_range(dep_route_state_t *state, dep_route_journal_t *journal,
                         const dep_fd_op_t *ops, uint32_t begin, uint32_t end,
                         dep_undo_result_t list) {
  for (uint32_t op = end; op-- > begin;) {
    uint32_t keys[3];
    uint32_t count = dep_fd_cleanup_keys(journal, ops + op, keys);
    for (uint32_t i = 0; i < count; i++) {
      dep_fd_access_t access;
      if (!dep_fd_cleanup_registered(state, journal, keys[i], &access))
        continue;
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FAILURE_UNDO);
      list = dep_fd_unwind_key(state, journal, keys[i], false, list);
      if (list == DEP_UNDO_EXHAUSTED)
        return list;
    }
  }
  return list;
}

typedef struct {
  dep_route_state_t *joined;
  dep_route_journal_t *journal;
  uint32_t left, source;
} dep_failure_join_walk_t;

static bool dep_failure_join_key(void *context, dep_fd_ref_t fd,
                                 dep_fd_access_t access, uint32_t from,
                                 uint32_t to) {
  (void)from, (void)to;
  DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FAILURE_DEPENDENCIES);
  dep_failure_join_walk_t *walk = context;
  return dep_fd_force_key(walk->joined, walk->journal, walk->left, walk->source,
                          fd, access);
}

/* Join source's facts into joined at every key the batch from version from
 * to version to changed. left is joined's root before this join. Only the
 * differing keys are visited. */
static SHELL_NONNULL(1, 2) bool dep_failure_join_batch(
    dep_route_state_t *joined, dep_route_journal_t *journal, uint32_t left,
    uint32_t source, uint32_t from, uint32_t to) {
  dep_failure_join_walk_t walk = {joined, journal, left, source};
  return dep_route_map_diff(journal, from, to, dep_failure_join_key, &walk);
}

static bool dep_failure_bit(const uint64_t *words, uint32_t index) {
  return (words[index / 64] >> (index % 64)) & 1u;
}

static void dep_failure_set(uint64_t *words, uint32_t index) {
  words[index / 64] |= UINT64_C(1) << (index % 64);
}

/* The state a setup failure leaves, from the joined unwind state of one
 * undo-list class. A stopped or possibly stopped list leaves stderr as it
 * was when the restore failed. */
static SHELL_NONNULL(1, 2) bool dep_failure_finish(dep_route_state_t *failed,
                                                   dep_route_journal_t *journal,
                                                   dep_undo_result_t list) {
  if (list != DEP_UNDO_DONE && !dep_record_diagnostic(failed, journal))
    return false;
  return dep_route_state_store_access(
             failed, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
             DEP_FD_ACCESS_ENTRY, (dep_route_set_t){.ready = true}) &&
         (!dep_fd_raw_fact(failed, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
                           DEP_FD_ACCESS_SETUP_MODE)
               .count ||
          dep_route_state_store_access(
              failed, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
              DEP_FD_ACCESS_SETUP_MODE, (dep_route_set_t){.ready = true}));
}

/* Setup-failure outcomes of a redirect list, as a forward dataflow problem
 * with exceptional control flow. Each prepared batch is a statement that may
 * raise a setup failure, and registers undo handlers that Bash runs newest
 * first when a later statement raises. The handlers form one unwind chain
 * shared by every raise point, so the failed setup's exit state is the
 * maximal fixpoint of that acyclic graph.
 *
 * A forward pass records the versions before every batch, their parents and
 * the raise points. A backward pass then carries, per version, the joined
 * state of every raise point not yet unwound, and runs each batch's handlers
 * on it once. A handler whose save may be closed is a branch: states are
 * partitioned by undo-list class (running, possibly stopped, stopped), so a
 * raise point joins the running class and leaves it only through such a
 * handler. A raise point's state differs from the running state, once that
 * has been unwound past the batches between them, only at keys those batches
 * changed, so it is joined there alone; each batch's changes are walked once.
 * Altogether this is O(changed keys × log n) for the list, with one handler
 * evaluation per batch and version. Paths reaching one handler that disagree
 * about its save being closed are joined there, a sound superset. */
static SHELL_NONNULL(1, 2, 4, 5) bool dep_fd_correlated_setup_failures(
    dep_route_journal_t *journal, const dep_fd_op_t *ops, uint32_t op_count,
    dep_fd_flow_t *failures, const dep_route_state_t *setup_entry,
    dep_domain_collection_t collection) {
  *failures = (dep_fd_flow_t){0};
  dep_failure_scan_t *scan = &collection.workspace->failure_scan;
  dep_route_state_t local = {0};
  collection.roots[3] = &local;
  collection.flow = failures;
  uint32_t count = dep_route_state_count(setup_entry);
  dep_route_iterator_t iterator = dep_route_iterator(setup_entry);
  for (uint32_t path = 0; path < count; path++) {
    dep_route_state_t one =
        dep_route_state_single(dep_route_take(&iterator, journal));
    dep_route_state_inherit(&one, setup_entry);
    dep_route_set_t frame = {0};
    dep_route_set_set(&frame, (dep_fd_route_t){DEP_ROUTE_INHERITED, one.root});
    if (!dep_route_state_store_access(&one, journal,
                                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                                      DEP_FD_ACCESS_ENTRY, frame))
      return false;
    for (uint32_t op = 0; op < op_count; op++)
      if (ops[op].fd == SHELL_DEP_FD_NAMED && ops[op].resets_descriptor &&
          !dep_fd_mark_absent(&one, journal, dep_fd_operation_target(ops + op)))
        return false;
    if (path == 0)
      local = one;
    else if (!dep_route_state_add_root(&local, journal, one.root))
      return false;
  }
  dep_route_state_inherit(&local, setup_entry);
  if (op_count && !dep_setup_begin(&local, journal, ops[0].undo_mode))
    return false;
  bool reference = false;
#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
  reference = dep_failure_reference;
#endif
  collection.roots[3] = NULL;
  collection.states = scan->level;
  collection.state_count = 0;
  uint32_t levels = 0;
  bool have_next = true;
  for (uint32_t begin = 0; begin < op_count && have_next;) {
    uint32_t end = begin + 1;
    while (end < op_count && ops[end].pos == ops[begin].pos)
      end++;
    if (levels + 1 >= DEP_FAILURE_LEVELS)
      return false;
    uint32_t level = levels++;
    scan->level[level] = local;
    scan->begin[level] = begin;
    scan->end[level] = end;
    memset(scan->raises[level], 0, sizeof(scan->raises[level]));
    collection.state_count = levels;
    dep_route_state_t next = {0};
    collection.roots[4] = &next;
    have_next = false;
    uint32_t children = 0;
    dep_route_iterator_t paths = dep_route_iterator(&local);
    uint32_t root, version = 0;
    while (dep_route_next(&paths, journal, &root)) {
      if (version == DEP_ROUTE_STATE_CAPACITY)
        return false;
      scan->root[level][version] = root;
      dep_route_state_t one = dep_route_state_single(root);
      dep_route_state_inherit(&one, &local);
      dep_domain_collection_t path_pins = {
          .workspace = collection.workspace,
          .frame = collection.frame,
          .roots = {&one},
          .remaining = &paths,
          .parent = &collection,
      };
      dep_route_domains_collect(journal, &path_pins, &one, &next);
      uint8_t outcomes =
          dep_fd_level_outcomes(ops + begin, end - begin, &one, journal);
      if (outcomes & DEP_STATUS_MAY_FAIL) {
        if (!dep_record_diagnostic(&one, journal))
          return false;
        dep_failure_set(scan->raises[level], version);
        if (reference) {
          /* The test reference unwinds every raise point on its own. */
          dep_route_state_t failed = one;
          dep_undo_result_t list = dep_fd_cleanup_range(
              &failed, journal, ops, 0, begin, DEP_UNDO_DONE);
          if (list == DEP_UNDO_EXHAUSTED ||
              !dep_failure_finish(&failed, journal, list) ||
              !dep_fd_add(failures, 1, failed, journal))
            return false;
        }
      }
      if (outcomes & DEP_STATUS_MAY_SUCCEED) {
        dep_route_state_t applied = one;
        if (!dep_route_state_apply(&applied, journal, ops + begin, end - begin,
                                   false, &path_pins))
          return false;
        dep_route_iterator_t branches = dep_route_iterator(&applied);
        uint32_t applied_root;
        while (dep_route_next(&branches, journal, &applied_root)) {
          if (children == DEP_ROUTE_STATE_CAPACITY)
            return false;
          scan->parent[level + 1][children++] = (uint8_t)version;
          if (!have_next) {
            next = dep_route_state_single(applied_root);
            dep_route_state_inherit(&next, &applied);
            have_next = true;
          } else if (!dep_route_state_add_root(&next, journal, applied_root))
            return false;
        }
      }
      version++;
    }
    scan->count[level] = version;
    if (have_next) {
      dep_route_state_inherit(&next, &local);
      local = next;
    }
    scan->count[level + 1] = children;
    begin = end;
  }
  if (reference || !levels)
    return true;
  /* The versions after the last batch only need their roots, as lineage
   * ends for the walk below. */
  scan->level[levels] = have_next ? local : (dep_route_state_t){0};
  collection.state_count = levels + 1;
  if (have_next) {
    dep_route_iterator_t paths = dep_route_iterator(&local);
    uint32_t root, version = 0;
    while (dep_route_next(&paths, journal, &root))
      scan->root[levels][version++] = root;
  }
  memset(scan->present, 0, sizeof(scan->present));
  memset(scan->pending, 0, sizeof(scan->pending));
  for (uint32_t level = levels; level-- > 0;) {
    uint32_t below = (level + 1) & 1u, here = level & 1u;
    memset(scan->present[here], 0, sizeof(scan->present[here]));
    memset(scan->pending[here], 0, sizeof(scan->pending[here]));
    /* Run this batch's handlers on every state not yet unwound. */
    for (uint32_t child = 0; child < scan->count[level + 1]; child++) {
      uint32_t parent = scan->parent[level + 1][child];
      for (uint32_t partition = 0; partition < DEP_FAILURE_CLASSES;
           partition++) {
        if (!dep_failure_bit(scan->present[below][partition], child))
          continue;
        dep_route_state_t state = scan->pending[below][partition][child];
        dep_undo_result_t list = partition == 0   ? DEP_UNDO_DONE
                                 : partition == 1 ? DEP_UNDO_MAYBE_STOPPED
                                                  : DEP_UNDO_STOPPED;
        list = dep_fd_cleanup_range(&state, journal, ops, scan->begin[level],
                                    scan->end[level], list);
        if (list == DEP_UNDO_EXHAUSTED)
          return false;
        uint32_t into = list == DEP_UNDO_DONE            ? 0
                        : list == DEP_UNDO_MAYBE_STOPPED ? 1
                                                         : 2;
        DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FAILURE_COMPOSITION);
        dep_route_state_t *target = &scan->pending[here][into][parent];
        if (dep_failure_bit(scan->present[here][into], parent)) {
          if (!dep_fd_join(target, &state, journal))
            return false;
          if (into == 0)
            scan->anchor_level[here][parent] = DEP_FAILURE_LEVELS;
          continue;
        }
        *target = state;
        dep_failure_set(scan->present[here][into], parent);
        if (into == 0) {
          scan->anchor_level[here][parent] =
              partition == 0 ? scan->anchor_level[below][child]
                             : DEP_FAILURE_LEVELS;
          scan->anchor_version[here][parent] =
              scan->anchor_version[below][child];
        }
      }
    }
    /* Raise points of this batch join the running partition. */
    for (uint32_t version = 0; version < scan->count[level]; version++) {
      if (!dep_failure_bit(scan->raises[level], version))
        continue;
      DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_FAILURE_COMPOSITION);
      dep_route_state_t raised =
          dep_route_state_single(scan->root[level][version]);
      dep_route_state_inherit(&raised, &scan->level[level]);
      dep_route_state_t *running = &scan->pending[here][0][version];
      if (!dep_failure_bit(scan->present[here][0], version)) {
        *running = raised;
        dep_failure_set(scan->present[here][0], version);
      } else if (scan->anchor_level[here][version] == DEP_FAILURE_LEVELS) {
        if (!dep_fd_join(running, &raised, journal))
          return false;
      } else {
        /* Walk the anchor's lineage back to this level: the running state
         * differs from this raise point only where those batches changed
         * something. Join into an uncorrelated copy, as dep_fd_join does: a
         * correlated result stops a merge. */
        dep_route_state_t joined = dep_route_state_single(running->root);
        uint32_t left = running->root;
        uint32_t walk = scan->anchor_version[here][version];
        for (uint32_t at = scan->anchor_level[here][version]; at > level;
             at--) {
          uint32_t up = scan->parent[at][walk];
          if (!dep_failure_join_batch(&joined, journal, left, raised.root,
                                      scan->root[at - 1][up],
                                      scan->root[at][walk]))
            return false;
          walk = up;
        }
        running->root = joined.root;
        running->truncated |= joined.truncated;
      }
      scan->anchor_level[here][version] = level;
      scan->anchor_version[here][version] = version;
    }
  }
  /* The undo-list classes matter only while unwinding: a version leaves one
   * failure state, the join of its classes. */
  for (uint32_t version = 0; version < scan->count[0]; version++) {
    dep_route_state_t failed = {0};
    bool have_failed = false;
    for (uint32_t partition = 0; partition < DEP_FAILURE_CLASSES; partition++) {
      if (!dep_failure_bit(scan->present[0][partition], version))
        continue;
      dep_route_state_t finished = scan->pending[0][partition][version];
      if (!dep_failure_finish(&finished, journal,
                              partition == 0   ? DEP_UNDO_DONE
                              : partition == 1 ? DEP_UNDO_MAYBE_STOPPED
                                               : DEP_UNDO_STOPPED))
        return false;
      if (!have_failed) {
        failed = finished;
        have_failed = true;
      } else if (!dep_fd_join(&failed, &finished, journal))
        return false;
    }
    if (have_failed && !dep_fd_add(failures, 1, failed, journal))
      return false;
  }
  return true;
}

/* Consume each prepared redirect batch once. Keep immutable prefix versions;
 * never copy a growing descriptor table or replay the source for each failure.
 * Apply registered cleanup, retaining named allocations and stopped undo. */
static SHELL_NONNULL(1, 2, 3, 8, 9, 10, 11) bool dep_fd_setup_failure_states(
    const dep_route_state_t *entry, dep_route_journal_t *journal,
    const dep_route_state_t *completed, const dep_fd_op_t *ops,
    uint32_t op_count, bool descriptor_exec, bool named_binding,
    const dep_named_mutations_t *mutations, dep_fd_flow_t *failures,
    const dep_route_state_t *setup_entry, const dep_parse_context_t *context,
    const dep_domain_collection_t *parent_pins) {
  if (!op_count) {
    *failures = (dep_fd_flow_t){0};
    return true;
  }
  /* Numeric-only setup has no surviving prefix publication: every failure
   * returns the entry version itself. Do not manufacture an equivalent map
   * by undoing the completed tree, which loses shared identity and makes
   * successive conditional failures merge ever-growing descriptor tables. */
  bool numeric_only = !mutations->count, has_move = false, has_named = false,
       high_target = false, fallible = false;
  for (uint32_t op = 0; op < op_count; op++) {
    fallible |= ops[op].kind != DEP_FD_OP_PROCESS &&
                ops[op].kind != DEP_FD_OP_IDENTITY &&
                !(ops[op].kind == DEP_FD_OP_CLOSE &&
                  ops[op].fd != SHELL_DEP_FD_NAMED) &&
                !dep_fd_op_numeric_self_dup(ops + op);
    has_move |= ops[op].kind == DEP_FD_OP_MOVE;
    has_named |= ops[op].fd == SHELL_DEP_FD_NAMED;
    numeric_only &=
        ops[op].fd != SHELL_DEP_FD_NAMED && ops[op].kind != DEP_FD_OP_MOVE;
    if (journal->scratch_observable) {
      /* A low numeric target cannot overwrite a Bash save (all saves start at
       * fd 10). Until a high target is applied, failed setup therefore restores
       * the entry table regardless of which inherited low FDs needed saves.
       * A final high redirect can fail before it changes that target; no later
       * failure observes its successful overwrite. High-source copies and pipe
       * allocation can inspect those saves and need the correlated engine. */
      numeric_only &= (!high_target || ops[op].paired_open ||
                       ops[op].kind == DEP_FD_OP_CLOSE ||
                       ops[op].kind == DEP_FD_OP_IDENTITY ||
                       dep_fd_op_numeric_self_dup(ops + op)) &&
                      ops[op].kind != DEP_FD_OP_PROCESS &&
                      (!dep_fd_op_copies(ops[op].kind) ||
                       dep_fd_op_numeric_self_dup(ops + op) ||
                       ops[op].target_fd < DEP_BASH_VARREDIR_MIN_FD);
      high_target |= ops[op].fd >= DEP_BASH_VARREDIR_MIN_FD &&
                     ops[op].kind != DEP_FD_OP_IDENTITY &&
                     !dep_fd_op_numeric_self_dup(ops + op);
    }
  }
  /* These prepared operations have no shell setup-failure outcome. In
   * particular, do not replay symbolic process-pipe allocation and cleanup
   * merely to discover that every operation necessarily succeeds. */
  if (!fallible) {
    *failures = (dep_fd_flow_t){0};
    return true;
  }
  if (numeric_only) {
    *failures = (dep_fd_flow_t){0};
    failures->state[1] = *entry;
    if (!dep_ifs_copy(&failures->state[1], setup_entry, journal))
      return false;
    dep_route_state_t local = *setup_entry;
    for (uint32_t begin = 0; begin < op_count;) {
      uint32_t end = begin + 1;
      while (end < op_count && ops[end].pos == ops[begin].pos)
        end++;
      uint8_t outcomes =
          dep_fd_level_outcomes(ops + begin, end - begin, &local, journal);
      if (outcomes & DEP_STATUS_MAY_FAIL) {
        if (!dep_record_diagnostic(&local, journal))
          return false;
        failures->mask = DEP_STATUS_MAY_FAIL;
      }
      if (!(outcomes & DEP_STATUS_MAY_SUCCEED) || end == op_count)
        break;
      for (uint32_t op = begin; op < end; op++) {
        dep_fd_op_t diagnostic = ops[op];
        /* Only capabilities are observed by this proven restoring prefix.
         * Its scratch choices cannot affect either setup failure or stderr. */
        diagnostic.undo_mode = DEP_UNDO_CHILD;
        if (!dep_route_state_apply(&local, journal, &diagnostic, 1, op == 0,
                                   NULL))
          return false;
      }
      begin = end;
    }
    return true;
  }
  bool single_allocation = op_count && !mutations->count &&
                           ops[0].fd == SHELL_DEP_FD_NAMED &&
                           ops[0].resets_descriptor;
  for (uint32_t op = 1; op < op_count; op++)
    single_allocation &= ops[op].pos == ops[0].pos;
  if (single_allocation) {
    *failures = (dep_fd_flow_t){0};
    uint8_t outcomes =
        dep_fd_level_outcomes(ops, op_count, setup_entry, journal);
    if (outcomes & DEP_STATUS_MAY_FAIL) {
      if (!dep_record_diagnostic(setup_entry, journal))
        return false;
      failures->mask = DEP_STATUS_MAY_FAIL;
      failures->state[1] = *entry;
      if (!dep_fd_mark_absent(&failures->state[1], journal,
                              dep_fd_operation_target(ops)))
        return false;
    }
    return true;
  }
  if (has_move || has_named || journal->scratch_observable ||
      dep_route_state_correlated(entry) ||
      dep_route_state_correlated(completed)) {
    dep_domain_collection_t collection = {
        .workspace = context->workspace,
        .frame =
            journal == &context->workspace->journal ? context->snapshot : NULL,
        .roots = {entry, completed, setup_entry, NULL, NULL},
        .parent = parent_pins};
    return dep_fd_correlated_setup_failures(journal, ops, op_count, failures,
                                            setup_entry, collection);
  }
  dep_route_state_t local = *setup_entry, persistent = *entry;
  *failures = (dep_fd_flow_t){0};
  /* Restore only changed values over the completed version, so both outcome
   * versions share their unchanged subtrees. */
  failures->state[1] = *completed;
  if (!dep_ifs_copy(&failures->state[1], setup_entry, journal) ||
      !dep_ifs_copy(&persistent, setup_entry, journal))
    return false;
  if (!dep_route_state_store_access(
          &failures->state[1], journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
          DEP_FD_ACCESS_AVAILABLE,
          dep_fd_raw_fact(entry, journal, dep_fd_numeric(SHELL_DEP_FD_NONE),
                          DEP_FD_ACCESS_AVAILABLE)))
    return false;
  for (uint32_t i = 0; i < op_count; i++) {
    if (!dep_fd_op_persists(ops + i, descriptor_exec, named_binding))
      continue;
    /* Named operations and moves use the correlated engine above. This
     * remaining path only rolls back numeric exec setup and builtin state. */
    dep_fd_ref_t fd = dep_fd_numeric(ops[i].fd);
    uint32_t last = DEP_FD_ACCESS_BINDING;
    for (uint32_t access = DEP_FD_ACCESS_READ; access <= last; access <<= 1)
      if (!dep_route_state_store_access(
              &failures->state[1], journal, fd, (dep_fd_access_t)access,
              dep_fd_raw_fact(entry, journal, fd, (dep_fd_access_t)access)))
        return false;
  }
  if (!mutations->before_redirect) {
    /* This path has only numeric setup. No named allocation can have changed
     * the entry scalar map; restore that immutable version as one value. The
     * correlated engine above retains reached named allocations separately. */
    DEP_METADATA_WORK(SHELLSPLIT_TEST_WORK_BINDING_INVALIDATION);
    if (!dep_route_state_store_access(
            &failures->state[1], journal, dep_fd_numeric(0),
            DEP_FD_ACCESS_NAMED_BINDINGS,
            dep_fd_raw_fact(entry, journal, dep_fd_numeric(0),
                            DEP_FD_ACCESS_NAMED_BINDINGS)))
      return false;
  }
  for (uint32_t begin = 0; begin < op_count;) {
    uint32_t end = begin + 1;
    while (end < op_count && ops[end].pos == ops[begin].pos)
      end++;
    uint8_t outcomes =
        dep_fd_level_outcomes(ops + begin, end - begin, &local, journal);
    if (outcomes & DEP_STATUS_MAY_FAIL) {
      if (!dep_record_diagnostic(&local, journal))
        return false;
      uint32_t ifs = dep_ifs_get(&persistent, journal);
      if (failures->mask)
        ifs = dep_ifs_join(ifs, dep_ifs_get(&failures->state[1], journal));
      if (!dep_ifs_store(&failures->state[1], journal, ifs))
        return false;
      if (!(failures->mask
                ? dep_fd_join_slot(&failures->state[1], &persistent, journal,
                                   dep_fd_numeric(SHELL_DEP_FD_NONE),
                                   DEP_FD_ACCESS_AVAILABLE)
                : dep_route_state_store_access(
                      &failures->state[1], journal,
                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                      DEP_FD_ACCESS_AVAILABLE,
                      dep_fd_raw_fact(&persistent, journal,
                                      dep_fd_numeric(SHELL_DEP_FD_NONE),
                                      DEP_FD_ACCESS_AVAILABLE))))
        return false;
      failures->mask = DEP_STATUS_MAY_FAIL;
    }
    if (!(outcomes & DEP_STATUS_MAY_SUCCEED))
      break;
    if (!dep_route_state_apply(&local, journal, ops + begin, end - begin,
                               begin == 0, NULL))
      return false;
    begin = end;
  }
  return true;
}

/* A failed setup's exit exists only on paths where one of its fallible opens
 * failed, or a copy lost a source which an earlier failed open left missing:
 * given that every such open succeeds, the path is infeasible. Each setup
 * target missing on it (a closed descriptor, or an unset `{name}`) therefore
 * records those opens as its causes: its missing routes carry a cause id
 * instead of UINT32_MAX, so that a later use requires the opens
 * (dep_fd_binding_exists) rather than being unmodeled. Any other fallible
 * operation leaves the plain missing routes, which a later use cannot excuse.
 */
/* Mark one failure-state target's plain missing routes with the setup's
 * failed-open causes (see dep_failure_mark_opens); live and caused routes
 * stay. Returns false only when storing the marked binding fails; sets
 * *bailed when a bounded set cannot hold the marked routes, in which case
 * the caller leaves the remaining targets unmarked. */
static SHELL_NONNULL(1, 2, 4, 6) bool dep_failure_mark_target(
    dep_route_state_t *failed, dep_route_journal_t *journal,
    dep_fd_ref_t target, const uint32_t *causes, uint32_t cause_count,
    bool *bailed) {
  dep_route_set_t binding =
      dep_fd_raw_fact(failed, journal, target, DEP_FD_ACCESS_BINDING);
  /* Every path of the failure state exists because a cause occurred, so
   * each plain missing route gains the causes; live routes stay. */
  dep_route_set_t marked = {.ready = true};
  bool changed = false;
  for (uint32_t i = 0; i < binding.count; i++) {
    dep_fd_route_t route = binding.routes[i];
    bool plain = (route.kind == DEP_ROUTE_CLOSED ||
                  route.kind == DEP_ROUTE_UNAVAILABLE ||
                  route.kind == DEP_ROUTE_ABSENT) &&
                 route.value == UINT32_MAX;
    if (!plain) {
      if (!dep_route_set_add(&marked, route)) {
        *bailed = true;
        return true;
      }
      continue;
    }
    changed = true;
    for (uint32_t cause = 0; cause < cause_count; cause++)
      if (!dep_route_set_add(&marked,
                             (dep_fd_route_t){route.kind, causes[cause]})) {
        *bailed = true;
        return true;
      }
  }
  if (changed && !dep_route_state_store_access(failed, journal, target,
                                               DEP_FD_ACCESS_BINDING, marked))
    return false;
  return true;
}

static SHELL_NONNULL(1, 2, 3, 4, 6) bool dep_failure_mark_opens(
    dep_route_state_t *failed, dep_route_journal_t *journal,
    const dep_route_state_t *completed, const dep_fd_op_t *ops,
    uint32_t op_count, const dep_parse_context_t *context) {
  dep_route_journal_t *registry = &context->workspace->journal;
  uint32_t causes[SHELL_DEP_TIME_MAX_EXTERNAL_FDS], cause_count = 0;
  for (uint32_t op = 0; op < op_count; op++) {
    dep_fd_op_kind_t kind = ops[op].kind;
    if (kind == DEP_FD_OP_DOCUMENT || kind == DEP_FD_OP_DYNAMIC) {
      const char *spelling = context->cmd + ops[op].pos;
      uint32_t cause = 0;
      while (cause < registry->open_cause_count &&
             registry->open_causes[cause] != spelling)
        cause++;
      if (cause == registry->open_cause_count) {
        if (cause == DEP_OPEN_CAUSE_CAPACITY)
          return true;
        registry->open_causes[registry->open_cause_count] = spelling;
        registry->open_cause_required[registry->open_cause_count++] = false;
      }
      if (cause_count == SHELL_DEP_TIME_MAX_EXTERNAL_FDS)
        return true;
      causes[cause_count++] = cause;
    } else if (dep_fd_op_copies(kind) ||
               (kind == DEP_FD_OP_CLOSE && ops[op].fd == SHELL_DEP_FD_NAMED)) {
      /* A copy fails only for a missing source, and a named close only for
       * an unbound name: recorded causes carry over; a plain miss blocks. */
      bool copy = dep_fd_op_copies(kind);
      dep_route_set_t source = dep_fd_fact(
          failed, journal,
          copy ? (dep_fd_ref_t){.name = ops[op].target_fd_name,
                                .value = ops[op].target_fd,
                                .name_len = ops[op].target_fd_name_len}
               : dep_fd_operation_target(ops + op),
          DEP_FD_ACCESS_BINDING);
      for (uint32_t i = 0; i < source.count; i++) {
        dep_fd_route_t route = source.routes[i];
        if (route.kind != DEP_ROUTE_CLOSED &&
            route.kind != DEP_ROUTE_UNAVAILABLE &&
            route.kind != DEP_ROUTE_ABSENT)
          continue;
        if (route.value == UINT32_MAX) {
          if (copy)
            continue;
          return true;
        }
        if (cause_count == SHELL_DEP_TIME_MAX_EXTERNAL_FDS)
          return true;
        causes[cause_count++] = route.value;
      }
    } else if (kind == DEP_FD_OP_FAILED)
      return true;
  }
  if (!cause_count)
    return true;
  /* A numeric close never fails (dep_fd_operation_outcomes), so no failure
   * path exists because of it: a close target missing here is missing because
   * a recorded cause failed, and requiring those opens excuses it. Named
   * closes are unaffected: a plain-missing named source already blocked all
   * marking above, so only caused-or-present named targets reach this loop.
   * Process operations keep their own resource model and stay skipped. */
  for (uint32_t op = 0; op < op_count; op++) {
    if (ops[op].kind == DEP_FD_OP_PROCESS)
      continue;
    bool bailed = false;
    dep_fd_ref_t target = dep_fd_operation_target(ops + op);
    if (!dep_failure_mark_target(failed, journal, target, causes, cause_count,
                                 &bailed))
      return false;
    if (bailed)
      return true;
    /* The final walk resolves a named target through its allocation places,
     * so a place missing here is missing for the same recorded causes: mark
     * what the named binding holds as well, here and where the completed
     * setup allocated it. A later use of such a place through another name
     * then reaches the missing route only on this failure path. The places
     * are bounded by the binding's route set, not by the descriptor table.
     * Private slots above the public descriptor domain carry their own
     * identity and stay out of this numeric marking. */
    if (target.value != SHELL_DEP_FD_NAMED)
      continue;
    for (unsigned side = 0; side < 2; side++) {
      dep_route_set_t binding = dep_fd_raw_fact(
          side ? completed : failed, journal, target, DEP_FD_ACCESS_BINDING);
      for (uint32_t i = 0; i < binding.count; i++) {
        if (binding.routes[i].kind != DEP_ROUTE_ALIAS ||
            binding.routes[i].value > SHELL_DEP_FD_MAX)
          continue;
        if (!dep_failure_mark_target(failed, journal,
                                     dep_fd_numeric(binding.routes[i].value),
                                     causes, cause_count, &bailed))
          return false;
        if (bailed)
          return true;
      }
    }
  }
  return true;
}

/* Setup-failure outcomes (dep_fd_setup_failure_states), with the failed
 * opens behind each missing setup target recorded (dep_failure_mark_opens). */
static SHELL_NONNULL(1, 2, 3, 8, 9, 10, 11) bool dep_fd_setup_failures(
    const dep_route_state_t *entry, dep_route_journal_t *journal,
    const dep_route_state_t *completed, const dep_fd_op_t *ops,
    uint32_t op_count, bool descriptor_exec, bool named_binding,
    const dep_named_mutations_t *mutations, dep_fd_flow_t *failures,
    const dep_route_state_t *setup_entry, const dep_parse_context_t *context,
    const dep_domain_collection_t *parent_pins) {
  return dep_fd_setup_failure_states(entry, journal, completed, ops, op_count,
                                     descriptor_exec, named_binding, mutations,
                                     failures, setup_entry, context,
                                     parent_pins) &&
         (!(failures->mask & (1u << 1)) ||
          dep_failure_mark_opens(&failures->state[1], journal, completed, ops,
                                 op_count, context));
}

#ifdef SHELLSPLIT_TEST_SOURCE_SCANS
/* Whether the fact of (fd, access) in state is the single route kind/value. */
static bool dep_test_fact_is(const dep_route_state_t *state,
                             const dep_route_journal_t *journal, uint32_t fd,
                             dep_fd_access_t access, dep_route_kind_t kind,
                             uint32_t value) {
  dep_route_set_t fact =
      dep_fd_raw_fact(state, journal, dep_fd_numeric(fd), access);
  return fact.count == 1 && fact.routes[0].kind == kind &&
         fact.routes[0].value == value;
}

static bool dep_test_fresh_workspace(void *workspace) {
  dep_route_workspace_t *w = workspace;
  memset(w, 0, sizeof(*w));
  dep_route_arena_reset(&w->route_arena);
  dep_route_journal_reset(&w->journal, &w->route_arena);
  return true;
}

bool shellsplit_test_route_collection_contract(void *workspace) {
  dep_route_workspace_t *w = workspace;
  dep_test_fresh_workspace(workspace);
  dep_route_journal_t *journal = &w->journal;
  dep_route_set_t fact = {0};
  dep_route_set_set(&fact, (dep_fd_route_t){DEP_ROUTE_INHERITED, 7});
  /* Facts a collection must keep, each held a different way: by the live
   * state (a plain fact, an owned end, a named-binding holder), by a pinned
   * flow, and by a cursor over remaining alternatives. */
  dep_route_state_t live = {0}, flowed = {0}, remaining = {0}, names = {0};
  if (!dep_route_state_append_one(&live, journal, dep_fd_numeric(3),
                                  DEP_FD_ACCESS_WRITE, fact) ||
      !dep_process_owned_set(&live, journal, dep_fd_numeric(5), true) ||
      !dep_route_state_append_one(&names, journal, dep_fd_numeric(9),
                                  DEP_FD_ACCESS_BINDING, fact))
    return false;
  dep_route_set_t holder = {0};
  dep_route_set_set(&holder, (dep_fd_route_t){DEP_ROUTE_INHERITED, names.root});
  if (!dep_route_state_append_map(&live, journal, dep_fd_numeric(0),
                                  DEP_FD_ACCESS_NAMED_BINDINGS, holder) ||
      !dep_route_state_append_one(&flowed, journal, dep_fd_numeric(6),
                                  DEP_FD_ACCESS_WRITE, fact) ||
      !dep_route_state_append_one(&remaining, journal, dep_fd_numeric(7),
                                  DEP_FD_ACCESS_WRITE, fact))
    return false;
  dep_fd_flow_t flow = {.mask = 1u};
  flow.state[0] = flowed;
  dep_route_iterator_t cursor = dep_route_iterator(&remaining);
  /* Fill the pools until a collection is due: more distinct descriptor
   * states than any source within the graph limits can produce. */
  dep_route_state_t junk = {0};
  uint32_t seed = 12345u;
  const uint32_t pressure = DEP_ROUTE_CHANGE_CAPACITY * 3 / 4;
  for (uint32_t step = 0;
       journal->arena->maps.count < pressure ||
       journal->arena->maps.allocations < DEP_ROUTE_CHANGE_CAPACITY / 16;
       step++) {
    if (step == 100000)
      return false;
    seed = seed * 1103515245u + 12345u;
    dep_route_set_t value = {0};
    dep_route_set_set(&value, (dep_fd_route_t){DEP_ROUTE_INHERITED,
                                               1000 + (seed >> 8) % 700});
    if (!dep_route_state_append_one(&junk, journal,
                                    dep_fd_numeric(10 + (seed >> 16) % 200),
                                    DEP_FD_ACCESS_WRITE, value))
      return false;
  }
  uint32_t available = shell_pmap_available(&journal->arena->maps);
  uint32_t snapshots = journal->arena->snapshot_count;
  dep_domain_collection_t collection = {
      .workspace = w, .roots = {&live}, .flow = &flow, .remaining = &cursor};
  dep_route_domains_collect(journal, &collection, &live, NULL);
  /* The dead states are reclaimed, the interned values they alone used too,
   * and the allocation counters restart. */
  if (shell_pmap_available(&journal->arena->maps) < available + 10000u ||
      journal->arena->snapshot_count >= snapshots ||
      journal->arena->maps.allocations != 0)
    return false;
  /* Every pinned fact reads the same, through every kind of pin. */
  if (!dep_test_fact_is(&live, journal, 3, DEP_FD_ACCESS_WRITE,
                        DEP_ROUTE_INHERITED, 7) ||
      !dep_process_owned(&live, journal, dep_fd_numeric(5)) ||
      !dep_test_fact_is(&flowed, journal, 6, DEP_FD_ACCESS_WRITE,
                        DEP_ROUTE_INHERITED, 7) ||
      !dep_test_fact_is(&remaining, journal, 7, DEP_FD_ACCESS_WRITE,
                        DEP_ROUTE_INHERITED, 7) ||
      !dep_route_root_snapshot(dep_named_bindings(live.root, journal).value,
                               journal, dep_fd_numeric(9),
                               DEP_FD_ACCESS_BINDING))
    return false;
  /* Reclaimed ids are reusable: later updates and reads still work. */
  dep_route_set_t later = {0};
  dep_route_set_set(&later, (dep_fd_route_t){DEP_ROUTE_INHERITED, 99});
  return dep_route_state_append_one(&live, journal, dep_fd_numeric(4),
                                    DEP_FD_ACCESS_WRITE, later) &&
         dep_test_fact_is(&live, journal, 4, DEP_FD_ACCESS_WRITE,
                          DEP_ROUTE_INHERITED, 99) &&
         dep_test_fact_is(&live, journal, 3, DEP_FD_ACCESS_WRITE,
                          DEP_ROUTE_INHERITED, 7);
}

/* A forked child keeps the process-substitution ends its parent owns; the
 * parent closes exactly those numbers and gives up their ownership. */
bool shellsplit_test_process_fork_contract(void *workspace) {
  dep_route_workspace_t *w = workspace;
  dep_test_fresh_workspace(workspace);
  dep_route_journal_t *journal = &w->journal;
  dep_route_set_t open = {0};
  dep_route_set_set(&open, (dep_fd_route_t){DEP_ROUTE_INHERITED, UINT32_MAX});
  dep_route_state_t parent = {0};
  /* fds 20 and 21 are owned ends, fd 22 an unrelated open descriptor. */
  for (uint32_t fd = 20; fd <= 22; fd++)
    if (!dep_route_state_append_one(&parent, journal, dep_fd_numeric(fd),
                                    DEP_FD_ACCESS_BINDING, open) ||
        (fd < 22 &&
         !dep_process_owned_set(&parent, journal, dep_fd_numeric(fd), true)))
      return false;
  /* A group forks: the child keeps every descriptor and owns nothing, and the
   * origin it records for the parent has the owned ends closed. */
  dep_route_state_t child = parent;
  if (!dep_fd_private_begin(&child, journal, 0) ||
      dep_process_owned_root(&child, journal) != 0 ||
      !dep_test_fact_is(&child, journal, 20, DEP_FD_ACCESS_BINDING,
                        DEP_ROUTE_INHERITED, UINT32_MAX))
    return false;
  dep_route_set_t origin = dep_fd_raw_fact(&child, journal, dep_fd_numeric(0),
                                           DEP_FD_ACCESS_PRIVATE_ENTRY);
  if (origin.count != 1)
    return false;
  dep_route_state_t returned = dep_route_state_single(origin.routes[0].value);
  if (!dep_test_fact_is(&returned, journal, 20, DEP_FD_ACCESS_BINDING,
                        DEP_ROUTE_CLOSED, UINT32_MAX) ||
      !dep_test_fact_is(&returned, journal, 21, DEP_FD_ACCESS_BINDING,
                        DEP_ROUTE_CLOSED, UINT32_MAX) ||
      !dep_test_fact_is(&returned, journal, 22, DEP_FD_ACCESS_BINDING,
                        DEP_ROUTE_INHERITED, UINT32_MAX) ||
      dep_process_owned_root(&returned, journal) != 0)
    return false;
  /* Another command range forks the same way for its child but leaves the
   * recorded parent view as it was. */
  child = parent;
  if (!dep_fd_private_begin(&child, journal, SHELL_MAX_GROUPS) ||
      dep_process_owned_root(&child, journal) != 0)
    return false;
  origin = dep_fd_raw_fact(&child, journal, dep_fd_numeric(SHELL_MAX_GROUPS),
                           DEP_FD_ACCESS_PRIVATE_ENTRY);
  if (origin.count != 1)
    return false;
  returned = dep_route_state_single(origin.routes[0].value);
  if (!dep_test_fact_is(&returned, journal, 20, DEP_FD_ACCESS_BINDING,
                        DEP_ROUTE_INHERITED, UINT32_MAX))
    return false;
  /* Cleanup closes the owned ends in the forking parent itself. */
  dep_route_state_t cleaned = parent;
  return dep_process_cleanup(&cleaned, journal) &&
         dep_process_owned_root(&cleaned, journal) == 0 &&
         dep_test_fact_is(&cleaned, journal, 20, DEP_FD_ACCESS_BINDING,
                          DEP_ROUTE_CLOSED, UINT32_MAX) &&
         dep_test_fact_is(&cleaned, journal, 21, DEP_FD_ACCESS_BINDING,
                          DEP_ROUTE_CLOSED, UINT32_MAX) &&
         dep_test_fact_is(&cleaned, journal, 22, DEP_FD_ACCESS_BINDING,
                          DEP_ROUTE_INHERITED, UINT32_MAX);
}

/* Branches that own different descriptors join into one version. An end owned
 * on every branch stays owned; one owned on some may be owned, and closing a
 * maybe-owned end keeps what it held beside CLOSED. */
bool shellsplit_test_process_owned_join_contract(void *workspace) {
  dep_route_workspace_t *w = workspace;
  dep_test_fresh_workspace(workspace);
  dep_route_journal_t *journal = &w->journal;
  dep_route_set_t open = {0};
  dep_route_set_set(&open, (dep_fd_route_t){DEP_ROUTE_INHERITED, UINT32_MAX});
  dep_route_state_t base = {0};
  for (uint32_t fd = 20; fd <= 22; fd++)
    if (!dep_route_state_append_one(&base, journal, dep_fd_numeric(fd),
                                    DEP_FD_ACCESS_BINDING, open))
      return false;
  dep_route_state_t left = base, right = base;
  if (!dep_process_owned_set(&left, journal, dep_fd_numeric(20), true) ||
      !dep_process_owned_set(&left, journal, dep_fd_numeric(22), true) ||
      !dep_process_owned_set(&right, journal, dep_fd_numeric(21), true) ||
      !dep_process_owned_set(&right, journal, dep_fd_numeric(22), true) ||
      !dep_fd_join(&left, &right, journal))
    return false;
  /* No owned end of either branch is forgotten by the join. */
  if (!dep_process_owned(&left, journal, dep_fd_numeric(20)) ||
      !dep_process_owned(&left, journal, dep_fd_numeric(21)) ||
      !dep_process_owned(&left, journal, dep_fd_numeric(22)))
    return false;
  dep_route_state_t cleaned = left;
  if (!dep_process_cleanup(&cleaned, journal) ||
      dep_process_owned_root(&cleaned, journal) != 0)
    return false;
  /* Owned on both branches: certainly closed. Owned on one: closed or not. */
  for (uint32_t fd = 20; fd <= 22; fd++) {
    dep_route_set_t fact = dep_fd_raw_fact(
        &cleaned, journal, dep_fd_numeric(fd), DEP_FD_ACCESS_BINDING);
    bool closed = false, kept = false;
    for (uint32_t i = 0; i < fact.count; i++) {
      closed |= fact.routes[i].kind == DEP_ROUTE_CLOSED;
      kept |= fact.routes[i].kind == DEP_ROUTE_INHERITED;
    }
    if (!closed || kept != (fd != 22))
      return false;
  }
  return true;
}

/* depth nested conditionals, each writing a descriptor of its own in its
 * `then` list and none in its empty `else` list: every enclosing join joins
 * the version holding all the writes of the levels inside it with the entry
 * version. Checks that each descriptor ends joined with its default, closed.
 * The persistent-map work it takes is counted by the caller. */
bool shellsplit_test_nested_join_contract(void *workspace, uint32_t depth) {
  dep_route_workspace_t *w = workspace;
  dep_test_fresh_workspace(workspace);
  dep_route_journal_t *journal = &w->journal;
  dep_route_state_t entry = {0};
  dep_route_set_t base = {0};
  dep_route_set_set(&base, (dep_fd_route_t){DEP_ROUTE_INHERITED, 1});
  if (!dep_route_state_append_one(&entry, journal, dep_fd_numeric(70),
                                  DEP_FD_ACCESS_WRITE, base))
    return false;
  dep_route_state_t exit = entry;
  for (uint32_t level = depth; level-- > 0;) {
    dep_route_set_t fact = {0};
    dep_route_set_set(&fact,
                      (dep_fd_route_t){DEP_ROUTE_INHERITED, 100 + level});
    dep_route_state_t then = exit;
    if (!dep_route_state_append_one(&then, journal, dep_fd_numeric(100 + level),
                                    DEP_FD_ACCESS_WRITE, fact) ||
        !dep_fd_join(&then, &entry, journal))
      return false;
    exit = then;
  }
  for (uint32_t level = 0; level < depth; level++) {
    dep_route_set_t fact = dep_fd_raw_fact(
        &exit, journal, dep_fd_numeric(100 + level), DEP_FD_ACCESS_WRITE);
    bool written = false, closed = false;
    for (uint32_t i = 0; i < fact.count; i++) {
      written |= fact.routes[i].kind == DEP_ROUTE_INHERITED &&
                 fact.routes[i].value == 100 + level;
      closed |= fact.routes[i].kind == DEP_ROUTE_CLOSED;
    }
    if (!written || !closed)
      return false;
  }
  return dep_test_fact_is(&exit, journal, 70, DEP_FD_ACCESS_WRITE,
                          DEP_ROUTE_INHERITED, 1);
}

/* The same nesting through the exact merge a conditional's exits take: each
 * level's version, which holds every write inside it, factors with the entry
 * version into one version, however deep. */
bool shellsplit_test_nested_merge_contract(void *workspace, uint32_t depth) {
  dep_route_workspace_t *w = workspace;
  dep_test_fresh_workspace(workspace);
  dep_route_journal_t *journal = &w->journal;
  dep_route_state_t entry = {0};
  dep_route_set_t base = {0};
  dep_route_set_set(&base, (dep_fd_route_t){DEP_ROUTE_INHERITED, 1});
  if (!dep_route_state_append_one(&entry, journal, dep_fd_numeric(70),
                                  DEP_FD_ACCESS_WRITE, base))
    return false;
  dep_route_state_t exit = entry;
  for (uint32_t level = depth; level-- > 0;) {
    dep_route_set_t fact = {0};
    dep_route_set_set(&fact,
                      (dep_fd_route_t){DEP_ROUTE_INHERITED, 100 + level});
    dep_route_state_t then = exit;
    if (!dep_route_state_append_one(&then, journal, dep_fd_numeric(100 + level),
                                    DEP_FD_ACCESS_WRITE, fact) ||
        !dep_fd_merge(&then, &entry, journal) ||
        dep_route_state_count(&then) != 1)
      return false;
    exit = then;
  }
  return true;
}

/* An undetermined descriptor below 64 reads as closed when its version's
 * occupancy says it is not occupied, as its contract default when the
 * occupancy leaves it open. Joining a version that stores a binding for it
 * with one that stores none must give the stored binding and that default. */
bool shellsplit_test_domain_join_contract(void *workspace) {
  dep_route_workspace_t *w = workspace;
  dep_test_fresh_workspace(workspace);
  dep_route_journal_t *journal = &w->journal;
  dep_route_set_t open = {0};
  dep_route_set_set(&open, (dep_fd_route_t){DEP_ROUTE_INHERITED, UINT32_MAX});
  /* left: fd 5 open. right: stores nothing for fd 5, and its occupancy says
   * fd 5 is not occupied. */
  dep_route_state_t left = {0}, right = {0};
  if (!dep_route_state_append_one(&left, journal, dep_fd_numeric(5),
                                  DEP_FD_ACCESS_BINDING, open))
    return false;
  shell_fd_occupancy_t none = {UINT64_MAX, UINT64_MAX & ~(UINT64_C(1) << 5)};
  shell_fd_partition_t partition = shell_fd_partition_split(&none);
  if (!dep_fd_domain_store(&right, journal, &partition))
    return false;
  dep_route_state_t joined = left;
  if (!dep_fd_join(&joined, &right, journal))
    return false;
  dep_route_set_t fact = dep_fd_raw_fact(&joined, journal, dep_fd_numeric(5),
                                         DEP_FD_ACCESS_BINDING);
  bool live = false, closed = false;
  for (uint32_t i = 0; i < fact.count; i++) {
    live |= fact.routes[i].kind == DEP_ROUTE_INHERITED;
    closed |= fact.routes[i].kind == DEP_ROUTE_CLOSED;
  }
  /* Joined the other way round, the facts are the same. */
  dep_route_state_t reversed = right;
  if (!dep_fd_join(&reversed, &left, journal))
    return false;
  dep_route_set_t other = dep_fd_raw_fact(&reversed, journal, dep_fd_numeric(5),
                                          DEP_FD_ACCESS_BINDING);
  return live && closed && fact.count == other.count;
}

/* Two parent versions fork the same private group, and the child versions are
 * joined into one. Returning to the parent must account for both parents. */
bool shellsplit_test_private_entry_join_contract(void *workspace) {
  dep_route_workspace_t *w = workspace;
  dep_test_fresh_workspace(workspace);
  dep_route_journal_t *journal = &w->journal;
  dep_route_set_t first = {0}, second = {0};
  dep_route_set_set(&first, (dep_fd_route_t){DEP_ROUTE_INHERITED, 11});
  dep_route_set_set(&second, (dep_fd_route_t){DEP_ROUTE_INHERITED, 12});
  dep_route_state_t left = {0}, right = {0};
  if (!dep_route_state_append_one(&left, journal, dep_fd_numeric(20),
                                  DEP_FD_ACCESS_WRITE, first) ||
      !dep_route_state_append_one(&right, journal, dep_fd_numeric(20),
                                  DEP_FD_ACCESS_WRITE, second) ||
      !dep_fd_private_begin(&left, journal, 0) ||
      !dep_fd_private_begin(&right, journal, 0) ||
      !dep_fd_join(&left, &right, journal))
    return false;
  dep_route_state_t returned = {0};
  if (!dep_fd_private_project(&left, journal, 0, &returned))
    return false;
  dep_route_set_t fact = dep_fd_raw_fact(&returned, journal, dep_fd_numeric(20),
                                         DEP_FD_ACCESS_WRITE);
  bool saw_first = false, saw_second = false;
  for (uint32_t i = 0; i < fact.count; i++) {
    saw_first |= fact.routes[i].value == 11;
    saw_second |= fact.routes[i].value == 12;
  }
  return saw_first && saw_second;
}
#endif
